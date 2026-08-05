"""Snippet-only allowlisted search; CrisisWeave never fetches arbitrary result URLs."""

from __future__ import annotations

import json
import math
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from crisisweave.config import Settings
from crisisweave.models import (
    SOURCE_OBSERVED_AT_METADATA_KEY,
    SOURCE_TIME_KIND_METADATA_KEY,
    Evidence,
    Modality,
    SourceTimeKind,
)
from crisisweave.security import assess_prompt


class WebSearchProviderError(RuntimeError):
    """A safe, non-sensitive description of a provider contract failure."""


class WebSearch:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _allowed(self, url: str) -> bool:
        if any(character.isspace() or ord(character) < 32 for character in url):
            return False
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return False
        host = parsed.hostname.lower().rstrip(".")
        return any(
            host == domain or host.endswith(f".{domain}")
            for domain in self.settings.allowed_domain_values
        )

    async def search(self, tenant_id: str, query: str, limit: int = 5) -> list[Evidence]:
        if self.settings.web_search_provider == "disabled":
            return []
        key = self.settings.tavily_api_key
        if key is None:
            return []
        normalized_query = query.strip()
        if not 1 <= len(normalized_query) <= 400:
            raise WebSearchProviderError("Tavily query must contain between 1 and 400 characters")
        result_limit = max(1, min(limit, 5))
        payload = {
            "query": normalized_query,
            "search_depth": "advanced",
            "max_results": result_limit,
            "include_domains": list(self.settings.allowed_domain_values),
            "include_raw_content": False,
        }
        headers = {"Authorization": f"Bearer {key.get_secret_value()}"}
        timeout = httpx.Timeout(self.settings.web_timeout_seconds)
        async with (
            httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream(
                "POST", self.settings.tavily_endpoint, headers=headers, json=payload
            ) as response,
        ):
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > self.settings.max_web_response_bytes:
                    raise WebSearchProviderError(
                        "Tavily response exceeded the configured byte limit"
                    )
                body.extend(chunk)
        items = _validate_response(body)
        results: list[Evidence] = []
        for item in items[:result_limit]:
            url = item["url"]
            if not self._allowed(url):
                continue
            content_assessment = assess_prompt(item["content"].strip()[:4000])
            content = content_assessment.sanitized
            if not content:
                continue
            raw_title = item["title"].strip()[:1000] or url
            title_assessment = assess_prompt(raw_title)
            source_name = title_assessment.sanitized.strip()[:300] or url[:300]
            evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{tenant_id}:{url}:{content}"))
            metadata: dict[str, Any] = {
                "provider": "tavily",
                "untrusted": True,
                "untrusted_fields": ["source_name", "text"],
                "prompt_injection_suspected": (
                    content_assessment.suspicious or title_assessment.suspicious
                ),
            }
            if item["published_date"] is not None:
                metadata[SOURCE_OBSERVED_AT_METADATA_KEY] = item["published_date"]
                metadata[SOURCE_TIME_KIND_METADATA_KEY] = SourceTimeKind.PUBLICATION.value
            results.append(
                Evidence(
                    id=evidence_id,
                    tenant_id=tenant_id,
                    document_id=evidence_id,
                    source_name=source_name,
                    source_uri=url,
                    modality=Modality.WEB,
                    text=content,
                    score=max(0.0, min(1.0, item["score"])),
                    metadata=metadata,
                )
            )
        return results


def _validate_response(body: bytes | bytearray) -> list[dict[str, Any]]:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise WebSearchProviderError("Tavily returned malformed JSON") from exc
    if not isinstance(data, dict):
        raise WebSearchProviderError("Tavily returned a non-object response")
    raw_results = data.get("results")
    if not isinstance(raw_results, list):
        raise WebSearchProviderError("Tavily response field 'results' must be an array")

    validated: list[dict[str, Any]] = []
    for index, item in enumerate(raw_results):
        if not isinstance(item, dict):
            raise WebSearchProviderError(f"Tavily result {index} must be an object")
        url = item.get("url")
        title = item.get("title")
        content = item.get("content")
        score = item.get("score")
        published_date = item.get("published_date")
        if not isinstance(url, str) or not 1 <= len(url.strip()) <= 2048:
            raise WebSearchProviderError(f"Tavily result {index} has an invalid URL")
        if not isinstance(title, str) or len(title) > 1000:
            raise WebSearchProviderError(f"Tavily result {index} has an invalid title")
        if not isinstance(content, str) or len(content) > 100_000:
            raise WebSearchProviderError(f"Tavily result {index} has invalid content")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise WebSearchProviderError(f"Tavily result {index} has an invalid score")
        numeric_score = float(score)
        if not math.isfinite(numeric_score):
            raise WebSearchProviderError(f"Tavily result {index} has a non-finite score")
        normalized_publication: str | None = None
        if published_date is not None:
            if not isinstance(published_date, str) or not 1 <= len(published_date) <= 64:
                raise WebSearchProviderError(
                    f"Tavily result {index} has an invalid publication time"
                )
            try:
                parsed_publication = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            except ValueError as exc:
                raise WebSearchProviderError(
                    f"Tavily result {index} has an invalid publication time"
                ) from exc
            if parsed_publication.tzinfo is None:
                raise WebSearchProviderError(
                    f"Tavily result {index} has an invalid publication time"
                )
            normalized_publication = parsed_publication.astimezone(UTC).isoformat()
        validated.append(
            {
                "url": url.strip(),
                "title": title,
                "content": content,
                "score": numeric_score,
                "published_date": normalized_publication,
            }
        )
    return validated
