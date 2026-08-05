from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from crisisweave.agent import CrisisAgent
from crisisweave.llm import Plan, PlannedTool
from crisisweave.models import QueryRequest, Route
from crisisweave.web_search import WebSearch, WebSearchProviderError


def _mock_client(monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
    async_client = httpx.AsyncClient

    def factory(
        *, timeout: httpx.Timeout, follow_redirects: bool, trust_env: bool
    ) -> httpx.AsyncClient:
        assert trust_env is False
        assert follow_redirects is False
        return async_client(
            transport=transport,
            timeout=timeout,
            follow_redirects=follow_redirects,
            trust_env=trust_env,
        )

    monkeypatch.setattr(httpx, "AsyncClient", factory)


async def test_tavily_request_uses_bearer_contract_without_secret_body(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["authorization"] = request.headers.get("Authorization")
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "NOAA update",
                        "url": "https://www.noaa.gov/update",
                        "content": "Official incident update",
                        "score": 0.9,
                    },
                    {
                        "title": "Untrusted result",
                        "url": "https://example.com/not-allowed",
                        "content": "Must be filtered",
                        "score": 1.0,
                    },
                ]
            },
        )

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-contract-secret"),
            "web_allowed_domains": "noaa.gov",
        }
    )

    results = await WebSearch(configured).search("tenant", "current wildfire update", limit=5)

    assert captured["url"] == "https://api.tavily.com/search"
    assert captured["authorization"] == "Bearer tvly-contract-secret"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert "api_key" not in payload
    assert payload == {
        "query": "current wildfire update",
        "search_depth": "advanced",
        "max_results": 5,
        "include_domains": ["noaa.gov"],
        "include_raw_content": False,
    }
    assert len(results) == 1
    assert results[0].source_uri == "https://www.noaa.gov/update"
    assert results[0].metadata["untrusted_fields"] == ["source_name", "text"]


async def test_tavily_http_error_is_raised(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Unauthorized"})

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-invalid-secret"),
        }
    )

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await WebSearch(configured).search("tenant", "current wildfire update")

    assert exc_info.value.response.status_code == 401


async def test_tavily_uses_operator_pinned_gateway_endpoint(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"results": []})

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-gateway-secret"),
            "tavily_endpoint": "https://egress.internal.example/tavily/search",
        }
    )
    assert await WebSearch(configured).search("tenant", "current wildfire update") == []
    assert captured["url"] == "https://egress.internal.example/tavily/search"


async def test_tavily_response_body_is_bounded(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "NOAA update",
                        "url": "https://www.noaa.gov/update",
                        "content": "x" * 5000,
                        "score": 0.9,
                    }
                ]
            },
        )

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-contract-secret"),
            "max_web_response_bytes": 4096,
        }
    )

    with pytest.raises(WebSearchProviderError, match="configured byte limit"):
        await WebSearch(configured).search("tenant", "current wildfire update")


async def test_tavily_query_length_is_bounded(settings) -> None:
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-contract-secret"),
        }
    )

    with pytest.raises(WebSearchProviderError, match="between 1 and 400"):
        await WebSearch(configured).search("tenant", "x" * 401)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"results": {}},
        {"results": ["not-an-object"]},
        {
            "results": [
                {
                    "title": "NOAA update",
                    "url": "https://www.noaa.gov/update",
                    "content": "Official incident update",
                    "score": "high",
                }
            ]
        },
        {
            "results": [
                {
                    "title": "NOAA update",
                    "url": f"https://www.noaa.gov/{'x' * 2048}",
                    "content": "Official incident update",
                    "score": 0.9,
                }
            ]
        },
    ],
)
async def test_tavily_malformed_success_response_is_controlled_provider_error(
    settings, monkeypatch: pytest.MonkeyPatch, payload: object
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-contract-secret"),
        }
    )

    with pytest.raises(WebSearchProviderError, match="Tavily"):
        await WebSearch(configured).search("tenant", "current wildfire update")


async def test_tavily_result_url_rejects_embedded_credentials(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "Credential-bearing URL",
                        "url": "https://user:password@www.noaa.gov/update",
                        "content": "Must be filtered",
                        "score": 0.9,
                    }
                ]
            },
        )

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-contract-secret"),
            "web_allowed_domains": "noaa.gov",
        }
    )

    assert await WebSearch(configured).search("tenant", "current wildfire update") == []


async def test_tavily_result_url_rejects_malformed_ipv6(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "title": "Malformed URL",
                        "url": "https://[invalid/update",
                        "content": "Must be filtered",
                        "score": 0.9,
                    }
                ]
            },
        )

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-contract-secret"),
            "web_allowed_domains": "noaa.gov",
        }
    )

    assert await WebSearch(configured).search("tenant", "current wildfire update") == []


async def test_agent_degrades_gracefully_when_tavily_contract_is_malformed(
    settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"results": "not-an-array"})

    _mock_client(monkeypatch, httpx.MockTransport(handler))
    configured = settings.model_copy(
        update={
            "web_search_provider": "tavily",
            "tavily_api_key": SecretStr("tvly-contract-secret"),
        }
    )
    agent = object.__new__(CrisisAgent)
    agent.settings = configured
    agent.web = WebSearch(configured)

    result = await agent._execute(  # noqa: SLF001 - focused tool-boundary regression test
        {
            "tenant_id": "tenant",
            "request": QueryRequest(query="What is the current wildfire update?", allow_web=True),
            "started_at": 0.0,
            "query": "What is the current wildfire update?",
            "plan": Plan(
                tools=[PlannedTool(route=Route.WEB, query="What is the current wildfire update?")]
            ),
            "warnings": [],
        }
    )

    assert result["evidence"] == []
    assert result["traces"][0].status == "error"
    assert any(
        "web tool unavailable (WebSearchProviderError)" in warning for warning in result["warnings"]
    )
