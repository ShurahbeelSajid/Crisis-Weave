"""Security boundary helpers for uploads, prompts, SQL, and outbound URLs."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import socket
import struct

# The antivirus executable and arguments are validated administrator configuration.
import subprocess  # nosec B404
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image

from crisisweave.config import Settings


class SecurityError(ValueError):
    """Raised when untrusted input violates a security boundary."""


class MalwareDetectedError(SecurityError):
    """Raised only when a scanner returns an explicit malware verdict."""


ALLOWED_MEDIA_TYPES: dict[str, set[str]] = {
    "application/pdf": {".pdf"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
    "image/webp": {".webp"},
    "video/mp4": {".mp4", ".m4v"},
    "video/webm": {".webm"},
    "text/csv": {".csv"},
    "application/json": {".json"},
    "text/plain": {".txt", ".md", ".srt", ".vtt"},
}

_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"ignore\s+(?:all\s+)?(?:guardrails|instructions|policies|rules)\b",
        r"reveal\s+(the\s+)?(system|developer)\s+prompt",
        r"(?:system|developer)\s+message\s*:",
        r"<\s*/?\s*(?:tool|system|assistant)(?:_call)?\b",
        r"(?:execute|run)\s+(?:this\s+)?(?:shell|command|sql)\s*:",
        r"(?:fabricate|invent|make\s+up)\b.{0,80}\b(?:answer|citation|fact|number|toll)",
    )
)


@dataclass(frozen=True)
class PromptAssessment:
    sanitized: str
    suspicious: bool
    reasons: tuple[str, ...]


def constant_time_key_is_valid(candidate: str | None, valid_keys: tuple[str, ...]) -> bool:
    if not candidate or not valid_keys:
        return False
    return any(hmac.compare_digest(candidate.encode(), key.encode()) for key in valid_keys)


def safe_filename(filename: str | None) -> str:
    if not filename:
        raise SecurityError("A filename is required")
    leaf = Path(filename.replace("\\", "/")).name
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", leaf).strip(" .")
    if not cleaned or cleaned in {".", ".."}:
        raise SecurityError("The filename is invalid")
    return cleaned[:180]


def sniff_media_type(path: Path) -> str:
    with path.open("rb") as handle:
        head = handle.read(4096)
    suffix = path.suffix.lower()
    detected: str | None = None
    if head.startswith(b"%PDF-"):
        detected = "application/pdf"
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        detected = "image/png"
    elif head.startswith(b"\xff\xd8\xff"):
        detected = "image/jpeg"
    elif head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        detected = "image/webp"
    elif len(head) > 12 and head[4:8] == b"ftyp":
        detected = "video/mp4"
    elif head.startswith(b"\x1aE\xdf\xa3"):
        detected = "video/webm"
    else:
        try:
            decoded = head.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecurityError("Unsupported or unrecognized binary format") from exc
        stripped = decoded.lstrip("\ufeff\r\n\t ")
        if suffix == ".json" and stripped[:1] in {"{", "["}:
            detected = "application/json"
        elif suffix == ".csv" and ("," in decoded or "\t" in decoded):
            detected = "text/csv"
        elif suffix in {".txt", ".md", ".srt", ".vtt"}:
            detected = "text/plain"
    if not detected or suffix not in ALLOWED_MEDIA_TYPES.get(detected, set()):
        raise SecurityError("File content does not match an allowed extension")
    return detected


def validate_image(path: Path, max_pixels: int) -> None:
    Image.MAX_IMAGE_PIXELS = max_pixels
    try:
        with Image.open(path) as image:
            width, height = image.size
            if width * height > max_pixels:
                raise SecurityError(f"Image exceeds {max_pixels:,} pixels")
            image.verify()
    except (OSError, Image.DecompressionBombError) as exc:
        raise SecurityError("Image is corrupt or unsafe to decode") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assess_prompt(value: str) -> PromptAssessment:
    normalized = "".join(ch for ch in value if ch in "\n\t" or ord(ch) >= 32).strip()
    reasons = tuple(pattern.pattern for pattern in _PROMPT_PATTERNS if pattern.search(normalized))
    return PromptAssessment(sanitized=normalized, suspicious=bool(reasons), reasons=reasons)


def safe_outbound_url(url: str, allowed_domains: tuple[str, ...]) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise SecurityError("Only credential-free HTTPS URLs are allowed")
    host = parsed.hostname.lower().rstrip(".")
    if not any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains):
        raise SecurityError("Outbound domain is not allowlisted")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise SecurityError("Outbound hostname did not resolve") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise SecurityError("Outbound hostname resolves to a non-public address")
    return url


def _remaining_timeout(deadline: float | None, maximum: float) -> float:
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SecurityError("Upload processing exceeded its execution budget")
    return max(0.1, min(maximum, remaining))


def run_malware_scan(path: Path, settings: Settings, *, deadline: float | None = None) -> None:
    if settings.malware_scanner_host:
        _run_clamd_scan(path, settings, deadline=deadline)
        return
    if not settings.malware_scanner_path:
        return
    executable = Path(settings.malware_scanner_path)
    if not executable.is_absolute():
        raise SecurityError("malware_scanner_path must be an absolute path")
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [str(executable), "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=_remaining_timeout(deadline, float(settings.command_timeout_seconds)),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SecurityError("Malware scanning failed closed") from exc
    if result.returncode == 1:
        raise MalwareDetectedError("Upload rejected by malware scanner")
    if result.returncode != 0:
        raise SecurityError("Malware scanning failed closed")


def _check_clamd_verdict(verdict: bytes) -> None:
    if verdict.endswith(b": OK"):
        return
    if verdict.endswith(b" FOUND"):
        raise MalwareDetectedError("Upload rejected by malware scanner")
    raise SecurityError("Malware scanning failed closed")


def _run_clamd_scan(path: Path, settings: Settings, *, deadline: float | None = None) -> None:
    try:
        with socket.create_connection(
            (settings.malware_scanner_host or "", settings.malware_scanner_port),
            timeout=_remaining_timeout(
                deadline, min(float(settings.command_timeout_seconds), 30.0)
            ),
        ) as connection:
            connection.settimeout(
                _remaining_timeout(deadline, min(float(settings.command_timeout_seconds), 30.0))
            )
            connection.sendall(b"zINSTREAM\0")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    connection.settimeout(_remaining_timeout(deadline, 30.0))
                    connection.sendall(struct.pack(">I", len(chunk)))
                    connection.sendall(chunk)
            connection.sendall(struct.pack(">I", 0))
            response = bytearray()
            while len(response) <= 8192:
                connection.settimeout(_remaining_timeout(deadline, 30.0))
                block = connection.recv(1024)
                if not block:
                    break
                response.extend(block)
                if b"\0" in block:
                    break
    except OSError as exc:
        raise SecurityError("Malware scanning failed closed") from exc
    verdict = bytes(response).rstrip(b"\0\r\n")
    _check_clamd_verdict(verdict)


def _clamd_command(settings: Settings, command: bytes) -> bytes:
    try:
        with socket.create_connection(
            (settings.malware_scanner_host or "", settings.malware_scanner_port),
            timeout=min(float(settings.command_timeout_seconds), 10.0),
        ) as connection:
            connection.settimeout(min(float(settings.command_timeout_seconds), 10.0))
            connection.sendall(command)
            response = connection.recv(4096)
    except OSError as exc:
        raise SecurityError("Malware scanner health check failed closed") from exc
    if not response:
        raise SecurityError("Malware scanner returned an empty health response")
    return response.rstrip(b"\0\r\n")


def malware_scanner_healthcheck(settings: Settings) -> bool:
    if not settings.malware_scanner_host:
        return settings.app_env != "production"
    try:
        response = _clamd_command(settings, b"zVERSION\0").decode("ascii", errors="strict")
        parts = response.split("/", 2)
        if len(parts) != 3 or not parts[0].startswith("ClamAV"):
            return False
        signature_date = parsedate_to_datetime(parts[2])
        if signature_date.tzinfo is None:
            signature_date = signature_date.replace(tzinfo=UTC)
        age_hours = (datetime.now(UTC) - signature_date.astimezone(UTC)).total_seconds() / 3600
        return -24 <= age_hours <= settings.max_malware_signature_age_hours
    except (ValueError, TypeError, OverflowError):
        return False


def verify_malware_scanner(settings: Settings) -> None:
    if not malware_scanner_healthcheck(settings):
        raise RuntimeError("ClamAV is unavailable or its signature database is stale")
    canary_dir = settings.data_dir / "tmp"
    canary_dir.mkdir(parents=True, exist_ok=True)
    clean = canary_dir / f"clamav-clean-{uuid.uuid4()}.bin"
    eicar = canary_dir / f"clamav-eicar-{uuid.uuid4()}.txt"
    try:
        with clean.open("xb") as handle:
            handle.truncate(settings.max_upload_bytes)
        run_malware_scan(
            clean,
            settings,
            deadline=time.monotonic() + settings.command_timeout_seconds,
        )
        signature = b"".join(
            (
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
                b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            )
        )
        eicar.write_bytes(signature)
        malware_detected = False
        try:
            run_malware_scan(
                eicar,
                settings,
                deadline=time.monotonic() + settings.command_timeout_seconds,
            )
        except MalwareDetectedError:
            malware_detected = True
        if not malware_detected:
            raise RuntimeError("ClamAV failed the malware-detection canary")
    finally:
        clean.unlink(missing_ok=True)
        eicar.unlink(missing_ok=True)
