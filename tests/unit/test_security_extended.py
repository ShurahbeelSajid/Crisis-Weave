from __future__ import annotations

import hashlib
import socket
import struct
import subprocess
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from PIL import Image

from crisisweave.config import Settings
from crisisweave.security import (
    MalwareDetectedError,
    SecurityError,
    _clamd_command,
    _remaining_timeout,
    _run_clamd_scan,
    constant_time_key_is_valid,
    malware_scanner_healthcheck,
    run_malware_scan,
    safe_filename,
    safe_outbound_url,
    sha256_file,
    sniff_media_type,
    validate_image,
    verify_malware_scanner,
)


class FakeSocket:
    def __init__(self, responses: list[bytes] | None = None) -> None:
        self.responses = list(responses or [])
        self.sent: list[bytes] = []
        self.timeouts: list[float] = []
        self.closed = False

    def __enter__(self) -> FakeSocket:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def recv(self, _size: int) -> bytes:
        return self.responses.pop(0) if self.responses else b""


def scanner_settings(settings: Settings, **updates: Any) -> Settings:
    defaults: dict[str, Any] = {
        "malware_scanner_host": "clamd.internal",
        "malware_scanner_port": 3310,
        "command_timeout_seconds": 5,
    }
    defaults.update(updates)
    return settings.model_copy(update=defaults)


@pytest.mark.parametrize(
    ("candidate", "valid_keys", "expected"),
    [
        ("key-two", ("key-one", "key-two"), True),
        ("unknown", ("key-one", "key-two"), False),
        (None, ("key-one",), False),
        ("key-one", (), False),
    ],
)
def test_constant_time_key_validation(
    candidate: str | None, valid_keys: tuple[str, ...], expected: bool
) -> None:
    assert constant_time_key_is_valid(candidate, valid_keys) is expected


@pytest.mark.parametrize("filename", [None, "", "...", " "])
def test_safe_filename_rejects_empty_or_punctuation_only(filename: str | None) -> None:
    with pytest.raises(SecurityError, match="filename"):
        safe_filename(filename)


def test_safe_filename_is_bounded() -> None:
    assert len(safe_filename(f"{'a' * 300}.pdf")) == 180


@pytest.mark.parametrize(
    ("suffix", "payload", "expected"),
    [
        (".pdf", b"%PDF-1.7\n", "application/pdf"),
        (".png", b"\x89PNG\r\n\x1a\ncontent", "image/png"),
        (".jpg", b"\xff\xd8\xffcontent", "image/jpeg"),
        (".jpeg", b"\xff\xd8\xffcontent", "image/jpeg"),
        (".webp", b"RIFF\x04\x00\x00\x00WEBP", "image/webp"),
        (".mp4", b"\x00\x00\x00\x18ftypisom0000", "video/mp4"),
        (".m4v", b"\x00\x00\x00\x18ftypisom0000", "video/mp4"),
        (".webm", b"\x1aE\xdf\xa3content", "video/webm"),
        (".json", b'\xef\xbb\xbf  {"safe": true}', "application/json"),
        (".csv", b"field\tvalue\nitem\t1", "text/csv"),
        (".txt", b"plain text", "text/plain"),
        (".md", b"# Report", "text/plain"),
        (".srt", b"1\n00:00:00,000 --> 00:00:01,000", "text/plain"),
        (".vtt", b"WEBVTT", "text/plain"),
    ],
)
def test_media_signatures_are_recognized(
    tmp_path: Path, suffix: str, payload: bytes, expected: str
) -> None:
    path = tmp_path / f"upload{suffix}"
    path.write_bytes(payload)
    assert sniff_media_type(path) == expected


@pytest.mark.parametrize(
    ("name", "payload"),
    [
        ("binary.txt", b"\xff\xfe\xfd"),
        ("object.json", b"not json"),
        ("rows.csv", b"one-column-without-a-separator"),
        ("unknown.bin", b"plain text"),
    ],
)
def test_unrecognized_or_mislabeled_media_is_rejected(
    tmp_path: Path, name: str, payload: bytes
) -> None:
    path = tmp_path / name
    path.write_bytes(payload)
    with pytest.raises(SecurityError):
        sniff_media_type(path)


def test_validate_image_rejects_excessive_dimensions(tmp_path: Path) -> None:
    path = tmp_path / "large.png"
    Image.new("RGB", (11, 10), "blue").save(path)
    with (
        pytest.warns(Image.DecompressionBombWarning),
        pytest.raises(SecurityError, match="exceeds"),
    ):
        validate_image(path, 100)


def test_validate_image_rejects_corruption(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.png"
    path.write_bytes(b"not an image")
    with pytest.raises(SecurityError, match="corrupt or unsafe"):
        validate_image(path, 1_000)


def test_sha256_file_streams_the_complete_file(tmp_path: Path) -> None:
    payload = b"a" * (1024 * 1024) + b"final-block"
    path = tmp_path / "large.bin"
    path.write_bytes(payload)
    assert sha256_file(path) == hashlib.sha256(payload).hexdigest()


def public_dns_result(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


def test_safe_outbound_url_accepts_allowlisted_public_subdomain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", public_dns_result)
    url = "https://api.example.com/report?id=7"
    assert safe_outbound_url(url, ("example.com",)) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/report",
        "https://user@example.com/report",
        "https://user:secret@example.com/report",
        "https:///missing-host",
        "https://notexample.com/report",
    ],
)
def test_safe_outbound_url_rejects_invalid_authority_or_domain(
    monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", public_dns_result)
    with pytest.raises(SecurityError):
        safe_outbound_url(url, ("example.com",))


@pytest.mark.parametrize("address", ["127.0.0.1", "10.2.3.4", "::1", "fe80::1"])
def test_safe_outbound_url_rejects_non_public_dns_answers(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(0, 0, 0, "", (address, 443))],
    )
    with pytest.raises(SecurityError, match="non-public"):
        safe_outbound_url("https://example.com/report", ("example.com",))


def test_safe_outbound_url_rejects_dns_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_dns(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        raise socket.gaierror("unavailable")

    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    with pytest.raises(SecurityError, match="did not resolve"):
        safe_outbound_url("https://example.com/report", ("example.com",))


def test_remaining_timeout_obeys_deadline_and_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("crisisweave.security.time.monotonic", lambda: 100.0)
    assert _remaining_timeout(None, 5.0) == 5.0
    assert _remaining_timeout(102.0, 5.0) == 2.0
    assert _remaining_timeout(100.01, 5.0) == 0.1
    with pytest.raises(SecurityError, match="execution budget"):
        _remaining_timeout(100.0, 5.0)


def test_run_malware_scan_delegates_to_clamd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, settings: Settings
) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"safe")
    configured = scanner_settings(settings)
    calls: list[tuple[Path, Settings, float | None]] = []

    def record(target: Path, current: Settings, *, deadline: float | None = None) -> None:
        calls.append((target, current, deadline))

    monkeypatch.setattr("crisisweave.security._run_clamd_scan", record)
    run_malware_scan(path, configured, deadline=123.0)
    assert calls == [(path, configured, 123.0)]


def test_run_malware_scan_is_noop_when_unconfigured(tmp_path: Path, settings: Settings) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"safe")
    run_malware_scan(path, settings)


def test_command_scanner_requires_absolute_path(tmp_path: Path, settings: Settings) -> None:
    configured = settings.model_copy(update={"malware_scanner_path": "clamdscan"})
    with pytest.raises(SecurityError, match="absolute"):
        run_malware_scan(tmp_path / "upload.bin", configured)


@pytest.mark.parametrize("returncode", [0, 1, 2])
def test_command_scanner_enforces_exit_status(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings: Settings,
    returncode: int,
) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"safe")
    configured = settings.model_copy(update={"malware_scanner_path": "C:/tools/scan.exe"})
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(subprocess, "run", fake_run)
    if returncode == 1:
        with pytest.raises(MalwareDetectedError, match="rejected"):
            run_malware_scan(path, configured)
    elif returncode:
        with pytest.raises(SecurityError, match="failed closed"):
            run_malware_scan(path, configured)
    else:
        run_malware_scan(path, configured)
    assert calls[0][0] == ["C:\\tools\\scan.exe", "--no-summary", str(path)]
    assert calls[0][1]["timeout"] == configured.command_timeout_seconds
    assert calls[0][1]["check"] is False


@pytest.mark.parametrize("error", [OSError("failed"), subprocess.TimeoutExpired("scan", 5)])
def test_command_scanner_fails_closed_on_execution_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings: Settings,
    error: Exception,
) -> None:
    configured = settings.model_copy(update={"malware_scanner_path": "C:/tools/scan.exe"})

    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(SecurityError, match="failed closed"):
        run_malware_scan(tmp_path / "upload.bin", configured)


def test_clamd_stream_protocol_sends_framed_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, settings: Settings
) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"payload")
    connection = FakeSocket([b"stream: ", b"OK\0"])
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: connection)

    _run_clamd_scan(path, scanner_settings(settings))

    assert connection.closed
    assert connection.sent == [
        b"zINSTREAM\0",
        struct.pack(">I", 7),
        b"payload",
        struct.pack(">I", 0),
    ]
    assert connection.timeouts


@pytest.mark.parametrize(
    ("response", "exception", "message"),
    [
        (b"stream: Eicar-Signature FOUND\0", MalwareDetectedError, "rejected"),
        (b"", SecurityError, "failed closed"),
    ],
)
def test_clamd_stream_rejects_non_ok_verdict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    settings: Settings,
    response: bytes,
    exception: type[SecurityError],
    message: str,
) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"payload")
    connection = FakeSocket([response])
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: connection)
    with pytest.raises(exception, match=message):
        _run_clamd_scan(path, scanner_settings(settings))


def test_clamd_stream_fails_closed_on_socket_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, settings: Settings
) -> None:
    def fail(*_args: object, **_kwargs: object) -> FakeSocket:
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", fail)
    with pytest.raises(SecurityError, match="failed closed"):
        _run_clamd_scan(tmp_path / "upload.bin", scanner_settings(settings))


def test_clamd_command_returns_trimmed_response(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    connection = FakeSocket([b"PONG\0\r\n"])
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: connection)
    configured = scanner_settings(settings)
    assert _clamd_command(configured, b"zPING\0") == b"PONG"
    assert connection.sent == [b"zPING\0"]
    assert connection.closed


def test_clamd_command_rejects_empty_response(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    with pytest.raises(SecurityError, match="empty health response"):
        _clamd_command(scanner_settings(settings), b"zPING\0")


def test_clamd_command_fails_closed_on_socket_error(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    def fail(*_args: object, **_kwargs: object) -> FakeSocket:
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", fail)
    with pytest.raises(SecurityError, match="health check failed closed"):
        _clamd_command(scanner_settings(settings), b"zPING\0")


def version_response(at: datetime) -> bytes:
    return f"ClamAV 1.4.3/27366/{format_datetime(at, usegmt=True)}".encode()


def test_scanner_health_is_optional_only_outside_production(settings: Settings) -> None:
    assert malware_scanner_healthcheck(settings)
    assert not malware_scanner_healthcheck(settings.model_copy(update={"app_env": "production"}))


def test_scanner_health_accepts_recent_signatures(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setattr(
        "crisisweave.security._clamd_command",
        lambda *_args, **_kwargs: version_response(datetime.now(UTC) - timedelta(hours=1)),
    )
    assert malware_scanner_healthcheck(scanner_settings(settings))


@pytest.mark.parametrize(
    "response",
    [
        b"unexpected",
        b"Engine/123/Sun, 02 Aug 2026 00:00:00 GMT",
        b"ClamAV 1.4/123/not-a-date",
        b"\xff",
    ],
)
def test_scanner_health_rejects_malformed_version(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, response: bytes
) -> None:
    monkeypatch.setattr("crisisweave.security._clamd_command", lambda *_args, **_kwargs: response)
    assert not malware_scanner_healthcheck(scanner_settings(settings))


@pytest.mark.parametrize("offset_hours", [-49, 25])
def test_scanner_health_rejects_stale_or_implausibly_future_signatures(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, offset_hours: int
) -> None:
    response = version_response(datetime.now(UTC) + timedelta(hours=offset_hours))
    monkeypatch.setattr("crisisweave.security._clamd_command", lambda *_args, **_kwargs: response)
    configured = scanner_settings(settings, max_malware_signature_age_hours=48)
    assert not malware_scanner_healthcheck(configured)


def test_scanner_health_supports_timezone_naive_signature_dates(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    date = datetime.now(UTC).replace(tzinfo=None).strftime("%a, %d %b %Y %H:%M:%S")
    response = f"ClamAV 1.4.3/27366/{date}".encode()
    monkeypatch.setattr("crisisweave.security._clamd_command", lambda *_args, **_kwargs: response)
    assert malware_scanner_healthcheck(scanner_settings(settings))


def test_verify_scanner_rejects_failed_healthcheck(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    monkeypatch.setattr("crisisweave.security.malware_scanner_healthcheck", lambda _value: False)
    with pytest.raises(RuntimeError, match="unavailable"):
        verify_malware_scanner(settings)


def test_verify_scanner_removes_canaries_when_clean_scan_fails(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    configured = scanner_settings(settings, max_upload_bytes=1024)
    monkeypatch.setattr("crisisweave.security.malware_scanner_healthcheck", lambda _value: True)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise SecurityError("scanner unavailable")

    monkeypatch.setattr("crisisweave.security.run_malware_scan", fail)
    with pytest.raises(SecurityError, match="unavailable"):
        verify_malware_scanner(configured)
    assert list((configured.data_dir / "tmp").iterdir()) == []
