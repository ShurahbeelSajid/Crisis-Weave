from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from crisisweave.config import Settings  # noqa: E402


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        app_env="test",
        data_dir=tmp_path / "data",
        api_keys="alpha=test-alpha-key,beta=test-beta-key",
        rate_limit_requests=1000,
        enable_docs=True,
        llm_provider="disabled",
        embedding_provider="hash",
        reranker_provider="lexical",
        web_search_provider="disabled",
        tesseract_path="definitely-not-installed-tesseract",
    )
