"""Configuration via environment variables (optionally loaded from a .env file). No secrets in code."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(ROOT / ".env")


def _path(env: str, default: str) -> Path:
    p = Path(os.getenv(env, default))
    return p if p.is_absolute() else ROOT / p


class Settings:
    CLOUD_DATA_PATH = _path("CLOUD_DATA_PATH", "data/cloud/novatech.json")
    LOG_DATA_PATH = _path("LOG_DATA_PATH", "data/logs/cloudtrail_sample.json")
    KNOWLEDGE_DIR = _path("KNOWLEDGE_DIR", "data/knowledge")
    DB_PATH = _path("DB_PATH", "data/analyst.db")
    REPORT_DIR = _path("REPORT_DIR", "data/reports")

    # LLM: "offline" (deterministic, no model) or "ollama"
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "offline").lower()
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
    LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))

    # API
    API_KEY = os.getenv("API_KEY", "")  # if set, API requires X-API-Key header
    MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(1_000_000)))
    MAX_CHAT_CHARS = int(os.getenv("MAX_CHAT_CHARS", "1000"))

    # Analysis tuning
    UNUSED_KEY_DAYS = int(os.getenv("UNUSED_KEY_DAYS", "90"))
    TRUSTED_CIDRS = [c for c in os.getenv("TRUSTED_CIDRS", "10.0.0.0/8,203.0.113.0/24").split(",") if c]
    BUSINESS_HOURS_UTC = (6, 20)  # events outside this window count as off-hours


settings = Settings()
