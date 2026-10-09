"""LLM client abstraction. `offline` = no model (deterministic analyst); `ollama` = local model via HTTP."""
from __future__ import annotations

import json
import logging
import re

import requests

from config.settings import settings

log = logging.getLogger(__name__)


class LLM:
    name = "offline"

    def complete(self, system: str, user: str) -> str | None:
        return None


class OllamaLLM(LLM):
    name = "ollama"

    def complete(self, system: str, user: str) -> str | None:
        try:
            r = requests.post(f"{settings.OLLAMA_URL}/api/chat", timeout=settings.LLM_TIMEOUT, json={
                "model": settings.OLLAMA_MODEL, "stream": False, "format": "json",
                "options": {"temperature": 0.1},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            r.raise_for_status()
            return r.json()["message"]["content"]
        except Exception as exc:  # network, model missing, bad JSON...
            log.warning("LLM call failed (%s); falling back to offline analyst", exc)
            return None


def get_llm() -> LLM:
    return OllamaLLM() if settings.LLM_PROVIDER == "ollama" else LLM()


def parse_json_object(text: str | None) -> dict | None:
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    try:
        obj = json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None
