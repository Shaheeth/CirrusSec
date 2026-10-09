"""Load + validate + normalize cloud and log data.

Cloud data is treated as UNTRUSTED input: it is size-limited, schema-checked and resource IDs are
restricted to a safe character set (this also blocks prompt-injection text hidden in identifiers).
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from core.models import Event, Resource

log = logging.getLogger(__name__)

ALLOWED_TYPES = {"VPC", "SecurityGroup", "EC2", "S3", "IAMUser", "IAMRole", "RDS", "CloudTrail"}
ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,127}$")
MAX_RESOURCES = 5000
MAX_EVENTS = 50_000
MAX_BYTES = 5_000_000


class IngestionError(ValueError):
    """Raised when input data is malformed or unsafe."""


def _parse_json(raw: str | bytes) -> Any:
    if len(raw) > MAX_BYTES:
        raise IngestionError(f"input too large ({len(raw)} bytes, limit {MAX_BYTES})")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IngestionError(f"malformed JSON: {exc}") from exc


def parse_cloud(raw: str | bytes) -> tuple[str, list[Resource]]:
    data = _parse_json(raw)
    if not isinstance(data, dict) or not isinstance(data.get("resources"), list):
        raise IngestionError("cloud data must be an object with a 'resources' list")
    items = data["resources"]
    if len(items) > MAX_RESOURCES:
        raise IngestionError(f"too many resources ({len(items)}, limit {MAX_RESOURCES})")

    resources: list[Resource] = []
    seen: set[str] = set()
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise IngestionError(f"resource #{i} is not an object")
        rtype, rid = item.get("resource_type"), item.get("resource_id")
        if rtype not in ALLOWED_TYPES:
            raise IngestionError(f"resource #{i}: unsupported resource_type {str(rtype)[:40]!r}")
        if not isinstance(rid, str) or not ID_PATTERN.match(rid):
            raise IngestionError(f"resource #{i}: invalid resource_id (allowed: letters, digits, . _ : / -)")
        if rid in seen:
            raise IngestionError(f"duplicate resource_id {rid!r}")
        seen.add(rid)
        props = {k: v for k, v in item.items() if k not in ("resource_type", "resource_id")}
        resources.append(Resource(resource_type=rtype, resource_id=rid, properties=props))

    account = str(data.get("account", "unknown-account"))[:100]
    log.info("loaded %d resources for account %s", len(resources), account)
    return account, resources


def parse_events(raw: str | bytes) -> list[Event]:
    data = _parse_json(raw)
    items = data.get("events") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise IngestionError("log data must be a list or an object with an 'events' list")
    if len(items) > MAX_EVENTS:
        raise IngestionError(f"too many events ({len(items)}, limit {MAX_EVENTS})")
    events: list[Event] = []
    for i, item in enumerate(items):
        try:
            events.append(Event(**item))
        except (ValidationError, TypeError) as exc:
            raise IngestionError(f"event #{i} invalid: {str(exc)[:150]}") from exc
    return sorted(events, key=lambda e: e.event_time)


def load_cloud(path: Path) -> tuple[str, list[Resource]]:
    return parse_cloud(Path(path).read_text(encoding="utf-8"))


def load_events(path: Path) -> list[Event]:
    p = Path(path)
    if not p.exists():
        log.warning("log file %s not found; continuing without activity data", p)
        return []
    return parse_events(p.read_text(encoding="utf-8"))
