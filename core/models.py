"""Shared data models used by every layer (rules, graph, AI, DB, API, UI)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Resource(BaseModel):
    """A normalized cloud resource. Type-specific attributes live in `properties`."""

    resource_type: str
    resource_id: str
    properties: dict[str, Any] = Field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.properties.get(key, default)


class MitreMapping(BaseModel):
    technique_id: str
    technique: str
    tactic: str
    why_relevant: str
    limitations: str


class Finding(BaseModel):
    """A deterministic, evidence-backed security finding (FACT)."""

    finding_id: str
    rule_id: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    severity: Severity
    confidence: float = 1.0  # 0..1 - how sure the rule is (config facts are usually 1.0)
    category: str  # iam | network | storage | database | logging | compute
    evidence: dict[str, Any] = Field(default_factory=dict)
    affected_resource: str = ""
    security_control: str = ""
    why_it_matters: str = ""
    potential_impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=now_utc)
    # Filled in later by the pipeline
    risk_score: int = 0
    risk_level: Severity = Severity.LOW
    risk_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    attack_path_ids: list[str] = Field(default_factory=list)
    mitre: list[MitreMapping] = Field(default_factory=list)


class AttackPath(BaseModel):
    """A POTENTIAL attack path through the resource graph (never proof of attack)."""

    path_id: str
    entry_point: str
    target: str
    nodes: list[str]
    node_types: list[str]
    steps: list[str]
    finding_ids: list[str]
    severity: Severity = Severity.LOW
    risk_score: int = 0
    impact: str = ""
    narrative: str = ""


class Event(BaseModel):
    event_id: str
    event_time: datetime
    event_name: str
    event_source: str = ""
    user: str
    source_ip: str
    user_agent: str = ""
    region: str = "us-east-1"
    resource: str = ""
    error: str = ""
    params: dict[str, Any] = Field(default_factory=dict)


class Alert(BaseModel):
    """Suspicious-activity alert from log analysis (activity analysis, not config analysis)."""

    alert_id: str
    title: str
    severity: Severity
    actor: str
    source_ip: str
    event_ids: list[str]
    evidence: list[str]
    explanation: str
    mitre: list[MitreMapping] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str
    account: str
    scanned_at: datetime = Field(default_factory=now_utc)
    resources: list[Resource]
    findings: list[Finding]
    attack_paths: list[AttackPath]
    events: list[Event]
    alerts: list[Alert]
    posture_score: int
    relationships: list[dict[str, Any]] = Field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.finding_id == finding_id), None)

    def resource(self, resource_id: str) -> Resource | None:
        return next((r for r in self.resources if r.resource_id == resource_id), None)
