"""Transparent, explainable risk scoring.

score = (severity_base + exposure + sensitivity + privilege + attack_path) * confidence_factor, capped at 100.
Every factor is recorded in `risk_breakdown` so an analyst can see exactly why a score is what it is.
"""
from __future__ import annotations

from core.models import AttackPath, Finding, Severity
from rules.engine import CloudEnv

SEVERITY_BASE = {Severity.LOW: 15, Severity.MEDIUM: 35, Severity.HIGH: 55, Severity.CRITICAL: 75}
EXPOSURE_POINTS = 10
SENSITIVITY_POINTS = 8
PRIVILEGE_POINTS = 7
ATTACK_PATH_POINTS = 10


def level_for(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 35:
        return Severity.MEDIUM
    return Severity.LOW


def score_finding(f: Finding, env: CloudEnv, exposed: set[str]) -> None:
    res = env.get(f.resource_id)
    parts = [{"factor": "severity", "points": SEVERITY_BASE[f.severity], "reason": f"rule severity {f.severity.value}"}]
    if f.resource_id in exposed:
        parts.append({"factor": "exposure", "points": EXPOSURE_POINTS, "reason": "reachable from the internet in the resource graph"})
    if res and (res.get("contains_sensitive_data") or res.get("data_classification") in ("confidential", "restricted")):
        parts.append({"factor": "asset_sensitivity", "points": SENSITIVITY_POINTS, "reason": "resource holds sensitive data"})
    if f.evidence.get("wildcard"):
        parts.append({"factor": "privileges", "points": PRIVILEGE_POINTS, "reason": "wildcard (*) action grants full privileges"})
    if f.attack_path_ids:
        parts.append({"factor": "attack_path", "points": ATTACK_PATH_POINTS,
                      "reason": f"sits on potential attack path(s) {', '.join(f.attack_path_ids)}"})
    raw = sum(p["points"] for p in parts)
    factor = round(0.7 + 0.3 * f.confidence, 2)
    if factor != 1.0:
        parts.append({"factor": "confidence", "points": 0, "reason": f"scaled by x{factor} (rule confidence {f.confidence})"})
    f.risk_score = min(100, round(raw * factor))
    f.risk_level = level_for(f.risk_score)
    f.risk_breakdown = parts


def score_path(p: AttackPath, findings: list[Finding]) -> None:
    linked = [f for f in findings if f.finding_id in set(p.finding_ids)]
    if not linked:
        p.risk_score, p.severity = 0, Severity.LOW
        return
    mean = sum(f.risk_score for f in linked) / len(linked)
    p.risk_score = min(100, round(mean + min(10, 2 * len(linked))))  # more linked findings = more ways in
    p.severity = level_for(p.risk_score)


def posture_score(findings: list[Finding]) -> int:
    """100 = no findings. Each finding subtracts risk/15 points (floored at 0)."""
    return max(0, round(100 - sum(f.risk_score / 15 for f in findings)))
