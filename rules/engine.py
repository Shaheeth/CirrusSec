"""Rule engine: a rule is Input (CloudEnv) -> Condition -> Detection -> Finding(+evidence+remediation)."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

from core.models import Finding, Resource, Severity

log = logging.getLogger(__name__)


class CloudEnv:
    """Read-only index over the normalized resources, handed to every rule."""

    def __init__(self, resources: list[Resource]):
        self.resources = resources
        self._by_id = {r.resource_id: r for r in resources}

    def by_type(self, *types: str) -> list[Resource]:
        return [r for r in self.resources if r.resource_type in types]

    def get(self, resource_id: str) -> Resource | None:
        return self._by_id.get(resource_id)

    def sg_open_to_internet(self, sg_id: str) -> list[dict]:
        sg = self.get(sg_id)
        if not sg:
            return []
        return [r for r in sg.get("ingress", []) if r.get("cidr") in ("0.0.0.0/0", "::/0")]


@dataclass
class Rule:
    rule_id: str
    title: str
    category: str
    security_control: str
    why_it_matters: str
    potential_impact: str
    remediation: str
    references: list[str]
    check: Callable[[CloudEnv, "Rule"], list[Finding]]

    def finding(self, resource: Resource, severity: Severity, description: str, evidence: dict,
                confidence: float = 1.0, title: str | None = None) -> Finding:
        return Finding(
            finding_id=f"{self.rule_id}:{resource.resource_id}",
            rule_id=self.rule_id, title=title or self.title, description=description,
            resource_id=resource.resource_id, resource_type=resource.resource_type,
            severity=severity, confidence=confidence, category=self.category, evidence=evidence,
            affected_resource=f"{resource.resource_type}/{resource.resource_id}",
            security_control=self.security_control, why_it_matters=self.why_it_matters,
            potential_impact=self.potential_impact, remediation=self.remediation,
            references=self.references,
        )


REGISTRY: list[Rule] = []


def register(rule: Rule) -> Rule:
    REGISTRY.append(rule)
    return rule


def run_rules(env: CloudEnv, rules: list[Rule] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules or REGISTRY:
        try:
            findings.extend(rule.check(env, rule))
        except Exception:  # one broken rule must not stop the scan
            log.exception("rule %s failed", rule.rule_id)
    return findings
