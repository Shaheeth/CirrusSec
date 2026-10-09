"""MITRE ATT&CK (cloud/enterprise) mappings. Only mapped where it makes sense - many findings are left unmapped on purpose."""
from __future__ import annotations

from core.models import Finding, MitreMapping

_T = {
    "T1530": ("Data from Cloud Storage", "Collection"),
    "T1133": ("External Remote Services", "Initial Access / Persistence"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1562.008": ("Impair Defenses: Disable or Modify Cloud Logs", "Defense Evasion"),
    "T1562.007": ("Impair Defenses: Disable or Modify Cloud Firewall", "Defense Evasion"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "Initial Access / Persistence / Privilege Escalation"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1136.003": ("Create Account: Cloud Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence / Privilege Escalation"),
    "T1098.001": ("Account Manipulation: Additional Cloud Credentials", "Persistence"),
    "T1485": ("Data Destruction", "Impact"),
}


def mapping(tid: str, why: str, limitations: str) -> MitreMapping:
    name, tactic = _T[tid]
    return MitreMapping(technique_id=tid, technique=name, tactic=tactic, why_relevant=why, limitations=limitations)


# Config-finding mappings: rule_id -> (technique, why, limitation)
FINDING_MAP = {
    "CSA-002": ("T1530", "Public buckets are directly readable, which is the precondition for collecting data from cloud storage.",
                "A misconfiguration is only the precondition; there is no evidence of data collection unless access logs show it."),
    "CSA-001": ("T1133", "An internet-exposed remote-admin service is an entry point adversaries use for initial access.",
                "Exposure is not exploitation; the technique applies only if an actor actually authenticates."),
    "CSA-007": ("T1190", "Internet-exposed services can be targeted by exploitation of vulnerabilities in them.",
                "Depends on a vulnerable service version, which this scanner does not assess."),
    "CSA-006": ("T1190", "A publicly reachable database can be targeted directly.",
                "Depends on credentials/vulnerabilities; configuration alone does not prove compromise."),
    "CSA-005": ("T1562.008", "Disabled or incomplete logging is the condition that lets cloud log tampering go unnoticed.",
                "A disabled trail may be a misconfiguration rather than an adversary action."),
    "CSA-004": ("T1078.004", "Stale long-lived access keys are valid credentials an adversary could reuse unnoticed.",
                "No evidence of misuse without activity logs."),
}


def map_finding(f: Finding) -> list[MitreMapping]:
    entry = FINDING_MAP.get(f.rule_id)
    return [mapping(entry[0], entry[1], entry[2])] if entry else []
