"""Cloud ACTIVITY analysis over CloudTrail-style events.

Configuration analysis asks "is the environment set up safely?"; activity analysis asks "what has happened?".
Alerts here are indicators that warrant investigation - not proof of compromise.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta

from config.settings import settings
from core.models import Alert, Event, Severity
from log_analyzer.mitre import mapping

PRIVILEGE_EVENTS = {"CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
                    "PutRolePolicy", "CreateLoginProfile"}
DEFENSE_EVASION = {"StopLogging", "DeleteTrail", "UpdateTrail"}


def is_trusted_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c, strict=False) for c in settings.TRUSTED_CIDRS)


def is_off_hours(e: Event) -> bool:
    lo, hi = settings.BUSINESS_HOURS_UTC
    return not (lo <= e.event_time.hour < hi)


class _Alerts:
    def __init__(self) -> None:
        self.items: list[Alert] = []

    def add(self, title, severity, actor, ip, events, evidence, explanation, mitre=None) -> None:
        self.items.append(Alert(alert_id=f"ALR-{len(self.items) + 1:03d}", title=title, severity=severity, actor=actor,
                                source_ip=ip, event_ids=[e.event_id for e in events], evidence=evidence,
                                explanation=explanation, mitre=mitre or []))


def analyze_events(events: list[Event]) -> list[Alert]:
    a = _Alerts()
    events = sorted(events, key=lambda e: e.event_time)

    # 1. Failed logins followed by success (possible brute force / credential stuffing)
    logins = defaultdict(list)
    for e in events:
        if e.event_name == "ConsoleLogin":
            logins[(e.user, e.source_ip)].append(e)
    for (user, ip), evs in logins.items():
        fails = [e for e in evs if e.error]
        succ = [e for e in evs if not e.error and fails and e.event_time >= fails[0].event_time]
        if len(fails) >= 3 and succ:
            a.add("Repeated failed logins followed by a successful login", Severity.HIGH, user, ip, fails + succ[:1],
                  [f"{len(fails)} failed ConsoleLogin attempts from {ip}", f"successful login at {succ[0].event_time.isoformat()}"],
                  "Pattern consistent with password guessing that eventually succeeded. Verify with the account owner.",
                  [mapping("T1110", "Multiple failed authentications followed by success match password guessing.",
                           "Could also be a user mistyping a password; confirm source IP and user intent.")])

    # 2. Successful sign-in / role use from untrusted IPs
    for e in events:
        if e.event_name in ("ConsoleLogin", "AssumeRole") and not e.error and not is_trusted_ip(e.source_ip):
            if e.event_name == "AssumeRole" and e.source_ip.startswith("10."):
                continue
            a.add(f"{e.event_name} from an untrusted IP address", Severity.MEDIUM, e.user, e.source_ip, [e],
                  [f"source IP {e.source_ip} is outside trusted ranges {settings.TRUSTED_CIDRS}"],
                  "Access from an IP outside known ranges. May be legitimate travel/VPN; validate before concluding anything.",
                  [mapping("T1078.004", "Cloud account used from an unfamiliar network location.",
                           "IP reputation/geolocation is not assessed; trusted ranges are configuration-based.")])

    # 3. Privilege changes (higher severity when off-hours or untrusted source)
    for e in events:
        if e.event_name in PRIVILEGE_EVENTS:
            risky = is_off_hours(e) or not is_trusted_ip(e.source_ip)
            tid = {"CreateUser": "T1136.003", "CreateAccessKey": "T1098.001"}.get(e.event_name, "T1098")
            ev = [f"{e.event_name} on {e.resource or 'n/a'} by {e.user}"]
            if is_off_hours(e):
                ev.append(f"performed off-hours ({e.event_time.strftime('%H:%M')} UTC)")
            if not is_trusted_ip(e.source_ip):
                ev.append(f"from untrusted IP {e.source_ip}")
            a.add(f"Privilege/identity change: {e.event_name}", Severity.HIGH if risky else Severity.LOW, e.user,
                  e.source_ip, [e], ev,
                  "Identity and permission changes can create persistence or escalate privileges; confirm they were approved.",
                  [mapping(tid, f"{e.event_name} alters accounts or credentials.",
                           "Routine administration produces the same events; context (who/when/where) decides.")])

    # 4. Sequence: CreateUser -> AttachUserPolicy -> CreateAccessKey by one actor within 60 minutes
    by_actor = defaultdict(list)
    for e in events:
        if e.event_name in ("CreateUser", "AttachUserPolicy", "CreateAccessKey"):
            by_actor[e.user].append(e)
    for actor, evs in by_actor.items():
        names = [e.event_name for e in evs]
        if all(n in names for n in ("CreateUser", "AttachUserPolicy", "CreateAccessKey")):
            if evs[-1].event_time - evs[0].event_time <= timedelta(minutes=60):
                a.add("Possible persistence sequence: new user, policy attached, access key created",
                      Severity.HIGH, actor, evs[0].source_ip, evs,
                      [f"{e.event_time.strftime('%H:%M:%S')} {e.event_name} {e.resource}" for e in evs],
                      "This sequence is a common way to create a backdoor identity. Review the new identity and its permissions.",
                      [mapping("T1136.003", "Creating a new cloud account followed by credentials and permissions matches backdoor-account creation.",
                               "An administrator onboarding someone looks identical; check for a change ticket.")])

    # 5. Defense evasion
    for e in events:
        if e.event_name in DEFENSE_EVASION:
            a.add(f"Audit logging changed: {e.event_name}", Severity.CRITICAL, e.user, e.source_ip, [e],
                  [f"{e.event_name} on {e.resource}"],
                  "Stopping or altering CloudTrail removes visibility. Treat as high priority until explained.",
                  [mapping("T1562.008", "Disabling or modifying cloud logging reduces detection capability.",
                           "Could be planned maintenance; validate against change records.")])
        if e.event_name == "AuthorizeSecurityGroupIngress" and e.params.get("cidr") in ("0.0.0.0/0", "::/0"):
            a.add("Security group opened to the internet", Severity.HIGH, e.user, e.source_ip, [e],
                  [f"ingress 0.0.0.0/0 port {e.params.get('port')} on {e.resource}"],
                  "A security group rule was widened to the whole internet.",
                  [mapping("T1562.007", "Opening a firewall rule to everyone weakens network controls.",
                           "Mapping fits when done by an adversary; may also be an administrative mistake.")])
        if e.event_name == "DeleteBucket":
            a.add("S3 bucket deleted", Severity.HIGH, e.user, e.source_ip, [e], [f"DeleteBucket {e.resource}"],
                  "Bucket deletion is destructive; confirm it was intended.",
                  [mapping("T1485", "Deleting storage destroys data.", "Legitimate clean-up uses the same API call.")])

    # 6. Burst of object reads (>= 5 GetObject on the same bucket by one actor within 10 minutes)
    reads = defaultdict(list)
    for e in events:
        if e.event_name == "GetObject":
            reads[(e.user, e.resource)].append(e)
    for (user, bucket), evs in reads.items():
        for i in range(len(evs)):
            window = [x for x in evs[i:] if x.event_time - evs[i].event_time <= timedelta(minutes=10)]
            if len(window) >= 5:
                risky = any(not is_trusted_ip(x.source_ip) for x in window)
                a.add("Burst of object reads from a bucket", Severity.HIGH if risky else Severity.LOW, user,
                      window[0].source_ip, window,
                      [f"{len(window)} GetObject calls on {bucket} within 10 minutes"],
                      "Rapid repeated reads can indicate bulk data collection; compare with normal behaviour for this identity.",
                      [mapping("T1530", "Repeated reads from cloud storage match data collection.",
                               "Backups and batch jobs generate similar bursts; no baseline of normal volume is modelled.")])
                break
    return a.items
