"""Generate the synthetic CloudTrail-style log file (all IPs are documentation ranges, all data is fake)."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "logs" / "cloudtrail_sample.json"

CORP = "203.0.113.10"      # trusted office IP (TEST-NET-3)
ODD = "198.51.100.77"      # untrusted IP (TEST-NET-2)

events: list[dict] = []
n = 0


def add(ts: datetime, name: str, user: str, ip: str, source: str = "signin.amazonaws.com",
        resource: str = "", error: str = "", params: dict | None = None, ua: str = "console"):
    global n
    n += 1
    events.append({
        "event_id": f"evt-{n:03d}", "event_time": ts.isoformat(), "event_name": name,
        "event_source": source, "user": user, "source_ip": ip, "user_agent": ua,
        "resource": resource, "error": error, "params": params or {},
    })


day = datetime(2026, 9, 28, tzinfo=timezone.utc)

# --- Normal business-hours activity ---
add(day.replace(hour=9, minute=2), "ConsoleLogin", "alice-analyst", CORP)
add(day.replace(hour=9, minute=15), "GetObject", "alice-analyst", CORP, "s3.amazonaws.com", "marketing-assets")
add(day.replace(hour=10, minute=40), "PutObject", "alice-analyst", CORP, "s3.amazonaws.com", "marketing-assets")
add(day.replace(hour=14, minute=5), "AssumeRole", "app-server-01", "10.0.1.15", "sts.amazonaws.com", "app-server-role")

# --- Suspicious sequence (synthetic), next night ---
night = day + timedelta(days=1)
for i in range(4):
    add(night.replace(hour=2, minute=10 + i), "ConsoleLogin", "dev-user", ODD, error="Failed authentication")
add(night.replace(hour=2, minute=14), "ConsoleLogin", "dev-user", ODD)
add(night.replace(hour=2, minute=20), "CreateUser", "dev-user", ODD, "iam.amazonaws.com", "backup-admin")
add(night.replace(hour=2, minute=21), "AttachUserPolicy", "dev-user", ODD, "iam.amazonaws.com", "backup-admin",
    params={"policy": "AdministratorAccess"})
add(night.replace(hour=2, minute=22), "CreateAccessKey", "dev-user", ODD, "iam.amazonaws.com", "backup-admin")
for i in range(7):
    add(night.replace(hour=2, minute=30 + i), "GetObject", "backup-admin", ODD, "s3.amazonaws.com", "customer-data")
add(night.replace(hour=2, minute=45), "AuthorizeSecurityGroupIngress", "backup-admin", ODD, "ec2.amazonaws.com", "db-sg",
    params={"cidr": "0.0.0.0/0", "port": 5432})
add(night.replace(hour=2, minute=50), "StopLogging", "backup-admin", ODD, "cloudtrail.amazonaws.com", "main-trail")

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps({"events": events}, indent=2), encoding="utf-8")
print(f"wrote {len(events)} events to {OUT}")
