"""The 10 deterministic AWS posture rules. Importing this module registers them.

CIS references are approximate pointers to the CIS AWS Foundations Benchmark; verify the control
number against the benchmark version you use.
"""
from __future__ import annotations

from typing import Iterator

from config.settings import settings
from core.models import Finding, Resource, Severity, SEVERITY_ORDER
from rules.engine import CloudEnv, Rule, register

SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}
DANGEROUS_IAM = {"iam:*", "iam:passrole", "iam:createaccesskey", "iam:attachuserpolicy",
                 "iam:putuserpolicy", "sts:assumerole"}

AWS_DOCS = "https://docs.aws.amazon.com"


# ---------------------------------------------------------------- helpers
def _covers(rule: dict, port: int) -> bool:
    proto = str(rule.get("protocol", "tcp")).lower()
    if proto not in ("tcp", "-1", "all"):
        return False
    lo, hi = int(rule.get("from_port", 0)), int(rule.get("to_port", 65535))
    return proto in ("-1", "all") or lo <= port <= hi


def _all_traffic(rule: dict) -> bool:
    proto = str(rule.get("protocol", "tcp")).lower()
    lo, hi = int(rule.get("from_port", 0)), int(rule.get("to_port", 65535))
    return proto in ("-1", "all") or (hi - lo) >= 1000


def _statements(res: Resource) -> Iterator[tuple[str, dict]]:
    for pol in res.get("policies", []):
        for st in pol.get("statements", []):
            yield pol.get("name", "unnamed-policy"), st


def _lower(items) -> list[str]:
    return [str(a).lower() for a in items]


def _is_sensitive(res: Resource) -> bool:
    return bool(res.get("contains_sensitive_data")) or res.get("data_classification") in ("confidential", "restricted", "pii")


def _worst(*sevs: Severity) -> Severity:
    return max(sevs, key=lambda s: SEVERITY_ORDER[s])


def internet_ingress(env: CloudEnv):
    for sg in env.by_type("SecurityGroup"):
        for rule in env.sg_open_to_internet(sg.resource_id):
            yield sg, rule


# ---------------------------------------------------------------- rules
def check_ssh_open(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    for sg in env.by_type("SecurityGroup"):
        bad = [r for r in env.sg_open_to_internet(sg.resource_id) if _covers(r, 22) and not _all_traffic(r)]
        if bad:
            out.append(rule.finding(sg, Severity.HIGH,
                       f"Security group {sg.resource_id} allows SSH (TCP/22) from anywhere on the internet.",
                       {"offending_rules": bad, "condition": "ingress 0.0.0.0/0 TCP 22"}))
    return out


def check_public_s3(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    for b in env.by_type("S3"):
        if b.get("public_access"):
            sev = Severity.CRITICAL if _is_sensitive(b) else Severity.HIGH
            out.append(rule.finding(b, sev,
                       f"S3 bucket {b.resource_id} allows public access"
                       + (" and is classified as holding sensitive data." if _is_sensitive(b) else "."),
                       {"public_access": True, "data_classification": b.get("data_classification"),
                        "contains_sensitive_data": bool(b.get("contains_sensitive_data"))}))
    return out


def check_permissive_iam(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    for p in env.by_type("IAMRole", "IAMUser"):
        hits, sev, wildcard = [], Severity.LOW, False
        for pol_name, st in _statements(p):
            if str(st.get("effect", "Allow")).lower() != "allow":
                continue
            actions = _lower(st.get("actions", []))
            resources = [str(r) for r in st.get("resources", [])]
            if "*" not in resources:
                continue
            if "*" in actions:
                hits.append({"policy": pol_name, "actions": actions, "resources": resources})
                sev, wildcard = _worst(sev, Severity.CRITICAL), True
            elif any(a.endswith(":*") for a in actions):
                hits.append({"policy": pol_name, "actions": actions, "resources": resources})
                sev = _worst(sev, Severity.HIGH)
            elif any(a in DANGEROUS_IAM for a in actions):
                hits.append({"policy": pol_name, "actions": actions, "resources": resources})
                sev = _worst(sev, Severity.HIGH)
        if hits:
            out.append(rule.finding(p, sev,
                       f"{p.resource_type} {p.resource_id} has policy statements granting wildcard permissions on all resources.",
                       {"statements": hits, "wildcard": wildcard}))
    return out


def check_unused_keys(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    limit = settings.UNUSED_KEY_DAYS
    for u in env.by_type("IAMUser"):
        stale = []
        for k in u.get("access_keys", []):
            age = k.get("last_used_days_ago")
            if k.get("active", True) and (age is None or age > limit):
                stale.append({"key_id": k.get("key_id"), "last_used_days_ago": age})
        if stale:
            out.append(rule.finding(u, Severity.MEDIUM,
                       f"IAM user {u.resource_id} has active access keys unused for more than {limit} days.",
                       {"stale_keys": stale, "threshold_days": limit}))
    return out


def check_cloudtrail(env: CloudEnv, rule: Rule) -> list[Finding]:
    trails = env.by_type("CloudTrail")
    if not trails:
        ghost = Resource(resource_type="CloudTrail", resource_id="no-trail-configured")
        return [rule.finding(ghost, Severity.HIGH, "No CloudTrail trail exists in this environment.",
                             {"trails_found": 0})]
    out = []
    for t in trails:
        issues, sev = [], Severity.LOW
        if not t.get("enabled", False):
            issues.append("trail is not logging (disabled)")
            sev = _worst(sev, Severity.HIGH)
        if not t.get("multi_region", False):
            issues.append("trail is not multi-region")
            sev = _worst(sev, Severity.MEDIUM)
        if not t.get("log_file_validation", False):
            issues.append("log file integrity validation is off")
            sev = _worst(sev, Severity.LOW)
        if issues:
            out.append(rule.finding(t, sev, f"CloudTrail {t.resource_id}: " + "; ".join(issues) + ".",
                       {"enabled": t.get("enabled", False), "multi_region": t.get("multi_region", False),
                        "log_file_validation": t.get("log_file_validation", False)}))
    return out


def check_public_db(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    for db in env.by_type("RDS"):
        if db.get("publicly_accessible"):
            sev = Severity.CRITICAL if _is_sensitive(db) else Severity.HIGH
            out.append(rule.finding(db, sev,
                       f"RDS instance {db.resource_id} ({db.get('engine', 'unknown engine')}) is publicly accessible.",
                       {"publicly_accessible": True, "security_groups": db.get("security_groups", [])}))
    return out


def check_sensitive_ports(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    for sg in env.by_type("SecurityGroup"):
        ports, all_open, offending = {}, False, []
        for r in env.sg_open_to_internet(sg.resource_id):
            if _all_traffic(r):
                all_open = True
                offending.append(r)
                continue
            for port, name in SENSITIVE_PORTS.items():
                if _covers(r, port):
                    ports[port] = name
                    offending.append(r)
        if all_open or ports:
            sev = Severity.CRITICAL if all_open else Severity.HIGH
            desc = ("allows ALL traffic/port ranges from the internet" if all_open else
                    "exposes sensitive service ports to the internet: " + ", ".join(f"{p}/{n}" for p, n in sorted(ports.items())))
            out.append(rule.finding(sg, sev, f"Security group {sg.resource_id} {desc}.",
                       {"sensitive_ports": {str(p): n for p, n in ports.items()}, "all_traffic_open": all_open,
                        "offending_rules": offending}))
    return out


def check_user_excessive(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    for u in env.by_type("IAMUser"):
        broad = [pol for pol, st in _statements(u)
                 if str(st.get("effect", "Allow")).lower() == "allow"
                 and any(a == "*" or a.endswith(":*") for a in _lower(st.get("actions", [])))
                 and "*" in [str(r) for r in st.get("resources", [])]]
        if u.get("console_access") and not u.get("mfa_enabled") and broad:
            out.append(rule.finding(u, Severity.HIGH,
                       f"IAM user {u.resource_id} has console access and broad permissions but no MFA.",
                       {"mfa_enabled": False, "console_access": True, "broad_policies": sorted(set(broad))}))
    return out


def check_encryption(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    checks = {"S3": ("encrypted", "bucket default encryption"), "RDS": ("storage_encrypted", "storage encryption"),
              "EC2": ("root_volume_encrypted", "root volume encryption")}
    for res in env.by_type(*checks):
        key, label = checks[res.resource_type]
        if res.get(key) is False:
            sev = Severity.HIGH if _is_sensitive(res) else Severity.MEDIUM
            out.append(rule.finding(res, sev, f"{res.resource_type} {res.resource_id} has {label} disabled.",
                                    {key: False, "contains_sensitive_data": _is_sensitive(res)}))
    return out


def check_exposed_compute(env: CloudEnv, rule: Rule) -> list[Finding]:
    out = []
    for vm in env.by_type("EC2"):
        if not vm.get("public_ip") or not vm.get("iam_role"):
            continue
        open_rules = [r for sg in vm.get("security_groups", []) for r in env.sg_open_to_internet(sg)]
        if not open_rules:
            continue
        web_only = all(int(r.get("from_port", 0)) == int(r.get("to_port", 0)) and int(r.get("from_port", 0)) in (80, 443)
                       for r in open_rules)
        out.append(rule.finding(vm, Severity.MEDIUM,
                   f"EC2 instance {vm.resource_id} is reachable from the internet and holds credentials for IAM role {vm.get('iam_role')}.",
                   {"public_ip": True, "iam_role": vm.get("iam_role"), "internet_open_rules": open_rules},
                   confidence=0.6 if web_only else 1.0))
    return out


# ---------------------------------------------------------------- registration
register(Rule("CSA-001", "SSH exposed to the internet", "network", "CIS AWS 5.2 (remote admin ports)",
    "SSH is a remote-administration channel. Open to 0.0.0.0/0 it is continuously scanned and brute-forced.",
    "Remote shell access to instances; foothold for credential theft from the instance and lateral movement.",
    "Restrict TCP/22 to a bastion/VPN CIDR or remove it and use SSM Session Manager. Revoke the 0.0.0.0/0 rule.",
    [f"{AWS_DOCS}/AWSEC2/latest/UserGuide/security-group-rules.html", "https://attack.mitre.org/techniques/T1133/"],
    check_ssh_open))
register(Rule("CSA-002", "Public S3 bucket", "storage", "CIS AWS 2.1.x (S3 public access)",
    "Public buckets can be listed or read by anyone; misconfigured buckets are a leading cause of cloud data leaks.",
    "Unauthorised disclosure of stored data; regulatory and reputational damage if the data is sensitive.",
    "Enable S3 Block Public Access on the bucket and account, remove public ACLs/policies, serve public content via CloudFront if needed.",
    [f"{AWS_DOCS}/AmazonS3/latest/userguide/access-control-block-public-access.html", "https://attack.mitre.org/techniques/T1530/"],
    check_public_s3))
register(Rule("CSA-003", "Overly permissive IAM policy", "iam", "CIS AWS 1.16 (no full '*:*' admin policies)",
    "Wildcard actions on all resources violate least privilege: any compromise of the identity inherits every permission.",
    "A compromised identity can read/modify/delete across the account, escalate privileges or create persistence.",
    "Replace wildcards with the specific actions and resource ARNs the workload needs. Use IAM Access Analyzer to generate least-privilege policies.",
    [f"{AWS_DOCS}/IAM/latest/UserGuide/best-practices.html"], check_permissive_iam))
register(Rule("CSA-004", "Unused IAM access key", "iam", "CIS AWS 1.14 (rotate/disable stale keys)",
    "Long-lived credentials that nobody uses are never noticed when stolen and widen the attack surface.",
    "Stolen or leaked key stays valid and goes unnoticed; abuse can persist for months.",
    "Deactivate then delete unused keys; prefer roles / short-lived credentials; rotate required keys every 90 days.",
    [f"{AWS_DOCS}/IAM/latest/UserGuide/id_credentials_access-keys.html", "https://attack.mitre.org/techniques/T1078/004/"],
    check_unused_keys))
register(Rule("CSA-005", "CloudTrail disabled or misconfigured", "logging", "CIS AWS 3.1 (CloudTrail in all regions)",
    "CloudTrail is the audit log of API activity. Without it, incidents cannot be detected or investigated.",
    "Attacker actions are invisible; forensics and compliance evidence are lost.",
    "Enable a multi-region trail with log file validation, deliver to a protected S3 bucket and alert on StopLogging/DeleteTrail.",
    [f"{AWS_DOCS}/awscloudtrail/latest/userguide/cloudtrail-user-guide.html", "https://attack.mitre.org/techniques/T1562/008/"],
    check_cloudtrail))
register(Rule("CSA-006", "Database publicly accessible", "database", "CIS AWS 2.3.x (RDS not public)",
    "A database reachable from the internet exposes its login surface to brute force and exploitation.",
    "Direct attack against the data store; data theft or ransomware.",
    "Set PubliclyAccessible=false, place the DB in private subnets and allow only application security groups.",
    [f"{AWS_DOCS}/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"], check_public_db))
register(Rule("CSA-007", "Sensitive ports open to the internet", "network", "CIS AWS 5.x (restrict ingress)",
    "Database, RDP, SMB and cache ports are not designed to face the internet and are heavily scanned.",
    "Direct exploitation or credential attacks against internal services.",
    "Remove 0.0.0.0/0 rules for these ports; restrict to specific source security groups or CIDRs.",
    [f"{AWS_DOCS}/vpc/latest/userguide/vpc-security-groups.html"], check_sensitive_ports))
register(Rule("CSA-008", "IAM user with excessive permissions and no MFA", "iam", "CIS AWS 1.10 (MFA for console users)",
    "Privileged console users without MFA are protected by a single password.",
    "Phished or reused password gives an attacker broad account control.",
    "Enforce MFA, remove direct wildcard policies, use roles/groups with least privilege.",
    [f"{AWS_DOCS}/IAM/latest/UserGuide/id_credentials_mfa.html"], check_user_excessive))
register(Rule("CSA-009", "Missing encryption at rest", "storage", "CIS AWS 2.1.1 / 2.2.1 / 2.3.1 (encryption at rest)",
    "Encryption at rest limits the value of leaked snapshots, disks or storage media and is a common compliance requirement.",
    "Data exposure if storage is copied, snapshotted or shared incorrectly.",
    "Enable default encryption (SSE-S3/KMS for S3, storage encryption for RDS, EBS encryption by default). Existing RDS/EBS need snapshot-copy to encrypt.",
    [f"{AWS_DOCS}/AmazonS3/latest/userguide/bucket-encryption.html"], check_encryption))
register(Rule("CSA-010", "Internet-reachable instance with IAM role credentials", "compute", "AWS Well-Architected SEC 5 (protect networks)",
    "Instances carry role credentials via the metadata service. If an internet-facing instance is compromised those credentials can be stolen.",
    "Pivot from the instance to every AWS resource its role can reach (see attack paths).",
    "Reduce exposure (load balancer/WAF, private subnets), enforce IMDSv2, and shrink the instance role to least privilege.",
    [f"{AWS_DOCS}/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"], check_exposed_compute))
