from tests.helpers import env_of, sg
from core.models import Resource, Severity
from rules import run_rules


def ids(findings):
    return {f.rule_id for f in findings}


def test_ssh_open_to_internet_is_high():
    f = [x for x in run_rules(env_of(sg())) if x.rule_id == "CSA-001"]
    assert len(f) == 1 and f[0].severity == Severity.HIGH and f[0].evidence["offending_rules"]


def test_ssh_restricted_has_no_finding():
    assert "CSA-001" not in ids(run_rules(env_of(sg(cidr="203.0.113.0/24"))))


def test_ssh_range_covering_22_detected():
    assert "CSA-001" in ids(run_rules(env_of(sg(port=20, to_port=30))))


def test_https_only_is_clean():
    assert ids(run_rules(env_of(sg(port=443)))) <= {"CSA-005"}  # only the missing-CloudTrail finding


def test_database_port_open_is_high():
    f = [x for x in run_rules(env_of(sg(port=5432))) if x.rule_id == "CSA-007"]
    assert f and f[0].severity == Severity.HIGH


def test_all_traffic_is_critical():
    f = [x for x in run_rules(env_of(sg(port=0, to_port=65535, proto="-1"))) if x.rule_id == "CSA-007"]
    assert f and f[0].severity == Severity.CRITICAL


def test_public_sensitive_bucket_critical_and_private_clean():
    pub = Resource(resource_type="S3", resource_id="b1", properties={"public_access": True, "contains_sensitive_data": True, "encrypted": True})
    priv = Resource(resource_type="S3", resource_id="b2", properties={"public_access": False, "encrypted": True})
    f = [x for x in run_rules(env_of(pub, priv)) if x.rule_id == "CSA-002"]
    assert [x.resource_id for x in f] == ["b1"] and f[0].severity == Severity.CRITICAL


def test_wildcard_iam_policy_critical_and_scoped_policy_clean():
    bad = Resource(resource_type="IAMRole", resource_id="r1", properties={"policies": [{"name": "p", "statements": [
        {"effect": "Allow", "actions": ["*"], "resources": ["*"]}]}]})
    good = Resource(resource_type="IAMRole", resource_id="r2", properties={"policies": [{"name": "p", "statements": [
        {"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::x/*"]}]}]})
    f = [x for x in run_rules(env_of(bad, good)) if x.rule_id == "CSA-003"]
    assert [x.resource_id for x in f] == ["r1"] and f[0].severity == Severity.CRITICAL and f[0].evidence["wildcard"]


def test_service_wildcard_is_high():
    r = Resource(resource_type="IAMRole", resource_id="r", properties={"policies": [{"name": "p", "statements": [
        {"effect": "Allow", "actions": ["s3:*"], "resources": ["*"]}]}]})
    f = [x for x in run_rules(env_of(r)) if x.rule_id == "CSA-003"]
    assert f[0].severity == Severity.HIGH


def test_deny_statement_not_flagged():
    r = Resource(resource_type="IAMRole", resource_id="r", properties={"policies": [{"name": "p", "statements": [
        {"effect": "Deny", "actions": ["*"], "resources": ["*"]}]}]})
    assert "CSA-003" not in ids(run_rules(env_of(r)))


def test_unused_key_threshold():
    old = Resource(resource_type="IAMUser", resource_id="u1", properties={"access_keys": [{"key_id": "K", "active": True, "last_used_days_ago": 120}]})
    new = Resource(resource_type="IAMUser", resource_id="u2", properties={"access_keys": [{"key_id": "K", "active": True, "last_used_days_ago": 5}]})
    inactive = Resource(resource_type="IAMUser", resource_id="u3", properties={"access_keys": [{"key_id": "K", "active": False, "last_used_days_ago": 500}]})
    assert {f.resource_id for f in run_rules(env_of(old, new, inactive)) if f.rule_id == "CSA-004"} == {"u1"}


def test_cloudtrail_cases():
    off = Resource(resource_type="CloudTrail", resource_id="t", properties={"enabled": False, "multi_region": True, "log_file_validation": True})
    good = Resource(resource_type="CloudTrail", resource_id="t", properties={"enabled": True, "multi_region": True, "log_file_validation": True})
    assert [f.severity for f in run_rules(env_of(off)) if f.rule_id == "CSA-005"] == [Severity.HIGH]
    assert "CSA-005" not in ids(run_rules(env_of(good)))
    assert "CSA-005" in ids(run_rules(env_of()))  # no trail at all


def test_public_rds_and_private_rds():
    pub = Resource(resource_type="RDS", resource_id="d1", properties={"publicly_accessible": True, "storage_encrypted": True})
    priv = Resource(resource_type="RDS", resource_id="d2", properties={"publicly_accessible": False, "storage_encrypted": True})
    assert {f.resource_id for f in run_rules(env_of(pub, priv)) if f.rule_id == "CSA-006"} == {"d1"}


def test_user_without_mfa_and_admin():
    u = Resource(resource_type="IAMUser", resource_id="u", properties={"console_access": True, "mfa_enabled": False, "policies": [
        {"name": "a", "statements": [{"effect": "Allow", "actions": ["*"], "resources": ["*"]}]}]})
    ok = Resource(resource_type="IAMUser", resource_id="u2", properties={"console_access": True, "mfa_enabled": True, "policies": u.properties["policies"]})
    assert {f.resource_id for f in run_rules(env_of(u, ok)) if f.rule_id == "CSA-008"} == {"u"}


def test_encryption_rule():
    s3 = Resource(resource_type="S3", resource_id="b", properties={"encrypted": False})
    ok = Resource(resource_type="S3", resource_id="b2", properties={"encrypted": True})
    assert {f.resource_id for f in run_rules(env_of(s3, ok)) if f.rule_id == "CSA-009"} == {"b"}


def test_exposed_instance_with_role_confidence():
    s = sg("web", port=443)
    vm = Resource(resource_type="EC2", resource_id="vm", properties={"public_ip": True, "security_groups": ["web"], "iam_role": "r"})
    f = [x for x in run_rules(env_of(s, vm)) if x.rule_id == "CSA-010"]
    assert f and f[0].confidence < 1.0  # web-only exposure => lower confidence


def test_every_finding_has_required_fields(scan):
    for f in scan.findings:
        assert f.finding_id and f.title and f.evidence and f.remediation and f.references and f.security_control
