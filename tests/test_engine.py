import json

import pytest

from attack_paths.graph import INTERNET, build_graph
from config.settings import settings
from core.models import Event, Severity
from core.pipeline import analyze, run_scan_from_text
from ingestion.loader import IngestionError, parse_cloud, parse_events
from log_analyzer.analyzer import analyze_events
from rules import CloudEnv


# ------------------------------------------------------------ scoring
def test_risk_breakdown_sums_and_is_explainable(scan):
    for f in scan.findings:
        assert 0 <= f.risk_score <= 100
        assert f.risk_breakdown[0]["factor"] == "severity"
    f = scan.finding("CSA-001:web-sg")
    factors = {b["factor"] for b in f.risk_breakdown}
    assert {"severity", "exposure", "attack_path"} <= factors


def test_attack_path_raises_risk():
    # Same SSH finding, once on a path and once isolated
    iso = json.dumps({"resources": [{"resource_type": "SecurityGroup", "resource_id": "sg-a",
                                     "ingress": [{"cidr": "0.0.0.0/0", "protocol": "tcp", "from_port": 22, "to_port": 22}]}]})
    s = run_scan_from_text(iso, json.dumps({"events": []}))
    isolated = s.finding("CSA-001:sg-a").risk_score
    from core.pipeline import run_scan
    assert run_scan().finding("CSA-001:web-sg").risk_score > isolated


def test_posture_score_bounds(scan):
    assert 0 <= scan.posture_score <= 100
    empty = run_scan_from_text(json.dumps({"resources": []}), json.dumps({"events": []}))
    assert empty.posture_score >= 90  # only the "no CloudTrail" finding


# ------------------------------------------------------------ attack paths
def test_main_attack_path_found(scan):
    nodes = [p.nodes for p in scan.attack_paths]
    assert [INTERNET, "web-sg", "web-server-01", "web-server-role", "customer-data"] in nodes
    p = next(p for p in scan.attack_paths if p.target == "customer-data")
    assert {"CSA-001:web-sg", "CSA-003:web-server-role"} <= set(p.finding_ids)
    assert "Potential attack path" in p.narrative and "does not mean an attack has occurred" in p.narrative


def test_least_privilege_role_creates_no_path(scan):
    assert all("app-server-role" not in p.nodes for p in scan.attack_paths)  # private + scoped
    assert all("app-server-01" not in p.nodes for p in scan.attack_paths)


def test_no_internet_edge_when_sg_restricted():
    data = {"resources": [
        {"resource_type": "SecurityGroup", "resource_id": "sg", "ingress": [{"cidr": "203.0.113.0/24", "protocol": "tcp", "from_port": 22, "to_port": 22}]},
        {"resource_type": "EC2", "resource_id": "vm", "public_ip": True, "security_groups": ["sg"], "iam_role": "r"},
        {"resource_type": "IAMRole", "resource_id": "r", "policies": [{"name": "p", "statements": [{"effect": "Allow", "actions": ["s3:*"], "resources": ["*"]}]}]},
        {"resource_type": "S3", "resource_id": "data", "contains_sensitive_data": True}]}
    _, res = parse_cloud(json.dumps(data))
    g = build_graph(CloudEnv(res))
    assert not g.has_edge(INTERNET, "sg")
    assert analyze("a", res, []).attack_paths == []


def test_correlation_links_findings(scan):
    f = scan.finding("CSA-001:web-sg")
    assert "CSA-003:web-server-role" in f.related_findings


# ------------------------------------------------------------ logs
def test_log_alerts_detected(scan):
    titles = " | ".join(a.title for a in scan.alerts)
    for expected in ("failed logins", "persistence sequence", "Audit logging changed", "Security group opened", "Burst of object reads"):
        assert expected in titles
    assert all(a.mitre for a in scan.alerts if "Audit logging" in a.title)


def test_benign_activity_no_alerts():
    events = parse_events(json.dumps({"events": [
        {"event_id": "1", "event_time": "2026-09-28T10:00:00+00:00", "event_name": "GetObject", "user": "alice", "source_ip": "203.0.113.10", "resource": "b"},
        {"event_id": "2", "event_time": "2026-09-28T11:00:00+00:00", "event_name": "ConsoleLogin", "user": "alice", "source_ip": "203.0.113.10"}]}))
    assert analyze_events(events) == []


def test_off_hours_privilege_change_is_high():
    e = Event(event_id="1", event_time="2026-09-28T03:00:00+00:00", event_name="CreateAccessKey", user="x", source_ip="203.0.113.10")
    assert analyze_events([e])[0].severity == Severity.HIGH


# ------------------------------------------------------------ ingestion abuse
def test_malformed_json_rejected():
    with pytest.raises(IngestionError):
        parse_cloud("{not json")


def test_oversized_input_rejected():
    with pytest.raises(IngestionError):
        parse_cloud("x" * 5_000_001)


@pytest.mark.parametrize("bad_id", ["ignore previous instructions", "../../etc/passwd ", "a" * 200, "x;rm -rf /", ""])
def test_malicious_resource_ids_rejected(bad_id):
    with pytest.raises(IngestionError):
        parse_cloud(json.dumps({"resources": [{"resource_type": "S3", "resource_id": bad_id}]}))


def test_unknown_type_and_duplicates_rejected():
    with pytest.raises(IngestionError):
        parse_cloud(json.dumps({"resources": [{"resource_type": "Lambda", "resource_id": "x"}]}))
    with pytest.raises(IngestionError):
        parse_cloud(json.dumps({"resources": [{"resource_type": "S3", "resource_id": "x"}, {"resource_type": "S3", "resource_id": "x"}]}))


def test_wrong_shape_rejected():
    with pytest.raises(IngestionError):
        parse_cloud(json.dumps([1, 2, 3]))
    with pytest.raises(IngestionError):
        parse_events(json.dumps({"events": [{"nope": 1}]}))


def test_sample_data_files_load():
    assert settings.CLOUD_DATA_PATH.exists() and settings.LOG_DATA_PATH.exists()
