"""End-to-end scan pipeline: ingest -> rules -> graph/paths -> correlate -> score -> MITRE -> logs."""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from attack_paths.graph import build_graph, correlate, exposed_nodes, find_attack_paths, graph_relationships
from config.settings import settings
from core.models import Event, Resource, ScanResult
from ingestion.loader import load_cloud, load_events, parse_cloud, parse_events
from log_analyzer.analyzer import analyze_events
from log_analyzer.mitre import map_finding
from risk_engine.scoring import posture_score, score_finding, score_path
from rules import CloudEnv, run_rules

log = logging.getLogger(__name__)


def analyze(account: str, resources: list[Resource], events: list[Event]) -> ScanResult:
    env = CloudEnv(resources)
    findings = run_rules(env)
    graph = build_graph(env)
    paths = find_attack_paths(graph, findings)
    correlate(findings, paths)
    exposed = exposed_nodes(graph)
    for f in findings:
        score_finding(f, env, exposed)
        f.mitre = map_finding(f)
    for p in paths:
        score_path(p, findings)
    findings.sort(key=lambda f: f.risk_score, reverse=True)
    paths.sort(key=lambda p: p.risk_score, reverse=True)
    alerts = analyze_events(events)
    result = ScanResult(scan_id=uuid.uuid4().hex[:12], account=account, resources=resources, findings=findings,
                        attack_paths=paths, events=events, alerts=alerts, posture_score=posture_score(findings),
                        relationships=graph_relationships(graph))
    log.info("scan %s: %d findings, %d paths, %d alerts, posture %d", result.scan_id, len(findings), len(paths),
             len(alerts), result.posture_score)
    return result


def run_scan(cloud_path: Path | None = None, log_path: Path | None = None) -> ScanResult:
    account, resources = load_cloud(cloud_path or settings.CLOUD_DATA_PATH)
    return analyze(account, resources, load_events(log_path or settings.LOG_DATA_PATH))


def run_scan_from_text(cloud_json: str | bytes, log_json: str | bytes | None = None) -> ScanResult:
    account, resources = parse_cloud(cloud_json)
    events = parse_events(log_json) if log_json else load_events(settings.LOG_DATA_PATH)
    return analyze(account, resources, events)
