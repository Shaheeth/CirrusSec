"""SQLite persistence. Parameterised queries only (no string-built SQL).

Tables: scan_history (PK scan_id) is the parent; resources, findings, relationships, attack_paths,
events, alerts reference it via scan_id (FK). ai_analysis and reports store AI output and generated files.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.models import ScanResult

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS scan_history (
  scan_id TEXT PRIMARY KEY, account TEXT, scanned_at TEXT, posture_score INTEGER, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS resources (
  scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE, resource_id TEXT, resource_type TEXT, properties TEXT,
  PRIMARY KEY (scan_id, resource_id));
CREATE TABLE IF NOT EXISTS findings (
  scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE, finding_id TEXT, rule_id TEXT, resource_id TEXT,
  severity TEXT, risk_score INTEGER, title TEXT, data TEXT, PRIMARY KEY (scan_id, finding_id));
CREATE TABLE IF NOT EXISTS relationships (
  scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE, source TEXT, target TEXT, relation TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS attack_paths (
  scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE, path_id TEXT, risk_score INTEGER, data TEXT,
  PRIMARY KEY (scan_id, path_id));
CREATE TABLE IF NOT EXISTS events (
  scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE, event_id TEXT, event_time TEXT, event_name TEXT,
  user TEXT, source_ip TEXT, data TEXT, PRIMARY KEY (scan_id, event_id));
CREATE TABLE IF NOT EXISTS alerts (
  scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE, alert_id TEXT, severity TEXT, data TEXT,
  PRIMARY KEY (scan_id, alert_id));
CREATE TABLE IF NOT EXISTS ai_analysis (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE,
  question TEXT, response TEXT, mode TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT REFERENCES scan_history(scan_id) ON DELETE CASCADE,
  path TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
"""


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.execute("PRAGMA foreign_keys = ON")
        return c

    def save_scan(self, s: ScanResult) -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO scan_history VALUES (?,?,?,?,?)",
                      (s.scan_id, s.account, s.scanned_at.isoformat(), s.posture_score, s.model_dump_json()))
            c.executemany("INSERT OR REPLACE INTO resources VALUES (?,?,?,?)",
                          [(s.scan_id, r.resource_id, r.resource_type, json.dumps(r.properties)) for r in s.resources])
            c.executemany("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?)",
                          [(s.scan_id, f.finding_id, f.rule_id, f.resource_id, f.severity.value, f.risk_score, f.title,
                            f.model_dump_json()) for f in s.findings])
            c.executemany("INSERT INTO relationships VALUES (?,?,?,?,?)",
                          [(s.scan_id, r["source"], r["target"], r.get("relation"), r.get("detail")) for r in s.relationships])
            c.executemany("INSERT OR REPLACE INTO attack_paths VALUES (?,?,?,?)",
                          [(s.scan_id, p.path_id, p.risk_score, p.model_dump_json()) for p in s.attack_paths])
            c.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?)",
                          [(s.scan_id, e.event_id, e.event_time.isoformat(), e.event_name, e.user, e.source_ip,
                            e.model_dump_json()) for e in s.events])
            c.executemany("INSERT OR REPLACE INTO alerts VALUES (?,?,?,?)",
                          [(s.scan_id, a.alert_id, a.severity.value, a.model_dump_json()) for a in s.alerts])

    def latest_scan(self) -> ScanResult | None:
        with self._conn() as c:
            row = c.execute("SELECT payload FROM scan_history ORDER BY scanned_at DESC LIMIT 1").fetchone()
        return ScanResult.model_validate_json(row[0]) if row else None

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self._conn() as c:
            row = c.execute("SELECT payload FROM scan_history WHERE scan_id = ?", (scan_id,)).fetchone()
        return ScanResult.model_validate_json(row[0]) if row else None

    def list_scans(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT scan_id, account, scanned_at, posture_score FROM scan_history ORDER BY scanned_at DESC").fetchall()
        return [dict(zip(("scan_id", "account", "scanned_at", "posture_score"), r)) for r in rows]

    def save_ai(self, scan_id: str, question: str, response: str, mode: str) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO ai_analysis (scan_id, question, response, mode) VALUES (?,?,?,?)",
                      (scan_id, question, response, mode))

    def save_report(self, scan_id: str, path: str) -> int:
        with self._conn() as c:
            return c.execute("INSERT INTO reports (scan_id, path) VALUES (?,?)", (scan_id, path)).lastrowid

    def get_report(self, report_id: int) -> str | None:
        with self._conn() as c:
            row = c.execute("SELECT path FROM reports WHERE id = ?", (report_id,)).fetchone()
        return row[0] if row else None


def diff_scans(old: ScanResult, new: ScanResult) -> dict:
    o = {f.finding_id: f for f in old.findings}
    n = {f.finding_id: f for f in new.findings}
    return {
        "new": sorted(set(n) - set(o)), "resolved": sorted(set(o) - set(n)),
        "unchanged": sorted(set(o) & set(n)),
        "posture_change": new.posture_score - old.posture_score,
    }
