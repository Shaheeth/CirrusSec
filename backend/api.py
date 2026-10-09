"""FastAPI backend. Run: uvicorn backend.api:app --reload

If API_KEY is set in the environment every endpoint requires an `X-API-Key` header.
"""
from __future__ import annotations

import hmac
import logging

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ai.analyst import SecurityAnalyst
from config.settings import settings
from core.models import ScanResult
from core.pipeline import run_scan, run_scan_from_text
from database.db import Database, diff_scans
from ingestion.loader import IngestionError
from rag.retriever import Retriever
from reports.pdf_report import generate_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def require_key(x_api_key: str = Header(default="")) -> None:
    if settings.API_KEY and not hmac.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(401, "invalid or missing API key")


app = FastAPI(title="AI Cloud Security Analyst", version="1.0", dependencies=[Depends(require_key)])
db = Database(settings.DB_PATH)
retriever = Retriever(settings.KNOWLEDGE_DIR)


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=settings.MAX_CHAT_CHARS)


class AnalyzeRequest(BaseModel):
    finding_id: str | None = Field(default=None, max_length=200)
    path_id: str | None = Field(default=None, max_length=50)


def current_scan() -> ScanResult:
    scan = db.latest_scan()
    if scan is None:
        scan = run_scan()
        db.save_scan(scan)
    return scan


def analyst() -> SecurityAnalyst:
    return SecurityAnalyst(current_scan(), retriever)


@app.get("/resources")
def resources():
    return current_scan().resources


@app.get("/findings")
def findings(severity: str | None = None):
    fs = current_scan().findings
    return [f for f in fs if f.severity.value == severity.upper()] if severity else fs


@app.get("/findings/{finding_id:path}")
def finding(finding_id: str):
    f = current_scan().finding(finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@app.get("/attack-paths")
def attack_paths():
    return current_scan().attack_paths


@app.get("/events")
def events():
    s = current_scan()
    return {"events": s.events, "alerts": s.alerts}


@app.get("/scans")
def scans():
    return db.list_scans()


@app.post("/scan")
async def scan(request: Request):
    """Run a scan. Optional JSON body = cloud environment (size-limited, validated). Empty body = default lab data."""
    body = await request.body()
    if len(body) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(413, "request body too large")
    try:
        result = run_scan_from_text(body) if body.strip() else run_scan()
    except IngestionError as exc:
        raise HTTPException(422, str(exc)) from exc
    previous = db.latest_scan()
    db.save_scan(result)
    out = {"scan_id": result.scan_id, "posture_score": result.posture_score, "counts": result.counts(),
           "attack_paths": len(result.attack_paths), "alerts": len(result.alerts)}
    if previous:
        out["diff_vs_previous"] = diff_scans(previous, result)
    return out


@app.post("/analyze")
def analyze():
    """Re-run analysis on the default data (alias of POST /scan without a body)."""
    result = run_scan()
    db.save_scan(result)
    return {"scan_id": result.scan_id, "posture_score": result.posture_score, "counts": result.counts()}


@app.post("/ai/analyze")
def ai_analyze(req: AnalyzeRequest):
    a = analyst()
    if req.finding_id:
        if not current_scan().finding(req.finding_id):
            raise HTTPException(404, "finding not found")
        resp = a.explain_finding(req.finding_id)
    elif req.path_id:
        resp = a.explain_path(req.path_id)
    else:
        resp = a.investigation_summary()
    db.save_ai(current_scan().scan_id, resp.question, resp.model_dump_json(), resp.mode)
    return resp


@app.post("/ai/chat")
def ai_chat(req: ChatRequest):
    resp = analyst().chat(req.question)
    db.save_ai(current_scan().scan_id, req.question, resp.model_dump_json(), resp.mode)
    return resp


@app.post("/report")
def make_report():
    scan_ = current_scan()
    path = generate_report(scan_, SecurityAnalyst(scan_, retriever), settings.REPORT_DIR)
    return {"report_id": db.save_report(scan_.scan_id, str(path))}


@app.get("/report/{report_id}")
def get_report(report_id: int):
    path = db.get_report(report_id)
    if not path:
        raise HTTPException(404, "report not found")
    return FileResponse(path, media_type="application/pdf", filename=f"security_report_{report_id}.pdf")
