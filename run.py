"""CLI entry point.

python run.py scan        run the analysis on the NovaTech demo and print a summary
python run.py report      scan + write the PDF report
python run.py api         start the FastAPI server (http://127.0.0.1:8000/docs)
python run.py dashboard   start the Streamlit dashboard
"""
import logging
import subprocess
import sys

from config.settings import settings

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "scan"
    if cmd in ("scan", "report"):
        from ai.analyst import SecurityAnalyst
        from core.pipeline import run_scan
        from database.db import Database
        from rag.retriever import Retriever
        from reports.pdf_report import generate_report

        scan = run_scan()
        db = Database(settings.DB_PATH)
        db.save_scan(scan)
        print(f"\nScan {scan.scan_id} — {scan.account}")
        print(f"Posture {scan.posture_score}/100 | findings {scan.counts()} | paths {len(scan.attack_paths)} | alerts {len(scan.alerts)}\n")
        for f in scan.findings:
            print(f"  [{f.severity.value:8}] risk {f.risk_score:3}  {f.finding_id:32} {f.title}")
        for p in scan.attack_paths:
            print(f"  PATH {p.path_id} ({p.risk_score}): " + " -> ".join(p.nodes))
        if cmd == "report":
            path = generate_report(scan, SecurityAnalyst(scan, Retriever(settings.KNOWLEDGE_DIR)), settings.REPORT_DIR)
            db.save_report(scan.scan_id, str(path))
            print(f"\nReport written to {path}")
        return 0
    if cmd == "api":
        return subprocess.call([sys.executable, "-m", "uvicorn", "backend.api:app", "--host", "127.0.0.1", "--port", "8000"])
    if cmd == "dashboard":
        return subprocess.call([sys.executable, "-m", "streamlit", "run", "dashboard/app.py"])
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
