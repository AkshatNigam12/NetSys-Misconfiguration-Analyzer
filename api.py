"""
Analyzer2 - FastAPI Backend
REST API for running scans and retrieving results.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, BackgroundTasks
from scanner.scan_runner import run_scan
from scanner.database import fetch_scan_history, is_connected
from scanner.config import API_HOST, API_PORT

app = FastAPI(
    title="Analyzer2 API",
    description="Network & System Misconfiguration Scanner API",
    version="1.0.0",
)

# In-memory cache of the latest scan result
_latest_scan = None


@app.get("/")
def root():
    """API health check."""
    return {
        "service": "Analyzer2",
        "status": "running",
        "database": "connected" if is_connected() else "not configured",
    }


@app.post("/scan/start")
def start_scan(background_tasks: BackgroundTasks):
    """Start a scan in the background."""
    background_tasks.add_task(_run_background_scan)
    return {"message": "Scan started in background"}


@app.get("/scan/latest")
def get_latest_scan():
    """Get the most recent scan result."""
    if _latest_scan is None:
        return {"error": "No scan has been run yet. POST /scan/start to begin."}
    return {
        "network_issues": len(_latest_scan.get("network_results", [])),
        "system_issues": len(_latest_scan.get("system_results", [])),
        "report_path": _latest_scan.get("report_path"),
        "issues": _latest_scan.get("issues", {}),
    }


@app.get("/scans/history")
def get_scan_history(limit: int = 10):
    """Fetch scan history from the database."""
    if not is_connected():
        return {"error": "Database not configured. Set ANALYZER_MONGODB_URI."}
    history = fetch_scan_history(limit=limit)
    return {"scans": history}


def _run_background_scan():
    """Run scan and cache the result."""
    global _latest_scan
    _latest_scan = run_scan(generate_report=True)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=API_HOST, port=API_PORT, reload=True)
