"""
SBOM Analyzer — Application Entry Point
Run with:  python run.py
           uvicorn app.main:app --reload
"""
from __future__ import annotations

import os

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; rely on shell env

# Initialise logging before importing the app so all modules inherit the config
from app.logger import setup_logging
setup_logging()

import uvicorn
from app.logger import get_logger

log = get_logger("runner")

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("RELOAD", "false").lower() == "true"

    log.info("Starting SBOM Analyzer on http://%s:%d  (reload=%s)", host, port, reload)
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
    )
