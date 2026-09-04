"""
SBOM Analyzer — Application Entry Point
Run with:  python run.py
           uvicorn app.main:app --reload
"""

from __future__ import annotations

import os
from pathlib import Path

# Local dev convenience: make sure .env carries the AI credential master key
# before it is loaded, so Settings → AI works on a fresh checkout with no
# extra setup step. Deliberately gated on an existing local .env — that file
# is dockerignored, so this is a no-op in a container, where the key must come
# from the platform's secret store (see scripts/generate_encryption_key.py).
_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.isfile(_ENV_FILE):
    try:
        from scripts.generate_encryption_key import ensure_env_key

        ensure_env_key(Path(_ENV_FILE))
    except Exception:  # noqa: BLE001 — never block startup on a convenience step
        pass

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
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("RELOAD", "false").lower() == "true"

    log.info("Starting SBOM Analyzer on http://%s:%d  (reload=%s)", host, port, reload)
    # log_config=None  → keep OUR logger configuration; don't let uvicorn
    #                    replace the root handlers with its default config.
    # access_log=False → our FastAPI middleware already logs every request
    #                    with timing, so uvicorn's access log would duplicate.
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_config=None,
        access_log=False,
    )
