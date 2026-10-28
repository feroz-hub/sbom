"""One-command entry point for SBOM Analyzer local development.

Run from a complete repository checkout:
    python dev.py
    python dev.py doctor
    python dev.py status
    python dev.py stop

The implementation and process-ownership helpers live under scripts/.
"""

from scripts.dev import cli


if __name__ == "__main__":
    raise SystemExit(cli())
