#!/usr/bin/env python3
"""Verify that a stored SBOM matches an original upload file."""

from __future__ import annotations

import argparse
import json
import os
import sys

# Allow running from repo root without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db import SessionLocal
from app.services.sbom_document_service import verify_upload_integrity


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify SBOM upload/storage integrity")
    parser.add_argument("--sbom-id", type=int, required=True, help="Stored SBOM id")
    parser.add_argument("--file-path", type=str, help="Path to the original uploaded SBOM file")
    args = parser.parse_args()

    session = SessionLocal()
    try:
        report = verify_upload_integrity(
            session,
            args.sbom_id,
            original_path=args.file_path,
        )
    finally:
        session.close()

    print(json.dumps(report, indent=2, sort_keys=True))
    if report.get("truncation_detected"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
