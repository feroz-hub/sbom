"""Inspect SBOM rows whose component extraction cannot run cleanly.

Usage:
    python scripts/check_unsupported_sboms.py
    python scripts/check_unsupported_sboms.py --mark-skipped
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db import SessionLocal
from app.models import SBOMSource
from app.services.sbom_service import (
    COMPONENT_EXTRACTION_COMPLETED,
    COMPONENT_EXTRACTION_SKIPPED,
    detect_supported_component_extraction_format,
    now_iso,
)

TRUSTED_STATUSES = {"validated", "accepted", "imported", "trusted"}


def _status_reason(sbom: SBOMSource) -> str | None:
    status = (sbom.status or "").strip().lower()
    if status not in TRUSTED_STATUSES:
        return f"SBOM validation status is '{status or 'unknown'}'; repair or revalidate before extracting components."
    _fmt, _version, reason = detect_supported_component_extraction_format(sbom.sbom_data)
    return reason


def _iter_unsupported(sboms: Iterable[SBOMSource]) -> Iterable[tuple[SBOMSource, str]]:
    for sbom in sboms:
        extraction_status = (sbom.component_extraction_status or "").strip().lower()
        if extraction_status == COMPONENT_EXTRACTION_COMPLETED:
            continue
        reason = sbom.component_extraction_error if extraction_status == COMPONENT_EXTRACTION_SKIPPED else None
        reason = reason or _status_reason(sbom)
        if reason:
            yield sbom, reason


def main() -> int:
    parser = argparse.ArgumentParser(description="List SBOMs that should be skipped by component extraction.")
    parser.add_argument("--mark-skipped", action="store_true", help="Mark detected unsupported SBOMs as skipped.")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        sboms = db.execute(select(SBOMSource).order_by(SBOMSource.id.asc())).scalars().all()
        rows = list(_iter_unsupported(sboms))
        if not rows:
            print("No unsupported SBOM rows found.")
            return 0

        headers = (
            "id",
            "name",
            "format",
            "spec_version",
            "validation_status",
            "component_extraction_status",
            "component_extraction_error",
            "created_at",
        )
        print("\t".join(headers))
        for sbom, reason in rows:
            print(
                "\t".join(
                    [
                        str(sbom.id),
                        str(sbom.sbom_name or ""),
                        str(sbom.format or ""),
                        str(sbom.spec_version or ""),
                        str(sbom.status or ""),
                        str(sbom.component_extraction_status or ""),
                        str(reason or ""),
                        str(sbom.created_on or ""),
                    ]
                )
            )
            if args.mark_skipped and sbom.component_extraction_status != COMPONENT_EXTRACTION_SKIPPED:
                sbom.component_extraction_status = COMPONENT_EXTRACTION_SKIPPED
                sbom.component_extraction_error = reason
                sbom.component_extraction_attempted_at = now_iso()
                sbom.component_extraction_completed_at = None
                db.add(sbom)

        if args.mark_skipped:
            db.commit()
            print(f"Marked {len(rows)} SBOM row(s) as skipped.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
