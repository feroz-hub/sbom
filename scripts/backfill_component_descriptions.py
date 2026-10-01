"""Backfill ``sbom_component.description`` from each SBOM's stored document.

Secure Component Advisor, FR-SCA-009 (purpose evidence of source SBOM).
Migration 068 adds the column empty. This re-parses ``sbom_source.sbom_data``
with the same parser used at upload and fills ``description`` only where it
is NULL, matching rows by ``bom_ref`` (then name + version). It never
overwrites a value and never touches any other column.

Usage:
    python scripts/backfill_component_descriptions.py --dry-run
    python scripts/backfill_component_descriptions.py --apply [--batch 200]
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.core.context import minimal_background_context, tenant_scope  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.models import SBOMComponent, SBOMSource  # noqa: E402
from app.parsing.extract import extract_components  # noqa: E402


@dataclass
class Stats:
    sboms_scanned: int = 0
    sboms_unparseable: int = 0
    components_updated: int = 0


def _key(name, version):
    return ((name or "").strip().lower(), (version or "").strip().lower())


def backfill(*, apply: bool, batch: int = 200) -> Stats:
    stats = Stats()
    with SessionLocal() as db:
        rows = db.execute(
            select(SBOMSource.__table__.c.id, SBOMSource.__table__.c.tenant_id)
            .where(SBOMSource.__table__.c.sbom_data.is_not(None))
            .order_by(SBOMSource.__table__.c.id)
        ).all()
    for start in range(0, len(rows), batch):
        with SessionLocal() as db:
            for sbom_id, tenant_id in rows[start : start + batch]:
                with tenant_scope(minimal_background_context(tenant_id)):
                    stats.sboms_scanned += 1
                    data = db.execute(select(SBOMSource.sbom_data).where(SBOMSource.id == sbom_id)).scalar()
                    try:
                        parsed = extract_components(data)
                    except Exception:  # noqa: BLE001 - unparseable legacy documents are counted, not fatal
                        stats.sboms_unparseable += 1
                        continue
                    by_ref = {c["bom_ref"]: c["description"] for c in parsed if c.get("bom_ref") and c.get("description")}
                    by_nv = {_key(c.get("name"), c.get("version")): c["description"] for c in parsed if c.get("description")}
                    if not by_ref and not by_nv:
                        continue
                    components = db.scalars(
                        select(SBOMComponent).where(
                            SBOMComponent.tenant_id == tenant_id,
                            SBOMComponent.sbom_id == sbom_id,
                            SBOMComponent.description.is_(None),
                        )
                    ).all()
                    for component in components:
                        description = by_ref.get(component.bom_ref) or by_nv.get(_key(component.name, component.version))
                        if description:
                            stats.components_updated += 1
                            if apply:
                                component.description = description
                    if apply:
                        db.commit()
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--batch", type=int, default=200)
    args = parser.parse_args()
    stats = backfill(apply=args.apply, batch=args.batch)
    verb = "updated" if args.apply else "would update"
    print(
        f"SBOMs scanned: {stats.sboms_scanned}; unparseable: {stats.sboms_unparseable}; "
        f"components {verb}: {stats.components_updated}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
