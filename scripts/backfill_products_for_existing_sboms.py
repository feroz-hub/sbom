"""Backfill Product rows for legacy Project → SBOM data.

Usage:
    python scripts/backfill_products_for_existing_sboms.py --dry-run
    python scripts/backfill_products_for_existing_sboms.py --apply
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from app.db import SessionLocal
from app.models import AnalysisRun, Product, Projects, SBOMSource
from app.services.product_service import (
    DEFAULT_PRODUCT_SLUG,
    get_or_create_default_product,
    get_or_create_unassigned_project,
)
from sqlalchemy import select


@dataclass
class BackfillStats:
    projects_scanned: int = 0
    default_products_created: int = 0
    sboms_linked: int = 0
    sboms_skipped: int = 0
    errors: int = 0


def run_backfill(*, apply: bool) -> BackfillStats:
    stats = BackfillStats()
    db = SessionLocal()
    try:
        projects = db.execute(select(Projects).order_by(Projects.id.asc())).scalars().all()
        stats.projects_scanned = len(projects)
        for project in projects:
            try:
                before = db.execute(
                    select(Product.id).where(
                        Product.tenant_id == project.tenant_id,
                        Product.project_id == project.id,
                        Product.slug == DEFAULT_PRODUCT_SLUG,
                    )
                ).scalar_one_or_none()
                product = get_or_create_default_product(
                    db,
                    tenant_id=project.tenant_id,
                    project_id=project.id,
                    actor="backfill",
                )
                if before is None:
                    stats.default_products_created += 1

                sboms = db.execute(
                    select(SBOMSource).where(
                        SBOMSource.tenant_id == project.tenant_id,
                        SBOMSource.projectid == project.id,
                        SBOMSource.product_id.is_(None),
                    )
                ).scalars().all()
                for sbom in sboms:
                    sbom.product_id = product.id
                    sbom.product_name = product.name
                    stats.sboms_linked += 1
                    runs = db.execute(
                        select(AnalysisRun).where(
                            AnalysisRun.tenant_id == sbom.tenant_id,
                            AnalysisRun.sbom_id == sbom.id,
                            AnalysisRun.product_id.is_(None),
                        )
                    ).scalars().all()
                    for run in runs:
                        run.product_id = product.id
                        run.project_id = sbom.projectid
            except Exception:
                stats.errors += 1
                if apply:
                    db.rollback()
        projectless_sboms = db.execute(
            select(SBOMSource).where(SBOMSource.projectid.is_(None), SBOMSource.product_id.is_(None))
        ).scalars().all()
        by_tenant: dict[int, list[SBOMSource]] = {}
        for sbom in projectless_sboms:
            by_tenant.setdefault(sbom.tenant_id, []).append(sbom)
        for tenant_id, rows in by_tenant.items():
            project = get_or_create_unassigned_project(db, tenant_id=tenant_id, actor="backfill")
            product = get_or_create_default_product(db, tenant_id=tenant_id, project_id=project.id, actor="backfill")
            for sbom in rows:
                sbom.projectid = project.id
                sbom.product_id = product.id
                sbom.product_name = product.name
                stats.sboms_linked += 1
        stats.sboms_skipped = 0
        if apply:
            db.commit()
        else:
            db.rollback()
        return stats
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Backfill products for existing SBOM rows.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Calculate changes without committing.")
    mode.add_argument("--apply", action="store_true", help="Apply the backfill.")
    args = parser.parse_args(argv)

    stats = run_backfill(apply=bool(args.apply))
    print(f"Projects scanned: {stats.projects_scanned}")
    print(f"Default products created: {stats.default_products_created}")
    print(f"SBOMs linked: {stats.sboms_linked}")
    print(f"SBOMs skipped: {stats.sboms_skipped}")
    print(f"Errors: {stats.errors}")
    return 1 if stats.errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
