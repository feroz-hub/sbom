#!/usr/bin/env python
"""Reconcile cached AnalysisRun finding counts from persisted findings.

Diagnostic PostgreSQL SQL for a run:

WITH finding_keys AS (
    SELECT
        af.analysis_run_id AS run_id,
        COALESCE(
            'component_id:' || af.component_id::text,
            'cpe:' || lower(af.cpe),
            'component:' || lower(coalesce(af.component_name, '')) || ':' || lower(coalesce(af.component_version, ''))
        ) AS component_key,
        COALESCE(
            (
                SELECT upper(value)
                FROM jsonb_array_elements_text(
                    CASE
                        WHEN af.aliases IS NOT NULL AND af.aliases ~ '^\\s*\\[' THEN af.aliases::jsonb
                        ELSE '[]'::jsonb
                    END
                ) AS alias(value)
                WHERE upper(value) ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                LIMIT 1
            ),
            CASE WHEN upper(af.vuln_id) ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN upper(af.vuln_id) END,
            (
                SELECT upper(value)
                FROM jsonb_array_elements_text(
                    CASE
                        WHEN af.aliases IS NOT NULL AND af.aliases ~ '^\\s*\\[' THEN af.aliases::jsonb
                        ELSE '[]'::jsonb
                    END
                ) AS alias(value)
                WHERE upper(value) ~ '^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$'
                LIMIT 1
            ),
            upper(af.vuln_id)
        ) AS canonical_vulnerability_id,
        af.source
    FROM analysis_finding af
    WHERE af.analysis_run_id = :run_id
      AND af.is_active = TRUE
)
SELECT
    run_id,
    COUNT(*) AS persisted_rows,
    COUNT(DISTINCT component_key || '|' || canonical_vulnerability_id) AS unique_findings
FROM finding_keys
GROUP BY run_id;

WITH finding_keys AS (
    SELECT
        af.analysis_run_id AS run_id,
        COALESCE(
            'component_id:' || af.component_id::text,
            'cpe:' || lower(af.cpe),
            'component:' || lower(coalesce(af.component_name, '')) || ':' || lower(coalesce(af.component_version, ''))
        ) AS component_key,
        COALESCE(
            (
                SELECT upper(value)
                FROM jsonb_array_elements_text(
                    CASE
                        WHEN af.aliases IS NOT NULL AND af.aliases ~ '^\\s*\\[' THEN af.aliases::jsonb
                        ELSE '[]'::jsonb
                    END
                ) AS alias(value)
                WHERE upper(value) ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                LIMIT 1
            ),
            CASE WHEN upper(af.vuln_id) ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN upper(af.vuln_id) END,
            upper(af.vuln_id)
        ) AS canonical_vulnerability_id,
        af.source
    FROM analysis_finding af
    WHERE af.analysis_run_id = :run_id
      AND af.is_active = TRUE
)
SELECT
    run_id,
    component_key,
    canonical_vulnerability_id,
    COUNT(*) AS duplicate_count,
    ARRAY_AGG(source) AS sources
FROM finding_keys
GROUP BY run_id, component_key, canonical_vulnerability_id
HAVING COUNT(*) > 1;
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db import SessionLocal
from app.metrics.findings import canonical_finding_metrics_for_run, canonical_findings_for_run
from app.models import AnalysisRun
from app.services.finding_metrics import apply_metrics_to_run
from sqlalchemy import select


def _severity_total(run: AnalysisRun) -> int:
    return int(run.critical_count or 0) + int(run.high_count or 0) + int(run.medium_count or 0) + int(
        run.low_count or 0
    ) + int(run.unknown_count or 0)


def _iter_runs(db, args) -> list[AnalysisRun]:
    stmt = select(AnalysisRun).order_by(AnalysisRun.id.asc())
    if args.run_id is not None:
        stmt = stmt.where(AnalysisRun.id == args.run_id)
    if args.tenant_id is not None:
        stmt = stmt.where(AnalysisRun.tenant_id == args.tenant_id)
    if not args.all and args.run_id is None:
        stmt = stmt.limit(1)
    return list(db.execute(stmt).scalars())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--run-id", type=int, help="Reconcile one analysis run.")
    target.add_argument("--all", action="store_true", help="Reconcile every analysis run in scope.")
    parser.add_argument("--tenant-id", type=int, help="Restrict reconciliation to one tenant id.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Print changes without writing them.")
    mode.add_argument("--apply", action="store_true", help="Persist reconciled cached metrics.")
    args = parser.parse_args()

    if not args.apply:
        args.dry_run = True

    db = SessionLocal()
    updated = 0
    try:
        runs = _iter_runs(db, args)
        if args.run_id is not None and not runs:
            print(f"Run {args.run_id}: not found")
            return 1

        for run in runs:
            stored_total = int(run.total_findings or 0)
            before_severity = _severity_total(run)
            metrics = canonical_finding_metrics_for_run(db, run=run)
            after_severity = sum(metrics.severity_counts.values())
            rows = canonical_findings_for_run(db, run_id=int(run.id))
            changed = (
                stored_total != metrics.total_findings
                or int(run.critical_count or 0) != metrics.severity_counts["critical"]
                or int(run.high_count or 0) != metrics.severity_counts["high"]
                or int(run.medium_count or 0) != metrics.severity_counts["medium"]
                or int(run.low_count or 0) != metrics.severity_counts["low"]
                or int(run.unknown_count or 0) != metrics.severity_counts["unknown"]
            )
            print(f"Run {run.id}:")
            print(f"  stored findings_count: {stored_total}")
            print(f"  persisted finding rows: {len(rows)}")
            print(f"  provider observations: {metrics.raw_observation_count}")
            print(f"  canonical findings: {metrics.total_findings}")
            print(f"  severity total before: {before_severity}")
            print(f"  severity total after: {after_severity}")
            print(f"  updated: {'yes' if changed and args.apply else 'no'}")

            if changed and args.apply:
                apply_metrics_to_run(run, metrics)
                db.add(run)
                updated += 1

        if args.apply:
            db.commit()
        else:
            db.rollback()
        if args.all:
            print(f"Reconciled runs updated: {updated}")
    finally:
        db.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
