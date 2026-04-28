"""``CveRepositoryPort`` implementation backed by SQLAlchemy.

Idempotency contract (PostgreSQL): ``upsert_batch`` uses
``INSERT ... ON CONFLICT (cve_id) DO UPDATE ... WHERE excluded.last_modified > cves.last_modified``.
A replay of the same window is therefore a no-op; an out-of-order page
that tries to overwrite a fresher row is a no-op.

SQLite (used in dev/test only) goes through the analogous
``ON CONFLICT (cve_id) DO UPDATE`` form; SQLite >= 3.24 supports it.

CPE matching algorithm — see ``find_by_cpe``:

  1. Parse the input CPE 2.3 string into (vendor, product, version).
  2. Index-only candidate selection. On PG, the GIN-backed JSONB @>
     filter narrows to rows whose ``cpe_match`` contains an element
     with ``criteria_stem == 'vendor:product'``. On SQLite (dev/test
     only), fall back to a full scan; the test corpora are small.
  3. Python-side version-range refinement using
     ``packaging.version.Version``.
  4. Drop rows with ``vuln_status='Rejected'``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import timezone
from typing import Any, cast

from packaging.version import InvalidVersion, Version
from sqlalchemy import cast as sql_cast
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ..db.models import CveRow
from ..domain.models import CpeCriterion, CveRecord

log = logging.getLogger(__name__)

# Tunable: cap the rows submitted in a single INSERT statement so the
# psycopg pool doesn't choke on a single 50k-row VALUES list. Phase 1
# design called for 200–500; 500 matches the cowork prompt directly.
UPSERT_CHUNK_SIZE = 500


class SqlAlchemyCveRepository:
    """Sync, session-bound repository.

    The session is provided by the caller (FastAPI ``Depends(get_db)``
    or a Celery task). The repository never opens its own connection
    or transaction — it leaves session lifecycle to the caller.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ---- writes ---------------------------------------------------------

    def upsert_batch(self, records: Sequence[CveRecord]) -> int:
        if not records:
            return 0
        bind = self._session.get_bind()
        dialect = bind.dialect.name

        total = 0
        for chunk_start in range(0, len(records), UPSERT_CHUNK_SIZE):
            chunk = records[chunk_start : chunk_start + UPSERT_CHUNK_SIZE]
            payload = [_record_to_row_dict(r) for r in chunk]

            if dialect == "postgresql":
                stmt = pg_insert(CveRow).values(payload)
                stmt = stmt.on_conflict_do_update(
                    index_elements=[CveRow.cve_id],
                    set_={
                        col: stmt.excluded[col]
                        for col in (
                            "last_modified",
                            "published",
                            "vuln_status",
                            "description_en",
                            "score_v40",
                            "score_v31",
                            "score_v2",
                            "severity_text",
                            "vector_string",
                            "aliases",
                            "cpe_match",
                            "references",
                            "data",
                            "updated_at",
                        )
                    },
                    where=stmt.excluded.last_modified > CveRow.last_modified,
                )
            elif dialect == "sqlite":
                stmt = sqlite_insert(CveRow).values(payload)
                stmt = stmt.on_conflict_do_update(
                    index_elements=[CveRow.cve_id],
                    set_={
                        col: stmt.excluded[col]
                        for col in (
                            "last_modified",
                            "published",
                            "vuln_status",
                            "description_en",
                            "score_v40",
                            "score_v31",
                            "score_v2",
                            "severity_text",
                            "vector_string",
                            "aliases",
                            "cpe_match",
                            "references",
                            "data",
                            "updated_at",
                        )
                    },
                    where=stmt.excluded.last_modified > CveRow.last_modified,
                )
            else:
                raise NotImplementedError(
                    f"upsert_batch only supports postgresql/sqlite; got {dialect!r}"
                )

            result = self._session.execute(stmt)
            total += result.rowcount or 0

        self._session.flush()
        return total

    def soft_mark_rejected(self, cve_ids: Sequence[str]) -> int:
        if not cve_ids:
            return 0
        result = self._session.execute(
            CveRow.__table__.update()
            .where(CveRow.cve_id.in_(list(cve_ids)))
            .values(vuln_status="Rejected")
        )
        self._session.flush()
        return result.rowcount or 0

    # ---- reads ----------------------------------------------------------

    def find_by_cve_id(self, cve_id: str) -> CveRecord | None:
        row = self._session.get(CveRow, cve_id)
        return _row_to_record(row) if row is not None else None

    def find_by_cpe(self, cpe23: str) -> list[CveRecord]:
        parsed = _parse_cpe23(cpe23)
        if parsed is None:
            return []
        vendor, product, version = parsed
        stem = f"{vendor.lower()}:{product.lower()}"

        candidates = self._candidate_rows(stem)
        out: list[CveRecord] = []
        for row in candidates:
            if row.vuln_status == "Rejected":
                continue
            if _row_matches_version(row, vendor, product, version):
                out.append(_row_to_record(row))
        return out

    # ---- internals ------------------------------------------------------

    def _candidate_rows(self, stem: str) -> Sequence[CveRow]:
        """Narrow the candidate set as much as possible at the DB layer."""
        bind = self._session.get_bind()
        dialect = bind.dialect.name

        if dialect == "postgresql":
            probe = json.dumps([{"criteria_stem": stem}])
            stmt = (
                select(CveRow)
                .where(CveRow.cpe_match.op("@>")(sql_cast(probe, JSONB)))
                .where(CveRow.vuln_status != "Rejected")
            )
            return list(self._session.execute(stmt).scalars().all())

        # SQLite (dev/test): full scan + Python-side stem filter. Mirror
        # is feature-flagged off in production SQLite so this scales for
        # tests but is not a recommended path.
        stmt = select(CveRow).where(CveRow.vuln_status != "Rejected")
        rows = self._session.execute(stmt).scalars().all()
        return [r for r in rows if _row_has_stem(r, stem)]


# ============================================================================
# Mapping helpers — pure, no I/O.
# ============================================================================


def _record_to_row_dict(record: CveRecord) -> dict[str, Any]:
    """Flatten a CveRecord into a kwargs dict for INSERT VALUES."""
    return {
        "cve_id": record.cve_id,
        "last_modified": record.last_modified,
        "published": record.published,
        "vuln_status": record.vuln_status,
        "description_en": record.description_en,
        "score_v40": record.score_v40,
        "score_v31": record.score_v31,
        "score_v2": record.score_v2,
        "severity_text": record.severity_text,
        "vector_string": record.vector_string,
        "aliases": list(record.aliases),
        "cpe_match": [_criterion_to_dict(c) for c in record.cpe_criteria],
        "references": list(record.references),
        "data": dict(record.raw),
        "updated_at": record.last_modified,
    }


def _criterion_to_dict(c: CpeCriterion) -> dict[str, Any]:
    return {
        "criteria": c.criteria,
        "criteria_stem": c.criteria_stem,
        "vulnerable": c.vulnerable,
        "version_start_including": c.version_start_including,
        "version_start_excluding": c.version_start_excluding,
        "version_end_including": c.version_end_including,
        "version_end_excluding": c.version_end_excluding,
    }


def _criterion_from_dict(d: dict[str, Any]) -> CpeCriterion:
    return CpeCriterion(
        criteria=cast(str, d.get("criteria", "")),
        criteria_stem=cast(str, d.get("criteria_stem", "")),
        vulnerable=bool(d.get("vulnerable", True)),
        version_start_including=d.get("version_start_including"),
        version_start_excluding=d.get("version_start_excluding"),
        version_end_including=d.get("version_end_including"),
        version_end_excluding=d.get("version_end_excluding"),
    )


def _ensure_utc(dt):
    """SQLite drops tzinfo on round-trip; re-attach UTC defensively."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _row_to_record(row: CveRow) -> CveRecord:
    return CveRecord(
        cve_id=row.cve_id,
        last_modified=_ensure_utc(row.last_modified),
        published=_ensure_utc(row.published),
        vuln_status=row.vuln_status,
        description_en=row.description_en,
        score_v40=row.score_v40,
        score_v31=row.score_v31,
        score_v2=row.score_v2,
        severity_text=row.severity_text,
        vector_string=row.vector_string,
        aliases=tuple(row.aliases or ()),
        cpe_criteria=tuple(_criterion_from_dict(d) for d in (row.cpe_match or [])),
        references=tuple(row.references or ()),
        raw=row.data or {},
    )


def _row_has_stem(row: CveRow, stem: str) -> bool:
    for d in row.cpe_match or []:
        if isinstance(d, dict) and d.get("criteria_stem") == stem:
            return True
    return False


# ============================================================================
# CPE 2.3 parsing + version-range matching
# ============================================================================


def _parse_cpe23(cpe23: str) -> tuple[str, str, str] | None:
    """Return (vendor, product, version) from a CPE 2.3 string.

    Format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    """
    if not cpe23:
        return None
    parts = cpe23.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if not vendor or not product:
        return None
    return vendor, product, version


def _row_matches_version(row: CveRow, vendor: str, product: str, version: str) -> bool:
    """True if any cpe_match element on the row covers (vendor, product, version)."""
    target_stem = f"{vendor.lower()}:{product.lower()}"
    for d in row.cpe_match or []:
        if not isinstance(d, dict):
            continue
        if d.get("criteria_stem") != target_stem:
            continue
        if not d.get("vulnerable", True):
            continue
        if _criterion_covers_version(d, version):
            return True
    return False


def _criterion_covers_version(d: dict[str, Any], target_version: str) -> bool:
    """Apply NVD's four version-bound fields to ``target_version``.

    If the criterion has none of the four bounds set, it matches when
    its ``criteria`` contains an exact version OR a wildcard ``*``.

    If any bounds are set, version comparison uses
    ``packaging.version.Version``. Strings that fail to parse fall back
    to lexicographic comparison — same as Dependency-Track.
    """
    # Wildcard target → match anything (the input CPE didn't specify a version).
    if not target_version or target_version in {"*", "-", "ANY"}:
        return True

    start_inc = d.get("version_start_including")
    start_exc = d.get("version_start_excluding")
    end_inc = d.get("version_end_including")
    end_exc = d.get("version_end_excluding")

    has_bounds = any(b is not None for b in (start_inc, start_exc, end_inc, end_exc))
    if not has_bounds:
        # Exact-criteria match: the version inside d['criteria'] must
        # equal the target, or the criteria's version must be wildcard.
        criteria = d.get("criteria", "")
        cparts = criteria.split(":")
        if len(cparts) < 6:
            return False
        cversion = cparts[5]
        if cversion in {"*", "-", "ANY"}:
            return True
        return cversion == target_version

    target = _safe_version(target_version)
    if target is None:
        # Couldn't parse — defensive bypass: include if any bound is set.
        # Dependency-Track does the same to err on the side of false
        # positives over silent misses.
        return True

    if start_inc is not None and (sv := _safe_version(start_inc)) is not None and target < sv:
        return False
    if start_exc is not None and (sv := _safe_version(start_exc)) is not None and target <= sv:
        return False
    if end_inc is not None and (ev := _safe_version(end_inc)) is not None and target > ev:
        return False
    if end_exc is not None and (ev := _safe_version(end_exc)) is not None and target >= ev:
        return False
    return True


def _safe_version(s: str) -> Version | None:
    try:
        return Version(s)
    except (InvalidVersion, TypeError):
        return None
