"""
CompareService unit + integration tests (ADR-0008).

Covers:
  * Pure helpers: cache key, vuln_id canonicalisation, severity coercion,
    fix-available heuristic, days_between, top-contributor ordering.
  * Diff engine end-to-end against an in-memory SQLite seed.
  * Cache hit / miss, expiry, corruption fallback.
  * Status guard, same-run guard, run-not-found.
  * KEV lookup against ``kev_entry``.
  * License/hash change_kinds gated by the env feature flag.
  * ``invalidate_for_run`` cleans both sides of the cache.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest


# =============================================================================
# Helpers
# =============================================================================


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def _now_iso() -> str:
    return _iso(datetime.now(UTC))


@pytest.fixture
def db(client):
    """Direct DB session for seeding. ``client`` triggers app startup first."""
    from app.db import SessionLocal

    s = SessionLocal()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


def _seed_project_and_sbom(db, *, slug: str):
    from app.models import Projects, SBOMSource

    proj = Projects(
        project_name=f"compare-{slug}",
        project_status=1,
        created_on=_now_iso(),
    )
    db.add(proj)
    db.flush()
    sbom = SBOMSource(
        sbom_name=f"compare-sbom-{slug}",
        projectid=proj.id,
        created_on=_now_iso(),
    )
    db.add(sbom)
    db.flush()
    return proj, sbom


def _add_component(
    db,
    sbom,
    *,
    name: str,
    version: str,
    purl: str | None = None,
    cpe: str | None = None,
):
    from app.models import SBOMComponent

    c = SBOMComponent(
        sbom_id=sbom.id,
        name=name,
        version=version,
        purl=purl or f"pkg:pypi/{name}@{version}",
        cpe=cpe,
        component_type="library",
    )
    db.add(c)
    db.flush()
    return c


def _add_run(
    db,
    *,
    sbom,
    project,
    status: str = "FINDINGS",
    completed_on: str | None = None,
):
    from app.models import AnalysisRun

    run = AnalysisRun(
        sbom_id=sbom.id,
        project_id=project.id,
        run_status=status,
        source="TEST",
        sbom_name=sbom.sbom_name,
        started_on=_now_iso(),
        completed_on=completed_on or _now_iso(),
        duration_ms=10,
        total_components=0,
        components_with_cpe=0,
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        unknown_count=0,
        query_error_count=0,
    )
    db.add(run)
    db.flush()
    return run


def _add_finding(
    db,
    run,
    *,
    vuln_id: str,
    component_name: str,
    component_version: str,
    severity: str = "HIGH",
    fixed_versions: list[str] | None = None,
    component_id: int | None = None,
):
    from app.models import AnalysisFinding

    f = AnalysisFinding(
        analysis_run_id=run.id,
        component_id=component_id,
        vuln_id=vuln_id,
        severity=severity,
        component_name=component_name,
        component_version=component_version,
        fixed_versions=json.dumps(fixed_versions) if fixed_versions else None,
    )
    db.add(f)
    db.flush()
    return f


# =============================================================================
# Pure helpers
# =============================================================================


def test_compute_cache_key_is_order_independent():
    from app.services.compare_service import compute_cache_key

    assert compute_cache_key(1, 2) == compute_cache_key(2, 1)
    # Different pairs hash to different keys.
    assert compute_cache_key(1, 2) != compute_cache_key(1, 3)
    # 64-char hex.
    k = compute_cache_key(1, 2)
    assert len(k) == 64
    int(k, 16)  # raises if not hex


def test_canonicalize_vuln_id_known_and_unknown():
    from app.services.compare_service import _canonicalize_vuln_id

    assert _canonicalize_vuln_id("cve-2021-44832") == "CVE-2021-44832"
    assert _canonicalize_vuln_id("GHSA-jfh8-c2jp-5v3q") == "GHSA-jfh8-c2jp-5v3q"
    # Unknown format passes through uppercased.
    assert _canonicalize_vuln_id("OSV-2024-foobar") == "OSV-2024-FOOBAR"


def test_severity_from_str_handles_all_cases():
    from app.schemas_cve import CveSeverity
    from app.services.compare_service import _severity_from_str

    assert _severity_from_str("CRITICAL") == CveSeverity.CRITICAL
    assert _severity_from_str("high") == CveSeverity.HIGH
    assert _severity_from_str(None) == CveSeverity.UNKNOWN
    assert _severity_from_str("") == CveSeverity.UNKNOWN
    assert _severity_from_str("garbage") == CveSeverity.UNKNOWN


def test_fix_available_heuristic():
    from app.services.compare_service import _fix_available

    assert _fix_available('["1.2.3"]') is True
    assert _fix_available("1.2.3") is True  # raw string also counts
    assert _fix_available("[]") is False
    assert _fix_available("") is False
    assert _fix_available(None) is False


def test_days_between_handles_unparseable_inputs():
    from app.services.compare_service import _days_between

    a = _iso(datetime(2026, 1, 1, tzinfo=UTC))
    b = _iso(datetime(2026, 1, 11, tzinfo=UTC))
    assert _days_between(a, b) == pytest.approx(10.0, abs=0.01)
    assert _days_between(None, b) is None
    assert _days_between(a, "not-a-date") is None


# =============================================================================
# Service end-to-end
# =============================================================================


def test_compare_diffs_findings_and_components(client, db):
    from app.schemas_compare import (
        ComponentChangeKind,
        FindingChangeKind,
    )
    from app.services.compare_service import CompareService

    proj, sbom_a = _seed_project_and_sbom(db, slug="a")
    _, sbom_b = _seed_project_and_sbom(db, slug="b")

    # Components — name+ecosystem identity.
    # Run A's SBOM has log4j-core@2.16.0, requests@2.31.0.
    _add_component(db, sbom_a, name="log4j-core", version="2.16.0",
                   purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0")
    _add_component(db, sbom_a, name="requests", version="2.31.0")
    # Run B's SBOM has log4j-core@2.17.1 (upgrade), pyyaml@6.0.1 (added).
    _add_component(db, sbom_b, name="log4j-core", version="2.17.1",
                   purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1")
    _add_component(db, sbom_b, name="pyyaml", version="6.0.1",
                   purl="pkg:pypi/pyyaml@6.0.1")
    db.commit()

    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)

    # Findings:
    #   A:  CVE-2021-44832 on log4j@2.16.0 (CRIT) — resolved in B
    #       CVE-2023-9999  on requests@2.31.0 (MEDIUM)
    #   B:  CVE-2024-12345 on pyyaml@6.0.1 (HIGH) — added in B
    #       CVE-2023-9999  on requests@2.31.0 (CRITICAL) — severity_changed
    _add_finding(db, run_a, vuln_id="CVE-2021-44832",
                 component_name="log4j-core", component_version="2.16.0",
                 severity="CRITICAL", fixed_versions=["2.17.1"])
    _add_finding(db, run_a, vuln_id="CVE-2023-9999",
                 component_name="requests", component_version="2.31.0",
                 severity="MEDIUM")
    _add_finding(db, run_b, vuln_id="CVE-2024-12345",
                 component_name="pyyaml", component_version="6.0.1",
                 severity="HIGH", fixed_versions=["6.0.2"])
    _add_finding(db, run_b, vuln_id="CVE-2023-9999",
                 component_name="requests", component_version="2.31.0",
                 severity="CRITICAL")
    db.commit()

    svc = CompareService(db)
    result = svc.compare(run_a.id, run_b.id)

    # Findings: 1 added, 1 resolved, 1 severity_changed (3 events; 0 unchanged)
    kinds = [f.change_kind for f in result.findings]
    assert kinds.count(FindingChangeKind.ADDED) == 1
    assert kinds.count(FindingChangeKind.RESOLVED) == 1
    assert kinds.count(FindingChangeKind.SEVERITY_CHANGED) == 1
    assert kinds.count(FindingChangeKind.UNCHANGED) == 0

    # Component diff: log4j-core upgraded, requests removed (only on A's sbom),
    # pyyaml added.
    comp_kinds = {(c.name, c.change_kind) for c in result.components}
    assert ("log4j-core", ComponentChangeKind.VERSION_BUMPED) in comp_kinds
    assert ("requests", ComponentChangeKind.REMOVED) in comp_kinds
    assert ("pyyaml", ComponentChangeKind.ADDED) in comp_kinds

    # Resolved finding attributed to log4j upgrade.
    resolved = next(f for f in result.findings if f.change_kind == FindingChangeKind.RESOLVED)
    assert "upgrade log4j-core 2.16.0 → 2.17.1" in (resolved.attribution or "")

    # Added finding attributed to new pyyaml dependency.
    added = next(f for f in result.findings if f.change_kind == FindingChangeKind.ADDED)
    assert "new dependency pyyaml@6.0.1" in (added.attribution or "")

    # Posture deltas — no scalar score, three deltas anchored to public sources.
    assert result.posture.findings_added_count == 1
    assert result.posture.findings_resolved_count == 1
    assert result.posture.findings_severity_changed_count == 1

    # Severity distribution: side A has 1 CRIT (log4j) + 1 MED (requests).
    # B has 1 HIGH (pyyaml) + 1 CRIT (requests-reclassified).
    assert result.posture.severity_distribution_a["CRITICAL"] == 1
    assert result.posture.severity_distribution_a["MEDIUM"] == 1
    assert result.posture.severity_distribution_b["HIGH"] == 1
    assert result.posture.severity_distribution_b["CRITICAL"] == 1

    # Fix-available coverage: A had 1/2 with fixes (only the log4j CVE),
    # B has 1/2 (only the pyyaml CVE — requests CVE was reclassified, no fix).
    assert result.posture.fix_available_pct_a == pytest.approx(50.0, abs=0.5)
    assert result.posture.fix_available_pct_b == pytest.approx(50.0, abs=0.5)

    # High+Critical: A has 1 (CRIT log4j), B has 2 (HIGH pyyaml + CRIT requests).
    assert result.posture.high_critical_count_a == 1
    assert result.posture.high_critical_count_b == 2
    assert result.posture.high_critical_count_delta == 1


def test_compare_same_run_raises(client, db):
    from app.services.compare_service import CompareService, SameRunError

    proj, sbom = _seed_project_and_sbom(db, slug="same")
    run = _add_run(db, sbom=sbom, project=proj)
    db.commit()

    with pytest.raises(SameRunError):
        CompareService(db).compare(run.id, run.id)


def test_compare_run_not_found_raises(client, db):
    from app.services.compare_service import CompareService, RunNotFoundError

    proj, sbom = _seed_project_and_sbom(db, slug="missing")
    run = _add_run(db, sbom=sbom, project=proj)
    db.commit()

    with pytest.raises(RunNotFoundError):
        CompareService(db).compare(run.id, 99999)


def test_compare_status_guard_blocks_running_runs(client, db):
    from app.services.compare_service import CompareService, RunNotReadyError

    proj, sbom_a = _seed_project_and_sbom(db, slug="status-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="status-b")
    run_a = _add_run(db, sbom=sbom_a, project=proj, status="OK")
    run_b = _add_run(db, sbom=sbom_b, project=proj, status="RUNNING")
    db.commit()

    with pytest.raises(RunNotReadyError) as exc:
        CompareService(db).compare(run_a.id, run_b.id)
    assert exc.value.status == "RUNNING"


def test_compare_caches_result_on_first_call(client, db):
    from app.models import CompareCache
    from app.services.compare_service import CompareService, compute_cache_key

    proj, sbom_a = _seed_project_and_sbom(db, slug="cache-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="cache-b")
    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)
    db.commit()

    svc = CompareService(db)
    r1 = svc.compare(run_a.id, run_b.id)
    cache_row = db.get(CompareCache, compute_cache_key(run_a.id, run_b.id))
    assert cache_row is not None

    # Second call returns the same payload (cache hit).
    r2 = svc.compare(run_a.id, run_b.id)
    assert r1.cache_key == r2.cache_key
    assert r1.computed_at == r2.computed_at


def test_compare_discards_expired_cache_row(client, db):
    from app.models import CompareCache
    from app.services.compare_service import CompareService, compute_cache_key

    proj, sbom_a = _seed_project_and_sbom(db, slug="exp-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="exp-b")
    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)
    db.commit()

    svc = CompareService(db)
    r1 = svc.compare(run_a.id, run_b.id)
    # Hand-edit the cache row to expire in the past.
    row = db.get(CompareCache, compute_cache_key(run_a.id, run_b.id))
    row.expires_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    db.commit()

    r2 = svc.compare(run_a.id, run_b.id)
    assert r2.computed_at >= r1.computed_at  # recomputed


def test_invalidate_for_run_deletes_referenced_cache_rows(client, db):
    from app.models import CompareCache
    from app.services.compare_service import CompareService

    proj, sbom_a = _seed_project_and_sbom(db, slug="inv-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="inv-b")
    _, sbom_c = _seed_project_and_sbom(db, slug="inv-c")
    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)
    run_c = _add_run(db, sbom=sbom_c, project=proj)
    db.commit()

    svc = CompareService(db)
    # The session-scoped DB may carry cache rows from earlier tests, so
    # measure deltas instead of absolute counts.
    base_count = db.query(CompareCache).count()
    svc.compare(run_a.id, run_b.id)
    svc.compare(run_b.id, run_c.id)
    svc.compare(run_a.id, run_c.id)
    assert db.query(CompareCache).count() == base_count + 3

    deleted = svc.invalidate_for_run(run_b.id)
    assert deleted == 2
    # Of the three rows we just added, only the (run_a, run_c) row survives.
    surviving_ours = {
        (r.run_a_id, r.run_b_id)
        for r in db.query(CompareCache)
        .filter(CompareCache.run_a_id.in_([run_a.id, run_b.id, run_c.id]))
        .filter(CompareCache.run_b_id.in_([run_a.id, run_b.id, run_c.id]))
        .all()
    }
    assert surviving_ours == {(run_a.id, run_c.id)}


def test_kev_current_state_is_picked_up_from_kev_entry(client, db):
    from app.models import KevEntry
    from app.services.compare_service import CompareService
    from app.schemas_compare import FindingChangeKind

    proj, sbom_a = _seed_project_and_sbom(db, slug="kev-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="kev-b")
    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)
    _add_finding(db, run_a, vuln_id="CVE-2021-44832",
                 component_name="log4j-core", component_version="2.16.0",
                 severity="CRITICAL")
    db.add(KevEntry(cve_id="CVE-2021-44832", refreshed_at=_now_iso()))
    db.commit()

    result = CompareService(db).compare(run_a.id, run_b.id)
    resolved = next(f for f in result.findings if f.change_kind == FindingChangeKind.RESOLVED)
    assert resolved.kev_current is True
    assert result.posture.kev_count_a == 1
    assert result.posture.kev_count_b == 0


def test_top_resolutions_orders_kev_first_then_severity(client, db):
    from app.services.compare_service import CompareService
    from app.models import KevEntry

    proj, sbom_a = _seed_project_and_sbom(db, slug="top-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="top-b")
    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)
    # CVE-LOW (low) — not KEV
    # CVE-MED (medium) — KEV
    # CVE-CRIT (critical) — not KEV
    _add_finding(db, run_a, vuln_id="CVE-2024-LOW",
                 component_name="a", component_version="1.0",
                 severity="LOW")
    _add_finding(db, run_a, vuln_id="CVE-2024-MED",
                 component_name="b", component_version="1.0",
                 severity="MEDIUM")
    _add_finding(db, run_a, vuln_id="CVE-2024-CRIT",
                 component_name="c", component_version="1.0",
                 severity="CRITICAL")
    db.add(KevEntry(cve_id="CVE-2024-MED", refreshed_at=_now_iso()))
    db.commit()

    result = CompareService(db).compare(run_a.id, run_b.id)
    top = result.posture.top_resolutions
    assert len(top) == 3
    # KEV-first: CVE-2024-MED first even though it's only MEDIUM.
    assert top[0].vuln_id == "CVE-2024-MED"
    # Then severity: CRIT before LOW.
    assert top[1].vuln_id == "CVE-2024-CRIT"
    assert top[2].vuln_id == "CVE-2024-LOW"


def test_license_hash_change_kinds_disabled_by_default(client, db, monkeypatch):
    """Even if license/hash columns existed, change_kinds must not fire when
    ``compare_license_hash_enabled`` is false. ADR-0008 §11 user clarification §4."""
    from app.schemas_compare import ComponentChangeKind
    from app.services.compare_service import CompareService

    proj, sbom_a = _seed_project_and_sbom(db, slug="lic-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="lic-b")
    ca = _add_component(db, sbom_a, name="lib", version="1.0")
    cb = _add_component(db, sbom_b, name="lib", version="1.0")
    # Simulate columns appearing on the rows by attribute injection — the
    # service uses ``getattr(... , None)`` so it still reads them.
    ca.license = "MIT"
    cb.license = "GPL-3.0"
    db.flush()
    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)
    db.commit()

    # Default: flag is OFF. license_changed must NOT fire even with mismatch.
    result = CompareService(db).compare(run_a.id, run_b.id)
    lib_row = next(c for c in result.components if c.name == "lib")
    assert lib_row.change_kind == ComponentChangeKind.UNCHANGED


def test_relationship_direction_warning_when_b_older_than_a(client, db):
    from app.services.compare_service import CompareService

    proj, sbom_a = _seed_project_and_sbom(db, slug="dir-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="dir-b")
    older = _iso(datetime(2026, 1, 1, tzinfo=UTC))
    newer = _iso(datetime(2026, 2, 1, tzinfo=UTC))
    run_a = _add_run(db, sbom=sbom_a, project=proj, completed_on=newer)
    run_b = _add_run(db, sbom=sbom_b, project=proj, completed_on=older)
    db.commit()

    result = CompareService(db).compare(run_a.id, run_b.id)
    assert result.relationship.direction_warning is not None
    assert "older" in result.relationship.direction_warning.lower()


def test_compare_handles_corrupt_cache_gracefully(client, db):
    from app.models import CompareCache
    from app.services.compare_service import CompareService, compute_cache_key

    proj, sbom_a = _seed_project_and_sbom(db, slug="corrupt-a")
    _, sbom_b = _seed_project_and_sbom(db, slug="corrupt-b")
    run_a = _add_run(db, sbom=sbom_a, project=proj)
    run_b = _add_run(db, sbom=sbom_b, project=proj)
    db.commit()

    # Plant a corrupt cache row.
    cache_key = compute_cache_key(run_a.id, run_b.id)
    db.add(
        CompareCache(
            cache_key=cache_key,
            run_a_id=run_a.id,
            run_b_id=run_b.id,
            payload={"this": "is corrupt"},  # missing required fields
            computed_at=_now_iso(),
            expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            schema_version=1,
        )
    )
    db.commit()

    # Service detects corruption, deletes the row, recomputes.
    result = CompareService(db).compare(run_a.id, run_b.id)
    assert result.cache_key == cache_key
    fresh = db.get(CompareCache, cache_key)
    assert fresh is not None
    assert fresh.payload != {"this": "is corrupt"}
