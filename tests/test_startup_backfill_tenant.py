"""Startup backfill tenant-isolation regression tests.

These tests verify that the analytics startup backfill:

1. Requires an explicit tenant context for tenant-owned writes.
2. Processes only the specified tenant's SBOM records.
3. Isolates two tenants' analytics data.
4. Cleans up context after a failure.
5. Is idempotent (no duplicate runs on repeated startup).
6. Skips inactive (DISABLED) tenants.
7. Rejects a mismatched tenant_id parameter.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.core.context import (
    bind_context,
    get_bound_context,
    minimal_background_context,
    reset_context,
    tenant_scope,
)
from app.db import SessionLocal
from app.models import (
    AnalysisFinding,
    AnalysisRun,
    IAMUser,
    Product,
    Projects,
    SBOMSource,
    Tenant,
    TenantUser,
)
from app.services.analysis_service import backfill_analytics_tables
from sqlalchemy import func, select


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _suffix() -> str:
    return uuid4().hex[:8]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


_SAMPLE_CDX = json.dumps({
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "test-lib",
            "version": "1.0.0",
            "purl": "pkg:pypi/test-lib@1.0.0",
        }
    ],
})


def _create_tenant(db, *, name: str, status: str = "ACTIVE") -> Tenant:
    """Create and flush a new tenant."""
    now = datetime.now(UTC)
    suffix = _suffix()
    tenant = Tenant(
        name=name,
        slug=f"{name.lower().replace(' ', '-')}-{suffix}",
        external_iam_tenant_id=f"ext-{name.lower().replace(' ', '-')}-{suffix}",
        status=status,
        created_at=now,
        updated_at=now,
    )
    db.add(tenant)
    db.flush()
    return tenant


def _create_sbom(db, *, tenant_id: int, name: str | None = None, data: str | None = None) -> SBOMSource:
    """Create and flush an SBOM belonging to the given tenant."""
    sbom = SBOMSource(
        sbom_name=name or f"sbom-{_suffix()}",
        sbom_version="1.0",
        sbom_data=data,
        tenant_id=tenant_id,
        status="validated",
        created_on=_now_iso(),
    )
    db.add(sbom)
    db.flush()
    return sbom


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _initialized_database(client):
    """Ensure the default test database (with tenant 1) is ready."""
    return None


# ---------------------------------------------------------------------------
# Test 1 — Missing tenant context remains blocked
# ---------------------------------------------------------------------------

def test_missing_tenant_context_blocks_tenant_owned_write():
    """Writing a tenant-owned AnalysisRun without context raises RuntimeError."""
    from app.settings import get_settings

    if not get_settings().auth_enabled:
        pytest.skip("Tenant guard defaults to tenant_id=1 when auth is disabled")

    db = SessionLocal()
    try:
        sbom = db.execute(select(SBOMSource).limit(1)).scalar_one_or_none()
        if sbom is None:
            pytest.skip("No SBOM in database to test with")

        run = AnalysisRun(
            sbom_id=sbom.id,
            run_status="OK",
            source="TEST",
            started_on=_now_iso(),
            completed_on=_now_iso(),
        )
        db.add(run)
        with pytest.raises(RuntimeError, match="Tenant context is required"):
            db.flush()
    finally:
        db.rollback()
        db.close()


# ---------------------------------------------------------------------------
# Test 2 — One-tenant backfill
# ---------------------------------------------------------------------------

def test_single_tenant_backfill_creates_correct_analytics():
    """Backfill for tenant 1 creates analytics only for tenant 1 SBOMs."""
    db = SessionLocal()
    try:
        # Seed an SBOM for the default test tenant (id=1)
        token = bind_context(minimal_background_context(1))
        try:
            sbom = _create_sbom(db, tenant_id=1, name=f"backfill-test-{_suffix()}")
            db.commit()
        finally:
            reset_context(token)

        # Run backfill under tenant scope
        ctx = minimal_background_context(tenant_id=1)
        with tenant_scope(ctx):
            backfill_analytics_tables(db, tenant_id=1)
            db.commit()

        # Verify run was created
        run = db.execute(
            select(AnalysisRun).where(AnalysisRun.sbom_id == sbom.id)
        ).scalar_one_or_none()
        assert run is not None, "Backfill should have created an AnalysisRun"
        assert run.tenant_id == 1, "AnalysisRun tenant_id must match"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 3 — Two-tenant isolation
# ---------------------------------------------------------------------------

def test_two_tenant_isolation():
    """Each tenant's backfill processes only that tenant's SBOMs."""
    db = SessionLocal()
    try:
        # Create tenant A (reuse default tenant 1)
        tenant_a_id = 1

        # Create tenant B
        tenant_b = _create_tenant(db, name="BackfillTenantB")
        tenant_b_id = tenant_b.id
        db.commit()

        # Create SBOMs under each tenant
        token_a = bind_context(minimal_background_context(tenant_a_id))
        try:
            sbom_a = _create_sbom(db, tenant_id=tenant_a_id, name=f"iso-a-{_suffix()}")
            db.commit()
        finally:
            reset_context(token_a)

        token_b = bind_context(minimal_background_context(tenant_b_id))
        try:
            sbom_b = _create_sbom(db, tenant_id=tenant_b_id, name=f"iso-b-{_suffix()}")
            db.commit()
        finally:
            reset_context(token_b)

        # Backfill tenant A
        with tenant_scope(minimal_background_context(tenant_a_id)):
            backfill_analytics_tables(db, tenant_id=tenant_a_id)
            db.commit()

        # Backfill tenant B
        with tenant_scope(minimal_background_context(tenant_b_id)):
            backfill_analytics_tables(db, tenant_id=tenant_b_id)
            db.commit()

        # Verify: tenant A's run is only for sbom_a
        runs_a = db.execute(
            select(AnalysisRun).where(
                AnalysisRun.sbom_id == sbom_a.id,
            )
        ).scalars().all()
        assert all(r.tenant_id == tenant_a_id for r in runs_a)

        # Verify: tenant B's run is only for sbom_b
        runs_b = db.execute(
            select(AnalysisRun).where(
                AnalysisRun.sbom_id == sbom_b.id,
            )
        ).scalars().all()
        assert all(r.tenant_id == tenant_b_id for r in runs_b)

        # Cross-check: no tenant A run for sbom_b
        cross = db.execute(
            select(AnalysisRun).where(
                AnalysisRun.sbom_id == sbom_b.id,
                AnalysisRun.tenant_id == tenant_a_id,
            )
        ).scalar_one_or_none()
        assert cross is None, "No cross-tenant analytics rows should exist"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 4 — Context cleanup after failure
# ---------------------------------------------------------------------------

def test_context_cleanup_after_failure():
    """After a failed backfill, tenant context must be reset."""
    db = SessionLocal()
    try:
        # Create a tenant
        tenant = _create_tenant(db, name="FailTenant")
        db.commit()
        tenant_id = tenant.id

        # Verify no context before
        assert get_bound_context() is None

        ctx = minimal_background_context(tenant_id=tenant_id)
        try:
            with tenant_scope(ctx):
                # Force an error by passing an invalid tenant_id
                with pytest.raises(ValueError):
                    backfill_analytics_tables(db, tenant_id=-1)
        except Exception:
            pass

        # Context must be cleaned up
        assert get_bound_context() is None, "Tenant context should be reset after failure"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 5 — Idempotent startup
# ---------------------------------------------------------------------------

def test_idempotent_startup():
    """Running backfill twice does not create duplicate analytics runs."""
    db = SessionLocal()
    try:
        # Seed SBOM
        token = bind_context(minimal_background_context(1))
        try:
            sbom = _create_sbom(db, tenant_id=1, name=f"idempotent-{_suffix()}")
            db.commit()
        finally:
            reset_context(token)

        # First backfill
        with tenant_scope(minimal_background_context(1)):
            backfill_analytics_tables(db, tenant_id=1)
            db.commit()

        count_after_first = db.scalar(
            select(func.count(AnalysisRun.id)).where(
                AnalysisRun.sbom_id == sbom.id,
                AnalysisRun.tenant_id == 1,
            )
        )

        # Second backfill (must be idempotent)
        with tenant_scope(minimal_background_context(1)):
            backfill_analytics_tables(db, tenant_id=1)
            db.commit()

        count_after_second = db.scalar(
            select(func.count(AnalysisRun.id)).where(
                AnalysisRun.sbom_id == sbom.id,
                AnalysisRun.tenant_id == 1,
            )
        )

        assert count_after_first == count_after_second, (
            f"Idempotency violated: {count_after_first} runs after first, "
            f"{count_after_second} after second"
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 6 — Inactive tenant skipped
# ---------------------------------------------------------------------------

def test_inactive_tenant_not_processed():
    """DISABLED tenants should not appear in _load_active_tenant_ids."""
    from app.main import _load_active_tenant_ids

    db = SessionLocal()
    try:
        disabled = _create_tenant(db, name="DisabledTenant", status="DISABLED")
        db.commit()
        disabled_id = disabled.id

        active_ids = _load_active_tenant_ids()
        assert disabled_id not in active_ids, "DISABLED tenant must not be in active list"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 7 — Wrong tenant parameter rejected
# ---------------------------------------------------------------------------

def test_wrong_tenant_parameter_rejected():
    """backfill_analytics_tables rejects invalid tenant_id values."""
    db = SessionLocal()
    try:
        with pytest.raises(ValueError, match="valid tenant_id"):
            backfill_analytics_tables(db, tenant_id=0)

        with pytest.raises(ValueError, match="valid tenant_id"):
            backfill_analytics_tables(db, tenant_id=-1)

        with pytest.raises((ValueError, TypeError)):
            backfill_analytics_tables(db, tenant_id="abc")  # type: ignore[arg-type]
    finally:
        db.close()
