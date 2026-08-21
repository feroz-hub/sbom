"""Focused unit and integration tests for stable, immutable tenant_key (Phase 1)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.tenant_keys import (
    TENANT_KEY_PATTERN,
    TENANT_KEY_PREFIX,
    generate_tenant_key,
    is_valid_tenant_key,
)
from app.db import SessionLocal
from app.models import Tenant
from app.services import tenant_service as ts
from tests.phase7_helpers import seed_eligible_admin, seed_requester, tenant_payload


# ---------------------------------------------------------------------------
# Unit tests: generator & validator
# ---------------------------------------------------------------------------

def test_tenant_key_generator_format():
    key = generate_tenant_key()
    assert key.startswith(TENANT_KEY_PREFIX)
    assert len(key) == 36  # "tnt_" (4) + 32 hex chars
    assert TENANT_KEY_PATTERN.fullmatch(key) is not None
    assert is_valid_tenant_key(key) is True
    assert ":" not in key
    assert " " not in key


def test_tenant_key_validator_rejects_invalid_values():
    assert is_valid_tenant_key(None) is False
    assert is_valid_tenant_key("") is False
    assert is_valid_tenant_key("tnt_") is False
    assert is_valid_tenant_key("tnt_1") is False
    assert is_valid_tenant_key("tnt_acme") is False
    assert is_valid_tenant_key("acme:TENANT_ADMIN") is False
    assert is_valid_tenant_key("tnt_9f8c3e:TENANT_ADMIN") is False
    assert is_valid_tenant_key("tnt_0123456789abcdef0123456789abcdef ") is False
    assert is_valid_tenant_key(" tnt_0123456789abcdef0123456789abcdef") is False
    assert is_valid_tenant_key("tnt_0123456789ABCDEF0123456789ABCDEF") is False  # Uppercase hex
    assert is_valid_tenant_key("tnt_0123456789abcdef0123456789abcdef") is True


# ---------------------------------------------------------------------------
# Service tests: tenant creation & properties
# ---------------------------------------------------------------------------

def test_new_tenant_receives_opaque_tenant_key_with_prefix():
    with SessionLocal() as db:
        requester = seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        suffix = uuid4().hex[:8]

        result = ts.create_tenant_with_initial_admin(
            db,
            actor_user_id=requester.id,
            name=f"Acme Corp {suffix}",
            slug=f"acme-{suffix}",
            external_iam_tenant_id=f"ext-acme-{suffix}",
            initial_admin_user_id=initial_admin.id,
        )
        tenant = result.tenant

        assert tenant.tenant_key is not None
        assert tenant.tenant_key.startswith("tnt_")
        assert is_valid_tenant_key(tenant.tenant_key) is True


def test_two_tenants_receive_different_tenant_keys():
    with SessionLocal() as db:
        requester = seed_requester(db)
        admin1 = seed_eligible_admin(db)
        admin2 = seed_eligible_admin(db)
        s1, s2 = uuid4().hex[:8], uuid4().hex[:8]

        res1 = ts.create_tenant_with_initial_admin(
            db,
            actor_user_id=requester.id,
            name=f"Tenant One {s1}",
            slug=f"tenant-one-{s1}",
            external_iam_tenant_id=f"ext-one-{s1}",
            initial_admin_user_id=admin1.id,
        )
        res2 = ts.create_tenant_with_initial_admin(
            db,
            actor_user_id=requester.id,
            name=f"Tenant Two {s2}",
            slug=f"tenant-two-{s2}",
            external_iam_tenant_id=f"ext-two-{s2}",
            initial_admin_user_id=admin2.id,
        )

        assert res1.tenant.tenant_key != res2.tenant.tenant_key
        assert is_valid_tenant_key(res1.tenant.tenant_key)
        assert is_valid_tenant_key(res2.tenant.tenant_key)


def test_tenant_key_not_derived_from_name_slug_or_id():
    with SessionLocal() as db:
        requester = seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        name = "Globex Corporation SuperUniqueName"
        slug = "globex-corp-unique-slug"
        ext_id = "external-globex-tenant-id"

        result = ts.create_tenant_with_initial_admin(
            db,
            actor_user_id=requester.id,
            name=name,
            slug=slug,
            external_iam_tenant_id=ext_id,
            initial_admin_user_id=initial_admin.id,
        )
        tenant = result.tenant
        key = tenant.tenant_key

        assert "globex" not in key.lower()
        assert "superunique" not in key.lower()
        assert "unique" not in key.lower()
        assert "external" not in key.lower()
        assert str(tenant.id) != key[4:]


def test_changing_tenant_name_and_slug_does_not_change_tenant_key():
    with SessionLocal() as db:
        requester = seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        s = uuid4().hex[:8]

        result = ts.create_tenant_with_initial_admin(
            db,
            actor_user_id=requester.id,
            name=f"Original Name {s}",
            slug=f"original-{s}",
            external_iam_tenant_id=f"ext-orig-{s}",
            initial_admin_user_id=initial_admin.id,
        )
        original_key = result.tenant.tenant_key
        tenant_id = result.tenant.id

        # Update name and slug directly
        tenant = db.get(Tenant, tenant_id)
        tenant.name = f"Renamed Tenant {s}"
        tenant.slug = f"renamed-{s}"
        db.flush()
        db.refresh(tenant)

        assert tenant.tenant_key == original_key
        assert tenant.name == f"Renamed Tenant {s}"
        assert tenant.slug == f"renamed-{s}"


# ---------------------------------------------------------------------------
# API & Schema tests
# ---------------------------------------------------------------------------

def test_tenant_create_api_does_not_require_tenant_key_and_returns_it(client):
    with SessionLocal() as db:
        requester = seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        payload = tenant_payload(initial_admin.id)

    res = client.post("/api/tenants", json=payload)
    assert res.status_code == 201, res.text
    data = res.json()
    assert "tenant" in data
    tenant_data = data["tenant"]
    assert "tenant_key" in tenant_data
    assert tenant_data["tenant_key"].startswith("tnt_")
    assert is_valid_tenant_key(tenant_data["tenant_key"])
    assert tenant_data["name"] == payload["name"]
    assert tenant_data["slug"] == payload["slug"]


def test_tenant_create_api_rejects_client_supplied_tenant_key(client):
    with SessionLocal() as db:
        requester = seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        payload = tenant_payload(
            initial_admin.id,
            tenant_key="tnt_customclientkey12345678901234",
        )

    res = client.post("/api/tenants", json=payload)
    # Extra fields forbidden by ConfigDict(extra="forbid")
    assert res.status_code == 422


def test_list_tenants_endpoint_exposes_tenant_key(client):
    with SessionLocal() as db:
        requester = seed_requester(db)
        initial_admin = seed_eligible_admin(db)
        suffix = uuid4().hex[:8]
        result = ts.create_tenant_with_initial_admin(
            db,
            actor_user_id=requester.id,
            name=f"Listable Tenant {suffix}",
            slug=f"listable-{suffix}",
            external_iam_tenant_id=f"ext-list-{suffix}",
            initial_admin_user_id=initial_admin.id,
        )
        tenant_key = result.tenant.tenant_key

    res = client.get("/api/tenants")
    assert res.status_code == 200, res.text
    tenants = res.json()
    matching = [t for t in tenants if t.get("tenant_key") == tenant_key]
    assert len(matching) == 1
    assert matching[0]["tenant_key"].startswith("tnt_")


# ---------------------------------------------------------------------------
# Database constraint tests
# ---------------------------------------------------------------------------

def test_database_rejects_duplicate_tenant_key():
    with SessionLocal() as db:
        now = datetime.now(UTC)
        shared_key = generate_tenant_key()
        s1, s2 = uuid4().hex[:8], uuid4().hex[:8]

        t1 = Tenant(
            tenant_key=shared_key,
            name=f"Tenant Dupe 1 {s1}",
            slug=f"dupe-one-{s1}",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(t1)
        db.flush()

        t2 = Tenant(
            tenant_key=shared_key,
            name=f"Tenant Dupe 2 {s2}",
            slug=f"dupe-two-{s2}",
            status="ACTIVE",
            created_at=now,
            updated_at=now,
        )
        db.add(t2)
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()


# ---------------------------------------------------------------------------
# Migration validation
# ---------------------------------------------------------------------------

def test_all_tenants_in_database_have_valid_tenant_keys():
    with SessionLocal() as db:
        rows = db.execute(select(Tenant.id, Tenant.tenant_key)).all()
        assert len(rows) > 0
        keys = [row[1] for row in rows]

        # No NULL or empty keys
        assert all(k is not None and len(k) > 0 for k in keys)
        # All keys must match canonical format (is_valid checks prefix + 32 hex)
        assert all(is_valid_tenant_key(k) for k in keys)
        # No duplicates
        assert len(keys) == len(set(keys))


def test_schema_has_tenant_key_index_and_unique_constraint():
    from app.db import engine
    from sqlalchemy import inspect

    inspector = inspect(engine)
    columns = {c["name"]: c for c in inspector.get_columns("tenants")}
    assert "tenant_key" in columns
    assert columns["tenant_key"]["nullable"] is False

    indexes = {idx["name"]: idx for idx in inspector.get_indexes("tenants")}
    assert "ix_tenants_tenant_key" in indexes

    unique_constraints = {
        uq["name"]: uq for uq in inspector.get_unique_constraints("tenants")
    }
    assert "uq_tenants_tenant_key" in unique_constraints or any(
        "tenant_key" in uq.get("column_names", []) for uq in unique_constraints.values()
    )


def test_alembic_revision_051_tenant_key_exists():
    """Verify 051_tenant_key revision exists; head check is operational (alembic heads)."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    rev = scripts.get_revision("051_tenant_key")
    assert rev is not None
    assert rev.revision == "051_tenant_key"
    assert rev.down_revision == "050_optional_external_tenant_mapping"
    # Operational head check: ensure at least one head exists and 051 is in history
    heads = scripts.get_heads()
    assert len(heads) > 0
    # Walk back from each head to ensure 051 is ancestor or is head itself
    found = False
    for head in heads:
        cur = scripts.get_revision(head)
        while cur is not None:
            if cur.revision == "051_tenant_key":
                found = True
                break
            cur = scripts.get_revision(cur.down_revision) if cur.down_revision else None
        if found:
            break
    assert found, "051_tenant_key must be present in migration history"
