"""Platform defaults, independent tenant overrides, and runtime isolation."""

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from app.ai.config_loader import _VersionCounter, reset_loader, resolve_effective_ai_configuration
from app.ai.registry import get_registry, reset_registry
from app.core.context import get_bound_context, minimal_background_context, tenant_scope
from app.core.security import get_current_user
from app.db import SessionLocal
from app.models import AiProviderCredential, AuthorizationAuditLog, Tenant
from app.security.secrets import generate_master_key
from app.services.lifecycle.provider_config_service import (
    configuration_cache_namespace,
    resolve_effective_lifecycle_provider,
)
from app.services.lifecycle.secret_service import LifecycleProviderSecretService
from app.settings import reset_settings
from sqlalchemy import select

from tests.phase6_helpers import identity_claims, seed_membership, seed_platform_grant, seed_user


@pytest.fixture
def configured_actors(app, client, monkeypatch):
    monkeypatch.setenv("AI_CONFIG_ENCRYPTION_KEY", generate_master_key())
    monkeypatch.setenv("APP_SECRET_KEY", generate_master_key())
    monkeypatch.setenv("AI_FIXES_ENABLED", "true")
    monkeypatch.setenv("AI_FIXES_UI_CONFIG_ENABLED", "true")
    monkeypatch.setattr(_VersionCounter, "_client", lambda self: None)
    reset_settings()
    reset_loader()
    reset_registry()
    with SessionLocal() as db:
        now = datetime.now(UTC)
        for tid, name in ((2, "AstraMed"), (3, "MedTech")):
            db.add(Tenant(id=tid, name=name, slug=name.lower(), status="ACTIVE", created_at=now, updated_at=now))
        db.flush()
        platform = seed_user(db)
        seed_platform_grant(db, platform)
        olympus = seed_user(db)
        astra = seed_user(db)
        viewer = seed_user(db)
        seed_membership(db, olympus, tenant_id=1, role="TENANT_ADMIN")
        seed_membership(db, astra, tenant_id=2, role="TENANT_ADMIN")
        seed_membership(db, viewer, tenant_id=1, role="VIEWER")
        identities = {
            "platform": identity_claims(platform),
            "olympus": identity_claims(olympus),
            "astra": identity_claims(astra),
            "viewer": identity_claims(viewer),
        }
        db.commit()

    def call(actor, method, path, **kwargs):
        app.dependency_overrides[get_current_user] = lambda: identities[actor]
        headers = kwargs.pop("headers", {})
        if actor != "platform":
            headers.setdefault("X-Tenant-ID", "2" if actor == "astra" else "1")
        return client.request(method, path, headers=headers, **kwargs)

    yield call
    app.dependency_overrides.pop(get_current_user, None)
    reset_loader()
    reset_registry()
    reset_settings()


def add_provider(call, actor="platform", model="platform-model", **extra):
    base = "/api/platform/configuration/ai" if actor == "platform" else "/api/v1/ai"
    result = call(
        actor,
        "POST",
        f"{base}/credentials",
        json={
            "provider_name": "ollama",
            "base_url": "http://127.0.0.1:11434",
            "default_model": model,
            "is_default": True,
            "is_local": True,
            **extra,
        },
    )
    assert result.status_code == 201, result.text
    return result.json()["id"]


def test_ai_dynamic_defaults_override_update_and_reset(configured_actors):
    call = configured_actors
    pid = add_provider(call)
    default = call("olympus", "GET", "/api/v1/ai/effective-config")
    assert default.status_code == 200, default.text
    assert default.json()["source"] == "PLATFORM_DEFAULT"
    override = call("astra", "POST", "/api/v1/ai/override")
    assert override.status_code == 200, override.text
    aid = add_provider(call, "astra", "astra-model")
    with tenant_scope(minimal_background_context(1)):
        assert get_registry().get_default_config().default_model == "platform-model"
    with tenant_scope(minimal_background_context(2)):
        assert get_registry().get_default_config().default_model == "astra-model"
    updated = call(
        "platform",
        "PUT",
        f"/api/platform/configuration/ai/credentials/{pid}",
        json={"default_model": "platform-new"},
        headers={"X-Tenant-ID": "2"},
    )
    assert updated.status_code == 200, updated.text
    assert (
        next(config.default_model for config in resolve_effective_ai_configuration(1)[0] if config.is_default)
        == "platform-new"
    )
    assert (
        next(config.default_model for config in resolve_effective_ai_configuration(2)[0] if config.is_default)
        == "astra-model"
    )
    assert (
        next(config.default_model for config in resolve_effective_ai_configuration(3)[0] if config.is_default)
        == "platform-new"
    )
    assert call("astra", "DELETE", "/api/v1/ai/override").status_code == 204
    assert (
        next(config.default_model for config in resolve_effective_ai_configuration(2)[0] if config.is_default)
        == "platform-new"
    )
    with SessionLocal() as db:
        assert db.get(AiProviderCredential, aid) is None
        assert db.get(AiProviderCredential, pid).tenant_id is None


@pytest.mark.parametrize(
    "family,path,payload",
    [
        ("ai", "/settings", {"feature_enabled": False}),
        ("lifecycle", "/repository_health", {"priority": 88}),
    ],
)
def test_tenant_admin_cannot_modify_platform_configuration(configured_actors, family, path, payload):
    result = configured_actors("olympus", "PUT", f"/api/platform/configuration/{family}{path}", json=payload)
    assert result.status_code == 403, result.text


@pytest.mark.parametrize(
    "path,method,payload",
    [
        ("/api/v1/ai/settings", "PUT", {"feature_enabled": False}),
        ("/api/v1/ai/credentials", "GET", None),
        ("/api/admin/lifecycle-providers/repository_health", "PUT", {"priority": 80}),
        ("/api/admin/lifecycle-providers", "GET", None),
    ],
)
def test_platform_configuration_does_not_grant_tenant_entry(configured_actors, path, method, payload):
    result = configured_actors("platform", method, path, json=payload, headers={"X-Tenant-ID": "1"})
    assert result.status_code == 403, result.text


@pytest.mark.parametrize("path", ["/api/v1/ai/effective-config", "/api/admin/lifecycle-providers"])
def test_cross_tenant_configuration_request_rejected(configured_actors, path):
    assert configured_actors("olympus", "GET", path, headers={"X-Tenant-ID": "2"}).status_code == 403
    assert configured_actors("viewer", "GET", path).status_code == 403


def test_ai_credentials_are_scope_isolated_and_never_serialized(configured_actors):
    call = configured_actors
    key = "private-tenant-secret-never-return-this"
    tid = add_provider(call, "astra", "astra-model", api_key=key)
    for actor, base in (("platform", "/api/platform/configuration/ai"), ("olympus", "/api/v1/ai")):
        assert call(actor, "GET", f"{base}/credentials/{tid}").status_code == 404
        result = call(actor, "POST", f"{base}/credentials/test", json={"provider_name": "ollama", "credential_id": tid})
        assert result.status_code == 404, result.text
    response = call("astra", "GET", f"/api/v1/ai/credentials/{tid}")
    assert response.status_code == 200
    assert response.json()["api_key_present"] is True
    assert response.json()["api_key_preview"] is None
    assert key not in response.text
    with SessionLocal() as db:
        assert key not in db.get(AiProviderCredential, tid).api_key_encrypted
        for audit in db.scalars(select(AuthorizationAuditLog)):
            assert key not in str(audit.new_value)


def test_ai_unusable_override_never_falls_back_to_platform(configured_actors):
    call = configured_actors
    add_provider(call)
    add_provider(call, "astra", "astra-model", enabled=False)
    configs, _ = resolve_effective_ai_configuration(2)
    assert len(configs) == 1 and not configs[0].enabled
    assert all(config.default_model != "platform-model" for config in configs)


def test_ai_tenant_cache_invalidation_does_not_invalidate_other_tenant(configured_actors):
    call = configured_actors
    add_provider(call)
    before = resolve_effective_ai_configuration(1)[0]
    add_provider(call, "astra", "astra-model")
    assert resolve_effective_ai_configuration(1)[0] is before


def test_ai_default_can_switch_back_to_lower_id_in_same_scope(configured_actors):
    call = configured_actors
    first = add_provider(call)
    second = add_provider(call, label="second")
    assert call("platform", "PUT", f"/api/platform/configuration/ai/credentials/{first}/set-default").status_code == 200
    assert (
        next(config.credential_id for config in resolve_effective_ai_configuration(1)[0] if config.is_default) == first
    )
    assert first < second


def test_direct_provider_override_has_independent_controls(configured_actors):
    call = configured_actors
    platform_path = "/api/platform/configuration/ai/settings"
    assert call("platform", "PUT", platform_path, json={"budget_daily_usd": 25}).status_code == 200
    add_provider(call, "astra", "astra-model")
    assert call("platform", "PUT", platform_path, json={"budget_daily_usd": 30}).status_code == 200
    assert resolve_effective_ai_configuration(1)[1].budget_daily_usd == 30
    assert resolve_effective_ai_configuration(2)[1].budget_daily_usd == 25


def test_ai_result_cache_partitioned_by_tenant_and_effective_config(configured_actors):
    from app.ai.cache import make_cache_key

    call = configured_actors
    pid = add_provider(call)

    def cache_key(tenant_id):
        with tenant_scope(minimal_background_context(tenant_id)):
            return make_cache_key(vuln_id="CVE-2026-1", component_name="library", component_version="1")

    olympus = cache_key(1)
    astra = cache_key(2)
    assert olympus != astra
    add_provider(call, "astra", "astra-model")
    assert cache_key(1) == olympus
    assert cache_key(2) != astra
    assert (
        call(
            "platform", "PUT", f"/api/platform/configuration/ai/credentials/{pid}", json={"default_model": "changed"}
        ).status_code
        == 200
    )
    assert cache_key(1) != olympus


def test_discovery_worker_binds_each_credential_owner_and_skips_disabled_tenant(configured_actors, monkeypatch):
    from app.workers import ai_model_discovery

    call = configured_actors
    add_provider(call)
    add_provider(call, "astra", "astra-model")
    add_provider(call, "olympus", "olympus-model")
    with SessionLocal() as db:
        db.get(Tenant, 1).status = "DISABLED"
        db.commit()
    observed = []

    async def refresh(db, credential):
        context = get_bound_context()
        observed.append((credential.tenant_id, context.tenant_id if context else None))
        return SimpleNamespace(discovered=1)

    monkeypatch.setattr(ai_model_discovery, "refresh_models", refresh)
    # Even an inherited task context cannot make platform credential refresh
    # invalidate/use a tenant's cache.
    with tenant_scope(minimal_background_context(3)):
        counts = asyncio.run(ai_model_discovery._refresh_enabled())
    assert observed == [(None, None), (2, 2)]
    assert counts["succeeded"] == 2


def test_ai_audit_contains_safe_change_metadata_and_correlation(configured_actors):
    call = configured_actors
    pid = add_provider(call)
    result = call(
        "platform",
        "PUT",
        f"/api/platform/configuration/ai/credentials/{pid}",
        json={"default_model": "changed-model"},
        headers={"X-Request-ID": "config-audit-test"},
    )
    assert result.status_code == 200
    with SessionLocal() as db:
        row = db.scalar(
            select(AuthorizationAuditLog).where(AuthorizationAuditLog.correlation_id == "config-audit-test")
        )
        assert row.action == "PLATFORM_AI_CONFIGURATION_UPDATED"
        assert row.old_value["model"] == "platform-model"
        assert row.new_value["model"] == "changed-model"


def test_lifecycle_provider_independent_override_and_dynamic_inheritance(configured_actors):
    call = configured_actors
    base = "/api/platform/configuration/lifecycle"
    assert call("platform", "PUT", f"{base}/repository_health", json={"priority": 88}).status_code == 200
    override = call("astra", "PUT", "/api/admin/lifecycle-providers/repository_health", json={"priority": 99})
    assert override.status_code == 200, override.text
    assert override.json()["source"] == "TENANT_OVERRIDE"
    assert call("platform", "PUT", f"{base}/repository_health", json={"priority": 77}).status_code == 200
    with SessionLocal() as db:
        assert resolve_effective_lifecycle_provider(db, 1, "repository_health").priority == 77
        assert resolve_effective_lifecycle_provider(db, 2, "repository_health").priority == 99
        assert resolve_effective_lifecycle_provider(db, 2, "osv").tenant_id is None
    assert call("astra", "DELETE", "/api/admin/lifecycle-providers/repository_health/override").status_code == 204
    with SessionLocal() as db:
        assert resolve_effective_lifecycle_provider(db, 2, "repository_health").priority == 77


def test_lifecycle_connection_test_uses_effective_owner_credentials(configured_actors, monkeypatch):
    from app.services.lifecycle import provider_config_service

    call = configured_actors
    for actor, base, value in (
        ("platform", "/api/platform/configuration/lifecycle", "platform-private"),
        ("astra", "/api/admin/lifecycle-providers", "astra-private"),
    ):
        assert call(actor, "PUT", f"{base}/xeol_api", json={"enabled": True}).status_code == 200
        assert call(actor, "PUT", f"{base}/xeol_api/secret", json={"secret_value": value}).status_code == 200
    headers_seen = []

    class ProbeClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, *, json, headers):
            headers_seen.append(headers["Authorization"])
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(provider_config_service.httpx, "Client", ProbeClient)
    for actor, base in (
        ("olympus", "/api/admin/lifecycle-providers"),
        ("astra", "/api/admin/lifecycle-providers"),
        ("platform", "/api/platform/configuration/lifecycle"),
    ):
        response = call(actor, "POST", f"{base}/xeol_api/test")
        assert response.status_code == 200 and response.json()["success"]
        assert "private" not in response.text
    assert headers_seen == ["Bearer platform-private", "Bearer astra-private", "Bearer platform-private"]


def test_lifecycle_probe_error_never_serializes_secret(configured_actors, monkeypatch):
    from app.services.lifecycle.provider_config_service import LifecycleProviderConfigService

    secret = "private-value-never-return"

    def fail(*args, **kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(LifecycleProviderConfigService, "_run_provider_probe", fail)
    response = configured_actors("olympus", "POST", "/api/admin/lifecycle-providers/repository_health/test")
    assert response.status_code == 200
    assert response.json()["success"] is False
    assert secret not in response.text
    with SessionLocal() as db:
        assert all(secret not in str(row.new_value) for row in db.scalars(select(AuthorizationAuditLog)))


def test_lifecycle_circuit_breakers_are_tenant_and_configuration_isolated():
    from app.services.lifecycle.provider_status import get_provider_status_tracker

    with tenant_scope(minimal_background_context(1)):
        olympus = get_provider_status_tracker("olympus-before")
        olympus.register("Xeol", priority=10)
        for _ in range(100):
            olympus.record_failure("Xeol", "connection failed")
        assert olympus.is_circuit_open("Xeol")
    with tenant_scope(minimal_background_context(2)):
        astra = get_provider_status_tracker("astra-config")
        assert not astra.is_circuit_open("Xeol")
        assert astra is not olympus
    with tenant_scope(minimal_background_context(1)):
        assert get_provider_status_tracker("olympus-before") is olympus
        assert not get_provider_status_tracker("olympus-after").is_circuit_open("Xeol")


def test_tenant_lifecycle_registry_does_not_fall_back_without_database():
    from app.services.lifecycle.provider_registry import LifecycleProviderRegistry

    with tenant_scope(minimal_background_context(1)):
        with pytest.raises(RuntimeError, match="requires a database session"):
            LifecycleProviderRegistry().build_provider_chain(None)


@pytest.mark.parametrize("provider_key", ["xeol_api", "xeol_db"])
def test_invalid_tenant_provider_does_not_use_environment_defaults(configured_actors, provider_key):
    from dataclasses import replace

    from app.services.lifecycle.provider_config_service import LifecycleProviderConfigService
    from app.services.lifecycle.provider_registry import LifecycleProviderRegistry

    with SessionLocal() as db, tenant_scope(minimal_background_context(1)):
        base = next(
            row for row in LifecycleProviderConfigService().list_snapshots(db) if row.provider_key == provider_key
        )
        broken = replace(base, tenant_id=1, enabled=True, base_url=None, config={})
        with pytest.raises(RuntimeError, match="not configured"):
            LifecycleProviderRegistry()._provider_from_snapshot(
                db, SimpleNamespace(xeol_db_path="/platform-only.sqlite"), broken
            )


def test_lifecycle_credentials_use_exact_effective_owner(configured_actors):
    call = configured_actors
    for actor, base, value in (
        ("platform", "/api/platform/configuration/lifecycle", "platform-private"),
        ("astra", "/api/admin/lifecycle-providers", "astra-private"),
    ):
        response = call(actor, "PUT", f"{base}/xeol_api/secret", json={"secret_value": value})
        assert response.status_code == 200, response.text
        assert response.json()["value_preview"] is None
        assert value not in call(actor, "GET", base).text
    with SessionLocal() as db:
        platform = resolve_effective_lifecycle_provider(db, 1, "xeol_api")
        override = resolve_effective_lifecycle_provider(db, 2, "xeol_api")
        assert (
            LifecycleProviderSecretService(tenant_id=platform.tenant_id).get_secret(db, "xeol_api")
            == "platform-private"
        )
        assert (
            LifecycleProviderSecretService(tenant_id=override.tenant_id).get_secret(db, "xeol_api") == "astra-private"
        )
        assert LifecycleProviderSecretService(tenant_id=1).get_secret(db, "xeol_api") is None


def test_lifecycle_result_cache_partition_and_configuration_change(configured_actors):
    with SessionLocal() as db:
        with tenant_scope(minimal_background_context(1)):
            first = configuration_cache_namespace(db)
        with tenant_scope(minimal_background_context(2)):
            second = configuration_cache_namespace(db)
        assert first != second
    configured_actors("astra", "PUT", "/api/admin/lifecycle-providers/repository_health", json={"priority": 95})
    with SessionLocal() as db:
        with tenant_scope(minimal_background_context(1)):
            assert configuration_cache_namespace(db) == first
        with tenant_scope(minimal_background_context(2)):
            assert configuration_cache_namespace(db) != second


def test_disabled_tenant_workload_cannot_resolve_configuration(configured_actors):
    with SessionLocal() as db:
        db.get(Tenant, 2).status = "DISABLED"
        db.commit()
    with pytest.raises(Exception, match="active tenant"):
        resolve_effective_ai_configuration(2)
    with SessionLocal() as db, pytest.raises(Exception, match="active tenant"):
        resolve_effective_lifecycle_provider(db, 2, "osv")
