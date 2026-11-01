"""Approved platform policy: repeated/concurrent calls cannot spend untracked USD."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest
from app.ai.probe_policy import PLATFORM_PROBE_BLOCKED, PlatformProbeBlockedError, check_probe_spending
from app.core.context import minimal_background_context, tenant_scope
from app.routers.ai_credentials import _run_probe


def platform_context():
    return replace(minimal_background_context(1), tenant_id=None, is_platform_admin=True)


@pytest.mark.asyncio
async def test_repeated_independent_concurrent_platform_probes_never_invoke_provider():
    calls = []

    class Provider:
        name = "openai"
        default_model = "unknown-future-model"
        is_local = False

        async def test_connection(self, **kw):
            calls.append(kw)
            raise AssertionError("Untracked billable probe")

    with tenant_scope(platform_context()):
        # New provider instances and overlapping callers cannot reset/bypass
        # the policy, even when old pricing would return a zero estimate.
        results = await asyncio.gather(*[_run_probe(Provider(), "unknown-future-model") for _ in range(24)])
        results += [await _run_probe(Provider(), "gpt-4o") for _ in range(3)]
    assert not calls
    assert all(not r.success and r.error_kind == "configuration" for r in results)
    assert all(r.error_message == PLATFORM_PROBE_BLOCKED for r in results)
    assert all(r.accessible is None and r.generation_verified is None and r.workload_compatible is None for r in results)
    assert all(r.usage is None for r in results)


@pytest.mark.parametrize("name,tier,local,allowed", [
    ("openai", "paid", False, False),
    ("openai", "free", False, False),  # Label cannot invent a supported free tier.
    ("unknown", "free", False, False),
    ("gemini", "paid", False, False),
    ("gemini", "free", False, True),
    ("grok", "free", False, True),
    ("ollama", "paid", True, True),
    ("custom_openai", "paid", True, True),
    ("custom_openai", "paid", False, False),
])
def test_platform_policy_uses_effective_free_local_configuration(name, tier, local, allowed):
    provider = SimpleNamespace(name=name, is_local=local)
    with tenant_scope(platform_context()):
        if allowed:
            check_probe_spending(provider, tier=tier)
        else:
            with pytest.raises(PlatformProbeBlockedError):
                check_probe_spending(provider, tier=tier)
    with tenant_scope(minimal_background_context(1)):
        check_probe_spending(provider, tier=tier)  # Existing tenant budgets apply.


@pytest.mark.asyncio
@pytest.mark.parametrize("name,tier,local,tenant", [
    ("gemini", "free", False, None), ("ollama", "paid", True, None), ("openai", "paid", False, 1),
])
async def test_free_local_and_tenant_connection_tests_still_execute(name, tier, local, tenant):
    from app.ai.providers.base import ConnectionTestResult

    calls = []

    async def probe(**kwargs):
        calls.append(kwargs)
        return ConnectionTestResult(success=True, provider=name)

    provider = SimpleNamespace(name=name, is_local=local, default_model="gpt-4o", test_connection=probe)
    context = platform_context() if tenant is None else minimal_background_context(tenant)
    with tenant_scope(context):
        result = await _run_probe(provider, "gpt-4o", tier=tier)
    assert result.success and len(calls) == 1


@pytest.mark.asyncio
async def test_platform_registry_test_preserves_credentials_and_records_no_usage():
    from app.ai.model_registry import test_model as verify_model
    from app.db import SessionLocal
    from app.models import AiUsageLog

    from tests.ai.test_openai_verification_state import add_rows

    class Provider:
        name = "openai"
        is_local = False

        async def generate(self, request):
            raise AssertionError("Untracked billable model generation")

    with tenant_scope(platform_context()), SessionLocal() as db:
        credential, model = add_rows(db)
        for _ in range(3):
            ok, error = await verify_model(db, credential, model, provider=Provider())
            assert not ok and error == PLATFORM_PROBE_BLOCKED
            assert credential.enabled and credential.default_model == "gpt-4o-mini"
            assert model.raw_metadata["verification"]["accessible"] is None
            assert model.raw_metadata["verification"]["generation_verified"] is None
            assert model.last_verified_at is None
    # The policy never attempted a tenant-less write to the operational ledger.
    with SessionLocal() as db:
        assert db.query(AiUsageLog).count() == 0


@pytest.mark.asyncio
async def test_platform_paid_model_discovery_remains_available():
    from app.ai.model_registry import refresh_models
    from app.db import SessionLocal

    from tests.ai.test_openai_verification_state import add_rows

    calls = []

    async def discover():
        calls.append(True)
        return []

    with tenant_scope(platform_context()), SessionLocal() as db:
        credential, _ = add_rows(db)
        await refresh_models(db, credential, provider=SimpleNamespace(list_models=discover))
    assert len(calls) == 1
