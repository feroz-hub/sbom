"""AI service tests execute as the explicitly seeded local test tenant."""

import pytest


@pytest.fixture(autouse=True)
def selected_ai_test_tenant(client):
    from app.core.context import minimal_background_context, tenant_scope

    # Direct service/fixture DB operations have no FastAPI dependency to bind
    # their owner. Model the tenant-1 execution path explicitly, retaining
    # statement/write guards. Missing-context regressions bind None themselves.
    with tenant_scope(minimal_background_context(1)):
        yield
