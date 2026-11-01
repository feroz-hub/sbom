"""Lead-approved temporary spending policy for platform verification only."""

from ..core.context import get_bound_context
from .catalog import get_catalog_entry
from .providers.base import AiProviderError

PLATFORM_PROBE_BLOCKED = (
    "Billable platform model tests are temporarily blocked until durable platform "
    "spending controls are available. Tenant-scoped tests and configured free/local "
    "probes remain available. No provider request was sent."
)


class PlatformProbeBlockedError(AiProviderError):
    """No durable platform accounting exists for a potentially billed probe."""


def check_probe_spending(provider, *, tier: str | None = None) -> None:
    context = get_bound_context()
    if context is not None and context.tenant_id is not None:
        return
    if getattr(provider, "is_local", False):
        return
    catalog = get_catalog_entry(provider.name)
    effective_tier = tier if tier is not None else getattr(provider, "tier", "paid")
    if catalog is not None and catalog.supports_free_tier and effective_tier == "free":
        return
    # Unknown pricing is not proof of a free call. This gate precedes any
    # connection probe (including its discovery request) or generation call.
    raise PlatformProbeBlockedError(PLATFORM_PROBE_BLOCKED)
