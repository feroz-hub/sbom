"""Sequential provider chain selection and lookup orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from .decision_engine import choose_lifecycle_result
from .provider_base import LifecycleProvider
from .provider_status import LifecycleProviderStatusTracker
from .types import HIGH, UNKNOWN, LifecycleResult, NormalizedComponent, unknown_result

# Provider priority bands (lower = higher precedence).
PRIORITY_MANUAL = 0
PRIORITY_VENDOR = 10
PRIORITY_OPENEOX = 20
PRIORITY_ENDOFLIFE_DATE = 30
PRIORITY_XEOL = 40
PRIORITY_REGISTRY = 50
PRIORITY_DEPS_DEV = 60
PRIORITY_OSV = 70
PRIORITY_REPO_HEALTH = 80
PRIORITY_HEURISTIC = 90


def _should_stop_chain(result: LifecycleResult) -> bool:
    """Stop fallback providers when we have high-confidence known lifecycle evidence."""
    if result.lifecycle_status == UNKNOWN:
        return False
    if result.confidence != HIGH:
        return False
    if result.eol_date or result.eos_date or result.eof_date:
        return True
    return result.lifecycle_status not in {UNKNOWN}


def select_providers_for_component(
    providers: list[LifecycleProvider],
    component: NormalizedComponent,
) -> list[LifecycleProvider]:
    """Filter and order providers applicable to this component identity."""
    applicable = [provider for provider in providers if provider.supports(component)]
    return sorted(applicable, key=lambda provider: (provider.priority, provider.name))


def lookup_provider_chain(
    providers: list[LifecycleProvider],
    component: NormalizedComponent,
    *,
    timeout_seconds: float,
    status_tracker: LifecycleProviderStatusTracker | None = None,
) -> tuple[LifecycleResult, list[str]]:
    """Query providers sequentially; stop early on high-confidence results."""
    chain = select_providers_for_component(providers, component)
    results: list[LifecycleResult] = []
    errors: list[str] = []

    for provider in chain:
        if status_tracker and status_tracker.is_circuit_open(provider.name):
            errors.append(f"{provider.name}: circuit open")
            continue
        result = _lookup_with_timeout(provider, component, timeout_seconds=timeout_seconds)
        if result.lifecycle_status == UNKNOWN and result.source_name == provider.name:
            if status_tracker:
                status_tracker.record_failure(provider.name, "unknown or timeout")
        else:
            if status_tracker:
                status_tracker.record_success(provider.name)
        results.append(result)
        repository_url = result.evidence.get("repository_url") if isinstance(result.evidence, dict) else None
        if repository_url and not component.repository_url:
            component.repository_url = str(repository_url)
        if _should_stop_chain(result):
            break

    chosen = (choose_lifecycle_result(results) or unknown_result(component)).canonicalized()
    if errors and chosen.lifecycle_status == UNKNOWN:
        chosen.evidence = {**chosen.evidence, "provider_errors": errors}
    return chosen, errors


def _lookup_with_timeout(
    provider: LifecycleProvider,
    component: NormalizedComponent,
    *,
    timeout_seconds: float,
) -> LifecycleResult:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_lookup_provider_safely, provider, component)
    try:
        return future.result(timeout=max(0.1, timeout_seconds))
    except FuturesTimeoutError:
        return unknown_result(component, provider.name).canonicalized()
    except Exception:
        return unknown_result(component, provider.name).canonicalized()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _lookup_provider_safely(provider: LifecycleProvider, component: NormalizedComponent) -> LifecycleResult:
    try:
        return provider.lookup(component).canonicalized()
    except Exception:
        return unknown_result(component, provider.name).canonicalized()


__all__ = [
    "PRIORITY_DEPS_DEV",
    "PRIORITY_ENDOFLIFE_DATE",
    "PRIORITY_HEURISTIC",
    "PRIORITY_MANUAL",
    "PRIORITY_OPENEOX",
    "PRIORITY_OSV",
    "PRIORITY_REGISTRY",
    "PRIORITY_REPO_HEALTH",
    "PRIORITY_VENDOR",
    "PRIORITY_XEOL",
    "lookup_provider_chain",
    "select_providers_for_component",
]
