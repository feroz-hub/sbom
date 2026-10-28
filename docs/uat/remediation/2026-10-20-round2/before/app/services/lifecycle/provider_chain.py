"""Sequential provider chain selection and lookup orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from .decision_engine import choose_lifecycle_result
from .provider_base import LifecycleProvider
from .provider_http import RequestPolicy, policy_context
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


def _runtime_config(provider):
    from .provider_config_service import ProviderConfigSnapshot

    config = getattr(provider, "runtime_config", None)
    return config if isinstance(config, ProviderConfigSnapshot) else None


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
        config = _runtime_config(provider)
        breaker_enabled = config is None or config.circuit_breaker_enabled
        if breaker_enabled and status_tracker and status_tracker.is_circuit_open(provider.name):
            errors.append(f"{provider.name}: circuit open")
            continue
        result = _lookup_with_timeout(provider, component, timeout_seconds=None if config else timeout_seconds)
        provider_error = _provider_error(result)
        if provider_error:
            if status_tracker:
                status_tracker.record_failure(provider.name, provider_error)
            errors.append(f"{provider.name}: {provider_error}")
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
    outcomes = [
        {
            "provider": result.source_name,
            "provider_key": result.evidence.get("provider_key"),
            "status": result.lifecycle_status,
            "error": result.evidence.get("provider_error"),
            "checked_at": result.checked_at,
        }
        for result in results
    ]
    policies = [r.evidence["cache_policy"] for r in results if r.evidence.get("cache_policy")]
    # Conservative minimum over all consulted sources, independent of winner ordering.
    if policies:
        from .provider_capabilities import provider_capabilities

        defaults = provider_capabilities("endoflife_date")["cache_defaults"]
        chosen.evidence = {
            **chosen.evidence,
            "cache_policy": {k: min(p.get(k) or defaults[k] for p in policies) for k in defaults},
        }
    chosen.evidence = {**chosen.evidence, "provider_outcomes": outcomes}
    if errors:
        chosen.evidence = {**chosen.evidence, "provider_errors": errors}
    return chosen, errors


def _lookup_with_timeout(
    provider: LifecycleProvider,
    component: NormalizedComponent,
    *,
    timeout_seconds: float | None,
) -> LifecycleResult:
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(_lookup_provider_safely, provider, component)
    try:
        return future.result(timeout=max(0.1, timeout_seconds) if timeout_seconds is not None else None)
    except FuturesTimeoutError:
        result = unknown_result(component, provider.name)
        result.evidence = {"provider_error": "timeout"}
        return result.canonicalized()
    except Exception:
        result = unknown_result(component, provider.name)
        result.evidence = {"provider_error": "provider exception"}
        return result.canonicalized()
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _lookup_provider_safely(provider: LifecycleProvider, component: NormalizedComponent) -> LifecycleResult:
    config = _runtime_config(provider)
    policy = RequestPolicy(
        timeout=config.timeout_seconds if config else getattr(provider, "_timeout_seconds", 5),
        retries=config.max_retries if config else 0,
    )
    token = policy_context.set(policy)
    try:
        result = provider.lookup(component).canonicalized()
    except Exception as exc:
        result = unknown_result(component, provider.name)
        result.evidence = {"provider_error": policy.errors[-1] if policy.errors else type(exc).__name__}
    finally:
        policy_context.reset(token)
    if policy.errors:
        result.evidence = {**result.evidence, "provider_error": ", ".join(dict.fromkeys(policy.errors))}
    if config:
        result.evidence = {
            **result.evidence,
            "provider_key": config.provider_key,
            "cache_policy": {
                "known_days": config.cache_ttl_known_days,
                "unknown_hours": config.cache_ttl_unknown_hours,
                "failure_minutes": config.cache_ttl_failure_minutes,
                "deprecated_days": config.cache_ttl_deprecated_days,
            },
        }
    return result.canonicalized()


def _provider_error(result: LifecycleResult) -> str | None:
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    error = evidence.get("provider_error")
    return str(error) if error else None


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
