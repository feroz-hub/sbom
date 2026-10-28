"""External package-metadata adapters for alternative discovery (FR-SCA-012, NFR-SCA-003).

Adapter contract only. **No production source is registered**: spec §12
requires an approved source list, licensing and refresh limits first. A
deployment (or a test) registers adapters with :func:`register_source`.

Failure isolation: each adapter call runs with a timeout behind a per-source
:class:`~app.integrations.cve.base.CircuitBreaker`. Errors, timeouts and open
breakers become :class:`SourceResult` outcomes (reused ``FetchOutcome``
vocabulary) that the recommendation records as a degraded state — they never
fail the evaluation and never touch core SBOM viewing or analysis.

An adapter is never the sole source of truth: its candidates still pass the
same purpose and compatibility gates as tenant-observed ones, and their
vulnerability posture is reported as not observed in the tenant.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ...integrations.cve.base import CircuitBreaker, FetchOutcome

DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class ExternalCandidate:
    name: str
    version: str | None
    ecosystem: str
    purl: str | None = None
    licenses: tuple[str, ...] | None = None
    #: ``{"technology_category", "primary_use_case", "functional_description", "confidence"}``
    purpose: dict[str, Any] = field(default_factory=dict)
    lifecycle_status: str | None = None
    compatibility_evidence: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceResult:
    source: str
    outcome: FetchOutcome
    candidates: tuple[ExternalCandidate, ...] = ()
    error: str | None = None
    latency_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "outcome": self.outcome.value, "candidates": len(self.candidates),
                "error": self.error, "latency_ms": self.latency_ms}


class PackageMetadataSource(Protocol):
    """What an adapter implements. Synchronous; called with a timeout."""

    name: str

    def find_alternatives(
        self, *, ecosystem: str, category: str, purpose_text: str | None
    ) -> list[ExternalCandidate]:  # pragma: no cover - protocol
        ...


_lock = threading.Lock()
_sources: list[PackageMetadataSource] = []
_breakers: dict[str, CircuitBreaker] = {}


def register_source(source: PackageMetadataSource) -> None:
    with _lock:
        _sources.append(source)
        _breakers.setdefault(source.name, CircuitBreaker(threshold=3, reset_seconds=900))


def clear_sources() -> None:
    """Test seam."""
    with _lock:
        _sources.clear()
        _breakers.clear()


def configured_sources() -> list[PackageMetadataSource]:
    with _lock:
        return list(_sources)


def query_sources(
    *, ecosystem: str, category: str, purpose_text: str | None, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> list[SourceResult]:
    """Ask every configured adapter; never raises."""
    results = []
    for source in configured_sources():
        breaker = _breakers.setdefault(source.name, CircuitBreaker(threshold=3, reset_seconds=900))
        if not breaker.allow():
            results.append(SourceResult(source.name, FetchOutcome.CIRCUIT_OPEN, error="circuit open"))
            continue
        started = time.perf_counter()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(source.find_alternatives, ecosystem=ecosystem, category=category,
                                     purpose_text=purpose_text)
            found = future.result(timeout=timeout)
            breaker.record_success()
            outcome = FetchOutcome.OK if found else FetchOutcome.NOT_FOUND
            results.append(SourceResult(source.name, outcome, tuple(found or ()),
                                        latency_ms=int((time.perf_counter() - started) * 1000)))
        except concurrent.futures.TimeoutError:
            breaker.record_failure()
            results.append(SourceResult(source.name, FetchOutcome.ERROR, error="timeout",
                                        latency_ms=int((time.perf_counter() - started) * 1000)))
        except Exception as exc:  # noqa: BLE001 - adapter failures are a degraded state, never fatal
            breaker.record_failure()
            results.append(SourceResult(source.name, FetchOutcome.ERROR, error=type(exc).__name__,
                                        latency_ms=int((time.perf_counter() - started) * 1000)))
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
    return results


__all__ = [
    "ExternalCandidate",
    "PackageMetadataSource",
    "SourceResult",
    "clear_sources",
    "configured_sources",
    "query_sources",
    "register_source",
]
