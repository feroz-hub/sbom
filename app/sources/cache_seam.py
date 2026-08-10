"""Source-response cache seam (roadmap #2, PR-B).

Per-component cache wrapper for per-component external vulnerability
sources. Wraps the FETCH boundary only — the cached payload flows
through the normal processing path on hit so #1 / #3 / #6 logic
(version-range filter, confidence scorer, strategy capture) runs fresh
on every read regardless of cache state.

What's here
-----------
* ``component_cache_key(comp)`` — builds the canonical PURL key shape
  the cache uses. Returns ``None`` when no usable PURL is available;
  the seam then falls through to a live fetch with no cache read/write
  (cache fails open).
* ``cached_fetch(source, key, *, live_fetch, settings)`` — the seam
  itself. Flag-off path is a pass-through (byte-identical to today).
  Flag-on path: read cache → return on fresh hit; else live_fetch +
  write cache. Storage failures are logged-and-swallowed; the live
  fetch is never blocked by a cache problem.
* Structured-event metrics on the ``sbom.source_cache.metrics``
  logger, mirroring the helper at ``analysis.py::_emit_nvd_metric``.

What's NOT here
---------------
* Force-refresh / bypass (PR-D).
* Periodic sweep of expired rows (housekeeping, future).
* Per-source TTL override (the seam reads
  ``settings.source_cache_ttl_seconds`` as a single default; the
  repository's ``set`` signature already accepts a per-call override
  so the upgrade is one-file when calibration ships).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable
from typing import Any

from .purl import parse_purl

log = logging.getLogger(__name__)


# Structured metrics. Same shape as analysis.py::_emit_nvd_metric so
# log handlers + dashboards already wired for that pattern pick this
# up uniformly. Tests assert via stdlib ``caplog``.
_SOURCE_CACHE_METRICS_LOG = logging.getLogger("sbom.source_cache.metrics")


def _emit_source_cache_metric(name: str, *, source: str, value: int = 1) -> None:
    _SOURCE_CACHE_METRICS_LOG.info(
        name,
        extra={"metric": name, "labels": {"source": source}, "value": value},
    )


# ---------------------------------------------------------------------------
# Component key
# ---------------------------------------------------------------------------


# Ecosystems whose package names are case-insensitive in their
# canonical registry. Lowercasing the namespace+name here is safe and
# raises hit-rate when upstream payloads vary in casing.
_NPM_LOWERCASE_ECOSYSTEMS = frozenset({"npm"})

# Ecosystems with their own normalisation rules (see code below).
_PYPI_ECOSYSTEMS = frozenset({"pypi"})

# PEP 503: lowercase + collapse runs of [-_.] to a single dash. Used
# only for ``pypi``; other ecosystems preserve case verbatim.
_PYPI_NAME_NORMALISE_RE = re.compile(r"[-_.]+")


def _parse_canonical_parts(
    comp: dict,
) -> tuple[str, str, str, str, dict[str, str]] | None:
    """Return ``(type, namespace, name, version, qualifiers)`` after
    applying the canonical per-ecosystem normalisation used by both
    versioned and versionless cache keys, or ``None`` when the input
    has no usable PURL.
    """
    purl = comp.get("purl")
    if not isinstance(purl, str) or not purl:
        return None
    parsed = parse_purl(purl)
    if not parsed:
        return None
    ptype = (parsed.get("type") or "").lower()
    if not ptype:
        return None
    name = parsed.get("name") or ""
    if not name:
        return None
    namespace = parsed.get("namespace") or ""
    version = parsed.get("version") or ""
    qualifiers = parsed.get("qualifiers") or {}

    if ptype in _NPM_LOWERCASE_ECOSYSTEMS:
        namespace = namespace.lower()
        name = name.lower()
    elif ptype in _PYPI_ECOSYSTEMS:
        # PEP 503 normalisation. PyPI has no namespace concept.
        name = _PYPI_NAME_NORMALISE_RE.sub("-", name.lower())
        namespace = ""
    # else: leave case as-is

    return ptype, namespace, name, version, qualifiers


def component_cache_key(comp: dict) -> str | None:
    """Canonical version-included PURL key for the response cache.

    Returns ``None`` for any component without a parseable PURL — the
    caller should fall through to an uncached live fetch in that case.

    Normalisation
    ~~~~~~~~~~~~~
      * PURL ``type`` lowercased (spec — type is case-insensitive).
      * ``npm`` → lowercase namespace + name (registry-normalised).
      * ``pypi`` → PEP 503: lowercase name, collapse ``[-_.]+`` to a
        single dash. PyPI has no namespace concept; force empty.
      * Other ecosystems (``maven``, ``golang``, ``nuget``, ``rubygems``,
        ``composer``, ``cargo``, ``deb``, ``rpm``, ``apk``, ``conan``,
        ``generic``) preserve case — Maven artifact IDs and golang
        import paths are case-sensitive at upstream.
      * Version preserved verbatim — version-strings can be
        case-sensitive in some ecosystems (``1.0.0-RC1`` vs
        ``1.0.0-rc1``).
      * Qualifiers retained, sorted by key for deterministic ordering.
        ``classifier=sources`` matters for Maven; we don't drop it.
      * Subpath dropped (not vulnerability-relevant).

    Repository is case-sensitive (PR-A), so a normalisation mismatch
    between writer and reader yields a cache MISS — never a wrong-vuln
    collision. Consistency only costs hit-rate.
    """
    parts_tuple = _parse_canonical_parts(comp)
    if parts_tuple is None:
        return None
    ptype, namespace, name, version, qualifiers = parts_tuple

    parts: list[str] = [f"pkg:{ptype}/"]
    if namespace:
        parts.append(namespace)
        parts.append("/")
    parts.append(name)
    if version:
        parts.append("@")
        parts.append(version)
    if qualifiers:
        sorted_q = "&".join(f"{k}={v}" for k, v in sorted(qualifiers.items()))
        parts.append("?")
        parts.append(sorted_q)
    return "".join(parts)


def component_cache_key_versionless(comp: dict) -> str | None:
    """Canonical VERSIONLESS PURL key — for sources whose query is
    version-agnostic (GHSA's ``securityVulnerabilities(ecosystem,
    package)``). Same per-ecosystem normalisation as
    :func:`component_cache_key`, but the ``@version`` suffix is
    dropped and qualifiers are also dropped (a Maven ``classifier``
    only matters for version-specific lookups; GHSA returns the same
    advisory set regardless).

    Two components sharing ``(type, namespace, name)`` but differing
    in version yield the SAME key. That is the whole point: GHSA
    deduplicates the fetch at ``(eco, name)`` granularity, so the
    cache key matches.

    Returns ``None`` when no usable PURL is available.
    """
    parts_tuple = _parse_canonical_parts(comp)
    if parts_tuple is None:
        return None
    ptype, namespace, name, _version, _qualifiers = parts_tuple

    parts: list[str] = [f"pkg:{ptype}/"]
    if namespace:
        parts.append(namespace)
        parts.append("/")
    parts.append(name)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Cached fetch seam
# ---------------------------------------------------------------------------


async def cached_fetch(
    source: str,
    component_key: str | None,
    *,
    live_fetch: Callable[[], Awaitable[Any]],
    settings: Any,
) -> Any:
    """Run ``live_fetch`` under the source-response cache when enabled.

    Returns the cached payload on a fresh hit, otherwise calls
    ``live_fetch()`` and writes the result to the cache.

    Failure modes are all "fall through to live fetch":
      * Flag off: pure pass-through, no DB session opened.
      * ``component_key`` is ``None``: pass-through (no usable cache key).
      * Cache read raises: warn + treat as miss.
      * Cache write raises: warn (and continue — the live fetch's
        result is still returned).

    The cache uses its OWN session per call so the seam doesn't hold
    a connection across the live fetch's awaits. PR-A's repository
    accepts the session in its constructor — the seam owns the
    lifecycle here.
    """
    if not bool(getattr(settings, "source_cache_enabled", False)):
        return await live_fetch()
    if component_key is None:
        return await live_fetch()

    # Lazy imports break a load-time circular: ``app.db`` and
    # ``app.services.source_response_cache`` both import from
    # ``app.models`` which transitively imports from ``app.sources``
    # through other modules. Paying the import cost once on first call
    # is fine.
    from app.db import SessionLocal
    from app.services.source_response_cache import (
        SourceResponseCacheRepository,
    )

    # Roadmap #2 PR-E — force-refresh bypass. When the per-run flag is
    # set, skip the cache read entirely and treat as a miss; the write
    # phase below still fires so the fresh result OVERWRITES the stale
    # entry (PR-A's repository.set is last-write-wins). Force-refresh
    # is "get fresh data now AND update the cache for next time," not
    # "disable the cache."
    force_refresh = bool(getattr(settings, "source_cache_force_refresh", False))

    # Read phase
    cached: Any = None
    if not force_refresh:
        try:
            with SessionLocal() as session:
                repo = SourceResponseCacheRepository(session)
                cached = repo.get(source, component_key)
        except Exception as exc:  # pragma: no cover — defensive
            log.warning(
                "source_cache: read failed (source=%r key=%r): %s",
                source,
                component_key,
                exc,
            )
            cached = None

    if cached is not None:
        _emit_source_cache_metric("source_cache.hit_total", source=source)
        return cached

    _emit_source_cache_metric("source_cache.miss_total", source=source)

    # Live fetch — propagates any exception from the source.
    payload = await live_fetch()

    # Write phase. Repository's ``set`` is already defensive (rollback
    # on failure, never raises) but wrap defensively in case the
    # session-open itself fails.
    ttl = int(getattr(settings, "source_cache_ttl_seconds", 4 * 60 * 60) or 4 * 60 * 60)
    try:
        with SessionLocal() as session:
            repo = SourceResponseCacheRepository(session)
            repo.set(source, component_key, payload, ttl_seconds=ttl)
    except Exception as exc:  # pragma: no cover — defensive
        log.warning(
            "source_cache: write failed (source=%r key=%r): %s",
            source,
            component_key,
            exc,
        )

    return payload


async def partition_by_cache(
    source: str,
    items_with_keys: list[tuple[str | None, Any]],
    *,
    settings: Any,
) -> tuple[dict[str, Any], list[Any]]:
    """Partition ``items_with_keys`` into cache hits and live-fetch misses.

    Used by batch-shaped sources (OSV, roadmap #2 PR-D) where the
    single-fetch ``cached_fetch`` seam doesn't fit. Opens ONE DB session
    for the whole partition pass so an N-component scan reads cache in
    a single round trip rather than N.

    Behaviour
    ~~~~~~~~~
      * Flag off → returns ``({}, [v for _, v in items])`` immediately
        without opening a session or emitting metrics. Byte-identical
        no-op for the caller's flag-off path.
      * Item key is ``None`` → goes to misses (no cache lookup possible).
      * Read fails (any exception) → fail open. Returns
        ``({}, [v for _, v in items])`` so every item retries live;
        the warning is logged.
      * Otherwise per-item ``repo.get(source, key)``; hit goes to
        ``hits``, miss to misses list. Per-item ``source_cache.hit_total``
        / ``miss_total`` metric fires with the same shape PR-B used.

    Returns
    -------
    ``(hits, misses)`` where ``hits`` maps ``cache_key`` → cached
    payload (whatever the producer wrote — could be a list, dict,
    primitive, or empty container) and ``misses`` is the list of
    original values that need live fetches.
    """
    if not bool(getattr(settings, "source_cache_enabled", False)):
        return {}, [v for _, v in items_with_keys]

    # Roadmap #2 PR-E — force-refresh bypass. Same semantic as
    # ``cached_fetch``: skip the read pass entirely so every item lands
    # in the miss list (the caller fetches live), but later
    # ``write_cache_entries`` calls still run so the fresh results
    # overwrite stale rows. Emit a miss metric per item so dashboards
    # accurately count the bypass-induced "misses".
    force_refresh = bool(getattr(settings, "source_cache_force_refresh", False))
    if force_refresh:
        for key, _value in items_with_keys:
            if key is not None:
                _emit_source_cache_metric(
                    "source_cache.miss_total",
                    source=source,
                )
        return {}, [v for _, v in items_with_keys]

    from app.db import SessionLocal
    from app.services.source_response_cache import (
        SourceResponseCacheRepository,
    )

    hits: dict[str, Any] = {}
    misses: list[Any] = []

    try:
        with SessionLocal() as session:
            repo = SourceResponseCacheRepository(session)
            for key, value in items_with_keys:
                if key is None:
                    misses.append(value)
                    continue
                cached = repo.get(source, key)
                if cached is not None:
                    hits[key] = cached
                    _emit_source_cache_metric(
                        "source_cache.hit_total",
                        source=source,
                    )
                else:
                    misses.append(value)
                    _emit_source_cache_metric(
                        "source_cache.miss_total",
                        source=source,
                    )
    except Exception as exc:  # pragma: no cover — defensive
        log.warning(
            "source_cache: batch read failed (source=%r): %s — falling open",
            source,
            exc,
        )
        return {}, [v for _, v in items_with_keys]

    return hits, misses


def write_cache_entries(
    source: str,
    entries: list[tuple[str, Any]],
    *,
    settings: Any,
) -> None:
    """Bulk-write cache entries. No-op when flag off or entries empty.

    Empty payloads (``[]``, ``{}``) are intentionally cacheable — for
    batch sources, "this component had no OSV vulns" is a HIT-worthy
    fact and shouldn't be re-fetched until TTL.

    Storage failures are logged + swallowed; the repository's ``set``
    is itself defensive (rollback on error), so the worst case is
    "some entries didn't write" rather than a raised exception
    reaching the caller.
    """
    if not bool(getattr(settings, "source_cache_enabled", False)):
        return
    if not entries:
        return
    ttl = int(getattr(settings, "source_cache_ttl_seconds", 4 * 60 * 60) or 4 * 60 * 60)

    from app.db import SessionLocal
    from app.services.source_response_cache import (
        SourceResponseCacheRepository,
    )

    try:
        with SessionLocal() as session:
            repo = SourceResponseCacheRepository(session)
            for key, payload in entries:
                if key is None:
                    continue
                repo.set(source, key, payload, ttl_seconds=ttl)
    except Exception as exc:  # pragma: no cover — defensive
        log.warning(
            "source_cache: bulk write failed (source=%r entries=%d): %s",
            source,
            len(entries),
            exc,
        )


__all__ = [
    "cached_fetch",
    "component_cache_key",
    "component_cache_key_versionless",
    "partition_by_cache",
    "write_cache_entries",
]
