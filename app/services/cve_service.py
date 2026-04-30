"""
CveDetailService — read-through cache + delegate to the aggregator.

Flow for ``get(raw_id)``:
  1. ``classify(raw_id)``. If the ID format isn't recognised, raise
     :class:`UnrecognizedIdFormatError` — the API layer maps that to a
     400 with a structured envelope (``CVE_VAL_E001_UNRECOGNIZED_ID``).
  2. Read ``cve_cache`` keyed on ``vid.normalized``. If present and
     ``expires_at > now()``, return cached.
  3. Otherwise call ``aggregator.aggregate(vid, sources)`` — that is now
     the single owner of fan-out, alias re-fan, status derivation.
  4. Upsert into ``cve_cache`` with TTL-bucketed ``expires_at``.
  5. Return ``CveDetail`` (always — never raises on upstream failure).

The scan-aware variant additionally joins ``AnalysisFinding`` to derive
component context and the recommended-upgrade callout.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..integrations.cve.aggregator import aggregate
from ..integrations.cve.epss import EpssSource
from ..integrations.cve.ghsa import GhsaClient
from ..integrations.cve.identifiers import IdKind, SUPPORTED_FORMATS, classify
from ..integrations.cve.kev import KevSource
from ..integrations.cve.nvd import NvdClient
from ..integrations.cve.osv import OsvClient
from ..models import AnalysisFinding, AnalysisRun, CveCache, SBOMComponent
from ..schemas_cve import (
    CveDetail,
    CveDetailWithContext,
    CveResultStatus,
    CveScanContext,
)
from ..settings import get_settings

log = logging.getLogger("sbom.services.cve")

#: Cache schema version. Bumped to 2 when CveResultStatus was added — old
#: rows missing that field deserialise with the default (``OK``) but the
#: service treats schema_version<2 as stale and refetches on read.
CACHE_SCHEMA_VERSION = 2


class UnrecognizedIdFormatError(ValueError):
    """
    Raised when an identifier doesn't match any supported format.

    Carries the raw input verbatim so the API layer can echo it in the
    error envelope without the user having to retype. This is distinct
    from :class:`InvalidCveIdError` (kept as an alias for back-compat with
    callers that expected the legacy name).
    """

    def __init__(self, raw_id: str) -> None:
        super().__init__(f"unrecognized advisory identifier format: {raw_id!r}")
        self.raw_id = raw_id


# Back-compat: callers that imported the legacy name still work.
InvalidCveIdError = UnrecognizedIdFormatError


def normalise_cve_id(value: str) -> str:
    """Validate + canonicalise. Raises :class:`UnrecognizedIdFormatError`.

    Kept as ``normalise_cve_id`` (and not renamed to ``normalise_vuln_id``)
    for back-compat with callers and tests that already hold this name.
    """
    if not isinstance(value, str):
        raise UnrecognizedIdFormatError(str(value))
    vid = classify(value)
    if vid.kind == IdKind.UNKNOWN:
        raise UnrecognizedIdFormatError(value)
    return vid.normalized


def is_cve_id(value: str) -> bool:
    """True if ``value`` classifies as a CVE."""
    return classify(value).kind == IdKind.CVE


def is_ghsa_id(value: str) -> bool:
    """True if ``value`` classifies as a GHSA."""
    return classify(value).kind == IdKind.GHSA


class CveDetailService:
    """
    Cache-read-through service that fans enrichment fetches out across the
    enabled CVE sources, merges, persists, and returns ``CveDetail``.

    ``http_clients`` and ``db`` adapters are injectable for tests; the
    default constructor builds the production wiring.
    """

    def __init__(
        self,
        db: Session,
        *,
        osv: OsvClient | None = None,
        ghsa: GhsaClient | None = None,
        nvd: NvdClient | None = None,
        kev: KevSource | None = None,
        epss: EpssSource | None = None,
    ) -> None:
        self._db = db
        s = get_settings()
        enabled = set(s.cve_sources_enabled_list)
        self._sources = []
        if "osv" in enabled:
            self._sources.append(osv or OsvClient())
        if "ghsa" in enabled:
            self._sources.append(ghsa or GhsaClient())
        if "nvd" in enabled:
            self._sources.append(nvd or NvdClient())
        if "kev" in enabled:
            self._sources.append(kev or KevSource(db))
        if "epss" in enabled:
            self._sources.append(epss or EpssSource(db))

    # ------------------------------------------------------------------ public

    async def get(self, cve_id: str) -> CveDetail:
        """Fetch a single advisory — cache-read-through.

        ``cve_id`` accepts any supported identifier kind (CVE / GHSA /
        PYSEC / RUSTSEC / GO). Raises :class:`UnrecognizedIdFormatError`
        when the format isn't recognised; the API layer maps that to 400.
        """
        vid = classify(cve_id)
        if vid.kind == IdKind.UNKNOWN:
            raise UnrecognizedIdFormatError(cve_id)
        cached = self._read_cache(vid.normalized)
        if cached is not None:
            return cached
        return await self._fetch_and_cache(vid)

    async def get_many(self, cve_ids: Iterable[str]) -> dict[str, CveDetail]:
        """Fetch many advisories concurrently. Unrecognised IDs raise."""
        vids: dict[str, IdKind] = {}
        for raw in cve_ids:
            v = classify(raw)
            if v.kind == IdKind.UNKNOWN:
                raise UnrecognizedIdFormatError(raw)
            vids[v.normalized] = v.kind
        if not vids:
            return {}
        out: dict[str, CveDetail] = {}
        cold: list[str] = []
        for n in sorted(vids.keys()):
            hit = self._read_cache(n)
            if hit is not None:
                out[n] = hit
            else:
                cold.append(n)
        if cold:
            tasks = [self._fetch_and_cache(classify(c)) for c in cold]
            results = await asyncio.gather(*tasks)
            for c, r in zip(cold, results):
                out[c] = r
        return out

    async def get_with_scan_context(self, cve_id: str, scan_id: int) -> CveDetailWithContext:
        """Scan-aware variant — joins component context + recommended upgrade."""
        detail = await self.get(cve_id)
        run = self._db.get(AnalysisRun, scan_id)
        if run is None:
            return CveDetailWithContext(**detail.model_dump())

        cve = detail.cve_id
        finding = (
            self._db.execute(
                select(AnalysisFinding)
                .where(AnalysisFinding.analysis_run_id == scan_id)
                .where(AnalysisFinding.vuln_id == cve)
            )
            .scalars()
            .first()
        )
        if finding is None:
            # The scan exists but doesn't carry this CVE — return detail with empty context.
            return CveDetailWithContext(**detail.model_dump())

        component = self._component_context(finding)
        status, recommended = self._upgrade_recommendation(detail, component)

        return CveDetailWithContext(
            **detail.model_dump(),
            component=component,
            current_version_status=status,
            recommended_upgrade=recommended,
        )

    # ------------------------------------------------------------------ cache

    def _read_cache(self, cve_id: str) -> CveDetail | None:
        """Read a cached payload by canonical id.

        Misses include: row not present, ``expires_at`` passed, payload
        unparseable, OR ``schema_version`` below the current code version
        (lazy refresh path — see ``CACHE_SCHEMA_VERSION``).
        """
        row = self._db.get(CveCache, cve_id)
        if row is None:
            return None
        if (row.schema_version or 1) < CACHE_SCHEMA_VERSION:
            return None
        try:
            expires = datetime.fromisoformat(row.expires_at)
        except ValueError:
            return None
        if datetime.now(timezone.utc) >= expires:
            return None
        try:
            payload = row.payload if isinstance(row.payload, dict) else json.loads(row.payload)
            return CveDetail.model_validate(payload)
        except (ValueError, TypeError) as exc:
            log.warning("cve_cache deserialise failed for %s: %s", cve_id, exc)
            return None

    def _write_cache(self, detail: CveDetail) -> None:
        ttl = self._ttl_for(detail)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl)
        payload = detail.model_dump(mode="json")
        try:
            self._db.merge(
                CveCache(
                    cve_id=detail.cve_id,
                    payload=payload,
                    sources_used=",".join(detail.sources_used),
                    fetched_at=now.isoformat(),
                    expires_at=expires.isoformat(),
                    fetch_error=None if detail.status == CveResultStatus.OK else detail.status.value,
                    schema_version=CACHE_SCHEMA_VERSION,
                )
            )
            self._db.commit()
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("cve_cache write failed for %s: %s", detail.cve_id, exc)
            self._db.rollback()

    def _ttl_for(self, detail: CveDetail) -> int:
        s = get_settings()
        if detail.exploitation.cisa_kev_listed:
            return s.cve_cache_ttl_kev_seconds
        if not detail.sources_used:
            return s.cve_cache_ttl_error_seconds
        if detail.published_at is not None:
            age_days = (datetime.now(timezone.utc) - detail.published_at).days
            if age_days <= s.cve_recent_window_days:
                return s.cve_cache_ttl_recent_seconds
        return s.cve_cache_ttl_stable_seconds

    # ------------------------------------------------------------------ fetch

    async def _fetch_and_cache(self, vid) -> CveDetail:
        """Delegate fan-out + alias resolution + status derivation to the
        aggregator, then persist. This is the only remaining I/O path; the
        legacy bespoke two-pass methods that used to live here have moved
        into ``aggregator.aggregate`` so the orchestration logic has a
        single owner.
        """
        detail = await aggregate(vid, self._sources)
        self._write_cache(detail)
        return detail

    # ------------------------------------------------------------------ scan

    def _component_context(self, finding: AnalysisFinding) -> CveScanContext:
        # Prefer the linked SBOMComponent row (carries purl + ecosystem) if present;
        # fall back to the denormalised name/version on the finding.
        component_row: SBOMComponent | None = None
        if finding.component_id is not None:
            component_row = self._db.get(SBOMComponent, finding.component_id)
        if component_row is not None:
            return CveScanContext(
                name=component_row.name or (finding.component_name or "unknown"),
                version=component_row.version or finding.component_version,
                ecosystem=_purl_ecosystem(component_row.purl),
                purl=component_row.purl,
            )
        return CveScanContext(
            name=finding.component_name or "unknown",
            version=finding.component_version,
            ecosystem=None,
            purl=None,
        )

    def _upgrade_recommendation(
        self, detail: CveDetail, component: CveScanContext
    ) -> tuple[str, str | None]:
        """
        Pick the best upgrade target from ``fix_versions`` for the detected
        component. Returns (status, recommended_upgrade).

        Status decisions:
          * ``vulnerable`` if the current version is below at least one fix
          * ``fixed``      if the current version is at-or-above every applicable fix
          * ``unknown``    if no fix-version row applies to this ecosystem

        Version comparison is intentionally simple — packaging.version when it
        parses, lexicographic fallback otherwise. Cross-ecosystem semver
        nuances (npm semver ranges, Maven's quirks) are out of scope for v1.
        """
        if not detail.fix_versions or not component.version:
            return "unknown", None

        applicable = [
            fv
            for fv in detail.fix_versions
            if fv.fixed_in
            and (component.ecosystem is None or fv.ecosystem.lower() == (component.ecosystem or "").lower())
            and (fv.package.lower() == component.name.lower())
        ]
        if not applicable:
            # Try without ecosystem strict-match — name match alone.
            applicable = [
                fv
                for fv in detail.fix_versions
                if fv.fixed_in and fv.package.lower() == component.name.lower()
            ]
        if not applicable:
            return "unknown", None

        try:
            from packaging.version import InvalidVersion, Version

            current = Version(component.version)
            unfixed = [fv for fv in applicable if Version(fv.fixed_in or "0") > current]
            if not unfixed:
                return "fixed", None
            unfixed.sort(key=lambda fv: Version(fv.fixed_in or "0"))
            return "vulnerable", unfixed[0].fixed_in
        except (InvalidVersion, Exception):
            # Lexicographic fallback — better than nothing.
            for fv in applicable:
                if (fv.fixed_in or "") > (component.version or ""):
                    return "vulnerable", fv.fixed_in
            return "fixed", None


def _purl_ecosystem(purl: str | None) -> str | None:
    """Extract a coarse ecosystem hint from a Package URL (purl)."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = purl[len("pkg:") :]
    eco = rest.split("/", 1)[0].split("@", 1)[0]
    if not eco:
        return None
    # purl uses lowercase types ("npm", "pypi", "maven"); map a couple back to the
    # OSV-canonical names where they differ.
    mapping = {"pypi": "PyPI", "maven": "Maven", "nuget": "NuGet", "rubygems": "RubyGems"}
    return mapping.get(eco.lower(), eco)
