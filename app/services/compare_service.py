"""
CompareService — diff two analysis runs (ADR-0008).

Public surface:

    svc = CompareService(db)
    result = svc.compare(run_a_id, run_b_id)            # CompareResult
    svc.invalidate_for_run(run_id)                      # cache hook

Algorithm (one pass, two SELECTs per side, no N+1):

    1.  Validate identity (same-run guard).
    2.  Load both runs (eager-load sbom + project for the picker headers).
    3.  Status guard — both must be in COMPARABLE_RUN_STATUSES.
    4.  Cache check — return cached payload if present and not expired.
    5.  Load components and findings for each run in two queries each.
    6.  Build the component diff (identity = (name_lower, ecosystem)).
    7.  Build the finding diff (identity = (vuln_id_canonical, name, ver)).
    8.  Attribute every ``added`` / ``resolved`` finding to a component
        change row (or fallback string).
    9.  Compute posture (KEV / fix-available / high-critical / severity
        distribution / top contributors). NO scalar score.
    10. Persist into ``compare_cache`` and return.

License + hash change_kinds are scaffolded but never fire in v1 — gated
behind ``Settings.compare_license_hash_enabled`` per ADR-0008 §10 OOS.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..integrations.cve.identifiers import IdKind, classify
from ..models import (
    AnalysisFinding,
    AnalysisRun,
    CompareCache,
    CveCache,
    KevEntry,
    Projects,
    SBOMComponent,
    SBOMSource,
)
from ..schemas_compare import (
    COMPARABLE_RUN_STATUSES,
    CompareResult,
    ComponentChangeKind,
    ComponentDiffRow,
    ERR_COMPARE_RUN_NOT_FOUND,
    ERR_COMPARE_RUN_NOT_READY,
    ERR_COMPARE_SAME_RUN,
    FindingChangeKind,
    FindingDiffRow,
    PostureDelta,
    RunRelationship,
    RunSummary,
)
from ..schemas_cve import CveSeverity
from ..services.cve_service import _purl_ecosystem
from ..settings import Settings, get_settings

log = logging.getLogger("sbom.services.compare")

# =============================================================================
# Public exceptions — routers map to specific HTTP envelopes
# =============================================================================


class CompareError(Exception):
    """Base for compare-service-specific errors."""

    error_code: str = "COMPARE_E000_UNKNOWN"
    http_status: int = 500


class RunNotFoundError(CompareError):
    error_code = ERR_COMPARE_RUN_NOT_FOUND
    http_status = 404

    def __init__(self, run_id: int) -> None:
        super().__init__(f"run {run_id} not found")
        self.run_id = run_id


class RunNotReadyError(CompareError):
    error_code = ERR_COMPARE_RUN_NOT_READY
    http_status = 409

    def __init__(self, run_id: int, status: str) -> None:
        super().__init__(f"run {run_id} status={status} is not comparable")
        self.run_id = run_id
        self.status = status


class SameRunError(CompareError):
    error_code = ERR_COMPARE_SAME_RUN
    http_status = 400

    def __init__(self, run_id: int) -> None:
        super().__init__(f"runs A and B are the same ({run_id})")
        self.run_id = run_id


# =============================================================================
# Internal data structures (private to this module)
# =============================================================================


@dataclass(frozen=True)
class _FindingKey:
    """Identity tuple for a finding diff row. See ADR-0008 §7.2."""

    vuln_id_canonical: str  # uppercase, classified-or-raw
    component_name: str  # lowercase
    component_version: str  # raw; empty string if missing


@dataclass(frozen=True)
class _ComponentKey:
    """Identity tuple for a component diff row. See ADR-0008 §7.1."""

    name: str  # lowercase
    ecosystem: str  # mixed-case ecosystem (PyPI, npm, ...) or 'unknown'


@dataclass
class _LoadedFinding:
    """In-memory snapshot of one finding row + its joined component PURL."""

    vuln_id_raw: str
    severity: CveSeverity
    component_name: str
    component_version: str
    component_purl: str | None
    fix_available: bool


@dataclass
class _LoadedComponent:
    """In-memory snapshot of one component row."""

    name: str
    ecosystem: str
    version: str
    purl: str | None
    license: str | None  # always None today
    content_hash: str | None  # always None today


# =============================================================================
# Service
# =============================================================================


class CompareService:
    """Stateless wrapper around a DB session. Cheap to construct per request."""

    def __init__(self, db: Session, *, settings: Settings | None = None) -> None:
        self._db = db
        self._settings = settings or get_settings()

    # -- public API -----------------------------------------------------------

    def compare(self, run_a_id: int, run_b_id: int) -> CompareResult:
        """Run the full diff. May read from or write to ``compare_cache``."""
        if run_a_id == run_b_id:
            raise SameRunError(run_a_id)

        run_a = self._load_run(run_a_id)
        run_b = self._load_run(run_b_id)
        self._guard_status(run_a)
        self._guard_status(run_b)

        cache_key = compute_cache_key(run_a_id, run_b_id)
        cached = self._read_cache(cache_key)
        if cached is not None:
            log.info(
                "compare cache_hit cache_key=%s run_a=%d run_b=%d",
                cache_key,
                run_a_id,
                run_b_id,
            )
            return cached

        log.info(
            "compare cache_miss cache_key=%s run_a=%d run_b=%d",
            cache_key,
            run_a_id,
            run_b_id,
        )
        result = self._compute(cache_key, run_a, run_b)
        self._write_cache(result)
        return result

    def invalidate_for_run(self, run_id: int) -> int:
        """Delete every cache row referencing ``run_id``. Returns row count."""
        rows = (
            self._db.execute(
                select(CompareCache).where(
                    (CompareCache.run_a_id == run_id)
                    | (CompareCache.run_b_id == run_id)
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            self._db.delete(row)
        if rows:
            self._db.commit()
            log.info(
                "compare cache_invalidated run_id=%d rows=%d",
                run_id,
                len(rows),
            )
        return len(rows)

    # -- step 2 / 3 -----------------------------------------------------------

    def _load_run(self, run_id: int) -> AnalysisRun:
        run = self._db.get(AnalysisRun, run_id)
        if run is None:
            raise RunNotFoundError(run_id)
        return run

    def _guard_status(self, run: AnalysisRun) -> None:
        status = (run.run_status or "").upper()
        if status not in COMPARABLE_RUN_STATUSES:
            raise RunNotReadyError(run.id, status)

    # -- step 4 ---------------------------------------------------------------

    def _read_cache(self, cache_key: str) -> CompareResult | None:
        row = self._db.get(CompareCache, cache_key)
        if row is None:
            return None
        if _expires_at_passed(row.expires_at):
            self._db.delete(row)
            self._db.commit()
            return None
        try:
            return CompareResult.model_validate(row.payload)
        except Exception as exc:
            log.warning(
                "compare cache_corrupt cache_key=%s err=%s — discarding row",
                cache_key,
                exc,
            )
            self._db.delete(row)
            self._db.commit()
            return None

    def _write_cache(self, result: CompareResult) -> None:
        ttl = self._settings.compare_cache_ttl_seconds
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        existing = self._db.get(CompareCache, result.cache_key)
        payload = json.loads(result.model_dump_json())  # ensure JSON-portable
        if existing is None:
            self._db.add(
                CompareCache(
                    cache_key=result.cache_key,
                    run_a_id=result.run_a.id,
                    run_b_id=result.run_b.id,
                    payload=payload,
                    computed_at=result.computed_at.isoformat(),
                    expires_at=expires_at.isoformat(),
                    schema_version=result.schema_version,
                )
            )
        else:
            existing.payload = payload
            existing.computed_at = result.computed_at.isoformat()
            existing.expires_at = expires_at.isoformat()
            existing.run_a_id = result.run_a.id
            existing.run_b_id = result.run_b.id
            existing.schema_version = result.schema_version
        self._db.commit()

    # -- step 5–10 (orchestration) -------------------------------------------

    def _compute(
        self,
        cache_key: str,
        run_a: AnalysisRun,
        run_b: AnalysisRun,
    ) -> CompareResult:
        comps_a = self._load_components(run_a.sbom_id)
        comps_b = self._load_components(run_b.sbom_id)
        finds_a = self._load_findings(run_a.id)
        finds_b = self._load_findings(run_b.id)

        component_diff = self._diff_components(comps_a, comps_b)
        finding_diff = self._diff_findings(finds_a, finds_b)

        # Enrich findings with current KEV / EPSS state. One batch lookup
        # against kev_entry / cve_cache — never refetches.
        kev_set = self._lookup_current_kev(finding_diff)
        epss_map = self._lookup_current_epss(finding_diff)
        for row in finding_diff:
            row.kev_current = row.vuln_id.upper() in kev_set
            entry = epss_map.get(row.vuln_id.upper())
            if entry is not None:
                row.epss_current = entry[0]
                row.epss_percentile_current = entry[1]

        self._attribute_findings(finding_diff, component_diff)

        posture = self._compute_posture(finding_diff, component_diff)

        relationship = self._compute_relationship(run_a, run_b)

        run_a_summary = self._summarize_run(run_a)
        run_b_summary = self._summarize_run(run_b)

        return CompareResult(
            cache_key=cache_key,
            run_a=run_a_summary,
            run_b=run_b_summary,
            relationship=relationship,
            posture=posture,
            findings=finding_diff,
            components=component_diff,
            computed_at=datetime.now(timezone.utc),
            schema_version=1,
        )

    # -- step 5: load --------------------------------------------------------

    def _load_components(self, sbom_id: int | None) -> dict[_ComponentKey, _LoadedComponent]:
        if sbom_id is None:
            return {}
        rows = (
            self._db.execute(
                select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)
            )
            .scalars()
            .all()
        )
        out: dict[_ComponentKey, _LoadedComponent] = {}
        for r in rows:
            name = (r.name or "").strip()
            if not name:
                continue
            ecosystem = _purl_ecosystem(r.purl) or "unknown"
            key = _ComponentKey(name=name.lower(), ecosystem=ecosystem)
            # If duplicate (rare; sbom_component has a uq fingerprint that
            # includes bom_ref + version + cpe so identity collisions on
            # (name, ecosystem) only) keep the first version we see and
            # ignore alternates — it's an edge case that ADR-0008 §7.1
            # explicitly accepts.
            if key in out:
                continue
            out[key] = _LoadedComponent(
                name=name,
                ecosystem=ecosystem,
                version=(r.version or "").strip(),
                purl=r.purl,
                license=getattr(r, "license", None),  # never present today
                content_hash=getattr(r, "content_hash", None),  # never present today
            )
        return out

    def _load_findings(self, run_id: int) -> dict[_FindingKey, _LoadedFinding]:
        # LEFT JOIN to SBOMComponent so we pick up the PURL when component_id
        # is set (most rows). Findings without a component_id still produce a
        # row, just with purl=None.
        stmt = (
            select(AnalysisFinding, SBOMComponent.purl)
            .where(AnalysisFinding.analysis_run_id == run_id)
            .outerjoin(
                SBOMComponent, SBOMComponent.id == AnalysisFinding.component_id
            )
        )
        out: dict[_FindingKey, _LoadedFinding] = {}
        for finding, purl in self._db.execute(stmt).all():
            vuln_id_raw = (finding.vuln_id or "").strip()
            if not vuln_id_raw:
                continue
            canonical = _canonicalize_vuln_id(vuln_id_raw)
            comp_name = (finding.component_name or "").strip()
            comp_ver = (finding.component_version or "").strip()
            key = _FindingKey(
                vuln_id_canonical=canonical,
                component_name=comp_name.lower(),
                component_version=comp_ver,
            )
            # Multi-source fan-out can produce multiple rows for the same
            # finding identity (e.g. NVD + OSV both find CVE-X on pkg@1.2.3).
            # The schema's uq_analysis_finding_run_vuln_cpe key uses CPE,
            # which can differ between sources. Collapse on identity here
            # and prefer the most-severe.
            existing = out.get(key)
            sev = _severity_from_str(finding.severity)
            if existing is not None and _severity_ord(existing.severity) >= _severity_ord(sev):
                continue
            out[key] = _LoadedFinding(
                vuln_id_raw=vuln_id_raw,
                severity=sev,
                component_name=comp_name,
                component_version=comp_ver,
                component_purl=purl,
                fix_available=_fix_available(finding.fixed_versions),
            )
        return out

    # -- step 6: component diff ----------------------------------------------

    def _diff_components(
        self,
        a: dict[_ComponentKey, _LoadedComponent],
        b: dict[_ComponentKey, _LoadedComponent],
    ) -> list[ComponentDiffRow]:
        keys = set(a) | set(b)
        out: list[ComponentDiffRow] = []
        license_hash_enabled = self._settings.compare_license_hash_enabled
        for key in keys:
            la = a.get(key)
            lb = b.get(key)
            if la is None and lb is not None:
                out.append(_component_row(ComponentChangeKind.ADDED, key, None, lb))
                continue
            if la is not None and lb is None:
                out.append(_component_row(ComponentChangeKind.REMOVED, key, la, None))
                continue
            assert la is not None and lb is not None
            if la.version != lb.version:
                out.append(
                    _component_row(ComponentChangeKind.VERSION_BUMPED, key, la, lb)
                )
                continue
            # Same version: license / hash diffs. These NEVER fire today
            # because the columns aren't stored, AND additionally the hard
            # guard ``compare_license_hash_enabled`` must be true. See
            # ADR-0008 §10 OOS and Phase 3 user clarification §4.
            if (
                license_hash_enabled
                and la.license is not None
                and lb.license is not None
                and la.license != lb.license
            ):
                out.append(
                    _component_row(ComponentChangeKind.LICENSE_CHANGED, key, la, lb)
                )
                continue
            if (
                license_hash_enabled
                and la.content_hash is not None
                and lb.content_hash is not None
                and la.content_hash != lb.content_hash
            ):
                out.append(
                    _component_row(ComponentChangeKind.HASH_CHANGED, key, la, lb)
                )
                continue
            # Otherwise unchanged — emitted so the Components tab can show
            # ``show_unchanged=true`` rows; client filter excludes by default.
            out.append(_component_row(ComponentChangeKind.UNCHANGED, key, la, lb))
        return out

    # -- step 7: finding diff ------------------------------------------------

    def _diff_findings(
        self,
        a: dict[_FindingKey, _LoadedFinding],
        b: dict[_FindingKey, _LoadedFinding],
    ) -> list[FindingDiffRow]:
        keys = set(a) | set(b)
        out: list[FindingDiffRow] = []
        for key in keys:
            la = a.get(key)
            lb = b.get(key)
            if la is None and lb is not None:
                out.append(_finding_row(FindingChangeKind.ADDED, None, lb))
                continue
            if la is not None and lb is None:
                out.append(_finding_row(FindingChangeKind.RESOLVED, la, None))
                continue
            assert la is not None and lb is not None
            if la.severity != lb.severity:
                out.append(
                    _finding_row(FindingChangeKind.SEVERITY_CHANGED, la, lb)
                )
                continue
            out.append(_finding_row(FindingChangeKind.UNCHANGED, la, lb))
        return out

    # -- step 8: attribution -------------------------------------------------

    def _attribute_findings(
        self,
        findings: list[FindingDiffRow],
        components: list[ComponentDiffRow],
    ) -> None:
        # Strict index by (name_lower, ecosystem) — preferred match.
        # Lax index by name_lower only — fallback for findings whose
        # ``component_id`` FK is null (so the LEFT JOIN to SBOMComponent
        # yielded no purl, leaving ``component_ecosystem`` as "unknown").
        # This is the common case for findings produced by the CPE-matched
        # path, so without the lax fallback most attributions would
        # collapse to "via vulnerability re-classification".
        strict: dict[tuple[str, str], ComponentDiffRow] = {}
        lax: dict[str, ComponentDiffRow] = {}
        for c in components:
            strict[(c.name.lower(), c.ecosystem)] = c
            # Multiple components with the same name but different
            # ecosystems → keep the first one we see for the lax index.
            lax.setdefault(c.name.lower(), c)
        for f in findings:
            if f.change_kind not in (FindingChangeKind.ADDED, FindingChangeKind.RESOLVED):
                continue
            ecosystem = f.component_ecosystem or "unknown"
            comp = strict.get((f.component_name.lower(), ecosystem))
            if comp is None:
                comp = lax.get(f.component_name.lower())
            f.attribution = _attribution_string(f.change_kind, comp)
            if comp is not None:
                if f.change_kind == FindingChangeKind.RESOLVED:
                    comp.findings_resolved += 1
                else:
                    comp.findings_added += 1

    # -- step 9: posture -----------------------------------------------------

    def _compute_posture(
        self,
        findings: list[FindingDiffRow],
        components: list[ComponentDiffRow],
    ) -> PostureDelta:
        # KEV exposure: count findings whose CVE is currently KEV-listed,
        # scoped to each run side. A finding present in run A counts in
        # ``a``; present in B counts in ``b``; present in both counts in
        # both — same definition as the SQL in ADR-0008 §6.1.
        kev_a = sum(1 for f in findings if f.kev_current and _present_in_a(f))
        kev_b = sum(1 for f in findings if f.kev_current and _present_in_b(f))

        # Fix-available coverage (percentage).
        a_total = sum(1 for f in findings if _present_in_a(f))
        b_total = sum(1 for f in findings if _present_in_b(f))
        a_fix = sum(1 for f in findings if _present_in_a(f) and f.fix_available)
        b_fix = sum(1 for f in findings if _present_in_b(f) and f.fix_available)
        fix_pct_a = round((a_fix * 100.0 / a_total), 2) if a_total else 0.0
        fix_pct_b = round((b_fix * 100.0 / b_total), 2) if b_total else 0.0

        # High+Critical exposure.
        hc_a = sum(
            1
            for f in findings
            if _present_in_a(f) and f.severity_a in (CveSeverity.HIGH, CveSeverity.CRITICAL)
        )
        hc_b = sum(
            1
            for f in findings
            if _present_in_b(f) and f.severity_b in (CveSeverity.HIGH, CveSeverity.CRITICAL)
        )

        # Severity composition.
        dist_a = _severity_distribution(findings, side="a")
        dist_b = _severity_distribution(findings, side="b")

        # Distribution-bar / event counts.
        added = sum(1 for f in findings if f.change_kind == FindingChangeKind.ADDED)
        resolved = sum(1 for f in findings if f.change_kind == FindingChangeKind.RESOLVED)
        sev_changed = sum(
            1 for f in findings if f.change_kind == FindingChangeKind.SEVERITY_CHANGED
        )
        unchanged = sum(1 for f in findings if f.change_kind == FindingChangeKind.UNCHANGED)

        comp_added = sum(1 for c in components if c.change_kind == ComponentChangeKind.ADDED)
        comp_removed = sum(
            1 for c in components if c.change_kind == ComponentChangeKind.REMOVED
        )
        comp_bumped = sum(
            1 for c in components if c.change_kind == ComponentChangeKind.VERSION_BUMPED
        )
        comp_unchanged = sum(
            1 for c in components if c.change_kind == ComponentChangeKind.UNCHANGED
        )

        # Top contributors — display-only ordinal rank, NOT a weighted score.
        top_resolutions = _top_contributors(findings, FindingChangeKind.RESOLVED, n=5)
        top_regressions = _top_contributors(findings, FindingChangeKind.ADDED, n=5)

        return PostureDelta(
            kev_count_a=kev_a,
            kev_count_b=kev_b,
            kev_count_delta=kev_b - kev_a,
            fix_available_pct_a=fix_pct_a,
            fix_available_pct_b=fix_pct_b,
            fix_available_pct_delta=round(fix_pct_b - fix_pct_a, 2),
            high_critical_count_a=hc_a,
            high_critical_count_b=hc_b,
            high_critical_count_delta=hc_b - hc_a,
            findings_added_count=added,
            findings_resolved_count=resolved,
            findings_severity_changed_count=sev_changed,
            findings_unchanged_count=unchanged,
            components_added_count=comp_added,
            components_removed_count=comp_removed,
            components_version_bumped_count=comp_bumped,
            components_unchanged_count=comp_unchanged,
            severity_distribution_a=dist_a,
            severity_distribution_b=dist_b,
            top_resolutions=top_resolutions,
            top_regressions=top_regressions,
        )

    # -- step 8 (relationship) -----------------------------------------------

    def _compute_relationship(
        self, run_a: AnalysisRun, run_b: AnalysisRun
    ) -> RunRelationship:
        same_project = (
            run_a.project_id is not None
            and run_b.project_id is not None
            and run_a.project_id == run_b.project_id
        )
        same_sbom = run_a.sbom_id == run_b.sbom_id
        days_between = _days_between(run_a.completed_on, run_b.completed_on)
        direction_warning = None
        if days_between is not None:
            if _parse_iso(run_b.completed_on) < _parse_iso(run_a.completed_on):
                direction_warning = (
                    f"Run B is older than Run A by {abs(days_between):.1f} days "
                    f"— did you mean to swap?"
                )
        return RunRelationship(
            same_project=same_project,
            same_sbom=same_sbom,
            days_between=days_between,
            direction_warning=direction_warning,
        )

    # -- KEV / EPSS lookup helpers (current state, never refetches) ----------

    def _lookup_current_kev(self, findings: list[FindingDiffRow]) -> set[str]:
        ids = {f.vuln_id.upper() for f in findings if f.vuln_id}
        if not ids:
            return set()
        rows = (
            self._db.execute(select(KevEntry.cve_id).where(KevEntry.cve_id.in_(ids)))
            .scalars()
            .all()
        )
        return {(r or "").upper() for r in rows}

    def _lookup_current_epss(
        self, findings: list[FindingDiffRow]
    ) -> dict[str, tuple[float | None, float | None]]:
        ids = {f.vuln_id.upper() for f in findings if f.vuln_id}
        if not ids:
            return {}
        rows = (
            self._db.execute(
                select(CveCache.cve_id, CveCache.payload).where(CveCache.cve_id.in_(ids))
            ).all()
        )
        out: dict[str, tuple[float | None, float | None]] = {}
        for cve_id, payload in rows:
            if not isinstance(payload, dict):
                continue
            exploitation = payload.get("exploitation") or {}
            score = exploitation.get("epss_score")
            pct = exploitation.get("epss_percentile")
            score_f = float(score) if isinstance(score, (int, float)) else None
            pct_f = float(pct) if isinstance(pct, (int, float)) else None
            out[(cve_id or "").upper()] = (score_f, pct_f)
        return out

    # -- run summary ---------------------------------------------------------

    def _summarize_run(self, run: AnalysisRun) -> RunSummary:
        sbom_name = run.sbom_name
        project_name: str | None = None
        if run.project_id is not None:
            proj = self._db.get(Projects, run.project_id)
            if proj is not None:
                project_name = proj.project_name
        if sbom_name is None and run.sbom_id is not None:
            sbom = self._db.get(SBOMSource, run.sbom_id)
            if sbom is not None:
                sbom_name = sbom.sbom_name
        return RunSummary(
            id=run.id,
            sbom_id=run.sbom_id,
            sbom_name=sbom_name,
            project_id=run.project_id,
            project_name=project_name,
            run_status=(run.run_status or "").upper(),
            completed_on=run.completed_on,
            started_on=run.started_on,
            total_findings=int(run.total_findings or 0),
            total_components=int(run.total_components or 0),
        )


# =============================================================================
# Module-level helpers (pure functions — easy to unit-test in isolation)
# =============================================================================


def compute_cache_key(run_a_id: int, run_b_id: int) -> str:
    """Order-independent SHA-256 cache key.

    ``compare(A, B)`` and ``compare(B, A)`` MUST hit the same cache row.
    """
    lo, hi = sorted((int(run_a_id), int(run_b_id)))
    return hashlib.sha256(f"{lo}:{hi}".encode("ascii")).hexdigest()


def _canonicalize_vuln_id(raw: str) -> str:
    """Use classifier's canonical form. GHSA stays mixed-case per spec."""
    vid = classify(raw)
    if vid.kind == IdKind.UNKNOWN:
        return raw.strip().upper()
    return vid.normalized


def _severity_from_str(value: str | None) -> CveSeverity:
    if not value:
        return CveSeverity.UNKNOWN
    s = value.strip().lower()
    try:
        return CveSeverity(s)
    except ValueError:
        return CveSeverity.UNKNOWN


_SEVERITY_ORDER: dict[CveSeverity, int] = {
    CveSeverity.CRITICAL: 5,
    CveSeverity.HIGH: 4,
    CveSeverity.MEDIUM: 3,
    CveSeverity.LOW: 2,
    CveSeverity.NONE: 1,
    CveSeverity.UNKNOWN: 0,
}


def _severity_ord(s: CveSeverity) -> int:
    return _SEVERITY_ORDER.get(s, 0)


def _fix_available(fixed_versions_raw: str | None) -> bool:
    if not fixed_versions_raw:
        return False
    s = fixed_versions_raw.strip()
    if not s or s == "[]":
        return False
    return True


def _expires_at_passed(expires_at_iso: str | None) -> bool:
    if not expires_at_iso:
        return True
    try:
        dt = datetime.fromisoformat(expires_at_iso)
    except ValueError:
        return True
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt <= datetime.now(timezone.utc)


def _parse_iso(value: str | None) -> datetime:
    """Best-effort ISO parse. Returns datetime.min when unparseable."""
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _days_between(a_iso: str | None, b_iso: str | None) -> float | None:
    a = _parse_iso(a_iso)
    b = _parse_iso(b_iso)
    if a == datetime.min.replace(tzinfo=timezone.utc) or b == datetime.min.replace(
        tzinfo=timezone.utc
    ):
        return None
    delta = b - a
    return round(delta.total_seconds() / 86400.0, 2)


def _present_in_a(f: FindingDiffRow) -> bool:
    return f.change_kind in (
        FindingChangeKind.RESOLVED,
        FindingChangeKind.SEVERITY_CHANGED,
        FindingChangeKind.UNCHANGED,
    )


def _present_in_b(f: FindingDiffRow) -> bool:
    return f.change_kind in (
        FindingChangeKind.ADDED,
        FindingChangeKind.SEVERITY_CHANGED,
        FindingChangeKind.UNCHANGED,
    )


def _severity_distribution(
    findings: list[FindingDiffRow], *, side: str
) -> dict[str, int]:
    keys = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    out = dict.fromkeys(keys, 0)
    for f in findings:
        if side == "a":
            if not _present_in_a(f):
                continue
            sev = f.severity_a
        else:
            if not _present_in_b(f):
                continue
            sev = f.severity_b
        if sev is None:
            continue
        # NONE collapses into UNKNOWN to match analysis_run aggregate columns.
        bucket = sev.value.upper() if sev != CveSeverity.NONE else "UNKNOWN"
        if bucket in out:
            out[bucket] += 1
        else:
            out["UNKNOWN"] += 1
    return out


def _top_contributors(
    findings: list[FindingDiffRow], kind: FindingChangeKind, *, n: int
) -> list[FindingDiffRow]:
    """Display-only ordinal rank — NOT a weighted score. ADR-0008 §5 / Tab 3.

    Sort key: (KEV first, severity ord desc, fix-available first, vuln_id asc).
    """
    candidates = [f for f in findings if f.change_kind == kind]
    candidates.sort(
        key=lambda f: (
            0 if f.kev_current else 1,
            -_severity_ord(_pick_visible_severity(f)),
            0 if f.fix_available else 1,
            f.vuln_id.upper(),
        )
    )
    return candidates[:n]


def _pick_visible_severity(f: FindingDiffRow) -> CveSeverity:
    if f.change_kind == FindingChangeKind.RESOLVED:
        return f.severity_a or CveSeverity.UNKNOWN
    if f.change_kind == FindingChangeKind.ADDED:
        return f.severity_b or CveSeverity.UNKNOWN
    return f.severity_b or f.severity_a or CveSeverity.UNKNOWN


# =============================================================================
# Diff-row constructors
# =============================================================================


def _component_row(
    kind: ComponentChangeKind,
    key: _ComponentKey,
    a: _LoadedComponent | None,
    b: _LoadedComponent | None,
) -> ComponentDiffRow:
    name = (b or a).name if (a or b) else key.name
    purl = (b.purl if b else None) or (a.purl if a else None)
    return ComponentDiffRow(
        change_kind=kind,
        name=name,
        ecosystem=key.ecosystem,
        purl=purl,
        version_a=a.version if a else None,
        version_b=b.version if b else None,
        license_a=a.license if a else None,
        license_b=b.license if b else None,
        hash_a=a.content_hash if a else None,
        hash_b=b.content_hash if b else None,
        findings_resolved=0,
        findings_added=0,
    )


def _finding_row(
    kind: FindingChangeKind,
    a: _LoadedFinding | None,
    b: _LoadedFinding | None,
) -> FindingDiffRow:
    src = b or a  # whichever side has the row
    assert src is not None
    purl = src.component_purl
    if purl is None and a is not None:
        purl = a.component_purl
    if purl is None and b is not None:
        purl = b.component_purl
    ecosystem = _purl_ecosystem(purl) or "unknown"
    # B (current state) wins fix-available when both sides exist; A is used
    # only for RESOLVED rows where B doesn't exist.
    if b is not None:
        fix_avail = b.fix_available
    elif a is not None:
        fix_avail = a.fix_available
    else:
        fix_avail = False
    return FindingDiffRow(
        change_kind=kind,
        vuln_id=src.vuln_id_raw,
        severity_a=a.severity if a else None,
        severity_b=b.severity if b else None,
        kev_current=False,  # filled in after batch lookup
        epss_current=None,
        epss_percentile_current=None,
        component_name=src.component_name,
        component_version_a=a.component_version if a else None,
        component_version_b=b.component_version if b else None,
        component_purl=purl,
        component_ecosystem=ecosystem,
        fix_available=fix_avail,
        attribution=None,  # filled in step 8
    )


def _attribution_string(
    kind: FindingChangeKind, comp: ComponentDiffRow | None
) -> str | None:
    if kind not in (FindingChangeKind.ADDED, FindingChangeKind.RESOLVED):
        return None
    if comp is None:
        if kind == FindingChangeKind.RESOLVED:
            return "via vulnerability re-classification"
        return "newly published advisory against existing dependency"
    if kind == FindingChangeKind.RESOLVED:
        if comp.change_kind == ComponentChangeKind.VERSION_BUMPED:
            return f"via upgrade {comp.name} {comp.version_a} → {comp.version_b}"
        if comp.change_kind == ComponentChangeKind.REMOVED:
            return f"via removal of {comp.name}"
        return "via vulnerability re-classification"
    # ADDED
    if comp.change_kind == ComponentChangeKind.VERSION_BUMPED:
        return f"introduced by upgrade {comp.name} {comp.version_a} → {comp.version_b}"
    if comp.change_kind == ComponentChangeKind.ADDED:
        return f"via new dependency {comp.name}@{comp.version_b}"
    return "newly published advisory against existing dependency"
