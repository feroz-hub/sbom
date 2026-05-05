"""GroundingContext builder — the model's ONLY view into the real world.

Phase 2 §2.2 hard rule:

    "You will be given grounded vulnerability data. You may only recommend
    fix versions that appear in the ``fix_versions`` array."

This module materialises that contract. It pulls from:

  * :class:`~app.models.AnalysisFinding` — the finding row that the user
    clicked on / the batch worker is processing.
  * :class:`~app.models.SBOMComponent` — the component referenced by the
    finding, used for ecosystem / purl context.
  * :class:`~app.models.CveCache` — the merged OSV/GHSA/NVD/EPSS/KEV
    payload built by :class:`~app.services.cve_service.CveDetailService`.
    This is the canonical source of fix-version data.
  * :class:`~app.models.KevEntry`, :class:`~app.models.EpssScore` — direct
    fall-backs when the cve_cache row hasn't been built yet (cold start).

The output, :class:`GroundingContext`, is the JSON the model sees. It's
intentionally narrow — every field has to earn its place because every
field is a token paid for in production.
"""

from __future__ import annotations

import json
import logging
from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    AnalysisFinding,
    CveCache,
    EpssScore,
    KevEntry,
    SBOMComponent,
)

log = logging.getLogger("sbom.ai.grounding")


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


class FixVersionRef(BaseModel):
    """A single fix version, scoped to a (ecosystem, package) pair."""

    model_config = ConfigDict(extra="forbid")

    ecosystem: str
    package: str
    fixed_in: str | None = None
    introduced_in: str | None = None
    range: str | None = None


class ComponentRef(BaseModel):
    """The affected component as the model sees it."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    ecosystem: str | None = None
    purl: str | None = None
    cpe: str | None = None


class GroundingContext(BaseModel):
    """Single source of truth for an LLM call.

    The model is permitted to use ONLY this data when generating a fix.
    Anything not in here is hallucination. The ``fix_versions`` list is
    the single most-important field — it bounds the upgrade-command output.
    """

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    aliases: list[str] = Field(default_factory=list)

    component: ComponentRef

    cve_summary_from_db: str = Field(default="", description="Existing prose from cve_cache; never written by the model.")
    severity: Literal["critical", "high", "medium", "low", "none", "unknown"] = "unknown"
    cvss_v3_score: float | None = None
    cvss_v3_vector: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)

    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)

    kev_listed: bool = False
    kev_due_date: date | None = None

    fix_versions: list[FixVersionRef] = Field(default_factory=list)
    workaround: str | None = None

    references: list[str] = Field(default_factory=list)

    # Provenance: which sources contributed to this context. The model
    # should only cite sources that appear here.
    sources_used: list[Literal["osv", "ghsa", "nvd", "epss", "kev", "fix_version_data"]] = Field(
        default_factory=list
    )

    def model_dump_for_prompt(self) -> str:
        """Compact JSON serialization for prompt injection.

        Sorted keys + no spaces minimises tokens. Date values are stringified
        for JSON portability (Pydantic does this naturally with
        ``mode="json"``).
        """
        return json.dumps(self.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def _safe_json_list(raw: str | None) -> list[str]:
    """Permissive parser for the JSON-array-in-text columns we inherited."""
    if not raw:
        return []
    try:
        val = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    if not isinstance(val, list):
        return []
    return [str(x).strip() for x in val if str(x).strip()]


def _ecosystem_from_purl(purl: str | None) -> str | None:
    """Extract the ecosystem prefix from a purl string (``pkg:npm/...`` → ``npm``)."""
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[4:]
    if "/" not in rest:
        return None
    return rest.split("/", 1)[0] or None


def _fix_versions_from_finding(
    finding: AnalysisFinding,
    component: SBOMComponent | None,
) -> list[FixVersionRef]:
    """Materialise fix versions from the finding's JSON column.

    Falls back to an empty list when the data isn't available — the model
    is then required to flag ``tested_against_data=False``.
    """
    raw = _safe_json_list(finding.fixed_versions)
    eco = _ecosystem_from_purl(component.purl if component else None) or "unknown"
    pkg = (finding.component_name or (component.name if component else "")) or "unknown"
    out: list[FixVersionRef] = []
    for v in raw:
        out.append(FixVersionRef(ecosystem=eco, package=pkg, fixed_in=v))
    return out


def _fix_versions_from_cve_cache(
    payload: dict[str, Any] | None,
) -> list[FixVersionRef]:
    """Materialise fix versions from the cve_cache payload."""
    if not isinstance(payload, dict):
        return []
    raw = payload.get("fix_versions") or []
    out: list[FixVersionRef] = []
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            try:
                out.append(
                    FixVersionRef(
                        ecosystem=str(entry.get("ecosystem") or "unknown"),
                        package=str(entry.get("package") or "unknown"),
                        fixed_in=(entry.get("fixed_in") or None),
                        introduced_in=(entry.get("introduced_in") or None),
                        range=(entry.get("range") or None),
                    )
                )
            except Exception:
                continue
    return out


def _references_from_cve_cache(payload: dict[str, Any] | None) -> list[str]:
    if not isinstance(payload, dict):
        return []
    refs = payload.get("references") or []
    out: list[str] = []
    if isinstance(refs, list):
        for entry in refs:
            if isinstance(entry, dict):
                url = entry.get("url")
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    out.append(url)
    return out[:8]


def _normalise_severity(s: str | None) -> str:
    if not s:
        return "unknown"
    v = s.strip().lower()
    if v in {"critical", "high", "medium", "low", "none"}:
        return v
    return "unknown"


def build_grounding_context(
    finding: AnalysisFinding,
    *,
    db: Session,
    component: SBOMComponent | None = None,
) -> GroundingContext:
    """Assemble the :class:`GroundingContext` for a single finding.

    Resolves enrichment data lazily — readers don't pay for KEV / EPSS
    look-ups when the cve_cache row already has the merged answer.
    """
    if component is None and finding.component_id is not None:
        component = db.execute(
            select(SBOMComponent).where(SBOMComponent.id == finding.component_id)
        ).scalar_one_or_none()

    cve_cache_row = db.execute(
        select(CveCache).where(CveCache.cve_id == finding.vuln_id)
    ).scalar_one_or_none()
    cve_payload: dict[str, Any] | None = None
    if cve_cache_row is not None:
        if isinstance(cve_cache_row.payload, dict):
            cve_payload = cve_cache_row.payload
        elif isinstance(cve_cache_row.payload, str):
            try:
                cve_payload = json.loads(cve_cache_row.payload)
            except json.JSONDecodeError:
                cve_payload = None

    sources_used: list[str] = []
    if cve_payload:
        sources_used.extend(
            s for s in (cve_payload.get("sources_used") or [])
            if isinstance(s, str)
        )

    fix_versions = _fix_versions_from_cve_cache(cve_payload) or _fix_versions_from_finding(finding, component)
    if fix_versions and "fix_version_data" not in sources_used:
        sources_used.append("fix_version_data")

    # KEV / EPSS — prefer the merged cve_cache; fall back to the dedicated
    # caches when the merged row hasn't been built (cold start).
    kev_listed = False
    kev_due_date: date | None = None
    if cve_payload and isinstance(cve_payload.get("exploitation"), dict):
        exp = cve_payload["exploitation"]
        kev_listed = bool(exp.get("cisa_kev_listed"))
        try:
            d = exp.get("cisa_kev_due_date")
            if isinstance(d, str) and d:
                kev_due_date = date.fromisoformat(d[:10])
        except Exception:
            kev_due_date = None
    if not kev_listed:
        kev_row = db.execute(
            select(KevEntry).where(KevEntry.cve_id == finding.vuln_id)
        ).scalar_one_or_none()
        if kev_row is not None:
            kev_listed = True
            if "kev" not in sources_used:
                sources_used.append("kev")

    epss_score: float | None = None
    epss_percentile: float | None = None
    if cve_payload and isinstance(cve_payload.get("exploitation"), dict):
        exp = cve_payload["exploitation"]
        epss_score = exp.get("epss_score")
        epss_percentile = exp.get("epss_percentile")
    if epss_score is None:
        epss_row = db.execute(
            select(EpssScore).where(EpssScore.cve_id == finding.vuln_id)
        ).scalar_one_or_none()
        if epss_row is not None:
            epss_score = float(epss_row.epss) if epss_row.epss is not None else None
            epss_percentile = float(epss_row.percentile) if epss_row.percentile is not None else None
            if "epss" not in sources_used:
                sources_used.append("epss")

    component_ref = ComponentRef(
        name=(finding.component_name or (component.name if component else "") or "unknown"),
        version=(finding.component_version or (component.version if component else "") or "unknown"),
        ecosystem=_ecosystem_from_purl(component.purl if component else None),
        purl=(component.purl if component else None),
        cpe=finding.cpe,
    )

    cve_summary = ""
    if cve_payload:
        cve_summary = str(cve_payload.get("summary") or "").strip()
    if not cve_summary:
        cve_summary = (finding.description or finding.title or "").strip()

    return GroundingContext(
        cve_id=finding.vuln_id,
        aliases=_safe_json_list(finding.aliases),
        component=component_ref,
        cve_summary_from_db=cve_summary[:1500],
        severity=_normalise_severity(finding.severity),
        cvss_v3_score=finding.score if finding.score is not None else None,
        cvss_v3_vector=finding.vector,
        cwe_ids=_safe_json_list(finding.cwe),
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        kev_listed=kev_listed,
        kev_due_date=kev_due_date,
        fix_versions=fix_versions,
        workaround=(cve_payload.get("workaround") if cve_payload else None),
        references=_references_from_cve_cache(cve_payload),
        sources_used=[
            s for s in sources_used if s in {"osv", "ghsa", "nvd", "epss", "kev", "fix_version_data"}
        ],
    )
