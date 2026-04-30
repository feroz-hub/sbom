"""
Pydantic models for the CVE detail enrichment service.

Single normalized output regardless of which upstream sources contributed.
Consumed by ``GET /api/v1/cves/{cve_id}``, ``POST /api/v1/cves/batch``, and
``GET /api/v1/scans/{scan_id}/cves/{cve_id}``.

Path note: the prompt asked for ``app/schemas/cve.py``; the existing
``app/schemas.py`` is a flat module imported from many callers, so the
new models live here instead. Same surface, lower blast radius.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class CveSeverity(str, Enum):
    """
    Severity bucket. Lowercase to match the JSON wire format the modal
    consumes; the existing ``AnalysisFinding.severity`` column carries the
    uppercase form, so the service layer normalises on the way in.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"


class CveResultStatus(str, Enum):
    """
    Outcome discriminator the frontend reads to pick the correct banner.

      OK          — at least one source returned data; the payload is fully usable.
      PARTIAL     — at least one source contributed; at least one other failed.
      NOT_FOUND   — every queried source returned NOT_FOUND. ID is well-formed,
                    no upstream record exists yet (newly-published advisories,
                    pre-CVE-assignment GHSA, etc).
      UNREACHABLE — every queried source errored / timed out. The payload is
                    a degraded shell (modal still renders the row data the
                    client already had); user should retry.
    """

    OK = "ok"
    PARTIAL = "partial"
    NOT_FOUND = "not_found"
    UNREACHABLE = "unreachable"


SourceName = Literal["osv", "ghsa", "nvd", "epss", "kev"]


class CveFixVersion(BaseModel):
    """One fix-version row, scoped to a (ecosystem, package) pair."""

    model_config = ConfigDict(extra="forbid")

    ecosystem: str = Field(..., description="OSV ecosystem identifier (npm, PyPI, Maven, ...)")
    package: str = Field(..., description="Affected package name within the ecosystem")
    fixed_in: str | None = Field(default=None, description="First version that fixes this CVE")
    introduced_in: str | None = Field(default=None, description="Earliest known affected version")
    range: str | None = Field(default=None, description="Raw OSV / GHSA range expression")


class CveReference(BaseModel):
    """External reference link surfaced in the modal footer / fix sections."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(..., description='Human label, e.g. "GHSA", "NVD", "Vendor advisory"')
    url: HttpUrl
    type: Literal["advisory", "patch", "exploit", "report", "fix", "web"] = "web"


class CveExploitation(BaseModel):
    """Exploitation-likelihood signals for the 'How is it exploited?' section."""

    model_config = ConfigDict(extra="forbid")

    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    cisa_kev_listed: bool = False
    cisa_kev_due_date: date | None = None
    attack_vector: str | None = None  # NETWORK | ADJACENT | LOCAL | PHYSICAL
    attack_complexity: str | None = None  # LOW | HIGH
    privileges_required: str | None = None  # NONE | LOW | HIGH
    user_interaction: str | None = None  # NONE | REQUIRED
    impact_summary: str | None = Field(default=None, max_length=1500)


class CveDetail(BaseModel):
    """
    The normalised CVE detail payload the modal consumes.

    Always returns a value — the service degrades gracefully when upstream
    sources fail (``is_partial=True``, ``sources_used`` records the survivors).
    """

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    aliases: list[str] = Field(default_factory=list)
    title: str | None = None
    summary: str = Field(default="", max_length=2000)
    severity: CveSeverity = CveSeverity.UNKNOWN
    cvss_v3_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v3_vector: str | None = None
    cvss_v4_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_v4_vector: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    published_at: datetime | None = None
    modified_at: datetime | None = None
    exploitation: CveExploitation = Field(default_factory=CveExploitation)
    fix_versions: list[CveFixVersion] = Field(default_factory=list)
    workaround: str | None = None
    references: list[CveReference] = Field(default_factory=list)
    sources_used: list[SourceName] = Field(default_factory=list)
    is_partial: bool = False
    status: CveResultStatus = CveResultStatus.OK
    fetched_at: datetime

    @field_validator("cve_id", mode="before")
    @classmethod
    def _normalize_cve_id(cls, v: object) -> object:
        """Canonicalise via the central classifier — same form the cache and
        every other consumer keys on. CVE → uppercase; GHSA → uppercase head,
        lowercase tail. Unknown formats pass through unchanged so the
        validator doesn't double-reject what the service layer already
        validates upstream.
        """
        if isinstance(v, str):
            from .integrations.cve.identifiers import IdKind, classify

            vid = classify(v)
            return v.strip() if vid.kind == IdKind.UNKNOWN else vid.normalized
        return v

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def _normalize_cwe_ids(cls, v: object) -> object:
        if isinstance(v, list):
            return [str(item).strip().upper() for item in v if str(item).strip()]
        return v


class CveScanContext(BaseModel):
    """Component context appended by the scan-aware endpoint variant."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None


class CveDetailWithContext(CveDetail):
    """Scan-aware variant — adds component context + upgrade recommendation."""

    component: CveScanContext | None = None
    current_version_status: Literal["vulnerable", "fixed", "unknown"] = "unknown"
    recommended_upgrade: str | None = None


class CveBatchRequest(BaseModel):
    """Body for ``POST /api/v1/cves/batch``."""

    model_config = ConfigDict(extra="forbid")

    ids: list[str] = Field(..., min_length=1, max_length=50)


class CveBatchResponse(BaseModel):
    """Response for ``POST /api/v1/cves/batch`` — keyed by canonical CVE ID."""

    model_config = ConfigDict(extra="forbid")

    items: dict[str, CveDetail]
    not_found: list[str] = Field(default_factory=list)
