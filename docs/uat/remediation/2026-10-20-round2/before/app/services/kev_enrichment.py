"""KEV enrichment for persisted vulnerability findings.

Findings remain normalized: KEV catalog data lives in ``kev_vulnerabilities``
and is joined by CVE id at read/enrichment time.  This service batches those
lookups so SBOM analysis and run-detail APIs do not issue one query per
finding.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisFinding, KevEntry
from .vulnerability_ids import cves_for_finding


@dataclass(frozen=True)
class KevFindingEnrichment:
    is_kev: bool
    matched_cve: str | None = None
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    required_action: str | None = None
    vendor_project: str | None = None
    product: str | None = None
    ransomware_status: str | None = None
    notes: str | None = None
    vulnerability_name: str | None = None
    short_description: str | None = None
    cwes: list[str] | None = None

    @property
    def in_kev(self) -> bool:
        """Backward-compatible naming used by existing frontend/risk APIs."""
        return self.is_kev

    @property
    def known_ransomware_campaign_use(self) -> str | None:
        return self.ransomware_status

    def to_response_fields(self) -> dict:
        """Shape expected by finding API responses."""
        return {
            "is_kev": self.is_kev,
            "in_kev": self.is_kev,
            "kev_date_added": self.kev_date_added,
            "kev_due_date": self.kev_due_date,
            "required_action": self.required_action,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "ransomware_status": self.ransomware_status,
            "notes": self.notes,
        }


EMPTY_KEV_ENRICHMENT = KevFindingEnrichment(is_kev=False)


def _entry_to_enrichment(entry: KevEntry | None, *, matched_cve: str | None = None) -> KevFindingEnrichment:
    if entry is None:
        return EMPTY_KEV_ENRICHMENT
    cwes = entry.cwes if isinstance(entry.cwes, list) else None
    return KevFindingEnrichment(
        is_kev=True,
        matched_cve=matched_cve or entry.cve_id,
        kev_date_added=entry.date_added,
        kev_due_date=entry.due_date,
        required_action=entry.required_action,
        vendor_project=entry.vendor_project,
        product=entry.product,
        ransomware_status=entry.known_ransomware_campaign_use,
        notes=entry.notes or entry.short_description,
        vulnerability_name=entry.vulnerability_name,
        short_description=entry.short_description,
        cwes=[str(cwe) for cwe in cwes] if cwes else None,
    )


def lookup_kev_entries(db: Session, cve_ids: Iterable[str]) -> dict[str, KevEntry]:
    """Return KEV rows keyed by normalized CVE id."""
    normalized = sorted({cve.strip().upper() for cve in cve_ids if cve and cve.strip()})
    if not normalized:
        return {}
    rows = db.execute(select(KevEntry).where(KevEntry.cve_id.in_(normalized))).scalars().all()
    return {row.cve_id.upper(): row for row in rows if row.cve_id}


def enrich_finding_with_kev(
    finding: AnalysisFinding,
    kev_entries_by_cve: dict[str, KevEntry],
) -> KevFindingEnrichment:
    """Resolve the first KEV match across a finding's primary id and aliases."""
    for cve in cves_for_finding(finding.vuln_id, finding.aliases):
        entry = kev_entries_by_cve.get(cve)
        if entry is not None:
            return _entry_to_enrichment(entry, matched_cve=cve)
    return EMPTY_KEV_ENRICHMENT


def enrich_findings_with_kev(
    db: Session,
    findings: Iterable[AnalysisFinding],
) -> dict[int, KevFindingEnrichment]:
    """Batch enrich findings with CISA KEV metadata from the local mirror."""
    finding_list = list(findings)
    all_cves: set[str] = set()
    for finding in finding_list:
        all_cves.update(cves_for_finding(finding.vuln_id, finding.aliases))

    kev_entries = lookup_kev_entries(db, all_cves)
    return {finding.id: enrich_finding_with_kev(finding, kev_entries) for finding in finding_list}
