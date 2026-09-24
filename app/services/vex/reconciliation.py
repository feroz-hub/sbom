"""The VEX reconciliation engine (spec sections 4, 11, 17-20).

Takes three independent evidence streams for one SBOM —

* analyser findings from the latest successful run (Convention A),
* mapped VEX assertions,
* manual/internal decisions,

— and produces one :class:`~app.models.VexInvestigation` per vulnerability
context, carrying an effective status and a reconciliation status.

Invariants this module must never break:

* It never creates, alters or deletes an ``AnalysisFinding`` (VEX-DATA-003/004)
  and never touches severity (VEX-DATA-005). It only reads them.
* It never resolves a conflict between independently authored assertions by
  status priority or row recency (VEX-INV-005). ``choose_vex_result`` in
  ``app/services/lifecycle/decision_engine.py`` exists and must stay unused.
* A manual decision outranks every later import until explicitly changed
  (VEX-INV-004); re-analysis updates evidence and never resets a decision
  (VEX-INV-001).

:func:`recompute_for_sbom` is pure with respect to its inputs and idempotent:
running it twice over unchanged data produces no further writes. It runs
synchronously at each trigger, but is written so it could move behind a queue
without changing callers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...metrics.vex import vex_current_findings_for_sbom, vex_run_query_error_count
from ...models import VexInvestigation, VexStatement
from ..lifecycle.types import now_iso
from .enums import (
    AnalyzerDetectionState,
    EffectiveVexStatus,
    ReconciliationStatus,
)
from .identity import canonical_for_finding, canonical_vulnerability

#: ``source_name`` written by the manual-override path. Matching
#: ``effective_vex_statements`` in vex_provider, which keys off the same value.
MANUAL_SOURCE_NAME = "Manual VEX Override"


def _is_manual(statement: VexStatement) -> bool:
    return statement.vex_document_id is None and statement.source_name == MANUAL_SOURCE_NAME


#: The only values an effective status may take (VEX-STAT-001).
_CANONICAL_STATUSES = frozenset(s.value for s in EffectiveVexStatus)


def _effective_status(statement: VexStatement) -> str:
    """Canonical status for a statement, preferring the normalized column.

    ``normalized_status`` is *validated*, not trusted. A row written before
    this column existed, backfilled from an unrecognised legacy status, or
    carrying a stray value like ``UNKNOWN`` would otherwise leak a fifth
    status into the contexts — which silently breaks the VEX-DASH-002
    invariant, because the dashboard sums exactly four buckets and such a
    context would fall outside all of them. Anything unrecognised is re-derived
    from the legacy ``status`` column, and ultimately lands on
    UNDER_INVESTIGATION (spec section 8).
    """
    from ..lifecycle.vex_provider import effective_status_for

    normalized = (statement.normalized_status or "").strip().upper()
    if normalized in _CANONICAL_STATUSES:
        return normalized
    return effective_status_for(statement.status)


def _authority(statement: VexStatement) -> tuple:
    """Who authored an assertion, for conflict detection (VEX-INV-005).

    "Independent" means a different author *or* a different source document.
    A newer version of the same document supersedes its predecessor and is
    explicitly not a conflict, so document identity — not row id — is the key.
    """
    document = statement.vex_document
    if document is None:
        return ("manual", statement.source_name or "")
    return (
        "document",
        document.source_document_id or f"doc:{document.id}",
        (document.author or statement.source_name or "").strip().lower(),
    )


@dataclass
class ContextEvidence:
    """Everything known about one vulnerability context before deciding."""

    canonical_id: str
    aliases: set[str] = field(default_factory=set)
    component_id: int | None = None
    unresolved_discriminator: str = ""
    analyzer_detected: bool = False
    analyzer_sources: set[str] = field(default_factory=set)
    statements: list[VexStatement] = field(default_factory=list)

    @property
    def manual(self) -> VexStatement | None:
        """Latest manual decision, if any."""
        manual = [s for s in self.statements if _is_manual(s)]
        return max(manual, key=lambda s: s.id) if manual else None

    @property
    def applicable_imports(self) -> list[VexStatement]:
        """Imported assertions eligible to become effective.

        Excludes manual decisions and anything the version check ruled out
        (VEX-MAP-002): a non-applicable statement is retained as evidence but
        must not drive the outcome.
        """
        return [
            s
            for s in self.statements
            if not _is_manual(s) and s.version_applicable is not False
        ]


def _latest_per_authority(statements: list[VexStatement]) -> list[VexStatement]:
    """One assertion per independent author: newest version of each document."""
    by_authority: dict[tuple, VexStatement] = {}
    for statement in statements:
        key = _authority(statement)
        current = by_authority.get(key)
        if current is None or statement.id > current.id:
            by_authority[key] = statement
    return list(by_authority.values())


def decide(evidence: ContextEvidence) -> tuple[str, str]:
    """Apply the VEX-REC-002 A-H rules. Returns ``(effective, reconciliation)``.

    Pure: no database access, so every rule is unit-testable in isolation.
    """
    manual = evidence.manual

    # Ambiguous or missing component binding outranks the rest: we cannot
    # honestly say a decision applies to a component we could not identify
    # (VEX-MAP-001). Risk is never reduced by an unresolved mapping.
    if evidence.component_id is None and not evidence.analyzer_detected:
        status = _effective_status(manual) if manual else None
        if status is None:
            applicable = evidence.applicable_imports
            status = (
                _effective_status(applicable[0])
                if len(applicable) == 1
                else EffectiveVexStatus.UNDER_INVESTIGATION.value
            )
        return status, ReconciliationStatus.UNRESOLVED_MAPPING.value

    # H (manual): an explicit internal decision wins over every later import
    # (VEX-INV-004). Imports remain stored and visible; they just do not
    # silently replace the determination.
    if manual is not None:
        return _effective_status(manual), (
            ReconciliationStatus.MATCHED.value
            if evidence.applicable_imports or evidence.analyzer_detected
            else ReconciliationStatus.VEX_ONLY.value
        )

    applicable = _latest_per_authority(evidence.applicable_imports)

    # A: analyser found it, no applicable VEX -> the default for every newly
    # discovered vulnerability.
    if not applicable:
        if evidence.analyzer_detected:
            return (
                EffectiveVexStatus.UNDER_INVESTIGATION.value,
                ReconciliationStatus.ANALYZER_ONLY.value,
            )
        # Only non-applicable evidence exists (e.g. a version range that does
        # not cover this component): still a context, still under review.
        return (
            EffectiveVexStatus.UNDER_INVESTIGATION.value,
            ReconciliationStatus.VEX_ONLY.value,
        )

    statuses = {_effective_status(s) for s in applicable}

    # G (conflict): independent sources disagree. Never resolved by priority
    # or recency — an analyst must decide (VEX-INV-005).
    if len(statuses) > 1:
        return (
            EffectiveVexStatus.UNDER_INVESTIGATION.value,
            ReconciliationStatus.CONFLICT_REVIEW_REQUIRED.value,
        )

    status = next(iter(statuses))

    # F (revalidation): VEX says FIXED but the analyser still detects it. The
    # source status is preserved on the statement; the operational state is
    # not "safely resolved".
    if status == EffectiveVexStatus.FIXED.value and evidence.analyzer_detected:
        return (
            EffectiveVexStatus.UNDER_INVESTIGATION.value,
            ReconciliationStatus.REVALIDATION_REQUIRED.value,
        )

    # B/E/F: analyser and VEX agree on one context.
    if evidence.analyzer_detected:
        return status, ReconciliationStatus.MATCHED.value

    # C/D: VEX-only. Retained and visible; contributes no analyser finding.
    return status, ReconciliationStatus.VEX_ONLY.value


def _detection_state(
    detected: bool, *, run_id: int | None, query_errors: int
) -> str:
    """Distinguish a true negative from an absent or failed query (VEX-REC-004)."""
    if detected:
        return AnalyzerDetectionState.DETECTED.value
    if run_id is None:
        return AnalyzerDetectionState.NOT_QUERIED.value
    if query_errors:
        return AnalyzerDetectionState.SOURCE_ERROR.value
    return AnalyzerDetectionState.NOT_DETECTED.value


def _discriminator(statement: VexStatement) -> str:
    """Stable per-assertion key so unresolved contexts do not multiply.

    Derived from the owning document and the raw vulnerability id rather than
    the statement's row id, so re-importing the same document reuses the same
    context instead of creating a new one on every recompute.
    """
    document = statement.vex_document
    document_key = (
        (document.source_document_id or f"doc:{document.id}") if document else "manual"
    )
    raw = f"{document_key}|{(statement.vulnerability_id or '').strip().upper()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _collect(
    db: Session, *, tenant_id: int, sbom_id: int
) -> tuple[dict[tuple[int | None, str, str], ContextEvidence], int | None, int]:
    """Gather analyser and VEX evidence into one context map."""
    run_id, findings = vex_current_findings_for_sbom(db, tenant_id=tenant_id, sbom_id=sbom_id)
    query_errors = (
        vex_run_query_error_count(db, tenant_id=tenant_id, run_id=run_id) if run_id else 0
    )

    contexts: dict[tuple[int | None, str, str], ContextEvidence] = {}

    def slot(component_id: int | None, canonical: str, discriminator: str) -> ContextEvidence:
        key = (component_id, canonical, discriminator)
        if key not in contexts:
            contexts[key] = ContextEvidence(
                canonical_id=canonical,
                component_id=component_id,
                unresolved_discriminator=discriminator,
            )
        return contexts[key]

    # --- analyser evidence -------------------------------------------------
    # Multi-source dedup (VEX-REC-003): NVD, OSV and GHSA rows that resolve to
    # one canonical id on one component collapse into a single context, with
    # every contributing source recorded.
    for finding in findings:
        identity = canonical_for_finding(finding)
        entry = slot(finding.component_id, identity.canonical_id, "")
        entry.aliases.update(identity.aliases)
        entry.analyzer_detected = True
        if finding.source:
            entry.analyzer_sources.add(str(finding.source))

    # --- VEX evidence ------------------------------------------------------
    statements = list(
        db.scalars(
            select(VexStatement)
            .where(VexStatement.tenant_id == tenant_id, VexStatement.sbom_id == sbom_id)
            .order_by(VexStatement.id)
        ).all()
    )
    for statement in statements:
        identity = canonical_vulnerability(
            statement.vulnerability_id, canonical_id=statement.cve_id
        )
        if statement.component_id is None:
            entry = slot(None, identity.canonical_id, _discriminator(statement))
        else:
            entry = slot(statement.component_id, identity.canonical_id, "")
        entry.aliases.update(identity.aliases)
        entry.statements.append(statement)

    return contexts, run_id, query_errors


def recompute_for_sbom(db: Session, *, tenant_id: int, sbom_id: int) -> dict[str, Any]:
    """Rebuild every VEX investigation context for one SBOM.

    Idempotent: re-running over unchanged evidence changes nothing. Contexts
    that are no longer present are marked ``is_current = False`` rather than
    deleted, so history and audit survive (VEX-INV-001/002).

    Does not commit — the caller owns the transaction, so reconciliation joins
    the analysis-run or import commit rather than half-landing beside it.
    """
    contexts, run_id, query_errors = _collect(db, tenant_id=tenant_id, sbom_id=sbom_id)
    now = now_iso()

    existing = {
        (row.component_id, row.canonical_vulnerability_id, row.unresolved_discriminator): row
        for row in db.scalars(
            select(VexInvestigation).where(
                VexInvestigation.tenant_id == tenant_id, VexInvestigation.sbom_id == sbom_id
            )
        ).all()
    }

    created = updated = retired = 0

    for key, evidence in contexts.items():
        effective_status, reconciliation_status = decide(evidence)
        detection_state = _detection_state(
            evidence.analyzer_detected, run_id=run_id, query_errors=query_errors
        )
        aliases_json = canonical_vulnerability(
            evidence.canonical_id, aliases=sorted(evidence.aliases)
        ).aliases_json
        applicable = _latest_per_authority(evidence.applicable_imports)
        effective_statement = evidence.manual or (applicable[0] if len(applicable) == 1 else None)

        row = existing.get(key)
        is_new = row is None
        if is_new:
            row = VexInvestigation(
                tenant_id=tenant_id,
                sbom_id=sbom_id,
                canonical_vulnerability_id=evidence.canonical_id,
                unresolved_discriminator=evidence.unresolved_discriminator,
                first_seen_at=now,
                last_seen_at=now,
                created_at=now,
                row_version=1,
            )
            row.assign_component(evidence.component_id)
            db.add(row)
            created += 1
        else:
            updated += 1

        # A new row is born at version 1; only a genuine change to an existing
        # row bumps it, so an unchanged recompute cannot invalidate an
        # analyst's in-flight optimistic-concurrency token (VEX-AUD-002).
        changed = not is_new and (
            row.effective_status != effective_status
            or row.reconciliation_status != reconciliation_status
            or row.analyzer_detection_state != detection_state
            or row.aliases_json != aliases_json
            or row.effective_vex_statement_id != (effective_statement.id if effective_statement else None)
            or not row.is_current
        )

        row.effective_status = effective_status
        row.reconciliation_status = reconciliation_status
        row.analyzer_detection_state = detection_state
        row.aliases_json = aliases_json
        row.effective_vex_statement_id = effective_statement.id if effective_statement else None
        row.is_current = True
        row.last_seen_at = now
        if run_id is not None:
            row.last_analysis_run_id = run_id
        if changed:
            row.updated_at = now
            row.row_version = (row.row_version or 1) + 1

    # Contexts absent from the current evidence leave the queue but are kept.
    for key, row in existing.items():
        if key not in contexts and row.is_current:
            row.is_current = False
            row.updated_at = now
            row.row_version = (row.row_version or 1) + 1
            retired += 1

    db.flush()
    return {
        "tenant_id": tenant_id,
        "sbom_id": sbom_id,
        "analysis_run_id": run_id,
        "contexts": len(contexts),
        "created": created,
        "updated": updated,
        "retired": retired,
    }


__all__ = [
    "ContextEvidence",
    "decide",
    "recompute_for_sbom",
]
