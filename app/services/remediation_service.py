"""
Vulnerability Fix & Remediation Tracking Service.
"""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import VulnerabilityRemediation, VulnerabilityRemediationAudit

log = logging.getLogger(__name__)

ALLOWED_STATUSES = {"Open", "In Progress", "Fixed", "Accepted Risk", "Closed"}
ALLOWED_TRANSITIONS: dict[str, set[str]] = {status: set(ALLOWED_STATUSES) for status in ALLOWED_STATUSES}


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _clean_optional(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _parse_date_field(field_name: str, value: Any) -> str | None:
    cleaned = _clean_optional(value)
    if cleaned is None:
        return None
    try:
        return date.fromisoformat(cleaned).isoformat()
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD format.") from exc


def _candidate_value(data: dict[str, Any], field: str, current: str | None = None) -> str | None:
    if field not in data:
        return current
    return _clean_optional(data.get(field))


def _validate_transition(old_status: str | None, new_status: str) -> None:
    if new_status not in ALLOWED_STATUSES:
        allowed = ", ".join(sorted(ALLOWED_STATUSES))
        raise ValueError(f"Invalid remediation status '{new_status}'. Allowed statuses: {allowed}.")
    if old_status is None:
        return
    if old_status not in ALLOWED_STATUSES:
        raise ValueError(f"Existing remediation status '{old_status}' is invalid and must be corrected first.")
    if new_status not in ALLOWED_TRANSITIONS[old_status]:
        raise ValueError(f"Invalid remediation status transition: {old_status} -> {new_status}.")


def _validate_payload(candidate: dict[str, str | None], old_status: str | None) -> None:
    new_status = candidate["status"]
    if new_status is None:
        raise ValueError("status is required.")
    _validate_transition(old_status, new_status)

    owner = candidate["owner"]
    if owner is not None and len(owner) > 128:
        raise ValueError("owner must be 128 characters or fewer.")

    fixed_version = candidate["fixed_version"]
    if fixed_version is not None and len(fixed_version) > 128:
        raise ValueError("fixed_version must be 128 characters or fewer.")

    fix_notes = candidate["fix_notes"]
    if fix_notes is not None and len(fix_notes) > 4000:
        raise ValueError("fix_notes must be 4000 characters or fewer.")

    if new_status in {"Fixed", "Closed"} and not candidate["resolution_date"]:
        raise ValueError("resolution_date is required when status is Fixed or Closed.")
    if new_status == "Fixed" and not fixed_version and not fix_notes:
        raise ValueError("Fixed remediation requires fixed_version or fix_notes.")
    if new_status == "Accepted Risk" and not fix_notes:
        raise ValueError("Accepted Risk remediation requires fix_notes with the acceptance reason.")


def create_or_update_remediation(
    db: Session,
    project_id: int,
    data: dict[str, Any],
    changed_by: str | None = None,
) -> VulnerabilityRemediation:
    """
    Create or update a remediation tracking record.
    """
    vuln_id = (data.get("vuln_id") or "").strip()
    component_name = (data.get("component_name") or "").strip()
    component_version = (data.get("component_version") or "").strip()
    
    if not vuln_id or not component_name or not component_version:
        raise ValueError("vuln_id, component_name, and component_version are required fields.")
        
    # Check if record already exists
    record = db.execute(
        select(VulnerabilityRemediation).where(
            VulnerabilityRemediation.project_id == project_id,
            VulnerabilityRemediation.vuln_id == vuln_id,
            VulnerabilityRemediation.component_name == component_name,
            VulnerabilityRemediation.component_version == component_version
        )
    ).scalar_one_or_none()

    old_status = record.status if record else None
    candidate = {
        "fixed_version": _candidate_value(data, "fixed_version", record.fixed_version if record else None),
        "status": _clean_optional(data.get("status")) or (record.status if record else "Open"),
        "owner": _candidate_value(data, "owner", record.owner if record else None),
        "due_date": _parse_date_field("due_date", data.get("due_date"))
        if "due_date" in data
        else (record.due_date if record else None),
        "resolution_date": _parse_date_field("resolution_date", data.get("resolution_date"))
        if "resolution_date" in data
        else (record.resolution_date if record else None),
        "fix_notes": _candidate_value(data, "fix_notes", record.fix_notes if record else None),
    }
    _validate_payload(candidate, old_status)

    old_values = None
    if record:
        old_values = {
            "fixed_version": record.fixed_version,
            "status": record.status,
            "owner": record.owner,
            "due_date": record.due_date,
            "resolution_date": record.resolution_date,
            "fix_notes": record.fix_notes,
        }
        # Update
        record.fixed_version = candidate["fixed_version"]
        record.status = candidate["status"]
        record.owner = candidate["owner"]
        record.due_date = candidate["due_date"]
        record.resolution_date = candidate["resolution_date"]
        record.fix_notes = candidate["fix_notes"]
        record.updated_on = _now_iso()
    else:
        # Create
        now = _now_iso()
        record = VulnerabilityRemediation(
            project_id=project_id,
            vuln_id=vuln_id,
            component_name=component_name,
            component_version=component_version,
            fixed_version=candidate["fixed_version"],
            status=candidate["status"],
            owner=candidate["owner"],
            due_date=candidate["due_date"],
            resolution_date=candidate["resolution_date"],
            fix_notes=candidate["fix_notes"],
            created_on=now,
            updated_on=now,
        )
        db.add(record)

    changed = old_values is None or any(old_values[field] != candidate[field] for field in old_values)
    db.flush()
    if changed:
        db.add(
            VulnerabilityRemediationAudit(
                remediation_id=record.id,
                project_id=project_id,
                vuln_id=vuln_id,
                component_name=component_name,
                component_version=component_version,
                old_status=old_status,
                new_status=record.status,
                changed_by=_clean_optional(changed_by),
                changed_at=_now_iso(),
                note=candidate["fix_notes"],
            )
        )

    db.commit()
    db.refresh(record)
    return record


def get_remediation_for_finding(
    db: Session,
    project_id: int,
    vuln_id: str,
    component_name: str,
    component_version: str
) -> VulnerabilityRemediation | None:
    """
    Get the remediation record for a specific vulnerability finding.
    """
    return db.execute(
        select(VulnerabilityRemediation).where(
            VulnerabilityRemediation.project_id == project_id,
            VulnerabilityRemediation.vuln_id == vuln_id,
            VulnerabilityRemediation.component_name == component_name,
            VulnerabilityRemediation.component_version == component_version
        )
    ).scalar_one_or_none()


def list_remediations_for_project(db: Session, project_id: int) -> list[VulnerabilityRemediation]:
    """
    List all remediation records associated with a project.
    """
    return list(db.execute(
        select(VulnerabilityRemediation).where(VulnerabilityRemediation.project_id == project_id)
    ).scalars().all())


def list_remediation_history(db: Session, remediation_id: int) -> list[VulnerabilityRemediationAudit]:
    """
    List append-only audit history for a remediation record.
    """
    return list(
        db.execute(
            select(VulnerabilityRemediationAudit)
            .where(VulnerabilityRemediationAudit.remediation_id == remediation_id)
            .order_by(VulnerabilityRemediationAudit.id.asc())
        )
        .scalars()
        .all()
    )


def enrich_finding_with_remediation(
    db: Session,
    finding: dict[str, Any],
    project_id: int
) -> dict[str, Any]:
    """
    Enrich a finding dictionary with remediation details.
    """
    res = dict(finding)
    vuln_id = res.get("vuln_id")
    comp_name = res.get("component_name")
    comp_ver = res.get("component_version")
    
    if vuln_id and comp_name and comp_ver:
        rem = get_remediation_for_finding(db, project_id, vuln_id, comp_name, comp_ver)
        if rem:
            res["remediation"] = {
                "id": rem.id,
                "status": rem.status,
                "owner": rem.owner,
                "due_date": rem.due_date,
                "resolution_date": rem.resolution_date,
                "fix_notes": rem.fix_notes,
                "fixed_version": rem.fixed_version,
                "updated_on": rem.updated_on
            }
        else:
            res["remediation"] = {
                "id": None,
                "status": "Open",
                "owner": None,
                "due_date": None,
                "resolution_date": None,
                "fix_notes": None,
                "fixed_version": None,
                "updated_on": None
            }
    return res
