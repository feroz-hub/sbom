"""VEX import, statement mapping, and manual override services."""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import SBOMComponent, SBOMSource, VexDocument, VexOverrideAudit, VexStatement
from .types import HIGH, MEDIUM, UNKNOWN_CONFIDENCE, VexResult, now_iso

ALLOWED_VEX_STATUSES = {"affected", "not_affected", "fixed", "under_investigation", "unknown"}

CYCLONEDX_ANALYSIS_STATUS_MAP = {
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "exploitable": "affected",
    "in_triage": "under_investigation",
    "false_positive": "not_affected",
    "not_affected": "not_affected",
}

CYCLONEDX_AFFECTED_STATUS_MAP = {
    "affected": "affected",
    "unaffected": "not_affected",
    "unknown": "unknown",
}


class VexProvider:
    """Parse VEX-like statements from supported JSON documents."""

    name = "VEX"

    def parse_document(
        self,
        document: dict[str, Any],
        *,
        sbom: SBOMSource,
        components: list[SBOMComponent],
        source_name: str = "Uploaded VEX",
        source_url: str | None = None,
    ) -> list[VexResult]:
        if not isinstance(document, dict):
            raise HTTPException(status_code=422, detail="VEX document must be a JSON object")
        if "vulnerabilities" in document:
            return self._parse_cyclonedx(document, sbom=sbom, components=components, source_name=source_name, source_url=source_url)
        if "statements" in document:
            return self._parse_openvex(document, sbom=sbom, components=components, source_name=source_name, source_url=source_url)
        raise HTTPException(status_code=422, detail="Unsupported VEX document format")

    def _parse_cyclonedx(
        self,
        document: dict[str, Any],
        *,
        sbom: SBOMSource,
        components: list[SBOMComponent],
        source_name: str,
        source_url: str | None,
    ) -> list[VexResult]:
        results: list[VexResult] = []
        for vuln in document.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = _vulnerability_id(vuln)
            if not vuln_id:
                continue
            analysis = vuln.get("analysis") if isinstance(vuln.get("analysis"), dict) else {}
            base_status = _normalize_vex_status(
                CYCLONEDX_ANALYSIS_STATUS_MAP.get(str(analysis.get("state") or "").lower(), "unknown")
            )
            affected_entries = vuln.get("affects") or []
            if not isinstance(affected_entries, list) or not affected_entries:
                results.append(_result_from_payload(vuln, None, vuln_id, base_status, sbom, source_name, source_url))
                continue
            for affected in affected_entries:
                if not isinstance(affected, dict):
                    continue
                ref = affected.get("ref")
                component = _match_component(components, ref)
                versions = affected.get("versions") if isinstance(affected.get("versions"), list) else []
                status = base_status
                fixed_version = _fixed_version(analysis)
                if versions:
                    for version in versions:
                        if not isinstance(version, dict):
                            continue
                        mapped = CYCLONEDX_AFFECTED_STATUS_MAP.get(str(version.get("status") or "").lower())
                        status = _normalize_vex_status(mapped or status)
                        if version.get("version") and status == "fixed":
                            fixed_version = str(version.get("version"))
                        results.append(
                            _result_from_payload(
                                vuln,
                                component,
                                vuln_id,
                                status,
                                sbom,
                                source_name,
                                source_url,
                                fixed_version=fixed_version,
                                affected_ref=ref,
                                affected_version=version,
                            )
                        )
                else:
                    results.append(
                        _result_from_payload(
                            vuln,
                            component,
                            vuln_id,
                            status,
                            sbom,
                            source_name,
                            source_url,
                            fixed_version=fixed_version,
                            affected_ref=ref,
                        )
                    )
        return [_validate_vex_result(result) for result in results]

    def _parse_openvex(
        self,
        document: dict[str, Any],
        *,
        sbom: SBOMSource,
        components: list[SBOMComponent],
        source_name: str,
        source_url: str | None,
    ) -> list[VexResult]:
        results: list[VexResult] = []
        for statement in document.get("statements") or []:
            if not isinstance(statement, dict):
                continue
            vulnerability = statement.get("vulnerability") or {}
            vuln_id = (
                vulnerability.get("name")
                if isinstance(vulnerability, dict)
                else None
            ) or statement.get("vulnerability_id") or statement.get("vuln_id")
            if not vuln_id:
                continue
            products = statement.get("products") or []
            if not isinstance(products, list):
                products = []
            status = _normalize_vex_status(statement.get("status"))
            for product in products or [None]:
                component = _match_component(components, product)
                results.append(
                    _validate_vex_result(
                        VexResult(
                            component_name=component.name if component else str(product or sbom.sbom_name),
                            component_version=component.version if component else None,
                            vulnerability_id=str(vuln_id),
                            cve_id=_cve_id(str(vuln_id)),
                            product_context=sbom.sbom_name,
                            vex_status=status,
                            vex_justification=statement.get("justification"),
                            impact_statement=statement.get("impact_statement"),
                            action_statement=statement.get("action_statement"),
                            fixed_version=statement.get("fixed_version"),
                            mitigation=statement.get("mitigation"),
                            source_name=source_name,
                            source_url=source_url,
                            evidence={"statement": statement, "product": product},
                            confidence=MEDIUM,
                        )
                    )
                )
        return results


def import_vex_document(
    db: Session,
    sbom_id: int,
    document: dict[str, Any],
    *,
    source_type: str = "uploaded",
    source_name: str = "Uploaded VEX",
    source_url: str | None = None,
    author: str | None = None,
    uploaded_by: str | None = None,
) -> dict[str, Any]:
    sbom = db.get(SBOMSource, sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    components = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)).scalars().all()
    results = VexProvider().parse_document(
        document,
        sbom=sbom,
        components=list(components),
        source_name=source_name,
        source_url=source_url,
    )
    now = now_iso()
    vex_document = VexDocument(
        sbom_id=sbom_id,
        source_type=source_type,
        format=_detect_format(document),
        author=author or _author(document),
        uploaded_by=uploaded_by,
        uploaded_at=now,
        raw_document_json=document,
        validation_status="accepted",
    )
    db.add(vex_document)
    db.flush()
    statements = [
        _statement_from_result(result, sbom_id=sbom_id, vex_document_id=vex_document.id, components=list(components), created_at=now)
        for result in results
    ]
    for statement in statements:
        db.add(statement)
    db.commit()
    db.refresh(vex_document)
    return {
        "document_id": vex_document.id,
        "sbom_id": sbom_id,
        "statements_imported": len(statements),
        "format": vex_document.format,
        "validation_status": vex_document.validation_status,
    }


def process_embedded_vex_for_sbom(db: Session, sbom_id: int) -> dict[str, Any]:
    """Best-effort import of VEX statements embedded in a trusted SBOM."""
    sbom = db.get(SBOMSource, sbom_id)
    if sbom is None or not sbom.sbom_data:
        return {"sbom_id": sbom_id, "statements_imported": 0}
    try:
        document = json.loads(sbom.sbom_data)
    except (TypeError, ValueError):
        return {"sbom_id": sbom_id, "statements_imported": 0}
    if not isinstance(document, dict) or "vulnerabilities" not in document:
        return {"sbom_id": sbom_id, "statements_imported": 0}
    try:
        return import_vex_document(
            db,
            sbom_id,
            document,
            source_type="embedded",
            source_name="Embedded CycloneDX VEX",
        )
    except HTTPException:
        return {"sbom_id": sbom_id, "statements_imported": 0, "validation_status": "ignored"}


def list_vex_statements(db: Session, sbom_id: int) -> dict[str, Any]:
    sbom = db.get(SBOMSource, sbom_id)
    if sbom is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    statements = db.execute(select(VexStatement).where(VexStatement.sbom_id == sbom_id)).scalars().all()
    return {"sbom_id": sbom_id, "statements": [_statement_dict(statement) for statement in statements]}


def apply_vex_override(
    db: Session,
    component_id: int,
    vulnerability_id: str,
    payload: dict[str, Any],
    *,
    changed_by: str | None = None,
) -> VexStatement:
    component = db.get(SBOMComponent, component_id)
    if component is None:
        raise HTTPException(status_code=404, detail="Component not found")
    status = _normalize_vex_status(payload.get("status") or payload.get("vex_status"))
    result = _validate_vex_result(
        VexResult(
            component_name=component.name,
            component_version=component.version,
            vulnerability_id=vulnerability_id,
            cve_id=_cve_id(vulnerability_id),
            product_context=component.sbom.sbom_name if component.sbom else None,
            vex_status=status,
            vex_justification=payload.get("justification") or payload.get("vex_justification"),
            impact_statement=payload.get("impact_statement"),
            action_statement=payload.get("action_statement"),
            fixed_version=payload.get("fixed_version"),
            mitigation=payload.get("mitigation"),
            source_name="Manual VEX Override",
            source_url=payload.get("evidence_url") or payload.get("source_url"),
            evidence={"reason": payload.get("reason"), "evidence_url": payload.get("evidence_url")},
            confidence=HIGH if payload.get("evidence_url") else MEDIUM,
        )
    )
    if not payload.get("reason"):
        raise HTTPException(status_code=422, detail="Manual VEX override requires reason")
    existing = db.execute(
        select(VexStatement)
        .where(VexStatement.component_id == component_id)
        .where(func.lower(VexStatement.vulnerability_id) == vulnerability_id.lower())
        .order_by(VexStatement.id.desc())
    ).scalars().first()
    old = _statement_dict(existing) if existing else None
    statement = _statement_from_result(
        result,
        sbom_id=component.sbom_id,
        vex_document_id=None,
        components=[component],
        created_at=now_iso(),
    )
    db.add(statement)
    db.flush()
    db.add(
        VexOverrideAudit(
            component_id=component_id,
            vulnerability_id=vulnerability_id,
            old_value_json=old,
            new_value_json=_statement_dict(statement),
            reason=str(payload.get("reason")),
            evidence_url=payload.get("evidence_url"),
            changed_by=changed_by,
            changed_at=now_iso(),
        )
    )
    db.commit()
    db.refresh(statement)
    return statement


def vex_dashboard_summary(db: Session) -> dict[str, Any]:
    statements = db.execute(select(VexStatement)).scalars().all()
    counts = {status: 0 for status in ALLOWED_VEX_STATUSES}
    latest_by_key: dict[tuple[int | None, str], VexStatement] = {}
    for statement in statements:
        key = (statement.component_id, statement.vulnerability_id)
        if key not in latest_by_key or statement.id > latest_by_key[key].id:
            latest_by_key[key] = statement
    for statement in latest_by_key.values():
        counts[_normalize_vex_status(statement.status)] += 1
    requiring_action = counts["affected"] + counts["under_investigation"] + counts["unknown"]
    top_affected = [
        _statement_dict(statement)
        for statement in latest_by_key.values()
        if _normalize_vex_status(statement.status) == "affected"
    ][:10]
    return {
        "affected_count": counts["affected"],
        "not_affected_count": counts["not_affected"],
        "fixed_count": counts["fixed"],
        "under_investigation_count": counts["under_investigation"],
        "unknown_count": counts["unknown"],
        "vulnerabilities_reduced_by_vex": counts["not_affected"] + counts["fixed"],
        "vulnerabilities_requiring_action": requiring_action,
        "top_affected_components": top_affected,
    }


def _result_from_payload(
    vuln: dict[str, Any],
    component: SBOMComponent | None,
    vuln_id: str,
    status: str,
    sbom: SBOMSource,
    source_name: str,
    source_url: str | None,
    *,
    fixed_version: str | None = None,
    affected_ref: Any | None = None,
    affected_version: Any | None = None,
) -> VexResult:
    analysis = vuln.get("analysis") if isinstance(vuln.get("analysis"), dict) else {}
    return VexResult(
        component_name=component.name if component else str(affected_ref or sbom.sbom_name),
        component_version=component.version if component else None,
        vulnerability_id=vuln_id,
        cve_id=_cve_id(vuln_id),
        product_context=sbom.sbom_name,
        vex_status=_normalize_vex_status(status),
        vex_justification=analysis.get("justification") or vuln.get("justification"),
        impact_statement=analysis.get("detail") or vuln.get("description"),
        action_statement=_response_text(analysis),
        fixed_version=fixed_version,
        mitigation=vuln.get("recommendation"),
        source_name=source_name,
        source_url=source_url,
        evidence={"vulnerability": vuln, "affected_ref": affected_ref, "affected_version": affected_version},
        confidence=MEDIUM,
    )


def _statement_from_result(
    result: VexResult,
    *,
    sbom_id: int,
    vex_document_id: int | None,
    components: list[SBOMComponent],
    created_at: str,
) -> VexStatement:
    component = _match_component(components, result.component_name)
    return VexStatement(
        vex_document_id=vex_document_id,
        sbom_id=sbom_id,
        component_id=component.id if component else None,
        vulnerability_id=result.vulnerability_id,
        cve_id=result.cve_id,
        status=result.vex_status,
        justification=result.vex_justification,
        impact_statement=result.impact_statement,
        action_statement=result.action_statement,
        fixed_version=result.fixed_version,
        mitigation=result.mitigation,
        source_name=result.source_name,
        source_url=result.source_url,
        confidence=result.confidence,
        evidence_json=result.evidence,
        created_at=created_at,
    )


def _validate_vex_result(result: VexResult) -> VexResult:
    result.vex_status = _normalize_vex_status(result.vex_status)
    if result.vex_status == "not_affected" and not (result.vex_justification or result.impact_statement):
        raise HTTPException(status_code=422, detail="VEX not_affected requires justification or impact statement")
    if result.vex_status == "fixed" and not (result.fixed_version or result.impact_statement or result.evidence):
        raise HTTPException(status_code=422, detail="VEX fixed requires fixed version or evidence")
    return result


def _normalize_vex_status(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "unaffected": "not_affected",
        "notaffected": "not_affected",
        "resolved": "fixed",
        "resolved_with_pedigree": "fixed",
        "in_triage": "under_investigation",
        "investigating": "under_investigation",
        "exploitable": "affected",
    }
    text = aliases.get(text, text)
    if text not in ALLOWED_VEX_STATUSES:
        raise HTTPException(status_code=422, detail="Invalid VEX status")
    return text


def _match_component(components: list[SBOMComponent], ref: Any) -> SBOMComponent | None:
    if ref is None:
        return None
    text = str(ref).strip().lower()
    if not text:
        return None
    for component in components:
        candidates = {
            str(component.id).lower(),
            (component.bom_ref or "").lower(),
            (component.purl or "").lower(),
            (component.cpe or "").lower(),
            (component.name or "").lower(),
        }
        if text in candidates:
            return component
    return None


def _vulnerability_id(payload: dict[str, Any]) -> str | None:
    value = payload.get("id") or payload.get("bom-ref")
    if value:
        return str(value)
    ratings = payload.get("ratings") if isinstance(payload.get("ratings"), list) else []
    for rating in ratings:
        if isinstance(rating, dict) and rating.get("source"):
            return str(rating["source"])
    return None


def _cve_id(value: str) -> str | None:
    upper = value.upper()
    return upper if upper.startswith("CVE-") else None


def _fixed_version(analysis: dict[str, Any]) -> str | None:
    value = analysis.get("fixedVersion") or analysis.get("fixed_version")
    return str(value) if value else None


def _response_text(analysis: dict[str, Any]) -> str | None:
    responses = analysis.get("response")
    if isinstance(responses, list) and responses:
        return ", ".join(str(item) for item in responses)
    return str(responses) if responses else None


def _detect_format(document: dict[str, Any]) -> str:
    if "vulnerabilities" in document and "bomFormat" in document:
        return "CycloneDX VEX"
    if "statements" in document:
        return "OpenVEX"
    return "VEX JSON"


def _author(document: dict[str, Any]) -> str | None:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    supplier = metadata.get("supplier") if isinstance(metadata.get("supplier"), dict) else {}
    value = document.get("author") or supplier.get("name")
    return str(value) if value else None


def _statement_dict(statement: VexStatement | None) -> dict[str, Any] | None:
    if statement is None:
        return None
    return {
        "id": statement.id,
        "vex_document_id": statement.vex_document_id,
        "sbom_id": statement.sbom_id,
        "component_id": statement.component_id,
        "component_name": statement.component.name if statement.component else None,
        "component_version": statement.component.version if statement.component else None,
        "vulnerability_id": statement.vulnerability_id,
        "cve_id": statement.cve_id,
        "status": statement.status,
        "justification": statement.justification,
        "impact_statement": statement.impact_statement,
        "action_statement": statement.action_statement,
        "fixed_version": statement.fixed_version,
        "mitigation": statement.mitigation,
        "source_name": statement.source_name,
        "source_url": statement.source_url,
        "confidence": statement.confidence or UNKNOWN_CONFIDENCE,
        "evidence_json": statement.evidence_json,
        "created_at": statement.created_at,
    }


__all__ = [
    "ALLOWED_VEX_STATUSES",
    "VexProvider",
    "apply_vex_override",
    "import_vex_document",
    "list_vex_statements",
    "process_embedded_vex_for_sbom",
    "vex_dashboard_summary",
]
