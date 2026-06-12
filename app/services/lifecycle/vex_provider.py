"""VEX import, statement mapping, and manual override services."""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import SBOMComponent, SBOMSource, VexDocument, VexOverrideAudit, VexStatement
from .types import HIGH, LOW, MEDIUM, UNKNOWN_CONFIDENCE, VexResult, now_iso

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
        if _is_csaf_document(document):
            return self._parse_csaf(document, sbom=sbom, components=components, source_name=source_name, source_url=source_url)
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
                evidence = {"statement": statement, "product": product}
                if component:
                    evidence["matched_component_id"] = component.id
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
                            evidence=evidence,
                            confidence=MEDIUM if component else LOW,
                        )
                    )
                )
        return results

    def _parse_csaf(
        self,
        document: dict[str, Any],
        *,
        sbom: SBOMSource,
        components: list[SBOMComponent],
        source_name: str,
        source_url: str | None,
    ) -> list[VexResult]:
        _validate_csaf_structure(document)
        products = _csaf_products(document)
        metadata = document.get("document") if isinstance(document.get("document"), dict) else {}
        publisher = metadata.get("publisher") if isinstance(metadata.get("publisher"), dict) else {}
        tracking = metadata.get("tracking") if isinstance(metadata.get("tracking"), dict) else {}
        author = publisher.get("name") or metadata.get("title") or source_name or "CSAF VEX"
        timestamp = tracking.get("current_release_date") or tracking.get("initial_release_date") or now_iso()
        results: list[VexResult] = []

        for vuln in document.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = _csaf_vulnerability_id(vuln)
            if not vuln_id:
                continue
            emitted = False
            product_status = vuln.get("product_status") if isinstance(vuln.get("product_status"), dict) else {}
            for csaf_status, raw_product_ids in product_status.items():
                status = _csaf_status(csaf_status)
                if status is None:
                    continue
                product_ids = raw_product_ids if isinstance(raw_product_ids, list) else [raw_product_ids]
                for product_id in product_ids:
                    if not product_id:
                        continue
                    product_key = str(product_id)
                    product = products.get(product_key, {"product_id": product_key, "name": product_key})
                    component = _match_component(components, product)
                    evidence: dict[str, Any] = {
                        "format": "CSAF",
                        "product_id": product_key,
                        "product": product,
                        "vulnerability": vuln,
                        "csaf_status": csaf_status,
                        "author": author,
                        "timestamp": timestamp,
                        "mapping": "matched" if component else "unmatched",
                    }
                    if component:
                        evidence["matched_component_id"] = component.id
                    results.append(
                        _validate_vex_result(
                            VexResult(
                                component_name=component.name if component else str(product.get("name") or product_key),
                                component_version=component.version if component else _text(product.get("version")),
                                vulnerability_id=str(vuln_id),
                                cve_id=_cve_id(str(vuln_id)),
                                product_context=sbom.sbom_name,
                                vex_status=status,
                                vex_justification=_csaf_justification(vuln, product_key),
                                impact_statement=_csaf_impact_statement(vuln, product_key),
                                action_statement=_csaf_action_statement(vuln, product_key),
                                fixed_version=_csaf_fixed_version(vuln, product_key),
                                mitigation=_csaf_mitigation(vuln, product_key),
                                source_name=str(author),
                                source_url=source_url,
                                evidence=evidence,
                                confidence=MEDIUM if component else LOW,
                                checked_at=str(timestamp),
                            )
                        )
                    )
                    emitted = True

            if not emitted:
                results.append(
                    _validate_vex_result(
                        VexResult(
                            component_name=sbom.sbom_name,
                            component_version=sbom.productver,
                            vulnerability_id=str(vuln_id),
                            cve_id=_cve_id(str(vuln_id)),
                            product_context=sbom.sbom_name,
                            vex_status="unknown",
                            impact_statement=_csaf_impact_statement(vuln, None),
                            action_statement=_csaf_action_statement(vuln, None),
                            source_name=str(author),
                            source_url=source_url,
                            evidence={
                                "format": "CSAF",
                                "vulnerability": vuln,
                                "mapping": "unmatched",
                                "reason": "No CSAF product_status entry mapped this vulnerability to a product.",
                                "author": author,
                                "timestamp": timestamp,
                            },
                            confidence=LOW,
                            checked_at=str(timestamp),
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
    discovery_evidence: dict[str, Any] | None = None,
    last_refresh_status: str | None = None,
    provider_errors: list[dict[str, Any]] | None = None,
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
        source_url=source_url,
        discovery_evidence_json=discovery_evidence,
        last_refresh_status=last_refresh_status,
        provider_errors_json=provider_errors,
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
        "matched_statements": sum(1 for statement in statements if statement.component_id is not None),
        "unmatched_statements": sum(1 for statement in statements if statement.component_id is None),
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


def vex_report(db: Session, sbom_id: int, *, status_filter: str | None = None) -> dict[str, Any]:
    data = list_vex_statements(db, sbom_id)
    statements = data["statements"]
    if status_filter:
        status = _normalize_vex_status(status_filter)
        statements = [statement for statement in statements if _normalize_vex_status(statement.get("status")) == status]
    counts = {status: 0 for status in ALLOWED_VEX_STATUSES}
    unmatched = 0
    for statement in statements:
        counts[_normalize_vex_status(statement.get("status"))] += 1
        if statement.get("component_id") is None:
            unmatched += 1
    return {
        **data,
        "generated_at": now_iso(),
        "summary": {**counts, "total": len(statements), "unmatched": unmatched},
        "statements": statements,
    }


def vex_report_csv(db: Session, sbom_id: int, *, status_filter: str | None = None) -> str:
    import csv
    import io

    report = vex_report(db, sbom_id, status_filter=status_filter)
    out = io.StringIO()
    writer = csv.DictWriter(
        out,
        fieldnames=[
            "vulnerability_id",
            "cve_id",
            "component_name",
            "component_version",
            "status",
            "justification",
            "impact_statement",
            "action_statement",
            "fixed_version",
            "mitigation",
            "source_name",
            "source_url",
            "confidence",
            "created_at",
            "matched",
        ],
    )
    writer.writeheader()
    for statement in report["statements"]:
        writer.writerow(
            {
                "vulnerability_id": statement.get("vulnerability_id"),
                "cve_id": statement.get("cve_id"),
                "component_name": statement.get("component_name"),
                "component_version": statement.get("component_version"),
                "status": statement.get("status"),
                "justification": statement.get("justification"),
                "impact_statement": statement.get("impact_statement"),
                "action_statement": statement.get("action_statement"),
                "fixed_version": statement.get("fixed_version"),
                "mitigation": statement.get("mitigation"),
                "source_name": statement.get("source_name"),
                "source_url": statement.get("source_url"),
                "confidence": statement.get("confidence"),
                "created_at": statement.get("created_at"),
                "matched": statement.get("component_id") is not None,
            }
        )
    return out.getvalue()


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
    if status == "fixed" and not (
        payload.get("fixed_version")
        or payload.get("evidence_url")
        or payload.get("source_url")
        or payload.get("impact_statement")
    ):
        raise HTTPException(status_code=422, detail="Manual VEX fixed override requires fixed version or evidence")
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
    evidence = {"vulnerability": vuln, "affected_ref": affected_ref, "affected_version": affected_version}
    if component:
        evidence["matched_component_id"] = component.id
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
        evidence=evidence,
        confidence=MEDIUM if component else LOW,
    )


def _statement_from_result(
    result: VexResult,
    *,
    sbom_id: int,
    vex_document_id: int | None,
    components: list[SBOMComponent],
    created_at: str,
) -> VexStatement:
    matched_id = result.evidence.get("matched_component_id") if isinstance(result.evidence, dict) else None
    component = next((c for c in components if c.id == matched_id), None) if matched_id else None
    component = component or _match_component(components, result.component_name)
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
    ref_data = ref if isinstance(ref, dict) else {}
    text = _component_ref_text(ref)
    for component in components:
        if text and text in _component_candidates(component):
            return component
        if ref_data and _component_matches_product(component, ref_data):
            return component
    return None


def _component_candidates(component: SBOMComponent) -> set[str]:
    name = _norm(component.name)
    version = _norm(component.version)
    supplier = _norm(component.supplier)
    candidates = {
        _norm(component.id),
        _norm(component.bom_ref),
        _norm(component.purl),
        _norm(component.cpe),
        name,
    }
    if name and version:
        candidates.update({f"{name}@{version}", f"{name}:{version}", f"{name} {version}"})
    if supplier and name and version:
        candidates.update({f"{supplier}/{name}@{version}", f"{supplier}:{name}:{version}", f"{supplier} {name} {version}"})
    return {candidate for candidate in candidates if candidate}


def _component_matches_product(component: SBOMComponent, product: dict[str, Any]) -> bool:
    helper = product.get("product_identification_helper") if isinstance(product.get("product_identification_helper"), dict) else {}
    purls = _as_list(product.get("purl")) + _as_list(helper.get("purl"))
    cpes = _as_list(product.get("cpe")) + _as_list(helper.get("cpe")) + _as_list(helper.get("cpe23Uri"))
    product_name = _norm(product.get("name") or product.get("product_name"))
    product_version = _norm(product.get("version") or helper.get("version"))
    product_supplier = _norm(product.get("supplier") or product.get("vendor") or helper.get("supplier"))
    if component.purl and any(_norm(component.purl) == _norm(purl) for purl in purls):
        return True
    if component.cpe and any(_norm(component.cpe) == _norm(cpe) for cpe in cpes):
        return True
    comp_name = _norm(component.name)
    comp_version = _norm(component.version)
    comp_supplier = _norm(component.supplier)
    if product_name and product_name == comp_name and (not product_version or product_version == comp_version):
        return True
    return bool(
        product_supplier
        and comp_supplier
        and product_supplier == comp_supplier
        and product_name == comp_name
        and (not product_version or product_version == comp_version)
    )


def _component_ref_text(ref: Any) -> str:
    if isinstance(ref, dict):
        for key in ("product_id", "productId", "id", "bom_ref", "bom-ref", "purl", "cpe", "name"):
            value = ref.get(key)
            if value:
                return _norm(value)
        return ""
    return _norm(ref)


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
    if _is_csaf_document(document):
        return "CSAF VEX"
    if "vulnerabilities" in document and "bomFormat" in document:
        return "CycloneDX VEX"
    if "statements" in document:
        return "OpenVEX"
    return "VEX JSON"


def _author(document: dict[str, Any]) -> str | None:
    csaf_doc = document.get("document") if isinstance(document.get("document"), dict) else {}
    publisher = csaf_doc.get("publisher") if isinstance(csaf_doc.get("publisher"), dict) else {}
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    supplier = metadata.get("supplier") if isinstance(metadata.get("supplier"), dict) else {}
    value = document.get("author") or publisher.get("name") or supplier.get("name")
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


def _is_csaf_document(document: dict[str, Any]) -> bool:
    return (
        isinstance(document.get("document"), dict)
        and isinstance(document.get("product_tree"), dict)
        and isinstance(document.get("vulnerabilities"), list)
    )


def _validate_csaf_structure(document: dict[str, Any]) -> None:
    if not isinstance(document.get("document"), dict):
        raise HTTPException(status_code=422, detail="CSAF document missing document metadata")
    if not isinstance(document.get("product_tree"), dict):
        raise HTTPException(status_code=422, detail="CSAF document missing product_tree")
    if not isinstance(document.get("vulnerabilities"), list):
        raise HTTPException(status_code=422, detail="CSAF document missing vulnerabilities")


def _csaf_products(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    products: dict[str, dict[str, Any]] = {}
    tree = document.get("product_tree") if isinstance(document.get("product_tree"), dict) else {}

    def add_product(payload: dict[str, Any]) -> None:
        product_id = payload.get("product_id") or payload.get("productId")
        if not product_id:
            return
        products[str(product_id)] = {
            "product_id": str(product_id),
            "name": payload.get("name") or payload.get("product_name") or str(product_id),
            "product_identification_helper": payload.get("product_identification_helper") or {},
            "version": payload.get("version"),
            "supplier": payload.get("supplier"),
        }

    for full in tree.get("full_product_names") or []:
        if isinstance(full, dict):
            add_product(full)
    for relationship in tree.get("relationships") or []:
        if isinstance(relationship, dict) and isinstance(relationship.get("full_product_name"), dict):
            add_product(relationship["full_product_name"])

    def walk_branch(branch: dict[str, Any], inherited: list[str] | None = None) -> None:
        inherited = inherited or []
        name_parts = inherited + ([str(branch.get("name"))] if branch.get("name") else [])
        if isinstance(branch.get("product"), dict):
            product = dict(branch["product"])
            product.setdefault("name", " ".join(name_parts) or product.get("product_id"))
            add_product(product)
        for child in branch.get("branches") or []:
            if isinstance(child, dict):
                walk_branch(child, name_parts)

    for branch in tree.get("branches") or []:
        if isinstance(branch, dict):
            walk_branch(branch)
    return products


def _csaf_vulnerability_id(vuln: dict[str, Any]) -> str | None:
    if vuln.get("cve"):
        return str(vuln["cve"])
    for item in vuln.get("ids") or []:
        if isinstance(item, dict) and item.get("text"):
            return str(item["text"])
    return _text(vuln.get("title"))


def _csaf_status(status: str) -> str | None:
    key = str(status or "").strip().lower()
    if key in {"known_affected", "first_affected", "last_affected", "affected"}:
        return "affected"
    if key in {"known_not_affected", "not_affected"}:
        return "not_affected"
    if key in {"fixed", "first_fixed", "recommended"}:
        return "fixed"
    if key == "under_investigation":
        return "under_investigation"
    if key == "unknown":
        return "unknown"
    return None


def _csaf_justification(vuln: dict[str, Any], product_id: str | None) -> str | None:
    for flag in vuln.get("flags") or []:
        if not isinstance(flag, dict):
            continue
        products = {str(item) for item in flag.get("product_ids") or []}
        if product_id is None or not products or product_id in products:
            return _text(flag.get("label")) or _text(flag.get("description"))
    return None


def _csaf_impact_statement(vuln: dict[str, Any], product_id: str | None) -> str | None:
    for threat in vuln.get("threats") or []:
        if not isinstance(threat, dict):
            continue
        products = {str(item) for item in threat.get("product_ids") or []}
        if product_id is None or not products or product_id in products:
            if str(threat.get("category") or "").lower() in {"impact", "exploit_status"}:
                return _text(threat.get("details"))
    for note in vuln.get("notes") or []:
        if isinstance(note, dict) and str(note.get("category") or "").lower() in {"description", "summary"}:
            return _text(note.get("text"))
    return None


def _csaf_action_statement(vuln: dict[str, Any], product_id: str | None) -> str | None:
    actions: list[str] = []
    for remediation in vuln.get("remediations") or []:
        if not isinstance(remediation, dict):
            continue
        products = {str(item) for item in remediation.get("product_ids") or []}
        if product_id is not None and products and product_id not in products:
            continue
        category = str(remediation.get("category") or "").replace("_", " ")
        details = _text(remediation.get("details"))
        if details:
            actions.append(f"{category}: {details}" if category else details)
    return "; ".join(actions) if actions else None


def _csaf_fixed_version(vuln: dict[str, Any], product_id: str | None) -> str | None:
    for remediation in vuln.get("remediations") or []:
        if not isinstance(remediation, dict):
            continue
        products = {str(item) for item in remediation.get("product_ids") or []}
        if product_id is not None and products and product_id not in products:
            continue
        if str(remediation.get("category") or "").lower() in {"vendor_fix", "update"}:
            for key in ("fixed_version", "version"):
                value = remediation.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _csaf_mitigation(vuln: dict[str, Any], product_id: str | None) -> str | None:
    mitigations: list[str] = []
    for remediation in vuln.get("remediations") or []:
        if not isinstance(remediation, dict):
            continue
        products = {str(item) for item in remediation.get("product_ids") or []}
        if product_id is not None and products and product_id not in products:
            continue
        if str(remediation.get("category") or "").lower() in {"mitigation", "workaround", "no_fix_planned"}:
            details = _text(remediation.get("details"))
            if details:
                mitigations.append(details)
    return "; ".join(mitigations) if mitigations else None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


__all__ = [
    "ALLOWED_VEX_STATUSES",
    "VexProvider",
    "apply_vex_override",
    "import_vex_document",
    "list_vex_statements",
    "process_embedded_vex_for_sbom",
    "vex_report",
    "vex_report_csv",
    "vex_dashboard_summary",
]
