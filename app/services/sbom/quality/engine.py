"""Nine advisory dimensions over one shared index; validation remains authoritative."""

from collections import Counter
from datetime import UTC, datetime
from functools import lru_cache
from hashlib import sha256

from app.parsing.strict_json import require_unambiguous_json
from app.validation import run as validate
from app.validation.context import ValidationContext
from app.validation.stages import detect, ingress, security
from app.validation.stages.schema import _build_json_validator, _ensure_json_schema
from app.validation.stages.semantic_cyclonedx import _HASH_HEX_LENGTHS
from packageurl import PackageURL

from ..repair.classifier import classify
from ..repair.registry import default_rules
from .inspection import (
    CPE_TYPES,
    HASH_TYPES,
    SOFTWARE_TYPES,
    DocumentIndex,
    canonical_cpe,
    repair_quality_issues,
    valid_purl,
)
from .models import QualityDimensionScore, QualityFinding, SbomQualityScore
from .policy import NAMES, QualityPolicy


@lru_cache(maxsize=3)
def field_validators(version):
    schema = _ensure_json_schema("cyclonedx", version)
    validator = _build_json_validator(schema, "cyclonedx", version)
    component = schema["definitions"]["component"]["properties"]
    metadata = schema["definitions"]["metadata"]["properties"]
    return {k: validator.evolve(schema=s) for k, s in component.items()}, {
        k: validator.evolve(schema=s) for k, s in metadata.items()
    }


def percentage(good, total):
    return round(100 * good / total, 1) if total else 100.0


class QualityEngine:
    def __init__(self, policy=None, repair_enabled=None):
        self.policy = policy or QualityPolicy.configured()
        if repair_enabled is not None:
            self.policy = self.policy.model_copy(update={"repair_enabled": repair_enabled})
        self.repair_enabled = self.policy.repair_enabled

    def calculate(self, raw: bytes, report=None, validation_options=None):
        report = report if report is not None else validate(raw, **(validation_options or {}))
        context = ingress.run(ValidationContext(raw_bytes=raw))
        if not context.report.has_errors() and len(raw) <= self.policy.max_bytes:
            context = detect.run(context)
            if not context.report.has_errors():
                context = security.run(context)
        supported = (
            len(raw) <= self.policy.max_bytes
            and not context.report.has_errors()
            and context.spec == "cyclonedx"
            and context.encoding == "json"
        )
        if supported:
            try:
                require_unambiguous_json(context.text)
            except (ValueError, TypeError):
                supported = False
        common = dict(
            calculated_at=datetime.now(UTC),
            artifact_hash=sha256(raw).hexdigest(),
            configuration_hash=self.policy.fingerprint(),
            configuration=self.policy.model_dump(mode="json"),
            spec_version=context.spec_version,
            validation_status="FAILED" if report.has_errors() else "PASSED",
            validation_report_truncated=report.truncated,
        )
        if not supported:
            return SbomQualityScore(
                overall_score=0,
                grade="NOT_ASSESSED",
                dimensions=[],
                findings=[],
                supported=False,
                reason="Quality scoring requires safely parsed CycloneDX JSON within the configured size limit.",
                **common,
            )
        return self._score(context.parsed_dict, report, common)

    def _score(self, document, report, common):
        index = DocumentIndex(document)
        component_fields, metadata_fields = field_validators(common["spec_version"])
        findings = []
        counts = Counter()
        totals = Counter()
        losses = Counter()
        rules = default_rules()
        classification_cache = {}
        repair_codes = set().union(*(r.error_codes for r in rules))
        repairable = self.repair_enabled and not index.signed

        def finding(code, dimension, path, message, action, severity="MINOR", error=None, impact=1):
            diagnostic = error or {"code": code, "path": path}
            key = (diagnostic["code"], diagnostic["path"])
            assessed = True
            if not repairable or diagnostic["code"] not in repair_codes:
                kind, change = classify(document, diagnostic, (), False)
            elif key in classification_cache:
                kind, change = classification_cache[key]
            elif len(classification_cache) < 100 and len(findings) < self.policy.max_findings:
                kind, change = classify(document, diagnostic, rules, True)
                classification_cache[key] = (kind, change)
            else:
                kind, change = classify(document, diagnostic, (), False)
                assessed = False
            counts[dimension] += 1
            losses[dimension] += impact
            if len(findings) < self.policy.max_findings:
                findings.append(
                    QualityFinding(
                        code=code,
                        dimension=dimension,
                        path=path,
                        severity=severity,
                        message=message,
                        remediation=action,
                        repairable=change is not None,
                        repair_classification=kind.value,
                        repairability_assessed=assessed,
                        quality_impact=impact,
                    )
                )

        schema_errors = [e for e in report.errors if e.stage in {"ingress", "detect", "schema"}]
        schema_score = max(0, 100 - 25 * len(schema_errors))
        for entry in schema_errors:
            finding(
                entry.code,
                "QD-01",
                entry.path,
                entry.message,
                entry.remediation,
                "BLOCKING",
                entry.model_dump(mode="json"),
                25,
            )
        for ref, path in index.declarations:
            totals["QD-02"] += 1
            if index.refs[ref] > 1:
                finding(
                    "QUALITY_ID_DUPLICATE_BOM_REF",
                    "QD-02",
                    path,
                    "Identifier is declared more than once.",
                    "Resolve the duplicate identity without guessing reference targets.",
                    "BLOCKING",
                    {"code": "SBOM_VAL_E051_BOM_REF_DUPLICATE", "path": path},
                )
        metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
        component_points = component_possible = 0
        coverage = {d: Counter() for d in ("QD-05", "QD-06", "QD-07", "QD-08")}
        for component, path in index.components:
            kind = str(component.get("type", "")).strip().lower()
            ref = component.get("bom-ref")
            if "bom-ref" in component and (
                not isinstance(ref, str) or not ref.strip() or not component_fields["bom-ref"].is_valid(ref)
            ):
                totals["QD-02"] += 1
                finding(
                    "QUALITY_ID_BOM_REF_INVALID",
                    "QD-02",
                    f"{path}/bom-ref",
                    "Declared component reference is invalid.",
                    "Provide a known identifier without inventing identity.",
                    "MAJOR",
                )
            cpe = canonical_cpe(component.get("cpe"))
            if cpe and "\\" not in cpe:
                cpe_version = cpe.split(":")[5]
                if cpe_version not in {"*", "-"} and component.get("version") and cpe_version != component["version"]:
                    totals["QD-02"] += 1
                    finding(
                        "QUALITY_ID_CPE_VERSION_CONFLICT",
                        "QD-02",
                        f"{path}/cpe",
                        "Component version differs from the literal CPE version.",
                        "Verify producer data; neither version is automatically changed.",
                        "MAJOR",
                    )
            fields = {"name": 40, "type": 20, "bom-ref": 15}
            if kind in SOFTWARE_TYPES:
                fields["version"] = 15
            if kind in {"application", "device", "firmware", "operating-system"}:
                fields["supplier"] = 10
            for key, points in fields.items():
                component_possible += points
                value = component.get(key)
                present = bool(value) and key in component_fields and component_fields[key].is_valid(value)
                if key == "supplier":
                    present |= (
                        bool(component.get("manufacturer"))
                        and "manufacturer" in component_fields
                        and component_fields["manufacturer"].is_valid(component["manufacturer"])
                    )
                if present:
                    component_points += points
                else:
                    finding(
                        "QUALITY_COMPONENT_" + key.replace("-", "_").upper() + "_MISSING",
                        "QD-04",
                        f"{path}/{key}",
                        f"Useful component {key} is missing or invalid.",
                        "Provide known component metadata; do not infer it.",
                        impact=points,
                    )
            for field, dimension, eligible, valid in (
                ("purl", "QD-05", kind in SOFTWARE_TYPES or "purl" in component, valid_purl(component.get("purl"))),
                (
                    "cpe",
                    "QD-06",
                    kind in CPE_TYPES or "cpe" in component,
                    canonical_cpe(component.get("cpe")) == component.get("cpe") and bool(component.get("cpe")),
                ),
                (
                    "licenses",
                    "QD-07",
                    kind in SOFTWARE_TYPES | {"data", "machine-learning-model"} or "licenses" in component,
                    bool(component.get("licenses")) and component_fields["licenses"].is_valid(component["licenses"]),
                ),
                (
                    "hashes",
                    "QD-08",
                    kind in HASH_TYPES or "hashes" in component,
                    bool(component.get("hashes")) and component_fields["hashes"].is_valid(component["hashes"]),
                ),
            ):
                metric = coverage[dimension]
                metric["components_total"] += 1
                if not eligible:
                    metric["not_applicable"] += 1
                    continue
                metric["eligible"] += 1
                value = component.get(field)
                if field == "hashes":
                    metric["components_with_hashes" if value else "components_without_hashes"] += 1
                if field == "hashes" and isinstance(value, list):
                    for h in value:
                        if not isinstance(h, dict):
                            metric["invalid_hash_values"] += 1
                            valid = False
                        elif not isinstance(h.get("alg"), str) or h["alg"] not in _HASH_HEX_LENGTHS:
                            metric["unsupported_algorithms"] += 1
                            valid = False
                        elif not isinstance(h.get("content"), str) or len(h["content"]) != _HASH_HEX_LENGTHS[h["alg"]]:
                            metric["invalid_hash_values"] += 1
                            valid = False
                if valid:
                    metric["valid"] += 1
                    if field == "licenses":
                        for lic in value:
                            form = (
                                "expression"
                                if "expression" in lic
                                else "spdx_identifier"
                                if "id" in lic.get("license", {})
                                else "license_name"
                            )
                            metric[form] += 1
                else:
                    state = "invalid" if value else "missing"
                    metric[state] += 1
                    diagnostic = (
                        {
                            "code": "SBOM_VAL_E052_PURL_INVALID" if field == "purl" else "SBOM_VAL_E053_CPE_INVALID",
                            "path": f"{path}/{field}",
                        }
                        if field in {"purl", "cpe"}
                        else None
                    )
                    finding(
                        "QUALITY_" + field.upper() + "_" + state.upper(),
                        dimension,
                        f"{path}/{field}",
                        f"Eligible component has {state} {field}.",
                        "Provide verified metadata from the producer; unknown values cannot be invented.",
                        "MAJOR" if state == "invalid" else "MINOR",
                        diagnostic,
                    )
                if field in {"purl", "cpe"} and value:
                    totals["QD-02"] += 1
                    if not valid:
                        finding(
                            "QUALITY_ID_" + field.upper() + "_INVALID",
                            "QD-02",
                            f"{path}/{field}",
                            f"Existing {field.upper()} is invalid.",
                            "Correct it from existing authoritative data.",
                            "MAJOR",
                            diagnostic,
                        )
            if valid_purl(component.get("purl")):
                parsed = PackageURL.from_string(component["purl"])
                # Version comparison is exact; ecosystem name aliases are never guessed.
                if parsed.version and component.get("version") and parsed.version != component["version"]:
                    totals["QD-02"] += 1
                    finding(
                        "QUALITY_ID_VERSION_CONFLICT",
                        "QD-02",
                        f"{path}/purl",
                        "Component version differs from the PURL version.",
                        "Verify the producer data; neither version is automatically changed.",
                        "MAJOR",
                    )
                if parsed.name != component.get("name"):
                    finding(
                        "QUALITY_ID_NAME_DIFFERENCE",
                        "QD-02",
                        f"{path}/purl",
                        "Component name differs from its PURL name; an ecosystem alias may explain it.",
                        "Review naming context; no identifier is rewritten.",
                        "INFORMATIONAL",
                        impact=0,
                    )
        if not index.components:
            finding(
                "QUALITY_COMPONENT_INVENTORY_EMPTY",
                "QD-04",
                "/components",
                "No component inventory is available to assess completeness.",
                "Provide the known inventory or document why the empty inventory is intentional.",
                "MAJOR",
                impact=100,
            )
        node_counts = Counter(
            n.get("ref") for n in index.dependencies if isinstance(n, dict) and isinstance(n.get("ref"), str)
        )
        graph_edges = 0
        for i, node in enumerate(index.dependencies):
            path = f"/dependencies/{i}"
            totals["QD-03"] += 1
            if not isinstance(node, dict):
                finding(
                    "QUALITY_DEPENDENCY_NODE_INVALID",
                    "QD-03",
                    path,
                    "Dependency node is not an object.",
                    "Correct the source representation.",
                    "BLOCKING",
                )
                continue
            ref = node.get("ref")
            if not isinstance(ref, str) or index.refs.get(ref, 0) != 1:
                error = {"code": "SBOM_VAL_E070_DEPENDENCY_REF_DANGLING", "path": f"{path}/ref"}
                finding(
                    "QUALITY_DEPENDENCY_SOURCE_INVALID",
                    "QD-03",
                    f"{path}/ref",
                    "Dependency source is unresolved or ambiguous.",
                    "Use an existing unambiguous declaration.",
                    "BLOCKING",
                    error,
                )
                totals["QD-02"] += 1
                finding(
                    "QUALITY_ID_SOURCE_UNRESOLVED",
                    "QD-02",
                    f"{path}/ref",
                    "Dependency source does not resolve uniquely.",
                    "Review the existing identifiers.",
                    "BLOCKING",
                    error,
                )
            targets = node.get("dependsOn", [])
            if not isinstance(targets, list):
                finding(
                    "QUALITY_DEPENDENCY_TARGETS_INVALID",
                    "QD-03",
                    f"{path}/dependsOn",
                    "Dependency targets are not an array.",
                    "Correct the representation.",
                    "BLOCKING",
                )
                continue
            seen = set()
            for j, target in enumerate(targets):
                graph_edges += 1
                totals["QD-03"] += 1
                totals["QD-02"] += 1
                error = {"code": "SBOM_VAL_E070_DEPENDENCY_REF_DANGLING", "path": f"{path}/dependsOn/{j}"}
                if not isinstance(target, str) or index.refs.get(target, 0) != 1:
                    finding(
                        "QUALITY_DEPENDENCY_DANGLING",
                        "QD-03",
                        error["path"],
                        "Dependency target is unresolved or ambiguous.",
                        "Resolve only an exact unambiguous existing identity.",
                        "BLOCKING",
                        error,
                    )
                    finding(
                        "QUALITY_ID_TARGET_UNRESOLVED",
                        "QD-02",
                        error["path"],
                        "Dependency target does not resolve uniquely.",
                        "Review existing identifiers.",
                        "BLOCKING",
                        error,
                    )
                if target == ref:
                    finding(
                        "QUALITY_DEPENDENCY_SELF",
                        "QD-03",
                        error["path"],
                        "Application validation prohibits self-dependencies.",
                        "Remove only the proven self-edge.",
                        "BLOCKING",
                        {"code": "SBOM_VAL_E071_DEPENDENCY_REF_SELF", "path": f"{path}/ref"},
                    )
                if isinstance(target, str):
                    if target in seen:
                        finding(
                            "QUALITY_DEPENDENCY_DUPLICATE_EDGE",
                            "QD-03",
                            f"{path}/dependsOn",
                            "An identical edge is repeated.",
                            "Retain one occurrence of the same existing edge.",
                            error={"code": "SBOM_VAL_E025_SCHEMA_VIOLATION", "path": f"{path}/dependsOn"},
                        )
                    seen.add(target)
            if isinstance(ref, str) and node_counts[ref] > 1:
                finding(
                    "QUALITY_DEPENDENCY_DUPLICATE_NODE",
                    "QD-03",
                    path,
                    "Dependency source has multiple records.",
                    "Only identical or redundant empty records can be removed automatically.",
                    impact=1,
                )
        for issue in repair_quality_issues(document, index):
            dim = "QD-03" if issue["code"] == "QUALITY_DUPLICATE_EMPTY_NODE" else "QD-02"
            totals[dim] += 1
            finding(
                issue["code"],
                dim,
                issue["path"],
                issue["message"],
                "Review the deterministic proposal before acceptance.",
                error=issue,
            )
        metadata_possible = metadata_good = 0
        fields = [
            ("serialNumber", 10, document),
            ("version", 10, document),
            ("timestamp", 25, metadata),
            ("component", 25, metadata),
            ("tools", 20, metadata),
        ]
        fields.append(("producer", 10, metadata))
        for key, points, source in fields:
            metadata_possible += points
            if key == "producer":
                good = any(
                    metadata.get(k) and k in metadata_fields and metadata_fields[k].is_valid(metadata[k])
                    for k in ("authors", "manufacturer", "supplier", "manufacture")
                )
            elif source is document:
                schema = _ensure_json_schema("cyclonedx", common["spec_version"])
                good = bool(source.get(key)) and _build_json_validator(
                    schema, "cyclonedx", common["spec_version"]
                ).evolve(schema=schema["properties"][key]).is_valid(source[key])
            else:
                good = bool(source.get(key)) and key in metadata_fields and metadata_fields[key].is_valid(source[key])
            if good:
                metadata_good += points
            else:
                finding(
                    "QUALITY_METADATA_" + key.upper() + "_MISSING",
                    "QD-09",
                    f"/metadata/{key}" if source is metadata else f"/{key}",
                    f"Optional useful {key} metadata is missing or invalid.",
                    "Provide it when known and meaningful to the document context.",
                    impact=points,
                )
        # Lifecycle information is meaningful only when declared, and only in versions supporting it.
        lifecycle_invalid = (
            "lifecycles" in metadata
            and "lifecycles" in metadata_fields
            and not metadata_fields["lifecycles"].is_valid(metadata["lifecycles"])
        )
        if lifecycle_invalid:
            finding(
                "QUALITY_METADATA_LIFECYCLES_INVALID",
                "QD-09",
                "/metadata/lifecycles",
                "Declared lifecycle metadata is invalid.",
                "Use the declared-version schema.",
                "MAJOR",
                impact=10,
            )
        scores = {
            "QD-01": schema_score,
            "QD-02": percentage(max(0, totals["QD-02"] - losses["QD-02"]), totals["QD-02"]),
            "QD-03": percentage(max(0, totals["QD-03"] - losses["QD-03"]), totals["QD-03"]),
            "QD-04": percentage(component_points, component_possible) if component_possible else 0,
            "QD-09": max(0, percentage(metadata_good, metadata_possible) - (10 if lifecycle_invalid else 0)),
        }
        dimensions = []
        for code, name in NAMES.items():
            metric = dict(coverage.get(code, {}))
            if code in coverage:
                scores[code] = percentage(metric.get("valid", 0), metric.get("eligible", 0))
                metric["coverage_percentage"] = scores[code]
                if code == "QD-08":
                    for key in (
                        "components_with_hashes",
                        "components_without_hashes",
                        "invalid_hash_values",
                        "unsupported_algorithms",
                    ):
                        metric.setdefault(key, 0)
                for key in ("eligible", "valid", "missing", "invalid", "not_applicable"):
                    metric.setdefault(key, 0)
            if code == "QD-03":
                metric.update(
                    nodes=len(index.dependencies), edges=graph_edges, graph_declared="dependencies" in document
                )
            dimensions.append(
                QualityDimensionScore(
                    code=code,
                    name=name,
                    score=scores[code],
                    weight=self.policy.weights[code],
                    finding_count=counts[code],
                    metrics=metric,
                )
            )
        for f in findings:
            if f.dimension in {"QD-02", "QD-03"}:
                f.quality_impact = round(100 * f.quality_impact / max(1, totals[f.dimension]), 1)
            elif f.dimension in coverage:
                f.quality_impact = round(100 / max(1, coverage[f.dimension]["eligible"]), 1)
            elif f.dimension == "QD-04":
                f.quality_impact = round(100 * f.quality_impact / max(1, component_possible), 1)
        overall = round(sum(d.score * d.weight / 100 for d in dimensions), 1)
        return SbomQualityScore(
            overall_score=overall,
            grade=self.policy.grade(overall),
            dimensions=dimensions,
            findings=findings,
            findings_truncated=sum(counts.values()) > len(findings),
            **common,
        )


def comparison(before, after):
    comparable = (
        before["supported"]
        and after["supported"]
        and before["engine_version"] == after["engine_version"]
        and before["configuration_hash"] == after["configuration_hash"]
        and before["spec_version"] == after["spec_version"]
    )
    return {
        "before": before,
        "after": after,
        "comparable": comparable,
        "improvement": round(after["overall_score"] - before["overall_score"], 1) if comparable else None,
        "dimensions": [
            {
                "code": b["code"],
                "name": b["name"],
                "before": b["score"],
                "after": a["score"],
                "improvement": round(a["score"] - b["score"], 1),
            }
            for b, a in zip(before["dimensions"], after["dimensions"], strict=False)
            if comparable and b["score"] != a["score"]
        ],
    }
