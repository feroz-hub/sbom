"""Advisory quality dimensions independent of vulnerability severity/upload gates."""

import copy
import json

import pytest
from app.services.sbom.quality.engine import QualityEngine
from app.services.sbom.quality.policy import QualityPolicy
from app.validation import run


def rich_document(version="1.6"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": version,
        "version": 1,
        "serialNumber": "urn:uuid:12345678-1234-4234-9234-123456789abc",
        "metadata": {
            "timestamp": "2026-10-06T00:00:00Z",
            "tools": [{"name": "fixture", "version": "1"}],
            "authors": [{"name": "Producer"}],
            "component": {
                "type": "application",
                "name": "product",
                "version": "1",
                "bom-ref": "product",
                "supplier": {"name": "Producer"},
                "purl": "pkg:generic/product@1",
                "cpe": "cpe:2.3:a:producer:product:1:*:*:*:*:*:*:*",
                "licenses": [{"license": {"id": "MIT"}}],
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            },
        },
        "components": [
            {
                "type": "library",
                "name": "alpha",
                "version": "1",
                "bom-ref": "alpha",
                "purl": "pkg:generic/alpha@1",
                "licenses": [{"license": {"id": "MIT"}}],
                "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
            }
        ],
        "dependencies": [{"ref": "product", "dependsOn": ["alpha"]}],
    }


def score(doc, **kwargs):
    return QualityEngine(**kwargs).calculate(json.dumps(doc).encode())


def dimension(result, code):
    return next(d for d in result.dimensions if d.code == code)


@pytest.mark.parametrize("version", ["1.4", "1.5", "1.6"])
def test_high_quality_supported_schema_scores_highly(version):
    result = score(rich_document(version))
    assert result.validation_status == "PASSED"
    assert result.overall_score == 100
    assert result.grade == "EXCELLENT"


def test_incomplete_valid_document_keeps_validation_pass():
    doc = rich_document()
    doc.pop("metadata")
    doc["dependencies"] = []
    for c in doc["components"]:
        c.pop("licenses")
        c.pop("hashes")
        c.pop("purl")
    result = score(doc)
    assert not run(json.dumps(doc).encode()).has_errors()
    assert result.validation_status == "PASSED"
    assert result.overall_score < 80
    assert dimension(result, "QD-07").score == 0
    assert any(f.code == "QUALITY_LICENSES_MISSING" and not f.repairable for f in result.findings)


@pytest.mark.parametrize(
    "field,code,value",
    [
        ("purl", "QD-05", "invalid"),
        ("cpe", "QD-06", "invalid"),
        ("hashes", "QD-08", [{"alg": "SHA-256", "content": "x"}]),
        ("licenses", "QD-07", [{"license": {"id": "NOT-SPDX"}}]),
    ],
)
def test_invalid_field_reduces_specific_quality(field, code, value):
    doc = rich_document()
    doc["metadata"]["component"][field] = value
    result = score(doc)
    assert dimension(result, code).score < 100
    assert result.overall_score < 100


def test_duplicate_and_dangling_integrity_is_measured_even_after_schema_failure():
    doc = rich_document()
    doc["components"][0]["bom-ref"] = "product"
    doc["dependencies"][0]["dependsOn"] = ["missing"]
    result = score(doc)
    assert dimension(result, "QD-02").score < 100
    assert dimension(result, "QD-03").score < 100
    assert result.validation_status == "FAILED"


@pytest.mark.parametrize("kind", ["device", "data", "file", "cryptographic-asset"])
def test_purl_not_applicable_does_not_reduce_coverage(kind):
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"type": kind, "name": "entity", "bom-ref": "entity"}],
    }
    result = score(doc)
    assert dimension(result, "QD-05").score == 100
    assert dimension(result, "QD-05").metrics["eligible"] == 0


def test_cpe_not_applicable_for_library_and_missing_applicable_hashes():
    doc = rich_document()
    doc.pop("metadata")
    doc["dependencies"] = []
    doc["components"][0].pop("hashes")
    result = score(doc)
    assert dimension(result, "QD-06").metrics["not_applicable"] == 1
    assert dimension(result, "QD-06").score == 100
    assert dimension(result, "QD-08").score == 0


@pytest.mark.parametrize(
    "license_value,form",
    [
        ([{"license": {"id": "MIT"}}], "spdx_identifier"),
        ([{"license": {"name": "Proprietary"}}], "license_name"),
        ([{"expression": "MIT OR Apache-2.0"}], "expression"),
    ],
)
def test_supported_license_representations(license_value, form):
    doc = rich_document()
    doc["components"][0]["licenses"] = license_value
    result = score(doc)
    assert dimension(result, "QD-07").score == 100
    assert dimension(result, "QD-07").metrics[form] >= 1


def test_same_bytes_policy_and_version_produce_identical_scores_and_findings():
    doc = rich_document()
    raw = json.dumps(doc).encode()
    before = copy.deepcopy(doc)
    a = QualityEngine().calculate(raw).model_dump(exclude={"calculated_at"})
    b = QualityEngine().calculate(raw).model_dump(exclude={"calculated_at"})
    assert a == b and doc == before
    assert len(a["artifact_hash"]) == 64
    assert sum(d["weight"] for d in a["dimensions"]) == 100


@pytest.mark.parametrize(
    "weights", [{"QD-01": 100}, {"QD-01": -1}, dict(zip([f"QD-0{i}" for i in range(1, 10)], [10] * 9, strict=True))]
)
def test_invalid_weight_configuration_rejected(weights):
    with pytest.raises(ValueError):
        QualityPolicy(weights=weights)


def test_identity_version_conflict_is_manual_and_not_rewritten():
    doc = rich_document()
    doc["components"][0]["purl"] = "pkg:generic/alpha@2"
    result = score(doc)
    issue = next(f for f in result.findings if f.code == "QUALITY_ID_VERSION_CONFLICT")
    assert not issue.repairable and doc["components"][0]["version"] == "1"


def test_findings_cap_does_not_change_dimension_scores():
    doc = rich_document()
    doc.pop("metadata")
    doc["dependencies"] = []
    doc["components"] *= 100
    small = score(doc, policy=QualityPolicy(max_findings=1))
    large = score(doc, policy=QualityPolicy(max_findings=500))
    assert small.overall_score == large.overall_score
    assert small.findings_truncated
    assert [d.score for d in small.dimensions] == [d.score for d in large.dimensions]


def test_no_security_severity_or_vulnerability_data_affects_score():
    doc = rich_document()
    a = score(doc)
    doc["vulnerabilities"] = [{"id": "CVE-2026-12345", "ratings": [{"severity": "critical"}]}]
    b = score(doc)
    assert a.overall_score == b.overall_score


@pytest.mark.parametrize("version", ["1.4", "1.5", "1.6"])
def test_rule_registry_declares_actual_supported_versions(version):
    from app.services.sbom.repair.registry import default_rules

    doc = rich_document(version)
    for rule in default_rules():
        assert rule.supports(doc)
        metadata = rule.metadata()
        assert version in metadata["supported_versions"]
        assert metadata["safe"] and metadata["quality_dimensions"]
        assert not rule.supports({**doc, "specVersion": "1.3"})


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:PyPI/Requests@2.31.0?b=2&a=1",
        "pkg:generic/alpha@1?b=two&a=one#./src//lib",
        "pkg:generic/%61lpha@1",
    ],
)
def test_purl_canonicalization_is_safe_idempotent_and_quality_linked(purl):
    from app.services.sbom.quality.inspection import canonical_purl
    from app.services.sbom.repair.engine import RepairEngine

    doc = rich_document()
    doc["components"][0]["purl"] = purl
    raw = json.dumps(doc).encode()
    result = RepairEngine().run(raw)
    assert json.loads(result.candidate)["components"][0]["purl"] == canonical_purl(purl)
    assert RepairEngine().run(result.candidate).candidate == result.candidate
    assert doc["components"][0]["purl"] == purl
    before, after = QualityEngine().calculate(raw), QualityEngine().calculate(result.candidate)
    assert dimension(after, "QD-02").score > dimension(before, "QD-02").score
    assert dimension(after, "QD-07").score == dimension(before, "QD-07").score
    assert dimension(after, "QD-08").score == dimension(before, "QD-08").score


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:generic/alpha@1?a=1&A=2",
        "pkg:generic/alpha@1#../src",
        "pkg:generic/al%zzpha@1",
        "pkg:generic/al%FFpha@1",
        "pkg:generic/alpha@1?a=",
    ],
)
def test_lossy_or_ambiguous_purls_remain_manual(purl):
    from app.services.sbom.quality.inspection import canonical_purl
    from app.services.sbom.repair.engine import RepairEngine

    assert canonical_purl(purl) is None
    doc = rich_document()
    doc["components"][0]["purl"] = purl
    raw = json.dumps(doc).encode()
    assert RepairEngine().run(raw).candidate == raw


def test_cpe_normalization_only_trims_known_valid_identity_and_is_idempotent():
    from app.services.sbom.repair.engine import RepairEngine

    doc = rich_document()
    cpe = doc["metadata"]["component"]["cpe"]
    doc["metadata"]["component"]["cpe"] = " " + cpe + " "
    result = RepairEngine().run(json.dumps(doc).encode())
    assert json.loads(result.candidate)["metadata"]["component"]["cpe"] == cpe
    assert RepairEngine().run(result.candidate).candidate == result.candidate


def test_graph_cleanup_preserves_other_edges_and_is_idempotent():
    from app.services.sbom.repair.engine import RepairEngine

    doc = rich_document()
    doc["dependencies"] = [
        {"ref": "product", "dependsOn": ["product", "alpha", "alpha"]},
        {"ref": "product", "dependsOn": []},
    ]
    result = RepairEngine().run(json.dumps(doc).encode())
    assert json.loads(result.candidate)["dependencies"] == [{"ref": "product", "dependsOn": ["alpha"]}]
    assert result.report["validation_status"] == "PASSED"
    assert RepairEngine().run(result.candidate).candidate == result.candidate


def test_canonical_dangling_match_is_unambiguous_or_left_manual():
    from app.services.sbom.repair.engine import RepairEngine

    doc = rich_document()
    doc["components"][0]["purl"] = "pkg:pypi/alpha@1"
    doc["dependencies"][0]["dependsOn"] = ["pkg:PyPI/Alpha@1"]
    result = RepairEngine().run(json.dumps(doc).encode())
    assert json.loads(result.candidate)["dependencies"][0]["dependsOn"] == ["alpha"]
    doc["components"].append({**doc["components"][0], "bom-ref": "other"})
    raw = json.dumps(doc).encode()
    result = RepairEngine().run(raw)
    assert result.candidate == raw
    assert result.report["analysis"]["suggested"] > 0


def test_signed_quality_is_advisory_and_normalization_is_never_offered():
    from app.services.sbom.repair.engine import RepairEngine

    doc = rich_document()
    doc["components"][0]["purl"] = "pkg:generic/%61lpha@1"
    doc["signature"] = {"algorithm": "RS256", "value": "abc"}
    raw = json.dumps(doc).encode()
    assessment = QualityEngine().calculate(raw)
    assert assessment.supported
    assert not any(f.repairable for f in assessment.findings)
    assert RepairEngine().run(raw).candidate == raw


def test_assessment_range_and_policy_version_prevent_invalid_comparisons():
    from app.services.sbom.quality.engine import comparison

    a = score(rich_document()).model_dump(mode="json")
    assert 0 <= a["overall_score"] <= 100
    assert all(0 <= d["score"] <= 100 for d in a["dimensions"])
    b = {**a, "configuration_hash": "changed"}
    assert comparison(a, b)["improvement"] is None
    assert comparison(a, {**a, "spec_version": "1.4"})["improvement"] is None


def test_ambiguous_json_keys_are_never_scored_as_authoritative():
    raw = b'{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"version":2}'
    result = QualityEngine().calculate(raw)
    assert not result.supported and result.grade == "NOT_ASSESSED"


def test_large_quality_fixture_uses_all_components_without_truncating_score():
    doc = rich_document()
    base = doc["components"][0]
    doc["components"] = [
        {**base, "name": f"package-{i}", "bom-ref": f"c-{i}", "purl": f"pkg:generic/package-{i}@1"} for i in range(1000)
    ]
    doc["dependencies"] = [{"ref": "product", "dependsOn": ["c-0"]}] + [
        {"ref": f"c-{i}", "dependsOn": [f"c-{i + 1}"] if i < 999 else []} for i in range(1000)
    ]
    result = score(doc)
    assert result.overall_score == 100
    assert dimension(result, "QD-05").metrics["eligible"] == 1001
    assert result.validation_status == "PASSED"


def test_literal_cpe_version_conflict_is_manual_and_invalid_reference_lowers_integrity():
    doc = rich_document()
    doc["metadata"]["component"]["cpe"] = "cpe:2.3:a:producer:product:2:*:*:*:*:*:*:*"
    doc["components"][0]["bom-ref"] = 42
    result = score(doc)
    conflicts = [
        f for f in result.findings if f.code in {"QUALITY_ID_CPE_VERSION_CONFLICT", "QUALITY_ID_BOM_REF_INVALID"}
    ]
    assert len(conflicts) == 2 and all(not f.repairable for f in conflicts)
    assert dimension(result, "QD-02").score < 100


def test_empty_inventory_is_not_presented_as_complete_or_rejected_by_quality():
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
    result = score(doc)
    assert result.validation_status == "PASSED"
    assert dimension(result, "QD-04").score == 0
    assert any(f.code == "QUALITY_COMPONENT_INVENTORY_EMPTY" and not f.repairable for f in result.findings)


def test_limited_nonblocking_report_does_not_make_advisory_quality_validation_fail():
    from app.validation.errors import ErrorReport

    report = ErrorReport()
    report.truncated = True
    assessment = QualityEngine().calculate(json.dumps(rich_document()).encode(), report)
    assert assessment.validation_status == "PASSED" and assessment.validation_report_truncated


@pytest.mark.parametrize(
    "field,canonical,alias",
    [
        ("purl", "pkg:pypi/alpha@1", "pkg:PyPI/Alpha@1"),
        ("cpe", "cpe:2.3:a:producer:alpha:1:*:*:*:*:*:*:*", " cpe:2.3:a:producer:alpha:1:*:*:*:*:*:*:* "),
    ],
)
def test_exact_identifier_does_not_choose_between_canonical_alias_declarations(field, canonical, alias):
    from app.services.sbom.repair.engine import RepairEngine
    from app.services.sbom.repair.rules.dangling_dependency_ref import DanglingDependencyRefRule

    doc = rich_document()
    doc["components"][0][field] = canonical
    doc["components"].append({**doc["components"][0], "bom-ref": "other", field: alias})
    doc["dependencies"][0]["dependsOn"] = [canonical]
    issue = {"code": "SBOM_VAL_E070_DEPENDENCY_REF_DANGLING", "path": "/dependencies/0/dependsOn/0"}
    rule = DanglingDependencyRefRule()
    assert len(rule.matches(doc, issue)) == 2 and rule.propose(doc, issue) is None
    result = RepairEngine().run(json.dumps(doc).encode())
    assert json.loads(result.candidate)["dependencies"][0]["dependsOn"] == [canonical]
    assert result.report["validation_status"] == "FAILED"
