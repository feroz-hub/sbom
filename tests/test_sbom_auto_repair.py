"""Deterministic repair uses real vendored schemas and the full validator."""

import copy
import json

import pytest
from app.services.sbom.repair.engine import RepairEngine
from app.services.sbom.repair.policy import RepairPolicy
from app.validation import run as validate


def document():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "bom-ref": "a", "name": "alpha", "version": "1.0"},
            {"type": "library", "bom-ref": "b", "name": "beta", "version": "2.0", "purl": "pkg:npm/beta@2.0"},
        ],
        "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
    }

def repair(doc, **kwargs):
    original = json.dumps(doc).encode()
    before = copy.deepcopy(doc)
    result = RepairEngine(**kwargs).run(original)
    assert doc == before
    return result

def test_valid_is_unchanged_and_not_required():
    doc = document()
    result = repair(doc)
    assert result.candidate == json.dumps(doc).encode()
    assert result.report["status"] == "NOT_REQUIRED"

def test_unreferenced_duplicate_gets_stable_unique_id():
    doc = document()
    doc["dependencies"] = []
    doc["components"][1]["bom-ref"] = "a"
    first = repair(doc)
    second = repair(doc)
    assert first.report["status"] == "REPAIRED"
    assert first.candidate == second.candidate
    candidate = json.loads(first.candidate)
    assert len({c["bom-ref"] for c in candidate["components"]}) == 2
    assert not validate(first.candidate).has_errors()
    assert RepairEngine().run(first.candidate).candidate == first.candidate

def test_identical_duplicate_with_dependencies_retains_targets():
    doc = document()
    doc["components"].append(copy.deepcopy(doc["components"][1]))
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    candidate = json.loads(result.candidate)
    assert candidate["dependencies"] == doc["dependencies"]
    assert len(candidate["components"]) == 2
    assert not validate(result.candidate).has_errors()

def test_distinct_duplicate_with_references_requires_review():
    doc = document()
    doc["components"][1]["bom-ref"] = "a"
    doc["dependencies"] = [{"ref": "a", "dependsOn": []}]
    result = repair(doc)
    assert result.report["repairs_applied"] == 0
    assert result.report["analysis"]["suggested"] == 1
    assert result.report["validation_status"] == "FAILED"

@pytest.mark.parametrize("identifier", ["pkg:npm/beta@2.0", "beta@2.0", " b "])
def test_exact_unambiguous_dangling_dependency(identifier):
    doc = document()
    doc["dependencies"][0]["dependsOn"] = [identifier]
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["dependencies"][0]["dependsOn"] == ["b"]

def test_dangling_source_node_without_edges():
    doc = document()
    doc["dependencies"] = [{"ref": "pkg:npm/beta@2.0", "dependsOn": []}]
    assert repair(doc).report["status"] == "REPAIRED"

def test_ambiguous_purl_not_automatically_fixed():
    doc = document()
    doc["components"].append(
        {"type": "library", "bom-ref": "c", "name": "beta", "version": "2.0", "purl": "pkg:npm/beta@2.0"}
    )
    doc["dependencies"][0]["dependsOn"] = ["pkg:npm/beta@2.0"]
    result = repair(doc)
    assert result.report["repairs_applied"] == 0
    assert result.report["analysis"]["suggested"] == 1

@pytest.mark.parametrize("duplicate_node", [False, True])
def test_dependency_deduplication_retains_order_and_semantics(duplicate_node):
    doc = document()
    if duplicate_node:
        doc["dependencies"].append(copy.deepcopy(doc["dependencies"][0]))
    else:
        doc["dependencies"][0]["dependsOn"] = ["b", "b"]
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["dependencies"] == document()["dependencies"]

def test_safe_enum_case_normalization_uses_exact_spec():
    doc = document()
    doc["components"][0]["type"] = " Library "
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["components"][0]["type"] == "library"

def test_partial_repair_discovers_later_errors_without_weakening_validation():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    doc["components"][1]["purl"] = "made-up-purl"
    result = repair(doc)
    assert result.report["status"] == "PARTIALLY_REPAIRED"
    assert result.report["validation_status"] == "FAILED"
    assert result.report["repairs_applied"] == 1
    assert json.loads(result.candidate)["components"][1]["purl"] == "made-up-purl"

def test_repair_that_creates_self_edge_is_rolled_back():
    doc = document()
    doc["dependencies"] = [{"ref": "b", "dependsOn": ["pkg:npm/beta@2.0"]}]
    result = repair(doc)
    assert result.report["status"] == "REPAIR_FAILED"
    assert result.candidate == json.dumps(doc).encode()
    assert result.report["rollback"]

def test_no_missing_facts_are_fabricated():
    doc = document()
    doc["components"][0].pop("version")
    result = repair(doc, policy=RepairPolicy(strict_ntia=True))
    assert result.report["validation_status"] == "FAILED"
    assert all(i["classification"] == "MANUAL_ONLY" for i in result.report["analysis"]["issues"])
    assert "version" not in json.loads(result.candidate)["components"][0]

def test_disabled_keeps_original_errors_and_content():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    result = repair(doc, policy=RepairPolicy(enabled=False))
    assert result.report["errors_before"] == result.report["errors_after"] > 0
    assert result.candidate == json.dumps(doc).encode()

def test_security_walk_runs_even_when_schema_fails():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    doc["__proto__"] = {"attack": "data"}
    result = repair(doc)
    assert result.report["repairs_applied"] == 0
    assert all(i["classification"] == "MANUAL_ONLY" for i in result.report["analysis"]["issues"])

def test_signed_document_is_never_modified():
    doc = document()
    doc["components"][0]["type"] = "LIBRARY"
    doc["signature"] = {"algorithm": "RS256", "value": "abc"}
    assert repair(doc).report["repairs_applied"] == 0

def test_maximum_passes_bound_large_repair_set():
    doc = document()
    doc["dependencies"] = []
    doc["components"] = [
        {"type": "LIBRARY", "bom-ref": str(i), "name": f"component-{i}", "version": "1"} for i in range(105)
    ]
    result = repair(doc, policy=RepairPolicy(max_passes=1))
    assert result.report["passes"] == 1
    assert result.report["repairs_applied"] <= 100
    assert result.report["status"] == "PARTIALLY_REPAIRED"

def test_duplicate_json_keys_never_lose_facts_through_serialization():
    raw = (
        json.dumps(document())
        .replace('"bom-ref": "a"', '"bom-ref": "first", "bom-ref": "a"')
        .replace('"type": "library"', '"type": "LIBRARY"', 1)
        .encode()
    )
    result = RepairEngine().run(raw)
    assert result.candidate == raw
    assert result.report["repairs_applied"] == 0

def test_byte_budget_leaves_large_document_manual_only():
    raw = json.dumps(document()).replace('"type": "library"', '"type": "LIBRARY"', 1).encode()
    result = RepairEngine(RepairPolicy(max_bytes=1)).run(raw)
    assert result.candidate == raw
    assert result.report["analysis"]["manual_only"] > 0

def test_repair_cannot_remove_unknown_reference_target():
    doc = document()
    doc["dependencies"] = []
    doc["components"][1]["bom-ref"] = "a"
    doc["properties"] = [{"name": "external-link", "value": "a"}]
    assert repair(doc).report["repairs_applied"] == 0

def test_cpe_exact_match_reuses_existing_identity():
    doc = document()
    cpe = "cpe:2.3:a:vendor:beta:2.0:*:*:*:*:*:*:*"
    doc["components"][1]["cpe"] = cpe
    doc["dependencies"][0]["dependsOn"] = [cpe]
    assert repair(doc).report["status"] == "REPAIRED"

def test_purl_surrounding_whitespace_does_not_invent_facts():
    doc = document()
    doc["components"][1]["purl"] = " pkg:npm/beta@2.0 "
    result = repair(doc)
    assert result.report["status"] == "REPAIRED"
    assert json.loads(result.candidate)["components"][1]["purl"] == "pkg:npm/beta@2.0"
