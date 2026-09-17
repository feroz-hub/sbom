"""Unit tests for stage 5 — cross-reference integrity (Tarjan SCC + dangling)."""

from __future__ import annotations

from app.validation import errors as E
from app.validation.context import ValidationContext
from app.validation.models import (
    Component,
    DependencyEdge,
    DocumentMetadata,
    InternalSbom,
)
from app.validation.normalize import normalize_cyclonedx
from app.validation.stages import integrity


def _ctx(model: InternalSbom) -> ValidationContext:
    return ValidationContext(raw_bytes=b"", internal_model=model)


def _component(ref: str) -> Component:
    return Component(ref=ref, name=ref, version="1.0.0", raw_path=f"components[{ref}]")


def test_dangling_dependency_rejected_for_cyclonedx() -> None:
    model = InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        components=[_component("a")],
        dependencies=[DependencyEdge(source="a", target="missing")],
        declared_refs={"a"},
    )
    ctx = integrity.run(_ctx(model))
    assert E.E070_DEPENDENCY_REF_DANGLING in [e.code for e in ctx.report.errors]


def test_dangling_relationship_rejected_for_spdx() -> None:
    model = InternalSbom(
        spec="spdx",
        spec_version="SPDX-2.3",
        metadata=DocumentMetadata(),
        components=[_component("SPDXRef-A")],
        dependencies=[DependencyEdge(source="SPDXRef-A", target="SPDXRef-Missing")],
        declared_refs={"SPDXRef-A"},
    )
    ctx = integrity.run(_ctx(model))
    assert E.E072_RELATIONSHIP_ELEMENT_DANGLING in [e.code for e in ctx.report.errors]


def test_documentref_pseudo_targets_accepted_for_spdx() -> None:
    model = InternalSbom(
        spec="spdx",
        spec_version="SPDX-2.3",
        metadata=DocumentMetadata(),
        components=[_component("SPDXRef-A")],
        dependencies=[DependencyEdge(source="SPDXRef-A", target="DocumentRef-other")],
        declared_refs={"SPDXRef-A"},
    )
    ctx = integrity.run(_ctx(model))
    assert E.E072_RELATIONSHIP_ELEMENT_DANGLING not in [e.code for e in ctx.report.errors]


def test_self_edge_rejected() -> None:
    model = InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        components=[_component("a")],
        dependencies=[DependencyEdge(source="a", target="a")],
        declared_refs={"a"},
    )
    ctx = integrity.run(_ctx(model))
    assert E.E071_DEPENDENCY_REF_SELF in [e.code for e in ctx.report.errors]


def test_three_node_cycle_warned() -> None:
    model = InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        components=[_component("a"), _component("b"), _component("c")],
        dependencies=[
            DependencyEdge(source="a", target="b"),
            DependencyEdge(source="b", target="c"),
            DependencyEdge(source="c", target="a"),
        ],
        declared_refs={"a", "b", "c"},
    )
    ctx = integrity.run(_ctx(model))
    codes = [e.code for e in ctx.report.warnings]
    assert E.W074_DEPENDENCY_CYCLE_DETECTED in codes
    # NB: cycles are warnings, not errors.
    assert not ctx.report.has_errors()


def test_orphan_emitted_as_info() -> None:
    model = InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        components=[_component("a"), _component("b")],
        dependencies=[],
        declared_refs={"a", "b"},
    )
    ctx = integrity.run(_ctx(model))
    info_codes = [e.code for e in ctx.report.info]
    assert info_codes.count(E.I075_ORPHAN_COMPONENT) == 2


# ---------------------------------------------------------------------------
# Regression: the BOM root component as dependency-graph root, and accurate
# error paths for one-to-many dependency entries.
# ---------------------------------------------------------------------------


def test_root_component_as_graph_root_is_not_dangling() -> None:
    """End-to-end over normalize → integrity: the real-world shape that broke.

    ``metadata.component.bom-ref`` used to be absent from ``declared_refs``, so
    every generator that roots the graph at the BOM's own component got one
    E070 per dependsOn target.
    """
    from app.validation.normalize import normalize_cyclonedx

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "device", "bom-ref": "root-device", "name": "gw"}},
        "components": [
            {"type": "library", "bom-ref": "lib-a", "name": "a", "version": "1"},
            {"type": "library", "bom-ref": "lib-b", "name": "b", "version": "1"},
        ],
        "dependencies": [
            {"ref": "root-device", "dependsOn": ["lib-a", "lib-b"]},
            {"ref": "lib-a", "dependsOn": ["lib-b"]},
            {"ref": "lib-b", "dependsOn": []},
        ],
    }
    ctx = integrity.run(_ctx(normalize_cyclonedx(doc, "1.5")))
    assert [e.code for e in ctx.report.errors] == []


def test_dangling_source_reported_once_with_source_document_path() -> None:
    """A fan-out entry with a bad ``ref`` is one defect, so it reports once.

    The path must point at the source document's entry index, not at the index
    of the flattened edge.
    """
    model = InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        components=[_component("a"), _component("b")],
        dependencies=[
            DependencyEdge(
                source="ghost",
                target=t,
                source_path="dependencies[3].ref",
                target_path=f"dependencies[3].dependsOn[{i}]",
            )
            for i, t in enumerate(("a", "b"))
        ],
        declared_refs={"a", "b"},
    )
    ctx = integrity.run(_ctx(model))
    dangling = [e for e in ctx.report.errors if e.code == E.E070_DEPENDENCY_REF_DANGLING]
    assert len(dangling) == 1
    assert dangling[0].path == "dependencies[3].ref"


def test_dangling_target_reported_per_target_with_indexed_path() -> None:
    """Distinct bad *targets* are distinct defects and each gets its own path."""
    model = InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        components=[_component("a")],
        dependencies=[
            DependencyEdge(
                source="a",
                target=t,
                source_path="dependencies[0].ref",
                target_path=f"dependencies[0].dependsOn[{i}]",
            )
            for i, t in enumerate(("ghost-1", "ghost-2"))
        ],
        declared_refs={"a"},
    )
    ctx = integrity.run(_ctx(model))
    paths = sorted(e.path for e in ctx.report.errors if e.code == E.E070_DEPENDENCY_REF_DANGLING)
    assert paths == ["dependencies[0].dependsOn[0]", "dependencies[0].dependsOn[1]"]


def test_dangling_still_detected_without_recorded_paths() -> None:
    """Edges built without path metadata keep the old fallback path shape."""
    model = InternalSbom(
        spec="cyclonedx",
        spec_version="1.6",
        metadata=DocumentMetadata(),
        components=[_component("a")],
        dependencies=[DependencyEdge(source="a", target="missing")],
        declared_refs={"a"},
    )
    ctx = integrity.run(_ctx(model))
    dangling = [e for e in ctx.report.errors if e.code == E.E070_DEPENDENCY_REF_DANGLING]
    assert len(dangling) == 1
    assert dangling[0].path == "dependencies[0].dependsOn"


def _cyclonedx_doc() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"type": "application", "bom-ref": "root-app", "name": "Root App", "version": "1.0.0"}
        },
        "components": [{"type": "library", "bom-ref": "lib-a", "name": "Library A", "version": "1.0.0"}],
        "dependencies": [{"ref": "root-app", "dependsOn": ["lib-a"]}],
    }


def _run_cyclonedx(doc: dict) -> ValidationContext:
    return integrity.run(_ctx(normalize_cyclonedx(doc, doc["specVersion"])))


def _dangling(ctx: ValidationContext) -> list:
    return [entry for entry in ctx.report.errors if entry.code == E.E070_DEPENDENCY_REF_DANGLING]


def test_metadata_subject_as_dependency_root_passes_stage_five() -> None:
    assert _dangling(_run_cyclonedx(_cyclonedx_doc())) == []


def test_dangling_dependency_node_with_no_edges_has_its_own_path() -> None:
    doc = _cyclonedx_doc()
    doc["dependencies"] = [{"ref": "does-not-exist", "dependsOn": []}]
    errors = _dangling(_run_cyclonedx(doc))
    assert [(error.path, error.message) for error in errors] == [
        ("dependencies[0].ref", "dependencies ref 'does-not-exist' does not match any declared bom-ref.")
    ]
    assert errors[0].spec_reference == "CycloneDX 1.5 §6"


def test_dangling_dependson_target_uses_edge_path_only() -> None:
    doc = _cyclonedx_doc()
    doc["dependencies"] = [{"ref": "root-app", "dependsOn": ["lib-a", "missing-lib"]}]
    errors = _dangling(_run_cyclonedx(doc))
    assert [(error.path, "missing-lib" in error.message) for error in errors] == [
        ("dependencies[0].dependsOn[1]", True)
    ]


def test_dependency_node_indexes_use_each_entries_own_ref() -> None:
    doc = _cyclonedx_doc()
    doc["components"].append({"type": "library", "bom-ref": "valid-a", "name": "Valid A"})
    doc["dependencies"] = [
        {"ref": "valid-a", "dependsOn": []},
        {"ref": "missing-b", "dependsOn": []},
        {"ref": "missing-c", "dependsOn": []},
    ]
    errors = _dangling(_run_cyclonedx(doc))
    assert [(error.path, error.message) for error in errors] == [
        ("dependencies[1].ref", "dependencies ref 'missing-b' does not match any declared bom-ref."),
        ("dependencies[2].ref", "dependencies ref 'missing-c' does not match any declared bom-ref."),
    ]


def test_nested_component_and_service_refs_resolve() -> None:
    doc = _cyclonedx_doc()
    doc["components"] = [
        {
            "type": "application",
            "bom-ref": "parent",
            "name": "Parent",
            "components": [{"type": "library", "bom-ref": "nested-lib", "name": "Nested"}],
        }
    ]
    doc["services"] = [
        {
            "bom-ref": "service-api",
            "name": "API Service",
            "services": [{"bom-ref": "service-child", "name": "Child Service"}],
        }
    ]
    doc["dependencies"] = [{"ref": "root-app", "dependsOn": ["nested-lib", "service-api", "service-child"]}]
    assert _dangling(_run_cyclonedx(doc)) == []


def test_real_device_subject_and_all_dependency_targets_resolve() -> None:
    doc = _cyclonedx_doc()
    refs = [
        "hw-mcu-stm32f407",
        "hw-flash-w25q128",
        "hw-wifi-esp32",
        "hw-sensor-bme280",
        "hw-sensor-lsm6dso",
        "fw-bootloader-mcuboot",
        "os-freertos-kernel",
        "app-gateway-firmware",
    ]
    doc["metadata"]["component"]["bom-ref"] = "device-securenode-gw100"
    doc["components"] = [{"type": "library", "bom-ref": ref, "name": ref, "version": "1.0.0"} for ref in refs]
    doc["dependencies"] = [{"ref": "device-securenode-gw100", "dependsOn": refs}]
    assert _dangling(_run_cyclonedx(doc)) == []


def test_missing_and_empty_dependencies_do_not_emit_dangling_errors() -> None:
    doc = _cyclonedx_doc()
    del doc["dependencies"]
    assert _dangling(_run_cyclonedx(doc)) == []
    doc["dependencies"] = []
    assert _dangling(_run_cyclonedx(doc)) == []


def test_malformed_dependency_entries_do_not_create_false_edges() -> None:
    doc = _cyclonedx_doc()
    doc["dependencies"] = [None, {"ref": 42, "dependsOn": ["lib-a"]}, {"ref": "root-app", "dependsOn": "lib-a"}]
    ctx = _run_cyclonedx(doc)
    assert _dangling(ctx) == []
    assert ctx.internal_model.dependencies == []


def test_declared_refs_work_for_supported_cyclonedx_versions() -> None:
    for version in ("1.4", "1.5", "1.6"):
        doc = _cyclonedx_doc()
        doc["specVersion"] = version
        assert _dangling(_run_cyclonedx(doc)) == []


def test_spdx_document_ref_is_not_implicitly_declared_in_cyclonedx() -> None:
    doc = _cyclonedx_doc()
    doc["dependencies"] = [{"ref": "SPDXRef-DOCUMENT", "dependsOn": []}]
    errors = _dangling(_run_cyclonedx(doc))
    assert [error.path for error in errors] == ["dependencies[0].ref"]
