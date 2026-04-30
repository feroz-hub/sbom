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
