"""Stage 5 — cross-reference integrity.

Operates on :class:`InternalSbom` produced by stage 4. Three checks:

* **Dangling refs** — every dependency / relationship target must resolve to
  a declared component or to a valid ``DocumentRef-…`` (SPDX). Unresolved
  refs are hard errors.
* **Self-edges** — ``A → A`` is never legitimate; emit
  :data:`E071_DEPENDENCY_REF_SELF`.
* **Cycles** — Tarjan SCCs of size > 1 (or singleton SCCs with a self-edge,
  which we already caught above). Emitted as :data:`W074_DEPENDENCY_CYCLE_DETECTED`
  warnings — *real BOMs frequently have cycles*, especially in JS / Rust.
* **Orphans** — components with neither inbound nor outbound edges. Emitted
  as :data:`I075_ORPHAN_COMPONENT` (info level, never blocks).

Algorithm: iterative Tarjan, no recursion (we run on the JSON-pinned 1e6
component limit and stack depth is real).
"""

from __future__ import annotations

from collections import defaultdict

from .. import errors as E
from ..context import ValidationContext

_STAGE = "integrity"


def run(ctx: ValidationContext) -> ValidationContext:
    sbom = ctx.internal_model
    if sbom is None:
        return ctx

    declared = sbom.declared_refs | sbom.document_refs | {"SPDXRef-DOCUMENT"}

    edges_by_source: dict[str, list[str]] = defaultdict(list)
    for index, dep in enumerate(sbom.dependencies):
        if dep.source == dep.target:
            ctx.report.add(
                E.E071_DEPENDENCY_REF_SELF,
                stage=_STAGE,
                path=f"dependencies[{index}]",
                message=f"Dependency entry '{dep.source}' depends on itself.",
                remediation="Self-edges are never legitimate. Remove the entry.",
                spec_reference="CycloneDX 1.6 §6",
            )
        if dep.source not in declared:
            _emit_dangling(ctx, sbom.spec, f"dependencies[{index}].ref", dep.source)
        if dep.target not in declared:
            _emit_dangling(ctx, sbom.spec, f"dependencies[{index}].dependsOn", dep.target)
        edges_by_source[dep.source].append(dep.target)

    cycles = _tarjan_scc(declared, edges_by_source)
    for cycle in cycles:
        if len(cycle) <= 1:
            continue  # singletons (without self-edge) are not cycles
        ctx.report.add(
            E.W074_DEPENDENCY_CYCLE_DETECTED,
            stage=_STAGE,
            path="dependencies",
            message=f"Dependency cycle detected: {' -> '.join(cycle)} -> {cycle[0]}.",
            remediation=(
                "Cycles are common in real BOMs and are reported for visibility, "
                "not rejected."
            ),
        )

    inbound: dict[str, int] = defaultdict(int)
    outbound: dict[str, int] = defaultdict(int)
    for dep in sbom.dependencies:
        outbound[dep.source] += 1
        inbound[dep.target] += 1

    for comp in sbom.components:
        if inbound[comp.ref] == 0 and outbound[comp.ref] == 0:
            ctx.report.add(
                E.I075_ORPHAN_COMPONENT,
                stage=_STAGE,
                path=comp.raw_path,
                message=f"Component '{comp.ref}' has no inbound or outbound dependency edges.",
                remediation=(
                    "Informational. Consider declaring the relationship that "
                    "brought this component in."
                ),
            )
    return ctx


def _emit_dangling(ctx: ValidationContext, spec: str, path: str, ref: str) -> None:
    if spec == "spdx":
        if ref.startswith("DocumentRef-"):
            return  # documentRefs are valid by spec, even if not declared in this doc
        ctx.report.add(
            E.E072_RELATIONSHIP_ELEMENT_DANGLING,
            stage=_STAGE,
            path=path,
            message=f"Relationship references SPDXID '{ref}' that is not declared.",
            remediation="Declare the element, or use a valid DocumentRef-* form.",
            spec_reference="SPDX 2.3 §11",
        )
    else:
        ctx.report.add(
            E.E070_DEPENDENCY_REF_DANGLING,
            stage=_STAGE,
            path=path,
            message=f"dependencies ref '{ref}' does not match any declared bom-ref.",
            remediation="Either declare a component with that bom-ref, or remove the dependency entry.",
            spec_reference="CycloneDX 1.6 §6",
        )


def _tarjan_scc(nodes: set[str], edges: dict[str, list[str]]) -> list[list[str]]:
    """Iterative Tarjan SCC. Returns SCCs in reverse topological order."""
    index_counter = [0]
    stack: list[str] = []
    on_stack: dict[str, bool] = {}
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    result: list[list[str]] = []

    # Iterative implementation to avoid Python recursion-limit pitfalls on
    # large dependency graphs.
    for start in nodes:
        if start in indices:
            continue

        # Each work item is (node, edge_iterator). The iterator is materialised
        # eagerly so successive pops resume where the previous one left off.
        work: list[tuple[str, list[str]]] = [(start, list(edges.get(start, [])))]
        indices[start] = index_counter[0]
        lowlinks[start] = index_counter[0]
        index_counter[0] += 1
        stack.append(start)
        on_stack[start] = True

        while work:
            node, remaining = work[-1]
            if remaining:
                target = remaining.pop(0)
                if target not in indices:
                    indices[target] = index_counter[0]
                    lowlinks[target] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(target)
                    on_stack[target] = True
                    work.append((target, list(edges.get(target, []))))
                elif on_stack.get(target):
                    lowlinks[node] = min(lowlinks[node], indices[target])
                # else: already-explored cross-edge, skip
                continue

            # finished node — propagate lowlink upward and possibly emit SCC
            work.pop()
            if work:
                parent, _ = work[-1]
                lowlinks[parent] = min(lowlinks[parent], lowlinks[node])
            if lowlinks[node] == indices[node]:
                scc: list[str] = []
                while True:
                    popped = stack.pop()
                    on_stack[popped] = False
                    scc.append(popped)
                    if popped == node:
                        break
                if len(scc) > 1:
                    result.append(scc)
    return result
