"""
Compare-result exporters: Markdown / CSV / JSON.

Pure functions — given a ``CompareResult``, return ``(content, media_type,
filename)``. No DB access, no settings reads, no I/O. Snapshot-friendly.

Markdown is the Slack/Notion-friendly format the user pastes into a
release ticket. CSV is the spreadsheet format. JSON is the machine
format (the same payload the API returns, re-serialised for download).
"""

from __future__ import annotations

import csv
import io
import json
from typing import Literal

from ..schemas_compare import (
    CompareResult,
    ComponentChangeKind,
    FindingChangeKind,
    FindingDiffRow,
)

ExportFormat = Literal["markdown", "csv", "json"]


def export(result: CompareResult, fmt: ExportFormat) -> tuple[str, str, str]:
    """Return ``(content, media_type, filename)`` for ``fmt``.

    Filename uses the run ids: ``compare_<a>_vs_<b>.<ext>``.
    """
    base = f"compare_{result.run_a.id}_vs_{result.run_b.id}"
    if fmt == "markdown":
        return _to_markdown(result), "text/markdown", f"{base}.md"
    if fmt == "csv":
        return _to_csv(result), "text/csv", f"{base}.csv"
    if fmt == "json":
        return _to_json(result), "application/json", f"{base}.json"
    raise ValueError(f"unknown export format: {fmt!r}")


# =============================================================================
# Markdown
# =============================================================================


def _to_markdown(r: CompareResult) -> str:
    lines: list[str] = []
    lines.append(f"# Compare: Run #{r.run_a.id} → Run #{r.run_b.id}")
    a_name = r.run_a.sbom_name or "(unknown SBOM)"
    b_name = r.run_b.sbom_name or "(unknown SBOM)"
    lines.append(f"_{a_name} ({r.run_a.completed_on}) → {b_name} ({r.run_b.completed_on})_")
    if r.relationship.direction_warning:
        lines.append(f"> ⚠ {r.relationship.direction_warning}")
    lines.append("")
    lines.append("## Posture")
    lines.append("")
    lines.append(
        f"- **KEV exposure**: {r.posture.kev_count_a} → {r.posture.kev_count_b} "
        f"({_signed(r.posture.kev_count_delta)})"
    )
    lines.append(
        f"- **Fix-available coverage**: {r.posture.fix_available_pct_a:.1f}% → "
        f"{r.posture.fix_available_pct_b:.1f}% "
        f"({_signed(r.posture.fix_available_pct_delta, suffix='pp')})"
    )
    lines.append(
        f"- **High+Critical exposure**: {r.posture.high_critical_count_a} → "
        f"{r.posture.high_critical_count_b} "
        f"({_signed(r.posture.high_critical_count_delta)})"
    )
    lines.append(
        f"- **Findings**: +{r.posture.findings_added_count} added, "
        f"-{r.posture.findings_resolved_count} resolved, "
        f"~{r.posture.findings_severity_changed_count} severity-changed"
    )
    lines.append("")

    resolved = [f for f in r.findings if f.change_kind == FindingChangeKind.RESOLVED]
    added = [f for f in r.findings if f.change_kind == FindingChangeKind.ADDED]
    sev_changed = [
        f for f in r.findings if f.change_kind == FindingChangeKind.SEVERITY_CHANGED
    ]

    if resolved:
        lines.append(f"## Resolved ({len(resolved)})")
        lines.append("")
        for f in resolved:
            lines.append(f"- ✓ {_finding_md_line(f)}")
        lines.append("")

    if added:
        lines.append(f"## Newly introduced ({len(added)})")
        lines.append("")
        for f in added:
            lines.append(f"- + {_finding_md_line(f)}")
        lines.append("")

    if sev_changed:
        lines.append(f"## Severity changed ({len(sev_changed)})")
        lines.append("")
        for f in sev_changed:
            sev_a = f.severity_a.value if f.severity_a else "—"
            sev_b = f.severity_b.value if f.severity_b else "—"
            lines.append(
                f"- ↑↓ `{f.vuln_id}` {sev_a} → {sev_b} "
                f"`{f.component_name}@{f.component_version_b or f.component_version_a or '?'}`"
            )
        lines.append("")

    component_events = [
        c
        for c in r.components
        if c.change_kind != ComponentChangeKind.UNCHANGED
    ]
    if component_events:
        lines.append(f"## Component changes ({len(component_events)})")
        lines.append("")
        for c in component_events:
            lines.append(f"- {_component_md_line(c)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _finding_md_line(f: FindingDiffRow) -> str:
    sev_label = (
        f.severity_b.value.upper()
        if f.change_kind == FindingChangeKind.ADDED and f.severity_b
        else (f.severity_a.value.upper() if f.severity_a else "—")
    )
    kev = ", KEV" if f.kev_current else ""
    version = f.component_version_b or f.component_version_a or "?"
    line = f"`{f.vuln_id}` ({sev_label}{kev}) — `{f.component_name}@{version}`"
    if f.attribution:
        line += f" _{f.attribution}_"
    return line


def _component_md_line(c) -> str:
    """ComponentDiffRow → markdown bullet body."""
    if c.change_kind == ComponentChangeKind.ADDED:
        return f"+ `{c.name}@{c.version_b}` _(added in B)_"
    if c.change_kind == ComponentChangeKind.REMOVED:
        return f"− `{c.name}@{c.version_a}` _(removed in B)_"
    if c.change_kind == ComponentChangeKind.VERSION_BUMPED:
        arrow = "↑" if (c.version_b or "") > (c.version_a or "") else "↓"
        return f"{arrow} `{c.name}` `{c.version_a} → {c.version_b}`"
    if c.change_kind == ComponentChangeKind.LICENSE_CHANGED:
        return f"⚠ `{c.name}` license changed: {c.license_a} → {c.license_b}"
    if c.change_kind == ComponentChangeKind.HASH_CHANGED:
        return f"🚨 `{c.name}@{c.version_a}` content hash changed (supply chain alert)"
    return f"= `{c.name}` (unchanged)"


def _signed(value: int | float, *, suffix: str = "") -> str:
    if isinstance(value, float):
        formatted = f"{value:+.1f}"
    else:
        formatted = f"{value:+d}"
    return f"{formatted}{suffix}"


# =============================================================================
# CSV
# =============================================================================


def _to_csv(r: CompareResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "section",
            "change_kind",
            "vuln_id",
            "severity_a",
            "severity_b",
            "kev_current",
            "epss_current",
            "epss_percentile_current",
            "component_name",
            "component_version_a",
            "component_version_b",
            "component_purl",
            "component_ecosystem",
            "fix_available",
            "attribution",
        ]
    )
    for f in r.findings:
        if f.change_kind == FindingChangeKind.UNCHANGED:
            continue
        writer.writerow(
            [
                "finding",
                f.change_kind.value,
                f.vuln_id,
                f.severity_a.value if f.severity_a else "",
                f.severity_b.value if f.severity_b else "",
                "true" if f.kev_current else "false",
                "" if f.epss_current is None else f"{f.epss_current:.4f}",
                ""
                if f.epss_percentile_current is None
                else f"{f.epss_percentile_current:.4f}",
                f.component_name,
                f.component_version_a or "",
                f.component_version_b or "",
                f.component_purl or "",
                f.component_ecosystem or "",
                "true" if f.fix_available else "false",
                f.attribution or "",
            ]
        )
    for c in r.components:
        if c.change_kind == ComponentChangeKind.UNCHANGED:
            continue
        writer.writerow(
            [
                "component",
                c.change_kind.value,
                "",
                "",
                "",
                "",
                "",
                "",
                c.name,
                c.version_a or "",
                c.version_b or "",
                c.purl or "",
                c.ecosystem,
                "",
                "",
            ]
        )
    return buf.getvalue()


# =============================================================================
# JSON
# =============================================================================


def _to_json(r: CompareResult) -> str:
    """Re-serialise the full payload exactly as the API returns it.

    Pretty-printed with indent=2 — files of this kind are read by humans
    when grep'd in a terminal, not just consumed by automation.
    """
    return r.model_dump_json(indent=2) + "\n"
