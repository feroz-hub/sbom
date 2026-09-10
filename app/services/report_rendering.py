"""Pure report rendering: escaped HTML, reviewable PDF, formula-safe streamed XLSX."""

import json
from html import escape
from io import BytesIO

from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

from .email_sender import EmailAttachment
from .report_composer import PART_NAMES


def _text(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return "—" if value is None else str(value)


def report_sections(report, *, compact=False):
    """One section source for all human-readable formats, including failed parts."""
    summary = report["summary"]
    yield (
        "Reporting window",
        ["Field", "Value"],
        [
            [k, report[k]]
            for k in (
                "tenant_id",
                "schema_version",
                "cycle_start",
                "cycle_end",
                "generated_at",
                "timezone",
                "scope",
                "runs_considered",
                "severity_floor",
            )
        ],
    )
    yield "Portfolio summary · Convention A", ["Metric", "Value"], [[k, v] for k, v in summary.items()]
    for part, totals in report["comparison_summary"].items():
        yield (
            f"Part {part} · Full-scope changes · Convention B per-SBOM occurrences",
            ["Metric", "Value"],
            list(totals.items()),
        )
    yield (
        "Coverage",
        ["Resolved SBOMs", "Included in detail", "Omitted by cap"],
        [[report["total_sboms"], report["included_sboms"], report["truncated_sboms"]]],
    )
    if report.get("scheduled_outcomes"):
        yield (
            "Scheduled cycle outcomes (posture uses the last successful data)",
            ["SBOM ID", "Completion status", "Run ID"],
            [[sid, outcome["status"], outcome.get("run_id")] for sid, outcome in report["scheduled_outcomes"].items()],
        )
    yield (
        "SBOM results",
        ["SBOM", "Version", "Run ID", "Successful status", "Latest attempt", "Findings"],
        [
            [
                s["name"],
                s["version"],
                s["A"]["run_id"],
                s["A"]["run_status"],
                s["A"]["latest_attempt_status"],
                s["A"]["total_findings"],
            ]
            for s in report["sboms"]
        ],
    )
    yield (
        "Top risks · KEV → EPSS → CVSS",
        ["SBOM", "Vulnerability", "Component", "Severity", "KEV", "EPSS", "CVSS"],
        [
            [
                r["sbom_name"],
                r["vuln_id"],
                r["component_name"],
                r["severity"],
                r["kev_current"],
                r["epss_current"],
                r["cvss"],
            ]
            for r in report["top_risks"]
        ],
    )
    for sbom in report["sboms"]:
        for part in report["parts"]:
            title = f"{sbom['name']} · Part {part}: {PART_NAMES[part]}"
            if part == "A":
                rows = sbom["A"]["findings"]
                if not compact:
                    yield (
                        title,
                        ["Vulnerability", "Component", "Version", "Severity", "KEV", "EPSS", "CVSS", "Fix", "VEX"],
                        [
                            [
                                r[k]
                                for k in (
                                    "vuln_id",
                                    "component_name",
                                    "component_version",
                                    "severity",
                                    "kev_current",
                                    "epss_current",
                                    "cvss",
                                    "fix_available",
                                    "vex_status",
                                )
                            ]
                            for r in rows
                        ],
                    )
                continue
            comparison = sbom["comparisons"][part]
            if comparison["status"] != "available":
                yield title, ["Status", "Explanation"], [[comparison["status"], comparison["message"]]]
                continue
            yield (
                title,
                ["Metric", "Value"],
                [
                    ["Baseline run", comparison["run_a"]["id"]],
                    ["Current run", comparison["run_b"]["id"]],
                    ["Elapsed days", comparison["relationship"]["days_between"]],
                    ["Relationship", comparison["relationship"]["classification"]],
                    *[[k, v] for k, v in comparison["posture"].items() if not isinstance(v, list)],
                ],
            )
            if compact and part == "C":
                yield (
                    title + " · Persistent finding count (all severities)",
                    ["Count"],
                    [[comparison["persistent_findings_count"]]],
                )
                yield (
                    title + " · Top persistent risks",
                    ["Vulnerability", "Component", "KEV", "First observed", "Age days"],
                    [
                        [
                            r.get(k)
                            for k in ("vuln_id", "component_name", "kev_current", "first_observed_at", "age_days")
                        ]
                        for r in comparison["persistent_findings"][:10]
                    ],
                )
            if not compact:
                yield (
                    title + " · Finding changes",
                    [
                        "Change",
                        "Vulnerability",
                        "Component",
                        "Version A",
                        "Version B",
                        "Severity A",
                        "Severity B",
                        "Attribution",
                    ],
                    [
                        [
                            r.get(k)
                            for k in (
                                "change_kind",
                                "vuln_id",
                                "component_name",
                                "component_version_a",
                                "component_version_b",
                                "severity_a",
                                "severity_b",
                                "attribution",
                            )
                        ]
                        for r in comparison["findings"]
                    ],
                )
                yield (
                    title + " · Component changes",
                    ["Change", "Component", "Version A", "Version B", "Added findings", "Resolved findings"],
                    [
                        [
                            r.get(k)
                            for k in (
                                "change_kind",
                                "name",
                                "version_a",
                                "version_b",
                                "findings_added",
                                "findings_resolved",
                            )
                        ]
                        for r in comparison["components"]
                    ],
                )
                if part == "C":
                    yield (
                        title + " · Persistent findings",
                        ["Vulnerability", "Component", "KEV", "First observed", "Age days"],
                        [
                            [
                                r.get(k)
                                for k in ("vuln_id", "component_name", "kev_current", "first_observed_at", "age_days")
                            ]
                            for r in comparison["persistent_findings"]
                        ],
                    )
    yield "Interpretation and limitations", ["Note"], [[note] for note in report["caveats"]]


# Email palette (email-client-safe inline styles only; mirrors the approved
# notification template: dark ink header, tile strip, severity pills).
_INK = "#0f2a3d"
_MUTED = "#64748b"
_BODY = "#334155"
_BORDER = "#eceff1"
_ROW_BORDER = "#f1f3f5"
_HEAD_BG = "#f8f9fb"
_RED = "#c0392b"
_RED_BG = "#fdecea"
_AMBER = "#b7791f"
_AMBER_BG = "#fdf3e3"
_GREEN = "#1a7a4c"


def _e(value):
    return escape(_text(value))


def _email_section(title):
    return f"<div style='font-size:15px; font-weight:600; color:#1a1a1a; margin:0 0 10px 0;'>{escape(title)}</div>"


def _email_table(columns, rows):
    """Template-style table: header row on light grey, hairline row borders.

    ``rows`` cells are already-safe HTML fragments (escape data before calling).
    """
    head = "".join(
        f"<td style='padding:8px 8px; color:{_MUTED}; font-weight:600; border-bottom:1px solid {_BORDER};'>{escape(c)}</td>"
        for c in columns
    )
    body = "".join(
        "<tr>"
        + "".join(
            f"<td style='padding:9px 8px; border-bottom:1px solid {_ROW_BORDER}; color:{_BODY}; vertical-align:top;'>{cell}</td>"
            for cell in row
        )
        + "</tr>"
        for row in rows
    )
    return (
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        "style='font-size:12.5px; border-collapse:collapse;'>"
        f"<tr style='background-color:{_HEAD_BG};'>{head}</tr>{body}</table>"
    )


def _severity_pill(severity, cvss=None):
    palette = {
        "CRITICAL": (_RED_BG, _RED, "CRIT"),
        "HIGH": (_AMBER_BG, _AMBER, "HIGH"),
        "MEDIUM": (_AMBER_BG, _AMBER, "MED"),
        "LOW": ("#eef1f4", _MUTED, "LOW"),
    }
    background, color, label = palette.get(severity or "", ("#eef1f4", _MUTED, escape(_text(severity)).upper()))
    prefix = f"{_e(cvss)} " if cvss not in (None, "", "—") else ""
    return (
        f"<span style='background-color:{background}; color:{color}; padding:2px 7px; "
        f"border-radius:10px; font-weight:600; white-space:nowrap;'>{prefix}{label}</span>"
    )


def _tile(value, label, color):
    return (
        f"<td align='center' style='padding:14px 4px; border-right:1px solid {_BORDER};'>"
        f"<div style='font-size:22px; font-weight:700; color:{color};'>{value}</div>"
        f"<div style='font-size:10.5px; color:{_MUTED}; margin-top:2px;'>{escape(label)}</div></td>"
    )


def _block(inner, *, padding="20px 36px 4px 36px"):
    return f"<tr><td style='padding:{padding};'>{inner}</td></tr>"


def _comparison_part(report):
    """First requested comparison part that has at least one usable baseline."""
    for part in ("B", "C", "D"):
        totals = report.get("comparison_summary", {}).get(part)
        if totals and totals.get("available_baselines"):
            return part, totals
    return None, None


def render_email(report, *, links=(), omitted=()):
    subject = f"SBOM security digest · {report['scope']} · {report['cycle_end'][:10]}"
    # The plain-text part carries the complete compact digest; the HTML part is
    # the executive template (full detail travels in the PDF/XLSX/JSON artifacts).
    text = [subject]
    for title, columns, rows in report_sections(report, compact=True):
        text.extend(["", title, " | ".join(columns)])
        text.extend(" | ".join(_text(v) for v in row) for row in rows)
    text.extend(omitted)
    text.extend(f"{label}: {url}" for label, url in links)

    summary = report["summary"]
    severity = summary.get("severity", {})
    part, totals = _comparison_part(report)
    generated = f"{_e(report['generated_at'][:16]).replace('T', ' · ')} UTC"

    html = [
        "<html><body style='margin:0; padding:0; background-color:#eef1f4; "
        "font-family:\"Segoe UI\", Arial, sans-serif;'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
        "style='background-color:#eef1f4; padding:32px 0;'><tr><td align='center'>",
        "<table role='presentation' width='680' cellpadding='0' cellspacing='0' "
        "style='background-color:#ffffff; border-radius:8px; overflow:hidden;'>",
        # Header
        f"<tr><td style='background-color:{_INK}; padding:28px 36px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0'><tr>"
        "<td style='color:#ffffff; font-size:13px; letter-spacing:0.3px; font-weight:600;'>"
        "SBOM ANALYSIS REPORT</td>"
        f"<td align='right' style='color:#9fb8c8; font-size:12px;'>Generated {generated}</td>"
        "</tr></table>"
        f"<div style='color:#ffffff; font-size:22px; font-weight:600; margin-top:10px;'>"
        f"{_e(report['scope'])} scope &nbsp;&mdash;&nbsp; security posture</div>"
        f"<div style='color:#9fb8c8; font-size:13px; margin-top:4px;'>"
        f"Cycle {_e(report['cycle_start'][:10])} &rarr; {_e(report['cycle_end'][:10])} &middot; "
        f"{_e(report['runs_considered'])} runs considered &middot; severity floor {_e(report['severity_floor'])}</div>"
        "</td></tr>",
    ]

    if part is None:
        html.append(
            _block(
                "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
                "style='font-size:12.5px; background-color:#eef4fb; border-radius:6px;'>"
                "<tr><td style='padding:10px 14px; color:#1e4d78;'>"
                "No earlier successful run is available to compare against, so this digest shows the "
                "complete security baseline instead of a delta.</td></tr></table>",
                padding="16px 36px 0 36px",
            )
        )
    elif report.get("unchanged"):
        html.append(
            _block(
                "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
                "style='font-size:12.5px; background-color:#e8f5ee; border-radius:6px;'>"
                f"<tr><td style='padding:10px 14px; color:{_GREEN};'>"
                "No security-relevant changes were detected since the previous cycle.</td></tr></table>",
                padding="16px 36px 0 36px",
            )
        )

    # Summary tile strip
    critical_high = severity.get("CRITICAL", 0) + severity.get("HIGH", 0)
    tiles = []
    if totals:
        added, resolved = totals.get("findings_added_count"), totals.get("findings_resolved_count")
        tiles.append(_tile(f"+{_e(added)}", "NEW FINDINGS", _RED if added else _INK))
        tiles.append(_tile(f"&minus;{_e(resolved)}", "FINDINGS RESOLVED", _GREEN if resolved else _INK))
    else:
        tiles.append(_tile(_e(summary.get("total_sboms")), "SBOMS IN SCOPE", _INK))
        tiles.append(_tile(_e(summary.get("total_findings")), "TOTAL FINDINGS", _INK))
    tiles.append(_tile(_e(summary.get("total_components")), "TOTAL COMPONENTS", _INK))
    tiles.append(_tile(_e(critical_high), "CRITICAL/HIGH", _RED if critical_high else _INK))
    kev = summary.get("kev_findings", 0)
    tiles.append(_tile(_e(kev), "KEV FINDINGS", _RED if kev else _INK))
    html.append(
        _block(
            "<table role='presentation' width='100%' cellpadding='0' cellspacing='0'><tr>"
            + "".join(tiles)
            + "</tr></table>",
            padding="22px 36px 8px 36px",
        )
    )
    html.append(f"<tr><td style='padding:8px 36px;'><hr style='border:none; border-top:1px solid {_BORDER};'></td></tr>")

    # Change summary per comparison part
    change_rows = []
    for name, values in report.get("comparison_summary", {}).items():
        change_rows.append(
            [
                f"<strong>Part {escape(name)}</strong> &middot; {escape(PART_NAMES.get(name, ''))}",
                f"<span style='color:{_RED if values.get('findings_added_count') else _BODY};'>+{_e(values.get('findings_added_count'))}</span>",
                f"<span style='color:{_GREEN if values.get('findings_resolved_count') else _BODY};'>&minus;{_e(values.get('findings_resolved_count'))}</span>",
                _e(values.get("findings_severity_changed_count")),
                f"+{_e(values.get('components_added_count'))} / &minus;{_e(values.get('components_removed_count'))} / "
                f"~{_e(values.get('components_version_bumped_count'))}",
                f"{_e(values.get('available_baselines'))} of {_e(values.get('sboms_considered'))}",
            ]
        )
    if change_rows:
        html.append(
            _block(
                _email_section("Changes by comparison part")
                + _email_table(
                    ["Part", "Added", "Resolved", "Severity changed", "Components + / − / bumped", "Baselines"],
                    change_rows,
                ),
                padding="12px 36px 4px 36px",
            )
        )

    # Top risks
    if report.get("top_risks"):
        risk_rows = [
            [
                _e(r.get("sbom_name")),
                f"{_e(r.get('vuln_id'))}",
                f"{_e(r.get('component_name'))}",
                _severity_pill(r.get("severity"), r.get("cvss")),
                f"<span style='color:{_RED};'>Known exploited (CISA KEV)</span>" if r.get("kev_current") else "—",
                _e(r.get("epss_current")),
                _e(r.get("fix_available")),
            ]
            for r in report["top_risks"]
        ]
        html.append(
            _block(
                _email_section("Top risks · KEV → EPSS → CVSS")
                + _email_table(
                    ["SBOM", "Vulnerability", "Component", "CVSS", "Exploit status", "EPSS", "Fix available"],
                    risk_rows,
                )
            )
        )

    # Per-SBOM results
    shown = report["sboms"][:20]
    sbom_rows = [
        [
            f"<strong>{_e(s['name'])}</strong>",
            _e(s.get("version")),
            _e(s["A"].get("run_id")),
            _e(s["A"].get("run_status")),
            _e(s["A"].get("total_findings")),
        ]
        for s in shown
    ]
    remainder = ""
    if len(report["sboms"]) > len(shown) or report.get("truncated_sboms"):
        hidden = len(report["sboms"]) - len(shown) + report.get("truncated_sboms", 0)
        remainder = (
            f"<div style='font-size:11.5px; color:#94a3b8; margin-top:8px;'>+ {hidden} more SBOMs — "
            "see the attached XLSX/JSON for the complete inventory.</div>"
        )
    html.append(
        _block(
            _email_section(f"SBOM results ({report['included_sboms']} of {report['total_sboms']} in scope)")
            + _email_table(["SBOM", "Version", "Run", "Status", "Findings"], sbom_rows)
            + remainder
        )
    )

    # Scheduled cycle outcomes
    if report.get("scheduled_outcomes"):
        outcome_rows = [
            [_e(sbom_id), _e(outcome.get("status")), _e(outcome.get("run_id"))]
            for sbom_id, outcome in report["scheduled_outcomes"].items()
        ]
        html.append(
            _block(
                _email_section("Scheduled cycle outcomes")
                + _email_table(["SBOM ID", "Completion status", "Run ID"], outcome_rows)
            )
        )

    # Omitted-content notes (amber callouts, e.g. attachment size caps)
    for note in omitted:
        html.append(
            _block(
                "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' "
                f"style='font-size:12.5px; background-color:{_AMBER_BG}; border-radius:6px;'>"
                f"<tr><td style='padding:10px 14px; color:#7a5a13;'>{escape(note)}</td></tr></table>"
            )
        )

    # CTA buttons (sign-in required)
    if links:
        buttons = "".join(
            f"<td style='background-color:{_INK}; border-radius:6px;'>"
            f"<a href='{escape(url, quote=True)}' style='display:inline-block; padding:12px 22px; color:#ffffff; "
            f"font-size:13px; font-weight:600; text-decoration:none;'>{escape(label)}</a></td>"
            "<td style='width:10px;'></td>"
            for label, url in links
        )
        html.append(
            _block(
                f"<table role='presentation' cellpadding='0' cellspacing='0'><tr>{buttons}</tr></table>"
                "<div style='font-size:11px; color:#94a3b8; margin-top:8px;'>Sign-in required.</div>",
                padding="26px 36px 22px 36px",
            )
        )

    # Interpretation notes + footer
    caveats = "<br>".join(escape(note) for note in report.get("caveats", ()))
    html.append(
        f"<tr><td style='padding:18px 36px; background-color:{_HEAD_BG}; border-top:1px solid {_BORDER};'>"
        f"<div style='font-size:11px; color:#94a3b8; line-height:1.6;'>{caveats}<br><br>"
        f"SBOM Analyzer &middot; tenant {_e(report['tenant_id'])} &middot; {_e(report['scope'])} scope &middot; "
        f"cycle {_e(report['cycle_start'][:10])} &rarr; {_e(report['cycle_end'][:10])}</div></td></tr>"
    )
    html.append("</table></td></tr></table></body></html>")
    return subject, "\n".join(text), "".join(html)


def render_pdf(report):
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles["BodyText"].fontSize = 7
    styles["BodyText"].leading = 9
    story = [Paragraph("SBOM security digest", styles["Title"])]
    # Executive PDF includes all selected parts and headline deltas. The XLSX
    # and JSON carry every finding; bounded executive tables keep memory stable.
    for title, columns, rows in report_sections(report, compact=True):
        story.extend([Spacer(1, 10), Paragraph(escape(title), styles["Heading2"])])
        # Split very large tables into bounded chunks; repeat headers per page.
        for start in range(0, max(len(rows), 1), 500):
            values = [columns, *rows[start : start + 500]]
            table = LongTable(
                [[Paragraph(escape(_text(v)), styles["BodyText"]) for v in row] for row in values],
                repeatRows=1,
                colWidths=[7.3 * inch / len(columns)] * len(columns),
                hAlign="LEFT",
            )
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf3fb")),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(table)
    SimpleDocTemplate(output, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36).build(story)
    return output.getvalue()


def spreadsheet_value(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    value = _text(value)
    # Spreadsheet formulas/DDE may never originate from uploaded SBOM text.
    if value.lstrip().startswith(("=", "+", "-", "@")):
        value = "'" + value
    return "".join(c for c in value if c in "\n\t\r" or ord(c) >= 32)[:32767]


def render_xlsx(report):
    workbook = Workbook(write_only=True)
    sheets = {
        name: workbook.create_sheet(name) for name in ["Rollup", *[f"Part {p}" for p in report["parts"]], "Metadata"]
    }
    metadata = sheets["Metadata"]
    metadata.append(["SBOM ID", "Part", "Baseline run ID", "Current run ID", "Status"])
    for sbom in report["sboms"]:
        metadata.append([sbom["id"], "A", None, sbom["A"]["run_id"], sbom["A"]["run_status"]])
        for part, comparison in sbom["comparisons"].items():
            metadata.append(
                [
                    sbom["id"],
                    part,
                    comparison.get("run_a", {}).get("id"),
                    comparison.get("run_b", {}).get("id"),
                    comparison["status"],
                ]
            )
    for title, columns, rows in report_sections(report):
        key = next((f"Part {p}" for p in report["parts"] if f"Part {p}:" in title), "Rollup")
        if title in {"Reporting window", "Interpretation and limitations"}:
            key = "Metadata"
        sheet = sheets[key]
        sheet.append([spreadsheet_value(title)])
        sheet.append(columns)
        for row in rows:
            sheet.append([spreadsheet_value(value) for value in row])
        sheet.append([])
    output = BytesIO()
    workbook.save(output)
    return output.getvalue()


def render_attachments(report, formats):
    result = []
    if "PDF" in formats:
        result.append(EmailAttachment("sbom-security-digest.pdf", "application/pdf", render_pdf(report)))
    if "XLSX" in formats:
        result.append(
            EmailAttachment(
                "sbom-security-digest.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                render_xlsx(report),
            )
        )
    result.append(
        EmailAttachment(
            "sbom-security-digest.json", "application/json", json.dumps(report, ensure_ascii=False).encode()
        )
    )
    return result
