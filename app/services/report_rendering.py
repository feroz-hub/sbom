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


def render_email(report, *, links=(), omitted=()):
    subject = f"SBOM security digest · {report['scope']} · {report['cycle_end'][:10]}"
    text = [subject]
    html = [
        "<html><body style='margin:0;font-family:Arial,sans-serif;color:#172b4d;background:#fff'>",
        "<table role='presentation' width='100%' cellpadding='16'><tr><td><h1>SBOM security digest</h1>",
    ]
    for title, columns, rows in report_sections(report, compact=True):
        text.extend(["", title, " | ".join(columns)])
        html.append(
            f"<h2 style='font-size:17px;color:#163e79'>{escape(title)}</h2><table width='100%' cellpadding='6' cellspacing='0' style='border-collapse:collapse;font-size:12px'>"
        )
        html.append(
            "<tr>"
            + "".join(
                f"<th align='left' style='border:1px solid #ddd;background:#edf3fb'>{escape(c)}</th>" for c in columns
            )
            + "</tr>"
        )
        for row in rows:
            text.append(" | ".join(_text(v) for v in row))
            html.append(
                "<tr>"
                + "".join(f"<td style='border:1px solid #ddd;vertical-align:top'>{escape(_text(v))}</td>" for v in row)
                + "</tr>"
            )
        html.append("</table>")
    for note in omitted:
        text.append(note)
        html.append(f"<p>{escape(note)}</p>")
    for label, url in links:
        text.append(f"{label}: {url}")
        html.append(f"<p><a href='{escape(url, quote=True)}'>{escape(label)}</a> (sign-in required)</p>")
    html.append("</td></tr></table></body></html>")
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
