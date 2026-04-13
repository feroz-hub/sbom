# ================================================================
#    SBOM MULTI‑SOURCE PDF REPORT GENERATOR (STANDALONE MODULE)
# ================================================================
#  Includes:
#     ✅ Consolidated flatteners (NVD / OSV / GHSA / Combined)
#     ✅ CVSS extraction
#     ✅ CWE extraction
#     ✅ Description extraction
#     ✅ Reference extraction
#     ✅ CWE Count in main table
#     ✅ Detailed CVSS & CWE section per finding
# ================================================================

import json
from collections import Counter
from datetime import datetime
from html import escape
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------
# 1. CONSTANTS (colors, severity order)
# ---------------------------------------------------------

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Accent palette
PRIMARY = colors.HexColor("#1f4e79")  # deep blue
MUTED = colors.HexColor("#4e5b6e")  # gray-blue
HEADER_BG = colors.HexColor("#e9eef5")  # light header bg
ROW_STRIPES = [colors.whitesmoke, colors.white]


def _sev_color(sev: str):
    s = (sev or "").upper()
    return {
        "CRITICAL": colors.HexColor("#d32f2f"),
        "HIGH": colors.HexColor("#f57c00"),
        "MEDIUM": colors.HexColor("#fbc02d"),
        "LOW": colors.HexColor("#388e3c"),
        "UNKNOWN": colors.HexColor("#9e9e9e"),
    }.get(s, colors.HexColor("#9e9e9e"))


def _short(text: str | None, n: int = 110) -> str:
    t = (text or "").strip().replace("\n", " ")
    return (t[:n] + "…") if len(t) > n else t


def _severity_bucket(sev: str | None) -> str:
    s = (sev or "").upper()
    return s if s in _SEV_ORDER else "UNKNOWN"


def _run_is_consolidated(run: dict[str, Any]) -> bool:
    comps = run.get("components") or []
    return bool(comps and isinstance(comps[0], dict) and "combined" in comps[0])


def _flatten_consolidated(run: dict[str, Any]) -> list[dict[str, Any]]:

    rows: list[dict[str, Any]] = []
    for comp in run.get("components") or []:
        cname = comp.get("name", "")
        cver = comp.get("version", "")
        purl = comp.get("purl")
        cpe = comp.get("cpe")

        for v in comp.get("combined") or []:
            rows.append(
                {
                    "component": cname,
                    "version": cver,
                    "purl": purl,
                    "cpe": cpe,
                    "id": v.get("id") or v.get("vuln_id"),
                    "severity": _severity_bucket(v.get("severity")),
                    "score": v.get("score"),
                    "published": v.get("published"),
                    "sources": ", ".join(v.get("sources") or []),
                    "url": v.get("url"),
                    "aliases": ", ".join(v.get("aliases") or []),
                    # Pass through for Finding Details (were dropped → always "—")
                    "attack_vector": v.get("attack_vector"),
                    "cwe": v.get("cwe"),
                    "fixed_versions": v.get("fixed_versions"),
                    "description": v.get("description"),
                }
            )
    return rows


def _flatten_nvd(run: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for comp in run.get("components") or []:
        cname = comp.get("name", "")
        cver = comp.get("version", "")
        purl = comp.get("purl")
        cpe = comp.get("cpe")
        cves = comp.get("cves") or (comp.get("sources", {}).get("nvd", {}).get("cves") if comp.get("sources") else [])
        for v in cves or []:
            rows.append(
                {
                    "component": cname,
                    "version": cver,
                    "purl": purl,
                    "cpe": cpe,
                    "id": v.get("id") or v.get("vuln_id"),
                    "severity": _severity_bucket(v.get("severity")),
                    "score": v.get("score"),
                    "published": v.get("published"),
                    "sources": "NVD",
                    "url": v.get("url"),
                    "aliases": "",
                    "attack_vector": v.get("attack_vector"),
                    "cwe": v.get("cwe"),
                    "fixed_versions": v.get("fixed_versions"),
                    "description": v.get("description"),
                }
            )
    return rows


def _flatten_ghsa(run: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for comp in run.get("components") or []:
        cname = comp.get("name", "")
        cver = comp.get("version", "")
        purl = comp.get("purl")
        advisories = comp.get("advisories") or (
            comp.get("sources", {}).get("ghsa", {}).get("advisories") if comp.get("sources") else []
        )
        for v in advisories or []:
            rows.append(
                {
                    "component": cname,
                    "version": cver,
                    "purl": purl,
                    "cpe": comp.get("cpe"),
                    "id": v.get("id") or v.get("vuln_id"),
                    "severity": _severity_bucket(v.get("severity")),
                    "score": v.get("score"),
                    "published": v.get("published"),
                    "sources": "GHSA",
                    "url": v.get("url"),
                    "aliases": "",
                    "attack_vector": v.get("attack_vector"),
                    "cwe": v.get("cwe"),
                    "fixed_versions": v.get("fixed_versions"),
                    "description": v.get("description"),
                }
            )
    return rows


def _flatten_osv(run: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for comp in run.get("components") or []:
        cname = comp.get("name", "")
        cver = comp.get("version", "")
        purl = comp.get("purl")
        advisories = comp.get("advisories") or (
            comp.get("sources", {}).get("osv", {}).get("advisories") if comp.get("sources") else []
        )
        for v in advisories or []:
            rows.append(
                {
                    "component": cname,
                    "version": cver,
                    "purl": purl,
                    "cpe": comp.get("cpe"),
                    "id": v.get("id") or v.get("vuln_id"),
                    "severity": _severity_bucket(v.get("severity")),
                    "score": v.get("score"),
                    "published": v.get("published"),
                    "sources": "OSV",
                    "url": v.get("url"),
                    "aliases": ", ".join(v.get("aliases") or []),
                    "attack_vector": v.get("attack_vector"),
                    "cwe": v.get("cwe"),
                    "fixed_versions": v.get("fixed_versions"),
                    "description": v.get("description"),
                }
            )
    return rows


def _flatten_for_pdf(run: dict[str, Any]) -> list[dict[str, Any]]:
    if _run_is_consolidated(run):
        return _flatten_consolidated(run)
    summ = run.get("summary", {}).get("findings", {})
    if "bySeverity" in summ and "total" in summ and (run.get("components") or []):
        comp0 = (run.get("components") or [{}])[0]
        if isinstance(comp0, dict):
            if "cves" in comp0:
                return _flatten_nvd(run)
            if "advisories" in comp0:
                adv0 = (comp0.get("advisories") or [{}])[0]
                if isinstance(adv0, dict) and "aliases" in adv0:
                    return _flatten_osv(run)
                return _flatten_ghsa(run)

    return _flatten_consolidated(run)


def _severity_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    c = Counter(_severity_bucket(r.get("severity")) for r in rows)
    return {k: c.get(k, 0) for k in _SEV_ORDER}


def _widths(total: float, fractions: list[float]) -> list[float]:
    s = float(sum(fractions)) or 1.0
    return [total * (f / s) for f in fractions]


def _build_pdf_from_run_impl(run: dict[str, Any], title: str = "SBOM Vulnerability Report") -> bytes:

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=PRIMARY,
            alignment=TA_CENTER,
            spaceAfter=10,
        )
    )

    # Section heading
    styles.add(
        ParagraphStyle(
            name="Section",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.black,
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True,
        )
    )

    # Metadata labels/values
    styles.add(
        ParagraphStyle(
            name="MetaKey", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=12, textColor=MUTED
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetaVal",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=12,
            textColor=colors.black,
        )
    )

    # Table cell text
    styles.add(
        ParagraphStyle(
            name="TCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=10.5,
            textColor=colors.black,
            spaceAfter=0,
        )
    )
    styles.add(ParagraphStyle(name="TCellRight", parent=styles["TCell"], alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="TCellCenter", parent=styles["TCell"], alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="TCellMuted", parent=styles["TCell"], textColor=MUTED))
    styles.add(ParagraphStyle(name="TCellBold", parent=styles["TCell"], fontName="Helvetica-Bold"))

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm
    )
    avail = doc.width
    story: list[Any] = []

    story.append(Paragraph(title, styles["ReportTitle"]))

    sbom_info = run.get("sbom", {}) or {}
    meta = [
        ("Generated:", f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"),
        ("Run ID:", str(run.get("runId", ""))),
        ("Status:", str(run.get("status", ""))),
        ("File:", str(sbom_info.get("filename", "N/A"))),
        ("Format:", f"{sbom_info.get('format', 'N/A')} {sbom_info.get('specVersion', '')}"),
        ("Completed:", str(run.get("summary", {}).get("completedOn", ""))),
        ("Duration:", f"{run.get('summary', {}).get('durationMs', 0)} ms"),
    ]
    meta_rows = [
        [Paragraph(f"{escape(k)}", styles["MetaKey"]), Paragraph(escape(v), styles["MetaVal"])] for k, v in meta
    ]
    meta_table = Table(meta_rows, colWidths=_widths(avail, [0.20, 0.80]), hAlign="LEFT")
    meta_table.setStyle(
        TableStyle(
            [
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 10))

    rows = _flatten_for_pdf(run)
    sev_counts = _severity_counts(rows)

    story.append(Paragraph("Report summary", styles["Section"]))
    comps = run.get("components") or []
    total_comp = len(comps)
    total_find = len(rows)
    summary_text = f"This report covers {total_comp} component(s) with {total_find} vulnerability finding(s) in total. Severity distribution and per-component details are below."
    story.append(Paragraph(escape(summary_text), styles["Normal"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Severity distribution", styles["Section"]))
    sev_data = [["Severity", "Count"]] + [[s, str(sev_counts.get(s, 0))] for s in _SEV_ORDER]
    sev_table = Table(sev_data, colWidths=_widths(avail * 0.45, [0.6, 0.4]), hAlign="LEFT")
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (-1, 0), PRIMARY),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 1), (0, -1), "LEFT"),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(sev_table)
    story.append(Spacer(1, 8))

    # Top 10 Most Critical Findings
    story.append(Paragraph("Top 10 Most Critical Findings", styles["Section"]))
    top10_rows_data = rows if rows else []

    def _sort_key_score(r):
        s = r.get("score")
        return s if s is not None else -1

    sorted_rows_top10 = sorted(top10_rows_data, key=_sort_key_score, reverse=True)[:10]
    top10_header = ["Vulnerability ID", "Component", "Severity", "Score"]
    top10_data: list[list[Any]] = [[Paragraph(h, styles["TCellBold"]) for h in top10_header]]
    if sorted_rows_top10:
        for r in sorted_rows_top10:
            comp_txt = (f"{r.get('component', '')}@{r.get('version', '')}".strip("@")).strip()
            sev = _severity_bucket(r.get("severity"))
            top10_data.append(
                [
                    Paragraph(escape(_short(r.get("id") or "", 30)), styles["TCell"]),
                    Paragraph(escape(_short(comp_txt, 40)), styles["TCell"]),
                    Paragraph(escape(sev), styles["TCellCenter"]),
                    Paragraph("" if r.get("score") is None else f"{r.get('score')}", styles["TCellRight"]),
                ]
            )
    else:
        top10_data.append(
            [
                Paragraph("No findings.", styles["TCellMuted"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
            ]
        )
    top10_cw = _widths(avail * 0.7, [0.30, 0.40, 0.15, 0.15])
    top10_table = Table(top10_data, colWidths=top10_cw, repeatRows=1, hAlign="LEFT")
    top10_style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (-1, 0), PRIMARY),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 1), (2, -1), "CENTER"),
        ("ALIGN", (3, 1), (3, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), ROW_STRIPES),
    ]
    for i, r in enumerate(sorted_rows_top10, start=1):
        sev = _severity_bucket(r.get("severity"))
        col = _sev_color(sev)
        top10_style.append(("BACKGROUND", (2, i), (2, i), col))
        top10_style.append(("TEXTCOLOR", (2, i), (2, i), colors.white if sev in ("CRITICAL", "HIGH") else colors.black))
    top10_table.setStyle(TableStyle(top10_style))
    story.append(top10_table)
    story.append(Spacer(1, 12))

    comps = run.get("components") or []
    story.append(Paragraph("Components (Summary)", styles["Section"]))

    comp_header = ["Component", "Version", "PURL", "CPE", "Findings"]
    comp_table_data: list[list[Any]] = [[Paragraph(h, styles["TCellBold"]) for h in comp_header]]

    if comps:
        for c in comps:
            if "combined" in c:
                findings_count = len(c.get("combined") or [])
            elif "cves" in c:
                findings_count = len(c.get("cves") or [])
            elif "advisories" in c:
                findings_count = len(c.get("advisories") or [])
            else:
                findings_count = 0

            comp_table_data.append(
                [
                    Paragraph(escape(_short(c.get("name") or "N/A", 80)), styles["TCell"]),
                    Paragraph(escape(_short(c.get("version") or "N/A", 24)), styles["TCellCenter"]),
                    Paragraph(escape(_short(c.get("purl") or "N/A", 120)), styles["TCell"]),
                    Paragraph(escape(_short(c.get("cpe") or "N/A", 80)), styles["TCell"]),
                    Paragraph(str(findings_count), styles["TCellRight"]),
                ]
            )
    else:
        comp_table_data.append(
            [
                Paragraph("No components detected.", styles["TCellMuted"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
            ]
        )

    comp_cw = _widths(avail, [0.30, 0.11, 0.36, 0.15, 0.08])
    comp_table = Table(comp_table_data, colWidths=comp_cw, repeatRows=1, hAlign="LEFT")
    comp_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (-1, 0), PRIMARY),
                ("FONTSIZE", (0, 0), (-1, 0), 9.5),
                ("FONTSIZE", (0, 1), (-1, -1), 8.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 1), (1, -1), "CENTER"),
                ("ALIGN", (4, 1), (4, -1), "RIGHT"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), ROW_STRIPES),
            ]
        )
    )
    story.append(comp_table)
    story.append(PageBreak())

    story.append(Paragraph("Findings", styles["Section"]))

    find_header = ["Component", "ID", "Severity", "Score", "Published", "Sources", "Fix Version"]
    find_table_data: list[list[Any]] = [[Paragraph(h, styles["TCellBold"]) for h in find_header]]

    # Track severity values per data row to paint color badges
    severity_by_row: dict[int, str] = {}

    if rows:
        for r in rows:
            comp_txt = (f"{r.get('component', '')}@{r.get('version', '')}".strip("@")).strip()
            fv_raw = r.get("fixed_versions") or "[]"
            if isinstance(fv_raw, str):
                try:
                    fv_list = json.loads(fv_raw)
                except Exception:
                    fv_list = []
            else:
                fv_list = list(fv_raw) if fv_raw else []
            fix_ver = fv_list[0] if fv_list else "—"
            sev = _severity_bucket(r.get("severity"))
            # Add row
            find_table_data.append(
                [
                    Paragraph(escape(_short(comp_txt, 50)), styles["TCell"]),
                    Paragraph(escape(_short(r.get("id") or "", 28)), styles["TCell"]),
                    Paragraph(escape(sev), styles["TCellCenter"]),
                    Paragraph("" if r.get("score") is None else f"{r.get('score')}", styles["TCellRight"]),
                    Paragraph(escape((r.get("published") or "")[:10]), styles["TCellCenter"]),
                    Paragraph(escape(_short(r.get("sources") or "", 28)), styles["TCell"]),
                    Paragraph(escape(_short(str(fix_ver), 20)), styles["TCell"]),
                ]
            )
            severity_by_row[len(find_table_data) - 1] = sev  # table row index
    else:
        find_table_data.append(
            [
                Paragraph("No findings in this run.", styles["TCellMuted"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
                Paragraph("", styles["TCell"]),
            ]
        )

    find_cw = _widths(avail, [0.25, 0.17, 0.10, 0.08, 0.11, 0.12, 0.17])
    find_table = Table(find_table_data, colWidths=find_cw, repeatRows=1, hAlign="LEFT")

    base_style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (-1, 0), PRIMARY),
        ("FONTSIZE", (0, 0), (-1, 0), 9.5),
        ("FONTSIZE", (0, 1), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (2, 1), (2, -1), "CENTER"),  # Severity
        ("ALIGN", (3, 1), (3, -1), "RIGHT"),  # Score
        ("ALIGN", (4, 1), (4, -1), "CENTER"),  # Published
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), ROW_STRIPES),
    ]

    for row_idx, sev in severity_by_row.items():
        col = _sev_color(sev)
        base_style.append(("BACKGROUND", (2, row_idx), (2, row_idx), col))
        base_style.append(
            ("TEXTCOLOR", (2, row_idx), (2, row_idx), colors.white if sev in ("CRITICAL", "HIGH") else colors.black)
        )

    find_table.setStyle(TableStyle(base_style))
    story.append(find_table)

    # Finding Details — mini-card per finding
    if rows:
        story.append(Spacer(1, 16))
        story.append(Paragraph("Finding Details", styles["Section"]))
        CARD_BG = colors.HexColor("#f5f7fa")

        for idx, r in enumerate(rows):
            if idx > 0 and idx % 8 == 0:
                story.append(PageBreak())

            sev = _severity_bucket(r.get("severity"))
            sev_col = _sev_color(sev)

            fv_raw = r.get("fixed_versions") or "[]"
            if isinstance(fv_raw, str):
                try:
                    fv_list = json.loads(fv_raw)
                except Exception:
                    fv_list = []
            else:
                fv_list = list(fv_raw) if fv_raw else []
            fix_ver = fv_list[0] if fv_list else "—"

            url_val = (r.get("url") or "").strip()
            cwe_val = r.get("cwe") or "—"
            if isinstance(cwe_val, list):
                cwe_val = ", ".join(cwe_val) or "—"

            attack_vec = r.get("attack_vector") or "—"
            description = _short(r.get("description") or "", 400)
            comp_txt = (f"{r.get('component', '')}@{r.get('version', '')}".strip("@")).strip()

            detail_lines = [
                f"<b>Component:</b> {escape(_short(comp_txt, 80))}",
                f"<b>Published:</b> {escape((r.get('published') or '')[:10] or '—')}",
                f"<b>Attack Vector:</b> {escape(str(attack_vec))}",
                f"<b>CWE:</b> {escape(str(cwe_val))}",
                f"<b>Fix:</b> {escape(str(fix_ver))}",
            ]
            if url_val:
                detail_lines.append(f'<b>URL:</b> <link href="{escape(url_val)}">{escape(_short(url_val, 80))}</link>')
            if description:
                detail_lines.append(f"<b>Description:</b> {escape(description)}")

            header_label = (
                f"{escape(r.get('id') or 'N/A')}  "
                f"[{escape(sev)}  {r.get('score') if r.get('score') is not None else '—'}]  "
                f"{escape(r.get('sources') or '')}"
            )

            card_content = [
                [Paragraph(header_label, styles["TCellBold"])],
                [Paragraph("<br/>".join(detail_lines), styles["TCell"])],
            ]

            card_style = [
                ("BACKGROUND", (0, 0), (-1, 0), sev_col),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white if sev in ("CRITICAL", "HIGH") else colors.black),
                ("BACKGROUND", (0, 1), (-1, -1), CARD_BG),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ]

            card_table = Table(card_content, colWidths=[avail], hAlign="LEFT")
            card_table.setStyle(TableStyle(card_style))
            story.append(card_table)
            story.append(Spacer(1, 6))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


class PdfReportBuilder:
    """
    Builder for ReportLab PDF output from a consolidated analysis run dict.

    Exposes ``build() -> bytes``; ``build_pdf_from_run_bytes`` delegates here.
    """

    __slots__ = ("_run", "_title")

    def __init__(self, run: dict[str, Any], title: str = "SBOM Vulnerability Report") -> None:
        self._run = run
        self._title = title

    def build(self) -> bytes:
        return _build_pdf_from_run_impl(self._run, self._title)


def build_pdf_from_run_bytes(run: dict[str, Any], title: str = "SBOM Vulnerability Report") -> bytes:
    return PdfReportBuilder(run, title=title).build()


def build_pdf_from_run(run: dict[str, Any], output_pdf: str, title: str = "Report") -> None:

    pdf_bytes = build_pdf_from_run_bytes(run, title=title)
    with open(output_pdf, "wb") as f:
        f.write(pdf_bytes)
