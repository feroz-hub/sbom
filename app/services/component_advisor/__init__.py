"""Secure Component Advisor domain package.

Source of truth: ``docs/specs/Secure_Component_Advisor_Requirements_v1_1.docx``;
plan and decisions: ``docs/secure-component-advisor/phase0-analysis.md``.

Pure domain modules (no SQL, NFR-SCA-009):

* :mod:`.classification` — spec §2 risk buckets (FR-SCA-003).
* :mod:`.lifecycle_mapping` — lifecycle statuses → advisor lifecycle buckets.
* :mod:`.identity` — unique-version and component-family keys.

Aggregation over findings and runs lives in :mod:`app.metrics.component_advisor`
(CLAUDE.md: no direct ``AnalysisFinding`` / ``AnalysisRun`` queries here).
The advisor is advisory only: nothing in this package writes to SBOMs,
components, findings or VEX (spec §1.1).
"""
