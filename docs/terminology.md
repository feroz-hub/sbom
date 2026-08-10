# SBOM Analyzer — Terminology Lockdown

**Status:** Locked 2026-04-30. Any new code that introduces vocabulary outside this list must add to this file in the same PR.

This is a security product. Wrong words on a dashboard get a SOC engineer paged at 2am for nothing. We commit to one meaning per word, everywhere.

## Nouns

| Term | Definition | Schema mapping | Example UI label |
|---|---|---|---|
| **Vulnerability** | A distinct CVE / GHSA / OSV identifier. One advisory record. | `count(distinct AnalysisFinding.vuln_id)` within scope. | "373 distinct vulnerabilities" |
| **Finding** | An *instance* of a vulnerability against a specific component in a specific run. One CVE on three components × five runs = 15 findings. | One row in `analysis_finding`. | "2,984 findings across 8 runs" |
| **Component** | A package / library entry in an SBOM. | One row in `sbom_component`. | "1,205 components scanned" |
| **Run** | One analysis pass over one SBOM. | One row in `analysis_run`. | "Run #8 · completed 13:42" |
| **SBOM** | One Software Bill of Materials document. | One row in `sbom_source`. | — |
| **Project** | A grouping of SBOMs under one application/team. | One row in `projects`. Active = `project_status = 1`. | — |
| **Active project** | A project with `project_status = 1`. KPI counts MUST filter on this. | `count(*) where project_status = 1` | "Active Projects: 3" |

## Severity buckets

CVSS v3 / v4 scoring → bucket. Backend stores UPPERCASE; the canonical-case decision lives in `compute_report_status` adjacent. Display layer lower-cases for keys.

| Severity | CVSS v3 score | Treatment |
|---|---|---|
| `CRITICAL` | 9.0 – 10.0 | red — paged |
| `HIGH` | 7.0 – 8.9 | orange — actionable |
| `MEDIUM` | 4.0 – 6.9 | amber — backlog |
| `LOW` | 0.1 – 3.9 | blue — informational |
| `UNKNOWN` | unscored | **NOT a severity** — data-quality signal. Render separately as "N with unscored severity". Never include in severity bar, severity counts, or risk math. |

`Exploitable band = CRITICAL + HIGH`. This is the operationally actionable count.

## Run-status enum (RENAMED — see ADR-0001)

| Value | Means | Treatment | Notes |
|---|---|---|---|
| `OK` (also accepts legacy `PASS`) | Run completed cleanly, **zero findings**. | green | Aliases: `PASS`. |
| `FINDINGS` (NEW; replaces `FAIL`) | Run completed cleanly, **≥1 finding**. | amber | This is a *successful* analysis with security-relevant output. **Not a pipeline failure.** Accepts `FAIL` as legacy alias for one release. |
| `PARTIAL` | Run completed but some upstream feeds errored (e.g. NVD timeout). Findings list is incomplete. | amber | |
| `ERROR` | Run failed technically. No usable findings. | red | This is the only "real" failure status. |
| `RUNNING` | In flight. | blue | |
| `PENDING` | Queued, not started. | grey | |
| `NO_DATA` | SBOM had no analyzable content. | grey | |

**Successful runs = `{OK, FINDINGS, PARTIAL}`.** Dashboard aggregations include these three and exclude `{ERROR, RUNNING, PENDING, NO_DATA}`.

## Posture bands (hero headline) — see ADR-0001

`Clean | Stable | Action needed | Urgent | Degraded`. `Degraded` takes precedence whenever data freshness or pipeline health is in doubt.

## Vocabulary explicitly retired

These terms must not appear in new code or new copy:

| Don't say | Say instead | Reason |
|---|---|---|
| "Critical risk" (as a static headline) | A computed posture (`Urgent`, `Action needed`, etc.) | "Critical risk" is a misclassification — it triggers when *any* critical bucket is non-empty regardless of proportion. |
| "Total Vulnerabilities" (when meaning finding count) | "Total Findings" or "Distinct Vulnerabilities" — pick one and match the query | The two are different numbers and one CVE can produce many findings. |
| "weighted trend" (without naming the weights in a tooltip + ADR) | Either rename to "30-day finding trend" (un-weighted) or document the weights | Don't claim weighting that isn't explained. |
| `FAIL` (run status) | `FINDINGS` | "FAIL" reads as outage; the run actually succeeded. |
| `Risk Index <number>` (without formula) | Remove from hero. Surface KEV count + fix-available count instead. | Magic numbers without a documented formula are unfit for a security product. |

## Pluralization rule

Use `Intl.PluralRules` in a tiny helper (`pluralize(n, singular, plural)`). No hardcoded English fallbacks for international users. Example: `pluralize(1, 'SBOM', 'SBOMs')` → `"1 SBOM"`; `pluralize(0, 'SBOM', 'SBOMs')` → `"0 SBOMs"`.
