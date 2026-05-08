# Metric Conventions

> **Audience:** anyone adding or changing a count, percentage, ratio, or aggregate that the user will see.
> **Companion docs:** [`dashboard-metrics-spec.md`](./dashboard-metrics-spec.md) — the catalog of every existing metric function. [`metric-correctness-audit.md`](./metric-correctness-audit.md) — the audit history (Phase 0 through Phase 4) that produced this document.

This product computes counts in **three** conventions. Every count rendered in the UI MUST go through `app/metrics/` and follow exactly one of them. Mixing conventions in a single tile is the bug class this document exists to prevent.

The architectural invariant test in `tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics` enforces "no inline metric SQL outside `app/metrics/`" at PR review time. Files that exist today and still bypass the layer are listed in `_LEGACY_DIRECT_QUERY_ALLOWLIST` in that file — that allowlist is the migration backlog.

---

## Convention A — Latest state

> "What's true *right now*?"

Counts as they exist *as of the latest successful run* per SBOM (or scoped to a single run, when the surface is per-run). Cumulative history doesn't appear; resolved findings drop out.

**Use when** the user is asking about *current* posture or scoped to a specific run.

**Examples** (this product):

| Surface | Function |
|---|---|
| Dashboard hero — KEV exposed, severity bar, fix-available coverage | `findings_latest_per_sbom_*`, `findings_kev_in_scope` |
| Run-detail severity counts | `findings_in_run_severity_distribution` |
| Run-detail total findings tile | `findings_in_run_total` |
| SBOM-detail risk summary | `findings_latest_per_sbom_*` filtered to one `sbom_id` |
| Analysis Runs page outcome buckets | `runs_aggregate(...).by_outcome` |

**SQL shape**

```sql
-- shared subquery, defined once in app/metrics/_helpers.py:22-34
SELECT MAX(id) FROM analysis_run
WHERE run_status IN ('OK','FINDINGS','PARTIAL')
GROUP BY sbom_id
```

```sql
SELECT COUNT(*) FROM analysis_finding
WHERE analysis_run_id IN (<latest_per_sbom_subquery>)
```

---

## Convention B — Lifetime distinct

> "How many *unique* issues have we ever surfaced?"

Counts unique findings across all runs, deduplicated on the canonical key `(vuln_id, component_name, component_version)`. The same finding appearing in N runs counts as 1.

**Use when** the user is asking about cumulative reach or "ever surfaced".

**Examples** (this product):

| Surface | Function |
|---|---|
| Dashboard "Findings Surfaced" lifetime tile | `findings_distinct_lifetime` |
| Findings-trend chart per-day snapshots | `findings_daily_distinct_active` (B applied per day) |
| Compare-runs added / resolved / unchanged set diffs | B-flavor over two specific runs |

**SQL shape**

```sql
SELECT COUNT(DISTINCT
  COALESCE(vuln_id, '') || '|' ||
  COALESCE(component_name, '') || '|' ||
  COALESCE(component_version, '')
)
FROM analysis_finding f
JOIN analysis_run r ON r.id = f.analysis_run_id
WHERE r.run_status IN ('OK','FINDINGS','PARTIAL');
```

The dedup key is **locked** in `finding_key()` at `app/metrics/_helpers.py:87-98`. Inline copies of this triplet are a code smell — call the helper.

---

## Convention C — Total raw rows

> "How many *rows* exist?"

Raw `COUNT(*)`, no dedup. The same finding in N runs counts as N. **Almost always wrong for user-facing displays of finding counts.**

**Legitimate uses** (rare):

- "Total LLM calls billed across all runs" — every call IS a row, no dedup is desired
- Internal analytics / ops dashboards that need write-volume signal
- `analysis_run.total_findings` (the denormalised per-run counter — Convention A scoped to one run, but stored as raw count)
- Cascade-impact dialogs ("This will delete N findings") — the user wants to know what the delete actually touches

**Examples** (this product):

| Surface | Note |
|---|---|
| Settings → AI Usage tile | C is correct here — every call is billable |
| Project / SBOM delete-impact dialogs | C is correct — counting rows about to vanish |
| List-page "N items" filter chips | C is correct — these are list lengths, not metrics |

If you're tempted to use C for a *finding count* tile, stop — pick A or B.

---

## Decision flowchart

```
Is the count showing "what's true right now"?           → Convention A
   (per-run page, latest-state hero tile, current-scope severity)

Is the count showing "how many unique things ever"?     → Convention B
   (lifetime tile, trend snapshot, set-diff between two runs)

Is the count a row count of an event log,
or "what will be deleted"?                              → Convention C
   (AI usage, delete-impact, FE list lengths)

Otherwise: re-read the user-facing label. If it says
"unique" / "distinct" / "ever" → B. If it implies
"now" / "this run" / "currently" → A. If neither
applies and the count is a raw event log, C. If neither
applies and you can't pick, the *label* is the bug —
fix it before the math.
```

---

## Hard rules

1. **No new conventions.** A, B, C cover every legitimate use case in this product. If you think you need a fourth, the surface is asking the wrong question — fix the surface.
2. **No mixing conventions in one tile.** A tile labelled "Findings" must compute its number in one convention end-to-end; Convention B totals with Convention A severity breakdowns produces the bug §I0.4-F5 audit screenshot showed (lifetime distinct < single-run total — mathematically valid but visually impossible-looking).
3. **No inline metric SQL outside `app/metrics/`.** Routers and services consume the metric layer; they don't roll their own aggregates. The architectural test in `tests/test_metric_consistency.py` catches this. Today's known violators are in `_LEGACY_DIRECT_QUERY_ALLOWLIST` and should migrate over time.
4. **No legacy run-status strings.** Backend emits `OK` / `FINDINGS` / `PARTIAL` / `ERROR` / `RUNNING` / `PENDING` / `NO_DATA`. The legacy `PASS` / `FAIL` aliases are for inbound idempotency only — never use them in display logic. The FE helper `canonicalRunStatus()` (`frontend/src/lib/analysisRunStatusLabels.ts:102`) maps legacy → canonical.
5. **Severity-bucket invariant.** For any single run, `total_findings == critical_count + high_count + medium_count + low_count + unknown_count`. Locked by `test_f4_denormalised_columns_match_live_count` in the metric-consistency suite — if you add a chip set that hides one of these buckets, the visible sum will not equal the row total (audit §I0.4-F3).

---

## When to update this doc

- Adding a new metric function in `app/metrics/` → add it to `dashboard-metrics-spec.md` (the catalog), not here. Update this doc only if the new function exercises a convention edge case worth calling out.
- Adding a new surface → no update here. Pick the right convention via the flowchart and call the existing function. Add a row to `dashboard-metrics-spec.md` if you needed a new function.
- Migrating a file out of `_LEGACY_DIRECT_QUERY_ALLOWLIST` → no update here, just remove the entry in the same PR.
- Discovering a fourth convention is needed → STOP. Re-read the surface's label and goal. Talk to the audit owner before adding to this doc.
