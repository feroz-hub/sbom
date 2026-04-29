# ADR-0001 — Dashboard posture model and run-status rename

- **Status:** Accepted (2026-04-30)
- **Context:** [docs/dashboard-audit.md](../dashboard-audit.md)
- **Authors:** Feroze Basha (FBT) / Claude
- **Supersedes:** none
- **Related:** [docs/terminology.md](../terminology.md), [docs/risk-index.md](../risk-index.md)

## Context

The home dashboard had two classes of defects (full audit in `docs/dashboard-audit.md`):

1. **Semantic.** Hero headline read `Critical risk` whenever the Critical bucket was non-empty, regardless of proportion. The `LIVE` pill was always green even when the underlying NVD mirror was down. The "Recent runs · FAIL · FAIL" panel wasn't reporting outages — it was reporting clean runs that found CVEs.
2. **Numeric.** Every hero number was a multiplier of one underlying scan because no query scoped to "latest run per SBOM". `Total Vulnerabilities` returned finding count, not distinct CVE count. Risk Index `42,925` had no documented formula.

The single root cause behind several symptoms was the **`run_status='FAIL'` overload**: `compute_report_status` returned `"FAIL"` whenever findings existed, and `"PASS"` only when a clean SBOM produced zero findings. The label collapsed two unrelated meanings — "the analyzer broke" and "the analyzer succeeded and found CVEs" — into one string that paints red everywhere it appears.

## Decision

### 1. Run-status rename: `FAIL → FINDINGS`

The enum `{PASS, FAIL, PARTIAL, ERROR, RUNNING, PENDING, NO_DATA}` becomes `{OK, FINDINGS, PARTIAL, ERROR, RUNNING, PENDING, NO_DATA}`.

- `OK` replaces `PASS` (also accepted as legacy alias for one release).
- `FINDINGS` replaces `FAIL` (also accepted as legacy alias for one release).
- `ERROR` retains its meaning: pipeline crash, no usable output.

**Migration:** Alembic 005 issues `UPDATE analysis_run SET run_status='FINDINGS' WHERE run_status='FAIL'` and the equivalent for `analysis_schedule.last_run_status`. Same for `PASS → OK`.

**Display tone:** `FINDINGS` is amber (a healthy scan with actionable output), distinct from `ERROR` which is red.

### 2. Posture model

The hero headline is computed by a single state machine `derivePosture(input) → DashboardPosture`:

```
input = {
  severity:    SeverityCounts,
  freshness:   { lastSuccessfulRunAt: ISO | null, hoursSinceLatest: number | null },
  health:      { apiOk: bool, nvdMirrorOk: bool },
  scope:       { totalSboms: int, totalActiveProjects: int }
}

If health.apiOk == false                          → Degraded (reason: "API unhealthy")
Else if health.nvdMirrorOk == false                → Degraded (reason: "NVD mirror unavailable")
Else if freshness.hoursSinceLatest === null        → Empty   (no successful runs ever)
Else if freshness.hoursSinceLatest > 24            → Degraded (reason: "Data stale (> 24h)")
Else if scope.totalSboms === 0                     → Empty
Else if severity.critical > 0                      → Urgent
Else if severity.high > 0                          → Action needed
Else if severity.medium > 0 || severity.low > 0    → Stable
Else                                                → Clean
```

`Degraded` ALWAYS takes precedence over severity-based bands because the underlying severity numbers may be wrong when the pipeline is unhealthy.

Bands and their copy:

| Band | Headline | Subtext template | Tone |
|---|---|---|---|
| `clean` | "All clear" | "No findings across {N} SBOMs in {M} active projects." | green |
| `stable` | "Stable" | "{X} medium/low findings — no urgent action required." | sky |
| `action_needed` | "Action needed" | "{X} High findings across {Y} components. {Z} have a known fix." | orange |
| `urgent` | "Urgent attention required" | "{X} Critical and {Y} High findings. {K} are on the CISA KEV list. {Z} have a known fix." | red |
| `degraded` | "Posture unavailable" | "{reason}. The numbers below may be stale or incomplete." | amber |
| `empty` | "Ready to scan" | "Upload an SBOM to see your security posture." | neutral |

### 3. Risk Index removed

The hero's `Risk Index` numeric tile is removed. It is replaced by:

- **KEV count**: number of distinct findings whose CVE appears in the CISA Known Exploited Vulnerabilities catalog (`KevEntry`). High-signal exploitability indicator with public provenance.
- **Fix-available count**: number of distinct findings with a non-empty `fixed_versions` array. Operationally actionable.

Rationale: a single magic number without provenance is unfit for a security product. Two numbers that map directly to documented public sources are more defensible AND more actionable. See `docs/risk-index.md` for the full rationale and data lineage.

### 4. Severity-bar redesign

Five-tier bar becomes four-tier (Critical/High/Medium/Low). `UNKNOWN` is rendered as a separate small data-quality pill (`"N with unscored severity"`). Unknown is not a severity — it's a signal that CVSS scoring was missing for that CVE in our feed.

### 5. State-coherence rule

The hero `LIVE` pill, the sidebar `API healthy / Degraded` indicator, and the runs feed must derive from the same posture. Implementation: the hero subscribes to the same `getHealth` query used by `SidebarStatus`, and the band state machine consumes both `severity` and `health`.

## Consequences

### Positive

- One word, one meaning. `FAIL` no longer shows up to mean two opposite things.
- Hero headline is honest about portfolio posture, not just bucket existence.
- Hero, footer, and sidebar can no longer disagree on the same screen.
- Removed the indefensible Risk Index; replaced with two numbers that have documented public sources.
- Schema can now correctly answer "latest successful run per SBOM" because *any* of `{OK, FINDINGS, PARTIAL}` is a successful run.

### Negative

- Migration touches every existing row that has `run_status='FAIL'`. Alembic handles this idempotently. One-time event.
- Frontend type union changes (`'FAIL' | 'PASS'` → `'FINDINGS' | 'OK'`). Touch-points enumerated in audit §1; one-time fix.
- API responses change for any consumer relying on the old enum. We accept `FAIL`/`PASS` as inbound aliases on query params for one release; outbound payloads always use the new names.

### Deferred (future ADRs)

- Findings triage / suppression schema (`AnalysisFinding.is_suppressed`, `triage_state`, `assignee`). Currently *no* schema support. The "actionable findings" copy on the hero conservatively uses `Critical + High` as the surrogate until triage exists.
- Per-finding KEV/EPSS materialization on `analysis_finding` (denormalize for query speed).
- Trend smoothing / 7-day moving average over rerun spikes.
