# Dashboard Source-of-Truth Audit (Phase 1, read-only)

**Audit date:** 2026-04-30
**Scope:** Home dashboard (`/`) — hero, KPI cards, severity chart, trend, sidebar status, "Recent runs" feed.
**Method:** Trace every visible number/string from the UI component → API client → FastAPI route → SQLAlchemy query → underlying table, then verify against the live SQLite DB (`sbom_api.db`).
**Posture:** No code or strings changed. Findings only. Awaiting confirmation before Phase 2.

---

## 0. Executive summary — 8 root-cause defects

The screenshot the user attached was generated against a DB state of **5 analysis runs of 1 SBOM, all of which the system labels FAIL**. The current DB has grown to 8 runs with the same per-run output (373 findings each). Every single number on the hero is a multiplier of one underlying scan.

| # | Defect | Severity |
|---|---|---|
| D1 | `run_status='FAIL'` overloads two unrelated meanings — *"findings exist"* AND *"the run broke"*. The screenshot's "FAIL · FAIL" runs in the sidebar never actually broke; they returned 373 findings each. | **P0** — semantic catastrophe; this single label is the root cause of D2/D5/D6 |
| D2 | `total_vulnerabilities` returns `count(AnalysisFinding.id)` — i.e. **finding count, not distinct CVE count**. With 8 reruns of the same SBOM, this number is 8× inflated. True distinct CVEs (`count(distinct vuln_id)`) = **373**, displayed = **2,984**. | **P0** |
| D3 | No dashboard query filters by `run_status`. Findings from broken/legacy/duplicate runs all aggregate into the hero. There is no concept of "latest successful run per SBOM". | **P0** |
| D4 | `Risk Index` formula is `Crit*100 + High*25 + Med*8 + Low*2 + Unknown*1`. It is hidden in [`HeroRiskPulse.tsx:78-82`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L78-L82), undocumented, with no tooltip, and **adds Unknown as if it were a severity tier**. Verified: `175*100 + 790*25 + 650*8 + 225*2 + 25 = 42,925` ✓ matches the displayed value. | P1 |
| D5 | Hero `Active Projects` is `count(Projects.id)` — not filtered by `project_status = 1`. The label says "Active" but the count includes inactive too. | P1 |
| D6 | `LIVE` pill in the hero is always-on whenever the dashboard renders. It's wired to react-query `isFetching` state, not to the health endpoint or the NVD-mirror banner. The `Degraded — NVD mirror disabled` footer and the `LIVE` hero are computed independently and can disagree on the same screen. | P1 |
| D7 | `30-day weighted trend` sparkline weights (`crit*4 + high*1 + med*0.4 + low*0.1` at [`HeroRiskPulse.tsx:134`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L134)) **differ from** the delta calculation weights in the same component (`crit*100 + high*25 + med*8 + low*2` at [`HeroRiskPulse.tsx:93`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L93)). Same chart label, two different weighting functions. | P1 |
| D8 | Hero subtext `"Aggregated across 1 SBOMs in 1 projects"` — pluralization is broken. The hero only conditions plural on `severity.critical === 1`, never on `total_sboms === 1` or `total_projects === 1`. | P2 |

---

## 1. Data-flow map (UI → backend → table)

| Hero element | Component | API client | Backend route | SQL / source |
|---|---|---|---|---|
| Hero headline `Critical risk` | [`HeroRiskPulse.tsx:69-76,196`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L69-L76) `deriveBand()` | — (derived from severity) | `GET /dashboard/severity` | see severity row below |
| `1,865 findings` chip | [`HeroRiskPulse.tsx:209`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L209) `stats.total_vulnerabilities` | `getDashboardStats` ([`api.ts:203`](frontend/src/lib/api.ts#L203)) | `GET /dashboard/stats` ([`dashboard_main.py:27`](app/routers/dashboard_main.py#L27)) | `select count(AnalysisFinding.id)` |
| `Aggregated across 1 SBOMs in 1 projects.` | [`HeroRiskPulse.tsx:217-220`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L217-L220) | `getDashboardStats` | `GET /dashboard/stats` | `count(SBOMSource.id)`, `count(Projects.id)` (no `project_status` filter) |
| `175 critical findings require attention` | [`HeroRiskPulse.tsx:222-225`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L222-L225) | `getDashboardSeverity` | `GET /dashboard/severity` ([`dashboard_main.py:67`](app/routers/dashboard_main.py#L67)) | `select severity, count(*) from analysis_finding group by severity` |
| Severity bar (Crit/High/Med/Low/Unknown) | [`HeroRiskPulse.tsx:122-131`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L122-L131) | `getDashboardSeverity` | same as above | same as above |
| `Risk index 42,925` | [`HeroRiskPulse.tsx:78-82,283`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L78-L82) `severityWeight()` | severity payload | — (client-side compute) | `Crit*100 + High*25 + Med*8 + Low*2 + Unknown*1` |
| `30-day weighted trend` (sparkline) | [`HeroRiskPulse.tsx:133-136`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L133-L136) | `getDashboardTrend(30)` ([`api.ts:563`](frontend/src/lib/api.ts#L563)) | `GET /dashboard/trend?days=30` ([`dashboard.py:21`](app/routers/dashboard.py#L21)) | `count(AnalysisFinding) group by date(AnalysisRun.started_on), severity` |
| Trend delta % vs prior period | [`HeroRiskPulse.tsx:88-101`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L88-L101) `computeDelta()` | trend payload | — (client-side) | weights `crit*100,high*25,med*8,low*2` (different from sparkline weights) |
| `Security posture · live` pill | [`HeroRiskPulse.tsx:184-191`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L184-L191) | — (no health input) | — | tied only to react-query `isFetching` |
| Action row buttons | `DashboardQuickActions.tsx` | — | — | static |
| KPI: `Active Projects` | [`StatsGrid.tsx:38-48`](frontend/src/components/dashboard/StatsGrid.tsx#L38-L48) | `getDashboardStats` | `GET /dashboard/stats` | `count(Projects.id)` |
| KPI: `Total SBOMs` | [`StatsGrid.tsx:49-58`](frontend/src/components/dashboard/StatsGrid.tsx#L49-L58) | same | same | `count(SBOMSource.id)` |
| KPI: `Total Vulnerabilities` | [`StatsGrid.tsx:59-71`](frontend/src/components/dashboard/StatsGrid.tsx#L59-L71) | same | same | `count(AnalysisFinding.id)` |
| Sidebar: `Degraded — NVD mirror disabled` | [`SidebarStatus.tsx:72-79,120-128`](frontend/src/components/layout/SidebarStatus.tsx#L72-L79) | `getHealth` | `GET /health` | `data.status` + `data.nvd_mirror.{available,enabled,stale}` |
| Recent SBOMs / Runs · `FAIL` | `RecentSboms.tsx`, run feed | `getDashboardRecentSboms`, runs API | `GET /dashboard/recent-sboms`, `GET /runs` | `analysis_run.run_status` (semantically overloaded — see D1) |

---

## 2. Live DB ground truth (`sbom_api.db`, 2026-04-30)

```
findings_total                = 2984    (was 1865 in screenshot)
distinct vuln_id              = 373     (the real "Total Vulnerabilities")
findings per run              = 373     × 8 runs = 2984       ← inflation factor
runs                          = 8, ALL run_status=FAIL
sboms                         = 2 (Test Sbom, Test1)
projects                      = 1 (Test Project)
severity (UPPERCASE in DB)    = CRITICAL=280  HIGH=1264  MEDIUM=1040  LOW=360  UNKNOWN=40
                                (= 8× the per-run 35/158/130/45/5)
```

Backend lowercases severity at read time (`(severity or 'unknown').lower()` — [`dashboard_main.py:75`](app/routers/dashboard_main.py#L75)), so the case mismatch isn't a bug, but it's worth noting that the canonical-case decision lives in two places.

**Note on the screenshot's `1,865`:** at the time the screenshot was captured, there were 5 runs (5 × 373 = 1,865; 5 × 35 = 175 critical; 5 × 158 = 790 high; etc.). Every number on the screenshot is reproducible as `runs × per_run_value`. This is the smoking gun for D2/D3.

---

## 3. Per-metric audit table

Legend: ✅ correct · ⚠️ partly correct / misleading · ❌ wrong.

| # | Metric (UI label) | Displayed value (screenshot) | Source (verified) | Value correct? | Terminology correct? | Notes / defect refs |
|---|---|---|---|---|---|---|
| 1 | Hero headline `Critical risk` | string | client `deriveBand()` reading `/dashboard/severity` | ❌ | ❌ | Triggers when `critical > 0`, regardless of proportion (175/1865 = 9.4%). No degraded/failed state. See user's prompt §1. |
| 2 | Hero `1,865 findings` chip | 1,865 | `count(AnalysisFinding.id)` ([`dashboard_main.py:32`](app/routers/dashboard_main.py#L32)) | ❌ | ⚠️ | Number is 5× inflated by 5 reruns of one SBOM. Label "findings" is consistent with code but contradicts the KPI card below which calls the same number "Total Vulnerabilities" (D2). |
| 3 | Hero subtext `1 SBOMs in 1 projects` | "1 SBOMs / 1 projects" | `count(SBOMSource.id)`, `count(Projects.id)` | ⚠️ (`Projects` count is *not* status-filtered, D5) | ❌ | Pluralization broken (D8). "1 SBOM in 1 project". |
| 4 | Hero `175 critical findings require attention` | 175 | `severity.critical` from `/dashboard/severity` | ❌ | ❌ | Cherry-picks Critical only; High (790) is also exploitable per CVSS. 175 itself is 5× inflated. There is no "require attention" filter (no `is_suppressed`, no triage state — see schema audit). |
| 5 | Severity bar — Critical | 175 | `severity.critical` | ❌ | ✅ | 5× inflated. |
| 6 | Severity bar — High | 790 | `severity.high` | ❌ | ✅ | 5× inflated. |
| 7 | Severity bar — Medium | 650 | `severity.medium` | ❌ | ✅ | 5× inflated. |
| 8 | Severity bar — Low | 225 | `severity.low` | ❌ | ✅ | 5× inflated. |
| 9 | Severity bar — Unknown | 25 | `severity.unknown` | ❌ | ❌ | 5× inflated; rendered as a severity tier alongside Crit/High/Med/Low (user's prompt §9). Unknown is a data-quality signal (CVSS unscored), not a severity. |
| 10 | `Risk Index 42,925` | 42,925 | client `severityWeight()` ([`HeroRiskPulse.tsx:78-82`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L78-L82)) | ⚠️ Formula matches displayed value, but the formula itself is undocumented and includes `Unknown`. | ❌ | Verified: `175*100 + 790*25 + 650*8 + 225*2 + 25 = 42,925`. The user's prompt suggested `100/25/5/1` weighting → 40,725; **the actual code uses `100/25/8/2/1` (incl. Unknown)**. No tooltip, no ADR. P1 (D4). |
| 11 | `30-day weighted trend` sparkline | (sparkline) | `/dashboard/trend?days=30`, weighted client-side `crit*4 + high*1 + med*0.4 + low*0.1` ([`HeroRiskPulse.tsx:134`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L134)) | ⚠️ Sample interval correct (per-day group-by); weighting is **inconsistent** with the delta computation. | ❌ | Two different weight vectors in same component for "the same" weighted trend (D7). Trend backend does not filter by `run_status`, so failed/duplicate-rerun spikes appear as trend events. |
| 12 | Hero `delta % vs prior period` | (e.g. "5% vs prior") | `computeDelta()` over series with weights `crit*100 + high*25 + med*8 + low*2` ([`HeroRiskPulse.tsx:93`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L93)) | ⚠️ | ❌ | Weight mismatch with sparkline (D7). |
| 13 | Hero `Security posture · LIVE` pill | "LIVE" | client react-query `isFetching` only | ❌ | ❌ | Never reflects API health, NVD mirror, or run-status. Always green-pulsing. State-coherence break with the `Degraded` footer (D6). |
| 14 | KPI `Active Projects = 1` | 1 | `count(Projects.id)` ([`dashboard_main.py:30`](app/routers/dashboard_main.py#L30)) | ⚠️ Happens to be right today (only one project, status=1) but query does not filter `project_status`. Will silently inflate as soon as anyone creates an inactive project. | ❌ | Label says "Active" — query doesn't enforce that (D5). |
| 15 | KPI `Total SBOMs = 1` | 1 | `count(SBOMSource.id)` | ⚠️ Stale: DB now has 2 SBOMs (`Test Sbom`, `Test1`); the screenshot is from before SBOM #2 was uploaded. | ✅ | Number itself is correctly defined (no scope filter needed). |
| 16 | KPI `Total Vulnerabilities = 1,865` | 1,865 | `count(AnalysisFinding.id)` | ❌ | ❌ | This is finding count, not vulnerability count. True distinct CVEs in scope = 373 (`count distinct vuln_id`). Label and query disagree on what the noun means (D2). |
| 17 | KPI `Total Vulnerabilities` link href | `/analysis?tab=runs&status=FAIL` | hardcoded ([`StatsGrid.tsx:65`](frontend/src/components/dashboard/StatsGrid.tsx#L65)) | ❌ | ❌ | Clicking the vuln count drills into runs filtered to FAIL only — relies on the overloaded FAIL meaning (D1) and looks like leaked debug. Same pattern hardcoded in `SeverityChart` slice click ([`SeverityChart.tsx:66`](frontend/src/components/dashboard/SeverityChart.tsx#L66)). |
| 18 | Sidebar `Recent runs · FAIL · FAIL` | "FAIL" | `analysis_run.run_status`, set by [`compute_report_status` `analysis_service.py:96-111`](app/services/analysis_service.py#L96-L111) — `if total_findings > 0: return "FAIL"` | ⚠️ Faithful to the (broken) source of truth. | ❌ | **Both runs in the screenshot did not actually fail** — they completed and produced 373 findings each. The status name FAIL means "findings exist" here. This is the single biggest semantic bug in the system (D1). |
| 19 | Footer `Degraded — NVD mirror disabled` | string | [`SidebarStatus.tsx:72-128`](frontend/src/components/layout/SidebarStatus.tsx#L72-L128) reading `GET /health.nvd_mirror.{available,enabled,stale}` | ✅ This one is right. | ⚠️ | The label is correct; the problem is that the hero doesn't subscribe to the same signal (D6). |

---

## 4. Schema audit — what the DB *can't* support today

The prompt suggests the dashboard should hide "suppressed" findings, surface "fix-available" findings, and treat "latest successful run" as the source of truth. The current schema cannot do any of this without migration.

| Capability needed | Schema today | Gap |
|---|---|---|
| Suppress / triage findings (hide from "require attention") | `AnalysisFinding` has no `is_suppressed`, `triage_state`, or `assigned_to` columns ([`models.py:152-185`](app/models.py#L152-L185)). | No way to compute "actionable findings" without a migration. |
| "Latest successful run per SBOM" | No `is_latest` flag, no `superseded_by`. Must compute on every read with `MAX(started_on) GROUP BY sbom_id WHERE run_status='PASS'`. | Doable via SQL but no helper exists; every dashboard query today aggregates across **all** runs. |
| Distinct CVE count | `vuln_id` is the CVE-id-ish identifier, with `aliases` JSON column for cross-feed dedup. No materialized "vulnerability" entity. | `count(distinct vuln_id)` is the right query — backend currently uses `count(*)`. |
| Fix-available count | `fixed_versions` text column on findings exists. ✅ Usable. | Just not surfaced by any current dashboard endpoint. |
| KEV / EPSS surfacing on the hero | `KevEntry`, `EpssScore` tables exist ([`models.py:204-225,293-311`](app/models.py#L204-L225)). ✅ Usable. | Hero never reads them. |

The good news: the rich data the user wants on a real security hero (KEV count, fix-available count, exploitable-band count) is **in the DB already** — just not on the dashboard.

---

## 5. The "FAIL" overload — single root cause for many symptoms

[`compute_report_status` (analysis_service.py:96-111)](app/services/analysis_service.py#L96-L111):

```python
def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    if total_findings > 0:
        return "FAIL"           # ← "findings exist" overloaded as "the run failed"
    if query_errors:
        return "PARTIAL"
    return "PASS"
```

Consequences chained from this one decision:

1. The "Recent runs · FAIL · FAIL" panel reads as a pipeline outage when it isn't.
2. The "Total Vulnerabilities" KPI card href deep-links to `?status=FAIL` because that's the *only* way to find runs with findings.
3. Severity chart slice clicks do the same (`?status=FAIL&severity=…`).
4. Any future "filter dashboard to successful runs only" code is incoherent — there are no successful runs once a SBOM has any findings.
5. The user can't tell, from the dashboard, whether NVD/OSV/GHSA actually failed or whether the analyzer ran fine and just found CVEs.

**Recommendation (deferred to Phase 2):** rename run-status enum: `OK | FINDINGS | PARTIAL | ERROR | RUNNING | NO_DATA`, where `FINDINGS` is the new name for the current `FAIL`, and `ERROR` is reserved for actual technical failure. Migration will need a one-liner to remap rows. UI string changes flow from there.

---

## 6. Open questions for Feroze (please confirm before Phase 2)

1. **Inflation policy.** The user's prompt says "use latest successful run only, by default". But under D1 there are no successful runs. Two options:
   - (a) Phase 2 ships the run-status rename (`FAIL→FINDINGS`) and *then* "latest non-error run per SBOM" becomes well-defined.
   - (b) Phase 2 ships a stop-gap: dashboard queries take only `MAX(started_on) per sbom_id` regardless of status. Lower blast radius, fixes the inflation today.
   I recommend **(b) first, (a) as a follow-up ADR**, but want your call.

2. **Risk Index — keep or drop?**
   Per the prompt's rules: a magic number with no formula is unfit for a security product. Three options:
   - (a) Keep the existing `100/25/8/2/1` weighting, document it in `docs/risk-index.md`, add a tooltip, drop `Unknown` from the formula (it shouldn't contribute to risk).
   - (b) Replace with the prompt's suggested `100/25/5/1` and accept the displayed number changes from 42,925 → 40,725.
   - (c) Remove the Risk Index from the hero entirely and replace with **KEV count + fix-available count** (data we already have). My recommendation.
   Your call.

3. **Posture model.**
   Prompt suggests `Clean / Stable / Action needed / Urgent / Degraded`. My one tweak: split `Action needed` into `Action needed (High)` and `Urgent (Critical)` only by visual treatment, not by separate copy. And `Degraded` should *additionally* gate on "data older than N hours". What's N? I'll default to **24h** unless you say otherwise.

4. **"Findings" vs "Vulnerabilities" lockdown.**
   Recommended definitions to commit to `docs/terminology.md`:
   - **Vulnerability** = distinct `vuln_id` (CVE/GHSA id) in scope.
   - **Finding** = one `AnalysisFinding` row = (component × vuln_id × run).
   - **Component** = one `SBOMComponent` row.
   - **Run** = one `AnalysisRun` row.
   Confirm or amend.

5. **`Active Projects` semantics.**
   I will change the query to `count(*) where project_status = 1`. Confirm Inactive projects (`project_status = 0`) should NOT appear in this KPI.

---

## 7. What Phase 2 will change (preview only — not yet executed)

If you confirm the above, Phase 2 will:

- Rewrite `/dashboard/stats`, `/dashboard/severity`, `/dashboard/trend` to scope to *latest non-error run per SBOM*.
- Add `/dashboard/posture` returning the computed band + reasons (single source for hero, footer, status pill).
- Replace hero headline with posture-aware copy + honest action-band count.
- Move `Unknown` out of the severity bar into a separate data-quality pill.
- Fix singular/plural with `Intl.PluralRules`.
- Wire the `LIVE` pill to `/health` + posture (kill the always-green pulse).
- Either document or remove Risk Index per your call on (Q2).
- Fix `Active Projects` query.
- Fix the leaked `?status=FAIL` deep-links in `StatsGrid` and `SeverityChart`.
- Lock terminology in `docs/terminology.md` and rename "Total Vulnerabilities" KPI to either honestly count distinct CVEs (preferred) or relabel as "Total Findings".

**No code or string changes will be made until you confirm.**
