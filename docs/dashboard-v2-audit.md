# Dashboard v2 — Discovery & Content Audit (Phase 1, read-only)

**Audit date:** 2026-05-02
**Branch:** `claude/modest-satoshi-80649e`
**Scope:** Home dashboard (`/`) — hero, quick actions, stats grid, donuts, trend, top-vulnerable list, activity feed, sidebar status footer.
**Goal:** Map every visible element to its data source, diagnose the broken trend chart, and inventory what lifetime/cumulative data the system can already supply for the v2 redesign. **No code changed.**

> The prior audit at [docs/dashboard-audit.md](docs/dashboard-audit.md) (2026-04-30) scoped pre-ADR-0001 defects (overloaded `FAIL` status, unscoped finding counts, undocumented Risk Index). Most of those have been remediated on the `00bf257` line. **This audit is forward-looking** — it documents the *current, post-ADR-0001* surface so the v2 redesign can plan against accurate state.

---

## 0. Executive summary

| # | Finding | Phase that addresses it |
|---|---|---|
| F1 | The Findings Trend chart is broken because the backend returns only days that have findings — no zero-fill. With the live DB containing one day of run history (`2026-04-30`, 1,259 findings), the chart receives a 1-point series and Recharts renders dots without a connecting line/area. | Phase 3 — backend zero-fill |
| F2 | The "**Urgent attention required**" headline is locked into [`dashboardPosture.ts:150`](frontend/src/lib/dashboardPosture.ts#L150) (`POSTURE_COPY['urgent']`) for *any* DB state with ≥1 critical, regardless of KEV exposure or scope. The v2 brief calls for state-specific copy with KEV-aware framing. | Phase 2 — copy rules; Phase 3 — server-side `headline_state` |
| F3 | The `Degraded · NVD mirror disabled` widget lives in the **left sidebar footer** (`SidebarStatus`), not the dashboard body. It is therefore visible on *every* authenticated page — projects, SBOMs, schedules — making "remove from user dashboard" actually a multi-page change. The v2 brief calls for it to move to an admin-only surface. | Phase 4 — relocate behind admin role / replace with neutral mirror-synced timestamp |
| F4 | All lifetime/cumulative data the v2 brief requires is **already derivable** from the existing schema — no migrations needed. Only `findings_resolved_total` requires an O(N runs²) cross-run join; cache-friendly. | Phase 3 — new `/dashboard/lifetime` endpoint |
| F5 | "Active Projects", "Total SBOMs", "Distinct Vulnerabilities" counter cards (Image 1 row 3) and the two donuts (Image 1 row 4) are slated for removal in the v2 layout. Their data sources stay live for `posture` consumption — only the visual cards are deleted. | Phase 4 — frontend removals |
| F6 | KEV count is computed correctly (in-scope, distinct, joined to `kev_entry`). `kev_entry.date_added` is the **CISA listing date**, not "when this vuln first appeared in our findings"; `kev_first_seen` annotations therefore need either (a) a new `first_seen_at` derived from `min(started_on) per vuln_id` or (b) listing-date as a proxy. v1 of the redesign should accept the (a) path computed live (cached 15m) and skip the annotation if no signal. | Phase 3 — annotations service (best-effort) |
| F7 | No Redis cache is wired for dashboard endpoints today — only `cve_cache` (Postgres table) and `compare_cache`. The redis_url setting exists for Celery, not dashboard. Phase 3's "1h Redis cache for lifetime, 15m for trend" needs either an in-process LRU + ETag (already in use via `maybe_not_modified`) or new Redis plumbing. ETag-based revalidation is sufficient for current single-tenant scope. | Phase 3 — caching choice |

---

## 1. UI → API → Backend → Table data-flow map

### 1.1 Above-the-fold (Image 1)

| UI element | Component | API call | Backend route | SQL / source |
|---|---|---|---|---|
| Hero `Security posture · live` pill | [`HeroRiskPulse.tsx:239-245,265-275`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L239) | `getHealth`, `derivePosture` | `GET /health` ([`health.py:85`](app/routers/health.py#L85)) + posture | `data.status === 'ok'`, posture band (state machine) |
| Hero headline `Urgent attention required` | [`HeroRiskPulse.tsx:280` ← `copy.headline`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L280) | `getDashboardPosture` | `GET /dashboard/posture` | `POSTURE_COPY[band]` lookup at [`dashboardPosture.ts:143-153`](frontend/src/lib/dashboardPosture.ts#L143) |
| Hero subtext `Aggregated across 3 SBOMs in 1 active project — 513 distinct vulnerabilities. 0 exploitable findings.` | [`HeroRiskPulse.tsx:196-234`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L196) | `getDashboardStats` + `getDashboardPosture` | `GET /dashboard/stats`, `/dashboard/posture` | counts in §1.4 below |
| Severity distribution bar | [`HeroRiskPulse.tsx:305-356`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L305) | `getDashboardPosture` | `/dashboard/posture` → `severity` | `count(*) GROUP BY severity` over latest successful run per SBOM |
| Hero `On CISA KEV` tile | [`HeroRiskPulse.tsx:363-369`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L363) | same | same | `count(distinct vuln_id) JOIN kev_entry` ([`dashboard_main.py:187-194`](app/routers/dashboard_main.py#L187)) |
| Hero `Fix available` tile | [`HeroRiskPulse.tsx:370-376`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L370) | same | same | `count(distinct vuln_id) WHERE fixed_versions IS NOT NULL/'[]'/''` ([`dashboard_main.py:199-209`](app/routers/dashboard_main.py#L199)) |
| Hero 30-day mini sparkline + label | [`HeroRiskPulse.tsx:380-393`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L380) | `getDashboardTrend(30)` | `GET /dashboard/trend?days=30` ([`dashboard.py:22`](app/routers/dashboard.py#L22)) | `count(*) GROUP BY date(started_on), severity` (no zero-fill — see F1) |
| Hero `View runs` link | [`HeroRiskPulse.tsx:415-421`](frontend/src/components/dashboard/HeroRiskPulse.tsx#L415) | — | — (static link to `/analysis?tab=runs`) | — |
| Quick actions row (4 buttons) | [`DashboardQuickActions.tsx:10-52`](frontend/src/components/dashboard/DashboardQuickActions.tsx#L10) | — | — | static |
| Stats card `Active Projects` | [`StatsGrid.tsx:53`](frontend/src/components/dashboard/StatsGrid.tsx#L53) | `getDashboardStats` | `/dashboard/stats` → `total_active_projects` | `count(Projects.id) WHERE project_status=1` ([`dashboard_main.py:72-74`](app/routers/dashboard_main.py#L72)) |
| Stats card `Total SBOMs` | [`StatsGrid.tsx:64`](frontend/src/components/dashboard/StatsGrid.tsx#L64) | same | same → `total_sboms` | `count(SBOMSource.id)` ([`dashboard_main.py:75`](app/routers/dashboard_main.py#L75)) |
| Stats card `Distinct Vulnerabilities` | [`StatsGrid.tsx:75`](frontend/src/components/dashboard/StatsGrid.tsx#L75) | same | same → `total_distinct_vulnerabilities` | `count(distinct vuln_id) WHERE run_id IN latest-successful-per-sbom` ([`dashboard_main.py:85-91`](app/routers/dashboard_main.py#L85)) |
| Donut `Vulnerability severity` | [`SeverityChart.tsx:53-184`](frontend/src/components/dashboard/SeverityChart.tsx#L53) | `getDashboardPosture` (via prop `posture.severity`) | `/dashboard/posture` → `severity` | same as severity bar |
| Donut `SBOM activity` (Active 30d / Stale) | [`ActivityChart.tsx:23-102`](frontend/src/components/dashboard/ActivityChart.tsx#L23) | `getDashboardActivity` | `GET /dashboard/activity` ([`dashboard_main.py:121`](app/routers/dashboard_main.py#L121)) | `count(SBOMSource) WHERE created_on >= now-30d` vs total |

### 1.2 Below-the-fold (Image 2)

| UI element | Component | API call | Backend route | SQL / source |
|---|---|---|---|---|
| `Findings trend · last 30 days` chart | [`TrendChart.tsx:69-240`](frontend/src/components/dashboard/TrendChart.tsx#L69) | `getDashboardTrend(30)` | `/dashboard/trend?days=30` | **broken — see §3** |
| `Top vulnerable SBOMs` list | [`TopVulnerableSboms.tsx:57-`](frontend/src/components/dashboard/TopVulnerableSboms.tsx#L57) | `getRuns({run_status:'FINDINGS', page_size:100})` | `/api/runs?run_status=FINDINGS` (not in dashboard router — `runs.py`) | client-side aggregate; weight = `crit*100 + high*25 + med*8 + low*2` |
| `Recent activity` feed | [`ActivityFeed.tsx`](frontend/src/components/dashboard/ActivityFeed.tsx) | `getRecentSboms`, `getRuns` | `GET /dashboard/recent-sboms`, `GET /api/runs` | recent rows by `id desc` |

### 1.3 Sidebar footer (every page)

| UI element | Component | API call | Backend route | SQL / source |
|---|---|---|---|---|
| `Degraded · NVD mirror disabled` widget | [`SidebarStatus.tsx:61-133`](frontend/src/components/layout/SidebarStatus.tsx#L61) | `getHealth` (polled 30s) | `GET /health` | `data.nvd_mirror.{enabled,available,stale,last_success_at}` ([`health.py:94-148`](app/routers/health.py#L94)) |

> Mounted by [`Sidebar.tsx:144-146`](frontend/src/components/layout/Sidebar.tsx#L144) — appears on **every authenticated page**, not just `/`. The redesign brief calls this out as "user-facing dashboard"; the actual surface is the global app shell.

### 1.4 Effective scoping rules (post-ADR-0001)

All hero / posture aggregates are scoped to **the latest successful run per SBOM**, where successful = `{OK, FINDINGS, PARTIAL}`. Subquery: [`dashboard_main.py:42-54`](app/routers/dashboard_main.py#L42).

`ERROR`, `RUNNING`, `PENDING`, `NO_DATA` runs are excluded — their findings may be partial/wrong. The trend endpoint applies the same filter at [`dashboard.py:57-58`](app/routers/dashboard.py#L57).

---

## 2. Component / file inventory

### 2.1 Frontend (Next.js 15 / React 19)

| Path | Role |
|---|---|
| [`frontend/src/app/page.tsx`](frontend/src/app/page.tsx) | Dashboard route. Mounts five `useQuery` hooks, lays out hero → quick actions → stats grid → severity+activity grid → trend → top-vulnerable+activity-feed. |
| [`frontend/src/components/dashboard/HeroRiskPulse.tsx`](frontend/src/components/dashboard/HeroRiskPulse.tsx) | Hero card. 461 LOC, computes `result` from `derivePosture`, renders headline + severity bar + KEV/Fix tiles + sparkline + delta. |
| [`frontend/src/components/dashboard/DashboardQuickActions.tsx`](frontend/src/components/dashboard/DashboardQuickActions.tsx) | 4 static link buttons. No state, no data. |
| [`frontend/src/components/dashboard/StatsGrid.tsx`](frontend/src/components/dashboard/StatsGrid.tsx) | 3 counter cards (Active Projects / Total SBOMs / Distinct Vulnerabilities). To be deleted in v2. |
| [`frontend/src/components/dashboard/SeverityChart.tsx`](frontend/src/components/dashboard/SeverityChart.tsx) | Recharts `<PieChart>` donut. To be deleted in v2. |
| [`frontend/src/components/dashboard/ActivityChart.tsx`](frontend/src/components/dashboard/ActivityChart.tsx) | Hand-rolled SVG ring (active vs stale). To be deleted in v2. |
| [`frontend/src/components/dashboard/TrendChart.tsx`](frontend/src/components/dashboard/TrendChart.tsx) | Recharts `<AreaChart>`, stacked, severity-coloured. Keeps the chart logic — only the data feeding it is broken. v2 enhances this with annotations + reference line + empty-state. |
| [`frontend/src/components/dashboard/TopVulnerableSboms.tsx`](frontend/src/components/dashboard/TopVulnerableSboms.tsx) | Top-5 SBOMs by weighted severity. **Preserved** in v2. |
| [`frontend/src/components/dashboard/ActivityFeed.tsx`](frontend/src/components/dashboard/ActivityFeed.tsx) | Timeline of recent uploads + runs. **Preserved** in v2. |
| [`frontend/src/components/dashboard/RecentSboms.tsx`](frontend/src/components/dashboard/RecentSboms.tsx) | Older list component, not currently mounted on `/`. |
| [`frontend/src/lib/dashboardPosture.ts`](frontend/src/lib/dashboardPosture.ts) | Pure state-machine: `(posture, health) → band ∈ {clean, stable, action_needed, urgent, degraded, empty}`. v2 needs a **6-state replacement** (`clean, kev_present, criticals_no_kev, high_only, low_volume, no_data`) + tone metadata. |
| [`frontend/src/lib/api.ts`](frontend/src/lib/api.ts) | All dashboard endpoint wrappers: `getDashboardStats`, `getDashboardActivity`, `getDashboardSeverity`, `getDashboardPosture`, `getDashboardTrend`, `getRecentSboms`, `getHealth`. |
| [`frontend/src/types/index.ts`](frontend/src/types/index.ts) | `DashboardStats`, `DashboardPosture`, `DashboardTrend`, `DashboardTrendPoint`, `ActivityData`, `SeverityData`, `HealthResponse`. |
| [`frontend/src/components/layout/SidebarStatus.tsx`](frontend/src/components/layout/SidebarStatus.tsx) | The "Degraded · NVD mirror disabled" widget (target for relocation). |
| [`frontend/src/components/ui/Sparkline.tsx`](frontend/src/components/ui/Sparkline.tsx) | Inline mini-trend SVG used by hero. v2 reuses this for the new mini-trend tile. |

### 2.2 Backend (FastAPI / SQLAlchemy 2.x, single-tenant)

| Path | Role |
|---|---|
| [`app/routers/dashboard_main.py`](app/routers/dashboard_main.py) | `GET /dashboard/{stats,recent-sboms,activity,severity,posture}`. Also defines `_latest_successful_run_ids_subq()` — the canonical scoping subquery shared by stats / severity / posture. |
| [`app/routers/dashboard.py`](app/routers/dashboard.py) | `GET /dashboard/trend` — the broken one. 84 LOC, single endpoint. |
| [`app/routers/health.py`](app/routers/health.py) | `GET /health` — feeds the sidebar widget. `_nvd_mirror_health()` returns `{enabled, last_success_at, watermark, stale, counters}` or `{available: false, error}` on failure. |
| [`app/services/analysis_service.py`](app/services/analysis_service.py) | Defines `SUCCESSFUL_RUN_STATUSES = (OK, FINDINGS, PARTIAL)`. |
| [`app/models.py`](app/models.py) | SQLAlchemy models: `Projects`, `SBOMSource`, `AnalysisRun`, `AnalysisFinding`, `KevEntry`, `EpssScore`, `CveCache`, `CompareCache`, `AnalysisSchedule`. |
| [`app/etag.py`](app/etag.py) | `maybe_not_modified` — used by every dashboard route for 304 short-circuiting. |

### 2.3 Pydantic models

There are **no Pydantic response models** for any of the dashboard endpoints today — they all return raw `dict` payloads. OpenAPI schema therefore declares them as untyped `object`. Phase 3 should add response models per the v2 spec (so the frontend types stay in sync via OpenAPI codegen).

---

## 3. Findings Trend chart — root cause

### 3.1 What you see in the screenshot
Two floating dots on `2026-04-30` with no connecting area / line, and the rest of the 30-day window blank.

### 3.2 What the API actually returns

```sh
$ sqlite3 sbom_api.db "
  SELECT substr(started_on,1,10) AS day, count(*) AS finding_count
  FROM analysis_finding f
  JOIN analysis_run r ON r.id=f.analysis_run_id
  WHERE r.run_status IN ('OK','FINDINGS','PARTIAL')
    AND r.started_on >= datetime('now','-30 days')
  GROUP BY day ORDER BY day;"
2026-04-30|1259
```

The endpoint at [`dashboard.py:48-77`](app/routers/dashboard.py#L48) groups `count(*)` by `(date, severity)` and returns only the rows that exist:

```py
series = [{"date": date, **counts} for date, counts in sorted(daily.items())]
```

So the response shape is:
```json
{
  "days": 30,
  "series": [
    {"date": "2026-04-30", "critical": 0, "high": 0, "medium": 1259, "low": 0}
  ]
}
```

A 1-element series. Recharts' `<AreaChart>` cannot draw an area or connecting line from a single datum — it renders the active dot for the hover state and the area-edge marker, which is what you see as "two floating dots."

### 3.3 Three independent breaks in the same chart

1. **Backend zero-fill missing.** No `generate_series` or Python date-range loop. Days with no findings simply do not exist in the response. **This is the primary defect.**
2. **Severity bucketing is silent on `unknown`.** The aggregator at [`dashboard.py:68-74`](app/routers/dashboard.py#L68) only accumulates `critical/high/medium/low` — `unknown` findings are dropped. The hero severity bar renders unknown as a separate pill (correct), but the trend chart silently loses them. Phase 3 should restore unknown to the trend response so the chart can render the same categories the hero does.
3. **No annotations / reference line / empty state.** The current chart renders nothing useful when `series.length < 7`. The brief calls for an explicit `<EmptyState />` and a 30-day-average reference line.

### 3.4 What "fixed" looks like

```json
{
  "days": 30,
  "series": [
    {"date": "2026-04-03", "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0},
    ...28 zero days...,
    {"date": "2026-04-30", "critical": 0, "high": 0, "medium": 1259, "low": 0, "unknown": 0, "total": 1259},
    {"date": "2026-05-01", "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0},
    {"date": "2026-05-02", "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0}
  ],
  "annotations": [
    {"date": "2026-04-29", "kind": "sbom_uploaded", "label": "first SBOM uploaded"},
    {"date": "2026-04-30", "kind": "sbom_uploaded", "label": "+2 SBOMs uploaded"}
  ],
  "avg_total": 41.97,
  "earliest_run_date": "2026-04-30"
}
```

`earliest_run_date` lets the frontend pick between the empty-state and the populated chart (`days_since_first_run < 7 → empty`).

---

## 4. "Degraded · NVD mirror disabled" widget — origin

| Aspect | Finding |
|---|---|
| File | [`frontend/src/components/layout/SidebarStatus.tsx:120-128`](frontend/src/components/layout/SidebarStatus.tsx#L120) |
| Backend feed | `GET /health` ([`health.py:94-148`](app/routers/health.py#L94)) — returns `{nvd_mirror: {enabled: false, ...}}` whenever the mirror is opt-in but unconfigured |
| When it shows | Polls every 30s. Triggers `degraded` band whenever `data.status !== 'ok'` OR `data.nvd_mirror.stale`. Sub-line shows `"NVD mirror disabled"` whenever `data.nvd_mirror.enabled === false`. |
| Where it shows | Sidebar footer at [`Sidebar.tsx:144-146`](frontend/src/components/layout/Sidebar.tsx#L144). Visible on **every authenticated page** — not just `/`. |
| Why it leaks operator concern to users | The mirror is an admin-controlled feed (CISA mirror under `app/nvd_mirror/`). Whether it is enabled has no bearing on whether the user's own findings are accurate — analysis runs use NVD's public API regardless. The widget is therefore an internal-state leak. |
| Cleanest move (per brief) | Move `SidebarStatus` to an admin-only surface (e.g., `/admin/health`) or replace the user-visible sidebar footer with a non-alarmist neutral element ("Last sync: 2m ago" / collapsed-mode dot only). **Phase 4 work.** |

---

## 5. Lifetime / cumulative data — what's already available

The v2 brief calls for a "Your Analyzer, So Far" section with four tiles. Every metric is computable from existing tables. Live DB values shown for `sbom_api.db@2026-05-02`.

| Metric | SQL (verified) | Live value | Cost |
|---|---|---|---|
| `sboms_scanned_total` | `SELECT count(*) FROM sbom_source` | **3** | O(1), indexed |
| `projects_total` | `SELECT count(*) FROM projects` | **1** | O(1) |
| `runs_executed_total` | `SELECT count(*) FROM analysis_run` | **4** | O(1) |
| `runs_executed_this_week` | `SELECT count(*) FROM analysis_run WHERE started_on >= datetime('now','-7 days')` | **3** | O(1) with index on `started_on` |
| `findings_surfaced_total` (deduplicated) | `SELECT count(DISTINCT (vuln_id, component_name, component_version)) FROM analysis_finding` | **513** | O(N findings); cache 1h |
| `first_run_at` | `SELECT min(started_on) FROM analysis_run WHERE run_status IN ('OK','FINDINGS','PARTIAL')` | **2026-04-30T02:37:29+00:00** | O(1), max-of-min on indexed col |
| `days_monitoring` | `(now - first_run_at).days` (Python) | **2** | derived |

### 5.1 The one expensive metric

| Metric | Approach | Cost |
|---|---|---|
| `findings_resolved_total` | For each SBOM, walk consecutive successful runs ordered by `started_on`; count findings present in run N but absent in run N+1, summed across all consecutive pairs. SQL: a self-join on `analysis_finding` keyed by `(sbom_id, vuln_id, component_name, component_version)` filtered to runs where `run_n+1.id` is the next successful run for that SBOM. | O(N runs × M findings); cache 1h. With 4 runs × 513 distinct findings = ~2k tuples — fine in single tenant. Will need re-thinking past ~10k runs. |

### 5.2 Trend annotation feasibility

| Annotation kind | Source available? | Notes |
|---|---|---|
| `sbom_uploaded` | ✅ `sbom_source.created_on` | Direct query, cheap |
| `remediation` (≥5 findings dropped between consecutive runs) | ✅ derivable from same self-join as `findings_resolved_total` | Cache with that query |
| `kev_first_seen` (a vuln on KEV first appears in our findings on date X) | ⚠️ **No direct field**. Computable as `min(r.started_on) FROM analysis_finding f JOIN analysis_run r ON r.id=f.analysis_run_id JOIN kev_entry k ON k.cve_id=f.vuln_id GROUP BY f.vuln_id`, then filter to "first appearance was within the trend window". Cache 15m. | Doable but moderately costly; the brief says "if not currently tracked, omit and log as follow-up" — so this is **acceptable to ship without** in Phase 3 |
| `scan_failed` | ✅ `analysis_run` rows with `run_status='ERROR'` and `started_on` in window | Cheap. Out of scope per brief — not in the v2 annotation kinds. |

### 5.3 What's missing entirely

Nothing. The schema captured by [`models.py`](app/models.py) is sufficient for every metric in the v2 brief without migration.

If we ever want **per-tenant** lifetime stats (deferred in the brief), we'd need a `tenant_id` column on `Projects`, `SBOMSource`, `AnalysisRun` — but that's the multi-tenant rework, not this audit.

---

## 6. Caching plan (Phase 3 input)

Today, dashboard endpoints rely on ETag-based 304 revalidation via [`maybe_not_modified`](app/etag.py) — no Redis, no in-process LRU. The browser refetches on every navigation; the 304 keeps the round-trip cheap and the query cost zero.

The v2 brief asks for "1h Redis cache for lifetime, 15m for trend." Given:
- Dashboard is single-tenant for now
- Findings churn is once-per-run (not constant)
- ETag already gives us 304s on every unchanged window

**Recommendation:** Keep ETag-based revalidation as the primary mechanism for `/trend` and `/lifetime`. Add a server-side `functools.lru_cache(maxsize=1)` with a 15m TTL keyed by `max(analysis_run.id)` for `/lifetime` so the expensive `findings_resolved_total` query runs at most once per quarter-hour even on cold-start. Defer Redis to multi-tenant rework.

If the team has a strong preference for Redis from day one, the existing `redis_url` setting at [`settings.py:91`](app/settings.py#L91) (Celery broker) is reusable. Defer this decision to the Phase 3 gate.

---

## 7. Preserved / replaced / removed / added — element classification

| Element | v1 | v2 disposition |
|---|---|---|
| Sidebar nav | `Sidebar.tsx` | **Preserved** |
| Recent runs sidebar widget | `Sidebar.tsx` (PinnedSection / RecentSection) | **Preserved** |
| Top bar / breadcrumb | `TopBar.tsx` | **Preserved** |
| Hero card shell (Surface) | `HeroRiskPulse.tsx` | **Preserved** (visual treatment); **Replaced** content (new headline rules + new metric row) |
| Hero `Security posture · live` red dot | `HeroRiskPulse.tsx:264-275` | **Removed** per §4.1 of the brief |
| Hero `Urgent attention required` headline | `dashboardPosture.ts:150` | **Replaced** by 6 new state-driven headlines (Phase 2 §2.1) |
| Hero severity bar | `HeroRiskPulse.tsx:305-356` | **Preserved**, made larger (≥28px) |
| Hero KEV / Fix-available tiles | `HeroRiskPulse.tsx:362-377` | **Replaced** by 4-tile metric row including Net 7d + mini-trend (Phase 2 §2.1) |
| Hero `View runs` link | `HeroRiskPulse.tsx:415-421` | **Replaced** by adaptive primary CTA driven by `headline_state` |
| Quick actions row | `DashboardQuickActions.tsx` | **Preserved** (relocated below hero), **Replaced** primary button by adaptive CTA |
| `Active Projects` / `Total SBOMs` / `Distinct Vulnerabilities` cards | `StatsGrid.tsx` | **Removed** (data reincarnates in the new "Your Analyzer, So Far" section) |
| `Vulnerability severity` donut | `SeverityChart.tsx` | **Removed** |
| `SBOM activity` donut | `ActivityChart.tsx` | **Removed** |
| `Findings trend · last 30 days` chart | `TrendChart.tsx` + `dashboard.py` | **Preserved** chart, **Replaced** data feed (zero-fill, annotations, reference line, empty state) |
| `Top vulnerable SBOMs` | `TopVulnerableSboms.tsx` | **Preserved** as-is |
| `Recent activity` timeline | `ActivityFeed.tsx` | **Preserved** as-is |
| Sidebar `Degraded · NVD mirror disabled` footer | `SidebarStatus.tsx` | **Removed** from user surface; relocated to admin route in Phase 4 |
| Pydantic response models | (none today) | **Added** — Phase 3 |
| `/dashboard/lifetime` endpoint | (none today) | **Added** — Phase 3 |
| `headline_state` + `primary_action` on `/dashboard/posture` (or `/summary`) | (none today) | **Added** — Phase 3 §3.3 |

---

## 8. Phase-2 inputs already locked

The v2 brief specified these in §2; this audit confirms each is accurate / feasible:

- ✅ Six headline states are deterministic from `(critical, high, medium, low, kev_count, sbom_count)` — all available on `/dashboard/posture` today.
- ✅ Four hero metric tiles can be served from existing endpoints; only `Net 7-day change` is new (added/resolved). Resolved requires the cross-run join from §5.1.
- ✅ Four lifetime tiles served from `/dashboard/lifetime` (new endpoint, no migration).
- ✅ Trend annotations: `sbom_uploaded` and `remediation` are cheap; `kev_first_seen` is best-effort (omit if signal unavailable).
- ✅ Empty state when `points.length < 7` — backend already returns `earliest_run_date` proposal so frontend can branch deterministically.

---

## 9. Open questions for Phase 2 gate

1. **`Net 7-day change`** — should "added" mean *new vuln_ids* (one per CVE per SBOM) or *new finding rows* (one per CVE × component)? The brief shows `+{added} / -{resolved}` colored by direction; users probably expect "5 more critical CVEs to triage", which is the vuln_id semantic. Recommend vuln_id semantic.
2. **Sidebar widget relocation** — does Phase 4 ship a stub admin route (`/admin/health`) for the relocated mirror status, or simply hide it pending a future admin surface? Stubbing keeps operator visibility; hiding ships faster. Default plan: hide on user pages, retain in collapsed mode as a single neutral dot only.
3. **Caching choice** — ETag-only (recommended for single-tenant now) vs. add Redis from day one (cleaner long-term, more work)?
4. **Headline state ownership** — server-side computation (per brief §2.1) is the right call, but it adds a small amount of business logic to the API surface. Confirm the team is OK with the headline rules being a Python-side concern rather than purely declarative TypeScript copy.

---

**End of audit. No code or strings changed.** Awaiting `continue` to proceed to Phase 2 (information architecture & copy design).
