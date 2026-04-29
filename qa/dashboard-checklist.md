# Dashboard QA Checklist — ADR-0001 ship-ready

Run this before merging. Tick each box; if any fail, file a P0 against the ADR-0001 work and don't merge.

**Pre-flight (one-time per environment):**

- [ ] `alembic upgrade head` ran cleanly. `005_rename_run_status` is in `alembic_version`.
- [ ] `sqlite3 sbom_api.db "SELECT DISTINCT run_status FROM analysis_run"` returns ONLY values from `{OK, FINDINGS, PARTIAL, ERROR, RUNNING, PENDING, NO_DATA}` — no `FAIL`, no `PASS`.
- [ ] Backend tests pass: `pytest tests/ -q` → 287+ passing.
- [ ] Frontend tests pass: `cd frontend && npx vitest run` → 27+ passing.
- [ ] Frontend type-check clean: `cd frontend && npx tsc --noEmit` → no errors.

## A. Hero — semantic correctness

- [ ] **Hero never shows the literal string "Critical risk"** — replaced by posture-aware copy from `derivePosture`.
- [ ] With current DB state (multiple runs of one SBOM with Critical findings), hero shows **"Urgent attention required"** and a red chip — NOT a plain "Critical" word.
- [ ] Hero subtext **never** prints `"1 SBOMs in 1 projects"` — it pluralizes via `pluralize()`. Verify with seed of exactly 1 SBOM and 1 active project: subtext reads `"1 SBOM in 1 active project"`.
- [ ] Hero "X findings" chip uses `pluralize`: 1 finding → `"1 finding"`; 0 → `"0 findings"`; 2,984 → `"2,984 findings"` (with thousands separator).
- [ ] Severity bar shows **only** Critical / High / Medium / Low. **Unknown is rendered as a separate small pill** below the bar reading `"N with unscored severity"`.
- [ ] Tooltip on the Unknown pill explains it's a data-quality signal, not a severity.
- [ ] Critical/High/Medium/Low colors meet WCAG 2.2 AA contrast on both light and dark themes (manual eyeball + axe extension).

## B. Hero — numeric correctness

- [ ] **Risk Index tile is GONE.** Replaced by two tiles: `On CISA KEV` and `Fix available`. Hovering each shows a tooltip with provenance.
- [ ] Hero numbers match SQL ground truth (run these queries and compare to what you see):

```sql
-- Distinct CVEs in scope (this is the new "Distinct Vulnerabilities" KPI)
SELECT COUNT(DISTINCT vuln_id) FROM analysis_finding
WHERE analysis_run_id IN (
  SELECT MAX(id) FROM analysis_run
  WHERE run_status IN ('OK','FINDINGS','PARTIAL')
  GROUP BY sbom_id
);

-- Severity buckets in scope (this is what the bar segments must equal)
SELECT severity, COUNT(*) FROM analysis_finding
WHERE analysis_run_id IN (
  SELECT MAX(id) FROM analysis_run
  WHERE run_status IN ('OK','FINDINGS','PARTIAL')
  GROUP BY sbom_id
) GROUP BY severity;

-- KEV count
SELECT COUNT(DISTINCT f.vuln_id)
FROM analysis_finding f JOIN kev_entry k ON k.cve_id = f.vuln_id
WHERE f.analysis_run_id IN (
  SELECT MAX(id) FROM analysis_run
  WHERE run_status IN ('OK','FINDINGS','PARTIAL')
  GROUP BY sbom_id
);
```

- [ ] After running the same SBOM twice in a row, hero numbers **do not double**. (Pre-fix: 5 reruns produced 5x findings; post-fix: latest-run-per-SBOM scoping is enforced server-side.)
- [ ] After running an SBOM whose analysis ERRORs out, hero numbers **do not change** — ERROR runs are excluded from severity / KEV / fix-available counts.

## C. State coherence

- [ ] Stop the API (`pkill -f run.py`); refresh dashboard. Within 30s, hero pill flips from green to amber, headline changes to "Posture unavailable", reason mentions "API". Sidebar `Degraded` indicator agrees.
- [ ] Restore API. Within 30s, hero recovers to its severity-derived band.
- [ ] Disable NVD mirror via env. Hero reflects `degraded` band, reason mentions "NVD mirror".
- [ ] Touch a successful run's `completed_on` to be 25h ago in the DB (`UPDATE analysis_run SET completed_on = ... WHERE id = X`). Hero must flip to `degraded` with reason "Data is older than 24h".

## D. Run-status rename — UI surfaces

- [ ] Sidebar "Recent" feed: a run that produced findings shows label "Findings detected" with **amber** styling — NOT "FAIL", NOT red.
- [ ] Run detail page hero (`/analysis/{id}`): same — amber, "Findings detected".
- [ ] SBOM list table status column: same — amber.
- [ ] Filter dropdown on `/analysis?tab=runs`: dropdown option reads "Vulnerabilities found" (label) but the underlying enum value sent in the URL is `FINDINGS`. Old `?status=FAIL` URLs still work via the legacy alias accepted by `normalize_run_status`.
- [ ] Clicking the "Distinct Vulnerabilities" KPI card navigates to `/analysis?tab=runs&status=FINDINGS`, NOT `&status=FAIL`.
- [ ] Clicking a SeverityChart slice navigates to `&status=FINDINGS&severity=...`.

## E. Active Projects KPI

- [ ] Create an inactive project (`project_status = 0`) via the API. **Active Projects KPI does NOT increment.**
- [ ] Reactivate the project (`project_status = 1`). **Active Projects KPI increments by 1.**

## F. Distinct vs. finding count

- [ ] Seed an SBOM with one CVE that affects three components in the same SBOM. Run analysis. Verify:
  - Severity bar segments sum to 3 findings.
  - "Distinct Vulnerabilities" KPI increases by 1.
  - These two numbers are **different** by design — they're not synonyms.

## G. Accessibility

- [ ] Hero headline has `aria-live="polite"` — announce on band change without interrupting other reads.
- [ ] All KPI cards have `title` and `aria-label` describing exactly what they count.
- [ ] Severity bar has `role="img"` and an aria-label that lists each severity + count.
- [ ] Tab navigation: Tab through hero → KPIs → severity chart → trend → top vulnerable → activity feed without traps.
- [ ] Screen reader (VoiceOver / NVDA): hero copy is read in a sensible order; KPI tooltips are announced on focus.

## H. Empty state

- [ ] Fresh DB with zero SBOMs: hero band is `empty`, headline reads "Ready to scan", subtext is the onboarding copy. No misleading numbers.

## I. Performance budget (no regressions)

- [ ] Network panel: `/dashboard/posture` response < 200ms uncached, < 50ms cached (304 via ETag).
- [ ] Lighthouse on `/`: FCP < 1.5s, LCP < 2.5s, CLS = 0, INP < 200ms (run with throttled CPU 4× to mimic mid-tier hardware).

## J. Backwards compatibility (one release window)

- [ ] Old `GET /api/runs?run_status=FAIL` still returns the FINDINGS-status rows (legacy alias).
- [ ] Old payloads with `total_vulnerabilities` field in response still parse on frontend (the field is kept as an optional alias on `DashboardStats`).

## Sign-off

- [ ] Feroze visually verified hero against real data and the screenshot from the audit no longer represents reality.
- [ ] No regressions in the runs page, SBOM list, or schedules page.
- [ ] PR description references `docs/dashboard-audit.md` and `docs/adr/0001-dashboard-posture-model.md`.
