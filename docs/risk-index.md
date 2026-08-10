# Risk Index — removed and replaced

**Status:** The "Risk Index" hero tile (e.g. `42,925`) was **removed** on 2026-04-30. This document records the removal, the formula it had, and what replaced it.

## What was removed

The hero displayed a tile labelled `Risk Index` with a single number, computed client-side in `HeroRiskPulse.tsx`:

```ts
function severityWeight(s: SeverityData): number {
  return s.critical * 100 + s.high * 25 + s.medium * 8 + s.low * 2 + s.unknown;
}
```

For the screenshot data (`Critical=175, High=790, Medium=650, Low=225, Unknown=25`):

```
175*100 + 790*25 + 650*8 + 225*2 + 25*1
=  17,500 + 19,750 + 5,200 + 450 + 25
=  42,925
```

The number was reproducible, but it had three problems:

1. **No documented formula.** Tooltip absent, ADR absent. A SOC engineer could not defend the number to anyone.
2. **`Unknown` was treated as a severity.** Unknown is a CVSS-unscored data-quality signal, not an exploitability tier. Including it inflated the index for SBOMs whose CPE coverage was poor.
3. **Inflated by reruns.** Until the run-status rename and "latest run per SBOM" scoping (ADR-0001), every rerun of the same SBOM multiplied this number.

## Why we removed instead of renaming/documenting

The index conflated severity, exploitability, and asset criticality into one opaque scalar. Industry practice (FAIR, EPSS, CISA SSVC) splits these. Two alternatives were considered:

- (a) Document the existing weights and add a tooltip — **rejected** because the formula is still arbitrary and the audience would still ask "vs. what threshold?"
- (b) Adopt FIRST.org EPSS or KEV directly — **adopted** because both have public provenance, are already cached in our schema (`epss_score`, `kev_entry`), and answer real questions ("is this exploited in the wild?", "is there an EPSS-predicted exploit probability?").

## What replaced it

The hero now shows two numbers tied to specific public sources:

### KEV count
- **Definition:** Distinct findings (de-duplicated by `vuln_id`, scoped to *latest non-error run per SBOM*) whose CVE appears in the CISA Known Exploited Vulnerabilities Catalog.
- **Source:** `kev_entry` table, refreshed every 24h from `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`.
- **Why it matters:** Presence on KEV is the single highest-signal exploitability indicator in public vulnerability data — it means the CVE has been observed exploited in the wild.

### Fix-available count
- **Definition:** Distinct findings (same scope) whose `fixed_versions` array is non-empty.
- **Source:** `analysis_finding.fixed_versions` (parsed from upstream feeds during analysis).
- **Why it matters:** This is the operationally actionable subset. Tells the team which findings can be remediated by a version bump *today* without waiting for an upstream patch.

## Worked example (current DB, 2026-04-30)

After ADR-0001's "latest run per SBOM" scoping, the headline numbers reduce from `2,984 findings` (8 reruns × 373) to `373 findings` (one latest run × one SBOM). KEV and fix-available counts will be computed from this scoped set.

```sql
-- distinct vulnerabilities in scope
select count(distinct f.vuln_id)
from analysis_finding f
join analysis_run r on r.id = f.analysis_run_id
where r.id in ( -- latest non-error run per sbom
  select max(id) from analysis_run
  where run_status in ('OK','FINDINGS','PARTIAL')
  group by sbom_id
);

-- KEV count
select count(distinct f.vuln_id)
from analysis_finding f
join analysis_run r on r.id = f.analysis_run_id
join kev_entry k on k.cve_id = f.vuln_id
where r.id in ( ... same subquery ... );

-- fix-available count
select count(distinct f.vuln_id)
from analysis_finding f
join analysis_run r on r.id = f.analysis_run_id
where r.id in ( ... same subquery ... )
  and f.fixed_versions is not null
  and f.fixed_versions != '[]'
  and f.fixed_versions != '';
```

## What the hero no longer claims

- It does not claim a portfolio "risk score". Risk depends on asset criticality and exploitability context which are not in scope of an SBOM scanner.
- It does not claim a "weighted trend" without naming the weights. The trend chart now shows finding count over time and the weights, if any, are documented in a tooltip.
