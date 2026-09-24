# VEX Dashboard & Investigation — Manual Test Plan

Everything the `SBOM_VEX` branch adds, in the order a tester would naturally
exercise it. Each item says what to do, what to expect, and — where it
matters — **what must not happen**, because several of these features are
defined by what they refuse to do.

Automated coverage is in [`acceptance-report.md`](./acceptance-report.md);
this is the human pass over the same ground.

---

## 0. Setup

```
start-all.bat
```

- API: <http://localhost:8000> · docs at `/docs`
- UI: <http://localhost:3000>
- `stop-all.bat` shuts both down and leaves PostgreSQL alone.

Prerequisites: `.venv`, `.env`, `frontend/node_modules`, PostgreSQL on 5432,
and the database at Alembic head (`058_vex_source_format`). The API refuses to
start otherwise and says which revision it found.

Test documents:
- SBOM with embedded VEX: `tests/fixtures/vex/sbom-with-embedded-vex.cdx.json`
- Supplier VEX: `supplier-a-openvex.json`, `supplier-a-openvex-v2.json`,
  `supplier-b-openvex-conflicting.json`, `supplier-csaf.json`,
  `version-range-not-applicable.json` (same folder)
- Older demo documents: `samples/vex/`

---

## 1. The new page

**Where:** sidebar → **VEX Investigation** (`/vex-investigation`)

| # | Do this | Expect |
|---|---|---|
| 1.1 | Open the page | Ten summary cards, then a table. The nav entry only appears with `vex:read`. |
| 1.2 | Click **Affected** | Table filters to AFFECTED; the URL gains `?effective_status=AFFECTED`. |
| 1.3 | Click **Needs Review** | Only conflict/revalidation rows remain. |
| 1.4 | Reload the page after filtering | Filters survive — the URL is the source of truth. |
| 1.5 | Type in the search box | One request after you stop typing, not one per keystroke (350 ms debounce). |
| 1.6 | Page through results | No row appears twice and none is skipped. |
| 1.7 | Sort by Vulnerability, then Component | Order changes; the URL records it. |

---

## 2. Reconciliation — the core behaviour

Upload `sbom-with-embedded-vex.cdx.json`, then run an analysis on it.

| # | Scenario | Expect |
|---|---|---|
| 2.1 | A CVE the analyser found, with no VEX | **UNDER_INVESTIGATION** / **ANALYZER_ONLY**. This is the headline change: previously such a finding had no VEX state at all. |
| 2.2 | `CVE-2026-4001` (embedded `false_positive`) | **NOT_AFFECTED** / **VEX_ONLY** — kept even though no scanner found it. |
| 2.3 | Analyser and VEX agree | One row, **MATCHED**. Not two rows. |
| 2.4 | Import `supplier-a-openvex.json` **and** `supplier-b-openvex-conflicting.json` | **CONFLICT_REVIEW_REQUIRED**, flagged amber. Both assertions still listed in the detail view. |
| 2.5 | A VEX says FIXED but the analyser still detects it | **REVALIDATION_REQUIRED**, not "fixed". The supplier's FIXED is still visible as their assertion. |
| 2.6 | Import `supplier-a-openvex-v2.json` after v1 | **MATCHED** with v2's verdict — a newer version of the *same* document supersedes rather than conflicting. The v1 assertion shows a **superseded** badge. |

**Must not happen:** a conflict resolved silently in favour of one supplier.
Disagreement between independent authors always lands in review.

---

## 3. Evidence stays separate

Open any row → detail dialog.

| # | Check | Why it matters |
|---|---|---|
| 3.1 | Three panels: Analyzer Evidence, Imported VEX, Internal Decision | They are never merged. You can always see who said what. |
| 3.2 | An assertion shows **Native** and **Normalized** separately | A CycloneDX `false_positive` reads `false_positive` next to `NOT_AFFECTED`, not only the latter. |
| 3.3 | Import `version-range-not-applicable.json` | The assertion is listed with a **not applicable** badge — retained as evidence, but it did not decide the outcome. |
| 3.4 | Severity on a NOT_AFFECTED row | Still the vulnerability's real severity (e.g. CRITICAL). VEX never rewrites it. |
| 3.5 | History section | Imports and decisions in one chronological list. |

---

## 4. Making a decision

| # | Do this | Expect |
|---|---|---|
| 4.1 | Set **NOT_AFFECTED** with no justification and no impact statement | Rejected, with the reason shown before any request is sent. |
| 4.2 | Set **FIXED** with no fixed version and no evidence | Rejected. |
| 4.3 | Save with an empty reason | Rejected — a reason is always required. |
| 4.4 | Save a valid decision | Row updates; effective status becomes your decision. |
| 4.5 | Open the same row in two tabs, save in both | The second save reports that someone else updated it and reloads. Your first decision is not silently overwritten. |
| 4.6 | Re-run the analysis after deciding | Your decision survives. Last-seen and run id update; the decision does not. |

**Must not happen:** a re-analysis or a later supplier import quietly replacing
an analyst's determination.

---

## 5. Unresolved mappings

An assertion the matcher could not tie to one component — e.g. two components
share a name.

| # | Do this | Expect |
|---|---|---|
| 5.1 | Find an **UNRESOLVED_MAPPING** row | Component shows *Unresolved*; the row is flagged. |
| 5.2 | Check the summary cards | Counted under **Unresolved Mapping**, and **excluded** from Total Contexts — an unresolved mapping never makes risk look smaller. |
| 5.3 | `PUT /api/vex/investigations/{id}/component` with a component in the same SBOM | Binds, re-reconciles, status changes away from UNRESOLVED_MAPPING. |
| 5.4 | Try binding a component from a different SBOM | 404. A determination must not attach to the wrong product context. |

**Must not happen:** the system guessing a component when several match weakly.

---

## 6. Dashboard numbers

| # | Check | Expect |
|---|---|---|
| 6.1 | Affected + Not Affected + Fixed + Under Investigation | Equals **Total Contexts** exactly. |
| 6.2 | Total Contexts vs the analyser finding total on the home dashboard | Deliberately **different** — VEX-only vulnerabilities exist. Not a bug. |
| 6.3 | Apply a filter, compare the card to the table's total | Identical. |
| 6.4 | Home dashboard VEX card | Still present; "Investigating" now includes what used to be counted as Unknown. |
| 6.5 | Mark an SBOM inactive, or upload a newer version | Its contexts drop out of the counts but remain in the database as history. |

---

## 7. Import behaviour

| # | Do this | Expect |
|---|---|---|
| 7.1 | Import the same VEX document twice | Second import reports *already imported*; no duplicate statements. |
| 7.2 | Reformat the document (reorder keys, change whitespace) and import | Still recognised as the same document. |
| 7.3 | Import a CycloneDX SBOM whose `vulnerabilities[]` entry has **no** `analysis` block | Treated as disclosure data — it must **not** become a VEX determination. |
| 7.4 | Import CSAF (`supplier-csaf.json`) | Imports; native status preserved. |

---

## 8. Permissions and isolation

| # | Do this | Expect |
|---|---|---|
| 8.1 | Sign in as a role without `vex:write` (DEVELOPER, VIEWER) | Page is read-only; no Save button. |
| 8.2 | Sign in without `vex:read` | The nav entry is hidden and the page refuses. |
| 8.3 | Call a decision endpoint directly without `vex:write` | Rejected by the backend — UI hiding is never the gate. |
| 8.4 | Request an investigation id belonging to another tenant | **404**, not 403. A 403 would confirm the row exists elsewhere. |

---

## 9. Regression — existing behaviour must be unchanged

| # | Check | Expect |
|---|---|---|
| 9.1 | SBOM detail → **Manage VEX** on a component | Works exactly as before. |
| 9.2 | VEX report (JSON and CSV) | Still generates, with the same columns. |
| 9.3 | `GET /api/sboms/{id}/reports/vex-pack` | ZIP still downloads. |
| 9.4 | Manual override from the component view | Still works, and now also appears in the portfolio queue. |
| 9.5 | Existing dashboards, analysis runs, uploads | Unaffected. |

---

## 10. Known gaps — do not raise these as bugs

| Gap | Detail |
|---|---|
| Sorting by **Severity** | Returns 400 by design. Severity lives on the finding, not the context, so there is nothing to sort on; an arbitrary order would be worse than refusing. Filtering by severity **does** work. Tracked as O-3. |
| VIEWER → 403 not automated | Item 8.3 is worth doing by hand — the automated suite runs with auth disabled. Tracked as O-2. |
| Assignment has no UI | `assigned_to` is settable via `PUT /{id}/assignment` and shows in the Owner column, but there is no control on the page yet. |
| Vendor-hosted discovery | `POST /vex/discover` is unchanged by this workstream and untested here. |

---

## 11. Quick API reference

```
GET    /dashboard/vex
GET    /api/vex/investigations?effective_status=&reconciliation_status=&severity=
                              &component=&q=&needs_review=&sort_by=&limit=&offset=
GET    /api/vex/investigations/{id}
PUT    /api/vex/investigations/{id}/decision      {status, row_version, reason, ...}
PUT    /api/vex/investigations/{id}/assignment    {assigned_to, row_version, reason}
PUT    /api/vex/investigations/{id}/component     {component_id, row_version, reason}
```

`row_version` is mandatory on every mutation; a stale one returns 409 with the
current row.
