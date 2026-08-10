# R2 — Merge Report: `persist_analysis_run` & `compute_report_status`

> Audit references: SOLID-SRP-003, DRY-005, DRY-003.

---

## Phase A — Implementation diff

[audit/r2_implementation_diff.md](r2_implementation_diff.md) (234 lines).

Side-by-side analysis of both copies of `persist_analysis_run` and `compute_report_status`, caller inventory, and merge plan. Confirmed the audit's two-field claim and surfaced **14 additional finding-level divergences** that the merge plan reconciled per "production behavior preserved + missing fields added".

---

## Phase B — Regression test

**File**: [tests/test_persist_run_query_errors_regression.py](../tests/test_persist_run_query_errors_regression.py) — 81 lines, single test.

**Mechanism**: monkeypatches `app.analysis.nvd_query_by_components_async` to return one synthetic error, `osv_query_by_components` and `github_query_by_components` to return empty. Calls `POST /api/sboms/{id}/analyze` (the production manual analyze path), then reads the persisted `AnalysisRun` row directly via `SessionLocal` and asserts:

1. `run.query_error_count >= 1`
2. `run.raw_report is not None` and parses as JSON containing the synthetic error message.

### Phase B.3 — confirmed failing on `main` (commit `b5c5180`)

```
tests/test_persist_run_query_errors_regression.py::test_persist_analysis_run_records_query_error_count_and_raw_report FAILED [100%]

>           assert run.query_error_count >= 1, (
                f"query_error_count was {run.query_error_count}; "
                "synthetic NVD error should have been counted (router-side "
                "persist_analysis_run is dropping the field)"
            )
E           AssertionError: query_error_count was 0; synthetic NVD error should have been counted (router-side persist_analysis_run is dropping the field)
E           assert 0 >= 1
E            +  where 0 = <app.models.AnalysisRun object at 0x11ec07530>.query_error_count
========================= 1 failed, 1 warning in 1.55s =========================
```

### Phase D.4 — confirmed passing after fix (commit `9cd3785`)

```
tests/test_persist_run_query_errors_regression.py::test_persist_analysis_run_records_query_error_count_and_raw_report PASSED [100%]
========================= 1 passed, 1 warning in 1.06s =========================
```

---

## Files modified

| File | Lines changed | Notes |
|---|---|---|
| [app/services/analysis_service.py](../app/services/analysis_service.py) | +57 / −12 | merged `persist_analysis_run` body — defensive `vuln_id` fallback (`UNKNOWN-CVE`), `title`/`cvss_version` columns now persisted, `(value or "").strip() or None` pattern adopted for str columns, `references[]` fallback for `reference_url`, JSON-encoded list pattern for `cwe`. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py) | +1 / −113 | deleted local `compute_report_status` and `persist_analysis_run` defs, added `from ..services.analysis_service import compute_report_status, persist_analysis_run`. |
| [app/routers/analyze_endpoints.py](../app/routers/analyze_endpoints.py) | +1 / −1 | swapped `from .sboms_crud import …` → `from ..services.analysis_service import …`. |
| [tests/_normalize.py](../tests/_normalize.py) | +5 / −0 | added `"raw_report"` to `_VOLATILE_KEYS` — the persisted JSON payload embeds non-deterministic timestamps and full per-finding objects; persistence of the field is now directly asserted by the dedicated regression test. |
| [tests/snapshots/post_sbom_analyze.json](../tests/snapshots/post_sbom_analyze.json) | +1 / −1 effective | `raw_report: null → "<volatile>"`, `source: "GITHUB,NVD,OSV" → "NVD,OSV,GITHUB"` (see snapshot section below). |
| [tests/test_persist_run_query_errors_regression.py](../tests/test_persist_run_query_errors_regression.py) | +81 / −0 | new file (Phase B). |

Total across R2 (`8e1eb20..cc7f351`): **6 files, +144 / −128**.

---

## Snapshots regenerated

**1 snapshot regenerated**: [`tests/snapshots/post_sbom_analyze.json`](../tests/snapshots/post_sbom_analyze.json).

Two intentional field changes:

| Field | Old value | New value | Reason |
|---|---|---|---|
| `raw_report` | `null` | `"<volatile>"` | **R2 fix landing.** Router-side `persist_analysis_run` was dropping the field; merged service-side helper now writes `json.dumps(details)`. Payload is non-deterministic (embeds duration ms, completed-on timestamp, full finding objects) so it is volatile-stripped via `_VOLATILE_KEYS` rather than pinned. Persistence is asserted by the regression test. |
| `source` | `"GITHUB,NVD,OSV"` | `"NVD,OSV,GITHUB"` | **Pre-existing snapshot drift, unrelated to R2.** Verified via `git show b5c5180:app/routers/sboms_crud.py` — the `source_label = ",".join(sources_used)` code in `create_auto_report` is byte-identical to current. The current path uses `configured_default_sources()` which honours the `ANALYSIS_SOURCES=NVD,OSV,GITHUB` env order set in `tests/conftest.py:79`. The previous snapshot value was captured against a removed `analyze_sbom_multi_source_async` helper that alphabetised the source list. Re-captured the correct ordering as part of this same fix per user direction (option 1). |

The four `analyze_sbom_*.json` snapshots are unaffected because [`_run_legacy_analysis`](../app/routers/analyze_endpoints.py) builds its response dict explicitly without a `raw_report` field.

---

## Test summary

```
======================= 221 passed, 5 warnings in 9.10s ========================
```

All 221 tests green after Phase D.5. The 5 warnings are pre-existing (Pydantic V2 deprecation, JWT key-length info notes — neither introduced by this PR).

---

## Commits applied

| Commit | Phase | Subject |
|---|---|---|
| `8e1eb20` | A | docs(audit): add R2 implementation diff for persist_analysis_run merge (SOLID-SRP-003, DRY-005, DRY-003) |
| `b5c5180` | B | test(regression): add failing test for persist_analysis_run dropping query_error_count and raw_report (SOLID-SRP-003, DRY-005) |
| `9cd3785` | D | fix(analysis): merge persist_analysis_run + compute_report_status into services/analysis_service — restores query_error_count and raw_report persistence (SOLID-SRP-003, DRY-005, DRY-003) |
| `cc7f351` | D | test(snapshots): regenerate post_sbom_analyze snapshot — query_error_count and raw_report now persisted correctly |

Chronology proves the bug: red between `b5c5180` and `9cd3785`, green at `cc7f351`.

---

> "R2 complete. persist_analysis_run unified in app/services/analysis_service.py. Regression test passing. 1 snapshot(s) regenerated. Awaiting confirmation before push."
