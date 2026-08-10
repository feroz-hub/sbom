# R2 — Implementation Diff: `persist_analysis_run` & `compute_report_status`

> Audit references: SOLID-SRP-003, DRY-005, DRY-003.
> Repo HEAD verified at: `f720c29` (`chore: add architectural audit reports and update frontend dependencies`). Audit was on `4435bd2`. Line numbers below are re-verified against the current HEAD.
> Out of scope: third copy of `compute_report_status` at `app/utils.py:39-44` (zero importers — R5 territory).

---

## A.1 — Files read

The following files were read end-to-end before any analysis was performed:

- [app/routers/sboms_crud.py](../app/routers/sboms_crud.py) — 950 lines (router copies live at `:168-173` and `:176-277`).
- [app/services/analysis_service.py](../app/services/analysis_service.py) — 309 lines (service copies live at `:96-111` and `:119-203`).
- [app/routers/analyze_endpoints.py](../app/routers/analyze_endpoints.py) — 416 lines (sole external caller of router copy via `:53` import).
- [app/services/sbom_service.py](../app/services/sbom_service.py) — 288 lines (provides `_upsert_components`, `now_iso`, `safe_int`, `resolve_component_id`, `normalized_key` reused by service-side `persist_analysis_run`).
- [app/services/__init__.py](../app/services/__init__.py) — re-exports `persist_analysis_run` + `compute_report_status` from `analysis_service`.
- [app/utils.py](../app/utils.py) — third (orphaned) copy of `compute_report_status` at `:39-44`. Confirmed zero importers via grep — left untouched (R5).
- [app/models.py](../app/models.py) — confirmed `AnalysisRun.query_error_count` (`:141`) and `AnalysisRun.raw_report` (`:143`) exist; no `AnalysisRun` audit columns (`created_by`, `created_on`, `modified_*`) on this table — audit's mention of "audit columns" does not apply.
- [app/schemas.py](../app/schemas.py) — confirmed `AnalysisRunOut` exposes `query_error_count: int` (`:115`) and `raw_report: str | None = None` (`:116`).
- [tests/conftest.py](../tests/conftest.py) — fixtures: `_tmp_database_path` (session SQLite tempfile), `app` (loads FastAPI after `DATABASE_URL` set), `client` (TestClient context manager), `sample_sbom_dict`, `seeded_sbom` (uploaded once per session), `mock_external_sources` (monkeypatches `app.analysis.*` source coroutines).
- [tests/test_sources_adapters.py](../tests/test_sources_adapters.py) — pattern: `monkeypatch.setattr(analysis_mod, "<func>", fake)` for stubbing source coroutines. Adapters delegate lazily, so patching at `app.analysis` covers every endpoint.
- [tests/test_sboms_analyze_snapshot.py](../tests/test_sboms_analyze_snapshot.py) — locks the `POST /api/sboms/{id}/analyze` JSON shape via `tests/snapshots/post_sbom_analyze.json`.
- [tests/test_analyze_endpoints_snapshot.py](../tests/test_analyze_endpoints_snapshot.py) — locks `/analyze-sbom-{nvd,github,osv,consolidated}` shapes.
- [tests/snapshots/post_sbom_analyze.json](../tests/snapshots/post_sbom_analyze.json) — current snapshot pins `"raw_report": null` and `"query_error_count": 0` (this is the bug surface; see A.5).
- [tests/snapshots/analyze_sbom_consolidated.json](../tests/snapshots/analyze_sbom_consolidated.json), [`analyze_sbom_nvd.json`](../tests/snapshots/analyze_sbom_nvd.json), [`analyze_sbom_github.json`](../tests/snapshots/analyze_sbom_github.json), [`analyze_sbom_osv.json`](../tests/snapshots/analyze_sbom_osv.json) — none of these contain `raw_report` because `_run_legacy_analysis` builds its return dict explicitly without that key (see A.5).
- [tests/_normalize.py](../tests/_normalize.py) — `_VOLATILE_KEYS = {completedOn, durationMs, duration_ms, started_on, completed_on, runId, run_id, id, sbom_id, lastModified}`. **`raw_report` is NOT volatile-stripped.**

---

## A.2 — `persist_analysis_run` side-by-side diff

**Router copy**: [app/routers/sboms_crud.py:176-277](../app/routers/sboms_crud.py#L176-L277).
**Service copy**: [app/services/analysis_service.py:119-203](../app/services/analysis_service.py#L119-L203).

| Aspect | Router copy (`sboms_crud.py:176-277`) | Service copy (`analysis_service.py:119-203`) | Notes |
|---|---|---|---|
| Signature | `(db, sbom_obj, details, components, run_status, source, started_on, completed_on, duration_ms) -> AnalysisRun` | identical | match |
| Component upsert helper | `upsert_components(db, sbom_obj, components)` (local fn at `:101-150`) | `_upsert_components(db, sbom_obj, components)` (imported from `sbom_service`) | functionally equivalent — both build `{"triplet": ..., "cpe": ...}` lookup map |
| `AnalysisRun.sbom_id` | `sbom_obj.id` | `sbom_obj.id` | match |
| `AnalysisRun.project_id` | `sbom_obj.projectid` | `sbom_obj.projectid` | match |
| `AnalysisRun.run_status` | `run_status` (passed-in) | `run_status` (passed-in) | match |
| `AnalysisRun.source` | `source` (passed-in) | `source` (passed-in) | match |
| `AnalysisRun.started_on` | `started_on` | `started_on` | match |
| `AnalysisRun.completed_on` | `completed_on` | `completed_on` | match |
| `AnalysisRun.duration_ms` | `duration_ms` | `duration_ms` | match |
| `AnalysisRun.total_components` | `safe_int(details.get("total_components"))` | `safe_int(details.get("total_components"))` | match |
| `AnalysisRun.components_with_cpe` | `safe_int(details.get("components_with_cpe"))` | `safe_int(details.get("components_with_cpe"))` | match |
| `AnalysisRun.total_findings` | `safe_int(details.get("total_findings"))` | `safe_int(details.get("total_findings"))` | match |
| `AnalysisRun.critical_count` | `safe_int(details.get("critical"))` | `safe_int(details.get("critical"))` | match |
| `AnalysisRun.high_count` | `safe_int(details.get("high"))` | `safe_int(details.get("high"))` | match |
| `AnalysisRun.medium_count` | `safe_int(details.get("medium"))` | `safe_int(details.get("medium"))` | match |
| `AnalysisRun.low_count` | `safe_int(details.get("low"))` | `safe_int(details.get("low"))` | match |
| `AnalysisRun.unknown_count` | `safe_int(details.get("unknown"))` | `safe_int(details.get("unknown"))` | match |
| **`AnalysisRun.query_error_count`** | **NOT WRITTEN — defaults to `0`** ([models.py:141](../app/models.py#L141)) | **`len(details.get("query_errors") or [])`** ([analysis_service.py:167](../app/services/analysis_service.py#L167)) | **router bug** |
| **`AnalysisRun.raw_report`** | **NOT WRITTEN — defaults to `NULL`** ([models.py:143](../app/models.py#L143)) | **`json.dumps(details)`** ([analysis_service.py:168](../app/services/analysis_service.py#L168)) | **router bug** |
| Audit columns on `AnalysisRun` | n/a — `AnalysisRun` has no `created_by`/`created_on`/`modified_*` columns | n/a | audit was wrong about audit columns; `AnalysisRun` has none |
| `db.flush()` after `db.add(run)` | yes (`:207`) | yes (`:171`) | match |
| Findings loop guard | none — iterates raw `details.get("findings", [])` | `if not isinstance(finding, dict): continue` ([:175-176](../app/services/analysis_service.py#L175-L176)) | **service is more defensive** |
| Finding `.analysis_run_id` | `run.id` | `run.id` | match |
| Finding `.component_id` | manual triplet lookup + CPE fallback (inlined `:214-226`) | `resolve_component_id(finding, component_maps)` ([sbom_service.py:185-217](../app/services/sbom_service.py#L185-L217)) | functionally equivalent — service helper does the same lookup |
| Finding `.vuln_id` | `(finding_raw.get("vuln_id") or finding_raw.get("id") or "").strip() or None` ([:260](../app/routers/sboms_crud.py#L260)) | `str(finding.get("vuln_id") or "UNKNOWN-CVE")` ([:183](../app/services/analysis_service.py#L183)) | **diverge.** Router falls back to legacy `id` key → trims → may end up `None`. Service hard-fallback `"UNKNOWN-CVE"`. **Production data flowing through the router never sets the legacy `id` key** (search of `app/sources/*` confirms only `vuln_id` is emitted). Column is `NOT NULL` on `analysis_finding.vuln_id` ([models.py:157](../app/models.py#L157)) — router copy can blow up on a finding with no `vuln_id` and no `id`; service copy never blows up. **Service wins** for safety. |
| Finding `.source` | `",".join(str(s) for s in sources)` if list else `str(sources) if sources else ""` ([:228-232](../app/routers/sboms_crud.py#L228-L232)) | `",".join(finding.get("sources", ["NVD"]))` ([:184](../app/services/analysis_service.py#L184)) | **diverge.** Router handles non-list `sources` gracefully and emits empty string; service crashes on non-list and defaults to `["NVD"]` when missing. Production findings always emit `sources` as a list (verified across `app/sources/`), but **the legacy `["NVD"]` fallback is misleading** when the finding actually came from elsewhere. **Router rule wins** for correctness. |
| Finding `.title` | NOT WRITTEN | `finding.get("title") or finding.get("vuln_id")` ([:185](../app/services/analysis_service.py#L185)) | **router bug** — column exists ([models.py:159](../app/models.py#L159)). Service writes it. **Service wins.** |
| Finding `.description` | `(finding_raw.get("description") or "").strip() or None` ([:267](../app/routers/sboms_crud.py#L267)) | `finding.get("description")` ([:186](../app/services/analysis_service.py#L186)) | **diverge.** Router strips empty → `None`; service stores raw (may persist empty string). **Router rule wins** for cleaner DB rows. |
| Finding `.severity` | `(finding_raw.get("severity") or "UNKNOWN").upper()` ([:261](../app/routers/sboms_crud.py#L261)) | `finding.get("severity")` ([:187](../app/services/analysis_service.py#L187)) | **diverge.** Router uppercases + defaults to `"UNKNOWN"`; service stores raw value (could be `None`/lowercase). Snapshot test asserts `severity` is uppercase via the bucket map upstream, so production data is already uppercased — but **router rule is safer**. |
| Finding `.score` | `finding_raw.get("score")` ([:262](../app/routers/sboms_crud.py#L262)) | `_safe_float(finding.get("score"))` ([:188](../app/services/analysis_service.py#L188)) | **diverge.** Router passes raw value (may be a string); service coerces to float / `None`. Column is `Float` ([models.py:162](../app/models.py#L162)) — SQLAlchemy will accept either, but **service coercion is safer**. |
| Finding `.vector` | `(finding_raw.get("vector") or "").strip() or None` | `finding.get("vector")` | router strips; service raw. Router wins. |
| Finding `.published_on` | `(finding_raw.get("published") or "").strip() or None` | `finding.get("published")` | router strips; service raw. Router wins. |
| Finding `.reference_url` | `(finding_raw.get("url") or "").strip() or None` ([:265](../app/routers/sboms_crud.py#L265)) | `finding.get("url") or (finding.get("references") or [None])[0]` ([:191](../app/services/analysis_service.py#L191)) | **diverge meaningfully.** Router only reads `url`; service falls back to first entry of `references[]` when `url` is missing. Legacy/ad-hoc adapters (e.g. VulDB, OSV) populate `references` but may leave `url` empty — see [test_sources_adapters.py:227](../tests/test_sources_adapters.py#L227) (`"references": [...]`). **Service wins.** |
| Finding `.cwe` | scalar OR list — JSON-encodes if list/tuple/set, else stripped string ([:244-250](../app/routers/sboms_crud.py#L244-L250)) | `",".join(finding.get("cwe", []))` if cwe else `None` ([:192](../app/services/analysis_service.py#L192)) | **diverge.** Router → JSON list when list, plain string when scalar. Service → comma-joined string when list, `None` otherwise. Column is `Text` ([models.py:166](../app/models.py#L166)). The frontend reader does not exist for this column today; either format is internally consistent. **Router wins** because it preserves the JSON-list shape that mirrors how `aliases` and `fixed_versions` are stored in adjacent `Text` columns — keeping a single "list-as-JSON" convention. |
| Finding `.cpe` | `(finding_raw.get("cpe") or "").strip() or None` | `finding.get("cpe")` | router strips; service raw. Router wins. |
| Finding `.component_name` | `(finding_raw.get("component_name") or "").strip() or None` | `finding.get("component_name")` | router strips; service raw. Router wins. |
| Finding `.component_version` | `(finding_raw.get("component_version") or "").strip() or None` | `finding.get("component_version")` | router strips; service raw. Router wins. |
| Finding `.fixed_versions` | `json.dumps(finding_raw.get("fixed_versions", []))` if `fixed_versions` else `None` ([:271-273](../app/routers/sboms_crud.py#L271-L273)) | `json.dumps(fv) if fv else None` where `fv = finding.get("fixed_versions") or []` ([:178, :196](../app/services/analysis_service.py#L178)) | match (functional equivalent) |
| Finding `.attack_vector` | `(finding_raw.get("attack_vector") or "").strip() or None` | `finding.get("attack_vector")` | router strips; service raw. Router wins. |
| Finding `.cvss_version` | NOT WRITTEN | `finding.get("cvss_version")` ([:198](../app/services/analysis_service.py#L198)) | **router bug** — column exists ([models.py:174](../app/models.py#L174)). Service writes it. **Service wins.** |
| Finding `.aliases` | `json.dumps(finding_raw["aliases"])` only if truthy, else `None`; swallows `(TypeError, ValueError)` to `None` ([:234-239](../app/routers/sboms_crud.py#L234-L239)) | `json.dumps(finding.get("aliases") or []) if finding.get("aliases") else None` ([:199](../app/services/analysis_service.py#L199)) | match (functional equivalent — both produce JSON string or `None`) |
| Loop terminator | implicit (`for finding_raw in details.get("findings", [])`) | `for finding in details.get("findings") or []` | functionally equivalent |
| Commit / flush semantics | `db.flush()` once after `run`, no commit (caller commits) | `db.flush()` once after `run`, no commit (caller commits) | match |
| Error handling | none in body | none in body | match |
| Return value | `AnalysisRun` instance | `AnalysisRun` instance | match |

---

## A.3 — `compute_report_status` diff

**Router copy**: [app/routers/sboms_crud.py:168-173](../app/routers/sboms_crud.py#L168-L173).

```python
def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    if total_findings > 0:
        return "FAIL"
    if query_errors:
        return "PARTIAL"
    return "PASS"
```

**Service copy**: [app/services/analysis_service.py:96-111](../app/services/analysis_service.py#L96-L111).

```python
def compute_report_status(total_findings: int, query_errors: list[dict]) -> str:
    """
    Compute the overall report status based on findings and errors.

    Args:
        total_findings: Number of vulnerabilities found
        query_errors: List of query error dictionaries

    Returns:
        Status string: "FAIL" (findings), "PARTIAL" (errors), or "PASS"
    """
    if total_findings > 0:
        return "FAIL"
    if query_errors:
        return "PARTIAL"
    return "PASS"
```

**Verdict**: bodies are byte-for-byte identical. Only difference is the docstring (service has one, router does not). Audit's "identical" claim is **confirmed**.

---

## A.4 — Caller inventory

### `persist_analysis_run` callers

```
app/routers/analyze_endpoints.py:53:from .sboms_crud import compute_report_status, persist_analysis_run
app/routers/analyze_endpoints.py:186:    run = persist_analysis_run(             # → router copy
app/routers/sboms_crud.py:176:def persist_analysis_run(                            # router definition
app/routers/sboms_crud.py:348:    run = persist_analysis_run(                     # → router copy (create_auto_report)
app/routers/sboms_crud.py:908:            run = persist_analysis_run(             # → router copy (analyze_sbom_stream)
app/services/__init__.py:15:    persist_analysis_run,                              # re-export
app/services/__init__.py:63:    "persist_analysis_run",                            # __all__
app/services/analysis_service.py:119:def persist_analysis_run(                    # service definition
app/services/analysis_service.py:297:        persist_analysis_run(               # → service copy (backfill_analytics_tables)
```

| File | Line | Copy called | Caller | Expects |
|---|---|---|---|---|
| `app/routers/sboms_crud.py` | 348 | router | `create_auto_report` (production `POST /api/sboms/{id}/analyze`) | returns `AnalysisRun`; caller does `db.commit()` next, then `analysis_run_to_dict(report)` for response |
| `app/routers/sboms_crud.py` | 908 | router | `analyze_sbom_stream` (SSE `POST /api/sboms/{id}/analyze/stream`) | returns `AnalysisRun`; caller does `db.commit()`, uses `run.id` in SSE `complete` payload |
| `app/routers/analyze_endpoints.py` | 186 | router (via `:53` import) | `_run_legacy_analysis` (NVD/GHSA/OSV/VulDB/Consolidated `/analyze-sbom-*`) | returns `AnalysisRun`; caller does `db.commit()`, uses `run.id` in flat response dict |
| `app/services/analysis_service.py` | 297 | service | `backfill_analytics_tables` (called from `app/main.py:on_startup` per docstring) | returns `AnalysisRun` (return value unused); caller does `db.commit()` once at end |

### `compute_report_status` callers

```
app/utils.py:39:def compute_report_status(...)                                   # orphaned — zero importers (R5)
app/routers/analyze_endpoints.py:53:from .sboms_crud import compute_report_status, persist_analysis_run
app/routers/analyze_endpoints.py:174:    run_status = compute_report_status(...)  # → router copy
app/routers/sboms_crud.py:168:def compute_report_status(...)                    # router definition
app/routers/sboms_crud.py:342:    run_status = compute_report_status(...)        # → router copy (create_auto_report)
app/routers/sboms_crud.py:902:            run_status = compute_report_status(...) # → router copy (analyze_sbom_stream)
app/services/__init__.py:12:    compute_report_status,                            # re-export
app/services/__init__.py:60:    "compute_report_status",                          # __all__
app/services/analysis_service.py:96:def compute_report_status(...)               # service definition
app/services/analysis_service.py:283:            run_status = ... compute_report_status(...) # → service copy (backfill)
```

Same call-graph topology as `persist_analysis_run` — three router-side production callers, one service-side backfill caller.

---

## A.5 — Merge plan

### Canonical home

`app/services/analysis_service.py` — already the audit-recommended location. Both functions stay here; router and `analyze_endpoints` re-import from `..services.analysis_service`.

### Field reconciliation

The merged service-side `persist_analysis_run` will adopt the production-correct value at every divergence. Default rule per prompt: **production behavior preserved + missing fields added**.

| Field | Resolution in merged version | Source |
|---|---|---|
| `AnalysisRun.query_error_count` | `len(details.get("query_errors") or [])` | service (router was missing — bug) |
| `AnalysisRun.raw_report` | `json.dumps(details)` | service (router was missing — bug) |
| All other `AnalysisRun.*` fields | unchanged (already match) | both |
| Findings loop guard | keep `if not isinstance(finding, dict): continue` | service (defensive) |
| Finding `.vuln_id` | `(finding.get("vuln_id") or finding.get("id") or "").strip() or "UNKNOWN-CVE"` | **merge** — accept legacy `id` key (router behavior) AND hard-fallback to `"UNKNOWN-CVE"` (service behavior) so we never violate the `NOT NULL` constraint |
| Finding `.source` | `",".join(str(s) for s in sources)` if list else `str(sources) if sources else ""` (router pattern) | router (handles non-list defensively, no misleading `["NVD"]` default) |
| Finding `.title` | `finding.get("title") or finding.get("vuln_id")` | service (router was missing) |
| Finding `.description` | `(finding.get("description") or "").strip() or None` | router (cleaner) |
| Finding `.severity` | `(finding.get("severity") or "UNKNOWN").upper()` | router (safer) |
| Finding `.score` | `_safe_float(finding.get("score"))` | service (type-safe) |
| Finding `.vector` | `(finding.get("vector") or "").strip() or None` | router |
| Finding `.published_on` | `(finding.get("published") or "").strip() or None` | router |
| Finding `.reference_url` | `(finding.get("url") or "").strip() or ((finding.get("references") or [None])[0])` | merge — router strip + service fallback |
| Finding `.cwe` | router pattern — JSON list when list, stripped string when scalar, `None` otherwise | router (consistent with adjacent JSON-in-Text columns) |
| Finding `.cpe` | `(finding.get("cpe") or "").strip() or None` | router |
| Finding `.component_name` | `(finding.get("component_name") or "").strip() or None` | router |
| Finding `.component_version` | `(finding.get("component_version") or "").strip() or None` | router |
| Finding `.fixed_versions` | `json.dumps(fv) if fv else None` (already matches both) | both |
| Finding `.attack_vector` | `(finding.get("attack_vector") or "").strip() or None` | router |
| Finding `.cvss_version` | `finding.get("cvss_version")` | service (router was missing) |
| Finding `.aliases` | `json.dumps(finding["aliases"]) if finding.get("aliases") else None` (try/except `(TypeError, ValueError)` → `None`) | router (defensive); functionally same |
| Component-id resolution | `resolve_component_id(finding, component_maps)` from `sbom_service` | service (already extracted helper) |

`compute_report_status` is byte-identical — keep service version (with docstring), drop router copy.

### Imports to update

- `app/routers/sboms_crud.py` — **delete** local `def compute_report_status(...)` (`:168-173`) and `def persist_analysis_run(...)` (`:176-277`); **add** `from ..services.analysis_service import compute_report_status, persist_analysis_run`. Internal call sites (`:342`, `:348`, `:902`, `:908`) already use bare names; no rewrite required.
- `app/routers/analyze_endpoints.py` — change `from .sboms_crud import compute_report_status, persist_analysis_run` (`:53`) to `from ..services.analysis_service import compute_report_status, persist_analysis_run`. Call sites (`:174`, `:186`) untouched.
- `app/services/__init__.py` — already re-exports both names from `analysis_service` (`:10-16`, `:60`, `:63`). No change.
- `app/services/analysis_service.py` — body of `persist_analysis_run` is updated per the table above.

### SSE streaming path (`analyze_sbom_stream`)

[`sboms_crud.py:715-949`](../app/routers/sboms_crud.py#L715-L949) calls `persist_analysis_run` at `:908`. After the merge, that call resolves to the imported service-side function — same signature, same return type, same `db.flush()` semantics, no commit inside the helper. **No code changes required to the SSE body.**

### Snapshot risk

| Snapshot | Constructed from | After-merge prediction |
|---|---|---|
| [`tests/snapshots/post_sbom_analyze.json`](../tests/snapshots/post_sbom_analyze.json) | `AnalysisRunOut.model_validate(...)` over the persisted `AnalysisRun` row (router-side `analysis_run_to_dict(report)` reads from the row that was just `db.flush`-ed via the router's `persist_analysis_run`). `AnalysisRunOut` exposes `query_error_count` ([schemas.py:115](../app/schemas.py#L115)) and `raw_report` ([schemas.py:116](../app/schemas.py#L116)). | **WILL CHANGE.** Currently `"query_error_count": 0, "raw_report": null`. After merge: `query_error_count` stays `0` (the test fixture produces no errors — `_fake_*` coroutines all return `[]` for errors), but `raw_report` becomes a non-null JSON string. **`raw_report` is not in `_VOLATILE_KEYS`** and will diff. Snapshot regeneration is **expected and required**. The fix is to add `raw_report` to `_VOLATILE_KEYS` OR re-capture the snapshot with the volatile-stripped JSON content. **Plan: add `"raw_report"` to `_VOLATILE_KEYS` in `tests/_normalize.py` and regenerate `post_sbom_analyze.json`.** This is one-line scope and stays inside the test infrastructure file the prompt does not enumerate as off-limits. |
| [`tests/snapshots/analyze_sbom_nvd.json`](../tests/snapshots/analyze_sbom_nvd.json) | `_run_legacy_analysis` returns an explicit dict ([analyze_endpoints.py:215-255](../app/routers/analyze_endpoints.py#L215-L255)) — does NOT include `raw_report`. | **No change** — `raw_report` is never in this response. `query_error_count` already populated explicitly from `len(query_errors)` ([analyze_endpoints.py:236](../app/routers/analyze_endpoints.py#L236)). |
| [`tests/snapshots/analyze_sbom_github.json`](../tests/snapshots/analyze_sbom_github.json) | same path as nvd | **No change** |
| [`tests/snapshots/analyze_sbom_osv.json`](../tests/snapshots/analyze_sbom_osv.json) | same path as nvd | **No change** |
| [`tests/snapshots/analyze_sbom_consolidated.json`](../tests/snapshots/analyze_sbom_consolidated.json) | same path as nvd | **No change** |

**Net snapshot impact: 1 file regenerated (`post_sbom_analyze.json`)**, achieved by adding `raw_report` to `_VOLATILE_KEYS` and re-capturing the file.

### Out-of-scope confirmation

- `app/utils.py:39-44` — third copy of `compute_report_status`, zero importers, R5 territory. **Untouched.**
- `app/routers/sboms_crud.py:81-99` — `now_iso`, `_coerce_sbom_data`, `normalized_key` duplicates of `app/services/sbom_service.py` helpers. R-quick-wins. **Untouched.**
- `AnalysisRun` audit columns (`created_by`, `modified_*`) — **do not exist** on the model. The audit's mention of audit-column reconciliation is moot.

---

**End of Phase A.** Proceeding to Phase B.
