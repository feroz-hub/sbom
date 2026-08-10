# R4 — Final Report: 500 information disclosure (BE-002)

> Audit reference: BE-002 (per refactor-plan R4).

---

## Phase A — Inventory summary

[audit/r4_leak_sites.md](r4_leak_sites.md) (236 lines).

- **4 leak sites** to sanitize (across 3 files):
  1. [app/routers/sboms_crud.py:501](../app/routers/sboms_crud.py#L501) — `update_sbom` `Failed to update SBOM: {exc}`
  2. [app/routers/sboms_crud.py:568](../app/routers/sboms_crud.py#L568) — `delete_sbom` `Failed to delete SBOM: {exc}`
  3. [app/routers/projects.py:80](../app/routers/projects.py#L80) — `create_project` `Something went wrong: {str(e)}`
  4. [app/routers/pdf.py:151](../app/routers/pdf.py#L151) — `PDF report` `Failed to generate PDF: {e}`
- **6** "Already safe" 500s with hardcoded strings — left alone.
- **4** broad `except Exception` blocks missing `log.exception(...)` — paired with the leak fixes (3 already had logging).
- **0** existing tests assert on 500 detail text — no test-update commit needed.
- **Existing envelope shape**: structured `{"detail": {"code", "message"}}` is the modern convention (matches R3 `MaxBodySizeMiddleware`). New 500 envelope aligned to this + adds `correlation_id`.
- **2 out-of-scope** SSE event-level leaks + 1 misclassified 404 leak — flagged in the audit doc, deferred.

---

## Phase B — Regression tests

**File**: [tests/test_500_no_leak.py](../tests/test_500_no_leak.py) — **209 lines**, 4 tests:

| Test | What it exercises |
|---|---|
| `test_500_from_db_error_returns_generic_envelope` | Per-route HTTPException(500) path. Injects `IntegrityError("synthetic-stmt UNIQUE constraint violated", "synthetic_params", Exception("synthetic_orig"))` via `app.dependency_overrides[get_db]` wrapping `Session.commit`. Asserts: 500, no leak of `IntegrityError` / `synthetic-stmt` / `synthetic_orig` / `synthetic_params` / `UNIQUE`, structured envelope, server-side log captured the failure. |
| `test_500_from_generic_exception_returns_generic_envelope` | Same hook; injects `RuntimeError("LEAKABLE_TOKEN_xyz123")`. Asserts no leak of the literal token or class name. |
| `test_4xx_validation_errors_unchanged` | POST malformed JSON → 422. Asserts the FastAPI list-shaped `detail` is still surfaced (proves the global Exception handler is not over-greedy). |
| `test_global_handler_500_includes_correlation_id` | Registers a synthetic `GET /__test_internal_error__` route that raises `RuntimeError(_LEAKABLE_TOKEN)`. The synthetic route bypasses every broad-except in the codebase — exception bubbles to Starlette's `ServerErrorMiddleware` → our handler. Asserts: 500, no leak, structured envelope, `correlation_id` is 12-hex AND present in the server log (proves the ops link). |

### Phase B.5 — confirmed failing on commit `f1b010d`

```
tests/test_500_no_leak.py::test_500_from_db_error_returns_generic_envelope FAILED
tests/test_500_no_leak.py::test_500_from_generic_exception_returns_generic_envelope FAILED
tests/test_500_no_leak.py::test_4xx_validation_errors_unchanged PASSED

E       AssertionError: 500 response leaked exception message: '{"detail":"Failed to update SBOM: LEAKABLE_TOKEN_xyz123"}'
E       assert 'LEAKABLE_TOKEN_xyz123' not in '{"detail":"...KEN_xyz123"}'
```

The verbatim leak captured. Test 3 (4xx unchanged) passed already, as expected.

### Phase D.6 — confirmed passing on commit `050eedc`

```
tests/test_500_no_leak.py::test_500_from_db_error_returns_generic_envelope PASSED [ 25%]
tests/test_500_no_leak.py::test_500_from_generic_exception_returns_generic_envelope PASSED [ 50%]
tests/test_500_no_leak.py::test_4xx_validation_errors_unchanged PASSED   [ 75%]
tests/test_500_no_leak.py::test_global_handler_500_includes_correlation_id PASSED [100%]

========================= 4 passed, 1 warning in 1.10s =========================
```

---

## Files modified

| File | Lines changed | Notes |
|---|---|---|
| [app/error_handlers.py](../app/error_handlers.py) | +49 | new module — `install(app)` registers an `@app.exception_handler(Exception)` that returns `{"detail": {"code": "internal_error", "message": "Internal server error.", "correlation_id": "<12-hex>"}}` and `log.exception(...)` with the same ID. |
| [app/main.py](../app/main.py) | +8 | one new `from . import error_handlers` import + one `error_handlers.install(app)` call after middleware registration. Existing handlers untouched. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py) | +13 / −4 | sanitized `update_sbom` (line 501) + `delete_sbom` (line 568) leaks; added `log.exception(...)` to the previously-silent `create_sbom` catch-all (line 367). |
| [app/routers/projects.py](../app/routers/projects.py) | +6 / −2 | sanitized `create_project` `Something went wrong: {str(e)}` leak; added `log.exception(...)`. |
| [app/routers/pdf.py](../app/routers/pdf.py) | +5 / −2 | sanitized `Failed to generate PDF: {e}` leak; replaced `log.error(..., exc_info=True)` with the more idiomatic `log.exception(...)`. |
| [tests/test_500_no_leak.py](../tests/test_500_no_leak.py) | +84 / −12 | refined post-Phase B — relaxed tests 1+2 to NOT require correlation_id in per-route 500s (per the prompt's example pattern), added test 4 for the global handler via synthetic route. |

Net across R4 (`f1b010d..050eedc`, excluding R3 closeout doc): **6 files, +156 / −19**.

---

## Sanitization counts

- **4 leak sites** sanitized (cataloged in [r4_leak_sites.md](r4_leak_sites.md) §A.2).
- **1 bare-except block** given new logging (`sboms_crud.py:367` — `create_sbom` catch-all). The other three (`update_sbom`, `delete_sbom`, `create_project`) had their logging added simultaneously with the leak fix.

---

## Test summary

```
======================= 227 passed, 5 warnings in 8.97s ========================
```

All 227 tests green (223 prior + 4 new). Pre-existing Pydantic V2 / JWT key-length warnings unchanged.

---

## Commits applied

| Commit | Phase | Subject |
|---|---|---|
| `637c342` | A (R3 closeout) | docs(audit): add R3 final report |
| `f1b010d` | B | test(security): add failing tests for 500 information disclosure (BE-002) |
| `050eedc` | D | fix(security): replace 500 detail leaks with canonical envelope; install global exception handler with correlation IDs (BE-002) |

R4 used the prompt's per-site fix scope plus a single Phase D commit (no test-update commit needed since A.5 found 0 tests asserting on 500 text). The Phase B commit also bundled the `audit/r4_leak_sites.md` Phase A artifact, mirroring the convention from R2/R3.

Chronology proves the fix: red between `f1b010d` and `050eedc`, green at `050eedc`.

---

## Sample correlation-ID flow

A user hits a buggy endpoint that exposes an unhandled exception. The response they see:

```json
{
  "detail": {
    "code": "internal_error",
    "message": "Internal server error.",
    "correlation_id": "a7f3375b44f8"
  }
}
```

The user reports the failure to support. An operator greps the server log for that ID:

```
$ grep a7f3375b44f8 server.log
[ERROR] 2026-04-28 22:06:23  app.error_handlers  unhandled error: method=GET path=/__test_internal_error__ correlation_id=a7f3375b44f8
Traceback (most recent call last):
  File ".../tests/test_500_no_leak.py", line 152, in _boom
    raise RuntimeError(_LEAKABLE_TOKEN)
RuntimeError: LEAKABLE_TOKEN_xyz123
```

The full stack trace, exception class, and message are visible to the operator while the client saw none of it.

---

## Out-of-scope leak surfaces (deferred)

Three leak surfaces were inventoried but explicitly deferred per prompt guardrails — surfacing here for the refactor plan:

| File | Line | Class | Reason deferred |
|---|---|---|---|
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L678) | 678 | SSE event-level leak (200-OK envelope) — `_sse_event("error", {"message": f"SBOM parse failed: {exc}"...})` | Not a 500 envelope. Different attack class — needs its own pass. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L828) | 828 | Same — SSE error event with `str(exc)` body | Same. |
| [app/routers/analyze_endpoints.py](../app/routers/analyze_endpoints.py#L122) | 122 | 404 with `detail=str(exc)` from `_load_sbom_from_ref` | **Misclassified leak**: 404, not 500. Per guardrail "Do not reclassify misclassified 500s to 4xx in this prompt." |

Six "Already safe" 500s in `sboms_crud.py` and `projects.py` use hardcoded strings — leak-free but they catch broad `SQLAlchemyError` for things that arguably belong in 4xx (e.g. `IntegrityError` → 409). Same misclassification ticket.

---

> "R4 complete. 4 leak sites sanitized. Global 500 handler installed with correlation IDs. 1 bare-except block now logged. Awaiting confirmation before push."
