# R4 — Leak-Site Inventory: 500 information disclosure

> Audit reference: BE-002 (per refactor-plan R4).
> Repo HEAD verified at `85af821` (post-R3). Audit was on `4435bd2`. Line numbers re-verified against current HEAD.

---

## A.1 — Greps run

```
$ grep -rEn "HTTPException\(\s*(status_code\s*=\s*)?500" --include='*.py' app/
app/routers/pdf.py:151:        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")
app/routers/projects.py:80:        raise HTTPException(status_code=500, detail=f"Something went wrong: {str(e)}")
app/routers/projects.py:96:        raise HTTPException(status_code=500, detail="Internal database error while fetching project details.") from exc
app/routers/projects.py:141:        raise HTTPException(status_code=500, detail="Internal database error while updating project.") from exc
app/routers/sboms_crud.py:417:        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOMs.") from exc
app/routers/sboms_crud.py:456:        raise HTTPException(status_code=500, detail="Internal database error while fetching SBOM components.") from exc
app/routers/sboms_crud.py:501:        raise HTTPException(status_code=500, detail=f"Failed to update SBOM: {exc}") from exc
app/routers/sboms_crud.py:568:        raise HTTPException(status_code=500, detail=f"Failed to delete SBOM: {exc}") from exc
app/routers/sboms_crud.py:590:            raise HTTPException(status_code=500, detail="Unable to generate analysis report") from exc
app/routers/sboms_crud.py:593:            raise HTTPException(status_code=500, detail="Unable to generate analysis report")
```

```
$ grep -rEn "HTTPException\(\s*5[0-9][0-9]" --include='*.py' app/
(empty)
```

```
$ grep -rEn "raise HTTPException.*detail=f" --include='*.py' app/
app/routers/analysis.py:33:        raise HTTPException(status_code=404, detail=f"Run {run_a} not found")
app/routers/analysis.py:35:        raise HTTPException(status_code=404, detail=f"Run {run_b} not found")
app/routers/projects.py:53:        raise HTTPException(status_code=422, detail=f"'{param_name}' must be an integer.")
app/routers/projects.py:55:        raise HTTPException(status_code=422, detail=f"'{param_name}' must be a positive integer (>= 1).")
app/routers/projects.py:80:        raise HTTPException(status_code=500, detail=f"Something went wrong: {str(e)}")
app/routers/pdf.py:138:        raise HTTPException(status_code=404, detail=f"Run {run_id} not found.")
app/routers/pdf.py:151:        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")
app/routers/sboms_crud.py:282:        raise HTTPException(status_code=422, detail=f"'{param_name}' must be an integer.")
app/routers/sboms_crud.py:284:        raise HTTPException(status_code=422, detail=f"'{param_name}' must be a positive integer (>= 1).")
app/routers/sboms_crud.py:501:        raise HTTPException(status_code=500, detail=f"Failed to update SBOM: {exc}") from exc
app/routers/sboms_crud.py:568:        raise HTTPException(status_code=500, detail=f"Failed to delete SBOM: {exc}") from exc
app/routers/sbom.py:114:        raise HTTPException(status_code=400, detail=f"Invalid SBOM JSON: {e}")
```

```
$ grep -rEn "detail=str\((exc|err|e)\)|JSONResponse.*status_code\s*=\s*5|return.*Response.*status_code\s*=\s*5" --include='*.py' app/
app/routers/analyze_endpoints.py:122:        raise HTTPException(status_code=404, detail=str(exc))
```

---

## A.2 — Leak-site catalog

| File | Line | Current code | Leak class | Disposition |
|---|---|---|---|---|
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L501) | 501 | `raise HTTPException(status_code=500, detail=f"Failed to update SBOM: {exc}") from exc` | DB error text (broad `except Exception` after `db.commit()`) | **Replace with generic.** Log full exc with `sbom_id`. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L568) | 568 | `raise HTTPException(status_code=500, detail=f"Failed to delete SBOM: {exc}") from exc` | DB error text (broad `except Exception` after cascade deletes + commit) | **Replace with generic.** Log full exc with `sbom_id`, `user_id`. |
| [app/routers/projects.py](../app/routers/projects.py#L80) | 80 | `raise HTTPException(status_code=500, detail=f"Something went wrong: {str(e)}")` | Generic `str(e)` (broad except after `db.commit()`) | **Replace with generic.** Log full exc with `project_name`. The handler is also missing logging entirely — `log.exception(...)` will be added. |
| [app/routers/pdf.py](../app/routers/pdf.py#L151) | 151 | `raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")` | Generic — `e` here is whatever `build_pdf_from_run_bytes` raises (often `reportlab.platypus` errors that may include path fragments). | **Replace with generic.** Existing `log.error("...", exc_info=True)` already logs the full trace; only the response detail is leaky. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L417) | 417 | `raise HTTPException(status_code=500, detail="Internal database error while fetching SBOMs.") from exc` | **Already safe** — hardcoded string, no interpolation. | **Already safe.** Leave alone. (Optional: align to structured envelope for consistency — but that's behavior-preserving and out of scope per "edit only the lines that need editing".) |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L456) | 456 | `raise HTTPException(status_code=500, detail="Internal database error while fetching SBOM components.") from exc` | **Already safe** — hardcoded string. | **Already safe.** |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L590) | 590 | `raise HTTPException(status_code=500, detail="Unable to generate analysis report") from exc` | **Already safe** — hardcoded string. | **Already safe.** |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L593) | 593 | `raise HTTPException(status_code=500, detail="Unable to generate analysis report")` | **Already safe** — hardcoded string. | **Already safe.** |
| [app/routers/projects.py](../app/routers/projects.py#L96) | 96 | `raise HTTPException(status_code=500, detail="Internal database error while fetching project details.") from exc` | **Already safe** — hardcoded string. | **Already safe.** |
| [app/routers/projects.py](../app/routers/projects.py#L141) | 141 | `raise HTTPException(status_code=500, detail="Internal database error while updating project.") from exc` | **Already safe** — hardcoded string. | **Already safe.** |

### Out-of-scope leak surfaces (different attack class — note for refactor plan)

| File | Line | Current code | Class | Why deferred |
|---|---|---|---|---|
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L678) | 678 | `yield _sse_event("error", {"message": f"SBOM parse failed: {exc}", "code": 400})` | SSE streaming event payload (200-OK envelope, embedded error event) | Not a 500 envelope. The R4 mission targets HTTPException 500 detail leaks. SSE event-level leak is a separate refactor. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L828) | 828 | `yield _sse_event("error", {"message": str(exc), "code": 500})` | Same — SSE error event. | Same. Defer. |
| [app/routers/analyze_endpoints.py](../app/routers/analyze_endpoints.py#L122) | 122 | `raise HTTPException(status_code=404, detail=str(exc))` | 404 leak via `str(exc)` from `_load_sbom_from_ref`. | **Misclassified leak surface** — 404, not 500. Per prompt §0 "Distinguish 500 leaks from 4xx messages" + guardrail "Do not reclassify misclassified 500s to 4xx". Note for refactor plan; defer. |

### Misclassification notes (out-of-scope)

The five "Already safe" 500s in [sboms_crud.py](../app/routers/sboms_crud.py) and [projects.py](../app/routers/projects.py) catch `SQLAlchemyError` and present a 500 — but `SQLAlchemyError` covers operational errors (`OperationalError`, connection drop) AND schema/data errors that arguably belong in 4xx (`IntegrityError` could be 409). Per guardrail "Do not reclassify misclassified 500s to 4xx in this prompt", these stay as 500s; flagged here for a future `R??-misclassified-500s` ticket.

---

## A.3 — Bare `except Exception` blocks missing logging

```
$ grep -rEn "except Exception" --include='*.py' app/
```

Triaged 39 hits. Below are blocks **in production request paths** that swallow without ANY logging. (Hits in unit-style helpers, conditional imports, and dead-code modules are excluded.)

| File | Line | Block purpose | Logging present? | Disposition |
|---|---|---|---|---|
| [app/routers/projects.py](../app/routers/projects.py#L78) | 78 | catch-all in `create_project` after `db.commit()` | **No** — silently swallows then 500s with leaky detail | **Add `log.exception("create_project failed: project_name=%s", payload.project_name)`** in Phase D (paired with the leak fix at line 80). |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L367) | 367 | catch-all in `create_sbom` after rollback | **No** — silently 500s | **Add `log.exception("create_sbom unexpected error: name=%s", payload.sbom_name)`**. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L499) | 499 | catch-all in `update_sbom` (paired with leak at line 501) | **No** — relies on the leaky detail | **Add `log.exception("update_sbom failed: sbom_id=%s", sbom_id)`** + sanitize line 501. |
| [app/routers/sboms_crud.py](../app/routers/sboms_crud.py#L566) | 566 | catch-all in `delete_sbom` (paired with leak at line 568) | **No** — relies on the leaky detail | **Add `log.exception("delete_sbom failed: sbom_id=%s user=%s", sbom_id, user_id)`** + sanitize line 568. |

The other broad-except blocks already log: `sboms_crud.py:187` (`log.warning`), `sboms_crud.py:205` (`log.error exc_info=True`), `sboms_crud.py:336` (`log.warning`), `sboms_crud.py:587` (`log.error exc_info=True`), `sboms_crud.py:826` (`log.error exc_info=True`), `pdf.py:149` (`log.error exc_info=True`), `analyze_endpoints.py:120` (raises `ValueError` — caller catches), and the various `app/services/*` and `app/sources/*` helpers (all log at `error`/`warning`).

`app/services/sbom_service.py:251` and `app/services/sbom_service.py:285` are narrow casting fallbacks (`except Exception: sbom_row = None`) inside a function whose immediate next line raises a typed `ValueError` — no leak, no operational concern, **leave alone**.

`app/middleware/max_body.py:122` is the R3 middleware's intentional swallow path — **leave alone**.

---

## A.4 — Existing error envelope shape

### Files read

- [app/error_handlers.py](../app/error_handlers.py) — **does not exist** (`test -f` confirmed). Will be created in Phase D.
- [app/main.py](../app/main.py) — read end-to-end. Existing exception-handler registrations:
  - Line 174: `app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)` — registered for `slowapi.errors.RateLimitExceeded` only.
  - No `@app.exception_handler(Exception)` exists. Adding one in Phase D will not conflict.
- [app/routers/sboms_crud.py](../app/routers/sboms_crud.py) — representative router for the existing 4xx envelope shape.
- [app/middleware/max_body.py](../app/middleware/max_body.py) — R3 middleware (the canonical envelope to align to).

### Envelope shapes in current production code

Mixed — but the structured form is the modern one:

```python
# Structured (newer code, R3 + sboms_crud 409/500):
{"detail": {"code": "duplicate_name",  "message": "An SBOM with name '...' already exists."}}      # sboms_crud.py:317-320
{"detail": {"code": "integrity_error", "message": "Integrity constraint violated while creating SBOM."}}  # sboms_crud.py:355-356
{"detail": {"code": "db_error",        "message": "Internal database error while creating SBOM."}}  # sboms_crud.py:361-362
{"detail": {"code": "unexpected",      "message": "Unexpected error while creating SBOM."}}          # sboms_crud.py:369-370
{"detail": {"code": "payload_too_large", "message": "Request body exceeds maximum allowed size."}}    # middleware/max_body.py (R3)

# Flat (legacy / 4xx string detail):
{"detail": "SBOM not found"}                                # sboms_crud.py:516
{"detail": "Forbidden: user cannot delete this SBOM"}       # sboms_crud.py:522
{"detail": "Project not found"}                             # projects.py many
{"detail": [...pydantic validation array...]}               # FastAPI 422 default
```

### Decision

**Align the new 500 handler to the structured `{"detail": {"code", "message"}}` form** — that's already the convention for 5xx in [sboms_crud.py](../app/routers/sboms_crud.py) and the canonical R3 envelope. Add `correlation_id` field per the prompt's pattern. Code value: `"internal_error"`.

```python
{
    "detail": {
        "code": "internal_error",
        "message": "Internal server error.",
        "correlation_id": "<12-hex>"
    }
}
```

Flat-string 4xx envelopes (FastAPI defaults, the dozens of `detail="..."` short messages) are **untouched**. Per guardrail "Do not change the 4xx envelope shape."

---

## A.5 — Tests asserting on 500 detail text

```
$ grep -rEn "status_code\s*==\s*500|assert.*\.status_code\s*==\s*5|Failed to update|Something went wrong|Failed to create|Failed to delete|Failed to generate" --include='*.py' tests/
tests/nvd_mirror/test_api.py:198:    assert r.status_code == 503
```

Only one hit, and it's a 503 assertion in the NVD mirror suite (unrelated). **Zero existing tests assert on 500 detail text or on the leaky strings.** No test updates required in Phase D. Phase D commit count drops to **one** (handler + leak-site fix in a single fix commit).

---

## A.6 — Conclusion

- **4** leak sites found in **3** files (`sboms_crud.py:501`, `sboms_crud.py:568`, `projects.py:80`, `pdf.py:151`). All four embed `{exc}` / `str(e)` directly in the 500 response detail.
- **6** "Already safe" 500s in `sboms_crud.py` and `projects.py` use hardcoded strings — leave alone (per "edit only the lines that need editing").
- **4** broad `except Exception` blocks in production routers are missing `log.exception(...)`. All four are paired with leak fixes above and will be co-fixed in Phase D.
- Existing envelope shape: **mixed**; structured `{"detail": {"code", "message"}}` for 5xx (and R3 413), flat `{"detail": "string"}` for legacy 4xx. New 500 handler aligns to the structured form + adds `correlation_id`.
- **0** tests will need updating.
- **2** out-of-scope leak surfaces flagged for the refactor plan (SSE event-level leaks at `sboms_crud.py:678`, `:828`; one 404 `str(exc)` leak at `analyze_endpoints.py:122`).
- **Verdict**: PROCEED. Single Phase D commit (no test-update commit needed).

---

**End of Phase A.** Proceeding to Phase B.
