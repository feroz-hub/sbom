# R3 — Final Report: `MAX_UPLOAD_BYTES` enforcement

> Audit reference: BE-001 (per refactor-plan R3).

---

## Phase A — Discovery summary

[audit/r3_upload_size_discovery.md](r3_upload_size_discovery.md) (125 lines).

- `Settings.MAX_UPLOAD_BYTES = 20 * 1024 * 1024` confirmed at [app/settings.py:225](../app/settings.py#L225).
- 4/4 enforcement greps empty: no existing `MAX_UPLOAD_BYTES` reader, no `Content-Length` inspection, no 413 handler, no `request.body()` / `UploadFile` consumers.
- 12 POST/PUT/PATCH routes inventoried; **2** carry unbounded bodies (`POST /api/sboms`, `PATCH /api/sboms/{id}` via `sbom_data: str | None`); **0** legitimately exceed the limit.
- 0 existing tests would break.
- `httpx>=0.28.1` already in `pyproject.toml` deps — `ASGITransport` chunked streaming test usable without adding a dep.
- **Verdict**: PROCEED.

---

## Phase B — Regression tests

**File**: [tests/test_max_upload_size.py](../tests/test_max_upload_size.py) — 96 lines, 2 tests:

| Test | Shape | Mechanism |
|---|---|---|
| `test_post_with_oversize_content_length_returns_413` | Honest oversize | `TestClient.post(content=b"x" * (max+1))` — TestClient/httpx auto-sets `Content-Length`. |
| `test_post_with_chunked_oversize_returns_413` | Lying / chunked | `httpx.AsyncClient(transport=ASGITransport(app=app))` with an `async def streamer` generator → forces `Transfer-Encoding: chunked`, no `Content-Length`. Asserts 413 AND that the streamer was cut off bounded by `max_bytes + 2 × 64 KB` of slack. |

Both assert `resp.json()["detail"]["code"] == "payload_too_large"` — the project's existing structured error envelope.

### Phase B.4 — confirmed failing on commit `1c4e733`

```
tests/test_max_upload_size.py::test_post_with_oversize_content_length_returns_413 FAILED [ 50%]
tests/test_max_upload_size.py::test_post_with_chunked_oversize_returns_413 FAILED [100%]

E       AssertionError: expected 413 from streaming oversize body; got 422
        (body: '{"detail":[{"type":"json_invalid","loc":["body",0],"msg":"JSON
        decode error","input":{},"ctx":{"error":"Expecting value"}}]}')
E       assert 422 == 413
========================= 2 failed, 1 warning in 1.56s =========================
```

The pre-fix code returns `422` because FastAPI's Pydantic body parser (Starlette buffers the entire body, then `json.loads` fails on the synthetic non-JSON payload) rejects before the `SBOMSourceCreate` schema validation. No size enforcement exists.

### Phase D.4 — confirmed passing on commit `85af821`

```
tests/test_max_upload_size.py::test_post_with_oversize_content_length_returns_413 PASSED [ 50%]
tests/test_max_upload_size.py::test_post_with_chunked_oversize_returns_413 PASSED [100%]
========================= 2 passed, 1 warning in 1.51s =========================
```

---

## Files modified

| File | Lines changed | Notes |
|---|---|---|
| [app/middleware/__init__.py](../app/middleware/__init__.py) | +5 | new package; re-exports `MaxBodySizeMiddleware`. |
| [app/middleware/max_body.py](../app/middleware/max_body.py) | +143 | new pure-ASGI middleware. Wraps `receive` + `send`, handles both attack shapes. Method allowlist (`GET/HEAD/OPTIONS/DELETE`) skips the check. Logs each rejection at `WARNING` so 413s remain in the audit trail despite being added outermost (above `log_requests`). |
| [app/main.py](../app/main.py) | +8 | one new import + one `app.add_middleware(...)` call placed LAST so Starlette's insert-at-0 semantics put it OUTERMOST. Existing middlewares left untouched. |
| [tests/test_max_upload_size.py](../tests/test_max_upload_size.py) | +96 | new file (Phase B). |
| [audit/r3_upload_size_discovery.md](r3_upload_size_discovery.md) | +125 | new file (Phase A). |

Net across R3 (`5d0002f..85af821`): **5 files, +377 / 0**.

---

## Test summary

```
======================= 223 passed, 5 warnings in 8.90s ========================
```

All 223 tests green (221 prior + 2 new). The 5 warnings are pre-existing (Pydantic V2 deprecation, JWT key-length info notes — neither introduced by this PR).

---

## Commits applied

| Commit | Phase | Subject |
|---|---|---|
| `5d0002f` | A (R2 closeout) | docs(audit): add R2 merge final report |
| `1c4e733` | B | test(security): add failing tests for MAX_UPLOAD_BYTES enforcement (BE-001) |
| `85af821` | D | fix(security): enforce MAX_UPLOAD_BYTES via ASGI middleware (BE-001) |

R3 used 2 prompt-budget commits (B and D) per the prompt's constraint. The Phase A discovery doc was bundled into the Phase B commit so the audit trail stayed within the budget. The R2 closeout doc commit (`5d0002f`) was unrelated leftover from the prior task.

Chronology proves the fix: red between `1c4e733` and `85af821`, green at `85af821`.

---

> "R3 complete. MAX_UPLOAD_BYTES enforced via ASGI middleware. Both honest-oversize and chunked-oversize attack shapes covered. Awaiting confirmation before push."
