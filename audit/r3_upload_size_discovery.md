# R3 — Discovery: `MAX_UPLOAD_BYTES` enforcement

> Audit reference: BE-001 (per refactor-plan R3).
> Repo HEAD verified at `cc7f351` (post-R2). Audit was on `4435bd2`. Line numbers re-verified against current HEAD.

---

## A.1 — Setting exists, current value

**Location**: [app/settings.py:225](../app/settings.py#L225).

```python
# Maximum upload size (20 MB)
Settings.MAX_UPLOAD_BYTES = 20 * 1024 * 1024
```

**Form**: assigned as a class attribute on `Settings` (not a Pydantic `Field`). It is therefore **a static module-load-time constant**, not env-overridable through Pydantic's `BaseSettings` mechanism. Default is **20,971,520 bytes (20 × 1024 × 1024)**.

`Settings` itself is a `pydantic_settings.BaseSettings` subclass at [app/settings.py:31](../app/settings.py#L31). Access pattern is `from app.settings import get_settings; get_settings().MAX_UPLOAD_BYTES` — confirmed by [app/settings.py:246-259](../app/settings.py#L246-L259).

**Audit's claim verified**: the constant exists at the path/line/value stated.

---

## A.2 — No existing enforcement

### `MAX_UPLOAD_BYTES` references

```
$ grep -rn "MAX_UPLOAD_BYTES" --include='*.py' .
app/settings.py:225:Settings.MAX_UPLOAD_BYTES = 20 * 1024 * 1024
```

Only the declaration. No reader. No enforcement.

### `Content-Length` references in the app

```
$ grep -rn "Content-Length\|content-length\|content_length" --include='*.py' app/
(empty)
```

No header inspection, anywhere in `app/`.

### Existing size-check / 413 handlers

```
$ grep -rn "max_body\|MaxBody\|BodySizeLimit\|413" --include='*.py' app/
(empty)
```

No middleware, no handler, no in-route check. Confirms R3 has not been partially implemented.

### Raw body / `UploadFile` consumers

```
$ grep -rn "request.body()\|await.*\.body()\|UploadFile" --include='*.py' app/
(empty)
```

**Notable**: no route uses `UploadFile` or `await request.body()`. Every body-accepting route binds a Pydantic model parameter. FastAPI buffers the entire body into memory before invoking the handler, so the DoS surface is the JSON body buffering — not file streaming.

---

## A.3 — POST/PUT/PATCH route inventory

| File | Route | Method | Body schema | Body size profile | Notes |
|---|---|---|---|---|---|
| [app/routers/sboms_crud.py:299](../app/routers/sboms_crud.py#L299) | `POST /api/sboms` | POST | `SBOMSourceCreate` ([schemas.py:58](../app/schemas.py#L58)) | **Unbounded.** `sbom_data: str \| None` carries the entire raw SBOM JSON inside the request body. | **Primary DoS surface.** This is the route the test will target. |
| [app/routers/sboms_crud.py:459](../app/routers/sboms_crud.py#L459) | `PATCH /api/sboms/{sbom_id}` | PATCH | `SBOMSourceUpdate` ([schemas.py:185](../app/schemas.py#L185)) | **Unbounded.** Same `sbom_data: str \| None` field on update path. | Secondary DoS surface. |
| [app/routers/sboms_crud.py:571](../app/routers/sboms_crud.py#L571) | `POST /api/sboms/{sbom_id}/analyze` | POST | none — body ignored | empty / minimal | No body-driven payload. |
| [app/routers/sboms_crud.py:604](../app/routers/sboms_crud.py#L604) | `POST /api/sboms/{sbom_id}/analyze/stream` | POST | `AnalyzeStreamPayload` ({sources: list[str] \| None}) | tiny | Capped by len(sources) × ~10 chars each. |
| [app/routers/projects.py:59](../app/routers/projects.py#L59) | `POST /projects` | POST | `ProjectCreate` ([schemas.py:19](../app/schemas.py#L19)) | tiny | name + status + optional details |
| [app/routers/projects.py:104](../app/routers/projects.py#L104) | `PATCH /projects/{project_id}` | PATCH | `ProjectUpdate` ([schemas.py:171](../app/schemas.py#L171)) | tiny | same fields |
| [app/routers/analyze_endpoints.py:261](../app/routers/analyze_endpoints.py#L261) | `POST /analyze-sbom-nvd` | POST | `AnalysisByRefNVD` | tiny | sbom_id/sbom_name + int |
| [app/routers/analyze_endpoints.py:292](../app/routers/analyze_endpoints.py#L292) | `POST /analyze-sbom-github` | POST | `AnalysisByRefGitHub` | tiny | same |
| [app/routers/analyze_endpoints.py:323](../app/routers/analyze_endpoints.py#L323) | `POST /analyze-sbom-osv` | POST | `AnalysisByRefOSV` | tiny | same |
| [app/routers/analyze_endpoints.py:354](../app/routers/analyze_endpoints.py#L354) | `POST /analyze-sbom-vulndb` | POST | `AnalysisByRefVulnDb` | tiny | same |
| [app/routers/analyze_endpoints.py:387](../app/routers/analyze_endpoints.py#L387) | `POST /analyze-sbom-consolidated` | POST | `AnalysisByRefConsolidated` | tiny | same |
| [app/routers/pdf.py:113](../app/routers/pdf.py#L113) | `POST /pdf-report` | POST | `PdfReportByIdRequest` ({runId, title?, filename?}) | tiny | response is a possibly-large PDF, but that's a server **output**, not an inbound request. |

DELETE routes (`DELETE /projects/{id}`, `DELETE /api/sboms/{id}`) take query params only — no body. Allowlisting `GET/HEAD/OPTIONS/DELETE` in the middleware is safe.

---

## A.4 — Routes that legitimately exceed `MAX_UPLOAD_BYTES`

**None.** Two routes (`POST /api/sboms`, `PATCH /api/sboms/{id}`) carry the SBOM JSON inside the request body, and 20 MB is generous for an SBOM — typical CycloneDX/SPDX outputs are in the low single-digit MB range; the project's seeded fixture in [tests/fixtures/sample_sbom.json](../tests/fixtures/sample_sbom.json) is well under 100 KB.

The SSE streaming endpoint `POST /api/sboms/{id}/analyze/stream` is request-side small; the **response** is the streaming body (server → client, unaffected by request-body limits).

PDF response payloads are server-generated — also unaffected.

**No per-route override mechanism is needed.** App-wide enforcement applies cleanly.

---

## A.5 — Tests that would break

```
$ grep -rn "MAX_UPLOAD_BYTES\|413\|RequestEntityTooLarge\|content.length\|content_length" --include='*.py' tests/
(empty)
```

No test asserts oversize-body acceptance, asserts 413, or otherwise references the limit. The middleware can be added without changing any existing test.

The fixture SBOM ([tests/fixtures/sample_sbom.json](../tests/fixtures/sample_sbom.json)) is well under 20 MB so [tests/conftest.py:124-143](../tests/conftest.py#L124-L143) (`seeded_sbom`) and the snapshot suite that depends on it remain unaffected.

---

## A.6 — Conclusion

- `MAX_UPLOAD_BYTES` exists at [`app/settings.py:225`](../app/settings.py#L225) with default `20 * 1024 * 1024` bytes (20,971,520).
- **2** routes accept large-content bodies (`POST /api/sboms`, `PATCH /api/sboms/{id}`); **0** of them legitimately exceed the limit.
- **0** existing tests would break.
- The existing middleware stack in [app/main.py:170-224](../app/main.py#L170-L224) is `SlowAPI → CORS → GZip → log_requests`. New middleware will go OUTERMOST (added last → first to run inbound) per the prompt's guidance.
- No `app/middleware/` package exists; will be created.
- No `app/error_handlers.py` exists; the 413 envelope must match the project's existing structured-error pattern (`{"detail": {"code": "...", "message": "..."}}`) seen at [app/routers/sboms_crud.py:316-321 / :355-357 / :361-363](../app/routers/sboms_crud.py).
- `httpx>=0.28.1` is already a project dependency ([pyproject.toml:21](../pyproject.toml)), so the chunked-streaming test can use `httpx.ASGITransport` without adding a dep.

**Verdict**: PROCEED.

---

**End of Phase A.** Proceeding to Phase B.
