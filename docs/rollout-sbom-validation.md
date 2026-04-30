# Rollout — SBOM validation pipeline (ADR-0007)

This document covers the **delivery** of the eight-stage validator: how we
move existing API consumers, how we ship the change progressively, and
how we verify it stuck after deploy.

Audience: anyone shipping the change end-to-end (deploy lead, on-call,
the team integrating the API).

For the design, read [ADR-0007](adr/0007-sbom-validation-architecture.md).
For day-2 operations, read [the runbook](runbook-sbom-validation.md).

---

## 1. Migration note for existing API consumers

### What changed

| Endpoint | Before | After |
|---|---|---|
| `POST /api/sboms` | Stored the row first, then "best-effort" parsed components. Malformed SBOMs persisted with empty component lists. | Validated **before** storing. Rejected SBOMs return 4xx and never persist a row. The endpoint is marked deprecated in the OpenAPI doc. |
| `POST /api/sboms/upload` | (did not exist) | New multipart endpoint — the canonical entry point for new integrations. Same validation pipeline; same error contract. |
| `POST /api/sboms/{id}/analyze` | Re-parsed the stored body each time. | Unchanged behavior; will be migrated to read the validated internal model in a follow-up. |

### Status codes that didn't exist before

The legacy endpoint returned **HTTP 500 with a generic message** for any
malformed SBOM. Callers branching on status codes need to add handling
for these new codes:

| Status | When | What to do |
|---|---|---|
| **413** | Body too large / decompression bomb | Compress, split, or contact your operator |
| **415** | Unsupported format / spec version (e.g. SPDX 3.0, CycloneDX Protobuf) | Re-export as a supported format |
| **422** | Schema or semantic violation | Read the `entries[].path` to find the offending field |
| **400** | Encoding error / parse failure / security cap | Fix the structural issue (encoding, JSON nesting, …) |

The response body shape on any 4xx is **always**:

```json
{"detail": {"entries": [{"code": "...", ...}, ...], "truncated": false}}
```

A previously 500-handling catch can be split into "unexpected (5xx)"
and "validation failure (4xx with entries)" branches. Concrete
example for a JS client:

```ts
// before
try { await fetch("/api/sboms", { ... }); }
catch (e) { showToast("upload failed"); }

// after
const r = await fetch("/api/sboms/upload", { ... });
if (r.status === 202) { /* success */ }
else if (r.status >= 400 && r.status < 500) {
  const body = await r.json();
  for (const entry of body.detail.entries) {
    showFieldError(entry.path, entry.message, entry.remediation);
  }
} else {
  showToast("unexpected server error");
}
```

### Existing rows are NOT retroactively rejected

SBOMs already in the database have **never** been validated. We do not
re-validate them on read. Two consequences:

1. The first analyse on each pre-existing row may now return 422 with a
   structured report — the SBOM remains in the DB, but the analyse
   itself produces no findings until the SBOM is re-uploaded.
2. A separate operator CLI (`python -m app.validation.audit_existing`)
   will iterate every row, run the validator, and write a triage queue.
   The CLI is a follow-up; flag this to your customer-success team so
   they can warn the largest customers ahead of time.

### Deprecation timeline

- **Today** — both endpoints accept uploads. Both validate. The legacy
  `POST /api/sboms` carries `Deprecation: true` and `Sunset: <date>`
  headers (planned).
- **+1 release** — legacy endpoint logs a WARN per request to surface
  remaining traffic.
- **+2 releases** — legacy endpoint returns `410 Gone` with a pointer
  to the multipart upload.

---

## 2. Rollout plan

### Pre-deploy (day -3 to day 0)

1. **Land the feature flag.** `SBOM_VALIDATION_ENABLED=false` short-circuits
   the new pipeline, falls back to legacy `extract_components`, returns
   the legacy response shape. Default `true` in test, `false` in prod
   for the canary phase. (Flag wiring is a < 50-line follow-up PR; the
   pipeline already supports being bypassed because the legacy router
   doesn't import it.)
2. **Bake in staging for 48 h.** Re-validate every SBOM uploaded by the
   internal QA tenant, compare rejection rates against the legacy
   "pass-everything" baseline, expect ≤ 5 % new rejections (mostly
   schema violations the old parser would have accepted with empty
   components). Investigate every new rejection class.
3. **Pre-warm the SPDX licence-list cache** in the staging lifespan
   hook (validate one SPDX fixture during startup) — see
   [runbook §"Cold caches"](runbook-sbom-validation.md#cold-caches).
4. **Confirm the import-linter contracts pass in CI.** The two new
   contracts in [`pyproject.toml`](../pyproject.toml) keep
   `app.validation` from importing routers / services / DB / models /
   `requests` / `httpx`.
5. **Check `python scripts/gen_error_code_reference.py --check` is
   green** — wire it into the lint stage.

### Canary (day 1)

| Hour | Cohort | Flag value |
|---|---|---|
| 0 | Internal-only tenants (1–5 % traffic) | `SBOM_VALIDATION_ENABLED=true` |
| 4 | If error budget is intact: 25 % traffic | `=true` |
| 24 | If error budget is intact: 100 % traffic | `=true` |

**Error budget:**
- p95 latency on `POST /api/sboms*` routes must stay below 750 ms (1.5×
  the design budget — gives headroom for cold caches without false
  alarms).
- Rejection rate must stay below 10 % across the canary cohort. A higher
  rate means we caught a class of bad SBOMs the old code accepted —
  triage **before** scaling further.
- Zero 500s from the validator. **Any 500 with stage in
  {"ingress","detect","schema","semantic","integrity","security","ntia","signature"}
  is an automatic rollback trigger.**

### Rollback triggers

Flip `SBOM_VALIDATION_ENABLED=false` and page on-call if **any** of:

1. p95 of `POST /api/sboms/upload` > 1500 ms for > 5 minutes.
2. > 5 distinct 500-stage errors in 1 hour.
3. Rejection rate > 30 % for > 15 minutes (something in production
   exporter behaviour we missed).
4. Auth / DB / Celery error rates correlate with the canary rollout.

The rollback **does not require a redeploy** — the flag is read at
request time. Confirmed-bad rollouts are reversible in seconds.

### After 100 %

1. Bake at 100 % for **3 days** before considering the change committed.
2. After 3 days, schedule the deprecation timeline above.
3. Schedule the audit-existing CLI run on the largest tenants in
   coordination with customer success.

---

## 3. Post-deploy verification checklist

Run this checklist within 30 minutes of flipping each canary stage.
Anything failing → either fix or rollback; do not "wait it out."

### A. Health & wiring

- [ ] `GET /health` returns 200 with the new validator schemas mounted
      (`schemas_loaded > 0` if the health endpoint is extended to expose
      it; otherwise grep the startup log for "schemas loaded").
- [ ] `GET /docs` shows the new `POST /api/sboms/upload` route under
      the `sboms` tag.
- [ ] `import-linter` and `mypy --strict` are clean against
      `app/validation/`.

### B. Golden-path uploads

For each of these, expect the matching code in the response. Run from a
prod-shaped network (not localhost) so the middleware path is real.

- [ ] **Valid CycloneDX 1.6 JSON** → 202 with `sbom_id` populated, zero
      errors, possibly NTIA warnings.
- [ ] **Valid SPDX 2.3 JSON** → 202 with `spec="spdx"`,
      `spec_version="SPDX-2.3"`.
- [ ] **Valid CycloneDX 1.6 XML** → 202 with `spec="cyclonedx"`,
      `encoding="xml"` (in metadata).
- [ ] **gzip-encoded valid SBOM** with `Content-Encoding: gzip` → 202.
- [ ] **`?strict_ntia=true` against an SBOM missing supplier** → 422
      with `SBOM_VAL_W100_NTIA_SUPPLIER_MISSING` promoted to error.

### C. Rejection paths

- [ ] **Empty body** → 400 + `SBOM_VAL_E005_EMPTY_BODY`.
- [ ] **51 MB body** → 413 + `SBOM_VAL_E001_SIZE_EXCEEDED`.
- [ ] **Both `bomFormat` and `spdxVersion`** → 415 +
      `SBOM_VAL_E011_FORMAT_AMBIGUOUS`.
- [ ] **CycloneDX 1.6 with malformed PURL** → 422 +
      `SBOM_VAL_E052_PURL_INVALID`.
- [ ] **SPDX 2.3 with non-`CC0-1.0` `dataLicense`** → 422 +
      `SBOM_VAL_E042_DATA_LICENSE_INVALID`.
- [ ] **CycloneDX with duplicate `bom-ref`** → 422 +
      `SBOM_VAL_E051_BOM_REF_DUPLICATE`.

### D. Attack paths

- [ ] **JSON depth-bomb fixture (80 levels)** → 400 +
      `SBOM_VAL_E080_JSON_DEPTH_EXCEEDED`. Wall time < 100 ms.
- [ ] **Billion-laughs XML** → 400 + one of `E083` / `E084` / `E085`.
      Wall time < 100 ms.
- [ ] **Decompression-bomb gzip (300 MB → 305 KB)** → 413 + one of
      `E002` / `E003`. Wall time < 1 s.
- [ ] **Document with `__proto__` key under a known nested path** →
      400 + `SBOM_VAL_E087_PROTOTYPE_POLLUTION_KEY`.

### E. Observability

- [ ] Each request emits exactly one log line (`api.access` INFO for 2xx,
      WARN for 4xx, ERROR for 5xx). No DEBUG spam from the validator
      (validation is supposed to be silent until the final structured
      line).
- [ ] No log line contains the SBOM body bytes (PII / IP risk — verify
      by grepping for `pkg:` substrings in the log stream over the
      canary window).
- [ ] Prometheus counters
      `validation_rejection_total{stage,code}` (or your equivalent) are
      ticking for the rejection paths exercised in §C / §D.
- [ ] Latency histogram per stage matches the budget table in
      [the runbook](runbook-sbom-validation.md#2-p95-latency-per-stage).

### F. Negative tests for the legacy endpoint

- [ ] `POST /api/sboms` with a malformed `sbom_data` field returns the
      **same** 4xx + entries shape as `POST /api/sboms/upload` — same
      pipeline.
- [ ] `POST /api/sboms` carries the `Deprecation: true` header (planned
      header — verify after that PR lands).

### G. End-to-end with a real-world SBOM

Per the workplan §6 success criteria — pick **one real SBOM each from
kubernetes / npm / cpython** (or the closest publicly-available
substitute) and verify:

- [ ] Upload returns 202.
- [ ] `POST /api/sboms/{id}/analyze` returns a populated finding count.
- [ ] PDF report generation works against the resulting run.

---

## 4. Communications

### Internal (engineering)

- Post in `#sbom-platform` Slack: "Canary at 1 % from <time>; flag is
  `SBOM_VALIDATION_ENABLED`; rollback is one env-var flip; runbook at
  [docs/runbook-sbom-validation.md](runbook-sbom-validation.md)."
- Update the on-call runbook page with a link to the rollout doc.

### External (customers via API)

- Mark `POST /api/sboms` deprecated in OpenAPI (planned).
- Add a banner to the dashboard SBOM-upload UI pointing to the new
  validation feedback ("Your SBOM is checked against SPDX / CycloneDX
  spec before storing — errors will tell you exactly what to fix").
- Send a customer-success email to the top-N tenants summarising the
  change with three bullets: stricter validation, structured errors, no
  retroactive rejection.

### After full rollout

- Update the [README.md "Supported SBOM Formats" table](../README.md#supported-sbom-formats)
  if anything moved (already current as of 2026-04-30).
- Schedule a 1-month review meeting to look at the rejection-rate top-10
  and decide whether any class warrants a warning-instead-of-error.

---

## 5. Sign-off

This rollout is considered done when **all** of the following are true
for **3 consecutive days**:

- [ ] 100 % of upload traffic flows through the new pipeline.
- [ ] Rejection rate is steady (no growing trend).
- [ ] Zero 500s from any validator stage.
- [ ] p95 of `POST /api/sboms/upload` < 500 ms.
- [ ] No customer escalation tickets blocking the deprecation timeline.
