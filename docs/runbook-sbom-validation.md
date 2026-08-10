# Runbook — SBOM validation pipeline

Operator-facing reference. Audience: on-call engineers, SREs, anyone
holding the pager when an SBOM upload starts misbehaving.

For the design, read [ADR-0007](adr/0007-sbom-validation-architecture.md).
For the user-facing fix-it list, read [sbom-validation.md](sbom-validation.md).

---

## At a glance

- The pipeline runs synchronously inside the request handler for
  payloads up to **5 MB** (`Settings.SBOM_SYNC_VALIDATION_BYTES`). Above
  that, the request returns 202 and the heavy stages run on Celery.
- Every rejection is **structured**: HTTP 4xx + a JSON body with
  `entries[]` of stable error codes. A 500 from the validator is **always
  a bug**.
- Validation is **side-effect-free**: no DB write, no S3 write, no log
  line above DEBUG until validation completes (then a single structured
  INFO/WARN/ERROR per request).

---

## Metrics to watch

The pipeline emits one log line per request at INFO. Operators should
front this with a Prometheus exporter / Loki / Datadog query that exposes
the four golden series below.

### 1. Rejection rate per stage

`count by stage of (validation_result == "rejected")` over a 5-minute
window.

| Threshold | Meaning |
|---|---|
| **Stage 1 / 2 spike** | Likely abuse (oversize bodies, scanning probes) — check whether the source IPs are repeat offenders, consider WAF rule |
| **Stage 3 spike** | Spec / schema drift — a new exporter version is emitting non-conformant SBOMs. Inspect top `path` values |
| **Stage 4 / 5 spike** | Data-quality regression at a specific exporter — typically harmless but worth a follow-up with the team that owns the exporter |
| **Stage 6 spike** | Active attack OR a buggy exporter producing prototype-pollution-shaped keys. Treat as P2; correlate with source IP |
| **Stage 7 spike** | Customer turned on `?strict_ntia=true` and most of their SBOMs are incomplete. Reach out before scaling alarm levels |
| **Stage 8 spike** | Signature feature was rolled out — see "Signature rollout" below |

### 2. p95 latency per stage

`histogram_quantile(0.95, validation_stage_duration_seconds_bucket)`
broken down by `stage`.

Baselines (under load on the realistic fixtures):

| Stage | Median budget | p95 budget |
|------:|---------------:|-----------:|
| 1 ingress | < 1 ms | < 5 ms |
| 2 detect | < 5 ms | < 20 ms |
| 3 schema | 10–25 ms | 50 ms |
| 4 semantic | 5–20 ms | 50 ms |
| 5 integrity | 1–5 ms | 20 ms |
| 6 security | 1–5 ms | 20 ms |
| 7 NTIA | < 5 ms | 20 ms |
| 8 signature | < 1 ms (off) / 5–20 ms (on) | 50 ms |
| **Total** | **< 50 ms** | **< 500 ms** |

If stage 4 latency creeps up over hours, suspect license-expression
cache miss — see "Cold caches" below.

### 3. Top error codes (rolling 24 h)

`topk(10, sum by code (validation_rejection_total))`. Track which codes
trend over time. A sudden new entry in the top 10 = upstream change in
a customer's SBOM exporter.

### 4. Truncation rate

`rate(validation_response_truncated_total[5m])`. Truncation
(`"truncated": true`) means a single document tripped > 100 entries —
indicates either a broken exporter or a customer trying to validate a
non-SBOM document. Should be < 1 % of rejections.

---

## How to triage a false positive

A user reports "my SBOM was rejected but it's valid." Three steps:

### Step 1 — get the correlation_id

Every rejection response carries the structured envelope:

```json
{"detail": {"entries": [{"code": "...", "path": "...", "stage": "..."}], ...}}
```

Ask the user for the **first error code** and the **`path`**. That's
enough to find the matching log line.

### Step 2 — reproduce

Save the user's SBOM bytes (with their explicit consent — SBOM bodies
are confidential) and run it through the pipeline locally:

```bash
.venv/bin/python -c "
from app.validation import run as run_validation
import sys
report = run_validation(open('user-sbom.json','rb').read())
for e in report.entries[:10]:
    print(e.severity.value, e.code, '|', e.path, '|', e.message[:120])
print('http_status =', report.http_status)
"
```

If the rejection reproduces locally, the validator is working as
intended — the SBOM really is invalid, and the user needs to talk to
the team that owns the exporter that produced it. Forward them
[the user guide](sbom-validation.md) and the specific code.

### Step 3 — if the rejection seems wrong

Open an issue with **(a) the redacted SBOM**, **(b) the error code +
path**, and **(c) the spec section** the user thinks the validator is
misinterpreting. Cross-check against:

- the [vendored schema](../app/validation/schemas/) for that spec
  version (start with `app/validation/schemas/<spec>/<version>/`);
- the relevant section in
  [ADR-0007](adr/0007-sbom-validation-architecture.md);
- the upstream spec section listed in the error's `spec_reference`.

If the validator is wrong, the fix lives in **one of the eight stage
modules** — never spread across them. Add a fixture under
`tests/fixtures/sboms/edge/` that captures the user's case so it
becomes a regression test.

---

## Bumping a vendored schema

When a new SPDX or CycloneDX version drops, the bump is a single PR with
three pieces:

1. **Vendor the schema files** under
   `app/validation/schemas/{spdx,cyclonedx}/<new-version>/`. Pull them
   from the upstream tag, never from a branch HEAD. The schemas
   directory needs an `__init__.py` so `importlib.resources.files()` can
   navigate to it.

2. **Update `SOURCE.md`** in the same directory. Add a row recording:
   - origin URL,
   - upstream commit SHA (`gh api repos/<repo>/commits/<tag>`),
   - retrieval date (today, in `YYYY-MM-DD`),
   - licence (CC0-1.0 for SPDX, Apache-2.0 for CycloneDX).

3. **Update the supported-versions set** in
   [`app/validation/stages/detect.py`](../app/validation/stages/detect.py):

   ```python
   _SUPPORTED_CDX = {"1.4", "1.5", "1.6", "1.7"}   # add the new version
   _SUPPORTED_SPDX_JSON = {"SPDX-2.2", "SPDX-2.3"}
   ```

   If the spec changed shape (new top-level fields, renamed enums) you
   *also* need a sibling `semantic_<spec>_<major>.py` module — see
   `semantic_spdx3.py` for the deferred-version stub pattern.

4. **Add a fixture** under `tests/fixtures/sboms/valid/` exercising the
   new version, plus an entry in `tests/validation/expected_outcomes.json`.

5. **Run the suite** before opening the PR:

   ```bash
   pytest tests/validation/ -m schema --cov=app.validation --cov-fail-under=90
   ```

6. **Add a CHANGELOG row** under "## [Unreleased] / Added".

CycloneDX XSDs `<xs:import>` an external `spdx.xsd` from the URL
`http://cyclonedx.org/schema/spdx`. We rewrite that to a local
`schemaLocation="spdx.xsd"` in the vendored copy so lxml resolves the
import without a network round-trip — see
[`app/validation/schemas/cyclonedx/SOURCE.md`](../app/validation/schemas/cyclonedx/SOURCE.md).

---

## Cold caches

The SPDX semantic stage caches the SPDX License List internally
(`license_expression.get_spdx_licensing()`, ~10 MB Aho-Corasick trie).
First request after a cold start pays ~150 ms; every subsequent SPDX
request is < 1 ms.

If you observe stage-4 p95 spiking on a fresh pod, **warm the cache** in
the lifespan startup hook by validating one SPDX fixture during
boot. The realistic fixture under
[`tests/fixtures/sboms/valid/spdx_2_3_realistic.json`](../tests/fixtures/sboms/valid/spdx_2_3_realistic.json)
exists for this purpose.

---

## Signature verification rollout

Stage 8 (signature) is feature-flagged off by default
(`SBOM_SIGNATURE_VERIFICATION=false`). When you turn it on:

- Any SBOM **without** a signature block produces
  `SBOM_VAL_W113_SIGNATURE_NOT_PRESENT` (warning — does not block).
- Any SBOM **with** a signature block currently produces
  `SBOM_VAL_E110_SIGNATURE_INVALID` because the verifier is a stub.
  This is a deliberate design point — the contract is stable now so
  rolling out the verifier later is a code-only change.

The full rollout (verifier implementation, key-management, sidecar
support for SPDX) is its own ADR — do not flip this flag in production
until that lands.

---

## Quick reference — stage failure → typical fix

| Stage | Typical failure | First thing to check |
|------:|-----------------|----------------------|
| 1 | gzip ratio cap tripped | Is the body actually gzip? Browser may auto-encoded it |
| 1 | UTF-16 BOM | Customer's editor saved as UTF-16; ask them to re-save UTF-8 |
| 2 | Format ambiguous | Customer's exporter merged SPDX and CycloneDX fields — exporter bug |
| 3 | "additionalProperties" violation | Customer's exporter is on the new spec version we don't support yet — see "Bumping a vendored schema" |
| 4 | PURL invalid | `packageurl-python` upstream knows what's wrong; the parser's reason is in the message |
| 4 | License expression invalid | Outdated SPDX License List — bump `license-expression` |
| 5 | Dangling dep ref | Components were filtered post-export but the dependency graph wasn't updated |
| 6 | JSON depth bomb | Real attack OR a customer with an absurd transitive-dep tree — confirm the source |
| 7 | NTIA W104 dominant | Customer enabled `?strict_ntia=true` against incomplete SBOMs |
| 8 | E110 (verifier stub) | Signature flag was turned on prematurely — flip back to false |

---

## Useful commands

```bash
# Regenerate the auto-generated error-code table after edits to errors.py
python scripts/gen_error_code_reference.py

# Verify the error-code table is in sync with errors.py (for CI)
python scripts/gen_error_code_reference.py --check

# Run only the security tests with their wall-time assertions
pytest tests/validation/ -m security

# Run the perf benchmark and emit a stats table
pytest tests/validation/ -m bench

# Full coverage gate
pytest tests/validation/ --cov=app.validation --cov-fail-under=90

# Re-run the validator against an existing SBOM in the DB by id
python -c "
from app.db import SessionLocal; from app.models import SBOMSource
from app.validation import run as run_validation
db = SessionLocal()
row = db.get(SBOMSource, 42)
report = run_validation((row.sbom_data or '').encode())
print(report.http_status)
for e in report.entries[:10]:
    print(' ', e.severity.value, e.code, '|', e.path)
"
```
