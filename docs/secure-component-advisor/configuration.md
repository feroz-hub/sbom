# Secure Component Advisor — configuration

All configuration is **versioned and append-only**. Changes are published as new policy versions through
`POST /api/component-advisor/policies/{kind}/versions` (see [api.md](./api.md)) and never edit an earlier version.

## Tenant Admin settings

Open **Settings → Component Advisor Policies** (`/settings/advisor-policies`) in the active tenant.
Tenant Admins can configure accepted-risk, trust and recommendation-scoring rules, publish a new version with a
required change reason, inspect effective rules and view version history. Choose a tenant policy, inherit the platform
default, or disable the tenant policy. Rules are edited as JSON and validated by the API before publishing.
Security Analysts have read-only access. The page uses `tenant:advisor-policy:read` / `update` permissions and the
active tenant context. A concurrent edit requires reloading the latest policy before another publish.

## Policy scope and resolution

This follows `docs/scoped-configuration.md`. Each kind has a platform default slot (`tenant_id IS NULL`) and at most one
tenant override slot. For a tenant:

1. The tenant slot's latest version:
   - **ACTIVE** applies;
   - **DISABLED** means no policy, and the platform default is deliberately blocked;
   - **INHERIT** falls through to step 2.
2. Otherwise the platform slot's latest ACTIVE version.
3. Otherwise there is no policy: nothing is Accepted Risk or Trusted, and scoring uses the built-in default.

The platform-default write API is **not implemented yet** (see the plan's open items). Platform rows are honoured when
they are present, for example when inserted by an operator script.

## Accepted-risk policy (`kind = accepted-risk`, FR-SCA-004)

```json
{
  "max_actionable_severity": "MEDIUM",
  "max_cvss_score": 6.9,
  "allowed_actionable_vex_statuses": ["UNDER_INVESTIGATION"],
  "max_actionable_vulnerabilities": 3,
  "allowed_lifecycle": ["SUPPORTED", "MAINTENANCE"],
  "max_analysis_age_days": 30
}
```

| Rule | Required | Meaning |
|---|---|---|
| `max_actionable_severity` | yes | `MEDIUM` or `LOW`. Critical/High can never be accepted, because they outrank review reasons and policy. |
| `max_cvss_score` | no | 0–10. A version with no CVSS fails this criterion. |
| `allowed_actionable_vex_statuses` | no (default both) | A subset of `AFFECTED` and `UNDER_INVESTIGATION`. |
| `max_actionable_vulnerabilities` | no | Integer ≥ 0. |
| `allowed_lifecycle` | no | Lifecycle buckets. |
| `max_analysis_age_days` | no | A missing analysis timestamp fails. |

A version with review reasons is never accepted. Every evaluation records its policy version id and per-criterion trace.

## Trust policy (`kind = trust`, FR-SCA-005) — disabled until configured

```json
{
  "allowed_classifications": ["NO_KNOWN_ACTIONABLE_VULNERABILITIES", "LOW"],
  "allowed_lifecycle": ["SUPPORTED"],
  "allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "denied_licenses": ["AGPL-3.0"],
  "max_evidence_age_days": 90,
  "min_tenant_products": 2,
  "require_no_review_reasons": true
}
```

- `allowed_classifications` and `allowed_lifecycle` are **required**, so trust can never come from adoption alone (T9).
- `allowed_classifications` may only contain NKAV, ACCEPTED_RISK, LOW or MEDIUM.
- `min_tenant_products` is an optional extra criterion.
- **The trust policy's license lists are also the license gate** for candidate compatibility. A denied license, or one
  outside the allow list, is a blocking FAIL. With no lists configured, a changed license is REVIEW_REQUIRED.
- **`allowed_lifecycle` is also the candidate lifecycle gate.** Without a trust policy, an EOL candidate is a blocking
  FAIL and an EOS candidate is REVIEW_REQUIRED.

## Scoring policy (`kind = scoring`, FR-SCA-017)

The built-in default is `builtin-default-2026-10-01`, used when no SCORING version applies. The weights are proposed for
review.

```json
{
  "weights": {
    "current_risk": 0.30, "lifecycle": 0.20, "vulnerability_trend": 0.15, "compatibility": 0.15,
    "maintenance": 0.08, "license": 0.05, "tenant_adoption": 0.05, "evidence_freshness": 0.02
  },
  "missing_data": "PENALIZE",
  "history_window_months": 24,
  "stale_after_days": 90
}
```

| Rule | Meaning |
|---|---|
| `weights` | Non-negative and normalized to sum to 1. Factor normalizations are documented in `recommendations/scoring.py`. `maintenance` has no evidence source yet, so it is always missing. |
| `missing_data` | `PENALIZE`: a missing factor scores 0. `EXCLUDE`: its weight is dropped and the rest are renormalized. Confidence completeness always uses the configured weights. |
| `history_window_months` | 6–120. The vulnerability-history window (FR-SCA-016). |
| `stale_after_days` | 1–3650. Older evidence lowers confidence and is flagged. It does **not** change the risk bucket. |

The score only orders candidates. It never lifts a blocked candidate and never makes one acceptable.

## Other thresholds (code constants, reported in `meta.thresholds`)

| Constant | Value | Where |
|---|---|---|
| Frequently adopted | ≥ 3 distinct products | `filters.FREQUENT_ADOPTION_MIN_PRODUCTS` |
| Snapshot cache TTL | 300 s; change markers bust it sooner | `intelligence_service.SNAPSHOT_TTL_SECONDS` |
| `as_of` tolerance | 300 s | `intelligence_service.AS_OF_TOLERANCE_SECONDS` |
| Max alternatives per evaluation | 10 | `alternative_discovery.MAX_ALTERNATIVES` |

## Purpose metadata (FR-SCA-009)

Sources, in priority order per field:

1. SBOM-declared component description. Fill existing rows with `scripts/backfill_component_descriptions.py --apply`.
2. `PACKAGE` rows.
3. `CURATED` rows (a tenant row overrides the platform row).
4. `AI` rows.

Write rows with `PUT /purpose/{family_key}`. AI rows must include `provenance.model` and `provenance.generated_at`. They
are always flagged `ai_assisted`, and LOW-confidence AI never satisfies a purpose or category search. There is no
automatic AI classification job; the seam exists, and enabling one requires the existing `AiSettings` gates.

## External package-metadata sources (FR-SCA-012, NFR-SCA-003)

Adapters implement `PackageMetadataSource.find_alternatives(ecosystem, category, purpose_text)` in
`app/services/component_advisor/sources.py` and are registered with `register_source()`.

- **None are registered by default.** Spec §12 requires an approved source list, licensing review and refresh limits
  first.
- Each call has a 5 s timeout and a per-source circuit breaker (3 failures → open for 15 min).
- Failures become `*_EXTERNAL_SOURCE_DEGRADED` outcomes and never errors.
- Adapter candidates still pass the same purpose and compatibility gates as any other candidate.

## Vulnerability history source

The NVD mirror is used per version CPE when `NVD_MIRROR_ENABLED=true`. Otherwise history comes from the tenant's own
analyses, and coverage reports `NVD_MIRROR_DISABLED`.
