# Requirement — Scheduled Consolidated Report Notifications

> **Status:** Draft for review
> **Author:** Feroze Basha S
> **Date:** 2026-09-04
> **Applies to:** SBOM Spectra / SBOM Analyser `2.0.0`
> **Current Alembic head at time of writing:** `044_kev_vulnerabilities_table`
> **Companion docs:** [`metric-conventions.md`](./metric-conventions.md) · [`runbook-compare.md`](./runbook-compare.md) · [`notification-coverage.md`](./notification-coverage.md) · [`adr/0008-compare-runs-architecture.md`](./adr/0008-compare-runs-architecture.md)

---

## 1. Purpose

When a scheduled analysis runs today, the result is silent. A user has to remember to open the
application, navigate to the run, and manually pick a second run to compare against. Nothing is
pushed, nothing is summarised, and nothing tells a project owner that their posture moved.

This requirement defines a **scheduled report notification** capability: after a scheduled analysis
completes, subscribed users receive an email containing a consolidated posture report and three
comparison views — against the previous run, against the initial baseline, and across SBOM versions.

The intent is that a security analyst who never logs in still knows, on their chosen cadence,
whether their scope got better or worse and why.

---

## 2. Scope

### 2.1 In scope

- Per-user, per-scope subscriptions to scheduled report notifications.
- Scope hierarchy: **Tenant → Project → Product → SBOM**.
- Report composition in four parts (A, B, C, D — see §5).
- Delivery by email: HTML summary in the body, PDF and Excel attachments.
- Same-version and cross-version SBOM comparison semantics.
- Delivery audit, retry, and failure visibility.
- Frontend surfaces for managing subscriptions and viewing delivery history.

### 2.2 Out of scope (this phase)

- In-app notification centre / bell icon (deferred — see §13).
- Webhook, Microsoft Teams, or Slack delivery (deferred).
- SMS or mobile push.
- User-authored report templates or custom branding per tenant.
- Changing how analysis itself is scheduled or executed. This feature *observes* the existing
  scheduler; it does not replace it.
- Real-time / event-driven alerting on individual CVE publication. This is a scheduled digest,
  not an alerting system.

---

## 3. Background — what exists today

Grounding the requirement in the current codebase, so that the delta is explicit.

| Capability | Today | File / table |
|---|---|---|
| Scheduled analysis | Works. Celery Beat `analysis-schedule-tick` fires every 15 min, `find_due_targets` scans due rows, one `analyze_sbom_async` task is enqueued per SBOM. | `app/workers/scheduled_analysis.py`, `app/workers/celery_app.py` |
| Schedule scoping | `analysis_schedule.scope` accepts `PROJECT`, `PRODUCT`, `SBOM`. Project rows cascade to every SBOM in the project at tick time; an SBOM row overrides the cascade. | `AnalysisSchedule` in `app/models.py`, `app/services/schedule_resolver.py` |
| Run-pair comparison | Works. `CompareService.compare(run_a_id, run_b_id)` produces a component diff, finding diff, posture delta, top contributors, and a `RunRelationship`. Cached in `compare_cache` with a 24 h TTL, keyed order-independently. | `app/services/compare_service.py` |
| Compare export | Cached diffs re-serialise as md / csv / json. | `app/services/compare_export.py`, `POST /api/v1/compare/{cache_key}/export` |
| SBOM version lineage | **New.** Uploads may now declare the SBOM version they supersede, producing a real parent/child chain. Lineage is *declared, not inferred*. | `app/services/sbom_version_lineage.py`, `SBOMSource.parent_id` |
| Excel reporting | Per-SBOM vulnerability workbook, and an FDA 510(k) workbook. | `app/services/sbom_vulnerability_excel_report_service.py`, `app/services/fda_510k_excel_report_service.py` |
| PDF reporting | Report generation exists. | `app/pdf_report.py`, `app/services/pdf_service.py`, `app/routers/pdf.py` |
| Email delivery | SMTP adapter exists but is **verification-only**: the `VerificationEmailSender` Protocol has exactly one method, `send_verification_email`, and no attachment support. | `app/services/email_sender.py`, `app/services/email_templates.py` |
| Metric layer | All user-facing counts must route through `app/metrics/`; conventions A / B / C are mandatory and enforced by an architectural test. | `app/metrics/`, `tests/test_metric_consistency.py` |

### 3.1 Gaps this requirement must close

- **G1** — There is no `TENANT` scope on `analysis_schedule`; the check constraint allows only
  `PROJECT`, `PRODUCT`, `SBOM`.
- **G2** — There is no subscription concept anywhere. No table, no API, no UI.
- **G3** — The email sender cannot send anything other than a verification email, and cannot
  attach files.
- **G4** — Nothing records that a notification was sent, to whom, or whether it succeeded.
- **G5** — `CompareService` distinguishes `same_sbom` but has no notion of *same lineage,
  different version*. Cross-version comparison has no first-class representation.
- **G6** — There is no query for "the initial run" or "the run before the latest" in
  `app/metrics/`; the comparison baselines this feature needs do not exist yet.
- **G7** — Scheduled runs complete without any completion hook other than writing back to
  `analysis_schedule.last_run_*`. There is no place to trigger downstream reporting.

---

## 4. Terminology

| Term | Definition |
|---|---|
| **Scope** | The subscription target: a tenant, project, product, or single SBOM. |
| **Subscription** | A user's standing request to receive reports for one scope on one cadence. |
| **Reporting cycle** | One execution of the report pipeline for one subscription. Produces at most one email. |
| **Latest run** | The most recent `analysis_run` for an SBOM whose `run_status` is `OK`, `FINDINGS`, or `PARTIAL`. |
| **Previous run** | The successful run immediately preceding the latest run for the same `sbom_id`. |
| **Initial run** | The earliest successful run — the baseline. See §5.4 for which baseline applies. |
| **Same-version comparison** | Two runs against the **same** `sbom_source` row. The document did not change; the vulnerability landscape did. |
| **Cross-version comparison** | Runs against **different** `sbom_source` rows connected by the `parent_id` lineage chain. The software changed. |
| **Digest** | One email covering every SBOM in a scope, rather than one email per SBOM. |

---

## 5. Functional requirements

### 5.1 Subscriptions

**NR-1** — A user MUST be able to subscribe to scheduled report notifications for a scope they can
already read. Subscription MUST NOT grant visibility the user does not otherwise have; the backend
tenant and permission checks remain authoritative.

**NR-2** — A subscription MUST record: the subscribing user, the tenant, the scope type
(`TENANT` | `PROJECT` | `PRODUCT` | `SBOM`), the scope target id, the delivery cadence, the
selected report parts, the attachment formats, the severity floor, and an enabled flag.

**NR-3** — Cadence MUST support `ON_EVERY_RUN`, `DAILY`, `WEEKLY`, and `MONTHLY`.
`ON_EVERY_RUN` sends a report each time a scheduled analysis completes for the scope; the others
aggregate everything since the previous successful delivery.

**NR-4** — A user MAY hold multiple subscriptions across different scopes. Where scopes overlap
(a project subscription and an SBOM subscription covering the same SBOM), the system MUST
deduplicate: the **narrowest** subscription wins for that SBOM, and the SBOM is excluded from the
broader scope's digest for that cycle. A user must never receive the same SBOM's report twice in
one cycle.

**NR-5** — A subscription MUST be suppressible without deletion (`enabled = false`), and MUST be
soft-deleted rather than hard-deleted, consistent with `SoftDeleteMixin` usage elsewhere.

**NR-6** — When a user is removed from a tenant, deactivated, or loses read access to a scope,
their subscriptions for that scope MUST stop delivering. This MUST be re-checked at send time, not
only at subscribe time.

**NR-7** — A severity floor (`CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `ALL`, default `ALL`) MUST
filter which findings appear in the detail sections. It MUST NOT filter the headline counts —
the summary always reports the full picture, and the report MUST state that a floor is applied.

**NR-8** — A subscription MUST support "quiet delivery": when a cycle produces **no change** in
Parts B, C, and D, the user MAY elect to receive nothing. Default is to send (an unchanged posture
is itself information). Part A is always non-empty, so this setting is meaningful only when at
least one delta part is selected.

### 5.2 Scope resolution and fan-out

**NR-9** — At cycle time the system MUST resolve a scope to a concrete set of SBOMs:

```
TENANT  -> every non-deleted SBOM in the tenant
PROJECT -> every non-deleted SBOM whose projectid matches
PRODUCT -> every non-deleted SBOM whose product_id matches
SBOM    -> that one SBOM
```

Soft-deleted SBOMs, projects, and products MUST be excluded.

**NR-10** — `TENANT` scope MUST be added to `analysis_schedule.scope` and to the resolver, so that
a tenant-wide schedule and a tenant-wide subscription are both expressible. The existing check
constraint and `find_due_targets` cascade MUST be extended, and the precedence order becomes
`SBOM > PRODUCT > PROJECT > TENANT`.

**NR-11** — Fan-out MUST be bounded. A scope resolving to more than `REPORT_MAX_SBOMS_PER_DIGEST`
(default 250) SBOMs MUST produce a truncated digest that names the cap, ranks included SBOMs by
risk, and links to the full view in the application. It MUST NOT silently drop rows.

**NR-12** — One reporting cycle MUST produce **at most one email per subscription**, regardless of
how many SBOMs the scope contains.

### 5.3 Report composition

Every report MUST carry a header block identifying: tenant, scope, cycle window
(`from` / `to` timestamps, UTC), the number of SBOMs covered, the number of runs considered, and
the report schema version.

#### Part A — Latest consolidated report

**NR-13** — Part A MUST present current posture across the scope, computed under **Convention A
(latest state)** per [`metric-conventions.md`](./metric-conventions.md), sourced exclusively from
`app/metrics/`.

Part A MUST include:

- Total SBOMs, total components, total findings.
- Severity distribution (critical / high / medium / low / unknown).
- KEV-exposed finding count and the distinct KEV CVEs in scope.
- Fix-available coverage.
- EPSS-based exploitation outlook where available, with the coverage caveat already used on the
  dashboard.
- Lifecycle posture summary (EOL / EOS / approaching, unmaintained).
- VEX posture summary. `not_affected` and `fixed` MUST be reported as *reduced by VEX*, explicitly
  distinguished from "no vulnerability found", per [`vex-integration.md`](./vex-integration.md).
- Top N (default 10) riskiest components, KEV-first then EPSS then CVSS.
- Per-SBOM roll-up table with each SBOM's run status and headline counts.

**NR-14** — Part A MUST render even when Parts B, C, and D are unavailable. It is the only
mandatory part.

#### Part B — Latest run vs previous run

**NR-15** — Part B MUST diff the latest successful run against the immediately preceding
successful run for the same SBOM, using `CompareService`. Set diffs are **Convention B
(lifetime distinct over two specific runs)**, as already documented for compare-runs.

Part B MUST report, per SBOM and aggregated across the scope:

- Findings **added**, **resolved**, and **unchanged**.
- Components **added**, **removed**, **version-changed**.
- Severity migration (a finding whose severity was re-scored between runs).
- Newly KEV-listed CVEs that were already present but not previously flagged.
- Net posture delta with direction.
- Elapsed time between the two runs.

**NR-16** — Where only one successful run exists, Part B MUST be omitted for that SBOM with an
explicit `insufficient_history` marker, following the precedent set by the dashboard v4 forecast
metric. It MUST NOT render as zeros — a zero delta and no baseline are different facts.

#### Part C — Latest run vs initial run

**NR-17** — Part C MUST diff the latest successful run against the **initial** run, giving
lifetime drift since the baseline. Same mechanism and same convention as Part B.

**NR-18** — Part C MUST additionally surface **persistent findings**: findings present in both the
initial and latest run. These are the backlog that has survived every cycle, and MUST be ranked
KEV-first with an age in days since first observation.

#### Part D — Version comparison

**NR-19** — The report MUST distinguish two comparison modes, because they answer different
questions:

| Mode | Runs compared | Question answered |
|---|---|---|
| **Same-version** | Two runs, same `sbom_source.id` | *The world changed.* New CVEs published, new KEV entries, re-scored severities — against an unchanged software bill. |
| **Cross-version** | Latest run of version *n* vs latest run of version *n−1*, joined by `SBOMSource.parent_id` | *We changed.* Components added, removed, upgraded; vulnerabilities introduced or remediated by our own release. |

**NR-20** — Parts B and C are same-version comparisons by default. Part D is the cross-version
comparison and MUST be produced whenever the SBOM has a lineage parent.

**NR-21** — Part D MUST attribute each finding change to a cause, distinguishing at minimum:
`introduced_by_new_component`, `introduced_by_version_upgrade`, `resolved_by_version_upgrade`,
`resolved_by_component_removal`, and `landscape_change` (the component is unchanged, the
vulnerability data moved). `CompareService._attribute_findings` already performs component-level
attribution and MUST be the basis for this.

**NR-22** — `RunRelationship` MUST be extended with a lineage-aware classification:
`SAME_SBOM` | `SAME_LINEAGE_DIFFERENT_VERSION` | `UNRELATED`, plus the two version strings when
they are known. The existing `same_sbom` and `same_project` fields MUST be retained for
compatibility.

**NR-23** — Where a lineage chain spans more than two versions, Part D MUST compare against the
immediate parent by default, and MUST offer a subscription option to compare against the **root**
of the chain instead.

### 5.4 Baseline selection

**NR-24** — "Initial run" (Part C) MUST be configurable per subscription:

- `FIRST_RUN_OF_SBOM` *(default)* — the earliest successful run for that `sbom_source` row.
- `FIRST_RUN_OF_LINEAGE_ROOT` — the earliest successful run for the root of the SBOM's lineage
  chain, giving true product-lifetime drift across versions.

**NR-25** — Baseline resolution MUST live in `app/metrics/` as named functions
(`runs_initial_for_sbom`, `runs_previous_for_sbom`, `runs_latest_for_sbom`) and MUST NOT be
inlined into the worker, the report service, or any router. This is a hard rule from
[`CLAUDE.md`](../CLAUDE.md), enforced by
`tests/test_metric_consistency.py::test_no_new_direct_finding_or_run_queries_outside_metrics`.

### 5.5 Delivery

**NR-26** — Delivery MUST be by email, containing:

1. An **HTML body** carrying the Part A summary, the headline deltas from Parts B / C / D, and
   deep links into the application for each section. The body MUST be legible on its own, without
   opening the attachments.
2. A **PDF attachment** — the formatted executive report, all selected parts.
3. An **Excel attachment** — finding-level detail: one sheet per part, plus a per-SBOM roll-up
   sheet and a metadata sheet recording the run ids, conventions, and generation timestamp.

**NR-27** — Every email MUST also include a plain-text alternative, consistent with the existing
verification email, which sets `set_content` for text and `add_alternative` for HTML.

**NR-28** — The existing `VerificationEmailSender` Protocol MUST be generalised into a
multi-purpose sender supporting arbitrary subject, body, and attachments. The verification path
MUST keep working unchanged and MUST keep its current behaviour of never logging the correlation
id to SMTP.

**NR-29** — Attachment size MUST be capped by `REPORT_MAX_ATTACHMENT_BYTES` (default 10 MB per
attachment, 20 MB per message). When a report exceeds the cap, the system MUST send the email with
the HTML summary and a download link instead of the attachment, and MUST state in the body why the
attachment was omitted. It MUST NOT silently truncate the report or silently drop the email.

**NR-30** — Generated report artifacts MUST be persisted and retrievable through an authenticated,
tenant-scoped download endpoint for `REPORT_RETENTION_DAYS` (default 90). Links in the email MUST
require authentication; they MUST NOT be unauthenticated signed URLs in this phase.

**NR-31** — Deep links MUST be built from a configured base URL setting, mirroring the pattern of
`email_verification_frontend_url`. Links MUST NOT be assembled from request headers.

### 5.6 Reliability and failure handling

**NR-32** — Report generation MUST NOT run inside the analysis worker. A completion hook MUST
enqueue a separate Celery task so that a report failure never fails or delays an analysis run,
and a slow PDF render never occupies an analysis worker slot.

**NR-33** — Every delivery attempt MUST be recorded with: subscription id, cycle window, status
(`PENDING` | `SENT` | `FAILED` | `SKIPPED` | `SUPPRESSED`), an error code on failure, attempt
count, and the ids of the artifacts produced. `EmailDeliveryStatus` already defines the first four
values and MUST be reused.

**NR-34** — Failed deliveries MUST retry with exponential backoff, bounded at 3 attempts, reusing
the `retry_backoff` pattern already used by `analyze_sbom_async`. SMTP authentication failures MUST
NOT be retried — they are configuration errors, not transient ones.

**NR-35** — A reporting cycle MUST be idempotent. Re-running a cycle for the same subscription and
the same window MUST NOT produce a second email. A uniqueness constraint on
`(subscription_id, cycle_start, cycle_end)` MUST enforce this.

**NR-36** — Generation MUST degrade rather than abort. If Part D fails for one SBOM in a digest of
forty, the email MUST still send, with that SBOM's Part D marked as errored and the reason
recorded.

**NR-37** — A tenant-level send rate limit MUST exist (`REPORT_MAX_EMAILS_PER_TENANT_PER_HOUR`,
default 200) to protect the SMTP relay from a misconfigured schedule.

---

## 6. Data model changes

Four new tables. All tenant-owned tables MUST use `TenantOwnedMixin`; user-managed rows MUST use
`SoftDeleteMixin`, consistent with existing models.

### 6.1 `report_subscription` — migration `045`

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `tenant_id` | int FK | via `TenantOwnedMixin` |
| `iam_user_id` | int FK → `iam_users.id` | the subscriber |
| `scope` | varchar(16) | `TENANT` \| `PROJECT` \| `PRODUCT` \| `SBOM` |
| `project_id` / `product_id` / `sbom_id` | int FK, nullable | exactly one non-null unless scope is `TENANT`, enforced by check constraint mirroring `ck_analysis_schedule_target` |
| `cadence` | varchar(16) | `ON_EVERY_RUN` \| `DAILY` \| `WEEKLY` \| `MONTHLY` |
| `parts` | varchar(16) | ordered flags for A / B / C / D |
| `formats` | varchar(32) | `HTML` always; `PDF`, `XLSX` optional |
| `severity_floor` | varchar(16) | default `ALL` |
| `baseline_mode` | varchar(32) | `FIRST_RUN_OF_SBOM` \| `FIRST_RUN_OF_LINEAGE_ROOT` |
| `cross_version_target` | varchar(16) | `IMMEDIATE_PARENT` \| `LINEAGE_ROOT` |
| `suppress_when_unchanged` | bool | default `false` |
| `enabled` | bool | default `true` |
| `last_delivered_at` | varchar | ISO string, matching the existing timestamp convention in this schema |
| `created_on` / `created_by` / `modified_on` / `modified_by` | varchar | |

Unique constraint on `(tenant_id, iam_user_id, scope, project_id, product_id, sbom_id)` where not
deleted — one subscription per user per scope target.

### 6.2 `report_delivery` — migration `046`

Append-only delivery ledger. Columns: `id`, `tenant_id`, `subscription_id` FK, `cycle_start`,
`cycle_end`, `status`, `error_code`, `attempt_count`, `recipient_email`, `sbom_count`,
`run_count`, `artifact_ids` (JSON), `sent_at`, `created_on`. Unique on
`(subscription_id, cycle_start, cycle_end)` per **NR-35**. Indexed on `(tenant_id, status)` and
`(subscription_id, cycle_end)`.

### 6.3 `report_artifact` — migration `046`

Generated files. Columns: `id`, `tenant_id`, `delivery_id` FK, `kind` (`PDF` | `XLSX` | `JSON`),
`filename`, `media_type`, `size_bytes`, `sha256`, `storage_path`, `expires_at`, `created_on`.
Retention sweeper deletes rows past `expires_at`.

### 6.4 `analysis_schedule` extension — migration `047`

Add `TENANT` to `ck_analysis_schedule_scope` and to `ck_analysis_schedule_target`, allowing a row
with all three target FKs null when `scope = 'TENANT'`. Extend `find_due_targets` accordingly.

### 6.5 Reused, unchanged

`analysis_run`, `analysis_finding`, `compare_cache`, `sbom_source` (including the new `parent_id`
lineage), `kev_vulnerabilities`, `epss_score`, `vex_statements`, `component_lifecycle_cache`.
This feature reads them; it does not alter them.

---

## 7. API surface

All routes tenant-scoped and permission-checked. Following the existing convention that HTTP
behaviour lives in `app/routers` and business behaviour in `app/services`.

| Method | Path | Purpose | Role |
|---|---|---|---|
| `GET` | `/api/report-subscriptions` | List the caller's subscriptions. | any authenticated |
| `POST` | `/api/report-subscriptions` | Create a subscription. | any authenticated, scope-read-checked |
| `PATCH` | `/api/report-subscriptions/{id}` | Update cadence, parts, formats, floor, enabled. | owner or `TENANT_ADMIN` |
| `DELETE` | `/api/report-subscriptions/{id}` | Soft-delete. | owner or `TENANT_ADMIN` |
| `POST` | `/api/report-subscriptions/{id}/preview` | Generate the report synchronously and return it **without sending email**. | owner |
| `POST` | `/api/report-subscriptions/{id}/send-now` | Force one cycle immediately. Rate-limited. | owner |
| `GET` | `/api/report-deliveries` | Delivery history, filterable by subscription and status. | owner; all-tenant for `TENANT_ADMIN` |
| `GET` | `/api/report-deliveries/{id}/artifacts/{artifact_id}` | Authenticated artifact download. | owner or `TENANT_ADMIN` |
| `GET` | `/api/tenants/{id}/report-subscriptions` | Tenant-wide subscription administration. | `TENANT_ADMIN`, `PLATFORM_ADMIN` |

**NR-38** — `preview` MUST use the same code path as scheduled generation, differing only in that
it does not send or persist a delivery row. A preview that diverges from the real report defeats
its purpose.

---

## 8. Worker and scheduling design

```
Celery Beat
  ├── analysis-schedule-tick        (existing, every 15 min)
  │      └── analyze_sbom_async     (existing, per SBOM)
  │             └── on completion → report_notifications.on_run_complete   [NEW]
  │                                    └── enqueues cycles for ON_EVERY_RUN subscriptions
  │
  └── report-notification-tick      (NEW, hourly at minute 5)
         └── scans report_subscription for due DAILY / WEEKLY / MONTHLY cycles
                └── report_notifications.build_and_send   (NEW, per subscription)
                       ├── resolve scope → SBOM set                      (§5.2)
                       ├── resolve baselines via app/metrics/            (NR-25)
                       ├── Part A via app/metrics/                       (NR-13)
                       ├── Parts B / C / D via CompareService            (NR-15, NR-17, NR-19)
                       ├── render HTML + PDF + XLSX                      (NR-26)
                       ├── persist report_artifact rows                  (§6.3)
                       └── send via the generalised email sender         (NR-28)
```

**NR-39** — `report-notification-tick` MUST be offset from the existing 03:00–03:45 maintenance
window (`kev-sync-daily`, `cve-cache-purge`, `source-cache-sweep`) so report generation does not
contend with those DELETE-heavy jobs.

**NR-40** — Celery Beat MUST remain a single instance. This is already an operational requirement
and this feature increases the cost of violating it: duplicate beats would mean duplicate emails.
**NR-35**'s idempotency constraint is the defence in depth.

**NR-41** — `build_and_send` MUST reuse `compare_cache` where a run pair has already been diffed,
and MUST tolerate a cache miss by computing. Report generation MUST NOT extend the cache TTL or
change the cache key derivation.

---

## 9. Non-functional requirements

| ID | Requirement |
|---|---|
| **NFR-1** | A digest covering 50 SBOMs with ~5,000 total findings MUST generate in under 120 seconds on the reference deployment. |
| **NFR-2** | Report generation MUST NOT hold a database session open across the PDF/Excel render step. |
| **NFR-3** | Peak memory per report task MUST stay under 512 MB; Excel generation MUST stream or chunk beyond 50,000 rows. |
| **NFR-4** | External provider calls MUST NOT be made during report generation. Reports read persisted analysis results only — no live NVD, OSV, or KEV fetches. |
| **NFR-5** | Every number in the report MUST be traceable to a named function in `app/metrics/` and MUST declare its convention (A / B / C) in the metadata sheet. |
| **NFR-6** | All timestamps MUST be UTC and MUST state so. Cadence boundaries respect the subscription's tenant timezone where set, defaulting to UTC. |
| **NFR-7** | The HTML email MUST render acceptably in Outlook desktop, Outlook Web, and Gmail — table-based layout, inline styles, no external CSS, no JavaScript. |
| **NFR-8** | Generated artifacts MUST be stored outside the repository working tree, under a configured path, and MUST NOT be world-readable. |

---

## 10. Security and tenancy

**NR-42** — Tenant isolation MUST be enforced in the backend at query time. A report MUST NEVER
contain data from a tenant other than the subscription's. Every metric call MUST be tenant-scoped.

**NR-43** — Permission MUST be re-evaluated at send time (**NR-6**). A subscription created while
the user had access MUST stop delivering the moment that access is withdrawn, without requiring a
cleanup job to have run.

**NR-44** — Email addresses MUST come from the verified `iam_users` record. A subscription MUST NOT
carry a free-text recipient address — that would be an exfiltration path out of the tenant
boundary. Sending to an arbitrary address is explicitly out of scope.

**NR-45** — Reports MUST NOT include secrets, provider API keys, raw SBOM content, or repair
workspace content. Component names, versions, CVE identifiers, and metrics only.

**NR-46** — Subscription create / update / delete and every delivery attempt MUST write an
`audit_log` row, consistent with existing audited actions.

**NR-47** — `send-now` and `preview` MUST be rate-limited per user to prevent using report
generation as a denial-of-service vector against the SMTP relay or the database.

**NR-48** — When `AUTH_ENABLED=false` (local development), delivery MUST default to disabled.
`email_delivery_enabled` already gates the sender via `DisabledVerificationEmailSender`; the
generalised sender MUST preserve that behaviour and return `SKIPPED`, not fail.

---

## 11. Frontend surfaces

| Surface | Behaviour |
|---|---|
| **Settings → Notifications** (new) | List, create, edit, delete subscriptions. Scope picker mirroring the schedule picker. Cadence, parts, formats, severity floor, baseline mode. |
| **Project / Product / SBOM detail** | A "Notify me" control creating a scoped subscription inline. |
| **Settings → Notifications → History** | Delivery history with status, artifact downloads, and error reasons for failures. |
| **Preview modal** | Renders the report for the current subscription configuration before saving it. |
| **Tenant admin** | Read-only view of all subscriptions in the tenant, with the ability to disable one. |

**NR-49** — Every mutation on these surfaces MUST be a `useMutation` and MUST invalidate the
subscription and delivery list caches through a new helper in
`frontend/src/lib/queryInvalidation.ts` — `invalidateReportSubscriptionLists` and
`invalidateReportDeliveryLists`. Raw `await someApiCall()` in an event handler is a violation.
This is enforced by `frontend/src/__tests__/mutation-invalidation.test.ts`.

**NR-50** — Success and error popups MUST be wired for create, update, delete, and send-now, and a
confirmation dialog for delete — closing the gaps that
[`notification-coverage.md`](./notification-coverage.md) tracks for other modules. These rows MUST
be added to that coverage table as `YES`.

**NR-51** — Run statuses displayed anywhere in these surfaces MUST go through
`canonicalRunStatus()`. Legacy `PASS` / `FAIL` MUST NOT appear in display logic or filters.

---

## 12. Configuration

New settings, following the existing `app/settings.py` conventions:

| Setting | Default | Purpose |
|---|---|---|
| `REPORT_NOTIFICATIONS_ENABLED` | `false` | Master feature flag. |
| `REPORT_NOTIFICATION_BASE_URL` | — | Base URL for deep links, mirroring `email_verification_frontend_url`. |
| `REPORT_MAX_SBOMS_PER_DIGEST` | `250` | Fan-out cap (**NR-11**). |
| `REPORT_MAX_ATTACHMENT_BYTES` | `10485760` | Per-attachment cap (**NR-29**). |
| `REPORT_MAX_MESSAGE_BYTES` | `20971520` | Per-message cap. |
| `REPORT_RETENTION_DAYS` | `90` | Artifact retention (**NR-30**). |
| `REPORT_MAX_EMAILS_PER_TENANT_PER_HOUR` | `200` | Send rate limit (**NR-37**). |
| `REPORT_ARTIFACT_STORAGE_PATH` | — | Filesystem path for generated artifacts. |
| `REPORT_GENERATION_TIMEOUT_SECONDS` | `300` | Hard timeout per cycle. |

Existing SMTP settings (`smtp_host`, `smtp_port`, `smtp_use_tls`, `smtp_use_starttls`,
`email_from_address`, `email_from_name`, `email_delivery_enabled`) are reused unchanged.

---

## 13. Phased delivery

| Phase | Content | Exit criterion |
|---|---|---|
| **P1 — Foundations** | Migrations 045–047. Generalised email sender with attachments. `TENANT` scope on schedules. Baseline metric functions. | Sender sends an arbitrary email with an attachment; verification email still passes its existing tests. |
| **P2 — Part A** | Scope resolution, Part A composition, HTML body, delivery ledger, `ON_EVERY_RUN` cadence. | A subscribed user receives a consolidated posture email after a scheduled run. |
| **P3 — Parts B & C** | Previous-run and initial-run deltas, `insufficient_history` handling, persistent-findings ranking. | Deltas match `POST /api/v1/compare` output for the same run pair, exactly. |
| **P4 — Part D** | Lineage-aware `RunRelationship`, cross-version comparison, change attribution. | A v1.0 → v1.1 upload chain produces a correct cross-version report. |
| **P5 — Attachments & UI** | PDF and Excel generation, artifact storage and download, Settings → Notifications, delivery history. | Full feature behind `REPORT_NOTIFICATIONS_ENABLED`. |
| **P6 — Hardening** | Rate limits, retention sweeper, DAILY/WEEKLY/MONTHLY cadences, load test at 250 SBOMs. | NFR-1 through NFR-8 met. |

Deferred to a later requirement: in-app notification centre, webhook / Teams / Slack delivery,
per-tenant report branding, user-authored templates.

---

## 14. Acceptance criteria

A reviewer should be able to verify each of these directly.

1. A user subscribed at `PROJECT` scope receives exactly one email per cycle covering every SBOM
   in that project, with no duplicates.
2. A user holding both a `PROJECT` and an `SBOM` subscription that overlap receives that SBOM's
   report exactly once, from the SBOM subscription (**NR-4**).
3. Part A's totals equal the dashboard's totals for the same scope and moment, to the number.
4. Part B's added / resolved / unchanged sets are byte-identical to `POST /api/v1/compare` for the
   same run pair.
5. An SBOM with exactly one successful run renders Part B as `insufficient_history`, not as zeros.
6. An SBOM uploaded as version 1.1.0 superseding 1.0.0 produces a Part D that attributes each
   changed finding to a component add, remove, upgrade, or landscape change.
7. Re-running a cycle for the same subscription and window produces no second email.
8. Revoking a user's tenant membership stops delivery on the very next cycle, with the delivery row
   recorded as `SUPPRESSED`.
9. An oversized report sends with a download link and an explanatory line, not silently truncated
   and not dropped.
10. An SMTP outage produces `FAILED` rows with retries and an error code, and does not affect any
    analysis run.
11. `tests/test_metric_consistency.py` passes with no new entries in
    `_LEGACY_DIRECT_QUERY_ALLOWLIST`.
12. `frontend/src/__tests__/mutation-invalidation.test.ts` passes with the new mutations covered.

### Test plan

- **Backend unit** — scope resolution, overlap deduplication, baseline selection, cadence window
  arithmetic, severity floor, attachment cap fallback.
- **Backend integration** — end-to-end cycle against a seeded tenant with multiple projects,
  products, SBOMs, and a lineage chain; assert one email per subscription with correct content.
- **Idempotency** — concurrent cycle execution for one subscription; assert the unique constraint
  holds and exactly one email is produced.
- **Tenancy** — a two-tenant fixture; assert no cross-tenant leakage in any part of any report.
- **Frontend** — Vitest coverage for subscription CRUD, cache invalidation, and popup coverage.
- **Load** — 250 SBOMs / 25,000 findings against NFR-1 and NFR-3.

---

## 15. Open questions

| # | Question | Owner | Blocking |
|---|---|---|---|
| Q1 | Should `TENANT`-scope subscriptions be restricted to `TENANT_ADMIN` and `SECURITY_ANALYST`, or open to any member who can read the whole tenant? | Product | P2 |
| Q2 | Where do artifacts live in the HCL.CS deployment — local filesystem, or object storage? `boto3` is already a dependency, which suggests S3 is available. | Platform | P5 |
| Q3 | Do we need per-tenant SMTP configuration, or is the single platform relay sufficient? | Platform | P1 |
| Q4 | Should `ON_EVERY_RUN` at `TENANT` scope be permitted at all, given a tenant-wide daily schedule across 200 SBOMs would emit 200 completion events? Proposal: coalesce into one digest per tick window. | Product | P2 |
| Q5 | Should the FDA 510(k) workbook be offered as a fourth attachment format for regulated customers? | Product | Post-P6 |
| Q6 | Retention of 90 days — does any HCL compliance policy require longer? | Compliance | P5 |

---

## 16. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Duplicate Beat instances emit duplicate emails. | User trust; relay reputation. | **NR-35** idempotency constraint; single-Beat deployment already documented. |
| Report generation contends with analysis workers. | Scheduled scans delayed. | **NR-32** separate task; **NR-39** offset schedule; consider a dedicated queue. |
| Metric drift between report and dashboard. | Two authoritative numbers that disagree — the exact bug class `metric-conventions.md` exists to prevent. | **NR-25**, **NFR-5**: same functions, declared conventions, acceptance criterion 3. |
| Large digests time out or exhaust memory. | Silent non-delivery. | **NR-11** cap, **NR-36** degrade-don't-abort, **NFR-3** streaming, **NR-33** ledger makes failure visible. |
| Cross-version attribution is wrong because lineage was declared incorrectly at upload. | Misleading report. | Lineage is declared and validated at upload time (`resolve_parent_sbom`); Part D MUST state which parent it compared against so a wrong link is visible. |
| Emailing findings widens the blast radius of a data leak. | Confidentiality. | **NR-44** verified addresses only; **NR-45** no raw SBOM content; **NR-30** authenticated downloads. |

---

## 17. Traceability to the original request

| Original ask | Requirement |
|---|---|
| Notify the respective user, tenant-wise / project-wise / product-wise | NR-1 … NR-12, NR-10 (adds `TENANT` scope), §6.1 |
| While running the scheduler | NR-32, §8 (completion hook + report tick) |
| Part A — latest consolidated report | NR-13, NR-14 |
| Part B — compare latest run with previous run | NR-15, NR-16 |
| Part C — compare with the initial run | NR-17, NR-18, NR-24 |
| Same-version comparison | NR-19 (same-version mode), NR-20 |
| Different-version comparison of the same SBOM | NR-19 (cross-version mode), NR-21, NR-22, NR-23 |
