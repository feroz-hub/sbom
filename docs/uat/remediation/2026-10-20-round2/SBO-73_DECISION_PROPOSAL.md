# SBO-73 — Global IAM candidate discovery: Decision Needed

No discovery policy was changed in Round 2. Product Owner and Security approval is required before implementing a narrower or broader rule. This is an identity-directory privacy decision, not evidence that foreign tenants can read Olympus business records.

## Current contract and evidence

`app/routers/tenants.py::search_tenant_user_candidates` requires `tenant:user:invite`, resolves an authorized tenant UUID, and requires that tenant to equal the current tenant. It deliberately searches global IAM accounts by substring of email, display name, first name or last name. It escapes SQL LIKE metacharacters and uses SQLAlchemy bound expressions. Input must contain 2–200 characters; pages start at 1 with 20 results by default and a maximum of 50. Active and verification-complete accounts qualify; accounts with any existing membership in the target tenant are excluded. Microsoft Entra verification follows the existing shared predicate.

The response contains IAM account ID, email, display name, status, verification flags and provider labels. It does not contain foreign tenant membership, project, product or SBOM data. Existing six-resource UUID translation does not turn IAM account identifiers into tenant/business identifiers.

The original foreign Admin `q=olympus` result contains the four Olympus accounts and the Platform account. Round 2 repeats this read and direct foreign Olympus-member access independently in `api-discovery-review.json`. The live seed directory still has four active Olympus members after disposable membership cleanup.

`app/rate_limit.py` supplies SlowAPI defaults (300/minute unless configured), keyed by verified transport IP plus bearer-token hash. `app/main.py` installs the middleware. This is a general request limit, not a per-tenant/user privacy budget; token rotation can produce another bucket. The candidate route has no stricter discovery-specific decorator. Runtime configuration and an actually exercised 429 are different evidence; Round 2 does not claim a load/rate-limit acceptance test.

`app/main.py::log_requests` can write a generic `tenant.switch` audit for successful requests carrying X-Tenant-ID; the candidate endpoint has no dedicated candidate-search audit. The generic entry records method/path, not the search terms or returned identities. Transport access records support correlation, but they do not by themselves provide a reviewed directory-discovery audit trail. Recording raw searches could itself collect personal data, so retention and access must be designed deliberately.

## Options

| Consideration | A — Retain global substring discovery | B — Restrict discovery |
|---|---|---|
| Product behavior | Preserve existing name/email search and cross-tenant invitation convenience | Require a complete normalized email; optionally use invitation-first generic acknowledgement |
| Exposure | Authorized inviters can enumerate active, verified global identities in bounded pages, including platform identities | Removes bulk name/substring browsing; exact-email responses still permit targeted existence checks unless invitation acknowledgement is generic |
| Authorization | Keep tenant:user:invite and current-tenant match; never imply access to returned user's tenants | Keep the same permission and tenant match; account lookup must not grant membership or platform authority |
| Minimum data | Current flags and provider labels expose more identity information than selection needs | At most display name/email plus an opaque invitation/selection handle; omit status, verification and provider details unless the inviter needs them to act |
| Abuse controls | Add an actor+tenant discovery budget independent of token rotation, monitoring, response/page caps and privacy review | Apply the same budget to exact-email and invitation requests; prevent predictable timing/body differences and repeated invite spam |
| Auditability | Dedicated event with actor, target tenant, query class, result count and correlation; avoid raw addresses by default | Audit request/acceptance/outcome and recipient-controlled consent, with restricted access and a retention policy |
| UX | Fast discovery without knowing a full address; ambiguous names and global-directory assumptions remain | Additional full-email entry; clear generic “If eligible, invitation instructions will be delivered” feedback, duplicate handling and safe resend/recovery guidance |
| Migration/compatibility | Documentation/UAT must explicitly accept the global directory exception | API and frontend contract tests must change together; retain native, HCL.CS and Entra eligibility and existing-member semantics |

## Recommendation (proposal only)

Choose **Option B**, preferably an invitation-first flow with exact-email entry and generic acknowledgement. Tenant administration needs a way to invite an intended collaborator; it does not require browsing all eligible platform identities. This reduces bulk enumeration and provider/verification disclosure while preserving deliberate cross-tenant collaboration. Exact-email lookup alone is an intermediate improvement, not a claim of complete enumeration resistance.

Keep successful addition/invitation behind the current role-assignment and membership eligibility checks. A lookup or invitation must never create account, tenant, role or platform authority implicitly. An explicit consent/acceptance decision is needed if the product wants to change the current immediate Add Existing Member workflow; Round 2 makes no such lifecycle change. Existing member detection should remain useful to authorized administrators without exposing unrelated account details. Unknown/ineligible address feedback should be decided together with delivery, cooldown, idempotency and abuse monitoring. Mail provider/activation tokens must never appear in audit or UI responses.

## Required approval and implementation acceptance

Product Owner and Security must approve: global visibility boundary; whether exact-email identity confirmation is permitted; which fields an inviter may see; whether invitation acceptance is required; platform-account eligibility; actor/tenant request budgets and retention; error/duplicate semantics and UX for unknown, existing, inactive and unverified accounts.

After approval, a separate scoped implementation should test authorized and unauthorized roles; name/partial-email rejection; normalization; wildcard and SQL-like inputs; existing and foreign eligible accounts; platform identities; inactive/unverified accounts; constant generic acknowledgement and timing tolerance where promised; delivery only through configured local/provider transport; token-rotation-resistant limits; audit content/retention; replay/idempotency; and continued tenant/business isolation. Explicitly reconcile the strict no-enumeration UAT criterion with the approved product contract.

Recommended Linear status: **Decision Needed**. No automatic tracker write. Existing UAT-DEF-002 remains open pending the decision; layout remediation SBO-72 does not alter discovery eligibility or scope.
