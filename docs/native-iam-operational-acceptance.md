> **SUPERSEDED STRATEGY:** The user approved greenfield Native-only staging after this report was drafted. The migration inventory, SF user mapping, live-HCL mandatory gates and cutover stages below are historical and must not be executed. See `native-iam-greenfield-acceptance.md` for the current plan. Local technical test evidence remains applicable.

# Native IAM operational acceptance and SF cutover readiness

**Overall: NO-GO for SF cutover.** Application architecture cleanup and local operational drills are provided, but an approved staging target, live test accounts and external provider acceptance are missing. HCL.CS/SF has not been disabled, removed, reconfigured or cut over.

## 1–4. Branch, baseline and changes

- Branch: `feat/native-user-management`.
- Approved/start/end HEAD: `dea456fbe902013f5235987e4ed2b5916674899d`; exact match verified before work. No commit, merge or push.
- Initial worktree was clean. Changes remain unstaged; no unrelated work discarded.
- Code head is `061_security_mail_outbox`. No new migration was added.
- Changes: credential-proof separation, active public verification-key custody, matching-key production validation, regression/operational test harnesses, read-only migration inventory utility and this acceptance/migration plan.

## Environment discovery and staging boundary

Inspected settings only as set/unset where sensitive. `.env.server` is absent. Native authentication, native enrollment, outbox production mode and production native secrets are not configured in the existing local files. Existing SMTP and HCL issuer both target loopback. Local Docker services include SBOM PostgreSQL/Mailpit and HCL PostgreSQL/Redis; an unrelated billing database was left alone. No existing SBOM API, frontend or Celery application processes were identified listening during the initial inventory.

The configured **local application database is at revision 055_ai_model_registry and contains four IAM users**. That is not the disposable test database (revision 061). Its contents and migration revision were inspected read-only; no application startup/seeding/migration was run against it. Code-head readiness must not be confused with this database's deployed revision.

The user was asked for an approved staging deployment, test mailbox, HCL roles and existing credential location. The response repeated the question without supplying those details. Consequently no remote/staging deployment, real external email, account mutation or outage drill was attempted. Loopback operational evidence is explicitly separated from staging acceptance below.

## 5. Migration staging result

**NOT VERIFIED.** No staging target/backup owner was supplied. The local configured database remains at 055 and must not be blindly advanced. The expected final migration is 061, through the existing migration job or `alembic upgrade head` after a verified backup and rollback checkpoint.

Disposable test databases use the repository's approved bootstrap/migration sequence. A local backup was restored into a separately created disposable database and revision, indexes, constraints, memberships, role assignments, credentials, audit and outbox ciphertext were checked. This proves a local rehearsal, not migration of staging. No ad hoc schema repair or edits to existing migrations were made.

Staging procedure: identify exact database and current revision; stop enrollment while taking a consistent encrypted/access-restricted backup; restore that backup into an isolated environment using matching PostgreSQL tools; verify row counts and role assignments; review migration SQL/history; run the approved migration job; assert 061 and outbox constraints/indexes; deploy matching application/configuration; verify readiness, HCL login and existing memberships before enabling Native enrollment. Roll back application flags first, not schema. Do not downgrade a database to fit an old checkout.

## 6–8. SMTP, retries and duplicate-delivery boundary

**Real staging SMTP: NOT VERIFIED.** The existing configured provider is local Mailpit; no approved external mailbox was supplied.

Local operational tests use a real loopback SMTP socket server and the production SMTP sender, not a mocked sender. The server captures mail only in test-process memory and has no external delivery capability. The tests verify intended recipient, fragment token in the email, failed TCP connection followed by successful retry, PENDING→DELIVERED, and ciphertext erasure. Raw tokens are checked absent from captured process/application diagnostics.

A separate worker subprocess is terminated with `os._exit` immediately after SMTP acceptance and before audit/delivery-state commit. Retry sends the **same token and Message-ID**, while user/membership/credential/action-token counts remain unchanged. This confirms **at-least-once mail delivery**. Exactly-once mail delivery is not claimed. Stable Message-ID may help downstream deduplication but is not a guarantee.

Phase 5 regression still covers maximum attempts→FAILED, expiry→EXPIRED, reissue→CANCELLED, audit rollback, encryption failures and committed delivery across new worker processes. A real Celery Beat/worker/broker outage and recovery drill against staging remains missing. PostgreSQL outbox durability alone does not prove scheduling/operations recovery. No production-style action tokens were manually decrypted or copied; only synthetic test recipients consume test-generated email.

## 9–10. Actual two-BFF processes and Redis recovery

An opt-in harness launches one real native FastAPI service, **two actual production Next standalone HTTP processes**, and a dedicated Redis server with AOF. It uses disposable PostgreSQL data, ephemeral keys, loopback ports and test-only credentials. Authentication is real native Argon2/JWT/database validation; no fake identity API is substituted. Existing services are not stopped. Owned child processes are terminated by the harness.

Tests exercise login A/use B, logout B/denial A, cookie HttpOnly/Secure/SameSite=Lax and opaque body, Redis loss/readiness failure, no usable offline session access, Redis restart/recovery, password change/reset/global disable/logout-all denying both BFFs, and one replica with a wrong session-encryption key. No bearer token is returned in the browser response. Redis clients retain bounded reconnect and no memory fallback/offline queue.

**Staging ingress/two-replica result: NOT VERIFIED.** These are direct loopback HTTP requests carrying the expected origin and inspecting the Secure cookie; the harness deliberately supplies the cookie for cross-process checks. It is not a browser TLS-cookie or real load-balancer test. Actual TLS ingress routing, direct-backend blocking, managed Redis failover, partition behavior, abrupt host/AOF crash recovery and rolling secret rollout remain required. Orderly local Redis restart is narrower than production failover.

## 11. Ingress and trusted-proxy result

**NOT VERIFIED on an actual ingress.** The Phase 5 Nginx snippet remains an undeployed example. Compose explicitly uses Uvicorn `--no-proxy-headers`; arbitrary X-Forwarded-For is not an application identity source. Existing tests verify shared source/account buckets, spoofed-header resistance and limiter Redis failure→503.

Staging must identify the internet boundary and any upstream load balancer, allowlist only exact trusted private CIDRs, overwrite untrusted headers, block direct backend access and tune edge limits independently of BFF aggregate-source/account-hash limits. Do not enable trust-all forwarding to improve apparent client IPs. Validate the deployed Nginx/load-balancer syntax and traffic behavior, not just the example file.

## 12. JWT rotation and custody

Architecture now separates `active_signing_key()`, `active_verification_key()` and `verification_key_for_kid()`. `signing_key` remains a compatibility alias for issuing code only. Validators read **NATIVE_JWT_PUBLIC_KEY** for the active key and public-only retired-key entries. There is no private-key fallback in validation. A regression removes all private signing material after issuance and verifies the token successfully; issuance then fails. Missing active public material fails safely. RS256, issuer/audience, required claims, kid and overlap expiry checks remain intact.

**Deployment change:** every validator needs `NATIVE_JWT_PUBLIC_KEY`. Supply the public PEM corresponding to the active signing kid, including during rotation. API/worker production validation checks the active private/public pair matches. Existing fixture/rotation tests now configure both sides explicitly; no production/private keys were committed.

The current application combines issuer and validator endpoints in one API process, so that combined API still needs private signing material for login. The validation library can run without it, but a separate production validator-only service topology was not introduced. Do not advertise the entire combined API as private-key-free.

Phase 4/5 drills test ephemeral A/B keys, separately configured validators, overlap, unknown/expired kid and algorithm substitution. **A real rolling rotation across staging API replicas and clock-skew monitoring is NOT VERIFIED.** Stage B public keys first, switch signer to B and active public key/kid together, retain A only through a bounded deadline, test A/B on every replica, then remove A and confirm rejection. Never reuse kid values. Preserve HCL validation configuration separately.

## 13. Native expiry UX

The approved default remains 900 seconds with no native refresh credential. The operational harness uses the existing configurable minimum (60 seconds) for an accelerated real HTTP expiry/denied-mutation check. This does not prove a human 15-minute interactive session, stakeholder acceptance, browser return-navigation or absence of every redirect loop.

**Product acceptance: MISSING.** A product owner must explicitly accept 15-minute native re-login after a human desktop/mobile test, or request a separately reviewed session-renewal design. HCL refresh remains separate. No long-lived Native refresh credential was added.

## 14–15. Live HCL and multi-tenant acceptance

**Live staging HCL regression: NOT VERIFIED.** No live test accounts/roles or accessible staging HCL runtime were provided. Existing HCL PostgreSQL/Redis services were not changed. Automated HCL OIDC/token/context/logout/provisioning and tenant-isolation regressions are run, but are not live provider evidence.

The approved tests preserve Tenant A SECURITY_ANALYST+DEVELOPER versus Tenant B VIEWER, tenant switching, membership-only deactivation and global disable/enable semantics. Local real HTTP session tests additionally verify global revocation on both BFFs. **Human multi-tenant staging acceptance remains missing.** Do not infer cross-tenant authorization from the BFF cookie alone; database membership and role assignments remain authority on every request.

## 16. Credential verification and lockout review

Authenticated password change previously called the full `login()` function, which updated last-login/provider-authentication timestamps, wrote LOGIN_SUCCESS and issued a discarded JWT. It now calls `verify_native_credential(..., purpose='password_change')`. Forced proof uses the same verification boundary with `purpose='forced_change'`; normal login alone records successful login activity and issues a token.

The verifier owns the same account→credential row locks and failed-attempt rules. Ordinary failed proof still locks globally at the configured threshold, increments security_version and records the approved failure/lock events. An expired normal lock clears only after correct login; forced proof retains FORCE_PASSWORD_CHANGE and its temporary credential lock until password replacement. Password-change success does not clear state prematurely; replacement/audit must commit atomically. There is no session/JWT issuance in credential proof.

A compatibility regression caught an initially over-strict profile-email binding in the refactor. It was corrected: login continues using the native provider identifier, including when profile email differs, while password-lifecycle operations retain their existing email binding. No approved brute-force semantics were intentionally changed.

Automated threshold, duration, forced-lock, manual unlock, old-token rejection and last-platform-admin non-exemption tests remain. **Configured staging threshold/manual unlock/auto-unlock on real accounts: NOT VERIFIED.** Restore test accounts only through approved lifecycle flows, never by editing hashes or lock state in staging SQL.

## 17–19. Backup, secret rotation and probes

The local backup/restore rehearsal uses pg_dump/pg_restore against disposable data and creates a separate isolated restore database. Backup files are mode 0600 under the test-private directory. The first attempt correctly failed because PostgreSQL 18 host tools emitted `transaction_timeout` against PostgreSQL 16. Repeating with matching PostgreSQL 16 tools inside the explicit local test container succeeded; the error was not suppressed. Match client/server major versions in the staging runbook.

Live database ciphertext erasure does not erase historical backups. Backup and outbox-key retention/access must be coordinated. Retain enough key material to recover intended pending mail during a restore, while avoiding uncontrolled indefinite access. A restored old outbox can resend unexpired mail; keep dispatch disabled during recovery until an operator reconciles restored delivery state.

Secret drills/decisions:

| Secret | Local evidence / policy | Staging remaining |
| --- | --- | --- |
| JWT signing/public pair | Public-only validation, pair mismatch and overlap tests | Rolling rotation and clock-skew drill |
| BFF encryption | Wrong-key rejection and shared-store tests | Coordinated real replica rollout; key replacement logs users out |
| Outbox encryption | Wrong-key failure tests; terminal erasure | Drain pending before replacement; do not rotate blindly |
| SMTP credential | Local transport outage/retry | Real provider credential replacement/recovery |
| Redis credential | None configured for the isolated local Redis | Authenticated/TLS Redis credential rotation |

Existing liveness is separate from IAM readiness; no new health implementation was needed. Local BFF readiness was observed failing/recovering with Redis. API readiness/worker heartbeat are covered in Phase 5 tests. **Actual orchestrator traffic withdrawal/recovery and SMTP-outage-without-restart behavior remain NOT VERIFIED.** Probe output must not expose URLs or credentials.

## 20. Accessibility

Prior axe and component keyboard/dialog checks are regression evidence only. No human screen-reader, contrast, focus-return, desktop/mobile or staging browser review was performed in this phase. **Human accessibility acceptance is NOT VERIFIED.** No accessibility defect was guessed or unrelated UI redesigned.

## 21–23. Inherited failure classification

The exact approved SHA was exported unchanged into a separate temporary checkout/archive and tested against its own disposable database. No main/master/develop checkout or shared database downgrade was used.

| Failure | Classification | Evidence and proposed correction |
| --- | --- | --- |
| Tenant write fixture/delegation | TEST DEFECT in setup; secondary APPLICATION DEFECT in frozen-exception traceback behavior | Fixture uses `source='TENANT_ADMIN'` to assign TENANT_ADMIN; `validate_role_delegation` forbids that. Seed via an authorized bootstrap/platform fixture while preserving the tenant-write assertions. Separately address exception traceback handling if reviewed. |
| Duplicate platform grant idempotency | TEST DEFECT | Existing `test_grant_is_eligible_duplicate_rejected_audited_and_immediate` requires 409 `IAM_PLATFORM_ADMIN_ALREADY_GRANTED`; concurrency test expects CREATED+EXISTING. Preserve the approved 409 contract and assert one committed grant plus one conflict. |
| Concurrent revoke/grant | TEST DEFECT in expected outcomes | Serializable lock ordering permits a grant-before-revoke conflict; the test does not accept the approved active-grant 409. Assert allowed serialized outcomes and one consistent final row, rather than changing grant semantics. |

No ambiguous role contract was silently resolved and none of these three tests/services was modified. Classification is provided for separate review, as their failures do not justify weakening delegation or changing grant semantics during operational acceptance.

## 24. SF migration inventory

`python scripts/iam_migration_inventory.py --output <new-private-file.json>` uses an explicitly supplied DATABASE_URL, a read-only transaction and exclusive mode-0600 output. It exports IAM user IDs, provider-record references, status, tenant memberships/role assignments and collision/manual-review flags. It does not export email/subject credentials, password hashes, action tokens or session material, and never links/merges users. The utility is tested against disposable identities; it was **not run against an approved staging population** because none was identified and the configured local database is on older schema 055.

| Category | Mapping and migration disposition |
| --- | --- |
| HCL-only | Keep HCL issuer/subject identity→existing IAMUser→existing per-tenant role assignments. Explicitly approved native enrollment must attach to that same reviewed person through a separately approved workflow; never auto-match email. |
| Native-only | Preserve native identity/credential and memberships; no SF password migration. |
| Explicit dual-provider | Preserve both identity records on the existing IAMUser; verify both paths; no implicit relinking. |
| Inactive/disabled | Preserve status and membership inactivity. Migration must not reactivate accounts. |
| Duplicate/collision | Quarantine for human identity proof and owner decision. Shared email is not proof of identity. |
| Incomplete external identity | Resolve missing issuer/subject linkage with SF owner before onboarding or preference changes; no guessed issuer/subject. |

The reviewed inventory must include actual population counts, collision disposition, each user's tenant-specific assignments and owner signoff before any tenant pilot. The four users observed in the local revision-055 database are not presented as the staging migration population.

## 25. Role mapping plan

| Existing authority | Local target | Rule |
| --- | --- | --- |
| Explicit approved SBOM platform administrator | PLATFORM_ADMIN | Review explicit platform grant, verified/active account and owner approval. SF token role alone cannot grant platform authority. |
| Tenant-scoped administrator | TENANT_ADMIN | Preserve each tenant's authorized assignment and last-admin safeguards. |
| Tenant security analyst | SECURITY_ANALYST | Preserve tenant-specific role assignment and catalog permissions. |
| Tenant developer | DEVELOPER | Preserve independently of analyst/viewer assignments. |
| Tenant viewer | VIEWER | Preserve read-only tenant policy. |
| Unknown/custom SF claim | Manual mapping review | No silent elevation, flattening or permanent trust of JWT claims. |

HCL subject resolves identity; local database grants/memberships/catalog resolve authorization. Multiple roles stay attached to their tenant. Catalog/custom-role differences require an explicit inventory mapping review rather than coercion into a nearest role.

## 26. Proposed cutover stages — NOT EXECUTED

Owners below are required role assignments, not claims that a named individual has accepted responsibility.

| Stage | Entry criteria | Exit criteria / metrics | Rollback | Owner |
| --- | --- | --- | --- | --- |
| 0 HCL only, Native disabled | Verified HCL baseline, backup and inventory | HCL success/error baselines; roles reviewed | Preserve HCL configuration and schema | IAM owner + DBA |
| 1 Internal dual-provider pilot | All critical staging gates pass; approved internal accounts | Activation/reset success, zero isolation defects, lockout/revocation drills | Disable native enrollment/login; stop dispatch safely; keep HCL | IAM owner + SRE |
| 2 Selected tenant pilot | Tenant owner accepts mapping and 15-minute UX | Login/reset failure rates acceptable, support readiness, per-tenant role parity | Revert native preference for pilot; HCL remains usable | Tenant owner + Product |
| 3 Broader native onboarding | Pilot stability window signed off | Delivery age/failure, auth errors, permission parity within agreed thresholds | Pause onboarding; restore HCL preference | Product + IAM operations |
| 4 Stop new SF-dependent SBOM enrollment | Explicit approved provisioning policy | New SBOM users have reviewed native lifecycle; exceptions tracked | Resume HCL provisioning policy | IAM owner |
| 5 Native preferred identity | Coverage/inventory reconciliation complete | Native login preference stable, no orphan accounts | Restore HCL-first frontend configuration | Product + SRE |
| 6 Stability observation | Native preference stable, rollback rehearsed | Agreed duration, zero critical incidents, backup/secret drills current | Revert preference and pause enrollment | Operations + Security |
| 7 Remove mandatory SF dependency | Explicit final approval after GO matrix, no unresolved dependencies | Acceptance evidence and dependency retirement signoff | Retained HCL configuration/secrets within approved retention window | Change authority + SF owner |

Set concrete SLO thresholds and stability-window duration with owners before Stage 1; this report does not invent stakeholder approval or silently authorize any stage.

## 27. Operational rollback plan

Rollback is configuration-first. Preserve the IAMUser, identity, credential, membership, role, audit and outbox tables. Disable Native enrollment first; if needed disable Native login, restore HCL-first frontend configuration and ensure existing HCL identities still resolve to the same local users. Stop security-mail dispatch/Beat safely while retaining outbox rows; do not delete pending mail as a rollback shortcut. Retain required encryption keys and matching public verification material securely. Existing active native tokens require an explicit revocation decision; turning off enrollment alone does not revoke authentication.

Before future cutover rehearse this on staging: change flags, verify HCL login/refresh and tenant roles, verify native-login rejection if disabled, inspect pending delivery preservation, restore flags and verify recovery. Do not make schema downgrade the primary rollback. Do not reset IAM passwords or merge identities to repair rollback failures. The rollback document is prepared; a live staging rollback was not executed.

## 28. GO / NO-GO matrix

FAIL below includes **required evidence missing**, not an assertion that an untested service is broken.

| Gate | Staging result | Available evidence / missing condition |
| --- | --- | --- |
| Staging migration to 061 | FAIL — missing | Local configured DB 055 untouched; disposable migration/restore only |
| Real SMTP activation/reset | FAIL — missing | Real loopback SMTP protocol passes; external provider/mailbox unapproved |
| SMTP retry/crash boundary | CONDITIONAL | Local transport and crash tests pass; real provider/worker scheduling pending |
| Two BFF replicas behind ingress | FAIL — missing | Two actual loopback BFF HTTP processes pass; staging TLS/LB missing |
| Redis failover | FAIL — missing | Local AOF orderly restart and fail-closed recovery pass; managed failover/partition missing |
| JWT rolling rotation | FAIL — missing | Library/configuration rotation tests pass; live API rollout missing |
| Ingress trust | FAIL — missing | App spoofed-header tests pass; deployed edge unverified |
| Native multi-tenant | FAIL — missing | Automated tenant isolation passes; human staging scenario missing |
| Lockout | FAIL — missing | Automated global/forced lockouts pass; staging threshold/accounts missing |
| Live HCL regression | FAIL — missing | Automated HCL regressions only |
| Backup/restore | CONDITIONAL | Local isolated PostgreSQL restore passes; staging restore/retention owner missing |
| Secret rotation | FAIL — missing | Public-key/wrong-key tests; live rotation/retention drills pending |
| Readiness/orchestration | FAIL — missing | Local BFF probe recovery; actual LB withdrawal and worker health pending |
| Accessibility | FAIL — missing | Automated axe only; human review pending |
| Critical automated tests | See final verification results | New/native regressions and full frontend; inherited failures separately classified |
| Product acceptance of 15-minute native re-login | FAIL — missing | No stakeholder signoff; no refresh credentials added |

**Overall: NO-GO for SF migration/cutover.** Local success cannot turn missing external acceptance into GO. HCL must remain functional and retained.

## 29–32. Tests, missing evidence, risks and Prompt 8

Final commands/counts are appended after verification. Missing manual evidence is exactly the staging items above: environment/account/mailbox approval, migration backup/restore, real SMTP and Celery/broker outages, two replicas behind actual TLS ingress, Redis failover/partition, live JWT rotation/skew, full 900-second human UX, live HCL roles/refresh, tenant lifecycle, lockout, secret rotation, orchestrator behavior, human accessibility and owner signoff.

Remaining risks: at-least-once email duplication after SMTP acceptance/commit gap; historical ciphertext in backups; session encryption changes logging users out; outbox key changes stranding pending delivery; copied current-session JWT validity until short expiry (logout-all remains security_version); aggregate BFF source throttling; deployed 055→061 migration not yet rehearsed on an approved staging clone; required new active public-key configuration; no automatic provider linking.

**Prompt 8 must not perform cutover from this NO-GO state.** Recommended scope: provide approved staging topology/accounts/owners, execute the missing acceptance and rollback drills, reconcile inventory/collisions/role mapping, obtain product/security signoffs and update this matrix. Only after sufficient GO gates and explicit change approval may a later prompt execute the staged SF migration. MFA/resource ACLs/automatic linking/major redesign remain excluded.
