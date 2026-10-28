# IAM identifier contract and dependency audit

Baseline: branch `feat/native-user-management`, HEAD `aa264cd3673b074b3f9c15c9cc72a4ed95bdb222`. Before changes, the authenticated read-only Greenfield observation found revision 100, 19 users, 19 provider links, 18 Native credentials, 21 memberships/assignments and four platform grants; IAM public_id is absent. No migration of that database is authorized. See evidence/main-database-readonly-baseline.json.

The complete pre-change source occurrence inventory (1,399 entries) and 60 identity-related route declarations are preserved in evidence/*.before.json. They are discovery evidence, not a claim every matching variable is a User resource.

| Identifier / owner | Classification | Public contract / action |
|---|---|---|
| IAMUser.id, UserIdentity.user_id, NativeUserCredential.user_id | Internal relationship | Integer remains, all FK definitions preserved |
| TenantUser.id, tenant_user_id, membership_id | Membership identity | Integer remains; never interpreted as IAM User UUID |
| PlatformUserRole.id / grant_id | Grant identity | Integer remains |
| AuthContextUser.id, auth/me.user_id, Native session.user_id | Public local User | UUIDv4; JWT sub is independently unchanged |
| Platform summary/search/candidates/detail .id | Public local User | UUIDv4 |
| user_id in membership creation, role paths, status and grant operations | Public local User | UUIDv4 at HTTP boundary; resolve after endpoint authorization |
| initial_admin_user_id, initial/current administrator.user_id | Public local User | UUIDv4 |
| ComponentRecommendationEvent.actor_user_id in two Advisor event routes | Public local User reference | UUIDv4; integer actor storage and event/recommendation IDs preserved |
| actor_user_id / target_user_id / assigned_by_user_id in IAM audit projections | Public local User reference | UUIDv4; underlying audit record stays integer; audit event IDs stay integer |
| created_by_user_id in platform grants | Public local User reference | UUIDv4 |
| report subscriber.iam_user_id | Public local User reference | UUIDv4; subscriber ID stays integer |
| provider issuer/subject, external_iam_user_id, external_user_id | Provider-issued identity | Preserve strings and exact trusted mapping; not local UUID |
| Native JWT sub, context.user_id, security_version, refresh/logout internal identities | Authenticated session | Preserve integer/string token semantics and revocation |
| SBOM validation user_id, actor_user_id, created_by, assigned_to provider strings | Non-IAM actor/domain reference | Preserve; do not globally reinterpret strings or integer-looking external subjects |
| tenant/project/product/logical/source/component public IDs | Existing six resources | Existing UUID boundary and guards preserved |
| AnalysisRun.id, event.id, role ID/code, policy version, token/session ID | Other resource | Preserve respective integer/string semantics |

Membership recommendation: retain current scoped integer membership routes in this change. They are distinct resources protected by tenant permissions; an independent future membership public-identity contract would need separate scope. User UUIDs are identifiers, never authorization.

Cutover: upgrade schema before restarting new backend; deploy matching frontend/backend together. Invalidate/refetch cached User responses and saved selections. Native/OIDC sessions remain valid because token subjects and internal keys do not change. No integer User compatibility window is authorized: integer HTTP references receive 422. External integrations must adopt UUID before cutover. Do not restart the existing application against an unmigrated database.

Additional audit decisions: `AiSettings.updated_by_user_id` and AI credential audit `user_id` are existing string actor/provider labels from trusted request subject metadata, not integer IAM FK selectors. Lifecycle configuration's integer updated_by_user_id remains an internal persisted owner/audit relationship and is excluded from its safe response projections. Revocation actor keys stay integer internally but are not exposed by the current assignment response; exposed assigned_by_user_id and history actor_user_id become UUIDs. Provider subjects, SBOM created_by/modified_by and validation/repair actor labels retain their separate semantics.

Error projections are included: a model-level validation error must echo the submitted public User UUID rather than its resolved integer. Audit event `id` is never interpreted as a User `id`, including the platform User audit route. Dedicated real-boundary regressions cover both distinctions.
