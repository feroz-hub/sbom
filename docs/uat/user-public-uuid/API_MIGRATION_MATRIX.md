# Public IAM API migration matrix

Full pre-change declarations: evidence/iam-route-inventory.before.json. Prefixes below are /api.

| Route family | Request User references | Response User references | Authorization / distinct IDs |
|---|---|---|---|
| platform/users, users/search, users/{user_id}, profile/status/activation | path user_id UUID | summary/detail.id, status.user_id, audit actors UUID | Existing platform permissions first |
| platform/administrators | body user_id UUID | user_id, created_by_user_id UUID | grant_id remains integer; existing platform grant/revoke safeguards |
| platform/tenant-admin-candidates, tenants/{tenant_id}/recover-admin | body user_id UUID | candidate.id UUID | Purpose-limited bootstrap/recovery permission; discovery policy unchanged |
| tenants creation | initial_admin_user_id UUID | initial_administrator.user_id UUID | Platform create + bootstrap permissions |
| tenants/{tenant_id}/user-candidates | none | candidate.id UUID | Existing eligible global discovery projection, invite permission; unchanged privacy policy |
| tenants/{tenant_id}/users, memberships | body user_id UUID | user_id UUID | Tenant invite; membership_id remains integer |
| tenants/{tenant_id}/users/{membership_id}, activate/deactivate/profile/audit/removal | membership_id integer | user_id, audit actor UUID | Tenant scope and role checks unchanged |
| tenants/{tenant_id}/users/{user_id}/roles and history | user_id UUID | user_id, assigned_by/actor UUID | Must be member of selected tenant; role/version policy unchanged |
| tenants/{tenant_id}/native-users and resend-activation | user_id UUID where present | user_id UUID | Existing enrollment scope checks |
| auth/me, v1/auth/me, auth/context, native/session | no public User selector | user_id / user.id UUID | Trusted resolved principal; token subjects unchanged |
| auth/native login, reset, activate, refresh/logout | email/action token/provider identity unchanged | local User references only, if present | Password, token, session semantics unchanged |
| component-advisor/audit/events, recommendations/{recommendation_id}/events | none | actor_user_id UUID | Existing audit permission; event/recommendation/candidate/Analysis Run IDs unchanged |
| tenant audit-history, report subscriptions | local User references in safe projection UUID | actor/target/iam_user_id UUID | Event/subscriber IDs and arbitrary evidence/provider strings unchanged |

Schemas retain internal integer DTO validation where the existing translation boundary requires it; OpenAPI describes the actual UUID wire contract. UUID syntax is checked before lookup, after authentication/endpoint authorization. Unauthorized endpoints must not become global identity resolvers. Output conversion only maps IDs in already-authorized service projections and batches distinct references request-locally.

The platform `/users/{user_id}/audit` collection keeps event IDs integer; only explicit actor User references change. Validation errors keep the existing 422 structure and public User input values. The reviewed OpenAPI IAM schema-field inventory is retained in evidence/openapi-user-fields.json; runtime generated UUID schema checks are part of the focused regression. Existing dynamic dictionary responses are described by this matrix and actual wire assertions rather than a claim that every untyped endpoint has a newly generated typed response schema.
