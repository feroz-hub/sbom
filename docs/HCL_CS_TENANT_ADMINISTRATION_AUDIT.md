# HCL.CS and SBOM tenancy responsibility audit

## Final responsibility boundary

HCL.CS authenticates users and supplies the validated issuer, subject, email,
profile, and verification claims. SBOM uses `(external_issuer,
external_subject)` as the stable identity key.

SBOM owns tenants, memberships, platform grants, tenant role assignments,
active-tenant selection, effective permissions, isolation, and authorization
audits. No HCL.CS tenant record or `tenant_id` claim is required to create or
use an SBOM tenant.

## Dependencies found and disposition

- `tenants.external_iam_tenant_id` was `NOT NULL`, required by tenant creation,
  and shown as mandatory in the Platform Tenants form. Migration 050 makes it
  nullable while preserving existing values and uniqueness for non-null
  values. It remains optional legacy metadata.
- `auth_context_service` used the configured token tenant claim as a fallback
  tenant selector. It now ignores the claim for authorization and emits only a
  safe diagnostic log when the hint differs from the SBOM-selected membership.
- The compatibility `resolve_active_tenant` helper also used the claim as a
  fallback selector. The claim is retained in its signature only for caller
  compatibility and is explicitly discarded.
- Explicit `X-Tenant-ID` selection remains a selector, never authority. Every
  request revalidates active platform authority or active local membership.
- Platform management may resolve an explicit target tenant without creating a
  fake tenant membership.
- Existing `local-default` metadata is preserved and remains non-authoritative.

## Authoritative role model

Migration 049 uses one `tenant_users` membership with one or more
`tenant_user_role_assignments`. Active assignment rows and the database-backed
authorization catalogue determine roles and permissions. `tenant_users.role`
is only the synchronized primary-role compatibility value.

Platform authority comes exclusively from an eligible user with an active
`platform_user_roles` `PLATFORM_ADMIN` grant.

## Tenant creation

The normal request is:

```json
{
  "name": "Wellysis",
  "slug": "wellysis",
  "initial_admin_user_id": 3
}
```

The tenant, active membership, active `TENANT_ADMIN` assignment, and success
audit rows are one atomic transaction. When the optional legacy mapping is
omitted, `external_iam_tenant_id` is `NULL`; it is never derived from the slug,
user ID, external subject, or token.
