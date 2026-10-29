# Security and IAM documentation

Scope: documentation navigation and current configuration boundaries, checked
against e62951c2 on 28 October 2026. This page approves no provider rollout,
credential rotation, bootstrap or production deployment.

## Identity-provider guidance

| Mode | Existing guide | Limits |
| --- | --- | --- |
| HCL.CS / HCL IAM | [OIDC configuration](../HCL_IAM_CONFIGURATION.md) | Validate the exact issuer/audience, claims, JWKS and registered browser origins. |
| Native IAM | [Fresh staging/operator setup](../native-iam-greenfield-setup.md), [runtime configuration validation](../../app/services/native_operations.py) | Local Native profiles are not production acceptance or an identity-data migration. |
| Microsoft Entra | [Phase 1 configuration](../microsoft-entra-phase1.md) | Runtime settings are required on API/BFF; current server Compose does not forward ENTRA_* values. Production use through that manifest remains unverified. |
| Windows HCL integration | [PostgreSQL HCL build](../WINDOWS_NATIVE_SETUP.md), [SF.8 SQL Server build](../WINDOWS_NATIVE_SETUP_SF8.md) | Select by provider build. “Native Windows” means host installation, not the Native IAM provider. |

AUTH_ENABLED requires authenticated API authority across supported provider
paths; it does not mean HCL alone. Native-only mode does not disable API
authentication. Keep synthetic development identity out of shared environments.

## Authorization and bootstrap

The API enforces tenant membership, current database roles/permissions and
resource ownership independently of frontend presentation. Public UUIDs remain
resource identities; display labels do not authorize access.

- [Authorization catalogue operations](../authorization-catalog.md)
- [Catalogue compatibility entry](../AUTHORIZATION_CATALOG.md)
- [Tenant-role assignments and downgrade restrictions](../TENANT_ROLE_ASSIGNMENTS.md)
- [Platform administrator bootstrap](../PLATFORM_ADMIN_BOOTSTRAP.md)
- [Native tenant provisioning](../native-tenant-provisioning.md)

Bootstrap and repair scripts have different targets and authority. Use only the
documented operator process after target identification and authorization; do not
invent a shared super-bootstrap or insert grants manually.

## Sessions, secrets and ingress

Production BFF sessions use shared Redis and encrypted session storage. Supply
stable session, JWT, security-outbox and provider-storage keys separately through
the approved secret/configuration mechanism. Memory sessions are a development
fallback and are refused for production session access. Multi-replica behavior
still requires deployment-specific acceptance.

Keep private keys, tokens, application SBOMs and customer evidence out of public
source control and public links. NEXT_PUBLIC_* values are public build settings.
Use [configuration precedence](../reference/configuration.md) and
[AI key lifecycle](../runbook-ai-credentials.md) before changing any key.

The [server deployment guide](../UBUNTU_DOCKER_DEPLOYMENT.md) requires HTTPS
ingress, a private API/database path, trusted provider certificates and rate-limit
configuration. The [IAM ingress example](../../deploy/iam-proxy.nginx.example)
is an integration fragment, not a complete ingress deployment.

## Release boundaries and unresolved policy

All schema changes are subject to the
[database compatibility gate](../DATABASE_BOOTSTRAP_AND_UPGRADE.md).
Revision 100 is fresh-only across populated pre-UUID targets; no generic
production migration or downgrade is approved.

Repository disclosure contacts, response SLAs, supported production provider/OS
combinations and enterprise retention periods require owner approval. No contact,
SLA or production certification is invented here. See the
[documentation storage strategy](../documentation-storage-strategy.md).
