# Secure Component Advisor — migration notes

Six additive migrations, applied in order after `066_platform_config_permissions`. The API refuses to start until the
database is at head (`app/main.py`), so apply them before starting API and worker processes.

| Revision | Adds | Backfill | Downgrade |
|---|---|---|---|
| `067_component_advisor_foundation` | Indexes `ix_sbom_component_tenant_canonical`, `ix_sbom_component_tenant_package_key`; permissions `component_advisor:read`, `…:recommendation:create/review/accept`, `…:audit:read` mapped to tenant roles | — | Drops the indexes; deletes the permissions and their role mappings |
| `068_component_advisor_policies` | `advisor_policy`, append-only `advisor_policy_version`, `component_purpose_metadata`, `sbom_component.description`; permissions `tenant:advisor-policy:read/update` | Run `scripts/backfill_component_descriptions.py --apply` after deploying (fills NULL descriptions only) | Drops the tables and column; deletes the permissions. **Policy history is lost.** |
| `069_component_recommendations` | `component_recommendation` (partial unique index for open items), `component_recommendation_candidate` | — | Drops both tables |
| `070_component_recommendation_compatibility` | `component_recommendation_compatibility_check` | — | Drops the table |
| `071_component_recommendation_factors` | `component_recommendation_factor` | Existing candidates are re-scored on their next evaluation | Drops the table |
| `072_component_recommendation_review` | Append-only `component_recommendation_event`; review columns on `component_recommendation` | — | Drops the table and columns. **Audit history is lost.** |

## Verified on representative data (2026-10-02)

A template clone of the development database (`sbom_analyser`: revision 059, 3 tenants, 10 SBOMs, 648 components,
652 findings, 317 VEX contexts) was used. Steps:

1. `alembic upgrade head`: 059 → 072 applied cleanly, including the existing 060–066.
2. Smoke test against real data:
   - Row counts unchanged.
   - 15 advisor role-permission mappings present.
   - Description backfill dry-run: 507 components would gain an SBOM description.
   - Snapshots built per tenant (425 / 95 / 103 versions, 0.1–0.2 s), with buckets reconciling.
   - A recommendation was created and evaluated on tenants 1 and 3; events were written.
   - The smoke test found a bug in background-task audit attribution for tenants other than 1. It was fixed and a
     regression test added.
3. `alembic downgrade 066_platform_config_permissions`: all advisor tables, the description column and the advisor
   permissions were removed. Components and findings were intact.
4. `alembic upgrade head` again: all six migrations re-applied cleanly.

## Rollback guidance

- Rolling back below 066 is refused by 065/066 by design (scoped-configuration security).
- Downgrading SCA migrations deletes advisor policy history and audit events. **Take a database backup first.** The
  advisor never writes to SBOM, component, finding or VEX tables, so core data is unaffected.
- Permissions removed by a downgrade are removed from every role. Custom role edits that granted them are lost too.
- The application code for a given revision expects its schema. Roll code and schema back together.

## Forward-compatibility notes

- New tables use `TenantOwnedMixin` (except the policy and purpose tables, whose NULL `tenant_id` means "platform").
  All queries filter on tenant explicitly.
- Append-only guarantees (`advisor_policy_version`, `component_recommendation_event`) are enforced by an ORM
  `before_flush` guard, not by database triggers. Direct SQL can still modify them, so restrict database access
  accordingly.
