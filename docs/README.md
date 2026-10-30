# Documentation index

This is the navigation entry point for maintained technical guidance. Workflow
behavior below was checked against source revision e62951c2 on 28 October 2026.
That is source evidence, not deployment or platform acceptance.

| Need | Authoritative entry | Scope |
| --- | --- | --- |
| Getting started | [Root README](../README.md) | Brief onboarding and existing launcher commands. |
| Architecture | [Current overview](architecture/overview.md) | Live backend/frontend boundaries and accepted decisions. |
| API contracts | [Version-matched contract discovery](architecture/overview.md#api-contracts) | Running API schema versus unowned historical snapshots. |
| Development setup | [Developer guide](development/README.md) | Profile selection, prerequisites, OS limitations and lifecycle. |
| Testing | [Testing guide](testing/README.md) | Disposable targets, pytest/Vitest/browser separation; [manual smoke plan](../Testing.md). |
| Configuration | [Configuration reference](reference/configuration.md) | Profile precedence, authentication and public build versus private runtime settings. |
| Deployment | [Ubuntu Docker deployment](UBUNTU_DOCKER_DEPLOYMENT.md) | Repository linux/amd64 configuration; provider and release acceptance remain required. |
| Database operations | [Bootstrap and upgrade](DATABASE_BOOTSTRAP_AND_UPGRADE.md) | Fresh/UUID/pre-UUID compatibility gate; Greenfield confirmation/backup contract. |
| Security and IAM | [Security index](security/README.md) | Native, HCL and Entra guides, catalogues, keys, sessions and operator access. |
| Troubleshooting | [Operations diagnosis](operations/troubleshooting.md) | Safe checks, ports, trust, migration refusal, queues and logs. |
| Historical records | [Storage and retention strategy](documentation-storage-strategy.md) | Classification and retention proposal; individual evidence is not promoted through this public index. |

Existing document paths remain available. The entry guides above take precedence
for current startup, configuration and migration instructions. Feature
requirements and accepted ADRs retain their own authority; historical reports
remain evidence of their recorded revision.

## Feature specifications and operations

| Area | Documents |
| --- | --- |
| Validation and repair | [Validation](sbom-validation.md), [repair workspace](sbom-validation-repair-workspace.md), [automatic repair](sbom-auto-repair.md), [validation operations](runbook-sbom-validation.md) |
| Versioning and scheduling | [Logical versions](sbom-logical-version-management.md), [operational lifecycle](sbom-operational-lifecycle.md), [hierarchical scheduler](hierarchical-analysis-scheduler.md) |
| VEX | [Requirements](requirements/vex-dashboard-investigation.md), [integration](vex-integration.md), [workstream plan](plans/vex-implementation-plan.md) |
| Metrics | [Metric conventions](metric-conventions.md), [dashboard specification](dashboard-metrics-spec.md), [metric debugging](runbook-metric-debugging.md) |
| Lifecycle and KEV | [Lifecycle sources](component-lifecycle-sources.md), [enrichment](lifecycle-enrichment.md), [KEV checks](kev_testing_checklist.md) |
| AI | [Configuration](features/ai-configuration.md), [providers](ai-providers.md), [fix operations](runbook-ai-fixes.md), [credential/key operations](runbook-ai-credentials.md) |
| Reports | [Report notifications](runbook-report-notifications.md) |
| Component Advisor | [API reference](secure-component-advisor/api.md), [operations](secure-component-advisor/runbook.md) |
| Logging | [Structured logging operations](structured-logging.md) |

## Architecture decisions

Keep accepted decision numbers and historical references stable:

- [ADR-0001: dashboard posture](adr/0001-dashboard-posture-model.md)
- [ADR-0007: validation](adr/0007-sbom-validation-architecture.md)
- [ADR-0008: compare](adr/0008-compare-runs-architecture.md)
- [ADR-0009: canonical metrics](adr/0009-dashboard-canonical-metrics-layer.md)

The root ADR-001-architecture-audit.md is a separate historical assessment,
not a replacement for accepted ADR-0001. It is not newly promoted as a
public-safe evidence record by this index.

## Maintenance

Current workflow documents should name their scope, source baseline or
verification date, related provider/profile and any unverified capability.
Follow the [storage strategy](documentation-storage-strategy.md) before
publishing or moving evidence. One-time implementation summaries, diffs and
verification results belong in sanitized pull-request discussion or controlled
local/enterprise review artifacts, unless a documented retention requirement
makes them part of the maintained repository. A public PR is not private storage.

Historical requirements, approvals and evidence retain their existing paths and
bytes. This index does not certify their publication classification or add a
catalogue of individual UAT results.
