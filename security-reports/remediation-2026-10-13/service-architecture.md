# Background service architecture (documented before changes)

## KEV

Three implementations/entry points coexist:

- Main authenticated FastAPI `/api/v1/kev/sync` invokes synchronous `app.services.kev_service.sync_kev` against the application database.
- Celery Beat invokes `kev.sync` and `cve_refresh.refresh_kev_cache` for global catalog/cache maintenance. These are system jobs, with broker access establishing publisher trust.
- Standalone `KEV/main.py` serves `/kev/sync`, `/kev`, `/kev/{cve_id}`, `/health`; it uses independent async SQLAlchemy configuration and initializes its table at lifespan. Its README proposes HTTP calls from cron/systemd/Kubernetes. No independent authentication exists. Server compose does not deploy it; no in-repository production caller has been established.

Do not expose standalone KEV on an untrusted network. Whether to retire its HTTP interface, restrict ingress, or integrate an approved service identity requires deployment/business confirmation. This remediation does not introduce a new service-to-service authentication contract or change standalone schemas.

## Celery

Main API, worker and Beat share Redis. Server compose does not publish Redis to the host, but Redis has no password/ACL command. Network membership is the existing trust boundary; any reachable publisher can submit tasks. JSON serialization is configured; this does not establish sender authenticity. Deployment must verify network restrictions, Redis authentication/ACLs, and approved scheduler/publisher identities. No production credential/grant/network changes performed.

AI fix user requests are authorized by the API, then enqueue tenant_id/run_id plus options. Existing task binds a minimal system tenant context, so tenant identity survives but requesting actor authority does not. The planned small patch carries authenticated actor_user_id and verifies live account, tenant membership, role permissions, and run ownership when execution begins. Old queued AI messages without actor identity will fail closed and require authorized resubmission. This does not authenticate a malicious publisher who can impersonate a valid actor through a compromised broker.

Scheduled analysis derives tenant from stored schedule, checks tenant status and SBOM/schedule agreement. Component Advisor binds tenant_id but still needs a dedicated requesting-actor audit. Reports bind tenant and already rebuild recipient authority; export authority must be checked again before producing deliverables. Global maintenance tasks intentionally run without a tenant. Security mail is system work.
