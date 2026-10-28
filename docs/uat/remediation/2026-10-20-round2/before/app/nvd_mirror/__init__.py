"""NVD mirroring bounded context.

Self-contained package implementing a self-hosted NVD CVE mirror modelled
on Dependency-Track's mirroring feature. See ``docs/nvd-mirror/`` for the
discovery report (Phase 0) and the design document (Phase 1).

Public surface (re-exports added per phase):
  * Phase 2 — settings, domain models, ports, adapters, ORM rows.
  * Phase 3 — remote adapter, use cases.
  * Phase 4 — Celery task, FastAPI admin router.
  * Phase 5 — NvdLookupService facade.
"""
