# Local development consolidation

The initial plan identified ownership, certificate trust, profile/database
isolation, Windows Celery limitations and production consumers as compatibility
risks. Orchestration was transferred into scripts/dev.py and verified before
deleting former entrypoints.

The current [cleanup plan and inventory](dev-launcher-cleanup.md) supersede the
initial retention stage. See the [lifecycle guide](../dev-launcher-lifecycle.md),
[bootstrap guide](../../scripts/BOOTSTRAP.md) and
[verification matrix](dev-launcher-platform-matrix.md). No compatibility launch
wrappers remain.
