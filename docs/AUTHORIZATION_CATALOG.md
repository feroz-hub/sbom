# Authorization catalogue

The Phase 8 role and permission catalogue, resolver modes, protected mappings,
APIs, and rollback procedure are documented in
[`authorization-catalog.md`](authorization-catalog.md).

Operator checks:

```bash
python scripts/compare_authorization_catalog.py --format text --fail-on-mismatch
python scripts/sync_authorization_catalog.py
```

The synchronization command is a dry run unless `--apply` is supplied. It only
adds missing code-backed system definitions and mappings; it never deletes
unknown definitions and does not run at application startup.
