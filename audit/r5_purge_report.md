# R5 — Purge Final Report

> Audit references: YAGNI-001 / 004 / 005 / 006, SOLID-LSP-003, SOLID-ISP-003, refactor-plan §R5.

---

## Phase A — Manifest

[audit/r5_deletion_manifest.md](r5_deletion_manifest.md) (276 lines).

22 of 22 candidates verified ELIGIBLE. Two audit divergences caught and resolved:
1. **C7**: audit listed 4 port classes; file actually defined 2 (no `ProjectRepositoryPort`, no `ComponentRepositoryPort`).
2. **C12–C18**: audit listed 7 `Settings.aws_*` fields with three different names than the actual file. Reality: 5 fields (`aws_access_key_id`, `aws_secret_access_key`, `aws_region`, `aws_s3_bucket`, `aws_s3_endpoint_url`). Phantoms `aws_addressing_style` / `aws_signature_version` dropped.

---

## Groups applied

| Group | Commit | Subject | Files deleted | LOC removed |
|---|---|---|---|---|
| 1 | `075e60e` | chore(cleanup): remove `app/utils.py` — zero importers (YAGNI-005) | 1 | 92 |
| 2 | `9aa6fe2` | chore(cleanup): remove `app/repositories/` and `app/ports/repositories.py` — unused, broken methods (YAGNI-001, SOLID-LSP-003) | 6 | 748 |
| 3 | `0108e06` | chore(cleanup): remove unused S3 storage adapter, StoragePort, and `aws_*` settings fields (YAGNI-006) | 3 | 84 (files) + 10 (settings fields) |
| 4 | `229e503` | chore(cleanup): remove unwired `app/services/dashboard_service.py` (YAGNI-004) | 1 | 361 |
| 5 | `d7d12c4` | chore(cleanup): remove four unused Pydantic schemas from `app/schemas.py` (YAGNI, refactor-plan R5) | 0 (in-file deletion) | 46 |

**Groups skipped**: none. All 5 approved groups landed.

---

## Totals

```
$ git diff --stat 050eedc..HEAD
 15 files changed, 1 insertion(+), 1366 deletions(-)
```

- **Files deleted**: 11
  - `app/utils.py`
  - `app/repositories/sbom_repo.py`
  - `app/repositories/analysis_repo.py`
  - `app/repositories/component_repo.py`
  - `app/repositories/project_repo.py`
  - `app/repositories/__init__.py`
  - `app/ports/repositories.py`
  - `app/ports/storage.py`
  - `app/infrastructure/s3_storage.py`
  - `app/infrastructure/__init__.py`
  - `app/services/dashboard_service.py`
- **Directories removed**: `app/repositories/`, `app/infrastructure/`
- **Files edited (collateral only)**: 4 — `app/ports/__init__.py`, `app/settings.py`, `app/services/__init__.py`, `app/schemas.py`. Each edit was either a removed-import line or a deleted class block per the prompt's no-collateral-edits-other-than-import-cleanup rule.
- **Net delta**: **−1,365 lines** across the candidate set (1 insertion is the new shorter `__all__` in `app/ports/__init__.py`).

---

## Negative-grep verification (post-purge)

Every deleted identifier returns zero hits across `*.py` / `*.ts` / `*.tsx`:

```
$ grep -rEn "from .utils\b|from app\.utils\b|..."  → empty
$ grep -rEn "\bSBOMRepository\b|\bAnalysisRepository\b|..."     → empty
$ grep -rEn "\bSBOMRepositoryPort\b|\bAnalysisRepositoryPort\b" → empty
$ grep -rEn "\bStoragePort\b"                                   → empty
$ grep -rEn "\bS3StorageAdapter\b|\btry_create_s3_adapter\b"    → empty
$ grep -rEn "from app\.services\.dashboard_service\b|..."       → empty
$ grep -rEn "\baws_access_key_id\b|...|\baws_s3_endpoint_url\b" → empty
$ grep -rEn "\bSBOMTypeCreate\b|\bSBOMAnalysisReportCreate\b|..." → empty
```

(Definition sites are gone, so the only hits a grep could return now would be stale references; there are none.)

---

## App-boot smoke

```
$ python -c "import app; from app.main import app as _; print('OK')"
[INFO] 2026-04-28 23:23:20  sbom.logger  Logging initialised — level=INFO  format=text  file=(console only)
OK
```

---

## Final test count

```
======================= 227 passed, 5 warnings in 9.31s ========================
```

**227 / 227 green** at HEAD `d7d12c4`. Pre-existing warnings (Pydantic V2 deprecation, JWT key length info notes) unchanged.

---

## Remaining `[REQUIRES VERIFICATION]` items

None. Every Phase A candidate had a clean grep-proof and pytest stayed green at every commit.

---

## Known stale references (NOT edited per prompt §1.3)

These are **doc / historical** references that became inaccurate post-purge but are not imports and were intentionally left untouched. Flagged for a future doc-pass refactor.

| File | Stale text |
|---|---|
| [app/main.py:13](../app/main.py#L13) | `"all DB access in app/repositories/, and all configuration in app/settings.py."` — `app/repositories/` no longer exists. |
| [audit/02_solid.md](02_solid.md), [audit/06_supporting_principles.md](06_supporting_principles.md), [audit/07_backend.md](07_backend.md), [audit/09_cross_cutting.md](09_cross_cutting.md), [audit/10_refactor_plan.md](10_refactor_plan.md) | Historical references to deleted modules. These are frozen audit snapshots — not edited. |
| [PROJECT_LENS_REPORT*.md](../PROJECT_LENS_REPORT.md), [ADR-001-architecture-audit.md](../ADR-001-architecture-audit.md) | Same — frozen historical artifacts. |
| [docs/nvd-mirror/00-discovery.md:432](../docs/nvd-mirror/00-discovery.md#L432) | One line referring to `app/infrastructure/` for s3 storage — the path no longer exists. |
| [app/ports/](../app/ports/) | Package now near-empty (`__all__: list[str] = []`). Per prompt §7, the package wasn't in the C1–C22 list and was retained. Followup: drop the package or repurpose it. |

---

> "R5 purge complete. 5 groups applied, 11 files deleted, 1,365 lines removed. All 227 tests green. Working tree clean."
