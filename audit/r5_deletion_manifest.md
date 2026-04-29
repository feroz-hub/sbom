# R5 — Deletion Manifest

> Audit references: YAGNI-001 / 004 / 005 / 006, SOLID-LSP-003, SOLID-ISP-003, refactor-plan §R5.
> Repo HEAD verified at `050eedc` (post-R4). Audit was on `4435bd2`. Three commits between (`9cd3785`, `85af821`, `050eedc`); none touched any candidate file. The "zero importers" claim is fresh.

---

## §0.1 — Baseline freshness check

```
$ git log --oneline 4435bd2..HEAD -- app/
050eedc fix(security): replace 500 detail leaks with canonical envelope; install global exception handler with correlation IDs (BE-002)
85af821 fix(security): enforce MAX_UPLOAD_BYTES via ASGI middleware (BE-001)
9cd3785 fix(analysis): merge persist_analysis_run + compute_report_status into services/analysis_service — restores query_error_count and raw_report persistence (SOLID-SRP-003, DRY-005, DRY-003)

$ git diff --name-only 4435bd2..HEAD -- app/
app/error_handlers.py
app/main.py
app/middleware/__init__.py
app/middleware/max_body.py
app/routers/analyze_endpoints.py
app/routers/pdf.py
app/routers/projects.py
app/routers/sboms_crud.py
app/services/analysis_service.py
```

None of the changed files appear in the C1–C22 candidate set. R3's `app/middleware/` and R4's `app/error_handlers.py` are explicitly NOT R5 targets and will not be deleted.

---

## A.1 — File-level candidates

### Candidate C1: `app/utils.py`

- **Lines:** 92
- **Audit reference:** YAGNI-005, refactor-plan R5
- **Greps run:**
  ```bash
  $ grep -rn "from .utils\|from app.utils\|from ..utils\|import app.utils" --include='*.py' .
  # → no results
  ```
- **Hits accounted for:** Zero. The file defines `now_iso`, `legacy_analysis_level`, `safe_int`, `safe_float`, `normalized_key`, `compute_report_status`, `normalize_details` — all of which exist as canonical implementations in `app/services/sbom_service.py` / `app/services/analysis_service.py`. R2 already merged the `compute_report_status` callers off the `app/utils.py` copy.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none

### Candidate C2: `app/repositories/sbom_repo.py`

- **Lines:** 206
- **Audit reference:** YAGNI-001, SOLID-LSP-003
- **Greps run:**
  ```bash
  $ grep -rEn "\bSBOMRepository\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/repositories/__init__.py:6:from .analysis_repo import AnalysisRepository
  app/repositories/__init__.py:9:from .sbom_repo import SBOMRepository
  app/repositories/__init__.py:12:    "SBOMRepository",
  app/repositories/sbom_repo.py:17:class SBOMRepository:
  app/ports/repositories.py:5:uses concrete ``SBOMRepository`` / ``AnalysisRepository`` classes.
  ```
- **Hits accounted for:** Definition site + own `__init__.py` re-export + a docstring mention in `app/ports/repositories.py` (also a deletion target, C7). Zero external importers.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none beyond C6's deletion of `__init__.py` itself.

### Candidate C3: `app/repositories/analysis_repo.py`

- **Lines:** 197
- **Audit reference:** YAGNI-001, SOLID-LSP-003
- **Greps run:**
  ```bash
  $ grep -rEn "\bAnalysisRepository\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/repositories/__init__.py:6:from .analysis_repo import AnalysisRepository
  app/repositories/__init__.py:13:    "AnalysisRepository",
  app/repositories/analysis_repo.py:16:class AnalysisRepository:
  app/ports/repositories.py:5:uses concrete ``SBOMRepository`` / ``AnalysisRepository`` classes.
  ```
- **Hits accounted for:** Definition site + own `__init__.py` re-export + a docstring mention in C7 (also doomed).
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none beyond C6.

### Candidate C4: `app/repositories/component_repo.py`

- **Lines:** 144
- **Audit reference:** YAGNI-001
- **Greps run:**
  ```bash
  $ grep -rEn "\bComponentRepository\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/repositories/__init__.py:7:from .component_repo import ComponentRepository
  app/repositories/__init__.py:15:    "ComponentRepository",
  app/repositories/component_repo.py:21:class ComponentRepository:
  ```
- **Hits accounted for:** Definition site + `__init__.py`.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none beyond C6.

### Candidate C5: `app/repositories/project_repo.py`

- **Lines:** 128
- **Audit reference:** YAGNI-001
- **Greps run:**
  ```bash
  $ grep -rEn "\bProjectRepository\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/repositories/__init__.py:8:from .project_repo import ProjectRepository
  app/repositories/__init__.py:14:    "ProjectRepository",
  app/repositories/project_repo.py:9:class ProjectRepository:
  ```
- **Hits accounted for:** Definition site + `__init__.py`.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none beyond C6.

### Candidate C6: `app/repositories/__init__.py`

- **Lines:** 16
- **Audit reference:** YAGNI-001 (package-level)
- **Greps run:**
  ```bash
  $ grep -rEn "from app.repositories|from \.repositories|import app\.repositories" --include='*.py' .
  app/nvd_mirror/ports/__init__.py:5:from .repositories import (
  app/ports/__init__.py:3:from .repositories import AnalysisRepositoryPort, SBOMRepositoryPort
  ```
- **Hits accounted for:** Two hits, both unrelated to `app/repositories/`:
  - `app/nvd_mirror/ports/__init__.py:5` — relative `from .repositories` resolves to `app/nvd_mirror/ports/repositories.py` (a sibling file in the NVD mirror's own ports package, NOT a deletion target).
  - `app/ports/__init__.py:3` — relative `from .repositories` resolves to `app/ports/repositories.py` (C7, also a deletion target). Collateral edit covered in Group 2.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** delete the `from .repositories import ...` line in `app/ports/__init__.py` (also covered by C7's deletion).

### Candidate C7: `app/ports/repositories.py`

- **Lines:** 57
- **Audit reference:** SOLID-ISP-003, SOLID-LSP-003
- **Audit divergence noted:** prompt's grep targets list four port classes (`SBOMRepositoryPort, AnalysisRepositoryPort, ProjectRepositoryPort, ComponentRepositoryPort`), but the file actually defines only two (`SBOMRepositoryPort` and `AnalysisRepositoryPort`). Verified by reading the file.
- **Greps run:**
  ```bash
  $ grep -rEn "\bSBOMRepositoryPort\b|\bAnalysisRepositoryPort\b|\bProjectRepositoryPort\b|\bComponentRepositoryPort\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/ports/__init__.py:3:from .repositories import AnalysisRepositoryPort, SBOMRepositoryPort
  app/ports/__init__.py:6:__all__ = ["AnalysisRepositoryPort", "SBOMRepositoryPort", "StoragePort"]
  app/ports/repositories.py:18:class SBOMRepositoryPort(Protocol):
  app/ports/repositories.py:40:class AnalysisRepositoryPort(Protocol):
  ```
- **Hits accounted for:** Definition site + `app/ports/__init__.py` re-export. The two phantom Port names from the audit (`ProjectRepositoryPort`, `ComponentRepositoryPort`) do not exist anywhere — the audit was wrong about that.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** delete the `from .repositories import ...` line in `app/ports/__init__.py` and remove the two Port names from `__all__`.

### Candidate C8: `app/ports/storage.py`

- **Lines:** 18
- **Audit reference:** YAGNI-006
- **Greps run:**
  ```bash
  $ grep -rEn "\bStoragePort\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/ports/storage.py:9:class StoragePort(Protocol):
  app/ports/__init__.py:4:from .storage import StoragePort
  app/ports/__init__.py:6:__all__ = ["AnalysisRepositoryPort", "SBOMRepositoryPort", "StoragePort"]
  app/infrastructure/s3_storage.py:1:"""S3-compatible storage adapter implementing StoragePort."""
  ```
- **Hits accounted for:** Definition site + `app/ports/__init__.py` re-export + docstring mention in `app/infrastructure/s3_storage.py` (C9, deletion target).
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** delete the `from .storage import StoragePort` line in `app/ports/__init__.py` and remove `"StoragePort"` from `__all__`.

### Candidate C9: `app/infrastructure/s3_storage.py`

- **Lines:** 61
- **Audit reference:** YAGNI-006
- **Greps run:**
  ```bash
  $ grep -rEn "\bS3StorageAdapter\b|\btry_create_s3_adapter\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/infrastructure/__init__.py:3:from .s3_storage import S3StorageAdapter
  app/infrastructure/__init__.py:5:__all__ = ["S3StorageAdapter"]
  app/infrastructure/s3_storage.py:15:class S3StorageAdapter:
  app/infrastructure/s3_storage.py:56:def try_create_s3_adapter() -> S3StorageAdapter | None:
  app/infrastructure/s3_storage.py:61:    return S3StorageAdapter()
  ```
- **Hits accounted for:** Definition site + own `__init__.py` re-export.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none beyond C10.

### Candidate C10: `app/infrastructure/__init__.py`

- **Lines:** 5
- **Audit reference:** YAGNI-006
- **Greps run:**
  ```bash
  $ grep -rEn "from app.infrastructure|from \.infrastructure|import app\.infrastructure" --include='*.py' .
  # → no results
  ```
- **Hits accounted for:** Zero importers anywhere in the codebase.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none

### Candidate C11: `app/services/dashboard_service.py`

- **Lines:** 361
- **Audit reference:** YAGNI-004, refactor-plan R5
- **Greps run:**
  ```bash
  $ grep -rEn "from app\.services\.dashboard_service|from \.dashboard_service|from \.\.services\.dashboard_service|import dashboard_service" --include='*.py' .
  app/services/__init__.py:19:from .dashboard_service import (

  $ grep -rEn "\bget_top_vulnerable_components\b|\bget_top_vulnerabilities\b|\bget_run_status_distribution\b|\bget_severity_distribution\b|\bget_component_stats\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/services/dashboard_service.py:175:def get_severity_distribution(...)
  app/services/dashboard_service.py:225:def get_component_stats(...)
  app/services/dashboard_service.py:260:def get_run_status_distribution(...)
  app/services/dashboard_service.py:281:def get_top_vulnerable_components(...)
  app/services/dashboard_service.py:323:def get_top_vulnerabilities(...)
  app/services/__init__.py:21,23,24,26,27 (re-exports)
  app/services/__init__.py:71-77 (__all__)

  $ grep -rEn "\bget_stats\b|\bget_recent_sboms\b|\bget_activity\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/services/__init__.py:20,22,25 (re-exports)
  app/services/__init__.py:70,72,75 (__all__)
  app/services/dashboard_service.py:24:def get_stats(...)
  app/services/dashboard_service.py:59:def get_recent_sboms(...)
  app/services/dashboard_service.py:115:def get_activity(...)
  ```
- **Hits accounted for:** All 8 dashboard-service function names appear ONLY at their definition site in `dashboard_service.py` and at the re-export + `__all__` lines in `app/services/__init__.py`. Zero external callers — including the routers `dashboard.py` / `dashboard_main.py` which compute their metrics inline (none of these names reach them). The potentially-shadowed names (`get_stats`, `get_recent_sboms`, `get_activity`) are NOT route handler names anywhere; verified.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** in `app/services/__init__.py`, delete the entire `from .dashboard_service import (...)` block and remove all 8 names from `__all__`.

---

## A.2 — `Settings.aws_*` field candidates

**Audit divergence noted**: the prompt lists 7 `aws_*` fields (C12–C18); the file actually declares **5**, with three named differently from the audit. Verified by direct read of [app/settings.py:97-105](../app/settings.py#L97-L105):

```
$ grep -nE "\baws_" /Users/ferozebasha/sbom/app/settings.py
98:    aws_access_key_id: str = Field(default="", description="S3 access key")
99:    aws_secret_access_key: str = Field(default="", description="S3 secret key")
100:    aws_region: str = Field(default="us-east-1", description="AWS region")
101:    aws_s3_bucket: str = Field(default="", description="SBOM artifact bucket")
102:    aws_s3_endpoint_url: str = Field(...)
```

The fields `aws_addressing_style` and `aws_signature_version` claimed by the audit (C17/C18) **do not exist** — those are dropped from the manifest. Per prompt §A.2: "If `Settings` declares any **additional** `aws_*` fields not in this list, add them as C18a, C18b…" — the inverse case (audit overshot) is treated symmetrically: the actual present fields stand.

| ID | Identifier | Line | Notes |
|---|---|---|---|
| C12 | `aws_access_key_id` | 98 | matches audit |
| C13 | `aws_secret_access_key` | 99 | matches audit |
| C14′ | `aws_region` | 100 | audit said `aws_region_name` (does not exist); ACTUAL is `aws_region` |
| C15′ | `aws_s3_bucket` | 101 | audit said `aws_bucket_name` (does not exist); ACTUAL is `aws_s3_bucket` |
| C16′ | `aws_s3_endpoint_url` | 102 | audit said `aws_endpoint_url` (does not exist); ACTUAL is `aws_s3_endpoint_url` |
| ~~C17~~ | ~~`aws_addressing_style`~~ | — | audit phantom; field does not exist; **DROP** |
| ~~C18~~ | ~~`aws_signature_version`~~ | — | audit phantom; field does not exist; **DROP** |

```
$ grep -rEn "\baws_access_key_id\b|\baws_secret_access_key\b|\baws_region\b|\baws_s3_bucket\b|\baws_s3_endpoint_url\b" --include='*.py' --include='*.ts' --include='*.tsx' --include='*.toml' --include='*.md' --include='*.yml' --include='*.yaml' --include='*.cfg' --include='*.ini' --include='*.env' .
app/settings.py:98–102 (definitions)
app/infrastructure/s3_storage.py:20–32, 59 (only consumer — deletion target C9)
```

- **Hits accounted for:** Definition + S3 adapter consumption. No env-file or config references. No `frontend/` references.
- **Verdict (C12–C16′):** **ELIGIBLE**
- **Collateral edits required:** delete five field declarations in [app/settings.py:98-105](../app/settings.py#L98-L105). No validators reference any `aws_*` field — confirmed by reading the validator section [`:131-167`](../app/settings.py#L131-L167).

---

## A.3 — Orphan Pydantic schemas in `app/schemas.py`

`app/schemas.py` does NOT define an `__all__` — verified by full read. Class-only file.

### Candidate C19: `SBOMTypeCreate`

- **Lines:** 42-46
- **Audit reference:** refactor-plan R5
- **Greps run:**
  ```bash
  $ grep -rEn "\bSBOMTypeCreate\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/schemas.py:42:class SBOMTypeCreate(BaseModel):
  ```
- **Hits accounted for:** Definition site only.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none

### Candidate C20: `SBOMAnalysisReportCreate`

- **Lines:** 162-168
- **Audit reference:** refactor-plan R5
- **Greps run:**
  ```bash
  $ grep -rEn "\bSBOMAnalysisReportCreate\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/schemas.py:162:class SBOMAnalysisReportCreate(BaseModel):
  ```
- **Hits accounted for:** Definition site only.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none

### Candidate C21: `SBOMAnalysisReportOut`

- **Lines:** 195-203
- **Audit reference:** refactor-plan R5
- **Greps run:**
  ```bash
  $ grep -rEn "\bSBOMAnalysisReportOut\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/schemas.py:195:class SBOMAnalysisReportOut(ORMModel):
  ```
- **Hits accounted for:** Definition site only.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none

### Candidate C22: `AnalysisRunSummary`

- **Lines:** 142-159
- **Audit reference:** refactor-plan R5
- **Greps run:**
  ```bash
  $ grep -rEn "\bAnalysisRunSummary\b" --include='*.py' --include='*.ts' --include='*.tsx' .
  app/schemas.py:142:class AnalysisRunSummary(ORMModel):
  ```
- **Hits accounted for:** Definition site only.
- **Verdict:** **ELIGIBLE**
- **Collateral edits required:** none. After deletion, `app/schemas.py` retains 11 active classes (`ORMModel`, `ProjectCreate`, `ProjectOut`, `SBOMTypeOut`, `SBOMSourceCreate`, `SBOMSourceOut`, `SBOMComponentOut`, `AnalysisRunOut`, `AnalysisFindingOut`, `ProjectUpdate`, `SBOMSourceUpdate`) — file remains substantive (well over the "only imports" threshold the prompt warns about).

---

## A.4 — Negative-grep coverage

Final cross-format grep across `*.py`, `*.ts`, `*.tsx`, `*.md`, `*.toml`, `*.yml`, `*.yaml`:

- All hits in `audit/*.md`, `PROJECT_LENS_REPORT*.md`, `ADR-001-architecture-audit.md`, and `docs/nvd-mirror/00-discovery.md` are **frozen historical references** (audit / project-lens / ADR documents). Per prompt §1.3 "removing a stale import in another file is the only kind of edit allowed" — these are NOT imports and are NOT in the candidate list. They will become inaccurate after deletion; that is a documented and accepted state for these artifacts.
- One docstring reference in [app/main.py:13](../app/main.py#L13) — `"all DB access in app/repositories/, and all configuration in app/settings.py."` — becomes inaccurate after Group 2 lands. Per prompt §1.3, **doc comments are not imports**, so this stays unedited; it's flagged here as a known stale comment for a follow-up doc-pass refactor (not R5).

No code imports point at any candidate beyond the collateral edits already enumerated.

---

## A.5 — Stop and wait

**Eligibility tally**: **22 of 22 candidates ELIGIBLE** (with two audit phantom fields C17/C18 dropped because they don't exist in the actual code).

**Audit divergences caught and resolved**:
1. C7 expected 4 port classes; only 2 exist (no `ProjectRepositoryPort`, no `ComponentRepositoryPort`).
2. C12–C18 expected 7 `aws_*` settings fields; only 5 exist (no `aws_addressing_style`, no `aws_signature_version`); three of the present ones are named differently from the audit (`aws_region` not `aws_region_name`; `aws_s3_bucket` not `aws_bucket_name`; `aws_s3_endpoint_url` not `aws_endpoint_url`).

**Phase C grouping** (one commit per group, in order):

| Group | Targets | Files deleted | Collateral edits |
|---|---|---|---|
| 1 | C1 | `app/utils.py` (1 file, 92 LOC) | none |
| 2 | C2–C7 | 5 repository files + `app/ports/repositories.py` (6 files, 748 LOC) | `app/ports/__init__.py` — drop two import lines + `__all__` entries |
| 3 | C8–C10 + C12–C16′ | `app/ports/storage.py` + 2 infrastructure files (3 files, 84 LOC) + 5 settings field declarations | `app/ports/__init__.py` — drop the storage import + `StoragePort` from `__all__`; `app/settings.py` — delete 5 field lines |
| 4 | C11 | `app/services/dashboard_service.py` (1 file, 361 LOC) | `app/services/__init__.py` — drop the import block + 8 `__all__` entries |
| 5 | C19–C22 | 4 schema-class blocks (4 deletions, ≈40 LOC) inside `app/schemas.py` | none |

> "Phase A complete. `audit/r5_deletion_manifest.md` has 22 ELIGIBLE candidates (audit's two phantom `aws_*` fields C17/C18 dropped; 0 EXCLUDED). Audit divergences caught: C7 had 2 ports not 4, and the `aws_*` set has 5 actual fields not 7. Awaiting approval to proceed to deletion. Reply 'approve r5' to continue, or list candidate IDs to drop."
