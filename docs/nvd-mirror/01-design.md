# Phase 1 — NVD Mirror Design

> **Scope:** Design of the new bounded context. No code is written until
> Phase 2. Every claim that depends on the existing repo cites Phase 0
> ([00-discovery.md](00-discovery.md)) so this document remains
> independently checkable.
>
> **Date:** 2026-04-28

---

## 0. Design ground rules

These are derived from the cowork prompt's "non-negotiable" constraints
(see prompt §"NON-NEGOTIABLE ENGINEERING CONSTRAINTS") plus the Phase 0
findings that constrain how those rules apply here.

| Rule                              | Applied here as                                                 |
|-----------------------------------|------------------------------------------------------------------|
| Hexagonal: domain has zero I/O    | `domain/` and `application/` import only stdlib + `domain` siblings + `ports`. No `httpx`, `sqlalchemy`, or `celery` imports allowed. Enforced via `import-linter` contract (already configured in `pyproject.toml:68-80`). |
| Idempotent writes (`ON CONFLICT`) | `cves` upserts use PG `INSERT … ON CONFLICT (cve_id) DO UPDATE … WHERE excluded.last_modified > cves.last_modified`. |
| All datetimes UTC, tz-aware       | DB columns `TIMESTAMPTZ`. Domain dataclasses hold `datetime` with `tzinfo=UTC` only. Never store naive datetimes. |
| No `Any` in new public APIs       | `domain/`, `ports/`, `application/`, and `api.py` request/response models must not contain bare `Any`. Only allowed inside adapters where third-party JSON is opaque. |
| Backward compat                   | `enabled=False` is the default. With it off, Phase 0's existing analyzer paths run unchanged. |
| No second HTTP library            | `httpx` only. Existing `requests` calls in `app/analysis.py` are not replaced (out of scope) but the new mirror code uses `httpx` everywhere. |
| Stdlib logging, structured `extra` | Phase 0 §A.3 — repo uses stdlib `logging`. We do not introduce `structlog`. |
| PostgreSQL-only feature           | Phase 0 §C.10 — SQLite remains supported for the **rest of the app** but the mirror's `cves` table relies on `JSONB` and `ON CONFLICT`. Default `enabled=False` means SQLite dev environments are unaffected. |

---

## 1. Bounded context — directory tree

The new bounded context lives at **`app/nvd_mirror/`**. It is a peer of
`app/sources/` and `app/services/`, not a child. The cowork prompt's
suggested `nvd_mirror/infrastructure/` sub-folder is **dropped** in favour
of flat top-level modules — the existing repo puts Celery in `app/workers/`
and FastAPI routers in `app/routers/`, never under an `infrastructure/`
sub-package (Phase 0 §A.1, §E.13). One sub-package level per concern is
plenty.

```
app/nvd_mirror/
├── __init__.py
├── settings.py                  # NvdMirrorSettings (dataclass)
│
├── domain/                      # PURE — no I/O, no third-party imports
│   ├── __init__.py
│   ├── models.py                # CveRecord, CveBatch, MirrorWindow,
│   │                            # MirrorWatermark, NvdSettingsSnapshot,
│   │                            # SyncReport
│   └── mappers.py               # NVD-JSON dict → CveRecord (pure fns)
│
├── ports/                       # Protocols only
│   ├── __init__.py
│   ├── remote.py                # NvdRemotePort
│   ├── repositories.py          # CveRepositoryPort, SettingsRepositoryPort,
│   │                            # SyncRunRepositoryPort
│   ├── secrets.py               # SecretsPort
│   └── clock.py                 # ClockPort
│
├── adapters/                    # Concrete impls of the ports
│   ├── __init__.py
│   ├── nvd_http.py              # NvdHttpAdapter (httpx + tenacity)
│   ├── cve_repository.py        # SqlAlchemyCveRepository
│   ├── settings_repository.py   # SqlAlchemySettingsRepository
│   ├── sync_run_repository.py   # SqlAlchemySyncRunRepository
│   ├── secrets.py               # FernetSecretsAdapter
│   └── clock.py                 # SystemClockAdapter
│
├── application/                 # Use cases — orchestrate ports
│   ├── __init__.py
│   ├── bootstrap.py             # BootstrapMirror
│   ├── incremental.py           # IncrementalMirror
│   ├── query.py                 # QueryMirror
│   └── facade.py                # NvdLookupService (Phase 5 facade)
│
├── db/                          # SQLAlchemy ORM (separate from domain)
│   ├── __init__.py
│   └── models.py                # CveRow, NvdSettingsRow, NvdSyncRunRow
│
├── api.py                       # FastAPI admin router (/admin/nvd-mirror)
└── tasks.py                     # Celery task `mirror_nvd`
```

### Justification per subpackage (1–2 sentences each)

* **`settings.py`** — One file holding the `NvdMirrorSettings` dataclass and
  its env-var loader (mirroring the style of
  [app/analysis.py:295](app/analysis.py#L295) `get_analysis_settings()`).
  Lives at the package root because it has zero internal dependencies.
* **`domain/`** — Pure dataclasses and value objects. Importable from
  anywhere (including tests) without paying for httpx, SQLAlchemy, or DB
  setup. `mappers.py` belongs here because it only transforms shapes; it
  performs no I/O.
* **`ports/`** — Protocol interfaces, one file per concern. Splitting
  `repositories.py` into one file per repo would be premature; three
  related Protocols are easier to read together.
* **`adapters/`** — Each port has exactly one adapter. Multiple adapters
  per port would only be justified by an actual second backend (e.g. a
  filesystem-feed adapter for `NvdRemotePort`); `download_feeds_enabled`
  in the settings is reserved for that future without committing to it
  now.
* **`application/`** — One file per use case. `facade.py` is separate from
  the use cases because it orchestrates the live-fallback path (Phase 5)
  rather than the mirror itself. This keeps the use cases composable in
  tests without dragging in the live HTTP client.
* **`db/`** — ORM models that depend on the existing
  [app/db.py](../../app/db.py) `Base`. Kept separate from `domain/` so
  domain stays pure. Phase 0 §C.8 — existing repo uses legacy
  `Column(...)` style; this package uses SQLAlchemy 2.0 typed
  `mapped_column` (consistent within the package, divergent from the rest
  of the repo by intent).
* **`api.py`** — One router. Single-file is fine because the admin
  surface is small (5 endpoints).
* **`tasks.py`** — Celery task lives at the package root because the
  existing convention is [app/workers/tasks.py](../../app/workers/tasks.py).
  We register the task into the existing `celery_app` rather than
  creating a parallel one.

---

## 2. Domain model

Pure `@dataclass(frozen=True)` types in `domain/models.py`. No ORM, no
HTTP, no `Any` in any public field.

```python
# All datetimes carry tzinfo=UTC. Construction without tzinfo is rejected
# in __post_init__.

@dataclass(frozen=True, slots=True)
class CveRecord:
    cve_id: str                                  # "CVE-2023-12345"
    last_modified: datetime                      # UTC
    published: datetime                          # UTC
    vuln_status: Literal[
        "Awaiting Analysis", "Undergoing Analysis",
        "Analyzed", "Modified", "Deferred",
        "Rejected", "Received", "Unknown",
    ]
    description_en: str | None
    score_v40: float | None
    score_v31: float | None
    score_v2: float | None
    severity_text: str | None                    # "CRITICAL"/"HIGH"/...
    vector_string: str | None                    # best CVSS vector available
    aliases: tuple[str, ...]                     # CWEs, GHSAs, etc.
    cpe_criteria: tuple[CpeCriterion, ...]       # flat from configurations[]
    references: tuple[str, ...]
    raw: Mapping[str, Any]                       # opaque NVD JSON, kept verbatim


@dataclass(frozen=True, slots=True)
class CpeCriterion:
    """Flattened single match line from NVD's configurations[].nodes[].cpeMatch[].

    'criteria' is the CPE 2.3 string. The four version-bound fields are
    optional because NVD itself does not always populate them.
    """
    criteria: str                                # "cpe:2.3:a:vendor:product:..."
    vulnerable: bool
    version_start_including: str | None
    version_start_excluding: str | None
    version_end_including: str | None
    version_end_excluding: str | None


@dataclass(frozen=True, slots=True)
class CveBatch:
    """One paginated response from NVD: 0..N records plus paging metadata."""
    records: tuple[CveRecord, ...]
    start_index: int
    results_per_page: int
    total_results: int


@dataclass(frozen=True, slots=True)
class MirrorWindow:
    """A [start, end] half-open lastModified window. NVD's API caps
    windows at 120 days; we use 119 to leave headroom.

    __post_init__ enforces:
      - both datetimes UTC
      - end > start
      - (end - start) <= timedelta(days=119)
    """
    start: datetime
    end: datetime


@dataclass(frozen=True, slots=True)
class MirrorWatermark:
    """Last successfully-mirrored lastModified UTC point and its sync run id.

    A None watermark means "never mirrored" — bootstrap chooses the
    historical floor (2002-01-01).
    """
    last_modified_utc: datetime | None
    last_sync_run_id: int | None


@dataclass(frozen=True, slots=True)
class NvdSettingsSnapshot:
    """Read-side snapshot of the mirror settings row.

    The api_key is *plaintext* in this snapshot — adapters decrypt on
    load. It is masked or omitted on write paths exposed via API.
    """
    enabled: bool
    api_endpoint: str
    api_key_plaintext: str | None
    download_feeds_enabled: bool
    page_size: int
    window_days: int
    min_freshness_hours: int
    last_modified_utc: datetime | None
    last_successful_sync_at: datetime | None
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class SyncReport:
    """Outcome of one bootstrap or incremental run."""
    run_kind: Literal["bootstrap", "incremental"]
    started_at: datetime
    finished_at: datetime
    windows_completed: int
    upserts: int
    rejected_marked: int
    errors: tuple[str, ...]
    final_watermark: datetime | None


@dataclass(frozen=True, slots=True)
class FreshnessVerdict:
    """Computed from min_freshness_hours + last_successful_sync_at.

    Used by the Phase 5 facade to decide mirror vs live.
    """
    is_fresh: bool
    age_hours: float | None
    last_successful_sync_at: datetime | None
```

**Why dataclasses, not Pydantic:** the domain layer is consumed by use
cases and tests, not by FastAPI request/response. Pydantic is the right
tool at the API boundary (see §6); inside the bounded context, plain
dataclasses give us cheaper construction and zero coupling to any
validator framework.

---

## 3. Ports (Protocols)

`from typing import Protocol`. All in `ports/`:

```python
# ports/remote.py
class NvdRemotePort(Protocol):
    async def fetch_window(
        self, window: MirrorWindow, *, page_size: int
    ) -> AsyncIterator[CveBatch]: ...
        # Yields one CveBatch per HTTP page. Caller owns pagination
        # consumption order.

# ports/repositories.py
class CveRepositoryPort(Protocol):
    def upsert_batch(self, records: Sequence[CveRecord]) -> int: ...
        # Returns the number of rows actually upserted (insert or update).
        # WHERE excluded.last_modified > cves.last_modified ensures
        # idempotent replays.

    def find_by_cpe(self, cpe23: str) -> Sequence[CveRecord]: ...
        # See §6 for the matching algorithm. Returns CVEs whose
        # cpe_criteria match `cpe23` taking version ranges into account.

    def find_by_cve_id(self, cve_id: str) -> CveRecord | None: ...

    def soft_mark_rejected(self, cve_ids: Sequence[str]) -> int: ...
        # vuln_status='Rejected' — never DELETE.

class SettingsRepositoryPort(Protocol):
    def load(self) -> NvdSettingsSnapshot: ...
        # Decrypts api_key via SecretsPort on read.

    def save(self, snapshot: NvdSettingsSnapshot) -> NvdSettingsSnapshot: ...
        # Encrypts api_key via SecretsPort on write. Returns the
        # persisted snapshot.

    def advance_watermark(
        self, *, last_modified_utc: datetime, last_successful_sync_at: datetime
    ) -> None: ...

    def reset_watermark(self) -> None: ...
        # Sets last_modified_utc=NULL — forces full re-bootstrap.

class SyncRunRepositoryPort(Protocol):
    def begin(self, *, run_kind: str, window: MirrorWindow) -> int: ...
        # Inserts a 'running' row, returns its id.

    def finish(
        self, run_id: int, *, status: str, upserts: int, error: str | None
    ) -> None: ...

    def latest(self, limit: int = 10) -> Sequence[Mapping[str, object]]: ...
        # Audit list for the admin UI.

# ports/secrets.py
class SecretsPort(Protocol):
    def encrypt(self, plaintext: str) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> str: ...

# ports/clock.py
class ClockPort(Protocol):
    def now(self) -> datetime: ...
        # Always tz-aware UTC.
```

**Why split repositories into three Protocols:** different consumers need
different subsets. The Phase 5 facade (`NvdLookupService`) only needs
`CveRepositoryPort.find_by_cpe`; it should not be coupled to
`SyncRunRepositoryPort`. Three small Protocols beat one big one.

---

## 4. Adapters

| Port                     | Adapter                                  | Library     |
|--------------------------|------------------------------------------|-------------|
| `NvdRemotePort`          | `adapters/nvd_http.py::NvdHttpAdapter`   | `httpx.AsyncClient`, `tenacity` |
| `CveRepositoryPort`      | `adapters/cve_repository.py::SqlAlchemyCveRepository` | SQLAlchemy 2.0 (sync `Session` from existing [app/db.py:53](../../app/db.py#L53)) |
| `SettingsRepositoryPort` | `adapters/settings_repository.py::SqlAlchemySettingsRepository` | SQLAlchemy 2.0 |
| `SyncRunRepositoryPort`  | `adapters/sync_run_repository.py::SqlAlchemySyncRunRepository` | SQLAlchemy 2.0 |
| `SecretsPort`            | `adapters/secrets.py::FernetSecretsAdapter` | `cryptography.fernet.Fernet` |
| `ClockPort`              | `adapters/clock.py::SystemClockAdapter`  | stdlib `datetime` |

**One adapter per port; no second adapter is justified yet.**
`download_feeds_enabled` in the settings is *reserved* for a future
filesystem-feed adapter implementing `NvdRemotePort` (mirroring
Dependency-Track's downloadable JSON feeds). Phase 1 does not commit to
it; the settings field exists so we can flip it on later without a schema
migration.

**Sync vs async session.** Phase 0 §C.10 — the rest of the repo is sync.
The mirror keeps that. The HTTP client is async (httpx), the use cases
are async, but the repository adapters block on sync `Session`. Inside
the Celery worker that is fine; inside an async FastAPI handler we wrap
repo calls with `asyncio.get_event_loop().run_in_executor(...)`. **Why
not async SQLAlchemy:** it would require a parallel engine and double the
test surface for one path. Not worth it.

---

## 5. Persistence schema additions

Three **new** tables. No edits to existing tables. PostgreSQL-only
features (`JSONB`, `TIMESTAMPTZ`, partial indexes, `CHECK`).

### 5.1 `nvd_settings` — singleton row

| Column                       | Type           | Constraints / notes                                       |
|------------------------------|----------------|-----------------------------------------------------------|
| `id`                         | `INTEGER`      | PK; **`CHECK (id = 1)`** — enforces singleton             |
| `enabled`                    | `BOOLEAN`      | `NOT NULL DEFAULT FALSE`                                  |
| `api_endpoint`               | `TEXT`         | `NOT NULL DEFAULT 'https://services.nvd.nist.gov/rest/json/cves/2.0'` |
| `api_key_ciphertext`         | `BYTEA`        | nullable; Fernet-encrypted; never logged                  |
| `download_feeds_enabled`     | `BOOLEAN`      | `NOT NULL DEFAULT FALSE`                                  |
| `page_size`                  | `INTEGER`      | `NOT NULL DEFAULT 2000`; `CHECK (page_size BETWEEN 1 AND 2000)` |
| `window_days`                | `INTEGER`      | `NOT NULL DEFAULT 119`; `CHECK (window_days BETWEEN 1 AND 119)` |
| `min_freshness_hours`        | `INTEGER`      | `NOT NULL DEFAULT 24`; `CHECK (min_freshness_hours >= 0)` |
| `last_modified_utc`          | `TIMESTAMPTZ`  | nullable — NULL means "never mirrored"                    |
| `last_successful_sync_at`    | `TIMESTAMPTZ`  | nullable                                                  |
| `created_at`                 | `TIMESTAMPTZ`  | `NOT NULL DEFAULT now()`                                  |
| `updated_at`                 | `TIMESTAMPTZ`  | `NOT NULL DEFAULT now()` (trigger or app-side update)     |

### 5.2 `cves` — one row per CVE

| Column            | Type          | Constraints / notes                                  |
|-------------------|---------------|------------------------------------------------------|
| `cve_id`          | `TEXT`        | **PK**                                               |
| `last_modified`   | `TIMESTAMPTZ` | `NOT NULL`                                           |
| `published`       | `TIMESTAMPTZ` | `NOT NULL`                                           |
| `vuln_status`     | `TEXT`        | `NOT NULL`                                           |
| `description_en`  | `TEXT`        | nullable                                             |
| `score_v40`       | `REAL`        | nullable                                             |
| `score_v31`       | `REAL`        | nullable                                             |
| `score_v2`        | `REAL`        | nullable                                             |
| `severity_text`   | `TEXT`        | nullable                                             |
| `vector_string`   | `TEXT`        | nullable                                             |
| `aliases`         | `TEXT[]`      | empty array allowed                                  |
| `cpe_match`       | `JSONB`       | array of `CpeCriterion`-shaped objects (denormalised from the `data` JSON for index-only candidate selection) |
| `references`      | `JSONB`       | array of strings                                     |
| `data`            | `JSONB`       | the full NVD CVE object — verbatim                   |
| `updated_at`      | `TIMESTAMPTZ` | `NOT NULL DEFAULT now()`                             |

**Indexes:**
* `ix_cves_last_modified` — `BTREE (last_modified DESC)` — used by incremental window queries and admin sorting.
* `ix_cves_vuln_status` — `BTREE (vuln_status)` — small cardinality but lets us filter rejected CVEs cheaply.
* `ix_cves_cpe_match_gin` — `GIN (cpe_match jsonb_path_ops)` — supports `WHERE cpe_match @> '[{"criteria":"cpe:2.3:a:..."}]'` candidate filtering before in-Python version-range refinement.
* `ix_cves_aliases_gin` — `GIN (aliases)` — supports `WHERE aliases && ARRAY['CVE-…']` for cross-source aliasing later.

### 5.3 `nvd_sync_runs` — audit log

| Column           | Type           | Constraints                                           |
|------------------|----------------|-------------------------------------------------------|
| `id`             | `BIGSERIAL`    | PK                                                    |
| `run_kind`       | `TEXT`         | `NOT NULL`; `CHECK (run_kind IN ('bootstrap','incremental'))` |
| `window_start`   | `TIMESTAMPTZ`  | `NOT NULL`                                            |
| `window_end`     | `TIMESTAMPTZ`  | `NOT NULL`                                            |
| `started_at`     | `TIMESTAMPTZ`  | `NOT NULL DEFAULT now()`                              |
| `finished_at`    | `TIMESTAMPTZ`  | nullable until run completes                          |
| `status`         | `TEXT`         | `NOT NULL DEFAULT 'running'`; `CHECK (status IN ('running','success','failed','aborted'))` |
| `upserted_count` | `INTEGER`      | `NOT NULL DEFAULT 0`                                  |
| `error_message`  | `TEXT`         | nullable                                              |

**Indexes:**
* `ix_nvd_sync_runs_started_at` — `BTREE (started_at DESC)` — admin "last 10 runs" query.
* No FK to `nvd_settings` — the audit log is independent of the (singleton) settings row.

### 5.4 No FKs between the new tables

The audit log doesn't FK into `cves` (per-window upserts can be many-to-many
with runs). The settings row is decoupled — you can wipe `cves` without
touching audit history.

---

## 6. Integration point — Phase 5 facade

The mirror replaces **the leaf NVD calls**, not the orchestrators. Both
`run_multi_source_analysis_async` ([app/pipeline/multi_source.py:127-152](../../app/pipeline/multi_source.py#L127))
and `nvd_query_by_components_async` ([app/analysis.py:1330-1336](../../app/analysis.py#L1330))
ultimately call `nvd_query_by_cpe(cpe, api_key, cfg)`. Routing those leaf
calls through `NvdLookupService` covers both pathways with one cut.

### BEFORE — current call site (multi_source.py:130-138)

```python
def _fetch_cpe(cpe: str) -> tuple[str, list[dict], str | None]:
    LOGGER.debug("NVD: fetching CPE '%s'", cpe)
    try:
        cve_objs = nvd_query_by_cpe(cpe, api_key, settings=cfg)
        LOGGER.debug("NVD: CPE '%s' → %d CVEs", cpe, len(cve_objs))
        return cpe, cve_objs, None
    except Exception as exc:
        LOGGER.warning("NVD: CPE '%s' query failed: %s", cpe, exc)
        return cpe, [], str(exc)
```

### AFTER — facade-mediated call site

```python
def _fetch_cpe(cpe: str) -> tuple[str, list[dict], str | None]:
    LOGGER.debug("NVD: fetching CPE '%s'", cpe)
    try:
        # NvdLookupService implements the same legacy contract:
        # returns list[dict] in the raw NVD CVE JSON shape so
        # _finding_from_raw() keeps working unchanged.
        cve_objs = nvd_lookup_service.query_legacy(cpe, api_key=api_key, settings=cfg)
        return cpe, cve_objs, None
    except Exception as exc:
        LOGGER.warning("NVD: CPE '%s' query failed: %s", cpe, exc)
        return cpe, [], str(exc)
```

The facade is constructed at module load (or via FastAPI `Depends`) and
internally:

```python
class NvdLookupService:
    """Phase 5 facade — decides mirror vs live, with fallback.

    Output parity rule (cowork prompt §5.4): query_legacy returns the
    list[dict] shape that _finding_from_raw expects. Mirror records are
    serialised back to the NVD JSON shape via CveRecord.raw, which is
    kept verbatim in CveRecord (see §2).
    """
    def __init__(
        self,
        mirror_query_uc: QueryMirror,
        live_callable: Callable[[str, str | None, AnalysisSettings], list[dict]],
        settings_repo: SettingsRepositoryPort,
        clock: ClockPort,
    ) -> None: ...

    def query_legacy(
        self, cpe23: str, *, api_key: str | None, settings: AnalysisSettings
    ) -> list[dict]:
        snapshot = self._settings_repo.load()

        if not snapshot.enabled:
            return self._live(cpe23, api_key, settings)

        verdict = compute_freshness(snapshot, self._clock.now())
        if not verdict.is_fresh:
            log.warning(
                "nvd_mirror_stale_falling_back",
                extra={"age_hours": verdict.age_hours},
            )
            return self._live(cpe23, api_key, settings)

        try:
            records = self._mirror_query_uc.execute(cpe23)
        except Exception as exc:
            log.error("nvd_mirror_query_failed_falling_back",
                      extra={"cpe": cpe23, "exc": str(exc)})
            return self._live(cpe23, api_key, settings)

        if not records:
            # Mirror has data but no hit — could mean the CPE is genuinely
            # unaffected. Re-query live only when configured (default off
            # — defaulting to "trust the mirror" is the whole point).
            return [r.raw for r in records]  # empty list

        return [r.raw for r in records]
```

### Wiring into `_MultiSettings`

A new field is added to `_MultiSettings` (without restructuring the
existing flat keys):

```python
@dataclass(frozen=True)
class NvdMirrorSettings:
    enabled: bool = False
    api_endpoint: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key_env_var: str = "NVD_API_KEY"
    download_feeds_enabled: bool = False
    page_size: int = 2000
    window_days: int = 119
    min_freshness_hours: int = 24


# inside _MultiSettings (analysis.py:677)
mirror: NvdMirrorSettings = field(default_factory=NvdMirrorSettings)
```

Existing call sites read `cfg.nvd_api_base_url` etc. unchanged — Phase 0
§D.11 confirmed that field is canonical, not a shim. The mirror is its
own nested namespace `cfg.mirror.*`.

### `find_by_cpe` matching algorithm (CveRepositoryPort)

This is the non-trivial part of the repository — call it out explicitly.

```text
INPUT: cpe23 like "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"

STEP 1 — Normalise.
  Parse the input CPE into (vendor, product, version) plus the rest
  (which we treat as wildcards for matching). Lower-case.

STEP 2 — Index-only candidate selection.
  Build a JSONB filter that asks PG for CVEs whose cpe_match contains
  *any* element with a matching vendor:product, regardless of version.
  This is the GIN-backed query:

    WHERE cpe_match @> jsonb_build_array(
      jsonb_build_object('criteria_stem', '<vendor>:<product>')
    )

  (We denormalise cpe_match elements to include a 'criteria_stem' key
  precisely so this query is index-resident.)

STEP 3 — In-Python version-range refinement.
  Loop the candidate rows. For each cpe_match element whose stem
  matches, evaluate:
    a. exact criteria match (criteria == cpe23, ignoring trailing
       wildcard segments) → include.
    b. range match: if the criteria's version is "*", apply the four
       version-bound fields against `version` from the input CPE,
       using `packaging.version.Version` for ordering.
  If any element accepts, include the CVE.

STEP 4 — Filter out vuln_status='Rejected'.

OUTPUT: Sequence[CveRecord]
```

Step 3 is post-filter in Python because PG cannot natively compare
PEP-440 / semver-ish version strings; the `packaging` lib handles the
oddities of NVD's mix. Volume estimate: with vendor:product GIN
filtering, the candidate set is a few dozen rows even for hot products
like `apache:log4j`. Acceptable.

---

## 7. Mirroring algorithm (pseudocode)

```text
BootstrapMirror.execute(now):
    snapshot = settings_repo.load()
    cursor = snapshot.last_modified_utc or 2002-01-01T00:00:00Z
    target = now
    upserts_total = 0
    while cursor < target:
        window = MirrorWindow(
            start=cursor,
            end=min(cursor + window_days(snapshot), target),
        )
        run_id = sync_run_repo.begin(run_kind='bootstrap', window=window)
        try:
            page_count = 0
            window_upserts = 0
            async for batch in remote.fetch_window(window, page_size=snapshot.page_size):
                # Idempotent upsert per page (chunks of 200-500 rows
                # internally). Watermark advances ONLY at end-of-window.
                window_upserts += repo.upsert_batch(batch.records)
                # Soft-mark rejected
                rejected = [r.cve_id for r in batch.records if r.vuln_status == 'Rejected']
                repo.soft_mark_rejected(rejected)
                page_count += 1
            # Atomic per-window: advance watermark + finish run in ONE tx.
            with tx():
                settings_repo.advance_watermark(
                    last_modified_utc=window.end,
                    last_successful_sync_at=clock.now(),
                )
                sync_run_repo.finish(run_id, status='success',
                                     upserts=window_upserts, error=None)
        except Exception as exc:
            sync_run_repo.finish(run_id, status='failed',
                                 upserts=window_upserts, error=str(exc))
            raise
        cursor = window.end
        upserts_total += window_upserts
    return SyncReport(run_kind='bootstrap', ..., final_watermark=target)


IncrementalMirror.execute(now):
    snapshot = settings_repo.load()
    if snapshot.last_modified_utc is None:
        # No prior bootstrap. Defer to BootstrapMirror.
        return BootstrapMirror(...).execute(now)
    cursor = snapshot.last_modified_utc
    # Same loop as bootstrap but typically only 1 window short of `now`.
    # ... identical body ...
```

**Why end-of-window watermark advance:** if we advance per-page and
crash mid-window, the next run skips the rest of that window. Per-window
advance means restarting overwrites the window — safe because
`upsert_batch` is idempotent (`WHERE excluded.last_modified > cves.last_modified`).

**Idempotent upsert SQL (applied by `upsert_batch`):**

```sql
INSERT INTO cves (cve_id, last_modified, published, vuln_status,
                  description_en, score_v40, score_v31, score_v2,
                  severity_text, vector_string, aliases, cpe_match,
                  references, data, updated_at)
VALUES %s
ON CONFLICT (cve_id) DO UPDATE SET
    last_modified  = EXCLUDED.last_modified,
    published      = EXCLUDED.published,
    vuln_status    = EXCLUDED.vuln_status,
    description_en = EXCLUDED.description_en,
    score_v40      = EXCLUDED.score_v40,
    score_v31      = EXCLUDED.score_v31,
    score_v2       = EXCLUDED.score_v2,
    severity_text  = EXCLUDED.severity_text,
    vector_string  = EXCLUDED.vector_string,
    aliases        = EXCLUDED.aliases,
    cpe_match      = EXCLUDED.cpe_match,
    references     = EXCLUDED.references,
    data           = EXCLUDED.data,
    updated_at     = now()
WHERE EXCLUDED.last_modified > cves.last_modified;
```

The `WHERE` clause is critical — it prevents an out-of-order page from
overwriting a *fresher* row that a later window already wrote. Replays
are no-ops; resumes after a crash overwrite their own window.

---

## 8. Rate-limit budget

NVD published rate limits
([reference](https://nvd.nist.gov/developers/start-here#RateLimits)):

| Mode             | Limit            | Min sleep between requests | Concurrency |
|------------------|------------------|----------------------------|-------------|
| **Anonymous**    | 5 req / 30 s     | ~6.5 s (with safety margin)| 1           |
| **With API key** | 50 req / 30 s    | ~0.7 s (with safety margin)| 1           |

We deliberately use **single-threaded sequential paging** in the mirror
client, mirroring the existing
`nvd_query_by_components_async`'s rationale (Phase 0 §G, bug-fix `g`).
Concurrency=1 with a calibrated sleep stays under the global token
bucket by construction.

### Retry policy (`tenacity`)

* **Triggers:** HTTP 429, 503, network timeouts, `httpx.RemoteProtocolError`.
* **Strategy:** exponential backoff, base=2 s, max=60 s, **with jitter**.
* **Max attempts:** 5.
* **Honour `Retry-After`:** on 429, use `max(backoff, Retry-After)` so we
  never undercut the server. Mirrors the existing pattern at
  [app/analysis.py:447-454](../../app/analysis.py#L447).

### Bootstrap time budget (informational)

```
NVD CVE corpus (~250k records, growing):
  200 windows of 119 days from 2002-01-01 to 2026-04-28.
  Typical window:  1-2 pages of 2000 results = 1-2 requests.
  With key:    200 windows × ~2 req × 0.7 s ≈ 4-6 minutes
  Without key: 200 windows × ~2 req × 6.5 s ≈ 45-60 minutes
```

These estimates go into `02-operations.md` (Phase 6).

---

## 9. Failure modes & recovery

| # | Failure                                              | Why it happens                                  | Recovery                                                                 |
|---|------------------------------------------------------|-------------------------------------------------|--------------------------------------------------------------------------|
| 1 | Watermark advanced but rows not persisted            | App crash between page upsert and watermark write | We never split this — the per-window transaction wraps both `advance_watermark` and `sync_run_repo.finish`. Page upserts happen in their own (smaller) transactions; if the window aborts before the final tx, the watermark stays put and the next run replays the window (idempotent). |
| 2 | Partial bootstrap interruption                       | `kill -9`, OOM, deploy mid-run                  | `last_modified_utc` is the watermark. Next run resumes from there; never restarts at 2002. The `nvd_sync_runs` row from the killed run stays at `status='running'` until either (a) admin marks it `'aborted'` via the admin API, or (b) a sweeper task at run start marks any `'running'` row older than 6× window-time as `'aborted'`. |
| 3 | API key revoked mid-run                              | NVD invalidates the key; HTTP 403 on every page | `tenacity` does **not** retry 403. The remote adapter raises; the use case writes `status='failed'` with the error message; the watermark does **not** advance. Operator gets a structured log line `nvd_mirror_auth_failed` and the admin `/sync/status` endpoint shows the failure. |
| 4 | PostgreSQL pool exhaustion under bulk upsert         | `executemany` of 50 000 rows in one statement   | `upsert_batch` chunks at **400 rows per `INSERT`** (between the prompt's 200–500 range). One transaction per chunk, sized for the default psycopg pool (~10 connections). |
| 5 | NVD returns malformed JSON for one record in a batch | Real-world: schema drift, partial NVD outage    | `mappers.py::map_cve_object` raises `MalformedCveError`. The use case catches per-record, increments an `errors` counter on the `SyncReport`, and continues. **One bad record never aborts a window.** |
| 6 | Out-of-order modifications across windows            | NVD sometimes back-fills `lastModified`         | The `WHERE excluded.last_modified > cves.last_modified` clause on the upsert ensures we never overwrite a fresher row. The bug is invisible to consumers. |
| 7 | Long-running bootstrap blocks Celery beat re-fire    | Celery beat schedules `mirror_nvd` every hour   | `mirror_nvd` checks `nvd_sync_runs` for any `status='running'` row at start; if present, it logs and exits early. **One mirror run at a time, ever.** |
| 8 | Redis unavailable                                    | Worker / beat can't run                         | Per cowork prompt: the mirror is **not** a hard dependency. The Phase 5 facade falls through to the live API when (a) `enabled=False` OR (b) `is_fresh=False` OR (c) the mirror raises. Redis being down only stops *new* mirroring runs; queries against existing mirror data still work because the repo doesn't need Redis. |
| 9 | 120-day window upper bound exceeded                  | Programmer error / config drift                 | `MirrorWindow.__post_init__` raises `ValueError`. Both bootstrap and incremental clamp at 119 days when constructing the window, so this is a defensive check, not a runtime path. |

---

## 10. Testing strategy

### 10.1 Unit tests — domain + use-cases (no I/O)

* **What:** every dataclass invariant, every mapper transformation, every
  use case with all four ports faked.
* **Where:** `tests/nvd_mirror/unit/`.
* **Fakes:** `FakeNvdRemote` yields canned `CveBatch`es; `FakeCveRepository`
  is an in-memory dict; `FakeSettingsRepository` is a single mutable dataclass;
  `FixedClock(now)` is a value object. **All fakes are <50 LOC each.**
* **Coverage targets per use case:**
  * `BootstrapMirror`: empty corpus; one full window; multiple windows;
    bootstrap-then-resume after fake crash mid-window; rejected-CVE handling;
    out-of-order modifications.
  * `IncrementalMirror`: no-op when watermark == now; one delta window;
    delegates to bootstrap when watermark is NULL.
  * `QueryMirror`: exact CPE hit; vendor:product hit with version range;
    vendor:product hit *outside* version range (excluded); rejected-CVE
    excluded; empty repo.
  * `NvdLookupService.query_legacy`: all five branches (mirror disabled →
    live; mirror enabled+fresh+hit → mirror; mirror enabled+stale → live
    with warning; mirror enabled+empty hit → mirror returns []; mirror
    enabled+raises → live + error log).

### 10.2 Integration tests — real PostgreSQL

* **Where:** `tests/nvd_mirror/integration/`.
* **Engine:** `testcontainers-python` `PostgresContainer`. Used **only**
  by the integration suite; default test runs (Phase 0 §C.10 SQLite path)
  remain unchanged.
* **Marker:** `@pytest.mark.integration` and a CI flag to opt in.
* **Tests:** repo upsert idempotency by replay; `find_by_cpe` with a
  fixture corpus of 5 hand-picked CVEs covering version ranges; migration
  apply/downgrade round-trip; settings encrypt/decrypt round-trip.

### 10.3 Contract tests — NVD client against fixtures

* **Where:** `tests/fixtures/nvd/` — recorded JSON pages from a real NVD
  query, committed to the repo.
* **Tool:** `respx` (httpx mock). The remote adapter is exercised against
  the fixtures, asserting (a) correct query parameters, (b) correct page
  iteration, (c) 429 retry behaviour with simulated `Retry-After`.
* **No live API calls in CI, ever.** Recording is a manual one-off,
  documented in `02-operations.md`.

### 10.4 End-to-end test — single window through to query

* **Where:** `tests/nvd_mirror/e2e/test_mirror_then_query.py`.
* **Scenario:** spin up Postgres-via-testcontainers; run `BootstrapMirror`
  with a *capped* window (e.g. 10 days, 1 page) using `respx`-mocked NVD
  responses; assert rows in `cves`; call `QueryMirror` on a known CPE
  from the fixture; assert non-empty result; assert `nvd_sync_runs` has
  `status='success'`; assert watermark advanced.

### 10.5 Existing tests must not regress

The Phase 0 baseline (8 test files in `tests/`) must pass unchanged. The
Phase 5 facade is wired so that with `enabled=False` (default) the
existing snapshot tests under `tests/snapshots/` produce identical output.

---

## 11. Backward compatibility

The contract is binary at the feature flag — but with three explicit
graceful-degradation rules to match the cowork prompt §11:

| Mirror state                                | Behaviour                                                  |
|---------------------------------------------|------------------------------------------------------------|
| `enabled=False`                             | **Bit-for-bit identical** to today. Phase 5 facade short-circuits to the live `nvd_query_by_cpe`. No DB reads against `cves` (the table may even be empty). |
| `enabled=True`, `cves` empty                | Falls through to live API. Logs once at WARNING: `nvd_mirror_empty_falling_back` so operators know to run a bootstrap. |
| `enabled=True`, watermark > min_freshness_hours old | Falls through to live API. Logs at WARNING per query: `nvd_mirror_stale_falling_back` with `age_hours` extra. Beat will eventually catch up. |
| `enabled=True`, fresh, mirror has data      | **Mirror path.** No live API calls for NVD. (OSV and GHSA paths are untouched.) |
| `enabled=True`, fresh, mirror raises        | Falls through to live API. Logs at ERROR: `nvd_mirror_query_failed_falling_back`. Tracks count for circuit-breaker hint. |

**OSV and GHSA paths are not modified by this change.** Phase 0 §B.7
showed both inhabit the same multi-source orchestrator; the facade
replaces only the `nvd_query_by_cpe` leaf, so OSV/GHSA call paths flow
through unchanged.

**Output schema is unchanged.** The cowork prompt §"WHAT YOU MUST NOT DO"
forbids changing the `Finding` shape. Our `query_legacy` returns
`list[dict]` in raw NVD CVE JSON — exactly what `_finding_from_raw`
([app/analysis.py:609](../../app/analysis.py#L609)) consumes today.

---

## Ready for Phase 2

This design is complete. Phase 2 implements §1, §2, §4 (DB adapters),
§5 (schema), and the settings additions from §6. Phase 3 implements §3
(remote adapter + use cases). Phase 4 wires Celery + admin router.
Phase 5 wires the facade. Phase 6 ships ops docs.

Open questions are listed and resolved; nothing in this design depends
on a Phase 0 finding that turned out to be wrong.
