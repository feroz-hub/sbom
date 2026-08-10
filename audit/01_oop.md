# Phase 2.1 — OOP Fundamentals Audit

> Encapsulation · Abstraction · Inheritance · Polymorphism. Every finding cites file paths read directly during inventory or this phase.

---

## Encapsulation

### Finding OOP-001: SQLAlchemy ORM rows leak through every layer

- **Principle violated:** Encapsulation
- **Severity:** High
- **Location:** [app/routers/sboms_crud.py:101-150, 153-158, 176-277, 401-712](../app/routers/sboms_crud.py); [app/services/sbom_service.py:120-217](../app/services/sbom_service.py); [app/services/analysis_service.py:119-203](../app/services/analysis_service.py); [app/routers/runs.py:99-134](../app/routers/runs.py); [app/services/dashboard_service.py:70-110](../app/services/dashboard_service.py)
- **Evidence:**
  ```python
  # routers/sboms_crud.py:101
  def upsert_components(db: Session, sbom_obj: SBOMSource, components: list[dict]) -> dict:
      existing_rows = db.execute(select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_obj.id)).scalars().all()
      ...
      by_comp_triplet[triplet] = row   # raw ORM row stashed in a dict that crosses functions
      ...
      return {"triplet": by_comp_triplet, "cpe": by_cpe}
  ```
  ```python
  # routers/runs.py:120
  for run, sbom_name in rows:
      run_dict = {k: v for k, v in run.__dict__.items() if not k.startswith("_")}   # reaches into ORM internals
      run_dict["sbom_name"] = sbom_name or run_dict.get("sbom_name")
      items.append(run_dict)
  ```
- **Why this violates the principle:** ORM session-bound objects with their `_sa_instance_state` and lazy-load relationships are passed across module boundaries (router → upsert helper → finding-persist helper). Callers iterate `obj.__dict__`, treat raw rows as dicts, and depend on whether the row is still attached to a session. There is no DTO/value-object boundary.
- **Impact:** A detached or expired row triggers `DetachedInstanceError` when a caller dereferences `row.id`. `runs.py` uses `__dict__` filtering — a private SQLAlchemy concern — and would silently lose mapped columns once `Mapped`/`mapped_column` (SQLA 2 idiom) is introduced. Refactoring the schema requires touching every consumer.
- **Recommended fix:** Return Pydantic/`dataclass` DTOs from repository methods (e.g. `SBOMComponentRef(id=int, cpe=str|None, name=str, version=str|None)`). Routers consume DTOs and map to response schemas; `__dict__` access disappears.
- **Effort:** L
- **Risk of fix:** Medium — touches ~7 hot paths.

### Finding OOP-002: Module-level mutable globals (`_completed`, `_locks`, `_executor`, `_nvd_session`, `_settings_instance`)

- **Principle violated:** Encapsulation
- **Severity:** Medium
- **Location:** [app/idempotency.py:45-46](../app/idempotency.py); [app/analysis.py:42-44, 750](../app/analysis.py); [app/settings.py:238, 257](../app/settings.py)
- **Evidence:**
  ```python
  # app/idempotency.py:45-46
  _completed: dict[str, tuple[float, dict]] = {}
  _locks: dict[str, asyncio.Lock] = {}
  ```
  ```python
  # app/analysis.py:42
  _nvd_session = requests.Session()
  _nvd_session.verify = certifi.where()
  ```
- **Why this violates the principle:** Process-global state survives between requests, but is owned by no class and can't be swapped or cleared per test. `_locks` is unbounded — every distinct idempotency key adds an `asyncio.Lock` that is never evicted (`_prune` only removes the response cache).
- **Impact:** Memory leak proportional to unique idempotency keys. Tests cannot reset cleanly without monkey-patching the module. Multiple FastAPI test apps in one process share the cache.
- **Recommended fix:** Wrap idempotency state in an `IdempotencyStore` class that owns `_completed` + `_locks`, provides `evict()`, and is bound to `app.state` via FastAPI lifespan. Same pattern for the NVD session: a `NvdHttpClient` class injected via `Depends`.
- **Effort:** M
- **Risk of fix:** Low.

### Finding OOP-003: `Settings` is mutated post-class-definition with bare `Settings.X = …` assignments

- **Principle violated:** Encapsulation, Principle of Least Astonishment
- **Severity:** Medium
- **Location:** [app/settings.py:209-231](../app/settings.py)
- **Evidence:**
  ```python
  # app/settings.py:208-231
  # NVD API endpoint
  Settings.NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
  Settings.GITHUB_GRAPHQL = "https://api.github.com/graphql"
  Settings.OSV_API = "https://api.osv.dev/v1"
  Settings.VULNDB_API = "https://vuldb.com/?api"
  Settings.OSV_MAX_BATCH = 1000
  Settings.MAX_UPLOAD_BYTES = 20 * 1024 * 1024
  Settings.DEFAULT_RESULTS_PER_PAGE = 20
  Settings.APP_VERSION = "2.0.0"
  ```
- **Why this violates the principle:** Pydantic v2 `BaseSettings` walks declared *fields* — these later assignments become **class attributes that bypass validation, env-var loading, and `model_dump()`**. Anyone introspecting `Settings.model_fields` won't see them; `Settings()` instances inherit them statically. They masquerade as settings but are constants, with no docstring saying so.
- **Impact:** A reader cannot tell which attributes are env-driven without diffing `model_fields` against `dir(Settings)`. Any future env override of `MAX_UPLOAD_BYTES` will silently fail.
- **Recommended fix:** Move the eight constants into a sibling `app/constants.py` module (or a `class Constants:` block at the top of `settings.py` whose attributes are clearly labelled). Keep `Settings` as fields-only.
- **Effort:** S
- **Risk of fix:** Low — touches three import sites (`main.py`, `health.py`, `analyze_endpoints.py`).

### Finding OOP-004: Underscored "private" helpers used as the public re-export surface

- **Principle violated:** Encapsulation
- **Severity:** Low
- **Location:** [app/analysis.py:347-363](../app/analysis.py); [app/routers/sboms_crud.py:30-35](../app/routers/sboms_crud.py); [app/routers/analyze_endpoints.py:37-42](../app/routers/analyze_endpoints.py); [app/routers/sbom.py:127, 140](../app/routers/sbom.py)
- **Evidence:**
  ```python
  # app/analysis.py:347-363 — leading underscores deliberately re-exported
  from .sources.cpe import cpe23_from_purl as _cpe23_from_purl
  from .sources.purl import parse_purl as _parse_purl
  ...
  ```
  ```python
  # app/routers/sbom.py:127
  from ..analysis import _parse_purl, extract_components
  ```
- **Why this violates the principle:** Names beginning with `_` signal "module-private" by Python convention, yet they are imported from across the codebase. Either the convention is a lie or the import is wrong.
- **Impact:** Future readers can't tell which symbols are real API; `__all__` (where present) doesn't catch them.
- **Recommended fix:** Drop the alias: import the public name (`parse_purl`, `cpe23_from_purl`) directly from `app.sources.purl` / `app.sources.cpe`. Delete the underscore re-export aliases from `analysis.py`.
- **Effort:** S
- **Risk of fix:** Low.

---

## Abstraction

### Finding OOP-005: `VulnSource` Protocol exists but adapters lazy-import the legacy module they were meant to replace

- **Principle violated:** Abstraction
- **Severity:** High
- **Location:** [app/sources/nvd.py:36-47](../app/sources/nvd.py); [app/sources/osv.py:38-44](../app/sources/osv.py); [app/sources/ghsa.py:42-60](../app/sources/ghsa.py); [app/sources/base.py:47-66](../app/sources/base.py)
- **Evidence:**
  ```python
  # app/sources/nvd.py:36-47
  async def query(self, components, settings) -> SourceResult:
      if not components:
          return empty_result()
      # Lazy import: ``app.analysis`` re-exports symbols from ``app.sources``
      # at module load time, so a top-level import here would create a
      # circular import. The lazy import is paid once per process.
      from app.analysis import nvd_query_by_components_async
      findings, errors, warnings = await nvd_query_by_components_async(
          components, settings, nvd_api_key=self.api_key,
      )
      return SourceResult(findings=findings, errors=errors, warnings=warnings)
  ```
- **Why this violates the principle:** The `VulnSource` Protocol promises a uniform abstraction, but three of four adapters are **shells** that delegate back into the 1.4k-line legacy module. The abstraction hides nothing — readers must still understand `nvd_query_by_components_async`, `osv_query_by_components`, `github_query_by_components` to reason about behaviour. The lazy-import comment confirms the inversion: the abstraction depends on the concretion.
- **Impact:** Any change to the legacy function ripples through the adapter even though the adapter exists to insulate callers. The promised "Phase 5 will move it" docstrings (in all three files) acknowledge the leak — but the move has not happened.
- **Recommended fix:** Move the bodies of `nvd_query_by_components_async`, `osv_query_by_components`, and `github_query_by_components` (and their helpers `_finding_from_raw`, `_best_score_and_vector_from_osv`, `_github_ecosystem_from_purl_type`, etc.) into `app/sources/{nvd,osv,ghsa}.py`. Keep `app.analysis` as a thin compatibility shim only as long as Celery `tasks.py` needs it (which is itself dead — see YAGNI).
- **Effort:** L
- **Risk of fix:** Medium — heavily covered by `tests/test_sources_adapters.py` and `tests/test_analyze_endpoints_snapshot.py`, so regressions surface fast.

### Finding OOP-006: `_MultiSettings` exposes per-source HTTP knobs to every adapter

- **Principle violated:** Abstraction (configuration leakage), ISP
- **Severity:** Medium
- **Location:** [app/analysis.py:681-743](../app/analysis.py); [app/sources/vulndb.py:194-208](../app/sources/vulndb.py); [app/sources/ghsa.py:50-57](../app/sources/ghsa.py)
- **Evidence:**
  ```python
  # app/analysis.py:681
  @dataclass(frozen=True)
  class _MultiSettings(AnalysisSettings):
      gh_graphql_url: str = "https://api.github.com/graphql"
      gh_token_env: str = "GITHUB_TOKEN"
      gh_token_override: str | None = None
      osv_api_base_url: str = "https://api.osv.dev"
      osv_results_per_batch: int = 1000
      vulndb_api_base_url: str = "https://vuldb.com/?api"
      ...
  ```
  ```python
  # app/sources/vulndb.py:202
  base_url = getattr(settings, "vulndb_api_base_url", "https://vuldb.com/?api")
  ```
- **Why this violates the principle:** A single mega-settings dataclass collects every URL, timeout, batch size, retry count, and credential for every source. Each adapter pulls only its slice with `getattr(settings, ..., default)`, bypassing static typing. The settings object is the abstraction — but a real abstraction would split into `NvdConfig`, `OsvConfig`, `GhsaConfig`, `VulnDbConfig`, and the runner would only see what it owns.
- **Impact:** Adding a new source forces editing the dataclass. The `getattr(..., default=…)` pattern hides typos. `gh_token_override` exists purely so `GhsaSource` can `dataclasses.replace(settings, gh_token_override=…)` — a backwards-compatibility shim that pollutes the shared schema.
- **Recommended fix:** Each adapter takes its own typed config object via constructor (`NvdSource(api_key=…, base_url=…, timeout=…)`); the runner passes a generic `RunSettings` only with cross-cutting concerns (concurrency, user-agent).
- **Effort:** M
- **Risk of fix:** Low.

### Finding OOP-007: `app/ports/` declares Protocols that no production code accepts as a parameter

- **Principle violated:** Abstraction (unused abstractions = no abstraction)
- **Severity:** Medium
- **Location:** [app/ports/repositories.py:17-58](../app/ports/repositories.py); [app/ports/storage.py](../app/ports/storage.py)
- **Evidence:**
  ```python
  # app/ports/repositories.py:18
  @runtime_checkable
  class SBOMRepositoryPort(Protocol):
      """Subset of SBOM data access used by services and tests."""
      @staticmethod
      def get_sbom(db: Session, sbom_id: int) -> SBOMSource | None: ...
  ```
  Verified by `grep -rn "SBOMRepositoryPort\|AnalysisRepositoryPort\|StoragePort"` — only definitions and the package `__init__` reference these names.
- **Why this violates the principle:** A port without an injection site is a comment, not an abstraction. Routers depend on concrete `SQLAlchemy` calls; services depend on functions that take `db: Session`. The Protocols document an architecture that does not exist.
- **Impact:** Reader confusion, false sense of testability.
- **Recommended fix:** Either (a) actually thread these into services via FastAPI dependencies and let production wire concrete repositories, OR (b) delete `app/ports/` and the dead `app/repositories/`. See YAGNI-001.
- **Effort:** L (option a) or S (option b).
- **Risk of fix:** Low.

### Finding OOP-008: `health.public_analysis_config()` is a giant `getattr(s, "x", default)` blob

- **Principle violated:** Abstraction (the abstraction is `AnalysisSettings`, but the consumer can't trust it)
- **Severity:** Low
- **Location:** [app/routers/health.py:31-70](../app/routers/health.py)
- **Evidence:**
  ```python
  # app/routers/health.py:39-65
  return {
      "source_name": getattr(s, "source_name", "NVD"),
      "http_user_agent": getattr(s, "http_user_agent", "SBOM-Analyzer/enterprise-2.0"),
      "nvd_api_base_url": getattr(s, "nvd_api_base_url", None),
      ...
  }
  ```
- **Why this violates the principle:** `s = get_analysis_settings_multi()` returns a frozen dataclass with statically known fields, yet every access wraps in `getattr(..., default=…)`. The dataclass is an abstraction that callers refuse to trust.
- **Impact:** Readability; if a default value is wrong it's silently used.
- **Recommended fix:** Use direct attribute access (`s.source_name`); the static type system is the contract.
- **Effort:** S
- **Risk of fix:** Low.

---

## Inheritance

### Finding OOP-009: Trivial inheritance of `_MultiSettings` from `AnalysisSettings`

- **Principle violated:** Inheritance vs Composition (composition over inheritance)
- **Severity:** Low
- **Location:** [app/analysis.py:681](../app/analysis.py)
- **Evidence:**
  ```python
  @dataclass(frozen=True)
  class _MultiSettings(AnalysisSettings):
      gh_graphql_url: str = "https://api.github.com/graphql"
      ...
  ```
- **Why this violates the principle:** `AnalysisSettings` describes NVD-specific config + global thresholds; `_MultiSettings` adds OSV/GitHub/VulDB knobs. Inheritance is used only to share fields. The result is a god-class settings object — see OOP-006.
- **Impact:** Splitting the per-source settings later requires undoing the inheritance.
- **Recommended fix:** Composition: `MultiAnalysisSettings(thresholds: CvssThresholds, nvd: NvdConfig, osv: OsvConfig, ghsa: GhsaConfig, vulndb: VulnDbConfig, runtime: RuntimeConfig)`.
- **Effort:** M
- **Risk of fix:** Low (covered by OOP-006).

### Finding OOP-010: `ORMModel(BaseModel)` is the only Pydantic base, and only sets one config flag

- **Principle violated:** Inheritance (gratuitous base class)
- **Severity:** Low
- **Location:** [app/schemas.py:14-17](../app/schemas.py)
- **Evidence:**
  ```python
  class ORMModel(BaseModel):
      class Config:
          from_attributes = True
  ```
- **Why this violates the principle:** Inheritance to share a single bool flag. Pydantic v2 supports `model_config = ConfigDict(from_attributes=True)` at any level; or a class decorator. The base adds a layer in the MRO with no behaviour.
- **Impact:** Negligible. Listed for completeness.
- **Recommended fix:** Either keep `ORMModel` (and stop apologising for it) or inline `model_config` in each `*Out` schema. The current Config-inner-class form is also pre-Pydantic-v2 idiom.
- **Effort:** S
- **Risk of fix:** Low.

### No-violation: NVD-mirror domain layer

The hexagonal sub-app under `app/nvd_mirror/` uses Protocols (`SettingsRepositoryPort`, `CveRepositoryPort`, `ClockPort`, `SecretsPort`) and concrete adapter classes that **do not extend** the Protocols (Python Protocols are structural — no inheritance needed). Verified by reading [app/nvd_mirror/application/facade.py:67-150](../app/nvd_mirror/application/facade.py) and [app/nvd_mirror/api.py:57-83](../app/nvd_mirror/api.py). This is the right shape and a positive example for the rest of the codebase.

---

## Polymorphism

### Finding OOP-011: `extract_components` does an `isinstance` switch on input shape

- **Principle violated:** Polymorphism (type-switch instead of dispatch)
- **Severity:** Low
- **Location:** [app/parsing/extract.py:12-57](../app/parsing/extract.py)
- **Evidence:**
  ```python
  def extract_components(sbom_json: Any) -> list[dict]:
      if isinstance(sbom_json, dict):
          ...
      text = sbom_json.strip()... if isinstance(sbom_json, str) else ""
      if text.startswith("{") or text.startswith("["):
          ...
      if text.startswith("<"):
          ...
  ```
- **Why this violates the principle:** A single function juggles four input modes (dict, JSON string, XML string, fallback JSON) with `startswith` heuristics. Each format has its own parser already (`parse_cyclonedx_dict`, `parse_cyclonedx_xml`, `parse_spdx_dict`, `parse_spdx_xml`) — but the dispatcher re-implements format detection inline rather than delegating to `parsing.format.detect_sbom_format`.
- **Impact:** SPDX detection in the dict branch checks `doc.get("spdxVersion") or doc.get("SPDXID")`, which differs from what `format.py` does. Drift risk.
- **Recommended fix:** Pull format detection into one helper used by both `extract_components` and `detect_sbom_format`. Replace the inline `if … elif …` with a small dispatch dict `{format_name: parser_fn}`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding OOP-012: `_finding_from_raw` swallows exceptions to retry the same parsing path

- **Principle violated:** Polymorphism (manual try/except instead of typed dispatch); Fail-Fast (overlap)
- **Severity:** Medium
- **Location:** [app/analysis.py:613-666](../app/analysis.py)
- **Evidence:**
  ```python
  def _finding_from_raw(raw, cpe, component_name, component_version, settings):
      try:
          record = CVERecord.from_dict(raw)
          score = record.cvss_best_base()
          ...
      except Exception:
          # Re-parses metrics + descriptions inline
          metric_score, metric_vector, metric_severity = _extract_best_cvss(raw.get("metrics") or {})
          ...
  ```
- **Why this violates the principle:** The `except Exception` branch reimplements ~20 lines of what the `try` branch already does, picking up only the pieces that don't go through `CVERecord.from_dict`. Two parallel codepaths for "same input shape" — the polymorphic alternative is to make `CVERecord.from_dict` resilient (return partial records) so there's one path.
- **Impact:** Bugs only manifest in the failure branch (rarely exercised in tests); behaviour drift between branches is invisible.
- **Recommended fix:** Make `CVERecord.from_dict` total — never raise. Return a `CVERecord` with whatever was parseable. Drop the second branch.
- **Effort:** M
- **Risk of fix:** Low — covered by snapshot tests.

### Finding OOP-013: Manual `cls()` factory in `app/sources/factory.py` instead of registry-driven dispatch

- **Principle violated:** Polymorphism (mixed strategies)
- **Severity:** Low
- **Location:** [app/sources/factory.py:46-56](../app/sources/factory.py); [app/sources/registry.py:24-29](../app/sources/registry.py)
- **Evidence:**
  ```python
  # factory.py:50-55
  factories = {
      "NVD": lambda: NvdSource(api_key=nvd_api_key_for_adapters()),
      "OSV": OsvSource,
      "GITHUB": lambda: GhsaSource(token=github_token_for_adapters()),
      "VULNDB": lambda: VulnDbSource(api_key=vulndb_api_key_for_adapters()),
  }
  ```
  ```python
  # registry.py:24-29
  SOURCE_REGISTRY: dict[str, type[VulnSource]] = {
      NvdSource.name: NvdSource,
      OsvSource.name: OsvSource,
      ...
  }
  ```
- **Why this violates the principle:** Two parallel registries (`SOURCE_REGISTRY` vs `factories` dict) both keyed by source name. The registry knows *types*; the factory knows *how to instantiate with credentials*. Adding a fifth source means editing both.
- **Impact:** Drift risk — `SOURCE_REGISTRY` will eventually include something the factory doesn't know how to construct.
- **Recommended fix:** Make each adapter class own its `from_settings(cls, settings) → cls` classmethod. The factory becomes `[get_source(name).from_settings(settings) for name in normalize_source_names(...)]`.
- **Effort:** S
- **Risk of fix:** Low.

### Finding OOP-014: Inline `if/elif sev …` ladders for severity bucketing repeat across modules

- **Principle violated:** Polymorphism / DRY overlap
- **Severity:** Low
- **Location:** [app/services/analysis_service.py:75-86](../app/services/analysis_service.py); [app/utils.py:74-85](../app/utils.py); [app/sources/vulndb.py:64-80](../app/sources/vulndb.py); [app/routers/sboms_crud.py:322-326](../app/routers/sboms_crud.py); [app/routers/dashboard_main.py:73-79](../app/routers/dashboard_main.py)
- **Evidence:**
  ```python
  # services/analysis_service.py:74-86
  buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
  for f in findings:
      sev = str((f or {}).get("severity", "UNKNOWN")).upper()
      if sev == "CRITICAL":
          buckets["critical"] += 1
      elif sev == "HIGH":
          ...
  ```
- **Why this violates the principle:** A polymorphic alternative is `bucket = sev.lower(); buckets[bucket if bucket in buckets else "unknown"] += 1` — already used in `routers/dashboard_main.py:73-79`. The `if/elif` form is an anti-pattern repeated five times.
- **Impact:** Minor; mostly DRY (cross-listed in `03_dry.md`).
- **Recommended fix:** A single `count_severities(findings: list[dict]) → dict[str,int]` in `app/sources/severity.py`. Five call sites converge.
- **Effort:** S
- **Risk of fix:** Low.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 2 |
| Medium | 5 |
| Low | 7 |
| **Total** | **14** |

**Most-leveraged fixes (top 3):**
1. **OOP-005** — Move source query bodies into `app/sources/{nvd,osv,ghsa}.py`. Eliminates the lazy-import detour, completes the abstraction the codebase advertised in three docstrings.
2. **OOP-001** — Stop passing raw ORM rows across module boundaries. Introduces typed DTOs at the repository ↔ service boundary; cuts the `__dict__`-copy hack in `routers/runs.py`.
3. **OOP-007** + YAGNI overlap — Either wire `app/ports/` into services or delete it along with `app/repositories/`. The Protocols are decorative as written.

The hexagonal sub-app `app/nvd_mirror/` is a positive counter-example and should be the model for the rest of the backend.
