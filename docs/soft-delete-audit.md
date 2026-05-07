# Soft-delete refactor — Phase 1 audit

**PR 2 of 3 in the soft-delete sequence.** Read-only inventory; no code changes. Every section maps a question from the prompt (§3 Phase 1) to concrete file/line evidence in the current tree (head migration `013_reclassify_unvalidated_sbom_source`).

---

## 1.1 Model inventory

The codebase keeps every ORM model in a single file: [app/models.py](app/models.py) (603 lines). 19 model classes total. Each row below names the class, its table, whether it currently has any soft-delete column, what FKs point IN, what FKs point OUT, and the cascade verdict.

`Notes` legend:
- **Soft (root)** = ownership root; user-facing delete must soft-delete
- **Soft (cascade child)** = soft-deleted by parent traversal
- **Hard (cache)** = derived/TTL data; hard-delete only, never tombstoned
- **Hard (audit/append-only)** = retention surface; cascade stops here
- **Hard (security)** = credentials / secrets; tombstoning is unsafe
- **Hard (reference)** = global reference data refreshed on a schedule

| # | Model | Table | File:line | Existing soft-delete? | FK IN (children) | FK OUT (parents) | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | `Projects` | `projects` | [models.py:21](app/models.py#L21) | `project_status` int (1=active/0=inactive) — partial precedent, not used in queries | `SBOMSource.projectid`, `AnalysisRun.project_id`, `AnalysisSchedule.project_id` (CASCADE) | — | **Soft (root)** |
| 2 | `SBOMType` | `sbom_type` | [models.py:37](app/models.py#L37) | None | `SBOMSource.sbom_type` | — | **Hard (reference)** — admin-managed lookup table |
| 3 | `SBOMSource` | `sbom_source` | [models.py:51](app/models.py#L51) | None | `SBOMAnalysisReport.sbom_ref_id`, `SBOMComponent.sbom_id`, `AnalysisRun.sbom_id`, `AnalysisSchedule.sbom_id` (CASCADE) | `projects.id`, `sbom_type.id` | **Soft (cascade child of Projects)** |
| 4 | `SBOMAnalysisReport` | `sbom_analysis_report` | [models.py:90](app/models.py#L90) | None | — | `sbom_source.id` | **Soft (cascade child of SBOMSource)** — vestigial table, but referenced by [sboms_crud.py:704](app/routers/sboms_crud.py#L704) hard-delete and the `SBOMSource.analysis_reports` relationship |
| 5 | `SBOMComponent` | `sbom_component` | [models.py:105](app/models.py#L105) | None | `AnalysisFinding.component_id` | `sbom_source.id` | **Soft (cascade child of SBOMSource)** |
| 6 | `AnalysisRun` | `analysis_run` | [models.py:137](app/models.py#L137) | None | `AnalysisFinding.analysis_run_id`, `AnalysisSchedule.last_run_id` (SET NULL), `AiFixBatch.run_id` (CASCADE) | `sbom_source.id`, `projects.id` | **Soft (cascade child of SBOMSource)** |
| 7 | `AnalysisFinding` | `analysis_finding` | [models.py:170](app/models.py#L170) | None | — | `analysis_run.id`, `sbom_component.id` | **Soft (cascade child of AnalysisRun)** |
| 8 | `RunCache` | `run_cache` | [models.py:206](app/models.py#L206) | None | — | (none — `sbom_id` is non-FK) | **Hard (cache)** — ad-hoc analyzer payload cache; reconstructable from `AnalysisRun + findings` per [pdf_service.py:35-41](app/services/pdf_service.py#L35-L41) |
| 9 | `KevEntry` | `kev_entry` | [models.py:222](app/models.py#L222) | None | — | — | **Hard (reference)** — refreshed every 24h from CISA |
| 10 | `AnalysisSchedule` | `analysis_schedule` | [models.py:246](app/models.py#L246) | `enabled` bool (toggle, not soft-delete) | — | `projects.id` (CASCADE), `sbom_source.id` (CASCADE), `analysis_run.id` (SET NULL) | **Soft (cascade child of Projects/SBOMSource)** |
| 11 | `EpssScore` | `epss_score` | [models.py:311](app/models.py#L311) | None | — | — | **Hard (reference)** — TTL-managed FIRST.org cache |
| 12 | `CveCache` | `cve_cache` | [models.py:332](app/models.py#L332) | None | — | — | **Hard (cache)** — TTL-managed CVE detail cache |
| 13 | `CompareCache` | `compare_cache` | [models.py:354](app/models.py#L354) | None | — | (`run_a_id`, `run_b_id` are not FKs) | **Hard (cache)** — see §1.4 open question |
| 14 | `AiUsageLog` | `ai_usage_log` | [models.py:375](app/models.py#L375) | None | — | — | **Hard (audit/append-only)** — cascade STOPS |
| 15 | `AiProviderConfig` | `ai_provider_config` | [models.py:402](app/models.py#L402) | `enabled` (nullable bool) | — | — | **Hard (settings)** — singleton overrides |
| 16 | `AiFixCache` | `ai_fix_cache` | [models.py:425](app/models.py#L425) | None | — | — | **Hard (cache)** — explicitly EXCLUDED from cascade per prompt §2; tenant-shared |
| 17 | `AiFixBatch` | `ai_fix_batch` | [models.py:473](app/models.py#L473) | None | — | `analysis_run.id` (CASCADE) | **Soft (cascade child of AnalysisRun)** — see open question §6 |
| 18 | `AiProviderCredential` | `ai_provider_credential` | [models.py:519](app/models.py#L519) | `enabled` (toggle) | — | — | **Hard (security)** per prompt §2; encrypted secret material |
| 19 | `AiSettings` | `ai_settings` | [models.py:560](app/models.py#L560) | `feature_enabled`, `kill_switch_active` | — | — | **Singleton, never deleted** |
| 20 | `AiCredentialAuditLog` | `ai_credential_audit_log` | [models.py:585](app/models.py#L585) | None | — | — | **Hard (audit/append-only)** — cascade STOPS |

**`SoftDeleteMixin` targets (in scope, get `is_active` + `deactivated_at` + `deactivated_by_user_id`):**
`Projects`, `SBOMSource`, `SBOMAnalysisReport`, `SBOMComponent`, `AnalysisRun`, `AnalysisFinding`, `AnalysisSchedule`, `AiFixBatch` — **8 tables**.

**Ownership tree (cascade walk):**

```
Projects (root)
├── SBOMSource
│   ├── SBOMAnalysisReport
│   ├── SBOMComponent
│   └── AnalysisRun
│       ├── AnalysisFinding
│       └── AiFixBatch
└── AnalysisSchedule (project-scope)
    └── (also targets SBOMSource, scope='SBOM')
```

Note: `AnalysisSchedule` is reachable from BOTH `Projects` (when `scope='PROJECT'`) and `SBOMSource` (when `scope='SBOM'`), enforced by [models.py:294-297](app/models.py#L294-L297) `ck_analysis_schedule_target`. The cascade walker must follow both relationships.

**`CASCADE_EXCLUDED_TABLES` (cascade STOPS):**
`ai_fix_cache`, `ai_usage_log`, `ai_credential_audit_log`, `ai_provider_credential`, `ai_provider_config`, `ai_settings`, `run_cache`, `kev_entry`, `epss_score`, `cve_cache`, `compare_cache`, `sbom_type`.

There is no `user` table — auth is currently a header-trusted `created_by` string. The mixin's `deactivated_by_user_id INTEGER REFERENCES "user"(id)` from prompt §2.1 cannot be implemented as written. **See §6 open question.**

---

## 1.2 Existing delete code paths

Five DELETE endpoints; one cascading service-level invalidate; three cache-row evictions:

| File:line | What | Currently does | Verdict |
|---|---|---|---|
| [projects.py:148-183](app/routers/projects.py#L148-L183) | `DELETE /projects/{project_id}` | Refuses if SBOMs/runs exist (409). Otherwise hard-deletes. | **Convert to soft** — also remove the 409 guard, since soft-delete is the cascade |
| [sboms_crud.py:657-727](app/routers/sboms_crud.py#L657-L727) | `DELETE /sboms/{sbom_id}` | Hard-deletes findings → runs → components → reports → SBOM in a single transaction | **Convert to soft** — replace explicit cascade with `SoftDeleteService.soft_delete(sbom)` |
| [schedules.py:250-263](app/routers/schedules.py#L250-L263) | `DELETE /projects/{project_id}/schedule` | Hard-deletes the `AnalysisSchedule` row | **Convert to soft** |
| [schedules.py:361-374](app/routers/schedules.py#L361-L374) | `DELETE /sboms/{sbom_id}/schedule` | Hard-deletes the SBOM-scope override | **Convert to soft** |
| [ai_credentials.py:456-479](app/routers/ai_credentials.py#L456-L479) | `DELETE /credentials/{cred_id}` | Hard-deletes; writes to `ai_credential_audit_log` | **Keep hard** per prompt §4 |
| [compare_service.py:202-223](app/services/compare_service.py#L202-L223) `invalidate_for_run` | `CompareCache` row eviction | Called on re-run; hard-deletes affected cache rows | **Keep hard** — cache eviction, not user-facing delete |
| [compare_service.py:240-258](app/services/compare_service.py#L240-L258) `_read_cache` | Expired / corrupt CompareCache | Hard-delete on TTL expiry / decode error | **Keep hard** — internal cache hygiene |
| [compare.py:132](app/routers/compare.py#L132) | Corrupt CompareCache eviction | Hard-delete on decode failure during export | **Keep hard** |
| [kev.py:134](app/sources/kev.py#L134) | Stale KEV entry pruning | `KevEntry.cve_id.in_(stale)` bulk delete | **Keep hard** — reference-data refresh |
| [progress.py:389,392](app/ai/progress.py#L389-L392) | Redis key cleanup | Not DB; ignore | n/a |

**No SQL `DELETE FROM` literals in code** — every delete goes through the ORM. Good for the soft-delete intercept story.

**No "cleanup job"-style bulk deletes for tombstones** exist yet; auto-purge of old soft-deletes is explicitly out of scope per prompt §4.

---

## 1.3 Existing list query patterns

Every place reading a soft-delete-eligible model. Each must either inherit Phase 3.2's transparent filter (Option C) or call `query_active()`. The "needs filter?" column flags whether tombstones leaking would be a user-visible bug.

### `Projects`
| Site | Needs `is_active` filter? |
|---|---|
| [projects.py:105](app/routers/projects.py#L105) — list-all endpoint | **YES** |
| [projects.py:62](app/routers/projects.py#L62) — name uniqueness pre-check on create | **YES** — see §1.5 |
| [runs.py:168,214](app/routers/runs.py#L168) — name subquery for run table | YES (avoid showing names of deleted projects) |

### `SBOMSource`
| Site | Needs `is_active` filter? |
|---|---|
| [sboms_crud.py:384](app/routers/sboms_crud.py#L384) — name uniqueness pre-check on create | **YES** — see §1.5 |
| [sboms_crud.py:534](app/routers/sboms_crud.py#L534) — list endpoint | **YES** |
| [projects.py:164](app/routers/projects.py#L164) — child-existence guard before project delete | YES (will be removed when guard is removed) |
| [schedules.py:458](app/routers/schedules.py#L458) — schedule resolver | **YES** — don't run scheduled analysis on tombstoned SBOMs |
| [schedule_resolver.py:89](app/services/schedule_resolver.py#L89) — schedule cascade | **YES** |
| [analysis_service.py:320](app/services/analysis_service.py#L320) — periodic-analysis sweep | **YES** |
| [sbom_service.py:288](app/services/sbom_service.py#L288) — name lookup | YES |
| [dashboard_main.py:90](app/routers/dashboard_main.py#L90) — recent SBOMs widget | **YES** |
| [runs.py:85,164,210](app/routers/runs.py#L85) — name subqueries | YES |

### `SBOMComponent`
| Site | Needs `is_active` filter? |
|---|---|
| [sboms_crud.py:149](app/routers/sboms_crud.py#L149) — load existing during reupload | YES (only consider live components) |
| [sboms_crud.py:590](app/routers/sboms_crud.py#L590) — components list | **YES** |
| [compare_service.py:341,375](app/services/compare_service.py#L341) — purl/finding joins | YES |
| [grounding.py:233](app/ai/grounding.py#L233) — single-component lookup by id | NO (defensive — id+is_active in a `.get()` is fine to skip) |
| [sbom_service.py:132](app/services/sbom_service.py#L132) — reupload reconciliation | YES |

### `AnalysisRun`
| Site | Needs `is_active` filter? |
|---|---|
| [runs.py:88,172,218](app/routers/runs.py#L88) — list, paginated, recent | **YES** |
| [sbom.py:48](app/routers/sbom.py#L48) — runs for an SBOM | **YES** |
| [sboms_crud.py:688](app/routers/sboms_crud.py#L688) — run-id collection during SBOM hard-delete | YES (will be replaced by cascade) |
| [analysis_service.py:339](app/services/analysis_service.py#L339) — has-run probe | **YES** |
| [scheduled_analysis.py:64](app/workers/scheduled_analysis.py#L64) — worker loop | **YES** |
| [ai_fixes.py:247](app/routers/ai_fixes.py#L247) — fix endpoint guard | **YES** |
| [metrics/findings.py:230](app/metrics/findings.py#L230) — dashboard rollups | **YES** |

### `AnalysisFinding`
| Site | Needs `is_active` filter? |
|---|---|
| [runs.py:281,337](app/routers/runs.py#L281) — findings list per run | **YES** |
| [sbom.py:60](app/routers/sbom.py#L60) — findings per latest run | **YES** |
| [analysis.py:135,182,274](app/routers/analysis.py#L135) — diff & legacy ad-hoc | YES |
| [ai_fixes.py:570,787,842](app/routers/ai_fixes.py#L570) — AI fix workflows | **YES** — must NOT generate fixes for deleted findings |
| [ai/batch.py:280](app/ai/batch.py#L280), [ai/scope.py:106](app/ai/scope.py#L106) | YES |
| [cve_service.py:183](app/services/cve_service.py#L183) — CVE detail join | YES |
| [metrics/findings.py:53,85](app/metrics/findings.py#L53) — severity rollups | **YES** |
| [pdf.py:42](app/routers/pdf.py#L42), [pdf_service.py:117](app/services/pdf_service.py#L117) — PDF rendering (`db.query`) | YES |

### `AnalysisSchedule`
| Site | Needs `is_active` filter? |
|---|---|
| 11 sites in [schedules.py](app/routers/schedules.py) (lookup, list, upsert paths) | **YES** for list (line 392); upsert paths must NOT see tombstones (would re-resurrect by mistake) |
| [schedule_resolver.py:43,75,118,131](app/services/schedule_resolver.py#L43) — cascade resolution | **YES** |
| [scheduled_analysis.py:97](app/workers/scheduled_analysis.py#L97) — due-schedule loader | **YES** |

### `AiFixBatch` — **No list-by-batch-table queries surfaced in this audit.** The router reads via the progress store (Redis) plus a few targeted `db.get()` lookups. Will need a `select(AiFixBatch).where(run_id == ...)` pattern; soft-delete filter applies if/when added.

### Two legacy `db.query(...)` call sites
[pdf.py:42](app/routers/pdf.py#L42) and [pdf_service.py:117](app/services/pdf_service.py#L117) use the legacy `db.query()` (1.x style) rather than `select()`. The Phase 3.2 Option C event listener (`do_orm_execute` → `with_loader_criteria`) **does** intercept legacy `Query` objects as well — they execute through the same statement path — so these don't need to be migrated to `select()` for filtering to apply, but they should be tested explicitly.

---

## 1.4 FK constraint behavior

Migration grep + model declarations:

| Constraint | Source | Behavior | Effect on soft-delete |
|---|---|---|---|
| `analysis_schedule.project_id` → `projects.id` | [004_analysis_schedule.py:55](alembic/versions/004_analysis_schedule.py#L55), [models.py:259](app/models.py#L259) | `ON DELETE CASCADE` | Soft-delete: no DB-level cascade fires (no row removed). App-level cascade walker handles it. Hard-delete: existing CASCADE works unchanged. ✓ |
| `analysis_schedule.sbom_id` → `sbom_source.id` | [004_analysis_schedule.py:62](alembic/versions/004_analysis_schedule.py#L62), [models.py:260](app/models.py#L260) | `ON DELETE CASCADE` | Same as above. ✓ |
| `analysis_schedule.last_run_id` → `analysis_run.id` | [004_analysis_schedule.py:94](alembic/versions/004_analysis_schedule.py#L94), [models.py:274](app/models.py#L274) | `ON DELETE SET NULL` | Soft-delete: no DB action; the schedule keeps its `last_run_id` pointing at a tombstone. Loader logic must filter via `is_active` when joining. **Note for Phase 3.** |
| `ai_fix_batch.run_id` → `analysis_run.id` | [011_ai_fix_batch.py:72](alembic/versions/011_ai_fix_batch.py#L72), [models.py:495](app/models.py#L495) | `ON DELETE CASCADE` | Same as project/sbom: app-level cascade walker handles soft. ✓ |
| All other FKs | [models.py](app/models.py) declarations only — no `ondelete=` in models, no migration-level `ON DELETE` clauses | Default `NO ACTION` | Hard-delete WILL fail with FK violation unless the application explicitly walks children first. The current SBOM hard-delete at [sboms_crud.py:687-710](app/routers/sboms_crud.py#L687-L710) does exactly that. After this refactor: soft-delete uses the new walker; hard-delete continues to use the explicit walker for SBOM. **Project hard-delete still relies on the 409 guard at [projects.py:169-172](app/routers/projects.py#L169-L172) which Phase 3 will remove.** Decision needed in §6. |

**No `ON DELETE RESTRICT` anywhere** — soft-delete won't be blocked by FK semantics.

**No `ON DELETE SET NULL` that points at a soft-deletable parent except `analysis_schedule.last_run_id`** — and that's only consulted on hard-delete, so it's fine.

---

## 1.5 Unique constraints that could conflict with tombstones

DB-level unique constraints on soft-delete-eligible tables:

| Table | Constraint | Source | Soft-delete impact | Mitigation |
|---|---|---|---|---|
| `sbom_component` | `uq_sbom_component_fingerprint` (`sbom_id`, `bom_ref`, `name`, `version`, `cpe`) | [models.py:124-132](app/models.py#L124-L132) | **No conflict in practice** — when an SBOM is soft-deleted its components are soft-deleted with it; an SBOM is never re-uploaded into the same row. New uploads create new SBOM rows. | None needed. |
| `analysis_finding` | `uq_analysis_finding_run_vuln_cpe` (`analysis_run_id`, `vuln_id`, `cpe`) | [models.py:201](app/models.py#L201) | **No conflict** — findings are tied to a specific run; a soft-deleted run is never re-populated. | None needed. |

**No DB-level conflict.** But there are two **application-level uniqueness checks** that WILL conflict:

| Table | Check | Source | Impact | Mitigation |
|---|---|---|---|---|
| `projects` | `db.query(Projects).filter(Projects.project_name == payload.project_name).first()` raises 409 if a row exists | [projects.py:62](app/routers/projects.py#L62) | After soft-delete, this still finds the tombstone and blocks re-creation with the same name | Add `Projects.is_active.is_(True)` to the filter (or rely on Phase 3.2 Option C transparent filter; the application check then naturally only sees live rows). |
| `sbom_source` | `db.execute(select(SBOMSource.id).where(SBOMSource.sbom_name == payload.sbom_name.strip())).first()` raises 409 | [sboms_crud.py:384](app/routers/sboms_crud.py#L384) | Same — tombstones block re-upload of the same name | Same mitigation. **Option C does this for free.** |

The prompt's Phase 2.3 partial-unique-index advice (`CREATE UNIQUE INDEX ... WHERE is_active = true`) is **not strictly needed** for this codebase because there are no DB-level uniques on user-facing names. But Option C transparent filtering DOES need to be relied upon to make the application-level checks correct. **Recommendation:** ship Option C and verify via test that soft-deleting a project allows re-creating one with the same name. Skip the partial-index migration unless §6 decides we want a defence-in-depth DB-level uniqueness for `project_name` / `sbom_name` (currently those are not even enforced uniqueness in the DB, only by application checks).

---

## 1.6 Frontend delete UX surfaces

Five surfaces, each using the shared [components/ui/Dialog.tsx](frontend/src/components/ui/Dialog.tsx)`ConfirmDialog` (lines 270-310):

| # | Surface | File:line | Type | Currently has "permanent" affordance? |
|---|---|---|---|---|
| 1 | Projects table | [components/projects/ProjectsTable.tsx:286-294](frontend/src/components/projects/ProjectsTable.tsx#L286-L294) | Project delete | No — single confirm |
| 2 | SBOMs table | [components/sboms/SbomsTable.tsx:405-413](frontend/src/components/sboms/SbomsTable.tsx#L405-L413) | SBOM delete | No |
| 3 | Schedule card | [components/schedules/ScheduleCard.tsx:312-323](frontend/src/components/schedules/ScheduleCard.tsx#L312-L323) | Schedule remove | No |
| 4 | Schedules page (table view) | [app/schedules/page.tsx:414-425](frontend/src/app/schedules/page.tsx#L414-L425) | Schedule remove | No |
| 5 | AI provider credential card | [components/settings/ai/ProvidersList/ProviderCard.tsx:222-253](frontend/src/components/settings/ai/ProvidersList/ProviderCard.tsx#L222-L253) | Credential delete | **Already has typed-name confirmation** (lines 227-233, 247-251) — the only one with the pattern Phase 4 spreads everywhere. Stays HARD (security). |

**Phase 4 work** = update `ConfirmDialog` (or wrap it in a new `DeleteConfirmDialog` to keep `ConfirmDialog` minimal) to expose the radio-select pattern, then thread surfaces 1-4 through. Surface 5 stays unchanged (always permanent).

**Frontend API client functions in [frontend/src/lib/api.ts](frontend/src/lib/api.ts):**
- `deleteProject(id)` — line 289
- `deleteSbom(id, userId)` — line 326
- `deleteProjectSchedule(projectId)` — line 782
- `deleteSbomSchedule(sbomId)` — line 817
- `deleteAiCredential(id)` — line 1117 (`/api/v1/ai/credentials/`)

Each will need a `permanent?: boolean` arg threaded into the URL as `?permanent=true`.

A new `getProjectDeleteImpact(id)` / `getSbomDeleteImpact(id)` etc. function is needed for the cascade pre-flight (Phase 4.2).

---

## 1.7 Audit log writers

Two distinct audit surfaces today:

1. **[ai_credential_audit.py](app/ai/credential_audit.py) → `ai_credential_audit_log`.** Writes only credential / settings mutations. Strict redaction at [credential_audit.py:84-101](app/ai/credential_audit.py#L84-L101). Errors are swallowed (`commit; except → log warning + rollback`). Used by [ai_credentials.py:443-450](app/ai/credentials.py#L443) (update), [ai_credentials.py:470-478](app/ai/credentials.py#L470-L478) (delete), and several toggle endpoints.
2. **[ai/observability.py:31, 295-301](app/ai/observability.py#L295-L301) → `audit_log` Python logger.** Stdout/JSON structured logs only — not a DB table. Tracks AI calls.

**There is no general-purpose audit log table for project / SBOM / run / schedule deletes today.** The SBOM hard-delete at [sboms_crud.py:719](app/routers/sboms_crud.py#L719) only logs to the Python logger on failure (`log.exception`). No durable audit row is written.

This is a **gap that the prompt's success-criteria assumes is filled**. Two options for Phase 3:

- **(A) Reuse `ai_credential_audit_log`** — repurpose the table for all audit events. Reasonable since the existing schema (`user_id`, `action`, `target_kind`, `target_id`, `detail`) already generalises. Rename to `audit_log` via a migration. Requires care — three of the prompt's `CASCADE_EXCLUDED_TABLES` reference `audit_log` by that name, so this aligns.
- **(B) Add a new `audit_log` table** alongside the existing one and leave credentials in their dedicated table.

**Recommendation:** **(A)** — single audit table, action vocabulary expanded with `project.soft_delete`, `project.permanent_delete`, `sbom.soft_delete`, etc. Keep the redaction helper in place.

---

## 6. Open questions (raised inline; collected here)

1. **`SoftDeleteMixin.deactivated_by_user_id` cannot reference a `user(id)` table because there is none.** Auth today is a header-trusted `created_by` string. Three options:
   - **(a) Use `String` instead of `Integer FK`** — name it `deactivated_by` to match `created_by`/`modified_by` pattern. **My recommendation** — matches existing identity model; deferred until a real users table exists.
   - **(b) Drop the column entirely; rely on the audit log row to record who.** Smaller schema; but loses the "self-describing tombstone" property.
   - **(c) Add a `user` table as part of this PR.** Out of scope.
   - **Need direction.**
2. **`CompareCache` cascade behavior on soft-delete.** Prompt says "Comparison → (no children)" implying it cascades. But `CompareCache` is a TTL-managed derived cache (no FK; keyed by hash of run-id pair) and it's already invalidated by `invalidate_for_run` when a run is reanalysed. Two options:
   - **(a) On run soft-delete, hard-delete CompareCache rows referencing that run** (same as re-run invalidation). Treat it like every other cache. **My recommendation.**
   - **(b) Cascade-soft-delete CompareCache rows** (adds the mixin to it). Doesn't add value — nobody queries tombstoned cache rows.
   - **Need direction.**
3. **`AiFixBatch` cascade.** Tied to `analysis_run` via FK CASCADE. Soft-deleting a run should hide its batches from the user's view. Adding `SoftDeleteMixin` makes the cascade walker pick it up automatically. **Default: in scope, gets the mixin.** Confirm.
4. **Project hard-delete guard.** [projects.py:169-172](app/routers/projects.py#L169-L172) refuses to hard-delete a project if SBOMs/runs exist. After Phase 3, soft-delete is the default — but for **permanent** delete with `?permanent=true`, should we:
   - **(a) Keep the guard** (force users to permanent-delete every SBOM first). Surprising UX.
   - **(b) Drop the guard and let the explicit ORM cascade fire** — same way the SBOM hard-delete already works ([sboms_crud.py:687-710](app/routers/sboms_crud.py#L687-L710)). **My recommendation.**
   - **Need direction.**
5. **Phase 3.2 default-filter mechanism.** Option C (event listener with `with_loader_criteria`) recommended. There is one wrinkle: two call sites use legacy `db.query(...)` ([pdf.py:42](app/routers/pdf.py#L42), [pdf_service.py:117](app/services/pdf_service.py#L117)). The `do_orm_execute` listener intercepts these too, but I want explicit test coverage at that boundary before declaring Option C safe. **Plan: write a smoke test in Phase 3 that covers both `select()` and `db.query()` paths and hard-fail if either leaks tombstones.**
6. **Audit log table strategy.** Recommend reusing `ai_credential_audit_log` and renaming to `audit_log`. Confirm.

---

## Phase 1 deliverable summary

- Models in scope for `SoftDeleteMixin`: **8** (Projects, SBOMSource, SBOMAnalysisReport, SBOMComponent, AnalysisRun, AnalysisFinding, AnalysisSchedule, AiFixBatch)
- `CASCADE_EXCLUDED_TABLES`: **12** (listed §1.1)
- DELETE endpoints to convert to soft: **4** (project, sbom, project-schedule, sbom-schedule)
- DELETE endpoints to keep hard: **1** (credentials, security)
- List query sites that must filter `is_active`: **~35** across routers/services/workers/metrics. Option C handles them transparently.
- DB-level unique conflicts: **0** (no real footgun in the schema)
- Application-level uniqueness checks that need attention: **2** (project name, SBOM name) — both fixed for free by Option C
- Frontend confirm-modal sites to update: **4** (projects, sboms, schedules×2)
- Audit-log gap: **YES** — no general-purpose audit table today; resolution needed (open Q6)
- Open questions: **6** — see §6

**Awaiting Phase 1 gate.** No code changes yet. Specifically need owner direction on Q1 (mixin user-id column shape), Q2 (CompareCache treatment), Q4 (project permanent-delete guard), Q6 (audit table strategy). Q3 and Q5 carry recommendations I'll proceed with unless told otherwise.
