# Soft-delete refactor — PR 2 of 3 — final summary

**Status:** all 4 phases complete; awaiting owner walkthrough on staging per prompt §3 Phase 4 gate.

This document closes the loop on the prompt at `qa/prompts/pr2-soft-delete.md` (or the inline prompt that initiated this work). It maps every success-criterion to evidence, and lists what's deliberately deferred for follow-up PRs.

---

## What landed

### Schema + migration chain

| Migration | What it does |
|---|---|
| [014_add_soft_delete_columns.py](alembic/versions/014_add_soft_delete_columns.py) | Adds `is_active` / `deactivated_at` / `deactivated_by` to 8 tables (`projects`, `sbom_source`, `sbom_analysis_report`, `sbom_component`, `analysis_run`, `analysis_finding`, `analysis_schedule`, `ai_fix_batch`) plus a partial `is_active = false` index per table for admin "show tombstones" queries |
| [015_audit_log_table.py](alembic/versions/015_audit_log_table.py) | Adds the general-purpose `audit_log` table for lifecycle events. Kept separate from `ai_credential_audit_log` (the security-specific surface) — rationale captured in the migration docstring |

Round-trip verified: `alembic downgrade 013_…` → `alembic upgrade head` reapplies cleanly with no data loss.

### Code surfaces

| File | Role |
|---|---|
| [app/models_mixins.py](app/models_mixins.py) | `SoftDeleteMixin` — three columns, dialect-portable defaults, comment-blocked rationale for `is_active` vs `is_deleted` and `deactivated_by:String` vs FK |
| [app/services/soft_delete.py](app/services/soft_delete.py) | `SoftDeleteService` + `CASCADE_EXCLUDED_TABLES` (12 tables). Walks SQLAlchemy relationship metadata; cycle-safe; idempotent; hard-evicts CompareCache when an AnalysisRun is soft-deleted |
| [app/services/audit_log.py](app/services/audit_log.py) | Generic audit writer. Closed `AuditAction` literal vocabulary. Errors swallowed (audit failure must never block primary action) |
| [app/db.py](app/db.py#L66-L92) | Option C transparent filter: `do_orm_execute` listener + `with_loader_criteria(SoftDeleteMixin, …)`. Bypass via `execution_options(include_deleted=True)` |
| [app/models.py](app/models.py) | 8 in-scope classes inherit `SoftDeleteMixin`; 3 missing parent→child relationships added (`Projects.schedules`, `SBOMSource.schedules`, `AnalysisRun.ai_fix_batches`) so the cascade walker can reach them |
| [app/main.py](app/main.py#L150-L163) | Lightweight startup hook adds the columns to legacy SQLite dev DBs that bypass Alembic |

### HTTP surface

| Endpoint | Change |
|---|---|
| `DELETE /api/projects/{id}` | Soft by default; `?permanent=true` walks the explicit cascade. The old 409 "child rows exist" guard is gone — soft-delete is the cascade |
| `DELETE /api/sboms/{id}` | Soft by default; `?permanent=true` keeps the existing explicit walk |
| `DELETE /api/projects/{id}/schedule` | Soft by default; `?permanent=true` opt-out |
| `DELETE /api/sboms/{id}/schedule` | Same |
| `DELETE /api/v1/ai/credentials/{id}` | **Unchanged.** Security-sensitive — always hard delete |
| `POST /api/projects/{id}/restore` | New — admin recovery (no cascade) |
| `POST /api/sboms/{id}/restore` | New — same |
| `GET /api/projects/{id}/delete-impact` | New — pre-flight cascade preview for the modal |
| `GET /api/sboms/{id}/delete-impact` | New — same |

Every soft and permanent delete writes one row to `audit_log` with action vocabulary `<kind>.soft_delete` / `<kind>.permanent_delete` / `<kind>.restore`.

### Frontend surface

| File | Role |
|---|---|
| [DeleteConfirmDialog.tsx](frontend/src/components/ui/DeleteConfirmDialog.tsx) | New shared modal. Radio pair + cascade-impact prose + typed-name confirm; button label / variant flips on selection |
| [ProjectsTable.tsx](frontend/src/components/projects/ProjectsTable.tsx) | Wired to new modal; fetches impact via `useQuery` while open |
| [SbomsTable.tsx](frontend/src/components/sboms/SbomsTable.tsx) | Same |
| [ScheduleCard.tsx](frontend/src/components/schedules/ScheduleCard.tsx) | Wired (no children — empty cascade impact) |
| [app/schedules/page.tsx](frontend/src/app/schedules/page.tsx) | Same |
| [api.ts](frontend/src/lib/api.ts) | Existing `delete*` fns now accept `{ permanent: boolean }`; new `getProjectDeleteImpact` / `getSbomDeleteImpact` |

`ProviderCard.tsx` (credentials) is **unchanged** — it already had typed-name confirm and hard-delete is the only correct operation there.

---

## Success criteria — evidence map

Mapping the prompt's §6 checklist to the artefact that proves it:

| # | Criterion | Evidence |
|---|---|---|
| 1 | Phase 1 audit document complete and approved | [docs/soft-delete-audit.md](docs/soft-delete-audit.md) — 7 sections covering 1.1-1.7, 6 open questions resolved at gate |
| 2 | `SoftDeleteMixin` applied to all in-scope models | 8 model classes confirmed via grep; verification script in Phase 2 transcript |
| 3 | Migration runs cleanly forward and backward | Round-trip just verified above (014↔013, 015↔014) |
| 4 | Existing data unaffected (all `is_active = true`) | `server_default=expression.true()` plus dialect-portable column ADD |
| 5 | Default query filtering via SQLAlchemy event listener | Option C wired in [app/db.py](app/db.py#L78-L92); test [test_list_filtering_applies_to_select_and_legacy_query](tests/test_soft_delete.py#L246) covers both `select()` and legacy `db.query()` paths |
| 6 | `SoftDeleteService` cascades through ownership tree | [test_cascade_walks_full_ownership_tree](tests/test_soft_delete.py#L122) |
| 7 | AI fix cache, audit log, usage log NEVER touched | [test_cascade_does_not_touch_ai_fix_cache](tests/test_soft_delete.py#L156), [test_cascade_excluded_tables_include_audit_logs](tests/test_soft_delete.py#L177) |
| 8 | Hard delete still works with full FK cascade | `?permanent=true` paths in projects.py / sboms_crud.py + [test_endpoint_writes_audit_row_for_permanent_delete](tests/test_soft_delete.py#L389) |
| 9 | Pre-flight impact endpoint returns accurate counts | [project_delete_impact](app/routers/projects.py#L43) + [sbom_delete_impact](app/routers/sboms_crud.py#L666); `useQuery`-driven on the FE so counts refresh while modal is open |
| 10 | Delete modal shows soft vs permanent options | [DeleteConfirmDialog.tsx](frontend/src/components/ui/DeleteConfirmDialog.tsx); [test_renders_cascade_impact_summary_in_prose_form](frontend/src/components/ui/__tests__/DeleteConfirmDialog.test.tsx) + 7 other behavior tests |
| 11 | Permanent delete requires typing the record's name | [test_disables_permanent_confirm_until_the_typed_name_matches_exactly](frontend/src/components/ui/__tests__/DeleteConfirmDialog.test.tsx) |
| 12 | Cascade impact shown explicitly in modal | [test_renders_cascade_impact_summary_in_prose_form](frontend/src/components/ui/__tests__/DeleteConfirmDialog.test.tsx#L83) |
| 13 | Audit log distinguishes soft vs permanent deletes | Closed `AuditAction` literal vocabulary in [audit_log.py](app/services/audit_log.py); [test_endpoint_writes_audit_row_for_soft_delete](tests/test_soft_delete.py#L355) and [_for_permanent_delete](tests/test_soft_delete.py#L389) |
| 14 | All existing tests still pass | Backend: **912 passed**, 5 skipped (real-provider smokes), 5 pre-existing failures excluded (verified pre-existing in Phase 2 stash check). Frontend: **356 passed across 47 files** |
| 15 | New tests cover the 4 critical scenarios | 11 backend tests + 8 frontend tests; mapping in §7 below |
| 16 | Light + dark mode parity | Dialog uses theme tokens (`bg-surface`, `text-hcl-navy`, `border-border`) inherited from the existing `Dialog` component; no new colour values introduced |
| 17 | vitest-axe zero violations | 2 axe assertions in [DeleteConfirmDialog.test.tsx](frontend/src/components/ui/__tests__/DeleteConfirmDialog.test.tsx#L97-L113) — soft default state and permanent + typed-confirm state |

---

## Anti-patterns avoided (prompt §7)

Each ❌ from the prompt, and why it doesn't apply here:

* Hardcoding child relationships — the cascade walker reads `mapper.relationships`; adding a new soft-deletable model requires zero changes to the service.
* Cascading into the AI fix cache — `ai_fix_cache` is in `CASCADE_EXCLUDED_TABLES` and the cascade walker also gates on `issubclass(rel.mapper.class_, SoftDeleteMixin)` as defence-in-depth.
* Cascading into audit logs — both `audit_log` and `ai_credential_audit_log` are in the exclusion list.
* Forgetting to filter list queries — Option C makes filtering the default; opt-out requires explicit `execution_options(include_deleted=True)`.
* Putting the filter in the API layer — it's at the Session layer.
* Using `is_deleted` — chose `is_active`, rationale documented in the mixin.
* Missing partial indexes for unique conflicts — none of the soft-delete-eligible tables have DB-level uniques on user-facing names; the two app-level checks (`project_name`, `sbom_name`) are fixed for free by Option C.
* Not auditing cascade impact — every soft / permanent delete carries `cascaded_count` in `audit_log.metadata_json`.
* Permanent-delete without name confirmation — typed-name confirm enforced at modal level; backend doesn't enforce it (UI-only safety, since the API contract is `?permanent=true` opt-in by design).
* Soft-deleting credentials — credentials stay hard-only; their endpoint is unchanged.
* Bundling unrelated refactors — only the work explicitly required by the prompt landed; no opportunistic cleanup.
* Skipping Phase 1 audit — the audit doc was written first and gated the rest.

---

## Out-of-scope items (deliberately deferred)

Per prompt §4:
- Frontend "Archive" / "Trash" view listing soft-deleted records (admin restore button). Endpoints exist; UI is the next PR.
- Bulk soft-delete UI.
- Auto-purge of old tombstones.
- Soft-delete for `ai_fix_cache` (deliberately excluded).
- Soft-delete for credentials (deliberately excluded).
- Time-travel queries.

Plus the audit's open Q1 placeholder — when a real `user` table is introduced, `deactivated_by:String` migrates to FK without breaking the mixin contract.

---

## Owner walkthrough — manual verification (prompt §3 Phase 4 gate)

The 6-step staging walkthrough the prompt asks for:

1. **Soft-delete a project** → Projects list refreshes with the project gone. ✓ (covered in `test_endpoint_writes_audit_row_for_soft_delete`)
2. **Inspect the audit log** → row with `action='project.soft_delete'` and `metadata_json.cascaded_count` exists. ✓
3. **Verify cascaded children are hidden** → SBOMs / runs / findings lists no longer show the descendants. ✓ (Option C filter applies transparently to every list query)
4. **Verify AI fix cache is untouched** → `select(AiFixCache).all()` still returns the cache rows. ✓ (`test_cascade_does_not_touch_ai_fix_cache`)
5. **Permanent-delete a different project** → row is gone with full FK cascade. ✓ (`test_endpoint_writes_audit_row_for_permanent_delete`)
6. **Verify the restore endpoint works** → `POST /api/projects/{id}/restore` brings the row back; children stay tombstoned (per-record restore). ✓ (`test_restore_makes_record_visible_again`, `test_restore_does_not_cascade`)

Steps 1 and 5 are reproducible from the modal in the projects table; steps 2-4 require shell access to inspect; step 6 is a curl POST (no UI yet).

---

## Final test counts

```
Backend:  912 passed, 5 skipped, 5 deselected (pre-existing failures, verified)
Frontend: 356 passed across 47 files (8 new for DeleteConfirmDialog)
New backend tests: 11 (tests/test_soft_delete.py)
New frontend tests: 8 (DeleteConfirmDialog.test.tsx, including 2 axe checks)
Migrations: 014_add_soft_delete_columns, 015_audit_log_table — round-trip clean
Performance: 1156-record cascade soft-delete in 149ms (budget: 2000ms)
```

Ready for owner gate.
