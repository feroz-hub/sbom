# W2.4A — F infrastructure and live-adapter preparation

**IMPLEMENTED (STAGED) / OFFLINE VERIFIED — 2026-10-19.** Thirteen new isolated artifacts, including nine Python sources/tests, an offline Compose proposal, pending approval template and runtime checklist. **426 offline tests PASS / 0 FAIL / 0 SKIP**: 126 new plus all300 selected existing tests. Live CLI remains unconditionally denied. No existing W2.1/W2.2/W2.3 source, package, lock, migration or application source was edited.

F NOT CREATED; frozen047 NOT RUNTIME ACCEPTED; all193 live integrity cases NOT EXECUTED. PostgreSQL connections/SQL execution, Docker commands/inspection, real credential reads, provisioning, migration/promotion, application startup and Git delivery: **zero**. Resource names/ports/capacity are proposals, not freshly verified availability. Historical D/E states and all previous failures remain historical evidence.

## Authority, prerequisites and preservation

Operator authorization is OFFLINE implementation/source review/testing/reporting only. Required branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac` verified. Snapshotted2,148 tracked/untracked nonignored existing files before implementation; tracker prerequisites/authority/acceptance/STOP were appended before source edits.

Read tracker, reports28–30, actual coordinator/authority/loader/observations/discovery/budget/lock and relevant bootstrap/finalization/compiler sources. Verified original W2.3 package byte SHA256 `cd15fbb1788fe8ac3099988b856f377fde3f3b4366f88395475a13063731a28b`, every11 embedded file hash, source lock `f6fe5d0a823d7af3b91dd6716dad62d2d43a90c83f9f4186227af343e5e9c83f`, all113 pinned inputs,91linear revisions and45scheduled units. Original W2.1 package7b524fd8484116a4190b4dfeb98edb7324bdca38b1ddd4989b5f13a236080b34/W2.2 package6112f88448ddc14d4959fd504311978bc4d3ec0de8930b3cb587dc7aeb1b5196 also verified unchanged. Active graph remains79revisions/head079; staged080–091 remain outside active discovery. No silently renewed approval or source repin.

## New source and exact hashes

Directory: [F activation preparation](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/README.md). All are new; full source and complete new-file unified diffs are included in the protected package.

|File|SHA256|
|---|---|
|[README.md](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/README.md)|`97e122f6b5e068469907205b03621b97c106a84755a94e67ddbb45f0f0dfd18a`|
|[activation.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/activation.py)|`4220022093bbd745635c263b779edaf84a450102b30b7e5087cb2e6dae0cb4a4`|
|[approval.pending.json](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/approval.pending.json)|`c31d3ba492bebcfc0caedfd3325b0b62515119db3977a749303e43a18f6f9fdd`|
|[binding.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/binding.py)|`7291256edd00ccbc7c5c8fbd2b94b04ad19f8bb0d0f5fc7c75be4ed13a88e13b`|
|[catalog.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/catalog.py)|`43071bba645d6f96c2935fd59f0163870f96042ff8ad5843827518652f496647`|
|[compose.f.proposed.yml](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/compose.f.proposed.yml)|`37af79b078078191a13c957f88ac31339362c5f683c8647b92959c5797def51c`|
|[journal.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/journal.py)|`e9fb8a23848e6db18a299456f1cbb957d1ef4e485e079ed5851e409ec308617c`|
|[resources.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/resources.py)|`591f88ced4524b1139728eb4bdef3f2a0732a260072cad56304bef392f95c0a2`|
|[reviewed.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/reviewed.py)|`cfba541dfe694b7c3360cc91e253b9a56a84de83006358b20e1530bf2f5bd6e0`|
|[runtime-checklist.md](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/runtime-checklist.md)|`27f0a398de08d6daf6ace5bf56a09ac99dd1ba062d34dabb3060d53d30e1068c`|
|[security.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/security.py)|`be6f0df8c664431f54a65800761c6e52e2525ad10a084ccaa5ce3f3eb1ae46c8`|
|[test_activation_offline.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/test_activation_offline.py)|`34ba10431e9a0c8faa7f2f4b345b70b4f274810e1b35beb61f9c1d14de1e0877`|
|[transport.py](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/transport.py)|`54acca5024ad5be239687ccfd00070cd5902d6e9ecd488f41cc22b426076d234`|

`reviewed.py` loads four exact-pinned inert W2.3 libraries with controlled imports; uses pure discovery/framing/source/observation functions only. It does not call the old mock coordinator or mock-only Operations binding with real adapters. The old source and type guards remain unchanged.

`resources.py` normalizes independently supplied Docker info/inspect/volume/network data, exact daemon/socket/container/image/start/labels/attachment/publication/storage identities and exclusive volume use. `security.py` checks actual normalized resource limits/startup/network state and provenance, then performs injected host/container byte equality. Descriptor-safe host reading checks O_NOFOLLOW, regular/single-link owner/mode/inode/size/timestamps before/after, private parent and all symlink path components. Only exact F host source or that same source's verified Docker Desktop /host_mnt representation is eligible; read-only bind/cardinality/destination enforced. Equality yields boolean provenance, never a secret hash; mutable buffers are erased, subject to explicitly documented Python/driver internal-copy limitations. No default Docker runner, mounted-secret runner, OS reader or CLI provider is activated.

## Manifest, connection and authentication boundaries

The new strict wrapper binds its original raw byte SHA256 and separately labeled canonical digest, the original private W2.3 unit manifest path/raw hash, all new source/configuration/document hashes and installed SQLAlchemy/Alembic/psycopg distribution-file/version pins. Private0700parent/0600regular single-link nonsymlink files, duplicate-key rejection, current UTC expiry, exact distinct action references and seven pending integrity flags remain mandatory. Reopen/reparse the same bytes and reject in-memory plan differences before authentication and at locked/prebody/premarker/precommit boundaries; recheck source/dependencies/target/budgets/security. Wrapper expiry cannot extend original unit expiry. Pending template has acceptedfalse/empty actions, null original manifest/connection/expiry, empty source pins, sevenfalse integrity flags and empty integrity actions. It cannot authenticate.

Future actions remain distinct `unit_validate`, `unit_execute`, `unit_readback`; no actual references were created. Original W2.3 authority supplies independently reviewed roles/ownership/ACL/reference-data/security/network/credential/source/prefix/postcondition evidence and new actual F identity. No manifest flag or mock receipt alone proves an observation. Installed file pinning does not prove loaded native libpq/optional binary backend/OS library origins; source-specific activation must resolve that gap.

The explicit **new transport proposal** is driver `autocommit=True`, dedicated SQLAlchemy AUTOCOMMIT/NullPool/skip_autocommit_rollback/no pool reset, with literal metered owned READ ONLY BEGIN/ROLLBACK followed by one READ WRITE BEGIN/COMMIT. The database unit is atomic inside that explicit transaction. This differs from W2.3's mocked constructor, is separately represented in the new wrapper and requires independent approval. W2.3's original constructor/authority was not modified or treated as approval for this change.

Fixed host+hostaddr127.0.0.1/port56043/DBuuid_w2_f_fresh/useruuid_w2_f_bootstrap; passfile/dev/null; service absent; SSL/GSS disable; connect5s; default_transaction_read_onlyon, row_securityon, search_pathpg_catalog and exact original per-unit statement/lock/idle settings. New application names distinguish unit/readback. Actual future process environment must be explicitly clean; PG*, DATABASE_URL/PYTHONPATH/Docker override environments refuse, not merely a filtered-dictionary assertion. No fallback endpoints/retries.

HBA evidence is current-file parse/content evidence, not proof of last-loaded effective rules. Supplying a password and connecting is not proof it was required. Effective password-authentication remains UNKNOWN unless separately independently reviewed proof bound to exact F identity/resources is accepted; inability to establish it is blocking. No extra connection/reload/correction is introduced.

## Metering, Operations and transaction evidence

The proxy attaches at the DBAPI cursor before SQLAlchemy dialect initialization. Only that boundary reserves SQL executions: logical wrappers do not count again. Reflection SELECT/SHOW consumes query quota even under an upgrade. Reviewed SQL framing requires one statement per call, an exact separately reviewed driver-SQL hash/category, bounded materialized executemany rows and no unowned controls or mutation outside owned transaction. Counts are conservative reserved executions, not a claim every reservation reached PostgreSQL. No wildcards or automatic SQL allowlist learning.

New binding independently configures MigrationContext/Operations against the one dedicated PostgreSQL/public-dialect connection, transactional_ddltrue/as_sqlfalse. Tests cover real compiler-context configuration against a mocked connection, injected factories and all44eligible source namespaces without upgrades. The new loader preserves historical function bodies and exact048/064frozen alternatives; prohibits001/app/env/globalproxy/settings/helper imports. SQLAlchemy reflection/driver initialization compatibility remains unverified live. Historical schema resolution uses the dedicated public default schema and reviewed transaction-local path, never a shared app dialect.

Each attempt claims an O_EXCL0600journal in its0700per-unit directory, fsyncs file/directory and records a bounded hash chain with UTC phase/class/SQLSTATE evidence, no SQL text/parameters/passwords. Claim reuse fails even with changed manifest/action; future process ownership/reconciliation must also prevent attempts through a different directory. Durable evidence failure before mutation prevents it. Cleanup rollback still operates after deadline or journal failure; reserved control quota prevents extra transactions.

Staged write lifecycle: authority/resources then immediate revalidation; one owned connection; ROcatalog preflight/ROLLBACK; RWBEGIN/advisory7160085085/versionEXCLUSIVE NOWAIT/ordinary-tableSHARE NOWAIT; actual locked schema/security/reference/identity/writer recheck; one body; expected post-schema with actual old marker; one parameterized INSERT/UPDATE RETURNINGnext/sole marker; authority recheck, durable intent, COMMIT acknowledgment, physical driver close and engine disposal. Frozen047 creates version table only after558schema statements acknowledge and records047 only after post-schema checks; later bodies never replay prior revisions.

Known precommit failure rolls back/closes and remains unverified pending reconciliation. Unknown COMMIT stops without guessed rollback/retry/repair. Known COMMIT with journal failure remains committed/evidence incomplete, never falsely rolled back. Closure/evidence failure blocks acceptance. Returned writes are COMMITTED_UNVERIFIED/acceptedfalse. Separate unit_readback requires a new readonly connection with post-prefix/revision/security/reference checks, ROLLBACK and close/dispose; it observes state rather than inventing historical execution provenance. No production/live acceptance path was activated.

## F Compose and frozen047 runtime readiness

[Compose proposal](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/compose.f.proposed.yml) parsed offline with PyYAML only; no Docker render or interpolation occurred. Names: project sbom-uuid-w2-f/service postgres_f/database uuid_w2_f_fresh/user uuid_w2_f_bootstrap; loopback127.0.0.1:56043:5432; dedicated sbom-uuid-w2-f_f_pgdata volume and sbom-uuid-w2-f_f_access network. Image requires a separately approved locally present16.15image ID through an explicit future input; pull_policynever/no build/restartno/no app or D/E attachment.

Limits:1CPU/512MiB/64MiBshm/128PIDs, max_connections12/shared_buffers64MiB/work_mem4MiB, default statement30s/lock1s/idle30s (unit-specific tighter settings retained), SCRAM host/local initialization and encryption. Secret file is only a proposed private F-only path; no credential created. Standard image bootstrap role privilege and PGDATA OS ownership need explicit independent review. Healthcheck readiness is not authentication/identity. Ordinary NAT bridge outbound connectivity is possible; ICCfalse/loopback are not zero-egress. This risk requires independent approval; no exposure enlarged or provisioned.

[Detailed runtime checklist](/Users/ferozebasha/sbom/infra/uuid-migration/f-activation/runtime-checklist.md) covers source review, collision/capacity/preservation, locally pinned image, fresh credentials/owners, first separately approved readonly identity/auth/freshness observation, exact047source/object/ACL/extension/lock/timeout/marker acceptance and each later45-unit boundary. Actual F cluster/DBOID/IP/IDs are UNKNOWN; no existing D/E identity was reused.

Frozen original e310421b5fea4ef93056be590756125726280671589b50d93aa85926b9833c09/proposed6173c58cca7061483edd1b69e9edd0c431eee808f46ae1021293549d13e8c900/transformation69d6a2bc019bbd991dcfe3b269938992be7d516e0cd9277381859f503ac63ce7 unchanged.558statements=12directives+546object statements:45tables,34sequences,34OWNEDBY,162ALTERTABLE,266indexes+5unique indexes.271explicit index statements are not total physical indexes: constraint-created indexes must be accepted too. OriginalPG14.18→16.15 grammar/semantic equivalence NOT established. No rows/sequence positions/credentials imported. Reference authorization data after048/064–068/075 and secure Native Login enrollment dependencies remain essential; no automatic admin/tenant/password/membership/grant.

## Offline results and development history

|Suite|PASS|FAIL|SKIP|
|---|---:|---:|---:|
|New W2.4A activation regressions|126|0|0|
|W2.3 coordinator|71|0|0|
|W2.1 bootstrap|102|0|0|
|W2.2 finalization|53|0|0|
|Expand runner|21|0|0|
|Integrity offline|53|0|0|
|Total|426|0|0|

Commands used `.venv/bin/python -B` for each test file; exact commands/outputs/hashes are protected. New command is in README; existing selected files are fresh-coordinator/test_coordinator_offline.py, fresh-bootstrap/test_fresh_bootstrap.py, finalization-tests/test_finalization_offline.py, staged-runner/test_expand_one_step.py and staged-runner/test_uuid_integrity_offline.py. These are not the193live cases.

118Python AST/in-memory compilations,113pins/91graph/45units,76SQLAlchemy template compilations and exact558statement framing PASS. Existing verify_offline.py PASS:42templates/14literal/18dynamic/six index-DDL compiles,79active+sixstaged expansion graph. It intentionally reports its own085expand head; new combined graph ends091 and activehead stays079. No SQL was sent to PostgreSQL. Nine new Python files Rufflint/format PASS; offline Compose parse/pending-template/whitespace/preservation PASS. Historical six080–085I001 import-order findings reconfirmed, sources unchanged; they are not new-code lint success or runtime blockers automatically waived.

Preserved development evidence: initial79tests72PASS/7ERROR from macOS /var synthetic path symlink; resolved fixture paths instead of weakening guards. Subsequent91/114/120/123/final126tests PASS. Initial124Ruff findings fixed only in new files through safe sorting/formatting/manual lambda rewrite. Initial shell wrapper appended redirection after here-doc terminator and caused a static-check Python SyntaxError before compilation; corrected standalone static checker PASS. Git fsmonitor emitted an initial daemon warning; subsequent read-only Git checks disabled fsmonitor. No Docker daemon command was involved. Later source review added exact in-memory/raw-byte consistency, owned transaction-control context, rollback budget preservation, descriptor checks and query-budget refusal regressions.

## Remaining execution blockers and next authorization

1. Full three-pass mature catalog collection needs at least318queries:3×(27catalog+71business-emptiness+identity+clients+locks+marker+4reference), before initialization/reflection/body queries. Original256-query rows therefore cannot support this recipe;512finalization quotas also need measurement. New meter refuses/rolls back at the limit. **No old limit/source lock was changed.** A separately reviewed new versioned per-unit budget/observation design is required before affected units activate.
2. Real IO/provider/clean-worker wiring and source-specific activation are absent. Exact driver SQL allowlists, native backend/libpq provenance, actual SQLAlchemy/psycopg wrapper/reset behavior, cooperative120s/fsync/statement/lock sufficiency and loaded authentication proof need review/runtime acceptance. No hard wall-clock guarantee is claimed.
3. F creation/identity/freshness/prefix/owner/ACL/reference approval and effective-auth evidence remain pending. First-F identity acceptance cannot reuse the unknown-ID unit template; it needs its own separately reviewed read-only scope.
4. PG16frozen047equivalence,048–079reflection/reference initialization/FK lock behavior, final UUID behavior,193live cases, DML/concurrency/recovery/performance/application/security integration remain NOT ACCEPTED.

Next: independently review this source package, including the explicit transport change and budget blocker. A subsequent narrowly separate authorization may cover fresh F infrastructure collision/capacity/daemon/image/credential/egress/preservation checks and provisioning only. First authenticated F read-only acceptance and any047execution are later independent boundaries; no automatic activation/provisioning/migration follows this task.

## Protected review package and STOP

[W2.4A complete source-review package](/Users/ferozebasha/.sbom-uuid-w2-review/w24a-20261019T032928881632Z/w24a-source-review-package.json)

- Original byte SHA256: `a426703bd57c74ba25a1cdddcfdd3223f7c4a2f29765a8814f639ab04991c277`.
- Review expiry: `2026-10-20T03:48:23.694094+00:00`. Review metadata only, not execution authority or renewal of any prior approval.
- Includes all13full files/diffs/hashes,113pins/91graph/45units, imported-library/distribution pins, frozen inventory/initialization/runtime contracts,426test results/development failures, infrastructure proposal and remaining blockers.
- acceptedfalse, all execution/integrity actions empty, seven integrity flagsfalse. No live approved manifest generated.

**STOP for independent source/package review. F NOT CREATED; frozen047 NOT RUNTIME ACCEPTED; all193live integrity cases NOT EXECUTED.**


Final W2.4A preservation: PASS. All2,147other contents from2,148existing tracked/untracked nonignored files remain unchanged; tracker is the sole existing-file append and retains its complete original bytes as prefix. Exactly14new files (13activation artifacts plus report31), no deleted baseline file. Required branch/HEAD, all earlier reports/packages/locks/history/staged080–091/W2.3 mock-only guards and active079 preserved. New package13source pins and0700/0600private modes verified; whitespace PASS.426selected offline tests PASS/0FAIL/0SKIP, zero live activity. Full source/report/tracker [change diff](/Users/ferozebasha/.sbom-uuid-w2-review/w24a-20261019T032928881632Z/w24a-complete-change.diff) and [final preservation evidence](/Users/ferozebasha/.sbom-uuid-w2-review/w24a-20261019T032928881632Z/final-evidence-manifest.json) retained. Source-review package remains a426703bd57c74ba25a1cdddcfdd3223f7c4a2f29765a8814f639ab04991c277. STOP independent review; query-budget/driver/auth/native/provider/runtime gates remain unresolved. F NOT CREATED,frozen047NOT RUNTIME ACCEPTED,193LIVEcasesNOTEXECUTED.
