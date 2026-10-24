# W2.3 — Fresh-install coordinator and isolated Alembic integration

**IMPLEMENTED (STAGED) / OFFLINE VERIFIED — 2026-10-18.** New versioned discovery/source lock, isolated individual-revision binding, F-only authority/raw-observation gates and executable mocked transaction/read-back integration. **300 offline tests PASS /0FAIL /0SKIP** (71new+229existing). Both W2.3 and unchanged W2.1 live modes remain denied. No concrete live connector/resource/credential/catalog adapter is activated; separately reviewed source-specific activation is mandatory.

Active Alembic head remains079; nothing was promoted. F NOT CREATED; frozen047 NOT RUNTIME ACCEPTED; all193LIVE integrity cases NOT EXECUTED. No PostgreSQL, Docker, real credential, SQL/migration, seed, application startup or Git delivery activity occurred. STOP independent source/package review; no automatic W2.4.

## Scope, prerequisites and preserved inputs

Operator authority covers OFFLINE integration/new sources/tests/documentation only. Required branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac` verified and retained. Scope/prerequisites/stop/acceptance recorded in tracker before implementation. Snapshotted2,136existing repository files; historical source/report/package preservation checked separately from new test results.

Read tracker/reports27–29, actual W2.1 adapter/catalog/lexer/frozen representation/lock/tests, W2.2 finalization/source tests/package, frozen SQL, active001–079 and staged080–091. Source/AST/import/declaration review and all44individual binding tests cover the actual eligible Python migrations, not a reconstruction from reports. Historical001 uses current ORM metadata and remains in verification-only history; it is never loaded or executed. W1.7private helpers/application env/settings/engines are not imported.

Verified both original protected package byte hashes and all embedded file hashes before changes:

- W2.1 `7b524fd8484116a4190b4dfeb98edb7324bdca38b1ddd4989b5f13a236080b34`.
- W2.2 `6112f88448ddc14d4959fd504311978bc4d3ec0de8930b3cb587dc7aeb1b5196`.

Original W2.1 source lock `ea4307ed66a08da663b3826f9bdf34e3cc72849e610a5f8f70e105731ff1f632`, original frozen047 `e310421b5fea4ef93056be590756125726280671589b50d93aa85926b9833c09`, proposed047 `6173c58cca7061483edd1b69e9edd0c431eee808f46ae1021293549d13e8c900` and all080–091 exact reviewed source pins remain unchanged. Both original packages/locks, six finalization bodies, historical001–079, app/env/bootstrap/config/Compose and prior reports remain untouched.

The fresh-install Product Owner decision removes legacy record transfer/backfill, without certifying a populated-upgrade path. Essential authorization reference initialization remains mandatory. Historical D085 acceptance and E NOT ACCEPTED/failures remain unchanged history, not fresh observations in W2.3.

## New implementation files and hashes

All eleven are under [fresh-coordinator](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/README.md).

| File | Purpose | SHA256 |
| --- | --- | --- |
|[README.md](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/README.md)|Execution/control/activation boundaries and offline commands|`f6a7054598bae07e8c467f5ddb0601774c6bb0c08be76f923f9ff976ef718b12`|
|[approval.pending.json](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/approval.pending.json)|Deliberately unusable future F047template; no target identities or approvals|`fea0161dfa6e057472122320e00319c4374262183fd2aec5a0ae6c436fe77e48`|
|[approval.schema.json](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/approval.schema.json)|Strict review schema,45exact transition/budget/connection conditions; Python validator remains authoritative|`a838c14eba83270324ce4c5414e0fb8283eba647b2ded27a4c03f66810ebc565`|
|[authority.py](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/authority.py)|Exact original manifest bytes/private path/duplicate-key/expiry/action/source/target checks and separately pinned effective-auth review artifact|`d9d9928165c4ef0e6dfbdd4f8623cf3bb3e4aae2054a03b5db22323618bbc9d9`|
|[coordinator.py](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/coordinator.py)|Offline CLI/live denial; mocked validate/write/read-back; one-step transaction/marker/commit/rollback/close and independent budgets|`4091c95d71c8e1ed0cf88ed41fcf94b60de4444ad69292c35a0bd017634e34cb`|
|[isolated_loader.py](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/isolated_loader.py)|Frozen558 framing; exact reviewed048/064seed alternatives; individual048–091binding to intercepted Operations/context factories|`fcb5b5700161e7b25fda6881229069ba0de8c866291a3db99525a9c4d82aca0d`|
|[observations.py](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/observations.py)|Raw resource/credential/identity/catalog/security/reference/freshness gates and typed W2.2 context derivation|`bc3418aa1299466df389681d7a8bd17cd0583dae79cfce0957d590df87f3bfe3`|
|[source-lock.v2.json](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/source-lock.v2.json)|New versioned source-lock proposal; preserves W2.1/W2.2 lineage and original pins|`f6fe5d0a823d7af3b91dd6716dad62d2d43a90c83f9f4186227af343e5e9c83f`|
|[source_registry.py](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/source_registry.py)|Versioned113-pin discovery; linear91graph;45units; deterministic promotion proposal; controlled W2.1 reference-library loading|`7ad5cc988816d000b709a214d9d53378d8e6f69c3e2e581299ac6183d4a5a4c4`|
|[test_coordinator_offline.py](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/test_coordinator_offline.py)|71offline regression tests and pure compiler checks|`f5eed8a57e6a6ca6bf7807860ddcb871fc2c2747293819d7116d1070f5001e2d`|
|[unit-budgets.v1.json](/Users/ferozebasha/sbom/infra/uuid-migration/fresh-coordinator/unit-budgets.v1.json)|All45explicit source-specific budget rows|`53ae99e41c48ed96fe7c4e45a75458ff67574687f57850bae91570dad36d11fa`|

Full new-file sources/unified diffs and their hashes are embedded in the protected package. New source-lock SHA256 `f6fe5d0a823d7af3b91dd6716dad62d2d43a90c83f9f4186227af343e5e9c83f` pins113inputs:93original historical inputs+11W2.1 artifacts+8W2.2 artifacts+new per-unit budget file. Runtime manifest source bundle additionally binds six new Python files and this new lock. Schema/pending documentation is separately pinned in the review package; Python validation is the actual authority contract.

## Versioned discovery and complete45-unit schedule

Discovery checks79historical active revisions, six expansion revisions, six finalization revisions and their exact bytes/source sets. It rejects extra Python migrations, changed/missing/symlinked files, duplicate IDs, branches/dependencies, cycles, missing ancestors/disconnected graphs and reordered numeric boundaries. The combined AST graph is linear001–091/head091; active discovery stays001–079/head079. No ScriptDirectory/env execution is used.

Installation deliberately skips historical001–047 execution: frozen047 is the first unit, followed by each actual048–079,080–085 and086–091. That is1+32+6+6=45units. Each row has one owned write transaction/explicit predecessor, next-only selection, physical close and independently authorized read-back; no head/range/skip/repeat invocation.

| Unit | Expected prior marker | Next marker | Source kind |
| --- | --- | --- | --- |
|1|ABSENT / fresh database|047_email_verification_tokens|frozen_047|
|2|047_email_verification_tokens|048_authorization_catalog|historical|
|3|048_authorization_catalog|049_tenant_multi_role_assignments|historical|
|4|049_tenant_multi_role_assignments|050_optional_external_tenant_mapping|historical|
|5|050_optional_external_tenant_mapping|051_report_subscription|historical|
|6|051_report_subscription|052_report_delivery_artifact|historical|
|7|052_report_delivery_artifact|053_tenant_analysis_schedule|historical|
|8|053_tenant_analysis_schedule|054_hierarchical_scheduler|historical|
|9|054_hierarchical_scheduler|055_ai_model_registry|historical|
|10|055_ai_model_registry|056_vex_investigation|historical|
|11|056_vex_investigation|057_vex_audit_hardening|historical|
|12|057_vex_audit_hardening|058_vex_source_format|historical|
|13|058_vex_source_format|059_vex_analyzer_sources|historical|
|14|059_vex_analyzer_sources|060_native_identity_foundation|historical|
|15|060_native_identity_foundation|061_security_mail_outbox|historical|
|16|061_security_mail_outbox|062_native_platform_bootstrap|historical|
|17|062_native_platform_bootstrap|063_microsoft_entra_identity|historical|
|18|063_microsoft_entra_identity|064_platform_tenant_v2|historical|
|19|064_platform_tenant_v2|065_scoped_configuration|historical|
|20|065_scoped_configuration|066_platform_config_permissions|historical|
|21|066_platform_config_permissions|067_component_advisor_foundation|historical|
|22|067_component_advisor_foundation|068_component_advisor_policies|historical|
|23|068_component_advisor_policies|069_component_recommendations|historical|
|24|069_component_recommendations|070_component_recommendation_compatibility|historical|
|25|070_component_recommendation_compatibility|071_component_recommendation_factors|historical|
|26|071_component_recommendation_factors|072_component_recommendation_review|historical|
|27|072_component_recommendation_review|073_sbom_operational_lifecycle|historical|
|28|073_sbom_operational_lifecycle|074_sbom_repair_jobs|historical|
|29|074_sbom_repair_jobs|075_platform_advisor_policies|historical|
|30|075_platform_advisor_policies|076_logical_sbom_versions|historical|
|31|076_logical_sbom_versions|077_sbom_selection_mode|historical|
|32|077_sbom_selection_mode|078_finding_reconciliation|historical|
|33|078_finding_reconciliation|079_lifecycle_provider_verification|historical|
|34|079_lifecycle_provider_verification|080_uuid_public_id_expand|uuid_expand|
|35|080_uuid_public_id_expand|081_uuid_projects_expand|uuid_expand|
|36|081_uuid_projects_expand|082_uuid_products_expand|uuid_expand|
|37|082_uuid_products_expand|083_uuid_logical_sbom_expand|uuid_expand|
|38|083_uuid_logical_sbom_expand|084_uuid_sbom_source_expand|uuid_expand|
|39|084_uuid_sbom_source_expand|085_uuid_sbom_component_expand|uuid_expand|
|40|085_uuid_sbom_component_expand|086_uuid_tenants_finalize|uuid_finalize|
|41|086_uuid_tenants_finalize|087_uuid_projects_finalize|uuid_finalize|
|42|087_uuid_projects_finalize|088_uuid_products_finalize|uuid_finalize|
|43|088_uuid_products_finalize|089_uuid_logical_sbom_finalize|uuid_finalize|
|44|089_uuid_logical_sbom_finalize|090_uuid_sbom_source_finalize|uuid_finalize|
|45|090_uuid_sbom_source_finalize|091_uuid_sbom_component_finalize|uuid_finalize|

Every row's exact source path/hash and budgets are in source-lock/unit-budgets and the protected package/offline CLI JSON. Staged revisions are not registered into active Alembic discovery.

## Isolated binding implementation

The pinned W2.1 pure libraries are loaded in private namespaces with explicitly controlled sibling imports, temporary dataclass module names and no sys.path/application initialization. No historical migration is imported by that mechanism. The loader separately validates the selected eligible unit, reads its pinned bytes and creates a private namespace with a controlled import hook. `alembic.op` is the supplied mocked Operations object;060's `alembic.context.is_offline_mode` refers to the isolated context. Only reviewed standard/compiler imports and pinned top-level SQLAlchemy type constructors are permitted.

For048/064, reproduce and verify the already reviewed frozen literal alternatives from the original W2.1 package. Exact proposed-source SHA and function AST equality prove only seed import bindings differ; historical files/bodies are untouched. No app package/seed runtime initializer is imported. All44Python unit namespaces bind without invoking upgrades or Operations methods during load. One additional test invokes the actual080 function with mocked Operations and verifies its tenants-only add-column/trigger calls; that is not PostgreSQL execution.

`configure_mock_operations` explicitly rehearses `MigrationContext.configure(connection=owned_connection,opts=...)` then `Operations(context)` with both factories intercepted. Options require online PostgreSQL transactional DDL and public version-table schema. No env.py, run_migrations, automatic version machinery, global op proxy, current ORM create_all or historical001 is invoked. Only the selected function is eligible, never its ancestors/downgrade.

**Historical creation-schema dependency:** most048–079DDL uses unqualified names. A dedicated future isolated dialect must have default_schema_name=public; the owned transaction uses SET LOCAL search_path=public,pg_catalog while that historical unit runs. Restore pg_catalog before inspection. This avoids silently creating objects in pg_catalog when the clean connection's inspection path is pg_catalog. The real isolated dialect/reflection behavior must be independently tested; no shared engine/dialect may be modified. Frozen047 already qualifies object names and retains its reviewed558statements and directives exactly; only a separate post-body inspection-path reset is added. Expansion/finalization keep their original source bodies/settings/guards.

No source incompatibility requiring a pinned historical edit was found. Actual PostgreSQL grammar, reflected constraint naming, seed behavior and047 equivalence remain unverified and can still fail future runtime gates.

## F-only approval and evidence contract

The new CLI imports inert modules and has useful offline output. `--mode live` always exits2 before source, manifest, Docker or credential access, even if other authority could be supplied. No bypass flag or real connection factory exists. Public transaction/binding rehearsals accept only unittest Mock adapters/factories and label all outcomes MOCK_ONLY. A caller-provided accepted=True or bare boolean receipt cannot produce live acceptance.

Future authority must bind exact original private JSON bytes to an externally supplied approved SHA256. Private0700parent/0600owner regular nonsymlink single-link bounded JSON, duplicate-key rejection, strict complete field sets/types, original unexpired UTC, actual F identity, exact current/next, full source bundle/budgets/connection options, independent review references and distinct unit_validate/unit_execute/unit_readback actions are mandatory. Old W16/W17D/E references, extra force fields, altered sources, expired authority, wrong target or substituted files fail. Reopen the same exact bytes and revalidate source/expiry/target/action at immediate pre-authentication, locked prebody, after binding, premarker and precommit boundaries. Raw byte hash and canonical digest have different evidence labels.

Fixed F target:127.0.0.1 host+hostaddr/56043, uuid_w2_f_fresh, uuid_w2_f_bootstrap, PostgreSQL16.15, project sbom-uuid-w2-f/service postgres_f/new f_pgdata and f_access. Actual cluster must differ from known D, with positive exact database OID, approved internal interface and matching actual database/current+session user/version/port/PGDATA/non-recovery/origin replication/row-security/search-path/transaction mode. F's actual values are UNKNOWN now. No D/E identity/fingerprint is reused as current F evidence.

Independent raw resource observations must establish exact local daemon/socket, container/start/image, project/service labels, sole dedicated network, exclusive volume mount, actual loopback-only publication, private F-only credential metadata, exact read-only host/Desktop bind mapping and one source/mounted-byte correlation. No matching metadata alone proves secret correctness. No actual secret observer/reader or Docker client is wired now; the concrete source-specific activation must perform these operations and preserve secret bytes only in memory.

Connection proposal retains explicit F target, passfile=/dev/null, no service keyword, SSL/GSS disabled, connect5s, default READ ONLY, search_path=pg_catalog and row_security=on. Mock connect receives explicit credential metadata and an empty clean worker environment; actual transient password sourcing/worker isolation must be reviewed before activation. No inherited PG*/DATABASE_URL/PYTHONPATH/Docker selection or application dotenv fallback is permitted.

A separate protected original-byte-pinned authentication-review artifact must bind target/identity/resources, effective-password-authentication scope, independent evidence hash and fresh expiry. HBA current-file/parse-only scope is rejected. This is an independently reviewed evidence artifact, not proof manufactured from flags or a successful socket connection; its underlying evidence/provenance remains a mandatory future operator gate. No reload, privilege elevation or extra connection is implemented.

W2.3 uses27full catalog templates plus four conditional reference-query sets; includes old freshness/security inventory and detailed columns, constraints, indexes, sequence definitions, function/trigger definitions and owners/ACLs. Complete approved prefix/postcatalog hashes and pre/post reference-data hashes are distinct. Full initial047freshness also reuses W2.1's24-category validator; the locked write recheck separately proves actual READ WRITE while applying the unchanged read-only freshness comparator to catalog facts (not falsely claiming the write transaction is READ ONLY).

All ordinary business tables must be observed empty; missing observations, RLS, competing clients/locks, event triggers/foreign/replication objects or role settings refuse. Authorization reference rows and seed audit are explicit exceptions, not business data. Source-derived checks require the five system roles/scopes/status/assignability, baseline permissions, protected grant semantics and seed audit. Exact V1 mappings before064 and final post079mappings/role versions are checked; intermediate064–078reference transitions additionally require their approved exact hashes. Missing reference data cannot be accepted merely by approving its empty hash. No user/tenant/customer/admin/password/membership is created automatically.

For086–091, the context is derived only after the raw resource/source/database/security/reference/prefix gates. It carries the exact unchanged W2.2 source pin and its own17-category snapshot hash, independently from W2.3's full catalog format. Tests pass the derived context through the unchanged086approval parser. No D Runner13/Independent31/W2.1 hash substitution or self-approved finalization receipt is permitted.

## Transaction, marker and recovery implementation

One mocked physical write connection performs a bounded READ ONLY preflight and ROLLBACK, then exactly one owned READ WRITE installation transaction. Acquire advisory7160085085, public.alembic_version EXCLUSIVE NOWAIT after047, and SHARE NOWAIT locks on all ordinary public tables. Existing UUID sources add their own target locks. This is a broad quiescent fresh-install window; FK/catalog lock dependencies require future PG16 acceptance.

Recheck original authority/resources/current marker/catalog/roles/references under locks, bind exactly one reviewed unit and recheck before invoking it. Frozen047 executes all558framed statements in order; only then create the version-table definition, inspect the complete expected post-schema/security/reference state with an empty marker, and insert047. Later units leave their old marker unchanged through all schema/postcondition checks. A planned-marker substitution is used only for comparing post-schema metadata after independently asserting the actual old marker; it is not claimed as a committed marker observation.

Marker SQL is fixed parameterized INSERT for047, or predecessor-qualified UPDATE later. Require exactly one rowcount/RETURNING value and one sole actual new marker. No stamp, ancestor replay or implicit Alembic marker machinery. COMMIT once after all gates; acknowledgment is recorded before physical close. The result remains COMMITTED_UNVERIFIED. A separate unit_readback authority/new bounded READ ONLY connection must verify marker, full schema/security/reference/data/resource state, ROLLBACK and close before MOCK_ACCEPTED. This label is never PostgreSQL acceptance.

Known precommit errors roll back/close and remain ROLLED_BACK_UNVERIFIED pending independently authorized state confirmation. Unknown rollback or lost COMMIT acknowledgment stops for manual reconciliation; no automatic retry/rollback after uncertain COMMIT, restore, recreation, downgrade or marker repair. Failed closure prevents acceptance. Error records retain sanitized class/SQLSTATE, never raw args/DSNs/secret values. Durable attempt/phase evidence flushing and concrete physical engine disposal remain activation-adapter requirements; a returned in-memory mock event list is not crash-durable commit evidence.

## Explicit independent budgets

All45rows have attempts1/concurrent1/connect5s/controls4/cooperative120s. Distinct catalog, migration, marker and session limits prevent conflating558bootstrap statements with64catalog queries. Frozen047 has558migration statements/two marker statements/256catalog queries.048/064allow2048migration executions for reference seeds; other Python units allow512. Finalization allows512catalog queries; other phases256. Session-statement allowance2covers historical creation/inspection path handling; marker allowance1later or2for047.

Statement caps:047/historical30s; expansion2s; finalization10s. Lock1s, expansion250ms; idle30s or UUID5s. These are proposed reviewed-source budget rows, not measured live sufficiency or a silent relaxation of existing source limits. Actual new target/operator execution approval is still required. Cleanup must run after cooperative deadline expiry; no hard network/COMMIT/close deadline is claimed.

Meter enforces logical operation quotas and provides a driver-event hook using the reviewed SQL framer. It counts every driver execution/executemany row; SELECT/SHOW/WITH/EXPLAIN additionally consume catalog budget, so reflection cannot evade the query cap by defaulting to the migration category. SQL transaction controls cannot enter through that unit-driver path. A real adapter must compose driver/observer/coordinator metering exactly once, including initialization/reflection/dynamic queries; this is not wired or runtime accepted now. Unsupported driver SQL framing must stop, never switch to permissive splitting.

## Actual offline results and development history

| Suite/check | Actual result |
| --- | --- |
|New W2.3 suite|71PASS /0FAIL /0SKIP|
|Existing W2.1|102PASS /0FAIL /0SKIP|
|Existing W2.2|53PASS /0FAIL /0SKIP|
|Existing expand runner|21PASS /0FAIL /0SKIP|
|Existing integrity OFFLINE|53PASS /0FAIL /0SKIP|
|Total|300PASS /0FAIL /0SKIP|
|AST/in-memory Python compilation|103files PASS; no historical upgrade invocation|
|New SQLAlchemy compilation|27catalog+4reference+6coordinator=37templates PASS|
|Existing compiler|42templates/14literal/18dynamic/six index-DDL compilations PASS; no index execution|
|Graph/source|91combined/45units;113new-lock inputs, original packages/080–091 preserved|
|Offline CLIs|W2.3PASS45units; unchanged W2.1PASS39units; expandPASS; live denial tested|
|Ruff|All6new Python files lint/format PASS|
|Whitespace/preservation|PASS; final details below|

Commands actually run:

```sh
.venv/bin/python -B infra/uuid-migration/fresh-coordinator/test_coordinator_offline.py
.venv/bin/python -B infra/uuid-migration/fresh-bootstrap/test_fresh_bootstrap.py
.venv/bin/python -B infra/uuid-migration/finalization-tests/test_finalization_offline.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_expand_one_step.py
.venv/bin/python -B infra/uuid-migration/staged-runner/test_uuid_integrity_offline.py
.venv/bin/python -B infra/uuid-migration/fresh-coordinator/coordinator.py --mode offline
.venv/bin/python -B infra/uuid-migration/fresh-bootstrap/fresh_bootstrap.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/expand_one_step.py --mode offline
.venv/bin/python -B infra/uuid-migration/staged-runner/verify_offline.py
.venv/bin/python -B -m ruff check --no-cache infra/uuid-migration/fresh-coordinator
.venv/bin/python -B -m ruff format --check --no-cache infra/uuid-migration/fresh-coordinator
```

New tests cover all45units/source-lock, duplicate/branch/missing/tampered discovery, frozen558order,44isolated module bindings/seed alternatives, intercepted Alembic factory recipe, actual080body against mocked Operations, no001/app/private-helper startup, exact F identity/budgets/manifests/private bytes/source/expiry/actions, invalid credentials/resources/roles/population/locks, effective-auth review versus HBA file, pre-DDL source/authority changes, required references/post-seed mismatch, one connection/no fallback, parameterized marker rowcounts, one commit, rollback/unknown rollback/unknown COMMIT, failed close, independently authorized read-back, sanitized SQLSTATEs and driver/query/deadline budgets.

First61tests:60PASS/oneERROR, because the new loader allowlist initially omitted reviewed072sa.Text/sa.DateTime constructors. Verified actual pinned source and allowed exactly those types; no historical source change. Corrected61PASS, expanded67/68/71PASS retained. Initial173new-file Ruff findings included10safe import fixes, then formatting removed semicolon/colon findings and one E731 was rewritten as a def. All final new files pass. Source review added historical public-schema binding/restoration, proper marker-table/precommit ordering, separate post-reference hashes/required reference contracts, independent authentication artifact and driver-query counting. These are offline development history, not PostgreSQL failures. Historical six expansion import-order warnings remain untouched.

Observed compiler dependencies: Python3.12.7, SQLAlchemy2.0.51, Alembic1.18.5, Ruff0.15.12. They are offline observations, not dependency upgrades. A future activation must bind/reverify exact accepted dependency versions and driver behavior. Compilation/framing is not PostgreSQL grammar/semantic equivalence, actual migration execution, allocator/immutability/unique/concurrency/rollback/recovery/performance or application acceptance.

## Promotion plan and first F procedure

The package contains12deterministic proposed exact-byte copy operations: each080–091 staged source to the same filename under alembic/versions, destination required absent. Nothing was copied/moved/deleted. Preserve the staged sources/packages. A later promotion must introduce a separately reviewed phase-specific discovery/lock selecting91active revisions while verifying retained staged copies without discovering their IDs twice. The current new lock intentionally describes79active+12staged. Old W2.1lock remains immutable and would correctly refuse a changed active count; do not weaken it or silently repin old evidence.

Normal root env still imports application state and cannot provide the fresh-only086–091receipt. It is not an approved execution path. The isolated F coordinator can select the current staged files without active promotion; copying files does not authorize a populated upgrade or bypass fresh-only finalization. Application migration invocation/configuration remains a separate review.

Proposed first-F sequence, entirely UNEXECUTED:

1. Independent review of this exact source/package, source-specific activation design and a new F infrastructure proposal. No action references are generated here. Actual resource/secret/catalog observers, clean worker, real owned SQLAlchemy binding/default schema, exactly-once driver metering, durable attempt/phase evidence, physical disposal and separate read-back require source-specific activation review; flipping a flag or trusting receipt booleans is insufficient.
2. Under separate explicit authorization, verify local daemon/socket, locally available PG16.15image, proposed names/127.0.0.1:56043 collision absence, capacity and existing A/B/D/E/app preservation. No image pull/build or resource reuse. Propose1CPU/512MiBRAM/64MiBshm/128PIDs, max_connections12/shared_buffers64MiB/work_mem4MiB, server statement30s/lock1s/idle30s to support frozen representation; per-unit connection caps remain independent. These settings are a proposal, not current observations or authority.
3. Approve a dedicated F project/service/database/user/volume/network and OS-random F-only private password at a reviewed0700/0600path. Explicitly review ordinary-NAT outbound exposure; loopback publication/ICC are not zero-egress isolation. No application/D/E network or storage/credential attachment.
4. Provision only after that exact resource grant; independently authenticate and accept actual new cluster/database/container/image/storage/network/port/credential identity, freshness, ownership/roles/ACL/extensions/settings and effective-password-authentication evidence. Health alone is insufficient. Preserve existing environments. No source schema export/restore or business record import is part of this fresh path.
5. Independently accept the F fresh catalog and derive/review the expected047semantic schema/security/reference postcondition, complete source/dependency pins and actual execution budgets. PG14dump→PG16grammar/equivalence and DDL timing are unverified now; a technical incompatibility is a STOP, not permission to edit pinned history or relax settings.
6. Only a fresh exact manifest/action grant may validate/execute one047unit, atomically record047, acknowledge commit, close and independently read back. Do not automatically048 or stamp079/085/091. Each subsequent unit needs its own accepted prefix/authority/commit/read-back boundary.

Current readiness: GO for independent source/package review and a separately scoped next-task proposal; NO-GO for provisioning/activation/execution now. No automatic W2.4. Native admin enrollment/reference application settings, final-schema adaptation of193integrity cases, ORM/API/frontend UUID boundaries, tenant/security/functional/SBOM workflows, concurrency/failure/recovery/performance and release remain separate work.

## Protected review package and stop

[Complete W2.3 source review](/Users/ferozebasha/.sbom-uuid-w2-review/w23-20261018T173823541360Z/w23-source-review-package.json)

- Exact byte SHA256 `cd15fbb1788fe8ac3099988b856f377fde3f3b4366f88395475a13063731a28b`.
- Review expiry `2026-10-19T18:08:24.338018+00:00` is metadata only, not execution authority or renewal of an old candidate.
- Private directory0700/files0600. Complete11new source/diffs/hashes,113-pin new lock, all91declarations/45unit budgets, isolated seed/binding contracts, raw-manifest/F/resource/auth/catalog/refdata/transaction/read-back contract, actual300tests/static/development outputs and promotion/first-F/activation limitations are included.
- Pending template `fea0161dfa6e057472122320e00319c4374262183fd2aec5a0ae6c436fe77e48` remains accepted=false, all seven source/resource/security reviews false, action approvals empty, seven integrity attestations false/integrity actions empty. Actual F identity/resource/credential/catalog/expiry/authentication-proof fields remain null. No live execution-approved manifest/action was created.

Only new fresh-coordinator source/tests/README/schema/lock/budget/template, this report and tracker changed. Previous package/source locks and historical task outcomes remain unchanged. Final preservation evidence below completes the record.

**STOP: independent source/package review. Active079unchanged; F NOT CREATED; frozen047 NOT RUNTIME ACCEPTED;193LIVEintegrity cases NOT EXECUTED.**


Final W2.3 preservation verification: PASS. Exactly11new coordinator artifacts plus report30; tracker is the only existing-file change. All2,135other contents from2,136baseline repository files preserved, no missing file; every earlier nonempty tracker line retained. Same required branch/HEAD, active079, immutable frozen047/history/080–091, original W2.1/W2.2 locks/packages/sources and all earlier reports unchanged. New package/source/pending/schema pins,0700/0600private modes, report links and whitespace PASS.300selected OFFLINE tests PASS/0FAIL/0SKIP; no PostgreSQL/Docker/credential/SQL/Alembic/startup/promotion/Git delivery. Complete source/report/tracker [change diff](/Users/ferozebasha/.sbom-uuid-w2-review/w23-20261018T173823541360Z/w23-complete-change.diff) and [final evidence manifest](/Users/ferozebasha/.sbom-uuid-w2-review/w23-20261018T173823541360Z/final-evidence-manifest.json) retained privately. Source-review package SHA remains cd15fbb1788fe8ac3099988b856f377fde3f3b4366f88395475a13063731a28b. STOP independent source/package review; no automatic W2.4. F NOT CREATED,frozen047 NOT RUNTIME ACCEPTED,193LIVE integrity cases NOT EXECUTED.
