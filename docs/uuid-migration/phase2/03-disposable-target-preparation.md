# W1.2 — Disposable PostgreSQL D: offline preparation

Prepared 2026-10-16 (Asia/Kolkata). Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`, matching the prior baseline. This task creates configuration and documentation only. **D has not been provisioned, started, connected, imported, stamped or tested.** Existing containers, databases, volumes, networks, application configuration and prior reports are untouched.

Read the complete [W0.1 target readiness](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:1), [W0.2 core UUID contract](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/01-core-public-uuid-contract.md:1) and [W1.1 schema design](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/02-w1-additive-schema-design.md:1). The new [Compose file](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:1) uses the requested path; no existing convention made that path unsafe. Required files did not already exist. Only these two outputs are added.

**Readiness: GO for operator review of separately approved D provisioning. Provisioning/execution remains NO-GO in this task.** Docker/Compose parsing, local daemon/port/resource availability, secret-file permissions, image initialization, host connectivity and database capabilities are unverified. Production remains unconfirmed. A and active B remain excluded.

## Isolation and resource contract

| Setting | Prepared design | Verification still required before/after separately authorized startup |
| --- | --- | --- |
| Compose project | Fixed top-level name and future CLI project `sbom-uuid-w1` | Verify no existing project/resource collision. Never override it with `sbom`, `sbom-analyser-server` or another shared project; names alone are not proof. |
| Service | One service, `postgres_d`, official `postgres:16`; no build, init/import mount or custom startup script | Inspect approved PG16 image digest/architecture before pull/use; record resolved digest. A major-version tag is mutable. No automatic baseline import or Alembic service exists. |
| Host endpoint | Only `127.0.0.1`, container TCP 5432, host `56` + required three-digit `UUID_W1_D_PORT_SUFFIX` | Select one free port 56000–56999; e.g. suffix 041 means 56041. This structurally excludes 55439 for valid single-port configuration. Reject non-three-digit suffix, ranges, zero/dynamic port and occupied ports. No automatic fallback to another port. |
| Persistent test volume | Project-managed `d_pgdata`, expected Engine name `sbom-uuid-w1_d_pgdata`, at `/var/lib/postgresql/data`; PGDATA subdirectory `pgdata` | Must be new on initial provisioning. Inspect Engine volume ID/name, driver/options, mount source/destination, Compose ownership and D labels, and all attached containers; no external/name override/bind mount to A/B data. Persistent means stop/restart retains test data. |
| Network | Project-managed bridge `d_private`, expected `sbom-uuid-w1_d_private`, `internal: true`, no external attachment | New network ID, correct project/D labels, only postgres_d attached, no connection to existing networks. Verify loopback publishing works on the actual Docker version. Internal networking is an egress/isolation aid, not a security boundary against host/Docker administrators. |
| Credentials | Only required `UUID_W1_D_POSTGRES_USER`, `UUID_W1_D_POSTGRES_DB`, and `UUID_W1_D_PASSWORD_FILE` inputs; no defaults for credentials | Independently create disposable-only values; never reuse A/B/production credentials. DB/user names aid recognition but do not prove physical isolation. |
| Password | Operator-owned external file mounted through Compose secret `uuid_w1_d_password`; image consumes `POSTGRES_PASSWORD_FILE` | Absolute resolved path outside checkout, dedicated new regular file, restricted host permissions and no unintended symlink/secret-source reuse. No plaintext password variable/CLI argument in configuration. |
| Authentication | Host and local init authentication SCRAM; password_encryption SCRAM | Verify actual initialized settings and authenticated connection later. A healthy pg_isready does not prove credentials, revision, authorization or isolation. |
| Lifecycle | `restart: "no"`; one PostgreSQL service only | No API, Celery, Beat, Redis, frontend, SMTP, mail sink, external provider, Docker socket or application source mount. There is no automatic migration/capability probe. |

The new file references no DATABASE_URL, root `.env`, `.env.dev.local`, existing volume/network, `extends`, `include` or external resource. PostgreSQL initializes the disposable database on an empty volume only; its image does not rotate an existing cluster's credentials when input variables change. A reused nonempty volume requires separate identity/credential review, never blind reinitialization. POSTGRES_USER is the image bootstrap administrator, not a least-privilege application role. Future migration/test roles need separate approval; this preparation creates none. [Official image initialization and password-file behavior](https://raw.githubusercontent.com/docker-library/docs/master/postgres/README.md).

Compose secrets are file mounts in this local design, not proof of encrypted secret storage or protection from Docker administrators. No credential file is created or read in W1.2. Do not put real passwords, source dumps, private manifests or credential env files in either output or in Git. [Compose secret file source](https://docs.docker.com/reference/compose-file/secrets/).

## Dedicated configuration and future invocation

Compose can automatically discover `.env` and inherit project/file/context overrides; merely using distinct variable names does not disable that behavior. Future invocation must explicitly disable discovery and start with a clean environment. Use only one absolute Compose file, a fixed project/project-directory and an operator-verified **local Unix Docker endpoint**. Do not merge this file with root/server Compose or pass an existing env-file. [Compose environment and project precedence](https://docs.docker.com/compose/how-tos/environment-variables/envvars/).

Operator-supplied inputs, created/set **only in a later authorized task**, are:

| Input | Contract |
| --- | --- |
| `UUID_W1_D_POSTGRES_USER` | New disposable bootstrap account; nonempty simple SQL identifier, independently generated/selected; no A/B credential reuse. |
| `UUID_W1_D_POSTGRES_DB` | New disposable database name; nonempty simple SQL identifier, never used as isolation proof. |
| `UUID_W1_D_PASSWORD_FILE` | Absolute path to new nonempty disposable-only secret file outside checkout; operator inspects provenance/resolved path and owner/mode privately. Do not print its content. |
| `UUID_W1_D_PORT_SUFFIX` | Exactly three decimal digits; full published port is 56xxx. Availability/identity preflight required. |
| `UUID_W1_D_DOCKER_ENDPOINT` | Explicit, verified local `unix:///absolute/socket/path`; no tcp/ssh/remote context, forwarder or deployment daemon. Inspect actual socket/daemon identity, not URI spelling alone. |

The following **future-only invocation template is not run by this task**. It defines a shell helper, not a repository file. Set the five inputs privately in the operator session first. No credential values are embedded. `$PATH` is used only to locate the approved Docker client; verify that client separately.

```sh
d_compose() {
  case "${UUID_W1_D_DOCKER_ENDPOINT:-}" in
    unix:///*) ;;
    *) echo 'STOP: approved local Unix Docker endpoint required' >&2; return 1 ;;
  esac
  case "${UUID_W1_D_PORT_SUFFIX:-}" in
    [0-9][0-9][0-9]) ;;
    *) echo 'STOP: exactly three port suffix digits required' >&2; return 1 ;;
  esac
  : "${UUID_W1_D_POSTGRES_USER:?Supply disposable-only user}"
  : "${UUID_W1_D_POSTGRES_DB:?Supply disposable-only database}"
  : "${UUID_W1_D_PASSWORD_FILE:?Supply dedicated password-file path}"
  env -i PATH="$PATH" COMPOSE_DISABLE_ENV_FILE=1 \
    UUID_W1_D_POSTGRES_USER="$UUID_W1_D_POSTGRES_USER" \
    UUID_W1_D_POSTGRES_DB="$UUID_W1_D_POSTGRES_DB" \
    UUID_W1_D_PORT_SUFFIX="$UUID_W1_D_PORT_SUFFIX" \
    UUID_W1_D_PASSWORD_FILE="$UUID_W1_D_PASSWORD_FILE" \
    docker --host "$UUID_W1_D_DOCKER_ENDPOINT" compose \
      --env-file /dev/null \
      --project-name sbom-uuid-w1 \
      --project-directory /Users/ferozebasha/sbom/infra/uuid-migration \
      --file /Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml \
      "$@"
}
```

This helper removes inherited DATABASE_URL, PG*, DOCKER_CONTEXT/HOST, COMPOSE_FILE/ENV_FILES/PROJECT_NAME and other ambient settings from the child environment. It passes only disposable configuration and an explicit daemon endpoint. It is an invocation convention, not an authorization mechanism: the operator must review the exact arguments, secret path, user/database identifiers, local endpoint and rendered resource identity. Never add project/file/host overrides, other Compose files, `--remove-orphans`, volume overrides or profiles to it. `/dev/null` is intentionally the explicit empty env-file on this macOS/Linux local workflow. If the required Compose features are unsupported, stop and review; do not fall back to root Compose or load another env file.

After separate approval, first perform Compose `config --quiet` validation through this convention, then inspect only nonsecret selected properties. Do not print full resolved configuration or container Config.Env, use shell tracing, or paste credentials into commands. Validate that the result contains exactly one service, one D-managed volume, one D-managed internal network and the expected loopback port. Only after the collision/target checks below pass may an operator-approved `up -d postgres_d` provision the instance. No such commands were executed here. Image pulls and volume creation are future effects requiring approval too.

The Compose interpolation syntax can require nonempty values but does not establish their provenance. It also cannot prevent an operator deliberately overriding CLI/project settings. The fixed port prefix prevents the known A/B port selection; complete isolation still depends on the resource checks and approved invocation. [Compose port host_ip/published definitions](https://docs.docker.com/reference/compose-file/services/#ports), [Compose internal network semantics](https://docs.docker.com/reference/compose-file/networks/#internal).

## Future target-safety checklist: evidence, not names alone

Do not run these inspections in W1.2. Before an authorized initial provision, and again before import/migration/deletion, record a secret-free target manifest:

1. Verify this branch, HEAD and reviewed Compose content/hash. Verify the Docker executable/version, explicit local Unix socket and daemon identity. Reject remote/SSH/TCP/context routing, uncertain forwarding and any unreviewed environment/file override. No deployment target is authorized by this report.
2. Check actual existing containers/projects, including `sbom-postgres-1`, and host listeners. The selected 56xxx loopback port must be free; record port, not DSN. Do not stop an existing listener to make room. Prior W0.1 observations of A/B at 55439 are not a fresh availability survey.
3. Require no existing `sbom-uuid-w1` resources on first provision. A collision means STOP, not adoption. After provision, record actual container ID, local image digest, creation time, Compose project/service/config-file labels and explicit D/disposable labels. Labels/names can be spoofed; cross-check reviewed mounts and resource IDs.
4. Inspect D's exact volume and network IDs, driver/options, attachment sets and mount destinations. Ensure the volume is not A/B's persistent source, an external volume, a bind to shared data, or attached to any other container. Ensure its bridge is separate from every existing application network and contains only D. No actual Engine resources have been inspected/created in this task.
5. Verify port publication is only 127.0.0.1:56xxx → D:5432, with no 0.0.0.0/IPv6 wildcard/host networking. Verify authenticated loopback access to D in a later authorized connection; pg_isready alone is insufficient. Also verify the internal bridge/host publishing combination on the installed Docker platform rather than assuming it works everywhere.
6. After connection authorization, correlate PG server address/version and fresh cluster system identifier to the D container/volume manifest. Compare to an already approved source-cluster identity if available; do not connect to A/B solely to discover identity without approval. Use container/socket/mount evidence as well: database name, username, port and Alembic marker individually do not prove isolation. Identical physical cluster identifier with a source suggests a physical/shared clone and requires review; the proposed fresh-init schema restore should use a new cluster.
7. Before any destructive action or reinitialization, reconfirm the same daemon/container/volume/network identity and absence of other users/attachments or issued public mappings that must be retained. A stale manifest, changed daemon, resource ID mismatch or unexpected content is a stop condition.

Only PostgreSQL infrastructure is provided. No API or worker can be started by this file. Later tooling must still use an explicit D-only connection and independently isolated resources; never edit `.env.dev.local`, repoint existing managed services or use `scripts/dev.py` to select D ([W0.1 launcher warning](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:138)).

## Operator-reviewed schema-only baseline procedure — future, not performed

Use a new D cluster, then a **schema-only** reproduction of actual authorized B metadata, followed later by synthetic fixtures. A schema-only export can still contain sensitive schema literals, functions, FDW/server definitions or embedded endpoint metadata; treat it as private and review it outside the checkout. No dump/archive or credentials are read/created by this task.

| Phase | Future procedure and approval boundary | Expected evidence / stop condition |
| --- | --- | --- |
| Source authorization | Explicitly approve B as the read-only source for schema extraction, confirm target identity/revision with a separate authorized metadata check and select compatible PostgreSQL 16 tools. Existing authorization is not permission to create dumps or use deployment credentials here. | Secret-free source/target manifest; source endpoint is B, never A by default; no production host inference. |
| Export | Operator-reviewed pg_dump plan uses schema-only custom archive. No business data, large objects/data-only dump, globals/roles/password hashes or CREATE DATABASE payload. Use a secure non-URL credential mechanism and bounded source operational window. Store outside checkout with restricted permissions; record archive hash and tool versions. | Archive object definitions reviewed; no TABLE DATA/sequence-state or business-record payload. Do not print dump contents in public logs. |
| Review | Inspect archive TOC and SQL privately before restore; restore artifacts can execute source-supplied definitions. Identify extensions/functions, ownership/ACL needs, cross-database/FDW/subscription links or unsafe handlers. Stop for unexpected external connectivity/security semantics; no automatic omitted object or mutation. | Accepted schema delta manifest; a privileged restore is a separately reviewed operation. |
| Restore to D | Recheck D identity and empty target. Future restore plan uses explicit D connection, schema-only selection, no-owner/no-privileges ownership remapping, fail-on-error and a single transaction if compatible with the reviewed archive. No --create, --clean or --disable-triggers, source role import, automatic retry into a partial schema, or migration-upgrade shortcut. | Fully restored object graph or failed transaction; if some object cannot restore transactionally, stop and revise the plan. New D owner/ACLs are intentional documented differences, not asserted B privilege parity. |
| Independent comparison | Compare D with captured B catalog: every relevant table/column/type/default/PK/FK/action/composite constraint, indexes/predicates/validity, checks, sequences/ownership definitions and other approved objects. Compare actual B, not Base.metadata.create_all. Check trigger/rule/extension/RLS differences explicitly. | Expected B-shaped shared schema plus Alembic table structure; no data assumed. Prior totals 72 tables/143 FKs are sanity evidence, not sufficient proof of equivalence or guaranteed fresh counts. |
| Revision establishment | Schema-only restore does not transfer rows, including the value in alembic_version. D is **schema-imported, revision-unestablished** until independent comparison and explicit reviewer acceptance. A missing/empty marker is expected; do not treat it as permission for upgrade from base. | Only a separately approved revision-establishment action may record 079_lifecycle_provider_verification after evidence review. No INSERT/stamp/upgrade command is supplied or run here; a revision row never substitutes for schema comparison. |
| Fixture/rehearsal authorization | Approve D-only synthetic data and W1 migration artifacts/runner separately, with restoration/discard policy and resource budgets. | No business data clone, no use of active B or existing queues. Provisioning/schema import approval does not implicitly authorize W1 DDL/backfill/tests. |

PostgreSQL defines schema-only export as object definitions without data. Consequently it does **not** carry the `alembic_version` revision row; imported table structure alone cannot establish revision 079. [PG16 pg_dump schema-only](https://www.postgresql.org/docs/16/app-pgdump.html).

Preserve the known B drift in the imported baseline: missing `vex_documents.superseded_by_id → vex_documents.id` FK (ORM declares SET NULL), report_subscription.deactivated_by length difference, and reviewed index/default/constraint representation differences. Do not repair them or regenerate a pristine ORM schema during import. See [W0.1:111](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:111) and [W1.1 baseline](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/02-w1-additive-schema-design.md:13). An inability to reproduce a required object is a blocker with an explicit disposition, not justification for silently stamping 079.

## Future capability and migration acceptance checks

All checks below require separately approved D access and, for fixtures/DDL, explicit mutation/test approval. No check was run here.

| Check | Future acceptance evidence |
| --- | --- |
| PG16 and UUID generation | Actual server is major 16; core pg_catalog.gen_random_uuid exists, is executable by intended roles and returns native UUIDv4 with correct variant. No new extension silently installed. Inspect default behavior for omitted and explicit-NULL inputs under W1.1 allocator design. |
| Trigger support / identity | Review PL/pgSQL/function/trigger privileges, hardened function resolution, twelve proposed INSERT/UPDATE triggers on six scoped tables and existing trigger interactions. Verify first NULL→UUID allowed, committed UUID changes/NULL/DEFAULT rejected, in-place domain updates and reused component occurrences retain identity. |
| Concurrent indexing | Rehearse CREATE UNIQUE INDEX CONCURRENTLY on approved fixtures, outside transaction; inspect valid/ready flags, duplicate failure/invalid-index remnants, snapshot waits and approved recovery. No assumption of zero locks; no repeated blind IF NOT EXISTS. |
| Migration transactions | Verify pinned Alembic/driver version, autocommit-block prior-commit behavior, per-stage/per-table revision boundaries, session timeout reset across autocommit and failure-marker reconciliation. Current env.py configuration requires explicit review; preparation does not change it. |
| Backfill / invariance | NULL-only bounded batches and COMMIT/checkpoint restart cases preserve mappings, integer PK/FK graph and old column values; no ORM flush side effects or unrelated VEX drift repair. No public UUID issuance before enforcement. |
| Performance | Agree synthetic cardinalities, concurrency and lock/disk/WAL budgets before measurement. Record EXPLAIN/query counts, p50/p95, insert rate and trigger/index overhead. No performance result or threshold is invented by offline preparation. |

### Carry-forward optimization: conditional AFTER UPDATE trigger

The next trigger benchmark should compare W1.1's all-row AFTER UPDATE validator with this candidate predicate (design text only):

```text
AFTER UPDATE ON <one of the six scoped tables>
FOR EACH ROW
WHEN (OLD.public_id IS DISTINCT FROM NEW.public_id)
```

This is an optimization candidate, **not implemented or assumed faster**. W1.1 specifies an AFTER UPDATE guard but does not currently include this WHEN clause; this runbook carries forward the requested refinement without editing that prior design. Keep the shared validator logic: OLD NULL→valid UUID is permitted during backfill, OLD non-NULL→changed/NULL is rejected, identical values require no validation call. The NULL-aware predicate must not be replaced by `<>`.

An AFTER WHEN predicate sees the updated row after BEFORE UPDATE triggers. Therefore a statement updating only a domain column must still be rejected if another BEFORE UPDATE trigger changes an already assigned public_id; do **not** narrow to UPDATE OF public_id, which is based on statement target columns. Test same-value statements, NULL transitions, bulk updates, first assignment, changed-value attempts, deliberate other-BEFORE-trigger interference and trigger ordering on disposable fixtures. Also exercise cascading/internal updates, return semantics and permissions without disabling production safeguards. [PG16 CREATE TRIGGER timing and WHEN semantics](https://www.postgresql.org/docs/16/sql-createtrigger.html).

Measure all-row validator versus conditional candidate under identical fixtures for ordinary unchanged-identity updates and backfill/changed-identity attempts; record invocation/queued-event evidence, CPU and p50/p95, plus correctness. WHEN evaluation itself has a cost. A correctness failure rejects the optimization irrespective of timing; no approval to alter the W1.1 trigger design is assumed from this preparation.

## Safe discard and recreate — future destructive approval required

Persistent D data survives ordinary stop/restart and a project down without volume deletion. Discard/recreate is allowed only after explicit operator confirmation of **daemon endpoint, project sbom-uuid-w1, container ID, exact volume ID/name, network ID/name, test-data status and mapping-retention decision**. Confirm no other container mounts D's volume and no other user depends on it. If public UUIDs have been issued or retained evidence is required, preserve the approved mappings/evidence first; "disposable" labels are not authority to lose them.

Future reviewed teardown sequence:

1. Review the current D-only manifest and resolved Compose identity using the same clean invocation. Require an explicit confirmation naming this exact target and volume, not a generic yes or a database-name check. Any mismatch stops deletion.
2. Use the fixed D project/file convention to stop/remove only D's service/network **without `--volumes` or `--remove-orphans` initially**. Reinspect the exact recorded volume and all remaining attachments. Do not stop or remove `sbom-postgres-1` or other services.
3. After the second explicit volume-deletion confirmation, remove only the exact recorded `sbom-uuid-w1_d_pgdata` volume on the verified daemon. Do not use `docker system prune`, volume/network prune, wildcards, name-prefix deletion, all-resource substitutions or root/server Compose down commands. If it is still attached or ownership is uncertain, stop rather than force removal.
4. Confirm only the recorded D resources disappeared. A/B infrastructure must remain unchanged. For recreation, repeat all initial collision/port/credential checks; approve a fresh volume and record new resource/cluster identities. A failed schema import is not permission to clean a shared volume or retry destructively.

No executable destructive helper is provided or run. The concrete commands and resource IDs must be reviewed in the separately approved discard task. No existing volume/network is inspected, altered or deleted in W1.2.

## Open gates and handoff

| Gate | Status / required next authorization |
| --- | --- |
| Offline files | Prepared; only static content/preservation review, not Compose/Docker runtime validation. |
| D provisioning | Pending explicit approval, disposable credentials/secret file, verified local daemon, free selected port, no resource collision, supported Compose/image and reviewed exact invocation. D is not claimed to exist. |
| B schema extraction | Separate source/export authorization and metadata/SQL review required; no dump or source credential access here. |
| D restore / revision | Separate D mutation approval; independent schema comparison and drift manifest acceptance before any approved establishment of revision 079. No automatic stamp. |
| W1 migrations / synthetic fixtures / benchmarks | Separate concrete artifact/execution approval and W1.1 integrity/recovery gates; conditional trigger optimization requires correctness/performance evidence. |
| Application / public cutover | Outside this infrastructure-only scope; tenant selection, identity/JWT, other resource contracts and UUID-preserving rollback remain dependent work. |

Created paths: `infra/uuid-migration/docker-compose.uuid-w1.yml` and `docs/uuid-migration/phase2/03-disposable-target-preparation.md`. Task-start branch/HEAD and 34 pre-existing modified/untracked file contents were preserved. No docker compose, pg_dump, pg_restore, psql, Alembic, tests, services, database connection, schema/data mutation, runtime-configuration edit or Git state mutation was performed. Examples describe future reviewed actions only. **GO for separately approved provisioning review; NO-GO for execution during this task.**

Offline review completed: YAML syntax parsed; one PostgreSQL service, dedicated required-input namespace, loopback port design, secret-file reference and project-managed volume/internal network inspected; seven local evidence-link locations checked. Only the two allowed outputs were added, all 34 pre-existing modified/untracked contents and the tracked binary diff matched the task-start snapshot, and whitespace checks passed. This is static file review, not Docker Compose validation, a test-suite run or runtime acceptance.
