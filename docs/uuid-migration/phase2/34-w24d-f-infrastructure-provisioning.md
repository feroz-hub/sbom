# W2.4D — Fresh PostgreSQL F infrastructure provisioning

**W2.4D F INFRASTRUCTURE ACCEPTED — 2026-10-19.** Exactly one targeted Compose startup, exit0; one new running/healthy F container, one new volume and one new ordinary bridge. No authenticated PostgreSQL connection, operator SQL, schema initialization/migration, role operation, Alembic marker, application startup or integrity case was executed. Standard PostgreSQL image internal initialization and readiness healthchecks were explicitly authorized and occurred. This is infrastructure acceptance only, **not database/schema/authentication acceptance**.

## Authorization and source preservation

Operator W2.4D authorizes read-only preflight and one conditional F-only startup. The initially missing mandatory network decision was requested before modification. Direct human answer: **“Accept the stated F-only bridge egress risk.”** This accepts ordinary bridge outbound reachability only within the reviewed F scope; loopback publication/ICCfalse do not establish zero egress. No D/E/application attachment or expanded exposure is authorized.

Branch `feat/native-user-management`, HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac` verified.2,195existing tracked/untracked nonignored files snapshotted before edits. Read tracker/reports27–33, W2.4A actual Compose/runtime checklist, W2.4B budgets and W2.4C correction. W2.4C package byteSHA256 `6e7b633e17ea2ff63c137c8f6829222999bae45b5dca6309122476da1f8b14df`, all15full sources and full diff hashes verified unchanged. No migration, source lock, adapter, existing Compose, application or previous report changed. No active Alembic promotion or live W2.4C activation; active head remains079 as source evidence, not a new PostgreSQL observation.

## Fresh preflight and exact configuration review

|Gate|Actual observation/result|
|---|---|
|Docker endpoint|Explicit Unix socket `/Users/ferozebasha/.docker/run/docker.sock`, socket type verified; no context/remote fallback|
|Daemon|`1f8c7fe5-5972-4adc-8d6e-363a38572be1`, docker-desktop, Docker Desktop/Linux aarch64, server29.8.2|
|Locally available image|`sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`; arm64/Linux; PG_VERSION16.15-1.pgdg13+2|
|Binary version|Same pinned image in existing D: `postgres --version` returned PostgreSQL16.15; version/filesystem/meminfo commands only, no source DB authentication or SQL|
|Host capacity|54,067,798,016bytes free disk;8GiB RAM; memory_pressure32% available (~2.56GiB estimate);8CPUs|
|Docker VM capacity|223,770,583,040bytes filesystem available; MemTotal4,010,356KiB/MemAvailable3,236,984KiB;8CPUs. Both disk>=2GiB and host/VM memory headroom>=1GiB passed|
|Collision checks|All existing containers/networks/volumes inspected; F project/service/container/labels/volume/network absent; F secret parent absent;127.0.0.1 and wildcard56043 bind probes succeeded and closed immediately|
|Original source|`infra/uuid-migration/f-activation/compose.f.proposed.yml`, SHA256 `37af79b078078191a13c957f88ac31339362c5f683c8647b92959c5797def51c`|
|Exact rendered config|SHA256 `4f5aa1607705c6f62407e72ab4321b61526f777e7dfc4e79c725585ac829c3fe`; Docker Compose5.6.0; clean allowlisted environment, explicit image value and `--env-file /dev/null`, private project directory|
|Resource delta|One F-only container, one dedicated local volume, one dedicated ordinary bridge, one new private F-only credential file; no source resource reuse|

Original Compose bytes were copied unchanged to protected `/Users/ferozebasha/.sbom-uuid-w2-review/w24d-20261019T060938878326Z/compose.f.reviewed.yml`. It is execution evidence, not a new tracked deployment configuration. The only substitution is the explicitly reviewed already-local image ID in F_POSTGRES_IMAGE. No image pull/build/registry action occurred. Original `.yml` remains byte-for-byte unchanged.

Reviewed and observed limits:1CPU,512MiB RAM,64MiB shared memory,128PIDs,restart=no,not privileged. Docker reports MemorySwap1GiB (default combined memory+swap accounting; no unapproved RAM increase). Startup command exactly preserves max_connections12/shared_buffers64MB/work_mem4MB/statement_timeout30s/lock_timeout1s/idle_in_transaction_session_timeout30s/password_encryptionscram-sha-256. Actual effective PostgreSQL settings remain unqueried. Initialization inputs are database uuid_w2_f_fresh/useruuid_w2_f_bootstrap/POSTGRES_PASSWORD_FILE and SCRAM host/local init arguments. Standard image bootstrap-user privileges must still be independently reviewed in the later authenticated role/security gate.

## Credential creation and single startup

Created `/Users/ferozebasha/.sbom-uuid-w2-f` mode0700 and `postgres-password` via O_EXCL/O_NOFOLLOW mode0600. Fresh OS-random48-byte URLsafe token,64ASCII bytes, no newline, F-only; never inherited from D/E or application configuration. Regular nonsymlink/single link, UID501/GID20, inode76156846, length64 verified; metadata unchanged after startup. Secret never printed, hash-logged, included in a command/environment, copied into the repository or reread for this acceptance. The standard image reads its own approved mounted initialization secret. No host/container content-correlation check or PostgreSQL credential authentication is claimed.

A durable exclusive startup-attempt claim preceded exactly this command (nonsecret image value supplied in clean environment):

```sh
/usr/local/bin/docker --host unix:///Users/ferozebasha/.docker/run/docker.sock compose \
  --env-file /dev/null \
  --project-directory /Users/ferozebasha/.sbom-uuid-w2-review/w24d-20261019T060938878326Z \
  --project-name sbom-uuid-w2-f \
  --file /Users/ferozebasha/.sbom-uuid-w2-review/w24d-20261019T060938878326Z/compose.f.reviewed.yml \
  up --detach --no-deps --no-build --no-recreate --pull never postgres_f
```

One invocation/exit0. Progress output repeats some create/created lines; independent resource-set comparison confirms exactly one volume/network/container addition, not repeated startup. No up retry, down, recreate, restart, cleanup, deletion, prune, image pull/build or dependency startup. On any actual resource/identity/security failure resources would have been retained; no automatic repair path was used.

## Actual F infrastructure identities

|Resource|Observed identity|
|---|---|
|Container|`964fe491cf9e12f6f9cf8125f5352e301d85f0fc1a0b05142cda6393c6d9152c`|
|Name/project/service|`sbom-uuid-w2-f-postgres_f-1` / `sbom-uuid-w2-f` / `postgres_f`|
|Created/start|2026-10-19T06:14:06.895365803Z / 2026-10-19T06:14:07.068935636Z|
|State|running/healthy;restartcount0;notOOMKilled/notdead/notrestarting;last5readiness exitcodes0|
|Image|Container `.Image` and local image `.Id` both exact approved `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`|
|Publication|Only `127.0.0.1:56043 -> 5432/tcp`; hostlistener independently observed|
|Volume|`sbom-uuid-w2-f_f_pgdata`;driverlocal;created2026-10-19T06:14:06Z;mountpoint`/var/lib/docker/volumes/sbom-uuid-w2-f_f_pgdata/_data`|
|Volume exclusivity|Only F container uses the new volume; no A/B/D/E storage reused|
|Network|`sbom-uuid-w2-f_f_access`, ID`5347909a2fb95db230d562557e5154cf623ccb613286eca309134da6e9122447`;driverbridge/local;internalfalse;attachablefalse|
|IP/subnet|F172.22.0.2;172.22.0.0/16;gateway172.22.0.1;IPv4on/IPv6off|
|Network attachments|Only F on the new network; F attached only to its dedicated network|
|Secret bind|Host `/Users/ferozebasha/.sbom-uuid-w2-f/postgres-password` -> `/run/secrets/f_password`;bind;RWfalse;rprivate;no duplicate secret mount|
|PG cluster ID/database OID|**UNKNOWN — no authenticated query or data-file probe**|
|Database/schema/marker|Initialization inputs known; actual authenticated identity/schema freshness/Alembic state **NOT QUERIED / NOT ACCEPTED**|

Compose bookkeeping label `com.docker.compose.image=sha256:1a43e6bb8872ccce507f8467e549a6166e8ff132ad26b49879f5ec86ee612868` is also identical on pre-existing D/E/B. It is recorded separately, not substituted for the exact authoritative image-inspect/container.Image pin. No image change or fallback occurred.

Network inspection materializes two extra explicit default options `com.docker.network.enable_ipv4=true` and `com.docker.network.enable_ipv6=false`. Both actual flags match. The original required enable_iccfalse/host_binding_ipv4127.0.0.1 remain exact. Final checker requires exactly these four keys/values; it does not allow arbitrary option additions. Ordinary NAT egress remains possible and operator-accepted; no network-policy or zero-egress claim.

## Existing-resource and process preservation

Before/after read-only metadata sets:5existing containers preserved plus1F;7existing networks preserved plus1F;27existing volumes preserved plus1F. All previous selected container properties/start/PID/restart/image/labels/mounts/limits/ports/network identities equal; complete previous network and volume metadata equal. No old container replacement/restart/network attachment/volume mutation. Original D `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e` and E05745ce… retain original starts, images, volumes/networks and loopback56041/56042. B/sbom-postgres container5d8b97a… still on55439; Redis135db956…/Mailpitb342c021… unchanged. A/local PostgreSQL18 is represented only by preserved host process metadata, not new database authentication/identity claims.

27relevant host process rows (PID/PPID/start/executable) preserved, including local PostgreSQL18/Redis/Docker and currently observed other-project node tooling. Existing listener metadata preserved; only intended F56043 added. `.dev-runtime.json` was inspected for PID fields only, not edited: historical launcher23095/API23229/Celery23230/Beat23231/frontend23232 and recorded members remain absent/stale. No SBOM service was started or claimed running. Port5173 node belongs to SafePot per child executable paths, not certified SBOM frontend. No full process arguments/environments or unrestricted server logs were collected. Process checks do not establish database/session/application behavior.

## Helper findings retained accurately

1. Initial read-only preflight collector raised `KeyError: User` because image inspect omitted an optional empty image-config field. No resources/credential existed then. Preserved original helper; recorded omission explicitly as null; subsequent version/image review passed.
2. Initial rendered-config validator asserted integer memory values while Compose5.6.0 emits decimal strings. Exact rendered bytes preserved; explicit numeric conversion verifies precisely536870912/67108864 without changing source or configuration. No resources/credential existed then.
3. First post-start checker failed its two-option cardinality assertion. F was already running/healthy after the one successful startup. Saved network evidence established the exact reviewed options plus explicit IPv4true/IPv6false defaults. Separate protected checker copy accepts only those exact four options and actual matching flags; full subsequent metadata acceptance passed. **No configuration change, startup retry, resource recreation or suppression of the failed helper outcome.**

These are collector/representation failures, not PostgreSQL query or transaction failures. Original artifacts/history preserved in `/Users/ferozebasha/.sbom-uuid-w2-review/w24d-20261019T060938878326Z/helper-history.json`. Final independent resource, ownership-permission metadata, startup/health and preservation checks pass. No authenticated PostgreSQL identity/security/freshness gate was attempted or inferred.

## Evidence, changed files and next gate

[Protected infrastructure acceptance](/Users/ferozebasha/.sbom-uuid-w2-review/w24d-20261019T060938878326Z/infrastructure-acceptance.json) byteSHA256 `b7fbc90503ffcfd812f6fbd58767ade79a926539b7d87add704b3a6a9b2923d5`. Protected0700evidence directory/0600files includes original Compose/render, exact startup claim/argv/result, current image/daemon/capacity/resource inventories, credential metadata **without secret content/digest**, helper originals/corrections/history and process/listener preservation. Evidence file hashes describe nonsecret metadata/source, never password bytes.

Repository changes: this new report and tracker append only. Existing sources/locks/staged migrations/frozen047/application/Compose/evidence unchanged. No new application unit test was needed or run for infrastructure-only provisioning; actual source/configuration/hash/schema-shape/metadata/health/preservation checks are recorded above, not counted as UUID integrity tests. User-facing SQL statements/authentication attempts/migrations/fixtures/193liveintegritycases all0. Container internal initialization/readiness is infrastructure behavior, not credential, catalog or schema acceptance.

**Next separate authorization:** F-only authenticated read-only database identity/authentication/freshness acceptance. Fresh exact resource/secret/source gates, a reviewed dedicated F-only one-attempt entrypoint/manifest with raw-byte hash and distinct action approval, bounded explicit read-only connection/queries/rollback/physicalclose. Observe actual16.15/systemidentifier/databaseOID/internalendpoint/PGDATA/roles/ACLs/extensions/effective-authentication evidence and complete fresh catalog/absent Alembic/application objects. A password supplied and healthy readiness do not prove authentication policy. Do not invent unknown IDs to satisfy a migration manifest. This stage must stop before schema/role/marker/migration execution. Frozen047 requires its own later source-specific unit authorization; W2.4C live execution remains disabled.

**STOP for independent review. W2.4D F INFRASTRUCTURE ACCEPTED only.** Fdatabase/schema baseline NOT ACCEPTED; frozen047NOT RUNTIME ACCEPTED; all193liveintegritycasesNOTEXECUTED. No automatic next task or cleanup.


Final W2.4D preservation: PASS. All2,194other existing repository contents unchanged; tracker retains its original bytes as exact prefix. One new report34; tracker is sole existing-file append. Branch/HEAD, original W2.1–W2.4C sources/packages/locks/migrations/Compose/historical reports preserved. Private0700/0600metadata permissions verified. Exactly1Compose startup/exit0/healthyF,1new container+volume+network;5previous containers/7networks/27volumes and27relevant hostprocessrows preserved. Credential secret contents/digest never included in evidence. UserSQL/authentication/migrations/liveintegritycases0. F INFRASTRUCTURE ACCEPTED; Fdatabase/schema identity/freshness NOT ACCEPTED, frozen047NOT RUNTIME ACCEPTED,193LIVEcasesNOTEXECUTED. STOP independent review.
