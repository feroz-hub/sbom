# W1.4e — D network correction and acceptance gate

**LATEST OUTCOME — authorized continuation: IMPLEMENTED / PARTIAL; D NOT ACCEPTED; W1.5 NO-GO.** The operator supplied the exact confirmation after the first report. The reviewed network correction and D-only container replacement were executed successfully. Actual loopback publication/listener now pass; the existing volume/host password and SBOM infrastructure are preserved. A mandatory D-only read-only acceptance probe raised an AssertionError without identifying its exact subcheck; no retry or rollback was attempted. Independent PG identity/schema/cluster acceptance is incomplete. See the authorized execution section below for exact evidence and limitations.

## Historical pre-authorization record — preserved, superseded by continuation below

2026-10-16, Asia/Kolkata; observation times UTC. **W1.4e BLOCKED — operator authorization NOT RECEIVED. Correction NOT IMPLEMENTED; D NOT ACCEPTED; W1.5 NO-GO.**

The task includes a mandatory confirmation template, but no separate affirmative operator confirmation accepting outbound connectivity was supplied. The quoted template inside the task is not that confirmation. Only the authorized read-only preflight and proposed correction review were performed. No Compose file or Docker resource was modified; no PostgreSQL connection, credential-content read, TCP probe, container exec or application test occurred.

## Authorization, scope and baseline

Required exact operator confirmation remains pending:

> I authorize W1.4e to replace only Database D's container, preserve its existing volume and credentials, and use a dedicated ordinary bridge. I accept that this bridge may permit outbound connectivity.

This gate comes directly from section 2 of the user's W1.4e request. If zero egress is required, this ordinary-bridge proposal is NO-GO; obtain a separately reviewed proxy/egress-control alternative. No implicit authorization is inferred from task title, prior provisioning approval, tracker status or container health.

Read tracker, W1.4c acceptance, W1.4d diagnosis, original Compose and preparation/preflight/config-validation/environment-integrity reports. Recorded W1.4e scope, prerequisite checks, proposed delta, acceptance/failure boundaries and missing authorization in the tracker before daemon preflight.

Branch feat/native-user-management; HEAD 2f48ff835d9e692fc84b31aaa951aad2495888ac. Task-start snapshot: 60 existing modified/untracked contents, including 20 modified tracked files. Only tracker update is permitted among existing files; preserve other 59 and tracked binary diff. No branch/ref/index/commit/push/reset/stash/pull action or origin-sync claim.

Original/current Compose: [docker-compose.uuid-w1.yml](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:1), SHA256 **3122e00cde19515533c62ff1d21667bb5857a493c669f03a990ecb299993edce**. It is unchanged.

## Fresh read-only preflight

T1 2026-10-16T15:31:09.446707+00:00; T2 2026-10-16T15:32:18.765098+00:00. All inspected resource/process/password/environment metadata matched start/end. No unexpected relevant drift was observed; historical D nonpublication persists.

| Gate | Verified observation / limitation |
| --- | --- |
| Local CLI/socket | CLI resolves to /Applications/Docker.app/Contents/Resources/bin/docker; explicit unix:///Users/ferozebasha/.docker/run/docker.sock, actual local socket UID 501 |
| Daemon | docker-desktop, Docker Desktop, Engine 29.8.2/aarch64; ID 1f8c7fe5-5972-4adc-8d6e-363a38572be1, matches W1.4c/d. No remote context/endpoint used |
| Compose | Plugin 5.6.0; original hash unchanged. Updated config validation NOT RUN because no edit/authorization |
| D container | 1f162bf136f39371dd9a834bf500b3ab0fec401fe41c339c48f82482337beaf0; created 2026-10-16T13:09:16.664044464Z, running/healthy, zero restarts; same start 2026-10-16T13:09:16.861010548Z |
| Ownership/provenance | Project sbom-uuid-w1, service postgres_d, D/disposable=true labels; single reviewed absolute Compose path and /dev/null environment-file label. Only recorded D container/volume/network in this project |
| Local image | postgres:16 already available, linux/arm64; image ID sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54; digest postgres@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54. D uses this exact ID. No pull/build; actual server major version NOT queried |
| Requested host binding | 5432/tcp → 127.0.0.1:56041 in HostConfig |
| Actual publication | NetworkSettings.Ports remains {"5432/tcp": []}. No published host port or wildcard/IPv6 D publication exists; required loopback endpoint is still absent |
| Host listener | lsof found no 56041 TCP listener at T1/T2, return 1 with empty stdout/stderr; 56379 listener is positive control. Free port is a point-in-time observation, not reserved/bound |
| Original private network | sbom-uuid-w1_d_private, ID 32f906902715f5fe1dee18bcdccc1987c6befd01416cf87dc922f214c2512a5c; created 2026-10-16T13:09:16.521058256Z; internal bridge, IPv4=true/IPv6=false, only D attached. Endpoint gateway empty; no application-network attachment |
| Proposed access network | No sbom-uuid-w1_d_access resource found. No new bridge created or adopted |
| Exact existing storage | sbom-uuid-w1_d_pgdata, local driver, created 2026-10-16T13:09:16Z, no driver options; mountpoint /var/lib/docker/volumes/sbom-uuid-w1_d_pgdata/_data → /var/lib/postgresql/data, exclusively attached to recorded D |
| Password metadata only | Existing external dedicated file, inode 75679830, 65 bytes, UID 501, regular/non-symlink, one hard link, 0600; exact mtime_ns/ctime_ns 1792153211012853252, matching W1.4c. Parent inode 75679829, UID 501, 0700/non-symlink. No content read/hash/rotation/chmod |
| Secret mount metadata | Read-only bind from dedicated file to /run/secrets/uuid_w1_d_password. Actual readability inside container NOT tested |
| Infrastructure inventory | Four container IDs, 26 volume names and five network IDs stable across preflight. No new/replaced/deleted resources |

The D volume has no separate immutable Engine UUID exposed by the inspected metadata; identity evidence combines exact name, driver, creation, mountpoint and exclusive attachment, not name alone. The historical cluster system identifier was never independently obtained; cluster equality cannot be asserted. No existing D cluster/user/database/schema/version was accessed here.

## Proposed exact Compose correction — NOT APPLIED

Only the service network attachment changes, plus a new dedicated ordinary logical d_access network with project-derived Engine name sbom-uuid-w1_d_access. Retain the original d_private definition and actual network for recovery, unused after future replacement. Existing single PostgreSQL service/image/user/database/secret/volume/command/healthcheck/security/loopback port configuration remains unchanged.

The following exact in-memory proposal was generated against the current original, without writing a candidate config file. Its proposed SHA256 is **13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab**. This is a review hash of unapplied UTF-8 text, not the current on-disk Compose hash or a validated configuration.

```diff
--- a/infra/uuid-migration/docker-compose.uuid-w1.yml
+++ b/infra/uuid-migration/docker-compose.uuid-w1.yml
@@ -31,7 +31,7 @@
     secrets:
       - uuid_w1_d_password
     networks:
-      - d_private
+      - d_access
     security_opt:
       - no-new-privileges:true
     healthcheck:
@@ -53,6 +53,19 @@
       io.sbom.uuid-migration.disposable: "true"

 networks:
+  d_access:
+    driver: bridge
+    internal: false
+    attachable: false
+    enable_ipv4: true
+    enable_ipv6: false
+    driver_opts:
+      com.docker.network.bridge.gateway_mode_ipv4: "nat"
+      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
+      com.docker.network.bridge.enable_icc: "false"
+    labels:
+      io.sbom.uuid-migration.target: D
+      io.sbom.uuid-migration.disposable: "true"
   d_private:
     driver: bridge
     internal: true
```

Dedicated bridge NAT/loopback default/ICC controls are documented by [Docker bridge options](https://docs.docker.com/engine/network/drivers/bridge/#options). Support/config behavior on this installed Engine must still be validated. Explicit service host_ip=127.0.0.1 remains authoritative; the bridge default is supplementary. ICC=false restricts inter-container connectivity on that bridge; it is **not a general outbound firewall**. Attachable=false is not a Docker-administrator access boundary.

A normal NAT bridge may permit D to initiate outbound host/LAN/internet traffic and reach existing host-published services without joining sbom_default. Existing application PostgreSQL currently publishes 55439 on IPv4/IPv6 wildcard addresses; this task does not modify or connect to it. The proposal is **not zero egress**. Actual destination reachability was not probed. No shared host/daemon firewall change, additional proxy/image, shared network, wildcard D publication or IPv6 publication is proposed.

## Future correction procedure — blocked, NOT RUN

After exact confirmation and a fresh passing preflight, apply only the reviewed diff and verify its new source hash. Preserve the exact D volume/password/image/bootstrap values. Revalidate the current local image and original storage identities before replacement; do not create a replacement data volume.

Use the reviewed clean-environment subprocess convention: only PATH, COMPOSE_DISABLE_ENV_FILE=1 and the four dedicated nonsecret file/user/database/port inputs, no ambient DATABASE_URL/PG*/DOCKER_CONTEXT/Compose override. Endpoint is the explicit verified local Unix socket argument. Single base invocation:

```text
/Applications/Docker.app/Contents/Resources/bin/docker \
  --host unix:///Users/ferozebasha/.docker/run/docker.sock compose \
  --env-file /dev/null \
  --project-name sbom-uuid-w1 \
  --project-directory /Users/ferozebasha/sbom/infra/uuid-migration \
  --file /Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml
```

Prepared inputs retain UUID_W1_D_POSTGRES_USER=uuid_w1_d_bootstrap, UUID_W1_D_POSTGRES_DB=uuid_w1_d_rehearsal, existing dedicated UUID_W1_D_PASSWORD_FILE path and UUID_W1_D_PORT_SUFFIX=041; UUID_W1_D_DOCKER_ENDPOINT is the verified socket above. Password itself is never an argument or environment variable.

Only after authorization/edit: suffix config --quiet, then inspect only nonsecret resolved structure. On success, targeted suffix **up --detach --no-deps --no-build --pull never --force-recreate postgres_d** applies only the selected service, retaining named-volume configuration. [Docker Compose up](https://docs.docker.com/reference/cli/docker/compose/up/) documents forced service recreation and mounted-volume preservation; correct targeting/storage must still be verified before/after. No command in this paragraph was executed.

Expected authorized delta: old D container gracefully replaced by one new D container, one new dedicated d_access bridge, same volume/password/image, old private network retained with no endpoints. Never run old/new PostgreSQL simultaneously on the data directory. No down/down -v/prune/orphan cleanup/image pull/network connect/disconnect or volume deletion/recreation.

Any error or uncertain recreation outcome: stop, inventory actual container/network/storage/port state, leave resources intact and report PARTIAL/NOT ACCEPTED. No automatic retry, port change, weaker secret permission, unrelated restart or unreviewed rollback. The present read-only task left only the same original D resources; there is no partial correction to clean up.

## Existing SBOM infrastructure preservation

All selected container IDs/image/start/state/restart/mount/network/requested and actual publication metadata matched T1/T2. Historical W1.4c/d records agree with the observed identities.

| Existing resource | Exact identity / state retained |
| --- | --- |
| sbom-postgres-1 (shared A/B local container) | 5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f; running/healthy, zero restarts, start 2026-10-16T08:01:48.746019708Z; sbom_postgres_data → /var/lib/postgresql/data; 55439 published on 0.0.0.0 and :: |
| sbom-redis-1 | 135db956488a91d46e4047bcc226ec6f63c3d938349adb80ba2e7b672dc67058; running/healthy, zero restarts; sbom_redis_data → /data; 127.0.0.1:56379 |
| sbom-mailpit-1 | b342c0214b040a1d5d177d8fbc731d022ac4324707afd6ca1bbb505e0efb9e68; running/healthy, zero restarts; no data mount; 127.0.0.1:1025 and :8025 |
| sbom_postgres_data | local driver, created 2026-07-17T18:04:02Z; exact name/driver/mountpoint/options unchanged |
| sbom_redis_data | local driver, created 2026-09-27T03:23:07Z; exact name/driver/mountpoint/options unchanged |
| sbom_default | 4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8; created 2026-10-01T03:08:14.738262464Z; only the same three SBOM container endpoints, unchanged network settings |
| Launcher/API/worker/Beat/frontend launcher | PIDs 23095/23229/23230/23231/23232; exact OS birth/executable/UID/PPID/PGID/SID tuples unchanged, matching prior reports |
| .env / .env.dev.local | Exact safe inode/size/owner/mode/mtime_ns/ctime_ns/symlink metadata unchanged T1/T2 and matches W1.4b historical values. No file contents or semantic-equivalence claim |

Process evidence uses only the statically inspected process_info function from scripts/dev.py with libproc; no Runtime methods, process arguments/environments or application endpoints were read. API/worker/Beat births are 1792137714:732547 / :736336 / :738942; launcher birth 1792137702:755614; frontend launcher birth 1792137714:742176. Roles are retained historical attribution, not a new inspection of each process's engine/credentials. No application service was stopped/restarted/signaled/reconfigured. No A/B connection or business-data equivalence claim.

## Acceptance checklist — not executed beyond preflight

| Mandatory condition | This task's actual result |
| --- | --- |
| Exact operator authorization / outbound acceptance | **BLOCKED — absent** |
| Local branch/hash/daemon/current D/storage/secret/image/no d_access collision/listener preflight | PASS at recorded observations, with normal freshness limitations |
| Changed Compose config validation / reviewed applied hash | NOT RUN / NOT APPLIED; original remains unchanged |
| D-only replacement / new container / new ordinary network | NOT RUN; original container/internal network retained |
| Actual new loopback publication / listener / TCP | FAIL remains: no actual mapping/listener. No TCP probe performed |
| Same original volume/image/password after replacement | Replacement NOT RUN; original identities metadata retained |
| Secret readability inside D | NOT RUN |
| Authenticated D-only read-only connection | NOT RUN |
| Actual PostgreSQL version/database/user/cluster/system identifier | NOT RUN / UNKNOWN; image tag/health is insufficient |
| Fresh schema / absent SBOM tables / absent Alembic revision | NOT RUN / UNVERIFIED |
| Historical cluster identifier equality | Cannot be claimed; prior independent observation unavailable. Future record newly observed ID and correlate exact preserved volume |
| Existing infrastructure metadata/process preservation | PASS T1/T2; no A/B data-level certification |
| Runtime/migration/application tests | NOT RUN |

Only safe source/Git/metadata reads, local explicit-endpoint Docker info/inspect/list/compose-version, lsof metadata, OS process metadata, in-memory diff/hash generation and documentation checks were executed. No docker compose config/up/down/run, container exec/log dump, pull/build/network mutation, schema import, SQL/Alembic/UUID/index/backfill, DB access, secret-content access, application startup/test or Git delivery.

## Decision and next action

**W1.4e BLOCKED; correction NOT IMPLEMENTED; D NOT ACCEPTED.** Missing exact operator confirmation is the execution blocker; all safety checks must be freshly repeated after it arrives. Ordinary-bridge outbound risk remains unaccepted. If zero egress is required, reject this solution and request a separately approved proxy-based alternative.

**W1.5 remains NO-GO.** A future accepted D would still require separately authorized B schema export/D import/parity and explicit revision review; this task grants none. No UUID migration or production authority is inferred.

Exact file delta: created docs/uuid-migration/phase2/13-d-network-correction-acceptance.md; updated docs/uuid-migration/MIGRATION_MASTER_TRACKER.md. Compose, prior reports, runtime/application configuration, credentials, all migration source and Docker resources unchanged.

Final documentation verification: 59 other pre-existing file contents and tracked binary diff matched task-start evidence; all 22 historical ledger rows and 12 Phase 1 open-issue rows retained verbatim. Exactly the new report and tracker changed; 40 local evidence links/nonblank line locations and whitespace checks passed. Original Compose hash unchanged; proposed new hash remains an unapplied review artifact. No application/database/runtime test was executed. W1.4e BLOCKED; D NOT ACCEPTED; W1.5 NO-GO.


## Authorized continuation — actual correction and partial acceptance

Operator authorization received verbatim:

> I authorize W1.4e to replace only Database D's container, preserve its existing volume and credentials, and use a dedicated ordinary bridge. I accept that this bridge may permit outbound connectivity.

The tracker was updated IN PROGRESS before fresh preflight/mutation. This authorizes only the reviewed D-only correction and narrow acceptance; no B import, Alembic, UUID/index/backfill/application change or production action.

### Fresh approved preflight and applied configuration

Fresh observation 2026-10-16T15:40:24.686969+00:00: branch/HEAD and original Compose hash matched. Explicit UID-501 local Desktop socket/daemon ID matched; original D/container/image/private network/exact volume and secret metadata matched the earlier reviewed snapshots. 56041 was unoccupied; d_access absent. All three existing SBOM containers, volumes/network and launcher/API/worker/Beat/frontend process birth tuples were unchanged. Local postgres:16 exact image was already available; no pull.

Applied exactly the diff recorded above. Original SHA256 3122e00cde19515533c62ff1d21667bb5857a493c669f03a990ecb299993edce → new on-disk SHA256 **13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab**. Earlier statements that the diff was unapplied refer only to the preserved first pass. No additional Compose changes.

At 2026-10-16T15:40:45.843292Z, clean-environment config --quiet exited 0 with empty stdout/stderr. A captured config --format json result was checked in memory, never printed in full: exactly postgres_d; same postgres:16, user/database/secret reference; unchanged nocopy named volume sbom-uuid-w1_d_pgdata; only d_access attached; explicit 127.0.0.1:56041:5432; no build/depends_on/env_file/network_mode overrides; dedicated ordinary bridge with NAT/loopback/ICC=false and IPv4-only options. The unused private definition remains on disk.

Using the single absolute Compose file/project/directory, explicit verified Unix endpoint and --env-file /dev/null base recorded above, issued exactly once:

```text
up --detach --no-deps --no-build --pull never --force-recreate postgres_d
```

Exit 0 at **2026-10-16T15:41:08.964545Z**; stdout 0 bytes, stderr 350 bytes of captured Compose progress (not container logs). No build/pull/dependency startup, down, volume removal, wildcard/orphan cleanup or retry. Scope of actual change: replace D container and add d_access network. Private network retained unused.

### Actual resource identities and publication

Final read-only inventory 2026-10-16T15:44:56.187274+00:00:

| Field | Actual observed result |
| --- | --- |
| Original D replaced | 1f162bf136f39371dd9a834bf500b3ab0fec401fe41c339c48f82482337beaf0 no longer listed |
| New D | fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e; name sbom-uuid-w1-postgres_d-1; project sbom-uuid-w1/service postgres_d |
| Creation / start | 2026-10-16T15:41:08.546396303Z / 2026-10-16T15:41:08.874607428Z; running, healthy, zero restarts |
| Image | sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54; same linux/arm64 postgres:16 local image and digest as preflight; actual SQL server version not accepted |
| Actual Docker publication | 5432/tcp → [{HostIp:127.0.0.1, HostPort:56041}]; requested binding matches. No wildcard/IPv6 publication |
| Host listener | com.docker.backend PID 22373, n127.0.0.1:56041; no wildcard/IPv6 D listener |
| Loopback TCP probe | 127.0.0.1:56041 socket connection attempted before SQL acceptance assertions; no socket error reported. This is not authenticated PostgreSQL acceptance |
| Access network | sbom-uuid-w1_d_access; ID 6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65; created 2026-10-16T15:41:08.370037303Z; ordinary bridge, internal=false/attachable=false, IPv4=true/IPv6=false; only new D attached |
| Network options | gateway_mode_ipv4=nat, host_binding_ipv4=127.0.0.1, enable_icc=false; D endpoint 172.20.0.2/16, gateway 172.20.0.1 |
| Application network exclusion | D attaches only d_access, absent from sbom_default; no application/shared network added |
| Retained private network | 32f906902715f5fe1dee18bcdccc1987c6befd01416cf87dc922f214c2512a5c; same creation/options, now zero endpoints |
| Preserved data volume | sbom-uuid-w1_d_pgdata, original creation 2026-10-16T13:09:16Z, local driver/no options, same mountpoint/source and /var/lib/postgresql/data destination, only new D attached. No volume creation/removal/reset |
| Inventory delta | Four containers before/after (one replaced), 26 same volume names, five→six networks (only new d_access) |

This controlled topology change restored actual host publication. It supports the earlier internal-only-network explanation operationally; no claim of a traced exact Engine code-path root cause.

### Secret-mount reconciliation and readability

Host secret remained inode 75679830, UID 501, one-link regular/non-symlink, 65 bytes, mode 0600; exact mtime_ns/ctime_ns 1792153211012853252 and private parent unchanged. No credentials generated/rotated/overwritten or permissions weakened.

A strict old/new mount comparison initially stopped because Engine now reports the secret bind source with /host_mnt prefixed to the same /Users/... suffix. Subsequent guest stat showed inode 4, UID 0, 65 bytes, 0600, rather than the host inode/UID; assuming cross-filesystem inode equality was an overly strict verification assumption, not proof of a different credential. The PG data-volume mount itself did not change.

Reconciled safely at **2026-10-16T15:42:56.677837Z**: the approved host file was opened O_NOFOLLOW in memory, and new D's mounted file was read through a captured exec pipe only in the root initialization context. In-memory constant-time comparison proved exact byte equality; no secret bytes or hashes were printed, stored in the report, passed as arguments/environment values or retained as an evidence artifact. Root test required regular/non-symlink/readable/nonempty mount. Result PASS: same credential bytes; readable by root initialization context; mount remains read-only. Do not claim readability as the unprivileged postgres OS account, which was not tested or required for root entrypoint file_env reading.

[Docker bind-mount documentation](https://docs.docker.com/engine/storage/bind-mounts/) explains Desktop's VM/host-path handling; path/inode translation alone was not accepted as identity proof. Byte equality plus unchanged host metadata resolved this check without relaxing permissions or changing the mount.

### Failed D-only read-only acceptance probe — stop honored

One probe attempted only exact D, no A/B or remote endpoint: explicit host/hostaddr 127.0.0.1, port 56041, database uuid_w1_d_rehearsal, user uuid_w1_d_bootstrap, existing password held in process memory, passfile=/dev/null, SSL/GSS discovery disabled, no inherited PG* overrides, default_transaction_read_only=on and bounded statement/lock timeouts. It requested an explicit read-only transaction and only identity/catalog/control metadata; no business rows or mutation statements were part of the probe.

The script exited 2 with **AssertionError, SQLSTATE null, details suppressed** between the secret check and final inventory. It did not retain a substep label or returned identity values before each assertion. Therefore the exact failed assertion is **UNKNOWN**; neither a password failure, wrong database, server version, schema content nor cluster mismatch is established. The sanitized output is not sufficient to certify which later checks completed. The missing substep instrumentation is a verification-harness limitation and must be corrected in a separately authorized diagnosis.

No assertion was weakened and no database acceptance retry/reconnect was attempted afterward. Only safe Docker/host/process preservation inventory followed. No container/network retry, rollback or credential change. Do not infer authenticated readiness from running/healthy status or from the exception category. No raw driver exception/connection string/secret was exposed.

| Acceptance condition | Final status |
| --- | --- |
| Exact authorization / outbound-risk acceptance | RECEIVED |
| Fresh preflight / reviewed Compose delta/hash / clean config | PASS |
| D-only replacement / same volume/image/credential | PASS by actual metadata and secret byte comparison |
| Dedicated ordinary network / private retained / no app attachment | PASS |
| Actual loopback Docker mapping / host listener | PASS |
| Socket-level loopback connectivity | Probe reached assertions without a socket error; insufficient for authenticated acceptance |
| Root initialization-context mounted secret readability | PASS; no postgres-OS-account claim |
| Authenticated D-only identity/read-only transaction acceptance | **NOT ACCEPTED — probe failed an unidentified assertion** |
| Actual PG16 version/database/user/cluster identity | **UNVERIFIED / not recorded as passed** |
| Fresh schema / no imported SBOM relations / no Alembic baseline | **UNVERIFIED / not recorded as passed** |
| Cluster system identifier / control-file-to-volume correlation | **UNVERIFIED**; no independently retained observation. Earlier cluster ID unavailable, so equality is never claimed |
| Existing SBOM resource/process/password/env metadata preservation | PASS before/after |
| Application/database application/migration tests | NOT RUN; this failed probe is acceptance metadata work, not a test-suite pass |

### Preservation, residual risk and resources left behind

Existing sbom-postgres-1, sbom-redis-1 and sbom-mailpit-1 retain exact IDs/image/start/restart/state/mount/port/network metadata from the fresh preflight. sbom_postgres_data, sbom_redis_data and sbom_default remain unchanged. Launcher/API/worker/Beat/frontend PIDs and exact births/executables/UID/PPID/PGID/SID match; host .env/.env.dev.local and password metadata also match. No A/B connection or business-data equivalence claim. No running application configuration or service was changed.

Resources intentionally retained: new running D container fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e; original dedicated D volume/password; new ordinary access network 6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65; original empty private network. The original container was removed by the one approved Compose replacement. No automatic rollback/cleanup followed acceptance failure.

Outbound connectivity risk was explicitly accepted. D is not zero-egress isolated; it may reach host/LAN/internet and host-published SBOM services. ICC=false is not an outbound firewall. No outbound probes or shared firewall modifications were performed.

**Final W1.4e outcome: PARTIAL / correction IMPLEMENTED; D NOT ACCEPTED. W1.5 remains NO-GO.** Next task must explicitly authorize narrowly scoped diagnosis of the failed D-only metadata assertion with per-substep nonsecret evidence, followed by acceptance only if every mandatory condition passes. Do not rerun correction or delete/recreate storage. No B schema export/import, Alembic baseline/UUID execution, index/backfill/application tests or production work is authorized here.

Authorized continuation file delta: updated existing Compose, this report (with historical first pass retained) and master tracker only. Source migrations/runners/prior reports and existing unrelated dirty work preserved.

Authorized-continuation final documentation verification: 58 other pre-existing file contents and tracked binary diff preserved; 23 earlier ledger rows and all 12 Phase 1 issue rows retained verbatim. No new files in the continuation; exactly Compose/report/tracker updated. New Compose hash, 41 local evidence links/nonblank line locations and whitespace checks passed. Git branch/HEAD unchanged. Actual runtime preservation checks are separately recorded above; no passed PostgreSQL acceptance or application/migration test is inferred. Final status remains PARTIAL / D NOT ACCEPTED / W1.5 NO-GO.
