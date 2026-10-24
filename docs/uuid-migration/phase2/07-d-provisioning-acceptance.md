# W1.4c — D provisioning and acceptance

2026-10-16, Asia/Kolkata; execution times below are UTC. **Task result: PARTIAL. Infrastructure IMPLEMENTED; D NOT ACCEPTED. W1.5: NO-GO.** Only the authorized D container, dedicated volume and dedicated network were created. Startup succeeded and the container became healthy, but the required actual loopback port publication is missing. Acceptance stopped at that failure. Nothing was deleted, recreated or reconfigured to bypass it.

## Authorization, baseline and prerequisites

The W1.4c user request explicitly authorized D-only creation/startup and narrowly scoped authenticated read-only verification. It excluded image pulls, A/B connections, application services, schema import, Alembic and UUID implementation. The [master tracker](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1) was updated to IN PROGRESS with scope, prerequisites, blockers, expected resource delta and acceptance criteria before Docker execution; it was marked IMPLEMENTED after successful creation/startup, with acceptance still pending.

Required tracker, [W1.2](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:1), [W1.3](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/04-d-isolation-preflight.md:1), [W1.4a](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/05-d-config-validation.md:1), [W1.4b](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/06-existing-env-integrity-review.md:1) and [Compose file](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:1) were read in full before execution. W1.4b's correction of the rounded-nanosecond alarm remains intact; this task uses decimal strings for nanosecond metadata.

| Baseline / preflight gate | Result |
| --- | --- |
| Git branch / HEAD | PASS: `feat/native-user-management`, `2f48ff835d9e692fc84b31aaa951aad2495888ac` |
| Initial dirty tree | 20 modified tracked files, 20 untracked files; 40 existing contents snapshotted, with tracker update explicitly allowed |
| Reviewed Compose SHA256 | PASS: `3122e00cde19515533c62ff1d21667bb5857a493c669f03a990ecb299993edce`, unchanged |
| CLI / local socket | PASS: `/usr/local/bin/docker` resolves to Docker Desktop bundled CLI; socket `unix:///Users/ferozebasha/.docker/run/docker.sock`, UID 501, real Unix socket with local Docker backend listener |
| Daemon | PASS: `docker-desktop`, ID `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, Docker Desktop 29.8.2, aarch64; matches reviewed daemon |
| Compose | `Docker Compose version v5.6.0` |
| D resource/project collision | PASS before creation: no matching D container/project/service/volume/network names or ownership labels, including retained resources |
| Initial local resource inventory | 3 containers, 25 volumes, 4 networks |
| Port 56041 before creation | PASS: no lsof listener, no Docker publication; TCP table examined 178 entries with zero local 56041 entries. Existing 56379 positive control: listener and 21 TCP entries. No preflight bind/reservation |
| Existing secret | PASS: same external dedicated path, UID 501, regular/non-symlink, nonempty (65 bytes), one link, mode 0600; real parent UID 501/mode 0700; no additional ACL; outside checkout, host-readable |
| Credential provenance | Reused only W1.4a's dedicated file; no root env/A/B/production credential reads, generation or rotation |
| Local image | PASS: `postgres:16` already present, linux/arm64; no image pull or build |

The password source remains `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/postgres-password`, inode 75679830, mtime_ns and ctime_ns `1792153211012853252`. Its contents were not opened, printed or passed in arguments/environment by the agent. Docker was authorized to mount the existing file. Parent/file modes were not relaxed.

## Executed configuration and startup

The invocation followed [the reviewed clean-environment convention](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:56). A new subprocess environment contained only PATH, `COMPOSE_DISABLE_ENV_FILE=1`, and these four dedicated inputs: user `uuid_w1_d_bootstrap`, database `uuid_w1_d_rehearsal`, the existing password-file path and suffix `041`. The explicit verified endpoint was supplied as a Docker argument. No ambient DATABASE_URL, PG*, DOCKER_CONTEXT/HOST or Compose override was inherited; no repository env file was opened.

Both commands used this single base invocation:

```sh
/usr/local/bin/docker \
  --host unix:///Users/ferozebasha/.docker/run/docker.sock compose \
  --env-file /dev/null \
  --project-name sbom-uuid-w1 \
  --project-directory /Users/ferozebasha/sbom/infra/uuid-migration \
  --file /Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml
```

| Command suffix / execution evidence | Result |
| --- | --- |
| `config --quiet`, 13:09:16.055665–13:09:16.317803 | Exit 0; stdout/stderr empty; no full resolved configuration printed |
| `up --detach --no-deps --no-build --pull never postgres_d`, 13:09:16.317803–13:09:17.042572 | Exit 0; resource-status output reported only D network/volume/container creation and container start |

No dependency startup, build, image pull, schema import or extra service command was used. The official image's fresh-volume initialization is part of the explicitly authorized D infrastructure startup; no application schema operation or SQL mutation was separately invoked.

## Actual D resources left running

| Identity | Observed value |
| --- | --- |
| Container | `sbom-uuid-w1-postgres_d-1` |
| Container ID | `1f162bf136f39371dd9a834bf500b3ab0fec401fe41c339c48f82482337beaf0` |
| Created / started | `2026-10-16T13:09:16.664044464Z` / `2026-10-16T13:09:16.861010548Z` |
| State / health / restarts | running / healthy / 0 at post-start inspection |
| Image reference / ID | `postgres:16` / `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54` |
| Local repository digest | `postgres@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54` |
| Image platform / created | linux/arm64 / `2026-09-19T00:39:34.069424262Z` |
| Volume | `sbom-uuid-w1_d_pgdata`, local driver, no driver options, created `2026-10-16T13:09:16Z` |
| Volume source / destination | `/var/lib/docker/volumes/sbom-uuid-w1_d_pgdata/_data` → `/var/lib/postgresql/data`, read/write; configured PGDATA subdirectory `pgdata` |
| Network | `sbom-uuid-w1_d_private`, ID `32f906902715f5fe1dee18bcdccc1987c6befd01416cf87dc922f214c2512a5c` |
| Network properties | bridge, internal=true, attachable=false, IPv4 enabled, IPv6 disabled |
| Network attachment | Only the D container, address `172.19.0.2/16`; D attached only to this network |
| Secret mount | Existing dedicated host file → `/run/secrets/uuid_w1_d_password`, bind mount read-only |

Container/project/service/config-file labels agree with `sbom-uuid-w1`, `postgres_d` and the single reviewed file. Volume/network labels name the correct project/logical resource and target D/disposable=true. A Docker local volume has no separate ID field in the inspected metadata: its identity is recorded by exact Engine name, creation time, mount source, driver/options, labels and attachment set, not an invented UUID.

A post-failure read-only inventory confirmed exactly one added container, one added volume and one added network with the identities above. Only D mounts the new volume, including stopped-container inspection. Its source differs from both existing SBOM volumes; only D attaches to the new network. These metadata facts do not override the failed port acceptance check.

## Acceptance matrix and stop point

The first post-start inspection began at `2026-10-16T13:10:03Z`. Running/healthy, zero restart and reviewed-image/ownership checks passed. The next mandatory check, actual port publication, failed; acceptance stopped immediately. Subsequent reads only inventoried the resources left behind and verified preservation of existing services. No container exec, alternate network path or PostgreSQL connection followed the failure.

| Mandatory postcondition | Result / evidence |
| --- | --- |
| Running and configured healthcheck healthy | PASS; health status healthy, running, restart count 0. Healthcheck output/logs were not dumped |
| Actual container/image/creation identity | PASS; recorded above, container image ID equals the reviewed locally available image |
| PostgreSQL major 16 | NOT INDEPENDENTLY VERIFIED; image tag is postgres:16, but binary/server query was skipped after stop |
| Exclusive actual `127.0.0.1:56041` publication | **FAIL**: desired `HostConfig.PortBindings` is `5432/tcp → 127.0.0.1:56041`, but actual `NetworkSettings.Ports` is `{"5432/tcp": []}`; lsof independently found no 56041 host TCP listener |
| New dedicated/exclusive volume | Metadata verified during left-behind inventory: expected local volume/source/destination, only D attached; no A/B source reuse |
| New isolated/exclusive network | Metadata verified during left-behind inventory: internal dedicated bridge, only D attached; no sbom_default attachment |
| Mounted secret readability by initialization process | NOT ACCEPTED / NOT DIRECTLY VERIFIED: expected read-only bind exists and container is healthy, but no explicit in-container readability probe or authenticated test was run; health alone is insufficient |
| Authenticated, narrowly scoped read-only D connection | SKIPPED after port failure; no password read or DB connection attempted |
| Actual DB/user identity and PG version | SKIPPED; configured disposable names are not authenticated identity evidence |
| Fresh application-free schema / no Alembic revision | UNVERIFIED in catalogs; no schema import/Alembic command was executed by this task. Newly created storage and no import command do not substitute for SQL verification |
| Cluster system identifier / correspondence to new storage | SKIPPED; no SQL or pg_controldata probe executed |

The missing publication was confirmed again in selected Docker metadata and host listener inspection. The network is internal and its endpoint has no gateway; this is relevant diagnostic evidence, **not a proven root-cause conclusion**. No network/Compose correction was made or tested. A later reviewed investigation must establish how to meet both isolation and loopback reachability on this Docker Desktop version; removing isolation or selecting a different path/port is not an approved workaround.

## Existing SBOM preservation

Before/after selected comparisons passed for container IDs, created/start times, image IDs, restart counts, states, labels, mounts, port publications and network attachments. Both existing volumes' driver/options/source/creation/labels and the existing network's ID/options/attachments remained unchanged.

| Existing resource | Preserved identity / publication |
| --- | --- |
| `sbom-postgres-1` | `5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f`; wildcard IPv4/IPv6 port 55439 → 5432 |
| `sbom-redis-1` | `135db956488a91d46e4047bcc226ec6f63c3d938349adb80ba2e7b672dc67058`; loopback 56379 → 6379 |
| `sbom-mailpit-1` | `b342c0214b040a1d5d177d8fbc731d022ac4324707afd6ca1bbb505e0efb9e68`; existing loopback 1025/8025 |
| `sbom_postgres_data` | Same local volume/source mounted by existing PostgreSQL; no new attachment |
| `sbom_redis_data` | Same local volume/source mounted by existing Redis; no new attachment |
| `sbom_default` | ID `4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8`; same three existing attachments, no D |

Read-only macOS process metadata also matched exactly before/after for launcher PID 23095, API 23229, worker 23230, Beat 23231 and frontend 23232: PID/birth/executable/UID/PPID/PGID/SID unchanged. Their environments, arguments and application endpoints were not read. Nothing was stopped, restarted, signaled or reconfigured.

Root `.env` and `.env.dev.local` were not opened or written; exact metadata was preserved. Existing file contents, reviewed Compose and prior reports were preserved, except the explicitly authorized tracker update. A/B databases were not connected; no claim of unchanged business data or freshly verified A/B revision follows from unchanged infrastructure metadata.

## Decision, remaining resources and W1.5 blockers

**PARTIAL / NOT ACCEPTED:** D infrastructure was created and started, but mandatory loopback publication failed. All three new D resources listed above remain present; the container was running/healthy at final inventory. The existing external password file remains in place. No cleanup, stop, recreation, permission change or retry occurred. A failed startup acceptance is not permission to delete its volume or rerun initial provisioning against a collision.

Before W1.5 can be considered, obtain separate scope for diagnosis and a concrete reviewed D-only correction of the publication issue, preserving existing services, secret privacy and dedicated resource isolation. Any restart/recreate/teardown or Compose change needs its own authorized plan and resource targets. Then rerun **all** D acceptance checks, including authenticated read-only DB/user/version, actual secret use, fresh schema/no Alembic marker and cluster/storage correlation. Do not accept D from health alone.

**W1.5 schema import/parity verification remains NO-GO.** This task authorizes neither B extraction nor schema restore/revision establishment. Preserve B's actual missing VEX supersession FK and other documented drift in any later approved baseline; schema-only import will not transfer the Alembic revision row. UUID migration implementation, performance/authorization tests and production/public cutover remain separate open gates.

Exact repository changes: created `docs/uuid-migration/phase2/07-d-provisioning-acceptance.md`; updated `docs/uuid-migration/MIGRATION_MASTER_TRACKER.md`. Executed checks were preflight metadata/port/image/privacy checks, Compose config/start, D health/isolation metadata, existing-resource/process preservation and documentation checks. No application/migration/browser/performance test suite, DB connection, SQL, container exec, schema export/import, Alembic, image pull/build, unrelated service start, resource deletion or Git commit/push/checkout/reset was performed.

Final documentation verification passed: all 39 pre-existing modified/untracked file contents other than the authorized tracker matched their snapshots; tracked binary diff unchanged; all 16 prior completed-task ledger rows retained verbatim; 36 report/tracker evidence links checked; whitespace and exact environment/secret metadata preservation checks passed. Only the report and tracker changed in the checkout. These checks do not close the failed D acceptance gate.
