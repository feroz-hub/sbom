# W1.4f — PostgreSQL D read-only acceptance diagnosis

**Decision: PARTIAL. Database D NOT ACCEPTED. W1.5 NO-GO.** One authorized authenticated D-only session executed on 2026-10-16; stopped at D04 without retry or reconnection. W1.4e's historical PARTIAL outcome is retained.

## Authority, baseline and evidence

The operator authorized one authenticated, read-only diagnostic session to existing D after fresh identity/isolation checks. W1.4f scope, prerequisites, stopping conditions and acceptance criteria were recorded in the master tracker before execution. Required tracker, W1.4e/W1.4c reports and Compose were read. No Docker lifecycle, configuration, database-state or application change was authorized or performed.

Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`. Existing dirty work preserved; no fetch or fresh origin-equivalence claim. Reviewed Compose SHA256 remains `13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab`.

Private execution evidence: [timestamped JSONL](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w14f-acceptance-20261016T155635863955Z.jsonl). Created exclusively with O_EXCL/O_NOFOLLOW, mode 0600 under the existing UID-501 directory mode 0700. STARTED/check ID was flushed and fsynced before each assertion. Safe values/types, timestamps, exception/SQLSTATE, preflight/final filtered snapshots and reconciliation records are retained; no credential contents or connection strings are recorded. The inline diagnostic was not saved as a repository script.

## Original failed probe review

W1.4e's inline command is recoverable from the preceding conversation tool-call evidence; there is no saved repository probe source. Its first combined assertion required the expected database/current user/session user, major version 16, **`identity[5] == '172.20.0.2'`**, server port 5432, read-only `on`, expected data directory and recovery false. The address query was `inet_server_addr()::text`. Subsequent schema/cluster assertions were behind this combined assertion. Historical raw results and the failing clause were not captured at the time.

The new labelled session confirms the address serialization defect: the actual value is **`'172.20.0.2/32'`**, type `str`. Comparing that text to bare `'172.20.0.2'` fails even though both describe the same host. Offline `ipaddress.ip_interface(actual).ip == ipaddress.ip_address(expected)` returned true; prefix length is 32. PostgreSQL documents that explicit inet-to-text conversion includes the netmask and `host(inet)` removes it. [PostgreSQL 16 network functions](https://www.postgresql.org/docs/16/functions-net.html).

**Confidence: CONFIRMED assertion defect and current reproduction.** The recovered original clause necessarily rejects this result representation. This pinpoints the incorrect original comparison, but does not manufacture an independently captured historical row or certify other original checks. Authentication failure, missing privilege and server misconfiguration are unsupported explanations for the observed D04 failure. No SQLSTATE occurred: local exception `CheckFailed`, SQLSTATE null; W1.4e reported `AssertionError`.

Host publication `127.0.0.1:56041` is the client destination. Server-side bridge address `172.20.0.2` and server port 5432 are the correct separate topology expectations. Neither equality with the host loopback address nor equality with host port 56041 should be required of `inet_server_addr()`/`inet_server_port()`.

## Fresh infrastructure preflight — PASS

Filtered read-only Docker/host metadata at **15:54:30.246689 UTC** matched the reviewed W1.4e final baseline before database access.

| Gate | Actual verified nonsecret evidence |
| --- | --- |
| Local endpoint | `unix:///Users/ferozebasha/.docker/run/docker.sock`, local Unix socket UID 501; explicit Docker CLI `/Applications/Docker.app/Contents/Resources/bin/docker` |
| Daemon | Docker Desktop `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, name docker-desktop, Engine 29.8.2, Compose 5.6.0; no remote endpoint |
| D container | `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e`; project sbom-uuid-w1/service postgres_d; created 15:41:08.546396303Z, started 15:41:08.874607428Z; running/healthy, zero restarts |
| Local image | `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`, postgres:16, linux/arm64; unchanged |
| Original volume | `sbom-uuid-w1_d_pgdata`, local, created 2026-10-16T13:09:16Z, no driver options; source `/var/lib/docker/volumes/sbom-uuid-w1_d_pgdata/_data`, mounted only by exact D at `/var/lib/postgresql/data` |
| Sole D network | `sbom-uuid-w1_d_access`, ID `6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65`; sole member D; bridge IP 172.20.0.2, gateway 172.20.0.1; ordinary NAT/IPv4, IPv6 disabled, ICC=false |
| Recovery network | `sbom-uuid-w1_d_private`, ID `32f906902715f5fe1dee18bcdccc1987c6befd01416cf87dc922f214c2512a5c`, retained empty |
| Actual publication | Actual and requested 5432/tcp bindings exclusively 127.0.0.1:56041, no wildcard/IPv6; lsof com.docker.backend PID 22373 listening there |
| Existing credential | Dedicated external password file inode 75679830, UID 501, 0600, regular/non-symlink, one hardlink, 65 bytes; original timestamps unchanged. Parent inode 75679829, UID 501, 0700 |
| Existing infrastructure | Same SBOM containers, original persistent volumes/application network, process birth/executable/owner tuples and environment-file metadata; no unexpected preflight drift |

## One-session execution and check matrix

The inline Python probe ran with a controlled environment and rejected inherited PG-prefixed variables. It used explicit host and hostaddr 127.0.0.1, port 56041, database uuid_w1_d_rehearsal, user uuid_w1_d_bootstrap, existing password read privately via O_NOFOLLOW, passfile `/dev/null`, no dotenv/application initialization. No password in command arguments, environment, evidence or report. Explicit connection read-only setting and transaction were used; statement timeout 10 seconds, lock timeout 1 second, search_path pg_catalog. Failure unwound the transaction and closed the connection. No reconnect/retry.

All timestamps below are UTC on 2026-10-16. No application tests were executed.

| Check | Expected | Safe actual / type | Result / timestamp / error |
| --- | --- | --- | --- |
| D01 Authentication/session | Exact approved database/current user/session user | uuid_w1_d_rehearsal / uuid_w1_d_bootstrap / uuid_w1_d_bootstrap, all str; server/client UTF8, driver utf-8 | PASS 15:56:35.899403; no exception/SQLSTATE |
| D02 Read-only | transaction_read_only = on | `on`, str | PASS 15:56:35.900194; no exception/SQLSTATE |
| D03 Server | Actual major 16 | server_version_num 160015, int; `16.15 (Debian 16.15-1.pgdg13+2)`, str | PASS 15:56:35.901010; no exception/SQLSTATE |
| D04 Endpoint | Correct internal D IP and port5432, separate host publication | Raw address `172.20.0.2/32`, str, versus bare expected `172.20.0.2`; server port5432, int | **FAIL** 15:56:35.901965; CheckFailed at 15:56:35.902011, SQLSTATE null; incorrect raw-text comparison |
| D05 Cluster | Permitted read-only system identifier | Not queried; no privilege conclusion or cluster ID | UNKNOWN / NOT RUN, recorded 15:57:27.676028 after D04 stop |
| D06 Fresh schema | No imported SBOM application tables | Not queried | UNKNOWN / NOT RUN, 15:57:27.676106 |
| D07 Alembic | No established application revision | Not queried; no stamp/create | UNKNOWN / NOT RUN, 15:57:27.676145 |
| D08 Storage correlation | Observed system identifier correlated with D-only storage | Exact volume metadata known, but cluster/control correlation not executed | UNKNOWN / NOT RUN, 15:57:27.676180 |
| D09 Preservation | Existing SBOM resource/process metadata unchanged | Filtered containers/volumes/networks/mounts/ports/process tuples/environment and password metadata equal; inventory identifier sets equal | PASS existing infrastructure after explicit reconciliation; observations 15:57:29.046028 and 15:59:25.574151 |

D04 also safely observed data directory `/var/lib/postgresql/data/pgdata`, recovery false (bool) and postmaster start `2026-10-16 15:41:09.226049+00`. These do not substitute for D05–D08.

### D09 comparison artifact retained and explained

The first broad comparison recorded FAIL solely for `secret_parent_metadata`: authorized evidence creation changed its directory size 96→128, links 3→4 and mtime/ctime to 1792166195864331057 ns (15:56:35.864331 UTC, evidence creation window). Parent inode/owner/mode remained unchanged. The password file itself was unchanged. This is an expected output-directory mutation, not an infrastructure or credential change.

The next reconciliation additionally flagged ordering of Docker container/network ID lists; sorted identifier sets were equal. Both intermediate records remain in the append-only evidence, followed by D09-RECONCILIATION-FINAL with zero infrastructure differences. No failing database assertion was changed to PASS and no database retry occurred. The observed parent changes are consistent with the authorized new evidence file; metadata alone cannot establish exclusive actor attribution.

## Existing-service preservation and limits

Before/after filtered metadata remained equal for:

- sbom-postgres-1 `5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f`, sbom-redis-1 `135db956488a91d46e4047bcc226ec6f63c3d938349adb80ba2e7b672dc67058`, sbom-mailpit-1 `b342c0214b040a1d5d177d8fbc731d022ac4324707afd6ca1bbb505e0efb9e68`: identities, image/start/state/restarts, selected mounts, ports and network attachments.
- sbom_postgres_data, sbom_redis_data and sbom_default `4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8`: identities, creation/mount/driver and member metadata.
- Launcher23095, API23229, worker23230, Beat23231 and frontend launcher23232: exact process births, executable paths, parents, ownership, groups/sessions. No process arguments/environments exposed; no restart or application probe.
- Root .env, .env.dev.local and dedicated password-file metadata only; no environment-file contents read. Inventory remains four containers, 26 volumes and six networks; zero resources created/removed/modified.

No A/B connection, business-record access, Docker exec/lifecycle, database mutation, SQL export/import, Alembic, UUID/index/backfill, service startup, application tests or Git delivery. Historical A055/B079 classifications were not revalidated. Unchanged resource metadata is not proof of unchanged A/B data. Actual secret-mount readability/byte equality was verified in W1.4e, not repeated here; host credential successfully authenticated this session. No historical pre-replacement cluster identifier exists to compare.

## Smallest correction and next authorization

Correct only the future diagnostic predicate: select `pg_catalog.host(pg_catalog.inet_server_addr())`, or parse the returned inet representation and compare typed host addresses, against the freshly verified D internal IP; compare server port5432 independently. Keep explicit client destination 127.0.0.1:56041 and every identity/isolation gate. Do not change Docker, PostgreSQL settings, storage, credentials or permissions to address this assertion defect.

This task's one-session allowance is exhausted. Obtain **separate authorization for a corrected D-only read-only acceptance session**, with fresh preflight and labelled D01–D09 evidence, especially actual system identifier/privileges, fresh schema, absent Alembic revision and cluster-to-volume correlation. Do not infer those from successful login/healthcheck/image/data-directory metadata. Ordinary bridge egress remains an accepted residual risk; ICC=false is not an outbound firewall.

D remains NOT ACCEPTED and W1.5 NO-GO. Even future D acceptance is not authorization for B schema-only export, D import, parity review or revision establishment; those require a separate W1.5 task. Preserve B's unrelated known drift and all staged migration work.
