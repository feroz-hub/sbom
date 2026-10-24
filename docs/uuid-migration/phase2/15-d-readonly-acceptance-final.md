# W1.4g — Corrected D-only read-only acceptance

**Decision: ACCEPTED — Database D infrastructure only.** All D01–D09 mandatory checks passed on 2026-10-16 in exactly one authenticated read-only PostgreSQL session. No reconnect or retry. W1.5 is **eligible for a separate authorization request, NOT APPROVED and NOT STARTED**.

W1.4c/e/f historical PARTIAL outcomes are preserved. This acceptance supersedes their outstanding D infrastructure acceptance blocker only; it does not accept the B-shaped application schema, revision079, staged UUID migrations, application behavior or production deployment.

## Authority and Git baseline

The user explicitly authorized one new D-only session to127.0.0.1:56041 with existing dedicated credentials, fresh read-only Docker/host metadata, labelled acceptance checks and private nonsecret evidence. W1.4g scope, prerequisites, stop conditions and acceptance gates were appended to the tracker before execution. Required tracker, W1.4f/W1.4e reports and Compose reviewed.

Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`. Existing dirty tree snapshotted before edits:62 modified/untracked file contents, including tracker. No branch/ref/index changes or fresh origin-equivalence claim. Reviewed Compose remains unchanged, SHA256 `13e2ba5f19945dd2c92d708b33199a0a6f89e4cf2556c0f479123f80fc4f73ab`.

## Fresh preflight — PASS

Filtered metadata at **16:07:06.968413 UTC** exactly matched W1.4f's final reviewed snapshot, including password-file/parent metadata and existing SBOM process identities. Identifier inventories were compared as sorted sets.

| Gate | Verified identity / result |
| --- | --- |
| Local Docker | CLI `/Applications/Docker.app/Contents/Resources/bin/docker`; explicit `unix:///Users/ferozebasha/.docker/run/docker.sock`, actual socket UID501; daemon `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, docker-desktop/Docker Desktop, Engine29.8.2, Compose5.6.0. No remote daemon |
| Exact D container | `fb805a9c32dba2e30e01da6a70a26957fcf78caaa4f7bce73418a55a05b3696e`, sbom-uuid-w1-postgres_d-1; project sbom-uuid-w1/service postgres_d; created15:41:08.546396303Z, started15:41:08.874607428Z; running/healthy, zero restarts |
| PostgreSQL image | `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`; digest `postgres@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`; local linux/arm64 postgres:16; unchanged, no pull |
| Original volume | `sbom-uuid-w1_d_pgdata`, local driver/no options, created2026-10-16T13:09:16Z, mountpoint `/var/lib/docker/volumes/sbom-uuid-w1_d_pgdata/_data`; exclusively attached to exact D at `/var/lib/postgresql/data` |
| Sole D network | `sbom-uuid-w1_d_access`, ID `6a4a35eef52453d29e621d6ae192fe85b7c46768d8b16915a8a36713932d6e65`; only D member; IP172.20.0.2/16, gateway172.20.0.1; ordinary NAT, ICC=false, IPv4 only; no sbom_default attachment |
| Retained private network | `32f906902715f5fe1dee18bcdccc1987c6befd01416cf87dc922f214c2512a5c`, sbom-uuid-w1_d_private; empty and unchanged |
| Actual host publication | Requested and actual5432/tcp binding only127.0.0.1:56041; lsof com.docker.backend PID22373 listening there; no wildcard/IPv6 D publication. Successful authenticated session additionally proves loopback connectivity |
| Credential metadata | Existing external disposable-only password file: inode75679830, UID501,0600, regular/non-symlink, one hardlink,65 bytes, unchanged mtime/ctime1792153211012853252ns. Parent inode75679829, UID501,0700. No new/rotated credentials or repository dotenv source |
| Existing services | Existing SBOM containers, volume/network identities, process births/ownership and environment-file metadata match; no unexpected preflight drift |

## Session safety and labelled execution

The first Homebrew Python launch stopped on `ModuleNotFoundError: psycopg` before evidence creation or any connection attempt. Offline import of psycopg3.3.4 in the existing repository virtual environment passed; no dependency installation or application import. The probe then ran with `.venv/bin/python -B` under `env -i PATH=/usr/bin:/bin`; PG-prefixed variables were explicitly rejected. This was not a database retry: **exactly one connection attempt and authenticated session** occurred.

Connection parameters were explicit: host/hostaddr127.0.0.1, port56041, database uuid_w1_d_rehearsal, user uuid_w1_d_bootstrap; password read privately with O_NOFOLLOW from the unchanged external file, checked by fstat, never passed in command arguments/environment/logs. Passfile `/dev/null`; no dotenv, service-file or application-engine fallback. Default read-only on, connection read_only=True, explicit transaction, statement timeout10s, lock timeout1s, connection timeout5s, search_path pg_catalog, client_encoding UTF8. SSL/GSS discovery disabled for this approved local loopback target. Only identity/catalog/control metadata queried; no business records, DDL or DML.

Each check label/expected condition was flushed and fsynced to the private0600 evidence file before assertions; actual safe values/types, status, UTC timestamp and sanitized exception/SQLSTATE fields followed. Every mandatory check below passed; exception_class and SQLSTATE are null. Transaction exited normally and sole connection closed before D09; no automatic reconnect/retry.

| Check | Expected nonsecret condition | Actual safe result / type | Result / UTC time |
| --- | --- | --- | --- |
| D01 | Approved database/current/session user | uuid_w1_d_rehearsal / uuid_w1_d_bootstrap / uuid_w1_d_bootstrap; three str values | **PASS** 16:08:53.542891 |
| D02 | transaction_read_only on | on (str) | **PASS** 16:08:53.543764 |
| D03 | Actual PostgreSQL major16; minor recorded | 160015 (int);16.15 (Debian16.15-1.pgdg13+2) (str) | **PASS** 16:08:53.544512 |
| D04 | Corrected server172.20.0.2:5432, separate host127.0.0.1:56041 | 172.20.0.2 (str),5432 (int); actual Docker host publication independently pinned | **PASS** 16:08:53.545202 |
| D05 | Permitted pg_control_system; positive native cluster identifier | 7697252084555804711 (native int, rendered decimal string for lossless evidence); no privilege elevation | **PASS** 16:08:53.550108 |
| D06 | Fresh user catalogs; no SBOM/application objects | Only public user schema; zero user relations/routines/types/constraints, event triggers, foreign servers or publications; only plpgsql extension in pg_catalog | **PASS** 16:08:53.587749 |
| D07 | No application Alembic baseline | to_regclass(public.alembic_version) IS NULL returned True (bool); no table or revision established | **PASS** 16:08:53.589267 |
| D08 | Current SQL/control-file cluster match and exact preserved D storage | SQL and pg_controldata both7697252084555804711; expected PGDATA, non-recovery false(bool), exact container/exclusive original volume | **PASS** 16:08:53.749841 |
| D09 | Existing resource/process metadata unchanged; only expected evidence creation | Zero differences;4 containers/26 volumes/6 networks, same identifier sets; existing environment/password metadata and process births equal | **PASS** 16:08:55.103289 |

D04 used exactly:

```sql
SELECT
    pg_catalog.host(pg_catalog.inet_server_addr()) AS server_ip,
    pg_catalog.inet_server_port() AS server_port;
```

Only the erroneous inet-to-text comparison was corrected; no runtime setting changed and no other gate was weakened. Host127.0.0.1:56041 and server172.20.0.2:5432 are distinct verified endpoints.

D05 used `SELECT system_identifier FROM pg_catalog.pg_control_system()` and succeeded without changing privileges. The native int identifier was recorded as decimal text in JSON fields to avoid numeric precision loss by downstream readers. No pre-replacement identifier was ever captured; this is a **newly observed** identity, not historical cluster-equality proof.

D06 queried pg_namespace, pg_class (all relation kinds), pg_proc, pg_type, pg_constraint, pg_event_trigger, pg_foreign_server, pg_publication and pg_extension. Normal pg_* and information_schema namespaces were excluded from user-object inventory; public exists normally and plpgsql in pg_catalog is expected. User relations include tables/indexes/sequences/views and were empty; routines/types/constraints also empty. No imported SBOM schema or unexpected application object was observed within these catalogs. No business-row queries or schema modifications.

D07 tested presence with to_regclass without querying a nonexistent version table. With no user relations and public.alembic_version absent, no application Alembic revision is established; **do not call this revision079**.

D08 read data_directory `/var/lib/postgresql/data/pgdata`, pg_is_in_recovery=False and postmaster start `2026-10-16 15:41:09.226049+00`. One read-only `docker --host <verified local Unix endpoint> exec <exact D ID> pg_controldata -D /var/lib/postgresql/data/pgdata` obtained the control-file identifier; only that nonsecret identifier was retained from captured output. This is not another PostgreSQL session or a Docker lifecycle change. SQL/control identifiers match, and PGDATA is under the exact mounted volume destination/source; only D attaches that volume. Name, original creation timestamp, driver/options, mountpoint, exclusivity and pinned container/network topology provide storage correlation. No independent historical cluster/control-file proof or volume-content hash is invented.

## D09 preservation and expected evidence-directory delta

Read-only final snapshot **16:08:54.949808 UTC** equals preflight for filtered container IDs/images/start/state/health/restarts/mounts/publications/endpoints, inspected volume/network metadata, daemon/image/listener, exclusive D volume attachment, environment/password-file metadata and exact process birth/executable/parent/owner/group/session tuples. Whole inventories compared as sorted identifier sets:4containers,26volumes,6networks; zero differences. No genuine drift hidden or failed database check reclassified.

Existing SBOM identities retained:

- PostgreSQL `5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f`, Redis `135db956488a91d46e4047bcc226ec6f63c3d938349adb80ba2e7b672dc67058`, Mailpit `b342c0214b040a1d5d177d8fbc731d022ac4324707afd6ca1bbb505e0efb9e68`.
- sbom_postgres_data, sbom_redis_data and sbom_default `4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8`, same attachments/settings.
- Launcher23095, API23229, worker23230, Beat23231 and frontend launcher23232, exact OS identity tuples unchanged. Only statically extracted process_info/libproc metadata used; no launcher execution, process environment/arguments or application endpoint reads.
- Root .env/.env.dev.local metadata only; contents unopened. Dedicated D password metadata unchanged; no A/B database connection or A/B data-equivalence claim.

Private parent metadata before→after evidence creation: inode75679829 unchanged, UID501/mode0700 unchanged; size128→160, links4→5, mtime/ctime1792166195864331057→1792166933514295312ns. Directory-entry set increased by exactly this new evidence filename. Parent metadata and entry set then remained equal to the explicit post-creation baseline through D09. This expected output creation was accounted before comparison, not retroactively used to override a database failure.

Mounted-secret source/destination/read-only metadata is unchanged. W1.4e already verified root initialization-context guest readability and exact host/guest bytes; that historical content comparison was not repeated here. This session independently authenticated using the unchanged host credential. No claim of a new postgres-OS-account secret-read test.

## Evidence, limits and next action

Private evidence: [W1.4g JSONL](/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w14g-acceptance-20261016T160853514071Z.jsonl), mode0600, UID501, exclusive O_EXCL/O_NOFOLLOW creation under0700 directory. SHA256 `a0c2e88badc49720d38f7e23ca745434bc75144e88bf09817562a4ca94a8d6e1`. Includes check STARTED/result records, safe before/after snapshots, connection-close evidence and the preconnection interpreter note; no credentials or full connection strings.

Exact repository delta: created this report; updated [master tracker](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1). Prior reports, Compose, application/runtime configuration and staged migrations/runners are preserved. Additional authorized output is the private external evidence file linked above. Inline probe source remains recoverable in task tool-call evidence, not a new executable artifact.

Checks actually executed: source/document/Git/hash and safe Docker/host/process metadata; offline driver import; one authenticated read-only D01–D08 session; one D-only pg_controldata metadata read; D09 before/after comparisons; documentation/preservation checks. No application/migration/performance tests, A/B access, remote/production access, Docker lifecycle, image pull, credential change, schema import, pg_dump/pg_restore, DDL/DML, Alembic/stamp, UUID/index/backfill or deployment.

**D infrastructure ACCEPTED at this observation.** Ordinary dedicated bridge egress remains an explicitly accepted residual risk: D may reach host/LAN/internet and host-published services; ICC=false is not an outbound firewall. No egress destinations were probed. Acceptance is a point-in-time observation; fresh target checks remain required for future operations.

**GO to request separate W1.5 authorization only.** Next task must explicitly scope B schema-only export, D import, parity review and any revision-establishment action. No such work was performed or approved here. Schema-only restore does not transfer the alembic_version row; preserve B's actual drift, including missing vex_documents.superseded_by_id FK, and independently review parity before any revision079 establishment. No actual approval manifest was created. W1.6 staged source remains NOT EXECUTED / NOT ACCEPTED; source-review findings, application/security/benchmark/rollback and production gates remain open.

Final documentation verification:61 other pre-existing file contents and tracked binary diff preserved;59 historical tracker rows retained;44 local evidence links/line locations, whitespace, pinned Compose hash/branch/HEAD, private evidence mode/hash and all nine STARTED-before-PASS sequences checked. Git whitespace check passed with filesystem monitor disabled. These are documentation/evidence checks, not application or migration tests.
