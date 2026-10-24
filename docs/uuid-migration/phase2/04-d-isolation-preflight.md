# W1.3 — Disposable database D safety preflight

Read-only preflight, 2026-10-16 (Asia/Kolkata). **Provisioning decision: NO-GO now.** Local Docker/Compose tooling and resource-isolation checks passed as described below, but all five required disposable inputs are unset and Compose runtime configuration validation is **BLOCKED / NOT RUN**. No credential was fabricated, discovered from another configuration or opened to bypass that gate. This report is evidence for a separately authorized provisioning task, not permission to start D.

Read the complete [prepared Compose file](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:1), [W1.2 preparation runbook](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:1) and [W0.1 deployment-target report](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:1). No prior report or Compose file was edited.

## Repository and file baseline

| Item | Observed result |
| --- | --- |
| Branch | `feat/native-user-management`, required branch |
| HEAD | `2f48ff835d9e692fc84b31aaa951aad2495888ac`, matches Phase 1/W0–W1 baseline |
| Initial working tree | 20 modified tracked files, 16 untracked files; all 36 existing modified/untracked file contents snapshotted and preserved |
| Pending work | Existing README/documentation/test and frontend edits, prior UUID reports and prepared infrastructure; no branch/ref update, staging, commit or push |
| Compose content | 66 lines; SHA256 `3122e00cde19515533c62ff1d21667bb5857a493c669f03a990ecb299993edce` |
| Configuration change | None; this file hash and the existing tracked binary diff remain unchanged |

Git inspection used per-command `core.fsmonitor=false`; Git configuration was not modified. This was a local working-tree check, not a remote synchronization check.

## Docker identity: verified locally before daemon inspection

| Item | Read-only observation |
| --- | --- |
| Docker executable | `/usr/local/bin/docker` resolves to `/Applications/Docker.app/Contents/Resources/bin/docker` |
| CLI version | Docker 29.8.2, build `7fc2dff` |
| Selected local context metadata | `desktop-linux`; context inspection itself did not contact a daemon |
| Actual explicit endpoint used | `unix:///Users/ferozebasha/.docker/run/docker.sock` |
| Socket verification | Resolved path is the same local Unix socket, owner UID 501; lsof identified local `com.docker.backend`, PID 22373, holding that socket |
| Daemon name / ID | `docker-desktop` / `1f8c7fe5-5972-4adc-8d6e-363a38572be1` |
| Server | Docker 29.8.2, Docker Desktop, Linux, aarch64, overlayfs; Engine root `/var/lib/docker` within the local Desktop environment |
| Compose version | `Docker Compose version v5.6.0` |

After validating the socket and its local Docker Desktop process, daemon reads explicitly supplied that Unix endpoint and used a minimal child environment containing PATH only. No ambient remote context/host was allowed to redirect those reads. No TCP/SSH/remote daemon was inspected or contacted. This establishes the observed local Desktop instance, not any production/deployment identity.

Only CLI/version/context metadata, daemon info, container/volume/network lists and selected inspect properties were read. No container exec, logs, command arguments, Config.Env or credential file contents were inspected. Compose **version** was invoked; Compose **config** was not. These are distinct checks.

## Resource inventory and collision checks

At `2026-10-16T12:06:19Z`, the explicitly selected daemon inventory contained **3 containers including stopped containers, 25 volumes and 4 networks**. All three containers were running and belonged to Compose project `sbom`. Across container/volume/network Compose labels, 13 project names were present; the other 12 were retained resource metadata, not evidence of 12 running stacks. No `sbom-uuid-w1` project was present on this daemon.

| Existing SBOM resource | Identity and relevant configuration | Isolation result |
| --- | --- | --- |
| `sbom-postgres-1` | Container `5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f`; image postgres:16; started `2026-10-16T08:01:48.746019708Z`; project/service `sbom` / `postgres` | Existing A/B infrastructure; excluded from D |
| PostgreSQL publication | Host `0.0.0.0:55439` and `[::]:55439` → container 5432 | D must not select 55439; no publication changed |
| `sbom_postgres_data` | local driver, no driver options; mounted read/write at `/var/lib/postgresql/data`; Engine source `/var/lib/docker/volumes/sbom_postgres_data/_data`; Compose project/logical volume `sbom` / `postgres_data` | Existing persistent data, never a D volume; content not accessed |
| `sbom-redis-1` | Container prefix `135db956488a`; running redis:7-alpine; `127.0.0.1:56379` → 6379; volume `sbom_redis_data` → `/data` | Existing shared application service/storage; excluded from D |
| `sbom-mailpit-1` | Container prefix `b342c0214b04`; running axllent/mailpit:v1.27; loopback ports 1025/8025 | Existing service; excluded from D |
| `sbom_default` | Network ID `4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8`; bridge, internal=false; attached only to those three containers | D must create its own network, not attach here |

The existing containers' Compose config-file label points to `/Users/ferozebasha/sbom/docker-compose.yml`, distinct from the prepared D file. Relevant volume/network labels and attachments were cross-checked; database names alone were not used as isolation evidence.

| Proposed identity / collision key | Result on selected daemon |
| --- | --- |
| Compose project `sbom-uuid-w1` | No matching container, volume or network project label/name |
| Logical service `postgres_d`; expected container `sbom-uuid-w1-postgres_d-1` | Absent; no existing container uses this service identity |
| Logical volume `d_pgdata`; expected Engine name `sbom-uuid-w1_d_pgdata` | Absent, including project/logical-volume label checks; no volume to adopt |
| Logical network `d_private`; expected Engine name `sbom-uuid-w1_d_private` | Absent, including project/logical-network label checks; no network to adopt |
| D target/disposable identity | No matching D-target resource observed |
| Existing SBOM storage/network overlap | Prepared file has no references to `sbom_postgres_data`, `sbom_redis_data` or `sbom_default`; no external/name override/driver-option reuse |

**No collisions observed**, including retained volumes/networks. This does not reserve resource names or authorize adopting a later collision. Repeat checks immediately before any separately approved provisioning. Actual future D container/volume/network IDs must be recorded and compared; their names/labels are not sufficient proof alone.

## Candidate host port: observation only

**Candidate: 127.0.0.1:56041**, corresponding to future suffix `041`; the suffix was not set in configuration or environment. At the TCP-table/listener observation around `12:08 UTC`, netstat examined 152 TCP entries across tcp4/tcp6/tcp46 with zero local entries for 56041. lsof showed no TCP listener on 56041. Docker inspect metadata showed no container publication on it. Existing 56379 provided a positive control: netstat showed 21 entries and lsof identified the Docker backend listener there.

Port 56379 is in 56000–56999 but already belongs to Redis and is not a candidate. **56041 was not bound, reserved, connected or published.** Availability can change immediately; kernel/listener/publication absence is a point-in-time check, not a guarantee that future bind succeeds. Recheck before approved startup and stop on conflict; do not stop another service or silently choose a fallback.

## Static Compose isolation and portability

Offline YAML parsing and content inspection passed; these are not Compose runtime validation or a test-suite execution.

| Check | Result / exact evidence |
| --- | --- |
| Exactly one PostgreSQL service | PASS: only postgres_d, image postgres:16; [Compose:6](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:6) |
| Loopback publication | PASS: host_ip 127.0.0.1, target TCP 5432, published 56 + required suffix; [Compose:18](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:18) |
| Dedicated persistent volume | PASS: only project-managed d_pgdata, local driver, no external/name/driver_opts, no shared bind; [Compose:48](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:48) |
| Dedicated network | PASS: only d_private bridge, internal=true, attachable=false; [Compose:55](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:55) |
| No application/background services | PASS: no API, Celery, Beat, Redis, frontend, mail, migrate/init job, dependencies, include/extends/build or socket/application mount |
| Credentials/authentication | PASS structurally: required disposable inputs, password-file secret reference, no plaintext password/trust-auth setting, SCRAM init args; [Compose:11](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:11), [Compose:64](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:64) |
| Healthcheck | pg_isready readiness only; not proof of auth, revision, SQL capabilities or target identity. It was not invoked by this task. |
| Compose file path portability | File itself has no hardcoded repository host directory; named volume/internal mount paths are container paths. Password source requires an operator absolute path. |
| Runbook path portability | Its absolute project/file paths exist in this checkout, but are specific to `/Users/ferozebasha/sbom`; `/dev/null` and Unix socket invocation are macOS/Linux-specific. On relocation, explicitly re-review absolute checkout paths and local endpoint. Do not silently use a different working directory/default Compose discovery. |
| Image / network behavior | postgres:16 remains a mutable major tag; no pull or image acceptance performed. Internal-bridge plus loopback publication, SCRAM init, secret readability and actual PG16 behavior remain unverified until authorized provisioning. |

**No mandatory Compose-file correction was identified by static review.** This is not a claim the file passes `docker compose config` or starts correctly. Its interpolation does not itself validate suffix length, credential provenance or external secret permissions; the approved invocation's three-digit check and operator preflight remain required. CLI project/file overrides could defeat naming expectations and must not be added. The runbook's absolute path needs adaptation only if the repository is moved; it is correct here. Any correction discovered by later authorized runtime validation requires a new reviewed change; this task leaves the existing file untouched.

## Five disposable inputs and Compose validation gate

Only presence/nonempty status in the current task environment was checked. Values were not displayed. No root `.env`, `.env.dev.local`, password file or alternate credential store was opened to source inputs.

| Required variable | Function | Current status |
| --- | --- | --- |
| UUID_W1_D_POSTGRES_USER | Disposable bootstrap username; YAML interpolation | UNSET |
| UUID_W1_D_POSTGRES_DB | Disposable database name; YAML interpolation | UNSET |
| UUID_W1_D_PASSWORD_FILE | Dedicated external secret-file path; YAML interpolation | UNSET; no password-file path or contents inspected |
| UUID_W1_D_PORT_SUFFIX | Exactly three decimal digits; YAML interpolation | UNSET; candidate 041 is an observation, not operator selection |
| UUID_W1_D_DOCKER_ENDPOINT | Explicit local Unix endpoint for approved invocation | UNSET; verified local socket is evidence, not a silently supplied operator variable |

Four variables are required by the YAML; the fifth controls the runbook's explicit Docker endpoint. Future operator security review must establish a new disposable-only regular, nonempty password file outside the checkout; resolved-path provenance, no unintended symlink/reuse, owner-only access (normally mode 0600 with restricted parent directory), and readability by the intended image initialization process. No such file was created, opened, printed or generated here; its security is **UNVERIFIED**.

**Compose runtime configuration validation: BLOCKED / NOT RUN.** Although the local CLI/plugin is available, the exact approved clean-environment invocation cannot be populated with already safely supplied inputs. No placeholders, dummy secret, borrowed A/B credentials or alternative env-file were used. Do not label the offline YAML parse as a successful `docker compose config --quiet` run.

Before validation, the operator must provide/approve those five inputs, review the exact invocation from [W1.2](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:41), use one explicit D file/project/local socket and the empty env-file/disabled default-env discovery, then separately authorize `config --quiet`. Do not print resolved secrets or full Config.Env. Successful config validation still would not prove image initialization, volume identity, auth or database readiness.

## Existing A/B targets and service preservation

No PostgreSQL connection or database command was made. A=055 and B=079 remain **prior W0.1 observations**, not freshly reverified revisions. Current read-only Docker evidence confirms the existing SBOM PostgreSQL container, port 55439, persistent volume and network remain present. Start/end selected inspection confirmed identical container IDs/start times/status, port publications, mounts and network IDs for PostgreSQL, Redis and Mailpit. Nothing was started/stopped/reconfigured by the preflight.

Read-only process identity checks found the recorded managed API PID 23229, Celery worker 23230, Beat 23231 and frontend launcher 23232 alive and matching the existing runtime identity records. Process arguments/environment and application endpoints were not inspected in this task; their database selection is not independently recertified. `.env` and `.env.dev.local` inode/size/mtime metadata remained unchanged; credential-file contents were not read. The ignored `.dev-runtime.json` metadata changed during the observation window. This preflight did not write that file; the cause of the change is UNCONFIRMED, so runtime-record preservation is not claimed. The prepared Compose file and all 36 pre-existing modified/untracked contents were preserved.

This confirms no audit-driven configuration/storage/service mutation and unchanged selected metadata; it does not assert that running services performed no normal business writes or that A/B data is byte-identical. Database values, schemas and revisions were deliberately not read.

## Provisioning GO/NO-GO checklist

| Gate | Status | Required action for a separate task |
| --- | --- | --- |
| Correct branch/HEAD; work preserved | PASS | Recheck before execution |
| Local CLI/plugin/socket/daemon identity | PASS at observation | Explicitly use verified local endpoint; stop on identity change/uncertainty |
| No D project/container/volume/network collision | PASS at observation | Repeat inspection; require new D-managed resources, never adopt a collision |
| Candidate loopback port 56041 | PASS at observation only | Operator selects suffix and rechecks availability; no reservation exists |
| One-service isolated Compose content | PASS static review | Keep reviewed file hash or review any correction; do not merge existing stacks |
| Disposable credentials and password-file security | **BLOCKED** | Operator supplies dedicated inputs and confirms file provenance/permissions privately; no reuse or credential generation authorized here |
| Exact approved invocation / config --quiet | **BLOCKED** | Supply/review all five inputs, including endpoint/suffix, and complete actual read-only Compose validation before provisioning |
| Image/runtime initialization | UNVERIFIED | Review local image/digest or separately approve pull; verify platform/init/internal-network behavior during authorized provisioning |
| Authority to create/start D resources | **NOT GRANTED** | Separate explicit authorization for D-only container, volume/network creation/startup and any pull |
| Schema-only B import / revision establishment / W1 rehearsal | FUTURE GATES | Separate approval, drift-preserving comparison and explicit revision review; none is implied by provisioning |

**NO-GO for D provisioning now:** missing operator inputs/secret-file verification and blocked Compose configuration validation prevent readiness. No observed resource collision or CLI failure is the blocker. Once those are closed, current resource/port/daemon checks are repeated and separate provisioning approval is granted, this is suitable to hand off for D-only provisioning. Do not provision, import, stamp, migrate or run tests based solely on this report.

Only repository output created: `docs/uuid-migration/phase2/04-d-isolation-preflight.md`. No Compose edit, application/runtime change, password-file access, credential generation, Docker resource mutation, image pull, database connection/export/restore, Alembic, test, service startup or Git mutation was performed. Temporary secret-free inspection records were kept outside the checkout. Final checks cover evidence links, existing-file preservation and whitespace; they are documentation checks, not runtime acceptance.
