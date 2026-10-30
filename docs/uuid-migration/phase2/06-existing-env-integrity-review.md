# W1.4b — Existing environment configuration integrity review

2026-10-16, UTC observations with local timezone Asia/Kolkata. **Recommendation: conditional GO for a separately authorized, D-only provisioning task. No provisioning is authorized or performed here.** The W1.4a environment metadata alarm is explained by lossy timestamp serialization, not evidence of an environment-file rewrite. There is no confirmed configuration-integrity blocker to an independently configured D startup. Existing A/B configuration semantics are not recertified.

Read the complete [W0.1 readiness report](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:1), [W1.3 preflight](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/04-d-isolation-preflight.md:1) and [W1.4a validation report](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/05-d-config-validation.md:1). This report corrects the interpretation of W1.4a's [preservation exception](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/05-d-config-validation.md:103); prior reports remain untouched.

## Repository preservation and inspection boundaries

Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`, matching the prior baseline. Initial working tree: 20 modified tracked files and 18 untracked files. All 38 existing modified/untracked file contents were snapshotted for preservation. Git reads used per-command `core.fsmonitor=false`; no checkout, reset, pull, index/ref change, commit or push.

The reviewed Compose SHA256 remains `3122e00cde19515533c62ff1d21667bb5857a493c669f03a990ecb299993edce`. Only this report is added. No new preservation script, manifest or temporary file was saved.

The three protected repository files were inspected using filesystem metadata only: no contents, dotenv parsing, new content hash, runtime-state JSON read, process environment or command arguments. Prior secret-free observations were read instead of reacquiring sensitive configuration. Source inspection did not execute a launcher, settings module, key generator or application. Only the already inspected standard-library `process_info` helper was called, under Python `-B`, for read-only OS process metadata; no Runtime methods were invoked.

## Safe filesystem metadata

Snapshot T1: `2026-10-16T12:27:39Z`. All three paths are regular files, not symlinks, owned by `ferozebasha`, UID 501. Timestamps below are UTC; exact nanoseconds are stored as decimal strings to avoid rounding.

| Path | Inode | Bytes | Mode | mtime UTC | ctime UTC |
| --- | --- | --- | --- | --- | --- |
| `.env` | 34755675 | 6374 | 0644 | 2026-09-08 01:49:13.748488 | 2026-09-08 01:49:13.748488 |
| `.env.dev.local` | 60382048 | 4308 | 0600 | 2026-09-30 02:26:27.708333 | 2026-10-16 08:01:43.452356 |
| `.dev-runtime.json` | 75681290 | 4912 | 0600 | 2026-10-16 12:27:38.725185 | 2026-10-16 12:27:38.725377 |

| Path | Exact mtime_ns | Exact ctime_ns |
| --- | --- | --- |
| `.env` | `1788832153748488020` | `1788832153748488020` |
| `.env.dev.local` | `1790735187708332827` | `1792137703452355808` |
| `.dev-runtime.json` | `1792153658725184831` | `1792153658725376957` |

At T2, `2026-10-16T12:30:11Z`, both environment files matched **every inspected field** from T1: inode, size, UID, mode, mtime_ns, ctime_ns, regular-file and symlink status. The runtime file had changed to inode 75681678, still 4912 bytes, UID 501, mode 0600, regular/non-symlink; mtime_ns `1792153810677854723`, ctime_ns `1792153810678218268`. No chmod, touch, restore or other file write was performed by this review. ctime is metadata-change time, not a record of who changed a file or proof that contents changed.

## Confirmed explanation of the W1.4a comparison failure

Available evidence includes the existing secret-free local snapshot `/tmp/sbom-w13-preserve.json`, which retains Python's exact integer inode/size/mtime values. Its two environment records match current inode, size and **exact** mtime_ns. W1.3 also reported the same fields unchanged ([W1.3:110](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/04-d-isolation-preflight.md:110)).

The W1.4a task-start metadata was passed through `JSON.parse` into JavaScript numbers in the tool orchestration store, then `JSON.stringify` back to Python for comparison. These epoch-nanosecond integers exceed JavaScript's safe-integer range. Inspection of that retained in-session baseline and direct numeric conversion reproduced the loss:

| File | Exact earlier Python mtime_ns = current mtime_ns | W1.4a round-tripped decimal | Apparent difference |
| --- | --- | --- | --- |
| `.env` | `1788832153748488020` | `1788832153748488000` | 20 ns |
| `.env.dev.local` | `1790735187708332827` | `1790735187708332800` | 27 ns |

For both files, converting the exact earlier string to a JavaScript number equals the retained W1.4a number; `Number.isSafeInteger` is false. Inode and size match. Thus the exact-equality assertions used in W1.4a could fail on unchanged files. **The W1.4a statement that these comparisons demonstrated unexpected filesystem metadata changes was a false positive.** This correction concerns the audit tooling, not repository code; no tooling/application change is made here. Future cross-language observations should preserve nanoseconds as strings and compare exact integers within Python.

Limits: the local snapshot is contemporaneous task evidence, not an independently signed forensic record. Historical ctime/mode/owner were not included in that W1.3 snapshot. Matching metadata does not prove semantic/content equality or rule out every transient write/restore. No historical environment content-hash baseline was found in the reviewed W0.1/W1.3/W1.4a preservation evidence; those file-content inventories excluded ignored environment files. No new environment hash was calculated, and a hash without an earlier trustworthy baseline would not establish historical equivalence.

## Static workflows capable of changing these files

Repository source search covered Python/shell/PowerShell/batch launch/bootstrap paths, excluding secret files, application tests and frontend work. These are capabilities, not evidence that a particular command ran in the disputed window.

| Workflow / target | Write or metadata behavior | Exact source evidence |
| --- | --- | --- |
| Managed dev startup → `.env.dev.local` | Unconditionally chmods an existing file to 0600 on a non-check Unix startup. This can change ctime while leaving inode/size/mtime unchanged. | [scripts/dev.py:1075](/Users/ferozebasha/sbom/scripts/dev.py:1075) |
| Managed dev configuration persistence → `.env.dev.local` | Writes a 0600 sibling temporary file, atomically replaces the target, then chmods 0600. A replacement can change inode/mtime/ctime. Called when resolved values differ from saved values, including local credential resolution or Docker-provider startup. | [scripts/dev.py:360](/Users/ferozebasha/sbom/scripts/dev.py:360), [scripts/dev.py:657](/Users/ferozebasha/sbom/scripts/dev.py:657), [scripts/dev.py:1131](/Users/ferozebasha/sbom/scripts/dev.py:1131) |
| `scripts/dev.py` → root `.env` | Calls `ensure_env_key` for an existing local file before dotenv load. Missing/blank AI encryption key can cause append or rewrite; an already set key causes no write. | [scripts/dev.py](../../../scripts/dev.py), [scripts/generate_encryption_key.py:54](/Users/ferozebasha/sbom/scripts/generate_encryption_key.py:54), [scripts/generate_encryption_key.py:70](/Users/ferozebasha/sbom/scripts/generate_encryption_key.py:70) |
| Key-generator CLI → root `.env` | `--ensure-env` / `--append-to-env` call that same helper. These are mutating paths and were not run. | [scripts/generate_encryption_key.py:94](/Users/ferozebasha/sbom/scripts/generate_encryption_key.py:94), [scripts/generate_encryption_key.py:102](/Users/ferozebasha/sbom/scripts/generate_encryption_key.py:102) |
| Shell / PowerShell bootstrap → root `.env` | Copies `.env.example` only if `.env` is absent, then may ensure its encryption key. | [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py](../../../scripts/dev.py) |
| Windows local initializer → root `.env` | Same absent-file copy and key-initialization behavior; separately writes Windows-specific configuration. No Windows execution is inferred on this Mac. | [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py](../../../scripts/dev.py) |
| Managed launcher → `.dev-runtime.json` | Begin/register/refresh use temporary JSON plus fsync/atomic replacement. Main running loop refreshes every 0.5 seconds, so inode/mtime/ctime can keep changing without a service restart. | [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py](../../../scripts/dev.py), [scripts/dev.py:1179](/Users/ferozebasha/sbom/scripts/dev.py:1179) |
| Normal application DB setup | Loads dotenv and resolves process DATABASE_URL, then constructs a module-level engine; these inspected selection paths do not write the env files. A file timestamp does not establish a running engine target change. | [app/db.py:10](/Users/ferozebasha/sbom/app/db.py:10), [app/db.py:36](/Users/ferozebasha/sbom/app/db.py:36), [app/db.py:127](/Users/ferozebasha/sbom/app/db.py:127) |

External editors, manual chmod/touch, restore/sync tools and commands outside the searched repository paths are not exhaustively excluded. No shell history, private logs, filesystem event trace or process environments were read to attribute an actor.

## Process, container and historical target correlation

Current OS process observation: `2026-10-16T12:28:45Z`, using macOS libproc via [process_info](../../../scripts/dev.py). Each process is UID 501. Executables are `/opt/anaconda3/bin/python3.12` for launcher/API/worker/Beat, and Node for the frontend. No arguments or environment values were inspected.

| Role | PID | PPID | OS start UTC, microsecond resolution |
| --- | --- | --- | --- |
| Launcher | 23095 | 22709 | 2026-10-16 08:01:42.755614 |
| API | 23229 | 23095 | 2026-10-16 08:01:54.732547 |
| Celery worker | 23230 | 23095 | 2026-10-16 08:01:54.736336 |
| Celery Beat | 23231 | 23095 | 2026-10-16 08:01:54.738942 |
| Frontend launcher | 23232 | 23095 | 2026-10-16 08:01:54.742176 |

These PIDs/parent relationships agree with prior observations and their current OS births precede the audits. Prior secret-free W0.1 evidence retains successful birth/ownership-match booleans, not all original birth tuples for an independent exact historical tuple comparison. PID reuse is not being ruled out from PID alone; current OS start/executable/ownership context is also recorded. The runtime file itself was not opened for a fresh identity comparison.

The `.env.dev.local` ctime at 08:01:43.452356 follows launcher birth by about 0.7 seconds, and precedes the application child starts. Startup chmod is a **possible** explanation consistent with source and this window, not confirmed actor attribution. Its content mtime is still September 30. Root `.env` mtime/ctime are September 8, not in W1.4a's 12:19–12:20 validation window. Runtime-file replacement during this review is compatible with the active launcher's periodic refresh; no event-level writer attribution was obtained.

At `2026-10-16T12:29:12Z`, the local socket owner/backend process was checked before explicitly addressing the Docker Desktop Unix endpoint. Daemon `docker-desktop`, ID `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, server 29.8.2 matched W1.3/W1.4a. PostgreSQL selected metadata:

- `sbom-postgres-1`: ID `5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f`, running, image `postgres:16`, start `2026-10-16T08:01:48.746019708Z`, matching prior evidence.
- Publication remains IPv4/IPv6 wildcard host port 55439 → 5432; mount remains `sbom_postgres_data` → `/var/lib/postgresql/data`, local driver, no driver options, same Engine mount source. Network remains `sbom_default`, ID `4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8`.

Only selected nonsecret inspect properties were requested; no container environment, exec, logs, volume data or remote daemon access. No PostgreSQL connection or revision refresh was performed.

Historical sanitized mapping is available in `/tmp/sbom-w01-observed.json` at `2026-10-16T11:15:51Z` and [W0.1:79](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/00-deployment-target-readiness.md:79): API/worker/Beat had target classification **B**, with recorded equality to then-current B configuration, not A; A/B were both loopback PostgreSQL at 55439. Historical revisions A=055 and B=079 remain historical. Those sanitized observations are not hashes of the env files or proof of their current contents. Live target/engine semantics, every worker child/task and production/deployment identity remain unconfirmed; no sensitive reacquisition was attempted.

## Findings by confidence

| Classification | Finding |
| --- | --- |
| **CONFIRMED** | W1.4a's timestamp comparison lost precision; the retained rounded values reproduce its failures on exact currently matching historical metadata. The reported environment-change alarm is unsupported. |
| **CONFIRMED** | Both environment files match earlier inode/size/exact mtime evidence and remained stable across this review's full metadata snapshots. Runtime metadata genuinely changed between observations. Existing named processes and PostgreSQL infrastructure remain present with the recorded identities/start metadata. |
| **POSSIBLE** | Startup chmod explains B-file ctime; active launcher refresh explains runtime-file replacements. Static capability plus timing supports these explanations but does not establish a writer. |
| **UNKNOWN** | Environment content equivalence, any unobserved transient rewrite/restore, historical ctime/permission history, exact file-change actor and current complete in-process target semantics. No trustworthy historical content-hash baseline was found in the reviewed evidence. |

## Secret mount acceptance and conditional provisioning recommendation

W1.4a already recorded host file ownership/privacy and successful clean-environment `config --quiet` validation ([W1.4a:53](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/05-d-config-validation.md:53)). This review did not reopen or regenerate the disposable password, repeat configuration validation, read Docker Desktop private settings again or change permissions. The previous macOS settings-read denial remains an evidence limitation.

Host metadata, a file-sharing allowlist or Compose syntax success cannot establish that a future container can read the mounted secret. **Actual mount/in-container readability is a post-provisioning acceptance test**, not a pre-provisioning success claim or a demand to weaken 0700/0600 permissions. A separately approved D-only startup may attempt the reviewed mount and must fail closed if Docker Desktop or PostgreSQL initialization cannot read it. Such a failure blocks D acceptance and dependent work; it does not authorize an alternate secret path, credential reuse, broader permissions or application startup. No diagnostic may print the password.

**Conditional GO for separately authorized D-only startup:** this review finds no concrete environment-file integrity defect requiring repair before an independent D launch. The earlier precision-artifact alarm can be closed; semantic uncertainty about A/B does not require repointing or inspecting A/B to provision an isolated, independently supplied target. Keep these gates explicit:

1. Obtain separate authorization for the exact D-only container/volume/network creation/startup and any image pull. This read-only review grants none. No schema import, revision establishment, migration, tests or application connections are implied.
2. Immediately reverify branch/HEAD, reviewed Compose hash, local Unix daemon identity, absence of D resource collisions and free loopback port 56041. Collision/port observations from W1.4a are not reservations or fresh checks in this review. Stop on any mismatch; never adopt an existing/shared volume or select another daemon implicitly.
3. Use only the existing dedicated disposable inputs and privately recheck their source-file metadata/provenance. Stop on unexpected path/owner/mode/symlink, missing input, secret-read error or configuration-validation failure. Never regenerate an existing secret or read A/B credential files as fallback.
4. Preserve the [clean invocation](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:56): one absolute D file/project, explicit local socket, disabled default-env discovery and `/dev/null` env-file. No root Compose/env file, shared volume/network, dev launcher or additional service is permitted.
5. After authorized creation, verify actual D resource IDs, exclusive volume/network attachments, loopback publication, image identity and secret-read/init success without secret output. Any failure leaves D **NOT ACCEPTED**; stop dependent work. Do not automatically delete/recreate resources without target-specific approval.
6. Keep API/worker/Beat/A/B unchanged. If a future check finds a real metadata/configuration mismatch, unexpected existing-service restart or storage overlap, stop and investigate separately. Do not silently repair the live environment.

Only repository output: `docs/uuid-migration/phase2/06-existing-env-integrity-review.md`. All prior report/code/config contents were preserved. No protected-file content reads, environment changes, credential creation, Docker resource mutation, database access, migrations, tests, service restart/startup or Git mutation occurred. Metadata/process/source and documentation-preservation checks are not application acceptance tests.
