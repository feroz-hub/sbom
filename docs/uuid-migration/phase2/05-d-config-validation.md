# W1.4a — Disposable D inputs and Compose validation

2026-10-16 (Asia/Kolkata). **Compose configuration validation: PASS. Provisioning: NO-GO pending the blockers below and separate authorization.** D was not provisioned or started. The new disposable password exists only in its dedicated external file; no password value is included here.

Read the complete [Compose file](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:1), [W1.2 preparation](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:1) and [W1.3 preflight](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/04-d-isolation-preflight.md:1). Neither those files nor application/runtime configuration were edited by this task.

## Reviewed baseline and local Docker

| Check | Evidence / result |
| --- | --- |
| Branch | `feat/native-user-management` — matches requirement |
| HEAD | `2f48ff835d9e692fc84b31aaa951aad2495888ac` — matches W1.3 |
| Initial working tree | 20 modified tracked files and 17 untracked files; all 37 file contents snapshotted and subsequently matched |
| Reviewed Compose SHA256 | `3122e00cde19515533c62ff1d21667bb5857a493c669f03a990ecb299993edce` — exact W1.3 match, unchanged |
| CLI | `/usr/local/bin/docker`, resolved to `/Applications/Docker.app/Contents/Resources/bin/docker` |
| Local endpoint | `unix:///Users/ferozebasha/.docker/run/docker.sock`; real local Unix socket, owner UID 501, local `com.docker.backend` listener |
| Daemon | `docker-desktop`, ID `1f8c7fe5-5972-4adc-8d6e-363a38572be1`; Docker Desktop, server 29.8.2, aarch64 — matches W1.3 |
| Compose | `Docker Compose version v5.6.0` |

Socket/process identity was checked before daemon reads. Every daemon read used the explicit verified Unix endpoint and a PATH-only child environment. No ambient remote context was selected; no TCP/SSH/remote Docker endpoint was contacted. Git reads used per-command `core.fsmonitor=false`; no branch/ref/index changes were made.

## Collision and port checks

At `2026-10-16T12:19:29Z`, the local daemon contained 3 containers (including stopped inventory), 25 volumes and 4 networks. All three containers were running SBOM services. Names and Compose project/service/volume/network labels were inspected across the inventory, including retained volumes and networks.

| Proposed D identity | Result |
| --- | --- |
| Project `sbom-uuid-w1` | Absent from container/volume/network ownership metadata |
| Service `postgres_d` / expected container `sbom-uuid-w1-postgres_d-1` | Absent |
| Logical volume `d_pgdata` / `sbom-uuid-w1_d_pgdata` | Absent |
| Logical network `d_private` / `sbom-uuid-w1_d_private` | Absent |
| D-target labels | No matching D-target resource |
| Host port `127.0.0.1:56041` | No lsof TCP listener, no Docker publication, no matching local TCP-table entry |

The TCP-table check inspected 146 entries; existing Redis port 56379 provided a positive control (21 entries and a Docker backend listener). No bind, reservation, connection or publication of 56041 occurred. Availability is point-in-time only; repeat collision, daemon and port checks immediately before any separately authorized provisioning. Existing `sbom_postgres_data` is an application volume, not a collision with the exact logical service name `postgres_d`.

## Disposable input provenance and secret-file verification

The following values were selected specifically for D during this authorized task. No A/B, production, repository `.env`, `.env.dev.local` or alternate credential store supplied them. The four YAML inputs were passed only in the clean Compose child environment; the endpoint was passed explicitly to Docker. No shell profile, env file or persistent configuration was created/modified. This table records the nonsecret inputs for a future reviewed invocation; it does not set variables in a future operator shell.

| Input | Prepared value / provenance |
| --- | --- |
| `UUID_W1_D_POSTGRES_USER` | `uuid_w1_d_bootstrap`; new disposable bootstrap role name, valid simple SQL identifier |
| `UUID_W1_D_POSTGRES_DB` | `uuid_w1_d_rehearsal`; new disposable database name, valid simple SQL identifier |
| `UUID_W1_D_PASSWORD_FILE` | `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/postgres-password`; newly created exclusively, outside checkout |
| `UUID_W1_D_PORT_SUFFIX` | `041`; exactly three decimal digits, resolves host port to 56041 |
| `UUID_W1_D_DOCKER_ENDPOINT` | `unix:///Users/ferozebasha/.docker/run/docker.sock`; independently verified local endpoint above |

Password generation used Python `secrets.token_hex(32)`, backed by the OS secure randomness source: 256 random bits, hexadecimal encoding, with a final newline. The password was written directly to an exclusively created file using `O_EXCL | O_NOFOLLOW`; no existing directory/file was adopted or overwritten. It was never emitted, hashed into this report, placed in Git, shell history, command arguments, process environment or a temporary credential file. It was not reopened to display or inspect its contents. No credential rotation or cleanup was attempted.

| Secret check | Result at creation/validation |
| --- | --- |
| Parent directory | New `/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016`, UID 501, mode `0700`, real directory, not a symlink |
| File | UID 501, mode `0600`, regular non-symlink file, nonempty, one hard link |
| Path | Absolute resolved path equals intended path; outside `/Users/ferozebasha/sbom` |
| Host access / ACL | Readable by task user; no additional ACL indicated for directory or file |
| Docker Desktop file sharing | **UNCONFIRMED**: macOS denied read access to `~/Library/Group Containers/group.com.docker/settings-store.json`. No permission bypass, settings modification or mount probe was attempted. |
| In-container readability | **UNVERIFIED**: no container exists; Compose config success is not a secret-mount/readability test |

The private file and directory must be retained securely for a later reviewed task. Do not regenerate or overwrite them implicitly on rerun; an existing path is a stop/review condition. Their existence does not authorize Docker resource creation.

## Exact Compose validation and structural checks

At `2026-10-16T12:20:11Z`, the following reviewed invocation was executed through a Python subprocess with a freshly constructed environment. The child environment contained only PATH, `COMPOSE_DISABLE_ENV_FILE=1` and the four disposable YAML inputs above. The password itself was absent from the environment and arguments.

```sh
/usr/local/bin/docker --host "$UUID_W1_D_DOCKER_ENDPOINT" compose \
  --env-file /dev/null \
  --project-name sbom-uuid-w1 \
  --project-directory /Users/ferozebasha/sbom/infra/uuid-migration \
  --file /Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml \
  config --quiet
```

**Result: exit 0, stdout empty, stderr empty.** No full resolved Compose configuration was printed or obtained. No other Compose configuration/rendering command, service command or lifecycle command was executed. Compose version and read-only Docker Engine metadata commands were also used.

The exact supplied interpolation values were additionally applied to an in-memory copy of the unchanged YAML and its nonsecret structure checked. These are input-resolved offline checks paired with successful Compose validation, not a claim to have inspected Compose's normalized rendered output.

| Property | Verified input-resolved value |
| --- | --- |
| Services / image | Exactly `postgres_d`, `postgres:16`; no API/Celery/Beat/Redis/frontend/mail service |
| Port | Only TCP 5432 → published `56041`, host_ip `127.0.0.1` |
| Volume | Only project-managed `d_pgdata`, local driver; expected `sbom-uuid-w1_d_pgdata`, no external/name/driver-options override or shared bind |
| Network | Only project-managed `d_private`, internal bridge, attachable=false; expected `sbom-uuid-w1_d_private`, no external/name override |
| Secret | Only `uuid_w1_d_password`, source equals the new external password-file path, service references that secret |
| Password delivery | `POSTGRES_PASSWORD_FILE=/run/secrets/uuid_w1_d_password`; no `POSTGRES_PASSWORD` value in service environment |
| Dependencies / merge | No depends_on, include, extends, env_file, build, network_mode override or additional Compose file |

No Compose-file correction was needed for configuration validation. `postgres:16` image availability/digest, actual initialization, SCRAM authentication, secret mounting, internal-network/loopback connectivity and PostgreSQL capabilities were not exercised. Image pull remains separately authorized work.

## Existing A/B infrastructure and preservation exception

Start/end selected metadata checks confirmed identical IDs, start times, states, labels, publications, mounts and network attachments for these existing containers:

| Existing container | Unchanged ID |
| --- | --- |
| `sbom-postgres-1` | `5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f` |
| `sbom-redis-1` | `135db956488a91d46e4047bcc226ec6f63c3d938349adb80ba2e7b672dc67058` |
| `sbom-mailpit-1` | `b342c0214b040a1d5d177d8fbc731d022ac4324707afd6ca1bbb505e0efb9e68` |

The selected metadata of `sbom_postgres_data`, `sbom_redis_data` and network `sbom_default` (`4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8`) remained identical. Total resource counts also remained unchanged. PostgreSQL publication remains 55439; nothing was repointed to D. No database connections occurred; A=055 and B=079 remain historical observations, not refreshed revisions. Database contents and normal business writes were not inspected.

**Preservation exception / STOP:** final metadata comparison found that both ignored `.env` and `.env.dev.local` differed from their task-start inode/size/mtime snapshots. This task did not open their contents or write either file. Cause and semantic impact are **UNCONFIRMED**; do not assume a harmless touch or claim unchanged A/B runtime configuration. Further configuration work stopped on this finding. All 37 pre-existing modified/untracked file contents, including the reviewed Compose and prior reports, still matched their snapshots. Docker infrastructure preservation does not resolve this runtime-configuration evidence gap.

## Decision and next gates

| Gate | Status / next action |
| --- | --- |
| Disposable inputs / private host password file | PASS at creation; reuse only through a new reviewed invocation, never implicit regeneration |
| Exact clean-environment Compose config | PASS, exit 0; closes the missing-input/config-validation blockers from W1.3 |
| Local identity / D collisions / port | PASS at observation; recheck before any resource mutation |
| Existing A/B Docker containers/storage | PASS for selected unchanged metadata; no database-level claim |
| Existing runtime configuration preservation | **BLOCKED / UNCONFIRMED**: unexplained `.env` and `.env.dev.local` metadata changes; reconcile with the operator before proceeding, without disclosing credentials |
| Docker Desktop secret-source sharing | **UNCONFIRMED** due to macOS access restriction; confirm through an approved non-mutating settings review where possible. No broader permissions or insecure file mode workaround. |
| Image and actual mount/init behavior | Future provisioning acceptance; no image pull, mount test or PostgreSQL connection authorized/executed here |
| D creation/startup | Separate explicit authorization still required; no provisioning authority follows from config success |

**GO for accepting the successful configuration-validation result; NO-GO for an unconditional D-only provisioning handoff now.** First reconcile the existing configuration metadata mismatch and the file-sharing evidence gap, then repeat target/collision/port checks and obtain separate D-only provisioning authorization. If a later approved startup cannot read the secret, stop; do not relax host permissions, reuse A/B credentials or merge another Compose file.

Only created artifacts: this report and the explicitly authorized external password file under its new private directory. No additional manifest/env/config/script file was saved. No Docker resource creation/removal, image pull, PostgreSQL connection, dump/restore, Alembic, migration, test, application startup, existing-file edit, Git commit/push/checkout/reset was performed. Report checks are documentation checks only.
