# W1.4d — D port-publication diagnosis and correction design

2026-10-16, Asia/Kolkata; evidence times below are UTC. **AUDIT/DESIGN COMPLETE, correction NOT IMPLEMENTED.** W1.4c remains **PARTIAL / NOT ACCEPTED**; W1.5 remains **NO-GO**. The leading explanation is **LIKELY: Engine handling of a container attached exclusively to an internal bridge suppresses publication**. This is supported by local state, primary documentation and matching upstream reports, but is not a controlled causal proof for Engine 29.8.2.

**Recommendation: Option A, conditional GO for a separately authorized W1.4e correction task:** replace only D's container onto a new dedicated ordinary bridge, retaining the exact D volume and password, with explicit loopback-only publication. Approval must acknowledge the outbound-access change. If policy requires enforced zero egress or inability to reach existing host-published services, this ordinary-bridge design is **NO-GO** until a separate egress-control/proxy design is accepted. No correction is authorized or performed by this report.

## Scope, prerequisites and baseline

Read completely: [master tracker](/Users/ferozebasha/sbom/docs/uuid-migration/MIGRATION_MASTER_TRACKER.md:1), [W1.4c acceptance](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/07-d-provisioning-acceptance.md:1), [W1.2 preparation](/Users/ferozebasha/sbom/docs/uuid-migration/phase2/03-disposable-target-preparation.md:1) and [reviewed Compose](/Users/ferozebasha/sbom/infra/uuid-migration/docker-compose.uuid-w1.yml:1). W1.4d prerequisites, stop conditions, expected zero runtime-resource delta and acceptance criteria were recorded IN PROGRESS in the tracker before inspection.

Branch `feat/native-user-management`; HEAD `2f48ff835d9e692fc84b31aaa951aad2495888ac`. Initial tree: 20 modified tracked files and 21 untracked files, 41 existing contents snapshotted; only the tracker is authorized to change among those files. Compose SHA256 remains `3122e00cde19515533c62ff1d21667bb5857a493c669f03a990ecb299993edce`. No remote-ref refresh or origin synchronization claim.

Only selected read-only Docker/host/process metadata and source documents were inspected. No unfiltered container configuration, Config.Env, process environments/arguments, healthcheck log contents or secret file contents were requested. No secret was opened or regenerated. No Compose command, container exec, TCP connection, DB connection, network mutation, restart, image pull or test was executed. Root environment files were checked by exact metadata only; nanosecond timestamps are strings.

## Fresh local evidence

Initial observation: `2026-10-16T13:19:42Z`; repeat: `2026-10-16T13:21:52Z`. Local CLI resolves to `/Applications/Docker.app/Contents/Resources/bin/docker`. Before daemon reads, the real socket `/Users/ferozebasha/.docker/run/docker.sock` was verified UID 501 with a local Docker backend listener. Every request explicitly addressed `unix:///Users/ferozebasha/.docker/run/docker.sock` with a PATH-only child environment. No remote daemon was contacted.

| Field | Actual observation |
| --- | --- |
| Daemon | `docker-desktop`, Docker Desktop server 29.8.2/aarch64; ID `1f8c7fe5-5972-4adc-8d6e-363a38572be1`, unchanged |
| D container | `sbom-uuid-w1-postgres_d-1`, ID `1f162bf136f39371dd9a834bf500b3ab0fec401fe41c339c48f82482337beaf0` |
| State | Running, configured health status healthy, zero restarts; start `2026-10-16T13:09:16.861010548Z`, unchanged |
| Image | `sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54`, unchanged |
| Desired HostConfig.PortBindings | `5432/tcp → [{HostIp:127.0.0.1, HostPort:56041}]` |
| Actual NetworkSettings.Ports | `{"5432/tcp": []}`; no actual mapping |
| Other publication properties | Config.ExposedPorts contains 5432/tcp; PublishAllPorts=false; network mode `sbom-uuid-w1_d_private` |
| Host listener | lsof found no TCP listener on 56041, with no command error; existing Docker backend listener on 56379 is a positive control |
| Compose provenance | Labels name the single reviewed absolute file, project sbom-uuid-w1, service postgres_d, `/dev/null` environment file and intended project directory |
| Sole endpoint | `sbom-uuid-w1_d_private`, endpoint `8bb3b3ce567eddabd12bb7a5caddc28ef56192e4493021004268efd8f9bf886a`; address `172.19.0.2/16`, endpoint Gateway and IPv6Gateway empty; GwPriority=0; DriverOpts/IPAMConfig null |
| Network | ID `32f906902715f5fe1dee18bcdccc1987c6befd01416cf87dc922f214c2512a5c`, created `2026-10-16T13:09:16.521058256Z`; bridge, Internal=true, Attachable=false, IPv4=true, IPv6=false |
| IPAM | Default driver, subnet `172.19.0.0/16`, reserved gateway `172.19.0.1`; this network-level reservation is not a configured endpoint default route |
| Driver options actually present | Only `com.docker.network.enable_ipv4=true` and `com.docker.network.enable_ipv6=false` |
| Relevant options absent | No explicit gateway_mode_ipv4/ipv6, inhibit_ipv4, enable_ip_masquerade, enable_icc, host_binding_ipv4 or trusted_host_interfaces override on D's network |
| Volume | `sbom-uuid-w1_d_pgdata`, local/no driver options, created `2026-10-16T13:09:16Z`; source `/var/lib/docker/volumes/sbom-uuid-w1_d_pgdata/_data` → `/var/lib/postgresql/data` |
| Attachments | Only D mounts that volume; only D attaches to d_private; D has no other network. D/project/disposable labels match reviewed ownership |

The secret's **mount metadata only** remains the expected read-only bind to `/run/secrets/uuid_w1_d_password`; the file itself was not accessed. No firewall/routing table inside the Desktop VM, actual server setting or packet path was inspected. Absence of an option in network metadata is not an inspection of every daemon-wide default.

## Upstream reconciliation and confidence

Primary references accessed 2026-10-16:

- [Moby issue 36174](https://github.com/moby/moby/issues/36174): the 2018 Engine 18.01 report shows a stored loopback request without a mapping on an internal bridge. A maintainer's February 7 comment describes the behavior as intended, with qualification; this is historical evidence, not a 29.8.2 guarantee.
- [Moby discussion 53256](https://github.com/moby/moby/discussions/53256): July 2026 report on Engine 29.6.2/Compose 5.3.1/Linux, with a normal-bridge control; another participant reports similar 29.5.2 behavior. Stored request versus missing mapping and healthy service match D. Those systems are not our 29.8.2 Desktop/Compose 5.6.0 system. A live-attachment workaround is reported, not certified for our version.
- [Docker internal-network reference](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal): internal networking omits a default route and filters inter-network traffic, while host/gateway communication can still exist. This reconciles reserved IPAM gateway with an empty endpoint gateway; it does not prove the exact publication code path.
- [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/#how-exposed-ports-work): Desktop uses its backend for host forwarding. Our absent host listener and absent Engine mapping point earlier than an authenticated PostgreSQL failure; existing backend publications still work as metadata controls.

| Explanation | Classification | Reason / remaining uncertainty |
| --- | --- | --- |
| Stored request exists but publication absent | **CONFIRMED symptom** | Exact HostConfig versus NetworkSettings discrepancy, repeated host-listener absence |
| Exclusively internal bridge suppresses publication | **LIKELY, high confidence** | Actual sole internal endpoint/no gateway, correct desired request, matching independent Engine generations and historical maintainer explanation. No ordinary-bridge control or source-level trace on this installed build was run |
| D-specific Engine/Desktop forwarding defect | **POSSIBLE** | Read-only evidence cannot exclude a version-specific bug. Generic Desktop forwarding outage is unsupported: existing SBOM publications/listener persist. Do not relabel this as a proven Desktop regression |
| Manually incorrect gateway / bridge driver mode | **UNSUPPORTED by inspected configuration** | No routed/isolated/inhibit override; IPAM gateway exists and Internal=true explains route suppression. Empty endpoint gateway is confirmed, but is not evidence that assigning a gateway manually repairs the mapping |
| Compose lost/mistranslated port or wrong file | **UNSUPPORTED** | Correct reviewed source/hash/provenance and exact desired HostConfig request survived translation. Source accepts a combination whose Engine behavior is unsuitable; that is different from a lost host_ip/port |
| PostgreSQL readiness or password failure explains missing host publication | **UNSUPPORTED** | Mapping is absent at Docker/host layers. Health does not certify auth, but no DB setting was queried and no evidence attributes publication to credentials |

No exact 29.8.2 causal trace or controlled topology change was performed. Attempts to retrieve candidate version-pinned Moby source URLs did not yield the files; this does not establish that a tag or source is absent upstream. The leading explanation remains LIKELY rather than CONFIRMED root cause.

## Correction alternatives — design only

### A — One PostgreSQL service on a dedicated ordinary bridge (recommended conditionally)

Expected: replacing D onto a normal NAT bridge should permit the existing explicit loopback host mapping. This follows [Docker's publication model](https://docs.docker.com/engine/network/port-publishing/#publishing-ports), but success on this exact host remains untested. Keep target/published/host_ip/protocol unchanged. Require actual mapping, host listener and authenticated read-only connection after correction, not config success alone.

Exact proposed Compose delta, **not applied**:

- Change only `services.postgres_d.networks` from `[d_private]` to `[d_access]`; retain the existing one-service, volume, secret, healthcheck and credential configuration.
- Add logical network `d_access`, expected Engine name `sbom-uuid-w1_d_access`, with bridge, internal=false, attachable=false, enable_ipv4=true, enable_ipv6=false and the existing D/disposable labels. Add these driver options:

```yaml
com.docker.network.bridge.gateway_mode_ipv4: "nat"
com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"
com.docker.network.bridge.enable_icc: "false"
```

- Retain the existing d_private definition/network, unattached after replacement, as a recorded rollback resource; do not try to mutate the existing network's immutable creation settings in place. No down/prune/orphan cleanup. Do not create a new data volume or change `d_pgdata` resolution.

[Bridge options](https://docs.docker.com/engine/network/drivers/bridge/#options) document default host-binding and inter-container controls. Proposed explicit loopback plus network default is defense in depth. ICC=false does not implement an outbound firewall; attachable=false is not an access-control boundary against a local Docker administrator.

Inbound: no wildcard/IPv6 publication, no shared SBOM network, no other D bridge members. Local host users/Docker administrators remain trusted-access risks; PostgreSQL authentication still applies. Outbound: a normal bridge provides routing/NAT, unlike the current internal-only topology. D could initiate traffic toward host/LAN/internet and existing host-published SBOM endpoints, depending on routing/policy. In particular, existing PostgreSQL publishes wildcard port 55439. No same-network attachment is necessary to attempt host-address traffic. These are risks inferred from topology, not connectivity tests executed here.

Controls within this minimal option: one database service only; no application/worker/provider process, no additional capabilities, no Docker socket/host networking/host aliases, dedicated bridge with ICC disabled, unchanged private secret, and explicit owner-only credentials. **These do not guarantee no egress or no access attempts to SBOM services.** Disabling masquerade, DNS or ICC alone must not be presented as an effective destination deny policy. No shared daemon/backend firewall change is proposed: it could affect A/B services. Accept this changed egress profile explicitly for a trusted disposable database, or reject A and commission B2/egress containment instead.

Replacement: **required by the proposed procedure**, so the desired topology and publication are applied together at container creation. Preserve the exact initialized D volume and password. Residual risks: broader outbound reachability, host-user access, Docker administrators and version-specific publication behavior. This is preferred for the infrastructure-only rehearsal because it adds no proxy image/code or extra privileged/trusted service; it is not a claim of strongest possible network isolation.

### B — Keep internal private networking and add a dedicated connectivity boundary

**B1: dual-home PostgreSQL itself.** Retain d_private; add new ordinary d_access and declare both on postgres_d at creation, with access network gw_priority=1. [Docker networking](https://docs.docker.com/engine/network/#connecting-to-multiple-networks) documents multi-network/gateway selection; [Compose gw_priority](https://docs.docker.com/reference/compose-file/services/#gw_priority) is documented from 2.33.1. Reported support is compatible with our plugin version, but actual behavior is unverified.

Expected host mapping is plausible from the 29.x report; keeping an internal interface does **not** keep a dual-homed database externally isolated. It gains the ordinary bridge's outbound route. It adds an unnecessary second interface/trust surface compared with A and still permits host-published-service reachability. No sbom_default attachment; same D storage/password can remain. Plan replacement rather than relying on attachment to the running container. Rollback uses original private-only topology and same volume, restoring the previous NOT ACCEPTED state. Not recommended.

**B2: dedicated TCP forwarding service.** Keep PostgreSQL solely on d_private; remove its ports declaration in the reviewed future configuration. Add exactly one named D-only forwarding service with a fixed backend `postgres_d:5432`, connected to d_private and a new ordinary d_access; only that service publishes 127.0.0.1:56041. It receives no password, data volume, Docker socket, dynamic backend selection or application integration. Retain SCRAM end-to-end. Docker documents this [front/back multi-network pattern](https://docs.docker.com/reference/compose-file/networks/#external); the TCP-forwarder implementation/image must be separately selected, pinned, reviewed and approved, not assumed supplied by Docker.

This avoids adding an external route to PostgreSQL, while the forwarding component has outbound exposure and can reach D. Internal network host/gateway reachability can remain; do not promise total isolation of D from the host. A compromised proxy or local Docker administrator remains a risk. Source-backed topology support does not certify an unknown proxy's PostgreSQL compatibility, logging/privacy or deny behavior. No proxy image availability, config or protocol test was inspected/executed.

Exact new resources: one D-only proxy container and d_access network; reuse current d_private and exact data volume. Proposed clean configuration removes stale D publication, so replace D deliberately while preserving storage, then start the separately approved proxy. A proxy could theoretically be added without replacing D, but leaving a stale requested binding on D invites ambiguity and is not the recommended procedure. Acceptance must identify the proxy as the publisher and prove that its backend is this exact D cluster. Rollback stops only the proxy and restores private-only D configuration under approval; retain all volume mappings, no automatic deletion. Safer if preserving PostgreSQL's restricted routing is mandatory, but not a minimal one-service correction and currently blocked on new component/image/config approval.

**No retroactive-binding assumption:** the discussion's 29.5.2 participant reports live non-internal attachment enabling publication. Official docs describe attachment, not a guarantee that it instantiates an existing requested host binding on 29.8.2. This remains UNCONFIRMED for D. Neither B1 nor B2 is permission to run network connect/disconnect in W1.4d.

### C — Other documented networking modes

Routed mode intentionally does not use a host port, so it does not meet the fixed loopback requirement; isolated gateway mode further limits internal connectivity rather than supplying a host publisher. Neither is the correction. [Gateway-mode documentation](https://docs.docker.com/engine/network/port-publishing/#gateway-modes).

[None networking](https://docs.docker.com/engine/network/drivers/none/) exposes only container loopback and cannot directly supply this host port. Host networking removes the dedicated network boundary and conflicts with Compose port-mapping semantics ([Compose ports](https://docs.docker.com/reference/compose-file/services/#ports)); macvlan/direct routes or global daemon changes are not acceptable shortcuts here. Those alternatives would change isolation/host configuration or the endpoint contract. Existing volume can in principle survive a container replacement, but no such alternative is approved; rollback/data-preservation principles remain the same. No resource/config delta is recommended for C.

## Proposed W1.4e procedure for A — not executed

The next request must explicitly approve the revised Compose delta/new hash, ordinary-bridge egress profile, creation of d_access and **replacement/removal of this exact D container only**, while preserving the exact volume, secret and old network. Previous initial-provision authority is not a continuing recreation permission. No image pull, new application, global firewall/daemon setting or data operation is implied.

1. Record before-state of the reviewed branch/HEAD, dirty tree, local daemon, exact current D/container/image/network/volume, existing SBOM resources/processes, env metadata and private password metadata. Coordinate exclusive operator ownership of this replacement window. Stop on unexpected state or new access-network collision; never adopt a same-name resource.
2. Before replacement, obtain an explicitly authorized D-only read-only `pg_controldata` system identifier from the current PGDATA, without reading a password or business data. It was not obtained in W1.4c/d. Record the storage manifest: volume `sbom-uuid-w1_d_pgdata`, created 2026-10-16T13:09:16Z, local/no options, source `/var/lib/docker/volumes/sbom-uuid-w1_d_pgdata/_data`, D ownership labels, only current D attached. Missing/mismatched volume or unexpectedly empty PGDATA means STOP, not permission to initialize a replacement cluster.
3. Prepare/review only the A delta described above; record its new hash and preserve the original reviewed configuration for rollback. Same project/service/logical d_pgdata, PGDATA path, image identity and password source must resolve to the existing volume/file. Require presence of the exact volume immediately before creation; no concurrent resource operator. For stricter fail-closed volume lookup, a separately reviewed external reference may pin this exact existing D volume so absence errors instead of creating one; that is an additional explicit config change, not authorization to adopt arbitrary external storage.
4. Review the clean-environment config and exact replacement command. Future D-only up may use `--detach --no-deps --no-build --pull never --force-recreate postgres_d` with the existing absolute file/project/local socket and disabled default-env discovery. Only issue it under explicit replacement authorization; no down, volumes flag, anonymous-volume renewal or remove-orphans. [Compose up](https://docs.docker.com/reference/cli/docker/compose/up/) documents recreation with mounted volumes preserved. A documented lifecycle is still not a guarantee against wrong-volume configuration: verify identity before and after.
5. The future replacement must gracefully stop the old D process before another PostgreSQL process opens the same data directory. No parallel old/new Postgres against one volume, copy/export/import, initdb, credential change or SQL repair. If a step fails, stop and inventory actual state. Leave resources/data intact; do not repeat a partially completed replacement blindly.
6. Require a new container ID but identical image/data-volume creation/source/ownership and cluster identifier, with only the replacement attached to d_access, no existing application network and only the same read-only secret bind. Existing d_private remains as a recorded empty rollback network. Record actual delta; no unrelated service/resource may change.
7. Complete every acceptance item below. Any publication, auth, data/cluster or preservation failure leaves D NOT ACCEPTED. Do not proceed to B export/import or UUID work.

**Rollback:** only under an approved D-only rollback scope, restore the original private-only configuration and recreate D using the same data volume, password and image. This returns the known unaccepted/no-host-publication topology, not a successful fix. Preserve the cluster/mappings and report partial resources; do not delete the volume or regenerate credentials. If A unexpectedly exposes a wildcard listener or violates the approved outbound policy, the future task must have explicit D-only stop/fail-closed authority; otherwise stop issuing commands and request that targeted action. No shared firewall or application service change is an acceptable rollback.

## Acceptance required after an approved correction

All DB/secret/process-in-container probes below are **future, NOT RUN in W1.4d**. Approval must include their narrowly scoped access methods. Do not reuse A/B authorization or fall back to 55439.

The planned cluster correlation uses PostgreSQL 16's documented [control-data functions](https://www.postgresql.org/docs/16/functions-info.html#FUNCTIONS-CONTROLDATA) and [pg_controldata utility](https://www.postgresql.org/docs/16/app-pgcontroldata.html); only the system identifier is needed for continuity, not mutable checkpoint/WAL state or business records. Neither was executed here.

| Gate | Required execution evidence |
| --- | --- |
| Host publication | Actual NetworkSettings.Ports exactly 5432/tcp → 127.0.0.1:56041; host Docker backend listener at only that address/port; no wildcard/IPv6 publication. Correlate both to the replacement ID; config/HostConfig alone insufficient |
| D-only network/storage | Correct new bridge settings/ownership/options, only expected D attachment, no SBOM attachment; exact original volume/source/creation and only replacement attached; retained old network empty. For B2, explicitly approve and account for proxy attachment differences |
| Secret mount/use | Same dedicated private source/readonly mount; approved non-disclosing readability probe under the initialization identity and actual authenticated connection. Do not require changing 0600 to accommodate an arbitrarily different user or print file/PGPASSWORD/env |
| Authentication / target / version | Verified D manifest first, then one bounded loopback connection to 127.0.0.1:56041, explicit disposable database/user, password read only into the client privately, no DSN/CLI password. Enforce read-only at connection/transaction start, bounded timeouts and ROLLBACK. Check current_database/current_user, server major 16/version, server address/port and read-only transaction state |
| Fresh schema / Alembic | Bounded catalog-only inventory finds no SBOM application objects or Alembic revision established. Check marker existence before attempting its read; no create/stamp/upgrade to make it pass |
| Cluster/storage continuity | Match SQL pg_control_system system identifier to approved pg_controldata before replacement and PGDATA on the same named volume after. A mismatch is STOP even if name/user/version look right; no A/B query is needed for this comparison |
| Existing services / files | Before/after exact IDs/start/restart/mount/port/network attachment metadata for the three existing SBOM containers/two volumes/sbom_default; OS birth/executable/ownership identities for launcher/API/worker/Beat/frontend; Compose delta only as approved, existing env metadata/work preserved. No business-data unchanged claim without evidence |
| Operational failure handling | Record actual resources left behind, error scope without secrets and stop on any failure. No automatic cleanup, restart-loop, policy relaxation, image pull or alternate port |

Passing these gates would establish D infrastructure acceptance only. W1.5 still needs separate B-source extraction and D-schema import/parity authorization, drift preservation and explicit review before revision establishment. Hybrid UUID implementation and production/public cutover remain separate gates.

## Preservation, verification and decision

All selected D/container/network/volume/attachment metadata and health were identical across the two read-only observations. All four container IDs, all 26 volume names and all five network IDs remained identical; no runtime resource was created, removed or modified by this task.

Existing SBOM container IDs remain PostgreSQL `5d8b97a004f68e02095f0bec101c3191d1910eee06d2edcda4b98fe7c1c1433f`, Redis `135db956488a91d46e4047bcc226ec6f63c3d938349adb80ba2e7b672dc67058`, Mailpit `b342c0214b040a1d5d177d8fbc731d022ac4324707afd6ca1bbb505e0efb9e68`. Their states/start times/restart counts/publications/mounts/attachments, `sbom_postgres_data`, `sbom_redis_data` and `sbom_default` ID `4086ad739d97715b44eb3505364a8636bb72bb5e128cdbbf16d9f43de16263d8` matched both start/end and the available W1.4c selected snapshots. Existing host publications remain 55439, 56379 and 1025/8025. No A/B connection or data-equivalence claim.

Launcher/API/worker/Beat/frontend PIDs 23095/23229/23230/23231/23232 and their exact OS birth/executable/UID/PPID/PGID/SID metadata also matched start/end and the prior W1.4c records. Runtime-state contents, commands, environments and application endpoints were not inspected. Read-only lsof positive-control success supports the absent-listener observation; no DB/network request or firewall rule was used as a diagnostic test.

**W1.4e: conditional GO for a separately authorized A correction, with explicit egress-risk acceptance and the volume-preserving replacement/stop/rollback scope above.** If that policy change is unacceptable, execution is NO-GO and B2 needs a separately approved concrete proxy/egress design first. Root cause remains LIKELY; remedy remains UNTESTED. **W1.4c PARTIAL / D NOT ACCEPTED; W1.5 NO-GO.**

Only files changed: created `docs/uuid-migration/phase2/08-d-port-publication-diagnosis.md`; updated `docs/uuid-migration/MIGRATION_MASTER_TRACKER.md`. The existing D Compose file and prior reports remain unchanged. Executed work: source/upstream reads, safe local Docker/host/process metadata and documentation-preservation checks. No Compose execution, DB/secret access, container exec, application/migration/browser/performance tests or runtime/configuration mutation occurred.

Final documentation checks passed: 40 pre-existing file-content hashes excluding the authorized tracker update and the tracked binary diff matched baseline; all 17 prior task-ledger rows retained verbatim; 35 local evidence links/nonblank line locations and whitespace checked; exact root environment metadata unchanged. Runtime inventory/preservation checks above also passed. These are executed metadata/document checks, not a correction experiment or database acceptance result.
