"""Explicit, bounded adapters for isolated PostgreSQL preparation.

Nothing runs at import. These adapters are trusted Python controller code, not a
sandbox against a same-user attacker who can edit that controller. Policy and
journal collaborators must independently validate consent, source, exclusivity,
image tools and private bundle receipts. Supplied JSON/booleans are not authority.
No default policy, image-tool approval, migration callback or TLS attestor exists.
No volume deletion, root helper, ownership repair, audit-setting change or
plaintext-password SQL fallback is provided. Helpers are retained and journaled.

libpq 17's PQchangePassword encrypts before sending ALTER ROLE. The SCRAM verifier
can still appear in server audit output; a trusted credential-audit policy must
approve that transport. We never disable logging. libpq does not expose peer DER
through Psycopg: a deployment must supply a reviewed verifier bound to the actual
connection, rather than claiming that a CA-file hash identifies its TLS peer.
Connect, statement, lock and idle-transaction limits are fixed. TCP user timeout
support is platform-dependent; these synchronous libpq settings alone are not a
hard wall-clock transport deadline. A reviewed transport policy and disposable
native acceptance remain prerequisites; no live acceptance is claimed here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field

if __package__:
    from . import dev_workspace_compose as compose
    from . import dev_workspace_database_prepare as db
    from . import dev_workspace_engine as engine
else:
    import dev_workspace_compose as compose
    import dev_workspace_database_prepare as db
    import dev_workspace_engine as engine

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_CHECKS = frozenset(
    {
        "exact-operator-action",
        "company-policy",
        "provider-ownership",
        "private-bundle",
        "exclusive-preparation",
        "image-contract",
        "nonroot-volume-ownership",
    }
)
_LIMIT = 1024 * 1024

# Fixed, reviewed GNU stat/find + POSIX sh + PostgreSQL pg_controldata contract.
# Only numeric metadata is printed. Every top-level name is checked; recursive
# symlinks (including externally mounted tablespaces) are refused.
_OBSERVE = r"""set -eu
export LC_ALL=C
d=/var/lib/postgresql/data
test -d "$d" && test ! -L "$d"
meta=$(stat -c '%u %g %a' "$d")
links=$(find "$d" -type l -printf x)
test -z "$links"
entries=$(find "$d" -mindepth 1 -maxdepth 1 -printf x)
if test -z "$entries"; then printf 'SBOMPG1 %s EMPTY 0\n' "$meta"; exit 0; fi
for p in "$d"/* "$d"/.[!.]* "$d"/..?*; do
 test -e "$p" || continue
 case "${p##*/}" in
 PG_VERSION|base|global|pg_commit_ts|pg_dynshmem|pg_logical|pg_multixact|pg_notify|pg_replslot|pg_serial|pg_snapshots|pg_stat|pg_stat_tmp|pg_subtrans|pg_tblspc|pg_twophase|pg_wal|pg_xact|postgresql.auto.conf|postgresql.conf|pg_hba.conf|pg_ident.conf|postmaster.opts|postmaster.pid) ;;
 *) exit 72;; esac
done
test -f "$d/PG_VERSION" && test -f "$d/global/pg_control"
control=$(pg_controldata "$d")
id=$(printf '%s\n' "$control" | awk '/^Database system identifier:/ {print $4}')
case "$id" in ''|*[!0-9]*) exit 73;; esac
printf 'SBOMPG1 %s INITIALIZED %s\n' "$meta" "$id"
"""
OBSERVER_DIGEST = hashlib.sha256(_OBSERVE.encode()).hexdigest()


class AdapterError(db.PreparationError):
    """Fixed redacted code; a known helper CID remains available on uncertainty."""

    def __init__(self, code, *, helper_id=None):
        super().__init__(code)
        self.helper_id = helper_id if type(helper_id) is str and _HEX.fullmatch(helper_id) else None


def _fail(code="DB_TARGET_UNVERIFIED", *, helper_id=None):
    raise AdapterError(code, helper_id=helper_id) from None


def cluster_fingerprint(identifier):
    if type(identifier) not in {str, int} or re.fullmatch(r"[1-9][0-9]{0,19}", str(identifier)) is None:
        _fail()
    if int(identifier) >= 2**64:
        _fail()
    return db._digest(["postgres-system-identifier-v1", str(identifier)])


@dataclass(frozen=True, slots=True)
class UtilityContract:
    """A reference for independent verification, never an approval token."""

    image: str
    platform: str
    observer_digest: str = OBSERVER_DIGEST

    def __post_init__(self):
        engine.dev_workspace_provider._image(self.image)
        if self.platform not in {"linux/amd64", "linux/arm64"} or self.observer_digest != OBSERVER_DIGEST:
            _fail("DB_POLICY_REQUIRED")


class DockerPreparationAdapter:
    """Uses the pinned Docker client's real resource verifier before every call.

    authority.verify_adapter(plan, consent, operation, fresh_records, contract)
    must return the complete independently verified checks below. journal.intent
    and journal.receipt must durably persist or raise. Observation creates a
    separately approved read-only helper before the executor's mutation claim.
    """

    def __init__(self, client, request, *, consent, authority, journal, utility_contract=None):
        if not isinstance(client, engine.DockerComposeClient):
            _fail("DB_POLICY_REQUIRED")
        self.client, self.request, self.consent = client, request, consent
        self.authority, self.journal, self.contract = authority, journal, utility_contract
        self.records = request.recorded
        self.helpers = {}
        self.unconfirmed_helper_ids = set()

    def _verify(self, plan, operation):
        try:
            fresh = db.plan_preparation(
                plan.provider_plan,
                plan.compose_plan,
                plan.records,
                plan.action,
                confirm_database=self.consent.confirm_database,
                source_fingerprint=plan.source_fingerprint,
                prior=plan.prior,
                migration=plan.migration,
            )
            if (
                fresh != plan
                or self.consent.plan_fingerprint != plan.fingerprint
                or self.consent.action != plan.action
                or self.request.recorded != plan.records
                or self.request.provider != plan.provider_plan
                or self.request.compose != plan.compose_plan
            ):
                _fail("DB_PROVIDER_DRIFT")
            self.client._current(self.request)
            self.client._engine()
            self.records = self.client._resources(self.request, records=self.records)
            checks = self.authority.verify_adapter(plan, self.consent, operation, self.records, self.contract)
            required = _CHECKS | {"preparation-server" if operation == "start-server" else "helper-tools"}
            if operation != "start-server":
                if (
                    type(self.contract) is not UtilityContract
                    or self.contract.image != plan.target.image
                    or self.contract.platform != self.client.capability.platform
                ):
                    _fail("DB_POLICY_REQUIRED")
            if operation == "observe":
                required |= {"read-only-volume-observer"}
            if operation == "initdb-helper":
                required |= {"initdb-image-tools", "fresh-empty-volume", "bootstrap-superuser"}
            if type(checks) is not frozenset or not required <= checks:
                _fail("DB_POLICY_REQUIRED")
        except AdapterError:
            raise
        except Exception:
            _fail("DB_PROVIDER_DRIFT")

    def _labels(self, plan, purpose):
        return dict(plan.provider_plan.labels) | {"sbom.dev.db.plan": plan.fingerprint, "sbom.dev.db.purpose": purpose}

    def _create(self, plan, purpose, command):
        self._verify(plan, "observe" if purpose == "observe" else "initdb-helper")
        labels = self._labels(plan, purpose)
        index = command.index(plan.target.image)
        extra = tuple(part for name, value in sorted(labels.items()) for part in ("--label", name + "=" + value))
        command = command[:index] + extra + command[index:]
        known = None
        try:
            self.journal.intent(plan, purpose + "-helper-create")
            raw = self.client._call(*command, timeout=10)
            known = raw.decode("ascii").strip()
            if _HEX.fullmatch(known) is None:
                _fail("DB_HELPER_UNCONFIRMED")
            self.unconfirmed_helper_ids.add(known)
            self.journal.receipt(plan, purpose + "-helper", known)
            self.helpers[known] = (purpose, command)
            self._helper(plan, known)
            self.unconfirmed_helper_ids.discard(known)
            return known
        except BaseException:
            _fail("DB_HELPER_UNCONFIRMED", helper_id=known)

    def _helper(self, plan, helper_id):
        """No adoption: only a CID returned and durably recorded by this object."""
        if helper_id not in self.helpers:
            _fail("DB_HELPER_UNCONFIRMED", helper_id=helper_id)
        purpose, command = self.helpers[helper_id]
        self._verify(plan, "observe" if purpose == "observe" else "initdb-helper")
        value = self.client._inspect("container", helper_id)
        image = self.client._inspect("image", plan.target.image)
        config, host, state = value.get("Config", {}), value.get("HostConfig", {}), value.get("State", {})
        index = command.index(plan.target.image)
        entrypoint = command[command.index("--entrypoint") + 1]
        mounts = [("volume", plan.target.volume_id, "/var/lib/postgresql/data", purpose != "observe")]
        if purpose == "initdb":
            reference = compose.secret_layout(plan.provider_plan)["postgres"]["bootstrap"]
            secret = next(item for item in self.records.secrets if item.reference == reference)
            if engine._file(secret.path, private=True) != secret.identity:
                _fail("DB_TARGET_UNVERIFIED")
            mounts.append(("bind", str(secret.path), "/run/secrets/bootstrap-password", False))
        actual = [
            (
                m.get("Type"),
                m.get("Name") if m.get("Type") == "volume" else m.get("Source"),
                m.get("Destination"),
                m.get("RW"),
            )
            for m in value.get("Mounts", [])
        ]
        if (
            value.get("Id") != helper_id
            or value.get("Image") != image.get("Id")
            or plan.target.image not in (image.get("RepoDigests") or [])
            or image.get("Os", "") + "/" + image.get("Architecture", "") != self.client.capability.platform
            or config.get("Image") != plan.target.image
            or config.get("User") != plan.target.user
            or config.get("Entrypoint") != [entrypoint]
            or tuple(config.get("Cmd") or ()) != command[index + 1 :]
            or config.get("Labels") != (image.get("Config", {}).get("Labels") or {}) | self._labels(plan, purpose)
            or config.get("Env") != image.get("Config", {}).get("Env")
            or config.get("Healthcheck") not in (None, {"Test": ["NONE"]})
            or sorted(actual) != sorted(mounts)
            or len(actual) != len(mounts)
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapDrop") != ["ALL"]
            or host.get("CapAdd") not in (None, [])
            or host.get("SecurityOpt") != ["no-new-privileges:true"]
            or host.get("Devices") not in (None, [])
            or host.get("Binds") not in (None, [])
            or host.get("DeviceRequests") not in (None, [])
            or host.get("VolumesFrom") not in (None, [])
            or host.get("PidMode") not in (None, "")
            or host.get("IpcMode") not in (None, "private", "")
            or host.get("UTSMode") not in (None, "")
            or host.get("CgroupnsMode") not in (None, "private", "")
            or host.get("Sysctls") not in (None, {})
            or host.get("ExtraHosts") not in (None, [])
            or host.get("PortBindings") not in (None, {})
            or host.get("Tmpfs") not in (None, {})
            or host.get("AutoRemove") is not False
            or host.get("RestartPolicy", {}).get("Name") not in ("no", "")
            or host.get("PidsLimit") != 192
            or host.get("Memory") != 805306368
            or host.get("NanoCpus") != 1500000000
            or state.get("Status") not in {"created", "exited", "running"}
        ):
            _fail("DB_HELPER_UNCONFIRMED", helper_id=helper_id)
        return state

    def _run(self, plan, helper_id, timeout):
        if type(timeout) is not int or not 1 <= timeout <= 120:
            _fail("DB_HELPER_UNCONFIRMED", helper_id=helper_id)
        if self._helper(plan, helper_id)["Status"] not in {"created", "exited"}:
            _fail("DB_HELPER_UNCONFIRMED", helper_id=helper_id)
        try:
            self.journal.intent(plan, "helper-start")
            raw = self.client._call("container", "start", "--attach", helper_id, timeout=timeout)
            state = self._helper(plan, helper_id)
            if state["Status"] != "exited" or type(state.get("ExitCode")) is not int:
                _fail("DB_HELPER_UNCONFIRMED", helper_id=helper_id)
            return raw, state["ExitCode"]
        except BaseException:
            self.unconfirmed_helper_ids.add(helper_id)
            # Original CID only, fresh exact identity; never volume removal or PID escalation.
            try:
                if self._helper(plan, helper_id)["Status"] == "running":
                    self.client._call("container", "stop", "--time", "2", helper_id, timeout=5)
                if self._helper(plan, helper_id)["Status"] == "exited":
                    self.unconfirmed_helper_ids.discard(helper_id)
            except BaseException:
                pass
            _fail("DB_HELPER_UNCONFIRMED", helper_id=helper_id)

    def observe(self, plan):
        command = (
            "container",
            "create",
            "--pull",
            "never",
            "--network",
            "none",
            "--user",
            plan.target.user,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--restart",
            "no",
            "--pids-limit",
            "192",
            "--memory",
            "805306368",
            "--cpus",
            "1.5",
            "--entrypoint",
            "/bin/sh",
            "--mount",
            "type=volume,source=" + plan.target.volume_id + ",target=/var/lib/postgresql/data,readonly,volume-nocopy",
            plan.target.image,
            "-c",
            _OBSERVE,
        )
        helper_id = self._create(plan, "observe", command)
        raw, code = self._run(plan, helper_id, 10)
        match = re.fullmatch(
            rb"SBOMPG1 ([0-9]{1,10}) ([0-9]{1,10}) ([0-7]{3,4}) (EMPTY|INITIALIZED) ([0-9]{1,20})\n", raw
        )
        if code != 0 or match is None:
            _fail("DB_VOLUME_NOT_FRESH", helper_id=helper_id)
        uid, gid, mode, population, identifier = (item.decode("ascii") for item in match.groups())
        initialized = population == "INITIALIZED"
        if (int(uid), int(gid)) != tuple(map(int, plan.target.user.split(":"))) or int(mode, 8) != 0o700:
            _fail("DB_VOLUME_NOT_FRESH", helper_id=helper_id)
        if not initialized and identifier != "0":
            _fail("DB_VOLUME_NOT_FRESH", helper_id=helper_id)
        value = self.client._inspect("container", plan.target.postgres_id)
        return db.ProviderState(
            plan.target.fingerprint(),
            population,
            value["State"]["Status"],
            int(uid),
            int(gid),
            int(mode, 8),
            cluster_fingerprint(identifier) if initialized else None,
        )

    def create_helper(self, plan, command):
        if plan.action != "initdb" or command != db.initdb_command(plan):
            _fail("DB_POLICY_REQUIRED")
        return self._create(plan, "initdb", command)

    def run_helper(self, plan, helper_id, *, timeout):
        if self.helpers.get(helper_id, (None,))[0] != "initdb":
            _fail("DB_HELPER_UNCONFIRMED", helper_id=helper_id)
        return self._run(plan, helper_id, timeout)[1]

    def start_server(self, plan, command, *, timeout):
        if (
            plan.action not in {"database", "migrate"}
            or command != ("container", "start", plan.target.postgres_id)
            or timeout != 30
        ):
            _fail("DB_POLICY_REQUIRED")
        self._verify(plan, "start-server")
        try:
            if self.client._inspect("container", plan.target.postgres_id).get("State", {}).get("Status") not in {
                "created",
                "exited",
            }:
                _fail("DB_PROVIDER_DRIFT")
            self.journal.intent(plan, "preparation-server-start")
            self.client._call(*command, timeout=timeout)
            # Refresh only this expected start, then pin its new StartedAt for all subsequent calls.
            updated = self.client._resources(
                self.request, records=self.records, refresh=True, expected_states={"postgres": {"running"}}
            )
            before = {item.component: item for item in self.records.containers}
            if any(item.component != "postgres" and item != before[item.component] for item in updated.containers):
                _fail("DB_PROVIDER_DRIFT")
            self.records = updated
        except BaseException:
            _fail("DB_PREPARATION_UNCONFIRMED")


@dataclass(frozen=True, slots=True)
class ConnectionFiles:
    """Private pre-recorded identities, not paths silently adopted at connect time."""

    bootstrap: engine.SecretFile = field(repr=False)
    runtime: engine.SecretFile = field(repr=False)
    ca: engine.SecretFile = field(repr=False)


def _read_private_bytes(item):
    """Bind the opened descriptor to the recorded FID, not just path snapshots."""
    try:
        if type(item) is not engine.SecretFile or engine._file(item.path, private=True) != item.identity:
            _fail()
        fd = os.open(item.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            stream = os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
        with stream:

            def verify():
                value = os.fstat(stream.fileno())
                stamp = (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                if (
                    stamp != item.identity
                    or not stat.S_ISREG(value.st_mode)
                    or value.st_nlink != 1
                    or getattr(value, "st_file_attributes", 0) & 1024
                    or engine._file(item.path, private=True) != item.identity
                ):
                    _fail()

            verify()
            raw = stream.read(16385)
            verify()
        if not 24 <= len(raw) <= 16384:
            _fail()
        return raw
    except Exception:
        _fail()


def _read_secret(item):
    try:
        raw = _read_private_bytes(item)
        value = raw.decode("ascii")
        if re.fullmatch(r"[A-Za-z0-9_-]{24,16384}", value) is None:
            _fail()
        return value
    except Exception:
        _fail()


_IDENTITY = """SELECT current_database(), session_user, current_user,
 current_setting('transaction_read_only'), current_setting('statement_timeout'),
 current_setting('lock_timeout'), current_setting('idle_in_transaction_session_timeout')"""
_ROLES = """SELECT r.rolname,r.oid,r.rolcanlogin,r.rolinherit,r.rolsuper,r.rolcreatedb,
 r.rolcreaterole,r.rolreplication,r.rolbypassrls,
 ARRAY(SELECT roleid FROM pg_auth_members WHERE member=r.oid ORDER BY roleid)
 FROM pg_roles r WHERE r.rolname IN (%s,%s) ORDER BY r.rolname"""
_DATABASE = "SELECT d.oid,r.rolname FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname=%s"
# No table contents or account identities are read. Catalog definitions remain
# private in memory and contribute only to the structural fingerprint.
_STRUCTURE = """SELECT jsonb_build_array(c.oid,c.relname,c.relkind,c.relowner,c.relrowsecurity,
 c.relforcerowsecurity,c.relacl::text,c.reloptions,
 COALESCE((SELECT jsonb_agg(jsonb_build_array(a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,
 a.attidentity,a.attgenerated,a.attcollation,
 (SELECT pg_get_expr(d.adbin,d.adrelid) FROM pg_attrdef d WHERE d.adrelid=c.oid AND d.adnum=a.attnum))
 ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'),
 COALESCE((SELECT jsonb_agg(jsonb_build_array(x.contype,pg_get_constraintdef(x.oid)) ORDER BY x.oid)
 FROM pg_constraint x WHERE x.conrelid=c.oid),'[]'),
 COALESCE((SELECT jsonb_agg(pg_get_indexdef(i.indexrelid) ORDER BY i.indexrelid)
 FROM pg_index i WHERE i.indrelid=c.oid),'[]'),
 COALESCE((SELECT jsonb_agg(jsonb_build_array(p.polname,p.polcmd,p.polpermissive,p.polroles,
 pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) ORDER BY p.oid)
 FROM pg_policy p WHERE p.polrelid=c.oid),'[]'),
 COALESCE((SELECT jsonb_agg(pg_get_triggerdef(t.oid) ORDER BY t.oid)
 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal),'[]'))
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.oid LIMIT 10001"""
_FUNCTIONS = """SELECT p.oid,p.proname,p.proowner,p.prosecdef,p.proacl::text,pg_get_functiondef(p.oid)
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND p.prokind IN ('f','p') ORDER BY p.oid LIMIT 10001"""
_TYPES = """SELECT t.oid,t.typname,t.typowner,t.typtype,t.typbasetype,t.typnotnull,t.typdefault,t.typacl::text,
 ARRAY(SELECT enumlabel FROM pg_enum e WHERE e.enumtypid=t.oid ORDER BY enumsortorder)
 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' ORDER BY t.oid LIMIT 10001"""
_NAMESPACES = """SELECT nspname,nspowner,nspacl::text FROM pg_namespace
 WHERE nspname !~ '^pg_' AND nspname<>'information_schema' ORDER BY nspname LIMIT 10001"""
_UNSAFE = """SELECT EXISTS(SELECT 1 FROM pg_namespace n,
 LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
 WHERE n.nspname='public' AND a.grantee=0 AND a.privilege_type='CREATE'),
 EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
 LATERAL aclexplode(COALESCE(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) a
 WHERE n.nspname='public' AND (a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=%s))
 AND (a.is_grantable OR a.privilege_type NOT IN ('SELECT','INSERT','UPDATE','DELETE','USAGE')
 OR (c.relname='alembic_version' AND a.privilege_type<>'SELECT'))),
 EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'),
 EXISTS(SELECT 1 FROM pg_default_acl),
 EXISTS(SELECT 1 FROM pg_database d,
 LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a
 WHERE d.datname=current_database() AND (a.grantee=0 OR a.grantee=(SELECT oid FROM pg_roles WHERE rolname=%s))
 AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'CONNECT')),
 has_schema_privilege(%s,'public','CREATE'),
 has_database_privilege(%s,current_database(),'CONNECT'),has_schema_privilege(%s,'public','USAGE')"""


class PsycopgDatabaseAdapter:
    """Explicit libpq parameters, private file revalidation and trusted TLS binding.

    authority.verify_database(plan, stage, connection) must independently verify
    current preparation consent/source/provider/exclusivity and return _CHECKS
    plus 'database-session' (and 'credential-audit' for password installation).
    peer_verifier(connection, plan, ca_file) must bind the actual TLS connection
    to a certificate fingerprint. A host-only preflight is insufficient.
    Driver may be injected in synthetic tests; lazy real import occurs at open.
    """

    def __init__(self, files, *, authority, peer_verifier, driver=None):
        if type(files) is not ConnectionFiles or not callable(peer_verifier):
            _fail("DB_POLICY_REQUIRED")
        self.files, self.authority, self.peer_verifier, self.driver = files, authority, peer_verifier, driver

    def _gate(self, plan, stage, connection=None):
        try:
            checks = self.authority.verify_database(plan, stage, connection)
            required = _CHECKS | {"database-session"}
            if stage == "credential":
                required |= {"credential-audit"}
            if type(checks) is not frozenset or not required <= checks:
                _fail("DB_POLICY_REQUIRED")
            for item in (self.files.bootstrap, self.files.runtime, self.files.ca):
                if engine._file(item.path, private=True) != item.identity:
                    _fail()
            refs = compose.secret_layout(plan.provider_plan)["postgres"]
            if (
                self.files.bootstrap.reference != refs["bootstrap"]
                or self.files.runtime.reference != refs["runtime"]
                or self.files.ca.reference != refs["ca"]
                or any(
                    item not in plan.records.secrets
                    for item in (self.files.bootstrap, self.files.runtime, self.files.ca)
                )
            ):
                _fail()
        except AdapterError:
            raise
        except Exception:
            _fail("DB_POLICY_REQUIRED")

    def open(self, plan, database, *, readonly=False):
        if (
            type(plan) is not db.PreparationPlan
            or database not in {"postgres", plan.target.database}
            or type(readonly) is not bool
            or plan.action not in {"database", "migrate"}
        ):
            _fail()
        self._gate(plan, "connect")
        # Prevent ambient libpq service/preload/keylog files from contributing to
        # a preparation connection. No dotenv or process environment mutation.
        if any(
            value and (name.startswith("PG") or name in {"SSLKEYLOGFILE", "OPENSSL_CONF", "OPENSSL_MODULES"})
            for name, value in os.environ.items()
        ):
            _fail("DB_POLICY_REQUIRED")
        connection = None
        try:
            driver = self.driver
            if driver is None:
                import psycopg as driver
            password = _read_secret(self.files.bootstrap)
            connection = driver.connect(
                host="127.0.0.1",
                hostaddr="127.0.0.1",
                port=plan.target.port,
                dbname=database,
                user=plan.target.bootstrap_role,
                password=password,
                sslmode="verify-full",
                sslrootcert=str(self.files.ca.path),
                sslcert="",
                sslkey="",
                sslcrl="",
                sslcrldir="",
                gssencmode="disable",
                channel_binding="require",
                connect_timeout=3,
                tcp_user_timeout=3000,
                keepalives=1,
                keepalives_idle=3,
                keepalives_interval=1,
                keepalives_count=2,
                application_name="sbom-isolated-preparation",
                autocommit=True,
                options="-c statement_timeout=3000 -c lock_timeout=250 -c idle_in_transaction_session_timeout=5000"
                " -c search_path=pg_catalog,public -c default_transaction_read_only=" + ("on" if readonly else "off"),
            )
            del password
            self._gate(plan, "connected", connection)
            if connection.pgconn.ssl_in_use is not True:
                _fail()
            peer = self.peer_verifier(connection, plan, self.files.ca)
            if type(peer) is not str or _HEX.fullmatch(peer) is None:
                _fail()
            session = PsycopgSession(self, driver, connection, plan, database, readonly, peer)
            session.inspect()
            return session
        except BaseException:
            if connection is not None:
                try:
                    connection.close()
                except BaseException:
                    pass
            _fail("DB_TARGET_UNVERIFIED")


class PsycopgSession:
    def __init__(self, adapter, driver, connection, plan, name, readonly, peer):
        self.adapter, self.driver, self.connection, self.plan = adapter, driver, connection, plan
        self.name, self.readonly, self.peer = name, readonly, peer
        self.active, self.closed = False, False
        self.cluster = None
        self.backend_pid = connection.pgconn.backend_pid
        if type(self.backend_pid) is not int or not 0 < self.backend_pid < 2**31:
            _fail()

    def _rows(self, sql, params=None):
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(sql, params)
                rows = cursor.fetchmany(10001)
            if len(rows) > 10000 or len(json.dumps(rows, default=str).encode()) > _LIMIT:
                _fail()
            return rows
        except AdapterError:
            raise
        except Exception:
            _fail("DB_TARGET_UNVERIFIED")

    def _execute(self, sql):
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(sql)
        except Exception:
            _fail("DB_PREPARATION_UNCONFIRMED")

    def _gate(self, stage, *, write=False):
        if self.closed or write and (self.readonly or self.name not in {"postgres", self.plan.target.database}):
            _fail("DB_POLICY_REQUIRED")
        self.adapter._gate(self.plan, stage, self.connection)
        if self.connection.pgconn.ssl_in_use is not True:
            _fail()
        if self.connection.pgconn.backend_pid != self.backend_pid:
            _fail()
        if self.adapter.peer_verifier(self.connection, self.plan, self.adapter.files.ca) != self.peer:
            _fail()

    def inspect(self):
        self._gate("inspect")
        target = self.plan.target
        identity = self._rows(_IDENTITY)
        if len(identity) != 1 or len(identity[0]) != 7:
            _fail()
        name, user, effective, readonly, statement, lock, idle = identity[0]
        if (
            name != self.name
            or user != target.bootstrap_role
            or effective not in {target.bootstrap_role, target.owner_role}
            or readonly != ("on" if self.readonly else "off")
            or statement != "3s"
            or lock != "250ms"
            or idle != "5s"
        ):
            _fail()
        if self.cluster is None:
            if effective != target.bootstrap_role:
                _fail()
            self.cluster = cluster_fingerprint(
                self._rows("SELECT system_identifier::text FROM pg_control_system()")[0][0]
            )
        if self.plan.prior is None or self.cluster != self.plan.prior.cluster_id:
            _fail("DB_TARGET_UNVERIFIED")
        roles = tuple(
            db.RoleState(*row[:-1], tuple(row[-1]))
            for row in self._rows(_ROLES, (target.owner_role, target.runtime_role))
        )
        database = self._rows(_DATABASE, (target.database,))
        if len(database) > 1:
            _fail()
        structure = self._rows(_STRUCTURE)
        functions, types, namespaces = self._rows(_FUNCTIONS), self._rows(_TYPES), self._rows(_NAMESPACES)
        revisions = ()
        if any(row[0][1] == "alembic_version" for row in structure):
            revisions = tuple(
                row[0]
                for row in self._rows("SELECT version_num FROM public.alembic_version ORDER BY version_num LIMIT 9")
            )
        public_create, unsafe, unsafe_functions, defaults, db_create, schema_create, connect, usage = (
            True,
            True,
            True,
            True,
            True,
            True,
            False,
            False,
        )
        if any(role.name == target.runtime_role for role in roles):
            public_create, unsafe, unsafe_functions, defaults, db_create, schema_create, connect, usage = self._rows(
                _UNSAFE, (target.runtime_role,) * 5
            )[0]
            if any(
                type(value) is not bool
                for value in (
                    public_create,
                    unsafe,
                    unsafe_functions,
                    defaults,
                    db_create,
                    schema_create,
                    connect,
                    usage,
                )
            ):
                _fail()
        safe = (
            not any((public_create, unsafe, unsafe_functions, defaults, db_create, schema_create)) and connect and usage
        )
        return db.DatabaseState(
            self.cluster,
            name,
            user,
            self.peer,
            True,
            roles,
            bool(database),
            database[0][0] if database else None,
            database[0][1] if database else None,
            not structure and not functions and not types and all(row[0] == "public" for row in namespaces),
            public_create,
            safe,
            revisions,
            effective,
            self.readonly,
            db._digest({"relations": structure, "functions": functions, "types": types, "namespaces": namespaces}),
        )

    def begin(self):
        self._gate("begin", write=True)
        if self.active:
            _fail("DB_POLICY_REQUIRED")
        self._execute("BEGIN")
        self.active = True
        key = int(self.plan.target.fingerprint()[:15], 16)
        self._rows("SELECT pg_advisory_xact_lock(%s)", (key,))

    def apply(self, operation, sql):
        self._gate(operation, write=True)
        allowed = {
            "database": {"create-owner", "create-runtime", "create-database", "prepare-schema", "runtime-login"},
            "migrate": {"migration-owner", "runtime-grants"},
        }
        expected_database = (
            "postgres"
            if operation in {"create-owner", "create-runtime", "create-database"}
            else self.plan.target.database
        )
        if operation not in allowed.get(self.plan.action, set()) or self.name != expected_database:
            _fail("DB_POLICY_REQUIRED")
        if sql != db.statements(self.plan, operation) or (operation == "create-database") == self.active:
            _fail("DB_POLICY_REQUIRED")
        if operation == "create-database" and self.name != "postgres":
            _fail("DB_POLICY_REQUIRED")
        for statement in sql:
            self._gate(operation, write=True)
            self._execute(statement.compose(self.driver.sql))
        if operation in {"create-owner", "create-runtime"}:
            role = self.plan.target.owner_role if operation == "create-owner" else self.plan.target.runtime_role
            rows = self._rows("SELECT oid FROM pg_roles WHERE rolname=%s", (role,))
            return self._oid(rows)
        if operation == "create-database":
            return self._oid(self._rows(_DATABASE, (self.plan.target.database,)))
        return None

    @staticmethod
    def _oid(rows):
        if len(rows) != 1 or not rows[0] or type(rows[0][0]) is not int or not 0 < rows[0][0] < 2**32:
            _fail("DB_ROLE_OR_SCHEMA_CONFLICT")
        return rows[0][0]

    def install_runtime_credential(self, role, reference):
        self._gate("credential", write=True)
        if (
            not self.active
            or self.plan.action != "database"
            or self.name != self.plan.target.database
            or role != self.plan.target.runtime_role
            or reference != self.adapter.files.runtime.reference
        ):
            _fail("DB_POLICY_REQUIRED")
        try:
            if (
                self.driver.pq.version() < 170000
                or not callable(getattr(self.connection.pgconn, "change_password", None))
                or self._rows("SHOW password_encryption") != [("scram-sha-256",)]
            ):
                _fail("DB_POLICY_REQUIRED")
            password = _read_secret(self.adapter.files.runtime)
            # Native libpq encryption; never SQL interpolation, argv or application logs.
            self.connection.pgconn.change_password(role.encode("ascii"), password.encode("ascii"))
            del password
        except AdapterError:
            raise
        except Exception:
            _fail("DB_PREPARATION_UNCONFIRMED")

    def commit(self):
        self._gate("commit", write=True)
        if not self.active:
            _fail("DB_POLICY_REQUIRED")
        self._execute("COMMIT")
        self.active = False

    def rollback(self):
        if not self.closed and self.active:
            self._execute("ROLLBACK")
            self.active = False

    def close(self):
        if not self.closed:
            try:
                self.connection.close()
                self.closed = True
            except Exception:
                _fail("DB_PREPARATION_UNCONFIRMED")


class ReviewedMigrationAdapter:
    """Explicit reviewed callable; no dynamic import, Alembic dispatch or retry.

    verifier(plan, callback) must independently re-read/pin all selected source
    files and controller identity, review transaction compatibility and return
    the exact plan fingerprint. A literal source hash supplied by a caller does
    not satisfy this contract. Callback uses only this already-owned transaction.
    """

    def __init__(self, callback, *, verifier):
        self.callback, self.verifier = callback, verifier

    def apply(self, plan, session):
        if (
            plan.action != "migrate"
            or plan.migration is None
            or type(session) is not PsycopgSession
            or session.plan != plan
            or not session.active
            or session.readonly
            or not callable(self.callback)
            or not callable(self.verifier)
        ):
            _fail("DB_MIGRATION_REVIEW_REQUIRED")
        session._gate("migration-source", write=True)
        try:
            if self.verifier(plan, self.callback) != plan.fingerprint:
                _fail("DB_MIGRATION_REVIEW_REQUIRED")
            self.callback(plan, session)
            if self.verifier(plan, self.callback) != plan.fingerprint or not session.active:
                _fail("DB_MIGRATION_REVIEW_REQUIRED")
        except AdapterError:
            raise
        except Exception:
            _fail("DB_PREPARATION_UNCONFIRMED")
