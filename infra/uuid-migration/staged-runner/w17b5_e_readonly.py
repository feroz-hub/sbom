"""W1.7B.5: inert import, offline review, future single E-only READ ONLY probe.

No historical helper import. No migration/test executor. Live requires separately
approved source and action pins. The 60s deadline is cooperative, not a hard kill.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

CANDIDATE = "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b4-20261018T141154944489Z/w17b5-e-readonly-acceptance-candidate.json"
CANDIDATE_SHA = "62e597cdce45606a1ba878390b3d51be5e39cf9ec8cd4a1168255e882793de01"
EXPIRY = "2026-10-19T14:18:51.915560+00:00"
REFERENCE = "/Users/ferozebasha/.sbom-uuid-w1-disposable-20261016/w17b2-20261018T034519653246Z/D-PREFLIGHT.private.json"
REFERENCE_SHA = "c0e214ba35ed0d00ef4e8004aa43955799b912ad7a8497b6cbf0638d54aab04e"
E_CONTAINER = "05745ce4998f26f3b46467f13315e50affc7a689e0e2bde664b3d9e8ce4fa98a"
E_NETWORK = "311da1a7411dbf72e7a84804b0a61f5ff320b1054c4e9722f96dd9e511d8a144"
DAEMON = "1f8c7fe5-5972-4adc-8d6e-363a38572be1"
D_CLUSTER = "7697252084555804711"
TARGET = {
    "host": "127.0.0.1",
    "hostaddr": "127.0.0.1",
    "port": 56042,
    "database": "uuid_w17_e_integrity",
    "user": "uuid_w1_d_bootstrap",
}
LIMITS = {"attempts": 1, "connections": 1, "queries": 64, "controls": 4, "seconds": 60}
CLEAN_ENV = {"HOME": "/Users/ferozebasha", "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
FLAGS = (
    "synthetic_only_reviewed",
    "schema_parity_reviewed",
    "privileges_and_writers_reviewed",
    "credential_provenance_reviewed",
    "exclusive_test_window_reviewed",
    "outbound_risk_reviewed",
    "fixture_ddl_reviewed",
)
OPTIONS = (
    "-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=250 "
    "-c idle_in_transaction_session_timeout=5000 -c search_path=pg_catalog -c row_security=on"
)

# Only these exact catalog statements can reach execute(). No caller-supplied SQL.
QUERIES = {
    "readonly": "SHOW transaction_read_only",
    "identity": "SELECT pg_catalog.current_database(),current_user,session_user,d.oid::int,"
    "s.system_identifier::text,pg_catalog.current_setting('server_version_num')::int,"
    "pg_catalog.host(pg_catalog.inet_server_addr()),pg_catalog.inet_server_port(),"
    "pg_catalog.pg_postmaster_start_time()::text,pg_catalog.pg_is_in_recovery(),"
    "pg_catalog.current_setting('session_replication_role') "
    "FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_control_system() s "
    "WHERE d.datname=pg_catalog.current_database()",
    "settings": "SELECT pg_catalog.current_setting('data_directory'),"
    "pg_catalog.current_setting('statement_timeout'),pg_catalog.current_setting('lock_timeout'),"
    "pg_catalog.current_setting('idle_in_transaction_session_timeout'),"
    "pg_catalog.current_setting('password_encryption'),pg_catalog.current_setting('ssl'),"
    "pg_catalog.current_setting('max_connections'),pg_catalog.current_setting('shared_buffers'),"
    "pg_catalog.current_setting('work_mem'),pg_catalog.current_setting('row_security'),"
    "pg_catalog.current_setting('search_path'),pg_catalog.current_setting('default_transaction_read_only')",
    "database": "SELECT pg_catalog.pg_get_userbyid(datdba),datacl::text,datallowconn,datistemplate "
    "FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()",
    "db_properties": "SELECT pg_catalog.pg_encoding_to_char(encoding),datcollate,datctype,"
    "datlocprovider::text,daticulocale,datcollversion FROM pg_catalog.pg_database "
    "WHERE datname=pg_catalog.current_database()",
    "schemas": "SELECT nspname,pg_catalog.pg_get_userbyid(nspowner),nspacl::text,"
    "pg_catalog.obj_description(oid,'pg_namespace') FROM pg_catalog.pg_namespace "
    "WHERE nspname !~ '^pg_' AND nspname<>'information_schema' ORDER BY nspname",
    "relations": "SELECT c.relkind::text,c.relname FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
    "WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' ORDER BY 1,2",
    "objects": "SELECT (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
    "ON n.oid=p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),"
    "(SELECT count(*) FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n "
    "ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),"
    "(SELECT count(*) FROM pg_catalog.pg_default_acl),"
    "(SELECT count(*) FROM pg_catalog.pg_event_trigger),"
    "(SELECT count(*) FROM pg_catalog.pg_foreign_server),"
    "(SELECT count(*) FROM pg_catalog.pg_foreign_data_wrapper),"
    "(SELECT count(*) FROM pg_catalog.pg_publication),"
    "(SELECT count(*) FROM pg_catalog.pg_subscription)",
    "alembic": "SELECT pg_catalog.to_regclass('public.alembic_version')::text",
    "roles": "SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,"
    "rolreplication,rolbypassrls,rolconnlimit,rolconfig FROM pg_catalog.pg_roles ORDER BY rolname",
    "memberships": "SELECT r.rolname,m.rolname,g.rolname,a.admin_option,a.inherit_option,a.set_option "
    "FROM pg_catalog.pg_auth_members a JOIN pg_catalog.pg_roles r ON r.oid=a.roleid "
    "JOIN pg_catalog.pg_roles m ON m.oid=a.member JOIN pg_catalog.pg_roles g "
    "ON g.oid=a.grantor ORDER BY 1,2,3",
    "owner_absent": "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s",
    "auth": "SELECT bool_and(error IS NULL AND auth_method='scram-sha-256') FROM pg_catalog.pg_hba_file_rules",
    "password_properties": "SELECT rolpassword IS NOT NULL,rolpassword LIKE 'SCRAM-SHA-256$%' "
    "FROM pg_catalog.pg_authid WHERE rolname=current_user",
    "extension": "SELECT e.extname,e.extversion,n.nspname,e.extrelocatable,e.extconfig::regclass[]::text,"
    "e.extcondition::text FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n "
    "ON n.oid=e.extnamespace ORDER BY 1",
    "extension_owner": "SELECT pg_catalog.pg_get_userbyid(extowner) FROM pg_catalog.pg_extension "
    "WHERE extname='plpgsql'",
    "language": "SELECT lanname,lanispl,lanpltrusted,lanplcallfoid::regprocedure::text,"
    "laninline::regprocedure::text,lanvalidator::regprocedure::text,lanacl::text "
    "FROM pg_catalog.pg_language WHERE lanname='plpgsql'",
    "routines": "SELECT p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid),"
    "pg_catalog.pg_get_functiondef(p.oid),p.prosecdef,p.proleakproof,p.provolatile::text,"
    "p.proparallel::text,p.proacl::text,p.proconfig FROM pg_catalog.pg_proc p WHERE p.oid IN "
    "(SELECT lanplcallfoid FROM pg_catalog.pg_language WHERE lanname='plpgsql' UNION "
    "SELECT laninline FROM pg_catalog.pg_language WHERE lanname='plpgsql' UNION "
    "SELECT lanvalidator FROM pg_catalog.pg_language WHERE lanname='plpgsql') ORDER BY 1",
    "privileges": "SELECT pg_catalog.has_database_privilege(current_user,pg_catalog.current_database(),'CONNECT'),"
    "pg_catalog.has_schema_privilege(current_user,'public','USAGE'),"
    "pg_catalog.has_function_privilege(current_user,'pg_catalog.pg_control_system()','EXECUTE')",
    "clients": "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=pg_catalog.current_database() "
    "AND backend_type='client backend' AND pid<>pg_catalog.pg_backend_pid()",
    "locks": "SELECT count(*) FROM pg_catalog.pg_locks WHERE pid IS DISTINCT FROM pg_catalog.pg_backend_pid() "
    "AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()) "
    "AND relation IS NOT NULL",
    "role_settings": "SELECT count(*) FROM pg_catalog.pg_db_role_setting",
}
CONTROLS = ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", "ROLLBACK")


class Refusal(Exception):
    """Fixed safe messages only; never interpolate driver values."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode())


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def approved_manifest(path, approved_sha256, original_raw=None):
    """Bind operator authority to exact private bytes, before parsing any values."""
    require(
        isinstance(approved_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", approved_sha256),
        "Operator-approved manifest byte SHA256 required",
    )
    raw = private_bytes(path)
    require(sha(raw) == approved_sha256, "Approved manifest bytes changed")
    require(original_raw is None or raw == original_raw, "Original manifest bytes changed")
    plan = unique_json(raw)
    require(isinstance(plan, dict), "Manifest object required")
    return raw, plan


def recheck_manifest(path, approved_sha256, original_raw, original_plan, original_candidate, action_ref):
    """Reread the same path; never adopt changed values at the pre-auth boundary."""
    raw, plan = approved_manifest(path, approved_sha256, original_raw)
    require(plan == original_plan, "Initial manifest semantics changed")
    fresh_candidate = candidate()
    require(fresh_candidate == original_candidate, "Original candidate changed before authentication")
    validate_manifest(plan, fresh_candidate, action_ref, source_pins(fresh_candidate), dependency_pins())
    return raw, plan


def hba_evidence():
    """The catalog view parses the current file; it is not the loaded-rule set."""
    return {
        "hba_evidence_scope": "current_file_contents_and_parse_only",
        "active_hba_rules": "UNKNOWN",
        "password_challenge": "UNKNOWN",
    }


def private_bytes(path, maximum=1048576):
    """Explicit review files only; this helper is never used for the password."""
    p = Path(path)
    require(p.suffix == ".json", "Only JSON review artifacts permitted; no credential-file reads")
    require(maximum == 1048576 or (str(p) == REFERENCE and maximum == 4194304), "Unapproved artifact read bound")
    require(p.is_absolute() and not any(x.is_symlink() for x in (p, *p.parents)), "Private canonical path required")
    require(
        not p.resolve().is_relative_to(Path(__file__).resolve().parents[3]), "Private files outside checkout required"
    )
    parent = p.parent.lstat()
    require(parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700, "Private directory required")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        s = os.fstat(stream.fileno())
        require(
            stat.S_ISREG(s.st_mode)
            and s.st_nlink == 1
            and s.st_uid == os.getuid()
            and stat.S_IMODE(s.st_mode) == 0o600
            and 0 < s.st_size <= maximum,
            "Private file required",
        )
        return stream.read(maximum + 1)


def candidate():
    raw = private_bytes(CANDIDATE)
    require(sha(raw) == CANDIDATE_SHA, "Original candidate changed")
    c = unique_json(raw)
    require(c["expires_utc"] == EXPIRY and datetime.fromisoformat(EXPIRY) > datetime.now(UTC), "Candidate expired")
    return c


def source_pins(c):
    here = Path(__file__).parent
    paths = {
        name: here.parent / "staged-alembic" / name if name[:3].isdigit() else here / name
        for name in c["source_sha256"]
    }
    paths.update(
        {
            name: here / name
            for name in ("w17b5_e_readonly.py", "test_w17b5_e_readonly.py", "test_uuid_integrity_connection_offline.py")
        }
    )
    return {name: sha(path.read_bytes()) for name, path in paths.items()}


def dependency_pins():
    """Pin installed direct/transitive non-stdlib distributions without connecting."""
    result = {"python_version": sys.version, "python_executable_sha256": sha(Path(sys.executable).read_bytes())}
    for name in ("psycopg", "psycopg-binary", "SQLAlchemy", "alembic"):
        distribution = importlib.metadata.distribution(name)
        records = {
            str(f): sha(distribution.locate_file(f).read_bytes())
            for f in distribution.files
            if str(f).endswith((".py", ".so", ".dylib", ".pyd"))
        }
        require(bool(records), "Dependency sources unavailable")
        result[name] = {"version": distribution.version, "code_sha256": digest(records)}
    return result


def validate_manifest(plan, c, action_ref, sources, dependencies, now=None):
    now = now or datetime.now(UTC)
    require(not any(k.startswith("PG") for k in os.environ), "Ambient libpq overrides prohibited")
    require(
        plan.get("task") == "W1.7B.5" and plan.get("candidate_sha256") == CANDIDATE_SHA, "Candidate authority mismatch"
    )
    require(plan.get("expires_utc") == EXPIRY and datetime.fromisoformat(EXPIRY) > now, "Approval expired")
    require(plan.get("target") == TARGET and plan.get("limits") == LIMITS, "Target or budget changed")
    require(all(type(plan["limits"][k]) is int for k in LIMITS), "Integer limits required")
    require(
        plan.get("source_review_approved") is True and plan.get("read_only_execution_approved") is True,
        "Operator source/read-only approval pending",
    )
    require(
        isinstance(action_ref, str) and bool(action_ref) and plan.get("approvals") == {"read_only_execute": action_ref},
        "Fresh read_only_execute approval required",
    )
    require(
        plan.get("accepted") is False
        and plan.get("integrity_action_approvals") == {}
        and all(plan.get(k) is False for k in FLAGS),
        "No baseline or integrity authority allowed",
    )
    require(
        plan.get("source_sha256") == sources and all(sources[k] == v for k, v in c["source_sha256"].items()),
        "Reviewed sources changed",
    )
    require(plan.get("dependency_sha256") == dependencies, "Installed dependencies changed")
    require(
        plan.get("Docker_metadata_reference") == c["Docker_metadata_reference"]
        and plan.get("credential_reference") == c["credential_reference"],
        "Resource/credential pins changed",
    )
    require(plan.get("reference_sha256") == REFERENCE_SHA, "Read-only security reference changed")
    d = c["Docker_metadata_reference"]
    require(
        d["container"]["id"] == E_CONTAINER
        and d["network"]["id"] == E_NETWORK
        and d["daemon"]["id"] == DAEMON
        and d["volume"]["name"] == "sbom-uuid-w17-e_e_pgdata",
        "Exact E resource identity required",
    )


class Budget:
    def __init__(self, clock=None):
        self.clock = clock or time.monotonic
        self.started = self.clock()
        self.queries = self.controls = self.attempts = 0

    def before(self):
        require(self.clock() - self.started < 60, "Cooperative client deadline exhausted")

    def query(self):
        self.before()
        require(self.queries < 64, "Catalog query budget exhausted")
        self.queries += 1

    def control(self, cleanup=False):
        if not cleanup:
            self.before()
        require(self.controls < (4 if cleanup else 3), "Transaction control budget exhausted; rollback slot reserved")
        self.controls += 1

    def connect(self):
        self.before()
        require(self.attempts == 0, "No second connection attempt")
        self.attempts += 1


def sanitized(error, secret):
    """Primary diagnostics only; bounded redaction, never serialize exception args."""

    def clean(value):
        if not isinstance(value, str) or len(value) > 16384:
            return "UNCLASSIFIED_REDACTED"
        for literal in (secret.decode(errors="replace"), secret.decode(errors="replace").strip()):
            if literal:
                value = value.replace(literal, "[REDACTED]")
        value = re.sub(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s<>]+", "[REDACTED_URI]", value)
        value = re.sub(
            r"(?i)\b(?:password|passfile|sslpassword|token|access_token|PGPASSWORD|PGSERVICEFILE)"
            r"\s*=\s*(?:'[^']*'|\"[^\"]*\"|[^\s,;]+)",
            "[REDACTED_PARAMETER]",
            value,
        )
        value = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[^\s]+", "[REDACTED_AUTH]", value)
        value = re.sub(r"(?i)\b(?:SCRAM-SHA-256\$[^\s]+|md5[0-9a-f]{32}\b)", "[REDACTED_HASH]", value)
        if (
            "-----BEGIN" in value
            or "\x00" in value
            or len(re.findall(r"(?i)\b(?:host|hostaddr|port|dbname|user|service|options)\s*=", value)) > 1
        ):
            return "UNCLASSIFIED_REDACTED"
        return " ".join("".join(ch if ch.isprintable() else " " for ch in value).split())[:1024]

    primary = getattr(getattr(error, "diag", None), "message_primary", None)
    reason = clean(primary) if primary else clean(str(error))
    code = getattr(error, "sqlstate", None)
    if not isinstance(code, str) or not re.fullmatch(r"[0-9A-Z]{5}", code):
        code = None
    return {"exception_class": type(error).__name__, "sqlstate": code, "primary": reason}


class Evidence:
    def __init__(self, path):
        p = Path(path)
        require(p.is_absolute() and not any(x.is_symlink() for x in (p, *p.parents)), "Private evidence path required")
        require(not p.is_relative_to(Path(__file__).resolve().parents[3]), "Evidence outside checkout required")
        s = p.parent.stat()
        require(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700, "Private evidence parent required")
        self.stream = os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")

    def emit(self, label, status, **fields):
        self.stream.write(
            json.dumps(
                {"utc": datetime.now(UTC).isoformat(), "check": label, "status": status, **fields}, sort_keys=True
            )
            + "\n"
        )
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def close(self):
        self.stream.close()


def resource_preflight(c, ctl, budget, correlate=True, evidence=None):
    """Fresh exact E metadata and reviewed local secret guard. No SQL probes."""

    def metadata(*args):
        budget.before()
        if evidence:
            evidence.emit("Docker-" + args[0], "STARTED")
        result = ctl.docker(*args)
        if evidence:
            evidence.emit("Docker-" + args[0], "OBSERVED", metadata_sha256=digest(result))
        return result

    d = c["Docker_metadata_reference"]
    daemon = metadata(
        "info",
        "--format",
        '{"id":{{json .ID}},"os":{{json .OperatingSystem}},"name":{{json .Name}},"type":{{json .OSType}}}',
    )
    require(daemon == d["daemon"] and sys.platform == "darwin", "Intended local Desktop daemon required")
    fmt = (
        '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
        '"created":{{json .Created}},"started":{{json .State.StartedAt}},"health":{{json .State.Health.Status}},'
        '"restarts":{{json .RestartCount}},"ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}},'
        '"networks":{{json .NetworkSettings.Networks}},'
        '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
        '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
        '"cpu":{{json .HostConfig.NanoCpus}},"memory":{{json .HostConfig.Memory}},'
        '"pids":{{json .HostConfig.PidsLimit}},"shm":{{json .HostConfig.ShmSize}},'
        '"restart_policy":{{json .HostConfig.RestartPolicy.Name}}}'
    )
    state = metadata("container", "inspect", "--format", fmt, E_CONTAINER)
    require(state == d["container"], "Exact E container metadata drift")
    require(state["ports"] == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56042"}]}, "Loopback only")
    require(set(state["networks"]) == {"sbom-uuid-w17-e_e_access"}, "Sole E network required")
    ctl.secret_mount(state["mounts"], True)
    require(
        metadata("ps", "-a", "--no-trunc", "--filter", "volume=sbom-uuid-w17-e_e_pgdata", "--format", "{{json .ID}}")
        == E_CONTAINER,
        "Exclusive E storage required",
    )
    volume = metadata(
        "volume",
        "inspect",
        "--format",
        '{"name":{{json .Name}},"created":{{json .CreatedAt}},'
        '"driver":{{json .Driver}},"mountpoint":{{json .Mountpoint}},"options":{{json .Options}},'
        '"labels":{{json .Labels}}}',
        "sbom-uuid-w17-e_e_pgdata",
    )
    require(volume == d["volume"], "Original E volume identity changed")
    network = metadata(
        "network",
        "inspect",
        "--format",
        '{"name":{{json .Name}},"id":{{json .Id}},'
        '"created":{{json .Created}},"driver":{{json .Driver}},"internal":{{json .Internal}},'
        '"ipv6":{{json .EnableIPv6}},"ipam":{{json .IPAM}},"options":{{json .Options}},'
        '"containers":{{json .Containers}}}',
        E_NETWORK,
    )
    require(
        network == d["network"] and set(network["containers"]) == {E_CONTAINER}, "Exact exclusive E network required"
    )
    budget.before()
    ref = c["credential_reference"]
    if correlate:
        if evidence:
            evidence.emit("secret_correlation", "STARTED")
        ctl.correlate_secret(
            {"password_file": ref["path"], "credential_metadata": ref["metadata"], "container_id": E_CONTAINER}
        )
    budget.before()
    require(ctl.credential_metadata(ctl.PASSWORD.lstat()) == ref["metadata"], "Credential metadata drift")
    if correlate and evidence:
        evidence.emit("secret_correlation", "PASS", content_equal=True, initialization_root_readable=True)
    return state["networks"]["sbom-uuid-w17-e_e_access"]["IPAddress"]


def preservation(ctl, budget):
    """Current D/SBOM Docker baseline only; no database or application process calls."""
    result = {}
    for name in (ctl.D_CONTAINER, "sbom-postgres-1", "sbom-redis-1", "sbom-mailpit-1"):
        budget.before()
        state = ctl.docker(
            "container",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"image":{{json .Image}},"started":{{json .State.StartedAt}},'
            '"state":{{json .State.Status}},"restarts":{{json .RestartCount}},'
            '"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}},'
            '"networks":{{json .NetworkSettings.Networks}}}',
            name,
        )
        if name == ctl.D_CONTAINER:
            data = [m for m in state["mounts"] if m.get("Destination") == "/var/lib/postgresql/data"]
            require(
                state["id"] == ctl.D_CONTAINER
                and state["image"] == ctl.IMAGE
                and state["state"] == "running"
                and len(data) == 1
                and data[0].get("Type") == "volume"
                and data[0].get("Name") == "sbom-uuid-w1_d_pgdata"
                and set(state["networks"]) == {"sbom-uuid-w1_d_access"}
                and state["ports"] == {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56041"}]},
                "Accepted D resource drift",
            )
        result[name] = state
    for name in ("sbom-uuid-w1_d_pgdata", "sbom_postgres_data", "sbom_redis_data"):
        budget.before()
        result[name] = ctl.docker(
            "volume",
            "inspect",
            "--format",
            '{"name":{{json .Name}},"created":{{json .CreatedAt}},"mountpoint":{{json .Mountpoint}}}',
            name,
        )
    for name in ("sbom_default", "sbom-uuid-w1_d_access", "sbom-uuid-w1_d_private"):
        budget.before()
        result[name] = ctl.docker(
            "network",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"containers":{{json .Containers}},"options":{{json .Options}}}',
            name,
        )
    budget.before()
    return result


class Probe:
    """One connection owned by one invocation. Cleanup cannot retry a query."""

    def __init__(self, budget, evidence):
        self.budget, self.evidence = budget, evidence
        self.conn = None
        self.secret = b""
        self.failed = False

    def query(self, label, params=None):
        require(label in QUERIES, "Only fixed catalog queries permitted")
        self.budget.query()
        self.evidence.emit(label, "STARTED")
        rows = self.conn.execute(QUERIES[label], params).fetchall()
        self.budget.before()
        return json.loads(json.dumps(rows, default=str))

    def control(self, statement, cleanup=False):
        require(statement in CONTROLS, "Only BEGIN READ ONLY/ROLLBACK permitted")
        self.budget.control(cleanup)
        self.evidence.emit("transaction_control", "STARTED", statement=statement)
        self.conn.execute(statement)

    def check(self, label, expected, params=None):
        rows = self.query(label, params)
        require(rows == expected, "Catalog assertion failed: " + label)
        self.evidence.emit(label, "PASS", result_sha256=digest(rows), **(hba_evidence() if label == "auth" else {}))
        return rows

    def run(self, connect, read_secret, observe):
        require(self.budget.attempts == 0, "No second connection attempt")
        try:
            self.budget.before()
            self.secret = read_secret()
            self.budget.connect()
            self.evidence.emit("E-CONNECT", "STARTED", attempt=1)
            self.conn = connect(
                host="127.0.0.1",
                hostaddr="127.0.0.1",
                port=56042,
                dbname="uuid_w17_e_integrity",
                user="uuid_w1_d_bootstrap",
                password=self.secret.decode().strip(),
                passfile="/dev/null",
                sslmode="disable",
                gssencmode="disable",
                connect_timeout=5,
                autocommit=True,
                application_name="uuid_w17b2_E_baseline",
                options=OPTIONS,
            )
            self.evidence.emit(
                "E-CONNECT",
                "CONNECTED",
                credential_supplied=True,
                authentication_method="UNKNOWN",
                password_challenge="UNKNOWN",
            )
            self.budget.before()
            self.control(CONTROLS[0])
            self.check("readonly", [["on"]])
            observe(self)
            self.budget.before()
        except BaseException as error:
            self.failed = True
            self.evidence.emit("STOP", "FAIL", **sanitized(error, self.secret))
            raise
        finally:
            try:
                if self.conn is not None:
                    try:
                        # Cleanup remains mandatory after deadline/error; no further catalog query.
                        self.control("ROLLBACK", cleanup=True)
                        self.evidence.emit("rollback", "PASS")
                    except BaseException as error:
                        self.evidence.emit("rollback", "FAIL", **sanitized(error, self.secret))
                        raise
                    finally:
                        self.conn.close()
                        require(self.conn.closed, "Physical connection closure not acknowledged")
                        self.evidence.emit("physical_close", "PASS")
            finally:
                self.secret = b""


def observe(probe, c, reference, server_ip):
    identity = probe.query("identity")
    require(len(identity) == 1 and len(identity[0]) == 11, "Identity shape mismatch")
    row = identity[0]
    require(
        row[:3] == [TARGET["database"], TARGET["user"], TARGET["user"]]
        and type(row[3]) is int
        and row[3] > 0
        and isinstance(row[4], str)
        and row[4].isdigit()
        and row[4] != D_CLUSTER
        and row[5:8] == [160015, server_ip, 5432]
        and bool(row[8])
        and row[9:] == [False, "origin"],
        "E server identity mismatch",
    )
    probe.evidence.emit(
        "identity",
        "PASS",
        database=TARGET["database"],
        system_identifier=row[4],
        database_oid=row[3],
        server_address=row[6],
        server_port=row[7],
        postmaster_started_at=row[8],
        server_version_num=row[5],
    )
    probe.check(
        "settings",
        [
            [
                "/var/lib/postgresql/data/pgdata",
                "2s",
                "250ms",
                "5s",
                "scram-sha-256",
                "off",
                "12",
                "64MB",
                "4MB",
                "on",
                "pg_catalog",
                "on",
            ]
        ],
    )
    probe.check("database", [[TARGET["user"], None, True, False]])
    probe.check("db_properties", reference["catalog"]["database_properties"])
    probe.check("schemas", reference["catalog"]["schemas"])
    probe.check("privileges", [[True, True, True]])
    probe.check("relations", [])
    probe.check("objects", [[0] * 8])
    probe.check("alembic", [[None]])
    owner = reference["owner_name"]
    probe.check("owner_absent", [], (owner,))
    probe.check("roles", [r for r in reference["roles"]["roles"] if r[0] != owner])
    probe.check("memberships", reference["roles"]["memberships"])
    probe.check("role_settings", [[0]])
    probe.check("auth", [[True]])
    probe.check("password_properties", [[True, True]])
    for label in ("extension", "language", "routines"):
        probe.check(label, reference["extension"][label])
    probe.check("extension_owner", reference["extension_owner"])
    probe.check("clients", [[0]])
    probe.check("locks", [[0]])
    probe.check("readonly", [["on"]])


def offline():
    c = candidate()
    pins = source_pins(c)
    require(all(pins[k] == v for k, v in c["source_sha256"].items()), "Reviewed dependency changed")
    require(sha(private_bytes(REFERENCE, maximum=4194304)) == REFERENCE_SHA, "Protected catalog reference changed")
    return {
        "status": "OFFLINE_SOURCE_VERIFIED",
        "candidate_sha256": CANDIDATE_SHA,
        "expires_utc": EXPIRY,
        "source_sha256": pins,
        "dependency_sha256": dependency_pins(),
        "database_connections": 0,
        "Docker_calls": 0,
        "password_reads": 0,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("offline", "live"), required=True)
    parser.add_argument("--manifest")
    parser.add_argument("--manifest-sha256", help="Separately operator-approved exact execution-manifest byte SHA256")
    parser.add_argument("--approval-id")
    parser.add_argument("--evidence")
    args = parser.parse_args(argv)
    if args.mode == "offline":
        require(
            not any((args.manifest, args.manifest_sha256, args.approval_id, args.evidence)),
            "Offline mode has no live options",
        )
        print(json.dumps(offline(), sort_keys=True))
        return 0
    require(
        all((args.manifest, args.manifest_sha256, args.approval_id, args.evidence)),
        "Explicit live authority/manifest byte SHA256/evidence required",
    )
    require(dict(os.environ) == CLEAN_ENV, "Live mode requires the exact reviewed env -i invocation")
    c = candidate()
    manifest_raw, plan = approved_manifest(args.manifest, args.manifest_sha256)
    validate_manifest(plan, c, args.approval_id, source_pins(c), dependency_pins())
    # Import only after authority/source validation. Never import historical private source.
    import uuid_integrity_control as ctl

    budget = Budget()
    evidence = Evidence(args.evidence)
    try:
        evidence.emit(
            "authority",
            "PASS",
            manifest_sha256=sha(manifest_raw),
            manifest_canonical_sha256=digest(plan),
            candidate_sha256=CANDIDATE_SHA,
        )
        before = preservation(ctl, budget)
        server_ip = resource_preflight(c, ctl, budget, evidence=evidence)
        budget.before()
        reference = private_bytes(REFERENCE, maximum=4194304)
        require(sha(reference) == REFERENCE_SHA, "Protected catalog reference changed")
        budget.before()
        # Refresh source/expiry gates immediately before secret/authentication.
        refreshed_raw, _ = recheck_manifest(
            args.manifest, args.manifest_sha256, manifest_raw, plan, c, args.approval_id
        )
        evidence.emit(
            "manifest_pre_auth", "PASS", manifest_sha256=sha(refreshed_raw), manifest_canonical_sha256=digest(plan)
        )

        def read_secret():
            budget.before()
            raw = ctl.common.private_file(ctl.PASSWORD)
            require(
                ctl.credential_metadata(ctl.PASSWORD.lstat()) == c["credential_reference"]["metadata"],
                "E credential changed after correlation",
            )
            require(datetime.now(UTC) < datetime.fromisoformat(EXPIRY), "Approval expired before authentication")
            return raw

        Probe(budget, evidence).run(
            ctl.psycopg.connect, read_secret, lambda probe: observe(probe, c, unique_json(reference), server_ip)
        )
        budget.before()
        resource_preflight(c, ctl, budget, correlate=False, evidence=evidence)
        require(preservation(ctl, budget) == before, "Existing D/SBOM resource metadata changed")
        evidence.emit(
            "readonly_acceptance",
            "UNKNOWN",
            catalog_checks="PASS",
            reason="Current HBA file and supplied-password session do not establish effective authentication policy",
            **hba_evidence(),
            queries=budget.queries,
            controls=budget.controls,
            attempts=budget.attempts,
            baseline_accepted=False,
        )
    except BaseException as error:
        evidence.emit("invocation", "FAIL", exception_class=type(error).__name__, no_retry=True)
        raise
    finally:
        evidence.close()
    # Do not accept a mandatory active-authentication requirement from file-only evidence.
    return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Primary driver diagnostics only go to private evidence with in-memory secret redaction.
        print(json.dumps({"status": "STOP", "exception_class": type(error).__name__, "no_retry": True}))
        raise SystemExit(2) from None
