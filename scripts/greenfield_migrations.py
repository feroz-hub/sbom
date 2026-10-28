"""Explicitly confirmed local UUID upgrades before service startup.

No application settings, engines, credentials or processes are loaded on import.
An ordinary start never stamps, recreates, repairs or upgrades an unknown schema.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime

from . import greenfield_uuid as stack

PREVIOUS = "100_greenfield_uuid_final"
CURRENT = "101_iam_user_public_uuid"
CONFIRMATION = "UPGRADE sbom_greenfield_uuid 100 TO 101"
TABLES = ("iam_users",)
ADVISORY_KEY = 7160085101
PINS = {
    "alembic/versions/100_greenfield_uuid_final.py": "365f64b4561c5475a9ebbc2162c49bb147beb3e3796ce942adb303fc5c8835fc",
    "alembic/versions/101_iam_user_public_uuid.py": "8c97790e5341e10823933dc2372fe0c351b24c96f54328af10b2ec9992ae630d",
    "app/iam_public_identity.py": "e834759cb556c91606ea00b647782cb877b2d71fb5328a7cfcf55d7da617fe64",
    "app/iam_schema.py": "581a43b097df374c2518f813302abc3ea693bcbe83afe2bc03d1ca98653a6fda",
}


class SchemaUpgradeError(RuntimeError):
    """Safe, nonsecret startup diagnostic."""


def verify_sources():
    for name, expected in PINS.items():
        if hashlib.sha256((stack.ROOT / name).read_bytes()).hexdigest() != expected:
            raise SchemaUpgradeError("Reviewed Greenfield migration source changed; independent review required.")


def engine(database=None, *, control=False):
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    if any(name.startswith("PG") and value for name, value in os.environ.items()):
        raise SchemaUpgradeError("Ambient PG* settings are not allowed for the fixed Greenfield migration target.")
    address = make_url(stack.url("greenfield_setup", "setup-password", "postgres" if control else stack.DB))
    if database is not None:
        if not re.fullmatch(r"sbom_greenfield_uuid_pre[0-9]{3,6}_[0-9a-f]{12}", database):
            raise SchemaUpgradeError("Invalid task-owned backup rehearsal database.")
        address = address.set(database=database)
    if (address.host, address.port, address.username) != ("127.0.0.1", 56044, "greenfield_setup"):
        raise SchemaUpgradeError("Unexpected Greenfield migration endpoint.")
    return create_engine(
        address,
        poolclass=NullPool,
        hide_parameters=True,
        isolation_level="AUTOCOMMIT" if control else "READ COMMITTED",
        connect_args={
            "connect_timeout": 5,
            "hostaddr": "127.0.0.1",
            "passfile": "/dev/null",
            "sslmode": "disable",
            "gssencmode": "disable",
            "application_name": "sbom-greenfield-schema-preflight",
            "options": "-c default_transaction_read_only=on -c statement_timeout=2000 "
            "-c lock_timeout=250 -c idle_in_transaction_session_timeout=5000 "
            "-c search_path=public,pg_catalog -c timezone=UTC",
        },
    )


def identity(c):
    row = c.exec_driver_sql(
        "SELECT current_database(),current_user,current_setting('server_version_num'),"
        "(SELECT system_identifier::text FROM pg_control_system()),"
        "pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()"
    ).one()
    if (row[0], row[1], row[2], row[4]) != (stack.DB, "greenfield_setup", "160015", "greenfield_setup"):
        raise SchemaUpgradeError("Unexpected Greenfield database/version/user/owner; no migration performed.")
    return tuple(row)


def exclusive(c):
    if c.exec_driver_sql(
        "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
        "AND pid<>pg_backend_pid() AND backend_type='client backend'"
    ).scalar_one():
        raise SchemaUpgradeError("Other Greenfield database clients remain; stop writers before confirming migration.")


def snapshot(c, *, omit_public_id_tables=("iam_users",)):
    """Semantic catalog plus per-table data digests; never persist rows/hashes of credentials."""
    catalog = {}
    queries = {
        "relations": "SELECT relname,relkind,relpersistence,relrowsecurity,pg_get_userbyid(relowner),relacl::text "
        "FROM pg_class WHERE relnamespace='public'::regnamespace ORDER BY relname",
        "columns": "SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,"
        "pg_get_expr(d.adbin,d.adrelid) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid "
        "LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum "
        "WHERE c.relnamespace='public'::regnamespace AND a.attnum>0 AND NOT a.attisdropped ORDER BY 1,2",
        "constraints": "SELECT conrelid::regclass::text,conname,pg_get_constraintdef(oid),convalidated "
        "FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY 1,2",
        "triggers": "SELECT tgrelid::regclass::text,tgname,tgenabled,pg_get_triggerdef(oid) FROM pg_trigger "
        "WHERE tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace='public'::regnamespace) "
        "AND NOT tgisinternal ORDER BY 1,2",
        "functions": "SELECT proname,pg_get_userbyid(proowner),proacl::text,pg_get_functiondef(oid) "
        "FROM pg_proc WHERE pronamespace='public'::regnamespace ORDER BY 1,2",
        "schema": "SELECT nspname,pg_get_userbyid(nspowner),COALESCE(nspacl,acldefault('n',nspowner))::text "
        "FROM pg_namespace WHERE nspname='public'",
        "sequences": "SELECT sequencename,start_value,min_value,max_value,increment_by,cycle,cache_size,last_value "
        "FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename",
        "database": "SELECT pg_get_userbyid(datdba),datacl::text,encoding,datcollate,datctype,datconnlimit "
        "FROM pg_database WHERE datname=current_database()",
        "database_settings": "SELECT COALESCE(r.rolname,''),s.setconfig FROM pg_db_role_setting s "
        "LEFT JOIN pg_roles r ON r.oid=s.setrole WHERE s.setdatabase=(SELECT oid FROM pg_database "
        "WHERE datname=current_database()) ORDER BY 1",
        "roles": "SELECT rolname,rolcanlogin,rolsuper,rolinherit,rolcreatedb,rolcreaterole,rolreplication,"
        "rolbypassrls,rolconfig FROM pg_roles WHERE rolname IN ('greenfield_owner','greenfield_app') ORDER BY rolname",
        "default_acls": "SELECT pg_get_userbyid(defaclrole),defaclnamespace::regnamespace::text,"
        "defaclobjtype,defaclacl::text FROM pg_default_acl ORDER BY 1,2,3",
    }
    for key, sql in queries.items():
        catalog[key] = [list(row) for row in c.exec_driver_sql(sql)]
    tables = [row[0] for row in catalog["relations"] if row[1] == "r"]
    if "iam_users" not in tables or "alembic_version" not in tables:
        raise SchemaUpgradeError("Incomplete Greenfield schema; bootstrap/recreation is not a startup operation.")
    data = {}
    for name in tables:
        if name == "alembic_version":
            continue
        table = c.dialect.identifier_preparer.quote(name)
        expression = "to_jsonb(t) - 'public_id'" if name in omit_public_id_tables else "to_jsonb(t)"
        digest = hashlib.sha256()
        count = 0
        for (value,) in c.exec_driver_sql(
            f"SELECT ({expression})::text FROM public.{table} t ORDER BY ({expression})::text LIMIT 100001"
        ):
            count += 1
            digest.update(value.encode() + b"\n")
        if count > 100000:
            raise SchemaUpgradeError("Development backup review exceeds the small-database row budget.")
        data[name] = [count, digest.hexdigest()]
    return {"catalog": catalog, "data": data}


def inspect_current(e):
    with e.connect() as c:
        observed_identity = identity(c)
        if c.exec_driver_sql("SHOW transaction_read_only").scalar_one() != "on":
            raise SchemaUpgradeError("Schema preflight must be READ ONLY.")
        marker = c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all()
        if marker not in ([PREVIOUS], [CURRENT]):
            raise SchemaUpgradeError("Unknown Greenfield revision; no automatic migration or stamping permitted.")
        c.rollback()
    return observed_identity, marker[0]


def review_security(c):
    exclusive(c)
    # Do not import or restore catalog objects capable of external effects.
    if c.exec_driver_sql(
        "SELECT (SELECT count(*) FROM pg_event_trigger)+(SELECT count(*) FROM pg_foreign_server)"
        "+(SELECT count(*) FROM pg_subscription)+(SELECT count(*) FROM pg_publication)"
    ).scalar_one():
        raise SchemaUpgradeError("Unreviewed external/replication objects; independent review required.")
    roles = c.exec_driver_sql(
        "SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls "
        "FROM pg_roles WHERE rolname IN ('greenfield_owner','greenfield_app') ORDER BY rolname"
    ).all()
    if [tuple(row) for row in roles] != [
        ("greenfield_app", True, False, False, False, False, False),
        ("greenfield_owner", False, False, False, False, False, False),
    ]:
        raise SchemaUpgradeError("Unexpected Greenfield owner/runtime privileges.")
    if c.exec_driver_sql(
        "SELECT count(*) FROM pg_auth_members WHERE member IN "
        "(SELECT oid FROM pg_roles WHERE rolname IN ('greenfield_owner','greenfield_app'))"
    ).scalar_one():
        raise SchemaUpgradeError("Unexpected Greenfield owner/runtime role membership.")


def before_upgrade(e):
    with e.connect() as c:
        review_security(c)
        result = snapshot(c)
        if any(row[0] == "iam_users" and row[1] == "public_id" for row in result["catalog"]["columns"]):
            raise SchemaUpgradeError("Partial IAM UUID upgrade; no automatic repair permitted.")
        if any(row[0] == "iam_users" for row in result["catalog"]["triggers"]):
            raise SchemaUpgradeError("Unexpected existing IAM trigger; independent review required.")
        if next(row[4] for row in result["catalog"]["relations"] if row[0] == "iam_users") != "greenfield_owner":
            raise SchemaUpgradeError("Unexpected IAM table owner.")
        c.rollback()
    return result


def _private(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def restored_snapshot_matches(before, restored):
    """PG16 round-trips literal varchar-array CHECK casts to per-item text casts.

    Accept only that exact built-in, constant-expression representation change.
    All names, literal values, operators, validated flags and other catalog/data
    evidence remain exact. This is NOT general SQL normalization.
    """

    def canonical(rows):
        result = []
        literal = r"'(?:[^']|'')*'::character varying"
        pattern = re.compile(r"\(ARRAY\[(" + literal + r"(?:, " + literal + r")*)\]\)::text\[\]")
        for row in rows:
            row = list(row)
            row[2] = pattern.sub(
                lambda match: (
                    "ARRAY[" + ", ".join("(" + value + ")::text" for value in re.findall(literal, match[1])) + "]"
                ),
                row[2],
            )
            result.append(row)
        return result

    if before["data"] != restored["data"] or set(before["catalog"]) != set(restored["catalog"]):
        return False
    for key in before["catalog"]:
        left, right = before["catalog"][key], restored["catalog"][key]
        if key == "constraints":
            left, right = canonical(left), canonical(right)
        if left != right:
            return False
    return True


def backup_and_rehearse(e, before, observed_identity, *, predecessor=PREVIOUS, snapshotter=None, successor=None):
    """Full PG16 custom archive, encrypted locally, restored to a NEW retained DB.

    The verified container's explicit local Unix socket uses its existing local
    auth policy. Never fall back to other credentials or print tool diagnostics.
    """
    from cryptography.fernet import Fernet

    from .greenfield_migration_graph import discover

    graph = discover(stack.ROOT)
    if successor is None:
        successor = {PREVIOUS: CURRENT, CURRENT: "102_public_membership_grant_analysis_uuid"}.get(predecessor)
    if not any(r.revision == successor and r.parent == predecessor for r in graph.revisions):
        raise SchemaUpgradeError("Backup must precede one discovered forward migration.")
    snapshotter = snapshot if snapshotter is None else snapshotter
    stack.verify_resources()
    with e.connect() as c:
        if identity(c) != observed_identity:
            raise SchemaUpgradeError("Backup source identity changed.")
        exclusive(c)
        c.rollback()
    parent = stack.STATE / "upgrade-backups"
    parent.mkdir(mode=0o700, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SchemaUpgradeError("Unsafe backup directory.")
    folder = parent / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:12])
    folder.mkdir(mode=0o700)
    container = json.loads(stack.read_private("docker-identities.json"))["sbom-greenfield-uuid-dev-postgres-1"]
    base = [*stack.DOCKER, "exec", "-i", container]
    next_number = successor.split("_", 1)[0]
    target = "sbom_greenfield_uuid_pre" + next_number + "_" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryFile(dir=folder) as temporary:
        result = subprocess.run(
            [
                *base,
                "pg_dump",
                "--host=/var/run/postgresql",
                "--username=greenfield_setup",
                "--no-password",
                "--format=custom",
                "--dbname=" + stack.DB,
            ],
            stdin=subprocess.DEVNULL,
            stdout=temporary,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        if result.returncode or not 0 < temporary.tell() <= 128 * 1024 * 1024:
            raise SchemaUpgradeError(
                "Full backup failed/exceeded 128 MiB; no migration performed. Diagnostics withheld."
            )
        temporary.seek(0)
        raw = temporary.read()
    key = Fernet.generate_key()
    _private(folder / "backup.key", key)
    _private(folder / "database.dump.fernet", Fernet(key).encrypt(raw))
    listing = subprocess.run([*base, "pg_restore", "--list"], input=raw, capture_output=True, timeout=30, check=False)
    if listing.returncode or not re.search(rb"\bSCHEMA - public greenfield_owner\b", listing.stdout):
        raise SchemaUpgradeError(
            "Backup public-schema ownership representation is unreviewed; no restore or migration."
        )
    _private(
        folder / "backup-attempt.json", json.dumps({"restored_database": target, "source_database": stack.DB}).encode()
    )
    control = engine(control=True)
    try:
        with control.connect() as c:
            if (
                c.exec_driver_sql("SELECT system_identifier::text FROM pg_control_system()").scalar_one()
                != observed_identity[3]
            ):
                raise SchemaUpgradeError("Backup rehearsal cluster changed.")
            c.exec_driver_sql("SET default_transaction_read_only=off")
            c.exec_driver_sql("CREATE DATABASE " + target + " TEMPLATE template0")
    finally:
        control.dispose()
    restored = engine(target)
    try:
        with restored.connect() as c:
            # PG16's public-schema archive entry assumes initdb's empty public
            # schema exists; restore applies its reviewed owner/ACL afterwards.
            if c.exec_driver_sql(
                "SELECT (SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace)"
                "+(SELECT count(*) FROM pg_proc WHERE pronamespace='public'::regnamespace)"
            ).scalar_one():
                raise SchemaUpgradeError("New backup rehearsal database is not empty; no restore attempted.")
            c.rollback()
        result = subprocess.run(
            [
                *base,
                "pg_restore",
                "--host=/var/run/postgresql",
                "--username=greenfield_setup",
                "--no-password",
                "--single-transaction",
                "--exit-on-error",
                "--dbname=" + target,
            ],
            input=Fernet(key).decrypt((folder / "database.dump.fernet").read_bytes()),
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode:
            diagnostic = result.stderr.decode(errors="replace")
            primary = next(
                (line.split("ERROR:", 1)[1] for line in diagnostic.splitlines() if "ERROR:" in line),
                "unclassified tool failure",
            )
            # Withhold identifiers, literal values, SQL/row context and all
            # unrestricted subprocess diagnostics; retain the failure class.
            primary = re.sub(r"([\"\']).*?\1", "[redacted]", primary)
            primary = "".join(char for char in primary if char.isprintable())[:240].strip()
            _private(
                folder / "restore-failure.json",
                json.dumps({"exit_code": result.returncode, "primary": primary}).encode(),
            )
            raise SchemaUpgradeError(
                "Backup restore rehearsal failed: " + primary + "; resources retained; no migration performed."
            )
        with restored.connect() as c:
            if c.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all() != [predecessor]:
                raise SchemaUpgradeError("Backup revision verification failed.")
            if not restored_snapshot_matches(before, snapshotter(c)):
                raise SchemaUpgradeError("Backup data/schema/owner/ACL parity failed; no migration performed.")
            c.rollback()
    finally:
        restored.dispose()
    _private(
        folder / "backup-verified.json",
        json.dumps(
            {
                "archive_sha256": hashlib.sha256(raw).hexdigest(),
                "restored_database": target,
                "restored_revision": predecessor,
                "schema_data_owner_acl_parity": True,
            },
            indent=2,
        ).encode(),
    )
    print(f"[OK] Verified encrypted backup: {folder}; recovery copy: {target}", flush=True)
    return folder


def validate_after(c, before):
    after = snapshot(c)
    if after["data"] != before["data"]:
        raise SchemaUpgradeError("Existing business/identity data changed outside IAM public_id.")
    # Compare every original catalog row; allow only the reviewed IAM additions.
    additions = {
        "relations": lambda r: r[0] == "uq_iam_users_public_id",
        "columns": lambda r: r[0] in ("iam_users", "uq_iam_users_public_id") and r[1] == "public_id",
        "constraints": lambda r: (
            r[0] == "iam_users" and r[1] in ("uq_iam_users_public_id", "ck_iam_users_public_id_v4")
        ),
        "triggers": lambda r: (
            r[0] == "iam_users" and r[1] in ("trg_iam_users_public_id_allocate", "trg_iam_users_public_id_immutable")
        ),
        "functions": lambda r: r[0] == "iam_user_public_identity_guard_v1",
        "schema": lambda r: False,
        "sequences": lambda r: False,
        "database": lambda r: False,
        "database_settings": lambda r: False,
        "roles": lambda r: False,
        "default_acls": lambda r: False,
    }
    expected_added = {
        "relations": 1,
        "columns": 2,
        "constraints": 2,
        "triggers": 2,
        "functions": 1,
        "schema": 0,
        "sequences": 0,
        "database": 0,
        "database_settings": 0,
        "roles": 0,
        "default_acls": 0,
    }
    for key, predicate in additions.items():
        old = [r for r in after["catalog"][key] if not predicate(r)]
        if old != before["catalog"][key] or len(after["catalog"][key]) - len(old) != expected_added[key]:
            raise SchemaUpgradeError("Unexpected post-upgrade catalog difference: " + key)
    row = c.exec_driver_sql(
        "SELECT count(*),count(DISTINCT public_id),count(*) FILTER(WHERE public_id IS NULL OR "
        "substring(public_id::text,15,1)<>'4' OR substring(public_id::text,20,1) NOT IN ('8','9','a','b')) FROM iam_users"
    ).one()
    if row[0] != row[1] or row[2]:
        raise SchemaUpgradeError("IAM UUID backfill verification failed.")
    column = next(r for r in after["catalog"]["columns"] if r[:2] == ["iam_users", "public_id"])
    if column[2:] != ["uuid", True, "gen_random_uuid()"]:
        raise SchemaUpgradeError("IAM native UUID/NOT NULL/default mismatch.")
    if c.exec_driver_sql("SELECT version_num FROM alembic_version").scalars().all() != [CURRENT]:
        raise SchemaUpgradeError("IAM revision verification failed.")
    guard = c.exec_driver_sql(
        "SELECT pg_get_userbyid(proowner),prosecdef,provolatile,proconfig,prosrc,"
        "has_function_privilege('public',oid,'EXECUTE') FROM pg_proc "
        "WHERE oid='public.iam_user_public_identity_guard_v1()'::regprocedure"
    ).one()
    from app.iam_public_identity import GUARD_SQL

    if tuple(guard) != (
        "greenfield_owner",
        False,
        "v",
        ["search_path=pg_catalog"],
        GUARD_SQL.split("$guard$")[1],
        False,
    ):
        raise SchemaUpgradeError("IAM guard owner/security mismatch.")


def apply_revision(c):
    from app.iam_schema import apply_user_uuid_revision

    apply_user_uuid_revision(c)


def describe_upgrade(before):
    return (
        f"{before['data']['iam_users'][0]} users. Existing integer keys/credentials/roles retained.\n"
        "Exactly one transactional IAM UUID migration follows. Statement/lock/idle timeouts: 2s/250ms/5s.\n"
        "Review docs/uat/user-public-uuid/DATABASE_MIGRATION_PLAN.md."
    )


def ensure_current(*, confirm=None):
    """Discover pending units automatically; require fresh confirmation for each."""
    from .greenfield_auto_migrations import ensure_current as discover_and_upgrade

    discover_and_upgrade(confirm=confirm)


def _ensure_unit(unit, *, confirm=None):
    unit.verify_sources()
    stack.verify_resources()
    pending = stack.STATE / "pending-schema-upgrade.json"
    if pending.exists() or pending.is_symlink():
        raise SchemaUpgradeError(
            "A prior schema-upgrade attempt needs manual reconciliation; inspect the private "
            "pending-schema-upgrade.json and upgrade-backups directory. No retry or service startup."
        )
    e = unit.engine()
    phase = "read-only schema preflight"
    try:
        observed_identity, marker = unit.inspect_current(e)
        if marker == unit.CURRENT:
            print("[OK] Schema             " + unit.CURRENT, flush=True)
            return
        before = unit.before_upgrade(e)
        print(
            f"[REVIEW] {stack.DB} at 127.0.0.1:56044, cluster {observed_identity[3]}: "
            f"{unit.PREVIOUS} -> {unit.CURRENT}.\n" + unit.describe_upgrade(before) + "\n"
            "A full encrypted backup and a NEW retained restore-verification database will be created first.\n"
            "Then independent read-back before services. No automatic retry, downgrade or cleanup.\n"
            f"Type {unit.CONFIRMATION!r} to authorize this local upgrade, or press Enter to cancel:",
            flush=True,
        )
        if confirm is None:
            if not sys.stdin.isatty():
                raise SchemaUpgradeError("Greenfield requires interactive migration approval before startup.")
            confirm = input
        if confirm().strip() != unit.CONFIRMATION:
            raise SchemaUpgradeError(
                "Migration not approved; database unchanged; application services were not started."
            )
        phase = "backup/restore verification"
        backup = unit.backup_and_rehearse(e, before, observed_identity)
        stack.verify_resources()
        unit.verify_sources()
        if unit.inspect_current(e) != (observed_identity, unit.PREVIOUS) or unit.before_upgrade(e) != before:
            raise SchemaUpgradeError("Source database changed after review/backup; no migration performed.")
        source_lock = getattr(unit, "source_lock", None)
        if source_lock is not None:
            source_lock.verify()
            _private(backup / "approved-source-snapshot.json", source_lock.original_json)
        _private(
            pending, json.dumps({"identity": observed_identity, "backup": str(backup), "unit": unit.CURRENT}).encode()
        )
        _private(backup / "upgrade-events.jsonl", b"")

        def journal(event):
            fd = os.open(backup / "upgrade-events.jsonl", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps({"event": event, "time": datetime.now(UTC).isoformat()}) + "\n")
                f.flush()
                os.fsync(f.fileno())

        journal("single_write_attempt_claimed")
        with e.connect() as c:
            transaction = c.begin()
            try:
                phase = "precommit migration"
                c.exec_driver_sql("SET TRANSACTION READ WRITE")
                if identity(c) != observed_identity:
                    raise SchemaUpgradeError("Migration target changed.")
                c.exec_driver_sql(f"SELECT pg_advisory_xact_lock({unit.ADVISORY_KEY})")
                c.exec_driver_sql("LOCK TABLE public.alembic_version IN EXCLUSIVE MODE NOWAIT")
                for table in unit.TABLES:
                    c.exec_driver_sql(f"LOCK TABLE ONLY public.{table} IN ACCESS EXCLUSIVE MODE NOWAIT")
                exclusive(c)
                unit.verify_sources()
                if unit.snapshot(c) != before:
                    raise SchemaUpgradeError("Database changed before locked migration.")
                c.exec_driver_sql("SET LOCAL ROLE greenfield_owner")
                unit.apply_revision(c)
                unit.validate_after(c, before)
                journal("precommit_checks_passed")
                phase = "COMMIT acknowledgement"
                transaction.commit()
                phase = "committed; independent verification"
                journal("commit_acknowledged")
            except BaseException:
                if phase == "precommit migration":
                    transaction.rollback()
                    journal("rollback_acknowledged")
                raise
        journal("write_connection_closed")
        with e.connect() as reader:
            if identity(reader) != observed_identity:
                raise SchemaUpgradeError("Read-back target changed.")
            unit.validate_after(reader, before)
            reader.rollback()
        journal("independent_readback_rolled_back_and_closed")
        _private(
            backup / "upgrade-accepted.json",
            json.dumps({"revision": unit.CURRENT, "independent_readback": True}).encode(),
        )
        pending.unlink()
        print(
            "[OK] Schema             " + unit.CURRENT + " committed, writer closed, independent read-back passed",
            flush=True,
        )
    except BaseException as error:
        # Never emit driver arguments, SQL parameters, passwords or backup rows.
        if phase == "COMMIT acknowledgement":
            message = "UNKNOWN COMMIT outcome; manual reconciliation required. Do not retry."
        elif phase == "committed; independent verification":
            message = "Migration committed but acceptance is incomplete. Do not retry or start services."
        elif isinstance(error, SchemaUpgradeError):
            raise
        else:
            message = "Stopped during " + phase + "; no automatic retry or cleanup."
        raise SchemaUpgradeError(message + " Error class: " + type(error).__name__) from None
    finally:
        e.dispose()
