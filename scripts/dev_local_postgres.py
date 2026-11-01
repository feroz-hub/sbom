"""Explicit local PostgreSQL provisioning; administrator credentials stay in memory.

The private recovery record is published before DDL. It contains only newly
generated setup/runtime credentials and an ownership token. Existing unrecorded
roles/databases are never adopted, changed, reset or removed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from uuid import UUID

if __package__:
    from . import dev_config, dev_environment, dev_private
else:
    import dev_config
    import dev_environment
    import dev_private

RECORD = ".env.dev.postgres.json"
ROLE_POLICY = (True, False, False, False, False, False, False)


class LocalPostgresError(ValueError):
    """Constant, secret-safe provisioning identity failure."""


def validate_target(database, port):
    if not isinstance(database, str) or not re.fullmatch(r"sbom_analyser_dev(?:_[a-z0-9_]{1,24})?", database):
        raise ValueError("LOCAL_DATABASE_TARGET_INVALID: choose sbom_analyser_dev or a short sbom_analyser_dev_<suffix> name.")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("LOCAL_POSTGRES_PORT_INVALID: choose a TCP port from 1 to 65535.")
    return database, port


def record_path(launcher):
    return Path(launcher.ROOT) / RECORD


def _url(record, kind):
    return (f"postgresql+psycopg://{quote(record[kind + '_user'], safe='')}:"
            f"{quote(record[kind + '_password'], safe='')}@127.0.0.1:{record['port']}/{record['database']}")


def read_record(launcher):
    path = record_path(launcher)
    dev_private.validate_parent(path, launcher.ROOT)
    if launcher.sys.platform == "win32":
        launcher.LocalHttps._windows_access(path, private=True)
    elif path.stat().st_mode & 0o077:
        raise launcher.SetupError("LOCAL_POSTGRES_RECORD_PRIVATE: restrict the recovery record to its owner before setup.")
    record = json.loads(dev_environment.bounded_read_text(path))
    validate_target(record["database"], record["port"])
    expected = {"version", "database", "port", "token", "setup_user", "runtime_user", "setup_password", "runtime_password"}
    if (set(record) != expected or record["version"] != 1
            or not re.fullmatch(r"[0-9a-f]{32}", record["token"])
            or record["setup_user"] != record["database"] + "_setup"
            or record["runtime_user"] != record["database"] + "_app"
            or any(not re.fullmatch(r"[A-Za-z0-9_-]{40,100}", record[k + "_password"]) for k in ("setup", "runtime"))
            or record["setup_password"] == record["runtime_password"]):
        raise launcher.SetupError("LOCAL_POSTGRES_RECORD_INVALID: restore the original private recovery record; no DDL ran.")
    return record


def _connect(record, user, password, *, control=False):
    import psycopg

    # libpq service/password/host/TLS environment must not redirect this target.
    if any(k.upper().startswith("PG") and v for k, v in os.environ.items()):
        raise ValueError("LOCAL_POSTGRES_AMBIENT_SETTINGS: remove PG* overrides in this terminal before local setup.")
    return psycopg.connect(
        host="127.0.0.1", hostaddr="127.0.0.1", port=record["port"],
        dbname="postgres" if control else record["database"], user=user, password=password,
        passfile=os.devnull, connect_timeout=3, autocommit=True,
        options="-c statement_timeout=10000 -c lock_timeout=2000 -c search_path=pg_catalog,public",
    )


def _role(connection, name):
    return connection.execute(
        "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit,"
        "shobj_description(oid,'pg_authid'),oid FROM pg_roles WHERE rolname=%s", (name,),
    ).fetchone()


def _verify_role(row, token):
    return row is not None and tuple(row[:7]) == ROLE_POLICY and row[7] == token


def matches_runtime_target(url, record):
    """Bind the recorded endpoint/role without pinning an obsolete password."""
    try:
        target = urlsplit(url)
        return (target.scheme == "postgresql+psycopg" and target.hostname in {"127.0.0.1", "localhost"}
                and target.port == record["port"] and target.path == "/" + record["database"]
                and unquote(target.username or "") == record["runtime_user"]
                and not target.query and not target.fragment)
    except (ValueError, TypeError):
        return False


def _verify_setup_connection(connection, record):
    setup = _role(connection, record["setup_user"])
    runtime = _role(connection, record["runtime_user"])
    owner = connection.execute("SELECT datdba FROM pg_database WHERE datname=current_database()").fetchone()
    memberships = connection.execute(
        "SELECT EXISTS (SELECT 1 FROM pg_auth_members WHERE member IN "
        "(SELECT oid FROM pg_roles WHERE rolname IN (%s,%s)))", (record["setup_user"], record["runtime_user"]),
    ).fetchone()
    if (not _verify_role(setup, record["token"]) or not _verify_role(runtime, record["token"])
            or owner is None or owner[0] != setup[-1] or memberships is None or memberships[0]):
        raise LocalPostgresError("LOCAL_POSTGRES_IDENTITY_CHANGED: review recorded role privileges, memberships and database ownership before any schema/grant operation.")


def provision(args, launcher):
    """Create only absent resources, or resume the exact recorded installation."""
    launcher._setup_requires(args, "local-postgres-provision")
    database, port = validate_target(getattr(args, "local_database", None) or launcher.DB_NAME,
                                     getattr(args, "local_postgres_port", None) or 5432)
    if args.confirm_database != database or not args.initialize_database:
        raise launcher.SetupError("LOCAL_POSTGRES_CONFIRMATION_REQUIRED: use --initialize-database --confirm-database with the exact selected name.")
    if (Path(launcher.CONFIG).exists() or Path(launcher.CONFIG).is_symlink()) and not record_path(launcher).is_file():
        raise launcher.SetupError("LOCAL_POSTGRES_EXISTING_CONFIG: provisioning never replaces .env.dev.local; use the credential transition action for an existing installation.")
    path = record_path(launcher)
    existing = path.exists() or path.is_symlink()
    record = read_record(launcher) if existing else {
        "version": 1, "database": database, "port": port, "token": secrets.token_hex(16),
        "setup_user": database + "_setup", "runtime_user": database + "_app",
        "setup_password": secrets.token_urlsafe(36), "runtime_password": secrets.token_urlsafe(36),
    }
    if (record["database"], record["port"]) != (database, port):
        raise launcher.SetupError("LOCAL_POSTGRES_RECORD_TARGET_CHANGED: reuse the exact recorded database and port; no resources were changed.")
    if Path(launcher.CONFIG).exists():
        saved = dev_config.parse_managed(dev_environment.bounded_read_text(launcher.CONFIG))
        if not matches_runtime_target(saved.get("DATABASE_URL", ""), record):
            raise launcher.SetupError("LOCAL_POSTGRES_CONFIG_MISMATCH: retain the saved configuration and recovery record; no provisioning ran.")
    print(f"[PLAN] Local PostgreSQL 127.0.0.1:{port}/{database}; roles {record['setup_user']} and {record['runtime_user']}.")
    print("[INFO] Administrator credentials are used once in memory; they are never saved or passed to application processes.")
    user, password = launcher.read_postgres_credentials()
    from psycopg import sql

    try:
        with _connect(record, user, password, control=True) as control:
            authority = control.execute("SELECT rolsuper OR (rolcreatedb AND rolcreaterole) FROM pg_roles WHERE rolname=current_user").fetchone()
            if authority is None or not authority[0]:
                raise launcher.SetupError("LOCAL_POSTGRES_ADMIN_AUTHORITY_REQUIRED: ask the local PostgreSQL administrator to provision this exact disposable target; no credentials were saved.")
            lock = int.from_bytes(hashlib.sha256(database.encode()).digest()[:8], "big", signed=True)
            if not control.execute("SELECT pg_try_advisory_lock(%s)", (lock,)).fetchone()[0]:
                raise launcher.SetupError("LOCAL_POSTGRES_BUSY: another provisioning operation owns this database name; retry after it finishes.")
            rows = [_role(control, record[k + "_user"]) for k in ("setup", "runtime")]
            db = control.execute("SELECT datdba FROM pg_database WHERE datname=%s", (database,)).fetchone()
            if not existing and (any(row is not None for row in rows) or db is not None):
                raise launcher.SetupError("LOCAL_POSTGRES_TARGET_EXISTS: choose a new --local-database name; existing roles and databases were retained.")
            if any(row is not None and not _verify_role(row, record["token"]) for row in rows):
                raise launcher.SetupError("LOCAL_POSTGRES_ROLE_UNOWNED: restore the matching recovery record or choose a fresh target; no role was altered.")
            if control.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_auth_members WHERE member IN "
                "(SELECT oid FROM pg_roles WHERE rolname IN (%s,%s)))",
                (record["setup_user"], record["runtime_user"]),
            ).fetchone()[0]:
                raise launcher.SetupError("LOCAL_POSTGRES_ROLE_MEMBERSHIP: recorded roles have unexpected memberships; review them manually before retrying.")
            if db is not None and (rows[0] is None or db[0] != rows[0][-1]):
                raise launcher.SetupError("LOCAL_POSTGRES_DATABASE_UNOWNED: existing database owner does not match the recorded setup role; no database was changed.")
            if not existing:
                dev_private.validate_parent(path, launcher.ROOT)
                dev_private.create_private_file(path, json.dumps(record, sort_keys=True).encode())
            # Role creation is atomic; CREATE DATABASE must run outside a transaction.
            with control.transaction():
                for kind, row in zip(("setup", "runtime"), rows, strict=True):
                    if row is None:
                        role = sql.Identifier(record[kind + "_user"])
                        control.execute(sql.SQL(
                            "CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}"
                        ).format(role, sql.Literal(record[kind + "_password"])))
                        control.execute(sql.SQL("COMMENT ON ROLE {} IS {}").format(role, sql.Literal(record["token"])))
            # A setup login may own this database but cannot create roles or databases.
            if db is None:
                control.execute(sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0").format(
                    sql.Identifier(database), sql.Identifier(record["setup_user"])))
        with _connect(record, record["setup_user"], record["setup_password"]) as connection:
            with connection.transaction():
                connection.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database)))
                connection.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(database), sql.Identifier(record["runtime_user"])))
                connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        return record
    except (launcher.SetupError, KeyboardInterrupt, EOFError):
        raise
    except Exception:
        raise launcher.SetupError(
            "LOCAL_POSTGRES_PROVISION_FAILED: verify the local administrator login has CREATE ROLE/CREATE DATABASE authority. "
            "If the private recovery record exists, retain it and repeat the same command to resume; no resource was deleted and no password was rotated."
        ) from None
    finally:
        password = None


def bootstrap_record(record, launcher):
    """Initialize empty recorded databases; validate completed ones read-only."""
    bootstrap = launcher._development_library("bootstrap_fresh_database").bootstrap

    url = setup_url(record)
    try:
        with _connect(record, record["setup_user"], record["setup_password"]) as connection:
            _verify_setup_connection(connection, record)
            nonempty = connection.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
                "AND c.relkind IN ('r','p','v','m','S','f'))"
            ).fetchone()[0]
    except LocalPostgresError as error:
        raise launcher.SetupError(str(error)) from None
    if not nonempty:
        bootstrap(url, record["database"])
    else:
        launcher.verify_existing_schema({"DATABASE_URL": url})
    try:
        grant_runtime(record)
    except LocalPostgresError as error:
        raise launcher.SetupError(str(error)) from None


def runtime_values(record):
    return {"DATABASE_URL": _url(record, "runtime"), "DEV_POSTGRES_PROVIDER": "local",
            "SBOM_DEV_RESOURCE_ID": str(UUID(hex=record["token"])),
            "APP_ENVIRONMENT": "development", "PYTHON_DOTENV_DISABLED": "1"}


def setup_url(record):
    return _url(record, "setup")


def grant_runtime(record):
    """Grant DML only, keeping schema and migration ownership with setup."""
    from psycopg import sql

    with _connect(record, record["setup_user"], record["setup_password"]) as connection:
        _verify_setup_connection(connection, record)
        with connection.transaction():
            role = sql.Identifier(record["runtime_user"])
            for query in (
                "GRANT USAGE ON SCHEMA public TO {}",
                "GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO {}",
                "GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO {}",
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO {}",
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO {}",
                "REVOKE ALL ON public.alembic_version FROM {}",
                "GRANT SELECT ON public.alembic_version TO {}",
            ):
                connection.execute(sql.SQL(query).format(role))


def transition_credentials(args, launcher):
    """Change only DATABASE_URL after consent and validation; retain exact bytes."""
    launcher._setup_requires(args, "database-credentials")
    path = Path(launcher.CONFIG)
    dev_private.validate_parent(path, launcher.ROOT)
    if launcher.sys.platform == "win32":
        launcher.LocalHttps._windows_access(path, private=True)
    elif path.stat().st_mode & 0o077:
        raise launcher.SetupError("PRIVATE_CONFIG_REQUIRED: restrict the original configuration before a credential transition.")
    original = dev_environment.bounded_read_bytes(path)
    values = dev_config.parse_managed(original.decode("utf-8-sig"))
    target = urlsplit(values["DATABASE_URL"])
    launcher.validate_database_url(values["DATABASE_URL"])
    if args.confirm_database != target.path[1:]:
        raise launcher.SetupError("DATABASE_CONFIRMATION_REQUIRED: confirm the saved database before changing credentials.")
    user, password = launcher.read_postgres_credentials(default_user=unquote(target.username or ""))
    if record_path(launcher).is_file() and user != read_record(launcher)["runtime_user"]:
        raise launcher.SetupError("RECORDED_RUNTIME_ROLE_REQUIRED: this installation retains its recorded runtime role; enter that role's renewed password. Role replacement requires a separate reviewed provisioning procedure.")
    candidate = f"postgresql+psycopg://{quote(user, safe='')}:{quote(password, safe='')}@{target.hostname}:{target.port}{target.path}"
    launcher.validate_database_credentials(candidate)
    validate_runtime_credentials(candidate, launcher)
    replacement = re.sub(rb"(?m)^DATABASE_URL=[^\r\n]*", lambda _: b"DATABASE_URL=" + json.dumps(candidate).encode(), original)
    backup = path.with_name(path.name + ".backup-" + secrets.token_hex(8))
    temporary = path.with_name(path.name + ".transition-" + secrets.token_hex(8))
    dev_private.create_private_file(backup, original)
    dev_private.create_private_file(temporary, replacement)
    # Retain backups and incomplete new artifacts on failure; never silently retry.
    if dev_environment.bounded_read_bytes(path) != original:
        raise launcher.SetupError("CONFIGURATION_CHANGED: the saved file changed during credential entry; retain the backup and review a new plan.")
    dev_private.validate_parent(path, launcher.ROOT)
    os.replace(temporary, path)
    print(f"[PASS] Only DATABASE_URL changed; the original private configuration is retained as {backup.name}.")


def validate_runtime_credentials(url, launcher):
    launcher.validate_database_url(url)
    target = urlsplit(url)
    with _connect({"database": target.path[1:], "port": target.port}, unquote(target.username or ""), unquote(target.password or "")) as connection:
        role = connection.execute(
            "SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user"
        ).fetchone()
        if role is None or any(role) or connection.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user))"
        ).fetchone()[0] or connection.execute("SELECT has_schema_privilege(current_user,'public','CREATE')").fetchone()[0]:
            raise launcher.SetupError("RUNTIME_ROLE_PRIVILEGED: choose a separately provisioned DML-only application login; no credentials were changed.")
