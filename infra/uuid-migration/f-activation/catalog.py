"""Bounded fixed catalog/reference observation, through the driver meter only."""

from __future__ import annotations

import ast
import re

from security import require

IDENTITY = """SELECT current_database() AS database,current_user AS user,session_user AS session_user,
 (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AS database_oid,
 (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier,
 current_setting('server_version_num')::int AS version,pg_catalog.pg_is_in_recovery() AS recovery,
 current_setting('session_replication_role') AS replication,current_setting('row_security') AS row_security,
 current_setting('transaction_read_only') AS read_only,current_setting('search_path') AS search_path,
 pg_catalog.inet_server_port() AS port,pg_catalog.host(pg_catalog.inet_server_addr()) AS server_ip,
 current_setting('data_directory') AS data_directory"""
MARKER_EXISTS = "SELECT pg_catalog.to_regclass('public.alembic_version')::text AS relation"
MARKER = "SELECT version_num FROM public.alembic_version"
ADVISORY = "SELECT pg_catalog.pg_try_advisory_xact_lock(7160085085) AS acquired"
VERSION_LOCK = "LOCK TABLE ONLY public.alembic_version IN EXCLUSIVE MODE NOWAIT"
VERSION_CREATE = "CREATE TABLE public.alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)"
INSERT = "INSERT INTO public.alembic_version (version_num) VALUES (:revision) RETURNING version_num"
UPDATE = "UPDATE public.alembic_version SET version_num=:revision WHERE version_num=:previous RETURNING version_num"
REFERENCE_TABLES = {
    "alembic_version",
    "authorization_roles",
    "authorization_permissions",
    "authorization_role_permissions",
    "authorization_audit_log",
}


def relation(name):
    require(isinstance(name, str) and re.fullmatch("[a-z_][a-z0-9_]{0,62}", name), "Unreviewed table identifier")
    return 'public."' + name + '"'


def query(connection, meter, text_factory, sql, params=None):
    # No logical charge here. Cursor.execute is the single charging boundary.
    with meter.scope("catalog_queries"):
        return [dict(row) for row in connection.execute(text_factory(sql), params or {}).mappings().all()]


def final_queries(authority):
    unit = next(u for u in authority.registry["units"] if u["next"] == "086_uuid_tenants_finalize")
    s = authority.modules["source_registry"]
    source = s.read_pinned(authority.root, unit["source"], unit["source_sha256"])
    node = next(
        n.value
        for n in ast.parse(source).body
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_SNAPSHOT" for t in n.targets)
    )
    return ast.literal_eval(node)


def collect(authority, connection, meter, text_factory, *, after=False):
    ua, modules, reg = authority.unit_authority, authority.modules, authority.registry
    refs = modules["source_registry"].reference_api(authority.root, reg)
    base = refs["fresh_catalog"].QUERIES

    def q(sql):
        return query(connection, meter, text_factory, sql)

    catalog = {key: q(sql) for key, sql in modules["observations"].catalog_queries(authority.root, reg).items()}
    identity = q(IDENTITY)
    require(len(identity) == 1, "Ambiguous F identity")
    clients, locks = q(base["clients"]), q(base["locks"])
    ordinary = {r["relname"] for r in catalog["relations"] if r["nspname"] == "public" and r["relkind"] == "r"}
    acl = {r["relname"]: r for r in catalog["owners_acl"] if r["nspname"] == "public"}
    business = []
    for name in sorted(ordinary - REFERENCE_TABLES):
        require(
            name in acl and acl[name]["relrowsecurity"] is False and acl[name]["relforcerowsecurity"] is False,
            "RLS could hide business rows",
        )
        rows = q("SELECT EXISTS (SELECT 1 FROM " + relation(name) + " LIMIT 1) AS has_rows")
        require(len(rows) == 1, "Missing business freshness result")
        business.append({"schema": "public", "table": name, "has_rows": rows[0]["has_rows"], "rls": False})
    marker = [r["version_num"] for r in q(MARKER)] if "alembic_version" in ordinary else []
    reference = {key: [] for key in modules["observations"].REFERENCE_SQL}
    if "authorization_roles" in ordinary:
        for key, sql in modules["observations"].REFERENCE_SQL.items():
            rows = q(sql)
            reference[key] = [r["action"] for r in rows] if key == "audit_actions" else rows
    fresh = None
    if ua.unit["kind"] == "frozen_047" and not after:
        # Retain W2.1's own aliases/format, never substitute a different digest.
        fresh = {key: q(sql) for key, sql in base.items()}
        fresh["identity"] = fresh["identity"][0]
        require(len(fresh["alembic"]) == 1, "Ambiguous initial version-table catalog")
        fresh["alembic"] = fresh["alembic"][0]
    final = None
    if ua.unit["kind"] == "uuid_finalize" and not after:
        final = {key: q(sql) for key, sql in final_queries(authority).items()}
    return {
        "identity": identity[0],
        "catalog": catalog,
        "references": reference,
        "business": business,
        "clients": clients,
        "locks": locks,
        "marker": marker,
        "fresh_catalog": fresh,
        "finalization_catalog": final,
    }


def verify(authority, raw, *, readonly, after=False):
    ua = authority.unit_authority
    return authority.modules["observations"].verify_database(
        authority.root, authority.registry, ua.plan, ua.unit, raw, readonly=readonly, after=after
    )
