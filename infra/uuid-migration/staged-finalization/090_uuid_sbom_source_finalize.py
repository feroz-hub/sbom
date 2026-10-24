"""Fresh-install sbom_source UUID finalization; staged, no certified data upgrade.

One separately authorized F-only transaction. No helper imports or internal
commit. The future reviewed coordinator must own marker/commit/close/read-back.
No runtime coordinator, active registration or execution approval ships here.
"""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import sqlalchemy as sa
from alembic import op

revision = "090_uuid_sbom_source_finalize"
down_revision = "089_uuid_logical_sbom_finalize"
branch_labels = None
depends_on = None

_TABLE = "sbom_source"
_POSITION = 4
_TABLES = ("tenants", "projects", "products", "logical_sbom", "sbom_source", "sbom_component")
_FINAL = (
    "086_uuid_tenants_finalize",
    "087_uuid_projects_finalize",
    "088_uuid_products_finalize",
    "089_uuid_logical_sbom_finalize",
    "090_uuid_sbom_source_finalize",
    "091_uuid_sbom_component_finalize",
)
_GUARD_SHA = "ff93761fa4dd31fa6dff7c25f3aedf41bc960e181a234d390f540e359d2e8d58"
_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_IDENTITY = """SELECT current_database() AS database,current_user AS user,session_user AS session_user,
 (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AS database_oid,
 (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier,
 current_setting('server_version_num')::int AS version,pg_catalog.pg_is_in_recovery() AS recovery,
 current_setting('session_replication_role') AS replication,current_setting('row_security') AS row_security,
 current_setting('transaction_read_only') AS readonly,current_setting('search_path') AS search_path,
 pg_catalog.inet_server_port() AS port,pg_catalog.host(pg_catalog.inet_server_addr()) AS ip,
 current_setting('data_directory') AS data_directory"""
_COLUMN = """SELECT c.oid,c.relkind::text,c.relpersistence::text,c.relrowsecurity,c.relforcerowsecurity,
 c.relispartition,a.attnum,a.atttypid='pg_catalog.uuid'::regtype AS uuid,a.attnotnull,
 a.attgenerated::text,a.attidentity::text,pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS default,
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid) AS plain,
 pg_catalog.pg_get_userbyid(c.relowner) AS owner,
 pg_catalog.pg_has_role(current_user,c.relowner,'USAGE') AS owns,
 pg_catalog.has_table_privilege(current_user,c.oid,'SELECT') AS can_select,
 EXISTS(SELECT 1 FROM pg_catalog.pg_constraint p JOIN pg_catalog.pg_attribute i ON i.attrelid=p.conrelid
  AND i.attname='id' WHERE p.conrelid=c.oid AND p.contype='p' AND p.conkey=ARRAY[i.attnum]::smallint[]
  AND i.atttypid='pg_catalog.int4'::regtype AND i.attnotnull) AS integer_pk
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attname='public_id' AND NOT a.attisdropped
 LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname='public' AND c.relname=:table"""
_CHECK = """SELECT contype::text,convalidated,connoinherit,pg_catalog.pg_get_expr(conbin,conrelid) AS expression
 FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND (conname=:name OR
 (contype='c' AND position('public_id' in pg_catalog.pg_get_constraintdef(oid))>0))"""
_TRIGGERS = """SELECT tgname,tgtype,tgenabled::text,tgnargs,pg_catalog.pg_get_triggerdef(oid) AS definition
 FROM pg_catalog.pg_trigger WHERE tgrelid=:oid AND NOT tgisinternal ORDER BY tgname"""
_GUARD = """SELECT p.prosrc,l.lanname,p.pronargs,p.prokind::text,p.prorettype='pg_catalog.trigger'::regtype AS trigger,
 p.provolatile::text,p.prosecdef,p.proisstrict,p.proretset,p.proleakproof,p.proparallel::text,p.proconfig,
 pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE') AS executable
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname='uuid_public_identity_guard_v1'"""
_INDEXES = """SELECT i.indexrelid,i.indisunique,i.indisvalid,i.indisready,i.indislive,i.indisprimary,
 i.indnkeyatts,i.indnatts,i.indnullsnotdistinct,am.amname,c.relname,
 i.indpred IS NULL AS full,i.indexprs IS NULL AS simple,
 k.conname,k.contype::text,k.condeferrable,k.condeferred,k.convalidated,
 i.indkey[0]=:attnum AS correct_key,pg_catalog.pg_get_indexdef(i.indexrelid,1,true) AS key_definition
 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
 JOIN pg_catalog.pg_am am ON am.oid=c.relam
 LEFT JOIN pg_catalog.pg_constraint k ON k.conindid=i.indexrelid AND k.contype IN ('u','p')
 WHERE i.indrelid=:oid AND (:attnum=ANY(i.indkey) OR c.relname=:name
 OR position('public_id' in pg_catalog.pg_get_indexdef(i.indexrelid))>0) ORDER BY c.relname"""
_RELATIONS = """SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname"""
# Baseline digest includes definitions, ACLs, roles and extension properties;
# no passwords, subscription conninfo, business records or sequence positions.
_SNAPSHOT = {
    "relations": "SELECT n.nspname,c.relname,c.relkind::text,c.relpersistence::text,c.relrowsecurity,c.relforcerowsecurity,c.relowner,c.relacl::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' ORDER BY n.nspname,c.relname",
    "columns": "SELECT a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attnotnull,a.attidentity::text,a.attgenerated::text,a.attacl::text,pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS expression FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attrelid,a.attnum",
    "constraints": "SELECT c.conrelid,c.conname,c.contype::text,c.convalidated,c.condeferrable,c.condeferred,pg_catalog.pg_get_constraintdef(c.oid) AS definition FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public' ORDER BY c.conrelid,c.conname",
    "indexes": "SELECT i.indrelid,c.relname,pg_catalog.pg_get_indexdef(i.indexrelid) AS definition,i.indisvalid,i.indisready,i.indislive FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY i.indrelid,c.relname",
    "functions": "SELECT n.nspname,p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,p.prosrc,p.prorettype,p.prokind::text,p.prolang,p.proretset,p.proowner,p.proacl::text,p.proconfig,p.prosecdef,p.provolatile::text,p.proparallel::text,p.proleakproof,p.proisstrict FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' ORDER BY p.proname,arguments",
    "triggers": "SELECT t.tgrelid,t.tgname,t.tgenabled::text,pg_catalog.pg_get_triggerdef(t.oid) AS definition FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY t.tgrelid,t.tgname",
    "roles": "SELECT oid,rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolconfig FROM pg_catalog.pg_roles ORDER BY oid",
    "memberships": "SELECT roleid,member,grantor,admin_option,inherit_option,set_option FROM pg_catalog.pg_auth_members ORDER BY roleid,member",
    "extensions": "SELECT extname,extversion,extnamespace,extowner FROM pg_catalog.pg_extension ORDER BY extname",
    "schemas": "SELECT nspname,nspowner,nspacl::text FROM pg_catalog.pg_namespace ORDER BY nspname",
    "default_acl": "SELECT defaclrole,defaclnamespace,defaclobjtype::text,defaclacl::text FROM pg_catalog.pg_default_acl ORDER BY defaclrole,defaclnamespace,defaclobjtype",
    "database": "SELECT oid,datname,datdba,datacl::text FROM pg_catalog.pg_database WHERE datname=current_database()",
    "sequences": "SELECT s.seqrelid,s.seqtypid,s.seqstart,s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle FROM pg_catalog.pg_sequence s JOIN pg_catalog.pg_class c ON c.oid=s.seqrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY s.seqrelid",
    "rules": "SELECT r.ev_class,r.rulename,pg_catalog.pg_get_ruledef(r.oid) AS definition FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY r.ev_class,r.rulename",
    "reference_roles": "SELECT id,code,scope,status,is_system,is_assignable,version FROM public.authorization_roles ORDER BY id",
    "reference_permissions": "SELECT id,code,scope,status,is_system FROM public.authorization_permissions ORDER BY id",
    "reference_mappings": "SELECT role_id,permission_id,is_protected FROM public.authorization_role_permissions ORDER BY role_id,permission_id",
}


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _rows(bind, sql, values=None):
    return [dict(r) for r in bind.execute(sa.text(sql), values or {}).mappings().all()]


def _approval(context):
    """Future coordinator receipt; never generated/approved by this revision.

    A separately reviewed coordinator must verify original private manifest raw
    bytes, resource/secret correlation, source pins and fresh catalog before
    constructing this exact per-unit context. No existing runner supplies it.
    """
    p = context.opts.get("w22_f_finalization")
    fields = {
        "target",
        "host",
        "port",
        "database",
        "user",
        "system_identifier",
        "database_oid",
        "server_ip",
        "current_revision",
        "next_revision",
        "manifest_sha256",
        "source_sha256",
        "catalog_sha256",
        "expires_at",
        "approval_reference",
        "resource_review_reference",
        "credential_review_reference",
        "security_review_reference",
        "writers_stopped",
        "fresh_install_accepted",
        "coordinator_reviewed",
    }
    _require(isinstance(p, dict) and set(p) == fields, "Exact F finalization approval context required")
    _require(
        (p["target"], p["host"], p["port"], p["database"], p["user"])
        == ("F", "127.0.0.1", 56043, "uuid_w2_f_fresh", "uuid_w2_f_bootstrap")
        and type(p["port"]) is int,
        "Only independently accepted F target is eligible",
    )
    _require(p["current_revision"] == down_revision and p["next_revision"] == revision, "Incorrect revision authority")
    _require(
        all(p[k] is True for k in ("writers_stopped", "fresh_install_accepted", "coordinator_reviewed")),
        "Fresh isolated writer/security window not approved",
    )
    for key in (
        "approval_reference",
        "resource_review_reference",
        "credential_review_reference",
        "security_review_reference",
    ):
        _require(isinstance(p[key], str) and bool(p[key].strip()), "Missing operator review/action reference")
    for key in ("manifest_sha256", "source_sha256", "catalog_sha256"):
        _require(isinstance(p[key], str) and re.fullmatch("[0-9a-f]{64}", p[key]), "Exact approved hash required")
    _require(
        p["source_sha256"] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "Finalization source changed"
    )
    _require(
        isinstance(p["system_identifier"], str)
        and re.fullmatch("[1-9][0-9]{0,19}", p["system_identifier"])
        and p["system_identifier"] != "7697252084555804711",
        "Verified distinct F cluster required",
    )
    _require(
        type(p["database_oid"]) is int and p["database_oid"] > 0 and isinstance(p["server_ip"], str),
        "Verified F database/interface required",
    )
    try:
        expiry = datetime.fromisoformat(p["expires_at"])
        _require(
            expiry.utcoffset() is not None and expiry.utcoffset().total_seconds() == 0 and expiry > datetime.now(UTC),
            "Expired/non-UTC authority",
        )
    except (ValueError, TypeError):
        raise RuntimeError("Invalid approval expiry") from None
    return dict(p)


def _identity(bind, plan):
    expected = {
        "database": plan["database"],
        "user": plan["user"],
        "session_user": plan["user"],
        "database_oid": plan["database_oid"],
        "system_identifier": plan["system_identifier"],
        "version": 160015,
        "recovery": False,
        "replication": "origin",
        "row_security": "on",
        "readonly": "off",
        "search_path": "pg_catalog",
        "port": 5432,
        "ip": plan["server_ip"],
        "data_directory": "/var/lib/postgresql/data",
    }
    _require(_rows(bind, _IDENTITY) == [expected], "F PostgreSQL identity/security mismatch")


def _check_guard(bind):
    rows = _rows(bind, _GUARD)
    _require(len(rows) == 1, "Shared guard missing or overloaded")
    row = rows[0]
    body = row.pop("prosrc")
    _require(hashlib.sha256(body.encode()).hexdigest() == _GUARD_SHA, "Shared UUID guard body changed")
    _require(
        row
        == {
            "lanname": "plpgsql",
            "pronargs": 0,
            "prokind": "f",
            "trigger": True,
            "provolatile": "v",
            "prosecdef": False,
            "proisstrict": False,
            "proretset": False,
            "proleakproof": False,
            "proparallel": "u",
            "proconfig": ["search_path=pg_catalog"],
            "executable": True,
        },
        "Shared guard signature/security changed",
    )


def _prefix(bind, completed):
    _check_guard(bind)
    for i, table in enumerate(_TABLES):
        done = i < completed
        col = _rows(bind, _COLUMN, {"table": table})
        _require(len(col) == 1, "Expanded UUID column missing")
        c = col[0]
        _require(
            c["relkind"] == "r"
            and c["relpersistence"] == "p"
            and c["plain"]
            and not c["relispartition"]
            and not c["relrowsecurity"]
            and not c["relforcerowsecurity"]
            and c["uuid"]
            and c["attnotnull"] is done
            and c["attgenerated"] == ""
            and c["attidentity"] == ""
            and c["default"] in ("gen_random_uuid()", "pg_catalog.gen_random_uuid()")
            and c["owns"]
            and c["can_select"]
            and c["integer_pk"],
            "Expanded table/type/default/role/PK mismatch",
        )
        checks = _rows(bind, _CHECK, {"oid": c["oid"], "name": f"ck_{table}_public_id_v4"})
        _require(
            len(checks) == 1
            and checks[0]["contype"] == "c"
            and checks[0]["convalidated"] is done
            and not checks[0]["connoinherit"],
            "UUID CHECK validation state mismatch",
        )
        normalized = re.sub(r'[\s()"]', "", checks[0]["expression"]).replace("pg_catalog.", "").replace("::text", "")
        _require(normalized == f"public_idISNULLORpublic_id~'{_PATTERN}'", "UUID CHECK expression changed")
        expected = [
            {
                "tgname": f"trg_{table}_public_id_immutable",
                "tgtype": 17,
                "tgenabled": "O",
                "tgnargs": 0,
                "definition": f"CREATE TRIGGER trg_{table}_public_id_immutable AFTER UPDATE ON public.{table} FOR EACH ROW WHEN ((old.public_id IS DISTINCT FROM new.public_id)) EXECUTE FUNCTION public.uuid_public_identity_guard_v1()",
            },
            {
                "tgname": f"trg_{table}_public_id_insert",
                "tgtype": 7,
                "tgenabled": "O",
                "tgnargs": 0,
                "definition": f"CREATE TRIGGER trg_{table}_public_id_insert BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.uuid_public_identity_guard_v1()",
            },
        ]
        _require(
            _rows(bind, _TRIGGERS, {"oid": c["oid"]}) == expected, "Unapproved trigger collision/definition/enablement"
        )
        _require(
            not _rows(
                bind,
                "SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=:oid AND ev_type<>'1' LIMIT 1",
                {"oid": c["oid"]},
            ),
            "Unapproved write rule",
        )
        indexes = _rows(bind, _INDEXES, {"oid": c["oid"], "attnum": c["attnum"], "name": f"uq_{table}_public_id"})
        if not done:
            _require(not indexes, "Unexpected existing UUID index; never silently adopt")
            _require(
                not _rows(
                    bind,
                    "SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=:name",
                    {"name": f"uq_{table}_public_id"},
                ),
                "Global index/relation name collision",
            )
            _require(
                not _rows(
                    bind,
                    "SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND conname=:name",
                    {"oid": c["oid"], "name": f"uq_{table}_public_id"},
                ),
                "UNIQUE name collision",
            )
        else:
            _require(len(indexes) == 1, "Exactly one UUID backing index required")
            idx = indexes[0]
            _require(
                all(
                    idx[k] is True
                    for k in (
                        "indisunique",
                        "indisvalid",
                        "indisready",
                        "indislive",
                        "full",
                        "simple",
                        "convalidated",
                        "correct_key",
                    )
                )
                and not any(idx[k] for k in ("indisprimary", "indnullsnotdistinct", "condeferrable", "condeferred"))
                and idx["indnkeyatts"] == idx["indnatts"] == 1
                and idx["amname"] == "btree"
                and idx["relname"] == idx["conname"] == f"uq_{table}_public_id"
                and idx["contype"] == "u"
                and idx["key_definition"] == "public_id",
                "UUID UNIQUE/backing-index definition mismatch",
            )


def _empty_business(bind):
    """Permit only source-chain authorization reference rows and seed audit.

    SHARE locks on all business tables prevent other-session DML during the
    fresh unit. This is intentionally broader than the one-table DDL scope.
    Qualified names are quoted by the dialect from actual catalog identifiers.
    """
    references = {"authorization_roles", "authorization_permissions", "authorization_role_permissions"}
    relations = _rows(bind, _RELATIONS)
    _require(
        all(not r["relrowsecurity"] and not r["relforcerowsecurity"] for r in relations),
        "RLS could hide populated business records",
    )
    names = [r["relname"] for r in relations]
    _require(
        set(_TABLES) | {"alembic_version", "authorization_audit_log"} <= set(names), "Incomplete application schema"
    )
    quote = bind.dialect.identifier_preparer.quote_identifier
    for name in names:
        qualified = "public." + quote(name)
        bind.execute(sa.text(f"LOCK TABLE ONLY {qualified} IN SHARE MODE NOWAIT"))
        if name in references or name == "alembic_version":
            continue
        if name == "authorization_audit_log":
            _require(
                not _rows(
                    bind,
                    f"SELECT 1 FROM {qualified} WHERE action IS DISTINCT FROM :seed LIMIT 1",
                    {"seed": "AUTHORIZATION_CATALOG_SEEDED"},
                ),
                "Unexpected authorization/business audit",
            )
        else:
            _require(
                not _rows(bind, f"SELECT 1 FROM {qualified} LIMIT 1"),
                "Populated installation is not a fresh finalization target",
            )


def _data_preconditions(bind):
    for table in _TABLES:
        q = f'public."{table}"'
        result = _rows(
            bind,
            f"SELECT EXISTS(SELECT 1 FROM {q} WHERE public_id IS NULL) AS nulls, EXISTS(SELECT 1 FROM {q} GROUP BY public_id HAVING count(*)>1) AS duplicates, EXISTS(SELECT 1 FROM {q} WHERE public_id::text !~ :pattern) AS invalid",
            {"pattern": _PATTERN},
        )
        _require(
            result == [{"nulls": False, "duplicates": False, "invalid": False}],
            "NULL/duplicate/invalid public UUID; no repair permitted",
        )


def _snapshot(bind):
    return {key: _rows(bind, sql) for key, sql in _SNAPSHOT.items()}


def _delta(before, after, target_oid):
    """Allow only one column flag, one CHECK validation and one UNIQUE/index."""
    for key in set(before) - {"columns", "constraints", "indexes", "relations"}:
        _require(before[key] == after[key], "Unrelated schema/security definition changed")
    old_cols = {(r["attrelid"], r["attnum"]): r for r in before["columns"]}
    new_cols = {(r["attrelid"], r["attnum"]): r for r in after["columns"]}
    _require(set(old_cols) == set(new_cols), "Columns were added/removed during finalization")
    for key, row in old_cols.items():
        expected = dict(row)
        if row["attrelid"] == target_oid and row["attname"] == "public_id":
            expected["attnotnull"] = True
        _require(new_cols[key] == expected, "Integer/business column or default changed")
    old = {(r["conrelid"], r["conname"]): r for r in before["constraints"]}
    new = {(r["conrelid"], r["conname"]): r for r in after["constraints"]}
    _require(
        set(new) - set(old) == {(target_oid, f"uq_{_TABLE}_public_id")} and set(old) <= set(new),
        "Unexpected constraint delta",
    )
    for key, row in old.items():
        expected = dict(row)
        if key == (target_oid, f"ck_{_TABLE}_public_id_v4"):
            expected["convalidated"] = True
            expected["definition"] = row["definition"].removesuffix(" NOT VALID")
        _require(new[key] == expected, "Original PK/FK/CHECK relationship changed")
    for category, keycols in [("indexes", ("indrelid", "relname")), ("relations", ("nspname", "relname"))]:
        old = {tuple(r[k] for k in keycols): r for r in before[category]}
        new = {tuple(r[k] for k in keycols): r for r in after[category]}
        expected = (
            (target_oid, f"uq_{_TABLE}_public_id") if category == "indexes" else ("public", f"uq_{_TABLE}_public_id")
        )
        _require(set(new) - set(old) == {expected} and set(old) <= set(new), "Unexpected index/relation delta")
        _require(all(new[k] == v for k, v in old.items()), "Original index/relation/ACL changed")


def upgrade():
    context = op.get_context()
    _require(
        not context.as_sql and context.dialect.name == "postgresql" and context.impl.transactional_ddl,
        "Approved online PostgreSQL transactional DDL required",
    )
    plan = _approval(context)
    bind = op.get_bind()
    _require(
        bind.in_transaction()
        and bind.get_execution_options().get("isolation_level") != "AUTOCOMMIT"
        and bind.connection.driver_connection.autocommit is False,
        "One owned transaction required",
    )
    _identity(bind, plan)
    # Bound operations, retain stricter caller limits (source-local caps).
    bind.execute(
        sa.text(
            "SELECT pg_catalog.set_config('lock_timeout',LEAST(NULLIF((SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='lock_timeout'),0),1000)::text,true), pg_catalog.set_config('statement_timeout',LEAST(NULLIF((SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='statement_timeout'),0),10000)::text,true)"
        )
    )
    _require(
        _rows(bind, "SELECT pg_catalog.pg_try_advisory_xact_lock(7160085085) AS acquired") == [{"acquired": True}],
        "Migration serialization unavailable",
    )
    bind.execute(sa.text("LOCK TABLE ONLY public.alembic_version IN EXCLUSIVE MODE NOWAIT"))
    _require(
        _rows(bind, "SELECT version_num FROM public.alembic_version") == [{"version_num": down_revision}],
        "Exact sole predecessor marker required",
    )
    bind.execute(sa.text(f'LOCK TABLE ONLY public."{_TABLE}" IN ACCESS EXCLUSIVE MODE NOWAIT'))
    _require(
        not _rows(
            bind,
            "SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend' LIMIT 1",
        ),
        "Competing F client/writer",
    )
    _require(
        not _rows(bind, "SELECT 1 FROM pg_catalog.pg_event_trigger LIMIT 1"), "Event triggers require separate review"
    )
    _prefix(bind, _POSITION)
    _data_preconditions(bind)
    _empty_business(bind)
    before = _snapshot(bind)
    _require(_digest(before) == plan["catalog_sha256"], "Independently approved F catalog/security prefix changed")
    _require(_approval(context) == plan, "Approval/source/expiry changed before finalization DDL")
    # Single ordinary UNIQUE constraint automatically creates its one full
    # nondeferrable B-tree backing index, atomically in this transaction.
    op.execute(f'ALTER TABLE public."{_TABLE}" ADD CONSTRAINT "uq_{_TABLE}_public_id" UNIQUE (public_id)')
    op.execute(f'ALTER TABLE public."{_TABLE}" VALIDATE CONSTRAINT "ck_{_TABLE}_public_id_v4"')
    op.execute(f'ALTER TABLE public."{_TABLE}" ALTER COLUMN public_id SET NOT NULL')
    _prefix(bind, _POSITION + 1)
    after = _snapshot(bind)
    target_oid = _rows(bind, _COLUMN, {"table": _TABLE})[0]["oid"]
    _delta(before, after, target_oid)
    _require(
        _rows(bind, "SELECT version_num FROM public.alembic_version") == [{"version_num": down_revision}],
        "Revision must advance only through the coordinator after this upgrade",
    )
    _data_preconditions(bind)
    _empty_business(bind)
    # No COMMIT/version UPDATE here. The future one-step coordinator must update
    # the marker in this owned transaction, acknowledge commit, physically close
    # and independently verify the full committed delta using a new connection.


def downgrade():
    raise RuntimeError(
        "Fresh UUID finalization downgrade is blocked; retain constraints and issued mappings pending separately reviewed recovery"
    )
