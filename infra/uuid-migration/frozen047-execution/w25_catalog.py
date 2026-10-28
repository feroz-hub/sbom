"""Fixed catalog-only F pre/post observers and source-derived schema acceptance."""

from __future__ import annotations

import copy

from w25_inputs import digest, require
from w25_schema import MARKER_SQL, expression

# The post columns projection is restricted to application base-table columns.
# Index/sequence/TOAST classes are independently covered by storage and indexes.
COLUMNS = """SELECT c.relname AS table,a.attname AS name,a.attnum AS position,
pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull AS not_null,
pg_catalog.pg_get_expr(d.adbin,d.adrelid,false) AS default,a.attidentity::text AS identity,
a.attgenerated::text AS generated,a.attacl::text AS acl,
CASE WHEN a.attcollation=0 THEN NULL ELSE co.collname END AS collation
FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
ORDER BY c.relname,a.attnum"""
CONSTRAINTS = """SELECT c.relname AS table,k.conname AS name,k.contype::text AS type,
ARRAY(SELECT a.attname::text FROM unnest(k.conkey) WITH ORDINALITY x(num,pos)
JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=x.num ORDER BY x.pos) AS columns,
f.relname AS foreign_table,CASE WHEN k.contype='f' THEN ARRAY(SELECT a.attname::text
FROM unnest(k.confkey) WITH ORDINALITY x(num,pos) JOIN pg_catalog.pg_attribute a
ON a.attrelid=f.oid AND a.attnum=x.num ORDER BY x.pos) ELSE NULL END AS foreign_columns,
CASE WHEN k.contype='f' THEN k.confupdtype::text ELSE 'a' END AS update,
CASE WHEN k.contype='f' THEN k.confdeltype::text ELSE 'a' END AS delete,
CASE WHEN k.contype='f' THEN k.confmatchtype::text ELSE 's' END AS match,
k.convalidated AS validated,k.condeferrable AS deferrable,k.condeferred AS deferred,
pg_catalog.pg_get_expr(k.conbin,k.conrelid,false) AS check
FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
JOIN pg_catalog.pg_namespace n ON n.oid=k.connamespace
LEFT JOIN pg_catalog.pg_class f ON f.oid=k.confrelid WHERE n.nspname='public'
ORDER BY c.relname,k.conname"""
INDEXES = """SELECT t.relname AS table,c.relname AS name,i.indisunique AS unique,i.indisprimary AS primary,
ARRAY(SELECT a.attname::text FROM unnest(i.indkey::smallint[]) WITH ORDINALITY x(num,pos)
JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=x.num ORDER BY x.pos) AS columns,
pg_catalog.pg_get_expr(i.indpred,i.indrelid,false) AS predicate,am.amname AS method,
ARRAY(SELECT CASE WHEN o.opcdefault THEN NULL ELSE o.opcname::text END
FROM unnest(i.indclass::oid[]) WITH ORDINALITY x(num,pos) JOIN pg_catalog.pg_opclass o ON o.oid=x.num ORDER BY x.pos) AS opclasses,
i.indisvalid AS valid,i.indisready AS ready,i.indislive AS live,
i.indexprs IS NULL AS no_expressions,i.indnkeyatts=i.indnatts AS no_include,
i.indoption::smallint[] AS options,i.indnullsnotdistinct AS nulls_not_distinct
FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE n.nspname='public' ORDER BY t.relname,c.relname"""
SEQUENCES = """SELECT c.relname AS name,pg_catalog.format_type(s.seqtypid,NULL) AS type,
s.seqstart AS start,s.seqincrement AS increment,s.seqmin AS min,s.seqmax AS max,s.seqcache AS cache,s.seqcycle AS cycle
FROM pg_catalog.pg_sequence s JOIN pg_catalog.pg_class c ON c.oid=s.seqrelid
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname"""
OWNERSHIP = """SELECT s.relname AS sequence,t.relname AS table,a.attname AS column,d.deptype::text AS dependency
FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_class s ON s.oid=d.objid
JOIN pg_catalog.pg_namespace n ON n.oid=s.relnamespace JOIN pg_catalog.pg_class t ON t.oid=d.refobjid
JOIN pg_catalog.pg_attribute a ON a.attrelid=t.oid AND a.attnum=d.refobjsubid
WHERE n.nspname='public' AND s.relkind='S' AND d.classid='pg_class'::regclass
AND d.refclassid='pg_class'::regclass AND d.refobjsubid>0 ORDER BY s.relname"""
STORAGE = """SELECT c.oid::bigint AS oid,n.nspname AS schema,c.relname AS name,c.relkind::text AS kind,
pg_catalog.pg_get_userbyid(c.relowner) AS owner,c.relacl::text AS acl,c.relpersistence::text AS persistence,
c.relrowsecurity AS rls,c.relforcerowsecurity AS force_rls,c.reloptions IS NULL AS default_options,
c.reltablespace=0 AS default_tablespace,c.relreplident::text AS replica_identity,
c.reltoastrelid::bigint AS toast_oid,p.oid::bigint AS parent_oid,p.relname AS parent,
pt.oid::bigint AS toast_parent_oid,pt.relname AS toast_parent,
EXISTS(SELECT 1 FROM pg_catalog.pg_inherits h WHERE h.inhrelid=c.oid OR h.inhparent=c.oid) AS inherits,
c.relispopulated AS populated,c.relispartition AS partition,
COALESCE(am.amname,'') AS method
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_catalog.pg_class p ON p.reltoastrelid=c.oid
LEFT JOIN pg_catalog.pg_index ix ON ix.indexrelid=c.oid
LEFT JOIN pg_catalog.pg_class tt ON tt.oid=ix.indrelid
LEFT JOIN pg_catalog.pg_class pt ON pt.reltoastrelid=tt.oid
LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam
WHERE c.oid>=16384 OR n.nspname NOT IN ('pg_catalog','pg_toast','information_schema')
ORDER BY n.nspname,c.relname"""
EXTRA = {
    "constraints": CONSTRAINTS,
    "indexes": INDEXES,
    "sequences": SEQUENCES,
    "sequence_ownership": OWNERSHIP,
    "storage": STORAGE,
}


def rows(connection, sql, limit=1024, *, meter=None):
    result = connection.exec_driver_sql(sql)
    data = [dict(x) for x in result.mappings().fetchmany(limit + 1)]
    require(len(data) <= limit, "Bounded result limit exhausted")
    if meter is not None:
        meter.observed_rows = getattr(meter, "observed_rows", 0) + len(data)
        require(meter.observed_rows <= 8192, "Unit catalog result budget exhausted")
    return data


def collect(connection, api, meter, model, *, after):
    queries = dict(api["readonly"]["catalog"].QUERIES)
    if after:
        queries["columns"] = COLUMNS
    data = {k: rows(connection, sql, meter=meter) for k, sql in queries.items()}
    meter.prefix(sorted(r["relname"] for r in data["relations"] if r["nspname"] == "public" and r["relkind"] == "r"))
    if after:
        data.update({k: rows(connection, sql, meter=meter) for k, sql in EXTRA.items()})
        data["business"] = [
            {
                "table": name,
                "has_rows": rows(
                    connection, 'SELECT EXISTS (SELECT 1 FROM public."' + name + '" LIMIT 1) AS has_rows', meter=meter
                )[0]["has_rows"],
            }
            for name in sorted(model["tables"])
            if name != "alembic_version"
        ]
        data["marker"] = rows(connection, MARKER_SQL, meter=meter)
    return data


def tokens(api, value):
    if value is None:
        return None
    return expression(api["fresh"]["pg_lex"].statements(value + ";")[0].tokens)


def equal_rows(actual, expected, label):
    require(
        type(actual) is list
        and len(actual) == len(expected)
        and sorted(digest(r) for r in actual) == sorted(digest(r) for r in expected),
        label + " mismatch/duplicate/missing",
    )


# Explicit four-phase policy. SET LOCAL changes source even if value is equal;
# only the reviewed six monitored assignments change to session post-body.
# REL_16_15 guc_funcs.c ExecSetVariableStmt; guc.c bool/int/string setters.
SETTING_PHASES = {
    (True, False): "initial_readonly",
    (False, False): "locked_pre_ddl",
    (False, True): "post_body",
    (True, True): "independent_readback",
}
LOCAL_MONITORED_SETTINGS = {
    "statement_timeout": "30000",
    "lock_timeout": "1000",
    "idle_in_transaction_session_timeout": "30000",
    "check_function_bodies": "on",
    "row_security": "on",
    "search_path": "pg_catalog",  # after the separately reviewed RESET SQL
}


def expected_settings(baseline, *, readonly, after):
    require(type(readonly) is bool and type(after) is bool, "Exact observation phase required")
    phase = SETTING_PHASES[(readonly, after)]
    result = copy.deepcopy(baseline["settings"])
    names = [row["name"] for row in result]
    require(
        len(names) == len(set(names)) and set(LOCAL_MONITORED_SETTINGS) <= set(names), "Incomplete baseline settings"
    )
    for row in result:
        if row["name"] in LOCAL_MONITORED_SETTINGS:
            require(row["source"] == "client", "Unexpected original F setting source")
            row["setting"] = LOCAL_MONITORED_SETTINGS[row["name"]]
            row["source"] = "session" if phase == "post_body" else "client"
        elif row["name"] == "transaction_read_only":
            require(row["source"] == "session", "Unexpected original transaction setting source")
            row["setting"] = "on" if readonly else "off"
    return result


def verify(data, baseline, api, model, *, readonly, after, marker):
    require(
        set(data)
        == set(baseline)
        | (
            {"constraints", "indexes", "sequences", "sequence_ownership", "storage", "business", "marker"}
            if after
            else set()
        ),
        "Incomplete catalog scope",
    )
    # Exact accepted F security/catalog metadata. Permitted session differences
    # are independently specified here; no observed value is rewritten to pass.
    expected = copy.deepcopy(baseline)
    expected["identity"][0]["transaction_read_only"] = "on" if readonly else "off"
    expected["settings"] = expected_settings(baseline, readonly=readonly, after=after)
    variable = {"relations", "columns", "types", "alembic", "shared_dependencies"} if after else set()
    for key in baseline:
        if key not in variable:
            require(data[key] == expected[key], "Accepted F security/session drift: " + key)
    api["readonly"]["catalog"].schema_privileges(data["schemas"], data["schema_privileges"])
    if not after:
        require(data == expected, "Fresh F catalog drift")
        return digest(data)
    m = model
    relation_rows = [
        {"nspname": "public", "relname": name, "relkind": kind, "relpersistence": "p"}
        for kind, names in [
            ("r", m["tables"]),
            ("S", [r["name"] for r in m["sequences"]]),
            ("i", [r["name"] for r in m["indexes"]]),
        ]
        for name in names
    ]
    equal_rows(data["relations"], relation_rows, "Relation graph")
    type_rows = [
        {"nspname": "public", "typname": name, "typtype": kind}
        for table in m["tables"]
        for name, kind in [(table, "c"), ("_" + table, "b")]
    ]
    equal_rows(data["types"], type_rows, "Composite type graph")
    cols = []
    for row in data["columns"]:
        row = dict(row)
        require(
            row.pop("collation") == ("default" if row["type"].startswith(("text", "character varying")) else None),
            "Column collation drift",
        )
        row["default"] = tokens(api, row["default"])
        cols.append(row)
    equal_rows(cols, [c for values in m["tables"].values() for c in values], "Columns/defaults/ACL")
    cons = []
    for row in data["constraints"]:
        row = dict(row)
        row["check"] = tokens(api, row["check"])
        row["columns"] = sorted(row["columns"]) if row["type"] == "c" else row["columns"]
        cons.append(row)
    equal_rows(cons, m["constraints"], "Constraints/integer FK graph")
    indexes = []
    for row in data["indexes"]:
        row = dict(row)
        require(
            all(row.pop(k) is True for k in ["valid", "ready", "live", "no_expressions", "no_include"]),
            "Invalid index properties",
        )
        require(row.pop("nulls_not_distinct") is False, "Unexpected null uniqueness")
        options = row.pop("options")
        require(type(options) is list and options == [0] * len(row["columns"]), "Index ordering/opclass options")
        row["predicate"] = tokens(api, row["predicate"])
        indexes.append(row)
    equal_rows(indexes, m["indexes"], "Indexes/opclasses/predicates")
    equal_rows(data["sequences"], m["sequences"], "Sequence configuration")
    equal_rows(data["sequence_ownership"], m["sequence_ownership"], "Sequence ownership")
    equal_rows(
        data["business"],
        [{"table": t, "has_rows": False} for t in m["tables"] if t != "alembic_version"],
        "Empty business tables",
    )
    require(
        data["alembic"] == [{"relation": "public.alembic_version"}] and data["marker"] == marker,
        "Exact actual Alembic state",
    )
    storage = data["storage"]
    public = {r["name"]: r for r in storage if r["schema"] == "public"}
    fields = {
        "oid",
        "schema",
        "name",
        "kind",
        "owner",
        "acl",
        "persistence",
        "rls",
        "force_rls",
        "default_options",
        "default_tablespace",
        "replica_identity",
        "toast_oid",
        "parent_oid",
        "parent",
        "toast_parent_oid",
        "toast_parent",
        "inherits",
        "populated",
        "partition",
        "method",
    }
    require(
        all(type(r) is dict and set(r) == fields and type(r["oid"]) is int and r["oid"] >= 16384 for r in storage),
        "Incomplete storage fields",
    )
    require(len(storage) == len({(r["schema"], r["name"]) for r in storage}), "Duplicate storage name")
    require(
        len(storage) == len({r["oid"] for r in storage}) and set(public) == {r["relname"] for r in relation_rows},
        "Storage identity/namespace drift",
    )
    public_oids = {r["oid"]: r for r in public.values()}
    toast = {}
    for row in storage:
        require(
            row["owner"] == baseline["identity"][0]["current_user"]
            and row["acl"] is None
            and row["persistence"] == "p"
            and row["rls"] is False
            and row["force_rls"] is False
            and row["inherits"] is False
            and row["partition"] is False
            and row["default_options"] is True
            and row["default_tablespace"] is True
            and row["populated"] is True,
            "Object owner/ACL/storage properties",
        )
        require(row["replica_identity"] == ("d" if row["kind"] == "r" else "n"), "Unexpected replica identity")
        if row["schema"] == "public":
            expected_kind = next(r["relkind"] for r in relation_rows if r["relname"] == row["name"])
            require(row["kind"] == expected_kind, "Storage kind mismatch")
            require(
                row["method"]
                == (
                    "heap"
                    if expected_kind == "r"
                    else next(i["method"] for i in m["indexes"] if i["name"] == row["name"])
                    if expected_kind == "i"
                    else ""
                ),
                "Storage method",
            )
            require(
                all(row[k] is None for k in ["parent_oid", "parent", "toast_parent_oid", "toast_parent"]),
                "Unexpected public storage parent",
            )
            if row["toast_oid"]:
                require(row["kind"] == "r", "Non-table TOAST pointer")
                toast[row["toast_oid"]] = row
        elif row["schema"] == "pg_toast":
            require(row["kind"] in {"t", "i"}, "Unknown TOAST object")
        else:
            raise ValueError("Unexpected storage namespace")
    for row in storage:
        if row["schema"] != "pg_toast":
            continue
        if row["kind"] == "t":
            require(
                row["oid"] in toast
                and toast[row["oid"]]["oid"] == row["parent_oid"]
                and row["parent_oid"] in public_oids
                and row["parent"] == public_oids[row["parent_oid"]]["name"]
                and row["name"] == "pg_toast_" + str(row["parent_oid"])
                and row["method"] == "heap"
                and row["toast_parent_oid"] is None
                and row["toast_parent"] is None
                and row["toast_oid"] == 0,
                "Unreviewed TOAST ownership",
            )
        else:
            require(
                row["toast_parent_oid"] in public_oids
                and public_oids[row["toast_parent_oid"]]["toast_oid"] in toast
                and row["toast_parent"] == public_oids[row["toast_parent_oid"]]["name"]
                and row["name"] == "pg_toast_" + str(row["toast_parent_oid"]) + "_index"
                and row["method"] == "btree"
                and row["parent_oid"] is None
                and row["parent"] is None
                and row["toast_oid"] == 0,
                "Unreviewed TOAST index",
            )
    require(
        len([r for r in storage if r["schema"] == "pg_toast"]) == 2 * len(toast), "Incomplete TOAST dependency graph"
    )
    allowed_roleoids = {r["oid"] for r in data["roles"]}
    require(
        all(
            r["refclassid"] in {"pg_authid", "pg_tablespace"}
            and (r["refclassid"] != "pg_authid" or r["refobjid"] in allowed_roleoids)
            for r in data["shared_dependencies"]
        ),
        "Unapproved shared dependency",
    )
    return digest(data)
