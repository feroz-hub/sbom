"""Fixed catalog-only SELECTs; never query table rows or execute function bodies."""

from __future__ import annotations

from security import require, sha

QUERIES = {
    "identity": "SELECT current_database() AS database,current_user AS current_user,session_user AS "
    "session_user,\n"
    "(SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname=current_database()) AS "
    "database_oid,\n"
    "(SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier,\n"
    "current_setting('server_version_num')::integer AS "
    "server_version_num,current_setting('server_version') AS server_version,\n"
    "current_setting('transaction_read_only') AS "
    "transaction_read_only,pg_catalog.pg_is_in_recovery() AS recovery,\n"
    "pg_catalog.host(pg_catalog.inet_server_addr()) AS server_ip,pg_catalog.inet_server_port() AS "
    "server_port,\n"
    "current_setting('data_directory') AS "
    "data_directory,pg_catalog.pg_postmaster_start_time()::text AS postmaster_start,\n"
    "current_setting('session_replication_role') AS replication,current_setting('row_security') AS "
    "row_security,\n"
    "current_setting('search_path') AS search_path",
    "schemas": "SELECT nspname, pg_catalog.pg_get_userbyid(nspowner) AS owner, nspacl::text AS acl\n"
    "      FROM pg_catalog.pg_namespace ORDER BY nspname",
    "relations": "SELECT n.nspname,c.relname,c.relkind,c.relpersistence\n"
    "      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace\n"
    "      WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE "
    "'pg_toast%'\n"
    "      OR (n.nspname='pg_catalog' AND c.oid>=16384) ORDER BY n.nspname,c.relname",
    "functions": "SELECT n.nspname,p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS "
    "arguments,\n"
    "      pg_catalog.pg_get_userbyid(p.proowner) AS owner,p.proacl::text AS "
    "acl,p.prosecdef,p.proconfig\n"
    "      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n"
    "      WHERE n.nspname NOT IN ('pg_catalog','information_schema') OR (p.oid>=16384 AND NOT "
    "EXISTS\n"
    "      (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_proc'::regclass AND "
    "d.objid=p.oid AND d.deptype='e'))\n"
    "      ORDER BY n.nspname,p.proname,arguments",
    "types": "SELECT n.nspname,t.typname,t.typtype FROM pg_catalog.pg_type t\n"
    "      JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace\n"
    "      WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE "
    "'pg_toast%'\n"
    "      OR (n.nspname='pg_catalog' AND t.oid>=16384) ORDER BY n.nspname,t.typname",
    "operators": "SELECT n.nspname,o.oprname FROM pg_catalog.pg_operator o\n"
    "      JOIN pg_catalog.pg_namespace n ON n.oid=o.oprnamespace\n"
    "      WHERE n.nspname<>'pg_catalog' OR o.oid>=16384 ORDER BY n.nspname,o.oprname",
    "other_objects": "SELECT 'collation' AS kind,n.nspname,c.collname AS name FROM pg_catalog.pg_collation c\n"
    "      JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE "
    "n.nspname<>'pg_catalog' OR c.oid>=16384\n"
    "      UNION ALL SELECT 'conversion',n.nspname,c.conname FROM pg_catalog.pg_conversion c\n"
    "      JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace WHERE "
    "n.nspname<>'pg_catalog' OR c.oid>=16384\n"
    "      UNION ALL SELECT 'textsearch',n.nspname,c.cfgname FROM pg_catalog.pg_ts_config c\n"
    "      JOIN pg_catalog.pg_namespace n ON n.oid=c.cfgnamespace WHERE "
    "n.nspname<>'pg_catalog' OR c.oid>=16384\n"
    "      UNION ALL SELECT 'language','',lanname FROM pg_catalog.pg_language WHERE lanname "
    "NOT IN ('internal','c','sql','plpgsql')\n"
    "      UNION ALL SELECT 'cast','',oid::text FROM pg_catalog.pg_cast WHERE oid>=16384\n"
    "      UNION ALL SELECT 'access_method','',amname FROM pg_catalog.pg_am WHERE oid>=16384\n"
    "      UNION ALL SELECT 'operator_class',n.nspname,c.opcname FROM pg_catalog.pg_opclass c "
    "JOIN pg_catalog.pg_namespace n ON n.oid=c.opcnamespace WHERE n.nspname<>'pg_catalog' OR "
    "c.oid>=16384\n"
    "      UNION ALL SELECT 'operator_family',n.nspname,c.opfname FROM pg_catalog.pg_opfamily "
    "c JOIN pg_catalog.pg_namespace n ON n.oid=c.opfnamespace WHERE n.nspname<>'pg_catalog' OR "
    "c.oid>=16384\n"
    "      UNION ALL SELECT 'textsearch_dictionary',n.nspname,c.dictname FROM "
    "pg_catalog.pg_ts_dict c JOIN pg_catalog.pg_namespace n ON n.oid=c.dictnamespace WHERE "
    "n.nspname<>'pg_catalog' OR c.oid>=16384\n"
    "      UNION ALL SELECT 'textsearch_parser',n.nspname,c.prsname FROM "
    "pg_catalog.pg_ts_parser c JOIN pg_catalog.pg_namespace n ON n.oid=c.prsnamespace WHERE "
    "n.nspname<>'pg_catalog' OR c.oid>=16384\n"
    "      UNION ALL SELECT 'textsearch_template',n.nspname,c.tmplname FROM "
    "pg_catalog.pg_ts_template c JOIN pg_catalog.pg_namespace n ON n.oid=c.tmplnamespace WHERE "
    "n.nspname<>'pg_catalog' OR c.oid>=16384\n"
    "      UNION ALL SELECT 'transform','',oid::text FROM pg_catalog.pg_transform\n"
    "      UNION ALL SELECT 'large_object','',oid::text FROM "
    "pg_catalog.pg_largeobject_metadata\n"
    "      UNION ALL SELECT 'security_label','',objoid::text FROM pg_catalog.pg_seclabel ORDER "
    "BY 1,2,3",
    "triggers": "SELECT tgname FROM pg_catalog.pg_trigger WHERE NOT tgisinternal ORDER BY tgname",
    "rules": "SELECT r.rulename FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class\n"
    "      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace\n"
    "      WHERE n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY r.rulename",
    "event_triggers": "SELECT evtname,evtenabled FROM pg_catalog.pg_event_trigger ORDER BY evtname",
    "extensions": "SELECT e.extname,e.extversion,n.nspname AS schema,pg_catalog.pg_get_userbyid(e.extowner) AS "
    "owner\n"
    "      FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace "
    "ORDER BY e.extname",
    "foreign_objects": "SELECT 'wrapper' AS kind,fdwname AS name FROM pg_catalog.pg_foreign_data_wrapper\n"
    "      UNION ALL SELECT 'server',srvname FROM pg_catalog.pg_foreign_server\n"
    "      UNION ALL SELECT 'mapping',oid::text FROM pg_catalog.pg_user_mapping ORDER BY 1,2",
    "replication": "SELECT 'publication' AS kind,pubname AS name FROM pg_catalog.pg_publication\n"
    "      UNION ALL SELECT 'subscription',subname FROM pg_catalog.pg_subscription WHERE "
    "subdbid=\n"
    "      (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) ORDER BY "
    "1,2",
    "roles": "SELECT r.oid,r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcanlogin,\n"
    "      r.rolreplication,r.rolbypassrls,r.rolconnlimit,r.rolconfig IS NULL AS config_null,\n"
    "      a.rolpassword IS NULL AS password_null,\n"
    "      COALESCE(a.rolpassword LIKE 'SCRAM-SHA-256$%',false) AS password_scram\n"
    "      FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_authid a ON a.oid=r.oid ORDER BY r.rolname",
    "memberships": "SELECT pg_catalog.pg_get_userbyid(roleid) AS role,pg_catalog.pg_get_userbyid(member) AS "
    "member,\n"
    "      pg_catalog.pg_get_userbyid(grantor) AS "
    "grantor,admin_option,inherit_option,set_option\n"
    "      FROM pg_catalog.pg_auth_members ORDER BY roleid,member",
    "ownership_acl": "SELECT oid::bigint AS oid,datname,pg_catalog.pg_get_userbyid(datdba) AS owner,\n"
    "datacl IS NULL AS default_acl,datistemplate,datallowconn,datconnlimit,\n"
    "pg_catalog.pg_encoding_to_char(encoding) AS "
    "encoding,datcollate,datctype,datlocprovider,datcollversion\n"
    "FROM pg_catalog.pg_database WHERE datname=current_database()",
    "default_acl": "SELECT pg_catalog.pg_get_userbyid(defaclrole) AS "
    "owner,defaclnamespace,defaclobjtype,defaclacl::text\n"
    "      FROM pg_catalog.pg_default_acl ORDER BY defaclrole,defaclnamespace,defaclobjtype",
    "role_settings": "SELECT setdatabase,setrole,setconfig IS NOT NULL AS has_settings\n"
    "      FROM pg_catalog.pg_db_role_setting ORDER BY setdatabase,setrole",
    "shared_dependencies": "SELECT classid::regclass::text,objid,refclassid::regclass::text,refobjid,deptype\n"
    "      FROM pg_catalog.pg_shdepend WHERE dbid=(SELECT oid FROM "
    "pg_catalog.pg_database WHERE datname=current_database())\n"
    "      ORDER BY classid,objid,refclassid,refobjid,deptype",
    "settings": "SELECT name,setting,source FROM pg_catalog.pg_settings WHERE name IN\n"
    "('statement_timeout','lock_timeout','idle_in_transaction_session_timeout','default_transaction_read_only',\n"
    " "
    "'transaction_read_only','search_path','row_security','check_function_bodies','password_encryption','ssl',\n"
    " "
    "'listen_addresses','port','max_connections','shared_buffers','work_mem','stats_fetch_consistency') "
    "ORDER BY name",
    "hba_file": "SELECT rule_number,type,database,user_name,address,netmask,auth_method,error IS NULL AS parse_ok\n"
    "      FROM pg_catalog.pg_hba_file_rules ORDER BY rule_number",
    "clients": "SELECT pid,usename,state,xact_start IS NOT NULL AS transaction_open\n"
    "      FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND "
    "pid<>pg_backend_pid()\n"
    "      AND backend_type='client backend' ORDER BY pid",
    "locks": "SELECT l.locktype,l.mode,l.granted,l.relation FROM pg_catalog.pg_locks l\n"
    "JOIN pg_catalog.pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database()\n"
    "AND a.backend_type='client backend' AND l.pid<>pg_backend_pid() ORDER BY l.pid,l.locktype,l.mode",
    "alembic": "SELECT pg_catalog.to_regclass('public.alembic_version')::text AS relation",
    "schema_privileges": "SELECT n.nspname,pg_catalog.pg_get_userbyid(n.nspowner) AS owner,\n"
    "CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS "
    "grantee,\n"
    "pg_catalog.pg_get_userbyid(a.grantor) AS grantor,\n"
    "a.privilege_type,a.is_grantable FROM pg_catalog.pg_namespace n\n"
    "CROSS JOIN LATERAL "
    "pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a\n"
    "ORDER BY n.nspname,grantee,a.privilege_type",
    "columns": "SELECT n.nspname,c.relname,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,\n"
    "a.attnotnull,a.attidentity,a.attgenerated FROM pg_catalog.pg_attribute a\n"
    "JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON "
    "n.oid=c.relnamespace\n"
    "WHERE a.attnum>0 AND NOT a.attisdropped AND ((n.nspname NOT IN "
    "('pg_catalog','information_schema')\n"
    "AND n.nspname NOT LIKE 'pg_toast%') OR c.oid>=16384) ORDER BY n.nspname,c.relname,a.attnum",
    "plpgsql_functions": "SELECT p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,\n"
    "pg_catalog.pg_get_function_result(p.oid) AS "
    "result,n.nspname,pg_catalog.pg_get_userbyid(p.proowner) AS owner,\n"
    "l.lanname,p.prosecdef,p.proleakproof,p.proconfig,p.proacl IS NULL AS default_acl\n"
    "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n"
    "JOIN pg_catalog.pg_language l ON l.oid=p.prolang JOIN pg_catalog.pg_depend d\n"
    "ON d.classid='pg_catalog.pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e'\n"
    "JOIN pg_catalog.pg_extension e ON e.oid=d.refobjid WHERE e.extname='plpgsql'\n"
    "ORDER BY p.proname,arguments",
    "privileges": "SELECT pg_catalog.has_database_privilege(current_database(),'CONNECT') AS connect,\n"
    "pg_catalog.has_database_privilege(current_database(),'CREATE') AS create_database_objects,\n"
    "pg_catalog.has_database_privilege(current_database(),'TEMP') AS temporary,\n"
    "pg_catalog.has_schema_privilege('public','USAGE') AS public_usage,\n"
    "pg_catalog.has_schema_privilege('public','CREATE') AS public_create,\n"
    "pg_catalog.has_table_privilege('pg_catalog.pg_authid','SELECT') AS role_read,\n"
    "pg_catalog.has_function_privilege('pg_catalog.pg_control_system()','EXECUTE') AS "
    "control_read",
    "databases": "SELECT datname,pg_catalog.pg_get_userbyid(datdba) AS owner,datistemplate,datallowconn\n"
    "FROM pg_catalog.pg_database ORDER BY datname",
    "tablespaces": "SELECT spcname,pg_catalog.pg_get_userbyid(spcowner) AS owner,spcacl IS NULL AS "
    "default_acl,\n"
    "pg_catalog.pg_tablespace_location(oid) AS location FROM pg_catalog.pg_tablespace ORDER BY "
    "spcname",
}

SQL_PINS = {key: sha(sql.encode()) for key, sql in QUERIES.items()}

EMPTY = (
    "relations",
    "columns",
    "functions",
    "types",
    "operators",
    "other_objects",
    "triggers",
    "rules",
    "event_triggers",
    "foreign_objects",
    "replication",
    "default_acl",
    "role_settings",
    "clients",
    "locks",
)
BUILTINS = {
    "pg_database_owner",
    "pg_read_all_data",
    "pg_write_all_data",
    "pg_monitor",
    "pg_read_all_settings",
    "pg_read_all_stats",
    "pg_stat_scan_tables",
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_execute_server_program",
    "pg_signal_backend",
    "pg_checkpoint",
    "pg_use_reserved_connections",
    "pg_create_subscription",
}
BOOT = "uuid_w2_f_bootstrap"

# REL_16_15 pg_namespace.dat, initdb.c:setup_privileges(), information_schema.sql,
# and acl.c:acldefault()/aclitemout(). Source derivation is not a live observation.
SCHEMA_OWNERS = {
    "public": "pg_database_owner",
    "pg_catalog": BOOT,
    "information_schema": BOOT,
    "pg_toast": BOOT,
}
SCHEMA_ROW_FIELDS = ("nspname", "owner", "grantee", "grantor", "privilege_type", "is_grantable")
SCHEMA_PRIVILEGES = (
    ("public", "pg_database_owner", "pg_database_owner", "pg_database_owner", "CREATE", False),
    ("public", "pg_database_owner", "pg_database_owner", "pg_database_owner", "USAGE", False),
    ("public", "pg_database_owner", "PUBLIC", "pg_database_owner", "USAGE", False),
    ("pg_catalog", BOOT, BOOT, BOOT, "CREATE", False),
    ("pg_catalog", BOOT, BOOT, BOOT, "USAGE", False),
    ("pg_catalog", BOOT, "PUBLIC", BOOT, "USAGE", False),
    ("information_schema", BOOT, BOOT, BOOT, "CREATE", False),
    ("information_schema", BOOT, BOOT, BOOT, "USAGE", False),
    ("information_schema", BOOT, "PUBLIC", BOOT, "USAGE", False),
    ("pg_toast", BOOT, BOOT, BOOT, "CREATE", False),
    ("pg_toast", BOOT, BOOT, BOOT, "USAGE", False),
)


def schema_privileges(schemas, privileges):
    """Exact fresh schema owners, ACL representation and exploded privilege multiset."""
    require(type(schemas) is list and len(schemas) == 4, "Incomplete schema ownership/ACL observations")
    require(
        all(type(r) is dict and set(r) == {"nspname", "owner", "acl"} for r in schemas),
        "Incomplete schema ownership/ACL fields",
    )
    require({r["nspname"] for r in schemas} == set(SCHEMA_OWNERS), "Unexpected/missing schema")
    for row in schemas:
        owner = SCHEMA_OWNERS[row["nspname"]]
        require(row["owner"] == owner, "Schema owner drift")
        # pg_toast retains its NULL/default ACL. The other schemas receive one
        # explicit PUBLIC USAGE grant after owner defaults. Order is preserved
        # by PostgreSQL ACL updates; any different representation needs review.
        expected_acl = None if row["nspname"] == "pg_toast" else "{" + owner + "=UC/" + owner + ",=U/" + owner + "}"
        require(row["acl"] == expected_acl, "Unexpected schema ACL representation")
    require(type(privileges) is list, "Incomplete schema privilege observations")
    require(
        all(
            type(r) is dict
            and set(r) == set(SCHEMA_ROW_FIELDS)
            and type(r["is_grantable"]) is bool
            and all(type(r[k]) is str and r[k] for k in SCHEMA_ROW_FIELDS[:-1])
            for r in privileges
        ),
        "Incomplete or malformed schema privilege fields",
    )
    # Compare the whole sorted multiset, not a set or broad allowlist: missing,
    # duplicate, extra, different-grantor and grantable entries all refuse.
    require(
        sorted(tuple(r[k] for k in SCHEMA_ROW_FIELDS) for r in privileges) == sorted(SCHEMA_PRIVILEGES),
        "Exact fresh schema privileges mismatch",
    )


def one(rows, label):
    require(isinstance(rows, list) and len(rows) == 1, "Ambiguous " + label)
    return rows[0]


def identity(row, server_ip):
    require(
        row["database"] == "uuid_w2_f_fresh"
        and row["current_user"] == row["session_user"] == BOOT
        and type(row["database_oid"]) is int
        and row["database_oid"] > 0
        and row["server_version_num"] == 160015
        and row["server_version"].startswith("16.15")
        and row["transaction_read_only"] == "on"
        and row["recovery"] is False
        and row["server_ip"] == server_ip
        and row["server_port"] == 5432
        and row["data_directory"] == "/var/lib/postgresql/data"
        and row["replication"] == "origin"
        and row["row_security"] == "on"
        and row["search_path"] == "pg_catalog",
        "F PostgreSQL identity/session mismatch",
    )
    value = row["system_identifier"]
    require(
        isinstance(value, str) and value.isdecimal() and 0 < int(value) < 2**64 and value != "7697252084555804711",
        "Unknown/old D cluster identity",
    )
    require(isinstance(row["postmaster_start"], str) and row["postmaster_start"], "Missing server start")


def validate(observed, server_ip, used_password):
    require(set(observed) == set(QUERIES), "Incomplete catalog coverage")
    ident = one(observed["identity"], "identity")
    identity(ident, server_ip)
    require(used_password is True, "UNKNOWN: effective password use not established by libpq")
    require(all(observed[key] == [] for key in EMPTY), "Unexpected objects/clients/locks or partial initialization")
    require(observed["alembic"] == [{"relation": None}], "Unexpected Alembic state")
    schema_privileges(observed["schemas"], observed["schema_privileges"])
    db = one(observed["ownership_acl"], "database")
    require(
        db["oid"] == ident["database_oid"]
        and db["datname"] == ident["database"]
        and db["owner"] == BOOT
        and db["default_acl"] is True
        and db["datistemplate"] is False
        and db["datallowconn"] is True
        and db["datconnlimit"] == -1
        and db["encoding"] == "UTF8"
        and db["datlocprovider"] == "c"
        and all(isinstance(db[k], str) and db[k] for k in ("datcollate", "datctype")),
        "Fresh database owner/locale/ACL mismatch",
    )
    roles = observed["roles"]
    require(
        len(roles) == len(BUILTINS) + 1 and {r["rolname"] for r in roles} == BUILTINS | {BOOT},
        "Unexpected cluster role",
    )
    for role in roles:
        bootstrap = role["rolname"] == BOOT
        require(
            all(
                role[k] is bootstrap
                for k in ("rolsuper", "rolcreatedb", "rolcreaterole", "rolcanlogin", "rolreplication", "rolbypassrls")
            )
            and role["rolinherit"] is True
            and role["rolconnlimit"] == -1
            and role["config_null"] is True
            and role["password_null"] is (not bootstrap)
            and role["password_scram"] is bootstrap,
            "Role privilege/password/configuration mismatch",
        )
    memberships = observed["memberships"]
    require(
        len(memberships) == 3
        and {(r["role"], r["member"]) for r in memberships}
        == {
            ("pg_read_all_settings", "pg_monitor"),
            ("pg_read_all_stats", "pg_monitor"),
            ("pg_stat_scan_tables", "pg_monitor"),
        }
        and all(
            r["grantor"] == BOOT
            and r["admin_option"] is False
            and r["inherit_option"] is True
            and r["set_option"] is True
            for r in memberships
        ),
        "Unexpected memberships",
    )
    ext = one(observed["extensions"], "extension")
    require(
        ext == {"extname": "plpgsql", "extversion": "1.0", "schema": "pg_catalog", "owner": BOOT},
        "Unexpected extension/owner",
    )
    funcs = observed["plpgsql_functions"]
    require(
        len(funcs) == 3
        and {(r["proname"], r["arguments"], r["result"]) for r in funcs}
        == {
            ("plpgsql_call_handler", "", "language_handler"),
            ("plpgsql_inline_handler", "internal", "void"),
            ("plpgsql_validator", "oid", "void"),
        },
        "Unexpected plpgsql members",
    )
    require(
        all(
            r["nspname"] == "pg_catalog"
            and r["owner"] == BOOT
            and r["lanname"] == "c"
            and r["prosecdef"] is False
            and r["proleakproof"] is False
            and r["proconfig"] is None
            and r["default_acl"] is True
            for r in funcs
        ),
        "plpgsql security/ACL mismatch",
    )
    privileges = one(observed["privileges"], "privileges")
    require(
        set(privileges)
        == {
            "connect",
            "create_database_objects",
            "temporary",
            "public_usage",
            "public_create",
            "role_read",
            "control_read",
        }
        and all(v is True for v in privileges.values()),
        "Required catalog privilege unavailable",
    )
    hba = observed["hba_file"]
    require(hba and all(r["parse_ok"] is True for r in hba), "HBA file empty/parse error")
    require(
        all(r["auth_method"] in {"scram-sha-256", "reject"} for r in hba), "Unexpected HBA FILE authentication method"
    )
    settings = {r["name"]: r["setting"] for r in observed["settings"]}
    expected = {
        "statement_timeout": "2000",
        "lock_timeout": "250",
        "idle_in_transaction_session_timeout": "5000",
        "default_transaction_read_only": "on",
        "transaction_read_only": "on",
        "row_security": "on",
        "search_path": "pg_catalog",
        "check_function_bodies": "on",
        "password_encryption": "scram-sha-256",
        "ssl": "off",
        "listen_addresses": "*",
        "port": "5432",
        "max_connections": "12",
        "shared_buffers": "8192",
        "work_mem": "4096",
        "stats_fetch_consistency": "none",
    }
    require(settings == expected, "Effective timeout/security/server configuration mismatch")
    require(
        {r["datname"] for r in observed["databases"]} == {"postgres", "template0", "template1", "uuid_w2_f_fresh"}
        and len(observed["databases"]) == 4
        and all(r["owner"] == BOOT for r in observed["databases"]),
        "Unexpected database/owner in new cluster",
    )
    require(
        {r["spcname"] for r in observed["tablespaces"]} == {"pg_default", "pg_global"}
        and len(observed["tablespaces"]) == 2
        and all(
            r["owner"] == BOOT and r["default_acl"] is True and r["location"] == "" for r in observed["tablespaces"]
        ),
        "Unexpected tablespace/owner",
    )
    roleoids = {r["oid"] for r in roles}
    require(
        all(
            r["refclassid"] in {"pg_authid", "pg_tablespace"}
            and (r["refclassid"] != "pg_authid" or r["refobjid"] in roleoids)
            for r in observed["shared_dependencies"]
        ),
        "Unexpected owner dependency",
    )
    return {
        "scope": "CATALOG_OBSERVATIONS_ONLY",
        "catalog_observations": "PASS",
        "authentication_evidence": "PASS",
        "catalog_fresh": True,
        "libpq_password_used": True,
        "HBA_evidence": "FILE_CONTENT_PARSE_ONLY",
        "loaded_hba_rules": "NOT_PROVEN",
        "exact_auth_mechanism": "NOT_PROVEN_BY_USED_PASSWORD",
        "bootstrap_privileged": True,
        "restricted_runtime_role": "NEEDED_BEFORE_APPLICATION_USE_NOT_CREATED",
        "identity": ident,
        "database": db,
        "overall_acceptance": "NOT_EVALUATED_HERE",
    }
