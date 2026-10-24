"""Future catalog-only observation contract. No connection implementation."""

from pg_lex import Refused

# Future observer must use these fixed SELECTs only, one bounded read-only
# connection, at most64 catalog statements/4 controls, and physically close.
# No passwords, role options, subscription conninfo or user-mapping secrets.
QUERIES = {
    "identity": """SELECT current_database() AS database, current_user AS current_user,
      session_user AS session_user, (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AS database_oid,
      (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_identifier,
      current_setting('server_version_num')::integer AS server_version_num,
      current_setting('transaction_read_only') AS transaction_read_only,
      pg_catalog.pg_is_in_recovery() AS recovery,
      pg_catalog.host(pg_catalog.inet_server_addr()) AS server_ip,
      pg_catalog.inet_server_port() AS server_port,
      current_setting('data_directory') AS data_directory""",
    "schemas": """SELECT nspname, pg_catalog.pg_get_userbyid(nspowner) AS owner, nspacl::text AS acl
      FROM pg_catalog.pg_namespace ORDER BY nspname""",
    "relations": """SELECT n.nspname,c.relname,c.relkind,c.relpersistence
      FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
      OR (n.nspname='pg_catalog' AND c.oid>=16384) ORDER BY n.nspname,c.relname""",
    "functions": """SELECT n.nspname,p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,
      pg_catalog.pg_get_userbyid(p.proowner) AS owner,p.proacl::text AS acl,p.prosecdef,p.proconfig
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname NOT IN ('pg_catalog','information_schema') OR (p.oid>=16384 AND NOT EXISTS
      (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid='pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e'))
      ORDER BY n.nspname,p.proname,arguments""",
    "types": """SELECT n.nspname,t.typname,t.typtype FROM pg_catalog.pg_type t
      JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
      WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
      OR (n.nspname='pg_catalog' AND t.oid>=16384) ORDER BY n.nspname,t.typname""",
    "operators": """SELECT n.nspname,o.oprname FROM pg_catalog.pg_operator o
      JOIN pg_catalog.pg_namespace n ON n.oid=o.oprnamespace
      WHERE n.nspname<>'pg_catalog' OR o.oid>=16384 ORDER BY n.nspname,o.oprname""",
    "other_objects": """SELECT 'collation' AS kind,n.nspname,c.collname AS name FROM pg_catalog.pg_collation c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'conversion',n.nspname,c.conname FROM pg_catalog.pg_conversion c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.connamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'textsearch',n.nspname,c.cfgname FROM pg_catalog.pg_ts_config c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.cfgnamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'language','',lanname FROM pg_catalog.pg_language WHERE lanname NOT IN ('internal','c','sql','plpgsql')
      UNION ALL SELECT 'cast','',oid::text FROM pg_catalog.pg_cast WHERE oid>=16384
      UNION ALL SELECT 'access_method','',amname FROM pg_catalog.pg_am WHERE oid>=16384
      UNION ALL SELECT 'operator_class',n.nspname,c.opcname FROM pg_catalog.pg_opclass c JOIN pg_catalog.pg_namespace n ON n.oid=c.opcnamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'operator_family',n.nspname,c.opfname FROM pg_catalog.pg_opfamily c JOIN pg_catalog.pg_namespace n ON n.oid=c.opfnamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'textsearch_dictionary',n.nspname,c.dictname FROM pg_catalog.pg_ts_dict c JOIN pg_catalog.pg_namespace n ON n.oid=c.dictnamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'textsearch_parser',n.nspname,c.prsname FROM pg_catalog.pg_ts_parser c JOIN pg_catalog.pg_namespace n ON n.oid=c.prsnamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'textsearch_template',n.nspname,c.tmplname FROM pg_catalog.pg_ts_template c JOIN pg_catalog.pg_namespace n ON n.oid=c.tmplnamespace WHERE n.nspname<>'pg_catalog' OR c.oid>=16384
      UNION ALL SELECT 'transform','',oid::text FROM pg_catalog.pg_transform
      UNION ALL SELECT 'large_object','',oid::text FROM pg_catalog.pg_largeobject_metadata
      UNION ALL SELECT 'security_label','',objoid::text FROM pg_catalog.pg_seclabel ORDER BY 1,2,3""",
    "triggers": "SELECT tgname FROM pg_catalog.pg_trigger WHERE NOT tgisinternal ORDER BY tgname",
    "rules": """SELECT r.rulename FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY r.rulename""",
    "event_triggers": "SELECT evtname,evtenabled FROM pg_catalog.pg_event_trigger ORDER BY evtname",
    "extensions": """SELECT e.extname,e.extversion,n.nspname AS schema,pg_catalog.pg_get_userbyid(e.extowner) AS owner
      FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid=e.extnamespace ORDER BY e.extname""",
    "foreign_objects": """SELECT 'wrapper' AS kind,fdwname AS name FROM pg_catalog.pg_foreign_data_wrapper
      UNION ALL SELECT 'server',srvname FROM pg_catalog.pg_foreign_server
      UNION ALL SELECT 'mapping',oid::text FROM pg_catalog.pg_user_mapping ORDER BY 1,2""",
    "replication": """SELECT 'publication' AS kind,pubname AS name FROM pg_catalog.pg_publication
      UNION ALL SELECT 'subscription',subname FROM pg_catalog.pg_subscription WHERE subdbid=
      (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) ORDER BY 1,2""",
    "roles": """SELECT r.oid,r.rolname,r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcanlogin,
      r.rolreplication,r.rolbypassrls,r.rolconnlimit,r.rolconfig IS NULL AS config_null,
      a.rolpassword IS NULL AS password_null,
      COALESCE(a.rolpassword LIKE 'SCRAM-SHA-256$%',false) AS password_scram
      FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_authid a ON a.oid=r.oid ORDER BY r.rolname""",
    "memberships": """SELECT pg_catalog.pg_get_userbyid(roleid) AS role,pg_catalog.pg_get_userbyid(member) AS member,
      pg_catalog.pg_get_userbyid(grantor) AS grantor,admin_option,inherit_option,set_option
      FROM pg_catalog.pg_auth_members ORDER BY roleid,member""",
    "ownership_acl": """SELECT datname,pg_catalog.pg_get_userbyid(datdba) AS owner,datacl::text AS acl,
      datistemplate,datallowconn FROM pg_catalog.pg_database WHERE datname=current_database()""",
    "default_acl": """SELECT pg_catalog.pg_get_userbyid(defaclrole) AS owner,defaclnamespace,defaclobjtype,defaclacl::text
      FROM pg_catalog.pg_default_acl ORDER BY defaclrole,defaclnamespace,defaclobjtype""",
    "role_settings": """SELECT setdatabase,setrole,setconfig IS NOT NULL AS has_settings
      FROM pg_catalog.pg_db_role_setting ORDER BY setdatabase,setrole""",
    "shared_dependencies": """SELECT classid::regclass::text,objid,refclassid::regclass::text,refobjid,deptype
      FROM pg_catalog.pg_shdepend WHERE dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
      ORDER BY classid,objid,refclassid,refobjid,deptype""",
    "settings": """SELECT name,setting,source FROM pg_catalog.pg_settings WHERE name IN
      ('statement_timeout','lock_timeout','idle_in_transaction_session_timeout','search_path','row_security',
       'check_function_bodies','password_encryption','ssl','listen_addresses','port','max_connections') ORDER BY name""",
    "hba_file": """SELECT rule_number,type,database,user_name,address,netmask,auth_method,error
      FROM pg_catalog.pg_hba_file_rules ORDER BY rule_number""",
    "clients": """SELECT pid,usename,application_name,state,xact_start IS NOT NULL AS transaction_open
      FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()
      AND backend_type='client backend' ORDER BY pid""",
    "locks": """SELECT l.locktype,l.mode,l.granted,l.relation FROM pg_catalog.pg_locks l
      JOIN pg_catalog.pg_stat_activity a ON a.pid=l.pid
      WHERE a.datname=current_database() AND l.pid<>pg_backend_pid() ORDER BY l.pid,l.locktype,l.mode""",
    "alembic": "SELECT pg_catalog.to_regclass('public.alembic_version')::text AS relation",
}

EMPTY = (
    "relations",
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


def validate_fresh(observed, plan):
    """Validate synthetic/future observations; does not gather any metadata.

    Exact approved cross-cluster role/ACL/system metadata is required, not an
    empty-public-table heuristic. Catalog privilege errors must be failures,
    never substituted empty lists. File HBA parse is not loaded-policy proof.
    """
    if not isinstance(observed, dict) or set(observed) != set(QUERIES):
        raise Refused("Incomplete catalog evidence")
    identity = observed["identity"]
    expected = plan["identity"]
    required = {
        "database": "uuid_w2_f_fresh",
        "current_user": "uuid_w2_f_bootstrap",
        "session_user": "uuid_w2_f_bootstrap",
        "server_version_num": 160015,
        "transaction_read_only": "on",
        "recovery": False,
        "server_port": 5432,
        "database_oid": expected["database_oid"],
        "system_identifier": expected["system_identifier"],
        "server_ip": expected["server_ip"],
        "data_directory": "/var/lib/postgresql/data",
    }
    if identity != required:
        raise Refused("Fresh F identity mismatch")
    if any(row.get("oid", 0) >= 16384 and row.get("rolname") != "uuid_w2_f_bootstrap" for row in observed["roles"]):
        raise Refused("Unapproved cluster-local role")
    bootstrap = [row for row in observed["roles"] if row.get("rolname") == "uuid_w2_f_bootstrap"]
    if len(bootstrap) != 1 or any(
        bootstrap[0].get(k) != v
        for k, v in {"rolcanlogin": True, "config_null": True, "password_null": False, "password_scram": True}.items()
    ):
        raise Refused("Bootstrap role/password policy mismatch")
    if any(observed[key] != [] for key in EMPTY):
        raise Refused("Partial, occupied or unsupported database")
    if observed["alembic"] != {"relation": None}:
        raise Refused("Alembic state already exists")
    schema_names = [row.get("nspname") for row in observed["schemas"]]
    if not all(isinstance(name, str) for name in schema_names):
        raise Refused("Malformed schema evidence")
    if sorted(schema_names) != sorted(["public", "pg_catalog", "information_schema", "pg_toast"]):
        raise Refused("Unexpected schema")
    extensions = observed["extensions"]
    if len(extensions) != 1 or any(
        extensions[0].get(k) != v
        for k, v in {"extname": "plpgsql", "extversion": "1.0", "schema": "pg_catalog"}.items()
    ):
        raise Refused("Unexpected extension")
    expected_metadata = plan.get("fresh_metadata")
    metadata_keys = set(QUERIES) - set(EMPTY) - {"identity", "alembic"}
    if not isinstance(expected_metadata, dict) or set(expected_metadata) != metadata_keys:
        raise Refused("Reviewed role/security metadata missing")
    if any(observed[k] != expected_metadata[k] for k in metadata_keys):
        raise Refused("Role, privilege, ownership, settings or security drift")
    if plan.get("effective_authentication_independently_reviewed") is not True:
        raise Refused("Effective authentication not established by HBA file view")
    return {"catalog_fresh": True, "hba_scope": "current_file_parse_only", "live_accepted": False}
