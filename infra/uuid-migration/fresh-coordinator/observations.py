"""Raw-observation validation. No self-asserted accepted receipt is sufficient.

Only mocked observers are wired in W2.3. A later activation must implement and
review actual catalog/resource/secret observation; these functions perform none.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from authority import TARGET
from source_registry import digest, read_pinned, reference_api, require

EXTRA_SQL = {
    "columns": "SELECT n.nspname,c.relname,a.attname,a.attnum,pg_catalog.format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull,a.attidentity::text,a.attgenerated::text,a.attacl::text,pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS expression FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum",
    "constraints": "SELECT c.relname,k.conname,k.contype::text,k.convalidated,k.condeferrable,k.condeferred,pg_catalog.pg_get_constraintdef(k.oid) AS definition FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=k.connamespace WHERE n.nspname='public' ORDER BY c.relname,k.conname",
    "indexes": "SELECT c.relname,t.relname AS table_name,pg_catalog.pg_get_indexdef(i.indexrelid) AS definition,i.indisvalid,i.indisready,i.indislive FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY t.relname,c.relname",
    "sequences": "SELECT c.relname,pg_catalog.format_type(s.seqtypid,NULL) AS type,s.seqstart,s.seqincrement,s.seqmax,s.seqmin,s.seqcache,s.seqcycle FROM pg_catalog.pg_sequence s JOIN pg_catalog.pg_class c ON c.oid=s.seqrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname",
    "function_definitions": "SELECT p.proname,pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments,pg_catalog.pg_get_functiondef(p.oid) AS definition,pg_catalog.pg_get_userbyid(p.proowner) AS owner,p.proacl::text,p.proconfig FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind IN ('f','p') ORDER BY p.proname,arguments",
    "trigger_definitions": "SELECT c.relname,t.tgname,t.tgenabled::text,pg_catalog.pg_get_triggerdef(t.oid) AS definition FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname",
    "owners_acl": "SELECT n.nspname,c.relname,pg_catalog.pg_get_userbyid(c.relowner) AS owner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname",
}
SECURITY_KEYS = ("roles", "memberships", "schemas", "extensions", "default_acl", "settings", "role_settings")
TOKEN = object()
REFERENCE_SQL = {
    "roles": "SELECT code,scope,status,is_system,is_assignable,version FROM public.authorization_roles ORDER BY code",
    "permissions": "SELECT code,scope,status,is_system FROM public.authorization_permissions ORDER BY code",
    "mappings": "SELECT r.code AS role,p.code AS permission,m.is_protected FROM public.authorization_role_permissions m JOIN public.authorization_roles r ON r.id=m.role_id JOIN public.authorization_permissions p ON p.id=m.permission_id ORDER BY r.code,p.code",
    "audit_actions": "SELECT DISTINCT action FROM public.authorization_audit_log ORDER BY action",
}


def reference_requirements(root, registry, state):
    number = int(state[:3]) if state is not None else 0
    if number < 48:
        return None
    legacy = reference_api(root, registry)["fresh_bootstrap"]
    contract = legacy.reference_contract(root, registry["lock"]["sources"])
    rel = "app/authorization_catalog_seed_v1.py"
    seed = legacy.seed_constants(ast.parse(read_pinned(root, rel, registry["lock"]["sources"][rel])))
    return {
        "number": number,
        "scopes": contract["after048"]["roles"],
        "base_permissions": contract["after048"]["permissions"],
        "mappings": contract["after079"]["role_permissions"]
        if number >= 79
        else contract["after048"]["role_permissions"]
        if number < 64
        else None,
        "versions": contract["after079"]["role_versions"] if number >= 79 else None,
        "protected": seed["PROTECTED_ROLE_PERMISSIONS_V1"],
    }


def verify_references(root, registry, state, rows):
    expected = reference_requirements(root, registry, state)
    if expected is None:
        require(all(value == [] for value in rows.values()), "Reference rows before048")
        return
    roles = {r["code"]: r for r in rows["roles"]}
    require(
        len(roles) == len(rows["roles"]) and set(roles) == set(expected["scopes"]),
        "Required system-role catalog missing/duplicated",
    )
    for code, row in roles.items():
        require(
            row["scope"] == expected["scopes"][code]
            and row["status"] == "ACTIVE"
            and row["is_system"] is True
            and row["is_assignable"] is True,
            "System-role scope/security mismatch",
        )
        if expected["versions"] is not None:
            require(row["version"] == expected["versions"][code], "Authorization role version mismatch")
    permissions = {r["code"]: r for r in rows["permissions"]}
    require(
        len(permissions) == len(rows["permissions"]) and set(expected["base_permissions"]) <= set(permissions),
        "Required permission catalog missing",
    )
    require(
        all(row["status"] == "ACTIVE" and row["is_system"] is True for row in permissions.values()),
        "Permission status/system mismatch",
    )
    pairs = {(r["role"], r["permission"]) for r in rows["mappings"]}
    require(
        len(pairs) == len(rows["mappings"]) and all(r in roles and p in permissions for r, p in pairs),
        "Permission mapping dependency mismatch",
    )
    if expected["mappings"] is not None:
        require(
            pairs == {(r, p) for r, perms in expected["mappings"].items() for p in perms},
            "Frozen role-permission contract mismatch",
        )
    for row in rows["mappings"]:
        protected = (row["role"] == "PLATFORM_ADMIN" and expected["number"] >= 64) or row["permission"] in expected[
            "protected"
        ].get(row["role"], ())
        require(row["is_protected"] is protected, "Protected grant changed")
    require(rows["audit_actions"] == ["AUTHORIZATION_CATALOG_SEEDED"], "Required seed audit evidence missing")


def catalog_queries(root, registry):
    queries = reference_api(root, registry)["fresh_catalog"].QUERIES
    return {**{k: v for k, v in queries.items() if k not in {"identity", "clients", "locks", "alembic"}}, **EXTRA_SQL}


def verify_resources(plan, raw):
    require(
        isinstance(raw, dict)
        and set(raw)
        == {
            "pins",
            "labels",
            "networks",
            "volume",
            "exclusive_volume_users",
            "publication",
            "mount",
            "credential",
            "correlation",
        },
        "Incomplete independently observed resources",
    )
    r = plan["resources"]
    credential = plan["credential_metadata"]
    require(
        raw["pins"] == r
        and raw["labels"] == {"project": TARGET["project"], "service": TARGET["service"]}
        and raw["networks"] == [{"name": TARGET["network"], "id": r["network_id"]}]
        and raw["volume"]
        == {"name": TARGET["volume"], "identity": r["volume_identity"], "destination": "/var/lib/postgresql/data"}
        and raw["exclusive_volume_users"] == [r["container_id"]]
        and raw["publication"] == [{"host_ip": "127.0.0.1", "host_port": 56043, "container_port": 5432}],
        "F resource/publication/storage drift",
    )
    require(
        raw["credential"] == {"regular": True, "symlink": False, "metadata": credential},
        "Credential stat/provenance drift",
    )
    mount = raw["mount"]
    require(
        isinstance(mount, dict)
        and set(mount) == {"type", "source", "destination", "rw"}
        and mount["type"] == "bind"
        and mount["source"] in (credential["path"], "/host_mnt" + credential["path"])
        and mount["destination"] == "/run/secrets/f_password"
        and mount["rw"] is False,
        "Secret mount mismatch",
    )
    require(
        raw["correlation"]
        == {
            "performed": True,
            "equal": True,
            "container_id": r["container_id"],
            "source": credential["path"],
            "destination": "/run/secrets/f_password",
        },
        "Independent secret-byte correlation required",
    )
    return digest(raw)


@dataclass(frozen=True)
class Verified:
    """Internal derivation, not independently sufficient execution authority."""

    token: object
    prefix: str
    finalization: str | None
    security: str
    references: str
    identity: dict
    table_names: tuple[str, ...]


def verify_database(root, registry, plan, unit, observed, *, readonly, after=False):
    require(
        isinstance(observed, dict)
        and set(observed)
        == {
            "identity",
            "catalog",
            "references",
            "business",
            "clients",
            "locks",
            "marker",
            "fresh_catalog",
            "finalization_catalog",
        },
        "Incomplete catalog observation",
    )
    expected = {
        **plan["identity"],
        "database": TARGET["database"],
        "user": TARGET["user"],
        "session_user": TARGET["user"],
        "version": 160015,
        "port": 5432,
        "data_directory": "/var/lib/postgresql/data",
        "read_only": "on" if readonly else "off",
        "recovery": False,
        "replication": "origin",
        "row_security": "on",
        "search_path": "pg_catalog",
    }
    require(observed["identity"] == expected, "Actual PostgreSQL F identity/security mismatch")
    require(observed["clients"] == [] and observed["locks"] == [], "Competing writer/client/lock")
    expected_marker = [unit["next"]] if after else [] if unit["previous"] is None else [unit["previous"]]
    require(observed["marker"] == expected_marker, "Wrong sole revision marker")
    catalog = observed["catalog"]
    require(
        isinstance(catalog, dict) and set(catalog) == set(catalog_queries(root, registry)),
        "Incomplete full catalog/source format",
    )
    require(
        digest(catalog) == plan["post_sha256" if after else "prefix_sha256"],
        "Catalog prefix/delta not independently approved",
    )
    require(
        catalog["event_triggers"] == []
        and catalog["foreign_objects"] == []
        and catalog["replication"] == []
        and catalog["role_settings"] == []
        and all(row.get("config_null") is True for row in catalog["roles"]),
        "Unapproved trigger/foreign/replication/role configuration",
    )
    security = digest({k: catalog[k] for k in SECURITY_KEYS})
    # Historical units legitimately change reference/ACL rows; expected full post
    # catalog is independently approved. Preflight security and references are
    # separately pinned; post equality is checked through the full post catalog.
    if not after:
        require(
            security == plan["security_sha256"] and digest(observed["references"]) == plan["reference_sha256"],
            "Role/ACL/reference drift",
        )
    else:
        require(
            digest(observed["references"]) == plan["post_reference_sha256"],
            "Post-unit reference initialization mismatch",
        )
    require(isinstance(observed["business"], list), "Missing business freshness observations")
    seen = set()
    for row in observed["business"]:
        require(
            set(row) == {"schema", "table", "has_rows", "rls"}
            and row["schema"] == "public"
            and isinstance(row["table"], str)
            and row["table"] not in seen
            and row["rls"] is False
            and row["has_rows"] is False,
            "Unauthorized populated/RLS business database",
        )
        seen.add(row["table"])
    ordinary = {
        row["relname"] for row in catalog["relations"] if row.get("nspname") == "public" and row.get("relkind") == "r"
    }
    references = {
        "alembic_version",
        "authorization_roles",
        "authorization_permissions",
        "authorization_role_permissions",
        "authorization_audit_log",
    }
    require(seen == ordinary - references, "Missing ordinary-business emptiness observation")
    require(
        isinstance(observed["references"], dict)
        and set(observed["references"]) == {"roles", "permissions", "mappings", "audit_actions"},
        "Reference scope incomplete",
    )
    require(
        all(action == "AUTHORIZATION_CATALOG_SEEDED" for action in observed["references"]["audit_actions"]),
        "Business/security audit data present",
    )
    verify_references(root, registry, unit["next"] if after else unit["previous"], observed["references"])
    finalization = None
    if unit["kind"] == "uuid_finalize" and not after:
        final = observed["finalization_catalog"]
        # Exact W2.2 snapshot categories, not this separate W2.3 catalog format.
        require(
            isinstance(final, dict)
            and set(final)
            == {
                "relations",
                "columns",
                "constraints",
                "indexes",
                "functions",
                "triggers",
                "roles",
                "memberships",
                "extensions",
                "schemas",
                "default_acl",
                "database",
                "sequences",
                "rules",
                "reference_roles",
                "reference_permissions",
                "reference_mappings",
            },
            "Wrong W2.2 catalog format",
        )
        finalization = digest(final)
        require(finalization == plan["finalization_catalog_sha256"], "Finalization prefix fingerprint changed")
    if unit["kind"] == "frozen_047" and not after:
        fresh = observed["fresh_catalog"]
        # The unchanged W2.1 validator checks read-only initial observations.
        # A locked write recheck must match that full catalog, with the actual
        # transaction mode checked above rather than falsely reporting READ ONLY.
        require(isinstance(fresh, dict), "Complete fresh catalog missing")
        fresh = {**fresh, "identity": {**fresh["identity"], "transaction_read_only": "on"}}
        reference_api(root, registry)["fresh_catalog"].validate_fresh(
            fresh,
            {
                "identity": plan["identity"],
                "fresh_metadata": plan["fresh_metadata"],
                "effective_authentication_independently_reviewed": True,
            },
        )
        require(plan["review_references"]["security"], "Independent effective-authentication policy review required")
    return Verified(
        TOKEN,
        digest(catalog),
        finalization,
        security,
        digest(observed["references"]),
        dict(observed["identity"]),
        tuple(sorted(ordinary)),
    )


def finalization_context(authority, verified):
    p, u = authority.plan, authority.unit
    require(
        isinstance(verified, Verified)
        and verified.token is TOKEN
        and u["kind"] == "uuid_finalize"
        and verified.prefix == p["prefix_sha256"]
        and verified.finalization == p["finalization_catalog_sha256"],
        "No context from manifest/self-asserted receipt alone",
    )
    return {
        "target": "F",
        "host": "127.0.0.1",
        "port": 56043,
        "database": TARGET["database"],
        "user": TARGET["user"],
        **p["identity"],
        "current_revision": u["previous"],
        "next_revision": u["next"],
        "manifest_sha256": authority.approved_hash,
        "source_sha256": u["source_sha256"],
        "catalog_sha256": verified.finalization,
        "expires_at": p["expires_at"],
        "approval_reference": authority.args[3],
        "resource_review_reference": p["review_references"]["target"],
        "credential_review_reference": p["review_references"]["credentials"],
        "security_review_reference": p["review_references"]["security"],
        "writers_stopped": True,
        "fresh_install_accepted": True,
        "coordinator_reviewed": True,
    }
