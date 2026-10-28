"""Synthetic E-only fixtures derived from the accepted D085 catalog, not ORM defaults.

Import is inert. Explicit negative PKs avoid advancing sequences. No cleanup SQL.
The caller must pass an authorized E session and reserve a unique slot per fixture.
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from psycopg import sql

TABLES = ("tenants", "projects", "products", "logical_sbom", "sbom_source", "sbom_component")
STAMP = datetime(2026, 1, 1, tzinfo=UTC)
BASE_ID = -1700000000
MAX_SLOT = 20000
PARENTS = {
    "tenants": (),
    "projects": ("tenants",),
    "products": ("tenants", "projects"),
    "logical_sbom": ("tenants", "products"),
    "sbom_source": ("tenants", "projects", "products", "logical_sbom"),
    "sbom_component": ("tenants", "sbom_source"),
}
NAME_COLUMN = {
    "tenants": "name",
    "projects": "project_name",
    "products": "name",
    "logical_sbom": "name",
    "sbom_source": "description",
    "sbom_component": "description",
}
# Real NOT NULL columns without database defaults (D catalog, report25).
REQUIRED = {
    "tenants": {"name", "slug", "status", "created_at", "updated_at"},
    "projects": {"tenant_id", "project_name", "project_status"},
    "products": {"created_at", "project_id", "tenant_id", "name", "normalized_name", "slug"},
    "logical_sbom": {"tenant_id", "name", "created_at", "updated_at"},
    "sbom_source": {"sbom_name", "tenant_id", "logical_sbom_id"},
    "sbom_component": {
        "sbom_id",
        "lifecycle_is_stale",
        "lifecycle_manual_override",
        "is_duplicate",
        "name",
        "tenant_id",
    },
}


def identity(table, slot):
    if table not in TABLES or type(slot) is not int or not 1 <= slot <= MAX_SLOT:
        raise ValueError("Unapproved fixture table/slot")
    return BASE_ID + slot * 16 + TABLES.index(table)


def verify_contract():
    """Compare builders with independently captured real catalog metadata offline."""
    metadata = json.loads(Path(__file__).with_name("uuid_integrity_fixture_catalog.json").read_text())
    if metadata["source_revision"] != "085_uuid_sbom_component_expand":
        raise ValueError("Fixture schema provenance changed")
    for table in TABLES:
        data = values(table, 1)
        columns = {x["name"]: x for x in metadata["tables"][table]["columns"]}
        required = {n for n, x in columns.items() if x["not_null"] and x["default"] is None}
        if required != REQUIRED[table] or not required <= data.keys() or not data.keys() <= columns.keys():
            raise ValueError("Builder/catalog required-column mismatch")
        if columns["public_id"] != {
            "name": "public_id",
            "type": "uuid",
            "not_null": False,
            "default": "gen_random_uuid()",
        }:
            raise ValueError("Unexpected UUID fixture contract")
        for constraint in metadata["tables"][table]["constraints"]:
            if constraint["kind"] != "f":
                continue
            match = re.match(r"FOREIGN KEY \(([^)]+)\) REFERENCES public\.(\w+)\(([^)]+)\)", constraint["definition"])
            if not match:
                raise ValueError("Unreviewed FK syntax")
            child, parent, referenced = match.groups()
            child_keys, parent_keys = child.split(", "), referenced.split(", ")
            if all(k in data for k in child_keys):
                if parent not in TABLES or TABLES.index(parent) >= TABLES.index(table):
                    raise ValueError("Unbuilt required FK dependency")
                if tuple(data[k] for k in child_keys) != tuple(values(parent, 1)[k] for k in parent_keys):
                    raise ValueError("Fixture composite/integer FK mismatch")
    return metadata


def values(table, slot):
    """Deterministic labelled values; each slot is its own tenant hierarchy."""
    ids = {t: identity(t, slot) for t in TABLES}
    label = f"synthetic-w17-{slot}"
    common = {"id": ids[table]}
    data = {
        "tenants": dict(name=label, slug=label, status="ACTIVE", created_at=STAMP, updated_at=STAMP),
        "projects": dict(tenant_id=ids["tenants"], project_name=label, project_status=1),
        "products": dict(
            tenant_id=ids["tenants"],
            project_id=ids["projects"],
            name=label,
            normalized_name=label,
            slug=label,
            created_at=STAMP.isoformat(),
        ),
        "logical_sbom": dict(
            tenant_id=ids["tenants"],
            product_id=ids["products"],
            name=label,
            created_at=STAMP.isoformat(),
            updated_at=STAMP.isoformat(),
        ),
        "sbom_source": dict(
            tenant_id=ids["tenants"],
            projectid=ids["projects"],
            product_id=ids["products"],
            logical_sbom_id=ids["logical_sbom"],
            sbom_name=label,
            sbom_version="1",
            description=label,
        ),
        "sbom_component": dict(
            tenant_id=ids["tenants"],
            sbom_id=ids["sbom_source"],
            name=label,
            lifecycle_is_stale=False,
            lifecycle_manual_override=False,
            is_duplicate=False,
            bom_ref=f"urn:synthetic:w17:{slot}",
            version="1.0",
            description=label,
        ),
    }[table]
    if not REQUIRED[table] <= data.keys():
        raise ValueError("Fixture misses required database fields")
    return {**common, **data}


def insert_statement(table, data):
    if table not in TABLES or not set(data) <= values(table, 1).keys() | {"public_id"}:
        raise ValueError("Unapproved insert identifiers")
    keys = sorted(data)
    statement = sql.SQL(
        "INSERT INTO public.{} ({}) VALUES ({}) RETURNING id,public_id,pg_typeof(public_id)::text"
    ).format(
        sql.Identifier(table),
        sql.SQL(",").join(map(sql.Identifier, keys)),
        sql.SQL(",").join(sql.Placeholder() for _ in keys),
    )
    return statement, tuple(data[k] for k in keys)


def insert_chain(conn, table, slot, reserve, public="omitted", supplied=None):
    """Insert only the required prefix, with all immediate/composite integer FKs."""
    if public not in ("omitted", "null", "supplied") or table not in TABLES:
        raise ValueError("Invalid fixture selection")
    result = None
    for current in TABLES[: TABLES.index(table) + 1]:
        data = values(current, slot)
        if current == table and public != "omitted":
            data["public_id"] = None if public == "null" else supplied
        reserve(current, data["id"])
        statement, args = insert_statement(current, data)
        result = conn.execute(statement, args).fetchone()
        if result[0] != data["id"] or type(result[0]) is not int:
            raise AssertionError("Integer fixture PK changed")
        # Read back real FK fields; FK constraints additionally enforce referenced tuples.
        fk = {
            k: v
            for k, v in data.items()
            if k in ("tenant_id", "project_id", "product_id", "projectid", "logical_sbom_id", "sbom_id")
        }
        if fk:
            names = sorted(fk)
            row = conn.execute(
                sql.SQL("SELECT {} FROM public.{} WHERE id=%s").format(
                    sql.SQL(",").join(map(sql.Identifier, names)), sql.Identifier(current)
                ),
                (data["id"],),
            ).fetchone()
            if row != tuple(fk[k] for k in names):
                raise AssertionError("Fixture integer relationship mismatch")
    return result


def read_identity(conn, table, row_id):
    if table not in TABLES:
        raise ValueError("Unapproved table")
    return conn.execute(
        sql.SQL("SELECT id,public_id,pg_typeof(public_id)::text FROM public.{} WHERE id=%s").format(
            sql.Identifier(table)
        ),
        (row_id,),
    ).fetchone()


def update(conn, table, row_id, column, value, null_only=False):
    if table not in TABLES or column not in ("public_id", NAME_COLUMN[table], "duplicate_of_component_id"):
        raise ValueError("Unapproved update identifiers")
    if column == "duplicate_of_component_id" and table != "sbom_component":
        raise ValueError("Self-reference applies only to components")
    return conn.execute(
        sql.SQL("UPDATE public.{} SET {}=%s WHERE id=%s{}").format(
            sql.Identifier(table), sql.Identifier(column), sql.SQL(" AND public_id IS NULL" if null_only else "")
        ),
        (value, row_id),
    )
