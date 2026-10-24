"""Dedicated proposed psycopg dialect subtype, no mutation of library sources.

TypeInfo.fetch() opens a native nested transaction/cursor outside our proxy and
requires a native Connection instance. Preserve its PG16 hstore lookup semantics
through the owned, metered SQLAlchemy connection instead. Never unwrap driver,
disable hstore, add SAVEPOINT budgets, or suppress a type-discovery failure.
"""

from __future__ import annotations

from kernel import require

TYPE_SQL = """SELECT typname AS name, oid, typarray AS array_oid,
oid::regtype::text AS regtype, typdelim AS delimiter
FROM pg_type t WHERE t.oid = pg_catalog.to_regtype(:name) ORDER BY t.oid"""


def factory(base, text, type_info):
    class OwnedDialect(base):
        supports_statement_cache = True

        def _type_info_fetch(self, connection, name):
            require(name == "hstore" and connection.in_transaction(), "Unreviewed native type lookup")
            rows = [dict(r) for r in connection.execute(text(TYPE_SQL), {"name": name}).mappings().all()]
            require(len(rows) <= 1, "Ambiguous hstore type")
            if not rows:
                return None
            row = rows[0]
            require(set(row) == {"name", "oid", "array_oid", "regtype", "delimiter"}, "Type shape drift")
            require(
                row["name"] == "hstore"
                and type(row["oid"]) is int
                and row["oid"] > 0
                and type(row["array_oid"]) is int
                and row["array_oid"] >= 0
                and isinstance(row["regtype"], str)
                and isinstance(row["delimiter"], str),
                "Unreviewed type identity",
            )
            return type_info(**row)

    return OwnedDialect
