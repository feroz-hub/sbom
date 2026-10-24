"""Offline source/graph/SQL checks only. Does not call a runner or connect.

Run with python -B. No Docker, application, Alembic env or migration imports.
This is not a PostgreSQL parser, fixture suite or acceptance test.
"""

import ast
import hashlib
import json
from pathlib import Path

import backfill_public_ids as backfill
import create_unique_indexes as indexes
import uuid_w1_common as common
from alembic.script.revision import Revision, RevisionMap
from sqlalchemy import Column, Index, MetaData, Table
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex


def declarations(path):
    tree = ast.parse(path.read_text())
    return {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in ("revision", "down_revision", "branch_labels", "depends_on")
    }


def main():
    here = Path(__file__).parent
    root = common.ROOT
    sources = {p.name: p.read_text() for p in here.glob("*.py")}
    for source in sources.values():
        ast.parse(source)
        assert not any(line.rstrip() != line for line in source.splitlines())
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                assert "app." not in ast.unparse(node) and "dotenv" not in ast.unparse(node)

    active = [declarations(p) for p in sorted((root / "alembic/versions").glob("*.py"))]
    active = [c for c in active if "revision" in c]
    staged_paths = sorted((root / "infra/uuid-migration/staged-alembic").glob("*.py"))
    staged = [declarations(p) for p in staged_paths]
    assert len(active) == 79 and len(staged) == 6
    assert len({c["revision"] for c in active + staged}) == 85

    def graph(items):
        return RevisionMap(
            lambda: iter(
                Revision(
                    c["revision"],
                    c["down_revision"],
                    dependencies=c.get("depends_on"),
                    branch_labels=c.get("branch_labels"),
                )
                for c in items
            )
        )

    assert graph(active).heads == ("079_lifecycle_provider_verification",)
    combined = graph(active + staged)
    assert combined.heads == (common.REVISION,)
    chain = list(combined.iterate_revisions(common.REVISION, "079_lifecycle_provider_verification"))
    assert [r.revision for r in chain] == [c["revision"] for c in reversed(staged)]

    first = ast.parse(staged_paths[0].read_text())
    constants = {n.targets[0].id: ast.literal_eval(n.value) for n in first.body if isinstance(n, ast.Assign)}
    guard_body = constants["_GUARD_FUNCTION_SQL"].split("$uuid_public_identity_guard$")[1]
    assert hashlib.sha256(guard_body.encode()).hexdigest() == common.GUARD_BODY_SHA256
    report = (root / "docs/uuid-migration/phase2/10-w1-expand-transaction-refactor.md").read_text()
    for path, table in zip(staged_paths, common.TABLES, strict=True):
        source = path.read_text()
        assert hashlib.sha256(path.read_bytes()).hexdigest() in report
        table_constants = {
            n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(source).body if isinstance(n, ast.Assign)
        }
        assert table_constants["_TABLE"] == table
        if table != "tenants":
            # Compare only the target declaration: global replacement would also
            # corrupt the function's six-table allowlist and give a false failure.
            assert table_constants["_PREFLIGHT_SQL"].split("$uuid_expected_guard$")[1] == guard_body

    sql_fragments = list(common.CATALOG_SQL.values()) + [
        common.IDENTITY_SQL,
        common.TABLE_SQL,
        common.TRIGGERS_SQL,
        common.INDEX_SQL,
        common.GUARD_SQL,
    ]
    for table in common.TABLES:
        ddl = common.index_ddl(table)
        assert "CREATE UNIQUE INDEX CONCURRENTLY" in ddl and f'ON "public"."{table}" USING btree ("public_id")' in ddl
        assert all(token not in ddl for token in ("WHERE", "IF NOT EXISTS", "NULLS NOT DISTINCT", "INCLUDE"))
        metadata = MetaData()
        model = Table(table, metadata, Column("public_id", postgresql.UUID()), schema="public")
        idx = Index(
            common.index_name(table),
            model.c.public_id,
            unique=True,
            postgresql_concurrently=True,
            postgresql_using="btree",
        )
        sqlalchemy_ddl = str(CreateIndex(idx).compile(dialect=postgresql.dialect()))
        assert "CREATE UNIQUE INDEX CONCURRENTLY" in sqlalchemy_ddl and " USING btree (public_id)" in sqlalchemy_ddl
        sql = backfill.batch_sql(table)
        assert set(common.compiled(sql)[1]) == {"cursor", "high", "batch"}
        assert "ORDER BY id LIMIT :batch FOR UPDATE" in sql and "SKIP LOCKED" not in sql
        assert "WHERE public_id IS NULL AND id > :cursor AND id <= :high" in sql
        assert "AND target.public_id IS NULL" in sql
        assert sql.count(" SET ") == 1 and "SET public_id = pg_catalog.gen_random_uuid()" in sql
        assert "RETURNING target.id" in sql and "RETURNING target.public_id" not in sql
        sql_fragments.extend((ddl, sql, indexes.duplicates_sql(table), backfill.gap_sql(table)))
    for sql in sql_fragments:
        statement, keys = common.compiled(sql)
        assert statement and isinstance(keys, tuple)
    # Compile literal SQL query arguments too (catalog gates and session settings).
    literal_count = 0
    dynamic_count = 0

    def rendered(node, table):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name) and node.id == "table":
            return table
        if isinstance(node, ast.JoinedStr):
            return "".join(
                str(rendered(part.value, table)) if isinstance(part, ast.FormattedValue) else part.value
                for part in node.values
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "qualified":
            return common.qualified(table)
        raise AssertionError("Review new dynamic SQL expression before extending offline renderer")

    for source in sources.values():
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "query":
                if (
                    len(node.args) > 1
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                ):
                    common.compiled(node.args[1].value)
                    literal_count += 1
                elif len(node.args) > 1 and isinstance(node.args[1], ast.JoinedStr):
                    for table in common.TABLES:
                        common.compiled(rendered(node.args[1], table))
                        dynamic_count += 1

    safety = sources["uuid_w1_common.py"]
    assert 'host="127.0.0.1"' in safety and "port=56041" in safety and 'passfile="/dev/null"' in safety
    assert 'plan["approvals"].get(key)' in safety and 'choices=("validate", "execute")' in safety
    assert "O_NOFOLLOW" in safety and "O_EXCL" in safety and "default_transaction_read_only=on" in safety
    assert "conn.transaction()" in safety and "statement_timeout" in safety and "_BATCH_DEADLINE" in safety
    assert "Existing valid index requires explicit reviewed OID" in safety and "indnullsnotdistinct" in safety
    assert "has_table_privilege" in safety and "pg_get_triggerdef" in safety
    assert any(
        isinstance(n, ast.IfExp)
        and ast.unparse(n.body) == "str(error)"
        and ast.unparse(n.test) == "isinstance(error, SafetyStop)"
        for n in ast.walk(ast.parse(safety))
    )
    assert "verify_all(conn, plan, require_all=True)" in sources["backfill_public_ids.py"]
    assert "conn.autocommit" in sources["create_unique_indexes.py"]
    assert "conn.read_only = False" in sources["backfill_public_ids.py"]
    for name in ("create_unique_indexes.py", "backfill_public_ids.py"):
        assert 'if __name__ == "__main__":' in sources[name]
        assert not any(
            token in sources[name]
            for token in ("DROP INDEX", "CASCADE", "DISABLE TRIGGER", "session_replication_role =", "stamp(")
        )
    example = json.loads((here / "d-approval.example.json").read_text())
    assert example["accepted"] is False and all(v is None for v in example["approvals"].values())
    assert example["accepted_index_oids"] == {} and example["index_statement_ms"] is None
    print(
        json.dumps(
            {
                "result": "PASS",
                "python_files": len(sources),
                "active_revisions": len(active),
                "staged_revisions": len(staged),
                "combined_head": combined.heads,
                "sql_templates_compiled": len(sql_fragments),
                "literal_query_compilations": literal_count,
                "dynamic_query_compilations": dynamic_count,
                "sqlalchemy_concurrent_index_ddl_compilations": 6,
                "database_execution": "NOT RUN",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
