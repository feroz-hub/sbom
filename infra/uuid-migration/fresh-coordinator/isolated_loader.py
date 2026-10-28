"""Pinned individual-revision binding; only mocked Operations can run here.

No ScriptDirectory, env.py, historical001, app package or engine initialization.
Future activation must separately wire an instrumented real Operations adapter.
"""

from __future__ import annotations

import ast
import builtins
from pathlib import Path
from types import SimpleNamespace

from source_registry import next_unit, read_pinned, reference_api, require, sha


def mock_only(value):
    from unittest.mock import Mock

    require(isinstance(value, Mock), "W2.3 permits only offline mock adapters; live activation absent")


def configure_mock_operations(connection, options, migration_context_factory, operations_factory):
    """Exact isolated Alembic factory recipe, with both factories intercepted.

    A source-specific activation must replace the mock factories with reviewed
    MigrationContext/Operations and attach the statement meter before use. It
    must never call run_migrations(), env.py or install a global op proxy.
    """
    for value in (connection, migration_context_factory, operations_factory):
        mock_only(value)
    allowed = {"as_sql", "transactional_ddl", "version_table", "version_table_schema", "w22_f_finalization"}
    require(
        set(options) <= allowed
        and options.get("as_sql") is False
        and options.get("transactional_ddl") is True
        and options.get("version_table") == "alembic_version"
        and options.get("version_table_schema") == "public",
        "Unsafe Alembic binding options",
    )
    context = migration_context_factory.configure(connection=connection, opts=dict(options))
    operations = operations_factory(context)
    mock_only(operations)
    return context, operations


def frozen_statements(root, registry):
    refs = reference_api(root, registry)
    pins = registry["lock"]["sources"]
    original = read_pinned(
        root, "scripts/schema/postgresql_047_baseline.sql", pins["scripts/schema/postgresql_047_baseline.sql"]
    )
    proposal = refs["frozen_047"].representation(original)
    raw = read_pinned(
        root, "infra/uuid-migration/fresh-bootstrap/047-execution.proposed.sql", proposal["execution_sha256"]
    )
    result = tuple(s.sql for s in refs["pg_lex"].statements(raw.decode()))
    require(len(result) == 558, "Frozen047 representation/order changed")
    return result


def binding_source(root, registry, unit):
    selected = next_unit(registry, unit["previous"], unit["next"])
    require(selected == unit, "Substituted installation unit")
    require(
        48 <= int(unit["next"][:3]) <= 91 and unit["kind"] != "frozen_047", "Only individual048–091 bodies eligible"
    )
    original = read_pinned(root, unit["source"], unit["source_sha256"]).decode()
    alternatives = registry["lock"]["seed_alternatives"]
    if unit["next"] not in alternatives:
        return original
    reviewed = alternatives[unit["next"]]
    require(sha(reviewed["source"].encode()) == reviewed["sha256"], "Frozen seed alternative changed")
    recipe = reference_api(root, registry)["fresh_bootstrap"].isolated_dependencies(root, registry["graph"])
    require(
        recipe["source_representations"][unit["next"]]["source"] == reviewed["source"],
        "Reviewed seed substitution mismatch",
    )
    old = ast.parse(original)
    new = ast.parse(reviewed["source"])

    # Every function body remains identical; only reviewed seed import bindings
    # change. Formatting differences are explicit source alternatives, not edits.
    def funcs(tree):
        return [ast.dump(n) for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    require(funcs(old) == funcs(new), "Historical function body was changed")
    return reviewed["source"]


def bind_mock(root, registry, unit, operations, context):
    mock_only(operations)
    source = binding_source(root, registry, unit)
    tree = ast.parse(source)
    # Pinned modules have no top-level startup; fail on newly introduced module
    # calls except reviewed SQLAlchemy type and frozen-container constructors.
    for node in tree.body:
        require(
            isinstance(node, (ast.Expr, ast.Assign, ast.Import, ast.ImportFrom, ast.FunctionDef)),
            "Unreviewed module initialization",
        )
        if isinstance(node, ast.Expr):
            require(
                isinstance(node.value, ast.Constant) and isinstance(node.value.value, str),
                "Executable module expression",
            )
        if isinstance(node, ast.Assign):
            require(
                all(
                    ast.unparse(call.func) in {"sa.Integer", "sa.String", "sa.Text", "sa.DateTime", "frozenset"}
                    for call in ast.walk(node)
                    if isinstance(call, ast.Call)
                ),
                "Unreviewed top-level constructor",
            )
    allowed = {"__future__", "datetime", "collections", "warnings", "hashlib", "json", "re", "pathlib"}
    alembic = SimpleNamespace(op=operations, context=SimpleNamespace(is_offline_mode=lambda: context.as_sql))

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        require(level == 0, "Relative migration import refused")
        if name == "alembic":
            require(set(fromlist) <= {"op", "context"}, "Unreviewed Alembic import")
            return alembic
        require(
            name in allowed or name in {"sqlalchemy", "sqlalchemy.dialects", "sqlalchemy.dialects.postgresql"},
            "Application/runtime import refused",
        )
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = {
        "__name__": "_w23_isolated_revision",
        "__file__": str(Path(root) / unit["source"]),
        "__builtins__": {**vars(builtins), "__import__": imports},
    }
    exec(compile(source, namespace["__file__"], "exec"), namespace)
    require(
        namespace["revision"] == unit["next"] and namespace["down_revision"] == unit["previous"],
        "Binding declaration mismatch",
    )
    return SimpleNamespace(upgrade=namespace["upgrade"], namespace=namespace, source=source)
