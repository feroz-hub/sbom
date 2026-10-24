"""New isolated Operations binding recipe. W2.3 mock-only functions unchanged."""

from __future__ import annotations

import ast
import builtins
from types import SimpleNamespace

from security import require


def operations(connection, *, context_factory, operations_factory, opts):
    require(
        connection.dialect.name == "postgresql" and connection.dialect.default_schema_name == "public",
        "Dedicated PostgreSQL/public dialect required",
    )
    require(set(opts) <= {"w22_f_finalization"}, "Unreviewed Alembic context options")
    context = context_factory.configure(
        connection=connection,
        opts={
            "as_sql": False,
            "transactional_ddl": True,
            "version_table": "alembic_version",
            "version_table_schema": "public",
            **opts,
        },
    )
    require(
        context.as_sql is False and context.impl.transactional_ddl is True, "DDL context is not owned/transactional"
    )
    op = operations_factory(context)
    require(op.get_bind() is connection and op.get_context() is context, "Operations escaped owned connection")
    return context, op


def bind(authority, operations, context):
    ua = authority.unit_authority
    source = authority.modules["isolated_loader"].binding_source(authority.root, authority.registry, ua.unit)
    tree = ast.parse(source)
    for node in tree.body:
        require(
            isinstance(node, (ast.Expr, ast.Assign, ast.Import, ast.ImportFrom, ast.FunctionDef)),
            "Unreviewed module startup",
        )
        if isinstance(node, ast.Expr):
            require(
                isinstance(node.value, ast.Constant) and isinstance(node.value.value, str),
                "Executable module expression",
            )
        if isinstance(node, ast.Assign):
            require(
                all(
                    ast.unparse(c.func) in {"sa.Integer", "sa.String", "sa.Text", "sa.DateTime", "frozenset"}
                    for c in ast.walk(node)
                    if isinstance(c, ast.Call)
                ),
                "Unreviewed top-level constructor",
            )
    facade = SimpleNamespace(op=operations, context=SimpleNamespace(is_offline_mode=lambda: context.as_sql))
    allowed = {
        "__future__",
        "datetime",
        "collections",
        "warnings",
        "hashlib",
        "json",
        "re",
        "pathlib",
        "sqlalchemy",
        "sqlalchemy.dialects",
        "sqlalchemy.dialects.postgresql",
    }

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        require(level == 0, "Relative migration import")
        if name == "alembic":
            require(set(fromlist) <= {"op", "context"}, "Global Alembic import")
            return facade
        require(name in allowed, "Application/runtime import")
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = {
        "__name__": "_w24a_isolated_unit",
        "__file__": str(authority.root / ua.unit["source"]),
        "__builtins__": {**vars(builtins), "__import__": imports},
    }
    exec(compile(source, namespace["__file__"], "exec"), namespace)
    require(
        namespace["revision"] == ua.unit["next"] and namespace["down_revision"] == ua.unit["previous"],
        "Wrong isolated body",
    )
    return namespace["upgrade"]
