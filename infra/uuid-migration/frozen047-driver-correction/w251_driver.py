"""Narrow versioned integration; no runtime providers or import side effects."""

from __future__ import annotations


def compatible_kernel(parent):
    """Return a separate class namespace. Never mutate historical kernel globals."""
    from types import SimpleNamespace

    class Driver(parent.Driver):
        @property
        def broken(self):
            # psycopg BaseConnection.broken is a Boolean local status getter.
            # Do NOT expose pgconn, connection unwrapping or a callable here.
            result = self.raw.broken
            parent.require(type(result) is bool, "Invalid broken-connection metadata")
            return result

    return SimpleNamespace(Driver=Driver, Cursor=parent.Cursor, Session=parent.Session, status=parent.status)


def compatible_dialect(parent_factory, policy):
    """Bound values remain bound; known parameterless SQL omits an empty mapping.

    Both paths still call the original owned metered Cursor.execute exactly once.
    No SQL changes, escaping heuristics, native execute or hidden transaction.
    """

    def factory(base, text, type_info):
        parent = parent_factory(base, text, type_info)

        class Dialect(parent):
            supports_statement_cache = True

            def do_execute(self, cursor, statement, parameters, context=None):
                bound = policy.validate(statement, parameters)
                if bound:
                    return super().do_execute(cursor, statement, parameters, context)
                return super().do_execute_no_params(cursor, statement, context)

            def do_execute_no_params(self, cursor, statement, context=None):
                policy.validate(statement, None)
                return super().do_execute_no_params(cursor, statement, context)

            def do_executemany(self, cursor, statement, parameters, context=None):
                raise ValueError("Frozen047 does not authorize driver batches")

        return Dialect

    return factory
