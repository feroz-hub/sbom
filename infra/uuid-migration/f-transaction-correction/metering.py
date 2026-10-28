"""Fail-closed SQL-family correction composed around the pinned W2.4B meter."""

from __future__ import annotations

from kernel import require

CONTROLS = {"BEGIN READ ONLY", "BEGIN READ WRITE", "COMMIT", "ROLLBACK"}
FAMILIES = {"CREATE", "ALTER", "DROP", "COMMENT", "INSERT", "UPDATE", "DELETE", "DO", "SET", "LOCK"}


def wrap(scoped_class):
    class StrictMeter(scoped_class):
        def classify(self, statement):
            require(isinstance(statement, str), "Text SQL required")
            control = statement.strip().rstrip(";").upper()
            if control in CONTROLS:
                return "transaction_controls"
            framed = self.parser(statement if statement.rstrip().endswith(";") else statement + ";")
            require(len(framed) == 1, "One driver statement required")
            first = framed[0].tokens[0].upper()
            if first in {"SELECT", "SHOW"}:
                return "catalog_queries"
            # WITH may contain data-modifying CTEs; EXPLAIN ANALYZE can execute
            # mutations; VALUES/TABLE/CALL/COPY/native protocols are not reviewed.
            require(first in FAMILIES, "Unreviewed SQL family (including WITH/VALUES/EXPLAIN)")
            require(self.category != "catalog_queries", "Nonquery in query scope")
            return self.category

        def driver(self, statement, parameters, many):
            self.classify(statement)  # fail BEFORE old scope can misclassify WITH
            return super().driver(statement, parameters, many)

    return StrictMeter
