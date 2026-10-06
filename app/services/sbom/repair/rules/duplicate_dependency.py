from app.validation import errors as E

from ..diff import pointer, proposal, unique_entries, value_at
from .base import RepairRule


class DuplicateDependencyRule(RepairRule):
    name = "duplicate_dependency"
    error_codes = {E.E025_SCHEMA_VIOLATION}

    def propose(self, document, error):
        path = pointer(error["path"])
        # Only arrays whose dependency semantics are known; never deduplicate
        # licenses, vulnerabilities or arbitrary user arrays.
        if path != "/dependencies" and not (path.startswith("/dependencies/") and path.endswith("/dependsOn")):
            return None
        try:
            old = value_at(document, path)
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        if not isinstance(old, list):
            return None
        new = unique_entries(old)
        if new == old:
            return None
        return proposal(
            error["code"],
            path,
            old,
            new,
            "duplicate_dependency",
            "Remove identical dependency entries while preserving first occurrence order and edges.",
        )
