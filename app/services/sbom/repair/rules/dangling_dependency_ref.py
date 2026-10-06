from app.validation import errors as E
from app.validation.normalize import iter_declared_bom_refs

from ..diff import pointer, proposal, value_at
from .base import RepairRule


class DanglingDependencyRefRule(RepairRule):
    name = "dangling_dependency_ref"
    error_codes = {E.E070_DEPENDENCY_REF_DANGLING}

    def matches(self, document, error):
        path = pointer(error["path"])
        if not path.startswith("/dependencies/"):
            return []
        try:
            missing = value_at(document, path)
        except (KeyError, IndexError, ValueError, TypeError):
            return []
        if not isinstance(missing, str):
            return []
        declarations = [
            (ref, value_at(document, pointer(loc).rsplit("/", 1)[0])) for ref, loc in iter_declared_bom_refs(document)
        ]
        # A duplicate registry is not a reliable identity source.
        refs = [r for r, _ in declarations]
        if len(refs) != len(set(refs)):
            return []
        tiers = [
            lambda r, c: missing == r,
            lambda r, c: missing == c.get("purl"),
            lambda r, c: missing == c.get("cpe"),
            lambda r, c: (
                isinstance(c.get("name"), str)
                and isinstance(c.get("version"), str)
                and missing == c["name"] + "@" + c["version"]
            ),
            lambda r, c: missing.strip() == r.strip(),
        ]
        for match in tiers:
            results = [r for r, c in declarations if match(r, c)]
            if results:
                return results
        return []

    def propose(self, document, error):
        matches = self.matches(document, error)
        if len(matches) != 1:
            return None
        path = pointer(error["path"])
        old = value_at(document, path)
        if old == matches[0]:
            return None
        return proposal(
            error["code"],
            path,
            old,
            matches[0],
            "dangling_dependency_ref",
            "Resolve an existing dependency identifier to exactly one declared component; no edge added.",
        )
