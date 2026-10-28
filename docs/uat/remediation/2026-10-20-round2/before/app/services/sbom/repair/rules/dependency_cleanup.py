from app.validation import errors as E

from ..diff import pointer, proposal, value_at
from .base import RepairRule


class DependencyCleanupRule(RepairRule):
    name = "dependency_cleanup"
    error_codes = {E.E071_DEPENDENCY_REF_SELF, "QUALITY_DUPLICATE_EMPTY_NODE"}

    def propose(self, document, error):
        path = pointer(error["path"])
        if not path.startswith("/dependencies/"):
            return None
        try:
            if error["code"] == "QUALITY_DUPLICATE_EMPTY_NODE":
                old = value_at(document, path)
                if (
                    not isinstance(old, dict)
                    or set(old) - {"ref", "dependsOn"}
                    or old.get("dependsOn") != []
                    or not isinstance(old.get("ref"), str)
                ):
                    return None
                if not any(
                    n is not old and isinstance(n, dict) and n.get("ref") == old["ref"]
                    for n in document.get("dependencies", [])
                ):
                    return None
                return proposal(
                    error["code"],
                    path,
                    old,
                    None,
                    self.name,
                    "Remove a redundant empty source record; all existing graph edges are preserved.",
                    "remove",
                )
            base = path.rsplit("/", 1)[0]
            node = value_at(document, base)
            old = node.get("dependsOn")
            if not isinstance(old, list) or node.get("ref") not in old:
                return None
            new = [target for target in old if target != node["ref"]]
            return proposal(
                error["code"],
                base + "/dependsOn",
                old,
                new,
                self.name,
                "Remove only the exact self-edge prohibited by the existing integrity validator; retain all other edges.",
            )
        except (KeyError, IndexError, TypeError, ValueError):
            return None
