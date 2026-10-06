"""Never guess the target of an ambiguous reference to distinct declarations."""

import json
from collections import defaultdict
from urllib.parse import unquote
from uuid import NAMESPACE_URL, uuid5

from app.validation import errors as E
from app.validation.normalize import iter_declared_bom_refs

from ..diff import pointer, proposal, unique_entries, value_at
from .base import RepairRule


class DuplicateBomRefRule(RepairRule):
    name = "duplicate_bom_ref"
    error_codes = {E.E051_BOM_REF_DUPLICATE, E.E025_SCHEMA_VIOLATION}

    def propose(self, document, error):
        path = pointer(error["path"])
        if error["code"] == E.E025_SCHEMA_VIOLATION:
            if path != "/components" and not path.endswith("/components"):
                return None
            try:
                old = value_at(document, path)
            except (KeyError, IndexError, TypeError, ValueError):
                return None
            if not isinstance(old, list) or not all(isinstance(c, dict) and c.get("bom-ref") for c in old):
                return None
            new = unique_entries(old)
            if old == new:
                return None
            return proposal(
                error["code"],
                path,
                old,
                new,
                "duplicate_bom_ref",
                "Remove identical repeated component declarations; references keep their original targets.",
            )
        try:
            ref = value_at(document, path)
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        groups = defaultdict(list)
        for value, location in iter_declared_bom_refs(document):
            groups[value].append(pointer(location))
        locations = groups[ref]
        if len(locations) < 2 or path == locations[0]:
            return None
        # Look across ALL extension/reference fields too. Unknown reference
        # locations make a rename unsafe; do not assume only dependencies use refs.
        declarations = set(locations)
        factual_locations = {
            pointer(location).rsplit("/", 1)[0] + "/" + key
            for values in groups.values()
            for location in values
            for key in ("name", "version", "description", "purl", "cpe", "type", "group", "supplier/name")
        }
        pending = [(document, "")]
        referenced = False
        while pending:
            node, here = pending.pop()
            if isinstance(node, dict):
                pending.extend((v, here + "/" + k.replace("~", "~0").replace("/", "~1")) for k, v in node.items())
            elif isinstance(node, list):
                pending.extend((v, here + "/" + str(i)) for i, v in enumerate(node))
            elif (
                here not in declarations
                and here not in factual_locations
                and (
                    node == ref
                    or (
                        isinstance(node, str) and node.startswith("urn:cdx:") and unquote(node.partition("#")[2]) == ref
                    )
                )
            ):
                referenced = True
        parent_path = path.rsplit("/", 1)[0]
        parent = value_at(document, parent_path)
        first = value_at(document, locations[0].rsplit("/", 1)[0])
        # Identical repeated leaf declarations in the SAME array can be removed:
        # every original reference continues to resolve to the same declaration.
        if (
            json.dumps(parent, sort_keys=True) == json.dumps(first, sort_keys=True)
            and parent_path.rsplit("/", 1)[0] == locations[0].rsplit("/", 2)[0]
        ):
            return proposal(
                error["code"],
                parent_path,
                parent,
                None,
                "duplicate_bom_ref",
                "Remove an identical repeated declaration; all references retain their target.",
                "remove",
            )
        if referenced:
            return None
        suffix = 0
        new = "urn:uuid:" + str(uuid5(NAMESPACE_URL, f"sbom-repair:{ref}:{path}:{suffix}"))
        while new in groups:
            suffix += 1
            new = "urn:uuid:" + str(uuid5(NAMESPACE_URL, f"sbom-repair:{ref}:{path}:{suffix}"))
        return proposal(
            error["code"],
            path,
            ref,
            new,
            "duplicate_bom_ref",
            "Assign a stable document-local identifier to an unreferenced duplicate declaration.",
        )
