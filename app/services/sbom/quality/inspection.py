"""Shared linear indexes and conservative identifier projections, never lookups."""

import re
from collections import Counter
from urllib.parse import parse_qsl, unquote

from app.validation.normalize import iter_declared_bom_refs
from app.validation.stages.semantic_cyclonedx import _CPE23_RE
from packageurl import PackageURL

from ..repair.diff import pointer, value_at

SOFTWARE_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device-driver",
    "firmware",
}
CPE_TYPES = {"application", "operating-system", "device", "firmware", "device-driver"}
HASH_TYPES = SOFTWARE_TYPES | {"file", "machine-learning-model"}


def canonical_purl(value):
    if not isinstance(value, str) or re.search(r"%(?![0-9a-fA-F]{2})", value):
        return None
    raw = value.strip()
    try:
        unquote(raw, errors="strict")
    except UnicodeDecodeError:
        return None  # Never replace undecodable identity bytes with a guessed character.
    qualifier = raw.split("?", 1)[1].split("#", 1)[0] if "?" in raw else ""
    keys = [k.lower() for k, _ in parse_qsl(qualifier, keep_blank_values=True)]
    if len(keys) != len(set(keys)) or any(not k or not v for k, v in parse_qsl(qualifier, keep_blank_values=True)):
        return None  # Parser would otherwise silently discard ambiguous qualifiers.
    if "#" in raw and ".." in unquote(raw.split("#", 1)[1]).split("/"):
        return None
    try:
        return PackageURL.from_string(raw).to_string()
    except (ValueError, TypeError):
        return None


def valid_purl(value):
    return isinstance(value, str) and value == value.strip() and canonical_purl(value) is not None


def canonical_cpe(value):
    if isinstance(value, str) and _CPE23_RE.fullmatch(value.strip()):
        return value.strip()
    return None


def components(document):
    metadata = document.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    pending = []
    roots = document.get("components")
    if isinstance(roots, list):
        pending.extend((v, f"/components/{i}") for i, v in enumerate(roots))
    if isinstance(metadata.get("component"), dict):
        pending.append((metadata["component"], "/metadata/component"))
    tools = metadata.get("tools")
    if isinstance(tools, dict) and isinstance(tools.get("components"), list):
        pending.extend((v, f"/metadata/tools/components/{i}") for i, v in enumerate(tools["components"]))
    while pending:
        component, path = pending.pop()
        if not isinstance(component, dict):
            continue
        yield component, path
        children = component.get("components")
        if isinstance(children, list):
            pending.extend((v, f"{path}/components/{i}") for i, v in enumerate(children))


class DocumentIndex:
    def __init__(self, document):
        self.components = list(components(document))
        self.declarations = [(r, pointer(p)) for r, p in iter_declared_bom_refs(document)]
        self.refs = Counter(r for r, _ in self.declarations)
        self.identities = []
        for ref, path in self.declarations:
            self.identities.append((ref, value_at(document, path.rsplit("/", 1)[0])))
        self.dependencies = document.get("dependencies") if isinstance(document.get("dependencies"), list) else []
        self.signed = False
        pending = [document]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                self.signed |= "signature" in node
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)


def repair_quality_issues(document, index=None):
    index = index or DocumentIndex(document)
    issues = []
    for component, path in index.components:
        for field, canonical, code in (
            ("purl", canonical_purl, "QUALITY_PURL_NONCANONICAL"),
            ("cpe", canonical_cpe, "QUALITY_CPE_WHITESPACE"),
        ):
            old = component.get(field)
            new = canonical(old)
            if new is not None and old != new:
                issues.append(
                    {
                        "code": code,
                        "path": f"{path}/{field}",
                        "message": f"{field.upper()} has a deterministic canonical representation.",
                        "severity": "minor",
                    }
                )
    counts = Counter(d.get("ref") for d in index.dependencies if isinstance(d, dict) and isinstance(d.get("ref"), str))
    for i, node in enumerate(index.dependencies):
        if (
            isinstance(node, dict)
            and set(node) <= {"ref", "dependsOn"}
            and isinstance(node.get("ref"), str)
            and counts[node["ref"]] > 1
            and node.get("dependsOn") == []
        ):
            issues.append(
                {
                    "code": "QUALITY_DUPLICATE_EMPTY_NODE",
                    "path": f"/dependencies/{i}",
                    "message": "Redundant empty dependency node repeats an existing source.",
                    "severity": "minor",
                }
            )
    return issues
