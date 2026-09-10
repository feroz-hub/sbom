#!/usr/bin/env python3
"""
Repair dangling SPDX relationship references produced by Snyk SBOM Export API.

THE BUG
-------
Snyk's SPDX 2.3 export emits `relationships[].spdxElementId` /
`relatedSpdxElement` values whose numeric index is one HIGHER than the
`SPDXID` actually declared on the corresponding package. The descriptive
tail of the identifier is byte-identical, so the intended target is
unambiguous:

    declared  in packages[]      : SPDXRef-20-apt-libapt-pkg6.0t64-2.8.3
    referenced in relationships[]: SPDXRef-21-apt-libapt-pkg6.0t64-2.8.3
                                            ^^

This violates SPDX 2.3 clause 11: every element referenced by a
relationship must be declared in the document (or be a DocumentRef-*
external reference). Validators correctly reject it — in SBOM Spectra as
SBOM_VAL_E072_RELATIONSHIP_ELEMENT_DANGLING at Stage 5 (Cross-Reference
Integrity).

THE REPAIR
----------
Rewrite each dangling reference to the declared SPDXID that carries the
same descriptive tail.

This is safe ONLY because the mapping is one-to-one. The script refuses to
write anything if any dangling reference resolves to zero or to more than
one declared package — in that case the file needs a fresh export, not a
patch. Nothing else in the document is touched: no packages are added,
removed, or renumbered, and no relationship is created or dropped.

USAGE
-----
    python fix_spdx_dangling_refs.py input.json [-o output.json]
    python fix_spdx_dangling_refs.py input.json --dry-run
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

# SPDXID shape emitted by Snyk: SPDXRef-<index>-<descriptive tail>
SPDXID_PATTERN = re.compile(r"^SPDXRef-(\d+)-(.+)$")

# Fields on a relationship object that hold an element reference.
REFERENCE_FIELDS = ("spdxElementId", "relatedSpdxElement")

# Reference values that are legal without being declared as a package.
EXEMPT_VALUES = {"SPDXRef-DOCUMENT", "NONE", "NOASSERTION"}


class RepairError(RuntimeError):
    """The document cannot be repaired safely."""


def build_tail_index(packages: list[dict]) -> dict[str, list[str]]:
    """Map each descriptive tail to the declared SPDXID(s) carrying it."""
    tails: dict[str, list[str]] = collections.defaultdict(list)
    for package in packages:
        spdx_id = package.get("SPDXID")
        if not spdx_id:
            continue
        match = SPDXID_PATTERN.match(spdx_id)
        if match:
            tails[match.group(2)].append(spdx_id)
    return tails


def find_dangling(document: dict) -> list[tuple[int, str, str]]:
    """Return (relationship_index, field_name, value) for every dangling ref."""
    declared = {p.get("SPDXID") for p in document.get("packages", [])}
    declared.discard(None)

    dangling: list[tuple[int, str, str]] = []
    for index, relationship in enumerate(document.get("relationships", [])):
        for field in REFERENCE_FIELDS:
            value = relationship.get(field)
            if not value or value in EXEMPT_VALUES:
                continue
            if value.startswith("DocumentRef-"):
                continue  # legal external reference
            if value not in declared:
                dangling.append((index, field, value))
    return dangling


def resolve(dangling: list[tuple[int, str, str]], tails: dict[str, list[str]]) -> dict[str, str]:
    """Map each dangling value to its unique declared SPDXID.

    Raises RepairError if any value is unresolvable or ambiguous, so a
    partial repair is never written to disk.
    """
    resolution: dict[str, str] = {}
    unresolvable: list[str] = []
    ambiguous: list[tuple[str, list[str]]] = []

    for _, _, value in dangling:
        if value in resolution:
            continue
        match = SPDXID_PATTERN.match(value)
        if not match:
            unresolvable.append(value)
            continue
        candidates = tails.get(match.group(2), [])
        if len(candidates) == 1:
            resolution[value] = candidates[0]
        elif not candidates:
            unresolvable.append(value)
        else:
            ambiguous.append((value, candidates))

    if unresolvable or ambiguous:
        lines = ["Cannot repair this document safely."]
        if unresolvable:
            lines.append(
                f"  {len(unresolvable)} reference(s) match no declared package "
                f"(e.g. {unresolvable[0]}). The package is genuinely absent — "
                "re-export the SBOM instead of patching it."
            )
        if ambiguous:
            first, cands = ambiguous[0]
            lines.append(
                f"  {len(ambiguous)} reference(s) match more than one declared package "
                f"(e.g. {first} -> {cands}). Repair would have to guess."
            )
        raise RepairError("\n".join(lines))

    return resolution


def apply_repair(document: dict, resolution: dict[str, str]) -> int:
    """Rewrite dangling references in place. Returns the number rewritten."""
    rewritten = 0
    for relationship in document.get("relationships", []):
        for field in REFERENCE_FIELDS:
            value = relationship.get(field)
            if value in resolution:
                relationship[field] = resolution[value]
                rewritten += 1
    return rewritten


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="SPDX JSON file to repair")
    parser.add_argument("-o", "--output", type=Path, help="output path (default: <input>-fixed.json)")
    parser.add_argument("--dry-run", action="store_true", help="report only, write nothing")
    args = parser.parse_args(argv)

    try:
        document = json.loads(args.input.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2

    version = document.get("spdxVersion", "unknown")
    packages = document.get("packages", [])
    relationships = document.get("relationships", [])
    print(f"{args.input.name}: {version}, {len(packages)} packages, {len(relationships)} relationships")

    dangling = find_dangling(document)
    if not dangling:
        print("No dangling relationship references. Nothing to repair.")
        return 0

    distinct = {value for _, _, value in dangling}
    print(f"Dangling references: {len(dangling)} occurrence(s) across {len(distinct)} distinct SPDXID(s)")

    try:
        resolution = resolve(dangling, build_tail_index(packages))
    except RepairError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Report the index shift pattern, so the reader can see this is a
    # systematic generator bug rather than scattered corruption.
    shifts: collections.Counter[int] = collections.Counter()
    for referenced, actual in resolution.items():
        ref_n = int(SPDXID_PATTERN.match(referenced).group(1))
        act_n = int(SPDXID_PATTERN.match(actual).group(1))
        shifts[act_n - ref_n] += 1
    for delta, count in sorted(shifts.items()):
        print(f"  index shift {delta:+d}: {count} package(s)")

    print("\nSample of the rewrites:")
    for referenced in sorted(resolution)[:5]:
        print(f"  {referenced}\n    -> {resolution[referenced]}")
    if len(resolution) > 5:
        print(f"  ... and {len(resolution) - 5} more")

    if args.dry_run:
        print("\n--dry-run: nothing written.")
        return 0

    rewritten = apply_repair(document, resolution)

    remaining = find_dangling(document)
    if remaining:
        print(f"error: {len(remaining)} reference(s) still dangling after repair; refusing to write", file=sys.stderr)
        return 1

    output = args.output or args.input.with_name(f"{args.input.stem}-fixed.json")
    output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nRewrote {rewritten} reference(s). Verified 0 dangling remain.")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
