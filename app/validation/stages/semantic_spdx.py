r"""Stage 4 — semantic validation for SPDX 2.x.

The schema check (stage 3) already enforces type / required / enum rules.
This stage covers the *semantic* invariants the schema cannot express:

* ``SPDXID`` matches ``^SPDXRef-[a-zA-Z0-9.\-]+$`` (or ``DocumentRef-…``).
* ``documentNamespace`` is an absolute URI without a fragment.
* ``dataLicense`` equals ``CC0-1.0``.
* Each ``licenseConcluded`` / ``licenseDeclared`` parses against the SPDX
  License List (via ``license-expression``).
* ``checksums[].checksumValue`` length matches the declared algorithm.
* ``creationInfo.created`` is ISO-8601 UTC ending in ``Z``.
* At least one ``DESCRIBES`` relationship from ``SPDXRef-DOCUMENT`` exists.

Outputs the projected :class:`InternalSbom` on ``ctx.internal_model``.
"""

from __future__ import annotations

import re
from datetime import datetime

from .. import errors as E
from ..context import ValidationContext
from ..normalize import normalize_spdx

_STAGE = "semantic"

_SPDXID_RE = re.compile(r"^(SPDXRef|DocumentRef)-[a-zA-Z0-9.\-]+$")
_NAMESPACE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://[^#]+$")
_HASH_LENGTHS = {
    "SHA1": 40,
    "SHA224": 56,
    "SHA256": 64,
    "SHA384": 96,
    "SHA512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "MD2": 32,
    "MD4": 32,
    "MD5": 32,
    "MD6": 64,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3": 64,
}


def run(ctx: ValidationContext) -> ValidationContext:
    doc = ctx.parsed_dict
    if doc is None or ctx.spec_version is None:
        return ctx

    _check_spdxid(doc.get("SPDXID"), "SPDXID", ctx)
    _check_data_license(doc.get("dataLicense"), ctx)
    _check_namespace(doc.get("documentNamespace"), ctx)
    _check_created(((doc.get("creationInfo") or {}).get("created")), ctx)

    for index, pkg in enumerate(doc.get("packages") or []):
        if not isinstance(pkg, dict):
            continue
        _check_spdxid(pkg.get("SPDXID"), f"packages[{index}].SPDXID", ctx)
        for j, chk in enumerate(pkg.get("checksums") or []):
            if isinstance(chk, dict):
                _check_checksum(chk, f"packages[{index}].checksums[{j}]", ctx)
        for key in ("licenseConcluded", "licenseDeclared"):
            value = pkg.get(key)
            if isinstance(value, str) and value not in ("NOASSERTION", "NONE"):
                _check_license_expression(value, f"packages[{index}].{key}", ctx)

    for index, file_block in enumerate(doc.get("files") or []):
        if isinstance(file_block, dict):
            _check_spdxid(file_block.get("SPDXID"), f"files[{index}].SPDXID", ctx)

    _check_describes_relationship(doc, ctx)

    ctx.internal_model = normalize_spdx(doc, ctx.spec_version)
    return ctx


def _check_spdxid(value: object, path: str, ctx: ValidationContext) -> None:
    if not isinstance(value, str):
        return  # schema stage already flagged the type error
    if value == "SPDXRef-DOCUMENT":
        return
    if not _SPDXID_RE.match(value):
        ctx.report.add(
            E.E040_SPDXID_MALFORMED,
            stage=_STAGE,
            path=path,
            message=f"SPDXID '{value}' does not match SPDXRef-/DocumentRef-[a-zA-Z0-9.-]+ pattern.",
            remediation="Rename the SPDXID to start with `SPDXRef-` and contain only [a-zA-Z0-9.-].",
            spec_reference="SPDX 2.3 §3.2",
        )


def _check_data_license(value: object, ctx: ValidationContext) -> None:
    if value is None:
        # schema check would have flagged a missing required field for SPDX docs
        return
    if value != "CC0-1.0":
        ctx.report.add(
            E.E042_DATA_LICENSE_INVALID,
            stage=_STAGE,
            path="dataLicense",
            message=f"dataLicense must be exactly 'CC0-1.0', got '{value}'.",
            remediation=(
                "Set dataLicense to 'CC0-1.0' — this is the licence of the SBOM "
                "document itself, not of the components."
            ),
            spec_reference="SPDX 2.3 §6.2",
        )


def _check_namespace(value: object, ctx: ValidationContext) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _NAMESPACE_RE.match(value):
        ctx.report.add(
            E.E041_DOCUMENT_NAMESPACE_INVALID,
            stage=_STAGE,
            path="documentNamespace",
            message=f"documentNamespace '{value}' is not an absolute URI without a fragment.",
            remediation="Provide an absolute URI with no '#' segment, e.g. https://example.com/sboms/{uuid}.",
            spec_reference="SPDX 2.3 §6.5",
        )


def _check_created(value: object, ctx: ValidationContext) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not value.endswith("Z"):
        ctx.report.add(
            E.E045_CREATED_TIMESTAMP_INVALID,
            stage=_STAGE,
            path="creationInfo.created",
            message=f"created '{value}' is not ISO-8601 UTC ending in 'Z'.",
            remediation="Emit timestamps as 2026-04-30T12:34:56Z.",
            spec_reference="SPDX 2.3 §6.9",
        )
        return
    try:
        # Replace trailing Z so ``fromisoformat`` (3.11+) accepts.
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        ctx.report.add(
            E.E045_CREATED_TIMESTAMP_INVALID,
            stage=_STAGE,
            path="creationInfo.created",
            message=f"created '{value}' is not parseable as ISO-8601.",
            remediation="Emit timestamps as 2026-04-30T12:34:56Z.",
            spec_reference="SPDX 2.3 §6.9",
        )


def _check_checksum(chk: dict, path: str, ctx: ValidationContext) -> None:
    alg = chk.get("algorithm")
    value = chk.get("checksumValue")
    if not isinstance(alg, str) or not isinstance(value, str):
        return
    expected = _HASH_LENGTHS.get(alg.upper().replace("-", ""))
    if expected is None:
        # schema check should have caught the enum mismatch; fall through
        return
    if len(value) != expected:
        ctx.report.add(
            E.E044_CHECKSUM_LENGTH_MISMATCH,
            stage=_STAGE,
            path=path,
            message=(
                f"Checksum has algorithm '{alg}' but value length {len(value)} hex "
                f"chars (expected {expected})."
            ),
            remediation="Recompute the digest with the algorithm declared.",
            spec_reference="SPDX 2.3 §7.10",
        )


_SPDX_LICENSING_CACHE: object | None = None


def _get_spdx_licensing():  # noqa: ANN202 — return type is library-internal
    """Load the SPDX licence index lazily and cache the result.

    ``license_expression.get_spdx_licensing()`` rebuilds a 1M-entry
    Aho-Corasick trie on every call (~5-15 ms each). Caching this object
    drops the SPDX-realistic path from > 5 s to < 100 ms.
    """
    global _SPDX_LICENSING_CACHE
    if _SPDX_LICENSING_CACHE is not None:
        return _SPDX_LICENSING_CACHE
    from license_expression import get_spdx_licensing  # type: ignore[import-untyped]

    _SPDX_LICENSING_CACHE = get_spdx_licensing()
    return _SPDX_LICENSING_CACHE


def _check_license_expression(expr: str, path: str, ctx: ValidationContext) -> None:
    try:
        licensing = _get_spdx_licensing()
    except ImportError:
        # If the dep is missing we still report — but as a degraded info, not
        # a hard error. The deployment is broken; user can't fix it.
        ctx.report.add(
            E.E043_LICENSE_EXPRESSION_INVALID,
            stage=_STAGE,
            path=path,
            message=(
                "license-expression library is not installed; cannot validate "
                f"expression '{expr}'."
            ),
            remediation="Contact your operator; install license-expression>=30.",
            spec_reference="SPDX 2.3 Annex D",
        )
        return
    try:
        # parse() throws ExpressionParseError on malformed input
        licensing.parse(expr, validate=True, strict=True)  # type: ignore[attr-defined]
    except Exception as exc:
        ctx.report.add(
            E.E043_LICENSE_EXPRESSION_INVALID,
            stage=_STAGE,
            path=path,
            message=f"License expression '{expr}' is unparseable: {exc}",
            remediation="Use a valid SPDX licence expression. See https://spdx.dev/learn/handling-license-info/.",
            spec_reference="SPDX 2.3 Annex D",
        )


def _check_describes_relationship(doc: dict, ctx: ValidationContext) -> None:
    relationships = doc.get("relationships") or []
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        if (
            rel.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and (rel.get("relationshipType") or "").upper() == "DESCRIBES"
        ):
            return
    # ``documentDescribes`` is the SPDX 2.2 short-form for the same intent.
    if doc.get("documentDescribes"):
        return
    ctx.report.add(
        E.E046_DESCRIBES_RELATIONSHIP_MISSING,
        stage=_STAGE,
        path="relationships",
        message="No DESCRIBES relationship from SPDXRef-DOCUMENT was found.",
        remediation=(
            "Add a relationship `{ \"spdxElementId\": \"SPDXRef-DOCUMENT\", "
            "\"relationshipType\": \"DESCRIBES\", \"relatedSpdxElement\": \"...\" }`."
        ),
        spec_reference="SPDX 2.3 §11",
    )
