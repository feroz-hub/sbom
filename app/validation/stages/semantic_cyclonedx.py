"""Stage 4 — semantic validation for CycloneDX 1.4 / 1.5 / 1.6.

Schema (stage 3) handles type / required / enum. This stage covers:

* ``serialNumber`` matches ``^urn:uuid:[0-9a-f-]{36}$``.
* ``bom-ref`` uniqueness within the document.
* Each ``purl`` parses via :mod:`packageurl`.
* Each ``cpe`` matches CPE 2.3 form.
* Each hash's content length matches the declared algorithm.
* Top-level ``version`` (BOM revision) is a non-negative integer.
* ``metadata.timestamp`` is ISO-8601.

Outputs the projected :class:`InternalSbom` on ``ctx.internal_model``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .. import errors as E
from ..context import ValidationContext
from ..normalize import normalize_cyclonedx

_STAGE = "semantic"

_SERIAL_RE = re.compile(r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HASH_HEX_LENGTHS = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2b-256": 64,
    "BLAKE2b-384": 96,
    "BLAKE2b-512": 128,
    "BLAKE3": 64,
}
_ALLOWED_COMPONENT_TYPES = {
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
    "cryptographic-asset",
}

# CPE 2.3 grammar — formatted form, not the legacy 2.2 URL form. Values may
# contain '*' wildcards and '?' anchors per the spec, plus escape sequences.
# We accept the formatted-string form per NIST IR 7695 §5.3.2 and let the
# semantic level treat structural deviations as a hard error.
_CPE23_RE = re.compile(
    r"^cpe:2\.3:[aho\*\-]"
    r"(:[a-zA-Z0-9._\-~%!@^&*()=+,;'\"\\\?\*]+){10}$"
)


def run(ctx: ValidationContext) -> ValidationContext:
    doc = ctx.parsed_dict
    if doc is None or ctx.spec_version is None:
        return ctx

    _check_serial_number(doc.get("serialNumber"), ctx)
    _check_bom_version(doc.get("version"), ctx)
    _check_metadata_timestamp(doc, ctx)

    seen_refs: dict[str, str] = {}
    for index, comp in enumerate(doc.get("components") or []):
        if not isinstance(comp, dict):
            continue
        path = f"components[{index}]"
        _check_component_ref_unique(comp, path, seen_refs, ctx)
        _check_component_type(comp, path, ctx)
        _check_purl(comp.get("purl"), f"{path}.purl", ctx)
        _check_cpe(comp.get("cpe"), f"{path}.cpe", ctx)
        for j, h in enumerate(comp.get("hashes") or []):
            if isinstance(h, dict):
                _check_hash(h, f"{path}.hashes[{j}]", ctx)

    ctx.internal_model = normalize_cyclonedx(doc, ctx.spec_version)
    return ctx


def _check_serial_number(value: object, ctx: ValidationContext) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _SERIAL_RE.match(value):
        ctx.report.add(
            E.E050_SERIAL_NUMBER_INVALID,
            stage=_STAGE,
            path="serialNumber",
            message=f"serialNumber '{value}' does not match urn:uuid:<uuid> form.",
            remediation="Use the form 'urn:uuid:{uuid4}'.",
            spec_reference="CycloneDX 1.6 §3",
        )


def _check_bom_version(value: object, ctx: ValidationContext) -> None:
    if value is None:
        return
    parsed: int | None
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.lstrip("-").isdigit():
        parsed = int(value)
    else:
        parsed = None
    if parsed is None or parsed < 0:
        ctx.report.add(
            E.E055_BOM_VERSION_INVALID,
            stage=_STAGE,
            path="version",
            message=f"Top-level 'version' must be a non-negative integer (BOM revision), got '{value}'.",
            remediation="This is the BOM revision, not a component version. Set to an integer ≥ 0.",
            spec_reference="CycloneDX 1.6 §3",
        )


def _check_metadata_timestamp(doc: dict[str, Any], ctx: ValidationContext) -> None:
    metadata = doc.get("metadata") or {}
    ts = metadata.get("timestamp") if isinstance(metadata, dict) else None
    if ts is None:
        return
    if not isinstance(ts, str):
        ctx.report.add(
            E.E056_METADATA_TIMESTAMP_INVALID,
            stage=_STAGE,
            path="metadata.timestamp",
            message=f"metadata.timestamp '{ts}' is not a string.",
            remediation="Emit timestamps as 2026-04-30T12:34:56Z.",
            spec_reference="CycloneDX 1.6 §3.3",
        )
        return
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        ctx.report.add(
            E.E056_METADATA_TIMESTAMP_INVALID,
            stage=_STAGE,
            path="metadata.timestamp",
            message=f"metadata.timestamp '{ts}' is not parseable as ISO-8601.",
            remediation="Emit timestamps as 2026-04-30T12:34:56Z.",
            spec_reference="CycloneDX 1.6 §3.3",
        )


def _check_component_ref_unique(comp: dict, path: str, seen: dict[str, str], ctx: ValidationContext) -> None:
    ref = comp.get("bom-ref") or comp.get("bomRef")
    if not isinstance(ref, str) or not ref:
        return
    if ref in seen:
        ctx.report.add(
            E.E051_BOM_REF_DUPLICATE,
            stage=_STAGE,
            path=f"{path}.bom-ref",
            message=f"bom-ref '{ref}' is duplicated; first seen at {seen[ref]}.",
            remediation="Every bom-ref must be unique within the document.",
            spec_reference="CycloneDX 1.6 §4.1",
        )
        return
    seen[ref] = f"{path}.bom-ref"


def _check_component_type(comp: dict, path: str, ctx: ValidationContext) -> None:
    t = comp.get("type")
    if t is None:
        return  # schema would have caught a missing required field
    if not isinstance(t, str) or t not in _ALLOWED_COMPONENT_TYPES:
        ctx.report.add(
            E.E057_COMPONENT_TYPE_INVALID,
            stage=_STAGE,
            path=f"{path}.type",
            message=f"components.type '{t}' is not in the allowed CycloneDX set.",
            remediation=(
                "Allowed: application, framework, library, container, platform, "
                "operating-system, device, device-driver, firmware, file, "
                "machine-learning-model, data, cryptographic-asset."
            ),
            spec_reference="CycloneDX 1.6 §4.4",
        )


def _check_purl(value: object, path: str, ctx: ValidationContext) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        ctx.report.add(
            E.E052_PURL_INVALID,
            stage=_STAGE,
            path=path,
            message="PURL is not a string.",
            remediation="Encode PURL as a string.",
            spec_reference="CycloneDX 1.6 §4.4.1",
        )
        return
    try:
        from packageurl import PackageURL  # type: ignore[import-untyped]
    except ImportError:
        ctx.report.add(
            E.E052_PURL_INVALID,
            stage=_STAGE,
            path=path,
            message="packageurl-python is not installed; cannot validate PURL.",
            remediation="Contact your operator; install packageurl-python>=0.15.",
        )
        return
    try:
        PackageURL.from_string(value)
    except Exception as exc:
        ctx.report.add(
            E.E052_PURL_INVALID,
            stage=_STAGE,
            path=path,
            message=f"PURL '{value}' is malformed: {exc}",
            remediation=(
                "Use the form `pkg:{type}/{namespace}/{name}@{version}`. "
                "See https://github.com/package-url/purl-spec."
            ),
            spec_reference="CycloneDX 1.6 §4.4.1",
        )


def _check_cpe(value: object, path: str, ctx: ValidationContext) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _CPE23_RE.match(value):
        ctx.report.add(
            E.E053_CPE_INVALID,
            stage=_STAGE,
            path=path,
            message=f"CPE '{value}' does not parse as CPE 2.3.",
            remediation="Use the CPE 2.3 form: cpe:2.3:{part}:{vendor}:{product}:{version}:…",
            spec_reference="CycloneDX 1.6 §4.4.1",
        )


def _check_hash(h: dict, path: str, ctx: ValidationContext) -> None:
    alg = h.get("alg")
    content = h.get("content")
    if not isinstance(alg, str) or not isinstance(content, str):
        return  # schema check would have flagged the type error
    expected = _HASH_HEX_LENGTHS.get(alg)
    if expected is None:
        return
    if len(content) != expected:
        ctx.report.add(
            E.E054_HASH_LENGTH_MISMATCH,
            stage=_STAGE,
            path=path,
            message=(
                f"Hash has alg '{alg}' but content length {len(content)} hex "
                f"chars (expected {expected})."
            ),
            remediation="Recompute the digest with the algorithm declared.",
            spec_reference="CycloneDX 1.6 §4.4.5",
        )
