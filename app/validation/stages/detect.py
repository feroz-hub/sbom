"""Stage 2 — format & version detection.

Decides ``(spec, spec_version, encoding)`` from a structural fingerprint.
Never guesses: documents that match more than one fingerprint are rejected
with :data:`E011_FORMAT_AMBIGUOUS`; documents matching none are rejected
with :data:`E010_FORMAT_INDETERMINATE`.

Encodings supported in v1:
  * JSON for SPDX 2.2/2.3 and CycloneDX 1.4/1.5/1.6
  * XML for CycloneDX 1.4/1.5/1.6
  * SPDX Tag-Value for SPDX 2.3

Deferred (rejected with :data:`E013_SPEC_VERSION_UNSUPPORTED`):
  * SPDX 3.0 JSON-LD
  * SPDX RDF/XML
  * CycloneDX Protobuf
  * YAML (until a concrete user request lands)

The v1 reject is *deliberate*: it gives a stable, machine-readable contract
that callers can branch on when v2 lands SPDX 3.0 / Protobuf support.
"""

from __future__ import annotations

import json
import re

from .. import errors as E
from ..context import ValidationContext
from . import security as _security

_STAGE = "detect"

_SUPPORTED_CDX = {"1.4", "1.5", "1.6"}
_SUPPORTED_SPDX_JSON = {"SPDX-2.2", "SPDX-2.3"}
_SUPPORTED_SPDX_TAGVAL = {"SPDX-2.2", "SPDX-2.3"}

# CycloneDX XML namespace per spec — see https://cyclonedx.org/docs/1.6/xml/
_CDX_NS_RE = re.compile(r"xmlns\s*=\s*['\"]http://cyclonedx\.org/schema/bom/(?P<v>\d+\.\d+)['\"]")


def run(ctx: ValidationContext) -> ValidationContext:
    text = ctx.text
    if text is None:
        return ctx  # ingress already failed; orchestrator short-circuits

    stripped = text.lstrip()
    if not stripped:
        ctx.report.add(
            E.E005_EMPTY_BODY,
            stage=_STAGE,
            path="",
            message="Document is empty after whitespace stripping.",
            remediation="Provide a non-empty SBOM document.",
        )
        return ctx

    first = stripped[0]

    if first == "{":
        return _detect_json(ctx, stripped)
    if first == "<":
        return _detect_xml(ctx, stripped)
    if stripped.startswith("SPDXVersion:") or _looks_like_tag_value(stripped):
        return _detect_tag_value(ctx, stripped)

    ctx.report.add(
        E.E010_FORMAT_INDETERMINATE,
        stage=_STAGE,
        path="",
        message="Unable to detect SBOM format. No SPDX or CycloneDX fingerprint matched.",
        remediation=(
            "The document must be SPDX (2.2 / 2.3 JSON or 2.3 Tag-Value) or "
            "CycloneDX (1.4 / 1.5 / 1.6 JSON or XML)."
        ),
    )
    return ctx


def _detect_json(ctx: ValidationContext, text: str) -> ValidationContext:
    # Detect is the *only* place a JSON SBOM is parsed in the pipeline. The
    # decoder is the depth-/breadth-/length-capped one from stage 6 so a
    # depth bomb is rejected here, before stage 3's schema validator sees
    # anything. Without this, a malicious document could blow up CPython's
    # parse_object recursion before stage 6 ever gets a chance to look.
    decoder = _security._CappedJSONDecoder()
    try:
        doc = decoder.decode(text)
    except _security._CappedDecodeError as exc:
        ctx.report.add(
            exc.code,
            stage=_STAGE,
            path=exc.path,
            message=exc.message,
            remediation=_security._remediation_for(exc.code),
        )
        return ctx
    except json.JSONDecodeError as exc:
        ctx.report.add(
            E.E020_JSON_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message=f"JSON parser failed at line {exc.lineno}, column {exc.colno}: {exc.msg}",
            remediation="Validate the document with a JSON linter before upload.",
        )
        return ctx
    if not isinstance(doc, dict):
        ctx.report.add(
            E.E010_FORMAT_INDETERMINATE,
            stage=_STAGE,
            path="",
            message="Top-level JSON value is not an object.",
            remediation="SPDX and CycloneDX documents are JSON objects at the top level.",
        )
        return ctx

    has_spdx = (
        "spdxVersion" in doc
        or "SPDXID" in doc
        or "@graph" in doc  # SPDX 3.0
    )
    bom_format = doc.get("bomFormat")
    has_cdx = (isinstance(bom_format, str) and bom_format.lower() == "cyclonedx") or "specVersion" in doc

    if has_spdx and has_cdx:
        ctx.report.add(
            E.E011_FORMAT_AMBIGUOUS,
            stage=_STAGE,
            path="",
            message="Document matches both SPDX and CycloneDX fingerprints.",
            remediation=(
                "The document mixes SPDX and CycloneDX fields. Pick one format "
                "and re-emit. The validator never guesses."
            ),
        )
        return ctx

    if has_cdx:
        version = doc.get("specVersion")
        if not isinstance(version, str):
            ctx.report.add(
                E.E014_SPEC_VERSION_MISSING,
                stage=_STAGE,
                path="specVersion",
                message="CycloneDX document is missing a string 'specVersion'.",
                remediation="Add 'specVersion' (e.g. '1.6') at the top level.",
                spec_reference="CycloneDX 1.6 §3",
            )
            return ctx
        if version not in _SUPPORTED_CDX:
            ctx.report.add(
                E.E013_SPEC_VERSION_UNSUPPORTED,
                stage=_STAGE,
                path="specVersion",
                message=f"CycloneDX specVersion '{version}' is not supported in v1.",
                remediation="Supported: 1.4, 1.5, 1.6.",
            )
            return ctx
        ctx.spec = "cyclonedx"
        ctx.spec_version = version
        ctx.encoding = "json"
        ctx.parsed_dict = doc
        return ctx

    if has_spdx:
        if "@graph" in doc:
            ctx.report.add(
                E.E013_SPEC_VERSION_UNSUPPORTED,
                stage=_STAGE,
                path="@graph",
                message="SPDX 3.0 JSON-LD is deferred in v1.",
                remediation=(
                    "Re-export as SPDX 2.3 JSON or SPDX 2.3 Tag-Value. "
                    "SPDX 3.0 will be added in a future release — see "
                    "app/validation/schemas/spdx/SOURCE.md."
                ),
            )
            return ctx
        version = doc.get("spdxVersion")
        if not isinstance(version, str):
            ctx.report.add(
                E.E014_SPEC_VERSION_MISSING,
                stage=_STAGE,
                path="spdxVersion",
                message="SPDX document is missing a string 'spdxVersion'.",
                remediation="Add 'spdxVersion' (e.g. 'SPDX-2.3') at the top level.",
                spec_reference="SPDX 2.3 §6.1",
            )
            return ctx
        if version not in _SUPPORTED_SPDX_JSON:
            ctx.report.add(
                E.E013_SPEC_VERSION_UNSUPPORTED,
                stage=_STAGE,
                path="spdxVersion",
                message=f"SPDX spdxVersion '{version}' is not supported in v1.",
                remediation="Supported: SPDX-2.2, SPDX-2.3.",
            )
            return ctx
        ctx.spec = "spdx"
        ctx.spec_version = version
        ctx.encoding = "json"
        ctx.parsed_dict = doc
        return ctx

    ctx.report.add(
        E.E010_FORMAT_INDETERMINATE,
        stage=_STAGE,
        path="",
        message="JSON document has neither SPDX nor CycloneDX fingerprint at the top level.",
        remediation=(
            "CycloneDX documents have 'bomFormat' = 'CycloneDX' and 'specVersion'; "
            "SPDX documents have 'spdxVersion' or 'SPDXID'."
        ),
    )
    return ctx


def _detect_xml(ctx: ValidationContext, text: str) -> ValidationContext:
    head = text[:4096]
    match = _CDX_NS_RE.search(head)
    if match:
        version = match.group("v")
        if version not in _SUPPORTED_CDX:
            ctx.report.add(
                E.E013_SPEC_VERSION_UNSUPPORTED,
                stage=_STAGE,
                path="",
                message=f"CycloneDX XML namespace declares spec {version}, not supported in v1.",
                remediation="Supported: 1.4, 1.5, 1.6.",
            )
            return ctx
        ctx.spec = "cyclonedx"
        ctx.spec_version = version
        ctx.encoding = "xml"
        return ctx

    if "spdx.org/rdf" in head.lower():
        ctx.report.add(
            E.E013_SPEC_VERSION_UNSUPPORTED,
            stage=_STAGE,
            path="",
            message="SPDX RDF/XML is deferred in v1.",
            remediation="Re-export as SPDX JSON or Tag-Value.",
        )
        return ctx

    ctx.report.add(
        E.E010_FORMAT_INDETERMINATE,
        stage=_STAGE,
        path="",
        message="XML document has no recognised CycloneDX or SPDX namespace.",
        remediation=(
            "CycloneDX XML root carries xmlns='http://cyclonedx.org/schema/bom/<v>'; "
            "SPDX RDF/XML is deferred in v1."
        ),
    )
    return ctx


def _detect_tag_value(ctx: ValidationContext, text: str) -> ValidationContext:
    version_match = re.search(r"^\s*SPDXVersion:\s*(\S+)\s*$", text, re.MULTILINE)
    if not version_match:
        ctx.report.add(
            E.E014_SPEC_VERSION_MISSING,
            stage=_STAGE,
            path="",
            message="SPDX Tag-Value document has no 'SPDXVersion:' line.",
            remediation="Add 'SPDXVersion: SPDX-2.3' at the top of the document.",
            spec_reference="SPDX 2.3 §6.1",
        )
        return ctx
    version = version_match.group(1).strip()
    if version not in _SUPPORTED_SPDX_TAGVAL:
        ctx.report.add(
            E.E013_SPEC_VERSION_UNSUPPORTED,
            stage=_STAGE,
            path="",
            message=f"SPDX Tag-Value SPDXVersion '{version}' is not supported in v1.",
            remediation="Supported: SPDX-2.2, SPDX-2.3.",
        )
        return ctx
    ctx.spec = "spdx"
    ctx.spec_version = version
    ctx.encoding = "tag-value"
    return ctx


def _looks_like_tag_value(text: str) -> bool:
    """Return True if the first 8 non-comment lines look like SPDX Tag-Value."""
    seen_tag_lines = 0
    for raw_line in text.splitlines()[:32]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            return False
        tag, _, _value = line.partition(":")
        if not tag.strip().isidentifier():
            return False
        seen_tag_lines += 1
        if seen_tag_lines >= 3:
            return True
    return False
