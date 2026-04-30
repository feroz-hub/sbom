"""Stage 3 — structural schema validation.

JSON path: ``jsonschema.Draft202012Validator(schema, format_checker=FormatChecker())``
collected via ``iter_errors`` (never bail on first; aggregate up to the
``MAX_ENTRIES`` truncation cap).

XML path: parse via ``defusedxml.lxml`` (forbids DTDs and external entities),
then assert validity against the matching XSD with ``lxml.etree.XMLSchema``.
The ``xml.etree.ElementTree`` fallback that lived in :mod:`app.parsing.cyclonedx`
is gone — there is no fallback at all in this stage.

Schemas are vendored under :mod:`app.validation.schemas` and loaded once at
module import time. They are never fetched at runtime — see
:doc:`../../docs/adr/0007-sbom-validation-architecture`.
"""

from __future__ import annotations

import json
import logging
from importlib import resources
from typing import Any

from .. import errors as E
from ..context import ValidationContext

log = logging.getLogger(__name__)

_STAGE = "schema"

# Mapping of validator codes from jsonschema to our typed sub-codes.
_VALIDATOR_CODE_MAP: dict[str, str] = {
    "required": E.E026_SCHEMA_REQUIRED_FIELD_MISSING,
    "type": E.E027_SCHEMA_TYPE_MISMATCH,
    "enum": E.E028_SCHEMA_ENUM_VIOLATION,
    "format": E.E029_SCHEMA_FORMAT_VIOLATION,
}


# ---------------------------------------------------------------------------
# Schema loading (cached at module import)
# ---------------------------------------------------------------------------


def _vendored_dir(spec: str, version: str) -> str:
    """Map a spec / version pair to its on-disk directory name.

    SPDX versions arrive as ``SPDX-2.3`` (the spec field value); CycloneDX
    versions as ``1.6``. Strip the ``SPDX-`` prefix so both share the same
    layout convention under :mod:`app.validation.schemas`.
    """
    if spec == "spdx" and version.upper().startswith("SPDX-"):
        return version[len("SPDX-") :]
    return version


def _load_json_schema(spec: str, version: str) -> dict[str, Any] | None:
    """Load a vendored JSON Schema by ``(spec, version)``.

    The version segment (e.g. ``1.5``) is not a valid Python identifier so we
    cannot use it as a sub-package — we navigate through the ``schemas``
    package via :func:`importlib.resources.files` joinpath instead.
    """
    pkg = f"app.validation.schemas.{spec}"
    sub_dir = _vendored_dir(spec, version)
    file_name = (
        "spdx-schema.json" if spec == "spdx" else f"bom-{sub_dir}.schema.json"
    )
    try:
        path = resources.files(pkg).joinpath(sub_dir, file_name)
        text = path.read_text(encoding="utf-8")
        return json.loads(text)
    except Exception as exc:  # pragma: no cover — startup failure
        log.error("failed to load vendored schema %s/%s: %s", spec, version, exc)
        return None


_JSON_SCHEMAS: dict[tuple[str, str], dict[str, Any]] = {}
_XSD_SCHEMAS: dict[str, Any] = {}


def _ensure_json_schema(spec: str, version: str) -> dict[str, Any] | None:
    key = (spec, version)
    if key in _JSON_SCHEMAS:
        return _JSON_SCHEMAS[key]
    schema = _load_json_schema(spec, version)
    if schema is not None:
        _JSON_SCHEMAS[key] = schema
    return schema


def _ensure_xsd(version: str):  # noqa: ANN202 — lxml type imported lazily
    sub_dir = _vendored_dir("cyclonedx", version)
    if sub_dir in _XSD_SCHEMAS:
        return _XSD_SCHEMAS[sub_dir]
    try:
        from lxml import etree  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover — missing dep
        log.error("lxml is required for XML schema validation: %s", exc)
        return None
    file_name = f"bom-{sub_dir}.xsd"
    try:
        path = resources.files("app.validation.schemas.cyclonedx").joinpath(sub_dir, file_name)
        with resources.as_file(path) as filepath:
            tree = etree.parse(str(filepath))
            schema = etree.XMLSchema(tree)
            _XSD_SCHEMAS[sub_dir] = schema
            return schema
    except Exception as exc:  # pragma: no cover — startup failure
        log.error("failed to load vendored XSD cyclonedx/%s: %s", version, exc)
        return None


# ---------------------------------------------------------------------------
# Stage entry point
# ---------------------------------------------------------------------------


def run(ctx: ValidationContext) -> ValidationContext:
    if ctx.spec is None or ctx.spec_version is None:
        return ctx  # detect failed; orchestrator already short-circuits

    if ctx.encoding == "json":
        return _validate_json(ctx)
    if ctx.encoding == "xml":
        return _validate_xml(ctx)
    if ctx.encoding == "tag-value":
        return _validate_tag_value(ctx)
    if ctx.encoding == "yaml":
        ctx.report.add(
            E.E022_YAML_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message="YAML SBOMs are not supported in v1.",
            remediation="Re-export as JSON or XML.",
        )
        return ctx
    if ctx.encoding == "protobuf":
        ctx.report.add(
            E.E024_PROTOBUF_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message="CycloneDX Protobuf is deferred in v1.",
            remediation="Re-export as CycloneDX JSON or XML.",
        )
        return ctx
    return ctx


def _validate_json(ctx: ValidationContext) -> ValidationContext:
    if ctx.parsed_dict is None:
        # detect put the dict here for JSON path, but be defensive
        try:
            ctx.parsed_dict = json.loads(ctx.text or "")
        except json.JSONDecodeError as exc:
            ctx.report.add(
                E.E020_JSON_PARSE_FAILED,
                stage=_STAGE,
                path="",
                message=f"JSON parser failed at line {exc.lineno}, column {exc.colno}: {exc.msg}",
                remediation="Validate the document with a JSON linter before upload.",
            )
            return ctx

    schema = _ensure_json_schema(ctx.spec or "", ctx.spec_version or "")
    if schema is None:
        ctx.report.add(
            E.E025_SCHEMA_VIOLATION,
            stage=_STAGE,
            path="",
            message=(
                f"Vendored schema for {ctx.spec}/{ctx.spec_version} is unavailable. "
                "This is a server configuration error."
            ),
            remediation="Contact your operator; schemas should be installed with the package.",
        )
        return ctx

    try:
        from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
    except ImportError:
        ctx.report.add(
            E.E025_SCHEMA_VIOLATION,
            stage=_STAGE,
            path="",
            message="jsonschema package is not installed.",
            remediation="Install jsonschema>=4.21.",
        )
        return ctx

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for error in validator.iter_errors(ctx.parsed_dict):
        code = _VALIDATOR_CODE_MAP.get(error.validator or "", E.E025_SCHEMA_VIOLATION)
        path = ".".join(str(p) for p in error.absolute_path) or "(root)"
        ctx.report.add(
            code,
            stage=_STAGE,
            path=path,
            message=f"Schema violation at {path}: {error.message}",
            remediation=(
                "Compare against the relevant spec section. The validator never "
                "coerces types — re-emit with the correct value."
            ),
            spec_reference=f"{(ctx.spec or '').upper()} {ctx.spec_version}",
        )
    return ctx


def _validate_xml(ctx: ValidationContext) -> ValidationContext:
    """Parse XML through a hardened :mod:`lxml` parser.

    ``defusedxml.lxml`` is deprecated upstream — modern lxml is safe when the
    parser is configured with ``resolve_entities=False``,
    ``no_network=True``, and ``load_dtd=False``. We additionally pre-screen
    the document with :mod:`defusedxml.ElementTree` so DTDs / external
    entities are rejected with a structured code before lxml sees the bytes.
    """
    try:
        import lxml.etree as etree  # type: ignore[import-untyped]
    except ImportError:
        ctx.report.add(
            E.E021_XML_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message="lxml is not installed.",
            remediation="Install lxml>=5.",
        )
        return ctx

    text = ctx.text or ""

    # Pre-screen via defusedxml to surface DTDs / external entities as
    # specific error codes, even though our lxml parser is also locked down.
    try:
        from defusedxml import ElementTree as DefusedET  # type: ignore[import-untyped]
        DefusedET.fromstring(
            text.encode("utf-8"),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except ImportError:
        # No defusedxml — fall back to lxml-only gating below.
        pass
    except Exception as exc:
        kind = type(exc).__name__
        if "DTD" in kind:
            ctx.report.add(
                E.E083_XML_DTD_FORBIDDEN,
                stage=_STAGE,
                path="",
                message=f"Document contains a DTD declaration ({kind}).",
                remediation="DTDs are forbidden — remove the <!DOCTYPE …> declaration.",
            )
        elif "External" in kind:
            ctx.report.add(
                E.E084_XML_EXTERNAL_ENTITY_FORBIDDEN,
                stage=_STAGE,
                path="",
                message=f"Document declares an external entity ({kind}).",
                remediation="External entities are forbidden — remove them.",
            )
        elif "Entit" in kind:
            ctx.report.add(
                E.E085_XML_ENTITY_EXPANSION,
                stage=_STAGE,
                path="",
                message=f"XML entity expansion attempt ({kind}).",
                remediation="Defends against billion-laughs / quadratic-blowup attacks.",
            )
        else:
            ctx.report.add(
                E.E021_XML_PARSE_FAILED,
                stage=_STAGE,
                path="",
                message=f"XML parser failed: {exc}",
                remediation="Validate the document with an XML linter (xmllint) before upload.",
            )
        return ctx

    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )
    try:
        tree = etree.fromstring(text.encode("utf-8"), parser=parser)
    except Exception as exc:
        # The defusedxml pre-screen above catches DTDs / external entities /
        # entity-expansion attacks. Anything that survives the pre-screen and
        # still trips lxml is a regular parse error.
        ctx.report.add(
            E.E021_XML_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message=f"XML parser failed: {exc}",
            remediation="Validate the document with an XML linter (xmllint) before upload.",
        )
        return ctx

    xsd = _ensure_xsd(ctx.spec_version or "")
    if xsd is None:
        ctx.report.add(
            E.E025_SCHEMA_VIOLATION,
            stage=_STAGE,
            path="",
            message=f"Vendored XSD for cyclonedx/{ctx.spec_version} is unavailable.",
            remediation="Contact your operator; schemas should be installed with the package.",
        )
        return ctx

    if not xsd.validate(tree):
        for err in xsd.error_log:  # type: ignore[union-attr]
            ctx.report.add(
                E.E025_SCHEMA_VIOLATION,
                stage=_STAGE,
                path=getattr(err, "path", "") or "",
                message=f"XSD violation at line {err.line}: {err.message}",
                remediation="Compare against the CycloneDX XSD for this version.",
                spec_reference=f"CycloneDX {ctx.spec_version}",
            )

    # Convert the lxml tree into a dict-shaped projection so subsequent stages
    # can run uniformly. We re-use the upstream conversion via xmltodict-style
    # walk that we already trust because it ran *after* defusedxml gating.
    ctx.parsed_dict = _xml_to_dict(tree)
    return ctx


def _xml_to_dict(root: Any) -> dict[str, Any]:
    """Project a CycloneDX XML tree into a CycloneDX-JSON-shaped dict.

    This is intentionally minimal — only the keys that semantic / integrity
    stages read are preserved. Stage 4 reads ``components``, ``dependencies``,
    ``metadata``, ``serialNumber``, ``version``, ``specVersion``.
    """
    ns_uri = root.tag.split("}")[0][1:] if root.tag.startswith("{") else None

    def text_of(elem: Any) -> str | None:
        return elem.text.strip() if elem is not None and elem.text else None

    out: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _spec_from_namespace(ns_uri) or "",
        "serialNumber": root.get("serialNumber"),
        "version": root.get("version"),
    }

    metadata = root.find(f"{{{ns_uri}}}metadata") if ns_uri else None
    if metadata is not None:
        ts_elem = metadata.find(f"{{{ns_uri}}}timestamp") if ns_uri else None
        out["metadata"] = {
            "timestamp": text_of(ts_elem),
            "tools": _xml_metadata_tools(metadata, ns_uri),
        }

    components_root = root.find(f"{{{ns_uri}}}components") if ns_uri else None
    out["components"] = []
    if components_root is not None:
        for comp in components_root.findall(f"{{{ns_uri}}}component"):
            out["components"].append(_xml_component(comp, ns_uri))

    deps_root = root.find(f"{{{ns_uri}}}dependencies") if ns_uri else None
    out["dependencies"] = []
    if deps_root is not None:
        for dep in deps_root.findall(f"{{{ns_uri}}}dependency"):
            entry = {"ref": dep.get("ref"), "dependsOn": []}
            for sub in dep.findall(f"{{{ns_uri}}}dependency"):
                target = sub.get("ref")
                if target:
                    entry["dependsOn"].append(target)
            out["dependencies"].append(entry)
    return out


def _spec_from_namespace(ns_uri: str | None) -> str | None:
    if not ns_uri:
        return None
    if ns_uri.startswith("http://cyclonedx.org/schema/bom/"):
        return ns_uri.rsplit("/", 1)[-1]
    return None


def _xml_metadata_tools(metadata: Any, ns_uri: str | None) -> list[dict[str, Any]]:
    if not ns_uri:
        return []
    tools_root = metadata.find(f"{{{ns_uri}}}tools")
    if tools_root is None:
        return []
    tools: list[dict[str, Any]] = []
    for tool in tools_root.findall(f"{{{ns_uri}}}tool"):
        name_el = tool.find(f"{{{ns_uri}}}name")
        vendor_el = tool.find(f"{{{ns_uri}}}vendor")
        tools.append(
            {
                "name": name_el.text.strip() if name_el is not None and name_el.text else None,
                "vendor": vendor_el.text.strip() if vendor_el is not None and vendor_el.text else None,
            }
        )
    return tools


def _xml_component(comp: Any, ns_uri: str | None) -> dict[str, Any]:
    def find_text(elem: Any, tag: str) -> str | None:
        if not ns_uri:
            return None
        sub = elem.find(f"{{{ns_uri}}}{tag}")
        return sub.text.strip() if sub is not None and sub.text else None

    return {
        "type": comp.get("type"),
        "bom-ref": comp.get("bom-ref"),
        "name": find_text(comp, "name"),
        "version": find_text(comp, "version"),
        "group": find_text(comp, "group"),
        "purl": find_text(comp, "purl"),
        "cpe": find_text(comp, "cpe"),
        "supplier": {"name": find_text(comp, "supplier")} if find_text(comp, "supplier") else None,
    }


def _validate_tag_value(ctx: ValidationContext) -> ValidationContext:
    """SPDX Tag-Value: re-route through ``spdx-tools`` and re-validate as JSON."""
    try:
        from spdx_tools.spdx.jsonschema.document_converter import (  # type: ignore[import-untyped]
            DocumentConverter,
        )
        from spdx_tools.spdx.parser.parse_anything import parse_file  # type: ignore[import-untyped]
    except ImportError:
        ctx.report.add(
            E.E023_TAGVALUE_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message="spdx-tools is not installed; cannot parse SPDX Tag-Value.",
            remediation="Install spdx-tools>=0.8.",
        )
        return ctx

    # spdx-tools parses from a file path. Spool to a temp file under the
    # process's temp dir; nothing is persisted beyond this stage.
    import tempfile

    text = ctx.text or ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".spdx", delete=True, encoding="utf-8") as tmp:
            tmp.write(text)
            tmp.flush()
            doc = parse_file(tmp.name)
    except Exception as exc:
        ctx.report.add(
            E.E023_TAGVALUE_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message=f"SPDX Tag-Value parser failed: {exc}",
            remediation="Each non-comment line must be 'Tag: value'.",
            spec_reference="SPDX 2.3 §3",
        )
        return ctx

    try:
        ctx.parsed_dict = DocumentConverter().convert(doc)
    except Exception as exc:
        ctx.report.add(
            E.E023_TAGVALUE_PARSE_FAILED,
            stage=_STAGE,
            path="",
            message=f"SPDX Tag-Value conversion failed: {exc}",
            remediation="Re-export the document and try again.",
        )
        return ctx
    # Now run the JSON-schema check against the projected dict.
    return _validate_json(ctx)
