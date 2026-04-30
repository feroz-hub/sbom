"""SBOM validation error codes, severity, and aggregated reports.

This module is the **single source of truth** for every code emitted by any
validation stage. Stages choose a code; this module owns the HTTP-status and
severity mapping. See [docs/validation-error-codes.md](../../docs/validation-error-codes.md)
for the human-facing reference and [docs/adr/0007-sbom-validation-architecture.md](../../docs/adr/0007-sbom-validation-architecture.md)
for the design.

Design invariants enforced here:

- Codes are immutable string constants, banded by stage (E001-E009 ingress,
  E010-E019 format, E020-E039 schema, E040-E069 semantic, E070-E079 cross-ref,
  E080-E099 security, E100-E109 NTIA, E110-E119 signature).
- Each code has exactly one HTTP status and exactly one default severity.
- HTTP precedence is ``413 > 415 > 422 > 400`` — when an ``ErrorReport``
  carries multiple error-severity entries, the highest-priority status wins.
- Reports cap at ``MAX_ENTRIES`` (100). The 101st entry sets ``truncated=True``
  and is dropped — never emit a 50 MB error response.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


# ---------------------------------------------------------------------------
# Error / warning / info code constants
# ---------------------------------------------------------------------------
# Stage 1 — Ingress guard ----------------------------------------------------
E001_SIZE_EXCEEDED = "SBOM_VAL_E001_SIZE_EXCEEDED"
E002_DECOMPRESSED_SIZE_EXCEEDED = "SBOM_VAL_E002_DECOMPRESSED_SIZE_EXCEEDED"
E003_DECOMPRESSION_RATIO_EXCEEDED = "SBOM_VAL_E003_DECOMPRESSION_RATIO_EXCEEDED"
E004_ENCODING_NOT_UTF8 = "SBOM_VAL_E004_ENCODING_NOT_UTF8"
E005_EMPTY_BODY = "SBOM_VAL_E005_EMPTY_BODY"
E006_UNSUPPORTED_COMPRESSION = "SBOM_VAL_E006_UNSUPPORTED_COMPRESSION"

# Stage 2 — Format & version detection --------------------------------------
E010_FORMAT_INDETERMINATE = "SBOM_VAL_E010_FORMAT_INDETERMINATE"
E011_FORMAT_AMBIGUOUS = "SBOM_VAL_E011_FORMAT_AMBIGUOUS"
E012_ENCODING_INDETERMINATE = "SBOM_VAL_E012_ENCODING_INDETERMINATE"
E013_SPEC_VERSION_UNSUPPORTED = "SBOM_VAL_E013_SPEC_VERSION_UNSUPPORTED"
E014_SPEC_VERSION_MISSING = "SBOM_VAL_E014_SPEC_VERSION_MISSING"
E015_SPEC_VERSION_MALFORMED = "SBOM_VAL_E015_SPEC_VERSION_MALFORMED"

# Stage 3 — Structural schema -----------------------------------------------
E020_JSON_PARSE_FAILED = "SBOM_VAL_E020_JSON_PARSE_FAILED"
E021_XML_PARSE_FAILED = "SBOM_VAL_E021_XML_PARSE_FAILED"
E022_YAML_PARSE_FAILED = "SBOM_VAL_E022_YAML_PARSE_FAILED"
E023_TAGVALUE_PARSE_FAILED = "SBOM_VAL_E023_TAGVALUE_PARSE_FAILED"
E024_PROTOBUF_PARSE_FAILED = "SBOM_VAL_E024_PROTOBUF_PARSE_FAILED"
E025_SCHEMA_VIOLATION = "SBOM_VAL_E025_SCHEMA_VIOLATION"
E026_SCHEMA_REQUIRED_FIELD_MISSING = "SBOM_VAL_E026_SCHEMA_REQUIRED_FIELD_MISSING"
E027_SCHEMA_TYPE_MISMATCH = "SBOM_VAL_E027_SCHEMA_TYPE_MISMATCH"
E028_SCHEMA_ENUM_VIOLATION = "SBOM_VAL_E028_SCHEMA_ENUM_VIOLATION"
E029_SCHEMA_FORMAT_VIOLATION = "SBOM_VAL_E029_SCHEMA_FORMAT_VIOLATION"

# Stage 4 — Semantic, SPDX --------------------------------------------------
E040_SPDXID_MALFORMED = "SBOM_VAL_E040_SPDXID_MALFORMED"
E041_DOCUMENT_NAMESPACE_INVALID = "SBOM_VAL_E041_DOCUMENT_NAMESPACE_INVALID"
E042_DATA_LICENSE_INVALID = "SBOM_VAL_E042_DATA_LICENSE_INVALID"
E043_LICENSE_EXPRESSION_INVALID = "SBOM_VAL_E043_LICENSE_EXPRESSION_INVALID"
E044_CHECKSUM_LENGTH_MISMATCH = "SBOM_VAL_E044_CHECKSUM_LENGTH_MISMATCH"
E045_CREATED_TIMESTAMP_INVALID = "SBOM_VAL_E045_CREATED_TIMESTAMP_INVALID"
E046_DESCRIBES_RELATIONSHIP_MISSING = "SBOM_VAL_E046_DESCRIBES_RELATIONSHIP_MISSING"
E047_SPDX_VERSION_FIELD_INCONSISTENT = "SBOM_VAL_E047_SPDX_VERSION_FIELD_INCONSISTENT"

# Stage 4 — Semantic, CycloneDX ---------------------------------------------
E050_SERIAL_NUMBER_INVALID = "SBOM_VAL_E050_SERIAL_NUMBER_INVALID"
E051_BOM_REF_DUPLICATE = "SBOM_VAL_E051_BOM_REF_DUPLICATE"
E052_PURL_INVALID = "SBOM_VAL_E052_PURL_INVALID"
E053_CPE_INVALID = "SBOM_VAL_E053_CPE_INVALID"
E054_HASH_LENGTH_MISMATCH = "SBOM_VAL_E054_HASH_LENGTH_MISMATCH"
E055_BOM_VERSION_INVALID = "SBOM_VAL_E055_BOM_VERSION_INVALID"
E056_METADATA_TIMESTAMP_INVALID = "SBOM_VAL_E056_METADATA_TIMESTAMP_INVALID"
E057_COMPONENT_TYPE_INVALID = "SBOM_VAL_E057_COMPONENT_TYPE_INVALID"

# Stage 5 — Cross-reference integrity ---------------------------------------
E070_DEPENDENCY_REF_DANGLING = "SBOM_VAL_E070_DEPENDENCY_REF_DANGLING"
E071_DEPENDENCY_REF_SELF = "SBOM_VAL_E071_DEPENDENCY_REF_SELF"
E072_RELATIONSHIP_ELEMENT_DANGLING = "SBOM_VAL_E072_RELATIONSHIP_ELEMENT_DANGLING"
E073_EXTERNAL_DOC_REF_INVALID = "SBOM_VAL_E073_EXTERNAL_DOC_REF_INVALID"
W074_DEPENDENCY_CYCLE_DETECTED = "SBOM_VAL_W074_DEPENDENCY_CYCLE_DETECTED"
I075_ORPHAN_COMPONENT = "SBOM_VAL_I075_ORPHAN_COMPONENT"

# Stage 6 — Security checks --------------------------------------------------
E080_JSON_DEPTH_EXCEEDED = "SBOM_VAL_E080_JSON_DEPTH_EXCEEDED"
E081_JSON_ARRAY_LENGTH_EXCEEDED = "SBOM_VAL_E081_JSON_ARRAY_LENGTH_EXCEEDED"
E082_JSON_STRING_LENGTH_EXCEEDED = "SBOM_VAL_E082_JSON_STRING_LENGTH_EXCEEDED"
E083_XML_DTD_FORBIDDEN = "SBOM_VAL_E083_XML_DTD_FORBIDDEN"
E084_XML_EXTERNAL_ENTITY_FORBIDDEN = "SBOM_VAL_E084_XML_EXTERNAL_ENTITY_FORBIDDEN"
E085_XML_ENTITY_EXPANSION = "SBOM_VAL_E085_XML_ENTITY_EXPANSION"
E086_YAML_UNSAFE_TAG = "SBOM_VAL_E086_YAML_UNSAFE_TAG"
E087_PROTOTYPE_POLLUTION_KEY = "SBOM_VAL_E087_PROTOTYPE_POLLUTION_KEY"
E088_EMBEDDED_BLOB_TOO_LARGE = "SBOM_VAL_E088_EMBEDDED_BLOB_TOO_LARGE"
E089_ZIP_BOMB_RATIO = "SBOM_VAL_E089_ZIP_BOMB_RATIO"

# Stage 7 — NTIA minimum elements (warning by default; promoted to error in
# strict mode) --------------------------------------------------------------
W100_NTIA_SUPPLIER_MISSING = "SBOM_VAL_W100_NTIA_SUPPLIER_MISSING"
W101_NTIA_COMPONENT_NAME_MISSING = "SBOM_VAL_W101_NTIA_COMPONENT_NAME_MISSING"
W102_NTIA_COMPONENT_VERSION_MISSING = "SBOM_VAL_W102_NTIA_COMPONENT_VERSION_MISSING"
W103_NTIA_UNIQUE_ID_MISSING = "SBOM_VAL_W103_NTIA_UNIQUE_ID_MISSING"
W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING = "SBOM_VAL_W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING"
W105_NTIA_AUTHOR_MISSING = "SBOM_VAL_W105_NTIA_AUTHOR_MISSING"
W106_NTIA_TIMESTAMP_MISSING = "SBOM_VAL_W106_NTIA_TIMESTAMP_MISSING"

# Stage 8 — Signature -------------------------------------------------------
E110_SIGNATURE_INVALID = "SBOM_VAL_E110_SIGNATURE_INVALID"
E111_SIGNATURE_ALG_UNSUPPORTED = "SBOM_VAL_E111_SIGNATURE_ALG_UNSUPPORTED"
E112_SIGNATURE_KEY_NOT_FOUND = "SBOM_VAL_E112_SIGNATURE_KEY_NOT_FOUND"
W113_SIGNATURE_NOT_PRESENT = "SBOM_VAL_W113_SIGNATURE_NOT_PRESENT"


# ---------------------------------------------------------------------------
# Code → (HTTP status, default severity) mapping
# ---------------------------------------------------------------------------
# Single source of truth. Stages never decide HTTP status — they pick a code
# and the orchestrator reads it from this table. NTIA codes are listed with
# their *default* (warning) severity; ``ntia.py`` promotes them to errors
# in strict mode and the table here remains the source for the strict status.

_CODE_TABLE: dict[str, tuple[int, Severity]] = {
    # Stage 1
    E001_SIZE_EXCEEDED: (413, Severity.ERROR),
    E002_DECOMPRESSED_SIZE_EXCEEDED: (413, Severity.ERROR),
    E003_DECOMPRESSION_RATIO_EXCEEDED: (413, Severity.ERROR),
    E004_ENCODING_NOT_UTF8: (400, Severity.ERROR),
    E005_EMPTY_BODY: (400, Severity.ERROR),
    E006_UNSUPPORTED_COMPRESSION: (415, Severity.ERROR),
    # Stage 2
    E010_FORMAT_INDETERMINATE: (415, Severity.ERROR),
    E011_FORMAT_AMBIGUOUS: (415, Severity.ERROR),
    E012_ENCODING_INDETERMINATE: (415, Severity.ERROR),
    E013_SPEC_VERSION_UNSUPPORTED: (415, Severity.ERROR),
    E014_SPEC_VERSION_MISSING: (422, Severity.ERROR),
    E015_SPEC_VERSION_MALFORMED: (422, Severity.ERROR),
    # Stage 3
    E020_JSON_PARSE_FAILED: (400, Severity.ERROR),
    E021_XML_PARSE_FAILED: (400, Severity.ERROR),
    E022_YAML_PARSE_FAILED: (400, Severity.ERROR),
    E023_TAGVALUE_PARSE_FAILED: (400, Severity.ERROR),
    E024_PROTOBUF_PARSE_FAILED: (400, Severity.ERROR),
    E025_SCHEMA_VIOLATION: (422, Severity.ERROR),
    E026_SCHEMA_REQUIRED_FIELD_MISSING: (422, Severity.ERROR),
    E027_SCHEMA_TYPE_MISMATCH: (422, Severity.ERROR),
    E028_SCHEMA_ENUM_VIOLATION: (422, Severity.ERROR),
    E029_SCHEMA_FORMAT_VIOLATION: (422, Severity.ERROR),
    # Stage 4 — SPDX
    E040_SPDXID_MALFORMED: (422, Severity.ERROR),
    E041_DOCUMENT_NAMESPACE_INVALID: (422, Severity.ERROR),
    E042_DATA_LICENSE_INVALID: (422, Severity.ERROR),
    E043_LICENSE_EXPRESSION_INVALID: (422, Severity.ERROR),
    E044_CHECKSUM_LENGTH_MISMATCH: (422, Severity.ERROR),
    E045_CREATED_TIMESTAMP_INVALID: (422, Severity.ERROR),
    E046_DESCRIBES_RELATIONSHIP_MISSING: (422, Severity.ERROR),
    E047_SPDX_VERSION_FIELD_INCONSISTENT: (422, Severity.ERROR),
    # Stage 4 — CycloneDX
    E050_SERIAL_NUMBER_INVALID: (422, Severity.ERROR),
    E051_BOM_REF_DUPLICATE: (422, Severity.ERROR),
    E052_PURL_INVALID: (422, Severity.ERROR),
    E053_CPE_INVALID: (422, Severity.ERROR),
    E054_HASH_LENGTH_MISMATCH: (422, Severity.ERROR),
    E055_BOM_VERSION_INVALID: (422, Severity.ERROR),
    E056_METADATA_TIMESTAMP_INVALID: (422, Severity.ERROR),
    E057_COMPONENT_TYPE_INVALID: (422, Severity.ERROR),
    # Stage 5
    E070_DEPENDENCY_REF_DANGLING: (422, Severity.ERROR),
    E071_DEPENDENCY_REF_SELF: (422, Severity.ERROR),
    E072_RELATIONSHIP_ELEMENT_DANGLING: (422, Severity.ERROR),
    E073_EXTERNAL_DOC_REF_INVALID: (422, Severity.ERROR),
    W074_DEPENDENCY_CYCLE_DETECTED: (200, Severity.WARNING),
    I075_ORPHAN_COMPONENT: (200, Severity.INFO),
    # Stage 6
    E080_JSON_DEPTH_EXCEEDED: (400, Severity.ERROR),
    E081_JSON_ARRAY_LENGTH_EXCEEDED: (400, Severity.ERROR),
    E082_JSON_STRING_LENGTH_EXCEEDED: (400, Severity.ERROR),
    E083_XML_DTD_FORBIDDEN: (400, Severity.ERROR),
    E084_XML_EXTERNAL_ENTITY_FORBIDDEN: (400, Severity.ERROR),
    E085_XML_ENTITY_EXPANSION: (400, Severity.ERROR),
    E086_YAML_UNSAFE_TAG: (400, Severity.ERROR),
    E087_PROTOTYPE_POLLUTION_KEY: (400, Severity.ERROR),
    E088_EMBEDDED_BLOB_TOO_LARGE: (400, Severity.ERROR),
    E089_ZIP_BOMB_RATIO: (413, Severity.ERROR),
    # Stage 7 — defaults are warnings; ntia.py promotes to errors in strict mode
    W100_NTIA_SUPPLIER_MISSING: (422, Severity.WARNING),
    W101_NTIA_COMPONENT_NAME_MISSING: (422, Severity.WARNING),
    W102_NTIA_COMPONENT_VERSION_MISSING: (422, Severity.WARNING),
    W103_NTIA_UNIQUE_ID_MISSING: (422, Severity.WARNING),
    W104_NTIA_DEPENDENCY_RELATIONSHIP_MISSING: (422, Severity.WARNING),
    W105_NTIA_AUTHOR_MISSING: (422, Severity.WARNING),
    W106_NTIA_TIMESTAMP_MISSING: (422, Severity.WARNING),
    # Stage 8
    E110_SIGNATURE_INVALID: (422, Severity.ERROR),
    E111_SIGNATURE_ALG_UNSUPPORTED: (422, Severity.ERROR),
    E112_SIGNATURE_KEY_NOT_FOUND: (422, Severity.ERROR),
    W113_SIGNATURE_NOT_PRESENT: (200, Severity.WARNING),
}


# HTTP status precedence: 413 > 415 > 422 > 400 > 200. The orchestrator
# picks the highest-priority status across error-severity entries.
_STATUS_PRIORITY: dict[int, int] = {413: 4, 415: 3, 422: 2, 400: 1, 200: 0}

MAX_ENTRIES = 100


def status_for(code: str) -> int:
    """Return the canonical HTTP status for ``code`` (raises if unknown)."""
    return _CODE_TABLE[code][0]


def default_severity_for(code: str) -> Severity:
    """Return the canonical default severity for ``code`` (raises if unknown)."""
    return _CODE_TABLE[code][1]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ValidationError(BaseModel):
    """A single error / warning / info entry produced by any stage."""

    model_config = ConfigDict(frozen=True)

    code: str
    severity: Severity
    stage: str
    path: str
    message: str
    remediation: str
    spec_reference: str | None = None


class ErrorReport(BaseModel):
    """Aggregated entries plus the derived HTTP status and short-circuit flag.

    Mutated only by the orchestrator and stages — never by callers. The
    orchestrator passes ``self`` into each stage's ``run()`` method which may
    append entries via :meth:`add`. Once ``MAX_ENTRIES`` is reached, further
    ``add`` calls flip ``truncated=True`` and silently drop the entry.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    entries: list[ValidationError] = []
    truncated: bool = False

    def add(
        self,
        code: str,
        *,
        stage: str,
        path: str,
        message: str,
        remediation: str,
        spec_reference: str | None = None,
        severity: Severity | None = None,
    ) -> None:
        """Append a new entry. Honours ``MAX_ENTRIES`` truncation."""
        if len(self.entries) >= MAX_ENTRIES:
            self.truncated = True
            return
        sev = severity if severity is not None else default_severity_for(code)
        self.entries.append(
            ValidationError(
                code=code,
                severity=sev,
                stage=stage,
                path=path,
                message=message,
                remediation=remediation,
                spec_reference=spec_reference,
            )
        )

    def has_errors(self) -> bool:
        """True if any entry has severity ``error``."""
        return any(e.severity is Severity.ERROR for e in self.entries)

    @property
    def errors(self) -> list[ValidationError]:
        return [e for e in self.entries if e.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[ValidationError]:
        return [e for e in self.entries if e.severity is Severity.WARNING]

    @property
    def info(self) -> list[ValidationError]:
        return [e for e in self.entries if e.severity is Severity.INFO]

    @property
    def http_status(self) -> int:
        """Return the highest-priority HTTP status across error-severity entries.

        If there are no error-severity entries, return 202 (Accepted). Stage
        precedence is ``413 > 415 > 422 > 400`` per ADR-0007 §5.
        """
        if not self.has_errors():
            return 202
        best_code = 400
        best_priority = -1
        for entry in self.errors:
            status = status_for(entry.code)
            if status == 200:
                continue
            priority = _STATUS_PRIORITY.get(status, 0)
            if priority > best_priority:
                best_priority = priority
                best_code = status
        return best_code

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical JSON shape for the FastAPI ``detail`` field."""
        return {
            "entries": [e.model_dump() for e in self.entries],
            "truncated": self.truncated,
        }
