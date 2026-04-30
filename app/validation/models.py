"""Internal SBOM model — the spec-neutral shape that stages 5-8 consume.

The model intentionally captures only what downstream stages need to reason
about: dependency edges, component identifiers, document-level metadata for
NTIA, and the raw signature block (if any). Spec-specific extensions are
preserved on each component as ``raw`` so semantic stages can re-read them
without re-parsing the document.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Component(BaseModel):
    """A single component / package, normalised across SPDX and CycloneDX."""

    model_config = ConfigDict(frozen=False)

    ref: str  # bom-ref (CycloneDX) or SPDXID (SPDX) — must be unique in the document
    name: str | None = None
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    hashes: list[dict[str, str]] = Field(default_factory=list)  # [{alg, content}, …]
    supplier: str | None = None
    type: str | None = None  # CycloneDX type or SPDX category
    licenses: list[str] = Field(default_factory=list)
    raw_path: str = ""  # JSONPath into the source doc, for error.path
    raw: dict[str, Any] = Field(default_factory=dict)  # untouched original entry


class DependencyEdge(BaseModel):
    """A single ref → ref dependency. SPDX relationships and CycloneDX
    ``dependencies[]`` are both flattened into this shape."""

    model_config = ConfigDict(frozen=True)

    source: str
    target: str
    kind: str = "DEPENDS_ON"  # SPDX relationshipType, or "DEPENDS_ON" for CycloneDX


class DocumentMetadata(BaseModel):
    """Top-level metadata used by stage 7 (NTIA)."""

    model_config = ConfigDict(frozen=False)

    document_namespace: str | None = None  # SPDX
    serial_number: str | None = None  # CycloneDX
    bom_version: int | None = None  # CycloneDX top-level "version"
    spec_version: str | None = None
    data_license: str | None = None  # SPDX
    name: str | None = None
    creators: list[str] = Field(default_factory=list)
    created: str | None = None  # ISO-8601 timestamp


class InternalSbom(BaseModel):
    """The spec-neutral internal model produced by stage 4 / normalize."""

    model_config = ConfigDict(frozen=False)

    spec: str  # "spdx" | "cyclonedx"
    spec_version: str
    metadata: DocumentMetadata
    components: list[Component] = Field(default_factory=list)
    dependencies: list[DependencyEdge] = Field(default_factory=list)
    declared_refs: set[str] = Field(default_factory=set)
    document_refs: set[str] = Field(default_factory=set)  # SPDX externalDocumentRefs
    signature_block: dict[str, Any] | None = None
    raw_dict: dict[str, Any] = Field(default_factory=dict)
