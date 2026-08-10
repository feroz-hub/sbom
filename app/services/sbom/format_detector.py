"""Content-based SBOM format detection."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Literal

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

SbomDetectedFormat = Literal[
    "cyclonedx_json",
    "cyclonedx_xml",
    "spdx_json",
    "spdx_tag_value",
    "unknown",
]


@dataclass(slots=True)
class SbomFormatDetection:
    format: SbomDetectedFormat
    spec_version: str | None = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def family(self) -> str | None:
        if self.format.startswith("cyclonedx"):
            return "cyclonedx"
        if self.format.startswith("spdx"):
            return "spdx"
        return None


_BOM_FORMAT_RE = re.compile(r'"bomFormat"\s*:\s*"CycloneDX"', re.IGNORECASE)
_SPEC_VERSION_RE = re.compile(r'"specVersion"\s*:\s*"([^"]+)"', re.IGNORECASE)
_SPDX_VERSION_RE = re.compile(r'"spdxVersion"\s*:\s*"([^"]+)"', re.IGNORECASE)


def detect_sbom_format_from_bytes(payload: bytes, *, sample_size: int = 1024 * 1024) -> SbomFormatDetection:
    sample = payload[:sample_size].decode("utf-8", errors="replace")
    return detect_sbom_format(sample)


def detect_sbom_format(content: str) -> SbomFormatDetection:
    text = (content or "").lstrip("\ufeff \t\r\n")
    if not text:
        return SbomFormatDetection("unknown", confidence=0.0, warnings=["empty content"])

    json_result = _detect_json(text)
    if json_result:
        return json_result

    tag_value_result = _detect_spdx_tag_value(text)
    if tag_value_result:
        return tag_value_result

    xml_result = _detect_xml(text)
    if xml_result:
        return xml_result

    return SbomFormatDetection("unknown", confidence=0.0, warnings=["no supported SBOM signature found"])


def _detect_json(text: str) -> SbomFormatDetection | None:
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        parsed = None
        parse_warning = f"json parse failed: {exc.__class__.__name__}"
    else:
        parse_warning = ""

    if isinstance(parsed, dict):
        if "spdxVersion" in parsed:
            evidence = ["spdxVersion present"]
            if "SPDXID" in parsed:
                evidence.append("SPDXID present")
            if "packages" in parsed:
                evidence.append("packages present")
            return SbomFormatDetection(
                "spdx_json",
                spec_version=str(parsed.get("spdxVersion") or "") or None,
                confidence=0.99,
                evidence=evidence,
            )
        if str(parsed.get("bomFormat") or "").lower() == "cyclonedx":
            evidence = ["bomFormat=CycloneDX"]
            if "components" in parsed:
                evidence.append("components present")
            return SbomFormatDetection(
                "cyclonedx_json",
                spec_version=str(parsed.get("specVersion") or "") or None,
                confidence=0.99,
                evidence=evidence,
            )

    # Fallback for malformed/truncated JSON where the identifying fields are
    # near the top of the document. This is detection only; validation still
    # runs against the full stored content.
    if _BOM_FORMAT_RE.search(text[:65536]):
        version_match = _SPEC_VERSION_RE.search(text[:65536])
        return SbomFormatDetection(
            "cyclonedx_json",
            spec_version=version_match.group(1) if version_match else None,
            confidence=0.82,
            evidence=["bomFormat=CycloneDX"],
            warnings=[parse_warning] if parse_warning else [],
        )
    spdx_match = _SPDX_VERSION_RE.search(text[:65536])
    if spdx_match:
        return SbomFormatDetection(
            "spdx_json",
            spec_version=spdx_match.group(1),
            confidence=0.82,
            evidence=["spdxVersion present"],
            warnings=[parse_warning] if parse_warning else [],
        )
    return None


def _detect_spdx_tag_value(text: str) -> SbomFormatDetection | None:
    for line in text.splitlines()[:20]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("spdxversion:"):
            version = stripped.split(":", 1)[1].strip() or None
            return SbomFormatDetection(
                "spdx_tag_value",
                spec_version=version,
                confidence=0.95,
                evidence=["SPDXVersion tag-value header"],
            )
        break
    return None


def _detect_xml(text: str) -> SbomFormatDetection | None:
    if not text.startswith("<"):
        return None
    sample = text[:65536]
    try:
        root = ET.fromstring(sample)
    except DefusedXmlException:
        return SbomFormatDetection("unknown", confidence=0.0, warnings=["xml security violation"])
    except ET.ParseError:
        lowered = sample.lower()
        if "<bom" in lowered and "cyclonedx" in lowered:
            version_match = re.search(r'version="([^"]+)"', sample, re.IGNORECASE)
            return SbomFormatDetection(
                "cyclonedx_xml",
                spec_version=version_match.group(1) if version_match else None,
                confidence=0.72,
                evidence=["CycloneDX XML bom root"],
                warnings=["xml parse failed on sample"],
            )
        return None
    tag = root.tag.lower()
    if tag.endswith("bom") and ("cyclonedx" in tag or "cyclonedx" in sample.lower()):
        return SbomFormatDetection(
            "cyclonedx_xml",
            spec_version=root.attrib.get("version"),
            confidence=0.96,
            evidence=["CycloneDX XML root"],
        )
    return None
