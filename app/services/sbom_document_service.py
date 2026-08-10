"""SBOM document statistics, raw chunk reads, and integrity helpers."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import SBOMComponent, SBOMSource
from ..parsing.extract import extract_components
from .sbom_service import _canonical_only_clause

log = logging.getLogger(__name__)

DEFAULT_RAW_CHUNK_LIMIT = 500
MAX_RAW_CHUNK_LIMIT = 2000


def content_sha256(text: str | None) -> str | None:
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def count_lines(text: str | None) -> int:
    if not text:
        return 0
    return len(text.splitlines())


def byte_size(text: str | None) -> int:
    if not text:
        return 0
    return len(text.encode("utf-8"))


def parse_sbom_dict(sbom_data: str | None) -> dict[str, Any]:
    if not sbom_data:
        return {}
    try:
        parsed = json.loads(sbom_data) if isinstance(sbom_data, str) else sbom_data
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def detect_format(sbom_dict: dict[str, Any]) -> tuple[str | None, str | None]:
    if sbom_dict.get("bomFormat") == "CycloneDX":
        return "CycloneDX", str(sbom_dict.get("specVersion") or "") or None
    if sbom_dict.get("spdxVersion") or sbom_dict.get("SPDXID"):
        return "SPDX", str(sbom_dict.get("spdxVersion") or "") or None
    if "components" in sbom_dict:
        return "CycloneDX", str(sbom_dict.get("specVersion") or "") or None
    return None, None


def count_graph_edges(sbom_dict: dict[str, Any]) -> tuple[int, int]:
    """Return (dependency_count, relationship_count) from parsed SBOM JSON."""
    if not sbom_dict:
        return 0, 0
    if sbom_dict.get("bomFormat") == "CycloneDX" or "components" in sbom_dict:
        dependencies = sbom_dict.get("dependencies") or []
        return len(dependencies) if isinstance(dependencies, list) else 0, 0
    if sbom_dict.get("spdxVersion") or sbom_dict.get("SPDXID"):
        relationships = sbom_dict.get("relationships") or []
        return 0, len(relationships) if isinstance(relationships, list) else 0
    return 0, 0


def parsed_component_count(sbom_data: str | None) -> int:
    if not sbom_data:
        return 0
    try:
        return len(extract_components(sbom_data))
    except Exception:
        log.debug("parsed_component_count: extract_components failed", exc_info=True)
        return 0


def db_component_counts(db: Session, sbom_id: int) -> tuple[int, int, int]:
    """Return (total_rows, unique_rows, duplicate_rows)."""
    sbom_clause = SBOMComponent.sbom_id == sbom_id
    duplicate_count = int(
        db.scalar(
            select(func.count(SBOMComponent.id)).where(
                sbom_clause,
                SBOMComponent.is_duplicate.is_(True),
            )
        )
        or 0
    )
    unique_count = int(
        db.scalar(select(func.count(SBOMComponent.id)).where(sbom_clause, _canonical_only_clause())) or 0
    )
    return unique_count + duplicate_count, unique_count, duplicate_count


def compute_document_stats(db: Session, sbom: SBOMSource) -> dict[str, Any]:
    sbom_dict = parse_sbom_dict(sbom.sbom_data)
    fmt, spec_version = detect_format(sbom_dict)
    dependency_count, relationship_count = count_graph_edges(sbom_dict)
    total_rows, unique_rows, duplicate_rows = db_component_counts(db, sbom.id)
    parsed_count = parsed_component_count(sbom.sbom_data)
    line_count = count_lines(sbom.sbom_data)
    file_size = byte_size(sbom.sbom_data)
    return {
        "sbom_id": sbom.id,
        "sbom_name": sbom.sbom_name,
        "format": fmt,
        "spec_version": spec_version,
        "file_size_bytes": file_size,
        "line_count": line_count,
        "parsed_component_count": parsed_count,
        "component_count": unique_rows,
        "component_total_rows": total_rows,
        "duplicate_component_count": duplicate_rows,
        "dependency_count": dependency_count,
        "relationship_count": relationship_count,
        "content_sha256": content_sha256(sbom.sbom_data),
        "validation_status": sbom.status,
    }


def read_raw_chunk(
    sbom_data: str | None,
    *,
    offset: int = 0,
    limit: int = DEFAULT_RAW_CHUNK_LIMIT,
) -> dict[str, Any]:
    if not sbom_data:
        return {
            "offset": 0,
            "limit": limit,
            "total_lines": 0,
            "lines": [],
            "preview": False,
            "truncated": False,
        }

    offset = max(0, offset)
    limit = max(1, min(limit, MAX_RAW_CHUNK_LIMIT))
    lines = sbom_data.splitlines()
    total_lines = len(lines)
    chunk = lines[offset : offset + limit]
    return {
        "offset": offset,
        "limit": limit,
        "total_lines": total_lines,
        "lines": chunk,
        "preview": total_lines > limit,
        "truncated": offset + len(chunk) < total_lines,
    }


def verify_upload_integrity(
    db: Session,
    sbom_id: int,
    *,
    original_text: str | None = None,
    original_path: str | None = None,
) -> dict[str, Any]:
    """Compare stored SBOM content against an original file or text payload."""
    from pathlib import Path

    sbom = db.get(SBOMSource, sbom_id)
    if sbom is None:
        raise ValueError(f"SBOM {sbom_id} not found")

    if original_path:
        path = Path(original_path)
        original_text = path.read_text(encoding="utf-8", errors="replace")
        original_bytes = path.read_bytes()
        original_sha = hashlib.sha256(original_bytes).hexdigest()
        original_lines = count_lines(original_text)
        original_size = len(original_bytes)
    elif original_text is not None:
        original_sha = content_sha256(original_text)
        original_lines = count_lines(original_text)
        original_size = byte_size(original_text)
    else:
        raise ValueError("original_text or original_path is required")

    stored_text = sbom.sbom_data or ""
    stored_sha = content_sha256(stored_text)
    stats = compute_document_stats(db, sbom)

    return {
        "sbom_id": sbom_id,
        "original_file_path": original_path,
        "original_size_bytes": original_size,
        "original_line_count": original_lines,
        "original_sha256": original_sha,
        "stored_size_bytes": stats["file_size_bytes"],
        "stored_line_count": stats["line_count"],
        "stored_sha256": stored_sha,
        "sha256_match": bool(original_sha and stored_sha and original_sha == stored_sha),
        "line_count_match": original_lines == stats["line_count"],
        "parsed_component_count": stats["parsed_component_count"],
        "db_component_count": stats["component_count"],
        "component_count_match": stats["parsed_component_count"] == stats["component_count"],
        "truncation_detected": bool(
            original_sha and stored_sha and original_sha != stored_sha
        )
        or original_lines != stats["line_count"],
        "validation_status": sbom.status,
    }


__all__ = [
    "DEFAULT_RAW_CHUNK_LIMIT",
    "MAX_RAW_CHUNK_LIMIT",
    "byte_size",
    "compute_document_stats",
    "content_sha256",
    "count_lines",
    "db_component_counts",
    "parsed_component_count",
    "detect_format",
    "parse_sbom_dict",
    "read_raw_chunk",
    "verify_upload_integrity",
]
