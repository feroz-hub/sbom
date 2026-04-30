"""Validation context — the mutable accumulator threaded through all stages.

Each stage reads what it needs and writes only into the slots it owns.
Slots become populated as the pipeline progresses:

  Stage 1 (ingress)  → ``raw_bytes``, ``text``
  Stage 2 (detect)   → ``spec``, ``spec_version``, ``encoding``
  Stage 3 (schema)   → ``parsed_dict``
  Stage 4 (semantic) → ``internal_model`` (via stages.normalize)
  Stages 5-8 read the internal model.

The dataclass is intentionally untyped-Pydantic — the ``parsed_dict`` field
can be a deeply nested ``dict[str, Any]`` whose shape varies by SBOM spec,
and Pydantic validation here would be circular: stage 3 *is* the schema check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .errors import ErrorReport
from .models import InternalSbom

Spec = Literal["spdx", "cyclonedx"]
Encoding = Literal["json", "xml", "yaml", "tag-value", "protobuf"]


@dataclass
class ValidationContext:
    """Accumulator threaded through every stage.

    Mutations are additive only. Stages append to ``report`` and write into
    their own slots; they never overwrite peer slots. The orchestrator may
    short-circuit between stages when ``report.has_errors()`` becomes true.
    """

    # Inputs ---------------------------------------------------------------
    raw_bytes: bytes
    content_encoding: str | None = None  # HTTP Content-Encoding header (gzip, …)
    strict_ntia: bool = False
    verify_signature: bool = False

    # Stage outputs --------------------------------------------------------
    text: str | None = None
    spec: Spec | None = None
    spec_version: str | None = None
    encoding: Encoding | None = None
    parsed_dict: dict[str, Any] | None = None
    internal_model: InternalSbom | None = None

    # Always-on accumulator -----------------------------------------------
    report: ErrorReport = field(default_factory=ErrorReport)
