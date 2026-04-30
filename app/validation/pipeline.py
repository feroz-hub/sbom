"""Validation pipeline orchestrator — runs the eight stages in order.

Stages are pure callables ``run(ctx) -> ctx``. The orchestrator short-circuits
to "fail" after a stage that emits an error-severity entry, **except** that
stage 7 (NTIA) always runs so the user gets a complete report. All other
stages (1, 2, 3, 4, 5, 6, 8) abort on prior errors.

Mutations on ``ctx`` must be additive — see :class:`ValidationContext` for
the slot ownership rules.

The pipeline is not async because each stage is CPU-bound (parse, walk, hash
compare). The async-vs-sync hand-off lives **above** the pipeline: the
FastAPI handler decides whether to run synchronously or enqueue a Celery
task, and the pipeline itself runs the same way in both paths.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Protocol

from .context import ValidationContext
from .errors import ErrorReport
from .stages import (
    detect,
    ingress,
    integrity,
    ntia,
    schema,
    security,
    semantic_cyclonedx,
    semantic_spdx,
    semantic_spdx3,
    signature,
)

log = logging.getLogger(__name__)


class Stage(Protocol):
    """Every pipeline stage exposes a ``name`` and a ``run`` function."""

    name: str

    def run(self, ctx: ValidationContext) -> ValidationContext: ...


class _CallableStage:
    """Wrap a module-level ``run`` function as a :class:`Stage`."""

    __slots__ = ("name", "_run", "_skip_on_errors")

    def __init__(self, name: str, run, *, skip_on_errors: bool = True) -> None:
        self.name = name
        self._run = run
        self._skip_on_errors = skip_on_errors

    def run(self, ctx: ValidationContext) -> ValidationContext:
        if self._skip_on_errors and ctx.report.has_errors():
            return ctx
        return self._run(ctx)


def default_stages() -> list[Stage]:
    """Return the canonical 8-stage ordering used in production.

    The semantic stage dispatches on ``ctx.spec`` / ``ctx.spec_version``;
    SPDX 2.x → :mod:`semantic_spdx`, SPDX 3.0 → :mod:`semantic_spdx3` (deferred,
    rejects at stage 2 today), CycloneDX → :mod:`semantic_cyclonedx`.
    """

    def _semantic_dispatch(ctx: ValidationContext) -> ValidationContext:
        if ctx.spec == "spdx":
            major = (ctx.spec_version or "").upper()
            if major.startswith("SPDX-3") or major.startswith("3."):
                return semantic_spdx3.run(ctx)
            return semantic_spdx.run(ctx)
        if ctx.spec == "cyclonedx":
            return semantic_cyclonedx.run(ctx)
        return ctx

    return [
        _CallableStage("ingress", ingress.run, skip_on_errors=False),
        _CallableStage("detect", detect.run),
        _CallableStage("schema", schema.run),
        _CallableStage("semantic", _semantic_dispatch),
        _CallableStage("integrity", integrity.run),
        _CallableStage("security", security.run),
        # NTIA always runs so the user sees its warnings even when an earlier
        # stage failed — this gives a more complete report on partial input.
        _CallableStage("ntia", ntia.run, skip_on_errors=False),
        _CallableStage("signature", signature.run),
    ]


def run(
    raw_bytes: bytes,
    *,
    content_encoding: str | None = None,
    strict_ntia: bool = False,
    verify_signature: bool = False,
    stages: Iterable[Stage] | None = None,
) -> ErrorReport:
    """Run the full pipeline against ``raw_bytes`` and return the report.

    Parameters
    ----------
    raw_bytes:
        The uploaded SBOM bytes, *before* any decoding. Stage 1 owns
        decompression, BOM stripping, and UTF-8 enforcement.
    content_encoding:
        HTTP ``Content-Encoding`` header (``gzip`` etc.) or ``None``.
    strict_ntia:
        When true, NTIA warnings (W100-W106) are promoted to errors.
    verify_signature:
        When true, stage 8 verifies any embedded signature. Default off.
    stages:
        Override the default stage list — used by tests to swap individual
        stages with stubs.
    """
    ctx = ValidationContext(
        raw_bytes=raw_bytes,
        content_encoding=content_encoding,
        strict_ntia=strict_ntia,
        verify_signature=verify_signature,
    )
    pipeline = list(stages) if stages is not None else default_stages()
    for stage in pipeline:
        try:
            ctx = stage.run(ctx)
        except Exception as exc:  # pragma: no cover — logged for tracing
            # A stage raising is a bug; do not leak the exception text into
            # the response. Map to a synthetic schema-violation error so the
            # caller gets a stable shape, and log full detail server-side.
            log.exception(
                "validation stage %s raised %s — promoted to E025",
                stage.name,
                type(exc).__name__,
            )
            ctx.report.add(
                "SBOM_VAL_E025_SCHEMA_VIOLATION",
                stage=stage.name,
                path="",
                message=f"Internal validator error in stage '{stage.name}'.",
                remediation=(
                    "This is a bug in the validator, not your SBOM. "
                    "Please re-upload; if the problem persists, contact support."
                ),
            )
            break
    return ctx.report


def get_internal_model(report: ErrorReport, ctx: ValidationContext | None = None):
    """Convenience accessor for callers that want the normalised SBOM after a
    successful run. ``None`` if validation failed or normalize never ran."""
    if ctx is None:
        return None
    return ctx.internal_model
