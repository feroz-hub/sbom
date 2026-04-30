"""Stage 1 — ingress guard.

Owns: hard size cap, decompression-bomb defence, BOM handling, UTF-8 assertion.

Limits live in :mod:`app.settings`:

  * ``MAX_UPLOAD_BYTES``        — uploaded body cap (default 50 MB)
  * ``MAX_DECOMPRESSED_BYTES``  — post-decompression cap (default 200 MB)
  * ``MAX_DECOMPRESSION_RATIO`` — gzip / deflate ratio cap (default 100)

Stage 1 is the only stage that runs even when prior errors exist — it has
no priors. It still appends to ``ctx.report`` rather than raising so the
orchestrator can keep its single error-handling path.
"""

from __future__ import annotations

import codecs
import gzip
import io
import zlib

from .. import errors as E
from ..context import ValidationContext

_STAGE = "ingress"

# UTF-8 BOM is the only BOM we *strip* (silently). Other BOMs trigger E004.
_UTF8_BOM = b"\xef\xbb\xbf"
_UTF16_LE_BOM = b"\xff\xfe"
_UTF16_BE_BOM = b"\xfe\xff"
_UTF32_LE_BOM = b"\xff\xfe\x00\x00"
_UTF32_BE_BOM = b"\x00\x00\xfe\xff"


def run(ctx: ValidationContext) -> ValidationContext:
    """Validate and decode ``ctx.raw_bytes`` into ``ctx.text``."""
    settings = _load_limits()
    body = ctx.raw_bytes

    if not body:
        ctx.report.add(
            E.E005_EMPTY_BODY,
            stage=_STAGE,
            path="",
            message="Request body is empty.",
            remediation="Provide a non-empty SBOM document.",
        )
        return ctx

    if len(body) > settings["max_upload"]:
        ctx.report.add(
            E.E001_SIZE_EXCEEDED,
            stage=_STAGE,
            path="",
            message=(
                f"Uploaded body of {len(body)} bytes exceeds MAX_UPLOAD_BYTES "
                f"({settings['max_upload']})."
            ),
            remediation=(
                "Compress the SBOM, split into multi-part, or contact your "
                "operator to raise the limit."
            ),
        )
        return ctx

    decompressed = _decompress(body, ctx.content_encoding, settings, ctx)
    if decompressed is None:
        return ctx  # error already appended

    if len(decompressed) > settings["max_decompressed"]:
        ctx.report.add(
            E.E002_DECOMPRESSED_SIZE_EXCEEDED,
            stage=_STAGE,
            path="",
            message=(
                f"Decompressed body of {len(decompressed)} bytes exceeds "
                f"MAX_DECOMPRESSED_BYTES ({settings['max_decompressed']})."
            ),
            remediation=(
                "Verify that the SBOM is not a decompression bomb. Real SBOMs "
                "decompress to < 200 MB."
            ),
        )
        return ctx

    cleaned, encoding_error = _strip_bom_and_decode(decompressed)
    if encoding_error is not None:
        ctx.report.add(
            E.E004_ENCODING_NOT_UTF8,
            stage=_STAGE,
            path="",
            message=encoding_error,
            remediation=(
                "Re-encode the SBOM as UTF-8. UTF-16 / UTF-32 BOMs are not "
                "accepted."
            ),
        )
        return ctx

    ctx.text = cleaned
    return ctx


def _load_limits() -> dict[str, int]:
    """Read limits from app.settings. Defaults match ADR-0007 §4.1.

    The local import keeps :mod:`app.validation` free of an import-time
    dependency on the settings singleton — the import-linter contract
    forbids ``app.validation -> app.routers/app.main/app.services``, but
    settings reads are explicitly allowed.
    """
    try:
        from app.settings import get_settings

        s = get_settings()
        return {
            "max_upload": int(getattr(s, "MAX_UPLOAD_BYTES", 50 * 1024 * 1024)),
            "max_decompressed": int(getattr(s, "MAX_DECOMPRESSED_BYTES", 200 * 1024 * 1024)),
            "max_ratio": int(getattr(s, "MAX_DECOMPRESSION_RATIO", 100)),
        }
    except Exception:
        return {
            "max_upload": 50 * 1024 * 1024,
            "max_decompressed": 200 * 1024 * 1024,
            "max_ratio": 100,
        }


def _decompress(
    body: bytes,
    content_encoding: str | None,
    limits: dict[str, int],
    ctx: ValidationContext,
) -> bytes | None:
    """Return decompressed bytes (or original) or ``None`` after recording an error."""
    if not content_encoding or content_encoding.lower() in ("identity", ""):
        return body

    encoding = content_encoding.lower().strip()
    if encoding not in {"gzip", "deflate"}:
        ctx.report.add(
            E.E006_UNSUPPORTED_COMPRESSION,
            stage=_STAGE,
            path="",
            message=f"Content-Encoding '{content_encoding}' is not supported.",
            remediation=(
                "Use identity, gzip, or deflate. Brotli / zstd are not yet "
                "supported by the validator."
            ),
        )
        return None

    max_total = limits["max_decompressed"]
    max_ratio = limits["max_ratio"]
    try:
        if encoding == "gzip":
            decoder = gzip.GzipFile(fileobj=io.BytesIO(body))
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = decoder.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_total + 1:
                    ctx.report.add(
                        E.E002_DECOMPRESSED_SIZE_EXCEEDED,
                        stage=_STAGE,
                        path="",
                        message=(
                            f"Decompressed body exceeded MAX_DECOMPRESSED_BYTES "
                            f"({max_total}) mid-stream."
                        ),
                        remediation=(
                            "Verify that the SBOM is not a decompression bomb."
                        ),
                    )
                    return None
                if len(body) > 0 and total / len(body) > max_ratio:
                    ctx.report.add(
                        E.E003_DECOMPRESSION_RATIO_EXCEEDED,
                        stage=_STAGE,
                        path="",
                        message=(
                            f"Decompression ratio {total // max(1, len(body))}:1 "
                            f"exceeds {max_ratio}:1 limit."
                        ),
                        remediation=(
                            "The compressed payload expanded too aggressively to "
                            "be a legitimate SBOM."
                        ),
                    )
                    return None
                chunks.append(chunk)
            return b"".join(chunks)
        # deflate
        decompressed = zlib.decompress(body)
        if len(decompressed) > max_total:
            ctx.report.add(
                E.E002_DECOMPRESSED_SIZE_EXCEEDED,
                stage=_STAGE,
                path="",
                message=(
                    f"Decompressed body of {len(decompressed)} bytes exceeds "
                    f"MAX_DECOMPRESSED_BYTES ({max_total})."
                ),
                remediation="Verify that the SBOM is not a decompression bomb.",
            )
            return None
        if len(body) > 0 and len(decompressed) / len(body) > max_ratio:
            ctx.report.add(
                E.E003_DECOMPRESSION_RATIO_EXCEEDED,
                stage=_STAGE,
                path="",
                message=(
                    f"Decompression ratio {len(decompressed) // max(1, len(body))}:1 "
                    f"exceeds {max_ratio}:1 limit."
                ),
                remediation=(
                    "The compressed payload expanded too aggressively to be a "
                    "legitimate SBOM."
                ),
            )
            return None
        return decompressed
    except (OSError, zlib.error) as exc:
        ctx.report.add(
            E.E020_JSON_PARSE_FAILED,  # transport-level failure surfaces as parse fail
            stage=_STAGE,
            path="",
            message=f"Failed to decompress {encoding}: {exc}",
            remediation="Verify the body matches the declared Content-Encoding.",
        )
        return None


def _strip_bom_and_decode(body: bytes) -> tuple[str, str | None]:
    """Strip a UTF-8 BOM if present, reject other BOMs, and decode UTF-8."""
    if body.startswith(_UTF32_LE_BOM) or body.startswith(_UTF32_BE_BOM):
        return "", "Body starts with a UTF-32 BOM."
    if body.startswith(_UTF16_LE_BOM) or body.startswith(_UTF16_BE_BOM):
        return "", "Body starts with a UTF-16 BOM."
    if body.startswith(_UTF8_BOM):
        body = body[len(_UTF8_BOM) :]
    try:
        return codecs.decode(body, "utf-8", errors="strict"), None
    except UnicodeDecodeError as exc:
        return "", f"Body is not valid UTF-8 (offset {exc.start}): {exc.reason}"


