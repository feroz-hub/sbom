"""Stage 6 — defensive security checks.

Two responsibilities:

1. **The depth-/breadth-/length-capped JSON decoder.** Defined here, but
   *invoked from stage 2 (detect)* — that's the only JSON parse in the
   pipeline, so depth bombs are caught at parse time, not after schema
   short-circuits. The decoder lives here because the cap constants and
   the error mapping all belong with the rest of the stage-6 surface.

2. **Walk the parsed document looking for prototype-pollution keys and
   oversized embedded blobs.** Constant-time per node.

The depth-capped decoder is implemented as a custom :class:`json.JSONDecoder`
subclass with hooks on ``parse_object`` / ``parse_array`` / ``parse_string``.
We do **not** parse first and walk after — that's how depth bombs win.

XML and Tag-Value paths have their security gating built into the parsers
already (defusedxml + spdx-tools). For those, this stage is a walk-only pass.
"""

from __future__ import annotations

import json
from json.scanner import py_make_scanner
from typing import Any

from .. import errors as E
from ..context import ValidationContext

_STAGE = "security"

MAX_DEPTH = 64
MAX_ARRAY_LENGTH = 1_000_000
MAX_STRING_LENGTH = 65_536
MAX_EMBEDDED_BLOB_BYTES = 1_024 * 1_024  # 1 MB

_FORBIDDEN_KEYS = frozenset({"__proto__", "constructor", "prototype"})

# Hash content fields are allowed to carry large hex strings without tripping
# the embedded-blob guard.
_KNOWN_BLOB_FIELDS = frozenset(
    {
        "content",  # cyclonedx hashes[].content
        "checksumValue",  # spdx checksums[].checksumValue
        "digest",
        "value",
    }
)


def run(ctx: ValidationContext) -> ValidationContext:
    """Walk the parsed document for prototype-pollution / oversized blobs.

    The depth-/breadth-/length-capped JSON decoder lives in stage 2 (detect)
    so a depth bomb is rejected *during the parse*, not after. Stage 6
    therefore inspects ``ctx.parsed_dict`` only — the document already
    survived every cap.
    """
    if ctx.text is None:
        return ctx
    parsed = ctx.parsed_dict
    if isinstance(parsed, dict):
        _walk(parsed, "", ctx)
    return ctx


# ---------------------------------------------------------------------------
# Capped JSON decoder
# ---------------------------------------------------------------------------


class _CappedDecodeError(Exception):
    """Raised mid-parse to abort decoding when a cap is exceeded.

    Carries the offending code + path so the caller can attach to the report
    without inspecting the exception message.
    """

    def __init__(self, code: str, path: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.message = message


def _remediation_for(code: str) -> str:
    if code == E.E080_JSON_DEPTH_EXCEEDED:
        return f"Real SBOMs do not exceed {MAX_DEPTH} levels of JSON nesting."
    if code == E.E081_JSON_ARRAY_LENGTH_EXCEEDED:
        return "Split the document or remove the offending array."
    if code == E.E082_JSON_STRING_LENGTH_EXCEEDED:
        return "Encoded payloads larger than 64 KB belong in a separate file referenced by URL."
    return ""


class _CappedJSONDecoder(json.JSONDecoder):
    """:class:`json.JSONDecoder` subclass that aborts on depth / size caps.

    The stdlib decoder exposes :func:`json.scanner.py_make_scanner` and uses
    bound :data:`parse_object` / :data:`parse_array` / :data:`parse_string`
    attributes. Overriding those *before* we ask :func:`py_make_scanner` to
    re-bind us gives us the cheapest possible per-node check (no extra
    function calls except when a cap is approached).

    Counters live on the decoder instance, not module-level, so concurrent
    callers don't share state.
    """

    def __init__(self) -> None:
        super().__init__()
        self._depth = 0
        self._path: list[str] = []
        # Re-bind hooks then re-make the scanner so it picks them up.
        self.parse_object = self._parse_object  # type: ignore[assignment]
        self.parse_array = self._parse_array  # type: ignore[assignment]
        self.parse_string = self._parse_string  # type: ignore[assignment]
        self.scan_once = py_make_scanner(self)

    def _parse_string(self, s: str, end: int, *args: Any, **kwargs: Any):  # noqa: ANN202
        result, idx = json.decoder.scanstring(s, end, self.strict)  # type: ignore[attr-defined]
        if len(result) > MAX_STRING_LENGTH:
            raise _CappedDecodeError(
                E.E082_JSON_STRING_LENGTH_EXCEEDED,
                ".".join(self._path) or "(root)",
                (
                    f"JSON string at {'.'.join(self._path) or '(root)'} length "
                    f"{len(result)} exceeds {MAX_STRING_LENGTH}."
                ),
            )
        return result, idx

    def _parse_object(  # noqa: ANN202
        self,
        s_and_end: tuple[str, int],
        strict: bool,
        scan_once: Any,
        object_hook: Any,
        object_pairs_hook: Any,
        memo: Any = None,
        _w: Any = None,
        _ws: Any = None,
    ):
        self._depth += 1
        if self._depth > MAX_DEPTH:
            raise _CappedDecodeError(
                E.E080_JSON_DEPTH_EXCEEDED,
                ".".join(self._path) or "(root)",
                f"JSON nesting depth {self._depth} exceeds {MAX_DEPTH}.",
            )
        try:
            return json.decoder.JSONObject(  # type: ignore[attr-defined]
                s_and_end,
                strict,
                scan_once,
                object_hook,
                object_pairs_hook,
                memo=memo,
            )
        finally:
            self._depth -= 1

    def _parse_array(  # noqa: ANN202
        self,
        s_and_end: tuple[str, int],
        scan_once: Any,
        _w: Any = None,
        _ws: Any = None,
    ):
        self._depth += 1
        if self._depth > MAX_DEPTH:
            raise _CappedDecodeError(
                E.E080_JSON_DEPTH_EXCEEDED,
                ".".join(self._path) or "(root)",
                f"JSON nesting depth {self._depth} exceeds {MAX_DEPTH}.",
            )
        try:
            arr, end = json.decoder.JSONArray(s_and_end, scan_once)  # type: ignore[attr-defined]
        finally:
            self._depth -= 1
        if len(arr) > MAX_ARRAY_LENGTH:
            raise _CappedDecodeError(
                E.E081_JSON_ARRAY_LENGTH_EXCEEDED,
                ".".join(self._path) or "(root)",
                f"JSON array length {len(arr)} exceeds {MAX_ARRAY_LENGTH}.",
            )
        return arr, end


# ---------------------------------------------------------------------------
# Walk: prototype-pollution keys, oversized embedded blobs
# ---------------------------------------------------------------------------


def _walk(node: Any, path: str, ctx: ValidationContext) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            sub_path = f"{path}.{key}" if path else key
            if key in _FORBIDDEN_KEYS:
                ctx.report.add(
                    E.E087_PROTOTYPE_POLLUTION_KEY,
                    stage=_STAGE,
                    path=sub_path,
                    message=f"Object key '{key}' at {sub_path} is forbidden.",
                    remediation=(
                        "Forbidden keys: __proto__, constructor, prototype. They enable "
                        "prototype-pollution attacks against downstream JS consumers."
                    ),
                )
                continue
            if isinstance(value, str) and len(value) > MAX_EMBEDDED_BLOB_BYTES and key not in _KNOWN_BLOB_FIELDS:
                ctx.report.add(
                    E.E088_EMBEDDED_BLOB_TOO_LARGE,
                    stage=_STAGE,
                    path=sub_path,
                    message=(
                        f"Embedded blob at {sub_path} is {len(value)} bytes (> 1 MB) "
                        "and is not a known content field."
                    ),
                    remediation=(
                        "Move the blob to a referenced URL, or use one of the standard "
                        "hash content fields."
                    ),
                )
                continue
            _walk(value, sub_path, ctx)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            _walk(item, f"{path}[{index}]", ctx)
