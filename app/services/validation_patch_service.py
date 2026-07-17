"""Safe patch application for validation repair sessions."""

from __future__ import annotations

import copy
import json
from typing import Any


class PatchApplyError(ValueError):
    """Raised when a user-approved patch cannot be applied safely."""


def apply_repair_patches(content: str, patches: list[dict[str, Any]]) -> str:
    """Apply selected repair patches and return the updated content.

    JSON content uses JSON Pointer targets. Non-JSON content is limited to
    exact text replacement because XML/YAML/SPDX structure-preserving patching
    has too many unsafe edge cases for a generic repair endpoint.
    """
    if not patches:
        raise PatchApplyError("No patches selected.")
    stripped = (content or "").lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return _apply_json_patches(content, patches)
    return _apply_text_patches(content, patches)


def _apply_json_patches(content: str, patches: list[dict[str, Any]]) -> str:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PatchApplyError(f"Current content is not valid JSON: {exc.msg}") from exc

    updated = copy.deepcopy(data)
    for patch in patches:
        op = str(patch.get("operation") or "").lower()
        target = str(patch.get("target") or "")
        if op not in {"add", "replace", "remove"}:
            raise PatchApplyError(f"Unsupported JSON patch operation: {op or '<missing>'}")
        if not target.startswith("/"):
            raise PatchApplyError("JSON patch target must be a JSON Pointer.")
        parent, key = _resolve_parent(updated, target, create_missing=(op == "add"))
        if isinstance(parent, list):
            index = _list_index(key, parent, allow_end=(op == "add"))
            if op == "add":
                parent.insert(index, patch.get("after"))
            elif op == "replace":
                if index >= len(parent):
                    raise PatchApplyError(f"JSON Pointer target does not exist: {target}")
                _assert_before(parent[index], patch.get("before"), target)
                parent[index] = patch.get("after")
            else:
                if index >= len(parent):
                    raise PatchApplyError(f"JSON Pointer target does not exist: {target}")
                _assert_before(parent[index], patch.get("before"), target)
                parent.pop(index)
            continue

        if not isinstance(parent, dict):
            raise PatchApplyError(f"JSON Pointer parent is not editable: {target}")
        if op == "add":
            parent[key] = patch.get("after")
        elif op == "replace":
            if key not in parent:
                raise PatchApplyError(f"JSON Pointer target does not exist: {target}")
            _assert_before(parent[key], patch.get("before"), target)
            parent[key] = patch.get("after")
        else:
            if key not in parent:
                raise PatchApplyError(f"JSON Pointer target does not exist: {target}")
            _assert_before(parent[key], patch.get("before"), target)
            del parent[key]

    return json.dumps(updated, indent=2, ensure_ascii=False) + "\n"


def _apply_text_patches(content: str, patches: list[dict[str, Any]]) -> str:
    updated = content
    for patch in patches:
        op = str(patch.get("operation") or "").lower()
        if op not in {"replace", "remove"}:
            raise PatchApplyError("Only exact replace/remove text patches are supported for non-JSON SBOMs.")
        before = patch.get("before")
        if not isinstance(before, str) or before == "":
            raise PatchApplyError("Text patches require a non-empty 'before' value.")
        count = updated.count(before)
        if count != 1:
            raise PatchApplyError("Text patch 'before' value must match exactly once.")
        after = "" if op == "remove" else patch.get("after")
        if not isinstance(after, str):
            raise PatchApplyError("Text replace patches require a string 'after' value.")
        updated = updated.replace(before, after, 1)
    return updated


def _resolve_parent(data: Any, pointer: str, *, create_missing: bool) -> tuple[Any, str]:
    tokens = [_decode_pointer_token(part) for part in pointer.split("/")[1:]]
    if not tokens:
        raise PatchApplyError("Root replacement is not supported in the repair workspace.")
    node = data
    for token in tokens[:-1]:
        if isinstance(node, dict):
            if token not in node:
                if not create_missing:
                    raise PatchApplyError(f"JSON Pointer target does not exist: {pointer}")
                node[token] = {}
            node = node[token]
        elif isinstance(node, list):
            idx = _list_index(token, node)
            if idx >= len(node):
                raise PatchApplyError(f"JSON Pointer target does not exist: {pointer}")
            node = node[idx]
        else:
            raise PatchApplyError(f"JSON Pointer target does not exist: {pointer}")
    return node, tokens[-1]


def _decode_pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _list_index(token: str, values: list[Any], *, allow_end: bool = False) -> int:
    if allow_end and token == "-":  # nosec B105: RFC 6901 list append marker, not a credential
        return len(values)
    try:
        idx = int(token)
    except ValueError as exc:
        raise PatchApplyError(f"Invalid JSON Pointer list index: {token}") from exc
    if idx < 0 or idx > len(values) or (idx == len(values) and not allow_end):
        raise PatchApplyError(f"JSON Pointer list index out of range: {token}")
    return idx


def _assert_before(actual: Any, expected: Any, target: str) -> None:
    if expected is None:
        return
    if actual != expected:
        raise PatchApplyError(f"Patch precondition failed at {target}.")
