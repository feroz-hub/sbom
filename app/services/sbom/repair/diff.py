"""Restricted server-generated JSON pointers; reuse the existing patch engine."""

import hashlib
import json
import re

from app.services.validation_patch_service import apply_repair_patches

from .models import RepairProposal


def pointer(path: str) -> str:
    if path.startswith("/"):
        return path
    parts = re.findall(r"[^.\[\]]+", path)
    return "/" + "/".join(p.replace("~", "~0").replace("/", "~1") for p in parts)


def value_at(document, path: str):
    node = document
    for part in pointer(path).split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def proposal(code, path, old, new, rule, reason, operation="replace"):
    path = pointer(path)
    key = json.dumps([code, path, old, new, rule], sort_keys=True, ensure_ascii=False)
    return RepairProposal(
        repair_id=hashlib.sha256(key.encode()).hexdigest(),
        error_code=code,
        operation=operation,
        path=path,
        old_value=old,
        new_value=new,
        rule_name=rule,
        reason=reason,
    )


def apply(document, change: RepairProposal):
    # No client-supplied operations are accepted by the deterministic endpoints.
    if change.operation not in {"replace", "remove"} or not change.path.startswith("/"):
        raise ValueError("Unsupported deterministic operation")
    if any(p in {"__proto__", "prototype", "constructor"} for p in change.path.split("/")):
        raise ValueError("Unsafe pointer")
    if value_at(document, change.path) != change.old_value:
        raise ValueError("Repair precondition failed")
    return json.loads(
        apply_repair_patches(
            json.dumps(document),
            [
                {
                    "target": change.path,
                    "operation": change.operation,
                    "before": change.old_value,
                    "after": change.new_value,
                }
            ],
        )
    )


def unique_entries(values):
    """JSON equality, preserving types and first occurrence order in O(n)."""
    seen, result = set(), []
    for value in values:
        key = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result
