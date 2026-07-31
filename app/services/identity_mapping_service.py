"""Canonical identity-mapping status model builder for tenant authorization."""

from __future__ import annotations

from typing import Any


def build_identity_mapping(
    external_iam_tenant_id: str | None = None,
    *,
    is_legacy: bool = False,
    verified: bool = True,
) -> dict[str, Any]:
    """Build the canonical identity mapping status payload for a tenant."""
    ext_id = (external_iam_tenant_id or "").strip() or None

    if is_legacy:
        mode = "LEGACY"
        display_status = "Legacy record"
    elif ext_id:
        if verified:
            mode = "CONNECTED"
            display_status = "HCL.CS connected"
        else:
            mode = "UNVERIFIED"
            display_status = "Mapping not verified"
    else:
        mode = "LOCAL_ONLY"
        display_status = "Local authorization"

    return {
        "mode": mode,
        "provider": "HCL.CS" if ext_id else None,
        "display_status": display_status,
        "external_tenant_id": ext_id,
        "verified": verified if ext_id else False,
        "is_legacy": is_legacy,
    }
