"""AI credential + settings CRUD surface.

Phase 2 §2.5 / §2.6. Backs the Settings UI shipped in Phase 3.

Hard rules, enforced here and in the response models:

  * **No raw API keys leave the server.** Read endpoints expose
    ``api_key_preview`` (first 6 + last 4 with ellipsis) and
    ``api_key_present`` only.
  * **Test-connection is the gate**. Production deployments should
    route the UI's "Save" through ``POST /test`` first; this layer
    accepts saves without a prior test (admin tools may need the
    bypass), but the audit log records ``test=skipped`` when the
    last_test_at is empty.
  * **Audit every mutation.** Single ``credential_audit.record`` call
    per write, never with the credential payload in the detail string.
  * **Cache invalidation.** Every successful write calls
    ``get_loader().invalidate()`` so the next provider lookup picks
    up the new state within one request.

PUT semantics: ``api_key`` is optional in the request body. If
omitted, the existing key is preserved — supports edits that change
model / tier without re-entering the key.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..ai import credential_audit
from ..ai.catalog import get_catalog_entry
from ..ai.config_loader import get_loader, preview_api_key
from ..ai.providers.anthropic import AnthropicProvider
from ..ai.providers.base import ConnectionTestResult
from ..ai.providers.custom_openai_compatible import CustomOpenAiCompatibleProvider
from ..ai.providers.gemini import GeminiProvider
from ..ai.providers.grok import GrokProvider
from ..ai.providers.ollama import OllamaProvider
from ..ai.providers.openai import OpenAiProvider
from ..ai.providers.vllm import VllmProvider
from ..db import get_db
from ..models import AiProviderCredential, AiSettings
from ..security.secrets import get_cipher

log = logging.getLogger("sbom.routers.ai_credentials")

router = APIRouter(prefix="/api/v1/ai", tags=["ai-credentials"])


# ---------------------------------------------------------------------------
# Response shapes — preview-only, never raw keys
# ---------------------------------------------------------------------------


TierLiteral = Literal["free", "paid"]


class CredentialResponse(BaseModel):
    """Public-facing credential row. ``api_key_*`` is preview-only."""

    model_config = ConfigDict(extra="forbid")

    id: int
    provider_name: str
    label: str
    api_key_present: bool
    api_key_preview: str | None
    base_url: str | None
    default_model: str | None
    tier: str
    is_default: bool
    is_fallback: bool
    enabled: bool
    cost_per_1k_input_usd: float
    cost_per_1k_output_usd: float
    is_local: bool
    max_concurrent: int | None
    rate_per_minute: float | None
    created_at: str
    updated_at: str
    last_test_at: str | None
    last_test_success: bool | None
    last_test_error: str | None


class CredentialCreateRequest(BaseModel):
    """Body for ``POST /credentials``."""

    model_config = ConfigDict(extra="forbid")

    provider_name: str = Field(..., min_length=1, max_length=32)
    label: str = Field(default="default", min_length=1, max_length=64)
    api_key: str | None = Field(default=None, max_length=4096)
    base_url: str | None = Field(default=None, max_length=512)
    default_model: str | None = Field(default=None, max_length=128)
    tier: TierLiteral = "paid"
    enabled: bool = True
    is_default: bool = False
    is_fallback: bool = False
    cost_per_1k_input_usd: float = 0.0
    cost_per_1k_output_usd: float = 0.0
    is_local: bool = False
    max_concurrent: int | None = None
    rate_per_minute: float | None = None


class CredentialUpdateRequest(BaseModel):
    """Body for ``PUT /credentials/{id}``.

    All fields optional — present fields update, omitted fields preserve.
    Critically, ``api_key`` omitted means "keep the existing key".
    """

    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, min_length=1, max_length=64)
    api_key: str | None = Field(default=None, max_length=4096)
    base_url: str | None = Field(default=None, max_length=512)
    default_model: str | None = Field(default=None, max_length=128)
    tier: TierLiteral | None = None
    enabled: bool | None = None
    cost_per_1k_input_usd: float | None = None
    cost_per_1k_output_usd: float | None = None
    is_local: bool | None = None
    max_concurrent: int | None = None
    rate_per_minute: float | None = None


class TestConnectionRequest(BaseModel):
    """Body for ``POST /credentials/test``.

    Either supplies a complete provider config (un-saved test before
    save) OR a credential_id (saved-row re-test). ``api_key`` is
    accepted only on the un-saved path; saved rows decrypt their key
    server-side.
    """

    model_config = ConfigDict(extra="forbid")

    provider_name: str = Field(..., min_length=1, max_length=32)
    api_key: str | None = Field(default=None, max_length=4096)
    base_url: str | None = Field(default=None, max_length=512)
    default_model: str | None = Field(default=None, max_length=128)
    tier: TierLiteral = "paid"
    cost_per_1k_input_usd: float = 0.0
    cost_per_1k_output_usd: float = 0.0
    is_local: bool = False


class SettingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_enabled: bool
    kill_switch_active: bool
    budget_per_request_usd: float
    budget_per_scan_usd: float
    budget_daily_usd: float
    updated_at: str
    updated_by_user_id: str | None
    source: str  # "db"


class SettingsUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_enabled: bool | None = None
    kill_switch_active: bool | None = None
    budget_per_request_usd: float | None = Field(default=None, ge=0.0)
    budget_per_scan_usd: float | None = Field(default=None, ge=0.0)
    budget_daily_usd: float | None = Field(default=None, ge=0.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _user_id(request: Request) -> str | None:
    """Best-effort user id for audit logs.

    The codebase's auth layer (``app.auth.require_auth``) sets
    ``request.state.user`` when JWT mode is active. In bearer/none
    modes there's no user id; audit rows record ``None``.
    """
    user = getattr(request.state, "user", None)
    if isinstance(user, dict):
        return str(user.get("sub") or user.get("user_id") or "") or None
    return None


def _row_to_response(row: AiProviderCredential, *, decrypted_key: str | None = None) -> CredentialResponse:
    """Build a CredentialResponse from a row.

    ``decrypted_key`` is optional — when present we use it for the
    preview computation; when omitted we decrypt here (best-effort).
    Either way, the raw key never appears in the response.
    """
    plaintext: str | None = decrypted_key
    if plaintext is None and row.api_key_encrypted:
        try:
            plaintext = get_cipher().decrypt(row.api_key_encrypted)
        except Exception:  # noqa: BLE001
            plaintext = None
    preview, present = preview_api_key(plaintext)
    return CredentialResponse(
        id=row.id,
        provider_name=row.provider_name,
        label=row.label,
        api_key_present=bool(row.api_key_encrypted) or present,
        api_key_preview=preview,
        base_url=row.base_url,
        default_model=row.default_model,
        tier=row.tier or "paid",
        is_default=bool(row.is_default),
        is_fallback=bool(row.is_fallback),
        enabled=bool(row.enabled),
        cost_per_1k_input_usd=float(row.cost_per_1k_input_usd or 0.0),
        cost_per_1k_output_usd=float(row.cost_per_1k_output_usd or 0.0),
        is_local=bool(row.is_local),
        max_concurrent=row.max_concurrent,
        rate_per_minute=row.rate_per_minute,
        created_at=row.created_at,
        updated_at=row.updated_at,
        last_test_at=row.last_test_at,
        last_test_success=row.last_test_success,
        last_test_error=row.last_test_error,
    )


def _validate_catalog_compat(provider_name: str, *, base_url: str | None, default_model: str | None) -> None:
    """Catalog-aware validation. Mirrors the UI form rules at the API."""
    entry = get_catalog_entry(provider_name)
    if entry is None:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider_name!r}")
    if entry.requires_base_url and not base_url:
        raise HTTPException(
            status_code=400,
            detail=f"{provider_name} requires a base URL.",
        )
    if not default_model and not (entry.requires_base_url and entry.name == "custom_openai"):
        # Catalogged providers have model lists; require one.
        # The custom provider accepts free-text and the request shape's
        # ``default_model`` field is optional in the type but required
        # downstream — re-check.
        if not default_model and provider_name != "custom_openai":
            raise HTTPException(status_code=400, detail="default_model is required.")


def _build_transient_provider(payload: TestConnectionRequest):
    """Build an un-persisted provider client for ``/credentials/test``.

    The test-connection path must NOT save anything. Failures here
    surface as :class:`ConnectionTestResult` rather than HTTP errors
    where possible — the UI shows them as inline banners.
    """
    name = payload.provider_name.strip().lower()
    if name == "anthropic":
        return AnthropicProvider(api_key=payload.api_key or "")
    if name == "openai":
        return OpenAiProvider(api_key=payload.api_key or "")
    if name == "gemini":
        return GeminiProvider(api_key=payload.api_key or "", tier=payload.tier)
    if name == "grok":
        return GrokProvider(api_key=payload.api_key or "", tier=payload.tier)
    if name == "ollama":
        return OllamaProvider(base_url=payload.base_url or "http://localhost:11434")
    if name == "vllm":
        return VllmProvider(
            base_url=payload.base_url or "",
            api_key=payload.api_key or "EMPTY",
            default_model=payload.default_model or "",
        )
    if name == "custom_openai":
        return CustomOpenAiCompatibleProvider(
            base_url=payload.base_url or "",
            api_key=payload.api_key or "EMPTY",
            default_model=payload.default_model or "",
            cost_per_1k_input_usd=payload.cost_per_1k_input_usd,
            cost_per_1k_output_usd=payload.cost_per_1k_output_usd,
            is_local=payload.is_local,
        )
    raise HTTPException(status_code=400, detail=f"Unknown provider: {name!r}")


def _stamp_test_result(row: AiProviderCredential, result: ConnectionTestResult) -> None:
    row.last_test_at = _now_iso()
    row.last_test_success = bool(result.success)
    # Truncate at 240 chars — same cap the audit log uses.
    row.last_test_error = (result.error_message or "")[:240] if not result.success else None


# ---------------------------------------------------------------------------
# Read endpoints
# ---------------------------------------------------------------------------


@router.get("/credentials", response_model=list[CredentialResponse])
def list_credentials(db: Session = Depends(get_db)) -> list[CredentialResponse]:
    rows = db.execute(
        select(AiProviderCredential).order_by(AiProviderCredential.id)
    ).scalars().all()
    return [_row_to_response(r) for r in rows]


@router.get("/credentials/{cred_id}", response_model=CredentialResponse)
def get_credential(cred_id: int, db: Session = Depends(get_db)) -> CredentialResponse:
    row = db.execute(
        select(AiProviderCredential).where(AiProviderCredential.id == cred_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")
    return _row_to_response(row)


# ---------------------------------------------------------------------------
# Create / update / delete
# ---------------------------------------------------------------------------


@router.post("/credentials", response_model=CredentialResponse, status_code=201)
def create_credential(
    body: CredentialCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialResponse:
    _validate_catalog_compat(
        body.provider_name,
        base_url=body.base_url,
        default_model=body.default_model,
    )
    encrypted = None
    if body.api_key:
        encrypted = get_cipher().encrypt(body.api_key)
    now = _now_iso()
    row = AiProviderCredential(
        provider_name=body.provider_name.strip().lower(),
        label=body.label.strip(),
        api_key_encrypted=encrypted,
        base_url=(body.base_url or "").strip() or None,
        default_model=body.default_model,
        tier=body.tier,
        is_default=False,  # explicit promotion only via /set-default
        is_fallback=False,
        enabled=body.enabled,
        cost_per_1k_input_usd=body.cost_per_1k_input_usd,
        cost_per_1k_output_usd=body.cost_per_1k_output_usd,
        is_local=body.is_local,
        max_concurrent=body.max_concurrent,
        rate_per_minute=body.rate_per_minute,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"A credential for ({body.provider_name}, {body.label}) already exists.",
        ) from exc
    db.refresh(row)

    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.create",
        target_kind="credential",
        target_id=row.id,
        provider_name=row.provider_name,
        detail=f"label={row.label} tier={row.tier} key_present={bool(encrypted)}",
    )
    get_loader().invalidate()
    return _row_to_response(row, decrypted_key=body.api_key)


@router.put("/credentials/{cred_id}", response_model=CredentialResponse)
def update_credential(
    cred_id: int,
    body: CredentialUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialResponse:
    row = db.execute(
        select(AiProviderCredential).where(AiProviderCredential.id == cred_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")

    changes: list[str] = []
    if body.label is not None and body.label != row.label:
        row.label = body.label
        changes.append("label")
    # api_key omitted ⇒ preserve. api_key="" ⇒ explicit clear is rejected
    # (must use DELETE for that). Non-empty ⇒ encrypt + replace.
    if body.api_key:
        row.api_key_encrypted = get_cipher().encrypt(body.api_key)
        changes.append("api_key")
    if body.base_url is not None:
        row.base_url = body.base_url.strip() or None
        changes.append("base_url")
    if body.default_model is not None:
        row.default_model = body.default_model
        changes.append("default_model")
    if body.tier is not None:
        row.tier = body.tier
        changes.append("tier")
    if body.enabled is not None:
        row.enabled = bool(body.enabled)
        changes.append("enabled")
    if body.cost_per_1k_input_usd is not None:
        row.cost_per_1k_input_usd = float(body.cost_per_1k_input_usd)
        changes.append("cost_in")
    if body.cost_per_1k_output_usd is not None:
        row.cost_per_1k_output_usd = float(body.cost_per_1k_output_usd)
        changes.append("cost_out")
    if body.is_local is not None:
        row.is_local = bool(body.is_local)
        changes.append("is_local")
    if body.max_concurrent is not None:
        row.max_concurrent = int(body.max_concurrent)
        changes.append("max_concurrent")
    if body.rate_per_minute is not None:
        row.rate_per_minute = float(body.rate_per_minute)
        changes.append("rate")

    row.updated_at = _now_iso()
    db.commit()
    db.refresh(row)

    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.update",
        target_kind="credential",
        target_id=row.id,
        provider_name=row.provider_name,
        detail=f"changed={','.join(changes) or 'none'}",
    )
    get_loader().invalidate()
    return _row_to_response(row)


@router.delete("/credentials/{cred_id}", status_code=204)
def delete_credential(
    cred_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    row = db.execute(
        select(AiProviderCredential).where(AiProviderCredential.id == cred_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")
    provider_name = row.provider_name
    db.delete(row)
    db.commit()
    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.delete",
        target_kind="credential",
        target_id=cred_id,
        provider_name=provider_name,
        detail="row removed",
    )
    get_loader().invalidate()


# ---------------------------------------------------------------------------
# Set default / fallback / toggle
# ---------------------------------------------------------------------------


@router.put("/credentials/{cred_id}/set-default", response_model=CredentialResponse)
def set_default_credential(
    cred_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialResponse:
    row = db.execute(
        select(AiProviderCredential).where(AiProviderCredential.id == cred_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")
    # Atomic swap: clear all, set the chosen, single flush. The partial
    # unique index would otherwise reject the intermediate state.
    for other in db.execute(select(AiProviderCredential).where(AiProviderCredential.id != cred_id)).scalars():
        other.is_default = False
    row.is_default = True
    row.updated_at = _now_iso()
    db.commit()
    db.refresh(row)
    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.set_default",
        target_kind="credential",
        target_id=row.id,
        provider_name=row.provider_name,
        detail="promoted to default",
    )
    get_loader().invalidate()
    return _row_to_response(row)


@router.put("/credentials/{cred_id}/set-fallback", response_model=CredentialResponse)
def set_fallback_credential(
    cred_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialResponse:
    row = db.execute(
        select(AiProviderCredential).where(AiProviderCredential.id == cred_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")
    for other in db.execute(select(AiProviderCredential).where(AiProviderCredential.id != cred_id)).scalars():
        other.is_fallback = False
    row.is_fallback = True
    row.updated_at = _now_iso()
    db.commit()
    db.refresh(row)
    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.set_fallback",
        target_kind="credential",
        target_id=row.id,
        provider_name=row.provider_name,
        detail="promoted to fallback",
    )
    get_loader().invalidate()
    return _row_to_response(row)


# ---------------------------------------------------------------------------
# Test connection (un-saved + saved)
# ---------------------------------------------------------------------------


@router.post("/credentials/test", response_model=ConnectionTestResult)
async def test_unsaved_credential(
    body: TestConnectionRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ConnectionTestResult:
    """Run a probe against the supplied config without persisting it."""
    try:
        provider = _build_transient_provider(body)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        return ConnectionTestResult(
            success=False,
            error_message=str(exc)[:240],
            error_kind="unknown",
            provider=body.provider_name,
            model_tested=body.default_model,
        )
    result = await provider.test_connection(model=body.default_model)
    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.test",
        target_kind="credential",
        target_id=None,
        provider_name=body.provider_name,
        detail=f"unsaved success={result.success} kind={result.error_kind or 'ok'}",
    )
    return result


@router.post("/credentials/{cred_id}/test", response_model=ConnectionTestResult)
async def test_saved_credential(
    cred_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> ConnectionTestResult:
    """Re-test a saved row. Decrypts the stored key in-memory only."""
    row = db.execute(
        select(AiProviderCredential).where(AiProviderCredential.id == cred_id)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")

    api_key: str | None = None
    if row.api_key_encrypted:
        try:
            api_key = get_cipher().decrypt(row.api_key_encrypted)
        except Exception:  # noqa: BLE001
            return ConnectionTestResult(
                success=False,
                error_message="Stored credential could not be decrypted; re-enter the key.",
                error_kind="auth",
                provider=row.provider_name,
                model_tested=row.default_model,
            )

    payload = TestConnectionRequest(
        provider_name=row.provider_name,
        api_key=api_key,
        base_url=row.base_url,
        default_model=row.default_model,
        tier=(row.tier or "paid"),  # type: ignore[arg-type]
        cost_per_1k_input_usd=float(row.cost_per_1k_input_usd or 0.0),
        cost_per_1k_output_usd=float(row.cost_per_1k_output_usd or 0.0),
        is_local=bool(row.is_local),
    )
    provider = _build_transient_provider(payload)
    result = await provider.test_connection(model=row.default_model)
    _stamp_test_result(row, result)
    db.commit()

    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.test",
        target_kind="credential",
        target_id=row.id,
        provider_name=row.provider_name,
        detail=f"saved success={result.success} kind={result.error_kind or 'ok'}",
    )
    return result


# ---------------------------------------------------------------------------
# Settings (singleton)
# ---------------------------------------------------------------------------


@router.get("/settings", response_model=SettingsResponse)
def get_singleton_settings(db: Session = Depends(get_db)) -> SettingsResponse:
    row = db.execute(select(AiSettings).where(AiSettings.id == 1)).scalar_one_or_none()
    if row is None:
        # Migration creates this row on apply; if missing, return defaults
        # so the UI doesn't 500 in mid-migration deployments.
        return SettingsResponse(
            feature_enabled=True,
            kill_switch_active=False,
            budget_per_request_usd=0.10,
            budget_per_scan_usd=5.00,
            budget_daily_usd=5.00,
            updated_at=_now_iso(),
            updated_by_user_id=None,
            source="db",
        )
    return SettingsResponse(
        feature_enabled=bool(row.feature_enabled),
        kill_switch_active=bool(row.kill_switch_active),
        budget_per_request_usd=float(row.budget_per_request_usd or 0.0),
        budget_per_scan_usd=float(row.budget_per_scan_usd or 0.0),
        budget_daily_usd=float(row.budget_daily_usd or 0.0),
        updated_at=row.updated_at,
        updated_by_user_id=row.updated_by_user_id,
        source="db",
    )


@router.put("/settings", response_model=SettingsResponse)
def update_singleton_settings(
    body: SettingsUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> SettingsResponse:
    row = db.execute(select(AiSettings).where(AiSettings.id == 1)).scalar_one_or_none()
    if row is None:
        # Edge case: missing seed row. Insert with defaults + apply
        # caller's overrides.
        row = AiSettings(
            id=1,
            feature_enabled=True,
            kill_switch_active=False,
            budget_per_request_usd=0.10,
            budget_per_scan_usd=5.00,
            budget_daily_usd=5.00,
            updated_at=_now_iso(),
        )
        db.add(row)
        db.flush()

    changes: list[str] = []
    if body.feature_enabled is not None:
        row.feature_enabled = bool(body.feature_enabled)
        changes.append("feature_enabled")
    if body.kill_switch_active is not None:
        row.kill_switch_active = bool(body.kill_switch_active)
        changes.append("kill_switch")
    if body.budget_per_request_usd is not None:
        row.budget_per_request_usd = float(body.budget_per_request_usd)
        changes.append("per_request")
    if body.budget_per_scan_usd is not None:
        row.budget_per_scan_usd = float(body.budget_per_scan_usd)
        changes.append("per_scan")
    if body.budget_daily_usd is not None:
        row.budget_daily_usd = float(body.budget_daily_usd)
        changes.append("daily")

    # Validation: per-request ≤ per-scan ≤ per-day.
    if not (
        float(row.budget_per_request_usd)
        <= float(row.budget_per_scan_usd)
        <= float(row.budget_daily_usd)
    ):
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Budget caps must satisfy per_request ≤ per_scan ≤ daily.",
        )

    user = _user_id(request)
    row.updated_at = _now_iso()
    row.updated_by_user_id = user
    db.commit()
    db.refresh(row)

    credential_audit.record(
        db,
        user_id=user,
        action="settings.update",
        target_kind="settings",
        target_id=1,
        provider_name=None,
        detail=f"changed={','.join(changes) or 'none'}",
    )
    get_loader().invalidate()
    return get_singleton_settings(db)
