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
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..ai import credential_audit
from ..ai.config_loader import get_loader, preview_api_key
from ..ai.config_types import ProviderConfig
from ..ai.provider_factory import build_provider, validate_provider_config
from ..ai.providers.base import ConnectionTestResult, ProviderUnavailableError
from ..db import get_db
from ..models import AiProviderCredential, AiSettings
from ..security.secrets import encryption_config_diagnostic, get_cipher

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
    cost_per_1k_input_usd: float = Field(default=0.0, ge=0.0)
    cost_per_1k_output_usd: float = Field(default=0.0, ge=0.0)
    is_local: bool = False
    max_concurrent: int | None = Field(default=None, gt=0)
    rate_per_minute: float | None = Field(default=None, gt=0)


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
    cost_per_1k_input_usd: float | None = Field(default=None, ge=0.0)
    cost_per_1k_output_usd: float | None = Field(default=None, ge=0.0)
    is_local: bool | None = None
    max_concurrent: int | None = Field(default=None, gt=0)
    rate_per_minute: float | None = Field(default=None, gt=0)


class TestConnectionRequest(BaseModel):
    """Body for ``POST /credentials/test``.

    Either supplies a complete provider config (un-saved test before
    save) OR a credential_id (saved-row re-test). ``api_key`` is
    accepted only on the un-saved path; saved rows decrypt their key
    server-side.
    """

    model_config = ConfigDict(extra="forbid")

    credential_id: int | None = Field(default=None, gt=0)
    provider_name: str = Field(..., min_length=1, max_length=32)
    api_key: str | None = Field(default=None, max_length=4096)
    base_url: str | None = Field(default=None, max_length=512)
    default_model: str | None = Field(default=None, max_length=128)
    tier: TierLiteral = "paid"
    cost_per_1k_input_usd: float = Field(default=0.0, ge=0.0)
    cost_per_1k_output_usd: float = Field(default=0.0, ge=0.0)
    is_local: bool = False
    max_concurrent: int | None = Field(default=None, gt=0)
    rate_per_minute: float | None = Field(default=None, gt=0)


class SettingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_enabled: bool
    kill_switch_active: bool
    budget_per_request_usd: float
    budget_per_scan_usd: float
    budget_daily_usd: float
    updated_at: str
    updated_by_user_id: str | None
    source: str  # "db" | "env"


class SettingsUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feature_enabled: bool | None = None
    kill_switch_active: bool | None = None
    budget_per_request_usd: float | None = Field(default=None, ge=0.0)
    budget_per_scan_usd: float | None = Field(default=None, ge=0.0)
    budget_daily_usd: float | None = Field(default=None, ge=0.0)


class EffectiveProviderDiagnostic(BaseModel):
    selection_key: str
    provider_name: str
    credential_id: int | None
    label: str
    source: str
    enabled: bool
    credential_present: bool
    model: str
    base_url: str | None
    is_default: bool
    is_fallback: bool
    config_error: str | None
    last_test_at: str | None = None
    last_test_success: bool | None = None


class EffectiveConfigDiagnostic(BaseModel):
    feature_enabled: bool
    kill_switch_active: bool
    settings_source: str
    ai_ui_config_enabled: bool
    budget_caps_usd: dict[str, float]
    configured_providers: list[EffectiveProviderDiagnostic]
    default_selection_key: str | None
    fallback_selection_key: str | None
    registry_config_version: int
    encryption_config_available: bool
    encryption_config_status: str


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


def _cipher():
    """Return the process cipher, or 503 when the master key is absent.

    ``get_cipher`` raises ``RuntimeError`` when
    ``AI_CONFIG_ENCRYPTION_KEY`` is unset. Left uncaught that surfaces
    as a bare 500 and reads like a bug, when it is really a one-line
    deployment gap — so name it in the response instead.
    """
    try:
        return get_cipher()
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "AI credential encryption is not configured, so provider keys "
                "cannot be stored. Set AI_CONFIG_ENCRYPTION_KEY (generate one with "
                "`python scripts/generate_encryption_key.py --append-to-env`) and "
                "restart the API."
            ),
        ) from exc


def _sanitized_base_url(value: str) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        return None
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        parsed_port = parsed.port
    except ValueError:
        return None
    port = f":{parsed_port}" if parsed_port is not None else ""
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{host}{port}{path}"


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


def _provider_config(
    *,
    provider_name: str,
    api_key: str | None,
    base_url: str | None,
    default_model: str | None,
    tier: str = "paid",
    cost_per_1k_input_usd: float = 0.0,
    cost_per_1k_output_usd: float = 0.0,
    is_local: bool = False,
    max_concurrent: int | None = None,
    rate_per_minute: float | None = None,
) -> ProviderConfig:
    return ProviderConfig(
        name=provider_name.strip().lower(),
        enabled=True,
        default_model=(default_model or "").strip(),
        api_key=(api_key or "").strip(),
        base_url=(base_url or "").strip(),
        max_concurrent=max_concurrent or 10,
        rate_per_minute=rate_per_minute or 60.0,
        tier=tier,
        cost_per_1k_input_usd=cost_per_1k_input_usd,
        cost_per_1k_output_usd=cost_per_1k_output_usd,
        is_local=is_local,
        source="transient",
    )


def _validate_catalog_compat(config: ProviderConfig) -> None:
    """Apply the exact same validation used by runtime construction."""
    try:
        validate_provider_config(config)
    except ProviderUnavailableError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _build_transient_provider(payload: TestConnectionRequest):
    """Build an un-persisted provider client for ``/credentials/test``.

    The test-connection path must NOT save anything. Failures here
    surface as :class:`ConnectionTestResult` rather than HTTP errors
    where possible — the UI shows them as inline banners.
    """
    config = _provider_config(
        provider_name=payload.provider_name,
        api_key=payload.api_key,
        base_url=payload.base_url,
        default_model=payload.default_model,
        tier=payload.tier,
        cost_per_1k_input_usd=payload.cost_per_1k_input_usd,
        cost_per_1k_output_usd=payload.cost_per_1k_output_usd,
        is_local=payload.is_local,
        max_concurrent=payload.max_concurrent,
        rate_per_minute=payload.rate_per_minute,
    )
    _validate_catalog_compat(config)
    return build_provider(config)


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
    rows = db.execute(select(AiProviderCredential).order_by(AiProviderCredential.id)).scalars().all()
    return [_row_to_response(r) for r in rows]


@router.get("/credentials/{cred_id}", response_model=CredentialResponse)
def get_credential(cred_id: int, db: Session = Depends(get_db)) -> CredentialResponse:
    row = db.execute(select(AiProviderCredential).where(AiProviderCredential.id == cred_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")
    return _row_to_response(row)


@router.get("/effective-config", response_model=EffectiveConfigDiagnostic)
def get_effective_config_diagnostic(db: Session = Depends(get_db)) -> EffectiveConfigDiagnostic:
    """Safe administrator/smoke-check view of the exact runtime snapshot."""
    from ..settings import get_settings

    loader = get_loader()
    configs, effective = loader.resolve()
    rows = {
        row.id: row
        for row in db.execute(select(AiProviderCredential).order_by(AiProviderCredential.id)).scalars()
    }
    default = next((cfg for cfg in configs if cfg.is_default), None)
    if default is None:
        try:
            from ..ai.registry import get_registry

            default = get_registry(db).get_default_config()
        except Exception:  # noqa: BLE001
            default = None
    fallback = next((cfg for cfg in configs if cfg.is_fallback), None)
    encryption_available, encryption_status = encryption_config_diagnostic()
    providers: list[EffectiveProviderDiagnostic] = []
    for cfg in configs:
        row = rows.get(cfg.credential_id) if cfg.credential_id is not None else None
        providers.append(
            EffectiveProviderDiagnostic(
                selection_key=cfg.selection_key,
                provider_name=cfg.name,
                credential_id=cfg.credential_id,
                label=cfg.label,
                source=cfg.source,
                enabled=cfg.enabled,
                credential_present=bool(row.api_key_encrypted) if row is not None else bool(cfg.api_key),
                model=cfg.default_model,
                base_url=_sanitized_base_url(cfg.base_url),
                is_default=cfg.is_default,
                is_fallback=cfg.is_fallback,
                config_error=cfg.config_error,
                last_test_at=row.last_test_at if row is not None else None,
                last_test_success=row.last_test_success if row is not None else None,
            )
        )
    return EffectiveConfigDiagnostic(
        feature_enabled=effective.feature_enabled,
        kill_switch_active=effective.kill_switch_active,
        settings_source=effective.source,
        ai_ui_config_enabled=bool(get_settings().ai_fixes_ui_config_enabled),
        budget_caps_usd={
            "per_request_usd": effective.budget_per_request_usd,
            "per_scan_usd": effective.budget_per_scan_usd,
            "per_day_org_usd": effective.budget_daily_usd,
        },
        configured_providers=providers,
        default_selection_key=default.selection_key if default is not None else None,
        fallback_selection_key=fallback.selection_key if fallback is not None else None,
        registry_config_version=loader.current_version(),
        encryption_config_available=encryption_available,
        encryption_config_status=encryption_status,
    )


# ---------------------------------------------------------------------------
# Create / update / delete
# ---------------------------------------------------------------------------


@router.post("/credentials", response_model=CredentialResponse, status_code=201)
def create_credential(
    body: CredentialCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> CredentialResponse:
    if body.is_default and body.is_fallback:
        raise HTTPException(status_code=400, detail="Default and fallback must be different credentials.")
    _validate_catalog_compat(
        _provider_config(
            provider_name=body.provider_name,
            api_key=body.api_key,
            base_url=body.base_url,
            default_model=body.default_model,
            tier=body.tier,
            cost_per_1k_input_usd=body.cost_per_1k_input_usd,
            cost_per_1k_output_usd=body.cost_per_1k_output_usd,
            is_local=body.is_local,
            max_concurrent=body.max_concurrent,
            rate_per_minute=body.rate_per_minute,
        )
    )
    encrypted = None
    if body.api_key:
        encrypted = _cipher().encrypt(body.api_key)
    now = _now_iso()
    if body.is_default:
        for existing in db.execute(select(AiProviderCredential)).scalars():
            existing.is_default = False
    if body.is_fallback:
        for existing in db.execute(select(AiProviderCredential)).scalars():
            existing.is_fallback = False
    row = AiProviderCredential(
        provider_name=body.provider_name.strip().lower(),
        label=body.label.strip(),
        api_key_encrypted=encrypted,
        base_url=(body.base_url or "").strip() or None,
        default_model=body.default_model,
        tier=body.tier,
        is_default=body.is_default,
        is_fallback=body.is_fallback,
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
    row = db.execute(select(AiProviderCredential).where(AiProviderCredential.id == cred_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")

    # Validate the complete post-update configuration before mutating the
    # row. ``PRESENT`` represents an existing encrypted key for validation
    # only; it is never persisted, logged, or returned.
    _validate_catalog_compat(
        _provider_config(
            provider_name=row.provider_name,
            api_key=body.api_key or ("PRESENT" if row.api_key_encrypted else None),
            base_url=body.base_url if body.base_url is not None else row.base_url,
            default_model=(
                body.default_model if body.default_model is not None else row.default_model
            ),
            tier=body.tier if body.tier is not None else (row.tier or "paid"),
            cost_per_1k_input_usd=(
                body.cost_per_1k_input_usd
                if body.cost_per_1k_input_usd is not None
                else float(row.cost_per_1k_input_usd or 0.0)
            ),
            cost_per_1k_output_usd=(
                body.cost_per_1k_output_usd
                if body.cost_per_1k_output_usd is not None
                else float(row.cost_per_1k_output_usd or 0.0)
            ),
            is_local=body.is_local if body.is_local is not None else bool(row.is_local),
            max_concurrent=(
                body.max_concurrent if body.max_concurrent is not None else row.max_concurrent
            ),
            rate_per_minute=(
                body.rate_per_minute if body.rate_per_minute is not None else row.rate_per_minute
            ),
        )
    )

    changes: list[str] = []
    if body.label is not None and body.label != row.label:
        row.label = body.label
        changes.append("label")
    # api_key omitted ⇒ preserve. api_key="" ⇒ explicit clear is rejected
    # (must use DELETE for that). Non-empty ⇒ encrypt + replace.
    if body.api_key:
        row.api_key_encrypted = _cipher().encrypt(body.api_key)
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
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"A credential for ({row.provider_name}, {row.label}) already exists.",
        ) from exc
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
    row = db.execute(select(AiProviderCredential).where(AiProviderCredential.id == cred_id)).scalar_one_or_none()
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
    row = db.execute(select(AiProviderCredential).where(AiProviderCredential.id == cred_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")
    # Atomic swap: clear all, set the chosen, single flush. The partial
    # unique index would otherwise reject the intermediate state.
    for other in db.execute(select(AiProviderCredential).where(AiProviderCredential.id != cred_id)).scalars():
        other.is_default = False
    row.is_default = True
    row.is_fallback = False
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
    row = db.execute(select(AiProviderCredential).where(AiProviderCredential.id == cred_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")
    if row.is_default:
        raise HTTPException(status_code=400, detail="Default and fallback must be different credentials.")
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
    """Probe candidate values without persisting them.

    Edit forms may supply ``credential_id`` and omit ``api_key``.  In that
    case the key is decrypted server-side while all other candidate values
    still come from the request, so an administrator can test a model or URL
    change without re-entering or exposing the saved secret.
    """
    test_body = body
    target_id: int | None = None
    if body.credential_id is not None:
        row = db.execute(
            select(AiProviderCredential).where(AiProviderCredential.id == body.credential_id)
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Credential {body.credential_id} not found.")
        if row.provider_name != body.provider_name.strip().lower():
            raise HTTPException(status_code=400, detail="Credential provider does not match the test request.")
        api_key = body.api_key
        if not api_key and row.api_key_encrypted:
            try:
                api_key = _cipher().decrypt(row.api_key_encrypted)
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(
                    status_code=503,
                    detail="The saved AI credential cannot be decrypted with the configured encryption key.",
                ) from exc
        test_body = body.model_copy(update={"api_key": api_key})
        target_id = row.id
    try:
        provider = _build_transient_provider(test_body)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        return ConnectionTestResult(
            success=False,
            error_message=str(exc)[:240],
            error_kind="unknown",
            provider=test_body.provider_name,
            model_tested=test_body.default_model,
        )
    result = await provider.test_connection(model=test_body.default_model)
    credential_audit.record(
        db,
        user_id=_user_id(request),
        action="credential.test",
        target_kind="credential",
        target_id=target_id,
        provider_name=test_body.provider_name,
        detail=f"candidate success={result.success} kind={result.error_kind or 'ok'}",
    )
    return result


@router.post("/credentials/{cred_id}/test", response_model=ConnectionTestResult)
async def test_saved_credential(
    cred_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> ConnectionTestResult:
    """Re-test a saved row. Decrypts the stored key in-memory only."""
    row = db.execute(select(AiProviderCredential).where(AiProviderCredential.id == cred_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {cred_id} not found.")

    api_key: str | None = None
    if row.api_key_encrypted:
        try:
            api_key = get_cipher().decrypt(row.api_key_encrypted)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=503,
                detail="The saved AI credential cannot be decrypted with the configured encryption key.",
            ) from exc

    payload = TestConnectionRequest(
        provider_name=row.provider_name,
        api_key=api_key,
        base_url=row.base_url,
        default_model=row.default_model,
        tier=(row.tier or "paid"),  # type: ignore[arg-type]
        cost_per_1k_input_usd=float(row.cost_per_1k_input_usd or 0.0),
        cost_per_1k_output_usd=float(row.cost_per_1k_output_usd or 0.0),
        is_local=bool(row.is_local),
        max_concurrent=row.max_concurrent,
        rate_per_minute=row.rate_per_minute,
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
        # Migration/startup compatibility: surface the exact env fallback
        # runtime is enforcing until the first DB write establishes an
        # authoritative singleton.
        effective = get_loader().resolve_settings()
        return SettingsResponse(
            feature_enabled=effective.feature_enabled,
            kill_switch_active=effective.kill_switch_active,
            budget_per_request_usd=effective.budget_per_request_usd,
            budget_per_scan_usd=effective.budget_per_scan_usd,
            budget_daily_usd=effective.budget_daily_usd,
            updated_at=_now_iso(),
            updated_by_user_id=None,
            source=effective.source,
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
        # First write promotes the current effective env fallback into an
        # authoritative DB row, then applies the caller's overrides.
        effective = get_loader().resolve_settings()
        row = AiSettings(
            id=1,
            feature_enabled=effective.feature_enabled,
            kill_switch_active=effective.kill_switch_active,
            budget_per_request_usd=effective.budget_per_request_usd,
            budget_per_scan_usd=effective.budget_per_scan_usd,
            budget_daily_usd=effective.budget_daily_usd,
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
    if not (float(row.budget_per_request_usd) <= float(row.budget_per_scan_usd) <= float(row.budget_daily_usd)):
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
