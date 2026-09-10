"""Persistence and administration service for discovered provider models."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models import AiProviderCredential, AiProviderModel
from ..security.secrets import get_cipher
from .config_loader import get_loader
from .config_types import ProviderConfig
from .provider_factory import build_provider
from .providers.base import DiscoveredModel, LlmProvider, LlmRequest

log = logging.getLogger("sbom.ai.model_registry")


@dataclass(frozen=True)
class RefreshResult:
    discovered: int
    created: int
    updated: int
    unavailable: int


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sanitize_metadata(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if not value:
        return None
    forbidden = ("key", "secret", "token", "authorization", "credential", "password", "header")

    def clean(item: Any, *, depth: int = 0) -> Any:
        if depth > 4:
            return None
        if item is None or isinstance(item, (str, int, float, bool)):
            return item
        if isinstance(item, list):
            return [clean(child, depth=depth + 1) for child in item[:50]]
        if isinstance(item, dict):
            return {
                str(key)[:80]: clean(child, depth=depth + 1)
                for key, child in list(item.items())[:50]
                if not any(part in str(key).lower() for part in forbidden)
            }
        return str(item)[:240]

    sanitized = clean(value)
    if not isinstance(sanitized, dict):
        return None
    encoded = json.dumps(sanitized, default=str)
    return sanitized if len(encoded) <= 8192 else {"metadata_truncated": True}


def provider_config_from_credential(row: AiProviderCredential) -> ProviderConfig:
    api_key = ""
    if row.api_key_encrypted:
        api_key = get_cipher().decrypt(row.api_key_encrypted)
    return ProviderConfig(
        name=str(row.provider_name).strip().lower(),
        enabled=bool(row.enabled),
        default_model=str(row.default_model or ""),
        api_key=api_key,
        base_url=str(row.base_url or "").strip(),
        max_concurrent=int(row.max_concurrent or 10),
        rate_per_minute=float(row.rate_per_minute or 60.0),
        tier=str(row.tier or "paid"),
        cost_per_1k_input_usd=float(row.cost_per_1k_input_usd or 0.0),
        cost_per_1k_output_usd=float(row.cost_per_1k_output_usd or 0.0),
        is_local=bool(row.is_local),
        credential_id=int(row.id),
        label=str(row.label or "default"),
        is_default=bool(row.is_default),
        is_fallback=bool(row.is_fallback),
        source="db",
    )


def build_provider_for_credential(row: AiProviderCredential) -> LlmProvider:
    return build_provider(provider_config_from_credential(row))


def ensure_legacy_model(session: Session, credential: AiProviderCredential) -> AiProviderModel | None:
    """Preserve a configured pre-registry model as selected/unverified."""
    current = session.execute(
        select(AiProviderModel).where(
            AiProviderModel.provider_credential_id == credential.id,
            AiProviderModel.is_selected.is_(True),
        )
    ).scalars().first()
    if current is not None or not str(credential.default_model or "").strip():
        return current
    now = _now()
    model_id = str(credential.default_model).strip()
    row = AiProviderModel(
        provider_credential_id=credential.id,
        provider_name=credential.provider_name,
        provider_model_id=model_id,
        runtime_model_id=model_id,
        display_name=None,
        is_available=None,
        is_enabled=True,
        is_selected=True,
        discovery_source="legacy",
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    session.flush()
    return row


def sync_legacy_configured_model(session: Session, credential: AiProviderCredential) -> AiProviderModel | None:
    """Make a manual legacy ``default_model`` edit the explicit selection."""
    model_id = str(credential.default_model or "").strip()
    if not model_id:
        return None
    row = session.execute(
        select(AiProviderModel).where(
            AiProviderModel.provider_credential_id == credential.id,
            AiProviderModel.runtime_model_id == model_id,
        ).order_by(AiProviderModel.is_available.is_(True).desc(), AiProviderModel.id)
    ).scalars().first()
    now = _now()
    if row is None:
        row = AiProviderModel(
            provider_credential_id=credential.id,
            provider_name=credential.provider_name,
            provider_model_id=model_id,
            runtime_model_id=model_id,
            is_available=None,
            is_enabled=True,
            discovery_source="legacy",
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()
    session.execute(
        update(AiProviderModel)
        .where(AiProviderModel.provider_credential_id == credential.id)
        .values(is_selected=False)
    )
    row.is_selected = True
    row.updated_at = now
    return row


async def refresh_models(
    session: Session,
    credential: AiProviderCredential,
    *,
    provider: LlmProvider | None = None,
) -> RefreshResult:
    """Refresh one credential atomically; failures leave existing rows intact."""
    provider = provider or build_provider_for_credential(credential)
    discovered = await provider.list_models()
    by_provider_id: dict[str, DiscoveredModel] = {}
    for item in discovered:
        if item.provider_name != credential.provider_name:
            item = item.model_copy(update={"provider_name": credential.provider_name})
        by_provider_id[item.provider_model_id] = item

    existing = session.execute(
        select(AiProviderModel).where(AiProviderModel.provider_credential_id == credential.id)
    ).scalars().all()
    existing_by_id = {str(row.provider_model_id): row for row in existing}
    now = _now()
    created = updated_count = unavailable = 0
    for provider_id, item in by_provider_id.items():
        row = existing_by_id.get(provider_id)
        if row is None:
            row = AiProviderModel(
                provider_credential_id=credential.id,
                provider_name=credential.provider_name,
                provider_model_id=provider_id,
                runtime_model_id=item.runtime_model_id,
                created_at=now,
                first_discovered_at=now,
                is_selected=False,
                is_enabled=True,
            )
            session.add(row)
            created += 1
        else:
            updated_count += 1
            if row.first_discovered_at is None:
                row.first_discovered_at = now
        row.runtime_model_id = item.runtime_model_id
        row.display_name = item.display_name
        row.provider_name = credential.provider_name
        row.is_available = True
        row.supports_chat = item.supports_chat
        row.supports_structured_output = item.supports_structured_output
        row.supports_streaming = item.supports_streaming
        row.supports_tools = item.supports_tools
        row.context_window = item.context_window
        row.max_output_tokens = item.max_output_tokens
        row.discovery_source = "live"
        row.last_discovered_at = now
        row.raw_metadata = _sanitize_metadata(item.raw_metadata)
        row.updated_at = now

    returned_ids = set(by_provider_id)
    for row in existing:
        if row.provider_model_id not in returned_ids:
            if row.is_available is not False:
                unavailable += 1
            row.is_available = False
            row.updated_at = now
    session.commit()
    return RefreshResult(len(by_provider_id), created, updated_count, unavailable)


def select_model(session: Session, credential: AiProviderCredential, model: AiProviderModel) -> None:
    if model.provider_credential_id != credential.id:
        raise ValueError("model does not belong to this provider credential")
    if model.is_available is not True or not model.is_enabled:
        raise ValueError("only an available, enabled model can be selected")
    if model.supports_chat is False or model.supports_structured_output is False:
        raise ValueError("model is known to be incompatible with AI generation requirements")
    session.execute(
        update(AiProviderModel)
        .where(AiProviderModel.provider_credential_id == credential.id)
        .values(is_selected=False)
    )
    model.is_selected = True
    credential.default_model = model.runtime_model_id
    now = _now()
    model.updated_at = now
    credential.updated_at = now
    session.commit()
    get_loader().invalidate()


async def test_model(
    session: Session,
    credential: AiProviderCredential,
    model: AiProviderModel,
    *,
    provider: LlmProvider | None = None,
) -> tuple[bool, str | None]:
    if model.provider_credential_id != credential.id:
        raise ValueError("model does not belong to this provider credential")
    provider = provider or build_provider_for_credential(credential)
    now = _now()
    try:
        response = await provider.generate(LlmRequest(
            system="Return only JSON matching the requested schema.",
            user='Return {"ok": true}.',
            response_schema={
                "type": "object",
                "properties": {"ok": {"type": "boolean", "const": True}},
                "required": ["ok"],
                "additionalProperties": False,
            },
            max_output_tokens=32,
            temperature=0.0,
            request_id=f"model-test-{uuid4()}",
            purpose="model_test",
            model=model.runtime_model_id,
        ))
        ok = isinstance(response.parsed, dict) and response.parsed.get("ok") is True
        error = None if ok else "Model generated a response but did not return the required structured JSON."
    except Exception as exc:  # noqa: BLE001
        log.info("ai.model_test.failed provider=%s model_id=%s error_type=%s", credential.provider_name, model.id, type(exc).__name__)
        ok = False
        error = "Model generation test failed. Check model access and provider configuration."
    model.last_verified_at = now
    model.last_test_success = ok
    model.last_test_error = error
    model.updated_at = now
    session.commit()
    return ok, error


__all__ = [
    "RefreshResult", "build_provider_for_credential", "ensure_legacy_model",
    "provider_config_from_credential", "refresh_models", "select_model", "sync_legacy_configured_model", "test_model",
]
