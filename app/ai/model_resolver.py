"""Canonical resolver for models selected in the persistent registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AiProviderCredential, AiProviderModel

AiFeature = Literal["provider_default", "ai_fix", "copilot", "validation_repair", "batch_ai_fix"]


@dataclass(frozen=True)
class ResolvedModel:
    model_id: str
    source: str
    registry_model_id: int | None = None


def resolve_model_for_credential(
    session: Session,
    credential: AiProviderCredential,
    *,
    feature: AiFeature = "provider_default",
) -> ResolvedModel:
    """Resolve one credential's effective runtime model.

    ``feature`` is accepted now as the extension point for future feature
    assignments. Current precedence is selected registry model, then the
    credential's preserved legacy default. An unavailable selected row remains
    selected until an administrator explicitly switches it.
    """
    del feature
    selected = session.execute(
        select(AiProviderModel)
        .where(
            AiProviderModel.provider_credential_id == credential.id,
            AiProviderModel.is_selected.is_(True),
        )
        .order_by(AiProviderModel.id)
    ).scalars().first()
    if selected is not None and selected.runtime_model_id:
        return ResolvedModel(
            model_id=str(selected.runtime_model_id),
            source="registry_selected",
            registry_model_id=int(selected.id),
        )
    return ResolvedModel(model_id=str(credential.default_model or ""), source="legacy_configured")


def resolve_model(
    session: Session,
    provider_name: str,
    *,
    feature: AiFeature = "provider_default",
) -> ResolvedModel | None:
    """Resolve the default configured credential for a provider name."""
    rows = session.execute(
        select(AiProviderCredential)
        .where(
            AiProviderCredential.provider_name == provider_name.strip().lower(),
            AiProviderCredential.enabled.is_(True),
        )
        .order_by(AiProviderCredential.is_default.desc(), AiProviderCredential.id)
    ).scalars().all()
    if not rows:
        return None
    return resolve_model_for_credential(session, rows[0], feature=feature)


__all__ = ["AiFeature", "ResolvedModel", "resolve_model", "resolve_model_for_credential"]
