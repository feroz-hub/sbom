"""Safe dashboard projection of the execution pipeline's effective snapshot.

Only the canonical loader/registry select credentials. Read stored verification
for that exact selected owner; do not probe providers or return credential IDs.
"""

from sqlalchemy import select

from ..core.context import get_bound_context
from ..db import SessionLocal
from ..models import AiProviderCredential, AiSettings
from ..services.configuration_scope import current_configuration_tenant, scope_clause
from ..settings import get_settings
from .config_loader import get_loader
from .provider_factory import validate_provider_config
from .providers.base import ProviderUnavailableError
from .registry import get_registry
from .verification import verification_status


def effective_ai_status() -> dict:
    context = get_bound_context()
    tenant_id = current_configuration_tenant()
    permission_scope = "tenant" if tenant_id is not None else "platform"
    ui_enabled = bool(get_settings().ai_fixes_ui_config_enabled)
    status = {
        "configured": False,
        "source": None,
        "provider": None,
        "model": None,
        "verification_status": "UNVERIFIED",
        "feature_enabled": False,
        "available_for_tenant": False,
        "state": "STATUS_UNAVAILABLE",
        "can_view_settings": bool(ui_enabled and context and context.has_permission(f"{permission_scope}:ai:read")),
        "can_configure": bool(ui_enabled and context and context.has_permission(f"{permission_scope}:ai:update")),
        "settings_scope": permission_scope,
    }
    # The loader enforces active-tenant use and its existing all-or-nothing
    # tenant override policy. Resolution failures never imply missing setup.
    try:
        _, settings = get_loader().resolve()
        status["feature_enabled"] = settings.feature_enabled and not settings.kill_switch_active
        try:
            cfg = get_registry().get_default_config()
        except ProviderUnavailableError:
            cfg = None
        with SessionLocal() as db:
            override = tenant_id is not None and bool(
                db.scalar(select(AiProviderCredential.id).where(scope_clause(AiProviderCredential, tenant_id)).limit(1))
                or db.scalar(select(AiSettings.id).where(scope_clause(AiSettings, tenant_id)).limit(1))
            )
            status["source"] = "TENANT" if override else "PLATFORM"
            if cfg is not None:
                row = (
                    db.scalar(
                        select(AiProviderCredential).where(
                            AiProviderCredential.id == cfg.credential_id,
                            scope_clause(AiProviderCredential, tenant_id if override else None),
                        )
                    )
                    if cfg.credential_id is not None
                    else None
                )
                status.update(
                    configured=bool(row is not None or cfg.enabled), provider=cfg.name, model=cfg.default_model
                )
                status["verification_status"] = verification_status(row) if row is not None else "UNVERIFIED"
                usable = cfg.enabled and not cfg.config_error
                try:
                    validate_provider_config(cfg)
                except ProviderUnavailableError:
                    usable = False
                if not status["feature_enabled"]:
                    status["state"] = "DISABLED"
                elif status["verification_status"] == "TEMPORARILY_UNAVAILABLE":
                    status["state"] = "TEMPORARILY_UNAVAILABLE"
                elif status["configured"] and (not usable or status["verification_status"] == "INVALID_CREDENTIALS"):
                    status["state"] = "CONFIGURATION_UNAVAILABLE"
                elif not status["configured"]:
                    status["state"] = "CONFIGURATION_REQUIRED"
                elif status["verification_status"] == "VERIFIED":
                    status["state"] = "AVAILABLE"
                    status["available_for_tenant"] = True
                else:
                    status["state"] = "VERIFICATION_PENDING"
            else:
                status["state"] = "CONFIGURATION_REQUIRED" if status["feature_enabled"] else "DISABLED"
    except Exception:
        # Never return resolver/decryption exception text to the dashboard.
        status["state"] = "STATUS_UNAVAILABLE"
        status["available_for_tenant"] = False
    return status
