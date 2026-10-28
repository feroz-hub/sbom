"""Single-directory access-token validation and pending-only provisioning."""

import json
from datetime import UTC, datetime
from functools import lru_cache
from urllib.parse import urlsplit
from urllib.request import urlopen
from uuid import UUID

import jwt
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..core.identity_states import IdentityAuditEvent
from ..models import IAMUser, UserIdentity
from ..settings import get_settings
from . import audit_service
from .identity_service import normalize_email

PROVIDER = "MICROSOFT_ENTRA"


def issuer():
    return f"https://login.microsoftonline.com/{get_settings().entra_tenant_id}/v2.0"


def validate_configuration():
    settings = get_settings()
    if not settings.entra_enabled:
        return
    errors = []
    for name in ("entra_tenant_id", "entra_frontend_client_id", "entra_api_client_id"):
        value = getattr(settings, name)
        try:
            if str(UUID(value)) != value:
                raise ValueError()
        except (ValueError, TypeError):
            errors.append(name.upper())
    scope = urlsplit(settings.entra_api_scope)
    if (scope.scheme not in {"api", "https"} or not scope.netloc
            or not scope.path.strip("/") or scope.path.endswith("/.default")
            or scope.query or scope.fragment or scope.username or scope.password
            or any(char.isspace() for char in settings.entra_api_scope)):
        errors.append("ENTRA_API_SCOPE")
    if settings.entra_frontend_client_id == settings.entra_api_client_id:
        errors.append("distinct frontend and API registrations")
    if not settings.auth_enabled or settings.dev_default_tenant:
        errors.append("AUTH_ENABLED=true and DEV_DEFAULT_TENANT=false")
    if settings.native_auth_enabled and settings.native_jwt_issuer == issuer():
        errors.append("distinct provider issuers")
    if errors:
        raise RuntimeError("Microsoft Entra configuration invalid: " + ", ".join(errors))


@lru_cache(maxsize=4)
def _jwks_client(tenant_id):
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    with urlopen(f"{authority}/v2.0/.well-known/openid-configuration", timeout=5) as response:
        metadata = json.load(response)
    url = urlsplit(metadata.get("jwks_uri", ""))
    if (metadata.get("issuer") != f"{authority}/v2.0" or url.scheme != "https"
            or url.hostname != "login.microsoftonline.com" or url.username or url.password
            or url.fragment or url.port not in {None, 443}):
        raise ValueError("Invalid Microsoft discovery metadata")
    # PyJWKClient refreshes its JWKS cache and retries an unknown kid.
    return jwt.PyJWKClient(metadata["jwks_uri"], lifespan=300, timeout=5)


def validate_token(token):
    settings = get_settings()
    if not settings.entra_enabled:
        raise HTTPException(401, "Authentication required")
    try:
        validate_configuration()
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str) or not header["kid"]:
            raise ValueError()
        key = _jwks_client(settings.entra_tenant_id).get_signing_key_from_jwt(token)
        if key.key_type != "RSA" or key.public_key_use not in {None, "sig"}:
            raise ValueError()
        key_issuer = key._jwk_data.get("issuer")
        if key_issuer and key_issuer.replace("{tenantid}", settings.entra_tenant_id) != issuer():
            raise ValueError()
        claims = jwt.decode(
            token, key.key, algorithms=["RS256"], audience=settings.entra_api_client_id,
            issuer=issuer(), options={"require": ["iss", "aud", "exp", "iat", "tid", "oid", "sub", "scp", "azp", "ver", "acct"], "strict_aud": True},
        )
        if (claims["tid"] != settings.entra_tenant_id or claims["ver"] != "2.0"
                or claims["azp"] != settings.entra_frontend_client_id
                or claims["acct"] not in (0, "0") or isinstance(claims["acct"], bool)
                or claims.get("idtyp") == "app"
                or not isinstance(claims["sub"], str) or not claims["sub"].strip()
                or str(UUID(claims["oid"])) != claims["oid"]
                or not isinstance(claims["scp"], str)
                or settings.entra_api_scope.rsplit("/", 1)[-1] not in claims["scp"].split()):
            raise ValueError()
        return claims
    except Exception:
        # Provider/network/parser errors must never disclose bearer material.
        raise HTTPException(401, "Invalid Microsoft Entra access token") from None


def _profile_text(claims, name, limit):
    value = claims.get(name)
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else None


def provision_user(db, claims, *, request=None):
    """Only accept validated claims. Never search or link an account by email."""
    query = select(UserIdentity).where(
        UserIdentity.provider_type == PROVIDER,
        UserIdentity.issuer == claims["iss"], UserIdentity.subject == claims["oid"],
    )
    identity = db.scalar(query)
    now = datetime.now(UTC)
    if identity is None:
        try:
            with db.begin_nested():
                email = _profile_text(claims, "email", 320) or _profile_text(claims, "preferred_username", 320)
                try:
                    email = normalize_email(email)
                except (HTTPException, ValueError):
                    email = None
                user = IAMUser(
                    status="PENDING", email=email,
                    display_name=_profile_text(claims, "name", 255) or "Microsoft Entra user",
                    user_principal_name=_profile_text(claims, "preferred_username", 320),
                    # Authentication does not attest to mailbox ownership.
                    email_verified=False, verification_required=False,
                    created_at=now, updated_at=now, last_login_at=now,
                )
                db.add(user)
                db.flush()
                identity = UserIdentity(
                    user_id=user.id, provider_type=PROVIDER, issuer=claims["iss"], subject=claims["oid"],
                    provider_email=email, created_at=now, updated_at=now, last_authenticated_at=now,
                )
                db.add(identity)
                db.flush()
                for event in (IdentityAuditEvent.USER_PROVISIONED, IdentityAuditEvent.EXTERNAL_IDENTITY_LINKED):
                    audit_service.write_authorization_audit(
                        db, action=str(event), actor_user_id=user.id, target_user_id=user.id,
                        request=request, new_value={"provider": PROVIDER, "status": "PENDING"},
                    )
        except IntegrityError:
            # The unique provider/issuer/oid key selects the concurrent winner.
            identity = db.scalar(query)
            if identity is None:
                raise HTTPException(503, "Identity provisioning unavailable") from None
    user = db.get(IAMUser, identity.user_id)
    # Never overwrite administrator status or authority on later sign-ins.
    identity.last_authenticated_at = now
    user.last_login_at = now
    db.flush()
    return user
