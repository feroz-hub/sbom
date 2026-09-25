"""Converge verified native and HCL identities before shared authorization."""

from dataclasses import dataclass

from ..models import IAMUser
from . import native_jwt_service
from .email_verification_service import ensure_initial_verification_delivery
from .identity_service import provision_local_identity


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    provider: str
    user: IAMUser
    claims: dict

    @property
    def local_user_id(self):
        return self.user.id


def resolve_principal(db, claims, *, request=None):
    # Provider routing depends on the verified issuer, never a caller role.
    from ..settings import get_settings

    s = get_settings()
    if s.native_auth_enabled and claims.get("iss") == s.native_jwt_issuer:
        user = native_jwt_service.resolve_user(db, claims)
        return AuthenticatedPrincipal("NATIVE", user, claims)
    provisioned = provision_local_identity(db, claims, request=request)
    db.commit()
    ensure_initial_verification_delivery(db, provisioned.user, request=request)
    db.refresh(provisioned.user)
    return AuthenticatedPrincipal("HCL_CS", provisioned.user, claims)
