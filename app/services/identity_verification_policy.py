"""Shared access eligibility; directory authentication is not mailbox verification."""
from sqlalchemy import and_, exists, or_, select

from ..models import IAMUser, UserIdentity


def verification_complete(user: IAMUser) -> bool:
    if user.verification_required:
        return False
    return bool(user.email_verified or any(
        identity.provider_type == "MICROSOFT_ENTRA" for identity in getattr(user, "identities", ())
    ))


def verification_complete_clause():
    """Use the same rule in candidate searches and last-administrator counts."""
    directory_identity = exists(select(UserIdentity.id).where(
        UserIdentity.user_id == IAMUser.id,
        UserIdentity.provider_type == "MICROSOFT_ENTRA",
    ).correlate(IAMUser))
    return and_(IAMUser.verification_required.is_(False), or_(IAMUser.email_verified.is_(True), directory_identity))
