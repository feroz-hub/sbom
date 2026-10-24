"""Provider and account vocabularies; no authentication or account linking."""

from enum import StrEnum


class IdentityProvider(StrEnum):
    HCL_CS = "HCL_CS"
    NATIVE = "NATIVE"
    MICROSOFT_ENTRA = "MICROSOFT_ENTRA"


class AccountStatus(StrEnum):
    # PENDING requires administrator approval; Native activation uses the
    # separate PENDING_EMAIL_VERIFICATION state.
    PENDING = "PENDING"
    PENDING_EMAIL_VERIFICATION = "PENDING_EMAIL_VERIFICATION"
    ACTIVE = "ACTIVE"
    LOCKED = "LOCKED"
    SUSPENDED = "SUSPENDED"
    DISABLED = "DISABLED"
    FORCE_PASSWORD_CHANGE = "FORCE_PASSWORD_CHANGE"


class AccountActionPurpose(StrEnum):
    ACCOUNT_ACTIVATION = "ACCOUNT_ACTIVATION"
    PASSWORD_RESET = "PASSWORD_RESET"
    EMAIL_CHANGE = "EMAIL_CHANGE"


def canonicalize_email(value: str | None) -> str | None:
    """Canonical profile value, not an account-linking or validation rule.

    Preserve dots, plus suffixes and Unicode; do not guess provider aliases.
    The existing identity service remains responsible for address validation.
    """
    return (value.strip().lower() or None) if value is not None else None
