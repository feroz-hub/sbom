"""Shadow-only comparison of local and validated HCL IAM identity grants."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.identity_grants import (
    IdentityGrantParseError,
    IdentityGrantScope,
    parse_identity_grant,
)
from app.core.identity_states import IdentityAuditEvent
from app.settings import IdentityGrantAuthorityMode, get_settings

from . import audit_service, tenant_role_assignment_service
from .identity_grant_service import (
    IdentityGrantValidationError,
    validate_identity_grant,
)

if TYPE_CHECKING:
    from .auth_context_service import ResolvedAuthorizationState

log = logging.getLogger("sbom.identity_grants")

_MISSING = object()
_CLAIM_SHAPE_INVALID = "CLAIM_SHAPE_INVALID"
_PARSE_ERROR = "PARSE_ERROR"


class IdentityGrantAuthorityModeError(RuntimeError):
    """Raised when the not-yet-supported IAM authority mode is consumed."""


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    """Normalized semantic authority used only for deterministic comparison."""

    scope: IdentityGrantScope
    tenant_id: int | None
    role: str


@dataclass(frozen=True, slots=True)
class IAMShadowAuthority:
    """Validated IAM shadow grants and safe invalid-reason counts."""

    grants: frozenset[AuthorityGrant]
    invalid_reason_counts: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True, slots=True)
class IdentityAuthorityComparison:
    """Order-independent comparison result; never an authorization decision."""

    matched: frozenset[AuthorityGrant]
    local_only: frozenset[AuthorityGrant]
    iam_only: frozenset[AuthorityGrant]
    invalid_iam_reason_counts: tuple[tuple[str, int], ...] = ()

    @property
    def is_match(self) -> bool:
        return not (
            self.local_only
            or self.iam_only
            or self.invalid_iam_reason_counts
        )


def _configured_claim(claims: Mapping[str, Any], path: str) -> object:
    value: object = claims
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _authority_grant(*, scope: IdentityGrantScope, tenant_id: int | None, role: str) -> AuthorityGrant:
    return AuthorityGrant(scope=scope, tenant_id=tenant_id, role=role)


def local_authority_grants(
    db: Session,
    state: ResolvedAuthorizationState,
    *,
    request: Request | None = None,
) -> frozenset[AuthorityGrant]:
    """Represent the same effective local grants used by current authorization."""
    grants: set[AuthorityGrant] = set()
    for membership, tenant in state.memberships:
        role_codes = tenant_role_assignment_service.effective_role_codes(
            db,
            membership,
            actor_user_id=state.user.id,
            request=request,
        )
        grants.update(
            _authority_grant(
                scope=IdentityGrantScope.TENANT,
                tenant_id=tenant.id,
                role=role,
            )
            for role in role_codes
        )
    if state.is_platform_admin:
        grants.add(
            _authority_grant(
                scope=IdentityGrantScope.PLATFORM,
                tenant_id=None,
                role="PLATFORM_ADMIN",
            )
        )
    return frozenset(grants)


def iam_shadow_authority(
    db: Session,
    claims: Mapping[str, Any],
    *,
    claim_path: str,
) -> IAMShadowAuthority:
    """Parse and validate configured claims without granting any authority."""
    raw_claim = _configured_claim(claims, claim_path)
    if raw_claim is _MISSING:
        return IAMShadowAuthority(frozenset())
    if isinstance(raw_claim, str):
        values: list[object] = [raw_claim]
    elif isinstance(raw_claim, list):
        values = list(raw_claim)
    else:
        return IAMShadowAuthority(
            frozenset(),
            ((_CLAIM_SHAPE_INVALID, 1),),
        )

    grants: set[AuthorityGrant] = set()
    invalid_reasons: Counter[str] = Counter()
    for value in values:
        try:
            parsed = parse_identity_grant(value)
        except IdentityGrantParseError:
            invalid_reasons[_PARSE_ERROR] += 1
            continue
        try:
            validated = validate_identity_grant(db, parsed)
        except IdentityGrantValidationError as exc:
            invalid_reasons[exc.reason.value] += 1
            continue
        grants.add(
            _authority_grant(
                scope=validated.scope,
                tenant_id=validated.tenant_id,
                role=validated.role,
            )
        )
    return IAMShadowAuthority(
        grants=frozenset(grants),
        invalid_reason_counts=tuple(sorted(invalid_reasons.items())),
    )


def compare_identity_grant_authority(
    local: frozenset[AuthorityGrant],
    iam: IAMShadowAuthority,
) -> IdentityAuthorityComparison:
    """Compare normalized sets without order, precedence, or access semantics."""
    return IdentityAuthorityComparison(
        matched=local & iam.grants,
        local_only=local - iam.grants,
        iam_only=iam.grants - local,
        invalid_iam_reason_counts=iam.invalid_reason_counts,
    )


def _grant_sort_key(grant: AuthorityGrant) -> tuple[str, int, str]:
    return (
        grant.scope.value,
        grant.tenant_id if grant.tenant_id is not None else -1,
        grant.role,
    )


def _audit_grant(grant: AuthorityGrant) -> dict[str, str | int | None]:
    return {
        "scope": grant.scope.value,
        "tenant_id": grant.tenant_id,
        "role": grant.role,
    }


def _record_comparison(
    db: Session,
    *,
    state: ResolvedAuthorizationState,
    comparison: IdentityAuthorityComparison,
    request: Request | None,
) -> None:
    try:
        audit_service.write_authorization_audit(
            db,
            action=str(IdentityAuditEvent.IDENTITY_AUTHORITY_COMPARE),
            outcome="SUCCESS" if comparison.is_match else "FAILED",
            actor_user_id=state.user.id,
            target_user_id=state.user.id,
            tenant_id=None,
            request=request,
            new_value={
                "mode": IdentityGrantAuthorityMode.COMPARE.value,
                "status": "MATCH" if comparison.is_match else "MISMATCH",
                "matched_count": len(comparison.matched),
                "local_only_count": len(comparison.local_only),
                "iam_only_count": len(comparison.iam_only),
                "invalid_iam_reason_counts": dict(
                    comparison.invalid_iam_reason_counts
                ),
                "local_only": [
                    _audit_grant(grant)
                    for grant in sorted(comparison.local_only, key=_grant_sort_key)
                ],
                "iam_only": [
                    _audit_grant(grant)
                    for grant in sorted(comparison.iam_only, key=_grant_sort_key)
                ],
            },
            detail=(
                "IDENTITY_AUTHORITY_MATCH"
                if comparison.is_match
                else "IDENTITY_AUTHORITY_MISMATCH"
            ),
            platform_global=True,
        )
    except Exception:  # noqa: BLE001 - observability must not affect LOCAL access
        log.exception("identity_grant.compare_audit_failed")


def observe_identity_grant_authority(
    db: Session,
    state: ResolvedAuthorizationState,
    claims: Mapping[str, Any],
    *,
    request: Request | None = None,
) -> IdentityAuthorityComparison | None:
    """Observe COMPARE mode and leave the locally resolved state untouched.

    LOCAL performs no IAM grant processing. COMPARE records a shadow-only
    comparison. IAM authority is deliberately unavailable until Phase 6.
    """
    settings = get_settings()
    mode = settings.identity_grant_authority_mode
    if mode is IdentityGrantAuthorityMode.LOCAL:
        return None
    if mode is IdentityGrantAuthorityMode.IAM:
        raise IdentityGrantAuthorityModeError(
            "IAM identity-grant authority is not enabled in this build"
        )

    local = local_authority_grants(db, state, request=request)
    iam = iam_shadow_authority(
        db,
        claims,
        claim_path=settings.hcl_iam_grant_claim,
    )
    comparison = compare_identity_grant_authority(local, iam)
    _record_comparison(
        db,
        state=state,
        comparison=comparison,
        request=request,
    )
    return comparison
