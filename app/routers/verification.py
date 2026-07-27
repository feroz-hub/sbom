"""Authenticated verification status/resend and token-based confirmation."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..core.identity_states import IdentityErrorCode
from ..core.security import get_current_user
from ..db import get_db
from ..rate_limit import verification_confirm_route_limit
from ..services.email_verification_service import (
    GENERIC_INVALID_MESSAGE,
    VerificationRateLimited,
    VerificationTokenInvalid,
    confirm_verification_token,
    ensure_initial_verification_delivery,
    issue_verification_email,
    verification_context,
)
from ..services.identity_service import provision_local_identity

router = APIRouter(prefix="/api/auth/verification", tags=["identity-verification"])


class ConfirmVerificationRequest(BaseModel):
    token: str = Field(min_length=40, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


def _status_response(user, context) -> dict:
    return {
        "email_verified": bool(user.email_verified),
        "verification_required": bool(user.verification_required),
        "delivery_status": context.delivery_status if context else None,
        "last_sent_at": context.last_sent_at if context else None,
        "resend_available_at": context.resend_available_at if context else None,
        "expires_at": context.expires_at if context else None,
    }


@router.get("/status")
def verification_status(
    request: Request,
    claims: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    provisioned = provision_local_identity(db, claims, request=request)
    db.commit()
    ensure_initial_verification_delivery(db, provisioned.user, request=request)
    db.refresh(provisioned.user)
    return _status_response(
        provisioned.user,
        verification_context(db, provisioned.user),
    )


@router.post("/resend")
def resend_verification(
    request: Request,
    claims: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    provisioned = provision_local_identity(db, claims, request=request)
    db.commit()
    user = provisioned.user
    if user.email_verified and not user.verification_required:
        return {
            "status": "VERIFIED",
            "delivery_status": None,
            "message": "Email verification has already been completed.",
            "resend_available_at": None,
        }
    try:
        delivery = issue_verification_email(
            db,
            user.id,
            request=request,
            resend=True,
        )
    except VerificationRateLimited as exc:
        retry_after = max(
            1,
            int((exc.resend_available_at - datetime.now(UTC)).total_seconds()),
        )
        raise HTTPException(
            status_code=429,
            detail={
                "code": str(IdentityErrorCode.VERIFICATION_RESEND_RATE_LIMITED),
                "message": "Please wait before requesting another verification email.",
                "resend_available_at": exc.resend_available_at.isoformat(),
            },
            headers={"Retry-After": str(retry_after)},
        ) from None
    sent = delivery.status == "SENT"
    return {
        "status": "VERIFICATION_REQUIRED",
        "delivery_status": delivery.status,
        "message": (
            "A verification email has been sent to your registered email address. "
            "Please verify your account to continue."
            if sent
            else "We could not send the verification email. Please try again later."
        ),
        "resend_available_at": (
            delivery.resend_available_at.isoformat()
            if delivery.resend_available_at
            else None
        ),
    }


@router.post("/confirm")
@verification_confirm_route_limit
def confirm_verification(
    request: Request,
    payload: ConfirmVerificationRequest,
    db: Session = Depends(get_db),
) -> dict:
    try:
        confirm_verification_token(db, payload.token, request=request)
    except VerificationTokenInvalid:
        raise HTTPException(
            status_code=400,
            detail={
                "code": str(IdentityErrorCode.VERIFICATION_TOKEN_INVALID),
                "message": GENERIC_INVALID_MESSAGE,
            },
        ) from None
    return {
        "status": "VERIFIED",
        "message": "Your email has been verified successfully.",
        "next_action": "REFRESH_AUTH_CONTEXT",
    }
