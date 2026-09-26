"""Public native credentials and explicit administrator enrollment permissions."""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.native_identity import canonicalize_email
from ..core.security import get_current_claims, require_permission, require_platform_permission
from ..db import SessionLocal, get_db
from ..models import IAMUser, UserIdentity
from ..services import native_abuse_service as abuse
from ..services import native_auth_service as auth
from ..services import native_enrollment_service as enrollment
from ..services import native_jwt_service, native_security_delivery
from ..services import native_password_service as passwords
from ..services.account_action_token_service import InvalidAccountActionToken
from ..services.identity_service import normalize_email
from ..services.tenant_role_assignment_service import AssignmentProblem
from ..settings import get_settings

router = APIRouter(prefix="/api")


class Login(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024, repr=False)


class Activation(BaseModel):
    token: str = Field(min_length=1, max_length=128, repr=False)
    password: str = Field(min_length=1, max_length=1024, repr=False)


class NewUser(BaseModel):
    first_name: str = Field(min_length=1, max_length=120)
    last_name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=1, max_length=320)
    phone: str = Field(min_length=1, max_length=64)
    tenant_id: int = Field(gt=0)
    role_codes: list[str] = Field(min_length=1, max_length=32)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value):
        result = normalize_email(value)
        if not result:
            raise ValueError("Valid email required")
        return result


class Membership(BaseModel):
    user_id: int = Field(gt=0)
    role_codes: list[str] = Field(min_length=1, max_length=32)


@router.post("/auth/native/login")
def login(payload: Login, response: Response, request: Request, db: Session = Depends(get_db)):
    if not get_settings().native_auth_enabled:
        raise HTTPException(404, "Native authentication unavailable")
    abuse.check(request, "login", payload.email)
    identity = db.scalar(
        select(UserIdentity).where(
            UserIdentity.provider_type == "NATIVE",
            UserIdentity.provider_identifier == canonicalize_email(payload.email),
        )
    )
    if identity and db.get(IAMUser, identity.user_id).status == "FORCE_PASSWORD_CHANGE":
        proved = passwords.forced_proof(db, payload.email, payload.password)
        db.commit()
        if not proved:
            raise HTTPException(401, "Invalid email or password")
        return {"password_change_required": True}
    token = auth.login(db, payload.email, payload.password)
    if token:
        passwords.audit(db, "SESSION_CREATED", identity.user_id)
    db.commit()  # Failed attempts must persist before returning 401.
    if token is None:
        raise HTTPException(401, "Invalid email or password")
    response.headers["Cache-Control"] = "no-store"
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": get_settings().native_jwt_access_token_ttl_seconds,
    }


@router.post("/auth/native/activate")
def activate(payload: Activation, request: Request, db: Session = Depends(get_db)):
    abuse.check(request, "activation", payload.token)
    try:
        auth.activate(db, payload.token, payload.password)
        db.commit()
    except InvalidAccountActionToken:
        db.rollback()
        raise HTTPException(400, "Activation link is invalid or unavailable") from None
    return {"status": "ACTIVE"}


def _create(payload, context, db):
    try:
        user, issued = enrollment.create_user(db, context, payload)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Native identity or membership already exists") from None
    except AssignmentProblem as exc:
        db.rollback()
        raise HTTPException(exc.status_code, str(exc)) from None
    return {"user_id": user.id, "status": user.status, "delivery": ({"status": "PENDING", "error_code": None} if get_settings().native_security_outbox_enabled else enrollment.deliver_activation(user, issued))}


@router.post("/platform/native-users", status_code=201)
def platform_create(
    payload: NewUser,
    context: CurrentContext = Depends(require_platform_permission("platform:user:manage_status")),
    db: Session = Depends(get_db),
):
    return _create(payload, context, db)


@router.post("/tenants/{tenant_id}/native-users", status_code=201)
def tenant_create(
    tenant_id: int,
    payload: NewUser,
    context: CurrentContext = Depends(require_permission("tenant:user:invite")),
    db: Session = Depends(get_db),
):
    if tenant_id != payload.tenant_id:
        raise HTTPException(403, "Tenant scope mismatch")
    return _create(payload, context, db)


@router.post("/tenants/{tenant_id}/memberships", status_code=201)
def add_existing(
    tenant_id: int,
    payload: Membership,
    context: CurrentContext = Depends(require_permission("tenant:user:invite")),
    db: Session = Depends(get_db),
):
    try:
        member = enrollment.add_membership(db, context, tenant_id, payload.user_id, payload.role_codes)
        db.commit()
    except AssignmentProblem as exc:
        db.rollback()
        raise HTTPException(exc.status_code, str(exc)) from None
    return {"membership_id": member.id, "user_id": member.user_id, "tenant_id": member.tenant_id}


@router.post("/tenants/{tenant_id}/native-users/{user_id}/resend-activation")
def resend(
    request: Request,
    tenant_id: int,
    user_id: int,
    context: CurrentContext = Depends(require_permission("tenant:user:invite")),
    db: Session = Depends(get_db),
):
    abuse.check(request, "resend", str(user_id))
    try:
        user, issued = enrollment.resend(db, context, tenant_id, user_id)
        db.commit()
    except InvalidAccountActionToken:
        db.rollback()
        raise HTTPException(400, "Activation unavailable") from None
    return {"user_id": user.id, "delivery": ({"status": "PENDING", "error_code": None} if get_settings().native_security_outbox_enabled else enrollment.deliver_activation(user, issued))}


class ForgotPassword(BaseModel):
    email: str = Field(max_length=320)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024, repr=False)
    new_password: str = Field(min_length=1, max_length=1024, repr=False)


class ForcedPasswordChange(PasswordChange):
    email: str = Field(min_length=1, max_length=320)


class PasswordReset(BaseModel):
    token: str = Field(min_length=1, max_length=128, repr=False)
    new_password: str = Field(min_length=1, max_length=1024, repr=False)


def native_claims(claims: dict = Depends(get_current_claims)):
    if (
        not get_settings().native_auth_enabled
        or claims.get("auth_provider") != "NATIVE"
        or claims.get("iss") != get_settings().native_jwt_issuer
    ):
        raise HTTPException(401, "Native authentication required")
    return claims


def reset_delivery(uid, issued):
    with SessionLocal() as db:
        user = db.get(IAMUser, uid)
        result = native_security_delivery.deliver_reset(user, issued)
        passwords.audit(
            db,
            "PASSWORD_RESET_DELIVERY",
            uid,
            outcome="SUCCESS" if result["status"] == "SENT" else "FAILED",
            new_value={"status": result["status"], "error_code": result["error_code"]},
        )
        db.commit()


@router.post("/auth/native/forgot-password")
def forgot_password(
    payload: ForgotPassword, request: Request, background: BackgroundTasks, db: Session = Depends(get_db)
):
    if not get_settings().native_auth_enabled:
        raise HTTPException(404, "Unavailable")
    abuse.check(request, "forgot-password", payload.email)
    issued = passwords.request_reset(db, payload.email)
    db.commit()
    if issued and not get_settings().native_security_outbox_enabled:
        background.add_task(reset_delivery, issued[0].id, issued[1])
    return {"message": passwords.GENERIC_RESET}


@router.post("/auth/native/reset-password")
def reset_password(payload: PasswordReset, request: Request, db: Session = Depends(get_db)):
    if not get_settings().native_auth_enabled:
        raise HTTPException(404, "Unavailable")
    abuse.check(request, "reset-password", payload.token)
    try:
        passwords.reset_password(db, payload.token, payload.new_password)
        db.commit()
    except InvalidAccountActionToken:
        db.rollback()
        raise HTTPException(400, "Reset link is invalid or unavailable") from None
    return {"success": True}


@router.post("/auth/native/change-password")
def change_password(
    payload: PasswordChange, request: Request, claims: dict = Depends(native_claims), db: Session = Depends(get_db)
):
    abuse.check(request, "change-password", claims["sub"])
    result = passwords.change_password(
        db, int(claims["sub"]), claims["security_version"], payload.current_password, payload.new_password
    )
    db.commit()
    if not result:
        raise HTTPException(401, "Current credential is invalid")
    return {"success": True}


@router.post("/auth/native/force-change-password")
def force_change_password(payload: ForcedPasswordChange, request: Request, db: Session = Depends(get_db)):
    if not get_settings().native_auth_enabled:
        raise HTTPException(404, "Unavailable")
    abuse.check(request, "login", payload.email)
    result = passwords.complete_forced(db, payload.email, payload.current_password, payload.new_password)
    db.commit()
    if not result:
        raise HTTPException(401, "Current credential is invalid")
    return {"success": True}


@router.get("/auth/native/session")
def native_session(claims: dict = Depends(native_claims), db: Session = Depends(get_db)):
    user = native_jwt_service.resolve_user(db, claims)
    return {"authenticated": True, "provider": "NATIVE", "user_id": user.id}


@router.post("/auth/native/logout-all")
def logout_all(request: Request, claims: dict = Depends(native_claims), db: Session = Depends(get_db)):
    abuse.check(request, "logout-all", claims["sub"])
    user, cred, _ = passwords.lock_native(db, int(claims["sub"]))
    if user.status != "ACTIVE" or cred.security_version != claims["security_version"]:
        raise HTTPException(401, "Authentication required")
    cred.security_version += 1
    passwords.audit(db, "ALL_SESSIONS_REVOKED", user.id)
    db.commit()
    return {"success": True}


@router.post("/auth/native/logout")
def record_logout(claims: dict = Depends(native_claims), db: Session = Depends(get_db)):
    user = native_jwt_service.resolve_user(db, claims)
    passwords.audit(db, "SESSION_REVOKED", user.id)
    db.commit()
    return {"success": True}
