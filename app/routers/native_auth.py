"""Public native credentials and explicit administrator enrollment permissions."""

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import require_permission, require_platform_permission
from ..db import get_db
from ..services import native_auth_service as auth
from ..services import native_enrollment_service as enrollment
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
def login(payload: Login, response: Response, db: Session = Depends(get_db)):
    if not get_settings().native_auth_enabled:
        raise HTTPException(404, "Native authentication unavailable")
    token = auth.login(db, payload.email, payload.password)
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
def activate(payload: Activation, db: Session = Depends(get_db)):
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
    return {"user_id": user.id, "status": user.status, "delivery": enrollment.deliver_activation(user, issued)}


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
    tenant_id: int,
    user_id: int,
    context: CurrentContext = Depends(require_permission("tenant:user:invite")),
    db: Session = Depends(get_db),
):
    try:
        user, issued = enrollment.resend(db, context, tenant_id, user_id)
        db.commit()
    except InvalidAccountActionToken:
        db.rollback()
        raise HTTPException(400, "Activation unavailable") from None
    return {"user_id": user.id, "delivery": enrollment.deliver_activation(user, issued)}
