"""Validated access-token exchange metadata for the opaque BFF session."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..core.security import get_current_claims
from ..db import get_db
from ..services import entra_auth_service
from ..services.auth_context_service import resolve_authorization_state
from ..services.authenticated_principal_service import resolve_principal
from ..settings import get_settings

router = APIRouter(prefix="/api/auth/entra")


@router.get("/session")
def session(request: Request, claims: dict = Depends(get_current_claims), db: Session = Depends(get_db)):
    if not get_settings().entra_enabled or claims.get("iss") != entra_auth_service.issuer():
        raise HTTPException(401, "Microsoft Entra authentication required")
    principal = resolve_principal(db, claims, request=request)
    state = resolve_authorization_state(db, principal.user, provider=principal.provider)
    db.commit()
    return {"provider": principal.provider, "status": str(state.status), "expires_at": claims["exp"]}
