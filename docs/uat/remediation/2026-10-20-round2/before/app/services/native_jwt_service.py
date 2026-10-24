"""Strict native identity tokens. Roles and permissions are never token authority."""

import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import IAMUser, NativeUserCredential, UserIdentity
from ..settings import get_settings

REQUIRED = ["iss", "sub", "aud", "iat", "exp", "jti", "auth_provider", "security_version"]


def validate_configuration() -> None:
    s = get_settings()
    issuer = urlsplit(s.native_jwt_issuer)
    if (
        not s.native_auth_enabled
        or not s.auth_enabled
        or s.native_jwt_algorithm != "RS256"
        or issuer.scheme != "https"
        or not issuer.netloc
        or issuer.username
        or issuer.query
        or issuer.fragment
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", s.native_jwt_active_kid)
        or not s.native_jwt_audience.strip()
        or s.native_jwt_issuer == s.hcl_iam_issuer
        or s.tenant_role_assignment_mode != "DATABASE"
        or s.authorization_catalog_mode != "DATABASE"
        or not s.tenant_role_assignment_fail_closed
        or not s.authorization_catalog_fail_closed
    ):
        raise RuntimeError("Invalid native JWT configuration")


def active_signing_key() -> rsa.RSAPrivateKey:
    validate_configuration()
    s = get_settings()
    try:
        key = serialization.load_pem_private_key(s.native_jwt_private_key.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
            raise ValueError()
        return key
    except (ValueError, TypeError):
        raise RuntimeError("Invalid native JWT signing key") from None


# Compatibility name for existing issuing paths. Never used by validation.
signing_key = active_signing_key


def active_verification_key() -> rsa.RSAPublicKey:
    validate_configuration()
    try:
        key = serialization.load_pem_public_key(get_settings().native_jwt_public_key.encode())
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError()
        return key
    except (ValueError, TypeError):
        raise RuntimeError("Invalid native JWT public verification key") from None


def verification_key_for_kid(kid) -> rsa.RSAPublicKey:
    s = get_settings()
    if kid is None or kid == s.native_jwt_active_kid:
        return active_verification_key()
    keys = json.loads(s.native_jwt_verification_keys_json)
    entry = keys.get(kid) if isinstance(keys, dict) and isinstance(kid, str) else None
    if (
        not isinstance(entry, dict)
        or type(entry.get("not_after")) is not int
        or entry["not_after"] <= int(datetime.now(UTC).timestamp())
        or not isinstance(entry.get("public_key"), str)
    ):
        raise jwt.InvalidTokenError()
    key = serialization.load_pem_public_key(entry["public_key"].encode())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise jwt.InvalidTokenError()
    return key


def issue_token(user: IAMUser, credential: NativeUserCredential) -> str:
    s = get_settings()
    now = int(datetime.now(UTC).timestamp())
    return jwt.encode(
        dict(
            iss=s.native_jwt_issuer,
            sub=str(user.id),
            aud=s.native_jwt_audience,
            iat=now,
            exp=now + s.native_jwt_access_token_ttl_seconds,
            jti=str(uuid4()),
            auth_provider="NATIVE",
            security_version=credential.security_version,
        ),
        signing_key(),
        algorithm="RS256",
        headers={"kid": s.native_jwt_active_kid},
    )


def validate_token(token: str) -> dict[str, Any]:
    s = get_settings()
    validate_configuration()
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        verification_key = verification_key_for_kid(kid)
        claims = jwt.decode(
            token,
            verification_key,
            algorithms=["RS256"],
            issuer=s.native_jwt_issuer,
            audience=s.native_jwt_audience,
            options={"require": REQUIRED},
        )
        if (
            claims["auth_provider"] != "NATIVE"
            or not isinstance(claims["sub"], str)
            or not claims["sub"].isascii()
            or not claims["sub"].isdigit()
            or str(int(claims["sub"])) != claims["sub"]
            or not 0 < int(claims["sub"]) <= 2147483647
            or type(claims["security_version"]) is not int
            or claims["security_version"] < 1
            or not isinstance(claims["jti"], str)
            or not claims["jti"].strip()
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or claims["exp"] <= claims["iat"]
            or ("nbf" in claims and type(claims["nbf"]) is not int)
        ):
            raise jwt.InvalidTokenError()
        return claims
    except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
        raise HTTPException(401, "Authentication required") from None


def resolve_user(db: Session, claims: dict[str, Any]) -> IAMUser:
    user = db.get(IAMUser, int(claims["sub"]), populate_existing=True)
    credential = db.scalar(
        select(NativeUserCredential)
        .where(NativeUserCredential.user_id == int(claims["sub"]))
        .execution_options(populate_existing=True)
    )
    identity = db.scalar(
        select(UserIdentity.id).where(
            UserIdentity.user_id == int(claims["sub"]), UserIdentity.provider_type == "NATIVE"
        )
    )
    if (
        not user
        or user.status != "ACTIVE"
        or not credential
        or not identity
        or credential.security_version != claims["security_version"]
    ):
        raise HTTPException(401, "Authentication required")
    return user
