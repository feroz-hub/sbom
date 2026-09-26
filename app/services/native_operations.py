"""Secret-safe native IAM deployment checks and operational projections."""

import json
import os
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from redis import Redis
from sqlalchemy import func, select

from ..models import SecurityMailOutbox
from ..settings import get_settings
from . import native_jwt_service
from .security_mail_outbox import cipher


def validate_configuration():
    s = get_settings()
    if not s.native_auth_enabled or not s.native_iam_production:
        return
    errors = []
    try:
        native_jwt_service.signing_key()
        cipher()
    except Exception:
        errors.append("signing_or_outbox_key")
    try:
        keyset = json.loads(s.native_jwt_verification_keys_json)
        if not isinstance(keyset, dict):
            raise ValueError()
        for kid, entry in keyset.items():
            if (
                not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", kid)
                or not isinstance(entry, dict)
                or type(entry.get("not_after")) is not int
            ):
                raise ValueError()
            public = serialization.load_pem_public_key(entry["public_key"].encode())
            if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
                raise ValueError()
    except Exception:
        errors.append("verification_keyset")
    origin = os.getenv("APP_ORIGIN", "")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.username
        or parsed.query
        or parsed.fragment
    ):
        errors.append("canonical_origin")
    for url in [s.native_activation_frontend_url, s.native_password_reset_frontend_url]:
        p = urlsplit(url)
        if p.scheme != "https" or p.netloc != parsed.netloc or p.username or p.query or p.fragment:
            errors.append("security_link_origin")
    if (
        not s.native_security_outbox_enabled
        or not s.email_delivery_enabled
        or not s.smtp_host
        or not s.email_from_address
    ):
        errors.append("durable_smtp_delivery")
    if not (s.smtp_use_tls or s.smtp_use_starttls):
        errors.append("smtp_transport")
    if (
        not s.native_auth_rate_limit_enabled
        or os.getenv("API_RATE_LIMIT_ENABLED", "true").lower() in {"0", "no", "false"}
        or urlsplit(s.native_auth_rate_limit_storage_uri).scheme not in {"redis", "rediss"}
    ):
        errors.append("shared_rate_limits")
    if errors:
        raise RuntimeError("Native IAM configuration invalid: " + ",".join(sorted(set(errors))))


def redis_client():
    return Redis.from_url(get_settings().native_auth_rate_limit_storage_uri, socket_connect_timeout=2, socket_timeout=2)


def heartbeat():
    with redis_client() as client:
        client.set("sbom:iam:mail-worker", "ready", ex=120)


def readiness(db):
    checks = {"database": False, "rate_limits": False, "delivery_worker": False}
    try:
        db.execute(select(SecurityMailOutbox.id).limit(1))
        checks["database"] = True
    except Exception:
        db.rollback()
    try:
        with redis_client() as client:
            checks["rate_limits"] = bool(client.ping())
            checks["delivery_worker"] = get_settings().native_security_outbox_enabled and bool(
                client.exists("sbom:iam:mail-worker")
            )
    except Exception:
        pass
    return {"ready": all(checks.values()), "checks": checks}


def delivery_health(db):
    counts = dict(db.execute(select(SecurityMailOutbox.status, func.count()).group_by(SecurityMailOutbox.status)).all())
    rows = db.scalars(select(SecurityMailOutbox).order_by(SecurityMailOutbox.id.desc()).limit(50))
    return {
        "counts": {s: counts.get(s, 0) for s in ["PENDING", "DELIVERED", "FAILED", "EXPIRED", "CANCELLED"]},
        "recent": [
            {
                "id": r.id,
                "purpose": r.purpose,
                "status": r.status,
                "attempts": r.attempts,
                "created_at": r.created_at,
                "sent_at": r.sent_at,
                "failed_at": r.failed_at,
                "next_attempt_at": r.next_attempt_at if r.status == "PENDING" else None,
            }
            for r in rows
        ],
        "observed_at": datetime.now(UTC),
    }
