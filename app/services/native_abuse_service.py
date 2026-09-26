"""Endpoint/IP/account buckets using the existing limits dependency.

Use Redis storage in multi-worker deployments. Never trust forwarded headers:
BFF source address supplies an aggregate boundary; hashed accounts add a layer.
Storage failure fails closed before Argon2. No email/token appears in keys.
"""

import hashlib
import os
from functools import lru_cache

from fastapi import HTTPException
from limits import RateLimitItemPerMinute
from limits.storage import storage_from_string
from limits.strategies import FixedWindowRateLimiter

from ..settings import get_settings


@lru_cache(maxsize=4)
def limiter(uri):
    return FixedWindowRateLimiter(storage_from_string(uri))


def check(request, endpoint, account=""):
    s = get_settings()
    if not s.native_auth_rate_limit_enabled or os.getenv("API_RATE_LIMIT_ENABLED", "true").lower() in {
        "false",
        "0",
        "no",
    }:
        return
    source = request.client.host if request.client else "unknown"
    key = hashlib.sha256(account.strip().lower().encode()).hexdigest()
    try:
        limits = limiter(s.native_auth_rate_limit_storage_uri)
        allowed = limits.hit(RateLimitItemPerMinute(s.native_auth_ip_limit_per_minute), "native", endpoint, source)
        if account:
            allowed = (
                limits.hit(
                    RateLimitItemPerMinute(s.native_auth_account_limit_per_minute), "native-account", endpoint, key
                )
                and allowed
            )
    except Exception:
        raise HTTPException(503, "Authentication service unavailable") from None
    if not allowed:
        raise HTTPException(429, "Too many requests", headers={"Retry-After": "60"})
