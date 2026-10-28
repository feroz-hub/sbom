"""Stored provider verification classification; never contacts an upstream."""


def verification_status(row) -> str:
    if row.last_test_success:
        return "VERIFIED"
    kind = (row.last_test_error or "").split(" ", 1)[0]
    if kind == "auth":
        return "INVALID_CREDENTIALS"
    if kind in {"network", "rate_limit", "provider_unavailable"}:
        return "TEMPORARILY_UNAVAILABLE"
    return "UNVERIFIED"
