"""
Regression tests for BE-002: 500 information disclosure.

Three independent cases:

  1. SQLAlchemy IntegrityError raised inside a route → 500 must NOT leak
     the SQLAlchemy class name, statement, or "synthetic" text.
  2. Generic RuntimeError raised inside a route → 500 must NOT leak the
     exception message ("LEAKABLE_TOKEN_xyz123") or the class name.
  3. Pydantic validation 422 must remain UNCHANGED — the global handler
     must intercept Exception only, not HTTPException / RequestValidationError.

The "leakable token" assertions are the smallest possible leak detector:
if the response body contains the literal "LEAKABLE_TOKEN_xyz123", the
handler is broken.
"""

from __future__ import annotations

import json
import logging

import pytest
import sqlalchemy.exc as sa_exc


_LEAKABLE_TOKEN = "LEAKABLE_TOKEN_xyz123"


@pytest.fixture()
def override_db_with_failing_commit(app):
    """Yield-style dependency override — `get_db` returns a session whose
    .commit() raises whatever the test injects via the closure variable."""
    from app.db import SessionLocal, get_db

    state = {"raise": None}

    def _override():
        db = SessionLocal()
        original_commit = db.commit

        def boom():
            if state["raise"] is not None:
                raise state["raise"]
            return original_commit()

        db.commit = boom  # type: ignore[method-assign]
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    yield state
    app.dependency_overrides.pop(get_db, None)


def test_500_from_db_error_returns_generic_envelope(
    client, seeded_sbom, override_db_with_failing_commit, caplog
):
    sbom_id = seeded_sbom["id"]
    override_db_with_failing_commit["raise"] = sa_exc.IntegrityError(
        "synthetic-stmt UNIQUE constraint violated", "synthetic_params", Exception("synthetic_orig")
    )

    with caplog.at_level(logging.ERROR):
        resp = client.patch(
            f"/api/sboms/{sbom_id}?user_id=snapshot-test",
            json={"sbom_version": "1.2.3", "modified_by": "snapshot-test"},
        )

    assert resp.status_code == 500, f"got {resp.status_code}: {resp.text[:200]!r}"

    body_text = resp.text
    for forbidden in ("IntegrityError", "synthetic-stmt", "synthetic_orig", "synthetic_params", "UNIQUE"):
        assert forbidden not in body_text, (
            f"500 response leaked SQLAlchemy text {forbidden!r}: {body_text[:300]!r}"
        )

    payload = resp.json()
    detail = payload.get("detail")
    assert isinstance(detail, dict), f"expected structured detail; got {detail!r}"
    assert detail.get("code") == "internal_error", f"500 envelope drifted: {detail!r}"
    assert detail.get("correlation_id"), f"missing correlation_id in 500 envelope: {detail!r}"

    server_log = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "synthetic" in server_log or "IntegrityError" in server_log or "update" in server_log.lower(), (
        f"server-side log did not capture the failure; records: {[r.getMessage() for r in caplog.records]!r}"
    )


def test_500_from_generic_exception_returns_generic_envelope(
    client, seeded_sbom, override_db_with_failing_commit
):
    sbom_id = seeded_sbom["id"]
    override_db_with_failing_commit["raise"] = RuntimeError(_LEAKABLE_TOKEN)

    resp = client.patch(
        f"/api/sboms/{sbom_id}?user_id=snapshot-test",
        json={"sbom_version": "9.9.9", "modified_by": "snapshot-test"},
    )

    assert resp.status_code == 500, f"got {resp.status_code}: {resp.text[:200]!r}"
    assert _LEAKABLE_TOKEN not in resp.text, (
        f"500 response leaked exception message: {resp.text[:300]!r}"
    )
    assert "RuntimeError" not in resp.text, (
        f"500 response leaked exception class name: {resp.text[:300]!r}"
    )

    payload = resp.json()
    detail = payload.get("detail")
    assert isinstance(detail, dict), f"expected structured detail; got {detail!r}"
    assert detail.get("code") == "internal_error", f"500 envelope drifted: {detail!r}"
    assert detail.get("correlation_id"), f"missing correlation_id in 500 envelope: {detail!r}"


def test_4xx_validation_errors_unchanged(client):
    """Pydantic 422 responses must still surface the validation `detail`
    list — the global Exception handler must not intercept HTTPException
    or RequestValidationError."""
    # Missing required `sbom_name` — FastAPI / Pydantic will emit 422.
    resp = client.post(
        "/api/sboms",
        content=json.dumps({"sbom_data": "{}"}),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422, f"expected 422, got {resp.status_code}: {resp.text[:200]!r}"
    payload = resp.json()
    detail = payload.get("detail")
    assert isinstance(detail, list), (
        f"FastAPI 422 detail shape changed; got {type(detail).__name__}: {detail!r}"
    )
    # The validation list should reference the missing field — proves the
    # handler hasn't redacted legitimate client-facing detail.
    flat = json.dumps(detail)
    assert "sbom_name" in flat, f"422 detail did not mention the missing field: {flat[:300]!r}"
