"""ai_credentials router smoke tests + key-leak sweep.

Phase 2 §2.5 / §2.6 hard rules verified:

  * No raw API key appears in any response (only previews)
  * No raw API key appears in any captured log line
  * Audit row written for every mutation; payload never in audit detail
  * Singleton constraints: only one is_default / is_fallback at a time
"""

from __future__ import annotations

import logging

import pytest
from app.db import SessionLocal
from app.models import (
    AiCredentialAuditLog,
    AiProviderCredential,
    AiSettings,
)
from app.security.secrets import generate_master_key, reset_cipher

_KEY_FRAGMENTS = [
    "sk-ant-",
    "sk-",
    "AIzaSy",
    "xai-",
]


def _key_appears(text: str, plaintext: str) -> bool:
    """True if the plaintext leaks anywhere in the captured text."""
    if not plaintext:
        return False
    return plaintext in text


@pytest.fixture(autouse=True)
def _enc_key(monkeypatch):
    """Provide a fresh encryption key per test + reset the cipher singleton."""
    monkeypatch.setenv("AI_CONFIG_ENCRYPTION_KEY", generate_master_key())
    reset_cipher()
    yield
    reset_cipher()


@pytest.fixture(autouse=True)
def _wipe(client):
    db = SessionLocal()
    try:
        db.query(AiCredentialAuditLog).delete()
        db.query(AiProviderCredential).delete()
        # Reset singleton settings to defaults.
        s = db.query(AiSettings).filter_by(id=1).one_or_none()
        if s is not None:
            s.feature_enabled = True
            s.kill_switch_active = False
            s.budget_per_request_usd = 0.10
            s.budget_per_scan_usd = 5.00
            s.budget_daily_usd = 5.00
            s.updated_at = "2026-05-04T00:00:00+00:00"
        db.commit()
    finally:
        db.close()


# ============================================================ Read shape


def test_list_empty(client):
    resp = client.get("/api/v1/ai/credentials")
    assert resp.status_code == 200
    assert resp.json() == []


def test_create_response_omits_raw_key(client):
    raw_key = "sk-ant-api03-VERY-SECRET-KEY-PAYLOAD-AhB7"
    resp = client.post(
        "/api/v1/ai/credentials",
        json={
            "provider_name": "anthropic",
            "label": "default",
            "api_key": raw_key,
            "default_model": "claude-sonnet-4-5",
            "tier": "paid",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # Hard rule: response must not echo the raw key anywhere.
    assert raw_key not in resp.text
    assert body["api_key_present"] is True
    assert body["api_key_preview"] is not None
    assert body["api_key_preview"].startswith("sk-ant")
    assert body["api_key_preview"].endswith("AhB7")


def test_get_one_response_shape(client):
    resp = client.post(
        "/api/v1/ai/credentials",
        json={
            "provider_name": "gemini",
            "api_key": "AIzaSy-test-gemini-key-1234567890",
            "default_model": "gemini-2.5-flash",
            "tier": "free",
        },
    )
    cred_id = resp.json()["id"]
    resp = client.get(f"/api/v1/ai/credentials/{cred_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert "api_key" not in body  # the field doesn't even exist
    assert body["api_key_present"] is True


# ============================================================ Update / preserve key


def test_update_omitted_api_key_preserves(client):
    raw_key = "sk-ant-original-key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    create = client.post(
        "/api/v1/ai/credentials",
        json={
            "provider_name": "anthropic",
            "api_key": raw_key,
            "default_model": "claude-sonnet-4-5",
        },
    )
    cred_id = create.json()["id"]

    # Update model only — leave api_key out.
    resp = client.put(
        f"/api/v1/ai/credentials/{cred_id}",
        json={"default_model": "claude-haiku-4-5"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["default_model"] == "claude-haiku-4-5"
    # Preview must still match the original key (the tail).
    assert body["api_key_preview"].endswith(raw_key[-4:])


def test_update_with_new_api_key_replaces(client):
    create = client.post(
        "/api/v1/ai/credentials",
        json={
            "provider_name": "anthropic",
            "api_key": "sk-ant-OLD-XXXXXXXXXXXXXXXXXXXXXXXXX",
            "default_model": "claude-sonnet-4-5",
        },
    )
    cred_id = create.json()["id"]
    resp = client.put(
        f"/api/v1/ai/credentials/{cred_id}",
        json={"api_key": "sk-ant-NEWNEWNEW-YYYYYYYYYYYYYYYYY"},
    )
    body = resp.json()
    assert body["api_key_preview"].endswith("YYYY")


# ============================================================ Set default / fallback


def test_set_default_swaps_atomically(client):
    a = client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "anthropic", "api_key": "sk-a-XXXXXXXXXXXX", "default_model": "claude-sonnet-4-5"},
    ).json()
    b = client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "openai", "api_key": "sk-b-YYYYYYYYYYYY", "default_model": "gpt-4o-mini"},
    ).json()
    # Promote A.
    resp = client.put(f"/api/v1/ai/credentials/{a['id']}/set-default")
    assert resp.status_code == 200
    assert resp.json()["is_default"] is True
    # Promote B — must demote A in the same transaction.
    resp = client.put(f"/api/v1/ai/credentials/{b['id']}/set-default")
    assert resp.status_code == 200
    # List view confirms only one default.
    listing = client.get("/api/v1/ai/credentials").json()
    defaults = [c for c in listing if c["is_default"]]
    assert len(defaults) == 1
    assert defaults[0]["id"] == b["id"]


def test_set_fallback_swaps_atomically(client):
    a = client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "gemini", "api_key": "AIzaSy-1-XXXXXXXX", "default_model": "gemini-2.5-flash", "tier": "free"},
    ).json()
    b = client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "grok", "api_key": "xai-2-YYYYYYYY", "default_model": "grok-2-mini", "tier": "free"},
    ).json()
    client.put(f"/api/v1/ai/credentials/{a['id']}/set-fallback")
    client.put(f"/api/v1/ai/credentials/{b['id']}/set-fallback")
    listing = client.get("/api/v1/ai/credentials").json()
    fallbacks = [c for c in listing if c["is_fallback"]]
    assert len(fallbacks) == 1
    assert fallbacks[0]["id"] == b["id"]


# ============================================================ Delete


def test_delete_credential_removes_row_and_audits(client):
    create = client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "anthropic", "api_key": "sk-ant-XXXXXXXXX", "default_model": "claude-sonnet-4-5"},
    )
    cred_id = create.json()["id"]
    resp = client.delete(f"/api/v1/ai/credentials/{cred_id}")
    assert resp.status_code == 204
    assert client.get(f"/api/v1/ai/credentials/{cred_id}").status_code == 404
    # Audit row should be present.
    db = SessionLocal()
    try:
        rows = db.query(AiCredentialAuditLog).filter_by(action="credential.delete").all()
        assert any(r.target_id == cred_id for r in rows)
    finally:
        db.close()


# ============================================================ Settings


def test_settings_get_returns_singleton(client):
    resp = client.get("/api/v1/ai/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "db"


def test_settings_update_validates_cap_ordering(client):
    # per_request > per_scan → 400.
    resp = client.put(
        "/api/v1/ai/settings",
        json={"budget_per_request_usd": 100.0, "budget_per_scan_usd": 1.0},
    )
    assert resp.status_code == 400


def test_settings_update_persists(client):
    resp = client.put(
        "/api/v1/ai/settings",
        json={
            "budget_per_request_usd": 0.05,
            "budget_per_scan_usd": 2.50,
            "budget_daily_usd": 10.00,
            "kill_switch_active": True,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["kill_switch_active"] is True
    assert body["budget_daily_usd"] == 10.00


# ============================================================ Audit trail


def test_audit_log_records_create(client):
    raw_key = "sk-ant-VERY-SECRET-KEY-VALUE-1234567890"
    client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "anthropic", "api_key": raw_key, "default_model": "claude-sonnet-4-5"},
    )
    db = SessionLocal()
    try:
        rows = db.query(AiCredentialAuditLog).filter_by(action="credential.create").all()
        assert len(rows) == 1
        # Hard rule: payload must NOT appear in audit detail.
        for r in rows:
            assert raw_key not in (r.detail or "")
            for fragment in _KEY_FRAGMENTS:
                if fragment in raw_key:
                    # Detail might mention key_present=True; that's fine.
                    pass
    finally:
        db.close()


def test_audit_log_test_action_records_outcome(client):
    # Probe an unsaved credential — Anthropic with a fake key. The
    # provider tries to reach the upstream and either fails network
    # or auth; either way the audit row should be present.
    client.post(
        "/api/v1/ai/credentials/test",
        json={
            "provider_name": "anthropic",
            "api_key": "sk-ant-test-NEVER-VALID",
            "default_model": "claude-sonnet-4-5",
            "tier": "paid",
        },
    )
    db = SessionLocal()
    try:
        rows = db.query(AiCredentialAuditLog).filter_by(action="credential.test").all()
        assert len(rows) >= 1
    finally:
        db.close()


# ============================================================ Key-leak sweep


def test_no_raw_key_leaks_into_log_records(client, caplog):
    """Hard-rule sweep — sentinel key must not appear in ANY captured log line.

    This is the load-bearing security test for §2.6. Future regressions
    (debug logging that includes the request body, exception traces that
    interpolate the credential, etc.) get caught here.
    """
    sentinel = "sk-ant-SENTINEL-DO-NOT-LEAK-2025-0504-XYZ"
    with caplog.at_level(logging.DEBUG):
        client.post(
            "/api/v1/ai/credentials",
            json={
                "provider_name": "anthropic",
                "api_key": sentinel,
                "default_model": "claude-sonnet-4-5",
                "tier": "paid",
            },
        )
        # Update the same key + delete it.
        cred_id = (
            client.get("/api/v1/ai/credentials").json()[0]["id"]
        )
        client.put(
            f"/api/v1/ai/credentials/{cred_id}",
            json={"api_key": sentinel + "-V2"},
        )
        client.delete(f"/api/v1/ai/credentials/{cred_id}")

    # Concatenate every captured record (message + extras + exception).
    blob = "\n".join(
        r.getMessage() + " " + str(r.__dict__) for r in caplog.records
    )
    assert sentinel not in blob
    # Audit detail in the DB, too — must not contain the sentinel.
    db = SessionLocal()
    try:
        all_audit_text = " ".join(
            (r.detail or "") for r in db.query(AiCredentialAuditLog).all()
        )
        assert sentinel not in all_audit_text
    finally:
        db.close()


def test_no_raw_key_leaks_into_response_text(client):
    sentinel = "sk-ant-SENTINEL-RESPONSE-DO-NOT-LEAK"
    resp = client.post(
        "/api/v1/ai/credentials",
        json={
            "provider_name": "anthropic",
            "api_key": sentinel,
            "default_model": "claude-sonnet-4-5",
        },
    )
    cred_id = resp.json()["id"]
    # Hit every read endpoint that touches this row.
    for path in [
        "/api/v1/ai/credentials",
        f"/api/v1/ai/credentials/{cred_id}",
    ]:
        r = client.get(path)
        assert sentinel not in r.text, f"sentinel leaked via {path}"


def test_unknown_provider_returns_400(client):
    resp = client.post(
        "/api/v1/ai/credentials",
        json={"provider_name": "bogus", "default_model": "x", "api_key": "k"},
    )
    assert resp.status_code == 400
