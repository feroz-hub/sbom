"""Subprocess scenario: no pytest seeds, existing identities or HCL provider."""
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from app.auth import validate_auth_setup
from app.db import SessionLocal
from app.main import _ensure_seed_data
from app.models import AuthorizationRole, IAMUser, NativePlatformBootstrap, SecurityMailOutbox, TenantUser, UserIdentity
from app.workers.celery_app import celery_app
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.engine import make_url

from tests.iam_acceptance_server import app

PASSWORD = "greenfield acceptance only passphrase"
validate_auth_setup()
_ensure_seed_data()
with SessionLocal() as db:
    assert db.scalar(select(func.count(IAMUser.id))) == 0
    assert {"PLATFORM_ADMIN", "TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"} <= set(db.scalars(select(AuthorizationRole.code)))
command = [sys.executable, "scripts/bootstrap_native_platform_user.py", "--confirm-database",
           make_url(os.environ["DATABASE_URL"]).database, "create", "--email", "platform@greenfield.test",
           "--first-name", "Platform", "--last-name", "Test", "--phone", "test-phone", "--operator-reference", "greenfield-acceptance"]
with ThreadPoolExecutor(2) as pool:
    results = list(pool.map(lambda _: subprocess.run(command, capture_output=True, text=True, timeout=30), range(2)))
assert sorted(r.returncode for r in results) == [0, 1], "Exactly one operator process must own bootstrap"
for result in results:
    assert "#token=" not in result.stdout + result.stderr
with SessionLocal() as db:
    uid = db.get(NativePlatformBootstrap, 1).user_id
    assert db.scalar(select(func.count(IAMUser.id))) == 1


def received_token(email):
    celery_app.send_task("security_mail.dispatch", args=[], kwargs={})
    deadline = time.monotonic() + 30
    while True:
        with SessionLocal() as db:
            pending = db.scalar(select(func.count(SecurityMailOutbox.id)).where(SecurityMailOutbox.status == "PENDING"))
        if not pending:
            break
        assert time.monotonic() < deadline, "Security mail worker delivery timed out"
        time.sleep(0.2)
    # Read the intended synthetic recipient's captured email, not DB ciphertext.
    listing = httpx.get("http://127.0.0.1:8025/api/v1/search", params={"query": "to:" + email}, timeout=10).json()
    item = listing["messages"][0]
    message = httpx.get("http://127.0.0.1:8025/api/v1/message/" + item["ID"], timeout=10).json()
    body = message["Text"]
    assert "SBOM Analyser" in body and "Support:" in body and "https://" in body
    assert "password_hash" not in body and "JWT" not in body
    return re.search(r"#token=([A-Za-z0-9_-]+)", body)[1]


client = TestClient(app)
old_bootstrap = received_token("platform@greenfield.test")
resend = subprocess.run(command[:4] + ["resend-activation"], capture_output=True, text=True, timeout=30)
assert resend.returncode == 0
assert client.post("/api/auth/native/activate", json={"token": old_bootstrap, "password": PASSWORD}).status_code == 400
raw = received_token("platform@greenfield.test")
r = client.post("/api/auth/native/activate", json={"token": raw, "password": PASSWORD})
assert r.status_code == 200, ("activation", r.status_code)
with SessionLocal() as db:
    assert db.get(NativePlatformBootstrap, 1).state == "COMPLETED"
r = client.post("/api/auth/native/login", json={"email": "platform@greenfield.test", "password": PASSWORD})
assert r.status_code == 200
bearer = {"Authorization": "Bearer " + r.json()["access_token"]}
tenants = []
for name in ("Olympus", "MedTech"):
    r = client.post("/api/tenants", headers=bearer, json={"name": name, "slug": name.lower(), "initial_admin_user_id": uid})
    assert r.status_code == 201, ("tenant creation", r.status_code, r.json())
    tenants.append(r.json()["tenant"]["id"])
for role in ("TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"):
    email = role.lower() + "@greenfield.test"
    r = client.post("/api/platform/native-users", headers=bearer, json={"tenant_id": tenants[0], "email": email,
        "first_name": "Test", "last_name": role, "phone": "test-phone", "role_codes": [role]})
    assert r.status_code == 201, ("native user", r.status_code, r.json())
    invited_uid = r.json()["user_id"]
    token = received_token(email)
    if role == "TENANT_ADMIN":
        time.sleep(31)  # Actual configured minimum resend cooldown, no DB clock edits.
        response = client.post(f"/api/tenants/{tenants[0]}/native-users/{invited_uid}/resend-activation",
                               headers={**bearer, "X-Tenant-ID": str(tenants[0])})
        assert response.status_code == 200
        assert client.post("/api/auth/native/activate", json={"token": token, "password": PASSWORD}).status_code == 400
        token = received_token(email)
    assert client.post("/api/auth/native/activate", json={"token": token, "password": PASSWORD}).status_code == 200
# Native tenant roles exercise real authorization rather than JWT role claims.
for role in ("TENANT_ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"):
    signed = client.post("/api/auth/native/login", json={"email": role.lower() + "@greenfield.test", "password": PASSWORD})
    assert signed.status_code == 200
    role_headers = {"Authorization": "Bearer " + signed.json()["access_token"], "X-Tenant-ID": str(tenants[0])}
    assert client.post("/api/tenants", headers=role_headers, json={"name": "Forbidden", "slug": "forbidden", "initial_admin_user_id": uid}).status_code == 403
    if role == "TENANT_ADMIN":
        assert client.get(f"/api/tenants/{tenants[0]}/users", headers=role_headers).status_code == 200
        assert client.get(f"/api/tenants/{tenants[1]}/users", headers={**role_headers, "X-Tenant-ID": str(tenants[1])}).status_code == 403
        for prohibited in ("TENANT_ADMIN", "PLATFORM_ADMIN"):
            assert client.post(f"/api/tenants/{tenants[0]}/native-users", headers=role_headers,
                json={"tenant_id": tenants[0], "email": "forbidden@greenfield.test", "first_name": "Denied", "last_name": "Test", "phone": "test-phone", "role_codes": [prohibited]}).status_code == 403
# Password reset follows the same provider and token lifecycle.
r = client.post("/api/auth/native/forgot-password", json={"email": "viewer@greenfield.test"})
assert r.status_code == 200
old_reset = received_token("viewer@greenfield.test")
time.sleep(61)  # Existing password-reset cooldown is intentionally 60 seconds.
assert client.post("/api/auth/native/forgot-password", json={"email": "viewer@greenfield.test"}).status_code == 200
reset = received_token("viewer@greenfield.test")
assert reset != old_reset
assert client.post("/api/auth/native/reset-password", json={"token": old_reset, "new_password": "replacement greenfield test passphrase"}).status_code == 400
assert client.post("/api/auth/native/reset-password", json={"token": reset, "new_password": "replacement greenfield test passphrase"}).status_code == 200
with SessionLocal() as db:
    assert set(db.scalars(select(UserIdentity.provider_type))) == {"NATIVE"}
    assert db.scalar(select(func.count(SecurityMailOutbox.id)).where(SecurityMailOutbox.status == "DELIVERED")) >= 6
r = client.post("/api/platform/native-users", headers=bearer, json={"tenant_id": tenants[0], "email": "multi@greenfield.test",
    "first_name": "Multi", "last_name": "Test", "phone": "test-phone", "role_codes": ["SECURITY_ANALYST", "DEVELOPER"]})
assert r.status_code == 201
multi = r.json()["user_id"]
assert client.post(f"/api/tenants/{tenants[1]}/memberships", headers={**bearer, "X-Tenant-ID": str(tenants[1])},
    json={"user_id": multi, "role_codes": ["VIEWER"]}).status_code == 201
assert client.post("/api/auth/native/activate", json={"token": received_token("multi@greenfield.test"), "password": PASSWORD}).status_code == 200

def login_multi():
    result = client.post("/api/auth/native/login", json={"email": "multi@greenfield.test", "password": PASSWORD})
    assert result.status_code == 200
    return {"Authorization": "Bearer " + result.json()["access_token"]}

multi_bearer = login_multi()
# Exercise normal context resolver and database tenant authorization.
for tenant, expected in zip(tenants, ({"SECURITY_ANALYST", "DEVELOPER"}, {"VIEWER"}), strict=True):
    result = client.get("/api/auth/me", headers={**multi_bearer, "X-Tenant-ID": str(tenant)})
    assert result.status_code == 200
    assert set(result.json()["roles"]) == expected
with SessionLocal() as db:
    membership = db.scalar(select(TenantUser.id).where(TenantUser.user_id == multi, TenantUser.tenant_id == tenants[0]))
assert client.post(f"/api/tenants/{tenants[0]}/users/{membership}/deactivate", headers={**bearer, "X-Tenant-ID": str(tenants[0])}).status_code == 200
assert client.get("/api/auth/me", headers={**multi_bearer, "X-Tenant-ID": str(tenants[0])}).status_code == 403
assert client.get("/api/auth/me", headers={**multi_bearer, "X-Tenant-ID": str(tenants[1])}).status_code == 200
assert client.patch(f"/api/platform/users/{multi}/status", headers=bearer, json={"status": "DISABLED"}).status_code == 200
for tenant in tenants:
    assert client.get("/api/auth/me", headers={**multi_bearer, "X-Tenant-ID": str(tenant)}).status_code in (401, 403)
assert client.patch(f"/api/platform/users/{multi}/status", headers=bearer, json={"status": "ACTIVE"}).status_code == 200
multi_bearer = login_multi()
assert client.get("/api/auth/me", headers={**multi_bearer, "X-Tenant-ID": str(tenants[0])}).status_code == 403
assert client.get("/api/auth/me", headers={**multi_bearer, "X-Tenant-ID": str(tenants[1])}).status_code == 200
print("Fresh Native schema, catalogue, bootstrap, Mailpit activation/reset, tenant creation, roles, isolation and lifecycle PASS")
