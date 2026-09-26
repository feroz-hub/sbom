"""Opt-in actual API + two production Next BFF HTTP processes + isolated Redis.

SBOM_RUN_HTTP_ACCEPTANCE=1 requires frontend/.next production build. This is
loopback operational evidence, never a claim about external staging ingress.
"""

import base64
import os
import socket
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from app.db import SessionLocal
from app.services import native_password_service as passwords
from app.services.account_state_service import transition_account
from app.settings import get_settings

from tests.test_native_iam_phase2 import PASSWORD, enrolled
from tests.test_native_iam_phase2 import native_config as native_config

pytestmark = pytest.mark.skipif(os.getenv("SBOM_RUN_HTTP_ACCEPTANCE") != "1", reason="opt-in real HTTP acceptance")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait(url):
    for _ in range(200):
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise RuntimeError("Acceptance process did not become ready")


@pytest.fixture
def topology(tmp_path):
    s = get_settings()
    with SessionLocal() as db:
        user = enrolled(db)
        uid = user.id
    api_port, redis_port, a_port, b_port = [port() for _ in range(4)]
    env = dict(
        os.environ,
        NATIVE_AUTH_ENABLED="true",
        HCL_AUTH_ENABLED="false",
        NATIVE_USER_CREATION_ENABLED="true",
        AUTH_ENABLED="true",
        DEV_DEFAULT_TENANT="false",
        NATIVE_JWT_ISSUER=s.native_jwt_issuer,
        NATIVE_JWT_AUDIENCE=s.native_jwt_audience,
        NATIVE_JWT_ACCESS_TOKEN_TTL_SECONDS="60",
        NATIVE_JWT_PRIVATE_KEY=s.native_jwt_private_key,
        NATIVE_JWT_PUBLIC_KEY=s.native_jwt_public_key,
        AUTHORIZATION_CATALOG_MODE="DATABASE",
        AUTHORIZATION_CATALOG_FAIL_CLOSED="true",
        TENANT_ROLE_ASSIGNMENT_MODE="DATABASE",
        TENANT_ROLE_ASSIGNMENT_FAIL_CLOSED="true",
        NATIVE_IAM_PRODUCTION="false",
        NATIVE_SECURITY_OUTBOX_ENABLED="false",
        SBOM_API_URL=f"http://127.0.0.1:{api_port}",
        APP_ORIGIN="https://acceptance.test",
        NEXT_PUBLIC_AUTH_ENABLED="true",
        NEXT_PUBLIC_HCL_AUTH_ENABLED="false",
        NEXT_PUBLIC_HCL_IAM_ISSUER="",
        NEXT_PUBLIC_HCL_IAM_CLIENT_ID="",
        AUTH_SESSION_STORE="redis",
        AUTH_SESSION_REDIS_URL=f"redis://127.0.0.1:{redis_port}/1",
        AUTH_SESSION_ENCRYPTION_KEY=base64.b64encode(os.urandom(32)).decode(),
        NODE_ENV="production",
    )
    procs = []
    logs = []

    def start(command):
        log = (tmp_path / f"process-{len(logs)}.log").open("w")
        logs.append(log)
        p = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        procs.append(p)
        return p

    redis_command = [
        "redis-server",
        "--bind",
        "127.0.0.1",
        "--port",
        str(redis_port),
        "--appendonly",
        "yes",
        "--dir",
        str(tmp_path),
    ]
    start(redis_command)
    start(
        [
            str(Path(".venv/bin/python").absolute()),
            "-m",
            "uvicorn",
            "tests.iam_acceptance_server:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(api_port),
            "--no-access-log",
            "--no-proxy-headers",
        ]
    )
    node = "/opt/homebrew/opt/node@20/bin/node"
    # Real Next production servers, same build and shared encrypted session store.
    for p in [a_port, b_port]:
        env["PORT"] = str(p)
        env["HOSTNAME"] = "127.0.0.1"
        start([node, "frontend/.next/standalone/server.js"])
    a, b = [f"http://127.0.0.1:{p}" for p in [a_port, b_port]]
    try:
        wait(f"http://127.0.0.1:{api_port}/health")
        wait(a + "/api/ready")
        wait(b + "/api/ready")
        yield dict(
            a=a, b=b, uid=uid, procs=procs, start=start, redis_command=redis_command, env=env, logs=logs, root=tmp_path
        )
    finally:
        for p in reversed(procs):
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for log in logs:
            log.close()


def login(top, password=PASSWORD):
    r = httpx.post(
        top["a"] + "/api/auth/native/login",
        headers={"Origin": "https://acceptance.test"},
        json={"email": "john@example.test", "password": password},
        timeout=20,
    )
    assert r.status_code == 200, f"login status {r.status_code}"
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    assert "access_token" not in r.text and "refresh_token" not in r.text
    return cookie.split(";")[0]


def session(base, cookie):
    return httpx.get(base + "/api/auth/session", headers={"Cookie": cookie}, timeout=10)


def test_two_actual_bffs_logout_recovery_and_security_revocation(topology):
    t = topology
    cookie = login(t)
    assert session(t["b"], cookie).json()["authenticated"]
    r = httpx.post(
        t["b"] + "/api/auth/logout", headers={"Cookie": cookie, "Origin": "https://acceptance.test"}, timeout=10
    )
    assert r.status_code == 200 and "Max-Age=0" in r.headers["set-cookie"]
    assert not session(t["a"], cookie).json()["authenticated"]
    cookie = login(t)
    t["procs"][0].terminate()
    t["procs"][0].wait(timeout=10)
    assert httpx.get(t["a"] + "/api/ready", timeout=10).status_code == 503
    assert session(t["b"], cookie).status_code >= 500
    t["start"](t["redis_command"])
    wait(t["a"] + "/api/ready")
    wait(t["b"] + "/api/ready")
    assert session(t["b"], cookie).json()["authenticated"]
    good_key = t["env"]["AUTH_SESSION_ENCRYPTION_KEY"]
    t["procs"][3].terminate()
    t["procs"][3].wait(timeout=10)
    t["env"]["AUTH_SESSION_ENCRYPTION_KEY"] = base64.b64encode(os.urandom(32)).decode()
    wrong = t["start"](["/opt/homebrew/opt/node@20/bin/node", "frontend/.next/standalone/server.js"])
    wait(t["b"] + "/api/ready")
    assert not session(t["b"], cookie).json()["authenticated"]
    wrong.terminate()
    wrong.wait(timeout=10)
    t["env"]["AUTH_SESSION_ENCRYPTION_KEY"] = good_key
    t["start"](["/opt/homebrew/opt/node@20/bin/node", "frontend/.next/standalone/server.js"])
    wait(t["b"] + "/api/ready")
    assert session(t["b"], cookie).json()["authenticated"]
    changed = httpx.post(
        t["a"] + "/api/auth/native/change-password",
        headers={"Cookie": cookie, "Origin": "https://acceptance.test"},
        json={"current_password": PASSWORD, "new_password": "a replacement acceptance password"},
        timeout=20,
    )
    assert changed.status_code == 200
    for base in [t["a"], t["b"]]:
        assert not session(base, cookie).json()["authenticated"]
    cookie = login(t, "a replacement acceptance password")
    with SessionLocal() as db:
        _, token = passwords.request_reset(db, "john@example.test")
        db.commit()
        passwords.reset_password(db, token.raw_token, "another acceptance reset password")
        db.commit()
    for base in [t["a"], t["b"]]:
        assert not session(base, cookie).json()["authenticated"]
    cookie = login(t, "another acceptance reset password")
    response = httpx.post(
        t["b"] + "/api/auth/native/logout-all",
        headers={"Cookie": cookie, "Origin": "https://acceptance.test"},
        json={},
        timeout=20,
    )
    assert response.status_code == 200
    for base in [t["a"], t["b"]]:
        assert not session(base, cookie).json()["authenticated"]
    cookie = login(t, "another acceptance reset password")
    with SessionLocal() as db:
        transition_account(db, t["uid"], "DISABLED", actor_user_id=None, explicitly_authorized=True)
        db.commit()
    for base in [t["a"], t["b"]]:
        assert not session(base, cookie).json()["authenticated"]
    # Password material must never enter process diagnostics.
    for log in t["logs"]:
        log.flush()
    for path in t["root"].glob("process-*.log"):
        contents = path.read_text()
        assert PASSWORD not in contents and token.raw_token not in contents


def test_actual_http_expiry_denies_mutation(topology):
    t = topology
    cookie = login(t)
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline and session(t["a"], cookie).json().get("authenticated"):
        time.sleep(2)
    assert not session(t["b"], cookie).json()["authenticated"]
    response = httpx.post(
        t["a"] + "/api/auth/native/change-password",
        headers={"Cookie": cookie, "Origin": "https://acceptance.test"},
        json={"current_password": PASSWORD, "new_password": "expiry should deny this change"},
        timeout=20,
    )
    assert response.status_code == 401
