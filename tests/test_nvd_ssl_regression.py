"""
Regression test for the NVD SSLContext TypeError.

Original bug (10+ failed fixes before this one):

    [WARNING] app.analysis  NVD CPE query failed — cpe='cpe:2.3:a:...'
      error=TypeError: stat: path should be string, bytes, os.PathLike
                       or integer, not SSLContext

Root cause: ``app/analysis.py`` was injecting an ``ssl.SSLContext`` into
``requests.Session.verify`` (via ``tls_ssl_context()`` helper). ``requests``
then did ``os.stat(verify)`` and raised the TypeError on every CPE — so NVD
enrichment returned 0 findings and N errors.

Fix: the NVD ``requests.Session`` points ``verify`` at a **path string**
produced by ``certifi.where()`` — nothing fancier. A path string cannot
retrigger the SSLContext TypeError by construction, and it makes NVD work
on Windows (venv / corporate network) where the plain ``verify=True``
lookup fails with "unable to get local issuer certificate".

Things that are still FORBIDDEN in the requests path (what the guards
below pin):

    * ``ssl.SSLContext`` — any form, any helper (``tls_ssl_context``,
      ``ssl.create_default_context``, ``truststore``, …).
    * ``verify=...`` passed as a kwarg to ``requests.get/post`` — the
      session already carries verify; per-call overrides are additive
      config and exactly what caused the 10 previous failed fixes.

The standalone script that always worked is the reference shape:

    response = requests.get(NVD_API_URL, params={...})   # no verify=, no ssl_context

These assertions keep the NVD path free of ad-hoc SSL plumbing so the
bug cannot regress.
"""

from __future__ import annotations

import pathlib
import ssl

import pytest
import requests
from requests.adapters import HTTPAdapter

# ---------------------------------------------------------------------------
# Deletion guard: NVD path must contain no SSL wiring at all.
# ---------------------------------------------------------------------------


def _requests_tls_nodes(source):
    """Inspect requests calls/session verification, excluding HTTPX's valid TLS API."""
    import ast

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = ast.unparse(node.func.value)
            if receiver in {"requests", "_nvd_session"}:
                yield node
        elif isinstance(node, ast.Assign) and any(
            ast.unparse(target) == "_nvd_session.verify" for target in node.targets
        ):
            yield node


def test_nvd_analysis_module_has_no_sslcontext_references():
    import ast

    source = (pathlib.Path(__file__).resolve().parents[1] / "app" / "analysis.py").read_text()
    forbidden = ("SSLContext", "create_default_context", "truststore", "tls_ssl_context")
    offenders = [ast.unparse(node) for node in _requests_tls_nodes(source)
                 if any(name in ast.unparse(node) for name in forbidden)]
    assert not offenders, offenders


def test_nvd_analysis_module_has_no_verify_kwargs():
    import ast

    source = (pathlib.Path(__file__).resolve().parents[1] / "app" / "analysis.py").read_text()
    offenders = [ast.unparse(node) for node in _requests_tls_nodes(source)
                 if isinstance(node, ast.Call)
                 and any(keyword.arg in {None, "verify", "ssl_context"} for keyword in node.keywords)]
    assert not offenders, offenders


@pytest.mark.parametrize("source", [
    "requests.get(url, verify=tls_ssl_context())",
    "_nvd_session.get(url, verify=False)",
    "_nvd_session.verify = ssl.create_default_context()",
])
def test_requests_guard_detects_unsafe_tls_changes(source):
    import ast

    nodes = list(_requests_tls_nodes(source))
    assert nodes
    assert any("verify" in ast.unparse(node) for node in nodes)


@pytest.mark.parametrize("operation", ["get", "post"])
def test_httpx_fallback_preserves_verified_tls_context(monkeypatch, operation):
    import asyncio
    from types import SimpleNamespace

    from app import analysis, http_client

    context = http_client.tls_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    captured = []

    def no_lifespan():
        raise RuntimeError("no lifespan")

    class Client:
        def __init__(self, **kwargs):
            captured.append(kwargs)
            assert kwargs["verify"] is context
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def get(self, *args, **kwargs):
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"ok": True})
        post = get

    monkeypatch.setattr(http_client, "get_async_http_client", no_lifespan)
    monkeypatch.setattr(analysis.httpx, "AsyncClient", Client)
    coroutine = analysis._async_get("https://provider.test") if operation == "get" else analysis._async_post("https://provider.test", {})
    assert asyncio.run(coroutine) == {"ok": True}
    assert len(captured) == 1


def test_nvd_session_verify_is_certifi_path_string():
    """
    ``_nvd_session.verify`` must be a filesystem PATH STRING to certifi's
    CA bundle — never ``True``, never ``False``, never an ``ssl.SSLContext``.

    Why a path and not just ``True``:

      * macOS + most dev machines: plain ``verify=True`` happens to find
        certifi via Python's bundle lookup, so NVD worked.
      * Windows in a venv, or any machine behind a corporate TLS proxy:
        that lookup silently falls back to an empty trust store and every
        NVD call fails with ``SSLCertVerificationError: unable to get
        local issuer certificate``. Pointing at ``certifi.where()`` makes
        it deterministic on every OS.
      * A path STRING is the only shape we can safely use here —
        ``ssl.SSLContext`` would retrigger the original TypeError, and
        ``False`` would disable verification entirely.
    """
    import certifi
    from app import analysis

    verify = analysis._nvd_session.verify

    # Must not be the failure modes.
    assert verify is not True, (
        "_nvd_session.verify must be an explicit path — bare True silently breaks on Windows (venv / corporate CA)."
    )
    assert verify is not False, "_nvd_session.verify must not disable verification."
    assert not isinstance(verify, ssl.SSLContext), (
        f"_nvd_session.verify must never be an SSLContext "
        f"(retriggers the original TypeError), got {type(verify).__name__}"
    )

    # Must be a path string pointing at certifi's bundle.
    assert isinstance(verify, str), (
        f"_nvd_session.verify must be a path STRING, got {type(verify).__name__}: {verify!r}"
    )
    assert pathlib.Path(verify).is_file(), f"_nvd_session.verify should point to a readable CA bundle, got {verify!r}"
    assert verify == certifi.where(), (
        f"_nvd_session.verify should be certifi.where() (= {certifi.where()!r}), got {verify!r}"
    )


# ---------------------------------------------------------------------------
# Pin the bug class: requests itself still rejects SSLContext on verify=.
# If this ever stops raising, upstream has added support and we can relax —
# but until then, the deletion guard above must stay.
# ---------------------------------------------------------------------------


def test_requests_still_rejects_sslcontext_on_verify():
    sess = requests.Session()
    sess.verify = ssl.create_default_context()

    adapter = HTTPAdapter()

    class _FakeConn:
        ca_certs = None
        ca_cert_dir = None
        cert_file = None
        key_file = None
        cert_reqs = None

    with pytest.raises(TypeError, match="not SSLContext"):
        adapter.cert_verify(_FakeConn(), "https://nvd.example/", sess.verify, None)
