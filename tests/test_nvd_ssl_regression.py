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

Fix: **delete** the custom SSL plumbing from the NVD path. The default
behaviour of ``requests`` (``verify=True``) and ``httpx`` already uses
certifi's CA bundle and works fine against ``services.nvd.nist.gov``.

The standalone script that always worked is the reference shape:

    response = requests.get(NVD_API_URL, params={...})   # no verify=, no ssl_context

These assertions keep the NVD path free of SSL plumbing so the bug
cannot regress.
"""

from __future__ import annotations

import inspect
import pathlib
import ssl

import pytest
import requests
from requests.adapters import HTTPAdapter


# ---------------------------------------------------------------------------
# Deletion guard: NVD path must contain no SSL wiring at all.
# ---------------------------------------------------------------------------


def test_nvd_analysis_module_has_no_sslcontext_references():
    """SSLContext in the NVD path is what caused the 10+ failed fixes.
    Keep the module free of it so the bug cannot regress."""
    from app import analysis as nvd_mod

    src = inspect.getsource(nvd_mod)
    assert "SSLContext" not in src, "NVD client must not use SSLContext"
    assert "create_default_context" not in src, (
        "NVD client must not build a custom SSL context — default SSL already uses certifi"
    )
    assert "truststore" not in src, "NVD client must not depend on truststore"
    assert "tls_ssl_context" not in src, (
        "tls_ssl_context() returns an SSLContext — it must never reach the NVD code path"
    )


def test_nvd_analysis_module_has_no_verify_kwargs():
    """
    Scan the executable lines (not comments) for any ``verify=``. The whole
    point of this fix is that default requests/httpx SSL is correct — any
    ``verify=`` in analysis.py is additive config and forbidden.
    """
    src = pathlib.Path(__file__).resolve().parents[1] / "app" / "analysis.py"
    text = src.read_text()

    bad_lines = [
        (i + 1, ln)
        for i, ln in enumerate(text.splitlines())
        if "verify=" in ln and not ln.lstrip().startswith("#")
    ]
    assert not bad_lines, (
        "verify= found in executable code in analysis.py — the NVD path must "
        "use default SSL. Offending lines:\n  "
        + "\n  ".join(f"{n}: {ln}" for n, ln in bad_lines)
    )


def test_nvd_session_uses_default_verification():
    """
    ``_nvd_session.verify`` must be the requests default (``True``). Anything
    else — an SSLContext, a path string, False — is additive SSL config and
    either reintroduces the TypeError or disables verification.
    """
    from app import analysis

    assert analysis._nvd_session.verify is True, (
        f"_nvd_session.verify should be the requests default True, "
        f"got {analysis._nvd_session.verify!r}. Remove the .verify assignment."
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
