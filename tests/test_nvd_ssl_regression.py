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

Things that are still FORBIDDEN in the NVD path (what the deletion guards
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
    """
    SSLContext in the NVD path is what caused the 10+ failed fixes. Keep the
    module's EXECUTABLE code free of it so the bug cannot regress.

    We scan non-comment lines only — the module is allowed (and encouraged)
    to mention SSLContext in comments that document why we avoid it.
    """
    src_path = pathlib.Path(__file__).resolve().parents[1] / "app" / "analysis.py"
    text = src_path.read_text()

    forbidden = (
        ("SSLContext", "NVD client must not use SSLContext"),
        (
            "create_default_context",
            "NVD client must not build a custom SSL context — "
            "certifi.where() is all we need",
        ),
        ("truststore", "NVD client must not depend on truststore"),
        (
            "tls_ssl_context",
            "tls_ssl_context() returns an SSLContext — "
            "it must never reach the NVD code path",
        ),
    )

    def _is_executable(line: str) -> bool:
        stripped = line.lstrip()
        return bool(stripped) and not stripped.startswith("#")

    for needle, message in forbidden:
        offenders = [
            (i + 1, ln)
            for i, ln in enumerate(text.splitlines())
            if needle in ln and _is_executable(ln)
        ]
        assert not offenders, (
            f"{message}. Offending executable line(s):\n  "
            + "\n  ".join(f"{n}: {ln}" for n, ln in offenders)
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
        "_nvd_session.verify must be an explicit path — bare True silently "
        "breaks on Windows (venv / corporate CA)."
    )
    assert verify is not False, (
        "_nvd_session.verify must not disable verification."
    )
    assert not isinstance(verify, ssl.SSLContext), (
        f"_nvd_session.verify must never be an SSLContext "
        f"(retriggers the original TypeError), got {type(verify).__name__}"
    )

    # Must be a path string pointing at certifi's bundle.
    assert isinstance(verify, str), (
        f"_nvd_session.verify must be a path STRING, "
        f"got {type(verify).__name__}: {verify!r}"
    )
    assert pathlib.Path(verify).is_file(), (
        f"_nvd_session.verify should point to a readable CA bundle, got {verify!r}"
    )
    assert verify == certifi.where(), (
        f"_nvd_session.verify should be certifi.where() "
        f"(= {certifi.where()!r}), got {verify!r}"
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
