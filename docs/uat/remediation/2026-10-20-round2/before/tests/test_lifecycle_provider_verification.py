"""Deterministic provider, transport and policy regression tests; no public I/O."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from app.services.lifecycle import provider_http as http
from app.services.lifecycle.lifecycle_cache_repository import _cache_ttl_for_result, lifecycle_cache_row_from_result
from app.services.lifecycle.provider_base import LifecycleProvider
from app.services.lifecycle.provider_chain import lookup_provider_chain
from app.services.lifecycle.provider_config_service import DEFAULT_PROVIDER_CONFIGS, ProviderConfigSnapshot
from app.services.lifecycle.provider_probe import run_probe
from app.services.lifecycle.provider_registry import LifecycleProviderRegistry
from app.services.lifecycle.provider_status import LifecycleProviderStatusTracker
from app.services.lifecycle.types import UNKNOWN, LifecycleResult, NormalizedComponent, unknown_result


def snapshot(key, **overrides):
    defaults = next(d for d in DEFAULT_PROVIDER_CONFIGS if d["provider_key"] == key)
    values = dict(
        provider_key=key,
        display_name=defaults["display_name"],
        provider_type=defaults["provider_type"],
        enabled=True,
        priority=defaults["priority"],
        base_url=defaults.get("base_url"),
        feed_urls=[],
        config={},
        timeout_seconds=11,
        max_retries=0,
        circuit_breaker_enabled=True,
        cache_ttl_known_days=None,
        cache_ttl_unknown_hours=None,
        cache_ttl_failure_minutes=None,
        cache_ttl_deprecated_days=None,
        last_success_at=None,
        last_failure_at=None,
        last_failure_message=None,
        health_status="unknown",
    )
    return ProviderConfigSnapshot(**(values | overrides))


@pytest.fixture
def transport(monkeypatch):
    state = SimpleNamespace(replies=[], calls=[], delays=[])

    class Client:
        def __init__(self, **kwargs):
            state.options = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def request(self, method, url, **kwargs):
            state.calls.append((method, url, kwargs))
            value = state.replies.pop(0)
            if isinstance(value, Exception):
                raise value
            status, data, headers = value
            return httpx.Response(status, json=data, headers=headers, request=httpx.Request(method, url))

    monkeypatch.setattr(http.httpx, "Client", Client)
    monkeypatch.setattr(http.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))])
    monkeypatch.setattr(http.time, "sleep", state.delays.append)
    return state


@pytest.mark.parametrize(
    "key,payload,matched,evidence,method",
    [
        ("endoflife_date", [{"cycle": "12", "eol": "2099-01-01"}], True, True, "GET"),
        ("deps_dev", {"versionKey": {"version": "2.31.0"}}, True, False, "GET"),
        ("osv", {}, False, False, "POST"),
        ("package_registry", {"info": {"version": "2.31.0"}}, True, False, "GET"),
        ("repository_health", {"full_name": "python/cpython", "archived": False}, True, False, "GET"),
        ("xeol_api", {"match": {"found": True}}, True, False, "POST"),
        ("openeox", [{"name": "sample", "version": "1", "status": "unknown"}], False, False, "GET"),
    ],
)
def test_genuine_probes_use_http_and_separate_coverage(transport, key, payload, matched, evidence, method):
    config = snapshot(key, feed_urls=["https://endoflife.date/feed"] if key == "openeox" else [])
    transport.replies = [(200, payload, {})]
    success, _, details = run_probe(config)
    assert success
    assert details["connection_verified"] and details["response_valid"] and details["real_provider_call"]
    assert details["sample_matched"] is matched
    assert details["lifecycle_evidence_found"] is evidence
    assert transport.calls[0][0] == method
    assert transport.options == {"timeout": 11, "follow_redirects": False}
    if key == "osv":
        assert transport.calls[0][2]["json"]["package"]["ecosystem"] == "PyPI"
    if key == "xeol_api":
        assert transport.calls[0][2]["json"]["component"]["name"] == "debian"


@pytest.mark.parametrize(
    "key", ["endoflife_date", "deps_dev", "osv", "package_registry", "repository_health", "xeol_api", "openeox"]
)
def test_invalid_payload_never_healthy(transport, key):
    transport.replies = [(200, [], {}), (200, [], {})]
    assert not run_probe(snapshot(key, feed_urls=["https://endoflife.date/feed"]))[0]


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_http_errors_are_truthful_and_sanitized(transport, status):
    transport.replies = [(status, {"token": "never-return-sensitive-body"}, {})]
    success, message, details = run_probe(snapshot("osv"))
    assert not success and details["http_status"] == status and details["connection_verified"]
    assert "never-return" not in str(details) + message
    if status in {401, 403}:
        assert details["authentication_verified"] is False


@pytest.mark.parametrize(
    "failure", [httpx.ConnectError("secret endpoint"), httpx.ReadTimeout("secret token"), OSError("dns secret")]
)
def test_connectivity_errors_are_distinct_from_no_match(transport, failure):
    transport.replies = [failure]
    success, message, details = run_probe(snapshot("osv"))
    assert not success and not details["connection_verified"]
    assert details["real_provider_call"]
    assert details["error_code"] in {"timeout", "connection_error"}
    assert "secret" not in str(details) + message


@pytest.mark.parametrize("status,expected", [(401, 1), (403, 1), (404, 1), (429, 3), (500, 3)])
def test_bounded_transient_retries_only(transport, status, expected):
    transport.replies = [(status, {}, {"Retry-After": "1"})] * 3
    run_probe(snapshot("osv", max_retries=2))
    assert len(transport.calls) == expected
    assert transport.delays == [1, 1] if expected == 3 else not transport.delays


def test_long_retry_after_does_not_retry_early(transport):
    transport.replies = [(429, {}, {"Retry-After": "3600"})]
    run_probe(snapshot("osv", max_retries=3))
    assert len(transport.calls) == 1 and not transport.delays


@pytest.mark.parametrize(
    "url",
    [
        "http://endoflife.date/api",
        "https://127.0.0.1",
        "https://169.254.169.254/latest",
        "https://user:pass@endoflife.date",
        "https://endoflife.date?token=secret",
        "https://arbitrary.example/api",
        "https://localhost",
        "https://[::1]",
        "https://endoflife.date:invalid/api",
        "https://[broken-ipv6",
    ],
)
def test_unsafe_endpoints_rejected(url):
    with pytest.raises(http.ProviderRequestError):
        http.validate_url(url)


def test_dns_private_address_rejected(transport, monkeypatch):
    monkeypatch.setattr(http.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.1", 443))])
    assert run_probe(snapshot("osv"))[2]["error_code"] == "blocked_destination"
    assert not transport.calls


def test_redirect_not_followed(transport):
    transport.replies = [(302, {}, {"Location": "https://169.254.169.254"})]
    assert not run_probe(snapshot("osv"))[0]
    assert len(transport.calls) == 1


def test_partial_feeds_are_degraded(transport):
    transport.replies = [(200, [{"name": "x", "status": "eol"}], {}), (500, {}, {})]
    result = run_probe(snapshot("openeox", feed_urls=["https://endoflife.date/a", "https://endoflife.date/b"]))
    assert not result[0] and len(transport.calls) == 2


def test_placeholder_and_static_reference_are_not_live_connections():
    success, _, result = run_probe(snapshot("official_vendor_lifecycle"))
    assert not success and result["probe_type"] == "unsupported"
    success, _, result = run_probe(snapshot("redhat_lifecycle"))
    assert success and result["lifecycle_evidence_found"]
    assert result["probe_type"] == "local_verification" and not result["connection_verified"]


def test_configuration_failure_never_falls_back():
    service = SimpleNamespace(list_snapshots=lambda db: (_ for _ in ()).throw(RuntimeError("database unavailable")))
    with pytest.raises(RuntimeError, match="execution stopped"):
        LifecycleProviderRegistry(config_service=service).build_provider_chain(object())


@pytest.mark.parametrize("breaker", [True, False])
def test_per_provider_circuit_toggle(breaker):
    class Provider(LifecycleProvider):
        name = "test"
        runtime_config = snapshot("osv", circuit_breaker_enabled=breaker)
        calls = 0

        def lookup(self, component):
            self.calls += 1
            return unknown_result(component, self.name)

    provider = Provider()
    tracker = LifecycleProviderStatusTracker()
    for _ in range(50):
        tracker.record_failure(provider.name, "timeout")
    result, errors = lookup_provider_chain(
        [provider],
        NormalizedComponent(component_id=None, name="sample", normalized_name="sample"),
        timeout_seconds=0.01,
        status_tracker=tracker,
    )
    assert provider.calls == (0 if breaker else 1)
    assert bool(errors) is breaker


@pytest.mark.parametrize(
    "status,policy,expected",
    [
        ("EOL", {"known_days": 3}, timedelta(days=3)),
        ("Unknown", {"unknown_hours": 2}, timedelta(hours=2)),
        ("Deprecated", {"deprecated_days": 4}, timedelta(days=4)),
    ],
)
def test_effective_cache_policy(status, policy, expected):
    result = LifecycleResult(
        ecosystem="generic",
        purl=None,
        component_name="x",
        component_version="1",
        lifecycle_status=status,
        evidence={"cache_policy": policy},
    )
    assert _cache_ttl_for_result(result) == expected
    row = lifecycle_cache_row_from_result(
        NormalizedComponent(component_id=None, name="x", normalized_name="x"), result, cache_ttl_days=7
    )
    assert abs((datetime.fromisoformat(row["expires_at"]) - datetime.now(UTC) - expected).total_seconds()) < 2


def test_failure_cache_policy_overrides_known_result():
    result = LifecycleResult(
        ecosystem="generic",
        purl=None,
        component_name="x",
        component_version="1",
        lifecycle_status="EOL",
        evidence={"provider_errors": ["timeout"], "cache_policy": {"failure_minutes": 2}},
    )
    assert _cache_ttl_for_result(result) == timedelta(minutes=2)


def test_runtime_outage_is_not_silent_unknown(transport):
    from app.services.lifecycle.osv_provider import OSVProvider

    transport.replies = [(500, {}, {})]
    provider = OSVProvider()
    provider.runtime_config = snapshot("osv")
    result, errors = lookup_provider_chain(
        [provider],
        NormalizedComponent(
            component_id=None,
            name="requests",
            normalized_name="requests",
            version="2.31.0",
            normalized_version="2.31.0",
            ecosystem="pypi",
        ),
        timeout_seconds=0.01,
    )
    assert result.lifecycle_status == UNKNOWN
    assert errors == ["OSV: http_500"]
    assert result.evidence["provider_errors"] == errors


def test_xeol_match_without_support_evidence_is_unknown():
    from app.services.lifecycle.xeol_db_provider import _result_from_record
    from app.services.lifecycle.xeol_provider import _parse_xeol_result

    assert _parse_xeol_result({"match": {"found": True}})["status"] == UNKNOWN
    assert (
        _result_from_record(
            {"name": "x"},
            NormalizedComponent(component_id=None, name="x", normalized_name="x"),
            today=None,
            source_name="test",
        ).lifecycle_status
        == UNKNOWN
    )


def test_effective_credentials_are_used_without_being_returned(transport, monkeypatch):
    from app.services.lifecycle.secret_service import LifecycleProviderSecretService

    monkeypatch.setattr(LifecycleProviderSecretService, "get_secret", lambda *a, **k: "fixture-sensitive-token")
    for key in ("xeol_api", "repository_health"):
        transport.replies = [
            (
                200,
                {"match": {"found": False}}
                if key == "xeol_api"
                else {"full_name": "python/cpython", "archived": False},
                {},
            )
        ]
        success, message, details = run_probe(snapshot(key), db=object())
        assert success and details["authentication_verified"]
        assert transport.calls[-1][2]["headers"]["Authorization"] == "Bearer fixture-sensitive-token"
        assert "fixture-sensitive-token" not in str(details) + message


def test_unknown_vendor_hint_never_overwrites_known_evidence():
    from app.services.lifecycle.decision_engine import choose_lifecycle_result

    hint = LifecycleResult(
        component_name="x",
        component_version="1",
        ecosystem="generic",
        purl=None,
        lifecycle_status="Unknown",
        confidence="Medium",
        evidence={"authority": "vendor"},
        recommended_version="2",
    )
    known = LifecycleResult(
        component_name="x",
        component_version="1",
        ecosystem="generic",
        purl=None,
        lifecycle_status="EOL",
        eol_date="2000-01-01",
        confidence="High",
    )
    assert choose_lifecycle_result([hint, known]).lifecycle_status == "EOL"


def test_runtime_invalid_response_is_visible(transport):
    from app.services.lifecycle.osv_provider import OSVProvider

    transport.replies = [(200, {"vulns": "invalid"}, {})]
    provider = OSVProvider()
    provider.runtime_config = snapshot("osv")
    result, errors = lookup_provider_chain(
        [provider],
        NormalizedComponent(
            component_id=None,
            name="requests",
            normalized_name="requests",
            normalized_version="2.31.0",
            ecosystem="pypi",
        ),
        timeout_seconds=0.01,
    )
    assert errors == ["OSV: invalid_response"] and result.lifecycle_status == UNKNOWN


def test_openeox_explicit_support_and_dates_are_preserved():
    from app.services.lifecycle.openeox_provider import _result_from_openeox_record

    component = NormalizedComponent(component_id=None, name="sample", normalized_name="sample")
    assert (
        _result_from_openeox_record(
            {"name": "sample", "status": "supported"}, component, today=None, source_name="test"
        ).lifecycle_status
        == "Supported"
    )
    assert (
        _result_from_openeox_record(
            {"name": "sample", "eol_date": "2000-01-01"}, component, today=None, source_name="test"
        ).lifecycle_status
        == "EOL"
    )


def test_platform_circuit_state_resets_on_configuration_change():
    from app.core.context import tenant_scope
    from app.services.lifecycle.provider_status import get_provider_status_tracker

    with tenant_scope(None):
        old = get_provider_status_tracker("platform-before")
        for _ in range(50):
            old.record_failure("OSV", "timeout")
        assert old.is_circuit_open("OSV")
        assert not get_provider_status_tracker("platform-after").is_circuit_open("OSV")


def test_cached_feed_failure_remains_visible_for_subsequent_components(transport):
    from app.services.lifecycle.openeox_provider import OpenEoXProvider

    transport.replies = [(500, {}, {})]
    provider = OpenEoXProvider(feed_urls=["https://endoflife.date/feed"])
    provider.runtime_config = snapshot("openeox", feed_urls=provider.feed_urls)
    for name in ("first", "second"):
        result, errors = lookup_provider_chain(
            [provider], NormalizedComponent(component_id=None, name=name, normalized_name=name), timeout_seconds=5
        )
        assert errors == ["OpenEoX: http_500"]
        assert result.lifecycle_status == UNKNOWN
    assert len(transport.calls) == 1


def test_matching_cycle_without_lifecycle_values_does_not_claim_evidence(transport):
    transport.replies = [(200, [{"cycle": "12", "eol": None}], {})]
    success, _, details = run_probe(snapshot("endoflife_date"))
    assert success and details["sample_matched"] and not details["lifecycle_evidence_found"]
