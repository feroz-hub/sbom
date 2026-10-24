"""Shared verified egress and bounded retry policy for lifecycle providers.

Redirects are rejected. Private destinations require an operator-owned exact host
allowlist, never an administrator-supplied provider option. TLS/proxy/CA handling
uses httpx platform defaults. Network diagnostics deliberately omit URLs/bodies.
"""

import ipaddress
import socket
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import httpx

from ...settings import get_settings


@dataclass
class RequestPolicy:
    timeout: float = 5
    retries: int = 0
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)


policy_context: ContextVar[RequestPolicy | None] = ContextVar("lifecycle_request_policy", default=None)


class ProviderRequestError(httpx.HTTPError):
    pass


def validate_url(url, *, resolve=False):
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (ValueError, TypeError):
        raise ProviderRequestError("unsafe_endpoint") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ProviderRequestError("unsafe_endpoint")
    host = parsed.hostname.lower()
    allowed = {v.strip().lower() for v in get_settings().lifecycle_egress_allowed_hosts.split(",") if v.strip()}
    builtins = {
        "endoflife.date",
        "edb-prod.xeol.io",
        "api.deps.dev",
        "api.osv.dev",
        "pypi.org",
        "registry.npmjs.org",
        "api.nuget.org",
        "rubygems.org",
        "search.maven.org",
        "api.github.com",
        "gitlab.com",
        "api.bitbucket.org",
    }
    if host not in allowed | builtins:
        raise ProviderRequestError("destination_not_allowlisted")
    if port not in {None, 443} and host not in allowed:
        raise ProviderRequestError("blocked_port")
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            if host not in allowed:
                raise ProviderRequestError("blocked_destination")
        addresses = []
        if resolve:
            addresses = [
                ipaddress.ip_address(row[4][0])
                for row in socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
            ]
    for address in addresses:
        # Metadata/link-local and loopback are never allowlisted.
        if address.is_link_local or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ProviderRequestError("blocked_destination")
        if not address.is_global and host not in allowed:
            raise ProviderRequestError("blocked_destination")


def invalid_response():
    policy = policy_context.get()
    if policy is not None:
        policy.errors.append("invalid_response")
    return None


def _retry_delay(response, attempt):
    value = response.headers.get("Retry-After") if response is not None else None
    if value:
        try:
            seconds = float(value)
        except ValueError:
            try:
                seconds = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
            except (ValueError, TypeError):
                seconds = 0
        # Do not retry earlier than requested when the server asks for a long delay.
        return max(0, seconds)
    return min(0.25 * 2**attempt, 4)


def request_json(method, url, *, timeout=5, headers=None, payload=None):
    policy = policy_context.get() or RequestPolicy(timeout=timeout)
    response = None
    code = "connection_error"
    for attempt in range(policy.retries + 1):
        try:
            validate_url(url, resolve=True)
            with httpx.Client(timeout=policy.timeout, follow_redirects=False) as client:
                policy.attempts += 1
                response = client.request(method, url, headers=headers, json=payload)
            policy.calls.append({"http_status": response.status_code})
            if response.status_code == 404:
                return None
            if response.status_code >= 300:
                code = f"http_{response.status_code}"
                transient = response.status_code in {408, 429, 500, 502, 503, 504}
                if not transient:
                    break
            else:
                try:
                    return response.json()
                except (ValueError, TypeError):
                    code = "invalid_response"
                    break
        except ProviderRequestError as exc:
            code = str(exc)
            break
        except (httpx.TimeoutException, TimeoutError):
            code = "timeout"
        except (httpx.HTTPError, OSError):
            code = "connection_error"
        if attempt < policy.retries:
            delay = _retry_delay(response, attempt)
            if delay > 10:
                break
            time.sleep(delay)
    policy.errors.append(code)
    raise ProviderRequestError(code)
