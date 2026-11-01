"""Opt-in disposable compatibility probes; never called by plan or diagnose."""

from __future__ import annotations

import secrets
import smtplib
import subprocess
from urllib.parse import urlsplit


class LocalServiceError(ValueError):
    pass


def loopback_url(url, schemes):
    try:
        target = urlsplit(url)
        if (target.scheme not in schemes or target.hostname not in {"127.0.0.1", "localhost", "::1"}
                or "?" in url or "#" in url or url != url.strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in url)):
            raise ValueError()
        if target.port is not None and not 1 <= target.port <= 65535:
            raise ValueError()
        return target
    except (ValueError, TypeError):
        raise LocalServiceError("LOCAL_SERVICE_EXPOSURE: select a loopback-only service URL with no query overrides; no probe was sent.") from None


def redis_compatibility(url, *, client_factory=None):
    """Test required protocol features in a random namespace, with short TTLs.

    Never publishes tasks, calls Celery control, uses application session IDs,
    flushes scripts/data or changes server configuration (including Garnet Lua).
    """
    loopback_url(url, {"redis", "rediss"})
    if client_factory is None:
        from redis import Redis
        from redis.backoff import NoBackoff
        from redis.retry import Retry

        def client_factory(value):
            return Redis.from_url(
                value, socket_connect_timeout=2, socket_timeout=2,
                retry=Retry(NoBackoff(), 0), retry_on_timeout=False,
                **({"ssl_cert_reqs": "required", "ssl_check_hostname": True} if value.startswith("rediss:") else {}),
            )
    client = client_factory(url)
    token = secrets.token_hex(16)
    prefix = "sbom:dev:compat:" + token
    keys = [prefix + ":" + name for name in ("lease", "session", "queue", "unacked", "index", "binding")]
    claimed, stage, cleanup_error = False, "connectivity", False
    try:
        if client.ping() is not True:
            raise ValueError()
        stage = "lease SET NX EX"
        if not client.set(keys[0], token, nx=True, ex=60):
            raise ValueError()
        claimed = True
        stage = "Lua EVAL / lease renewal"
        if client.eval("if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('expire',KEYS[1],60) else return 0 end", 1, keys[0], token) != 1:
            raise ValueError()
        stage = "session SETEX / GET / TTL"
        client.setex(keys[1], 60, token)
        if client.get(keys[1]) != token.encode() or not 0 < client.ttl(keys[1]) <= 60:
            raise ValueError()
        stage = "Celery MULTI / EXEC, lists, hashes, sorted sets, bindings"
        # Lua creates each non-string resource together with its expiry, so a
        # disconnected client cannot leave unbounded probe data behind.
        client.eval(
            "redis.call('lpush',KEYS[1],ARGV[1]); redis.call('expire',KEYS[1],60); "
            "redis.call('hset',KEYS[2],ARGV[1],ARGV[1]); redis.call('expire',KEYS[2],60); "
            "redis.call('zadd',KEYS[3],1,ARGV[1]); redis.call('expire',KEYS[3],60); "
            "redis.call('sadd',KEYS[4],ARGV[1]); redis.call('expire',KEYS[4],60); return 1",
            4, *keys[2:], token,
        )
        with client.pipeline(transaction=True) as pipeline:
            pipeline.llen(keys[2])
            pipeline.hget(keys[3], token)
            pipeline.zrange(keys[4], 0, -1)
            pipeline.smembers(keys[5])
            if pipeline.execute() != [1, token.encode(), [token.encode()], {token.encode()}]:
                raise ValueError()
        if client.brpop(keys[2], timeout=1) != (keys[2].encode(), token.encode()):
            raise ValueError()
        stage = "Celery WATCH / transaction and unacked cleanup"
        with client.pipeline() as pipeline:
            pipeline.watch(keys[1])
            if pipeline.get(keys[1]) != token.encode():
                raise ValueError()
            pipeline.multi()
            pipeline.hdel(keys[3], token)
            pipeline.zrem(keys[4], token)
            pipeline.srem(keys[5], token)
            if pipeline.execute() != [1, 1, 1]:
                raise ValueError()
        stage = "Lua compare-and-delete"
        if client.eval("if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end", 1, keys[0], token) != 1:
            raise ValueError()
    except Exception:
        raise LocalServiceError(
            f"REDIS_COMPATIBILITY_FAILED: {stage}. Use a service supporting these operations. "
            "For Garnet, enable its Lua scripting option (commonly --lua) in the service configuration. If Lua reads the wrong logical database, use a separate fresh local setup (database zero with unique resource namespaces) or a compatible Redis service; retain existing configuration. Then rerun setup --check-local-services. "
            "No server configuration was changed."
        ) from None
    finally:
        try:
            if claimed:
                client.delete(*keys)
        except Exception:
            cleanup_error = True
        finally:
            client.close()
        if cleanup_error:
            raise LocalServiceError("REDIS_PROBE_CLEANUP_UNCONFIRMED: only random probe keys were used, with a 60-second expiry; verify service connectivity before retrying.") from None


def mailpit_bindings(ports, *, runner=subprocess.run):
    """Inspect Windows listeners without changing services/firewall settings."""
    result = runner(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise LocalServiceError("MAILPIT_BINDING_UNVERIFIED: run netstat -ano -p tcp and verify both Mailpit ports bind only to loopback.")
    seen = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] != "TCP" or fields[3] != "LISTENING":
            continue
        address, _, raw_port = fields[1].rpartition(":")
        if not raw_port.isdigit() or int(raw_port) not in ports:
            continue
        if address.strip("[]") not in {"127.0.0.1", "::1"}:
            raise LocalServiceError("MAILPIT_EXPOSED: a selected SMTP/UI port listens beyond loopback. Start a separate Mailpit with --smtp 127.0.0.1:<smtp-port> --listen 127.0.0.1:<ui-port>; review existing service bindings explicitly.")
        seen.add(int(raw_port))
    if seen != set(ports):
        raise LocalServiceError("MAILPIT_BINDING_UNVERIFIED: start the selected loopback SMTP/UI listeners and rerun setup.")


def validate_mailpit(env, launcher):
    """Validate loopback Mailpit API and SMTP without sending or deleting mail."""
    host = env.get("SMTP_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise LocalServiceError("MAILPIT_EXPOSED: SMTP_HOST must be loopback for local setup; no connection was made.")
    try:
        port = int(env.get("SMTP_PORT", launcher.MAILPIT_SMTP_PORT))
        if not 1 <= port <= 65535 or env.get("SMTP_USERNAME") or env.get("SMTP_PASSWORD"):
            raise ValueError()
        ui_port = int(env.get("DEV_MAILPIT_UI_PORT", launcher.MAILPIT_UI_PORT))
        if not 1 <= ui_port <= 65535:
            raise ValueError()
        if launcher.sys.platform == "win32":
            mailpit_bindings({port, ui_port})
        if not launcher.mailpit_ready(ui_port):
            raise ValueError()
        with smtplib.SMTP(host, port, timeout=3) as client:
            if client.ehlo()[0] != 250:
                raise ValueError()
    except LocalServiceError:
        raise
    except Exception:
        raise LocalServiceError(
            "MAILPIT_LOCAL_VALIDATION_FAILED: start Mailpit with --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025 "
            "(or the selected saved loopback ports), then rerun setup. No email was sent or removed."
        ) from None


def check_local_services(env, launcher):
    validate_mailpit(env, launcher)
    for url in dict.fromkeys(env.get(name, "") for name in (
        "REDIS_URL", "CELERY_BROKER_URL", "CELERY_RESULT_BACKEND", "AUTH_SESSION_REDIS_URL", "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI",
    )):
        if url:
            redis_compatibility(url)
