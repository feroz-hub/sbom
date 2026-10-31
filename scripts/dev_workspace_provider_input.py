"""Strict, pure decoding of a proposed provider policy, never policy authority.

The JSON contains image references and private file *paths*, never file contents.
No default image, UID, engine, platform or company approval is invented here.
Trusted engine authorization is a separate mutation-boundary dependency.
"""

from __future__ import annotations

import json

if __package__:
    from . import dev_workspace_compose as compose
    from . import dev_workspace_provider as provider
else:
    import dev_workspace_compose as compose
    import dev_workspace_provider as provider


class ProviderInputError(ValueError):
    def __init__(self, code="PROVIDER_POLICY_INPUT_INVALID"):
        self.code = code
        super().__init__(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProviderInputError()
        result[key] = value
    return result


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ProviderInputError()
    return value


def parse_policy(raw, descriptor):
    """Return immutable proposal DTOs; read no files and grant no approvals."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 65536:
        raise ProviderInputError()
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        _fields(data, ("version", "container", "compose"))
        if type(data["version"]) is not int or data["version"] != 1:
            raise ProviderInputError()
        container = _fields(data["container"], ("engine", "policy_id", "engine_identity", "images", "users"))
        settings = _fields(
            data["compose"],
            (
                "reference",
                "bundle_generation",
                "host_platform",
                "platforms",
                "profiles",
                "limits",
                "data_ownership",
                "volume_population",
                "health",
                "secret_files",
            ),
        )
        limits = _fields(settings["limits"], ("postgres", "redis", "mailpit"))
        ownership = _fields(settings["data_ownership"], ("postgres", "redis"))
        health = _fields(
            settings["health"],
            ("interval_seconds", "timeout_seconds", "retries", "start_period_seconds", "stop_grace_seconds"),
        )
        secrets = settings["secret_files"]
        if type(secrets) is not list or not 1 <= len(secrets) <= 24:
            raise ProviderInputError()
        plan = provider.plan_provider(descriptor, provider.ContainerPolicy(**container))
        configuration = compose.ComposePolicy(
            **{
                key: value
                for key, value in settings.items()
                if key not in {"limits", "data_ownership", "health", "secret_files"}
            },
            limits={
                name: compose.ResourceLimits(
                    **_fields(value, ("cpus", "memory_bytes", "pids", "tmpfs_bytes", "shm_bytes"))
                )
                for name, value in limits.items()
            },
            data_ownership={
                name: compose.DataOwnership(**_fields(value, ("uid", "gid", "mode")))
                for name, value in ownership.items()
            },
            health=compose.HealthPolicy(**health),
            secret_files=tuple(
                compose.SecretFile(**_fields(value, ("reference", "source", "host_platform"))) for value in secrets
            ),
        )
        return plan, compose.plan_compose(plan, configuration)
    except Exception:
        # Values, private paths and parser/type exceptions never enter output.
        raise ProviderInputError() from None
