"""Pure development resource names; identifiers never establish ownership.

Only an approved launcher may bind these names to verified resources. This
helper neither discovers targets nor authorizes resource or privileged actions.
The Runtime's independent SBOM_DEV_INSTANCE launch generation is not consumed.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

_RESOURCE_KEY = "SBOM_DEV_RESOURCE_ID"
_ERRORS = frozenset({"DEV_INSTANCE_RESOURCE_ID_INVALID", "DEV_INSTANCE_ENVIRONMENT_UNVERIFIED"})


class InstanceNamespaceError(ValueError):
    """Fixed categories only; never include environment values in diagnostics."""

    def __init__(self, code: str):
        self.code = code if type(code) is str and code in _ERRORS else "DEV_INSTANCE_RESOURCE_ID_INVALID"
        super().__init__(self.code)


def _invalid():
    raise InstanceNamespaceError("DEV_INSTANCE_RESOURCE_ID_INVALID") from None


@dataclass(frozen=True, slots=True)
class InstanceNamespace:
    """An immutable public name snapshot, with unchanged production defaults."""

    resource_id: str | None = None

    def __post_init__(self):
        if self.resource_id is None:
            return
        if type(self.resource_id) is not str or len(self.resource_id) != 36:
            _invalid()
        try:
            if str(UUID(self.resource_id)) == self.resource_id:
                return
        except ValueError:
            pass
        _invalid()

    @property
    def _token(self) -> str:
        return self.resource_id.replace("-", "") if self.resource_id is not None else ""

    @property
    def queue_default(self) -> str:
        return f"sbom.dev.{self._token}.default" if self.resource_id is not None else "celery"

    @property
    def queue_reports(self) -> str:
        return f"sbom.dev.{self._token}.reports" if self.resource_id is not None else "reports"

    @property
    def beat_namespace(self) -> str:
        return f"sbom:dev:{self._token}:beat" if self.resource_id is not None else "sbom:dev:beat"

    @property
    def session_namespace(self) -> str:
        return f"sbom:bff:{self._token}:" if self.resource_id is not None else "sbom:bff:"

    @property
    def rate_limit_namespace(self) -> str:
        return f"sbom:iam:{self._token}:" if self.resource_id is not None else ""

    @property
    def mail_worker_heartbeat(self) -> str:
        return f"sbom:iam:{self._token}:mail-worker" if self.resource_id is not None else "sbom:iam:mail-worker"

    @property
    def native_rate_limit_bucket(self) -> str:
        return self.rate_limit_namespace + "native"

    @property
    def native_account_rate_limit_bucket(self) -> str:
        return self.rate_limit_namespace + "native-account"


def get_instance_namespace(environment: Mapping[str, str] | None = None) -> InstanceNamespace:
    """Read only the optional explicit resource UUID; never use launch identity.

    Absence preserves the existing application names. An explicitly empty,
    malformed or case-ambiguous selection fails closed instead of falling back.
    Callers must separately verify instance configuration/resource ownership.
    """
    values = os.environ if environment is None else environment
    if not isinstance(values, Mapping):
        raise InstanceNamespaceError("DEV_INSTANCE_ENVIRONMENT_UNVERIFIED") from None
    try:
        for name in values:
            if isinstance(name, str) and name.upper() == _RESOURCE_KEY:
                if type(name) is not str or name != _RESOURCE_KEY:
                    _invalid()
        if _RESOURCE_KEY not in values:
            return InstanceNamespace()
        selected = values[_RESOURCE_KEY]
        if selected is None:
            _invalid()
        return InstanceNamespace(selected)
    except InstanceNamespaceError:
        raise
    except Exception:
        raise InstanceNamespaceError("DEV_INSTANCE_ENVIRONMENT_UNVERIFIED") from None
