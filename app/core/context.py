from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CurrentContext:
    user_id: int
    external_user_id: str
    email: str | None
    display_name: str | None
    tenant_id: int
    external_tenant_id: str
    roles: frozenset[str]
    permissions: frozenset[str]
    is_platform_admin: bool = False

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions


_current_context: ContextVar[CurrentContext | None] = ContextVar(
    "sbom_current_context", default=None
)


def get_bound_context() -> CurrentContext | None:
    return _current_context.get()


def bind_context(context: CurrentContext) -> Token:
    return _current_context.set(context)


def reset_context(token: Token) -> None:
    _current_context.reset(token)


@contextmanager
def tenant_scope(context: CurrentContext) -> Iterator[None]:
    token = bind_context(context)
    try:
        yield
    finally:
        reset_context(token)
