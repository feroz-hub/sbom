"""Phase 5 facade: ``NvdLookupService``.

Decides whether a single-CPE NVD lookup is served from the local mirror
or by delegating to the live ``app.analysis.nvd_query_by_cpe`` function.

Output shape parity (cowork prompt §5.4): ``query_legacy`` returns
``list[dict]`` in raw NVD CVE JSON shape — exactly what the existing
``_finding_from_raw`` ([app/analysis.py:609](../../analysis.py#L609))
consumes today. Mirror-served records round-trip through ``CveRecord.raw``
which is the verbatim NVD payload kept on every row.

Five decision branches (cowork prompt §5.5):

  1. Mirror disabled                 → live
  2. Mirror enabled, stale data      → live + WARNING log
  3. Mirror enabled, fresh, hit      → mirror
  4. Mirror enabled, fresh, no hit   → live (double-check)
  5. Mirror enabled, mirror raises   → live + ERROR log

Two layers in this module:

  * ``NvdLookupService`` — port-based, fully testable with fakes.
    Used by the unit tests for the 5 decision paths.
  * ``SessionScopedNvdLookupService`` — wraps the port-based facade
    with session lifecycle management. One short SQLAlchemy session is
    opened and closed *per query* so the facade is safe to call from
    threads (multi-source's ``loop.run_in_executor`` fan-out).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Protocol

from ..adapters.cve_repository import SqlAlchemyCveRepository
from ..adapters.settings_repository import SqlAlchemySettingsRepository
from ..domain.models import NvdSettingsSnapshot
from ..observability import increment as _metric
from ..ports import (
    ClockPort,
    CveRepositoryPort,
    SecretsPort,
    SettingsRepositoryPort,
)
from ..settings import NvdMirrorSettings
from .freshness import compute_freshness

log = logging.getLogger(__name__)

# A live-query callable matches ``app.analysis.nvd_query_by_cpe``'s shape:
#   (cpe23, api_key, settings) -> list[dict]
LiveQuery = Callable[[str, "str | None", Any], list[dict[str, Any]]]


class _SessionFactory(Protocol):
    """Anything callable like ``SessionLocal`` — returns a fresh Session."""

    def __call__(self): ...


# ---------------------------------------------------------------------------
# Port-based facade (testable with fakes)
# ---------------------------------------------------------------------------


class NvdLookupService:
    """Port-based facade.

    No session management here — that lives one layer up (see
    ``SessionScopedNvdLookupService``). This class is pure orchestration
    so the 5-branch decision logic is unit-testable with in-memory fakes.
    """

    def __init__(
        self,
        *,
        settings_repo: SettingsRepositoryPort,
        cve_repo: CveRepositoryPort,
        clock: ClockPort,
        live_query: LiveQuery,
    ) -> None:
        self._settings_repo = settings_repo
        self._cve_repo = cve_repo
        self._clock = clock
        self._live_query = live_query

    def query_legacy(
        self,
        cpe23: str,
        *,
        api_key: str | None,
        settings: Any,
    ) -> list[dict[str, Any]]:
        """Return raw-NVD-shape dicts for ``cpe23``. Identical contract to
        ``app.analysis.nvd_query_by_cpe``."""
        snapshot = self._settings_repo.load()

        # 1. Mirror disabled → live, no warnings, no counter (this is the
        # default state; counting it as a "fallback" would be misleading).
        if not snapshot.enabled:
            return self._live_query(cpe23, api_key, settings)

        # 2. Mirror enabled but stale → live + warning.
        verdict = compute_freshness(snapshot, self._clock.now())
        if not verdict.is_fresh:
            log.warning(
                "nvd_mirror_stale_falling_back",
                extra={
                    "cpe": cpe23,
                    "age_hours": verdict.age_hours,
                    "last_success": (
                        verdict.last_successful_sync_at.isoformat()
                        if verdict.last_successful_sync_at
                        else None
                    ),
                },
            )
            _metric("nvd.live_fallbacks")
            return self._live_query(cpe23, api_key, settings)

        # 3 / 5. Mirror enabled and fresh — try mirror.
        try:
            records = list(self._cve_repo.find_by_cpe(cpe23))
        except Exception as exc:
            # 5. Mirror raises → live + error log + circuit hint.
            log.error(
                "nvd_mirror_query_failed_falling_back",
                extra={
                    "cpe": cpe23,
                    "exc_type": type(exc).__name__,
                    "error": str(exc),
                    "hint": "consider disabling mirror via /admin/nvd-mirror/settings",
                },
            )
            _metric("nvd.live_fallbacks")
            return self._live_query(cpe23, api_key, settings)

        # 4. Mirror returned empty → double-check live.
        if not records:
            log.info(
                "nvd_mirror_empty_double_checking_live",
                extra={"cpe": cpe23},
            )
            _metric("nvd.live_fallbacks")
            return self._live_query(cpe23, api_key, settings)

        # 3. Mirror hit — return raw NVD-shape dicts.
        return [dict(r.raw) for r in records]


# ---------------------------------------------------------------------------
# Session-scoped facade (production wrapper)
# ---------------------------------------------------------------------------


class SessionScopedNvdLookupService:
    """Production facade — opens / closes a SQLAlchemy session per query.

    Why per-query: the multi-source orchestrator runs ``_fetch_cpe`` in a
    thread pool (``loop.run_in_executor``). SQLAlchemy ``Session`` is not
    thread-safe, so a single shared session would corrupt under fan-out.
    A short read-only session per query is cheap on PostgreSQL with a
    small connection pool.

    For the disabled-mirror case (the default), the cost is one session
    open/close per CPE plus one ``settings_repo.load()`` read. The first
    call seeds the singleton ``nvd_settings`` row; subsequent calls just
    read it.
    """

    def __init__(
        self,
        *,
        session_factory: _SessionFactory,
        secrets: SecretsPort,
        clock: ClockPort,
        live_query: LiveQuery,
        env_defaults: NvdMirrorSettings | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._secrets = secrets
        self._clock = clock
        self._live_query = live_query
        self._env_defaults = env_defaults or NvdMirrorSettings()

    def query_legacy(
        self,
        cpe23: str,
        *,
        api_key: str | None,
        settings: Any,
    ) -> list[dict[str, Any]]:
        session = self._session_factory()
        try:
            inner = NvdLookupService(
                settings_repo=SqlAlchemySettingsRepository(
                    session, self._secrets, env_defaults=self._env_defaults
                ),
                cve_repo=SqlAlchemyCveRepository(session),
                clock=self._clock,
                live_query=self._live_query,
            )
            result = inner.query_legacy(
                cpe23, api_key=api_key, settings=settings
            )
            # The seed-on-load path inside SettingsRepository writes a row
            # the first time; commit so subsequent calls see it.
            session.commit()
            return result
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Production builder
# ---------------------------------------------------------------------------


def build_nvd_lookup_for_pipeline() -> SessionScopedNvdLookupService:
    """Build the facade with real adapters for the multi-source pipeline.

    The live callable is the late-bound ``app.analysis.nvd_query_by_cpe``
    so test monkeypatching via ``conftest.py`` continues to work — the
    function is re-resolved per call.
    """
    from app.db import SessionLocal

    from ..adapters.clock import SystemClockAdapter
    from ..adapters.secrets import (
        FernetSecretsAdapter,
        MissingFernetKeyError,
    )
    from ..settings import load_mirror_settings_from_env
    from ..tasks import _StubSecrets

    env_defaults = load_mirror_settings_from_env()
    try:
        secrets: SecretsPort = FernetSecretsAdapter.from_env(
            env_var=env_defaults.fernet_key_env_var
        )
    except MissingFernetKeyError:
        secrets = _StubSecrets(env_defaults.fernet_key_env_var)

    def _late_bound_live(cpe: str, api_key: str | None, settings: Any) -> list[dict]:
        # Re-import on each call so monkeypatching ``app.analysis.nvd_query_by_cpe``
        # at test time is honoured.
        from app.analysis import nvd_query_by_cpe

        return nvd_query_by_cpe(cpe, api_key, settings=settings)

    return SessionScopedNvdLookupService(
        session_factory=SessionLocal,
        secrets=secrets,
        clock=SystemClockAdapter(),
        live_query=_late_bound_live,
        env_defaults=env_defaults,
    )


__all__ = [
    "NvdLookupService",
    "SessionScopedNvdLookupService",
    "build_nvd_lookup_for_pipeline",
]
