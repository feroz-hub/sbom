"""In-memory lifecycle provider health, circuit breaker, and status tracking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any

from ...settings import get_settings


@dataclass(slots=True)
class ProviderHealthRecord:
    name: str
    priority: int
    enabled: bool = True
    last_success: str | None = None
    last_failure: str | None = None
    consecutive_failures: int = 0
    circuit_open_until: datetime | None = None
    degraded: bool = False
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "priority": self.priority,
            "enabled": self.enabled,
            "status": "degraded" if self.degraded or self.is_circuit_open() else "healthy",
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "consecutive_failures": self.consecutive_failures,
            "circuit_open": self.is_circuit_open(),
            "last_error": self.last_error,
        }

    def is_circuit_open(self) -> bool:
        if self.circuit_open_until is None:
            return False
        return datetime.now(UTC) < self.circuit_open_until


class LifecycleProviderStatusTracker:
    """Thread-safe provider health tracker with circuit breaker."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._providers: dict[str, ProviderHealthRecord] = {}

    def register(self, name: str, *, priority: int, enabled: bool = True) -> None:
        with self._lock:
            existing = self._providers.get(name)
            if existing is None:
                self._providers[name] = ProviderHealthRecord(name=name, priority=priority, enabled=enabled)
            else:
                existing.priority = priority
                existing.enabled = enabled

    def is_circuit_open(self, name: str) -> bool:
        with self._lock:
            record = self._providers.get(name)
            return bool(record and record.is_circuit_open())

    def record_success(self, name: str) -> None:
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        with self._lock:
            record = self._providers.setdefault(name, ProviderHealthRecord(name=name, priority=100))
            record.last_success = now
            record.consecutive_failures = 0
            record.circuit_open_until = None
            record.degraded = False
            record.last_error = None

    def record_failure(self, name: str, error: str | None = None) -> None:
        settings = get_settings()
        threshold = int(getattr(settings, "lifecycle_provider_failure_threshold", 3))
        cooldown_minutes = int(getattr(settings, "lifecycle_provider_circuit_cooldown_minutes", 15))
        now_dt = datetime.now(UTC)
        now = now_dt.replace(microsecond=0).isoformat()
        with self._lock:
            record = self._providers.setdefault(name, ProviderHealthRecord(name=name, priority=100))
            record.last_failure = now
            record.consecutive_failures += 1
            record.last_error = error
            record.degraded = record.consecutive_failures >= threshold
            if record.consecutive_failures >= threshold:
                record.circuit_open_until = now_dt + timedelta(minutes=cooldown_minutes)

    def list_sources(self) -> list[dict[str, Any]]:
        with self._lock:
            return sorted(
                [record.to_dict() for record in self._providers.values()],
                key=lambda row: (row["priority"], row["name"]),
            )

    def provider_status_summary(self) -> dict[str, Any]:
        sources = self.list_sources()
        degraded = [row for row in sources if row["status"] == "degraded"]
        return {
            "overall_status": "degraded" if degraded else "healthy",
            "degraded_count": len(degraded),
            "providers": sources,
        }

    def reset(self) -> None:
        with self._lock:
            self._providers.clear()


_provider_status_tracker = LifecycleProviderStatusTracker()


def get_provider_status_tracker() -> LifecycleProviderStatusTracker:
    return _provider_status_tracker


__all__ = ["LifecycleProviderStatusTracker", "ProviderHealthRecord", "get_provider_status_tracker"]
