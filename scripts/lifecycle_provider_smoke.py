"""Opt-in live provider checks. Never reads or writes database configuration.

PYTHONPATH=. .venv/bin/python scripts/lifecycle_provider_smoke.py --live
"""

import argparse
import json
import time
from datetime import UTC, datetime

from app.services.lifecycle.provider_config_service import DEFAULT_PROVIDER_CONFIGS, ProviderConfigSnapshot
from app.services.lifecycle.provider_probe import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Explicitly allow public provider network requests")
    parser.add_argument(
        "--provider",
        action="append",
        choices=["endoflife_date", "deps_dev", "osv", "package_registry", "repository_health"],
    )
    args = parser.parse_args()
    if not args.live:
        parser.error("--live is required; normal CI must use deterministic fixture tests")
    failed = False
    for key in args.provider or ["endoflife_date", "deps_dev", "osv", "package_registry"]:
        defaults = next(row for row in DEFAULT_PROVIDER_CONFIGS if row["provider_key"] == key)
        config = ProviderConfigSnapshot(
            provider_key=key,
            display_name=defaults["display_name"],
            provider_type=defaults["provider_type"],
            enabled=True,
            priority=defaults["priority"],
            base_url=defaults.get("base_url"),
            feed_urls=[],
            config={},
            timeout_seconds=5,
            max_retries=0,
            circuit_breaker_enabled=False,
            cache_ttl_known_days=None,
            cache_ttl_unknown_hours=None,
            cache_ttl_failure_minutes=None,
            cache_ttl_deprecated_days=None,
            last_success_at=None,
            last_failure_at=None,
            last_failure_message=None,
            health_status="unknown",
        )
        started = time.perf_counter()
        success, message, details = run_probe(config)
        print(
            json.dumps(
                {
                    "provider_key": key,
                    "success": success,
                    "message": message,
                    **details,
                    "latency_ms": int((time.perf_counter() - started) * 1000),
                    "checked_at": datetime.now(UTC).isoformat(),
                }
            )
        )
        failed |= not success
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
