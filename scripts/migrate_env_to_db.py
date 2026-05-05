#!/usr/bin/env python3
"""One-time migration: existing AI env vars → ``ai_provider_credential`` rows.

Phase 2 §2.7 / §4.1. Idempotent. Reads the current ``Settings`` and
creates one ``ai_provider_credential`` row per provider that has
credentials in env. Skips providers that already have a DB row.

Usage:

    # Pre-flight (no writes; print what would happen):
    python scripts/migrate_env_to_db.py --dry-run

    # Actually migrate:
    python scripts/migrate_env_to_db.py

    # Force re-create (dangerous — removes DB rows that match
    # env-derived rows, then re-adds. Use only when env was the
    # source of truth and DB is corrupt):
    python scripts/migrate_env_to_db.py --force

The script promotes the ``AI_DEFAULT_PROVIDER`` to ``is_default=True``
when no DB row currently carries that flag. Existing default-flag
state is left alone.

Exit codes:
    0  migration completed (or no work to do)
    1  encryption key not configured / unrecoverable error
    2  user-supplied --force on a deployment with existing DB rows
       (must confirm with --i-know-what-i-am-doing)
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Make sure DATABASE_URL points at the deployment DB before importing
# app modules (the engine is built at module-import time).
os.environ.setdefault(
    "DATABASE_URL", f"sqlite:///{ROOT / 'sbom_api.db'}"
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser(description="Migrate AI env config → DB rows.")
    ap.add_argument("--dry-run", action="store_true", help="Don't write; print intended actions.")
    ap.add_argument(
        "--force",
        action="store_true",
        help="Replace any existing rows whose (provider, label) match the env-derived rows.",
    )
    ap.add_argument(
        "--i-know-what-i-am-doing",
        action="store_true",
        help="Required alongside --force; safety belt against accidental destructive runs.",
    )
    args = ap.parse_args()

    try:
        from app.ai.config_loader import get_loader
        from app.ai.registry import build_configs_from_settings
        from app.db import SessionLocal
        from app.models import AiProviderCredential
        from app.security.secrets import get_cipher
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: failed to import app modules: {exc}", file=sys.stderr)
        return 1

    try:
        cipher = get_cipher()
    except Exception as exc:  # noqa: BLE001
        print(
            f"FATAL: AI_CONFIG_ENCRYPTION_KEY is not configured: {exc}\n"
            "Generate one with `python scripts/generate_encryption_key.py`.",
            file=sys.stderr,
        )
        return 1

    env_configs = build_configs_from_settings()
    enabled_env = [c for c in env_configs if c.enabled]
    if not enabled_env:
        print("No AI provider env vars are populated. Nothing to migrate.")
        return 0

    print(f"Found {len(enabled_env)} env-configured provider(s):")
    for c in enabled_env:
        print(
            f"  - {c.name}  model={c.default_model}  "
            f"key_present={'yes' if c.api_key else 'no'}  base_url={c.base_url or '—'}"
        )

    default_name = os.environ.get("AI_DEFAULT_PROVIDER", "anthropic").strip().lower()

    if args.dry_run:
        print("\nDry run — no DB writes performed.")
        return 0

    if args.force and not args.i_know_what_i_am_doing:
        print(
            "--force requires --i-know-what-i-am-doing. Aborting.",
            file=sys.stderr,
        )
        return 2

    created = 0
    updated = 0
    skipped = 0

    with SessionLocal() as db:
        # Existing rows, by (provider, label).
        existing = {
            (r.provider_name, r.label): r
            for r in db.query(AiProviderCredential).all()
        }
        any_default = any(r.is_default for r in existing.values())

        for cfg in enabled_env:
            label = "default"
            key = (cfg.name, label)
            if key in existing:
                if not args.force:
                    print(f"  · {cfg.name}: row already exists — skipping (use --force to replace)")
                    skipped += 1
                    continue
                # Force-replace path.
                existing_row = existing[key]
                existing_row.api_key_encrypted = cipher.encrypt(cfg.api_key) if cfg.api_key else None
                existing_row.base_url = cfg.base_url or None
                existing_row.default_model = cfg.default_model
                existing_row.tier = cfg.tier
                existing_row.cost_per_1k_input_usd = cfg.cost_per_1k_input_usd
                existing_row.cost_per_1k_output_usd = cfg.cost_per_1k_output_usd
                existing_row.is_local = cfg.is_local
                existing_row.max_concurrent = cfg.max_concurrent
                existing_row.rate_per_minute = cfg.rate_per_minute
                existing_row.enabled = True
                existing_row.updated_at = _now_iso()
                updated += 1
                print(f"  ✱ {cfg.name}: updated existing row (id={existing_row.id})")
                continue

            row = AiProviderCredential(
                provider_name=cfg.name,
                label=label,
                api_key_encrypted=cipher.encrypt(cfg.api_key) if cfg.api_key else None,
                base_url=cfg.base_url or None,
                default_model=cfg.default_model,
                tier=cfg.tier,
                is_default=(not any_default and cfg.name == default_name),
                is_fallback=False,
                enabled=True,
                cost_per_1k_input_usd=cfg.cost_per_1k_input_usd,
                cost_per_1k_output_usd=cfg.cost_per_1k_output_usd,
                is_local=cfg.is_local,
                max_concurrent=cfg.max_concurrent,
                rate_per_minute=cfg.rate_per_minute,
                created_at=_now_iso(),
                updated_at=_now_iso(),
            )
            if row.is_default:
                # Only one row can be default; we're guarded by ``any_default``.
                any_default = True
            db.add(row)
            created += 1
            mark = " (also: marked as default)" if row.is_default else ""
            print(f"  ✓ {cfg.name}: row created{mark}")
        db.commit()

    # Bump the cross-process version so any running API processes see
    # the new rows on their next request.
    get_loader().invalidate()

    print(
        f"\nDone. created={created} updated={updated} skipped={skipped} "
        f"of {len(enabled_env)} env-configured providers."
    )
    if created or updated:
        print(
            "\nVerification: open Settings → AI in the UI; the migrated providers "
            "should now appear with their api_key_preview values."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
