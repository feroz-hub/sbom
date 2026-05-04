#!/usr/bin/env python3
"""First-time-setup helper — generate the AI config encryption key.

Phase 2 §2.1 deliverable. Prints a 32-byte random key, base64-encoded,
ready to paste into the deployment environment as
``AI_CONFIG_ENCRYPTION_KEY``.

Usage:

    python scripts/generate_encryption_key.py
    # or, write directly to .env:
    python scripts/generate_encryption_key.py --append-to-env

CRITICAL: store this key the same way you store other production
secrets (env, vault, secrets manager). Losing the key means every
saved provider credential becomes unrecoverable — admins must
re-enter every API key. See docs/runbook-ai-credentials.md §3 for
the rotation procedure.

This script is intentionally NOT part of any migration. Generating
keys is a one-time operator action, not an automated pipeline step —
that distinction matters for KMS hand-offs later.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.security.secrets import generate_master_key  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the AI config encryption key.")
    ap.add_argument(
        "--append-to-env",
        action="store_true",
        help="Append AI_CONFIG_ENCRYPTION_KEY=<key> to .env (does not overwrite an existing line).",
    )
    args = ap.parse_args()

    key = generate_master_key()

    if args.append_to_env:
        env_path = ROOT / ".env"
        existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
        if "AI_CONFIG_ENCRYPTION_KEY=" in existing:
            print(
                "AI_CONFIG_ENCRYPTION_KEY already exists in .env — not overwriting.\n"
                "If you intend to rotate, follow docs/runbook-ai-credentials.md §3.",
                file=sys.stderr,
            )
            return 2
        with env_path.open("a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(f"AI_CONFIG_ENCRYPTION_KEY={key}\n")
        print(f"Appended AI_CONFIG_ENCRYPTION_KEY to {env_path}")
        return 0

    # Default: just print, with a banner so it's hard to miss the
    # operator action required.
    print("=" * 60)
    print("AI config encryption key (paste into your env):")
    print("=" * 60)
    print(f"AI_CONFIG_ENCRYPTION_KEY={key}")
    print("=" * 60)
    print(
        "\nStore this with the rest of your production secrets. Losing it\n"
        "means every saved AI provider credential must be re-entered.\n"
        "Rotation procedure: docs/runbook-ai-credentials.md §3.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
