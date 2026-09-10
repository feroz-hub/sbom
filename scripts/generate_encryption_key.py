#!/usr/bin/env python3
"""First-time-setup helper — generate the AI config encryption key.

Phase 2 §2.1 deliverable. Prints a 32-byte random key, base64-encoded,
ready to paste into the deployment environment as
``AI_CONFIG_ENCRYPTION_KEY``.

Usage:

    python scripts/generate_encryption_key.py
    # or, write directly to .env:
    python scripts/generate_encryption_key.py --append-to-env
    # or, for setup scripts — fill .env in only when it has no key yet:
    python scripts/generate_encryption_key.py --ensure-env

CRITICAL: store this key the same way you store other production
secrets (env, vault, secrets manager). Losing the key means every
saved provider credential becomes unrecoverable — admins must
re-enter every API key. See docs/runbook-ai-credentials.md §3 for
the rotation procedure.

This script is intentionally NOT part of any migration, and
:func:`ensure_env_key` writes only to a local ``.env``. Key generation
stays an operator action rather than something the API does to itself:
``.env`` is dockerignored, so a container that generated its own key
would lose it on the next deploy and orphan every credential it had
encrypted. Production injects the var from its own secret store — that
separation is also what keeps the KMS hand-off open later.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.security.secrets import generate_master_key  # noqa: E402

KEY_VAR = "AI_CONFIG_ENCRYPTION_KEY"

# A blank assignment counts as missing — that is exactly what copying
# .env.example leaves behind, and the shape setup has to fill in. "Set"
# therefore requires a non-whitespace value: a line of trailing spaces is
# not a key, and treating it as one would leave a .env that only fails
# later, at base64-decode time.
_SET_RE = re.compile(rf"^{KEY_VAR}=[ \t]*\S", re.MULTILINE)
_BLANK_RE = re.compile(rf"^{KEY_VAR}=[ \t]*$", re.MULTILINE)


def ensure_env_key(env_path: Path) -> str:
    """Idempotently give ``env_path`` a key. Returns what it did.

    ``"present"`` — a non-empty key was already there; nothing written.
    ``"filled"``  — the var was present but blank; filled in place.
    ``"created"`` — the var was absent; appended.

    Safe to call on every bootstrap or dev start: it never replaces a key
    that already has a value, so it cannot orphan stored credentials.
    """
    existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    if _SET_RE.search(existing):
        return "present"

    key = generate_master_key()
    if _BLANK_RE.search(existing):
        env_path.write_text(_BLANK_RE.sub(f"{KEY_VAR}={key}", existing, count=1), encoding="utf-8")
        return "filled"

    with env_path.open("a", encoding="utf-8") as f:
        if existing and not existing.endswith("\n"):
            f.write("\n")
        f.write(f"{KEY_VAR}={key}\n")
    return "created"


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the AI config encryption key.")
    ap.add_argument(
        "--append-to-env",
        action="store_true",
        help="Write AI_CONFIG_ENCRYPTION_KEY=<key> to .env (does not overwrite an existing key).",
    )
    ap.add_argument(
        "--ensure-env",
        action="store_true",
        help="Fill AI_CONFIG_ENCRYPTION_KEY into .env only when it has no value yet (idempotent).",
    )
    args = ap.parse_args()

    if args.ensure_env:
        outcome = ensure_env_key(ROOT / ".env")
        if outcome == "present":
            print(f"{KEY_VAR} already set in .env — left untouched.")
        else:
            print(f"{KEY_VAR} {outcome} in .env. Back it up with your other secrets.")
        return 0

    if args.append_to_env:
        env_path = ROOT / ".env"
        outcome = ensure_env_key(env_path)
        if outcome == "present":
            print(
                "AI_CONFIG_ENCRYPTION_KEY already set in .env — not overwriting.\n"
                "If you intend to rotate, follow docs/runbook-ai-credentials.md §3.",
                file=sys.stderr,
            )
            return 2
        print(f"Wrote AI_CONFIG_ENCRYPTION_KEY to {env_path}")
        return 0

    # Default: just print, with a banner so it's hard to miss the
    # operator action required.
    key = generate_master_key()
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
