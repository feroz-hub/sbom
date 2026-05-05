"""Prompt loader.

Prompts are checked-in text files versioned by name (``v1.*``). The
:data:`PROMPT_VERSION` constant participates in the cache key so a prompt
edit forces a regeneration on next read — without this we'd serve stale
outputs after every prompt iteration.

The system / user templates are deliberately small and deterministic.
``user_prompt`` does explicit substitution rather than calling
``str.format`` on the file contents directly so a literal ``{`` inside a
JSON sample (rare but possible) doesn't crash the loader.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

# Bumping this is a hard cache invalidation. Keep stable; bump only when a
# prompt change would alter the output meaningfully.
PROMPT_VERSION: str = "v1"

_PROMPTS_DIR = Path(__file__).parent

ALLOWED_SOURCES_LITERAL = "[osv, ghsa, nvd, epss, kev, fix_version_data]"


@lru_cache(maxsize=4)
def _read(name: str) -> str:
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


def system_prompt() -> str:
    """Return the system prompt for the current :data:`PROMPT_VERSION`."""
    return _read(f"{PROMPT_VERSION}.system.txt").rstrip() + "\n"


def user_prompt(*, grounding_json: str, schema: dict[str, Any]) -> str:
    """Render the user prompt with the grounding context + schema injected.

    Substitutes the three placeholders (``{grounding_json}``,
    ``{schema_json}``, ``{allowed_sources}``) without calling
    ``str.format`` on the whole template — that way unrelated braces in
    the JSON payload survive intact.
    """
    template = _read(f"{PROMPT_VERSION}.user.txt")
    schema_str = json.dumps(schema, separators=(",", ":"), sort_keys=True)
    return (
        template.replace("{grounding_json}", grounding_json)
        .replace("{schema_json}", schema_str)
        .replace("{allowed_sources}", ALLOWED_SOURCES_LITERAL)
    )


def reload_prompts() -> None:
    """Test / dev helper — bypass the LRU cache and re-read from disk."""
    _read.cache_clear()


__all__ = [
    "ALLOWED_SOURCES_LITERAL",
    "PROMPT_VERSION",
    "reload_prompts",
    "system_prompt",
    "user_prompt",
]
