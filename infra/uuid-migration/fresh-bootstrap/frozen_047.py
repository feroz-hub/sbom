"""Exact-source, directive-only proposal for frozen047; never executes SQL."""

import difflib
import hashlib
from collections import Counter

from pg_lex import Refused, statements

SOURCE_SHA256 = "e310421b5fea4ef93056be590756125726280671589b50d93aa85926b9833c09"
BASELINE = "047_email_verification_tokens"

# Exact token matching, not substring replacement. All proposed SETs are local
# to one future owned transaction. Original schema/object text is immutable.
DIRECTIVES = {
    "SET statement_timeout = 0;": "SET LOCAL statement_timeout = '30s';",
    "SET lock_timeout = 0;": "SET LOCAL lock_timeout = '1s';",
    "SET idle_in_transaction_session_timeout = 0;": "SET LOCAL idle_in_transaction_session_timeout = '30s';",
    "SET client_encoding = 'UTF8';": "SET LOCAL client_encoding = 'UTF8';",
    "SET standard_conforming_strings = on;": "SET LOCAL standard_conforming_strings = on;",
    "SELECT pg_catalog.set_config('search_path', '', false);": "SET LOCAL search_path = pg_catalog, public;",
    "SET check_function_bodies = false;": "SET LOCAL check_function_bodies = on;",
    "SET xmloption = content;": "SET LOCAL xmloption = content;",
    "SET client_min_messages = warning;": "SET LOCAL client_min_messages = warning;",
    "SET row_security = off;": "SET LOCAL row_security = on;",
    "SET default_tablespace = '';": "SET LOCAL default_tablespace = '';",
    "SET default_table_access_method = heap;": "SET LOCAL default_table_access_method = heap;",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def kind(tokens):
    """Recognize only the statement families actually in this pinned file."""
    for prefix, name in (
        (("CREATE", "TABLE", "public", "."), "table"),
        (("CREATE", "SEQUENCE", "public", "."), "sequence"),
        (("ALTER", "SEQUENCE", "public", "."), "sequence_ownership"),
        (("ALTER", "TABLE", "ONLY", "public", "."), "table_alter"),
        (("CREATE", "UNIQUE", "INDEX"), "unique_index"),
        (("CREATE", "INDEX"), "index"),
    ):
        if tokens[: len(prefix)] == prefix:
            return name
    raise Refused("Unreviewed statement family")


def representation(original: bytes):
    if not isinstance(original, bytes) or sha(original) != SOURCE_SHA256:
        raise Refused("Frozen047 original byte hash mismatch")
    text = original.decode("utf-8", errors="strict")
    framed = statements(text)
    mapping = {statements(old)[0].tokens: new for old, new in DIRECTIVES.items()}
    used, chunks, objects, directives, inventory = set(), [], [], [], []
    for number, entry in enumerate(framed, 1):
        replacement = mapping.get(entry.tokens)
        if replacement is not None:
            if entry.tokens in used:
                raise Refused("Repeated directive")
            used.add(entry.tokens)
            # Preserve all comments/whitespace before the exact directive.
            chunks.append(text[entry.start : entry.code_start] + replacement)
            directives.append(
                {"statement": number, "original": text[entry.code_start : entry.end], "proposed": replacement}
            )
            continue
        family = kind(entry.tokens)
        chunks.append(entry.sql)
        objects.append(entry.sql)
        inventory.append(
            {"statement": number, "family": family, "sha256": sha(entry.sql.encode()), "tokens": list(entry.tokens)}
        )
    if used != set(mapping) or len(framed) != 558:
        raise Refused("Frozen statement/directive inventory changed")
    proposed = "".join(chunks) + text[framed[-1].end :]
    proposed_objects = [entry.sql for entry in statements(proposed) if entry.tokens[:2] != ("SET", "LOCAL")]
    if objects != proposed_objects:
        raise Refused("Object definition or order changed")
    diff = "".join(
        difflib.unified_diff(
            text.splitlines(True), proposed.splitlines(True), fromfile="original047.sql", tofile="proposed047.sql"
        )
    )
    return {
        "source_sha256": SOURCE_SHA256,
        "execution_sql": proposed,
        "execution_sha256": sha(proposed.encode()),
        "diff": diff,
        "diff_sha256": sha(diff.encode()),
        "statements": len(framed),
        "object_statements": len(objects),
        "families": dict(Counter(row["family"] for row in inventory)),
        "directives": directives,
        "inventory": inventory,
        "runtime_equivalence": "NOT VERIFIED; framing/pinned object-byte preservation only",
    }
