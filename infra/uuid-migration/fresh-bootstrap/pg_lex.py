"""Conservative PostgreSQL statement framing, not a SQL grammar/semantic parser.

No imports perform I/O. Only the exact separately pinned snapshot is eligible
for transformation. Quoted bodies and comments are never rewritten or split.
"""

import re
from dataclasses import dataclass


class Refused(ValueError):
    """Input outside the independently reviewed contract."""


@dataclass(frozen=True)
class Statement:
    start: int
    code_start: int
    end: int
    sql: str
    tokens: tuple[str, ...]


def statements(source: str) -> tuple[Statement, ...]:
    """Frame terminated statements, rejecting ambiguous/unsupported lexemes.

    Supports standard strings, E strings, doubled identifier quotes, nested
    block comments, line comments and tagged/untagged dollar quotes. Ordinary
    backslash strings and Unicode escape prefixes are deliberately refused.
    Token strings retain literal contents; consumers must not regex-edit them.
    """
    if not isinstance(source, str) or "\x00" in source:
        raise Refused("SQL text required; NUL forbidden")
    i, start, code_start = 0, 0, 0
    tokens, result = [], []
    while i < len(source):
        char = source[i]
        if char.isspace():
            i += 1
            continue
        if source.startswith("--", i):
            stop = source.find("\n", i + 2)
            i = len(source) if stop < 0 else stop + 1
            continue
        if source.startswith("/*", i):
            level = 1
            i += 2
            while i < len(source) and level:
                if source.startswith("/*", i):
                    level += 1
                    i += 2
                elif source.startswith("*/", i):
                    level -= 1
                    i += 2
                else:
                    i += 1
            if level:
                raise Refused("Unterminated block comment")
            continue
        if not tokens:
            code_start = i
        escaped = char in "eE" and source[i + 1 : i + 2] == "'"
        if escaped or char in "'\"":
            first = i
            if escaped:
                i += 1
            quote = source[i]
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    if not escaped:
                        raise Refused("Ambiguous backslash quoted text")
                    i += 2
                elif source[i] == quote:
                    if source[i + 1 : i + 2] == quote:
                        i += 2
                    else:
                        i += 1
                        break
                else:
                    i += 1
            else:
                raise Refused("Unterminated quoted text")
            if i > len(source):
                raise Refused("Unterminated escape")
            tokens.append(source[first:i])
            continue
        if char == "$":
            tag = re.match(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$", source[i:])
            if tag is None:
                raise Refused("Unreviewed dollar token")
            delimiter = tag.group()
            stop = source.find(delimiter, i + len(delimiter))
            if stop < 0:
                raise Refused("Unterminated dollar body")
            stop += len(delimiter)
            tokens.append(source[i:stop])
            i = stop
            continue
        if char == ";":
            if not tokens:
                raise Refused("Empty statement")
            result.append(Statement(start, code_start, i + 1, source[start : i + 1], tuple(tokens)))
            tokens = []
            i += 1
            start = i
            continue
        if char == "\\":
            raise Refused("psql commands are forbidden")
        word = re.match(r"[A-Za-z_][A-Za-z_0-9$]*|[0-9]+", source[i:])
        if word:
            token = word.group()
            if token.upper() in {"U", "B", "X", "N"} and source[i + len(token) : i + len(token) + 1] in {"'", "&"}:
                raise Refused("Unreviewed quoted-text prefix")
            tokens.append(token)
            i += len(token)
        else:
            tokens.append(char)
            i += 1
    if tokens:
        raise Refused("Unterminated SQL statement")
    return tuple(result)
