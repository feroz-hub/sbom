"""
CPE 2.3 generation helpers.

The vendor/product heuristics here are intentionally per-ecosystem because
NVD's CPE dictionary uses radically different conventions across Maven
(group's last segment), npm (scope), Composer (vendor/package), Go (last
namespace segment), etc. ``cpe23_from_purl`` returns ``None`` if either
side cannot be derived — callers must handle that.
"""

from __future__ import annotations

from .purl import parse_purl


def slug(s: str | None) -> str | None:
    """
    Sanitise a vendor / product token for CPE: lowercase, alphanumerics,
    dot, dash, underscore. Anything else collapses to ``_``. Trailing
    punctuation is stripped. Returns ``None`` for empty input.
    """
    if not s:
        return None
    out = []
    for ch in s.lower():
        if ch.isalnum() or ch in ("_", "-", "."):
            out.append(ch)
        else:
            out.append("_")
    token = "".join(out).strip("._-")
    return token or None


def cpe23_from_purl(purl: str, version_override: str | None = None) -> str | None:
    """
    Best-effort mapping of a PURL to a CPE 2.3 string.

    The vendor/product heuristics are intentionally per-ecosystem because
    NVD's CPE dictionary uses radically different conventions across
    Maven (group's last segment), npm (scope), Composer (vendor/package),
    Go (last namespace segment), etc. Returns ``None`` if either side
    cannot be derived — callers must handle that.
    """
    parsed = parse_purl(purl)
    if not parsed:
        return None

    ptype = parsed.get("type")
    namespace = parsed.get("namespace") or ""
    name = parsed.get("name") or ""
    version = parsed.get("version") or version_override

    vnd: str | None = None
    prd: str | None = None

    # Ecosystem-specific mappings
    if ptype in {"pypi"}:
        # PyPI has no organisation namespace; use name as both vendor and product
        vnd = slug(name)
        prd = slug(name)

    elif ptype in {"npm"}:
        # npm: namespace is '@scope' (already percent-decoded)
        scope = namespace.split("/")[-1] if namespace else None
        if scope and scope.startswith("@"):
            scope = scope[1:]
        vnd = slug(scope or name)
        prd = slug(name)

    elif ptype in {"maven"}:
        # Maven: namespace = groupId, name = artifactId.
        # vendor = last segment of groupId (e.g., org.apache.logging.log4j -> log4j)
        group = namespace or ""
        vnd = slug(group.split(".")[-1] if group else name)
        prd = slug(name)

    elif ptype in {"golang", "go"}:
        # Go: namespace often like 'github.com/user', name='repo'
        if namespace:
            segs = namespace.split("/")
            vnd = slug(segs[-1] if len(segs) >= 2 else segs[0])
        else:
            vnd = slug(name)
        prd = slug(name)

    elif ptype in {"rubygems", "gem"}:
        vnd = slug(name)
        prd = slug(name)

    elif ptype in {"nuget"}:
        vnd = slug(name)
        prd = slug(name)

    elif ptype in {"composer"}:
        # Composer: namespace is vendor; name is package
        vnd = slug(namespace.split("/")[-1] if namespace else name)
        prd = slug(name)

    elif ptype in {"cargo", "crates"}:
        vnd = slug(namespace.split("/")[-1] if namespace else name)
        prd = slug(name)

    else:
        # Generic fallback
        vnd = slug(namespace.split("/")[-1] if namespace else name)
        prd = slug(name)

    if not vnd or not prd:
        return None

    # Sanitise version for CPE: alphanumeric + . - _ ; everything else -> _
    ver = version or "*"
    if ver != "*":
        ver = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in ver).strip("._-") or "*"

    # CPE 2.3 template:
    # cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
    #         :<sw_edition>:<target_sw>:<target_hw>:<other>
    return f"cpe:2.3:a:{vnd}:{prd}:{ver}:*:*:*:*:*:*:*"
