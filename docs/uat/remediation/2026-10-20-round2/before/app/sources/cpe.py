"""
CPE 2.3 generation helpers.

The vendor/product heuristics here are intentionally per-ecosystem because
NVD's CPE dictionary uses radically different conventions across Maven
(group's last segment), npm (scope), Composer (vendor/package), Go (last
namespace segment), etc. ``cpe23_from_purl`` returns ``None`` if either
side cannot be derived — callers must handle that.

Roadmap #5 PR-B note
--------------------
When ``distro_cpe_enabled`` is True, deb/rpm/apk/conan PURLs route
through ``app.sources.distro_cpe.resolve`` BEFORE the existing
per-ecosystem branches — the curated table there produces upstream
CPEs that match NVD (e.g. ``openssl:openssl:3.0.2`` for
``pkg:deb/debian/openssl@2:3.0.2-1``). Flag off → existing
generic-slugify path, byte-identical.

The flag is read either from an explicit ``settings`` kwarg (preferred
for tests) or, when that's ``None``, from the Pydantic singleton via
``get_settings()``. Production callers don't need to thread settings
through the four call sites of ``cpe23_from_purl`` — flipping the env
var ``DISTRO_CPE_ENABLED`` reaches the singleton automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .purl import parse_purl


@dataclass(frozen=True, slots=True)
class CpeMapping:
    cpe: str
    confidence: str
    vendor: str
    product: str


# Explicit, reviewed package-to-CPE identities. This table is intentionally
# small: it prevents broad PyPI/npm/etc. name aliases from turning unrelated
# packages into confirmed NVD matches.
TRUSTED_PURL_CPE_MAPPINGS: dict[tuple[str, str], tuple[str, str]] = {
    ("pypi", "pillow"): ("python", "pillow"),
}


def _distro_cpe_enabled(settings: Any | None) -> bool:
    """Check the distro-CPE flag from an explicit settings object,
    falling back to the Pydantic singleton.

    Tests pass an explicit ``settings`` for deterministic control;
    production callers leave it ``None`` and the env-mapped singleton
    decides. ``getattr`` with a default keeps the helper safe against
    settings objects that don't carry the field (e.g. test stubs).
    """
    if settings is not None:
        return bool(getattr(settings, "distro_cpe_enabled", False))
    try:
        from app.settings import get_settings

        return bool(getattr(get_settings(), "distro_cpe_enabled", False))
    except Exception:
        return False


_DISTRO_PTYPES = frozenset({"deb", "rpm", "apk", "conan", "alpine", "debian", "redhat"})


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


def ecosystem_from_component(comp: dict) -> str | None:
    """Return the canonical lowercase PURL ecosystem for a component dict.

    Checks ``comp["ecosystem"]`` first (set in OSV / heuristic-infer
    branches), then falls back to parsing ``comp["purl"]``. Returns
    ``None`` when neither is present or usable.

    Used by the NVD version-range filter (roadmap #1) to dispatch a
    per-ecosystem comparator. Roadmap #5's distro work also reads
    this — keep the threading clean so the same call site serves
    both.
    """
    eco = comp.get("ecosystem")
    if isinstance(eco, str):
        eco = eco.strip().lower()
        if eco:
            return eco
    purl = comp.get("purl")
    if isinstance(purl, str):
        parsed = parse_purl(purl)
        ptype = parsed.get("type") if parsed else None
        if isinstance(ptype, str) and ptype:
            return ptype.lower()
    return None


def cpe23_from_purl(
    purl: str,
    version_override: str | None = None,
    *,
    settings: Any | None = None,
) -> str | None:
    """
    Best-effort mapping of a PURL to a CPE 2.3 string.

    The vendor/product heuristics are intentionally per-ecosystem because
    NVD's CPE dictionary uses radically different conventions across
    Maven (group's last segment), npm (scope), Composer (vendor/package),
    Go (last namespace segment), etc. Returns ``None`` if either side
    cannot be derived — callers must handle that.

    Roadmap #5 PR-B: when ``distro_cpe_enabled`` is True, deb/rpm/apk/
    conan PURLs route through ``distro_cpe.resolve`` for an upstream
    CPE (e.g. ``openssl:openssl:3.0.2``). Flag off → existing
    generic-slugify path, byte-identical. ``settings`` is an explicit
    override for tests; production reads the Pydantic singleton.
    """
    parsed = parse_purl(purl)
    if not parsed:
        return None

    ptype = parsed.get("type")

    # Roadmap #5 PR-B — distro/conan routing. Skipped entirely when
    # the flag is off (byte-identical legacy path). When on, an
    # in-set ptype hits ``distro_cpe.resolve``; a non-None result is
    # returned directly. A None result (defensive — ``resolve``
    # returns None only for non-distro ptypes, which the set check
    # already excludes) falls through to the existing branches.
    if ptype in _DISTRO_PTYPES and _distro_cpe_enabled(settings):
        from .distro_cpe import resolve as _distro_resolve

        resolution = _distro_resolve(purl)
        if resolution is not None:
            return resolution.cpe

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
        # NVD typically uses vendor "apache" for org.apache.* and product "log4j"
        # for log4j-core / log4j-api (not artifactId verbatim).
        group = (namespace or "").strip()
        artifact = name or ""
        if group.startswith("org.apache.") or group == "org.apache":
            vnd = slug("apache")
        else:
            vnd = slug(group.split(".")[-1] if group else name)
        if artifact.startswith("log4j-"):
            prd = slug("log4j")
        else:
            prd = slug(artifact)

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


def trusted_cpe23_from_purl(purl: str, version_override: str | None = None) -> CpeMapping | None:
    parsed = parse_purl(purl)
    if not parsed:
        return None
    ptype = str(parsed.get("type") or "").strip().lower()
    name = str(parsed.get("name") or "").strip().lower()
    mapped = TRUSTED_PURL_CPE_MAPPINGS.get((ptype, name))
    if mapped is None:
        return None
    vendor, product = mapped
    version = parsed.get("version") or version_override or "*"
    ver = version if version == "*" else "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in version)
    cpe = f"cpe:2.3:a:{vendor}:{product}:{ver or '*'}:*:*:*:*:*:*:*"
    return CpeMapping(cpe=cpe, confidence="mapped", vendor=vendor, product=product)
