"""
Distro and Conan PURL → upstream CPE resolution (roadmap #5, PR-A).

Pure module — no I/O, no DB, no network, deterministic. Mirrors the
posture of ``app/sources/cpe.py`` and ``app/sources/version_range.py``:
inputs in, frozen result out, no global state.

Why this exists
---------------
SBOMs from container scanners commonly carry distro-package PURLs:

    pkg:deb/debian/openssl@2:3.0.2-1
    pkg:rpm/redhat/openssl@1:3.0.2-1.el8
    pkg:apk/alpine/openssl@3.0.2-r0
    pkg:conan/openssl@3.0.2

The generic fallback in ``cpe.py`` slugs these as
``cpe:2.3:a:debian:openssl:2_3.0.2-1:*:...`` — vendor token wrong,
version token unreadable to NVD. The NVD CVE for the actual upstream
OpenSSL is filed under ``cpe:2.3:a:openssl:openssl:3.0.2:*:...``, so
no match fires.

This resolver bridges the gap: it maps the distro/Conan package
name to its UPSTREAM (vendor, product) via a curated table (with a
documented heuristic fallback), and the distro version to its
UPSTREAM version (strip ``epoch:`` prefix + ``-revision`` /
``-release`` / ``-rN`` suffix). The result feeds the existing NVD
match path.

Scope, and the load-bearing limitation: BACKPORT UNAWARENESS
-----------------------------------------------------------
**v1 is upstream-version-only**. The distro revision tail
(``-1+deb11u5`` / ``-1.el8`` / ``-r0``) and epoch (``2:``) are
stripped so the resulting CPE matches NVD's upstream entry. This
means the resolver is NOT backport-aware: when Debian (or Red Hat,
or Ubuntu) ships a binary at upstream version ``3.0.2`` that has
been patched to fix CVE-X — without bumping the upstream version
in the version string — the resulting finding will OVER-REPORT
(the CPE matches the CVE, but the distro-built binary doesn't
actually contain the vulnerability anymore).

Closing this gap requires per-distro security feeds (DSA, RHSA,
USN, ASA) that map CVE-id → patched-distro-revision. That is a
separate feature: see the follow-up note. For now, downstream
callers should mark distro-sourced findings as "may be backported —
verify against the distro advisory."

What's covered
--------------
- PURL types: ``deb`` / ``rpm`` / ``apk`` / ``conan`` (plus
  non-spec aliases ``debian`` / ``redhat`` / ``alpine`` that some
  SBOM generators emit).
- Distro-revision stripping: deb/rpm/apk all strip the suffix after
  the LAST ``-`` plus the optional ``epoch:`` prefix.
- Conan: plain version, no stripping (Conan versions are upstream-shaped).
- Curated table for the high-frequency set (openssl, glibc, zlib,
  curl, openssh, python, bash, systemd, nginx, apache, libxml2,
  sqlite, gnupg, ...).
- Heuristic fallback: ``vendor == product == slug(name)``. The C/C++
  ecosystem convention is that vendor matches product for canonical
  libraries — true often enough that a best-effort CPE beats the
  generic fallback's ``debian:openssl``.

Non-distro PURL types (npm/pypi/maven/...) return ``None`` so the
caller in PR-B can route only the right types here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

from .purl import parse_purl


# ---------------------------------------------------------------------------
# Curated table
# ---------------------------------------------------------------------------
#
# Calibration-worthy and intentionally NOT exhaustive. Seeded against the
# high-frequency set seen on container-scanner SBOMs (Trivy / Grype /
# Syft) — extend as dogfooding surfaces misses. The bar for adding an
# entry: the (vendor, product) pair must match the upstream's
# canonical NVD CPE record. Spot-checking against
# https://nvd.nist.gov/products/cpe/search is the right calibration
# move.
#
# Distro packages often ship under names like ``libssl1.1`` /
# ``libsystemd0`` / ``libcurl4`` (the soname-versioned binary
# package) — each of these maps to the same upstream record.
# Including the soname-versioned aliases is the difference between
# a 60% and a 95% hit rate on real Debian/Ubuntu SBOMs.

_CURATED_DISTRO_CPE: Final[dict[str, tuple[str, str]]] = {
    # OpenSSL — common across debian/ubuntu/alpine/rhel/conan
    "openssl": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "libssl1.1": ("openssl", "openssl"),
    "libssl3": ("openssl", "openssl"),
    "libssl-dev": ("openssl", "openssl"),
    "openssl-libs": ("openssl", "openssl"),
    "libcrypto1.1": ("openssl", "openssl"),
    "libcrypto3": ("openssl", "openssl"),
    # GNU C Library + Alpine's musl
    "glibc": ("gnu", "glibc"),
    "glibc-common": ("gnu", "glibc"),
    "libc6": ("gnu", "glibc"),
    "libc-bin": ("gnu", "glibc"),
    "libc-dev": ("gnu", "glibc"),
    "musl": ("musl-libc", "musl"),
    # zlib
    "zlib": ("zlib", "zlib"),
    "zlib1g": ("zlib", "zlib"),
    "zlib-dev": ("zlib", "zlib"),
    "zlib1g-dev": ("zlib", "zlib"),
    "libz1": ("zlib", "zlib"),
    # Compression tools
    "gzip": ("gnu", "gzip"),
    "xz": ("tukaani", "xz"),
    "xz-utils": ("tukaani", "xz"),
    "liblzma5": ("tukaani", "xz"),
    "bzip2": ("bzip", "bzip2"),
    "libbz2-1.0": ("bzip", "bzip2"),
    # cURL family
    "curl": ("haxx", "curl"),
    "libcurl4": ("haxx", "curl"),
    "libcurl3": ("haxx", "curl"),
    "libcurl4-openssl-dev": ("haxx", "curl"),
    "libcurl-devel": ("haxx", "curl"),
    # wget
    "wget": ("gnu", "wget"),
    # OpenSSH
    "openssh": ("openbsd", "openssh"),
    "openssh-server": ("openbsd", "openssh"),
    "openssh-client": ("openbsd", "openssh"),
    "openssh-clients": ("openbsd", "openssh"),
    # CPython
    "python": ("python", "python"),
    "python3": ("python", "python"),
    "python3-minimal": ("python", "python"),
    "python3.10": ("python", "python"),
    "python3.11": ("python", "python"),
    "python3.12": ("python", "python"),
    # Shells / GNU coreutils
    "bash": ("gnu", "bash"),
    "coreutils": ("gnu", "coreutils"),
    "findutils": ("gnu", "findutils"),
    "tar": ("gnu", "tar"),
    "sed": ("gnu", "sed"),
    "grep": ("gnu", "grep"),
    # System
    "systemd": ("systemd_project", "systemd"),
    "libsystemd0": ("systemd_project", "systemd"),
    "udev": ("systemd_project", "systemd"),
    "libudev1": ("systemd_project", "systemd"),
    # Web servers
    "apache2": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "nginx-core": ("nginx", "nginx"),
    # XML / parsers
    "libxml2": ("xmlsoft", "libxml2"),
    "libxml2-dev": ("xmlsoft", "libxml2"),
    "expat": ("libexpat_project", "libexpat"),
    "libexpat1": ("libexpat_project", "libexpat"),
    # SQLite
    "sqlite": ("sqlite", "sqlite"),
    "sqlite3": ("sqlite", "sqlite"),
    "libsqlite3-0": ("sqlite", "sqlite"),
    # Cryptography stacks
    "gnupg": ("gnupg", "gnupg"),
    "gnupg2": ("gnupg", "gnupg"),
    "libgcrypt20": ("gnupg", "libgcrypt"),
    "libgnutls30": ("gnu", "gnutls"),
    "nss": ("mozilla", "nss"),
    "libnss3": ("mozilla", "nss"),
    # Regex
    "pcre": ("pcre", "pcre"),
    "pcre2": ("pcre", "pcre2"),
    "libpcre3": ("pcre", "pcre"),
    "libpcre2-8-0": ("pcre", "pcre2"),
    # Image libs
    "libpng": ("libpng", "libpng"),
    "libpng16-16": ("libpng", "libpng"),
    "libjpeg-turbo": ("libjpeg-turbo", "libjpeg-turbo"),
    # Java runtime (commonly shipped via distro packages)
    "openjdk": ("oracle", "openjdk"),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_DISTRO_PURL_TYPES: Final[frozenset[str]] = frozenset(
    {
        # PURL spec types
        "deb",
        "rpm",
        "apk",
        "conan",
        # Non-spec aliases occasionally emitted by SBOM generators
        "debian",
        "alpine",
        "redhat",
    }
)


@dataclass(frozen=True, slots=True)
class DistroCpeResolution:
    """One distro-PURL → upstream-CPE mapping.

    ``cpe`` is the full CPE 2.3 string ready for NVD lookup.
    ``cpe_vendor`` / ``cpe_product`` are exposed so PR-C's
    ``version_range`` integration can do its own structural matching.
    ``upstream_version`` is the distro version with epoch + revision
    stripped (empty string if the input had no version).
    ``source`` distinguishes curated-table hits from heuristic
    fallbacks — useful for explainability surfaces and for
    calibration metrics ("what fraction of resolutions are
    heuristic-only?").
    """

    cpe: str
    cpe_vendor: str
    cpe_product: str
    upstream_version: str
    source: Literal["curated", "heuristic"]


_EPOCH_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"^\d+:")


def normalize_upstream_version(version: str | None, purl_type: str) -> str:
    """Strip distro-packaging artefacts and return the upstream version.

    Rules per ecosystem (all conservative — every transform is a
    documented Debian/RPM/Alpine packaging convention):

      * **deb / debian**: strip epoch prefix (``\\d+:``) and the
        Debian revision (everything after the LAST ``-``, since
        upstream hyphens must be ``~``-quoted per Debian Policy 5.6.12).
        Examples:
          ``2:3.0.2-1``           → ``3.0.2``
          ``2:3.0.2-1+deb11u5``   → ``3.0.2``
          ``1.2.3-rc1-1``         → ``1.2.3-rc1`` (only the LAST hyphenated segment goes)

      * **rpm / redhat**: strip epoch and the RPM release (everything
        after the LAST ``-``). RPM releases carry the dist suffix
        (``.el8``, ``.fc39``, ``.amzn2023``); since they live in the
        release portion, the rsplit rule removes them.
        Examples:
          ``3.0.2-1.el8``         → ``3.0.2``
          ``1:3.0.2-1.el8``       → ``3.0.2``

      * **apk / alpine**: strip the Alpine revision (``-rN``).
        Examples:
          ``3.0.2-r0``            → ``3.0.2``
          ``3.0.2_p1-r0``         → ``3.0.2_p1`` (``_pN`` upstream-patch marker preserved)

      * **conan**: passthrough — Conan versions are already upstream-shaped.

      * **unknown / non-distro**: passthrough.

    Empty / ``None`` input returns ``""``.
    """
    if not version:
        return ""
    v = version.strip()
    if not v:
        return ""
    t = (purl_type or "").lower()
    if t in {"deb", "debian", "rpm", "redhat", "apk", "alpine"}:
        # Strip epoch (``\d+:`` at the start).
        v = _EPOCH_PREFIX_RE.sub("", v, count=1)
        # Strip the LAST hyphenated segment — Debian/RPM revision or
        # Alpine -rN. Upstream versions don't carry literal hyphens
        # in Debian (Policy 5.6.12); RPM and APK follow the same
        # one-hyphen-revision convention. A version with NO hyphen
        # means there's no revision to strip — passthrough.
        if "-" in v:
            v = v.rsplit("-", 1)[0]
        return v
    # Conan + everything else: passthrough.
    return v


def resolve(purl: str | None) -> DistroCpeResolution | None:
    """Resolve a distro/Conan PURL to its upstream CPE.

    Returns ``None`` when:
      * ``purl`` is empty / unparseable.
      * The PURL type isn't a distro/Conan type (npm, pypi, maven,
        etc.) — so the caller in ``cpe.py`` (PR-B) can short-circuit
        early and only route the right PURL types through here.

    On success returns a ``DistroCpeResolution`` whose ``cpe`` is the
    full CPE 2.3 string ready to feed NVD. The version slot is
    pre-sanitised with the same rule ``cpe.py:147-148`` uses (alnum +
    ``._-`` kept; anything else collapsed to ``_``; trailing
    punctuation stripped; empty → ``*``).
    """
    if not purl:
        return None
    parsed = parse_purl(purl)
    if not parsed:
        return None
    ptype = (parsed.get("type") or "").lower()
    if ptype not in _DISTRO_PURL_TYPES:
        return None
    name = (parsed.get("name") or "").strip()
    if not name:
        return None
    name_lc = name.lower()
    version = parsed.get("version") or ""
    upstream_version = normalize_upstream_version(version, ptype)

    if name_lc in _CURATED_DISTRO_CPE:
        vendor, product = _CURATED_DISTRO_CPE[name_lc]
        source: Literal["curated", "heuristic"] = "curated"
    else:
        vendor, product = _heuristic_vendor_product(name_lc)
        source = "heuristic"

    ver_slot = _sanitise_cpe_version_slot(upstream_version)
    cpe = f"cpe:2.3:a:{vendor}:{product}:{ver_slot}:*:*:*:*:*:*:*"
    return DistroCpeResolution(
        cpe=cpe,
        cpe_vendor=vendor,
        cpe_product=product,
        upstream_version=upstream_version,
        source=source,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


# Suffixes that the heuristic fallback strips before slug-cleaning.
# These are Debian/RPM binary-package conventions where the
# underlying upstream is the prefix (``libcurl-dev`` → upstream
# curl, ``openssl-doc`` → upstream openssl). Conservative list — a
# wider strip is calibration territory.
_HEURISTIC_SUFFIX_STRIP: Final[tuple[str, ...]] = (
    "-dev",
    "-doc",
    "-data",
    "-common",
    "-utils",
    "-bin",
    "-tools",
    "-devel",   # RPM convention for ``-dev``
)


def _heuristic_vendor_product(name_lc: str) -> tuple[str, str]:
    """Best-effort (vendor, product) for an uncovered package name.

    Rule: ``vendor == product == slug(name_lc)`` after a conservative
    suffix strip. The vendor-equals-product convention holds in NVD's
    CPE dictionary for the vast majority of canonical C/C++/system
    libraries (``zlib:zlib``, ``expat:libexpat``, ``sqlite:sqlite``,
    ``nginx:nginx``, ...). It's wrong for some — ``openssl`` /
    ``glibc`` / ``openssh`` / ``apache2`` — which is exactly why the
    curated table exists. An uncovered package still gets a
    best-effort CPE rather than ``None``: a wrong-vendor CPE produces
    no match (silently zero findings, no over-reporting), still
    better than the legacy ``debian:<name>`` shape which mismatched
    by definition.
    """
    base = name_lc
    for suffix in _HEURISTIC_SUFFIX_STRIP:
        if base.endswith(suffix) and len(base) > len(suffix):
            base = base[: -len(suffix)]
            break
    slugged = _slug(base)
    if not slugged:
        slugged = _slug(name_lc) or name_lc
    return slugged, slugged


def _slug(token: str) -> str:
    """Lowercase + alnum/``._-`` only + strip trailing punctuation.

    Same rule as ``cpe.py::slug``; duplicated here to keep this module
    free of internal cross-imports (matches the posture of
    ``version_range.py``, which doesn't import from ``cpe.py``
    either).
    """
    if not token:
        return ""
    out: list[str] = []
    for ch in token.lower():
        if ch.isalnum() or ch in ("_", "-", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip("._-")


def _sanitise_cpe_version_slot(version: str) -> str:
    """Match ``cpe.py:147-148`` exactly so the resolver's output
    plugs into the same NVD-lookup machinery."""
    if not version:
        return "*"
    cleaned = "".join(
        ch if ch.isalnum() or ch in "._-" else "_" for ch in version
    ).strip("._-")
    return cleaned or "*"


__all__ = [
    "DistroCpeResolution",
    "normalize_upstream_version",
    "resolve",
]
