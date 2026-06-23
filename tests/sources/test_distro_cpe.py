"""Tests for ``app/sources/distro_cpe.py`` (roadmap #5, PR-A).

Six buckets per the PR-A brief:

  1. Roadmap example — ``pkg:deb/debian/openssl@2:3.0.2-1`` resolves
     to the upstream OpenSSL CPE at version ``3.0.2``.
  2. Per-ecosystem version stripping (deb / rpm / apk).
  3. Curated-table hits — seeded packages map to the right
     ``(vendor, product)``.
  4. Heuristic fallback — uncovered packages get a best-effort CPE
     rather than ``None``.
  5. Conan — vendor inference; plain version, no stripping.
  6. Non-distro PURLs (npm / pypi / maven) → ``None`` so the future
     ``cpe.py`` router can short-circuit early.

Pure-module tests — no DB, no network, no fixtures beyond the inline
literal PURL strings.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from app.sources.distro_cpe import (
    normalize_upstream_version,
    resolve,
)

# =============================================================================
# Bucket 1 — Roadmap example
# =============================================================================


class TestRoadmapExample:
    def test_pkg_deb_debian_openssl_resolves_to_upstream_openssl(self) -> None:
        result = resolve("pkg:deb/debian/openssl@2:3.0.2-1")
        assert result is not None
        assert result.cpe_vendor == "openssl"
        assert result.cpe_product == "openssl"
        assert result.upstream_version == "3.0.2"
        assert result.source == "curated"
        assert result.cpe == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"


# =============================================================================
# Bucket 2 — Per-ecosystem version stripping
# =============================================================================


class TestVersionNormalisation:
    @pytest.mark.parametrize(
        "purl_type,version,expected",
        [
            # Debian: epoch + revision, including the +debNuN suffix.
            ("deb", "2:3.0.2-1", "3.0.2"),
            ("deb", "2:3.0.2-1+deb11u5", "3.0.2"),
            ("deb", "1.21.0", "1.21.0"),  # no epoch, no revision
            ("deb", "1:2.3.4", "2.3.4"),  # epoch only
            # RPM: epoch + .elN/.fcN/.amzn release suffix.
            ("rpm", "3.0.2-1.el8", "3.0.2"),
            ("rpm", "1:3.0.2-1.el8", "3.0.2"),
            ("rpm", "3.0.2-1.fc39", "3.0.2"),
            ("rpm", "3.0.2-1.amzn2023", "3.0.2"),
            # APK: -rN revision; the _pN upstream-patch marker survives.
            ("apk", "3.0.2-r0", "3.0.2"),
            ("apk", "3.0.2-r15", "3.0.2"),
            ("apk", "3.0.2_p1-r0", "3.0.2_p1"),
            # Conan: passthrough.
            ("conan", "1.81.0", "1.81.0"),
            # Non-distro: passthrough (defensive — caller short-circuits).
            ("npm", "1.0.0", "1.0.0"),
            # Empty / None / whitespace.
            ("deb", "", ""),
            ("deb", None, ""),
            ("deb", "   ", ""),
        ],
    )
    def test_normalize_upstream_version_strips_distro_artefacts(
        self, purl_type: str, version: str | None, expected: str
    ) -> None:
        assert normalize_upstream_version(version, purl_type) == expected

    def test_deb_with_tilde_quoted_prerelease_is_preserved(self) -> None:
        # Debian Policy 5.6.12: upstream hyphens MUST be ``~``-quoted,
        # so the rsplit-on-last-``-`` rule never eats an upstream
        # token. ``1.2.3~rc1-1`` → ``1.2.3~rc1``.
        assert normalize_upstream_version("1.2.3~rc1-1", "deb") == "1.2.3~rc1"
        assert normalize_upstream_version("1:1.2.3~rc1-1+deb11u3", "deb") == "1.2.3~rc1"


class TestVersionStrippingViaResolve:
    @pytest.mark.parametrize(
        "purl,expected_version",
        [
            ("pkg:deb/debian/openssl@2:3.0.2-1+deb11u5", "3.0.2"),
            ("pkg:rpm/redhat/openssl@1:3.0.2-1.el8", "3.0.2"),
            ("pkg:apk/alpine/openssl@3.0.2-r0", "3.0.2"),
        ],
    )
    def test_end_to_end_version_in_cpe_is_upstream(self, purl: str, expected_version: str) -> None:
        result = resolve(purl)
        assert result is not None
        assert result.upstream_version == expected_version
        # CPE version slot reflects the stripped value.
        assert f":openssl:openssl:{expected_version}:" in result.cpe


# =============================================================================
# Bucket 3 — Curated hits
# =============================================================================


class TestCuratedTableHits:
    @pytest.mark.parametrize(
        "purl,vendor,product",
        [
            ("pkg:deb/debian/openssl@2:3.0.2-1", "openssl", "openssl"),
            ("pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u3", "openssl", "openssl"),
            ("pkg:deb/debian/glibc@2.31-13+deb11u5", "gnu", "glibc"),
            ("pkg:deb/debian/libc6@2.31-13", "gnu", "glibc"),
            ("pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2+deb11u2", "zlib", "zlib"),
            ("pkg:deb/debian/curl@7.74.0-1.3+deb11u7", "haxx", "curl"),
            ("pkg:deb/debian/libcurl4@7.74.0-1.3", "haxx", "curl"),
            ("pkg:deb/debian/openssh-server@1:8.4p1-5+deb11u2", "openbsd", "openssh"),
            ("pkg:deb/debian/bash@5.1-2+deb11u1", "gnu", "bash"),
            ("pkg:deb/debian/coreutils@8.32-4+b1", "gnu", "coreutils"),
            ("pkg:rpm/redhat/openssh-clients@8.7p1-34.el9", "openbsd", "openssh"),
            ("pkg:apk/alpine/musl@1.2.4-r0", "musl-libc", "musl"),
            ("pkg:deb/debian/nginx-core@1.18.0-6.1+deb11u3", "nginx", "nginx"),
            ("pkg:deb/debian/apache2@2.4.54-1~deb11u1", "apache", "http_server"),
            ("pkg:deb/debian/libxml2@2.9.10+dfsg-6.7+deb11u4", "xmlsoft", "libxml2"),
            ("pkg:deb/debian/sqlite3@3.34.1-3", "sqlite", "sqlite"),
        ],
    )
    def test_curated_packages_map_to_expected_vendor_product(self, purl: str, vendor: str, product: str) -> None:
        result = resolve(purl)
        assert result is not None, f"resolve returned None for {purl!r}"
        assert result.cpe_vendor == vendor, f"{purl!r}: expected vendor {vendor!r}, got {result.cpe_vendor!r}"
        assert result.cpe_product == product, f"{purl!r}: expected product {product!r}, got {result.cpe_product!r}"
        assert result.source == "curated"


# =============================================================================
# Bucket 4 — Heuristic fallback
# =============================================================================


class TestHeuristicFallback:
    def test_uncovered_package_yields_vendor_equals_product_cpe(self) -> None:
        result = resolve("pkg:deb/debian/some-uncovered-pkg@1.0.0-1")
        assert result is not None, "heuristic must NOT return None"
        assert result.cpe_vendor == result.cpe_product
        assert result.source == "heuristic"
        # Sanitised version slot.
        assert result.cpe == (f"cpe:2.3:a:{result.cpe_vendor}:{result.cpe_product}:1.0.0:*:*:*:*:*:*:*")

    def test_heuristic_strips_common_distro_suffixes(self) -> None:
        # ``-dev`` is a Debian convention; the heuristic strips it so
        # ``customlib-dev`` maps to the same vendor/product as
        # ``customlib`` would.
        with_suffix = resolve("pkg:deb/debian/customlib-dev@1.0.0-1")
        without = resolve("pkg:deb/debian/customlib@1.0.0-1")
        assert with_suffix is not None and without is not None
        assert with_suffix.cpe_vendor == without.cpe_vendor
        assert with_suffix.cpe_product == without.cpe_product

    def test_heuristic_lowercases_input(self) -> None:
        upper = resolve("pkg:deb/debian/SomeLib@1.0.0-1")
        lower = resolve("pkg:deb/debian/somelib@1.0.0-1")
        assert upper is not None and lower is not None
        assert upper.cpe_vendor == lower.cpe_vendor

    def test_heuristic_collapses_non_slug_chars(self) -> None:
        # Funky package name — slug rule collapses non-alnum-non-``._-``.
        result = resolve("pkg:deb/debian/some+lib@1.0.0-1")
        assert result is not None
        # ``+`` → ``_``; trailing/leading punctuation stripped.
        assert result.cpe_vendor == "some_lib"
        assert result.cpe_product == "some_lib"


# =============================================================================
# Bucket 5 — Conan: vendor inference + plain version
# =============================================================================


class TestConan:
    def test_conan_unknown_package_infers_vendor_from_name(self) -> None:
        # ``pkg:conan/boost@1.81.0`` — not in curated table; heuristic
        # gives boost:boost, version unchanged.
        result = resolve("pkg:conan/boost@1.81.0")
        assert result is not None
        assert result.cpe_vendor == "boost"
        assert result.cpe_product == "boost"
        assert result.upstream_version == "1.81.0"  # no stripping
        assert result.source == "heuristic"

    def test_conan_curated_hit(self) -> None:
        # OpenSSL is in the curated table, regardless of PURL type.
        result = resolve("pkg:conan/openssl@3.0.2")
        assert result is not None
        assert (result.cpe_vendor, result.cpe_product) == ("openssl", "openssl")
        assert result.upstream_version == "3.0.2"

    def test_conan_version_passthrough_no_stripping(self) -> None:
        # A version that LOOKS like a deb revision is left alone for
        # conan — no rsplit-on-``-``.
        result = resolve("pkg:conan/example@1.2.3-1")
        assert result is not None
        assert result.upstream_version == "1.2.3-1"

    def test_conan_with_user_channel_qualifiers(self) -> None:
        # PURL spec allows ``pkg:conan/<name>@<v>?user=x&channel=y``.
        # parse_purl puts user/channel under qualifiers; the resolver
        # ignores them (CPE doesn't model channels).
        result = resolve("pkg:conan/openssl@3.0.2?user=conan&channel=stable")
        assert result is not None
        assert (result.cpe_vendor, result.cpe_product) == ("openssl", "openssl")


# =============================================================================
# Bucket 6 — Non-distro PURLs return None
# =============================================================================


class TestNonDistroReturnsNone:
    @pytest.mark.parametrize(
        "purl",
        [
            "pkg:npm/lodash@4.17.20",
            "pkg:pypi/django@4.0",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            "pkg:golang/github.com/foo/bar@v1.0.0",
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            "pkg:cargo/serde@1.0.0",
            "pkg:composer/symfony/console@5.4.0",
            "pkg:rubygems/rails@7.0.0",
        ],
    )
    def test_non_distro_purl_returns_none(self, purl: str) -> None:
        assert resolve(purl) is None, (
            f"resolve({purl!r}) must return None so cpe.py's router "
            f"only sends distro/conan PURLs into the distro resolver"
        )

    @pytest.mark.parametrize(
        "purl",
        [
            "",
            None,
            "not-a-purl",
            "pkg:",
            "pkg:deb",
            "pkg:deb/",
        ],
    )
    def test_empty_or_unparseable_purl_returns_none(self, purl: str | None) -> None:
        assert resolve(purl) is None  # type: ignore[arg-type]

    def test_distro_purl_without_version_still_resolves(self) -> None:
        # A distro PURL with no version yields a CPE with ``*`` in the
        # version slot — caller can still look up "any version" for
        # the upstream package. Curated table still applies.
        result = resolve("pkg:deb/debian/openssl")
        assert result is not None
        assert result.cpe_vendor == "openssl"
        assert result.upstream_version == ""
        assert result.cpe == "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"


# =============================================================================
# Output shape sanity
# =============================================================================


class TestResolutionShape:
    def test_resolution_is_frozen_dataclass(self) -> None:
        result = resolve("pkg:deb/debian/openssl@2:3.0.2-1")
        assert result is not None
        with pytest.raises(FrozenInstanceError):
            # frozen=True → attribute assignment raises FrozenInstanceError.
            result.cpe_vendor = "tampered"  # type: ignore[misc]

    def test_cpe_string_shape_matches_cpe_py_template(self) -> None:
        # Same 12-part shape as cpe.py:150-153.
        result = resolve("pkg:deb/debian/openssl@2:3.0.2-1")
        assert result is not None
        parts = result.cpe.split(":")
        assert parts[0] == "cpe"
        assert parts[1] == "2.3"
        assert parts[2] == "a"  # application part
        assert len(parts) == 13  # ``cpe`` + 12 fields

    def test_resolution_source_field_distinguishes_curated_from_heuristic(
        self,
    ) -> None:
        assert resolve("pkg:deb/debian/openssl@3.0.2-1").source == "curated"  # type: ignore[union-attr]
        assert resolve("pkg:deb/debian/some-uncovered-thing@1.0.0-1").source == "heuristic"  # type: ignore[union-attr]
