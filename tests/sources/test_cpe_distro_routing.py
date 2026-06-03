"""PR-B routing tests: ``cpe23_from_purl`` consults the
``distro_cpe_enabled`` flag to route distro/Conan PURLs through
``app.sources.distro_cpe.resolve`` (PR-A's resolver) BEFORE the
existing per-ecosystem branches.

Six fixed cases per the brief:
  1. Flag OFF → distro PURL uses the existing generic slugify
     (legacy CPE shape — proves no regression).
  2. Flag ON → distro PURL uses the resolver (upstream CPE).
  3. Flag ON → Conan PURL routes via the resolver.
  4. Flag ON → npm / pypi PURLs are unchanged (route to existing
     per-ecosystem branches; the distro-set check skips ``resolve``).
  5. (bonus) Flag ON, heuristic-resolved uncovered package — still
     a resolver hit, not a legacy fallthrough.
  6. (bonus) Pydantic-singleton fallback — flag flips reach the
     resolver via the global ``get_settings()`` when no explicit
     ``settings`` kwarg is passed.
"""

from __future__ import annotations

import pytest

from app.analysis import AnalysisSettings
from app.sources.cpe import cpe23_from_purl


def _settings(*, distro_on: bool) -> AnalysisSettings:
    return AnalysisSettings(distro_cpe_enabled=distro_on)


# =============================================================================
# 1. Flag OFF — legacy generic-slugify path (no regression)
# =============================================================================


class TestFlagOffLegacyPath:
    """When the flag is off, distro PURLs go through the generic
    fallback at cpe.py:137-140 — vendor=namespace, product=name. This
    test pins the EXACT legacy CPE shape so any future drift fails
    loudly."""

    def test_deb_openssl_flag_off_uses_generic_slugify(self) -> None:
        result = cpe23_from_purl(
            "pkg:deb/debian/openssl@2:3.0.2-1",
            settings=_settings(distro_on=False),
        )
        # Generic fallback: vendor=debian (from namespace), product=openssl.
        # Version slot has the epoch ``:`` collapsed to ``_``.
        assert result == "cpe:2.3:a:debian:openssl:2_3.0.2-1:*:*:*:*:*:*:*"

    def test_rpm_glibc_flag_off_uses_generic_slugify(self) -> None:
        result = cpe23_from_purl(
            "pkg:rpm/redhat/glibc@2.34-60.el9",
            settings=_settings(distro_on=False),
        )
        # vendor=redhat (namespace), product=glibc.
        assert result == "cpe:2.3:a:redhat:glibc:2.34-60.el9:*:*:*:*:*:*:*"

    def test_apk_musl_flag_off_uses_generic_slugify(self) -> None:
        result = cpe23_from_purl(
            "pkg:apk/alpine/musl@1.2.4-r0",
            settings=_settings(distro_on=False),
        )
        assert result == "cpe:2.3:a:alpine:musl:1.2.4-r0:*:*:*:*:*:*:*"


# =============================================================================
# 2. Flag ON — distro PURL routes through resolve()
# =============================================================================


class TestFlagOnDistroRouting:
    def test_deb_openssl_uses_resolver(self) -> None:
        result = cpe23_from_purl(
            "pkg:deb/debian/openssl@2:3.0.2-1",
            settings=_settings(distro_on=True),
        )
        # Resolver yields the upstream openssl:openssl:3.0.2.
        assert result == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"

    def test_rpm_glibc_uses_resolver(self) -> None:
        result = cpe23_from_purl(
            "pkg:rpm/redhat/glibc@2.34-60.el9",
            settings=_settings(distro_on=True),
        )
        # Resolver: glibc → gnu:glibc, upstream version 2.34.
        assert result == "cpe:2.3:a:gnu:glibc:2.34:*:*:*:*:*:*:*"

    def test_apk_openssl_uses_resolver(self) -> None:
        result = cpe23_from_purl(
            "pkg:apk/alpine/openssl@3.0.2-r0",
            settings=_settings(distro_on=True),
        )
        assert result == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"

    def test_deb_with_deb11u_revision_strips_to_upstream(self) -> None:
        result = cpe23_from_purl(
            "pkg:deb/debian/openssl@2:3.0.2-1+deb11u5",
            settings=_settings(distro_on=True),
        )
        assert result == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"


# =============================================================================
# 3. Flag ON — Conan PURL routes through resolve()
# =============================================================================


class TestFlagOnConanRouting:
    def test_conan_openssl_curated_hit(self) -> None:
        result = cpe23_from_purl(
            "pkg:conan/openssl@3.0.2",
            settings=_settings(distro_on=True),
        )
        # Curated table covers OpenSSL across all PURL types.
        assert result == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*"

    def test_conan_uncovered_package_vendor_equals_product(self) -> None:
        result = cpe23_from_purl(
            "pkg:conan/boost@1.81.0",
            settings=_settings(distro_on=True),
        )
        # Heuristic: vendor=product=boost.
        assert result == "cpe:2.3:a:boost:boost:1.81.0:*:*:*:*:*:*:*"

    def test_conan_version_passthrough_no_stripping(self) -> None:
        # Conan versions don't have epoch or distro revision; resolver
        # preserves them as-is (PR-A behaviour).
        result = cpe23_from_purl(
            "pkg:conan/example@1.2.3-1",
            settings=_settings(distro_on=True),
        )
        # ``1.2.3-1`` is preserved verbatim (no rsplit-on-``-`` for conan).
        assert result == "cpe:2.3:a:example:example:1.2.3-1:*:*:*:*:*:*:*"


# =============================================================================
# 4. Flag ON — npm / pypi / maven unchanged (routing skips them)
# =============================================================================


class TestFlagOnNonDistroPassthrough:
    @pytest.mark.parametrize(
        "purl,expected",
        [
            (
                "pkg:npm/lodash@4.17.20",
                "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*",
            ),
            (
                "pkg:pypi/django@4.0",
                "cpe:2.3:a:django:django:4.0:*:*:*:*:*:*:*",
            ),
            (
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
                "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*",
            ),
            (
                "pkg:rubygems/rails@7.0.0",
                "cpe:2.3:a:rails:rails:7.0.0:*:*:*:*:*:*:*",
            ),
        ],
    )
    def test_non_distro_ptype_skips_resolver(
        self, purl: str, expected: str
    ) -> None:
        """npm/pypi/maven/rubygems aren't in the distro-ptype set, so
        ``resolve()`` is NEVER called; the existing per-ecosystem
        branch fires unchanged. Result equals the legacy CPE.
        """
        flag_on = cpe23_from_purl(purl, settings=_settings(distro_on=True))
        flag_off = cpe23_from_purl(purl, settings=_settings(distro_on=False))
        assert flag_on == expected
        assert flag_on == flag_off, (
            f"non-distro PURL must produce IDENTICAL CPE regardless of "
            f"the distro_cpe_enabled flag; got "
            f"on={flag_on!r} off={flag_off!r}"
        )


# =============================================================================
# 5. Pydantic-singleton fallback when no explicit settings is passed
# =============================================================================


class TestSingletonFallback:
    def test_no_explicit_settings_reads_pydantic_singleton(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Production callers don't thread settings — they flip the env
        var and the singleton picks it up. Verify the helper reads
        ``get_settings().distro_cpe_enabled`` when no kwarg is passed.
        """
        from app import settings as settings_mod

        # Force a fresh singleton with the env var ON.
        monkeypatch.setenv("DISTRO_CPE_ENABLED", "true")
        settings_mod.reset_settings()
        try:
            result = cpe23_from_purl("pkg:deb/debian/openssl@2:3.0.2-1")
            assert result == "cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*", (
                "singleton fallback didn't pick up the env flag"
            )
        finally:
            # Reset for other tests.
            monkeypatch.delenv("DISTRO_CPE_ENABLED", raising=False)
            settings_mod.reset_settings()

    def test_singleton_default_false_yields_legacy_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app import settings as settings_mod

        monkeypatch.delenv("DISTRO_CPE_ENABLED", raising=False)
        settings_mod.reset_settings()
        try:
            result = cpe23_from_purl("pkg:deb/debian/openssl@2:3.0.2-1")
            # Default is False → legacy generic-slugify.
            assert result == "cpe:2.3:a:debian:openssl:2_3.0.2-1:*:*:*:*:*:*:*"
        finally:
            settings_mod.reset_settings()
