"""Performance guards for the cache-first NVD design."""

from app.services.nvd_client import build_nvd_params_for_cve_batch
from app.services.nvd_enrichment_service import collect_nvd_identifiers
from app.settings import Settings


def test_nvd_default_delays_follow_public_rate_limits():
    settings = Settings()
    assert settings.nvd_min_delay_without_api_key_seconds >= 6.0
    assert settings.nvd_min_delay_with_api_key_seconds >= 1.0


def test_cve_batch_has_hard_100_identifier_ceiling():
    ids = [f"CVE-2026-{10000 + i}" for i in range(100)]
    assert build_nvd_params_for_cve_batch(ids)["cveIds"].count(",") == 99


def test_purl_fanout_does_not_become_nvd_cpe_fanout():
    components = [{"name": f"pkg-{i}", "version": "1", "purl": f"pkg:pypi/pkg-{i}@1"} for i in range(500)]
    identifiers = collect_nvd_identifiers(components, [])
    assert identifiers.trusted_cpes == []


def test_generated_cpes_are_counted_but_never_queried():
    components = [
        {
            "name": f"pkg-{i}",
            "version": "1",
            "cpe": f"cpe:2.3:a:pkg-{i}:pkg-{i}:1:*:*:*:*:*:*:*",
            "cpe_source": "generated_fallback",
        }
        for i in range(50)
    ]
    identifiers = collect_nvd_identifiers(components, [])
    assert identifiers.trusted_cpes == []
    assert identifiers.skipped_generated_cpe == 50
