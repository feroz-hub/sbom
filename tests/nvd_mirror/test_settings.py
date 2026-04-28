"""Phase 2.2 — NvdMirrorSettings env loader."""

from __future__ import annotations

import pytest

from app.nvd_mirror.settings import (
    NvdMirrorSettings,
    load_mirror_settings_from_env,
)


@pytest.fixture(autouse=True)
def _clear_mirror_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip any NVD_MIRROR_* vars leaked in from the dev shell."""
    for var in (
        "NVD_MIRROR_ENABLED",
        "NVD_MIRROR_API_ENDPOINT",
        "NVD_MIRROR_API_KEY_ENV_VAR",
        "NVD_MIRROR_FERNET_KEY_ENV_VAR",
        "NVD_MIRROR_DOWNLOAD_FEEDS_ENABLED",
        "NVD_MIRROR_PAGE_SIZE",
        "NVD_MIRROR_WINDOW_DAYS",
        "NVD_MIRROR_MIN_FRESHNESS_HOURS",
    ):
        monkeypatch.delenv(var, raising=False)


def test_defaults_match_dataclass_defaults() -> None:
    s = load_mirror_settings_from_env()
    assert s == NvdMirrorSettings()
    assert s.enabled is False
    assert s.api_endpoint == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert s.api_key_env_var == "NVD_API_KEY"
    assert s.fernet_key_env_var == "NVD_MIRROR_FERNET_KEY"
    assert s.download_feeds_enabled is False
    assert s.page_size == 2000
    assert s.window_days == 119
    assert s.min_freshness_hours == 24


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
def test_enabled_truthy_values(monkeypatch: pytest.MonkeyPatch, truthy: str) -> None:
    monkeypatch.setenv("NVD_MIRROR_ENABLED", truthy)
    assert load_mirror_settings_from_env().enabled is True


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", "garbage", ""])
def test_enabled_falsy_values(monkeypatch: pytest.MonkeyPatch, falsy: str) -> None:
    monkeypatch.setenv("NVD_MIRROR_ENABLED", falsy)
    assert load_mirror_settings_from_env().enabled is False


def test_int_clamping(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_MIRROR_PAGE_SIZE", "0")
    monkeypatch.setenv("NVD_MIRROR_WINDOW_DAYS", "999")
    s = load_mirror_settings_from_env()
    assert s.page_size == 1
    assert s.window_days == 119


def test_int_invalid_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_MIRROR_PAGE_SIZE", "not-a-number")
    assert load_mirror_settings_from_env().page_size == 2000


def test_str_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NVD_MIRROR_API_ENDPOINT", "https://nvd-proxy.internal/api/cves/2.0")
    monkeypatch.setenv("NVD_MIRROR_API_KEY_ENV_VAR", "MY_NVD_KEY")
    s = load_mirror_settings_from_env()
    assert s.api_endpoint == "https://nvd-proxy.internal/api/cves/2.0"
    assert s.api_key_env_var == "MY_NVD_KEY"


def test_settings_is_frozen() -> None:
    s = NvdMirrorSettings()
    with pytest.raises((AttributeError, Exception)):
        s.enabled = True  # type: ignore[misc]


def test_multi_settings_carries_mirror_field() -> None:
    """get_analysis_settings_multi exposes the mirror sub-config."""
    from app.analysis import _MultiSettings, get_analysis_settings_multi

    s = get_analysis_settings_multi()
    assert isinstance(s, _MultiSettings)
    assert isinstance(s.mirror, NvdMirrorSettings)
    # Existing flat keys still work — backward-compat.
    assert s.nvd_api_base_url.startswith("https://services.nvd.nist.gov")
