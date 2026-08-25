from __future__ import annotations

import pytest
from app.settings import IdentityGrantAuthorityMode, Settings
from pydantic import ValidationError


def _settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.delenv("HCL_IAM_GRANT_CLAIM", raising=False)
    monkeypatch.delenv("IDENTITY_GRANT_AUTHORITY_MODE", raising=False)
    return Settings(_env_file=None)


def test_identity_grant_settings_have_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)

    assert settings.hcl_iam_grant_claim == "sbom_grant"
    assert settings.identity_grant_authority_mode is IdentityGrantAuthorityMode.LOCAL
    assert settings.auth_enabled is False
    assert settings.hcl_iam_role_claim == "role"
    assert settings.hcl_iam_tenant_claim == "tenant_id"


def test_custom_hcl_iam_grant_claim_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HCL_IAM_GRANT_CLAIM", "my_custom_grant")
    monkeypatch.delenv("IDENTITY_GRANT_AUTHORITY_MODE", raising=False)

    assert Settings(_env_file=None).hcl_iam_grant_claim == "my_custom_grant"


@pytest.mark.parametrize("mode", list(IdentityGrantAuthorityMode))
def test_supported_identity_grant_authority_modes_are_accepted(
    monkeypatch: pytest.MonkeyPatch,
    mode: IdentityGrantAuthorityMode,
) -> None:
    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", mode.value)

    assert Settings(_env_file=None).identity_grant_authority_mode is mode


@pytest.mark.parametrize(
    "mode",
    ["BOTH", "LEGACY", "ENABLED", "DISABLED", "TEST", "", "UNKNOWN", "local"],
)
def test_invalid_identity_grant_authority_modes_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    monkeypatch.setenv("IDENTITY_GRANT_AUTHORITY_MODE", mode)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)
