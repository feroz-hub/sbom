from pathlib import Path

from app.settings import PROJECT_ROOT, Settings


def test_relative_hcl_iam_ca_bundle_resolves_from_repository_root():
    settings = Settings(hcl_iam_ca_bundle=".certificates/hcl-cs-local.crt")

    assert settings.hcl_iam_ca_bundle == str(
        (PROJECT_ROOT / ".certificates/hcl-cs-local.crt").resolve()
    )


def test_absolute_hcl_iam_ca_bundle_is_preserved(tmp_path: Path):
    bundle = tmp_path / "hcl-ca.crt"

    settings = Settings(hcl_iam_ca_bundle=str(bundle))

    assert settings.hcl_iam_ca_bundle == str(bundle)
