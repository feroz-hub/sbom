from pathlib import Path

from scripts.bootstrap_fresh_database import BASELINE_REVISION, SNAPSHOT


def test_frozen_bootstrap_snapshot_is_revision_047_and_has_no_phase8_tables():
    assert BASELINE_REVISION == "047_email_verification_tokens"
    sql = Path(SNAPSHOT).read_text(encoding="utf-8")
    assert "CREATE TABLE public.iam_users" in sql
    assert "authorization_roles" not in sql
    assert "CREATE TABLE public.nvd_settings" in sql
    assert "CREATE TABLE public.nvd_sync_runs" in sql
    assert "CREATE TABLE public.cves" in sql


def test_bootstrap_requires_explicit_empty_database_confirmation():
    source = Path("scripts/bootstrap_fresh_database.py").read_text(encoding="utf-8")
    assert "--confirm-empty-database" in source
    assert "Refusing fresh bootstrap because the target database is not empty" in source
