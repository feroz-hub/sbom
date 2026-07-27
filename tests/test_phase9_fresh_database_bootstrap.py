from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_fresh_bootstrap_path_reaches_phase9_head_without_live_metadata_replay():
    source = Path("scripts/bootstrap_fresh_database.py").read_text()
    assert "047_email_verification_tokens" in source
    assert '"alembic", "upgrade", "head"' in source
    assert 'EXPECTED_HEAD = "049_tenant_multi_role_assignments"' in source
    assert "Base.metadata.create_all" not in source
    assert ScriptDirectory.from_config(Config("alembic.ini")).get_current_head() == (
        "049_tenant_multi_role_assignments"
    )
