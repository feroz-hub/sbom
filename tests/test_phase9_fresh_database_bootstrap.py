from pathlib import Path
from alembic.config import Config
from alembic.script import ScriptDirectory

def test_fresh_bootstrap_uses_dynamic_alembic_head_without_live_metadata_replay():
    source = Path("scripts/bootstrap_fresh_database.py").read_text() 
    assert "047_email_verification_tokens" in source
    assert '"alembic", "upgrade", "head"' in source
    # Fresh bootstrap must not hard-code the current Alembic head.

    assert "EXPECTED_HEAD =" not in source
    # Current Alembic head must be discovered from the migration graph.
    assert "ScriptDirectory.from_config" in source
    assert "get_heads()" in source

    # There must be at least one valid repository head.
    heads = set(
        ScriptDirectory.from_config(
            Config("alembic.ini")
        ).get_heads()
    )

    assert heads
    # Fresh PostgreSQL bootstrap must use the frozen schema,
    # not replay SQLAlchemy live metadata.
    assert "Base.metadata.create_all" not in source
