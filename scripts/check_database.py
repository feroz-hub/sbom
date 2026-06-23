#!/usr/bin/env python3
"""
Diagnostic script to check the active database configuration and connection.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

# Set ALLOW_SQLITE=true temporarily so that imports succeed when DATABASE_URL is unset
os.environ.setdefault("ALLOW_SQLITE", "true")

try:
    from app.db import engine
except Exception as e:
    print(f"Error importing app.db (probably missing DATABASE_URL): {e}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    try:
        # 1. Print active Python executable
        print(f"python: {sys.executable}")

        # 2. Parse database URL and mask password
        from sqlalchemy.engine import make_url

        url = make_url(engine.url)
        safe_url = url.render_as_string(hide_password=True)
        print(f"database_url: {safe_url}")

        # 3. Print dialect
        dialect = engine.dialect.name
        print(f"dialect: {dialect}")

        # 4. Try connectivity
        connectivity = "failed"
        table_names = []
        actual_heads = set()

        try:
            with engine.connect() as conn:
                # Execute a simple query to verify connection
                conn.execute(text("SELECT 1"))
                connectivity = "ok"

                insp = inspect(engine)
                table_names = insp.get_table_names()

                if "alembic_version" in table_names:
                    actual_heads = {
                        str(row[0]) for row in conn.execute(text("SELECT version_num FROM alembic_version"))
                    }
        except Exception as exc:
            exc_str = str(exc)
            if (
                "password authentication failed" in exc_str
                or "authentication failed" in exc_str
                or "fe_sendauth" in exc_str
            ):
                connectivity = "failed (authentication failed)"
            else:
                connectivity = f"failed ({exc})"

        print(f"connectivity: {connectivity}")

        # 5. DB User and Name
        db_user = url.username or ""
        db_name = url.database or ""
        print(f"current_user: {db_user}")
        print(f"database: {db_name}")

        # 6. Alembic versions
        root = Path(__file__).resolve().parent.parent
        config = Config(str(root / "alembic.ini"))
        expected_heads = set(ScriptDirectory.from_config(config).get_heads())

        alembic_current = ",".join(actual_heads) if actual_heads else "none"
        alembic_head = ",".join(expected_heads)

        print(f"alembic_current: {alembic_current}")
        print(f"alembic_head: {alembic_head}")

        # 7. sbom_source.tenant_id
        tenant_id_exists = False
        if "sbom_source" in table_names:
            insp = inspect(engine)
            columns = [c["name"] for c in insp.get_columns("sbom_source")]
            tenant_id_exists = "tenant_id" in columns

        print(f"sbom_source.tenant_id: {'present' if tenant_id_exists else 'absent'}")

        return 0 if connectivity == "ok" else 1
    except Exception as e:
        print(f"Error running check_database script: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
