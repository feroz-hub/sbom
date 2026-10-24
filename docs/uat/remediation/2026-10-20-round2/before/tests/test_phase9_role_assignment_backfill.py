import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from app.db import engine
from sqlalchemy import text


def test_backfill_creates_primary_assignment_and_migrated_history():
    spec = importlib.util.spec_from_file_location(
        "phase9_migration",
        Path("alembic/versions/049_tenant_multi_role_assignments.py"),
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        user_id = connection.scalar(
            text(
                """
                INSERT INTO iam_users
                    (external_iam_user_id, external_issuer, external_subject,
                     email, display_name, status, email_verified,
                     email_verified_at, verification_required, created_at, updated_at)
                VALUES
                    ('backfill-user','https://issuer.test','backfill-sub',
                     'backfill@example.test','Backfill User','ACTIVE',true,
                     :now,false,:now,:now)
                RETURNING id
                """
            ),
            {"now": now},
        )
        membership_id = connection.scalar(
            text(
                """
                INSERT INTO tenant_users
                    (tenant_id,user_id,role,role_assignment_version,status,created_at,updated_at)
                VALUES (1,:user_id,'VIEWER',1,'ACTIVE',:now,:now)
                RETURNING id
                """
            ),
            {"user_id": user_id, "now": now},
        )
        module._backfill(connection)
        assignment = connection.execute(
            text(
                """
                SELECT status,is_primary,assignment_source
                  FROM tenant_user_role_assignments
                 WHERE tenant_user_id=:id
                """
            ),
            {"id": membership_id},
        ).one()
        event = connection.scalar(
            text(
                """
                SELECT event_type
                  FROM tenant_user_role_assignment_history
                 WHERE tenant_user_id=:id
                """
            ),
            {"id": membership_id},
        )
    assert assignment == ("ACTIVE", True, "MIGRATION")
    assert event == "MIGRATED"
