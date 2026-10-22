"""Public Membership, Platform Grant and Analysis Run UUIDv4; integer graph retained.

Forward-only, one caller-owned transaction. Populated execution requires separate
backup, owner, row-count, lock-window and cutover approval. No automatic retry.
"""

from alembic import op
from sqlalchemy import text

revision = "102_public_membership_grant_analysis_uuid"
down_revision = "101_iam_user_public_uuid"
branch_labels = None
depends_on = None


def upgrade():
    from app.resource_public_identity import TABLES, install_resource_guards

    c = op.get_bind()
    if c.dialect.name != "postgresql" or not c.in_transaction():
        raise RuntimeError("Public resource UUID installation requires an owned PostgreSQL transaction")
    if c.connection.driver_connection.autocommit is not False:
        raise RuntimeError("Public resource UUID installation refuses DBAPI autocommit")
    c.exec_driver_sql("SET LOCAL statement_timeout = '30s'")
    c.exec_driver_sql("SET LOCAL lock_timeout = '250ms'")
    c.exec_driver_sql("SET LOCAL idle_in_transaction_session_timeout = '5s'")
    c.execute(text("SELECT pg_advisory_xact_lock(7160085102)"))
    c.exec_driver_sql("LOCK TABLE public.alembic_version IN EXCLUSIVE MODE NOWAIT")
    for table in TABLES:
        c.exec_driver_sql(f"LOCK TABLE ONLY public.{table} IN ACCESS EXCLUSIVE MODE NOWAIT")
    if c.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all() != [down_revision]:
        raise RuntimeError("Public resource UUID installation requires exactly revision 101")
    for table in TABLES:
        c.exec_driver_sql(f"ALTER TABLE public.{table} ADD COLUMN public_id uuid")
        c.exec_driver_sql(f"ALTER TABLE public.{table} ALTER COLUMN public_id SET DEFAULT pg_catalog.gen_random_uuid()")
        c.exec_driver_sql(f"UPDATE public.{table} SET public_id=pg_catalog.gen_random_uuid() WHERE public_id IS NULL")
        c.exec_driver_sql(f"ALTER TABLE public.{table} ALTER COLUMN public_id SET NOT NULL")
        c.exec_driver_sql(f"ALTER TABLE public.{table} ADD CONSTRAINT uq_{table}_public_id UNIQUE(public_id)")
    install_resource_guards(c)


def downgrade():
    raise RuntimeError(
        "Public resource identities are permanent; recovery requires separately approved backup restoration"
    )
