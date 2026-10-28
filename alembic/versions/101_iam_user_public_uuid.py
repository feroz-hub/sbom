"""Immutable UUIDv4 public IAM users, retaining all integer keys.

Forward-only transactional expansion/backfill/finalization. Review the populated
installation backup and DDL window before running. Revision 100 is not replayed.
"""

from alembic import op
from sqlalchemy import text

revision = "101_iam_user_public_uuid"
down_revision = "100_greenfield_uuid_final"
branch_labels = None
depends_on = None


def upgrade():
    from app.iam_public_identity import install_iam_guards

    connection = op.get_bind()
    if connection.dialect.name != "postgresql" or not connection.in_transaction():
        raise RuntimeError("IAM UUID installation requires an owned PostgreSQL transaction")
    connection.execute(text("SELECT pg_advisory_xact_lock(7160085101)"))
    connection.exec_driver_sql("LOCK TABLE public.alembic_version IN EXCLUSIVE MODE NOWAIT")
    connection.exec_driver_sql("LOCK TABLE ONLY public.iam_users IN ACCESS EXCLUSIVE MODE NOWAIT")
    if connection.exec_driver_sql("SELECT version_num FROM public.alembic_version").scalars().all() != [down_revision]:
        raise RuntimeError("IAM UUID installation requires exactly revision 100")
    connection.exec_driver_sql("ALTER TABLE public.iam_users ADD COLUMN public_id uuid")
    connection.exec_driver_sql(
        "ALTER TABLE public.iam_users ALTER COLUMN public_id SET DEFAULT pg_catalog.gen_random_uuid()"
    )
    connection.exec_driver_sql(
        "UPDATE public.iam_users SET public_id = pg_catalog.gen_random_uuid() WHERE public_id IS NULL"
    )
    connection.exec_driver_sql("ALTER TABLE public.iam_users ALTER COLUMN public_id SET NOT NULL")
    connection.exec_driver_sql("ALTER TABLE public.iam_users ADD CONSTRAINT uq_iam_users_public_id UNIQUE(public_id)")
    install_iam_guards(connection)


def downgrade():
    raise RuntimeError("IAM public identities are permanent; restore/recovery requires independent operator review")
