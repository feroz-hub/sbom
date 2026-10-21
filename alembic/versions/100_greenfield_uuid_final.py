"""Final UUID schema baseline for verified greenfield installations.

Existing populated installations must use a separately reviewed upgrade path.
The standalone greenfield installer builds and validates complete metadata before
recording this marker; it does not claim historical data migrations were replayed.
"""
revision = '100_greenfield_uuid_final'
down_revision = '079_lifecycle_provider_verification'
branch_labels = None
depends_on = None


def upgrade():
    from alembic import op
    from sqlalchemy import text
    from app.public_identity import TABLES, install_guards

    connection = op.get_bind()
    for table in TABLES:
        if connection.execute(text(f'SELECT EXISTS (SELECT 1 FROM public.{table})')).scalar_one():
            raise RuntimeError('Greenfield baseline refuses populated application tables')
    for table in TABLES:
        connection.exec_driver_sql(f'ALTER TABLE public.{table} ADD COLUMN public_id uuid NOT NULL DEFAULT gen_random_uuid()')
        connection.exec_driver_sql(f'ALTER TABLE public.{table} ADD CONSTRAINT uq_{table}_public_id UNIQUE(public_id)')
    install_guards(connection)


def downgrade():
    raise RuntimeError('Public identities cannot be downgraded')
