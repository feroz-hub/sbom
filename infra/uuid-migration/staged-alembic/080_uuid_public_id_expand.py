"""Expand tenants with nullable, guarded UUIDv4 public identity.

Revision ID: 080_uuid_public_id_expand
Revises: 079_lifecycle_provider_verification

STAGED ONLY. One target table; no backfill/index/NOT NULL/API cutover.
Execute only as the single next revision in its own approved transaction.
See phase2/10-w1-expand-transaction-refactor.md for partial-chain recovery.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "080_uuid_public_id_expand"
down_revision = "079_lifecycle_provider_verification"
branch_labels = None
depends_on = None

_SCHEMA = "public"
_TABLE = "tenants"
_V4_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"

# Transaction-local caps retain stricter caller limits; not a whole-unit deadline.
_TIMEOUT_SQL = """
DO $uuid_expand_timeouts$
BEGIN
    IF pg_catalog.current_setting('lock_timeout')::pg_catalog.interval
       = INTERVAL '0 seconds'
       OR pg_catalog.current_setting('lock_timeout')::pg_catalog.interval
       > INTERVAL '1 second' THEN
        PERFORM pg_catalog.set_config('lock_timeout', '1s', true);
    END IF;
    IF pg_catalog.current_setting('statement_timeout')::pg_catalog.interval
       = INTERVAL '0 seconds'
       OR pg_catalog.current_setting('statement_timeout')::pg_catalog.interval
       > INTERVAL '10 seconds' THEN
        PERFORM pg_catalog.set_config('statement_timeout', '10s', true);
    END IF;
END;
$uuid_expand_timeouts$;
"""

# Catalog-only checks under ONLY/NOWAIT lock on this revision's table.
# Subsequent units verify, never replace, the function installed by 080.
_PREFLIGHT_SQL = """
DO $uuid_expand_preflight$
DECLARE
    target CONSTANT pg_catalog.text := 'tenants';
    relation_oid pg_catalog.oid;
    id_attnum pg_catalog.int2;
    allocator_oid pg_catalog.oid;
BEGIN
    IF pg_catalog.current_setting('server_version_num')::pg_catalog.int4
       / 10000 <> 16 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'UUID expand requires the reviewed PostgreSQL 16 target';
    END IF;

    SELECT p.oid INTO allocator_oid
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    WHERE n.nspname = 'pg_catalog' AND p.proname = 'gen_random_uuid'
      AND p.pronargs = 0 AND p.prokind = 'f'
      AND p.prorettype = 'pg_catalog.uuid'::pg_catalog.regtype;
    IF allocator_oid IS NULL OR NOT pg_catalog.has_function_privilege(
        CURRENT_USER, allocator_oid, 'EXECUTE'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'Core UUID allocator is unavailable to the migration role';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_language WHERE lanname = 'plpgsql'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname = 'uuid_public_identity_guard_v1'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'UUID guard language or function precondition failed';
    END IF;

    relation_oid := pg_catalog.to_regclass(
        pg_catalog.format('public.%I', target)
    );
    IF relation_oid IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class AS c
        WHERE c.oid = relation_oid AND c.relkind = 'r'
          AND c.relpersistence = 'p'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_inherits
        WHERE inhrelid = relation_oid OR inhparent = relation_oid
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'UUID expand requires plain permanent non-inherited tables';
    END IF;

    SELECT a.attnum INTO id_attnum
    FROM pg_catalog.pg_attribute AS a
    WHERE a.attrelid = relation_oid AND a.attname = 'id'
      AND NOT a.attisdropped AND a.attnotnull
      AND a.atttypid = 'pg_catalog.int4'::pg_catalog.regtype;
    IF id_attnum IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint AS c
        WHERE c.conrelid = relation_oid AND c.contype = 'p'
          AND c.conkey = ARRAY[id_attnum]::pg_catalog.int2[]
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'UUID expand requires the existing single integer primary key';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute
        WHERE attrelid = relation_oid AND attname = 'public_id'
          AND NOT attisdropped
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid = relation_oid
          AND conname = 'ck_' || target || '_public_id_v4'
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger
        WHERE tgrelid = relation_oid AND tgname IN (
            'trg_' || target || '_public_id_insert',
            'trg_' || target || '_public_id_immutable'
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'UUID expand objects already exist; review partial or prior application';
    END IF;

    -- A later BEFORE INSERT trigger could erase the allocated UUID while
    -- the transitional CHECK still permits NULL. Require explicit review.
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger
        WHERE tgrelid = relation_oid AND NOT tgisinternal
          AND (tgtype & 2) = 2 AND (tgtype & 4) = 4
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_rewrite
        WHERE ev_class = relation_oid AND ev_type <> '1'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'Existing INSERT triggers or write rules require identity review';
    END IF;
END;
$uuid_expand_preflight$;
"""

_GUARD_FUNCTION_SQL = """
CREATE FUNCTION public.uuid_public_identity_guard_v1()
RETURNS pg_catalog.trigger
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $uuid_public_identity_guard$
BEGIN
    IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME NOT IN (
        'tenants', 'projects', 'products', 'logical_sbom',
        'sbom_source', 'sbom_component'
    ) OR TG_LEVEL <> 'ROW' OR TG_NARGS <> 0 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'Unsupported public identity guard invocation';
    END IF;

    IF TG_OP = 'INSERT' AND TG_WHEN = 'BEFORE' THEN
        IF NEW.public_id IS NULL THEN
            NEW.public_id := pg_catalog.gen_random_uuid();
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' AND TG_WHEN = 'AFTER' THEN
        IF OLD.public_id IS NOT NULL
           AND NEW.public_id IS DISTINCT FROM OLD.public_id THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'Public identity cannot be changed';
        END IF;
        -- First NULL-to-UUID assignment is allowed; the CHECK enforces v4.
        -- An AFTER trigger return value is ignored; never rewrite the row.
        RETURN NULL;
    END IF;

    RAISE EXCEPTION USING ERRCODE = '55000',
        MESSAGE = 'Unsupported public identity guard event';
END;
$uuid_public_identity_guard$;
"""


def upgrade():
    context = op.get_context()
    if context.as_sql or context.dialect.name != "postgresql":
        raise RuntimeError("Staged UUID expand requires an approved online PostgreSQL transaction")
    bind = op.get_bind()
    driver = bind.connection.driver_connection
    if (
        not context.impl.transactional_ddl
        or not bind.in_transaction()
        or bind.get_execution_options().get("isolation_level") == "AUTOCOMMIT"
        or getattr(driver, "autocommit", None) is not False
    ):
        raise RuntimeError("UUID expand refuses non-transactional execution")

    # The runner must commit this single revision before invoking the next.
    # No internal commit/autocommit: DDL and Alembic version advance stay atomic.
    op.execute(_TIMEOUT_SQL)
    qualified = f'"{_SCHEMA}"."{_TABLE}"'
    op.execute(f"LOCK TABLE ONLY {qualified} IN ACCESS EXCLUSIVE MODE NOWAIT")
    op.execute(_PREFLIGHT_SQL)
    op.execute(_GUARD_FUNCTION_SQL)
    op.add_column(
        _TABLE,
        sa.Column("public_id", postgresql.UUID(as_uuid=True), nullable=True),
        schema=_SCHEMA,
    )
    # Separate SET DEFAULT affects future inserts, not legacy rows.
    op.execute(f"ALTER TABLE {qualified} ALTER COLUMN public_id SET DEFAULT pg_catalog.gen_random_uuid()")
    op.execute(
        f'ALTER TABLE {qualified} ADD CONSTRAINT "ck_{_TABLE}_public_id_v4" '
        f"CHECK (public_id IS NULL OR public_id::pg_catalog.text "
        f"OPERATOR(pg_catalog.~) '{_V4_PATTERN}') NOT VALID"
    )
    op.execute(
        f'CREATE TRIGGER "trg_{_TABLE}_public_id_insert" '
        f"BEFORE INSERT ON {qualified} FOR EACH ROW "
        "EXECUTE FUNCTION public.uuid_public_identity_guard_v1()"
    )
    # WHEN sees the final NEW after every BEFORE UPDATE trigger; never UPDATE OF.
    op.execute(
        f'CREATE TRIGGER "trg_{_TABLE}_public_id_immutable" '
        f"AFTER UPDATE ON {qualified} FOR EACH ROW "
        "WHEN (OLD.public_id IS DISTINCT FROM NEW.public_id) "
        "EXECUTE FUNCTION public.uuid_public_identity_guard_v1()"
    )


def downgrade():
    raise RuntimeError(
        "UUID expand downgrade is blocked: retain issued mappings and obtain "
        "a separately reviewed mapping-preserving rollback procedure"
    )
