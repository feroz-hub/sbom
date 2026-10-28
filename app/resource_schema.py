"""Fresh 100->101->102 installation without modifying either frozen revision."""

import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import MetaData, UniqueConstraint, text

from .resource_public_identity import TABLES

REVISION = "102_public_membership_grant_analysis_uuid"


def revision101_metadata(metadata):
    result = MetaData(naming_convention=metadata.naming_convention)
    for table in metadata.tables.values():
        table.to_metadata(result)
    for name in TABLES:
        table = result.tables[name]
        column = table.c.public_id
        for constraint in list(table.constraints):
            if isinstance(constraint, UniqueConstraint) and column.name in constraint.columns:
                table.constraints.remove(constraint)
        table._columns.remove(column)
    return result


def revision100_metadata(metadata):
    from .iam_schema import revision100_metadata as before_user_uuid

    return before_user_uuid(revision101_metadata(metadata))


def apply_resource_uuid_revision(connection):
    path = Path(__file__).resolve().parents[1] / "alembic/versions/102_public_membership_grant_analysis_uuid.py"
    spec = importlib.util.spec_from_file_location("_resource_uuid_revision", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with Operations.context(MigrationContext.configure(connection)):
        module.upgrade()
    result = connection.execute(
        text("UPDATE public.alembic_version SET version_num=:next WHERE version_num=:previous"),
        {"next": module.revision, "previous": module.down_revision},
    )
    if result.rowcount != 1:
        raise RuntimeError("Public resource UUID marker update failed")
