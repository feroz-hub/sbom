"""Ordered fresh installation support without changing frozen revision 100."""

import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import MetaData, UniqueConstraint, text


def revision100_metadata(metadata):
    """Independent copy of current metadata before the sole 101 column change."""
    baseline = MetaData(naming_convention=metadata.naming_convention)
    for table in metadata.tables.values():
        table.to_metadata(baseline)
    users = baseline.tables["iam_users"]
    column = users.c.public_id
    for constraint in list(users.constraints):
        if isinstance(constraint, UniqueConstraint) and column.name in constraint.columns:
            users.constraints.remove(constraint)
    users._columns.remove(column)
    return baseline


def apply_user_uuid_revision(connection):
    """101 body and marker update belong to the caller's owned transaction."""
    path = Path(__file__).resolve().parents[1] / "alembic/versions/101_iam_user_public_uuid.py"
    spec = importlib.util.spec_from_file_location("_iam_user_uuid_revision", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with Operations.context(MigrationContext.configure(connection)):
        module.upgrade()
    result = connection.execute(
        text("UPDATE public.alembic_version SET version_num=:next WHERE version_num=:previous"),
        {"next": module.revision, "previous": module.down_revision},
    )
    if result.rowcount != 1:
        raise RuntimeError("IAM UUID marker update failed")
