"""Allow single-directory Microsoft Entra identities and local suspension."""
import sqlalchemy as sa
from alembic import op

revision = "063_microsoft_entra_identity"
down_revision = "062_native_platform_bootstrap"
branch_labels = None
depends_on = None


def _constraints(entra):
    providers = "'HCL_CS','NATIVE','MICROSOFT_ENTRA'" if entra else "'HCL_CS','NATIVE'"
    external = "provider_type IN ('HCL_CS','MICROSOFT_ENTRA')" if entra else "provider_type = 'HCL_CS'"
    statuses = "'ACTIVE','PENDING','DISABLED','PENDING_EMAIL_VERIFICATION','LOCKED','FORCE_PASSWORD_CHANGE'"
    if entra:
        statuses += ",'SUSPENDED'"
    for table, name, condition in (
        ("iam_users", "iam_user_status", f"status IN ({statuses})"),
        ("user_identities", "identity_provider", f"provider_type IN ({providers})"),
        ("user_identities", "identity_provider_fields",
         f"({external} AND issuer IS NOT NULL AND length(trim(issuer)) > 0 "
         "AND subject IS NOT NULL AND length(trim(subject)) > 0) OR "
         "(provider_type = 'NATIVE' AND issuer IS NULL AND subject IS NULL "
         "AND provider_identifier IS NOT NULL AND length(trim(provider_identifier)) > 0 "
         "AND provider_identifier = lower(trim(provider_identifier)))"),
    ):
        constraint = op.f(f"ck_{table}_{name}")
        op.drop_constraint(constraint, table, type_="check")
        op.create_check_constraint(constraint, table, condition)


def upgrade():
    _constraints(True)


def downgrade():
    connection = op.get_bind()
    if connection.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM user_identities WHERE provider_type = 'MICROSOFT_ENTRA')")) or connection.scalar(sa.text("SELECT EXISTS (SELECT 1 FROM iam_users WHERE status = 'SUSPENDED')")):
        raise RuntimeError("Cannot downgrade while Entra identities or suspended accounts exist")
    _constraints(False)
