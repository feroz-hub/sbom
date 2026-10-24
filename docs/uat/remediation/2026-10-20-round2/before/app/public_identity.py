"""Final persisted public identities; integer relationship keys remain internal."""

from __future__ import annotations

import uuid

from sqlalchemy import Column, Uuid, text

TABLES = ("tenants", "projects", "products", "logical_sbom", "sbom_source", "sbom_component")


class PublicIdentityMixin:
    public_id = Column(
        Uuid(as_uuid=True), nullable=False, unique=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )


def install_guards(connection):
    """Install only on a new final schema, with validated checks and NOT NULL."""
    connection.exec_driver_sql("""
CREATE FUNCTION public.uuid_public_identity_guard_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $guard$
BEGIN
 IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME NOT IN
 ('tenants','projects','products','logical_sbom','sbom_source','sbom_component')
 OR TG_LEVEL <> 'ROW' OR TG_NARGS <> 0 THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Unsupported identity guard';
 END IF;
 IF TG_OP='INSERT' AND TG_WHEN='BEFORE' THEN
  IF NEW.public_id IS NULL THEN NEW.public_id := pg_catalog.gen_random_uuid(); END IF;
  RETURN NEW;
 ELSIF TG_OP='UPDATE' AND TG_WHEN='AFTER' THEN
  IF NEW.public_id IS DISTINCT FROM OLD.public_id THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='Public identity cannot be changed';
  END IF;
  RETURN NULL;
 END IF;
 RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Unsupported identity event';
END; $guard$""")
    for table in TABLES:
        connection.exec_driver_sql(f"""ALTER TABLE public.{table} ADD CONSTRAINT ck_{table}_public_id_v4
 CHECK (substring(public_id::text,15,1)='4' AND substring(public_id::text,20,1) IN ('8','9','a','b'))""")
        connection.exec_driver_sql(f"""CREATE TRIGGER trg_{table}_public_id_insert
 BEFORE INSERT ON public.{table} FOR EACH ROW EXECUTE FUNCTION public.uuid_public_identity_guard_v1()""")
        connection.exec_driver_sql(f"""CREATE TRIGGER trg_{table}_public_id_immutable
 AFTER UPDATE ON public.{table} FOR EACH ROW
 WHEN (OLD.public_id IS DISTINCT FROM NEW.public_id)
 EXECUTE FUNCTION public.uuid_public_identity_guard_v1()""")
