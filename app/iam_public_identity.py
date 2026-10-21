"""Independent IAM UUID database guards; six-resource revision 100 is frozen."""

from sqlalchemy import text

GUARD_SQL = """
CREATE FUNCTION public.iam_user_public_identity_guard_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $guard$
BEGIN
 IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'iam_users'
    OR TG_LEVEL <> 'ROW' OR TG_NARGS <> 0 THEN
   RAISE EXCEPTION 'Unsupported IAM public identity guard context' USING ERRCODE='55000';
 END IF;
 IF TG_OP = 'INSERT' AND TG_WHEN = 'BEFORE' THEN
   IF NEW.public_id IS NULL THEN NEW.public_id := pg_catalog.gen_random_uuid(); END IF;
   RETURN NEW;
 ELSIF TG_OP = 'UPDATE' AND TG_WHEN = 'AFTER' THEN
   IF NEW.public_id IS DISTINCT FROM OLD.public_id THEN
     RAISE EXCEPTION 'IAM public identity is immutable' USING ERRCODE='23514';
   END IF;
   RETURN NULL;
 END IF;
 RAISE EXCEPTION 'Unsupported IAM public identity guard operation' USING ERRCODE='55000';
END
$guard$
"""
CHECK_SQL = "substring(public_id::text,15,1) = '4' AND substring(public_id::text,20,1) IN ('8','9','a','b')"


def install_iam_guards(connection):
    """Install on new metadata-created schema; never replace an existing guard."""
    connection.execute(text(GUARD_SQL))
    connection.exec_driver_sql(
        "ALTER TABLE public.iam_users ADD CONSTRAINT ck_iam_users_public_id_v4 CHECK (" + CHECK_SQL + ")"
    )
    connection.exec_driver_sql(
        "CREATE TRIGGER trg_iam_users_public_id_allocate BEFORE INSERT ON public.iam_users "
        "FOR EACH ROW EXECUTE FUNCTION public.iam_user_public_identity_guard_v1()"
    )
    connection.exec_driver_sql(
        "CREATE TRIGGER trg_iam_users_public_id_immutable AFTER UPDATE ON public.iam_users "
        "FOR EACH ROW WHEN (OLD.public_id IS DISTINCT FROM NEW.public_id) "
        "EXECUTE FUNCTION public.iam_user_public_identity_guard_v1()"
    )
    connection.exec_driver_sql("REVOKE ALL ON FUNCTION public.iam_user_public_identity_guard_v1() FROM PUBLIC")
