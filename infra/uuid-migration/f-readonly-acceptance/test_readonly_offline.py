"""Synthetic-only F acceptance regression suite; never use the real credential."""

from __future__ import annotations

import copy
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

import catalog as cat
import entry
import probe as pr
import runtime as rt

import security as sec

BOOT = cat.BOOT


def observations():
    data = {k: [] for k in cat.QUERIES}
    data["identity"] = [
        {
            "database": "uuid_w2_f_fresh",
            "current_user": BOOT,
            "session_user": BOOT,
            "database_oid": 12345,
            "system_identifier": "9000000000000000001",
            "server_version_num": 160015,
            "server_version": "16.15 (SYNTHETIC)",
            "transaction_read_only": "on",
            "recovery": False,
            "server_ip": "172.22.0.2",
            "server_port": 5432,
            "data_directory": "/var/lib/postgresql/data",
            "postmaster_start": "SYNTHETIC",
            "replication": "origin",
            "row_security": "on",
            "search_path": "pg_catalog",
        }
    ]
    data["ownership_acl"] = [
        {
            "oid": 12345,
            "datname": "uuid_w2_f_fresh",
            "owner": BOOT,
            "default_acl": True,
            "datistemplate": False,
            "datallowconn": True,
            "datconnlimit": -1,
            "encoding": "UTF8",
            "datcollate": "SYNTHETIC_UTF8",
            "datctype": "SYNTHETIC_UTF8",
            "datlocprovider": "c",
            "datcollversion": None,
        }
    ]
    data["schemas"] = [
        {
            "nspname": n,
            "owner": "pg_database_owner" if n == "public" else BOOT,
            "acl": None if n == "pg_toast" else "{" + owner + "=UC/" + owner + ",=U/" + owner + "}",
        }
        for n in ("public", "pg_catalog", "information_schema", "pg_toast")
        for owner in ["pg_database_owner" if n == "public" else BOOT]
    ]
    data["schema_privileges"] = [
        {
            "nspname": name,
            "owner": owner,
            "grantee": grantee,
            "grantor": owner,
            "privilege_type": priv,
            "is_grantable": False,
        }
        for name, owner, grantee, priv in [
            ("public", "pg_database_owner", "pg_database_owner", "CREATE"),
            ("public", "pg_database_owner", "pg_database_owner", "USAGE"),
            ("public", "pg_database_owner", "PUBLIC", "USAGE"),
            ("pg_catalog", BOOT, BOOT, "CREATE"),
            ("pg_catalog", BOOT, BOOT, "USAGE"),
            ("pg_catalog", BOOT, "PUBLIC", "USAGE"),
            ("information_schema", BOOT, BOOT, "CREATE"),
            ("information_schema", BOOT, BOOT, "USAGE"),
            ("information_schema", BOOT, "PUBLIC", "USAGE"),
            ("pg_toast", BOOT, BOOT, "CREATE"),
            ("pg_toast", BOOT, BOOT, "USAGE"),
        ]
    ]
    data["roles"] = []
    for i, name in enumerate(sorted(cat.BUILTINS | {BOOT}), 1):
        yes = name == BOOT
        data["roles"].append(
            {
                "oid": i,
                "rolname": name,
                "rolsuper": yes,
                "rolinherit": True,
                "rolcreaterole": yes,
                "rolcreatedb": yes,
                "rolcanlogin": yes,
                "rolreplication": yes,
                "rolbypassrls": yes,
                "rolconnlimit": -1,
                "config_null": True,
                "password_null": not yes,
                "password_scram": yes,
            }
        )
    data["memberships"] = [
        {
            "role": r,
            "member": "pg_monitor",
            "grantor": BOOT,
            "admin_option": False,
            "inherit_option": True,
            "set_option": True,
        }
        for r in ("pg_read_all_settings", "pg_read_all_stats", "pg_stat_scan_tables")
    ]
    data["extensions"] = [{"extname": "plpgsql", "extversion": "1.0", "schema": "pg_catalog", "owner": BOOT}]
    data["plpgsql_functions"] = [
        {
            "proname": name,
            "arguments": args,
            "result": ret,
            "nspname": "pg_catalog",
            "owner": BOOT,
            "lanname": "c",
            "prosecdef": False,
            "proleakproof": False,
            "proconfig": None,
            "default_acl": True,
        }
        for name, args, ret in [
            ("plpgsql_call_handler", "", "language_handler"),
            ("plpgsql_inline_handler", "internal", "void"),
            ("plpgsql_validator", "oid", "void"),
        ]
    ]
    data["privileges"] = [
        dict.fromkeys(
            (
                "connect",
                "create_database_objects",
                "temporary",
                "public_usage",
                "public_create",
                "role_read",
                "control_read",
            ),
            True,
        )
    ]
    data["hba_file"] = [{"auth_method": "scram-sha-256", "parse_ok": True}]
    settings = {
        "statement_timeout": "2000",
        "lock_timeout": "250",
        "idle_in_transaction_session_timeout": "5000",
        "default_transaction_read_only": "on",
        "transaction_read_only": "on",
        "row_security": "on",
        "search_path": "pg_catalog",
        "check_function_bodies": "on",
        "password_encryption": "scram-sha-256",
        "ssl": "off",
        "listen_addresses": "*",
        "port": "5432",
        "max_connections": "12",
        "shared_buffers": "8192",
        "work_mem": "4096",
        "stats_fetch_consistency": "none",
    }
    data["settings"] = [{"name": k, "setting": v, "source": "SYNTHETIC"} for k, v in settings.items()]
    data["databases"] = [
        {"datname": n, "owner": BOOT, "datistemplate": n.startswith("template"), "datallowconn": n != "template0"}
        for n in ("postgres", "template0", "template1", "uuid_w2_f_fresh")
    ]
    data["tablespaces"] = [
        {"spcname": n, "owner": BOOT, "default_acl": True, "location": ""} for n in ("pg_default", "pg_global")
    ]
    data["alembic"] = [{"relation": None}]
    return data


def plan():
    now = datetime.now(UTC)
    return {
        "schema": "w24e-f-readonly-v1",
        "accepted": False,
        "repository": str(sec.ROOT),
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "target": dict(sec.TARGET),
        "budgets": dict(sec.LIMITS),
        "sources": sec.source_bundle(),
        "infrastructure_reference": {"path": "/SYNTHETIC/infrastructure-baseline.json", "sha256": "a" * 64},
        "credential_metadata": {"path": sec.SECRET},
        "historical_evidence": copy.deepcopy(sec.HISTORICAL),
        "sql_sha256": dict(cat.SQL_PINS),
        "unknown_database_identity": dict.fromkeys(
            ("system_identifier", "database_oid", "authenticated_version", "catalog_fingerprint", "alembic_marker")
        ),
        "operator": dict.fromkeys(sec.REVIEWS, False),
        "approvals": {},
        "integrity_attestations": [False] * 7,
        "integrity_approvals": {},
        "review_observations": {},
    }


class Raw:
    def __init__(self, data=None):
        self.data = data or observations()
        self.autocommit = True
        self.closed = False
        self.pgconn = NS(used_password=True)
        self.info = NS(transaction_status=NS(name="IDLE"))
        self.calls = []
        self.fail_key = None
        self.fail_rollback = False
        self.fail_close = False
        self.fail_begin = False
        self.rows_override = None

    def cursor(self):
        return Cursor(self)

    def close(self):
        if self.fail_close:
            raise OSError("synthetic close failed")
        self.closed = True


class Cursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = []
        self.rows = []

    def execute(self, sql):
        c = self.conn
        c.calls.append(sql)
        if sql == "BEGIN READ ONLY":
            c.info.transaction_status.name = "INTRANS"
            if c.fail_begin:
                raise ValueError("synthetic BEGIN acknowledgment failed")
            return
        if sql == "ROLLBACK":
            if c.fail_rollback:
                raise ValueError("synthetic rollback failed")
            c.info.transaction_status.name = "IDLE"
            return
        key = next(k for k, v in cat.QUERIES.items() if v == sql)
        if c.fail_key == key:
            c.info.transaction_status.name = "INERROR"
            raise PermissionError("synthetic query permission denied")
        rows = c.rows_override if c.rows_override is not None else c.data[key]
        self.rows = copy.deepcopy(rows)
        cols = list(rows[0]) if rows else []
        self.description = [NS(name=name) for name in cols]
        self.rows = [tuple(row[n] for n in cols) for row in self.rows]

    def fetchmany(self, n):
        return self.rows[:n]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


def fixture():
    raw = Raw()
    authority = Mock()
    authority.expected = "a" * 64
    authority.plan = plan()
    journal = Mock()
    connector = Mock(return_value=raw)
    secret = bytearray(b"SYNTHETIC_F_CREDENTIAL")
    snapshot = Mock(return_value={"SYNTHETIC": "METADATA"})
    verify = Mock(return_value="172.22.0.2")
    p = pr.Probe(
        authority,
        pr.Budget(),
        journal,
        snapshot=snapshot,
        verify_resources=verify,
        correlate=Mock(return_value=secret),
        connector=connector,
        dependencies=Mock(),
    )
    return NS(
        raw=raw,
        authority=authority,
        journal=journal,
        connector=connector,
        dependencies=Mock(),
        secret=secret,
        p=p,
        snapshot=snapshot,
        verify=verify,
    )


class ProbeTests(unittest.TestCase):
    def test_success_one_connection_33_queries_two_controls(self):
        f = fixture()
        result = f.p.run({"SYNTHETIC": "BASELINE"})
        self.assertTrue(result["accepted"])
        f.connector.assert_called_once()
        self.assertEqual(result["queries"], len(cat.QUERIES) + 3)
        self.assertEqual(result["controls"], 2)
        self.assertTrue(result["closed"])
        self.assertTrue(result["rollback_ack"])
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)
        self.assertEqual(f.secret, bytearray(len(f.secret)))
        kwargs = f.connector.call_args.kwargs
        self.assertEqual({k: kwargs[k] for k in sec.TARGET}, sec.TARGET)
        self.assertNotIn("service", kwargs)
        self.assertEqual(kwargs["passfile"], "/dev/null")

    def test_failed_auth_no_retry_no_queries(self):
        f = fixture()
        f.connector.side_effect = ValueError("password=synthetic")
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertEqual(result["queries"], 0)
        f.connector.assert_called_once()
        self.assertFalse(result["closed"])

    def test_no_password_use_never_accepted(self):
        f = fixture()
        f.raw.pgconn.used_password = False
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertEqual(result["queries"], 0)
        self.assertTrue(f.raw.closed)

    def test_privilege_query_failure_rolls_back_and_closes(self):
        f = fixture()
        f.raw.fail_key = "roles"
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertTrue(result["rollback_ack"])
        self.assertTrue(result["closed"])

    def test_begin_ack_failure_still_rolls_back(self):
        f = fixture()
        f.raw.fail_begin = True
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)
        self.assertTrue(f.raw.closed)

    def test_rollback_failure_no_retry_still_close(self):
        f = fixture()
        f.raw.fail_rollback = True
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)
        self.assertTrue(result["closed"])

    def test_close_failure_not_accepted(self):
        f = fixture()
        f.raw.fail_close = True
        self.assertFalse(f.p.run({})["accepted"])

    def test_post_resource_drift_not_accepted(self):
        f = fixture()
        f.snapshot.side_effect = [{}, {}, ValueError("source resource drift")]
        self.assertFalse(f.p.run({})["accepted"])
        self.assertTrue(f.raw.closed)

    def test_pre_resource_drift_prevents_secret_and_connection(self):
        f = fixture()
        f.verify.side_effect = ValueError("wrong container")
        self.assertFalse(f.p.run({})["accepted"])
        f.connector.assert_not_called()
        f.p.correlate.assert_not_called()

    def test_last_moment_approval_substitution_prevents_connection(self):
        f = fixture()
        f.authority.recheck.side_effect = [None, None, ValueError("manifest changed")]
        self.assertFalse(f.p.run({})["accepted"])
        f.connector.assert_not_called()

    def test_secret_correlation_failure_no_connection(self):
        f = fixture()
        f.p.correlate.side_effect = ValueError("correlation failed")
        self.assertFalse(f.p.run({})["accepted"])
        f.connector.assert_not_called()

    def test_no_commit_or_noncatalog_sql(self):
        f = fixture()
        f.p.run({})
        self.assertTrue(all(s in cat.QUERIES.values() or s in {"BEGIN READ ONLY", "ROLLBACK"} for s in f.raw.calls))
        self.assertNotIn("COMMIT", f.raw.calls)

    def test_budget_exhaustion_rolls_back_before_extra_query(self):
        f = fixture()
        f.p.budget.queries = sec.LIMITS["queries"] - 1
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertEqual(len([s for s in f.raw.calls if s in cat.QUERIES.values()]), 1)
        self.assertTrue(result["closed"])
        self.assertTrue(result["rollback_ack"])

    def test_unknown_sql_key_before_driver(self):
        f = fixture()
        with self.assertRaises(ValueError):
            f.p.query("DROP TABLE x")
        self.assertEqual(f.raw.calls, [])

    def test_modified_sql_hash_refused(self):
        f = fixture()
        f.authority.plan["sql_sha256"]["identity"] = "b" * 64
        self.assertFalse(f.p.run({})["accepted"])
        self.assertEqual(f.raw.calls, ["BEGIN READ ONLY", "ROLLBACK"])

    def test_row_budget_rejection(self):
        f = fixture()
        f.raw.rows_override = [{"a": 1}] * (sec.LIMITS["rows_per_query"] + 1)
        self.assertFalse(f.p.run({})["accepted"])
        self.assertTrue(f.raw.closed)

    def test_deadline_before_auth_prevents_connection(self):
        f = fixture()
        f.p.budget.started -= 61
        self.assertFalse(f.p.run({})["accepted"])
        f.connector.assert_not_called()

    def test_deadline_after_begin_still_cleanup(self):
        f = fixture()
        original = f.p.query

        def q(key):
            result = original(key)
            f.p.budget.started -= 61
            return result

        f.p.query = q
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertTrue(result["rollback_ack"])

    def test_evidence_failure_still_cleanup(self):
        f = fixture()

        def record(event, **_):
            if event == "CATALOG":
                raise OSError("disk failure")

        f.journal.record.side_effect = record
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertTrue(f.raw.closed)

    def test_cleanup_rollback_survives_evidence_failure(self):
        f = fixture()
        f.raw.fail_key = "roles"

        def record(event, **fields):
            if fields.get("control") == "ROLLBACK":
                raise OSError("disk failure")

        f.journal.record.side_effect = record
        self.assertTrue(f.p.run({})["rollback_ack"])


class CatalogTests(unittest.TestCase):
    def test_complete_fresh_synthetic_catalog(self):
        value = cat.validate(observations(), "172.22.0.2", True)
        self.assertTrue(value["catalog_fresh"])
        self.assertEqual(value["loaded_hba_rules"], "NOT_PROVEN")

    def test_required_role_is_privileged_and_runtime_role_needed(self):
        self.assertEqual(
            cat.validate(observations(), "172.22.0.2", True)["restricted_runtime_role"],
            "NEEDED_BEFORE_APPLICATION_USE_NOT_CREATED",
        )

    def test_password_presence_not_authentication_proof(self):
        with self.assertRaises(ValueError):
            cat.validate(observations(), "172.22.0.2", False)

    def test_no_password_hash_or_hba_options_in_sql(self):
        self.assertNotIn("SELECT rolpassword", "\n".join(cat.QUERIES.values()))
        self.assertNotIn("subconninfo", "\n".join(cat.QUERIES.values()))
        self.assertIn("error IS NULL AS parse_ok", cat.QUERIES["hba_file"])

    def test_missing_catalog_category_rejected(self):
        data = observations()
        del data["types"]
        with self.assertRaises(ValueError):
            cat.validate(data, "172.22.0.2", True)


def occupied_test(key):
    def test(self):
        data = observations()
        data[key] = [{"unexpected": "SYNTHETIC"}]
        with self.assertRaises(ValueError):
            cat.validate(data, "172.22.0.2", True)

    return test


for key in cat.EMPTY:
    setattr(CatalogTests, "test_occupied_" + key, occupied_test(key))


def identity_test(key, value):
    def test(self):
        data = observations()
        data["identity"][0][key] = value
        with self.assertRaises(ValueError):
            cat.validate(data, "172.22.0.2", True)

    return test


for key, value in {
    "database": "uuid_w1_d_rehearsal",
    "current_user": "postgres",
    "session_user": "postgres",
    "server_version_num": 160014,
    "transaction_read_only": "off",
    "recovery": True,
    "server_ip": "172.22.0.99",
    "server_port": 56043,
    "data_directory": "/other",
    "system_identifier": "7697252084555804711",
    "row_security": "off",
    "search_path": "public",
    "database_oid": None,
}.items():
    setattr(CatalogTests, "test_wrong_identity_" + key, identity_test(key, value))


def security_test(category, key, value):
    def test(self):
        data = observations()
        data[category][0][key] = value
        with self.assertRaises(ValueError):
            cat.validate(data, "172.22.0.2", True)

    return test


for i, (category, key, value) in enumerate(
    [
        ("extensions", "owner", "other"),
        ("extensions", "extname", "pgcrypto"),
        ("roles", "rolsuper", True),
        ("memberships", "admin_option", True),
        ("ownership_acl", "default_acl", False),
        ("ownership_acl", "encoding", "LATIN1"),
        ("plpgsql_functions", "prosecdef", True),
        ("schema_privileges", "is_grantable", True),
        ("hba_file", "auth_method", "trust"),
        ("hba_file", "parse_ok", False),
        ("privileges", "role_read", False),
        ("tablespaces", "location", "/other"),
        ("databases", "owner", "other"),
    ]
):
    setattr(CatalogTests, "test_security_" + str(i), security_test(category, key, value))


class AuthorityTests(unittest.TestCase):
    def test_pending_manifest_not_live_authority(self):
        p = plan()
        sec.validate(p, sql_pins=cat.SQL_PINS)
        with self.assertRaises(ValueError):
            sec.validate(p, live=True, reference="W24E-F-READONLY-SYNTHETIC", sql_pins=cat.SQL_PINS)

    def test_no_old_action_approval_transfer(self):
        p = plan()
        p["operator"] = dict.fromkeys(sec.REVIEWS, True)
        p["approvals"] = {"read_only_execute": "W17B2-E-BASELINE-EXECUTE-20261018"}
        with self.assertRaises(ValueError):
            sec.validate(p, live=True, reference=p["approvals"]["read_only_execute"], sql_pins=cat.SQL_PINS)

    def test_expired(self):
        p = plan()
        p["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        with self.assertRaises(ValueError):
            sec.validate(p, sql_pins=cat.SQL_PINS)

    def test_wrong_sql_pin(self):
        p = plan()
        p["sql_sha256"]["roles"] = "b" * 64
        with self.assertRaises(ValueError):
            sec.validate(p, sql_pins=cat.SQL_PINS)

    def test_changed_source(self):
        p = plan()
        p["sources"]["entry.py"] = "b" * 64
        with self.assertRaises(ValueError):
            sec.validate(p, sql_pins=cat.SQL_PINS)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):
            sec.unique(b'{"x":1,"x":2}')

    def test_wrong_budget(self):
        p = plan()
        p["budgets"]["queries"] = 1024
        with self.assertRaises(ValueError):
            sec.validate(p, sql_pins=cat.SQL_PINS)

    def test_missing_raw_hash_before_runtime(self):
        with patch.object(Path, "lstat", side_effect=AssertionError("must not access")):
            with self.assertRaises(ValueError):
                sec.private_bytes("/unused", None)

    def test_raw_whitespace_hash_not_canonical(self):
        self.assertNotEqual(sec.sha(b'{"a":1}'), sec.sha(b'{ "a":1 }'))

    def test_private_file_raw_hash_and_replacement(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t).resolve()
            d.chmod(0o700)
            p = d / "manifest.json"
            p.write_bytes(b'{"a":1}')
            p.chmod(0o600)
            expected = sec.sha(p.read_bytes())
            self.assertEqual(sec.private_bytes(p, expected), b'{"a":1}')
            p.write_bytes(b'{ "a":1 }')
            with self.assertRaises(ValueError):
                sec.private_bytes(p, expected)

    def test_symlink_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t).resolve()
            p = d / "original"
            p.write_bytes(b"{}")
            p.chmod(0o600)
            link = d / "manifest"
            link.symlink_to(p)
            with self.assertRaises(ValueError):
                sec.private_bytes(link, sec.sha(b"{}"))

    def test_wrong_private_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t).resolve()
            p = d / "manifest"
            p.write_bytes(b"{}")
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                sec.private_bytes(p, sec.sha(b"{}"))

    def test_ambient_overrides_rejected(self):
        for key in (
            "PGHOST",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGSYSCONFDIR",
            "PGPORT",
            "PGDATABASE",
            "PGUSER",
            "PGPASSWORD",
            "PGPASSFILE",
            "PGOPTIONS",
            "DATABASE_URL",
            "PYTHONPATH",
            "DOCKER_HOST",
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                sec.clean_environment({key: "SYNTHETIC"})

    def test_last_moment_original_manifest_revalidation(self):
        p = plan()
        p["operator"] = dict.fromkeys(sec.REVIEWS, True)
        ref = "W24E-F-READONLY-SYNTHETIC"
        p["approvals"] = {"read_only_execute": ref}
        with tempfile.TemporaryDirectory() as t:
            d = Path(t).resolve()
            d.chmod(0o700)
            f = d / "approved.json"
            f.write_text(json.dumps(p))
            f.chmod(0o600)
            a = sec.Authority(f, sec.sha(f.read_bytes()), ref, cat.SQL_PINS)
            a.recheck()
            changed = copy.deepcopy(p)
            changed["target"]["port"] = 56042
            f.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                a.recheck()


def target_test(key, value):
    def test(self):
        p = plan()
        p["target"][key] = value
        with self.assertRaises(ValueError):
            sec.validate(p, sql_pins=cat.SQL_PINS)

    return test


for key, value in [
    ("host", "localhost"),
    ("hostaddr", "::1"),
    ("port", 56041),
    ("dbname", "uuid_w17_e_integrity"),
    ("user", "postgres"),
]:
    setattr(AuthorityTests, "test_target_" + key, target_test(key, value))


class BoundaryTests(unittest.TestCase):
    def test_live_missing_approval_never_runtime(self):
        with patch.dict("sys.modules", {"psycopg": None}):
            with self.assertRaises(ValueError):
                entry.main(["--mode", "live"])

    def test_offline_no_runtime_or_driver(self):
        with patch.dict("sys.modules", {"psycopg": None, "runtime": None}), redirect_stdout(io.StringIO()):
            self.assertEqual(entry.main(["--mode", "offline"]), 0)

    def test_error_sanitization_with_server_sqlstate(self):
        e = ValueError("postgresql://user:SECRET@127.0.0.1/db password=SECRET")
        e.sqlstate = "28P01"
        e.diag = NS(message_primary=None)
        value = sec.safe_error(e, b"SECRET")
        self.assertEqual(value["sqlstate"], "28P01")
        self.assertNotIn("SECRET", value["primary"])

    def test_scram_diagnostic_redacted(self):
        self.assertEqual(sec.safe_error(ValueError("SCRAM-SHA-256$abcdef"))["primary"], "UNCLASSIFIED_REDACTED")

    def test_output_bounded_controls_removed(self):
        result = sec.safe_error(ValueError("\x00\n" + "x" * 1000))
        self.assertLessEqual(len(result["primary"]), 256)
        self.assertNotIn("\n", result["primary"])

    def test_evidence_claim_no_reuse(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t).resolve()
            d.chmod(0o700)
            p = d / "attempt.jsonl"
            e = pr.Evidence(p)
            e.close()
            with self.assertRaises(ValueError):
                pr.Evidence(p)

    def test_ddl_control_rejected(self):
        with self.assertRaises(ValueError):
            fixture().p.control("CREATE TABLE x(id int)")

    def test_transaction_control_budget(self):
        b = pr.Budget()
        b.reserve("controls")
        b.reserve("controls")
        with self.assertRaises(ValueError):
            b.reserve("controls")

    def test_one_attempt_budget(self):
        b = pr.Budget()
        b.reserve("attempts")
        with self.assertRaises(ValueError):
            b.reserve("attempts")

    def test_no_migration_or_application_imports(self):
        import ast

        folder = Path(__file__).parent
        for p in folder.glob("*.py"):
            tree = ast.parse(p.read_bytes())
            for n in ast.walk(tree):
                if isinstance(n, ast.Import):
                    self.assertFalse(any(i.name.startswith(("app", "alembic", "dotenv")) for i in n.names))
                if isinstance(n, ast.ImportFrom):
                    self.assertFalse((n.module or "").startswith(("app", "alembic", "dotenv")))


# Synthetic metadata only; no current Docker or credential reads in this suite.
def resource_fixture():
    secret = {"Type": "bind", "Source": sec.SECRET, "Destination": "/run/secrets/f_password", "RW": False}
    data = {"Type": "volume", "Name": rt.VOLUME, "Destination": "/var/lib/postgresql/data", "RW": True}
    c = {
        "Id": rt.CONTAINER,
        "Image": rt.IMAGE,
        "State": {"Running": True},
        "Health": "healthy",
        "RestartCount": 0,
        "Labels": {"com.docker.compose.project": "sbom-uuid-w2-f", "com.docker.compose.service": "postgres_f"},
        "Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56043"}]},
        "Networks": {rt.NETWORK: {"NetworkID": rt.NETWORK_ID, "IPAddress": "172.22.0.2"}},
        "HostConfig": {
            "NanoCpus": 1000000000,
            "Memory": 536870912,
            "ShmSize": 67108864,
            "PidsLimit": 128,
            "RestartPolicy": {"Name": "no"},
            "Privileged": False,
        },
        "Mounts": [secret, data],
    }
    n = {
        "Id": rt.NETWORK_ID,
        "Name": rt.NETWORK,
        "Driver": "bridge",
        "Internal": False,
        "EnableIPv4": True,
        "EnableIPv6": False,
        "Containers": {rt.CONTAINER: {}},
        "Options": {
            "com.docker.network.bridge.enable_icc": "false",
            "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
            "com.docker.network.enable_ipv4": "true",
            "com.docker.network.enable_ipv6": "false",
        },
    }
    return {
        "daemon": {"ID": rt.DAEMON, "OperatingSystem": "Docker Desktop", "socket": rt.SOCKET},
        "containers": [c],
        "networks": [n],
        "volumes": [{"Name": rt.VOLUME, "Driver": "local"}],
        "image_id": rt.IMAGE,
        "credential": {"synthetic": "metadata"},
    }


class ResourceTests(unittest.TestCase):
    def test_fixed_resource_gate_accepts_synthetic_metadata(self):
        data = resource_fixture()
        self.assertEqual(rt.verify_resources(data, data), "172.22.0.2")

    def test_no_docker_mutation_method(self):
        docker = rt.Docker(lambda: None, {})
        for args in (
            ["network", "rm", rt.NETWORK],
            ["volume", "rm", rt.VOLUME],
            ["exec", rt.CONTAINER, "psql"],
            ["restart", rt.CONTAINER],
            ["compose", "up"],
            ["system", "prune"],
            ["image", "pull", "postgres:16"],
        ):
            with patch.object(rt.subprocess, "run", side_effect=AssertionError("must not invoke")):
                with self.assertRaises(ValueError):
                    docker.metadata(args)

    def test_no_extra_network_option(self):
        data = resource_fixture()
        data["networks"][0]["Options"]["unexpected"] = "true"
        with self.assertRaises(ValueError):
            rt.verify_resources(data, data)

    def test_no_shared_volume(self):
        data = resource_fixture()
        extra = copy.deepcopy(data["containers"][0])
        extra["Id"] = "other"
        data["containers"].append(extra)
        with self.assertRaises(ValueError):
            rt.verify_resources(data, data)

    def test_docker_command_deadline_checked_before_execution(self):
        docker = rt.Docker(Mock(side_effect=ValueError("expired")), {})
        with patch.object(rt.subprocess, "run", side_effect=AssertionError("must not invoke")):
            with self.assertRaises(ValueError):
                docker.metadata(["ps", "-aq", "--no-trunc"])


def resource_mutation(name, change):
    def test(self):
        data = resource_fixture()
        change(data)
        with self.assertRaises(ValueError):
            rt.verify_resources(data, data)

    return test


for label, change in [
    ("daemon", lambda x: x["daemon"].update(ID="other")),
    ("socket", lambda x: x["daemon"].update(socket="tcp://remote")),
    ("container", lambda x: x["containers"][0].update(Id="other")),
    ("image", lambda x: x.update(image_id="other")),
    ("network", lambda x: x["networks"][0].update(Id="other")),
    ("volume", lambda x: x["volumes"][0].update(Name="other")),
    ("project", lambda x: x["containers"][0]["Labels"].update({"com.docker.compose.project": "other"})),
    ("service", lambda x: x["containers"][0]["Labels"].update({"com.docker.compose.service": "other"})),
    ("port", lambda x: x["containers"][0]["Ports"]["5432/tcp"][0].update(HostPort="56042")),
    ("publication", lambda x: x["containers"][0]["Ports"]["5432/tcp"][0].update(HostIp="0.0.0.0")),
    ("secret_readwrite", lambda x: x["containers"][0]["Mounts"][0].update(RW=True)),
    ("secret_source", lambda x: x["containers"][0]["Mounts"][0].update(Source="/other/password")),
    ("secret_destination", lambda x: x["containers"][0]["Mounts"][0].update(Destination="/other/password")),
    ("missing_mount", lambda x: x["containers"][0]["Mounts"].pop()),
    ("extra_mount", lambda x: x["containers"][0]["Mounts"].append({"Destination": "/other"})),
    ("memory", lambda x: x["containers"][0]["HostConfig"].update(Memory=1073741824)),
    ("stopped", lambda x: x["containers"][0]["State"].update(Running=False)),
    ("restart", lambda x: x["containers"][0].update(RestartCount=1)),
    ("health", lambda x: x["containers"][0].update(Health="unhealthy")),
]:
    setattr(ResourceTests, "test_wrong_" + label, resource_mutation(label, change))


class SecretProvenanceTests(unittest.TestCase):
    def fake_stat(self, mode, **changes):
        values = dict(
            st_mode=mode,
            st_uid=os.getuid(),
            st_gid=20,
            st_ino=12345,
            st_size=64,
            st_nlink=1,
            st_mtime_ns=123,
            st_ctime_ns=456,
        )
        values.update(changes)
        return NS(**values)

    def metadata_case(self, change=None):
        import stat

        p = Path(sec.SECRET)
        file = self.fake_stat(stat.S_IFREG | 0o600)
        parent = self.fake_stat(stat.S_IFDIR | 0o700)
        ancestors = [self.fake_stat(stat.S_IFDIR | 0o755) for _ in list(p.parents)[1:]]
        if change:
            change(file, parent)
        with patch.object(Path, "lstat", side_effect=[file, parent, *ancestors]):
            return sec.credential_metadata()

    def test_descriptor_metadata_synthetic(self):
        self.assertEqual(self.metadata_case()["inode"], 12345)

    def test_symlink_file(self):
        import stat

        with self.assertRaises(ValueError):
            self.metadata_case(lambda f, p: setattr(f, "st_mode", stat.S_IFLNK | 0o777))

    def test_hardlink_file(self):
        with self.assertRaises(ValueError):
            self.metadata_case(lambda f, p: setattr(f, "st_nlink", 2))

    def test_wrong_owner(self):
        with self.assertRaises(ValueError):
            self.metadata_case(lambda f, p: setattr(f, "st_uid", os.getuid() + 1))

    def test_wrong_file_mode(self):
        import stat

        with self.assertRaises(ValueError):
            self.metadata_case(lambda f, p: setattr(f, "st_mode", stat.S_IFREG | 0o644))

    def test_wrong_parent_mode(self):
        import stat

        with self.assertRaises(ValueError):
            self.metadata_case(lambda f, p: setattr(p, "st_mode", stat.S_IFDIR | 0o755))

    def test_replaced_credential_no_open(self):
        with (
            patch.object(rt, "credential_metadata", return_value={"inode": 2}),
            patch.object(rt.os, "open", side_effect=AssertionError("no open")),
        ):
            with self.assertRaises(ValueError):
                rt.correlate({"inode": 1}, Mock())

    def correlate_case(self, equal=True):
        import stat

        expected = {"inode": 12345, "uid": os.getuid(), "size": 64, "mtime_ns": 123, "ctime_ns": 456}
        fake = self.fake_stat(stat.S_IFREG | 0o600)
        host = b"x" * 64
        mounted = bytearray(b"x" * 64 if equal else b"y" * 64)
        docker = Mock()
        docker.mounted_secret.return_value = mounted
        with (
            patch.object(rt, "credential_metadata", return_value=expected),
            patch.object(rt.os, "open", return_value=5),
            patch.object(rt.os, "fstat", return_value=fake),
            patch.object(rt.os, "read", return_value=host),
            patch.object(rt.os, "close"),
        ):
            result = rt.correlate(expected, docker)
        self.assertEqual(mounted, bytearray(64))
        return result

    def test_secret_bytes_only_in_memory_and_mounted_erased(self):
        self.assertEqual(self.correlate_case(), bytearray(b"x" * 64))

    def test_secret_mismatch_refuses(self):
        with self.assertRaises(ValueError):
            self.correlate_case(False)


class FinalControlTests(unittest.TestCase):
    def test_rollback_intent_evidence_failure_does_not_consume_cleanup_slot(self):
        f = fixture()

        def record(event, **fields):
            if fields.get("control") == "ROLLBACK":
                raise OSError("durable log unavailable")

        f.journal.record.side_effect = record
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertTrue(result["rollback_ack"])
        self.assertEqual(f.raw.calls.count("ROLLBACK"), 1)
        self.assertEqual(result["controls"], 2)

    def test_dependencies_rechecked_before_authentication(self):
        f = fixture()
        f.p.dependencies.side_effect = ValueError("native package changed")
        self.assertFalse(f.p.run({})["accepted"])
        f.connector.assert_not_called()

    def test_simultaneous_single_connection_and_no_prepared_maintenance(self):
        f = fixture()
        f.p.run({})
        self.assertEqual(f.connector.call_count, 1)
        self.assertEqual(sec.LIMITS["simultaneous_connections"], 1)
        self.assertIsNone(f.connector.call_args.kwargs["prepare_threshold"])

    def test_original_authority_invalid_hash_precedes_runtime_import(self):
        with patch.dict("sys.modules", {"runtime": None, "psycopg": None}):
            with self.assertRaises(ValueError):
                entry.main(
                    [
                        "--mode",
                        "live",
                        "--manifest",
                        "/SYNTHETIC/a.json",
                        "--manifest-sha256",
                        "bad",
                        "--approval-reference",
                        "W24E-F-READONLY-SYNTHETIC",
                    ]
                )

    def test_import_is_inert_under_io_guards(self):
        import builtins
        from types import ModuleType

        folder = Path(__file__).parent
        sources = {p.name: p.read_text() for p in folder.glob("*.py") if not p.name.startswith("test_")}
        with (
            patch.object(builtins, "open", side_effect=AssertionError("import opened a file")),
            patch.object(rt.subprocess, "run", side_effect=AssertionError("import ran a process")),
            patch.object(Path, "read_bytes", side_effect=AssertionError("import read a file")),
            patch.object(sec.os, "open", side_effect=AssertionError("import read a credential")),
        ):
            for name, source in sources.items():
                module = ModuleType("_offline_import_" + name)
                module.__file__ = str(folder / name)
                exec(compile(source, str(folder / name), "exec"), module.__dict__)

    def test_historical_reference_alteration_rejected(self):
        p = plan()
        p["historical_evidence"]["W24C"]["sha256"] = "b" * 64
        with self.assertRaises(ValueError):
            sec.validate(p, sql_pins=cat.SQL_PINS)

    def test_invented_e_actual_database_identity_rejected(self):
        p = plan()
        p["unknown_database_identity"]["system_identifier"] = "SYNTHETIC"
        with self.assertRaises(ValueError):
            sec.validate(p, sql_pins=cat.SQL_PINS)

    def test_integrity_or_role_approvals_forbidden(self):
        for approvals in ({"integrity_execute": "SYNTHETIC"}, {"role_create": "SYNTHETIC"}):
            p = plan()
            p["approvals"] = approvals
            with self.assertRaises(ValueError):
                sec.validate(p, sql_pins=cat.SQL_PINS)

    def test_changed_approval_fields_before_auth_refused(self):
        p = plan()
        p["operator"] = dict.fromkeys(sec.REVIEWS, True)
        ref = "W24E-F-READONLY-SYNTHETIC"
        p["approvals"] = {"read_only_execute": ref}
        with tempfile.TemporaryDirectory() as t:
            d = Path(t).resolve()
            d.chmod(0o700)
            f = d / "approved.json"
            f.write_text(json.dumps(p))
            f.chmod(0o600)
            a = sec.Authority(f, sec.sha(f.read_bytes()), ref, cat.SQL_PINS)
            a.plan["approvals"]["read_only_execute"] = "W24E-F-READONLY-CHANGED"
            with self.assertRaises(ValueError):
                a.recheck()

    def test_server_readonly_setting_drift_refuses(self):
        p = observations()
        next(row for row in p["settings"] if row["name"] == "transaction_read_only")["setting"] = "off"
        with self.assertRaises(ValueError):
            cat.validate(p, "172.22.0.2", True)

    def test_alembic_marker_state_refused_without_reading_rows(self):
        p = observations()
        p["alembic"] = [{"relation": "alembic_version"}]
        with self.assertRaises(ValueError):
            cat.validate(p, "172.22.0.2", True)
        self.assertNotIn("SELECT version_num", "\n".join(cat.QUERIES.values()))

    def test_installed_dependency_pins_without_connecting(self):
        with patch.dict("sys.modules", {"psycopg": None}):
            rt.verify_dependencies()

    def test_sql_sources_are_select_catalog_only(self):
        from sqlalchemy import text
        from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg

        for name, sql in cat.QUERIES.items():
            self.assertTrue(sql.startswith("SELECT "), name)
            self.assertEqual(sql.count(";"), 0)
            self.assertEqual(cat.SQL_PINS[name], sec.sha(sql.encode()))
            text(sql).compile(dialect=PGDialect_psycopg())


class ProjectedMetadataTests(unittest.TestCase):
    def test_raw_inspect_environment_output_refused(self):
        with patch.object(rt.subprocess, "run", side_effect=AssertionError("raw environment must not be read")):
            with self.assertRaises(ValueError):
                rt.Docker(lambda: None, {}).metadata(["inspect", rt.CONTAINER])

    def test_exact_server_side_projection_is_accepted(self):
        result = NS(returncode=0, stdout=b"{}")
        with patch.object(rt.subprocess, "run", return_value=result) as run:
            self.assertEqual(
                rt.Docker(lambda: None, {}).metadata(["inspect", "--format", rt.CONTAINER_FORMAT, rt.CONTAINER]), "{}"
            )
            self.assertIn(rt.CONTAINER_FORMAT, run.call_args.args[0])
        self.assertNotIn(".Config.Env", rt.CONTAINER_FORMAT)
        self.assertNotIn(".State.Health.Log", rt.CONTAINER_FORMAT)

    def test_modified_projection_is_refused(self):
        with patch.object(rt.subprocess, "run", side_effect=AssertionError("no command")):
            with self.assertRaises(ValueError):
                rt.Docker(lambda: None, {}).metadata(["inspect", "--format", "{{json .Config.Env}}", rt.CONTAINER])


class ActualAttemptEvidenceTests(unittest.TestCase):
    def test_durable_preconnect_failure_is_zero_actual_attempts(self):
        f = fixture()

        def record(event, **_):
            if event == "CONNECT_REQUESTED":
                raise OSError("durable evidence unavailable")

        f.journal.record.side_effect = record
        result = f.p.run({})
        self.assertFalse(result["accepted"])
        self.assertEqual(result["attempts"], 0)
        self.assertEqual(result["attempt_budget_reservations"], 1)
        f.connector.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
