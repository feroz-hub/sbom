"""W2.4A offline mocks only. No real credential, Docker or database access."""

from __future__ import annotations

import ast
import copy
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import activation as act
import binding
import catalog
import resources
import transport as tr
from journal import Journal, safe_error
from reviewed import load

import security as sec

ROOT = Path(__file__).resolve().parents[3]
MODULES, REG = load(ROOT)
PARSER = MODULES["source_registry"].reference_api(ROOT, REG)["pg_lex"].statements
LIMITS = REG["units"][0]["budgets"]


def meter(sqls=(), **kw):
    allow = {k: [sec.sha(s.encode()) for s in sqls] for k in tr.CATEGORIES}
    return tr.Meter(copy.deepcopy(LIMITS), allow, PARSER, **kw)


def controlled(cursor, statement):
    with cursor.meter.owned_control():
        cursor.execute(statement)


def resource_sample():
    p = {
        "resources": {
            "daemon_id": "1f8c7fe5-5972-4adc-8d6e-363a38572be1",
            "socket": "/Users/ferozebasha/.docker/run/docker.sock",
            "container_id": "1" * 64,
            "image_id": "sha256:" + "2" * 64,
            "volume_identity": "3" * 64,
            "network_id": "4" * 64,
            "started_at": "synthetic",
        },
        "credential_metadata": {
            "path": sec.F_SECRET,
            "uid": os.getuid(),
            "inode": 100,
            "size": 32,
            "mode": 0o600,
            "parent_mode": 0o700,
            "nlink": 1,
            "mtime_ns": 1,
            "ctime_ns": 1,
        },
    }
    r, c = p["resources"], p["credential_metadata"]
    raw = {
        "pins": copy.deepcopy(r),
        "labels": {"project": "sbom-uuid-w2-f", "service": "postgres_f"},
        "networks": [{"name": "sbom-uuid-w2-f_f_access", "id": r["network_id"]}],
        "volume": {
            "name": "sbom-uuid-w2-f_f_pgdata",
            "identity": r["volume_identity"],
            "destination": "/var/lib/postgresql/data",
        },
        "exclusive_volume_users": [r["container_id"]],
        "publication": [{"host_ip": "127.0.0.1", "host_port": 56043, "container_port": 5432}],
        "mount": {
            "type": "bind",
            "source": "/host_mnt" + sec.F_SECRET,
            "destination": "/run/secrets/f_password",
            "rw": False,
        },
        "credential": {"regular": True, "symlink": False, "metadata": copy.deepcopy(c)},
        "desktop": True,
        "platform": "Docker Desktop",
        "secret_mount_count": 1,
        "settings": {
            "running": True,
            "restart_count": 0,
            "nano_cpus": 1000000000,
            "memory": 536870912,
            "shm_size": 67108864,
            "pids_limit": 128,
            "restart_policy": "no",
            "network_internal": False,
            "icc": "false",
        },
    }
    provider = MagicMock()
    provider.resources.return_value = raw
    provider.read_host.return_value = bytearray(b"x" * 32)
    provider.read_mounted.return_value = bytearray(b"x" * 32)
    provider.stat_host.return_value = c
    authority = NS(recheck=lambda: p, modules=MODULES)
    return p, raw, provider, authority


class Sources(unittest.TestCase):
    def test_graph_and_frozen(self):
        self.assertEqual((len(REG["lock"]["sources"]), len(REG["graph"]), len(REG["units"])), (113, 91, 45))
        self.assertEqual(len(MODULES["isolated_loader"].frozen_statements(ROOT, REG)), 558)

    def test_imports_inert(self):
        folder = Path(__file__).parent
        for name in ("reviewed", "security", "transport", "resources", "catalog", "binding", "journal", "activation"):
            with (
                patch("builtins.open", side_effect=AssertionError("IO")),
                patch("os.open", side_effect=AssertionError("IO")),
            ):
                spec = importlib.util.spec_from_file_location("_inert", folder / (name + ".py"))
                spec.loader.exec_module(importlib.util.module_from_spec(spec))

    def test_live_cli_denied_before_root(self):
        with patch.object(act, "load", side_effect=AssertionError("Runtime access")):
            with self.assertRaises(SystemExit) as e:
                act.main(["--mode", "live", "--root", "/nonexistent"])
        self.assertEqual(e.exception.code, 2)

    def test_offline_cli(self):
        with redirect_stdout(io.StringIO()) as out:
            act.main(["--mode", "offline", "--root", str(ROOT)])
        self.assertEqual(json.loads(out.getvalue())["frozen_statements"], 558)

    def test_w23_live_denial_unchanged(self):
        source = (ROOT / "infra/uuid-migration/fresh-coordinator/coordinator.py").read_text()
        self.assertIn("parser.exit(2", source)
        with self.assertRaises(ValueError):
            MODULES["isolated_loader"].mock_only(object())

    def test_all_44_bind_without_upgrade(self):
        for u in REG["units"][1:]:
            a = NS(root=ROOT, registry=REG, modules=MODULES, unit_authority=NS(unit=u))
            op = MagicMock()
            upgrade = binding.bind(a, op, NS(as_sql=False))
            self.assertTrue(callable(upgrade))
            op.execute.assert_not_called()

    def test_final_snapshot_format(self):
        a = NS(root=ROOT, registry=REG, modules=MODULES)
        self.assertEqual(len(catalog.final_queries(a)), 17)

    def test_no_app_imports_or_connection_factory(self):
        for p in Path(__file__).parent.glob("*.py"):
            if p.name.startswith("test_"):
                continue
            tree = ast.parse(p.read_bytes())
            imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
            self.assertFalse(any(n.startswith(("app", "dotenv", "psycopg")) for n in imports))
            self.assertNotIn("create_all(", p.read_text())


class ResourceTests(unittest.TestCase):
    def test_content_equivalence(self):
        _, _, p, a = resource_sample()
        secret, digest = sec.observe_resources(a, p)
        self.assertEqual(secret, bytearray(b"x" * 32))
        self.assertEqual(len(digest), 64)
        self.assertEqual(p.read_mounted.return_value, bytearray(32))
        secret[:] = b"\0" * 32

    def test_exact_host_mapping(self):
        _, r, p, a = resource_sample()
        r["mount"]["source"] = sec.F_SECRET
        secret, _ = sec.observe_resources(a, p)
        secret[:] = b"\0" * 32

    def test_correlation_failure_erases(self):
        _, _, p, a = resource_sample()
        p.read_mounted.return_value = bytearray(b"y" * 32)
        with self.assertRaises(ValueError):
            sec.observe_resources(a, p)
        self.assertEqual(p.read_host.return_value, bytearray(32))
        self.assertEqual(p.read_mounted.return_value, bytearray(32))

    def test_metadata_changes_erase(self):
        _, _, p, a = resource_sample()
        p.stat_host.return_value = {}
        with self.assertRaises(ValueError):
            sec.observe_resources(a, p)
        self.assertEqual(p.read_host.return_value, bytearray(32))

    def test_no_claim_from_matching_hba(self):
        result = sec.authentication_evidence(connected=True, hba_rows=[{"error": None}], independently_reviewed=False)
        self.assertEqual(result["effective_password_rule"], "UNKNOWN")
        self.assertIn("does not prove", result["limitation"])

    def test_hba_errors_refuse(self):
        with self.assertRaises(ValueError):
            sec.authentication_evidence(connected=True, hba_rows=[{"error": "parse"}], independently_reviewed=False)

    def test_private_stat_refuses_symlink(self):
        with self.assertRaises(ValueError):
            sec.file_metadata(sec.F_SECRET, lstat=lambda _: NS(st_mode=0o120600))

    def test_host_reader_no_copy_persist(self):
        p, _, _, _ = resource_sample()
        meta = p["credential_metadata"]
        content = bytearray(b"x" * 32)
        self.assertIs(
            resources.host_read(
                sec.F_SECRET, meta, stat_reader=lambda _: meta, opener=lambda *_: (meta, content, meta)
            ),
            content,
        )

    def test_host_reader_race_erases(self):
        p, _, _, _ = resource_sample()
        meta = p["credential_metadata"]
        content = bytearray(b"x" * 32)
        with self.assertRaises(ValueError):
            resources.host_read(sec.F_SECRET, meta, stat_reader=lambda _: meta, opener=lambda *_: (meta, content, {}))
        self.assertEqual(content, bytearray(32))


# Every resource mutation below is its own discoverable regression, not a single
# large PASS counted as many cases. All metadata and bytes are synthetic.
def rejection(path, value):
    def test(self):
        _, raw, p, a = resource_sample()
        target = raw
        for k in path[:-1]:
            target = target[k]
        target[path[-1]] = value
        with self.assertRaises(ValueError):
            sec.observe_resources(a, p)

    return test


for name, path, value in [
    ("daemon", ("pins", "daemon_id"), "wrong"),
    ("container", ("pins", "container_id"), "9" * 64),
    ("image", ("pins", "image_id"), "sha256:" + "9" * 64),
    ("volume", ("volume", "name"), "sbom-uuid-w1_d_pgdata"),
    ("network", ("networks", 0, "name"), "sbom-uuid-w17-e_e_access"),
    ("publication", ("publication", 0, "host_ip"), "0.0.0.0"),
    ("port", ("publication", 0, "host_port"), 56041),
    ("project", ("labels", "project"), "sbom-uuid-w17-e"),
    ("service", ("labels", "service"), "postgres_e"),
    ("mount_rw", ("mount", "rw"), True),
    ("mount_source", ("mount", "source"), "/host_mnt/etc/passwd"),
    ("mount_dest", ("mount", "destination"), "/tmp/password"),
    ("mount_type", ("mount", "type"), "volume"),
    ("multiple_secrets", ("secret_mount_count",), 2),
    ("remote", ("desktop",), False),
    ("non_desktop", ("platform",), "Linux"),
    ("restart", ("settings", "restart_count"), 1),
    ("memory", ("settings", "memory"), 999999999),
    ("shared_volume", ("exclusive_volume_users",), ["1" * 64, "9" * 64]),
    ("file_mode", ("credential", "metadata", "mode"), 0o644),
    ("file_symlink", ("credential", "symlink"), True),
    ("wrong_socket", ("pins", "socket"), "/var/run/docker.sock"),
]:
    setattr(ResourceTests, "test_refuse_" + name, rejection(path, value))


class MeterTests(unittest.TestCase):
    def test_one_charge_no_wrapper_duplicate(self):
        m = meter(["SELECT 1"])
        c = tr.Cursor(MagicMock(), m)
        c.execute("SELECT 1")
        self.assertEqual(m.counts["catalog_queries"], 1)
        self.assertEqual(m.counts["migration_statements"], 0)

    def test_reflection_in_upgrade_charged_query(self):
        m = meter(["SELECT 1"])
        c = tr.Cursor(MagicMock(), m)
        with m.scope("migration_statements"):
            c.execute("SELECT 1")
        self.assertEqual(m.counts["catalog_queries"], 1)

    def test_executemany_reserved_before_driver(self):
        m = meter(["INSERT INTO public.x VALUES (%s)"])
        m.limits["migration_statements"] = 2
        raw = MagicMock()
        c = tr.Cursor(raw, m)
        controlled(c, "BEGIN READ WRITE")
        with m.scope("migration_statements"):
            with self.assertRaises(ValueError):
                c.executemany("INSERT INTO public.x VALUES (%s)", [(1,), (2,), (3,)])
        raw.executemany.assert_not_called()
        self.assertEqual(m.counts["migration_statements"], 0)

    def test_executemany_counts_rows_once(self):
        m = meter(["INSERT INTO public.x VALUES (%s)"])
        raw = MagicMock()
        c = tr.Cursor(raw, m)
        controlled(c, "BEGIN READ WRITE")
        with m.scope("migration_statements"):
            c.executemany("INSERT INTO public.x VALUES (%s)", [(1,), (2,)])
        self.assertEqual(m.counts["migration_statements"], 2)
        raw.executemany.assert_called_once()

    def test_generator_refused(self):
        m = meter(["INSERT INTO public.x VALUES (%s)"])
        c = tr.Cursor(MagicMock(), m)
        controlled(c, "BEGIN READ WRITE")
        with m.scope("migration_statements"):
            with self.assertRaises(ValueError):
                c.executemany("INSERT INTO public.x VALUES (%s)", iter([(1,)]))

    def test_unknown_sql_never_reaches_driver(self):
        raw = MagicMock()
        c = tr.Cursor(raw, meter())
        with self.assertRaises(ValueError):
            c.execute("SELECT 1")
        raw.execute.assert_not_called()

    def test_multistatement_refused(self):
        raw = MagicMock()
        c = tr.Cursor(raw, meter(["SELECT 1; SELECT 2"]))
        with self.assertRaises(ValueError):
            c.execute("SELECT 1; SELECT 2")
        raw.execute.assert_not_called()

    def test_catalog_dml_refused(self):
        c = tr.Cursor(MagicMock(), meter(["DELETE FROM public.x"]))
        with self.assertRaises(ValueError):
            c.execute("DELETE FROM public.x")

    def test_deadline_then_cleanup(self):
        now = [0]
        m = meter(["SELECT 1"], clock=lambda: now[0])
        c = tr.Cursor(MagicMock(), m)
        controlled(c, "BEGIN READ ONLY")
        now[0] = 121
        with self.assertRaises(ValueError):
            c.execute("SELECT 1")
        m.cleanup = True
        controlled(c, "ROLLBACK")
        self.assertFalse(m.transaction_open)

    def test_control_budget(self):
        m = meter()
        m.limits["transaction_controls"] = 2
        c = tr.Cursor(MagicMock(), m)
        controlled(c, "BEGIN READ ONLY")
        controlled(c, "ROLLBACK")
        with self.assertRaises(ValueError):
            controlled(c, "BEGIN READ WRITE")

    def test_journal_failure_prevents_driver(self):
        j = MagicMock()
        j.record.side_effect = OSError("synthetic")
        raw = MagicMock()
        c = tr.Cursor(raw, meter(["SELECT 1"], journal=j))
        with self.assertRaises(OSError):
            c.execute("SELECT 1")
        raw.execute.assert_not_called()

    def test_failed_commit_is_unknown(self):
        m = meter()
        raw = MagicMock()
        c = tr.Cursor(raw, m)
        controlled(c, "BEGIN READ WRITE")
        raw.execute.side_effect = OSError("synthetic")
        with self.assertRaises(OSError):
            controlled(c, "COMMIT")
        self.assertTrue(m.commit_sent)
        self.assertFalse(m.commit_ack)

    def test_no_driver_bypass(self):
        d = tr.Driver(NS(autocommit=True), meter())
        for name in ("execute", "transaction", "pipeline", "copy"):
            with self.assertRaises(ValueError):
                getattr(d, name)
        with self.assertRaises(ValueError):
            d.commit()
        with self.assertRaises(ValueError):
            d.rollback()

    def test_physical_close_assertion(self):
        raw = MagicMock()
        raw.autocommit = True
        raw.closed = False
        d = tr.Driver(raw, meter())
        with self.assertRaises(ValueError):
            d.close()
        raw.close.assert_called_once()


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name).resolve()
        self.path.chmod(0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def test_durable_chain_and_permissions(self):
        j = Journal(self.path, "a" * 64, "SYNTHETIC")
        j.record("COMMIT_REQUESTED")
        j.close()
        rows = j.path.read_bytes().splitlines(keepends=True)
        self.assertEqual(json.loads(rows[1])["previous_sha256"], sec.sha(rows[0]))
        self.assertEqual(j.path.stat().st_mode & 0o777, 0o600)

    def test_no_retry_claim(self):
        j = Journal(self.path, "a" * 64, "SYNTHETIC")
        j.close()
        with self.assertRaises(FileExistsError):
            Journal(self.path, "b" * 64, "OTHER")

    def test_unsafe_evidence_refused(self):
        j = Journal(self.path, "a" * 64, "SYNTHETIC")
        try:
            with self.assertRaises(ValueError):
                j.record("STOP", password="synthetic")
            with self.assertRaises(ValueError):
                j.record("STOP", outcome="password=synthetic")
        finally:
            j.close()

    def test_fsync_failure_stops_claim(self):
        with patch("os.fsync", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                Journal(self.path, "a" * 64, "SYNTHETIC")
        self.assertTrue((self.path / "unit-attempt.jsonl").exists())

    def test_safe_errors_have_no_arguments(self):
        e = ValueError("password=synthetic")
        e.sqlstate = "28P01"
        self.assertEqual(safe_error(e), {"exception": "ValueError", "sqlstate": "28P01"})
        self.assertNotIn("synthetic", json.dumps(safe_error(e)))


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name).resolve()
        self.path.chmod(0o700)
        self.a = MODULES["authority"]
        self.ua = NS(
            unit=REG["units"][0],
            args=(None, REG["units"][0]["next"], "unit_execute", "SYNTHETIC"),
            recheck=MagicMock(),
            plan={"expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat()},
        )
        self.wrapper = NS(unit_authority=self.ua, modules=MODULES)
        self.plan = {
            "schema": "w24a-activation-review-v1",
            "accepted": False,
            "w23_manifest": {"path": "/SYNTHETIC.json", "sha256": "b" * 64},
            "activation_sources": sec.source_bundle(ROOT),
            "dependency_sources": {},
            "sql_allowlist": dict.fromkeys(tr.CATEGORIES, []),
            "connection": tr.connection_options(self.wrapper),
            "approvals": {"unit_execute": "SYNTHETIC"},
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "integrity_attestations": [False] * 7,
            "integrity_approvals": {},
        }
        self.file = self.path / "manifest.json"

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, raw=None, expected=None):
        raw = raw or json.dumps(self.plan).encode()
        self.file.write_bytes(raw)
        self.file.chmod(0o600)
        with (
            patch.object(sec, "load", return_value=(MODULES, REG)),
            patch.object(sec, "verify_dependencies"),
            patch.object(self.a, "Authority", return_value=self.ua),
        ):
            return sec.Authority(ROOT, self.file, expected or sec.sha(raw), *self.ua.args)

    def test_exact_raw_hash_not_canonical(self):
        a = self.build()
        self.assertEqual(a.evidence()["manifest_sha256"], sec.sha(self.file.read_bytes()))
        self.assertNotEqual(a.evidence()["manifest_sha256"], a.evidence()["manifest_canonical_sha256"])

    def test_missing_raw_hash(self):
        with self.assertRaises(ValueError):
            sec.Authority(ROOT, "/nonexistent", None, *self.ua.args)

    def test_wrong_raw_hash(self):
        with self.assertRaises(ValueError):
            self.build(expected="f" * 64)

    def test_duplicates_refused(self):
        with self.assertRaises(ValueError):
            self.build(raw=b'{"accepted":false,"accepted":false}')

    def test_manifest_changes_at_boundary(self):
        a = self.build()
        self.file.write_bytes(self.file.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            a.recheck()

    def test_expiry(self):
        self.plan["expires_at"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(ValueError):
            self.build()

    def test_missing_action(self):
        self.plan["approvals"] = {}
        with self.assertRaises(ValueError):
            self.build()

    def test_wrong_source(self):
        self.plan["activation_sources"] = {}
        with self.assertRaises(ValueError):
            self.build()

    def test_wrong_connection(self):
        self.plan["connection"]["port"] = 56042
        with self.assertRaises(ValueError):
            self.build()

    def test_integrity_approval_refused(self):
        self.plan["integrity_approvals"] = {"integrity_execute": "BAD"}
        with self.assertRaises(ValueError):
            self.build()

    def test_private_mode(self):
        a = self.build()
        self.file.chmod(0o644)
        with self.assertRaises(ValueError):
            a.recheck()

    def test_in_memory_manifest_mutation_refused(self):
        a = self.build()
        a.plan["sql_allowlist"]["migration_statements"] = ["e" * 64]
        with self.assertRaises(ValueError):
            a.recheck()

    def test_dependency_pins_missing(self):
        with self.assertRaises(ValueError):
            sec.verify_dependencies({})


class TransportTests(unittest.TestCase):
    def build(self):
        ua = NS(unit=REG["units"][0], args=(None, REG["units"][0]["next"], "unit_execute", "SYNTHETIC"))
        a = NS(unit_authority=ua, modules=MODULES)
        connector, engine = MagicMock(), MagicMock()
        connector.return_value.autocommit = True
        t = tr.Transport(
            connector=connector,
            engine_factory=engine,
            null_pool=object(),
            options=tr.connection_options(a),
            secret=bytearray(b"x" * 32),
            meter=meter(),
            environment={},
        )
        return t, connector, engine

    def test_fixed_connection_no_service(self):
        t, c, _ = self.build()
        with patch.dict(os.environ, {}, clear=True):
            t._creator()
        options = c.call_args.kwargs
        self.assertEqual(
            (options["host"], options["hostaddr"], options["port"], options["dbname"], options["user"]),
            ("127.0.0.1", "127.0.0.1", 56043, "uuid_w2_f_fresh", "uuid_w2_f_bootstrap"),
        )
        self.assertNotIn("service", options)
        self.assertEqual(options["passfile"], "/dev/null")
        self.assertIn("default_transaction_read_only=on", options["options"])
        self.assertEqual(t.secret, bytearray(32))

    def test_single_constructor(self):
        t, c, _ = self.build()
        with patch.dict(os.environ, {}, clear=True):
            t._creator()
            with self.assertRaises(ValueError):
                t._creator()
        c.assert_called_once()

    def test_failure_no_retry_secret_erased(self):
        t, c, _ = self.build()
        c.side_effect = ValueError("synthetic")
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                t._creator()
        c.assert_called_once()
        self.assertEqual(t.secret, bytearray(32))

    def test_engine_contract(self):
        t, _, e = self.build()
        t.open()
        opts = e.call_args.kwargs
        self.assertEqual(e.call_args.args, ("postgresql+psycopg://",))
        self.assertTrue(opts["skip_autocommit_rollback"])
        self.assertIsNone(opts["pool_reset_on_return"])
        self.assertEqual(opts["isolation_level"], "AUTOCOMMIT")
        with self.assertRaises(ValueError):
            t.open()

    def test_disposal_after_connection_error(self):
        t, _, e = self.build()
        e.return_value.connect.side_effect = ValueError("synthetic")
        with self.assertRaises(ValueError):
            t.open()
        t.close()
        e.return_value.dispose.assert_called_once_with(close=True)

    def test_close_failure_does_not_skip_disposal(self):
        t, _, e = self.build()
        t.open()
        t.connection.close.side_effect = ValueError("synthetic")
        with self.assertRaises(ValueError):
            t.close()
        e.return_value.dispose.assert_called_once_with(close=True)

    def test_ambient_pg_refused(self):
        t, c, _ = self.build()
        with patch.dict(os.environ, {"PGSERVICE": "SYNTHETIC"}, clear=True):
            with self.assertRaises(ValueError):
                t._creator()
        c.assert_not_called()

    def test_operations_factories_owned(self):
        connection = MagicMock()
        connection.dialect.name = "postgresql"
        connection.dialect.default_schema_name = "public"
        factory = MagicMock()
        context = factory.configure.return_value
        context.as_sql = False
        context.impl.transactional_ddl = True
        op = MagicMock()
        op.get_bind.return_value = connection
        op.get_context.return_value = context
        _, bound = binding.operations(
            connection, context_factory=factory, operations_factory=MagicMock(return_value=op), opts={}
        )
        self.assertIs(bound, op)
        self.assertFalse(factory.configure.call_args.kwargs["opts"]["as_sql"])

    def test_operations_reject_foreign_bind(self):
        c = MagicMock()
        c.dialect.name = "postgresql"
        c.dialect.default_schema_name = "public"
        factory = MagicMock()
        factory.configure.return_value.as_sql = False
        factory.configure.return_value.impl.transactional_ddl = True
        with self.assertRaises(ValueError):
            binding.operations(c, context_factory=factory, operations_factory=MagicMock(), opts={})


class LifecycleTests(unittest.TestCase):
    def setup_case(self, fail=None, journal_fail=None):
        u = REG["units"][1]
        prior = u["previous"]
        nxt = u["next"]
        statements = [
            catalog.ADVISORY,
            catalog.VERSION_LOCK,
            'LOCK TABLE ONLY public."tenants" IN SHARE MODE NOWAIT',
            "SET LOCAL search_path = public, pg_catalog",
            "SET LOCAL search_path = pg_catalog",
            "CREATE TABLE public.synthetic (id integer)",
            catalog.UPDATE,
            catalog.MARKER,
        ]
        m = meter(statements)
        raw = MagicMock()
        if fail:

            def execute(statement, params):
                if statement == fail:
                    raise OSError("synthetic")

            raw.execute.side_effect = execute
        cursor = tr.Cursor(raw, m)

        class Result:
            rowcount = 1

            def __init__(self, rows):
                self.rows = rows

            def mappings(self):
                return self

            def all(self):
                return self.rows

        class Connection:
            dialect = NS(name="postgresql", default_schema_name="pg_catalog")

            def exec_driver_sql(self, statement):
                cursor.execute(statement)

            def execute(self, statement, params):
                cursor.execute(statement, params)
                if statement == catalog.ADVISORY:
                    return Result([{"acquired": True}])
                if statement in {catalog.UPDATE, catalog.MARKER}:
                    return Result([{"version_num": nxt}])
                return Result([])

        conn = Connection()
        t = MagicMock()
        t.options = {}
        t.open.return_value = conn
        a = NS(
            recheck=MagicMock(),
            unit_authority=NS(unit=u, args=(prior, nxt, "unit_execute", "SYNTHETIC")),
            plan={"connection": {}},
            modules=MODULES,
            registry=REG,
            root=ROOT,
        )
        j = MagicMock()
        if journal_fail:

            def record(phase, **fields):
                if phase == journal_fail:
                    raise OSError("synthetic")

            j.record.side_effect = record
        token = NS(table_names=("tenants",), prefix="a" * 64)
        gate = MagicMock()

        def upgrade():
            act.sql(conn, m, str, "CREATE TABLE public.synthetic (id integer)")

        stack = (
            patch.object(act, "observe", return_value=({}, token)),
            patch.object(catalog, "collect", return_value={"marker": [prior]}),
            patch.object(catalog, "verify"),
            patch.object(binding, "operations", return_value=(NS(), NS())),
            patch.object(binding, "bind", return_value=upgrade),
        )
        from contextlib import ExitStack

        self.enterContext(ExitStack())
        for item in stack:
            self.enterContext(item)

        def run():
            return act.stage_unit(
                a,
                t,
                m,
                j,
                resource_gate=gate,
                text_factory=str,
                context_factory=MagicMock(),
                operations_factory=MagicMock(),
            )

        return a, t, m, j, gate, run

    def test_acknowledged_commit_closes_unverified(self):
        _, t, m, _, _, run = self.setup_case()
        r = run()
        self.assertEqual(r["outcome"], "COMMITTED_UNVERIFIED")
        self.assertTrue(r["commit_acknowledged"])
        self.assertFalse(r["accepted"])
        t.open.assert_called_once()
        t.close.assert_called_once()
        self.assertEqual(m.counts["transaction_controls"], 4)

    def test_body_failure_rolls_back_closes(self):
        _, t, m, _, _, run = self.setup_case(fail="CREATE TABLE public.synthetic (id integer)")
        r = run()
        self.assertEqual(r["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertFalse(m.commit_sent)
        t.close.assert_called_once()
        self.assertFalse(m.transaction_open)

    def test_unknown_commit_no_rollback_retry(self):
        _, t, m, _, _, run = self.setup_case(fail="COMMIT")
        r = run()
        self.assertEqual(r["outcome"], "UNKNOWN_COMMIT_MANUAL_RECONCILIATION")
        self.assertEqual(m.counts["transaction_controls"], 4)
        t.open.assert_called_once()
        t.close.assert_called_once()

    def test_journal_failure_before_commit_prevents_commit(self):
        _, t, m, _, _, run = self.setup_case(journal_fail="COMMIT_REQUESTED")
        r = run()
        self.assertFalse(m.commit_sent)
        self.assertEqual(r["outcome"], "ROLLED_BACK_UNVERIFIED")
        t.close.assert_called_once()

    def test_journal_failure_after_ack_keeps_commit_fact(self):
        _, _, m, _, _, run = self.setup_case(journal_fail="COMMIT_ACKNOWLEDGED")
        r = run()
        self.assertEqual(r["outcome"], "COMMITTED_EVIDENCE_INCOMPLETE")
        self.assertTrue(r["commit_acknowledged"])
        self.assertFalse(m.transaction_open)

    def test_source_recheck_before_ddl(self):
        a, t, m, _, _, run = self.setup_case()
        a.recheck.side_effect = [None, None, None, ValueError("synthetic")]
        r = run()
        self.assertEqual(r["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertFalse(m.commit_sent)
        t.close.assert_called_once()

    def test_resource_change_prevents_mutation(self):
        _, t, m, _, gate, run = self.setup_case()
        gate.side_effect = [None, ValueError("synthetic")]
        r = run()
        self.assertEqual(r["outcome"], "ROLLED_BACK_UNVERIFIED")
        self.assertFalse(m.commit_sent)
        t.close.assert_called_once()

    def test_independent_readback_authority_required(self):
        a, t, m, j, gate, _ = self.setup_case()
        with self.assertRaises(ValueError):
            act.stage_readonly(a, t, m, j, resource_gate=gate, text_factory=str, after=True)
        t.open.assert_not_called()

    def test_separate_readback_rolls_back_closes(self):
        a, t, m, j, gate, _ = self.setup_case()
        a.unit_authority.args = (None, None, "unit_readback", "SEPARATE")
        r = act.stage_readonly(a, t, m, j, resource_gate=gate, text_factory=str, after=True)
        self.assertEqual(r["outcome"], "READBACK_OBSERVED")
        t.open.assert_called_once()
        t.close.assert_called_once()
        self.assertEqual(m.counts["transaction_controls"], 2)

    def test_no_connect_with_wrong_options(self):
        a, t, m, _, _, run = self.setup_case()
        a.plan["connection"] = {"port": 56042}
        r = run()
        t.open.assert_not_called()
        t.close.assert_called_once()
        self.assertFalse(m.commit_sent)
        self.assertEqual(r["outcome"], "BLOCKED")

    def test_connection_failure_closes_without_query(self):
        _, t, m, _, _, run = self.setup_case()
        t.open.side_effect = OSError("synthetic")
        r = run()
        self.assertEqual(r["outcome"], "BLOCKED")
        t.close.assert_called_once()
        self.assertEqual(m.counts["transaction_controls"], 0)

    def test_closure_failure_not_accepted(self):
        _, t, _, _, _, run = self.setup_case()
        t.close.side_effect = OSError("synthetic")
        r = run()
        self.assertIn("CLOSURE", r["outcome"])
        self.assertFalse(r["accepted"])


class AdditionalTests(unittest.TestCase):
    def test_real_alembic_context_compiler_only(self):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        from sqlalchemy.dialects.postgresql import dialect

        c = MagicMock()
        c.dialect = dialect()
        c.dialect.default_schema_name = "public"
        context, op = binding.operations(c, context_factory=MigrationContext, operations_factory=Operations, opts={})
        self.assertIs(op.get_context(), context)
        c.execute.assert_not_called()

    def test_safe_secret_descriptor_reader(self):
        p, _, _, _ = resource_sample()
        meta = p["credential_metadata"]
        file = NS(
            st_mode=0o100600, st_uid=meta["uid"], st_ino=100, st_size=32, st_nlink=1, st_mtime_ns=1, st_ctime_ns=1
        )
        parent = NS(st_mode=0o40700, st_uid=meta["uid"])
        osapi = MagicMock()
        osapi.lstat.side_effect = lambda path: file if str(path) == sec.F_SECRET else parent
        osapi.fstat.return_value = file
        osapi.read.side_effect = [b"x" * 32, b""]
        reader = resources.SecretFiles(osapi, MagicMock())
        self.assertEqual(reader.read_host(sec.F_SECRET, meta), bytearray(b"x" * 32))
        osapi.close.assert_called_once()
        self.assertTrue(osapi.open.call_args.args[1] & os.O_NOFOLLOW)

    def test_unreviewed_transport_target_refused(self):
        ua = NS(unit=REG["units"][0], args=(None, None, "unit_execute", "SYNTHETIC"))
        options = tr.connection_options(NS(unit_authority=ua, modules=MODULES))
        options["host"] = "/tmp"
        with self.assertRaises(ValueError):
            tr.Transport(
                connector=MagicMock(),
                engine_factory=MagicMock(),
                null_pool=object(),
                options=options,
                secret=bytearray(b"x" * 32),
                meter=meter(),
                environment={},
            )

    def test_query_budget_shortfall_is_a_stop(self):
        # Three full observations with71business emptiness queries alone consume
        # 3*(27catalog+71emptiness+identity+clients+locks+marker+4references)=318.
        # Reflection/initialization/freshness queries are additional. Never repin
        # or increase the original256quota to hide this activation dependency.
        minimum = 3 * (27 + 71 + 1 + 1 + 1 + 1 + 4)
        self.assertGreater(minimum, 256)
        m = meter(["SELECT 1"])
        c = tr.Cursor(MagicMock(), m)
        for _ in range(256):
            c.execute("SELECT 1")
        with self.assertRaises(ValueError):
            c.execute("SELECT 1")
        self.assertEqual(m.counts["catalog_queries"], 256)

    def test_rollback_after_broken_journal(self):
        j = MagicMock()
        m = meter(journal=j)
        c = tr.Cursor(MagicMock(), m)
        controlled(c, "BEGIN READ WRITE")
        j.record.side_effect = OSError("synthetic")
        m.cleanup = True
        controlled(c, "ROLLBACK")
        self.assertFalse(m.transaction_open)

    def test_catalog_fixed_selects_compile(self):
        from sqlalchemy import text
        from sqlalchemy.dialects.postgresql import dialect

        queries = MODULES["observations"].catalog_queries(ROOT, REG)
        self.assertEqual(len(queries), 27)
        for query in [*queries.values(), *MODULES["observations"].REFERENCE_SQL.values(), catalog.IDENTITY]:
            self.assertIsInstance(str(text(query).compile(dialect=dialect())), str)

    def test_quoted_identifier_refuses_injection(self):
        with self.assertRaises(ValueError):
            catalog.relation("tenants; DROP TABLE x")

    def test_no_credential_or_resource_reader_in_offline_cli(self):
        with patch.object(sec, "observe_resources", side_effect=AssertionError("secret")):
            with redirect_stdout(io.StringIO()):
                act.main(["--mode", "offline", "--root", str(ROOT)])

    def test_new_pending_is_not_authority(self):
        template = json.loads((Path(__file__).parent / "approval.pending.json").read_bytes())
        self.assertIs(template["accepted"], False)
        self.assertEqual(template["approvals"], {})
        self.assertEqual(template["integrity_attestations"], [False] * 7)
        self.assertIsNone(template["expires_at"])

    def test_offline_compose_proposal(self):
        import yaml

        data = yaml.safe_load((Path(__file__).parent / "compose.f.proposed.yml").read_bytes())
        service = data["services"]["postgres_f"]
        self.assertEqual(service["ports"], ["127.0.0.1:56043:5432"])
        self.assertEqual(service["pull_policy"], "never")
        self.assertEqual(service["restart"], "no")
        self.assertFalse(data["networks"]["f_access"]["internal"])
        self.assertNotIn("POSTGRES_PASSWORD", service["environment"])


for variable in (
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGSYSCONFDIR",
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGPASSFILE",
    "PGOPTIONS",
    "DATABASE_URL",
    "DOCKER_HOST",
    "PYTHONPATH",
):

    def test_env(self, name=variable):
        with self.assertRaises(ValueError):
            sec.clean_environment({name: "SYNTHETIC"})

    setattr(AdditionalTests, "test_ambient_" + variable, test_env)


class NormalizationTests(unittest.TestCase):
    def sample(self):
        p, raw, _, _ = resource_sample()
        r = p["resources"]
        labels = {"com.docker.compose.project": "sbom-uuid-w2-f", "com.docker.compose.service": "postgres_f"}
        daemon = {"ID": r["daemon_id"], "OperatingSystem": "Docker Desktop", "socket": r["socket"]}
        container = {
            "Id": r["container_id"],
            "Image": r["image_id"],
            "State": {"StartedAt": r["started_at"], "Running": True},
            "Config": {"Labels": labels},
            "RestartCount": 0,
            "HostConfig": {
                "NanoCpus": 1000000000,
                "Memory": 536870912,
                "ShmSize": 67108864,
                "PidsLimit": 128,
                "RestartPolicy": {"Name": "no"},
            },
            "Mounts": [
                {
                    "Destination": "/run/secrets/f_password",
                    "Type": "bind",
                    "Source": "/host_mnt" + sec.F_SECRET,
                    "RW": False,
                },
                {
                    "Destination": "/var/lib/postgresql/data",
                    "Type": "volume",
                    "Name": "sbom-uuid-w2-f_f_pgdata",
                    "RW": True,
                },
            ],
            "NetworkSettings": {
                "Networks": {"sbom-uuid-w2-f_f_access": {"NetworkID": r["network_id"]}},
                "Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56043"}]},
            },
        }
        volume = {
            "Name": "sbom-uuid-w2-f_f_pgdata",
            "Driver": "local",
            "CreatedAt": "synthetic",
            "Mountpoint": "synthetic",
            "Labels": labels,
            "Options": None,
        }
        network = {
            "Name": "sbom-uuid-w2-f_f_access",
            "Id": r["network_id"],
            "Driver": "bridge",
            "Labels": labels,
            "Containers": {r["container_id"]: {}},
            "Internal": False,
            "Options": {"com.docker.network.bridge.enable_icc": "false"},
        }
        return p, {
            "daemon": daemon,
            "container": container,
            "volume": volume,
            "network": network,
            "volume_users": [r["container_id"]],
            "credential": raw["credential"],
            "digest": MODULES["source_registry"].digest,
        }

    def test_normalize_independent_raw_metadata(self):
        p, k = self.sample()
        raw = resources.normalize(p, **k)
        self.assertEqual(raw["pins"]["container_id"], p["resources"]["container_id"])
        self.assertNotEqual(raw["pins"]["volume_identity"], p["resources"]["volume_identity"])
        self.assertEqual(raw["publication"][0]["host_port"], 56043)

    def test_normalize_wrong_daemon(self):
        p, k = self.sample()
        k["daemon"]["ID"] = "wrong"
        with self.assertRaises(ValueError):
            resources.normalize(p, **k)

    def test_normalize_restart(self):
        p, k = self.sample()
        k["container"]["State"]["StartedAt"] = "other"
        with self.assertRaises(ValueError):
            resources.normalize(p, **k)

    def test_normalize_extra_network_member(self):
        p, k = self.sample()
        k["network"]["Containers"]["other"] = {}
        with self.assertRaises(ValueError):
            resources.normalize(p, **k)

    def test_normalize_extra_mount(self):
        p, k = self.sample()
        k["container"]["Mounts"].append({"Destination": "/unapproved"})
        with self.assertRaises(ValueError):
            resources.normalize(p, **k)

    def test_normalize_nonlocal_publication(self):
        p, k = self.sample()
        k["container"]["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            resources.normalize(p, **k)


class FinalGuardTests(unittest.TestCase):
    def test_unit_sql_cannot_commit(self):
        m = meter()
        raw = MagicMock()
        c = tr.Cursor(raw, m)
        controlled(c, "BEGIN READ WRITE")
        with m.scope("migration_statements"):
            with self.assertRaises(ValueError):
                c.execute("COMMIT")
        self.assertFalse(m.commit_sent)

    def test_control_journal_failure_reserves_rollback_budget(self):
        j = MagicMock()
        m = meter(journal=j)
        c = tr.Cursor(MagicMock(), m)
        controlled(c, "BEGIN READ ONLY")
        controlled(c, "ROLLBACK")
        controlled(c, "BEGIN READ WRITE")
        j.record.side_effect = OSError("synthetic")
        with self.assertRaises(OSError):
            controlled(c, "COMMIT")
        self.assertFalse(m.commit_sent)
        m.cleanup = True
        controlled(c, "ROLLBACK")
        self.assertEqual(m.counts["transaction_controls"], 4)


class LastContractTests(unittest.TestCase):
    def test_readback_appname(self):
        a = NS(
            modules=MODULES, unit_authority=NS(unit=REG["units"][0], args=(None, None, "unit_readback", "SYNTHETIC"))
        )
        self.assertEqual(tr.connection_options(a)["application_name"], "sbom_w24a_f_readback")

    def test_no_mutation_before_owned_transaction(self):
        m = meter(["CREATE TABLE public.synthetic (id integer)"])
        raw = MagicMock()
        c = tr.Cursor(raw, m)
        with m.scope("migration_statements"):
            with self.assertRaises(ValueError):
                c.execute("CREATE TABLE public.synthetic (id integer)")
        raw.execute.assert_not_called()

    def test_existing_dependency_pins_then_tamper(self):
        from importlib.metadata import distribution

        pins = {}
        for name in ("SQLAlchemy", "alembic", "psycopg"):
            dist = distribution(name)
            pins[name] = {
                "version": dist.version,
                "files": {
                    str(f): sec.sha(Path(dist.locate_file(f)).read_bytes())
                    for f in dist.files
                    if str(f).endswith((".py", ".so", ".dylib"))
                },
            }
        sec.verify_dependencies(pins)
        pins["psycopg"]["version"] = "tampered"
        with self.assertRaises(ValueError):
            sec.verify_dependencies(pins)


if __name__ == "__main__":
    unittest.main(verbosity=2)
