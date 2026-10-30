"""Offline checks for the new development setup, using synthetic credentials only."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import dev
from scripts.dev import GreenfieldStack as setup


class SetupSafety(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.state = Path(self.folder.name)
        self.scope = patch.object(setup, "STATE", self.state)
        self.scope.start()
        self.addCleanup(self.scope.stop)
        self.addCleanup(self.folder.cleanup)

    def test_private_creation_and_read(self):
        path = setup.private_file("synthetic", "not-a-real-credential")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(setup.read_private("synthetic"), "not-a-real-credential")

    def test_no_overwrite(self):
        setup.private_file("synthetic", "first")
        with self.assertRaises(FileExistsError):
            setup.private_file("synthetic", "second")

    def test_symlink_refused(self):
        path = setup.private_file("original", "synthetic")
        (self.state / "link").symlink_to(path)
        with self.assertRaises(OSError):
            setup.read_private("link")

    def test_hardlink_refused(self):
        path = setup.private_file("original", "synthetic")
        os.link(path, self.state / "link")
        with self.assertRaises(RuntimeError):
            setup.read_private("original")

    def test_public_file_refused(self):
        path = setup.private_file("synthetic", "synthetic")
        path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            setup.read_private("synthetic")

    def test_public_directory_refused(self):
        self.state.chmod(0o755)
        with self.assertRaises(RuntimeError):
            setup.private_file("synthetic", "synthetic")

    def test_database_allowlist_before_secret_access(self):
        with patch.object(setup, "read_private") as reader:
            for database in ("uuid_w2_f_fresh", "uuid_w17_e_integrity", "production", "application"):
                with self.assertRaises(RuntimeError):
                    setup.url("greenfield_setup", "setup-password", database)
            reader.assert_not_called()

    def test_credential_selection_before_secret_access(self):
        with patch.object(setup, "read_private") as reader:
            with self.assertRaises(RuntimeError):
                setup.url("postgres", "setup-password")
            reader.assert_not_called()

    def test_fixed_connection_target(self):
        from sqlalchemy.engine import make_url

        setup.private_file("runtime-password", "synthetic-only")
        target = make_url(setup.url("greenfield_app", "runtime-password"))
        self.assertEqual(
            (target.host, target.port, target.database, target.username),
            ("127.0.0.1", 56044, "sbom_greenfield_uuid", "greenfield_app"),
        )

    def test_ambient_pg_configuration_is_not_inherited(self):
        setup.private_file("environment.json", json.dumps({"AI_CONFIG_ENCRYPTION_KEY": "synthetic-only"}))
        setup.private_file("runtime-password", "synthetic-only")
        setup.private_file("security-mail-key", __import__("base64").b64encode(os.urandom(32)).decode())
        with patch.dict(
            os.environ, {"PGHOST": "production", "PGPASSWORD": "synthetic-ambient", "DATABASE_URL": "wrong"}
        ):
            env = setup.settings()
        self.assertFalse(any(key.startswith("PG") for key in env))
        self.assertIn("56044", env["DATABASE_URL"])
        self.assertEqual(env["AUTH_ENABLED"], "true")
        self.assertEqual(env["NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"], "redis://127.0.0.1:56381/3")
        self.assertEqual(env["NATIVE_SECURITY_OUTBOX_ENABLED"], "true")
        self.assertEqual(env["API_RATE_LIMIT_ENABLED"], "true")
        self.assertEqual(len(__import__("base64").b64decode(env["NATIVE_SECURITY_OUTBOX_KEY"])), 32)

    def test_local_schedule_preserves_all_application_jobs(self):
        from types import SimpleNamespace

        original = {
            "security-mail-outbox": {"task": "security_mail.dispatch", "schedule": 30.0},
            "report-notifications-hourly": {"task": "report_notifications.tick", "schedule": 3600},
        }
        app = SimpleNamespace(conf=SimpleNamespace(beat_schedule=original))
        dev.configure_local_schedule(app, "greenfield")
        self.assertEqual(set(app.conf.beat_schedule), set(original))
        self.assertEqual(app.conf.beat_schedule["security-mail-outbox"]["schedule"], 10.0)
        self.assertEqual(original["security-mail-outbox"]["schedule"], 30.0)

    def test_unexpected_resource_inventory_refused_before_docker(self):
        setup.private_file("docker-identities.json", json.dumps({"unrelated": "wrong"}))
        with patch.object(dev.subprocess, "check_output") as docker:
            with self.assertRaises(RuntimeError):
                setup.verify_resources()
            docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
