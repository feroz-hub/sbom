"""Offline checks for the new development setup, using synthetic credentials only."""

import ast
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import greenfield_uuid as setup


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

    def test_worker_schedule_is_local_security_mail_only(self):
        tree = ast.parse((setup.ROOT / "scripts/greenfield_worker.py").read_text())
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign))
        schedule = ast.literal_eval(assignment.value)
        self.assertEqual(set(schedule), {"security-mail-outbox"})
        self.assertEqual(schedule["security-mail-outbox"]["task"], "security_mail.dispatch")

    def test_unexpected_resource_inventory_refused_before_docker(self):
        setup.private_file("docker-identities.json", json.dumps({"unrelated": "wrong"}))
        with patch.object(setup.subprocess, "check_output") as docker:
            with self.assertRaises(RuntimeError):
                setup.verify_resources()
            docker.assert_not_called()

    def test_approved_core_contract_field_coverage(self):
        tree = ast.parse((setup.ROOT / "app/public_api.py").read_text())
        maps = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"FIELDS", "BATCH_FIELDS", "CONTEXT"}
        }
        specialized = {"id", "ids", "parent_id", "version_a", "version_b", "cursor", "X-Next-Cursor", "X-Tenant-ID"}
        rows = [
            line.split(" | ")
            for line in (setup.ROOT / "docs/uuid-migration/phase2/01-core-public-uuid-contract.md")
            .read_text()
            .splitlines()
            if line.startswith("| C0")
        ]
        self.assertEqual(len(rows), 964)
        for row in rows:
            field = row[3].split(".")[-1].removesuffix("[]")
            self.assertIn(field, set(maps["FIELDS"]) | set(maps["BATCH_FIELDS"]) | specialized, row[3])
            if row[3].endswith(".id"):
                parent = row[3].split(".")[-2].removesuffix("[]")
                self.assertIn(parent, set(maps["CONTEXT"]) | {"", "items"}, row[3])


if __name__ == "__main__":
    unittest.main()
