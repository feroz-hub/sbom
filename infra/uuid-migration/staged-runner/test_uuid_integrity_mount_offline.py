"""Offline mount regression tests: synthetic bytes, mocked Docker, no PostgreSQL."""

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import uuid_integrity_control as ctl
from test_uuid_integrity_offline import approved

HOST = "/Users/ferozebasha/.sbom-uuid-w17-e/postgres-password"
VM = "/host_mnt" + HOST
DEST = "/run/secrets/e_password"


def mount(source=HOST):
    return {"Source": source, "Destination": DEST, "Type": "bind", "RW": False}


class MountSelectionTests(unittest.TestCase):
    def test_exact_host_path_on_non_desktop(self):
        self.assertEqual(ctl.secret_mount([mount()], False), mount())

    def test_exact_verified_desktop_translation(self):
        self.assertEqual(ctl.secret_mount([mount(VM)], True), mount(VM))

    def test_desktop_translation_refused_without_verified_context(self):
        for context in (False, None, "Docker Desktop", 1):
            with self.subTest(context=context), self.assertRaises(ctl.Stop):
                ctl.secret_mount([mount(VM)], context)

    def test_arbitrary_substitution_other_user_traversal_and_duplicates_rejected(self):
        for source in (
            "/host_mnt/tmp/postgres-password",
            VM.replace("ferozebasha", "different-user"),
            VM + "/../postgres-password",
            VM.replace("/Users/", "/Users//"),
            "/host_mnt" + VM,
            HOST + ".other",
            HOST + "/",
        ):
            with self.subTest(source=source), self.assertRaises(ctl.Stop):
                ctl.secret_mount([mount(source)], True)

    def test_wrong_destination_missing_or_multiple_refused(self):
        wrong = mount()
        wrong["Destination"] = "/run/secrets/other"
        for mounts in ([], [wrong], [mount(), mount(VM)]):
            with self.subTest(mounts=mounts), self.assertRaises(ctl.Stop):
                ctl.secret_mount(mounts, True)

    def test_rw_and_non_bind_refused(self):
        for key, value in (("RW", True), ("RW", None), ("Type", "volume")):
            wrong = mount()
            wrong[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ctl.Stop):
                ctl.secret_mount([wrong], True)

    def test_ambient_home_or_alternate_configured_path_cannot_change_source(self):
        with patch.object(ctl, "PASSWORD", Path("/Users/other/.sbom-uuid-w17-e/postgres-password")):
            with self.assertRaises(ctl.Stop):
                ctl.secret_mount([mount()], True)


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.plan = approved()
        self.daemon = {"id": ctl.DAEMON, "os": "Docker Desktop", "name": "docker-desktop", "type": "linux"}
        self.volume = {"name": "sbom-uuid-w17-e_e_pgdata", "created": "synthetic", "driver": "local"}
        self.plan["volume_sha256"] = ctl.digest(self.volume)
        self.plan["preservation_sha256"] = ctl.digest({"synthetic": True})
        self.state = {
            "id": self.plan["container_id"],
            "image": ctl.IMAGE,
            "running": True,
            "project": "sbom-uuid-w17-e",
            "service": "postgres_e",
            "limits": {"cpu": 1000000000, "memory": 512 * 1024**2, "shm": 64 * 1024**2, "pids": 128},
            "ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "56042"}]},
            "mounts": [
                mount(VM),
                {"Destination": "/var/lib/postgresql/data", "Type": "volume", "Name": "sbom-uuid-w17-e_e_pgdata"},
            ],
            "networks": {"sbom-uuid-w17-e_e_access": {"NetworkID": self.plan["network_id"]}},
        }
        self.config = {
            "driver": "bridge",
            "internal": False,
            "ipv6": False,
            "options": {
                "com.docker.network.bridge.enable_icc": "false",
                "com.docker.network.bridge.enable_ip_masquerade": "true",
                "com.docker.network.bridge.gateway_mode_ipv4": "nat",
            },
        }
        self.commands = []

    def docker(self, *args):
        self.commands.append(args)
        if args[0] == "info":
            return self.daemon
        if args[0] == "container":
            return self.state
        if args[0] == "ps":
            self.assertIn("-a", args)
            self.assertNotIn("-aq", args)
            return self.plan["container_id"]
        if args[0] == "volume":
            return self.volume
        if args[0] == "network":
            if args[3] == "{{json .Containers}}":
                return {self.plan["container_id"]: {}}
            return self.config
        raise AssertionError("Unexpected metadata command")

    def run_resources(self):
        with (
            patch.object(ctl, "docker", side_effect=self.docker),
            patch.object(ctl, "preservation", return_value={"synthetic": True}),
            patch.object(ctl.sys, "platform", "darwin"),
            patch.object(ctl, "correlate_secret", return_value={"content_equal": True}) as correlate,
        ):
            ctl.verify_resources(self.plan)
            correlate.assert_called_once_with(self.plan)

    def test_full_resource_gates_then_mandatory_content_correlation(self):
        self.run_resources()
        self.assertTrue(any(x[0] == "volume" for x in self.commands))

    def test_exact_host_source_still_requires_content_correlation(self):
        self.state["mounts"][0] = mount()
        self.run_resources()

    def test_wrong_container_image_project_service_or_network_stops_before_secret(self):
        variants = (
            ("id", "f" * 64),
            ("image", "sha256:" + "0" * 64),
            ("project", "sbom"),
            ("service", "postgres_d"),
            ("networks", {"sbom_default": {"NetworkID": self.plan["network_id"]}}),
            ("networks", {"sbom-uuid-w17-e_e_access": {"NetworkID": "f" * 64}}),
        )
        original = copy.deepcopy(self.state)
        for key, value in variants:
            self.state = copy.deepcopy(original)
            self.state[key] = value
            with (
                self.subTest(key=key, value=value),
                patch.object(ctl, "docker", side_effect=self.docker),
                patch.object(ctl, "correlate_secret") as correlate,
                self.assertRaises(ctl.Stop),
            ):
                ctl.verify_resources(self.plan)
            correlate.assert_not_called()

    def test_malformed_daemon_stops_with_safety_error(self):
        for daemon in (None, "unexpected daemon", {}, {"id": "wrong"}):
            with (
                self.subTest(daemon=daemon),
                patch.object(ctl, "docker", return_value=daemon),
                patch.object(ctl, "correlate_secret") as correlate,
                self.assertRaises(ctl.Stop),
            ):
                ctl.verify_resources(self.plan)
            correlate.assert_not_called()

    def test_linux_retains_exact_host_path_and_content_requirement(self):
        self.state["mounts"][0] = mount()
        with (
            patch.object(ctl, "docker", side_effect=self.docker),
            patch.object(ctl, "preservation", return_value={"synthetic": True}),
            patch.object(ctl.sys, "platform", "linux"),
            patch.object(ctl, "correlate_secret") as correlate,
        ):
            ctl.verify_resources(self.plan)
            correlate.assert_called_once_with(self.plan)

    def test_wrong_daemon_stops_before_secret(self):
        self.daemon["id"] = "wrong"
        with (
            patch.object(ctl, "docker", side_effect=self.docker),
            patch.object(ctl, "correlate_secret") as correlate,
            self.assertRaises(ctl.Stop),
        ):
            ctl.verify_resources(self.plan)
        correlate.assert_not_called()

    def test_non_desktop_and_linux_never_accept_vm_alias(self):
        for platform, key, value in (
            ("linux", "os", "Docker Desktop"),
            ("darwin", "os", "Unknown Docker"),
            ("darwin", "name", "other"),
            ("darwin", "type", "windows"),
        ):
            original = dict(self.daemon)
            self.daemon[key] = value
            with (
                self.subTest(platform=platform, key=key),
                patch.object(ctl, "docker", side_effect=self.docker),
                patch.object(ctl.sys, "platform", platform),
                patch.object(ctl, "correlate_secret") as correlate,
                self.assertRaises(ctl.Stop),
            ):
                ctl.verify_resources(self.plan)
            correlate.assert_not_called()
            self.daemon = original

    def test_preservation_failure_prevents_content_read(self):
        self.plan["preservation_sha256"] = "0" * 64
        with (
            patch.object(ctl, "docker", side_effect=self.docker),
            patch.object(ctl.sys, "platform", "darwin"),
            patch.object(ctl, "preservation", return_value={"synthetic": True}),
            patch.object(ctl, "correlate_secret") as correlate,
            self.assertRaises(ctl.Stop),
        ):
            ctl.verify_resources(self.plan)
        correlate.assert_not_called()

    def test_failed_content_correlation_never_returns_resource_success(self):
        with (
            patch.object(ctl, "docker", side_effect=self.docker),
            patch.object(ctl.sys, "platform", "darwin"),
            patch.object(ctl, "preservation", return_value={"synthetic": True}),
            patch.object(ctl, "correlate_secret", side_effect=ctl.Stop("synthetic mismatch")),
            self.assertRaises(ctl.Stop),
        ):
            ctl.verify_resources(self.plan)


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name).resolve(strict=True)
        self.parent.chmod(0o700)
        self.path = self.parent / "synthetic-password"
        self.sample = b"synthetic-offline-only\n"
        self.path.write_bytes(self.sample)
        self.path.chmod(0o600)
        self.plan = {
            "password_file": str(self.path),
            "credential_metadata": ctl.credential_metadata(self.path.stat()),
            "container_id": "a" * 64,
        }
        self.pw = patch.object(ctl, "PASSWORD", self.path)
        self.pw.start()
        self.addCleanup(self.pw.stop)

    def run_correlation(self, output=None, code=0):
        result = SimpleNamespace(returncode=code, stdout=self.sample if output is None else output)
        with patch.object(ctl.subprocess, "run", return_value=result) as run:
            value = ctl.correlate_secret(self.plan)
            args, kwargs = run.call_args
            self.assertEqual(args[0][:3], [ctl.DOCKER, "--host", "unix://" + ctl.SOCKET])
            self.assertIn("0:0", args[0])
            self.assertNotIn(self.sample.decode(), json.dumps(args[0]))
            self.assertEqual(kwargs["timeout"], 5)
            self.assertEqual(set(kwargs["env"]), {"HOME", "PATH", "LC_ALL"})
            return value

    def test_equal_bytes_returns_only_safe_boolean_results(self):
        self.assertEqual(self.run_correlation(), {"content_equal": True, "initialization_root_readable": True})

    def test_different_bytes_and_failed_read_refused(self):
        for data, code in ((b"different-synthetic", 0), (b"", 0), (b"", 1)):
            with self.subTest(code=code), self.assertRaises(ctl.Stop):
                self.run_correlation(data, code)

    def test_timeout_propagates_without_retry(self):
        with patch.object(ctl.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic", 5)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                ctl.correlate_secret(self.plan)
            self.assertEqual(run.call_count, 1)

    def test_mode_owner_link_size_metadata_and_parent_refusals_before_exec(self):
        for change in ("mode", "link", "metadata", "parent", "empty"):
            with self.subTest(change=change):
                old = copy.deepcopy(self.plan)
                if change == "mode":
                    self.path.chmod(0o644)
                elif change == "link":
                    os.link(self.path, self.parent / "extra-link")
                elif change == "metadata":
                    self.plan["credential_metadata"]["inode"] += 1
                elif change == "parent":
                    self.parent.chmod(0o755)
                elif change == "empty":
                    self.path.write_bytes(b"")
                with patch.object(ctl.subprocess, "run") as run, self.assertRaises(ctl.Stop):
                    ctl.correlate_secret(self.plan)
                run.assert_not_called()
                self.parent.chmod(0o700)
                self.path.chmod(0o600)
                (self.parent / "extra-link").unlink(missing_ok=True)
                self.path.write_bytes(self.sample)
                self.plan = old
                self.plan["credential_metadata"] = ctl.credential_metadata(self.path.stat())

    def test_symlink_and_traversal_refused_before_exec(self):
        real = self.path
        alias = self.parent / "alias"
        alias.symlink_to(real)
        for path in (alias, self.parent / "sub" / ".." / real.name):
            with patch.object(ctl, "PASSWORD", path), patch.object(ctl.subprocess, "run") as run:
                plan = {**self.plan, "password_file": str(path)}
                with self.assertRaises((ctl.Stop, FileNotFoundError)):
                    ctl.correlate_secret(plan)
                run.assert_not_called()

    def test_postread_host_mutation_refused(self):
        def mutate(*args, **kwargs):
            self.path.write_bytes(b"changed-synthetic")
            return SimpleNamespace(returncode=0, stdout=self.sample)

        with patch.object(ctl.subprocess, "run", side_effect=mutate) as run, self.assertRaises(ctl.Stop):
            ctl.correlate_secret(self.plan)
        self.assertEqual(run.call_count, 1)

    def test_alternate_password_path_refused(self):
        self.plan["password_file"] = "/tmp/not-the-approved-file"
        with patch.object(ctl.subprocess, "run") as run, self.assertRaises(ctl.Stop):
            ctl.correlate_secret(self.plan)
        run.assert_not_called()

    def test_pending_and_expired_approvals_refused_without_resource_or_db_access(self):
        for edit in ({"approvals": {}}, {"expires_utc": "2000-01-01T00:00:00+00:00"}):
            plan = approved()
            plan.update(edit)
            with (
                patch.object(ctl, "verify_resources") as resources,
                patch.object(ctl.psycopg, "connect") as db,
                self.assertRaises(ctl.Stop),
            ):
                ctl.validate_plan(plan, "integrity_execute", "SYNTHETIC-EXECUTE", ctl.common.TABLES, ctl.CATEGORIES)
            resources.assert_not_called()
            db.assert_not_called()

    def test_no_environment_or_database_fallback(self):
        with patch.dict(os.environ, {"PGHOST": "remote", "DATABASE_URL": "synthetic-only"}):
            with self.assertRaises(ctl.Stop):
                ctl.validate_plan(
                    approved(), "integrity_execute", "SYNTHETIC-EXECUTE", ctl.common.TABLES, ctl.CATEGORIES
                )
        with patch.object(ctl.psycopg, "connect") as db:
            self.run_correlation()
            db.assert_not_called()


if __name__ == "__main__":
    unittest.main()
