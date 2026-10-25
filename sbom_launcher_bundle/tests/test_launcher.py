"""Safe unit checks for the standalone developer launcher bundle.

These tests never install packages, launch containers, or modify databases.
"""

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import dev


class LauncherTests(unittest.TestCase):
    def test_doctor_is_available(self):
        self.assertEqual(dev.parse_args(["doctor"]).command, "doctor")

    def test_legacy_profile_is_explicit(self):
        self.assertEqual(dev.parse_args(["--profile", "legacy"]).profile, "legacy")

    def test_reports_incomplete_checkout_before_setup(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dev, "ROOT", Path(directory)):
            with self.assertRaises(dev.SetupError) as raised:
                dev.validate_repository_layout()
            self.assertIn("requirements.txt", str(raised.exception))
            self.assertIn("frontend/package-lock.json", str(raised.exception))

    def test_checkout_validation_succeeds_when_manifests_exist(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dev, "ROOT", Path(directory)):
            for name in ("requirements.txt", "alembic.ini", "frontend/package.json", "frontend/package-lock.json"):
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            dev.validate_repository_layout()

    def test_failed_command_prints_tail_and_redacts_password(self):
        output = io.StringIO()
        result = subprocess.CompletedProcess(["fake-installer"], 2, "error: secret-value\n", "missing package\n")
        with patch.object(dev, "VERBOSE", False), contextlib.redirect_stderr(output):
            dev.explain_failed_command(result, {"POSTGRES_PASSWORD": "secret-value"})
        self.assertIn("[REDACTED]", output.getvalue())
        self.assertNotIn("secret-value", output.getvalue())
        self.assertIn("missing package", output.getvalue())

    def test_failed_service_log_shows_last_30_lines(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, patch.object(dev, "ROOT", Path(directory)):
            log = dev.log_path("API")
            log.parent.mkdir()
            log.write_text("hidden\n" + "\n".join(str(i) for i in range(36)) + "\n")
            with patch.object(dev, "VERBOSE", False), contextlib.redirect_stderr(output):
                dev.show_log("API", {})
        self.assertNotIn("hidden", output.getvalue())
        self.assertIn("35", output.getvalue())

    def test_cli_reports_setup_errors(self):
        output = io.StringIO()
        with patch.object(dev, "main", side_effect=dev.SetupError("actionable reason")), \
             patch.object(dev, "VERBOSE", False), contextlib.redirect_stderr(output):
            self.assertEqual(dev.cli(), 1)
        self.assertIn("actionable reason", output.getvalue())


if __name__ == "__main__":
    unittest.main()
