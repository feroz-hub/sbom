"""Database-free CLI regression checks; also runnable with unittest directly.

Run: python -m unittest discover -s tests -p test_alembic_metadata_commands.py -v
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AlembicMetadataCommandsTest(unittest.TestCase):
    def run_alembic(self, *args: str, database_url: str | None = None):
        env = {key: value for key, value in os.environ.items() if key.upper() != "DATABASE_URL"}
        env["ALLOW_SQLITE"] = "false"
        env["PYTHONPATH"] = str(ROOT)
        if database_url is not None:
            env["DATABASE_URL"] = database_url
        # A fresh cwd isolates Settings' .env lookup. Disable python-dotenv's
        # source-relative lookup too, without altering production configuration.
        launcher = """
import sys
import dotenv
dotenv.load_dotenv = lambda *args, **kwargs: False
from alembic.config import main
main(argv=sys.argv[1:])
"""
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "alembic.ini"
            config.write_text(
                (ROOT / "alembic.ini").read_text().replace(
                    "script_location = alembic", f"script_location = {ROOT / 'alembic'}"
                )
            )
            return subprocess.run(
                [sys.executable, "-c", launcher, "-c", str(config), *args],
                cwd=directory,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )

    def test_heads_without_database_url(self):
        result = self.run_alembic("heads")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(head)", result.stdout)

    def test_history_without_database_url(self):
        result = self.run_alembic("history")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("<base> -> 001_initial_schema", result.stdout)

    def test_database_commands_fail_closed_without_database_url(self):
        for args in (("current",), ("upgrade", "head")):
            with self.subTest(command=args):
                result = self.run_alembic(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("DATABASE_URL is not configured", result.stderr)

    def test_database_commands_reject_postgres_url_without_password(self):
        for args in (("current",), ("upgrade", "head")):
            with self.subTest(command=args):
                result = self.run_alembic(*args, database_url="postgresql://user@localhost/test")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("PostgreSQL DATABASE_URL without password", result.stderr)
