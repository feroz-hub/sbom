"""Preserved manual public-contract audit; outside local runtime management."""
import ast
import unittest
from scripts.dev import GreenfieldStack as setup

class PublicUuidContract(unittest.TestCase):
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
