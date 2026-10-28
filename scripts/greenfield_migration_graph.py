"""Inert AST discovery and immutable source snapshots for local startup.

Discovery never imports a migration, Alembic env.py or application settings.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import re
from dataclasses import dataclass
from pathlib import Path

BASELINE = "100_greenfield_uuid_final"
IMMUTABLE = {
    "100_greenfield_uuid_final": "365f64b4561c5475a9ebbc2162c49bb147beb3e3796ce942adb303fc5c8835fc",
    "101_iam_user_public_uuid": "8c97790e5341e10823933dc2372fe0c351b24c96f54328af10b2ec9992ae630d",
    "102_public_membership_grant_analysis_uuid": "f8b049eebc7a7cccf07029fff26336936512024372bd729127233f5e46739d06",
}


class DiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class Revision:
    revision: str
    parent: str | None
    path: Path
    sha256: str
    startup: dict | None


@dataclass(frozen=True)
class Graph:
    revisions: tuple[Revision, ...]

    @property
    def head(self):
        return self.revisions[-1].revision

    def pending(self, current):
        ids = [r.revision for r in self.revisions]
        if current not in ids or ids.index(current) < ids.index(BASELINE):
            raise DiscoveryError("Database is not an accepted Greenfield baseline/descendant; no replay or stamping.")
        return self.revisions[ids.index(current) + 1 :]


def discover(root):
    found = {}
    for path in sorted((Path(root) / "alembic/versions").glob("*.py")):
        if path.name == "__init__.py":
            continue
        if path.is_symlink() or not path.is_file():
            raise DiscoveryError("Migration source must be a regular non-symlink file.")
        raw = path.read_bytes()
        tree = ast.parse(raw, filename=path.name)
        fields = {}
        for node in tree.body:
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {
                    "revision",
                    "down_revision",
                    "branch_labels",
                    "depends_on",
                    "startup",
                }:
                    if target.id in fields:
                        raise DiscoveryError("Duplicate migration declaration: " + path.name)
                    try:
                        fields[target.id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError) as exc:
                        raise DiscoveryError("Migration declarations must be literal: " + path.name) from exc
        revision = fields.get("revision")
        parent = fields.get("down_revision")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9]{3,6}_[a-z0-9_]+", revision):
            raise DiscoveryError("Invalid migration revision declaration: " + path.name)
        if "down_revision" not in fields or (parent is not None and not isinstance(parent, str)):
            raise DiscoveryError("Only a single linear migration ancestor is supported.")
        if fields.get("branch_labels") is not None or fields.get("depends_on") is not None or revision in found:
            raise DiscoveryError("Duplicate/branched/dependent migration graph is not supported.")
        digest = hashlib.sha256(raw).hexdigest()
        if revision in IMMUTABLE and digest != IMMUTABLE[revision]:
            raise DiscoveryError("Frozen Greenfield migration changed: " + revision)
        found[revision] = Revision(revision, parent, path, digest, fields.get("startup"))
    if BASELINE not in found or any(r.parent is not None and r.parent not in found for r in found.values()):
        raise DiscoveryError("Missing baseline or migration ancestor.")
    roots = [r for r in found.values() if r.parent is None]
    if len(roots) != 1:
        raise DiscoveryError("Expected exactly one migration root.")
    chain = [roots[0]]
    while True:
        children = [r for r in found.values() if r.parent == chain[-1].revision]
        if len(children) > 1:
            raise DiscoveryError("Multiple migration heads/branches; resolve before startup.")
        if not children:
            break
        if children[0] in chain:
            raise DiscoveryError("Migration cycle.")
        chain.extend(children)
    if len(chain) != len(found):
        raise DiscoveryError("Disconnected or cyclic migration graph.")
    return Graph(tuple(chain))


def source_snapshot(root):
    root = Path(root)
    files = {}
    for directory in ("app", "scripts", "alembic/versions"):
        for path in sorted((root / directory).rglob("*.py")):
            if path.is_symlink() or not path.is_file():
                raise DiscoveryError("Runtime source symlinks are not permitted during an upgrade.")
            files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    dependencies = {name: importlib.metadata.version(name) for name in ("SQLAlchemy", "psycopg", "alembic")}
    return {"files": files, "dependencies": dependencies}


@dataclass(frozen=True)
class SourceLock:
    root: Path
    original_json: bytes

    @classmethod
    def capture(cls, root):
        return cls(Path(root), json.dumps(source_snapshot(root), sort_keys=True, separators=(",", ":")).encode())

    @property
    def sha256(self):
        return hashlib.sha256(self.original_json).hexdigest()

    def verify(self):
        current = json.dumps(source_snapshot(self.root), sort_keys=True, separators=(",", ":")).encode()
        if current != self.original_json:
            raise DiscoveryError(
                "Migration/application source or installed dependencies changed after review; restart preflight."
            )
        discover(self.root)  # preserve frozen-history and graph checks too
