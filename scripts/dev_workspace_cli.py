"""Workspace inventory/plans via dev.py, never implicit provider preparation.

The initial registry writer records public proposals only. It grants no process,
provider, database, certificate, trust or administrator authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path

if __package__:
    from . import dev_environment, dev_instance_plan, dev_instance_registry, dev_private, dev_workspace
else:
    import dev_environment
    import dev_instance_plan
    import dev_instance_registry
    import dev_private
    import dev_workspace


class WorkspaceCommandError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class _SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "[BLOCKED] WORKSPACE_ARGUMENTS_INVALID; use workspace --help. Argument values are withheld.\n")


def _fail(code):
    raise WorkspaceCommandError(code) from None


def _path(value):
    return json.dumps(str(value), ensure_ascii=True)


def _parser():
    parser = _SafeParser(
        prog="python scripts/dev.py workspace",
        description="Read-only Git worktree inventory and isolated-instance proposals.",
        epilog="Plans/registry identities are not resource ownership or privileged authorization. Existing services are never adopted.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="list",
        choices=(
            "list",
            "plan",
            "prepare",
            "start",
            "stop",
            "restart",
            "status",
            "diagnose",
            "logs",
            "test",
            "compare",
        ),
    )
    parser.add_argument("--worktree", type=Path, help="Select a path from authoritative Git worktree discovery")
    parser.add_argument(
        "--json", action="store_true", help="Public metadata only; no environment or private configuration"
    )
    parser.add_argument("--mode", choices=("isolated", "mock", "shared-backend"))
    parser.add_argument(
        "--auth", choices=("native", "hcl"), help="Explicit new-instance mode; never converts an installation"
    )
    parser.add_argument("--provider", choices=("container", "local", "mock", "shared"))
    parser.add_argument(
        "--generation", type=int, help="Explicit public configuration generation; changes invalidate the plan"
    )
    parser.add_argument(
        "--scope", choices=("registry", "dependencies"), help="Preparation category; resource gates remain separate"
    )
    parser.add_argument("--port-min", type=int, default=20000)
    parser.add_argument("--port-max", type=int, default=29999)
    return parser


def _registry(snapshot):
    if snapshot.repository_id is None or snapshot.common_directory is None:
        _fail("WORKSPACE_REPOSITORY_UNVERIFIED")
    _verify_directory(snapshot.common_directory)
    # Keep instance metadata separate from potentially shared Git-directory ACLs.
    # Git's common-directory identity still binds the repository namespace.
    anchor = Path.home().resolve(strict=True)
    return dev_instance_registry.InstanceRegistry(
        anchor / ".sbom-dev" / "repositories" / snapshot.repository_id / "instances",
        anchor=anchor,
        repository_id=snapshot.repository_id,
    )


def _listed_target(snapshot, root, requested):
    try:
        candidate = Path(requested or root).absolute()
        known = {
            os.path.normcase(str(path))
            for item in snapshot.worktrees
            for path in (item.root, item.identity.canonical_path if item.identity else item.root)
        }
        if os.path.normcase(str(candidate)) not in known:
            _fail("WORKSPACE_TARGET_BLOCKED")
        selected = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        _fail("WORKSPACE_TARGET_UNVERIFIED")
    rows = [item for item in snapshot.worktrees if item.identity and item.identity.canonical_path == selected]
    if len(rows) != 1:
        _fail("WORKSPACE_TARGET_BLOCKED")
    return rows[0]


def _select(snapshot, root, requested):
    row = _listed_target(snapshot, root, requested)
    if row.status != "PASS" or row.locked or row.prunable or row.bare:
        _fail("WORKSPACE_TARGET_BLOCKED")
    if row.head is None or row.worktree_id is None:
        _fail("WORKSPACE_TARGET_UNVERIFIED")
    return row


def _verify_directory(identity):
    info = identity.canonical_path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & 1024
        or (info.st_dev, info.st_ino) != (identity.device, identity.inode)
    ):
        _fail("WORKSPACE_FILESYSTEM_CHANGED")


_CONTROLLER_SOURCES = (
    "scripts/dev.py",
    "scripts/dev_workspace.py",
    "scripts/dev_workspace_cli.py",
    "scripts/dev_instance_plan.py",
    "scripts/dev_instance_registry.py",
    "scripts/dev_instance_storage.py",
)


def _manifest_hashes(root, identity, controller_root, controller_identity):
    result = {}
    inputs = [
        (root, identity, name, name)
        for name in ("requirements.txt", "frontend/package.json", "frontend/package-lock.json")
    ]
    inputs += [(controller_root, controller_identity, name, "controller/" + name) for name in _CONTROLLER_SOURCES]
    for anchor, pinned, name, label in inputs:
        try:
            _verify_directory(pinned)
            dev_private.validate_parent(anchor / name, anchor)
            result[label] = hashlib.sha256(dev_environment.bounded_read_bytes(anchor / name, 8388608)).hexdigest()
            dev_private.validate_parent(anchor / name, anchor)
            _verify_directory(pinned)
        except Exception:
            _fail("WORKSPACE_PUBLIC_MANIFEST_UNVERIFIED")
    return result


def _make_plan(args, root):
    snapshot = dev_workspace.discover_workspaces(root)
    if snapshot.status != "PASS":
        _fail("WORKSPACE_INVENTORY_INCOMPLETE")
    selected = _select(snapshot, root, args.worktree)
    registry = _registry(snapshot)
    records = registry.read()
    if records.codes and records.codes != ("REGISTRY_MISSING",):
        _fail(records.codes[0])
    existing = next((item for item in records.entries if item.descriptor.worktree_id == selected.worktree_id), None)
    descriptor = existing.descriptor if existing else None
    mode = args.mode or (descriptor.mode if descriptor else None)
    auth = args.auth or (descriptor.auth_mode if descriptor else None)
    if mode is None or auth is None:
        _fail("WORKSPACE_MODE_AUTH_SELECTION_REQUIRED")
    ports = tuple(port for item in records.entries if item is not existing for port in item.descriptor.ports.values())
    plan = dev_instance_plan.plan_instance(
        repository_id=snapshot.repository_id,
        worktree_id=selected.worktree_id,
        commit=selected.head,
        generation=args.generation if args.generation is not None else (descriptor.generation if descriptor else 1),
        mode=mode,
        auth_mode=auth,
        provider=args.provider or (descriptor.provider if descriptor else None),
        manifest_hashes=_manifest_hashes(
            selected.identity.canonical_path, selected.identity, snapshot.identity.canonical_path, snapshot.identity
        ),
        config_generation=descriptor.config_generation if descriptor else None,
        config_present=descriptor.configuration_present if descriptor else False,
        claimed_ports=ports,
        port_range=(args.port_min, args.port_max),
    )
    return plan, registry, existing


def _print_plan(plan, as_json):
    if as_json:
        print(json.dumps(plan.to_dict(), sort_keys=True))
        return
    descriptor = plan.descriptor
    print(f"[PLANNED] {descriptor.mode}; instance {descriptor.instance_id}; commit {descriptor.commit}")
    print(f"[PLANNED] HTTPS origin {descriptor.origin}; ports {json.dumps(dict(descriptor.ports), sort_keys=True)}")
    print(f"[PLANNED] fingerprint {plan.fingerprint}")
    for action in plan.actions:
        dependency = (
            "independent of private configuration"
            if not action.requires_configuration
            else "requires validated configuration"
        )
        print(f"[NEEDS APPROVAL] {action.category}: {action.code}; {dependency}")
    for blocker in plan.blockers:
        print(f"[BLOCKED] {blocker.category}: {blocker.code}")
    print(
        "[INFO] Proposed names/ports do not authorize provisioning, binding, migration, trust or administrator enrollment."
    )


def _inventory(root, as_json=False, requested=None):
    snapshot = dev_workspace.discover_workspaces(root)
    records = (
        _registry(snapshot).read()
        if snapshot.repository_id and snapshot.common_directory
        else dev_instance_registry.RegistrySnapshot()
    )
    by_worktree = {entry.descriptor.worktree_id: entry for entry in records.entries}
    rows = []
    worktrees = snapshot.worktrees if requested is None else (_listed_target(snapshot, root, requested),)
    for item in worktrees:
        entry = by_worktree.get(item.worktree_id)
        rows.append(
            {
                "path": str(item.root),
                "worktree_id": item.worktree_id,
                "head": item.head,
                "branch": item.branch,
                "dirty": item.dirty,
                "locked": item.locked,
                "prunable": item.prunable,
                "agent_owner": item.agent_owner,
                "status": item.status,
                "codes": list(item.codes),
                "instance_id": entry.descriptor.instance_id if entry else None,
                "mode": entry.descriptor.mode if entry else None,
                "reported_state": entry.state if entry else "UNREGISTERED",
                "origin": entry.descriptor.origin if entry else None,
                "proposed_ports": dict(entry.descriptor.ports) if entry else {},
                "runtime_ownership": "UNVERIFIED",
                "last_code": entry.last_code if entry else None,
            }
        )
    result = {
        "version": 1,
        "repository_id": snapshot.repository_id,
        "status": snapshot.status,
        "codes": list(snapshot.codes),
        "registry_codes": list(records.codes),
        "worktrees": rows,
    }
    if as_json:
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    else:
        print(f"[{snapshot.status}] Git worktrees: {len(rows)}; agent ownership is not inferred from clean status.")
        for code in snapshot.codes:
            print(f"[BLOCKED] {code}")
        for row in rows:
            print(
                f"[{row['status']}] {_path(row['path'])}; {row['head'] or 'UNKNOWN'}; branch {_path(row['branch'])}; dirty={row['dirty']}; {row['reported_state']}"
            )
            for code in row["codes"]:
                print(f"[BLOCKED] {code}")
        for code in records.codes:
            print(
                f"[{'MISSING' if code == 'REGISTRY_MISSING' else 'BLOCKED'}] {code}; preserve records and review workspace plan."
            )
        print(
            "[INFO] Resource/runtime identities are not verified by Git or a registry descriptor. No service was contacted."
        )
    return 1 if snapshot.status != "PASS" or records.codes not in {(), ("REGISTRY_MISSING",)} else 0


def _prepare_registry(args, root):
    plan, registry, existing = _make_plan(args, root)
    _print_plan(plan, args.json)
    if args.scope != "registry":
        _fail("WORKSPACE_PREPARATION_SCOPE_REQUIRED")
    if args.json or not sys.stdin.isatty() or not sys.stdout.isatty():
        _fail("WORKSPACE_REGISTRY_APPROVAL_REQUIRED")
    deadline = time.monotonic() + 120
    literal = "REGISTER " + plan.descriptor.instance_id
    response = input(f"Only public registry metadata will be written. Type {literal}: ")
    if response != literal or time.monotonic() > deadline:
        _fail("WORKSPACE_REGISTRY_APPROVAL_REQUIRED")
    current, current_registry, current_existing = _make_plan(args, root)
    if current.fingerprint != plan.fingerprint or current_existing != existing:
        _fail("WORKSPACE_PLAN_CHANGED")
    if __package__:
        from .dev_instance_storage import initialize_private_directory
    else:
        from dev_instance_storage import initialize_private_directory
    initialize_private_directory(current_registry.root, anchor=current_registry.anchor)
    revision = current_existing.revision if current_existing else 0
    operations = current_existing.operations if current_existing else ()
    current_registry.publish(
        dev_instance_registry.RegistryEntry(
            current.descriptor,
            revision=revision + 1,
            state="PLANNED",
            plan_fingerprint=current.fingerprint,
            operations=(*operations, "REGISTRY_PREPARED"),
        ),
        expected_revision=revision,
    )
    print(
        "[PASS] WORKSPACE_REGISTRY_PREPARED; public proposal recorded. No application or provider resource was created."
    )
    return 0


def run_cli(argv, root):
    args = _parser().parse_args(argv)
    try:
        if args.command in {"list", "status", "diagnose"}:
            if any(
                (
                    args.mode,
                    args.auth,
                    args.provider,
                    args.generation is not None,
                    args.scope,
                    args.port_min != 20000,
                    args.port_max != 29999,
                )
            ):
                _fail("WORKSPACE_READ_ONLY_OPTIONS_REQUIRED")
            selected = args.worktree or (root if args.command != "list" else None)
            return _inventory(root, args.json, selected)
        if args.command == "plan":
            if args.scope:
                _fail("WORKSPACE_READ_ONLY_OPTIONS_REQUIRED")
            plan, _, _ = _make_plan(args, root)
            _print_plan(plan, args.json)
            return 1 if plan.blockers else 0
        if args.command == "prepare":
            return _prepare_registry(args, root)
        _fail("WORKSPACE_CAPABILITY_NOT_PREPARED")
    except Exception as error:
        code = getattr(error, "code", "WORKSPACE_INSPECTION_FAILED")
        if not isinstance(code, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", code) is None:
            code = "WORKSPACE_INSPECTION_FAILED"
        if args.json:
            print(json.dumps({"status": "BLOCKED", "code": code}))
        else:
            print(f"[BLOCKED] {code}; review workspace plan and retained records. No automatic repair was attempted.")
        return 1


def fresh_checkout(root):
    """Conservative presence-only gate; existing installations keep legacy dispatch."""
    root = Path(root)
    if any(
        path.exists() or path.is_symlink()
        for path in (
            root / ".dev-runtime.json",
            root / ".env.dev.local",
            root / ".env",
            root / ".windows/sbom.env.ps1",
            root / "frontend/.env.local",
        )
    ):
        return False
    return not (root / ".venv").is_dir()


def initial_inventory(root):
    print("[INFO] Unprepared checkout: read-only developer inventory; no application startup was attempted.")
    supported = sys.version_info >= (3, 11)
    print(
        f"[{'PASS' if supported else 'BLOCKED'}] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}; minimum 3.11."
    )
    for name in ("node", "npm"):
        print(
            f"[{'PASS' if shutil.which(name) else 'MISSING'}] {name}; executable discovery only, dependency readiness is not established."
        )
    _inventory(root)
    print("[NEXT] Choose an instance plan: python scripts/dev.py workspace plan --mode isolated --auth native")
    print(
        "[NEXT] Dependency preparation, provider resources, database operations and TLS trust have separate approval scopes."
    )
    return 1
