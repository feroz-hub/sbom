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
        description="Git worktree inventory, isolated-instance proposals and separately consented preparation.",
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
        "--scope",
        choices=("registry", "dependencies", "administrator", "provider"),
        help="Preparation category; administrator guidance cannot execute enrollment",
    )
    parser.add_argument(
        "--provider-policy", type=Path,
        help="Explicit proposed provider JSON; never supplies company or resource authorization",
    )
    parser.add_argument("--port-min", type=int, default=20000)
    parser.add_argument("--port-max", type=int, default=29999)
    parser.add_argument(
        "--suite",
        choices=("unit", "database", "integration", "migrations", "all"),
        help="Test category; data suites remain separately gated",
    )
    parser.add_argument("--plan", action="store_true", help="Inspect a workspace test plan without executing it")
    parser.add_argument("--baseline", type=Path, help="Git-listed baseline worktree for source comparison")
    parser.add_argument(
        "--service", choices=("setup", "api", "frontend", "worker", "reports", "beat", "postgres", "redis", "mailpit")
    )
    parser.add_argument(
        "--lines", type=int, default=80, help="Bounded log metadata records (1..200), never message text"
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Follow verified local log metadata for at most 30 seconds; JSON is newline-delimited",
    )
    parser.add_argument(
        "--host",
        action="store_true",
        help="Optional read-only CPU/home-filesystem disk observation; no readiness approval",
    )
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


def _dependency_plan(args, root):
    if any(
        (
            args.mode,
            args.auth,
            args.provider,
            args.generation is not None,
            args.port_min != 20000,
            args.port_max != 29999,
        )
    ):
        _fail("WORKSPACE_DEPENDENCY_INSTANCE_OPTIONS_REFUSED")
    if __package__:
        from . import dev_workspace_dependencies
    else:
        import dev_workspace_dependencies
    snapshot = dev_workspace.discover_workspaces(root)
    if snapshot.status != "PASS":
        _fail("WORKSPACE_INVENTORY_INCOMPLETE")
    selected = _select(snapshot, root, args.worktree)
    hashes = _manifest_hashes(selected.root, selected.identity, snapshot.root, snapshot.identity)
    plan = dev_workspace_dependencies.inspect_dependencies(snapshot, selected, manifest_hashes=hashes)
    fingerprint = hashlib.sha256(
        json.dumps(
            {"dependency_plan": plan.fingerprint, "controller_inputs": hashes},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    public = {
        "category": "software-dependencies",
        "worktree_id": selected.worktree_id,
        "repository_id": snapshot.repository_id,
        "commit": selected.head,
        "actions": list(plan.actions),
        "blockers": list(plan.blockers),
        "tool_versions": dict(plan.tool_versions),
        "fingerprint": fingerprint,
        "private_configuration_required": False,
        "package_sources": ["https://pypi.org/simple", "https://registry.npmjs.org"],
    }
    return plan, public


def _print_dependency_plan(public, as_json):
    if as_json:
        print(json.dumps(public, sort_keys=True))
        return
    print(f"[PLANNED] software-dependencies; worktree {public['worktree_id']}; commit {public['commit']}")
    print(f"[PLANNED] fingerprint {public['fingerprint']}")
    print("[INFO] Private configuration is not required. No database or application is contacted.")
    print(
        "[INFO] Binary Python packages from pypi.org; locked npm packages from registry.npmjs.org; install scripts disabled."
    )
    for action in public["actions"]:
        print(f"[NEEDS APPROVAL] {action}; independent writable dependencies, no shared mutable environment.")
    for code in public["blockers"]:
        print(f"[BLOCKED] {code}; preserve existing artifacts for review.")


def _prepare_dependencies(args, root):
    if __package__:
        from . import dev_workspace_dependencies
    else:
        import dev_workspace_dependencies
    plan, public = _dependency_plan(args, root)
    _print_dependency_plan(public, args.json)
    if plan.blockers:
        return 1
    if args.json or not sys.stdin.isatty() or not sys.stdout.isatty():
        _fail("WORKSPACE_DEPENDENCY_APPROVAL_REQUIRED")
    deadline = time.monotonic() + 120
    literal = "DEPENDENCIES " + public["fingerprint"]
    response = input(
        f"Review workstation package-source policy. Only this worktree's dependencies will be prepared. Type {literal}: "
    )
    if response != literal or time.monotonic() > deadline:
        _fail("WORKSPACE_DEPENDENCY_APPROVAL_REQUIRED")

    def authorize(candidate):
        _, current = _dependency_plan(args, root)
        if candidate is not plan or current != public or time.monotonic() > deadline:
            raise dev_workspace_dependencies.DependencyError("DEPENDENCY_PLAN_CHANGED") from None
        return True

    outcome = dev_workspace_dependencies.prepare_dependencies(plan, authorize=authorize)
    print(
        f"[{'PASS' if outcome.exit_code == 0 else 'BLOCKED'}] {outcome.code}; prepared={','.join(outcome.prepared) or 'none'}; verified={','.join(outcome.skipped) or 'none'}."
    )
    if outcome.artifacts_retained:
        print(
            "[INFO] Owned preparation artifacts were retained; no automatic repair or deletion. Review dependency plan before retrying."
        )
    return outcome.exit_code


def _dependency_observation(snapshot, selected):
    """Public software inspection only; no installation or package-readiness claim."""
    if __package__:
        from . import dev_workspace_dependencies
    else:
        import dev_workspace_dependencies
    try:
        hashes = _manifest_hashes(selected.root, selected.identity, snapshot.root, snapshot.identity)
        plan = dev_workspace_dependencies.inspect_dependencies(snapshot, selected, manifest_hashes=hashes)
        code = (
            plan.blockers[0]
            if plan.blockers
            else (
                "DEPENDENCY_PREPARATION_REQUIRED"
                if any(value is None for value in plan.target_stamps.values())
                else "DEPENDENCY_PACKAGE_VERIFICATION_REQUIRED"
            )
        )
        return {
            "status": "BLOCKED" if plan.blockers or code == "DEPENDENCY_PREPARATION_REQUIRED" else "WARN",
            "code": code,
            "tool_versions": dict(plan.tool_versions),
            "actions": list(plan.actions),
            "package_verification_performed": False,
            "compiler_verified": False,
        }
    except Exception:
        return {
            "status": "BLOCKED",
            "code": "WORKSPACE_PUBLIC_SOFTWARE_INSPECTION_UNVERIFIED",
            "package_verification_performed": False,
            "compiler_verified": False,
        }


def _inventory(root, as_json=False, requested=None, *, diagnostic=False, include_host=False, inspect_software=False):
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
        if diagnostic:
            if __package__:
                from . import dev_workspace_observe
            else:
                import dev_workspace_observe
            report = (
                dev_workspace_observe.diagnose_instance(entry.descriptor, include_host=include_host)
                if entry
                else dev_workspace_observe.diagnose_unregistered(include_host=include_host)
            )
            rows[-1]["diagnostics"] = report.to_dict()
            if inspect_software:
                rows[-1]["dependency_observation"] = _dependency_observation(snapshot, item)
    result = {
        "version": 1,
        "repository_id": snapshot.repository_id,
        "status": "BLOCKED" if diagnostic else snapshot.status,
        "git_status": snapshot.status,
        "application_readiness_verified": False,
        "codes": list(snapshot.codes),
        "registry_codes": list(records.codes),
        "discovered_worktree_count": len(snapshot.worktrees),
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
            for check in row.get("diagnostics", {}).get("results", []):
                print(f"[{check['status']}] {check['category']}: {check['code']}")
            if row.get("diagnostics", {}).get("host"):
                print("[INFO] Host observations: " + json.dumps(row["diagnostics"]["host"], sort_keys=True))
            if software := row.get("dependency_observation"):
                print(
                    f"[{software['status']}] software: {software['code']}; package/compiler readiness remains unverified."
                )
        for code in records.codes:
            print(
                f"[{'MISSING' if code == 'REGISTRY_MISSING' else 'BLOCKED'}] {code}; preserve records and review workspace plan."
            )
        print(
            "[INFO] Resource/runtime identities are not verified by Git or a registry descriptor. No service was contacted."
        )
        if diagnostic:
            print(
                "[NEXT] Review workspace plan and dependency plan. Approved read adapters are required before application readiness can be verified."
            )
    return 1 if diagnostic or snapshot.status != "PASS" or records.codes not in {(), ("REGISTRY_MISSING",)} else 0


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


def _registered_instance(args, root):
    snapshot = dev_workspace.discover_workspaces(root)
    if snapshot.status != "PASS":
        _fail("WORKSPACE_INVENTORY_INCOMPLETE")
    selected = _select(snapshot, root, args.worktree)
    records = _registry(snapshot).read()
    if records.codes:
        _fail(
            "WORKSPACE_INSTANCE_REGISTRATION_REQUIRED" if records.codes == ("REGISTRY_MISSING",) else records.codes[0]
        )
    entry = next((row for row in records.entries if row.descriptor.worktree_id == selected.worktree_id), None)
    if entry is None:
        _fail("WORKSPACE_INSTANCE_REGISTRATION_REQUIRED")
    return snapshot, selected, entry


def _lifecycle_blocked(args, root):
    if any(
        (
            args.scope,
            args.mode,
            args.auth,
            args.provider,
            args.generation is not None,
            args.port_min != 20000,
            args.port_max != 29999,
        )
    ):
        _fail("WORKSPACE_PREPARED_SELECTION_REQUIRED")
    if __package__:
        from . import dev_workspace_lifecycle
    else:
        import dev_workspace_lifecycle
    _, selected, entry = _registered_instance(args, root)
    if args.command != "stop" and entry.descriptor.commit != selected.head:
        _fail("WORKSPACE_INSTANCE_SOURCE_CHANGED")
    codes = dev_workspace_lifecycle.live_execution_blockers()
    code = "INSTANCE_RUNTIME_ADAPTER_REQUIRED" if args.command == "stop" else codes[0]
    result = {
        "status": "BLOCKED",
        "code": code,
        "blockers": list(codes),
        "instance_id": entry.descriptor.instance_id,
        "runtime_ownership_verified": False,
        "component": "instance-lifecycle",
        "process_status": "UNVERIFIED",
        "proposed_log_path": str(Path.home() / ".sbom-dev/instances" / entry.descriptor.instance_id / ".dev-logs"),
        "log_created": False,
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"[BLOCKED] {code}; instance {entry.descriptor.instance_id}; runtime ownership unverified.")
        for reason in codes:
            print(f"[BLOCKED] {reason}; reviewed company provider policy and concrete verified adapters are required.")
        print(
            f"[INFO] Proposed log directory {_path(result['proposed_log_path'])}; no application was started or stopped."
        )
        print(
            "[NEXT] Preserve records/resources. Existing profile-managed applications must be stopped through their original launcher from their own checkout."
        )
    return 1


def _onboarding_guidance(args, root):
    if __package__:
        from . import dev_workspace_onboarding
    else:
        import dev_workspace_onboarding
    plan, _, _ = _make_plan(args, root)
    if plan.descriptor.mode != "isolated":
        _fail("ONBOARDING_ISOLATED_INSTALLATION_REQUIRED")
    overview = dev_workspace_onboarding.uninspected_guidance(plan.descriptor.auth_mode)
    public = overview.to_dict()
    public["instance_id"] = plan.descriptor.instance_id
    public["proposed_origin"] = plan.descriptor.origin
    if args.json:
        print(json.dumps(public, sort_keys=True))
    else:
        print(f"[BLOCKED] {public['code']}; {public['state']}; no installation status inspection was performed.")
        for step in public["steps"]:
            print(f"[NEXT] {step['guidance']}")
        print("[INFO] This command requests no identity details or password and performs no privileged action.")
    return 1


def _test_command(args, root):
    if any(
        (
            args.scope,
            args.mode,
            args.auth,
            args.provider,
            args.generation is not None,
            args.port_min != 20000,
            args.port_max != 29999,
        )
    ):
        _fail("WORKSPACE_TEST_SELECTION_INVALID")
    if __package__:
        from . import dev_workspace_tests
    else:
        import dev_workspace_tests
    suite = args.suite or "unit"
    if suite == "unit":
        snapshot = dev_workspace.discover_workspaces(root)
        if snapshot.status != "PASS":
            _fail("WORKSPACE_INVENTORY_INCOMPLETE")
        selected = _select(snapshot, root, args.worktree)
        plan = dev_workspace_tests.plan_tests(selected.root, worktree_id=selected.worktree_id, suite=suite)
    else:
        plan = dev_workspace_tests.plan_tests(root, suite=suite)
    if args.plan or plan.blockers:
        if args.json:
            print(json.dumps(plan.to_dict(), sort_keys=True))
        else:
            print(
                f"[PLANNED] {suite} category; only the limited pure-contract unit suite is available. No application conftest or database authority."
            )
            for code in plan.blockers:
                print(
                    f"[BLOCKED] {code}; use the dependency plan or obtain exact disposable-target review as appropriate."
                )
        return 1 if plan.blockers else 0
    outcome = dev_workspace_tests.run_tests(plan)
    if args.json:
        print(json.dumps(outcome.to_dict(), sort_keys=True))
    else:
        print(f"[{'PASS' if outcome.exit_code == 0 else 'BLOCKED'}] {outcome.code}; raw child output is withheld.")
        print(json.dumps(outcome.to_dict(), sort_keys=True))
        if outcome.retained_directory is not None:
            print(
                f"[INFO] Owned test artifacts retained at {_path(outcome.retained_directory)}; no automatic deletion."
            )
    return outcome.exit_code


def _observation_selection(args):
    if any(
        (
            args.scope,
            args.mode,
            args.auth,
            args.provider,
            args.generation is not None,
            args.port_min != 20000,
            args.port_max != 29999,
        )
    ):
        _fail("WORKSPACE_READ_ONLY_OPTIONS_REQUIRED")


def _compare_command(args, root):
    _observation_selection(args)
    if args.baseline is None:
        _fail("WORKSPACE_BASELINE_REQUIRED")
    if __package__:
        from . import dev_workspace_observe
    else:
        import dev_workspace_observe
    snapshot = dev_workspace.discover_workspaces(root)
    baseline = _listed_target(snapshot, root, args.baseline)
    candidate = _listed_target(snapshot, root, args.worktree)
    records = _registry(snapshot).read()
    report = dev_workspace_observe.compare_workspaces(snapshot, baseline.worktree_id, candidate.worktree_id, records)
    print(json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=True))
    if not args.json:
        print(
            "[INFO] Source/public proposal comparison only. Runtime, API compatibility, screenshots and visual acceptance remain unverified."
        )
    return 1 if report.status == "BLOCKED" else 0


def _logs_command(args, root):
    _observation_selection(args)
    if not 1 <= args.lines <= 200:
        _fail("WORKSPACE_LOG_LIMIT_INVALID")
    if __package__:
        from . import dev_workspace_observe
    else:
        import dev_workspace_observe
    _, _, entry = _registered_instance(args, root)
    deadline, previous = time.monotonic() + 30, None
    try:
        while True:
            report = dev_workspace_observe.observe_logs(
                entry.descriptor.instance_id, args.service or "api", max_lines=args.lines
            )
            public = report.to_dict()
            if public != previous:
                print(json.dumps(public, sort_keys=True), flush=True)
                if not args.json:
                    print(
                        "[INFO] Log metadata only; message bodies are withheld. This is not verified process readiness."
                    )
                    if report.local_path is not None:
                        print(
                            f"[INFO] Open the verified local file privately for full content: {_path(report.local_path)}"
                        )
                previous = public
            if not args.follow or report.status != "OBSERVED" or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        return 130
    return 1 if report.status == "BLOCKED" else 0


def _provider_command(args, root):
    """Inspect only. Engine execution needs independent policy and target consent."""
    if __package__:
        from . import dev_workspace_provider_input
    else:
        import dev_workspace_provider_input
    if args.command == "prepare":
        _fail("PROVIDER_EXACT_TARGET_AUTHORIZATION_REQUIRED")
    plan, _, _ = _make_plan(args, root)
    if args.provider_policy is None:
        public = {
            "status": "BLOCKED", "code": "PROVIDER_POLICY_SELECTION_REQUIRED",
            "engine_on_path": shutil.which("docker") is not None,
            "podman_on_path": shutil.which("podman") is not None,
            "engine_probed": False, "live_authorized": False,
            "database_authorized": False, "ownership_verified": False,
        }
    else:
        source = args.provider_policy.absolute()
        before = source.lstat()
        if (source.is_symlink() or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1 or getattr(before, "st_file_attributes", 0) & 0x400):
            _fail("PROVIDER_POLICY_FILE_UNVERIFIED")
        raw = dev_environment.bounded_read_bytes(source, 65536)
        after = source.lstat()
        def stamp(value):
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
        if stamp(before) != stamp(after):
            _fail("PROVIDER_POLICY_FILE_CHANGED")
        provider, manifest = dev_workspace_provider_input.parse_policy(raw, plan.descriptor)
        public = {
            "status": "BLOCKED", "code": "PROVIDER_RUNTIME_CONTRACT_REVIEW_REQUIRED",
            "provider": provider.to_dict(), "compose": manifest.to_dict(),
            "engine_probed": False, "live_authorized": False,
            "database_authorized": False, "ownership_verified": False,
        }
    if args.json:
        print(json.dumps(public, sort_keys=True))
    else:
        print(f"[BLOCKED] {public['code']}; review policy, images, nonroot contracts and exact disposable targets.")
        print("[INFO] No engine, secret file, provider resource or database was accessed.")
    return 1


def run_cli(argv, root):
    args = _parser().parse_args(argv)
    try:
        if args.provider_policy is not None and (args.scope != "provider" or args.command != "plan"):
            _fail("WORKSPACE_PROVIDER_OPTIONS_REQUIRED")
        if (
            (args.baseline is not None and args.command != "compare")
            or ((args.service or args.follow or args.lines != 80) and args.command != "logs")
            or (args.host and args.command not in {"status", "diagnose"})
        ):
            _fail("WORKSPACE_OBSERVATION_OPTIONS_REQUIRED")
        if args.command != "test" and (args.plan or args.suite):
            _fail("WORKSPACE_TEST_OPTIONS_REQUIRED")
        if args.command == "test":
            return _test_command(args, root)
        if args.command == "compare":
            return _compare_command(args, root)
        if args.command == "logs":
            return _logs_command(args, root)
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
            return _inventory(
                root,
                args.json,
                selected,
                diagnostic=args.command != "list",
                include_host=args.host,
                inspect_software=args.command == "diagnose",
            )
        if args.command == "plan":
            if args.scope == "provider":
                return _provider_command(args, root)
            if args.scope == "administrator":
                return _onboarding_guidance(args, root)
            if args.scope == "dependencies":
                _, public = _dependency_plan(args, root)
                _print_dependency_plan(public, args.json)
                return 1 if public["blockers"] else 0
            if args.scope:
                _fail("WORKSPACE_READ_ONLY_OPTIONS_REQUIRED")
            plan, _, _ = _make_plan(args, root)
            _print_plan(plan, args.json)
            return 1 if plan.blockers else 0
        if args.command == "prepare":
            if args.scope == "provider":
                return _provider_command(args, root)
            if args.scope == "administrator":
                return _onboarding_guidance(args, root)
            if args.scope == "dependencies":
                return _prepare_dependencies(args, root)
            return _prepare_registry(args, root)
        if args.command in {"start", "stop", "restart"}:
            return _lifecycle_blocked(args, root)
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
    # Presence chooses guidance only; it never proves artifact ownership or
    # dependency freshness. Existing unmanaged venv-only checkouts keep dispatch.
    if any(
        (root / ".venv" / name).exists()
        for name in (
            ".sbom-workspace-dependencies.json",
            ".sbom-workspace-dependency-attempt",
        )
    ):
        return True
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
    print(f"[INFO] Platform {sys.platform}; Python interpreter {64 if sys.maxsize > 2**32 else 32}-bit.")
    _inventory(root, requested=root, diagnostic=True, include_host=True, inspect_software=True)
    print("[NEXT] Inspect all worktrees with python scripts/dev.py workspace list.")
    print("[NEXT] Choose an instance plan: python scripts/dev.py workspace plan --mode isolated --auth native")
    print(
        "[NEXT] Dependency preparation, provider resources, database operations and TLS trust have separate approval scopes."
    )
    return 1
