"""Preview preparation through the public launcher, with category-specific consent."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

if __package__:
    from . import dev_environment, dev_workspace, dev_workspace_cli, dev_workspace_preview
else:
    import dev_environment
    import dev_workspace
    import dev_workspace_cli
    import dev_workspace_preview


def _fail(code):
    raise dev_workspace_preview.PreviewError(code) from None


def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            _fail("PREVIEW_SETTINGS_INVALID")
        result[name] = value
    return result


def inspect(args, root):
    """Existing TLS/dependency metadata only; no Node or network invocation."""
    plan, _, _ = dev_workspace_cli._make_plan(args, root)
    if plan.descriptor.mode not in {"mock", "shared-backend"}:
        _fail("PREVIEW_MODE_SELECTION_REQUIRED")
    if args.preview_settings is None:
        _fail("PREVIEW_EXISTING_TLS_AND_NODE_SELECTION_REQUIRED")
    try:
        source = Path(args.preview_settings).absolute()
        before = source.lstat()
        raw = dev_environment.bounded_read_bytes(source, 32768)
        after = source.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail("PREVIEW_SETTINGS_CHANGED")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        if (
            type(data) is not dict
            or set(data) != {"version", "node", "tls", "shared_backend"}
            or type(data["version"]) is not int
            or data["version"] != 1
            or type(data["node"]) is not str
            or not Path(data["node"]).is_absolute()
            or type(data["tls"]) is not dict
            or set(data["tls"]) != {"certificate", "private_key", "ca_bundle"}
            or any(type(value) is not str for value in data["tls"].values())
        ):
            _fail("PREVIEW_SETTINGS_INVALID")
        shared = data["shared_backend"]
        if shared is not None:
            if type(shared) is not dict or set(shared) != {
                "registration_id",
                "origin",
                "tenant_id",
                "frontend_origin",
                "auth_mode",
                "non_production",
            }:
                _fail("PREVIEW_SETTINGS_INVALID")
            shared = dev_workspace_preview.SharedBackendRegistration(**shared)
        snapshot = dev_workspace.discover_workspaces(root)
        selected = dev_workspace_cli._select(snapshot, root, args.worktree)
        return dev_workspace_preview.plan_preview(
            snapshot,
            selected,
            plan.descriptor,
            state_anchor=Path.home(),
            node_executable=Path(data["node"]),
            tls=dev_workspace_preview.PreviewTls(**{key: Path(value) for key, value in data["tls"].items()}),
            shared_backend=shared,
        )
    except dev_workspace_preview.PreviewError:
        raise
    except Exception:
        _fail("PREVIEW_SETTINGS_INVALID")


def _print(plan, as_json):
    if as_json:
        print(json.dumps(plan.to_dict(), sort_keys=True))
    else:
        print(f"[PLANNED] {plan.descriptor.mode}; {plan.descriptor.origin}; preview {plan.fingerprint}")
        print(
            "[INFO] Preparation uses existing TLS files and selected-worktree dependencies. Runtime verification is still required."
        )
        if plan.shared_backend is not None:
            print("[WARN] Frontend actions can mutate the registered non-production backend and permitted tenant.")


def run(args, root):
    plan = inspect(args, root)
    if args.command == "plan":
        _print(plan, args.json)
        return 0
    if args.command != "prepare":
        _fail("PREVIEW_PREPARATION_OPTIONS_REQUIRED")
    if os.path.lexists(plan.workspace.parent):
        # Valid owned preparation is reusable without repeated mutation consent.
        dev_workspace_preview.require_preview(plan)
        if args.json:
            print(json.dumps({**plan.to_dict(), "preparation_verified": True}, sort_keys=True))
        else:
            print("[PASS] PREVIEW_PREPARATION_VERIFIED; no files changed or process started.")
        return 0
    if args.json or not sys.stdin.isatty() or not sys.stdout.isatty():
        _fail("PREVIEW_CATEGORY_APPROVAL_REQUIRED")
    _print(plan, False)
    deadline = time.monotonic() + 120
    literal = "PREVIEW " + plan.fingerprint
    response = input(
        f"Create only this preview's protected files/links, using existing TLS and dependencies. Type {literal}: "
    )
    if response != literal or time.monotonic() > deadline:
        _fail("PREVIEW_CATEGORY_APPROVAL_REQUIRED")

    def authorize(candidate):
        if candidate is not plan or time.monotonic() > deadline or inspect(args, root) != plan:
            _fail("PREVIEW_PLAN_CHANGED")
        return True

    dev_workspace_preview.prepare_preview(plan, authorize=authorize)
    print("[PASS] PREVIEW_PREPARED; no service, installer, certificate trust or database operation ran.")
    return 0
