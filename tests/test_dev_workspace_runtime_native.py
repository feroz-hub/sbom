"""Actual Runtime/Popen cleanup of fixture-only Python helpers, never app readiness.

No database, credentials, TLS material, provider or listening service is created.
The helper modules are in a fresh test source directory, never overlaid on app
modules. Readiness is deliberately synthetic; process ownership/shutdown is native.
"""

import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

from scripts import dev, dev_instance_storage
from scripts import dev_workspace_lifecycle as lifecycle
from scripts import dev_workspace_runtime as adapter


def test_native_partial_startup_cleans_only_verified_fixture_processes(tmp_path, monkeypatch):
    private_errors = []
    original_private_failure = adapter._private_failure

    def private_failure(stage, error=None, **kwargs):
        # Keep native failure evidence numeric/category-only, never raw errors.
        private_errors.append(
            {
                "stage": stage,
                "type": type(error).__name__,
                "errno": getattr(error, "errno", None),
                "winerror": getattr(error, "winerror", None),
            }
        )
        return original_private_failure(stage, error, **kwargs)

    monkeypatch.setattr(adapter, "_private_failure", private_failure)
    fixtures = Path(__file__).with_name("test_dev_workspace_lifecycle.py")
    spec = importlib.util.spec_from_file_location("sbo101_native_pure_fixtures", fixtures)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    descriptor, snapshot = module.prepared(platform=sys.platform)
    home = tmp_path.resolve() / "private fixture home"
    if sys.platform == "win32":
        dev_instance_storage._windows_create(home)
    else:
        home.mkdir(mode=0o700)
    root = home / ".sbom-dev/instances" / descriptor.instance_id
    dev_instance_storage.initialize_private_directory(root, anchor=home)
    source = tmp_path.resolve() / "synthetic source"
    source.mkdir()
    controller_source = str(Path(dev.__file__).resolve().parents[1])
    program = (
        "import os,sys,time\nfrom pathlib import Path\n"
        "sys.path.insert(0," + repr(controller_source) + ")\n"
        "from scripts.dev import windows_shutdown_requested\n"
        "Path(os.environ['SBOM_DEV_STATE_DIR'],str(os.getpid())+'.fixture-ready').touch()\n"
        "while not Path(os.environ['SBOM_DEV_STATE_DIR'],'.fixture-exit').exists() "
        "and not windows_shutdown_requested(os.environ): time.sleep(.05)\n"
    )
    for name in ("celery.py", "uvicorn.py"):
        (source / name).write_text(program, encoding="utf-8")
    old = snapshot.state_root
    environment = {
        key: value.replace(old, str(root)).replace(quote(old, safe=""), quote(str(root), safe=""))
        for key, value in snapshot.environment.items()
    }
    snapshot = replace(snapshot, source_root=str(source), state_root=str(root), environment=environment)
    plan = lifecycle.plan_lifecycle(descriptor, snapshot)
    location = adapter.RuntimeLocation(descriptor, root, home)
    launches = adapter.isolated_launches(
        location, plan, python_executable=Path(sys.executable).resolve(strict=True), frontend=None
    )
    children = []
    runtimes = []

    def owned_popen(*args, **kwargs):
        child = subprocess.Popen(*args, **kwargs)
        children.append(child)
        return child

    def runtime_factory(directory):
        runtime = dev.Runtime(directory)
        runtimes.append(runtime)
        return runtime

    runtime = adapter.WorkspaceRuntime(
        location,
        runtime_factory=runtime_factory,
        atomic_json=dev.atomic_json,
        process_info=dev.process_info,
        matches=dev.matches,
        popen=owned_popen,
    )

    def marker_ready(_launch, _budget):
        return len(tuple((root / ".dev-logs").glob("*.fixture-ready"))) >= len(children)

    def refuse_frontend(_active, _budget):
        # All four native backend helpers reached their workload. No fake TLS or
        # a caller READY marker is accepted as real frontend/application readiness.
        assert len(children) == 4
        raise adapter.RuntimeAdapterError("INSTANCE_FRONTEND_FACTORY_REQUIRED")

    try:
        probes = dict.fromkeys(lifecycle.COMPONENTS, marker_ready)
        outcome = runtime.start(
            launches, preflight=lambda *_: True, probes=probes, frontend_factory=refuse_frontend, timeout=25
        )
        assert outcome.code == "INSTANCE_FRONTEND_FACTORY_REQUIRED", json.dumps(
            {"outcome": outcome.to_dict(), "private_errors": private_errors}
        )
        assert not outcome.ready and not outcome.records_retained
        assert len(children) == 4 and all(child.wait(timeout=10) is not None for child in children)
        assert not (root / ".dev-runtime.json").exists()
        # Exercise the production adapter's pre-module synchronization, not a
        # workload delay hidden inside this fixture's Popen wrapper.
        signals = tuple((root / ".dev-logs").glob("interpreter-started-*.signal"))
        assert len(signals) == 4 and all(path.read_bytes() == adapter._INTERPRETER_SIGNAL for path in signals)
    finally:
        # Fixture-only recovery also works if a platform cannot verify a child:
        # only these fresh helper modules honor this private sentinel. No PID or
        # name signal is used to bypass the Runtime's ownership refusal.
        if any(child.poll() is None for child in children):
            (root / ".dev-logs/.fixture-exit").touch()
            for child in children:
                child.wait(timeout=10)
        runtime.stop(timeout=45)
        # Emergency fixture cleanup still uses only saved creation/executable
        # identities and original Popen objects, never a port/name lookup.
        for item in runtimes:
            for record in (item.state or {}).get("services", {}).values():
                item.terminate(record, timeout=2)
            item.release()
        assert all(child.poll() is not None for child in children), "Unconfirmed fixture children retained"
