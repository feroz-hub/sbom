"""Synthetic preview/browser/OS receipts only; no browser, network, DB or keygen."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import subprocess
import time
from dataclasses import FrozenInstanceError, replace
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev, dev_instance_plan, dev_instance_storage, dev_private, dev_windows_acl, dev_workspace
from scripts import dev_workspace_observe as observe
from scripts import dev_workspace_preview as preview
from scripts import dev_workspace_readiness as readiness
from scripts import dev_workspace_runtime as runtime
from scripts import dev_workspace_visual as visual

OPERATION = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SECRET = "synthetic-private-browser-value-never-output"


def _fixture_module():
    spec = importlib.util.spec_from_file_location("visual_safe_preview_fixture", Path(__file__).with_name("test_dev_workspace_preview.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _png(color=(255, 255, 255)):
    from PIL import Image
    output = BytesIO()
    Image.new("RGB", (320, 320), color).save(output, format="PNG")
    return output.getvalue()


def _immediate(coroutine):
    """Run only fake coroutines that never suspend; never opens an event-loop socket."""
    try:
        coroutine.send(None)
    except StopIteration as result:
        return result.value
    finally:
        coroutine.close()
    raise AssertionError("Synthetic coroutine unexpectedly suspended")


@pytest.fixture
def paired(tmp_path, monkeypatch):
    fixtures = _fixture_module()
    generators, values = [], []
    for index, role in enumerate(("b", "c")):
        base = tmp_path.resolve() / role
        fixtures.directory(base)
        generator = fixtures.candidate.__wrapped__(base, monkeypatch)
        value = next(generator)
        generators.append(generator)
        row = replace(value.row, worktree_id=role * 64, head=str(index + 1) * 40)
        snapshot = replace(value.snapshot, worktrees=(row,), head=row.head)
        value.row, value.snapshot = row, snapshot
        values.append(value)
    snapshots = {value.root: value.snapshot for value in values}
    monkeypatch.setattr(dev_workspace, "discover_workspaces", lambda root: snapshots[Path(root)])
    contexts, readers, requests, process_maps = [], {}, [], {}
    for index, (role, value) in enumerate(zip(("baseline", "candidate"), values, strict=True)):
        descriptor = dev_instance_plan.plan_instance(repository_id="a" * 64, worktree_id=value.row.worktree_id,
            commit=value.row.head, generation=1, mode="mock", auth_mode="native").descriptor
        plan = preview.plan_preview(value.snapshot, value.row, descriptor, state_anchor=value.home,
                                    node_executable=value.node, tls=value.tls)
        preview.prepare_preview(plan, authorize=lambda *args: True)
        launch = preview.validate_launch(plan, {}, verify_tls=lambda *args: True, verify_compiler=lambda *args: True)
        root = value.home / "instances" / descriptor.instance_id
        dev_instance_storage.initialize_private_directory(root, anchor=value.home)
        location = runtime.RuntimeLocation(descriptor, root, value.home)
        specification = runtime.preview_launch(location, launch)[0]
        environment = {**specification.environment, "SBOM_DEV_INSTANCE": "f" * 32,
                       "APP_ENVIRONMENT": "development", "PYTHON_DOTENV_DISABLED": "1"}
        specification = replace(specification, environment=environment)
        context = visual.VisualContext(plan, location, specification, runtime.RuntimeOutcome("INSTANCE_READY", 0, ready=True))
        contexts.append(context)
        pid = 10 + index
        identity = {"pid": pid, "birth": "birth-" + str(pid), "exe": "verified-synthetic-node"}
        process_maps[role] = {pid: identity}
        launcher = SimpleNamespace(process_info=lambda selected, mapping=process_maps[role]: mapping.get(selected),
            matches=lambda saved, current: current is not None and all(saved.get(key) == current.get(key) for key in ("pid", "birth", "exe")))
        state = {"instance": "f" * 32, "workspace_context": {"instance_id": descriptor.instance_id,
            "repository_id": descriptor.repository_id, "worktree_id": descriptor.worktree_id,
            "root_identity": list(location.identity)}, "services": {"Frontend": {**identity, "members": []}}}
        live = SimpleNamespace(root=root, state=state, service_status=lambda record: "RUNNING")
        read_context = readiness.ReadinessContext(descriptor, environment, root, value.root, value.tls, "103_tenant_admin_governance")
        def request(*args, **kwargs):
            requests.append((args, kwargs))
            return readiness.HttpResponse(200, b"synthetic mock HTML")
        readers[role] = readiness.WorkspaceReadiness(read_context, launcher, lambda live=live: live,
            listener_inspector=lambda address, port, pids, **kwargs: frozenset(pids), request=request,
            tls_validator=lambda *args: object())
    rows = tuple(observe.WorktreeView(context.preview.descriptor.worktree_id, context.preview.descriptor.commit,
        "refs/heads/mock", False, context.preview.descriptor) for context in contexts)
    comparison = observe.ComparisonReport("OBSERVED", *rows, ("COMMIT",))
    browser = values[0].node.parent / "chrome.exe"
    fixtures.write(browser, "synthetic browser executable; never execute")
    if os.name != "nt":
        browser.chmod(0o700)
    assert browser.is_absolute() and browser.resolve(strict=True) == browser
    visual.dev_private.validate_parent(browser, browser.parent)
    visual._file(browser, 268435456)
    plan = visual.plan_visual(comparison, *contexts, operation_id=OPERATION, browser_executable=browser,
                              viewport=visual.Viewport(320, 320))
    capture_calls, trust_calls = [], []
    class Browser:
        capability = staticmethod(lambda executable: visual.BrowserCapability("VISUAL_BROWSER_CANDIDATE", True))
        def capture(self, current, context, profile, directory, deadline):
            capture_calls.append((context, profile, directory, deadline))
            assert profile != context.location.root and not (profile / "personal-browser-state").exists()
            assert context.preview.descriptor.mode == "mock"
            return visual.CaptureData(_png(), b'{"traceEvents":[]}', "Chrome/130.0.0.0")
    def trust(context, executable, profile, timeout):
        trust_calls.append((context, executable, profile, timeout))
        return visual.BrowserTrustEvidence(context.preview.descriptor.instance_id, context.preview.descriptor.origin,
            visual._file(executable, 268435456)[1][-1], dev_instance_storage._identity(dev_instance_storage._verify(profile, private=True)),
            visual._file(context.preview.tls.certificate)[1][-1], "verified-browser-os-store")
    result = SimpleNamespace(plan=plan, contexts=contexts, readers=readers, browser=Browser(), trust=trust,
        capture_calls=capture_calls, trust_calls=trust_calls, requests=requests, process_maps=process_maps,
        fixtures=fixtures, values=values)
    yield result
    for generator in reversed(generators):
        next(generator, None)


def execute(paired, **changes):
    options = {"authorize": lambda plan, category: category == "visual-artifacts", "readers": paired.readers,
               "verify_browser_trust": paired.trust, "browser_adapter": paired.browser}
    options.update(changes)
    return visual.execute_visual(paired.plan, **options)


def test_plan_is_immutable_private_and_never_claims_functional_acceptance(paired):
    public = json.dumps(paired.plan.to_dict()) + repr(paired.plan) + repr(paired.plan.baseline)
    assert SECRET not in public and str(paired.contexts[0].location.anchor) not in public
    assert paired.plan.fingerprint not in public
    assert paired.plan.to_dict()["functional_acceptance_verified"] is False
    assert paired.capture_calls == paired.trust_calls == paired.requests == []
    with pytest.raises(FrozenInstanceError):
        paired.plan.route = "/api/private"


@pytest.mark.parametrize("change", ["script", "source", "api"])
def test_mock_context_must_bind_exact_prepared_next_source_and_inert_environment(paired, change):
    context = paired.plan.baseline
    spec = context.specification
    if change == "script":
        spec = replace(spec, argv=(*spec.argv[:3], str(context.location.root / "unapproved-script"), *spec.argv[4:]))
    else:
        values = {"source": {"SBOM_DEV_FRONTEND_SOURCE": str(context.preview.source)},
                  "api": {"NEXT_PUBLIC_API_URL": "https://unapproved.invalid"}}[change]
        spec = replace(spec, environment={**spec.environment, **values})
    with pytest.raises(visual.VisualError, match="^VISUAL_CONTEXT_UNVERIFIED$"):
        replace(context, specification=spec)


@pytest.mark.parametrize("answer", [False, 1, "yes", {"approved": True}])
def test_only_explicit_category_consent_allows_profiles_or_browser_work(paired, answer):
    result = execute(paired, authorize=lambda *args: answer)
    assert result.code == "VISUAL_CONSENT_REQUIRED" and paired.capture_calls == paired.requests == []
    for context in paired.contexts:
        assert not (context.location.root / "visual").exists()


def test_real_readiness_receipts_and_separate_browser_trust_precede_private_capture(paired):
    result = execute(paired)
    assert result.code == "VISUAL_CAPTURE_COMPLETED" and result.byte_equal is True and result.changed_pixels == 0
    assert len(result.artifacts) == 5 and len(paired.capture_calls) == 2 and len(paired.trust_calls) == 4
    assert len(paired.requests) == 6
    public = json.dumps(result.to_dict())
    assert SECRET not in public and str(paired.contexts[0].location.anchor) not in public
    assert result.to_dict()["api_verified"] is result.to_dict()["login_verified"] is False
    for artifact in result.artifacts:
        assert artifact.browser_version == "Chrome/130.0.0.0" and len(artifact.sha256) == 64
    for context in paired.contexts:
        directory = context.location.root / "visual" / OPERATION
        dev_instance_storage._verify(directory, private=True)
        for path in directory.iterdir():
            if path.is_file():
                dev_instance_registry = visual.dev_instance_registry
                dev_instance_registry._private(path)
    receipt = paired.plan.candidate.location.root / "visual" / OPERATION / ".visual-artifacts.json"
    assert json.loads(receipt.read_bytes()) == result.to_dict()


def test_pixel_difference_is_reported_without_a_functional_acceptance_claim(paired):
    original = paired.browser.capture
    def changed(plan, context, *args):
        capture = original(plan, context, *args)
        return replace(capture, png=_png((0, 0, 0))) if context is paired.plan.candidate else capture
    paired.browser.capture = changed
    result = execute(paired)
    assert result.code == "VISUAL_CAPTURE_COMPLETED" and result.changed_pixels == 320 * 320 and result.byte_equal is False
    assert result.to_dict()["functional_acceptance_verified"] is False


@pytest.mark.parametrize("evidence", [True, None, "client-ca-ready", readiness.ReadinessResult("Frontend", "PASS", "FRONTEND_READY")])
def test_client_ca_or_ready_labels_never_substitute_for_browser_os_trust(paired, evidence):
    result = execute(paired, verify_browser_trust=lambda *args: evidence)
    assert result.code == "VISUAL_BROWSER_TRUST_REQUIRED" and paired.capture_calls == []


@pytest.mark.parametrize("field", ["origin", "instance_id", "browser_sha256", "certificate_sha256", "profile_identity"])
def test_browser_trust_receipt_must_bind_exact_profile_leaf_origin_and_executable(paired, field):
    def bad(*args):
        evidence = paired.trust(*args)
        values = {"origin": "https://unrelated.invalid", "instance_id": "11111111-2222-4333-8444-555555555555",
                  "browser_sha256": "0" * 64, "certificate_sha256": "0" * 64, "profile_identity": (0, 99)}
        return replace(evidence, **{field: values[field]})
    assert execute(paired, verify_browser_trust=bad).code == "VISUAL_BROWSER_TRUST_REQUIRED"
    assert paired.capture_calls == []


def test_source_drift_during_consent_blocks_before_profile_creation(paired):
    def consent(*args):
        paired.plan.browser.write_bytes(b"changed synthetic browser")
        return True
    result = execute(paired, authorize=consent)
    assert result.code == "VISUAL_SOURCE_CHANGED" and paired.capture_calls == paired.requests == []
    assert not (paired.plan.baseline.location.root / "visual").exists()


def test_canonical_runtime_controller_is_pinned_across_artifact_consent(paired, monkeypatch):
    assert "dev.py" in dict(paired.plan.controller_proofs)
    original = visual._controllers
    def consent(*args):
        def drift():
            return tuple((name, (*proof[:-1], "0" * 64) if name == "dev.py" else proof)
                         for name, proof in original())
        monkeypatch.setattr(visual, "_controllers", drift)
        return True
    result = execute(paired, authorize=consent)
    assert result.code == "VISUAL_SOURCE_CHANGED" and paired.capture_calls == paired.requests == []
    assert not (paired.plan.baseline.location.root / "visual").exists()


def test_process_reuse_after_capture_blocks_artifact_publication(paired):
    original = paired.browser.capture
    def capture(*args):
        result = original(*args)
        paired.process_maps["baseline"][10] = {"pid": 10, "birth": "reused", "exe": "foreign"}
        return result
    paired.browser.capture = capture
    result = execute(paired)
    assert result.code == "VISUAL_CONTEXT_UNVERIFIED" and result.artifacts == ()
    assert not list((paired.plan.baseline.location.root / "visual" / OPERATION).glob("*.png"))


def test_runtime_ready_flag_cannot_unlock_a_foreign_frontend_listener(paired):
    paired.readers["baseline"].listener_inspector = lambda *args, **kwargs: frozenset({999})
    result = execute(paired)
    assert result.code == "VISUAL_CONTEXT_UNVERIFIED" and paired.capture_calls == paired.requests == []


def test_an_existing_operation_or_unknown_profile_is_never_adopted_or_deleted(paired):
    directory = paired.plan.candidate.location.root / "visual" / OPERATION
    dev_instance_storage.initialize_private_directory(directory, anchor=paired.plan.candidate.location.anchor)
    dev_private.create_private_file(directory / "unknown", SECRET.encode())
    result = execute(paired)
    assert result.code == "VISUAL_ARTIFACT_TARGET_EXISTS" and paired.capture_calls == []
    assert (directory / "unknown").read_text() == SECRET


def test_unknown_browser_cleanup_preserves_and_reports_pid_without_raw_error(paired):
    paired.browser.capture = Mock(side_effect=visual.VisualError("VISUAL_CLEANUP_UNCONFIRMED", probe_pid=91))
    result = execute(paired)
    assert result.code == "VISUAL_CLEANUP_UNCONFIRMED" and result.cleanup_verified is False
    assert result.retained_browser_pids == (91,) and SECRET not in json.dumps(result.to_dict())


@pytest.mark.parametrize("mode", ["shared-backend", "isolated"])
def test_real_application_modes_cannot_use_synthetic_capture_authority(paired, mode):
    context = paired.plan.baseline
    descriptor = dev_instance_plan.plan_instance(repository_id=context.preview.descriptor.repository_id,
        worktree_id=context.preview.descriptor.worktree_id, commit=context.preview.descriptor.commit,
        generation=1, mode=mode, auth_mode="native").descriptor
    with pytest.raises(visual.VisualError, match="^VISUAL_MOCK_ONLY$"):
        replace(context, preview=replace(context.preview, descriptor=descriptor))


@pytest.mark.parametrize("route", ["/api/probe", "//foreign.invalid", "/?token=" + SECRET, "/../", "https://foreign.invalid"])
def test_arbitrary_routes_or_urls_are_not_capture_targets(paired, route):
    with pytest.raises(visual.VisualError, match="^VISUAL_INPUT_INVALID$"):
        visual.plan_visual(paired.plan.comparison, paired.plan.baseline, paired.plan.candidate,
            operation_id=OPERATION, browser_executable=paired.plan.browser, route=route)


def test_browser_capability_reports_missing_library_without_install_or_launch(paired, monkeypatch):
    monkeypatch.setattr(visual.importlib.metadata, "version", Mock(side_effect=importlib.metadata.PackageNotFoundError("secret")))
    result = visual.detect_browser(paired.plan.browser)
    assert result.code == "VISUAL_LIBRARY_UNAVAILABLE" and result.available is result.probed is False


def test_missing_browser_or_trust_adapter_has_actionable_blocked_result(paired):
    assert execute(paired, verify_browser_trust=None).code == "VISUAL_BROWSER_TRUST_REQUIRED"
    assert execute(paired, browser_adapter=None).code == "VISUAL_BROWSER_UNAVAILABLE"
    assert visual.detect_browser(paired.plan.browser.parent / "missing-browser").code == "VISUAL_BROWSER_UNAVAILABLE"
    assert paired.capture_calls == paired.trust_calls == paired.requests == []


class Child:
    pid = 90
    _handle = 1090
    def poll(self):
        return None


class Ledger:
    def __init__(self, root, browser):
        self.root, self.path, self.stop_path = root, root / ".dev-runtime.json", root / ".dev-runtime.stop"
        self.state, self.processes, self.events = None, {}, []
        self.unknown, self.register_failure = False, False
        self.browser = browser
    def acquire(self):
        return True
    def load(self):
        return None
    def begin(self, profile):
        assert profile == "visual"
        self.state = {"services": {}}
    def register(self, name, pid):
        assert pid in self.processes
        if self.register_failure:
            raise OSError(SECRET)
        self.state["services"][name] = {"pid": pid, "birth": "browser-birth", "exe": str(self.browser), "members": []}
    def refresh(self):
        self.events.append("refresh")
    def service_status(self, record):
        return "UNKNOWN" if self.unknown or not record.get("birth") else "RUNNING"
    def stop_services(self, say):
        self.events.append("verified-stop")
        return not self.unknown and all(record.get("birth") for record in self.state["services"].values())
    def release(self):
        self.events.append("release")


def concrete(paired, monkeypatch, *, foreign_listener=False, unknown=False, register_failure=False):
    ledgers, launches, writes = [], [], []
    def factory(root):
        result = Ledger(root, paired.plan.browser)
        result.unknown, result.register_failure = unknown, register_failure
        ledgers.append(result)
        return result
    def popen(argv, **options):
        launches.append((argv, options))
        assert not any("ignore-certificate" in value or "disable-web-security" in value or "no-sandbox" in value for value in argv)
        assert not any(key in options["env"] for key in ("DATABASE_URL", "SSLKEYLOGFILE", "NODE_OPTIONS", "HTTP_PROXY"))
        profile = Path(next(value.split("=", 1)[1] for value in argv if value.startswith("--user-data-dir=")))
        dev_private.create_private_file(profile / "DevToolsActivePort", b"12345\n/devtools/browser/owned-fixture\n")
        return Child()
    adapter = visual.ChromiumCdpAdapter(runtime_factory=factory, atomic_json=lambda path, value: writes.append(copy.deepcopy(value)),
        process_info=lambda pid: {"pid": pid, "birth": "browser-birth", "exe": str(paired.plan.browser)},
        matches=lambda saved, current: all(saved.get(key) == current.get(key) for key in ("pid", "birth", "exe")),
        listener_inspector=lambda *args, **kwargs: frozenset({999} if foreign_listener else {90}),
        popen=popen, transport={"PATH": "/synthetic/bin", "DATABASE_URL": SECRET, "HTTP_PROXY": SECRET, "SSLKEYLOGFILE": SECRET})
    async def capture(*args):
        return visual.CaptureData(_png(), b'{"traceEvents":[]}', "Chrome/130.0.0.0")
    monkeypatch.setattr(adapter, "_capture_cdp", capture)
    monkeypatch.setattr(visual.asyncio, "run", _immediate)
    directory = paired.plan.baseline.location.root / "visual" / OPERATION
    visual._new_directory(directory, paired.plan.baseline.location.anchor)
    profile = directory / "browser-profile"
    visual._new_directory(profile, paired.plan.baseline.location.anchor)
    return SimpleNamespace(adapter=adapter, ledgers=ledgers, launches=launches, writes=writes,
                           directory=directory, profile=profile)


def test_concrete_adapter_owns_browser_with_safe_argv_environment_and_canonical_cleanup(paired, monkeypatch):
    value = concrete(paired, monkeypatch)
    result = value.adapter.capture(paired.plan, paired.plan.baseline, value.profile, value.directory, time.monotonic() + 5)
    assert result.browser_version == "Chrome/130.0.0.0" and len(value.launches) == 1
    assert value.ledgers[0].events[-2:] == ["verified-stop", "release"]
    argv, options = value.launches[0]
    assert "--remote-debugging-address=127.0.0.1" in argv and "--remote-debugging-port=0" in argv
    assert "--host-resolver-rules=MAP " + paired.plan.baseline.preview.descriptor.hostname + " 127.0.0.1, EXCLUDE localhost" in argv
    assert options["stdout"] == options["stderr"] == subprocess.DEVNULL


def test_foreign_debugger_listener_blocks_before_cdp_and_uses_only_verified_cleanup(paired, monkeypatch):
    value = concrete(paired, monkeypatch, foreign_listener=True)
    called = Mock(side_effect=AssertionError("Foreign CDP listener was contacted"))
    monkeypatch.setattr(value.adapter, "_capture_cdp", called)
    with pytest.raises(visual.VisualError, match="^VISUAL_DEBUGGER_OWNERSHIP_UNVERIFIED$"):
        value.adapter.capture(paired.plan, paired.plan.baseline, value.profile, value.directory, time.monotonic() + 5)
    called.assert_not_called()
    assert value.ledgers[0].events[-2:] == ["verified-stop", "release"]


def test_registration_failure_persists_unknown_record_and_never_guesses_pid_ownership(paired, monkeypatch):
    value = concrete(paired, monkeypatch, register_failure=True)
    with pytest.raises(visual.VisualError, match="^VISUAL_CLEANUP_UNCONFIRMED$") as caught:
        value.adapter.capture(paired.plan, paired.plan.baseline, value.profile, value.directory, time.monotonic() + 5)
    assert caught.value.probe_pid == 90 and value.writes[0]["services"]["Visual browser"]["tree_unverified"] is True
    assert value.profile.exists() and value.ledgers[0].events[-1] == "release"


def test_pid_identity_uncertainty_retains_private_browser_profile_and_record(paired, monkeypatch):
    value = concrete(paired, monkeypatch, unknown=True)
    with pytest.raises(visual.VisualError, match="^VISUAL_CLEANUP_UNCONFIRMED$") as caught:
        value.adapter.capture(paired.plan, paired.plan.baseline, value.profile, value.directory, time.monotonic() + 5)
    assert caught.value.probe_pid == 90 and value.profile.exists()


def test_real_runtime_browser_ledger_uses_explicit_private_owner_before_any_browser_spawn(paired, monkeypatch):
    value = concrete(paired, monkeypatch)
    explicit, states = set(), []
    original_create, original_private = dev_private.create_private_file, visual.dev_instance_registry._private
    ledger_root = value.directory / "browser-runtime"
    def create(path, raw):
        original_create(path, raw)
        info = Path(path).lstat()
        explicit.add((info.st_dev, info.st_ino))
    def private(path, **kwargs):
        info = original_private(path, **kwargs)
        if not kwargs.get("directory") and Path(path).is_relative_to(ledger_root):
            if (info.st_dev, info.st_ino) not in explicit:
                raise dev_windows_acl.AclVerificationError("EqualSid", category="OWNER_MISMATCH")
            if Path(path).name == ".dev-runtime.json":
                states.append(json.loads(Path(path).read_bytes()))
        return info
    monkeypatch.setattr(dev_private, "create_private_file", create)
    monkeypatch.setattr(visual.dev_instance_registry, "_private", private)
    monkeypatch.setattr(dev, "process_info", lambda pid: {"pid": pid, "birth": "fixture-launcher", "exe": "fixture-python"})
    unsafe = Mock(side_effect=AssertionError("Browser ledger used default-owner state writer"))
    value.adapter.factory = dev.Runtime
    value.adapter.atomic_json = unsafe
    # Stop before a process exists. Real Runtime locking/publication still run.
    value.adapter.popen = Mock(side_effect=OSError(SECRET))
    with pytest.raises(visual.VisualError, match="^VISUAL_CAPTURE_FAILED$") as caught:
        value.adapter.capture(paired.plan, paired.plan.baseline, value.profile, value.directory, time.monotonic() + 5)
    assert states and all(state["profile"] == "visual" and state["services"] == {} for state in states)
    private(ledger_root / ".dev-runtime.lock")
    assert not (ledger_root / ".dev-runtime.json").exists()
    assert SECRET not in str(caught.value)
    value.adapter.popen.assert_called_once()
    unsafe.assert_not_called()


def test_browser_ledger_preserves_unknown_owner_lock_without_spawn_or_cleanup(paired, monkeypatch):
    value = concrete(paired, monkeypatch)
    paths, snapshots = [], []
    original = visual.dev_instance_registry._private
    def factory(root):
        lock = root / ".dev-runtime.lock"
        dev_private.create_private_file(lock, b"\0")
        paths.append(lock)
        snapshots.append((lock.lstat().st_ino, lock.read_bytes()))
        return dev.Runtime(root)
    def private(path, **kwargs):
        if paths and Path(path) == paths[0]:
            raise dev_windows_acl.AclVerificationError("EqualSid", category="OWNER_MISMATCH")
        return original(path, **kwargs)
    monkeypatch.setattr(visual.dev_instance_registry, "_private", private)
    value.adapter.factory = factory
    spawned = Mock(side_effect=AssertionError("Unknown browser lock allowed a process"))
    value.adapter.popen = spawned
    with pytest.raises(visual.VisualError, match="^VISUAL_BROWSER_IDENTITY_UNVERIFIED$"):
        value.adapter.capture(paired.plan, paired.plan.baseline, value.profile, value.directory, time.monotonic() + 5)
    assert snapshots == [(paths[0].lstat().st_ino, paths[0].read_bytes())]
    assert not (paths[0].parent / ".dev-runtime.json").exists()
    spawned.assert_not_called()


def test_configurable_fake_registration_failure_uses_private_unknown_record_writer(paired, monkeypatch):
    value = concrete(paired, monkeypatch, register_failure=True)
    original_factory = value.adapter.factory
    def factory(root):
        ledger = original_factory(root)
        def configure(*, state_writer, lock_creator):
            ledger.state_writer, ledger.lock_creator = state_writer, lock_creator
        ledger.configure_private_io = configure
        return ledger
    value.adapter.factory = factory
    unsafe = Mock(side_effect=AssertionError("Registration fallback lost explicit private owner"))
    value.adapter.atomic_json = unsafe
    with pytest.raises(visual.VisualError, match="^VISUAL_CLEANUP_UNCONFIRMED$"):
        value.adapter.capture(paired.plan, paired.plan.baseline, value.profile, value.directory, time.monotonic() + 5)
    record = value.directory / "browser-runtime/.dev-runtime.json"
    visual.dev_instance_registry._private(record)
    assert json.loads(record.read_bytes())["services"]["Visual browser"]["tree_unverified"] is True
    unsafe.assert_not_called()


def test_cdp_request_filter_blocks_foreign_targets_without_logging_their_values():
    class Connection:
        def __init__(self):
            self.sent = []
            self.responses = [
                {"method": "Fetch.requestPaused", "sessionId": "s", "params": {"requestId": "foreign", "request": {"url": "https://foreign.invalid/?secret=" + SECRET}}},
                {"id": 1, "result": {"product": "Chrome/130.0.0.0"}},
            ]
        async def send(self, value):
            self.sent.append(json.loads(value))
        async def recv(self):
            return json.dumps(self.responses.pop(0))
    connection = Connection()
    cdp = visual._Cdp(connection, "https://mock.invalid:12345", time.monotonic() + 1)
    assert _immediate(cdp.call("Browser.getVersion"))["product"] == "Chrome/130.0.0.0"
    assert connection.sent[1]["method"] == "Fetch.failRequest"
    assert SECRET not in json.dumps(connection.sent)


def test_cdp_source_has_no_tls_auth_cors_bypass_or_browser_install_path():
    source = Path(visual.__file__).read_text(encoding="utf-8")
    for forbidden in ("setIgnoreCertificateErrors", "ignoreHTTPSErrors", "--ignore-certificate-errors", "--disable-web-security", "playwright install", "--no-sandbox"):
        assert forbidden not in source


def test_macos_default_listener_adapter_uses_existing_bounded_owned_lsof(monkeypatch):
    captured = []
    probe = Mock(return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
    monkeypatch.setattr(visual.readiness, "owned_lsof_probe", probe)
    def listener(address, port, pids, *, mac_probe, timeout):
        captured.append((address, port, pids, timeout))
        mac_probe(("/usr/sbin/lsof", "-nP"), timeout=2, max_output=262144)
        return pids
    monkeypatch.setattr(visual.readiness, "listener_pids", listener)
    monkeypatch.setattr(visual.sys, "platform", "darwin")
    identity, matches = Mock(), Mock()
    adapter = visual.ChromiumCdpAdapter(runtime_factory=Mock(), atomic_json=Mock(), process_info=identity,
                                       matches=matches, listener_inspector=listener)
    assert adapter.listener_inspector("127.0.0.1", 23456, frozenset({12}), timeout=1) == frozenset({12})
    assert captured == [("127.0.0.1", 23456, frozenset({12}), 1)]
    assert probe.call_args.kwargs["process_info"] is identity and probe.call_args.kwargs["matches"] is matches
    assert probe.call_args.kwargs["timeout"] == 1


@pytest.mark.parametrize("value", [SECRET, {"code": SECRET}, None])
def test_public_outcomes_refuse_arbitrary_error_messages(value):
    with pytest.raises(visual.VisualError, match="^VISUAL_INPUT_INVALID$") as caught:
        visual.VisualOutcome(value)
    assert SECRET not in str(caught.value)


def test_concrete_cdp_adapter_captures_only_mock_with_real_protocol_flow(paired, monkeypatch):
    commands, options = [], []
    class Connection:
        def __init__(self):
            self.queue = []
        async def send(self, raw):
            request = json.loads(raw)
            commands.append(request)
            method, result = request["method"], {}
            if method == "Browser.getVersion":
                result = {"product": "Chrome/130.0.0.0"}
            elif method == "Target.createTarget":
                result = {"targetId": "target"}
            elif method == "Target.attachToTarget":
                result = {"sessionId": "session"}
            elif method == "Page.navigate":
                self.queue.append({"method": "Page.loadEventFired", "params": {}, "sessionId": "session"})
            elif method == "Runtime.evaluate":
                result = {"result": {"value": True}}
            elif method == "Page.captureScreenshot":
                result = {"data": base64.b64encode(_png()).decode()}
            elif method == "Tracing.end":
                self.queue.append({"method": "Tracing.tracingComplete", "params": {"stream": "trace"}})
            elif method == "IO.read":
                result = {"data": '{"traceEvents":[]}', "eof": True}
            self.queue.append({"id": request["id"], "result": result})
        async def recv(self):
            return json.dumps(self.queue.pop(0))
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return False
    def connect(endpoint, **kwargs):
        options.append((endpoint, kwargs))
        return Connection()
    class Timeout:
        async def __aenter__(self):
            return None
        async def __aexit__(self, *args):
            return False
    monkeypatch.setattr(visual.asyncio, "timeout", lambda timeout: Timeout())
    adapter = visual.ChromiumCdpAdapter(runtime_factory=Mock(), atomic_json=Mock(), process_info=Mock(), matches=Mock(), connect=connect)
    result = _immediate(adapter._capture_cdp(paired.plan, paired.plan.baseline,
                        "ws://127.0.0.1:12345/devtools/browser/owned", time.monotonic() + 5))
    assert result.png.startswith(b"\x89PNG") and result.trace == b'{"traceEvents":[]}'
    assert options[0][1]["proxy"] is options[0][1]["compression"] is None
    assert options[0][1]["logger"].disabled is True and options[0][1]["logger"].propagate is False
    assert options[0][1]["open_timeout"] <= 5 and options[0][1]["close_timeout"] == 1
    navigate = next(request for request in commands if request["method"] == "Page.navigate")
    assert navigate["params"] == {"url": paired.plan.baseline.preview.descriptor.origin + "/"}
    assert all("certificate" not in request["method"].lower() for request in commands)
