"""Setup orchestration uses synthetic installers/private temporary storage only."""

from __future__ import annotations

import builtins
import json
import os
import socket
import uuid
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_workspace_cli as workspace_cli
from scripts import dev_workspace_setup as setup

from tests.test_dev_workspace_dependencies import candidate as candidate

SECRET = "synthetic-setup-private-value-never-output"


@pytest.fixture
def fixture(candidate, monkeypatch):
    scripts = candidate.root / "scripts"
    if os.name == "nt":
        setup.storage._windows_create(scripts)
    else:
        scripts.mkdir(mode=0o700)
    for name in workspace_cli._CONTROLLER_SOURCES:
        workspace_cli.dev_private.create_private_file(
            candidate.root / name, ("synthetic-public-controller:" + name).encode()
        )
    monkeypatch.setattr(setup.workspace, "discover_workspaces", lambda _path, runner=None: candidate.snapshot)
    selection = setup.Selection(candidate.selected.worktree_id, "isolated", "native", family="instance")

    def observe(selected=None):
        return setup.observe_setup(
            candidate.root,
            selected or selection,
            home=candidate.home,
            dependency_runner=candidate.runner,
            **candidate.tools,
        )

    observation = observe()
    assert observation.dependency_plan is not None and not observation.dependency_plan.blockers
    return SimpleNamespace(candidate=candidate, selection=selection, observe=observe, observation=observation)


def row(plan, category):
    return next(value for value in plan.rows if value.category == category)


def consent(plan, *categories, issued=0, expires=100):
    return tuple(
        setup.StageConsent(value, plan.fingerprint, plan.target_fingerprint, issued, expires) for value in categories
    )


def scoped_plan(fixture, *, statuses=None, categories=(), contexts=None):
    base = setup.plan_setup(fixture.observation, fixture.selection)
    stages = tuple(
        setup.StageContext(category, status, base.target_fingerprint, "e" * 64)
        for category, status in (statuses or {}).items()
    )
    contexts = contexts or setup.Contexts(stages)
    return setup.plan_setup(fixture.observation, fixture.selection, contexts=contexts, registered_categories=categories)


def proof(plan, category):
    return setup.StageAuthority(
        category, plan.target_fingerprint, dict(plan.stage_bindings)[category], setup._AUTHORITY[category]
    )


def executor(plan, adapters=(), **options):
    return setup.SetupExecutor(reobserve=lambda _selection: plan, adapters=adapters, clock=lambda: 1, **options)


def test_observation_reads_public_sources_only_and_creates_nothing(fixture, monkeypatch):
    candidate = fixture.candidate
    (candidate.root / ".env.dev.local").write_text(SECRET, encoding="utf-8")
    original = setup.dev_environment.bounded_read_bytes

    def public_only(path, limit):
        assert not path.name.startswith(".env")
        return original(path, limit)

    monkeypatch.setattr(setup.dev_environment, "bounded_read_bytes", public_only)
    monkeypatch.setenv("DATABASE_URL", SECRET)
    observation = fixture.observe()
    assert observation.private_configuration_present
    plan = setup.plan_setup(observation, fixture.selection)
    assert row(plan, "selection").code == "SETUP_EXISTING_FAMILY_REVIEW_REQUIRED"
    assert row(plan, "dependencies").executable
    assert SECRET not in repr(plan) + json.dumps(plan.to_dict())
    assert not (candidate.home / ".sbom-dev").exists() and not (candidate.root / ".venv").exists()
    candidate.forbidden.assert_not_called()


def test_plan_is_pure_immutable_and_dependencies_do_not_need_configuration(fixture, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("Pure plan performed I/O"))
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(uuid, "uuid4", forbidden)
    monkeypatch.setattr(os, "urandom", forbidden)
    old_environment = dict(os.environ)
    plan = setup.plan_setup(fixture.observation, fixture.selection)
    assert row(plan, "dependencies").status == "NEEDS_APPROVAL"
    assert row(plan, "provider-policy").status == "BLOCKED"
    assert row(plan, "private-credentials").status == "MISSING"
    assert dict(os.environ) == old_environment
    assert plan == setup.plan_setup(fixture.observation, fixture.selection)
    with pytest.raises(FrozenInstanceError):
        plan.fingerprint = "f" * 64
    forbidden.assert_not_called()


@pytest.mark.parametrize("auth", ["native", "hcl"])
def test_mock_skips_only_inapplicable_stages_without_provider_database_or_credential_contexts(fixture, auth):
    selection = replace(fixture.selection, mode="mock", provider="mock", auth_mode=auth)
    plan = setup.plan_setup(fixture.observation, selection)
    for category in setup._MOCK_NOT_REQUIRED:
        value = row(plan, category)
        assert (value.status, value.code, value.prerequisites, value.executable) == (
            "SKIPPED",
            "SETUP_NOT_REQUIRED",
            (),
            False,
        )
    assert row(plan, "certificates").prerequisites == ("registry",)
    assert row(plan, "trust").prerequisites == ("certificates",)
    assert not plan.to_dict()["application_ready"] and not plan.to_dict()["authentication_ready"]
    assert not plan.to_dict()["privileged_onboarding_authorized"]


def test_mock_registry_and_certificate_preparation_never_calls_provider_or_private_credential_adapters(fixture):
    selection = replace(fixture.selection, mode="mock", provider="mock")
    base = setup.plan_setup(fixture.observation, selection)
    contexts = setup.Contexts(
        (
            setup.StageContext("certificates", "NEEDS_APPROVAL", base.target_fingerprint, "e" * 64),
            setup.StageContext("trust", "NEEDS_APPROVAL", base.target_fingerprint, "d" * 64),
        )
    )
    plan = setup.plan_setup(
        fixture.observation, selection, contexts=contexts, registered_categories=("certificates", "trust")
    )
    assert row(plan, "certificates").executable
    forbidden = Mock(side_effect=AssertionError("Mock entered a provider, credential, database or trust mutator"))
    calls = []

    def certificate(current, guard):
        guard("certificates")
        calls.append(current.instance_plan.descriptor.instance_id)
        return setup.StageOutcome("certificates", "COMPLETED", "SETUP_STAGE_COMPLETED", ("certificates",), True)

    adapters = [
        setup.StageAdapter("certificates", certificate, lambda current, approved: proof(current, approved.category))
    ]
    adapters.extend(
        setup.StageAdapter(category, forbidden, forbidden)
        for category in setup._SENSITIVE
        if category != "certificates"
    )

    def reobserve(selected):
        return setup.plan_setup(
            fixture.observe(selected), selected, contexts=contexts, registered_categories=("certificates", "trust")
        )

    run = setup.SetupExecutor(reobserve=reobserve, adapters=tuple(adapters), clock=lambda: 1)
    result = run.execute_selected(
        plan,
        ("registry", "certificates", *tuple(sorted(setup._MOCK_NOT_REQUIRED))),
        consent(plan, "registry", "certificates"),
        interactive=True,
    )
    assert result.exit_code == 0 and calls == [base.instance_plan.descriptor.instance_id]
    for category in setup._MOCK_NOT_REQUIRED:
        stage = next(value for value in result.stages if value.category == category)
        assert (stage.status, stage.code, stage.completed_categories) == ("SKIPPED", "SETUP_NOT_REQUIRED", ())
    assert next(value for value in result.stages if value.category == "trust").code == "SETUP_NOT_SELECTED"
    assert not result.to_dict()["application_ready"] and not result.to_dict()["authentication_ready"]
    forbidden.assert_not_called()


def test_mock_certificate_still_requires_verified_registry_and_unknown_records_are_preserved(fixture):
    selection = replace(fixture.selection, mode="mock", provider="mock")
    observation = replace(
        fixture.observation, registry_snapshot=setup.registry.RegistrySnapshot(codes=("REGISTRY_UNKNOWN_ARTIFACT",))
    )
    base = setup.plan_setup(observation, selection)
    context = setup.Contexts((setup.StageContext("certificates", "NEEDS_APPROVAL", base.target_fingerprint, "e" * 64),))
    plan = setup.plan_setup(observation, selection, contexts=context, registered_categories=("certificates",))
    assert row(plan, "registry").status == "BLOCKED" and not row(plan, "certificates").executable
    blocked = Mock(side_effect=AssertionError("Unknown registry allowed preparation"))
    adapter = setup.StageAdapter("certificates", blocked, blocked)
    result = executor(plan, (adapter,)).execute_selected(
        plan, ("certificates",), consent(plan, "certificates"), interactive=True
    )
    assert result.exit_code == 1
    blocked.assert_not_called()


@pytest.mark.parametrize("mode", ["isolated", "shared-backend"])
def test_authenticated_modes_cannot_skip_real_backend_credentials_schema_or_onboarding(fixture, mode):
    selection = replace(fixture.selection, mode=mode, provider=None)
    plan = setup.plan_setup(fixture.observation, selection)
    assert not any(value.status == "SKIPPED" for value in plan.rows)
    for category in (
        "provider-policy",
        "private-credentials",
        "provider-resources",
        "database-init",
        "schema",
        "onboarding",
    ):
        assert row(plan, category).status not in {"READY", "SKIPPED"}
    with pytest.raises(setup.SetupError):
        setup.StageContext("private-credentials", "SKIPPED", plan.target_fingerprint, "e" * 64)


def test_setup_descriptor_manifests_match_public_workspace_launcher_exactly(fixture):
    observed = fixture.observation
    expected = workspace_cli._manifest_hashes(
        observed.worktree.root, observed.worktree.identity, observed.repository.root, observed.repository.identity
    )
    planned = setup.plan_setup(observed, fixture.selection)
    assert dict(observed.instance_manifest_hashes) == expected
    assert dict(planned.instance_plan.descriptor.manifest_hashes) == expected
    assert set(expected) > set(observed.dependency_plan.manifest_hashes)


def test_setup_and_workspace_cli_make_identical_instance_descriptors(fixture, monkeypatch):
    monkeypatch.setattr(workspace_cli, "_registry", lambda snapshot: fixture.observation.registry_store)
    args = SimpleNamespace(
        worktree=None,
        mode=fixture.selection.mode,
        auth=fixture.selection.auth_mode,
        generation=None,
        provider=None,
        port_min=20000,
        port_max=29999,
    )
    cli_plan, _, previous = workspace_cli._make_plan(args, fixture.candidate.root)
    setup_plan = setup.plan_setup(fixture.observation, fixture.selection)
    assert previous is None and cli_plan.descriptor == setup_plan.instance_plan.descriptor


def test_mock_preview_stage_has_only_frontend_prerequisites_and_is_explicitly_gated(fixture):
    selection = replace(fixture.selection, mode="mock", provider="mock")
    plan = setup.plan_setup(fixture.observation, selection)
    assert row(plan, "preview").prerequisites == ("registry", "dependencies", "certificates")
    assert row(plan, "preview").status == "BLOCKED" and not row(plan, "preview").executable
    assert setup._CATEGORIES.index("preview") == setup._CATEGORIES.index("certificates") + 1
    assert {"owned-source", "compiler-guard"} <= setup._AUTHORITY["preview"]


@pytest.mark.parametrize("missing_compiler_guard", [False, True])
def test_one_mock_session_can_prepare_registry_dependencies_certificates_and_preview_only(
    fixture, missing_compiler_guard
):
    selection = replace(fixture.selection, mode="mock", provider="mock")
    base = setup.plan_setup(fixture.observation, selection)
    contexts = setup.Contexts(
        tuple(
            setup.StageContext(category, "NEEDS_APPROVAL", base.target_fingerprint, "e" * 64)
            for category in ("certificates", "preview")
        )
    )
    categories = ("certificates", "preview")
    plan = setup.plan_setup(fixture.observation, selection, contexts=contexts, registered_categories=categories)
    calls = []

    def mutate(current, guard, category):
        guard(category)
        calls.append(category)
        return setup.StageOutcome(category, "COMPLETED", "SETUP_STAGE_COMPLETED", (category,), True)

    def authorize(current, approved):
        value = proof(current, approved.category)
        if missing_compiler_guard and approved.category == "preview":
            return replace(value, checks=value.checks - {"compiler-guard"})
        return value

    adapters = tuple(
        setup.StageAdapter(
            category, lambda current, guard, category=category: mutate(current, guard, category), authorize
        )
        for category in categories
    )

    def reobserve(selected):
        return setup.plan_setup(
            fixture.observe(selected), selected, contexts=contexts, registered_categories=categories
        )

    run = setup.SetupExecutor(
        reobserve=reobserve, adapters=adapters, clock=lambda: 1, dependency_runner=fixture.candidate.runner
    )
    selected = ("registry", "dependencies", "certificates", "preview")
    result = run.execute_selected(plan, selected, consent(plan, *selected), interactive=True)
    assert calls == (["certificates"] if missing_compiler_guard else ["certificates", "preview"])
    preview = next(value for value in result.stages if value.category == "preview")
    assert preview.code == ("SETUP_AUTHORITY_REQUIRED" if missing_compiler_guard else "SETUP_STAGE_COMPLETED")
    assert result.exit_code == (1 if missing_compiler_guard else 0)
    assert next(value for value in result.stages if value.category == "trust").code == "SETUP_NOT_SELECTED"
    assert not result.to_dict()["application_ready"] and not result.to_dict()["authentication_ready"]


@pytest.mark.parametrize("mode", ["isolated", "shared-backend"])
def test_backend_preview_is_ordered_after_its_real_requirements_and_never_skipped(fixture, mode):
    selection = replace(fixture.selection, mode=mode, provider=None)
    base = setup.plan_setup(fixture.observation, selection)
    contexts = setup.Contexts((setup.StageContext("preview", "NEEDS_APPROVAL", base.target_fingerprint, "e" * 64),))
    plan = setup.plan_setup(fixture.observation, selection, contexts=contexts, registered_categories=("preview",))
    value = row(plan, "preview")
    assert "provider-resources" in value.prerequisites and value.status == "BLOCKED"
    assert ("schema" in value.prerequisites) is (mode == "isolated")
    assert ("private-credentials" in value.prerequisites) is (mode == "shared-backend")
    # Selecting an already-ready public selection performs no mutation and lets
    # us inspect the executor's stable topological order, independent of display.
    result = executor(plan).execute_selected(plan, ("selection",), (), interactive=True)
    order = [value.category for value in result.stages]
    assert order.index("provider-resources") < order.index("preview")
    if mode == "isolated":
        assert order.index("schema") < order.index("preview")


def test_shared_plan_cannot_forge_mock_skips_or_bypass_typed_preview_prerequisites(fixture):
    selection = replace(fixture.selection, mode="shared-backend", provider="shared")
    plan = setup.plan_setup(fixture.observation, selection)
    with pytest.raises(setup.SetupError):
        replace(
            plan,
            rows=tuple(
                setup.PlanRow(value.category, "SKIPPED", "SETUP_NOT_REQUIRED", ())
                if value.category == "private-credentials"
                else value
                for value in plan.rows
            ),
        )
    with pytest.raises(setup.SetupError):
        replace(
            plan,
            rows=tuple(
                replace(value, prerequisites=("registry",)) if value.category == "preview" else value
                for value in plan.rows
            ),
        )


def test_source_advance_requests_registry_metadata_review_without_configuration_generation_rotation(fixture):
    initial = setup.plan_setup(fixture.observation, fixture.selection)
    original = replace(
        initial.instance_plan.descriptor, config_generation=str(uuid.uuid4()), configuration_present=True
    )
    entry = setup.registry.RegistryEntry(original, revision=7, state="STOPPED", operations=("REGISTRY_PREPARED",))
    selected = replace(fixture.observation.worktree, head="d" * 40)
    snapshot = replace(fixture.observation.repository, head=selected.head, worktrees=(selected,))
    observed = replace(
        fixture.observation,
        repository=snapshot,
        worktree=selected,
        registry_snapshot=setup.registry.RegistrySnapshot(entries=(entry,)),
    )
    planned = setup.plan_setup(observed, fixture.selection)
    assert row(planned, "registry").status == "NEEDS_APPROVAL" and row(planned, "registry").executable
    assert row(planned, "registry").code == "SETUP_REGISTRY_SOURCE_REVIEW_REQUIRED"
    current = planned.instance_plan.descriptor
    assert current.instance_id == original.instance_id and current.config_generation == original.config_generation
    assert current.configuration_present and current.commit == selected.head
    assert not row(planned, "private-credentials").executable and not row(planned, "certificates").executable


@pytest.mark.parametrize("state", ["READY", "STARTING", "BLOCKED", "FAILED"])
def test_source_advance_does_not_refresh_active_or_uncertain_registry_records(fixture, state):
    initial = setup.plan_setup(fixture.observation, fixture.selection)
    entry = setup.registry.RegistryEntry(initial.instance_plan.descriptor, state=state)
    selected = replace(fixture.observation.worktree, head="d" * 40)
    observed = replace(
        fixture.observation,
        worktree=selected,
        repository=replace(fixture.observation.repository, head=selected.head, worktrees=(selected,)),
        registry_snapshot=setup.registry.RegistrySnapshot(entries=(entry,)),
    )
    plan = setup.plan_setup(observed, fixture.selection)
    assert row(plan, "registry").status == "INCOMPATIBLE" and not row(plan, "registry").executable


def test_registry_metadata_update_preserves_state_configuration_and_operation_history(fixture):
    initial = setup.plan_setup(fixture.observation, fixture.selection)
    store = fixture.observation.registry_store
    setup.storage.initialize_private_directory(store.root, anchor=store.anchor)
    previous = setup.registry.RegistryEntry(
        initial.instance_plan.descriptor,
        revision=1,
        state="STOPPED",
        last_code="STOP_REQUESTED",
        operations=("REGISTRY_PREPARED", "STOP_REQUESTED"),
    )
    store.publish(previous, expected_revision=0)
    selected = replace(fixture.candidate.selected, head="d" * 40)
    fixture.candidate.snapshot = replace(fixture.candidate.snapshot, head=selected.head, worktrees=(selected,))
    plan = setup.plan_setup(fixture.observe(), fixture.selection)
    assert row(plan, "registry").code == "SETUP_REGISTRY_SOURCE_REVIEW_REQUIRED"
    denied = Mock(side_effect=AssertionError("Registry review must not rotate private credentials/certificates"))
    adapters = tuple(
        setup.StageAdapter(category, denied, denied) for category in ("private-credentials", "certificates")
    )
    run = setup.SetupExecutor(
        reobserve=lambda selection: setup.plan_setup(fixture.observe(selection), selection),
        adapters=adapters,
        clock=lambda: 1,
    )
    result = run.execute_selected(plan, ("registry",), consent(plan, "registry"), interactive=True)
    assert result.exit_code == 0
    updated = store.read().entries[0]
    assert updated.state == previous.state and updated.last_code == previous.last_code
    assert updated.revision == 2 and updated.operations == (*previous.operations, "REGISTRY_PREPARED")
    assert updated.descriptor.config_generation == previous.descriptor.config_generation
    denied.assert_not_called()


@pytest.mark.parametrize("family", ["legacy-managed", "legacy-env", "greenfield"])
def test_existing_family_must_be_preserved_but_does_not_block_dependency_only(fixture, family):
    selection = replace(fixture.selection, existing_family=family)
    plan = setup.plan_setup(replace(fixture.observation, private_configuration_present=True), selection)
    assert row(plan, "selection").status == "INCOMPATIBLE"
    assert row(plan, "dependencies").executable
    preserved = setup.plan_setup(fixture.observation, replace(selection, family=family))
    assert row(preserved, "selection").status == "READY"
    assert preserved.to_dict()["existing_family_preserved"] == family


def test_wrong_selected_worktree_cannot_register(fixture):
    plan = setup.plan_setup(fixture.observation, replace(fixture.selection, worktree_id="f" * 64))
    assert row(plan, "selection").status == "MISSING"
    assert not row(plan, "registry").executable


def test_unknown_registry_is_preserved_and_dependency_plan_remains_independent(fixture):
    observation = replace(
        fixture.observation, registry_snapshot=setup.registry.RegistrySnapshot(codes=("REGISTRY_UNKNOWN_ARTIFACT",))
    )
    plan = setup.plan_setup(observation, fixture.selection)
    assert row(plan, "registry").status == "BLOCKED"
    assert row(plan, "dependencies").executable


def test_real_default_registry_and_synthetic_dependency_adapters_prepare_once(fixture):
    plan = setup.plan_setup(fixture.observation, fixture.selection)

    def reobserve(selection):
        return setup.plan_setup(fixture.observe(), selection)

    runner = setup.SetupExecutor(reobserve=reobserve, clock=lambda: 1, dependency_runner=fixture.candidate.runner)
    outcome = runner.execute_selected(
        plan, ("registry", "dependencies"), consent(plan, "registry", "dependencies"), interactive=True
    )
    assert outcome.exit_code == 0, outcome
    assert [(value.category, value.status) for value in outcome.stages if value.status == "COMPLETED"] == [
        ("registry", "COMPLETED"),
        ("dependencies", "COMPLETED"),
    ]
    records = fixture.observation.registry_store.read()
    assert (
        not records.codes
        and len(records.entries) == 1
        and records.entries[0].descriptor == plan.instance_plan.descriptor
    )
    fresh = reobserve(fixture.selection)
    assert row(fresh, "registry").status == row(fresh, "dependencies").status == "READY"
    assert not fresh.to_dict()["application_ready"]
    before = list(fixture.candidate.runner.calls)
    again = runner.execute_selected(fresh, ("registry", "dependencies"), (), interactive=True)
    assert again.exit_code == 0 and fixture.candidate.runner.calls == before
    fixture.candidate.forbidden.assert_not_called()


def test_dependency_failure_retains_artifacts_and_redacts_raw_errors(fixture):
    fixture.candidate.runner.failure = "pip-install"
    plan = setup.plan_setup(fixture.observation, fixture.selection)
    outcome = setup.SetupExecutor(
        reobserve=lambda selection: setup.plan_setup(fixture.observe(), selection),
        dependency_runner=fixture.candidate.runner,
        clock=lambda: 1,
    ).execute_selected(plan, ("dependencies",), consent(plan, "dependencies"), interactive=True)
    assert outcome.exit_code == 1
    result = next(value for value in outcome.stages if value.category == "dependencies")
    assert result.status == "FAILED" and result.artifacts_retained
    assert SECRET not in repr(outcome) + json.dumps(outcome.to_dict())
    assert (fixture.candidate.root / ".venv").exists()


@pytest.mark.parametrize("journal_failure", [False, True])
def test_dependency_cancellation_stops_every_later_mutation(fixture, monkeypatch, journal_failure):
    plan = scoped_plan(fixture, statuses={"provider-policy": "NEEDS_APPROVAL"}, categories=("provider-policy",))
    monkeypatch.setattr(
        setup.dependencies,
        "prepare_dependencies",
        lambda *args, **kwargs: SimpleNamespace(exit_code=130, artifacts_retained=True),
    )
    mutate = Mock(side_effect=AssertionError("Cancellation continued setup"))
    adapter = setup.StageAdapter("provider-policy", mutate, mutate)
    journal = SimpleNamespace(record=Mock(side_effect=OSError(SECRET) if journal_failure else None))
    result = executor(plan, (adapter,), journal=journal).execute_selected(
        plan, ("dependencies", "provider-policy"), consent(plan, "dependencies", "provider-policy"), interactive=True
    )
    assert result.exit_code == 130 and result.stages[2].category == "dependencies"
    assert result.stages[2].artifacts_retained
    if journal_failure:
        assert result.stages[-1].code == "SETUP_JOURNAL_UNCONFIRMED"
    assert SECRET not in repr(result)
    mutate.assert_not_called()


def test_dependency_consent_expiry_prevents_later_installer_children(fixture):
    plan = setup.plan_setup(fixture.observation, fixture.selection)
    now = [1]
    fixture.candidate.runner.on_install = lambda: now.__setitem__(0, 101)
    result = setup.SetupExecutor(
        reobserve=lambda selection: setup.plan_setup(fixture.observe(), selection),
        clock=lambda: now[0],
        dependency_runner=fixture.candidate.runner,
    ).execute_selected(plan, ("dependencies",), consent(plan, "dependencies"), interactive=True)
    stage = next(value for value in result.stages if value.category == "dependencies")
    assert result.exit_code == 1 and stage.artifacts_retained and stage.code == "SETUP_CONSENT_EXPIRED"
    assert any("install" in command for command, _options in fixture.candidate.runner.calls)
    assert not any(command[-1] == "check" or "ci" in command for command, _options in fixture.candidate.runner.calls)


@pytest.mark.parametrize("check,interactive", [(True, True), (True, False), (False, False)])
def test_check_and_non_tty_never_invoke_any_mutator_or_journal(fixture, monkeypatch, check, interactive):
    plan = scoped_plan(fixture, statuses={"provider-policy": "NEEDS_APPROVAL"}, categories=("provider-policy",))
    forbidden = Mock(side_effect=AssertionError("Read-only setup attempted mutation"))
    adapter = setup.StageAdapter("provider-policy", forbidden, forbidden)
    monkeypatch.setattr(setup.dependencies, "prepare_dependencies", forbidden)
    monkeypatch.setattr(setup.storage, "initialize_private_directory", forbidden)
    monkeypatch.setattr(setup.registry.InstanceRegistry, "publish", forbidden)
    monkeypatch.setattr(uuid, "uuid4", forbidden)
    journal = SimpleNamespace(record=forbidden)
    outcome = setup.SetupExecutor(reobserve=forbidden, adapters=(adapter,), journal=journal).execute_selected(
        plan,
        ("registry", "dependencies", "provider-policy"),
        consent(plan, "registry", "dependencies", "provider-policy"),
        check=check,
        interactive=interactive,
    )
    assert outcome.code == "SETUP_READ_ONLY" and len(outcome.stages) == len(setup._CATEGORIES)
    forbidden.assert_not_called()


@pytest.mark.parametrize("kind", ["missing", "expired", "wrong-plan", "wrong-target"])
def test_exact_consent_precedes_every_mutator(fixture, monkeypatch, kind):
    plan = setup.plan_setup(fixture.observation, fixture.selection)
    values = consent(plan, "dependencies")
    if kind == "missing":
        values = ()
    elif kind == "expired":
        values = consent(plan, "dependencies", issued=-10, expires=-1)
    elif kind == "wrong-plan":
        values = (replace(values[0], plan_fingerprint="f" * 64),)
    else:
        values = (replace(values[0], target_fingerprint="f" * 64),)
    forbidden = Mock(side_effect=AssertionError("Unauthorized mutator"))
    monkeypatch.setattr(setup.dependencies, "prepare_dependencies", forbidden)
    outcome = executor(plan).execute_selected(plan, ("dependencies",), values, interactive=True)
    assert outcome.exit_code == 1
    assert next(value for value in outcome.stages if value.category == "dependencies").code in {
        "SETUP_CONSENT_REQUIRED",
        "SETUP_CONSENT_EXPIRED",
    }
    forbidden.assert_not_called()


@pytest.mark.parametrize("drift", ["controller", "head", "manifest", "registry"])
def test_drift_refuses_before_any_mutation(fixture, monkeypatch, drift):
    plan = setup.plan_setup(fixture.observation, fixture.selection)
    observation = fixture.observation
    category = "dependencies"
    if drift == "controller":
        observation = replace(observation, controller_fingerprint="f" * 64)
    elif drift == "head":
        selected = replace(observation.worktree, head="d" * 40)
        observation = replace(
            observation, worktree=selected, repository=replace(observation.repository, worktrees=(selected,))
        )
    elif drift == "manifest":
        (fixture.candidate.root / "requirements.txt").write_text("demo==2.3.4\n", encoding="utf-8")
        observation = fixture.observe()
    else:
        category = "registry"
        observation = replace(
            observation, registry_snapshot=setup.registry.RegistrySnapshot(codes=("REGISTRY_UNKNOWN_ARTIFACT",))
        )
    current = setup.plan_setup(observation, fixture.selection)
    forbidden = Mock(side_effect=AssertionError("Drift reached mutator"))
    monkeypatch.setattr(setup.dependencies, "prepare_dependencies", forbidden)
    monkeypatch.setattr(setup.storage, "initialize_private_directory", forbidden)
    outcome = setup.SetupExecutor(reobserve=lambda _selection: current, clock=lambda: 1).execute_selected(
        plan, (category,), consent(plan, category), interactive=True
    )
    assert next(value for value in outcome.stages if value.category == category).code == "SETUP_DRIFT_DETECTED"
    forbidden.assert_not_called()


def test_expiry_during_observation_refuses_before_authority_and_mutation(fixture):
    plan = scoped_plan(fixture, statuses={"provider-policy": "NEEDS_APPROVAL"}, categories=("provider-policy",))
    now = [1]
    authorize, mutate = Mock(return_value=proof(plan, "provider-policy")), Mock()

    def observe(_selection):
        now[0] = 101
        return plan

    adapter = setup.StageAdapter("provider-policy", mutate, authorize)
    outcome = setup.SetupExecutor(reobserve=observe, adapters=(adapter,), clock=lambda: now[0]).execute_selected(
        plan, ("provider-policy",), consent(plan, "provider-policy"), interactive=True
    )
    assert outcome.exit_code == 1 and mutate.call_count == 0


@pytest.mark.parametrize("authorization", [True, False, None])
def test_user_consent_and_boolean_assertions_are_not_independent_authority(fixture, authorization):
    plan = scoped_plan(fixture, statuses={"provider-policy": "NEEDS_APPROVAL"}, categories=("provider-policy",))
    mutate = Mock(side_effect=AssertionError("Unauthorized sensitive mutation"))
    adapter = setup.StageAdapter("provider-policy", mutate, lambda _plan, _consent: authorization)
    result = executor(plan, (adapter,)).execute_selected(
        plan, ("provider-policy",), consent(plan, "provider-policy"), interactive=True
    )
    assert (
        result.exit_code == 1
        and next(value for value in result.stages if value.category == "provider-policy").code
        == "SETUP_AUTHORITY_REQUIRED"
    )
    mutate.assert_not_called()


def test_sensitive_authority_is_revalidated_at_the_adapters_mutation_boundary(fixture):
    plan = scoped_plan(fixture, statuses={"provider-policy": "NEEDS_APPROVAL"}, categories=("provider-policy",))
    events, allowed = [], [True]

    def authorize(current, _consent):
        events.append("authority")
        return proof(current, "provider-policy") if allowed[0] else None

    def execute(_current, guard):
        allowed[0] = False
        guard("provider-policy")
        events.append("unsafe-mutation")

    adapter = setup.StageAdapter("provider-policy", execute, authorize)
    result = executor(plan, (adapter,)).execute_selected(
        plan, ("provider-policy",), consent(plan, "provider-policy"), interactive=True
    )
    assert result.exit_code == 1 and "unsafe-mutation" not in events
    assert events == ["authority", "authority"]
    assert next(value for value in result.stages if value.category == "provider-policy").artifacts_retained


def test_stage_order_partial_failure_continues_independent_trust_and_retains_outcomes(fixture):
    statuses = {category: "READY" for category in setup._SENSITIVE}
    statuses.update({"provider-policy": "NEEDS_APPROVAL", "trust": "NEEDS_APPROVAL"})
    plan = scoped_plan(fixture, statuses=statuses, categories=("provider-policy", "trust"))
    events = []

    def failed(_plan, _guard):
        events.append("provider-policy")
        raise ValueError(SECRET)

    def trusted(_plan, guard):
        guard("trust")
        events.append("trust")
        return setup.StageOutcome("trust", "COMPLETED", "SETUP_STAGE_COMPLETED", ("trust",), True)

    adapters = tuple(
        setup.StageAdapter(category, callback, lambda current, _consent, category=category: proof(current, category))
        for category, callback in (("provider-policy", failed), ("trust", trusted))
    )
    journal = SimpleNamespace(record=Mock())
    outcome = executor(plan, adapters, journal=journal).execute_selected(
        plan, ("trust", "provider-policy"), consent(plan, "trust", "provider-policy"), interactive=True
    )
    assert events == ["provider-policy", "trust"] and outcome.code == "SETUP_PARTIAL_RETAINED"
    assert len(outcome.stages) == len(setup._CATEGORIES) and journal.record.call_count == 1
    assert SECRET not in repr(outcome) + json.dumps(outcome.to_dict())


def test_bundle_adapter_requires_separate_certificate_and_credential_consents(fixture):
    statuses = {"provider-policy": "READY", "private-credentials": "NEEDS_APPROVAL", "certificates": "NEEDS_APPROVAL"}
    observation = fixture.observation
    base = setup.plan_setup(observation, fixture.selection)
    entry = setup.registry.RegistryEntry(base.instance_plan.descriptor)
    fixture.observation = replace(observation, registry_snapshot=setup.registry.RegistrySnapshot(entries=(entry,)))
    plan = scoped_plan(fixture, statuses=statuses, categories=("private-credentials", "certificates"))
    calls = []

    def execute(_plan, guard):
        guard("private-credentials")
        guard("certificates")
        calls.append("bundle")
        return setup.StageOutcome(
            "private-credentials", "COMPLETED", "SETUP_STAGE_COMPLETED", ("private-credentials", "certificates"), True
        )

    adapter = setup.StageAdapter(
        "private-credentials", execute, lambda current, approved: proof(current, approved.category), ("certificates",)
    )
    denied = executor(plan, (adapter,)).execute_selected(
        plan, ("private-credentials",), consent(plan, "private-credentials"), interactive=True
    )
    assert denied.exit_code == 1 and not calls
    accepted = executor(plan, (adapter,)).execute_selected(
        plan,
        ("private-credentials", "certificates"),
        consent(plan, "private-credentials", "certificates"),
        interactive=True,
    )
    assert accepted.exit_code == 0 and calls == ["bundle"]
    assert next(value for value in accepted.stages if value.category == "certificates").code == "SETUP_ALREADY_READY"


def test_failed_bundle_consumes_every_required_consent_and_cannot_replay_it(fixture):
    base = setup.plan_setup(fixture.observation, fixture.selection)
    fixture.observation = replace(
        fixture.observation,
        registry_snapshot=setup.registry.RegistrySnapshot(
            entries=(setup.registry.RegistryEntry(base.instance_plan.descriptor),)
        ),
    )
    plan = scoped_plan(
        fixture,
        statuses={
            "provider-policy": "READY",
            "private-credentials": "NEEDS_APPROVAL",
            "certificates": "NEEDS_APPROVAL",
        },
        categories=("private-credentials", "certificates"),
    )
    calls = []

    def execute(_plan, _guard):
        calls.append("credentials")
        raise ValueError(SECRET)

    later = Mock(side_effect=AssertionError("Consumed consent reused"))
    adapters = (
        setup.StageAdapter(
            "private-credentials",
            execute,
            lambda current, approved: proof(current, approved.category),
            ("certificates",),
        ),
        setup.StageAdapter(
            "certificates", later, lambda current, approved: proof(current, approved.category), ("private-credentials",)
        ),
    )
    run = executor(plan, adapters)
    approvals = consent(plan, "private-credentials", "certificates")
    result = run.execute_selected(plan, ("private-credentials", "certificates"), approvals, interactive=True)
    assert result.exit_code == 1 and calls == ["credentials"]
    assert next(value for value in result.stages if value.category == "certificates").code == "SETUP_CONSENT_REQUIRED"
    repeat = run.execute_selected(plan, ("certificates", "private-credentials"), approvals, interactive=True)
    assert repeat.exit_code == 1 and calls == ["credentials"]
    later.assert_not_called()


@pytest.mark.parametrize(
    "new_status,new_reference", [("BLOCKED", "e" * 64), ("INCOMPATIBLE", "e" * 64), ("READY", "f" * 64)]
)
def test_completed_prerequisite_cannot_override_fresh_negative_or_reference_drift(fixture, new_status, new_reference):
    base = setup.plan_setup(fixture.observation, fixture.selection)
    fixture.observation = replace(
        fixture.observation,
        registry_snapshot=setup.registry.RegistrySnapshot(
            entries=(setup.registry.RegistryEntry(base.instance_plan.descriptor),)
        ),
    )
    statuses = {"provider-policy": "NEEDS_APPROVAL", "private-credentials": "NEEDS_APPROVAL"}
    plan = scoped_plan(fixture, statuses=statuses, categories=tuple(statuses))
    current = [plan]

    def policy(_plan, guard):
        guard("provider-policy")
        stages = tuple(
            replace(value, status=new_status, reference=new_reference) if value.category == "provider-policy" else value
            for value in plan.contexts.stages
        )
        current[0] = setup.plan_setup(
            fixture.observation,
            fixture.selection,
            contexts=setup.Contexts(stages),
            registered_categories=tuple(statuses),
        )
        return setup.StageOutcome("provider-policy", "COMPLETED", "SETUP_STAGE_COMPLETED", ("provider-policy",), True)

    credentials = Mock(side_effect=AssertionError("Drifted prerequisite reached mutation"))
    adapters = (
        setup.StageAdapter("provider-policy", policy, lambda fresh, approved: proof(fresh, approved.category)),
        setup.StageAdapter("private-credentials", credentials, lambda fresh, approved: proof(fresh, approved.category)),
    )
    result = setup.SetupExecutor(
        reobserve=lambda _selection: current[0], adapters=adapters, clock=lambda: 1
    ).execute_selected(plan, tuple(statuses), consent(plan, *statuses), interactive=True)
    assert (
        result.exit_code == 1
        and next(value for value in result.stages if value.category == "provider-policy").status == "COMPLETED"
    )
    assert next(value for value in result.stages if value.category == "private-credentials").status == "BLOCKED"
    credentials.assert_not_called()


def native_context(plan):
    descriptor = plan.instance_plan.descriptor
    return setup.onboarding.OnboardingContext(
        descriptor.repository_id,
        descriptor.worktree_id,
        descriptor.instance_id,
        descriptor.commit,
        descriptor.generation,
        descriptor.config_generation,
        "d" * 64,
        "127.0.0.1",
        descriptor.ports["postgres"],
        descriptor.resources["database"],
        "103_tenant_admin_governance",
        descriptor.origin,
        descriptor.auth_mode,
    )


@pytest.mark.parametrize(
    "state,status,code",
    [
        ("EXISTING_ADMIN", "READY", "ONBOARDING_EXISTING_ADMIN"),
        ("ENROLLMENT_COMPLETED", "WARN", "ONBOARDING_COMPLETED_RESERVATION_PRESERVED"),
        ("ENROLLMENT_PENDING", "WARN", "ONBOARDING_PENDING_RESERVATION_PRESERVED"),
        ("ENROLLMENT_REQUIRED", "NEEDS_APPROVAL", "ENROLLMENT_READINESS_CONTRACT_REQUIRED"),
        ("UNKNOWN", "BLOCKED", "ONBOARDING_INSPECTION_REQUIRED"),
    ],
)
def test_native_guidance_observes_existing_and_pending_state_without_live_action(fixture, state, status, code):
    base = setup.plan_setup(fixture.observation, fixture.selection)
    guidance = setup.onboarding.OnboardingPlan(state, code, native_context(base), "f" * 64)
    plan = scoped_plan(fixture, contexts=setup.Contexts(onboarding_plan=guidance))
    assert row(plan, "onboarding").status == status and not row(plan, "onboarding").executable
    result = executor(plan).execute_selected(plan, ("onboarding",), consent(plan, "onboarding"), interactive=True)
    stage = next(value for value in result.stages if value.category == "onboarding")
    assert stage.code == ("SETUP_ALREADY_READY" if status == "READY" else "SETUP_PRIVILEGED_ONBOARDING_GATED")
    assert not result.to_dict()["privileged_onboarding_authorized"]


def test_completed_historical_enrollment_never_implies_an_effective_current_admin_or_reopens_it(fixture, monkeypatch):
    base = setup.plan_setup(fixture.observation, fixture.selection)
    guidance = setup.onboarding.OnboardingPlan(
        "ENROLLMENT_COMPLETED", "ONBOARDING_COMPLETED_RESERVATION_PRESERVED", native_context(base), "f" * 64
    )
    forbidden = Mock(side_effect=AssertionError("Completed reservation attempted privileged creation or recovery"))
    original_import = builtins.__import__

    def safe_import(name, *args, **kwargs):
        assert name.split(".", 1)[0] not in {"app", "psycopg", "sqlalchemy", "alembic", "celery", "redis"}
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", safe_import)
    plan = scoped_plan(fixture, contexts=setup.Contexts(onboarding_plan=guidance))
    value = row(plan, "onboarding")
    assert value.status == "WARN" and value.code == "SETUP_NATIVE_COMPLETED_RESERVATION_PRESERVED"
    assert not value.executable and value.code != "SETUP_NATIVE_ADMIN_EXISTS"
    text = value.to_dict()["guidance"]
    assert "does not establish a current Platform Admin grant" in text
    assert "approved effective-administrator status and recovery review" in text
    run = setup.SetupExecutor(reobserve=forbidden, journal=SimpleNamespace(record=forbidden))
    result = run.execute_selected(plan, ("onboarding",), consent(plan, "onboarding"), interactive=True)
    outcome = next(value for value in result.stages if value.category == "onboarding")
    assert outcome.status == "BLOCKED" and outcome.code == "SETUP_PRIVILEGED_ONBOARDING_GATED"
    assert not result.to_dict()["privileged_onboarding_authorized"] and not result.to_dict()["authentication_ready"]
    assert guidance.state == "ENROLLMENT_COMPLETED" and guidance.code == "ONBOARDING_COMPLETED_RESERVATION_PRESERVED"
    forbidden.assert_not_called()


@pytest.mark.parametrize("existing_users", [False, True])
def test_completed_reservation_with_missing_or_revoked_admin_remains_warn_after_real_pure_classification(
    fixture, existing_users
):
    initial = setup.plan_setup(fixture.observation, fixture.selection)
    descriptor = replace(initial.instance_plan.descriptor, config_generation=1, configuration_present=True)
    observed = replace(
        fixture.observation,
        registry_snapshot=setup.registry.RegistrySnapshot(entries=(setup.registry.RegistryEntry(descriptor),)),
    )
    base = setup.plan_setup(observed, fixture.selection)
    context = native_context(base)
    status = setup.onboarding.PublicEnrollmentStatus(
        "BOOTSTRAP_RESERVED", "COMPLETED", False, False, existing_users, False
    )
    classified = setup.onboarding.plan_onboarding(
        expected_context=context, observed_context=context, status=status, schema_state="READY"
    )
    assert classified.state == "ENROLLMENT_COMPLETED" and not classified.live_enrollment_authorized
    result = setup.plan_setup(observed, fixture.selection, contexts=setup.Contexts(onboarding_plan=classified))
    value = row(result, "onboarding")
    assert (value.status, value.code) == ("WARN", "SETUP_NATIVE_COMPLETED_RESERVATION_PRESERVED")
    assert not value.executable and not result.to_dict()["authentication_ready"]


@pytest.mark.parametrize(
    "mode,auth,expected",
    [("mock", "native", "SETUP_NOT_REQUIRED"), ("isolated", "hcl", "SETUP_HCL_PROVISIONING_APPROVAL_REQUIRED")],
)
def test_historical_native_completion_never_unlocks_mock_or_hcl_onboarding(fixture, mode, auth, expected):
    base = setup.plan_setup(fixture.observation, fixture.selection)
    completed = setup.onboarding.OnboardingPlan(
        "ENROLLMENT_COMPLETED", "ONBOARDING_COMPLETED_RESERVATION_PRESERVED", native_context(base), "f" * 64
    )
    selection = replace(fixture.selection, mode=mode, auth_mode=auth, provider=None)
    plan = setup.plan_setup(fixture.observation, selection, contexts=setup.Contexts(onboarding_plan=completed))
    assert row(plan, "onboarding").code == expected and not row(plan, "onboarding").executable
    assert row(plan, "onboarding").status != "READY" and not plan.to_dict()["authentication_ready"]


def test_native_observation_target_drift_cannot_claim_existing_administrator(fixture):
    base = setup.plan_setup(fixture.observation, fixture.selection)
    context = replace(native_context(base), database_name="different_database")
    guidance = setup.onboarding.OnboardingPlan("EXISTING_ADMIN", "ONBOARDING_EXISTING_ADMIN", context, "f" * 64)
    plan = scoped_plan(fixture, contexts=setup.Contexts(onboarding_plan=guidance))
    assert row(plan, "onboarding").status == "BLOCKED"


def test_existing_hcl_identity_can_be_reused_but_provisioning_remains_blocked(fixture):
    fixture.selection = replace(fixture.selection, auth_mode="hcl")
    base = setup.plan_setup(fixture.observation, fixture.selection)
    identity = setup.ExistingIdentity(native_context(base), "f" * 64, "EXISTING_AUTHORIZED")
    plan = scoped_plan(fixture, contexts=setup.Contexts(external_identity=identity))
    assert row(plan, "onboarding").code == "SETUP_HCL_IDENTITY_EXISTS"
    missing = scoped_plan(fixture)
    assert row(missing, "onboarding").code == "SETUP_HCL_PROVISIONING_APPROVAL_REQUIRED"
    assert not row(missing, "onboarding").executable


class FakeIO:
    def __init__(self, selected=(), interactive=True):
        self.selected, self.is_interactive, self.events = selected, interactive, []

    def interactive(self):
        self.events.append("interactive")
        return self.is_interactive

    def choose_selection(self, selection):
        self.events.append("selection")
        return replace(selection, mode="isolated", auth_mode="native", family="instance")

    def display(self, plan):
        self.events.append("plan")
        assert SECRET not in json.dumps(plan.to_dict())

    def approve_categories(self, choices):
        self.events.append("approval")
        assert set(self.selected) <= set(choices)
        return self.selected


def test_guided_tty_asks_scoped_selection_once_and_displays_one_consolidated_plan(fixture):
    io = FakeIO()

    def planner(selection):
        return setup.plan_setup(fixture.observation, selection)

    run = setup.SetupExecutor(reobserve=planner)
    outcome = setup.guided_session(
        replace(fixture.selection, mode=None, auth_mode=None, family=None), planner=planner, executor=run, io=io
    )
    assert outcome.code == "SETUP_READ_ONLY"
    assert io.events == ["interactive", "selection", "plan", "approval"]


@pytest.mark.parametrize("check", [False, True])
def test_guided_noninteractive_or_check_never_prompts_or_prepares(fixture, check):
    io = FakeIO(interactive=check)  # check wins even when IO would be a TTY.

    def planner(selection):
        return setup.plan_setup(fixture.observation, selection)

    forbidden = Mock(side_effect=AssertionError("Read-only session reached mutator"))
    run = setup.SetupExecutor(reobserve=forbidden, journal=SimpleNamespace(record=forbidden))
    result = setup.guided_session(fixture.selection, planner=planner, executor=run, io=io, check=check)
    assert result.code == "SETUP_READ_ONLY"
    assert io.events == (["plan"] if check else ["interactive", "plan"])
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "error,code,exit_code",
    [
        (KeyboardInterrupt(), "SETUP_CANCELLED", 130),
        (EOFError(), "SETUP_CANCELLED", 130),
        (ValueError(SECRET), "SETUP_OBSERVATION_BLOCKED", 1),
    ],
)
def test_guided_errors_are_safe_and_do_not_start_followup_actions(fixture, error, code, exit_code):
    failed = Mock(side_effect=error)
    result = setup.guided_session(fixture.selection, planner=failed, executor=Mock(), io=FakeIO())
    assert result.code == code and result.exit_code == exit_code
    assert SECRET not in repr(result) + json.dumps(result.to_dict())


@pytest.mark.parametrize(
    "factory",
    [
        lambda: setup.Selection(mode=[]),
        lambda: setup.Selection(family=[]),
        lambda: setup.StageContext("provider-policy", "READY", SECRET, "f" * 64),
        lambda: setup.StageConsent("dependencies", "e" * 64, "f" * 64, 0, 121),
        lambda: setup.StageOutcome("dependencies", "FAILED", "SETUP_STAGE_FAILED", ("dependencies",)),
        lambda: setup.StageOutcome("dependencies", "COMPLETED", "SETUP_STAGE_COMPLETED"),
        lambda: setup.StageAuthority([], "e" * 64, "f" * 64, frozenset()),
        lambda: setup.StageAdapter("onboarding", Mock(), Mock()),
    ],
)
def test_malformed_or_privileged_dtos_fail_closed_and_redact_input(factory):
    with pytest.raises(setup.SetupError) as raised:
        factory()
    assert SECRET not in str(raised.value)
