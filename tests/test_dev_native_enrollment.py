"""Synthetic operator protocol/transaction tests; use --noconftest, no live app/DB."""

from __future__ import annotations

import builtins
import io
import json
import os
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts import dev_config, dev_diagnostics, dev_operator
from scripts import dev_native_enrollment as enrollment

SECRET = "fixture-enrollment-secret-never-print"
EMAIL = "private-fixture@example.test"
HEAD = "103_tenant_admin_governance"


def identity():
    return enrollment.EnrollmentIdentity(EMAIL, "Private", "Fixture", "fixture-phone", "approved-fixture-reference")


def report(*, omit=None, extra=()):
    results = tuple(
        dev_diagnostics.DiagnosticResult(name, "PASS", code, "Safe fixture evidence.")
        for name, code in sorted(enrollment._REQUIRED)
        if (name, code) != omit
    )
    return dev_diagnostics.DiagnosticReport((*results, *extra))


@pytest.fixture
def candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    root = tmp_path / "checkout"
    source = Path(enrollment.__file__).resolve().parents[1]
    for name in enrollment._SOURCES:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / name).read_bytes())
    (root / ".env.dev.local").write_text("fixture-selected-configuration", encoding="utf-8")
    environment = dev_operator.OperatorEnvironment(
        {
            "DATABASE_URL": f"postgresql+psycopg://fixture:{SECRET}@localhost:5432/sbom_analyser_dev",
            "APP_ENVIRONMENT": "development",
            "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "false",
        }
    )
    context = dev_operator.NativeOperatorContext(
        "legacy",
        "managed",
        dev_config.DatabaseTarget("localhost", 5432, "sbom_analyser_dev"),
        "sbom_analyser_dev",
        environment,
        root,
        root,
    )
    launcher = SimpleNamespace(ROOT=root, venv_python=lambda: Path(sys.executable))
    args = SimpleNamespace(profile="legacy", legacy_config="managed", confirm_database="sbom_analyser_dev")
    resolve = Mock(return_value=context)
    status = Mock(
        return_value=dev_operator.NativeEnrollmentStatus(
            "ENROLLMENT_REQUIRED", "NOT_STARTED", False, True, False, False
        )
    )
    monkeypatch.setattr(dev_operator, "resolve_native_context", resolve)
    monkeypatch.setattr(dev_operator, "inspect_native_enrollment", status)
    monkeypatch.setattr(enrollment, "discover", lambda root: SimpleNamespace(head=HEAD))
    monkeypatch.setattr(os, "environ", {"APP_ENVIRONMENT": "development"})
    # A real application/driver import is never permitted in this test process.
    original_import = builtins.__import__

    def guarded_import(name, *values, **keywords):
        assert not (name == "app" or name.startswith("app.") or name.split(".", 1)[0] in {"psycopg", "sqlalchemy"})
        return original_import(name, *values, **keywords)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    return SimpleNamespace(context=context, launcher=launcher, args=args, resolve=resolve, status=status)


def inspect(candidate, *, action="create", checker=None):
    return enrollment.inspect_enrollment(
        candidate.args, candidate.launcher, action=action, readiness_checker=checker or (lambda *values: report())
    )


def tty(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)


def test_plan_is_immutable_redacted_and_uses_exact_confirmed_context(candidate):
    planned = inspect(candidate)
    assert planned.context is candidate.context and planned.database == candidate.context.database
    assert SECRET not in repr(planned) and planned.fingerprint not in repr(planned)
    candidate.status.assert_called_once_with(candidate.context, confirm_database="sbom_analyser_dev")
    with pytest.raises(FrozenInstanceError):
        planned.action = "resend-activation"
    assert EMAIL not in repr(identity())


def test_greenfield_fingerprint_uses_only_existing_protected_credential_reader(candidate):
    protected = Mock(side_effect=lambda name: "fixture-private-json" if name == "environment.json" else SECRET)
    launcher = SimpleNamespace(GreenfieldStack=SimpleNamespace(read_private=protected))
    context = replace(candidate.context, profile="greenfield", family="greenfield")
    fingerprint = enrollment._fingerprint(context, HEAD, launcher)
    assert len(fingerprint) == 64 and SECRET not in fingerprint
    assert [call.args[0] for call in protected.call_args_list] == ["environment.json", "runtime-password"]


def test_operator_child_projection_excludes_unneeded_secrets_and_python_preloads_but_retains_required_inputs(candidate):
    required = {
        "NATIVE_JWT_PRIVATE_KEY": SECRET,
        "NATIVE_JWT_PUBLIC_KEY": "fixture-public-key",
        "NATIVE_SECURITY_OUTBOX_KEY": "fixture-outbox-key",
        "SMTP_PASSWORD": SECRET,
        "SMTP_HOST": "fixture-smtp.invalid",
        "SSL_CERT_FILE": "fixture-ca.pem",
        "SSL_CERT_DIR": "fixture-ca-directory",
        "NODE_EXTRA_CA_CERTS": "fixture-node-ca.pem",
    }
    unwanted = {
        "SECRET_TOKEN",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "UNREVIEWED_SOURCE_SETTING",
    }
    source = {**candidate.context.environment, **required, **dict.fromkeys(unwanted, SECRET)}
    context = replace(candidate.context, environment=dev_operator.OperatorEnvironment(source))
    projected = enrollment._child_environment(context)
    assert all(projected[key] == value for key, value in required.items())
    assert not unwanted & set(projected)
    assert projected["DATABASE_URL"] == candidate.context.environment["DATABASE_URL"]
    assert projected["PYTHONPATH"] == str(context.root)
    assert projected["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"
    assert projected["PYTHON_DOTENV_DISABLED"] == projected["PYTHONDONTWRITEBYTECODE"] == "1"
    assert SECRET not in repr(projected)


def test_canonical_child_fingerprint_ignores_unprojected_ambient_values_but_keeps_selected_file_drift(candidate):
    initial = enrollment._fingerprint(candidate.context, HEAD, candidate.launcher)
    changed = replace(
        candidate.context,
        environment=dev_operator.OperatorEnvironment(
            {
                **candidate.context.environment,
                "SECRET_TOKEN": SECRET,
                "LD_PRELOAD": "fixture-hook",
                "UNREVIEWED_SOURCE_SETTING": "fixture",
            }
        ),
    )
    assert enrollment._fingerprint(changed, HEAD, candidate.launcher) == initial
    (candidate.context.root / ".env.dev.local").write_text(
        "UNREVIEWED_SOURCE_SETTING=changed-fixture", encoding="utf-8"
    )
    assert enrollment._fingerprint(changed, HEAD, candidate.launcher) != initial


@pytest.mark.parametrize("name", ["PGHOSTADDR", "PGSSLMODE", "PGSERVICE"])
def test_ambiguous_libpq_environment_is_rejected_before_projection(candidate, name):
    context = replace(
        candidate.context, environment=dev_operator.OperatorEnvironment({**candidate.context.environment, name: SECRET})
    )
    with pytest.raises(dev_operator.OperatorError, match="OPERATOR_LIBPQ_REVIEW_REQUIRED"):
        enrollment._child_environment(context)


@pytest.mark.parametrize("omitted", sorted(enrollment._REQUIRED))
def test_every_readiness_fact_is_required_even_if_every_other_check_passes(candidate, omitted):
    with pytest.raises(enrollment.EnrollmentError):
        inspect(candidate, checker=lambda *values: report(omit=omitted))


def test_default_readiness_remains_blocked_until_missing_runtime_contract_is_implemented(candidate, monkeypatch):
    skipped = dev_diagnostics.DiagnosticResult("Runtime", "SKIPPED", "RUNTIME_STOPPED", "Safe fixture.")
    monkeypatch.setattr(dev_diagnostics, "run_checks", lambda *values: report(extra=(skipped,)))
    with pytest.raises(enrollment.EnrollmentError, match="ENROLLMENT_READINESS_CONTRACT_REQUIRED"):
        enrollment.inspect_enrollment(candidate.args, candidate.launcher, action="create")


@pytest.mark.parametrize("state", ["WARN", "FAIL", "BLOCKED", "SKIPPED"])
def test_nonpassing_runtime_observation_never_becomes_enrollment_permission(candidate, state):
    extra = (dev_diagnostics.DiagnosticResult("Runtime", state, "RUNTIME_NOT_READY", "Private details withheld."),)
    with pytest.raises(enrollment.EnrollmentError):
        inspect(candidate, checker=lambda *values: report(extra=extra))


@pytest.mark.parametrize("code", ["ADMIN_READY", "PENDING_ACTIVATION", "BOOTSTRAP_RESERVED"])
def test_create_requires_unreserved_enrollment_state(candidate, code):
    candidate.status.return_value = replace(candidate.status.return_value, code=code)
    with pytest.raises(enrollment.EnrollmentError, match="ENROLLMENT_STATE_REFUSED"):
        inspect(candidate)


def test_invalid_action_and_confirmation_fail_before_any_child_or_driver(candidate):
    with pytest.raises(enrollment.EnrollmentError, match="ENROLLMENT_ACTION_INVALID"):
        inspect(candidate, action="grant-platform-admin")
    candidate.resolve.assert_not_called()
    candidate.resolve.side_effect = dev_operator.OperatorError(
        "OPERATOR_DATABASE_CONFIRMATION_REQUIRED", "Safe guidance."
    )
    with pytest.raises(dev_operator.OperatorError):
        inspect(candidate)
    candidate.status.assert_not_called()


def test_noninteractive_run_is_readonly_and_does_not_prompt_or_spawn(candidate, monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    forbidden = Mock(side_effect=AssertionError("Noninteractive enrollment mutated or prompted"))
    result = enrollment.run_enrollment(
        candidate.args,
        candidate.launcher,
        action="create",
        identity=identity(),
        readiness_checker=lambda *values: report(),
        child_runner=forbidden,
        input_fn=forbidden,
    )
    assert result.code == "ENROLLMENT_APPROVAL_REQUIRED" and result.committed is False
    assert SECRET not in capsys.readouterr().out
    forbidden.assert_not_called()


@pytest.mark.parametrize("response", ["no", "yes", "", EOFError(), KeyboardInterrupt()])
def test_decline_eof_and_cancel_never_spawn(candidate, monkeypatch, response):
    tty(monkeypatch)
    forbidden = Mock(side_effect=AssertionError("Declined enrollment started a child"))
    prompt = Mock(side_effect=response) if isinstance(response, BaseException) else Mock(return_value=response)
    result = enrollment.run_enrollment(
        candidate.args,
        candidate.launcher,
        action="create",
        identity=identity(),
        readiness_checker=lambda *values: report(),
        child_runner=forbidden,
        input_fn=prompt,
    )
    assert result.code in {"ENROLLMENT_APPROVAL_DECLINED", "ENROLLMENT_CANCELLED"}
    assert result.committed is False
    forbidden.assert_not_called()


def test_explicit_identity_target_approval_rechecks_readiness_before_single_child(candidate, monkeypatch, capsys):
    tty(monkeypatch)
    checker = Mock(return_value=report())
    runner = Mock(return_value=enrollment.EnrollmentOutcome("ACTIVATION_QUEUED", 0, True))
    result = enrollment.run_enrollment(
        candidate.args,
        candidate.launcher,
        action="create",
        identity=identity(),
        readiness_checker=checker,
        child_runner=runner,
        input_fn=lambda prompt: "CREATE NATIVE PLATFORM ADMIN",
    )
    assert result.committed is True and checker.call_count == 2
    runner.assert_called_once()
    assert runner.call_args.args[1] == identity()
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize(
    "failure",
    [KeyboardInterrupt(), RuntimeError(SECRET), MemoryError(SECRET), SystemExit(SECRET)],
    ids=("interrupt", "unexpected-error", "memory-error", "exit"),
)
def test_lost_runner_outcome_after_authorization_never_claims_no_commit(candidate, monkeypatch, failure):
    tty(monkeypatch)
    handoffs = []

    def runner(*values):
        handoffs.append("operation may have committed")
        raise failure

    result = enrollment.run_enrollment(
        candidate.args,
        candidate.launcher,
        action="create",
        identity=identity(),
        readiness_checker=lambda *values: report(),
        child_runner=runner,
        input_fn=lambda prompt: "CREATE NATIVE PLATFORM ADMIN",
    )
    assert handoffs
    assert result.code == "OUTCOME_UNCONFIRMED" and result.committed is None
    assert result.cleanup_confirmed is False


def test_existing_users_require_additional_review_and_no_email_linking(candidate, monkeypatch):
    tty(monkeypatch)
    candidate.status.return_value = replace(candidate.status.return_value, existing_users_present=True)
    runner = Mock()
    result = enrollment.run_enrollment(
        candidate.args,
        candidate.launcher,
        action="create",
        identity=identity(),
        readiness_checker=lambda *values: report(),
        child_runner=runner,
        input_fn=lambda prompt: "CREATE NATIVE PLATFORM ADMIN",
    )
    assert result.code == "ENROLLMENT_APPROVAL_DECLINED"
    runner.assert_not_called()


def test_changed_configuration_after_consent_aborts_without_child(candidate, monkeypatch):
    tty(monkeypatch)
    runner = Mock()

    def approve(prompt):
        (candidate.context.root / ".env.dev.local").write_text("changed-fixture", encoding="utf-8")
        return "CREATE NATIVE PLATFORM ADMIN"

    result = enrollment.run_enrollment(
        candidate.args,
        candidate.launcher,
        action="create",
        identity=identity(),
        readiness_checker=lambda *values: report(),
        child_runner=runner,
        input_fn=approve,
    )
    assert result.code == "ENROLLMENT_PLAN_CHANGED"
    runner.assert_not_called()


class Helper:
    def __init__(self, *, timeout=False, cleanup=True, output=None):
        self.pid, self.returncode = 4567, None
        self.timeout, self.cleanup = timeout, cleanup
        self.output = output or json.dumps({"version": 1, "code": "ACTIVATION_QUEUED", "committed": True})
        self.terminated, self.killed = False, False
        self.payload = None

    def communicate(self, payload, timeout):
        self.payload = payload
        if self.timeout:
            raise subprocess.TimeoutExpired("owned-fixture-helper", timeout)
        self.returncode = 0
        return self.output, None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout):
        if not self.cleanup:
            raise subprocess.TimeoutExpired("owned-fixture-helper", timeout)
        self.returncode = -15


def test_helper_uses_environment_for_credentials_and_stdin_for_identity_never_argv_or_files(candidate, monkeypatch):
    planned = inspect(candidate)
    unwanted = {"SECRET_TOKEN", "PYTHONHOME", "PYTHONINSPECT", "LD_PRELOAD", "NODE_OPTIONS"}
    context = replace(
        planned.context,
        environment=dev_operator.OperatorEnvironment(
            {
                **planned.context.environment,
                **dict.fromkeys(unwanted, SECRET),
            }
        ),
    )
    planned = replace(planned, context=context)
    helper = Helper()
    popen = Mock(return_value=helper)
    monkeypatch.setattr(subprocess, "Popen", popen)
    before = dict(os.environ)
    result = enrollment._launch_child(planned, identity(), candidate.launcher)
    argv = popen.call_args.args[0]
    request = json.loads(helper.payload)
    assert SECRET not in str(argv) and EMAIL not in str(argv)
    assert request["identity"]["email"] == EMAIL and SECRET not in helper.payload
    assert popen.call_args.kwargs["env"]["DATABASE_URL"] == candidate.context.environment["DATABASE_URL"]
    assert popen.call_args.kwargs["env"]["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "false"
    assert not unwanted & set(popen.call_args.kwargs["env"])
    assert popen.call_args.kwargs["stderr"] is subprocess.DEVNULL
    assert "-B" in argv and result.committed is True
    assert os.environ == before


@pytest.mark.parametrize("cleanup", [True, False])
def test_timeout_is_unconfirmed_and_only_original_helper_handle_is_stopped(candidate, monkeypatch, cleanup):
    helper = Helper(timeout=True, cleanup=cleanup)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=helper))
    forbidden = Mock(side_effect=AssertionError("Enrollment attempted PID/tree termination"))
    monkeypatch.setattr(os, "kill", forbidden)
    result = enrollment._launch_child(inspect(candidate), identity(), candidate.launcher)
    assert result.code == "OUTCOME_UNCONFIRMED" and result.committed is None
    assert helper.terminated and result.cleanup_confirmed is cleanup
    assert result.helper_pid == (None if cleanup else helper.pid)
    forbidden.assert_not_called()


@pytest.mark.parametrize(
    "output",
    [
        {"secret": SECRET, "email": EMAIL},
        {"version": True, "code": "ACTIVATION_QUEUED", "committed": True},
    ],
)
def test_unrecognized_or_private_child_output_is_not_relayed(candidate, monkeypatch, capsys, output):
    helper = Helper(output=json.dumps(output))
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=helper))
    result = enrollment._launch_child(inspect(candidate), identity(), candidate.launcher)
    assert result.code == "OUTCOME_UNCONFIRMED"
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err and EMAIL not in captured.out + captured.err


class Connection:
    def __init__(self, events):
        self.events, self.database, self.revisions = events, "sbom_analyser_dev", [(HEAD,)]
        self.existing_users = False

    def execute(self, statement):
        assert str(statement).startswith("SELECT")
        self.events.append("proof")
        scalar = self.existing_users if "SELECT EXISTS" in str(statement) else self.database
        return SimpleNamespace(scalar_one=lambda: scalar, fetchall=lambda: self.revisions)


class Session:
    def __init__(self, events, connection):
        self.events, self.pinned_connection = events, connection
        self.commit_error = self.rollback_error = self.close_error = False
        self.person = SimpleNamespace(email=EMAIL)
        self.row = SimpleNamespace(user_id=123, state="PENDING")

    def connection(self):
        self.events.append("session-owns-transaction")
        return self.pinned_connection

    def flush(self):
        self.events.append("flush")

    def commit(self):
        self.events.append("commit")
        if self.commit_error:
            raise RuntimeError(SECRET)

    def rollback(self):
        self.events.append("rollback")
        if self.rollback_error:
            raise RuntimeError(SECRET)

    def close(self):
        self.events.append("close")
        if self.close_error:
            raise RuntimeError(SECRET)

    def get(self, model, key, *, with_for_update):
        assert with_for_update is True
        return self.row if model == "reservation" else self.person


@pytest.fixture
def fake_application(candidate, monkeypatch):
    """Staged transaction simulation only; real mutation authorization stays shut."""
    events = []
    authorization = Mock(side_effect=lambda stage: events.append("gate:" + stage))
    monkeypatch.setattr(enrollment, "_require_mutation_authorization", authorization)
    connection = Connection(events)
    session = Session(events, connection)
    settings = SimpleNamespace(_settings_instance=None)

    def construct_settings(**kwargs):
        assert kwargs == {"_env_file": None}
        assert os.environ["PYTHON_DOTENV_DISABLED"] == "1"
        assert os.environ["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "true"
        assert os.environ["DATABASE_URL"] == candidate.context.environment["DATABASE_URL"]
        events.append("settings-explicit")
        return object()

    settings.Settings = Mock(side_effect=construct_settings)
    driver = Mock(return_value=object())
    engine = SimpleNamespace(dispose=Mock(side_effect=lambda: events.append("dispose")))

    def create_engine(url, **kwargs):
        assert url == "postgresql+psycopg://" and SECRET not in url
        assert kwargs["hide_parameters"] is True and kwargs["echo"] is False
        kwargs["creator"]()
        events.append("engine-pinned")
        return engine

    def tenant_session(**kwargs):
        assert kwargs["bind"] is engine
        events.append("tenant-session")
        return session

    def create(db, **kwargs):
        assert db is session and kwargs["email"] == EMAIL
        assert events.index("proof") < len(events)
        events.append("service-create")

    bootstrap = SimpleNamespace(
        create=Mock(side_effect=create),
        resend=Mock(side_effect=lambda db: events.append("service-resend")),
        _lock=Mock(side_effect=lambda db: events.append("advisory-lock")),
        normalize_email=lambda email: email.strip().casefold(),
    )
    modules = {
        "app.settings": settings,
        "app.db": SimpleNamespace(TenantSession=tenant_session),
        "sqlalchemy": SimpleNamespace(create_engine=create_engine, text=lambda value: value),
        "sqlalchemy.pool": SimpleNamespace(NullPool=object()),
        "psycopg": SimpleNamespace(connect=driver),
        "app.services.native_platform_bootstrap": bootstrap,
        "app.models": SimpleNamespace(NativePlatformBootstrap="reservation", IAMUser="person"),
    }

    def import_module(name):
        assert name in modules, "Unexpected application/driver import"
        if name not in {"app.settings"}:
            assert settings._settings_instance is not None
            assert "settings-explicit" in events
        events.append("import:" + name)
        return modules[name]

    monkeypatch.setattr(enrollment, "_import_module", import_module)
    return SimpleNamespace(
        events=events,
        connection=connection,
        session=session,
        settings=settings,
        driver=driver,
        engine=engine,
        bootstrap=bootstrap,
        authorization=authorization,
    )


def execute(candidate, fake_application, *, action="create", value=None):
    planned = inspect(candidate)
    request = enrollment._payload(replace(planned, action=action), value or identity(), "fixture-authorization")
    return enrollment._execute_child(request, value or identity(), candidate.launcher)


def test_child_primes_settings_pins_transport_and_commits_service_on_own_transaction_once(candidate, fake_application):
    before = dict(os.environ)
    result = execute(candidate, fake_application)
    events = fake_application.events
    assert result == {"version": 1, "code": "ACTIVATION_QUEUED", "committed": True}
    assert events.index("settings-explicit") < events.index("import:app.db")
    assert (
        events.index("session-owns-transaction")
        < events.index("proof")
        < events.index("service-create")
        < events.index("commit")
    )
    assert events.count("commit") == 1 and "rollback" not in events
    assert events[-2:] == ["close", "dispose"]
    kwargs = fake_application.driver.call_args.kwargs
    assert kwargs["hostaddr"] == "127.0.0.1" and kwargs["dbname"] == "sbom_analyser_dev"
    assert kwargs["host"] == "localhost" and kwargs["password"] == SECRET
    assert "statement_timeout=15000" in kwargs["options"]
    assert fake_application.settings._settings_instance is None and os.environ == before


@pytest.mark.parametrize("failure", ["target", "schema"])
def test_child_refuses_wrong_actual_target_or_schema_before_service_and_rolls_back(
    candidate, fake_application, failure
):
    if failure == "target":
        fake_application.connection.database = "wrong-fixture-database"
    else:
        fake_application.connection.revisions = []
    result = execute(candidate, fake_application)
    assert result["code"] == "ENROLLMENT_REFUSED" and result["committed"] is False
    fake_application.bootstrap.create.assert_not_called()
    assert "rollback" in fake_application.events and "commit" not in fake_application.events


def test_lost_commit_ack_is_unconfirmed_never_auto_retried(candidate, fake_application):
    fake_application.session.commit_error = True
    result = execute(candidate, fake_application)
    assert result["code"] == "OUTCOME_UNCONFIRMED" and result["committed"] is None
    assert fake_application.events.count("commit") == 1
    fake_application.bootstrap.create.assert_called_once()


@pytest.mark.parametrize("failure", ["rollback", "close"])
def test_transaction_cleanup_uncertainty_is_not_reported_as_rolled_back(candidate, fake_application, failure):
    if failure == "rollback":
        fake_application.bootstrap.create.side_effect = ValueError(SECRET)
        fake_application.session.rollback_error = True
    else:
        fake_application.session.close_error = True
    result = execute(candidate, fake_application)
    assert result["code"] == "OUTCOME_UNCONFIRMED" and result["committed"] is None
    assert fake_application.events.count("commit") <= 1


def test_preexisting_settings_cache_is_preserved_and_refused_before_database_import(candidate, fake_application):
    previous = object()
    fake_application.settings._settings_instance = previous
    result = execute(candidate, fake_application)
    assert result["code"] == "ENROLLMENT_REFUSED"
    assert fake_application.settings._settings_instance is previous
    assert "import:app.db" not in fake_application.events
    fake_application.bootstrap.create.assert_not_called()


def test_service_refusal_rolls_back_without_commit_or_private_exception_output(candidate, fake_application, capsys):
    fake_application.bootstrap.create.side_effect = ValueError(SECRET)
    result = execute(candidate, fake_application)
    assert result["code"] == "ENROLLMENT_REFUSED"
    assert "commit" not in fake_application.events and "rollback" in fake_application.events
    assert SECRET not in capsys.readouterr().out


def test_new_users_after_approval_refuse_create_before_service(candidate, fake_application):
    fake_application.connection.existing_users = True
    result = execute(candidate, fake_application)
    assert result["code"] == "ENROLLMENT_REFUSED" and result["committed"] is False
    fake_application.bootstrap.create.assert_not_called()
    assert "commit" not in fake_application.events


def test_existing_user_observation_changed_during_approval_requires_new_plan(candidate, monkeypatch):
    tty(monkeypatch)
    runner = Mock()

    def approve(prompt):
        candidate.status.return_value = replace(candidate.status.return_value, existing_users_present=True)
        return "CREATE NATIVE PLATFORM ADMIN"

    result = enrollment.run_enrollment(
        candidate.args,
        candidate.launcher,
        action="create",
        identity=identity(),
        readiness_checker=lambda *values: report(),
        child_runner=runner,
        input_fn=approve,
    )
    assert result.code == "ENROLLMENT_PLAN_CHANGED"
    runner.assert_not_called()


def test_resend_locks_and_confirms_reserved_identity_without_email_lookup_or_new_user(candidate, fake_application):
    result = execute(
        candidate, fake_application, action="resend-activation", value=enrollment.EnrollmentIdentity(EMAIL)
    )
    assert result["committed"] is True
    fake_application.bootstrap.create.assert_not_called()
    fake_application.bootstrap.resend.assert_called_once_with(fake_application.session)
    assert fake_application.events.index("advisory-lock") < fake_application.events.index("service-resend")


def test_resend_wrong_reserved_email_does_not_issue_token_or_commit(candidate, fake_application):
    fake_application.session.person.email = "different-private-fixture@example.test"
    result = execute(
        candidate, fake_application, action="resend-activation", value=enrollment.EnrollmentIdentity(EMAIL)
    )
    assert result["committed"] is False
    fake_application.bootstrap.resend.assert_not_called()
    assert "commit" not in fake_application.events


@pytest.mark.parametrize(
    "source", [".env.dev.local", "app/models.py", "app/services/audit_service.py", "app/core/native_identity.py"]
)
def test_child_revalidates_sources_before_any_application_import(candidate, fake_application, source):
    planned = inspect(candidate)
    request = enrollment._payload(planned, identity(), "fixture-authorization")
    (candidate.context.root / source).write_text("changed-fixture", encoding="utf-8")
    with pytest.raises(enrollment.EnrollmentError, match="ENROLLMENT_PLAN_CHANGED"):
        enrollment._execute_child(request, identity(), candidate.launcher)
    assert fake_application.events == ["gate:entry"]


@pytest.mark.parametrize("cached", ["app.db", "app.models", "app.services.native_platform_bootstrap"])
def test_child_refuses_nonfresh_application_modules_before_import(candidate, fake_application, monkeypatch, cached):
    monkeypatch.setitem(sys.modules, cached, object())
    with pytest.raises(enrollment.EnrollmentError, match="ENROLLMENT_CHILD_NOT_FRESH"):
        execute(candidate, fake_application)
    assert fake_application.events == ["gate:entry"]


@pytest.mark.parametrize("failure", ["bad-correlation", "oversized", "identity-password", "boolean-version"])
def test_private_protocol_rejects_invalid_correlation_size_or_extra_identity_fields(candidate, failure):
    request = enrollment._payload(inspect(candidate), identity(), "fixture-authorization")
    if failure == "bad-correlation":
        request["correlation"] = "wrong-fixture-correlation"
    if failure == "identity-password":
        request["identity"]["password"] = SECRET
    if failure == "boolean-version":
        request["version"] = True
    raw = json.dumps(request) if failure != "oversized" else " " * 16385
    with pytest.raises(enrollment.EnrollmentError, match="ENROLLMENT_PROTOCOL_REFUSED"):
        enrollment._decode_request(raw, "fixture-authorization")


def test_private_child_protocol_suppresses_private_output_and_marks_unexpected_execution_unconfirmed(
    candidate, monkeypatch, capsys
):
    request = enrollment._payload(inspect(candidate), identity(), "fixture-authorization")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request)))
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    os.environ[enrollment._MARKER] = "fixture-authorization"
    # Exercise uncertain execution only with a synthetic gate; production denies.
    monkeypatch.setattr(enrollment, "_require_mutation_authorization", lambda stage: None)

    def fail(*values):
        print(SECRET)
        print(EMAIL, file=sys.stderr)
        raise RuntimeError(SECRET)

    monkeypatch.setattr(enrollment, "_execute_child", fail)
    assert enrollment.child_main() == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"version": 1, "code": "OUTCOME_UNCONFIRMED", "committed": None}
    assert not captured.err and SECRET not in captured.out and EMAIL not in captured.out
    assert enrollment._MARKER not in os.environ


def _action_identity(action):
    return identity() if action == "create" else enrollment.EnrollmentIdentity(EMAIL)


def _direct_request(candidate, action):
    value = _action_identity(action)
    planned = replace(inspect(candidate), action=action)
    return enrollment._payload(planned, value, "caller-selected-correlation"), value


@pytest.mark.parametrize("action", ["create", "resend-activation"])
def test_default_child_gate_refuses_valid_direct_request_before_any_configuration_or_import(
    candidate, monkeypatch, capsys, action
):
    # Deliberately do not request fake_application: production authorization stays intact.
    request, value = _direct_request(candidate, action)
    decoded, decoded_identity = enrollment._decode_request(json.dumps(request), request["correlation"])
    assert decoded == request and decoded_identity == value
    os.environ.update(
        {
            enrollment._MARKER: request["correlation"],
            "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "true",
            "_SBOM_NATIVE_ENROLLMENT_AUTHORIZATION": "caller-selected-correlation",
            "ENROLLMENT_APPROVED": "true",
        }
    )
    before = dict(os.environ)
    forbidden = Mock(side_effect=AssertionError("Default denial reached configuration or application code"))
    monkeypatch.setattr(enrollment, "_verified_child_plan", forbidden)
    monkeypatch.setattr(enrollment, "_import_module", forbidden)
    monkeypatch.setattr(dev_operator, "resolve_native_context", forbidden)
    monkeypatch.setattr(enrollment.dev_environment, "bounded_read_bytes", forbidden)
    with pytest.raises(enrollment.EnrollmentError, match="^ENROLLMENT_READINESS_CONTRACT_REQUIRED$"):
        enrollment._execute_child(decoded, decoded_identity, candidate.launcher)
    forbidden.assert_not_called()
    assert os.environ == before and request == decoded
    output = capsys.readouterr()
    assert not output.out and not output.err


@pytest.mark.parametrize("stage", ["dispatch", "entry", "before-create", "before-resend", "before-commit", "unknown"])
def test_real_mutation_gate_has_no_enabling_stage_or_environment(candidate, stage):
    os.environ.update({"NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "true", "ENROLLMENT_APPROVED": "true"})
    with pytest.raises(enrollment.EnrollmentError, match="^ENROLLMENT_READINESS_CONTRACT_REQUIRED$"):
        enrollment._require_mutation_authorization(stage)


@pytest.mark.parametrize("action", ["create", "resend-activation"])
def test_actual_private_script_entry_refuses_self_chosen_matching_correlation_under_mutation_audit(
    candidate, tmp_path, action
):
    request, _ = _direct_request(candidate, action)
    script = Path(enrollment.__file__).resolve()
    # -I/-S/-B excludes ambient Python hooks, site packages and bytecode writes.
    # The audit is in the actual owned child, before executing the real CLI module.
    driver = r"""
import os
import runpy
import sys

violations = []
mutations = {
    "os.mkdir", "os.remove", "os.rename", "os.rmdir", "os.link", "os.symlink",
    "os.chmod", "os.chown", "os.truncate", "os.utime", "os.system",
    "os.posix_spawn", "os.exec", "subprocess.Popen",
}

def audit(event, arguments):
    forbidden = event in mutations or event.startswith("socket.")
    if event == "import":
        name = arguments[0]
        forbidden |= name in {"dev", "scripts.dev", "app", "psycopg", "sqlalchemy"}
        forbidden |= name.startswith(("app.", "psycopg.", "sqlalchemy."))
    if event == "open":
        mode = arguments[1]
        flags = arguments[2]
        forbidden |= isinstance(mode, str) and any(char in mode for char in "wax+")
        forbidden |= isinstance(flags, int) and bool(
            flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        )
    if forbidden:
        violations.append("FIXTURE_FORBIDDEN_ACTION")
        raise RuntimeError("FIXTURE_FORBIDDEN_ACTION")

script = sys.argv[1]
argument = sys.argv[2]
sys.path.insert(0, os.path.dirname(script))
sys.argv = [script, argument]
sys.addaudithook(audit)
try:
    runpy.run_path(script, run_name="__main__")
finally:
    if violations:
        raise SystemExit(97)
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", driver, str(script), enrollment._CHILD_ARGUMENT],
        input=json.dumps(request),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=15,
        cwd=tmp_path,
        env={
            "APP_ENVIRONMENT": "development",
            enrollment._MARKER: request["correlation"],
            "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "true",
            "DATABASE_URL": f"postgresql+psycopg://fixture:{SECRET}@127.0.0.1:5432/fixture_only",
        },
        check=False,
    )
    assert completed.returncode == 1
    assert completed.stderr == ""
    assert json.loads(completed.stdout) == {
        "version": 1,
        "code": "ENROLLMENT_READINESS_CONTRACT_REQUIRED",
        "committed": False,
    }
    assert SECRET not in completed.stdout and EMAIL not in completed.stdout


@pytest.mark.parametrize("action", ["create", "resend-activation"])
@pytest.mark.parametrize("revocation", ["service", "commit"])
def test_staged_authorization_revocation_rolls_back_before_service_or_commit(
    candidate, fake_application, action, revocation
):
    service_stage = "before-create" if action == "create" else "before-resend"
    refused_stage = service_stage if revocation == "service" else "before-commit"

    def authorize(stage):
        fake_application.events.append("gate:" + stage)
        if stage == refused_stage:
            raise enrollment.EnrollmentError("ENROLLMENT_READINESS_CONTRACT_REQUIRED")

    fake_application.authorization.side_effect = authorize
    before = dict(os.environ)
    result = execute(candidate, fake_application, action=action, value=_action_identity(action))
    assert result == {"version": 1, "code": "ENROLLMENT_REFUSED", "committed": False}
    events = fake_application.events
    assert events.count("rollback") == 1 and "commit" not in events
    assert events[-2:] == ["close", "dispose"] and os.environ == before
    service = fake_application.bootstrap.create if action == "create" else fake_application.bootstrap.resend
    assert service.call_count == (0 if revocation == "service" else 1)
    assert events.index("gate:entry") < events.index("gate:" + refused_stage) < events.index("rollback")
    if revocation == "service":
        assert "flush" not in events and "gate:before-commit" not in events
    else:
        assert events.index("flush") < events.index("gate:before-commit")


@pytest.mark.parametrize("action", ["create", "resend-activation"])
@pytest.mark.parametrize("timing", ["lock", "service", "flush"])
@pytest.mark.parametrize("changed", ["selected-config", "source", "environment"])
def test_staged_mutation_boundaries_detect_drift_after_lock_service_and_flush(
    candidate, fake_application, monkeypatch, action, timing, changed
):
    def drift():
        if changed == "environment":
            os.environ["SMTP_HOST"] = "changed-fixture.invalid"
        else:
            name = ".env.dev.local" if changed == "selected-config" else "app/services/native_platform_bootstrap.py"
            (candidate.context.root / name).write_text("changed-synthetic-fixture", encoding="utf-8")

    service = fake_application.bootstrap.create if action == "create" else fake_application.bootstrap.resend
    target = fake_application.bootstrap._lock if timing == "lock" else service
    if timing == "flush":
        previous = fake_application.session.flush

        def flush():
            previous()
            drift()

        monkeypatch.setattr(fake_application.session, "flush", flush)
    else:
        previous = target.side_effect

        def invoke(*values, **keywords):
            previous(*values, **keywords)
            drift()

        target.side_effect = invoke
    before = dict(os.environ)
    result = execute(candidate, fake_application, action=action, value=_action_identity(action))
    assert result == {"version": 1, "code": "ENROLLMENT_REFUSED", "committed": False}
    events = fake_application.events
    assert events.count("rollback") == 1 and "commit" not in events
    assert service.call_count == (0 if timing == "lock" else 1)
    assert events[-2:] == ["close", "dispose"] and os.environ == before
    expected_stage = (
        ("before-create" if action == "create" else "before-resend") if timing == "lock" else "before-commit"
    )
    assert "gate:" + expected_stage in events


@pytest.mark.parametrize("action", ["create", "resend-activation"])
def test_staged_settings_consume_selected_projection_and_restore_ambient_environment(
    candidate, fake_application, action
):
    selected = dev_operator.OperatorEnvironment(
        {**candidate.context.environment, "SMTP_HOST": "selected-fixture.invalid"}
    )
    candidate.context = replace(candidate.context, environment=selected)
    candidate.resolve.return_value = candidate.context
    os.environ.update(
        {
            "DATABASE_URL": f"postgresql+psycopg://ambient:{SECRET}@127.0.0.1:6543/wrong_fixture",
            "SMTP_HOST": "ambient-fixture.invalid",
            "AMBIENT_FIXTURE_SECRET": SECRET,
            "PYTHONINSPECT": "1",
        }
    )
    before = dict(os.environ)
    expected = {**enrollment._child_environment(candidate.context), "NATIVE_PLATFORM_BOOTSTRAP_ENABLED": "true"}
    previous = fake_application.settings.Settings.side_effect
    observed = []

    def settings(**keywords):
        observed.append(dict(os.environ))
        return previous(**keywords)

    fake_application.settings.Settings.side_effect = settings
    result = execute(candidate, fake_application, action=action, value=_action_identity(action))
    assert result == {"version": 1, "code": "ACTIVATION_QUEUED", "committed": True}
    assert observed == [expected] and os.environ == before
    assert "AMBIENT_FIXTURE_SECRET" not in expected and "PYTHONINSPECT" not in expected
    assert fake_application.settings._settings_instance is None
    assert [call.args[0] for call in fake_application.authorization.call_args_list] == [
        "entry",
        "before-create" if action == "create" else "before-resend",
        "before-commit",
    ]


@pytest.mark.parametrize(
    "committed, exit_code, accepted", [(False, 1, True), (True, 1, False), (None, 1, False), (False, 0, False)]
)
def test_parent_accepts_only_exact_known_blocked_child_result(candidate, monkeypatch, committed, exit_code, accepted):
    output = {"version": 1, "code": "ENROLLMENT_READINESS_CONTRACT_REQUIRED", "committed": committed}
    helper = Helper(output=json.dumps(output))

    def communicate(payload, timeout):
        assert timeout == 40
        helper.payload, helper.returncode = payload, exit_code
        return helper.output, None

    monkeypatch.setattr(helper, "communicate", communicate)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=helper))
    result = enrollment._launch_child(inspect(candidate), identity(), candidate.launcher)
    if accepted:
        assert result == enrollment.EnrollmentOutcome("ENROLLMENT_READINESS_CONTRACT_REQUIRED", 1, False)
    else:
        assert result.code == "OUTCOME_UNCONFIRMED" and result.committed is None
    assert not helper.terminated and not helper.killed
