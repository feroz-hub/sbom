"""Safety checks for the one-command development launcher."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from scripts import dev
from scripts.dev_runtime import Runtime


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch, tmp_path):
    for name in dev.REQUIRED_FILES:  # A complete checkout, so layout validation passes.
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).touch()
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "Runtime", lambda root: Runtime(tmp_path))
    monkeypatch.setattr(dev, "ACTIVE_RUNTIME", None)


def mock_virtualenv_handoff(monkeypatch, tmp_path, platform):
    python = tmp_path / "venv" / "python.exe"
    python.parent.mkdir()
    python.touch()
    monkeypatch.setattr(dev, "VENV", python.parent)
    monkeypatch.setattr(dev, "venv_python", lambda: python)
    monkeypatch.setattr(dev.sys, "prefix", str(tmp_path / "system-python"))
    monkeypatch.setattr(dev.sys, "platform", platform)
    monkeypatch.setattr(dev.sys, "argv", ["scripts/dev.py", "--verbose"])
    return [str(python), str(Path(dev.__file__).resolve()), "--verbose"]


@pytest.mark.parametrize("exit_code", [0, 1, 130])
def test_windows_handoff_waits_with_inherited_console(monkeypatch, tmp_path, exit_code):
    command = mock_virtualenv_handoff(monkeypatch, tmp_path, "win32")
    handlers = []
    original_handler = object()
    monkeypatch.setattr(dev.signal, "signal", lambda sig, handler: handlers.append(handler) or original_handler)

    def wait():
        # Windows broadcasts Ctrl+C to both processes. The parent stays alive
        # until the child has handled cancellation and completed cleanup.
        assert callable(handlers[0])
        handlers[0](dev.signal.SIGINT, None)
        return exit_code

    child = SimpleNamespace(wait=MagicMock(side_effect=wait))
    popen = MagicMock(return_value=child)
    monkeypatch.setattr(dev.subprocess, "Popen", popen)
    monkeypatch.setattr(dev.os, "execv", lambda *args: pytest.fail("Windows must not execv"))
    with pytest.raises(SystemExit) as result:
        dev.ensure_virtualenv()
    assert result.value.code == exit_code
    popen.assert_called_once_with(command)  # No pipes, detached console, or new process group.
    child.wait.assert_called_once_with()
    assert handlers[-1] is original_handler


def test_windows_handoff_restores_signal_handler_on_spawn_failure(monkeypatch, tmp_path):
    mock_virtualenv_handoff(monkeypatch, tmp_path, "win32")
    handler = MagicMock(return_value=dev.signal.default_int_handler)
    monkeypatch.setattr(dev.signal, "signal", handler)
    monkeypatch.setattr(dev.subprocess, "Popen", MagicMock(side_effect=OSError("spawn failed")))
    with pytest.raises(OSError, match="spawn failed"):
        dev.ensure_virtualenv()
    assert handler.call_args.args == (dev.signal.SIGINT, dev.signal.default_int_handler)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_posix_handoff_keeps_execv(monkeypatch, tmp_path, platform):
    command = mock_virtualenv_handoff(monkeypatch, tmp_path, platform)
    execute = MagicMock()
    monkeypatch.setattr(dev.os, "execv", execute)
    dev.ensure_virtualenv()
    execute.assert_called_once_with(command[0], command)


def test_virtualenv_handoff_does_not_relaunch_inside_venv(monkeypatch, tmp_path):
    mock_virtualenv_handoff(monkeypatch, tmp_path, "win32")
    monkeypatch.setattr(dev.sys, "prefix", str(dev.VENV))
    monkeypatch.setattr(dev.subprocess, "Popen", lambda *args: pytest.fail("Unexpected relaunch"))
    dev.ensure_virtualenv()


@pytest.mark.parametrize("keys,expected,masked", [
    ("Secret9!\r", "Secret9!", "********"),
    ("\bAb\bC\r", "AC", "**\b \b*"),
    ("A\x00KB\xe0MC\r", "ABC", "***"),
])
def test_windows_password_is_masked(monkeypatch, capsys, keys, expected, masked):
    characters = iter(keys)
    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setitem(dev.sys.modules, "msvcrt", SimpleNamespace(getwch=lambda: next(characters)))
    assert dev.read_password("Password: ") == expected
    output = capsys.readouterr().out
    assert output == f"Password: {masked}\n"
    assert expected not in output


@pytest.mark.parametrize("key", ["\x03", "\x1a", ""])
def test_windows_password_cancellation_is_safe(monkeypatch, capsys, key):
    characters = iter([*"private-secret", key])
    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setitem(dev.sys.modules, "msvcrt", SimpleNamespace(getwch=lambda: next(characters)))
    with pytest.raises(dev.SetupError, match="credential entry cancelled") as error:
        dev.read_postgres_credentials(input_fn=lambda prompt: "")
    assert "private-secret" not in str(error.value)
    assert "private-secret" not in capsys.readouterr().out


@pytest.mark.parametrize("exception", [KeyboardInterrupt, EOFError])
def test_username_entry_cancellation_is_safe(exception):
    def cancelled(prompt):
        raise exception
    with pytest.raises(dev.SetupError, match="credential entry cancelled"):
        dev.read_postgres_credentials(input_fn=cancelled)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_non_windows_password_uses_getpass(monkeypatch, platform):
    monkeypatch.setattr(dev.sys, "platform", platform)
    read = MagicMock(return_value="private-secret")
    monkeypatch.setattr(dev.getpass, "getpass", read)
    assert dev.read_password("Password: ") == "private-secret"
    read.assert_called_once_with("Password: ")


@pytest.mark.parametrize("valid", [False, True])
def test_interactive_credentials_validated_before_persistence(monkeypatch, tmp_path, capsys, valid):
    config = tmp_path / ".env.dev.local"
    prompts = []
    attempts = []

    def validate(url):
        attempts.append(url)
        assert not config.exists()
        if not valid or dev.unquote(dev.urlsplit(url).password or "") != "private-secret":
            raise dev.SetupError("invalid")

    monkeypatch.setattr(dev, "ensure_database", validate)
    kwargs = dict(
        config_path=config, repository_env=tmp_path / "missing.env",
        pgpass_path=tmp_path / "missing.pgpass", interactive=True,
        input_fn=lambda prompt: prompts.append(prompt) or "  ",
        password_fn=lambda prompt: "private-secret",
    )
    values = {"DATABASE_URL": dev.default_database_url("local", 5432)}
    if valid:
        dev.configure_local_database(values, {}, 5432, **kwargs)
        persisted = dev.read_config(config)["DATABASE_URL"]
        assert dev.unquote(dev.urlsplit(persisted).password) == "private-secret"
        assert dev.urlsplit(persisted).username == "postgres"
        assert persisted == attempts[-1]
    else:
        with pytest.raises(dev.SetupError, match="after 3 attempts") as error:
            dev.configure_local_database(values, {}, 5432, **kwargs)
        assert "private-secret" not in str(error.value)
        assert not config.exists()
    assert prompts == ["PostgreSQL user [postgres]: "] * (1 if valid else 3)
    assert "private-secret" not in capsys.readouterr().out


def test_config_roundtrip_and_secrets_persist(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / ".env.dev.local"
    values = dev.resolve_config({}, dev.POSTGRES_PORT, dev.REDIS_PORT, dev.MAILPIT_SMTP_PORT)
    dev.generate_keys(values)
    dev.write_config(values, path)
    loaded = dev.read_config(path)
    dev.generate_keys(loaded)
    assert loaded == values
    assert "BEGIN PRIVATE KEY" in loaded["NATIVE_JWT_PRIVATE_KEY"]
    assert loaded["REDIS_URL"].endswith("/0")
    assert loaded["AUTH_SESSION_REDIS_URL"].endswith("/1")
    assert loaded["NATIVE_AUTH_RATE_LIMIT_STORAGE_URI"].endswith("/2")
    assert loaded["CELERY_USE_DATABASE_BROKER"] == "false"
    assert loaded["HCL_AUTH_ENABLED"] == "false"
    assert loaded["DEV_POSTGRES_PROVIDER"] == "docker"
    assert loaded["DEV_REDIS_PROVIDER"] == "docker"
    assert loaded["DEV_API_PORT"] == "18000"
    assert loaded["DEV_FRONTEND_PORT"] == "13000"
    assert loaded["NATIVE_JWT_PRIVATE_KEY"] not in capsys.readouterr().out
    if dev.os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


def test_config_allows_simple_bootstrap_flag(tmp_path: Path) -> None:
    path = tmp_path / ".env.dev.local"
    path.write_text("NATIVE_PLATFORM_BOOTSTRAP_ENABLED=true\n")
    assert dev.read_config(path)["NATIVE_PLATFORM_BOOTSTRAP_ENABLED"] == "true"


def test_incomplete_keypair_is_rejected() -> None:
    with pytest.raises(dev.SetupError, match="incomplete"):
        dev.generate_keys({"NATIVE_JWT_PRIVATE_KEY": "existing"})


def test_invalid_or_mismatched_secrets_are_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    first: dict[str, str] = {}
    second: dict[str, str] = {}
    dev.generate_keys(first)
    dev.generate_keys(second)
    original_private = first["NATIVE_JWT_PRIVATE_KEY"]
    first["NATIVE_JWT_PUBLIC_KEY"] = second["NATIVE_JWT_PUBLIC_KEY"]
    with pytest.raises(dev.SetupError, match="does not match"):
        dev.generate_keys(first)
    assert first["NATIVE_JWT_PRIVATE_KEY"] == original_private
    assert original_private not in capsys.readouterr().out
    first["NATIVE_JWT_PUBLIC_KEY"] = second["NATIVE_JWT_PRIVATE_KEY"]
    with pytest.raises(dev.SetupError, match="keypair is invalid"):
        dev.validate_secrets(first)
    first["NATIVE_JWT_PUBLIC_KEY"] = second["NATIVE_JWT_PUBLIC_KEY"]
    first["NATIVE_JWT_PRIVATE_KEY"] = second["NATIVE_JWT_PRIVATE_KEY"]
    first["NATIVE_SECURITY_OUTBOX_KEY"] = "invalid"
    with pytest.raises(dev.SetupError, match="NATIVE_SECURITY_OUTBOX_KEY"):
        dev.validate_secrets(first)
    first["NATIVE_SECURITY_OUTBOX_KEY"] = second["NATIVE_SECURITY_OUTBOX_KEY"]
    first["AUTH_SESSION_ENCRYPTION_KEY"] = "invalid"
    with pytest.raises(dev.SetupError, match="AUTH_SESSION_ENCRYPTION_KEY"):
        dev.validate_secrets(first)


@pytest.mark.parametrize(
    "url",
    [
        "postgresql+psycopg://u:p@127.0.0.1:55439/sbom_analyser",
        "postgresql+psycopg://u:p@remote:5432/sbom_analyser_dev",
        "postgresql+psycopg://u:p@localhost:5432/sbom_analyser_dev?options=-csearch_path%3Dother",
        "sqlite:///sbom_analyser_dev",
    ],
)
def test_database_safety_rejects_other_targets(url: str) -> None:
    with pytest.raises(dev.SetupError, match="refusing another database"):
        dev.validate_database_url(url)


def test_saved_database_port_cannot_silently_change() -> None:
    with pytest.raises(dev.SetupError, match="different local PostgreSQL port"):
        dev.resolve_config(
            {"DATABASE_URL": "postgresql+psycopg://u:p@localhost:5432/sbom_analyser_dev"}, 55439, 56379, 1025
        )


def test_windows_username_is_not_used_for_local_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev.getpass, "getuser", lambda: pytest.fail("Windows username was used"))
    assert dev.default_database_url("local", 5432).startswith("postgresql+psycopg://postgres:@")


def test_docker_database_credentials_are_unchanged() -> None:
    assert (
        dev.default_database_url("docker", dev.POSTGRES_PORT)
        == "postgresql+psycopg://sbom:sbom@127.0.0.1:55439/sbom_analyser_dev"
    )


def test_saved_local_database_credentials_are_reused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    saved_url = "postgresql+psycopg://saved:saved-secret@localhost:5432/sbom_analyser_dev"
    checked = []
    monkeypatch.setattr(dev, "ensure_database", lambda url: checked.append(url))
    resolved = dev.resolve_local_database_url(
        saved_url,
        5432,
        repository_env=tmp_path / "missing.env",
        pgpass_path=tmp_path / "missing.pgpass",
        interactive=False,
    )
    assert resolved == saved_url
    assert checked == [saved_url]


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_repository_local_credentials_are_reused_with_dev_database(tmp_path: Path, host: str) -> None:
    path = tmp_path / ".env"
    path.write_text(f"DATABASE_URL=postgresql://app-user:app-password@{host}:5432/sbom_analyser\n")
    candidate = dev.repository_database_candidate(path, 5432)
    assert candidate == "postgresql+psycopg://app-user:app-password@127.0.0.1:5432/sbom_analyser_dev"


def test_repository_remote_database_url_is_not_a_candidate(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("DATABASE_URL=postgresql://app-user:secret@database.example:5432/sbom_analyser\n")
    assert dev.repository_database_candidate(path, 5432) is None


def test_pgpass_local_credentials_are_parsed_without_exposing_password(tmp_path: Path) -> None:
    path = tmp_path / ".pgpass"
    path.write_text(
        "# ignored\n"
        "database.example:5432:*:remote:remote-secret\n"
        "localhost:5432:sbom_analyser_dev:local-user:local\\:secret\n"
    )
    candidates = dev.pgpass_database_candidates(path, 5432)
    assert candidates == [
        "postgresql+psycopg://local-user:local%3Asecret@127.0.0.1:5432/sbom_analyser_dev"
    ]


def test_standard_pgpass_paths() -> None:
    assert dev.default_pgpass_path(platform_name="nt", environment={"APPDATA": "C:/Users/dev/AppData/Roaming"}) == Path(
        "C:/Users/dev/AppData/Roaming/postgresql/pgpass.conf"
    )
    assert dev.default_pgpass_path(platform_name="posix", home=Path("/Users/dev")) == Path("/Users/dev/.pgpass")


def test_local_prompt_defaults_to_postgres_and_hides_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prompts = []

    def validate(url: str) -> None:
        if dev.unquote(dev.urlsplit(url).password or "") != "prompt-secret":
            raise dev.SetupError("invalid")

    monkeypatch.setattr(dev, "ensure_database", validate)
    resolved = dev.resolve_local_database_url(
        None,
        5432,
        repository_env=tmp_path / "missing.env",
        pgpass_path=tmp_path / "missing.pgpass",
        interactive=True,
        input_fn=lambda prompt: prompts.append(prompt) or "",
        password_fn=lambda prompt: "prompt-secret",
    )
    assert dev.unquote(dev.urlsplit(resolved).username or "") == "postgres"
    assert prompts == ["PostgreSQL user [postgres]: "]
    assert "prompt-secret" not in capsys.readouterr().out


def test_invalid_prompted_credentials_can_be_retried_without_password_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    passwords = iter(["wrong-secret", "right-secret"])

    def validate(url: str) -> None:
        if dev.unquote(dev.urlsplit(url).password or "") != "right-secret":
            raise dev.SetupError("invalid")

    monkeypatch.setattr(dev, "ensure_database", validate)
    resolved = dev.resolve_local_database_url(
        None,
        5432,
        repository_env=tmp_path / "missing.env",
        pgpass_path=tmp_path / "missing.pgpass",
        interactive=True,
        input_fn=lambda prompt: "postgres",
        password_fn=lambda prompt: next(passwords),
    )
    output = capsys.readouterr().out
    assert dev.unquote(dev.urlsplit(resolved).password or "") == "right-secret"
    assert "Try again" in output
    assert "wrong-secret" not in output
    assert "right-secret" not in output


def test_invalid_local_credentials_are_not_persisted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = tmp_path / ".env.dev.local"
    monkeypatch.setattr(dev, "ensure_database", lambda url: (_ for _ in ()).throw(dev.SetupError("invalid")))
    with pytest.raises(dev.SetupError, match="credentials are required"):
        dev.configure_local_database(
            {"DATABASE_URL": dev.default_database_url("local", 5432)},
            {},
            5432,
            config_path=config,
            repository_env=tmp_path / "missing.env",
            pgpass_path=tmp_path / "missing.pgpass",
            interactive=False,
        )
    assert not config.exists()


def test_valid_local_credentials_are_persisted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repository_env = tmp_path / ".env"
    repository_env.write_text("DATABASE_URL=postgresql://local:valid-secret@localhost:5432/production_name\n")
    config = tmp_path / ".env.dev.local"
    monkeypatch.setattr(dev, "ensure_database", lambda url: None)
    values = {"DATABASE_URL": dev.default_database_url("local", 5432)}
    dev.configure_local_database(
        values,
        {},
        5432,
        config_path=config,
        repository_env=repository_env,
        pgpass_path=tmp_path / "missing.pgpass",
        interactive=False,
    )
    persisted = dev.read_config(config)
    assert persisted["DATABASE_URL"] == (
        "postgresql+psycopg://local:valid-secret@127.0.0.1:5432/sbom_analyser_dev"
    )


def test_provider_fallback_updates_only_development_urls() -> None:
    saved = dev.resolve_config({}, 55439, 56379, 1025)
    changed = dev.resolve_config(saved, 5432, 6379, 1025, pg_provider="local", redis_provider="local")
    assert changed["DEV_POSTGRES_PROVIDER"] == "local"
    assert changed["DEV_REDIS_PROVIDER"] == "local"
    assert changed["DATABASE_URL"].endswith(":5432/sbom_analyser_dev")
    assert changed["REDIS_URL"].endswith(":6379/0")
    assert changed["AUTH_SESSION_REDIS_URL"].endswith(":6379/1")


def test_generated_application_urls_use_development_ports() -> None:
    values = dev.resolve_config({}, 55439, 56379, 1025)
    assert values["SBOM_API_URL"] == "http://127.0.0.1:18000"
    assert values["NEXT_PUBLIC_API_URL"] == "http://127.0.0.1:18000"
    assert values["APP_ORIGIN"] == "https://localhost:13000"
    assert values["CORS_ORIGINS"] == "https://localhost:13000"
    assert values["NATIVE_ACTIVATION_FRONTEND_URL"] == "https://localhost:13000/activate-account"
    assert values["NATIVE_PASSWORD_RESET_FRONTEND_URL"] == "https://localhost:13000/reset-password"
    assert values["EMAIL_VERIFICATION_FRONTEND_URL"] == "https://localhost:13000/verify-email"
    assert values["NATIVE_JWT_ISSUER"] == "https://localhost:13000/native"


def test_docker_service_is_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "legacy_redis_container", lambda: False)
    monkeypatch.setattr(dev, "compose_container", lambda service: True)
    monkeypatch.setattr(dev, "service_available", lambda service, port: True)
    monkeypatch.setattr(dev, "start_compose", lambda *args: pytest.fail("started existing service"))
    assert dev.select_service("redis", 56379, 6379, check=False, env={}) == ("Docker", 56379)


def test_mailpit_readiness_succeeds_immediately_without_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "reachable", lambda host, port: True)
    monkeypatch.setattr(dev, "mailpit_ready", lambda: True)
    monkeypatch.setattr(dev.time, "sleep", lambda seconds: pytest.fail("unexpected readiness delay"))
    assert dev.wait_for_mailpit_ready()


def test_mailpit_readiness_retries_until_http_api_is_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = SimpleNamespace(now=0.0)
    sleeps = []
    http_results = iter((False, False, False, True))
    monkeypatch.setattr(dev, "reachable", lambda host, port: True)
    monkeypatch.setattr(dev, "mailpit_ready", lambda: next(http_results))
    monkeypatch.setattr(dev.time, "monotonic", lambda: clock.now)

    def advance(seconds):
        sleeps.append(seconds)
        clock.now += seconds

    monkeypatch.setattr(dev.time, "sleep", advance)
    assert dev.wait_for_mailpit_ready(timeout=2.0)
    assert sleeps == [0.5, 0.5, 0.5]


def test_mailpit_startup_waits_after_transient_http_failure(monkeypatch, capsys) -> None:
    http_results = iter((False, True))
    monkeypatch.setattr(dev, "reachable", lambda host, port: True)
    monkeypatch.setattr(dev, "mailpit_ready", lambda: next(http_results))
    wait = MagicMock(return_value=True)
    monkeypatch.setattr(dev, "wait_for_mailpit_ready", wait)
    dev.ensure_mailpit_ready()
    wait.assert_called_once_with(dev.MAILPIT_READY_TIMEOUT)
    assert capsys.readouterr().out.count("waiting for HTTP API") == 1


def test_mailpit_http_timeout_has_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(dev, "reachable", lambda host, port: True)
    monkeypatch.setattr(dev, "mailpit_ready", lambda: False)
    monkeypatch.setattr(dev.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(dev.time, "sleep", lambda seconds: setattr(clock, "now", clock.now + seconds))
    with pytest.raises(dev.SetupError, match="SMTP is reachable, but its HTTP API did not become ready.*1 seconds"):
        dev.ensure_mailpit_ready(timeout=1.0)


def test_mailpit_readiness_times_out_when_smtp_never_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(dev, "reachable", lambda host, port: False)
    monkeypatch.setattr(dev, "mailpit_ready", lambda: pytest.fail("HTTP must not be probed before SMTP is reachable"))
    monkeypatch.setattr(dev.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(dev.time, "sleep", lambda seconds: setattr(clock, "now", clock.now + seconds))
    assert not dev.wait_for_mailpit_ready(timeout=1.0)


def test_current_compose_mailpit_selection_waits_for_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "run", lambda command: SimpleNamespace(stdout="false\n"))
    selected = MagicMock(return_value=("Docker", dev.MAILPIT_SMTP_PORT))
    ready = MagicMock()
    monkeypatch.setattr(dev, "select_service", selected)
    monkeypatch.setattr(dev, "ensure_mailpit_ready", ready)
    assert dev.select_mailpit(check=False, env={}) == "Docker"
    selected.assert_called_once_with(
        "mailpit",
        dev.MAILPIT_SMTP_PORT,
        dev.MAILPIT_SMTP_PORT,
        check=False,
        env={},
    )
    ready.assert_called_once_with()


def test_legacy_mailpit_selection_keeps_compatibility(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "run", lambda command: SimpleNamespace(stdout="true\n"))
    monkeypatch.setattr(dev, "reachable", lambda host, port: True)
    ready = MagicMock()
    monkeypatch.setattr(dev, "ensure_mailpit_ready", ready)
    monkeypatch.setattr(dev, "select_service", lambda *args, **kwargs: pytest.fail("Compose Mailpit was touched"))
    assert dev.select_mailpit(check=False, env={}) == "Docker (sbom-mailpit)"
    ready.assert_called_once_with()


def test_docker_starts_project_service(monkeypatch: pytest.MonkeyPatch) -> None:
    started = []
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "legacy_redis_container", lambda: False)
    monkeypatch.setattr(dev, "compose_container", lambda service: False)
    monkeypatch.setattr(dev, "reachable", lambda host, port: False)
    monkeypatch.setattr(dev, "service_available", lambda service, port: False)
    monkeypatch.setattr(dev, "start_compose", lambda service, env: started.append(service))
    monkeypatch.setattr(dev, "wait_for_service", lambda service, port: True)
    assert dev.select_service("redis", 56379, 6379, check=False, env={}) == ("Docker", 56379)
    assert started == ["redis"]


def test_no_docker_uses_local_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: False)
    monkeypatch.setattr(dev, "service_available", lambda service, port: port == 6379)
    assert dev.select_service("redis", 56379, 6379, check=False, env={}) == ("local", 6379)


def test_saved_local_is_reused_even_with_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "service_available", lambda service, port: port == 6379)
    monkeypatch.setattr(dev, "compose_container", lambda service: pytest.fail("probed Docker unnecessarily"))
    assert dev.select_service("redis", 56379, 6379, check=False, env={}, preferred="local") == ("local", 6379)


def test_saved_docker_falls_back_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: False)
    monkeypatch.setattr(dev, "service_available", lambda service, port: port == 6379)
    assert dev.select_service("redis", 56379, 6379, check=False, env={}, preferred="docker") == ("local", 6379)


def test_infrastructure_port_conflict_is_clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "legacy_redis_container", lambda: False)
    monkeypatch.setattr(dev, "compose_container", lambda service: False)
    monkeypatch.setattr(dev, "reachable", lambda host, port: port == 56379)
    monkeypatch.setattr(dev, "service_available", lambda service, port: False)
    with pytest.raises(dev.SetupError, match="Port 56379 is occupied"):
        dev.select_service("redis", 56379, 6379, check=False, env={})


def test_provider_probe_requires_expected_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = MagicMock()
    connection.__enter__.return_value = connection
    monkeypatch.setattr(dev.socket, "create_connection", lambda *args, **kwargs: connection)
    connection.recv.return_value = b"+PONG\r\n"
    assert dev.service_available("redis", 6379)
    connection.recv.return_value = b"HTTP/1.1"
    assert not dev.service_available("redis", 6379)
    connection.recv.return_value = b"N"
    assert dev.service_available("postgres", 5432)


def test_exact_legacy_redis_is_reused_without_compose_change(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "legacy_redis_container", lambda: True)
    monkeypatch.setattr(dev, "compose_container", lambda service: pytest.fail("Compose Redis was touched"))
    assert dev.select_service("redis", 56379, 6379, check=False, env={}) == ("Docker (sbom-native-redis)", 56379)


def test_no_redis_does_not_switch_celery_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "docker_available", lambda: False)
    monkeypatch.setattr(dev, "service_available", lambda service, port: False)
    with pytest.raises(dev.SetupError, match="Redis is unavailable"):
        dev.select_service("redis", 56379, 6379, check=False, env={})


def test_check_mode_does_not_start_services_or_processes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "--check"])
    monkeypatch.setattr(dev, "docker_available", lambda: False)
    monkeypatch.setattr(dev, "reachable", lambda host, port: True)
    monkeypatch.setattr(dev, "service_available", lambda service, port: True)
    monkeypatch.setattr(dev, "read_config", lambda: {})
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: pytest.fail("venv created"))
    monkeypatch.setattr(dev, "ensure_database", lambda url: pytest.fail("database touched"))
    monkeypatch.setattr(dev, "start_process", lambda *args: pytest.fail("process started"))
    monkeypatch.setattr(dev, "wait_for_mailpit_ready", lambda *args: pytest.fail("readiness wait started"))
    monkeypatch.setattr(dev, "node_version", lambda: (22, 1, 0))
    dev.main()
    output = capsys.readouterr().out
    assert "no services or processes started" in output
    assert "database schema and migrations were not validated" in output
    assert "22.1.0" in output
    assert "BEGIN PRIVATE KEY" not in output


@pytest.mark.parametrize("platform", ["win32", "linux", "darwin"])
def test_startup_commands_use_solo_only_for_windows_worker_and_consume_reports_queue(monkeypatch, tmp_path, platform):
    monkeypatch.setattr(dev.sys, "platform", platform)
    monkeypatch.setattr(dev.sys, "argv", ["dev.py"])
    monkeypatch.setattr(dev, "CONFIG", tmp_path / ".env.dev.local")
    monkeypatch.setattr(dev, "BEAT_LOCK", tmp_path / "beat.lock")
    monkeypatch.setattr(dev, "venv_python", lambda: tmp_path / "python")
    monkeypatch.setattr(dev, "read_config", lambda: {})
    monkeypatch.setattr(dev, "docker_available", lambda: False)
    monkeypatch.setattr(dev, "select_service", lambda service, port, *args, **kwargs: ("Docker", port))
    monkeypatch.setattr(dev, "mailpit_ready", lambda: True)
    # This test constructs commands; service readiness has its own tests.
    monkeypatch.setattr(dev, "select_mailpit", lambda **kwargs: "Docker")
    def unexpected_network_probe(*args, **kwargs):
        pytest.fail("Command-generation test must not probe a live service")
    monkeypatch.setattr(dev, "reachable", unexpected_network_probe)
    for name in ("ensure_virtualenv", "ensure_dependencies", "generate_keys", "check_application_ports",
                 "ensure_database", "write_config", "validate_existing_schema", "acquire_beat_lock", "stop_processes"):
        monkeypatch.setattr(dev, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(dev, "run_migrations", lambda env: "test-head")
    monkeypatch.setattr(dev, "ensure_frontend", lambda: "npm")
    started = {}
    monkeypatch.setattr(dev, "start_process", lambda name, command, *args: started.setdefault(name, command))

    def ready(*args):
        raise KeyboardInterrupt  # End the simulated foreground run without launching anything.

    monkeypatch.setattr(dev, "wait_for_ready", ready)
    dev.start_application(SimpleNamespace(check=False))
    python = str(tmp_path / "python")
    celery = [python, "-m", "celery", "-A", "app.workers.celery_app"]
    assert started["Celery worker"] == [
        *celery, "worker", "--loglevel=info", "--queues=celery,reports", *(["--pool=solo"] if platform == "win32" else [])
    ]
    # Exactly one scheduler: the worker never embeds Beat, and Beat keeps its existing command.
    assert "--beat" not in started["Celery worker"] and "-B" not in started["Celery worker"]
    assert started["Celery Beat"] == [*celery, "beat", "--loglevel=info"]
    assert started["API"] == [python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                              "--port", "18000", "--no-proxy-headers"]
    assert started["Frontend"] == ["npm", "run", "dev:https", "--", "--port", "13000"]


@pytest.fixture
def frontend_install(monkeypatch, tmp_path):
    frontend = tmp_path / "frontend"
    frontend.mkdir(exist_ok=True)
    (frontend / "package.json").write_text('{"name":"test"}')
    (frontend / "package-lock.json").write_text('{"lockfileVersion":3}')
    certificates = frontend / "certificates"
    certificates.mkdir()
    (certificates / "localhost.pem").write_text("existing certificate")
    (certificates / "localhost-key.pem").write_text("existing key")
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev.shutil, "which", lambda name: "npm")
    monkeypatch.setattr(dev, "node_version", lambda: (20, 9, 0))

    def install(command):
        assert command == ["npm", "ci", "--prefix", "frontend"]
        (frontend / "node_modules").mkdir(exist_ok=True)
        return SimpleNamespace(returncode=0)

    runner = MagicMock(side_effect=install)
    monkeypatch.setattr(dev, "run", runner)
    monkeypatch.setattr(dev, "create_local_certificate", lambda *args: pytest.fail("Certificate replaced"))
    return frontend, runner


@pytest.mark.parametrize("existing_modules", [False, True])
def test_frontend_install_without_stamp_then_skip_unchanged(frontend_install, existing_modules):
    frontend, runner = frontend_install
    if existing_modules:
        (frontend / "node_modules").mkdir()
    assert dev.ensure_frontend() == "npm"
    assert (frontend / "node_modules/.sbom-dependencies-sha256").is_file()
    dev.ensure_frontend()
    assert runner.call_count == 1


@pytest.mark.parametrize("manifest", ["package.json", "package-lock.json"])
def test_frontend_manifest_change_reinstalls(frontend_install, manifest):
    frontend, runner = frontend_install
    dev.ensure_frontend()
    stamp = frontend / "node_modules/.sbom-dependencies-sha256"
    previous = stamp.read_text()
    (frontend / manifest).write_text('{"changed":true}')
    dev.ensure_frontend()
    assert runner.call_count == 2
    assert stamp.read_text() != previous
    dev.ensure_frontend()
    assert runner.call_count == 2


def test_failed_frontend_install_is_not_stamped_and_retries(frontend_install):
    frontend, runner = frontend_install
    dev.ensure_frontend()
    (frontend / "package-lock.json").write_text('{"changed":true}')
    install = runner.side_effect
    runner.side_effect = lambda command: SimpleNamespace(returncode=1, stdout="", stderr="npm ERR! network")
    with pytest.raises(dev.SetupError, match="Frontend npm ci failed"):
        dev.ensure_frontend()
    assert not (frontend / "node_modules/.sbom-dependencies-sha256").exists()
    runner.side_effect = install
    dev.ensure_frontend()
    assert runner.call_count == 3


def test_missing_frontend_manifest_fails_clearly(frontend_install):
    frontend, runner = frontend_install
    (frontend / "package-lock.json").unlink()
    with pytest.raises(dev.SetupError, match="Cannot read frontend"):
        dev.ensure_frontend()
    runner.assert_not_called()


def test_same_environment_passed_to_all_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    received = []

    def fake_popen(command, **kwargs):
        received.append(kwargs["env"])
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(dev.subprocess, "Popen", fake_popen)
    env = {"DATABASE_URL": "same", "NATIVE_SECURITY_OUTBOX_KEY": "same-secret"}
    dev.start_process("API", ["api"], env)
    dev.start_process("Worker", ["worker"], env)
    assert received == [env, env]


def test_schema_guard_allows_empty_and_known_revision() -> None:
    dev.check_schema_objects(set(), None, {"001_initial_schema"})
    dev.check_schema_objects({"alembic_version", "iam_users", "tenants"}, "001_initial_schema", {"001_initial_schema"})


@pytest.mark.parametrize(
    "objects,revision",
    [
        ({"other_app_table"}, None),
        ({"alembic_version", "iam_users", "tenants"}, "unknown_revision"),
        ({"alembic_version", "tenants"}, "001_initial_schema"),
    ],
)
def test_schema_guard_refuses_unknown_or_incomplete_database(objects: set[str], revision: str | None) -> None:
    with pytest.raises(dev.SetupError, match="unknown or incomplete schema"):
        dev.check_schema_objects(objects, revision, {"001_initial_schema"})


def test_verbose_prints_subprocess_output_but_redacts_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(dev, "VERBOSE", True)
    monkeypatch.setattr(
        dev.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="hello secret-value", stderr="error secret-value", returncode=1),
    )
    dev.run(["docker", "info"], env={"NATIVE_SECURITY_OUTBOX_KEY": "secret-value"})
    output = capsys.readouterr()
    assert "hello [REDACTED]" in output.out
    assert "error [REDACTED]" in output.err


def test_verbose_prints_startup_log_without_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / ".dev-logs"
    path.mkdir()
    (path / "api.log").write_text("startup failed secret-value")
    monkeypatch.setattr(dev, "ROOT", tmp_path)
    monkeypatch.setattr(dev, "VERBOSE", True)
    dev.show_log("API", {"NATIVE_SECURITY_OUTBOX_KEY": "secret-value"})
    output = capsys.readouterr().err
    assert "startup failed [REDACTED]" in output
    assert "secret-value" not in output


def test_readiness_waits_for_all_three_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = []
    monkeypatch.setattr(dev, "http_ready", lambda url, json_ready=False: requests.append((url, json_ready)) or True)
    processes = [SimpleNamespace(poll=lambda: None) for _ in range(4)]
    dev.wait_for_ready(processes, {}, dev.DEV_API_PORT, dev.DEV_FRONTEND_PORT, timeout=1)
    assert requests == [
        ("http://127.0.0.1:18000/health", False),
        ("http://127.0.0.1:18000/ready/iam", True),
        ("https://localhost:13000", False),
    ]


def test_readiness_failure_names_log(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "http_ready", lambda url, json_ready=False: False)
    processes = [SimpleNamespace(poll=lambda: None) for _ in range(4)]
    with pytest.raises(dev.SetupError, match=r"\.dev-logs/api\.log"):
        dev.wait_for_ready(processes, {}, dev.DEV_API_PORT, dev.DEV_FRONTEND_PORT, timeout=0)


def test_unrecognized_application_port_is_not_reused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(dev, "BEAT_LOCK", tmp_path / "absent.pid")
    monkeypatch.setattr(dev, "reachable", lambda host, port: port == dev.DEV_API_PORT)
    with pytest.raises(dev.SetupError, match=r"API port 18000 is already in use"):
        dev.check_application_ports(dev.DEV_API_PORT, dev.DEV_FRONTEND_PORT)


def test_production_application_ports_do_not_block_development(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dev, "reachable", lambda host, port: port in {3000, 8000})
    dev.check_application_ports(dev.DEV_API_PORT, dev.DEV_FRONTEND_PORT)


def test_existing_sbom_launcher_is_identified(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lock = tmp_path / "beat.pid"
    lock.write_text(str(dev.os.getpid()))
    monkeypatch.setattr(dev, "BEAT_LOCK", lock)
    monkeypatch.setattr(dev, "reachable", lambda host, port: port == dev.DEV_API_PORT)
    monkeypatch.setattr(dev, "http_ready", lambda url, json_ready=False: True)
    with pytest.raises(dev.SetupError, match="ownership: unrelated/unknown"):
        dev.check_application_ports(dev.DEV_API_PORT, dev.DEV_FRONTEND_PORT)


# --- Preflight, cross-platform and safety regressions (enterprise dev simplification) ---

REPOSITORY = Path(dev.__file__).resolve().parents[1]


def test_cli_surface_is_unchanged() -> None:
    assert dev.parse_args([]).command == "start"
    assert dev.parse_args([]).profile == "auto"
    for command in ("start", "stop", "restart", "status"):
        assert dev.parse_args([command, "--profile", "legacy"]).command == command
    args = dev.parse_args(["--check", "--verbose", "--profile", "greenfield"])
    assert (args.check, args.verbose, args.profile) == (True, True, "greenfield")
    with pytest.raises(SystemExit):
        dev.parse_args(["doctor"])  # --check remains the single inspection mode.


@pytest.mark.parametrize("platform", ["win32", "linux"])
def test_auto_profile_uses_legacy_where_greenfield_is_unsupported(monkeypatch, tmp_path, capsys, platform) -> None:
    monkeypatch.delenv("SBOM_DEV_PROFILE_NOTED", raising=False)
    (tmp_path / ".sbom-greenfield-uuid").mkdir()
    (dev.ROOT / "scripts").mkdir()
    (dev.ROOT / "scripts/greenfield_uuid.py").touch()
    assert dev.resolve_profile("auto", "start", platform_name=platform, home=tmp_path) == "legacy"
    assert "requires macOS" in capsys.readouterr().out
    # The .venv handoff re-runs main() with the inherited environment: no second note.
    assert dev.resolve_profile("auto", "start", platform_name=platform, home=tmp_path) == "legacy"
    assert capsys.readouterr().out == ""


def test_auto_profile_selects_installed_greenfield_on_macos(tmp_path) -> None:
    (tmp_path / ".sbom-greenfield-uuid").mkdir()
    (dev.ROOT / "scripts").mkdir()
    (dev.ROOT / "scripts/greenfield_uuid.py").touch()
    assert dev.resolve_profile("auto", "start", platform_name="darwin", home=tmp_path) == "greenfield"
    assert dev.resolve_profile("auto", "start", platform_name="darwin", home=tmp_path / "absent") == "legacy"


@pytest.mark.parametrize("platform", ["win32", "linux"])
@pytest.mark.parametrize("command", ["start", "restart", "status", "--check"])
def test_explicit_greenfield_fails_clearly_off_macos(platform, command) -> None:
    with pytest.raises(dev.SetupError, match="supports macOS only.*--profile legacy"):
        dev.resolve_profile("greenfield", command, platform_name=platform)


def test_greenfield_stop_stays_available_off_macos() -> None:
    # Stop only reads this checkout's ownership registry, so it is never refused.
    assert dev.resolve_profile("greenfield", "stop", platform_name="win32") == "greenfield"
    assert dev.resolve_profile("legacy", "start", platform_name="win32") == "legacy"


@pytest.mark.parametrize(
    "argv", [["dev.py", "--check", "--profile", "greenfield"], ["dev.py", "status", "--profile", "greenfield"]]
)
def test_unsupported_greenfield_is_refused_before_import(monkeypatch, capsys, argv) -> None:
    from scripts import dev_greenfield

    monkeypatch.setattr(dev.sys, "platform", "win32")
    monkeypatch.setattr(dev.sys, "argv", argv)
    monkeypatch.setattr(dev, "start_application", lambda args: pytest.fail("greenfield start reached"))
    monkeypatch.setattr(dev_greenfield, "status", lambda runtime: pytest.fail("greenfield status reached"))
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: pytest.fail("venv created"))
    assert dev.cli() == 1
    assert "supports macOS only" in capsys.readouterr().err


def test_old_python_is_refused_before_virtualenv(monkeypatch, capsys) -> None:
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "start", "--profile", "legacy"])
    monkeypatch.setattr(dev.sys, "version_info", (3, 10, 14, "final", 0))
    monkeypatch.setattr(dev.sys, "prefix", str(dev.ROOT / "system-python"))  # Not running inside .venv.
    monkeypatch.setattr(dev, "venv_python", lambda: dev.ROOT / "absent/python")  # No .venv to hand off to.
    monkeypatch.setattr(dev, "ensure_virtualenv", lambda: pytest.fail("venv created by an unsupported Python"))
    assert dev.cli() == 1
    assert "Python 3.10.14 is too old" in capsys.readouterr().err


def test_old_launcher_python_hands_off_to_an_existing_venv(monkeypatch, tmp_path) -> None:
    # A supported .venv checks its own interpreter after the handoff.
    python = tmp_path / ".venv/bin/python"
    python.parent.mkdir(parents=True)
    python.touch()
    monkeypatch.setattr(dev, "VENV", tmp_path / ".venv")
    monkeypatch.setattr(dev, "venv_python", lambda: python)
    monkeypatch.setattr(dev.sys, "prefix", str(tmp_path / "system-python"))
    monkeypatch.setattr(dev.sys, "version_info", (3, 9, 6, "final", 0))
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "start", "--profile", "legacy"])
    handoff = MagicMock(side_effect=SystemExit(0))
    monkeypatch.setattr(dev, "ensure_virtualenv", handoff)
    with pytest.raises(SystemExit):
        dev.main()
    handoff.assert_called_once_with()


def test_old_python_inside_existing_venv_explains_recreation(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(dev, "VENV", tmp_path / ".venv")
    monkeypatch.setattr(dev.sys, "prefix", str(tmp_path / ".venv"))
    with pytest.raises(dev.SetupError, match="existing .venv uses Python 3.10.0"):
        dev.validate_python_version((3, 10, 0))
    dev.validate_python_version((3, 11, 0))


def test_incomplete_checkout_is_refused_before_any_setup(monkeypatch) -> None:
    (dev.ROOT / "frontend/package-lock.json").unlink()
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", "--check", "--profile", "legacy"])
    monkeypatch.setattr(dev, "start_application", lambda args: pytest.fail("setup started"))
    with pytest.raises(dev.SetupError, match="Missing: frontend/package-lock.json"):
        dev.main()


@pytest.mark.parametrize("command", ["stop", "status"])
def test_stop_and_status_do_not_require_a_complete_checkout(monkeypatch, command) -> None:
    (dev.ROOT / "requirements.txt").unlink()
    monkeypatch.setattr(dev.sys, "argv", ["dev.py", command, "--profile", "legacy"])
    calls = []
    monkeypatch.setattr(dev, "stop_application", lambda: calls.append("stop"))
    monkeypatch.setattr(dev, "application_status", lambda: calls.append("status"))
    dev.main()
    assert calls == [command]


def test_cli_maps_outcomes_to_exit_codes(monkeypatch, capsys) -> None:
    monkeypatch.setattr(dev, "main", lambda: None)
    assert dev.cli() == 0
    monkeypatch.setattr(dev, "main", MagicMock(side_effect=KeyboardInterrupt))
    assert dev.cli() == 130
    monkeypatch.setattr(dev, "main", MagicMock(side_effect=dev.SetupError("readable reason")))
    assert dev.cli() == 1
    assert "[ERROR] readable reason" in capsys.readouterr().err


def test_failed_setup_command_tail_is_redacted(capsys) -> None:
    secret = "super-secret-password"
    output = "\n".join(f"line {number}" for number in range(50)) + f"\nconnecting with {secret}"
    dev.explain_failed_command(SimpleNamespace(returncode=1, stdout=output, stderr=""), {"POSTGRES_PASSWORD": secret})
    error = capsys.readouterr().err
    assert secret not in error and "[REDACTED]" in error
    assert "line 16" in error and "line 15" not in error  # Only the last 35 lines.


def test_failed_setup_command_tail_is_silent_on_success_or_verbose(monkeypatch, capsys) -> None:
    dev.explain_failed_command(SimpleNamespace(returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr(dev, "VERBOSE", True)  # Verbose mode already streamed the output.
    dev.explain_failed_command(SimpleNamespace(returncode=1, stdout="failed", stderr=""))
    assert capsys.readouterr().err == ""


def test_pip_failure_reports_detail_and_keeps_stamp_unset(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(dev, "VENV", tmp_path / ".venv")
    monkeypatch.setitem(dev.sys.modules, "celery", None)  # A missing import forces installation.
    failure = SimpleNamespace(returncode=1, stdout="", stderr="No matching distribution")
    monkeypatch.setattr(dev, "run", lambda command: failure)
    with pytest.raises(dev.SetupError, match="Python dependency installation failed"):
        dev.ensure_dependencies()
    assert "No matching distribution" in capsys.readouterr().err
    assert not (tmp_path / ".venv/.sbom-requirements-sha256").exists()


def test_service_logs_stay_behind_verbose(capsys) -> None:
    path = dev.log_path("API")
    path.parent.mkdir()
    path.write_text("Authorization: Bearer runtime-token")
    dev.show_log("API", {})
    assert "runtime-token" not in capsys.readouterr().err


def test_child_output_is_decoded_as_utf8(monkeypatch) -> None:
    captured = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(stdout="", stderr="")

    monkeypatch.setattr(dev.subprocess, "run", fake_run)
    dev.run(["tool"])
    assert (captured["encoding"], captured["errors"]) == ("utf-8", "replace")


@pytest.mark.parametrize(
    ("output", "expected"),
    [("v22.11.0\n", (22, 11, 0)), ("v20.9.0", (20, 9, 0)), ("v23.0.0-rc.1", (23, 0, 0)), ("garbage", None)],
)
def test_node_version_is_parsed(monkeypatch, output, expected) -> None:
    monkeypatch.setattr(dev.shutil, "which", lambda name: "node")
    monkeypatch.setattr(dev, "run", lambda command: SimpleNamespace(returncode=0, stdout=output, stderr=""))
    assert dev.node_version() == expected


def test_node_requirement_matches_locked_next_release() -> None:
    import json

    lock = json.loads((REPOSITORY / "frontend/package-lock.json").read_text(encoding="utf-8"))
    engines = lock["packages"]["node_modules/next"]["engines"]["node"]
    assert engines == ">=" + ".".join(str(part) for part in dev.MIN_NODE)
    assert dev.node_problem((20, 8, 1)) and dev.node_problem(None)
    assert dev.node_problem((20, 9, 0)) is None and dev.node_problem((24, 0, 0)) is None


def test_old_node_is_refused_before_npm_ci(monkeypatch) -> None:
    monkeypatch.setattr(dev.shutil, "which", lambda name: name)
    monkeypatch.setattr(dev, "node_version", lambda: (20, 5, 1))
    monkeypatch.setattr(dev, "run", lambda command: pytest.fail("npm ci ran with an unsupported Node.js"))
    with pytest.raises(dev.SetupError, match="Node.js 20.5.1 is too old"):
        dev.ensure_frontend()


def test_legacy_worker_matches_production_queue_set() -> None:
    compose = (REPOSITORY / "docker-compose.server.yml").read_text(encoding="utf-8")
    assert f'"--queues={dev.WORKER_QUEUES}"' in compose
    routes = (REPOSITORY / "app/workers/celery_app.py").read_text(encoding="utf-8")
    assert '"report_notifications.*": {"queue": "reports"}' in routes
    assert "task_default_queue" not in routes  # The default queue is Celery's "celery".
    assert dev.celery_worker_command(["celery"], "linux") == [
        "celery", "worker", "--loglevel=info", "--queues=celery,reports"
    ]
    assert dev.celery_worker_command(["celery"], "win32")[-1] == "--pool=solo"


def test_untrusted_env_cannot_add_identity_providers_or_keys() -> None:
    saved = {"ENTRA_ENABLED": "true", "NATIVE_JWT_VERIFICATION_KEYS_JSON": '{"other": "key"}'}
    values = dev.resolve_config(saved, dev.POSTGRES_PORT, dev.REDIS_PORT, dev.MAILPIT_SMTP_PORT)
    assert values["ENTRA_ENABLED"] == "false"
    assert values["NATIVE_JWT_VERIFICATION_KEYS_JSON"] == "{}"
    assert values["HCL_AUTH_ENABLED"] == "false" and values["NATIVE_AUTH_ENABLED"] == "true"


def test_beat_lock_never_signals_a_recorded_pid(monkeypatch, tmp_path) -> None:
    lock = tmp_path / "beat.pid"
    lock.write_text("4242")
    monkeypatch.setattr(dev, "BEAT_LOCK", lock)
    monkeypatch.setattr(dev.os, "kill", lambda *args: pytest.fail("os.kill is not a liveness probe on Windows"))
    monkeypatch.setattr(dev, "process_info", lambda pid: None)  # Exited: the stale lock is reclaimed.
    dev.acquire_beat_lock()
    assert lock.read_text() == str(dev.os.getpid())


@pytest.mark.parametrize("probe", [lambda pid: {"pid": pid}, MagicMock(side_effect=dev.OwnershipError("denied"))])
def test_live_or_uninspectable_beat_owner_is_kept(monkeypatch, tmp_path, probe) -> None:
    lock = tmp_path / "beat.pid"
    lock.write_text("4242")
    monkeypatch.setattr(dev, "BEAT_LOCK", lock)
    monkeypatch.setattr(dev, "process_info", probe)
    with pytest.raises(dev.SetupError, match="already owns Celery Beat"):
        dev.acquire_beat_lock()
    assert lock.read_text() == "4242"


def test_malformed_beat_lock_is_reclaimed(monkeypatch, tmp_path) -> None:
    lock = tmp_path / "beat.pid"
    lock.write_text("not-a-pid")
    monkeypatch.setattr(dev, "BEAT_LOCK", lock)
    monkeypatch.setattr(dev, "process_info", lambda pid: pytest.fail("no lookup for a malformed PID"))
    dev.acquire_beat_lock()
    assert lock.read_text() == str(dev.os.getpid())


@pytest.mark.parametrize(
    ("platform", "hint"),
    [("win32", "netstat -ano | findstr :18000"), ("darwin", "lsof -nP -iTCP:18000 -sTCP:LISTEN")],
)
def test_port_conflicts_suggest_read_only_inspection(monkeypatch, platform, hint) -> None:
    monkeypatch.setattr(dev.sys, "platform", platform)
    assert hint in dev.port_diagnostic(18000)
    assert "ownership: unrelated/unknown" in dev.port_diagnostic(18000)


@pytest.mark.parametrize(("platform", "command"), [("nt", "python scripts/dev.py"), ("posix", "python3 scripts/dev.py")])
def test_launcher_hint_uses_platform_python(platform, command) -> None:
    assert dev.launcher_command(platform) == command


def test_identity_tables_match_revision_100_guard() -> None:
    from app.public_identity import TABLES

    assert dev.PUBLIC_IDENTITY_TABLES == TABLES


def test_pre_uuid_revisions_are_strict_ancestors_of_revision_100() -> None:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(Config(str(REPOSITORY / "alembic.ini")))
    ancestors = dev.pre_uuid_revisions(script)
    assert {"079_lifecycle_provider_verification", "078_finding_reconciliation"} <= ancestors
    assert dev.GREENFIELD_UUID_BASELINE not in ancestors
    assert not {"101_iam_user_public_uuid", "103_tenant_admin_governance"} & ancestors


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0]

    def __iter__(self):
        return iter(self.rows)


class FakeConnection:
    """Catalogue double: records every statement and fails on anything but a read-only SELECT."""

    def __init__(self, revision, populated):
        self.revision = revision
        self.populated = populated
        self.statements = []
        self.read_only = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, statement, params=None):
        assert self.read_only, "schema inspection must use a read-only session"
        assert statement.lstrip().upper().startswith("SELECT"), statement
        self.statements.append(statement)
        if "pg_class" in statement:
            tables = ["alembic_version", "iam_users", *dev.PUBLIC_IDENTITY_TABLES]
            return FakeCursor([("public", table) for table in tables])
        if "alembic_version" in statement:
            return FakeCursor([(self.revision,)])
        table = statement.split('public."')[1].split('"')[0]
        return FakeCursor([(table in self.populated,)])


def inspect_schema(monkeypatch, revision, populated):
    connection = FakeConnection(revision, populated)
    monkeypatch.setitem(dev.sys.modules, "psycopg", SimpleNamespace(connect=lambda url: connection, Error=Exception))
    monkeypatch.setattr(dev, "ROOT", REPOSITORY)
    dev.validate_existing_schema("postgresql+psycopg://sbom:sbom@127.0.0.1:55439/sbom_analyser_dev")
    return connection


@pytest.mark.parametrize("revision", ["079_lifecycle_provider_verification", "078_finding_reconciliation"])
def test_populated_pre_uuid_database_is_refused_before_alembic(monkeypatch, revision) -> None:
    with pytest.raises(dev.SetupError, match=rf"pre-UUID revision {revision} and has rows in tenants, sbom_component"):
        inspect_schema(monkeypatch, revision, {"tenants", "sbom_component"})


def test_empty_pre_uuid_identity_tables_may_continue(monkeypatch) -> None:
    connection = inspect_schema(monkeypatch, "079_lifecycle_provider_verification", set())
    assert sum("SELECT EXISTS" in statement for statement in connection.statements) == len(dev.PUBLIC_IDENTITY_TABLES)


@pytest.mark.parametrize("revision", ["100_greenfield_uuid_final", "103_tenant_admin_governance"])
def test_uuid_databases_skip_the_row_probe(monkeypatch, revision) -> None:
    connection = inspect_schema(monkeypatch, revision, {"tenants"})
    assert not any("SELECT EXISTS" in statement for statement in connection.statements)


def test_refused_pre_uuid_database_never_reaches_migrations(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(dev, "CONFIG", tmp_path / ".env.dev.local")
    monkeypatch.setattr(dev, "read_config", lambda: {})
    monkeypatch.setattr(dev, "select_service", lambda service, port, *args, **kwargs: ("Docker", port))
    monkeypatch.setattr(dev, "select_mailpit", lambda **kwargs: "Docker")
    for name in ("ensure_dependencies", "generate_keys", "check_application_ports", "ensure_database", "write_config"):
        monkeypatch.setattr(dev, name, lambda *args, **kwargs: None)

    def refuse(url):
        raise dev.SetupError("pre-UUID revision refused")

    monkeypatch.setattr(dev, "validate_existing_schema", refuse)
    monkeypatch.setattr(dev, "run_migrations", lambda env: pytest.fail("Alembic ran after a refusal"))
    with pytest.raises(dev.SetupError, match="pre-UUID revision refused"):
        dev.start_application(SimpleNamespace(check=False, profile="legacy"))


def test_compose_failure_detail_only_when_no_local_fallback(monkeypatch, capsys) -> None:
    failure = SimpleNamespace(returncode=1, stdout="", stderr="pull access denied")
    monkeypatch.setattr(dev, "docker_available", lambda: True)
    monkeypatch.setattr(dev, "compose_container", lambda service: False)
    monkeypatch.setattr(dev, "reachable", lambda host, port: False)
    monkeypatch.setattr(dev, "run", lambda command, env=None: failure)
    monkeypatch.setattr(dev.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(dev, "service_available", lambda service, port: port == 5432)
    assert dev.select_service("postgres", 55439, 5432, check=False, env={}, preferred="docker") == ("local", 5432)
    assert "pull access denied" not in capsys.readouterr().err  # Fallback succeeded: no dump.
    monkeypatch.setattr(dev, "service_available", lambda service, port: False)
    with pytest.raises(dev.SetupError, match="Could not start project postgres"):
        dev.select_service("postgres", 55439, 5432, check=False, env={}, preferred="docker")
    assert "pull access denied" in capsys.readouterr().err
