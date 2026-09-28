"""Safety checks for the one-command development launcher."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from scripts import dev


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
    dev.main()
    output = capsys.readouterr().out
    assert "no services or processes started" in output
    assert "BEGIN PRIVATE KEY" not in output


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
    with pytest.raises(dev.SetupError, match=r"Development port\(s\) 18000 are unavailable"):
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
    with pytest.raises(dev.SetupError, match="SBOM dev launcher appears to be running"):
        dev.check_application_ports(dev.DEV_API_PORT, dev.DEV_FRONTEND_PORT)
