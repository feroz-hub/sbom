from types import SimpleNamespace

from app.workers import celery_app as configured_celery_app
from app.workers.celery_app import _broker_url, _result_backend


def _settings(**overrides: str) -> SimpleNamespace:
    values = {
        "database_url": "postgresql+psycopg://sbom:secret@127.0.0.1:5432/sbom_analyser",
        "redis_url": "redis://localhost:6379/0",
        "celery_broker_url": "",
        "celery_use_database_broker": False,
        "celery_result_backend": "",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_redis_remains_default_broker_and_backend(monkeypatch) -> None:
    monkeypatch.setattr("app.settings.get_settings", lambda: _settings())

    assert _broker_url() == "redis://localhost:6379/0"
    assert _result_backend() == "redis://localhost:6379/0"


def test_sqlalchemy_broker_derives_database_result_backend(monkeypatch) -> None:
    broker = "sqla+postgresql+psycopg://sbom:secret@127.0.0.1:5432/sbom_analyser"
    monkeypatch.setattr(
        "app.settings.get_settings",
        lambda: _settings(celery_broker_url=broker),
    )

    assert _broker_url() == broker
    assert _result_backend() == "db+postgresql+psycopg://sbom:secret@127.0.0.1:5432/sbom_analyser"


def test_database_broker_reuses_database_url_without_duplicate_secret(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.settings.get_settings",
        lambda: _settings(celery_use_database_broker=True),
    )

    assert _broker_url() == "sqla+postgresql+psycopg://sbom:secret@127.0.0.1:5432/sbom_analyser"
    assert _result_backend() == "db+postgresql+psycopg://sbom:secret@127.0.0.1:5432/sbom_analyser"


def test_database_broker_requires_database_url(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.settings.get_settings",
        lambda: _settings(celery_use_database_broker=True, database_url=""),
    )

    try:
        _broker_url()
    except RuntimeError as exc:
        assert "DATABASE_URL is not configured" in str(exc)
    else:
        raise AssertionError("database broker mode should require DATABASE_URL")


def test_explicit_result_backend_wins(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.settings.get_settings",
        lambda: _settings(
            celery_broker_url="sqla+postgresql://broker/db",
            celery_result_backend="db+postgresql://results/db",
        ),
    )

    assert _result_backend() == "db+postgresql://results/db"


def test_configured_application_keeps_broker_and_backend_separate() -> None:
    assert configured_celery_app.conf.broker_url
    assert configured_celery_app.conf.result_backend
