"""Pure isolated transport contract; no TLS material or live connections."""

import importlib.util
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit

import pytest
from scripts import dev_workspace_lifecycle as lifecycle


def prepared():
    source = Path(__file__).with_name("test_dev_workspace_lifecycle.py")
    spec = importlib.util.spec_from_file_location("sbo101_tls_contract_fixture", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.prepared()


def test_secure_generated_transport_shape_is_accepted_without_claiming_readiness():
    descriptor, snapshot = prepared()
    plan = lifecycle.plan_lifecycle(descriptor, snapshot)
    assert not plan.ready and not plan.live_operations_authorized
    assert urlsplit(snapshot.environment["DATABASE_URL"]).query
    assert not urlsplit(snapshot.environment["AUTH_SESSION_REDIS_URL"]).query


@pytest.mark.parametrize(
    "key,query",
    [
        ("DATABASE_URL", ""),
        ("DATABASE_URL", "sslmode=disable"),
        ("DATABASE_URL", "sslmode=verify-full&sslmode=disable"),
        ("DATABASE_URL", "sslmode=verify-full&sslrootcert=wrong&options=unsafe"),
        ("REDIS_URL", ""),
        ("REDIS_URL", "ssl_cert_reqs=none&ssl_check_hostname=false"),
        ("REDIS_URL", "ssl_cert_reqs=required&ssl_cert_reqs=none"),
        ("AUTH_SESSION_REDIS_URL", "ssl_cert_reqs=none"),
    ],
)
def test_missing_weak_duplicate_or_unknown_tls_parameters_fail_closed(key, query):
    descriptor, snapshot = prepared()
    url = urlsplit(snapshot.environment[key])
    altered = replace(snapshot, environment={**snapshot.environment, key: urlunsplit(url._replace(query=query))})
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_TLS_CONFIGURATION_REQUIRED$"):
        lifecycle.plan_lifecycle(descriptor, altered)


@pytest.mark.parametrize(
    "key",
    [
        "REDIS_URL",
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "AUTH_SESSION_REDIS_URL",
        "NATIVE_AUTH_RATE_LIMIT_STORAGE_URI",
    ],
)
def test_every_role_rejects_plaintext_redis_even_when_target_is_own(key):
    descriptor, snapshot = prepared()
    value = snapshot.environment[key].replace("rediss://", "redis://", 1)
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_REDIS_TARGET_REFUSED$"):
        lifecycle.plan_lifecycle(descriptor, replace(snapshot, environment={**snapshot.environment, key: value}))


@pytest.mark.parametrize(
    "key,value",
    [
        ("SSL_CERT_FILE", "relative.pem"),
        ("SSL_CERT_FILE", "C:\\another-instance\\ca.pem"),
        ("NODE_EXTRA_CA_CERTS", "C:\\another-instance\\ca.pem"),
        ("SSL_CERT_DIR", "C:\\ambient"),
        ("SMTP_USE_STARTTLS", "false"),
        ("SMTP_USE_TLS", "true"),
        ("SMTP_USERNAME", "another-instance"),
    ],
)
def test_ca_and_smtp_contract_cannot_drift_or_fall_back(key, value):
    descriptor, snapshot = prepared()
    with pytest.raises(lifecycle.LifecycleError):
        lifecycle.plan_lifecycle(descriptor, replace(snapshot, environment={**snapshot.environment, key: value}))


def test_ca_query_binding_is_compared_after_decoding_but_never_printed():
    descriptor, snapshot = prepared()
    url = urlsplit(snapshot.environment["DATABASE_URL"])
    query = urlencode({"sslmode": "verify-full", "sslrootcert": "C:\\synthetic-private-ca\\secret.pem"})
    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle.plan_lifecycle(
            descriptor,
            replace(
                snapshot,
                environment={
                    **snapshot.environment,
                    "DATABASE_URL": urlunsplit(url._replace(query=query)),
                },
            ),
        )
    assert "synthetic-private" not in str(caught.value)


def test_tls_key_logging_is_refused_during_pure_snapshot_creation():
    _, snapshot = prepared()
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_AMBIENT_OVERRIDE_REFUSED$"):
        replace(snapshot, environment={**snapshot.environment, "SSLKEYLOGFILE": "private-output"})


def test_frontend_cannot_receive_the_broker_credential_under_a_different_url_name():
    descriptor, snapshot = prepared()
    value = snapshot.environment["AUTH_SESSION_REDIS_URL"].replace(
        "fixture-private-frontend-redis-password", "fixture-private-lifecycle-value-never-print"
    )
    with pytest.raises(lifecycle.LifecycleError, match="^INSTANCE_SHARED_KEY_REFUSED$"):
        lifecycle.plan_lifecycle(
            descriptor, replace(snapshot, environment={**snapshot.environment, "AUTH_SESSION_REDIS_URL": value})
        )


@pytest.mark.parametrize("other", ["AUTH_SESSION_ENCRYPTION_KEY", "NATIVE_SECURITY_OUTBOX_KEY"])
def test_provider_storage_key_is_independent_and_missing_key_cannot_fall_back(other):
    descriptor, snapshot = prepared()
    for value in ("", snapshot.environment[other]):
        with pytest.raises(lifecycle.LifecycleError):
            lifecycle.plan_lifecycle(
                descriptor, replace(snapshot, environment={**snapshot.environment, "AI_CONFIG_ENCRYPTION_KEY": value})
            )
