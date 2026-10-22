"""Opt-in regression launcher guard; never publish tasks to the running app."""

from urllib.parse import urlsplit


def pytest_collection_finish(session):
    from app.workers.celery_app import celery_app
    from celery import current_app

    for app in (celery_app, current_app):
        target = urlsplit(app.conf.broker_url)
        if (target.scheme, target.hostname, target.port) != ("redis", "127.0.0.1", 63392):
            raise RuntimeError("Public resource regression broker isolation refused before test execution")


def pytest_runtest_setup(item):
    from app.workers.celery_app import celery_app

    target = urlsplit(celery_app.conf.broker_url)
    if (target.scheme, target.hostname, target.port) != ("redis", "127.0.0.1", 63392):
        raise RuntimeError("Public resource regression broker drift refused")
