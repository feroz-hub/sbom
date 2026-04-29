"""HTTP integration tests for /api/projects|sboms|schedules schedule routes.

These mock out the Celery .delay() call on the per-SBOM task — the API
layer's job is to validate, persist, and enqueue; whether the task body
actually runs is covered separately by tests/test_schedule_resolver.py
and the scheduling unit tests.
"""

from __future__ import annotations

import json
import uuid

import pytest


@pytest.fixture
def project_id(client) -> int:
    name = f"schedule-api-{uuid.uuid4().hex[:8]}"
    resp = client.post(
        "/api/projects",
        json={"project_name": name, "created_by": "test"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.fixture
def sbom_id(client, project_id: int, sample_sbom_dict) -> int:
    name = f"schedule-api-sbom-{uuid.uuid4().hex[:8]}"
    resp = client.post(
        "/api/sboms",
        json={
            "sbom_name": name,
            "sbom_data": json.dumps(sample_sbom_dict),
            "projectid": project_id,
            "created_by": "test",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.fixture(autouse=True)
def _stub_celery(monkeypatch):
    """Replace the per-SBOM Celery task with a recording stub so tests don't
    need a broker. The list of (sbom_id, schedule_id) tuples is exposed on
    the fixture for assertions.

    We swap the whole module attribute (not just `.delay`) because the
    router imports the task inside the function body, and Celery's bound
    Task instances have method-resolution quirks that defeat instance-level
    monkeypatching.
    """
    captured: list[tuple[int, int]] = []

    class _FakeTask:
        @staticmethod
        def delay(sbom_id, schedule_id):
            captured.append((sbom_id, schedule_id))
            return None

    from app.workers import scheduled_analysis

    monkeypatch.setattr(scheduled_analysis, "analyze_sbom_async", _FakeTask)
    yield captured


# ---------------------------------------------------------------------------
# POST /api/projects/{id}/schedule
# ---------------------------------------------------------------------------


def test_create_project_schedule_weekly(client, project_id):
    resp = client.post(
        f"/api/projects/{project_id}/schedule",
        json={
            "cadence": "WEEKLY",
            "day_of_week": 1,  # Tuesday
            "hour_utc": 2,
            "timezone": "Asia/Kolkata",
            "modified_by": "alice",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["scope"] == "PROJECT"
    assert body["project_id"] == project_id
    assert body["cadence"] == "WEEKLY"
    assert body["enabled"] is True
    assert body["next_run_at"] is not None  # cadence resolved to a real cursor


def test_create_project_schedule_validates_cadence(client, project_id):
    resp = client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "WEEKLY"},  # missing day_of_week
    )
    assert resp.status_code == 422


def test_get_project_schedule_404_when_missing(client, project_id):
    resp = client.get(f"/api/projects/{project_id}/schedule")
    assert resp.status_code == 404


def test_patch_project_schedule_replaces_only_set_fields(client, project_id):
    client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "DAILY", "hour_utc": 2},
    )
    resp = client.patch(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "WEEKLY", "day_of_week": 4, "hour_utc": 14},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cadence"] == "WEEKLY"
    assert body["day_of_week"] == 4
    assert body["hour_utc"] == 14


def test_delete_project_schedule_idempotent(client, project_id):
    client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "DAILY"},
    )
    first = client.delete(f"/api/projects/{project_id}/schedule")
    second = client.delete(f"/api/projects/{project_id}/schedule")
    assert first.status_code == 200
    assert first.json()["status"] == "deleted"
    assert second.status_code == 200
    assert second.json()["status"] == "no_schedule"


# ---------------------------------------------------------------------------
# /api/sboms/{id}/schedule — inheritance + override semantics
# ---------------------------------------------------------------------------


def test_get_sbom_schedule_returns_inherited_from_project(
    client, project_id, sbom_id
):
    client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "WEEKLY", "day_of_week": 0},
    )
    resp = client.get(f"/api/sboms/{sbom_id}/schedule")
    assert resp.status_code == 200
    body = resp.json()
    assert body["inherited"] is True
    assert body["schedule"]["scope"] == "PROJECT"


def test_sbom_override_takes_precedence_over_project(client, project_id, sbom_id):
    client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "WEEKLY", "day_of_week": 0},
    )
    client.post(
        f"/api/sboms/{sbom_id}/schedule",
        json={"cadence": "DAILY", "hour_utc": 5},
    )
    resp = client.get(f"/api/sboms/{sbom_id}/schedule")
    assert resp.status_code == 200
    body = resp.json()
    assert body["inherited"] is False
    assert body["schedule"]["scope"] == "SBOM"
    assert body["schedule"]["cadence"] == "DAILY"


def test_delete_sbom_override_falls_back_to_inherited(client, project_id, sbom_id):
    client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "WEEKLY", "day_of_week": 0},
    )
    client.post(
        f"/api/sboms/{sbom_id}/schedule",
        json={"cadence": "DAILY"},
    )
    delete = client.delete(f"/api/sboms/{sbom_id}/schedule")
    assert delete.status_code == 200
    follow_up = client.get(f"/api/sboms/{sbom_id}/schedule")
    assert follow_up.json()["inherited"] is True


def test_get_sbom_schedule_when_no_schedule_anywhere(client, sbom_id):
    resp = client.get(f"/api/sboms/{sbom_id}/schedule")
    assert resp.status_code == 200
    assert resp.json() == {"inherited": False, "schedule": None}


# ---------------------------------------------------------------------------
# Operator surface — list, pause/resume, run-now
# ---------------------------------------------------------------------------


def test_list_schedules_filters_by_scope(client, project_id, sbom_id):
    client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "DAILY"},
    )
    client.post(
        f"/api/sboms/{sbom_id}/schedule",
        json={"cadence": "DAILY"},
    )
    resp = client.get("/api/schedules?scope=SBOM")
    assert resp.status_code == 200
    rows = resp.json()
    assert all(r["scope"] == "SBOM" for r in rows)
    assert any(r["sbom_id"] == sbom_id for r in rows)


def test_pause_then_resume_cycles_next_run_at(client, project_id):
    create = client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "DAILY"},
    )
    sched_id = create.json()["id"]

    paused = client.post(f"/api/schedules/{sched_id}/pause")
    assert paused.status_code == 200
    assert paused.json()["enabled"] is False
    assert paused.json()["next_run_at"] is None

    resumed = client.post(f"/api/schedules/{sched_id}/resume")
    assert resumed.status_code == 200
    assert resumed.json()["enabled"] is True
    assert resumed.json()["next_run_at"] is not None


def test_run_now_for_project_fans_out_to_member_sboms(
    client, project_id, sbom_id, _stub_celery
):
    create = client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "DAILY"},
    )
    sched_id = create.json()["id"]

    resp = client.post(f"/api/schedules/{sched_id}/run-now")
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert sbom_id in body["sbom_ids"]
    # Stub recorded the per-SBOM enqueue
    assert (sbom_id, sched_id) in _stub_celery


def test_run_now_for_sbom_enqueues_only_that_sbom(client, sbom_id, _stub_celery):
    create = client.post(
        f"/api/sboms/{sbom_id}/schedule",
        json={"cadence": "DAILY"},
    )
    sched_id = create.json()["id"]

    resp = client.post(f"/api/schedules/{sched_id}/run-now")
    assert resp.status_code == 202
    assert resp.json()["sbom_ids"] == [sbom_id]
    assert _stub_celery == [(sbom_id, sched_id)]


def test_run_now_returns_502_when_broker_drops_every_enqueue(
    client, sbom_id, monkeypatch
):
    """Silent enqueue failure must surface — 202 with empty list lies to the user."""
    create = client.post(
        f"/api/sboms/{sbom_id}/schedule",
        json={"cadence": "DAILY"},
    )
    sched_id = create.json()["id"]

    class _BrokenTask:
        @staticmethod
        def delay(sbom_id, schedule_id):  # noqa: ARG004
            raise ConnectionError("[Errno 111] Connection refused")

    from app.workers import scheduled_analysis

    monkeypatch.setattr(scheduled_analysis, "analyze_sbom_async", _BrokenTask)
    resp = client.post(f"/api/schedules/{sched_id}/run-now")
    assert resp.status_code == 502, resp.text
    body = resp.json()
    assert body["detail"]["code"] == "broker_unavailable"
    assert sbom_id in body["detail"]["failed_sbom_ids"]


def test_run_now_skips_overridden_sbom_in_project_fan_out(
    client, project_id, sbom_id, _stub_celery
):
    """SBOM-level row (even disabled) opts the SBOM out of project fan-out."""
    proj = client.post(
        f"/api/projects/{project_id}/schedule",
        json={"cadence": "DAILY"},
    )
    proj_id = proj.json()["id"]
    client.post(
        f"/api/sboms/{sbom_id}/schedule",
        json={"cadence": "DAILY", "enabled": False},
    )

    resp = client.post(f"/api/schedules/{proj_id}/run-now")
    assert resp.status_code == 202
    assert sbom_id not in resp.json()["sbom_ids"]
