"""Uploading an SBOM as a new version of an existing one.

Before this, upload always wrote ``parent_id = NULL``: re-uploading "the same
SBOM, next version" produced two unrelated rows, so Version History,
compare-versions and restore — all of which read the parent/child chain — did
nothing for the path a build pipeline actually uses. Only the in-app edit
endpoint ever created a chain.

These tests pin the declared-lineage contract: the link is set when asked for,
refused when it would cross a product boundary or move the version backwards,
and the existing version endpoints see the result.
"""

from __future__ import annotations

import json
import uuid

import pytest
from app.db import SessionLocal
from app.models import SBOMSource
from app.services.sbom_version_lineage import parse_version


def _name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _project(client, name: str | None = None) -> dict:
    resp = client.post("/api/projects", json={"project_name": name or _name("project")})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _product(client, project_id: int, name: str | None = None) -> dict:
    resp = client.post(f"/api/projects/{project_id}/products", json={"name": name or _name("product")})
    assert resp.status_code == 201, resp.text
    return resp.json()


def _upload(
    client,
    *,
    project_id: int,
    product_id: int,
    version: str,
    parent_sbom_id: int | None = None,
    name: str | None = None,
):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "demo", "version": version}},
        "components": [],
    }
    data = {
        "sbom_name": name or _name("sbom"),
        "project_id": str(project_id),
        "product_id": str(product_id),
        "sbom_version": version,
    }
    if parent_sbom_id is not None:
        data["parent_sbom_id"] = str(parent_sbom_id)
    return client.post(
        "/api/sboms/upload",
        data=data,
        files={"file": ("sbom.cdx.json", json.dumps(sbom), "application/json")},
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.0.0", (1, 0, 0)),
        ("2.1", (2, 1)),
        ("7", (7,)),
        ("  1.2.3  ", (1, 2, 3)),
        ("2.0.0-rc1", None),
        ("2024.09-build7", None),
        ("v1.0.0", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_version_only_accepts_dotted_numeric(raw, expected):
    """Suffixed versions return None so ordering is skipped, not guessed at."""
    assert parse_version(raw) == expected


def test_upload_without_parent_stays_standalone(client):
    project = _project(client)
    product = _product(client, project["id"])

    resp = _upload(client, project_id=project["id"], product_id=product["id"], version="1.0.0")
    assert resp.status_code == 202, resp.text

    with SessionLocal() as db:
        row = db.get(SBOMSource, resp.json()["sbom_id"])
        assert row.parent_id is None


def test_upload_as_new_version_links_the_chain(client):
    project = _project(client)
    product = _product(client, project["id"])

    first = _upload(client, project_id=project["id"], product_id=product["id"], version="1.0.0")
    assert first.status_code == 202, first.text
    first_id = first.json()["sbom_id"]

    second = _upload(
        client,
        project_id=project["id"],
        product_id=product["id"],
        version="1.1.0",
        parent_sbom_id=first_id,
    )
    assert second.status_code == 202, second.text
    second_id = second.json()["sbom_id"]

    with SessionLocal() as db:
        child = db.get(SBOMSource, second_id)
        assert child.parent_id == first_id
        assert "new version of" in (child.change_summary or "").lower()

    # Both endpoints that read the chain now see two versions from either end.
    for sbom_id in (first_id, second_id):
        listed = client.get(f"/api/sboms/{sbom_id}/versions")
        assert listed.status_code == 200, listed.text
        assert [row["id"] for row in listed.json()] == [first_id, second_id]

    compared = client.get(f"/api/sboms/compare-versions?version_a={first_id}&version_b={second_id}")
    assert compared.status_code == 200, compared.text


def test_linking_an_older_version_extends_the_chain_instead_of_forking(client):
    """Pointing at 1.0.0 when 1.1.0 exists must not create two competing tips."""
    project = _project(client)
    product = _product(client, project["id"])

    v1 = _upload(client, project_id=project["id"], product_id=product["id"], version="1.0.0").json()["sbom_id"]
    v2 = _upload(
        client, project_id=project["id"], product_id=product["id"], version="1.1.0", parent_sbom_id=v1
    ).json()["sbom_id"]

    # Deliberately name the root, not the tip.
    third = _upload(
        client, project_id=project["id"], product_id=product["id"], version="1.2.0", parent_sbom_id=v1
    )
    assert third.status_code == 202, third.text
    v3 = third.json()["sbom_id"]

    with SessionLocal() as db:
        assert db.get(SBOMSource, v3).parent_id == v2

    listed = client.get(f"/api/sboms/{v1}/versions")
    assert [row["id"] for row in listed.json()] == [v1, v2, v3]


def test_version_must_move_forward(client):
    project = _project(client)
    product = _product(client, project["id"])
    parent_id = _upload(client, project_id=project["id"], product_id=product["id"], version="2.0.0").json()["sbom_id"]

    for backwards in ("1.9.0", "2.0.0", "2.0"):
        resp = _upload(
            client,
            project_id=project["id"],
            product_id=product["id"],
            version=backwards,
            parent_sbom_id=parent_id,
        )
        assert resp.status_code == 422, f"{backwards}: {resp.text}"
        assert "does not come after" in resp.text


def test_non_numeric_versions_skip_the_ordering_check(client):
    """A build-stamped version has no defined precedence — allow the link."""
    project = _project(client)
    product = _product(client, project["id"])
    parent_id = _upload(
        client, project_id=project["id"], product_id=product["id"], version="2024.09-build7"
    ).json()["sbom_id"]

    resp = _upload(
        client,
        project_id=project["id"],
        product_id=product["id"],
        version="2024.08-build3",
        parent_sbom_id=parent_id,
    )
    assert resp.status_code == 202, resp.text


def test_parent_from_a_different_product_is_refused(client):
    project = _project(client)
    product_a = _product(client, project["id"])
    product_b = _product(client, project["id"])

    parent_id = _upload(client, project_id=project["id"], product_id=product_a["id"], version="1.0.0").json()[
        "sbom_id"
    ]

    resp = _upload(
        client,
        project_id=project["id"],
        product_id=product_b["id"],
        version="1.1.0",
        parent_sbom_id=parent_id,
    )
    assert resp.status_code == 422, resp.text
    assert "different product" in resp.text


def test_unknown_parent_returns_404(client):
    project = _project(client)
    product = _product(client, project["id"])

    resp = _upload(
        client,
        project_id=project["id"],
        product_id=product["id"],
        version="1.1.0",
        parent_sbom_id=99_999_999,
    )
    assert resp.status_code == 404, resp.text


def test_product_latest_version_follows_the_newest_upload(client):
    """The product screen's Latest Version is derived, so linking keeps it right."""
    project = _project(client)
    product = _product(client, project["id"])

    first_id = _upload(client, project_id=project["id"], product_id=product["id"], version="1.0.0").json()["sbom_id"]
    _upload(
        client, project_id=project["id"], product_id=product["id"], version="1.1.0", parent_sbom_id=first_id
    )

    detail = client.get(f"/api/products/{product['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["latest_sbom_version"] == "1.1.0"


def test_same_name_different_version_is_allowed(client):
    """The unique index is (tenant, name, version) — versioning reuses the name.

    A name-only duplicate check (which the upload form used to apply) makes the
    entire version workflow unreachable: you pick "new version of X" and are
    then told X's name is taken.
    """
    project = _project(client)
    product = _product(client, project["id"])
    shared_name = _name("Telemetry Service")

    first = _upload(
        client, project_id=project["id"], product_id=product["id"], version="1.0.0", name=shared_name
    )
    assert first.status_code == 202, first.text

    second = _upload(
        client,
        project_id=project["id"],
        product_id=product["id"],
        version="1.1.0",
        parent_sbom_id=first.json()["sbom_id"],
        name=shared_name,
    )
    assert second.status_code == 202, second.text


def test_same_name_and_version_conflicts_with_409_not_500(client):
    """A real collision is user-correctable, so it must not read as a crash."""
    project = _project(client)
    product = _product(client, project["id"])
    shared_name = _name("Telemetry Service")

    first = _upload(
        client, project_id=project["id"], product_id=product["id"], version="1.0.0", name=shared_name
    )
    assert first.status_code == 202, first.text

    clash = _upload(
        client, project_id=project["id"], product_id=product["id"], version="1.0.0", name=shared_name
    )
    assert clash.status_code == 409, clash.text
    assert clash.json()["detail"]["code"] == "duplicate_sbom_version"
