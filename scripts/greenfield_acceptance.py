"""Real HTTP/PG acceptance. Targets only the explicitly task-owned greenfield stack."""

from __future__ import annotations

import json
import time
import unittest
import uuid
from datetime import UTC, datetime

import httpx

from scripts.dev import GreenfieldStack

STATE = GreenfieldStack.STATE


def public(value):
    parsed = uuid.UUID(value)
    assert parsed.version == 4 and parsed.variant == uuid.RFC_4122
    return value


class APIAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = httpx.Client(base_url="http://127.0.0.1:18000", timeout=60)
        cls.users = json.loads((STATE / "users.json").read_text())
        cls.headers = {}
        for role, user in cls.users.items():
            r = cls.client.post("/api/auth/native/login", json={"email": user["email"], "password": user["password"]})
            assert r.status_code == 200, (role, r.status_code)
            cls.headers[role] = {
                "Authorization": "Bearer " + r.json()["access_token"],
                **({"X-Tenant-ID": user["tenant_id"]} if user["tenant_id"] else {}),
            }
        h = cls.headers["admin"]
        projects = cls.client.get("/api/projects", headers=h).json()
        cls.project = next(p for p in projects if p["project_name"] == "Olympus Release")["id"]
        public(cls.project)
        products = cls.client.get(f"/api/projects/{cls.project}/products", headers=h).json()["items"]
        cls.product = next(p for p in products if p["name"] == "Olympus Gateway")["id"]
        public(cls.product)
        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "metadata": {
                "timestamp": datetime.now(UTC).isoformat(),
                "tools": [{"vendor": "Synthetic Olympus", "name": "Acceptance", "version": "1"}],
            },
            "components": [
                {
                    "type": "application",
                    "bom-ref": "app",
                    "name": "olympus-gateway",
                    "version": "1.0.0",
                    "purl": "pkg:generic/olympus-gateway@1.0.0",
                    "supplier": {"name": "Synthetic Olympus"},
                },
                {
                    "type": "library",
                    "bom-ref": "library",
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                    "supplier": {"name": "Synthetic Olympus"},
                },
            ],
            "dependencies": [{"ref": "app", "dependsOn": ["library"]}],
        }
        r = cls.client.post(
            "/api/sboms/upload",
            headers=h,
            data={
                "sbom_name": "Olympus API " + str(uuid.uuid4()),
                "project_id": cls.project,
                "product_id": cls.product,
            },
            files={"file": ("olympus.cdx.json", json.dumps(doc), "application/json")},
        )
        assert r.status_code == 202, (r.status_code, r.text[:400])
        cls.sbom = public(r.json()["sbom_id"])
        cls.upload = r.json()
        r = cls.client.get(f"/api/sboms/{cls.sbom}/components", headers=h)
        assert r.status_code == 200, r.text[:200]
        items = r.json()
        cls.components = items.get("items", []) if isinstance(items, dict) else items
        assert len(cls.components) == 2

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_01_authentication(self):
        self.assertEqual(self.client.get("/api/projects").status_code, 401)
        u = self.users["admin"]
        r = self.client.post(
            "/api/auth/native/login", json={"email": u["email"], "password": "synthetic-wrong-password"}
        )
        self.assertEqual(r.status_code, 401)

    def test_02_six_resource_identities(self):
        h = self.headers["admin"]
        data = self.client.get(f"/api/sboms/{self.sbom}", headers=h).json()
        for value in [
            self.users["admin"]["tenant_id"],
            self.project,
            self.product,
            self.sbom,
            data["logical_sbom_id"],
        ] + [c["id"] for c in self.components]:
            public(value)
        r = self.client.get("/api/logical-sboms/" + data["logical_sbom_id"], headers=h)
        self.assertEqual(r.status_code, 200)

    def test_03_foreign_scope(self):
        for path in [
            f"/api/projects/{self.project}",
            f"/api/products/{self.product}",
            f"/api/sboms/{self.sbom}",
            f"/api/components/{self.components[0]['id']}/lifecycle-override",
        ]:
            r = (
                self.client.get(path, headers=self.headers["foreign"])
                if "override" not in path
                else self.client.patch(path, headers=self.headers["foreign"], json={})
            )
            self.assertEqual(r.status_code, 404, (path, r.status_code))

    def test_04_foreign_tenant_selector(self):
        h = {**self.headers["foreign"], "X-Tenant-ID": self.users["admin"]["tenant_id"]}
        self.assertEqual(self.client.get("/api/projects", headers=h).status_code, 403)

    def test_05_bad_and_missing_uuid(self):
        for value in ["1", "no-uuid", str(uuid.uuid1()), str(uuid.UUID(int=0))]:
            self.assertEqual(self.client.get("/api/projects/" + value, headers=self.headers["admin"]).status_code, 422)
        self.assertEqual(
            self.client.get("/api/projects/" + str(uuid.uuid4()), headers=self.headers["admin"]).status_code, 404
        )

    def test_06_role_permissions(self):
        for role in ("viewer", "developer"):
            r = self.client.post("/api/projects", headers=self.headers[role], json={"project_name": "Denied fixture"})
            self.assertEqual(r.status_code, 403)

    def test_07_uuid_filters(self):
        r = self.client.get(
            "/api/sboms", headers=self.headers["admin"], params={"project_id": self.project, "product_id": self.product}
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertIn(self.sbom, [x["id"] for x in r.json()])

    def test_08_project_crud(self):
        h = self.headers["admin"]
        r = self.client.post("/api/projects", headers=h, json={"project_name": "Synthetic CRUD " + uuid.uuid4().hex})
        self.assertEqual(r.status_code, 201)
        identity = public(r.json()["id"])
        r = self.client.patch("/api/projects/" + identity, headers=h, json={"project_name": "Updated " + identity})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["id"], identity)
        r = self.client.delete("/api/projects/" + identity, headers=h, params={"confirm": "yes"})
        self.assertEqual(r.status_code, 200, r.text[:200])
        self.assertEqual(self.client.get("/api/projects/" + identity, headers=h).status_code, 404)

    def test_09_component_lookup(self):
        for component in self.components:
            r = self.client.get("/api/lifecycle/component/" + public(component["id"]), headers=self.headers["admin"])
            self.assertEqual(r.status_code, 200, r.text[:200])
            self.assertEqual(r.json()["sbom_id"], self.sbom)

    def test_10_no_integer_public_references(self):
        def walk(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if (
                        key
                        in (
                            "tenant_id",
                            "project_id",
                            "product_id",
                            "sbom_id",
                            "logical_sbom_id",
                            "component_id",
                            "projectid",
                        )
                        and item is not None
                    ):
                        public(item)
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        for path in [
            "/api/projects",
            f"/api/products/{self.product}",
            f"/api/sboms/{self.sbom}",
            f"/api/sboms/{self.sbom}/components",
            "/api/auth/me",
        ]:
            r = self.client.get(path, headers=self.headers["admin"])
            self.assertEqual(r.status_code, 200)
            walk(r.json())

    def test_11_identity_change_rejected(self):
        h = self.headers["admin"]
        for payload in ({"id": str(uuid.uuid4())}, {"public_id": str(uuid.uuid4())}):
            r = self.client.patch("/api/projects/" + self.project, headers=h, json=payload)
            self.assertEqual(r.status_code, 422, r.text[:100])
        r = self.client.get("/api/projects/" + self.project, headers=h)
        self.assertEqual(r.json()["id"], self.project)

    def test_12_openapi_contract(self):
        doc = self.client.get("/openapi.json").json()
        for schema in ("ProjectOut", "ProductRead", "SBOMSourceOut", "SBOMComponentOut", "LogicalSBOMOut"):
            self.assertEqual(doc["components"]["schemas"][schema]["properties"]["id"]["format"], "uuid")
        parameter = next(
            p for p in doc["paths"]["/api/projects/{project_id}"]["get"]["parameters"] if p["name"] == "project_id"
        )
        self.assertEqual(parameter["schema"]["format"], "uuid")
        parent = doc["components"]["schemas"]["SBOMSourceOut"]["properties"]["parent_id"]
        self.assertEqual(next(item for item in parent["anyOf"] if item["type"] != "null")["format"], "uuid")

    def test_13_real_osv_analysis(self):
        r = self.client.post(
            f"/api/sboms/{self.sbom}/analyze/stream", headers=self.headers["admin"], json={"sources": ["OSV"]}
        )
        self.assertEqual(r.status_code, 200, r.text[:200])
        complete = [
            json.loads(line[6:])
            for block in r.text.split("\n\n")
            if "event: complete" in block
            for line in block.splitlines()
            if line.startswith("data: ")
        ]
        self.assertEqual(len(complete), 1, r.text[:500])
        self.assertIn(complete[0]["status"], ("OK", "FINDINGS"), complete)
        self.assertEqual(complete[0]["errors"], 0, complete)
        runs = self.client.get(f"/api/sboms/{self.sbom}/analysis-runs", headers=self.headers["admin"])
        self.assertEqual(runs.status_code, 200)
        self.assertEqual(runs.json()[0]["sbom_id"], self.sbom)

    def test_14_report_preview_scope(self):
        payload = {"scope": "SBOM", "sbom_id": self.sbom, "parts": ["A"], "formats": ["XLSX"]}
        r = self.client.post("/api/report-subscriptions/preview", headers=self.headers["admin"], json=payload)
        self.assertEqual(r.status_code, 200, r.text[:300])
        r = self.client.post("/api/report-subscriptions", headers=self.headers["admin"], json=payload)
        self.assertEqual(r.status_code, 201, r.text[:300])
        identifier = r.json()["id"]
        self.assertEqual(r.json()["sbom_id"], self.sbom)
        sent = self.client.post(f"/api/report-subscriptions/{identifier}/send-now", headers=self.headers["admin"])
        self.assertEqual(sent.status_code, 202, sent.text[:200])
        delivery_id = sent.json()["id"]
        delivery = None
        for _ in range(30):
            listing = self.client.get("/api/report-deliveries", headers=self.headers["admin"])
            self.assertEqual(listing.status_code, 200)
            rows = listing.json()
            rows = rows.get("items", []) if isinstance(rows, dict) else rows
            delivery = next((row for row in rows if row["id"] == delivery_id), None)
            if delivery and delivery["status"] not in ("PENDING", "GENERATING", "SENDING"):
                break
            time.sleep(1)
        self.assertIsNotNone(delivery)
        self.assertEqual(delivery["status"], "SENT", str(delivery)[:300])
        self.assertEqual(
            self.client.delete(f"/api/report-subscriptions/{identifier}", headers=self.headers["admin"]).status_code,
            204,
        )

    def test_15_product_crud(self):
        h = self.headers["admin"]
        r = self.client.post(
            f"/api/projects/{self.project}/products",
            headers=h,
            json={"name": "Synthetic UUID application " + uuid.uuid4().hex},
        )
        self.assertEqual(r.status_code, 201, r.text[:200])
        identifier = public(r.json()["id"])
        r = self.client.patch(
            f"/api/products/{identifier}", headers=h, json={"description": "Synthetic updated application"}
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["id"], identifier)
        self.assertEqual(
            self.client.get(f"/api/products/{identifier}", headers=self.headers["foreign"]).status_code, 404
        )
        r = self.client.delete(f"/api/products/{identifier}", headers=h)
        self.assertEqual(r.status_code, 200, r.text[:200])

    def test_16_vex_write_and_role_denial(self):
        component = public(self.components[0]["id"])
        path = f"/api/sboms/{self.sbom}/components/{component}/vulnerabilities/CVE-2099-9001/vex-override"
        payload = {"status": "under_investigation", "reason": "Clearly synthetic Olympus acceptance evidence"}
        self.assertEqual(self.client.patch(path, headers=self.headers["viewer"], json=payload).status_code, 403)
        response = self.client.patch(path, headers=self.headers["admin"], json=payload)
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["component_id"], component)
        history = self.client.get(path + "/history", headers=self.headers["admin"])
        self.assertEqual(history.status_code, 200, history.text[:200])

    def test_17_platform_tenant_directory(self):
        response = self.client.get("/api/platform/tenants", headers=self.headers["platform"])
        self.assertEqual(response.status_code, 200, response.text[:200])
        data = response.json()
        rows = data.get("items", []) if isinstance(data, dict) else data
        self.assertTrue(rows)
        for row in rows:
            public(row["id"])
        selected = self.client.get(
            "/api/platform/tenants",
            headers={**self.headers["platform"], "X-Tenant-ID": self.users["admin"]["tenant_id"]},
        )
        self.assertEqual(selected.status_code, 200, selected.text[:200])
        data = selected.json()
        self.assertEqual(len(data.get("items", []) if isinstance(data, dict) else data), len(rows))

    def test_18_tenant_creation_and_context_isolation(self):
        suffix = uuid.uuid4().hex
        response = self.client.post(
            "/api/tenants",
            headers=self.headers["platform"],
            json={
                "name": "Synthetic acceptance " + suffix,
                "slug": "synthetic-" + suffix,
                "initial_admin_user_id": self.users["admin"]["user_id"],
            },
        )
        self.assertEqual(response.status_code, 201, response.text[:300])
        tenant = public(response.json()["tenant"]["id"])
        context = {**self.headers["admin"], "X-Tenant-ID": tenant}
        self.assertEqual(self.client.get("/api/projects", headers=context).json(), [])
        self.assertEqual(self.client.get("/api/projects/" + self.project, headers=context).status_code, 404)

    def test_19_permanent_sbom_delete_retains_public_references(self):
        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"type": "application", "name": "synthetic-delete", "version": "1"}},
            "components": [],
        }
        response = self.client.post(
            "/api/sboms/upload",
            headers=self.headers["admin"],
            data={
                "sbom_name": "Synthetic delete " + uuid.uuid4().hex,
                "project_id": self.project,
                "product_id": self.product,
            },
            files={"file": ("delete.cdx.json", json.dumps(doc), "application/json")},
        )
        self.assertEqual(response.status_code, 202, response.text[:200])
        identity = public(response.json()["sbom_id"])
        pending = self.client.delete(f"/api/sboms/{identity}", headers=self.headers["admin"])
        self.assertIn(identity, pending.json()["example"])
        response = self.client.delete(
            f"/api/sboms/{identity}", headers=self.headers["admin"], params={"confirm": "yes", "permanent": "true"}
        )
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertEqual(response.json()["sbom_id"], identity)
        self.assertEqual(response.json()["deleted_sbom_ids"], [identity])
        self.assertEqual(self.client.get(f"/api/sboms/{identity}", headers=self.headers["admin"]).status_code, 404)

    def test_20_uuid_keyset_pagination(self):
        first = self.client.get("/api/sboms", headers=self.headers["admin"], params={"page_size": 1})
        self.assertEqual(first.status_code, 200)
        anchor = public(first.headers["X-Next-Cursor"])
        self.assertEqual(first.json()[0]["id"], anchor)
        second = self.client.get("/api/sboms", headers=self.headers["admin"], params={"page_size": 1, "cursor": anchor})
        self.assertEqual(second.status_code, 200, second.text[:200])
        self.assertNotIn(anchor, [item["id"] for item in second.json()])
        self.assertEqual(
            self.client.get("/api/sboms", headers=self.headers["admin"], params={"cursor": "1"}).status_code, 422
        )


def endpoint_test(path):
    def run(self):
        r = self.client.get(
            path.format(sbom=self.sbom, project=self.project, product=self.product), headers=self.headers["admin"]
        )
        self.assertEqual(r.status_code, 200, (path, r.text[:300]))

    return run


for index, path in enumerate(
    [
        "/dashboard/stats",
        "/dashboard/posture",
        "/dashboard/filter-options/projects",
        "/dashboard/filter-options/applications?project_id={project}",
        "/dashboard/filter-options/sboms?project_id={project}&product_id={product}",
        "/api/runs",
        "/api/lifecycle/sources",
        "/api/sboms/{sbom}/vex",
        "/api/sboms/{sbom}/vex/report",
        "/api/products/{product}/logical-sboms",
        "/api/products/{product}/schedule/effective",
        "/api/report-subscriptions",
        "/dashboard/lifecycle",
        "/dashboard/vex",
        "/dashboard/health",
    ]
):
    setattr(APIAcceptance, f"test_endpoint_{index:02}", endpoint_test(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
