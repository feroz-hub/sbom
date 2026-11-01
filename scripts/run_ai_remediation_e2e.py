#!/usr/bin/env python3
"""SBO-100 acceptance: real app/IAM/DB/Redis/Celery, local synthetic OpenAI.

Requires a disposable *_test PostgreSQL URL, Postman CLI, Redis and existing
frontend/e2e dependencies. No saved AI credentials or live inference are used.
Set REPAIR_E2E_NODE if needed; REMEDIATION_BROWSER_CHANNEL=chrome selects an
already-installed Chrome instead of Playwright's bundled Chromium.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from scripts.run_sbom_repair_e2e import ROOT, port, setup


def seed(manifest_path, mock_url):
    from app.core.context import minimal_background_context, tenant_scope
    from app.db import SessionLocal
    from app.models import (
        AiProviderCredential,
        AiSettings,
        AnalysisFinding,
        AnalysisRun,
        CveCache,
        LogicalSBOM,
        SBOMSource,
    )
    from app.security.secrets import SecretCipher

    manifest = json.loads(manifest_path.read_text())
    now = datetime.now(UTC).isoformat()
    with tenant_scope(minimal_background_context(1)), SessionLocal() as db:
        db.add(
            AiSettings(
                tenant_id=1,
                feature_enabled=True,
                kill_switch_active=False,
                budget_per_request_usd=0.1,
                budget_per_scan_usd=5,
                budget_daily_usd=5,
                updated_at=now,
            )
        )
        db.add(
            AiProviderCredential(
                tenant_id=1,
                provider_name="openai",
                label="Synthetic HTTP",
                api_key_encrypted=SecretCipher.from_env().encrypt("synthetic-local-only"),
                base_url=mock_url + "/v1",
                default_model="gpt-4o",
                tier="paid",
                is_default=True,
                enabled=True,
                max_concurrent=2,
                rate_per_minute=6000,
                created_at=now,
                updated_at=now,
            )
        )
        logical = LogicalSBOM(
            tenant_id=1, product_id=manifest["product_id"], name="Synthetic remediation", created_at=now, updated_at=now
        )
        db.add(logical)
        db.flush()
        sbom = SBOMSource(
            tenant_id=1,
            logical_sbom_id=logical.id,
            sbom_name="Synthetic Log4j remediation",
            projectid=manifest["project_id"],
            product_id=manifest["product_id"],
            sbom_version="1.0",
            created_on=now,
            status="validated",
        )
        db.add(sbom)
        db.flush()
        from app.schemas_cve import CveDetail

        detail = CveDetail(
            cve_id="CVE-2021-44228",
            title="Synthetic Log4j evidence",
            summary="Synthetic Log4j remediation acceptance fixture.",
            severity="high",
            cvss_v3_score=8.1,
            sources_used=["nvd"],
            fetched_at=datetime.now(UTC),
        )
        db.add(
            CveCache(
                cve_id=detail.cve_id,
                payload=detail.model_dump(mode="json"),
                sources_used="nvd",
                fetched_at=now,
                expires_at=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
                schema_version=2,
            )
        )
        runs = {}
        for label, count in [
            ("individual", 1),
            ("small", 3),
            ("bulk", 75),
            ("cancel", 15),
            ("errors", 3),
            ("budget", 3),
        ]:
            run = AnalysisRun(
                tenant_id=1,
                sbom_id=sbom.id,
                project_id=manifest["project_id"],
                product_id=manifest["product_id"],
                sbom_name=sbom.sbom_name,
                run_status="FINDINGS",
                source="NVD",
                started_on=now,
                completed_on=now,
                total_components=count,
                total_findings=count,
                high_count=count,
            )
            db.add(run)
            db.flush()
            ids = []
            for i in range(count):
                finding = AnalysisFinding(
                    tenant_id=1,
                    analysis_run_id=run.id,
                    vuln_id="CVE-2021-44228",
                    source="NVD",
                    component_name=f"log4j-core-{label}-{i}",
                    component_version="2.14.1",
                    severity="HIGH",
                    score=8.1,
                    description="Synthetic Log4j test evidence. No customer data.",
                    fixed_versions=json.dumps(["2.17.1"]),
                )
                db.add(finding)
                db.flush()
                ids.append(finding.id)
            runs[label] = {"id": str(run.public_id), "internal_id": run.id, "findings": ids}
        db.commit()
    manifest.update(runs=runs, mock_url=mock_url)
    manifest_path.write_text(json.dumps(manifest))
    manifest_path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix="sbom-ai-remediation-", dir="/tmp"))
    directory.chmod(0o700)
    processes, files = [], []
    template = name = None

    def start(command, cwd, label, env):
        output = (directory / f"{label}.log").open("w")
        files.append(output)
        processes.append(
            subprocess.Popen(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        )

    try:
        node = os.getenv("REPAIR_E2E_NODE") or shutil.which("node")
        os.environ.update(
            AI_CONFIG_ENCRYPTION_KEY=base64.b64encode(os.urandom(32)).decode(),
            AI_PROVIDERS="openai",
            AI_DEFAULT_PROVIDER="openai",
            AI_FIXES_ENABLED="true",
        )
        env, manifest, commands, template, name = setup(directory)
        redis_url = env["AUTH_SESSION_REDIS_URL"].rsplit("/", 1)[0] + "/0"
        env.update(
            REDIS_URL=redis_url,
            CELERY_BROKER_URL=redis_url,
            CELERY_RESULT_BACKEND=redis_url,
            CELERY_USE_DATABASE_BROKER="false",
            AI_PROVIDERS="openai",
            AI_DEFAULT_PROVIDER="openai",
        )
        os.environ.update(env)
        mock_port = port()
        mock_url = f"http://127.0.0.1:{mock_port}/openai"
        start(
            [
                "postman",
                "simulation",
                "run",
                "postman/simulations/ai-remediation.sim.yaml",
                "--port",
                str(mock_port),
                "--output",
                "ndjson",
                "--no-history",
            ],
            ROOT,
            "mock",
            env,
        )
        seed(manifest, mock_url)
        for command, cwd, label in commands:
            start(command, cwd, label, env)
        start(
            [
                sys.executable,
                "-m",
                "celery",
                "-A",
                "app.workers.celery_app:celery_app",
                "worker",
                "--pool=solo",
                "--concurrency=1",
                "--loglevel=INFO",
                "--queues=celery",
            ],
            directory,
            "worker",
            env,
        )
        info = json.loads(manifest.read_text())
        with httpx.Client(verify=False) as client:
            for endpoint in [mock_url + "/__metrics", info["api_url"] + "/health", info["origin"] + "/native-sign-in"]:
                deadline = time.monotonic() + 180
                while True:
                    if any(p.poll() is not None for p in processes):
                        raise RuntimeError("An isolated server stopped")
                    try:
                        if client.get(endpoint, timeout=5).status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError("Isolated readiness timeout")
                    time.sleep(0.25)
        with httpx.Client(verify=False) as client:
            user = info["users"]["analyst"]
            r = client.post(
                info["origin"] + "/api/auth/native/login",
                headers={"Origin": info["origin"]},
                json={"email": user["email"], "password": user["password"]},
                timeout=90,
            )
            if r.status_code != 200:
                raise RuntimeError(f"Warmup login failed: {r.status_code}")
            for route in [
                "/",
                "/api/auth/session",
                "/api/backend/api/auth/me",
                *["/analysis/" + run["id"] for run in info["runs"].values()],
            ]:
                client.get(info["origin"] + route, timeout=90)
        print(f"Isolated remediation ready; manifest: {manifest}", flush=True)
        if args.serve:
            while True:
                time.sleep(1)
        browser_process = subprocess.Popen(
            [
                node,
                str(ROOT / "frontend/e2e/node_modules/playwright/cli.js"),
                "test",
                "--config=ai-remediation.config.ts",
            ],
            cwd=ROOT / "frontend/e2e",
            env={
                **env,
                "REPAIR_E2E_MANIFEST": str(manifest),
                "REMEDIATION_E2E_RESULTS": str(directory / "browser-results"),
            },
            start_new_session=True,
        )
        processes.append(browser_process)
        result = browser_process.wait()
        from app.ai.cache import make_cache_key
        from app.core.context import minimal_background_context, tenant_scope
        from app.db import SessionLocal
        from app.models import AiFixBatch, AiFixCache, AiUsageLog, AnalysisFinding
        from sqlalchemy import select

        evidence = {}
        for tenant in (1, 2):
            with tenant_scope(minimal_background_context(tenant)), SessionLocal() as db:
                usage = list(db.scalars(select(AiUsageLog)))
                batches = list(db.scalars(select(AiFixBatch)))
                findings = list(db.scalars(select(AnalysisFinding)))
                keys = [
                    make_cache_key(
                        vuln_id=f.vuln_id, component_name=f.component_name, component_version=f.component_version
                    )
                    for f in findings
                ]
                cache = list(db.scalars(select(AiFixCache).where(AiFixCache.cache_key.in_(keys))))
                evidence[str(tenant)] = {
                    "cache_rows": len(cache),
                    "usage_rows": len(usage),
                    "input_tokens": sum(row.input_tokens for row in usage),
                    "output_tokens": sum(row.output_tokens for row in usage),
                    "cost_usd": sum(row.cost_usd for row in usage),
                    "batches": [
                        {
                            "status": row.status,
                            "total": row.total,
                            "generated": row.generated_count,
                            "cached": row.cached_count,
                            "failed": row.failed_count,
                            "cost_usd": row.cost_usd,
                        }
                        for row in batches
                    ],
                }
        (directory / "ledger-evidence.json").write_text(json.dumps(evidence, indent=2))
        return result
    except KeyboardInterrupt:
        return 130
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        for output in files:
            output.close()
        if not name and (directory / "database.json").exists():
            marker = json.loads((directory / "database.json").read_text())
            template, name = make_url(marker["database_url"]), marker["name"]
        if name and template:
            control = create_engine(template.set(database="postgres"), isolation_level="AUTOCOMMIT")
            with control.connect() as connection:
                connection.exec_driver_sql(
                    "DROP DATABASE " + connection.dialect.identifier_preparer.quote(name) + " WITH (FORCE)"
                )
            control.dispose()
        print(f"Private diagnostics retained at {directory}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
