"""Fresh-process report resource probe; invoked only by trusted test fixtures.

No pytest/conftest import, database initialization, unguarded session, or writes.
The parent fixture commits its data before starting this process.
"""

import json
import os
import resource
import sys
import time
from pathlib import Path


def peak_rss_mb():
    """Peak of this exec's address space, excluding the fork parent's RSS.

    Linux ru_maxrss can retain the pre-exec inherited footprint. VmHWM is
    tracked on the new mm and includes this interpreter's imports/rendering.
    Fail if the Ubuntu measurement facility is unavailable; never substitute
    current RSS or silently ignore the memory budget.
    """
    status = Path("/proc/self/status").read_text()
    high_water = next(line for line in status.splitlines() if line.startswith("VmHWM:"))
    _, kib, unit = high_water.split()
    assert unit == "kB" and int(kib) > 0
    return int(kib) / 1024


def main():
    # Bound the child as well as its inherited validation cgroup and timeout.
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    from sqlalchemy.engine import make_url

    test_url = os.environ["TEST_POSTGRES_DATABASE_URL"]
    assert os.environ["DATABASE_URL"] == test_url
    assert "test" in (make_url(test_url).database or "").lower()
    from app.db import SessionLocal, engine
    from app.models import Projects
    from app.schemas_reports import ReportPreferences
    from app.services.report_composer import compose_report
    from app.services.report_rendering import render_pdf, render_xlsx

    from tests.tenant_fixture_scope import verified_fixture_tenant

    fixture = json.loads(sys.stdin.read())
    try:
        start = time.monotonic()
        with SessionLocal() as db, verified_fixture_tenant(db, fixture["tenant_id"]):
            project = db.get(Projects, fixture["project_id"])
            assert project is not None and project.tenant_id == fixture["tenant_id"]
            report = compose_report(
                db, ReportPreferences(scope="PROJECT", project_id=project.id, parts=["A", "B", "C", "D"]),
                tenant_id=project.tenant_id, cycle_start=fixture["cycle_start"], cycle_end=fixture["cycle_end"],
            )
        pdf, xlsx = render_pdf(report), render_xlsx(report)
        assert pdf.startswith(b"%PDF") and xlsx.startswith(b"PK")
        result = {"included_sboms": report["included_sboms"], "total_findings": report["summary"]["total_findings"],
                  "elapsed_seconds": time.monotonic() - start,
                  "peak_mb": peak_rss_mb(), "peak_method": "linux-exec-VmHWM",
                  "inherited_rusage_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
                  "pdf_bytes": len(pdf), "xlsx_bytes": len(xlsx)}
        print(json.dumps(result))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
