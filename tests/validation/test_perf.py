"""Performance benchmark — assert p95 < 500 ms on a realistic SBOM.

Run with ``pytest -m bench`` for a benchmark report; default ``pytest``
includes the assertion-only test below.

The realistic CycloneDX 1.6 XML fixture (520 components, ~127 KB) is the
unit of work the budget is calibrated against. The SPDX 2.3 realistic
fixture (220 packages, ~190 KB JSON) provides a parallel sanity run.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.validation import run as run_validation

CORPUS = Path(__file__).parent.parent / "fixtures" / "sboms" / "valid"

# 500 ms p95 budget per ADR-0007 §2.4 / soft-constraint §4.2. We assert the
# *single-run* time as a proxy in unit-test mode; pytest-benchmark runs
# multiple iterations under -m bench and reports p95 explicitly.
SINGLE_RUN_BUDGET_MS = 500


@pytest.mark.parametrize(
    "fixture_name",
    ["spdx_2_3_realistic.json", "cyclonedx_1_6_realistic.xml"],
)
def test_realistic_under_budget(fixture_name: str) -> None:
    body = (CORPUS / fixture_name).read_bytes()
    import time

    t0 = time.perf_counter()
    report = run_validation(body)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert not report.has_errors(), [e.code for e in report.errors][:5]
    assert elapsed_ms < SINGLE_RUN_BUDGET_MS, (
        f"{fixture_name}: single run took {elapsed_ms:.1f} ms (budget {SINGLE_RUN_BUDGET_MS} ms)"
    )


@pytest.mark.bench
@pytest.mark.parametrize(
    "fixture_name",
    ["spdx_2_3_realistic.json", "cyclonedx_1_6_realistic.xml"],
)
def test_benchmark(benchmark, fixture_name: str) -> None:
    """pytest-benchmark — produces a stats table in the CI log."""
    body = (CORPUS / fixture_name).read_bytes()
    benchmark(run_validation, body)
