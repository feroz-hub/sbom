"""Security tests — every attack/* fixture is rejected at the right stage,
without crash, hang, or > 100 ms wall-time."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from app.validation import errors as E
from app.validation import run as run_validation

ATTACK_DIR = Path(__file__).parent.parent / "fixtures" / "sboms" / "attack"

# Per-fixture wall-time budget.  Attack fixtures must reject in < 100 ms each.
WALL_TIME_BUDGET_S = 0.1


def _read(name: str) -> bytes:
    return (ATTACK_DIR / name).read_bytes()


@pytest.mark.security
def test_json_depth_bomb_rejected_fast() -> None:
    body = _read("json_depth_bomb.json")
    t0 = time.perf_counter()
    report = run_validation(body)
    elapsed = time.perf_counter() - t0
    assert elapsed < WALL_TIME_BUDGET_S, f"depth bomb took {elapsed*1000:.1f}ms"
    codes = [e.code for e in report.errors]
    # The capped decoder lives in stage 2 (detect), so depth bombs surface
    # there with stage="detect" before stage 3's schema validator runs.
    assert E.E080_JSON_DEPTH_EXCEEDED in codes


@pytest.mark.security
def test_billion_laughs_rejected_fast() -> None:
    body = _read("xxe_billion_laughs.xml")
    t0 = time.perf_counter()
    report = run_validation(body)
    elapsed = time.perf_counter() - t0
    assert elapsed < WALL_TIME_BUDGET_S, f"billion laughs took {elapsed*1000:.1f}ms"
    codes = [e.code for e in report.errors]
    # Either DTD-forbidden, entity-forbidden, or entity-expansion — all map
    # to a structured rejection rather than a crash. Verify rejection
    # happened and no 500-shaped response.
    assert any(c in codes for c in (
        E.E083_XML_DTD_FORBIDDEN,
        E.E084_XML_EXTERNAL_ENTITY_FORBIDDEN,
        E.E085_XML_ENTITY_EXPANSION,
        E.E021_XML_PARSE_FAILED,
    )), codes
    assert report.http_status in (400, 415, 422), report.http_status


@pytest.mark.security
def test_yaml_pickle_rejected_fast() -> None:
    body = _read("yaml_pickle.yaml")
    t0 = time.perf_counter()
    report = run_validation(body)
    elapsed = time.perf_counter() - t0
    assert elapsed < WALL_TIME_BUDGET_S, f"yaml pickle took {elapsed*1000:.1f}ms"
    # YAML SBOMs are deferred in v1 — stage 2 / 3 should reject. Either
    # E010 (format indeterminate at first byte) or E022 (yaml parse) is
    # acceptable. The contract is: no crash, no exec.
    assert report.has_errors(), [e.code for e in report.entries]


@pytest.mark.security
def test_zip_bomb_rejected_fast() -> None:
    body = _read("zip_bomb.zip")
    t0 = time.perf_counter()
    report = run_validation(body, content_encoding="gzip")
    elapsed = time.perf_counter() - t0
    # Decompression-bomb defence triggers mid-stream; budget is generous to
    # account for the tens of MB the test allocates before the cap fires.
    assert elapsed < 1.0, f"zip bomb took {elapsed*1000:.1f}ms"
    codes = [e.code for e in report.errors]
    assert any(c in codes for c in (
        E.E002_DECOMPRESSED_SIZE_EXCEEDED,
        E.E003_DECOMPRESSION_RATIO_EXCEEDED,
    )), codes


@pytest.mark.security
def test_no_500_envelope_from_any_attack() -> None:
    """Every attack fixture must produce a 4xx — never 500."""
    for fixture in ATTACK_DIR.iterdir():
        if not fixture.is_file():
            continue
        body = fixture.read_bytes()
        encoding = "gzip" if fixture.suffix == ".zip" else None
        report = run_validation(body, content_encoding=encoding)
        assert 400 <= report.http_status < 500, (
            f"{fixture.name}: status {report.http_status} is not 4xx"
        )
