"""Integration tests — run the full pipeline against every corpus fixture.

Each fixture has an expected-outcome row in :file:`expected_outcomes.json`;
contract drift surfaces as a precise diff at the path level.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.validation import run as run_validation

EXPECTED = json.loads(
    (Path(__file__).parent / "expected_outcomes.json").read_text(encoding="utf-8")
)
CORPUS_ROOT = Path(__file__).parent.parent / "fixtures" / "sboms"


@pytest.mark.integration
@pytest.mark.parametrize("rel_path", [k for k in EXPECTED if not k.startswith("_")])
def test_corpus_fixture_matches_expected(rel_path: str) -> None:
    expected = EXPECTED[rel_path]
    body = (CORPUS_ROOT / rel_path).read_bytes()

    report = run_validation(body)
    codes = [e.code for e in report.entries]

    assert report.http_status == expected["http_status"], (
        f"{rel_path}: http={report.http_status} expected={expected['http_status']}; codes={codes}"
    )
    for must in expected["must_contain"]:
        assert must in codes, f"{rel_path}: missing required code {must}; got {codes}"
    for forbidden in expected["must_not_contain"]:
        assert forbidden not in codes, (
            f"{rel_path}: forbidden code {forbidden} present; got {codes}"
        )


@pytest.mark.integration
def test_wild_corpus_runs_without_500() -> None:
    """Every wild fixture must produce a structured report (never crash)."""
    wild = CORPUS_ROOT / "wild"
    if not wild.exists():
        pytest.skip("no wild SBOMs vendored")
    for fixture in sorted(wild.iterdir()):
        if not fixture.is_file():
            continue
        body = fixture.read_bytes()
        report = run_validation(body)
        # We do NOT assert any specific status — wild SBOMs may be invalid.
        # We only assert that the validator did not crash, and that any
        # error has a recognised code.
        for entry in report.entries:
            assert entry.code.startswith("SBOM_VAL_"), entry.code
