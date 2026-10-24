"""Whole-pipeline truncation regression, independent of repair rules."""

import json

from app.validation import run


def test_information_entries_cannot_hide_later_strict_ntia_blocker():
    source = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": str(i),
                "name": f"fixture-{i}",
                "version": "1",
                "purl": f"pkg:generic/fixture-{i}@1",
            }
            for i in range(120)
        ],
        "dependencies": [],
    }
    report = run(json.dumps(source).encode(), strict_ntia=True)
    assert report.truncated
    assert report.has_errors()
    assert report.error_count > 0
    assert report.http_status >= 400
    assert report.first_error_stage == "ntia"
    assert len(report.entries) == 100
