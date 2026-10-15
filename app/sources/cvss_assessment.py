"""Validated, coherent CVSS assessments; no severity-derived measured scores.

Prefer provider authority, then CVSS 3.1, 3.0, 4.0, 2.0 for comparability
with existing base-score reports. Score magnitude is never a selection key.
"""

from __future__ import annotations

import math
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

VERSION_ORDER = {"3.1": 0, "3.0": 1, "4.0": 2, "2.0": 3, None: 4}


def numeric_score(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return score if math.isfinite(score) and 0 <= score <= 10 else None


def severity_for_score(score: float) -> str:
    return (
        "CRITICAL"
        if score >= 9
        else "HIGH"
        if score >= 7
        else "MEDIUM"
        if score >= 4
        else "LOW"
        if score > 0
        else "UNKNOWN"
    )


def assessment(score: Any, vector: Any = None, version: Any = None, *, provider: str = "") -> dict | None:
    original = {"score": score, "vector": vector, "version": version}
    supplied = numeric_score(score)
    version = str(version).removeprefix("CVSS:") if version else None
    version = {"V31": "3.1", "V30": "3.0", "V40": "4.0", "V2": "2.0"}.get(version, version)
    vector = str(vector).strip() if vector else None
    kind = "base"
    if vector:
        try:
            if vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
                inferred = vector.split("/", 1)[0][5:]
                calculated = float(CVSS3(vector).scores()[0])
            elif vector.startswith("CVSS:4.0/"):
                inferred = "4.0"
                calculated = float(CVSS4(vector).scores()[0])
                kind = (
                    "CVSS-BTE"
                    if any(
                        f"/{m}:" in vector
                        for m in (
                            "MAV",
                            "MAC",
                            "MAT",
                            "MPR",
                            "MUI",
                            "MVC",
                            "MVI",
                            "MVA",
                            "MSC",
                            "MSI",
                            "MSA",
                            "CR",
                            "IR",
                            "AR",
                        )
                    )
                    else "CVSS-BT"
                    if "/E:" in vector
                    else "base"
                )
            elif version == "2.0":
                inferred = "2.0"
                calculated = float(CVSS2(vector).scores()[0])
            else:
                return None
            if version and inferred != version:
                return None
            if score is not None and (supplied is None or abs(supplied - calculated) > 0.05):
                return None
            supplied, version = calculated, inferred
        except (CVSSError, ValueError, TypeError, KeyError, ArithmeticError):
            return None
    if supplied is None or (version and version not in VERSION_ORDER):
        return None
    return {
        "score": supplied,
        "vector": vector,
        "version": version,
        "provider": provider,
        "assessment_type": kind,
        "original_evidence": original,
    }


def select_assessment(observations: list[dict], *, cve: bool = True) -> dict | None:
    candidates = []
    for obs in observations:
        provider = str(obs.get("provider") or (obs.get("sources") or [obs.get("source") or ""])[0]).upper()
        candidate = assessment(obs.get("score"), obs.get("vector"), obs.get("cvss_version"), provider=provider)
        if candidate:
            candidates.append(candidate)
    authority = {"NVD": 0 if cve else 2, "GITHUB": 1, "GHSA": 1, "OSV": 2}
    return (
        min(
            candidates,
            key=lambda a: (
                authority.get(a["provider"], 3),
                VERSION_ORDER.get(a["version"], 4),
                str(a["vector"] or ""),
                a["score"],
            ),
        )
        if candidates
        else None
    )


def osv_assessment(vuln: dict) -> dict | None:
    candidates = []
    for item in vuln.get("severity") or []:
        if not isinstance(item, dict):
            continue
        declared = {"CVSS_V3": None, "CVSS_V4": "4.0"}.get(item.get("type"))
        if item.get("type") not in {"CVSS_V3", "CVSS_V4"}:
            continue
        raw = item.get("score")
        is_vector = isinstance(raw, str) and raw.startswith("CVSS:")
        if is_vector and item.get("type") == "CVSS_V3" and not raw.startswith(("CVSS:3.0/", "CVSS:3.1/")):
            continue
        a = assessment(None if is_vector else raw, raw if is_vector else None, declared, provider="OSV")
        if a:
            candidates.append(a)
    db = (vuln.get("database_specific") or {}).get("cvss") or {}
    if isinstance(db, dict):
        a = assessment(db.get("score"), db.get("vectorString") or db.get("vector"), db.get("version"), provider="OSV")
        if a:
            candidates.append(a)
    return (
        min(candidates, key=lambda a: (VERSION_ORDER.get(a["version"], 4), str(a["vector"] or ""), a["score"]))
        if candidates
        else None
    )
