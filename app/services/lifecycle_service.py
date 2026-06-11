"""
Component Lifecycle Service — Business logic for EOL, EOS, deprecation, and support status checking.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from packaging.version import InvalidVersion, Version
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import SBOMComponent

log = logging.getLogger(__name__)

# Seed catalog of known EOL/EOS dates for common libraries and utilities
# Maps package names (lowercase) to version-specific or global lifecycle definitions.
LIFECYCLE_CATALOG: dict[str, list[dict[str, Any]]] = {
    "log4j-core": [
        {
            "version_max": "2.17.0",
            "eos_date": "2021-12-15",
            "eol_date": "2021-12-30",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "log4j": [
        {
            "version_max": "2.17.0",
            "eos_date": "2021-12-15",
            "eol_date": "2021-12-30",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "commons-cli": [
        {
            "version_max": "1.3",
            "eos_date": "2018-06-01",
            "eol_date": "2019-01-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "bytelist": [
        {
            "version_max": "999.0",  # all versions
            "eos_date": "2014-09-01",
            "eol_date": "2015-03-01",
            "is_deprecated": True,
            "maintenance_status": "unmaintained",
        }
    ],
    "constantine": [
        {
            "version_max": "999.0",
            "eos_date": "2013-06-01",
            "eol_date": "2014-01-01",
            "is_deprecated": True,
            "maintenance_status": "unmaintained",
        }
    ],
    "jna-posix": [
        {
            "version_max": "999.0",
            "eos_date": "2015-06-01",
            "eol_date": "2016-01-01",
            "is_deprecated": True,
            "maintenance_status": "unmaintained",
        }
    ],
    "jruby-complete": [
        {
            "version_max": "1.5.0",
            "eos_date": "2012-11-01",
            "eol_date": "2013-05-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "libiconv": [
        {
            "version_max": "1.15",
            "eos_date": "2017-06-01",
            "eol_date": "2018-01-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "libiconv2.dll": [
        {
            "version_max": "1.15",
            "eos_date": "2017-06-01",
            "eol_date": "2018-01-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "patch": [
        {
            "version_max": "2.6",
            "eos_date": "2014-12-01",
            "eol_date": "2015-06-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "regex": [
        {
            "version_max": "3.0",
            "eos_date": "2015-06-01",
            "eol_date": "2016-01-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "regex2.dll": [
        {
            "version_max": "3.0",
            "eos_date": "2015-06-01",
            "eol_date": "2016-01-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
    "sed": [
        {
            "version_max": "4.3",
            "eos_date": "2017-12-01",
            "eol_date": "2018-06-01",
            "is_deprecated": False,
            "maintenance_status": "unmaintained",
        }
    ],
}


def parse_clean_version(version_str: str | None) -> Version | None:
    """Clean and parse non-standard version strings into Version objects."""
    if not version_str or version_str.upper() == "UNKNOWN":
        return None
    # Replace commas with dots, remove extra letters
    cleaned = version_str.replace(",", ".").replace(" ", "").strip()
    try:
        return Version(cleaned)
    except InvalidVersion:
        # Fallback: keep only numbers and dots
        numeric_parts = []
        for char in cleaned:
            if char.isdigit() or char == ".":
                numeric_parts.append(char)
        numeric_str = "".join(numeric_parts).strip(".")
        try:
            return Version(numeric_str) if numeric_str else None
        except InvalidVersion:
            return None


def analyze_component_lifecycle(name: str, version_str: str | None) -> dict[str, Any]:
    """
    Match component coordinates against the reference lifecycle catalog.
    
    Returns:
        A dict with keys:
            - lifecycle_status: "eol" | "eos" | "active" | "deprecated" | "unsupported"
            - eos_date: str (YYYY-MM-DD) or None
            - eol_date: str (YYYY-MM-DD) or None
            - is_deprecated: bool
            - maintenance_status: "active" | "unmaintained"
    """
    default_res = {
        "lifecycle_status": "active",
        "eos_date": None,
        "eol_date": None,
        "is_deprecated": False,
        "maintenance_status": "active",
    }
    
    if not name:
        return default_res
        
    normalized_name = name.strip().lower()
    
    # Try finding the package in our catalog
    rules = LIFECYCLE_CATALOG.get(normalized_name)
    if not rules:
        return default_res
        
    comp_ver = parse_clean_version(version_str)
    
    for rule in rules:
        rule_max_ver = Version(rule["version_max"])
        
        # Match condition: if component version is unknown, we assume it matches the rule.
        # Otherwise, check if comp_ver <= rule_max_ver.
        matches = False
        if comp_ver is None:
            matches = True
        else:
            matches = comp_ver <= rule_max_ver
            
        if matches:
            eol_date_str = rule.get("eol_date")
            eos_date_str = rule.get("eos_date")
            is_dep = rule.get("is_deprecated", False)
            maint = rule.get("maintenance_status", "active")
            
            # Determine lifecycle status based on current date
            today_str = datetime.now(UTC).date().isoformat()
            
            status = "active"
            if is_dep:
                status = "deprecated"
            elif maint == "unmaintained":
                status = "unsupported"
                
            if eol_date_str and today_str >= eol_date_str:
                status = "eol"
            elif eos_date_str and today_str >= eos_date_str:
                status = "eos"
                
            return {
                "lifecycle_status": status,
                "eos_date": eos_date_str,
                "eol_date": eol_date_str,
                "is_deprecated": is_dep,
                "maintenance_status": maint,
            }
            
    return default_res


def sync_lifecycle_for_sbom(db: Session, sbom_id: int) -> None:
    """
    Perform lifecycle analysis for all components of a specific SBOM version and persist the findings.
    """
    components = db.execute(
        select(SBOMComponent).where(SBOMComponent.sbom_id == sbom_id)
    ).scalars().all()
    
    for comp in components:
        # Respect existing lifecycle status (e.g. manual overrides or carried-forward overrides)
        if comp.lifecycle_status is not None and comp.lifecycle_status.strip() != "":
            continue

        # Run analysis
        info = analyze_component_lifecycle(comp.name, comp.version)
        
        # Persist values onto the component row
        comp.lifecycle_status = info["lifecycle_status"]
        comp.eos_date = info["eos_date"]
        comp.eol_date = info["eol_date"]
        comp.is_deprecated = info["is_deprecated"]
        comp.maintenance_status = info["maintenance_status"]
        db.add(comp)
        
    db.commit()
