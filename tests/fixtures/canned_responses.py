"""
Canned external API payloads used by every snapshot test.

These shapes are deliberately small but realistic — they exercise the same
extractor branches that the production source fetchers exercise. Keeping them
in one module means that all snapshot tests see the same input, so any drift
between the legacy `vuln_sources.py` path and the future `services/sources/`
adapters can be diffed deterministically.
"""

from __future__ import annotations

from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# NVD — REST 2.0 shape used by `vuln_sources.nvd_fetch`
# ---------------------------------------------------------------------------
NVD_LOG4J_RESPONSE: Dict[str, Any] = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:00.000",
                "lastModified": "2024-01-01T00:00:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 6.0,
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [{"lang": "en", "value": "CWE-502"}],
                    }
                ],
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html"}
                ],
            }
        }
    ],
}

NVD_EMPTY_RESPONSE: Dict[str, Any] = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": [],
}


# ---------------------------------------------------------------------------
# GitHub Security Advisories — GraphQL shape returned by `github_fetch_advisories`
# ---------------------------------------------------------------------------
GHSA_LOG4J_RESPONSE: Dict[str, Any] = {
    "data": {
        "securityVulnerabilities": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [
                {
                    "severity": "CRITICAL",
                    "updatedAt": "2021-12-10T00:00:00Z",
                    "vulnerableVersionRange": "< 2.15.0",
                    "firstPatchedVersion": {"identifier": "2.15.0"},
                    "package": {
                        "name": "org.apache.logging.log4j:log4j-core",
                        "ecosystem": "MAVEN",
                    },
                    "advisory": {
                        "ghsaId": "GHSA-jfh8-c2jp-5v3q",
                        "summary": "Remote code execution in Log4j 2.x",
                        "description": "Log4j JNDI lookup feature allows remote code execution.",
                        "publishedAt": "2021-12-10T00:00:00Z",
                        "references": [
                            {"url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"}
                        ],
                        "cvss": {
                            "score": 10.0,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        },
                        "cwes": {"nodes": [{"cweId": "CWE-502", "name": "Deserialization"}]},
                    },
                }
            ],
        }
    }
}

GHSA_EMPTY_RESPONSE: Dict[str, Any] = {
    "data": {
        "securityVulnerabilities": {
            "pageInfo": {"hasNextPage": False, "endCursor": None},
            "nodes": [],
        }
    }
}


# ---------------------------------------------------------------------------
# OSV — batch + single-vuln shapes used by `osv_querybatch` / `osv_get_vuln_by_id`
# ---------------------------------------------------------------------------
OSV_BATCH_RESPONSE: List[Dict[str, Any]] = [
    {
        "vulns": [
            {"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2024-01-01T00:00:00Z"}
        ]
    },
    {
        "vulns": [
            {"id": "PYSEC-2018-28", "modified": "2024-01-01T00:00:00Z"}
        ]
    },
]

OSV_VULN_DETAIL: Dict[str, Dict[str, Any]] = {
    "GHSA-jfh8-c2jp-5v3q": {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "summary": "Remote code execution in Log4j 2.x",
        "details": "Log4j JNDI lookup feature allows remote code execution.",
        "aliases": ["CVE-2021-44228"],
        "modified": "2024-01-01T00:00:00Z",
        "published": "2021-12-10T00:00:00Z",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
        ],
        "affected": [
            {
                "package": {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.15.0"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "WEB", "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"}
        ],
    },
    "PYSEC-2018-28": {
        "id": "PYSEC-2018-28",
        "summary": "requests vulnerability in 2.19.0",
        "details": "requests <= 2.19.0 leaks Authorization headers on redirect.",
        "aliases": ["CVE-2018-18074"],
        "modified": "2024-01-01T00:00:00Z",
        "published": "2018-10-09T00:00:00Z",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            }
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.20.0"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-18074"}
        ],
    },
}


# ---------------------------------------------------------------------------
# Pre-shaped finding lists for `app.analysis.*_query_by_components` mocks.
#
# These match the dict shape that the real coroutines return: a 3-tuple of
# (findings, query_errors, query_warnings). They are intentionally tiny —
# the goal is to lock the orchestration / persistence path, not to test the
# extractors (which the legacy `vuln_sources` path covers via canned HTTP).
# ---------------------------------------------------------------------------
ASYNC_NVD_FINDING: Dict[str, Any] = {
    "vuln_id": "CVE-2021-44228",
    "aliases": ["CVE-2021-44228"],
    "sources": ["NVD"],
    "description": "Apache Log4j2 JNDI features used in configuration ...",
    "severity": "CRITICAL",
    "score": 10.0,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "attack_vector": "NETWORK",
    "cvss_version": "3.1",
    "published": "2021-12-10T10:15:00.000",
    "references": ["https://logging.apache.org/log4j/2.x/security.html"],
    "cwe": ["CWE-502"],
    "fixed_versions": ["2.15.0"],
    "component_name": "log4j-core",
    "component_version": "2.14.1",
    "cpe": "cpe:2.3:a:log4j-core:log4j-core:2.14.1:*:*:*:*:*:*:*",
}

ASYNC_OSV_FINDING_REQUESTS: Dict[str, Any] = {
    "vuln_id": "PYSEC-2018-28",
    "aliases": ["CVE-2018-18074", "PYSEC-2018-28"],
    "sources": ["OSV"],
    "description": "requests <= 2.19.0 leaks Authorization headers on redirect.",
    "severity": "HIGH",
    "score": 7.5,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "attack_vector": "NETWORK",
    "cvss_version": "3.1",
    "published": "2018-10-09T00:00:00Z",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2018-18074"],
    "cwe": [],
    "fixed_versions": ["2.20.0"],
    "component_name": "requests",
    "component_version": "2.19.0",
    "cpe": None,
}

ASYNC_GHSA_FINDING: Dict[str, Any] = {
    "vuln_id": "GHSA-jfh8-c2jp-5v3q",
    "aliases": ["GHSA-jfh8-c2jp-5v3q"],
    "sources": ["GITHUB"],
    "description": "Remote code execution in Log4j 2.x",
    "severity": "CRITICAL",
    "score": 10.0,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "attack_vector": "NETWORK",
    "cvss_version": None,
    "published": "2021-12-10T00:00:00Z",
    "references": ["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"],
    "cwe": ["CWE-502"],
    "fixed_versions": ["2.15.0"],
    "component_name": "log4j-core",
    "component_version": "2.14.1",
    "cpe": None,
}
