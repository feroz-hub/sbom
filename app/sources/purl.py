"""
PURL (package URL) parsing helpers.

Canonical extraction from ``app/analysis.py`` (the production multi-source
path). ``app/services/vuln_sources.py`` historically carried a near-duplicate
``_parse_purl``; that copy will be removed when Phase 4 cuts over the legacy
``/analyze-sbom-*`` endpoints.

Keep this module dependency-free — no settings, no logging, no HTTP. It is
imported by every source adapter.
"""

from __future__ import annotations

from typing import Dict
from urllib.parse import parse_qs, unquote


def parse_purl(purl: str) -> dict:
    """
    Minimal purl parser per spec:
      pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>

    Subpath is ignored. Namespace and name are percent-decoded. Returns
    an empty dict for any input that does not look like a purl, so the
    caller can use a single ``if not parsed`` guard.
    """
    if not purl or not purl.startswith("pkg:"):
        return {}
    rest = purl[4:]

    # Remove subpath if present
    if "#" in rest:
        rest, _sub = rest.split("#", 1)

    # Split query
    qualifiers: Dict[str, str] = {}
    if "?" in rest:
        rest, q = rest.split("?", 1)
        qualifiers = {k: v[0] for k, v in parse_qs(q, keep_blank_values=True).items()}

    # Separate version (last '@' is the version separator)
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version) if version else None
    parts = rest.split("/")
    if len(parts) < 2:
        return {}

    ptype = parts[0].lower()
    if len(parts) == 2:
        namespace = None
        name = unquote(parts[1])
    else:
        namespace = unquote("/".join(parts[1:-1])) if len(parts) > 2 else None
        name = unquote(parts[-1])

    return {
        "type": ptype,
        "namespace": namespace,
        "name": name,
        "version": version,
        "qualifiers": qualifiers,
    }
