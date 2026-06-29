"""Package URL normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from .version_normalizer import normalize_version

try:  # pragma: no cover - exercised in integration tests when installed.
    from packageurl import PackageURL
except ModuleNotFoundError:  # pragma: no cover
    PackageURL = None  # type: ignore[assignment]


LOWERCASE_NAMESPACE_TYPES = {"bitbucket", "deb", "github", "golang", "maven", "npm", "pypi"}
LOWERCASE_NAME_TYPES = {"apk", "bitbucket", "deb", "github", "golang", "gem", "maven", "npm", "nuget", "pypi", "rpm"}


@dataclass(slots=True)
class PurlNormalizationResult:
    original_purl: str | None
    normalized_purl: str | None
    valid: bool
    purl_type: str | None = None
    namespace: str | None = None
    name: str | None = None
    version: str | None = None
    qualifiers: dict[str, str] = field(default_factory=dict)
    subpath: str | None = None
    notes: list[str] = field(default_factory=list)


def normalize_purl(value: Any, *, fallback_version: str | None = None) -> PurlNormalizationResult:
    raw = str(value).strip() if value is not None else ""
    if not raw:
        return PurlNormalizationResult(None, None, False, notes=["missing_purl"])
    if PackageURL is None:
        return _fallback_parse(raw, fallback_version=fallback_version)
    try:
        parsed = PackageURL.from_string(raw)
    except Exception:
        return PurlNormalizationResult(raw, None, False, notes=["invalid_purl"])

    ptype = (parsed.type or "").strip().lower()
    namespace = _clean_part(parsed.namespace)
    name = _clean_part(parsed.name)
    version = normalize_version(parsed.version or fallback_version, ecosystem=ptype).normalized_version
    if namespace and ptype in LOWERCASE_NAMESPACE_TYPES:
        namespace = namespace.lower()
    if name and ptype in LOWERCASE_NAME_TYPES:
        name = name.lower()
    qualifiers = {
        str(k).strip().lower(): str(v).strip()
        for k, v in (parsed.qualifiers or {}).items()
        if str(k).strip() and str(v).strip()
    }
    qualifiers = dict(sorted(qualifiers.items()))
    normalized = PackageURL(
        type=ptype,
        namespace=namespace,
        name=name,
        version=version,
        qualifiers=qualifiers or None,
        subpath=_clean_part(parsed.subpath),
    ).to_string()
    notes = []
    if normalized != raw:
        notes.append("normalized_purl")
    return PurlNormalizationResult(
        original_purl=raw,
        normalized_purl=normalized,
        valid=True,
        purl_type=ptype,
        namespace=namespace,
        name=name,
        version=version,
        qualifiers=qualifiers,
        subpath=_clean_part(parsed.subpath),
        notes=notes,
    )


def _clean_part(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = unquote(str(value).strip())
    return cleaned or None


def _fallback_parse(raw: str, *, fallback_version: str | None) -> PurlNormalizationResult:
    if not raw.startswith("pkg:") or "/" not in raw[4:]:
        return PurlNormalizationResult(raw, None, False, notes=["invalid_purl"])
    body, _, subpath = raw[4:].partition("#")
    body, _, query = body.partition("?")
    ptype, _, rest = body.partition("/")
    path, at, version = rest.rpartition("@")
    if not at:
        path = rest
        version = fallback_version or ""
    parts = [_clean_part(part) for part in path.split("/") if part]
    if not ptype or not parts:
        return PurlNormalizationResult(raw, None, False, notes=["invalid_purl"])
    name = parts[-1]
    namespace = "/".join(part for part in parts[:-1] if part) or None
    qualifiers: dict[str, str] = {}
    for item in query.split("&") if query else []:
        key, _, qvalue = item.partition("=")
        if key.strip() and qvalue.strip():
            qualifiers[key.strip().lower()] = qvalue.strip()
    ptype = ptype.lower()
    version = normalize_version(version, ecosystem=ptype).normalized_version
    normalized = f"pkg:{ptype}/"
    if namespace:
        normalized += f"{namespace.lower() if ptype in LOWERCASE_NAMESPACE_TYPES else namespace}/"
    normalized += name.lower() if ptype in LOWERCASE_NAME_TYPES and name else name or ""
    if version:
        normalized += f"@{version}"
    if qualifiers:
        normalized += "?" + "&".join(f"{k}={qualifiers[k]}" for k in sorted(qualifiers))
    if subpath:
        normalized += f"#{subpath}"
    return PurlNormalizationResult(raw, normalized, True, ptype, namespace, name, version, qualifiers, subpath or None)
