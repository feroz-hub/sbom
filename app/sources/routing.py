"""Shared vulnerability-source routing and outcome helpers."""

from __future__ import annotations

from typing import Any, Literal

ProviderOutcome = Literal["MATCH", "NO_MATCH", "SKIPPED", "ERROR"]

AUTHORITATIVE_CPE_SOURCES = frozenset(
    {"sbom_provided", "official_nvd_cpe", "manual_verified", "trusted_mapping"}
)
NON_QUERYABLE_COMPONENT_TYPES = frozenset({"file", "application", "root"})
PLACEHOLDER_COMPONENT_NAMES = frozenset({"package.json", "requirements.txt"})
NON_ERROR_REASONS = frozenset(
    {
        "unsupported_ecosystem",
        "missing_cpe",
        "missing_authoritative_cpe",
        "missing_authoritative_mapping",
        "missing_credentials",
        "no_match",
        "skipped",
        "disabled",
        "not_queryable_component",
    }
)


def is_authoritative_cpe(component: dict[str, Any]) -> bool:
    cpe = str(component.get("cpe") or "").strip()
    if not cpe.lower().startswith("cpe:2.3:"):
        return False
    source = str(component.get("cpe_source") or "").strip().lower()
    return source in AUTHORITATIVE_CPE_SOURCES


def count_authoritative_cpes(components: list[dict[str, Any]]) -> int:
    return len({str(component.get("cpe")).strip() for component in components if is_authoritative_cpe(component)})


def component_skip_reason(component: dict[str, Any]) -> str | None:
    ctype = str(component.get("type") or component.get("component_type") or "").strip().lower()
    if ctype in NON_QUERYABLE_COMPONENT_TYPES:
        return "not_queryable_component"

    name = str(component.get("name") or "").strip()
    if not name:
        return "missing_name"
    if name.lower().split("/")[-1] in PLACEHOLDER_COMPONENT_NAMES:
        return "placeholder_component"
    if not str(component.get("version") or "").strip():
        return "missing_version"
    return None


def queryable_components(components: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    queryable: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for component in components:
        item = dict(component or {})
        reason = component_skip_reason(item)
        if reason:
            skipped.append(
                {
                    "outcome": "SKIPPED",
                    "reason": reason,
                    "component": item.get("bom_ref") or item.get("purl") or item.get("name"),
                    "component_name": item.get("name"),
                    "component_version": item.get("version"),
                }
            )
        else:
            queryable.append(item)
    return queryable, skipped


def provider_error_type(error: dict[str, Any]) -> str:
    explicit = str(error.get("error_type") or "").strip()
    if explicit:
        return explicit
    status = error.get("status") or error.get("http_status")
    try:
        status_int = int(status)
    except (TypeError, ValueError):
        status_int = None
    if status_int == 429:
        return "rate_limited"
    if status_int is not None and status_int >= 500:
        return "provider_5xx"
    message = str(error.get("message") or error.get("error") or "").lower()
    if "timeout" in message or "timed out" in message:
        return "timeout"
    if "429" in message or "rate limit" in message:
        return "rate_limited"
    if "401" in message or "403" in message or "auth" in message:
        return "authentication_failure"
    if "parse" in message or "json" in message:
        return "response_parse_failure"
    if "network" in message or "connection" in message or "ssl" in message:
        return "network_failure"
    return "provider_exception"


def is_genuine_provider_error(error: dict[str, Any]) -> bool:
    outcome = str(error.get("outcome") or "").strip().upper()
    if outcome and outcome != "ERROR":
        return False
    reason = str(error.get("reason") or "").strip().lower()
    if reason in NON_ERROR_REASONS:
        return False
    return True


def normalize_query_errors(errors: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for raw in errors or []:
        if not isinstance(raw, dict) or not is_genuine_provider_error(raw):
            continue
        item = dict(raw)
        item["outcome"] = "ERROR"
        item["error_type"] = provider_error_type(item)
        message = str(item.get("message") or item.get("error") or item.get("reason") or "").strip()
        if not message:
            message = item["error_type"]
        item.setdefault("message", message)
        source = str(item.get("source") or "UNKNOWN").upper()
        component_id = str(
            item.get("component_id")
            or item.get("component")
            or item.get("component_name")
            or item.get("identifier")
            or item.get("package")
            or ""
        )
        key = (source, component_id, item["error_type"], message)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    return normalized


def finding_sources(finding: dict[str, Any]) -> set[str]:
    raw = finding.get("sources") or finding.get("source")
    if isinstance(raw, list):
        return {str(value).strip().upper() for value in raw if str(value).strip()}
    if isinstance(raw, str):
        return {value.strip().upper() for value in raw.split(",") if value.strip()}
    return set()


def summarize_source(
    source: str,
    *,
    queried: int,
    matched: int,
    skipped: int,
    errors: int,
    status: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    no_match = max(int(queried) - int(matched) - int(errors), 0)
    return {
        "source": source.upper(),
        "queried": int(queried),
        "matched": int(matched),
        "no_match": no_match,
        "skipped": int(skipped),
        "errors": int(errors),
        "status": status or ("error" if errors else "complete"),
        **({"reason": reason} if reason else {}),
    }
