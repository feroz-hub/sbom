"""Truthful provider verification, separate from lifecycle coverage."""

from .provider_http import RequestPolicy, policy_context, request_json
from .types import UNKNOWN, NormalizedComponent


def run_probe(snapshot, db=None):
    from ...settings import get_settings
    from .endoflife_date_provider import _extract_cycles, _match_cycle
    from .openeox_provider import _parse_openeox_payload
    from .provider_capabilities import provider_capabilities
    from .provider_registry import LifecycleProviderRegistry
    from .secret_service import LifecycleProviderSecretService
    from .xeol_db_provider import XeolDbProvider, _load_xeol_db, validate_xeol_db_path
    from .xeol_provider import _parse_xeol_result

    key = snapshot.provider_key
    capabilities = provider_capabilities(key)
    details = dict(
        probe_type="network" if capabilities["network"] else "local_verification",
        configuration_valid=True,
        connection_verified=False,
        authentication_verified=None,
        response_valid=False,
        sample_matched=False,
        lifecycle_evidence_found=False,
        http_status=None,
        error_code=None,
        real_provider_call=False,
    )
    sample = {"name": "debian", "version": "12", "ecosystem": "generic"}
    policy = RequestPolicy(timeout=snapshot.timeout_seconds, retries=snapshot.max_retries)
    token = policy_context.set(policy)
    headers = None
    success, message = False, "Provider verification failed."
    try:
        if not capabilities["implemented"]:
            details.update(probe_type="unsupported", configuration_valid=False, error_code="unimplemented")
            message = capabilities["coverage"]
        elif key == "xeol_db":
            success, message, evidence = validate_xeol_db_path(str(snapshot.config.get("db_path") or ""))
            details.update(response_valid=success, configuration_valid=success)
            if success:
                provider = XeolDbProvider(db_path=str(snapshot.config.get("db_path")))
                records = _load_xeol_db(provider.db_path)
                if records:
                    record = records[0]
                    sample = {
                        "name": str(record.get("name") or record.get("component") or ""),
                        "version": str(record.get("version") or ""),
                        "ecosystem": str(record.get("ecosystem") or "generic"),
                    }
                    result = provider.lookup(
                        NormalizedComponent(
                            component_id=None,
                            **sample,
                            normalized_name=sample["name"],
                            normalized_version=sample["version"],
                        )
                    )
                    details.update(
                        sample_matched=bool(sample["name"]),
                        lifecycle_evidence_found=result.lifecycle_status != UNKNOWN,
                        sample_evidence={"format": evidence.get("format"), "status": result.lifecycle_status},
                    )
                else:
                    success = False
                    message = "Database format is valid but no representative record is readable."
        elif key in {"redhat_lifecycle", "custom_vendor_records"}:
            registry = LifecycleProviderRegistry()
            provider = registry._provider_from_snapshot(db, get_settings(), snapshot)
            if key == "redhat_lifecycle":
                sample = {"name": "rhel", "version": "8", "ecosystem": "generic"}
            elif provider and provider.records:
                record = provider.records[0]
                sample = {
                    "name": record.get("name", ""),
                    "version": record.get("version") or "",
                    "ecosystem": record.get("ecosystem", "generic"),
                }
            result = (
                provider.lookup(
                    NormalizedComponent(
                        component_id=None,
                        **sample,
                        normalized_name=sample["name"],
                        normalized_version=sample["version"],
                    )
                )
                if provider
                else None
            )
            success = result is not None and result.lifecycle_status != UNKNOWN
            details.update(
                response_valid=provider is not None,
                sample_matched=success,
                lifecycle_evidence_found=success,
                sample_evidence={"status": result.lifecycle_status, "source": result.source_url} if result else None,
            )
            message = (
                "Static reference verified locally; vendor freshness is unverified."
                if key == "redhat_lifecycle"
                else "Active custom records checked using runtime matching."
                if success
                else "No representative active custom record matched."
            )
        else:
            sample = {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"}
            method, payload, headers = "GET", None, None
            if key == "endoflife_date":
                from .provider_config_service import _endoflife_probe_urls

                urls = list(_endoflife_probe_urls(snapshot.base_url))
                sample = {"name": "debian", "version": "12", "ecosystem": "generic"}
            elif key == "deps_dev":
                urls = ["https://api.deps.dev/v3/systems/PYPI/packages/requests/versions/2.31.0"]
            elif key == "osv":
                urls = ["https://api.osv.dev/v1/query"]
                method, payload = "POST", {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"}
            elif key == "package_registry":
                urls = ["https://pypi.org/pypi/requests/2.31.0/json"]
            elif key == "repository_health":
                urls = ["https://api.github.com/repos/python/cpython"]
                secret = (
                    LifecycleProviderSecretService(tenant_id=snapshot.tenant_id).get_secret(db, key, "github_token")
                    if db
                    else None
                )
                headers = {"Authorization": f"Bearer {secret}"} if secret else None
                sample = {"repository": "python/cpython"}
            elif key == "xeol_api":
                urls = [snapshot.base_url or capabilities["effective_endpoint"]]
                secret = (
                    LifecycleProviderSecretService(tenant_id=snapshot.tenant_id).get_secret(db, key, "api_key")
                    if db
                    else None
                )
                if not secret and snapshot.tenant_id is None:
                    secret = get_settings().lifecycle_xeol_api_key
                headers = {"Authorization": f"Bearer {secret}"} if secret else None
                sample = {"name": "debian", "version": "12", "ecosystem": "generic"}
                method, payload = "POST", {"component": sample}
            else:
                urls = snapshot.feed_urls
            if not urls:
                raise ValueError("missing_source")
            feeds = []
            for url in urls:
                try:
                    data = request_json(method, url, payload=payload, headers=headers)
                    valid, matched, evidence = False, False, False
                    if key == "endoflife_date":
                        cycles = _extract_cycles(data)
                        valid = bool(cycles) and all(
                            isinstance(row.get("cycle") or row.get("name"), (str, int, float)) for row in cycles
                        )
                        cycle = _match_cycle(cycles, "12") if cycles else None
                        if cycle:
                            details["sample_evidence"] = {
                                k: cycle[k]
                                for k in ("cycle", "name", "eol", "eolFrom", "support", "eoasFrom", "isEol")
                                if k in cycle
                            }
                        matched = cycle is not None
                        from .endoflife_date_provider import EndOfLifeDateProvider

                        parsed_result = EndOfLifeDateProvider(http_get=lambda _url, payload=data: payload).lookup(
                            NormalizedComponent(
                                component_id=None,
                                **sample,
                                normalized_name=sample["name"],
                                normalized_version=sample["version"],
                            )
                        )
                        evidence = parsed_result.lifecycle_status != UNKNOWN

                    elif key == "deps_dev":
                        valid = isinstance(data, dict) and isinstance(data.get("versionKey"), dict)
                        matched = valid and data["versionKey"].get("version") == "2.31.0"
                        evidence = bool(valid and (data.get("isDeprecated") or data.get("deprecated")))
                    elif key == "osv":
                        valid = isinstance(data, dict) and isinstance(data.get("vulns", []), list)
                        matched = bool(data and data.get("vulns"))
                    elif key == "package_registry":
                        valid = isinstance(data, dict) and isinstance(data.get("info"), dict)
                        matched = valid and data["info"].get("version") == "2.31.0"
                        evidence = bool(valid and data["info"].get("yanked"))
                    elif key == "repository_health":
                        valid = (
                            isinstance(data, dict)
                            and isinstance(data.get("archived"), bool)
                            and isinstance(data.get("full_name"), str)
                        )
                        matched = valid
                        evidence = bool(valid and (data.get("archived") or data.get("disabled")))
                    elif key == "xeol_api":
                        body = data.get("result", data) if isinstance(data, dict) else None
                        valid = (
                            isinstance(body, dict)
                            and not body.get("error")
                            and any(k in body for k in ("match", "eol", "componentName", "entity", "version"))
                        )
                        parsed = _parse_xeol_result(body) if valid else None
                        matched = bool(parsed and parsed["matched"])
                        evidence = bool(parsed and parsed["status"] != UNKNOWN)
                    elif key == "openeox":
                        records = _parse_openeox_payload(data)
                        valid = bool(records) and all(
                            any(row.get(k) for k in ("name", "product", "component"))
                            and any(
                                k in row
                                for k in (
                                    "status",
                                    "phase",
                                    "lifecycle_status",
                                    "eol",
                                    "eol_date",
                                    "eos_date",
                                    "eof_date",
                                )
                            )
                            for row in records
                        )
                        matched = False  # Feed validation is not a component lookup.
                        evidence = False
                    feeds.append(
                        {"response_valid": valid, "sample_matched": matched, "lifecycle_evidence_found": evidence}
                    )
                    if key == "endoflife_date" and valid:
                        break
                except Exception:
                    feeds.append({"response_valid": False, "sample_matched": False, "lifecycle_evidence_found": False})
            # A partial feed failure is degraded, even if other feeds are valid.
            success = bool(feeds) and (
                any(f["response_valid"] for f in feeds)
                if key == "endoflife_date"
                else all(f["response_valid"] for f in feeds)
            )
            details.update(
                response_valid=success,
                sample_matched=any(f["sample_matched"] for f in feeds),
                lifecycle_evidence_found=any(f["lifecycle_evidence_found"] for f in feeds),
                feeds=feeds,
            )
            message = (
                "Provider response verified; lifecycle coverage is reported separately."
                if success
                else "Provider response unavailable, incomplete or invalid."
            )
    except Exception as exc:
        details["error_code"] = (
            str(exc) if isinstance(exc, ValueError) and str(exc) == "missing_source" else "verification_failed"
        )
        message = "Provider verification failed; check configuration and connectivity."
    finally:
        policy_context.reset(token)
    details["real_provider_call"] = policy.attempts > 0
    details["connection_verified"] = bool(policy.calls)
    details["http_status"] = policy.calls[-1]["http_status"] if policy.calls else None
    if details["http_status"] in {401, 403}:
        details["authentication_verified"] = False
    elif capabilities["secret_name"] and details["response_valid"] and headers:
        details["authentication_verified"] = True
    if policy.errors:
        details["error_code"] = policy.errors[-1]
        if policy.errors[-1] in {
            "unsafe_endpoint",
            "destination_not_allowlisted",
            "blocked_destination",
            "blocked_port",
        }:
            details["configuration_valid"] = False
    elif not success and details["error_code"] is None:
        details["error_code"] = "invalid_response" if policy.calls else "no_matching_evidence"
    details["sample_component"] = sample
    return success, message, details
