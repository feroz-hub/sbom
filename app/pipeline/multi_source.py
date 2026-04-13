"""
Multi-source SBOM analysis pipeline (async).

Orchestrates parse → enrich → concurrent source queries → dedupe → summary.
Implementation extracted from ``app.analysis`` for clarity and testing.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..parsing import extract_components
from ..sources.dedupe import deduplicate_findings


async def run_multi_source_analysis_async(
    sbom_json: str,
    sources: list[str] | None = None,
    settings: Any | None = None,
) -> dict:
    """
    Asynchronously analyze an SBOM against the selected sources.

    sources: ["NVD","OSV","GITHUB"]; if None, read env ANALYSIS_SOURCES or default ["NVD"].
    Returns a normalized dict compatible with the existing API.
    """
    # Late import: ``analysis`` must be fully initialized (this module is loaded from it).
    from ..analysis import (
        LOGGER,
        AnalysisSource,
        _augment_components_with_cpe,
        _env_list,
        _executor,
        _finding_from_raw,
        enrich_component_for_osv,
        get_analysis_settings_multi,
        github_query_by_components,
        nvd_query_by_cpe,
        osv_query_by_components,
        resolve_nvd_api_key,
    )

    cfg = settings or get_analysis_settings_multi()
    components = extract_components(sbom_json)
    LOGGER.debug("Extracted %d components from SBOM", len(components))

    components = [enrich_component_for_osv(c) for c in components]
    components_w_cpe, generated_cpe_count = _augment_components_with_cpe(components)
    LOGGER.debug(
        "CPE augmentation: %d components total, %d CPEs generated",
        len(components_w_cpe),
        generated_cpe_count,
    )

    default_sources = _env_list(cfg.analysis_sources_env, ["NVD"])
    selected = [s.strip().upper() for s in (sources or default_sources)]
    selected_enum: set[AnalysisSource] = set()
    for s in selected:
        try:
            selected_enum.add(AnalysisSource[s])
        except KeyError:
            LOGGER.warning("Unknown analysis source ignored: %s", s)

    if not any(c.get("cpe") for c in components_w_cpe):
        if AnalysisSource.NVD in selected_enum:
            LOGGER.info("Skipping NVD: no CPEs found in any component")
            selected_enum.remove(AnalysisSource.NVD)

    LOGGER.info(
        "Starting multi-source analysis: sources=%s components=%d",
        [s.name for s in selected_enum],
        len(components_w_cpe),
    )

    all_findings: list[dict] = []
    query_errors: list[dict] = []
    query_warnings: list[dict] = []

    async def _nvd() -> None:
        nonlocal all_findings, query_errors
        cpe_set: set[str] = set()
        name_by_cpe: dict[str, tuple[str, str | None]] = {}
        for comp in components_w_cpe:
            cpe = comp.get("cpe")
            if cpe:
                cpe_set.add(cpe)
                name_by_cpe[cpe] = (comp.get("name") or "", comp.get("version"))
        if not cpe_set:
            LOGGER.debug("NVD: no CPEs to query — skipping")
            return
        LOGGER.debug("NVD: querying %d unique CPEs concurrently", len(cpe_set))
        loop = asyncio.get_running_loop()

        def _fetch_one(cpe: str) -> tuple[str, list[dict], str | None]:
            LOGGER.debug("NVD: fetching CPE '%s'", cpe)
            try:
                cve_objs = nvd_query_by_cpe(cpe, resolve_nvd_api_key(cfg), settings=cfg)
                LOGGER.debug("NVD: CPE '%s' → %d CVEs", cpe, len(cve_objs))
                return cpe, cve_objs, None
            except Exception as exc:
                LOGGER.warning("NVD: CPE '%s' query failed: %s", cpe, exc)
                return cpe, [], str(exc)

        _nvd_sem = asyncio.Semaphore(cfg.max_concurrency)

        async def _bounded_fetch(cpe: str):
            async with _nvd_sem:
                return await loop.run_in_executor(_executor, _fetch_one, cpe)

        tasks = [_bounded_fetch(cpe) for cpe in sorted(cpe_set)]
        results = await asyncio.gather(*tasks)
        nvd_findings = 0
        for cpe, raw_list, err in results:
            if err:
                query_errors.append({"source": "NVD", "cpe": cpe, "error": err})
                continue
            comp_name, comp_ver = name_by_cpe.get(cpe, ("", None))
            for raw in raw_list:
                if not isinstance(raw, dict):
                    continue
                all_findings.append(
                    _finding_from_raw(
                        raw=raw,
                        cpe=cpe,
                        component_name=comp_name,
                        component_version=comp_ver,
                        settings=cfg,
                    )
                )
                nvd_findings += 1
        LOGGER.info(
            "NVD complete: %d findings from %d CPEs (%d errors)",
            nvd_findings,
            len(cpe_set),
            len(query_errors),
        )

    async def _osv() -> None:
        nonlocal all_findings, query_errors, query_warnings
        LOGGER.debug("OSV: querying %d components", len(components))
        f, e, w = await osv_query_by_components(components, cfg)
        LOGGER.info("OSV complete: %d findings, %d errors, %d warnings", len(f), len(e), len(w))
        all_findings.extend(f)
        query_errors.extend(e)
        query_warnings.extend(w)

    async def _gh() -> None:
        nonlocal all_findings, query_errors
        LOGGER.debug("GitHub: querying %d components", len(components))
        f, e, _w = await github_query_by_components(components, cfg)
        LOGGER.info("GitHub complete: %d findings, %d errors", len(f), len(e))
        all_findings.extend(f)
        query_errors.extend(e)

    coros = []
    if AnalysisSource.NVD in selected_enum:
        coros.append(_nvd())
    if AnalysisSource.OSV in selected_enum:
        coros.append(_osv())
    if AnalysisSource.GITHUB in selected_enum:
        coros.append(_gh())
    if coros:
        await asyncio.gather(*coros)

    findings = deduplicate_findings(all_findings)
    LOGGER.debug(
        "Deduplication: %d raw findings → %d unique findings",
        len(all_findings),
        len(findings),
    )

    buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for f in findings:
        sev = str((f or {}).get("severity", "UNKNOWN")).upper()
        buckets[sev if sev in buckets else "UNKNOWN"] += 1

    LOGGER.info(
        "Multi-source analysis summary: total=%d  CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d UNKNOWN=%d  errors=%d",
        len(findings),
        buckets["CRITICAL"],
        buckets["HIGH"],
        buckets["MEDIUM"],
        buckets["LOW"],
        buckets["UNKNOWN"],
        len(query_errors),
    )

    details: dict[str, Any] = {
        "total_components": len(components),
        "components_with_cpe": len({c.get("cpe") for c in components_w_cpe if c.get("cpe")}),
        "total_findings": len(findings),
        "critical": buckets["CRITICAL"],
        "high": buckets["HIGH"],
        "medium": buckets["MEDIUM"],
        "low": buckets["LOW"],
        "unknown": buckets["UNKNOWN"],
        "query_errors": query_errors,
        "query_warnings": query_warnings,
        "findings": findings,
        "analysis_metadata": {
            "sources": sorted([s.value for s in selected_enum]),
            "generated_cpe_count": generated_cpe_count,
            "nvd_api_base_url": getattr(cfg, "nvd_api_base_url", None),
            "osv_api_base_url": getattr(cfg, "osv_api_base_url", None),
            "gh_graphql_url": getattr(cfg, "gh_graphql_url", None),
        },
    }
    if generated_cpe_count > 0:
        details["note"] = f"Generated {generated_cpe_count} CPEs from package URLs to enable NVD correlation."
    if AnalysisSource.NVD in selected_enum and details["components_with_cpe"] == 0:
        details["message"] = "No CPE values could be generated; NVD correlation not executed."
    return details
