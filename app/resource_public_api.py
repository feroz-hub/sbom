"""Explicit wire ownership for Membership, Platform Grant and Analysis Run.

Worker/database identifiers and unrelated provider/event/assignment IDs remain
integers. Called by the authenticated public boundary, never by persistence.
"""

from fastapi import HTTPException
from sqlalchemy import select

from .models import AnalysisRun, PlatformUserRole, TenantUser

UUID4_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"


def valid_selector(value):
    import re

    return isinstance(value, str) and re.fullmatch(UUID4_PATTERN, value) is not None


MODELS = {"tenant_users": TenantUser, "platform_user_roles": PlatformUserRole, "analysis_run": AnalysisRun}
RUN_FIELDS = frozenset(
    {
        "run_id",
        "runId",
        "analysis_run_id",
        "last_analysis_run_id",
        "last_run_id",
        "run_a_id",
        "run_b_id",
        "run_a",
        "run_b",
        "previous_run_id",
        "current_run_id",
        "scan_id",
        "scanId",
        "findings_analysis_run_id",
        "lifecycle_analysis_run_id",
    }
)
MEMBER_FIELDS = frozenset({"membership_id", "tenant_user_id", "target_membership_id"})
SCHEMAS = {"AnalysisRunOut": "analysis_run", "RunSummary": "analysis_run"}
SCHEMA_FIELDS = {
    "LatestAnalysisOut": RUN_FIELDS,
    "AnalysisFindingOut": RUN_FIELDS,
    "ScheduleOut": RUN_FIELDS,
    "InvestigationRow": RUN_FIELDS,
    "InvestigationDetail": RUN_FIELDS,
    "AnalyzerEvidenceSection": RUN_FIELDS,
    "ReportGenerateRequest": RUN_FIELDS,
    "Fda510kReportSelectionIn": RUN_FIELDS,
    "BatchProgress": RUN_FIELDS,
    "FindingFixListResponse": RUN_FIELDS,
    "BatchListItem": RUN_FIELDS,
    "BatchListResponse": RUN_FIELDS,
    "EstimateResponse": RUN_FIELDS,
    "BatchDurationEstimateResponse": RUN_FIELDS,
    "CompareRequest": RUN_FIELDS,
    "PdfReportByIdRequest": RUN_FIELDS,
    "PlatformTenantMembershipSummary": MEMBER_FIELDS,
    "TenantAdministratorGovernanceResponse": MEMBER_FIELDS,
    "TenantAdministratorMembership": MEMBER_FIELDS,
    "PlatformGrantSummary": frozenset({"grant_id"}),
    "PlatformAdministratorGrantResponse": frozenset({"grant_id"}),
}


def run_route(path):
    # Explicit application AnalysisRun surfaces. NVD mirror sync/run identities
    # belong to another resource and are deliberately outside this list.
    return path.startswith(
        (
            "/api/runs",
            "/api/v1/runs",
            "/api/analysis-runs",
            "/api/v1/compare",
            "/api/sboms",
            "/api/sbom/",
            "/api/products",
            "/api/projects",
            "/api/logical-sboms",
            "/api/vex/",
            "/api/vulnerabilities",
            "/api/schedules",
            "/api/pdf-report",
            "/api/component-advisor/",
            "/api/v1/scans",
            "/api/reports",
            "/dashboard",
        )
    ) or path.startswith("/analyze-sbom-")


def resource_field(key, path):
    if key in RUN_FIELDS and run_route(path):
        return "analysis_run"
    if path.startswith(("/api/tenants", "/api/platform/", "/api/auth/", "/api/v1/auth/")):
        if key in MEMBER_FIELDS:
            return "tenant_users"
        if key == "grant_id":
            return "platform_user_roles"
    return None


def response_entity(path):
    if path in {
        "/api/runs",
        "/api/runs/recent",
        "/api/runs/search",
        "/dashboard/runs",
        "/api/sboms/{sbom_id}/analysis-runs",
        "/api/vex/investigations/analysis-runs",
        "/api/sboms/{sbom_id}/analyze",
    } or path.startswith("/analyze-sbom-"):
        return "analysis_run"
    if path in {"/api/runs/{run_id}"}:
        return "analysis_run"
    return None


def resource_statement(entity, context, *, request=False, path=None, tenant_id=None):
    table = MODELS[entity].__table__
    statement = select(table.c.id, table.c.public_id)
    if context is None:
        raise HTTPException(401, "Authentication required")
    if entity == "platform_user_roles":
        if (
            not context.is_platform_admin
            or context.tenant_id is not None
            or (path and not path.startswith("/api/platform/"))
        ):
            raise HTTPException(403, "Platform permission required")
    elif (
        entity == "tenant_users" and context.is_platform_admin and context.tenant_id is None
        and request and context.has_permission("platform:tenant_admin:manage")
        and path in {
            "/api/platform/tenants/{tenant_id}/administrators/{membership_id}/revoke",
            "/api/platform/tenants/{tenant_id}/administrators/{membership_id}/deactivate",
            "/api/platform/tenants/{tenant_id}/administrators/{membership_id}",
        }
    ):
        # Only these governance selectors may resolve authorization metadata
        # across tenants; the tenant selector was decoded first.
        statement = statement.where(table.c.tenant_id == tenant_id)
    elif entity == "tenant_users" and context.is_platform_admin and context.tenant_id is None and not request:
        # Cross-tenant summaries have already been authorized by platform routes.
        pass
    else:
        if context.tenant_id is None:
            raise HTTPException(403, "Active tenant context required")
        statement = statement.where(table.c.tenant_id == context.tenant_id)
    return table, statement


def namespace_field(key, path):
    """VEX's stored namespaced membership keys are an internal contract only."""
    return path.startswith("/api/vex/investigations") and key in {
        "assigned_to",
        "assignee",
        "previous_assignee",
        "new_assignee",
        "id",
    }


def public_run_error(value, cache):
    """Redact known decoded Run selectors in public error prose only.

    Do not rewrite arbitrary numbers or suppress conversion/validation failures.
    Structured resource fields are handled by the ordinary batched projection.
    """
    import re

    if isinstance(value, list):
        return [public_run_error(item, cache) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in {"message", "msg", "detail"} and isinstance(item, str):
            for (entity, internal), identity in cache.items():
                if entity == "analysis_run":
                    item = re.sub(
                        r"(\b(?:[Aa]nalysis )?[Rr]un\s+#?)" + str(internal) + r"\b",
                        lambda match, identity=identity: match[1] + identity,
                        item,
                    )
            result[key] = item
        else:
            result[key] = public_run_error(item, cache)
    return result


def missing_run(path, public_id):
    if path == "/api/v1/compare":
        raise HTTPException(
            404,
            {
                "error_code": "COMPARE_E001_RUN_NOT_FOUND",
                "message": "Analysis run not found",
                "run_id": str(public_id),
                "retryable": False,
            },
        )
    if path == "/api/analysis-runs/compare":
        raise HTTPException(
            404, {"code": "run_not_found", "message": "Analysis run not found", "run_id": str(public_id)}
        )
    raise HTTPException(404, "Resource not found")
