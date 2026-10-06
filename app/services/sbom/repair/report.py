from app.services.validation_repair_service import serialize_report


def validation_result(report):
    result = serialize_report(report)
    result["validation_status"] = "FAILED" if report.has_errors() or report.truncated else "PASSED"
    return result


def summary(entries, report, proposals):
    counts = {
        key: sum(e["classification"] == key for e in entries) for key in ("AUTO_FIX", "SUGGEST_FIX", "MANUAL_ONLY")
    }
    return dict(
        validation_status="FAILED" if report.has_errors() or report.truncated else "PASSED",
        total_errors=report.error_count,
        auto_fixable=counts["AUTO_FIX"],
        suggested=counts["SUGGEST_FIX"],
        manual_only=counts["MANUAL_ONLY"],
        truncated=report.truncated,
        issues=entries,
        repairs=[p.model_dump(mode="json") for p in proposals],
    )
