"""Copy-on-write deterministic repair with the canonical nine-stage validator."""

import json
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from time import monotonic

from app.parsing.strict_json import require_unambiguous_json
from app.validation import run as validate
from app.validation.context import ValidationContext
from app.validation.stages import STAGE_NUMBERS, detect, ingress, security

from ..quality.inspection import repair_quality_issues
from .classifier import classify
from .diff import pointer
from .models import RepairStatus as S
from .policy import RepairPolicy
from .registry import default_rules
from .report import summary, validation_result


@dataclass
class RepairResult:
    candidate: bytes
    report: dict


class RepairEngine:
    def __init__(self, policy=None, rules=None, validator=validate):
        self.policy = policy or RepairPolicy.configured()
        self.rules = default_rules() if rules is None else rules
        self.validate = validator

    def _validation(self, raw):
        return self.validate(raw, strict_ntia=self.policy.strict_ntia, verify_signature=self.policy.verify_signature)

    def _unsupported(self, reason):
        self._blocked_reason = reason
        return None

    def _document(self, raw):
        self._blocked_reason = None
        # Reuse the capped parser and ALWAYS run the existing security walk:
        # the normal validator skips that walk when schema/semantic fails.
        if len(raw) > self.policy.max_bytes:
            return self._unsupported("Document exceeds the automatic repair size limit; use manual handling.")
        ctx = ingress.run(ValidationContext(raw_bytes=raw))
        if ctx.report.has_errors():
            return self._unsupported("Input is blocked by ingress validation and cannot be repaired automatically.")
        ctx = detect.run(ctx)
        if ctx.report.has_errors():
            return self._unsupported("Input cannot be parsed safely in a supported repair format; use manual handling.")
        if ctx.spec not in {"cyclonedx", "spdx"} or ctx.encoding != "json":
            return self._unsupported(
                "Automatic repair is unsupported for this format; supported formats are CycloneDX JSON 1.4–1.6 and SPDX JSON 2.2/2.3."
            )
        ctx = security.run(ctx)
        if ctx.report.has_errors():
            return self._unsupported("Security validation blocks automatic repair; use manual review.")

        try:
            require_unambiguous_json(ctx.text)
        except (ValueError, TypeError):
            return self._unsupported("Ambiguous JSON keys or non-JSON numbers require manual handling.")
        doc = ctx.parsed_dict
        # Changing any signed document would invalidate its signatures.
        pending = [doc]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                if "signature" in node:
                    return self._unsupported(
                        "Signed documents require manual handling; automatic repair would invalidate the signature."
                    )
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)
        return doc

    def _analyze(self, raw, report):
        self._blocked_reason = "Auto-repair is disabled."
        doc = self._document(raw) if self.policy.enabled else None
        entries, changes = [], []
        diagnostics = [entry.model_dump(mode="json") for entry in report.errors]
        from ..quality.spdx_inspection import prepared_spdx
        with prepared_spdx(doc):
            quality_issues = repair_quality_issues(doc) if doc is not None else []
            diagnostics.extend(quality_issues)
            for error in diagnostics:
                kind, change = classify(doc, error, self.rules, self.policy.enabled)
                error["classification"] = kind.value
                entries.append(error)
                if change and change.confidence >= self.policy.confidence:
                    changes.append(change)
        result = summary(entries, report, changes)
        result.update(repair_supported=doc is not None, manual_review_reason=self._blocked_reason,
                      quality_issue_count=len(quality_issues),
                      format="SPDX_JSON" if doc and doc.get("spdxVersion") else "CYCLONEDX_JSON" if doc else None,
                      spec_version=doc.get("spdxVersion", doc.get("specVersion", "")).removeprefix("SPDX-") if doc else None,
                      rule_metadata=[r.metadata() for r in self.rules if doc is None or r.supports(doc)])
        return result, doc, changes

    def analyze(self, raw):
        return self._analyze(raw, self._validation(raw))[0]

    def run(self, raw):
        before = self._validation(raw)
        current, after = raw, before
        applied, passes, rolled_back = [], 0, False
        rolled_back_changes = []
        seen = {sha256(raw).digest()}
        deadline = monotonic() + self.policy.max_seconds
        for _ in range(self.policy.max_passes) if self.policy.enabled else ():
            analysis, doc, changes = self._analyze(current, after)
            if not changes:
                break
            # Apply ONE proposal then revalidate. Array index shifts and changes
            # to reference registries cannot invalidate other proposals in a batch.
            # A pass is a bounded batch of freshly generated repairs.
            pass_changed = False
            for _ in range(100):
                if monotonic() >= deadline:
                    break
                _, doc, changes = self._analyze(current, after)
                if not changes:
                    break
                change = changes[0]
                rule = next(r for r in self.rules if r.name == change.rule_name)
                candidate = (json.dumps(rule.apply(doc, change), indent=2, ensure_ascii=False) + "\n").encode()
                if sha256(candidate).digest() in seen:
                    break
                checked = self._validation(candidate)
                # Later stages can reveal previously hidden errors. They remain
                # FAILED/partial, never approved. New errors at an already reached
                # stage (or extra warnings) cause rollback of this entire proposal.
                cutoff = STAGE_NUMBERS.get(after.first_error_stage, 99)
                old_counts = Counter((e.code, e.stage) for e in after.errors)
                new_counts = Counter(
                    (e.code, e.stage) for e in checked.errors if STAGE_NUMBERS.get(e.stage, 99) <= cutoff
                )
                old_warning = Counter((e.code, e.stage) for e in after.warnings)
                new_warning = Counter(
                    (e.code, e.stage) for e in checked.warnings if STAGE_NUMBERS.get(e.stage, 99) <= cutoff
                )
                remaining = any(e.code == change.error_code and pointer(e.path) == change.path for e in checked.errors)
                if change.error_code.startswith('QUALITY_'):
                    candidate_doc = self._document(candidate)
                    remaining = candidate_doc is None or any(e['code'] == change.error_code and pointer(e['path']) == change.path
                                                            for e in repair_quality_issues(candidate_doc))
                reduced = sum(e.code == change.error_code for e in checked.errors) < sum(
                    e.code == change.error_code for e in after.errors
                )
                if new_counts - old_counts or new_warning - old_warning or (remaining and not reduced):
                    rolled_back = True
                    rolled_back_changes.append(
                        {
                            **change.model_dump(mode="json"),
                            "reason": "Rolled back: revalidation introduced an error or did not resolve the target issue.",
                            "error_count_after_attempt": checked.error_count,
                        }
                    )
                    break
                seen.add(sha256(candidate).digest())
                current, after = candidate, checked
                applied.append(change.model_dump(mode="json"))
                pass_changed = True
            passes += 1
            if not pass_changed or rolled_back or monotonic() >= deadline:
                break
        final = self._analyze(current, after)[0]
        for attempted in rolled_back_changes:
            for issue in final["issues"]:
                if issue["code"] == attempted["error_code"] and pointer(issue["path"]) == attempted["path"]:
                    issue["classification"] = "MANUAL_ONLY"
                    issue["repair_reason"] = attempted["reason"]
            final["repairs"] = [p for p in final["repairs"] if p["repair_id"] != attempted["repair_id"]]
        if rolled_back_changes:
            final["auto_fixable"] = sum(i["classification"] == "AUTO_FIX" for i in final["issues"])
            final["manual_only"] = sum(i["classification"] == "MANUAL_ONLY" for i in final["issues"])
            final["manual_review_reason"] = (
                "A proposed repair failed full revalidation and was rolled back; manual review is required."
            )
        limit_reached = bool(final["auto_fixable"] and (passes == self.policy.max_passes or monotonic() >= deadline))
        status = (
            S.NOT_REQUIRED
            if not applied and not before.has_errors() and not before.truncated
            else S.REPAIR_FAILED
            if rolled_back and not applied
            else S.REPAIRED
            if applied and not after.has_errors() and not after.truncated
            else S.PARTIALLY_REPAIRED
            if applied
            else S.MANUAL_REVIEW_REQUIRED
        )
        return RepairResult(
            current,
            dict(
                status=status.value,
                format=final["format"],
                spec_version=final["spec_version"],
                rule_metadata=final["rule_metadata"],
                errors_before=before.error_count,
                errors_after=after.error_count,
                repairs_applied=len(applied),
                passes=passes,
                max_passes=self.policy.max_passes,
                rollback=rolled_back,
                rolled_back_changes=rolled_back_changes,
                manual_review_reason=final["manual_review_reason"],
                limit_reached=limit_reached,
                suggested_repairs=final["suggested"],
                manual_errors=final["manual_only"],
                validation_status=final["validation_status"],
                changes=applied,
                before_validation=validation_result(before),
                after_validation=validation_result(after),
                analysis=final,
                validation_complete=not after.truncated,
                approval_status="PENDING",
                requires_approval=True,
            ),
        )
