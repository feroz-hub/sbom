from .models import RepairClassification as C
from .rules.dangling_dependency_ref import DanglingDependencyRefRule
from .rules.duplicate_bom_ref import DuplicateBomRefRule


def classify(document, error, rules, enabled=True):
    for rule in rules if document is not None and enabled else ():
        if error["code"] not in rule.error_codes or not rule.supports(document):
            continue
        change = rule.propose(document, error)
        if change is not None:
            return C.AUTO_FIX, change
        if (isinstance(rule, DuplicateBomRefRule) and error["code"] == "SBOM_VAL_E051_BOM_REF_DUPLICATE") or (
            isinstance(rule, DanglingDependencyRefRule) and rule.matches(document, error)
        ):
            return C.SUGGEST_FIX, None
    return C.MANUAL_ONLY, None
