from .rules.dangling_dependency_ref import DanglingDependencyRefRule
from .rules.duplicate_bom_ref import DuplicateBomRefRule
from .rules.duplicate_dependency import DuplicateDependencyRule
from .rules.enum_normalization import EnumNormalizationRule
from .rules.purl_normalization import PurlNormalizationRule


def default_rules():
    return (
        DuplicateBomRefRule(),
        DanglingDependencyRefRule(),
        DuplicateDependencyRule(),
        EnumNormalizationRule(),
        PurlNormalizationRule(),
    )
