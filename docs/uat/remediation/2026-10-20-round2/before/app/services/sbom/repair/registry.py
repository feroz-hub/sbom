from .rules.dangling_dependency_ref import DanglingDependencyRefRule
from .rules.dependency_cleanup import DependencyCleanupRule
from .rules.duplicate_bom_ref import DuplicateBomRefRule
from .rules.duplicate_dependency import DuplicateDependencyRule
from .rules.enum_normalization import EnumNormalizationRule
from .rules.identifier_canonicalization import CpeNormalizationRule, PurlCanonicalizationRule
from .rules.purl_normalization import PurlNormalizationRule
from .rules.spdx import (
    SpdxChecksumRule,
    SpdxDeduplicationRule,
    SpdxExternalReferenceRule,
    SpdxIdentifierRule,
    SpdxReferenceRule,
)


def default_rules():
    return (
        DuplicateBomRefRule(),
        DanglingDependencyRefRule(),
        DuplicateDependencyRule(),
        EnumNormalizationRule(),
        PurlNormalizationRule(),
        PurlCanonicalizationRule(),
        CpeNormalizationRule(),
        DependencyCleanupRule(),
        SpdxIdentifierRule(),
        SpdxReferenceRule(),
        SpdxDeduplicationRule(),
        SpdxExternalReferenceRule(),
        SpdxChecksumRule(),
    )
