from app.validation import errors as E

from ...quality.inspection import canonical_cpe, canonical_purl
from ..diff import pointer, proposal, value_at
from .base import RepairRule


class PurlCanonicalizationRule(RepairRule):
    name = "purl_canonicalization"
    error_codes = {"QUALITY_PURL_NONCANONICAL", E.E052_PURL_INVALID, E.E029_SCHEMA_FORMAT_VIOLATION}

    def propose(self, document, error):
        path = pointer(error["path"])
        if not path.endswith("/purl"):
            return None
        try:
            old = value_at(document, path)
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        canonical = canonical_purl(old)
        if canonical is None or old == canonical:
            return None
        return proposal(
            error["code"],
            path,
            old,
            canonical,
            self.name,
            "Canonicalize existing PURL using packageurl-python; retain all supplied identity facts.",
        )


class CpeNormalizationRule(RepairRule):
    name = "cpe_normalization"
    error_codes = {
        "QUALITY_CPE_WHITESPACE",
        E.E053_CPE_INVALID,
        E.E029_SCHEMA_FORMAT_VIOLATION,
        E.E025_SCHEMA_VIOLATION,
    }

    def propose(self, document, error):
        path = pointer(error["path"])
        if not path.endswith("/cpe"):
            return None
        try:
            old = value_at(document, path)
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        canonical = canonical_cpe(old)
        if canonical is None or old == canonical:
            return None
        return proposal(
            error["code"],
            path,
            old,
            canonical,
            self.name,
            "Trim only surrounding whitespace from an already valid CPE 2.3; no identity field changes.",
        )
