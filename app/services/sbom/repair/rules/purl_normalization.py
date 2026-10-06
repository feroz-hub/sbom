from app.services.lifecycle.normalizer import parse_purl
from app.validation import errors as E

from ..diff import pointer, proposal, value_at
from .base import RepairRule


class PurlNormalizationRule(RepairRule):
    name = "purl_normalization"
    error_codes = {E.E052_PURL_INVALID, E.E029_SCHEMA_FORMAT_VIOLATION, E.E025_SCHEMA_VIOLATION}

    def propose(self, document, error):
        path = pointer(error["path"])
        if not path.endswith("/purl"):
            return None
        try:
            old = value_at(document, path)
        except (KeyError, IndexError, TypeError, ValueError):
            return None
        if not isinstance(old, str) or old == old.strip() or parse_purl(old.strip()) is None:
            return None
        return proposal(
            error["code"],
            path,
            old,
            old.strip(),
            "purl_normalization",
            "Remove surrounding whitespace from an existing parseable PURL; package facts are unchanged.",
        )
