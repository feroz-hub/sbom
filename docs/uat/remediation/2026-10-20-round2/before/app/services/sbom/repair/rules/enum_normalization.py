from app.validation import errors as E
from app.validation.stages.schema import _build_json_validator, _ensure_json_schema

from ..diff import pointer, proposal
from .base import RepairRule


class EnumNormalizationRule(RepairRule):
    name = "enum_normalization"
    error_codes = {E.E028_SCHEMA_ENUM_VIOLATION, E.E057_COMPONENT_TYPE_INVALID}

    def propose(self, document, error):
        schema = _ensure_json_schema("cyclonedx", document["specVersion"])
        validator = _build_json_validator(schema, "cyclonedx", document["specVersion"])
        path = pointer(error["path"])
        for issue in validator.iter_errors(document):
            here = "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in issue.absolute_path)
            # Do not change license IDs, hashes, signatures or security facts.
            if issue.validator != "enum" or here != path or here.split("/")[-1] != "type":
                continue
            if not isinstance(issue.instance, str):
                continue
            matches = [
                v
                for v in issue.validator_value
                if isinstance(v, str) and v.casefold() == issue.instance.strip().casefold()
            ]
            if len(matches) == 1:
                return proposal(
                    error["code"],
                    path,
                    issue.instance,
                    matches[0],
                    "enum_normalization",
                    "Normalize component type to its unique value in the exact vendored specification enum.",
                )
        return None
