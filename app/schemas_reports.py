"""Report preferences have no recipient, URL, filesystem or query escape hatches."""

from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator

Scope = Literal["TENANT", "PROJECT", "PRODUCT", "SBOM"]


class ReportPreferences(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope: Scope
    project_id: int | None = Field(default=None, gt=0)
    product_id: int | None = Field(default=None, gt=0)
    sbom_id: int | None = Field(default=None, gt=0)
    cadence: Literal["ON_EVERY_RUN", "DAILY", "WEEKLY", "MONTHLY"] = "DAILY"
    parts: list[Literal["A", "B", "C", "D"]] = Field(default_factory=lambda: ["A", "B"], max_length=4)
    formats: list[Literal["PDF", "XLSX"]] = Field(default_factory=lambda: ["PDF", "XLSX"], max_length=2)
    severity_floor: Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "ALL"
    baseline_mode: Literal["FIRST_RUN_OF_SBOM", "FIRST_RUN_OF_LINEAGE_ROOT"] = "FIRST_RUN_OF_SBOM"
    cross_version_target: Literal["PARENT", "ROOT"] = "PARENT"
    timezone: str = Field(default="UTC", max_length=64)
    suppress_when_unchanged: bool = False
    enabled: bool = True

    @model_validator(mode="after")
    def validate_preferences(self):
        expected = {"PROJECT": "project_id", "PRODUCT": "product_id", "SBOM": "sbom_id"}.get(self.scope)
        for field in ("project_id", "product_id", "sbom_id"):
            if (getattr(self, field) is not None) != (field == expected):
                raise ValueError("Supply exactly the target ID appropriate for the scope")
        if "A" not in self.parts or len(set(self.parts)) != len(self.parts):
            raise ValueError("Part A is mandatory; parts must be unique")
        if len(set(self.formats)) != len(self.formats):
            raise ValueError("Formats must be unique")
        if self.suppress_when_unchanged and not set(self.parts) & {"B", "C", "D"}:
            raise ValueError("Suppress unchanged requires a comparison part")
        try:
            ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("Unknown IANA timezone") from exc
        return self

    def database_values(self):
        return {**self.model_dump(), "parts": ",".join(sorted(self.parts)), "formats": ",".join(sorted(self.formats))}


def preferences_for(row) -> ReportPreferences:
    return ReportPreferences.model_validate(
        {
            field: getattr(row, field).split(",")
            if field in {"parts", "formats"} and getattr(row, field)
            else []
            if field in {"parts", "formats"}
            else getattr(row, field)
            for field in ReportPreferences.model_fields
        }
    )
