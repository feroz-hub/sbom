"""Structured proposals: content is data, never an instruction or executable patch."""

from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field


class RepairClassification(StrEnum):
    AUTO_FIX = "AUTO_FIX"
    SUGGEST_FIX = "SUGGEST_FIX"
    MANUAL_ONLY = "MANUAL_ONLY"


class RepairMethod(StrEnum):
    DETERMINISTIC = "DETERMINISTIC"
    INFERRED = "INFERRED"
    AI_ASSISTED = "AI_ASSISTED"


class RepairStatus(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    REPAIR_AVAILABLE = "REPAIR_AVAILABLE"
    REPAIR_IN_PROGRESS = "REPAIR_IN_PROGRESS"
    REPAIRED = "REPAIRED"
    PARTIALLY_REPAIRED = "PARTIALLY_REPAIRED"
    REPAIR_FAILED = "REPAIR_FAILED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    REJECTED = "REJECTED"


class RepairProposal(BaseModel):
    repair_id: str
    error_code: str
    operation: str
    path: str
    old_value: Any
    new_value: Any
    method: RepairMethod = RepairMethod.DETERMINISTIC
    confidence: float = Field(default=1.0, ge=0, le=1)
    reason: str
    rule_name: str


class RepairAdvisor(Protocol):
    async def propose(self, document: dict, errors: list[dict]) -> list[RepairProposal]: ...


class NullRepairAdvisor:
    async def propose(self, document: dict, errors: list[dict]) -> list[RepairProposal]:
        return []
