"""Pydantic schemas for API request/response payloads."""

from datetime import date, datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class KevEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[date] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[date] = None
    known_ransomware_campaign_use: Optional[str] = None
    notes: Optional[str] = None
    cwes: Optional[List[str]] = None
    catalog_version: Optional[str] = None
    updated_at: Optional[datetime] = None


class SyncResult(BaseModel):
    catalog_version: Optional[str]
    catalog_date_released: Optional[datetime]
    total_in_feed: int
    filtered_since: Optional[date]
    matched_after_filter: int
    upserted: int
    duration_seconds: float


class KevListOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[KevEntryOut]
