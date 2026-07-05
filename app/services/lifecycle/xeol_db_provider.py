"""Xeol-style local database/JSON lifecycle provider (no per-request CLI)."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .provider_base import LifecycleProvider
from .provider_chain import PRIORITY_XEOL
from .types import (
    DEPRECATED,
    EOL,
    EOL_SOON,
    HIGH,
    MEDIUM,
    SUPPORTED,
    UNSUPPORTED,
    LifecycleResult,
    NormalizedComponent,
    unknown_result,
)

EOL_SOON_DAYS = 90
SQLITE_HEADER = b"SQLite format 3\x00"
REQUIRED_SQLITE_TABLES = {"products", "cycles", "purls"}


class XeolDbProvider(LifecycleProvider):
    """Match components against a pre-synced Xeol-compatible JSON export."""

    name = "Xeol DB"
    priority = PRIORITY_XEOL

    def __init__(self, *, db_path: str | None = None, today: date | None = None) -> None:
        self.db_path = db_path
        self.today = today

    def supports(self, component: NormalizedComponent) -> bool:
        return bool(self.db_path and Path(self.db_path).is_file())

    def lookup(self, component: NormalizedComponent) -> LifecycleResult:
        records = _load_xeol_db(self.db_path)
        if not records:
            return unknown_result(component, self.name)
        record = _match_record(records, component)
        if record is None:
            return unknown_result(component, self.name)
        return _result_from_record(record, component, today=self.today, source_name=self.name)


@lru_cache(maxsize=4)
def _load_xeol_db(db_path: str | None) -> list[dict[str, Any]]:
    if not db_path:
        return []
    path = Path(db_path)
    if not path.is_file():
        return []
    if _looks_like_sqlite(path):
        return _load_sqlite_xeol_db(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("components", "records", "entities", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return []


def validate_xeol_db_path(db_path: str | None) -> tuple[bool, str, dict[str, Any] | None]:
    """Validate that a local Xeol DB path is readable and has a supported schema."""

    if not db_path:
        return False, "Xeol DB requires config.db_path when enabled.", None
    path = Path(db_path)
    if not path.is_file():
        return False, "Configured Xeol DB path does not exist.", None
    try:
        with path.open("rb") as handle:
            header = handle.read(len(SQLITE_HEADER))
    except OSError as exc:
        return False, f"Configured Xeol DB path is not readable: {exc.strerror or exc}", None

    if header == SQLITE_HEADER:
        ok, message, sample = _validate_sqlite_xeol_db(path)
    else:
        ok, message, sample = _validate_json_xeol_export(path)
    if ok:
        return True, "Local Xeol DB path is readable.", sample
    return False, message, sample


def _looks_like_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(SQLITE_HEADER)) == SQLITE_HEADER
    except OSError:
        return False


def _connect_sqlite_readonly(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _validate_sqlite_xeol_db(path: Path) -> tuple[bool, str, dict[str, Any] | None]:
    try:
        with _connect_sqlite_readonly(path) as connection:
            tables = {
                str(row["name"])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            missing = sorted(REQUIRED_SQLITE_TABLES - tables)
            if missing:
                return False, f"Local Xeol DB SQLite schema is missing required tables: {', '.join(missing)}.", {
                    "db_path": str(path),
                    "format": "sqlite",
                }
            product_count = int(connection.execute("SELECT COUNT(*) FROM products").fetchone()[0])
            cycle_count = int(connection.execute("SELECT COUNT(*) FROM cycles").fetchone()[0])
            if product_count == 0 or cycle_count == 0:
                return False, "Local Xeol DB SQLite database contains no lifecycle records.", {
                    "db_path": str(path),
                    "format": "sqlite",
                    "products": product_count,
                    "cycles": cycle_count,
                }
            metadata = connection.execute("SELECT * FROM id LIMIT 1").fetchone() if "id" in tables else None
            sample = {
                "db_path": str(path),
                "format": "sqlite",
                "products": product_count,
                "cycles": cycle_count,
            }
            if metadata is not None:
                sample["schema_version"] = metadata["schema_version"]
                sample["build_timestamp"] = metadata["build_timestamp"]
            return True, "Local Xeol DB path is readable.", sample
    except sqlite3.Error as exc:
        return False, f"Local Xeol DB SQLite database is not readable: {exc}.", {
            "db_path": str(path),
            "format": "sqlite",
        }


def _validate_json_xeol_export(path: Path) -> tuple[bool, str, dict[str, Any] | None]:
    try:
        records = _load_json_xeol_export(path)
    except OSError as exc:
        return False, f"Configured Xeol DB path is not readable: {exc.strerror or exc}", None
    except json.JSONDecodeError:
        return False, "Local Xeol DB file is neither SQLite nor a valid Xeol JSON export.", {
            "db_path": str(path),
            "format": "json",
        }
    if not records:
        return False, "Local Xeol DB JSON export contains no lifecycle records.", {
            "db_path": str(path),
            "format": "json",
        }
    return True, "Local Xeol DB path is readable.", {
        "db_path": str(path),
        "format": "json",
        "records": len(records),
    }


def _load_json_xeol_export(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("components", "records", "entities", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return []


def _load_sqlite_xeol_db(path: Path) -> list[dict[str, Any]]:
    try:
        with _connect_sqlite_readonly(path) as connection:
            tables = {
                str(row["name"])
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            if REQUIRED_SQLITE_TABLES - tables:
                return []
            rows = connection.execute(
                """
                SELECT
                    products.name AS product_name,
                    products.permalink AS permalink,
                    cycles.release_cycle AS release_cycle,
                    cycles.eol AS eol,
                    cycles.eol_bool AS eol_bool,
                    cycles.latest_release AS latest_release,
                    cycles.latest_release_date AS latest_release_date,
                    cycles.release_date AS release_date,
                    cycles.support AS support,
                    purls.purl AS purl
                FROM cycles
                JOIN products ON products.id = cycles.product_id
                LEFT JOIN purls ON purls.product_id = products.id
                """
            )
            return [_sqlite_row_to_record(row) for row in rows]
    except sqlite3.Error:
        return []


def _sqlite_row_to_record(row: sqlite3.Row) -> dict[str, Any]:
    purl = str(row["purl"] or "")
    ecosystem, package_name = _ecosystem_and_name_from_purl(purl)
    product_name = str(row["product_name"] or "")
    eol_bool = row["eol_bool"]
    eol_value: Any = bool(eol_bool) if eol_bool is not None else row["eol"]
    return {
        "name": package_name or product_name,
        "component": product_name,
        "ecosystem": ecosystem or "generic",
        "version": str(row["release_cycle"] or ""),
        "eol": eol_value,
        "eol_date": row["eol"] if row["eol"] else None,
        "latest_release": row["latest_release"],
        "latest_release_date": row["latest_release_date"],
        "release_date": row["release_date"],
        "support": bool(row["support"]) if row["support"] is not None else None,
        "source_url": row["permalink"] or "https://www.xeol.io/",
        "purl": purl or None,
    }


def _ecosystem_and_name_from_purl(purl: str) -> tuple[str | None, str | None]:
    if not purl.startswith("pkg:"):
        return None, None
    body = purl[4:].split("?", 1)[0].split("@", 1)[0]
    package_type, _, path = body.partition("/")
    if not package_type or not path:
        return package_type or None, None
    name = unquote(path.rsplit("/", 1)[-1])
    return package_type.lower(), name or None


def clear_xeol_db_cache() -> None:
    _load_xeol_db.cache_clear()


def _match_record(records: list[dict[str, Any]], component: NormalizedComponent) -> dict[str, Any] | None:
    name = (component.normalized_name or component.name).casefold()
    version = (component.normalized_version or "").casefold().lstrip("v")
    ecosystem = (component.ecosystem or "generic").casefold()
    matches: list[tuple[int, dict[str, Any]]] = []
    for record in records:
        record_name = str(record.get("name") or record.get("component") or "").casefold()
        if name != record_name:
            continue
        record_eco = str(record.get("ecosystem") or "generic").casefold()
        if record_eco not in {"", "generic", ecosystem}:
            continue
        record_version = str(record.get("version") or "").casefold().lstrip("v")
        if record_version and version != record_version and not version.startswith(f"{record_version}."):
            continue
        matches.append((len(record_version), record))
    return max(matches, key=lambda item: item[0])[1] if matches else None


def _result_from_record(
    record: dict[str, Any],
    component: NormalizedComponent,
    *,
    today: date | None,
    source_name: str,
) -> LifecycleResult:
    current = today or datetime.now(UTC).date()
    eol_date = _iso_date(record.get("eol_date") or record.get("eol"))
    reason = str(record.get("eol_reason") or "").strip().lower()
    status = SUPPORTED
    if reason == "registry_deprecated":
        status = DEPRECATED
    elif record.get("eol") is True or (eol_date and _parse_date(eol_date) and _parse_date(eol_date) < current):
        status = EOL
    elif eol_date and _parse_date(eol_date) and current <= _parse_date(eol_date) <= current + timedelta(days=EOL_SOON_DAYS):
        status = EOL_SOON
    elif reason == "source_archived":
        status = UNSUPPORTED
    evidence_url = str(record.get("source_url") or record.get("evidence_url") or "https://www.xeol.io/")
    return LifecycleResult(
        component_name=component.normalized_name,
        component_version=component.normalized_version,
        ecosystem=component.ecosystem,
        purl=component.purl,
        cpe=component.cpe,
        lifecycle_status=status,
        eol_date=eol_date,
        deprecated=status == DEPRECATED,
        unsupported=status in {EOL, UNSUPPORTED},
        source_name=source_name,
        source_url=evidence_url,
        evidence={"provider": "xeol_db", "record": record},
        confidence=HIGH if reason == "vendor_announced" else MEDIUM,
    ).canonicalized()


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _iso_date(value: Any) -> str | None:
    parsed = _parse_date(str(value) if value is not None else None)
    return parsed.isoformat() if parsed else None


__all__ = ["XeolDbProvider", "clear_xeol_db_cache", "validate_xeol_db_path"]
