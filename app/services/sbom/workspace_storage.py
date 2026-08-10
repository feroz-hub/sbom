"""Filesystem-backed storage helpers for SBOM validation workspaces."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from tempfile import NamedTemporaryFile

from ...settings import get_settings


def _int_setting(name: str, default: int) -> int:
    value = os.getenv(name)
    if value:
        try:
            return int(value)
        except ValueError:
            return default
    return int(getattr(get_settings(), name, default))


def _str_setting(name: str, default: str) -> str:
    return os.getenv(name) or str(getattr(get_settings(), name, default))


@dataclass(frozen=True, slots=True)
class StoredWorkspaceFile:
    storage_backend: str
    storage_path: str | None
    inline_text: str | None
    inline_blob: bytes | None
    size_bytes: int
    sha256: str
    total_lines: int
    is_large_file: bool
    full_editor_allowed: bool


class SbomWorkspaceStorage:
    def __init__(self, root: str | Path | None = None):
        configured = root or _str_setting("SBOM_WORKSPACE_STORAGE_DIR", "./data/sbom-workspaces")
        self.root = Path(configured).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.small_file_max_bytes = _int_setting("SBOM_SMALL_FILE_MAX_BYTES", 5 * 1024 * 1024)
        self.full_editor_max_lines = _int_setting("SBOM_FULL_EDITOR_MAX_LINES", 20_000)
        self.line_page_size = _int_setting("SBOM_LINE_PAGE_SIZE", 500)
        self.search_max_results = _int_setting("SBOM_SEARCH_MAX_RESULTS", 1000)

    def store_original_upload(self, workspace_id: str, payload: bytes) -> StoredWorkspaceFile:
        digest = sha256(payload).hexdigest()
        size = len(payload)
        total_lines = count_lines_bytes(payload)
        full_editor_allowed = size <= self.small_file_max_bytes and total_lines <= self.full_editor_max_lines
        if full_editor_allowed:
            text = payload.decode("utf-8", errors="replace")
            return StoredWorkspaceFile(
                storage_backend="db",
                storage_path=None,
                inline_text=text,
                inline_blob=payload,
                size_bytes=size,
                sha256=digest,
                total_lines=total_lines,
                is_large_file=False,
                full_editor_allowed=True,
            )
        path = self._workspace_dir(workspace_id) / "original.sbom"
        path.write_bytes(payload)
        return StoredWorkspaceFile(
            storage_backend="filesystem",
            storage_path=str(path),
            inline_text=None,
            inline_blob=None,
            size_bytes=size,
            sha256=digest,
            total_lines=total_lines,
            is_large_file=True,
            full_editor_allowed=False,
        )

    def seed_repair_from_original(self, original_path: str | None, workspace_id: str) -> str | None:
        if not original_path:
            return None
        repair_path = self._workspace_dir(workspace_id) / "repair-draft.sbom"
        if not repair_path.exists():
            shutil.copyfile(original_path, repair_path)
        return str(repair_path)

    def write_repair_draft(self, workspace_id: str, content: str) -> StoredWorkspaceFile:
        payload = content.encode("utf-8", errors="replace")
        total_lines = count_lines_bytes(payload)
        full_editor_allowed = len(payload) <= self.small_file_max_bytes and total_lines <= self.full_editor_max_lines
        if full_editor_allowed:
            return StoredWorkspaceFile(
                storage_backend="db",
                storage_path=None,
                inline_text=content,
                inline_blob=payload,
                size_bytes=len(payload),
                sha256=sha256(payload).hexdigest(),
                total_lines=total_lines,
                is_large_file=False,
                full_editor_allowed=True,
            )
        path = self._workspace_dir(workspace_id) / "repair-draft.sbom"
        path.write_bytes(payload)
        return StoredWorkspaceFile(
            storage_backend="filesystem",
            storage_path=str(path),
            inline_text=None,
            inline_blob=None,
            size_bytes=len(payload),
            sha256=sha256(payload).hexdigest(),
            total_lines=total_lines,
            is_large_file=True,
            full_editor_allowed=False,
        )

    def path_for(self, session, source: str = "repair_draft") -> str | None:
        if source == "original":
            return getattr(session, "raw_storage_path", None)
        if source in {"repair_draft", "repair"}:
            return getattr(session, "repair_storage_path", None) or getattr(session, "raw_storage_path", None)
        raise ValueError("source must be original or repair_draft")

    def read_chunk_from_path(self, path: str, *, offset: int, limit: int) -> tuple[str, int, bool, str]:
        safe_offset = max(0, offset)
        safe_limit = max(1, min(limit, _int_setting("SBOM_CONTENT_CHUNK_SIZE_BYTES", 65_536) * 16))
        p = Path(path)
        total_size = p.stat().st_size
        hasher = sha256()
        with p.open("rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                hasher.update(block)
            fh.seek(safe_offset)
            data = fh.read(safe_limit)
        return data.decode("utf-8", errors="replace"), total_size, safe_offset + len(data) >= total_size, hasher.hexdigest()

    def read_lines_from_path(self, path: str, *, start_line: int, line_count: int) -> tuple[list[str], int, bool]:
        safe_start = max(1, start_line)
        safe_count = max(1, min(line_count, 5000))
        selected: list[str] = []
        total = 0
        with Path(path).open("r", encoding="utf-8", errors="replace", newline=None) as fh:
            for total, line in enumerate(fh, start=1):
                if total < safe_start:
                    continue
                if len(selected) < safe_count:
                    selected.append(line.rstrip("\r\n"))
        eof = safe_start - 1 + len(selected) >= total
        return selected, total, eof

    def search_lines(self, path: str, query: str, *, limit: int) -> list[dict[str, object]]:
        needle = query or ""
        if not needle:
            return []
        max_results = max(1, min(limit, self.search_max_results))
        matches: list[dict[str, object]] = []
        with Path(path).open("r", encoding="utf-8", errors="replace", newline=None) as fh:
            for line_number, line in enumerate(fh, start=1):
                column = line.find(needle)
                if column == -1:
                    continue
                preview = line.rstrip("\r\n")
                if len(preview) > 500:
                    start = max(0, column - 120)
                    preview = preview[start : start + 500]
                matches.append({"line_number": line_number, "column": column + 1, "preview": preview})
                if len(matches) >= max_results:
                    break
        return matches

    def apply_line_patches_to_path(self, base_path: str, workspace_id: str, patches: list[dict]) -> StoredWorkspaceFile:
        normalized = sorted(patches, key=lambda p: int(p.get("start_line") or p.get("line_number") or 1))
        output_path = self._workspace_dir(workspace_id) / "repair-draft.sbom"
        temp = NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=str(output_path.parent), newline="")
        temp_path = Path(temp.name)
        try:
            current_line = 1
            patch_idx = 0
            with Path(base_path).open("r", encoding="utf-8", errors="replace", newline="") as source, temp:
                for line in source:
                    while patch_idx < len(normalized):
                        patch = normalized[patch_idx]
                        operation = str(patch.get("operation") or "").strip().lower()
                        start = int(patch.get("start_line") or patch.get("line_number") or 1)
                        if operation == "insert_before_line" and start == current_line:
                            temp.write(_ensure_trailing_newline(str(patch.get("replacement_text") or "")))
                            patch_idx += 1
                            continue
                        break
                    if patch_idx < len(normalized):
                        patch = normalized[patch_idx]
                        operation = str(patch.get("operation") or "").strip().lower()
                        start = int(patch.get("start_line") or patch.get("line_number") or 1)
                        end = int(patch.get("end_line") or start)
                        if operation == "replace_lines" and start <= current_line <= end:
                            if current_line == start:
                                temp.write(_ensure_trailing_newline(str(patch.get("replacement_text") or "")))
                            if current_line == end:
                                patch_idx += 1
                            current_line += 1
                            continue
                        if operation == "delete_lines" and start <= current_line <= end:
                            if current_line == end:
                                patch_idx += 1
                            current_line += 1
                            continue
                    temp.write(line)
                    current_line += 1
                for patch in normalized[patch_idx:]:
                    if str(patch.get("operation") or "").strip().lower() == "insert_before_line":
                        temp.write(_ensure_trailing_newline(str(patch.get("replacement_text") or "")))
            temp_path.replace(output_path)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        return self.stats_for_path(output_path)

    def stats_for_path(self, path: str | Path) -> StoredWorkspaceFile:
        p = Path(path)
        size = p.stat().st_size
        digest = sha256_path(p)
        total_lines = count_lines_path(p)
        full_editor_allowed = size <= self.small_file_max_bytes and total_lines <= self.full_editor_max_lines
        return StoredWorkspaceFile(
            storage_backend="filesystem",
            storage_path=str(p),
            inline_text=None,
            inline_blob=None,
            size_bytes=size,
            sha256=digest,
            total_lines=total_lines,
            is_large_file=not full_editor_allowed,
            full_editor_allowed=full_editor_allowed,
        )

    def _workspace_dir(self, workspace_id: str) -> Path:
        path = self.root / workspace_id
        path.mkdir(parents=True, exist_ok=True)
        return path


def count_lines_bytes(payload: bytes) -> int:
    if not payload:
        return 0
    return payload.count(b"\n") + (0 if payload.endswith(b"\n") else 1)


def count_lines_path(path: str | Path) -> int:
    total = 0
    with Path(path).open("rb") as fh:
        previous = b""
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            total += block.count(b"\n")
            previous = block[-1:]
    if previous and previous != b"\n":
        total += 1
    return total


def sha256_path(path: str | Path) -> str:
    digest = sha256()
    with Path(path).open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_file(path: str | Path, chunk_size: int = 1024 * 1024) -> Iterable[bytes]:
    with Path(path).open("rb") as fh:
        yield from iter(lambda: fh.read(chunk_size), b"")


def _ensure_trailing_newline(text: str) -> str:
    if not text:
        return ""
    return text if text.endswith("\n") else text + "\n"
