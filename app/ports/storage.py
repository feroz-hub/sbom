"""S3-compatible object storage port."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class StoragePort(Protocol):
    """Put/get/delete SBOM blobs and generated artifacts."""

    def put_object(self, key: str, body: bytes, content_type: str) -> str:
        """Store bytes; return storage key or URI."""
        ...

    def get_object(self, key: str) -> bytes: ...

    def delete_object(self, key: str) -> None: ...
