"""Infrastructure adapters (S3, DB drivers, etc.)."""

from .s3_storage import S3StorageAdapter

__all__ = ["S3StorageAdapter"]
