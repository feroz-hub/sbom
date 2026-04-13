"""S3-compatible storage adapter implementing StoragePort."""

from __future__ import annotations

import logging

import boto3
from botocore.exceptions import ClientError

from ..settings import get_settings

log = logging.getLogger(__name__)


class S3StorageAdapter:
    """Thin boto3 wrapper; optional endpoint for MinIO."""

    def __init__(self) -> None:
        s = get_settings()
        self._bucket = (s.aws_s3_bucket or "").strip()
        endpoint = (s.aws_s3_endpoint_url or "").strip() or None
        region = (s.aws_region or "us-east-1").strip()
        ak = (s.aws_access_key_id or "").strip()
        sk = (s.aws_secret_access_key or "").strip()
        if not self._bucket:
            raise ValueError("aws_s3_bucket is not configured")
        kwargs: dict = {"region_name": region}
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        if ak and sk:
            kwargs["aws_access_key_id"] = ak
            kwargs["aws_secret_access_key"] = sk
        self._client = boto3.client("s3", **kwargs)

    def put_object(self, key: str, body: bytes, content_type: str) -> str:
        self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body,
            ContentType=content_type,
        )
        return key

    def get_object(self, key: str) -> bytes:
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=key)
            return resp["Body"].read()
        except ClientError as exc:
            log.warning("S3 get_object failed key=%s: %s", key, exc)
            raise

    def delete_object(self, key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=key)


def try_create_s3_adapter() -> S3StorageAdapter | None:
    """Return adapter if bucket is configured; otherwise None."""
    s = get_settings()
    if not (s.aws_s3_bucket or "").strip():
        return None
    return S3StorageAdapter()
