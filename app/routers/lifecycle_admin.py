"""Admin APIs for lifecycle provider configuration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from ..core.context import CurrentContext
from ..core.security import require_permission
from ..db import get_db
from ..schemas_lifecycle_admin import (
    LifecycleProviderConfigResponse,
    LifecycleProviderSecretRequest,
    LifecycleProviderSecretResponse,
    LifecycleProviderSyncResponse,
    LifecycleProviderTestResponse,
    LifecycleProviderUpdateRequest,
    LifecycleVendorRecordImportRequest,
    LifecycleVendorRecordImportResponse,
    LifecycleVendorRecordListResponse,
    LifecycleVendorRecordRequest,
    LifecycleVendorRecordResponse,
)
from ..services.lifecycle.provider_config_service import (
    LifecycleProviderConfigService,
    LifecycleVendorRecordService,
)

router = APIRouter(tags=["lifecycle-admin"])


def _provider_response(service: LifecycleProviderConfigService, db: Session, row) -> LifecycleProviderConfigResponse:
    return LifecycleProviderConfigResponse.model_validate(service.safe_config_dict(db, row))


def _record_response(service: LifecycleVendorRecordService, row) -> LifecycleVendorRecordResponse:
    return LifecycleVendorRecordResponse.model_validate(service.to_dict(row))


@router.get(
    "/api/admin/lifecycle-providers",
    response_model=list[LifecycleProviderConfigResponse],
)
def list_lifecycle_providers(
    db: Session = Depends(get_db),
    _context: CurrentContext = Depends(require_permission("lifecycle:provider:read")),
):
    service = LifecycleProviderConfigService()
    rows = service.list_configs(db)
    return [_provider_response(service, db, row) for row in rows]


@router.put(
    "/api/admin/lifecycle-providers/{provider_key}",
    response_model=LifecycleProviderConfigResponse,
)
def update_lifecycle_provider(
    provider_key: str,
    payload: LifecycleProviderUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:provider:update")),
):
    service = LifecycleProviderConfigService()
    row = service.update_config(
        db,
        provider_key,
        payload.to_service_payload(),
        context=context,
        request=request,
    )
    db.commit()
    db.refresh(row)
    return _provider_response(service, db, row)


@router.put(
    "/api/admin/lifecycle-providers/{provider_key}/secret",
    response_model=LifecycleProviderSecretResponse,
)
def put_lifecycle_provider_secret(
    provider_key: str,
    payload: LifecycleProviderSecretRequest,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:provider:update")),
):
    row = LifecycleProviderConfigService().set_secret(
        db,
        provider_key,
        payload.secret_name,
        payload.secret_value,
        context=context,
        request=request,
    )
    db.commit()
    db.refresh(row)
    return LifecycleProviderSecretResponse(
        provider_key=row.provider_key,
        secret_name=row.secret_name,
        value_preview=row.value_preview,
        updated_at=row.updated_at,
    )


@router.delete(
    "/api/admin/lifecycle-providers/{provider_key}/secret/{secret_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_lifecycle_provider_secret(
    provider_key: str,
    secret_name: str,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:provider:update")),
):
    LifecycleProviderConfigService().delete_secret(
        db,
        provider_key,
        secret_name,
        context=context,
        request=request,
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/api/admin/lifecycle-providers/{provider_key}/test",
    response_model=LifecycleProviderTestResponse,
)
def test_lifecycle_provider(
    provider_key: str,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:provider:test")),
):
    result = LifecycleProviderConfigService().test_provider(db, provider_key, context=context, request=request)
    db.commit()
    return result


@router.post(
    "/api/admin/lifecycle-providers/{provider_key}/sync",
    response_model=LifecycleProviderSyncResponse,
)
def sync_lifecycle_provider(
    provider_key: str,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:provider:sync")),
):
    result = LifecycleProviderConfigService().sync_provider(db, provider_key, context=context, request=request)
    db.commit()
    return result


@router.get(
    "/api/admin/lifecycle-vendor-records",
    response_model=LifecycleVendorRecordListResponse,
)
def list_lifecycle_vendor_records(
    search: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    ecosystem: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _context: CurrentContext = Depends(require_permission("lifecycle:vendor-record:read")),
):
    service = LifecycleVendorRecordService()
    rows, total = service.list_records(db, search=search, status=status_filter, ecosystem=ecosystem, limit=limit, offset=offset)
    return LifecycleVendorRecordListResponse(
        items=[_record_response(service, row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/api/admin/lifecycle-vendor-records",
    response_model=LifecycleVendorRecordResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_lifecycle_vendor_record(
    payload: LifecycleVendorRecordRequest,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:vendor-record:write")),
):
    service = LifecycleVendorRecordService()
    row = service.create_record(db, payload.model_dump(exclude_unset=True), context=context, request=request)
    db.commit()
    db.refresh(row)
    return _record_response(service, row)


@router.put(
    "/api/admin/lifecycle-vendor-records/{record_id}",
    response_model=LifecycleVendorRecordResponse,
)
def update_lifecycle_vendor_record(
    record_id: int,
    payload: LifecycleVendorRecordRequest,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:vendor-record:write")),
):
    service = LifecycleVendorRecordService()
    row = service.update_record(db, record_id, payload.model_dump(exclude_unset=True), context=context, request=request)
    db.commit()
    db.refresh(row)
    return _record_response(service, row)


@router.delete(
    "/api/admin/lifecycle-vendor-records/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_lifecycle_vendor_record(
    record_id: int,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:vendor-record:delete")),
):
    LifecycleVendorRecordService().disable_record(db, record_id, context=context, request=request)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/api/admin/lifecycle-vendor-records/import",
    response_model=LifecycleVendorRecordImportResponse,
)
def import_lifecycle_vendor_records(
    payload: LifecycleVendorRecordImportRequest,
    request: Request,
    db: Session = Depends(get_db),
    context: CurrentContext = Depends(require_permission("lifecycle:vendor-record:write")),
):
    result = LifecycleVendorRecordService().import_records(db, payload.records, context=context, request=request)
    db.commit()
    return result


@router.get("/api/admin/lifecycle-vendor-records/export")
def export_lifecycle_vendor_records(
    db: Session = Depends(get_db),
    _context: CurrentContext = Depends(require_permission("lifecycle:vendor-record:read")),
):
    return {"records": LifecycleVendorRecordService().export_records(db)}
