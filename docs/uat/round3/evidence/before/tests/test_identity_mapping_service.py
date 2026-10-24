import pytest
from app.services.identity_mapping_service import build_identity_mapping

def test_build_identity_mapping_connected():
    mapping = build_identity_mapping(external_iam_tenant_id="wellysis-iam-99")
    assert mapping["state"] == "CONNECTED"
    assert mapping["display_status"] == "Connected to HCL.CS tenant"
    assert mapping["is_legacy"] is False

def test_build_identity_mapping_not_configured():
    mapping = build_identity_mapping(external_iam_tenant_id=None)
    assert mapping["state"] == "NOT_CONFIGURED"
    assert mapping["display_status"] == "Not configured"
    assert mapping["is_legacy"] is False

def test_build_identity_mapping_legacy():
    mapping = build_identity_mapping(external_iam_tenant_id="old-tenant", is_legacy=True)
    assert mapping["state"] == "LEGACY"
    assert mapping["display_status"] == "Legacy record"
    assert mapping["is_legacy"] is True
