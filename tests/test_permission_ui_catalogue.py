"""Frontend role-matrix fixtures must reflect the backend catalogue, never define policy."""
import json
from pathlib import Path
from app.core.permissions import ALL_PERMISSIONS, ROLE_PERMISSIONS

def test_frontend_permission_test_fixture_matches_authoritative_catalogue():
    data = json.loads((Path(__file__).parents[1] / 'frontend/src/test/permissionCatalogue.json').read_text())
    assert set(data['permissions']) == ALL_PERMISSIONS
    assert {role: set(values) for role, values in data['roles'].items()} == ROLE_PERMISSIONS
