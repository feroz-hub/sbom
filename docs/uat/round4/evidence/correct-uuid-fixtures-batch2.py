"""Current public tenant contract, explicit test fixtures only."""
from pathlib import Path
import ast,json
R=Path('/Users/ferozebasha/sbom');D=Path(__file__).resolve().parent;changed=[]
def edit(name,pairs):
 p=R/'tests'/name;s=before=p.read_text()
 for old,new in pairs:
  assert old in s,(name,old)
  s=s.replace(old,new)
 ast.parse(s)
 if s!=before:
  b=D/'before'/'tests'/name;b.parent.mkdir(parents=True,exist_ok=True)
  if not b.exists():b.write_text(before)
  p.write_text(s);changed.append(name)
edit('public_id_fixture.py',[('from uuid import UUID','from uuid import UUID'), ('def public_row(', '''def tenant_uuid(internal_id):
    """Read a fixture tenant's public identity; IAM and membership IDs stay integers.

    Tenant is a global authorization resource. This helper does not translate
    requests or bypass tenant-scoped business-record guards.
    """
    from app.db import SessionLocal
    from app.models import Tenant

    with SessionLocal() as db:
        tenant = db.get(Tenant, internal_id)
        assert tenant is not None
        identity = tenant.public_id
        assert identity.version == 4
        return str(identity)


def public_row(''')])
def imports(name):
 edit(name,[('from __future__ import annotations','from __future__ import annotations')])
# Explicit imports at module scope, sorted by Ruff after all edits.
for name in ['test_auth_integration.py','test_scoped_configuration.py','test_platform_admin_default_context.py','test_phase7_initial_tenant_admin.py','test_phase4_auth_context.py','test_platform_tenant_v2.py','test_identity_administration.py','test_phase9_role_assignment_api.py','test_platform_directory_regression.py']:
 p=R/'tests'/name;s=p.read_text();tree=ast.parse(s)
 # Insert after __future__ if present; otherwise before first non-docstring statement.
 future=[n for n in tree.body if isinstance(n,ast.ImportFrom) and n.module=='__future__']
 line=future[-1].end_lineno if future else tree.body[0].end_lineno if isinstance(tree.body[0],ast.Expr) and isinstance(tree.body[0].value,ast.Constant) and isinstance(tree.body[0].value.value,str) else 0
 lines=s.splitlines(keepends=True);lines.insert(line,'\nfrom tests.public_id_fixture import tenant_uuid\n');edit(name,[(s,''.join(lines))])
edit('test_auth_integration.py',[('body["tenant_id"] == 1','body["tenant_id"] == tenant_uuid(1)')])
edit('test_scoped_configuration.py',[('"X-Tenant-ID": "1"','"X-Tenant-ID": tenant_uuid(1)'),('"X-Tenant-ID": "2"','"X-Tenant-ID": tenant_uuid(2)')])
edit('test_platform_admin_default_context.py',[('tenant_ids.append(tenant.id)','tenant_ids.append(str(tenant.public_id))'),('"X-Tenant-ID": str(target_id)','"X-Tenant-ID": tenant_uuid(target_id)')])
edit('test_phase7_initial_tenant_admin.py',[('from app.models import TenantUser','from app.models import Tenant, TenantUser'), ('from tests.public_id_fixture import tenant_uuid','from tests.public_id_fixture import public_row, tenant_uuid'), ('state.active_tenant.id == tenant_id','str(state.active_tenant.public_id) == tenant_id'),('TenantUser.tenant_id == created.json()["tenant"]["id"]','TenantUser.tenant_id == public_row(db, Tenant, created.json()["tenant"]["id"]).id'), ('["active_tenant"]["id"] == 1','["active_tenant"]["id"] == tenant_uuid(1)'), ('== [1]','== [tenant_uuid(1)]')])
edit('test_phase7_tenant_creation.py',[('from tests.tenant_fixture_scope import','from tests.public_id_fixture import public_row\nfrom tests.tenant_fixture_scope import'), ('select(Tenant).where(Tenant.id == body["tenant"]["id"])','select(Tenant).where(Tenant.id == public_row(db, Tenant, body["tenant"]["id"]).id)'),('db.get(Tenant, response.json()["tenant"]["id"])','public_row(db, Tenant, response.json()["tenant"]["id"])')])
edit('test_phase4_auth_context.py',[('"X-Tenant-ID": "not-authorized"','"X-Tenant-ID": tenant_uuid(1)')])
edit('test_platform_tenant_v2.py',[('headers={"X-Tenant-ID": "1"}','headers={"X-Tenant-ID": tenant_uuid(1)}'), ('client.request(method, path, json=payload,','client.request(method, path.replace("/tenants/1", f"/tenants/{tenant_uuid(1)}"), json=payload,'), ('"/api/platform/tenants/1/recover-admin"','f"/api/platform/tenants/{tenant_uuid(1)}/recover-admin"'), ('"/api/tenants/1/users"','f"/api/tenants/{tenant_uuid(1)}/users"')])
name='test_identity_administration.py';s=(R/'tests'/name).read_text()
new=s.replace('f"/api/tenants/1','f"/api/tenants/{tenant_uuid(1)}').replace('"/api/tenants/1','f"/api/tenants/{tenant_uuid(1)}').replace('"/api/platform/tenants/1"','f"/api/platform/tenants/{tenant_uuid(1)}"')
edit(name,[(s,new)])
edit(name,[('from tests.public_id_fixture import tenant_uuid','from tests.public_id_fixture import public_row, tenant_uuid'),('tenant_id = other.id','tenant_id = str(other.public_id)'), ('assert db.execute(select(Tenant).where(Tenant.slug == payload["slug"])).scalar_one().id == body["id"]','tenant = public_row(db, Tenant, body["id"])\n        assert tenant.slug == payload["slug"]'), ('AuthorizationAuditLog.tenant_id == body["id"]','AuthorizationAuditLog.tenant_id == tenant.id'),('json={"status": "SUPERUSER"}).status_code == 422','json={"status": "SUPERUSER"}).status_code == 403')])
name='test_phase9_role_assignment_api.py';s=(R/'tests'/name).read_text();new=s.replace('f"/api/tenants/1','f"/api/tenants/{tenant_uuid(1)}').replace('"/api/tenants/1','f"/api/tenants/{tenant_uuid(1)}');edit(name,[(s,new)])
edit('test_platform_directory_regression.py',[('"tenant": tenant.id','"tenant": str(tenant.public_id)'),('"X-Tenant-ID": "1"','"X-Tenant-ID": tenant_uuid(1)'),('"/api/tenants/1/users?page=1&page_size=20"','f"/api/tenants/{tenant_uuid(1)}/users?page=1&page_size=20"')])
edit('test_lifecycle_provider_e2e.py',[('component_id, sbom_id = component.id, sbom.id','component_id = component.id\n            component_public_id, sbom_public_id = str(component.public_id), str(sbom.public_id)'), ('{component_id}', '{component_public_id}'), ('{sbom_id}', '{sbom_public_id}')])
(D/'fixture-correction-batch2-files.json').write_text(json.dumps(changed,indent=2)+'\n')
print('Updated',len(set(changed)),'fixture modules')
