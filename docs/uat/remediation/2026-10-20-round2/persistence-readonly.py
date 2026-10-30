"""Read-only task-owned evidence: one intended statement and two audit scopes."""
import json,os
from pathlib import Path
from uuid import UUID
from sqlalchemy import select,func,text
from scripts.dev import GreenfieldStack
settings = GreenfieldStack.settings
os.environ.update(settings())
from app.db import SessionLocal
from app.models import Tenant,VexStatement,VexOverrideAudit,SBOMSource,VexDocument
from app.core.context import minimal_background_context,tenant_scope
out=Path(__file__).resolve().parent
cases=json.loads((out/'api-round1-final.json').read_text());decision=next(x for x in cases if x['id']=='UAT-VEX-DECISION');reason=decision['actual']['response']['internal_decision'].get('reason')
# Exact reason comes from the observed response history if the draft field differs.
if not reason:
 reason=next(x['reason'] for x in decision['actual']['response']['history'] if str(x.get('reason','')).startswith('Round 2 protection round1-final one deliberate decision'))
assert reason.startswith('Round 2 protection round1-final one deliberate decision')
users=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text());f=json.loads((out/'fixtures.json').read_text())
with SessionLocal() as db:
 tid=db.scalar(select(Tenant.id).where(Tenant.public_id==UUID(users['admin']['tenant_id'])))
 with tenant_scope(minimal_background_context(tid)):
  sbom=db.scalar(select(SBOMSource).where(SBOMSource.public_id==UUID(f['sbom_id'])));assert sbom.sbom_name.startswith('UAT R1 ')
  statements=db.scalar(select(func.count()).select_from(VexStatement).where(VexStatement.sbom_id==sbom.id,VexStatement.evidence_json["reason"].as_string()==reason))
  scoped=db.scalar(select(func.count()).select_from(VexOverrideAudit).where(VexOverrideAudit.investigation_id==f['investigation_id'],VexOverrideAudit.reason==reason))
  component=db.scalar(select(func.count()).select_from(VexOverrideAudit).where(VexOverrideAudit.investigation_id.is_(None),VexOverrideAudit.sbom_id==sbom.id,VexOverrideAudit.reason==reason))
  e={'readOnly':True,'manualStatements':statements,'investigationAudits':scoped,'componentAudits':component,'result':'PASS' if (statements,scoped,component)==(1,1,1) else 'FAIL'}
(out/'persistence-readonly.json').write_text(json.dumps(e,indent=2));print(e)
