"""Read-only diagnosis of the observed VEX response validation failure."""
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path('/Users/ferozebasha/sbom')
pid = subprocess.check_output(['/usr/sbin/lsof', '-tiTCP:18000', '-sTCP:LISTEN'], text=True).split()[0]
environment = subprocess.check_output(['/bin/ps', 'eww', '-p', pid, '-o', 'command='], text=True)
match = re.search(r'(?:^|\s)DATABASE_URL=([^\s]+)', environment)
if not match or not match.group(1).endswith('/sbom_greenfield_uuid'):
    raise SystemExit('Declared greenfield database could not be verified')
os.environ['DATABASE_URL'] = match.group(1)
os.environ['PYTHON_DOTENV_DISABLED'] = '1'

from pydantic import ValidationError
from app.core.context import CurrentContext, tenant_scope
from app.db import engine, SessionLocal
from app.models import VexInvestigation
from app.routers.vex_investigations import _detail_payload
from app.schemas_vex import InvestigationDetail

context = CurrentContext(user_id=1, external_user_id='', email='admin@olympus.example.test', display_name='Synthetic Olympus admin', tenant_id=1, external_tenant_id=None, roles=frozenset({'TENANT_ADMIN'}), permissions=frozenset({'vex:read', 'vex:write'}))
findings = []
with engine.connect() as connection:
    connection.exec_driver_sql('SET TRANSACTION READ ONLY')
    with tenant_scope(context), SessionLocal(bind=connection) as db:
        row = db.get(VexInvestigation, 42)
        if row is None:
            raise SystemExit('UAT-created investigation is unavailable')
        payload = _detail_payload(db, row, context)
        try:
            InvestigationDetail.model_validate(payload)
        except ValidationError as error:
            findings = [{'location': list(e['loc']), 'type': e['type'], 'message': e['msg'], 'input_type': type(e.get('input')).__name__} for e in error.errors()]
        db.rollback()
    connection.rollback()
result = {'read_only': True, 'investigation_id': 42, 'validation_errors': findings}
(ROOT / 'docs/uat/evidence/2026-10-19/vex-detail-validation.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
