"""One deliberate source-document probe; never retries a failed mutation."""
import importlib.util,json,uuid
from pathlib import Path
out=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('api',out.parent/'2026-10-20-round1/live-api.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
f=json.loads((out/'fixtures.json').read_text());doc=json.loads(Path('tests/fixtures/vex/supplier-csaf.json').read_text())
doc['document']['tracking']['id']='UAT-R2-'+str(uuid.uuid4())
r=m.api('admin','/api/sboms/'+f['sbom_id']+'/vex','POST',{'document':doc})
(out/'api-vex-source-document-before.json').write_text(json.dumps({'id':'R2-VEX-CSAF-PRODUCT-IDENTITY','preconditions':'Only retained UAT fixture SBOM; one deliberate import request','expected':'Source-native CSAF IDs are not application Product UUIDs','actual':r,'replayed':False},indent=2))
print('Source-document probe HTTP',r['status'])
