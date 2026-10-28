"""Read-only collection metadata; never changes test selection or outcome."""
import json
from pathlib import Path

def pytest_collection_finish(session):
 if not session.config.option.collectonly:
  return
 rows=[]
 for item in session.items:
  names=sorted({m.name for m in item.iter_markers()});node=item.nodeid;fixtures=list(getattr(item,'fixturenames',[]));s=node.lower()
  category=('AI/provider' if '/ai/' in s or 'provider' in s else 'Authentication/authorization' if any(t in s for t in ('native','auth','permission','platform','tenant_user')) else 'UUID public API' if any(t in s for t in ('uuid','public_identity','public_boundary')) else 'Vulnerability/VEX' if any(t in s for t in ('vex','vulnerability','osv','kev','source_')) else 'Advisor/policies' if any(t in s for t in ('advisor','policy')) else 'Scheduling/reporting' if any(t in s for t in ('schedul','report','notification')) else 'Ingestion/validation' if any(t in s for t in ('validation','sbom','repair','parsing','ingest')) else 'Lifecycle' if 'lifecycle' in s else 'Other unit/integration')
  rows.append({'nodeid':node,'markers':names,'fixtures':fixtures,'category':category,'defaultExcluded':bool({'integration','bench'}&set(names)),'defaultExclusionReason':'Repository default addopts excludes integration and bench' if {'integration','bench'}&set(names) else None,'databaseFixture':any('db' in f or 'postgres' in f for f in fixtures),'environmentOrExternalHint':any(t in s for t in ('http_acceptance','real_provider','external','smoke','dev_launcher'))})
 Path(__file__).with_name('pytest-inventory.json').write_text(json.dumps(rows,indent=2)+'\n')
