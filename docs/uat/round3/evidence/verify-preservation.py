"""Read-only historical preservation and exact Round3 source delta, without Git reset/stash."""
from pathlib import Path
import hashlib,json,difflib,subprocess
ROOT=Path('/Users/ferozebasha/sbom');D=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
protected=json.loads((D/'protected-sha256.json').read_text());changed=[f for f,h in protected.items() if not(ROOT/f).is_file() or sha(ROOT/f)!=h]
before=json.loads((D/'workspace-before-sha256.json').read_text());diff=[];changes=[]
for f,h in before.items():
 p=ROOT/f
 if not p.is_file() or sha(p)==h:continue
 if not(f.startswith(('app/','tests/','frontend/src/')) or f in ('requirements.txt','pyproject.toml')):continue
 prior=D/'before'/f
 if f=='app/public_api.py' and not prior.exists():prior=D/'before/public_api.py'
 if prior.exists() and sha(prior)!=h:raise RuntimeError('Before snapshot mismatch: '+f)
 changes.append({'file':f,'beforeSha256':h,'afterSha256':sha(p),'beforeCopy':str(prior.relative_to(D)) if prior.exists() else None})
 if prior.is_file():diff.extend(difflib.unified_diff(prior.read_text().splitlines(True),p.read_text().splitlines(True),fromfile='before/'+f,tofile='after/'+f))
for f in ['app/validation/schemas/cyclonedx/jsf-0.82.schema.json','tests/test_repair_candidate_public_boundary.py','tests/test_round3_native_expiry.py','tests/validation/test_signed_schema_dependency.py','tests/public_id_fixture.py','tests/test_legacy_analysis_public_identity.py']:
 p=ROOT/f
 if f not in before and p.is_file():
  changes.append({'file':f,'newInRound3':True,'afterSha256':sha(p)})
  diff.extend(difflib.unified_diff([],p.read_text().splitlines(True),fromfile='/dev/null',tofile='after/'+f))
(D/'round3-source.patch').write_text(''.join(diff));(D/'round3-source-files.json').write_text(json.dumps(changes,indent=2)+'\n');(D/'historical-integrity.json').write_text(json.dumps({'protectedFiles':len(protected),'changed':changed,'unchanged':not changed,'branch':subprocess.check_output(['git','-c','core.fsmonitor=false','branch','--show-current'],cwd=ROOT,text=True).strip(),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()},indent=2)+'\n')
print('Protected',len(protected),'changed',len(changed),'Round3 source files',len(changes))
