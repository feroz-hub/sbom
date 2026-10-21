"""Reconcile artifacts against the pre-existing dirty checkout without Git mutation."""
from pathlib import Path
import json,hashlib,difflib,subprocess,re
out=Path(__file__).resolve().parent
root=out.parents[3]
initial=json.loads((out/'workspace-before-sha256.json').read_text());changed=[];patch=[]
for f,h in initial.items():
 if not f.startswith(('app/','tests/','frontend/src/','docs/plans/','docs/secure-component-advisor/')):continue
 p=root/f
 if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()!=h:
  changed.append(f);patch.extend(difflib.unified_diff((out/'before'/f).read_text().splitlines(True),p.read_text().splitlines(True),fromfile='a/'+f,tofile='b/'+f))
for f in ['tests/test_policy_public_identity.py','tests/test_vex_source_public_identity.py','frontend/src/components/admin/PlatformKevSync.tsx','frontend/src/components/admin/PlatformKevSync.test.tsx']:
 if f not in initial:
  changed.append(f);patch.extend(difflib.unified_diff([],(root/f).read_text().splitlines(True),fromfile='/dev/null',tofile='b/'+f))
(out/'source.patch').write_text(''.join(patch));(out/'changed-files.json').write_text(json.dumps(changed,indent=2));(out/'source-final-sha256.json').write_text(json.dumps({f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in changed},indent=2))
protected=json.loads((out/'protected-evidence-sha256.json').read_text());bad=[f for f,h in protected.items() if not(root/f).is_file() or hashlib.sha256((root/f).read_bytes()).hexdigest()!=h]
master=root/'docs/uat/SBOM_ANALYZER_FULL_UAT_REPORT.md';old=(out/'before/docs/uat/SBOM_ANALYZER_FULL_UAT_REPORT.md').read_bytes()
remaining=[f for f,h in initial.items() if (root/f).is_file() and hashlib.sha256((root/f).read_bytes()).hexdigest()!=h and f not in changed and f!='docs/uat/SBOM_ANALYZER_FULL_UAT_REPORT.md']
removed=[f for f in initial if not(root/f).is_file()]
users=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text());secrets=[]
for p in out.rglob('*'):
 if not p.is_file() or p.suffix=='.png':continue
 try:s=p.read_text()
 except UnicodeDecodeError:continue
 if any(u['password'] in s for u in users.values()):secrets.append(str(p.relative_to(out)))
 if ('-----BEGIN '+'PRIVATE KEY-----') in s or ('-----BEGIN '+'RSA PRIVATE KEY-----') in s:secrets.append(str(p.relative_to(out)))
# Report validity, never the credential values or encrypted session data.
checks={'protectedEvidenceFiles':len(protected),'protectedEvidenceChanged':bad,'originalMasterIsUnchangedPrefix':master.read_bytes().startswith(old),'originalCaseCount':len(json.loads((out/'baseline-case-index.json').read_text())),'preexistingFilesRemoved':removed,'preexistingChangesOutsideRound2Scope':remaining,'round1VexSourceUnchanged':hashlib.sha256((root/'app/routers/vex_investigations.py').read_bytes()).hexdigest()==initial['app/routers/vex_investigations.py'],'round1DashboardParserUnchanged':hashlib.sha256((root/'frontend/src/lib/dashboardScopeUrl.ts').read_bytes()).hexdigest()==initial['frontend/src/lib/dashboardScopeUrl.ts'],'discoveryPolicySourceUnchanged':hashlib.sha256((root/'app/routers/tenants.py').read_bytes()).hexdigest()==initial['app/routers/tenants.py'],'secretMatches':secrets}
whitespace=subprocess.run(['git','-c','core.fsmonitor=false','diff','--check'],cwd=root,capture_output=True,text=True);checks['whitespaceExit']=whitespace.returncode
checks['result']='PASS' if not(bad or remaining or removed or secrets) and checks['originalMasterIsUnchangedPrefix'] and checks['round1VexSourceUnchanged'] and checks['round1DashboardParserUnchanged'] and checks['discoveryPolicySourceUnchanged'] and whitespace.returncode==0 else 'FAIL'
(out/'git-status-final.txt').write_bytes(subprocess.check_output(['git','-c','core.fsmonitor=false','status','--porcelain=v1','--untracked-files=all'],cwd=root));(out/'final-verification.json').write_text(json.dumps(checks,indent=2));print(json.dumps(checks,indent=2))
assert checks['result']=='PASS'
