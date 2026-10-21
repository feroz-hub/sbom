import importlib.util,json,subprocess
from pathlib import Path
s=importlib.util.spec_from_file_location('m',Path(__file__).with_name('live-common.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);f=m.create_tenant()
try:
 target={'user_id':f['user_id'],'email':f['email'],'tenant_id':m.USERS['admin']['tenant_id'],'owned':'Round3','original_tenant_id':f['tenant_id']};(m.OUT/'membership-fixture.json').write_text(json.dumps(target,indent=2))
 node='/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node';r=subprocess.run([node,'--use-system-ca',str(m.OUT/'browser-membership.cjs'),'membership-round3'],cwd=m.OUT);print('Membership browser exit',r.returncode)
finally:
 # Browser owns cleanup of its new Olympus membership; do not remove any other membership.
 r=m.call('/api/platform/tenants/'+f['tenant_id'],'PATCH',{'status':'DISABLED'},role='platform');m.rec('R3-MEMBERSHIP-OWNED-TENANT-CLEANUP','Disable only newly created fixture tenant','200',m.payload(r),r.status_code==200,file='membership-cleanup.json')
