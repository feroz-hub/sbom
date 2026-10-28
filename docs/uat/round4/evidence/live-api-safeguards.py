"""Read-only real Native authentication and six-role context evidence; secrets stay in memory."""
import json
from datetime import datetime, timezone
from pathlib import Path

import requests

D=Path(__file__).resolve().parent
users=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
base='http://127.0.0.1:18000'
rows=[]
for role, account in users.items():
    login=requests.post(base+'/api/auth/native/login',json={k:account[k] for k in ('email','password')},timeout=45)
    assert login.status_code==200, 'Native authentication failed: '+role
    bearer=login.json()['access_token']
    headers={'Authorization':'Bearer '+bearer}
    initial=requests.get(base+'/api/auth/context',headers=headers,timeout=45)
    assert initial.status_code==200
    if account.get('tenant_id'):
        headers['X-Tenant-ID']=account['tenant_id']
    me=requests.get(base+'/api/auth/me',headers=headers,timeout=45)
    context=requests.get(base+'/api/auth/context',headers=headers,timeout=45)
    assert me.status_code==context.status_code==200
    m=me.json();c=context.json();tenant=m.get('tenant_id')
    assert tenant==account.get('tenant_id'), 'Seeded tenant context changed: '+role
    if role=='platform':
        assert m.get('is_platform_admin') and tenant is None
    else:
        assert not m.get('is_platform_admin')
    session=requests.get(base+'/api/auth/native/session',headers=headers,timeout=45)
    assert session.status_code==200 and session.json()['authenticated']
    rows.append({'id':'R4-LIVE-'+role.upper(),'role':role,'result':'PASS','login':login.status_code,'me':me.status_code,'context':context.status_code,'session':session.status_code,'tenant_id':tenant,'roles':m.get('roles'),'initialAuthorizationState':initial.json().get('status'),'authorizationState':c.get('status'),'provider':session.json()['provider']})
    # This endpoint records logout; it does not revoke the signed bearer.
    # BFF session destruction and absolute expiry are covered independently.
    logout=requests.post(base+'/api/auth/native/logout',headers=headers,timeout=45)
    assert logout.status_code==200
    rows[-1]['logoutAuditStatus']=logout.status_code
    del bearer
admin=users['admin']
login=requests.post(base+'/api/auth/native/login',json={k:admin[k] for k in ('email','password')},timeout=45)
headers={'Authorization':'Bearer '+login.json()['access_token'],'X-Tenant-ID':admin['tenant_id']}
r=requests.get(base+'/api/tenants/'+admin['tenant_id']+'/users',headers=headers,timeout=45)
assert r.status_code==200
body=r.json();members=body if isinstance(body,list) else body['items']
seeded=[m for m in members if m['email'] in {users[k]['email'] for k in ('admin','analyst','developer','viewer')}]
assert len(members)==len(seeded)==4
rows.append({'id':'R4-LIVE-OLYMPUS-MEMBERS','result':'PASS','status':r.status_code,'memberCount':len(members),'members':[{'email':m['email'],'roles':m['roles'],'membershipStatus':m.get('membership_status',m.get('status')),'accountStatus':m.get('user_status',m.get('account_status')),'verified':m.get('email_verified')} for m in seeded]})
for m in rows[-1]['members']:
    assert m['membershipStatus']=='ACTIVE' and m['accountStatus']=='ACTIVE' and m['verified'] is True
requests.post(base+'/api/auth/native/logout',headers=headers,timeout=45)
(D/'live-api-safeguards.json').write_text(json.dumps({'time':datetime.now(timezone.utc).isoformat(),'checks':rows,'secretsRecorded':False,'seededCredentialsRolesMembershipsChanged':False},indent=2)+'\n')
print('Real API safeguards:',len(rows),'PASS')
