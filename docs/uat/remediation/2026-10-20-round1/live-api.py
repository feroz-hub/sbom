"""Round 1 real HTTP acceptance; credentials never leave process memory."""
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[3]
USERS=json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
TOKENS={}
PHASE=sys.argv[1] if len(sys.argv)>1 else 'before'
CASES=[]
def api(role,path,method='GET',body=None,**kwargs):
    user=USERS[role]
    if role not in TOKENS:
        r=requests.post('http://127.0.0.1:18000/api/auth/native/login',json={k:user[k] for k in ('email','password')},timeout=30)
        if r.status_code!=200:raise RuntimeError('Native authentication unavailable for '+role)
        TOKENS[role]=r.json()['access_token']
    headers={'Authorization':'Bearer '+TOKENS[role]}
    if user.get('tenant_id'):headers['X-Tenant-ID']=user['tenant_id']
    r=requests.request(method,'http://127.0.0.1:18000'+path,headers=headers,json=body,timeout=180,**kwargs)
    try:data=r.json()
    except ValueError:data={'non_json_bytes':len(r.content)}
    return {'status':r.status_code,'data':data,'request_id':r.headers.get('x-request-id')}
def rows(data):return data if isinstance(data,list) else data.get('items',[])
def case(id,expected,actual,passed,role='admin'):
    CASES.append({'id':id,'phase':PHASE,'role':role,'expected':expected,'actual':actual,'result':'PASS' if passed else 'FAIL','time':datetime.now(timezone.utc).isoformat()})
    (OUT/('api-'+PHASE+'.json')).write_text(json.dumps(CASES,indent=2))
    print(id,CASES[-1]['result'],actual.get('status'),flush=True)
def create():
    name='UAT R1 '+str(time.time_ns())
    p=api('admin','/api/projects','POST',{'project_name':name,'project_status':1})
    assert p['status']==201
    pid=p['data']['id']
    p=api('admin',f'/api/projects/{pid}/products','POST',{'name':name+' Application','status':'active'})
    assert p['status']==201
    product=p['data']['id']
    doc=json.loads((ROOT/'docs/uat/evidence/2026-10-19/uat.cdx.json').read_text())
    doc['serialNumber']='urn:uuid:'+str(uuid.uuid4())
    r=api('admin','/api/sboms/upload','POST',data={'sbom_name':name+' SBOM','project_id':pid,'product_id':product},files={'file':('round1.cdx.json',json.dumps(doc),'application/json')})
    assert r['status']==202
    sid=r['data'].get('sbom_id') or r['data']['id']
    fixture={'project_id':pid,'product_id':product,'sbom_id':sid,'name':name}
    (OUT/'fixtures.json').write_text(json.dumps(fixture,indent=2))
    # Actual configured OSV application run; consume its terminal stream once.
    u=USERS['admin'];r=requests.post(f'http://127.0.0.1:18000/api/sboms/{sid}/analyze/stream',headers={'Authorization':'Bearer '+TOKENS['admin'],'X-Tenant-ID':u['tenant_id']},json={'sources':['OSV']},timeout=180)
    events=[]
    for block in r.text.split('\n\n'):
        if 'event: complete' in block:
            for line in block.splitlines():
                if line.startswith('data: '):events.append(json.loads(line[6:]))
    case('R1-SETUP-OSV','OSV produces real findings in disposable scope',{'status':r.status_code,'complete':events},r.status_code==200 and bool(events) and events[0].get('errors')==0)
    found=api('admin','/api/vex/investigations?sbom_id='+sid)
    assert found['status']==200 and rows(found['data'])
    fixture['investigation_id']=rows(found['data'])[0]['id']
    (OUT/'fixtures.json').write_text(json.dumps(fixture,indent=2))
    return fixture
def current(f):
    r=api('admin','/api/vex/investigations?sbom_id='+f['sbom_id'])
    return next(c for c in rows(r['data']) if c['id']==f['investigation_id'])
def main():
    f=create() if PHASE=='before' else json.loads((OUT/'fixtures.json').read_text())
    # Refuse mutation unless the target still belongs to this exact UAT project.
    p=api('admin','/api/projects/'+f['project_id']);assert p['status']==200 and p['data']['project_name']==f['name']
    path='/api/vex/investigations/'+str(f['investigation_id'])
    before=current(f);r=api('admin',path)
    case('UAT-VEX-DETAIL','Detail serializes analyzer confidence without HTTP 500',r,r['status']==200)
    version=before['row_version']
    history_before=sum(h['kind']=='decision' for h in r['data'].get('history',[])) if r['status']==200 else None
    reason='Round 1 '+PHASE+' one deliberate decision '+str(uuid.uuid4())
    decision=api('admin',path+'/decision','PUT',{'status':'UNDER_INVESTIGATION','row_version':version,'reason':reason})
    persisted=current(f)
    case('UAT-VEX-DECISION','One decision returns 200 with persisted row_version',{'status':decision['status'],'response':decision['data'],'beforeVersion':version,'persistedVersion':persisted['row_version'],'request_id':decision['request_id']},decision['status']==200 and decision['data']['row_version']==persisted['row_version'] and persisted['row_version']>version)
    # Never retry the failed mutation. A deliberate stale *different* request tests concurrency.
    stale=api('admin',path+'/decision','PUT',{'status':'AFFECTED','row_version':version,'reason':'Round 1 explicit stale concurrency probe'})
    after=current(f)
    case('UAT-VEX-STALE','Stale version returns 409 and does not mutate again',{'status':stale['status'],'response':stale['data'],'beforeStale':persisted,'afterStale':after,'request_id':stale['request_id']},stale['status']==409 and after['row_version']==persisted['row_version'] and after['effective_status']==persisted['effective_status'])
    if PHASE=='before':return
    detail=api('admin',path)
    history=detail['data'].get('history',[])
    case('R1-VEX-NO-DUPLICATE','One component audit plus one context audit are appended; stale request appends none',{'status':detail['status'],'decisionHistoryBefore':history_before,'decisionHistoryAfter':sum(h['kind']=='decision' for h in history),'reasonOccurrencesAcrossTwoAuditScopes':sum(h.get('reason')==reason and h['kind']=='decision' for h in history)},sum(h['kind']=='decision' for h in history)==history_before+2 and sum(h.get('reason')==reason and h['kind']=='decision' for h in history)==2)
    invalid=api('admin',path+'/decision','PUT',{'status':'NOT_AFFECTED','row_version':after['row_version'],'reason':'Round 1 missing justification'})
    case('UAT-VEX-VALIDATION','NOT_AFFECTED without justification is rejected with 422',invalid,invalid['status']==422)
    for role,expected in [('viewer',403),('developer',403),('foreign',404)]:
        denied=api(role,path+'/decision','PUT',{'status':'AFFECTED','row_version':after['row_version'],'reason':'Round 1 role/tenant negative'})
        case('UAT-VEX-DENY-'+role,'Unowned/foreign decision rejected HTTP '+str(expected),denied,denied['status']==expected,role)
    foreign=api('foreign',path);case('R1-VEX-FOREIGN-DETAIL','Cross-tenant detail concealed with 404',foreign,foreign['status']==404,'foreign')
    # Assign only the disposable investigation; seeded Developer membership is read, not changed.
    members=rows(api('admin','/api/tenants/'+USERS['admin']['tenant_id']+'/users')['data'])
    member=next(m for m in members if m['email']==USERS['developer']['email'])
    key='membership:'+str(member['membership_id'])
    assignment=api('admin',path+'/assignment','PUT',{'assigned_to':key,'row_version':after['row_version'],'reason':'Round 1 assigned Developer acceptance'})
    case('R1-VEX-ASSIGN','Assignment returns fully serialized detail',assignment,assignment['status']==200)
    owned=api('developer',path)
    case('UAT-VEX-ASSIGNED-DEVELOPER-DETAIL','Assigned Developer can read detail with update capability',owned,owned['status']==200 and owned['data']['capabilities']['can_update'],'developer')
    decision=api('developer',path+'/decision','PUT',{'status':'AFFECTED','row_version':owned['data']['row_version'],'reason':'Round 1 assigned Developer actual review'})
    case('UAT-VEX-ASSIGNED-DEVELOPER','Assigned Developer decision returns 200 with persisted state',decision,decision['status']==200 and decision['data']['effective_status']=='AFFECTED','developer')
    unassigned=api('admin',path+'/assignment','PUT',{'assigned_to':None,'row_version':decision['data']['row_version'],'reason':'Round 1 remove disposable assignment'})
    case('R1-VEX-UNASSIGN','Admin unassigns disposable context without changing seeded membership',unassigned,unassigned['status']==200)
    revoked=api('developer',path+'/decision','PUT',{'status':'UNDER_INVESTIGATION','row_version':unassigned['data']['row_version'],'reason':'Round 1 immediate ownership revocation control'})
    case('R1-VEX-OWNERSHIP-REVOKED','Previously assigned Developer immediately loses mutation authority',revoked,revoked['status']==403,'developer')
if __name__=='__main__':main()
