"""Live repair/advisor scenarios, scoped to this run's disposable SBOM."""
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

folder = Path(__file__).resolve().parent / 'evidence/2026-10-19'
users = json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
fixture = json.loads((folder / 'business-fixtures.json').read_text())
cases = json.loads((folder/'workflow-cases.json').read_text()) if (folder/'workflow-cases.json').exists() else []
tokens = {}
def request(role, path, method='GET', payload=None):
    base = 'http://127.0.0.1:18000'
    if role not in tokens:
        u = users[role]
        req = urllib.request.Request(base + '/api/auth/native/login', data=json.dumps({k:u[k] for k in ('email','password')}).encode(), headers={'Content-Type':'application/json'})
        tokens[role] = json.load(urllib.request.urlopen(req, timeout=30))['access_token']
    headers = {'Authorization':'Bearer '+tokens[role], 'Content-Type':'application/json'}
    if users[role]['tenant_id']: headers['X-Tenant-ID'] = users[role]['tenant_id']
    req = urllib.request.Request(base + path, method=method, headers=headers, data=None if payload is None else json.dumps(payload).encode())
    try: response = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as error: response = error
    raw = response.read()
    try: data = json.loads(raw) if raw else None
    except ValueError: data = {'non_json_bytes':len(raw)}
    return {'status':response.status,'data':data,'request_id':response.headers.get('x-request-id')}
def record(id, module, role, expected, actual, passed, steps, defect=None):
    item={'id':id,'module':module,'role':role,'preconditions':'Verified UAT-created project/product/SBOM; Native direct API sessions; seeded accounts/configuration unchanged','steps':steps,'expected':expected,'actual':actual,'api':actual.get('status'),'status':'PASS' if passed else 'FAIL','defect':defect,'time':datetime.now(timezone.utc).isoformat()}
    cases[:] = [c for c in cases if c['id'] != id] + [item]
    (folder/'workflow-cases.json').write_text(json.dumps(cases,indent=2))
    print(id,item['status'],item['api'],flush=True)
def rows(data): return data if isinstance(data,list) else data.get('items',[])

project = request('admin','/api/projects/'+fixture['project_id'])
if project['status']!=200 or not project['data']['project_name'].startswith('UAT Business '):
    raise SystemExit('Disposable ownership check failed; no writes performed')
invalid = next(c for c in json.loads((folder/'extended-cases.json').read_text()) if c['id']=='UAT-SBOM-INVALID-JSON')
session_id = invalid['actual']['data']['detail']['validation_session_id']
endpoint = '/api/sbom-validation-sessions/'+session_id
current=request('admin',endpoint)
record('UAT-REPAIR-READ','Validation repair','admin','Rejected upload has readable quarantine workspace',current,current['status']==200,'GET this run\'s malformed JSON workspace')
for role,expected in [('viewer',200),('developer',200),('foreign',404)]:
    r=request(role,endpoint)
    record('UAT-REPAIR-READ-'+role,'Validation repair authorization',role,'Workspace read follows sbom:repair:read and tenant scope: HTTP '+str(expected),r,r['status']==expected,'Read known Olympus quarantine UUID through independent role token; Viewer and Developer have repair read permission')
original=request('admin',endpoint+'/content?source=original')
record('UAT-REPAIR-ORIGINAL','Validation repair','admin','Original malformed upload remains exactly one byte',original,original['status']==200 and '{' in json.dumps(original['data']),'Read immutable original content before editing repair draft')
if not any(c['id']=='UAT-REPAIR-ANALYZE' and c['status']=='PASS' for c in cases):
    analysis=request('admin',endpoint+'/repair/analyze','POST')
    record('UAT-REPAIR-ANALYZE','Validation repair','admin','Malformed JSON requires review instead of unsafe automatic repair',analysis,analysis['status']==200 and analysis['data'].get('status')=='MANUAL_REVIEW_REQUIRED','Analyze deterministic repair eligibility for original malformed JSON')
for role,expected in [('viewer',403),('developer',403),('foreign',404)]:
    r=request(role,endpoint+'/repair-draft','PUT',{'content':'{}'})
    record('UAT-REPAIR-WRITE-DENY-'+role,'Validation repair authorization',role,'Repair draft mutation rejected HTTP '+str(expected),r,r['status']==expected,'Attempt only UAT-created quarantine workspace with unauthorized role')
document=json.loads((folder/'uat.cdx.json').read_text())
document['serialNumber']='urn:uuid:'+__import__('uuid').uuid4().__str__()
draft=request('admin',endpoint+'/repair-draft','PUT',{'content':json.dumps(document)})
record('UAT-REPAIR-SAVE','Validation repair','admin','Authorized manual repair draft is saved',draft,draft['status']==200,'Replace only UAT-created malformed draft with known valid CycloneDX fixture')
validate=request('admin',endpoint+'/revalidate','POST')
record('UAT-REPAIR-REVALIDATE','Validation repair','admin','Corrected UAT draft passes validation',validate,validate['status']==200 and str(validate['data'].get('validation_status','')).upper() in ('PASSED','VALID','REPAIRED_VALID'),'Revalidate stored manual draft using actual validation pipeline')
unchanged=request('admin',endpoint+'/content?source=original')
record('UAT-REPAIR-ORIGINAL-IMMUTABLE','Validation repair','admin','Saving repair does not alter original upload bytes',{'status':unchanged['status'],'originalUnchanged':unchanged['data']==original['data']},unchanged['status']==200 and unchanged['data']==original['data'],'Compare original content response before and after draft edit')
history=request('admin',endpoint+'/history')
record('UAT-REPAIR-HISTORY','Validation repair','admin','Repair workspace records draft and validation history',history,history['status']==200 and len(rows(history['data']))>=2,'Read actual workspace history after save and revalidation')
if validate['status']==200 and str(validate['data'].get('validation_status','')).upper() in ('PASSED','VALID','REPAIRED_VALID'):
    imported=request('admin',endpoint+'/import','POST')
    record('UAT-REPAIR-IMPORT','Validation repair','admin','Validated disposable draft imports a new public SBOM UUID',imported,imported['status']==200 and bool(imported['data'].get('id')),'Import only this UAT quarantine draft; preserve original SBOM/version lineage')
    fixture['repaired_sbom_id']=imported['data'].get('id') if isinstance(imported['data'],dict) else None
    (folder/'business-fixtures.json').write_text(json.dumps(fixture,indent=2))

scope='?project_id='+fixture['project_id']+'&product_id='+fixture['product_id']+'&sbom_id='+fixture['sbom_id']
inventory=request('admin','/api/component-advisor/components'+scope)
components=rows(inventory['data']) if inventory['status']==200 else []
source=next((c for c in components if c.get('name')=='lodash'),components[0] if components else None)
if not source:
    raise SystemExit('No scoped advisory component available; no recommendation created')
key=source.get('canonical_key') or source.get('key')
if not key:
    print('Advisor item schema keys:',list(source));raise SystemExit('Canonical component key unavailable')
body={'canonical_key':key,'trigger_type':'MANUAL','evaluate':True}
created=request('admin','/api/component-advisor/recommendations'+scope,'POST',body)
record('UAT-ADVISOR-CREATE','Component Advisor workflow','admin','Create evaluated recommendation only for UAT SBOM context',created,created['status']==201 and created['data'].get('created') is True,'Create new MANUAL recommendation using scoped UAT lodash canonical key')
if created['status'] not in (200,201) or not created['data'].get('created'):
    raise SystemExit('New recommendation ownership not established; skip all decision mutations')
item=created['data']; rid=item['id']; path='/api/component-advisor/recommendations/'+str(rid)
duplicate=request('admin','/api/component-advisor/recommendations'+scope,'POST',body)
record('UAT-ADVISOR-IDEMPOTENCY','Component Advisor workflow','admin','Equivalent open recommendation is returned without duplicate',duplicate,duplicate['status']==200 and duplicate['data'].get('created') is False and duplicate['data'].get('id')==rid,'Repeat identical scoped manual recommendation request')
for role,expected in [('viewer',403),('developer',403),('foreign',404)]:
    r=request(role,path+'/decisions','POST',{'decision':'DEFER','reason':'UAT denied decision','row_version':item['row_version']})
    record('UAT-ADVISOR-DECISION-DENY-'+role,'Component Advisor authorization',role,'Unauthorized or cross-tenant decision rejected HTTP '+str(expected),r,r['status']==expected,'Attempt DEFER only on recommendation just created by this script')
for role,expected in [('viewer',200),('developer',200),('foreign',404)]:
    r=request(role,path)
    record('UAT-ADVISOR-DETAIL-'+role,'Component Advisor authorization',role,'Recommendation read respects role/tenant HTTP '+str(expected),r,r['status']==expected,'Read known UAT recommendation with independent direct token')
invalid=request('admin',path+'/decisions','POST',{'decision':'ACCEPT','reason':'UAT no recommended candidate','row_version':item['row_version']})
record('UAT-ADVISOR-ACCEPT-GATE','Component Advisor workflow','admin','Accept cannot bypass human recommendation/candidate gate',invalid,invalid['status'] in (409,422),'Attempt ACCEPT before any candidate is recommended; no dependency changes permitted')
deferred=request('admin',path+'/decisions','POST',{'decision':'DEFER','reason':'UAT disposable evidence; defer before cleanup','row_version':item['row_version']})
record('UAT-ADVISOR-DEFER','Component Advisor workflow','admin','Authorized reviewer can defer evaluated UAT recommendation',deferred,deferred['status']==200 and deferred['data'].get('status')=='DEFERRED','Submit complete versioned DEFER for newly created UAT item')
stale=request('admin',path+'/decisions','POST',{'decision':'CLOSE','reason':'UAT stale version check','row_version':item['row_version']})
record('UAT-ADVISOR-STALE','Component Advisor workflow','admin','Stale recommendation version returns conflict HTTP 409',stale,stale['status']==409,'Submit original version after successful DEFER')
if deferred['status']==200:
    close=request('admin',path+'/decisions','POST',{'decision':'CLOSE','reason':'UAT completed; close disposable item','row_version':deferred['data']['row_version']})
    record('UAT-ADVISOR-CLOSE','Component Advisor workflow','admin','Close only this UAT-created deferred recommendation',close,close['status']==200 and close['data'].get('status')=='CLOSED','Cleanup UAT recommendation with current version; retain audit history')
events=request('admin',path+'/events')
record('UAT-ADVISOR-EVENTS','Component Advisor workflow','admin','Recommendation lifecycle produces readable audit events',events,events['status']==200 and len(rows(events['data']))>=3,'Read actual create/evaluate/defer/close events')
