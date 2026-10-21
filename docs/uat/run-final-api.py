"""Additional live controls, exports and disposable-record lifecycle checks."""
import io
import json
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

FOLDER = Path('/Users/ferozebasha/sbom/docs/uat/evidence/2026-10-19')
users = json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())
cases = json.loads((FOLDER / 'extended-cases.json').read_text())
tokens = {}
def request(role, endpoint, method='GET', body=None, binary=False):
    if role not in tokens:
        u = users[role]
        req = urllib.request.Request('http://127.0.0.1:18000/api/auth/native/login', data=json.dumps({'email':u['email'],'password':u['password']}).encode(),headers={'Content-Type':'application/json'})
        tokens[role] = json.load(urllib.request.urlopen(req, timeout=30))['access_token']
    headers = {'Authorization':'Bearer '+tokens[role], 'Content-Type':'application/json'}
    if users[role]['tenant_id']:
        headers['X-Tenant-ID'] = users[role]['tenant_id']
    req = urllib.request.Request('http://127.0.0.1:18000'+endpoint, method=method, headers=headers, data=json.dumps(body).encode() if body is not None else None)
    try:
        r = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as error:
        r = error
    data = r.read()
    return {'status':r.status, 'data':data if binary and r.status==200 else json.loads(data), 'request_id':r.headers.get('x-request-id')}
def record(identifier, module, role, expected, actual, status, steps, http=None, defect=None):
    global cases
    case={'id':identifier,'module':module,'role':role,'preconditions':'Live greenfield stack; private credentials in memory; only UAT-created records mutated','steps':steps,'expected':expected,'actual':actual,'api':http,'status':status,'defect':defect,'time':datetime.now(timezone.utc).isoformat()}
    cases=[c for c in cases if c['id']!=identifier]+[case]
    (FOLDER/'extended-cases.json').write_text(json.dumps(cases,indent=2))
    print(identifier,status,http)
def check(identifier,module,role,expected,result,passed,steps):
    record(identifier,module,role,expected,result,'PASS' if passed else 'FAIL',steps,result['status'])
def rows(data):
    return data if isinstance(data,list) else data.get('items',[])

f=json.loads((FOLDER/'business-fixtures.json').read_text());sid=f['sbom_id'];pid=f['project_id'];product=f['product_id']
r=request('admin','/api/projects/'+pid)
if r['status']!=200 or not r['data']['project_name'].startswith('UAT Business '):
    raise SystemExit('Disposable ownership guard failed')
r=request('admin','/api/projects/'+pid,'PATCH',{'project_details':'UAT confirmed project update'})
check('UAT-PROJECT-UPDATE','Projects','admin','Authorized project update persists on UAT record',r,r['status']==200 and r['data']['project_details']=='UAT confirmed project update','PATCH only UAT-created project')
r=request('admin',f"/api/runs/{f['run_id']}/findings");findings=rows(r['data'])
evidence={'status':r['status'],'findings':[{'vuln_id':v.get('vuln_id'),'source':v.get('source'),'severity':v.get('severity'),'component_id':v.get('component_id')} for v in findings]}
check('UAT-OSV-FINDING-EVIDENCE','Vulnerability analysis and OSV','admin','Persisted findings identify OSV as observed source',evidence,r['status']==200 and len(findings)==5 and all('OSV' in (v.get('source') or '') for v in findings),'Read actual findings for UAT run; provider transport cache-vs-outbound was not separately instrumented')
download=request('admin',f'/api/sboms/{sid}/reports/vulnerabilities.xlsx',binary=True)
if download['status']==200:
    archive=zipfile.ZipFile(io.BytesIO(download['data']));names=archive.namelist();bad=archive.testzip();xml='\n'.join(archive.read(n).decode('utf-8',errors='replace') for n in names if n.startswith('xl/') and n.endswith('.xml'))
    expected_ids=[v['vuln_id'] for v in findings];missing=[v for v in expected_ids if v not in xml]
    check('UAT-REPORT-XLSX-CONTENT','Reports','admin','XLSX archive is valid and includes all UAT finding identifiers',{'status':200,'zip_crc_error':bad,'contains_workbook':'xl/workbook.xml' in names,'finding_count':len(expected_ids),'missing_finding_ids':missing},bad is None and 'xl/workbook.xml' in names and not missing,'Download UAT report in memory; check ZIP CRC, workbook XML and finding identifiers; no production report saved')
for role,expected in [('viewer',403),('developer',403),('foreign',404)]:
    r=request(role,f'/api/sboms/{sid}/reports/vulnerabilities.xlsx')
    check('UAT-REPORT-EXPORT-DENY-'+role,'Reports authorization',role,'Report export enforces sbom:export and tenant scope',r,r['status']==expected,'GET UAT report independently of UI')
r=request('admin','/api/report-subscriptions','POST',{'scope':'SBOM','sbom_id':sid,'parts':['A'],'formats':['XLSX'],'enabled':False})
sub=r['data'].get('id')
check('UAT-REPORT-OWNERSHIP-SETUP','Reports authorization','admin','Create disabled disposable report subscription',{'status':r['status'],'id':sub},r['status']==201 and sub is not None,'Create disabled subscription for ownership controls')
if sub:
    for role in ('viewer','foreign'):
        denied=request(role,f'/api/report-subscriptions/{sub}','PATCH',{'enabled':False})
        check('UAT-REPORT-OWNERSHIP-'+role,'Reports authorization',role,'Other-user/cross-tenant subscription mutation is concealed with 404',denied,denied['status']==404,'PATCH only a disabled UAT-created subscription')
    # Successful DELETE has an empty response body.
    headers={'Authorization':'Bearer '+tokens['admin'],'X-Tenant-ID':users['admin']['tenant_id']}
    req=urllib.request.Request(f'http://127.0.0.1:18000/api/report-subscriptions/{sub}',method='DELETE',headers=headers)
    response=urllib.request.urlopen(req,timeout=30)
    check('UAT-REPORT-OWNERSHIP-CLEANUP','Reports authorization','admin','Remove only temporary ownership-test subscription',{'status':response.status},response.status==204,'DELETE newly created disabled subscription')
second=f.get('second_sbom_id')
if second:
    for status in ('INACTIVE','ACTIVE'):
        r=request('admin',f'/api/sboms/{second}/lifecycle','POST',{'status':status,'reason':'Disposable UAT lifecycle transition'})
        check('UAT-SBOM-LIFECYCLE-'+status,'SBOM lifecycle and versioning','admin','Authorized lifecycle transition returns expected status for UAT second revision',r,r['status']==200,'Transition only UAT-created second SBOM revision')
    history=request('admin',f'/api/sboms/{second}/lifecycle-history')
    check('UAT-SBOM-LIFECYCLE-HISTORY','SBOM lifecycle and versioning','admin','Lifecycle transition history is readable and nonempty',{'status':history['status'],'data':history['data']},history['status']==200 and bool(history['data']),'Read UAT revision lifecycle audit history')
    denied=request('viewer',f'/api/sboms/{second}/lifecycle','POST',{'status':'INACTIVE','reason':'UAT denied mutation'})
    check('UAT-SBOM-LIFECYCLE-DENY','SBOM authorization','viewer','Viewer lifecycle mutation rejected HTTP 403',denied,denied['status']==403,'POST valid lifecycle transition on UAT-owned revision')
r=request('admin',f'/api/products/{product}/schedule','POST',{'cadence':'CUSTOM','cron_expression':'0 2 1 * *','enabled':False})
dependency='croniter' in json.dumps(r['data'])
record('UAT-SCHEDULE-CUSTOM','Schedules','admin','Valid custom cron can be stored without enabling execution',r,'BLOCKED' if dependency else 'PASS' if r['status'] in (200,201) else 'FAIL','Submit valid disabled cron; inspect current optional parser prerequisite',r['status'],'ENV-002' if dependency else None)
if dependency:
    for c in cases:
        if c['id']=='UAT-SCHEDULE-VALIDATION':
            c['status']='BLOCKED';c['actual']['limitation']='The optional croniter parser is missing. Rejection did not establish invalid-cron syntax validation.';c['defect']='ENV-002'
    (FOLDER/'extended-cases.json').write_text(json.dumps(cases,indent=2))
if r['status'] in (200,201):
    # No custom schedule should remain active; this request was explicitly disabled.
    request('admin',f'/api/products/{product}/schedule','DELETE')
for role in ('analyst','developer','viewer','foreign','admin'):
    r=request(role,'/api/v1/kev/sync','POST',{'since':'2099-01-01','prune_stale':False})
    check('UAT-KEV-SYNC-DENY-'+role,'CISA KEV authorization',role,'Only current platform authority can sync the global catalogue',r,r['status']==403,'POST no-prune future cutoff with tenant role; no catalog change')
r=request('platform','/api/v1/kev/sync','POST',{'since':'2099-01-01','prune_stale':False})
check('UAT-KEV-SYNC-PLATFORM','CISA KEV','platform','Platform can fetch the actual CISA feed with no matching rows or destructive pruning',r,r['status']==200 and r['data'].get('upserted')==0,'POST future cutoff and prune_stale=false to exercise configured provider/auth without changing existing catalogue rows')
