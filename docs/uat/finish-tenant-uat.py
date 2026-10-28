"""Exercise tenant activation with only this UAT's disposable administrator."""
import json
import re
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FOLDER = Path('/Users/ferozebasha/sbom/docs/uat/evidence/2026-10-19')
cases = json.loads((FOLDER / 'extended-cases.json').read_text())
seeded = json.loads(Path('/Users/ferozebasha/.sbom-greenfield-uuid/users.json').read_text())

def request(endpoint, method='GET', payload=None, token=None, tenant=None, mail=False):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if tenant:
        headers['X-Tenant-ID'] = tenant
    base = 'http://127.0.0.1:8026' if mail else 'http://127.0.0.1:18000'
    req = urllib.request.Request(base + endpoint, method=method, headers=headers, data=json.dumps(payload).encode() if payload is not None else None)
    try:
        result = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as error:
        result = error
    return result.status, json.load(result), result.headers.get('x-request-id')

def record(identifier, expected, actual, passed, steps, status=None):
    global cases
    case = {'id': identifier, 'module': 'Tenant Management', 'role': 'platform/disposable tenant administrator', 'preconditions': 'Only UAT-created tenant and administrator; local Mailpit; seeded accounts unchanged', 'steps': steps, 'expected': expected, 'actual': actual, 'api': status, 'status': 'PASS' if passed else 'FAIL', 'defect': None, 'time': datetime.now(timezone.utc).isoformat()}
    cases = [c for c in cases if c['id'] != identifier] + [case]
    (FOLDER / 'extended-cases.json').write_text(json.dumps(cases, indent=2))
    print(identifier, case['status'], status)

creation = next(c for c in cases if c['id'] == 'UAT-TENANT-CREATE')['actual']
tenant_id = creation['tenant']['id']
email = creation['initial_administrator']['email']
if not creation['tenant']['name'].startswith('UAT Tenant ') or not email.startswith('uat-tenant-admin-'):
    raise SystemExit('Disposable ownership guard failed')
old = next(c for c in cases if c['id'] == 'UAT-TENANT-ACTIVE')
record('UAT-TENANT-ACTIVATE-PENDING-ADMIN', 'Activation is rejected with 409 while the only administrator is unverified', old['actual'], old['actual']['status'] == 409, 'Attempt activation before initial administrator completes the invitation', old['actual']['status'])
_, login, _ = request('/api/auth/native/login', 'POST', {k: seeded['platform'][k] for k in ('email', 'password')})
platform_token = login['access_token']
status, tenant, _ = request('/api/platform/tenants/' + tenant_id, token=platform_token)
if status != 200 or not tenant['name'].startswith('UAT Tenant '):
    raise SystemExit('Live disposable ownership guard failed')
_, mailbox, _ = request('/api/v1/messages', mail=True)
mail = next((m for m in mailbox.get('messages', []) if any(t['Address'] == email for t in m.get('To', []))), None)
if not mail:
    raise SystemExit('Disposable tenant activation mail not yet available; no state changed')
_, message, _ = request('/api/v1/message/' + mail['ID'], mail=True)
match = re.search(r'[#?&]token=([A-Za-z0-9_-]+)', message.get('Text') or message.get('HTML') or '')
if not match:
    raise SystemExit('Activation link missing; message withheld')
password = 'Uat!' + secrets.token_urlsafe(24)
status, activated, rid = request('/api/auth/native/activate', 'POST', {'token': match.group(1), 'password': password})
record('UAT-TENANT-ADMIN-ACTIVATION', 'Local invitation activates the UAT-created initial administrator', {'status': status, 'account_status': activated.get('status'), 'request_id': rid, 'mail_recipient': email}, status == 200, 'Consume only UAT tenant administrator Mailpit activation link through Native API; password stays in memory', status)
status, result, rid = request('/api/platform/tenants/' + tenant_id, 'PATCH', {'status': 'ACTIVE'}, token=platform_token)
record('UAT-TENANT-ACTIVE', 'Verified effective administrator permits tenant activation', {'status': status, 'result': result, 'request_id': rid}, status == 200 and result.get('status') == 'ACTIVE', 'Activate only UAT-created tenant after initial administrator activation', status)
status, user_login, _ = request('/api/auth/native/login', 'POST', {'email': email, 'password': password})
user_token = user_login.get('access_token')
if user_token:
    me_status, me, _ = request('/api/auth/me', token=user_token, tenant=tenant_id)
    record('UAT-TENANT-ADMIN-CONTEXT', 'New initial administrator resolves only its authorized tenant context', {'login_status': status, 'me_status': me_status, 'tenant_id': me.get('tenant_id'), 'roles': me.get('roles')}, status == 200 and me_status == 200 and me.get('tenant_id') == tenant_id and me.get('roles') == ['TENANT_ADMIN'], 'Native Login newly activated disposable administrator; read its authorized context', me_status)
status, result, rid = request('/api/platform/tenants/' + tenant_id, 'PATCH', {'status': 'DISABLED'}, token=platform_token)
record('UAT-TENANT-CLEANUP-DISABLED', 'Leave disposable tenant disabled after activation test', {'status': status, 'result': result, 'request_id': rid}, status == 200 and result.get('status') == 'DISABLED', 'Disable only UAT-created tenant; no seeded tenant status changes', status)
if user_token:
    status, denied, rid = request('/api/projects', token=user_token, tenant=tenant_id)
    record('UAT-TENANT-INACTIVE-DENIAL', 'Disabled tenant prevents protected project access for its administrator', {'status': status, 'result': denied, 'request_id': rid}, status == 403, 'Use existing disposable administrator token after its tenant is disabled', status)
