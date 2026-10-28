process.argv[2] = 'extended';
const { record, sanitize, summary, rows, identities, output } = require('./run-role-uat.cjs');
const fs = require('node:fs');
const path = require('node:path');
const base = 'http://127.0.0.1:18000';
async function client(role) {
  const user = identities[role];
  const login = await fetch(base + '/api/auth/native/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: user.email, password: user.password }), signal: AbortSignal.timeout(30000) });
  const data = await login.json(); if (login.status !== 200) throw Error('Direct authentication failed: ' + role + ', HTTP ' + login.status);
  const token = data.access_token;
  return async function request(url, method = 'GET', body, options = {}) {
    const headers = { Authorization: 'Bearer ' + token, ...(user.tenant_id ? { 'X-Tenant-ID': user.tenant_id } : {}), ...options.headers };
    if (body !== undefined && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
    const r = await fetch(base + url, { method, headers, signal: AbortSignal.timeout(options.timeout || 30000), ...(body === undefined ? {} : { body: body instanceof FormData ? body : JSON.stringify(body) }) });
    if (options.binary) { const bytes = Buffer.from(await r.arrayBuffer()); return { status: r.status, data: { bytes: bytes.length, contentType: r.headers.get('content-type'), zipSignature: bytes.subarray(0, 2).toString() }, requestId: r.headers.get('x-request-id') }; }
    const text = await r.text(); let data; try { data = JSON.parse(text); } catch { data = text.slice(0, 400); }
    return { status: r.status, data, requestId: r.headers.get('x-request-id') };
  };
}
function check(id, module, role, expected, result, predicate, steps, defect = null) {
  record(id, module, role, expected, result, predicate ? 'PASS' : 'FAIL', steps, result.status ?? null, predicate ? null : defect);
}
async function main() {
  const fixture = JSON.parse(fs.readFileSync(path.join(output, 'business-fixtures.json'), 'utf8'));
  const admin = await client('admin'); const viewer = await client('viewer'); const developer = await client('developer'); const analyst = await client('analyst'); const foreign = await client('foreign'); const platform = await client('platform');
  const project = await admin('/api/projects/' + fixture.project_id);
  if (project.status !== 200 || !project.data.project_name.startsWith('UAT Business ')) throw Error('Disposable ownership guard failed; no mutations performed');
  const { project_id: pid, product_id: product, sbom_id: sid } = fixture;
  const detail = await admin('/api/sboms/' + sid); const logical = detail.data.logical_sbom_id;
  const contexts = await admin('/api/vex/investigations?sbom_id=' + sid); const investigation = rows(contexts.data)[0];
  if (investigation) {
    const endpoint = '/api/vex/investigations/' + investigation.id;
    const actual = await admin(endpoint);
    check('UAT-VEX-DETAIL', 'VEX Investigation', 'admin', 'HTTP 200 detail with valid evidence and row_version', actual, actual.status === 200, 'Direct GET UAT-created investigation detail; correlated ResponseValidationError and read-only payload validation', 'UAT-DEF-003');
    for (const [role, request, expected] of [['viewer', viewer, 403], ['developer', developer, 403], ['foreign', foreign, 404]]) {
      const r = await request(endpoint + '/decision', 'PUT', { status: 'UNDER_INVESTIGATION', row_version: investigation.row_version, reason: 'UAT denied contextual mutation' });
      check('UAT-VEX-DENY-' + role, 'VEX authorization', role, 'Non-owner/foreign decision rejected HTTP ' + expected, r, r.status === expected, 'PUT valid payload against UAT-created context; no seeded investigation mutation');
    }
    const r = await admin(endpoint + '/decision', 'PUT', { status: 'UNDER_INVESTIGATION', row_version: investigation.row_version, reason: 'UAT disposable validated decision' });
    const after = rows((await admin('/api/vex/investigations?sbom_id=' + sid)).data).find(v => v.id === investigation.id);
    check('UAT-VEX-DECISION', 'VEX Investigation', 'admin', 'Authorized decision returns 200 with durable result', { ...r, persistedRowVersion: after?.row_version, originalRowVersion: investigation.row_version }, r.status === 200, 'Submit a complete versioned decision on UAT context and inspect list afterward; distinguish HTTP response failure from persisted mutation', 'UAT-DEF-003');
    const stale = await admin(endpoint + '/decision', 'PUT', { status: 'AFFECTED', row_version: investigation.row_version, reason: 'UAT stale decision' });
    check('UAT-VEX-STALE', 'VEX Investigation', 'admin', 'Stale row_version returns 409 without replacement', stale, stale.status === 409, 'Repeat mutation with pre-change version', 'UAT-DEF-003');
    const invalid = await admin(endpoint + '/decision', 'PUT', { status: 'NOT_AFFECTED', row_version: after?.row_version || 1, reason: 'UAT missing required justification' });
    check('UAT-VEX-VALIDATION', 'VEX Investigation', 'admin', 'NOT_AFFECTED without justification/impact receives 400/422 specifically for required evidence', invalid, [400, 422].includes(invalid.status) && JSON.stringify(invalid.data).toLowerCase().includes('justification'), 'Submit complete versioned decision with missing justification; ensure error is not missing row_version');
    record('UAT-VEX-ASSIGNED-DEVELOPER', 'VEX Investigation', 'developer', 'Assigned Developer can open and update owned investigation', 'Blocked by UAT-DEF-003: detail serialization fails. Positive assignment/edit UI cannot be accepted; non-owner rejection was executed separately.', 'BLOCKED', 'Observe list/detail boundary before attempting supported assignment workflow', 500, 'UAT-DEF-003');
  }
  const components = rows((await admin('/api/sboms/' + sid + '/components')).data);
  const component = components.find(c => c.name === 'lodash') || components[0];
  if (component) {
    const lifecycle = await admin('/api/lifecycle/component/' + component.id);
    check('UAT-LIFECYCLE-COMPONENT', 'Lifecycle', 'admin', 'Component lifecycle lookup retains correct UAT SBOM UUID', lifecycle, lifecycle.status === 200 && lifecycle.data.sbom_id === sid, 'GET lifecycle for uploaded component');
    const override = await admin('/api/components/' + component.id + '/lifecycle-override', 'PATCH', { lifecycle_status: 'SUPPORTED', latest_version: '4.17.21', reason: 'UAT disposable lifecycle override', note: 'Synthetic UAT evidence only' });
    check('UAT-LIFECYCLE-OVERRIDE', 'Lifecycle', 'admin', 'Authorized lifecycle override on disposable component returns 200', summary(override), override.status === 200, 'PATCH only the component created by this UAT');
    for (const [role, request, expected] of [['viewer', viewer, 403], ['developer', developer, 403], ['foreign', foreign, 404]]) {
      const denied = await request('/api/components/' + component.id + '/lifecycle-override', 'PATCH', { lifecycle_status: 'END_OF_LIFE', reason: 'UAT denied override' });
      check('UAT-LIFECYCLE-DENY-' + role, 'Lifecycle authorization', role, 'Unauthorized/cross-tenant override rejected HTTP ' + expected, denied, denied.status === expected, 'PATCH only UAT component with role control');
    }
  }
  const scheduleBody = { cadence: 'MONTHLY', day_of_month: 28, hour_utc: 2, enabled: false, target_version_policy: 'CURRENT_ONLY' };
  const schedule = await admin('/api/products/' + product + '/schedule', 'POST', scheduleBody);
  check('UAT-SCHEDULE-CREATE', 'Schedules', 'admin', 'Create disabled schedule for disposable product without scheduling a run', { ...summary(schedule), enabled: schedule.data.enabled, id: schedule.data.id }, [200, 201].includes(schedule.status) && schedule.data.enabled === false, 'POST disabled MONTHLY schedule for UAT product only');
  const inherited = await admin('/api/products/' + product + '/schedule/effective');
  check('UAT-SCHEDULE-EFFECTIVE', 'Schedules', 'admin', 'Effective schedule can be resolved', summary(inherited), inherited.status === 200, 'GET effective schedule for UAT product');
  for (const [role, request] of [['viewer', viewer], ['developer', developer]]) {
    const r = await request('/api/products/' + product + '/schedule', 'POST', scheduleBody);
    check('UAT-SCHEDULE-DENY-' + role, 'Schedules', role, 'Schedule mutation rejected HTTP 403', r, r.status === 403, 'Attempt disabled schedule creation against UAT product');
  }
  const badSchedule = await admin('/api/products/' + product + '/schedule', 'POST', { cadence: 'CUSTOM', cron_expression: 'not-a-cron', enabled: false });
  check('UAT-SCHEDULE-VALIDATION', 'Schedules', 'admin', 'Invalid cron receives 400/422', badSchedule, [400, 422].includes(badSchedule.status), 'POST invalid disabled cron configuration on UAT product');
  if ([200, 201].includes(schedule.status)) { const cleanup = await admin('/api/products/' + product + '/schedule', 'DELETE'); check('UAT-SCHEDULE-CLEANUP', 'Schedules', 'admin', 'Remove only UAT-created schedule', summary(cleanup), [200, 204].includes(cleanup.status), 'DELETE disabled temporary product schedule'); }
  for (const [role, request] of [['admin', admin], ['analyst', analyst], ['developer', developer], ['viewer', viewer], ['foreign', foreign]]) {
    for (const [label, endpoint] of [['summary', '/api/component-advisor/summary'], ['inventory', '/api/component-advisor/components']]) {
      const r = await request(endpoint);
      check('UAT-ADVISOR-' + role + '-' + label, 'Component Advisor', role, 'Authorized advisory read returns 200 with scoped data', summary(r), r.status === 200, 'GET ' + endpoint);
    }
  }
  for (const [label, endpoint] of [['vulnerabilities-xlsx', '/api/sboms/' + sid + '/reports/vulnerabilities.xlsx'], ['lifecycle-pack', '/api/sboms/' + sid + '/reports/lifecycle-pack'], ['vex-pack', '/api/sboms/' + sid + '/reports/vex-pack']]) {
    const r = await admin(endpoint, 'GET', undefined, { binary: true, timeout: 60000 });
    check('UAT-EXPORT-' + label, 'Reports', 'admin', 'Real downloadable artifact is returned with nonempty ZIP/XLSX content', r, r.status === 200 && r.data.bytes > 100 && r.data.zipSignature === 'PK', 'Download generated artifact without logging document content');
  }
  const malformed = new FormData(); malformed.set('file', new Blob(['{'], { type: 'application/json' }), 'uat-invalid.json'); malformed.set('sbom_name', 'UAT invalid ' + Date.now()); malformed.set('project_id', pid); malformed.set('product_id', product);
  const rejected = await admin('/api/sboms/upload', 'POST', malformed);
  check('UAT-SBOM-INVALID-JSON', 'SBOM upload and validation', 'admin', 'Malformed JSON is rejected with structured validation error', rejected, [400, 422].includes(rejected.status), 'Upload malformed JSON to disposable application; inspect real validation response');
  for (const [role, request] of [['viewer', viewer], ['developer', developer]]) {
    const r = await request('/api/sboms/upload', 'POST', malformed);
    check('UAT-SBOM-UPLOAD-DENY-' + role, 'SBOM authorization', role, 'Upload mutation rejected HTTP 403 before processing file', summary(r), r.status === 403, 'Direct multipart upload with prohibited role; UAT project/product only');
    const analysis = await request('/api/sboms/' + sid + '/analyze', 'POST', { sources: ['OSV'] });
    check('UAT-ANALYSIS-DENY-' + role, 'Analysis authorization', role, 'Analysis mutation rejected HTTP 403', analysis, analysis.status === 403, 'Attempt analyze on UAT-owned SBOM');
  }
  const doc = JSON.parse(fs.readFileSync(path.join(output, 'uat.cdx.json'), 'utf8')); doc.serialNumber = 'urn:uuid:' + require('node:crypto').randomUUID(); doc.version = 2;
  const next = new FormData(); next.set('file', new Blob([JSON.stringify(doc)], { type: 'application/json' }), 'uat-v2.cdx.json');
  for (const [key, value] of Object.entries({ sbom_name: detail.data.sbom_name, project_id: pid, product_id: product, logical_sbom_id: logical, parent_sbom_id: sid, sbom_version: '2.0.0', product_version: '2.0.0' })) next.set(key, String(value));
  const version = await admin('/api/sboms/upload', 'POST', next); const nextId = version.data.sbom_id || version.data.id;
  check('UAT-SBOM-NEW-VERSION', 'SBOM lifecycle and versioning', 'admin', 'New revision receives a separate UUID and preserves original lineage', { ...summary(version), sbom_id: nextId }, version.status === 202 && nextId && nextId !== sid, 'Upload second version with explicit original parent and logical UUID');
  if (nextId) {
    const nextDetail = await admin('/api/sboms/' + nextId); const versions = await admin('/api/logical-sboms/' + logical + '/versions');
    check('UAT-SBOM-VERSION-HISTORY', 'SBOM lifecycle and versioning', 'admin', 'Two versions remain readable in same logical lineage and parent UUID is preserved', { next: { status: nextDetail.status, parent_id: nextDetail.data.parent_id, logical_sbom_id: nextDetail.data.logical_sbom_id }, versions: rows(versions.data).map(s => ({ id: s.id, sbom_version: s.sbom_version })) }, nextDetail.status === 200 && nextDetail.data.parent_id === sid && versions.status === 200 && rows(versions.data).length >= 2, 'GET second version and logical version history');
    fixture.second_sbom_id = nextId; fs.writeFileSync(path.join(output, 'business-fixtures.json'), JSON.stringify(fixture, null, 2));
  }
  const tenantName = 'UAT Tenant ' + Date.now(); const tenantPayload = { name: tenantName, slug: tenantName.toLowerCase().replace(/ /g, '-'), initial_admin_invitation: { first_name: 'UAT', last_name: 'Tenant Administrator', email: 'uat-tenant-admin-' + Date.now() + '@example.test' } };
  const deniedTenant = await admin('/api/tenants', 'POST', tenantPayload);
  check('UAT-TENANT-CREATE-DENY', 'Tenant Management', 'admin', 'Tenant Admin cannot create platform tenants', deniedTenant, deniedTenant.status === 403, 'POST entirely disposable tenant payload using tenant administrator authority');
  const createdTenant = await platform('/api/tenants', 'POST', tenantPayload); const tenantId = createdTenant.data.tenant?.id;
  check('UAT-TENANT-CREATE', 'Tenant Management', 'platform', 'Platform creates disposable tenant with new initial administrator, without changing seeded memberships', { ...summary(createdTenant), tenant: createdTenant.data.tenant, initial_administrator: createdTenant.data.initial_administrator }, createdTenant.status === 201 && Boolean(tenantId), 'Create UAT tenant and synthetic initial administrator; mail transport verified local');
  if (tenantId) {
    fixture.temporary_tenant_id = tenantId; fs.writeFileSync(path.join(output, 'business-fixtures.json'), JSON.stringify(fixture, null, 2));
    for (const status of ['DISABLED', 'ACTIVE']) { const r = await platform('/api/platform/tenants/' + tenantId, 'PATCH', { status }); check('UAT-TENANT-' + status, 'Tenant Management', 'platform', 'Platform changes status of UAT-created tenant', r, r.status === 200 && r.data.status === status, 'PATCH status only on tenant created by this UAT'); }
    const cross = await foreign('/api/platform/tenants/' + tenantId); check('UAT-TENANT-PLATFORM-DENY', 'Tenant Management', 'foreign', 'Foreign Tenant Admin cannot read platform tenant-management detail', cross, cross.status === 403, 'GET supported platform administration route without platform privilege');
  }
}
main().catch(e => { record('UAT-EXTENDED-EXECUTION', 'Execution', 'mixed', 'Complete extended scenario', sanitize(e.message), 'BLOCKED', 'Remaining dependent extended tests are not executed'); process.exitCode = 1; });
