/* Real Chrome, task-owned DB/users only. Never save tokens, credentials or traces. */
const fs=require('node:fs');
const assert=require('node:assert/strict');
const {chromium}=require('/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const state='/Users/ferozebasha/.sbom-public-resource-uuid';
const users=JSON.parse(fs.readFileSync(state+'/users.json','utf8'));
const origin='https://localhost:13400';
const results=[];
let currentPage;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function misplaced(id){const raw=id.replace(/-/g,'');return raw.slice(0,9)+'-'+raw.slice(9,12)+'-'+raw.slice(12,16)+'-'+raw.slice(16,20)+'-'+raw.slice(20);}
function safe(error){let value=String(error);for(const u of Object.values(users))value=value.split(u.password).join('[REDACTED]');return value.replace(/eyJ[A-Za-z0-9_.-]+/g,'[TOKEN]').slice(0,1200);}
function record(name,result,observations){results.push({name,result,observations,time:new Date().toISOString()});fs.writeFileSync(state+'/evidence/browser-results.json',JSON.stringify(results,null,2));console.log(name,result);}
async function scenario(name,body){if(process.env.UUID_BROWSER_SCENARIO&&!name.includes(process.env.UUID_BROWSER_SCENARIO))return;try{const observations=await body();record(name,'PASS',observations||{});}catch(e){record(name,'FAIL',{error:safe(e)});}}
async function login(browser,role,platform=role==='platform'){
 const context=await browser.newContext({ignoreHTTPSErrors:false,viewport:{width:1440,height:1100},reducedMotion:'reduce'});const page=await context.newPage();currentPage=page;page.setDefaultTimeout(60000);page.setDefaultNavigationTimeout(120000);
 await page.goto(origin+'/native-sign-in');
 await page.getByRole('heading',{name:'Welcome back',exact:true}).waitFor();
 await page.getByLabel('Email address').fill(users[role].email);await page.getByLabel('Password',{exact:true}).fill(users[role].password);
 const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/auth/native/login'&&r.request().method()==='POST');
 await page.getByRole('button',{name:'Sign in',exact:true}).click();assert.equal((await response).status(),200);
 const heading=page.getByRole('heading',{name:platform?'Platform Dashboard':'Dashboard',exact:true});
 const selection=page.getByRole('heading',{name:'Select tenant',exact:true});await heading.or(selection).waitFor();
 if(await selection.isVisible()){const text=role==='foreign'?'UUID Test Foreign Tenant Admin':'UUID Test Olympus Tenant Admin';await page.getByRole('button',{name:text,exact:true}).click();}
 await heading.waitFor();return {context,page};
}
async function api(page,role,path,method='GET',body){
 return page.evaluate(async({path,method,body,tenant,origin})=>{const response=await fetch('/api/backend'+path,{method,headers:{'Content-Type':'application/json',Origin:origin,...(tenant?{'X-Tenant-ID':tenant}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:response.status,data:await response.json().catch(()=>null)};},{path,method,body,tenant:role==='platform'?null:users[role].tenant_id,origin});
}
(async()=>{const browser=await chromium.launch({channel:'chrome',headless:true});
try{
 for(const role of ['admin','analyst','developer','viewer','foreign','platform'])await scenario(role+': login, UUID context, refresh, logout/login stability',async()=>{
  const {context,page}=await login(browser,role);try{
   const me=await api(page,role,'/api/auth/me');assert.equal(me.status,200);assert.match(me.data.user_id,uuid);assert.equal(me.data.user_id,users[role].public_id);assert.equal(me.data.auth_context.user.id,me.data.user_id);
   await page.reload();await page.getByRole('heading',{name:role==='platform'?'Platform Dashboard':'Dashboard',exact:true}).waitFor();assert.equal((await api(page,role,'/api/auth/me')).data.user_id,me.data.user_id);
   if(role==='foreign'){
    const denied=await page.evaluate(async tenant=>(await fetch('/api/backend/api/projects',{headers:{'X-Tenant-ID':tenant}})).status,users.admin.tenant_id);assert.equal(denied,403);
   }
   if(role==='viewer'){
    assert.equal((await api(page,role,`/api/tenants/${users.viewer.tenant_id}/user-candidates?q=uuid`)).status,403);
   }
   if(role==='platform'){
    for(const path of ['/api/platform/users',`/api/platform/users/${users.admin.public_id}`])assert.equal((await api(page,role,path)).status,403);
    const candidates=await api(page,role,'/api/platform/tenant-admin-candidates?q=uuid-');assert.equal(candidates.status,200);assert(candidates.data.items.every(u=>uuid.test(u.id)));
   }
   await page.getByRole('button',{name:/Account menu for/}).click();await page.getByRole('menuitem',{name:'Sign Out',exact:true}).click();await page.waitForURL(/logged-out/);
   await page.goto(origin+'/settings/tenant');await page.getByRole('heading',{name:'Welcome back',exact:true}).waitFor();
  }finally{await context.close();}
  const again=await login(browser,role);try{assert.equal((await api(again.page,role,'/api/auth/me')).data.user_id,users[role].public_id);}finally{await again.context.close();}
 });
 await scenario('Tenant Admin: actual Users & Access find/add/change roles/remove UUID user',async()=>{
  const {context,page}=await login(browser,'admin');try{
   await page.goto(origin+'/settings/tenant');
   const previous=await api(page,'admin',`/api/tenants/${users.admin.tenant_id}/users`);
   const old=previous.data.find(u=>u.user_id===users.candidate.public_id);
   if(old){await page.getByRole('button',{name:'Open actions for UUID Test candidate',exact:true}).click();await page.getByRole('menuitem',{name:'Remove from tenant',exact:true}).click();const cleanup=page.getByRole('dialog');await cleanup.getByRole('checkbox',{name:'I understand this user will lose access to this tenant',exact:true}).check();await cleanup.getByRole('button',{name:'Remove from tenant',exact:true}).click();await cleanup.waitFor({state:'hidden'});}
   await page.getByRole('button',{name:'Add Existing Member',exact:true}).waitFor();await page.getByRole('button',{name:'Add Existing Member',exact:true}).click();
   const dialog=page.getByRole('dialog',{name:'Add Existing Member',exact:true});await dialog.waitFor();await dialog.getByRole('combobox',{name:'Search existing user'}).fill(users.candidate.email);
   const option=page.getByRole('option',{name:/UUID Test candidate/});await option.waitFor();await option.click();
   const pending=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(`/tenants/${users.admin.tenant_id}/users`)&&r.request().method()==='POST');await dialog.getByRole('button',{name:'Add Member',exact:true}).click();assert.equal((await pending).status(),201);
   const list=await api(page,'admin',`/api/tenants/${users.admin.tenant_id}/users`);assert.equal(list.status,200);const member=list.data.find(u=>u.user_id===users.candidate.public_id);assert(member);assert.match(member.membership_id,uuid);
   assert.equal((await api(page,'admin',`/api/tenants/${users.admin.tenant_id}/users/${misplaced(member.membership_id)}`)).status,422);
   const action=page.getByRole('button',{name:'Open actions for UUID Test candidate',exact:true});await action.waitFor();await action.click();await page.getByRole('menuitem',{name:/Manage roles/i}).click();
   const roles=page.getByRole('dialog');await roles.waitFor();await roles.getByRole('checkbox',{name:/Developer/i}).check();const save=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(`/users/${users.candidate.public_id}/roles`)&&r.request().method()==='PUT').catch(()=>null);await roles.getByRole('button',{name:'Save changes',exact:true}).click();assert.equal((await save).status(),200);
   await roles.waitFor({state:'hidden'});
   for(const [operation,label] of [['deactivate','Disable membership'],['activate','Enable membership']]){
    await action.click();await page.getByRole('menuitem',{name:label,exact:true}).click();const confirmation=page.getByRole('dialog');await confirmation.waitFor();
    const status=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(`/users/${member.membership_id}/${operation}`)&&r.request().method()==='POST');await confirmation.getByRole('button',{name:label,exact:true}).click();const changed=await status;assert.equal(changed.status(),200);assert.equal((await changed.json()).membership_id,member.membership_id);await confirmation.waitFor({state:'hidden'});
   }
   await action.click();await page.getByRole('menuitem',{name:'Remove from tenant',exact:true}).click();const removal=page.getByRole('dialog');await removal.waitFor();const removed=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(`/users/${member.membership_id}`)&&r.request().method()==='DELETE');await removal.getByRole('checkbox',{name:'I understand this user will lose access to this tenant',exact:true}).check();await removal.getByRole('button',{name:'Remove from tenant',exact:true}).click();assert.equal((await removed).status(),204);
  }finally{await context.close();}
 });
 await scenario('Platform Admin: purpose-limited UUID selection, actual grant/revoke UI',async()=>{
  const {context,page}=await login(browser,'platform');let pendingGrant=null;try{
   await page.goto(origin+'/settings/platform');await page.getByRole('heading',{name:'Grant Platform Administrator',exact:true}).waitFor();
   await page.getByRole('combobox',{name:'Search users by email or name'}).fill(users.candidate.email);await page.getByRole('option',{name:/UUID Test candidate/}).click();
   const granted=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/platform/administrators')&&r.request().method()==='POST');
   await page.getByRole('button',{name:'Grant Platform Administrator',exact:true}).click();const response=await granted;assert.equal(response.status(),201);assert.equal(response.request().postDataJSON().user_id,users.candidate.public_id);
   const grant=await response.json();pendingGrant=grant.grant_id;assert.match(pendingGrant,uuid);assert.equal(grant.user_id,users.candidate.public_id);assert.equal(grant.created_by_user_id,users.platform.public_id);
   assert.equal((await api(page,'platform',`/api/platform/administrators/${misplaced(pendingGrant)}`,'DELETE')).status,422);
   const target=await login(browser,'candidate',true);
   try {
    const before=await api(target.page,'platform','/api/auth/me');assert.equal(before.data.auth_context.platform.is_platform_admin,true);
   const row=page.getByRole('row').filter({hasText:'UUID Test candidate'});await row.getByRole('button',{name:'Revoke',exact:true}).click();
   const revoked=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(`/platform/administrators/${pendingGrant}`)&&r.request().method()==='DELETE');await page.getByRole('dialog').getByRole('button',{name:'Revoke authority',exact:true}).click();assert.equal((await revoked).status(),204);pendingGrant=null;
    const after=await api(target.page,'platform','/api/platform/administrators');assert.equal(after.status,403);
   } finally {await target.context.close();}
  }finally{if(pendingGrant!==null){const cleaned=await api(page,'platform',`/api/platform/administrators/${pendingGrant}`,'DELETE');assert.equal(cleaned.status,204,'Task-only grant cleanup failed');}await context.close();}
 });
 await scenario('Analyst: real SBOM upload, analysis SSE, persisted UUID polling and foreign isolation',async()=>{
  const admin=await login(browser,'admin');let sbom,productId;
  try {
   const project=await api(admin.page,'admin','/api/projects','POST',{project_name:'UUID Browser Release '+Date.now(),project_status:1});assert.equal(project.status,201);assert.match(project.data.id,uuid);
   const product=await api(admin.page,'admin',`/api/projects/${project.data.id}/products`,'POST',{name:'UUID Browser Gateway'});assert.equal(product.status,201);assert.match(product.data.id,uuid);
   productId=product.data.id;
   await admin.page.goto(origin+'/sboms');await admin.page.getByRole('button',{name:'Upload SBOM',exact:true}).click();
   const dialog=admin.page.getByRole('dialog');const name='UUID Browser Analysis '+Date.now();await dialog.getByLabel('SBOM Name').fill(name);
   const document={bomFormat:'CycloneDX',specVersion:'1.6',version:1,serialNumber:'urn:uuid:'+require('node:crypto').randomUUID(),metadata:{timestamp:new Date().toISOString(),tools:[{vendor:'UUID Test',name:'Synthetic Fixture',version:'1'}]},components:[{type:'library','bom-ref':'requests',name:'requests',version:'2.19.0',purl:'pkg:pypi/requests@2.19.0',supplier:{name:'Synthetic'}},{type:'library','bom-ref':'log4j',name:'log4j-core',version:'2.14.1',purl:'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',supplier:{name:'Synthetic'}}],dependencies:[{ref:'requests',dependsOn:[]},{ref:'log4j',dependsOn:[]}]};
   await dialog.locator('input[type=file]').setInputFiles({name:'uuid-analysis.cdx.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(document))});
   await dialog.getByRole('combobox',{name:'Project',exact:true}).selectOption(project.data.id);await dialog.getByRole('combobox',{name:'Application',exact:true}).selectOption(product.data.id);
   const pending=admin.page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/api/sboms/upload')&&r.request().method()==='POST');await dialog.getByRole('button',{name:'Upload SBOM',exact:true}).click();const uploaded=await pending;assert.equal(uploaded.status(),202);sbom=(await uploaded.json()).sbom_id;assert.match(sbom,uuid);
  }finally{await admin.context.close();}
  const analyst=await login(browser,'analyst');let run;
  try{
   await analyst.page.goto(origin+'/sboms/'+sbom);await analyst.page.getByRole('button',{name:'Overview & Risk',exact:true}).click();
   const pending=analyst.page.waitForResponse(r=>new URL(r.url()).pathname.endsWith(`/api/sboms/${sbom}/analyze/stream`)&&r.request().method()==='POST');await analyst.page.getByRole('button',{name:'Run Analysis',exact:true}).click();const analyzed=await pending;assert.equal(analyzed.status(),200);
   const stream=await analyzed.text();const frame=stream.split('\n\n').find(s=>s.includes('event: complete'));assert(frame,'Analysis did not finish');const outcome=JSON.parse(frame.split('\n').find(s=>s.startsWith('data: ')).slice(6));assert.equal(outcome.errors,0);assert.equal(outcome.status,'FINDINGS');run=outcome.runId;assert.match(run,uuid);
   await analyst.page.getByRole('button',{name:'Analysis Runs',exact:true}).click();const row=analyst.page.getByRole('table',{name:'Analysis runs for this SBOM'}).getByRole('row').filter({hasText:'#'+run});await row.getByRole('link',{name:'View',exact:true}).click();await analyst.page.waitForURL('**/analysis/'+run);
   const fetched=await api(analyst.page,'analyst','/api/runs/'+run);assert.equal(fetched.status,200);assert.equal(fetched.data.id,run);assert(fetched.data.total_findings>0);
   const findings=await api(analyst.page,'analyst',`/api/runs/${run}/findings`);assert.equal(findings.status,200);
   const history=await api(analyst.page,'analyst',`/api/sboms/${sbom}/analysis-runs`);assert(history.data.some(r=>r.id===run));
   const products=await api(analyst.page,'analyst',`/api/products/${productId}/sboms`);assert.equal(products.status,200);assert.equal(products.data.find(s=>s.id===sbom).latest_analysis.run_id,run);
   const compared=await api(analyst.page,'analyst',`/api/analysis-runs/compare?run_a=${run}&run_b=${run}`);assert.equal(compared.status,200);assert.equal(compared.data.run_a.id,run);assert.equal(compared.data.run_b.id,run);
   await analyst.page.reload();assert.equal((await api(analyst.page,'analyst','/api/runs/'+run)).data.id,run);assert.equal((await api(analyst.page,'analyst','/api/runs/1')).status,422);
   assert.equal((await api(analyst.page,'analyst','/api/runs/'+misplaced(run))).status,422);
  }finally{await analyst.context.close();}
  const foreign=await login(browser,'foreign');try{assert.equal((await api(foreign.page,'foreign','/api/runs/'+run)).status,404);}finally{await foreign.context.close();}
  return {sbom_id:sbom,run_id:run,provider:'local Postman OSV simulation',foreign_status:404,integer_status:422};
 });
 await scenario('Admin UUID path syntax, missing identities and membership separation',async()=>{
  const {context,page}=await login(browser,'admin');try{
   const invalidRole=await api(page,'admin',`/api/tenants/${users.admin.tenant_id}/users`,'POST',{user_id:users.candidate.public_id,roles:[]});assert.equal(invalidRole.status,422);assert.equal(invalidRole.data.detail.find(e=>e.loc.length===1&&e.loc[0]==='body').input.user_id,users.candidate.public_id);
   for(const id of ['1','malformed','00000000-0000-1000-8000-000000000001'])assert.equal((await api(page,'admin',`/api/tenants/${users.admin.tenant_id}/users/${id}/roles`)).status,422);
   assert.equal((await api(page,'admin',`/api/tenants/${users.admin.tenant_id}/users/${users.foreign.public_id}/roles`)).status,404);
  }finally{await context.close();}
 });
 await scenario('Public resource denials: foreign Membership, integer Grant, Viewer mutations and numeric UI route',async()=>{
  const foreign=await login(browser,'foreign');let membership;
  try{const listed=await api(foreign.page,'foreign',`/api/tenants/${users.foreign.tenant_id}/users`);assert.equal(listed.status,200);membership=listed.data.find(m=>m.user_id===users.foreign.public_id).membership_id;assert.match(membership,uuid);}finally{await foreign.context.close();}
  const admin=await login(browser,'admin');
  try{assert.equal((await api(admin.page,'admin',`/api/tenants/${users.admin.tenant_id}/users/${membership}`)).status,404);await admin.page.goto(origin+'/analysis/1');await admin.page.getByText('This analysis run does not exist or was removed.',{exact:true}).waitFor();}finally{await admin.context.close();}
  const platform=await login(browser,'platform');try{assert.equal((await api(platform.page,'platform','/api/platform/administrators/1','DELETE')).status,422);}finally{await platform.context.close();}
  const viewer=await login(browser,'viewer');try{
   assert.equal((await api(viewer.page,'viewer',`/api/tenants/${users.viewer.tenant_id}/users`,'POST',{user_id:users.candidate.public_id,roles:['VIEWER']})).status,403);
   assert.equal((await api(viewer.page,'viewer','/api/platform/administrators','POST',{user_id:users.candidate.public_id})).status,403);
   await viewer.page.goto(origin+'/settings/tenant');assert.equal(await viewer.page.getByRole('button',{name:'Add Existing Member',exact:true}).count(),0);
  }finally{await viewer.context.close();}
  return {foreign_membership:404,integer_grant:422,viewer_membership_mutation:403,viewer_platform_mutation:403,numeric_ui_route:'Not found'};
 });
}finally{await browser.close();}
process.exitCode=results.some(r=>r.result==='FAIL')?1:0;
})().catch(e=>{record('harness','FAIL',{error:safe(e)});process.exitCode=1;});
