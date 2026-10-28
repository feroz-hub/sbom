const fs = require('node:fs');
const path = require('node:path');
const {chromium}=require('/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const out=__dirname, phase=process.argv[2]||'vex';
const users=JSON.parse(fs.readFileSync('/Users/ferozebasha/.sbom-greenfield-uuid/users.json','utf8'));
const fixture=JSON.parse(fs.readFileSync(path.join(out,'fixtures.json'),'utf8'));
const cases=[];
let currentPage;
let currentRole;
const origin='https://localhost:13000';
function clean(s){for(const u of Object.values(users))s=s.split(u.password).join('[REDACTED]');return s.replace(/eyJ[A-Za-z0-9_.-]+/g,'[TOKEN]').replace(/(__Host-sbom-session=)[^;\s]+/g,'$1[REDACTED]').replace(/(\b[Cc]ookie:)[^\n]+/g,'$1 [REDACTED]');}
function record(id,expected,actual,passed,role='admin'){cases.push({id,role,expected,actual,result:passed?'PASS':'FAIL',time:new Date().toISOString()});fs.writeFileSync(path.join(out,'browser-protection-'+phase+'.json'),clean(JSON.stringify(cases,null,2)));console.log(id,passed?'PASS':'FAIL',clean(JSON.stringify(actual)).slice(0,230));}
async function api(page,url,method='GET',body){const r=await page.context().request.fetch(origin+'/api/backend'+url,{method,headers:{Origin:origin,'X-Tenant-ID':users[currentRole].tenant_id},...(body===undefined?{}:{data:body}),timeout:90000});return {status:r.status(),data:await r.json()};}
async function login(browser,role){currentRole=role;const context=await browser.newContext({ignoreHTTPSErrors:false,reducedMotion:'reduce',viewport:{width:1440,height:1100}});const page=await context.newPage();currentPage=page;page.setDefaultTimeout(20000);page.setDefaultNavigationTimeout(60000);
 await page.goto(origin+'/native-sign-in',{waitUntil:'domcontentloaded'});await page.waitForLoadState('networkidle',{timeout:5000}).catch(()=>{});
 // Verify client hydration with an empty field before entering credentials.
 await page.getByRole('button',{name:'Show password',exact:true}).click();
 await page.getByRole('button',{name:'Hide password',exact:true}).waitFor({timeout:30000});
 await page.getByRole('button',{name:'Hide password',exact:true}).click();
 await page.getByLabel('Email address').fill(users[role].email);await page.getByLabel('Password',{exact:true}).fill(users[role].password);
 const response=page.waitForResponse(r=>r.url().endsWith('/api/auth/native/login')&&r.request().method()==='POST');await page.getByRole('button',{name:'Sign in',exact:true}).click();const accepted=await response;if(accepted.status()!==200)throw Error('Native Login failed');await accepted.finished();console.log('Native login accepted',role);
 await page.waitForURL(u=>u.pathname==='/',{waitUntil:'domcontentloaded',timeout:45000});
 await page.getByRole('heading',{name:'Dashboard',exact:true}).or(page.getByRole('heading',{name:'Select tenant',exact:true})).waitFor({timeout:60000}).catch(async error=>{console.log('Login state',clean(JSON.stringify({path:new URL(page.url()).pathname,headings:await page.locator('h1,h2').allTextContents(),messages:await page.locator('[role="alert"],[role="status"]').allTextContents()})));throw error;});
 console.log('Authenticated headings',await page.locator('h1,h2').allTextContents());
 if(await page.getByRole('heading',{name:'Select tenant',exact:true}).isVisible()){console.log('Selecting authorized tenant',role);await page.getByRole('button',{name:role==='foreign'?/^Isolation Control\s/:/^Olympus\s/}).click();}
 await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor({timeout:60000});return {context,page};}
async function logout(session){const {page,context}=session;if(await page.getByRole('dialog').count())await page.keyboard.press('Escape');await page.getByRole('button',{name:/^Account menu for /}).click();const pending=page.waitForResponse(r=>r.url().endsWith('/api/auth/logout')&&r.request().method()==='POST');await page.getByRole('menuitem',{name:'Sign Out',exact:true}).click();await pending;await context.close();}
async function openVex(page){
 const list=await api(page,'/api/vex/investigations?sbom_id='+fixture.sbom_id);const item=list.data.items.find(v=>v.id===fixture.investigation_id);
 await page.goto(origin+'/vex-investigation?sbom_id='+fixture.sbom_id+'&q='+item.canonical_vulnerability_id,{waitUntil:'domcontentloaded'});
 const row=page.getByRole('row').filter({hasText:fixture.name+' SBOM'}).filter({has:page.getByRole('button',{name:'View vulnerability '+item.canonical_vulnerability_id,exact:true})});
 await row.getByRole('button',{name:'Investigate',exact:true}).click();await page.getByRole('heading',{name:/Analy[sz]er Evidence/i}).waitFor();
 return page.getByRole('dialog');}
async function vex(browser){
 let session=await login(browser,'admin');try{
  const {page}=session;const panel=await openVex(page);
  record('UAT-VEX-DECISION-UI-DETAIL','Real investigation dialog opens analyzer evidence without 500',{text:(await panel.innerText()).slice(0,1500)},true);
  await panel.getByLabel('Status',{exact:false}).selectOption('UNDER_INVESTIGATION');await panel.getByLabel('Reason for this decision').fill('Round 2 actual Admin browser save');
  const save=page.waitForResponse(r=>r.url().endsWith('/'+fixture.investigation_id+'/decision')&&r.request().method()==='PUT');await panel.getByRole('button',{name:'Save decision',exact:true}).click();const result=await save;const body=await result.json();
  record('UAT-VEX-DECISION-UI','Admin UI decision returns 200 and displays persisted state',{status:result.status(),row_version:body.row_version,statusValue:body.effective_status},result.status()===200&&body.effective_status==='UNDER_INVESTIGATION');
  // Wait for the save's awaited query invalidation, not only the HTTP response.
  await panel.getByRole('button',{name:'Save decision',exact:true}).click({trial:true});
  await panel.getByRole('combobox',{name:'Assignee',exact:true}).fill('developer@olympus.example.test');await page.getByRole('option').filter({hasText:'developer@olympus.example.test'}).click();
  const assigned=page.waitForResponse(r=>r.url().endsWith('/'+fixture.investigation_id+'/assignment')&&r.request().method()==='PUT');await panel.getByRole('button',{name:'Save assignment',exact:true}).click();const a=await assigned;
  record('R1-VEX-ASSIGN-UI','Admin UI can assign disposable context to authorized Developer',{status:a.status()},a.status()===200);
  await page.screenshot({path:path.join(out,'vex-admin.png'),fullPage:true});
 }catch(error){await session.page.screenshot({path:path.join(out,'vex-ui-diagnostic.png'),fullPage:true}).catch(()=>{});record('R1-VEX-ADMIN-UI-ERROR','Open and use actual investigation dialog',{error:clean(error.message),dialog:await session.page.getByRole('dialog').innerText().catch(()=>''),controls:await session.page.getByRole('dialog').locator('input,select,textarea').evaluateAll(es=>es.map(e=>({tag:e.tagName,label:e.getAttribute('aria-label'),id:e.id}))).catch(()=>[])},false);throw error;}finally{await logout(session).catch(async()=>{await session.context.close();});}
 session=await login(browser,'developer');try{
  const {page}=session;const panel=await openVex(page);await panel.getByLabel('Status',{exact:false}).selectOption('AFFECTED');await panel.getByLabel('Reason for this decision').fill('Round 2 actual assigned Developer browser save');
  const pending=page.waitForResponse(r=>r.url().endsWith('/'+fixture.investigation_id+'/decision')&&r.request().method()==='PUT');await panel.getByRole('button',{name:'Save decision',exact:true}).click();const r=await pending;const data=await r.json();
  record('UAT-VEX-ASSIGNED-DEVELOPER-UI','Assigned Developer can save actual browser decision',{status:r.status(),effective_status:data.effective_status},r.status()===200&&data.effective_status==='AFFECTED','developer');
  await page.screenshot({path:path.join(out,'vex-developer.png'),fullPage:true});
 }catch(error){record('R1-VEX-DEVELOPER-UI-ERROR','Open and use actual assigned Developer dialog',{error:clean(error.message)},false);throw error;}finally{await logout(session).catch(async()=>{await session.context.close();});}
 session=await login(browser,'admin');try{const {page}=session;const detail=await api(page,'/api/vex/investigations/'+fixture.investigation_id);const r=await api(page,'/api/vex/investigations/'+fixture.investigation_id+'/assignment','PUT',{assigned_to:null,row_version:detail.data.row_version,reason:'Round 1 UI ownership cleanup'});record('R1-VEX-UI-CLEANUP','Remove only disposable assignment',{status:r.status},r.status===200);}finally{await logout(session);}
}
async function dashboardBefore(browser){const session=await login(browser,'admin');try{const {page}=session;const filters=page.getByRole('region',{name:'Dashboard filters'});await filters.getByLabel('Project',{exact:true}).selectOption(fixture.project_id);await page.waitForLoadState('networkidle',{timeout:10000}).catch(()=>{});const selected=await filters.getByLabel('Project',{exact:true}).inputValue();record('UAT-DASHBOARD-FILTER-UI','Project UUID selection is retained',{url:page.url(),selected,expected:fixture.project_id},selected===fixture.project_id);await page.screenshot({path:path.join(out,'dashboard-before.png'),fullPage:true});}finally{await logout(session);}}
async function dashboard(browser){
 let session=await login(browser,'admin');
 const full='/?project='+fixture.project_id+'&application='+fixture.product_id+'&sbom='+fixture.sbom_id;
 try{const {page}=session;const filters=page.getByRole('region',{name:'Dashboard filters'});
  const choices=[['Project',fixture.project_id,'project_id'],['Application',fixture.product_id,'product_id'],['SBOM',fixture.sbom_id,'sbom_id']];
  let expected={};let finalSummary;
  for(const [label,id,key] of choices){expected[key]=id;
   const response=page.waitForResponse(r=>{const u=new URL(r.url());return u.pathname.endsWith('/dashboard/summary')&&Object.entries(expected).every(([k,v])=>u.searchParams.get(k)===v)&&r.status()===200;},{timeout:40000});
   await filters.getByLabel(label,{exact:true}).selectOption(id);const r=await response;const data=await r.json();const direct=await api(page,'/dashboard/summary?'+new URLSearchParams(expected));
   const selected=await filters.getByLabel(label,{exact:true}).inputValue();finalSummary=data;
   record('UAT-DASHBOARD-FILTER-'+label.toUpperCase(),'Actual UUID '+label+' filter retains selection and agrees with scoped API',{status:r.status(),selected,expected:id,requestScope:expected,posture:data.posture,directPosture:direct.data.posture},selected===id&&JSON.stringify(data.posture)===JSON.stringify(direct.data.posture)&&data.posture.total_sboms===1);
  }
  const cards=[['Total SBOMs Stored','total_sboms'],['Total Projects Scanned','total_applications_scanned'],['Total SBOM Files Analysed','total_sboms_analysed']];
  for(const [label,key] of cards){const button=page.getByRole('button',{name:new RegExp(label)});const displayed=await button.locator('.font-metric').innerText();record('R1-DASHBOARD-METRIC-'+key,'Displayed counter equals selected-scope API value',{label,displayed,apiValue:finalSummary.posture[key]},displayed===finalSummary.posture[key].toLocaleString());}
  await page.screenshot({path:path.join(out,'dashboard-after.png'),fullPage:true});
  await page.reload({waitUntil:'domcontentloaded'});await filters.getByLabel('SBOM',{exact:true}).waitFor();await page.waitForFunction(id=>Array.from(document.querySelectorAll('select')).some(e=>e.value===id),fixture.sbom_id,{timeout:30000});
  const selected=await Promise.all(choices.map(([label])=>filters.getByLabel(label,{exact:true}).inputValue()));
  record('UAT-DASHBOARD-FILTER-REFRESH','Full UUID hierarchy survives actual page refresh',{url:page.url(),selected},selected.join('|')===[fixture.project_id,fixture.product_id,fixture.sbom_id].join('|'));
  await page.getByRole('button',{name:/Total SBOMs Stored/}).click();await page.waitForURL(u=>u.pathname==='/sboms',{waitUntil:'domcontentloaded',timeout:90000});const u=new URL(page.url());
  record('R1-DASHBOARD-DRILLDOWN','Stored-SBOM tile carries scope into inventory deep link',{url:page.url()},u.searchParams.get('project')===fixture.project_id&&u.searchParams.get('product')===fixture.product_id&&u.searchParams.get('sbom')===fixture.sbom_id);
  await page.goto(origin+full,{waitUntil:'domcontentloaded'});await page.waitForFunction(id=>Array.from(document.querySelectorAll('select')).some(e=>e.value===id),fixture.sbom_id,{timeout:30000});
  record('R1-DASHBOARD-DEEP-LINK','Direct navigation restores complete UUID scope',{url:page.url(),sbom:await filters.getByLabel('SBOM',{exact:true}).inputValue()},await filters.getByLabel('SBOM',{exact:true}).inputValue()===fixture.sbom_id);
  await filters.getByLabel('Project',{exact:true}).selectOption('');await page.waitForURL(u=>!u.searchParams.has('project'));await page.waitForFunction(()=>document.querySelector('[aria-label="Dashboard filters"]')?.querySelectorAll('select')[1]?.disabled);
  record('R1-DASHBOARD-RESET-DESCENDANTS','Clearing project clears dependent selections',{application:await filters.getByLabel('Application',{exact:true}).inputValue(),sbom:await filters.getByLabel('SBOM',{exact:true}).inputValue(),applicationDisabled:await filters.getByLabel('Application',{exact:true}).isDisabled(),sbomDisabled:await filters.getByLabel('SBOM',{exact:true}).isDisabled()},await filters.getByLabel('Application',{exact:true}).isDisabled()&&await filters.getByLabel('SBOM',{exact:true}).isDisabled());
  await page.goto(origin+'/?project=1&application='+fixture.product_id+'&sbom='+fixture.sbom_id,{waitUntil:'domcontentloaded'});await filters.getByLabel('Project',{exact:true}).waitFor();
  record('R1-DASHBOARD-INVALID-ID','Numeric project ID is rejected locally and orphaned children cleared',{project:await filters.getByLabel('Project',{exact:true}).inputValue(),application:await filters.getByLabel('Application',{exact:true}).inputValue(),sbom:await filters.getByLabel('SBOM',{exact:true}).inputValue()},(await Promise.all(choices.map(([label])=>filters.getByLabel(label,{exact:true}).inputValue()))).every(v=>v===''));
 }catch(error){record('R1-DASHBOARD-UI-ERROR','Complete dependent dashboard browser scenarios',{error:clean(error.message)},false);throw error;}finally{await logout(session).catch(async()=>{await session.context.close();});}
 session=await login(browser,'foreign');try{const {page}=session;await page.goto(origin+full,{waitUntil:'domcontentloaded'});await page.getByRole('alert').filter({hasText:'Unable to load this dashboard scope'}).waitFor({timeout:30000});const direct=await api(page,'/dashboard/summary?project_id='+fixture.project_id+'&product_id='+fixture.product_id+'&sbom_id='+fixture.sbom_id);const text=await page.getByRole('region',{name:'Portfolio metrics'}).innerText();record('R1-DASHBOARD-FOREIGN-DEEP-LINK','Foreign UUID scope is rejected; no Olympus metrics rendered',{status:direct.status,metricText:text},direct.status===404&&!text.includes(fixture.name),'foreign');}finally{await logout(session).catch(async()=>{await session.context.close();});}
}
async function main(){const browser=await chromium.launch({channel:'chrome',headless:true});try{if(phase==='vex')await vex(browser);else if(phase==='vex-readback'){const session=await login(browser,'admin');try{const panel=await openVex(session.page);const value=await panel.getByLabel('Status',{exact:false}).inputValue();const savedReasonVisible=(await panel.innerText()).includes('Round 2 actual assigned Developer browser save');record('R1-VEX-UI-PERSISTED-READBACK','Reopened real dialog displays persisted Developer determination and audit reason',{statusValue:value,savedReasonVisible},value==='AFFECTED'&&savedReasonVisible);await panel.screenshot({path:path.join(out,'vex-persisted-readback.png')});}finally{await logout(session);}}else if(phase==='dashboard-before')await dashboardBefore(browser);else if(phase==='dashboard-after')await dashboard(browser);else throw Error('Unknown phase');}finally{await browser.close();}}
main().catch(e=>{record('R1-BROWSER-EXECUTION','Complete browser scenario',{error:clean(e.message)},false);process.exitCode=1;});
