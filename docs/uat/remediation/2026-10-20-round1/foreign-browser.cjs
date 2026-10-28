/* Scope-isolation acceptance: real Native BFF auth fixture, clean Chrome context. */
const fs=require('node:fs'),path=require('node:path');
const {chromium}=require('/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const out=__dirname,origin='https://localhost:13000';
const user=JSON.parse(fs.readFileSync('/Users/ferozebasha/.sbom-greenfield-uuid/users.json','utf8')).foreign;
const f=JSON.parse(fs.readFileSync(path.join(out,'fixtures.json'),'utf8'));
function clean(s){return s.split(user.password).join('[REDACTED]').replace(/eyJ[A-Za-z0-9_.-]+/g,'[TOKEN]').replace(/(__Host-sbom-session=)[^;\s]+/g,'$1[REDACTED]').replace(/(\b[Cc]ookie:)[^\n]+/g,'$1 [REDACTED]');}
async function main(){const browser=await chromium.launch({channel:'chrome',headless:true});const context=await browser.newContext({ignoreHTTPSErrors:false,reducedMotion:'reduce',viewport:{width:1440,height:1100}});try{
 const login=await context.request.post(origin+'/api/auth/native/login',{headers:{Origin:origin},data:{email:user.email,password:user.password},timeout:30000});if(login.status()!==200)throw Error('Native BFF authentication failed HTTP '+login.status());
 const page=await context.newPage();page.setDefaultTimeout(30000);await page.goto(origin+'/',{waitUntil:'domcontentloaded',timeout:60000});
 await page.getByRole('heading',{name:'Dashboard',exact:true}).or(page.getByRole('heading',{name:'Select tenant',exact:true})).waitFor();
 if(await page.getByRole('heading',{name:'Select tenant',exact:true}).isVisible())await page.getByRole('button',{name:/^Isolation Control\s/}).click();
 await page.getByRole('heading',{name:'Dashboard',exact:true}).waitFor();
 const query='project_id='+f.project_id+'&product_id='+f.product_id+'&sbom_id='+f.sbom_id;
 const denied=page.waitForResponse(r=>r.url().includes('/dashboard/summary?')&&r.status()===404,{timeout:45000});
 await page.goto(origin+'/?project='+f.project_id+'&application='+f.product_id+'&sbom='+f.sbom_id,{waitUntil:'domcontentloaded',timeout:60000});
 const response=await denied;await page.getByRole('alert').filter({hasText:'Unable to load this dashboard scope'}).waitFor();
 const result=await page.evaluate(async q=>{const r=await fetch('/api/backend/dashboard/summary?'+q,{headers:{'X-Tenant-ID':sessionStorage.getItem('sbom_active_tenant_id')}});return {status:r.status,body:await r.json(),tenant:sessionStorage.getItem('sbom_active_tenant_id')};},query);
 const text=await page.getByRole('region',{name:'Portfolio metrics'}).innerText();const numeric=await page.getByRole('region',{name:'Portfolio metrics'}).locator('.font-metric').allTextContents();
 const item={id:'R1-DASHBOARD-FOREIGN-DEEP-LINK',role:'foreign',preconditions:'Clean Chrome context; actual Native BFF login API fixture; TLS validation enabled; actual supported tenant selection/browser navigation',expected:'Foreign UUID scope rejected with no Olympus metrics',actual:{loginStatus:login.status(),scopeStatus:response.status(),api:result,metricText:text,numericMetricValues:numeric},result:response.status()===404&&result.status===404&&result.tenant===user.tenant_id&&!text.includes(f.name)&&numeric.length===0?'PASS':'FAIL',time:new Date().toISOString()};
 fs.writeFileSync(path.join(out,'browser-dashboard-foreign.json'),clean(JSON.stringify([item],null,2)));console.log(item.id,item.result,item.actual.scopeStatus);
 await page.screenshot({path:path.join(out,'dashboard-foreign-denied.png'),fullPage:false});
 await page.getByRole('button',{name:/^Account menu for /}).click();const logout=page.waitForResponse(r=>r.url().endsWith('/api/auth/logout')&&r.request().method()==='POST');await page.getByRole('menuitem',{name:'Sign Out',exact:true}).click();await logout;
}finally{await context.close();await browser.close();}}
main().catch(e=>{console.log(clean(e.message));process.exitCode=1;});
