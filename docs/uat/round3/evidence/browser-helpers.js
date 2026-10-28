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
 const response=page.waitForResponse(r=>r.url().endsWith('/api/auth/native/login')&&r.request().method()==='POST');await page.getByRole('button',{name:'Sign in',exact:true}).click();const accepted=await response;if(accepted.status()!==200)throw Error('Native Login HTTP '+accepted.status());await accepted.finished();console.log('Native login accepted',role);
 await page.waitForURL(u=>(u.pathname==='/'||u.pathname==='/platform'),{waitUntil:'domcontentloaded',timeout:45000});
 await page.getByRole('heading',{name:'Dashboard',exact:true}).or(page.getByRole('heading',{name:'Select tenant',exact:true})).or(page.getByRole('heading',{name:'Platform Dashboard',exact:true})).waitFor({timeout:60000}).catch(async error=>{console.log('Login state',clean(JSON.stringify({path:new URL(page.url()).pathname,headings:await page.locator('h1,h2').allTextContents(),messages:await page.locator('[role="alert"],[role="status"]').allTextContents()})));throw error;});
 console.log('Authenticated headings',await page.locator('h1,h2').allTextContents());
 if(await page.getByRole('heading',{name:'Select tenant',exact:true}).isVisible()){console.log('Selecting authorized tenant',role);await page.getByRole('button',{name:role==='foreign'?/^Isolation Control\s/:/^Olympus\s/}).click();}
 await page.getByRole('heading',{name:role==='platform'?'Platform Dashboard':'Dashboard',exact:true}).waitFor({timeout:60000});return {context,page};}
async function logout(session){const {page,context}=session;if(await page.getByRole('dialog').count())await page.keyboard.press('Escape');await page.getByRole('button',{name:/^Account menu for /}).click();const pending=page.waitForResponse(r=>r.url().endsWith('/api/auth/logout')&&r.request().method()==='POST');await page.getByRole('menuitem',{name:'Sign Out',exact:true}).click();await pending;await context.close();}
async function openVex(page){
 const list=await api(page,'/api/vex/investigations?sbom_id='+fixture.sbom_id);const item=list.data.items.find(v=>v.id===fixture.investigation_id);
 await page.goto(origin+'/vex-investigation?sbom_id='+fixture.sbom_id+'&q='+item.canonical_vulnerability_id,{waitUntil:'domcontentloaded'});
 const row=page.getByRole('row').filter({hasText:fixture.name+' SBOM'}).filter({has:page.getByRole('button',{name:'View vulnerability '+item.canonical_vulnerability_id,exact:true})});
 await row.getByRole('button',{name:'Investigate',exact:true}).click();await page.getByRole('heading',{name:/Analy[sz]er Evidence/i}).waitFor();
 return page.getByRole('dialog');}

module.exports={login,logout,openVex,chromium,users,origin,out,clean};
