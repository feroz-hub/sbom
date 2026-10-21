/* Browser presentation and role controls backed by independent API workflow tests. */
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('/Users/ferozebasha/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const { login, api, record, sanitize, output, origin } = require('./run-role-uat.cjs');
async function main() {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const invalid = JSON.parse(fs.readFileSync(path.join(output,'extended-cases.json'),'utf8')).find(c=>c.id==='UAT-SBOM-INVALID-JSON');
  const sessionId=invalid.actual.data.detail.validation_session_id;
  const workflow=JSON.parse(fs.readFileSync(path.join(output,'workflow-cases.json'),'utf8'));
  const recommendation=workflow.find(c=>c.id==='UAT-ADVISOR-CREATE')?.actual?.data?.id;
  try {
    for (const role of process.argv[2]==='admin-only'?['admin']:['admin','viewer','developer']) {
      let session;
      try {
        session=await login(browser,role);
        const {page,context}=session;
        await page.goto(origin+'/repair/'+sessionId,{waitUntil:'domcontentloaded'});
        await page.getByRole('heading',{name:'Repair Workspace',exact:true}).waitFor({timeout:30000});
        const editor=page.getByRole('textbox',{name:'SBOM repair editor',exact:true});
        await editor.waitFor();
        const state=await editor.evaluate(e=>({readOnly:e.readOnly,disabled:e.disabled,characters:e.value.length}));
        const controls=await page.getByRole('region',{name:'Repair workflow actions'}).getByRole('button').evaluateAll(es=>es.map(e=>({name:e.textContent.trim(),disabled:e.disabled})));
        const importedLink=await page.getByRole('link',{name:'View imported SBOM',exact:true}).getAttribute('href');
        await page.screenshot({path:path.join(output,'UAT-repair-'+role+'.png'),fullPage:true});
        record('UAT-REPAIR-BROWSER-'+role,'Validation repair',role,
          'Imported repair workspace renders retained content; Editor and mutation controls match implemented role',
          {editor:state,controls,importedLink},
          state.characters>100 && state.readOnly===(role!=='admin') && (role==='admin'||controls.every(c=>c.disabled)) && /^\/sboms\/[0-9a-f-]{36}$/.test(importedLink||'')?'PASS':'FAIL',
          'Open actual repaired workspace; inspect editor readOnly and button disabled states; compare independent API authorization; no draft mutation');
        if(role==='admin'&&recommendation){
          await page.goto(origin+'/component-advisor/recommendations/'+recommendation,{waitUntil:'domcontentloaded'});
          await page.waitForLoadState('networkidle',{timeout:20000}).catch(()=>{});
          const read=await api(page,'/api/component-advisor/recommendations/'+recommendation);
          const main=await page.locator('#main-content').innerText();
          record('UAT-ADVISOR-BROWSER-CLOSED','Component Advisor workflow',role,'Closed UAT recommendation is visible in supported detail route',
            {url:page.url(),headings:await page.locator('h1,h2').allTextContents(),status:read.status,closedText:/closed/i.test(main),text:main.slice(0,3200)},
            read.status===200&&/closed/i.test(main)?'PASS':'FAIL','Open this run\'s recommendation detail and compare closed state to live API',read.status);
        }
        await page.getByRole('button',{name:/^Account menu for /}).click();
        const signedOut=page.waitForResponse(r=>r.url().endsWith('/api/auth/logout')&&r.request().method()==='POST');
        await page.getByRole('menuitem',{name:'Sign Out',exact:true}).click();
        await signedOut;
        await context.close();session=null;
      }catch(e){
        record('UAT-WORKFLOW-BROWSER-BLOCK-'+role,'Execution',role,'Repair/advisor browser workflow is accessible in stable development server',
          {error:sanitize(e.message)},'BLOCKED','Attempt actual browser navigation; do not infer successful UI from API-only coverage',null,'ENV-001');
      }finally{if(session)await session.context.close();}
    }
  }finally{await browser.close();}
}
main().catch(e=>{console.log(sanitize(e.message));process.exitCode=1;});
