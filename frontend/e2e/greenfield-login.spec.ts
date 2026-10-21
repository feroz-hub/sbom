/** Real local Native Login. Never save passwords, token bodies, traces or screenshots. */
import { test, expect, type Page, type TestInfo } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';
import { createClient } from 'redis';
const state = `${homedir()}/.sbom-greenfield-uuid`;
const users = JSON.parse(readFileSync(`${state}/users.json`, 'utf8'));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function safe(value: unknown) {
  let text = String(value);
  for (const user of Object.values(users) as Array<{password: string}>) text = text.split(user.password).join('[REDACTED]');
  return text.replace(/eyJ[A-Za-z0-9_.-]+/g, '[TOKEN]').replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]').slice(0,2000);
}
function scenario(name: string, body: (page: Page) => Promise<void>) {
  test(name, async ({ page }, info: TestInfo) => {
    const evidence: { started: string; status?: string; error?: string; responses: unknown[]; console: string[]; failures: unknown[] } = {started:new Date().toISOString(), responses:[],console:[],failures:[]};
    page.on('response', r => { const path=new URL(r.url()).pathname; if(path.includes('/auth/') || r.status()>=400) evidence.responses.push({path,status:r.status(),requestId:r.headers()['x-request-id']??null}); });
    page.on('pageerror', e => evidence.console.push(safe(e.message)));
    page.on('requestfailed', r => evidence.failures.push({path:new URL(r.url()).pathname,reason:safe(r.failure()?.errorText)}));
    try { await body(page); expect(evidence.console).toEqual([]); evidence.status='PASS'; }
    catch (error) { evidence.status='FAIL';evidence.error=safe(error);throw new Error(evidence.error); }
    finally { writeFileSync(`${state}/login-diagnostic/${info.testId.replace(/[^a-z0-9]/gi,'_')}.json`, JSON.stringify(evidence,null,2),{mode:0o600}); }
  });
}
async function login(page: Page, role: string, preference?: string) {
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Welcome back',exact:true})).toBeVisible();
  await page.getByLabel('Email address').fill(users[role].email);
  await page.getByLabel('Password',{exact:true}).fill(users[role].password);
  if (preference!==undefined) await page.evaluate(value=>sessionStorage.setItem('sbom_active_tenant_id',value),preference);
  const pending=page.waitForResponse(r=>r.url().endsWith('/api/auth/native/login')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Sign in',exact:true}).click();
  expect((await pending).status()).toBe(200);
  const dashboard=page.getByRole('heading',{name:role==='platform'?'Platform Dashboard':'Dashboard',exact:true});
  const selection=page.getByRole('heading',{name:'Select tenant',exact:true});
  await expect(dashboard.or(selection)).toBeVisible();
  if (await selection.isVisible()) await page.getByRole('button',{name:'Olympus Tenant Admin',exact:true}).click();
  await expect(dashboard).toBeVisible();
}
async function authContext(page: Page) {
  return page.evaluate(async()=>{
    const id=sessionStorage.getItem('sbom_active_tenant_id');
    const response=await fetch('/api/backend/api/auth/me',{headers:id?{'X-Tenant-ID':id}:{}});
    const data=await response.json();
    return {status:response.status,tenantId:data.tenant_id,roles:data.roles,permissions:data.permissions,isPlatform:data.is_platform_admin};
  });
}
const roles: Record<string,string>={admin:'TENANT_ADMIN',analyst:'SECURITY_ANALYST',developer:'DEVELOPER',viewer:'VIEWER',foreign:'TENANT_ADMIN',platform:'PLATFORM_ADMIN'};
for(const [role,expectedRole] of Object.entries(roles)) scenario(`${role}: real login, context, refresh and secure cookie`,async page=>{
  await login(page,role);
  const me=await authContext(page);expect(me.status).toBe(200);expect(me.roles).toContain(expectedRole);
  if(role==='platform'){expect(me.isPlatform).toBe(true);expect(me.tenantId).toBeNull();}
  else {expect(me.tenantId).toBe(users[role].tenant_id);expect(me.tenantId).toMatch(UUID);}
  const cookie=(await page.context().cookies()).find(c=>c.name==='__Host-sbom-session');
  expect(Boolean(cookie?.httpOnly&&cookie?.secure&&cookie?.sameSite==='Lax'&&cookie?.path==='/')).toBe(true);
  await page.reload();await expect(page.getByRole('heading',{name:role==='platform'?'Platform Dashboard':'Dashboard',exact:true})).toBeVisible();
  expect((await authContext(page)).tenantId).toBe(me.tenantId);
  if(role==='viewer'){
    const status=await page.evaluate(async()=>{const response=await fetch('/api/backend/api/projects',{method:'POST',headers:{'Content-Type':'application/json','X-Tenant-ID':sessionStorage.getItem('sbom_active_tenant_id')!},body:JSON.stringify({project_name:'Denied Viewer Mutation',project_status:1})});return response.status;});
    expect(status).toBe(403);
    await page.goto('/projects');await expect(page.getByRole('button',{name:'Create Project',exact:true})).toHaveCount(0);
  }
  if(role==='foreign'){
    const status=await page.evaluate(async id=>(await fetch('/api/backend/api/projects',{headers:{'X-Tenant-ID':id}})).status,users.admin.tenant_id);
    expect(status).toBe(403);
  }
});
for(const value of ['1','NaN','not-a-uuid'])scenario(`legacy tenant preference ${value} cannot break successful login`,async page=>{
  await login(page,'admin',value);expect((await authContext(page)).tenantId).toBe(users.admin.tenant_id);
});
scenario('invalid password and nonexistent identity receive identical rejection',async page=>{
  await page.goto('/');await page.getByLabel('Email address').fill(users.viewer.email);
  await page.getByLabel('Password',{exact:true}).fill('Synthetic-invalid-password-once!');
  let response=page.waitForResponse(r=>r.url().endsWith('/api/auth/native/login')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Sign in',exact:true}).click();const first=await response;expect(first.status()).toBe(401);const firstBody=await first.json();
  await expect(page.getByRole('status')).toHaveText('The email address or password you entered is incorrect.');
  await page.getByLabel('Email address').fill('nonexistent-login-diagnostic@example.test');
  response=page.waitForResponse(r=>r.url().endsWith('/api/auth/native/login')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Sign in',exact:true}).click();const second=await response;expect(second.status()).toBe(401);expect(await second.json()).toEqual(firstBody);
  expect((await page.context().cookies()).some(c=>c.name==='__Host-sbom-session')).toBe(false);
});
scenario('logout destroys session and direct protected-route access requires sign-in',async page=>{
  await login(page,'admin');
  await page.getByRole('button',{name:'Account menu for Synthetic Olympus admin',exact:true}).click();
  await page.getByRole('menuitem',{name:'Sign Out',exact:true}).click();
  await expect(page).toHaveURL(/logged-out/);
  expect((await page.context().cookies()).some(c=>c.name==='__Host-sbom-session')).toBe(false);
  await page.goto('/projects');await expect(page.getByRole('heading',{name:'Welcome back',exact:true})).toBeVisible();
  const status=await page.evaluate(async()=>(await fetch('/api/backend/api/projects')).status);expect(status).toBe(401);
});
scenario('expired server-side session requires reauthentication and remains signed out on refresh',async page=>{
  await login(page,'developer');
  const cookie=(await page.context().cookies()).find(c=>c.name==='__Host-sbom-session')!;
  const client=createClient({url:'redis://127.0.0.1:56381/1'});
  client.on('error',()=>{});await client.connect();
  try {const key='sbom:bff:'+createHash('sha256').update(cookie.value).digest('hex');expect(await client.expire(key,1)).toBe(1);await new Promise(resolve=>setTimeout(resolve,1200));}
  finally{await client.quit();}
  // Dashboard requests detect expiry and navigate to sign-in automatically.
  // Confirm that actual reauthentication boundary before refreshing it, so a
  // second navigation cannot race the application's in-progress redirect.
  await expect(page.getByRole('heading',{name:'Welcome back',exact:true})).toBeVisible();
  await page.reload();await expect(page.getByRole('heading',{name:'Welcome back',exact:true})).toBeVisible();
  const session=await page.evaluate(async()=>{const response=await fetch('/api/auth/session');return response.json();});
  expect(session.authenticated).toBe(false);
});
scenario('Admin opens Olympus project, application, components and analysis runs with UUID references',async page=>{
  await login(page,'admin');
  await page.getByRole('link',{name:'Projects',exact:true}).click();
  await page.getByRole('button',{name:'Select project Olympus Release',exact:true}).click();
  await expect(page.getByText('Olympus Gateway',{exact:true}).first()).toBeVisible();
  const data=await page.evaluate(async()=>{const headers={'X-Tenant-ID':sessionStorage.getItem('sbom_active_tenant_id')!};const projects=await(await fetch('/api/backend/api/projects',{headers})).json();const project=projects.find((p:{project_name:string})=>p.project_name==='Olympus Release');const response=await fetch(`/api/backend/api/projects/${project.id}/products`,{headers});const products=await response.json();return {projects,products:products.items,productStatus:response.status};});
  expect(data.projects.every((p:{id:string})=>UUID.test(p.id))).toBe(true);expect(data.productStatus).toBe(200);
  const gateway=data.products.find((p:{name:string})=>p.name==='Olympus Gateway');expect(gateway.id).toMatch(UUID);expect(gateway.project_id).toMatch(UUID);
  await page.goto(`/products/${gateway.id}`);await expect(page.getByRole('heading',{name:'Olympus Gateway',exact:true})).toBeVisible();
  await page.getByRole('link',{name:'SBOMs',exact:true}).click();
  await expect(page.getByRole('heading',{name:'SBOMs',exact:true})).toBeVisible();
});
