// Scope this test to one fresh hosted Windows user and its signed artifact.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
assert.equal(process.env.RUNNER_OS, 'Windows');
const host = 'handoff-' + randomBytes(16).toString('hex') + '.invalid';
const id = randomUUID();
const db = 'flyw8t_handoff_' + randomBytes(8).toString('hex');
const pg = file => path.join(process.env.PGBIN, file + '.exe');
const pgEnv = { ...process.env, PGHOST: '127.0.0.1', PGUSER: 'postgres', PGPASSWORD: 'root', PGPORT: '5432' };
const email = 'release@example.test';
const password = randomBytes(24).toString('hex');
const profile = await fs.mkdtemp(path.join(process.env.RUNNER_TEMP, 'signed-handoff-'));
const binaries = path.resolve(process.env.FLYW8T_TEST_BINARIES);
const technician = path.join(binaries, 'flyw8t-technician.exe');
const chromeExe = path.join(process.env.ProgramFiles, 'Google/Chrome/Application/chrome.exe');
const shell = path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');

const listener = createServer();
await new Promise((resolve, reject) => listener.once('error', reject).listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
const origin = 'http://127.0.0.1:' + port;
let server, chrome, ws, owned = false, databaseCreated = false;

async function waitFor(check, description, timeout = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const result = await check();
    if (result) return result;
    await delay(150);
  }
  throw new Error(description);
}

const pending = new Map();
let sequence = 0;
function call(method, params = {}) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(method + ' timed out')); }, 30000);
    pending.set(id, reply => {
      clearTimeout(timer);
      reply.error ? reject(new Error(method + ' failed')) : resolve(reply.result);
    });
    ws.send(JSON.stringify({id, method, params}));
  });
}
async function evaluate(expression) {
  const result = await call('Runtime.evaluate', { expression, returnByValue: true });
  if (result.exceptionDetails) throw new Error('Candidate console DOM assertion failed');
  return result.result.value;
}
function inspect(action, mode) {
  const args = ['-NoProfile', '-NoLogo', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File',
    path.resolve('scripts/signed-browser-window.ps1'), '-Action', action, '-Binary', technician, '-ExpectedComputer', host];
  if (mode) args.push('-ChromeProcessId', String(chrome.pid), '-Origin', origin, '-Mode', mode);
  execFileSync(shell,args,{stdio:'inherit',timeout:90000,windowsHide:true});
}

async function clickMode(mode) {
  await call('Page.bringToFront');
  const selector = 'a[href="flyw8t://open/' + mode + '?host=' + host + '"]';
  const coords = await evaluate('(() => { const a=document.querySelector('+JSON.stringify(selector)+');' +
    'if (!a) return null; a.scrollIntoView({block:"center",behavior:"instant"}); const r=a.getBoundingClientRect();' +
    'const x=r.x+r.width/2,y=r.y+r.height/2; return a.contains(document.elementFromPoint(x,y))?{x,y}:null; })()');
  assert.ok(coords, mode + ' link missing or obscured on the candidate device page');
  for (const type of ['mouseMoved','mousePressed','mouseReleased']) {
    const input = {type, ...coords};
    if (type !== 'mouseMoved') Object.assign(input, {button:'left',buttons:type === 'mousePressed' ? 1 : 0,clickCount:1});
    await call('Input.dispatchMouseEvent',input);
  }
}

try {
  execFileSync(pg('createdb'), [db], {env:pgEnv,windowsHide:true});
  databaseCreated = true;
  server = spawn(path.join(binaries, 'flyw8t-server.exe'), [], {
    windowsHide:true, stdio:'ignore', env:{...process.env, FLYW8T_DATABASE_URL:'postgres://postgres:root@127.0.0.1:5432/'+db,
      FLYW8T_BIND:'127.0.0.1:'+port, FLYW8T_PUBLIC_URL:origin, FLYW8T_BOOTSTRAP_ADMIN_EMAIL:email,
      FLYW8T_BOOTSTRAP_ADMIN_PASSWORD:password, FLYW8T_REQUIRE_MFA:'false'}
  });
  await waitFor(async () => {
    if (server.exitCode !== null) throw new Error('Downloaded server exited during startup');
    try {return (await fetch(origin+'/readyz',{signal:AbortSignal.timeout(1000)})).ok;} catch {return false;}
  },'Signed server did not become ready',60000);
  // Every interpolated SQL value here is generated above; the device has no network endpoint.
  const seed = "WITH org AS (INSERT INTO organizations(name) VALUES ('Release fixture') RETURNING id) " +
    "INSERT INTO devices(id, organization_id, hostname, os_family) SELECT '" + id + "', id, '" + host + "', 'windows' FROM org;";
  execFileSync(pg('psql'),['-X','-v','ON_ERROR_STOP=1','-d',db],{env:pgEnv,input:seed,windowsHide:true});
  inspect('Enable');
  owned = true;
  // Leave the profile untouched; the real first-use prompt is a release assertion.
  chrome = spawn(chromeExe, ['--user-data-dir='+profile,'--remote-debugging-address=127.0.0.1','--remote-debugging-port=0',
    '--no-first-run','--no-default-browser-check','--disable-sync','--disable-background-networking',
    '--disable-component-update','--disable-extensions','--force-renderer-accessibility','--lang=en-US',
    '--disable-backgrounding-occluded-windows','--disable-renderer-backgrounding','--window-size=1280,900','about:blank'],
    {stdio:'ignore'});
  const cdpPort = await waitFor(async () => {
    if (chrome.exitCode !== null) throw new Error('Test Chrome exited');
    try {return Number((await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]);} catch {return null;}
  },'Fresh Chrome debugging port missing');
  const tab = await waitFor(async () => {
    try {return (await (await fetch('http://127.0.0.1:'+cdpPort+'/json/list')).json()).find(t=>t.type==='page'&&t.url==='about:blank');}
    catch {return null;}
  },'Fresh Chrome tab missing');
  ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=()=>reject(new Error('Local Chrome CDP unavailable'));});
  ws.onmessage = event => {
    const message = JSON.parse(event.data);
    const receiver = pending.get(message.id);
    if (receiver) {pending.delete(message.id);receiver(message);}
  };
  await call('Page.bringToFront');
  await call('Page.navigate',{url:origin+'/login'});
  await waitFor(()=>evaluate('location.origin === '+JSON.stringify(origin)+' && !!document.querySelector("input[name=login_csrf]")'),'Candidate sign-in form missing');
  await evaluate('(() => { const f=document.querySelector("form[action=\\"/login\\"]"); f.elements.email.value='+JSON.stringify(email)+
    ';f.elements.password.value='+JSON.stringify(password)+';f.requestSubmit();return true; })()');
  await waitFor(()=>evaluate('location.origin === '+JSON.stringify(origin)+' && location.pathname === "/"'),'Fixture sign-in did not reach the console');
  if (process.env.FLYW8T_TEST_SIGNED_TRIAL_INSTALL === '1') {
    const { exerciseSignedTrial } = await import('./signed-trial-install.mjs');
    await exerciseSignedTrial({ origin, binaries, shell, call, evaluate, waitFor });
  }
  await call('Page.navigate',{url:origin+'/devices/'+id});
  await waitFor(()=>evaluate('document.querySelectorAll("a.desktop-choice").length === 3'),'Candidate device page did not offer the three session modes');
  console.log('Candidate '+process.env.GITHUB_SHA+', Chrome '+(await call('Browser.getVersion')).product+', Windows '+process.env.ImageVersion);
  for (const mode of ['assist','console','sign-in']) {
    await clickMode(mode);
    inspect('Confirm',mode);
  }
  inspect('Remove');
  owned = false;
  await clickMode('assist');
  inspect('Absent','assist');
} finally {
  try {
    if (owned) inspect('Remove');
  } finally {
    if (ws?.readyState === WebSocket.OPEN) {
      try {await call('Browser.close');} catch {}
      ws.close();
    }
    if (chrome && chrome.exitCode === null) chrome.kill();
    if (server && server.exitCode === null) server.kill();
    if (databaseCreated) execFileSync(pg('dropdb'),['--force',db],{env:pgEnv,windowsHide:true});
    // The GitHub-hosted VM and its throwaway Chrome profile are discarded with the job.
  }
}
