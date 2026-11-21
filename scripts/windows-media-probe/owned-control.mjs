// Local developer launcher. There is no HTTP listener. Private browser bindings
// hand precisely one top-level document a freshly paired native process.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {once} from 'node:events';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {createInterface} from 'node:readline';
import {chromium} from 'playwright-core';

const [executable, flag, modelTest] = process.argv.slice(2);
assert.ok(executable && (!flag || flag === '--check') && process.argv.length <= 5,
  'Usage: node owned-control.mjs <owned-control.exe> [--check [example-test.exe]]');
const check = flag === '--check';
const base = 'http://127.0.0.1/board';
const files = new Map([
  [base, ['text/html; charset=utf-8',await readFile(new URL('./owned-control.html',import.meta.url))]],
  ['http://127.0.0.1/viewer.mjs',['text/javascript; charset=utf-8',await readFile(new URL('./owned-control-viewer.mjs',import.meta.url))]]]);
const browser = await chromium.launch({channel:'msedge',headless:check,args:['--allow-loopback-in-peer-connection']});

async function run(mode) {
  const wrongPeer = mode === 'wrong-peer';
  const model = ['viewer-close','owner-revoke','login-replaced'].includes(mode);
  const id = randomUUID();
  const binary = model ? modelTest : executable;
  const testName = mode === 'login-replaced' ? 'browser_replaced_login_ends_an_idle_held_press' : 'browser_keyboard_and_pointer_to_memory_board';
  const args = model ? ['--ignored','--exact',testName,
    '--nocapture','--format=terse'] : [check ? '--verify-no-permission' : '--attended-owned-board'];
  const child = spawn(resolve(binary),args,
    {windowsHide:true,stdio:['pipe','pipe','pipe'],timeout:125000});
  const done = once(child,'close');
  const lines = createInterface({input:child.stdout})[Symbol.asyncIterator]();
  let errors = '', stage = 'start';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', v => { errors = (errors+v).slice(-2048); });
  child.stdin.on('error', () => {}); // EOF during end races an already-closed native process.
  const page = await browser.newPage();
  try {
    await page.route('**/*',route => {
      const file = files.get(route.request().url());
      return file ? route.fulfill({contentType:file[0],body:file[1],
        headers:{'cache-control':'no-store','content-security-policy':"default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"}}) : route.abort();
    });
    const bind = (name,fn) => page.exposeBinding(name,(source,...args) => {
      assert.equal(source.frame,page.mainFrame());
      assert.equal(source.frame.url(),base);
      return fn(...args);
    });
    await bind('boardSession',() => id);
    await bind('boardOffer',async commit => {
      assert.equal(stage,'start');
      assert.match(commit,/^[0-9a-f]{64}$/);
      stage = 'offering';
      child.stdin.write(JSON.stringify({session:id,commit:wrongPeer ? '0'.repeat(64) : commit})+'\n');
      let first = await lines.next();
      if (model) {
        while (!first.done && !first.value.startsWith('{')) first = await lines.next();
      }
      assert.equal(first.done,false);
      const offer = JSON.parse(first.value);
      assert.equal(offer.type,'offer');
      stage = 'answer';
      return offer;
    });
    await bind('boardAnswer',answer => {
      assert.equal(stage,'answer');
      assert.equal(answer.type,'answer');
      assert.ok(typeof answer.sdp === 'string' && answer.sdp.length < 65000);
      stage = 'connected';
      child.stdin.write(JSON.stringify({type:'answer',sdp:answer.sdp})+'\n');
    });
    await bind('closeBoard',() => child.stdin.end());
    if (check) {
      // The negative test deliberately sends a well-formed event before any
      // native consent; the normal viewer only enables controls after Allow.
      await page.addInitScript(() => {
        const Base = window.RTCPeerConnection;
        window.RTCPeerConnection = class extends Base {
          constructor(...args) {
            super(...args);
            this.addEventListener('datachannel',({channel}) => { window.testChannel = channel; });
          }
        };
      });
    }
    await page.goto(base);
    if (model) {
      await page.waitForFunction(() => /^\d{6}$/.test(document.querySelector('#code').textContent)
        && document.querySelector('#status').textContent === 'You control the practice board.',{}, {timeout:20000});
      const bounds = await page.locator('#board').boundingBox();
      await page.mouse.move(bounds.x+bounds.width*6.5/8,bounds.y+bounds.height*2.5/4);
      await page.mouse.down();
      await page.keyboard.type('H');
      await page.keyboard.down('i');
      // The native replacement test changes its observed logon on the same
      // numeric session as soon as it sees both held inputs. No further packet
      // or browser disconnect is needed to trigger the endpoint watchdog.
      if (mode !== 'login-replaced') {
        await page.waitForFunction(() => document.querySelector('#typed').textContent === 'Hi' &&
          document.querySelectorAll('#board span')[22].hasAttribute('data-marked'),{}, {timeout:5000});
        if (mode === 'owner-revoke') {
          assert.equal(await page.evaluate(() => window.testChannel.readyState),'open');
          child.stdin.end();
        } else await page.close();
      }
    } else if (check && !wrongPeer) {
      await page.waitForFunction(() => /^\d{6}$/.test(document.querySelector('#code').textContent)
        && document.querySelector('#status').textContent.includes('click Allow'),{}, {timeout:20000});
      const verified = await lines.next();
      assert.equal(JSON.parse(verified.value).type,'peer_verified');
      await page.evaluate(() => window.testChannel.send(JSON.stringify({
        scope:'owned_board',activation:'0'.repeat(64),seq:1,event:{kind:'button',x:1,y:2,down:true}})));
    }
    const [status] = await done;
    if (wrongPeer) {
      assert.notEqual(status,0);
      assert.match(errors,/viewer certificate did not match/);
    } else assert.equal(status,0,errors);
    if (check) {
      const results = {
        'viewer-close':'Edge input reached the board. Closing the viewer released held input.',
        'owner-revoke':'The supervisor revoked an open channel. Held input was released before exit.',
        'login-replaced':'The same session ID acquired a different test logon. Idle held input was released.',
        'wrong-peer':'Wrong viewer certificate refused before local consent.',
        'pre-consent':'Input before local consent closed the ordered SCTP session.',
      };
      console.log(results[mode]);
    }
  } finally {
    child.stdin.end();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await page.close();
  }
}
try {
  await run(check ? 'pre-consent' : 'interactive');
  if (check) await run('wrong-peer');
  if (modelTest) {
    for (const mode of ['viewer-close','owner-revoke','login-replaced']) await run(mode);
  }
} finally { await browser.close(); }
