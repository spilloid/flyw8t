// Check the exact static site that Pages uploads. Usage: node scripts/check-product-site.mjs
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const site = new URL('../site/', import.meta.url);
const captures = ['devices', 'enrollment', 'windows-device'].map(name => 'screenshots/' + name + '.png');
const browsers = process.platform === 'win32'
  ? [process.env.ProgramFiles, process.env['ProgramFiles(x86)']].filter(Boolean).map(root => path.join(root, 'Google/Chrome/Application/chrome.exe'))
  : ['/usr/bin/google-chrome', '/usr/bin/chromium'];
if (process.env.CHROME_BIN) browsers.unshift(process.env.CHROME_BIN);
const chromePath = (await Promise.all(browsers.map(async p => { try { await access(p); return p; } catch { return null; } }))).find(Boolean);
assert.ok(chromePath, 'Install Chrome or set CHROME_BIN to its executable');
for (const file of captures) {
  const bytes = await readFile(new URL(file, site));
  assert.equal(bytes.subarray(0, 8).toString('hex'), '89504e470d0a1a0a', file + ' must be a PNG');
}

const profile = await mkdtemp(path.join(tmpdir(), 'flyw8t-pages-'));
const chrome = spawn(chromePath, ['--headless', '--user-data-dir=' + profile, '--remote-debugging-address=127.0.0.1',
  '--remote-debugging-port=0', '--disable-background-networking', '--disable-sync', '--disable-extensions',
  '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: 'ignore', windowsHide: true });
const stopped = new Promise(resolve => { chrome.once('error', resolve); chrome.once('exit', resolve); });
let ws;
try {
  let port;
  for (let attempt = 0; !port && attempt < 100; attempt++) {
    if (chrome.exitCode !== null || !chrome.pid) throw Error('Chrome exited during startup');
    try { port = Number((await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); }
    catch { await delay(100); }
  }
  assert.ok(port, 'Chrome debugging port unavailable');
  const pages = await (await fetch('http://127.0.0.1:' + port + '/json/list', { signal: AbortSignal.timeout(5000) })).json();
  ws = new WebSocket(pages.find(p => p.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(Error('Chrome connection failed')); });
  let sequence = 0;
  function command(method, params = {}) {
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { ws.removeEventListener('message', receive); reject(Error(method + ' timed out')); }, 10000);
      function receive(event) {
        const reply = JSON.parse(event.data);
        if (reply.id !== id) return;
        clearTimeout(timer);
        ws.removeEventListener('message', receive);
        if (reply.error) reject(Error(method + ': ' + reply.error.message)); else resolve(reply.result);
      }
      ws.addEventListener('message', receive);
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  // This function runs in the page. Decode lazy images as well, and check the visible
  // caption's keyboard-accessible link to the same full-size image.
  async function inspect() {
    if (document.readyState !== 'complete') await new Promise(resolve => window.addEventListener('load', resolve, { once: true }));
    const figures = [...document.querySelectorAll('main figure')];
    const images = await Promise.all(figures.map(async figure => {
      const img = figure.querySelector('img');
      img.loading = 'eager';
      await img.decode();
      const link = figure.querySelector('figcaption a[href]');
      const name = (link?.getAttribute('aria-label') || link?.textContent || '').trim();
      return { file: img.getAttribute('src'), decoded: img.naturalWidth > 0 && img.naturalHeight > 0,
        alt: !!img.alt.trim(), linked: !!name && link.tabIndex >= 0 && link.href === img.currentSrc && link.getClientRects().length > 0 };
    }));
    return { images, width: innerWidth, dark: matchMedia('(prefers-color-scheme: dark)').matches,
      overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      sections: [...document.querySelectorAll('a[href^="#"]')].every(a => document.getElementById(a.hash.slice(1))) };
  }

  await command('Network.enable');
  await command('Network.setBlockedURLs', { urls: ['http://*', 'https://*'] });
  await command('Page.navigate', { url: new URL('index.html', site).href });
  for (const [width, theme] of [[320, 'dark'], [390, 'light'], [768, 'dark'], [1440, 'light']]) {
    await command('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
    await command('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] });
    const result = await command('Runtime.evaluate', { expression: '(' + inspect.toString() + ')()', awaitPromise: true, returnByValue: true });
    assert.ok(!result.exceptionDetails, 'Page inspection failed at ' + width + 'px (check image decoding)');
    const { images, overflow, sections } = result.result.value;
    assert.equal(result.result.value.width, width);
    assert.equal(result.result.value.dark, theme === 'dark');
    assert.deepEqual(images.map(i => i.file).sort(), [...captures].sort(), 'Expected the three console screenshots');
    for (const i of images) assert.ok(i.decoded && i.alt && i.linked, i.file + ' needs an image description and full-size caption link');
    assert.ok(!overflow && sections, 'Horizontal overflow or a broken in-page link at ' + width + 'px');
    console.log(width + 'px ' + theme + ': screenshots, full-size links and layout passed');
  }
} finally {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ id: 0, method: 'Browser.close' }));
    await Promise.race([stopped, delay(2000)]);
  }
  ws?.close();
  if (chrome.pid && chrome.exitCode === null) chrome.kill();
  await stopped;
  // Remove only the randomly named Chrome profile this check created.
  if (path.dirname(profile) === path.resolve(tmpdir()) && path.basename(profile).startsWith('flyw8t-pages-')) {
    await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}
