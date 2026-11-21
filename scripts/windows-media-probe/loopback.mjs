// Same-machine H.264 WebRTC test. Only generated pixels and loopback ICE are allowed.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { chromium } from 'playwright-core';

assert.equal(process.argv.length, 3, 'usage: node loopback.mjs <probe executable>');
const browser = await chromium.launch({
  channel: 'msedge',
  headless: true,
  args: ['--allow-loopback-in-peer-connection', '--autoplay-policy=no-user-gesture-required'],
});
async function run(mismatch) {
  const source = spawn(resolve(process.argv[2]), ['--loopback'], {
    stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, timeout: 30_000,
  });
  const done = once(source, 'close');
  let diagnostics = '';
  source.stderr.setEncoding('utf8');
  source.stderr.on('data', text => { diagnostics = (diagnostics + text).slice(-4096); });
  const page = await browser.newPage();
  try {
    const fingerprint = await page.evaluate(async () => {
      window.fixtureCert = await RTCPeerConnection.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256' });
      return window.fixtureCert.getFingerprints().find(f => f.algorithm === 'sha-256').value;
    });
    const pin = mismatch ? '00:'.repeat(31) + '00' : fingerprint;
    source.stdin.write(pin + '\n');
    const lines = createInterface({ input: source.stdout });
    let offer;
    for await (const line of lines) {
      offer = JSON.parse(line);
      break;
    }
    assert.equal(offer?.type, 'offer', 'native sender must provide an SDP offer');
    const media = offer.sdp.split(/\r?\n/).filter(l => l.startsWith('m='));
    assert.equal(media.length, 1);
    assert.match(media[0], /^m=video /);
    const candidates = offer.sdp.split(/\r?\n/).filter(l => l.startsWith('a=candidate:'));
    assert.ok(candidates.length > 0);
    assert.ok(candidates.every(l => l.split(/\s+/)[4] === '127.0.0.1'));
    const answer = await page.evaluate(async offer => {
      const peer = new RTCPeerConnection({ iceServers: [], bundlePolicy: 'max-bundle', certificates: [window.fixtureCert] });
      window.fixturePeer = peer;
      const video = document.createElement('video');
      document.body.append(video);
      video.autoplay = video.muted = true;
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = 1;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      window.fixtureBands = [];
      peer.ontrack = e => {
        video.srcObject = new MediaStream([e.track]);
        function frame() {
          ctx.drawImage(video, 0, 0, 1, 1);
          const level = ctx.getImageData(0, 0, 1, 1).data[0];
          const band = level <= 50 ? 'dark' : level >= 190 ? 'light' : null;
          if (band && band !== window.fixtureBands.at(-1)) window.fixtureBands.push(band);
          video.requestVideoFrameCallback(frame);
        }
        video.requestVideoFrameCallback(frame);
      };
      await peer.setRemoteDescription(offer);
      // The offerer is reachable on loopback. No non-loopback browser candidate is sent to it.
      await peer.setLocalDescription(await peer.createAnswer());
      return { type: peer.localDescription.type, sdp: peer.localDescription.sdp
        .split('\r\n').filter(line => !line.startsWith('a=candidate:') || line.split(/\s+/)[4] === '127.0.0.1').join('\r\n') };
    }, offer);
    source.stdin.write(JSON.stringify(answer) + '\n');
    if (mismatch) {
      const [status] = await done;
      assert.equal(status, 1, diagnostics);
      assert.match(diagnostics, /actual DTLS peer does not match/);
      assert.equal(await page.evaluate(() => window.fixtureBands.length), 0);
      console.log('Mismatched certificate rejected before a frame was presented.');
      return;
    }
    await page.waitForFunction(() => window.fixtureBands.length >= 4, { }, { timeout: 18_000 });
    const result = await page.evaluate(async () => {
      const report = await window.fixturePeer.getStats();
      const video = [...report.values()].find(s => s.type === 'inbound-rtp' && s.kind === 'video');
      const codec = report.get(video.codecId);
      return { bands: window.fixtureBands, codec: codec.mimeType, frames: video.framesDecoded };
    });
    assert.equal(result.codec.toLowerCase(), 'video/h264');
    assert.ok(result.frames >= 4);
    assert.deepEqual(result.bands.slice(0, 4), ['dark', 'light', 'dark', 'light']);
    console.log('Native H.264 over loopback WebRTC:', result);
    // Revoking the private fixture pipe must stop the native sender before its frame budget.
    source.stdin.end();
    const [status] = await done;
    assert.equal(status, 0, 'native sender did not finish cleanly');
  } finally {
    if (source.exitCode === null) source.kill();
    await page.close();
  }
}

try {
  await run(false);
  await run(true);
} finally {
  await browser.close();
}
