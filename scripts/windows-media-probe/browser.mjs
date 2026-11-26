// Drive the installed Edge with a synthetic MP4 emitted by the native test process.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { chromium } from 'playwright-core';

assert.equal(process.argv.length, 3, 'usage: node browser.mjs <probe executable>');
const fixture = execFileSync(resolve(process.argv[2]), ['--emit-mp4'], {
  maxBuffer: 2 * 1024 * 1024,
  timeout: 30_000,
  windowsHide: true,
});
const browser = await chromium.launch({ channel: 'msedge', headless: true });
try {
  const page = await browser.newPage();
  const samples = await page.evaluate(async encoded => {
    const video = document.createElement('video');
    video.muted = true;
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = 1;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const event = type => new Promise((resolve, reject) => {
      const controller = new AbortController();
      const timer = setTimeout(() => finish(new Error(type + ' timed out')), 5000);
      function finish(error) {
        clearTimeout(timer);
        controller.abort();
        if (error) reject(error);
        else resolve();
      }
      video.addEventListener(type, () => finish(), { signal: controller.signal });
      video.addEventListener('error', () => finish(new Error(video.error?.message || 'decoder error')), { signal: controller.signal });
    });
    const ready = event('loadeddata');
    video.src = 'data:video/mp4;base64,' + encoded;
    await ready;
    const samples = [];
    for (const frame of [4, 12, 20, 28]) {
      const sought = event('seeked');
      video.currentTime = frame / 30;
      await sought;
      ctx.drawImage(video, 0, 0, 1, 1);
      samples.push(ctx.getImageData(0, 0, 1, 1).data[0]);
    }
    return { width: video.videoWidth, height: video.videoHeight, samples };
  }, fixture.toString('base64'));
  assert.equal(samples.width, 320);
  assert.equal(samples.height, 180);
  for (const [i, luma] of samples.samples.entries()) {
    assert.ok(i % 2 === 0 ? luma <= 50 : luma >= 190, 'unexpected decoded sample ' + i + ': ' + luma);
  }
  console.log('Edge decoded all four alternating bands:', samples.samples.join(', '));
} finally {
  await browser.close();
}
