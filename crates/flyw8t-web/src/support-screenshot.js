// The support page supplies the current track and owns all media. This module can only read
// the technician's video after an explicit screenshot grant for that same stream.
function attendedScreenshots({ root, role, session, element, send, source, usable }) {
  const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
  let grant = null;
  let capture = null;
  let lastRequest = null;
  const originalTitle = document.title;

  const visible = (id, show) => { const el = element(id); if (el) el.hidden = !show; };
  const label = (id, value) => { const el = element(id); if (el) el.textContent = value; };
  function display() {
    const pending = grant?.phase === 'requested';
    const active = grant?.phase === 'allowed';
    if (role === 'participant') {
      document.title = pending ? 'Screenshot permission requested · flyw8t' : originalTitle;
      visible('screenshot-panel', Boolean(grant));
      if (!grant) return;
      label('screenshot-recipient', grant.recipient);
      label('screenshot-title', active ? 'Screenshots are on' : 'Allow screenshots?');
      label('screenshot-description', active
        ? 'This client can receive still images of your shared screen. You can turn this off and keep sharing with your technician.'
        : 'This client is asking to receive still images of what you share for this session. You can turn access off at any time.');
      visible('screenshot-allow', !active);
      visible('screenshot-decline', !active);
      visible('screenshot-revoke', active);
      element('screenshot-allow').disabled = !pending;
    } else {
      visible('screenshot-status', Boolean(active));
      label('screenshot-status', active ? 'Screenshots allowed for ' + grant.recipient + '.' : '');
    }
  }

  function clear(notify = false) {
    if (notify && grant) send({ type: 'screenshot_permission', grant_id: grant.id, allow: false });
    capture?.abort();
    capture = null;
    grant = null;
    display();
  }

  // These listeners are attached once per media source. Track/stream replacement, removal
  // or temporary loss must not carry a grant into the next source.
  function watchSource(stream, track) {
    const changed = () => { if (grant?.stream === stream) clear(true); };
    stream?.addEventListener?.('addtrack', changed);
    stream?.addEventListener?.('removetrack', changed);
    for (const event of ['ended', 'mute', 'capturehandlechange', 'configurationchange']) {
      track?.addEventListener?.(event, changed);
    }
  }

  function hasSource(permission) {
    const stream = source();
    const tracks = stream?.getVideoTracks?.();
    return usable() && permission.stream === stream && tracks?.length === 1
      && permission.track === tracks[0] && tracks[0].readyState === 'live' && !tracks[0].muted;
  }

  function permission(msg) {
    if (!uuid.test(msg.grant_id) || typeof msg.recipient !== 'string') return;
    if (msg.type === 'screenshot_allowed' && role === 'participant') {
      if (grant?.id !== msg.grant_id || grant.phase !== 'accepting' || !hasSource(grant)) return;
      grant.phase = 'allowed';
    } else {
      clear();
      const stream = source();
      grant = { id: msg.grant_id, recipient: msg.recipient, stream, track: stream?.getVideoTracks?.()[0],
        phase: msg.type === 'screenshot_consent' ? 'requested' : 'allowed' };
      if (!hasSource(grant)) { clear(true); return; }
    }
    display();
  }

  function decide(allow) {
    if (!grant) return;
    if (!allow || !hasSource(grant)) {
      clear(true);
      element('end')?.focus?.({ preventScroll: true });
      return;
    }
    if (grant.phase !== 'requested') return;
    grant.phase = 'accepting';
    display();
    send({ type: 'screenshot_permission', grant_id: grant.id, allow: true });
  }
  if (role === 'participant') {
    element('screenshot-allow')?.addEventListener('click', () => decide(true));
    element('screenshot-decline')?.addEventListener('click', () => decide(false));
    element('screenshot-revoke')?.addEventListener('click', () => decide(false));
  }

  function cropRectangle(crop, width, height) {
    if (crop == null) return [0, 0, width, height];
    const { x, y, width: w, height: h } = crop;
    if (![x, y, w, h].every(Number.isFinite) || x < 0 || y < 0 || w <= 0 || h <= 0 || x + w > 1 || y + h > 1) {
      throw new Error('capture_failed');
    }
    // Rounding inward keeps samples outside the requested rectangle out of the image.
    const left = Math.ceil(x * width), top = Math.ceil(y * height);
    const pixelsWide = Math.floor((x + w) * width) - left;
    const pixelsHigh = Math.floor((y + h) * height) - top;
    if (pixelsWide < 1 || pixelsHigh < 1) throw new Error('capture_failed');
    return [left, top, pixelsWide, pixelsHigh];
  }

  function nextFrame(video, crop, signal, valid) {
    return new Promise((resolve, reject) => {
      if (!video.requestVideoFrameCallback || !valid()) { reject(new Error('no_fresh_frame')); return; }
      let frame;
      const stop = () => {
        clearTimeout(timer);
        video.cancelVideoFrameCallback?.(frame);
        signal.removeEventListener('abort', aborted);
      };
      const aborted = () => { stop(); reject(new Error('screenshot_revoked')); };
      const timer = setTimeout(() => { stop(); reject(new Error('no_fresh_frame')); }, 2000);
      signal.addEventListener('abort', aborted, { once: true });
      frame = video.requestVideoFrameCallback((now, meta) => {
        stop();
        try {
          if (!valid()) throw new Error('source_changed');
          const observedAt = meta?.receiveTime ?? meta?.presentationTime;
          if (video.readyState < 2 || !video.videoWidth || !video.videoHeight
              || !Number.isFinite(observedAt) || observedAt > now + 100
              || now - observedAt > 3000) throw new Error('no_fresh_frame');
          const observed = Date.now();
          const [x, y, w, h] = cropRectangle(crop, video.videoWidth, video.videoHeight);
          const scale = Math.min(1, 1920 / Math.max(w, h));
          const canvas = document.createElement('canvas');
          canvas.width = Math.max(1, Math.floor(w * scale));
          canvas.height = Math.max(1, Math.floor(h * scale));
          canvas.getContext('2d', { alpha: false }).drawImage(video, x, y, w, h, 0, 0, canvas.width, canvas.height);
          resolve({ canvas, observed });
        } catch (err) { reject(err); }
      });
    });
  }

  async function boundedPng(original, valid) {
    let canvas = original;
    const limit = 512 * 1024;
    for (;;) {
      if (!valid()) throw new Error('screenshot_revoked');
      const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
      if (!blob || !blob.size || blob.type !== 'image/png') throw new Error('capture_failed');
      if (blob.size <= limit) return { bytes: await blob.arrayBuffer(), width: canvas.width, height: canvas.height };
      if (canvas.width === 1 && canvas.height === 1) throw new Error('image_too_large');
      const scale = Math.min(0.75, Math.sqrt(limit / blob.size) * 0.95);
      const smaller = document.createElement('canvas');
      smaller.width = Math.max(1, Math.floor(canvas.width * scale));
      smaller.height = Math.max(1, Math.floor(canvas.height * scale));
      smaller.getContext('2d', { alpha: false }).drawImage(original, 0, 0, smaller.width, smaller.height);
      canvas = smaller;
    }
  }

  function base64(buffer) {
    const bytes = new Uint8Array(buffer), parts = [];
    for (let i = 0; i < bytes.length; i += 8192) parts.push(String.fromCharCode(...bytes.subarray(i, i + 8192)));
    return btoa(parts.join(''));
  }

  async function encrypt(png, observed, msg) {
    const raw = Uint8Array.from(atob(msg.public_key), c => c.charCodeAt(0));
    const curve = { name: 'ECDH', namedCurve: 'P-256' };
    const recipient = await crypto.subtle.importKey('raw', raw, curve, false, []);
    const pair = await crypto.subtle.generateKey(curve, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'ECDH', public: recipient }, pair.privateKey,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new Uint8Array(16 + png.bytes.byteLength);
    const header = new DataView(data.buffer);
    header.setBigUint64(0, BigInt(observed));
    header.setUint32(8, png.width);
    header.setUint32(12, png.height);
    data.set(new Uint8Array(png.bytes), 16);
    const aad = new TextEncoder().encode(['flyw8t-screenshot-v1', session, msg.request_id].join('\n'));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, data);
    return { public_key: base64(await crypto.subtle.exportKey('raw', pair.publicKey)), iv: base64(iv), ciphertext: base64(ciphertext) };
  }

  async function captureOne(msg) {
    if (capture || !uuid.test(msg.request_id) || lastRequest === msg.request_id
        || grant?.id !== msg.grant_id || grant?.phase !== 'allowed') return;
    const owner = grant;
    const pending = new AbortController();
    capture = pending;
    lastRequest = msg.request_id;
    const valid = () => grant === owner && !pending.signal.aborted && hasSource(owner);
    const status = text => { if (grant === owner && capture === pending) label('screenshot-status', text); };
    const slow = setTimeout(() => status('Preparing a screenshot for ' + owner.recipient + '…'), 900);
    const deadline = setTimeout(() => {
      if (capture !== pending) return;
      status('The screenshot request expired. Keep the viewer open for the next request.');
      pending.abort();
      capture = null;
    }, 8000);
    let result;
    try {
      const frame = await nextFrame(element('remote'), msg.crop, pending.signal, valid);
      const png = await boundedPng(frame.canvas, valid);
      if (!valid()) throw new Error('source_changed');
      result = { envelope: await encrypt(png, frame.observed, msg) };
      if (!valid()) throw new Error('source_changed');
      if (Date.now() - frame.observed > 3000) throw new Error('no_fresh_frame');
    } catch (err) {
      const reason = ['source_changed', 'screenshot_revoked', 'no_fresh_frame', 'image_too_large'].includes(err.message)
        ? err.message : 'capture_failed';
      result = { error: reason };
    }
    try {
      if (grant !== owner || pending.signal.aborted) return;
      if (!hasSource(owner)) { clear(true); return; }
      const response = await fetch('/support/' + session + '/screenshot/' + msg.request_id, {
        method: 'POST', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
        headers: { 'Content-Type': 'application/json' }, signal: pending.signal,
        body: JSON.stringify({ grant_id: owner.id, csrf: root.dataset.csrf, ...result }),
      });
      if (!response.ok) status('The server could not accept this screenshot. Check that the request is still open.');
      else if (result.error === 'no_fresh_frame') status('No fresh frame was available. Keep the viewer visible for the next screenshot.');
      else if (result.error) status('The viewer could not take a screenshot of this shared screen.');
      else status('Screenshot ready for ' + owner.recipient + '.');
    } catch (_) {
      status('Could not reach the support server to return the screenshot.');
    } finally {
      clearTimeout(slow);
      clearTimeout(deadline);
      if (capture === pending) capture = null;
    }
  }

  function message(msg) {
    if (msg.type === 'screenshot_revoked') {
      if (grant && grant.id === msg.grant_id) clear();
    } else if (msg.type === 'screenshot_allowed' || (msg.type === 'screenshot_consent' && role === 'participant')) {
      permission(msg);
    } else if (msg.type === 'screenshot_capture' && role === 'technician') {
      return captureOne(msg);
    }
  }
  return { message, clear, watchSource };
}
