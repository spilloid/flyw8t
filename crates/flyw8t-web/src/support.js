// flyw8t attended support (browser screen view). Loaded only on /support/{id} and /s/session.
// The server relays signaling only after the participant allows; media is WebRTC between the
// two browsers.
//
// Fail closed: whenever this page can no longer reach the server (or the person ends the
// session, or the page goes away) it stops capture and closes the media connection itself,
// without waiting for anyone.
//
// Security code (docs/attended-support.md § Security code): each browser fixes its DTLS
// certificate before any signaling. Right after consent the technician sends a commitment to
// its certificate; the participant refuses to make an offer until it has one, and once media
// connects it checks that the certificate actually in use matches it. Both then show a code
// derived from the two certificates actually in use, which the people compare out loud.
(() => {
  'use strict';
  const root = document.getElementById('support');
  if (!root) return;
  const role = root.dataset.role;
  const sessionId = root.dataset.session || '';
  const ice = JSON.parse(root.dataset.ice || '[]');
  const $ = (id) => document.getElementById(id);
  const setText = (id, text) => { const el = $(id); if (el) el.textContent = text; };
  const show = (id, on) => { const el = $(id); if (el) el.hidden = !on; };
  const path = role === 'technician'
    ? `/api/support/${sessionId}/ws`
    : '/api/support/participant/ws';

  let ws = null;
  let pc = null;
  let stream = null;
  let ended = false;
  let cert = null;
  let commitment = null; // participant: the technician's commitment, from signaling
  let committed = false; // technician: commitment sent
  let offered = false; // technician: one offer per session, never a renegotiation
  let picker = 0; // participant: generation of the screen picker; bumped to cancel it

  const send = (msg) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg)); };
  const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  const sha256 = async (data) => hex(await crypto.subtle.digest('SHA-256',
    typeof data === 'string' ? new TextEncoder().encode(data) : data));
  const certReady = RTCPeerConnection.generateCertificate({ name: 'ECDSA', namedCurve: 'P-256' })
    .then((c) => { cert = c; return c; });
  const localFingerprint = () => {
    const f = cert.getFingerprints().find((x) => x.algorithm === 'sha-256');
    return f ? f.value.replace(/:/g, '').toLowerCase() : '';
  };
  const commitTo = (fp) => sha256(`flyw8t-sas-commit-v1|${sessionId}|${fp}`);

  const badgeClass = (state) => ({ connected: 'badge good', connection_failed: 'badge bad' }[state]
    || (['connecting', 'waiting', 'authorizing', 'created'].includes(state) ? 'badge busy' : 'badge neutral'));

  function setBadge(state, label) {
    const badge = $('state-badge');
    if (badge) { badge.textContent = label; badge.className = badgeClass(state); }
  }

  function render(state, label, peerPresent) {
    if (ended) return;
    root.dataset.state = state;
    setText('state', label);
    setBadge(state, label);
    if (role === 'participant') {
      show('decide', state === 'authorizing');
      show('end', state === 'connecting' || state === 'connected');
    } else {
      setText('peer', peerPresent ? 'The other person has this session open.' : 'The other person does not have this session open yet.');
      show('viewer', state === 'connecting' || state === 'connected');
    }
  }

  // Stop every local media resource. Safe to call any number of times.
  function stopMedia() {
    picker += 1; // a picker still open is now stale: whatever it returns is stopped at once
    if (pc) { pc.close(); pc = null; }
    if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
    const video = $('remote');
    if (video) video.srcObject = null;
  }

  function finish(state, label) {
    stopMedia();
    if (ended) return;
    ended = true;
    root.dataset.state = 'ended';
    setText('state', label);
    setBadge(state, label);
    show('decide', false);
    show('end', false);
    show('end-live', false);
    show('sas-box', false);
    show('viewer', false);
    setText('peer', '');
  }

  // End from this page: stop locally first, then tell the server if it can still hear us.
  function endHere(state, label) {
    finish(state, label);
    send({ type: 'end' });
  }

  async function securityCheck() {
    const transport = ((pc.getSenders()[0] || pc.getReceivers()[0]) || {}).transport;
    const remote = transport && transport.getRemoteCertificates ? transport.getRemoteCertificates() : [];
    if (!remote.length) {
      root.dataset.sas = 'unavailable';
      setText('sas', 'not available in this browser');
      show('sas-box', true);
      return;
    }
    const theirs = await sha256(remote[0]);
    const mine = localFingerprint();
    if (role === 'participant' && (await commitTo(theirs)) !== commitment) {
      // The certificate in use is not the one the technician committed to.
      root.dataset.sas = 'mismatch';
      endHere('connection_failed', 'Stopped: this connection is not the one your technician set up. Someone may be in the middle.');
      return;
    }
    const [tech, part] = role === 'technician' ? [mine, theirs] : [theirs, mine];
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(`flyw8t-sas-v1|${sessionId}|${tech}|${part}`)));
    const n = (((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3]) % 1000000;
    const code = String(n).padStart(6, '0');
    if (ended) return;
    root.dataset.sas = 'shown';
    setText('sas', `${code.slice(0, 3)} ${code.slice(3)}`);
    show('sas-box', true);
  }

  function newPeerConnection() {
    pc = new RTCPeerConnection({ iceServers: ice, certificates: [cert] });
    const mine = pc;
    pc.onicecandidate = (e) => { if (e.candidate && pc === mine) send({ type: 'signal', data: { candidate: e.candidate.toJSON() } }); };
    pc.onconnectionstatechange = () => {
      if (pc !== mine) return;
      if (pc.connectionState === 'connected') {
        send({ type: 'media', state: 'connected' });
        securityCheck();
      } else if (pc.connectionState === 'failed') {
        send({ type: 'media', state: 'failed' });
      }
    };
    pc.ontrack = (e) => {
      const video = $('remote');
      if (video && pc === mine) video.srcObject = e.streams[0] || new MediaStream([e.track]);
    };
  }

  async function onSignal(data) {
    if (ended) return;
    if (data.commit && role === 'participant') {
      if (commitment === null) commitment = String(data.commit);
      await maybeStartSharing();
    } else if (data.sdp && role === 'technician' && data.sdp.type === 'offer') {
      if (offered) return; // the certificate was committed to once; no renegotiation
      offered = true;
      await certReady;
      newPeerConnection();
      await pc.setRemoteDescription(data.sdp);
      await pc.setLocalDescription(await pc.createAnswer());
      send({ type: 'signal', data: { sdp: pc.localDescription } });
    } else if (data.sdp && role === 'participant' && data.sdp.type === 'answer' && pc && !pc.remoteDescription) {
      await pc.setRemoteDescription(data.sdp);
    } else if (data.candidate && pc) {
      try { await pc.addIceCandidate(data.candidate); } catch (_) { /* stale candidate */ }
    }
  }

  // The participant offers only with consent given, a stream chosen, and the technician's
  // commitment in hand.
  async function maybeStartSharing() {
    if (ended || pc || !stream || commitment === null || root.dataset.state !== 'connecting') return;
    await certReady;
    if (ended || pc || !stream) return;
    newPeerConnection();
    stream.getTracks().forEach((track) => pc.addTrack(track, stream));
    await pc.setLocalDescription(await pc.createOffer());
    send({ type: 'signal', data: { sdp: pc.localDescription } });
  }

  async function onState(msg) {
    render(msg.state, msg.label, msg.peer_present);
    if (msg.state !== 'connecting') return;
    if (role === 'technician' && !committed) {
      committed = true;
      await certReady;
      send({ type: 'signal', data: { commit: await commitTo(localFingerprint()) } });
    } else if (role === 'participant') {
      await maybeStartSharing();
    }
  }

  function connect() {
    ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`);
    ws.onmessage = async (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'state') {
        await onState(msg);
      } else if (msg.type === 'signal') {
        await onSignal(msg.data || {});
      } else if (msg.type === 'ended') {
        finish(msg.state, msg.label);
      } else if (msg.type === 'error') {
        setText('error', msg.message);
      }
    };
    // Without the server, nobody could end this session through it: end it here.
    const lost = () => finish('connection_failed', 'Disconnected from the server, so the session was stopped here. Reload the page to see its state.');
    ws.onclose = lost;
    ws.onerror = lost;
  }

  if (role === 'participant') {
    const allow = $('allow');
    allow.addEventListener('click', async () => {
      if (ended || allow.disabled) return;
      setText('error', '');
      allow.disabled = true;
      const mine = ++picker;
      let chosen;
      try {
        // The browser's own picker: the person chooses exactly what to share, or nothing.
        chosen = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
      } catch (_) {
        if (mine === picker && !ended) {
          allow.disabled = false;
          setText('error', 'Nothing was shared. You can try again, or decline.');
        }
        return;
      }
      if (ended || mine !== picker) {
        // The session ended while the picker was open: never start capturing now.
        chosen.getTracks().forEach((t) => t.stop());
        return;
      }
      stream = chosen;
      // The browser's own "Stop sharing" button ends the session.
      stream.getTracks().forEach((t) => { t.onended = () => endHere('closed', 'You stopped sharing. The session has ended.'); });
      send({ type: 'approve' });
    });
    $('decline').addEventListener('click', () => {
      send({ type: 'decline' });
      finish('rejected', 'Declined');
    });
    $('end').addEventListener('click', () => endHere('closed', 'You ended the session.'));
  } else {
    const endLive = $('end-live');
    // With a live socket, end at once; otherwise the form posts as usual.
    if (endLive) {
      endLive.addEventListener('click', (e) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
          e.preventDefault();
          endHere('closed', 'You ended the session.');
        }
      });
    }
  }
  window.addEventListener('pagehide', () => endHere('closed', 'Ended'));
  if (root.dataset.state !== 'ended') connect();
})();
