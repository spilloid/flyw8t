// flyw8t attended support (browser screen view). Loaded only on /support/{id} and /s/session.
// The server relays signaling only after the participant allows; media is WebRTC between the
// two browsers. Both sides show a short code derived from the two DTLS fingerprints so the
// people can confirm no one is in the middle (docs/attended-support.md).
(() => {
  'use strict';
  const root = document.getElementById('support');
  if (!root) return;
  const role = root.dataset.role;
  const ice = JSON.parse(root.dataset.ice || '[]');
  const $ = (id) => document.getElementById(id);
  const setText = (id, text) => { const el = $(id); if (el) el.textContent = text; };
  const show = (id, on) => { const el = $(id); if (el) el.hidden = !on; };
  const path = role === 'technician'
    ? `/api/support/${root.dataset.session}/ws`
    : '/api/support/participant/ws';

  let ws = null;
  let pc = null;
  let stream = null;
  let ended = false;

  const send = (msg) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg)); };

  const badgeClass = (state) => ({ connected: 'badge good', connection_failed: 'badge bad' }[state]
    || (['connecting', 'waiting', 'authorizing', 'created'].includes(state) ? 'badge busy' : 'badge neutral'));

  function setBadge(state, label) {
    const badge = $('state-badge');
    if (badge) { badge.textContent = label; badge.className = badgeClass(state); }
  }

  function render(state, label, peerPresent) {
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

  function finish(state, label) {
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
    if (pc) pc.close();
    if (stream) stream.getTracks().forEach((t) => t.stop());
    const video = $('remote');
    if (video) video.srcObject = null;
  }

  async function showSecurityCode() {
    const fingerprint = (sdp) => ((sdp || '').match(/^a=fingerprint:\S+ (\S+)/m) || [])[1] || '';
    const a = fingerprint(pc.localDescription && pc.localDescription.sdp);
    const b = fingerprint(pc.remoteDescription && pc.remoteDescription.sdp);
    if (!a || !b) return;
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode([a, b].sort().join('|'))));
    const n = ((digest[0] << 16) | (digest[1] << 8) | digest[2]) % 1000000;
    const code = String(n).padStart(6, '0');
    setText('sas', `${code.slice(0, 3)} ${code.slice(3)}`);
    show('sas-box', true);
  }

  function newPeerConnection() {
    pc = new RTCPeerConnection({ iceServers: ice });
    pc.onicecandidate = (e) => { if (e.candidate) send({ type: 'signal', data: { candidate: e.candidate.toJSON() } }); };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') {
        send({ type: 'media', state: 'connected' });
        showSecurityCode();
      } else if (pc.connectionState === 'failed') {
        send({ type: 'media', state: 'failed' });
      }
    };
    pc.ontrack = (e) => {
      const video = $('remote');
      if (video) video.srcObject = e.streams[0] || new MediaStream([e.track]);
    };
  }

  async function onSignal(data) {
    if (data.sdp) {
      if (!pc) newPeerConnection();
      await pc.setRemoteDescription(data.sdp);
      if (data.sdp.type === 'offer') {
        await pc.setLocalDescription(await pc.createAnswer());
        send({ type: 'signal', data: { sdp: pc.localDescription } });
      }
    } else if (data.candidate && pc) {
      try { await pc.addIceCandidate(data.candidate); } catch (_) { /* stale candidate */ }
    }
  }

  async function startSharing() {
    newPeerConnection();
    stream.getTracks().forEach((track) => {
      pc.addTrack(track, stream);
      // The browser's own "Stop sharing" button ends the session.
      track.onended = () => send({ type: 'end' });
    });
    await pc.setLocalDescription(await pc.createOffer());
    send({ type: 'signal', data: { sdp: pc.localDescription } });
  }

  function connect() {
    ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`);
    ws.onmessage = async (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'state') {
        render(msg.state, msg.label, msg.peer_present);
        if (role === 'participant' && msg.state === 'connecting' && stream && !pc) await startSharing();
      } else if (msg.type === 'signal') {
        await onSignal(msg.data);
      } else if (msg.type === 'ended') {
        finish(msg.state, msg.label);
      } else if (msg.type === 'error') {
        setText('error', msg.message);
      }
    };
    ws.onclose = () => { if (!ended) setText('error', 'The connection to the server was lost. Reload the page to reconnect.'); };
  }

  if (role === 'participant') {
    $('allow').addEventListener('click', async () => {
      setText('error', '');
      try {
        // The browser's own picker: the person chooses exactly what to share, or nothing.
        stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
      } catch (_) {
        setText('error', 'Nothing was shared. You can try again, or decline.');
        return;
      }
      send({ type: 'approve' });
    });
    $('decline').addEventListener('click', () => send({ type: 'decline' }));
    $('end').addEventListener('click', () => send({ type: 'end' }));
  } else {
    const endLive = $('end-live');
    if (endLive) endLive.addEventListener('click', (e) => { e.preventDefault(); send({ type: 'end' }); });
  }
  if (root.dataset.state !== 'ended') connect();
})();
