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
  // A control session: the native helper captures and takes input (ADR-0012); this page only
  // consents, shows status, offers the helper and can end it.
  const control = root.dataset.control === '1';
  const sessionId = root.dataset.session || '';
  const ice = JSON.parse(root.dataset.ice || '[]');
  const $ = (id) => document.getElementById(id);
  const setText = (id, text) => { const el = $(id); if (el && el.textContent !== text) el.textContent = text; };
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
  let acceptedSdp = false; // exactly one remote offer (technician) or answer (participant)
  const pendingIce = [];
  const maxPendingIce = 64;
  let iceReadyPeer = null;
  let drainingIce = null;
  let epoch = 0; // bumped by every teardown: async work started before it must not act after it
  let sessionState = root.dataset.state;
  let sessionLabel = $('state').textContent;
  let peerPresent = false;
  let frameReady = false;
  let hint = '';
  let hintTimer;
  const routeDetails = role === 'technician' && $('connection-details');
  let routeTransport = null;
  let routeGeneration = 0;
  let routeTimer;

  const send = (msg) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg)); };
  const screenshots = attendedScreenshots({
    root, role, session: sessionId, element: $, send,
    source: () => role === 'technician' ? $('remote')?.srcObject : stream,
    usable: () => !ended && !control && pc?.connectionState === 'connected' && (role === 'participant' || frameReady),
  });
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

  const badgeClass = (state) => ({ connected: 'badge good', interrupted: 'badge busy', connection_failed: 'badge bad' }[state]
    || (['connecting', 'waiting', 'authorizing', 'created'].includes(state) ? 'badge busy' : 'badge neutral'));

  function setBadge(state, label) {
    const badge = $('state-badge');
    if (badge) { badge.textContent = label; badge.className = badgeClass(state); }
  }

  function delayedHint(next) {
    if (next === hint) return;
    clearTimeout(hintTimer);
    hint = next;
    setText('peer', '');
    show('peer', false);
    if (next) hintTimer = setTimeout(() => {
      setText('peer', next);
      show('peer', true);
    }, 2500);
  }

  function contextHint(state) {
    if (state === 'interrupted') return 'The screen connection was interrupted. Check that both devices are still online.';
    if (role === 'technician') {
      if (state === 'created' || state === 'waiting') return 'Send the participant the invitation link or code.';
      if (state === 'authorizing') return 'Ask the participant to review the request on their support page.';
      if (state === 'awaiting_helper') return 'Ask the participant to open the downloaded helper and review its request.';
    }
    if (state !== 'connecting') return '';
    if (!peerPresent) return 'Waiting for the other side. Check that they still have the session open.';
    if (role === 'technician' && pc?.connectionState === 'connected' && !frameReady)
      return 'Waiting for the first frame. Ask the participant to check their shared screen.';
    return 'The screen connection is still starting. Keep the session open on both devices.';
  }

  function render() {
    if (ended) return;
    let state = sessionState;
    let label = sessionLabel;
    const live = state === 'connecting' || state === 'connected';
    if (live && (pc?.connectionState === 'disconnected' || pc?.connectionState === 'failed')) {
      state = 'interrupted';
      label = 'Screen interrupted';
    } else if (state === 'connected' && !(control && role === 'participant')
      && (pc?.connectionState !== 'connected' || (role === 'technician' && !frameReady))) {
      state = 'connecting';
      label = 'Waiting for the screen';
    }
    root.dataset.state = state;
    setText('state', label);
    setBadge(state, label);
    delayedHint(contextHint(state));
    if (role === 'participant') {
      const heading = $('participant-heading');
      if (state !== 'authorizing' && heading?.dataset.live) setText('participant-heading', heading.dataset.live);
      show('screen-permissions', state === 'authorizing');
      show('decide', state === 'authorizing');
      show('helper-box', control && state === 'awaiting_helper');
      show('end', live);
    } else {
      show('viewer', live);
    }
  }

  // Stop every local media resource. Safe to call any number of times.
  function stopMedia() {
    screenshots.clear();
    epoch += 1; // anything still in flight (a screen picker, an offer, an answer) is now stale
    pendingIce.length = 0;
    iceReadyPeer = drainingIce = null;
    if (pc) { pc.close(); pc = null; }
    refreshRoute();
    if (stream) { stream.getTracks().forEach((t) => t.stop()); stream = null; }
    const video = $('remote');
    if (video) video.srcObject = null;
  }

  function finish(state, label) {
    stopMedia();
    if (ended) return;
    ended = true;
    delayedHint('');
    root.dataset.state = 'ended';
    setText('state', label);
    setBadge(state, label);
    if (role === 'participant') setText('participant-heading', 'Session ended');
    show('screen-permissions', false);
    show('decide', false);
    show('end', false);
    show('end-live', false);
    show('sas-box', false);
    show('viewer', false);
    show('helper-box', false);
    setText('peer', '');
  }

  // End from this page: stop locally first, then tell the server if it can still hear us.
  function endHere(state, label) {
    finish(state, label);
    send({ type: 'end' });
  }

  // Exactly one media section, carrying video: the screen. Anything else (a second section, a
  // second transport) could carry media the security code does not cover, so it is refused.
  const oneVideoSection = (sdp) => {
    const m = String((sdp && sdp.sdp) || '').match(/^m=\S+/gm) || [];
    return m.length === 1 && m[0] === 'm=video';
  };
  const refuseTopology = () => endHere('connection_failed', 'Stopped: the connection did not have the expected shape (one shared screen). Someone may be tampering with it.');

  // The one transport that media uses: the participant's single sender, or the technician's
  // single receiver (the one whose track is on screen).
  function mediaTransport() {
    const ends = role === 'participant' ? pc.getSenders() : pc.getReceivers();
    return ends.length === 1 ? ends[0].transport : null;
  }

  function routeLabel(local, remote) {
    if (local === 'relay' || remote === 'relay') return 'TURN relay';
    const direct = ['host', 'srflx', 'prflx'];
    return direct.includes(local) && direct.includes(remote) ? 'Direct' : 'Unavailable';
  }

  async function selectedRoute(conn, transport) {
    const pair = transport?.getSelectedCandidatePair?.();
    if (pair) return routeLabel(pair.local?.type, pair.remote?.type);
    // A nominated or successful pair can be idle. Follow the transport's selected pair.
    const stats = await conn.getStats();
    for (const entry of stats.values()) {
      if (entry.type !== 'transport' || !entry.selectedCandidatePairId) continue;
      const active = stats.get(entry.selectedCandidatePairId);
      if (active?.type === 'candidate-pair') {
        return routeLabel(stats.get(active.localCandidateId)?.candidateType,
          stats.get(active.remoteCandidateId)?.candidateType);
      }
    }
    return 'Unavailable';
  }

  async function refreshRoute() {
    if (!routeDetails) return;
    const generation = ++routeGeneration;
    clearTimeout(routeTimer);
    const conn = pc;
    const visible = routeDetails.open && !document.hidden && !ended && conn?.connectionState === 'connected';
    const ice = visible ? mediaTransport()?.iceTransport : null;
    const observable = ice && 'onselectedcandidatepairchange' in ice ? ice : null;
    if (observable !== routeTransport) {
      routeTransport?.removeEventListener('selectedcandidatepairchange', refreshRoute);
      routeTransport = observable;
      routeTransport?.addEventListener('selectedcandidatepairchange', refreshRoute);
    }
    if (!visible) { setText('connection-route', 'Unavailable'); return; }
    let label = 'Unavailable';
    try { label = await selectedRoute(conn, ice); } catch (_) { /* browser statistics unavailable */ }
    if (generation !== routeGeneration || ended || conn !== pc || !routeDetails.open || document.hidden
        || conn.connectionState !== 'connected') return;
    setText('connection-route', label);
    // A few browsers expose selection only through stats. Sample while the details are visible.
    if (!observable) routeTimer = setTimeout(refreshRoute, 5000);
  }

  async function securityCheck(conn, mine0) {
    const transport = mediaTransport();
    if (!transport) { refuseTopology(); return; }
    // The certificate can lag the "connected" event by a moment; wait briefly before saying
    // this browser cannot show a code.
    const certificates = () => (transport.getRemoteCertificates ? transport.getRemoteCertificates() : []);
    let remote = certificates();
    for (let i = 0; !remote.length && transport.getRemoteCertificates && i < 30; i++) {
      await new Promise((r) => setTimeout(r, 100));
      if (stale(conn, mine0)) return;
      remote = certificates();
    }
    if (!remote.length) {
      root.dataset.sas = 'unavailable';
      setText('sas', 'not available in this browser');
      show('sas-box', true);
      return;
    }
    const theirs = await sha256(remote[0]);
    if (stale(conn, mine0)) return;
    const mine = localFingerprint();
    if (role === 'participant' && (await commitTo(theirs)) !== commitment) {
      // The certificate in use is not the one the technician committed to.
      root.dataset.sas = 'mismatch';
      endHere('connection_failed', 'Stopped: this connection is not the one your technician set up. Someone may be in the middle.');
      return;
    }
    const [tech, part] = role === 'technician' ? [mine, theirs] : [theirs, mine];
    const code = await securityCode(sessionId, tech, part);
    if (stale(conn, mine0)) return;
    root.dataset.sas = 'shown';
    setText('sas', `${code.slice(0, 3)} ${code.slice(3)}`);
    show('sas-box', true);
  }

  async function securityCode(session, techFp, partFp) {
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(`flyw8t-sas-v1|${session}|${techFp}|${partFp}`)));
    const n = (((d[0] << 24) >>> 0) + (d[1] << 16) + (d[2] << 8) + d[3]) % 1000000;
    return String(n).padStart(6, '0');
  }

  // An operation started before an ending, or for a connection since replaced, must not act.
  const stale = (conn, mine) => ended || mine !== epoch || (conn !== undefined && pc !== conn);

  async function drainIce() {
    const conn = iceReadyPeer;
    if (!conn || drainingIce === conn) return;
    const mine = epoch;
    drainingIce = conn;
    while (pendingIce.length && !stale(conn, mine)) {
      const candidate = pendingIce.shift();
      try { await conn.addIceCandidate(candidate); } catch (_) { /* invalid or obsolete candidate */ }
    }
    if (drainingIce === conn) drainingIce = null;
  }

  async function acceptRemoteSdp(conn, sdp, mine) {
    await conn.setRemoteDescription(sdp);
    if (stale(conn, mine)) return;
    iceReadyPeer = conn;
    void drainIce(); // Applying candidates must not delay SDP, End, or revocation.
  }

  function newPeerConnection(relayOnly = false) {
    // One bundled transport for everything: the security code covers exactly that transport.
    pc = new RTCPeerConnection({ iceServers: ice, iceTransportPolicy: relayOnly ? 'relay' : 'all', certificates: [cert], bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require' });
    const conn = pc;
    const mine = epoch;
    let shown = false;
    let reported = false;
    let frameGeneration = 0;
    // Once interrupted, an already decoded frame may still be visible in the element.
    // A fresh frame confirms recovery even if the server still has both original reports.
    let framesAtInterruption = null;
    const video = $('remote');
    function reportReady() {
      if (!reported && conn.connectionState === 'connected' && (role === 'participant' || frameReady)) {
        reported = true;
        send({ type: 'media', state: 'connected' });
      }
    }
    function watchFrame() {
      if (!video?.srcObject || conn.connectionState !== 'connected' || frameReady) return;
      const check = ++frameGeneration;
      const received = () => {
        if (stale(conn, mine) || check !== frameGeneration || conn.connectionState !== 'connected') return;
        frameReady = true;
        video.onloadeddata = video.ontimeupdate = null;
        reportReady();
        render();
      };
      if (framesAtInterruption === null && video.videoWidth > 0 && video.readyState >= 2) {
        received();
      } else if (video.requestVideoFrameCallback) {
        video.requestVideoFrameCallback(received);
      } else {
        video.onloadeddata = received;
        video.ontimeupdate = () => {
          if (video.videoWidth > 0 && video.getVideoPlaybackQuality?.().totalVideoFrames > (framesAtInterruption ?? 0)) received();
        };
      }
    }
    pc.onicecandidate = (e) => { if (e.candidate && !stale(conn, mine)) send({ type: 'signal', data: { candidate: e.candidate.toJSON() } }); };
    pc.onconnectionstatechange = () => {
      if (stale(conn, mine)) return;
      refreshRoute();
      if (conn.connectionState === 'connected') {
        watchFrame();
        reportReady();
        securityCheck(conn, mine);
      } else if (conn.connectionState === 'disconnected' || conn.connectionState === 'failed') {
        screenshots.clear(true);
        frameGeneration += 1;
        frameReady = false;
        framesAtInterruption = video?.getVideoPlaybackQuality?.().totalVideoFrames ?? 0;
        if (conn.connectionState === 'failed') send({ type: 'media', state: 'failed' });
      }
      render();
    };
    pc.ontrack = (e) => {
      if (stale(conn, mine)) return;
      if (shown || e.track.kind !== 'video') { refuseTopology(); return; }
      shown = true;
      if (video) {
        video.srcObject = e.streams[0] || new MediaStream([e.track]);
        screenshots.watchSource(video.srcObject, e.track);
      }
      watchFrame();
    };
  }

  async function onSignal(data) {
    if (ended) return;
    const mine = epoch;
    if (data.commit && role === 'participant') {
      if (commitment === null) commitment = String(data.commit);
      await maybeStartSharing();
    } else if (data.sdp && role === 'technician' && data.sdp.type === 'offer') {
      if (acceptedSdp) return; // the certificate was committed to once; no renegotiation
      acceptedSdp = true;
      if (!oneVideoSection(data.sdp)) { refuseTopology(); return; }
      await certReady;
      if (stale(undefined, mine)) return;
      newPeerConnection(data.relayOnly === true);
      const conn = pc;
      await acceptRemoteSdp(conn, data.sdp, mine);
      if (stale(conn, mine)) return;
      const answer = await conn.createAnswer();
      if (stale(conn, mine)) return;
      await conn.setLocalDescription(answer);
      if (stale(conn, mine)) return;
      send({ type: 'signal', data: { sdp: conn.localDescription } });
    } else if (data.sdp && role === 'participant' && data.sdp.type === 'answer' && pc && !acceptedSdp) {
      acceptedSdp = true;
      if (!oneVideoSection(data.sdp)) { refuseTopology(); return; }
      await acceptRemoteSdp(pc, data.sdp, mine);
    } else if (data.candidate) {
      if (role === 'participant' && !stream) return;
      if (pendingIce.length >= maxPendingIce) {
        endHere('connection_failed', 'The screen connection stopped after receiving too many pending network candidates.');
        return;
      }
      pendingIce.push(data.candidate);
      void drainIce();
    }
  }

  // The participant offers only with consent given, a stream chosen, and the technician's
  // commitment in hand.
  async function maybeStartSharing() {
    if (ended || pc || !stream || commitment === null || root.dataset.state !== 'connecting') return;
    const mine = epoch;
    await certReady;
    if (stale(undefined, mine) || pc || !stream) return;
    newPeerConnection();
    const conn = pc;
    stream.getVideoTracks().slice(0, 1).forEach((track) => conn.addTrack(track, stream));
    const offer = await conn.createOffer();
    if (stale(conn, mine)) return;
    await conn.setLocalDescription(offer);
    if (stale(conn, mine)) return;
    send({ type: 'signal', data: { sdp: conn.localDescription } });
  }

  async function onState(msg) {
    if (ended) return;
    sessionState = msg.state;
    sessionLabel = msg.label;
    peerPresent = msg.peer_present;
    render();
    if (msg.state !== 'connecting') return;
    if (role === 'technician' && !committed) {
      committed = true;
      const mine = epoch;
      await certReady;
      const commit = await commitTo(localFingerprint());
      if (stale(undefined, mine)) return;
      send({ type: 'signal', data: { commit } });
    } else if (role === 'participant') {
      await maybeStartSharing();
    }
  }

  function connect() {
    delayedHint('Waiting for the support server. Check your network connection.');
    ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${path}`);
    ws.onmessage = async (event) => {
      if (ended) return;
      const msg = JSON.parse(event.data);
      if (msg.type === 'state') {
        await onState(msg);
      } else if (msg.type === 'signal') {
        await onSignal(msg.data || {});
      } else if (typeof msg.type === 'string' && msg.type.startsWith('screenshot_') && !control) {
        await screenshots.message(msg);
      } else if (msg.type === 'ended') {
        finish(msg.state, msg.label);
        if (msg.state === 'connection_failed') {
          setText('peer', 'Check that both devices are online before starting a new session.');
          show('peer', true);
        }
      } else if (msg.type === 'helper' && control && role === 'participant') {
        // Only a helper download from this server ever goes into the link.
        const link = $('helper-link');
        if (link && typeof msg.download === 'string' && msg.download.startsWith('/s/helper/')) link.href = msg.download;
        show('helper-box', true);
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
      if (control) {
        // No picker here: the helper captures, after its own consent.
        allow.disabled = true;
        send({ type: 'approve' });
        return;
      }
      setText('error', '');
      allow.disabled = true;
      const mine = ++epoch;
      let chosen;
      try {
        // The browser's own picker: the person chooses exactly what to share, or nothing.
        chosen = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false, surfaceSwitching: 'exclude' });
      } catch (_) {
        if (mine === epoch && !ended) {
          allow.disabled = false;
          setText('error', 'Nothing was shared. You can try again, or decline.');
        }
        return;
      }
      if (ended || mine !== epoch) {
        // The session ended while the picker was open: never start capturing now.
        chosen.getTracks().forEach((t) => t.stop());
        return;
      }
      stream = chosen;
      screenshots.watchSource(stream, stream.getVideoTracks()[0]);
      // The browser's own "Stop sharing" button ends the session.
      stream.getTracks().forEach((t) => { t.onended = () => endHere('closed', 'You stopped sharing. The session has ended.'); });
      send({ type: 'approve' });
    });
    const cancelHelper = $('cancel-helper');
    if (cancelHelper) {
      // End, not Decline: the helper may already have been allowed, and End stops the
      // session whatever state it reached (the server decides under its row lock).
      cancelHelper.addEventListener('click', () => endHere('closed', 'You cancelled. The session has ended.'));
    }
    $('decline').addEventListener('click', () => {
      send({ type: 'decline' });
      finish('rejected', 'Declined');
    });
    $('end').addEventListener('click', () => endHere('closed', 'You ended the session.'));
  } else {
    if (routeDetails) {
      routeDetails.addEventListener('toggle', refreshRoute);
      document.addEventListener('visibilitychange', refreshRoute);
    }
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
