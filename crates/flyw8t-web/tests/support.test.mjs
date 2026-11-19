// Unit tests for support.js in a mocked browser: fail-closed teardown, the screen picker
// racing an ending, and the security-code commitment. Run with `node --test` (the Rust test
// `support_js` does this). The real-browser run is crates/flyw8t-server/tests/support_browser.rs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import vm from 'node:vm';

const SOURCE = readFileSync(new URL('../src/support.js', import.meta.url), 'utf8');
const SID = '11111111-2222-3333-4444-555555555555';
const CRLF = String.fromCharCode(13, 10);
const VIDEO_SDP = ['v=0', 'm=video 9 UDP/TLS/RTP/SAVPF 96', 'a=mid:0', ''].join(CRLF);
const offer = (sdp = VIDEO_SDP) => ({ type: 'signal', data: { sdp: { type: 'offer', sdp } } });
const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 20; i++) await tick(); };
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hex(await webcrypto.subtle.digest('SHA-256', typeof s === 'string' ? new TextEncoder().encode(s) : s));
const der = (label) => new TextEncoder().encode(`certificate ${label}`).buffer;
const fpOf = async (d) => (await sha(d)).match(/../g).join(':').toUpperCase();
const commitOf = async (d) => sha(`flyw8t-sas-commit-v1|${SID}|${await sha(d)}`);

// A page with support.js loaded. `localDer` is this browser's certificate, `remoteDer` the
// one the other end presents over DTLS.
async function page({ role, localDer, remoteDer, transports = 1, delayCert = false, lateCerts = 0, control = false }) {
  const els = new Map();
  const el = (id) => {
    if (!els.has(id)) {
      els.set(id, {
        id, hidden: false, disabled: false, textContent: '', className: '', dataset: {}, srcObject: null,
        handlers: {}, addEventListener(t, f) { this.handlers[t] = f; },
        click() { return this.handlers.click && this.handlers.click({ preventDefault() {} }); },
      });
    }
    return els.get(id);
  };
  el('support').dataset = { role, session: SID, ice: '[]', state: role === 'participant' ? 'authorizing' : 'waiting', control: control ? '1' : '0' };
  const sockets = [];
  const peers = [];
  const hintTimers = new Map();
  let pickerCalls = 0;
  let releaseCert = () => {};
  const certGate = delayCert ? new Promise((r) => { releaseCert = r; }) : Promise.resolve();
  let resolvePicker;
  let rejectPicker;
  class WebSocket {
    static OPEN = 1;
    constructor() { this.readyState = 1; this.sent = []; sockets.push(this); }
    send(x) { this.sent.push(JSON.parse(x)); }
  }
  class RTCPeerConnection {
    static async generateCertificate() {
      await certGate;
      const value = await fpOf(localDer);
      return { getFingerprints: () => [{ algorithm: 'sha-256', value }] };
    }
    constructor(cfg) {
      this.cfg = cfg; this.closed = false; this.connectionState = 'new'; this.tracks = [];
      this.remoteDescription = null; this.localDescription = null; peers.push(this);
    }
    addTrack(t) { this.tracks.push(t); }
    ends() {
      return Array.from({ length: transports }, () => ({
        transport: { getRemoteCertificates: () => (lateCerts-- > 0 ? [] : [remoteDer]) },
      }));
    }
    getSenders() { return role === 'participant' ? this.ends() : []; }
    getReceivers() { return role === 'technician' ? this.ends() : []; }
    async createOffer() { return { type: 'offer', sdp: VIDEO_SDP }; }
    async createAnswer() { return { type: 'answer', sdp: VIDEO_SDP }; }
    async setLocalDescription(d) { this.localDescription = d; }
    async setRemoteDescription(d) { this.remoteDescription = d; }
    async addIceCandidate() {}
    close() { this.closed = true; }
    connect() { this.connectionState = 'connected'; this.onconnectionstatechange(); }
  }
  const windowHandlers = {};
  const context = {
    document: { getElementById: el, addEventListener() {} },
    location: { protocol: 'https:', host: 'rmm.example' },
    WebSocket, RTCPeerConnection, MediaStream: class {},
    crypto: webcrypto, TextEncoder,
    setTimeout(fn, delay) {
      if (delay < 2500) return setTimeout(fn, delay);
      const token = {};
      hintTimers.set(token, fn);
      return token;
    },
    clearTimeout(token) { if (!hintTimers.delete(token)) clearTimeout(token); },
    navigator: { mediaDevices: { getDisplayMedia: () => { pickerCalls += 1; return new Promise((res, rej) => { resolvePicker = res; rejectPicker = rej; }); } } },
    window: { addEventListener: (t, f) => { windowHandlers[t] = f; } },
  };
  vm.runInNewContext(SOURCE, context);
  await settle();
  const ws = sockets[0];
  const track = { kind: 'video', stopped: false, stop() { this.stopped = true; } };
  return {
    el, ws, peers, windowHandlers, track,
    showDelayedHint() {
      const callbacks = [...hintTimers.values()];
      hintTimers.clear();
      callbacks.forEach(fn => fn());
    },
    pickerCalls: () => pickerCalls,
    pick: async () => { resolvePicker({ getTracks: () => [track], getVideoTracks: () => [track] }); await settle(); },
    releaseCert: async () => { releaseCert(); await settle(); },
    cancelPicker: async () => { rejectPicker(new Error('NotAllowed')); await settle(); },
    recv: async (msg) => { await ws.onmessage({ data: JSON.stringify(msg) }); await settle(); },
    sent: (type) => ws.sent.filter((m) => m.type === type),
    sas: () => el('sas').textContent,
  };
}

const state = (s) => ({ type: 'state', state: s, label: s, peer_present: true });

function routeStats(local, remote, selected = 'using') {
  return new Map([
    ['transport', { type: 'transport', selectedCandidatePairId: selected }],
    ['unused', { type: 'candidate-pair', nominated: true, localCandidateId: 'another', remoteCandidateId: 'r' }],
    ['another', { type: 'local-candidate', candidateType: 'relay' }],
    ['using', { type: 'candidate-pair', localCandidateId: 'l', remoteCandidateId: 'r' }],
    ['l', { type: 'local-candidate', candidateType: local, address: '192.0.2.100' }],
    ['r', { type: 'remote-candidate', candidateType: remote, address: '198.51.100.42' }],
  ]);
}

test('route disclosure reads the selected pair on demand and tracks path changes while open', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv(state('connecting'));
  await t.recv(offer());
  const pc = t.peers[0];
  const details = t.el('connection-details');
  const route = t.el('connection-route');
  const ice = new EventTarget();
  ice.onselectedcandidatepairchange = null;
  const dtls = pc.getReceivers()[0].transport;
  pc.getReceivers = () => [{ transport: { ...dtls, iceTransport: ice } }];
  let lookups = 0;
  let stats = routeStats('srflx', 'host');
  pc.getStats = async () => { lookups++; return stats; };
  pc.connect();
  assert.equal(lookups, 0);
  details.open = true;
  await details.handlers.toggle();
  assert.equal(route.textContent, 'Direct');
  for (const [local, remote, selected, label] of [
    ['host', 'relay', 'using', 'TURN relay'],
    ['relay', 'host', 'using', 'TURN relay'],
    ['host', undefined, 'using', 'Unavailable'],
    ['host', 'host', 'missing', 'Unavailable'],
  ]) {
    stats = routeStats(local, remote, selected);
    ice.dispatchEvent(new Event('selectedcandidatepairchange'));
    await tick();
    assert.equal(route.textContent, label);
  }
  details.open = false;
  await details.handlers.toggle();
  ice.dispatchEvent(new Event('selectedcandidatepairchange'));
  await tick();
  assert.equal(lookups, 5);
  // When the browser exposes the actual pair on the ICE transport, no stats lookup is needed.
  ice.getSelectedCandidatePair = () => ({ local: { type: 'host' }, remote: { type: 'relay' } });
  details.open = true;
  await details.handlers.toggle();
  assert.equal(route.textContent, 'TURN relay');
  assert.equal(lookups, 5);
});

test('late route stats cannot overwrite a newer selected pair, disconnect, or revocation', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv(state('connecting'));
  await t.recv(offer());
  const pc = t.peers[0];
  const details = t.el('connection-details');
  const route = t.el('connection-route');
  pc.connect();
  details.open = true;
  let release;
  const slow = () => new Promise(r => { release = () => r(routeStats('host', 'relay')); });
  pc.getStats = slow;
  const pending = details.handlers.toggle();
  pc.connectionState = 'disconnected';
  pc.onconnectionstatechange();
  assert.equal(route.textContent, 'Unavailable');
  pc.getStats = async () => routeStats('host', 'srflx');
  pc.connect();
  await tick();
  assert.equal(route.textContent, 'Direct');
  release();
  await pending;
  assert.equal(route.textContent, 'Direct');
  pc.getStats = slow;
  const lastLookup = details.handlers.toggle();
  await t.recv({ type: 'ended', state: 'revoked', label: 'Ended' });
  release();
  await lastLookup;
  assert.equal(route.textContent, 'Unavailable');
  assert.equal(t.el('viewer').hidden, true);
});

test('a normal connection stays quiet; repeated waiting updates keep one actionable hint', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv({ ...state('waiting'), peer_present: false });
  assert.equal(t.el('peer').textContent, '');
  t.showDelayedHint();
  assert.match(t.el('peer').textContent, /invitation/i);
  await t.recv({ ...state('waiting'), peer_present: false });
  assert.match(t.el('peer').textContent, /invitation/i);
  await t.recv(state('connecting'));
  assert.equal(t.el('peer').textContent, '');
  await t.recv({ type: 'ended', state: 'revoked', label: 'Access ended' });
  t.showDelayedHint();
  assert.equal(t.el('state').textContent, 'Access ended');
  assert.equal(t.el('peer').textContent, '');
});

test('a technician reports connected only after a displayable frame and a connected transport', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv(state('connecting'));
  await t.recv(offer());
  const pc = t.peers[0];
  const video = t.el('remote');
  let frame;
  video.requestVideoFrameCallback = cb => { frame = cb; };
  pc.ontrack({ track: { kind: 'video' }, streams: [{}] });
  pc.connect();
  assert.equal(t.sent('media').length, 0);
  await t.recv(state('connected'));
  assert.notEqual(t.el('support').dataset.state, 'connected');
  t.showDelayedHint();
  assert.match(t.el('peer').textContent, /first frame/i);
  frame();
  assert.equal(t.sent('media').length, 1);
  assert.equal(t.el('support').dataset.state, 'connected');
  assert.equal(t.el('peer').textContent, '');
  pc.connectionState = 'disconnected';
  pc.onconnectionstatechange();
  await t.recv(state('connected'));
  assert.equal(t.el('support').dataset.state, 'interrupted');
  t.showDelayedHint();
  assert.match(t.el('peer').textContent, /connection/i);
  pc.connect();
  assert.notEqual(t.el('support').dataset.state, 'connected');
  frame();
  assert.equal(t.el('support').dataset.state, 'connected');
  assert.equal(t.sent('media').length, 1);
  assert.equal(t.peers.length, 1);
});

test('a frame delivered after revocation cannot reopen the viewer or report media', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv(state('connecting'));
  await t.recv(offer());
  const pc = t.peers[0];
  const video = t.el('remote');
  pc.connect();
  pc.ontrack({ track: { kind: 'video' }, streams: [{}] });
  const lateFrame = video.onloadeddata;
  await t.recv({ type: 'ended', state: 'revoked', label: 'Access ended' });
  lateFrame();
  t.showDelayedHint();
  assert.equal(t.sent('media').length, 0);
  assert.equal(t.el('support').dataset.state, 'ended');
  assert.equal(t.el('viewer').hidden, true);
  assert.equal(t.el('peer').textContent, '');
});

async function consentedParticipant(opts = {}) {
  const tDer = der('technician');
  const p = await page({ role: 'participant', localDer: der('participant'), remoteDer: opts.remoteDer || tDer });
  const allowing = p.el('allow').click();
  await p.pick();
  await allowing;
  assert.equal(p.sent('approve').length, 1);
  await p.recv(state('connecting'));
  return { p, tDer };
}

test('losing the signaling socket stops capture and closes the connection', async () => {
  const { p, tDer } = await consentedParticipant();
  await p.recv({ type: 'signal', data: { commit: await commitOf(tDer) } });
  assert.equal(p.peers.length, 1);
  p.ws.readyState = 3;
  p.ws.onclose();
  assert.equal(p.track.stopped, true);
  assert.equal(p.peers[0].closed, true);
  assert.equal(p.el('support').dataset.state, 'ended');
  assert.equal(p.el('end').hidden, true);
});

test('End works with no socket: capture stops locally first', async () => {
  const { p } = await consentedParticipant();
  p.ws.readyState = 3;
  p.el('end').click();
  assert.equal(p.track.stopped, true);
  assert.equal(p.el('support').dataset.state, 'ended');
});

test('a screen chosen after the session ended is stopped at once and never approved', async () => {
  const p = await page({ role: 'participant', localDer: der('p'), remoteDer: der('t') });
  const allowing = p.el('allow').click();
  await p.recv({ type: 'ended', state: 'revoked', label: 'Ended by the technician' });
  await p.pick();
  await allowing;
  assert.equal(p.track.stopped, true);
  assert.equal(p.sent('approve').length, 0);
  assert.equal(p.peers.length, 0);
});

test('Allow cannot open a second picker while one is open', async () => {
  const p = await page({ role: 'participant', localDer: der('p'), remoteDer: der('t') });
  p.el('allow').click();
  p.el('allow').click();
  assert.equal(p.pickerCalls(), 1);
  await p.cancelPicker();
  assert.equal(p.el('allow').disabled, false, 'a cancelled picker can be retried');
});

test('the participant makes no offer until the technician has committed', async () => {
  const { p, tDer } = await consentedParticipant();
  assert.equal(p.peers.length, 0);
  assert.equal(p.sent('signal').length, 0);
  await p.recv({ type: 'signal', data: { commit: await commitOf(tDer) } });
  assert.equal(p.peers.length, 1);
  assert.equal(p.sent('signal')[0].data.sdp.type, 'offer');
});

test('a certificate that does not match the commitment ends the session', async () => {
  const { p, tDer } = await consentedParticipant({ remoteDer: der('someone in the middle') });
  await p.recv({ type: 'signal', data: { commit: await commitOf(tDer) } });
  p.peers[0].connect();
  await settle();
  assert.equal(p.el('support').dataset.sas, 'mismatch');
  assert.equal(p.track.stopped, true);
  assert.equal(p.sent('end').length, 1);
  assert.equal(p.el('sas-box').hidden, true, 'no code is shown');
});

test('both sides derive the same code from the certificates in use', async () => {
  const { p, tDer } = await consentedParticipant();
  await p.recv({ type: 'signal', data: { commit: await commitOf(tDer) } });
  p.peers[0].connect();
  await settle();
  assert.equal(p.el('support').dataset.sas, 'shown');
  assert.match(p.sas(), /^\d{3} \d{3}$/);

  const t = await page({ role: 'technician', localDer: tDer, remoteDer: der('participant') });
  await t.recv(state('connecting'));
  const commits = t.sent('signal').filter((m) => m.data.commit);
  assert.equal(commits.length, 1);
  assert.equal(commits[0].data.commit, await commitOf(tDer), 'the commitment is to its own certificate');
  await t.recv(offer());
  t.peers[0].connect();
  t.peers[0].ontrack({ track: { kind: 'video' }, streams: [{}] });
  t.el('remote').onloadeddata();
  await settle();
  assert.equal(t.sas(), p.sas());
  assert.equal(t.sent('media').length, 1);
});

test('the technician answers one offer only', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv(state('connecting'));
  await t.recv(offer(VIDEO_SDP + 'a=one'));
  await t.recv(offer(VIDEO_SDP + 'a=two'));
  assert.equal(t.peers.length, 1);
  assert.match(t.peers[0].remoteDescription.sdp, /a=one/);
});

// An independent computation of the code, so a constant or a wrong formula fails.
async function expectedCode(techDer, partDer) {
  const input = `flyw8t-sas-v1|${SID}|${await sha(techDer)}|${await sha(partDer)}`;
  const d = new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(input)));
  const n = (d[0] * 2 ** 24 + d[1] * 2 ** 16 + d[2] * 2 ** 8 + d[3]) % 1000000;
  const s = String(n).padStart(6, '0');
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}

async function connectedTechnician(partDer) {
  const tDer = der('technician');
  const t = await page({ role: 'technician', localDer: tDer, remoteDer: partDer });
  await t.recv(state('connecting'));
  await t.recv(offer());
  t.peers[0].connect();
  await settle();
  return { t, tDer };
}

test('the code is the specified hash of both certificates and changes with either', async () => {
  const pA = der('participant A');
  const { t, tDer } = await connectedTechnician(pA);
  assert.equal(t.sas(), await expectedCode(tDer, pA));
  const { t: t2 } = await connectedTechnician(der('participant B'));
  assert.notEqual(t2.sas(), t.sas(), 'a different participant certificate gives a different code');
  assert.equal(t2.sas(), await expectedCode(tDer, der('participant B')));
});

test('an offer with more than one media section is refused, unanswered', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv(state('connecting'));
  await t.recv(offer(VIDEO_SDP + ['m=video 9 UDP/TLS/RTP/SAVPF 97', 'a=mid:1', ''].join(CRLF)));
  assert.equal(t.peers.length, 0);
  assert.equal(t.sent('signal').filter((m) => m.data.sdp).length, 0);
  assert.equal(t.el('support').dataset.state, 'ended');
});

test('a second transport or a second track ends the session instead of showing it', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p'), transports: 2 });
  await t.recv(state('connecting'));
  await t.recv(offer());
  t.peers[0].connect();
  await settle();
  assert.equal(t.el('support').dataset.state, 'ended', 'two transports: no code computed over one of them');
  assert.notEqual(t.el('support').dataset.sas, 'shown');

  const u = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await u.recv(state('connecting'));
  await u.recv(offer());
  const video = { kind: 'video' };
  u.peers[0].ontrack({ track: video, streams: [{ id: 'genuine' }] });
  assert.equal(u.el('remote').srcObject.id, 'genuine');
  u.peers[0].ontrack({ track: video, streams: [{ id: 'injected' }] });
  assert.equal(u.el('support').dataset.state, 'ended');
  assert.equal(u.el('remote').srcObject, null, 'nothing stays on screen');
});

test('an offer still waiting for the certificate is dropped if the session ends meanwhile', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p'), delayCert: true });
  const handling = t.recv(offer());
  await t.recv({ type: 'ended', state: 'closed', label: 'Ended' });
  await t.releaseCert();
  await handling;
  assert.equal(t.peers.length, 0, 'no connection is created after the end');
  assert.equal(t.sent('signal').length, 0, 'no answer is sent after the end');
});

test('leaving the page ends the session', async () => {
  const { p } = await consentedParticipant();
  p.windowHandlers.pagehide();
  assert.equal(p.track.stopped, true);
  assert.equal(p.sent('end').length, 1);
});

test('a certificate that arrives just after "connected" still gives a code', async () => {
  const tDer = der('technician');
  const pDer = der('participant');
  const t = await page({ role: 'technician', localDer: tDer, remoteDer: pDer, lateCerts: 3 });
  await t.recv(state('connecting'));
  await t.recv(offer());
  t.peers[0].connect();
  await new Promise((r) => setTimeout(r, 600));
  await settle();
  assert.equal(t.el('support').dataset.sas, 'shown');
  assert.equal(t.sas(), await expectedCode(tDer, pDer));
});

test('control session: Allow consents without a picker, then offers the helper', async () => {
  const p = await page({ role: 'participant', localDer: der('p'), remoteDer: der('t'), control: true });
  await p.el('allow').click();
  assert.equal(p.pickerCalls(), 0, 'the helper captures, not the browser');
  assert.equal(p.sent('approve').length, 1);
  await p.recv(state('awaiting_helper'));
  assert.equal(p.el('helper-box').hidden, false);
  await p.recv({ type: 'helper', download: '/s/helper/download', expires_in_secs: 120 });
  assert.equal(p.el('helper-link').href, '/s/helper/download');
  // Only a same-server helper path is ever put in the link.
  await p.recv({ type: 'helper', download: 'https://evil.example/helper.exe', expires_in_secs: 120 });
  assert.equal(p.el('helper-link').href, '/s/helper/download');
  // The browser page never makes an offer in a control session.
  await p.recv(state('connecting'));
  assert.equal(p.peers.length, 0);
  await p.recv({ type: 'ended', state: 'closed', label: 'Ended' });
  assert.equal(p.el('helper-box').hidden, true);
});

test('control session: Cancel ends the session even if the helper was already allowed', async () => {
  const p = await page({ role: 'participant', localDer: der('p'), remoteDer: der('t'), control: true });
  await p.el('allow').click();
  await p.recv(state('awaiting_helper'));
  await p.recv(state('connecting'));
  p.el('cancel-helper').click();
  assert.equal(p.sent('end').length, 1, 'End, which stops any state, not Decline');
  assert.equal(p.sent('decline').length, 0);
  assert.equal(p.el('support').dataset.state, 'ended');
});
