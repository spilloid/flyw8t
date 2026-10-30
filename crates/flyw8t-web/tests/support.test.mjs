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
const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 20; i++) await tick(); };
const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
const sha = async (s) => hex(await webcrypto.subtle.digest('SHA-256', typeof s === 'string' ? new TextEncoder().encode(s) : s));
const der = (label) => new TextEncoder().encode(`certificate ${label}`).buffer;
const fpOf = async (d) => (await sha(d)).match(/../g).join(':').toUpperCase();
const commitOf = async (d) => sha(`flyw8t-sas-commit-v1|${SID}|${await sha(d)}`);

// A page with support.js loaded. `localDer` is this browser's certificate, `remoteDer` the
// one the other end presents over DTLS.
async function page({ role, localDer, remoteDer }) {
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
  el('support').dataset = { role, session: SID, ice: '[]', state: role === 'participant' ? 'authorizing' : 'waiting' };
  const sockets = [];
  const peers = [];
  let pickerCalls = 0;
  let resolvePicker;
  let rejectPicker;
  class WebSocket {
    static OPEN = 1;
    constructor() { this.readyState = 1; this.sent = []; sockets.push(this); }
    send(x) { this.sent.push(JSON.parse(x)); }
  }
  class RTCPeerConnection {
    static async generateCertificate() {
      const value = await fpOf(localDer);
      return { getFingerprints: () => [{ algorithm: 'sha-256', value }] };
    }
    constructor(cfg) {
      this.cfg = cfg; this.closed = false; this.connectionState = 'new'; this.tracks = [];
      this.remoteDescription = null; this.localDescription = null; peers.push(this);
    }
    addTrack(t) { this.tracks.push(t); }
    getSenders() { return [{ transport: { getRemoteCertificates: () => [remoteDer] } }]; }
    getReceivers() { return []; }
    async createOffer() { return { type: 'offer', sdp: 'offer' }; }
    async createAnswer() { return { type: 'answer', sdp: 'answer' }; }
    async setLocalDescription(d) { this.localDescription = d; }
    async setRemoteDescription(d) { this.remoteDescription = d; }
    async addIceCandidate() {}
    close() { this.closed = true; }
    connect() { this.connectionState = 'connected'; this.onconnectionstatechange(); }
  }
  const windowHandlers = {};
  const context = {
    document: { getElementById: el },
    location: { protocol: 'https:', host: 'rmm.example' },
    WebSocket, RTCPeerConnection, MediaStream: class {},
    crypto: webcrypto, TextEncoder, setTimeout,
    navigator: { mediaDevices: { getDisplayMedia: () => { pickerCalls += 1; return new Promise((res, rej) => { resolvePicker = res; rejectPicker = rej; }); } } },
    window: { addEventListener: (t, f) => { windowHandlers[t] = f; } },
  };
  vm.runInNewContext(SOURCE, context);
  await settle();
  const ws = sockets[0];
  const track = { stopped: false, stop() { this.stopped = true; } };
  return {
    el, ws, peers, windowHandlers, track,
    pickerCalls: () => pickerCalls,
    pick: async () => { resolvePicker({ getTracks: () => [track] }); await settle(); },
    cancelPicker: async () => { rejectPicker(new Error('NotAllowed')); await settle(); },
    recv: async (msg) => { await ws.onmessage({ data: JSON.stringify(msg) }); await settle(); },
    sent: (type) => ws.sent.filter((m) => m.type === type),
    sas: () => el('sas').textContent,
  };
}

const state = (s) => ({ type: 'state', state: s, label: s, peer_present: true });

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
  await t.recv({ type: 'signal', data: { sdp: { type: 'offer', sdp: 'offer' } } });
  t.peers[0].connect();
  await settle();
  assert.equal(t.sas(), p.sas());
  assert.equal(t.sent('media').length, 1);
});

test('the technician answers one offer only', async () => {
  const t = await page({ role: 'technician', localDer: der('t'), remoteDer: der('p') });
  await t.recv(state('connecting'));
  await t.recv({ type: 'signal', data: { sdp: { type: 'offer', sdp: 'one' } } });
  await t.recv({ type: 'signal', data: { sdp: { type: 'offer', sdp: 'two' } } });
  assert.equal(t.peers.length, 1);
  assert.equal(t.peers[0].remoteDescription.sdp, 'one');
});

test('leaving the page ends the session', async () => {
  const { p } = await consentedParticipant();
  p.windowHandlers.pagehide();
  assert.equal(p.track.stopped, true);
  assert.equal(p.sent('end').length, 1);
});
