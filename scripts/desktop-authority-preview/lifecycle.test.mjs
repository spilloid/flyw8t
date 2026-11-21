import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { once } from 'node:events';
import { isMainThread, parentPort, Worker, workerData } from 'node:worker_threads';
import { decodeJwt, SignJWT } from 'jose';
import { confirmInFixtureViewer, grantAuthority, grantType, makeEndpointOffer, softwareViewSigner } from './evidence.mjs';
import { maxPolicyAge, selectionType, WorkstationSelections } from './selection.mjs';
import { EndpointLedger } from './ledger.mjs';

const clockStart = 946684800;
const policy = Object.freeze({
  authority: 'urn:flyw8t:test:authority', policyIssuer: 'urn:flyw8t:test:policy', tenant: 'synthetic-tenant', device: 'synthetic-device',
  enrollment: 'synthetic-enrollment', generation: 17, endpointIssuer: 'urn:flyw8t:test:endpoint',
  viewerIssuer: 'urn:flyw8t:test:viewer', viewerOrigin: 'https://viewer.invalid',
  operatorSubject: 'sensitive-technician-subject', identityIssuer: 'https://idp.invalid',
  identityAudience: 'independent-authority-client', totpAssurance: 'urn:example:pwd-and-totp',
});
const session = Object.freeze({ session: 'synthetic-chart-session', viewerFingerprint: 'a'.repeat(64),
  endpointFingerprint: 'b'.repeat(64) });
const keyPair = () => generateKeyPairSync('ed25519');
const sign = (claims, type, key) =>
  new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', typ: type }).sign(key);

// Only this test process holds a synthetic policy administrator's private key.
function fixtureSelection(p, key, now, revision, mode, expires = now + maxPolicyAge) {
  return new SignJWT({ iss: p.policyIssuer, aud: p.authority, sub: p.enrollment,
    tenant: p.tenant, device: p.device, generation: p.generation, revision, mode, iat: now, exp: expires })
    .setProtectedHeader({ alg: 'EdDSA', typ: selectionType }).sign(key);
}

async function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'flyw8t-authority-'));
  const file = join(dir, 'endpoint.sqlite');
  const keys = { idp: keyPair(), endpoint: keyPair(), viewer: keyPair(), authority: keyPair(), admin: keyPair() };
  const ledgers = new Set();
  let time = clockStart;
  const clock = () => time;
  const open = (target = policy, path = file) => {
    const ledger = new EndpointLedger(path, target, keys.authority.publicKey, keys.admin.publicKey, clock);
    ledgers.add(ledger);
    return ledger;
  };
  const close = ledger => { ledger.close(); ledgers.delete(ledger); };
  const ledger = open();
  const raw = new DatabaseSync(file);
  const registryDb = new DatabaseSync(join(dir, 'authority.sqlite'));
  const selections = new WorkstationSelections(registryDb, policy, keys.admin.publicKey, clock);
  const signPolicy = (device, revision, mode, expires) => fixtureSelection(device, keys.admin.privateKey, time, revision, mode, expires);
  const first = await signPolicy(policy, 1, 'notify_with_stop');
  await selections.apply(first);
  await ledger.applyPolicy(first);
  t.after(() => {
    for (const l of ledgers) l.close();
    registryDb.close();
    raw.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const config = { policy, selections, identityKey: keys.idp.publicKey, viewerKey: keys.viewer.publicKey,
    endpointKey: keys.endpoint.publicKey, signer: softwareViewSigner(policy, keys.authority.privateKey), clock };
  const authorize = grantAuthority(config);
  function identity(nonce, overrides = {}, key = keys.idp.privateKey) {
    return sign({ iss: policy.identityIssuer, sub: policy.operatorSubject, aud: policy.identityAudience,
      iat: time, exp: time + 60, auth_time: time, acr: policy.totpAssurance,
      amr: ['pwd','otp'], nonce, ...overrides }, 'JWT', key);
  }
  function confirmation(offer, overrides = {}, signingKey = keys.viewer.privateKey) {
    return confirmInFixtureViewer(policy, signingKey, { offer, subject: policy.operatorSubject,
      observedViewerFingerprint: session.viewerFingerprint, observedEndpointFingerprint:session.endpointFingerprint,
      session:session.session, ...overrides }, time);
  }
  async function request() {
    const { offer, nonce } = await ledger.prepare(keys.endpoint.privateKey, session);
    return { offer, nonce, identity: await identity(nonce), confirmation: await confirmation(offer) };
  }
  return { file, keys, config, authorize, ledger, raw, open, close, identity, confirmation, signPolicy, clock, selections, first,
    request, advance(seconds) { time += seconds; } };
}

if (!isMainThread) {
  const { file, pinnedKey, policyKey, token } = workerData;
  const ledger = new EndpointLedger(file, policy, createPublicKey(pinnedKey), createPublicKey(policyKey), () => clockStart);
  parentPort.postMessage('ready');
  await once(parentPort, 'message');
  let outcome;
  try { await ledger.admit(token); outcome = 'admitted'; }
  catch (error) { outcome = error.message; }
  ledger.close();
  parentPort.postMessage(outcome);
} else {
  test('two same-tenant workstations require their own current administrator selection', async t => {
    const f = await fixture(t);
    const second = { ...policy, device: 'other-pc', enrollment: 'second-enrollment', endpointIssuer: 'urn:other:endpoint' };
    const endpoint = keyPair();
    const other = f.open(second, f.file + '.other');
    const authorize = grantAuthority({ ...f.config, policy: second, endpointKey: endpoint.publicKey,
      signer: softwareViewSigner(second, f.keys.authority.privateKey) });
    const req = await f.request();
    const mintOffer = async revision => {
      const offer = await makeEndpointOffer(second, endpoint.privateKey, { ...session, nonce: req.nonce, policyRevision: revision }, clockStart);
      return { ...req, offer, confirmation: await f.confirmation(offer) };
    };
    await assert.rejects(other.prepare(endpoint.privateKey, session));
    await assert.rejects(authorize(await mintOffer(1)));
    for (const [index,mode] of ['ask_first','disabled'].entries()) {
      const update = await f.signPolicy(second, index + 1, mode);
      await f.selections.apply(update);
      await other.applyPolicy(update);
      await assert.rejects(authorize(await mintOffer(index + 1)));
      await assert.rejects(other.prepare(endpoint.privateKey, session));
    }
    const one = await f.authorize(req);
    assert.equal(f.ledger.active(await f.ledger.admit(one)), true);
    await assert.rejects(other.admit(one), /Grant denied/);
    const foreign = await f.signPolicy({ ...second, tenant: 'other-organization' }, 3, 'notify_with_stop');
    await f.selections.apply(foreign);
    await assert.rejects(other.applyPolicy(foreign), /another workstation/);
    await assert.rejects(authorize(await mintOffer(3)));
    await assert.rejects(other.prepare(endpoint.privateKey, session));
  });

  test('a signed demotion vetoes pending and active work across restart and later reselection', async t => {
    const f = await fixture(t);
    const live = await f.ledger.admit(await f.authorize(await f.request()));
    const waiting = await f.request();
    const pending = await f.authorize(waiting);
    const ask = await f.signPolicy(policy, 2, 'ask_first');
    const peer = f.open();
    await peer.applyPolicy(ask);
    await f.selections.apply(ask);
    assert.equal(f.ledger.active(live), false);
    await assert.rejects(f.ledger.admit(pending), /Grant denied/);
    await assert.rejects(f.authorize(waiting));
    await assert.rejects(f.request());
    f.close(f.ledger);
    f.close(peer);
    const restarted = f.open();
    await assert.rejects(restarted.applyPolicy(f.first), /Stale/);
    const conflict = await f.signPolicy(policy, 2, 'notify_with_stop');
    await assert.rejects(restarted.applyPolicy(conflict), /conflicting/);
    await assert.rejects(f.selections.apply(conflict), /conflicting/);
    const restored = await f.signPolicy(policy, 3, 'notify_with_stop');
    await restarted.applyPolicy(restored);
    await restarted.applyPolicy(restored);
    await f.selections.apply(restored);
    await assert.rejects(restarted.admit(pending), /Grant denied/);
    assert.equal(restarted.active(live), false);
    await assert.rejects(f.authorize(waiting));
    const req = await restarted.prepare(f.keys.endpoint.privateKey, session);
    const fresh = await f.authorize({ ...req, identity: await f.identity(req.nonce), confirmation: await f.confirmation(req.offer) });
    assert.equal(restarted.active(await restarted.admit(fresh)), true);
    assert.deepEqual(f.raw.prepare('SELECT mode FROM workstation_selections ORDER BY revision').all().map(e => e.mode),
      ['notify_with_stop','ask_first','notify_with_stop']);
  });

  test('re-enrollment, incorrect policy signature, changed trust and policy expiry all fail closed', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const reEnrolled = { ...policy, enrollment: 'replacement-enrollment', generation: 18 };
    assert.throws(() => new EndpointLedger(f.file, policy, f.keys.authority.publicKey, keyPair().publicKey));
    const wrongKey = await fixtureSelection(policy, f.keys.authority.privateKey, clockStart, 2, 'notify_with_stop');
    await assert.rejects(f.ledger.applyPolicy(wrongKey));
    await assert.rejects(f.selections.apply(wrongKey));
    const replacement = await f.signPolicy(reEnrolled, 2, 'notify_with_stop');
    await f.selections.apply(replacement);
    await f.ledger.applyPolicy(replacement);
    await assert.rejects(f.authorize(req));
    await assert.rejects(f.request());
    const invalidMode = await f.signPolicy(policy, 3, 'control_desktop');
    await assert.rejects(f.ledger.applyPolicy(invalidMode));
    const tooLong = await f.signPolicy(policy, 3, 'notify_with_stop', clockStart + 121);
    await assert.rejects(f.selections.apply(tooLong));
    const short = await f.signPolicy(policy, 3, 'notify_with_stop', clockStart + 2);
    await f.selections.apply(short);
    await f.ledger.applyPolicy(short);
    const grant = await f.authorize(await f.request());
    assert.equal(decodeJwt(grant).exp, clockStart + 2);
    const lease = await f.ledger.admit(grant);
    f.advance(2);
    assert.equal(f.ledger.active(lease), false);
    await assert.rejects(f.authorize(req));
    f.advance(-1);
    assert.equal(f.ledger.active(lease), false);
    await assert.rejects(f.request());
  });

  test('a policy change during signing prevents the authority returning even a valid chart grant', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const veto = await f.signPolicy(policy, 2, 'disabled');
    const typed = f.config.signer;
    const authorize = grantAuthority({ ...f.config, signer: {
      publicKey: typed.publicKey,
      async signViewGrant(transaction) {
        const grant = await typed.signViewGrant(transaction);
        await f.selections.apply(veto);
        return grant;
      },
    } });
    await assert.rejects(authorize(req));
  });

  test('authority requires separately signed endpoint, viewer and strict recent dedicated TOTP evidence', async t => {
    const f = await fixture(t);
    const req = await f.request();
    for (const [claim, value] of [
      ['iss', 'https://console.invalid'], ['aud', 'console-client'], ['aud', [policy.identityAudience,'other']],
      ['sub','unentitled'], ['acr','urn:example:generic-otp'], ['amr',['pwd']], ['amr',['pwd','recovery']],
      ['auth_time', clockStart - 301], ['auth_time', clockStart + 1], ['auth_time', undefined],
      ['nonce', 'substituted'], ['iat', clockStart + 1], ['exp',clockStart],
    ]) {
      const invalid = await f.identity(req.nonce, { [claim]: value });
      await assert.rejects(f.authorize({ ...req, identity: invalid }));
    }
    await assert.rejects(f.authorize({ ...req, identity: await f.identity(req.nonce, {}, keyPair().privateKey) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer, {}, keyPair().privateKey) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer, { subject: 'other' }) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer,
      { observedViewerFingerprint: session.endpointFingerprint }) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer,
      { observedEndpointFingerprint: session.viewerFingerprint }) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer,
      { session:'other-synthetic-session' }) }));
    const other = await f.request();
    await assert.rejects(f.authorize({ ...req, confirmation: other.confirmation }));
    const rogue = await makeEndpointOffer(policy, keyPair().privateKey, { ...session, policyRevision: 1, nonce: req.nonce }, clockStart);
    await assert.rejects(f.authorize({ ...req, offer: rogue, confirmation: await f.confirmation(rogue) }));
    assert.throws(() => grantAuthority({ ...f.config, viewerKey: f.keys.endpoint.publicKey }));
    const token = await f.authorize(req);
    assert.equal(decodeJwt(token).scope, 'view_synthetic_chart');
  });

  test('independent endpoint verifies restricted grant and binds it to its persisted offer', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const token = await f.authorize(req);
    const claims = decodeJwt(token);
    for (const [field, value] of [
      ['aud','other-endpoint'], ['iss','console-control-plane'], ['scope','control_desktop'],
      ['enrollment','other'], ['generation',16], ['assurance','otp'], ['binding','0'.repeat(64)],
      ['nonce','z'.repeat(43)], ['exp',clockStart+31], ['auth_time',clockStart-301],
    ]) {
      const changed = await sign({ ...claims, [field]: value }, grantType, f.keys.authority.privateKey);
      await assert.rejects(f.ledger.admit(changed), /Grant denied/);
    }
    await assert.rejects(f.ledger.admit(await sign(claims, grantType, keyPair().privateKey)), /Grant denied/);
    const lease = await f.ledger.admit(token);
    assert.equal(f.ledger.active(lease), true);
    f.advance(30);
    assert.equal(f.ledger.active(lease), false);
    await assert.rejects(f.ledger.admit(token), /Grant denied/);
    assert.throws(() => new EndpointLedger(f.file, { ...policy, generation: 1 }, f.keys.authority.publicKey, f.keys.admin.publicKey));
  });

  test('authority only invokes the provider-independent typed signer after verification and checks its response', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const typed = f.config.signer;
    const calls = [];
    const recordingSigner = {
      publicKey: typed.publicKey,
      signViewGrant(transaction) {
        calls.push(transaction);
        return typed.signViewGrant(transaction);
      },
    };
    const authorize = grantAuthority({ ...f.config, signer: recordingSigner });
    await assert.rejects(authorize({ ...req, identity: await f.identity(req.nonce, { acr: 'password' }) }));
    assert.equal(calls.length, 0);
    const token = await authorize(req);
    assert.equal(calls.length, 1);
    assert.deepEqual(Object.keys(calls[0]).sort(), ['authenticatedAt','binding','expiresAt','issuedAt','nonce']);
    assert.ok(Object.isFrozen(calls[0]));
    assert.equal(decodeJwt(token).scope, 'view_synthetic_chart');
    const broken = grantAuthority({ ...f.config, signer: {
      publicKey: typed.publicKey,
      signViewGrant: transaction => typed.signViewGrant({ ...transaction, nonce:'z'.repeat(43) }),
    } });
    await assert.rejects(broken(req), /Evidence rejected/);
  });

  test('independent worker connections racing distinct signed grants for one challenge admit exactly one; replay stays spent after restart', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const tokens = await Promise.all(Array.from({ length: 4 }, () => f.authorize(req)));
    assert.equal(new Set(tokens.map(jwt => decodeJwt(jwt).jti)).size, 4);
    const pinnedKey = f.keys.authority.publicKey.export({ type: 'spki', format: 'pem' });
    const policyKey = f.keys.admin.publicKey.export({ type: 'spki', format: 'pem' });
    const workers = tokens.map(token => new Worker(new URL(import.meta.url), { workerData: { file: f.file, pinnedKey, policyKey, token } }));
    t.after(async () => { await Promise.all(workers.map(w => w.terminate())); });
    const exits = workers.map(w => once(w, 'exit'));
    const ready = await Promise.all(workers.map(w => once(w, 'message')));
    assert.ok(ready.every(([s]) => s === 'ready'));
    const results = workers.map(w => once(w, 'message'));
    for (const worker of workers) worker.postMessage('redeem');
    const outcomes = (await Promise.all(results)).map(([s]) => s).sort();
    assert.deepEqual(outcomes, ['Grant denied','Grant denied','Grant denied','admitted']);
    await Promise.all(exits);
    const lease = f.raw.prepare('SELECT id FROM leases').get().id;
    f.close(f.ledger);
    const reopened = f.open();
    for (const token of tokens) await assert.rejects(reopened.admit(token), /Grant denied/);
    assert.equal(reopened.active(lease), true);
    assert.equal(f.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE event='admitted'").get().n, 1);
  });

  test('admission, spend and redacted audit are atomic on real SQLite audit write failure', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const token = await f.authorize(req);
    f.raw.exec("CREATE TRIGGER failed_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END");
    await assert.rejects(f.ledger.admit(token), /audit unavailable/);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM leases').get().n, 0);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
    f.raw.exec('DROP TRIGGER failed_audit');
    const lease = await f.ledger.admit(token);
    await assert.rejects(f.ledger.admit(token), /Grant denied/);
    const reference = f.raw.prepare("SELECT correlation FROM audit WHERE event='admitted'").get().correlation;
    assert.equal(f.ledger.active(lease), true);
    assert.equal(f.ledger.active(reference), false);
    f.ledger.revoke(lease);
    const events = f.raw.prepare('SELECT * FROM audit ORDER BY sequence').all();
    assert.deepEqual(Object.keys(events[0]), ['sequence','occurred','event','correlation']);
    assert.match(reference, /^[a-f0-9]{64}$/);
    assert.notEqual(reference, lease);
    assert.deepEqual(events.map(e => [e.event,e.correlation]), [['admitted',reference],['denied',null],['revoked',reference]]);
    for (const value of [req.nonce, req.offer, req.identity, req.confirmation, token, policy.operatorSubject,
      lease, policy.device, policy.tenant, policy.viewerOrigin, session.viewerFingerprint]) {
      assert.equal(JSON.stringify(events).includes(value), false);
    }
  });

  test('targeted offer veto before admission persists, applies to in-flight signing, and leaves unrelated offers usable', async t => {
    const f = await fixture(t);
    const pending = await f.request();
    const unaffected = await f.request();
    const inFlight = f.authorize(pending);
    const peer = f.open();
    peer.cancelLocalOffer(pending.nonce);
    f.close(peer);
    f.close(f.ledger);
    const reopened = f.open();
    await assert.rejects(reopened.admit(await inFlight), /Grant denied/);
    await assert.rejects(reopened.admit(await f.authorize(pending)), /Grant denied/);
    const lease = await reopened.admit(await f.authorize(unaffected));
    assert.equal(reopened.active(lease), true);
    reopened.cancelLocalOffer(unaffected.nonce);
    assert.equal(reopened.active(lease), false);
    reopened.cancelLocalOffer(pending.nonce);
    const events = f.raw.prepare("SELECT correlation FROM audit WHERE event='offer_stopped'").all();
    assert.equal(events.length, 2);
    assert.ok(events.every(e => /^[a-f0-9]{64}$/.test(e.correlation)));
    assert.notEqual(events[0].correlation, pending.nonce);
  });

  test('revocation veto immediately reaches another open connection, persists when audit delivery fails and recovers exactly once', async t => {
    const f = await fixture(t);
    const lease = await f.ledger.admit(await f.authorize(await f.request()));
    const peer = f.open();
    assert.equal(peer.active(lease), true);
    f.raw.exec("CREATE TRIGGER failed_revoke BEFORE INSERT ON audit WHEN NEW.event='revoked' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END");
    assert.throws(() => f.ledger.revoke(lease), /audit unavailable/);
    assert.equal(peer.active(lease), false);
    assert.equal(f.raw.prepare('SELECT journaled FROM revocations WHERE id=?').get(lease).journaled, 0);
    f.close(f.ledger);
    f.close(peer);
    const reopened = f.open();
    assert.equal(reopened.active(lease), false);
    f.raw.exec('DROP TRIGGER failed_revoke');
    reopened.flushRevocations();
    reopened.revoke(lease);
    assert.equal(f.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE event='revoked'").get().n, 1);
    f.close(reopened);
    assert.equal(reopened.active(lease), false);
  });

  test('local emergency stop revokes outstanding and active transactions across restart', async t => {
    const f = await fixture(t);
    const lease = await f.ledger.admit(await f.authorize(await f.request()));
    const outstanding = await f.authorize(await f.request());
    const peer = f.open();
    peer.stopLocally();
    assert.equal(f.ledger.active(lease), false);
    await assert.rejects(f.ledger.admit(outstanding), /Grant denied/);
    await assert.rejects(f.request(), /Evidence rejected/);
    f.close(peer);
    f.close(f.ledger);
    const restarted = f.open();
    restarted.stopLocally();
    assert.equal(restarted.active(lease), false);
    assert.equal(f.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE event='stopped'").get().n, 1);
  });

  test('rolling the wall clock back after expiry cannot resurrect a persisted lease', async t => {
    const f = await fixture(t);
    const token = await f.authorize(await f.request());
    const lease = await f.ledger.admit(token);
    f.advance(31);
    assert.equal(f.ledger.active(lease), false);
    f.close(f.ledger);
    f.advance(-30);
    const reopened = f.open();
    assert.equal(reopened.active(lease), false);
    await assert.rejects(reopened.admit(token), /Grant denied/);
  });

  test('a clock rollback between signature verification and the SQLite commit denies admission', async t => {
    const f = await fixture(t);
    const req = await f.request();
    f.advance(10);
    const token = await f.authorize(req);
    const samples = [clockStart+10, clockStart+5];
    const rolling = new EndpointLedger(f.file, policy, f.keys.authority.publicKey, f.keys.admin.publicKey, () => samples.shift());
    try {
      await assert.rejects(rolling.admit(token), /Grant denied/);
      assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM leases').get().n, 0);
    } finally { rolling.close(); }
  });
}
