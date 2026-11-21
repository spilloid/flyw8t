import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { once } from 'node:events';
import { isMainThread, parentPort, Worker, workerData } from 'node:worker_threads';
import { decodeJwt, SignJWT } from 'jose';
import { confirmInFixtureViewer, grantAuthority, grantType, makeEndpointOffer, softwareViewSigner } from './evidence.mjs';
import { maxPolicyAge, selectionType, WorkstationSelections } from './selection.mjs';
import { EndpointLedger, openChartConnection } from './ledger.mjs';

const clockStart = 946684800;
const policy = Object.freeze({
  authority: 'urn:flyw8t:test:authority', policyIssuer: 'urn:flyw8t:test:policy', tenant: 'synthetic-tenant', device: 'synthetic-device',
  enrollment: 'synthetic-enrollment', generation: 17, endpointIssuer: 'urn:flyw8t:test:endpoint',
  viewerIssuer: 'urn:flyw8t:test:viewer', viewerOrigin: 'https://viewer.invalid',
  operatorSubject: 'sensitive-technician-subject', identityIssuer: 'https://idp.invalid',
  identityAudience: 'independent-authority-client', totpAssurance: 'urn:example:pwd-and-totp',
});
const session = Object.freeze({ session: 'synthetic-chart-session', viewerFingerprint: 'a'.repeat(64),
  endpointFingerprint: 'b'.repeat(64), loginBinding:'c'.repeat(64), connected:true, transport:{} });
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
  const connection = openChartConnection(() => session);
  const raw = new DatabaseSync(file);
  const registryFile = join(dir, 'authority.sqlite');
  const registryDb = new DatabaseSync(registryFile);
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
      session:session.session, expectedLoginBinding:session.loginBinding, ...overrides }, time);
  }
  async function request(live = connection, endpoint = ledger) {
    const { offer, nonce } = await endpoint.prepare(keys.endpoint.privateKey, live);
    return { offer, nonce, identity: await identity(nonce), confirmation: await confirmation(offer) };
  }
  return { file, connection, registryFile, keys, config, authorize, ledger, raw, open, close, identity, confirmation, signPolicy, clock, selections, first,
    request, advance(seconds) { time += seconds; } };
}

if (process.argv[2] === '--reopened-observer') {
  const state = JSON.parse(readFileSync(0, 'utf8'));
  const reopened = new EndpointLedger(state.file, state.policy, createPublicKey(state.grantKey),
    createPublicKey(state.policyKey), () => clockStart);
  const live = openChartConnection(() => state.session);
  let pending = 'admitted';
  try { await reopened.admit(state.pending, live); } catch (error) { pending = error.message; }
  process.stdout.write(JSON.stringify({ active:reopened.active(state.lease, live), pending }));
  reopened.close();
} else if (!isMainThread) {
  const { file, pinnedKey, policyKey, token } = workerData;
  const ledger = new EndpointLedger(file, policy, createPublicKey(pinnedKey), createPublicKey(policyKey), () => clockStart);
  parentPort.postMessage('ready');
  await once(parentPort, 'message');
  let outcome;
  try { await ledger.admit(token, openChartConnection(() => session)); outcome = 'admitted'; }
  catch (error) { outcome = error.message; }
  ledger.close();
  parentPort.postMessage(outcome);
} else {
  test('only the originating transport can admit or supervise a lease', async t => {
    const f = await fixture(t);
    const request = await f.request();
    const offer = decodeJwt(request.offer);
    const token = await f.authorize(request);
    const other = openChartConnection(() => session);
    const otherRequest = decodeJwt((await f.request(other)).offer);
    assert.equal(offer.login_binding, session.loginBinding);
    assert.match(offer.connection_binding, /^[a-f0-9]{64}$/);
    assert.notEqual(offer.connection_binding, otherRequest.connection_binding);
    const forged = { ...session, connectionBinding:offer.connection_binding };
    for (const bad of [undefined, {}, other, forged, Object.create(f.connection)]) {
      await assert.rejects(f.ledger.admit(token, bad), /Grant denied/);
    }
    const lease = await f.ledger.admit(token, f.connection);
    assert.equal(f.ledger.active(lease, f.connection), true);
    for (const bad of [undefined, {}, other, forged, Object.create(f.connection)]) {
      assert.equal(f.ledger.active(lease, bad), false);
    }
    assert.equal(f.ledger.active(lease, f.connection), true);
    assert.equal(f.raw.prepare('SELECT binding FROM chart_connections WHERE nonce=?').get(request.nonce).binding,
      offer.connection_binding);
    const audit = JSON.stringify(f.raw.prepare('SELECT * FROM audit ORDER BY sequence').all());
    for (const value of [session.session, session.loginBinding, session.endpointFingerprint, session.viewerFingerprint,
      offer.connection_binding, request.nonce, lease]) assert.equal(audit.includes(value), false);
    f.connection.close();
    assert.equal(f.ledger.active(lease, f.connection), false);
    await assert.rejects(f.ledger.prepare(f.keys.endpoint.privateKey, f.connection));
  });

  for (const [reason, sample] of [
    ['login incarnation changed', { ...session, loginBinding:'d'.repeat(64) }],
    ['session changed', { ...session, session:'another-login-session' }],
    ['local certificate changed', { ...session, endpointFingerprint:'d'.repeat(64) }],
    ['viewer certificate changed', { ...session, viewerFingerprint:'d'.repeat(64) }],
    ['transport disconnected', { ...session, connected:false }],
    ['transport object replaced with the same login and certificate pair', { ...session, transport:{} }],
    ['login data missing', { ...session, loginBinding:undefined }],
    ['endpoint observer failed', null],
  ]) {
    test(reason + ' permanently closes that supervision handle', async t => {
      const f = await fixture(t);
      let observed = session;
      const live = openChartConnection(() => {
        if (!observed) throw Error('Native observation unavailable');
        return observed;
      });
      const token = await f.authorize(await f.request(live));
      const lease = await f.ledger.admit(token, live);
      assert.equal(f.ledger.active(lease, live), true);
      observed = sample;
      assert.equal(f.ledger.active(lease, live), false);
      observed = session;
      assert.equal(f.ledger.active(lease, live), false);
      await assert.rejects(f.ledger.prepare(f.keys.endpoint.privateKey, live));
    });
  }

  test('missing or malformed observations cannot open a live connection', () => {
    for (const sample of [null, {}, {...session, transport:undefined}, {...session, transport:'connection'},
      {...session, connected:'true'}, {...session, session:''},
      {...session, loginBinding:'user name'}, {...session, viewerFingerprint:session.endpointFingerprint},
      {...session, endpointFingerprint:'unverified'}]) {
      assert.throws(() => openChartConnection(() => sample), /Evidence rejected/);
    }
  });

  test('a close during endpoint signing or grant verification cannot commit a grant', async t => {
    const f = await fixture(t);
    const preparing = openChartConnection(() => session);
    const prepared = f.ledger.prepare(f.keys.endpoint.privateKey, preparing);
    preparing.close();
    await assert.rejects(prepared);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM challenges').get().n, 0);
    const token = await f.authorize(await f.request());
    const admission = f.ledger.admit(token, f.connection);
    f.connection.close();
    await assert.rejects(admission, /Grant denied/);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM leases').get().n, 0);
  });

  test('a fresh process with the same SQLite ledger and peer observations cannot reuse a grant', async t => {
    const f = await fixture(t);
    const lease = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
    const pending = await f.authorize(await f.request());
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--reopened-observer'], {
      input:JSON.stringify({ file:f.file, lease, pending, policy, session,
        grantKey:f.keys.authority.publicKey.export({type:'spki',format:'pem'}),
        policyKey:f.keys.admin.publicKey.export({type:'spki',format:'pem'}) }),
      encoding:'utf8', timeout:10000, windowsHide:true,
    });
    assert.equal(child.status, 0, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), { active:false, pending:'Grant denied' });
    assert.equal(f.ledger.active(lease, f.connection), true);
  });

  test('reopening a pre-binding ledger retains revocation and audit but denies old offers and leases', async t => {
    const f = await fixture(t);
    const old = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
    const pending = await f.authorize(await f.request());
    f.close(f.ledger);
    // This is the prior schema: the grant and spent nonce exist without a connection record.
    f.raw.exec('DROP TABLE chart_connections');
    const upgraded = f.open();
    assert.equal(upgraded.active(old, f.connection), false);
    await assert.rejects(upgraded.admit(pending, f.connection), /Grant denied/);
    upgraded.revoke(old);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM revocations').get().n, 1);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM audit WHERE event=?').get('revoked').n, 1);
    const fresh = await f.authorize(await f.request(f.connection, upgraded));
    const lease = await upgraded.admit(fresh, f.connection);
    assert.equal(upgraded.active(lease, f.connection), true);
  });

  test('two same-tenant workstations require their own current administrator selection', async t => {
    const f = await fixture(t);
    const second = { ...policy, device: 'other-pc', enrollment: 'second-enrollment', endpointIssuer: 'urn:other:endpoint' };
    const endpoint = keyPair();
    const other = f.open(second, f.file + '.other');
    const authorize = grantAuthority({ ...f.config, policy: second, endpointKey: endpoint.publicKey,
      signer: softwareViewSigner(second, f.keys.authority.privateKey) });
    const req = await f.request();
    const mintOffer = async revision => {
      const offer = await makeEndpointOffer(second, endpoint.privateKey, { ...session, connectionBinding: decodeJwt(req.offer).connection_binding, nonce: req.nonce, policyRevision: revision }, clockStart);
      return { ...req, offer, confirmation: await f.confirmation(offer) };
    };
    await assert.rejects(other.prepare(endpoint.privateKey, f.connection));
    await assert.rejects(authorize(await mintOffer(1)));
    for (const [index,mode] of ['ask_first','disabled'].entries()) {
      const update = await f.signPolicy(second, index + 1, mode);
      await f.selections.apply(update);
      await other.applyPolicy(update);
      await assert.rejects(authorize(await mintOffer(index + 1)));
      await assert.rejects(other.prepare(endpoint.privateKey, f.connection));
    }
    const one = await f.authorize(req);
    assert.equal(f.ledger.active(await f.ledger.admit(one, f.connection), f.connection), true);
    await assert.rejects(other.admit(one, f.connection), /Grant denied/);
    const foreign = await f.signPolicy({ ...second, tenant: 'other-organization' }, 3, 'notify_with_stop');
    await f.selections.apply(foreign);
    await assert.rejects(other.applyPolicy(foreign), /another workstation/);
    await assert.rejects(authorize(await mintOffer(3)));
    await assert.rejects(other.prepare(endpoint.privateKey, f.connection));
  });

  test('a signed demotion vetoes pending and active work across restart and later reselection', async t => {
    const f = await fixture(t);
    const live = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
    const waiting = await f.request();
    const pending = await f.authorize(waiting);
    const ask = await f.signPolicy(policy, 2, 'ask_first');
    const peer = f.open();
    await peer.applyPolicy(ask);
    await f.selections.apply(ask);
    assert.equal(f.ledger.active(live, f.connection), false);
    await assert.rejects(f.ledger.admit(pending, f.connection), /Grant denied/);
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
    await assert.rejects(restarted.admit(pending, f.connection), /Grant denied/);
    assert.equal(restarted.active(live, f.connection), false);
    await assert.rejects(f.authorize(waiting));
    const req = await restarted.prepare(f.keys.endpoint.privateKey, f.connection);
    const fresh = await f.authorize({ ...req, identity: await f.identity(req.nonce), confirmation: await f.confirmation(req.offer) });
    assert.equal(restarted.active(await restarted.admit(fresh, f.connection), f.connection), true);
    assert.deepEqual(f.raw.prepare('SELECT mode FROM workstation_selections ORDER BY revision').all().map(e => e.mode),
      ['notify_with_stop','ask_first','notify_with_stop']);
  });

  test('re-enrollment is monotone and cannot replace the enrollment ID within a generation', async t => {
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
    f.close(f.ledger);
    const restarted = f.open();
    const registry = new DatabaseSync(f.registryFile);
    try {
      const reloaded = new WorkstationSelections(registry, policy, f.keys.admin.publicKey, f.clock);
      for (const stale of [policy, { ...reEnrolled, enrollment: 'substituted-enrollment' }]) {
        const update = await f.signPolicy(stale, 3, 'notify_with_stop');
        await assert.rejects(restarted.applyPolicy(update), /Stale or conflicting/);
        await assert.rejects(reloaded.apply(update), /Stale or conflicting/);
      }
      const ask = await f.signPolicy(reEnrolled, 3, 'ask_first');
      await restarted.applyPolicy(ask);
      await reloaded.apply(ask);
      assert.equal(reloaded.allowed(policy, f.clock()), null);
      await assert.rejects(restarted.prepare(f.keys.endpoint.privateKey, f.connection));
    } finally { registry.close(); }
  });

  test('policy limits grant expiry and refuses invalid scope, stale time and excessive age', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const invalidMode = await f.signPolicy(policy, 3, 'control_desktop');
    await assert.rejects(f.ledger.applyPolicy(invalidMode));
    const tooLong = await f.signPolicy(policy, 3, 'notify_with_stop', clockStart + 121);
    await assert.rejects(f.selections.apply(tooLong));
    const short = await f.signPolicy(policy, 3, 'notify_with_stop', clockStart + 2);
    await f.selections.apply(short);
    await f.ledger.applyPolicy(short);
    const grant = await f.authorize(await f.request());
    assert.equal(decodeJwt(grant).exp, clockStart + 2);
    const lease = await f.ledger.admit(grant, f.connection);
    f.advance(2);
    assert.equal(f.ledger.active(lease, f.connection), false);
    await assert.rejects(f.authorize(req));
    f.advance(-1);
    assert.equal(f.ledger.active(lease, f.connection), false);
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
      { observedViewerFingerprint: 'd'.repeat(64) }) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer,
      { observedEndpointFingerprint: 'd'.repeat(64) }) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer,
      { session:'other-synthetic-session' }) }));
    await assert.rejects(f.authorize({ ...req, confirmation: await f.confirmation(req.offer,
      { expectedLoginBinding:'d'.repeat(64) }) }));
    for (const field of ['connection_binding','login_binding']) {
      const legacy = decodeJwt(req.offer);
      delete legacy[field];
      const offer = await sign(legacy, 'flyw8t-preview-endpoint+jwt', f.keys.endpoint.privateKey);
      await assert.rejects(f.authorize({ ...req, offer, confirmation:await f.confirmation(offer) }));
    }
    const other = await f.request();
    await assert.rejects(f.authorize({ ...req, confirmation: other.confirmation }));
    const rogue = await makeEndpointOffer(policy, keyPair().privateKey, { ...session, connectionBinding: decodeJwt(req.offer).connection_binding, policyRevision: 1, nonce: req.nonce }, clockStart);
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
      await assert.rejects(f.ledger.admit(changed, f.connection), /Grant denied/);
    }
    await assert.rejects(f.ledger.admit(await sign(claims, grantType, keyPair().privateKey), f.connection), /Grant denied/);
    const lease = await f.ledger.admit(token, f.connection);
    assert.equal(f.ledger.active(lease, f.connection), true);
    f.advance(30);
    assert.equal(f.ledger.active(lease, f.connection), false);
    await assert.rejects(f.ledger.admit(token, f.connection), /Grant denied/);
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

  test('other worker connections cannot redeem or supervise; concurrent local decisions spend the challenge once', async t => {
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
    const clients = tokens.map(() => f.open());
    const contenders = await Promise.allSettled(clients.map((client, i) => client.admit(tokens[i], f.connection)));
    assert.equal(contenders.filter(result => result.status === 'fulfilled').length, 1);
    const outcomes = (await Promise.all(results)).map(([s]) => s);
    assert.deepEqual(outcomes, tokens.map(() => 'Grant denied'));
    await Promise.all(exits);
    const lease = f.raw.prepare('SELECT id FROM leases').get().id;
    f.close(f.ledger);
    const reopened = f.open();
    for (const token of tokens) await assert.rejects(reopened.admit(token, f.connection), /Grant denied/);
    // A new SQLite connection can still supervise the original live endpoint object.
    assert.equal(reopened.active(lease, f.connection), true);
    assert.equal(reopened.active(lease, openChartConnection(() => session)), false);
    assert.equal(f.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE event='admitted'").get().n, 1);
  });

  test('admission, spend and redacted audit are atomic on real SQLite audit write failure', async t => {
    const f = await fixture(t);
    const req = await f.request();
    const token = await f.authorize(req);
    f.raw.exec("CREATE TRIGGER failed_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END");
    await assert.rejects(f.ledger.admit(token, f.connection), /audit unavailable/);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM leases').get().n, 0);
    assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 0);
    f.raw.exec('DROP TRIGGER failed_audit');
    const lease = await f.ledger.admit(token, f.connection);
    await assert.rejects(f.ledger.admit(token, f.connection), /Grant denied/);
    const reference = f.raw.prepare("SELECT correlation FROM audit WHERE event='admitted'").get().correlation;
    assert.equal(f.ledger.active(lease, f.connection), true);
    assert.equal(f.ledger.active(reference, f.connection), false);
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
    await assert.rejects(reopened.admit(await inFlight, f.connection), /Grant denied/);
    await assert.rejects(reopened.admit(await f.authorize(pending), f.connection), /Grant denied/);
    const lease = await reopened.admit(await f.authorize(unaffected), f.connection);
    // A new SQLite connection can still supervise the original live endpoint object.
    assert.equal(reopened.active(lease, f.connection), true);
    assert.equal(reopened.active(lease, openChartConnection(() => session)), false);
    reopened.cancelLocalOffer(unaffected.nonce);
    assert.equal(reopened.active(lease, f.connection), false);
    reopened.cancelLocalOffer(pending.nonce);
    const events = f.raw.prepare("SELECT correlation FROM audit WHERE event='offer_stopped'").all();
    assert.equal(events.length, 2);
    assert.ok(events.every(e => /^[a-f0-9]{64}$/.test(e.correlation)));
    assert.notEqual(events[0].correlation, pending.nonce);
  });

  test('revocation veto immediately reaches another open connection, persists when audit delivery fails and recovers exactly once', async t => {
    const f = await fixture(t);
    const lease = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
    const peer = f.open();
    assert.equal(peer.active(lease, f.connection), true);
    f.raw.exec("CREATE TRIGGER failed_revoke BEFORE INSERT ON audit WHEN NEW.event='revoked' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END");
    assert.throws(() => f.ledger.revoke(lease), /audit unavailable/);
    assert.equal(peer.active(lease, f.connection), false);
    assert.equal(f.raw.prepare('SELECT journaled FROM revocations WHERE id=?').get(lease).journaled, 0);
    f.close(f.ledger);
    f.close(peer);
    const reopened = f.open();
    assert.equal(reopened.active(lease, f.connection), false);
    f.raw.exec('DROP TRIGGER failed_revoke');
    reopened.flushRevocations();
    reopened.revoke(lease);
    assert.equal(f.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE event='revoked'").get().n, 1);
    f.close(reopened);
    assert.equal(reopened.active(lease, f.connection), false);
  });

  test('local emergency stop revokes outstanding and active transactions across restart', async t => {
    const f = await fixture(t);
    const lease = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
    const outstanding = await f.authorize(await f.request());
    const peer = f.open();
    peer.stopLocally();
    assert.equal(f.ledger.active(lease, f.connection), false);
    await assert.rejects(f.ledger.admit(outstanding, f.connection), /Grant denied/);
    await assert.rejects(f.request(), /Evidence rejected/);
    f.close(peer);
    f.close(f.ledger);
    const restarted = f.open();
    restarted.stopLocally();
    await restarted.applyPolicy(await f.signPolicy(policy, 2, 'notify_with_stop'));
    await assert.rejects(restarted.prepare(f.keys.endpoint.privateKey, f.connection), /Evidence rejected/);
    assert.equal(restarted.active(lease, f.connection), false);
    assert.equal(f.raw.prepare("SELECT COUNT(*) AS n FROM audit WHERE event='stopped'").get().n, 1);
  });

  for (const veto of ['revoke','cancelLocalOffer','stopLocally']) {
    test(veto + ' remembers a later time across restart and still works with a broken clock', async t => {
      const f = await fixture(t);
      const makeLease = async () => f.ledger.admit(await f.authorize(await f.request()), f.connection);
      const unrelated = await makeLease();
      const targeted = await makeLease();
      const outstanding = await f.request();
      const arg = veto === 'revoke' ? targeted : outstanding.nonce;
      f.advance(31);
      f.ledger[veto](arg);
      f.close(f.ledger);
      f.advance(-30);
      const reopened = f.open();
      assert.equal(reopened.active(unrelated, f.connection), false);
      assert.equal(f.raw.prepare('SELECT checked_at FROM configuration').get().checked_at, clockStart + 31);
      // Vetoes also work while the wall clock throws, even for an item that
      // had no previous veto. The recorded time is the last durable observation.
      const broken = new EndpointLedger(f.file, policy, f.keys.authority.publicKey, f.keys.admin.publicKey,
        () => { throw Error('clock unavailable'); });
      try {
        if (veto === 'revoke') broken.revoke(unrelated);
        else if (veto === 'cancelLocalOffer') broken.cancelLocalOffer(f.raw.prepare('SELECT nonce FROM leases WHERE id=?').get(unrelated).nonce);
        else broken.stopLocally();
      } finally { broken.close(); }
      const table = { revoke:'revocations', cancelLocalOffer:'offer_vetoes', stopLocally:'configuration' }[veto];
      const stamp = veto === 'stopLocally' ? 'stopped_at' : 'occurred';
      const decisions = f.raw.prepare('SELECT ' + stamp + ' AS at FROM ' + table).all();
      assert.equal(decisions.length, veto === 'stopLocally' ? 1 : 2);
      assert.ok(decisions.every(e => e.at === clockStart + 31));
    });
  }

  for (const { failure, start, finish } of [
    { failure: 'offer expires while signing', start: 1, finish: 61 },
    { failure: 'signing key fails', start: 1, finish: 31 },
    { failure: 'signing key fails after rollback', start: 31, finish: 1 },
    { failure: 'challenge persistence fails', start: 1, finish: 31 },
  ]) {
    test(failure + ' leaves unrelated expired leases unusable after restart', async t => {
      const f = await fixture(t);
      const unrelated = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
      const samples = [clockStart + start, clockStart + finish];
      const signer = new EndpointLedger(f.file, policy, f.keys.authority.publicKey, f.keys.admin.publicKey,
        () => samples.shift());
      if (failure === 'challenge persistence fails') {
        f.raw.exec("CREATE TRIGGER fail_policy_bind BEFORE INSERT ON challenge_policies BEGIN SELECT RAISE(ABORT,'binding unavailable'); END");
      }
      try {
        // A public key makes the real JOSE signing operation reject.
        const key = failure.startsWith('signing key fails') ? f.keys.endpoint.publicKey : f.keys.endpoint.privateKey;
        await assert.rejects(signer.prepare(key, f.connection));
      } finally { signer.close(); }
      assert.equal(samples.length, 0);
      assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM challenges').get().n, 1);
      assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM challenge_policies').get().n, 1);
      f.close(f.ledger);
      f.advance(1);
      assert.equal(f.open().active(unrelated, f.connection), false);
      assert.equal(f.raw.prepare('SELECT checked_at FROM configuration').get().checked_at, clockStart + Math.max(start, finish));
    });
  }

  for (const rejection of ['invalid signature','rolled back at commit','failed audit at commit']) {
    test(rejection + ' preserves verification and decision times for unrelated leases after restart', async t => {
      const f = await fixture(t);
      const unrelated = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
      f.advance(20);
      const valid = await f.authorize(await f.request());
      const badAudit = rejection === 'failed audit at commit';
      const samples = badAudit ? [clockStart + 20, clockStart + 31] : [clockStart + 31, clockStart + 20];
      const clocked = new EndpointLedger(f.file, policy, f.keys.authority.publicKey, f.keys.admin.publicKey,
        () => samples.shift());
      if (badAudit) f.raw.exec("CREATE TRIGGER reject_decision BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'journal unavailable'); END");
      try {
        const token = rejection === 'invalid signature'
          ? await sign(decodeJwt(valid), grantType, keyPair().privateKey) : valid;
        await assert.rejects(clocked.admit(token, f.connection), badAudit ? /journal unavailable/ : /Grant denied/);
      } finally { clocked.close(); }
      assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM leases').get().n, 1);
      f.close(f.ledger);
      assert.equal(f.open().active(unrelated, f.connection), false);
      assert.equal(f.raw.prepare('SELECT checked_at FROM configuration').get().checked_at, clockStart + 31);
    });
  }

  for (const failure of ['invalid lease argument','failed policy lookup']) {
    test(failure + ' preserves the supervision time for an unrelated lease after reopening', async t => {
      const f = await fixture(t);
      const unrelated = await f.ledger.admit(await f.authorize(await f.request()), f.connection);
      assert.equal(f.ledger.active(unrelated, f.connection), true);
      f.advance(31);
      if (failure === 'invalid lease argument') {
        assert.equal(f.ledger.active({ invalid:1 }, f.connection), false);
      } else {
        f.raw.exec("CREATE TRIGGER fail_supervision BEFORE UPDATE ON workstation_selections BEGIN SELECT RAISE(ABORT,'lookup failure'); END");
        assert.equal(f.ledger.active(unrelated, f.connection), false);
        f.raw.exec('DROP TRIGGER fail_supervision');
      }
      f.close(f.ledger);
      f.advance(-30);
      const reopened = f.open();
      assert.equal(reopened.active(unrelated, f.connection), false);
      assert.equal(f.raw.prepare('SELECT checked_at FROM configuration').get().checked_at, clockStart + 31);
    });
  }

  test('rolling the wall clock back after expiry cannot resurrect a persisted lease', async t => {
    const f = await fixture(t);
    const token = await f.authorize(await f.request());
    const lease = await f.ledger.admit(token, f.connection);
    f.advance(31);
    assert.equal(f.ledger.active(lease, f.connection), false);
    f.close(f.ledger);
    f.advance(-30);
    const reopened = f.open();
    assert.equal(reopened.active(lease, f.connection), false);
    await assert.rejects(reopened.admit(token, f.connection), /Grant denied/);
  });

  test('a clock rollback between signature verification and the SQLite commit denies admission', async t => {
    const f = await fixture(t);
    const req = await f.request();
    f.advance(10);
    const token = await f.authorize(req);
    const samples = [clockStart+10, clockStart+5];
    const rolling = new EndpointLedger(f.file, policy, f.keys.authority.publicKey, f.keys.admin.publicKey, () => samples.shift());
    try {
      await assert.rejects(rolling.admit(token, f.connection), /Grant denied/);
      assert.equal(f.raw.prepare('SELECT COUNT(*) AS n FROM leases').get().n, 0);
    } finally { rolling.close(); }
  });
}
