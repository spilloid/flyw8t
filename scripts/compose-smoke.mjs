// Exercise fresh Compose recovery or migration and recovery from the published 0.2.0 image.
// Node 22+, Docker Compose. Creates only a unique throwaway project and removes it on exit.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { readdirSync } from 'node:fs';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
const upgrade = args.length === 1 && args[0] === '--upgrade-from-0.2.0';
assert.ok(args.length === 0 || upgrade, 'usage: node scripts/compose-smoke.mjs [--upgrade-from-0.2.0]');
// Published in https://github.com/spilloid/flyw8t/releases/tag/v0.2.0.
const baselineImage = 'ghcr.io/spilloid/flyw8t-server:0.2.0@sha256:0acdf7dcc5745cf5a52c824fac624bf41174642fa90369cd6d26203a3b161be6';
const candidateImage = 'flyw8t-server:ci';
const project = `flyw8t-smoke-${upgrade ? 'upgrade' : 'fresh'}-${randomBytes(8).toString('hex')}`;
const listener = createServer();
await new Promise((resolve, reject) => listener.once('error', reject).listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
const base = `http://localhost:${port}`;
const email = `${project}@example.test`;
const password = randomBytes(24).toString('hex');
const env = {
  ...process.env,
  COMPOSE_PROFILES: '',
  FLYW8T_DB_PASSWORD: randomBytes(24).toString('hex'),
  FLYW8T_PUBLISH: `127.0.0.1:${port}`,
  FLYW8T_PUBLIC_URL: base,
  FLYW8T_BOOTSTRAP_ADMIN_EMAIL: email,
  FLYW8T_BOOTSTRAP_ADMIN_PASSWORD: password,
  FLYW8T_REQUIRE_MFA: 'true',
  FLYW8T_TLS_CERT: '',
  FLYW8T_TLS_KEY: '',
  FLYW8T_TRUSTED_PROXIES: '',
  FLYW8T_HELPER_PATH: '',
  FLYW8T_FIELD_KEY: randomBytes(32).toString('base64'),
};

function docker(args, options = {}) {
  return execFileSync('docker', args, {
    cwd: root, env, maxBuffer: 32 * 1024 * 1024, timeout: 15 * 60_000, ...options,
  });
}

function compose(args, options = {}, image) {
  const files = ['-f', 'deploy/compose/compose.yaml'];
  if (image) {
    files.push('-f', '-');
    options = { ...options, input: `services:\n  server:\n    image: ${JSON.stringify(image)}\n` };
  }
  return docker(['compose', '--project-name', project, ...files, ...args], options);
}

function startImage(image) {
  compose(['up', '-d', '--force-recreate', '--no-deps', '--no-build', '--pull', 'never', 'server'], {
    stdio: ['pipe', 'inherit', 'inherit'],
  }, image);
  const id = compose(['ps', '-q', 'server']).toString().trim();
  assert.match(id, /^[a-f0-9]{12,64}$/, 'exactly one fixture server is running');
  const actual = docker(['inspect', '--format', '{{.Image}}', id]).toString().trim();
  const expected = docker(['image', 'inspect', '--format', '{{.Id}}', image]).toString().trim();
  assert.match(expected, /^sha256:[a-f0-9]{64}$/);
  assert.equal(actual, expected, `fixture is running the requested image ${image}`);
}

function browser() {
  const cookies = new Map();
  return async (path, form) => {
    const url = new URL(path, base);
    assert.equal(url.origin, base, 'never send test credentials to another origin');
    const headers = { Cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join('; ') };
    if (form) Object.assign(headers, { Origin: base, 'Content-Type': 'application/x-www-form-urlencoded' });
    const response = await fetch(url, {
      method: form ? 'POST' : 'GET', headers, redirect: 'manual',
      body: form ? new URLSearchParams(form) : undefined, signal: AbortSignal.timeout(15_000),
    });
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0];
      const separator = pair.indexOf('=');
      cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
    return { status: response.status, location: response.headers.get('location'), html: await response.text() };
  };
}

function input(html, name) {
  const tag = [...html.matchAll(/<input\b[^>]*>/g)].map(match => match[0])
    .find(tag => tag.includes(`name="${name}"`));
  assert.ok(tag, `page has ${name} input`);
  const value = tag.match(/\bvalue="([^"]*)"/);
  assert.ok(value, `${name} has a value`);
  return value[1];
}

function totp(grouped) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const letter of grouped.replace(/\s/g, '')) {
    const value = alphabet.indexOf(letter);
    assert.ok(value >= 0, 'TOTP key uses base32');
    bits += value.toString(2).padStart(5, '0');
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map(byte => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = createHmac('sha1', key).update(counter).digest();
  return ((mac.readUInt32BE(mac[19] & 15) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

async function ready() {
  for (let attempt = 0; attempt < 90; attempt++) {
    try {
      if ((await fetch(`${base}/readyz`, { signal: AbortSignal.timeout(2_000) })).status === 200) return;
    } catch { /* server or database still starting */ }
    await new Promise(resolve => setTimeout(resolve, 1_000));
  }
  throw new Error('Compose server did not become ready');
}

async function passwordSignIn(request) {
  const login = await request('/login');
  assert.equal(login.status, 200);
  const response = await request('/login', { email, password, login_csrf: input(login.html, 'login_csrf') });
  assert.equal(response.status, 303, 'password accepted');
  assert.ok(response.location?.startsWith('/'), 'sign-in has a local next step');
  return response.location;
}

async function createOrganization(request, name) {
  const organizations = await request('/organizations');
  assert.equal(organizations.status, 200, 'fully signed in after MFA');
  const created = await request('/organizations', { csrf: input(organizations.html, 'csrf'), name });
  assert.equal(created.status, 303);
  assert.match(created.location, /^\/organizations\/[0-9a-f-]+/);
  return created.location;
}

async function seedFixture() {
  const request = browser();
  const next = await passwordSignIn(request);
  const setup = await request(next);
  assert.equal(setup.status, 200);
  const key = setup.html.match(/id="totp-key"[^>]*>([^<]+)</);
  assert.ok(key, 'MFA is required on a fresh deployment');
  const enrolled = await request('/account/mfa', { csrf: input(setup.html, 'csrf'), code: totp(key[1]) });
  assert.equal(enrolled.status, 200, 'MFA setup succeeds');
  const recovery = enrolled.html.match(/id="recovery-codes"[^>]*>([^<]+)</);
  assert.ok(recovery, 'recovery codes are shown once');
  const recoveryCode = recovery[1].trim().split(/\s+/)[0];
  const organizationPath = await createOrganization(request, project);
  return { organizationPath, recoveryCode };
}

function snapshot() {
  const dump = compose(['exec', '-T', 'db', 'pg_dump', '-U', 'flyw8t', '-Fc', 'flyw8t']);
  assert.ok(dump.length > 0);
  return dump;
}

function restoreSnapshot(dump) {
  // Only this script's randomly named Compose project is addressed. Never touch a host DB.
  compose(['exec', '-T', 'db', 'dropdb', '-U', 'flyw8t', '--force', 'flyw8t']);
  compose(['exec', '-T', 'db', 'createdb', '-U', 'flyw8t', 'flyw8t']);
  compose(['exec', '-T', 'db', 'pg_restore', '-U', 'flyw8t', '-d', 'flyw8t', '--no-owner', '--exit-on-error'], { input: dump });
}

function migrationVersions() {
  const sql = 'SELECT version FROM _sqlx_migrations WHERE success ORDER BY version';
  return compose(['exec', '-T', 'db', 'psql', '-XAt', '-v', 'ON_ERROR_STOP=1', '-U', 'flyw8t', '-d', 'flyw8t', '-c', sql])
    .toString().trim().split('\n').map(Number);
}

function clearBootstrap() {
  env.FLYW8T_BOOTSTRAP_ADMIN_EMAIL = '';
  env.FLYW8T_BOOTSTRAP_ADMIN_PASSWORD = '';
}

async function verifyFixture({ organizationPath, recoveryCode }) {
  const restored = browser();
  const challenge = await restored(await passwordSignIn(restored));
  assert.equal(challenge.status, 200);
  assert.ok(!challenge.html.includes('id="totp-key"'), 'MFA configuration survived restore');
  const signedIn = await restored('/login/mfa', { csrf: input(challenge.html, 'csrf'), code: recoveryCode });
  assert.equal(signedIn.status, 303, 'restored account accepts its recovery code');
  const organization = await restored(organizationPath);
  assert.equal(organization.status, 200);
  assert.ok(organization.html.includes(project), 'created organization survived restore');
  return restored;
}

async function freshInstall() {
  compose(['up', '-d', '--build', 'db', 'server'], { stdio: 'inherit' });
  await ready();
  const fixture = await seedFixture();
  console.log('Compose startup, password + TOTP, and organization creation passed');

  const dump = snapshot();
  compose(['stop', 'server']);
  restoreSnapshot(dump);
  clearBootstrap();
  compose(['up', '-d', '--no-deps', 'server']);
  await ready();
  await verifyFixture(fixture);
  console.log('Restore into an empty database, sign-in without bootstrap credentials, and record recovery passed');
}

async function upgradeAndRecover() {
  docker(['pull', baselineImage], { stdio: 'inherit' });
  compose(['up', '-d', '--wait', 'db'], { stdio: 'inherit' });
  startImage(baselineImage);
  await ready();
  const fixture = await seedFixture();
  compose(['stop', 'server']);
  const before = migrationVersions();
  assert.equal(before.at(-1), 16, 'published 0.2.0 migration history');
  const dump = snapshot();
  clearBootstrap();

  startImage(candidateImage);
  await ready();
  const after = migrationVersions();
  assert.deepEqual(after.slice(0, before.length), before, 'upgrade preserves baseline migrations');
  assert.ok(after.length > before.length, 'candidate applied new migrations');
  const expected = readdirSync(new URL('../migrations/', import.meta.url))
    .map(name => name.match(/^(\d+)_.+\.sql$/))
    .filter(Boolean)
    .map(match => Number(match[1]))
    .sort((left, right) => left - right);
  assert.deepEqual(after, expected, 'candidate applied every source migration');
  const upgraded = await verifyFixture(fixture);
  const createdAfterUpgrade = await createOrganization(upgraded, `${project}-candidate`);
  console.log('Published 0.2.0 upgraded on the original database and preserved MFA and organization data');

  compose(['stop', 'server']);
  restoreSnapshot(dump);
  startImage(baselineImage);
  await ready();
  assert.deepEqual(migrationVersions(), before, 'restored database has the baseline migration history');
  // The restored snapshot predates use of the recovery code and creation of this organization.
  const recovered = await verifyFixture(fixture);
  assert.equal((await recovered(createdAfterUpgrade)).status, 404);
  console.log('Published 0.2.0 recovered from its original snapshot with working MFA and original records');
}

try {
  if (upgrade) await upgradeAndRecover();
  else await freshInstall();
} finally {
  compose(['down', '--volumes', '--remove-orphans'], { stdio: 'inherit' });
}
