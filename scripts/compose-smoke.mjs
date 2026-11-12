// Exercise the actual Compose image, MFA sign-in, and a dump/restore into an empty database.
// Node 22+, Docker Compose. Creates only a unique throwaway project and removes it on exit.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const project = `flyw8t-smoke-${randomBytes(8).toString('hex')}`;
const listener = createServer();
await new Promise((resolve, reject) => listener.once('error', reject).listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise((resolve, reject) => listener.close(error => error ? reject(error) : resolve()));
const base = `http://localhost:${port}`;
const email = 'smoke@example.test';
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

function compose(args, options = {}) {
  return execFileSync('docker', ['compose', '--project-name', project, '-f', 'deploy/compose/compose.yaml', ...args], {
    cwd: root, env, maxBuffer: 32 * 1024 * 1024, timeout: 15 * 60_000, ...options,
  });
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

try {
  compose(['up', '-d', '--build', 'db', 'server'], { stdio: 'inherit' });
  await ready();
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
  const organizations = await request('/organizations');
  assert.equal(organizations.status, 200, 'fully signed in after MFA');
  const created = await request('/organizations', { csrf: input(organizations.html, 'csrf'), name: project });
  assert.equal(created.status, 303);
  assert.match(created.location, /^\/organizations\/[0-9a-f-]+/);
  const organizationPath = created.location;
  console.log('Compose startup, password + TOTP, and organization creation passed');

  const dump = compose(['exec', '-T', 'db', 'pg_dump', '-U', 'flyw8t', '-Fc', 'flyw8t']);
  assert.ok(dump.length > 0);
  compose(['stop', 'server']);
  // Only this script's randomly named Compose project is addressed. Never touch a host DB.
  compose(['exec', '-T', 'db', 'dropdb', '-U', 'flyw8t', '--force', 'flyw8t']);
  compose(['exec', '-T', 'db', 'createdb', '-U', 'flyw8t', 'flyw8t']);
  compose(['exec', '-T', 'db', 'pg_restore', '-U', 'flyw8t', '-d', 'flyw8t', '--no-owner', '--exit-on-error'], { input: dump });
  env.FLYW8T_BOOTSTRAP_ADMIN_EMAIL = '';
  env.FLYW8T_BOOTSTRAP_ADMIN_PASSWORD = '';
  compose(['up', '-d', '--no-deps', 'server']);
  await ready();
  const restored = browser();
  const challenge = await restored(await passwordSignIn(restored));
  assert.equal(challenge.status, 200);
  assert.ok(!challenge.html.includes('id="totp-key"'), 'MFA configuration survived restore');
  const signedIn = await restored('/login/mfa', { csrf: input(challenge.html, 'csrf'), code: recoveryCode });
  assert.equal(signedIn.status, 303, 'restored account accepts its recovery code');
  const organization = await restored(organizationPath);
  assert.equal(organization.status, 200);
  assert.ok(organization.html.includes(project), 'created organization survived restore');
  console.log('Restore into an empty database, sign-in without bootstrap credentials, and record recovery passed');
} finally {
  compose(['down', '--volumes', '--remove-orphans'], { stdio: 'inherit' });
}
