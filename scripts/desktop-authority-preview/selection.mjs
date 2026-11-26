import { createHash } from 'node:crypto';
import { jwtVerify } from 'jose';

export const selectionType = 'flyw8t-preview-workstation-policy+jwt';
export const maxPolicyAge = 120;
const id = /^[A-Za-z0-9_.:-]{1,120}$/;
const modes = new Set(['disabled', 'ask_first', 'notify_with_stop']);
const positiveInteger = n => Number.isSafeInteger(n) && n > 0;

// Each verifier owns a local SQLite connection and trusts its provisioned
// policy administrator key. The runtime only verifies signed updates.
export class WorkstationSelections {
  #db;
  #issuer;
  #audience;
  #key;
  #clock;

  constructor(db, { policyIssuer, authority }, publicKey, clock) {
    if (publicKey?.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519' ||
        !policyIssuer || !authority || policyIssuer === authority) throw Error('Invalid policy trust');
    this.#db = db;
    this.#key = publicKey;
    this.#issuer = policyIssuer;
    this.#audience = authority;
    this.#clock = clock;
    const pin = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    db.exec(`CREATE TABLE IF NOT EXISTS selection_trust(
      singleton INTEGER PRIMARY KEY CHECK(singleton=1), issuer TEXT, audience TEXT, pin TEXT) STRICT;
      CREATE TABLE IF NOT EXISTS workstation_selections(
        tenant TEXT, device TEXT, enrollment TEXT NOT NULL, generation INTEGER NOT NULL,
        revision INTEGER NOT NULL, mode TEXT NOT NULL, expires INTEGER NOT NULL,
        applied_at INTEGER NOT NULL, checked_at INTEGER NOT NULL, digest TEXT NOT NULL,
        PRIMARY KEY(tenant,device,revision)) STRICT;`);
    db.prepare('INSERT OR IGNORE INTO selection_trust VALUES(1,?,?,?)').run(policyIssuer, authority, pin);
    if (!db.prepare('SELECT 1 FROM selection_trust WHERE issuer=? AND audience=? AND pin=?')
      .get(policyIssuer, authority, pin)) throw Error('Policy trust mismatch');
  }

  get publicKey() { return this.#key; }

  async apply(token, target) {
    if (typeof token !== 'string' || token.length > 8192) throw Error('Invalid policy update');
    const verifiedAt = this.#clock();
    const { payload: p, protectedHeader } = await jwtVerify(token, this.#key, {
      algorithms: ['EdDSA'], typ: selectionType, issuer: this.#issuer, audience: this.#audience,
      currentDate: new Date(verifiedAt * 1000), requiredClaims: ['iat','exp','sub'],
    });
    const now = this.#clock();
    if (target && (p.tenant !== target.tenant || p.device !== target.device)) {
      throw Error('Policy update targets another workstation');
    }
    if (!Object.keys(protectedHeader).every(k => ['alg','typ'].includes(k)) ||
        p.aud !== this.#audience || ![p.tenant,p.device,p.sub].every(v => typeof v === 'string' && id.test(v)) ||
        ![p.generation,p.revision].every(positiveInteger) || !modes.has(p.mode) ||
        ![p.iat,p.exp,now,verifiedAt].every(Number.isSafeInteger) || now < verifiedAt ||
        p.iat > verifiedAt || p.exp <= now || p.exp - p.iat > maxPolicyAge) throw Error('Invalid policy update');
    const digest = createHash('sha256').update(token).digest('hex');
    // One atomic statement preserves the policy decision history and rejects
    // stale arrivals, including when multiple verifiers apply updates at once.
    const applied = this.#db.prepare(`INSERT INTO workstation_selections
      SELECT ?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM workstation_selections
        WHERE tenant=? AND device=? AND (revision>? OR checked_at>? OR generation>?
          OR (generation=? AND enrollment<>?)))
      ON CONFLICT(tenant,device,revision) DO UPDATE SET checked_at=excluded.checked_at
      WHERE digest=excluded.digest`)
      .run(p.tenant,p.device,p.sub,p.generation,p.revision,p.mode,p.exp,now,now,digest,
        p.tenant,p.device,p.revision,now,p.generation,p.generation,p.sub);
    if (!applied.changes) throw Error('Stale or conflicting policy update');
  }

  // Recording the time even for an expired or denied policy prevents an old
  // selection becoming current again if the verifier clock moves backwards.
  allowed(policy, now) {
    if (!Number.isSafeInteger(now) || policy.policyIssuer !== this.#issuer ||
        policy.authority !== this.#audience) return null;
    const row = this.#db.prepare(`UPDATE workstation_selections SET checked_at=?
      WHERE tenant=? AND device=? AND checked_at<=? AND revision=(
        SELECT MAX(revision) FROM workstation_selections WHERE tenant=? AND device=?)
      RETURNING enrollment,generation,revision,mode,expires`)
      .get(now,policy.tenant,policy.device,now,policy.tenant,policy.device);
    if (row?.mode !== 'notify_with_stop' || row.expires <= now ||
        row.enrollment !== policy.enrollment || row.generation !== policy.generation) return null;
    return row;
  }
}
