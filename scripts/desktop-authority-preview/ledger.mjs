import { randomBytes, createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { digest, makeEndpointOffer, nowSeconds, requireEvidence, verifyGrant } from './evidence.mjs';
import { WorkstationSelections } from './selection.mjs';

const schema = `
  CREATE TABLE IF NOT EXISTS configuration(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL,
    checked_at INTEGER NOT NULL DEFAULT 0, stopped_at INTEGER,
    stop_journaled INTEGER NOT NULL DEFAULT 0 CHECK(stop_journaled IN (0,1))
  ) STRICT;
  CREATE TABLE IF NOT EXISTS challenges(
    nonce TEXT PRIMARY KEY, binding TEXT NOT NULL UNIQUE, expires INTEGER NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS leases(
    id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE REFERENCES challenges(nonce),
    expires INTEGER NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS challenge_policies(
    nonce TEXT PRIMARY KEY REFERENCES challenges(nonce), revision INTEGER NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS revocations(
    id TEXT PRIMARY KEY REFERENCES leases(id), occurred INTEGER NOT NULL,
    journaled INTEGER NOT NULL DEFAULT 0 CHECK(journaled IN (0,1))
  ) STRICT;
  CREATE TABLE IF NOT EXISTS offer_vetoes(
    nonce TEXT PRIMARY KEY REFERENCES challenges(nonce), occurred INTEGER NOT NULL,
    journaled INTEGER NOT NULL DEFAULT 0 CHECK(journaled IN (0,1))
  ) STRICT;
  CREATE TABLE IF NOT EXISTS audit(
    sequence INTEGER PRIMARY KEY, occurred INTEGER NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('admitted','denied','revoked','offer_stopped','stopped')),
    correlation TEXT, CHECK ((event IN ('denied','stopped'))=(correlation IS NULL))
  ) STRICT;`;

function keyDigest(key) {
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}

// Independent endpoint state. All callers use their own connection to the same
// local file. Callers can only receive an opaque lease from successful admission.
export class EndpointLedger {
  #db;
  #policy;
  #verifyKey;
  #clock;
  #selections;

  constructor(path, policy, grantPublicKey, policyPublicKey, clock = nowSeconds) {
    this.#policy = Object.freeze({ ...policy });
    this.#verifyKey = grantPublicKey;
    this.#clock = clock;
    const db = this.#db = new DatabaseSync(path);
    try {
      db.exec('PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
      db.exec(schema);
      const p = this.#policy;
      requireEvidence(keyDigest(grantPublicKey) !== keyDigest(policyPublicKey));
      const binding = digest(JSON.stringify([p.authority,p.endpointIssuer,p.enrollment,p.device,p.tenant,
        p.generation,p.viewerIssuer,p.viewerOrigin,p.operatorSubject,p.identityIssuer,p.identityAudience,
        p.totpAssurance,keyDigest(grantPublicKey)]));
      this.#write(() => {
        this.#selections = new WorkstationSelections(db, p, policyPublicKey, clock);
        db.prepare('INSERT OR IGNORE INTO configuration(singleton,binding) VALUES(1, ?)').run(binding);
        requireEvidence(db.prepare('SELECT binding FROM configuration WHERE singleton=1').get().binding === binding);
      });
    } catch (error) {
      db.close();
      throw error;
    }
  }

  applyPolicy(signedUpdate) { return this.#selections.apply(signedUpdate, this.#policy); }

  #write(fn) {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
  }

  #log(event, id, occurred) {
    const domain = event === 'offer_stopped' ? 'offer' : 'lease';
    const correlation = id ? digest('flyw8t.preview.audit.' + domain + '.' + id) : null;
    this.#db.prepare('INSERT INTO audit(occurred,event,correlation) VALUES(?,?,?)').run(occurred, event, correlation);
  }

  #advanceClock(now) {
    if (!Number.isSafeInteger(now)) return false;
    return this.#db.prepare(`UPDATE configuration SET checked_at=?
      WHERE checked_at<=? AND stopped_at IS NULL`).run(now, now).changes === 1;
  }

  async prepare(endpointKey, session) {
    const nonce = randomBytes(32).toString('base64url');
    const now = this.#clock();
    const selected = this.#selections.allowed(this.#policy, now);
    requireEvidence(selected);
    const offer = await makeEndpointOffer(this.#policy, endpointKey, { ...session, nonce, policyRevision: selected.revision }, now);
    this.#write(() => {
      const atCommit = this.#clock();
      requireEvidence(atCommit >= now && atCommit < now + 60 && this.#advanceClock(atCommit));
      requireEvidence(this.#selections.allowed(this.#policy, atCommit)?.revision === selected.revision);
      this.#db.prepare('INSERT INTO challenges VALUES(?,?,?)').run(nonce, digest(offer), now + 60);
      this.#db.prepare('INSERT INTO challenge_policies VALUES(?,?)').run(nonce, selected.revision);
    });
    return { offer, nonce };
  }

  async admit(token) {
    let grant;
    const verifiedAt = this.#sampleClock();
    // This observation is durable before yielding to the signature verifier.
    if (this.#observeTime(verifiedAt) === verifiedAt) {
      try {
        grant = await verifyGrant(token, this.#policy, this.#verifyKey, verifiedAt);
      } catch { /* Record a denial in the same decision path. */ }
    }
    const decision = this.#write(() => {
      const now = this.#sampleClock();
      const highWater = this.#observeTime(now);
      // Keep the clock observation when a failed audit write rolls back a spend.
      this.#db.exec('SAVEPOINT admission');
      try {
        const lease = grant && now === highWater ? this.#redeem(grant, now) : null;
        this.#log(lease ? 'admitted' : 'denied', lease, highWater);
        this.#db.exec('RELEASE admission');
        return { lease };
      } catch (error) {
        this.#db.exec('ROLLBACK TO admission; RELEASE admission');
        return { error };
      }
    });
    if (decision.error) throw decision.error;
    if (!decision.lease) throw new Error('Grant denied');
    return decision.lease;
  }

  #redeem(grant, now) {
    const selected = this.#selections.allowed(this.#policy, now);
    if (!selected || now < grant.iat) return null;
    const inserted = this.#db.prepare(`INSERT INTO leases(id,nonce,expires)
      SELECT ?,nonce,? FROM challenges WHERE nonce=? AND binding=? AND expires>? AND ?>?
      AND EXISTS (SELECT 1 FROM configuration WHERE singleton=1 AND stopped_at IS NULL)
      AND EXISTS (SELECT 1 FROM challenge_policies WHERE nonce=challenges.nonce AND revision=?)
      AND NOT EXISTS (SELECT 1 FROM offer_vetoes WHERE nonce=challenges.nonce)
      ON CONFLICT DO NOTHING`).run(grant.jti, grant.exp, grant.nonce,
        grant.binding, now, grant.exp, now, selected.revision);
    return inserted.changes === 1 ? grant.jti : null;
  }

  // For the rehearsal this predicate guards a simulated use of a lease. Each use
  // consults durable state. Production work must stop an existing transport too.
  active(lease) {
    try {
      return this.#write(() => {
        const now = this.#clock();
        const selected = this.#selections.allowed(this.#policy, now);
        return Boolean(selected && this.#advanceClock(now) && this.#db.prepare(`SELECT 1 FROM leases WHERE id=? AND expires>?
          AND EXISTS (SELECT 1 FROM challenge_policies WHERE nonce=leases.nonce AND revision=?)
          AND NOT EXISTS (SELECT 1 FROM revocations WHERE id=leases.id)
          AND NOT EXISTS (SELECT 1 FROM offer_vetoes WHERE nonce=leases.nonce)`).get(lease, now, selected.revision));
      });
    } catch {
      return false;
    }
  }

  // A veto must remain available even when the clock fails or moves backwards.
  // Persist each trustworthy observation before another lease can be used.
  #sampleClock() {
    try { return this.#clock(); } catch { return undefined; }
  }

  #observeTime(observed) {
    return this.#db.prepare(`UPDATE configuration SET checked_at=MAX(checked_at,?)
      WHERE singleton=1 RETURNING checked_at`).get(Number.isSafeInteger(observed) ? observed : 0).checked_at;
  }

  revoke(lease) {
    // Commit the veto and its durable audit intent together. If journal delivery
    // fails, every reader still sees the veto, including after process restart.
    this.#write(() => {
      requireEvidence(this.#db.prepare('SELECT 1 FROM leases WHERE id=?').get(lease));
      const occurred = this.#observeTime(this.#sampleClock());
      this.#db.prepare('INSERT OR IGNORE INTO revocations(id,occurred) VALUES(?,?)').run(lease, occurred);
    });
    this.flushRevocations();
  }

  cancelLocalOffer(nonce) {
    this.#write(() => {
      requireEvidence(this.#db.prepare('SELECT 1 FROM challenges WHERE nonce=?').get(nonce));
      const occurred = this.#observeTime(this.#sampleClock());
      this.#db.prepare('INSERT OR IGNORE INTO offer_vetoes(nonce,occurred) VALUES(?,?)').run(nonce, occurred);
    });
    this.flushRevocations();
  }

  stopLocally() {
    this.#write(() => {
      const occurred = this.#observeTime(this.#sampleClock());
      this.#db.prepare('UPDATE configuration SET stopped_at=? WHERE stopped_at IS NULL').run(occurred);
    });
    this.flushRevocations();
  }

  flushRevocations() {
    this.#write(() => {
      for (const row of this.#db.prepare('SELECT id,occurred FROM revocations WHERE journaled=0').all()) {
        this.#log('revoked', row.id, row.occurred);
        this.#db.prepare('UPDATE revocations SET journaled=1 WHERE id=?').run(row.id);
      }
      for (const row of this.#db.prepare('SELECT nonce,occurred FROM offer_vetoes WHERE journaled=0').all()) {
        this.#log('offer_stopped', row.nonce, row.occurred);
        this.#db.prepare('UPDATE offer_vetoes SET journaled=1 WHERE nonce=?').run(row.nonce);
      }
      const stopped = this.#db.prepare('SELECT stopped_at FROM configuration WHERE stopped_at IS NOT NULL AND stop_journaled=0').get();
      if (stopped) {
        this.#log('stopped', null, stopped.stopped_at);
        this.#db.exec('UPDATE configuration SET stop_journaled=1');
      }
    });
  }

  close() { this.#db.close(); }
}
