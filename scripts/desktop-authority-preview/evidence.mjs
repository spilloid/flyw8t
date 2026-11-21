import { createHash, createPublicKey, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { WorkstationSelections } from './selection.mjs';

export const grantType = 'flyw8t-preview-view-grant+jwt';
const offerType = 'flyw8t-preview-endpoint+jwt';
const viewerType = 'flyw8t-preview-viewer+jwt';
const scope = 'view_synthetic_chart';
export const maxGrantAge = 30;
const maxEvidenceAge = 60;
const maxMfaAge = 300;
const jwtLimit = 12 * 1024;
const idPattern = /^[a-zA-Z0-9_.:-]{1,120}$/;
const noncePattern = /^[a-zA-Z0-9_-]{43}$/;
const fpPattern = /^[a-f0-9]{64}$/;
export const nowSeconds = () => Math.floor(Date.now() / 1000);
export const digest = token => createHash('sha256').update(token, 'utf8').digest('hex');
const matches = (pattern, value) => typeof value === 'string' && pattern.test(value);

export function requireEvidence(condition) {
  if (!condition) throw new Error('Evidence rejected');
}

// Each role uses a distinct pinned issuer, key, audience and token type.
// Never look up keys from the untrusted JOSE header or payload.
async function verified(token, { key, issuer, audience, type, now, claims, age }) {
  requireEvidence(typeof token === 'string' && token.length <= jwtLimit);
  const { payload, protectedHeader } = await jwtVerify(token, key, {
    algorithms: ['EdDSA'], issuer, audience, typ: type,
    currentDate: new Date(now * 1000),
    requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp', ...claims],
  });
  requireEvidence(Object.keys(protectedHeader).every(k => ['alg', 'typ'].includes(k))
    && payload.aud === audience && Number.isSafeInteger(payload.iat)
    && Number.isSafeInteger(payload.exp) && payload.iat <= now
    && payload.exp > payload.iat && (!age || payload.exp - payload.iat <= age)
    && now < payload.exp);
  return payload;
}

function sign(payload, type, key) {
  return new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: type }).sign(key);
}

export function makeEndpointOffer(p, key, { session, viewerFingerprint, endpointFingerprint, nonce, policyRevision }, now) {
  requireEvidence(matches(idPattern, session) && matches(noncePattern, nonce)
    && matches(fpPattern, viewerFingerprint) && matches(fpPattern, endpointFingerprint)
    && viewerFingerprint !== endpointFingerprint && Number.isSafeInteger(policyRevision) && policyRevision > 0);
  return sign({
    iss: p.endpointIssuer, sub: p.enrollment, aud: p.authority,
    iat: now, exp: now + maxEvidenceAge, tenant: p.tenant, device: p.device,
    generation: p.generation, policy_revision: policyRevision, session, scope, viewer_origin: p.viewerOrigin,
    viewer_fp: viewerFingerprint, endpoint_fp: endpointFingerprint, nonce,
  }, offerType, key);
}

export function confirmInFixtureViewer(p, viewerKey, { offer, subject, session, observedViewerFingerprint, observedEndpointFingerprint }, now) {
  requireEvidence(matches(fpPattern, observedViewerFingerprint) && matches(fpPattern, observedEndpointFingerprint) && matches(idPattern,session));
  return sign({
    iss: p.viewerIssuer, sub: subject, aud: p.authority, iat: now, exp: now + maxEvidenceAge,
    viewer_origin: p.viewerOrigin, binding: digest(offer), viewer_fp: observedViewerFingerprint,
    endpoint_fp:observedEndpointFingerprint, session,
  }, viewerType, viewerKey);
}

// An independently operated adapter supplies a pinned public key and one
// grant-specific operation. Only this test adapter sees a software private key.
// Provider adapters can keep their key handles inside their own boundary.
export function softwareViewSigner(policy, privateKey) {
  const p = Object.freeze({ ...policy });
  return Object.freeze({
    publicKey: createPublicKey(privateKey),
    signViewGrant({ binding, nonce, authenticatedAt, issuedAt, expiresAt }) {
      requireEvidence(matches(fpPattern, binding) && matches(noncePattern, nonce)
        && [authenticatedAt, issuedAt, expiresAt].every(Number.isSafeInteger)
        && authenticatedAt <= issuedAt && expiresAt > issuedAt
        && expiresAt <= issuedAt + maxGrantAge && expiresAt <= authenticatedAt + maxMfaAge);
      return sign({ iss: p.authority, sub: p.operatorSubject, aud: p.endpointIssuer,
        iat: issuedAt, exp: expiresAt, jti: randomUUID(), scope, binding, nonce,
        generation: p.generation, enrollment: p.enrollment, assurance: p.totpAssurance,
        auth_time: authenticatedAt }, grantType, privateKey);
    },
  });
}

// The independent authority provisions policy and role pins. Its signer adapter
// supplies a public verification key and a grant-specific signing operation.
export function grantAuthority({ policy, identityKey, endpointKey, viewerKey, signer, selections, clock = nowSeconds }) {
  const p = Object.freeze({ ...policy });
  const grantKey = signer.publicKey;
  const issue = signer.signViewGrant.bind(signer);
  requireEvidence(selections instanceof WorkstationSelections);
  const keys = [identityKey, endpointKey, viewerKey, grantKey, selections.publicKey];
  requireEvidence(keys.every(k => k.type === 'public' && k.asymmetricKeyType === 'ed25519'));
  const keyIds = keys.map(k => k.export({ type: 'spki', format: 'der' }).toString('base64'));
  requireEvidence(new Set(keyIds).size === 5
    && new Set([p.authority, p.identityIssuer, p.endpointIssuer, p.viewerIssuer, p.policyIssuer]).size === 5);
  return async function authorize({ identity, offer, confirmation }) {
    const now = clock();
    const transaction = await verified(offer, { key: endpointKey, issuer: p.endpointIssuer,
      audience: p.authority, type: offerType, now, age: maxEvidenceAge,
      claims: ['tenant','device','generation','policy_revision','session','scope','viewer_origin','viewer_fp','endpoint_fp','nonce'] });
    requireEvidence(transaction.sub === p.enrollment && transaction.tenant === p.tenant
      && transaction.device === p.device && transaction.generation === p.generation
      && transaction.scope === scope && transaction.viewer_origin === p.viewerOrigin
      && matches(idPattern, transaction.session) && matches(noncePattern, transaction.nonce)
      && matches(fpPattern, transaction.viewer_fp) && matches(fpPattern, transaction.endpoint_fp)
      && transaction.viewer_fp !== transaction.endpoint_fp);
    const user = await verified(identity, { key: identityKey, issuer: p.identityIssuer,
      audience: p.identityAudience, type: 'JWT', now, claims: ['auth_time','acr','amr','nonce'] });
    requireEvidence(user.sub === p.operatorSubject && user.nonce === transaction.nonce
      && user.acr === p.totpAssurance && Array.isArray(user.amr) && user.amr.length === 2
      && user.amr.includes('pwd') && user.amr.includes('otp')
      && Number.isSafeInteger(user.auth_time) && user.auth_time <= user.iat
      && now - user.auth_time <= maxMfaAge);
    const binding = digest(offer);
    const viewer = await verified(confirmation, { key: viewerKey, issuer: p.viewerIssuer,
      audience: p.authority, type: viewerType, now, age: maxEvidenceAge,
      claims: ['viewer_origin','viewer_fp','endpoint_fp','session','binding'] });
    requireEvidence(viewer.sub === user.sub && viewer.viewer_origin === p.viewerOrigin
      && viewer.viewer_fp === transaction.viewer_fp && viewer.endpoint_fp===transaction.endpoint_fp
      && viewer.session===transaction.session && viewer.binding === binding);
    const selected = selections.allowed(p, clock());
    requireEvidence(selected && selected.revision === transaction.policy_revision);
    const endsAt = Math.min(now + maxGrantAge, transaction.exp, viewer.exp, user.exp, selected.expires,
      user.auth_time + maxMfaAge);
    requireEvidence(endsAt > now);
    const request = Object.freeze({ binding, nonce: transaction.nonce, authenticatedAt: user.auth_time,
      issuedAt: now, expiresAt: endsAt });
    const token = await issue(request);
    const signed = await verifyGrant(token, p, grantKey, clock());
    requireEvidence(selections.allowed(p, clock())?.revision === selected.revision);
    requireEvidence(signed.binding === binding && signed.nonce === request.nonce
      && signed.auth_time === request.authenticatedAt && signed.iat === now && signed.exp === endsAt);
    return token;
  };
}

export async function verifyGrant(token, p, publicKey, now) {
  const grant = await verified(token, { key: publicKey, issuer: p.authority,
    audience: p.endpointIssuer, type: grantType, now, age: maxGrantAge,
    claims: ['jti','scope','binding','nonce','generation','enrollment','assurance','auth_time'] });
  requireEvidence(grant.sub === p.operatorSubject && grant.scope === scope
    && grant.generation === p.generation && grant.enrollment === p.enrollment
    && grant.assurance === p.totpAssurance && Number.isSafeInteger(grant.auth_time)
    && grant.auth_time <= grant.iat && grant.exp <= grant.auth_time + maxMfaAge
    && matches(/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/, grant.jti)
    && matches(noncePattern, grant.nonce) && matches(fpPattern, grant.binding));
  return grant;
}
