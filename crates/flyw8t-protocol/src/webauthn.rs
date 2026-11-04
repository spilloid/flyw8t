//! Verifying WebAuthn signatures (passkeys and security keys), for the server now and the agent later (ADR-0014).
//!
//! Only what both sides need: checking a `clientDataJSON` and the authenticator data, and verifying an ES256 (ECDSA
//! P-256, SHA-256) signature over them. Registration, which parses CBOR, is the server's alone.
//!
//! An assertion signs `authenticatorData || SHA-256(clientDataJSON)`. The challenge sits inside `clientDataJSON`, so
//! choosing the challenge chooses what is signed: a random nonce for sudo mode, the hash of a statement for an approval.

use base64::Engine;
use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::Deserialize;

/// User present: someone touched the key.
pub const FLAG_UP: u8 = 0x01;
/// User verified: a PIN, biometric or device unlock, not only a touch.
pub const FLAG_UV: u8 = 0x04;
/// Attested credential data follows (registration only).
pub const FLAG_AT: u8 = 0x40;
/// Extension data follows.
pub const FLAG_ED: u8 = 0x80;

/// Length of an uncompressed SEC1 P-256 public key: `0x04 || x || y`.
pub const P256_KEY_LEN: usize = 65;

/// Largest `clientDataJSON` accepted. Browsers send a few hundred bytes.
pub const MAX_CLIENT_DATA: usize = 4096;
/// Largest authenticator data accepted in an assertion.
pub const MAX_AUTHENTICATOR_DATA: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    /// `navigator.credentials.create`: registering a credential.
    Create,
    /// `navigator.credentials.get`: signing with one.
    Get,
}

impl Ceremony {
    fn client_type(self) -> &'static str {
        match self {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        }
    }
}

/// What a signature must have been made for.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub ceremony: Ceremony,
    /// The exact challenge bytes the browser was given.
    pub challenge: &'a [u8],
    /// `scheme://host[:port]` of the console, as the browser reports it.
    pub origin: &'a str,
    /// The relying party ID: the console's host name.
    pub rp_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("client data is not valid")]
    ClientData,
    #[error("signed for a different purpose")]
    WrongCeremony,
    #[error("signed for a different challenge")]
    WrongChallenge,
    #[error("signed on a different site")]
    WrongOrigin,
    #[error("authenticator data is not valid")]
    AuthenticatorData,
    #[error("signed for a different relying party")]
    WrongRelyingParty,
    #[error("the key was not touched")]
    NotPresent,
    #[error("the key did not verify its user (PIN, biometric or device unlock)")]
    NotVerified,
    #[error("the signature does not verify")]
    BadSignature,
}

pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, with or without padding (browsers and libraries differ).
pub fn from_b64url(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// Check `clientDataJSON`: the ceremony, the challenge and the origin, and that it was not made inside a frame of
/// another site.
pub fn check_client_data(json: &[u8], exp: &Expected) -> Result<(), Error> {
    if json.len() > MAX_CLIENT_DATA {
        return Err(Error::ClientData);
    }
    let c: ClientData = serde_json::from_slice(json).map_err(|_| Error::ClientData)?;
    if c.kind != exp.ceremony.client_type() {
        return Err(Error::WrongCeremony);
    }
    if from_b64url(&c.challenge).as_deref() != Some(exp.challenge) {
        return Err(Error::WrongChallenge);
    }
    if c.origin != exp.origin || c.cross_origin == Some(true) {
        return Err(Error::WrongOrigin);
    }
    Ok(())
}

/// The fixed start of authenticator data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub flags: u8,
    pub sign_count: u32,
}

/// Check the fixed part of authenticator data: the relying party, and that the user was present and verified.
pub fn check_authenticator_data(data: &[u8], rp_id: &str) -> Result<AuthenticatorData, Error> {
    if data.len() < 37 || data.len() > MAX_AUTHENTICATOR_DATA {
        return Err(Error::AuthenticatorData);
    }
    if data[..32] != *digest(&SHA256, rp_id.as_bytes()).as_ref() {
        return Err(Error::WrongRelyingParty);
    }
    let flags = data[32];
    if flags & FLAG_UP == 0 {
        return Err(Error::NotPresent);
    }
    if flags & FLAG_UV == 0 {
        return Err(Error::NotVerified);
    }
    Ok(AuthenticatorData {
        flags,
        sign_count: u32::from_be_bytes([data[33], data[34], data[35], data[36]]),
    })
}

/// Verify an assertion made with `public_key` (uncompressed SEC1 P-256) for `exp`. Returns the authenticator's
/// signature counter, which the caller may compare with the last one seen.
pub fn verify_assertion(
    public_key: &[u8],
    exp: &Expected,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<AuthenticatorData, Error> {
    debug_assert_eq!(exp.ceremony, Ceremony::Get);
    check_client_data(client_data_json, exp)?;
    let auth = check_authenticator_data(authenticator_data, exp.rp_id)?;
    if public_key.len() != P256_KEY_LEN || public_key[0] != 0x04 {
        return Err(Error::BadSignature);
    }
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(digest(&SHA256, client_data_json).as_ref());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&signed, signature)
        .map_err(|_| Error::BadSignature)?;
    Ok(auth)
}

/// The console's origin and relying party ID, from its public URL (`https://rmm.example.com:8443/x` gives
/// `https://rmm.example.com:8443` and `rmm.example.com`). A default port is left out, as browsers do.
pub fn origin_and_rp_id(public_url: &str) -> Option<(String, String)> {
    let (scheme, rest) = public_url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let (h, after) = v6.split_once(']')?;
            (format!("[{h}]"), after.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.clone(), None),
        },
    };
    let port = port.filter(|p| !matches!((scheme.as_str(), *p), ("https", "443") | ("http", "80")));
    let origin = match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    Some((
        origin,
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
    ))
}

/// Browsers refuse an IP address as the relying party ID: passkeys need the console to be reached by a host name
/// (`localhost` counts).
pub fn rp_id_usable(rp_id: &str) -> bool {
    !rp_id.is_empty() && rp_id.parse::<std::net::IpAddr>().is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    const ORIGIN: &str = "https://rmm.example.com";
    const RP: &str = "rmm.example.com";

    struct Key(EcdsaKeyPair);

    impl Key {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            Key(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap(),
            )
        }
        fn public(&self) -> Vec<u8> {
            self.0.public_key().as_ref().to_vec()
        }
        fn sign(&self, auth: &[u8], client: &[u8]) -> Vec<u8> {
            let mut m = auth.to_vec();
            m.extend_from_slice(digest(&SHA256, client).as_ref());
            self.0
                .sign(&SystemRandom::new(), &m)
                .unwrap()
                .as_ref()
                .to_vec()
        }
    }

    fn auth_data(rp: &str, flags: u8, count: u32) -> Vec<u8> {
        let mut d = digest(&SHA256, rp.as_bytes()).as_ref().to_vec();
        d.push(flags);
        d.extend_from_slice(&count.to_be_bytes());
        d
    }

    fn client(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::json!({ "type": kind, "challenge": b64url(challenge), "origin": origin, "crossOrigin": false })
            .to_string()
            .into_bytes()
    }

    fn exp(challenge: &[u8]) -> Expected<'_> {
        Expected {
            ceremony: Ceremony::Get,
            challenge,
            origin: ORIGIN,
            rp_id: RP,
        }
    }

    #[test]
    fn a_good_assertion_verifies_and_reports_its_counter() {
        let k = Key::new();
        let a = auth_data(RP, FLAG_UP | FLAG_UV, 7);
        let c = client("webauthn.get", b"nonce", ORIGIN);
        let got = verify_assertion(&k.public(), &exp(b"nonce"), &a, &c, &k.sign(&a, &c)).unwrap();
        assert_eq!(got.sign_count, 7);
    }

    #[test]
    fn every_part_of_what_was_signed_matters() {
        let k = Key::new();
        let good_a = auth_data(RP, FLAG_UP | FLAG_UV, 1);
        let good_c = client("webauthn.get", b"nonce", ORIGIN);
        let check = |a: &[u8], c: &[u8], signed_a: &[u8], signed_c: &[u8], key: &Key| {
            verify_assertion(
                &key.public(),
                &exp(b"nonce"),
                a,
                c,
                &key.sign(signed_a, signed_c),
            )
        };
        // Each case is signed honestly over what it presents, unless it is about the signature itself.
        let cases: Vec<(Vec<u8>, Vec<u8>, Error)> = vec![
            (
                good_a.clone(),
                client("webauthn.create", b"nonce", ORIGIN),
                Error::WrongCeremony,
            ),
            (
                good_a.clone(),
                client("webauthn.get", b"other", ORIGIN),
                Error::WrongChallenge,
            ),
            (
                good_a.clone(),
                client("webauthn.get", b"nonce", "https://evil.example"),
                Error::WrongOrigin,
            ),
            (
                good_a.clone(),
                client("webauthn.get", b"nonce", "https://rmm.example.com:444"),
                Error::WrongOrigin,
            ),
            (good_a.clone(), b"not json".to_vec(), Error::ClientData),
            (
                auth_data("evil.example", FLAG_UP | FLAG_UV, 1),
                good_c.clone(),
                Error::WrongRelyingParty,
            ),
            (auth_data(RP, FLAG_UV, 1), good_c.clone(), Error::NotPresent),
            (
                auth_data(RP, FLAG_UP, 1),
                good_c.clone(),
                Error::NotVerified,
            ),
            (
                good_a[..36].to_vec(),
                good_c.clone(),
                Error::AuthenticatorData,
            ),
        ];
        for (a, c, want) in cases {
            assert_eq!(check(&a, &c, &a, &c, &k), Err(want.clone()), "{want:?}");
        }
        let framed = serde_json::json!({ "type": "webauthn.get", "challenge": b64url(b"nonce"), "origin": ORIGIN, "crossOrigin": true })
            .to_string()
            .into_bytes();
        assert_eq!(
            check(&good_a, &framed, &good_a, &framed, &k),
            Err(Error::WrongOrigin)
        );
        // Signed over something else, or by another key.
        let other_a = auth_data(RP, FLAG_UP | FLAG_UV, 2);
        assert_eq!(
            check(&good_a, &good_c, &other_a, &good_c, &k),
            Err(Error::BadSignature)
        );
        let other_c = client("webauthn.get", b"nonce", ORIGIN)
            .into_iter()
            .chain(*b" ")
            .collect::<Vec<_>>();
        assert_eq!(
            check(&good_a, &good_c, &good_a, &other_c, &k),
            Err(Error::BadSignature)
        );
        let a = good_a.clone();
        let sig = k.sign(&a, &good_c);
        assert_eq!(
            verify_assertion(&Key::new().public(), &exp(b"nonce"), &a, &good_c, &sig),
            Err(Error::BadSignature)
        );
        let mut bad = k.public();
        bad[0] = 0x02;
        assert_eq!(
            verify_assertion(&bad, &exp(b"nonce"), &a, &good_c, &sig),
            Err(Error::BadSignature)
        );
        assert!(verify_assertion(&k.public(), &exp(b"nonce"), &a, &good_c, &sig).is_ok());
    }

    #[test]
    fn padded_challenges_decode_too() {
        assert_eq!(from_b64url("bm9uY2U="), Some(b"nonce".to_vec()));
        assert_eq!(from_b64url("bm9uY2U"), Some(b"nonce".to_vec()));
        assert_eq!(from_b64url("bm9u+2U"), None);
    }

    #[test]
    fn origin_and_rp_id_follow_the_browser() {
        let o = |u: &str| origin_and_rp_id(u);
        assert_eq!(
            o("https://rmm.example.com"),
            Some((ORIGIN.into(), RP.into()))
        );
        assert_eq!(
            o("https://RMM.example.com:443/console"),
            Some((ORIGIN.into(), RP.into()))
        );
        assert_eq!(
            o("https://rmm.example.com:8443"),
            Some(("https://rmm.example.com:8443".into(), RP.into()))
        );
        assert_eq!(
            o("http://localhost:8080"),
            Some(("http://localhost:8080".into(), "localhost".into()))
        );
        assert_eq!(
            o("http://[::1]:8080"),
            Some(("http://[::1]:8080".into(), "::1".into()))
        );
        assert_eq!(o("https://user@rmm.example.com"), None);
        assert_eq!(o("rmm.example.com"), None);
    }

    #[test]
    fn ip_addresses_cannot_be_relying_parties() {
        assert!(rp_id_usable("rmm.example.com"));
        assert!(rp_id_usable("localhost"));
        for ip in ["127.0.0.1", "192.168.1.10", "::1", ""] {
            assert!(!rp_id_usable(ip), "{ip:?}");
        }
    }
}
