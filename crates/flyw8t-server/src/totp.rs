//! Time-based one-time passwords (RFC 6238: HMAC-SHA1, 30-second steps, 6 digits) and
//! recovery codes for the web console's second factor.
//!
//! A code is accepted for the current step and one step either side (clock skew), and only
//! for a step later than the last one this user spent, so an observed code cannot be replayed.
//! The caller enforces the "later than" rule atomically in the database.

use ring::hmac;
use ring::rand::SecureRandom;

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
pub const SECRET_LEN: usize = 20;
/// Steps either side of now that are still accepted.
pub const SKEW: u64 = 1;
pub const RECOVERY_CODES: usize = 10;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn new_secret() -> Vec<u8> {
    let mut s = vec![0u8; SECRET_LEN];
    ring::rand::SystemRandom::new()
        .fill(&mut s)
        .expect("system RNG");
    s
}

/// RFC 4648 base32 without padding, as authenticator apps expect.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

pub fn now_step() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    step_at(secs)
}

/// The code for one step, as an integer below 10^digits.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = hmac::sign(&key, &counter.to_be_bytes());
    let h = mac.as_ref();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits)
}

pub fn code_at(secret: &[u8], step: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, step, DIGITS),
        width = DIGITS as usize
    )
}

/// Strip the spaces and dashes people type; `None` unless exactly six digits remain.
pub fn normalize_code(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    (s.len() == DIGITS as usize && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

/// The step `code` matches within the skew window around `now`, if any. Checks every
/// candidate so the time taken does not depend on which one matched.
pub fn matching_step(secret: &[u8], code: &str, now: u64) -> Option<u64> {
    let code = normalize_code(code)?;
    let mut found = None;
    for step in now.saturating_sub(SKEW)..=now + SKEW {
        if crate::web::constant_time_eq(code_at(secret, step).as_bytes(), code.as_bytes()) {
            found = found.or(Some(step));
        }
    }
    found
}

/// `otpauth://` URI for QR enrollment.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        base32(secret),
        enc(issuer)
    )
}

/// A recovery code: 80 random bits as `xxxx-xxxx-xxxx-xxxx` in lowercase base32.
pub fn new_recovery_code() -> String {
    let mut b = [0u8; 10];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system RNG");
    let s = base32(&b).to_lowercase();
    format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
}

/// Canonical form of a typed recovery code (case, spaces and dashes ignored), or `None`
/// when it cannot be one.
pub fn normalize_recovery(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_lowercase();
    (s.len() == 16 && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B (SHA1, 8 digits).
        for (t, want) in [
            (59u64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ] {
            assert_eq!(hotp(RFC_SECRET, step_at(t), 8), want, "T={t}");
        }
        // Six digits is the same value truncated.
        assert_eq!(code_at(RFC_SECRET, step_at(59)), "287082");
        assert_eq!(code_at(RFC_SECRET, step_at(1111111109)), "081804");
    }

    #[test]
    fn base32_matches_rfc4648() {
        for (raw, want) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(raw.as_bytes()), want);
        }
        assert_eq!(base32(RFC_SECRET), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn window_is_one_step_either_side() {
        let s = new_secret();
        let now = 1_000_000;
        assert_eq!(matching_step(&s, &code_at(&s, now), now), Some(now));
        assert_eq!(matching_step(&s, &code_at(&s, now - 1), now), Some(now - 1));
        assert_eq!(matching_step(&s, &code_at(&s, now + 1), now), Some(now + 1));
        // Two steps away is refused unless it happens to collide with a code in the window.
        let far = code_at(&s, now + 2);
        let in_window = (now - 1..=now + 1).any(|t| code_at(&s, t) == far);
        assert_eq!(matching_step(&s, &far, now).is_some(), in_window);
    }

    #[test]
    fn codes_are_normalized_strictly() {
        assert_eq!(normalize_code(" 123 456 ").as_deref(), Some("123456"));
        assert_eq!(normalize_code("123-456").as_deref(), Some("123456"));
        assert_eq!(normalize_code("12345"), None);
        assert_eq!(normalize_code("1234567"), None);
        assert_eq!(normalize_code("12345a"), None);
        assert_eq!(normalize_code("１２３４５６"), None);
    }

    #[test]
    fn recovery_codes_round_trip() {
        let c = new_recovery_code();
        assert_eq!(c.len(), 19);
        let n = normalize_recovery(&c).unwrap();
        assert_eq!(
            normalize_recovery(&c.to_uppercase().replace('-', " ")),
            Some(n)
        );
        assert_ne!(new_recovery_code(), c);
        assert_eq!(normalize_recovery("123456"), None);
        assert_eq!(normalize_recovery("abcd-efgh-ijkl-mno1"), None);
    }

    #[test]
    fn otpauth_uri_escapes_labels() {
        let u = otpauth_uri("flyw8t", "a+b@example.com", RFC_SECRET);
        assert!(u.starts_with("otpauth://totp/flyw8t:a%2Bb%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=flyw8t"));
    }
}
