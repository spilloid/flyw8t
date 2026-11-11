//! The statement encoding (ADR-0015 section 4; the grammar is `docs/spec/trust-encoding.md`).
//!
//! Typed and length-prefixed: every value starts with a one-byte tag, so a value of one type can never be read as
//! another, and every variable-length value carries its length, so no boundary can shift. Lists are sorted by their
//! encoded bytes and may not hold the same item twice, so a list has exactly one encoding.

use ring::digest::{digest, SHA256};

/// Value tags. Never renumbered: a new kind of value gets a new number.
pub mod tag {
    pub const BYTES: u8 = 0x01;
    pub const TEXT: u8 = 0x02;
    pub const UINT: u8 = 0x03;
    pub const BOOL: u8 = 0x04;
    pub const UUID: u8 = 0x05;
    pub const HASH: u8 = 0x06;
    pub const TIME: u8 = 0x07;
    pub const DURATION: u8 = 0x08;
    pub const ENUM: u8 = 0x09;
    pub const NONE: u8 = 0x0a;
    pub const SOME: u8 = 0x0b;
    pub const LIST: u8 = 0x0c;
    pub const RECORD: u8 = 0x0d;
}

/// Record kinds, after [`tag::RECORD`].
pub mod record {
    pub const SIGNER: u8 = 0x01;
    pub const PARAMETER: u8 = 0x02;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("a list holds the same item twice")]
    DuplicateInList,
}

/// Builds the bytes of one statement, or of one value inside one.
#[derive(Debug, Default, Clone)]
pub struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    pub fn new() -> Self {
        Self::default()
    }

    /// A statement: its domain string first, as a text value.
    pub fn statement(domain: &str) -> Self {
        let mut e = Self::new();
        e.text(domain);
        e
    }

    fn len(&mut self, n: usize) {
        self.buf.extend_from_slice(&(n as u64).to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.push(tag::BYTES);
        self.len(b.len());
        self.buf.extend_from_slice(b);
        self
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.buf.push(tag::TEXT);
        self.len(s.len());
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    pub fn uint(&mut self, n: u64) -> &mut Self {
        self.buf.push(tag::UINT);
        self.buf.extend_from_slice(&n.to_be_bytes());
        self
    }

    pub fn boolean(&mut self, b: bool) -> &mut Self {
        self.buf.push(tag::BOOL);
        self.buf.push(b as u8);
        self
    }

    pub fn uuid(&mut self, u: &uuid::Uuid) -> &mut Self {
        self.buf.push(tag::UUID);
        self.len(16);
        self.buf.extend_from_slice(u.as_bytes());
        self
    }

    pub fn hash(&mut self, h: &[u8; 32]) -> &mut Self {
        self.buf.push(tag::HASH);
        self.len(32);
        self.buf.extend_from_slice(h);
        self
    }

    /// Whole seconds since the Unix epoch.
    pub fn time(&mut self, secs: u64) -> &mut Self {
        self.buf.push(tag::TIME);
        self.buf.extend_from_slice(&secs.to_be_bytes());
        self
    }

    /// Whole seconds.
    pub fn duration(&mut self, secs: u64) -> &mut Self {
        self.buf.push(tag::DURATION);
        self.buf.extend_from_slice(&secs.to_be_bytes());
        self
    }

    pub fn enumeration(&mut self, n: u8) -> &mut Self {
        self.buf.push(tag::ENUM);
        self.buf.push(n);
        self
    }

    /// An optional value: absent, or present and encoded by `f`.
    pub fn option<T>(&mut self, v: Option<T>, f: impl FnOnce(&mut Self, T)) -> &mut Self {
        match v {
            None => self.buf.push(tag::NONE),
            Some(v) => {
                self.buf.push(tag::SOME);
                f(self, v);
            }
        }
        self
    }

    /// A list: the count, then each item's encoding in ascending byte order. The same item twice is refused.
    pub fn list<T>(
        &mut self,
        items: impl IntoIterator<Item = T>,
        mut f: impl FnMut(&mut Self, T),
    ) -> Result<&mut Self, EncodeError> {
        let mut encoded: Vec<Vec<u8>> = items
            .into_iter()
            .map(|item| {
                let mut e = Enc::new();
                f(&mut e, item);
                e.buf
            })
            .collect();
        encoded.sort();
        if encoded.windows(2).any(|w| w[0] == w[1]) {
            return Err(EncodeError::DuplicateInList);
        }
        self.buf.push(tag::LIST);
        self.len(encoded.len());
        for item in encoded {
            self.buf.extend_from_slice(&item);
        }
        Ok(self)
    }

    /// A record: its kind, its field count, then the fields `f` writes, in their fixed order.
    pub fn record(&mut self, kind: u8, fields: u64, f: impl FnOnce(&mut Self)) -> &mut Self {
        self.buf.push(tag::RECORD);
        self.buf.push(kind);
        self.buf.extend_from_slice(&fields.to_be_bytes());
        f(self);
        self
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// SHA-256 of everything written.
    pub fn hash32(&self) -> [u8; 32] {
        sha256(&self.buf)
    }
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    digest(&SHA256, b)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_value_is_tagged_and_sized() {
        let mut e = Enc::statement("d");
        e.uint(1).boolean(true).text("hé");
        assert_eq!(
            hex::encode(e.as_bytes()),
            concat!(
                "02",
                "0000000000000001",
                "64", // text "d"
                "03",
                "0000000000000001", // uint 1
                "04",
                "01", // true
                "02",
                "0000000000000003",
                "68c3a9", // text "hé" (UTF-8)
            )
        );
    }

    #[test]
    fn lists_sort_and_refuse_duplicates() {
        let mut a = Enc::new();
        a.list([3u64, 1, 2], |e, n| {
            e.uint(n);
        })
        .unwrap();
        let mut b = Enc::new();
        b.list([1u64, 2, 3], |e, n| {
            e.uint(n);
        })
        .unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(
            Enc::new()
                .list([1u64, 1], |e, n| {
                    e.uint(n);
                })
                .err(),
            Some(EncodeError::DuplicateInList)
        );
    }

    #[test]
    fn a_value_cannot_pass_for_another_type_or_shift_a_boundary() {
        let enc = |f: &dyn Fn(&mut Enc)| {
            let mut e = Enc::new();
            f(&mut e);
            e.into_bytes()
        };
        assert_ne!(
            enc(&|e| {
                e.text("ab");
            }),
            enc(&|e| {
                e.bytes(b"ab");
            })
        );
        assert_ne!(
            enc(&|e| {
                e.time(5);
            }),
            enc(&|e| {
                e.uint(5);
            })
        );
        assert_ne!(
            enc(&|e| {
                e.duration(5);
            }),
            enc(&|e| {
                e.time(5);
            })
        );
        assert_ne!(
            enc(&|e| {
                e.text("ab").text("c");
            }),
            enc(&|e| {
                e.text("a").text("bc");
            })
        );
        assert_ne!(
            enc(&|e| {
                e.option(None::<u64>, |e, n| {
                    e.uint(n);
                });
            }),
            enc(&|e| {
                e.option(Some(0u64), |e, n| {
                    e.uint(n);
                });
            })
        );
    }
}
