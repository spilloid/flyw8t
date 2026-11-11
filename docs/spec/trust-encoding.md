# Trust statement encoding, version 1

This is the byte-level grammar of [ADR-0015](../decisions/ADR-0015-script-trust-and-running.md) section 4. Two encoders implement it: `flyw8t_protocol::trust::encode` in Rust, and [`trust_vectors.py`](trust_vectors.py), a standard-library Python script written separately from this text. CI checks that the Python output equals [`tests/vectors/trust.json`](../../crates/flyw8t-protocol/tests/vectors/trust.json), and the Rust tests check that Rust produces the same bytes.

Nothing in this file changes meaning once released. A new kind of value, record or statement gets a new number or a new domain.

## Values

Every value starts with a one-byte tag. Lengths and integers are 8 bytes, unsigned, big-endian.

| Tag | Value | Then |
|---|---|---|
| `01` | bytes | length, the bytes |
| `02` | text | length, the UTF-8 bytes |
| `03` | unsigned integer | 8 bytes |
| `04` | boolean | one byte, `00` or `01` |
| `05` | UUID | length (16), the 16 bytes in RFC 9562 order |
| `06` | SHA-256 hash | length (32), the 32 bytes |
| `07` | time | 8 bytes: whole seconds since the Unix epoch |
| `08` | duration | 8 bytes: whole seconds |
| `09` | enumeration | one byte (numbers below) |
| `0a` | absent optional value | nothing |
| `0b` | present optional value | the value |
| `0c` | list | count, then each item's encoding in ascending byte order. Two equal items are refused. |
| `0d` | record | one byte of kind, field count, then the fields in the order below |

There is one ordering rule for every list: sort the items' complete encodings as byte strings. Parameter lists follow it too.

## Enumerations

| Enumeration | Numbers |
|---|---|
| key kind | passkey `1`, offline `2`, device `3` |
| may approve up to | none `0`, C0 `1`, C1 `2`, C2 `3`, C3 `4` |
| risk class | C0 `1`, C1 `2`, C2 `3`, C3 `4` |
| scope kind | every organization `1`, listed organizations `2` |
| role | signer `1`, list admin `2`, root `3` |

## Records

**Signer** (kind `01`, 9 fields):

1. key kind (enumeration)
2. public key (bytes): Ed25519, 32 raw bytes; P-256, the 65-byte uncompressed SEC1 point `04 || x || y`
3. credential id (optional bytes): present for a passkey only
4. person id (UUID)
5. person name (text)
6. may approve up to (enumeration)
7. scope kind (enumeration)
8. organizations (list of UUID): empty when the scope is every organization
9. role (enumeration)

**Parameter** (kind `02`, 2 fields): name (text, as declared), value (text).

## Statements

A statement's hash is SHA-256 over its domain string, encoded as a text value, then its fields in order.

**Key id**, domain `flyw8t key id v1`: key kind, public key (bytes). A key is accepted in its canonical form only:
- **Ed25519:** a point of large order whose encoding is that point's only one.
- **P-256:** a point on the curve, uncompressed.

**Trust list**, domain `flyw8t trust list v1`:

1. deployment id (UUID)
2. version (integer). The first version is `1`.
3. previous version's hash (optional hash)
4. relying-party id (text)
5. allowed origins (list of text)
6. threshold (integer)
7. signers (list of Signer records)
8. removed keys (list of hash)
9. revoked revisions (list of hash)
10. made at (time)

**Revision approval**, domain `flyw8t revision approval v1`:

1. deployment id (UUID)
2. script id (UUID)
3. revision number (integer)
4. revision content hash (hash)
5. risk class (enumeration)
6. language (text)
7. script scope (optional UUID): absent for a global script
8. approved at (time)
9. signer key id (hash)

**Run authorization**, domain `flyw8t run authorization v1`:

1. deployment id (UUID)
2. job id (UUID)
3. device key ids (list of hash)
4. revision content hash (hash)
5. parameter commitment (hash)
6. timeout (duration)
7. issued at (time)
8. expires at (time)
9. signer key id (hash)

**Parameter commitment**, domain `flyw8t run values v1`:

1. salt (bytes, 32)
2. every declared parameter (list of Parameter records)

**Revision content hash.** This one is unchanged from ADR-0014 build step 2 and does not use the grammar above. It is SHA-256 over the ASCII bytes `flyw8t script revision v1` and a NUL. Then come five parts, each written as an 8-byte length followed by its bytes:
1. the script UUID's 16 bytes
2. the language
3. the risk class as text (`C0` to `C3`)
4. the parameter declarations
5. the source

## Signatures

- **Offline:** Ed25519 over the ASCII bytes `flyw8t offline signature v1`, a NUL, then the 32-byte statement hash. The signature is 64 bytes and is verified strictly: non-canonical signatures and small-order keys are refused.
- **Passkey:** a WebAuthn assertion. Its `clientDataJSON` challenge is the base64url of the 32-byte statement hash.

## JSON transport

JSON only carries values. What is signed is always re-encoded from the parsed values. Every object refuses unknown fields and duplicate fields.

- Hashes and key ids are written `sha256:` followed by 64 lower-case hex digits.
- Bytes are unpadded base64url, and only the canonical spelling is accepted.
