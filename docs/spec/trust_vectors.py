"""Reference encoder for docs/spec/trust-encoding.md, independent of the Rust one.

Prints the literal test vectors in crates/flyw8t-protocol/tests/vectors/trust.json. Run: python -I trust_vectors.py
Standard library only. Public keys are fixed constants (an Ed25519 key from the seed 01*32, and the P-256 base point);
signatures are not computed here.
"""
import hashlib, json, uuid

BYTES, TEXT, UINT, BOOL, UUID, HASH, TIME, DURATION, ENUM, NONE, SOME, LIST, RECORD = range(1, 14)
SIGNER, PARAMETER = 1, 2

def n8(n): return n.to_bytes(8, "big")
def by(b): return bytes([BYTES]) + n8(len(b)) + b
def tx(s): b = s.encode("utf-8"); return bytes([TEXT]) + n8(len(b)) + b
def ui(n): return bytes([UINT]) + n8(n)
def uu(u): return bytes([UUID]) + n8(16) + u.bytes
def ha(h): return bytes([HASH]) + n8(32) + h
def tm(n): return bytes([TIME]) + n8(n)
def du(n): return bytes([DURATION]) + n8(n)
def en(n): return bytes([ENUM, n])
def op(v): return bytes([NONE]) if v is None else bytes([SOME]) + v
def li(items):
    items = sorted(items)
    assert len(set(items)) == len(items)
    return bytes([LIST]) + n8(len(items)) + b"".join(items)
def rec(kind, fields): return bytes([RECORD, kind]) + n8(len(fields)) + b"".join(fields)
def sha(b): return hashlib.sha256(b).digest()

def key_id(kind, pk): return sha(tx("flyw8t key id v1") + en(kind) + by(pk))

ED = bytes.fromhex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")
G = bytes.fromhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
U = lambda n: uuid.UUID(int=n)
DEP = U(0x0d)
C3, ALL, ORGS, ROLE_SIGNER, ROLE_ROOT = 4, 1, 2, 1, 3

def signer(kind, pk, cred, person, name, may, scope_kind, orgs, role):
    return rec(SIGNER, [en(kind), by(pk), op(None if cred is None else by(cred)), uu(person), tx(name),
                        en(may), en(scope_kind), li([uu(o) for o in orgs]), en(role)])

genesis = (tx("flyw8t trust list v1") + uu(DEP) + ui(1) + op(None) + tx("rmm.example.com")
           + li([tx("https://rmm.example.com")]) + ui(1)
           + li([signer(2, ED, None, U(0x0a), "Root", C3, ALL, [], ROLE_ROOT),
                 signer(1, G, b"cred-1", U(0x0b), "Operator", C3, ORGS, [U(0x0e), U(0x0f)], ROLE_SIGNER)])
           + li([]) + li([]) + tm(1_800_000_000))

content = bytes.fromhex(open("crates/flyw8t-protocol/tests/vectors/content_hash.txt").read().strip())
root = key_id(2, ED)
approval = (tx("flyw8t revision approval v1") + uu(DEP) + uu(U(1)) + ui(1) + ha(content) + en(C3)
            + tx("powershell") + op(None) + tm(1_800_000_100) + ha(root))
commit = sha(tx("flyw8t run values v1") + by(bytes([0x22]) * 32)
             + li([rec(PARAMETER, [tx("Delay"), tx("30")]), rec(PARAMETER, [tx("Reason"), tx("ok")])]))
device = key_id(3, ED)
run = (tx("flyw8t run authorization v1") + uu(DEP) + uu(U(0x77)) + li([ha(device)]) + ha(content) + ha(commit)
       + du(600) + tm(1_800_000_200) + tm(1_800_001_100) + ha(root))

print(json.dumps({
    "key_id_offline": key_id(2, ED).hex(),
    "key_id_passkey": key_id(1, G).hex(),
    "key_id_device": device.hex(),
    "genesis_encoding": genesis.hex(),
    "genesis_hash": sha(genesis).hex(),
    "approval_encoding": approval.hex(),
    "approval_hash": sha(approval).hex(),
    "commitment": commit.hex(),
    "run_encoding": run.hex(),
    "run_hash": sha(run).hex(),
}, indent=2))
