#!/usr/bin/env python3
"""
LEDGER V2 — INDEPENDENT ORACLE for the generic typed-effect result wire
(effect_wire.{h,c}) and the effect value-hash helper.

PROVENANCE: written by the ORCHESTRATOR directly from the approved
typed-effect season specification (offsets, field order, tag literals,
caps, legality matrix, canonical-order comparator), NOT by reading or
transcribing the C implementation. It shares no code with the C.
Hash primitive: python3 hashlib.sha3_512 (stdlib, FIPS-202).

Run:  python3 effect_wire_oracle.py
The emitted C arrays are pinned verbatim in tests/test_effect_wire.c.

── SPEC (frozen) ────────────────────────────────────────────────────────
Family tag "DNA.EFFRES.v1" (13 chars, zero-padded to 16).
Fixed head (23 bytes):
  off  0  family[16]
  off 16  result_version  u8  (= 1)
  off 17  effect_count    u16 BE   (0 .. 64 inclusive; 0 = empty result)
  off 19  reserved        u32 BE   MUST be 0
Per-effect record (84 bytes), record i at 23 + 84*i:
  +0   op_id             u32 BE   adapter operation identifier
  +4   effect_kind       u8       CREATE(1) | SET(2) | DELETE(3); 0 invalid
  +5   precond_tag       u8       ABSENT(1) | EXISTS(2) | EXISTS_VERSION(3)
                                  | EXISTS_VHASH(4); 0 invalid
  +6   expected_version  u64 BE   MUST be 0 unless precond_tag == 3
  +14  expected_vhash    [64]     MUST be all-zero unless precond_tag == 4
  +78  key_len           u16 BE   1 .. 128
  +80  value_len         u32 BE   0 .. 8192; MUST be 0 when kind == DELETE
Then ALL key blobs in record order, then ALL value blobs in record order.
Total encoded length <= 65536 (inclusive); exact consumption.
Kind/precondition legality: CREATE <=> ABSENT; SET/DELETE require one of
EXISTS / EXISTS_VERSION / EXISTS_VHASH.
Canonical order: records STRICTLY ascending by (effect_kind, op_id, key)
where keys compare lexicographically (memcmp over the common prefix, then
shorter < longer). Full triple equality is a duplicate. Additionally the
LOGICAL key (op_id, key bytes) must be unique across the WHOLE result
regardless of kind.
Value hash: SHA3-512("DNA.EFFVAL.v1"(16) || value_len u32 BE || value).
"""
import hashlib
import struct

# ── constants (spec) ────────────────────────────────────────────────────
FAMILY        = b"DNA.EFFRES.v1".ljust(16, b"\0")
TAG_VALHASH   = b"DNA.EFFVAL.v1".ljust(16, b"\0")

RESULT_VERSION   = 1
FIXED_HEAD       = 23
RECORD_LEN       = 84
MAX_COUNT        = 64
MAX_KEY_LEN      = 128
MAX_VALUE_LEN    = 8192
MAX_TOTAL_LEN    = 65536

K_CREATE, K_SET, K_DELETE = 1, 2, 3
P_ABSENT, P_EXISTS, P_EXISTS_VERSION, P_EXISTS_VHASH = 1, 2, 3, 4

assert len(FAMILY) == 16 and len(TAG_VALHASH) == 16

def be8(v):  return struct.pack(">B", v)
def be16(v): return struct.pack(">H", v)
def be32(v): return struct.pack(">I", v)
def be64(v): return struct.pack(">Q", v)
def sha3(b): return hashlib.sha3_512(b).digest()


def value_hash(value):
    assert len(value) <= MAX_VALUE_LEN
    return sha3(TAG_VALHASH + be32(len(value)) + value)


class Effect:
    def __init__(self, op_id, kind, precond, key, value,
                 expected_version=0, expected_vhash=b"\0" * 64):
        self.op_id = op_id
        self.kind = kind
        self.precond = precond
        self.key = key
        self.value = value
        self.expected_version = expected_version
        self.expected_vhash = expected_vhash

    def record_bytes(self):
        b = (be32(self.op_id) + be8(self.kind) + be8(self.precond) +
             be64(self.expected_version) + self.expected_vhash +
             be16(len(self.key)) + be32(len(self.value)))
        assert len(b) == RECORD_LEN, len(b)
        return b


def key_cmp(a, b):
    """Spec comparator: memcmp over common prefix, then shorter < longer."""
    n = min(len(a), len(b))
    if a[:n] != b[:n]:
        return -1 if a[:n] < b[:n] else 1
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0


def effect_cmp(x, y):
    if x.kind != y.kind:
        return -1 if x.kind < y.kind else 1
    if x.op_id != y.op_id:
        return -1 if x.op_id < y.op_id else 1
    return key_cmp(x.key, y.key)


def validate(effects):
    """The full structural predicate a decoder must enforce. True/False."""
    if len(effects) > MAX_COUNT:
        return False
    total = FIXED_HEAD + RECORD_LEN * len(effects)
    for e in effects:
        if e.kind not in (K_CREATE, K_SET, K_DELETE):
            return False
        if e.precond not in (P_ABSENT, P_EXISTS, P_EXISTS_VERSION,
                             P_EXISTS_VHASH):
            return False
        if (e.kind == K_CREATE) != (e.precond == P_ABSENT):
            return False                      # CREATE <=> ABSENT
        if e.precond != P_EXISTS_VERSION and e.expected_version != 0:
            return False
        if e.precond != P_EXISTS_VHASH and e.expected_vhash != b"\0" * 64:
            return False
        if not (1 <= len(e.key) <= MAX_KEY_LEN):
            return False
        if len(e.value) > MAX_VALUE_LEN:
            return False
        if e.kind == K_DELETE and len(e.value) != 0:
            return False
        total += len(e.key) + len(e.value)
    if total > MAX_TOTAL_LEN:
        return False
    for i in range(1, len(effects)):
        if effect_cmp(effects[i - 1], effects[i]) >= 0:
            return False                      # strict canonical order
    for i in range(len(effects)):             # logical-key uniqueness,
        for j in range(i + 1, len(effects)):  # regardless of kind
            if (effects[i].op_id == effects[j].op_id and
                    effects[i].key == effects[j].key):
                return False
    return True


def encode(effects):
    assert validate(effects)
    out = FAMILY + be8(RESULT_VERSION) + be16(len(effects)) + be32(0)
    assert len(out) == FIXED_HEAD
    for e in effects:
        out += e.record_bytes()
    for e in effects:
        out += e.key
    for e in effects:
        out += e.value
    assert len(out) <= MAX_TOTAL_LEN
    return out


def c_array(name, data):
    body = ",".join("0x%02x" % b for b in data)
    return "static const uint8_t %s[%d] = {%s};" % (name, len(data), body)


def main():
    # ── KAT1: the empty result (count 0) — exactly the 23-byte head ─────
    empty = encode([])
    assert len(empty) == FIXED_HEAD

    # ── KAT2: one CREATE effect ─────────────────────────────────────────
    e_single = Effect(7, K_CREATE, P_ABSENT,
                      bytes.fromhex("0102030405060708"),
                      bytes.fromhex("a0a1a2a3"))
    single = encode([e_single])
    assert len(single) == FIXED_HEAD + RECORD_LEN + 8 + 4   # 119

    # ── KAT3: five effects — every kind, every precondition tag ─────────
    old_val = bytes.fromhex("eeef")
    e0 = Effect(1, K_CREATE, P_ABSENT, bytes.fromhex("10"),
                bytes.fromhex("c0c1"))
    e1 = Effect(2, K_CREATE, P_ABSENT, bytes.fromhex("1112131415161718"),
                bytes.fromhex("c2c3c4c5"))
    e2 = Effect(1, K_SET, P_EXISTS_VERSION, bytes.fromhex("2021"),
                bytes.fromhex("d0d1d2"), expected_version=5)
    e3 = Effect(1, K_SET, P_EXISTS_VHASH, bytes.fromhex("202122"),
                bytes.fromhex("d3"), expected_vhash=value_hash(old_val))
    e4 = Effect(3, K_DELETE, P_EXISTS, bytes(range(64)), b"")
    multi_effects = [e0, e1, e2, e3, e4]
    multi = encode(multi_effects)
    assert len(multi) == FIXED_HEAD + 5 * RECORD_LEN + (1 + 8 + 2 + 3 + 64) \
        + (2 + 4 + 3 + 1 + 0)                                # 531

    # ── value-hash KATs ─────────────────────────────────────────────────
    h_empty = value_hash(b"")
    h_v1 = value_hash(bytes.fromhex("a0a1a2a3"))
    h_old = value_hash(old_val)

    print("/* ORACLE: python3 hashlib.sha3_512 — effect_wire_oracle.py */")
    print(c_array("K_EFF_EMPTY", empty))
    print(c_array("K_EFF_SINGLE", single))
    print(c_array("K_EFF_MULTI", multi))
    print(c_array("K_VH_EMPTY", h_empty))
    print(c_array("K_VH_A0A1A2A3", h_v1))
    print(c_array("K_VH_EEEF", h_old))

    # ── oracle self-checks (spec properties, asserted independently) ────
    # comparator: prefix-shorter sorts first; e2 < e3 by that rule alone
    assert effect_cmp(e2, e3) < 0 and e2.key == e3.key[:2]
    # order inversion rejects
    assert not validate([e1, e0])
    # kind-order inversion rejects
    assert not validate([e4, e0])
    assert not validate([e2, e0])
    # duplicate same kind/key rejects
    assert not validate([e0, e0])
    # duplicate LOGICAL key across different kinds rejects: (op 1, key 10)
    dup_cross = Effect(1, K_SET, P_EXISTS, bytes.fromhex("10"), b"\xff")
    assert not validate([e0, dup_cross])
    # CREATE with a non-ABSENT precondition rejects, and vice versa
    assert not validate([Effect(1, K_CREATE, P_EXISTS, b"\x01", b"")])
    assert not validate([Effect(1, K_SET, P_ABSENT, b"\x01", b"")])
    # expected_version outside tag 3 rejects; expected_vhash outside 4 too
    assert not validate([Effect(1, K_SET, P_EXISTS, b"\x01", b"",
                                expected_version=1)])
    assert not validate([Effect(1, K_SET, P_EXISTS, b"\x01", b"",
                                expected_vhash=b"\x01" + b"\0" * 63)])
    # DELETE with a value rejects
    assert not validate([Effect(1, K_DELETE, P_EXISTS, b"\x01", b"\x00")])
    # key bounds: 0 rejects, 128 accepts, 129 rejects
    assert not validate([Effect(1, K_CREATE, P_ABSENT, b"", b"")])
    assert validate([Effect(1, K_CREATE, P_ABSENT, b"\x01" * 128, b"")])
    assert not validate([Effect(1, K_CREATE, P_ABSENT, b"\x01" * 129, b"")])
    # value bounds: 8192 accepts, 8193 rejects
    assert validate([Effect(1, K_CREATE, P_ABSENT, b"\x01", b"\x02" * 8192)])
    assert not validate([Effect(1, K_CREATE, P_ABSENT, b"\x01",
                               b"\x02" * 8193)])
    # count bounds: 64 accepts, 65 rejects (distinct ascending keys)
    many = [Effect(1, K_CREATE, P_ABSENT, bytes([0x40, i]), b"")
            for i in range(65)]
    assert validate(many[:64]) and not validate(many)
    # exact total cap: build a result of exactly 65536 bytes, then +1 over
    # 8 effects, 1-byte keys, 7 values of 8192 + one tuned remainder
    base = FIXED_HEAD + 8 * RECORD_LEN + 8       # head + records + keys
    rem = MAX_TOTAL_LEN - base - 7 * MAX_VALUE_LEN
    assert 0 <= rem <= MAX_VALUE_LEN
    exact = [Effect(1, K_CREATE, P_ABSENT, bytes([i + 1]),
                    b"\x5a" * (MAX_VALUE_LEN if i < 7 else rem))
             for i in range(8)]
    assert validate(exact) and len(encode(exact)) == MAX_TOTAL_LEN
    over = [Effect(1, K_CREATE, P_ABSENT, bytes([i + 1]),
                   b"\x5a" * (MAX_VALUE_LEN if i < 7 else rem + 1))
            for i in range(8)]
    assert not validate(over)
    print("/* oracle self-check: legality, order, dup, bounds — OK */")


if __name__ == "__main__":
    main()
