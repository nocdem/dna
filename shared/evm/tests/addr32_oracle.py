#!/usr/bin/env python3
"""
addr32_oracle.py — independent oracle for tests/test_addr32.c (Nodus EVM 32-byte
address mode, design docs/plans/2026-10-04-nodus-evm-engine-design.md §2).

Writes tests/addr32_vectors.h: the 32-byte account addresses the test uses,
the init code it deploys, and the EXPECTED contract addresses

    CREATE  : keccak256(rlp([sender_32B, nonce]))                  all 32 B
    CREATE2 : keccak256(0xff || sender_32B || salt || keccak256(initcode))

computed here WITHOUT any code from the engine or from shared/crypto:
Keccak-f[1600] is implemented below from its FIPS 202 definition (rho
offsets and iota round constants are DERIVED by the FIPS 202 algorithms
3.2.2 / 5 (rc), not tabulated), Keccak-256 = the original Keccak padding
(0x01 .. 0x80, rate 136), RLP from the Ethereum yellow paper appendix B.

Before anything is emitted the oracle asserts its own primitives:
  - keccak256("")    = c5d24601...5d85a470   (dispatch-given vector)
  - keccak256("abc") = 4e03657a...12d6c45    (dispatch-given vector)
  - RLP: 0 -> 80, "dog" -> 83646f67, ["cat","dog"] -> c88363617483646f67,
    1024 -> 820400 (yellow paper appendix B examples)
  - EIP-1014 example 0 (20-byte form): sender 0x00..00, salt 0, initcode
    0x00 -> 0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38 — recalled, not read
    from a file in this tree; it can only make the oracle REFUSE to emit,
    never change an emitted value.
Any failure exits non-zero and writes nothing.

Deterministic: fixed constants, no randomness, no timestamps.
Usage: python3 tests/addr32_oracle.py <out.h>
"""

import sys

# ── Keccak-f[1600] (FIPS 202 §3) ────────────────────────────────────────

MASK = (1 << 64) - 1


def _rot(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK if n else v


def _rc_bit(t):
    """FIPS 202 Algorithm 5: rc(t)."""
    if t % 255 == 0:
        return 1
    r = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(1, t % 255 + 1):
        r = [0] + r
        r[0] ^= r[8]
        r[4] ^= r[8]
        r[5] ^= r[8]
        r[6] ^= r[8]
        r = r[:8]
    return r[0]


def _round_constants():
    out = []
    for ir in range(24):
        rc = 0
        for j in range(7):
            if _rc_bit(j + 7 * ir):
                rc |= 1 << ((1 << j) - 1)
        out.append(rc)
    return out


def _rho_offsets():
    """FIPS 202 Algorithm 2 (rho): offsets[x][y]."""
    off = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        off[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return off


RC = _round_constants()
RHO = _rho_offsets()


def keccak_f(a):
    """a: 5x5 list of 64-bit lanes, a[x][y]."""
    for ir in range(24):
        # theta
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        # rho + pi: B[y][2x+3y] = rot(A[x][y], r[x][y])
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rot(a[x][y], RHO[x][y])
        # chi
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y] & MASK) & b[(x + 2) % 5][y])
              for y in range(5)] for x in range(5)]
        # iota
        a[0][0] ^= RC[ir]
    return a


def keccak256(data):
    rate = 136
    msg = bytearray(data)
    pad = rate - (len(msg) % rate)
    if pad == 1:
        msg += b"\x81"
    else:
        msg += b"\x01" + b"\x00" * (pad - 2) + b"\x80"
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[8 * i:8 * i + 8], "little")
            x, y = i % 5, i // 5
            a[x][y] ^= lane
        a = keccak_f(a)
    out = b""
    for i in range(4):                       # 32 bytes < rate: one squeeze
        x, y = i % 5, i // 5
        out += a[x][y].to_bytes(8, "little")
    return out


# ── RLP (yellow paper appendix B) ───────────────────────────────────────

def _be_len(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def rlp_bytes(b):
    if len(b) == 1 and b[0] < 0x80:
        return bytes(b)
    if len(b) < 56:
        return bytes([0x80 + len(b)]) + b
    ln = _be_len(len(b))
    return bytes([0xb7 + len(ln)]) + ln + b


def rlp_uint(n):
    return rlp_bytes(_be_len(n) if n else b"")


def rlp_list(items):
    payload = b"".join(items)
    if len(payload) < 56:
        return bytes([0xc0 + len(payload)]) + payload
    ln = _be_len(len(payload))
    return bytes([0xf7 + len(ln)]) + ln + payload


# ── address formulas (design §2) ────────────────────────────────────────

def create_addr32(sender32, nonce):
    assert len(sender32) == 32
    return keccak256(rlp_list([rlp_bytes(sender32), rlp_uint(nonce)]))


def create2_addr32(sender32, salt32, initcode):
    assert len(sender32) == 32 and len(salt32) == 32
    return keccak256(b"\xff" + sender32 + salt32 + keccak256(initcode))


def create2_addr20(sender20, salt32, initcode):
    return keccak256(b"\xff" + sender20 + salt32 + keccak256(initcode))[12:]


# ── self-checks (refuse to emit on any failure) ─────────────────────────

def self_check():
    h = bytes.fromhex
    assert keccak256(b"") == h(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), \
        "keccak256('')"
    assert keccak256(b"abc") == h(
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"), \
        "keccak256('abc')"
    assert rlp_uint(0) == h("80"), "rlp(0)"
    assert rlp_bytes(b"dog") == h("83646f67"), "rlp('dog')"
    assert rlp_list([rlp_bytes(b"cat"), rlp_bytes(b"dog")]) == \
        h("c88363617483646f67"), "rlp(['cat','dog'])"
    assert rlp_uint(1024) == h("820400"), "rlp(1024)"
    assert create2_addr20(b"\x00" * 20, b"\x00" * 32, b"\x00") == \
        h("4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"), "EIP-1014 example 0"


# ── the scenario constants (shared with test_addr32.c via the header) ───

def mk(hi, lo):
    """32-byte address: 12 bytes `hi`, then 20 bytes `lo`."""
    return bytes([hi]) * 12 + bytes([lo]) * 20


ADDRS = [
    # name, value, comment
    ("SENDER",      mk(0xE0, 0x5E), "tx origin (EOA)"),
    ("COINBASE",    mk(0xC0, 0xCB), "block coinbase"),
    ("ENV_OUTER",   mk(0xB0, 0x9B), "check 1: tx target, CALLs ENV_INNER"),
    ("ENV_INNER",   mk(0xB1, 0x1C), "check 1: stores ADDRESS/CALLER/ORIGIN/COINBASE"),
    ("TWIN_DRIVER", mk(0xB2, 0x2D), "check 2: probes every twin pair"),
    ("X_HI",        mk(0x11, 0x41), "check 2 CALL/BALANCE/EXTCODE*: twin A"),
    ("X_LO",        mk(0x22, 0x41), "check 2 CALL/BALANCE/EXTCODE*: twin B"),
    ("X_PROJ",      mk(0x00, 0x41), "check 2: 20-byte projection, ABSENT"),
    ("Y_HI",        mk(0x11, 0x42), "check 2 STATICCALL twin A"),
    ("Y_LO",        mk(0x22, 0x42), "check 2 STATICCALL twin B"),
    ("Z_HI",        mk(0x11, 0x43), "check 2 DELEGATECALL twin A"),
    ("Z_LO",        mk(0x22, 0x43), "check 2 DELEGATECALL twin B"),
    ("W_HI",        mk(0x11, 0x44), "check 2 CALLCODE twin A"),
    ("W_LO",        mk(0x22, 0x44), "check 2 CALLCODE twin B"),
    ("SD",          mk(0xD0, 0xD5), "check 2: pre-existing contract that SELFDESTRUCTs"),
    ("S_HI",        mk(0x11, 0x45), "check 2 SELFDESTRUCT beneficiary"),
    ("S_LO",        mk(0x22, 0x45), "check 2 SELFDESTRUCT twin of the beneficiary"),
    ("S_PROJ",      mk(0x00, 0x45), "check 2: 20-byte projection, ABSENT"),
    ("FACTORY",     mk(0xF0, 0xFA), "check 3: CREATE x2 + CREATE2, nonce 0x7f"),
    ("PC_DRIVER",   mk(0xB3, 0x3E), "check 4: calls real and fake precompiles"),
    ("FAKE01",      bytes([0xFF]) * 12 + bytes(19) + b"\x01",
                                    "check 4: high bytes set, low 20 = 0x..01"),
    ("FAKE04",      bytes([0xFF]) * 12 + bytes(19) + b"\x04",
                                    "check 4: high bytes set, low 20 = 0x..04"),
    ("CREATOR0",    mk(0xCE, 0x50), "check 5: create-tx sender, nonce 0"),
    ("CREATOR1",    mk(0xCE, 0x51), "check 5: create-tx sender, nonce 0x0100"),
    ("CREATOR_EF",  mk(0xCE, 0x52), "check 6: create-tx sender, 0xEF init code"),
    ("EF_FACTORY",  mk(0xF1, 0xFB), "check 6: nested CREATE of 0xEF code, nonce 1"),
    ("DELEGATED",   mk(0xE7, 0x77), "check 6: code = 0xef0100 || DEL_TARGET20"),
    ("DEL_TARGET",  mk(0x00, 0x78), "check 6: 12 zero bytes || DEL_TARGET20"),
    ("DEL_DECOY",   mk(0x99, 0x78), "check 6: non-zero high || DEL_TARGET20"),
    ("DEL_DRIVER",  mk(0xB4, 0x4F), "check 6: CALLs DELEGATED"),
]

NONCES = {
    "FACTORY": 0x7F,       # CREATE #1 uses 0x7f (single byte), #2 0x80 (81 80)
    "CREATOR0": 0,         # rlp(0) = 0x80
    "CREATOR1": 0x0100,    # two-byte nonce: 82 01 00
    "CREATOR_EF": 0,
    "EF_FACTORY": 1,
}

# deploys the one-byte runtime 0x2a: MSTORE8(0, 0x2a); RETURN(0, 1)
INITCODE = bytes.fromhex("602a60005360016000f3")
# same shape, deploys 0xEF (EIP-3541 must refuse it)
INITCODE_EF = bytes.fromhex("60ef60005360016000f3")
SALT = bytes.fromhex(
    "5a17000000000000000000000000000000000000000000000000000000c0ffee")


def c_array(name, data, comment=None):
    lines = []
    if comment:
        lines.append("/* %s */" % comment)
    lines.append("static const uint8_t %s[%d] = {" % (name, len(data)))
    for i in range(0, len(data), 12):
        chunk = ", ".join("0x%02x" % b for b in data[i:i + 12])
        lines.append("    " + chunk + ("," if i + 12 < len(data) else ""))
    lines.append("};")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: addr32_oracle.py <out.h>\n")
        return 2
    self_check()

    a = {n: v for n, v, _ in ADDRS}
    for n, v, _ in ADDRS:
        assert len(v) == 32, n
    assert len(set(a.values())) == len(a), "address constants not unique"

    exp = [
        ("EXP_CREATE_FACTORY_N7F", create_addr32(a["FACTORY"], 0x7F),
         "CREATE by FACTORY at nonce 0x7f"),
        ("EXP_CREATE_FACTORY_N80", create_addr32(a["FACTORY"], 0x80),
         "CREATE by FACTORY at nonce 0x80"),
        ("EXP_CREATE2_FACTORY", create2_addr32(a["FACTORY"], SALT, INITCODE),
         "CREATE2 by FACTORY, SALT, INITCODE"),
        ("EXP_TXCREATE_CREATOR0", create_addr32(a["CREATOR0"], 0),
         "create tx by CREATOR0 at nonce 0"),
        ("EXP_TXCREATE_CREATOR1", create_addr32(a["CREATOR1"], 0x0100),
         "create tx by CREATOR1 at nonce 0x0100"),
        ("EXP_TXCREATE_CREATOR_EF", create_addr32(a["CREATOR_EF"], 0),
         "create tx by CREATOR_EF at nonce 0 (refused code)"),
        ("EXP_CREATE_EF_FACTORY_N1", create_addr32(a["EF_FACTORY"], 1),
         "nested CREATE by EF_FACTORY at nonce 1 (refused code)"),
    ]
    for n, v, _ in exp:
        assert len(v) == 32 and any(v[:12]), n   # high 12 bytes must be used

    out = []
    out.append("/* GENERATED by tests/addr32_oracle.py — do not edit.")
    out.append(" * Regenerate: make -C shared/evm addr32-vectors")
    out.append(" * Keccak-256 / RLP implemented independently in the oracle")
    out.append(" * (no engine or shared/crypto code). */")
    out.append("#ifndef EVM_ADDR32_VECTORS_H")
    out.append("#define EVM_ADDR32_VECTORS_H")
    out.append("")
    out.append("#include <stdint.h>")
    out.append("")
    for n, v, c in ADDRS:
        out.append(c_array("ADDR32_" + n, v, c))
    out.append("")
    for n in sorted(NONCES):
        out.append("#define ADDR32_NONCE_%s 0x%xu" % (n, NONCES[n]))
    out.append("")
    out.append(c_array("ADDR32_INITCODE", INITCODE,
                       "MSTORE8(0,0x2a); RETURN(0,1) -> runtime 0x2a"))
    out.append(c_array("ADDR32_INITCODE_EF", INITCODE_EF,
                       "MSTORE8(0,0xef); RETURN(0,1) -> runtime 0xef"))
    out.append(c_array("ADDR32_SALT", SALT, "CREATE2 salt"))
    out.append("")
    for n, v, c in exp:
        out.append(c_array("ADDR32_" + n, v, c))
    out.append("")
    out.append("#endif /* EVM_ADDR32_VECTORS_H */")
    text = "\n".join(out) + "\n"
    with open(sys.argv[1], "w", newline="\n") as f:
        f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
