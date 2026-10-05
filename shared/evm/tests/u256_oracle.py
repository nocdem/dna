#!/usr/bin/env python3
"""
u256_oracle.py — test-vector GENERATOR for shared/evm/evm_u256.c.

Writes shared/evm/tests/u256_vectors.h (next to this script). It is a
generator, not a test: run it once, commit its output, and the C test
(test_u256.c) checks the C implementation against every vector.

Semantics are implemented here INDEPENDENTLY of the C code, with Python big
integers, from the pinned reference ethereum/execution-specs @a87891f7,
src/ethereum/forks/prague/vm/instructions/:
  arithmetic.py  add sub mul div sdiv mod smod addmod mulmod exp signextend
  bitwise.py     bitwise_and bitwise_or bitwise_xor bitwise_not get_byte
                 bitwise_shl bitwise_shr bitwise_sar
  comparison.py  less_than signed_less_than (cmp / scmp ordering)
plus src/ethereum/utils/numeric.py get_sign. Values are taken mod 2**256,
signed values are two's complement (U256.to_signed / U256.from_signed).

Determinism: the only randomness is random.Random(20261004); the output
carries no timestamp, path or environment string, so regenerating gives a
byte-identical file.

Vector fields (all lowercase minimal hex without 0x, "" = unused):
  op   U256_OP_* (enum emitted into the header)
  a, b first / second operand (the EVM stack order: a is popped first)
  c    third operand for ADDMOD/MULMOD (the modulus);
       for ADD / SUB: the expected carry / borrow out ("0" / "1");
       for TOU64: "1" if a < 2^64 else "0"
  x    expected result; for CMP / SCMP the result -1/0/1 is encoded as
       (-1/0/1) mod 2^256; for BITLEN the bit length; for ISZERO 0/1;
       for TOU64 the value when it fits, else "0".

Coverage diagnostic (stdout only, not in the header): the number of
divisions that take the Knuth algorithm D add-back step (D6), computed by a
32-bit-digit model of algorithm D. It shows the vectors reach that rare
branch; the expected values themselves come from Python's exact // and %.
"""

import os
import random
import sys

M = 2 ** 256
MAX = M - 1
H = 2 ** 255
SEED = 20261004
RANDOM_PER_OP = 4000
RANDOM_PER_UNARY = 1000

# ── reference semantics (independent of the C code) ──────────────────────


def to_signed(x):
    return x - M if x >= H else x


def from_signed(v):
    return v % M


def get_sign(v):
    return (v > 0) - (v < 0)


def op_add(a, b):
    return (a + b) % M


def op_sub(a, b):
    return (a - b) % M


def op_mul(a, b):
    return (a * b) % M


def op_div(a, b):
    return 0 if b == 0 else a // b


def op_mod(a, b):
    return 0 if b == 0 else a % b


def op_sdiv(a, b):
    x, y = to_signed(a), to_signed(b)
    if y == 0:
        q = 0
    elif x == -H and y == -1:
        q = -H
    else:
        q = get_sign(x * y) * (abs(x) // abs(y))
    return from_signed(q)


def op_smod(a, b):
    x, y = to_signed(a), to_signed(b)
    r = 0 if y == 0 else get_sign(x) * (abs(x) % abs(y))
    return from_signed(r)


def op_addmod(a, b, n):
    return 0 if n == 0 else (a + b) % n


def op_mulmod(a, b, n):
    return 0 if n == 0 else (a * b) % n


def op_exp(a, e):
    return pow(a, e, M)


def op_signextend(b, x):
    # arithmetic.py:signextend, byte-wise exactly as the reference.
    if b > 31:
        return x
    vb = x.to_bytes(32, "big")[31 - b:]
    if vb[0] >> 7 == 0:
        return int.from_bytes(vb, "big")
    return int.from_bytes(bytes([0xFF] * (32 - (b + 1))) + vb, "big")


def op_and(a, b):
    return a & b


def op_or(a, b):
    return a | b


def op_xor(a, b):
    return a ^ b


def op_not(a):
    return MAX ^ a


def op_byte(i, x):
    if i >= 32:
        return 0
    return (x >> ((31 - i) * 8)) & 0xFF


def op_shl(s, v):
    return ((v << s) & MAX) if s < 256 else 0


def op_shr(s, v):
    return (v >> s) if s < 256 else 0


def op_sar(s, v):
    sv = to_signed(v)
    if s < 256:
        return from_signed(sv >> s)
    return 0 if sv >= 0 else MAX


def op_cmp(a, b):
    return from_signed((a > b) - (a < b))


def op_scmp(a, b):
    x, y = to_signed(a), to_signed(b)
    return from_signed((x > y) - (x < y))


# ── Knuth D add-back coverage model (diagnostic only) ────────────────────


def knuth_addbacks(num, den):
    """Count D6 add-back steps of 32-bit-digit algorithm D for num // den."""
    if den == 0:
        return 0
    b = 1 << 32
    u = [(num >> (32 * i)) & (b - 1) for i in range(16)]
    v = [(den >> (32 * i)) & (b - 1) for i in range(8)]
    m = 16
    while m > 0 and u[m - 1] == 0:
        m -= 1
    n = 8
    while n > 0 and v[n - 1] == 0:
        n -= 1
    if m < n or n == 1:
        return 0
    s = 32 - v[n - 1].bit_length()
    vn_int = den << s
    un_int = num << s
    vn = [(vn_int >> (32 * i)) & (b - 1) for i in range(n)]
    un = [(un_int >> (32 * i)) & (b - 1) for i in range(m + 1)]
    count = 0
    for j in range(m - n, -1, -1):
        top = (un[j + n] << 32) | un[j + n - 1]
        qhat, rhat = divmod(top, vn[n - 1])
        while qhat >= b or qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2]):
            qhat -= 1
            rhat += vn[n - 1]
            if rhat >= b:
                break
        cur = sum(un[j + i] << (32 * i) for i in range(n + 1))
        prod = qhat * sum(vn[i] << (32 * i) for i in range(n))
        diff = cur - prod
        if diff < 0:
            count += 1
            diff += sum(vn[i] << (32 * i) for i in range(n))
        for i in range(n + 1):
            un[j + i] = (diff >> (32 * i)) & (b - 1)
    return count


# ── value sources ────────────────────────────────────────────────────────

EDGES = sorted(set([
    0, 1, 2, 3, 0xFF, 0x100,
    2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1,
    2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1, 2 ** 64, 2 ** 64 + 1,
    2 ** 96 - 1, 2 ** 127, 2 ** 128 - 1, 2 ** 128, 2 ** 128 + 1,
    2 ** 191, 2 ** 192 - 1, 2 ** 192, 2 ** 192 + 1,
    2 ** 255 - 1,              # max positive signed
    2 ** 255,                  # -2^255
    2 ** 255 + 1,              # -(2^255 - 1)
    MAX - 1,                   # -2
    MAX,                       # -1 / 2^256 - 1
    0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,
    0x5555555555555555555555555555555555555555555555555555555555555555,
    0x8000000000000000000000000000000000000000000000000000000000000001,
    0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF,
    0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000,
    0x7FFFFFFF800000000000000000000000,   # 32-bit-digit boundary patterns
    0x800000000000000000000001,
    0x0000800000000000000000000000000000000000000000000000000000000003,
]))

# Small edge set for the ternary ops (|E_small|^2 * |N| combinations).
EDGES_SMALL = [0, 1, 2, 2 ** 64 - 1, 2 ** 64, 2 ** 128 - 1, 2 ** 128,
               2 ** 255 - 1, 2 ** 255, MAX - 1, MAX,
               0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]
MODULI = [0, 1, 2, 3, 2 ** 32 - 1, 2 ** 64 - 1, 2 ** 64, 2 ** 64 + 1,
          2 ** 128 - 1, 2 ** 128 + 1, 2 ** 255 - 19, 2 ** 255, 2 ** 255 + 1,
          MAX - 1, MAX]

SHIFTS = [0, 1, 7, 8, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 257,
          2 ** 64, 2 ** 64 + 1, 2 ** 128, 2 ** 255, MAX]
BYTE_IDX = [0, 1, 7, 8, 15, 16, 23, 24, 30, 31, 32, 33, 255, 256,
            2 ** 64, 2 ** 64 + 31, MAX]
SIGNEXT_B = list(range(0, 34)) + [255, 256, 2 ** 64, 2 ** 64 + 1, MAX]


def struct_value(rng):
    """Value built from 32-bit digits drawn from boundary patterns."""
    pool = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
    ndig = rng.randint(1, 8)
    v = 0
    for i in range(ndig):
        d = rng.choice(pool) if rng.random() < 0.8 else rng.getrandbits(32)
        v |= d << (32 * i)
    return v


def gen_value(rng):
    mode = rng.randint(0, 4)
    if mode == 0:
        return rng.getrandbits(256)
    if mode == 1:
        return rng.getrandbits(rng.randint(0, 256))
    if mode == 2:
        return struct_value(rng)
    if mode == 3:
        return rng.choice(EDGES)
    return (rng.choice(EDGES) + rng.randint(-3, 3)) % M


def gen_small_or_value(rng, small_max):
    if rng.random() < 0.5:
        return rng.randint(0, small_max)
    return gen_value(rng)


# ── vector assembly ──────────────────────────────────────────────────────

BINARY = [
    ("ADD", op_add), ("SUB", op_sub), ("MUL", op_mul), ("DIV", op_div),
    ("MOD", op_mod), ("SDIV", op_sdiv), ("SMOD", op_smod), ("EXP", op_exp),
    ("SIGNEXTEND", op_signextend), ("AND", op_and), ("OR", op_or),
    ("XOR", op_xor), ("BYTE", op_byte), ("SHL", op_shl), ("SHR", op_shr),
    ("SAR", op_sar), ("CMP", op_cmp), ("SCMP", op_scmp),
]
TERNARY = [("ADDMOD", op_addmod), ("MULMOD", op_mulmod)]
UNARY = ["NOT", "BITLEN", "ISZERO", "TOU64"]
OPS = [n for n, _ in BINARY] + [n for n, _ in TERNARY] + UNARY

FIRST_OPERAND = {          # (fixed list, random small bound) for index-like operands
    "SIGNEXTEND": (SIGNEXT_B, 40),
    "BYTE": (BYTE_IDX, 40),
    "SHL": (SHIFTS, 300),
    "SHR": (SHIFTS, 300),
    "SAR": (SHIFTS, 300),
}


def hx(v):
    return format(v, "x")


def main():
    rng = random.Random(SEED)
    vecs = []        # (op, a, b, c, x) with ints or None
    addbacks = 0

    def emit_bin(name, fn, a, b):
        nonlocal addbacks
        c = None
        if name == "ADD":
            c = 1 if a + b >= M else 0
        elif name == "SUB":
            c = 1 if a < b else 0
        elif name in ("DIV", "MOD"):
            addbacks += knuth_addbacks(a, b)
        elif name in ("SDIV", "SMOD"):
            addbacks += knuth_addbacks(abs(to_signed(a)), abs(to_signed(b)))
        vecs.append((name, a, b, c, fn(a, b)))

    def emit_ter(name, fn, a, b, n):
        nonlocal addbacks
        addbacks += knuth_addbacks(a + b if name == "ADDMOD" else a * b, n)
        vecs.append((name, a, b, n, fn(a, b, n)))

    def emit_un(name, a):
        if name == "NOT":
            vecs.append((name, a, None, None, op_not(a)))
        elif name == "BITLEN":
            vecs.append((name, a, None, None, a.bit_length()))
        elif name == "ISZERO":
            vecs.append((name, a, None, None, 1 if a == 0 else 0))
        else:  # TOU64
            fits = a < 2 ** 64
            vecs.append((name, a, None, 1 if fits else 0, a if fits else 0))

    pow2 = [2 ** k for k in range(256)]

    # Fixed edge cases.
    for name, fn in BINARY:
        firsts = FIRST_OPERAND.get(name, (EDGES, 0))[0]
        for a in firsts:
            for b in EDGES:
                emit_bin(name, fn, a, b)
        if name in ("MUL", "DIV", "MOD", "SDIV", "SMOD"):
            for p in pow2:
                emit_bin(name, fn, MAX, p)
                emit_bin(name, fn, p, 3)
                emit_bin(name, fn, p + 1 if p < MAX else p, p)
                emit_bin(name, fn, MAX - p + 1, p)
        if name == "EXP":
            for e in [0, 1, 2, 3, 255, 256, 2 ** 64, MAX]:
                for a in [0, 1, 2, 3, MAX, H, 2 ** 128]:
                    emit_bin(name, fn, a, e)
            for k in range(256):
                emit_bin(name, fn, 2, k)
        if name in ("SHL", "SHR", "SAR"):
            for k in range(257):
                emit_bin(name, fn, k, MAX)
                emit_bin(name, fn, k, H)
                emit_bin(name, fn, k, 1)
        if name == "BYTE":
            x = int.from_bytes(bytes(range(1, 33)), "big")
            for i in range(34):
                emit_bin(name, fn, i, x)
    for name, fn in TERNARY:
        for a in EDGES_SMALL:
            for b in EDGES_SMALL:
                for n in MODULI:
                    emit_ter(name, fn, a, b, n)
    for name in UNARY:
        for a in EDGES:
            emit_un(name, a)
        for p in pow2:
            emit_un(name, p)
            emit_un(name, p - 1)

    # Random cases from the fixed seed.
    for name, fn in BINARY:
        small = FIRST_OPERAND.get(name, (None, None))[1]
        for _ in range(RANDOM_PER_OP):
            a = gen_small_or_value(rng, small) if small else gen_value(rng)
            if name == "EXP" and rng.random() < 0.3:
                b = rng.randint(0, 300)
            else:
                b = gen_value(rng)
            if name in ("DIV", "MOD", "SDIV", "SMOD") and rng.random() < 0.3:
                # divisor of random digit length, to reach every n in algorithm D
                b = struct_value(rng)
            emit_bin(name, fn, a, b)
    for name, fn in TERNARY:
        for _ in range(RANDOM_PER_OP):
            a, b = gen_value(rng), gen_value(rng)
            n = struct_value(rng) if rng.random() < 0.3 else gen_value(rng)
            emit_ter(name, fn, a, b, n)
    for name in UNARY:
        for _ in range(RANDOM_PER_UNARY):
            emit_un(name, gen_value(rng))

    # The 15 MB vector header is a BUILD product (not committed): the
    # Makefile passes build/u256_vectors.h; the default stays next to
    # this script for a manual run.
    out_path = (sys.argv[1] if len(sys.argv) > 1 else
                os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "u256_vectors.h"))
    lines = []
    lines.append("/* GENERATED by u256_oracle.py — do not edit by hand.")
    lines.append(" * Reference: ethereum/execution-specs @a87891f7, Prague.")
    lines.append(" * Seed: random.Random(%d). Field meaning: see u256_oracle.py. */" % SEED)
    lines.append("#ifndef EVM_U256_VECTORS_H")
    lines.append("#define EVM_U256_VECTORS_H")
    lines.append("")
    lines.append("enum u256_op {")
    for name in OPS:
        lines.append("    U256_OP_%s," % name)
    lines.append("    U256_OP_COUNT")
    lines.append("};")
    lines.append("")
    lines.append("static const char *const U256_OP_NAMES[] = {")
    for name in OPS:
        lines.append('    "%s",' % name)
    lines.append("};")
    lines.append("")
    lines.append("typedef struct {")
    lines.append("    int op;")
    lines.append("    const char *a, *b, *c, *x;")
    lines.append("} u256_vector;")
    lines.append("")
    lines.append("static const u256_vector U256_VECTORS[] = {")
    for (name, a, b, c, x) in vecs:
        f = lambda v: '""' if v is None else '"%s"' % hx(v)
        lines.append("{U256_OP_%s,%s,%s,%s,%s}," % (name, f(a), f(b), f(c), f(x)))
    lines.append("};")
    lines.append("")
    lines.append("#define U256_VECTOR_COUNT (sizeof(U256_VECTORS) / sizeof(U256_VECTORS[0]))")
    lines.append("")
    lines.append("#endif /* EVM_U256_VECTORS_H */")
    with open(out_path, "w", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")

    per_op = {}
    for v in vecs:
        per_op[v[0]] = per_op.get(v[0], 0) + 1
    print("wrote %s: %d vectors" % (out_path, len(vecs)))
    for name in OPS:
        print("  %-10s %d" % (name, per_op.get(name, 0)))
    print("Knuth D add-back (D6) occurrences across division vectors: %d" % addbacks)


if __name__ == "__main__":
    main()
