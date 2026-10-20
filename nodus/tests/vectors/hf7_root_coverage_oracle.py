#!/usr/bin/env python3
"""Independent oracle for the HF-7 root-coverage byte layouts.

PROVENANCE
  Written from docs/plans/2026-09-11-nodus-ledger-snapshot-design.md,
  subsection "### 8.9 FINAL — normative byte spec" ONLY: common rules C1-C7,
  items S1-S8 and the "KAT obligations" paragraph. Sections 8.1-8.4 of that
  document (withdrawn history) were NOT used. Governing record read:
  docs/plans/decisions/2026-10-15-kurultay-24-summary.md (round 3: SYSTEM v6 =
  12 legs, segment leaf v2 with tag hex 4e44532e535453474c4541462e763200,
  DomainHead v2, GLOBAL v2 = domains_root | replay_root, CORE stays v2) — no
  contradiction with 8.9 found.
  The C implementation of these roots was NOT read (author != oracle): the
  file:line citations inside 8.9 (shared/dnac/ledger_roots_v2.c/.h) are
  provenance in the spec text only and were not opened. The FORMAT of this
  script (structure, not content) copies
  nodus/tests/vectors/storage_reward_oracle.py.

  Honest label: SELF-CONSISTENT. This proves a second implementation of the
  same document agrees byte for byte; it does not prove the document sound.

Usage: python3 hf7_root_coverage_oracle.py [out.json]
  default output: hf7_root_coverage_kat.json next to this script.
Dependencies: Python 3 standard library only (hashlib.sha3_512).

READINGS (places where 8.9 leaves a choice open; the reading taken here)
  R1  S6 enc89 fields (domain_id u32, domain_height u64,
      last_updated_global_height u64, ruleset_version u32, status u8) have no
      stated range in 8.9; the range is the full width of the type (C3 errors
      only outside it). status is not restricted to any value set.
  R2  Opaque 64-byte inputs (S4 L1..L9 and its three new legs, S5 Root(k),
      S6 domain_state_root / last_upd_hash, S8 domains_root / replay_root) are
      checked for length only (C4); their content is not interpreted.
  R3  C4 "fixed length as written": a byte string of the wrong length (or a
      non-bytes value) is treated as an ERROR, although the KAT obligations
      paragraph does not list that case. Such vectors are emitted (S1, S5,
      S7, S8).
  R4  C3: a non-integer (including bool) where an integer is written is an
      ERROR. Integers are checked against the STATED range of the item (e.g.
      S1 amount 0..2^63-1, S7 expiry 1..2^64-1), not only the type width.
  R5  S7 "both tx_id and intent_id unique across the set": uniqueness is per
      column. A tx_id equal to some other row's intent_id is NOT an error.
      tx_id uniqueness follows from the strict ascending order of C5 and is
      reported as "duplicate key"; intent_id uniqueness is a separate check
      reported as "duplicate intent_id".
  R6  "S4, S6, S8 with fixed and with random inputs": "fixed" = constant byte
      patterns (all 0x00, all 0xFF, per-input constant byte) and fixed
      integers (0, type maximum, or the per-input constant byte value);
      "random" = deterministic pseudo-random
      inputs, every byte string = SHA3-512("hf7_root_coverage_kat/" + label)
      and every integer = the leading bytes of such a digest, big-endian,
      shifted to the type width. No `random` module, no unseeded source.
  R7  C6 Merkle inputs are the 64-byte leaf HASHES (S1/S3/S5/S7 leaves, S6
      head hashes); n == 1 root = that hash itself (no node tag applied).
  R8  The root functions REFUSE non-canonical input (C5) instead of sorting
      it; the KAT generator sorts its own valid inputs before calling them.
  R9  When an input has more than one defect, the error reported is the first
      one detected, in this check order: (S6 only) empty list; per row in row
      order, each field in written order (type, length, range); (S6 only)
      first head not domain 0; key order (equal neighbour -> "duplicate key",
      descending neighbour -> "unsorted keys"); (S7 only) duplicate intent_id.
      The ERROR vectors each carry exactly one defect, so this order does not
      change any expected result.
  R10 S2 "absent" is represented as JSON null / Python None.
  R11 S6 "first being domain 0": the first head's domain_id must equal 0;
      an equal domain_id neighbour is the C5 "duplicate key" ERROR.
  R12 JSON: byte strings are lowercase hex; integers are decimal strings
      (exact for u64 and for out-of-range values such as 2^64). Every leaf /
      vstat / head / composition also carries its full preimage hex, which
      pins the big-endian encoding independently of the decimal fields.
"""

import hashlib
import json
import os
import sys

TAG_LEN = 16
FP_LEN = 64
HASH_LEN = 64

U8_MAX = (1 << 8) - 1
U32_MAX = (1 << 32) - 1
U63_MAX = (1 << 63) - 1
U64_MAX = (1 << 64) - 1


class SpecError(ValueError):
    """An ERROR case of 8.9: no root is produced."""


# ── primitives (C1-C7) ────────────────────────────────────────────────────

def h(data: bytes) -> bytes:
    """C1: SHA3-512, 64-byte output."""
    return hashlib.sha3_512(data).digest()


def tag(s: str) -> bytes:
    """C2: ASCII name followed by 0x00 up to exactly 16 bytes; names are
    at most 15 characters."""
    b = s.encode("ascii")
    if len(b) > TAG_LEN - 1:
        raise ValueError("tag longer than 15 characters: " + s)
    return b + b"\x00" * (TAG_LEN - len(b))


def uint(v, width_bytes, lo, hi, name):
    """C3: unsigned big-endian of the written width; outside the stated
    range [lo, hi] is an ERROR, never truncated or wrapped."""
    assert 0 <= lo <= hi <= (1 << (8 * width_bytes)) - 1
    if type(v) is not int:
        raise SpecError("%s: not an integer" % name)
    if not lo <= v <= hi:
        raise SpecError("out-of-range integer: %s = %d, allowed %d..%d"
                        % (name, v, lo, hi))
    return v.to_bytes(width_bytes, "big")


def u8(v, lo, hi, name):
    return uint(v, 1, lo, hi, name)


def u32(v, lo, hi, name):
    return uint(v, 4, lo, hi, name)


def u64(v, lo, hi, name):
    return uint(v, 8, lo, hi, name)


def fixed(b, n, name):
    """C4: fixed-length raw bytes, no length prefix."""
    if not isinstance(b, (bytes, bytearray)):
        raise SpecError("%s: not a byte string" % name)
    if len(b) != n:
        raise SpecError("%s: length %d, required %d" % (name, len(b), n))
    return bytes(b)


def check_strictly_ascending(keys):
    """C5: strictly ascending; Python tuple / int / bytes comparison gives
    field-by-field, numeric and unsigned-bytewise (memcmp) order."""
    for i in range(1, len(keys)):
        if keys[i - 1] == keys[i]:
            raise SpecError("duplicate key at index %d" % i)
        if keys[i - 1] > keys[i]:
            raise SpecError("unsorted keys at index %d" % i)


def tagged_merkle(node_tag: str, leaves):
    """C6: n == 1 -> L[0]; otherwise pairwise parent = SHA3-512(node_tag |
    left | right), an odd last node carried up UNCHANGED after the parents."""
    if not leaves:
        raise ValueError("tagged_merkle needs n >= 1")
    t = tag(node_tag)
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(h(t + level[i] + level[i + 1]))
        if len(level) & 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def empty_root(empty_tag: str) -> bytes:
    """C7: SHA3-512 over the 16-byte padded empty tag alone."""
    return h(tag(empty_tag))


# ── tags ──────────────────────────────────────────────────────────────────

T_BCLEAF = "NDS.BCLEAF.v1"
T_BCNODE = "NDS.BCNODE.v1"
T_E_BCOPY = "NDS.E.BCOPY.v1"
T_VSTAT = "NDS.VSTAT.v1"
T_SMLEAF = "NDS.SMLEAF.v1"
T_SMNODE = "NDS.SMNODE.v1"
T_E_STMEM = "NDS.E.STMEM.v1"
T_SYS6 = "NDS.SYS.v6"
T_STSGLEAF2 = "NDS.STSGLEAF.v2"
T_STSGNODE = "NDS.STSGNODE.v1"
T_E_STSEG = "NDS.E.STSEG.v1"
T_DOMHEAD2 = "NDS.DOMHEAD.v2"
T_DOMNODE = "NDS.DOMNODE.v1"
T_RPLEAF = "NDS.RPLEAF.v1"
T_RPNODE = "NDS.RPNODE.v1"
T_E_REPLAY = "NDS.E.REPLAY.v1"
T_GLOBAL2 = "NDS.GLOBAL.v2"

ALL_TAGS = [T_BCLEAF, T_BCNODE, T_E_BCOPY, T_VSTAT, T_SMLEAF, T_SMNODE,
            T_E_STMEM, T_SYS6, T_STSGLEAF2, T_STSGNODE, T_E_STSEG,
            T_DOMHEAD2, T_DOMNODE, T_RPLEAF, T_RPNODE, T_E_REPLAY, T_GLOBAL2]
EMPTY_TAGS = [T_E_BCOPY, T_E_STMEM, T_E_STSEG, T_E_REPLAY]

# S5 states the tag hex explicitly; pin it.
assert tag(T_STSGLEAF2).hex() == "4e44532e535453474c4541462e763200"
for _t in ALL_TAGS:
    assert len(tag(_t)) == TAG_LEN


# ── S1 balance-copy leg ───────────────────────────────────────────────────
# row = (epoch_start, validator_fp, owner_fp, kind, amount)

S1_FIELDS = ("epoch_start", "validator_fp", "owner_fp", "kind", "amount")


def s1_leaf_preimage(row):
    es, vfp, ofp, kind, amount = row
    pre = (tag(T_BCLEAF) + u64(es, 0, U63_MAX, "epoch_start") +
           fixed(vfp, FP_LEN, "validator_fp") +
           fixed(ofp, FP_LEN, "owner_fp") +
           u8(kind, 0, 1, "kind") + u64(amount, 0, U63_MAX, "amount"))
    assert len(pre) == 16 + 8 + 64 + 64 + 1 + 8
    return pre


def s1_key(row):
    return (row[0], bytes(row[1]), bytes(row[2]), row[3])


def s1_root(rows):
    if not rows:
        return empty_root(T_E_BCOPY)
    leaves = [h(s1_leaf_preimage(r)) for r in rows]
    check_strictly_ascending([s1_key(r) for r in rows])
    return tagged_merkle(T_BCNODE, leaves)


# ── S2 active-count leg ───────────────────────────────────────────────────

def s2_vstat_preimage(active_count):
    if active_count is None:
        raise SpecError("active_count row absent")
    return tag(T_VSTAT) + u64(active_count, 0, U63_MAX, "active_count")


def s2_vstat(active_count):
    return h(s2_vstat_preimage(active_count))


# ── S3 storage-member leg ─────────────────────────────────────────────────
# row = (epoch_start, node_fp, fail_streak, grace_until)

S3_FIELDS = ("epoch_start", "node_fp", "fail_streak", "grace_until")


def s3_leaf_preimage(row):
    es, nfp, streak, grace = row
    pre = (tag(T_SMLEAF) + u64(es, 1, U63_MAX, "epoch_start") +
           fixed(nfp, FP_LEN, "node_fp") +
           u32(streak, 0, U32_MAX, "fail_streak") +
           u64(grace, 0, U63_MAX, "grace_until"))
    assert len(pre) == 16 + 8 + 64 + 4 + 8
    return pre


def s3_key(row):
    return (row[0], bytes(row[1]))


def s3_root(rows):
    if not rows:
        return empty_root(T_E_STMEM)
    leaves = [h(s3_leaf_preimage(r)) for r in rows]
    check_strictly_ascending([s3_key(r) for r in rows])
    return tagged_merkle(T_SMNODE, leaves)


# ── S4 SYSTEM composition v6 ──────────────────────────────────────────────

SYS_V5_LEGS = ["validator", "delegation", "chain_config", "validator_set",
               "domain_registry", "manifest", "attendance", "treasury",
               "storage"]


def s4_system_v6_preimage(legs9, bcopy_root, vstat, stmem_root):
    if not isinstance(legs9, (list, tuple)) or len(legs9) != 9:
        raise SpecError("SYSTEM v6 needs exactly 9 v5 legs")
    body = b"".join(fixed(v, HASH_LEN, "L%d (%s)" % (i + 1, SYS_V5_LEGS[i]))
                    for i, v in enumerate(legs9))
    pre = (tag(T_SYS6) + body + fixed(bcopy_root, HASH_LEN, "bcopy_root") +
           fixed(vstat, HASH_LEN, "vstat") +
           fixed(stmem_root, HASH_LEN, "stmem_root"))
    assert len(pre) == 16 + 12 * 64
    return pre


def s4_system_v6(*a):
    return h(s4_system_v6_preimage(*a))


# ── S5 segment leaf v2 ────────────────────────────────────────────────────
# row = (k, root_k, published_height)

S5_FIELDS = ("k", "root_k", "published_height")


def s5_leaf_preimage(row):
    k, root_k, ph = row
    pre = (tag(T_STSGLEAF2) + u64(k, 1, U63_MAX, "k") +
           fixed(root_k, HASH_LEN, "Root(k)") +
           u64(ph, 1, U63_MAX, "published_height"))
    assert len(pre) == 96
    return pre


def s5_key(row):
    return row[0]


def s5_root(rows):
    if not rows:
        return empty_root(T_E_STSEG)
    leaves = [h(s5_leaf_preimage(r)) for r in rows]
    check_strictly_ascending([s5_key(r) for r in rows])
    return tagged_merkle(T_STSGNODE, leaves)


# ── S6 DomainHead v2 and domains_root ─────────────────────────────────────
# head = (domain_id, domain_state_root, domain_height,
#         last_updated_global_height, ruleset_version, status, last_upd_hash)

S6_FIELDS = ("domain_id", "domain_state_root", "domain_height",
             "last_updated_global_height", "ruleset_version", "status",
             "last_upd_hash")


def s6_enc89(head):
    did, dsr, dh, lugh, rv, st, _luh = head
    enc = (u32(did, 0, U32_MAX, "domain_id") +
           fixed(dsr, HASH_LEN, "domain_state_root") +
           u64(dh, 0, U64_MAX, "domain_height") +
           u64(lugh, 0, U64_MAX, "last_updated_global_height") +
           u32(rv, 0, U32_MAX, "ruleset_version") +
           u8(st, 0, U8_MAX, "status"))
    assert len(enc) == 89
    return enc


def s6_head_preimage(head):
    pre = (tag(T_DOMHEAD2) + s6_enc89(head) +
           fixed(head[6], HASH_LEN, "last_upd_hash"))
    assert len(pre) == 169
    return pre


def s6_head_hash(head):
    return h(s6_head_preimage(head))


def s6_domains_root(heads):
    if not heads:
        raise SpecError("empty domain list")
    hashes = [s6_head_hash(x) for x in heads]
    if heads[0][0] != 0:
        raise SpecError("first head not domain 0")
    check_strictly_ascending([x[0] for x in heads])
    return tagged_merkle(T_DOMNODE, hashes)


# ── S7 replay leg ─────────────────────────────────────────────────────────
# row = (tx_id, intent_id, expiry_height)

S7_FIELDS = ("tx_id", "intent_id", "expiry_height")


def s7_leaf_preimage(row):
    tx, intent, exp = row
    pre = (tag(T_RPLEAF) + fixed(tx, HASH_LEN, "tx_id") +
           fixed(intent, HASH_LEN, "intent_id") +
           u64(exp, 1, U64_MAX, "expiry_height"))
    assert len(pre) == 16 + 64 + 64 + 8
    return pre


def s7_key(row):
    return bytes(row[0])


def s7_root(rows):
    if not rows:
        return empty_root(T_E_REPLAY)
    leaves = [h(s7_leaf_preimage(r)) for r in rows]
    check_strictly_ascending([s7_key(r) for r in rows])
    seen = set()
    for i, r in enumerate(rows):
        ib = bytes(r[1])
        if ib in seen:
            raise SpecError("duplicate intent_id at index %d" % i)
        seen.add(ib)
    return tagged_merkle(T_RPNODE, leaves)


# ── S8 GLOBAL composition v2 ──────────────────────────────────────────────

def s8_global_v2_preimage(domains_root, replay_root):
    pre = (tag(T_GLOBAL2) + fixed(domains_root, HASH_LEN, "domains_root") +
           fixed(replay_root, HASH_LEN, "replay_root"))
    assert len(pre) == 16 + 64 + 64
    return pre


def s8_global_v2(*a):
    return h(s8_global_v2_preimage(*a))


# ── deterministic test inputs ─────────────────────────────────────────────

def d(label: str) -> bytes:
    return h(("hf7_root_coverage_kat/" + label).encode("ascii"))


def dint(label: str, bits: int) -> int:
    """Deterministic integer of the given bit width from a digest."""
    return int.from_bytes(d(label)[:8], "big") >> (64 - bits)


def X(b):
    return b.hex()


def jval(v):
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return X(v)
    if type(v) is int:
        return str(v)
    return repr(v)


def jrow(fields, row):
    return {f: jval(v) for f, v in zip(fields, row)}


def expect_error(fn, *args):
    """Run fn and return the SpecError reason; a missing error is a defect
    of this generator and stops it."""
    try:
        fn(*args)
    except SpecError as e:
        return str(e)
    raise RuntimeError("expected ERROR not raised by %s" % fn.__name__)


SET_SIZES = (0, 1, 2, 3, 5)


def set_vectors(fields, rows_for_n, key_fn, pre_fn, root_fn):
    out = []
    for n in SET_SIZES:
        rows = sorted(rows_for_n(n), key=key_fn)
        out.append({
            "n": n,
            "rows_sorted": [dict(jrow(fields, r),
                                 preimage=X(pre_fn(r)),
                                 leaf=X(h(pre_fn(r)))) for r in rows],
            "root": X(root_fn(rows)),
        })
    return out


def error_vectors(fields, cases, root_fn):
    out = []
    for name, rows in cases:
        out.append({"name": name,
                    "input": [jrow(fields, r) for r in rows],
                    "error": expect_error(root_fn, rows)})
    return out


# ── S1 inputs ─────────────────────────────────────────────────────────────

S1_TEMPLATE = [
    (0, "v0", "o0", 0, 0),
    (0, "v0", "o0", 1, 1),             # same prefix, differs in kind only
    (720, "v0", "o1", 0, 10 ** 15),
    (720, "v1", "o0", 1, U63_MAX),
    (U63_MAX, "v2", "o2", 0, 123456789),
]


def s1_rows(n):
    return [(es, d("s1/n%d/%s" % (n, v)), d("s1/n%d/%s" % (n, o)), kind, amt)
            for es, v, o, kind, amt in S1_TEMPLATE[:n]]


def s1_errors():
    va, vb = sorted([d("s1/err/va"), d("s1/err/vb")])
    o = d("s1/err/o")
    return [
        ("epoch_start_2^63", [(1 << 63, va, o, 0, 1)]),
        ("kind_2", [(720, va, o, 2, 1)]),
        ("amount_2^63", [(720, va, o, 0, 1 << 63)]),
        ("amount_negative", [(720, va, o, 0, -1)]),
        ("validator_fp_len_63", [(720, va[:63], o, 0, 1)]),
        ("unsorted_kind_descending",
         [(720, va, o, 1, 5), (720, va, o, 0, 5)]),
        ("unsorted_validator_fp_memcmp",
         [(720, vb, o, 0, 5), (720, va, o, 0, 5)]),
        ("unsorted_epoch_start",
         [(1440, va, o, 0, 5), (720, va, o, 0, 5)]),
        ("duplicate_key_amount_differs",
         [(720, va, o, 1, 5), (720, va, o, 1, 6)]),
    ]


# ── S3 inputs ─────────────────────────────────────────────────────────────

S3_TEMPLATE = [
    (1, "n0", 0, 0),
    (1, "n1", U32_MAX, U63_MAX),
    (720, "n0", 3, 1440),
    (1440, "n2", 1, 0),
    (U63_MAX, "n3", 0, U63_MAX),
]


def s3_rows(n):
    return [(es, d("s3/n%d/%s" % (n, nf)), fs, gu)
            for es, nf, fs, gu in S3_TEMPLATE[:n]]


def s3_errors():
    na, nb = sorted([d("s3/err/na"), d("s3/err/nb")])
    return [
        ("epoch_start_0", [(0, na, 0, 0)]),
        ("epoch_start_2^63", [(1 << 63, na, 0, 0)]),
        ("fail_streak_2^32", [(720, na, 1 << 32, 0)]),
        ("grace_until_2^63", [(720, na, 0, 1 << 63)]),
        ("unsorted_epoch_start", [(1440, na, 0, 0), (720, na, 0, 0)]),
        ("unsorted_node_fp_memcmp", [(720, nb, 0, 0), (720, na, 0, 0)]),
        ("duplicate_key_fail_streak_differs",
         [(720, na, 0, 0), (720, na, 1, 0)]),
    ]


# ── S5 inputs ─────────────────────────────────────────────────────────────

S5_TEMPLATE = [
    (1, 1),
    (2, 17280),
    (3, U63_MAX),
    (1000, 5),
    (U63_MAX, U63_MAX),
]


def s5_rows(n):
    return [(k, d("s5/n%d/root/%d" % (n, k)), ph) for k, ph in S5_TEMPLATE[:n]]


def s5_errors():
    r = d("s5/err/root")
    return [
        ("k_0", [(0, r, 1)]),
        ("k_2^63", [(1 << 63, r, 1)]),
        ("published_height_0", [(1, r, 0)]),
        ("published_height_2^63", [(1, r, 1 << 63)]),
        ("root_len_65", [(1, r + b"\x00", 1)]),
        ("unsorted_k", [(2, r, 1), (1, r, 1)]),
        ("duplicate_k", [(1, r, 1), (1, d("s5/err/root2"), 2)]),
    ]


# ── S7 inputs ─────────────────────────────────────────────────────────────

S7_TEMPLATE = [
    ("t0", "i0", 1),
    ("t1", "i1", U64_MAX),
    ("t2", "i2", 720),
    ("t3", "i3", 100),
    ("t4", "i4", 1 << 63),
]


def s7_rows(n):
    return [(d("s7/n%d/%s" % (n, t)), d("s7/n%d/%s" % (n, i)), e)
            for t, i, e in S7_TEMPLATE[:n]]


def s7_errors():
    ta, tb = sorted([d("s7/err/ta"), d("s7/err/tb")])
    ia, ib = d("s7/err/ia"), d("s7/err/ib")
    return [
        ("expiry_0", [(ta, ia, 0)]),
        ("expiry_2^64", [(ta, ia, 1 << 64)]),
        ("intent_id_len_0", [(ta, b"", 1)]),
        ("unsorted_tx_id_memcmp", [(tb, ia, 1), (ta, ib, 1)]),
        ("duplicate_key_tx_id", [(ta, ia, 1), (ta, ib, 2)]),
        ("duplicate_intent_id", [(ta, ia, 1), (tb, ia, 2)]),
    ]


# ── S6 inputs ─────────────────────────────────────────────────────────────

def s6_fixed_head(did, byte):
    """Fixed head: every byte string = 64 x `byte`; integers 0 when byte is
    0x00, type maximum when byte is 0xFF, otherwise the byte value."""
    if byte == 0x00:
        ints = (0, 0, 0, 0)
    elif byte == 0xFF:
        ints = (U64_MAX, U64_MAX, U32_MAX, U8_MAX)
    else:
        ints = (byte, byte, byte, byte)
    return (did, bytes([byte]) * 64, ints[0], ints[1], ints[2], ints[3],
            bytes([byte]) * 64)


def s6_random_head(did, label):
    p = "s6/%s/d%d/" % (label, did)
    return (did, d(p + "domain_state_root"),
            dint(p + "domain_height", 64),
            dint(p + "last_updated_global_height", 64),
            dint(p + "ruleset_version", 32),
            dint(p + "status", 8),
            d(p + "last_upd_hash"))


def s6_head_json(head):
    pre = s6_head_preimage(head)
    return dict(jrow(S6_FIELDS, head), enc89=X(s6_enc89(head)),
                preimage=X(pre), head_hash=X(h(pre)))


# The READINGS block of the module docstring, one normalised string per item
# (single source: the docstring). Empty under `python -OO` (no docstrings).
AMBIGUITIES = ["R" + " ".join(item.split()) for item in
               (__doc__ or "READINGS").split("READINGS", 1)[1]
               .split("\n  R")[1:]]


def build():
    vec = {}
    count = 0

    vec["tags"] = {t: X(tag(t)) for t in ALL_TAGS}
    vec["empty_roots"] = {t: X(empty_root(t)) for t in EMPTY_TAGS}
    count += len(EMPTY_TAGS)

    # S1
    s1 = set_vectors(S1_FIELDS, s1_rows, s1_key, s1_leaf_preimage, s1_root)
    s1e = error_vectors(S1_FIELDS, s1_errors(), s1_root)
    vec["S1_balance_copy"] = {"roots": s1, "errors": s1e}
    count += len(s1) + len(s1e)

    # S2
    s2 = []
    for ac in (0, 1, U63_MAX):
        pre = s2_vstat_preimage(ac)
        s2.append({"active_count": str(ac), "preimage": X(pre),
                   "vstat": X(h(pre))})
    s2e = []
    for ac in (1 << 63, None):
        s2e.append({"input": {"active_count": jval(ac)},
                    "error": expect_error(s2_vstat, ac)})
    vec["S2_active_count"] = {"values": s2, "errors": s2e}
    count += len(s2) + len(s2e)

    # S3
    s3 = set_vectors(S3_FIELDS, s3_rows, s3_key, s3_leaf_preimage, s3_root)
    s3e = error_vectors(S3_FIELDS, s3_errors(), s3_root)
    vec["S3_storage_members"] = {"roots": s3, "errors": s3e}
    count += len(s3) + len(s3e)

    # S5
    s5 = set_vectors(S5_FIELDS, s5_rows, s5_key, s5_leaf_preimage, s5_root)
    s5e = error_vectors(S5_FIELDS, s5_errors(), s5_root)
    vec["S5_segments_v2"] = {"roots": s5, "errors": s5e}
    count += len(s5) + len(s5e)

    # S7
    s7 = set_vectors(S7_FIELDS, s7_rows, s7_key, s7_leaf_preimage, s7_root)
    s7e = error_vectors(S7_FIELDS, s7_errors(), s7_root)
    vec["S7_replay"] = {"roots": s7, "errors": s7e}
    count += len(s7) + len(s7e)

    # S4
    s4_cases = [
        ("fixed_all_00", [b"\x00" * 64] * 9, b"\x00" * 64, b"\x00" * 64,
         b"\x00" * 64),
        ("fixed_all_ff", [b"\xff" * 64] * 9, b"\xff" * 64, b"\xff" * 64,
         b"\xff" * 64),
        ("fixed_input_i_is_byte_i",
         [bytes([i + 1]) * 64 for i in range(9)],
         bytes([10]) * 64, bytes([11]) * 64, bytes([12]) * 64),
        ("random",
         [d("s4/random/" + nm) for nm in SYS_V5_LEGS],
         d("s4/random/bcopy_root"), d("s4/random/vstat"),
         d("s4/random/stmem_root")),
        ("random_legs_new_legs_empty_vstat0",
         [d("s4/random2/" + nm) for nm in SYS_V5_LEGS],
         empty_root(T_E_BCOPY), s2_vstat(0), empty_root(T_E_STMEM)),
        ("random_legs_new_legs_from_S1_S2_S3_n5",
         [d("s4/random3/" + nm) for nm in SYS_V5_LEGS],
         bytes.fromhex(s1[-1]["root"]), s2_vstat(5),
         bytes.fromhex(s3[-1]["root"])),
    ]
    s4 = []
    for name, legs, bc, vs, sm in s4_cases:
        pre = s4_system_v6_preimage(legs, bc, vs, sm)
        s4.append({"name": name,
                   "v5_legs_in_order": [{"leg": ln, "value": X(v)}
                                        for ln, v in zip(SYS_V5_LEGS, legs)],
                   "bcopy_root": X(bc), "vstat": X(vs),
                   "stmem_root": X(sm), "preimage": X(pre),
                   "system_state_root": X(h(pre))})
    eight = [d("s4/err/" + nm) for nm in SYS_V5_LEGS[:8]]
    s4e = [{"name": "only_8_v5_legs",
            "input": {"v5_legs": [X(v) for v in eight],
                      "bcopy_root": X(d("s4/err/bc")),
                      "vstat": X(d("s4/err/vs")),
                      "stmem_root": X(d("s4/err/sm"))},
            "error": expect_error(s4_system_v6, eight, d("s4/err/bc"),
                                  d("s4/err/vs"), d("s4/err/sm"))}]
    vec["S4_system_v6"] = {"compositions": s4, "errors": s4e}
    count += len(s4) + len(s4e)

    # S6 — single heads
    s6_heads = [
        ("fixed_all_00_domain0", s6_fixed_head(0, 0x00)),
        ("fixed_all_ff_domain_max", s6_fixed_head(U32_MAX, 0xFF)),
        ("random_domain0", s6_random_head(0, "single")),
        ("random_domain7", s6_random_head(7, "single")),
    ]
    s6h = [dict(s6_head_json(hd), name=nm) for nm, hd in s6_heads]
    count += len(s6h)

    # S6 — domains_root
    s6_lists = [
        ("fixed_1_head", [s6_fixed_head(0, 0x00)]),
        ("fixed_3_heads", [s6_fixed_head(0, 0x00), s6_fixed_head(1, 0x11),
                           s6_fixed_head(U32_MAX, 0xFF)]),
        ("random_1_head", [s6_random_head(0, "list1")]),
        ("random_3_heads", [s6_random_head(0, "list3"),
                            s6_random_head(1, "list3"),
                            s6_random_head(42, "list3")]),
        ("random_5_heads", [s6_random_head(did, "list5")
                            for did in (0, 1, 2, 9, 1000)]),
    ]
    s6r = []
    for nm, heads in s6_lists:
        s6r.append({"name": nm,
                    "heads": [s6_head_json(x) for x in heads],
                    "domains_root": X(s6_domains_root(heads))})
    count += len(s6r)

    s6_err = [
        ("empty_list", []),
        ("first_head_not_domain0", [s6_random_head(1, "err"),
                                    s6_random_head(2, "err")]),
        ("unsorted_domain_ids", [s6_random_head(0, "err"),
                                 s6_random_head(5, "err"),
                                 s6_random_head(3, "err")]),
        ("duplicate_domain_id", [s6_random_head(0, "err"),
                                 s6_random_head(4, "err"),
                                 s6_random_head(4, "err2")]),
        ("domain_id_2^32", [s6_random_head(0, "err"),
                            (1 << 32,) + s6_random_head(1, "err")[1:]]),
        ("status_256", [s6_random_head(0, "err")[:5] + (256,) +
                        s6_random_head(0, "err")[6:]]),
    ]
    s6e = []
    for nm, heads in s6_err:
        s6e.append({"name": nm,
                    "input": [jrow(S6_FIELDS, x) for x in heads],
                    "error": expect_error(s6_domains_root, heads)})
    count += len(s6e)
    vec["S6_domainhead_v2"] = {"head_hashes": s6h, "domains_roots": s6r,
                               "errors": s6e}

    # S8
    s8_cases = [
        ("fixed_all_00", b"\x00" * 64, b"\x00" * 64),
        ("fixed_all_ff", b"\xff" * 64, b"\xff" * 64),
        ("fixed_01_02", b"\x01" * 64, b"\x02" * 64),
        ("random", d("s8/random/domains_root"), d("s8/random/replay_root")),
        ("S6_random_3_heads_with_empty_replay",
         bytes.fromhex(s6r[3]["domains_root"]), empty_root(T_E_REPLAY)),
        ("S6_random_3_heads_with_S7_n5",
         bytes.fromhex(s6r[3]["domains_root"]),
         bytes.fromhex(s7[-1]["root"])),
    ]
    s8 = []
    for nm, dr, rr in s8_cases:
        pre = s8_global_v2_preimage(dr, rr)
        s8.append({"name": nm, "domains_root": X(dr), "replay_root": X(rr),
                   "preimage": X(pre), "global_state_root": X(h(pre))})
    bad = d("s8/err/domains_root")[:63]
    s8e = [{"name": "domains_root_len_63",
            "input": {"domains_root": X(bad),
                      "replay_root": X(d("s8/err/replay_root"))},
            "error": expect_error(s8_global_v2, bad,
                                  d("s8/err/replay_root"))}]
    vec["S8_global_v2"] = {"compositions": s8, "errors": s8e}
    count += len(s8) + len(s8e)

    return {
        "spec": "docs/plans/2026-09-11-nodus-ledger-snapshot-design.md "
                "section 8.9 FINAL — normative byte spec (C1-C7, S1-S8)",
        "decision": "docs/plans/decisions/2026-10-15-kurultay-24-summary.md",
        "oracle": "nodus/tests/vectors/hf7_root_coverage_oracle.py",
        "label": "SELF-CONSISTENT (independent re-implementation of the "
                 "same document; not an external reference)",
        "conventions": {
            "hash": "SHA3-512 (hashlib.sha3_512)",
            "tag": "16 bytes, ASCII, right-padded with 0x00",
            "integers": "big-endian in preimages; decimal strings in JSON",
            "hex": "lowercase, no prefix",
            "merkle": "C6: n==1 -> leaf; pairs SHA3-512(node_tag|L|R); odd "
                      "last node carried up unchanged",
            "empty": "C7: SHA3-512(16-byte padded empty tag)",
            "inputs": "byte strings = SHA3-512('hf7_root_coverage_kat/' + "
                      "label); random integers = first 8 bytes of such a "
                      "digest, big-endian, shifted right to the type width; "
                      "fixed = constant byte patterns / 0 / type maximum",
            "errors": "each error vector has one defect; 'error' is the "
                      "oracle's reason string (reason class is normative, "
                      "exact wording is not)",
        },
        "ambiguities": AMBIGUITIES,
        "vector_count": count,
        "vectors": vec,
    }


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "hf7_root_coverage_kat.json")
    doc = build()
    with open(out, "w", encoding="ascii") as f:
        json.dump(doc, f, indent=1, sort_keys=False)
        f.write("\n")
    sys.stdout.write("wrote %s (%d vectors)\n" % (out, doc["vector_count"]))


if __name__ == "__main__":
    main()
