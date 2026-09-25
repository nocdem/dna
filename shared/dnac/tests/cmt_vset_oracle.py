#!/usr/bin/env python3
"""
Independent vector oracle for wave R1-C of the cometbft @709fd12b → C port
(shared/dnac/cmt_validator_set.{h,c}, cmt_results.{h,c}, cmt_params.{h,c},
cmt_genesis.{h,c}).

── PROVENANCE ──────────────────────────────────────────────────────────
Reference tree: cometbft @709fd12b4b18cf1442d43c5d34009392c7d674ed, the
pinned tarball (.claude/ref/cometbft-709fd12b-tree.tar.gz, SHA-256
0876957c...). The files this oracle encodes rules from, each hashed before
use and matching tasks/comet-port-map.md:

  types/validator.go       194 lines
    fe21832f8b1edd6e1f5adc151276efe092c5cf36c750ac2925b3332c097da7aa
  types/validator_set.go  1053 lines
    6c3a663aaf84fbee94735731eaba27d1a8e5269dd6e316e0b175595e32902221
  types/results.go          54 lines
    74de33a8e62eb9755258363b621d5b2137d834ead605b2acb97f004cbd35f830
  types/params.go          370 lines
    1766c8ec54f5932ce43c77f48a8358237b16428f3bddd69f2998e32a0c2e7746
  types/genesis.go         137 lines
    3f3bd9169368cbd0757a1d6cd88f279569dfa652ca059bb503072b17c16065f4
  types/validator_set_test.go 1678 lines
    f720c25cb837c425f2990e6bbb4307ed47eec30a74fd7d466abe255757ddc4dd
  spec/consensus/proposer-selection.md 323 lines
    b4a06738866bfe59241bee09449790bf435cfd6c5c53c145bc431c1f68cb8a1f

Encoding helpers are imported from cmt_pb_oracle.py (wave R1-A), which
derives them from the pinned .proto and .pb.go files and self-checks
against the REV 3.2 golden values before emitting anything.

── HOW THIS CAN LIE ────────────────────────────────────────────────────
 1. The SHA3-512 digests below are SELF-CONSISTENT FREEZES, not vectors
    published by cometbft: cometbft hashes with SHA-256 and the hash
    substitution is ours. They pin that our C agrees with an independent
    python implementation of the same construction, and that the shapes
    have not drifted. They do NOT prove the shape is the reference's —
    only reading the .go against the .c does.
 2. The PROPOSER SEQUENCES are different in kind and are the strongest
    thing here: PROP_SEL_1 is the literal expected string of
    validator_set_test.go:232-236, i.e. cometbft's OWN vector, and this
    oracle reproduces it from an independently written implementation of
    the algorithm. Agreement there is agreement with the reference, not
    with ourselves. It is checked before anything is emitted.
 3. The averaging cases are the reference's own table
    (validator_set_test.go:474-506); this oracle recomputes them.
 4. Nothing here exercises a 128-validator set, a real ML-DSA-87 key or
    the wire decoder. It pins ARITHMETIC and SHAPE.

Read-only: it opens nothing, writes nothing, and prints to stdout.

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cmt_pb_oracle import (        # noqa: E402
    H, c_array, c_digest, empty_hash, hexs, leaf_hash, m_exec_tx_result,
    m_hashed_params, m_public_key_mldsa87, m_simple_validator, merkle_proofs,
    merkle_root, pat,
)

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
MAX_TOTAL_VOTING_POWER = INT64_MAX // 8
PRIORITY_WINDOW_SIZE_FACTOR = 2


# ══ the reference's int64 arithmetic ═════════════════════════════════════
# Go int64 wraps; python does not. Every operation the reference performs
# on an int64 goes through wrap() so the two agree bit for bit.

def wrap(v):
    v &= (1 << 64) - 1
    return v - (1 << 64) if v >= (1 << 63) else v


def safe_add(a, b):
    """validator_set.go:993-1000."""
    if b > 0 and a > INT64_MAX - b:
        return -1, True
    if b < 0 and a < INT64_MIN - b:
        return -1, True
    return a + b, False


def safe_sub(a, b):
    """validator_set.go:1002-1009."""
    if b > 0 and a < INT64_MIN + b:
        return -1, True
    if b < 0 and a > INT64_MAX + b:
        return -1, True
    return a - b, False


def safe_add_clip(a, b):
    """validator_set.go:1011-1020."""
    c, over = safe_add(a, b)
    if over:
        return INT64_MIN if b < 0 else INT64_MAX
    return c


def safe_sub_clip(a, b):
    """validator_set.go:1022-1031."""
    c, over = safe_sub(a, b)
    if over:
        return INT64_MIN if b > 0 else INT64_MAX
    return c


def go_trunc_div(a, b):
    """Go's `/`: truncation toward zero, and MinInt64 / -1 == MinInt64."""
    if b == 0:
        raise ZeroDivisionError("integer divide by zero")
    if a == INT64_MIN and b == -1:
        return INT64_MIN
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def big_div(a, n):
    """(*big.Int).Div — Euclidean, which for n > 0 is floor division."""
    assert n > 0
    return a // n


# ══ the proposer-priority machine (validator_set.go) ═════════════════════
# An INDEPENDENT implementation, written from the .go and not from the C.

class Val:
    def __init__(self, address, power, prio=0):
        self.address = address
        self.power = power
        self.prio = prio

    def copy(self):
        return Val(self.address, self.power, self.prio)


def cmp_bytes(a, b):
    """Go bytes.Compare: common prefix, then length."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return -1 if a[i] < b[i] else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def compare_proposer_priority(v, other):
    """validator.go:65-85."""
    if v is None:
        return other
    if v.prio > other.prio:
        return v
    if v.prio < other.prio:
        return other
    r = cmp_bytes(v.address, other.address)
    if r < 0:
        return v
    if r > 0:
        return other
    raise AssertionError("Cannot compare identical validators")


def total_voting_power(vals):
    """validator_set.go:314-337."""
    s = 0
    for v in vals:
        s = safe_add_clip(s, v.power)
        assert s <= MAX_TOTAL_VOTING_POWER, "total voting power overflow"
    return s


def compute_avg(vals):
    """validator_set.go:196-209 — big.Int sum, Euclidean divide."""
    s = sum(v.prio for v in vals)
    avg = big_div(s, len(vals))
    assert INT64_MIN <= avg <= INT64_MAX
    return avg


def max_min_diff(vals):
    """validator_set.go:212-231 — both operations WRAP."""
    mx, mn = INT64_MIN, INT64_MAX
    for v in vals:
        mn = min(mn, v.prio)
        mx = max(mx, v.prio)
    diff = wrap(mx - mn)
    return wrap(-diff) if diff < 0 else diff


def rescale(vals, diff_max):
    """validator_set.go:158-179."""
    if diff_max <= 0:
        return
    diff = max_min_diff(vals)
    ratio = go_trunc_div(wrap(wrap(diff + diff_max) - 1), diff_max)
    if diff > diff_max:
        for v in vals:
            v.prio = go_trunc_div(v.prio, ratio)


def shift_by_avg(vals):
    """validator_set.go:241-249."""
    avg = compute_avg(vals)
    for v in vals:
        v.prio = safe_sub_clip(v.prio, avg)


def increment_once(vals):
    """validator_set.go:181-193."""
    for v in vals:
        v.prio = safe_add_clip(v.prio, v.power)
    res = None
    for v in vals:
        res = compare_proposer_priority(res, v)
    res.prio = safe_sub_clip(res.prio, total_voting_power(vals))
    return res


def increment(vals, times):
    """validator_set.go:131-153."""
    assert times > 0
    rescale(vals, PRIORITY_WINDOW_SIZE_FACTOR * total_voting_power(vals))
    shift_by_avg(vals)
    prop = None
    for _ in range(times):
        prop = increment_once(vals)
    return prop


def find_proposer(vals):
    """validator_set.go:351-359."""
    prop = None
    for v in vals:
        if prop is None or cmp_bytes(v.address, prop.address) != 0:
            prop = compare_proposer_priority(prop, v)
    return prop


def by_voting_power_key(v):
    """validator_set.go:851-856 — power DESC, address ASC."""
    return (-v.power, v.address)


def new_validator_set(valz):
    """validator_set.go:77-89 restricted to the ADD-ONLY case the vectors
    use: updateWithChangeSet(valz, false) with an empty starting set, which
    reduces to the -1.125*P entry penalty, rescale, centre and sort.

    Returns (validators, proposer). The proposer matters: :86's
    IncrementProposerPriority(1) STORES the one it elected (:152), and
    GetProposer (:341-349) returns THAT — it only falls back to
    findProposer when the field is unset (:345-347). The two differ, and
    they differ immediately: the elected validator has just been pushed
    back by P at :190, so it is no longer the one findProposer would pick.
    """
    vals = [v.copy() for v in valz]
    for v in vals:
        assert v.power > 0
    tvp = total_voting_power(vals)
    for v in vals:                                       # :512-530
        v.prio = wrap(-wrap(tvp + (tvp >> 3)))
    rescale(vals, PRIORITY_WINDOW_SIZE_FACTOR * tvp)     # :671
    shift_by_avg(vals)                                   # :672
    vals.sort(key=by_voting_power_key)                   # :674
    proposer = increment(vals, 1) if vals else None      # :85-87
    return vals, proposer


# ══ the reference's own vectors ══════════════════════════════════════════

# validator_set_test.go:232-236, TestProposerSelection1's literal expected
# string. This is cometbft's OWN answer; reproducing it from the algorithm
# above is the one leg of this oracle that is not self-referential.
PROP_SEL_1_EXPECTED = (
    "foo baz foo bar foo foo baz foo bar foo foo baz foo foo bar foo baz foo foo bar"
    " foo foo baz foo bar foo foo baz foo bar foo foo baz foo foo bar foo baz foo foo bar"
    " foo baz foo foo bar foo baz foo foo bar foo baz foo foo foo baz bar foo foo foo baz"
    " foo bar foo foo baz foo bar foo foo baz foo bar foo foo baz foo bar foo foo baz foo"
    " foo bar foo baz foo foo bar foo baz foo foo bar foo baz foo foo"
)


def prop_sel_1():
    """validator_set_test.go:221-241."""
    vals, proposer = new_validator_set([Val(b"foo", 1000), Val(b"bar", 300),
                                        Val(b"baz", 330)])
    out = []
    for _ in range(99):
        out.append(proposer.address.decode())
        proposer = increment(vals, 1)
    return " ".join(out)


def prop_sel_2_counts():
    """validator_set_test.go:296-334 — the proportionality leg."""
    a0 = bytes(20)
    a1 = bytes(19) + b"\x01"
    a2 = bytes(19) + b"\x02"
    vals, proposer = new_validator_set([Val(a0, 4), Val(a1, 5), Val(a2, 3)])
    counts = [0, 0, 0]
    for _ in range(120):
        counts[proposer.address[19]] += 1
        proposer = increment(vals, 1)
    return counts


def prop_sel_2_equal_power():
    """validator_set_test.go:248-259 — equal power goes in address order."""
    addrs = [bytes(20), bytes(19) + b"\x01", bytes(19) + b"\x02"]
    vals, proposer = new_validator_set([Val(a, 100) for a in addrs])
    seen = []
    for _ in range(15):
        seen.append(proposer.address[19])
        proposer = increment(vals, 1)
    return seen


def averaging_cases():
    """validator_set_test.go:508-560 — TestAveragingInIncrementProposerPriority.
    Every validator has ZERO voting power, so the whole effect is the
    centring step and the expected result is `prio - avg`."""
    cases = [
        ([(b"a", 1), (b"b", 2), (b"c", 3)], 1, 2),
        ([(b"a", 10), (b"b", -10), (b"c", 1)], 11, 0),
        ([(b"a", 100), (b"b", -10), (b"c", 1)], 1, 91 // 3),
    ]
    out = []
    for entries, times, avg in cases:
        vals = [Val(a, 0, p) for a, p in entries]
        got = [v.prio for v in vals]
        work = [v.copy() for v in vals]
        increment(work, times)
        by_addr = {v.address: v.prio for v in work}
        expect = [p - avg for _, p in entries]
        actual = [by_addr[a] for a, _ in entries]
        out.append((entries, times, avg, got, expect, actual))
    return out


def avg_proposer_priority_cases():
    """validator_set_test.go:474-506 — TestAvgProposerPriority. The two
    MaxInt64 / MinInt64 rows are exactly the ones an int64 accumulator gets
    wrong, which is why the C port carries a 128-bit one."""
    return [
        ([0, 0, 0], 0),
        ([INT64_MAX, 0, 0], INT64_MAX // 3),
        ([INT64_MAX, 0], INT64_MAX // 2),
        ([INT64_MAX, INT64_MAX], INT64_MAX),
        ([INT64_MIN, INT64_MIN], INT64_MIN),
    ]


# ══ hash vectors ═════════════════════════════════════════════════════════

# Pattern-filled ML-DSA-87 public keys. `pat` is cmt_pb_oracle's
# deterministic filler, so the C test builds the identical bytes.
KEY_SEEDS = (0x11, 0x22, 0x33, 0x44)
KEYS = [pat(2592, s) for s in KEY_SEEDS]
ADDRS = [hashlib.sha3_512(k).digest()[:32] for k in KEYS]


def validator_leaf(key, power):
    """validator.go:118-134 — the SimpleValidator marshal.

    `key` is the RAW 2592-byte ML-DSA-87 key: m_simple_validator wraps it
    in tendermint.crypto.PublicKey itself (cmt_pb_oracle.py:217-220), the
    same convention as m_validator (:223-227). Delta C-1: the first cut
    wrapped it here TOO, so every leaf carried PublicKey{PublicKey{key}}
    (2603 bytes instead of 2600) and every ValidatorsHash vector was wrong
    while the C was right. check() now pins the leaf length."""
    return m_simple_validator(key, power)


def by_voting_power_order(entries):
    """entries: [(key_index, power)] -> sorted per validator_set.go:851-856."""
    return sorted(entries, key=lambda e: (-e[1], ADDRS[e[0]]))


def validators_hash(entries):
    """validator_set.go:365-371 over ValidatorsByVotingPower order."""
    ordered = by_voting_power_order(entries)
    return merkle_root([validator_leaf(KEYS[i], p) for i, p in ordered])


def consensus_hash(max_bytes, max_gas):
    """params.go:272-290 — FLAT hash of the HashedParams marshal."""
    return H(m_hashed_params(max_bytes, max_gas))


def results_hash(results):
    """results.go:22-24 over the marshalled ExecTxResults."""
    return merkle_root([m_exec_tx_result(*r) for r in results])


# ══ self-check ═══════════════════════════════════════════════════════════

def check():
    problems = []

    got = prop_sel_1()
    if got != PROP_SEL_1_EXPECTED:
        problems.append(
            "TestProposerSelection1: this oracle's independent algorithm "
            "does not reproduce cometbft's own expected string.\n"
            "    want %s...\n    got  %s..."
            % (PROP_SEL_1_EXPECTED[:60], got[:60]))

    counts = prop_sel_2_counts()
    if counts != [40, 50, 30]:
        problems.append("TestProposerSelection2 counts: want [40, 50, 30], "
                        "got %r" % (counts,))

    seen = prop_sel_2_equal_power()
    if seen != [0, 1, 2] * 5:
        problems.append("TestProposerSelection2 equal power: want the "
                        "address order repeated, got %r" % (seen,))

    for prios, want in avg_proposer_priority_cases():
        vals = [Val(bytes([i]), 0, p) for i, p in enumerate(prios)]
        got_avg = compute_avg(vals)
        if got_avg != want:
            problems.append("computeAvgProposerPriority(%r): want %d got %d"
                            % (prios, want, got_avg))

    for entries, times, avg, _pre, expect, actual in averaging_cases():
        if expect != actual:
            problems.append(
                "TestAveragingInIncrementProposerPriority(%r, times=%d, "
                "avg=%d): want %r got %r" % (entries, times, avg, expect,
                                             actual))

    # REV 3.2 golden value, re-derived here rather than pasted.
    hp = m_hashed_params(22020096, -1)
    if hexs(hp) != "088080c00a10ffffffffffffffffff01":
        problems.append("HashedParams{22020096, -1} != the REV 3.2 golden "
                        "value; got %s" % hexs(hp))

    # An empty result marshals to zero bytes and its leaf is H(0x00).
    if m_exec_tx_result(0, b"", 0, 0) != b"":
        problems.append("a wholly zero ExecTxResult must marshal to 0 bytes")
    if leaf_hash(b"") != H(b"\x00"):
        problems.append("the nil leaf must be H(0x00)")

    # An empty validator set hashes to the empty tree's root.
    if validators_hash([]) != empty_hash():
        problems.append("Hash() of an empty validator set must be H(\"\")")

    # Delta C-1 — the SimpleValidator leaf is EXACTLY one PublicKey deep:
    #   field 1 tag (1) + len uvarint(2595) (2)
    #     + PublicKey: field 9 tag (1) + len uvarint(2592) (2) + key (2592)
    #   + field 2 tag (1) + varint(1) (1)                       = 2600.
    # The R1-A golden V_SIMPLEVAL_FULL (cmt_pb_oracle.py:610) is built the
    # same way from a raw key, and the C agreed with it in stage A.
    leaf = validator_leaf(KEYS[0], 1)
    if len(leaf) != 2600:
        problems.append("SimpleValidator leaf must be 2600 bytes (one "
                        "PublicKey wrap), got %d" % len(leaf))
    if leaf != m_simple_validator(KEYS[0], 1):
        problems.append("validator_leaf must equal the R1-A encoder's "
                        "m_simple_validator on the raw key")

    return problems


# ══ emit ═════════════════════════════════════════════════════════════════

def emit():
    out = []

    def add(s):
        out.append(s)

    add("/* ── addresses: SHA3-512(pubkey)[0..31] ────────────────────── */")
    add("/*  the derivation this tree already uses for a witness id:      */")
    add("/*  nodus_witness_chain_config.c:637-652 derive_witness_id       */")
    for i, s in enumerate(KEY_SEEDS):
        add("/* KEY_%d = pat(2592, 0x%02x) -> address %s */"
            % (i, s, hexs(ADDRS[i])[:32] + "..."))
        add(c_array("V_ADDR_%d" % i, ADDRS[i]))

    add("")
    add("/* ── one validator's SimpleValidator leaf (validator.go:118) ── */")
    leaf1 = validator_leaf(KEYS[0], 1)
    add("/* len = %d, at most CMT_VALIDATOR_BYTES_MAX = 2609 */" % len(leaf1))
    add(c_digest("V_VAL_LEAF_K0_P1", leaf1))

    add("")
    add("/* ── ValidatorsHash, ValidatorsByVotingPower order ──────────── */")
    add("/* empty set -> the empty tree's root, H(\"\") */")
    add(c_array("V_VSET_HASH_EMPTY", validators_hash([])))
    add("/* one validator: key 0, power 10 */")
    add(c_array("V_VSET_HASH_1", validators_hash([(0, 10)])))
    add("/* three: (k0,10) (k1,30) (k2,20) -> power DESC k1,k2,k0 */")
    add(c_array("V_VSET_HASH_3", validators_hash([(0, 10), (1, 30), (2, 20)])))
    add("/* four with a POWER TIE broken by ASCENDING address:")
    ordered = by_voting_power_order([(0, 5), (1, 5), (2, 5), (3, 9)])
    for i, p in ordered:
        add("     key %d power %d addr %s..." % (i, p, hexs(ADDRS[i])[:16]))
    add("*/")
    add(c_array("V_VSET_HASH_4_TIE",
                validators_hash([(0, 5), (1, 5), (2, 5), (3, 9)])))
    add("/* the tie order as key indices, for the test to assert directly */")
    add("static const int V_VSET_4_TIE_ORDER[4] = { %s };"
        % ", ".join(str(i) for i, _ in ordered))

    add("")
    add("/* ── ConsensusHash = H(HashedParams marshal), FLAT ──────────── */")
    add("/* DefaultConsensusParams: MaxBytes 22020096, MaxGas -1 */")
    add("/* preimage = %s */" % hexs(m_hashed_params(22020096, -1)))
    add(c_array("V_CONSENSUS_HASH_DEFAULT", consensus_hash(22020096, -1)))
    add("/* a second point so the test cannot pass on one constant */")
    add("/* preimage = %s */" % hexs(m_hashed_params(1, 0)))
    add(c_array("V_CONSENSUS_HASH_1_0", consensus_hash(1, 0)))

    add("")
    add("/* ── LastResultsHash (results.go:22-24) ─────────────────────── */")
    add("/* empty list -> H(\"\") */")
    add(c_array("V_RESULTS_HASH_0", results_hash([])))
    add("/* one wholly ZERO result: marshal is 0 bytes, leaf is H(0x00) */")
    add(c_array("V_RESULTS_HASH_1_ZERO", results_hash([(0, b"", 0, 0)])))
    add("/* three results, the middle one zero */")
    r3 = [(1, b"\xaa\xbb", 21000, 20000), (0, b"", 0, 0), (7, b"\x01", -1, 5)]
    for r in r3:
        add("/*   ExecTxResult%r -> %s */" % ((r,), hexs(m_exec_tx_result(*r))))
    add(c_array("V_RESULTS_HASH_3", results_hash(r3)))
    add("/* proof of index 1 in that 3-item tree */")
    _root, proofs = merkle_proofs([m_exec_tx_result(*r) for r in r3])
    add("/*   %d aunts */" % len(proofs[1]))
    for j, a in enumerate(proofs[1]):
        add(c_array("V_RESULTS_PROOF1_AUNT%d" % j, a))

    add("")
    add("/* ── TestProposerSelection1 (validator_set_test.go:221-241) ─── */")
    add("/* cometbft's OWN expected string, reproduced by this oracle's")
    add(" * independent implementation. 0 = bar, 1 = baz, 2 = foo. */")
    seq = prop_sel_1().split(" ")
    idx = {"bar": 0, "baz": 1, "foo": 2}
    add("#define V_PROP_SEL_1_N %d" % len(seq))
    add("static const unsigned char V_PROP_SEL_1[%d] = {" % len(seq))
    for i in range(0, len(seq), 20):
        add("    " + " ".join("%d," % idx[s] for s in seq[i:i + 20]))
    add("};")

    add("")
    add("/* ── TestProposerSelection2 proportionality (:296-334) ──────── */")
    add("static const int V_PROP_SEL_2_COUNTS[3] = { %s };"
        % ", ".join(str(c) for c in prop_sel_2_counts()))

    return "\n".join(out)


if __name__ == "__main__":
    problems = check()
    if problems:
        sys.stderr.write("R1-C ORACLE SELF-CHECK FAILED — STOP:\n")
        for p in problems:
            sys.stderr.write("  " + p + "\n")
        sys.exit(1)
    sys.stderr.write("R1-C oracle: cometbft's own TestProposerSelection1/2 "
                     "vectors reproduced from an independent implementation\n")
    print("/* GENERATED by shared/dnac/tests/cmt_vset_oracle.py "
          "— do not edit */")
    print(emit())
