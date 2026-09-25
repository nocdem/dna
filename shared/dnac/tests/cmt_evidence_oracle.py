#!/usr/bin/env python3
"""
cometbft @709fd12b C PORT (wave R1-D) — INDEPENDENT ORACLE for the evidence
vectors pinned by nodus/tests/test_cmt_evidence.c.

PROVENANCE: this file computes its vectors from the pinned Go SOURCE
(types/evidence.go) and from the K-1 rev 2 wire rules, NOT by reading or
transcribing shared/dnac/cmt_evidence.c. It shares no code and no constant
table with the C implementation.

It DOES import shared/dnac/tests/cmt_pb_oracle.py, wave R1-A's independent
proto3 encoder — which already carries `m_duplicate_vote_evidence`,
`m_evidence_duplicate`, `m_vote` and the RFC 6962 Merkle walk — rather than
writing a THIRD encoder to keep in step. That file is itself independent of
the C codec; see its own provenance header. Hash primitive: python3
hashlib.sha3_512 (stdlib, FIPS-202), independent of
shared/crypto/hash/qgp_sha3.c.

WHAT THE TWO HASHES ARE, because they are easy to confuse:
  · DuplicateVoteEvidence.Hash()  (evidence.go:106-108) = a FLAT
    SHA3-512 of the BARE DuplicateVoteEvidence marshal. `EvidenceList.Has`
    compares these.
  · EvidenceList.Hash()           (evidence.go:450-461) = the MERKLE root
    whose leaves are those same bare marshals. This is the header's
    EvidenceHash (block.go:1383, D-19 rev 6 item 8).
Neither is ever taken over the `Evidence` oneof WRAPPER.

Run:  python3 shared/dnac/tests/cmt_evidence_oracle.py
The emitted C arrays are pinned verbatim in nodus/tests/test_cmt_evidence.c.

Reference pins (SHA-256 verified against tasks/comet-port-map.md before use):
  types/evidence.go   5a41f27f0de4a63412f7e8a64f288b81d8fa52502102ad5b111214211c091fde
  types/block.go      2094420e26fa23d4b6a592a06e7953025541973694bd96ff9c8e5d9911162109
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cmt_pb_oracle import (                              # noqa: E402
    m_duplicate_vote_evidence, m_evidence_duplicate, m_vote,
    m_part_set_header, m_block_id,
    H, empty_hash, leaf_hash, merkle_root,
    c_array, c_vec, pat, hexs,
)

# ── the fixture ───────────────────────────────────────────────────────
#
# Two PRECOMMIT votes by the SAME validator at the SAME height and round
# for DIFFERENT blocks — the shape a duplicate-vote evidence has
# (evidence.go:34 "a single validator signing two conflicting votes").
#
# Every field is chosen so that both votes pass Vote.ValidateBasic
# (vote.go:275-353): a valid vote type, height > 0, round >= 0, a COMPLETE
# BlockID (64-byte hash, non-zero part total, 64-byte part hash), a 32-byte
# validator address, a non-negative index, a non-empty signature no longer
# than MaxSignatureSize, and — because a non-nil precommit may carry an
# extension only WITH its signature — neither an extension nor an
# extension signature.
#
# The two BlockIDs are ordered so that Key(A) < Key(B), which
# DuplicateVoteEvidence.ValidateBasic REQUIRES (evidence.go:140-143).
# Key() is the hash bytes followed by the marshalled PartSetHeader
# (block.go:1474-1483), so the first hash byte decides it here: 0x10 < 0x90.

PSH_A = (7, pat(64, 0x20))
PSH_B = (7, pat(64, 0x21))
BID_A = (pat(64, 0x10), PSH_A)
BID_B = (pat(64, 0x90), PSH_B)

TS_VOTE = (1700000000, 123456789)
TS_EV = (1700000001, 500)

VAL_ADDR = pat(32, 0x30)
SIG_A = pat(64, 0x40)
SIG_B = pat(64, 0x41)

PRECOMMIT = 2

# m_vote(vtype, height, round_, block_id, timestamp, validator_address,
#        validator_index, signature, extension, extension_signature)
VOTE_A = (PRECOMMIT, 9, 3, BID_A, TS_VOTE, VAL_ADDR, 1, SIG_A, b"", b"")
VOTE_B = (PRECOMMIT, 9, 3, BID_B, TS_VOTE, VAL_ADDR, 1, SIG_B, b"", b"")

# A SECOND, different piece of evidence — same shape, another height — so
# the two-item list has two distinct leaves and `Has` has a true negative.
VOTE_C = (PRECOMMIT, 11, 0, BID_A, TS_VOTE, VAL_ADDR, 1, SIG_A, b"", b"")
VOTE_D = (PRECOMMIT, 11, 0, BID_B, TS_VOTE, VAL_ADDR, 1, SIG_B, b"", b"")

# m_duplicate_vote_evidence(vote_a, vote_b, total_voting_power,
#                           validator_power, timestamp)
DVE_1 = (VOTE_A, VOTE_B, 150, 100, TS_EV)
DVE_2 = (VOTE_C, VOTE_D, 150, 100, TS_EV)


def dve_bytes(dve):
    """evidence.go:95-103 Bytes() — the BARE message, never the wrapper."""
    return m_duplicate_vote_evidence(*dve)


def dve_hash(dve):
    """evidence.go:106-108 Hash() — FLAT tmhash.Sum(Bytes())."""
    return H(dve_bytes(dve))


def evidence_list_hash(dves):
    """evidence.go:450-461 EvidenceList.Hash() — MERKLE over Bytes()."""
    return merkle_root([dve_bytes(d) for d in dves])


# ══ self-check ════════════════════════════════════════════════════════

def check():
    """Properties that must hold if the readings above are right.
    A failure is a STOP condition, not something to paper over."""
    fails = []

    def want(name, cond, detail=""):
        if not cond:
            fails.append("%s %s" % (name, detail))

    # The wrapper is NOT the hashed preimage: the Evidence oneof adds a tag
    # and a length prefix, so the two byte strings differ. If this ever
    # passed, the port would be hashing the wrong thing.
    bare = dve_bytes(DVE_1)
    wrapped = m_evidence_duplicate(bare)
    want("wrapper-vs-bare", bare != wrapped,
         "the Evidence wrapper must not equal the bare message")
    want("wrapper-length", len(wrapped) > len(bare),
         "the wrapper adds a tag and a length prefix")

    # An empty list hashes to the empty tree's root, NOT to zeroes.
    want("empty-root", evidence_list_hash([]) == empty_hash(),
         "an empty EvidenceList must hash to H(\"\")")
    want("empty-not-zero", evidence_list_hash([]) != bytes(64),
         "H(\"\") is not 64 zero bytes")

    # A one-item list is leafHash(item), not the item's flat hash: the
    # Merkle domain separator 0x00 is what distinguishes them.
    want("one-item", evidence_list_hash([DVE_1]) == leaf_hash(bare),
         "a one-item root is leafHash(bytes)")
    want("one-item-not-flat", evidence_list_hash([DVE_1]) != dve_hash(DVE_1),
         "the Merkle root of one item is NOT the item's flat Hash()")

    # The two fixtures must actually differ, or the two-item vectors and
    # the Has negative would prove nothing.
    want("distinct", dve_hash(DVE_1) != dve_hash(DVE_2),
         "the two fixtures must be distinct")

    # The ORDER rule: Key(A) < Key(B) for the fixtures, and the reversed
    # pair must violate it. Key() = hash ‖ marshal(PartSetHeader).
    def key(bid):
        h, psh = bid
        return h + m_part_set_header(*psh)

    want("order", key(BID_A) < key(BID_B),
         "the fixture must satisfy Key(A) < Key(B)")
    want("order-reversed", not (key(BID_B) < key(BID_A)),
         "the reversed pair must violate the order rule")
    want("order-equal", not (key(BID_A) < key(BID_A)),
         "an equal pair must violate the order rule (>= 0 refuses)")

    # BlockID.Key is a concatenation, so it is not the marshalled BlockID.
    want("key-not-marshal", key(BID_A) != m_block_id(*BID_A),
         "Key() is hash ‖ psh-marshal, not the BlockID marshal")

    return fails


# ══ emission ══════════════════════════════════════════════════════════

def emit():
    out = []

    def add(s):
        out.append(s)

    bare1 = dve_bytes(DVE_1)
    bare2 = dve_bytes(DVE_2)

    add("/* ══ evidence.go:95-103 Bytes() — the BARE DuplicateVoteEvidence"
        " ══ */")
    add(c_vec("V_DVE1_BYTES", bare1))
    add(c_vec("V_DVE2_BYTES", bare2))
    add("/* the Evidence WRAPPER over the same item — a different string,"
        " never hashed */")
    add(c_vec("V_DVE1_WRAPPED", m_evidence_duplicate(bare1)))

    add("")
    add("/* ══ evidence.go:106-108 Hash() — FLAT SHA3-512 of Bytes() ══ */")
    add(c_array("V_DVE1_HASH", dve_hash(DVE_1)))
    add(c_array("V_DVE2_HASH", dve_hash(DVE_2)))

    add("")
    add("/* ══ evidence.go:450-461 EvidenceList.Hash() — MERKLE root ══ */")
    add("/* 0 items: the empty tree's root H(\"\"), block.go:1383 */")
    add(c_array("V_EVLIST0_ROOT", evidence_list_hash([])))
    add("/* 1 item: leafHash(bytes) = H(0x00 ‖ bytes) */")
    add(c_array("V_EVLIST1_ROOT", evidence_list_hash([DVE_1])))
    add("/* 2 items: innerHash(leaf(a), leaf(b)) */")
    add(c_array("V_EVLIST2_ROOT", evidence_list_hash([DVE_1, DVE_2])))

    add("")
    add("/* ══ anchors ══ */")
    add('/* SHA3-512("")                 = %s */' % hexs(empty_hash()))
    add('/* Key(BID_A) first byte 0x10 < Key(BID_B) first byte 0x90 */')
    return "\n".join(out)


if __name__ == "__main__":
    problems = check()
    if problems:
        sys.stderr.write("ORACLE SELF-CHECK FAILED — STOP:\n")
        for p in problems:
            sys.stderr.write("  " + p + "\n")
        sys.exit(1)
    sys.stderr.write("cmt_evidence_oracle: self-check passed\n")
    print("/* GENERATED by shared/dnac/tests/cmt_evidence_oracle.py"
          " — do not edit */")
    print(emit())
