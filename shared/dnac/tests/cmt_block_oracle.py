#!/usr/bin/env python3
"""
cometbft @709fd12b C PORT (wave R1-B) — INDEPENDENT ORACLE for the block,
header, commit, vote, proposal and part-set vectors pinned by
nodus/tests/test_cmt_block.c, test_cmt_vote.c and test_cmt_part_set.c.

PROVENANCE: this file computes its vectors from the pinned Go SOURCE
(types/block.go, vote.go, proposal.go, canonical.go, part_set.go, tx.go,
encoding_helper.go) and from the K-1 rev 2 wire rules, NOT by reading or
transcribing shared/dnac/cmt_block.c, cmt_vote.c, cmt_proposal.c,
cmt_canonical.c or cmt_part_set.c. It shares no code and no constant table
with the C implementation.

It DOES import shared/dnac/tests/cmt_pb_oracle.py, wave R1-A's independent
proto3 encoder, rather than re-implementing the wire rules a second time:
that file is itself independent of the C codec (see its own provenance
header), and re-deriving proto3 here would produce a THIRD encoder to keep
in step without adding any independence. Hash primitive: python3
hashlib.sha3_512 (stdlib, FIPS-202), independent of
shared/crypto/hash/qgp_sha3.c.

Run:  python3 shared/dnac/tests/cmt_block_oracle.py
The emitted C arrays are pinned verbatim in the three test files.

Reference pins (SHA-256 verified against tasks/comet-port-map.md before use):
  types/block.go            2094420e26fa23d4b6a592a06e7953025541973694bd96ff9c8e5d9911162109
  types/vote.go             dd978df4530187c34902fad06ba1f7065896ece92b68d07d3a9bfc55ddb82e0f
  types/proposal.go         0b56660bee6071267b75c9dabe148036cb96c814f640f4e4323baa59af44eba0
  types/canonical.go        868e059415a616344f955c4539f9e0e30f38d24341e531563b8e38283f1edc33
  types/part_set.go         10101396b373475d18f81235a829c6d55341d2146ac2a667e851f650f5f44379
  types/tx.go               186fd6822ee915c2c0daa2426fceaf60ac7b00859df8c70b2c540480b0747091
  types/encoding_helper.go  3deeeaa72d628f5d0f9d8435ec8dbffbfbb492b3cc055bcf745c47a4e9105815
  types/params.go           1766c8ec54f5932ce43c77f48a8358237b16428f3bddd69f2998e32a0c2e7746
  crypto/merkle/tree.go     1dff4c0a658b53091cbca57ee25dc252b85ac1d195d3846cb10c568bbeb5a453

── SPEC (frozen; the reference lines these vectors implement) ────────────
Header.Hash (block.go:445-480) is the RFC-6962 Merkle root over FOURTEEN
leaves, in this order:
  [0]  Version.Marshal()               bare tendermint.version.Consensus
  [1]  cdcEncode(ChainID)              StringValue{1}, nil when empty
  [2]  cdcEncode(Height)               Int64Value{1}, EMPTY (not nil) at 0
  [3]  StdTimeMarshal(Time)            bare google.protobuf.Timestamp
  [4]  LastBlockID.ToProto().Marshal() bare BlockID; zero → 12 00
  [5]  cdcEncode(LastCommitHash)       BytesValue{1}, nil when empty
  [6]  cdcEncode(DataHash)
  [7]  cdcEncode(ValidatorsHash)
  [8]  cdcEncode(NextValidatorsHash)
  [9]  cdcEncode(ConsensusHash)
  [10] cdcEncode(AppHash)
  [11] cdcEncode(LastResultsHash)
  [12] cdcEncode(EvidenceHash)
  [13] cdcEncode(ProposerAddress)
A nil or empty leaf hashes to H(0x00) (merkle/hash.go:21-23), so the
"nil vs empty" distinction of cdcEncode never changes a byte.
Header.Hash is NIL when ValidatorsHash is empty (:446-448).

Commit.Hash  (block.go:935-954) = Merkle over the MARSHALLED CommitSig of
             every entry, in list order. The empty commit → H("").
Data.Hash    (block.go:1302-1311 → tx.go:45-50) = Merkle over SHA3-512 of
             each transaction.
VoteSignBytes / ProposalSignBytes (vote.go:148-156, proposal.go:110-118)
             = uvarint(len) ‖ CanonicalVote / CanonicalProposal.
PartSet      (part_set.go:194-222) = the data cut into `partSize` chunks,
             the root and per-part proofs from ProofsFromByteSlices.

DNA size substitutions (umbrella rev 3 §10.8): SHA3-512 / 64-byte hashes,
signature 4627, public key 2592, address 32, chain id 32 raw bytes.

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cmt_pb_oracle import (                                    # noqa: E402
    GO_ZERO_TIME,
    m_consensus, m_timestamp, m_block_id,
    m_int64value, m_stringvalue, m_bytesvalue,
    m_commit_sig, m_commit, m_vote, m_proposal,
    m_canonical_vote, m_canonical_proposal,
    marshal_delimited,
    empty_hash, leaf_hash, merkle_root, merkle_proofs,
    c_array, c_digest, hexs, pat,
)

# ══ helpers ═══════════════════════════════════════════════════════════


def sha3(b):
    return hashlib.sha3_512(b).digest()


def cdc_bytes(b):
    """types/encoding_helper.go:32-40 — BytesValue{1}, nil when empty
    (types/utils.go:21-29 isEmpty). A nil leaf and an empty leaf hash
    alike, so b"" stands for both."""
    return m_bytesvalue(b) if b else b""


def cdc_string(s):
    """encoding_helper.go:14-22 — StringValue{1}, nil when empty."""
    return m_stringvalue(s) if s else b""


def cdc_int64(v):
    """encoding_helper.go:23-31 — Int64Value{1}. NEVER nil: an int64 is
    not a container, so isEmpty falls to its default. At 0 the encoding is
    EMPTY but not nil, which hashes the same."""
    return m_int64value(v)


def header_leaves(version, chain_id, height, time_, last_block_id,
                  last_commit_hash, data_hash, validators_hash,
                  next_validators_hash, consensus_hash, app_hash,
                  last_results_hash, evidence_hash, proposer_address):
    """block.go:464-479, in that order."""
    return [
        m_consensus(*version),
        cdc_string(chain_id),
        cdc_int64(height),
        m_timestamp(time_),
        m_block_id(*last_block_id),
        cdc_bytes(last_commit_hash),
        cdc_bytes(data_hash),
        cdc_bytes(validators_hash),
        cdc_bytes(next_validators_hash),
        cdc_bytes(consensus_hash),
        cdc_bytes(app_hash),
        cdc_bytes(last_results_hash),
        cdc_bytes(evidence_hash),
        cdc_bytes(proposer_address),
    ]


def header_hash(**kw):
    return merkle_root(header_leaves(**kw))


def commit_hash(signatures):
    """block.go:935-954 — Merkle over the marshalled CommitSig entries."""
    return merkle_root([m_commit_sig(*s) for s in signatures])


def data_hash(txs):
    """block.go:1302-1311 via tx.go:29-31 and :47-49."""
    return merkle_root([sha3(tx) for tx in txs])


def part_set(data, part_size):
    """part_set.go:194-222 — the split, the root and the proofs."""
    total = (len(data) + part_size - 1) // part_size
    parts = [data[i * part_size:min(len(data), (i + 1) * part_size)]
             for i in range(total)]
    root, proofs = merkle_proofs(parts)
    return total, parts, root, proofs


# ══ fixtures ══════════════════════════════════════════════════════════

CHAIN     = pat(32, 0x50)             # 32 raw bytes in the proto `string`
ADDR      = pat(32, 0x40)
H_LCOMMIT = pat(64, 0x11)
H_DATA    = pat(64, 0x22)
H_VALS    = pat(64, 0x33)
H_NEXT    = pat(64, 0x44)
H_CONS    = pat(64, 0x55)
H_APP     = pat(64, 0x66)
H_RESULTS = pat(64, 0x77)
H_EVID    = pat(64, 0x88)
PSH_HASH  = pat(64, 0x99)
LBID_HASH = pat(64, 0xAA)
SIG_S     = pat(9, 0x60)
TS_A      = (1700000000, 123456789)
TS_B      = (1700000001, 0)

FULL_HEADER = dict(
    version=(11, 7),
    chain_id=CHAIN,
    height=1234567,
    time_=TS_A,
    last_block_id=(LBID_HASH, (9, PSH_HASH)),
    last_commit_hash=H_LCOMMIT,
    data_hash=H_DATA,
    validators_hash=H_VALS,
    next_validators_hash=H_NEXT,
    consensus_hash=H_CONS,
    app_hash=H_APP,
    last_results_hash=H_RESULTS,
    evidence_hash=H_EVID,
    proposer_address=ADDR,
)

# A genesis-like header: height 1, a ZERO LastBlockID (leaf 12 00), the
# empty-tree root for the three body hashes, and an EMPTY AppHash and
# LastResultsHash, whose leaves are therefore the nil leaf H(0x00).
GENESIS_HEADER = dict(
    version=(11, 0),
    chain_id=CHAIN,
    height=1,
    time_=GO_ZERO_TIME,
    last_block_id=(b"", (0, b"")),
    last_commit_hash=empty_hash(),
    data_hash=empty_hash(),
    validators_hash=H_VALS,
    next_validators_hash=H_VALS,
    consensus_hash=H_CONS,
    app_hash=b"",
    last_results_hash=b"",
    evidence_hash=empty_hash(),
    proposer_address=ADDR,
)

BID_A  = (LBID_HASH, (9, PSH_HASH))
BID_NIL = (b"", (0, b""))

# {Absent, Commit, Nil}: block.go:614-620, :101-123.
COMMIT_SIGS = [
    (1, b"",       GO_ZERO_TIME, b""),        # Absent — 15 bytes
    (2, ADDR,      TS_A,         SIG_S),      # Commit
    (3, ADDR,      TS_B,         b"\x01"),    # Nil
]

def part_payload(n):
    """byte i = (0x11 + 7*i) mod 251.

    The modulus is 251, not 256, ON PURPOSE. cmt_pb_oracle's pat() has a
    period of 256, which DIVIDES the 65 536-byte part size, so every full
    part of a pat() buffer is byte-identical to every other — and a test
    built on that could not tell a correct proof from a proof for the
    wrong part. 251 is prime and does not divide 65 536, so no two parts
    of this buffer are equal.
    """
    return bytes((0x11 + 7 * i) % 251 for i in range(n))


PART_DATA = part_payload(200000)
PART_SIZE = 65536                             # types/params.go:19


# ══ self-check against values pinned elsewhere ════════════════════════

def check():
    problems = []
    # REV 3.2 golden: CanonicalVote{PRECOMMIT, h=1, r=0, nil, zero-ts,
    # chain="ab"} MarshalDelimited begins with 1c.
    cv = m_canonical_vote(2, 1, 0, None, GO_ZERO_TIME, b"ab")
    want = bytes.fromhex(
        "0802110100000000000000" "2a0b088092b8c398feffffff01" "32026162")
    if cv != want:
        problems.append("CanonicalVote REV 3.2 golden: %s" % hexs(cv))
    if marshal_delimited(cv)[0] != 0x1c:
        problems.append("MarshalDelimited prefix is not 1c")
    # REV 3.2 golden: the zero BlockID marshals to 12 00 and its leaf is
    # SHA3-512(00 1200).
    if m_block_id(*BID_NIL) != bytes.fromhex("1200"):
        problems.append("zero BlockID is not 1200")
    if not hexs(leaf_hash(m_block_id(*BID_NIL))).startswith("6870f405"):
        problems.append("leaf(zero BlockID) does not start 6870f405")
    if not hexs(empty_hash()).startswith("a69f73cc"):
        problems.append('SHA3-512("") does not start a69f73cc')
    if not hexs(leaf_hash(b"")).startswith("7127aab2"):
        problems.append("leaf(nil) does not start 7127aab2")
    # An Absent CommitSig is the 15-byte REV 3.2 vector.
    if m_commit_sig(1, b"", GO_ZERO_TIME, b"") != bytes.fromhex(
            "08011a0b088092b8c398feffffff01"):
        problems.append("Absent CommitSig is not the 15-byte vector")
    # The empty commit hashes to H("") — D-19 rev 6 item 4.
    if commit_hash([]) != empty_hash():
        problems.append("empty Commit.Hash is not H(\"\")")
    # cdcEncode(int64 0) is EMPTY but not nil, and hashes like nil.
    if cdc_int64(0) != b"":
        problems.append("cdcEncode(0) is not empty")
    return problems


# ══ emit ══════════════════════════════════════════════════════════════

def emit():
    out = []
    add = out.append

    add("/* ══ Header.Hash ══ */")
    add("/* leaves of the fully populated header (block.go:464-479) */")
    for i, leaf in enumerate(header_leaves(**FULL_HEADER)):
        add("/*   [%2d] %d bytes %s */"
            % (i, len(leaf), hexs(leaf)[:32] + ("…" if len(leaf) > 16 else "")))
    add(c_array("V_HEADER_FULL_HASH", header_hash(**FULL_HEADER)))
    add(c_array("V_HEADER_GENESIS_HASH", header_hash(**GENESIS_HEADER)))
    add('/* leaf[4] of the genesis header = SHA3-512(00 ‖ 1200) = %s */'
        % hexs(leaf_hash(m_block_id(*BID_NIL))))
    add('/* leaf[10] and leaf[11] of the genesis header = SHA3-512(00) = %s */'
        % hexs(leaf_hash(b"")))
    add("/* the marshalled leaves, concatenated, so the C test can pin the")
    add(" * encoding of each one before the tree is built */")
    add(c_array("V_HEADER_FULL_LEAF0", header_leaves(**FULL_HEADER)[0]))
    add(c_array("V_HEADER_FULL_LEAF1", header_leaves(**FULL_HEADER)[1]))
    add(c_array("V_HEADER_FULL_LEAF2", header_leaves(**FULL_HEADER)[2]))
    add(c_array("V_HEADER_FULL_LEAF3", header_leaves(**FULL_HEADER)[3]))
    add(c_digest("V_HEADER_FULL_LEAF4", header_leaves(**FULL_HEADER)[4]))
    add(c_digest("V_HEADER_FULL_LEAF13", header_leaves(**FULL_HEADER)[13]))

    add("")
    add("/* ══ Commit.Hash ══ */")
    add(c_array("V_COMMIT_EMPTY_HASH", commit_hash([])))
    add(c_array("V_COMMIT_THREE_HASH", commit_hash(COMMIT_SIGS)))
    add(c_array("V_COMMIT_SIG_ABSENT", m_commit_sig(*COMMIT_SIGS[0])))
    add(c_array("V_COMMIT_SIG_COMMIT", m_commit_sig(*COMMIT_SIGS[1])))
    add(c_array("V_COMMIT_SIG_NIL", m_commit_sig(*COMMIT_SIGS[2])))
    add(c_digest("V_COMMIT_THREE_WIRE",
                 m_commit(9, 2, BID_A, COMMIT_SIGS)))

    add("")
    add("/* ══ Data.Hash ══ */")
    add(c_array("V_DATA_HASH_0", data_hash([])))
    add(c_array("V_DATA_HASH_1", data_hash([b"tx0"])))
    add(c_array("V_DATA_HASH_3", data_hash([b"tx0", b"", b"tx2"])))
    add('/* SHA3-512("")    = %s */' % hexs(sha3(b"")))
    add('/* SHA3-512("tx0") = %s */' % hexs(sha3(b"tx0")))

    add("")
    add("/* ══ VoteSignBytes (vote.go:148-156) ══ */")
    add("/* REV 3.2 golden: PRECOMMIT, h=1, r=0, nil BlockID, zero time,")
    add(' * chain id "ab" — 28 bytes, MarshalDelimited prefix 1c */')
    add(c_array("V_VOTE_SIGN_GOLDEN",
                marshal_delimited(
                    m_canonical_vote(2, 1, 0, None, GO_ZERO_TIME, b"ab"))))
    add("/* a full vote: PRECOMMIT, h=1234567, r=3, complete BlockID,")
    add(" * a real timestamp and the 32-byte chain id */")
    add(c_array("V_VOTE_SIGN_FULL",
                marshal_delimited(
                    m_canonical_vote(2, 1234567, 3, BID_A, TS_A, CHAIN))))
    add("/* the same vote on the wire (types.Vote), for the codec test */")
    add(c_digest("V_VOTE_FULL_WIRE",
                 m_vote(2, 1234567, 3, BID_A, TS_A, ADDR, 5, SIG_S,
                        b"", b"")))

    add("")
    add("/* ══ ProposalSignBytes (proposal.go:110-118) ══ */")
    add("/* POLRound -1 widens to an int64 varint: 10 bytes of two's")
    add(" * complement (canonical.go:47) */")
    add(c_array("V_PROPOSAL_SIGN_POLNEG",
                marshal_delimited(
                    m_canonical_proposal(32, 1234567, 3, -1, BID_A,
                                         TS_A, CHAIN))))
    add(c_array("V_PROPOSAL_SIGN_POL0",
                marshal_delimited(
                    m_canonical_proposal(32, 1234567, 3, 0, BID_A,
                                         TS_A, CHAIN))))
    add(c_digest("V_PROPOSAL_FULL_WIRE",
                 m_proposal(32, 1234567, 3, -1, BID_A, TS_A, SIG_S)))

    add("")
    add("/* ══ PartSet (part_set.go:194-222) ══ */")
    total, parts, root, proofs = part_set(PART_DATA, PART_SIZE)
    add("#define V_PARTSET_DATA_LEN %d" % len(PART_DATA))
    add("#define V_PARTSET_PART_SIZE %d" % PART_SIZE)
    add("#define V_PARTSET_TOTAL %d" % total)
    add("/* the payload is byte i = (0x11 + 7*i) mod 251, rebuilt in C.")
    add(" * 251 is prime and does not divide the part size, so no two")
    add(" * parts are equal — see part_payload() for why that matters. */")
    for i, p in enumerate(parts):
        add("/*   part[%d]: %d bytes, %d aunts */"
            % (i, len(p), len(proofs[i])))
    assert len(set(parts)) == len(parts), "parts must be pairwise distinct"
    add(c_array("V_PARTSET_ROOT", root))
    add(c_array("V_PARTSET_LEAF0", leaf_hash(parts[0])))
    for j, a in enumerate(proofs[0]):
        add("/*   proof[0].aunt[%d] = %s */" % (j, hexs(a)))
    add(c_array("V_PARTSET_P0_AUNTS", b"".join(proofs[0])))
    add(c_array("V_PARTSET_P3_AUNTS", b"".join(proofs[total - 1])))
    add("/* a one-byte part set: a single leaf, no aunts, root = leaf */")
    t1, p1, r1, pr1 = part_set(b"\x2a", PART_SIZE)
    add("/*   total=%d aunts=%d */" % (t1, len(pr1[0])))
    add(c_array("V_PARTSET_ONE_ROOT", r1))
    add("/* an EMPTY part set: total 0, root = H(\"\") */")
    add(c_array("V_PARTSET_EMPTY_ROOT", part_set(b"", PART_SIZE)[2]))

    add("")
    add("/* ══ anchors ══ */")
    add('/* SHA3-512("")            = %s */' % hexs(empty_hash()))
    add('/* SHA3-512(00)            = %s */' % hexs(leaf_hash(b"")))
    add('/* SHA3-512(00 ‖ 1200)     = %s */'
        % hexs(leaf_hash(m_block_id(*BID_NIL))))
    return "\n".join(out)


if __name__ == "__main__":
    problems = check()
    if problems:
        sys.stderr.write("ORACLE SELF-CHECK FAILED — STOP:\n")
        for p in problems:
            sys.stderr.write("  " + p + "\n")
        sys.exit(1)
    sys.stderr.write("cmt_block_oracle: self-check passed\n")
    print("/* GENERATED by shared/dnac/tests/cmt_block_oracle.py"
          " — do not edit */")
    print(emit())
