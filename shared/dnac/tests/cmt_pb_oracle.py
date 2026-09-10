#!/usr/bin/env python3
"""
cometbft @709fd12b C PORT (wave R1-A) — INDEPENDENT proto3 ORACLE for
shared/dnac/cmt_pb.{h,c}, plus the SHA3-512 Merkle / BitArray / time
vectors pinned by the R1-A ctest files.

PROVENANCE: this file was written from the pinned `.proto` field numbers
and types, and from the K-1 rev 2 wire rules (a)-(h) as recorded in Atlas
decision atlas-dec-3ba8153088b0d60c63083028023b61be, NOT by reading or
transcribing shared/dnac/cmt_pb.c. It shares no code and no constant
table with the C implementation; the only inputs are the .proto files
listed below and the rules restated in the SPEC block. Hash primitive:
python3 hashlib.sha3_512 (stdlib, FIPS-202) — an implementation
independent of shared/crypto/hash/qgp_sha3.c.

Run:  python3 shared/dnac/tests/cmt_pb_oracle.py
The emitted C arrays are pinned verbatim in nodus/tests/test_cmt_pb.c and
the digests/roots in nodus/tests/test_cmt_merkle.c.

Reference pins (SHA-256 verified against tasks/comet-port-map.md before use):
  proto/tendermint/types/types.proto      363190881ae6c9f3f39a5a86426254393a6415b66178a871ce11afeee1e4ed07
  proto/tendermint/types/canonical.proto  385527f799916a6132ade2284d5cb084b316b4717b4151bfdb4bf1733a88c365
  proto/tendermint/types/validator.proto  d11afbbc8cc831f7d7e5af3a35d7f1641afd1ec0551e1f4d37ef2902d85a0b4c
  proto/tendermint/types/params.proto     d4141c7d3dcb7ef207f9e46bcbddb124a1ee68aa9ae32c7abc95a4e57bd32e1c
  proto/tendermint/types/evidence.proto   8075adcb2e76832e92ca04c2dbedaff3c601a4b9b28ba28428967b4338e8b9e0
  proto/tendermint/version/types.proto    75f74bdc37f509f28763ddb4f6291e5f397d1df252179d66caf60c9d318066fe
  proto/tendermint/crypto/keys.proto      41021beae17901ad2360d1f1ab040d7d28adb89a784fba9935fcbed638e39bac
  proto/tendermint/crypto/proof.proto     926346f92322a8460753426c578e360c13cce5124d0d6e7245230c56b88613f7
  proto/tendermint/libs/bits/types.proto  b61ef79f665140836f5fb10c0c95c9bc32eaecc225e5cf339c42306fdb1a2b6f
  proto/tendermint/abci/types.proto       b0b78373a8f93c4f8a747367ba1a52f41e4d5e228ead24fe4ab71da600c33efd
  google/protobuf/timestamp.proto v25.1   14052c6042c1dd2d0b50245f2812eaab6eaf82db0b6e8ce483eae527f73b6ee8
  google/protobuf/wrappers.proto  v25.1   a26c1d6ec73a592ac31796289a61ceffe2db2453ff427dfdd7697aac50844280

── SPEC (frozen; K-1 rev 2 rules (a)-(h)) ───────────────────────────────
Wire types: 0 varint, 1 fixed64, 2 length-delimited. tag = (field<<3)|wt.
Fields are emitted in ASCENDING field-number order (the generated
MarshalToSizedBuffer writes backwards from the end of the buffer, which
produces ascending order in the finished bytes).

(a) OMIT-ZERO. A scalar equal to 0 is not written. A bytes/string field of
    length 0 is not written. A POINTER (nullable) embedded message that is
    nil is not written.
(b) ALWAYS-EMIT. An embedded message declared `(gogoproto.nullable) = false`
    is ALWAYS written as tag ‖ uvarint(len) ‖ body, even when the body is
    empty — then the two bytes `tag 00`.
(c) Timestamp = {int64 seconds = 1, int32 nanos = 2} with omit-zero, valid
    range seconds in [-62135596800, 253402300800), nanos in [0, 1e9).
    Go's zero time.Time is seconds = -62135596800, nanos = 0.
(d) Header leaves are BARE message bytes, not tagged fields: Consensus
    marshal, StringValue{1}, Int64Value{1}, the bare Timestamp, the
    BlockID marshal and BytesValue{1}; an empty string/bytes yields nil,
    which the Merkle leaf hashes as H(0x00).
(e) Sign bytes: MarshalDelimited = uvarint(len) ‖ message. Canonical
    height/round are sfixed64 (tags 0x11 / 0x19, 8 bytes LITTLE-endian)
    and are themselves omit-zero.
(f) `repeated uint64 elems` is PACKED (one tag 0x12, one total length,
    consecutive varints); repeated bytes / repeated message carry one tag
    per element.
(g) Negative int32/int64/enum varints are the 10-byte two's-complement
    form (Go widens to uint64 before writing).
(h) PublicKey oneof: ML-DSA-87 is branch 9 (tag 0x4a), 2592 bytes — K-2,
    atlas-dec-7fde65722d68b32eca08be61fbcb47ac. Branches 1 and 2 exist in
    the pinned .proto but are never produced by this port.

DNA size substitutions (umbrella rev 3 §10.8): hash 64 (SHA3-512),
signature 4627, public key 2592, address 32, chain id 32 raw bytes in the
proto `string` field.

Copyright (c) 2026 nocdem
SPDX-License-Identifier: MIT
"""

import hashlib
import sys

# ══ primitives ════════════════════════════════════════════════════════

MIN_TS_SECONDS = -62135596800          # timestamp.go:45  minValidSeconds
MAX_TS_SECONDS = 253402300800          # timestamp.go:48  maxValidSeconds
GO_ZERO_TIME = (MIN_TS_SECONDS, 0)     # Go's zero time.Time
U64 = (1 << 64) - 1


def uvarint(v):
    """Base-128 varint of a non-negative integer (encodeVarintTypes)."""
    assert 0 <= v <= U64, v
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def varint_signed(v):
    """int32/int64/enum: Go widens to uint64, so negatives are 10 bytes."""
    return uvarint(v & U64)


def sfixed64(v):
    """8 bytes, little-endian two's complement."""
    return (v & U64).to_bytes(8, "little")


def tag(field, wt):
    return uvarint((field << 3) | wt)


def f_varint(field, v):
    """Omit-zero scalar written as a varint."""
    return b"" if v == 0 else tag(field, 0) + varint_signed(v)


def f_sfixed64(field, v):
    """Omit-zero scalar written as sfixed64 (canonical height/round)."""
    return b"" if v == 0 else tag(field, 1) + sfixed64(v)


def f_bytes(field, b):
    """Omit-empty bytes/string."""
    return b"" if not b else tag(field, 2) + uvarint(len(b)) + b


def f_msg_always(field, body):
    """(gogoproto.nullable) = false — written even when body is empty."""
    return tag(field, 2) + uvarint(len(body)) + body


def f_msg_ptr(field, body):
    """Pointer message — omitted when nil (body is None)."""
    return b"" if body is None else tag(field, 2) + uvarint(len(body)) + body


def f_rep_bytes(field, items):
    """repeated bytes / repeated message: one tag per element."""
    return b"".join(tag(field, 2) + uvarint(len(x)) + x for x in items)


def f_packed_u64(field, values):
    """PACKED repeated uint64 (libs/bits BitArray.elems)."""
    if not values:
        return b""
    body = b"".join(uvarint(v) for v in values)
    return tag(field, 2) + uvarint(len(body)) + body


# ══ messages ══════════════════════════════════════════════════════════
# Each function takes plain Python values and returns the message body.

def m_timestamp(ts):
    """google.protobuf.Timestamp {seconds = 1, nanos = 2}."""
    sec, nanos = ts
    if not (MIN_TS_SECONDS <= sec < MAX_TS_SECONDS):
        raise ValueError("timestamp seconds out of range: %d" % sec)
    if not (0 <= nanos < 1000000000):
        raise ValueError("timestamp nanos out of range: %d" % nanos)
    return f_varint(1, sec) + f_varint(2, nanos)


def m_int64value(v):
    """gogotypes.Int64Value {value = 1}."""
    return f_varint(1, v)


def m_stringvalue(s):
    """gogotypes.StringValue {value = 1}."""
    return f_bytes(1, s)


def m_bytesvalue(b):
    """gogotypes.BytesValue {value = 1}."""
    return f_bytes(1, b)


def m_consensus(block, app):
    """tendermint.version.Consensus {block = 1, app = 2} (uint64)."""
    return f_varint(1, block) + f_varint(2, app)


def m_part_set_header(total, h):
    """tendermint.types.PartSetHeader {total = 1 uint32, hash = 2}."""
    return f_varint(1, total) + f_bytes(2, h)


def m_canonical_part_set_header(total, h):
    """tendermint.types.CanonicalPartSetHeader — same shape."""
    return f_varint(1, total) + f_bytes(2, h)


def m_block_id(h, psh):
    """tendermint.types.BlockID {hash = 1, part_set_header = 2 ALWAYS}."""
    return f_bytes(1, h) + f_msg_always(2, m_part_set_header(*psh))


def m_canonical_block_id(h, psh):
    """CanonicalBlockID {hash = 1, part_set_header = 2 ALWAYS}."""
    return f_bytes(1, h) + f_msg_always(2, m_canonical_part_set_header(*psh))


def m_proof(total, index, leaf_hash, aunts):
    """tendermint.crypto.Proof {total 1, index 2, leaf_hash 3, aunts 4}."""
    return (f_varint(1, total) + f_varint(2, index) +
            f_bytes(3, leaf_hash) + f_rep_bytes(4, aunts))


def m_part(index, data, proof):
    """tendermint.types.Part {index 1 uint32, bytes 2, proof 3 ALWAYS}."""
    return (f_varint(1, index) + f_bytes(2, data) +
            f_msg_always(3, m_proof(*proof)))


def m_public_key_mldsa87(key):
    """tendermint.crypto.PublicKey, ML-DSA-87 branch = field 9 (K-2)."""
    return f_bytes(9, key)


def m_simple_validator(pub_key, voting_power):
    """SimpleValidator {pub_key = 1 POINTER, voting_power = 2}."""
    pk = None if pub_key is None else m_public_key_mldsa87(pub_key)
    return f_msg_ptr(1, pk) + f_varint(2, voting_power)


def m_validator(address, pub_key, voting_power, proposer_priority):
    """Validator {address 1, pub_key 2 ALWAYS, power 3, priority 4}."""
    return (f_bytes(1, address) +
            f_msg_always(2, m_public_key_mldsa87(pub_key)) +
            f_varint(3, voting_power) + f_varint(4, proposer_priority))


def m_validator_set(validators, proposer, total_voting_power):
    """ValidatorSet {validators 1 repeated, proposer 2 POINTER, total 3}."""
    return (f_rep_bytes(1, [m_validator(*v) for v in validators]) +
            f_msg_ptr(2, None if proposer is None else m_validator(*proposer)) +
            f_varint(3, total_voting_power))


def m_hashed_params(block_max_bytes, block_max_gas):
    """tendermint.types.HashedParams {block_max_bytes 1, block_max_gas 2}."""
    return f_varint(1, block_max_bytes) + f_varint(2, block_max_gas)


def m_header(version, chain_id, height, time, last_block_id,
             last_commit_hash, data_hash, validators_hash,
             next_validators_hash, consensus_hash, app_hash,
             last_results_hash, evidence_hash, proposer_address):
    """tendermint.types.Header — 14 fields; 1, 4 and 5 ALWAYS-emitted."""
    return (f_msg_always(1, m_consensus(*version)) +
            f_bytes(2, chain_id) +
            f_varint(3, height) +
            f_msg_always(4, m_timestamp(time)) +
            f_msg_always(5, m_block_id(*last_block_id)) +
            f_bytes(6, last_commit_hash) +
            f_bytes(7, data_hash) +
            f_bytes(8, validators_hash) +
            f_bytes(9, next_validators_hash) +
            f_bytes(10, consensus_hash) +
            f_bytes(11, app_hash) +
            f_bytes(12, last_results_hash) +
            f_bytes(13, evidence_hash) +
            f_bytes(14, proposer_address))


def m_data(txs):
    """tendermint.types.Data {txs = 1 repeated bytes}."""
    return f_rep_bytes(1, txs)


def m_vote(vtype, height, round_, block_id, timestamp, validator_address,
           validator_index, signature, extension, extension_signature):
    """tendermint.types.Vote — 10 fields; 4 and 5 ALWAYS-emitted."""
    return (f_varint(1, vtype) + f_varint(2, height) + f_varint(3, round_) +
            f_msg_always(4, m_block_id(*block_id)) +
            f_msg_always(5, m_timestamp(timestamp)) +
            f_bytes(6, validator_address) + f_varint(7, validator_index) +
            f_bytes(8, signature) + f_bytes(9, extension) +
            f_bytes(10, extension_signature))


def m_commit_sig(flag, validator_address, timestamp, signature):
    """tendermint.types.CommitSig — field 3 (timestamp) ALWAYS-emitted."""
    return (f_varint(1, flag) + f_bytes(2, validator_address) +
            f_msg_always(3, m_timestamp(timestamp)) + f_bytes(4, signature))


def m_commit(height, round_, block_id, signatures):
    """tendermint.types.Commit — field 3 ALWAYS; 4 repeated message."""
    return (f_varint(1, height) + f_varint(2, round_) +
            f_msg_always(3, m_block_id(*block_id)) +
            f_rep_bytes(4, [m_commit_sig(*s) for s in signatures]))


def m_extended_commit_sig(flag, validator_address, timestamp, signature,
                          extension, extension_signature):
    """tendermint.types.ExtendedCommitSig (types.proto:133-143) — the four
    CommitSig fields (field 3 ALWAYS-emitted) plus the vote extension (5)
    and its signature (6), both singular `bytes` and therefore omit-empty
    (types.pb.go:1837, :1844).  APPENDED BY WAVE R1-B."""
    return (f_varint(1, flag) + f_bytes(2, validator_address) +
            f_msg_always(3, m_timestamp(timestamp)) + f_bytes(4, signature) +
            f_bytes(5, extension) + f_bytes(6, extension_signature))


def m_extended_commit(height, round_, block_id, extended_signatures):
    """tendermint.types.ExtendedCommit (types.proto:122-128) — field 3
    ALWAYS-emitted (types.pb.go:1794-1803), field 4 repeated message with
    one tag per element (:1780-1792).  APPENDED BY WAVE R1-B."""
    return (f_varint(1, height) + f_varint(2, round_) +
            f_msg_always(3, m_block_id(*block_id)) +
            f_rep_bytes(4, [m_extended_commit_sig(*s)
                            for s in extended_signatures]))


def m_proposal(ptype, height, round_, pol_round, block_id, timestamp,
               signature):
    """tendermint.types.Proposal — fields 5 and 6 ALWAYS-emitted."""
    return (f_varint(1, ptype) + f_varint(2, height) + f_varint(3, round_) +
            f_varint(4, pol_round) +
            f_msg_always(5, m_block_id(*block_id)) +
            f_msg_always(6, m_timestamp(timestamp)) +
            f_bytes(7, signature))


def m_canonical_vote(vtype, height, round_, block_id, timestamp, chain_id):
    """CanonicalVote — height/round sfixed64; block_id POINTER; ts ALWAYS."""
    cb = None if block_id is None else m_canonical_block_id(*block_id)
    return (f_varint(1, vtype) + f_sfixed64(2, height) +
            f_sfixed64(3, round_) + f_msg_ptr(4, cb) +
            f_msg_always(5, m_timestamp(timestamp)) + f_bytes(6, chain_id))


def m_canonical_proposal(ptype, height, round_, pol_round, block_id,
                         timestamp, chain_id):
    """CanonicalProposal — pol_round is int64 (field 4), not int32."""
    cb = None if block_id is None else m_canonical_block_id(*block_id)
    return (f_varint(1, ptype) + f_sfixed64(2, height) +
            f_sfixed64(3, round_) + f_varint(4, pol_round) +
            f_msg_ptr(5, cb) + f_msg_always(6, m_timestamp(timestamp)) +
            f_bytes(7, chain_id))


def m_canonical_vote_extension(extension, height, round_, chain_id):
    """CanonicalVoteExtension {extension 1, height 2, round 3, chain 4}."""
    return (f_bytes(1, extension) + f_sfixed64(2, height) +
            f_sfixed64(3, round_) + f_bytes(4, chain_id))


def m_duplicate_vote_evidence(vote_a, vote_b, total_voting_power,
                              validator_power, timestamp):
    """DuplicateVoteEvidence — votes are POINTERS; timestamp ALWAYS."""
    return (f_msg_ptr(1, None if vote_a is None else m_vote(*vote_a)) +
            f_msg_ptr(2, None if vote_b is None else m_vote(*vote_b)) +
            f_varint(3, total_voting_power) + f_varint(4, validator_power) +
            f_msg_always(5, m_timestamp(timestamp)))


def m_evidence_duplicate(dve_body):
    """Evidence oneof, branch 1 = DuplicateVoteEvidence."""
    return f_msg_ptr(1, dve_body)


def m_exec_tx_result(code, data, gas_wanted, gas_used):
    """abci.ExecTxResult restricted to the deterministic fields
    {code = 1 uint32, data = 2, gas_wanted = 5, gas_used = 6}
    (types/results.go:47-54 strips log/info/events/codespace)."""
    return (f_varint(1, code) + f_bytes(2, data) +
            f_varint(5, gas_wanted) + f_varint(6, gas_used))


def m_bit_array(bits, elems):
    """tendermint.libs.bits.BitArray {bits = 1, elems = 2 PACKED}."""
    return f_varint(1, bits) + f_packed_u64(2, elems)


def marshal_delimited(body):
    """libs/protoio/writer.go:96-103 — uvarint(len) ‖ message."""
    return uvarint(len(body)) + body


# ══ SHA3-512 Merkle (RFC 6962, cometbft crypto/merkle with the DNA hash) ══

HASH_SIZE = 64


def H(b):
    return hashlib.sha3_512(b).digest()


def empty_hash():
    """merkle/hash.go:16-18 emptyHash()."""
    return H(b"")


def leaf_hash(leaf):
    """merkle/hash.go:21-23 leafHash() — H(0x00 ‖ leaf)."""
    return H(b"\x00" + leaf)


def inner_hash(left, right):
    """merkle/hash.go:34-36 innerHash() — H(0x01 ‖ left ‖ right)."""
    return H(b"\x01" + left + right)


def split_point(length):
    """merkle/tree.go:101-112 getSplitPoint() — largest power of 2 < length."""
    assert length >= 1
    k = 1 << (length.bit_length() - 1)
    if k == length:
        k >>= 1
    return k


def merkle_root(items):
    """merkle/tree.go:15-27 hashFromByteSlices()."""
    if len(items) == 0:
        return empty_hash()
    if len(items) == 1:
        return leaf_hash(items[0])
    k = split_point(len(items))
    return inner_hash(merkle_root(items[:k]), merkle_root(items[k:]))


def merkle_proofs(items):
    """merkle/proof.go:232-252 trailsFromByteSlices() + :35-48, expressed
    as the aunt list per index (leaf's sibling first, root's child last)."""
    n = len(items)
    if n == 0:
        return empty_hash(), []
    if n == 1:
        h = leaf_hash(items[0])
        return h, [[]]
    k = split_point(n)
    lroot, launts = merkle_proofs(items[:k])
    rroot, raunts = merkle_proofs(items[k:])
    root = inner_hash(lroot, rroot)
    # a left-subtree leaf gains the right root as its outermost aunt
    out = [a + [rroot] for a in launts] + [a + [lroot] for a in raunts]
    return root, out


# ══ C emission ════════════════════════════════════════════════════════

# Vectors at or below this length are pinned as literal byte arrays;
# longer ones are pinned as (length, SHA3-512 digest), which constrains the
# bytes exactly as tightly and keeps the test file readable. The C test
# rebuilds the same inputs and compares the digest of what it produced.
C_INLINE_MAX = 40


def c_array(name, data, indent="    "):
    """Literal byte array, always — used for the short decisive vectors."""
    if len(data) == 0:
        return ("#define %s_LEN 0\nstatic const uint8_t %s[1] = { 0 };"
                "  /* 0 bytes */" % (name, name))
    lines = ["#define %s_LEN %d" % (name, len(data))]
    lines.append("static const uint8_t %s[%d] = {" % (name, len(data)))
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        lines.append(indent + " ".join("0x%02x," % b for b in chunk))
    lines.append("};")
    return "\n".join(lines)


def c_digest(name, data):
    """Length + SHA3-512 of the encoding, for the long vectors."""
    return ('#define %s_LEN %d\n'
            'static const char %s_SHA3[] =\n    "%s";'
            % (name, len(data), name, hashlib.sha3_512(data).hexdigest()))


def c_vec(name, data):
    """Literal below the threshold, digest above it."""
    if len(data) <= C_INLINE_MAX:
        return c_array(name, data)
    return c_digest(name, data)


def c_hex(name, data):
    return c_digest(name, data)


def hexs(b):
    return b.hex()


def pat(n, seed):
    """Deterministic filler: byte i = (seed + 7*i) mod 256."""
    return bytes((seed + 7 * i) & 0xFF for i in range(n))


# ══ golden-vector self-check (tasks/comet-port-map.md REV 3.2) ════════

def check():
    """Recompute every REV 3.2 golden vector from this file's own rules.
    A mismatch is a STOP condition, not something to paper over."""
    fails = []

    def eq(name, got, want_hex):
        if got.hex() != want_hex:
            fails.append("%s: got %s want %s" % (name, got.hex(), want_hex))

    eq("varint(uint64(-62135596800))",
       varint_signed(MIN_TS_SECONDS), "8092b8c398feffffff01")
    eq("Timestamp{zero}", m_timestamp(GO_ZERO_TIME),
       "088092b8c398feffffff01")
    eq("CommitSig{Absent}", m_commit_sig(1, b"", GO_ZERO_TIME, b""),
       "08011a0b088092b8c398feffffff01")
    eq("BlockID{zero}", m_block_id(b"", (0, b"")), "1200")
    cv = m_canonical_vote(2, 1, 0, None, GO_ZERO_TIME, b"ab")
    eq("CanonicalVote{PRECOMMIT,h=1,r=0,nil,zero-ts,ab}", cv,
       "08021101000000000000002a0b088092b8c398feffffff0132026162")
    eq("MarshalDelimited(CanonicalVote)", marshal_delimited(cv),
       "1c" + "08021101000000000000002a0b088092b8c398feffffff0132026162")
    eq("Int64Value{5}", m_int64value(5), "0805")
    eq("Int64Value{0}", m_int64value(0), "")
    eq('StringValue{"ab"}', m_stringvalue(b"ab"), "0a026162")
    eq("HashedParams{22020096,-1}", m_hashed_params(22020096, -1),
       "088080c00a10ffffffffffffffffff01")

    # SHA3-512 anchors (prefixes as recorded in REV 3.2)
    for name, got, want in (
        ('SHA3-512("")', empty_hash().hex(), "a69f73cc"),
        ("leaf(nil) = SHA3-512(00)", leaf_hash(b"").hex(), "7127aab2"),
        ("leaf(BlockID zero) = SHA3-512(00 1200)",
         leaf_hash(m_block_id(b"", (0, b""))).hex(), "6870f405"),
    ):
        if not got.startswith(want):
            fails.append("%s: got %s... want %s..." % (name, got[:8], want))
    if empty_hash().hex()[-4:] != "cd26":
        fails.append("SHA3-512(\"\") tail: got %s want cd26"
                     % empty_hash().hex()[-4:])
    if leaf_hash(b"").hex()[-4:] != "97da":
        fails.append("leaf(nil) tail: got %s want 97da"
                     % leaf_hash(b"").hex()[-4:])
    if leaf_hash(m_block_id(b"", (0, b""))).hex()[-4:] != "8b65":
        fails.append("leaf(BlockID zero) tail: got %s want 8b65"
                     % leaf_hash(m_block_id(b"", (0, b""))).hex()[-4:])
    return fails


# ══ fixtures ══════════════════════════════════════════════════════════

HASH_A = pat(64, 0x10)
HASH_B = pat(64, 0x20)
HASH_C = pat(64, 0x30)
ADDR_A = pat(32, 0x40)
CHAIN = pat(32, 0x50)               # 32 raw bytes in the proto `string`
SIG_S = pat(9, 0x60)                # short stand-in signature
KEY_S = pat(11, 0x70)               # short stand-in public key
SIG_FULL = pat(4627, 0x01)          # QGP_DSA87_SIGNATURE_BYTES
KEY_FULL = pat(2592, 0x02)          # QGP_DSA87_PUBLICKEYBYTES
TS_A = (1700000000, 123456789)

PSH_A = (7, HASH_A)
BID_A = (HASH_B, PSH_A)
BID_ZERO = (b"", (0, b""))


def emit():
    out = []
    add = out.append

    add("/* ══ Timestamp (google.protobuf.Timestamp) ══ */")
    add(c_vec("V_TS_ZERO", m_timestamp(GO_ZERO_TIME)))
    add(c_vec("V_TS_A", m_timestamp(TS_A)))
    add("/* Timestamp{0,0} (Unix epoch, NOT Go's zero time) marshals to 0 "
        "bytes */")

    add("")
    add("/* ══ gogotypes wrappers (header leaves) ══ */")
    add(c_vec("V_INT64VALUE_5", m_int64value(5)))
    add("/* Int64Value{0}: 0 bytes */")
    add(c_vec("V_INT64VALUE_NEG", m_int64value(-3)))
    add(c_vec("V_STRINGVALUE_AB", m_stringvalue(b"ab")))
    add(c_vec("V_BYTESVALUE_HASH_A", m_bytesvalue(HASH_A)))
    add("/* StringValue{\"\"} and BytesValue{empty}: 0 bytes (nil leaf) */")

    add("")
    add("/* ══ version.Consensus ══ */")
    add(c_vec("V_CONSENSUS_11_0", m_consensus(11, 0)))
    add(c_vec("V_CONSENSUS_11_7", m_consensus(11, 7)))
    add("/* Consensus{0,0}: 0 bytes */")

    add("")
    add("/* ══ PartSetHeader / BlockID ══ */")
    add(c_vec("V_PSH_ZERO", m_part_set_header(0, b"")))
    add(c_vec("V_PSH_A", m_part_set_header(*PSH_A)))
    add(c_vec("V_BLOCKID_ZERO", m_block_id(*BID_ZERO)))
    add(c_vec("V_BLOCKID_A", m_block_id(*BID_A)))

    add("")
    add("/* ══ crypto.Proof ══ */")
    add(c_vec("V_PROOF_ZERO", m_proof(0, 0, b"", [])))
    add(c_vec("V_PROOF_3AUNTS",
                m_proof(8, 3, HASH_A, [HASH_B, HASH_C, HASH_A])))
    # DELTA 1 — not a REV 3.2 golden value: derived here from
    # crypto/proof.pb.go:373-381, which writes every element of `aunts`
    # unconditionally. An empty aunt is `22 00`, not an omission. The
    # message is refused by the reference's own ValidateBasic
    # (proof.go:113-132, an aunt must be tmhash-sized) — the point of the
    # vector is the WIRE bytes the generated encoder produces.
    # Deliberately SHORT hashes so the vector stays a literal and the
    # `22 00` is visible in the test source rather than folded into a
    # digest. Lengths are not tmhash-sized; see the ValidateBasic note.
    add("/* an empty aunt is one element: 22 00, not an omission */")
    add(c_vec("V_PROOF_EMPTY_AUNT",
                m_proof(2, 0, pat(2, 0xB0), [b"", pat(3, 0xB1)])))

    add("")
    add("/* ══ types.Part ══ */")
    add(c_vec("V_PART_ZERO", m_part(0, b"", (0, 0, b"", []))))
    add(c_vec("V_PART_A",
                m_part(2, pat(5, 0x80), (4, 2, HASH_A, [HASH_B]))))

    add("")
    add("/* ══ crypto.PublicKey (K-2 branch 9) ══ */")
    add(c_hex("V_PUBKEY_FULL_2592", m_public_key_mldsa87(KEY_FULL)))
    add("/* K-2 NEGATIVE vector: branch 9 with an 11-byte key. The C "
        "encoder\n * cannot produce this (its key field is exactly 2592 "
        "bytes); it exists\n * only so the DECODER can be shown refusing "
        "it. */")
    add(c_vec("V_PUBKEY_BAD_LEN", m_public_key_mldsa87(KEY_S)))
    add("/* K-2 NEGATIVE vectors: the ed25519 and secp256k1 branches of "
        "the\n * pinned keys.proto, which this port never produces and "
        "must refuse. */")
    add(c_vec("V_PUBKEY_BRANCH1", f_bytes(1, pat(32, 0x11))))
    add(c_vec("V_PUBKEY_BRANCH2", f_bytes(2, pat(33, 0x12))))

    add("")
    add("/* ══ SimpleValidator / Validator / ValidatorSet ══ */")
    add(c_vec("V_SIMPLEVAL_NIL_KEY", m_simple_validator(None, 0)))
    add(c_hex("V_SIMPLEVAL_FULL", m_simple_validator(KEY_FULL, 100)))
    add(c_vec("V_VALIDATOR_ZERO", m_validator(b"", b"", 0, 0)))
    add(c_hex("V_VALIDATOR_FULL",
              m_validator(ADDR_A, KEY_FULL, 100, -5)))
    add(c_vec("V_VALSET_EMPTY", m_validator_set([], None, 0)))
    add(c_hex("V_VALSET_2",
              m_validator_set([(ADDR_A, KEY_FULL, 100, -5),
                               (pat(32, 0x41), KEY_FULL, 50, 5)],
                              (ADDR_A, KEY_FULL, 100, -5), 150)))

    add("")
    add("/* ══ types.HashedParams (ConsensusHash preimage) ══ */")
    add(c_vec("V_HASHEDPARAMS_DEFAULT", m_hashed_params(22020096, -1)))
    add(c_vec("V_HASHEDPARAMS_ZERO", m_hashed_params(0, 0)))

    add("")
    add("/* ══ types.Header ══ */")
    hdr_zero = m_header((0, 0), b"", 0, GO_ZERO_TIME, BID_ZERO,
                        b"", b"", b"", b"", b"", b"", b"", b"", b"")
    add(c_vec("V_HEADER_ZERO", hdr_zero))
    hdr_full = m_header((11, 3), CHAIN, 42, TS_A, BID_A,
                        HASH_A, HASH_B, HASH_C, HASH_A, HASH_B, HASH_C,
                        HASH_A, HASH_B, ADDR_A)
    add(c_vec("V_HEADER_FULL", hdr_full))

    add("")
    add("/* ══ types.Data ══ */")
    add("/* Data{} (no txs): 0 bytes */")
    add(c_vec("V_DATA_3TX",
                m_data([pat(3, 0x90), b"", pat(5, 0x91)])))
    # DELTA 1 — not a REV 3.2 golden value: derived here from
    # types.pb.go:1552-1560. Empty txs at BOTH ends, where a
    # trailing-element bug and a leading-element bug look different.
    add("/* txs = {\"\", \"ab\", \"\"} — three elements, two of them empty */")
    add(c_vec("V_DATA_EMPTY_ENDS", m_data([b"", b"ab", b""])))

    add("")
    add("/* ══ types.Vote ══ */")
    vote_zero = m_vote(0, 0, 0, BID_ZERO, GO_ZERO_TIME, b"", 0, b"", b"", b"")
    add(c_vec("V_VOTE_ZERO", vote_zero))
    vote_short = m_vote(2, 42, 1, BID_A, TS_A, ADDR_A, 3, SIG_S,
                        pat(4, 0xA0), pat(6, 0xA1))
    add(c_vec("V_VOTE_SHORT", vote_short))
    add(c_hex("V_VOTE_FULLSIG",
              m_vote(2, 42, 1, BID_A, TS_A, ADDR_A, 3, SIG_FULL,
                     pat(4, 0xA0), SIG_FULL)))

    add("")
    add("/* ══ types.CommitSig / types.Commit ══ */")
    sig_absent = (1, b"", GO_ZERO_TIME, b"")
    sig_commit = (2, ADDR_A, TS_A, SIG_S)
    sig_nil = (3, pat(32, 0x41), TS_A, SIG_S)
    add(c_vec("V_COMMITSIG_ABSENT", m_commit_sig(*sig_absent)))
    add(c_vec("V_COMMITSIG_COMMIT", m_commit_sig(*sig_commit)))
    add(c_vec("V_COMMIT_ZERO", m_commit(0, 0, BID_ZERO, [])))
    add(c_vec("V_COMMIT_3SIGS",
                m_commit(42, 1, BID_A, [sig_absent, sig_commit, sig_nil])))

    add("")
    add("/* ══ types.Proposal ══ */")
    add(c_vec("V_PROPOSAL_ZERO",
                m_proposal(0, 0, 0, 0, BID_ZERO, GO_ZERO_TIME, b"")))
    add(c_vec("V_PROPOSAL_A",
                m_proposal(32, 42, 1, -1, BID_A, TS_A, SIG_S)))

    add("")
    add("/* ══ canonical.proto (sign bytes) ══ */")
    cv_golden = m_canonical_vote(2, 1, 0, None, GO_ZERO_TIME, b"ab")
    add(c_vec("V_CANONVOTE_GOLDEN", cv_golden))
    add(c_vec("V_CANONVOTE_GOLDEN_DELIM", marshal_delimited(cv_golden)))
    add(c_vec("V_CANONVOTE_FULL",
                m_canonical_vote(2, 42, 1, (HASH_B, PSH_A), TS_A, CHAIN)))
    add(c_vec("V_CANONBLOCKID_ZERO",
                m_canonical_block_id(b"", (0, b""))))
    add(c_vec("V_CANONPSH_A", m_canonical_part_set_header(*PSH_A)))
    add(c_vec("V_CANONPROPOSAL_A",
                m_canonical_proposal(32, 42, 1, -1, (HASH_B, PSH_A), TS_A,
                                     CHAIN)))
    add(c_vec("V_CANONPROPOSAL_NILBID",
                m_canonical_proposal(32, 1, 0, 0, None, GO_ZERO_TIME,
                                     b"ab")))
    add(c_vec("V_CANONVOTEEXT_A",
                m_canonical_vote_extension(pat(6, 0xB0), 42, 1, CHAIN)))
    add(c_vec("V_CANONVOTEEXT_ZERO",
                m_canonical_vote_extension(b"", 0, 0, b"")))

    add("")
    add("/* ══ evidence.proto ══ */")
    ev_vote_a = (2, 42, 1, BID_A, TS_A, ADDR_A, 3, SIG_S, b"", b"")
    ev_vote_b = (2, 42, 1, (HASH_C, PSH_A), TS_A, ADDR_A, 3, SIG_S, b"", b"")
    dve = m_duplicate_vote_evidence(ev_vote_a, ev_vote_b, 150, 100, TS_A)
    add(c_vec("V_DVE_A", dve))
    add(c_vec("V_DVE_ZERO",
                m_duplicate_vote_evidence(None, None, 0, 0, GO_ZERO_TIME)))
    add(c_vec("V_EVIDENCE_DVE_A", m_evidence_duplicate(dve)))

    add("")
    add("/* ══ abci.ExecTxResult (deterministic subset) ══ */")
    add(c_vec("V_EXECTXRESULT_ZERO", m_exec_tx_result(0, b"", 0, 0)))
    add(c_vec("V_EXECTXRESULT_A",
                m_exec_tx_result(7, pat(5, 0xC0), 1000, 999)))

    add("")
    add("/* ══ libs.bits.BitArray (packed elems) ══ */")
    add(c_vec("V_BITARRAY_3ELEMS",
                m_bit_array(140, [0x0000000000000001,
                                  0xFFFFFFFFFFFFFFFF,
                                  0x0000000000000FFF])))
    add(c_vec("V_BITARRAY_1BIT", m_bit_array(1, [1])))
    add("/* BitArray{0, []}: 0 bytes */")

    add("")
    add("/* ══ SHA3-512 / Merkle anchors ══ */")
    add('/* SHA3-512("")       = %s */' % hexs(empty_hash()))
    add('/* SHA3-512(00)       = %s */' % hexs(leaf_hash(b"")))
    add('/* SHA3-512(00 1200)  = %s */'
        % hexs(leaf_hash(m_block_id(*BID_ZERO))))
    items = [bytes([i]) for i in range(8)]
    for n in (0, 1, 2, 3, 5, 8):
        add(c_array("V_MERKLE_ROOT_%d" % n, merkle_root(items[:n])))
    add("/* getSplitPoint: %s */"
        % ", ".join("%d->%d" % (n, split_point(n)) for n in
                    (1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 1601)))
    root5, proofs5 = merkle_proofs(items[:5])
    add("/* ProofsFromByteSlices(5 items): root = %s */" % hexs(root5))
    for i, aunts in enumerate(proofs5):
        add("/*   proof[%d]: leaf %s, %d aunts */"
            % (i, hexs(leaf_hash(items[i]))[:16], len(aunts)))
        for j, a in enumerate(aunts):
            add("/*     aunt[%d] = %s */" % (j, hexs(a)))
    add(c_array("V_MERKLE_LEAVES_0_7",
                b"".join(leaf_hash(x) for x in items)))
    return "\n".join(out)


def emit_extended():
    """WAVE R1-B: vectors for the two messages appended above. Nothing in
    emit() above is touched."""
    out = []
    add = out.append
    add("")
    add("/* ══ wave R1-B: ExtendedCommitSig / ExtendedCommit ══ */")

    # An Absent ExtendedCommitSig is the Absent CommitSig, byte for byte:
    # the extension fields are empty and omitted.
    add(c_array("V_EXT_COMMIT_SIG_ABSENT",
                m_extended_commit_sig(1, b"", GO_ZERO_TIME, b"", b"", b"")))
    # NIL entry (flag 3) with a short signature and no extension.
    add(c_array("V_EXT_COMMIT_SIG_NIL",
                m_extended_commit_sig(3, ADDR_A[:4], TS_A, SIG_S, b"", b"")))
    # COMMIT entry carrying an extension and its signature.
    add(c_array("V_EXT_COMMIT_SIG_EXT",
                m_extended_commit_sig(2, ADDR_A[:4], TS_A, SIG_S,
                                      b"ext", SIG_S)))
    # An EMPTY extension with a present extension signature: field 5 is
    # omitted (omit-empty) while field 6 is written.
    add(c_array("V_EXT_COMMIT_SIG_EMPTY_EXT",
                m_extended_commit_sig(2, ADDR_A[:4], TS_A, SIG_S,
                                      b"", SIG_S)))
    # Full-size fields: address 32, signature 4627, extension signature 4627.
    add(c_digest("V_EXT_COMMIT_SIG_FULL",
                 m_extended_commit_sig(2, ADDR_A, TS_A, SIG_FULL,
                                       b"ext", SIG_FULL)))
    # ExtendedCommit with zero height/round and no entries: only the
    # ALWAYS-emitted block_id survives.
    add(c_array("V_EXT_COMMIT_EMPTY",
                m_extended_commit(0, 0, BID_ZERO, [])))
    add(c_array("V_EXT_COMMIT_THREE",
                m_extended_commit(9, 2, BID_A, [
                    (1, b"", GO_ZERO_TIME, b"", b"", b""),
                    (2, ADDR_A[:4], TS_A, SIG_S, b"ext", SIG_S),
                    (3, ADDR_A[:4], TS_A, SIG_S, b"", b""),
                ])))
    return "\n".join(out)


if __name__ == "__main__":
    problems = check()
    if problems:
        sys.stderr.write("GOLDEN VECTOR MISMATCH — STOP:\n")
        for p in problems:
            sys.stderr.write("  " + p + "\n")
        sys.exit(1)
    sys.stderr.write("golden vectors: all REV 3.2 values reproduced\n")
    print("/* GENERATED by shared/dnac/tests/cmt_pb_oracle.py — do not edit */")
    print(emit())
    print(emit_extended())
