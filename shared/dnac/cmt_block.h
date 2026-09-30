/**
 * @file shared/dnac/cmt_block.h
 * @brief cometbft @v0.38.26 `types/block.go` ported to C — block, header,
 *        BlockID, commit and every hash they carry.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-B of the cometbft → C consensus port. Nothing in the running
 * chain calls anything in this file; it is additive only. The live witness
 * BFT, the QC V2 path and the T3 wave-1 modules (tm_commit, tm_vote,
 * tm_wal) are byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * THIS FILE PRODUCES THE BLOCK HASH. Header.Hash is the Merkle root of
 * fourteen proto3 leaves; it is half of a BlockID, and a BlockID is inside
 * every vote's sign bytes. A one-byte difference from the reference is a
 * different chain. The structure is D-19 rev 6, APPROVED
 * (atlas-dec-d106407a31d7d16d49d51990b75c36c6), which makes the pinned
 * cometbft source normative field for field.
 *
 * ── Domain ↔ wire ──────────────────────────────────────────────────────
 * `types.BlockID`, `Header`, `CommitSig`, `ExtendedCommitSig`, `Commit`,
 * `ExtendedCommit` and `Data` are FIELD-IDENTICAL to the cmt_pb wire
 * structs of the same names (same fields, same order, same types), so each
 * domain type is a typedef of the wire type and `_to_proto` is the
 * identity — exactly as R1-A did for `cmt_proof_t` (cmt_pb.h:550-561).
 * `_from_proto` is the identity FOLLOWED BY ValidateBasic wherever the
 * reference's is (block.go:575, :721, :841, :1052, :1292, :1554).
 * `EvidenceData` is the one type that is NOT an alias: the Go domain type
 * holds `EvidenceList` (a list of Evidence INTERFACES) while the wire type
 * is `EvidenceList{repeated Evidence}`, so it gets its own struct below.
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 * 1. SHA3-512 / 64-byte digests; Dilithium signature 4627; address 32;
 *    chain id 32 raw bytes (umbrella rev 3 item 4). `crypto.AddressSize`
 *    20 → CMT_ADDRESS_SIZE 32 at block.go:413-418 and :681-686;
 *    `MaxSignatureSize` (types/signable.go:12, 64 — 709fd12b; at v0.38.26: :13, max(64, mldsa65's 3309)) → 4627.
 * 2. Every DERIVED size constant is RE-DERIVED, never copied — see the
 *    arithmetic under each constant below.
 * 3. NO MUTEX (block.go:44, :61-62, :128-129, :150-151) and NO
 *    MEMOISATION: the `verifiedHash` cache of :46/:134-136/:139, the
 *    `Commit.hash` of :861/:946-958 and the `ExtendedCommit.bitArray` of
 *    :1065/:1196-1204 are DROPPED. Each memo is a pure function of the
 *    struct, so dropping it changes no byte — only the cost of asking
 *    twice. Single-threaded port, umbrella rev 3 item 4.
 * 4. panic → error return; every Go index panic becomes an explicit check
 *    (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 * 5. Lists use caller-provided storage with an explicit capacity;
 *    overflow REFUSES.
 *
 * ⚠ WHERE THE BLOCK'S OWN proto3 ENCODER LIVES. `Block.MakePartSet`
 * (:146-164) and `Block.Size` (:177-184) need the marshalled
 * `tendermint.types.Block`, and `EvidenceData` needs the marshalled
 * `EvidenceList`. Wave R1-A's cmt_pb did not carry those two messages and
 * wave R1-B's file whitelist admitted only ExtendedCommitSig and
 * ExtendedCommit into cmt_pb, so R1-B built both encoders HERE, on a
 * forward writer over cmt_pb's public per-message marshals, and recorded
 * the recommendation to relocate them.
 *
 * WAVE R2-B DID THAT (R1B-6). `cmt_pb_block_marshal` and
 * `cmt_pb_evidence_list_marshal` now live in cmt_pb.c on the same backward
 * writer as every other generated encoder (block.pb.go:136-184,
 * evidence.pb.go:581-601); `cmt_block_marshal` below builds the cmt_pb view
 * of the block — a four-field copy, because `(b *Block) ToProto()` is the
 * identity on this representation — and calls it. The bytes are unchanged.
 * No DECODER is needed on either side: the reference's `BlockFromProto`
 * takes an already-decoded proto struct, and bytes → struct is
 * `proto.Unmarshal`, which is cmt_pb's job.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments. No clock is
 * read (the block time arrives as a value; the one clock in the reference
 * is the vote stamp — clock POLICY atlas-dec-4ac0423068085c100fdfa3e264ca16bc),
 * no randomness is drawn, no map is iterated. Commit signatures are hashed
 * in VALIDATOR-INDEX order, which is the order the list is built in, and
 * the header leaves are hashed in the fixed order of block.go:464-479.
 * Two nodes holding the same block produce the same hash, byte for byte.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `Block.String` (:189-191), `StringIndented` (:200-215), `StringShort`
 *     (:218-223), `Header.StringIndented` (:483-519), `CommitSig.String`
 *     (:634-640), `ExtendedCommitSig.String` (:745-751),
 *     `Commit.StringIndented` (:983-1004), `Data.StringIndented`
 *     (:1320-1337), `EvidenceData.StringIndented` (:1407-1424),
 *     `BlockID.String` (:1522-1524) — display only.
 *   · `Commit.ToVoteSet` (:1107-1123), `ExtendedCommit.ToExtendedVoteSet`
 *     (:1081-1085), `ExtendedCommit.addSigsToVoteSet` (:1088-1102) —
 *     they build a `VoteSet`, which wave R2 ports. Listed, not stubbed.
 *
 * ── stage-D holes: BOTH FILLED IN WAVE R1-D ────────────────────────────
 * Wave R1-B named two checks it could not perform, because both are the
 * EVIDENCE DOMAIN and that module did not exist yet:
 *   · `Block.ValidateBasic` (:92-97) loops `ev.ValidateBasic()` over the
 *     evidence — now performed at `cmt_block_validate_basic`, through
 *     `cmt_evidence_from_proto` (the decode path in which this branch's
 *     ValidateBasic lives, evidence.go:537 → :199);
 *   · `EvidenceData.FromProto` (:1454) calls `EvidenceFromProto` — now
 *     performed per item in `cmt_evidence_data_from_proto`.
 * Nothing was stubbed and no callback was invented in either wave.
 * `EvidenceData.Hash` (:1386-1392) likewise now makes the one call the
 * reference makes, to `cmt_evidence_list_hash` (evidence.go:453-464);
 * the leaves and therefore the bytes are unchanged.
 *
 * cmt_evidence.h is included from cmt_block.**c**, never from this header,
 * so that cmt_evidence.h may keep including this one for `BlockID.Key()`.
 *
 * Reference @v0.38.26 (SHA-256 recomputed on the v0.38.26 tree, not the port map,
 * before use):
 *   types/block.go            1561 lines 33ba0d2c8040449e96dca739708106e6044101af3ad6ba33945ea1949c0e0889
 *   types/test_util.go         123 lines 32333c3ef6fb373706e8d7d6b87723c08d9c5b35d0b23094eb42178a8ae8caf2 (MakeBlock :106-123 ported as cmt_make_block; MakeExtCommit :14, signAddVote :47, MakeVote :57, MakeVoteNoError :90 are test helpers — YOK)
 *   types/tx.go                192 lines 186fd6822ee915c2c0daa2426fceaf60ac7b00859df8c70b2c540480b0747091
 *   types/evidence.go          640 lines bbdf366ff13c1f6a03db070f741784741cdf77dc152f3e6857c70b6b7f77115f
 *   types/encoding_helper.go    47 lines 3deeeaa72d628f5d0f9d8435ec8dbffbfbb492b3cc055bcf745c47a4e9105815
 *   types/utils.go              29 lines a763ee01281ce10403e167e70b12bcf8c96b1a15d5dd46ff503322fa7f1aa931
 *   types/signable.go           24 lines ec3376f8d8ef05e32f7e4ab3da36bd82b990db38833433d3645d5c4254fcedb0
 *   types/genesis.go           137 lines 3f3bd9169368cbd0757a1d6cd88f279569dfa652ca059bb503072b17c16065f4
 *   version/version.go          21 lines 8b56396aa5291e1e02cef2790b583321a60b59ccc8e713548bc97d23aa6d9079
 *     ⚠ version/version.go is NOT in the map's pin table; its SHA-256 was
 *       computed here and is reported as an unpinned dependency opened by
 *       this wave. block.go:384 compares against `version.BlockProtocol`,
 *       so the literal is needed.
 *   types/block_test.go        988 lines 6df0acaa2a18f2334fd0ee7434cc690b072be10d9924506f1f845d8c1684b4bd
 *     ⚠ types/block_test.go is NOT in the map's pin table either; opened for
 *       ONE range (:401-436), the reference's own measurement of
 *       MaxHeaderBytes, which CMT_MAX_HEADER_BYTES below re-derives.
 *       SHA-256 computed by the ORCHESTRATOR (Delta B-3).
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * K-2 (atlas-dec-7fde65722d68b32eca08be61fbcb47ac),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * chunking rev 2 (atlas-dec-6d35670369b69df4439cb720036fa2d7),
 * D-17 rev 4 (atlas-dec-9d96e2ec31ad4840cf258df21732b67f),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_BLOCK_H
#define SHARED_DNAC_CMT_BLOCK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_merkle.h"
#include "cmt_time.h"
#include "cmt_part_set.h"   /* PartSetHeader, PartSet, cmt_validate_hash */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ constants ════════════════════════════════════════════════════════ */

/**
 * A hash the reference would have returned as `nil`. POSITIVE, like
 * CMT_BITS_NIL and CMT_PART_SET_EOF, so it is never confused with
 * CMT_REJECT / CMT_FAULT: `Header.Hash`, `Block.Hash` and
 * `Commit.Hash` all have documented nil results, and nil is a normal
 * answer there, not a failure. `out` is left untouched.
 */
#define CMT_HASH_NIL 1

/** cometbft@v0.38.26 crypto/crypto.go:8-11 — `AddressSize`.
 *  `tmhash.TruncatedSize` 20 → 32, the DNA witness id width
 *  (umbrella rev 3 item 4). Same value as cmt_pb.h's CMT_PB_ADDRESS_MAX. */
#define CMT_ADDRESS_SIZE CMT_PB_ADDRESS_MAX

/* The address width and the hash TRUNCATION width are the same quantity in
 * the reference — `crypto.AddressSize = tmhash.TruncatedSize`
 * (crypto/crypto.go:8-11) — so they must not drift apart here either.
 * cmt_tmhash.h has to spell its constant as a literal (cmt_pb.h includes
 * that header), which is exactly the situation where a comment rots; this
 * makes the tie a compile error instead. */
_Static_assert((int)CMT_ADDRESS_SIZE == (int)CMT_TMHASH_TRUNCATED_SIZE,
               "crypto.AddressSize must equal tmhash.TruncatedSize");

/** cometbft@v0.38.26 types/signable.go:9-14 — `MaxSignatureSize`.
 *  `max(ed25519.SignatureSize, 64)` = 64 (709fd12b:12) → the ML-DSA-87 signature size
 *  4627 (shared/crypto/sign/qgp_dilithium.h:14). Same value as cmt_pb.h's
 *  CMT_PB_SIG_MAX. cometbft@v0.38.26 signable.go:13 makes it
 *  `max(ed25519.SignatureSize, mldsa65.SignatureSize)` = 3309 — the
 *  ML-DSA-65 key type this port does not have (ML-DSA-87 is the one key
 *  type); the substitution, and so the value, is unchanged. */
#define CMT_MAX_SIGNATURE_SIZE CMT_PB_SIG_MAX

/** cometbft@v0.38.26 types/vote.go:18-19 — `MaxVoteExtensionSize`,
 *  1024 * 1024. UNCHANGED: it bounds application data, which no DNA
 *  substitution touches. It is declared HERE, in the lower header, because
 *  `ExtendedCommitSig.ValidateBasic` (block.go:760) needs it and
 *  cmt_vote.h includes this file rather than the other way round. */
#define CMT_MAX_VOTE_EXTENSION_SIZE ((size_t)(1024 * 1024))

/** cometbft@v0.38.26 types/genesis.go:18-21 — `MaxChainIDLen` = 50.
 *  UNCHANGED: it bounds the chain id in BYTES, and DNA's chain id is a
 *  32-byte value carried in the proto `string` field, so the check at
 *  block.go:387-389 can never fire for a chain id this port produces.
 *  NOTE (Delta B-3, verifier B): it cannot fire for a WIRE header either —
 *  cmt_pb's decoder refuses any chain id above CMT_PB_CHAINID_MAX (32)
 *  before ValidateBasic runs, so the check at cmt_block.c:359-361 is
 *  currently unreachable. It is kept as the reference's row. If the chain
 *  id capacity is raised to 50 (deviation register R1C-1, an operator
 *  question), CMT_MAX_HEADER_BYTES below becomes 808 (chain id field
 *  1+1+50 = 52 instead of 34) and test_cmt_block's measurement will say so. */
#define CMT_MAX_CHAIN_ID_LEN 50

/** cometbft@v0.38.26 version/version.go:14-16 — `BlockProtocol` = 11.
 *  The value `Header.ValidateBasic` (block.go:384-386) requires in
 *  `Version.Block`. The HOST passes it to cmt_make_block; it is not
 *  hard-coded into the constructor. */
#define CMT_BLOCK_PROTOCOL 11u

/**
 * cometbft@v0.38.26 types/block.go:26-29 — `MaxHeaderBytes`, 626 there.
 *
 * RE-DERIVED, not copied. The reference gives no arithmetic in the source;
 * its own test `types/block_test.go:401-436` DEFINES the maximum by
 * marshalling a header whose every field is at its widest, and asserts
 * 626. The same construction with the DNA sizes gives 790:
 *
 *   field                       tag  len  body                     total
 *   1  version   (ALWAYS)        1    1   block 1+9, app 1+9 = 20     22
 *   2  chain_id                  1    1   32 raw bytes                34
 *   3  height                    1    -   varint(MaxInt64) = 9        10
 *   4  time      (ALWAYS)        1    1   sec 1+10, nanos 1+5 = 17    19
 *   5  last_block_id (ALWAYS)    1    2   hash 1+1+64 = 66            143
 *                                         + part_set_header 1+1+72=74
 *                                           (total 1+5, hash 1+1+64)
 *   6..13  eight 64-byte hashes  1    1   64 each                    528
 *   14 proposer_address          1    1   32                          34
 *                                                            total = 790
 *
 * The SAME arithmetic reproduces the reference's 626 exactly with its own
 * sizes (chain id 200 bytes — fifty 4-byte supplementary runes, which is
 * why its own ValidateBasic would reject that header; hash 32; address
 * 20): 22 + 203 + 10 + 19 + 78 + 272 + 22 = 626. That agreement is what
 * makes this derivation the reference's and not an invention.
 *
 * Still a SOFT max, for the reference's stated reason (:27-28): AppHash is
 * of arbitrary length in cometbft. In this port cmt_pb bounds it at 64
 * bytes, so 790 is a real bound here — but it is left named "soft" because
 * the reference's constant is, and because `MaxDataBytes` treats it as an
 * estimate rather than a checked limit.
 */
#define CMT_MAX_HEADER_BYTES ((int64_t)790)

/**
 * cometbft@v0.38.26 types/block.go:31-39 — `MaxOverheadForBlock` = 11.
 * UNCHANGED. Its four terms are the uvarint length of MaxBlockSizeBytes
 * (4), two embedded-field tags (2), the uvarint length of Data.Txs (4) and
 * the Data.Txs tag (1). Every one depends on MaxBlockSizeBytes
 * (types/params.go:17, 104857600 — not substituted) or on a field number,
 * and no DNA substitution touches either. Checked, not copied.
 */
#define CMT_MAX_OVERHEAD_FOR_BLOCK ((int64_t)11)

/**
 * cometbft@v0.38.26 types/block.go:592-593 — `MaxCommitOverheadBytes`,
 * 94 there. RE-DERIVED: a Commit with no signatures is
 *   block_id (field 3, ALWAYS) 143  (the same 143 as header field 5)
 * + height   1 + varint(MaxInt64) 9  =  10
 * + round    1 + varint(MaxInt32) 5  =   6
 * = 159.
 * The identical arithmetic gives the reference's 94 with its sizes
 * (78 + 10 + 6). NOTE: the reference's source comment ("82 for BlockID, 8
 * for Height, 4 for Round") does not add up to its own constant; the
 * constant is right and the comment is loose. Recorded, not copied.
 */
#define CMT_MAX_COMMIT_OVERHEAD_BYTES ((int64_t)159)

/**
 * cometbft@v0.38.26 types/block.go:595-603 — `MaxCommitSigBytes`.
 *
 * v0.38.26 replaced 709fd12b's measured constant 109 (:595-597) with a
 * FORMULA, `MaxSignatureSize + 20 + 1 + 14 + maxCommitSigProtoEncOverhead`
 * where the overhead is 4 + 2 + 1 + 1 + 3 = 11 (:598, :603). With this
 * port's substitutions — MaxSignatureSize 4627 (ML-DSA-87) and the address
 * 32 bytes (crypto.AddressSize, the `20` of :601) — that is
 *   4627 + 32 + 1 + 14 + 11 = 4685,
 * which is EXACTLY the marshalled size of a widest DNA CommitSig, measured
 * by test_cmt_block.c:
 *   block_id_flag      1 + varint 1                         =    2
 *   validator_address  1 + 1 + 32                           =   34
 *   timestamp (ALWAYS) 1 + 1 + (1+10 seconds, 1+5 nanos)    =   19
 *   signature          1 + 2 + 4627                         = 4630
 *                                                      total = 4685
 * So the value is unchanged by the pin move; only its derivation is now
 * the reference's formula. (Upstream's own value moved from 109 to 3355,
 * because its MaxSignatureSize became ML-DSA-65's 3309 — a key type this
 * port does not have.)
 */
#define CMT_MAX_COMMIT_SIG_BYTES ((int64_t)4685)

_Static_assert(CMT_MAX_COMMIT_SIG_BYTES ==
               (int64_t)CMT_MAX_SIGNATURE_SIZE + (int64_t)CMT_ADDRESS_SIZE +
               1 + 14 + (4 + 2 + 1 + 1 + 3),
               "MaxCommitSigBytes must equal the v0.38.26 formula "
               "(types/block.go:598, :603) at this port's sizes");

/** cometbft@v0.38.26 types/block.go:583-589 — `BlockIDFlag`.
 *  The same three values as cmt_pb.h's wire enum, which this aliases so
 *  there is ONE definition of the flag in the port. */
typedef cmt_pb_block_id_flag_t cmt_block_id_flag_t;
#define CMT_BLOCK_ID_FLAG_ABSENT CMT_PB_BLOCK_ID_FLAG_ABSENT
#define CMT_BLOCK_ID_FLAG_COMMIT CMT_PB_BLOCK_ID_FLAG_COMMIT
#define CMT_BLOCK_ID_FLAG_NIL    CMT_PB_BLOCK_ID_FLAG_NIL

/** Upper bound on the BARE marshal of a BlockID: hash 1+1+64 = 66 plus
 *  part_set_header 1+1+72 = 74. Used to size the header-leaf scratch and
 *  the `Key()` buffer. */
#define CMT_BLOCK_ID_MAX_BYTES 140

/** The widest single leaf of Header.Hash: leaf [4], the bare BlockID. */
#define CMT_HEADER_LEAF_MAX CMT_BLOCK_ID_MAX_BYTES

/** The number of Header.Hash leaves (block.go:464-479). */
#define CMT_HEADER_LEAVES 14

/* ══ BlockID (block.go:1468-1561) ═════════════════════════════════════ */

/** cometbft@v0.38.26 types/block.go:1468-1472 — `type BlockID struct`.
 *  Field-identical to cmt_pb_block_id_t {hash, part_set_header}. */
typedef cmt_pb_block_id_t cmt_block_id_t;

/** cometbft@v0.38.26 types/block.go:1474-1478 — `Equals()`. */
bool cmt_block_id_equals(const cmt_block_id_t *a, const cmt_block_id_t *b);

/**
 * cometbft@v0.38.26 types/block.go:1480-1489 — `Key()`.
 * The machine-readable identity of a BlockID: its hash bytes followed by
 * the marshalled PartSetHeader. The reference builds a Go string; here it
 * is written into the caller's buffer, because a C string cannot hold
 * embedded NULs and these bytes can. `evidence.go:64` compares two of
 * these to order a duplicate-vote pair.
 * @param cap must be at least 64 + 72; @param out_len receives the length.
 * @return CMT_OK, CMT_REJECT if it does not fit, CMT_FAULT on NULL.
 */
int cmt_block_id_key(const cmt_block_id_t *bid, uint8_t *out, size_t cap,
                     size_t *out_len);

/** cometbft@v0.38.26 types/block.go:1491-1501 — `ValidateBasic()`.
 *  The hash MAY be empty (:1493 — a Proposal's POL BlockID has none).
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_block_id_validate_basic(const cmt_block_id_t *bid);

/** cometbft@v0.38.26 types/block.go:1503-1507 — `IsZero()`. */
bool cmt_block_id_is_zero(const cmt_block_id_t *bid);

/** cometbft@v0.38.26 types/block.go:1509-1514 — `IsComplete()`.
 *  `tmhash.Size` 32 → CMT_TMHASH_SIZE 64 at :1511 and :1513. */
bool cmt_block_id_is_complete(const cmt_block_id_t *bid);

/** cometbft@v0.38.26 types/block.go:1526-1536 — `ToProto()`. The identity;
 *  a NULL receiver yields the zero BlockID (:1528-1530). */
int cmt_block_id_to_proto(const cmt_block_id_t *bid, cmt_pb_block_id_t *out);

/** cometbft@v0.38.26 types/block.go:1538-1555 — `BlockIDFromProto()`.
 *  Identity, then PartSetHeaderFromProto (:1546) and ValidateBasic
 *  (:1554). This is the function that makes `VoteFromProto` validate
 *  something even though vote.go:77-80 says it validates nothing. */
int cmt_block_id_from_proto(const cmt_pb_block_id_t *bp, cmt_block_id_t *out);

/** cometbft@v0.38.26 types/block.go:1557-1561 — `ProtoBlockIDIsNil()`. */
bool cmt_proto_block_id_is_nil(const cmt_pb_block_id_t *bp);

/* ══ Header (block.go:325-576) ════════════════════════════════════════ */

/** cometbft@v0.38.26 types/block.go:330-356 — `type Header struct`, the
 *  fourteen fields in the order Header.Hash uses. Field-identical to
 *  cmt_pb_header_t. */
typedef cmt_pb_header_t cmt_header_t;

/**
 * cometbft@v0.38.26 types/block.go:360-377 — `(h *Header) Populate()`.
 * Sets the ten state-derived fields. It deliberately does NOT set Height
 * (MakeBlock does) nor the three fields fillHeader computes.
 * @return CMT_OK, CMT_REJECT if a byte argument is longer than its field,
 *         CMT_FAULT on NULL.
 */
int cmt_header_populate(cmt_header_t *h,
                        const cmt_pb_consensus_t *version,
                        const uint8_t *chain_id, size_t chain_id_len,
                        cmt_time_t timestamp,
                        const cmt_block_id_t *last_block_id,
                        const uint8_t *val_hash, size_t val_hash_len,
                        const uint8_t *next_val_hash, size_t next_val_hash_len,
                        const uint8_t *consensus_hash, size_t consensus_hash_len,
                        const uint8_t *app_hash, size_t app_hash_len,
                        const uint8_t *last_results_hash,
                        size_t last_results_hash_len,
                        const uint8_t *proposer_address,
                        size_t proposer_address_len);

/**
 * cometbft@v0.38.26 types/block.go:383-437 — `(h Header) ValidateBasic()`.
 * Eleven checks in the reference's order. AppHash is deliberately NOT
 * length-checked (:431).
 * @param block_protocol the value Version.Block must equal — the host's,
 *        normally CMT_BLOCK_PROTOCOL. It is a parameter because
 *        `version.BlockProtocol` is a build-time constant of the reference
 *        binary and a chain parameter here.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL.
 */
int cmt_header_validate_basic(const cmt_header_t *h, uint64_t block_protocol);

/**
 * cometbft@v0.38.26 types/block.go:445-480 — `(h *Header) Hash()`.
 *
 * The Merkle root of the fourteen leaves of :464-479, in that order:
 *   [0]  Version.Marshal()                      (bare Consensus message)
 *   [1]  cdcEncode(ChainID)                     (StringValue{1})
 *   [2]  cdcEncode(Height)                      (Int64Value{1})
 *   [3]  StdTimeMarshal(Time)                   (bare Timestamp message)
 *   [4]  LastBlockID.ToProto().Marshal()        (bare BlockID message)
 *   [5..13] cdcEncode(the eight hashes and the address) (BytesValue{1})
 * An empty string/bytes yields the reference's nil, whose leaf is H(0x00)
 * (K-1 rev 2 rule d).
 *
 * @return CMT_OK; CMT_HASH_NIL where the reference returns nil — an empty
 *         ValidatorsHash (:446-448) AND the three marshal failures of
 *         :449-463, of which only the Time one is reachable (an
 *         out-of-range timestamp). The reference returns the same nil for
 *         all four, so this port returns the same code for all four;
 *         CMT_FAULT on NULL or a hash backend failure.
 */
int cmt_header_hash(const cmt_header_t *h, uint8_t out[CMT_TMHASH_SIZE]);

/** cometbft@v0.38.26 types/block.go:521-543 — `(h *Header) ToProto()`.
 *  The identity; a NULL receiver is the reference's nil (:523-525). */
int cmt_header_to_proto(const cmt_header_t *h, cmt_pb_header_t *out);

/**
 * cometbft@v0.38.26 types/block.go:546-576 — `HeaderFromProto()`.
 * Identity, BlockIDFromProto (:554) and ValidateBasic (:575).
 *
 * NOTE reference quirk (:561 and :563): `h.Height = ph.Height` is written
 * TWICE. Ported as-is (the second assignment is a no-op); listed in the
 * report's quirk table.
 */
int cmt_header_from_proto(const cmt_pb_header_t *ph, uint64_t block_protocol,
                          cmt_header_t *out);

/* ══ CommitSig (block.go:605-722) ═════════════════════════════════════ */

/** cometbft@v0.38.26 types/block.go:605-611 — `type CommitSig struct`.
 *  Field-identical to cmt_pb_commit_sig_t. */
typedef cmt_pb_commit_sig_t cmt_commit_sig_t;

/** cometbft@v0.38.26 types/block.go:613-618 — `MaxCommitBytes()`.
 *  `MaxCommitOverheadBytes + ((MaxCommitSigBytes + 3) * valCount)`; the 3
 *  is the repeated field's tag plus a two-byte length varint (:615 — it
 *  was 2 at 709fd12b:610). Overflow REFUSES.
 *  @return CMT_OK, CMT_REJECT on a negative count or an overflow. */
int cmt_max_commit_bytes(int64_t val_count, int64_t *out);

/** cometbft@v0.38.26 types/block.go:620-626 — `NewCommitSigAbsent()`.
 *  Everything empty and the timestamp at GO'S ZERO TIME, which is
 *  CMT_TIME_ZERO and NOT a memset — that is what makes an Absent entry
 *  fifteen bytes on the wire, not two. */
void cmt_new_commit_sig_absent(cmt_commit_sig_t *out);

/** cometbft@v0.38.26 types/block.go:642-657 — `(cs CommitSig) BlockID()`.
 *  Absent and Nil yield the zero BlockID; Commit yields the commit's.
 *  @return CMT_OK, CMT_REJECT for an unknown flag (:653-655 panics),
 *          CMT_FAULT on NULL. */
int cmt_commit_sig_block_id(const cmt_commit_sig_t *cs,
                            const cmt_block_id_t *commit_block_id,
                            cmt_block_id_t *out);

/** cometbft@v0.38.26 types/block.go:659-697 — `(cs CommitSig) ValidateBasic()`.
 *  Two switches: the flag must be one of the three, and then an ABSENT
 *  entry must carry NOTHING (empty address, GO'S ZERO time, empty
 *  signature) while any other must carry a full address and a signature of
 *  1..CMT_MAX_SIGNATURE_SIZE bytes.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_commit_sig_validate_basic(const cmt_commit_sig_t *cs);

/** cometbft@v0.38.26 types/block.go:699-711 — `ToProto()`. The identity. */
int cmt_commit_sig_to_proto(const cmt_commit_sig_t *cs,
                            cmt_pb_commit_sig_t *out);

/** cometbft@v0.38.26 types/block.go:713-722 — `(cs *CommitSig) FromProto()`.
 *  Identity then ValidateBasic (:721) — THIS is where the Absent rule is
 *  enforced on the wire (the map's REV 3 note on 709fd12b block.go:709-716). */
int cmt_commit_sig_from_proto(const cmt_pb_commit_sig_t *csp,
                              cmt_commit_sig_t *out);

/* ══ ExtendedCommitSig (block.go:726-842) ═════════════════════════════ */

/** cometbft@v0.38.26 types/block.go:726-732 —
 *  `type ExtendedCommitSig struct`. Field-identical to
 *  cmt_pb_extended_commit_sig_t; the Go type EMBEDS CommitSig, so its
 *  promoted `ecs.ValidatorAddress` is `ecs->commit_sig.validator_address`
 *  here. */
typedef cmt_pb_extended_commit_sig_t cmt_extended_commit_sig_t;

/** cometbft@v0.38.26 types/block.go:734-738 — `NewExtendedCommitSigAbsent()`. */
void cmt_new_extended_commit_sig_absent(cmt_extended_commit_sig_t *out);

/** cometbft@v0.38.26 types/block.go:753-773 —
 *  `(ecs ExtendedCommitSig) ValidateBasic()`. The CommitSig checks first,
 *  then: a COMMIT entry may carry an extension of at most
 *  CMT_MAX_VOTE_EXTENSION_SIZE and a signature of at most
 *  CMT_MAX_SIGNATURE_SIZE; any other entry may not carry an extension
 *  without a signature for it.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_ecs_validate_basic(const cmt_extended_commit_sig_t *ecs);

/** cometbft@v0.38.26 types/block.go:775-812 —
 *  `(ecs ExtendedCommitSig) EnsureExtension()`. With extensions enabled a
 *  COMMIT entry MUST have an extension signature and a non-COMMIT entry
 *  must have neither field; with them disabled nobody may have either.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_ecs_ensure_extension(const cmt_extended_commit_sig_t *ecs,
                             bool ext_enabled);

/** cometbft@v0.38.26 types/block.go:814-828 — `ToProto()`. The identity. */
int cmt_ecs_to_proto(const cmt_extended_commit_sig_t *ecs,
                     cmt_pb_extended_commit_sig_t *out);

/** cometbft@v0.38.26 types/block.go:830-842 — `FromProto()`.
 *  Identity then ValidateBasic (:841). */
int cmt_ecs_from_proto(const cmt_pb_extended_commit_sig_t *ecsp,
                       cmt_extended_commit_sig_t *out);

/* ══ Commit (block.go:846-1053) ═══════════════════════════════════════ */

/** cometbft@v0.38.26 types/block.go:846-862 — `type Commit struct`.
 *  Field-identical to cmt_pb_commit_t; the `hash` memo of :861 is dropped
 *  (see the header). The signature list is in VALIDATOR-INDEX order
 *  (D-19 rev 6 item 4; types/vote_set.go:649-658 builds it that way). */
typedef cmt_pb_commit_t cmt_commit_t;

/** cometbft@v0.38.26 types/block.go:864-871 — `Clone()`. Deep copy of the
 *  signature list into caller storage.
 *  @return CMT_OK, CMT_REJECT if `sigs_cap` is too small, CMT_FAULT on NULL. */
int cmt_commit_clone(const cmt_commit_t *commit, cmt_commit_sig_t *sigs,
                     size_t sigs_cap, cmt_commit_t *out);

/**
 * cometbft@v0.38.26 types/block.go:873-890 — `(commit *Commit) GetVote()`.
 * Rebuilds the precommit that produced signature `val_idx`. `out` is a
 * `cmt_pb_vote_t`, which IS `cmt_vote_t` (cmt_vote.h) — the two headers do
 * not include each other, and the type is the same.
 * @return CMT_OK, CMT_REJECT where the reference panics on
 *         `val_idx >= commit.Size()` (:877) or meets an unknown flag,
 *         CMT_FAULT on NULL.
 */
int cmt_commit_get_vote(const cmt_commit_t *commit, int32_t val_idx,
                        cmt_pb_vote_t *out);

/** cometbft@v0.38.26 types/block.go:892-904 — `(commit *Commit) VoteSignBytes()`.
 *  GetVote followed by VoteSignBytes; the only part that differs between
 *  validators is the timestamp.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_commit_vote_sign_bytes(const cmt_commit_t *commit,
                               const uint8_t *chain_id, size_t chain_id_len,
                               int32_t val_idx,
                               uint8_t *out, size_t cap, size_t *out_len);

/** cometbft@v0.38.26 types/block.go:906-912 — `Size()`. NULL → 0. */
size_t cmt_commit_size(const cmt_commit_t *commit);

/** cometbft@v0.38.26 types/block.go:914-939 — `(commit *Commit) ValidateBasic()`.
 *  At height 1 the commit is EMPTY BUT NOT NIL and only the two sign
 *  checks apply (:924 gates the rest on `Height >= 1` — note that this
 *  means height 0 skips them, which is the reference's own boundary).
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_commit_validate_basic(const cmt_commit_t *commit);

/**
 * cometbft@v0.38.26 types/block.go:941-960 — `(commit *Commit) Hash()`.
 * The Merkle root over the MARSHALLED CommitSig of every entry, in list
 * order (D-19 rev 6 item 4). The empty commit of height 1 therefore
 * hashes to the empty-tree root H("") — NOT to a run of zero bytes.
 * Allocates one buffer of Size() * CMT_MAX_COMMIT_SIG_BYTES, which is the
 * C cost of the reference's `[][]byte`.
 * @return CMT_OK, CMT_HASH_NIL for a NULL commit (:943-945), CMT_REJECT if
 *         an entry will not marshal, CMT_FAULT on allocation or hash
 *         backend failure.
 */
int cmt_commit_hash(const cmt_commit_t *commit, uint8_t out[CMT_TMHASH_SIZE]);

/** cometbft@v0.38.26 types/block.go:962-980 — `WrappedExtendedCommit()`.
 *  Every entry keeps its CommitSig and gets empty extension fields.
 *  @return CMT_OK, CMT_REJECT if `sigs_cap` is too small, CMT_FAULT on NULL. */
int cmt_commit_wrapped_extended_commit(const cmt_commit_t *commit,
                                       cmt_extended_commit_sig_t *sigs,
                                       size_t sigs_cap,
                                       cmt_pb_extended_commit_t *out);

/** cometbft@v0.38.26 types/block.go:1006-1024 — `ToProto()`. The identity. */
int cmt_commit_to_proto(const cmt_commit_t *commit, cmt_pb_commit_t *out);

/** cometbft@v0.38.26 types/block.go:1026-1053 — `CommitFromProto()`.
 *  BlockIDFromProto (:1035), every entry's FromProto (:1042) and
 *  ValidateBasic (:1052). `sigs` is the caller's storage for the result. */
int cmt_commit_from_proto(const cmt_pb_commit_t *cp, cmt_commit_sig_t *sigs,
                          size_t sigs_cap, cmt_commit_t *out);

/* ══ ExtendedCommit (block.go:1057-1307) ══════════════════════════════ */

/** cometbft@v0.38.26 types/block.go:1057-1066 —
 *  `type ExtendedCommit struct`. Field-identical to
 *  cmt_pb_extended_commit_t; the `bitArray` memo of :1065 is dropped. */
typedef cmt_pb_extended_commit_t cmt_extended_commit_t;

/** cometbft@v0.38.26 types/block.go:1068-1075 — `Clone()`. */
int cmt_extended_commit_clone(const cmt_extended_commit_t *ec,
                              cmt_extended_commit_sig_t *sigs,
                              size_t sigs_cap, cmt_extended_commit_t *out);

/** cometbft@v0.38.26 types/block.go:1127-1134 — `EnsureExtensions()`.
 *  Runs `cmt_ecs_ensure_extension` over every entry in list order and
 *  returns the FIRST refusal, exactly as the reference's loop returns the
 *  first error (:1128-1132). An ExtendedCommit with no entries is accepted.
 *  @return CMT_OK, CMT_REJECT from the first failing entry, CMT_FAULT on
 *          NULL or on a non-zero length with a NULL entry list. */
int cmt_extended_commit_ensure_extensions(const cmt_extended_commit_t *ec,
                                          bool ext_enabled);

/** cometbft@v0.38.26 types/block.go:1136-1149 — `ToCommit()`.
 *  Drops the two extension fields of every entry. */
int cmt_extended_commit_to_commit(const cmt_extended_commit_t *ec,
                                  cmt_commit_sig_t *sigs, size_t sigs_cap,
                                  cmt_commit_t *out);

/** cometbft@v0.38.26 types/block.go:1151-1168 — `GetExtendedVote()`.
 *  Like Commit.GetVote but keeps the extension and its signature. */
int cmt_extended_commit_get_extended_vote(const cmt_extended_commit_t *ec,
                                          int32_t val_index,
                                          cmt_pb_vote_t *out);

/** cometbft@v0.38.26 types/block.go:1170-1173 — `Type()`. Always Precommit. */
uint8_t cmt_extended_commit_type(const cmt_extended_commit_t *ec);

/** cometbft@v0.38.26 types/block.go:1175-1177 — `GetHeight()`. */
int64_t cmt_extended_commit_get_height(const cmt_extended_commit_t *ec);

/** cometbft@v0.38.26 types/block.go:1179-1181 — `GetRound()`. */
int32_t cmt_extended_commit_get_round(const cmt_extended_commit_t *ec);

/** cometbft@v0.38.26 types/block.go:1183-1190 — `Size()`. NULL → 0. */
size_t cmt_extended_commit_size(const cmt_extended_commit_t *ec);

/** cometbft@v0.38.26 types/block.go:1192-1205 — `BitArray()`. Bit i is set
 *  when entry i is NOT Absent. NOTE the reference's own TODO at :1198-1199:
 *  the BlockID is not consulted, so a conflicting vote sets its bit too.
 *  @return CMT_OK, CMT_BITS_NIL for an empty commit (bits.NewBitArrayFromFn
 *          with 0), CMT_REJECT above the derived bit bound, CMT_FAULT on
 *          NULL. */
int cmt_extended_commit_bit_array(const cmt_extended_commit_t *ec,
                                  cmt_bit_array_t *out);

/** cometbft@v0.38.26 types/block.go:1207-1212 — `GetByIndex()`.
 *  The same function as GetExtendedVote; both rows kept. */
int cmt_extended_commit_get_by_index(const cmt_extended_commit_t *ec,
                                     int32_t val_idx, cmt_pb_vote_t *out);

/** cometbft@v0.38.26 types/block.go:1214-1218 — `IsCommit()`. */
bool cmt_extended_commit_is_commit(const cmt_extended_commit_t *ec);

/** cometbft@v0.38.26 types/block.go:1220-1245 — `ValidateBasic()`. */
int cmt_extended_commit_validate_basic(const cmt_extended_commit_t *ec);

/** cometbft@v0.38.26 types/block.go:1247-1265 — `ToProto()`. The identity. */
int cmt_extended_commit_to_proto(const cmt_extended_commit_t *ec,
                                 cmt_pb_extended_commit_t *out);

/** cometbft@v0.38.26 types/block.go:1267-1293 — `ExtendedCommitFromProto()`.
 *  BlockIDFromProto (:1276), every entry's FromProto (:1283) and
 *  ValidateBasic (:1292). */
int cmt_extended_commit_from_proto(const cmt_pb_extended_commit_t *ecp,
                                   cmt_extended_commit_sig_t *sigs,
                                   size_t sigs_cap,
                                   cmt_extended_commit_t *out);

/* ══ Data and transactions (block.go:1297-1373, tx.go) ════════════════ */

/** cometbft@v0.38.26 types/block.go:1297-1306 — `type Data struct`.
 *  Field-identical to cmt_pb_data_t; the `hash` memo of :1305 is dropped. */
typedef cmt_pb_data_t cmt_data_t;

/** cometbft@v0.38.26 types/tx.go:28-31 — `(tx Tx) Hash()`.
 *  `tmhash.Sum(tx)` → SHA3-512 here. This is the LEAF of DataHash, so the
 *  tree is over transaction hashes, not over transactions.
 *  @return CMT_OK, CMT_FAULT on NULL or a hash backend failure. */
int cmt_tx_hash(const uint8_t *tx, size_t tx_len,
                uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@v0.38.26 types/block.go:1308-1317 — `(data *Data) Hash()`, via
 * `Txs.Hash` and `hashList` (types/tx.go:45-50, :63-69).
 * A NULL Data hashes the empty transaction list (:1310-1312), i.e. H("").
 * Allocates one n * 64 buffer for the hash list.
 * @return CMT_OK, CMT_FAULT on allocation or hash backend failure.
 */
int cmt_data_hash(const cmt_data_t *data, uint8_t out[CMT_TMHASH_SIZE]);

/** cometbft@v0.38.26 types/block.go:1339-1352 — `(data *Data) ToProto()`.
 *  The identity. NOTE: the reference leaves `tp.Txs` nil for an empty list
 *  (:1343) — an empty and a nil list marshal and hash alike, so the
 *  distinction has no byte consequence and none is representable here. */
int cmt_data_to_proto(const cmt_data_t *data, cmt_pb_data_t *out);

/** cometbft@v0.38.26 types/block.go:1354-1373 — `DataFromProto()`.
 *  The identity. NOTE reference behaviour at :1369: an empty input yields
 *  an EMPTY-BUT-NOT-NIL `Txs`. In C both are `{NULL, 0}` and both hash to
 *  H(""), so nothing observable changes; recorded because the map calls
 *  the line out. This FromProto does NOT validate — the reference's does
 *  not either. */
int cmt_data_from_proto(const cmt_pb_data_t *dp, cmt_data_t *out);

/* ══ EvidenceData (block.go:1377-1464, evidence.go) ═══════════════════ */

/**
 * cometbft@v0.38.26 types/block.go:1377-1384 — `type EvidenceData struct`.
 *
 * THE ONE TYPE THAT IS NOT AN ALIAS. The Go domain field is an
 * `EvidenceList` of Evidence INTERFACES; the wire type is
 * `EvidenceList{repeated Evidence}`. An item is modelled as R1-A's
 * `cmt_pb_evidence_t`, the wire oneof wrapper, of which only the
 * DuplicateVoteEvidence branch is in scope (cmt_pb.h:379-393).
 *
 * `byte_size` is the reference's cache at :1383, which unlike the hash
 * caches is OBSERVABLE: `FromProto` sets it from the incoming message
 * (:1461) while `ByteSize` computes it lazily (:1396-1402). Kept for that
 * reason, and only for it.
 */
typedef struct {
    cmt_pb_evidence_t *evidence;       /* block.go:1379, caller-owned */
    size_t             evidence_cap;
    size_t             evidence_len;
    int64_t            byte_size;      /* :1383 */
} cmt_evidence_data_t;

/**
 * cometbft@v0.38.26 types/block.go:1386-1392 — `(data *EvidenceData) Hash()`,
 * via `EvidenceList.Hash` (types/evidence.go:452-464).
 *
 * The Merkle root over each item's `Bytes()`, which for
 * DuplicateVoteEvidence is the marshal of the BARE
 * DuplicateVoteEvidence message — NOT of the Evidence wrapper
 * (evidence.go:94-103). Two different byte strings; cmt_pb.h:386-392 warns
 * about the same confusion.
 *
 * Since wave R1-D this DELEGATES to `cmt_evidence_list_hash`
 * (cmt_evidence.h), which is the reference's `EvidenceList.Hash` and this
 * row's actual home — the reference's body here is that one call. One
 * implementation, identical bytes.
 * @return CMT_OK, CMT_REJECT if an item is not a DuplicateVoteEvidence or
 *         will not marshal, CMT_FAULT on NULL, allocation or hash failure.
 */
int cmt_evidence_data_hash(const cmt_evidence_data_t *data,
                           uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@v0.38.26 types/block.go:1394-1404 — `ByteSize()`.
 * The marshalled size of the WRAPPED EvidenceList (`pb.Size()` at :1401),
 * not of the bare items. Zero for an empty list, and the reference's
 * `data.byteSize == 0` guard (:1396) means a list whose real size is 0
 * would be recomputed every call — harmless, ported as-is.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_evidence_data_byte_size(cmt_evidence_data_t *data, int64_t *out);

/** cometbft@v0.38.26 types/block.go:1426-1444 — `(data *EvidenceData) ToProto()`.
 *  The identity: every item is already the wire wrapper. `out` is the
 *  caller's array of `out_cap` slots; `out_len` receives the count. */
int cmt_evidence_data_to_proto(const cmt_evidence_data_t *data,
                               cmt_pb_evidence_t *out, size_t out_cap,
                               size_t *out_len);

/**
 * cometbft@v0.38.26 types/block.go:1446-1464 — `(data *EvidenceData) FromProto()`.
 * Copies the items and sets `byte_size` from the incoming list (:1461).
 *
 * Since wave R1-D every item goes through `cmt_evidence_from_proto`
 * (:1454) before it is copied, so an item that is not a recognised branch,
 * whose votes are malformed, or whose pair is not strictly ordered makes
 * the WHOLE call fail (:1455-1457) — the reference's behaviour. The
 * reference stores the decoded domain object (:1458) and this stores the
 * wire item, which carries the same bytes; see the note at the call site.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_evidence_data_from_proto(const cmt_pb_evidence_t *items, size_t n,
                                 cmt_pb_evidence_t *storage, size_t cap,
                                 cmt_evidence_data_t *out);

/* ══ Block (block.go:42-321) ══════════════════════════════════════════ */

/** cometbft@v0.38.26 types/block.go:42-51 — `type Block struct`.
 *  The mutex (:44) and the `verifiedHash` memo (:46) are dropped;
 *  `last_commit` is a POINTER, as the reference's is. */
typedef struct {
    cmt_header_t        header;        /* block.go:47 */
    cmt_data_t          data;          /* :48 */
    cmt_evidence_data_t evidence;      /* :49 */
    cmt_commit_t       *last_commit;   /* :50 */
} cmt_block_t;

/**
 * cometbft@v0.38.26 types/test_util.go:106-123 — `MakeBlock()`.
 *
 * THE PRODUCTION BLOCK CONSTRUCTOR despite living in a file named
 * test_util.go: state/state.go:234-271 (`MakeBlock`) is its only caller
 * chain, reached from state/execution.go:137 and :171. Pin record rev 4
 * (atlas-dec-483ec17cbb352ef0ec2267ccd953339c) pins the file for that
 * reason.
 *
 * `Version{Block: version.BlockProtocol, App: 0}` at :112 are VALUES the
 * reference's build fixes; here BOTH are parameters the host passes, so
 * the App version is never silently zero (D-19 rev 6 item 1).
 * The constructor ends in fillHeader (:121).
 *
 * @return CMT_OK, CMT_REJECT, CMT_FAULT (fillHeader allocates).
 */
int cmt_make_block(int64_t height,
                   uint64_t version_block, uint64_t version_app,
                   const cmt_data_t *data,
                   cmt_commit_t *last_commit,
                   const cmt_evidence_data_t *evidence,
                   cmt_block_t *out);

/**
 * cometbft@v0.38.26 types/block.go:109-120 — `(b *Block) fillHeader()`.
 * Fills the three header fields that are a function of the block body.
 *
 * NOTE reference quirk (:111, :114, :117): each guard is `== nil`, not
 * `len(...) == 0`. C has no nil/empty distinction for a fixed-size field,
 * so an EMPTY field is filled here where the reference would fill only an
 * absent one. The two agree everywhere the reference is reachable: a
 * present hash is always CMT_TMHASH_SIZE wide, and a zero-length one is
 * exactly the nil the reference means.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_block_fill_header(cmt_block_t *b);

/**
 * cometbft@v0.38.26 types/block.go:53-107 — `(b *Block) ValidateBasic()`.
 * Header.ValidateBasic, then LastCommit present and valid and its hash
 * equal to LastCommitHash, then DataHash, then the per-evidence
 * ValidateBasic loop, then the evidence hash — the reference's order.
 *
 * Since wave R1-D the loop of :92-97 is PERFORMED. It reaches this
 * branch's ValidateBasic the way the port's representation requires,
 * through `cmt_evidence_from_proto` (evidence.go:537 → :199): the
 * reference's Block holds already-decoded domain objects and re-validates
 * them, while this port holds wire items. The check is a pure predicate
 * over each item's own fields, so the verdict is identical.
 *
 * ⚠ CONSEQUENCE FOR CALLERS: a block carrying evidence whose votes are
 * malformed, or whose duplicate pair is not strictly ordered by BlockID
 * key, is now REJECTED here where wave R1-B accepted it. No block WITHOUT
 * evidence changes verdict.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_block_validate_basic(const cmt_block_t *b, uint64_t block_protocol);

/**
 * cometbft@v0.38.26 types/block.go:122-141 — `(b *Block) Hash()`.
 * fillHeader, then Header.Hash.
 * @return CMT_OK; CMT_HASH_NIL for a NULL block (:125-127), a NULL
 *         LastCommit (:131-133) or a nil header hash; CMT_FAULT.
 */
int cmt_block_hash(cmt_block_t *b, uint8_t out[CMT_TMHASH_SIZE]);

/** cometbft@v0.38.26 types/block.go:164-174 — `HashesTo()`.
 *  False for an empty `hash` (:167-169) or a NULL block (:170-172). */
bool cmt_block_hashes_to(cmt_block_t *b, const uint8_t *hash, size_t hash_len);

/**
 * cometbft@v0.38.26 types/block.go:225-244 — `(b *Block) ToProto()` FOLLOWED
 * BY `proto.Marshal` — in the reference two steps, here one, because the
 * domain struct IS the proto struct (see the header) and only the bytes
 * are ever wanted (:153-160, :178-183).
 *
 * The outer frame is block.pb.go:136-184: header (1, ALWAYS), data (2,
 * ALWAYS), evidence (3, ALWAYS, an EvidenceList), last_commit (4, POINTER,
 * omitted when NULL).
 * @return CMT_OK, CMT_REJECT if it does not fit in `cap`, CMT_FAULT.
 */
int cmt_block_marshal(const cmt_block_t *b, uint8_t *out, size_t cap,
                      size_t *out_len);

/** cometbft@v0.38.26 types/block.go:176-184 — `(b *Block) Size()`.
 *  The marshalled size. The reference returns 0 when ToProto fails
 *  (:179-181); so does this.
 *  @param scratch a buffer of `scratch_cap` bytes to marshal into. */
size_t cmt_block_size(const cmt_block_t *b, uint8_t *scratch,
                      size_t scratch_cap);

/**
 * cometbft@v0.38.26 types/block.go:143-162 — `(b *Block) MakePartSet()`.
 * Marshals the block and splits it into parts.
 * @param scratch receives the marshalled block and MUST outlive the part
 *        set: the parts point into it (cmt_part_set.h's payload note).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_block_make_part_set(const cmt_block_t *b, uint32_t part_size,
                            uint8_t *scratch, size_t scratch_cap,
                            cmt_part_t *parts, size_t parts_cap,
                            cmt_part_set_t *out);

/**
 * cometbft@v0.38.26 types/block.go:246-277 — `BlockFromProto()`.
 * HeaderFromProto (:254), DataFromProto (:259), EvidenceData.FromProto
 * (:264), CommitFromProto when LastCommit is present (:268-274), then
 * Block.ValidateBasic (:276).
 * @param last_commit storage for the decoded LastCommit, or NULL to
 *        reproduce the reference's nil-LastCommit path.
 */
int cmt_block_from_proto(const cmt_block_t *bp, uint64_t block_protocol,
                         cmt_commit_sig_t *sigs, size_t sigs_cap,
                         cmt_pb_evidence_t *ev_storage, size_t ev_cap,
                         cmt_commit_t *last_commit,
                         cmt_block_t *out);

/** cometbft@v0.38.26 types/block.go:281-300 — `MaxDataBytes()`.
 *  The reference PANICS on a negative result (:291-297); this REFUSES.
 *  @return CMT_OK, CMT_REJECT on a negative result or an overflow. */
int cmt_max_data_bytes(int64_t max_bytes, int64_t evidence_bytes,
                       int64_t vals_count, int64_t *out);

/** cometbft@v0.38.26 types/block.go:302-321 — `MaxDataBytesNoEvidence()`.
 *  The same with the evidence term assumed zero.
 *  @return CMT_OK, CMT_REJECT on a negative result or an overflow. */
int cmt_max_data_bytes_no_evidence(int64_t max_bytes, int64_t vals_count,
                                   int64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_BLOCK_H */
