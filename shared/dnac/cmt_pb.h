/**
 * @file shared/dnac/cmt_pb.h
 * @brief cometbft @709fd12b's proto3 wire encoding, reproduced in C (K-1).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-A of the cometbft → C consensus port. No consensus path calls
 * anything here yet; additive only. The live witness BFT, QC V2 and the
 * T3 wave-1 modules (tm_commit, tm_vote, tm_wal) are byte-identically
 * untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * These are THE BYTES THAT GET HASHED AND SIGNED. Every header leaf, every
 * Merkle leaf, every sign-bytes preimage and every stored certificate in
 * the ported consensus is produced here. A one-byte difference from the
 * reference is a different chain.
 *
 * No third-party protobuf library is linked; the rules are reproduced from
 * the pinned `.proto` files (field numbers and types) and the pinned
 * generated encoders (which fields are written, and when).
 *
 * ── THE RULES (K-1 rev 2, atlas-dec-3ba8153088b0d60c63083028023b61be) ──
 * Fields are emitted in ASCENDING field-number order. tag = (field<<3)|wt,
 * wire types 0 varint, 1 fixed64, 2 length-delimited.
 *
 *  (a) OMIT-ZERO — a scalar equal to 0, a bytes/string of length 0, and a
 *      POINTER (nullable) embedded message that is nil are NOT written.
 *  (b) ALWAYS-EMIT — a message field declared `(gogoproto.nullable) = false`
 *      is written even when its body is empty, as `tag 00`. Every such
 *      field is marked ALWAYS in the structs below.
 *  (c) Timestamp — {int64 seconds = 1, int32 nanos = 2}, itself omit-zero,
 *      valid range seconds in [-62135596800, 253402300800), nanos in
 *      [0, 1e9). Go's ZERO time is seconds = -62135596800, so the zero
 *      time is eleven bytes, not zero bytes. See cmt_time.h — a
 *      memset-zeroed cmt_time_t is 1970, NOT Go's zero.
 *  (d) Header leaves are BARE message bytes, not tagged fields — see
 *      cmt_pb_cdc_encode_* below.
 *  (e) Sign bytes are uvarint(len) ‖ message (cmt_pb_marshal_delimited);
 *      canonical height/round are sfixed64 and are themselves omit-zero.
 *  (f) `repeated uint64` is PACKED; repeated bytes/messages carry one tag
 *      per element.
 *  (g) A negative int32/int64/enum is the 10-byte two's-complement varint
 *      (Go widens to uint64 before writing).
 *  (h) PublicKey's ML-DSA-87 branch is field 9 — K-2,
 *      atlas-dec-7fde65722d68b32eca08be61fbcb47ac.
 *
 * ── DECODE CONTRACT ────────────────────────────────────────────────────
 * Each `_unmarshal` mirrors the message's generated `Unmarshal`: fields in
 * any order, a repeated scalar accepted packed OR unpacked, an unknown
 * field number skipped by wire type (including group markers), a repeated
 * embedded message appended, a NON-repeated embedded message MERGED into
 * whatever is already there, and a scalar last-one-wins.
 *
 * On top of that, and only on top of that, comes the APPROVED INVARIANT
 * (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07): every length and count
 * that arrives from the wire is checked against the buffer and against the
 * destination before anything is read or written, and a message whose
 * fields do not agree is REFUSED. Where Go's runtime would have panicked,
 * this returns CMT_REJECT. It never reads out of bounds and it never
 * aborts the process.
 *
 * ⚠ NO POINTER INTO THE INPUT BUFFER SURVIVES A DECODE CALL. Fixed-size
 * fields are copied into the message struct; variable-length fields
 * (transaction bytes, a block part's payload, a vote extension, a tx
 * result's data) are copied into the `cmt_pb_arena_t` the caller supplies,
 * and the resulting `cmt_pb_bytes_t` point THERE. The arena must outlive
 * the decoded message. There is no `keep_input` contract on any field.
 *
 * ── DNA SIZE SUBSTITUTIONS (umbrella rev 3 §10.8 item 4) ───────────────
 * hash 64 (SHA3-512), signature 4627, public key 2592, address 32, chain
 * id 32 raw bytes carried in the proto `string` field. A byte field whose
 * wire length EXCEEDS its destination is refused — that is a buffer
 * capacity rule, not a semantic one. SEMANTIC length rules (ValidateHash,
 * "an address is exactly 32 bytes", "a signature is exactly 4627") belong
 * to the ValidateBasic ports of waves R1-B / R1-C and are NOT applied
 * here, because the generated Unmarshal does not apply them either. The
 * two exceptions, both because the reference itself checks at that point:
 *   · PublicKey branch 9 must be exactly 2592 bytes (K-2; the size rule
 *     follows crypto/encoding/codec.go:42-63, which refuses a wrong key
 *     size on decode);
 *   · cmt_proof_from_proto ends in cmt_proof_validate_basic
 *     (crypto/merkle/proof.go:160).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Encoding is a pure function of the message struct: field order is fixed
 * by field number, no map is iterated, no clock is read, no randomness is
 * drawn, no floating point is used. Two nodes holding the same struct
 * emit the same bytes. Decoding is a pure function of the input buffer.
 *
 * ── ENUM VALUES ARE NOT VALIDATED ──────────────────────────────────────
 * proto3 enums are open and the generated decoders store whatever varint
 * arrives; so does this one. Rejecting an unknown SignedMsgType or
 * BlockIDFlag is ValidateBasic's job in a later wave (types/vote.go:278,
 * types/block.go:654), not the codec's.
 *
 * Reference @709fd12b — .proto (field numbers/types) and .pb.go (which
 * fields are written), SHA-256 of every one verified before use; the full
 * table is in tasks/comet-port-map.md "K-1" and "Pin tablosu eki (rev 4)".
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * K-2 (atlas-dec-7fde65722d68b32eca08be61fbcb47ac),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * pin rev 4 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PB_H
#define SHARED_DNAC_CMT_PB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"    /* CMT_OK / CMT_REJECT / CMT_FAULT, CMT_TMHASH_SIZE */
#include "cmt_time.h"      /* cmt_time_t, CMT_TIME_ZERO                       */
#include "cmt_merkle.h"    /* cmt_proof_t                                     */
#include "cmt_bits.h"      /* cmt_bit_array_t                                 */

#include "crypto/sign/qgp_dilithium.h"   /* QGP_DSA87_* sizes */

#ifdef __cplusplus
extern "C" {
#endif

/* ── sizes ──────────────────────────────────────────────────────────── */

#define CMT_PB_HASH_MAX     CMT_TMHASH_SIZE            /* 64   */
#define CMT_PB_ADDRESS_MAX  32                         /* witness id       */
#define CMT_PB_CHAINID_MAX  32                         /* derived chain id */
#define CMT_PB_SIG_MAX      QGP_DSA87_SIGNATURE_BYTES  /* 4627 */
#define CMT_PB_PUBKEY_LEN   QGP_DSA87_PUBLICKEYBYTES   /* 2592 */

/* ── enums, from the pinned .proto ──────────────────────────────────── */

/** cometbft@709fd12b proto/tendermint/types/types.proto:17-23. */
typedef enum {
    CMT_PB_MSG_TYPE_UNKNOWN   = 0,
    CMT_PB_MSG_TYPE_PREVOTE   = 1,
    CMT_PB_MSG_TYPE_PRECOMMIT = 2,
    CMT_PB_MSG_TYPE_PROPOSAL  = 32
} cmt_pb_signed_msg_type_t;

/** cometbft@709fd12b proto/tendermint/types/validator.proto:14-17. */
typedef enum {
    CMT_PB_BLOCK_ID_FLAG_UNKNOWN = 0,
    CMT_PB_BLOCK_ID_FLAG_ABSENT  = 1,
    CMT_PB_BLOCK_ID_FLAG_COMMIT  = 2,
    CMT_PB_BLOCK_ID_FLAG_NIL     = 3
} cmt_pb_block_id_flag_t;

/* ── variable-length payloads ───────────────────────────────────────── */

/** A byte range the caller owns. After a decode it points into the arena
 *  that decode was given — never into the input buffer. */
typedef struct {
    const uint8_t *data;
    size_t         len;
} cmt_pb_bytes_t;

/** Scratch the decoder copies variable-length payloads into. The caller
 *  supplies the storage and its lifetime; the decoder only bumps `used`
 *  and never frees. Reset by setting `used` to 0. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   used;
} cmt_pb_arena_t;

/* ── messages ───────────────────────────────────────────────────────── */

/** version/types.proto:19-24 — `tendermint.version.Consensus`. */
typedef struct {
    uint64_t block;    /* field 1 */
    uint64_t app;      /* field 2 */
} cmt_pb_consensus_t;

/** types/types.proto:27-30 — `PartSetHeader`.
 *  canonical.proto:15-18's `CanonicalPartSetHeader` has the identical
 *  shape ({uint32 total = 1, bytes hash = 2}) and shares this type; the
 *  two messages keep separate marshal/unmarshal entry points so each
 *  reference message is accounted for. */
typedef struct {
    uint32_t total;                          /* field 1 */
    uint8_t  hash[CMT_PB_HASH_MAX];          /* field 2 */
    size_t   hash_len;
} cmt_pb_part_set_header_t;

typedef cmt_pb_part_set_header_t cmt_pb_canonical_part_set_header_t;

/** types/types.proto:39-42 — `BlockID`. canonical.proto:10-13's
 *  `CanonicalBlockID` has the identical shape and shares this type. */
typedef struct {
    uint8_t hash[CMT_PB_HASH_MAX];                  /* field 1 */
    size_t  hash_len;
    cmt_pb_part_set_header_t part_set_header;       /* field 2, ALWAYS */
} cmt_pb_block_id_t;

typedef cmt_pb_block_id_t cmt_pb_canonical_block_id_t;

/** types/types.proto:32-36 — `Part`. `bytes` is up to
 *  BlockPartSizeBytes (65536) and lives in the arena. */
typedef struct {
    uint32_t       index;      /* field 1 */
    cmt_pb_bytes_t bytes;      /* field 2 */
    cmt_proof_t    proof;      /* field 3, ALWAYS (cmt_merkle.h) */
} cmt_pb_part_t;

/** crypto/keys.proto:9-17 — `PublicKey`, with the ML-DSA-87 branch at
 *  field 9 (K-2). `present` is false for the reference's nil oneof. */
typedef struct {
    bool    present;
    uint8_t key[CMT_PB_PUBKEY_LEN];   /* field 9, exactly 2592 bytes */
} cmt_pb_public_key_t;

/** validator.proto:34-37 — `SimpleValidator`. This is the leaf whose
 *  Merkle root is ValidatorsHash (types/validator.go:118-134). `pub_key`
 *  is a POINTER field: absent when `pub_key.present` is false. */
typedef struct {
    cmt_pb_public_key_t pub_key;       /* field 1, POINTER */
    int64_t             voting_power;  /* field 2 */
} cmt_pb_simple_validator_t;

/** validator.proto:27-32 — `Validator`. `pub_key` is ALWAYS emitted here,
 *  unlike SimpleValidator's. */
typedef struct {
    uint8_t             address[CMT_PB_ADDRESS_MAX];  /* field 1 */
    size_t              address_len;
    cmt_pb_public_key_t pub_key;                      /* field 2, ALWAYS */
    int64_t             voting_power;                 /* field 3 */
    int64_t             proposer_priority;            /* field 4 */
} cmt_pb_validator_t;

/** validator.proto:21-25 — `ValidatorSet`. `validators` is caller-owned
 *  storage: `validators_cap` slots, `validators_len` used. `proposer` is
 *  a POINTER field, present when `has_proposer`. */
typedef struct {
    cmt_pb_validator_t *validators;        /* field 1, repeated */
    size_t              validators_cap;
    size_t              validators_len;
    bool                has_proposer;      /* field 2, POINTER */
    cmt_pb_validator_t  proposer;
    int64_t             total_voting_power; /* field 3 */
} cmt_pb_validator_set_t;

/** params.proto:75-78 — `HashedParams`. H(marshal) is ConsensusHash
 *  (types/params.go:272-290). */
typedef struct {
    int64_t block_max_bytes;   /* field 1 */
    int64_t block_max_gas;     /* field 2 */
} cmt_pb_hashed_params_t;

/** types/types.proto:47-71 — `Header`, the 14 fields in order. Fields 1
 *  (version), 4 (time) and 5 (last_block_id) are ALWAYS emitted. */
typedef struct {
    cmt_pb_consensus_t version;                                  /* 1  ALWAYS */
    uint8_t  chain_id[CMT_PB_CHAINID_MAX]; size_t chain_id_len;  /* 2  */
    int64_t  height;                                             /* 3  */
    cmt_time_t time;                                             /* 4  ALWAYS */
    cmt_pb_block_id_t last_block_id;                             /* 5  ALWAYS */
    uint8_t  last_commit_hash[CMT_PB_HASH_MAX];    size_t last_commit_hash_len;     /* 6  */
    uint8_t  data_hash[CMT_PB_HASH_MAX];           size_t data_hash_len;            /* 7  */
    uint8_t  validators_hash[CMT_PB_HASH_MAX];     size_t validators_hash_len;      /* 8  */
    uint8_t  next_validators_hash[CMT_PB_HASH_MAX];size_t next_validators_hash_len; /* 9  */
    uint8_t  consensus_hash[CMT_PB_HASH_MAX];      size_t consensus_hash_len;       /* 10 */
    uint8_t  app_hash[CMT_PB_HASH_MAX];            size_t app_hash_len;             /* 11 */
    uint8_t  last_results_hash[CMT_PB_HASH_MAX];   size_t last_results_hash_len;    /* 12 */
    uint8_t  evidence_hash[CMT_PB_HASH_MAX];       size_t evidence_hash_len;        /* 13 */
    uint8_t  proposer_address[CMT_PB_ADDRESS_MAX]; size_t proposer_address_len;     /* 14 */
} cmt_pb_header_t;

/** types/types.proto:74-79 — `Data`. Each tx lives in the arena. */
typedef struct {
    cmt_pb_bytes_t *txs;       /* field 1, repeated */
    size_t          txs_cap;
    size_t          txs_len;
} cmt_pb_data_t;

/** types/types.proto:83-103 — `Vote`. Fields 4 (block_id) and 5
 *  (timestamp) are ALWAYS emitted. `extension` is application data of
 *  unbounded length and lives in the arena. */
typedef struct {
    int32_t           type;                /* 1  */
    int64_t           height;              /* 2  */
    int32_t           round;               /* 3  */
    cmt_pb_block_id_t block_id;            /* 4  ALWAYS */
    cmt_time_t        timestamp;           /* 5  ALWAYS */
    uint8_t validator_address[CMT_PB_ADDRESS_MAX]; size_t validator_address_len; /* 6 */
    int32_t           validator_index;     /* 7  */
    uint8_t signature[CMT_PB_SIG_MAX];             size_t signature_len;         /* 8 */
    cmt_pb_bytes_t    extension;           /* 9  */
    uint8_t extension_signature[CMT_PB_SIG_MAX];   size_t extension_signature_len; /* 10 */
} cmt_pb_vote_t;

/** types/types.proto:114-120 — `CommitSig`. Field 3 (timestamp) is ALWAYS
 *  emitted; an Absent entry is therefore 15 bytes, never 2. */
typedef struct {
    int32_t    block_id_flag;                                    /* 1 */
    uint8_t    validator_address[CMT_PB_ADDRESS_MAX];            /* 2 */
    size_t     validator_address_len;
    cmt_time_t timestamp;                                        /* 3 ALWAYS */
    uint8_t    signature[CMT_PB_SIG_MAX];                        /* 4 */
    size_t     signature_len;
} cmt_pb_commit_sig_t;

/** types/types.proto:106-111 — `Commit`. Field 3 is ALWAYS emitted;
 *  `signatures` is caller-owned storage. */
typedef struct {
    int64_t              height;         /* 1 */
    int32_t              round;          /* 2 */
    cmt_pb_block_id_t    block_id;       /* 3 ALWAYS */
    cmt_pb_commit_sig_t *signatures;     /* 4 repeated */
    size_t               signatures_cap;
    size_t               signatures_len;
} cmt_pb_commit_t;

/** types/types.proto:145-154 — `Proposal`. Fields 5 and 6 are ALWAYS
 *  emitted. Note `pol_round` is int32 here and int64 in CanonicalProposal. */
typedef struct {
    int32_t           type;        /* 1 */
    int64_t           height;      /* 2 */
    int32_t           round;       /* 3 */
    int32_t           pol_round;   /* 4 */
    cmt_pb_block_id_t block_id;    /* 5 ALWAYS */
    cmt_time_t        timestamp;   /* 6 ALWAYS */
    uint8_t signature[CMT_PB_SIG_MAX]; size_t signature_len;   /* 7 */
} cmt_pb_proposal_t;

/** canonical.proto:30-37 — `CanonicalVote`, the vote sign-bytes message.
 *  height and round are SFIXED64 and omit-zero; `block_id` is a POINTER
 *  (absent when `has_block_id` is false — CanonicalizeBlockID returns nil
 *  for a zero BlockID, types/canonical.go:18-34); timestamp is ALWAYS. */
typedef struct {
    int32_t                     type;          /* 1 */
    int64_t                     height;        /* 2 sfixed64 */
    int64_t                     round;         /* 3 sfixed64 */
    bool                        has_block_id;  /* 4 POINTER */
    cmt_pb_canonical_block_id_t block_id;
    cmt_time_t                  timestamp;     /* 5 ALWAYS */
    uint8_t chain_id[CMT_PB_CHAINID_MAX]; size_t chain_id_len;  /* 6 */
} cmt_pb_canonical_vote_t;

/** canonical.proto:20-28 — `CanonicalProposal`. `pol_round` is INT64
 *  here (field 4), unlike Proposal's int32. */
typedef struct {
    int32_t                     type;          /* 1 */
    int64_t                     height;        /* 2 sfixed64 */
    int64_t                     round;         /* 3 sfixed64 */
    int64_t                     pol_round;     /* 4 int64 */
    bool                        has_block_id;  /* 5 POINTER */
    cmt_pb_canonical_block_id_t block_id;
    cmt_time_t                  timestamp;     /* 6 ALWAYS */
    uint8_t chain_id[CMT_PB_CHAINID_MAX]; size_t chain_id_len;  /* 7 */
} cmt_pb_canonical_proposal_t;

/** canonical.proto:41-46 — `CanonicalVoteExtension`. No ALWAYS field and
 *  no timestamp; every field is omit-zero. */
typedef struct {
    cmt_pb_bytes_t extension;   /* 1 */
    int64_t        height;      /* 2 sfixed64 */
    int64_t        round;       /* 3 sfixed64 */
    uint8_t chain_id[CMT_PB_CHAINID_MAX]; size_t chain_id_len;  /* 4 */
} cmt_pb_canonical_vote_extension_t;

/** evidence.proto:19-25 — `DuplicateVoteEvidence`. vote_a and vote_b are
 *  POINTERS; timestamp is ALWAYS. H(marshal of THIS message, with no
 *  Evidence wrapper) is the evidence hash (types/evidence.go:95-108). */
typedef struct {
    bool          has_vote_a;          /* 1 POINTER */
    cmt_pb_vote_t vote_a;
    bool          has_vote_b;          /* 2 POINTER */
    cmt_pb_vote_t vote_b;
    int64_t       total_voting_power;  /* 3 */
    int64_t       validator_power;     /* 4 */
    cmt_time_t    timestamp;           /* 5 ALWAYS */
} cmt_pb_duplicate_vote_evidence_t;

/**
 * evidence.proto:11-16 — `Evidence`, the oneof wrapper.
 *
 * ONLY branch 1 (DuplicateVoteEvidence) is in scope. Branch 2
 * (LightClientAttackEvidence) belongs to the light client, which this
 * chain does not have and which the port map places out of scope (REV 3
 * "Kapsam kuralı"); the decoder REFUSES it rather than skipping it,
 * because silently dropping an evidence branch would let two nodes that
 * disagree about scope hash the same list differently.
 *
 * Note that this wrapper is used for the EvidenceList on the block wire,
 * NOT for hashing: `DuplicateVoteEvidence.Bytes()` (evidence.go:95-101)
 * and `EvidenceList.Hash()` (:450-461) both marshal the BARE
 * DuplicateVoteEvidence. Two different byte strings; do not confuse them.
 */
typedef struct {
    bool                             has_duplicate_vote_evidence;
    cmt_pb_duplicate_vote_evidence_t duplicate_vote_evidence;
} cmt_pb_evidence_t;

/**
 * abci/types.proto — `ExecTxResult`, RESTRICTED to the four deterministic
 * fields {code = 1 uint32, data = 2, gas_wanted = 5, gas_used = 6}.
 *
 * DELIBERATE DEPARTURE from "mirror the generated Unmarshal": the
 * generated decoder does not skip fields 3 (log), 4 (info), 7 (events)
 * and 8 (codespace) — it PARSES each one into the struct
 * (abci/types/types.pb.go:15354, :15386, :15456, :15490). Here the
 * DECODER REFUSES any field number other than the four above. The reason
 * is types/results.go:47-54: only these four survive into
 * `deterministicExecTxResult`, and the Merkle root of those marshalled
 * results is LastResultsHash (D-19 rev 6 item 7). This port never stores
 * or transports the stripped fields, so a message that carries one is not
 * a message this chain produced, and accepting it would mean hashing
 * bytes we did not write. Recorded as a stated deviation.
 */
typedef struct {
    uint32_t       code;        /* 1 */
    cmt_pb_bytes_t data;        /* 2 */
    int64_t        gas_wanted;  /* 5 */
    int64_t        gas_used;    /* 6 */
} cmt_pb_exec_tx_result_t;

/* ══ primitives ═══════════════════════════════════════════════════════
 * Exposed so the tests can pin them directly. Each names the generated
 * helper it reproduces. */

/** Number of bytes a uvarint of `v` occupies — cometbft's `sovTypes`
 *  (e.g. proto/tendermint/libs/bits/types.pb.go, `sovTypes`). */
size_t cmt_pb_uvarint_size(uint64_t v);

/** Append a base-128 varint. cometbft's `encodeVarintTypes`.
 *  @return CMT_OK, CMT_REJECT if it does not fit. */
int cmt_pb_put_uvarint(uint8_t *out, size_t cap, size_t *off, uint64_t v);

/** Read a base-128 varint with the generated decoder's two guards: a
 *  shift of 64 or more is `ErrIntOverflow`, and running off the end is
 *  `io.ErrUnexpectedEOF`.
 *  @return CMT_OK or CMT_REJECT. */
int cmt_pb_get_uvarint(const uint8_t *in, size_t len, size_t *off,
                       uint64_t *v);

/** uvarint(len) ‖ message — cometbft@709fd12b libs/protoio/writer.go:96-103
 *  `MarshalDelimited()` and :78-86. This is the outer frame of every
 *  sign-bytes preimage (VoteSignBytes types/vote.go:148-156,
 *  ProposalSignBytes types/proposal.go:110-118), which waves R1-B / R1-C
 *  build on top of cmt_pb_canonical_vote_marshal / _proposal_marshal.
 *  @return CMT_OK, CMT_REJECT if it does not fit in `cap`. */
int cmt_pb_marshal_delimited(const uint8_t *msg, size_t msg_len,
                             uint8_t *out, size_t cap, size_t *out_len);

/* ── header-leaf helpers (K-1 rev 2 rule d) ─────────────────────────── */

/**
 * cometbft@709fd12b types/encoding_helper.go:11-47 — `cdcEncode()`, the
 * function that turns a header field into a Merkle LEAF.
 *
 * A leaf is the BARE marshal of a gogotypes wrapper — `Int64Value`,
 * `StringValue` or `BytesValue`, each with the single field 1 — and NOT a
 * tagged field of any enclosing message.
 *
 * `*is_nil` reports the reference's nil result (encoding_helper.go:46):
 * an empty string or empty bytes is `isEmpty` (types/utils.go:21-29) and
 * yields nil, which the caller must hash as the NIL leaf, H(0x00). An
 * int64 is never `isEmpty` — `isEmpty` falls to its `default` for a
 * non-container — so `Int64Value{0}` is a NON-nil, ZERO-LENGTH encoding.
 * Both hash to H(0x00) all the same, because cmt_merkle_leaf_hash of a
 * zero-length leaf is H(0x00) either way; the flag is reported so a caller
 * that must distinguish them can, and so the distinction stays visible.
 *
 * @return CMT_OK, CMT_REJECT if the encoding does not fit in `cap`.
 */
int cmt_pb_cdc_encode_int64(int64_t v, uint8_t *out, size_t cap,
                            size_t *out_len, bool *is_nil);
int cmt_pb_cdc_encode_string(const uint8_t *s, size_t s_len, uint8_t *out,
                             size_t cap, size_t *out_len, bool *is_nil);
int cmt_pb_cdc_encode_bytes(const uint8_t *b, size_t b_len, uint8_t *out,
                            size_t cap, size_t *out_len, bool *is_nil);

/* ══ per-message API ══════════════════════════════════════════════════
 * For every message X:
 *   void cmt_pb_X_init(cmt_pb_X_t *m);
 *       Sets the reference's ZERO VALUE — which is NOT memset(0) for any
 *       message holding a time: Go's zero time.Time is CMT_TIME_ZERO.
 *       Every _unmarshal calls this first, exactly as Go allocates a zero
 *       message before Unmarshal.
 *   int cmt_pb_X_marshal(const cmt_pb_X_t *m, uint8_t *out, size_t cap,
 *                        size_t *out_len);
 *       CMT_OK, CMT_REJECT if it does not fit or a field is malformed.
 *   int cmt_pb_X_unmarshal(const uint8_t *in, size_t len, cmt_pb_X_t *m
 *                          [, cmt_pb_arena_t *arena]);
 *       CMT_OK, CMT_REJECT on any malformed or over-long input.
 * The arena argument is present only on messages that carry a
 * variable-length payload.
 */

#define CMT_PB_DECL(name, type)                                            \
    void name##_init(type *m);                                             \
    int  name##_marshal(const type *m, uint8_t *out, size_t cap,           \
                        size_t *out_len);                                  \
    int  name##_unmarshal(const uint8_t *in, size_t len, type *m)

#define CMT_PB_DECL_ARENA(name, type)                                      \
    void name##_init(type *m);                                             \
    int  name##_marshal(const type *m, uint8_t *out, size_t cap,           \
                        size_t *out_len);                                  \
    int  name##_unmarshal(const uint8_t *in, size_t len, type *m,          \
                          cmt_pb_arena_t *arena)

/* google.protobuf.Timestamp — {seconds = 1, nanos = 2}, K-1 rev 2 rule c.
 * Marshal REFUSES an out-of-range value, as StdTimeMarshalTo does through
 * TimestampProto (gogoproto timestamp_gogo.go:75-81, timestamp.go:111-120,
 * which validates at :116); unmarshal refuses it as StdTimeUnmarshal does
 * through TimestampFromProto (timestamp_gogo.go:83-94, timestamp.go:88-98,
 * which returns validateTimestamp at :97). */
void cmt_pb_timestamp_init(cmt_time_t *m);
int  cmt_pb_timestamp_marshal(const cmt_time_t *m, uint8_t *out, size_t cap,
                              size_t *out_len);
int  cmt_pb_timestamp_unmarshal(const uint8_t *in, size_t len, cmt_time_t *m);

CMT_PB_DECL(cmt_pb_consensus,               cmt_pb_consensus_t);
CMT_PB_DECL(cmt_pb_part_set_header,         cmt_pb_part_set_header_t);
CMT_PB_DECL(cmt_pb_canonical_part_set_header,
            cmt_pb_canonical_part_set_header_t);
CMT_PB_DECL(cmt_pb_block_id,                cmt_pb_block_id_t);
CMT_PB_DECL(cmt_pb_canonical_block_id,      cmt_pb_canonical_block_id_t);
CMT_PB_DECL(cmt_pb_public_key,              cmt_pb_public_key_t);
CMT_PB_DECL(cmt_pb_simple_validator,        cmt_pb_simple_validator_t);
CMT_PB_DECL(cmt_pb_validator,               cmt_pb_validator_t);
CMT_PB_DECL(cmt_pb_validator_set,           cmt_pb_validator_set_t);
CMT_PB_DECL(cmt_pb_hashed_params,           cmt_pb_hashed_params_t);
CMT_PB_DECL(cmt_pb_header,                  cmt_pb_header_t);
CMT_PB_DECL(cmt_pb_commit_sig,              cmt_pb_commit_sig_t);
CMT_PB_DECL(cmt_pb_commit,                  cmt_pb_commit_t);
CMT_PB_DECL(cmt_pb_proposal,                cmt_pb_proposal_t);
CMT_PB_DECL(cmt_pb_canonical_proposal,      cmt_pb_canonical_proposal_t);
/* CanonicalVote carries no variable-length payload — every one of its
 * fields is a scalar, a fixed-size hash, the 32-byte chain id or an
 * embedded message — so it needs no arena. */
CMT_PB_DECL(cmt_pb_canonical_vote,          cmt_pb_canonical_vote_t);

CMT_PB_DECL_ARENA(cmt_pb_part,              cmt_pb_part_t);
CMT_PB_DECL_ARENA(cmt_pb_data,              cmt_pb_data_t);
CMT_PB_DECL_ARENA(cmt_pb_vote,              cmt_pb_vote_t);
CMT_PB_DECL_ARENA(cmt_pb_canonical_vote_extension,
                  cmt_pb_canonical_vote_extension_t);
CMT_PB_DECL_ARENA(cmt_pb_duplicate_vote_evidence,
                  cmt_pb_duplicate_vote_evidence_t);
CMT_PB_DECL_ARENA(cmt_pb_evidence,          cmt_pb_evidence_t);
CMT_PB_DECL_ARENA(cmt_pb_exec_tx_result,    cmt_pb_exec_tx_result_t);

/* crypto.Proof — the struct is cmt_merkle.h's cmt_proof_t, because
 * `(sp *Proof) ToProto` (crypto/merkle/proof.go:134-146) copies field for
 * field and so is the identity in C. */
void cmt_pb_proof_init(cmt_proof_t *m);
int  cmt_pb_proof_marshal(const cmt_proof_t *m, uint8_t *out, size_t cap,
                          size_t *out_len);
int  cmt_pb_proof_unmarshal(const uint8_t *in, size_t len, cmt_proof_t *m);

/** cometbft@709fd12b crypto/merkle/proof.go:134-146 — `ToProto()`.
 *  A field-for-field copy; the identity on cmt_proof_t. Present so the
 *  reference row has a C counterpart and so call sites read alike. */
int cmt_proof_to_proto(const cmt_proof_t *sp, cmt_proof_t *out);

/** cometbft@709fd12b crypto/merkle/proof.go:148-161 — `ProofFromProto()`.
 *  Decodes and then runs cmt_proof_validate_basic, which is the `return
 *  sp, sp.ValidateBasic()` of :160. */
int cmt_proof_from_proto(const uint8_t *in, size_t len, cmt_proof_t *out);

/** cometbft@709fd12b libs/bits/bit_array.go:475-484 — `ToProto()`.
 *  Returns CMT_BITS_NIL for the reference's nil result (a NULL array or
 *  one with no words, :476-478). */
int cmt_bits_to_proto(const cmt_bit_array_t *ba, uint8_t *out, size_t cap,
                      size_t *out_len);

/**
 * cometbft@709fd12b libs/bits/bit_array.go:487-497 — `FromProto()`.
 *
 * NOTE reference gap, closed here by the APPROVED INVARIANT: the reference
 * takes `Bits` straight off the wire and copies `Elems` without ever
 * checking that `len(Elems)` equals `(Bits+63)/64` (:493-496). A later
 * index derived from `Bits` then panics in Go — and would read out of
 * bounds in a literal C translation. This decoder REQUIRES
 * `n_elems == (bits+63)/64` and `bits >= 0`, and refuses anything else.
 * It is the one place where this port is deliberately stricter than the
 * reference; it adds no consensus rule, it reproduces at the message
 * boundary the fail-stop Go's runtime provides
 * (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Also refuses `bits > CMT_BITS_MAX_BITS`, the derived capacity bound of
 * cmt_bits.h — a wire value can never make this module allocate.
 */
int cmt_bits_from_proto(const uint8_t *in, size_t len, cmt_bit_array_t *ba);

/* ══ wave R1-B addition ═══════════════════════════════════════════════
 * The two wire messages of types.proto that wave R1-A did not carry.
 * Nothing above this line changed; these are appended, and they follow
 * exactly the same rules (K-1 rev 2, INVARIANT 7495d337, the arena
 * contract, CMT_TIME_ZERO for every embedded time).
 * ═════════════════════════════════════════════════════════════════════ */

/**
 * types/types.proto:133-143 — `ExtendedCommitSig`.
 *
 * The same four fields as CommitSig plus the vote extension and its
 * signature. `commit_sig` is a MEMBER rather than four repeated fields
 * because the Go type EMBEDS CommitSig (types/block.go:722-726), so
 * `ecs.ValidatorAddress` there is `ecs->commit_sig.validator_address`
 * here; the wire field numbers 1-4 are unchanged by the embedding
 * (types.pb.go:1832-1879 writes them through the same code).
 *
 * Field 3 (timestamp, inside commit_sig) is `(gogoproto.nullable) = false`
 * and is therefore ALWAYS emitted — types.pb.go:1858-1865 writes it with
 * no `if`, exactly as CommitSig's does. An Absent ExtendedCommitSig is
 * consequently the same 15 bytes as an Absent CommitSig.
 *
 * `extension` is application data of unbounded length and lives in the
 * arena; `extension_signature` is a fixed-size field like `signature`.
 */
typedef struct {
    cmt_pb_commit_sig_t commit_sig;          /* 1,2,3(ALWAYS),4 */
    cmt_pb_bytes_t      extension;           /* 5 */
    uint8_t extension_signature[CMT_PB_SIG_MAX];   /* 6 */
    size_t  extension_signature_len;
} cmt_pb_extended_commit_sig_t;

/**
 * types/types.proto:122-128 — `ExtendedCommit`.
 *
 * Field 3 (block_id) is `(gogoproto.nullable) = false` and is ALWAYS
 * emitted (types.pb.go:1794-1803, no `if`); field 4 is repeated and
 * every element carries its own tag (:1780-1792). `extended_signatures`
 * is caller-owned storage, as Commit's `signatures` is.
 */
typedef struct {
    int64_t                       height;                    /* 1 */
    int32_t                       round;                     /* 2 */
    cmt_pb_block_id_t             block_id;                  /* 3 ALWAYS */
    cmt_pb_extended_commit_sig_t *extended_signatures;       /* 4 repeated */
    size_t                        extended_signatures_cap;
    size_t                        extended_signatures_len;
} cmt_pb_extended_commit_t;

CMT_PB_DECL_ARENA(cmt_pb_extended_commit_sig, cmt_pb_extended_commit_sig_t);
CMT_PB_DECL_ARENA(cmt_pb_extended_commit,     cmt_pb_extended_commit_t);

/* ══ wave R2-B addition ═══════════════════════════════════════════════
 * The consensus package's own wire (proto/tendermint/consensus/types.proto
 * and wal.proto), the round-state event (proto/tendermint/types/
 * events.proto), google.protobuf.Duration, and the Block / EvidenceList
 * encoders relocated out of cmt_block.c (R1B-6).
 *
 * Nothing above this line changed. These follow exactly the same rules
 * (K-1 rev 2, INVARIANT 7495d337, the arena contract, CMT_TIME_ZERO for
 * every embedded time), and every struct field carries its .proto line.
 *
 * Reference files added by pin record rev 6 (atlas-dec-483ec17c…, PROPOSED
 * at the time this was written — see the wave report):
 *   proto/tendermint/consensus/types.proto     92 lines
 *   proto/tendermint/consensus/types.pb.go   3425 lines (encoder evidence)
 *   proto/tendermint/consensus/wal.proto       46 lines
 *   proto/tendermint/consensus/wal.pb.go     1540 lines
 *   proto/tendermint/consensus/message.go     110 lines (oneof wrappers)
 *   proto/tendermint/types/events.proto        10 lines
 *   proto/tendermint/types/events.pb.go       387 lines
 *   gogoproto v1.7.0 types/duration.go, duration.pb.go, duration_gogo.go
 *   google/protobuf v25.1 duration.proto
 * ═════════════════════════════════════════════════════════════════════ */

/* ── google.protobuf.Duration ───────────────────────────────────────── */

/** gogoproto v1.7.0 types/duration.go:46 — `maxSeconds`, about 10 000
 *  years: int64(10000 * 365.25 * 24 * 60 * 60). */
#define CMT_PB_DURATION_MAX_SECONDS ((int64_t)315576000000)
/** duration.go:47 — `minSeconds = -maxSeconds`. */
#define CMT_PB_DURATION_MIN_SECONDS (-CMT_PB_DURATION_MAX_SECONDS)

/**
 * google/protobuf v25.1 duration.proto:106-114 — `Duration`.
 * {int64 seconds = 1, int32 nanos = 2}, both omit-zero
 * (gogoproto duration.pb.go:287-307).
 *
 * ⚠ NOT Timestamp. `nanos` may be NEGATIVE here, and when it is, the
 * 10-byte two's-complement varint of K-1 rev 2 rule (g) is what goes on the
 * wire. Seconds and nanos must agree in sign unless nanos is zero
 * (duration.go:64-67).
 */
typedef struct {
    int64_t seconds;   /* field 1 */
    int32_t nanos;     /* field 2 */
} cmt_pb_duration_t;

/** gogoproto v1.7.0 types/duration.go:54-69 — `validateDuration()`.
 *  Seconds within ±10 000 years, nanos strictly inside ±1e9, and the two
 *  agreeing in sign unless nanos is zero.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_pb_duration_validate(const cmt_pb_duration_t *d);

/** gogoproto v1.7.0 types/duration.go:92-99 — `DurationProto()`.
 *  Splits a nanosecond count into {seconds, nanos} by truncating division,
 *  so both halves carry the sign of the input.
 *  @return CMT_OK, CMT_FAULT on NULL. */
int cmt_pb_duration_proto(int64_t d_ns, cmt_pb_duration_t *out);

/**
 * gogoproto v1.7.0 types/duration.go:74-89 — `DurationFromProto()`.
 * validateDuration, then the conversion to a nanosecond count with the
 * reference's two overflow checks (:79-81 and :84-86).
 * @return CMT_OK, CMT_REJECT (invalid or out of range for a nanosecond
 *         count), CMT_FAULT on NULL.
 */
int cmt_pb_duration_from_proto(const cmt_pb_duration_t *p, int64_t *out_ns);

CMT_PB_DECL(cmt_pb_duration, cmt_pb_duration_t);

/**
 * gogoproto v1.7.0 types/duration_gogo.go:84-87 — `StdDurationMarshalTo()`,
 * i.e. DurationProto followed by the generated Marshal. This is what a
 * `(gogoproto.stdduration) = true` field writes.
 *
 * NOTE: the marshal side does NOT validate — DurationProto cannot produce
 * an out-of-range value from an int64 nanosecond count, so the reference
 * has nothing to check there. The UNMARSHAL side does (below).
 * @return CMT_OK, CMT_REJECT if it does not fit, CMT_FAULT on NULL.
 */
int cmt_pb_std_duration_marshal(int64_t d_ns, uint8_t *out, size_t cap,
                                size_t *out_len);

/** gogoproto v1.7.0 types/duration_gogo.go:89-99 —
 *  `StdDurationUnmarshal()`: the generated Unmarshal, then
 *  DurationFromProto, which validates.
 *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
int cmt_pb_std_duration_unmarshal(const uint8_t *in, size_t len,
                                  int64_t *out_ns);

/** duration_gogo.go:72-75 — `SizeOfStdDuration()`. */
size_t cmt_pb_std_duration_size(int64_t d_ns);

/* ── types/events.proto — EventDataRoundState ───────────────────────── */

/**
 * The widest `step` string the reference can produce is
 * "RoundStepPrecommitWait", 22 bytes — consensus/types/round_state.go:39-59
 * (`(rs RoundStepType) String()`; the eight named steps plus
 * "RoundStepUnknown"). 32 rounds that up. A longer value on the wire is
 * REFUSED, which is cmt_pb.h's standing capacity rule, not a semantic one.
 *
 * round_state.go IS pinned: tasks/comet-port-map.md records it at 224
 * lines, SHA-256
 * 44404a9f7c8125449edc3756c50c5f7575a9de45db6fb2b568ead80ac3e8c354.
 */
#define CMT_PB_ROUND_STEP_STR_MAX 32

/** types/events.proto:6-10 — `EventDataRoundState`. Every field is
 *  omit-zero (events.pb.go:123-146). */
typedef struct {
    int64_t height;                               /* field 1 */
    int32_t round;                                /* field 2 */
    uint8_t step[CMT_PB_ROUND_STEP_STR_MAX];      /* field 3 */
    size_t  step_len;
} cmt_pb_event_data_round_state_t;

CMT_PB_DECL(cmt_pb_event_data_round_state,
            cmt_pb_event_data_round_state_t);

/* ── consensus/types.proto — the nine reactor messages ──────────────── */

/** consensus/types.proto:12-18 — `NewRoundStep`. All scalars, all
 *  omit-zero (types.pb.go:876-907). */
typedef struct {
    int64_t  height;                    /* field 1 */
    int32_t  round;                     /* field 2 */
    uint32_t step;                      /* field 3 */
    int64_t  seconds_since_start_time;  /* field 4 */
    int32_t  last_commit_round;         /* field 5 */
} cmt_pb_new_round_step_t;

/**
 * consensus/types.proto:23-29 — `NewValidBlock`.
 * Field 3 is `(gogoproto.nullable) = false` and ALWAYS emitted; field 4 is
 * a POINTER BitArray, omitted when nil (types.pb.go:924-972).
 */
typedef struct {
    int64_t                  height;                 /* 1 */
    int32_t                  round;                  /* 2 */
    cmt_pb_part_set_header_t block_part_set_header;  /* 3 ALWAYS */
    bool                     has_block_parts;        /* 4 POINTER */
    cmt_bit_array_t          block_parts;
    bool                     is_commit;              /* 5 */
} cmt_pb_new_valid_block_t;

/** consensus/types.proto:32-34 — `Proposal` (the consensus-package
 *  wrapper, NOT types.Proposal). Field 1 is ALWAYS emitted
 *  (types.pb.go:989-1005). */
typedef struct {
    cmt_pb_proposal_t proposal;   /* 1 ALWAYS */
} cmt_pb_cons_proposal_t;

/** consensus/types.proto:37-41 — `ProposalPOL`. Field 3 is ALWAYS
 *  emitted, so an empty POL bit array is `1a 00` on the wire
 *  (types.pb.go:1022-1048; golden vector msgs_test.go:384). */
typedef struct {
    int64_t         height;              /* 1 */
    int32_t         proposal_pol_round;  /* 2 */
    cmt_bit_array_t proposal_pol;        /* 3 ALWAYS */
} cmt_pb_proposal_pol_t;

/** consensus/types.proto:44-48 — `BlockPart`. Field 3 is ALWAYS emitted
 *  (types.pb.go:1065-1091). The part's payload lives in the arena. */
typedef struct {
    int64_t       height;   /* 1 */
    int32_t       round;    /* 2 */
    cmt_pb_part_t part;     /* 3 ALWAYS */
} cmt_pb_block_part_t;

/** consensus/types.proto:51-53 — `Vote` (the consensus-package wrapper).
 *  Field 1 is a POINTER, omitted when nil (types.pb.go:1108-1126). */
typedef struct {
    bool          has_vote;   /* 1 POINTER */
    cmt_pb_vote_t vote;
} cmt_pb_cons_vote_t;

/** consensus/types.proto:56-61 — `HasVote`. All scalars, all omit-zero
 *  (types.pb.go:1143-1169). */
typedef struct {
    int64_t height;   /* 1 */
    int32_t round;    /* 2 */
    int32_t type;     /* 3 SignedMsgType */
    int32_t index;    /* 4 */
} cmt_pb_has_vote_t;

/** consensus/types.proto:64-69 — `VoteSetMaj23`. Field 4 is ALWAYS
 *  emitted (types.pb.go:1186-1217). */
typedef struct {
    int64_t           height;    /* 1 */
    int32_t           round;     /* 2 */
    int32_t           type;      /* 3 SignedMsgType */
    cmt_pb_block_id_t block_id;  /* 4 ALWAYS */
} cmt_pb_vote_set_maj23_t;

/** consensus/types.proto:72-78 — `VoteSetBits`. Fields 4 AND 5 are ALWAYS
 *  emitted (types.pb.go:1234-1275). */
typedef struct {
    int64_t           height;    /* 1 */
    int32_t           round;     /* 2 */
    int32_t           type;      /* 3 SignedMsgType */
    cmt_pb_block_id_t block_id;  /* 4 ALWAYS */
    cmt_bit_array_t   votes;     /* 5 ALWAYS */
} cmt_pb_vote_set_bits_t;

/** consensus/types.proto:80-92 — the `Message` oneof's field numbers.
 *  0 is the reference's nil `Sum`, which marshals to zero bytes
 *  (types.pb.go:1292-1307). */
typedef enum {
    CMT_PB_CONS_MSG_NONE            = 0,
    CMT_PB_CONS_MSG_NEW_ROUND_STEP  = 1,
    CMT_PB_CONS_MSG_NEW_VALID_BLOCK = 2,
    CMT_PB_CONS_MSG_PROPOSAL        = 3,
    CMT_PB_CONS_MSG_PROPOSAL_POL    = 4,
    CMT_PB_CONS_MSG_BLOCK_PART      = 5,
    CMT_PB_CONS_MSG_VOTE            = 6,
    CMT_PB_CONS_MSG_HAS_VOTE        = 7,
    CMT_PB_CONS_MSG_VOTE_SET_MAJ23  = 8,
    CMT_PB_CONS_MSG_VOTE_SET_BITS   = 9
} cmt_pb_cons_msg_kind_t;

/**
 * consensus/types.proto:80-92 — `Message`.
 *
 * ⚠ LARGE. The Vote branch alone carries two 4627-byte signatures and the
 * BlockPart branch a 100-aunt proof; sizeof this struct is on the order of
 * ten kilobytes. Heap-allocate it or make it a long-lived member — never a
 * stack local inside a deep call.
 *
 * DECODE: the generated Unmarshal REPLACES `Sum` on every oneof field it
 * meets (types.pb.go:3035-3039 and the eight siblings allocate a FRESH
 * branch message each time), so a repeated oneof field is last-one-wins
 * with no merge. This decoder does the same.
 *
 * ⚠ BUILDING ONE BY HAND: `cmt_pb_cons_message_init` sets `sum` to NONE
 * and zeroes the union, which is Go's nil `Sum`. A caller that then
 * SELECTS a branch must call that branch's own `_init` before filling it —
 * a memset is the wrong zero value for any branch holding a time (Vote and
 * Proposal), where Go's zero is CMT_TIME_ZERO. The decoder does this for
 * itself on every occurrence.
 */
typedef struct {
    cmt_pb_cons_msg_kind_t sum;
    union {
        cmt_pb_new_round_step_t  new_round_step;   /* 1 */
        cmt_pb_new_valid_block_t new_valid_block;  /* 2 */
        cmt_pb_cons_proposal_t   proposal;         /* 3 */
        cmt_pb_proposal_pol_t    proposal_pol;     /* 4 */
        cmt_pb_block_part_t      block_part;       /* 5 */
        cmt_pb_cons_vote_t       vote;             /* 6 */
        cmt_pb_has_vote_t        has_vote;         /* 7 */
        cmt_pb_vote_set_maj23_t  vote_set_maj23;   /* 8 */
        cmt_pb_vote_set_bits_t   vote_set_bits;    /* 9 */
    } u;
} cmt_pb_cons_message_t;

CMT_PB_DECL(cmt_pb_new_round_step,   cmt_pb_new_round_step_t);
CMT_PB_DECL(cmt_pb_new_valid_block,  cmt_pb_new_valid_block_t);
CMT_PB_DECL(cmt_pb_proposal_pol,     cmt_pb_proposal_pol_t);
CMT_PB_DECL(cmt_pb_has_vote,         cmt_pb_has_vote_t);
CMT_PB_DECL(cmt_pb_vote_set_maj23,   cmt_pb_vote_set_maj23_t);
CMT_PB_DECL(cmt_pb_vote_set_bits,    cmt_pb_vote_set_bits_t);
CMT_PB_DECL(cmt_pb_cons_proposal,    cmt_pb_cons_proposal_t);

CMT_PB_DECL_ARENA(cmt_pb_block_part,   cmt_pb_block_part_t);
CMT_PB_DECL_ARENA(cmt_pb_cons_vote,    cmt_pb_cons_vote_t);
CMT_PB_DECL_ARENA(cmt_pb_cons_message, cmt_pb_cons_message_t);

/* ── consensus/wal.proto ────────────────────────────────────────────── */

/**
 * wal.proto:15 declares `peer_id` a proto3 `string`.
 *
 * SUBSTITUTION (port map REV 3.4 item 7; deviation register R2-2): a DNA
 * peer identity is the 32-byte witness id — SHA3-512(pubkey)[0..31], the
 * same construction as cmt_address_hash — so field 2 carries those 32 RAW
 * bytes as its length-delimited payload, exactly as the 32-byte chain id is
 * carried in its own proto `string` field elsewhere in this port.
 *
 * The node's OWN messages carry the EMPTY id, which is the reference's
 * `msgInfo{PeerID: ""}` (state.go:839 enqueues own messages with no peer);
 * omit-zero then leaves field 2 off the wire entirely.
 *
 * The decoder accepts EXACTLY 0 or 32 bytes and refuses any other length.
 * That is stricter than the plain capacity rule this header states for
 * every other byte field, and it is deliberate: a WAL row is replayed as if
 * it had been received, so a peer id that is neither empty nor a witness id
 * is a row this node cannot have written (INVARIANT
 * atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 */
#define CMT_PB_PEER_ID_MAX 32

/** wal.proto:13-16 — `MsgInfo`. Field 1 is ALWAYS emitted, field 2 is
 *  omit-empty (wal.pb.go:427-450). */
typedef struct {
    cmt_pb_cons_message_t msg;                        /* 1 ALWAYS */
    uint8_t               peer_id[CMT_PB_PEER_ID_MAX];/* 2 */
    size_t                peer_id_len;
} cmt_pb_msg_info_t;

/**
 * wal.proto:19-25 — `TimeoutInfo`.
 *
 * Field 1 is `(gogoproto.nullable) = false, (gogoproto.stdduration) = true`
 * and is ALWAYS emitted (wal.pb.go:487-494, which calls
 * StdDurationMarshalTo with no `if`), so a ZERO duration is `0a 00`.
 * `duration` is held as Go holds a `time.Duration`: a count of NANOSECONDS.
 */
typedef struct {
    int64_t  duration;   /* 1 ALWAYS, nanoseconds */
    int64_t  height;     /* 2 */
    int32_t  round;      /* 3 */
    uint32_t step;       /* 4 */
} cmt_pb_timeout_info_t;

/** wal.proto:29-31 — `EndHeight`. One omit-zero scalar, so `EndHeight{0}`
 *  has an EMPTY body and appears in a WALMessage as `22 00`
 *  (wal.pb.go:513-524, :626-641). */
typedef struct {
    int64_t height;   /* 1 */
} cmt_pb_end_height_t;

/**
 * wal.proto:33-40 — the `WALMessage` oneof's field numbers.
 *
 * These numbers ARE the WAL row's `kind` column (D-15 rev 5, PROPOSED at
 * the time of writing — atlas-dec-c0bfc5344204b9282ceaaa5e06042350). 0 is
 * the reference's nil `Sum`, which marshals to zero bytes.
 */
typedef enum {
    CMT_PB_WAL_NONE                   = 0,
    CMT_PB_WAL_EVENT_DATA_ROUND_STATE = 1,
    CMT_PB_WAL_MSG_INFO               = 2,
    CMT_PB_WAL_TIMEOUT_INFO           = 3,
    CMT_PB_WAL_END_HEIGHT             = 4
} cmt_pb_wal_kind_t;

/** wal.proto:33-40 — `WALMessage`. Same replace-not-merge oneof decode
 *  rule as cmt_pb_cons_message_t (wal.pb.go:1148-1337). */
typedef struct {
    cmt_pb_wal_kind_t sum;
    union {
        cmt_pb_event_data_round_state_t event_data_round_state; /* 1 */
        cmt_pb_msg_info_t               msg_info;               /* 2 */
        cmt_pb_timeout_info_t           timeout_info;           /* 3 */
        cmt_pb_end_height_t             end_height;             /* 4 */
    } u;
} cmt_pb_wal_message_t;

/**
 * wal.proto:43-46 — `TimedWALMessage`.
 *
 * Field 1 is `(gogoproto.nullable) = false, (gogoproto.stdtime) = true` and
 * is ALWAYS emitted, so Go's ZERO time is the eleven bytes of K-1 rev 2
 * rule (c) — use CMT_TIME_ZERO, never a memset. Field 2 is a POINTER,
 * omitted when nil (wal.pb.go:657-683).
 */
typedef struct {
    cmt_time_t           time;      /* 1 ALWAYS */
    bool                 has_msg;   /* 2 POINTER */
    cmt_pb_wal_message_t msg;
} cmt_pb_timed_wal_message_t;

CMT_PB_DECL(cmt_pb_timeout_info, cmt_pb_timeout_info_t);
CMT_PB_DECL(cmt_pb_end_height,   cmt_pb_end_height_t);

CMT_PB_DECL_ARENA(cmt_pb_msg_info,          cmt_pb_msg_info_t);
CMT_PB_DECL_ARENA(cmt_pb_wal_message,       cmt_pb_wal_message_t);
CMT_PB_DECL_ARENA(cmt_pb_timed_wal_message, cmt_pb_timed_wal_message_t);

/* ── Block and EvidenceList, relocated from cmt_block.c (R1B-6) ─────── */

/**
 * types/evidence.proto:36-38 — `EvidenceList`. One repeated field, every
 * element carrying its own tag (evidence.pb.go:581-601).
 *
 * The elements are CALLER-OWNED, as every repeated field in this header
 * is; `evidence` may be NULL only when `evidence_len` is 0.
 */
typedef struct {
    const cmt_pb_evidence_t *evidence;   /* field 1, repeated */
    size_t                   evidence_len;
} cmt_pb_evidence_list_t;

/**
 * types/block.proto:10-15 — `Block`. Fields 1, 2 and 3 are
 * `(gogoproto.nullable) = false` and ALWAYS emitted; field 4 is a POINTER
 * (block.pb.go:136-184).
 *
 * WHY IT MOVED. Wave R1-B built this encoder inside cmt_block.c because
 * that wave's whitelist closed cmt_pb, and recorded the relocation as
 * recommended (R1B-6). It is here now, on the same backward writer every
 * other message uses; cmt_block.c's `cmt_block_marshal` fills this struct
 * from its domain `cmt_block_t` and calls `cmt_pb_block_marshal`. THE
 * BYTES ARE UNCHANGED — the forward frame-and-memmove writer that used to
 * live there produced exactly what the generated backward writer does, and
 * test_cmt_block.c's vectors, which this wave does not touch, are the
 * proof.
 *
 * There is deliberately NO `cmt_pb_block_unmarshal`: the reference decodes
 * a block through `BlockFromProto` (types/block.go:246-278), which wave
 * R1-B ported as `cmt_block_from_proto` over an already-decoded structure.
 * Adding a wire decoder here would be a function with no reference row.
 */
typedef struct {
    cmt_pb_header_t        header;        /* 1 ALWAYS */
    cmt_pb_data_t          data;          /* 2 ALWAYS */
    cmt_pb_evidence_list_t evidence;      /* 3 ALWAYS */
    const cmt_pb_commit_t *last_commit;   /* 4 POINTER */
} cmt_pb_block_t;

/** cometbft@709fd12b proto/tendermint/types/evidence.pb.go:581-601 —
 *  `EvidenceList.MarshalToSizedBuffer`.
 *  @return CMT_OK, CMT_REJECT if it does not fit or an element will not
 *          encode, CMT_FAULT on NULL. */
int cmt_pb_evidence_list_marshal(const cmt_pb_evidence_list_t *m,
                                 uint8_t *out, size_t cap, size_t *out_len);

/** cometbft@709fd12b proto/tendermint/types/block.pb.go:136-184 —
 *  `Block.MarshalToSizedBuffer`. */
int cmt_pb_block_marshal(const cmt_pb_block_t *m, uint8_t *out, size_t cap,
                         size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PB_H */
