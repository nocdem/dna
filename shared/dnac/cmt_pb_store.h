/**
 * @file shared/dnac/cmt_pb_store.h
 * @brief cometbft @709fd12b — the proto3 codecs of the STORED values:
 *        what `store/store.go` and `state/store.go` marshal into their
 *        `dbm.DB`, plus the `Block` wire DECODER `state.go:2005-2019`
 *        needs and cmt_pb.h deliberately left out.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * FLEET-TM-R3 wave W1, package R3-B. Nothing in the running chain calls
 * anything here; `nodus_witness_cmt_store.c` and
 * `nodus_witness_cmt_host.c` are the consumers, themselves inactive.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS FILE IS ──────────────────────────────────────────────────
 * cmt_pb.h carries the messages consensus HASHES and SIGNS. The stores
 * write nine more, and the reference marshals them with the same
 * generated gogoproto encoders (`bs.Marshal()` in `mustEncode`,
 * store.go:718-728; `proto.Marshal` throughout state/store.go). Every
 * rule of K-1 rev 2 applies unchanged: scalars are omitted when zero,
 * `(gogoproto.nullable) = false` embedded messages are ALWAYS written,
 * pointer embedded messages only when set, fields ascend by number,
 * `Timestamp` and `Duration` are gogoproto's std forms. Each message
 * names its generated encoder by file:line, and the ALWAYS/POINTER
 * status of every embedded field is stated on the struct.
 *
 *   BlockMeta              types.proto:166-171     types.pb.go:2058
 *   BlockStoreState        store/types.proto:6-9   store/types.pb.go:113
 *   State                  state/types.proto:61-96 state/types.pb.go:1005
 *   Version                state/types.proto:56-59 state/types.pb.go:965
 *   ValidatorsInfo         state/types.proto:39-42 state/types.pb.go:835
 *   ConsensusParamsInfo    state/types.proto:45-48 state/types.pb.go:875
 *   ABCIResponsesInfo      state/types.proto:50-54 state/types.pb.go:913
 *   ConsensusParams (+5)   types/params.proto      params.pb.go:702-975
 *   ResponseFinalizeBlock  abci/types.proto:352-370 abci/types.pb.go:6775
 *     Event                abci/types.proto:390-398 abci/types.pb.go:6943
 *     EventAttribute       abci/types.proto:399-407 abci/types.pb.go:6987
 *     ExecTxResult (all 8) abci/types.proto:408-418 abci/types.pb.go:7034
 *     ValidatorUpdate      abci/types.proto:439-443 abci/types.pb.go:7199
 *   Block (DECODER)        types/block.proto:10-15  block.pb.go:222
 *
 * ── ON TOP OF cmt_pb, NOT INSIDE IT ────────────────────────────────────
 * The embedded messages that already exist (BlockID, Header, Consensus,
 * ValidatorSet, PublicKey, Timestamp, Duration, Data, Commit, Evidence)
 * are written and read through cmt_pb's PUBLIC `_marshal` / `_unmarshal`.
 * Two consequences, both recorded:
 *
 *   · the writer and reader primitives of cmt_pb.c (its backward writer
 *     `pb_w_t` and forward tag reader, cmt_pb.c:46-437) are `static`
 *     there. They are DUPLICATED at the top of cmt_pb_store.c, each
 *     marked `DUPLICATE of cmt_pb.c:<line> — merge at O7`, because this
 *     package's whitelist does not include cmt_pb.{h,c}. A QUESTION in
 *     the R3-B report asks to export them.
 *   · a nested cmt_pb message is decoded with its public `_unmarshal`,
 *     which INITS before it merges. The generated decoder MERGES a
 *     second occurrence of a non-repeated embedded field into the first
 *     (e.g. state/types.pb.go's `m.Version.Unmarshal(...)`); here the
 *     second occurrence REPLACES the first. Byte streams this chain
 *     writes never carry a field twice, so the two agree on every value
 *     this chain produces; the difference is stated as a DEVIATION at
 *     each site. Unknown fields are SKIPPED by wire type, exactly as
 *     cmt_pb.h:46-51 states for every cmt_pb reader.
 *
 * ── WHERE THE C-SIDE TYPES ARE ─────────────────────────────────────────
 *   State            ↔ cmt_state_t             state.go:145-232
 *   ConsensusParams  ↔ cmt_consensus_params_t  params.go:325-370
 *   Version          ↔ cmt_state_version_t     (identity + a copy)
 *   ValidatorSet     ↔ cmt_validator_set_t     cmt_validator_set.h (exists)
 *   BlockMeta        ↔ itself: `cmt_header_t` IS `cmt_pb_header_t` and
 *                      `cmt_block_id_t` IS `cmt_pb_block_id_t`, so the
 *                      wire struct is the domain struct; block_meta.go's
 *                      functions live with the store.
 *   ExecTxResult     the STORED form keeps log/info/events/codespace
 *                    (types.proto:411-417). `cmt_pb_exec_tx_result_t` is
 *                    deliberately the four-field deterministic copy and
 *                    its decoder REFUSES the other four (cmt_pb.h:399-
 *                    420); the stored form is a WRAPPER struct here, and
 *                    `cmt_new_results` takes the wrapper's `det` member.
 *
 * ── CAPACITY BOUNDS (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07) ─
 * Every repeated field is caller-owned storage with a capacity; every
 * string is a fixed array with a length or an arena slice. Anything that
 * does not fit is REFUSED, never truncated. The bounds here are this
 * port's, not the reference's — the reference's slices are unbounded.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Pure functions of their arguments. No clock, no allocation (the
 * arena and pools are the caller's), no unordered iteration: repeated
 * fields keep their list order.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   proto/tendermint/state/types.proto  100 lines
 *   proto/tendermint/state/types.pb.go  2732 lines
 *     (9434e985d5641147170fe7d121ab6bc88c4d55cc5e0380dac1efede6a65d4fc7 —
 *      the R3-B report called this unpinned; it is PINNED, rev 4)
 *   proto/tendermint/types/params.proto / params.pb.go, types.proto,
 *   types.pb.go, store/types.proto, store/types.pb.go, abci/types.proto,
 *   abci/types/types.pb.go, block.pb.go — see the R3-B report's pin table.
 * Governing records: umbrella rev 4 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * D-17 rev 5 (atlas-dec-9d96e2ec31ad4840cf258df21732b67f, PROPOSED,
 * operator ruling 2026-09-11), D-23 rev 4
 * (atlas-dec-cb08dde681aa3c4ab1d1f1b33cdb68e1, PROPOSED, operator ruling
 * 2026-09-11), INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PB_STORE_H
#define SHARED_DNAC_CMT_PB_STORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_params.h"
#include "cmt_state.h"
#include "cmt_block.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ store/types.proto:6-9 — BlockStoreState ═════════════════════════ */

/** store/types.pb.go:113-131. Both fields omit-zero. */
typedef struct {
    int64_t base;     /* 1 */
    int64_t height;   /* 2 */
} cmt_pb_block_store_state_t;

/* ══ types.proto:166-171 — BlockMeta ═════════════════════════════════ */

/** types.pb.go:2058-2098. `block_id` (1) and `header` (3) are
 *  `nullable=false` and ALWAYS written; 2 and 4 omit-zero. The domain
 *  type of block_meta.go:12-17 is this same struct (see the header). */
typedef struct {
    cmt_pb_block_id_t block_id;     /* 1 ALWAYS */
    int64_t           block_size;   /* 2 */
    cmt_pb_header_t   header;       /* 3 ALWAYS */
    int64_t           num_txs;      /* 4 */
} cmt_pb_block_meta_t;

/* ══ state/types.proto:56-59 — Version ═══════════════════════════════ */

/** The longest `software` string stored, WITHOUT the NUL; equals
 *  cmt_state_version_t's array so `to_c` never truncates. */
#define CMT_PB_STORE_SOFTWARE_MAX (CMT_STATE_SOFTWARE_MAX - 1)

/** state/types.pb.go:965-1003. `consensus` (1) ALWAYS; `software` (2)
 *  omitted when empty. */
typedef struct {
    cmt_pb_consensus_t consensus;                          /* 1 ALWAYS */
    uint8_t            software[CMT_PB_STORE_SOFTWARE_MAX]; /* 2 string */
    size_t             software_len;
} cmt_pb_version_t;

/* ══ types/params.proto — ConsensusParams and its five ═══════════════ */

/**
 * params.pb.go:702-783. Five POINTER sub-messages, each written only when
 * set (`if m.Block != nil` …). `cmt_consensus_params_proto_t`
 * (cmt_params.h) already carries exactly that nil-ness, so it IS the
 * wire struct; only the Duration changes form on the wire:
 *   BlockParams     (:785-816)  max_bytes 1, max_gas 2 — omit-zero
 *   EvidenceParams  (:818-857)  max_age_num_blocks 1; max_age_duration 2
 *                   is `nullable=false, stdduration` and ALWAYS written
 *                   (a zero Duration is `12 00`); max_bytes 3
 *   ValidatorParams (:859-889)  pub_key_types 1, repeated string, one tag
 *                   per element, the SLICE guarded (`if len > 0`)
 *   VersionParams   (:891-917)  app 1 uint64
 *   ABCIParams      (:952-978)  vote_extensions_enable_height 1
 */
typedef cmt_consensus_params_proto_t cmt_pb_consensus_params_t;

/* ══ state/types.proto:61-96 — State ═════════════════════════════════ */

/**
 * state/types.pb.go:1005-1116 — the generated encoder writes 14 down to
 * 1, so the wire ascends by FIELD NUMBER, which is NOT the .proto's
 * declaration order (initial_height is declared third but is field 14
 * and goes LAST):
 *   1 version           ALWAYS (`nullable=false`)
 *   2 chain_id          string, omitted when empty — the 32 raw bytes
 *                       exactly as cmt_pb.c:1746 writes Header.chain_id
 *   3 last_block_height omit-zero
 *   4 last_block_id     ALWAYS
 *   5 last_block_time   ALWAYS, stdtime (Go's zero time is CMT_TIME_ZERO
 *                       and marshals to the 11 bytes of K-1 rule c)
 *   6 next_validators   POINTER
 *   7 validators        POINTER
 *   8 last_validators   POINTER — `ToProto` sets it only when
 *                       LastBlockHeight >= 1 (state.go:169-175)
 *   9 last_height_validators_changed
 *  10 consensus_params  ALWAYS
 *  11 last_height_consensus_params_changed
 *  12 last_results_hash bytes, omitted when empty
 *  13 app_hash          bytes, omitted when empty
 *  14 initial_height
 * The three validator sets are `cmt_pb_validator_set_t` with CALLER
 * storage (`validators` / `validators_cap` survive `_init`, as they do
 * in cmt_pb.c:1490-1504).
 */
typedef struct {
    cmt_pb_version_t          version;                          /* 1 ALWAYS  */
    uint8_t                   chain_id[CMT_PB_CHAINID_MAX];     /* 2         */
    size_t                    chain_id_len;
    int64_t                   last_block_height;                /* 3         */
    cmt_pb_block_id_t         last_block_id;                    /* 4 ALWAYS  */
    cmt_time_t                last_block_time;                  /* 5 ALWAYS  */
    bool                      has_next_validators;              /* 6 POINTER */
    cmt_pb_validator_set_t    next_validators;
    bool                      has_validators;                   /* 7 POINTER */
    cmt_pb_validator_set_t    validators;
    bool                      has_last_validators;              /* 8 POINTER */
    cmt_pb_validator_set_t    last_validators;
    int64_t                   last_height_validators_changed;   /* 9         */
    cmt_pb_consensus_params_t consensus_params;                 /* 10 ALWAYS */
    int64_t                   last_height_consensus_params_changed; /* 11    */
    uint8_t                   last_results_hash[CMT_PB_HASH_MAX];   /* 12    */
    size_t                    last_results_hash_len;
    uint8_t                   app_hash[CMT_PB_HASH_MAX];        /* 13        */
    size_t                    app_hash_len;
    int64_t                   initial_height;                   /* 14        */
} cmt_pb_state_t;

/* ══ state/types.proto:39-48 — ValidatorsInfo, ConsensusParamsInfo ══ */

/** state/types.pb.go:835-873. `validator_set` (1) is a POINTER. */
typedef struct {
    bool                   has_validator_set;    /* 1 POINTER */
    cmt_pb_validator_set_t validator_set;
    int64_t                last_height_changed;  /* 2 */
} cmt_pb_validators_info_t;

/** state/types.pb.go:875-911. `consensus_params` (1) ALWAYS. */
typedef struct {
    cmt_pb_consensus_params_t consensus_params;     /* 1 ALWAYS */
    int64_t                   last_height_changed;  /* 2 */
} cmt_pb_consensus_params_info_t;

/* ══ abci/types.proto:390-443 — the FinalizeBlock response family ═══ */

/** abci/types.pb.go:6987-7026 — EventAttribute. Strings live in the
 *  caller's arena; `index` (3) is a bool written only when true. */
typedef struct {
    cmt_pb_bytes_t key;     /* 1 string */
    cmt_pb_bytes_t value;   /* 2 string */
    bool           index;   /* 3 */
} cmt_pb_event_attribute_t;

/** abci/types.pb.go:6943-6985 — Event. `attributes` (2) is repeated
 *  `nullable=false`: one tag per element, the slice guarded. */
typedef struct {
    cmt_pb_bytes_t            type;             /* 1 string */
    cmt_pb_event_attribute_t *attributes;       /* 2 repeated, caller pool */
    size_t                    attributes_cap;
    size_t                    attributes_len;
} cmt_pb_event_t;

/**
 * abci/types.pb.go:7034-7097 — ExecTxResult, ALL EIGHT FIELDS, the form
 * `ABCIResponsesInfo` STORES (state/store.go `SaveFinalizeBlockResponse`).
 * `det` is the deterministic four {1 code, 2 data, 5 gas_wanted,
 * 6 gas_used} in cmt_pb's own struct so `cmt_new_results` can take it
 * unchanged; 3 log, 4 info, 7 events (repeated `nullable=false`) and
 * 8 codespace are the nondeterministic four (types.proto:411-417).
 */
typedef struct {
    cmt_pb_exec_tx_result_t det;          /* 1, 2, 5, 6 */
    cmt_pb_bytes_t          log;          /* 3 string */
    cmt_pb_bytes_t          info;         /* 4 string */
    cmt_pb_event_t         *events;       /* 7 repeated, caller pool */
    size_t                  events_cap;
    size_t                  events_len;
    cmt_pb_bytes_t          codespace;    /* 8 string */
} cmt_pb_stored_exec_tx_result_t;

/** abci/types.pb.go:7199-7235 — ValidatorUpdate. `pub_key` (1) is
 *  `nullable=false` and ALWAYS written — a key whose `present` is false
 *  goes out as the empty message `0a 00`, which `PubKeyFromProto`
 *  (crypto/encoding/codec.go:42-63) then refuses as a nil oneof. */
typedef struct {
    cmt_pb_public_key_t pub_key;   /* 1 ALWAYS */
    int64_t             power;     /* 2 */
} cmt_pb_validator_update_t;

/**
 * abci/types.pb.go:6775-6843 — ResponseFinalizeBlock.
 *   1 events                  repeated `nullable=false`
 *   2 tx_results              repeated (pointer elements; nil never
 *                             written by this chain)
 *   3 validator_updates       repeated `nullable=false`
 *   4 consensus_param_updates POINTER
 *   5 app_hash                bytes, omitted when empty
 * `app_hash` is a fixed CMT_PB_HASH_MAX array with a length: this chain's
 * app hash is a SHA3-512 or empty, and `cmt_state_t.app_hash` receives it
 * unchanged (execution.go:741).
 */
typedef struct {
    cmt_pb_event_t                 *events;                    /* 1 */
    size_t                          events_cap;
    size_t                          events_len;
    cmt_pb_stored_exec_tx_result_t *tx_results;                /* 2 */
    size_t                          tx_results_cap;
    size_t                          tx_results_len;
    cmt_pb_validator_update_t      *validator_updates;         /* 3 */
    size_t                          validator_updates_cap;
    size_t                          validator_updates_len;
    bool                            has_consensus_param_updates; /* 4 POINTER */
    cmt_pb_consensus_params_t       consensus_param_updates;
    uint8_t                         app_hash[CMT_PB_HASH_MAX]; /* 5 */
    size_t                          app_hash_len;
} cmt_pb_response_finalize_block_t;

/**
 * The DECODER's storage for a ResponseFinalizeBlock: flat pools the
 * decoder carves the message's repeated fields out of, in order of
 * appearance (an event's `attributes` and a tx result's `events` point
 * into the shared pools), plus the arena for every string and byte
 * field. All caller-owned; a pool that runs out REFUSES the message.
 */
typedef struct {
    cmt_pb_event_t                 *events;             size_t events_cap;
    cmt_pb_event_attribute_t       *attributes;         size_t attributes_cap;
    cmt_pb_stored_exec_tx_result_t *tx_results;         size_t tx_results_cap;
    cmt_pb_validator_update_t      *validator_updates;  size_t validator_updates_cap;
    cmt_pb_arena_t                 *arena;
} cmt_pb_rfb_storage_t;

/* ══ state/types.proto:50-54 — ABCIResponsesInfo ═════════════════════ */

/** state/types.pb.go:913-963. Field 1 `legacy_abci_responses` is the
 *  legacy slot this chain NEVER writes and its decoder REFUSES (there is
 *  no legacy format in this chain — D-23 rev 4); 2 height omit-zero;
 *  3 response_finalize_block POINTER. */
typedef struct {
    int64_t                          height;                      /* 2 */
    bool                             has_response_finalize_block; /* 3 POINTER */
    cmt_pb_response_finalize_block_t response_finalize_block;
} cmt_pb_abci_responses_info_t;

/* ══ per-message API ═════════════════════════════════════════════════
 * For every message X:
 *   void   cmt_pb_store_X_init(cmt_pb_X_t *m)      — the zero value;
 *          caller storage (pointers and caps) survives, as in cmt_pb.c
 *   size_t cmt_pb_store_X_upper_bound(...)         — a buffer size that
 *          always fits the marshalled message for the given counts
 *   int    cmt_pb_store_X_marshal(m, out, cap, out_len)
 *          CMT_OK, CMT_REJECT if it does not fit or a field is malformed,
 *          CMT_FAULT on NULL
 *   int    cmt_pb_store_X_unmarshal(in, len, m[, storage])
 *          CMT_OK, CMT_REJECT on malformed / over-capacity input,
 *          CMT_FAULT on NULL
 */

/* BlockStoreState */
void   cmt_pb_store_block_store_state_init(cmt_pb_block_store_state_t *m);
size_t cmt_pb_store_block_store_state_upper_bound(void);
int    cmt_pb_store_block_store_state_marshal(const cmt_pb_block_store_state_t *m,
                                              uint8_t *out, size_t cap,
                                              size_t *out_len);
int    cmt_pb_store_block_store_state_unmarshal(const uint8_t *in, size_t len,
                                                cmt_pb_block_store_state_t *m);

/* BlockMeta */
void   cmt_pb_store_block_meta_init(cmt_pb_block_meta_t *m);
size_t cmt_pb_store_block_meta_upper_bound(void);
int    cmt_pb_store_block_meta_marshal(const cmt_pb_block_meta_t *m,
                                       uint8_t *out, size_t cap,
                                       size_t *out_len);
int    cmt_pb_store_block_meta_unmarshal(const uint8_t *in, size_t len,
                                         cmt_pb_block_meta_t *m);

/* Version */
void   cmt_pb_store_version_init(cmt_pb_version_t *m);
size_t cmt_pb_store_version_upper_bound(void);
int    cmt_pb_store_version_marshal(const cmt_pb_version_t *m, uint8_t *out,
                                    size_t cap, size_t *out_len);
int    cmt_pb_store_version_unmarshal(const uint8_t *in, size_t len,
                                      cmt_pb_version_t *m);
/** `sm.Version = state.Version` (state.go:151) — the copy. */
int    cmt_pb_store_version_from_c(const cmt_state_version_t *v,
                                   cmt_pb_version_t *out);
/** `state.Version = pb.Version` (state.go:195). REJECTS a software string
 *  the fixed array cannot hold (capacity). */
int    cmt_pb_store_version_to_c(const cmt_pb_version_t *m,
                                 cmt_state_version_t *out);

/* ConsensusParams and its five sub-messages */
void   cmt_pb_store_consensus_params_init(cmt_pb_consensus_params_t *m);
size_t cmt_pb_store_consensus_params_upper_bound(void);
int    cmt_pb_store_consensus_params_marshal(const cmt_pb_consensus_params_t *m,
                                             uint8_t *out, size_t cap,
                                             size_t *out_len);
int    cmt_pb_store_consensus_params_unmarshal(const uint8_t *in, size_t len,
                                               cmt_pb_consensus_params_t *m);
/** types/params.go:325-346 — `(params *ConsensusParams) ToProto()`. All
 *  five sub-messages are SET (has_* true). */
int    cmt_pb_store_consensus_params_from_c(const cmt_consensus_params_t *p,
                                            cmt_pb_consensus_params_t *out);
/**
 * types/params.go:348-370 — `ConsensusParamsFromProto()`.
 * The reference dereferences Block, Evidence, Validator and Version
 * WITHOUT a nil check (:349-365) and checks only Abci (:366). Go's nil
 * dereference is a panic; per the APPROVED INVARIANT
 * (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07) and cmt_params.h:288-296
 * that is an explicit refusal here: a message missing any of the four
 * is CMT_REJECT. An absent Abci leaves the height 0 (:366-368).
 */
int    cmt_pb_store_consensus_params_to_c(const cmt_pb_consensus_params_t *m,
                                          cmt_consensus_params_t *out);
/** `params.Equal(&emptypb)` (state/store.go's `saveState` and
 *  `LoadConsensusParams` sites): true when no sub-message is set. */
bool   cmt_pb_store_consensus_params_is_empty(const cmt_pb_consensus_params_t *m);

/* State */
void   cmt_pb_store_state_init(cmt_pb_state_t *m);
/** @param n_validators the LARGEST of the three sets' lengths. */
size_t cmt_pb_store_state_upper_bound(size_t n_validators);
int    cmt_pb_store_state_marshal(const cmt_pb_state_t *m, uint8_t *out,
                                  size_t cap, size_t *out_len);
int    cmt_pb_store_state_unmarshal(const uint8_t *in, size_t len,
                                    cmt_pb_state_t *m);
/**
 * state/state.go:145-183 — `(state *State) ToProto()`. The three sets go
 * through `cmt_validator_set_to_proto` (an empty set becomes an EMPTY
 * MESSAGE, never an omission); `last_validators` only when
 * `last_block_height >= 1` (:169-175).
 * @param out's three `cmt_pb_validator_set_t.validators` must point at
 *        caller storage of at least the source set's length each.
 * @return CMT_OK; CMT_REJECT from ToProto (:159-176); CMT_FAULT on NULL.
 */
int    cmt_pb_store_state_from_c(const cmt_state_t *state, cmt_pb_state_t *out);
/**
 * state/state.go:186-232 — `FromProto()`. BlockIDFromProto (:197),
 * `ValidatorSetFromProto` for validators and next_validators — an
 * ABSENT set is the reference's "nil validator set" error (:205-215) —
 * last_validators when `last_block_height >= 1` else
 * `NewValidatorSet(nil)`, an EMPTY-NOT-NIL set (:217-225),
 * ConsensusParamsFromProto (:228).
 * @param out must be `cmt_state_init`ialised with its own storage; the
 *        three sets are bound into it here.
 * @return CMT_OK, CMT_REJECT for any error return, CMT_FAULT on NULL or
 *         a state without storage.
 */
int    cmt_pb_store_state_to_c(const cmt_pb_state_t *m, cmt_state_t *out);

/* ValidatorsInfo */
void   cmt_pb_store_validators_info_init(cmt_pb_validators_info_t *m);
size_t cmt_pb_store_validators_info_upper_bound(size_t n_validators);
int    cmt_pb_store_validators_info_marshal(const cmt_pb_validators_info_t *m,
                                            uint8_t *out, size_t cap,
                                            size_t *out_len);
int    cmt_pb_store_validators_info_unmarshal(const uint8_t *in, size_t len,
                                              cmt_pb_validators_info_t *m);

/* ConsensusParamsInfo */
void   cmt_pb_store_consensus_params_info_init(cmt_pb_consensus_params_info_t *m);
size_t cmt_pb_store_consensus_params_info_upper_bound(void);
int    cmt_pb_store_consensus_params_info_marshal(
           const cmt_pb_consensus_params_info_t *m, uint8_t *out, size_t cap,
           size_t *out_len);
int    cmt_pb_store_consensus_params_info_unmarshal(
           const uint8_t *in, size_t len, cmt_pb_consensus_params_info_t *m);

/* EventAttribute / Event / stored ExecTxResult / ValidatorUpdate —
 * marshal only as elements of ResponseFinalizeBlock; exposed for the
 * golden-vector tests. */
size_t cmt_pb_store_event_attribute_upper_bound(const cmt_pb_event_attribute_t *a);
int    cmt_pb_store_event_attribute_marshal(const cmt_pb_event_attribute_t *m,
                                            uint8_t *out, size_t cap,
                                            size_t *out_len);
size_t cmt_pb_store_event_upper_bound(const cmt_pb_event_t *e);
int    cmt_pb_store_event_marshal(const cmt_pb_event_t *m, uint8_t *out,
                                  size_t cap, size_t *out_len);
size_t cmt_pb_store_stored_exec_tx_result_upper_bound(
           const cmt_pb_stored_exec_tx_result_t *r);
int    cmt_pb_store_stored_exec_tx_result_marshal(
           const cmt_pb_stored_exec_tx_result_t *m, uint8_t *out, size_t cap,
           size_t *out_len);
size_t cmt_pb_store_validator_update_upper_bound(void);
int    cmt_pb_store_validator_update_marshal(const cmt_pb_validator_update_t *m,
                                             uint8_t *out, size_t cap,
                                             size_t *out_len);

/* ResponseFinalizeBlock */
void   cmt_pb_store_response_finalize_block_init(
           cmt_pb_response_finalize_block_t *m);
size_t cmt_pb_store_response_finalize_block_upper_bound(
           const cmt_pb_response_finalize_block_t *m);
int    cmt_pb_store_response_finalize_block_marshal(
           const cmt_pb_response_finalize_block_t *m, uint8_t *out, size_t cap,
           size_t *out_len);
int    cmt_pb_store_response_finalize_block_unmarshal(
           const uint8_t *in, size_t len, cmt_pb_response_finalize_block_t *m,
           cmt_pb_rfb_storage_t *storage);

/* ABCIResponsesInfo */
void   cmt_pb_store_abci_responses_info_init(cmt_pb_abci_responses_info_t *m);
size_t cmt_pb_store_abci_responses_info_upper_bound(
           const cmt_pb_abci_responses_info_t *m);
int    cmt_pb_store_abci_responses_info_marshal(
           const cmt_pb_abci_responses_info_t *m, uint8_t *out, size_t cap,
           size_t *out_len);
/** A field 1 (legacy) occurrence is CMT_REJECT — see the struct. */
int    cmt_pb_store_abci_responses_info_unmarshal(
           const uint8_t *in, size_t len, cmt_pb_abci_responses_info_t *m,
           cmt_pb_rfb_storage_t *storage);

/* ══ types/block.proto:10-15 — the Block DECODER ═════════════════════ */

/**
 * block.pb.go:222-380 — `Block.Unmarshal`, the middle step of
 * state.go:2005-2019 (`proto.Unmarshal(bz, pbb)`) that cmt_pb.h:1043-1046
 * leaves out. The result is a `cmt_block_t`-SHAPED proto view — the same
 * shape `cmt_block_from_proto` (cmt_block.h:897) takes as `bp`, because
 * header, data and commit are typedef-identical to their cmt_pb structs.
 *
 * Fields: 1 header (ALWAYS; `cmt_pb_header_unmarshal`), 2 data (ALWAYS;
 * `cmt_pb_data_unmarshal`, txs into `out->data.txs` caller storage, tx
 * bytes into `arena`), 3 evidence (ALWAYS; EvidenceList.Unmarshal
 * evidence.pb.go:1227-1300 appends one `cmt_pb_evidence_unmarshal` per
 * element into `out->evidence.evidence` caller storage), 4 last_commit
 * (POINTER; allocated-if-nil in Go, here `last_commit` storage with
 * `sigs` for its signatures — `out->last_commit` is set to it when the
 * field occurs, left NULL otherwise).
 *
 * The caller sets `out->data.txs`/`txs_cap` and
 * `out->evidence.evidence`/`evidence_cap` before the call; everything
 * else is written here. `last_commit->signatures`/`signatures_cap` are
 * the caller's too.
 *
 * @return CMT_OK; CMT_REJECT for malformed bytes or a repeated field that
 *         overflows its storage; CMT_FAULT on NULL.
 */
int cmt_pb_block_unmarshal(const uint8_t *in, size_t len, cmt_block_t *out,
                           cmt_commit_t *last_commit, cmt_pb_arena_t *arena);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PB_STORE_H */
