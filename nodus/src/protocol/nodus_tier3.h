/**
 * Nodus — Tier 3 Protocol (Witness BFT Consensus)
 *
 * CBOR encode/decode for witness-to-witness BFT messages.
 * All messages use "w_" prefixed methods, self-authenticated via
 * per-message Dilithium5 signature ("wsig" field).
 *
 * Wire format:
 *   { "t": txn_id, "y": "q", "q": "w_propose",
 *     "wh": { "v":2, "rnd":N, "vw":V, "sid":bstr32, "ts":T, "nc":nonce, "cid":bstr32 },
 *     "a":  { method-specific fields },
 *     "wsig": bstr4627 }
 *
 * Sign payload (for wsig computation):
 *   { "q": method, "wh": header, "a": args }
 *
 * Decoded messages use zero-copy pointers for large fields (tx_data,
 * pubkeys, signatures). These pointers reference the input CBOR buffer
 * and are only valid while that buffer is alive.
 *
 * @file nodus_tier3.h
 */

#ifndef NODUS_TIER3_H
#define NODUS_TIER3_H

#include "nodus/nodus_types.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum encode buffer size (fits any T3 message) */
#define NODUS_T3_MAX_MSG_SIZE  131072

/* ── Message types ───────────────────────────────────────────────── */

typedef enum {
    NODUS_T3_PROPOSE    = 1,
    NODUS_T3_PREVOTE    = 2,
    NODUS_T3_PRECOMMIT  = 3,
    NODUS_T3_COMMIT     = 4,
    NODUS_T3_VIEWCHG    = 5,
    NODUS_T3_NEWVIEW    = 6,
    NODUS_T3_FWD_REQ    = 7,
    NODUS_T3_FWD_RSP    = 8,
    NODUS_T3_ROST_Q     = 9,
    NODUS_T3_ROST_R     = 10,
    NODUS_T3_IDENT      = 11,
    NODUS_T3_SYNC_REQ   = 12,
    NODUS_T3_SYNC_RSP   = 13,
} nodus_t3_msg_type_t;

/* ── Common witness header ───────────────────────────────────────── */

typedef struct {
    uint8_t     version;
    uint64_t    round;
    uint32_t    view;
    uint8_t     sender_id[NODUS_T3_WITNESS_ID_LEN];
    uint64_t    timestamp;
    uint64_t    nonce;
    uint8_t     chain_id[32];
} nodus_t3_header_t;

/* ── Per-type argument structs ───────────────────────────────────── */

/** Single TX entry in a batch proposal/commit */
typedef struct {
    uint8_t         tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t         nullifier_count;
    const uint8_t  *nullifiers[NODUS_T3_MAX_TX_INPUTS];  /* ptrs to 64-byte each */
    uint8_t         tx_type;
    const uint8_t  *tx_data;                              /* ptr, tx_len bytes */
    uint32_t        tx_len;
    const uint8_t  *client_pubkey;                        /* ptr, NODUS_PK_BYTES */
    const uint8_t  *client_sig;                           /* ptr, NODUS_SIG_BYTES */
    uint64_t        fee;
} nodus_t3_batch_tx_t;

/** w_propose: Leader proposes a transaction batch for consensus.
 * Phase 9 / Task 9.1 — legacy single-TX fields removed.
 * Phase 9 / Task 9.4 — block_hash field renamed to tx_root (it is the
 * RFC 6962 Merkle root over the batch's TX hashes, NOT the full block
 * header hash — that is computed by nodus_witness_compute_block_hash). */
typedef struct {
    int             batch_count;
    nodus_t3_batch_tx_t batch_txs[NODUS_W_MAX_BLOCK_TXS];
    uint8_t         tx_root[NODUS_T3_TX_HASH_LEN];
} nodus_t3_propose_t;

/** w_prevote / w_precommit: Witness votes on a proposal.
 * Phase 9 / Task 9.5 — the field carrying the in-progress block hash
 * is named vote_target (wire key vh) so it does not get confused with
 * a per-TX hash. Vote signatures bind the target via cert_sig below. */
typedef struct {
    uint8_t     vote_target[NODUS_T3_TX_HASH_LEN];
    uint32_t    vote;           /* 0=approve, 1=reject */
    char        reason[256];
    /* Phase 7.5 / Task 7.5.2 — cert preimage signature.
     * Only meaningful for PRECOMMIT; PREVOTE encoders set this to all
     * zeros and PREVOTE decoders ignore it. The signature is over the
     * 144-byte preimage produced by nodus_witness_compute_cert_preimage
     * (block_hash, voter_id = sender_id, height = local block_height + 1
     * at the moment of signing, chain_id). Wire-independent: the same
     * bytes are signed and verified regardless of T3 envelope shape. */
    uint8_t     cert_sig[NODUS_SIG_BYTES];
} nodus_t3_vote_t;

/** Precommit certificate entry (voter_id + signature) */
typedef struct {
    uint8_t     voter_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     signature[NODUS_SIG_BYTES];
} nodus_t3_cert_entry_t;

/** w_commit: Leader broadcasts commit after quorum.
 * Phase 9 / Task 9.1 — legacy single-TX fields removed. Every commit
 * is batch-shaped post Phase 7. */
typedef struct {
    uint64_t        proposal_timestamp;
    uint8_t         proposer_id[NODUS_T3_WITNESS_ID_LEN];
    uint32_t        n_precommits;
    uint8_t         state_root[NODUS_KEY_BYTES]; /* RFC 6962 Merkle root over UTXO set */
    nodus_t3_cert_entry_t certs[NODUS_T3_MAX_WITNESSES]; /* Precommit signatures */

    int             batch_count;
    nodus_t3_batch_tx_t batch_txs[NODUS_W_MAX_BLOCK_TXS];
    uint8_t         tx_root[NODUS_T3_TX_HASH_LEN];
} nodus_t3_commit_t;

/** w_viewchg: Witness requests view change */
typedef struct {
    uint32_t    new_view;
    uint64_t    last_committed_round;
} nodus_t3_viewchg_t;

/** w_newview: New leader after view change */
typedef struct {
    uint32_t    new_view;
    uint32_t    n_proofs;
} nodus_t3_newview_t;

/** w_fwd_req: Non-leader forwards client request to leader */
typedef struct {
    uint8_t         tx_hash[NODUS_T3_TX_HASH_LEN];
    const uint8_t  *tx_data;
    uint32_t        tx_len;
    const uint8_t  *client_pubkey;
    const uint8_t  *client_sig;
    uint64_t        fee;
    uint8_t         forwarder_id[NODUS_T3_WITNESS_ID_LEN];
} nodus_t3_fwd_req_t;

/** Witness signature entry (used in w_fwd_rsp) */
typedef struct {
    const uint8_t  *witness_id;     /* ptr, 32 bytes */
    const uint8_t  *signature;      /* ptr, NODUS_SIG_BYTES */
    const uint8_t  *pubkey;         /* ptr, NODUS_PK_BYTES */
    uint64_t        timestamp;
} nodus_t3_witness_sig_t;

/** w_fwd_rsp: Leader responds to forward request */
typedef struct {
    uint32_t    status;
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint32_t    witness_count;
    nodus_t3_witness_sig_t witnesses[NODUS_T3_MAX_TX_WITNESSES];
} nodus_t3_fwd_rsp_t;

/** w_rost_q: Request roster from peer */
typedef struct {
    uint32_t    version;    /* Minimum version requested */
} nodus_t3_rost_q_t;

/** Roster entry (used in w_rost_r) */
typedef struct {
    const uint8_t  *witness_id;     /* ptr, 32 bytes */
    const uint8_t  *pubkey;         /* ptr, NODUS_PK_BYTES */
    char            address[256];
    uint64_t        joined_epoch;
    bool            active;
} nodus_t3_roster_entry_t;

/** w_rost_r: Roster response */
typedef struct {
    uint32_t    version;
    uint32_t    n_witnesses;
    nodus_t3_roster_entry_t witnesses[NODUS_T3_MAX_WITNESSES];
    const uint8_t  *roster_sig;     /* ptr, NODUS_SIG_BYTES */
} nodus_t3_rost_r_t;

/** w_ident: Witness identification on connect */
typedef struct {
    const uint8_t  *witness_id;     /* ptr, 32 bytes */
    const uint8_t  *pubkey;         /* ptr, NODUS_PK_BYTES */
    char            address[256];
    uint64_t        block_height;                       /* current chain height */
    uint8_t         state_root[NODUS_KEY_BYTES];        /* RFC 6962 Merkle root over UTXO set */
    uint32_t        current_view;                       /* BFT view number */
    uint32_t        roster_size;                        /* sender's roster n_witnesses */
    uint64_t        ts_local;                           /* Phase 10 / Task 10.4 — sender wall clock for skew probe */
    bool            has_block_height;                   /* true if bh/sr/view present */
} nodus_t3_ident_t;

/** w_sync_req: Request block at height N for sync */
typedef struct {
    uint64_t    height;         /* requested block height (0 = genesis) */
} nodus_t3_sync_req_t;

/** Sync response certificate entry */
typedef struct {
    uint8_t     voter_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     signature[NODUS_SIG_BYTES];
} nodus_t3_sync_cert_t;

/** w_sync_rsp: Full block data for sync */
typedef struct {
    bool        found;
    uint64_t    height;
    uint8_t     tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     tx_type;
    const uint8_t *tx_data;             /* ptr, tx_len bytes */
    uint32_t    tx_len;
    uint64_t    timestamp;
    uint8_t     proposer_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     prev_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     nullifier_count;
    const uint8_t *nullifiers[NODUS_T3_MAX_TX_INPUTS]; /* ptrs to 64-byte each */
    uint32_t    cert_count;
    nodus_t3_sync_cert_t certs[NODUS_T3_MAX_WITNESSES];
} nodus_t3_sync_rsp_t;

/* ── Full decoded message ────────────────────────────────────────── */

typedef struct {
    uint32_t            txn_id;
    nodus_t3_msg_type_t type;
    char                method[16];
    nodus_t3_header_t   header;
    const uint8_t      *wsig;       /* ptr into decode buffer, NODUS_SIG_BYTES */

    union {
        nodus_t3_propose_t  propose;
        nodus_t3_vote_t     vote;       /* prevote or precommit */
        nodus_t3_commit_t   commit;
        nodus_t3_viewchg_t  viewchg;
        nodus_t3_newview_t  newview;
        nodus_t3_fwd_req_t  fwd_req;
        nodus_t3_fwd_rsp_t  fwd_rsp;
        nodus_t3_rost_q_t   rost_q;
        nodus_t3_rost_r_t   rost_r;
        nodus_t3_ident_t    ident;
        nodus_t3_sync_req_t sync_req;
        nodus_t3_sync_rsp_t sync_rsp;
    };
} nodus_t3_msg_t;

/* ── Encode ──────────────────────────────────────────────────────── */

/**
 * Encode a Tier 3 BFT message into CBOR wire format.
 * Signs the canonical payload {method, header, args} with sk.
 *
 * Caller must set msg->type, msg->txn_id, msg->header, and the
 * appropriate union fields (including all pointer fields).
 *
 * @param msg      Filled-in message
 * @param sk       Secret key for wsig (Dilithium5)
 * @param buf      Output buffer (recommend NODUS_T3_MAX_MSG_SIZE)
 * @param cap      Buffer capacity
 * @param out_len  Bytes written
 * @return 0 on success, -1 on error
 */
int nodus_t3_encode(const nodus_t3_msg_t *msg, const nodus_seckey_t *sk,
                     uint8_t *buf, size_t cap, size_t *out_len);

/* ── Decode ──────────────────────────────────────────────────────── */

/**
 * Decode a Tier 3 CBOR payload into structured message.
 * Does NOT verify the wsig signature — call nodus_t3_verify() separately.
 *
 * Pointer fields in the decoded message reference the input buffer.
 * The decoded message is only valid while buf remains alive.
 *
 * @param buf  Raw CBOR payload
 * @param len  Payload length
 * @param msg  Output message struct (caller-owned)
 * @return 0 on success, -1 on decode error
 */
int nodus_t3_decode(const uint8_t *buf, size_t len, nodus_t3_msg_t *msg);

/* ── Verify ──────────────────────────────────────────────────────── */

/**
 * Verify the wsig of a decoded T3 message.
 * Re-encodes the sign payload and verifies against pk.
 *
 * @param msg  Decoded message (pointer fields must still be valid)
 * @param pk   Signer's public key (from roster)
 * @return 0 if valid, -1 if invalid or error
 */
int nodus_t3_verify(const nodus_t3_msg_t *msg, const nodus_pubkey_t *pk);

/* ── Method/type helpers ─────────────────────────────────────────── */

const char *nodus_t3_type_to_method(nodus_t3_msg_type_t type);
nodus_t3_msg_type_t nodus_t3_method_to_type(const char *method);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TIER3_H */
