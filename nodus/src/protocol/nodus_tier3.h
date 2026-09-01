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
/* O15H D8 — the V2 envelope family marker + its versioned capacity
 * bound, for nodus_t3_tx_size_limit below. env_wire.h is dependency-free
 * by its own rule (it may include ledger_ids.h and nothing from nodus),
 * so this direction of the include is the safe one. */
#include "dnac/env_wire.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum encode buffer size (fits any T3 message) */
#define NODUS_T3_MAX_MSG_SIZE  131072

/* O15H D8 — the family-aware per-transaction size bound, in ONE place.
 *
 * Two lanes, two ceilings, one selector. A Ledger V2 envelope is bounded
 * by its OWN versioned capacity constant (DNA_ENV_MAX_TOTAL_LEN, derived
 * and oracle-checked in shared/dnac/env_wire.h); everything else keeps
 * the legacy semantic limit EXACTLY as it was. Selection is by the
 * leading 16-byte wire-family marker, read before any length-driven
 * work, so a legacy frame can never be sized against the larger bound
 * and legacy behaviour is byte-identical.
 *
 * Carrying capacity is NOT assumed — it was checked. PROPOSE and COMMIT
 * already ride the 1 MB heap encode/verify path
 * (nodus_witness_bft_broadcast + nodus_t3_verify, NODUS_W_MAX_SYNC_RSP_SIZE),
 * and the one stack buffer that carried a transaction — the w_fwd
 * forward request in nodus_witness_handlers.c — moved to that same heap
 * bound with this change. peer.c's three NODUS_T3_MAX_MSG_SIZE buffers
 * carry w_ident / w_rost_q / w_rost_r, none of which holds a
 * transaction, so they are untouched.
 *
 * NOTE the asymmetry this preserves: raising a bound cannot make a node
 * accept anything a peer would refuse to produce, because the envelope
 * decode, admission and the engine's preflight all still apply. It only
 * stops a node refusing a transaction its own consensus rules require.
 */
static inline uint32_t nodus_t3_tx_size_limit(const uint8_t *tx, size_t len)
{
    return dna_env_wire_is_envelope(tx, len) ? (uint32_t)DNA_ENV_MAX_TOTAL_LEN
                                             : (uint32_t)NODUS_T3_MAX_TX_SIZE;
}

/* Phase 11 / Task 11.3 — three-tier sync_rsp size guard.
 *
 * Multi-tx sync_rsp can carry up to NODUS_W_MAX_BLOCK_TXS * tx_len
 * plus cert data, which exceeds the 128 KB NODUS_T3_MAX_MSG_SIZE.
 * Sync senders/receivers use this larger 1 MB cap instead. The
 * decoder enforces:
 *
 *   tier 1: tx_count <= NODUS_W_MAX_BLOCK_TXS (10)
 *   tier 2: per-TX tx_len <= NODUS_T3_MAX_TX_SIZE (64 KB)
 *   tier 3: aggregate wire bytes <= NODUS_W_MAX_SYNC_RSP_SIZE (1 MB)
 */
#define NODUS_W_MAX_SYNC_RSP_SIZE  (1024 * 1024)

/* PR 3 Yol B — bootstrap protocol bounds.
 *
 * NODUS_W_MAX_CHAIN_DEF_BLOB caps the chain_def_blob size carried in a
 * w_genesis_rsp message. H-2 mitigation against resource-exhaustion DoS
 * (A7 in design Section 5): decoder rejects oversize cdb BEFORE running
 * the Dilithium5 wsig verify so an attacker cannot waste verify cycles
 * with arbitrarily large payloads. Realistic chain_def is ~5-10 KB; the
 * 64 KB cap leaves headroom without enabling abuse.
 *
 * NODUS_W_BOOTSTRAP_NONCE_LEN sized for collision resistance in the
 * w_chain_q → w_chain_r round (C-4 mitigation): 16 random bytes echoed
 * in the response sig preimage prevent replay across chain wipes. */
#define NODUS_W_MAX_CHAIN_DEF_BLOB   (64 * 1024)
#define NODUS_W_BOOTSTRAP_NONCE_LEN  16

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
    /* Hard-Fork v1 Stage C.2 — chain_config vote-collect RPC. */
    NODUS_T3_CC_VOTE_REQ = 14,  /* proposer asks peer to sign a proposal */
    NODUS_T3_CC_VOTE_RSP = 15,  /* peer returns (witness_id, signature) or reject */
    /* PR 3 Yol B — witness auto-bootstrap discovery + chain fetch. */
    NODUS_T3_CHAIN_Q     = 16,  /* fresh node asks peer "what chain are you on?" */
    NODUS_T3_CHAIN_R     = 17,  /* peer replies cid + tip + gh + cdh + nonce echo */
    NODUS_T3_GENESIS_REQ = 18,  /* fresh node fetches chain_def + genesis from agreeing peer */
    NODUS_T3_GENESIS_RSP = 19,  /* peer sends chain_def_blob + genesis anchor */
    /* ── Ledger V2 O15B — PRODUCTION-DORMANT ────────────────────────────
     *
     * The verbs a V2 block and a V2 range travel under. They are ASSIGNED
     * and DECODABLE, and they are never dispatched into consensus on this
     * build: `nodus_witness_v2_ingress_block()` asks the activation gate
     * before it looks at a byte, and the gate can never open (no committed
     * activation authority exists; the preflight is structurally never
     * ready — nodus_witness_v2_gate.h).
     *
     * Assigned rather than left blank so the numbers cannot later be
     * claimed by something else and so an unknown-verb reject is
     * distinguishable from a not-active reject. Values are APPENDED; 1-19
     * do not move.
     */
    NODUS_T3_V2_BLOCK    = 20,  /* one finalized Ledger V2 block (BlockMessage v1) */
    NODUS_T3_V2_HEAD     = 21,  /* head advertisement — a HINT, never authority   */
    NODUS_T3_V2_RANGE_REQ = 22, /* bounded range request                          */
    NODUS_T3_V2_RANGE_RSP = 23, /* bounded range response                         */
    /* O15E Faz D — successor genesis bundle transfer (pinned-genesis
     * joiner bootstrap). Offset-chunked because a 20-validator bundle
     * exceeds the 128 KB T3 message bound. */
    NODUS_T3_V2_GBUNDLE_REQ = 24, /* {chain32, pin64, offset}             */
    NODUS_T3_V2_GBUNDLE_RSP = 25, /* {chain32, pin64, total, offset, chunk} */
    /* O15N Faz 2C1 — VIEW AUTHORITY. One message shape serves two uses:
     * a broadcast carries n_entries = 1 (this node's own statement), a
     * proof response carries f+1. Fewer verbs, one decoder, one clamp. */
    NODUS_T3_VIEWOK     = 26,   /* bundle of 1..N VIEW_OK statements     */
    NODUS_T3_VIEWOK_REQ = 27,   /* "what view can you prove?"            */
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
 * header hash — that is computed by nodus_witness_compute_block_hash).
 * A2 fix — block_height is the leader-claimed proposed-block height
 * (= leader's local height + 1). Carried on the wire so all witnesses
 * sign the PREPARED preimage with the same height (preventing the
 * cert_sig verify FAILED loop when followers have drifted). The follower
 * MUST validate prop->block_height == nodus_witness_block_height(w) + 1
 * before signing — leader's claim is locally checkable, no F-CONS-06
 * fast-path is introduced (the field anchors the round, it does not
 * substitute for state recompute). */
typedef struct {
    int             batch_count;
    nodus_t3_batch_tx_t batch_txs[NODUS_W_MAX_BLOCK_TXS];
    uint8_t         tx_root[NODUS_T3_TX_HASH_LEN];
    uint64_t        block_height;
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
     * (block_hash, voter_id = sender_id, height, chain_id).
     * Wire-independent: the same bytes are signed and verified regardless
     * of T3 envelope shape.
     *
     * O15L Faz 3 — `height` is the ROUND ANCHOR, w->round_state.
     * block_height, on BOTH sides: the signer (nodus_witness_bft.c, the
     * `cert_height` assignment feeding compute_cert_preimage) and the
     * tally-time verifier in handle_vote. This comment previously said
     * "local block_height + 1 at the moment of signing", which was the
     * old sign-side behaviour and the one cert site that never received
     * the A2 treatment.
     *
     * Why an anchor and not a fresh head read: the A2 rule is that all
     * cert_sig signing and verification within a round read the height
     * the round was opened at, so leader and followers agree on the
     * signed height even if a local head moves mid-round. The leader
     * sets the anchor to block_height(w)+1 at round start and a follower
     * refuses any proposal whose height is not its own local next, so
     * the two expressions are EQUAL for every node actually in the
     * round — they diverge only when a node's head shifts between round
     * start and signing, which is precisely the case A2 exists for.
     * With the per-vote cert check added this season, a signer using its
     * own shifted head would have its vote DROPPED by every receiver;
     * anchoring both sides removes that possibility rather than
     * tolerating it. */
    uint8_t     cert_sig[NODUS_SIG_BYTES];
} nodus_t3_vote_t;

/** Precommit certificate entry (voter_id + signature) */
typedef struct {
    uint8_t     voter_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     signature[NODUS_SIG_BYTES];
} nodus_t3_cert_entry_t;

/** w_commit: Leader broadcasts commit after quorum.
 * Phase 9 / Task 9.1 — legacy single-TX fields removed. Every commit
 * is batch-shaped post Phase 7.
 *
 * 2026-05-02 — A2 simetrisi: block_height field added (matches the
 * propose-side A2 fix). Without it, a follower that missed round N's
 * PRECOMMIT/COMMIT messages and receives round N+1's COMMIT cannot
 * detect the round skip — commit_batch defaults to local_chain_head+1
 * which mismatches the leader's actual height. Live cluster bug
 * 2026-05-01: US-1 halted at h=114 because of this exact path.
 *
 * Backward-compat: legacy peers (pre-Faz 2) emit block_height=0 by
 * struct zero-init; handle_commit treats 0 as "missing/legacy" and
 * rejects with sync trigger (mirrors enc_propose_args A2 fix).
 *
 * Wire key: "bh" (uint). */
typedef struct {
    uint64_t        proposal_timestamp;
    uint8_t         proposer_id[NODUS_T3_WITNESS_ID_LEN];
    uint64_t        block_height;                /* A2 simetrisi (2026-05-02) */
    uint32_t        n_precommits;
    uint8_t         state_root[NODUS_KEY_BYTES]; /* RFC 6962 Merkle root over UTXO set;
                                                  * O15D successor rounds carry the V2
                                                  * GLOBAL state root here (same
                                                  * semantic slot, C3-analog compare) */
    nodus_t3_cert_entry_t certs[NODUS_T3_MAX_WITNESSES]; /* Precommit signatures */

    int             batch_count;
    nodus_t3_batch_tx_t batch_txs[NODUS_W_MAX_BLOCK_TXS];
    uint8_t         tx_root[NODUS_T3_TX_HASH_LEN];

    /* ── O15D — SUCCESSOR-only OPTIONAL fields (wire keys "vbi"/"vcs").
     * The sender's engine-derived BlockID and its DNA.CERT.v2 signature
     * over it (the post-commit QC certificate exchange). Absent on every
     * legacy round: has_v2_cert stays 0 and the keys are not emitted, so
     * the legacy commit wire is byte-identical. Receivers treat the pair
     * as UNTRUSTED collection input — each certificate is verified
     * against the committed authority snapshot before it can count
     * toward a QC (nodus_witness_v2_produce.h). */
    int             has_v2_cert;
    uint8_t         v2_block_id[NODUS_T3_TX_HASH_LEN];
    uint8_t         v2_cert_sig[NODUS_SIG_BYTES];
} nodus_t3_commit_t;

/** w_viewchg: Witness requests view change.
 *
 * C5 — PBFT prepared-certificate extension. When has_prepared=true, the
 * sender is advertising "the highest (view, height, tx_hash) I observed
 * reach PREVOTE quorum locally, with 2f+1 witness sigs over the
 * PREPARED preimage (view(4B BE) || height(8B BE) || tx_hash(64B))".
 * The new leader uses this to pick the re-proposal per PBFT rule. When
 * has_prepared=false, this sender has no prepared-but-uncommitted block
 * to protect — the rest of the fields are ignored. */
typedef struct {
    uint32_t    new_view;
    uint64_t    last_committed_round;
    bool        has_prepared;
    uint64_t    prepared_height;
    uint32_t    prepared_view;
    uint8_t     prepared_tx_hash[NODUS_T3_TX_HASH_LEN];
    uint32_t    prepared_n_sigs;
    nodus_t3_cert_entry_t prepared_sigs[NODUS_T3_MAX_WITNESSES];
} nodus_t3_viewchg_t;

/** w_newview: New leader after view change.
 *
 * C5 — PBFT re-proposal constraint. When has_reproposal=true, the new
 * leader is committing to re-propose (reproposal_tx_hash, reproposal_height)
 * as the first PROPOSE under new_view. Followers verify this against
 * their own local VIEW_CHANGE log (w->view_changes[]) — the
 * reproposal_tx_hash MUST match one of the prepared-cert tx_hashes the
 * follower saw in a VIEW_CHANGE for this new_view. When
 * has_reproposal=false, no VIEW_CHANGE carried a prepared cert, so the
 * new leader is free to propose any TX from the mempool.
 *
 * n_proofs stays as observability field.
 *
 * ── O15C-D.3 — THE CARRIED PREPARED CERTIFICATE ──────────────────────
 *
 * Until O15C-D.3 this message carried the reproposal DIGEST only, and
 * the comment here said quorum was "established client-side from the
 * follower's own view_changes[] log, NOT from wire-carried proofs".
 * That was the convergence defect: `view_changes[]` is a node-local
 * FIRST-2f+1 subset which freezes at quorum (handle_viewchg drops any
 * later VIEW_CHANGE for the accepted view), so two honest followers can
 * permanently hold different subsets and reach different verdicts on the
 * SAME NEW_VIEW — one matching the digest locally, the other rejecting a
 * perfectly valid view.
 *
 * The message now carries the SELECTED certificate itself, so every
 * validator verifies the same decision from the same authenticated
 * bytes instead of consulting its own accident of message delivery:
 *
 *   reproposal_prepared_view  the cert's VIEW — the D.2 comparator's
 *                             equal-height discriminator, and part of
 *                             the signed PREPARED preimage.
 *   reproposal_n_sigs         number of per-voter signatures carried.
 *   reproposal_sigs           (voter_id, signature) pairs over the
 *                             116-byte purpose-0x07 PREPARED preimage
 *                             ("prepared" ‖ chain_id ‖ view ‖ height ‖
 *                             tx_hash) — the SAME
 *                             preimage and verification VIEW_CHANGE
 *                             already uses. No new preimage, no new
 *                             domain separation, nothing newly signed:
 *                             the leader's T3 envelope signature already
 *                             covers these keys.
 *
 * SIZE. One entry is 4659 B. The binding cap on this path is NOT the
 * 128 KB NODUS_T3_MAX_MSG_SIZE. Both VIEW_CHANGE
 * (nodus_witness_bft.c:7357) and NEW_VIEW (nodus_witness_bft.c:7890)
 * are sent through nodus_witness_bft_broadcast
 * (nodus_witness_bft.c:774), which encodes into a HEAP buffer of
 * NODUS_W_MAX_SYNC_RSP_SIZE = 1 MB (nodus_witness_bft.c:805; the
 * constant is defined above in this header), and nodus_t3_verify
 * (nodus_tier3.c:2238) heap-allocates the SAME 1 MB — so send and
 * verify are symmetric. The frame itself is bounded by
 * NODUS_MAX_FRAME_TCP = 5 MB (nodus_types.h:49).
 *
 * 1 MB holds about 225 entries at 4659 B, so the sender can attach
 * QUORUM-many signatures (the minimal sufficient proof), sorted by
 * voter_id for one canonical encoding, and quorum-many FITS for every
 * committee size this array supports: reproposal_sigs is sized
 * NODUS_T3_MAX_WITNESSES = 128 (nodus_types.h:152), and
 * dna_bft_quorum(128) = 86 (nodus_witness_bft.c:7069) — about 400 KB.
 * The shipped n=7 (quorum 5) is ~22 KB. A cert that will not fit must
 * NEVER be sent as a stripped claim: the leader fails closed and lets
 * the view rotate. */
typedef struct {
    uint32_t    new_view;
    uint32_t    n_proofs;
    bool        has_reproposal;
    uint64_t    reproposal_height;
    uint8_t     reproposal_tx_hash[NODUS_T3_TX_HASH_LEN];
    /* O15C-D.3 — the carried certificate proving the reproposal. */
    uint32_t    reproposal_prepared_view;
    uint32_t    reproposal_n_sigs;
    nodus_t3_cert_entry_t reproposal_sigs[NODUS_T3_MAX_WITNESSES];
} nodus_t3_newview_t;

/** w_viewok: a BUNDLE of 1..N VIEW_OK statements for ONE (height, view)
 * under ONE committee set hash — O15N Faz 2C1.
 *
 * Each entry is one node's purpose-0x08 signature over the 148-byte
 * VIEW_OK preimage (compute_view_ok_preimage, nodus_witness_bft.c):
 * "viewok\0\0" ‖ chain_id ‖ height ‖ view ‖ set_hash ‖ voter_id. The
 * statement certifies the OUTCOME of a view change — "I observed a
 * view-change quorum for this view" — never a vote. See
 * nodus_witness_bft_verify_view_proof for the f+1 rule and the
 * fault-vs-verdict split.
 *
 * ONE SHAPE, TWO USES: a broadcast carries n_entries = 1 (the sender's
 * own statement); a response to w_viewok_q carries f+1 (the proof).
 * There is deliberately no second verb for the second use — one decoder,
 * one clamp, one place to get the bound right.
 *
 * NO chain_id FIELD, AND THAT IS NOT AN OVERSIGHT. The T3 header already
 * carries one, but more to the point the SIGNED preimage binds the
 * VERIFIER's own w->chain_id: a statement harvested from another chain
 * fails signature verification rather than needing a wire comparison.
 * Adding a wire chain_id would create a second, weaker answer to a
 * question the signature already settles.
 *
 * ⚠ SIZE — A FUTURE SENDER MUST NOT USE THE 128 KB STACK PATTERN.
 * sizeof(nodus_t3_cert_entry_t) is 4659, so f+1 entries is ~14 KB at
 * n = 7 but ~200 KB at n = 128. Eleven send sites in this tree encode
 * into uint8_t buf[NODUS_T3_MAX_MSG_SIZE] — a 128 KB STACK buffer —
 * which holds 131072/4659 = 28 entries and therefore breaks at n >= 42
 * (dna_bft_quorum(42) = 29). Send this through the 1 MB HEAP path
 * nodus_witness_bft_broadcast already uses (NODUS_W_MAX_SYNC_RSP_SIZE,
 * nodus_witness_bft.c), the same one VIEW_CHANGE and NEW_VIEW ride;
 * nodus_t3_verify heap-allocates the same size, so send and verify stay
 * symmetric. */
typedef struct {
    uint64_t              height;
    uint32_t              view;
    uint8_t               set_hash[64];
    uint32_t              n_entries;
    nodus_t3_cert_entry_t entries[NODUS_T3_MAX_WITNESSES];
} nodus_t3_viewok_t;

/** w_viewok_q: ask a peer for the proof of the view it currently holds.
 *
 * `height_hint` is the requester's own next block height. It is a HINT
 * and authorizes NOTHING: the responder answers about the view IT can
 * prove, and the requester re-verifies the returned bundle against the
 * committee governing the height carried INSIDE that bundle. A hint that
 * is wrong, stale or hostile changes which proof is offered, never
 * whether it is believed. */
typedef struct {
    uint64_t height_hint;
} nodus_t3_viewok_q_t;

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
    /* Phase 13 / Task 13.2 — full receipt data passed through to the
     * forwarder so the original client sees block_height / tx_index /
     * chain_id in the spend result. Without these fields on the wire the
     * forwarder had to hardcode 0/0 and the client UI would display zero
     * block height even though the TX committed. */
    uint64_t    block_height;
    uint32_t    tx_index;
    uint8_t     chain_id[32];
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
    /* CC-OPS-002 / Q14 — binary-skew detection. Fields carry the sender's
     * packed (MAJOR<<16)|(MINOR<<8)|PATCH nodus version and the
     * chain_config schema version the sender was compiled with. Legacy
     * peers (pre hard-fork v1) don't send these — decoder leaves both
     * at 0, which receivers interpret as "legacy binary". */
    uint32_t        nodus_version;                      /* 0 = legacy peer */
    uint32_t        chain_config_schema;                /* 0 = legacy peer */
    /* 2026-05-02 audit C-1: heartbeat checksum signature.
     *
     * Dilithium5 signature over the 152-byte preimage:
     *   "wid\0\0\0\0\0" (8) || sender witness_id (32) || chain_id (32) ||
     *   ts_local (8 LE) || block_height (8 LE) || state_root (64) = 152
     *
     * Receiver verifies before any halt-recovery-quorum tally consults
     * peer.remote_checksum. Without this, a single Byzantine peer
     * could spoof remote_checksum to coerce halt_recovery_check into
     * either spurious DB drops or denial-of-recovery on honest halted
     * nodes (B-3 + C-1 combined risk).
     *
     * Wire key: "csg" (bstr 4627B). Backward-compat: legacy peers
     * (pre Faz 4F) emit zeros; receiver treats all-zero as unsigned
     * heartbeat — accepted for non-recovery uses (skew probe, height
     * advertisement) but ignored by halt_recovery_check. */
    uint8_t         checksum_sig[NODUS_SIG_BYTES];
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

/** w_cc_vote_req: Proposer asks a committee peer to sign a chain_config
 *  proposal preimage. Hard-Fork v1 Stage C.2. The peer runs its local
 *  signing-policy check (params-in-range + other soft rules) before
 *  deciding to sign; see nodus_witness_handle_cc_vote_req. */
typedef struct {
    uint8_t     param_id;
    uint64_t    new_value;
    uint64_t    effective_block_height;
    uint64_t    proposal_nonce;
    uint64_t    signed_at_block;
    uint64_t    valid_before_block;
    /* chain_id lives in the T3 header "cid" field — same binding as
     * proposal preimage (see nodus_chain_config_compute_digest). Not
     * duplicated here. */
} nodus_t3_cc_vote_req_t;

/** w_cc_vote_rsp: Peer's response to a vote request. Either carries a
 *  signed vote (accepted=true) or a reject with a human-readable reason
 *  (accepted=false). */
typedef struct {
    bool            accepted;
    /* Valid only when accepted == true: */
    uint8_t         witness_id[32];
    uint8_t         signature[NODUS_SIG_BYTES];
    /* Valid only when accepted == false (UTF-8, NUL-terminated): */
    char            reject_reason[128];
} nodus_t3_cc_vote_rsp_t;

/* ── PR 3 Yol B — witness auto-bootstrap (chain discovery + fetch) ── */

/** w_chain_q: Fresh node asks any peer "what chain are you on?".
 *
 * Sent broadcast-style during the DISCOVER bootstrap state. Receivers
 * that are themselves DISCOVER (no chain DB) MUST NOT respond — that's
 * the C-2 cabal protection that prevents two fresh nodes from agreeing
 * on a fictitious chain.
 *
 * The 16-byte nonce protects against replay: it's covered by the
 * w_chain_r sig preimage so a captured response cannot be replayed to a
 * different fresh node (different nonce = different sig).
 *
 * Wire keys: "n" (16B nonce). */
typedef struct {
    uint8_t     nonce[NODUS_W_BOOTSTRAP_NONCE_LEN];
} nodus_t3_w_chain_q_t;

/** w_chain_r: HAVE_CHAIN peer responds with chain identity + nonce echo.
 *
 * Fresh node collects responses from all auth'd peers, requires
 * 2f+1-of-seed_nodes agreement on (cid, cdh) before advancing to
 * FETCH_GENESIS. The "tip" field is informational and does not feed the
 * quorum decision.
 *
 * Wire keys: "cid" (32B), "tip" (uint), "gh" (64B), "cdh" (64B), "n" (16B). */
typedef struct {
    uint8_t     cid[32];                                /* peer's chain_id */
    uint64_t    tip;                                    /* peer's block_height */
    uint8_t     gh[NODUS_T3_TX_HASH_LEN];               /* genesis block hash, 64B */
    uint8_t     cdh[NODUS_T3_TX_HASH_LEN];              /* SHA3-512(chain_def_blob), 64B */
    uint8_t     nonce[NODUS_W_BOOTSTRAP_NONCE_LEN];     /* echo of w_chain_q nonce */
} nodus_t3_w_chain_r_t;

/** w_genesis_req: Fresh node fetches chain_def + genesis anchor.
 *
 * Sent ONLY after w_chain_r quorum agrees on a (cid, cdh). Target peer
 * is randomly selected from the agreeing-quorum set with a deterministic
 * PRNG seeded from SHA3(local_chain_q_nonce) — Section 4 #2 invariant.
 *
 * Wire keys: "cid" (32B). */
typedef struct {
    uint8_t     cid[32];                                /* requested chain_id */
} nodus_t3_w_genesis_req_t;

/** w_genesis_rsp: Peer sends chain_def_blob + genesis anchor.
 *
 * Receiver MUST validate before any DB write:
 *   1. cdb_len <= NODUS_W_MAX_CHAIN_DEF_BLOB (64 KB) — H-2 mitigation
 *   2. SHA3-512(cdb) == quorum-agreed cdh from w_chain_r — A6 mitigation
 *   3. gth (genesis tx_hash) matches the genesis anchor inside cdb
 * Steps 1-3 happen BEFORE the Dilithium5 wsig is even verified at
 * dispatch level so an oversize/forged response cannot waste verify
 * cycles.
 *
 * cdb is a zero-copy pointer into the decode buffer (matches tx_data
 * pattern elsewhere in tier3); valid only while the input CBOR buffer
 * is alive.
 *
 * Wire keys: "cid" (32B), "cdb" (var, ≤64KB), "gth" (64B), "gts" (uint),
 * "gpid" (32B). */
typedef struct {
    uint8_t         cid[32];                            /* must match request */
    const uint8_t  *cdb;                                /* ptr into decode buf */
    uint32_t        cdb_len;
    uint8_t         gth[NODUS_T3_TX_HASH_LEN];          /* genesis tx_hash, 64B */
    uint64_t        gts;                                /* genesis timestamp (informational) */
    uint8_t         gpid[NODUS_T3_WITNESS_ID_LEN];      /* genesis proposer_id, 32B */
} nodus_t3_w_genesis_rsp_t;

/* ── O15E Faz B — Ledger V2 successor sync payloads (verbs 20-23) ───
 *
 * Values were assigned in O15B; these are their payload codecs. All
 * four are SUCCESSOR-scoped: handlers ask the activation gate before
 * touching a byte, and an unactivated node answers nothing. None of
 * them carries a vote, so none joins the BFT-protocol-version-gated
 * set — the BlockMessage's own msg_version and the head hint's "pv"
 * field version this surface (nodus_witness_v2_sync2.h). */

/** w_v2_block (verb 20): single-block fetch REQUEST. The identity binds
 * chain + height + the exact BlockID the requester already holds (the
 * QC-recovery shape: a node that committed the block but missed the
 * certificate exchange re-fetches THE block it has, for its QC).
 * The response is a verb-23 w_v2_range_r with n == 1.
 * Wire keys: "c" (32B), "h" (uint), "bi" (64B). */
typedef struct {
    uint8_t     chain[32];
    uint64_t    height;
    uint8_t     block_id[64];
} nodus_t3_w_v2_block_q_t;

/** w_v2_head (verb 21): successor head advertisement — a HINT, never
 * authority (nodus_witness_v2_sync2.h). Broadcast on the witness tick
 * and once after each local commit, successor+armed nodes only.
 * Wire keys: "c" (32B), "g" (64B), "hh" (uint), "pv" (uint). */
typedef struct {
    uint8_t     chain[32];
    uint8_t     genesis_id[64];
    uint64_t    head;
    uint32_t    proto;              /* DNA_BLKW_VERSION the sender speaks */
} nodus_t3_w_v2_head_t;

/** w_v2_range_q (verb 22): bounded range request.
 * Wire keys: "c" (32B), "g" (64B), "fr" (uint), "n" (uint). */
typedef struct {
    uint8_t     chain[32];
    uint8_t     genesis_id[64];
    uint64_t    from;
    uint32_t    count;
} nodus_t3_w_v2_range_q_t;

/** Per-response frame cap for w_v2_range_r. The BYTE budget is the real
 * bound; a server sends however many whole frames fit, at most this
 * many. */
#define NODUS_T3_V2_RANGE_MAX_FRAMES 8u
/** Total packed-frame byte budget inside one w_v2_range_r. T3 messages
 * of this class ride the 1 MB heap encode/verify path
 * (NODUS_W_MAX_SYNC_RSP_SIZE — the COMMIT/SYNC_RSP precedent,
 * nodus_witness_bft.c broadcast + nodus_t3_verify's heap sign buffer);
 * 768 KB leaves ample headroom for the T3 envelope + Dilithium5 wsig.
 * A single BlockMessage larger than this budget is UNSERVABLE over T3
 * (named O15E limit — nothing live produces one). */
#define NODUS_T3_V2_RANGE_MAX_BYTES  786432u

/** w_v2_range_r (verb 23): bounded range response — `n` encoded
 * BlockMessage v1 frames for CONTIGUOUS ascending heights starting at
 * `from`. Frames are packed back-to-back in `frames` (zero-copy pointer
 * into the decode buffer, the w_genesis_rsp cdb pattern); frame i
 * starts at the sum of the previous lengths.
 * Wire keys: "c" (32B), "fr" (uint), "n" (uint), "fl" (bstr, n×u32 BE),
 * "fb" (bstr, packed frames). */
typedef struct {
    uint8_t         chain[32];
    uint64_t        from;
    uint32_t        n;
    uint32_t        frame_len[NODUS_T3_V2_RANGE_MAX_FRAMES];
    const uint8_t  *frames;         /* ptr into decode buf (rx) / caller
                                     * buffer (tx); packed back-to-back */
    uint32_t        frames_len;     /* total packed bytes               */
} nodus_t3_w_v2_range_r_t;

/** O15E Faz D — genesis bundle REQUEST (verb 24). Offset-chunked pull.
 * Wire keys: "c" (32B), "p" (64B pinned genesis id), "o" (uint offset). */
typedef struct {
    uint8_t     chain[32];
    uint8_t     pin[64];
    uint64_t    offset;
} nodus_t3_w_v2_gbundle_q_t;

/** O15E Faz D — genesis bundle RESPONSE (verb 25). One chunk of the
 * canonical bundle at `offset`; `total` is the full bundle length so the
 * requester knows when it is complete. `chunk` is a zero-copy pointer
 * into the decode buffer (the w_genesis_rsp cdb pattern).
 * Wire keys: "c" (32B), "p" (64B), "t" (uint total), "o" (uint offset),
 * "d" (bstr chunk). */
#define NODUS_T3_V2_GBUNDLE_CHUNK_MAX 49152u   /* 48 KB — under 128KB T3  */
typedef struct {
    uint8_t         chain[32];
    uint8_t         pin[64];
    uint64_t        total;
    uint64_t        offset;
    const uint8_t  *chunk;          /* ptr into decode buf              */
    uint32_t        chunk_len;
} nodus_t3_w_v2_gbundle_r_t;

/** w_sync_rsp: Full block data for sync (Phase 11 / Task 11.1).
 *
 * Multi-tx replay payload: the sender serializes EVERY committed
 * transaction in the requested block, ordered by tx_index. The
 * receiver MUST recompute tx_root locally via merkle_tx_root over the
 * decoded body and feed the recomputed value into compute_block_hash
 * before verify_sync_certs (Task 11.4 step b/c). NEVER trust the
 * wire-supplied tx_root field on its own.
 *
 * Three-tier wire size guard (Task 11.3):
 *   tx_count <= NODUS_W_MAX_BLOCK_TXS (10),
 *   per-TX tx_len <= NODUS_T3_MAX_TX_SIZE (64 KB),
 *   aggregate <= 1 MB enforced at the encoder/decoder. */
typedef struct {
    bool        found;
    uint64_t    height;
    uint64_t    timestamp;
    uint8_t     proposer_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t     prev_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t     tx_root[NODUS_T3_TX_HASH_LEN];   /* sender's claim — receiver MUST recompute */
    uint8_t     state_root[NODUS_KEY_BYTES];     /* C3 fix follow-up (2026-05-02): sender's
                                                   * post-block state root. Receiver passes
                                                   * to replay_block as expected_state_root
                                                   * so finalize_block can reject Byzantine
                                                   * blocks before any state mutation.
                                                   * Wire key: "sr". */

    int         tx_count;
    nodus_t3_batch_tx_t batch_txs[NODUS_W_MAX_BLOCK_TXS];

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
        nodus_t3_cc_vote_req_t cc_vote_req;
        nodus_t3_cc_vote_rsp_t cc_vote_rsp;
        nodus_t3_w_chain_q_t     w_chain_q;
        nodus_t3_w_chain_r_t     w_chain_r;
        nodus_t3_w_genesis_req_t w_genesis_req;
        nodus_t3_w_genesis_rsp_t w_genesis_rsp;
        nodus_t3_w_v2_block_q_t  w_v2_block_q;
        nodus_t3_w_v2_head_t     w_v2_head;
        nodus_t3_w_v2_range_q_t  w_v2_range_q;
        nodus_t3_w_v2_range_r_t  w_v2_range_r;
        nodus_t3_w_v2_gbundle_q_t w_v2_gbundle_q;
        nodus_t3_w_v2_gbundle_r_t w_v2_gbundle_r;
        nodus_t3_viewok_t         viewok;
        nodus_t3_viewok_q_t       viewok_q;
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
