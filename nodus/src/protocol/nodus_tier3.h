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
 * Carrying capacity is NOT assumed — it was checked, against the lane
 * that existed at O15H D8: PROPOSE and COMMIT rode the 1 MB heap
 * encode/verify path (nodus_witness_bft_broadcast + nodus_t3_verify,
 * NODUS_W_MAX_SYNC_RSP_SIZE), and the one stack buffer that carried a
 * transaction — the w_fwd forward request in nodus_witness_handlers.c
 * — moved to that same heap bound. R3 W4 deleted that whole lane
 * (PROPOSE/COMMIT/w_fwd went with it); this function's surviving
 * caller is the client tx-submit gate in nodus_witness_handlers.c,
 * which still needs the family-aware bound below. peer.c's three
 * NODUS_T3_MAX_MSG_SIZE buffers carry w_ident / w_rost_q / w_rost_r,
 * none of which holds a transaction, so they are untouched.
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

/* Phase 11 / Task 11.3 — legacy 1 MB heap-encode/verify bound.
 *
 * Originally sized against the old multi-tx sync_rsp (up to
 * NODUS_W_MAX_BLOCK_TXS * tx_len plus cert data), which exceeded the
 * 128 KB NODUS_T3_MAX_MSG_SIZE. R3 W4 deleted sync_rsp and the
 * three-tier decoder guard (tx_count / per-TX tx_len / aggregate wire
 * bytes) that used to enforce this bound on it. The macro survives as
 * the heap-encode/verify ceiling nodus_t3_verify's legacy-verb default
 * case and nodus_t3_tx_size_limit's legacy branch above still use,
 * plus the genesis-bundle response and the join-sync response's own
 * heap sends — none of which needs anywhere near 1 MB in practice.
 */
#define NODUS_W_MAX_SYNC_RSP_SIZE  (1024 * 1024)

/* R3 W4-D (Delta B) — NODUS_W_MAX_CHAIN_DEF_BLOB (the w_genesis_rsp
 * chain_def_blob size cap) and NODUS_W_BOOTSTRAP_NONCE_LEN (the
 * w_chain_q -> w_chain_r round's C-4 replay-mitigation nonce length,
 * deleted earlier this delta) are BOTH DELETED: nodus_t3_w_chain_q_t /
 * nodus_t3_w_genesis_rsp_t / nodus_t3_w_chain_r_t are gone with the closed
 * consensus lane, and both macros' only callers (test_witness_bootstrap_
 * nonce_stale.c, test_t3_bootstrap_wire.c) are deleted this delta too. */

/* ── Message types ───────────────────────────────────────────────── */

typedef enum {
    /* R3 W4 — the legacy PBFT round/vote/commit verbs (1-8), the legacy
     * sync/bootstrap verbs (12-13, 16-19), the Ledger V2 old-lane
     * block/range verbs (20-23) and the view-authority verbs (26-27) are
     * RETIRED with the closed consensus lane, exactly like the
     * Tendermint T3 legacy verbs 28-34 below. THE NUMBERS ARE RETIRED
     * AND NEVER REUSED — see nodus_t3_max_msg_size and
     * nodus_t3_type_to_method, which both answer "not a verb" for every
     * one of them. Values are NEVER renumbered; 9-11, 24-25, 35-39 and
     * 40-41 keep their assigned numbers exactly. */
    NODUS_T3_ROST_Q     = 9,
    NODUS_T3_ROST_R     = 10,
    NODUS_T3_IDENT      = 11,
    /* R3 W4-CC (D-16 rev 7, atlas-dec-0c86593601db977cd5af648b78910004) —
     * verbs 14 (w_cc_vote_req) and 15 (w_cc_vote_rsp) are RETIRED, exactly
     * like 1-8/12-13/16-23/26-27/28-34: their struct types, union members,
     * codecs and method-table rows are gone. R3-W4-D (register R3-W4-D-8)
     * kept the codec compiling with no reachable RPC behind it, pending
     * this operator decision; that decision is now made — the RPC is
     * REBUILT on the pre-auth envelope as verbs 40-41 below, never as a
     * revival of 14-15. THE NUMBERS 14 AND 15 ARE NEVER REUSED. */
    /* O15E Faz D — successor genesis bundle transfer (pinned-genesis
     * joiner bootstrap). Offset-chunked because a 20-validator bundle
     * exceeds the 128 KB T3 message bound. */
    NODUS_T3_V2_GBUNDLE_REQ = 24, /* {chain32, pin32, offset}             */
    NODUS_T3_V2_GBUNDLE_RSP = 25, /* {chain32, pin32, total, offset, chunk} */
    /* ── Tendermint T3 legacy verbs 28-34 (T2 wire design §4.2; D-16 rev 4)
     *    were RETIRED in W3 (D-16 rev 5, atlas-dec-0c86593601db977cd5af648b78910004
     *    rev 5). They were field-by-field CBOR copies of the reactor's nine
     *    messages, written before cmt_conr / cmt_memr existed to marshal
     *    the reactor's own bytes. THE NUMBERS 28-34 ARE RETIRED AND NEVER
     *    REUSED — see nodus_t3_max_msg_size and nodus_t3_type_to_method,
     *    which both answer "not a verb" for them.
     *
     * ── cometbft envelope verbs 35-39 (D-16 rev 5) — the VERB IS THE
     *    CHANNEL. Args = { m: bstr }, exactly the bytes cmt_conr / cmt_memr
     *    already marshalled (cmt_pb_cons_message for 35-38, the mempool
     *    Message for 39); this tier-3 layer decodes NOTHING inside `m`.
     *    Channel mapping (shared/dnac/cmt_conr.h / cmt_ps.h channel ids,
     *    cometbft@709fd12b consensus/reactor.go:24-30 and
     *    mempool/reactor.go:81):
     *      35 w_cmt_state -> consensus State channel        0x20
     *      36 w_cmt_data  -> consensus Data channel          0x21
     *      37 w_cmt_vote  -> consensus Vote channel           0x22
     *      38 w_cmt_bits  -> consensus VoteSetBits channel  0x23
     *      39 w_cmt_txs   -> mempool channel                  0x30
     * Frame gate (D-16 rev 5 F10): wh.cid is the derived 32-byte chain id;
     * wh.rnd and wh.vw are written 0 and never read.
     * NODUS_T3_BFT_PROTOCOL_VER moves 6 -> 7 in W3 (nodus_types.h). */
    NODUS_T3_CMT_STATE         = 35,  /* w_cmt_state — State channel 0x20         */
    NODUS_T3_CMT_DATA          = 36,  /* w_cmt_data  — Data channel  0x21         */
    NODUS_T3_CMT_VOTE          = 37,  /* w_cmt_vote  — Vote channel  0x22         */
    NODUS_T3_CMT_VOTE_SET_BITS = 38,  /* w_cmt_bits  — VoteSetBits channel 0x23   */
    NODUS_T3_CMT_TXS           = 39,  /* w_cmt_txs   — mempool channel 0x30       */

    /* ── SYSTEM-governance approval collection (verbs 40-41; D-16 rev 7,
     * W4-CC) — a GOVERNANCE RPC, not a consensus verb: NOT on the version
     * gate or the quarantine list (those stay exactly verbs 35-39), and
     * NODUS_T3_BFT_PROTOCOL_VER is unchanged at 7.
     *
     * 40 w_cc_appr_req: a proposer asks ONE committee peer to approve a
     * PRE-AUTH single-leg SYSTEM-governance envelope (today exactly
     * CHAIN_CONFIG, runtime_op 6) — the envelope's auth blob is
     * zero-filled at its FINAL length (submitter + the proposer's chosen
     * N approvals; N is fixed BEFORE anyone signs, since the approval
     * COUNT is bound into the leg auth_digest through auth_len). Args
     * { e: bstr }, e <= DNA_ENV_MAX_TOTAL_LEN — zero-copy on decode, the
     * same idiom as verb 39's `m`.
     *
     * 41 w_cc_appr_rsp: the peer's answer — one signed committee-seat
     * approval, or a refusal with a reason. Args { ok: bool, i: uint
     * (seat, u16), s: bstr(4627), sh: bstr(64), ep: uint, r: tstr <=128 }.
     * ok=true: i/s/sh/ep are the signed approval, r is absent. ok=false:
     * only r is meaningful.
     *
     * A server never RECEIVES 41 (it is a client-only reply, like 15 was)
     * — dispatch drops it exactly like the retired 14-15 dropped:
     * log-and-drop at `default:`, unchanged shape. */
    NODUS_T3_CC_APPR_REQ = 40,  /* w_cc_appr_req — collect one committee approval */
    NODUS_T3_CC_APPR_RSP = 41,  /* w_cc_appr_rsp — one seat's signed approval or refusal */
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

/* R3 W4 — nodus_t3_batch_tx_t and the structs it and its sibling
 * cert_entry_t fed (nodus_t3_propose_t, nodus_t3_vote_t,
 * nodus_t3_cert_entry_t, nodus_t3_commit_t, nodus_t3_viewchg_t,
 * nodus_t3_newview_t, nodus_t3_viewok_t, nodus_t3_viewok_q_t,
 * nodus_t3_fwd_req_t, nodus_t3_witness_sig_t, nodus_t3_fwd_rsp_t) are
 * DELETED with the closed consensus lane they served: the legacy PBFT
 * round (PROPOSE/PREVOTE/PRECOMMIT/COMMIT/VIEWCHG/NEWVIEW), the
 * view-authority bundle (VIEWOK/VIEWOK_REQ) and the non-leader forward
 * path (FWD_REQ/FWD_RSP). None of verbs 1-8 or 26-27 is a verb any more. */

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

/* R3 W4 — nodus_t3_sync_req_t and nodus_t3_sync_cert_t are DELETED with
 * the closed consensus lane they served: the legacy single-block sync
 * request/response pair (verbs 12-13). Neither is a verb any more. */

/* R3 W4-CC — nodus_t3_cc_vote_req_t / nodus_t3_cc_vote_rsp_t (the retired
 * verbs 14-15) are DELETED with the legacy vote-collect RPC; see the
 * verb 40-41 structs below for the pre-auth-envelope replacement. */

/* ── PR 3 Yol B — witness auto-bootstrap (chain discovery + fetch) ── */

/* R3 W4 — nodus_t3_w_chain_q_t, nodus_t3_w_chain_r_t,
 * nodus_t3_w_genesis_req_t, nodus_t3_w_genesis_rsp_t (the PR 3 Yol B
 * witness auto-bootstrap discovery + chain fetch, verbs 16-19) and
 * nodus_t3_w_v2_block_q_t, nodus_t3_w_v2_head_t, nodus_t3_w_v2_range_q_t,
 * nodus_t3_w_v2_range_r_t (the Ledger V2 old-lane block/range payloads,
 * verbs 20-23) are DELETED with the closed consensus lane: none of
 * verbs 16-23 is a verb any more. The surviving genesis-bundle payloads
 * (verbs 24-25) follow. */

/** O15E Faz D — genesis bundle REQUEST (verb 24). Offset-chunked pull.
 *
 * D-24 rev 4 (1): `pin` is 32 bytes, not 64 — the joiner's ONLY input is
 * the 32-byte chain id (D-17 rev 10 / D-18 rev 4: a version-3 chain's
 * identity is the hash of its stored genesis DOCUMENT, not a genesis
 * BLOCK; there is no 64-byte genesis BlockID left to pin to). `chain` and
 * `pin` now name the same identity from two angles — which chain this
 * request is about, and the requester's own expectation of it.
 * Wire keys: "c" (32B), "p" (32B, the chain id), "o" (uint offset). */
typedef struct {
    uint8_t     chain[32];
    uint8_t     pin[32];
    uint64_t    offset;
} nodus_t3_w_v2_gbundle_q_t;

/** O15E Faz D — genesis bundle RESPONSE (verb 25). One chunk of the
 * canonical bundle at `offset`; `total` is the full bundle length so the
 * requester knows when it is complete. `chunk` is a zero-copy pointer
 * into the decode buffer (the w_genesis_rsp cdb pattern).
 *
 * D-24 rev 4 (1): `pin` is 32 bytes — see the REQUEST's doc comment.
 * Wire keys: "c" (32B), "p" (32B), "t" (uint total), "o" (uint offset),
 * "d" (bstr chunk). */
#define NODUS_T3_V2_GBUNDLE_CHUNK_MAX 49152u   /* 48 KB — under 128KB T3  */
typedef struct {
    uint8_t         chain[32];
    uint8_t         pin[32];
    uint64_t        total;
    uint64_t        offset;
    const uint8_t  *chunk;          /* ptr into decode buf              */
    uint32_t        chunk_len;
} nodus_t3_w_v2_gbundle_r_t;

/* R3 W4 — nodus_t3_sync_rsp_t (the legacy multi-tx sync replay payload,
 * verb 13) is DELETED with the closed consensus lane: it referenced
 * nodus_t3_batch_tx_t and nodus_t3_sync_cert_t, both already deleted
 * above, and verb 13 is not a verb any more. */

/* ── cometbft envelope payload (verbs 35-39; D-16 rev 5) ───────────────
 *
 * atlas-dec-0c86593601db977cd5af648b78910004 rev 5. All five verbs share
 * ONE struct: the verb IS the channel, and the ONLY field is the
 * reactor's own already-marshalled bytes. This layer never looks inside
 * `m` — it is opaque here, exactly as p2p/peer.go:277-280 hands the
 * transport bytes it has already marshalled. Wire key: "m" (bstr) —
 * exact key set (no other key admitted), same discipline as the legacy
 * verbs 28-34 this replaces.
 *
 * ZERO-COPY ON DECODE: `m` points into the input CBOR buffer — the same
 * idiom the retired nodus_t3_tm_prop_t's `v` field and w_v2_range_r's
 * `frames` used (a large bstr is never copied, only bounded and
 * pointed-at; see dec_w_v2_gbundle_r_args's `chunk`, still present in
 * the .c file). It is valid only while that buffer is alive. On ENCODE,
 * `m` is caller-owned for the duration of the nodus_t3_encode call.
 *
 * NOTHING IS VALIDATED HERE beyond the byte-string length ceiling. The
 * reactor's own ValidateBasic gate (cmt_msgs.c) and the `wh.cid`
 * derived-identity gate run on the DECODED bytes, downstream of this
 * codec, never inside it. */
typedef struct {
    const uint8_t *m;       /* ptr into decode buf (rx) / caller buf (tx) */
    size_t         m_len;
} nodus_t3_w_cmt_t;

/* ── Per-verb message classes (D-16 rev 5 "envelope overhead on top") ──
 *
 * `m`'s ceiling comes from the reactor that marshalled it, not from this
 * layer: verbs 35-38 share the consensus reactor's `maxMsgSize`
 * (cometbft@709fd12b consensus/reactor.go:30, CMT_CONR_MAX_MSG_SIZE,
 * shared/dnac/cmt_ps.h:164); verb 39 takes the mempool reactor's
 * RecvMessageCapacity at the default MaxTxBytes
 * (Message{Txs{[MaxTxBytes]}}.Size(), cmt_memr_get_channels,
 * shared/dnac/cmt_memr.h:114-116) — EIGHT BYTES LARGER than the
 * consensus ceiling, so one shared constant would be wrong for one of
 * the two. The envelope overhead figure is the retired
 * NODUS_T3_TM_ENVELOPE_OVERHEAD's, unchanged: the {t,y,q,wh,a,wsig} map,
 * the 7-key `wh`, the method string, the per-key CBOR headers and the
 * 4627-byte frame wsig. test_tier3.c MEASURES the real overhead of a
 * maximal message and asserts it stays below. */
#define NODUS_T3_CMT_ENVELOPE_OVERHEAD  8192u      /* wh + wsig 4627 + CBOR keys + slack */
#define NODUS_T3_CMT_CONS_M_MAX         1048576u   /* verbs 35-38: CMT_CONR_MAX_MSG_SIZE */
#define NODUS_T3_CMT_TXS_M_MAX          1048584u   /* verb 39: mempool RecvMessageCapacity at default MaxTxBytes */

/* ── SYSTEM-governance approval collection payload (verbs 40-41; D-16
 * rev 7, W4-CC) — see the two verbs' own enum comments above. */

/** w_cc_appr_req (verb 40): the pre-auth envelope. Zero-copy on decode —
 *  the same idiom as verb 39's `m` (nodus_t3_w_cmt_t) and w_v2_range_r's
 *  `frames`: `e` points into the decode buffer and is valid only while
 *  that buffer is alive; on encode it is caller-owned for the duration
 *  of the nodus_t3_encode call. This layer decodes NOTHING inside `e` —
 *  the responder's own engine seam does (nodus_witness_v2_block_ctx_build
 *  + nodus_witness_v2_env_preflight_batch, the same seam CheckTx uses). */
typedef struct {
    const uint8_t *e;       /* ptr into decode buf (rx) / caller buf (tx) */
    size_t         e_len;
} nodus_t3_cc_appr_req_t;

/** w_cc_appr_rsp (verb 41): one committee seat's answer.
 *  ok=true: seat/sig/set_hash/epoch are the signed "DNA.CCAPPR.v1"
 *  approval (nodus_rt_cc_approval_digest); reason is empty.
 *  ok=false: only reason is meaningful (UTF-8, NUL-terminated). */
typedef struct {
    bool     ok;
    uint16_t seat;
    uint8_t  sig[NODUS_SIG_BYTES];
    uint8_t  set_hash[64];
    uint64_t epoch;
    char     reason[129];   /* <= 128 chars + NUL, matches D-16 rev 7's
                             * "r: tstr <= 128" exactly (not 127) */
} nodus_t3_cc_appr_rsp_t;

/** Verb 40's `e` ceiling: the largest pre-auth envelope this layer will
 *  carry — the same versioned capacity bound the engine's own envelope
 *  codec enforces (shared/dnac/env_wire.h), so this transport layer can
 *  never refuse an envelope the engine would otherwise accept. Verb 41's
 *  ceiling is its three variable-length fields' worst case: a 4627-byte
 *  Dilithium5 signature, a 64-byte set hash, and headroom for the
 *  refusal string (128 declared, 256 to leave slack for future reasons
 *  without moving this ceiling again). */
#define NODUS_T3_CC_APPR_E_MAX    DNA_ENV_MAX_TOTAL_LEN
#define NODUS_T3_CC_APPR_RSP_MAX  (4627u + 64u + 256u)

/**
 * Per-type message ceiling — the size nodus_t3_encode/nodus_t3_verify must
 * be able to hold for `type`.
 *
 * Verbs 35-38 return NODUS_T3_CMT_CONS_M_MAX + the envelope overhead;
 * verb 39 returns NODUS_T3_CMT_TXS_M_MAX + the envelope overhead. Verb 40
 * returns NODUS_T3_CC_APPR_E_MAX + the envelope overhead; verb 41 returns
 * NODUS_T3_CC_APPR_RSP_MAX + the envelope overhead. Verbs 14-15 and 28-34
 * are RETIRED and return 0 (nodus_t3_type_to_method(14/15/28..34) is
 * NULL — they are not a verb any more). EVERY legacy type returns
 * NODUS_W_MAX_SYNC_RSP_SIZE, which is the bound the legacy path uses
 * today: nodus_t3_verify (nodus_tier3.c) allocates exactly that, for
 * every type. Reporting anything smaller here would describe a ceiling
 * the tree does not actually apply.
 *
 * READ THIS BEFORE SIZING peer.c's RECEIVE BUFFERS FROM IT — unchanged
 * warning from wave 1: this answers from the VERIFY side, which is
 * uniform for every legacy verb, not the smaller SEND-side bound most
 * of them actually use.
 *
 * @return the ceiling in bytes; 0 for a type that is not a T3 verb.
 */
size_t nodus_t3_max_msg_size(nodus_t3_msg_type_t type);

/* ── Full decoded message ────────────────────────────────────────── */

typedef struct {
    uint32_t            txn_id;
    nodus_t3_msg_type_t type;
    char                method[16];
    nodus_t3_header_t   header;
    const uint8_t      *wsig;       /* ptr into decode buffer, NODUS_SIG_BYTES */

    /* R3 W4 — the union members for every retired verb (propose, vote,
     * commit, viewchg, newview, fwd_req, fwd_rsp, sync_req, sync_rsp,
     * w_chain_q, w_chain_r, w_genesis_req, w_genesis_rsp, w_v2_block_q,
     * w_v2_head, w_v2_range_q, w_v2_range_r, viewok, viewok_q) are
     * DELETED with the closed consensus lane; their struct types no
     * longer exist. R3 W4-CC deletes cc_vote_req/cc_vote_rsp (verbs
     * 14-15) the same way — cc_appr_req/cc_appr_rsp (verbs 40-41) below
     * are their replacement, not a revival. */
    union {
        nodus_t3_rost_q_t   rost_q;
        nodus_t3_rost_r_t   rost_r;
        nodus_t3_ident_t    ident;
        nodus_t3_cc_appr_req_t cc_appr_req;
        nodus_t3_cc_appr_rsp_t cc_appr_rsp;
        nodus_t3_w_v2_gbundle_q_t w_v2_gbundle_q;
        nodus_t3_w_v2_gbundle_r_t w_v2_gbundle_r;
        /* cometbft envelope (verbs 35-39; D-16 rev 5). */
        nodus_t3_w_cmt_t          w_cmt;
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
