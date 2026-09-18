/**
 * Nodus — Tier 3 Protocol (Witness BFT Consensus)
 *
 * CBOR encode/decode for all 13 BFT message types.
 * Sign payload = canonical CBOR of {method + header + args}.
 * Wire format  = {t, y, q, wh, a, wsig}.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"
/* D-16 rev 5 — the cometbft envelope (verbs 35-39) ties its per-verb
 * ceiling to the reactor's own maxMsgSize; this is the one place that
 * number is pinned against its source. */
#include "dnac/cmt_ps.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "T3"

/* Key comparison helper */
#define KEY_IS(k, s) \
    ((k).tstr.len == sizeof(s) - 1 && memcmp((k).tstr.ptr, (s), sizeof(s) - 1) == 0)

/* ── Method ↔ Type mapping ───────────────────────────────────────── */

const char *nodus_t3_type_to_method(nodus_t3_msg_type_t type) {
    switch (type) {
        /* R3 W4 — the case arms for every retired verb (PROPOSE, PREVOTE,
         * PRECOMMIT, COMMIT, VIEWCHG, NEWVIEW, FWD_REQ, FWD_RSP,
         * SYNC_REQ, SYNC_RSP, CHAIN_Q, CHAIN_R, GENESIS_REQ, GENESIS_RSP,
         * V2_BLOCK, V2_HEAD, V2_RANGE_REQ, V2_RANGE_RSP, VIEWOK,
         * VIEWOK_REQ) are DELETED with the closed consensus lane; none
         * of their enum values exists any more — they fall to
         * `default: return NULL` below, exactly like verbs 28-34.
         * R3 W4-CC retires CC_VOTE_REQ/CC_VOTE_RSP (14-15) the same way
         * — CC_APPR_REQ/CC_APPR_RSP (40-41) below are their
         * replacement. */
        case NODUS_T3_ROST_Q:    return "w_rost_q";
        case NODUS_T3_ROST_R:    return "w_rost_r";
        case NODUS_T3_IDENT:     return "w_ident";
        case NODUS_T3_V2_GBUNDLE_REQ: return "w_v2_gbundle_q";
        case NODUS_T3_V2_GBUNDLE_RSP: return "w_v2_gbundle_r";
        /* cometbft envelope (D-16 rev 5). All five verbs appear in BOTH
         * tables, in enc_args's dispatch, in pass-2's dispatch and in
         * nodus_t3_verify's range test — a verb named in one table only
         * would make nodus_t3_decode return 0 with a zeroed struct (the
         * pass-2 switch falls through `default: break`). Verbs 28-34 are
         * RETIRED: they fall to `default: return NULL` below, exactly
         * like any other unknown type. */
        case NODUS_T3_CMT_STATE:         return "w_cmt_state";
        case NODUS_T3_CMT_DATA:          return "w_cmt_data";
        case NODUS_T3_CMT_VOTE:          return "w_cmt_vote";
        case NODUS_T3_CMT_VOTE_SET_BITS: return "w_cmt_bits";
        case NODUS_T3_CMT_TXS:           return "w_cmt_txs";
        /* SYSTEM-governance approval collection (verbs 40-41; D-16
         * rev 7, W4-CC) — same both-tables discipline as the cometbft
         * envelope above. */
        case NODUS_T3_CC_APPR_REQ: return "w_cc_appr_req";
        case NODUS_T3_CC_APPR_RSP: return "w_cc_appr_rsp";
        default:                 return NULL;
    }
}

nodus_t3_msg_type_t nodus_t3_method_to_type(const char *method) {
    if (!method) return 0;
    /* R3 W4 — the method-string comparisons for every retired verb
     * (w_propose, w_prevote, w_precommit, w_commit, w_viewchg, w_newview,
     * w_fwd_req, w_fwd_rsp, w_sync_req, w_sync_rsp, w_chain_q, w_chain_r,
     * w_genesis_req, w_genesis_rsp, w_v2_block, w_v2_head, w_v2_range_q,
     * w_v2_range_r, w_viewok, w_viewok_q) are DELETED with the closed
     * consensus lane; none of their method names is recognised any more
     * — an incoming frame naming one falls through to the final
     * `return 0` below, exactly like any other unknown method.
     * R3 W4-CC retires w_cc_vote_req/w_cc_vote_rsp the same way —
     * w_cc_appr_req/w_cc_appr_rsp below are their replacement. */
    if (strcmp(method, "w_rost_q") == 0)     return NODUS_T3_ROST_Q;
    if (strcmp(method, "w_rost_r") == 0)     return NODUS_T3_ROST_R;
    if (strcmp(method, "w_ident") == 0)      return NODUS_T3_IDENT;
    if (strcmp(method, "w_v2_gbundle_q") == 0) return NODUS_T3_V2_GBUNDLE_REQ;
    if (strcmp(method, "w_v2_gbundle_r") == 0) return NODUS_T3_V2_GBUNDLE_RSP;
    /* cometbft envelope — the same five verbs as the table above. */
    if (strcmp(method, "w_cmt_state") == 0)    return NODUS_T3_CMT_STATE;
    if (strcmp(method, "w_cmt_data") == 0)     return NODUS_T3_CMT_DATA;
    if (strcmp(method, "w_cmt_vote") == 0)     return NODUS_T3_CMT_VOTE;
    if (strcmp(method, "w_cmt_bits") == 0)     return NODUS_T3_CMT_VOTE_SET_BITS;
    if (strcmp(method, "w_cmt_txs") == 0)      return NODUS_T3_CMT_TXS;
    /* SYSTEM-governance approval collection (verbs 40-41; W4-CC). */
    if (strcmp(method, "w_cc_appr_req") == 0)  return NODUS_T3_CC_APPR_REQ;
    if (strcmp(method, "w_cc_appr_rsp") == 0)  return NODUS_T3_CC_APPR_RSP;
    return 0;
}

/* ── Per-type message ceiling (D-14 rev 2; header contract) ──────── */

size_t nodus_t3_max_msg_size(nodus_t3_msg_type_t type) {
    switch (type) {
        case NODUS_T3_CMT_STATE:
        case NODUS_T3_CMT_DATA:
        case NODUS_T3_CMT_VOTE:
        case NODUS_T3_CMT_VOTE_SET_BITS:
            return (size_t)NODUS_T3_CMT_CONS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD;
        case NODUS_T3_CMT_TXS:
            return (size_t)NODUS_T3_CMT_TXS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD;
        case NODUS_T3_CC_APPR_REQ:
            return (size_t)NODUS_T3_CC_APPR_E_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD;
        case NODUS_T3_CC_APPR_RSP:
            return (size_t)NODUS_T3_CC_APPR_RSP_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD;
        default:
            /* Every legacy verb: the bound the legacy path actually uses
             * today — nodus_t3_verify's fixed 1 MB heap allocation below.
             * A type that is no verb at all (including the RETIRED 28-34)
             * has no ceiling to report. */
            return nodus_t3_type_to_method(type) ? (size_t)NODUS_W_MAX_SYNC_RSP_SIZE
                                                 : (size_t)0;
    }
}

/* D-16 rev 5 — the consensus channels' ceiling IS the reactor's own
 * constant, pinned here so a drift in either fails the build. The
 * mempool ceiling (NODUS_T3_CMT_TXS_M_MAX) cannot be pinned the same
 * way: cmt_memr_get_channels computes it at runtime from
 * cmt_mempool_config_t.max_tx_bytes, so it is not a compile-time
 * constant on the cmt_memr side — test_tier3.c's
 * test_tm_max_msg_size pins it against a live cmt_memr_get_channels()
 * call instead. */
_Static_assert(NODUS_T3_CMT_CONS_M_MAX == CMT_CONR_MAX_MSG_SIZE,
               "T3 cmt consensus ceiling drifted from CMT_CONR_MAX_MSG_SIZE");
/* The largest verb-39 frame this layer will ever try to send: its
 * message ceiling, plus the 7-byte transport frame header
 * (nodus_wire.c), plus one more ML-DSA-87 signature's worth of slack
 * (NODUS_SIG_BYTES) so a future rounding of the envelope overhead does
 * not silently approach NODUS_MAX_FRAME_TCP unnoticed. */
_Static_assert((uint64_t)NODUS_T3_CMT_TXS_M_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD
               + 7u + NODUS_SIG_BYTES < (uint64_t)NODUS_MAX_FRAME_TCP,
               "T3 cmt TXS ceiling exceeds NODUS_MAX_FRAME_TCP");
/* D-16 rev 7 (W4-CC) — the same frame-size proof for verb 40, the larger
 * of the two new governance verbs (verb 41's ceiling is a few KB). */
_Static_assert((uint64_t)NODUS_T3_CC_APPR_E_MAX + NODUS_T3_CMT_ENVELOPE_OVERHEAD
               + 7u + NODUS_SIG_BYTES < (uint64_t)NODUS_MAX_FRAME_TCP,
               "T3 cc_appr_req ceiling exceeds NODUS_MAX_FRAME_TCP");

/* R3 W4 — the PR 3 Yol B bootstrap sig domain separator
 * (NODUS_T3_BOOTSTRAP_SIG_DOMAIN, is_bootstrap_type) is DELETED with the
 * closed consensus lane: the 4 bootstrap message types it distinguished
 * (CHAIN_Q, CHAIN_R, GENESIS_REQ, GENESIS_RSP) are all deleted, and
 * nodus_t3_type_to_method now returns NULL for every one of them, so
 * enc_sign_payload already refuses before is_bootstrap_type could ever
 * be reached. */

/* ══════════════════════════════════════════════════════════════════
 * ENCODE
 * ══════════════════════════════════════════════════════════════════ */

/* ── Header encode ───────────────────────────────────────────────── */

static void enc_wh(cbor_encoder_t *enc, const nodus_t3_header_t *hdr) {
    cbor_encode_cstr(enc, "wh");
    cbor_encode_map(enc, 7);
    cbor_encode_cstr(enc, "v");   cbor_encode_uint(enc, hdr->version);
    cbor_encode_cstr(enc, "rnd"); cbor_encode_uint(enc, hdr->round);
    cbor_encode_cstr(enc, "vw");  cbor_encode_uint(enc, hdr->view);
    cbor_encode_cstr(enc, "sid"); cbor_encode_bstr(enc, hdr->sender_id,
                                                    NODUS_T3_WITNESS_ID_LEN);
    cbor_encode_cstr(enc, "ts");  cbor_encode_uint(enc, hdr->timestamp);
    cbor_encode_cstr(enc, "nc");  cbor_encode_uint(enc, hdr->nonce);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, hdr->chain_id, 32);
}

/* ── Per-type args encode ────────────────────────────────────────── */

/* R3 W4 — enc_batch_tx and every retired-verb encoder it fed
 * (enc_propose_args, enc_vote_args, enc_commit_certs, enc_commit_args,
 * enc_viewchg_args, enc_newview_args) are DELETED with the closed
 * consensus lane. See enc_args's own deletion note below for the full
 * case list. */

/* R3 W4 — enc_viewok_args, enc_viewok_q_args, enc_fwd_req_args and
 * enc_fwd_rsp_args are DELETED with the closed consensus lane: the
 * view-authority bundle (verbs 26-27) and the non-leader forward path
 * (verbs 7-8). See enc_args's own deletion note below for the full case
 * list. */

static void enc_rost_q_args(cbor_encoder_t *enc, const nodus_t3_rost_q_t *r) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "v"); cbor_encode_uint(enc, r->version);
}

static void enc_rost_r_args(cbor_encoder_t *enc, const nodus_t3_rost_r_t *r) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "v");  cbor_encode_uint(enc, r->version);
    cbor_encode_cstr(enc, "nw"); cbor_encode_uint(enc, r->n_witnesses);
    cbor_encode_cstr(enc, "ws");
    cbor_encode_array(enc, r->n_witnesses);
    for (uint32_t i = 0; i < r->n_witnesses; i++) {
        const nodus_t3_roster_entry_t *e = &r->witnesses[i];
        cbor_encode_map(enc, 5);
        cbor_encode_cstr(enc, "wid");  cbor_encode_bstr(enc, e->witness_id,
                                                         NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(enc, "pk");   cbor_encode_bstr(enc, e->pubkey,
                                                         NODUS_PK_BYTES);
        cbor_encode_cstr(enc, "addr"); cbor_encode_cstr(enc, e->address);
        cbor_encode_cstr(enc, "je");   cbor_encode_uint(enc, e->joined_epoch);
        cbor_encode_cstr(enc, "act");  cbor_encode_bool(enc, e->active);
    }
    cbor_encode_cstr(enc, "rsig");
    if (r->roster_sig)
        cbor_encode_bstr(enc, r->roster_sig, NODUS_SIG_BYTES);
    else {
        uint8_t zero_sig[NODUS_SIG_BYTES];
        memset(zero_sig, 0, NODUS_SIG_BYTES);
        cbor_encode_bstr(enc, zero_sig, NODUS_SIG_BYTES);
    }
}

/* ── w_cc_appr_req / w_cc_appr_rsp args (D-16 rev 7, W4-CC) ──────────
 * R3 W4-CC replaces the retired verbs 14-15 (Hard-Fork v1 Stage C.2)
 * with this pair, over the pre-auth SYSTEM-governance envelope. */

static void enc_cc_appr_req_args(cbor_encoder_t *enc,
                                 const nodus_t3_cc_appr_req_t *r) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "e"); cbor_encode_bstr(enc, r->e, r->e_len);
}

static void enc_cc_appr_rsp_args(cbor_encoder_t *enc,
                                 const nodus_t3_cc_appr_rsp_t *r) {
    if (r->ok) {
        cbor_encode_map(enc, 5);
        cbor_encode_cstr(enc, "ok"); cbor_encode_bool(enc, true);
        cbor_encode_cstr(enc, "i");  cbor_encode_uint(enc, r->seat);
        cbor_encode_cstr(enc, "s");  cbor_encode_bstr(enc, r->sig, NODUS_SIG_BYTES);
        cbor_encode_cstr(enc, "sh"); cbor_encode_bstr(enc, r->set_hash, 64);
        cbor_encode_cstr(enc, "ep"); cbor_encode_uint(enc, r->epoch);
    } else {
        cbor_encode_map(enc, 2);
        cbor_encode_cstr(enc, "ok"); cbor_encode_bool(enc, false);
        cbor_encode_cstr(enc, "r");  cbor_encode_cstr(enc, r->reason);
    }
}

static void enc_ident_args(cbor_encoder_t *enc, const nodus_t3_ident_t *id) {
    /* Map count: wid, pk, addr, tsl, nv, ccs = 6 base;
     * +4 for bh, sr, vw, rn when has_block_height; +1 for csg
     * (Faz 4F C-1 heartbeat sig) when has_block_height (the signature
     * binds bh+sr+ts so it only meaningful when those are present). */
    cbor_encode_map(enc, id->has_block_height ? 11 : 6);
    cbor_encode_cstr(enc, "wid");  cbor_encode_bstr(enc, id->witness_id,
                                                     NODUS_T3_WITNESS_ID_LEN);
    cbor_encode_cstr(enc, "pk");   cbor_encode_bstr(enc, id->pubkey,
                                                     NODUS_PK_BYTES);
    cbor_encode_cstr(enc, "addr"); cbor_encode_cstr(enc, id->address);
    cbor_encode_cstr(enc, "tsl");  cbor_encode_uint(enc, id->ts_local);
    /* CC-OPS-002 / Q14 — binary-skew / schema advertisement. */
    cbor_encode_cstr(enc, "nv");   cbor_encode_uint(enc, id->nodus_version);
    cbor_encode_cstr(enc, "ccs");  cbor_encode_uint(enc, id->chain_config_schema);
    if (id->has_block_height) {
        cbor_encode_cstr(enc, "bh");  cbor_encode_uint(enc, id->block_height);
        cbor_encode_cstr(enc, "sr"); cbor_encode_bstr(enc, id->state_root,
                                                        NODUS_KEY_BYTES);
        cbor_encode_cstr(enc, "vw");  cbor_encode_uint(enc, id->current_view);
        cbor_encode_cstr(enc, "rn");  cbor_encode_uint(enc, id->roster_size);
        cbor_encode_cstr(enc, "csg"); cbor_encode_bstr(enc, id->checksum_sig,
                                                        NODUS_SIG_BYTES);
    }
}

/* R3 W4 — enc_sync_req_args, enc_sync_rsp_args (verbs 12-13),
 * enc_w_chain_q_args, enc_w_chain_r_args, enc_w_genesis_req_args,
 * enc_w_genesis_rsp_args (the PR 3 Yol B witness auto-bootstrap arg
 * encoders, verbs 16-19) and enc_w_v2_block_q_args, enc_w_v2_head_args,
 * enc_w_v2_range_q_args, enc_w_v2_range_r_args (the Ledger V2 old-lane
 * sync arg encoders, verbs 20-23) are DELETED with the closed consensus
 * lane. See enc_args's own deletion note below for the full case list. */

static void enc_w_v2_gbundle_q_args(cbor_encoder_t *enc,
                                    const nodus_t3_w_v2_gbundle_q_t *m) {
    cbor_encode_map(enc, 3);
    cbor_encode_cstr(enc, "c"); cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "p"); cbor_encode_bstr(enc, m->pin, 32);
    cbor_encode_cstr(enc, "o"); cbor_encode_uint(enc, m->offset);
}

static void enc_w_v2_gbundle_r_args(cbor_encoder_t *enc,
                                    const nodus_t3_w_v2_gbundle_r_t *m) {
    cbor_encode_map(enc, 5);
    cbor_encode_cstr(enc, "c"); cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "p"); cbor_encode_bstr(enc, m->pin, 32);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, m->total);
    cbor_encode_cstr(enc, "o"); cbor_encode_uint(enc, m->offset);
    cbor_encode_cstr(enc, "d"); cbor_encode_bstr(enc, m->chunk, m->chunk_len);
}

/* ── cometbft envelope arg encoder (verbs 35-39; D-16 rev 5) ─────────
 *
 * One encoder for all five verbs: the args map is exactly { m: bstr },
 * the reactor's own already-marshalled bytes. The class ceiling (35-38
 * vs 39) is checked in enc_args below, before any byte is emitted, the
 * same H-2 / O15E discipline already used for cdb, the range response
 * and the gbundle chunk. */

static void enc_w_cmt_args(cbor_encoder_t *enc, const nodus_t3_w_cmt_t *m) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "m"); cbor_encode_bstr(enc, m->m, m->m_len);
}

/* ── Args dispatch ───────────────────────────────────────────────── */

static int enc_args(cbor_encoder_t *enc, const nodus_t3_msg_t *msg) {
    /* R3 W4 — the H-2 chain_def_blob cap (NODUS_T3_GENESIS_RSP) and the
     * O15E Faz B range-response cap (NODUS_T3_V2_RANGE_RSP) are DELETED
     * with the closed consensus lane: neither enum value exists any
     * more. */
    if (msg->type == NODUS_T3_V2_GBUNDLE_RSP &&
        (msg->w_v2_gbundle_r.chunk_len > NODUS_T3_V2_GBUNDLE_CHUNK_MAX ||
         (msg->w_v2_gbundle_r.chunk_len > 0 && !msg->w_v2_gbundle_r.chunk)))
        return -1;
    /* cometbft envelope (verbs 35-39; D-16 rev 5) — the sender refuses an
     * out-of-class `m` before emitting, so an encoder can never produce
     * bytes its own decoder would reject (DG-13 bijection). The ceiling
     * is the reactor's, not a T2 field range: 35-38 share the consensus
     * reactor's class, 39 takes the (larger) mempool class. */
    if (msg->type >= NODUS_T3_CMT_STATE && msg->type <= NODUS_T3_CMT_TXS) {
        const nodus_t3_w_cmt_t *c = &msg->w_cmt;
        size_t m_cap = (msg->type == NODUS_T3_CMT_TXS)
                       ? (size_t)NODUS_T3_CMT_TXS_M_MAX
                       : (size_t)NODUS_T3_CMT_CONS_M_MAX;
        if ((c->m == NULL && c->m_len != 0) || c->m_len > m_cap)
            return -1;
    }
    /* SYSTEM-governance approval collection (verbs 40-41; D-16 rev 7,
     * W4-CC) — same out-of-class refusal-before-emit discipline as the
     * cometbft envelope above (DG-13 bijection). */
    if (msg->type == NODUS_T3_CC_APPR_REQ) {
        const nodus_t3_cc_appr_req_t *r = &msg->cc_appr_req;
        if ((r->e == NULL && r->e_len != 0) ||
            r->e_len > (size_t)NODUS_T3_CC_APPR_E_MAX)
            return -1;
    }
    cbor_encode_cstr(enc, "a");
    switch (msg->type) {
        /* R3 W4 — the case arms for every retired verb (PROPOSE, PREVOTE,
         * PRECOMMIT, COMMIT, VIEWCHG, NEWVIEW, FWD_REQ, FWD_RSP,
         * SYNC_REQ, SYNC_RSP, CHAIN_Q, CHAIN_R, GENESIS_REQ, GENESIS_RSP,
         * V2_BLOCK, V2_HEAD, V2_RANGE_REQ, V2_RANGE_RSP, VIEWOK,
         * VIEWOK_REQ) are DELETED with the closed consensus lane; none
         * of their enum values exists any more. R3 W4-CC retires
         * CC_VOTE_REQ/CC_VOTE_RSP the same way — CC_APPR_REQ/CC_APPR_RSP
         * below are their replacement. */
        case NODUS_T3_ROST_Q:    enc_rost_q_args(enc, &msg->rost_q);     break;
        case NODUS_T3_ROST_R:    enc_rost_r_args(enc, &msg->rost_r);     break;
        case NODUS_T3_IDENT:     enc_ident_args(enc, &msg->ident);       break;
        case NODUS_T3_V2_GBUNDLE_REQ:
            enc_w_v2_gbundle_q_args(enc, &msg->w_v2_gbundle_q); break;
        case NODUS_T3_V2_GBUNDLE_RSP:
            enc_w_v2_gbundle_r_args(enc, &msg->w_v2_gbundle_r); break;
        /* cometbft envelope (verbs 35-39; D-16 rev 5). */
        case NODUS_T3_CMT_STATE:
        case NODUS_T3_CMT_DATA:
        case NODUS_T3_CMT_VOTE:
        case NODUS_T3_CMT_VOTE_SET_BITS:
        case NODUS_T3_CMT_TXS:
            enc_w_cmt_args(enc, &msg->w_cmt);                 break;
        /* SYSTEM-governance approval collection (verbs 40-41; W4-CC). */
        case NODUS_T3_CC_APPR_REQ:
            enc_cc_appr_req_args(enc, &msg->cc_appr_req);     break;
        case NODUS_T3_CC_APPR_RSP:
            enc_cc_appr_rsp_args(enc, &msg->cc_appr_rsp);     break;
        default: return -1;
    }
    return 0;
}

/* ── Sign payload encode ─────────────────────────────────────────── */

static int enc_sign_payload(const nodus_t3_msg_t *msg,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    const char *method = nodus_t3_type_to_method(msg->type);
    if (!method) return -1;

    /* R3 W4 — the bootstrap sig domain prefix (H-3 mitigation) is
     * DELETED with the closed consensus lane: the 4 bootstrap types it
     * conditioned the sign input for are all gone, and `method` above is
     * already NULL for each of them, so this function never reached the
     * prefix branch for any live type. */
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, method);
    enc_wh(&enc, &msg->header);
    if (enc_args(&enc, msg) != 0) return -1;

    *out_len = cbor_encoder_len(&enc);
    return *out_len > 0 ? 0 : -1;
}

/* ── Public encode ───────────────────────────────────────────────── */

int nodus_t3_encode(const nodus_t3_msg_t *msg, const nodus_seckey_t *sk,
                     uint8_t *buf, size_t cap, size_t *out_len) {
    if (!msg || !sk || !buf || !out_len) return -1;

    /* Step 1: Encode sign payload into buf (temporary) */
    size_t sign_len;
    if (enc_sign_payload(msg, buf, cap, &sign_len) != 0)
        return -1;

    /* Step 2: Sign the payload (C2: T3_ENVELOPE domain) */
    nodus_sig_t wsig;
    if (nodus_sign_t3_envelope(&wsig, buf, sign_len, sk) != 0)
        return -1;

    /* Step 3: Encode full wire message (overwrites buf) */
    const char *method = nodus_t3_type_to_method(msg->type);
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 6);
    cbor_encode_cstr(&enc, "t");    cbor_encode_uint(&enc, msg->txn_id);
    cbor_encode_cstr(&enc, "y");    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");    cbor_encode_cstr(&enc, method);
    enc_wh(&enc, &msg->header);
    enc_args(&enc, msg);
    cbor_encode_cstr(&enc, "wsig"); cbor_encode_bstr(&enc, wsig.bytes,
                                                      NODUS_SIG_BYTES);

    *out_len = cbor_encoder_len(&enc);
    return *out_len > 0 ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════
 * DECODE
 * ══════════════════════════════════════════════════════════════════ */

/* ── Header decode ───────────────────────────────────────────────── */

static void dec_wh(cbor_decoder_t *dec, size_t count, nodus_t3_header_t *hdr) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "v")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) hdr->version = (uint8_t)val.uint_val;
        }
        else if (KEY_IS(key, "rnd")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) hdr->round = val.uint_val;
        }
        else if (KEY_IS(key, "vw")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) hdr->view = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "sid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(hdr->sender_id, val.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        }
        else if (KEY_IS(key, "ts")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) hdr->timestamp = val.uint_val;
        }
        else if (KEY_IS(key, "nc")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) hdr->nonce = val.uint_val;
        }
        else if (KEY_IS(key, "cid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(hdr->chain_id, val.bstr.ptr, 32);
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

/* ── Per-type args decode ────────────────────────────────────────── */

/* R3 W4 — dec_batch_tx_entry and every retired-verb decoder it fed
 * (dec_propose_args, dec_vote_args, dec_commit_field, dec_commit_args,
 * dec_viewchg_args) are DELETED with the closed consensus lane. See
 * nodus_t3_decode's own deletion note below for the full dispatch case
 * list. */

/* R3 W4 — dec_newview_args, dec_viewok_args, dec_viewok_q_args,
 * dec_fwd_req_args and dec_fwd_rsp_args are DELETED with the closed
 * consensus lane. See nodus_t3_decode's own deletion note below for the
 * full dispatch case list. */

static void dec_rost_q_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_rost_q_t *r) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "v")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->version = (uint32_t)val.uint_val;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_rost_r_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_rost_r_t *r) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "v")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->version = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "nw")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) {
                r->n_witnesses = (uint32_t)val.uint_val;
                if (r->n_witnesses > NODUS_T3_MAX_WITNESSES)
                    r->n_witnesses = NODUS_T3_MAX_WITNESSES;
            }
        }
        else if (KEY_IS(key, "ws")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                size_t max = arr.count < NODUS_T3_MAX_WITNESSES ?
                             arr.count : NODUS_T3_MAX_WITNESSES;
                for (size_t j = 0; j < max; j++) {
                    cbor_item_t em = cbor_decode_next(dec);
                    if (em.type != CBOR_ITEM_MAP) {
                        cbor_decode_skip(dec); continue;
                    }
                    nodus_t3_roster_entry_t *e = &r->witnesses[j];
                    for (size_t k = 0; k < em.count; k++) {
                        cbor_item_t ek = cbor_decode_next(dec);
                        if (ek.type != CBOR_ITEM_TSTR) {
                            cbor_decode_skip(dec); continue;
                        }
                        if (KEY_IS(ek, "wid")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_BSTR &&
                                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                                e->witness_id = val.bstr.ptr;
                        }
                        else if (KEY_IS(ek, "pk")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_BSTR &&
                                val.bstr.len == NODUS_PK_BYTES)
                                e->pubkey = val.bstr.ptr;
                        }
                        else if (KEY_IS(ek, "addr")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_TSTR) {
                                size_t clen = val.tstr.len < sizeof(e->address) - 1 ?
                                              val.tstr.len : sizeof(e->address) - 1;
                                memcpy(e->address, val.tstr.ptr, clen);
                                e->address[clen] = '\0';
                            }
                        }
                        else if (KEY_IS(ek, "je")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_UINT)
                                e->joined_epoch = val.uint_val;
                        }
                        else if (KEY_IS(ek, "act")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_BOOL)
                                e->active = val.bool_val;
                        }
                        else {
                            cbor_decode_skip(dec);
                        }
                    }
                }
                for (size_t j = max; j < arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else if (KEY_IS(key, "rsig")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                r->roster_sig = val.bstr.ptr;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_ident_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_ident_t *id) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "wid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                id->witness_id = val.bstr.ptr;
        }
        else if (KEY_IS(key, "pk")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_PK_BYTES)
                id->pubkey = val.bstr.ptr;
        }
        else if (KEY_IS(key, "addr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_TSTR) {
                size_t clen = val.tstr.len < sizeof(id->address) - 1 ?
                              val.tstr.len : sizeof(id->address) - 1;
                memcpy(id->address, val.tstr.ptr, clen);
                id->address[clen] = '\0';
            }
        }
        else if (KEY_IS(key, "bh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) {
                id->block_height = val.uint_val;
                id->has_block_height = true;
            }
        }
        else if (KEY_IS(key, "sr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_KEY_BYTES)
                memcpy(id->state_root, val.bstr.ptr, NODUS_KEY_BYTES);
        }
        else if (KEY_IS(key, "csg")) {
            /* 2026-05-02 audit C-1: heartbeat checksum signature.
             * Decoder accepts; verifier (handle_ident) checks the
             * Dilithium5 sig against the 152-byte preimage. Absent or
             * length-mismatch leaves checksum_sig zero → halt-recovery
             * path treats as unverified. */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_SIG_BYTES)
                memcpy(id->checksum_sig, val.bstr.ptr, NODUS_SIG_BYTES);
        }
        else if (KEY_IS(key, "vw")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                id->current_view = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "rn")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                id->roster_size = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "tsl")) {
            /* Phase 10 / Task 10.4 — sender wall clock for skew probe */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                id->ts_local = val.uint_val;
        }
        else if (KEY_IS(key, "nv")) {
            /* CC-OPS-002 / Q14 — sender nodus_version */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                id->nodus_version = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "ccs")) {
            /* CC-OPS-002 / Q14 — sender chain_config_schema */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                id->chain_config_schema = (uint32_t)val.uint_val;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

/* ── Sync decode ────────────────────────────────────────────────── */

/* R3 W4 — dec_sync_req_args, dec_sync_rsp_args (verbs 12-13),
 * dec_w_chain_q_args, dec_w_chain_r_args, dec_w_genesis_req_args and
 * dec_w_genesis_rsp_args (the PR 3 Yol B witness auto-bootstrap arg
 * decoders, verbs 16-19) are DELETED with the closed consensus lane.
 * See nodus_t3_decode's own deletion note below for the full dispatch
 * case list. */

/* ── w_cc_appr_req / w_cc_appr_rsp decoders (D-16 rev 7, W4-CC) ──────
 * Replace the retired verbs 14-15's loose decoders with the STRICT
 * exact-key-set discipline the newer verbs (w_cmt, gbundle) use: an
 * unrecognized key, a wrong-typed value, an oversize `e`, or a key the
 * `ok` value does not admit are all `dec->error = true`, never a
 * silently-skipped field. */

static void dec_cc_appr_req_args(cbor_decoder_t *dec, size_t count,
                                 nodus_t3_cc_appr_req_t *r) {
    bool seen_e = false;
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "e")) {
            if (seen_e) { dec->error = true; return; }
            seen_e = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR ||
                val.bstr.len > (size_t)NODUS_T3_CC_APPR_E_MAX) {
                dec->error = true;
                return;
            }
            r->e     = val.bstr.ptr;
            r->e_len = val.bstr.len;
        } else {
            dec->error = true; return;
        }
    }
    if (!seen_e) dec->error = true;   /* the key was missing */
}

/* `ok` gates which OTHER keys are legal: ok=true admits exactly
 * {ok,i,s,sh,ep} (r absent); ok=false admits exactly {ok,r} (i/s/sh/ep
 * absent). Every key is parsed once regardless of `ok`'s value (order on
 * the wire is not load-bearing), and the cross-check runs after the
 * loop — so a peer naming a key its own `ok` does not admit is refused,
 * not silently accepted. */
static void dec_cc_appr_rsp_args(cbor_decoder_t *dec, size_t count,
                                 nodus_t3_cc_appr_rsp_t *r) {
    bool seen_ok = false, ok_val = false;
    bool seen_i = false, seen_s = false, seen_sh = false;
    bool seen_ep = false, seen_r = false;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "ok")) {
            if (seen_ok) { dec->error = true; return; }
            seen_ok = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BOOL) { dec->error = true; return; }
            ok_val = val.bool_val;
            r->ok = ok_val;
        } else if (KEY_IS(key, "i")) {
            if (seen_i) { dec->error = true; return; }
            seen_i = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_UINT || val.uint_val > UINT16_MAX) {
                dec->error = true; return;
            }
            r->seat = (uint16_t)val.uint_val;
        } else if (KEY_IS(key, "s")) {
            if (seen_s) { dec->error = true; return; }
            seen_s = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != NODUS_SIG_BYTES) {
                dec->error = true; return;
            }
            memcpy(r->sig, val.bstr.ptr, NODUS_SIG_BYTES);
        } else if (KEY_IS(key, "sh")) {
            if (seen_sh) { dec->error = true; return; }
            seen_sh = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != 64) {
                dec->error = true; return;
            }
            memcpy(r->set_hash, val.bstr.ptr, 64);
        } else if (KEY_IS(key, "ep")) {
            if (seen_ep) { dec->error = true; return; }
            seen_ep = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_UINT) { dec->error = true; return; }
            r->epoch = val.uint_val;
        } else if (KEY_IS(key, "r")) {
            if (seen_r) { dec->error = true; return; }
            seen_r = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_TSTR ||
                val.tstr.len > sizeof(r->reason) - 1) {
                dec->error = true; return;
            }
            memcpy(r->reason, val.tstr.ptr, val.tstr.len);
            r->reason[val.tstr.len] = '\0';
        } else {
            dec->error = true; return;
        }
    }
    if (!seen_ok) { dec->error = true; return; }
    if (ok_val) {
        if (!seen_i || !seen_s || !seen_sh || !seen_ep || seen_r) {
            dec->error = true; return;
        }
    } else {
        if (!seen_r || seen_i || seen_s || seen_sh || seen_ep) {
            dec->error = true; return;
        }
    }
}

/* ── Public decode ───────────────────────────────────────────────── */

/* R3 W4 — the forward declarations for dec_w_v2_block_q_args,
 * dec_w_v2_head_args, dec_w_v2_range_q_args and dec_w_v2_range_r_args
 * (verbs 20-23) are DELETED with the closed consensus lane; their
 * bodies are deleted below, near their encoder siblings. */
static void dec_w_v2_gbundle_q_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_v2_gbundle_q_t *m);
static void dec_w_v2_gbundle_r_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_v2_gbundle_r_t *m);
/* cometbft envelope decoder (verbs 35-39; D-16 rev 5) — same arrangement.
 * `type` selects the class ceiling (35-38 vs 39, D-16 rev 5 "envelope
 * overhead on top"). */
static void dec_w_cmt_args(cbor_decoder_t *dec, size_t count,
                           nodus_t3_msg_type_t type, nodus_t3_w_cmt_t *m);

int nodus_t3_decode(const uint8_t *buf, size_t len, nodus_t3_msg_t *msg) {
    if (!buf || !msg) return -1;
    memset(msg, 0, sizeof(*msg));

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, len);

    cbor_item_t top = cbor_decode_next(&dec);
    if (top.type != CBOR_ITEM_MAP) return -1;
    size_t map_count = top.count;

    /* Save position for second pass (args decode) */
    size_t entries_start = dec.pos;

    /* D-22 rev 3 — set by the pass-1 walker if `a` contained a negative
     * integer anywhere, at any nesting depth. The admitted set is now
     * EMPTY: read below, unconditionally, once the verb is known. */
    bool a_negint = false;

    /* Pass 1: extract method, txn_id, header, wsig.
     *
     * Phase 9 / Task 9.3 — strict mode. The ONLY valid top-level keys
     * in a T3 envelope are { t, q, wh, wsig, a }. Any other key is a
     * protocol violation (or a pre-chain-wipe peer that should never
     * exist after deploy). Reject defensively with -1 so attackers can
     * not append shadow fields to a wsig-protected envelope hoping
     * the receiver silently skips. */
    for (size_t i = 0; i < map_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) return -1;

        if (KEY_IS(key, "t")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT)
                msg->txn_id = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "q")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_TSTR) {
                size_t clen = val.tstr.len < sizeof(msg->method) - 1 ?
                              val.tstr.len : sizeof(msg->method) - 1;
                memcpy(msg->method, val.tstr.ptr, clen);
                msg->method[clen] = '\0';
            }
        }
        else if (KEY_IS(key, "wh")) {
            cbor_item_t wh = cbor_decode_next(&dec);
            if (wh.type == CBOR_ITEM_MAP)
                dec_wh(&dec, wh.count, &msg->header);
            else
                return -1;
        }
        else if (KEY_IS(key, "wsig")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                msg->wsig = val.bstr.ptr;
        }
        else if (KEY_IS(key, "a")) {
            /* args body — dispatched in pass 2; step over it here.
             *
             * D-22 rev 3: this still uses the SIGNED walker, not the
             * shared cbor_decode_skip — the shared walker treats a major
             * type 1 item as an error, which would die here in pass 1
             * before reaching the method name and the wsig. The admitted
             * set for `a_negint` is now EMPTY for every verb (below), so
             * the walker's only remaining job is recording that a
             * negative was present so the gate can refuse it; it costs
             * nothing to keep the same primitive rather than reverting to
             * cbor_decode_skip for an identical outcome. The shared
             * walker and its ≈230 call sites are untouched. */
            cbor_decode_skip_signed(&dec, &a_negint);
        }
        else if (KEY_IS(key, "y")) {
            /* message-type marker emitted by encoder; consume value */
            cbor_decode_skip(&dec);
        }
        else {
            /* Phase 9 / Task 9.3 — unknown top-level key = reject */
            return -1;
        }
    }

    /* Determine type from method */
    msg->type = nodus_t3_method_to_type(msg->method);
    if (msg->type == 0) return -1;

    /* D-22 rev 3: the admitted set is EMPTY — a negative integer anywhere
     * inside `a` is refused for EVERY verb, including the new envelope
     * verbs 35-39 (whose only field is a byte string and never carries
     * one). This is the same refusal pass 1 gave before
     * cbor_decode_skip_signed existed, now stated unconditionally rather
     * than as a two-verb exception (the retired verbs 28/29 were the only
     * exception, and they are gone). */
    if (a_negint)
        return -1;

    /* Pass 2: decode args based on type */
    dec.pos = entries_start;
    dec.error = false;

    for (size_t i = 0; i < map_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        if (KEY_IS(key, "a")) {
            cbor_item_t args = cbor_decode_next(&dec);
            if (args.type != CBOR_ITEM_MAP) break;

            switch (msg->type) {
                /* R3 W4 — the case arms for every retired verb (PROPOSE,
                 * PREVOTE, PRECOMMIT, COMMIT, VIEWCHG, NEWVIEW, FWD_REQ,
                 * FWD_RSP, SYNC_REQ, SYNC_RSP, CHAIN_Q, CHAIN_R,
                 * GENESIS_REQ, GENESIS_RSP, V2_BLOCK, V2_HEAD,
                 * V2_RANGE_REQ, V2_RANGE_RSP, VIEWOK, VIEWOK_REQ) are
                 * DELETED with the closed consensus lane; none of their
                 * enum values exists any more — a decoded method can
                 * never resolve to one (nodus_t3_method_to_type returns 0
                 * for their method strings), so this switch can never see
                 * one. R3 W4-CC retires CC_VOTE_REQ/CC_VOTE_RSP the same
                 * way — CC_APPR_REQ/CC_APPR_RSP below are their
                 * replacement. */
                case NODUS_T3_ROST_Q:
                    dec_rost_q_args(&dec, args.count, &msg->rost_q);
                    break;
                case NODUS_T3_ROST_R:
                    dec_rost_r_args(&dec, args.count, &msg->rost_r);
                    break;
                case NODUS_T3_IDENT:
                    dec_ident_args(&dec, args.count, &msg->ident);
                    break;
                case NODUS_T3_V2_GBUNDLE_REQ:
                    dec_w_v2_gbundle_q_args(&dec, args.count,
                                            &msg->w_v2_gbundle_q);
                    break;
                case NODUS_T3_V2_GBUNDLE_RSP:
                    dec_w_v2_gbundle_r_args(&dec, args.count,
                                            &msg->w_v2_gbundle_r);
                    break;
                /* cometbft envelope (verbs 35-39; D-16 rev 5) — all five,
                 * so `default: break` (which would return 0 with a zeroed
                 * struct) can never be reached by one of these verbs. */
                case NODUS_T3_CMT_STATE:
                case NODUS_T3_CMT_DATA:
                case NODUS_T3_CMT_VOTE:
                case NODUS_T3_CMT_VOTE_SET_BITS:
                case NODUS_T3_CMT_TXS:
                    dec_w_cmt_args(&dec, args.count, msg->type, &msg->w_cmt);
                    break;
                /* SYSTEM-governance approval collection (verbs 40-41;
                 * D-16 rev 7, W4-CC) — both, so `default: break` can
                 * never be reached by one of these verbs either. */
                case NODUS_T3_CC_APPR_REQ:
                    dec_cc_appr_req_args(&dec, args.count, &msg->cc_appr_req);
                    break;
                case NODUS_T3_CC_APPR_RSP:
                    dec_cc_appr_rsp_args(&dec, args.count, &msg->cc_appr_rsp);
                    break;
                default:
                    break;
            }
            break; /* done — found "a" */
        }
        else {
            cbor_decode_skip(&dec);
        }
    }

    return dec.error ? -1 : 0;
}

/* R3 W4 — dec_w_v2_block_q_args, dec_w_v2_head_args,
 * dec_w_v2_range_q_args and dec_w_v2_range_r_args (the Ledger V2
 * old-lane sync arg decoders, verbs 20-23) are DELETED with the closed
 * consensus lane. The surviving genesis-bundle decoders (verbs 24-25)
 * follow. */

static void dec_w_v2_gbundle_q_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_v2_gbundle_q_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "p")) {
            /* D-24 rev 4 (1): the pin is EXACTLY the 32-byte chain id —
             * unlike most fixed-width fields in this file, a wrong length
             * here is a HARD DECODE ERROR, not a silently-zeroed field.
             * The pin is the whole of a joiner's trust decision
             * (nodus_witness_v2_join.c / D-24); leaving it zero-filled on
             * a malformed wire value would let a 31- or 33-byte `p` decode
             * "successfully" into an all-zero pin that then fails the
             * comparison downstream for the wrong reason — a decode bug
             * disguised as a routine mismatch. */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != 32) {
                dec->error = true;
                return;
            }
            memcpy(m->pin, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "o")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->offset = val.uint_val;
        } else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_w_v2_gbundle_r_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_v2_gbundle_r_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "p")) {
            /* D-24 rev 4 (1) — see dec_w_v2_gbundle_q_args's "p" branch: a
             * wrong-length pin is a hard decode error here too. */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != 32) {
                dec->error = true;
                return;
            }
            memcpy(m->pin, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "t")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->total = val.uint_val;
        } else if (KEY_IS(key, "o")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->offset = val.uint_val;
        } else if (KEY_IS(key, "d")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR) {
                if (val.bstr.len > NODUS_T3_V2_GBUNDLE_CHUNK_MAX) {
                    dec->error = true;
                    return;
                }
                m->chunk = val.bstr.ptr;
                m->chunk_len = (uint32_t)val.bstr.len;
            }
        } else {
            cbor_decode_skip(dec);
        }
    }
}

/* ── cometbft envelope arg decoder (verbs 35-39; D-16 rev 5) ─────────
 *
 * STRICTER THAN THE LEGACY dec_*_args, AND THAT IS THE SPECIFICATION —
 * the same discipline the retired verbs 28-34 introduced: unlike the
 * legacy decoders that skip an unrecognised key and leave a missing one
 * at zero, this rejects on
 *
 *   - a non-text key, an unknown key, or "m" seen twice;
 *   - a value that is not a byte string;
 *   - a byte string above the verb's class ceiling (35-38 the consensus
 *     reactor's, 39 the mempool's — D-16 rev 5 "envelope overhead on
 *     top");
 *   - a key set that is incomplete when the map ends (missing "m").
 *
 * That exactness is what keeps the codec bijective — encode(decode(b))
 * == b and decode(encode(x)) == x (DG-13). `m` is ZERO-COPY: it points
 * into the decode buffer and is valid only while that buffer is alive,
 * the same idiom as w_v2_range_r's `frames` and dec_w_v2_gbundle_r_args's
 * `chunk` above. The pass-2 cap follows dec_w_v2_gbundle_r_args's
 * `NODUS_T3_V2_GBUNDLE_CHUNK_MAX` idiom (:2500-2503, this file). */
static void dec_w_cmt_args(cbor_decoder_t *dec, size_t count,
                           nodus_t3_msg_type_t type, nodus_t3_w_cmt_t *m) {
    size_t m_cap = (type == NODUS_T3_CMT_TXS) ? (size_t)NODUS_T3_CMT_TXS_M_MAX
                                              : (size_t)NODUS_T3_CMT_CONS_M_MAX;
    bool seen_m = false;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "m")) {
            if (seen_m) { dec->error = true; return; }
            seen_m = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len > m_cap) {
                dec->error = true;
                return;
            }
            m->m     = val.bstr.ptr;
            m->m_len = val.bstr.len;
        } else {
            dec->error = true; return;
        }
    }
    if (!seen_m) dec->error = true;   /* the key was missing */
}

/* ── Public verify ───────────────────────────────────────────────── */

int nodus_t3_verify(const nodus_t3_msg_t *msg, const nodus_pubkey_t *pk) {
    if (!msg || !pk || !msg->wsig) return -1;

    /* Heap-allocate the sign buffer at NODUS_W_MAX_SYNC_RSP_SIZE (1 MB)
     * for every non-envelope verb that survives R3 W4 (9-11 roster/ident,
     * 14-15 chain-config vote, 24-25 genesis bundle): the two senders
     * that can exceed the 128 KB NODUS_T3_MAX_MSG_SIZE — the genesis
     * bundle response (nodus_witness_v2_sync2.c handle_gbundle_q) and
     * the joiner's bundle request (nodus_witness_v2_join.c) — encode
     * into a heap buffer of the SAME size, so encode and verify stay
     * symmetric. The sync_rsp / COMMIT / PROPOSE messages this bound was
     * originally sized for were deleted with the legacy lane (R3 W4-D).
     *
     * D-16 rev 5: the cometbft envelope verbs 35-39 instead take their
     * PER-CLASS bound (35-38 the consensus reactor's, 39 the larger
     * mempool one), so a maximal mempool Txs message can be verified
     * while a vote-set-bits reply never reserves more than its class.
     * D-16 rev 7 (W4-CC): verbs 40-41 take their own per-class bound the
     * same way — verb 40's ceiling (DNA_ENV_MAX_TOTAL_LEN + overhead) is
     * LARGER than NODUS_W_MAX_SYNC_RSP_SIZE, so routing it through the
     * legacy branch would under-allocate the sign buffer for a maximal
     * pre-auth envelope. The legacy branch is written as the literal it
     * always was, not routed through nodus_t3_max_msg_size, so "legacy
     * allocation unchanged" is visible in this function rather than
     * inferred from another one. This is the wire-walker's
     * cross-component pair 4: send (enc_sign_payload's caller) and this
     * verify are symmetric only because both read the SAME class for a
     * given type — keep that property when adding a verb here. */
    bool is_per_class = (msg->type >= NODUS_T3_CMT_STATE &&
                        msg->type <= NODUS_T3_CMT_TXS) ||
                       msg->type == NODUS_T3_CC_APPR_REQ ||
                       msg->type == NODUS_T3_CC_APPR_RSP;
    size_t sign_cap = is_per_class ? nodus_t3_max_msg_size(msg->type)
                                   : (size_t)NODUS_W_MAX_SYNC_RSP_SIZE;
    if (sign_cap == 0) return -1;

    uint8_t *sign_buf = malloc(sign_cap);
    if (!sign_buf) return -1;

    size_t sign_len = 0;
    if (enc_sign_payload(msg, sign_buf, sign_cap, &sign_len) != 0) {
        free(sign_buf);
        return -1;
    }

    nodus_sig_t sig;
    memcpy(sig.bytes, msg->wsig, NODUS_SIG_BYTES);
    /* C2: T3_ENVELOPE domain verify */
    int result = nodus_verify_t3_envelope(&sig, sign_buf, sign_len, pk);
    free(sign_buf);
    return result;
}
