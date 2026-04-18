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
        case NODUS_T3_PROPOSE:   return "w_propose";
        case NODUS_T3_PREVOTE:   return "w_prevote";
        case NODUS_T3_PRECOMMIT: return "w_precommit";
        case NODUS_T3_COMMIT:    return "w_commit";
        case NODUS_T3_VIEWCHG:   return "w_viewchg";
        case NODUS_T3_NEWVIEW:   return "w_newview";
        case NODUS_T3_FWD_REQ:   return "w_fwd_req";
        case NODUS_T3_FWD_RSP:   return "w_fwd_rsp";
        case NODUS_T3_ROST_Q:    return "w_rost_q";
        case NODUS_T3_ROST_R:    return "w_rost_r";
        case NODUS_T3_IDENT:     return "w_ident";
        case NODUS_T3_SYNC_REQ:  return "w_sync_req";
        case NODUS_T3_SYNC_RSP:  return "w_sync_rsp";
        default:                 return NULL;
    }
}

nodus_t3_msg_type_t nodus_t3_method_to_type(const char *method) {
    if (!method) return 0;
    if (strcmp(method, "w_propose") == 0)    return NODUS_T3_PROPOSE;
    if (strcmp(method, "w_prevote") == 0)    return NODUS_T3_PREVOTE;
    if (strcmp(method, "w_precommit") == 0)  return NODUS_T3_PRECOMMIT;
    if (strcmp(method, "w_commit") == 0)     return NODUS_T3_COMMIT;
    if (strcmp(method, "w_viewchg") == 0)    return NODUS_T3_VIEWCHG;
    if (strcmp(method, "w_newview") == 0)    return NODUS_T3_NEWVIEW;
    if (strcmp(method, "w_fwd_req") == 0)    return NODUS_T3_FWD_REQ;
    if (strcmp(method, "w_fwd_rsp") == 0)    return NODUS_T3_FWD_RSP;
    if (strcmp(method, "w_rost_q") == 0)     return NODUS_T3_ROST_Q;
    if (strcmp(method, "w_rost_r") == 0)     return NODUS_T3_ROST_R;
    if (strcmp(method, "w_ident") == 0)      return NODUS_T3_IDENT;
    if (strcmp(method, "w_sync_req") == 0)  return NODUS_T3_SYNC_REQ;
    if (strcmp(method, "w_sync_rsp") == 0)  return NODUS_T3_SYNC_RSP;
    return 0;
}

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

/* Encode a single batch TX entry into CBOR (shared by propose + commit) */
static void enc_batch_tx(cbor_encoder_t *enc, const nodus_t3_batch_tx_t *tx) {
    cbor_encode_map(enc, 8);
    cbor_encode_cstr(enc, "txh");  cbor_encode_bstr(enc, tx->tx_hash,
                                                     NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "nlc");  cbor_encode_uint(enc, tx->nullifier_count);
    cbor_encode_cstr(enc, "nls");
    cbor_encode_array(enc, tx->nullifier_count);
    for (int i = 0; i < tx->nullifier_count; i++)
        cbor_encode_bstr(enc, tx->nullifiers[i], NODUS_T3_NULLIFIER_LEN);
    cbor_encode_cstr(enc, "tty");  cbor_encode_uint(enc, tx->tx_type);
    cbor_encode_cstr(enc, "txd");  cbor_encode_bstr(enc, tx->tx_data, tx->tx_len);
    cbor_encode_cstr(enc, "pk");   cbor_encode_bstr(enc, tx->client_pubkey,
                                                     NODUS_PK_BYTES);
    cbor_encode_cstr(enc, "csig"); cbor_encode_bstr(enc, tx->client_sig,
                                                     NODUS_SIG_BYTES);
    cbor_encode_cstr(enc, "fee");  cbor_encode_uint(enc, tx->fee);
}

static void enc_propose_args(cbor_encoder_t *enc, const nodus_t3_propose_t *p) {
    /* Phase 9 / Task 9.4 — wire key bh -> tr, field block_hash -> tx_root. */
    cbor_encode_map(enc, 2);
    cbor_encode_cstr(enc, "tr");
    cbor_encode_bstr(enc, p->tx_root, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "btx");
    cbor_encode_array(enc, (size_t)p->batch_count);
    for (int i = 0; i < p->batch_count; i++)
        enc_batch_tx(enc, &p->batch_txs[i]);
}

static void enc_vote_args(cbor_encoder_t *enc, const nodus_t3_vote_t *v) {
    /* Phase 9 / Task 9.5 — wire key txh -> vh; field is vote_target.
     * Phase 7.5 / Task 7.5.2 — cs cert_sig. */
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "vh");  cbor_encode_bstr(enc, v->vote_target,
                                                    NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "vt");  cbor_encode_uint(enc, v->vote);
    cbor_encode_cstr(enc, "rsn"); cbor_encode_cstr(enc, v->reason);
    cbor_encode_cstr(enc, "cs");  cbor_encode_bstr(enc, v->cert_sig,
                                                    NODUS_SIG_BYTES);
}

/* Encode commit cert array (shared between batch and legacy) */
static void enc_commit_certs(cbor_encoder_t *enc, const nodus_t3_commit_t *c) {
    cbor_encode_cstr(enc, "pts");  cbor_encode_uint(enc, c->proposal_timestamp);
    cbor_encode_cstr(enc, "pid");  cbor_encode_bstr(enc, c->proposer_id,
                                                     NODUS_T3_WITNESS_ID_LEN);
    cbor_encode_cstr(enc, "npc");  cbor_encode_uint(enc, c->n_precommits);
    cbor_encode_cstr(enc, "sr");  cbor_encode_bstr(enc, c->state_root,
                                                     NODUS_KEY_BYTES);
    cbor_encode_cstr(enc, "cer");
    cbor_encode_array(enc, c->n_precommits);
    for (uint32_t i = 0; i < c->n_precommits; i++) {
        cbor_encode_map(enc, 2);
        cbor_encode_cstr(enc, "vid");
        cbor_encode_bstr(enc, c->certs[i].voter_id, NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(enc, "sig");
        cbor_encode_bstr(enc, c->certs[i].signature, NODUS_SIG_BYTES);
    }
}

static void enc_commit_args(cbor_encoder_t *enc, const nodus_t3_commit_t *c) {
    /* Phase 9 / Task 9.4 — wire key bh -> tr, field block_hash -> tx_root. */
    cbor_encode_map(enc, 7);
    cbor_encode_cstr(enc, "tr");
    cbor_encode_bstr(enc, c->tx_root, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "btx");
    cbor_encode_array(enc, (size_t)c->batch_count);
    for (int i = 0; i < c->batch_count; i++)
        enc_batch_tx(enc, &c->batch_txs[i]);
    enc_commit_certs(enc, c);
}

static void enc_viewchg_args(cbor_encoder_t *enc, const nodus_t3_viewchg_t *v) {
    cbor_encode_map(enc, 2);
    cbor_encode_cstr(enc, "nv");  cbor_encode_uint(enc, v->new_view);
    cbor_encode_cstr(enc, "lcr"); cbor_encode_uint(enc, v->last_committed_round);
}

static void enc_newview_args(cbor_encoder_t *enc, const nodus_t3_newview_t *n) {
    cbor_encode_map(enc, 2);
    cbor_encode_cstr(enc, "nv"); cbor_encode_uint(enc, n->new_view);
    cbor_encode_cstr(enc, "np"); cbor_encode_uint(enc, n->n_proofs);
}

static void enc_fwd_req_args(cbor_encoder_t *enc, const nodus_t3_fwd_req_t *f) {
    cbor_encode_map(enc, 6);
    cbor_encode_cstr(enc, "txh");  cbor_encode_bstr(enc, f->tx_hash,
                                                     NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "txd");  cbor_encode_bstr(enc, f->tx_data, f->tx_len);
    cbor_encode_cstr(enc, "pk");   cbor_encode_bstr(enc, f->client_pubkey,
                                                     NODUS_PK_BYTES);
    cbor_encode_cstr(enc, "csig"); cbor_encode_bstr(enc, f->client_sig,
                                                     NODUS_SIG_BYTES);
    cbor_encode_cstr(enc, "fee");  cbor_encode_uint(enc, f->fee);
    cbor_encode_cstr(enc, "fid");  cbor_encode_bstr(enc, f->forwarder_id,
                                                     NODUS_T3_WITNESS_ID_LEN);
}

static void enc_fwd_rsp_args(cbor_encoder_t *enc, const nodus_t3_fwd_rsp_t *f) {
    cbor_encode_map(enc, 7);
    cbor_encode_cstr(enc, "st");  cbor_encode_uint(enc, f->status);
    cbor_encode_cstr(enc, "txh"); cbor_encode_bstr(enc, f->tx_hash,
                                                    NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "bnr"); cbor_encode_uint(enc, f->block_height);
    cbor_encode_cstr(enc, "ti");  cbor_encode_uint(enc, (uint64_t)f->tx_index);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, f->chain_id, 32);
    cbor_encode_cstr(enc, "wc");  cbor_encode_uint(enc, f->witness_count);
    cbor_encode_cstr(enc, "ws");
    cbor_encode_array(enc, f->witness_count);
    for (uint32_t i = 0; i < f->witness_count; i++) {
        const nodus_t3_witness_sig_t *w = &f->witnesses[i];
        cbor_encode_map(enc, 4);
        cbor_encode_cstr(enc, "wid"); cbor_encode_bstr(enc, w->witness_id,
                                                        NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(enc, "sig"); cbor_encode_bstr(enc, w->signature,
                                                        NODUS_SIG_BYTES);
        cbor_encode_cstr(enc, "pk");  cbor_encode_bstr(enc, w->pubkey,
                                                        NODUS_PK_BYTES);
        cbor_encode_cstr(enc, "ts");  cbor_encode_uint(enc, w->timestamp);
    }
}

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

static void enc_ident_args(cbor_encoder_t *enc, const nodus_t3_ident_t *id) {
    /* Map count: wid, pk, addr, tsl, nv, ccs = 6 base;
     * +4 for bh, sr, vw, rn when has_block_height. CC-OPS-002 / Q14
     * adds nv + ccs unconditionally so legacy-peer detection works even
     * before a peer starts reporting block_height. */
    cbor_encode_map(enc, id->has_block_height ? 10 : 6);
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
    }
}

static void enc_sync_req_args(cbor_encoder_t *enc, const nodus_t3_sync_req_t *r) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "h"); cbor_encode_uint(enc, r->height);
}

static void enc_sync_rsp_args(cbor_encoder_t *enc, const nodus_t3_sync_rsp_t *r) {
    /* Phase 11 / Task 11.2 — multi-tx sync_rsp encoder.
     * Map shape (found): f, h, ts, pid, ph, tr, btx, cer = 8 keys. */
    cbor_encode_map(enc, r->found ? 8 : 2);
    cbor_encode_cstr(enc, "f");  cbor_encode_bool(enc, r->found);
    cbor_encode_cstr(enc, "h");  cbor_encode_uint(enc, r->height);
    if (!r->found) return;
    cbor_encode_cstr(enc, "ts");  cbor_encode_uint(enc, r->timestamp);
    cbor_encode_cstr(enc, "pid"); cbor_encode_bstr(enc, r->proposer_id,
                                                    NODUS_T3_WITNESS_ID_LEN);
    cbor_encode_cstr(enc, "ph");  cbor_encode_bstr(enc, r->prev_hash,
                                                    NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "tr");  cbor_encode_bstr(enc, r->tx_root,
                                                    NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "btx");
    cbor_encode_array(enc, (size_t)r->tx_count);
    for (int i = 0; i < r->tx_count; i++)
        enc_batch_tx(enc, &r->batch_txs[i]);
    cbor_encode_cstr(enc, "cer");
    cbor_encode_array(enc, r->cert_count);
    for (uint32_t i = 0; i < r->cert_count; i++) {
        cbor_encode_map(enc, 2);
        cbor_encode_cstr(enc, "vid");
        cbor_encode_bstr(enc, r->certs[i].voter_id, NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(enc, "sig");
        cbor_encode_bstr(enc, r->certs[i].signature, NODUS_SIG_BYTES);
    }
}

/* ── Args dispatch ───────────────────────────────────────────────── */

static int enc_args(cbor_encoder_t *enc, const nodus_t3_msg_t *msg) {
    cbor_encode_cstr(enc, "a");
    switch (msg->type) {
        case NODUS_T3_PROPOSE:   enc_propose_args(enc, &msg->propose);   break;
        case NODUS_T3_PREVOTE:
        case NODUS_T3_PRECOMMIT: enc_vote_args(enc, &msg->vote);         break;
        case NODUS_T3_COMMIT:    enc_commit_args(enc, &msg->commit);     break;
        case NODUS_T3_VIEWCHG:   enc_viewchg_args(enc, &msg->viewchg);   break;
        case NODUS_T3_NEWVIEW:   enc_newview_args(enc, &msg->newview);   break;
        case NODUS_T3_FWD_REQ:   enc_fwd_req_args(enc, &msg->fwd_req);   break;
        case NODUS_T3_FWD_RSP:   enc_fwd_rsp_args(enc, &msg->fwd_rsp);   break;
        case NODUS_T3_ROST_Q:    enc_rost_q_args(enc, &msg->rost_q);     break;
        case NODUS_T3_ROST_R:    enc_rost_r_args(enc, &msg->rost_r);     break;
        case NODUS_T3_IDENT:     enc_ident_args(enc, &msg->ident);       break;
        case NODUS_T3_SYNC_REQ:  enc_sync_req_args(enc, &msg->sync_req); break;
        case NODUS_T3_SYNC_RSP:  enc_sync_rsp_args(enc, &msg->sync_rsp); break;
        default: return -1;
    }
    return 0;
}

/* ── Sign payload encode ─────────────────────────────────────────── */

static int enc_sign_payload(const nodus_t3_msg_t *msg,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    const char *method = nodus_t3_type_to_method(msg->type);
    if (!method) return -1;

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

    /* Step 2: Sign the payload */
    nodus_sig_t wsig;
    if (nodus_sign(&wsig, buf, sign_len, sk) != 0)
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

/* Decode a single batch TX entry from CBOR map */
static void dec_batch_tx_entry(cbor_decoder_t *dec, size_t count,
                                nodus_t3_batch_tx_t *tx) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "txh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(tx->tx_hash, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "nlc")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) {
                tx->nullifier_count = (uint8_t)val.uint_val;
                if (tx->nullifier_count > NODUS_T3_MAX_TX_INPUTS)
                    tx->nullifier_count = NODUS_T3_MAX_TX_INPUTS;
            }
        }
        else if (KEY_IS(key, "nls")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                size_t max = arr.count < NODUS_T3_MAX_TX_INPUTS ?
                             arr.count : NODUS_T3_MAX_TX_INPUTS;
                for (size_t j = 0; j < max; j++) {
                    cbor_item_t val = cbor_decode_next(dec);
                    if (val.type == CBOR_ITEM_BSTR &&
                        val.bstr.len == NODUS_T3_NULLIFIER_LEN)
                        tx->nullifiers[j] = val.bstr.ptr;
                }
                for (size_t j = max; j < arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else if (KEY_IS(key, "tty")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) tx->tx_type = (uint8_t)val.uint_val;
        }
        else if (KEY_IS(key, "txd")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len <= NODUS_T3_MAX_TX_SIZE) {
                tx->tx_data = val.bstr.ptr;
                tx->tx_len = (uint32_t)val.bstr.len;
            }
        }
        else if (KEY_IS(key, "pk")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_PK_BYTES)
                tx->client_pubkey = val.bstr.ptr;
        }
        else if (KEY_IS(key, "csig")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                tx->client_sig = val.bstr.ptr;
        }
        else if (KEY_IS(key, "fee")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) tx->fee = val.uint_val;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_propose_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_propose_t *p) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        /* Batch mode detection: "btx" key */
        if (KEY_IS(key, "btx")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                int max = (int)arr.count;
                if (max > NODUS_W_MAX_BLOCK_TXS) max = NODUS_W_MAX_BLOCK_TXS;
                p->batch_count = max;
                for (int j = 0; j < max; j++) {
                    cbor_item_t entry = cbor_decode_next(dec);
                    if (entry.type == CBOR_ITEM_MAP)
                        dec_batch_tx_entry(dec, entry.count, &p->batch_txs[j]);
                }
                /* Skip excess entries */
                for (int j = max; j < (int)arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else if (KEY_IS(key, "tr")) {
            /* Phase 9 / Task 9.4 — wire key bh -> tr */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(p->tx_root, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        /* Phase 9 / Task 9.2 — legacy single-TX propose keys
         * (txh/nlc/nls/tty/txd/pk/csig/fee) decoder branches deleted. */
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_vote_args(cbor_decoder_t *dec, size_t count,
                           nodus_t3_vote_t *v) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "vh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(v->vote_target, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "vt")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) v->vote = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "rsn")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_TSTR) {
                size_t clen = val.tstr.len < sizeof(v->reason) - 1 ?
                              val.tstr.len : sizeof(v->reason) - 1;
                memcpy(v->reason, val.tstr.ptr, clen);
                v->reason[clen] = '\0';
            }
        }
        else if (KEY_IS(key, "cs")) {
            /* Phase 7.5 / Task 7.5.2 — cert preimage signature */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_SIG_BYTES)
                memcpy(v->cert_sig, val.bstr.ptr, NODUS_SIG_BYTES);
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

/* Helper: decode commit-specific fields (certs, timestamps) — shared */
static void dec_commit_field(cbor_decoder_t *dec, const cbor_item_t *key,
                               nodus_t3_commit_t *c) {
    if (KEY_IS(*key, "pts")) {
        cbor_item_t val = cbor_decode_next(dec);
        if (val.type == CBOR_ITEM_UINT) c->proposal_timestamp = val.uint_val;
    }
    else if (KEY_IS(*key, "pid")) {
        cbor_item_t val = cbor_decode_next(dec);
        if (val.type == CBOR_ITEM_BSTR &&
            val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
            memcpy(c->proposer_id, val.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
    }
    else if (KEY_IS(*key, "npc")) {
        cbor_item_t val = cbor_decode_next(dec);
        if (val.type == CBOR_ITEM_UINT) c->n_precommits = (uint32_t)val.uint_val;
    }
    else if (KEY_IS(*key, "sr")) {
        cbor_item_t val = cbor_decode_next(dec);
        if (val.type == CBOR_ITEM_BSTR &&
            val.bstr.len == NODUS_KEY_BYTES)
            memcpy(c->state_root, val.bstr.ptr, NODUS_KEY_BYTES);
    }
    else if (KEY_IS(*key, "cer")) {
        cbor_item_t arr = cbor_decode_next(dec);
        if (arr.type == CBOR_ITEM_ARRAY) {
            size_t max = arr.count < NODUS_T3_MAX_WITNESSES ?
                         arr.count : NODUS_T3_MAX_WITNESSES;
            for (size_t j = 0; j < max; j++) {
                cbor_item_t m = cbor_decode_next(dec);
                if (m.type != CBOR_ITEM_MAP) { cbor_decode_skip(dec); continue; }
                for (size_t k = 0; k < m.count; k++) {
                    cbor_item_t mk = cbor_decode_next(dec);
                    if (mk.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
                    if (KEY_IS(mk, "vid")) {
                        cbor_item_t v = cbor_decode_next(dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                            memcpy(c->certs[j].voter_id, v.bstr.ptr,
                                   NODUS_T3_WITNESS_ID_LEN);
                    } else if (KEY_IS(mk, "sig")) {
                        cbor_item_t v = cbor_decode_next(dec);
                        if (v.type == CBOR_ITEM_BSTR &&
                            v.bstr.len == NODUS_SIG_BYTES)
                            memcpy(c->certs[j].signature, v.bstr.ptr,
                                   NODUS_SIG_BYTES);
                    } else {
                        cbor_decode_skip(dec);
                    }
                }
            }
            for (size_t j = max; j < arr.count; j++)
                cbor_decode_skip(dec);
        }
    }
    else {
        cbor_decode_skip(dec);
    }
}

static void dec_commit_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_commit_t *c) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        /* Batch mode detection */
        if (KEY_IS(key, "btx")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                int max = (int)arr.count;
                if (max > NODUS_W_MAX_BLOCK_TXS) max = NODUS_W_MAX_BLOCK_TXS;
                c->batch_count = max;
                for (int j = 0; j < max; j++) {
                    cbor_item_t entry = cbor_decode_next(dec);
                    if (entry.type == CBOR_ITEM_MAP)
                        dec_batch_tx_entry(dec, entry.count, &c->batch_txs[j]);
                }
                for (int j = max; j < (int)arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else if (KEY_IS(key, "tr")) {
            /* Phase 9 / Task 9.4 — wire key bh -> tr */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(c->tx_root, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        /* Phase 9 / Task 9.2 — legacy single-TX commit keys
         * (txh/nlc/nls/tty/txd) decoder branches deleted. Falls through
         * to commit-specific fields (certs / timestamps) or skip. */
        else {
            dec_commit_field(dec, &key, c);
        }
    }
}

static void dec_viewchg_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_viewchg_t *v) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "nv")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) v->new_view = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "lcr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                v->last_committed_round = val.uint_val;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_newview_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_newview_t *n) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "nv")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) n->new_view = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "np")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) n->n_proofs = (uint32_t)val.uint_val;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_fwd_req_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_fwd_req_t *f) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "txh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(f->tx_hash, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "txd")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len <= NODUS_T3_MAX_TX_SIZE) {
                f->tx_data = val.bstr.ptr;
                f->tx_len = (uint32_t)val.bstr.len;
            }
        }
        else if (KEY_IS(key, "pk")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_PK_BYTES)
                f->client_pubkey = val.bstr.ptr;
        }
        else if (KEY_IS(key, "csig")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                f->client_sig = val.bstr.ptr;
        }
        else if (KEY_IS(key, "fee")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) f->fee = val.uint_val;
        }
        else if (KEY_IS(key, "fid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(f->forwarder_id, val.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_fwd_rsp_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_fwd_rsp_t *f) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "st")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) f->status = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "txh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(f->tx_hash, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "bnr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) f->block_height = val.uint_val;
        }
        else if (KEY_IS(key, "ti")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                f->tx_index = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "cid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(f->chain_id, val.bstr.ptr, 32);
        }
        else if (KEY_IS(key, "wc")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) {
                f->witness_count = (uint32_t)val.uint_val;
                if (f->witness_count > NODUS_T3_MAX_TX_WITNESSES)
                    f->witness_count = NODUS_T3_MAX_TX_WITNESSES;
            }
        }
        else if (KEY_IS(key, "ws")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                size_t max = arr.count < NODUS_T3_MAX_TX_WITNESSES ?
                             arr.count : NODUS_T3_MAX_TX_WITNESSES;
                for (size_t j = 0; j < max; j++) {
                    cbor_item_t em = cbor_decode_next(dec);
                    if (em.type != CBOR_ITEM_MAP) {
                        cbor_decode_skip(dec); continue;
                    }
                    nodus_t3_witness_sig_t *w = &f->witnesses[j];
                    for (size_t k = 0; k < em.count; k++) {
                        cbor_item_t ek = cbor_decode_next(dec);
                        if (ek.type != CBOR_ITEM_TSTR) {
                            cbor_decode_skip(dec); continue;
                        }
                        if (KEY_IS(ek, "wid")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_BSTR &&
                                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                                w->witness_id = val.bstr.ptr;
                        }
                        else if (KEY_IS(ek, "sig")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_BSTR &&
                                val.bstr.len == NODUS_SIG_BYTES)
                                w->signature = val.bstr.ptr;
                        }
                        else if (KEY_IS(ek, "pk")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_BSTR &&
                                val.bstr.len == NODUS_PK_BYTES)
                                w->pubkey = val.bstr.ptr;
                        }
                        else if (KEY_IS(ek, "ts")) {
                            cbor_item_t val = cbor_decode_next(dec);
                            if (val.type == CBOR_ITEM_UINT)
                                w->timestamp = val.uint_val;
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
        else {
            cbor_decode_skip(dec);
        }
    }
}

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

static void dec_sync_req_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_sync_req_t *r) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "h")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->height = val.uint_val;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_sync_rsp_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_sync_rsp_t *r) {
    /* Phase 11 / Task 11.2 — multi-tx sync_rsp decoder. */
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "f")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BOOL) r->found = val.bool_val;
        }
        else if (KEY_IS(key, "h")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->height = val.uint_val;
        }
        else if (KEY_IS(key, "ts")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->timestamp = val.uint_val;
        }
        else if (KEY_IS(key, "pid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(r->proposer_id, val.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        }
        else if (KEY_IS(key, "ph")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(r->prev_hash, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "tr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(r->tx_root, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "btx")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                int max = (int)arr.count;
                /* Phase 11 / Task 11.3 — three-tier guard, top tier */
                if (max > NODUS_W_MAX_BLOCK_TXS) max = NODUS_W_MAX_BLOCK_TXS;
                r->tx_count = max;
                for (int j = 0; j < max; j++) {
                    cbor_item_t entry = cbor_decode_next(dec);
                    if (entry.type == CBOR_ITEM_MAP)
                        dec_batch_tx_entry(dec, entry.count, &r->batch_txs[j]);
                }
                for (int j = max; j < (int)arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else if (KEY_IS(key, "cer")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                size_t max = arr.count < NODUS_T3_MAX_WITNESSES ?
                             arr.count : NODUS_T3_MAX_WITNESSES;
                r->cert_count = (uint32_t)max;
                for (size_t j = 0; j < max; j++) {
                    cbor_item_t m = cbor_decode_next(dec);
                    if (m.type != CBOR_ITEM_MAP) { cbor_decode_skip(dec); continue; }
                    for (size_t k = 0; k < m.count; k++) {
                        cbor_item_t mk = cbor_decode_next(dec);
                        if (mk.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
                        if (KEY_IS(mk, "vid")) {
                            cbor_item_t v = cbor_decode_next(dec);
                            if (v.type == CBOR_ITEM_BSTR &&
                                v.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                                memcpy(r->certs[j].voter_id, v.bstr.ptr,
                                       NODUS_T3_WITNESS_ID_LEN);
                        } else if (KEY_IS(mk, "sig")) {
                            cbor_item_t v = cbor_decode_next(dec);
                            if (v.type == CBOR_ITEM_BSTR &&
                                v.bstr.len == NODUS_SIG_BYTES)
                                memcpy(r->certs[j].signature, v.bstr.ptr,
                                       NODUS_SIG_BYTES);
                        } else {
                            cbor_decode_skip(dec);
                        }
                    }
                }
                for (size_t j = max; j < arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

/* ── Public decode ───────────────────────────────────────────────── */

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
            /* args body — dispatched in pass 2; skip here */
            cbor_decode_skip(&dec);
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
                case NODUS_T3_PROPOSE:
                    dec_propose_args(&dec, args.count, &msg->propose);
                    break;
                case NODUS_T3_PREVOTE:
                case NODUS_T3_PRECOMMIT:
                    dec_vote_args(&dec, args.count, &msg->vote);
                    break;
                case NODUS_T3_COMMIT:
                    dec_commit_args(&dec, args.count, &msg->commit);
                    break;
                case NODUS_T3_VIEWCHG:
                    dec_viewchg_args(&dec, args.count, &msg->viewchg);
                    break;
                case NODUS_T3_NEWVIEW:
                    dec_newview_args(&dec, args.count, &msg->newview);
                    break;
                case NODUS_T3_FWD_REQ:
                    dec_fwd_req_args(&dec, args.count, &msg->fwd_req);
                    break;
                case NODUS_T3_FWD_RSP:
                    dec_fwd_rsp_args(&dec, args.count, &msg->fwd_rsp);
                    break;
                case NODUS_T3_ROST_Q:
                    dec_rost_q_args(&dec, args.count, &msg->rost_q);
                    break;
                case NODUS_T3_ROST_R:
                    dec_rost_r_args(&dec, args.count, &msg->rost_r);
                    break;
                case NODUS_T3_IDENT:
                    dec_ident_args(&dec, args.count, &msg->ident);
                    break;
                case NODUS_T3_SYNC_REQ:
                    dec_sync_req_args(&dec, args.count, &msg->sync_req);
                    break;
                case NODUS_T3_SYNC_RSP:
                    dec_sync_rsp_args(&dec, args.count, &msg->sync_rsp);
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

/* ── Public verify ───────────────────────────────────────────────── */

int nodus_t3_verify(const nodus_t3_msg_t *msg, const nodus_pubkey_t *pk) {
    if (!msg || !pk || !msg->wsig) return -1;

    /* Heap-allocate sign buffer (thread-safe, no persistent 131KB BSS) */
    uint8_t *sign_buf = malloc(NODUS_T3_MAX_MSG_SIZE);
    if (!sign_buf) return -1;

    size_t sign_len = 0;
    if (enc_sign_payload(msg, sign_buf, NODUS_T3_MAX_MSG_SIZE, &sign_len) != 0) {
        free(sign_buf);
        return -1;
    }

    nodus_sig_t sig;
    memcpy(sig.bytes, msg->wsig, NODUS_SIG_BYTES);
    int result = nodus_verify(&sig, sign_buf, sign_len, pk);
    free(sign_buf);
    return result;
}
