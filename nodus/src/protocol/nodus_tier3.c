/**
 * Nodus v5 — Tier 3 Protocol (Witness BFT Consensus)
 *
 * CBOR encode/decode for all 11 BFT message types.
 * Sign payload = canonical CBOR of {method + header + args}.
 * Wire format  = {t, y, q, wh, a, wsig}.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "crypto/nodus_sign.h"

#include <string.h>
#include <stdio.h>

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

static void enc_propose_args(cbor_encoder_t *enc, const nodus_t3_propose_t *p) {
    cbor_encode_map(enc, 8);
    cbor_encode_cstr(enc, "txh");  cbor_encode_bstr(enc, p->tx_hash,
                                                     NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "nlc");  cbor_encode_uint(enc, p->nullifier_count);
    cbor_encode_cstr(enc, "nls");
    cbor_encode_array(enc, p->nullifier_count);
    for (int i = 0; i < p->nullifier_count; i++)
        cbor_encode_bstr(enc, p->nullifiers[i], NODUS_T3_NULLIFIER_LEN);
    cbor_encode_cstr(enc, "tty");  cbor_encode_uint(enc, p->tx_type);
    cbor_encode_cstr(enc, "txd");  cbor_encode_bstr(enc, p->tx_data, p->tx_len);
    cbor_encode_cstr(enc, "pk");   cbor_encode_bstr(enc, p->client_pubkey,
                                                     NODUS_PK_BYTES);
    cbor_encode_cstr(enc, "csig"); cbor_encode_bstr(enc, p->client_sig,
                                                     NODUS_SIG_BYTES);
    cbor_encode_cstr(enc, "fee");  cbor_encode_uint(enc, p->fee);
}

static void enc_vote_args(cbor_encoder_t *enc, const nodus_t3_vote_t *v) {
    cbor_encode_map(enc, 3);
    cbor_encode_cstr(enc, "txh"); cbor_encode_bstr(enc, v->tx_hash,
                                                    NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "vt");  cbor_encode_uint(enc, v->vote);
    cbor_encode_cstr(enc, "rsn"); cbor_encode_cstr(enc, v->reason);
}

static void enc_commit_args(cbor_encoder_t *enc, const nodus_t3_commit_t *c) {
    cbor_encode_map(enc, 9);
    cbor_encode_cstr(enc, "txh");  cbor_encode_bstr(enc, c->tx_hash,
                                                     NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "nlc");  cbor_encode_uint(enc, c->nullifier_count);
    cbor_encode_cstr(enc, "nls");
    cbor_encode_array(enc, c->nullifier_count);
    for (int i = 0; i < c->nullifier_count; i++)
        cbor_encode_bstr(enc, c->nullifiers[i], NODUS_T3_NULLIFIER_LEN);
    cbor_encode_cstr(enc, "tty");  cbor_encode_uint(enc, c->tx_type);
    cbor_encode_cstr(enc, "txd");  cbor_encode_bstr(enc, c->tx_data, c->tx_len);
    cbor_encode_cstr(enc, "pts");  cbor_encode_uint(enc, c->proposal_timestamp);
    cbor_encode_cstr(enc, "pid");  cbor_encode_bstr(enc, c->proposer_id,
                                                     NODUS_T3_WITNESS_ID_LEN);
    cbor_encode_cstr(enc, "npc");  cbor_encode_uint(enc, c->n_precommits);
    cbor_encode_cstr(enc, "uck");  cbor_encode_bstr(enc, c->utxo_checksum,
                                                     NODUS_KEY_BYTES);
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
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "st");  cbor_encode_uint(enc, f->status);
    cbor_encode_cstr(enc, "txh"); cbor_encode_bstr(enc, f->tx_hash,
                                                    NODUS_T3_TX_HASH_LEN);
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
    cbor_encode_cstr(enc, "rsig"); cbor_encode_bstr(enc, r->roster_sig,
                                                     NODUS_SIG_BYTES);
}

static void enc_ident_args(cbor_encoder_t *enc, const nodus_t3_ident_t *id) {
    cbor_encode_map(enc, 3);
    cbor_encode_cstr(enc, "wid");  cbor_encode_bstr(enc, id->witness_id,
                                                     NODUS_T3_WITNESS_ID_LEN);
    cbor_encode_cstr(enc, "pk");   cbor_encode_bstr(enc, id->pubkey,
                                                     NODUS_PK_BYTES);
    cbor_encode_cstr(enc, "addr"); cbor_encode_cstr(enc, id->address);
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

static void dec_propose_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_propose_t *p) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "txh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(p->tx_hash, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "nlc")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) {
                p->nullifier_count = (uint8_t)val.uint_val;
                if (p->nullifier_count > NODUS_T3_MAX_TX_INPUTS)
                    p->nullifier_count = NODUS_T3_MAX_TX_INPUTS;
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
                        p->nullifiers[j] = val.bstr.ptr;
                }
                for (size_t j = max; j < arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else if (KEY_IS(key, "tty")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) p->tx_type = (uint8_t)val.uint_val;
        }
        else if (KEY_IS(key, "txd")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len <= NODUS_T3_MAX_TX_SIZE) {
                p->tx_data = val.bstr.ptr;
                p->tx_len = (uint32_t)val.bstr.len;
            }
        }
        else if (KEY_IS(key, "pk")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_PK_BYTES)
                p->client_pubkey = val.bstr.ptr;
        }
        else if (KEY_IS(key, "csig")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                p->client_sig = val.bstr.ptr;
        }
        else if (KEY_IS(key, "fee")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) p->fee = val.uint_val;
        }
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

        if (KEY_IS(key, "txh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(v->tx_hash, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
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
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_commit_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_commit_t *c) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "txh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(c->tx_hash, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "nlc")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) {
                c->nullifier_count = (uint8_t)val.uint_val;
                if (c->nullifier_count > NODUS_T3_MAX_TX_INPUTS)
                    c->nullifier_count = NODUS_T3_MAX_TX_INPUTS;
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
                        c->nullifiers[j] = val.bstr.ptr;
                }
                for (size_t j = max; j < arr.count; j++)
                    cbor_decode_skip(dec);
            }
        }
        else if (KEY_IS(key, "tty")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) c->tx_type = (uint8_t)val.uint_val;
        }
        else if (KEY_IS(key, "txd")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len <= NODUS_T3_MAX_TX_SIZE) {
                c->tx_data = val.bstr.ptr;
                c->tx_len = (uint32_t)val.bstr.len;
            }
        }
        else if (KEY_IS(key, "pts")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) c->proposal_timestamp = val.uint_val;
        }
        else if (KEY_IS(key, "pid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(c->proposer_id, val.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        }
        else if (KEY_IS(key, "npc")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) c->n_precommits = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "uck")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_KEY_BYTES)
                memcpy(c->utxo_checksum, val.bstr.ptr, NODUS_KEY_BYTES);
        }
        else {
            cbor_decode_skip(dec);
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

    /* Pass 1: extract method, txn_id, header, wsig */
    for (size_t i = 0; i < map_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

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
                cbor_decode_skip(&dec);
        }
        else if (KEY_IS(key, "wsig")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                msg->wsig = val.bstr.ptr;
        }
        else {
            cbor_decode_skip(&dec);
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

    /* Re-encode sign payload for verification */
    static uint8_t sign_buf[NODUS_T3_MAX_MSG_SIZE];
    size_t sign_len = 0;

    if (enc_sign_payload(msg, sign_buf, sizeof(sign_buf), &sign_len) != 0)
        return -1;

    nodus_sig_t sig;
    memcpy(sig.bytes, msg->wsig, NODUS_SIG_BYTES);
    return nodus_verify(&sig, sign_buf, sign_len, pk);
}
