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
        case NODUS_T3_CC_VOTE_REQ: return "w_cc_vote_req";
        case NODUS_T3_CC_VOTE_RSP: return "w_cc_vote_rsp";
        case NODUS_T3_CHAIN_Q:     return "w_chain_q";
        case NODUS_T3_CHAIN_R:     return "w_chain_r";
        case NODUS_T3_GENESIS_REQ: return "w_genesis_req";
        case NODUS_T3_GENESIS_RSP: return "w_genesis_rsp";
        case NODUS_T3_V2_BLOCK:     return "w_v2_block";
        case NODUS_T3_V2_HEAD:      return "w_v2_head";
        case NODUS_T3_V2_RANGE_REQ: return "w_v2_range_q";
        case NODUS_T3_V2_RANGE_RSP: return "w_v2_range_r";
        case NODUS_T3_V2_GBUNDLE_REQ: return "w_v2_gbundle_q";
        case NODUS_T3_V2_GBUNDLE_RSP: return "w_v2_gbundle_r";
        case NODUS_T3_VIEWOK:     return "w_viewok";
        case NODUS_T3_VIEWOK_REQ: return "w_viewok_q";
        /* Tendermint T3 (T2 wire design §4.2; D-16 rev 4). All seven verbs
         * appear in BOTH tables and all seven have a codec — a verb named
         * in one table only, or named without an encoder, would make
         * nodus_t3_decode return 0 with a zeroed struct (the pass-2 switch
         * falls through `default: break`). The comment in
         * nodus_t3_method_to_type records what one-sided editing cost
         * before. */
        case NODUS_T3_TM_STEP:    return "w_tm_step";
        case NODUS_T3_TM_PROP:    return "w_tm_prop";
        case NODUS_T3_TM_POL:     return "w_tm_pol";
        case NODUS_T3_TM_VOTE:    return "w_tm_vote";
        case NODUS_T3_TM_HAS:     return "w_tm_has";
        case NODUS_T3_TM_MAJ23:   return "w_tm_maj23";
        case NODUS_T3_TM_BITS:    return "w_tm_bits";
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
    if (strcmp(method, "w_cc_vote_req") == 0) return NODUS_T3_CC_VOTE_REQ;
    if (strcmp(method, "w_cc_vote_rsp") == 0) return NODUS_T3_CC_VOTE_RSP;
    if (strcmp(method, "w_chain_q") == 0)     return NODUS_T3_CHAIN_Q;
    if (strcmp(method, "w_chain_r") == 0)     return NODUS_T3_CHAIN_R;
    if (strcmp(method, "w_genesis_req") == 0) return NODUS_T3_GENESIS_REQ;
    if (strcmp(method, "w_genesis_rsp") == 0) return NODUS_T3_GENESIS_RSP;
    /* Ledger V2 O15B — PRODUCTION-DORMANT verbs. Recognising a method name
     * is not dispatching it: every one of these ends at the activation
     * gate, which can never open in this build. Naming them here means an
     * unknown verb and a not-active verb are distinguishable, instead of
     * both dying as "unknown" and hiding which one happened. */
    if (strcmp(method, "w_v2_block") == 0)     return NODUS_T3_V2_BLOCK;
    if (strcmp(method, "w_v2_head") == 0)      return NODUS_T3_V2_HEAD;
    if (strcmp(method, "w_v2_range_q") == 0)   return NODUS_T3_V2_RANGE_REQ;
    if (strcmp(method, "w_v2_range_r") == 0)   return NODUS_T3_V2_RANGE_RSP;
    if (strcmp(method, "w_v2_gbundle_q") == 0) return NODUS_T3_V2_GBUNDLE_REQ;
    if (strcmp(method, "w_v2_gbundle_r") == 0) return NODUS_T3_V2_GBUNDLE_RSP;
    /* O15N Faz 2C1 — BOTH directions, deliberately adjacent. O15E added
     * verbs to this file and updated only one of the two tables, so a
     * frame encoded with an empty method string was undispatchable. */
    if (strcmp(method, "w_viewok") == 0)       return NODUS_T3_VIEWOK;
    if (strcmp(method, "w_viewok_q") == 0)     return NODUS_T3_VIEWOK_REQ;
    /* Tendermint T3 — the same seven verbs as the table above. */
    if (strcmp(method, "w_tm_step") == 0)      return NODUS_T3_TM_STEP;
    if (strcmp(method, "w_tm_prop") == 0)      return NODUS_T3_TM_PROP;
    if (strcmp(method, "w_tm_pol") == 0)       return NODUS_T3_TM_POL;
    if (strcmp(method, "w_tm_vote") == 0)      return NODUS_T3_TM_VOTE;
    if (strcmp(method, "w_tm_has") == 0)       return NODUS_T3_TM_HAS;
    if (strcmp(method, "w_tm_maj23") == 0)     return NODUS_T3_TM_MAJ23;
    if (strcmp(method, "w_tm_bits") == 0)      return NODUS_T3_TM_BITS;
    return 0;
}

/* ── Per-type message ceiling (D-14 rev 2; header contract) ──────── */

size_t nodus_t3_max_msg_size(nodus_t3_msg_type_t type) {
    switch (type) {
        case NODUS_T3_TM_PROP:  return NODUS_T3_TM_PROP_MAX_MSG;
        case NODUS_T3_TM_VOTE:  return NODUS_T3_TM_VOTE_MAX_MSG;
        case NODUS_T3_TM_STEP:
        case NODUS_T3_TM_POL:
        case NODUS_T3_TM_HAS:
        case NODUS_T3_TM_MAJ23:
        case NODUS_T3_TM_BITS:  return NODUS_T3_TM_SMALL_MAX_MSG;
        default:
            /* Every legacy verb: the bound the legacy path actually uses
             * today — nodus_t3_verify's fixed 1 MB heap allocation below.
             * A type that is no verb at all has no ceiling to report. */
            return nodus_t3_type_to_method(type) ? (size_t)NODUS_W_MAX_SYNC_RSP_SIZE
                                                 : (size_t)0;
    }
}

/* ── PR 3 Yol B — bootstrap sig domain separator ─────────────────── */

/* H-3 mitigation: a wsig over (q, wh, a) for one bootstrap method must
 * not be reusable as a wsig for a different method. The 4 new bootstrap
 * messages prepend this fixed domain string + the method name into the
 * Dilithium5 signing input. Existing T3 message types (PROPOSE, COMMIT,
 * IDENT, ...) keep their legacy CBOR-only preimage so old/new binaries
 * remain wire-compatible during rolling deploy. */
#define NODUS_T3_BOOTSTRAP_SIG_DOMAIN "nodus-t3-v1-bootstrap"

/* O15N Faz 2C1 — VERBS 26/27 ARE DELIBERATELY NOT HERE, and that is a
 * decision, not an omission.
 *
 * A bootstrap verb runs BEFORE a committee exists — that is the whole
 * reason the set is what it is. A VIEW_OK statement is meaningless
 * without a committee: its entire content is a committee set hash, and
 * both sides refuse when there is none (nodus_witness_bft_sign_view_ok
 * returns -1 on count 0, nodus_witness_bft_verify_view_proof returns -2).
 * A node asking for a view proof already holds a chain and can resolve
 * its committee; it is behind the cluster, not pre-genesis.
 *
 * Adding them here would prefix their envelope signature with the
 * bootstrap domain, which no existing test would catch — the O15N
 * red-team round named this as a decision with no safe default. */
static bool is_bootstrap_type(nodus_t3_msg_type_t t) {
    return t == NODUS_T3_CHAIN_Q     || t == NODUS_T3_CHAIN_R ||
           t == NODUS_T3_GENESIS_REQ || t == NODUS_T3_GENESIS_RSP;
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
    /* Phase 9 / Task 9.4 — wire key tr is the tx_root (RFC 6962 Merkle).
     * A2 fix — wire key bh is the leader-claimed proposed-block height,
     * carried so all witnesses sign the PREPARED preimage with the same
     * height regardless of local block_height drift. */
    cbor_encode_map(enc, 3);
    cbor_encode_cstr(enc, "tr");
    cbor_encode_bstr(enc, p->tx_root, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "bh");
    cbor_encode_uint(enc, p->block_height);
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
    /* Phase 9 / Task 9.4 — wire key bh -> tr, field block_hash -> tx_root.
     * 2026-05-02 — A2 simetri: "bh" key reintroduced as block_height
     * (uint), bumping map size 7 -> 8. Decoder treats absent/zero as
     * legacy-peer reject signal (mirrors enc_propose_args).
     * O15D — successor rounds append the OPTIONAL "vbi"/"vcs" pair (the
     * sender's V2 BlockID + DNA.CERT.v2 signature; map 8 -> 10). Legacy
     * rounds never set has_v2_cert, so their bytes do not move — the
     * has_prepared pattern from enc_viewchg_args. */
    cbor_encode_map(enc, c->has_v2_cert ? 10 : 8);
    cbor_encode_cstr(enc, "tr");
    cbor_encode_bstr(enc, c->tx_root, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "bh");
    cbor_encode_uint(enc, c->block_height);
    cbor_encode_cstr(enc, "btx");
    cbor_encode_array(enc, (size_t)c->batch_count);
    for (int i = 0; i < c->batch_count; i++)
        enc_batch_tx(enc, &c->batch_txs[i]);
    enc_commit_certs(enc, c);
    if (c->has_v2_cert) {
        cbor_encode_cstr(enc, "vbi");
        cbor_encode_bstr(enc, c->v2_block_id, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(enc, "vcs");
        cbor_encode_bstr(enc, c->v2_cert_sig, NODUS_SIG_BYTES);
    }
}

static void enc_viewchg_args(cbor_encoder_t *enc, const nodus_t3_viewchg_t *v) {
    /* C5 — when has_prepared, emit 5 additional keys: prepared_height,
     * prepared_view, prepared_tx_hash, prepared_n_sigs, prepared_sigs. No
     * explicit has_prepared wire key: receiver sets has_prepared=true
     * when it decodes the prepared_tx_hash key (mirrors has_block_height
     * pattern in enc_ident_args). */
    cbor_encode_map(enc, v->has_prepared ? 7 : 2);
    cbor_encode_cstr(enc, "nv");  cbor_encode_uint(enc, v->new_view);
    cbor_encode_cstr(enc, "lcr"); cbor_encode_uint(enc, v->last_committed_round);
    if (v->has_prepared) {
        cbor_encode_cstr(enc, "ph");  cbor_encode_uint(enc, v->prepared_height);
        cbor_encode_cstr(enc, "pv");  cbor_encode_uint(enc, v->prepared_view);
        cbor_encode_cstr(enc, "pth");
        cbor_encode_bstr(enc, v->prepared_tx_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(enc, "psc"); cbor_encode_uint(enc, v->prepared_n_sigs);
        cbor_encode_cstr(enc, "psgs");
        cbor_encode_array(enc, (size_t)v->prepared_n_sigs);
        for (uint32_t i = 0; i < v->prepared_n_sigs; i++) {
            cbor_encode_map(enc, 2);
            cbor_encode_cstr(enc, "vid");
            cbor_encode_bstr(enc, v->prepared_sigs[i].voter_id,
                             NODUS_T3_WITNESS_ID_LEN);
            cbor_encode_cstr(enc, "sig");
            cbor_encode_bstr(enc, v->prepared_sigs[i].signature,
                             NODUS_SIG_BYTES);
        }
    }
}

static void enc_newview_args(cbor_encoder_t *enc, const nodus_t3_newview_t *n) {
    /* C5 — when has_reproposal, emit reproposal_height + reproposal_tx_hash.
     * has_reproposal=false keeps 2-key backward-compat wire (no VIEW_CHANGE
     * carried a prepared cert, so new leader is free). */
    /* O15C-D.3 — with a reproposal the message now also carries the
     * certificate proving it (prepared view + per-voter sigs), so every
     * follower verifies the same decision instead of consulting its own
     * frozen first-2f+1 subset. 7 keys with a reproposal, 2 without. */
    cbor_encode_map(enc, n->has_reproposal ? 7 : 2);
    cbor_encode_cstr(enc, "nv"); cbor_encode_uint(enc, n->new_view);
    cbor_encode_cstr(enc, "np"); cbor_encode_uint(enc, n->n_proofs);
    if (n->has_reproposal) {
        cbor_encode_cstr(enc, "rh"); cbor_encode_uint(enc, n->reproposal_height);
        cbor_encode_cstr(enc, "rth");
        cbor_encode_bstr(enc, n->reproposal_tx_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(enc, "rpv");
        cbor_encode_uint(enc, n->reproposal_prepared_view);
        cbor_encode_cstr(enc, "rns");
        cbor_encode_uint(enc, n->reproposal_n_sigs);
        cbor_encode_cstr(enc, "rsg");
        {
            uint32_t ns = n->reproposal_n_sigs;
            if (ns > NODUS_T3_MAX_WITNESSES) ns = NODUS_T3_MAX_WITNESSES;
            cbor_encode_array(enc, ns);
            for (uint32_t i = 0; i < ns; i++) {
                cbor_encode_map(enc, 2);
                cbor_encode_cstr(enc, "vid");
                cbor_encode_bstr(enc, n->reproposal_sigs[i].voter_id,
                                 NODUS_T3_WITNESS_ID_LEN);
                cbor_encode_cstr(enc, "sig");
                cbor_encode_bstr(enc, n->reproposal_sigs[i].signature,
                                 NODUS_SIG_BYTES);
            }
        }
    }
}

/* O15N Faz 2C1 — VIEW_OK bundle.
 *
 * ⚠ THE ARRAY LENGTH IS THE ONLY COUNT. There is deliberately no separate
 * count key. Its neighbour above emits "psc" alongside the "psgs" array,
 * and a wire that carries a count AND a length has two sources of truth
 * that an attacker can make disagree — the exact asymmetry the O15N
 * red-team round flagged, where "psc" is stored UNBOUNDED from the wire
 * while its sibling "rns" rejects at decode. One number, decoded from the
 * array header, clamped there. */
static void enc_viewok_args(cbor_encoder_t *enc, const nodus_t3_viewok_t *v) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "h");   cbor_encode_uint(enc, v->height);
    cbor_encode_cstr(enc, "v");   cbor_encode_uint(enc, v->view);
    cbor_encode_cstr(enc, "sh");  cbor_encode_bstr(enc, v->set_hash, 64);
    cbor_encode_cstr(enc, "sts");
    cbor_encode_array(enc, (size_t)v->n_entries);
    for (uint32_t i = 0; i < v->n_entries; i++) {
        cbor_encode_map(enc, 2);
        cbor_encode_cstr(enc, "vid");
        cbor_encode_bstr(enc, v->entries[i].voter_id,
                         NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(enc, "sig");
        cbor_encode_bstr(enc, v->entries[i].signature, NODUS_SIG_BYTES);
    }
}

static void enc_viewok_q_args(cbor_encoder_t *enc,
                                const nodus_t3_viewok_q_t *q) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "hh"); cbor_encode_uint(enc, q->height_hint);
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

/* ── w_cc_vote_req / w_cc_vote_rsp args (Hard-Fork v1 Stage C.2) ──── */

static void enc_cc_vote_req_args(cbor_encoder_t *enc,
                                   const nodus_t3_cc_vote_req_t *r) {
    cbor_encode_map(enc, 6);
    cbor_encode_cstr(enc, "pid"); cbor_encode_uint(enc, r->param_id);
    cbor_encode_cstr(enc, "nv");  cbor_encode_uint(enc, r->new_value);
    cbor_encode_cstr(enc, "eb");  cbor_encode_uint(enc, r->effective_block_height);
    cbor_encode_cstr(enc, "pn");  cbor_encode_uint(enc, r->proposal_nonce);
    cbor_encode_cstr(enc, "sab"); cbor_encode_uint(enc, r->signed_at_block);
    cbor_encode_cstr(enc, "vbb"); cbor_encode_uint(enc, r->valid_before_block);
}

static void enc_cc_vote_rsp_args(cbor_encoder_t *enc,
                                   const nodus_t3_cc_vote_rsp_t *r) {
    if (r->accepted) {
        cbor_encode_map(enc, 3);
        cbor_encode_cstr(enc, "ok");  cbor_encode_uint(enc, 1);
        cbor_encode_cstr(enc, "wid"); cbor_encode_bstr(enc, r->witness_id, 32);
        cbor_encode_cstr(enc, "sig"); cbor_encode_bstr(enc, r->signature,
                                                         NODUS_SIG_BYTES);
    } else {
        cbor_encode_map(enc, 2);
        cbor_encode_cstr(enc, "ok");  cbor_encode_uint(enc, 0);
        cbor_encode_cstr(enc, "rr");  cbor_encode_cstr(enc, r->reject_reason);
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

static void enc_sync_req_args(cbor_encoder_t *enc, const nodus_t3_sync_req_t *r) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "h"); cbor_encode_uint(enc, r->height);
}

static void enc_sync_rsp_args(cbor_encoder_t *enc, const nodus_t3_sync_rsp_t *r) {
    /* Phase 11 / Task 11.2 — multi-tx sync_rsp encoder.
     * 2026-05-02 — C3 fix follow-up: "sr" (state_root) added so the
     * receiver can verify Byzantine peer rejection in replay_block.
     * Map shape (found): f, h, ts, pid, ph, tr, sr, btx, cer = 9 keys. */
    cbor_encode_map(enc, r->found ? 9 : 2);
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
    cbor_encode_cstr(enc, "sr");  cbor_encode_bstr(enc, r->state_root,
                                                    NODUS_KEY_BYTES);
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

/* ── PR 3 Yol B — witness auto-bootstrap arg encoders ────────────── */

static void enc_w_chain_q_args(cbor_encoder_t *enc,
                                const nodus_t3_w_chain_q_t *m) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "n");
    cbor_encode_bstr(enc, m->nonce, NODUS_W_BOOTSTRAP_NONCE_LEN);
}

static void enc_w_chain_r_args(cbor_encoder_t *enc,
                                const nodus_t3_w_chain_r_t *m) {
    cbor_encode_map(enc, 5);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, m->cid, 32);
    cbor_encode_cstr(enc, "tip"); cbor_encode_uint(enc, m->tip);
    cbor_encode_cstr(enc, "gh");
    cbor_encode_bstr(enc, m->gh, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "cdh");
    cbor_encode_bstr(enc, m->cdh, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "n");
    cbor_encode_bstr(enc, m->nonce, NODUS_W_BOOTSTRAP_NONCE_LEN);
}

static void enc_w_genesis_req_args(cbor_encoder_t *enc,
                                    const nodus_t3_w_genesis_req_t *m) {
    cbor_encode_map(enc, 1);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, m->cid, 32);
}

static void enc_w_genesis_rsp_args(cbor_encoder_t *enc,
                                    const nodus_t3_w_genesis_rsp_t *m) {
    /* Sender side. The H-2 cap check happens upstream in enc_args
     * before any bytes are emitted. */
    cbor_encode_map(enc, 5);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, m->cid, 32);
    cbor_encode_cstr(enc, "cdb"); cbor_encode_bstr(enc, m->cdb, m->cdb_len);
    cbor_encode_cstr(enc, "gth");
    cbor_encode_bstr(enc, m->gth, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(enc, "gts"); cbor_encode_uint(enc, m->gts);
    cbor_encode_cstr(enc, "gpid");
    cbor_encode_bstr(enc, m->gpid, NODUS_T3_WITNESS_ID_LEN);
}

/* ── O15E Faz B — Ledger V2 successor sync arg encoders ──────────── */

static void enc_w_v2_block_q_args(cbor_encoder_t *enc,
                                  const nodus_t3_w_v2_block_q_t *m) {
    cbor_encode_map(enc, 3);
    cbor_encode_cstr(enc, "c");  cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "h");  cbor_encode_uint(enc, m->height);
    cbor_encode_cstr(enc, "bi"); cbor_encode_bstr(enc, m->block_id, 64);
}

static void enc_w_v2_head_args(cbor_encoder_t *enc,
                               const nodus_t3_w_v2_head_t *m) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "c");  cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "g");  cbor_encode_bstr(enc, m->genesis_id, 64);
    cbor_encode_cstr(enc, "hh"); cbor_encode_uint(enc, m->head);
    cbor_encode_cstr(enc, "pv"); cbor_encode_uint(enc, m->proto);
}

static void enc_w_v2_range_q_args(cbor_encoder_t *enc,
                                  const nodus_t3_w_v2_range_q_t *m) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "c");  cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "g");  cbor_encode_bstr(enc, m->genesis_id, 64);
    cbor_encode_cstr(enc, "fr"); cbor_encode_uint(enc, m->from);
    cbor_encode_cstr(enc, "n");  cbor_encode_uint(enc, m->count);
}

static void enc_w_v2_range_r_args(cbor_encoder_t *enc,
                                  const nodus_t3_w_v2_range_r_t *m) {
    /* Frame-length vector as n×u32 BE inside one bstr; frames packed
     * back-to-back in a second bstr. Caps are enforced in enc_args
     * BEFORE any byte is emitted. */
    uint8_t fl[NODUS_T3_V2_RANGE_MAX_FRAMES * 4];
    for (uint32_t i = 0; i < m->n && i < NODUS_T3_V2_RANGE_MAX_FRAMES; i++) {
        fl[i * 4 + 0] = (uint8_t)(m->frame_len[i] >> 24);
        fl[i * 4 + 1] = (uint8_t)(m->frame_len[i] >> 16);
        fl[i * 4 + 2] = (uint8_t)(m->frame_len[i] >> 8);
        fl[i * 4 + 3] = (uint8_t)(m->frame_len[i]);
    }
    cbor_encode_map(enc, 5);
    cbor_encode_cstr(enc, "c");  cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "fr"); cbor_encode_uint(enc, m->from);
    cbor_encode_cstr(enc, "n");  cbor_encode_uint(enc, m->n);
    cbor_encode_cstr(enc, "fl"); cbor_encode_bstr(enc, fl, (size_t)m->n * 4);
    cbor_encode_cstr(enc, "fb");
    cbor_encode_bstr(enc, m->frames, m->frames_len);
}

static void enc_w_v2_gbundle_q_args(cbor_encoder_t *enc,
                                    const nodus_t3_w_v2_gbundle_q_t *m) {
    cbor_encode_map(enc, 3);
    cbor_encode_cstr(enc, "c"); cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "p"); cbor_encode_bstr(enc, m->pin, 64);
    cbor_encode_cstr(enc, "o"); cbor_encode_uint(enc, m->offset);
}

static void enc_w_v2_gbundle_r_args(cbor_encoder_t *enc,
                                    const nodus_t3_w_v2_gbundle_r_t *m) {
    cbor_encode_map(enc, 5);
    cbor_encode_cstr(enc, "c"); cbor_encode_bstr(enc, m->chain, 32);
    cbor_encode_cstr(enc, "p"); cbor_encode_bstr(enc, m->pin, 64);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, m->total);
    cbor_encode_cstr(enc, "o"); cbor_encode_uint(enc, m->offset);
    cbor_encode_cstr(enc, "d"); cbor_encode_bstr(enc, m->chunk, m->chunk_len);
}

/* ── Tendermint T3 wire constants ────────────────────────────────────
 *
 * The vote type byte takes the CometBFT SignedMsgType values — PREVOTE
 * 0x01, PRECOMMIT 0x02 — per APPROVED D-12
 * (atlas-dec-ae3830947ee947d1d9bea33ad259d70b, signing.md:21-25 @1c55dd4f).
 * These are deliberately NOT dna_cmsg_type_t's PREVOTE 2 / PRECOMMIT 3:
 * D-12 keeps the core enum unchanged and maps enum <-> wire byte in one
 * host-side table. 0x20 (ProposalType) is reserved and must never appear.
 *
 * File-scope rather than in the header on purpose: shared/dnac/tm_vote.h
 * owns the public names for these (wave 1 package (a)), and protocol/ must
 * not grow a dependency on bft/ to reach the core enum. */
#define T3_TM_TY_PREVOTE     0x01u
#define T3_TM_TY_PRECOMMIT   0x02u

static inline bool t3_tm_ty_ok(uint8_t ty) {
    return ty == T3_TM_TY_PREVOTE || ty == T3_TM_TY_PRECOMMIT;
}

/* ── Tendermint T3 arg encoders (verbs 28-34) ─────────────────────
 *
 * T2 wire design §4.2 / D-16 rev 4. Key ORDER here is the canonical
 * emission order of that table; the decoders accept any order but demand
 * the exact key SET. Sender-side range refusals live in enc_args, before a
 * byte is emitted, following the H-2 / O15E discipline already used for
 * cdb, the range response and the gbundle chunk. */

static void enc_tm_step_args(cbor_encoder_t *enc, const nodus_t3_tm_step_t *m) {
    cbor_encode_map(enc, 5);
    cbor_encode_cstr(enc, "h");   cbor_encode_uint(enc, m->h);
    cbor_encode_cstr(enc, "r");   cbor_encode_uint(enc, m->r);
    cbor_encode_cstr(enc, "s");   cbor_encode_uint(enc, m->s);
    /* sst is written and never read back by the host (T2 §4.2); it is
     * carried faithfully anyway so the twin test can prove two nodes whose
     * sst differs still produce identical traces. */
    cbor_encode_cstr(enc, "sst"); cbor_encode_int(enc, m->sst);
    cbor_encode_cstr(enc, "lcr"); cbor_encode_int(enc, m->lcr);
}

static void enc_tm_prop_args(cbor_encoder_t *enc, const nodus_t3_tm_prop_t *m) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "h");  cbor_encode_uint(enc, m->h);
    cbor_encode_cstr(enc, "r");  cbor_encode_uint(enc, m->r);
    cbor_encode_cstr(enc, "vr"); cbor_encode_int(enc, m->vr);
    cbor_encode_cstr(enc, "v");  cbor_encode_bstr(enc, m->v, m->v_len);
}

static void enc_tm_pol_args(cbor_encoder_t *enc, const nodus_t3_tm_pol_t *m) {
    cbor_encode_map(enc, 3);
    cbor_encode_cstr(enc, "h");  cbor_encode_uint(enc, m->h);
    cbor_encode_cstr(enc, "pr"); cbor_encode_uint(enc, m->pr);
    cbor_encode_cstr(enc, "bm"); cbor_encode_bstr(enc, m->bm, m->bm_len);
}

static void enc_tm_vote_args(cbor_encoder_t *enc, const nodus_t3_tm_vote_t *m) {
    cbor_encode_map(enc, 8);
    cbor_encode_cstr(enc, "ty");  cbor_encode_uint(enc, m->ty);
    cbor_encode_cstr(enc, "h");   cbor_encode_uint(enc, m->h);
    cbor_encode_cstr(enc, "r");   cbor_encode_uint(enc, m->r);
    cbor_encode_cstr(enc, "bi");  cbor_encode_bstr(enc, m->bi, 64);
    cbor_encode_cstr(enc, "vid"); cbor_encode_bstr(enc, m->vid, 32);
    cbor_encode_cstr(enc, "ix");  cbor_encode_uint(enc, m->ix);
    cbor_encode_cstr(enc, "ts");  cbor_encode_uint(enc, m->ts);
    cbor_encode_cstr(enc, "sig");
    cbor_encode_bstr(enc, m->sig, QGP_DSA87_SIGNATURE_BYTES);
}

static void enc_tm_has_args(cbor_encoder_t *enc, const nodus_t3_tm_has_t *m) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "h");  cbor_encode_uint(enc, m->h);
    cbor_encode_cstr(enc, "r");  cbor_encode_uint(enc, m->r);
    cbor_encode_cstr(enc, "ty"); cbor_encode_uint(enc, m->ty);
    cbor_encode_cstr(enc, "ix"); cbor_encode_uint(enc, m->ix);
}

static void enc_tm_maj23_args(cbor_encoder_t *enc, const nodus_t3_tm_maj23_t *m) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "h");  cbor_encode_uint(enc, m->h);
    cbor_encode_cstr(enc, "r");  cbor_encode_uint(enc, m->r);
    cbor_encode_cstr(enc, "ty"); cbor_encode_uint(enc, m->ty);
    cbor_encode_cstr(enc, "bi"); cbor_encode_bstr(enc, m->bi, 64);
}

static void enc_tm_bits_args(cbor_encoder_t *enc, const nodus_t3_tm_bits_t *m) {
    cbor_encode_map(enc, 5);
    cbor_encode_cstr(enc, "h");  cbor_encode_uint(enc, m->h);
    cbor_encode_cstr(enc, "r");  cbor_encode_uint(enc, m->r);
    cbor_encode_cstr(enc, "ty"); cbor_encode_uint(enc, m->ty);
    cbor_encode_cstr(enc, "bi"); cbor_encode_bstr(enc, m->bi, 64);
    cbor_encode_cstr(enc, "bm"); cbor_encode_bstr(enc, m->bm, m->bm_len);
}

/* ── Args dispatch ───────────────────────────────────────────────── */

static int enc_args(cbor_encoder_t *enc, const nodus_t3_msg_t *msg) {
    /* H-2 sender-side cap on chain_def_blob: refuse to emit oversize
     * payload so a misconfigured/buggy responder cannot blast a
     * fresh-node decoder with >64 KB cdb. The matching decoder cap
     * lands in A4 (strict cap pass before sig verify). */
    if (msg->type == NODUS_T3_GENESIS_RSP &&
        msg->w_genesis_rsp.cdb_len > NODUS_W_MAX_CHAIN_DEF_BLOB) {
        return -1;
    }
    /* O15E Faz B — sender-side caps on the range response, refused
     * before any byte is emitted: frame count, per-frame sanity and the
     * packed-byte budget (the sum of the declared lengths must equal
     * the packed length exactly — no slack, no truncation). */
    if (msg->type == NODUS_T3_V2_RANGE_RSP) {
        const nodus_t3_w_v2_range_r_t *r = &msg->w_v2_range_r;
        if (r->n > NODUS_T3_V2_RANGE_MAX_FRAMES) return -1;
        if (r->frames_len > NODUS_T3_V2_RANGE_MAX_BYTES) return -1;
        if (r->n > 0 && !r->frames) return -1;
        uint64_t sum = 0;
        for (uint32_t i = 0; i < r->n; i++) {
            if (r->frame_len[i] == 0) return -1;
            sum += (uint64_t)r->frame_len[i];
        }
        if (sum != (uint64_t)r->frames_len) return -1;
    }
    if (msg->type == NODUS_T3_V2_GBUNDLE_RSP &&
        (msg->w_v2_gbundle_r.chunk_len > NODUS_T3_V2_GBUNDLE_CHUNK_MAX ||
         (msg->w_v2_gbundle_r.chunk_len > 0 && !msg->w_v2_gbundle_r.chunk)))
        return -1;
    /* Tendermint T3 (verbs 28-34) — the sender refuses out-of-range fields
     * before emitting, so an encoder can never produce bytes its own
     * decoder would reject (DG-13 bijection). The ranges are T2 §4.2's:
     * s in 0..3, lcr and vr >= -1, ty in {1, 2} (D-12 SignedMsgType
     * values), a bitmap of 1..16 bytes (ceil(DNA_MAX_ACTIVE_VALIDATORS/8))
     * and a value of 1..DNA_TM_VALUE_MAX_LEN bytes. `sst` has no range:
     * T2 §4.2 says any i64. */
    if (msg->type == NODUS_T3_TM_STEP &&
        (msg->tm_step.s > NODUS_T3_TM_STEP_NEW_HEIGHT ||
         msg->tm_step.lcr < -1))
        return -1;
    if (msg->type == NODUS_T3_TM_PROP &&
        (msg->tm_prop.vr < -1 ||
         msg->tm_prop.v == NULL ||
         msg->tm_prop.v_len == 0 ||
         (size_t)msg->tm_prop.v_len > (size_t)DNA_TM_VALUE_MAX_LEN))
        return -1;
    if (msg->type == NODUS_T3_TM_POL &&
        (msg->tm_pol.bm_len == 0 ||
         msg->tm_pol.bm_len > NODUS_T3_TM_BITMAP_MAX))
        return -1;
    if (msg->type == NODUS_T3_TM_VOTE && !t3_tm_ty_ok(msg->tm_vote.ty))
        return -1;
    if (msg->type == NODUS_T3_TM_HAS && !t3_tm_ty_ok(msg->tm_has.ty))
        return -1;
    if (msg->type == NODUS_T3_TM_MAJ23 && !t3_tm_ty_ok(msg->tm_maj23.ty))
        return -1;
    if (msg->type == NODUS_T3_TM_BITS &&
        (!t3_tm_ty_ok(msg->tm_bits.ty) ||
         msg->tm_bits.bm_len == 0 ||
         msg->tm_bits.bm_len > NODUS_T3_TM_BITMAP_MAX))
        return -1;
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
        case NODUS_T3_CC_VOTE_REQ: enc_cc_vote_req_args(enc, &msg->cc_vote_req); break;
        case NODUS_T3_CC_VOTE_RSP: enc_cc_vote_rsp_args(enc, &msg->cc_vote_rsp); break;
        case NODUS_T3_SYNC_REQ:  enc_sync_req_args(enc, &msg->sync_req); break;
        case NODUS_T3_SYNC_RSP:  enc_sync_rsp_args(enc, &msg->sync_rsp); break;
        case NODUS_T3_CHAIN_Q:
            enc_w_chain_q_args(enc, &msg->w_chain_q);     break;
        case NODUS_T3_CHAIN_R:
            enc_w_chain_r_args(enc, &msg->w_chain_r);     break;
        case NODUS_T3_GENESIS_REQ:
            enc_w_genesis_req_args(enc, &msg->w_genesis_req); break;
        case NODUS_T3_GENESIS_RSP:
            enc_w_genesis_rsp_args(enc, &msg->w_genesis_rsp); break;
        case NODUS_T3_V2_BLOCK:
            enc_w_v2_block_q_args(enc, &msg->w_v2_block_q);   break;
        case NODUS_T3_V2_HEAD:
            enc_w_v2_head_args(enc, &msg->w_v2_head);         break;
        case NODUS_T3_V2_RANGE_REQ:
            enc_w_v2_range_q_args(enc, &msg->w_v2_range_q);   break;
        case NODUS_T3_V2_RANGE_RSP:
            enc_w_v2_range_r_args(enc, &msg->w_v2_range_r);   break;
        case NODUS_T3_V2_GBUNDLE_REQ:
            enc_w_v2_gbundle_q_args(enc, &msg->w_v2_gbundle_q); break;
        case NODUS_T3_V2_GBUNDLE_RSP:
            enc_w_v2_gbundle_r_args(enc, &msg->w_v2_gbundle_r); break;
        case NODUS_T3_VIEWOK:
            enc_viewok_args(enc, &msg->viewok);               break;
        case NODUS_T3_VIEWOK_REQ:
            enc_viewok_q_args(enc, &msg->viewok_q);           break;
        /* Tendermint T3. */
        case NODUS_T3_TM_STEP:
            enc_tm_step_args(enc, &msg->tm_step);             break;
        case NODUS_T3_TM_PROP:
            enc_tm_prop_args(enc, &msg->tm_prop);             break;
        case NODUS_T3_TM_POL:
            enc_tm_pol_args(enc, &msg->tm_pol);               break;
        case NODUS_T3_TM_VOTE:
            enc_tm_vote_args(enc, &msg->tm_vote);             break;
        case NODUS_T3_TM_HAS:
            enc_tm_has_args(enc, &msg->tm_has);               break;
        case NODUS_T3_TM_MAJ23:
            enc_tm_maj23_args(enc, &msg->tm_maj23);           break;
        case NODUS_T3_TM_BITS:
            enc_tm_bits_args(enc, &msg->tm_bits);             break;
        default: return -1;
    }
    return 0;
}

/* ── Sign payload encode ─────────────────────────────────────────── */

static int enc_sign_payload(const nodus_t3_msg_t *msg,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    const char *method = nodus_t3_type_to_method(msg->type);
    if (!method) return -1;

    /* H-3 mitigation: bootstrap types (CHAIN_Q, CHAIN_R, GENESIS_REQ,
     * GENESIS_RSP) prepend a fixed domain separator + the method name to
     * the Dilithium5 sign input so a captured wsig over one method's
     * (q, wh, a) cannot be passed off as a wsig for a different method.
     * The prefix never enters the wire frame; it only conditions the
     * signing/verifying input. Existing T3 message types keep the
     * legacy CBOR-only preimage to remain wire-compatible with old
     * binaries during rolling deploy. */
    size_t prefix_len = 0;
    if (is_bootstrap_type(msg->type)) {
        const char *dom = NODUS_T3_BOOTSTRAP_SIG_DOMAIN;
        size_t dom_len = strlen(dom);
        size_t method_len = strlen(method);
        if (dom_len + method_len > cap) return -1;
        memcpy(buf, dom, dom_len);
        memcpy(buf + dom_len, method, method_len);
        prefix_len = dom_len + method_len;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf + prefix_len, cap - prefix_len);
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "q"); cbor_encode_cstr(&enc, method);
    enc_wh(&enc, &msg->header);
    if (enc_args(&enc, msg) != 0) return -1;

    *out_len = prefix_len + cbor_encoder_len(&enc);
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
            /* O15H D8 — family-aware (nodus_t3_tx_size_limit); same
             * silent-drop shape as the w_fwd decoder below. */
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len <= nodus_t3_tx_size_limit(val.bstr.ptr,
                                                         val.bstr.len)) {
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
        else if (KEY_IS(key, "bh")) {
            /* A2 fix — leader-claimed proposed-block height (uint). If
             * absent (e.g., legacy peer), p->block_height stays 0 and
             * handle_propose's sanity check rejects the proposal so the
             * follower triggers sync rather than signing under drift. */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                p->block_height = val.uint_val;
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
    else if (KEY_IS(*key, "bh")) {
        /* 2026-05-02 — A2 simetri: leader-claimed block_height. Absent
         * (legacy peer) leaves c->block_height = 0; handle_commit
         * rejects 0 with sync trigger (mirrors propose A2 behavior). */
        cbor_item_t val = cbor_decode_next(dec);
        if (val.type == CBOR_ITEM_UINT) c->block_height = val.uint_val;
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
    /* O15D — OPTIONAL successor QC-certificate pair. has_v2_cert is set
     * only when BOTH fields decode at their exact lengths; a lone or
     * malformed half leaves the pair absent (fail closed, never partial). */
    else if (KEY_IS(*key, "vbi")) {
        cbor_item_t val = cbor_decode_next(dec);
        if (val.type == CBOR_ITEM_BSTR &&
            val.bstr.len == NODUS_T3_TX_HASH_LEN) {
            memcpy(c->v2_block_id, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
            c->has_v2_cert |= 1;            /* half 1 of 2 */
        }
    }
    else if (KEY_IS(*key, "vcs")) {
        cbor_item_t val = cbor_decode_next(dec);
        if (val.type == CBOR_ITEM_BSTR &&
            val.bstr.len == NODUS_SIG_BYTES) {
            memcpy(c->v2_cert_sig, val.bstr.ptr, NODUS_SIG_BYTES);
            c->has_v2_cert |= 2;            /* half 2 of 2 */
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
    /* O15D — normalize the optional pair: BOTH halves (bits 1|2) or
     * neither. A lone half is dropped, so no consumer can ever read a
     * BlockID with someone else's signature bytes. */
    c->has_v2_cert = (c->has_v2_cert == 3) ? 1 : 0;
}

static void dec_viewchg_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_viewchg_t *v) {
    /* v is already zero-initialized by the outer msg memset, so
     * has_prepared defaults to false and is flipped to true when we see
     * a valid prepared_tx_hash key. */
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
        else if (KEY_IS(key, "ph")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) v->prepared_height = val.uint_val;
        }
        else if (KEY_IS(key, "pv")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                v->prepared_view = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "pth")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN) {
                memcpy(v->prepared_tx_hash, val.bstr.ptr,
                       NODUS_T3_TX_HASH_LEN);
                v->has_prepared = true;
            }
        }
        else if (KEY_IS(key, "psc")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                v->prepared_n_sigs = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "psgs")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type == CBOR_ITEM_ARRAY) {
                size_t max = arr.count < NODUS_T3_MAX_WITNESSES ?
                             arr.count : NODUS_T3_MAX_WITNESSES;
                for (size_t j = 0; j < max; j++) {
                    cbor_item_t m = cbor_decode_next(dec);
                    if (m.type != CBOR_ITEM_MAP) {
                        cbor_decode_skip(dec);
                        continue;
                    }
                    for (size_t k = 0; k < m.count; k++) {
                        cbor_item_t mk = cbor_decode_next(dec);
                        if (mk.type != CBOR_ITEM_TSTR) {
                            cbor_decode_skip(dec);
                            continue;
                        }
                        if (KEY_IS(mk, "vid")) {
                            cbor_item_t mv = cbor_decode_next(dec);
                            if (mv.type == CBOR_ITEM_BSTR &&
                                mv.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                                memcpy(v->prepared_sigs[j].voter_id,
                                       mv.bstr.ptr,
                                       NODUS_T3_WITNESS_ID_LEN);
                        } else if (KEY_IS(mk, "sig")) {
                            cbor_item_t mv = cbor_decode_next(dec);
                            if (mv.type == CBOR_ITEM_BSTR &&
                                mv.bstr.len == NODUS_SIG_BYTES)
                                memcpy(v->prepared_sigs[j].signature,
                                       mv.bstr.ptr, NODUS_SIG_BYTES);
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

static void dec_newview_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_newview_t *n) {
    /* n is zero-initialized by outer msg memset; has_reproposal flips to
     * true when we see a valid reproposal_tx_hash key. */
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
        else if (KEY_IS(key, "rh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                n->reproposal_height = val.uint_val;
        }
        else if (KEY_IS(key, "rth")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN) {
                memcpy(n->reproposal_tx_hash, val.bstr.ptr,
                       NODUS_T3_TX_HASH_LEN);
                n->has_reproposal = true;
            }
        }
        /* O15C-D.3 — the carried prepared certificate. Strict: a field
         * of the wrong type or length is simply not stored, so the
         * verifier downstream sees an incomplete cert and fails closed
         * rather than accepting a partially-parsed proof. */
        else if (KEY_IS(key, "rpv")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                n->reproposal_prepared_view = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "rns")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT &&
                val.uint_val <= NODUS_T3_MAX_WITNESSES)
                n->reproposal_n_sigs = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "rsg")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type != CBOR_ITEM_ARRAY) { cbor_decode_skip(dec); continue; }
            size_t cnt = arr.count;
            if (cnt > NODUS_T3_MAX_WITNESSES) cnt = NODUS_T3_MAX_WITNESSES;
            for (size_t j = 0; j < cnt; j++) {
                cbor_item_t m = cbor_decode_next(dec);
                if (m.type != CBOR_ITEM_MAP) { cbor_decode_skip(dec); continue; }
                for (size_t k = 0; k < m.count; k++) {
                    cbor_item_t mk = cbor_decode_next(dec);
                    if (mk.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
                    if (KEY_IS(mk, "vid")) {
                        cbor_item_t mv = cbor_decode_next(dec);
                        if (mv.type == CBOR_ITEM_BSTR &&
                            mv.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                            memcpy(n->reproposal_sigs[j].voter_id,
                                   mv.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
                    } else if (KEY_IS(mk, "sig")) {
                        cbor_item_t mv = cbor_decode_next(dec);
                        if (mv.type == CBOR_ITEM_BSTR &&
                            mv.bstr.len == NODUS_SIG_BYTES)
                            memcpy(n->reproposal_sigs[j].signature,
                                   mv.bstr.ptr, NODUS_SIG_BYTES);
                    } else {
                        cbor_decode_skip(dec);
                    }
                }
            }
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

/* O15N Faz 2C1 — VIEW_OK bundle.
 *
 * ⚠ THE CLAMP IS A HARD REJECT, NOT A TRUNCATION. Its neighbour above
 * takes min(arr.count, MAX_WITNESSES) and skips the tail, which is safe
 * only because every current consumer re-clamps; a consumer written
 * without one would inherit an attacker-chosen count. Here an oversized
 * array sets dec->error, which fails the WHOLE frame (nodus_t3_decode
 * returns -1 on it) — so no consumer of this verb can ever be handed a
 * count it did not ask for, and none has to remember to re-check.
 *
 * n_entries is taken from the array header and NOWHERE else; there is no
 * count key on this wire to disagree with it. */
static void dec_viewok_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_viewok_t *v) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "h")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) v->height = val.uint_val;
        }
        else if (KEY_IS(key, "v")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) v->view = (uint32_t)val.uint_val;
        }
        else if (KEY_IS(key, "sh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64)
                memcpy(v->set_hash, val.bstr.ptr, 64);
        }
        else if (KEY_IS(key, "sts")) {
            cbor_item_t arr = cbor_decode_next(dec);
            if (arr.type != CBOR_ITEM_ARRAY) { cbor_decode_skip(dec); continue; }
            if (arr.count > NODUS_T3_MAX_WITNESSES) {
                /* HARD REJECT — see the note above. */
                dec->error = true;
                return;
            }
            for (size_t j = 0; j < arr.count; j++) {
                cbor_item_t m = cbor_decode_next(dec);
                if (m.type != CBOR_ITEM_MAP) { cbor_decode_skip(dec); continue; }
                for (size_t k = 0; k < m.count; k++) {
                    cbor_item_t mk = cbor_decode_next(dec);
                    if (mk.type != CBOR_ITEM_TSTR) {
                        cbor_decode_skip(dec);
                        continue;
                    }
                    if (KEY_IS(mk, "vid")) {
                        cbor_item_t mv = cbor_decode_next(dec);
                        if (mv.type == CBOR_ITEM_BSTR &&
                            mv.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                            memcpy(v->entries[j].voter_id, mv.bstr.ptr,
                                   NODUS_T3_WITNESS_ID_LEN);
                    } else if (KEY_IS(mk, "sig")) {
                        cbor_item_t mv = cbor_decode_next(dec);
                        if (mv.type == CBOR_ITEM_BSTR &&
                            mv.bstr.len == NODUS_SIG_BYTES)
                            memcpy(v->entries[j].signature, mv.bstr.ptr,
                                   NODUS_SIG_BYTES);
                    } else {
                        cbor_decode_skip(dec);
                    }
                }
            }
            v->n_entries = (uint32_t)arr.count;
        }
        else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_viewok_q_args(cbor_decoder_t *dec, size_t count,
                                nodus_t3_viewok_q_t *q) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "hh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) q->height_hint = val.uint_val;
        } else {
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
            /* O15H D8 — family-aware (nodus_t3_tx_size_limit). An
             * oversize bstr is DROPPED here rather than rejected, so the
             * legacy ceiling made a V2 envelope arrive with tx_data
             * NULL — a silent disappearance one layer below the handler
             * that would have reported it. */
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len <= nodus_t3_tx_size_limit(val.bstr.ptr,
                                                         val.bstr.len)) {
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

/* ── w_cc_vote_req / w_cc_vote_rsp decoders (Hard-Fork v1 Stage C.2) ── */

static void dec_cc_vote_req_args(cbor_decoder_t *dec, size_t count,
                                   nodus_t3_cc_vote_req_t *r) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "pid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->param_id = (uint8_t)val.uint_val;
        } else if (KEY_IS(key, "nv")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->new_value = val.uint_val;
        } else if (KEY_IS(key, "eb")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->effective_block_height = val.uint_val;
        } else if (KEY_IS(key, "pn")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->proposal_nonce = val.uint_val;
        } else if (KEY_IS(key, "sab")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->signed_at_block = val.uint_val;
        } else if (KEY_IS(key, "vbb")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->valid_before_block = val.uint_val;
        } else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_cc_vote_rsp_args(cbor_decoder_t *dec, size_t count,
                                   nodus_t3_cc_vote_rsp_t *r) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "ok")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) r->accepted = (val.uint_val != 0);
        } else if (KEY_IS(key, "wid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(r->witness_id, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "sig")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                memcpy(r->signature, val.bstr.ptr, NODUS_SIG_BYTES);
        } else if (KEY_IS(key, "rr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_TSTR) {
                size_t clen = val.tstr.len < sizeof(r->reject_reason) - 1
                            ? val.tstr.len : sizeof(r->reject_reason) - 1;
                memcpy(r->reject_reason, val.tstr.ptr, clen);
                r->reject_reason[clen] = '\0';
            }
        } else {
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
        else if (KEY_IS(key, "sr")) {
            /* 2026-05-02 — C3 fix follow-up: leader's state_root claim
             * for the synced block. Receiver passes this to replay_block
             * as expected_state_root so finalize_block can detect
             * Byzantine peer fake blocks before any state mutation. */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_KEY_BYTES)
                memcpy(r->state_root, val.bstr.ptr, NODUS_KEY_BYTES);
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

/* ── PR 3 Yol B — witness auto-bootstrap arg decoders ────────────── */

static void dec_w_chain_q_args(cbor_decoder_t *dec, size_t count,
                                nodus_t3_w_chain_q_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "n")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_W_BOOTSTRAP_NONCE_LEN)
                memcpy(m->nonce, val.bstr.ptr, NODUS_W_BOOTSTRAP_NONCE_LEN);
        }
        else { cbor_decode_skip(dec); }
    }
}

static void dec_w_chain_r_args(cbor_decoder_t *dec, size_t count,
                                nodus_t3_w_chain_r_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "cid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->cid, val.bstr.ptr, 32);
        }
        else if (KEY_IS(key, "tip")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->tip = val.uint_val;
        }
        else if (KEY_IS(key, "gh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(m->gh, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "cdh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(m->cdh, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "n")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_W_BOOTSTRAP_NONCE_LEN)
                memcpy(m->nonce, val.bstr.ptr, NODUS_W_BOOTSTRAP_NONCE_LEN);
        }
        else { cbor_decode_skip(dec); }
    }
}

static void dec_w_genesis_req_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_genesis_req_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "cid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->cid, val.bstr.ptr, 32);
        }
        else { cbor_decode_skip(dec); }
    }
}

static void dec_w_genesis_rsp_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_genesis_rsp_t *m) {
    /* Receiver side. The chain_def_blob is plumbed through as a
     * zero-copy pointer into the input CBOR buffer (matches tx_data
     * pattern elsewhere). The strict 64 KB cap rejection lands in A4
     * as a pre-sig-verify pass; A3 just decodes whatever the wire
     * carried so the GREEN test can confirm roundtrip. */
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }

        if (KEY_IS(key, "cid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->cid, val.bstr.ptr, 32);
        }
        else if (KEY_IS(key, "cdb")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR) {
                /* H-2 strict cap (A4): reject before sig verify so a
                 * malicious peer cannot waste Dilithium5 verify cycles
                 * (≈300 µs) with arbitrarily large cdb payloads. The
                 * matching encoder cap (in enc_args dispatch) means
                 * honest binaries never emit oversize cdb; this branch
                 * defends against custom/forked encoders. dec->error
                 * propagates to nodus_t3_decode return value -1. */
                if (val.bstr.len > NODUS_W_MAX_CHAIN_DEF_BLOB) {
                    dec->error = true;
                    return;
                }
                m->cdb = val.bstr.ptr;
                m->cdb_len = (uint32_t)val.bstr.len;
            }
        }
        else if (KEY_IS(key, "gth")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN)
                memcpy(m->gth, val.bstr.ptr, NODUS_T3_TX_HASH_LEN);
        }
        else if (KEY_IS(key, "gts")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->gts = val.uint_val;
        }
        else if (KEY_IS(key, "gpid")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_WITNESS_ID_LEN)
                memcpy(m->gpid, val.bstr.ptr, NODUS_T3_WITNESS_ID_LEN);
        }
        else { cbor_decode_skip(dec); }
    }
}

/* ── Public decode ───────────────────────────────────────────────── */

/* O15E Faz B decoders — defined after this function, near their
 * encoder siblings; declared here so the dispatch below can name them. */
static void dec_w_v2_block_q_args(cbor_decoder_t *dec, size_t count,
                                  nodus_t3_w_v2_block_q_t *m);
static void dec_w_v2_head_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_w_v2_head_t *m);
static void dec_w_v2_range_q_args(cbor_decoder_t *dec, size_t count,
                                  nodus_t3_w_v2_range_q_t *m);
static void dec_w_v2_range_r_args(cbor_decoder_t *dec, size_t count,
                                  nodus_t3_w_v2_range_r_t *m);
static void dec_w_v2_gbundle_q_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_v2_gbundle_q_t *m);
static void dec_w_v2_gbundle_r_args(cbor_decoder_t *dec, size_t count,
                                    nodus_t3_w_v2_gbundle_r_t *m);
/* Tendermint T3 decoders — same arrangement. */
static void dec_tm_step_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_step_t *m);
static void dec_tm_prop_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_prop_t *m);
static void dec_tm_pol_args(cbor_decoder_t *dec, size_t count,
                            nodus_t3_tm_pol_t *m);
static void dec_tm_vote_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_vote_t *m);
static void dec_tm_has_args(cbor_decoder_t *dec, size_t count,
                            nodus_t3_tm_has_t *m);
static void dec_tm_maj23_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_tm_maj23_t *m);
static void dec_tm_bits_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_bits_t *m);

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

    /* D-22 rev 2 — set by the pass-1 walker if `a` contained a negative
     * integer anywhere, at any nesting depth. Read by the type gate below,
     * once the verb is known. */
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
             * D-22 rev 2: this uses the SIGNED walker, not the shared
             * cbor_decode_skip. Pass 1 reaches the method name and the wsig
             * by walking past `a` without reading it, and the shared walker
             * treats a major type 1 item as an error — so before this
             * change every envelope carrying a negative integer anywhere in
             * `a` died here, in pass 1, before its own arg decoder ever
             * ran. The error is sticky (dec_has returns false once it is
             * set), so the next key read returned ERROR and the function
             * returned -1. Only this one call site changes; the shared
             * walker and its ≈230 call sites are untouched, and the type gate
             * below keeps the legacy acceptance set identical. */
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

    /* D-22 rev 2: a negative integer inside `a` is structurally admitted ONLY for the two
     * verbs whose specification has signed fields (28 sst/lcr, 29 vr). For verbs 30-34 and
     * every legacy verb 1-27 it is rejected here exactly as pass 1 rejected it before
     * cbor_decode_skip_signed existed — both paths return -1; with no negative present the
     * two walkers walk identically, so the legacy acceptance set is unchanged. */
    if (a_negint && msg->type != NODUS_T3_TM_STEP && msg->type != NODUS_T3_TM_PROP)
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
                case NODUS_T3_CC_VOTE_REQ:
                    dec_cc_vote_req_args(&dec, args.count, &msg->cc_vote_req);
                    break;
                case NODUS_T3_CC_VOTE_RSP:
                    dec_cc_vote_rsp_args(&dec, args.count, &msg->cc_vote_rsp);
                    break;
                case NODUS_T3_CHAIN_Q:
                    dec_w_chain_q_args(&dec, args.count, &msg->w_chain_q);
                    break;
                case NODUS_T3_CHAIN_R:
                    dec_w_chain_r_args(&dec, args.count, &msg->w_chain_r);
                    break;
                case NODUS_T3_GENESIS_REQ:
                    dec_w_genesis_req_args(&dec, args.count,
                                            &msg->w_genesis_req);
                    break;
                case NODUS_T3_GENESIS_RSP:
                    dec_w_genesis_rsp_args(&dec, args.count,
                                            &msg->w_genesis_rsp);
                    break;
                case NODUS_T3_V2_BLOCK:
                    dec_w_v2_block_q_args(&dec, args.count,
                                          &msg->w_v2_block_q);
                    break;
                case NODUS_T3_V2_HEAD:
                    dec_w_v2_head_args(&dec, args.count, &msg->w_v2_head);
                    break;
                case NODUS_T3_V2_RANGE_REQ:
                    dec_w_v2_range_q_args(&dec, args.count,
                                          &msg->w_v2_range_q);
                    break;
                case NODUS_T3_V2_RANGE_RSP:
                    dec_w_v2_range_r_args(&dec, args.count,
                                          &msg->w_v2_range_r);
                    break;
                case NODUS_T3_V2_GBUNDLE_REQ:
                    dec_w_v2_gbundle_q_args(&dec, args.count,
                                            &msg->w_v2_gbundle_q);
                    break;
                case NODUS_T3_V2_GBUNDLE_RSP:
                    dec_w_v2_gbundle_r_args(&dec, args.count,
                                            &msg->w_v2_gbundle_r);
                    break;
                case NODUS_T3_VIEWOK:
                    dec_viewok_args(&dec, args.count, &msg->viewok);
                    break;
                case NODUS_T3_VIEWOK_REQ:
                    dec_viewok_q_args(&dec, args.count, &msg->viewok_q);
                    break;
                /* Tendermint T3 — all seven, so `default: break` (which
                 * would return 0 with a zeroed struct) can never be
                 * reached by a Tendermint verb. */
                case NODUS_T3_TM_STEP:
                    dec_tm_step_args(&dec, args.count, &msg->tm_step);
                    break;
                case NODUS_T3_TM_PROP:
                    dec_tm_prop_args(&dec, args.count, &msg->tm_prop);
                    break;
                case NODUS_T3_TM_POL:
                    dec_tm_pol_args(&dec, args.count, &msg->tm_pol);
                    break;
                case NODUS_T3_TM_VOTE:
                    dec_tm_vote_args(&dec, args.count, &msg->tm_vote);
                    break;
                case NODUS_T3_TM_HAS:
                    dec_tm_has_args(&dec, args.count, &msg->tm_has);
                    break;
                case NODUS_T3_TM_MAJ23:
                    dec_tm_maj23_args(&dec, args.count, &msg->tm_maj23);
                    break;
                case NODUS_T3_TM_BITS:
                    dec_tm_bits_args(&dec, args.count, &msg->tm_bits);
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

/* ── O15E Faz B — Ledger V2 successor sync arg decoders ──────────── */

static void dec_w_v2_block_q_args(cbor_decoder_t *dec, size_t count,
                                  nodus_t3_w_v2_block_q_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "h")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->height = val.uint_val;
        } else if (KEY_IS(key, "bi")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64)
                memcpy(m->block_id, val.bstr.ptr, 64);
        } else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_w_v2_head_args(cbor_decoder_t *dec, size_t count,
                               nodus_t3_w_v2_head_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "g")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64)
                memcpy(m->genesis_id, val.bstr.ptr, 64);
        } else if (KEY_IS(key, "hh")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->head = val.uint_val;
        } else if (KEY_IS(key, "pv")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                m->proto = (uint32_t)val.uint_val;
        } else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_w_v2_range_q_args(cbor_decoder_t *dec, size_t count,
                                  nodus_t3_w_v2_range_q_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "g")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64)
                memcpy(m->genesis_id, val.bstr.ptr, 64);
        } else if (KEY_IS(key, "fr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->from = val.uint_val;
        } else if (KEY_IS(key, "n")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT)
                m->count = (uint32_t)val.uint_val;
        } else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_w_v2_range_r_args(cbor_decoder_t *dec, size_t count,
                                  nodus_t3_w_v2_range_r_t *m) {
    /* Strict caps land HERE, pre-sig-verify (the H-2/A4 discipline):
     * an oversize or inconsistent response is a decode error and never
     * reaches the Dilithium5 verify. */
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "fr")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->from = val.uint_val;
        } else if (KEY_IS(key, "n")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) {
                if (val.uint_val > NODUS_T3_V2_RANGE_MAX_FRAMES) {
                    dec->error = true;
                    return;
                }
                m->n = (uint32_t)val.uint_val;
            }
        } else if (KEY_IS(key, "fl")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR) {
                if (val.bstr.len >
                        (size_t)NODUS_T3_V2_RANGE_MAX_FRAMES * 4 ||
                    (val.bstr.len % 4) != 0) {
                    dec->error = true;
                    return;
                }
                for (size_t k = 0; k < val.bstr.len / 4; k++) {
                    const uint8_t *p = val.bstr.ptr + k * 4;
                    m->frame_len[k] = ((uint32_t)p[0] << 24) |
                                      ((uint32_t)p[1] << 16) |
                                      ((uint32_t)p[2] << 8) |
                                      (uint32_t)p[3];
                }
            }
        } else if (KEY_IS(key, "fb")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR) {
                if (val.bstr.len > NODUS_T3_V2_RANGE_MAX_BYTES) {
                    dec->error = true;
                    return;
                }
                m->frames = val.bstr.ptr;
                m->frames_len = (uint32_t)val.bstr.len;
            }
        } else {
            cbor_decode_skip(dec);
        }
    }
    /* Cross-field consistency: the declared lengths must tile the
     * packed blob exactly, and every frame must be non-empty. */
    uint64_t sum = 0;
    for (uint32_t k = 0; k < m->n; k++) {
        if (m->frame_len[k] == 0) { dec->error = true; return; }
        sum += (uint64_t)m->frame_len[k];
    }
    if (sum != (uint64_t)m->frames_len) { dec->error = true; return; }
    if (m->n > 0 && !m->frames)         { dec->error = true; return; }
}

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
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64)
                memcpy(m->pin, val.bstr.ptr, 64);
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
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64)
                memcpy(m->pin, val.bstr.ptr, 64);
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

/* ── Tendermint T3 arg decoders (verbs 30-34) ────────────────────────
 *
 * STRICTER THAN EVERY DECODER ABOVE, AND THAT IS THE SPECIFICATION, not an
 * inconsistency: T2 wire design §4.2 requires the key set to be exact and
 * complete ("anahtar kümesi tam ve fazlasız, tip uyumsuz RED"). So, unlike
 * the legacy dec_*_args which skip an unknown key and leave a missing one
 * at zero, these five reject on
 *
 *   - a non-text key, an unknown key, or a key seen twice;
 *   - a value of the wrong CBOR type, or an integer that does not fit;
 *   - a byte string of the wrong length (bi 64, vid 32, sig 4627,
 *     bm 1..16);
 *   - a vote type byte other than D-12's 0x01 / 0x02;
 *   - a key set that is incomplete when the map ends.
 *
 * That exactness is what makes the codec bijective — encode(decode(b)) == b
 * and decode(encode(x)) == x (DG-13) — which a skip-unknown decoder cannot
 * be, because it maps many byte strings onto one struct.
 *
 * Rejection is `dec->error = true` and an immediate return: the existing
 * dec_w_v2_range_r_args idiom, which nodus_t3_decode turns into -1. */

/** Record that a key was present; a second sighting is a duplicate. */
static bool tm_seen_mark(cbor_decoder_t *dec, uint32_t *seen, uint32_t bit) {
    if (*seen & bit) { dec->error = true; return false; }
    *seen |= bit;
    return true;
}

static bool tm_get_u64(cbor_decoder_t *dec, uint64_t *out) {
    cbor_item_t val = cbor_decode_next(dec);
    if (val.type != CBOR_ITEM_UINT) { dec->error = true; return false; }
    *out = val.uint_val;
    return true;
}

static bool tm_get_u32(cbor_decoder_t *dec, uint32_t *out) {
    cbor_item_t val = cbor_decode_next(dec);
    if (val.type != CBOR_ITEM_UINT || val.uint_val > UINT32_MAX) {
        dec->error = true;
        return false;
    }
    *out = (uint32_t)val.uint_val;
    return true;
}

/** The vote type byte: D-12's CometBFT SignedMsgType values, nothing else. */
static bool tm_get_ty(cbor_decoder_t *dec, uint8_t *out) {
    cbor_item_t val = cbor_decode_next(dec);
    /* Range BEFORE the narrowing cast: 0x101 truncates to 0x01 and would
     * otherwise look like a valid PREVOTE. */
    if (val.type != CBOR_ITEM_UINT || val.uint_val > 0xFFu ||
        !t3_tm_ty_ok((uint8_t)val.uint_val)) {
        dec->error = true;
        return false;
    }
    *out = (uint8_t)val.uint_val;
    return true;
}

/** Exactly `want` bytes, copied out of the decode buffer. */
static bool tm_get_bstr_exact(cbor_decoder_t *dec, size_t want, uint8_t *out) {
    cbor_item_t val = cbor_decode_next(dec);
    if (val.type != CBOR_ITEM_BSTR || val.bstr.len != want) {
        dec->error = true;
        return false;
    }
    memcpy(out, val.bstr.ptr, want);
    return true;
}

/** A vote bitmap: 1..ceil(DNA_MAX_ACTIVE_VALIDATORS/8) bytes. The HOST
 *  checks bm_len == ceil(N/8) for the governing set; the codec only bounds
 *  it (T2 §4.2). */
static bool tm_get_bitmap(cbor_decoder_t *dec, uint8_t *out, uint8_t *out_len) {
    cbor_item_t val = cbor_decode_next(dec);
    if (val.type != CBOR_ITEM_BSTR ||
        val.bstr.len == 0 ||
        val.bstr.len > (size_t)NODUS_T3_TM_BITMAP_MAX) {
        dec->error = true;
        return false;
    }
    memcpy(out, val.bstr.ptr, val.bstr.len);
    *out_len = (uint8_t)val.bstr.len;
    return true;
}

/** A signed field, read through the only door to CBOR major type 1, then
 *  bounded. Used for lcr and vr (min -1, the reference's "none"; max
 *  INT32_MAX because both fields are i32). `sst` does NOT come through
 *  here: T2 §4.2 leaves it unconstrained, and a range check against the
 *  full int64_t span is a comparison that is always false — which
 *  -Wtype-limits would rightly reject. It calls cbor_decode_int directly. */
static bool tm_get_int_range(cbor_decoder_t *dec, int64_t min, int64_t max,
                             int64_t *out) {
    int64_t v = 0;
    if (!cbor_decode_int(dec, &v)) return false;   /* already set dec->error */
    if (v < min || v > max) {
        dec->error = true;
        return false;
    }
    *out = v;
    return true;
}

static void dec_tm_step_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_step_t *m) {
    enum { K_H = 1u << 0, K_R = 1u << 1, K_S = 1u << 2, K_SST = 1u << 3,
           K_LCR = 1u << 4,
           K_ALL = K_H | K_R | K_S | K_SST | K_LCR };
    uint32_t seen = 0;
    uint64_t u = 0;
    int64_t  s = 0;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "h")) {
            if (!tm_seen_mark(dec, &seen, K_H))          return;
            if (!tm_get_u64(dec, &m->h))                 return;
        } else if (KEY_IS(key, "r")) {
            if (!tm_seen_mark(dec, &seen, K_R))          return;
            if (!tm_get_u32(dec, &m->r))                 return;
        } else if (KEY_IS(key, "s")) {
            if (!tm_seen_mark(dec, &seen, K_S))          return;
            if (!tm_get_u64(dec, &u))                    return;
            if (u > NODUS_T3_TM_STEP_NEW_HEIGHT) { dec->error = true; return; }
            m->s = (uint8_t)u;
        } else if (KEY_IS(key, "sst")) {
            /* Any i64 (T2 §4.2: written, never read) — no range to apply,
             * so cbor_decode_int's own int64 bound is the whole rule. */
            if (!tm_seen_mark(dec, &seen, K_SST))        return;
            if (!cbor_decode_int(dec, &m->sst))          return;
        } else if (KEY_IS(key, "lcr")) {
            if (!tm_seen_mark(dec, &seen, K_LCR))        return;
            if (!tm_get_int_range(dec, -1, INT32_MAX, &s)) return;
            m->lcr = (int32_t)s;
        } else {
            dec->error = true; return;
        }
    }
    if (seen != (uint32_t)K_ALL) dec->error = true;   /* a key was missing */
}

static void dec_tm_prop_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_prop_t *m) {
    enum { K_H = 1u << 0, K_R = 1u << 1, K_VR = 1u << 2, K_V = 1u << 3,
           K_ALL = K_H | K_R | K_VR | K_V };
    uint32_t seen = 0;
    int64_t  s = 0;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "h")) {
            if (!tm_seen_mark(dec, &seen, K_H))          return;
            if (!tm_get_u64(dec, &m->h))                 return;
        } else if (KEY_IS(key, "r")) {
            if (!tm_seen_mark(dec, &seen, K_R))          return;
            if (!tm_get_u32(dec, &m->r))                 return;
        } else if (KEY_IS(key, "vr")) {
            if (!tm_seen_mark(dec, &seen, K_VR))         return;
            if (!tm_get_int_range(dec, -1, INT32_MAX, &s)) return;
            m->vr = (int32_t)s;
        } else if (KEY_IS(key, "v")) {
            /* ZERO-COPY, like w_v2_range_r.frames: `v` points INTO the
             * decode buffer and is valid only while that buffer lives.
             * 2.8 MB is not copied here, and the class buffer
             * (NODUS_T3_TM_PROP_MAX_MSG) is what bounds it. */
            if (!tm_seen_mark(dec, &seen, K_V))          return;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR ||
                val.bstr.len == 0 ||
                val.bstr.len > (size_t)DNA_TM_VALUE_MAX_LEN) {
                dec->error = true;
                return;
            }
            m->v     = val.bstr.ptr;
            m->v_len = (uint32_t)val.bstr.len;
        } else {
            dec->error = true; return;
        }
    }
    if (seen != (uint32_t)K_ALL) dec->error = true;   /* a key was missing */
}

static void dec_tm_pol_args(cbor_decoder_t *dec, size_t count,
                            nodus_t3_tm_pol_t *m) {
    enum { K_H = 1u << 0, K_PR = 1u << 1, K_BM = 1u << 2,
           K_ALL = K_H | K_PR | K_BM };
    uint32_t seen = 0;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "h")) {
            if (!tm_seen_mark(dec, &seen, K_H))          return;
            if (!tm_get_u64(dec, &m->h))                 return;
        } else if (KEY_IS(key, "pr")) {
            if (!tm_seen_mark(dec, &seen, K_PR))         return;
            if (!tm_get_u32(dec, &m->pr))                return;
        } else if (KEY_IS(key, "bm")) {
            if (!tm_seen_mark(dec, &seen, K_BM))         return;
            if (!tm_get_bitmap(dec, m->bm, &m->bm_len))  return;
        } else {
            dec->error = true; return;
        }
    }
    if (seen != (uint32_t)K_ALL) dec->error = true;   /* a key was missing */
}

static void dec_tm_vote_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_vote_t *m) {
    enum { K_TY = 1u << 0, K_H = 1u << 1, K_R = 1u << 2, K_BI = 1u << 3,
           K_VID = 1u << 4, K_IX = 1u << 5, K_TS = 1u << 6, K_SIG = 1u << 7,
           K_ALL = K_TY | K_H | K_R | K_BI | K_VID | K_IX | K_TS | K_SIG };
    uint32_t seen = 0;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "ty")) {
            if (!tm_seen_mark(dec, &seen, K_TY))         return;
            if (!tm_get_ty(dec, &m->ty))                 return;
        } else if (KEY_IS(key, "h")) {
            if (!tm_seen_mark(dec, &seen, K_H))          return;
            if (!tm_get_u64(dec, &m->h))                 return;
        } else if (KEY_IS(key, "r")) {
            if (!tm_seen_mark(dec, &seen, K_R))          return;
            if (!tm_get_u32(dec, &m->r))                 return;
        } else if (KEY_IS(key, "bi")) {
            if (!tm_seen_mark(dec, &seen, K_BI))         return;
            if (!tm_get_bstr_exact(dec, 64, m->bi))      return;
        } else if (KEY_IS(key, "vid")) {
            if (!tm_seen_mark(dec, &seen, K_VID))        return;
            if (!tm_get_bstr_exact(dec, 32, m->vid))     return;
        } else if (KEY_IS(key, "ix")) {
            if (!tm_seen_mark(dec, &seen, K_IX))         return;
            if (!tm_get_u32(dec, &m->ix))                return;
        } else if (KEY_IS(key, "ts")) {
            if (!tm_seen_mark(dec, &seen, K_TS))         return;
            if (!tm_get_u64(dec, &m->ts))                return;
        } else if (KEY_IS(key, "sig")) {
            /* The INNER vote signature. Carried and length-checked here;
             * VERIFIED by the host in wave 2 (D-16 rev 4, vote-admission
             * step 3), never by this codec. */
            if (!tm_seen_mark(dec, &seen, K_SIG))        return;
            if (!tm_get_bstr_exact(dec, QGP_DSA87_SIGNATURE_BYTES, m->sig))
                return;
        } else {
            dec->error = true; return;
        }
    }
    if (seen != (uint32_t)K_ALL) dec->error = true;   /* a key was missing */
}

static void dec_tm_has_args(cbor_decoder_t *dec, size_t count,
                            nodus_t3_tm_has_t *m) {
    enum { K_H = 1u << 0, K_R = 1u << 1, K_TY = 1u << 2, K_IX = 1u << 3,
           K_ALL = K_H | K_R | K_TY | K_IX };
    uint32_t seen = 0;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "h")) {
            if (!tm_seen_mark(dec, &seen, K_H))          return;
            if (!tm_get_u64(dec, &m->h))                 return;
        } else if (KEY_IS(key, "r")) {
            if (!tm_seen_mark(dec, &seen, K_R))          return;
            if (!tm_get_u32(dec, &m->r))                 return;
        } else if (KEY_IS(key, "ty")) {
            if (!tm_seen_mark(dec, &seen, K_TY))         return;
            if (!tm_get_ty(dec, &m->ty))                 return;
        } else if (KEY_IS(key, "ix")) {
            if (!tm_seen_mark(dec, &seen, K_IX))         return;
            if (!tm_get_u32(dec, &m->ix))                return;
        } else {
            dec->error = true; return;
        }
    }
    if (seen != (uint32_t)K_ALL) dec->error = true;   /* a key was missing */
}

static void dec_tm_maj23_args(cbor_decoder_t *dec, size_t count,
                              nodus_t3_tm_maj23_t *m) {
    enum { K_H = 1u << 0, K_R = 1u << 1, K_TY = 1u << 2, K_BI = 1u << 3,
           K_ALL = K_H | K_R | K_TY | K_BI };
    uint32_t seen = 0;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "h")) {
            if (!tm_seen_mark(dec, &seen, K_H))          return;
            if (!tm_get_u64(dec, &m->h))                 return;
        } else if (KEY_IS(key, "r")) {
            if (!tm_seen_mark(dec, &seen, K_R))          return;
            if (!tm_get_u32(dec, &m->r))                 return;
        } else if (KEY_IS(key, "ty")) {
            if (!tm_seen_mark(dec, &seen, K_TY))         return;
            if (!tm_get_ty(dec, &m->ty))                 return;
        } else if (KEY_IS(key, "bi")) {
            if (!tm_seen_mark(dec, &seen, K_BI))         return;
            if (!tm_get_bstr_exact(dec, 64, m->bi))      return;
        } else {
            dec->error = true; return;
        }
    }
    if (seen != (uint32_t)K_ALL) dec->error = true;   /* a key was missing */
}

static void dec_tm_bits_args(cbor_decoder_t *dec, size_t count,
                             nodus_t3_tm_bits_t *m) {
    enum { K_H = 1u << 0, K_R = 1u << 1, K_TY = 1u << 2, K_BI = 1u << 3,
           K_BM = 1u << 4,
           K_ALL = K_H | K_R | K_TY | K_BI | K_BM };
    uint32_t seen = 0;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "h")) {
            if (!tm_seen_mark(dec, &seen, K_H))          return;
            if (!tm_get_u64(dec, &m->h))                 return;
        } else if (KEY_IS(key, "r")) {
            if (!tm_seen_mark(dec, &seen, K_R))          return;
            if (!tm_get_u32(dec, &m->r))                 return;
        } else if (KEY_IS(key, "ty")) {
            if (!tm_seen_mark(dec, &seen, K_TY))         return;
            if (!tm_get_ty(dec, &m->ty))                 return;
        } else if (KEY_IS(key, "bi")) {
            if (!tm_seen_mark(dec, &seen, K_BI))         return;
            if (!tm_get_bstr_exact(dec, 64, m->bi))      return;
        } else if (KEY_IS(key, "bm")) {
            if (!tm_seen_mark(dec, &seen, K_BM))         return;
            if (!tm_get_bitmap(dec, m->bm, &m->bm_len))  return;
        } else {
            dec->error = true; return;
        }
    }
    if (seen != (uint32_t)K_ALL) dec->error = true;   /* a key was missing */
}

/* ── Public verify ───────────────────────────────────────────────── */

int nodus_t3_verify(const nodus_t3_msg_t *msg, const nodus_pubkey_t *pk) {
    if (!msg || !pk || !msg->wsig) return -1;

    /* Heap-allocate sign buffer at NODUS_W_MAX_SYNC_RSP_SIZE (1 MB) so
     * sync_rsp / COMMIT / PROPOSE messages whose {q, wh, a} payload
     * exceeds the 128 KB NODUS_T3_MAX_MSG_SIZE — produced by the
     * matching sender caps in nodus_witness_sync.c:647 and
     * nodus_witness_bft.c — verify symmetrically.
     *
     * D-14 rev 2 / G19: the Tendermint verbs 28-34 instead take their PER-
     * CLASS bound, so a 2.8 MB PROPOSAL can be verified while a vote or a
     * step announcement never reserves more than its class. The legacy
     * branch is written as the literal it always was, not routed through
     * nodus_t3_max_msg_size, so "legacy allocation unchanged" is visible in
     * this function rather than inferred from another one. */
    size_t sign_cap = (msg->type >= NODUS_T3_TM_STEP &&
                       msg->type <= NODUS_T3_TM_BITS)
                      ? nodus_t3_max_msg_size(msg->type)
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
