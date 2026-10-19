/**
 * @file shared/dht2/dht2_envelope.c
 * @brief DHT v2 — RFC 0002 Signed Envelope + the owner-signed LIST request.
 *        See dht2_envelope.h for the design rows, references and named
 *        deviations.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dht2/dht2_envelope.h"
#include "dht2/dht2_cbor.h"
#include "dht2/dht2_record.h"   /* dht2_fp, dht2_id_inbox */

#include "crypto/sign/qgp_dilithium.h"
#include "dnac/cmt_pb_wire.h"   /* r_tag / r_ld / pb_skip: the ONE proto3 reader */

#include <stdlib.h>
#include <string.h>

/* RFC/0002-signed-envelopes.md:76-100 field numbers. */
#define ENV_F_PUBKEY   1u
#define ENV_F_TYPE     2u
#define ENV_F_PAYLOAD  3u
#define ENV_F_SIG      5u

/* A marshalled PublicKey{9: 2592 B}: tag 0x4a, uvarint(2592) = a0 14. */
#define PK_MSG_LEN (1u + 2u + DHT2_PUBKEY_LEN)

/* LIST payload keys (row 23), in canonical order (length, then bytes). */
#define LK_C      "c"
#define LK_N      "n"
#define LK_OP     "op"
#define LK_INBOX  "inbox"
#define LK_CURSOR "cursor"
#define LIST_OP   "list"
/* The payload's largest encoding: map head 1; "c" 2 + 2 + 32; "n" 2 + 2 +
 * 32; "op" 3 + "list" 5; "inbox" 6 + 2 + 64; "cursor" 7 + 2 + 64. */
#define LIST_PAYLOAD_MAX (1u + 36u + 36u + 8u + 72u + 73u)

/* ══ the signed buffer (RFC 0002 :104-116) ═════════════════════════════ */

/* uvarint(len domain) ‖ domain ‖ uvarint(len type) ‖ type ‖ uvarint(len
 * payload) ‖ payload, into a fresh heap buffer the caller frees. */
static int signed_buffer(const char *domain, const uint8_t *pt, size_t pt_len,
                         const uint8_t *pl, size_t pl_len,
                         uint8_t **out, size_t *out_len)
{
    size_t   dl = strlen(domain);
    size_t   total, off = 0;
    uint8_t *b;

    /* Each part ≤ SIZE_MAX / 4, so the sum plus three ≤ 10-byte uvarints
     * cannot wrap. */
    if (pt_len > SIZE_MAX / 4 || pl_len > SIZE_MAX / 4 || dl > SIZE_MAX / 4) {
        return -1;
    }
    total = cmt_pb_uvarint_size(dl) + dl +
            cmt_pb_uvarint_size(pt_len) + pt_len +
            cmt_pb_uvarint_size(pl_len) + pl_len;
    b = (uint8_t *)malloc(total == 0 ? 1 : total);
    if (b == NULL) {
        return -1;
    }
    if (cmt_pb_put_uvarint(b, total, &off, (uint64_t)dl) != CMT_OK) {
        goto fail;
    }
    memcpy(b + off, domain, dl);
    off += dl;
    if (cmt_pb_put_uvarint(b, total, &off, (uint64_t)pt_len) != CMT_OK) {
        goto fail;
    }
    if (pt_len != 0) {
        memcpy(b + off, pt, pt_len);
    }
    off += pt_len;
    if (cmt_pb_put_uvarint(b, total, &off, (uint64_t)pl_len) != CMT_OK) {
        goto fail;
    }
    if (pl_len != 0) {
        memcpy(b + off, pl, pl_len);
    }
    off += pl_len;
    *out = b;
    *out_len = off;
    return 0;
fail:
    free(b);
    return -1;
}

/* ══ envelope encode ═══════════════════════════════════════════════════ */

/* tag ‖ uvarint(n) ‖ bytes, omit-empty (cmt_pb.h:26 rule a); `out` NULL →
 * count only. */
static int put_ld(uint8_t *out, size_t cap, size_t *off, uint32_t field,
                  const uint8_t *p, size_t n)
{
    uint64_t tag = ((uint64_t)field << 3) | 2u;
    size_t   need;

    if (n == 0) {
        return 0;
    }
    need = cmt_pb_uvarint_size(tag) + cmt_pb_uvarint_size((uint64_t)n);
    if (n > SIZE_MAX - need || *off > SIZE_MAX - need - n) {
        return -1;
    }
    if (out == NULL) {
        *off += need + n;
        return 0;
    }
    if (cmt_pb_put_uvarint(out, cap, off, tag) != CMT_OK ||
        cmt_pb_put_uvarint(out, cap, off, (uint64_t)n) != CMT_OK ||
        n > cap - *off) {
        return -1;
    }
    memcpy(out + *off, p, n);
    *off += n;
    return 0;
}

int dht2_env_seal(const char *domain,
                  const uint8_t *payload_type, size_t payload_type_len,
                  const uint8_t *payload, size_t payload_len,
                  const uint8_t *sk, const uint8_t pk[DHT2_PUBKEY_LEN],
                  uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_public_key_t pkv;
    uint8_t             pkm[PK_MSG_LEN];
    uint8_t             sig[DHT2_SIG_LEN];
    size_t              pkm_len = 0, siglen = 0, total = 0, off = 0;
    uint8_t            *sb = NULL;
    size_t              sb_len = 0;
    int                 rc;

    if (domain == NULL || pk == NULL || out_len == NULL ||
        (payload_type == NULL && payload_type_len != 0) ||
        (payload == NULL && payload_len != 0) ||
        (out != NULL && sk == NULL) ||
        strlen(domain) > QGP_DSA87_CTX_MAX_BYTES) {
        return DHT2_E_ARG;
    }
    pkv.present = true;
    memcpy(pkv.key, pk, DHT2_PUBKEY_LEN);
    if (cmt_pb_public_key_marshal(&pkv, pkm, sizeof(pkm), &pkm_len)
        != CMT_OK) {
        return DHT2_E_ARG;
    }
    /* Size: field 1 (embedded message, present), 2, 3, 5 — ascending. */
    if (put_ld(NULL, 0, &total, ENV_F_PUBKEY, pkm, pkm_len) != 0 ||
        put_ld(NULL, 0, &total, ENV_F_TYPE, payload_type,
               payload_type_len) != 0 ||
        put_ld(NULL, 0, &total, ENV_F_PAYLOAD, payload, payload_len) != 0 ||
        put_ld(NULL, 0, &total, ENV_F_SIG, sig, DHT2_SIG_LEN) != 0) {
        return DHT2_E_ARG;
    }
    if (out == NULL) {
        *out_len = total;
        return DHT2_OK;
    }
    if (cap < total) {
        return DHT2_E_ARG;
    }

    if (signed_buffer(domain, payload_type, payload_type_len, payload,
                      payload_len, &sb, &sb_len) != 0) {
        return DHT2_E_HOLDER_FAULT;
    }
    /* Hedged ML-DSA-87, ctx = the domain (§4.4 named deviation). */
    rc = qgp_dsa87_sign_ctx(sig, &siglen, sb, sb_len,
                            (const uint8_t *)domain, strlen(domain), sk);
    free(sb);
    if (rc != 0 || siglen != DHT2_SIG_LEN) {
        return DHT2_E_HOLDER_FAULT;
    }
    if (put_ld(out, cap, &off, ENV_F_PUBKEY, pkm, pkm_len) != 0 ||
        put_ld(out, cap, &off, ENV_F_TYPE, payload_type,
               payload_type_len) != 0 ||
        put_ld(out, cap, &off, ENV_F_PAYLOAD, payload, payload_len) != 0 ||
        put_ld(out, cap, &off, ENV_F_SIG, sig, DHT2_SIG_LEN) != 0) {
        return DHT2_E_ARG;
    }
    *out_len = off;
    return DHT2_OK;
}

/* ══ envelope decode / verify ══════════════════════════════════════════ */

int dht2_env_decode(const uint8_t *in, size_t len, size_t max_len,
                    dht2_env_t *env)
{
    size_t i = 0;

    if (env == NULL || (in == NULL && len != 0)) {
        return DHT2_E_ARG;
    }
    memset(env, 0, sizeof(*env));
    if (len > max_len) {
        return DHT2_E_TOO_LARGE;          /* bounded BEFORE any decode */
    }
    while (i < len) {
        size_t         start = i;
        int32_t        fieldnum;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return DHT2_E_BAD_ENCODING;
        }
        switch (fieldnum) {
        case (int32_t)ENV_F_PUBKEY: {
            cmt_pb_public_key_t tmp;

            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return DHT2_E_BAD_ENCODING;
            }
            /* A non-repeated embedded message is MERGED (cmt_pb.h:46-52):
             * PublicKey's only field is 9, so a later occurrence that
             * carries the key replaces it and an empty one keeps it. */
            if (cmt_pb_public_key_unmarshal(p, n, &tmp) != CMT_OK) {
                return DHT2_E_BAD_ENCODING;
            }
            if (tmp.present) {
                env->pk = tmp;
            }
            break;
        }
        case (int32_t)ENV_F_TYPE:
        case (int32_t)ENV_F_PAYLOAD:
        case (int32_t)ENV_F_SIG:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return DHT2_E_BAD_ENCODING;
            }
            if (fieldnum == (int32_t)ENV_F_TYPE) {
                env->payload_type = p;
                env->payload_type_len = n;
            } else if (fieldnum == (int32_t)ENV_F_PAYLOAD) {
                env->payload = p;
                env->payload_len = n;
            } else {
                env->sig = p;
                env->sig_len = n;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return DHT2_E_BAD_ENCODING;
            }
            break;
        }
    }
    /* RFC 0002 :96 — the recipient derives the signer from this key. */
    if (!env->pk.present) {
        return DHT2_E_BAD_ENCODING;
    }
    if (dht2_fp(env->pk.key, env->fp) != 0) {
        return DHT2_E_HOLDER_FAULT;
    }
    return DHT2_OK;
}

int dht2_env_verify(const dht2_env_t *env, const char *domain)
{
    uint8_t *sb = NULL;
    size_t   sb_len = 0;
    int      rc;

    if (env == NULL || domain == NULL ||
        strlen(domain) > QGP_DSA87_CTX_MAX_BYTES) {
        return DHT2_E_ARG;
    }
    if (!env->pk.present || env->sig == NULL || env->sig_len != DHT2_SIG_LEN) {
        return DHT2_E_BAD_SIGNATURE;
    }
    if (signed_buffer(domain, env->payload_type, env->payload_type_len,
                      env->payload, env->payload_len, &sb, &sb_len) != 0) {
        return DHT2_E_HOLDER_FAULT;
    }
    rc = qgp_dsa87_verify_ctx(env->sig, env->sig_len, sb, sb_len,
                              (const uint8_t *)domain, strlen(domain),
                              env->pk.key);
    free(sb);
    return (rc == 0) ? DHT2_OK : DHT2_E_BAD_SIGNATURE;
}

/* ══ LIST request payload (row 23) ═════════════════════════════════════ */

static void list_emit(const dht2_list_req_t *req, dht2_cbor_wr_t *w)
{
    dht2_cbor_wr_map(w, req->has_cursor ? 5u : 4u);
    dht2_cbor_wr_key(w, LK_C);
    dht2_cbor_wr_bytes(w, req->chain, DHT2_CHAIN_LEN);
    dht2_cbor_wr_key(w, LK_N);
    dht2_cbor_wr_bytes(w, req->nonce, DHT2_NONCE_LEN);
    dht2_cbor_wr_key(w, LK_OP);
    dht2_cbor_wr_text(w, (const uint8_t *)LIST_OP, strlen(LIST_OP));
    dht2_cbor_wr_key(w, LK_INBOX);
    dht2_cbor_wr_bytes(w, req->inbox, DHT2_ID_LEN);
    if (req->has_cursor) {
        dht2_cbor_wr_key(w, LK_CURSOR);
        dht2_cbor_wr_bytes(w, req->cursor, DHT2_FP_LEN);
    }
}

int dht2_list_payload_encode(const dht2_list_req_t *req, uint8_t *out,
                             size_t cap, size_t *out_len)
{
    dht2_cbor_wr_t w;

    if (req == NULL || out_len == NULL) {
        return DHT2_E_ARG;
    }
    if (out == NULL) {
        dht2_cbor_wr_init_count(&w);
    } else {
        dht2_cbor_wr_init(&w, out, cap);
    }
    list_emit(req, &w);
    if (!dht2_cbor_wr_ok(&w)) {
        return DHT2_E_ARG;
    }
    *out_len = w.len;
    return DHT2_OK;
}

int dht2_list_payload_decode(const uint8_t *in, size_t len,
                             dht2_list_req_t *req)
{
    dht2_cbor_rd_t r;
    dht2_cbor_wr_t w;
    uint64_t       nkeys, i;
    const uint8_t *prev = NULL;
    size_t         prev_len = 0;
    bool           seen_c = false, seen_n = false, seen_op = false;
    bool           seen_inbox = false;

    if (req == NULL || (in == NULL && len != 0)) {
        return DHT2_E_ARG;
    }
    memset(req, 0, sizeof(*req));
    dht2_cbor_rd_init(&r, in, len);
    if (dht2_cbor_rd_map(&r, &nkeys) != 0 || nkeys < 4u || nkeys > 5u) {
        return DHT2_E_MALFORMED_REQ;
    }
    for (i = 0; i < nkeys; i++) {
        const uint8_t *k, *p;
        size_t         kl, n;

        if (dht2_cbor_rd_key(&r, prev, prev_len, &k, &kl) != 0) {
            return DHT2_E_MALFORMED_REQ;
        }
        prev = k;
        prev_len = kl;
        if (dht2_cbor_key_is(k, kl, LK_C)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 || n != DHT2_CHAIN_LEN) {
                return DHT2_E_MALFORMED_REQ;
            }
            memcpy(req->chain, p, DHT2_CHAIN_LEN);
            seen_c = true;
        } else if (dht2_cbor_key_is(k, kl, LK_N)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 || n != DHT2_NONCE_LEN) {
                return DHT2_E_MALFORMED_REQ;      /* row 7: nonce ≠ 32 B */
            }
            memcpy(req->nonce, p, DHT2_NONCE_LEN);
            seen_n = true;
        } else if (dht2_cbor_key_is(k, kl, LK_OP)) {
            if (dht2_cbor_rd_text(&r, &p, &n) != 0 ||
                !dht2_cbor_key_is(p, n, LIST_OP)) {
                return DHT2_E_MALFORMED_REQ;      /* unknown operation */
            }
            seen_op = true;
        } else if (dht2_cbor_key_is(k, kl, LK_INBOX)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 || n != DHT2_ID_LEN) {
                return DHT2_E_MALFORMED_REQ;
            }
            memcpy(req->inbox, p, DHT2_ID_LEN);
            seen_inbox = true;
        } else if (dht2_cbor_key_is(k, kl, LK_CURSOR)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 || n != DHT2_FP_LEN) {
                return DHT2_E_MALFORMED_REQ;      /* row 7: a bad cursor */
            }
            memcpy(req->cursor, p, DHT2_FP_LEN);
            req->has_cursor = true;
        } else {
            return DHT2_E_MALFORMED_REQ;
        }
    }
    if (!dht2_cbor_rd_done(&r) || !seen_c || !seen_n || !seen_op ||
        !seen_inbox) {
        return DHT2_E_MALFORMED_REQ;
    }
    dht2_cbor_wr_init_compare(&w, in, len);       /* re-encode identity */
    list_emit(req, &w);
    if (!dht2_cbor_wr_ok(&w)) {
        return DHT2_E_MALFORMED_REQ;
    }
    return DHT2_OK;
}

int dht2_list_req_build(const dht2_list_req_t *req, const uint8_t *sk,
                        const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out,
                        size_t cap, size_t *out_len)
{
    uint8_t payload[LIST_PAYLOAD_MAX];
    size_t  plen = 0;
    int     rc;

    if (req == NULL || out_len == NULL) {
        return DHT2_E_ARG;
    }
    rc = dht2_list_payload_encode(req, payload, sizeof(payload), &plen);
    if (rc != DHT2_OK) {
        return rc;
    }
    return dht2_env_seal(DHT2_DOMAIN_LIST,
                         (const uint8_t *)DHT2_PT_LIST, strlen(DHT2_PT_LIST),
                         payload, plen, sk, pk, out, cap, out_len);
}

int dht2_list_req_open(const uint8_t *in, size_t len,
                       const uint8_t local_chain[DHT2_CHAIN_LEN],
                       dht2_list_req_t *req, uint8_t *owner_fp)
{
    dht2_env_t env;
    uint8_t    inbox[DHT2_ID_LEN];
    int        rc;

    if (req == NULL || local_chain == NULL || (in == NULL && len != 0)) {
        return DHT2_E_ARG;
    }
    rc = dht2_env_decode(in, len, DHT2_ENVELOPE_MAX, &env);
    if (rc == DHT2_E_HOLDER_FAULT) {
        return rc;
    }
    if (rc != DHT2_OK) {
        return DHT2_E_MALFORMED_REQ;
    }
    if (env.payload_type_len != strlen(DHT2_PT_LIST) ||
        memcmp(env.payload_type, DHT2_PT_LIST, env.payload_type_len) != 0) {
        return DHT2_E_MALFORMED_REQ;
    }
    rc = dht2_list_payload_decode(env.payload, env.payload_len, req);
    if (rc != DHT2_OK) {
        return DHT2_E_MALFORMED_REQ;
    }
    if (memcmp(req->chain, local_chain, DHT2_CHAIN_LEN) != 0) {
        return DHT2_E_BAD_CHAIN;
    }
    rc = dht2_env_verify(&env, DHT2_DOMAIN_LIST);
    if (rc != DHT2_OK) {
        return rc;
    }
    /* Row 23: the holder recomputes SHA3-512(`nodus.dht.inbox.v1` ‖ c ‖
     * SHA3-512(signer key)) and requires it to equal `inbox`. */
    if (dht2_id_inbox(req->chain, env.fp, inbox) != 0) {
        return DHT2_E_HOLDER_FAULT;
    }
    if (memcmp(inbox, req->inbox, DHT2_ID_LEN) != 0) {
        return DHT2_E_NOT_OWNER;
    }
    if (owner_fp != NULL) {
        memcpy(owner_fp, env.fp, DHT2_FP_LEN);
    }
    return DHT2_OK;
}
