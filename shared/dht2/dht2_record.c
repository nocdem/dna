/**
 * @file shared/dht2/dht2_record.c
 * @brief DHT v2 — the signed record. See dht2_record.h for the design
 *        sections, references, named deviations and code readings.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dht2/dht2_record.h"
#include "dht2/dht2_cbor.h"
#include "dht2/dht2_time.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "dnac/cmt_pb_wire.h"   /* r_tag / r_ld / pb_skip: the ONE proto3 reader */
#include "dnac/res_meter.h"     /* dna_ck_add_u64 */

#include <stdlib.h>
#include <string.h>

/* IpnsEntry field numbers, ipns-record.md:195-238. */
#define IPNS_F_PUBKEY  7u
#define IPNS_F_SIG_V2  8u
#define IPNS_F_DATA    9u

/* A marshalled PublicKey{9: 2592 B}: tag 0x4a, uvarint(2592) = a0 14. */
#define PK_MSG_LEN (1u + 2u + DHT2_PUBKEY_LEN)

/* §13 row 15: entry = fp 64 ‖ mark 1 ‖ through 8 (u64 BE); ≤ 3,500. */
#define CTL_ENTRY_LEN   (DHT2_FP_LEN + 1u + 8u)
#define CTL_ENTRIES_MAX 3500u
#define CTL_MARK_HANDLED 1u
#define CTL_MARK_DENIED  2u

/* The data map's eleven keys (§3.1, §13 row 5). */
#define K_TTL          "TTL"
#define K_ID           "_id"
#define K_DEL          "_del"
#define K_VALUE        "Value"
#define K_DATA         "_data"
#define K_PREV         "_prev"
#define K_CHAIN        "_chain"
#define K_CLASS        "_class"
#define K_SEQUENCE     "Sequence"
#define K_VALIDITY     "Validity"
#define K_VALIDITYTYPE "ValidityType"
#define DATA_KEYS_MIN  8u      /* the eight every record carries */
#define DATA_KEYS_MAX  11u

/* ══ small helpers ═════════════════════════════════════════════════════ */

int dht2_bytes_compare(const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen)
{
    size_t n = (alen < blen) ? alen : blen;
    int    c = (n == 0) ? 0 : memcmp(a, b, n);

    if (c != 0) {
        return (c < 0) ? -1 : 1;
    }
    if (alen == blen) {
        return 0;
    }
    return (alen < blen) ? -1 : 1;
}

int dht2_fp(const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t out[DHT2_FP_LEN])
{
    if (pk == NULL || out == NULL) {
        return -1;
    }
    return qgp_sha3_512(pk, DHT2_PUBKEY_LEN, out) == 0 ? 0 : -1;
}

int dht2_address(const uint8_t id[DHT2_ID_LEN],
                 const uint8_t owner_fp[DHT2_FP_LEN],
                 uint8_t out[DHT2_HASH_LEN])
{
    uint8_t pre[DHT2_ID_LEN + DHT2_FP_LEN];

    if (id == NULL || owner_fp == NULL || out == NULL) {
        return -1;
    }
    /* Bee pkg/soc/soc.go:199-207 — hash(id, owner), in that order. */
    memcpy(pre, id, DHT2_ID_LEN);
    memcpy(pre + DHT2_ID_LEN, owner_fp, DHT2_FP_LEN);
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dht2_id(const char *label, const uint8_t chain[DHT2_CHAIN_LEN],
            const uint8_t *params, size_t params_len,
            uint8_t out[DHT2_ID_LEN])
{
    size_t   llen, total;
    uint8_t *pre;
    int      rc;

    if (label == NULL || chain == NULL || out == NULL ||
        (params == NULL && params_len != 0)) {
        return -1;
    }
    llen = strlen(label);
    if (params_len > SIZE_MAX - llen - DHT2_CHAIN_LEN) {
        return -1;
    }
    total = llen + DHT2_CHAIN_LEN + params_len;
    pre = (uint8_t *)malloc(total);
    if (pre == NULL) {
        return -1;
    }
    memcpy(pre, label, llen);
    memcpy(pre + llen, chain, DHT2_CHAIN_LEN);
    if (params_len != 0) {
        memcpy(pre + llen + DHT2_CHAIN_LEN, params, params_len);
    }
    rc = (qgp_sha3_512(pre, total, out) == 0) ? 0 : -1;
    free(pre);
    return rc;
}

int dht2_id_feed_entry(const uint8_t topic[DHT2_HASH_LEN], uint64_t index,
                       uint8_t out[DHT2_ID_LEN])
{
    uint8_t pre[DHT2_HASH_LEN + 8];
    int     k;

    if (topic == NULL || out == NULL) {
        return -1;
    }
    memcpy(pre, topic, DHT2_HASH_LEN);
    for (k = 0; k < 8; k++) {        /* 8-byte big-endian, sequence.go:47-51 */
        pre[DHT2_HASH_LEN + (size_t)k] = (uint8_t)(index >> (8 * (7 - k)));
    }
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dht2_id_feed_head(const uint8_t chain[DHT2_CHAIN_LEN],
                      const uint8_t topic[DHT2_HASH_LEN],
                      uint8_t out[DHT2_ID_LEN])
{
    return dht2_id(DHT2_LABEL_HEAD, chain, topic, DHT2_HASH_LEN, out);
}

int dht2_id_inbox(const uint8_t chain[DHT2_CHAIN_LEN],
                  const uint8_t recipient_fp[DHT2_FP_LEN],
                  uint8_t out[DHT2_ID_LEN])
{
    return dht2_id(DHT2_LABEL_INBOX, chain, recipient_fp, DHT2_FP_LEN, out);
}

int dht2_id_inbox_ctl(const uint8_t chain[DHT2_CHAIN_LEN],
                      const uint8_t recipient_fp[DHT2_FP_LEN],
                      uint8_t out[DHT2_ID_LEN])
{
    return dht2_id(DHT2_LABEL_INBOX_CTL, chain, recipient_fp, DHT2_FP_LEN,
                   out);
}

int dht2_id_dm(const uint8_t chain[DHT2_CHAIN_LEN],
               const uint8_t recipient_fp[DHT2_FP_LEN],
               const uint8_t salt[DHT2_SALT_LEN],
               uint8_t out[DHT2_ID_LEN])
{
    uint8_t params[DHT2_FP_LEN + DHT2_SALT_LEN];

    if (recipient_fp == NULL || salt == NULL) {
        return -1;
    }
    memcpy(params, recipient_fp, DHT2_FP_LEN);
    memcpy(params + DHT2_FP_LEN, salt, DHT2_SALT_LEN);
    return dht2_id(DHT2_LABEL_DM, chain, params, sizeof(params), out);
}

int dht2_id_group_head(const uint8_t chain[DHT2_CHAIN_LEN],
                       const uint8_t group_id[DHT2_GROUP_ID_LEN],
                       uint8_t out[DHT2_ID_LEN])
{
    return dht2_id(DHT2_LABEL_GROUP_HEAD, chain, group_id,
                   DHT2_GROUP_ID_LEN, out);
}

/* group id ‖ key version u32 BE — the params of the record and key-packet
 * ids. */
static int id_group_versioned(const char *label,
                              const uint8_t chain[DHT2_CHAIN_LEN],
                              const uint8_t group_id[DHT2_GROUP_ID_LEN],
                              uint32_t key_version, uint8_t out[DHT2_ID_LEN])
{
    uint8_t params[DHT2_GROUP_ID_LEN + DHT2_KEY_VERSION_LEN];

    if (group_id == NULL) {
        return -1;
    }
    memcpy(params, group_id, DHT2_GROUP_ID_LEN);
    params[DHT2_GROUP_ID_LEN + 0] = (uint8_t)(key_version >> 24);
    params[DHT2_GROUP_ID_LEN + 1] = (uint8_t)(key_version >> 16);
    params[DHT2_GROUP_ID_LEN + 2] = (uint8_t)(key_version >> 8);
    params[DHT2_GROUP_ID_LEN + 3] = (uint8_t)key_version;
    return dht2_id(label, chain, params, sizeof(params), out);
}

int dht2_id_group_record(const uint8_t chain[DHT2_CHAIN_LEN],
                         const uint8_t group_id[DHT2_GROUP_ID_LEN],
                         uint32_t key_version, uint8_t out[DHT2_ID_LEN])
{
    return id_group_versioned(DHT2_LABEL_GROUP_RECORD, chain, group_id,
                              key_version, out);
}

int dht2_id_group_keys(const uint8_t chain[DHT2_CHAIN_LEN],
                       const uint8_t group_id[DHT2_GROUP_ID_LEN],
                       uint32_t key_version, uint8_t out[DHT2_ID_LEN])
{
    return id_group_versioned(DHT2_LABEL_GROUP_KEYS, chain, group_id,
                              key_version, out);
}

int dht2_id_group_feed(const uint8_t chain[DHT2_CHAIN_LEN],
                       const uint8_t group_id[DHT2_GROUP_ID_LEN],
                       uint8_t out[DHT2_ID_LEN])
{
    return dht2_id(DHT2_LABEL_GROUP_FEED, chain, group_id,
                   DHT2_GROUP_ID_LEN, out);
}

/* ══ data map ══════════════════════════════════════════════════════════ */

/* The one emission path: WRITE, COUNT and COMPARE all run through it. */
static int data_emit(const dht2_data_t *d, dht2_cbor_wr_t *w)
{
    uint8_t  vtext[DHT2_VALIDITY_LEN];
    uint64_t nkeys = DATA_KEYS_MIN;

    if (d->sequence == 0 || d->validity_type > DHT2_VT_NONE) {
        return DHT2_E_BAD_ENCODING;
    }
    if (d->validity_type == DHT2_VT_EOL &&
        dht2_validity_format(d->expiry, vtext) != 0) {
        return DHT2_E_BAD_ENCODING;
    }
    if (d->has_prev && d->prev_len != 0 && d->prev_len != DHT2_HASH_LEN) {
        return DHT2_E_BAD_ENCODING;
    }
    nkeys += (d->del ? 1u : 0u) + (d->has_data ? 1u : 0u) +
             (d->has_prev ? 1u : 0u);

    /* dag-cbor/spec.md:58 order — length first, then bytewise. */
    dht2_cbor_wr_map(w, nkeys);
    dht2_cbor_wr_key(w, K_TTL);
    dht2_cbor_wr_uint(w, 0);                        /* row 6: TTL = 0 */
    dht2_cbor_wr_key(w, K_ID);
    dht2_cbor_wr_bytes(w, d->id, DHT2_ID_LEN);
    if (d->del) {
        dht2_cbor_wr_key(w, K_DEL);
        dht2_cbor_wr_true(w);
    }
    dht2_cbor_wr_key(w, K_VALUE);
    dht2_cbor_wr_bytes(w, NULL, 0);                 /* §3.1: empty */
    if (d->has_data) {
        dht2_cbor_wr_key(w, K_DATA);
        dht2_cbor_wr_bytes(w, d->data, d->data_len);
    }
    if (d->has_prev) {
        dht2_cbor_wr_key(w, K_PREV);
        dht2_cbor_wr_bytes(w, d->prev, d->prev_len);
    }
    dht2_cbor_wr_key(w, K_CHAIN);
    dht2_cbor_wr_bytes(w, d->chain, DHT2_CHAIN_LEN);
    dht2_cbor_wr_key(w, K_CLASS);
    dht2_cbor_wr_uint(w, d->cls);
    dht2_cbor_wr_key(w, K_SEQUENCE);
    dht2_cbor_wr_uint(w, d->sequence);
    dht2_cbor_wr_key(w, K_VALIDITY);
    if (d->validity_type == DHT2_VT_EOL) {
        dht2_cbor_wr_bytes(w, vtext, DHT2_VALIDITY_LEN);
    } else {
        dht2_cbor_wr_bytes(w, NULL, 0);             /* §3.1: type 1 ⇒ empty */
    }
    dht2_cbor_wr_key(w, K_VALIDITYTYPE);
    dht2_cbor_wr_uint(w, d->validity_type);
    return DHT2_OK;
}

int dht2_data_encode(const dht2_data_t *d, uint8_t *out, size_t cap,
                     size_t *out_len)
{
    dht2_cbor_wr_t w;
    int            rc;

    if (d == NULL || out_len == NULL) {
        return DHT2_E_ARG;
    }
    if ((d->has_data && d->data == NULL && d->data_len != 0) ||
        (d->has_prev && d->prev == NULL && d->prev_len != 0)) {
        return DHT2_E_ARG;
    }
    if (out == NULL) {
        dht2_cbor_wr_init_count(&w);
    } else {
        dht2_cbor_wr_init(&w, out, cap);
    }
    rc = data_emit(d, &w);
    if (rc != DHT2_OK) {
        return rc;
    }
    if (!dht2_cbor_wr_ok(&w)) {
        return DHT2_E_ARG;              /* only the caller's buffer can fail */
    }
    *out_len = w.len;
    return DHT2_OK;
}

int dht2_data_decode(const uint8_t *in, size_t len, dht2_data_t *d)
{
    dht2_cbor_rd_t r;
    dht2_cbor_wr_t w;
    uint64_t       nkeys, i, v;
    const uint8_t *prev_key = NULL;
    size_t         prev_key_len = 0;
    const uint8_t *validity = NULL;
    size_t         validity_len = 0;
    bool seen_ttl = false, seen_id = false, seen_value = false;
    bool seen_chain = false, seen_class = false, seen_seq = false;
    bool seen_validity = false, seen_vt = false;

    if (d == NULL || (in == NULL && len != 0)) {
        return DHT2_E_ARG;
    }
    memset(d, 0, sizeof(*d));
    dht2_cbor_rd_init(&r, in, len);

    if (dht2_cbor_rd_map(&r, &nkeys) != 0 ||
        nkeys < DATA_KEYS_MIN || nkeys > DATA_KEYS_MAX) {
        return DHT2_E_BAD_ENCODING;
    }
    for (i = 0; i < nkeys; i++) {
        const uint8_t *k, *p;
        size_t         kl, n;

        /* Strictly ascending keys: refuses unsorted AND duplicate keys. */
        if (dht2_cbor_rd_key(&r, prev_key, prev_key_len, &k, &kl) != 0) {
            return DHT2_E_BAD_ENCODING;
        }
        prev_key = k;
        prev_key_len = kl;

        if (dht2_cbor_key_is(k, kl, K_TTL)) {
            if (dht2_cbor_rd_uint(&r, &v) != 0 || v != 0) {
                return DHT2_E_BAD_ENCODING;             /* row 6: TTL = 0 */
            }
            seen_ttl = true;
        } else if (dht2_cbor_key_is(k, kl, K_ID)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 || n != DHT2_ID_LEN) {
                return DHT2_E_BAD_ENCODING;
            }
            memcpy(d->id, p, DHT2_ID_LEN);
            seen_id = true;
        } else if (dht2_cbor_key_is(k, kl, K_DEL)) {
            if (dht2_cbor_rd_true(&r) != 0) {
                return DHT2_E_BAD_ENCODING;     /* row 5: `_del` only `true` */
            }
            d->del = true;
        } else if (dht2_cbor_key_is(k, kl, K_VALUE)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 || n != 0) {
                return DHT2_E_BAD_ENCODING;     /* §3.1: `Value` (empty) */
            }
            seen_value = true;
        } else if (dht2_cbor_key_is(k, kl, K_DATA)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0) {
                return DHT2_E_BAD_ENCODING;
            }
            d->has_data = true;
            d->data = p;
            d->data_len = n;
        } else if (dht2_cbor_key_is(k, kl, K_PREV)) {
            /* row 3: length ∈ {0, 64} */
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 ||
                (n != 0 && n != DHT2_HASH_LEN)) {
                return DHT2_E_BAD_ENCODING;
            }
            d->has_prev = true;
            d->prev = p;
            d->prev_len = n;
        } else if (dht2_cbor_key_is(k, kl, K_CHAIN)) {
            if (dht2_cbor_rd_bytes(&r, &p, &n) != 0 || n != DHT2_CHAIN_LEN) {
                return DHT2_E_BAD_ENCODING;
            }
            memcpy(d->chain, p, DHT2_CHAIN_LEN);
            seen_chain = true;
        } else if (dht2_cbor_key_is(k, kl, K_CLASS)) {
            if (dht2_cbor_rd_uint(&r, &d->cls) != 0) {
                return DHT2_E_BAD_ENCODING;     /* range: check_class */
            }
            seen_class = true;
        } else if (dht2_cbor_key_is(k, kl, K_SEQUENCE)) {
            /* row 6: 1 … 2^64−1 */
            if (dht2_cbor_rd_uint(&r, &d->sequence) != 0 || d->sequence == 0) {
                return DHT2_E_BAD_ENCODING;
            }
            seen_seq = true;
        } else if (dht2_cbor_key_is(k, kl, K_VALIDITY)) {
            if (dht2_cbor_rd_bytes(&r, &validity, &validity_len) != 0) {
                return DHT2_E_BAD_ENCODING;
            }
            seen_validity = true;
        } else if (dht2_cbor_key_is(k, kl, K_VALIDITYTYPE)) {
            /* row 6: ∈ {0, 1} */
            if (dht2_cbor_rd_uint(&r, &d->validity_type) != 0 ||
                d->validity_type > DHT2_VT_NONE) {
                return DHT2_E_BAD_ENCODING;
            }
            seen_vt = true;
        } else {
            return DHT2_E_BAD_ENCODING;         /* row 5: unknown key */
        }
    }
    if (!dht2_cbor_rd_done(&r)) {
        return DHT2_E_BAD_ENCODING;             /* trailing byte, spec :66 */
    }
    if (!seen_ttl || !seen_id || !seen_value || !seen_chain || !seen_class ||
        !seen_seq || !seen_validity || !seen_vt) {
        return DHT2_E_BAD_ENCODING;
    }
    /* §3.1: ValidityType 0 ⇒ `Validity` present and 20 B; 1 ⇒ empty. */
    if (d->validity_type == DHT2_VT_EOL) {
        if (dht2_validity_parse(validity, validity_len, &d->expiry) != 0) {
            return DHT2_E_BAD_ENCODING;
        }
    } else if (validity_len != 0) {
        return DHT2_E_BAD_ENCODING;
    }

    /* §3.1 "re-encode check": the canonical form of what was parsed must
     * be the input, byte for byte. */
    dht2_cbor_wr_init_compare(&w, in, len);
    if (data_emit(d, &w) != DHT2_OK || !dht2_cbor_wr_ok(&w)) {
        return DHT2_E_BAD_ENCODING;
    }
    return DHT2_OK;
}

/* ══ envelope ══════════════════════════════════════════════════════════ */

int dht2_record_parse(const uint8_t *in, size_t len,
                      const uint8_t local_chain[DHT2_CHAIN_LEN],
                      const uint8_t *expect_address, dht2_record_t *rec)
{
    const uint8_t *pkb = NULL;
    size_t         pkb_len = 0;
    size_t         i = 0;
    int            rc;

    if (rec == NULL || local_chain == NULL || (in == NULL && len != 0)) {
        return DHT2_E_ARG;
    }
    memset(rec, 0, sizeof(*rec));

    /* §3.1 "Size": checked before any decode. */
    if (len > DHT2_ENVELOPE_MAX) {
        return DHT2_E_TOO_LARGE;
    }

    /* IpnsEntry decode, the tree's generated-Unmarshal contract
     * (cmt_pb.h:46-52): any order, unknown fields skipped by wire type
     * (incl. IPNS's own V1 fields 1-6), last-one-wins. */
    while (i < len) {
        size_t         start = i;
        int32_t        fieldnum;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return DHT2_E_BAD_ENCODING;
        }
        if (fieldnum == (int32_t)IPNS_F_PUBKEY ||
            fieldnum == (int32_t)IPNS_F_SIG_V2 ||
            fieldnum == (int32_t)IPNS_F_DATA) {
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return DHT2_E_BAD_ENCODING;
            }
            if (fieldnum == (int32_t)IPNS_F_PUBKEY) {
                pkb = p;
                pkb_len = n;
            } else if (fieldnum == (int32_t)IPNS_F_SIG_V2) {
                rec->sig = p;
                rec->sig_len = n;
            } else {
                rec->data = p;
                rec->data_len = n;
            }
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return DHT2_E_BAD_ENCODING;
            }
        }
    }

    /* `data` strict DAG-CBOR with the re-encode check. */
    rc = dht2_data_decode(rec->data, rec->data_len, &rec->d);
    if (rc != DHT2_OK) {
        return DHT2_E_BAD_ENCODING;
    }

    /* `_chain` = the local chain (khan 22 / agreed fix 4; the tree's
     * pattern cmt_p2p_addrbook.h:25-26, :42). */
    if (memcmp(rec->d.chain, local_chain, DHT2_CHAIN_LEN) != 0) {
        return DHT2_E_BAD_CHAIN;
    }

    /* pubKey → owner fp: the ML-DSA-87 branch only, exactly 2592 B
     * (cmt_pb_public_key_unmarshal refuses every other field / size). */
    if (pkb == NULL ||
        cmt_pb_public_key_unmarshal(pkb, pkb_len, &rec->pk) != CMT_OK ||
        !rec->pk.present) {
        return DHT2_E_BAD_ENCODING;
    }
    if (dht2_fp(rec->pk.key, rec->fp) != 0) {
        return DHT2_E_HOLDER_FAULT;
    }

    if (dht2_address(rec->d.id, rec->fp, rec->address) != 0) {
        return DHT2_E_HOLDER_FAULT;
    }
    if (expect_address != NULL &&
        memcmp(expect_address, rec->address, DHT2_HASH_LEN) != 0) {
        return DHT2_E_BAD_ADDRESS;
    }
    return DHT2_OK;
}

/* §13 row 15: fp 64 ‖ mark 1 ‖ through 8, strictly ascending by fp, mark
 * 1 HANDLED / 2 DENIED, ≤ 3,500 entries. */
static bool ctl_list_ok(const uint8_t *p, size_t n)
{
    size_t count, k;

    if (n % CTL_ENTRY_LEN != 0) {
        return false;
    }
    count = n / CTL_ENTRY_LEN;
    if (count > CTL_ENTRIES_MAX) {
        return false;
    }
    for (k = 0; k < count; k++) {
        const uint8_t *e = p + k * CTL_ENTRY_LEN;
        uint8_t        mark = e[DHT2_FP_LEN];

        if (mark != CTL_MARK_HANDLED && mark != CTL_MARK_DENIED) {
            return false;
        }
        if (k > 0 && memcmp(e - CTL_ENTRY_LEN, e, DHT2_FP_LEN) >= 0) {
            return false;
        }
    }
    return true;
}

int dht2_record_check_class(const dht2_record_t *rec)
{
    const dht2_data_t *d;

    if (rec == NULL) {
        return DHT2_E_ARG;
    }
    d = &rec->d;
    if (d->cls < DHT2_CLASS_OWNER || d->cls > DHT2_CLASS_INBOX_CTL) {
        return DHT2_E_BAD_CLASS;                         /* row 5 */
    }
    /* Row 5 matrix. A tombstone: `_del` true, `_data` and `_prev`
     * absent. Otherwise: `_data` required, `_prev` exactly for class 2. */
    if (d->del) {
        if (d->has_data || d->has_prev) {
            return DHT2_E_BAD_CLASS;
        }
    } else {
        if (!d->has_data) {
            return DHT2_E_BAD_CLASS;
        }
        if (d->has_prev != (d->cls == DHT2_CLASS_FEED_ENTRY)) {
            return DHT2_E_BAD_CLASS;
        }
        if (d->cls == DHT2_CLASS_FEED_HEAD && d->data_len != 8u) {
            return DHT2_E_BAD_CLASS;                     /* 8 B index */
        }
        if (d->cls == DHT2_CLASS_INBOX_CTL &&
            !ctl_list_ok(d->data, d->data_len)) {
            return DHT2_E_BAD_CLASS;                     /* row 15 */
        }
    }
    /* §3.2: an inbox control record is accepted only if its signer's fp
     * is the recipient fp of its own `_id` preimage — recomputed, not
     * trusted. Applies to its tombstone too (same `_id`, same class). */
    if (d->cls == DHT2_CLASS_INBOX_CTL) {
        uint8_t ctl[DHT2_ID_LEN];

        if (dht2_id_inbox_ctl(d->chain, rec->fp, ctl) != 0) {
            return DHT2_E_HOLDER_FAULT;
        }
        if (memcmp(ctl, d->id, DHT2_ID_LEN) != 0) {
            return DHT2_E_BAD_CLASS;
        }
    }
    return DHT2_OK;
}

int dht2_record_check_expiry(const dht2_record_t *rec, uint64_t chain_now,
                             bool writer_named)
{
    const dht2_data_t *d;
    bool               unbounded = false;
    uint64_t           max = 0, bound;

    if (rec == NULL) {
        return DHT2_E_ARG;
    }
    d = &rec->d;
    /* Row 5 "Class max (by number and the WRITER's name status, §5)";
     * a tombstone inherits its class's max. */
    switch (d->cls) {
    case DHT2_CLASS_OWNER:
    case DHT2_CLASS_FEED_HEAD:
    case DHT2_CLASS_INBOX_CTL:
        if (writer_named) {
            unbounded = true;           /* no expiry allowed (ValidityType 1) */
        } else {
            max = DHT2_SEC_7D;
        }
        break;
    case DHT2_CLASS_FEED_ENTRY:
        max = DHT2_SEC_7D;
        break;
    case DHT2_CLASS_INBOX_ENTRY:
        max = writer_named ? DHT2_SEC_7D : DHT2_SEC_24H;
        break;
    default:
        return DHT2_E_BAD_CLASS;
    }

    if (d->validity_type == DHT2_VT_NONE) {
        return unbounded ? DHT2_OK : DHT2_E_TOO_LONG;
    }
    /* Lower bound — the rule is design §4.1 "expiry > holder chain time".
     * NAMED: boxo validation.go:73 refuses only `time.Now().After(eol)`,
     * i.e. it still accepts eol == now; ours refuses eol == chain time, one
     * second stricter (whole-second chain time). */
    if (d->expiry <= chain_now) {
        return DHT2_E_EXPIRED;
    }
    if (unbounded) {
        return DHT2_OK;
    }
    /* Upper bound: ≤ chain time + class max + 3 h, checked (row 6). After
     * the lower bound chain_now < expiry ≤ 253402300799, so this sum
     * cannot overflow; the check stays because row 6 requires it. */
    if (dna_ck_add_u64(chain_now, max, &bound) != 0 ||
        dna_ck_add_u64(bound, DHT2_SEC_SLACK_3H, &bound) != 0) {
        return DHT2_E_HOLDER_FAULT;
    }
    if (d->expiry > bound) {
        return DHT2_E_TOO_LONG;
    }
    return DHT2_OK;
}

int dht2_record_verify(const dht2_record_t *rec)
{
    if (rec == NULL) {
        return DHT2_E_ARG;
    }
    if (!rec->pk.present || rec->sig == NULL ||
        rec->sig_len != DHT2_SIG_LEN || rec->data == NULL) {
        return DHT2_E_BAD_SIGNATURE;
    }
    /* §3.1: ML-DSA-87 over the `data` bytes, FIPS 204 ctx
     * `nodus.dht.record.v1` (replaces "ipns-signature:", ipns-record.md:339). */
    if (qgp_dsa87_verify_ctx(rec->sig, rec->sig_len, rec->data, rec->data_len,
                             (const uint8_t *)DHT2_CTX_RECORD,
                             strlen(DHT2_CTX_RECORD), rec->pk.key) != 0) {
        return DHT2_E_BAD_SIGNATURE;
    }
    return DHT2_OK;
}

/* One length-delimited field (tag ‖ uvarint(n) ‖ bytes), omit-zero
 * (cmt_pb.h:26, rule a). `out` NULL → only counts. */
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

int dht2_record_canonical(const dht2_record_t *rec, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    uint8_t pkm[PK_MSG_LEN];
    size_t  pkm_len = 0, off = 0;

    if (rec == NULL || out_len == NULL || !rec->pk.present) {
        return DHT2_E_ARG;
    }
    /* A signature that is not ML-DSA-87-sized can never verify: there is
     * no stored form for it. */
    if (rec->sig == NULL || rec->sig_len != DHT2_SIG_LEN) {
        return DHT2_E_BAD_SIGNATURE;
    }
    if (cmt_pb_public_key_marshal(&rec->pk, pkm, sizeof(pkm), &pkm_len)
        != CMT_OK) {
        return DHT2_E_ARG;
    }
    /* Row 4: fields 7, 8, 9 only, ascending, each once. */
    if (put_ld(out, cap, &off, IPNS_F_PUBKEY, pkm, pkm_len) != 0 ||
        put_ld(out, cap, &off, IPNS_F_SIG_V2, rec->sig, rec->sig_len) != 0 ||
        put_ld(out, cap, &off, IPNS_F_DATA, rec->data, rec->data_len) != 0) {
        return DHT2_E_ARG;
    }
    *out_len = off;
    return DHT2_OK;
}

int dht2_record_build(const dht2_data_t *d, const uint8_t *sk,
                      const uint8_t pk[DHT2_PUBKEY_LEN], uint8_t *out,
                      size_t cap, size_t *out_len)
{
    cmt_pb_public_key_t pkv;
    uint8_t             pkm[PK_MSG_LEN];
    size_t              pkm_len = 0, dlen = 0, total = 0, off = 0;
    size_t              sig_off, data_off, siglen = 0;
    uint64_t            tag;
    int                 rc;

    if (d == NULL || pk == NULL || out_len == NULL ||
        (out != NULL && sk == NULL)) {
        return DHT2_E_ARG;
    }
    rc = dht2_data_encode(d, NULL, 0, &dlen);
    if (rc != DHT2_OK) {
        return rc;
    }
    /* Refuse before any size arithmetic: the sum below then stays far
     * from SIZE_MAX. */
    if (dlen > DHT2_ENVELOPE_MAX) {
        return DHT2_E_TOO_LARGE;
    }
    pkv.present = true;
    memcpy(pkv.key, pk, DHT2_PUBKEY_LEN);
    if (cmt_pb_public_key_marshal(&pkv, pkm, sizeof(pkm), &pkm_len)
        != CMT_OK) {
        return DHT2_E_ARG;
    }
    /* Size the canonical envelope (data is never empty: the map head). */
    if (put_ld(NULL, 0, &total, IPNS_F_PUBKEY, pkm, pkm_len) != 0) {
        return DHT2_E_ARG;
    }
    tag = ((uint64_t)IPNS_F_SIG_V2 << 3) | 2u;
    total += cmt_pb_uvarint_size(tag) + cmt_pb_uvarint_size(DHT2_SIG_LEN) +
             DHT2_SIG_LEN;
    tag = ((uint64_t)IPNS_F_DATA << 3) | 2u;
    total += cmt_pb_uvarint_size(tag) + cmt_pb_uvarint_size((uint64_t)dlen) +
             dlen;
    if (total > DHT2_ENVELOPE_MAX) {
        return DHT2_E_TOO_LARGE;
    }
    if (out == NULL) {
        *out_len = total;
        return DHT2_OK;
    }
    if (cap < total) {
        return DHT2_E_ARG;
    }

    /* Field 7, then the field-8 head, then field 9 in place; the
     * signature is written into its slot last, over the data bytes. */
    if (put_ld(out, cap, &off, IPNS_F_PUBKEY, pkm, pkm_len) != 0 ||
        cmt_pb_put_uvarint(out, cap, &off,
                           ((uint64_t)IPNS_F_SIG_V2 << 3) | 2u) != CMT_OK ||
        cmt_pb_put_uvarint(out, cap, &off, DHT2_SIG_LEN) != CMT_OK) {
        return DHT2_E_ARG;
    }
    sig_off = off;
    off += DHT2_SIG_LEN;
    if (cmt_pb_put_uvarint(out, cap, &off,
                           ((uint64_t)IPNS_F_DATA << 3) | 2u) != CMT_OK ||
        cmt_pb_put_uvarint(out, cap, &off, (uint64_t)dlen) != CMT_OK) {
        return DHT2_E_ARG;
    }
    data_off = off;
    rc = dht2_data_encode(d, out + data_off, cap - data_off, &dlen);
    if (rc != DHT2_OK) {
        return rc;
    }
    off += dlen;

    /* Hedged signing kept (FIPS 204 §3.4; Kurultay #21 khan 2). */
    if (qgp_dsa87_sign_ctx(out + sig_off, &siglen, out + data_off, dlen,
                           (const uint8_t *)DHT2_CTX_RECORD,
                           strlen(DHT2_CTX_RECORD), sk) != 0 ||
        siglen != DHT2_SIG_LEN) {
        memset(out, 0, total);
        return DHT2_E_HOLDER_FAULT;
    }
    *out_len = off;
    return DHT2_OK;
}

int dht2_record_compare(const dht2_record_t *a, const dht2_record_t *b)
{
    bool a_none, b_none;
    int  c;

    if (a == NULL || b == NULL) {           /* NULL = nothing held */
        return (a == b) ? 0 : (a == NULL ? -1 : 1);
    }
    if (a->d.sequence != b->d.sequence) {                /* record.go:683-687 */
        return (a->d.sequence > b->d.sequence) ? 1 : -1;
    }
    a_none = (a->d.validity_type == DHT2_VT_NONE);
    b_none = (b->d.validity_type == DHT2_VT_NONE);
    if (a_none != b_none) {                  /* no expiry above any expiry */
        return a_none ? 1 : -1;
    }
    if (!a_none && a->d.expiry != b->d.expiry) {         /* record.go:699-702 */
        return (a->d.expiry > b->d.expiry) ? 1 : -1;
    }
    /* bytes.Compare tie-breaks (validation.go:247-249), on the canonical
     * data bytes, then on the signature bytes. */
    c = dht2_bytes_compare(a->data, a->data_len, b->data, b->data_len);
    if (c != 0) {
        return c;
    }
    return dht2_bytes_compare(a->sig, a->sig_len, b->sig, b->sig_len);
}

int dht2_record_placement_key(const dht2_record_t *rec,
                              uint8_t out[DHT2_HASH_LEN])
{
    if (rec == NULL || out == NULL) {
        return DHT2_E_ARG;
    }
    if (rec->d.cls == DHT2_CLASS_INBOX_ENTRY) {
        memcpy(out, rec->d.id, DHT2_ID_LEN);
        return DHT2_OK;
    }
    if (rec->d.cls == DHT2_CLASS_INBOX_CTL) {
        return dht2_id_inbox(rec->d.chain, rec->fp, out) == 0
                   ? DHT2_OK : DHT2_E_HOLDER_FAULT;
    }
    memcpy(out, rec->address, DHT2_HASH_LEN);
    return DHT2_OK;
}
