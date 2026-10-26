/**
 * Nodus — the owner-signed chain query `qa` (contract: nodus_owner_query.h)
 */

#include "protocol/nodus_owner_query.h"
#include "protocol/nodus_cbor.h"

#include "dht2/dht2_cbor.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_types.h"
#include "crypto/hash/qgp_sha3.h"

#include <string.h>

_Static_assert(NODUS_OQ_CHAIN_LEN == DHT2_CHAIN_LEN, "chain id size");
_Static_assert(NODUS_OQ_FP_LEN == DHT2_FP_LEN, "fingerprint size");
_Static_assert(NODUS_OQ_PK_LEN == DHT2_PUBKEY_LEN, "ML-DSA-87 key size");
_Static_assert(NODUS_OQ_PK_LEN == CMT_PB_PUBKEY_LEN, "envelope key size");

/* Payload keys: all one byte, so the canonical (length first, then
 * bytewise) order is c < m < o < s. */
static void oq_emit(const nodus_oq_payload_t *p, dht2_cbor_wr_t *w) {
    dht2_cbor_wr_map(w, 4u);
    dht2_cbor_wr_key(w, "c");
    dht2_cbor_wr_bytes(w, p->chain, NODUS_OQ_CHAIN_LEN);
    dht2_cbor_wr_key(w, "m");
    dht2_cbor_wr_text(w, (const uint8_t *)p->method, strlen(p->method));
    dht2_cbor_wr_key(w, "o");
    dht2_cbor_wr_bytes(w, p->o, NODUS_OQ_O_LEN);
    dht2_cbor_wr_key(w, "s");
    dht2_cbor_wr_bytes(w, p->s, NODUS_OQ_T_LEN);
}

int nodus_oq_payload_encode(const nodus_oq_payload_t *p, uint8_t *out,
                            size_t cap, size_t *out_len) {
    dht2_cbor_wr_t w;

    if (!p || !out_len) return -1;
    /* a method name is non-empty, bounded and NUL-terminated within the field */
    size_t ml = strnlen(p->method, sizeof(p->method));
    if (ml == 0 || ml > NODUS_OQ_METHOD_MAX) return -1;
    if (out == NULL)
        dht2_cbor_wr_init_count(&w);
    else
        dht2_cbor_wr_init(&w, out, cap);
    oq_emit(p, &w);
    if (!dht2_cbor_wr_ok(&w)) return -1;
    *out_len = w.len;
    return 0;
}

int nodus_oq_payload_decode(const uint8_t *in, size_t len,
                            nodus_oq_payload_t *p) {
    dht2_cbor_rd_t r;
    dht2_cbor_wr_t w;
    uint64_t       nkeys;
    const uint8_t *prev = NULL;
    size_t         prev_len = 0;
    bool           seen_c = false, seen_m = false, seen_o = false, seen_s = false;

    if (!p || !in || len == 0 || len > NODUS_OQ_PAYLOAD_MAX) return -1;
    memset(p, 0, sizeof(*p));
    dht2_cbor_rd_init(&r, in, len);
    if (dht2_cbor_rd_map(&r, &nkeys) != 0 || nkeys != 4u) return -1;
    for (uint64_t i = 0; i < nkeys; i++) {
        const uint8_t *k, *v;
        size_t         kl, n;

        if (dht2_cbor_rd_key(&r, prev, prev_len, &k, &kl) != 0) return -1;
        prev = k;
        prev_len = kl;
        if (dht2_cbor_key_is(k, kl, "c")) {
            if (dht2_cbor_rd_bytes(&r, &v, &n) != 0 || n != NODUS_OQ_CHAIN_LEN)
                return -1;
            memcpy(p->chain, v, n);
            seen_c = true;
        } else if (dht2_cbor_key_is(k, kl, "m")) {
            if (dht2_cbor_rd_text(&r, &v, &n) != 0 || n == 0 ||
                n > NODUS_OQ_METHOD_MAX || memchr(v, 0, n) != NULL)
                return -1;
            memcpy(p->method, v, n);
            p->method[n] = '\0';
            seen_m = true;
        } else if (dht2_cbor_key_is(k, kl, "o")) {
            if (dht2_cbor_rd_bytes(&r, &v, &n) != 0 || n != NODUS_OQ_O_LEN)
                return -1;
            memcpy(p->o, v, n);
            seen_o = true;
        } else if (dht2_cbor_key_is(k, kl, "s")) {
            if (dht2_cbor_rd_bytes(&r, &v, &n) != 0 || n != NODUS_OQ_T_LEN)
                return -1;
            memcpy(p->s, v, n);
            seen_s = true;
        } else {
            return -1;
        }
    }
    if (!seen_c || !seen_m || !seen_o || !seen_s || !dht2_cbor_rd_done(&r))
        return -1;
    /* re-encode identity: what was parsed, written again, is the input */
    dht2_cbor_wr_init_compare(&w, in, len);
    oq_emit(p, &w);
    if (!dht2_cbor_wr_ok(&w)) return -1;
    return 0;
}

int nodus_oq_build(const uint8_t chain[NODUS_OQ_CHAIN_LEN], const char *method,
                   const uint8_t o[NODUS_OQ_O_LEN],
                   const uint8_t t[NODUS_OQ_T_LEN],
                   const uint8_t *sk, const uint8_t pk[NODUS_OQ_PK_LEN],
                   uint8_t *out, size_t cap, size_t *out_len) {
    nodus_oq_payload_t p;
    uint8_t            payload[NODUS_OQ_PAYLOAD_MAX];
    size_t             plen = 0;

    if (!chain || !method || !o || !t || !sk || !pk || !out_len) return -1;
    size_t ml = strlen(method);
    if (ml == 0 || ml > NODUS_OQ_METHOD_MAX) return -1;
    memset(&p, 0, sizeof(p));
    memcpy(p.chain, chain, NODUS_OQ_CHAIN_LEN);
    memcpy(p.method, method, ml);
    memcpy(p.o, o, NODUS_OQ_O_LEN);
    memcpy(p.s, t, NODUS_OQ_T_LEN);
    if (nodus_oq_payload_encode(&p, payload, sizeof(payload), &plen) != 0)
        return -1;
    int rc = dht2_env_seal(NODUS_OQ_DOMAIN,
                           (const uint8_t *)NODUS_OQ_PAYLOAD_TYPE,
                           strlen(NODUS_OQ_PAYLOAD_TYPE),
                           payload, plen, sk, pk, out, cap, out_len);
    if (rc == DHT2_OK) return 0;
    return rc == DHT2_E_ARG ? -1 : NODUS_OQ_E_FAULT;
}

int nodus_oq_open(const uint8_t *env_buf, size_t env_len,
                  const uint8_t chain[NODUS_OQ_CHAIN_LEN], const char *method,
                  const uint8_t t[NODUS_OQ_T_LEN], nodus_oq_proof_t *proof) {
    dht2_env_t         env;
    nodus_oq_payload_t p;
    int                rc;

    if (!proof) return NODUS_OQ_E_MALFORMED;
    memset(proof, 0, sizeof(*proof));
    if (!env_buf || !chain || !method || !t) return NODUS_OQ_E_MALFORMED;
    if (env_len == 0 || env_len > NODUS_OQ_ENV_MAX) return NODUS_OQ_E_MALFORMED;

    rc = dht2_env_decode(env_buf, env_len, NODUS_OQ_ENV_MAX, &env);
    if (rc == DHT2_E_HOLDER_FAULT) return NODUS_OQ_E_FAULT;
    if (rc != DHT2_OK) return NODUS_OQ_E_MALFORMED;
    /* the payload type, explicitly */
    if (env.payload_type_len != strlen(NODUS_OQ_PAYLOAD_TYPE) ||
        memcmp(env.payload_type, NODUS_OQ_PAYLOAD_TYPE,
               env.payload_type_len) != 0)
        return NODUS_OQ_E_MALFORMED;
    /* the signature, under the domain */
    rc = dht2_env_verify(&env, NODUS_OQ_DOMAIN);
    if (rc == DHT2_E_HOLDER_FAULT) return NODUS_OQ_E_FAULT;
    if (rc != DHT2_OK) return NODUS_OQ_E_SIGNATURE;
    /* the payload, then c / m / s */
    if (nodus_oq_payload_decode(env.payload, env.payload_len, &p) != 0)
        return NODUS_OQ_E_MALFORMED;
    if (memcmp(p.chain, chain, NODUS_OQ_CHAIN_LEN) != 0 ||
        strcmp(p.method, method) != 0 ||
        memcmp(p.s, t, NODUS_OQ_T_LEN) != 0)
        return NODUS_OQ_E_BINDING;

    memcpy(proof->pk, env.pk.key, NODUS_OQ_PK_LEN);
    memcpy(proof->fp, env.fp, NODUS_OQ_FP_LEN);
    memcpy(proof->o, p.o, NODUS_OQ_O_LEN);
    return NODUS_OQ_OK;
}

int nodus_oq_find(const uint8_t *frame, size_t frame_len,
                  const uint8_t **env, size_t *env_len) {
    cbor_decoder_t dec;
    bool           found = false;

    if (!frame || !env || !env_len) return -1;
    *env = NULL;
    *env_len = 0;
    cbor_decoder_init(&dec, frame, frame_len);
    cbor_item_t top = cbor_decode_next(&dec);
    if (top.type != CBOR_ITEM_MAP) return -1;
    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) return -1;
        if (key.tstr.len == 2 && memcmp(key.tstr.ptr, "qa", 2) == 0) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (found || val.type != CBOR_ITEM_BSTR) return -1;
            *env = val.bstr.ptr;
            *env_len = val.bstr.len;
            found = true;
        } else {
            cbor_decode_skip(&dec);
        }
        if (dec.error) return -1;
    }
    if (dec.error) return -1;
    return found ? 0 : 1;
}

int nodus_oq_delegations_subject(const uint8_t *pubkey, size_t len,
                                 uint8_t out[NODUS_OQ_O_LEN]) {
    if (!pubkey || !out || len != NODUS_OQ_PK_LEN) return -1;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= pubkey[i];
    if (acc == 0) return -1;
    return qgp_sha3_512(pubkey, len, out) == 0 ? 0 : -1;
}

bool nodus_oq_subject_ok(const uint8_t o[NODUS_OQ_O_LEN],
                         const uint8_t subject[NODUS_OQ_O_LEN]) {
    if (!o || !subject) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < NODUS_OQ_O_LEN; i++) diff |= (uint8_t)(o[i] ^ subject[i]);
    return diff == 0;
}

bool nodus_oq_method_takes_qa(const char *method) {
    if (!method) return false;
    return strcmp(method, "dnac_utxo") == 0 ||
           strcmp(method, "dnac_addr_history") == 0 ||
           strcmp(method, "dnac_delegations") == 0 ||
           strcmp(method, "dnac_msig_utxo") == 0 ||
           strcmp(method, "dnac_msig_addr_history") == 0;
}
