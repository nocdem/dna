/**
 * Nodus — Tier 2 Protocol (Client-Nodus)
 *
 * CBOR encode/decode for client↔server messages.
 * Auth: hello, challenge, auth, auth_ok
 * DHT:  put, get, get_all, listen, unlisten, ping/pong
 * Push: result, error, value_changed
 */

#include "protocol/nodus_tier2.h"
#include "protocol/nodus_cbor.h"
#include "core/nodus_value.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Portable strndup (missing on Windows — both MSVC and MinGW) */
#ifdef _WIN32
static char *portable_strndup(const char *s, size_t n) {
    size_t len = 0;
    while (len < n && s[len]) len++;
    char *p = (char *)malloc(len + 1);
    if (p) { memcpy(p, s, len); p[len] = '\0'; }
    return p;
}
#define strndup portable_strndup
#endif

/* Circuit / inter-node method-prefix checks (for decoder dispatch on
 * shared keys like "cid", "d", "code" that appear in both circ_* and
 * ri_* methods as well as legacy methods like put). */
#define IS_CIRC_METHOD(m) (strncmp((m), "circ_", 5) == 0)
#define IS_RI_METHOD(m)   (strncmp((m), "ri_", 3) == 0)

/* ── Common helpers ──────────────────────────────────────────────── */

static void enc_query_header(cbor_encoder_t *enc, size_t map_count,
                              uint32_t txn, const char *method) {
    cbor_encode_map(enc, map_count);
    cbor_encode_cstr(enc, "t");  cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y");  cbor_encode_cstr(enc, "q");
    cbor_encode_cstr(enc, "q");  cbor_encode_cstr(enc, method);
}

static void enc_response_header(cbor_encoder_t *enc, size_t map_count,
                                 uint32_t txn, const char *method) {
    cbor_encode_map(enc, map_count);
    cbor_encode_cstr(enc, "t");  cbor_encode_uint(enc, txn);
    cbor_encode_cstr(enc, "y");  cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q");  cbor_encode_cstr(enc, method);
}

static void enc_token(cbor_encoder_t *enc, const uint8_t *token) {
    cbor_encode_cstr(enc, "tok");
    if (token)
        cbor_encode_bstr(enc, token, NODUS_SESSION_TOKEN_LEN);
    else
        cbor_encode_bstr(enc, (const uint8_t *)"", 0);
}

static int finish(cbor_encoder_t *enc, size_t *out_len) {
    size_t len = cbor_encoder_len(enc);
    if (len == 0) return -1;
    *out_len = len;
    return 0;
}

/* ── Client → Nodus encode ───────────────────────────────────────── */

int nodus_t2_hello(uint32_t txn, const nodus_pubkey_t *pk,
                    const nodus_key_t *fp,
                    uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "hello");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "pk");
    cbor_encode_bstr(&enc, pk->bytes, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "fp");
    cbor_encode_bstr(&enc, fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "v");
    cbor_encode_uint(&enc, 2);   /* v=2: supports channel encryption */
    return finish(&enc, out_len);
}

int nodus_t2_auth(uint32_t txn, const nodus_sig_t *sig,
                   uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "auth");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, sig->bytes, NODUS_SIG_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_put(uint32_t txn, const uint8_t *token,
                  const nodus_key_t *key, const uint8_t *data, size_t data_len,
                  nodus_value_type_t type, uint32_t ttl,
                  uint64_t vid, uint64_t seq,
                  const nodus_sig_t *sig,
                  uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "put");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 7);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_bstr(&enc, data, data_len);
    cbor_encode_cstr(&enc, "type");
    cbor_encode_uint(&enc, (uint64_t)type);
    cbor_encode_cstr(&enc, "ttl");
    cbor_encode_uint(&enc, ttl);
    cbor_encode_cstr(&enc, "vid");
    cbor_encode_uint(&enc, vid);
    cbor_encode_cstr(&enc, "seq");
    cbor_encode_uint(&enc, seq);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, sig->bytes, NODUS_SIG_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_get(uint32_t txn, const uint8_t *token,
                  const nodus_key_t *key,
                  uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "get");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_get_all(uint32_t txn, const uint8_t *token,
                      const nodus_key_t *key,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "get_all");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_listen(uint32_t txn, const uint8_t *token,
                     const nodus_key_t *key,
                     uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "listen");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_unlisten(uint32_t txn, const uint8_t *token,
                       const nodus_key_t *key,
                       uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "unlisten");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_ping(uint32_t txn, const uint8_t *token,
                   uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ping");
    enc_token(&enc, token);
    return finish(&enc, out_len);
}

int nodus_t2_servers(uint32_t txn, const uint8_t *token,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "servers");
    enc_token(&enc, token);
    return finish(&enc, out_len);
}

/* Cluster-status query (Phase 0 / Task 0.2) — args-less query, server
 * reports its own state in the response. */
int nodus_t2_status(uint32_t txn, const uint8_t *token,
                     uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "status");
    enc_token(&enc, token);
    return finish(&enc, out_len);
}

int nodus_t2_circ_open(uint32_t txn, const uint8_t *token,
                        uint64_t cid, const nodus_key_t *peer_fp,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "circ_open");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    cbor_encode_cstr(&enc, "fp");  cbor_encode_bstr(&enc, peer_fp->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_circ_open_e2e(uint32_t txn, const uint8_t *token,
                            uint64_t cid, const nodus_key_t *peer_fp,
                            const uint8_t *e2e_ct,
                            uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "circ_open");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    cbor_encode_cstr(&enc, "fp");  cbor_encode_bstr(&enc, peer_fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "ect"); cbor_encode_bstr(&enc, e2e_ct, NODUS_KYBER_CT_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_circ_open_ok(uint32_t txn, uint64_t cid,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "circ_open");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    return finish(&enc, out_len);
}

int nodus_t2_circ_open_err(uint32_t txn, uint64_t cid, int code,
                            uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "circ_open_err");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "cid");  cbor_encode_uint(&enc, cid);
    cbor_encode_cstr(&enc, "code"); cbor_encode_uint(&enc, (uint64_t)code);
    return finish(&enc, out_len);
}

int nodus_t2_circ_inbound(uint32_t txn, uint64_t cid, const nodus_key_t *peer_fp,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "circ_inbound");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    cbor_encode_cstr(&enc, "fp");  cbor_encode_bstr(&enc, peer_fp->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_circ_inbound_e2e(uint32_t txn, uint64_t cid, const nodus_key_t *peer_fp,
                               const uint8_t *e2e_ct,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "circ_inbound");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    cbor_encode_cstr(&enc, "fp");  cbor_encode_bstr(&enc, peer_fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "ect"); cbor_encode_bstr(&enc, e2e_ct, NODUS_KYBER_CT_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_circ_data(uint32_t txn, const uint8_t *token,
                        uint64_t cid, const uint8_t *data, size_t data_len,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    if (data_len > NODUS_MAX_CIRCUIT_PAYLOAD) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "circ_data");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    cbor_encode_cstr(&enc, "d");   cbor_encode_bstr(&enc, data, data_len);
    return finish(&enc, out_len);
}

int nodus_t2_circ_close(uint32_t txn, const uint8_t *token, uint64_t cid,
                         uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "circ_close");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    return finish(&enc, out_len);
}

/* ── Inter-node circuit forwarding (Faz 1, TCP 4002) ────────────── */

int nodus_t2_ri_open(uint32_t txn, uint64_t ups_cid,
                      const nodus_key_t *src_fp, const nodus_key_t *dst_fp,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ri_open");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "ups"); cbor_encode_uint(&enc, ups_cid);
    cbor_encode_cstr(&enc, "src"); cbor_encode_bstr(&enc, src_fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "dst"); cbor_encode_bstr(&enc, dst_fp->bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_ri_open_e2e(uint32_t txn, uint64_t ups_cid,
                          const nodus_key_t *src_fp, const nodus_key_t *dst_fp,
                          const uint8_t *e2e_ct,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ri_open");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "ups"); cbor_encode_uint(&enc, ups_cid);
    cbor_encode_cstr(&enc, "src"); cbor_encode_bstr(&enc, src_fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "dst"); cbor_encode_bstr(&enc, dst_fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "ect"); cbor_encode_bstr(&enc, e2e_ct, NODUS_KYBER_CT_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_ri_open_ok(uint32_t txn, uint64_t ups_cid, uint64_t dns_cid,
                         uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ri_open_ok");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ups"); cbor_encode_uint(&enc, ups_cid);
    cbor_encode_cstr(&enc, "dns"); cbor_encode_uint(&enc, dns_cid);
    return finish(&enc, out_len);
}

int nodus_t2_ri_open_err(uint32_t txn, uint64_t ups_cid, int code,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ri_open_err");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ups");  cbor_encode_uint(&enc, ups_cid);
    cbor_encode_cstr(&enc, "code"); cbor_encode_uint(&enc, (uint64_t)code);
    return finish(&enc, out_len);
}

int nodus_t2_ri_data(uint32_t txn, uint64_t cid,
                      const uint8_t *data, size_t data_len,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    if (data_len > NODUS_MAX_CIRCUIT_PAYLOAD) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ri_data");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    cbor_encode_cstr(&enc, "d");   cbor_encode_bstr(&enc, data, data_len);
    return finish(&enc, out_len);
}

int nodus_t2_ri_close(uint32_t txn, uint64_t cid,
                       uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ri_close");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "cid"); cbor_encode_uint(&enc, cid);
    return finish(&enc, out_len);
}

/* ── Media operations (Client → Nodus) ──────────────────────────── */

int nodus_t2_media_put(uint32_t txn, const uint8_t *token,
                       const uint8_t content_hash[64],
                       uint32_t chunk_index, uint32_t chunk_count,
                       uint64_t total_size, uint8_t media_type,
                       uint32_t ttl, bool encrypted,
                       const uint8_t *data, size_t data_len,
                       const nodus_sig_t *sig,
                       uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "m_put");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 9);
    cbor_encode_cstr(&enc, "mh");
    cbor_encode_bstr(&enc, content_hash, 64);
    cbor_encode_cstr(&enc, "ci");
    cbor_encode_uint(&enc, chunk_index);
    cbor_encode_cstr(&enc, "cc");
    cbor_encode_uint(&enc, chunk_count);
    cbor_encode_cstr(&enc, "tsz");
    cbor_encode_uint(&enc, total_size);
    cbor_encode_cstr(&enc, "mt");
    cbor_encode_uint(&enc, media_type);
    cbor_encode_cstr(&enc, "ttl");
    cbor_encode_uint(&enc, ttl);
    cbor_encode_cstr(&enc, "menc");
    cbor_encode_bool(&enc, encrypted);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_bstr(&enc, data, data_len);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, sig->bytes, NODUS_SIG_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_media_get_meta(uint32_t txn, const uint8_t *token,
                            const uint8_t content_hash[64],
                            uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "m_meta");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "mh");
    cbor_encode_bstr(&enc, content_hash, 64);
    return finish(&enc, out_len);
}

int nodus_t2_media_get_chunk(uint32_t txn, const uint8_t *token,
                             const uint8_t content_hash[64],
                             uint32_t chunk_index,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "m_chunk");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "mh");
    cbor_encode_bstr(&enc, content_hash, 64);
    cbor_encode_cstr(&enc, "ci");
    cbor_encode_uint(&enc, chunk_index);
    return finish(&enc, out_len);
}

/* ── Batch operations (Client → Nodus) ──────────────────────────── */

int nodus_t2_get_batch(uint32_t txn, const uint8_t *token,
                        const nodus_key_t *keys, int key_count,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    if (!keys || key_count < 1 || key_count > NODUS_MAX_BATCH_KEYS) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "get_batch");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "ks");
    cbor_encode_array(&enc, (size_t)key_count);
    for (int i = 0; i < key_count; i++)
        cbor_encode_bstr(&enc, keys[i].bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_count_batch(uint32_t txn, const uint8_t *token,
                          const nodus_key_t *keys, int key_count,
                          const nodus_key_t *caller_fp,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    if (!keys || key_count < 1 || key_count > NODUS_MAX_BATCH_KEYS) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "cnt_batch");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, caller_fp ? 2 : 1);
    cbor_encode_cstr(&enc, "ks");
    cbor_encode_array(&enc, (size_t)key_count);
    for (int i = 0; i < key_count; i++)
        cbor_encode_bstr(&enc, keys[i].bytes, NODUS_KEY_BYTES);
    if (caller_fp) {
        cbor_encode_cstr(&enc, "fp");
        cbor_encode_bstr(&enc, caller_fp->bytes, NODUS_KEY_BYTES);
    }
    return finish(&enc, out_len);
}

/* ── Batch responses (Nodus → Client) ───────────────────────────── */

int nodus_t2_result_get_batch(uint32_t txn,
                               const nodus_key_t *keys, int key_count,
                               nodus_value_t ***vals_per_key,
                               const size_t *counts_per_key,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    if (!keys || key_count < 1) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "result");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "batch");
    cbor_encode_array(&enc, (size_t)key_count);
    for (int i = 0; i < key_count; i++) {
        size_t vc = counts_per_key ? counts_per_key[i] : 0;
        cbor_encode_map(&enc, 2);
        cbor_encode_cstr(&enc, "k");
        cbor_encode_bstr(&enc, keys[i].bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&enc, "vs");
        cbor_encode_array(&enc, vc);
        for (size_t j = 0; j < vc; j++) {
            uint8_t *vbuf = NULL;
            size_t vlen = 0;
            if (vals_per_key && vals_per_key[i] && vals_per_key[i][j] &&
                nodus_value_serialize(vals_per_key[i][j], &vbuf, &vlen) == 0) {
                cbor_encode_bstr(&enc, vbuf, vlen);
                free(vbuf);
            } else {
                cbor_encode_bstr(&enc, (const uint8_t *)"", 0);
            }
        }
    }
    return finish(&enc, out_len);
}

int nodus_t2_result_count_batch(uint32_t txn,
                                 const nodus_key_t *keys, int key_count,
                                 const size_t *counts,
                                 const bool *has_mine,
                                 uint8_t *buf, size_t cap, size_t *out_len) {
    if (!keys || key_count < 1) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "result");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "counts");
    cbor_encode_array(&enc, (size_t)key_count);
    for (int i = 0; i < key_count; i++) {
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "k");
        cbor_encode_bstr(&enc, keys[i].bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&enc, "c");
        cbor_encode_uint(&enc, counts ? counts[i] : 0);
        cbor_encode_cstr(&enc, "my");
        cbor_encode_bool(&enc, has_mine ? has_mine[i] : false);
    }
    return finish(&enc, out_len);
}

/* ── Channel operations (Client → Nodus) ─────────────────────────── */

int nodus_t2_ch_create(uint32_t txn, const uint8_t *token,
                        const uint8_t uuid[NODUS_UUID_BYTES],
                        bool encrypted,
                        const char *name, const char *description,
                        bool is_public,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_create");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    /* Count map entries: ch(1) + enc?(1) + name?(1) + desc?(1) + pub?(1) */
    int map_count = 1;
    if (encrypted) map_count++;
    if (name) map_count++;
    if (description) map_count++;
    if (is_public) map_count++;
    cbor_encode_map(&enc, map_count);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, uuid, NODUS_UUID_BYTES);
    if (encrypted) {
        cbor_encode_cstr(&enc, "enc");
        cbor_encode_bool(&enc, true);
    }
    if (name) {
        cbor_encode_cstr(&enc, "name");
        cbor_encode_cstr(&enc, name);
    }
    if (description) {
        cbor_encode_cstr(&enc, "desc");
        cbor_encode_cstr(&enc, description);
    }
    if (is_public) {
        cbor_encode_cstr(&enc, "pub");
        cbor_encode_bool(&enc, true);
    }
    return finish(&enc, out_len);
}

int nodus_t2_ch_post(uint32_t txn, const uint8_t *token,
                      const uint8_t ch_uuid[NODUS_UUID_BYTES],
                      const uint8_t post_uuid[NODUS_UUID_BYTES],
                      const uint8_t *body, size_t body_len,
                      uint64_t timestamp, const nodus_sig_t *sig,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_post");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "pid");
    cbor_encode_bstr(&enc, post_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_bstr(&enc, body, body_len);
    cbor_encode_cstr(&enc, "ts");
    cbor_encode_uint(&enc, timestamp);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, sig->bytes, NODUS_SIG_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_ch_get_posts(uint32_t txn, const uint8_t *token,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           uint64_t since_received_at, int max_count,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_get");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "ra");
    cbor_encode_uint(&enc, since_received_at);
    cbor_encode_cstr(&enc, "max");
    cbor_encode_uint(&enc, (uint64_t)max_count);
    return finish(&enc, out_len);
}

int nodus_t2_ch_subscribe(uint32_t txn, const uint8_t *token,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_sub");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, uuid, NODUS_UUID_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_ch_unsubscribe(uint32_t txn, const uint8_t *token,
                              const uint8_t uuid[NODUS_UUID_BYTES],
                              uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_unsub");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, uuid, NODUS_UUID_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_ch_member_update(uint32_t txn, const uint8_t *token,
                              const uint8_t ch_uuid[NODUS_UUID_BYTES],
                              uint8_t action,
                              const nodus_key_t *target_fp,
                              const nodus_sig_t *sig,
                              uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_mu");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "act");
    cbor_encode_uint(&enc, action);
    cbor_encode_cstr(&enc, "tfp");
    cbor_encode_bstr(&enc, target_fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, sig->bytes, NODUS_SIG_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_ch_member_update_ok(uint32_t txn,
                                  uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_mu_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

/* ── Channel discovery (Client → Nodus) ──────────────────────────── */

int nodus_t2_ch_list(uint32_t txn, const uint8_t *token,
                      int offset, int limit,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_list");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "off");
    cbor_encode_uint(&enc, (uint64_t)offset);
    cbor_encode_cstr(&enc, "lim");
    cbor_encode_uint(&enc, (uint64_t)limit);
    return finish(&enc, out_len);
}

int nodus_t2_ch_search(uint32_t txn, const uint8_t *token,
                        const char *query, int offset, int limit,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_search");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, query);
    cbor_encode_cstr(&enc, "off");
    cbor_encode_uint(&enc, (uint64_t)offset);
    cbor_encode_cstr(&enc, "lim");
    cbor_encode_uint(&enc, (uint64_t)limit);
    return finish(&enc, out_len);
}

int nodus_t2_ch_get(uint32_t txn, const uint8_t *token,
                     const uint8_t uuid[NODUS_UUID_BYTES],
                     uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "ch_get");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, uuid, NODUS_UUID_BYTES);
    return finish(&enc, out_len);
}

/* Helper: encode UUID bytes as 32-char hex string */
static void uuid_bytes_to_hex(const uint8_t uuid[NODUS_UUID_BYTES], char out[33]) {
    for (int i = 0; i < NODUS_UUID_BYTES; i++)
        snprintf(out + i * 2, 3, "%02x", uuid[i]);
    out[32] = '\0';
}

int nodus_t2_ch_list_ok(uint32_t txn,
                         const nodus_channel_meta_t *metas, size_t count,
                         uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_list_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "channels");
    cbor_encode_array(&enc, count);

    for (size_t i = 0; i < count; i++) {
        const nodus_channel_meta_t *m = &metas[i];
        cbor_encode_map(&enc, 5);

        cbor_encode_cstr(&enc, "uuid");
        char hex[33];
        uuid_bytes_to_hex(m->uuid, hex);
        cbor_encode_cstr(&enc, hex);

        cbor_encode_cstr(&enc, "name");
        cbor_encode_cstr(&enc, m->name);

        cbor_encode_cstr(&enc, "desc");
        cbor_encode_cstr(&enc, m->description);

        cbor_encode_cstr(&enc, "fp");
        if (m->has_creator_fp) {
            cbor_encode_bstr(&enc, m->creator_fp.bytes, NODUS_KEY_BYTES);
        } else {
            cbor_encode_bstr(&enc, (const uint8_t *)"", 0);
        }

        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, m->created_at);
    }

    return finish(&enc, out_len);
}

/* ── Nodus → Client encode ───────────────────────────────────────── */

int nodus_t2_challenge(uint32_t txn, const uint8_t *nonce,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "challenge");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "nonce");
    cbor_encode_bstr(&enc, nonce, NODUS_NONCE_LEN);
    return finish(&enc, out_len);
}

int nodus_t2_auth_ok(uint32_t txn, const uint8_t *token,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "auth_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "tok");
    cbor_encode_bstr(&enc, token, NODUS_SESSION_TOKEN_LEN);
    return finish(&enc, out_len);
}

int nodus_t2_auth_ok_kyber(uint32_t txn, const uint8_t *token,
                            const uint8_t *kyber_pk,
                            const nodus_pubkey_t *server_pk,
                            const nodus_sig_t *kpk_sig,
                            uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "auth_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 4);
    cbor_encode_cstr(&enc, "tok");
    cbor_encode_bstr(&enc, token, NODUS_SESSION_TOKEN_LEN);
    cbor_encode_cstr(&enc, "kpk");
    cbor_encode_bstr(&enc, kyber_pk, NODUS_KYBER_PK_BYTES);
    cbor_encode_cstr(&enc, "spk");
    cbor_encode_bstr(&enc, server_pk->bytes, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "kpk_sig");
    cbor_encode_bstr(&enc, kpk_sig->bytes, NODUS_SIG_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_key_init(uint32_t txn, const uint8_t *kyber_ct,
                       const uint8_t *nonce_c,
                       uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "key_init");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ct");
    cbor_encode_bstr(&enc, kyber_ct, NODUS_KYBER_CT_BYTES);
    cbor_encode_cstr(&enc, "nc");
    cbor_encode_bstr(&enc, nonce_c, NODUS_NONCE_LEN);
    return finish(&enc, out_len);
}

int nodus_t2_key_ack(uint32_t txn, const uint8_t *nonce_s,
                      uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "key_ack");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "ns");
    cbor_encode_bstr(&enc, nonce_s, NODUS_NONCE_LEN);
    return finish(&enc, out_len);
}

int nodus_t2_result(uint32_t txn, const nodus_value_t *val,
                     uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t *vbuf = NULL;
    size_t vlen = 0;
    if (nodus_value_serialize(val, &vbuf, &vlen) != 0)
        return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "result");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "val");
    cbor_encode_bstr(&enc, vbuf, vlen);

    free(vbuf);
    return finish(&enc, out_len);
}

int nodus_t2_result_multi(uint32_t txn, nodus_value_t **vals, size_t count,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "result");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "vals");
    cbor_encode_array(&enc, count);

    for (size_t i = 0; i < count; i++) {
        uint8_t *vbuf = NULL;
        size_t vlen = 0;
        if (nodus_value_serialize(vals[i], &vbuf, &vlen) != 0) {
            return -1;
        }
        cbor_encode_bstr(&enc, vbuf, vlen);
        free(vbuf);
    }

    return finish(&enc, out_len);
}

int nodus_t2_result_empty(uint32_t txn,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "result");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

int nodus_t2_error(uint32_t txn, int code, const char *msg,
                    uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    /* Error type 'e' */
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, txn);
    cbor_encode_cstr(&enc, "y"); cbor_encode_cstr(&enc, "e");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "code"); cbor_encode_uint(&enc, (uint64_t)code);
    cbor_encode_cstr(&enc, "msg");  cbor_encode_cstr(&enc, msg ? msg : "");
    return finish(&enc, out_len);
}

int nodus_t2_value_changed(uint32_t txn, const nodus_key_t *key,
                            const nodus_value_t *val,
                            uint8_t *buf, size_t cap, size_t *out_len) {
    uint8_t *vbuf = NULL;
    size_t vlen = 0;
    if (nodus_value_serialize(val, &vbuf, &vlen) != 0)
        return -1;

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "value_changed");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "k");
    cbor_encode_bstr(&enc, key->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "val");
    cbor_encode_bstr(&enc, vbuf, vlen);

    free(vbuf);
    return finish(&enc, out_len);
}

int nodus_t2_pong(uint32_t txn,
                   uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 3, txn, "pong");
    return finish(&enc, out_len);
}

int nodus_t2_put_ok(uint32_t txn,
                     uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "put_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

int nodus_t2_listen_ok(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "listen_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

/* ── Media responses (Nodus → Client) ───────────────────────────── */

int nodus_t2_media_put_ok(uint32_t txn, uint32_t chunk_index, bool complete,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "m_put_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ci");
    cbor_encode_uint(&enc, chunk_index);
    cbor_encode_cstr(&enc, "cmp");
    cbor_encode_bool(&enc, complete);
    return finish(&enc, out_len);
}

int nodus_t2_media_meta_result(uint32_t txn, const nodus_media_meta_t *meta,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "m_meta_r");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 7);
    cbor_encode_cstr(&enc, "mh");
    cbor_encode_bstr(&enc, meta->content_hash, 64);
    cbor_encode_cstr(&enc, "mt");
    cbor_encode_uint(&enc, meta->media_type);
    cbor_encode_cstr(&enc, "tsz");
    cbor_encode_uint(&enc, meta->total_size);
    cbor_encode_cstr(&enc, "cc");
    cbor_encode_uint(&enc, meta->chunk_count);
    cbor_encode_cstr(&enc, "menc");
    cbor_encode_bool(&enc, meta->encrypted);
    cbor_encode_cstr(&enc, "ttl");
    cbor_encode_uint(&enc, meta->ttl);
    cbor_encode_cstr(&enc, "cmp");
    cbor_encode_bool(&enc, meta->complete);
    return finish(&enc, out_len);
}

int nodus_t2_media_chunk_result(uint32_t txn, uint32_t chunk_index,
                                const uint8_t *data, size_t data_len,
                                uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "m_chunk_r");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ci");
    cbor_encode_uint(&enc, chunk_index);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_bstr(&enc, data, data_len);
    return finish(&enc, out_len);
}

/* ── Channel responses (Nodus → Client) ──────────────────────────── */

int nodus_t2_ch_create_ok(uint32_t txn,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_create_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

int nodus_t2_ch_post_ok(uint32_t txn, uint64_t received_at,
                         uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_post_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "ra");
    cbor_encode_uint(&enc, received_at);
    return finish(&enc, out_len);
}

int nodus_t2_ch_posts(uint32_t txn, const nodus_channel_post_t *posts,
                       size_t count,
                       uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_posts");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "posts");
    cbor_encode_array(&enc, count);

    for (size_t i = 0; i < count; i++) {
        const nodus_channel_post_t *p = &posts[i];
        cbor_encode_map(&enc, 6);
        cbor_encode_cstr(&enc, "ra");
        cbor_encode_uint(&enc, p->received_at);
        cbor_encode_cstr(&enc, "pid");
        cbor_encode_bstr(&enc, p->post_uuid, NODUS_UUID_BYTES);
        cbor_encode_cstr(&enc, "afp");
        cbor_encode_bstr(&enc, p->author_fp.bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, p->timestamp);
        cbor_encode_cstr(&enc, "d");
        cbor_encode_bstr(&enc, (const uint8_t *)p->body, p->body_len);
        cbor_encode_cstr(&enc, "sig");
        cbor_encode_bstr(&enc, p->signature.bytes, NODUS_SIG_BYTES);
    }

    return finish(&enc, out_len);
}

int nodus_t2_ch_sub_ok(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_sub_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

int nodus_t2_ch_post_notify(uint32_t txn,
                             const uint8_t ch_uuid[NODUS_UUID_BYTES],
                             const nodus_channel_post_t *post,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ch_ntf");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 7);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "ra");
    cbor_encode_uint(&enc, post->received_at);
    cbor_encode_cstr(&enc, "pid");
    cbor_encode_bstr(&enc, post->post_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "afp");
    cbor_encode_bstr(&enc, post->author_fp.bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "ts");
    cbor_encode_uint(&enc, post->timestamp);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_bstr(&enc, (const uint8_t *)post->body, post->body_len);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, post->signature.bytes, NODUS_SIG_BYTES);
    return finish(&enc, out_len);
}

/* ── Cluster-status response (Phase 0 / Task 0.2) ─────────────────── */

int nodus_t2_status_result(uint32_t txn,
                            const nodus_t2_status_info_t *info,
                            uint8_t *buf, size_t cap, size_t *out_len) {
    if (!info) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "status");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 7);
    cbor_encode_cstr(&enc, "bh");   cbor_encode_uint(&enc, info->block_height);
    cbor_encode_cstr(&enc, "sr");   cbor_encode_bstr(&enc, info->state_root, 64);
    cbor_encode_cstr(&enc, "chid"); cbor_encode_bstr(&enc, info->chain_id, 32);
    cbor_encode_cstr(&enc, "pc");   cbor_encode_uint(&enc, info->peer_count);
    cbor_encode_cstr(&enc, "us");   cbor_encode_uint(&enc, info->uptime_sec);
    cbor_encode_cstr(&enc, "wc");   cbor_encode_uint(&enc, info->wall_clock);
    cbor_encode_cstr(&enc, "df");   cbor_encode_uint(&enc, info->disk_free_pct);
    return finish(&enc, out_len);
}

/* ── Server list response ─────────────────────────────────────────── */

int nodus_t2_servers_result(uint32_t txn,
                             const nodus_t2_server_info_t *servers,
                             int server_count,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "servers");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "srvs");
    cbor_encode_array(&enc, (size_t)server_count);

    for (int i = 0; i < server_count; i++) {
        int fields = servers[i].has_dil_fp ? 3 : 2;
        cbor_encode_map(&enc, (size_t)fields);
        cbor_encode_cstr(&enc, "ip");
        cbor_encode_cstr(&enc, servers[i].ip);
        cbor_encode_cstr(&enc, "tp");
        cbor_encode_uint(&enc, servers[i].tcp_port);
        if (servers[i].has_dil_fp) {
            cbor_encode_cstr(&enc, "fp");
            cbor_encode_bstr(&enc, servers[i].dil_fp, 16);
        }
    }

    return finish(&enc, out_len);
}

/* ── Presence protocol ────────────────────────────────────────────── */

int nodus_t2_presence_query(uint32_t txn, const uint8_t *token,
                              const nodus_key_t *fps, int count,
                              uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 5, txn, "pq");
    enc_token(&enc, token);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "fps");
    cbor_encode_array(&enc, (size_t)count);
    for (int i = 0; i < count; i++)
        cbor_encode_bstr(&enc, fps[i].bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

int nodus_t2_presence_result(uint32_t txn,
                               const nodus_key_t *fps, const bool *online,
                               const uint8_t *peers, const uint64_t *last_seen,
                               int count,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    int online_count = 0;
    int offline_seen_count = 0;
    if (fps && online) {
        for (int i = 0; i < count; i++) {
            if (online[i])
                online_count++;
            else if (last_seen && last_seen[i] > 0)
                offline_seen_count++;
        }
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    int rmap = 1 + (offline_seen_count > 0 ? 1 : 0);
    enc_response_header(&enc, 4, txn, "pq");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, (size_t)rmap);

    /* ps: online entries */
    cbor_encode_cstr(&enc, "ps");
    cbor_encode_array(&enc, (size_t)online_count);
    if (fps && online) {
        for (int i = 0; i < count; i++) {
            if (!online[i]) continue;
            int fields = last_seen ? 3 : 2;
            cbor_encode_map(&enc, (size_t)fields);
            cbor_encode_cstr(&enc, "fp");
            cbor_encode_bstr(&enc, fps[i].bytes, NODUS_KEY_BYTES);
            cbor_encode_cstr(&enc, "pi");
            cbor_encode_uint(&enc, peers ? peers[i] : 0);
            if (last_seen) {
                cbor_encode_cstr(&enc, "ls");
                cbor_encode_uint(&enc, last_seen[i]);
            }
        }
    }

    /* os: offline entries with last_seen */
    if (offline_seen_count > 0 && fps && online && last_seen) {
        cbor_encode_cstr(&enc, "os");
        cbor_encode_array(&enc, (size_t)offline_seen_count);
        for (int i = 0; i < count; i++) {
            if (online[i] || last_seen[i] == 0) continue;
            cbor_encode_map(&enc, 2);
            cbor_encode_cstr(&enc, "fp");
            cbor_encode_bstr(&enc, fps[i].bytes, NODUS_KEY_BYTES);
            cbor_encode_cstr(&enc, "ls");
            cbor_encode_uint(&enc, last_seen[i]);
        }
    }

    return finish(&enc, out_len);
}

int nodus_t2_presence_sync(uint32_t txn, const nodus_key_t *fps, int count,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "p_sync");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "fps");
    cbor_encode_array(&enc, (size_t)count);
    for (int i = 0; i < count; i++)
        cbor_encode_bstr(&enc, fps[i].bytes, NODUS_KEY_BYTES);
    return finish(&enc, out_len);
}

/* ── Inter-Nodus media replication ────────────────────────────────── */

int nodus_t2_media_store_value(uint32_t txn,
                               const nodus_media_meta_t *meta,
                               uint32_t chunk_index,
                               const uint8_t *data, size_t data_len,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    if (!meta || !data || data_len == 0) return -1;
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "m_sv");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 9);
    cbor_encode_cstr(&enc, "mh");
    cbor_encode_bstr(&enc, meta->content_hash, 64);
    cbor_encode_cstr(&enc, "ci");
    cbor_encode_uint(&enc, chunk_index);
    cbor_encode_cstr(&enc, "cc");
    cbor_encode_uint(&enc, meta->chunk_count);
    cbor_encode_cstr(&enc, "tsz");
    cbor_encode_uint(&enc, meta->total_size);
    cbor_encode_cstr(&enc, "mt");
    cbor_encode_uint(&enc, meta->media_type);
    cbor_encode_cstr(&enc, "ttl");
    cbor_encode_uint(&enc, meta->ttl);
    cbor_encode_cstr(&enc, "menc");
    cbor_encode_bool(&enc, meta->encrypted);
    cbor_encode_cstr(&enc, "cmp");
    cbor_encode_bool(&enc, meta->complete);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_bstr(&enc, data, data_len);
    return finish(&enc, out_len);
}

/* ── Inter-Nodus replication ──────────────────────────────────────── */

int nodus_t2_ch_replicate(uint32_t txn,
                           const uint8_t ch_uuid[NODUS_UUID_BYTES],
                           const nodus_channel_post_t *post,
                           const nodus_pubkey_t *author_pk,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ch_rep");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, author_pk ? 8 : 7);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "ra");
    cbor_encode_uint(&enc, post->received_at);
    cbor_encode_cstr(&enc, "pid");
    cbor_encode_bstr(&enc, post->post_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "afp");
    cbor_encode_bstr(&enc, post->author_fp.bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "ts");
    cbor_encode_uint(&enc, post->timestamp);
    cbor_encode_cstr(&enc, "d");
    cbor_encode_bstr(&enc, (const uint8_t *)post->body, post->body_len);
    cbor_encode_cstr(&enc, "sig");
    cbor_encode_bstr(&enc, post->signature.bytes, NODUS_SIG_BYTES);
    /* Author public key for signature verification (SECURITY: CRIT-01) */
    if (author_pk) {
        cbor_encode_cstr(&enc, "apk");
        cbor_encode_bstr(&enc, author_pk->bytes, NODUS_PK_BYTES);
    }
    return finish(&enc, out_len);
}

int nodus_t2_ch_rep_ok(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_rep_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

/* ── Ring management (Nodus ↔ Nodus, TCP 4002) ─────────────────── */

int nodus_t2_ring_check(uint32_t txn,
                          const nodus_key_t *node_id,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const char *status,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ring_check");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "nid");
    cbor_encode_bstr(&enc, node_id->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "st");
    cbor_encode_cstr(&enc, status);
    return finish(&enc, out_len);
}

int nodus_t2_ring_ack(uint32_t txn,
                        const uint8_t ch_uuid[NODUS_UUID_BYTES],
                        bool agree,
                        uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ring_ack");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "ag");
    cbor_encode_bool(&enc, agree);
    return finish(&enc, out_len);
}

int nodus_t2_ring_evict(uint32_t txn,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          uint32_t version,
                          uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ring_evict");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "v");
    cbor_encode_uint(&enc, version);
    return finish(&enc, out_len);
}

int nodus_t2_ch_ring_changed(uint32_t txn,
                               const uint8_t ch_uuid[NODUS_UUID_BYTES],
                               uint32_t version,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ch_ring");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "v");
    cbor_encode_uint(&enc, version);
    return finish(&enc, out_len);
}

/* ── Channel rewrite: node-to-node protocol (TCP 4003) ────────── */

int nodus_t2_ch_node_hello(uint32_t txn, const nodus_pubkey_t *pk,
                            const nodus_key_t *fp, uint32_t ring_version,
                            uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "node_hello");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "pk");
    cbor_encode_bstr(&enc, pk->bytes, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "fp");
    cbor_encode_bstr(&enc, fp->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "rv");
    cbor_encode_uint(&enc, ring_version);
    return finish(&enc, out_len);
}

int nodus_t2_ch_node_auth_ok(uint32_t txn,
                              const uint8_t *token, size_t token_len,
                              uint32_t current_ring_version,
                              const nodus_ring_member_t *ring_members, int ring_count,
                              uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "node_auth_ok");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "tok");
    cbor_encode_bstr(&enc, token, token_len);
    cbor_encode_cstr(&enc, "rv");
    cbor_encode_uint(&enc, current_ring_version);
    cbor_encode_cstr(&enc, "ring");
    cbor_encode_array(&enc, (size_t)ring_count);
    for (int i = 0; i < ring_count; i++) {
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "ip");
        cbor_encode_cstr(&enc, ring_members[i].ip);
        cbor_encode_cstr(&enc, "port");
        cbor_encode_uint(&enc, ring_members[i].tcp_port);
        cbor_encode_cstr(&enc, "nid");
        cbor_encode_bstr(&enc, ring_members[i].node_id.bytes, NODUS_KEY_BYTES);
    }
    return finish(&enc, out_len);
}

int nodus_t2_ch_heartbeat(uint32_t txn,
                           uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ch_hb");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

int nodus_t2_ch_heartbeat_ack(uint32_t txn,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_hb_ack");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 0);
    return finish(&enc, out_len);
}

int nodus_t2_ch_sync_request(uint32_t txn,
                              const uint8_t ch_uuid[NODUS_UUID_BYTES],
                              uint64_t since_ms,
                              uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ch_sync_req");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "since");
    cbor_encode_uint(&enc, since_ms);
    return finish(&enc, out_len);
}

int nodus_t2_ch_sync_response(uint32_t txn,
                               const uint8_t ch_uuid[NODUS_UUID_BYTES],
                               const nodus_channel_post_t *posts, size_t count,
                               uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_response_header(&enc, 4, txn, "ch_sync_res");
    cbor_encode_cstr(&enc, "r");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "ch");
    cbor_encode_bstr(&enc, ch_uuid, NODUS_UUID_BYTES);
    cbor_encode_cstr(&enc, "posts");
    cbor_encode_array(&enc, count);
    for (size_t i = 0; i < count; i++) {
        const nodus_channel_post_t *p = &posts[i];
        cbor_encode_map(&enc, 6);
        cbor_encode_cstr(&enc, "ra");
        cbor_encode_uint(&enc, p->received_at);
        cbor_encode_cstr(&enc, "pid");
        cbor_encode_bstr(&enc, p->post_uuid, NODUS_UUID_BYTES);
        cbor_encode_cstr(&enc, "afp");
        cbor_encode_bstr(&enc, p->author_fp.bytes, NODUS_KEY_BYTES);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, p->timestamp);
        cbor_encode_cstr(&enc, "d");
        cbor_encode_bstr(&enc, (const uint8_t *)p->body, p->body_len);
        cbor_encode_cstr(&enc, "sig");
        cbor_encode_bstr(&enc, p->signature.bytes, NODUS_SIG_BYTES);
    }
    return finish(&enc, out_len);
}

int nodus_t2_ch_ring_rejoin(uint32_t txn,
                             const nodus_key_t *node_id,
                             uint32_t my_ring_version,
                             uint8_t *buf, size_t cap, size_t *out_len) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_query_header(&enc, 4, txn, "ring_rejoin");
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 2);
    cbor_encode_cstr(&enc, "nid");
    cbor_encode_bstr(&enc, node_id->bytes, NODUS_KEY_BYTES);
    cbor_encode_cstr(&enc, "rv");
    cbor_encode_uint(&enc, my_ring_version);
    return finish(&enc, out_len);
}

/* ── Decode ──────────────────────────────────────────────────────── */

/* IMPORTANT: This decoder dispatches on msg->method for shared keys
 * ("cid", "d", "code", "fp", "src", "dst"). This relies on the encoder
 * writing the "q" (method) field BEFORE "a" (args) in the top-level map.
 * All encoders in this file follow that order via enc_query_header /
 * enc_response_header — do not reorder them. */
int nodus_t2_decode(const uint8_t *buf, size_t len, nodus_tier2_msg_t *msg) {
    if (!buf || !msg) return -1;
    memset(msg, 0, sizeof(*msg));

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, buf, len);

    cbor_item_t top = cbor_decode_next(&dec);
    if (top.type != CBOR_ITEM_MAP) return -1;
    size_t map_count = top.count;

    for (size_t i = 0; i < map_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(&dec); continue; }

        /* "t" → transaction ID */
        if (key.tstr.len == 1 && key.tstr.ptr[0] == 't') {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT)
                msg->txn_id = (uint32_t)val.uint_val;
        }
        /* "y" → type */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'y') {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_TSTR && val.tstr.len >= 1)
                msg->type = val.tstr.ptr[0];
        }
        /* "q" → method */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'q') {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_TSTR) {
                size_t clen = val.tstr.len < sizeof(msg->method) - 1 ?
                              val.tstr.len : sizeof(msg->method) - 1;
                memcpy(msg->method, val.tstr.ptr, clen);
                msg->method[clen] = '\0';
            }
        }
        /* "tok" → session token */
        else if (key.tstr.len == 3 && memcmp(key.tstr.ptr, "tok", 3) == 0) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SESSION_TOKEN_LEN) {
                memcpy(msg->token, val.bstr.ptr, NODUS_SESSION_TOKEN_LEN);
                msg->has_token = true;
            }
        }
        /* "a" → arguments */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'a') {
            cbor_item_t args = cbor_decode_next(&dec);
            if (args.type != CBOR_ITEM_MAP) continue;

            for (size_t j = 0; j < args.count; j++) {
                cbor_item_t akey = cbor_decode_next(&dec);
                if (akey.type != CBOR_ITEM_TSTR) {
                    cbor_decode_skip(&dec); continue;
                }

                /* pk (hello) */
                if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "pk", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_PK_BYTES)
                        memcpy(msg->pk.bytes, val.bstr.ptr, NODUS_PK_BYTES);
                }
                /* fp (hello / circ_open / circ_inbound peer fp) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "fp", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES) {
                        if (strcmp(msg->method, "circ_open") == 0 ||
                            strcmp(msg->method, "circ_inbound") == 0) {
                            memcpy(msg->circ_peer_fp.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                            msg->has_circ = true;
                        } else {
                            memcpy(msg->fp.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                        }
                    }
                }
                /* cid (circ_*: circuit id; ri_data/ri_close: inter-node cid) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "cid", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        if (strcmp(msg->method, "ri_data") == 0 ||
                            strcmp(msg->method, "ri_close") == 0) {
                            msg->ri_cid = val.uint_val;
                            msg->has_ri = true;
                        } else {
                            msg->circ_cid = val.uint_val;
                            if (IS_CIRC_METHOD(msg->method)) {
                                msg->has_circ = true;
                            }
                        }
                    }
                }
                /* code (circ_open_err / ri_open_err: error code) */
                else if (akey.tstr.len == 4 && memcmp(akey.tstr.ptr, "code", 4) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        if (strcmp(msg->method, "ri_open_err") == 0) {
                            msg->ri_err_code = (int)val.uint_val;
                            msg->has_ri = true;
                        } else if (IS_CIRC_METHOD(msg->method)) {
                            msg->circ_err_code = (int)val.uint_val;
                            msg->has_circ = true;
                        }
                    }
                }
                /* ups (ri_open / ri_open_ok / ri_open_err: upstream cid) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "ups", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->ri_ups_cid = val.uint_val;
                        msg->has_ri = true;
                    }
                }
                /* dns (ri_open_ok: downstream cid) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "dns", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->ri_dns_cid = val.uint_val;
                        msg->has_ri = true;
                    }
                }
                /* src (ri_open: source user fp) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "src", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES &&
                        IS_RI_METHOD(msg->method)) {
                        memcpy(msg->ri_src_fp.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                        msg->has_ri = true;
                    }
                }
                /* dst (ri_open: target user fp) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "dst", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES &&
                        IS_RI_METHOD(msg->method)) {
                        memcpy(msg->ri_dst_fp.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                        msg->has_ri = true;
                    }
                }
                /* sig (auth) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "sig", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES)
                        memcpy(msg->sig.bytes, val.bstr.ptr, NODUS_SIG_BYTES);
                }
                /* ect (circ_open/circ_inbound/ri_open: E2E Kyber ciphertext) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "ect", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KYBER_CT_BYTES) {
                        memcpy(msg->e2e_ct, val.bstr.ptr, NODUS_KYBER_CT_BYTES);
                        msg->has_e2e_ct = true;
                    }
                }
                /* v (hello: protocol version) */
                else if (akey.tstr.len == 1 && akey.tstr.ptr[0] == 'v') {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->proto_version = (uint32_t)val.uint_val;
                }
                /* ct (key_init: Kyber ciphertext) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "ct", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KYBER_CT_BYTES) {
                        memcpy(msg->kyber_ct, val.bstr.ptr, NODUS_KYBER_CT_BYTES);
                        msg->has_kyber_ct = true;
                    }
                }
                /* nc (key_init: client nonce) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "nc", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_NONCE_LEN) {
                        memcpy(msg->key_nonce, val.bstr.ptr, NODUS_NONCE_LEN);
                        msg->has_key_nonce = true;
                    }
                }
                /* k (put/get/listen key) */
                else if (akey.tstr.len == 1 && akey.tstr.ptr[0] == 'k') {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                        memcpy(msg->key.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                }
                /* d (put data / circ_data / ri_data payload) */
                else if (akey.tstr.len == 1 && akey.tstr.ptr[0] == 'd') {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len > 0) {
                        if (strcmp(msg->method, "circ_data") == 0) {
                            msg->circ_data = malloc(val.bstr.len);
                            if (msg->circ_data) {
                                memcpy(msg->circ_data, val.bstr.ptr, val.bstr.len);
                                msg->circ_data_len = val.bstr.len;
                                msg->has_circ = true;
                            }
                        } else if (strcmp(msg->method, "ri_data") == 0) {
                            msg->ri_data = malloc(val.bstr.len);
                            if (msg->ri_data) {
                                memcpy(msg->ri_data, val.bstr.ptr, val.bstr.len);
                                msg->ri_data_len = val.bstr.len;
                                msg->has_ri = true;
                            }
                        } else {
                            msg->data = malloc(val.bstr.len);
                            if (msg->data) {
                                memcpy(msg->data, val.bstr.ptr, val.bstr.len);
                                msg->data_len = val.bstr.len;
                            }
                        }
                    }
                }
                /* type (put) */
                else if (akey.tstr.len == 4 && memcmp(akey.tstr.ptr, "type", 4) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->val_type = (nodus_value_type_t)val.uint_val;
                }
                /* ttl (put) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "ttl", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ttl = (uint32_t)val.uint_val;
                }
                /* vid (put) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "vid", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->vid = val.uint_val;
                }
                /* seq (put) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "seq", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->seq = val.uint_val;
                }
                /* ra (channel received_at — ch_get, ch_ntf, ch_rep) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "ra", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ch_received_at = val.uint_val;
                }
                /* val (value_changed, serialized value) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "val", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR)
                        nodus_value_deserialize(val.bstr.ptr, val.bstr.len, &msg->value);
                }
                /* ch (channel UUID) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "ch", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_UUID_BYTES)
                        memcpy(msg->channel_uuid, val.bstr.ptr, NODUS_UUID_BYTES);
                }
                /* pid (post UUID) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "pid", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_UUID_BYTES)
                        memcpy(msg->post_uuid_ch, val.bstr.ptr, NODUS_UUID_BYTES);
                }
                /* ts (timestamp) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "ts", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ch_timestamp = val.uint_val;
                }
                /* max (max count) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "max", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ch_max_count = (int)val.uint_val;
                }
                /* afp (author fingerprint) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "afp", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                        memcpy(msg->fp.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                }
                /* apk (author public key for ch_rep sig verification, CRIT-01) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "apk", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_PK_BYTES) {
                        memcpy(msg->author_pk.bytes, val.bstr.ptr, NODUS_PK_BYTES);
                        msg->has_author_pk = true;
                    }
                }
                /* nid (ring_check: node_id) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "nid", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                        memcpy(msg->ring_node_id.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                }
                /* st (ring_check: status "dead"/"alive") */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "st", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_TSTR && val.tstr.len < sizeof(msg->ring_status)) {
                        memcpy(msg->ring_status, val.tstr.ptr, val.tstr.len);
                        msg->ring_status[val.tstr.len] = '\0';
                    }
                }
                /* v (ring_evict/ch_ring_changed: version) */
                else if (akey.tstr.len == 1 && akey.tstr.ptr[0] == 'v') {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ring_version = (uint32_t)val.uint_val;
                }
                /* rv (node_hello/ring_rejoin: ring version) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "rv", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ring_version = (uint32_t)val.uint_val;
                }
                /* since (ch_sync_req: since timestamp ms) */
                else if (akey.tstr.len == 5 && memcmp(akey.tstr.ptr, "since", 5) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ch_since_ms = val.uint_val;
                }
                /* fps (presence query/sync: array of fingerprints) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "fps", 3) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t cap = arr.count > NODUS_MAX_WIRE_FPS ? NODUS_MAX_WIRE_FPS : arr.count;
                        msg->pq_fps = calloc(cap, sizeof(nodus_key_t));
                        if (msg->pq_fps) {
                            msg->pq_count = 0;
                            for (size_t k = 0; k < arr.count; k++) {
                                cbor_item_t vi = cbor_decode_next(&dec);
                                if (vi.type == CBOR_ITEM_BSTR &&
                                    vi.bstr.len == NODUS_KEY_BYTES &&
                                    (size_t)msg->pq_count < cap) {
                                    memcpy(msg->pq_fps[msg->pq_count].bytes,
                                           vi.bstr.ptr, NODUS_KEY_BYTES);
                                    msg->pq_count++;
                                }
                            }
                        }
                    }
                }
                /* enc (ch_create: encrypted flag) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "enc", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BOOL)
                        msg->ch_encrypted = val.bool_val;
                }
                /* name (ch_create: channel name) */
                else if (akey.tstr.len == 4 && memcmp(akey.tstr.ptr, "name", 4) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_TSTR && val.tstr.len > 0) {
                        msg->ch_name = strndup(val.tstr.ptr, val.tstr.len);
                    }
                }
                /* desc (ch_create: channel description) */
                else if (akey.tstr.len == 4 && memcmp(akey.tstr.ptr, "desc", 4) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_TSTR) {
                        msg->ch_description = strndup(val.tstr.ptr, val.tstr.len);
                    }
                }
                /* pub (ch_create: is_public flag) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "pub", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BOOL)
                        msg->ch_is_public = val.bool_val;
                }
                /* q (ch_search: query string) */
                else if (akey.tstr.len == 1 && akey.tstr.ptr[0] == 'q') {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_TSTR && val.tstr.len > 0)
                        msg->ch_query = strndup(val.tstr.ptr, val.tstr.len);
                }
                /* off (ch_list/ch_search: offset) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "off", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ch_offset = (int)val.uint_val;
                }
                /* lim (ch_list/ch_search: limit) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "lim", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ch_limit = (int)val.uint_val;
                }
                /* act (ch_member_update: action 1=add, 2=remove) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "act", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->ch_mu_action = (uint8_t)val.uint_val;
                        msg->has_ch_mu = true;
                    }
                }
                /* tfp (ch_member_update: target fingerprint) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "tfp", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KEY_BYTES)
                        memcpy(msg->ch_mu_target_fp.bytes, val.bstr.ptr, NODUS_KEY_BYTES);
                }
                /* mh (media: content hash SHA3-512) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "mh", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64) {
                        memcpy(msg->media_hash, val.bstr.ptr, 64);
                        msg->has_media = true;
                    }
                }
                /* ci (media: chunk index) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "ci", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_chunk_idx = (uint32_t)val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* cc (media: chunk count) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "cc", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_chunk_count = (uint32_t)val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* tsz (media: total size) */
                else if (akey.tstr.len == 3 && memcmp(akey.tstr.ptr, "tsz", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_total_size = val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* mt (media: media type) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "mt", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_type = (uint8_t)val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* menc (media: encrypted flag) */
                else if (akey.tstr.len == 4 && memcmp(akey.tstr.ptr, "menc", 4) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BOOL) {
                        msg->media_encrypted = val.bool_val;
                        msg->has_media = true;
                    }
                }
                /* ks (get_batch / cnt_batch: key array) */
                else if (akey.tstr.len == 2 && memcmp(akey.tstr.ptr, "ks", 2) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t bk_cap = arr.count > NODUS_MAX_BATCH_KEYS ?
                                        NODUS_MAX_BATCH_KEYS : arr.count;
                        msg->batch_keys = calloc(bk_cap, sizeof(nodus_key_t));
                        if (msg->batch_keys) {
                            msg->batch_key_count = 0;
                            for (size_t k = 0; k < arr.count; k++) {
                                cbor_item_t vi = cbor_decode_next(&dec);
                                if (vi.type == CBOR_ITEM_BSTR &&
                                    vi.bstr.len == NODUS_KEY_BYTES &&
                                    (size_t)msg->batch_key_count < bk_cap) {
                                    memcpy(msg->batch_keys[msg->batch_key_count].bytes,
                                           vi.bstr.ptr, NODUS_KEY_BYTES);
                                    msg->batch_key_count++;
                                }
                            }
                        }
                    }
                }
                else {
                    cbor_decode_skip(&dec);
                }
            }
        }
        /* "r" → results */
        else if (key.tstr.len == 1 && key.tstr.ptr[0] == 'r') {
            cbor_item_t res = cbor_decode_next(&dec);
            if (res.type != CBOR_ITEM_MAP) continue;

            for (size_t j = 0; j < res.count; j++) {
                cbor_item_t rkey = cbor_decode_next(&dec);
                if (rkey.type != CBOR_ITEM_TSTR) {
                    cbor_decode_skip(&dec); continue;
                }

                /* nonce (challenge) */
                if (rkey.tstr.len == 5 && memcmp(rkey.tstr.ptr, "nonce", 5) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_NONCE_LEN)
                        memcpy(msg->nonce, val.bstr.ptr, NODUS_NONCE_LEN);
                }
                /* tok (auth_ok) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "tok", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SESSION_TOKEN_LEN) {
                        memcpy(msg->token, val.bstr.ptr, NODUS_SESSION_TOKEN_LEN);
                        msg->has_token = true;
                    }
                }
                /* kpk (auth_ok: server Kyber pubkey) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "kpk", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_KYBER_PK_BYTES) {
                        memcpy(msg->kyber_pk, val.bstr.ptr, NODUS_KYBER_PK_BYTES);
                        msg->has_kyber_pk = true;
                    }
                }
                /* spk (auth_ok: server Dilithium5 pubkey) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "spk", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_PK_BYTES) {
                        memcpy(msg->server_pk.bytes, val.bstr.ptr, NODUS_PK_BYTES);
                        msg->has_server_pk = true;
                    }
                }
                /* kpk_sig (auth_ok: Dilithium5 sig over kyber_pk || nonce) */
                else if (rkey.tstr.len == 7 && memcmp(rkey.tstr.ptr, "kpk_sig", 7) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_SIG_BYTES) {
                        memcpy(msg->kpk_sig.bytes, val.bstr.ptr, NODUS_SIG_BYTES);
                        msg->has_kpk_sig = true;
                    }
                }
                /* ns (key_ack: server nonce) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "ns", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_NONCE_LEN) {
                        memcpy(msg->key_nonce, val.bstr.ptr, NODUS_NONCE_LEN);
                        msg->has_key_nonce = true;
                    }
                }
                /* val (result single) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "val", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR)
                        nodus_value_deserialize(val.bstr.ptr, val.bstr.len, &msg->value);
                }
                /* vals (result multi) */
                else if (rkey.tstr.len == 4 && memcmp(rkey.tstr.ptr, "vals", 4) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t cap = arr.count > NODUS_MAX_WIRE_VALUES ? NODUS_MAX_WIRE_VALUES : arr.count;
                        msg->values = calloc(cap, sizeof(nodus_value_t *));
                        if (msg->values) {
                            msg->value_count = 0;
                            for (size_t k = 0; k < arr.count; k++) {
                                cbor_item_t vi = cbor_decode_next(&dec);
                                if (vi.type == CBOR_ITEM_BSTR && msg->value_count < cap) {
                                    nodus_value_t *v = NULL;
                                    if (nodus_value_deserialize(vi.bstr.ptr, vi.bstr.len, &v) == 0)
                                        msg->values[msg->value_count++] = v;
                                }
                            }
                        }
                    }
                }
                /* batch (get_batch result: array of {k, vs}) */
                else if (rkey.tstr.len == 5 && memcmp(rkey.tstr.ptr, "batch", 5) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t bk_cap = arr.count > NODUS_MAX_BATCH_KEYS ?
                                        NODUS_MAX_BATCH_KEYS : arr.count;
                        msg->batch_keys = calloc(bk_cap, sizeof(nodus_key_t));
                        msg->batch_vals = calloc(bk_cap, sizeof(nodus_value_t **));
                        msg->batch_val_counts = calloc(bk_cap, sizeof(size_t));
                        if (msg->batch_keys && msg->batch_vals && msg->batch_val_counts) {
                            msg->batch_key_count = 0;
                            for (size_t ki = 0; ki < arr.count; ki++) {
                                cbor_item_t emap = cbor_decode_next(&dec);
                                if (emap.type != CBOR_ITEM_MAP) continue;
                                if ((size_t)msg->batch_key_count >= bk_cap) {
                                    for (size_t m = 0; m < emap.count; m++) {
                                        cbor_decode_skip(&dec);
                                        cbor_decode_skip(&dec);
                                    }
                                    continue;
                                }
                                int bi = msg->batch_key_count;
                                msg->batch_vals[bi] = NULL;
                                msg->batch_val_counts[bi] = 0;
                                for (size_t m = 0; m < emap.count; m++) {
                                    cbor_item_t ek = cbor_decode_next(&dec);
                                    if (ek.type != CBOR_ITEM_TSTR) {
                                        cbor_decode_skip(&dec); continue;
                                    }
                                    if (ek.tstr.len == 1 && ek.tstr.ptr[0] == 'k') {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_BSTR &&
                                            ev.bstr.len == NODUS_KEY_BYTES)
                                            memcpy(msg->batch_keys[bi].bytes,
                                                   ev.bstr.ptr, NODUS_KEY_BYTES);
                                    } else if (ek.tstr.len == 2 &&
                                               memcmp(ek.tstr.ptr, "vs", 2) == 0) {
                                        cbor_item_t varr = cbor_decode_next(&dec);
                                        if (varr.type == CBOR_ITEM_ARRAY) {
                                            size_t vc = varr.count > NODUS_MAX_WIRE_VALUES ?
                                                        NODUS_MAX_WIRE_VALUES : varr.count;
                                            if (vc > 0) {
                                                msg->batch_vals[bi] = calloc(vc,
                                                    sizeof(nodus_value_t *));
                                            }
                                            if (msg->batch_vals[bi] || vc == 0) {
                                                for (size_t vi2 = 0; vi2 < varr.count; vi2++) {
                                                    cbor_item_t vitem = cbor_decode_next(&dec);
                                                    if (vitem.type == CBOR_ITEM_BSTR &&
                                                        msg->batch_val_counts[bi] < vc) {
                                                        nodus_value_t *v = NULL;
                                                        if (nodus_value_deserialize(
                                                                vitem.bstr.ptr, vitem.bstr.len,
                                                                &v) == 0)
                                                            msg->batch_vals[bi][
                                                                msg->batch_val_counts[bi]++] = v;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        cbor_decode_skip(&dec);
                                    }
                                }
                                msg->batch_key_count++;
                            }
                        }
                    }
                }
                /* counts (count_batch result: array of {k, c, my}) */
                else if (rkey.tstr.len == 6 && memcmp(rkey.tstr.ptr, "counts", 6) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t bk_cap = arr.count > NODUS_MAX_BATCH_KEYS ?
                                        NODUS_MAX_BATCH_KEYS : arr.count;
                        msg->batch_keys = calloc(bk_cap, sizeof(nodus_key_t));
                        msg->batch_counts = calloc(bk_cap, sizeof(size_t));
                        msg->batch_has_mine = calloc(bk_cap, sizeof(bool));
                        if (msg->batch_keys && msg->batch_counts && msg->batch_has_mine) {
                            msg->batch_key_count = 0;
                            for (size_t ki = 0; ki < arr.count; ki++) {
                                cbor_item_t emap = cbor_decode_next(&dec);
                                if (emap.type != CBOR_ITEM_MAP) continue;
                                if ((size_t)msg->batch_key_count >= bk_cap) {
                                    for (size_t m = 0; m < emap.count; m++) {
                                        cbor_decode_skip(&dec);
                                        cbor_decode_skip(&dec);
                                    }
                                    continue;
                                }
                                int ci = msg->batch_key_count;
                                for (size_t m = 0; m < emap.count; m++) {
                                    cbor_item_t ek = cbor_decode_next(&dec);
                                    if (ek.type != CBOR_ITEM_TSTR) {
                                        cbor_decode_skip(&dec); continue;
                                    }
                                    if (ek.tstr.len == 1 && ek.tstr.ptr[0] == 'k') {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_BSTR &&
                                            ev.bstr.len == NODUS_KEY_BYTES)
                                            memcpy(msg->batch_keys[ci].bytes,
                                                   ev.bstr.ptr, NODUS_KEY_BYTES);
                                    } else if (ek.tstr.len == 1 && ek.tstr.ptr[0] == 'c') {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_UINT)
                                            msg->batch_counts[ci] = (size_t)ev.uint_val;
                                    } else if (ek.tstr.len == 2 &&
                                               memcmp(ek.tstr.ptr, "my", 2) == 0) {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_BOOL)
                                            msg->batch_has_mine[ci] = ev.bool_val;
                                    } else {
                                        cbor_decode_skip(&dec);
                                    }
                                }
                                msg->batch_key_count++;
                            }
                        }
                    }
                }
                /* ra (ch_post_ok: assigned received_at) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "ra", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ch_received_at = val.uint_val;
                }
                /* posts (ch_posts: array of channel posts) */
                else if (rkey.tstr.len == 5 && memcmp(rkey.tstr.ptr, "posts", 5) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t cap = arr.count > NODUS_MAX_WIRE_POSTS ? NODUS_MAX_WIRE_POSTS : arr.count;
                        msg->ch_posts = calloc(cap, sizeof(nodus_channel_post_t));
                        if (msg->ch_posts) {
                            msg->ch_post_count = 0;
                            for (size_t k = 0; k < arr.count; k++) {
                                cbor_item_t pmap = cbor_decode_next(&dec);
                                if (pmap.type != CBOR_ITEM_MAP) continue;
                                if ((size_t)msg->ch_post_count >= cap) {
                                    for (size_t m = 0; m < pmap.count; m++) {
                                        cbor_decode_skip(&dec);
                                        cbor_decode_skip(&dec);
                                    }
                                    continue;
                                }
                                nodus_channel_post_t *p = &msg->ch_posts[msg->ch_post_count];
                                memset(p, 0, sizeof(*p));
                                for (size_t m = 0; m < pmap.count; m++) {
                                    cbor_item_t pk = cbor_decode_next(&dec);
                                    if (pk.type != CBOR_ITEM_TSTR) {
                                        cbor_decode_skip(&dec); continue;
                                    }
                                    if (pk.tstr.len == 2 && memcmp(pk.tstr.ptr, "ra", 2) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_UINT) p->received_at = v.uint_val;
                                    } else if (pk.tstr.len == 3 && memcmp(pk.tstr.ptr, "pid", 3) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_UUID_BYTES)
                                            memcpy(p->post_uuid, v.bstr.ptr, NODUS_UUID_BYTES);
                                    } else if (pk.tstr.len == 3 && memcmp(pk.tstr.ptr, "afp", 3) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES)
                                            memcpy(p->author_fp.bytes, v.bstr.ptr, NODUS_KEY_BYTES);
                                    } else if (pk.tstr.len == 2 && memcmp(pk.tstr.ptr, "ts", 2) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_UINT) p->timestamp = v.uint_val;
                                    } else if (pk.tstr.len == 1 && pk.tstr.ptr[0] == 'd') {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len > 0) {
                                            p->body = malloc(v.bstr.len + 1);
                                            if (p->body) {
                                                memcpy(p->body, v.bstr.ptr, v.bstr.len);
                                                p->body[v.bstr.len] = '\0';
                                                p->body_len = v.bstr.len;
                                            }
                                        }
                                    } else if (pk.tstr.len == 3 && memcmp(pk.tstr.ptr, "sig", 3) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_SIG_BYTES)
                                            memcpy(p->signature.bytes, v.bstr.ptr, NODUS_SIG_BYTES);
                                    } else if (pk.tstr.len == 2 && memcmp(pk.tstr.ptr, "ra", 2) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_UINT) p->received_at = v.uint_val;
                                    } else {
                                        cbor_decode_skip(&dec);
                                    }
                                }
                                msg->ch_post_count++;
                            }
                        }
                    }
                }
                /* channels (ch_list_ok / ch_search_ok: array of channel metas) */
                else if (rkey.tstr.len == 8 && memcmp(rkey.tstr.ptr, "channels", 8) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t cap2 = arr.count > 200 ? 200 : arr.count;
                        msg->ch_metas = calloc(cap2, sizeof(nodus_channel_meta_t));
                        if (msg->ch_metas) {
                            msg->ch_meta_count = 0;
                            for (size_t k = 0; k < arr.count; k++) {
                                cbor_item_t cmap = cbor_decode_next(&dec);
                                if (cmap.type != CBOR_ITEM_MAP) continue;
                                if (msg->ch_meta_count >= cap2) {
                                    for (size_t m2 = 0; m2 < cmap.count; m2++) {
                                        cbor_decode_skip(&dec);
                                        cbor_decode_skip(&dec);
                                    }
                                    continue;
                                }
                                nodus_channel_meta_t *cm = &msg->ch_metas[msg->ch_meta_count];
                                memset(cm, 0, sizeof(*cm));
                                for (size_t m2 = 0; m2 < cmap.count; m2++) {
                                    cbor_item_t ck = cbor_decode_next(&dec);
                                    if (ck.type != CBOR_ITEM_TSTR) {
                                        cbor_decode_skip(&dec); continue;
                                    }
                                    if (ck.tstr.len == 4 && memcmp(ck.tstr.ptr, "uuid", 4) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_TSTR && v.tstr.len == 32) {
                                            /* Parse 32-char hex to 16-byte binary */
                                            for (int b = 0; b < NODUS_UUID_BYTES; b++) {
                                                unsigned int byte;
                                                if (sscanf(v.tstr.ptr + b * 2, "%2x", &byte) == 1)
                                                    cm->uuid[b] = (uint8_t)byte;
                                            }
                                        }
                                    } else if (ck.tstr.len == 4 && memcmp(ck.tstr.ptr, "name", 4) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_TSTR)
                                            snprintf(cm->name, sizeof(cm->name), "%.*s",
                                                     (int)v.tstr.len, v.tstr.ptr);
                                    } else if (ck.tstr.len == 4 && memcmp(ck.tstr.ptr, "desc", 4) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_TSTR)
                                            snprintf(cm->description, sizeof(cm->description), "%.*s",
                                                     (int)v.tstr.len, v.tstr.ptr);
                                    } else if (ck.tstr.len == 2 && memcmp(ck.tstr.ptr, "fp", 2) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_BSTR && v.bstr.len == NODUS_KEY_BYTES) {
                                            memcpy(cm->creator_fp.bytes, v.bstr.ptr, NODUS_KEY_BYTES);
                                            cm->has_creator_fp = true;
                                        }
                                    } else if (ck.tstr.len == 2 && memcmp(ck.tstr.ptr, "ts", 2) == 0) {
                                        cbor_item_t v = cbor_decode_next(&dec);
                                        if (v.type == CBOR_ITEM_UINT) cm->created_at = v.uint_val;
                                    } else {
                                        cbor_decode_skip(&dec);
                                    }
                                }
                                cm->is_public = true;  /* Only public channels in list */
                                msg->ch_meta_count++;
                            }
                        }
                    }
                }
                /* ps (presence result: sparse array of online entries) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "ps", 2) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t cap = arr.count > NODUS_MAX_WIRE_FPS ? NODUS_MAX_WIRE_FPS : arr.count;
                        msg->pq_fps = calloc(cap, sizeof(nodus_key_t));
                        msg->pq_online = calloc(cap, sizeof(bool));
                        msg->pq_peers = calloc(cap, sizeof(uint8_t));
                        msg->pq_last_seen = calloc(cap, sizeof(uint64_t));
                        if (msg->pq_fps && msg->pq_online && msg->pq_peers) {
                            msg->pq_count = 0;
                            for (size_t k = 0; k < arr.count; k++) {
                                cbor_item_t emap = cbor_decode_next(&dec);
                                if (emap.type != CBOR_ITEM_MAP) continue;
                                if ((size_t)msg->pq_count >= cap) {
                                    /* Skip remaining entries beyond cap */
                                    for (size_t m = 0; m < emap.count; m++) {
                                        cbor_decode_skip(&dec);
                                        cbor_decode_skip(&dec);
                                    }
                                    continue;
                                }
                                int ci = msg->pq_count;
                                msg->pq_online[ci] = true;
                                for (size_t m = 0; m < emap.count; m++) {
                                    cbor_item_t ek = cbor_decode_next(&dec);
                                    if (ek.type != CBOR_ITEM_TSTR) {
                                        cbor_decode_skip(&dec); continue;
                                    }
                                    if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "fp", 2) == 0) {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_BSTR &&
                                            ev.bstr.len == NODUS_KEY_BYTES)
                                            memcpy(msg->pq_fps[ci].bytes,
                                                   ev.bstr.ptr, NODUS_KEY_BYTES);
                                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "pi", 2) == 0) {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_UINT)
                                            msg->pq_peers[ci] = (uint8_t)ev.uint_val;
                                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "ls", 2) == 0) {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_UINT && msg->pq_last_seen)
                                            msg->pq_last_seen[ci] = ev.uint_val;
                                    } else {
                                        cbor_decode_skip(&dec);
                                    }
                                }
                                msg->pq_count++;
                            }
                        }
                    }
                }
                /* os (offline-seen entries with last_seen) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "os", 2) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY && arr.count > 0) {
                        size_t cap = arr.count > NODUS_MAX_WIRE_FPS ? NODUS_MAX_WIRE_FPS : arr.count;
                        msg->os_fps = calloc(cap, sizeof(nodus_key_t));
                        msg->os_last_seen = calloc(cap, sizeof(uint64_t));
                        if (msg->os_fps && msg->os_last_seen) {
                            msg->os_count = 0;
                            for (size_t k = 0; k < arr.count; k++) {
                                cbor_item_t emap = cbor_decode_next(&dec);
                                if (emap.type != CBOR_ITEM_MAP) continue;
                                if ((size_t)msg->os_count >= cap) {
                                    for (size_t m = 0; m < emap.count; m++) {
                                        cbor_decode_skip(&dec);
                                        cbor_decode_skip(&dec);
                                    }
                                    continue;
                                }
                                int ci = msg->os_count;
                                for (size_t m = 0; m < emap.count; m++) {
                                    cbor_item_t ek = cbor_decode_next(&dec);
                                    if (ek.type != CBOR_ITEM_TSTR) {
                                        cbor_decode_skip(&dec); continue;
                                    }
                                    if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "fp", 2) == 0) {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_BSTR &&
                                            ev.bstr.len == NODUS_KEY_BYTES)
                                            memcpy(msg->os_fps[ci].bytes,
                                                   ev.bstr.ptr, NODUS_KEY_BYTES);
                                    } else if (ek.tstr.len == 2 && memcmp(ek.tstr.ptr, "ls", 2) == 0) {
                                        cbor_item_t ev = cbor_decode_next(&dec);
                                        if (ev.type == CBOR_ITEM_UINT)
                                            msg->os_last_seen[ci] = ev.uint_val;
                                    } else {
                                        cbor_decode_skip(&dec);
                                    }
                                }
                                msg->os_count++;
                            }
                        }
                    }
                }
                /* srvs (servers list) */
                else if (rkey.tstr.len == 4 && memcmp(rkey.tstr.ptr, "srvs", 4) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY) {
                        msg->server_count = 0;
                        for (size_t k = 0; k < arr.count && msg->server_count < 17; k++) {
                            cbor_item_t smap = cbor_decode_next(&dec);
                            if (smap.type != CBOR_ITEM_MAP) continue;
                            int idx = msg->server_count;
                            memset(&msg->servers[idx], 0, sizeof(msg->servers[idx]));
                            for (size_t m = 0; m < smap.count; m++) {
                                cbor_item_t sk = cbor_decode_next(&dec);
                                if (sk.type != CBOR_ITEM_TSTR) {
                                    cbor_decode_skip(&dec); continue;
                                }
                                if (sk.tstr.len == 2 && memcmp(sk.tstr.ptr, "ip", 2) == 0) {
                                    cbor_item_t sv = cbor_decode_next(&dec);
                                    if (sv.type == CBOR_ITEM_TSTR) {
                                        size_t cl = sv.tstr.len < sizeof(msg->servers[0].ip) - 1 ?
                                                    sv.tstr.len : sizeof(msg->servers[0].ip) - 1;
                                        memcpy(msg->servers[idx].ip, sv.tstr.ptr, cl);
                                        msg->servers[idx].ip[cl] = '\0';
                                    }
                                } else if (sk.tstr.len == 2 && memcmp(sk.tstr.ptr, "tp", 2) == 0) {
                                    cbor_item_t sv = cbor_decode_next(&dec);
                                    if (sv.type == CBOR_ITEM_UINT)
                                        msg->servers[idx].tcp_port = (uint16_t)sv.uint_val;
                                } else if (sk.tstr.len == 2 && memcmp(sk.tstr.ptr, "fp", 2) == 0) {
                                    cbor_item_t sv = cbor_decode_next(&dec);
                                    if (sv.type == CBOR_ITEM_BSTR && sv.bstr.len == 16) {
                                        memcpy(msg->servers[idx].dil_fp, sv.bstr.ptr, 16);
                                        msg->servers[idx].has_dil_fp = true;
                                    }
                                } else {
                                    cbor_decode_skip(&dec);
                                }
                            }
                            msg->server_count++;
                        }
                    }
                }
                /* Cluster-status response fields (Phase 0 / Task 0.2) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "bh", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_UINT) {
                        msg->status_info.block_height = v.uint_val;
                        msg->has_status_info = true;
                    }
                }
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "sr", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 64) {
                        memcpy(msg->status_info.state_root, v.bstr.ptr, 64);
                        msg->has_status_info = true;
                    }
                }
                else if (rkey.tstr.len == 4 && memcmp(rkey.tstr.ptr, "chid", 4) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_BSTR && v.bstr.len == 32) {
                        memcpy(msg->status_info.chain_id, v.bstr.ptr, 32);
                        msg->has_status_info = true;
                    }
                }
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "pc", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_UINT) {
                        msg->status_info.peer_count = (uint32_t)v.uint_val;
                        msg->has_status_info = true;
                    }
                }
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "us", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_UINT) {
                        msg->status_info.uptime_sec = v.uint_val;
                        msg->has_status_info = true;
                    }
                }
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "wc", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_UINT) {
                        msg->status_info.wall_clock = v.uint_val;
                        msg->has_status_info = true;
                    }
                }
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "df", 2) == 0) {
                    cbor_item_t v = cbor_decode_next(&dec);
                    if (v.type == CBOR_ITEM_UINT) {
                        msg->status_info.disk_free_pct = (uint8_t)v.uint_val;
                        msg->has_status_info = true;
                    }
                }
                /* rv (node_auth_ok: ring version) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "rv", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->ring_version = (uint32_t)val.uint_val;
                }
                /* ring (node_auth_ok: ring member array → servers[]) */
                else if (rkey.tstr.len == 4 && memcmp(rkey.tstr.ptr, "ring", 4) == 0) {
                    cbor_item_t arr = cbor_decode_next(&dec);
                    if (arr.type == CBOR_ITEM_ARRAY) {
                        msg->server_count = 0;
                        for (size_t k = 0; k < arr.count && msg->server_count < 17; k++) {
                            cbor_item_t rmap = cbor_decode_next(&dec);
                            if (rmap.type != CBOR_ITEM_MAP) continue;
                            int idx = msg->server_count;
                            memset(&msg->servers[idx], 0, sizeof(msg->servers[idx]));
                            for (size_t m = 0; m < rmap.count; m++) {
                                cbor_item_t rk = cbor_decode_next(&dec);
                                if (rk.type != CBOR_ITEM_TSTR) {
                                    cbor_decode_skip(&dec); continue;
                                }
                                if (rk.tstr.len == 2 && memcmp(rk.tstr.ptr, "ip", 2) == 0) {
                                    cbor_item_t rv = cbor_decode_next(&dec);
                                    if (rv.type == CBOR_ITEM_TSTR) {
                                        size_t cl = rv.tstr.len < sizeof(msg->servers[0].ip) - 1 ?
                                                    rv.tstr.len : sizeof(msg->servers[0].ip) - 1;
                                        memcpy(msg->servers[idx].ip, rv.tstr.ptr, cl);
                                        msg->servers[idx].ip[cl] = '\0';
                                    }
                                } else if (rk.tstr.len == 4 && memcmp(rk.tstr.ptr, "port", 4) == 0) {
                                    cbor_item_t rv = cbor_decode_next(&dec);
                                    if (rv.type == CBOR_ITEM_UINT)
                                        msg->servers[idx].tcp_port = (uint16_t)rv.uint_val;
                                } else if (rk.tstr.len == 3 && memcmp(rk.tstr.ptr, "nid", 3) == 0) {
                                    cbor_item_t rv = cbor_decode_next(&dec);
                                    if (rv.type == CBOR_ITEM_BSTR && rv.bstr.len == NODUS_KEY_BYTES)
                                        memcpy(msg->ring_node_id.bytes, rv.bstr.ptr, NODUS_KEY_BYTES);
                                } else {
                                    cbor_decode_skip(&dec);
                                }
                            }
                            msg->server_count++;
                        }
                    }
                }
                /* ch (ring_ack: channel UUID) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "ch", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == NODUS_UUID_BYTES)
                        memcpy(msg->channel_uuid, val.bstr.ptr, NODUS_UUID_BYTES);
                }
                /* ag (ring_ack: agree) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "ag", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BOOL)
                        msg->ring_agree = val.bool_val;
                }
                /* mh (media response: content hash) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "mh", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64) {
                        memcpy(msg->media_hash, val.bstr.ptr, 64);
                        msg->has_media = true;
                    }
                }
                /* ci (media response: chunk index) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "ci", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_chunk_idx = (uint32_t)val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* cc (media response: chunk count) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "cc", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_chunk_count = (uint32_t)val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* tsz (media response: total size) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "tsz", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_total_size = val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* mt (media response: media type) */
                else if (rkey.tstr.len == 2 && memcmp(rkey.tstr.ptr, "mt", 2) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->media_type = (uint8_t)val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* menc (media response: encrypted flag) */
                else if (rkey.tstr.len == 4 && memcmp(rkey.tstr.ptr, "menc", 4) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BOOL) {
                        msg->media_encrypted = val.bool_val;
                        msg->has_media = true;
                    }
                }
                /* cmp (media response: complete flag) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "cmp", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BOOL) {
                        msg->media_complete = val.bool_val;
                        msg->has_media = true;
                    }
                }
                /* d (media response: chunk data) */
                else if (rkey.tstr.len == 1 && rkey.tstr.ptr[0] == 'd') {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_BSTR && val.bstr.len > 0) {
                        msg->data = malloc(val.bstr.len);
                        if (msg->data) {
                            memcpy(msg->data, val.bstr.ptr, val.bstr.len);
                            msg->data_len = val.bstr.len;
                        }
                    }
                }
                /* ttl (media response: TTL) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "ttl", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT) {
                        msg->ttl = (uint32_t)val.uint_val;
                        msg->has_media = true;
                    }
                }
                /* code (error) */
                else if (rkey.tstr.len == 4 && memcmp(rkey.tstr.ptr, "code", 4) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_UINT)
                        msg->error_code = (int)val.uint_val;
                }
                /* msg (error) */
                else if (rkey.tstr.len == 3 && memcmp(rkey.tstr.ptr, "msg", 3) == 0) {
                    cbor_item_t val = cbor_decode_next(&dec);
                    if (val.type == CBOR_ITEM_TSTR) {
                        size_t clen = val.tstr.len < sizeof(msg->error_msg) - 1 ?
                                      val.tstr.len : sizeof(msg->error_msg) - 1;
                        memcpy(msg->error_msg, val.tstr.ptr, clen);
                        msg->error_msg[clen] = '\0';
                    }
                }
                else {
                    cbor_decode_skip(&dec);
                }
            }
        }
        else {
            cbor_decode_skip(&dec);
        }
    }

    return dec.error ? -1 : 0;
}

void nodus_t2_msg_free(nodus_tier2_msg_t *msg) {
    if (!msg) return;
    free(msg->data);
    msg->data = NULL;
    if (msg->circ_data) { free(msg->circ_data); msg->circ_data = NULL; msg->circ_data_len = 0; }
    if (msg->ri_data) { free(msg->ri_data); msg->ri_data = NULL; msg->ri_data_len = 0; }
    if (msg->value) {
        nodus_value_free(msg->value);
        msg->value = NULL;
    }
    if (msg->values) {
        for (size_t i = 0; i < msg->value_count; i++)
            nodus_value_free(msg->values[i]);
        free(msg->values);
        msg->values = NULL;
    }
    if (msg->ch_posts) {
        for (size_t i = 0; i < msg->ch_post_count; i++)
            free(msg->ch_posts[i].body);
        free(msg->ch_posts);
        msg->ch_posts = NULL;
    }
    free(msg->ch_name);
    msg->ch_name = NULL;
    free(msg->ch_description);
    msg->ch_description = NULL;
    free(msg->ch_query);
    msg->ch_query = NULL;
    free(msg->ch_metas);
    msg->ch_metas = NULL;
    free(msg->pq_fps);
    msg->pq_fps = NULL;
    free(msg->pq_online);
    msg->pq_online = NULL;
    free(msg->pq_peers);
    msg->pq_peers = NULL;
    free(msg->pq_last_seen);
    msg->pq_last_seen = NULL;
    free(msg->os_fps);
    msg->os_fps = NULL;
    free(msg->os_last_seen);
    msg->os_last_seen = NULL;

    /* Batch fields */
    if (msg->batch_vals) {
        for (int i = 0; i < msg->batch_key_count; i++) {
            if (msg->batch_vals[i]) {
                for (size_t j = 0; j < (msg->batch_val_counts ?
                     msg->batch_val_counts[i] : 0); j++)
                    nodus_value_free(msg->batch_vals[i][j]);
                free(msg->batch_vals[i]);
            }
        }
        free(msg->batch_vals);
        msg->batch_vals = NULL;
    }
    free(msg->batch_val_counts);
    msg->batch_val_counts = NULL;
    free(msg->batch_keys);
    msg->batch_keys = NULL;
    free(msg->batch_counts);
    msg->batch_counts = NULL;
    free(msg->batch_has_mine);
    msg->batch_has_mine = NULL;
}
