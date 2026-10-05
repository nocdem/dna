/* Nodus Connect groups — the codec layer (package G1). Layouts, references
 * and the reader order: nc_group.h; governing records
 * docs/plans/2026-10-05-connect-groups-bytes.md items 1-7 + REV 2
 * (approved, docs/plans/decisions/2026-10-05-groups-apt-bytes-approved.md),
 * docs/plans/2026-10-04-connect-groups-design.md rev 1,
 * docs/plans/decisions/2026-10-04-connect-groups.md items 1-11.
 *
 * Pure: no network, no clock, no global state. The only randomness is the
 * ML-KEM encapsulation, the GCM nonce (both drawn inside the primitives),
 * ML-DSA-87's randomized signing and the message_id (qgp_randombytes).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_group.h"

#include "crypto/enc/aes_keywrap.h"
#include "crypto/enc/qgp_aes.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_random.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NC_GROUP"

/* The header's literals, pinned to the primitives they size. */
_Static_assert(NC_GROUP_KEM_CT_LEN == QGP_MLKEM1024_CIPHERTEXTBYTES, "ML-KEM-1024 ct");
_Static_assert(NC_GROUP_KEM_PK_LEN == QGP_MLKEM1024_PUBLICKEYBYTES, "ML-KEM-1024 ek");
_Static_assert(NC_GROUP_KEM_SK_LEN == QGP_MLKEM1024_SECRETKEYBYTES, "ML-KEM-1024 dk");
_Static_assert(NC_GROUP_SS_LEN == QGP_MLKEM1024_SHAREDSECRET_BYTES, "ML-KEM-1024 ss");
_Static_assert(NC_GROUP_SIG_LEN == QGP_DSA87_SIGNATURE_BYTES, "ML-DSA-87 sig");
_Static_assert(NC_GROUP_DSA_PK_LEN == QGP_DSA87_PUBLICKEYBYTES, "ML-DSA-87 pk");
_Static_assert(NC_GROUP_DSA_SK_LEN == QGP_DSA87_SECRETKEYBYTES, "ML-DSA-87 sk");
_Static_assert(NC_GROUP_DIGEST_LEN == QGP_SHA3_512_DIGEST_LENGTH, "SHA3-512");
_Static_assert(NC_GROUP_KEY_LEN <= QGP_SHA3_256_DIGEST_LENGTH, "one HKDF block");
_Static_assert(NC_GROUP_ENTRY_LEN == 1608, "R2-1 entry");
_Static_assert(NC_GROUP_RECORD_PT_MAX == 4171, "R2-8 record plaintext cap");
_Static_assert(NC_GROUP_KP_HEADER_LEN ==
               NC_GROUP_TAG_LEN + NC_GROUP_ID_LEN + NC_GROUP_FP_LEN + 4 +
               2 * NC_GROUP_DIGEST_LEN + 8 + 2, "§2 header");
_Static_assert(NC_GROUP_REC_AAD_LEN == NC_GROUP_TAG_LEN + NC_GROUP_ID_LEN + 4, "§3 AAD");
_Static_assert(NC_GROUP_HEAD_SIGNED_LEN ==
               NC_GROUP_TAG_LEN + NC_GROUP_ID_LEN + NC_GROUP_FP_LEN + 4 +
               NC_GROUP_DIGEST_LEN + 8, "R2-4 HEAD span");
_Static_assert(NC_GROUP_MSG_AAD_LEN ==
               NC_GROUP_TAG_LEN + NC_GROUP_ID_LEN + 4 + NC_GROUP_FP_LEN +
               NC_GROUP_MSG_ID_LEN + 8 + 4, "R2-5 AAD");
_Static_assert(NC_GROUP_MSG_H_LEN == NC_GROUP_MSG_AAD_LEN + NC_GROUP_NONCE_LEN, "§5 H");

/* ── tags: 16 bytes, ASCII right-padded with 0x00 (bytes § Reference) ── */

static const uint8_t TAGS[NC_GROUP_TAG_COUNT][NC_GROUP_TAG_LEN] = {
    [NC_GROUP_TAG_GSALT] = "NDS.GSALT.v1",
    [NC_GROUP_TAG_GADDR] = "NDS.GADDR.v1",
    [NC_GROUP_TAG_GKP]   = "NDS.GKP.v1",
    [NC_GROUP_TAG_GKEK]  = "NDS.GKEK.v1",
    [NC_GROUP_TAG_GREC]  = "NDS.GREC.v1",
    [NC_GROUP_TAG_GHEAD] = "NDS.GHEAD.v1",
    [NC_GROUP_TAG_GMSG]  = "NDS.GMSG.v1",
    [NC_GROUP_TAG_GBKT]  = "NDS.GBKT.v1",
};

const uint8_t *nc_group_tag(nc_group_tag_id_t id) {
    if ((int)id < 0 || id >= NC_GROUP_TAG_COUNT) return NULL;
    return TAGS[id];
}

/* ── big-endian helpers ───────────────────────────────────────────────── */

static void put_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put_u32(uint8_t *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (24 - 8 * i));
}
static void put_u64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = v << 8 | p[i];
    return v;
}

static const char HEXD[] = "0123456789abcdef";

static void hex_enc(const uint8_t *p, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = HEXD[p[i] >> 4];
        out[2 * i + 1] = HEXD[p[i] & 15];
    }
    out[2 * n] = '\0';
}

/* Exactly 2n lowercase hex characters -> n bytes. */
static int hex_dec(const char *s, size_t slen, uint8_t *out, size_t n) {
    if (!s || slen != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int v[2];
        for (int j = 0; j < 2; j++) {
            char c = s[2 * i + (size_t)j];
            v[j] = (c >= '0' && c <= '9') ? c - '0'
                 : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
            if (v[j] < 0) return -1;
        }
        out[i] = (uint8_t)(v[0] << 4 | v[1]);
    }
    return 0;
}

static int is_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* Strictly ascending (memcmp) list of `count` fingerprints. */
static int fps_ascending(const uint8_t (*fps)[NC_GROUP_FP_LEN], size_t count) {
    for (size_t i = 1; i < count; i++)
        if (memcmp(fps[i - 1], fps[i], NC_GROUP_FP_LEN) >= 0) return 0;
    return 1;
}

static int fp_in(const uint8_t fp[NC_GROUP_FP_LEN],
                 const uint8_t (*fps)[NC_GROUP_FP_LEN], size_t count) {
    for (size_t i = 0; i < count; i++)
        if (memcmp(fps[i], fp, NC_GROUP_FP_LEN) == 0) return 1;
    return 0;
}

/* ML-DSA-87 over m; the signature must be exactly NC_GROUP_SIG_LEN. */
static int sign_exact(uint8_t sig[NC_GROUP_SIG_LEN], const uint8_t *m, size_t mlen,
                      const uint8_t *sk) {
    size_t siglen = 0;
    if (qgp_dsa87_sign(sig, &siglen, m, mlen, sk) != 0 || siglen != NC_GROUP_SIG_LEN) {
        qgp_secure_memzero(sig, NC_GROUP_SIG_LEN);
        QGP_LOG_ERROR(LOG_TAG, "ML-DSA-87 signing failed");
        return NC_GROUP_FAULT;
    }
    return NC_GROUP_OK;
}

/* ── salt_v / addresses / day ─────────────────────────────────────────── */

int nc_group_salt_v(const uint8_t group_id[NC_GROUP_ID_LEN],
                    const uint8_t group_key[NC_GROUP_KEY_LEN], uint32_t v,
                    uint8_t salt_out[NC_GROUP_SECRET_LEN]) {
    if (!salt_out) return NC_GROUP_REFUSED;
    memset(salt_out, 0, NC_GROUP_SECRET_LEN);
    if (!group_id || !group_key || v == 0) return NC_GROUP_REFUSED;
    uint8_t info[NC_GROUP_TAG_LEN + 4];
    memcpy(info, TAGS[NC_GROUP_TAG_GSALT], NC_GROUP_TAG_LEN);
    put_u32(info + NC_GROUP_TAG_LEN, v);
    /* hkdf_sha3.c refuses only NULLs / oversized lengths (none here) or an
     * OpenSSL failure: any -1 is a fault. */
    if (hkdf_sha3_256(group_id, NC_GROUP_ID_LEN, group_key, NC_GROUP_KEY_LEN,
                      info, sizeof(info), salt_out, NC_GROUP_SECRET_LEN) != 0) {
        qgp_secure_memzero(salt_out, NC_GROUP_SECRET_LEN);
        return NC_GROUP_FAULT;
    }
    return NC_GROUP_OK;
}

int nc_group_addr(nc_group_purpose_t purpose,
                  const uint8_t group_id[NC_GROUP_ID_LEN],
                  const uint8_t secret[NC_GROUP_SECRET_LEN], uint64_t x,
                  uint8_t k_out[NC_GROUP_DIGEST_LEN],
                  char str_out[NC_GROUP_ADDR_STR_LEN + 1]) {
    if (!k_out) return NC_GROUP_REFUSED;
    memset(k_out, 0, NC_GROUP_DIGEST_LEN);
    if (str_out) str_out[0] = '\0';
    if (!group_id || !secret) return NC_GROUP_REFUSED;
    switch (purpose) {
    case NC_GROUP_PURPOSE_HEAD:
        if (x != 0) return NC_GROUP_REFUSED;
        break;
    case NC_GROUP_PURPOSE_KEY_PACKET:
    case NC_GROUP_PURPOSE_RECORD:
        if (x == 0 || x > UINT32_MAX) return NC_GROUP_REFUSED;
        break;
    case NC_GROUP_PURPOSE_OUTBOX:
        if (x > UINT32_MAX) return NC_GROUP_REFUSED;
        break;
    default:
        return NC_GROUP_REFUSED;
    }
    uint8_t pre[NC_GROUP_TAG_LEN + 1 + NC_GROUP_ID_LEN + NC_GROUP_SECRET_LEN + 8];
    size_t o = 0;
    memcpy(pre + o, TAGS[NC_GROUP_TAG_GADDR], NC_GROUP_TAG_LEN); o += NC_GROUP_TAG_LEN;
    pre[o++] = (uint8_t)purpose;
    memcpy(pre + o, group_id, NC_GROUP_ID_LEN); o += NC_GROUP_ID_LEN;
    memcpy(pre + o, secret, NC_GROUP_SECRET_LEN); o += NC_GROUP_SECRET_LEN;
    put_u64(pre + o, x);
    int rc = qgp_sha3_512(pre, sizeof(pre), k_out);
    qgp_secure_memzero(pre, sizeof(pre));            /* holds the secret */
    if (rc != 0) {
        memset(k_out, 0, NC_GROUP_DIGEST_LEN);
        return NC_GROUP_FAULT;
    }
    if (str_out) {
        memcpy(str_out, "ncg:", 4);
        hex_enc(k_out, NC_GROUP_DIGEST_LEN, str_out + 4);
    }
    return NC_GROUP_OK;
}

int nc_group_day(uint64_t timestamp_ms, uint32_t *day_out) {
    if (!day_out) return NC_GROUP_REFUSED;
    *day_out = 0;
    uint64_t d = timestamp_ms / NC_GROUP_MS_PER_DAY;
    if (d > UINT32_MAX) return NC_GROUP_REFUSED;
    *day_out = (uint32_t)d;
    return NC_GROUP_OK;
}

/* ── key packet ───────────────────────────────────────────────────────── */

int nc_group_kek(const uint8_t ss[NC_GROUP_SS_LEN],
                 const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                 const uint8_t member_fp[NC_GROUP_FP_LEN],
                 const uint8_t owner_fp[NC_GROUP_FP_LEN],
                 uint8_t kek_out[NC_GROUP_KEY_LEN]) {
    if (!kek_out) return NC_GROUP_REFUSED;
    memset(kek_out, 0, NC_GROUP_KEY_LEN);
    if (!ss || !group_id || !member_fp || !owner_fp || v == 0) return NC_GROUP_REFUSED;
    uint8_t info[NC_GROUP_TAG_LEN + 4 + 2 * NC_GROUP_FP_LEN];   /* 148 */
    memcpy(info, TAGS[NC_GROUP_TAG_GKEK], NC_GROUP_TAG_LEN);
    put_u32(info + NC_GROUP_TAG_LEN, v);
    memcpy(info + NC_GROUP_TAG_LEN + 4, member_fp, NC_GROUP_FP_LEN);
    memcpy(info + NC_GROUP_TAG_LEN + 4 + NC_GROUP_FP_LEN, owner_fp, NC_GROUP_FP_LEN);
    if (hkdf_sha3_256(group_id, NC_GROUP_ID_LEN, ss, NC_GROUP_SS_LEN,
                      info, sizeof(info), kek_out, NC_GROUP_KEY_LEN) != 0) {
        qgp_secure_memzero(kek_out, NC_GROUP_KEY_LEN);
        return NC_GROUP_FAULT;
    }
    return NC_GROUP_OK;
}

int nc_group_wrap(const uint8_t ss[NC_GROUP_SS_LEN],
                  const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                  const uint8_t member_fp[NC_GROUP_FP_LEN],
                  const uint8_t owner_fp[NC_GROUP_FP_LEN],
                  const uint8_t group_key[NC_GROUP_KEY_LEN],
                  uint8_t wrapped_out[NC_GROUP_WRAPPED_LEN]) {
    if (!wrapped_out) return NC_GROUP_REFUSED;
    memset(wrapped_out, 0, NC_GROUP_WRAPPED_LEN);
    if (!group_key) return NC_GROUP_REFUSED;
    uint8_t kek[NC_GROUP_KEY_LEN];
    int rc = nc_group_kek(ss, group_id, v, member_fp, owner_fp, kek);
    if (rc != NC_GROUP_OK) return rc;
    if (aes256_wrap_key(group_key, NC_GROUP_KEY_LEN, kek, wrapped_out) != 0) {
        memset(wrapped_out, 0, NC_GROUP_WRAPPED_LEN);
        rc = NC_GROUP_FAULT;
    }
    qgp_secure_memzero(kek, sizeof(kek));
    return rc;
}

static void kp_write_header(uint8_t *b, const nc_group_kp_hdr_t *h, size_t count) {
    size_t o = 0;
    memcpy(b + o, TAGS[NC_GROUP_TAG_GKP], NC_GROUP_TAG_LEN); o += NC_GROUP_TAG_LEN;
    memcpy(b + o, h->group_id, NC_GROUP_ID_LEN);             o += NC_GROUP_ID_LEN;
    memcpy(b + o, h->owner_fp, NC_GROUP_FP_LEN);             o += NC_GROUP_FP_LEN;
    put_u32(b + o, h->v);                                    o += 4;
    memcpy(b + o, h->prev_digest, NC_GROUP_DIGEST_LEN);      o += NC_GROUP_DIGEST_LEN;
    memcpy(b + o, h->record_digest, NC_GROUP_DIGEST_LEN);    o += NC_GROUP_DIGEST_LEN;
    put_u64(b + o, h->issued_at_ms);                         o += 8;
    put_u16(b + o, (uint16_t)count);
}

static void kp_read_header(const uint8_t *b, nc_group_kp_hdr_t *h) {
    size_t o = NC_GROUP_TAG_LEN;
    memcpy(h->group_id, b + o, NC_GROUP_ID_LEN);             o += NC_GROUP_ID_LEN;
    memcpy(h->owner_fp, b + o, NC_GROUP_FP_LEN);             o += NC_GROUP_FP_LEN;
    h->v = get_u32(b + o);                                   o += 4;
    memcpy(h->prev_digest, b + o, NC_GROUP_DIGEST_LEN);      o += NC_GROUP_DIGEST_LEN;
    memcpy(h->record_digest, b + o, NC_GROUP_DIGEST_LEN);    o += NC_GROUP_DIGEST_LEN;
    h->issued_at_ms = get_u64(b + o);
}

int nc_group_kp_assemble(const nc_group_kp_hdr_t *hdr,
                         const uint8_t group_key[NC_GROUP_KEY_LEN],
                         const uint8_t (*member_fps)[NC_GROUP_FP_LEN],
                         const uint8_t (*kem_ct)[NC_GROUP_KEM_CT_LEN],
                         const uint8_t (*ss)[NC_GROUP_SS_LEN],
                         size_t count,
                         uint8_t **pre_out, size_t *pre_len) {
    if (!pre_out || !pre_len) return NC_GROUP_REFUSED;
    *pre_out = NULL;
    *pre_len = 0;
    if (!hdr || !group_key || !member_fps || !kem_ct || !ss) return NC_GROUP_REFUSED;
    if (count < 1 || count > NC_GROUP_MAX_MEMBERS) return NC_GROUP_REFUSED;
    if (hdr->v == 0) return NC_GROUP_REFUSED;
    if (hdr->v == 1 && !is_zero(hdr->prev_digest, NC_GROUP_DIGEST_LEN)) return NC_GROUP_REFUSED;
    if (!fps_ascending(member_fps, count) || !fp_in(hdr->owner_fp, member_fps, count))
        return NC_GROUP_REFUSED;

    /* Entry order = kem_ct ascending, memcmp over all 1,568 bytes (R2-1,
     * reading 6). Insertion sort of indices; count <= 64. */
    size_t idx[NC_GROUP_MAX_MEMBERS];
    for (size_t i = 0; i < count; i++) {
        size_t j = i;
        while (j > 0 && memcmp(kem_ct[idx[j - 1]], kem_ct[i], NC_GROUP_KEM_CT_LEN) > 0) {
            idx[j] = idx[j - 1];
            j--;
        }
        idx[j] = i;
    }
    for (size_t i = 1; i < count; i++)
        if (memcmp(kem_ct[idx[i - 1]], kem_ct[idx[i]], NC_GROUP_KEM_CT_LEN) == 0)
            return NC_GROUP_REFUSED;                 /* duplicate kem_ct */

    const size_t len = NC_GROUP_KP_HEADER_LEN + count * NC_GROUP_ENTRY_LEN;
    uint8_t *b = malloc(len);
    if (!b) return NC_GROUP_FAULT;
    kp_write_header(b, hdr, count);
    for (size_t k = 0; k < count; k++) {
        size_t i = idx[k];
        uint8_t *e = b + NC_GROUP_KP_HEADER_LEN + k * NC_GROUP_ENTRY_LEN;
        memcpy(e, kem_ct[i], NC_GROUP_KEM_CT_LEN);
        int rc = nc_group_wrap(ss[i], hdr->group_id, hdr->v, member_fps[i],
                               hdr->owner_fp, group_key, e + NC_GROUP_KEM_CT_LEN);
        if (rc != NC_GROUP_OK) {
            free(b);                 /* holds no secret: ct and wrapped keys */
            return rc;
        }
    }
    *pre_out = b;
    *pre_len = len;
    return NC_GROUP_OK;
}

int nc_group_kp_parse(const uint8_t *data, size_t len,
                      nc_group_kp_hdr_t *hdr_out, size_t *count_out) {
    if (hdr_out) memset(hdr_out, 0, sizeof(*hdr_out));
    if (count_out) *count_out = 0;
    if (!data || len < NC_GROUP_KP_HEADER_LEN) return NC_GROUP_REFUSED;
    if (memcmp(data, TAGS[NC_GROUP_TAG_GKP], NC_GROUP_TAG_LEN) != 0) return NC_GROUP_REFUSED;
    size_t count = get_u16(data + NC_GROUP_KP_HEADER_LEN - 2);
    if (count < 1 || count > NC_GROUP_MAX_MEMBERS) return NC_GROUP_REFUSED;
    const size_t off = NC_GROUP_KP_HEADER_LEN + count * NC_GROUP_ENTRY_LEN;
    if (len < off + 2) return NC_GROUP_REFUSED;
    if (get_u16(data + off) != NC_GROUP_SIG_LEN) return NC_GROUP_REFUSED;
    if (len != off + 2 + NC_GROUP_SIG_LEN) return NC_GROUP_REFUSED;
    nc_group_kp_hdr_t h;
    kp_read_header(data, &h);
    if (h.v == 0) return NC_GROUP_REFUSED;
    if (h.v == 1 && !is_zero(h.prev_digest, NC_GROUP_DIGEST_LEN)) return NC_GROUP_REFUSED;
    for (size_t i = 1; i < count; i++) {
        const uint8_t *a = data + NC_GROUP_KP_HEADER_LEN + (i - 1) * NC_GROUP_ENTRY_LEN;
        const uint8_t *b = a + NC_GROUP_ENTRY_LEN;
        if (memcmp(a, b, NC_GROUP_KEM_CT_LEN) >= 0) return NC_GROUP_REFUSED;
    }
    if (hdr_out) *hdr_out = h;
    if (count_out) *count_out = count;
    return NC_GROUP_OK;
}

int nc_group_kp_digest(const uint8_t *data, size_t len,
                       uint8_t digest_out[NC_GROUP_DIGEST_LEN]) {
    if (!digest_out) return NC_GROUP_REFUSED;
    memset(digest_out, 0, NC_GROUP_DIGEST_LEN);
    size_t count;
    if (nc_group_kp_parse(data, len, NULL, &count) != NC_GROUP_OK) return NC_GROUP_REFUSED;
    if (qgp_sha3_512(data, NC_GROUP_KP_HEADER_LEN + count * NC_GROUP_ENTRY_LEN,
                     digest_out) != 0) {
        memset(digest_out, 0, NC_GROUP_DIGEST_LEN);
        return NC_GROUP_FAULT;
    }
    return NC_GROUP_OK;
}

int nc_group_kp_build(const nc_group_kp_hdr_t *hdr,
                      const uint8_t group_key[NC_GROUP_KEY_LEN],
                      const uint8_t (*member_fps)[NC_GROUP_FP_LEN],
                      const uint8_t (*member_eks)[NC_GROUP_KEM_PK_LEN],
                      size_t count,
                      const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                      const uint8_t owner_sk[NC_GROUP_DSA_SK_LEN],
                      uint8_t **out, size_t *out_len,
                      uint8_t digest_out[NC_GROUP_DIGEST_LEN]) {
    if (!out || !out_len) return NC_GROUP_REFUSED;
    *out = NULL;
    *out_len = 0;
    if (digest_out) memset(digest_out, 0, NC_GROUP_DIGEST_LEN);
    if (!hdr || !group_key || !member_fps || !member_eks || !owner_pk || !owner_sk)
        return NC_GROUP_REFUSED;
    if (count < 1 || count > NC_GROUP_MAX_MEMBERS) return NC_GROUP_REFUSED;

    uint8_t (*cts)[NC_GROUP_KEM_CT_LEN] = malloc(count * NC_GROUP_KEM_CT_LEN);
    uint8_t (*sss)[NC_GROUP_SS_LEN] = calloc(count, NC_GROUP_SS_LEN);
    uint8_t *pre = NULL, *b = NULL;
    size_t pre_len = 0;
    int rc = NC_GROUP_FAULT;
    if (!cts || !sss) goto done;

    /* A member whose ML-KEM key does not pass the FIPS 203 §7.2 check fails
     * the whole transition (design §3: never skipped). */
    for (size_t i = 0; i < count; i++) {
        if (qgp_mlkem1024_ek_check(member_eks[i]) != 0) {
            QGP_LOG_WARN(LOG_TAG, "kp_build: member %zu ML-KEM key refused", i);
            rc = NC_GROUP_REFUSED;
            goto done;
        }
        if (qgp_mlkem1024_encapsulate(cts[i], sss[i], member_eks[i]) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "kp_build: encapsulation failed");
            goto done;
        }
    }
    rc = nc_group_kp_assemble(hdr, group_key, member_fps,
                              (const uint8_t (*)[NC_GROUP_KEM_CT_LEN])cts,
                              (const uint8_t (*)[NC_GROUP_SS_LEN])sss,
                              count, &pre, &pre_len);
    if (rc != NC_GROUP_OK) goto done;

    rc = NC_GROUP_FAULT;
    const size_t len = pre_len + 2 + NC_GROUP_SIG_LEN;
    b = malloc(len);
    if (!b) goto done;
    memcpy(b, pre, pre_len);
    put_u16(b + pre_len, NC_GROUP_SIG_LEN);
    if (sign_exact(b + pre_len + 2, b, pre_len, owner_sk) != NC_GROUP_OK) goto done;

    /* Read back what a member's reader runs first. */
    if (nc_group_kp_parse(b, len, NULL, NULL) != NC_GROUP_OK ||
        qgp_dsa87_verify(b + pre_len + 2, NC_GROUP_SIG_LEN, b, pre_len, owner_pk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "kp_build: built packet does not read back");
        goto done;
    }
    if (digest_out && qgp_sha3_512(b, pre_len, digest_out) != 0) goto done;
    *out = b;
    *out_len = len;
    b = NULL;
    rc = NC_GROUP_OK;

done:
    if (sss) { qgp_secure_memzero(sss, count * NC_GROUP_SS_LEN); free(sss); }
    free(cts);
    free(pre);
    free(b);
    if (rc != NC_GROUP_OK && digest_out) memset(digest_out, 0, NC_GROUP_DIGEST_LEN);
    return rc;
}

int nc_group_decap_mlkem(uint8_t ss[NC_GROUP_SS_LEN],
                         const uint8_t ct[NC_GROUP_KEM_CT_LEN], void *user) {
    if (!ss || !ct || !user) return -1;
    if (qgp_mlkem1024_decapsulate(ss, ct, (const uint8_t *)user) != 0) {
        qgp_secure_memzero(ss, NC_GROUP_SS_LEN);
        return -1;
    }
    return 0;
}

nc_group_kp_status_t nc_group_kp_open(const uint8_t *data, size_t len,
                                      const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                                      const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                                      const uint8_t expect_owner_fp[NC_GROUP_FP_LEN],
                                      uint32_t expect_v,
                                      const uint8_t *stored_prev_digest,
                                      const uint8_t my_fp[NC_GROUP_FP_LEN],
                                      nc_group_decap_fn decap, void *decap_user,
                                      nc_group_kp_open_t *out) {
    if (!out) return NC_GROUP_KP_BAD_STRUCTURE;
    memset(out, 0, sizeof(*out));
    if (!owner_pk || !expect_group_id || !expect_owner_fp || !my_fp || !decap)
        return NC_GROUP_KP_BAD_STRUCTURE;

    /* 1. structure */
    nc_group_kp_hdr_t h;
    size_t count;
    if (nc_group_kp_parse(data, len, &h, &count) != NC_GROUP_OK)
        return NC_GROUP_KP_BAD_STRUCTURE;
    const size_t pre_len = NC_GROUP_KP_HEADER_LEN + count * NC_GROUP_ENTRY_LEN;

    /* 2. the pinned owner's signature, before anything is trusted */
    if (qgp_dsa87_verify(data + pre_len + 2, NC_GROUP_SIG_LEN, data, pre_len, owner_pk) != 0)
        return NC_GROUP_KP_BAD_SIG;

    out->hdr = h;
    out->count = count;
    if (qgp_sha3_512(data, pre_len, out->digest) != 0) {
        memset(out, 0, sizeof(*out));
        return NC_GROUP_KP_FAULT;
    }

    /* 3. what was asked */
    if (memcmp(h.group_id, expect_group_id, NC_GROUP_ID_LEN) != 0 || h.v != expect_v ||
        memcmp(h.owner_fp, expect_owner_fp, NC_GROUP_FP_LEN) != 0)
        return NC_GROUP_KP_MISMATCH;

    /* 4. predecessor binding (v == 1: zeros, checked by the parse) */
    if (h.v > 1) {
        if (!stored_prev_digest) return NC_GROUP_KP_PREV_UNAVAILABLE;
        if (memcmp(h.prev_digest, stored_prev_digest, NC_GROUP_DIGEST_LEN) != 0)
            return NC_GROUP_KP_PREV_CONFLICT;
    }

    /* 5. trial unwrap (R2-1) */
    for (size_t i = 0; i < count; i++) {
        const uint8_t *e = data + NC_GROUP_KP_HEADER_LEN + i * NC_GROUP_ENTRY_LEN;
        uint8_t ss[NC_GROUP_SS_LEN], kek[NC_GROUP_KEY_LEN], key[NC_GROUP_KEY_LEN];
        if (decap(ss, e, decap_user) != 0) {
            qgp_secure_memzero(ss, sizeof(ss));
            continue;
        }
        int rc = nc_group_kek(ss, h.group_id, h.v, my_fp, h.owner_fp, kek);
        qgp_secure_memzero(ss, sizeof(ss));
        if (rc != NC_GROUP_OK) return NC_GROUP_KP_FAULT;
        int un = aes256_unwrap_key(e + NC_GROUP_KEM_CT_LEN, NC_GROUP_WRAPPED_LEN, kek, key);
        qgp_secure_memzero(kek, sizeof(kek));
        if (un == 0) {
            memcpy(out->group_key, key, NC_GROUP_KEY_LEN);
            qgp_secure_memzero(key, sizeof(key));
            return NC_GROUP_KP_OK;
        }
        qgp_secure_memzero(key, sizeof(key));
    }
    return NC_GROUP_KP_NO_ENTRY;
}

/* ── record ───────────────────────────────────────────────────────────── */

int nc_group_record_pt_parse(const uint8_t *pt, size_t len, nc_group_record_t *out) {
    if (!out) return NC_GROUP_REFUSED;
    memset(out, 0, sizeof(*out));
    if (!pt || len > NC_GROUP_RECORD_PT_MAX || len < 1) return NC_GROUP_REFUSED;
    size_t nl = pt[0];
    if (nl > NC_GROUP_NAME_MAX) return NC_GROUP_REFUSED;
    size_t p = 1 + nl;
    if (len < p + 2) return NC_GROUP_REFUSED;
    size_t count = get_u16(pt + p);
    p += 2;
    if (count < 1 || count > NC_GROUP_MAX_MEMBERS) return NC_GROUP_REFUSED;
    if (len != p + count * NC_GROUP_FP_LEN + 8) return NC_GROUP_REFUSED;
    const uint8_t (*fps)[NC_GROUP_FP_LEN] = (const uint8_t (*)[NC_GROUP_FP_LEN])(pt + p);
    if (!fps_ascending(fps, count)) return NC_GROUP_REFUSED;   /* order + duplicates */
    memcpy(out->name, pt + 1, nl);
    out->name[nl] = 0;
    out->name_len = nl;
    out->count = count;
    memcpy(out->members, pt + p, count * NC_GROUP_FP_LEN);
    out->created_at_ms = get_u64(pt + p + count * NC_GROUP_FP_LEN);
    return NC_GROUP_OK;
}

int nc_group_record_digest(const uint8_t *data, size_t len,
                           uint8_t digest_out[NC_GROUP_DIGEST_LEN]) {
    if (!digest_out) return NC_GROUP_REFUSED;
    memset(digest_out, 0, NC_GROUP_DIGEST_LEN);
    if (!data || len == 0) return NC_GROUP_REFUSED;
    if (qgp_sha3_512(data, len, digest_out) != 0) {
        memset(digest_out, 0, NC_GROUP_DIGEST_LEN);
        return NC_GROUP_FAULT;
    }
    return NC_GROUP_OK;
}

static void rec_write_aad(uint8_t *b, const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v) {
    memcpy(b, TAGS[NC_GROUP_TAG_GREC], NC_GROUP_TAG_LEN);
    memcpy(b + NC_GROUP_TAG_LEN, group_id, NC_GROUP_ID_LEN);
    put_u32(b + NC_GROUP_TAG_LEN + NC_GROUP_ID_LEN, v);
}

nc_group_rec_status_t nc_group_record_open(const uint8_t *data, size_t len,
                                           const uint8_t group_key[NC_GROUP_KEY_LEN],
                                           const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                                           uint32_t expect_v,
                                           const uint8_t expect_digest[NC_GROUP_DIGEST_LEN],
                                           size_t expect_count,
                                           const uint8_t owner_fp[NC_GROUP_FP_LEN],
                                           nc_group_record_t *out) {
    if (!out) return NC_GROUP_REC_BAD_STRUCTURE;
    memset(out, 0, sizeof(*out));
    if (!group_key || !expect_group_id || !expect_digest || !owner_fp)
        return NC_GROUP_REC_BAD_STRUCTURE;

    /* structure: cap on the ct_len FIELD before anything else (reading 10) */
    if (!data || len < NC_GROUP_REC_HEADER_LEN + NC_GROUP_GCM_TAG_LEN)
        return NC_GROUP_REC_BAD_STRUCTURE;
    if (memcmp(data, TAGS[NC_GROUP_TAG_GREC], NC_GROUP_TAG_LEN) != 0)
        return NC_GROUP_REC_BAD_STRUCTURE;
    const size_t ct_len = get_u32(data + NC_GROUP_REC_AAD_LEN + NC_GROUP_NONCE_LEN);
    if (ct_len > NC_GROUP_RECORD_PT_MAX) return NC_GROUP_REC_BAD_STRUCTURE;
    if (len != NC_GROUP_REC_HEADER_LEN + ct_len + NC_GROUP_GCM_TAG_LEN)
        return NC_GROUP_REC_BAD_STRUCTURE;
    /* qgp_aes256_decrypt refuses an empty ciphertext (qgp_aes.c:135-138);
     * no valid plaintext is that short anyway. */
    if (ct_len == 0) return NC_GROUP_REC_BAD_STRUCTURE;

    if (memcmp(data + NC_GROUP_TAG_LEN, expect_group_id, NC_GROUP_ID_LEN) != 0 ||
        get_u32(data + NC_GROUP_TAG_LEN + NC_GROUP_ID_LEN) != expect_v)
        return NC_GROUP_REC_MISMATCH;

    uint8_t dig[NC_GROUP_DIGEST_LEN];
    if (qgp_sha3_512(data, len, dig) != 0) return NC_GROUP_REC_FAULT;
    if (memcmp(dig, expect_digest, NC_GROUP_DIGEST_LEN) != 0) return NC_GROUP_REC_BAD_DIGEST;

    uint8_t pt[NC_GROUP_RECORD_PT_MAX];
    size_t pt_len = 0;
    nc_group_rec_status_t st;
    if (qgp_aes256_decrypt(group_key, data + NC_GROUP_REC_HEADER_LEN, ct_len,
                           data, NC_GROUP_REC_AAD_LEN,
                           data + NC_GROUP_REC_AAD_LEN,
                           data + NC_GROUP_REC_HEADER_LEN + ct_len,
                           pt, &pt_len) != 0 || pt_len != ct_len) {
        /* tag mismatch and an OpenSSL allocation failure are the same -1
         * inside qgp_aes (qgp_aes.c:146-149, :184-192) */
        st = NC_GROUP_REC_BAD_AUTH;
    } else if (nc_group_record_pt_parse(pt, pt_len, out) != NC_GROUP_OK) {
        st = NC_GROUP_REC_BAD_PLAINTEXT;
    } else if (out->count != expect_count) {
        st = NC_GROUP_REC_COUNT;
    } else if (!fp_in(owner_fp, (const uint8_t (*)[NC_GROUP_FP_LEN])out->members, out->count)) {
        st = NC_GROUP_REC_NO_OWNER;
    } else {
        st = NC_GROUP_REC_OK;
    }
    qgp_secure_memzero(pt, sizeof(pt));
    if (st != NC_GROUP_REC_OK) qgp_secure_memzero(out, sizeof(*out));
    return st;
}

int nc_group_record_seal(const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                         const uint8_t group_key[NC_GROUP_KEY_LEN],
                         const uint8_t owner_fp[NC_GROUP_FP_LEN],
                         const uint8_t *name, size_t name_len,
                         const uint8_t (*members)[NC_GROUP_FP_LEN], size_t count,
                         uint64_t created_at_ms,
                         uint8_t **out, size_t *out_len,
                         uint8_t digest_out[NC_GROUP_DIGEST_LEN]) {
    if (!out || !out_len) return NC_GROUP_REFUSED;
    *out = NULL;
    *out_len = 0;
    if (digest_out) memset(digest_out, 0, NC_GROUP_DIGEST_LEN);
    if (!group_id || !group_key || !owner_fp || !members || v == 0) return NC_GROUP_REFUSED;
    if (name_len > NC_GROUP_NAME_MAX || (name_len && !name)) return NC_GROUP_REFUSED;
    if (count < 1 || count > NC_GROUP_MAX_MEMBERS) return NC_GROUP_REFUSED;
    if (!fps_ascending(members, count) || !fp_in(owner_fp, members, count))
        return NC_GROUP_REFUSED;

    uint8_t pt[NC_GROUP_RECORD_PT_MAX];
    size_t p = 0;
    pt[p++] = (uint8_t)name_len;
    if (name_len) memcpy(pt + p, name, name_len);
    p += name_len;
    put_u16(pt + p, (uint16_t)count); p += 2;
    memcpy(pt + p, members, count * NC_GROUP_FP_LEN); p += count * NC_GROUP_FP_LEN;
    put_u64(pt + p, created_at_ms); p += 8;

    const size_t len = NC_GROUP_REC_HEADER_LEN + p + NC_GROUP_GCM_TAG_LEN;
    uint8_t *b = malloc(len);
    int rc = NC_GROUP_FAULT;
    uint8_t dig[NC_GROUP_DIGEST_LEN];
    nc_group_record_t *chk = NULL;
    if (!b) goto done;
    rec_write_aad(b, group_id, v);
    put_u32(b + NC_GROUP_REC_AAD_LEN + NC_GROUP_NONCE_LEN, (uint32_t)p);
    size_t ct_len = 0;
    /* AAD = the first 52 bytes; the nonce the call draws lands after them. */
    if (qgp_aes256_encrypt(group_key, pt, p, b, NC_GROUP_REC_AAD_LEN,
                           b + NC_GROUP_REC_HEADER_LEN, &ct_len,
                           b + NC_GROUP_REC_AAD_LEN,
                           b + NC_GROUP_REC_HEADER_LEN + p) != 0 || ct_len != p) {
        QGP_LOG_ERROR(LOG_TAG, "record_seal: AES-256-GCM failed");
        goto done;
    }
    if (qgp_sha3_512(b, len, dig) != 0) goto done;
    chk = malloc(sizeof(*chk));
    if (!chk) goto done;
    if (nc_group_record_open(b, len, group_key, group_id, v, dig, count, owner_fp, chk) !=
        NC_GROUP_REC_OK) {
        QGP_LOG_ERROR(LOG_TAG, "record_seal: sealed record does not open back");
        goto done;
    }
    if (digest_out) memcpy(digest_out, dig, NC_GROUP_DIGEST_LEN);
    *out = b;
    *out_len = len;
    b = NULL;
    rc = NC_GROUP_OK;

done:
    qgp_secure_memzero(pt, sizeof(pt));
    if (chk) { qgp_secure_memzero(chk, sizeof(*chk)); free(chk); }
    free(b);                               /* ciphertext only: no secret */
    return rc;
}

/* ── HEAD ─────────────────────────────────────────────────────────────── */

int nc_group_head_preimage(const nc_group_head_t *h,
                           uint8_t pre_out[NC_GROUP_HEAD_SIGNED_LEN]) {
    if (!pre_out) return NC_GROUP_REFUSED;
    memset(pre_out, 0, NC_GROUP_HEAD_SIGNED_LEN);
    if (!h || h->v == 0) return NC_GROUP_REFUSED;
    size_t o = 0;
    memcpy(pre_out + o, TAGS[NC_GROUP_TAG_GHEAD], NC_GROUP_TAG_LEN); o += NC_GROUP_TAG_LEN;
    memcpy(pre_out + o, h->group_id, NC_GROUP_ID_LEN);               o += NC_GROUP_ID_LEN;
    memcpy(pre_out + o, h->owner_fp, NC_GROUP_FP_LEN);               o += NC_GROUP_FP_LEN;
    put_u32(pre_out + o, h->v);                                      o += 4;
    memcpy(pre_out + o, h->kp_digest, NC_GROUP_DIGEST_LEN);          o += NC_GROUP_DIGEST_LEN;
    put_u64(pre_out + o, h->issued_at_ms);
    return NC_GROUP_OK;
}

int nc_group_head_build(const nc_group_head_t *h,
                        const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                        const uint8_t owner_sk[NC_GROUP_DSA_SK_LEN],
                        uint8_t out[NC_GROUP_HEAD_LEN]) {
    if (!out) return NC_GROUP_REFUSED;
    memset(out, 0, NC_GROUP_HEAD_LEN);
    if (!owner_pk || !owner_sk) return NC_GROUP_REFUSED;
    int rc = nc_group_head_preimage(h, out);
    if (rc != NC_GROUP_OK) return rc;
    put_u16(out + NC_GROUP_HEAD_SIGNED_LEN, NC_GROUP_SIG_LEN);
    rc = sign_exact(out + NC_GROUP_HEAD_SIGNED_LEN + 2, out, NC_GROUP_HEAD_SIGNED_LEN, owner_sk);
    if (rc == NC_GROUP_OK &&
        qgp_dsa87_verify(out + NC_GROUP_HEAD_SIGNED_LEN + 2, NC_GROUP_SIG_LEN,
                         out, NC_GROUP_HEAD_SIGNED_LEN, owner_pk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "head_build: signature does not verify under owner_pk");
        rc = NC_GROUP_FAULT;
    }
    if (rc != NC_GROUP_OK) memset(out, 0, NC_GROUP_HEAD_LEN);
    return rc;
}

int nc_group_head_parse(const uint8_t *data, size_t len, nc_group_head_t *h_out) {
    if (h_out) memset(h_out, 0, sizeof(*h_out));
    if (!data || len < NC_GROUP_HEAD_SIGNED_LEN + 2) return NC_GROUP_REFUSED;
    if (memcmp(data, TAGS[NC_GROUP_TAG_GHEAD], NC_GROUP_TAG_LEN) != 0) return NC_GROUP_REFUSED;
    if (get_u16(data + NC_GROUP_HEAD_SIGNED_LEN) != NC_GROUP_SIG_LEN) return NC_GROUP_REFUSED;
    if (len != NC_GROUP_HEAD_LEN) return NC_GROUP_REFUSED;
    nc_group_head_t h;
    size_t o = NC_GROUP_TAG_LEN;
    memcpy(h.group_id, data + o, NC_GROUP_ID_LEN);          o += NC_GROUP_ID_LEN;
    memcpy(h.owner_fp, data + o, NC_GROUP_FP_LEN);          o += NC_GROUP_FP_LEN;
    h.v = get_u32(data + o);                                o += 4;
    memcpy(h.kp_digest, data + o, NC_GROUP_DIGEST_LEN);     o += NC_GROUP_DIGEST_LEN;
    h.issued_at_ms = get_u64(data + o);
    if (h.v == 0) return NC_GROUP_REFUSED;
    if (h_out) *h_out = h;
    return NC_GROUP_OK;
}

nc_group_head_status_t nc_group_head_verify(const uint8_t *data, size_t len,
                                            const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                                            const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                                            const uint8_t expect_owner_fp[NC_GROUP_FP_LEN],
                                            nc_group_head_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !owner_pk || !expect_group_id || !expect_owner_fp)
        return NC_GROUP_HEAD_BAD_STRUCTURE;
    nc_group_head_t h;
    if (nc_group_head_parse(data, len, &h) != NC_GROUP_OK) return NC_GROUP_HEAD_BAD_STRUCTURE;
    if (qgp_dsa87_verify(data + NC_GROUP_HEAD_SIGNED_LEN + 2, NC_GROUP_SIG_LEN,
                         data, NC_GROUP_HEAD_SIGNED_LEN, owner_pk) != 0)
        return NC_GROUP_HEAD_BAD_SIG;
    if (memcmp(h.group_id, expect_group_id, NC_GROUP_ID_LEN) != 0 ||
        memcmp(h.owner_fp, expect_owner_fp, NC_GROUP_FP_LEN) != 0)
        return NC_GROUP_HEAD_MISMATCH;
    *out = h;
    return NC_GROUP_HEAD_OK;
}

/* ── message ──────────────────────────────────────────────────────────── */

int nc_group_msg_aad(const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                     const uint8_t sender_fp[NC_GROUP_FP_LEN],
                     const uint8_t message_id[NC_GROUP_MSG_ID_LEN],
                     uint64_t timestamp_ms,
                     uint8_t aad_out[NC_GROUP_MSG_AAD_LEN]) {
    if (!aad_out) return NC_GROUP_REFUSED;
    memset(aad_out, 0, NC_GROUP_MSG_AAD_LEN);
    if (!group_id || !sender_fp || !message_id || v == 0) return NC_GROUP_REFUSED;
    uint32_t day;
    if (nc_group_day(timestamp_ms, &day) != NC_GROUP_OK) return NC_GROUP_REFUSED;
    size_t o = 0;
    memcpy(aad_out + o, TAGS[NC_GROUP_TAG_GMSG], NC_GROUP_TAG_LEN); o += NC_GROUP_TAG_LEN;
    memcpy(aad_out + o, group_id, NC_GROUP_ID_LEN);                 o += NC_GROUP_ID_LEN;
    put_u32(aad_out + o, v);                                        o += 4;
    memcpy(aad_out + o, sender_fp, NC_GROUP_FP_LEN);                o += NC_GROUP_FP_LEN;
    memcpy(aad_out + o, message_id, NC_GROUP_MSG_ID_LEN);           o += NC_GROUP_MSG_ID_LEN;
    put_u64(aad_out + o, timestamp_ms);                             o += 8;
    put_u32(aad_out + o, day);
    return NC_GROUP_OK;
}

int nc_group_msg_parse(const uint8_t *data, size_t len, bool exact, nc_group_msg_t *out) {
    if (!out) return NC_GROUP_REFUSED;
    memset(out, 0, sizeof(*out));
    if (!data || len < NC_GROUP_MSG_H_LEN + 4) return NC_GROUP_REFUSED;
    if (memcmp(data, TAGS[NC_GROUP_TAG_GMSG], NC_GROUP_TAG_LEN) != 0) return NC_GROUP_REFUSED;
    nc_group_msg_t m;
    memset(&m, 0, sizeof(m));
    size_t o = NC_GROUP_TAG_LEN;
    memcpy(m.group_id, data + o, NC_GROUP_ID_LEN);          o += NC_GROUP_ID_LEN;
    m.v = get_u32(data + o);                                o += 4;
    memcpy(m.sender_fp, data + o, NC_GROUP_FP_LEN);         o += NC_GROUP_FP_LEN;
    memcpy(m.message_id, data + o, NC_GROUP_MSG_ID_LEN);    o += NC_GROUP_MSG_ID_LEN;
    m.timestamp_ms = get_u64(data + o);                     o += 8;
    m.day = get_u32(data + o);
    if (m.v == 0) return NC_GROUP_REFUSED;
    uint32_t day;
    if (nc_group_day(m.timestamp_ms, &day) != NC_GROUP_OK || day != m.day)
        return NC_GROUP_REFUSED;
    m.ct_len = get_u32(data + NC_GROUP_MSG_H_LEN);
    if (m.ct_len > NC_GROUP_TEXT_MAX) return NC_GROUP_REFUSED;      /* R2-8 */
    /* Decision 11 (nc_group.h EMPTY TEXT): text >= 1 byte, refused on the
     * field here, not left to qgp_aes at open. */
    if (m.ct_len == 0) {
        QGP_LOG_WARN(LOG_TAG, "msg_parse: empty message text refused (decision 11)");
        return NC_GROUP_REFUSED;
    }
    m.signed_len = NC_GROUP_MSG_H_LEN + 4 + m.ct_len + NC_GROUP_GCM_TAG_LEN;
    if (len < m.signed_len + 2) return NC_GROUP_REFUSED;
    if (get_u16(data + m.signed_len) != NC_GROUP_SIG_LEN) return NC_GROUP_REFUSED;
    m.item_len = m.signed_len + 2 + NC_GROUP_SIG_LEN;
    if (len < m.item_len || (exact && len != m.item_len)) return NC_GROUP_REFUSED;
    m.h = data;
    m.ct = data + NC_GROUP_MSG_H_LEN + 4;
    m.gcm_tag = m.ct + m.ct_len;
    m.sig = data + m.signed_len + 2;
    *out = m;
    return NC_GROUP_OK;
}

int nc_group_msg_seal(const uint8_t group_key[NC_GROUP_KEY_LEN],
                      const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                      const uint8_t sender_fp[NC_GROUP_FP_LEN],
                      uint64_t timestamp_ms,
                      const uint8_t *text, size_t text_len,
                      const uint8_t sender_pk[NC_GROUP_DSA_PK_LEN],
                      const uint8_t sender_sk[NC_GROUP_DSA_SK_LEN],
                      uint8_t message_id_out[NC_GROUP_MSG_ID_LEN],
                      uint8_t **item_out, size_t *item_len) {
    if (!item_out || !item_len || !message_id_out) return NC_GROUP_REFUSED;
    *item_out = NULL;
    *item_len = 0;
    memset(message_id_out, 0, NC_GROUP_MSG_ID_LEN);
    if (!group_key || !group_id || !sender_fp || !text || !sender_pk || !sender_sk)
        return NC_GROUP_REFUSED;
    /* Decision 11 (nc_group.h EMPTY TEXT): text >= 1 byte. */
    if (text_len == 0) {
        QGP_LOG_WARN(LOG_TAG, "msg_seal: empty message text refused (decision 11)");
        return NC_GROUP_REFUSED;
    }
    if (text_len > NC_GROUP_TEXT_MAX) return NC_GROUP_REFUSED;

    uint8_t mid[NC_GROUP_MSG_ID_LEN];
    if (qgp_randombytes(mid, sizeof(mid)) != 0) return NC_GROUP_FAULT;
    uint8_t aad[NC_GROUP_MSG_AAD_LEN];
    int rc = nc_group_msg_aad(group_id, v, sender_fp, mid, timestamp_ms, aad);
    if (rc != NC_GROUP_OK) return rc;

    const size_t signed_len = NC_GROUP_MSG_H_LEN + 4 + text_len + NC_GROUP_GCM_TAG_LEN;
    const size_t len = signed_len + 2 + NC_GROUP_SIG_LEN;
    uint8_t *b = malloc(len);
    if (!b) return NC_GROUP_FAULT;
    rc = NC_GROUP_FAULT;
    memcpy(b, aad, NC_GROUP_MSG_AAD_LEN);
    put_u32(b + NC_GROUP_MSG_H_LEN, (uint32_t)text_len);
    size_t ct_len = 0;
    /* AAD = H minus its last 12 bytes (R2-5); the nonce the call draws is
     * written straight into those 12 bytes. */
    if (qgp_aes256_encrypt(group_key, text, text_len, b, NC_GROUP_MSG_AAD_LEN,
                           b + NC_GROUP_MSG_H_LEN + 4, &ct_len,
                           b + NC_GROUP_MSG_AAD_LEN,
                           b + NC_GROUP_MSG_H_LEN + 4 + text_len) != 0 || ct_len != text_len) {
        QGP_LOG_ERROR(LOG_TAG, "msg_seal: AES-256-GCM failed");
        goto done;
    }
    put_u16(b + signed_len, NC_GROUP_SIG_LEN);
    if (sign_exact(b + signed_len + 2, b, signed_len, sender_sk) != NC_GROUP_OK) goto done;
    nc_group_msg_t m;
    if (nc_group_msg_parse(b, len, true, &m) != NC_GROUP_OK ||
        qgp_dsa87_verify(m.sig, NC_GROUP_SIG_LEN, b, signed_len, sender_pk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "msg_seal: sealed item does not read back");
        goto done;
    }
    memcpy(message_id_out, mid, NC_GROUP_MSG_ID_LEN);
    *item_out = b;
    *item_len = len;
    b = NULL;
    rc = NC_GROUP_OK;

done:
    free(b);                               /* ciphertext only: no secret */
    return rc;
}

nc_group_msg_status_t nc_group_msg_open(const nc_group_msg_t *m,
                                        const uint8_t group_key[NC_GROUP_KEY_LEN],
                                        const uint8_t sender_pk[NC_GROUP_DSA_PK_LEN],
                                        uint8_t *text_out, size_t *text_len) {
    if (text_len) *text_len = 0;
    if (!m || !m->h || !m->sig || !group_key || !sender_pk || !text_out || !text_len)
        return NC_GROUP_MSG_REFUSED;
    if (m->ct_len > NC_GROUP_TEXT_MAX ||
        m->signed_len != NC_GROUP_MSG_H_LEN + 4 + m->ct_len + NC_GROUP_GCM_TAG_LEN)
        return NC_GROUP_MSG_REFUSED;
    /* Decision 11 (nc_group.h EMPTY TEXT): nc_group_msg_parse already
     * refuses ct_len 0; checked again for a hand-filled struct, before the
     * signature check. */
    if (m->ct_len == 0) return NC_GROUP_MSG_REFUSED;

    if (qgp_dsa87_verify(m->sig, NC_GROUP_SIG_LEN, m->h, m->signed_len, sender_pk) != 0)
        return NC_GROUP_MSG_BAD_SIG;
    size_t pt_len = 0;
    if (qgp_aes256_decrypt(group_key, m->ct, m->ct_len, m->h, NC_GROUP_MSG_AAD_LEN,
                           m->h + NC_GROUP_MSG_AAD_LEN, m->gcm_tag,
                           text_out, &pt_len) != 0 || pt_len != m->ct_len) {
        qgp_secure_memzero(text_out, m->ct_len);
        return NC_GROUP_MSG_BAD_AUTH;
    }
    *text_len = pt_len;
    return NC_GROUP_MSG_OK;
}

bool nc_group_msg_accept(const uint8_t sender_fp[NC_GROUP_FP_LEN],
                         const uint8_t (*members_v)[NC_GROUP_FP_LEN], size_t n_v,
                         const uint8_t (*members_next)[NC_GROUP_FP_LEN], size_t n_next) {
    if (!sender_fp || !members_v) return false;
    if (!fp_in(sender_fp, members_v, n_v)) return false;
    if (members_next && !fp_in(sender_fp, members_next, n_next)) return false;
    return true;
}

/* ── bucket ───────────────────────────────────────────────────────────── */

#define BKT_HEADER_LEN (NC_GROUP_TAG_LEN + 2)

/* Item k against item 0 (same group / v / day / sender) and against every
 * earlier item (unique message_id). */
static int bucket_item_ok(const nc_group_msg_t *items, size_t k) {
    const nc_group_msg_t *a = &items[0], *m = &items[k];
    if (k > 0 &&
        (memcmp(m->group_id, a->group_id, NC_GROUP_ID_LEN) != 0 || m->v != a->v ||
         m->day != a->day || memcmp(m->sender_fp, a->sender_fp, NC_GROUP_FP_LEN) != 0))
        return 0;
    for (size_t j = 0; j < k; j++)
        if (memcmp(items[j].message_id, m->message_id, NC_GROUP_MSG_ID_LEN) == 0) return 0;
    return 1;
}

int nc_group_bucket_encode(const uint8_t *const *items, const size_t *item_lens,
                           size_t n, uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return NC_GROUP_REFUSED;
    *out = NULL;
    *out_len = 0;
    if (!items || !item_lens || n < 1 || n > NC_GROUP_BUCKET_ITEMS_MAX) return NC_GROUP_REFUSED;
    nc_group_msg_t parsed[NC_GROUP_BUCKET_ITEMS_MAX];
    size_t total = BKT_HEADER_LEN;
    for (size_t k = 0; k < n; k++) {
        if (!items[k] || item_lens[k] > NC_GROUP_BUCKET_MAX) return NC_GROUP_REFUSED;
        if (nc_group_msg_parse(items[k], item_lens[k], true, &parsed[k]) != NC_GROUP_OK)
            return NC_GROUP_REFUSED;
        if (!bucket_item_ok(parsed, k)) return NC_GROUP_REFUSED;
        total += item_lens[k];
        if (total > NC_GROUP_BUCKET_MAX) return NC_GROUP_REFUSED;
    }
    uint8_t *b = malloc(total);
    if (!b) return NC_GROUP_FAULT;
    memcpy(b, TAGS[NC_GROUP_TAG_GBKT], NC_GROUP_TAG_LEN);
    put_u16(b + NC_GROUP_TAG_LEN, (uint16_t)n);
    size_t o = BKT_HEADER_LEN;
    for (size_t k = 0; k < n; k++) {
        memcpy(b + o, items[k], item_lens[k]);
        o += item_lens[k];
    }
    *out = b;
    *out_len = total;
    return NC_GROUP_OK;
}

int nc_group_bucket_decode(const uint8_t *data, size_t len,
                           const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                           uint32_t expect_v, uint32_t expect_day,
                           nc_group_msg_t **items_out, size_t *count_out) {
    if (!items_out || !count_out) return NC_GROUP_REFUSED;
    *items_out = NULL;
    *count_out = 0;
    if (!data || !expect_group_id) return NC_GROUP_REFUSED;
    if (len < BKT_HEADER_LEN || len > NC_GROUP_BUCKET_MAX) return NC_GROUP_REFUSED;
    if (memcmp(data, TAGS[NC_GROUP_TAG_GBKT], NC_GROUP_TAG_LEN) != 0) return NC_GROUP_REFUSED;
    size_t count = get_u16(data + NC_GROUP_TAG_LEN);
    if (count > NC_GROUP_BUCKET_ITEMS_MAX) return NC_GROUP_REFUSED;
    if (count == 0) return len == BKT_HEADER_LEN ? NC_GROUP_OK : NC_GROUP_REFUSED;

    nc_group_msg_t *items = calloc(count, sizeof(*items));
    if (!items) return NC_GROUP_FAULT;
    size_t o = BKT_HEADER_LEN;
    for (size_t k = 0; k < count; k++) {
        if (nc_group_msg_parse(data + o, len - o, false, &items[k]) != NC_GROUP_OK ||
            memcmp(items[k].group_id, expect_group_id, NC_GROUP_ID_LEN) != 0 ||
            items[k].v != expect_v || items[k].day != expect_day ||
            !bucket_item_ok(items, k)) {
            free(items);
            return NC_GROUP_REFUSED;
        }
        o += items[k].item_len;
    }
    if (o != len) { free(items); return NC_GROUP_REFUSED; }
    *items_out = items;
    *count_out = count;
    return NC_GROUP_OK;
}

/* ── invite / accept / welcome JSON ───────────────────────────────────── */

static const char *const JSON_TYPE[] = {
    NULL, "nodus_group_invite", "nodus_group_accept", "nodus_group_welcome"
};

/* Copy out the encoded JSON after reading it back with the strict parser
 * (an encoder never returns what nc_group_json_parse would refuse — e.g. a
 * name that is not valid UTF-8). */
static int json_out(const char *s, size_t n, char **out, size_t *out_len) {
    if (n == 0 || n > NC_GROUP_JSON_MAX) return NC_GROUP_REFUSED;
    nc_group_json_t chk;
    int rc = nc_group_json_parse(s, n, &chk);
    qgp_secure_memzero(&chk, sizeof(chk));
    if (rc != NC_GROUP_OK) return rc;
    char *c = malloc(n + 1);
    if (!c) return NC_GROUP_FAULT;
    memcpy(c, s, n);
    c[n] = '\0';
    *out = c;
    *out_len = n;
    return NC_GROUP_OK;
}

/* The invite holds no secret and carries a free-text name: json-c writes
 * it (compact, "/" not escaped, UTF-8 passed through), in insertion order. */
int nc_group_invite_encode(const uint8_t group_id[NC_GROUP_ID_LEN],
                           const uint8_t owner_fp[NC_GROUP_FP_LEN],
                           const char *name, size_t name_len,
                           const uint8_t invite_id[NC_GROUP_INVITE_ID_LEN],
                           char **out, size_t *out_len) {
    if (!out || !out_len) return NC_GROUP_REFUSED;
    *out = NULL;
    *out_len = 0;
    if (!group_id || !owner_fp || !invite_id || (name_len && !name)) return NC_GROUP_REFUSED;
    if (name_len > NC_GROUP_NAME_MAX || (name_len && memchr(name, 0, name_len)))
        return NC_GROUP_REFUSED;
    char gid[2 * NC_GROUP_ID_LEN + 1], own[2 * NC_GROUP_FP_LEN + 1];
    char iid[2 * NC_GROUP_INVITE_ID_LEN + 1];
    hex_enc(group_id, NC_GROUP_ID_LEN, gid);
    hex_enc(owner_fp, NC_GROUP_FP_LEN, own);
    hex_enc(invite_id, NC_GROUP_INVITE_ID_LEN, iid);

    json_object *o = json_object_new_object();
    if (!o) return NC_GROUP_FAULT;
    json_object_object_add(o, "type", json_object_new_string(JSON_TYPE[NC_GROUP_JSON_INVITE]));
    json_object_object_add(o, "v", json_object_new_int(1));
    json_object_object_add(o, "group_id", json_object_new_string(gid));
    json_object_object_add(o, "owner", json_object_new_string(own));
    json_object_object_add(o, "name", json_object_new_string_len(name_len ? name : "",
                                                                 (int)name_len));
    json_object_object_add(o, "invite_id", json_object_new_string(iid));
    int rc = NC_GROUP_FAULT;
    if (json_object_object_length(o) == 6) {
        size_t n = 0;
        const char *s = json_object_to_json_string_length(
            o, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE, &n);
        if (s) rc = json_out(s, n, out, out_len);
    }
    json_object_put(o);
    return rc;
}

/* accept / welcome are hex and integers only — no escaping can apply — so
 * they are written into one buffer this file owns and wipes (the welcome
 * carries addr_secret; json-c's growing print buffer would leave freed,
 * unwiped copies). Same compact form and key order as the invite. */
int nc_group_accept_encode(const uint8_t group_id[NC_GROUP_ID_LEN],
                           const uint8_t invite_id[NC_GROUP_INVITE_ID_LEN],
                           char **out, size_t *out_len) {
    if (!out || !out_len) return NC_GROUP_REFUSED;
    *out = NULL;
    *out_len = 0;
    if (!group_id || !invite_id) return NC_GROUP_REFUSED;
    char gid[2 * NC_GROUP_ID_LEN + 1], iid[2 * NC_GROUP_INVITE_ID_LEN + 1];
    hex_enc(group_id, NC_GROUP_ID_LEN, gid);
    hex_enc(invite_id, NC_GROUP_INVITE_ID_LEN, iid);
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
                     "{\"type\":\"%s\",\"v\":1,\"group_id\":\"%s\",\"invite_id\":\"%s\"}",
                     JSON_TYPE[NC_GROUP_JSON_ACCEPT], gid, iid);
    if (n <= 0 || (size_t)n >= sizeof(buf)) return NC_GROUP_FAULT;
    return json_out(buf, (size_t)n, out, out_len);
}

int nc_group_welcome_encode(const uint8_t group_id[NC_GROUP_ID_LEN],
                            const uint8_t owner_fp[NC_GROUP_FP_LEN],
                            const uint8_t addr_secret[NC_GROUP_SECRET_LEN],
                            uint32_t key_version,
                            const uint8_t kp_digest[NC_GROUP_DIGEST_LEN],
                            const uint8_t invite_id[NC_GROUP_INVITE_ID_LEN],
                            char **out, size_t *out_len) {
    if (!out || !out_len) return NC_GROUP_REFUSED;
    *out = NULL;
    *out_len = 0;
    if (!group_id || !owner_fp || !addr_secret || !kp_digest || !invite_id || key_version == 0)
        return NC_GROUP_REFUSED;
    char gid[2 * NC_GROUP_ID_LEN + 1], own[2 * NC_GROUP_FP_LEN + 1];
    char sec[2 * NC_GROUP_SECRET_LEN + 1], dig[2 * NC_GROUP_DIGEST_LEN + 1];
    char iid[2 * NC_GROUP_INVITE_ID_LEN + 1];
    hex_enc(group_id, NC_GROUP_ID_LEN, gid);
    hex_enc(owner_fp, NC_GROUP_FP_LEN, own);
    hex_enc(addr_secret, NC_GROUP_SECRET_LEN, sec);
    hex_enc(kp_digest, NC_GROUP_DIGEST_LEN, dig);
    hex_enc(invite_id, NC_GROUP_INVITE_ID_LEN, iid);
    char buf[768];
    int n = snprintf(buf, sizeof(buf),
                     "{\"type\":\"%s\",\"v\":1,\"group_id\":\"%s\",\"owner\":\"%s\","
                     "\"addr_secret\":\"%s\",\"key_version\":%lu,\"kp_digest\":\"%s\","
                     "\"invite_id\":\"%s\"}",
                     JSON_TYPE[NC_GROUP_JSON_WELCOME], gid, own, sec,
                     (unsigned long)key_version, dig, iid);
    int rc = (n <= 0 || (size_t)n >= sizeof(buf)) ? NC_GROUP_FAULT
                                                 : json_out(buf, (size_t)n, out, out_len);
    qgp_secure_memzero(sec, sizeof(sec));
    qgp_secure_memzero(buf, sizeof(buf));
    return rc;
}

/* Members of the top-level object as written in the text: ':' at depth 1
 * outside strings. Compared with the parsed object's member count, a
 * difference means a key appeared twice (json-c keeps the last). */
static size_t json_text_members(const char *s, size_t len) {
    size_t n = 0;
    int depth = 0, in_str = 0, esc = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (in_str) {
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') in_str = 1;
        else if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') depth--;
        else if (c == ':' && depth == 1) n++;
    }
    return n;
}

static int jfield_hex(json_object *o, const char *key, uint8_t *out, size_t n) {
    json_object *v = NULL;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_string))
        return -1;
    return hex_dec(json_object_get_string(v), (size_t)json_object_get_string_len(v), out, n);
}

/* A JSON integer (never a double, string or boolean) in [lo, hi]. */
static int jfield_int(json_object *o, const char *key, int64_t lo, int64_t hi, int64_t *out) {
    json_object *v = NULL;
    if (!json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_int))
        return -1;
    /* json-c saturates an out-of-range integer at INT64_MIN / INT64_MAX:
     * both fall outside every [lo, hi] used here. */
    int64_t x = json_object_get_int64(v);
    if (x < lo || x > hi) return -1;
    *out = x;
    return 0;
}

/* Wipe the bytes json-c holds for a string member (welcome addr_secret). */
static void jfield_wipe(json_object *o, const char *key) {
    json_object *v = NULL;
    if (json_object_object_get_ex(o, key, &v) && json_object_is_type(v, json_type_string)) {
        int n = json_object_get_string_len(v);
        char *p = (char *)json_object_get_string(v);
        if (p && n > 0) qgp_secure_memzero(p, (size_t)n);
    }
}

int nc_group_json_parse(const char *json, size_t len, nc_group_json_t *out) {
    if (!out) return NC_GROUP_REFUSED;
    memset(out, 0, sizeof(*out));
    if (!json || len < 2 || len > NC_GROUP_JSON_MAX || memchr(json, 0, len))
        return NC_GROUP_REFUSED;
    /* Exact consumption (R2-8): the strict tokener still eats whitespace
     * after the closing brace and reports success (json-c 0.17
     * json_tokener.c:1293-1299 flags only a non-whitespace trailing char),
     * so no byte outside the object is allowed, whitespace included. */
    if (json[0] != '{' || json[len - 1] != '}') return NC_GROUP_REFUSED;

    json_tokener *tok = json_tokener_new();
    if (!tok) return NC_GROUP_FAULT;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    json_object *o = json_tokener_parse_ex(tok, json, (int)len);
    int parsed = o && json_tokener_get_error(tok) == json_tokener_success &&
                 json_tokener_get_parse_end(tok) == len;
    json_tokener_free(tok);
    int rc = NC_GROUP_REFUSED;
    if (!parsed || !json_object_is_type(o, json_type_object)) goto done;

    json_object *jt = NULL;
    if (!json_object_object_get_ex(o, "type", &jt) || !json_object_is_type(jt, json_type_string))
        goto done;
    const char *type = json_object_get_string(jt);
    /* a "\u0000" inside the value would end strcmp early: the length must
     * match too */
    size_t tl = (size_t)json_object_get_string_len(jt);
    if (!type || tl != strlen(type)) goto done;
    size_t want;
    if (strcmp(type, JSON_TYPE[NC_GROUP_JSON_INVITE]) == 0) {
        out->type = NC_GROUP_JSON_INVITE;  want = 6;
    } else if (strcmp(type, JSON_TYPE[NC_GROUP_JSON_ACCEPT]) == 0) {
        out->type = NC_GROUP_JSON_ACCEPT;  want = 4;
    } else if (strcmp(type, JSON_TYPE[NC_GROUP_JSON_WELCOME]) == 0) {
        out->type = NC_GROUP_JSON_WELCOME; want = 8;
    } else {
        goto done;
    }
    /* exactly the field set: every expected key below must be present, so
     * an equal count leaves no room for another key; the text count catches
     * a duplicate */
    if ((size_t)json_object_object_length(o) != want ||
        json_text_members(json, len) != want)
        goto done;

    int64_t iv;
    if (jfield_int(o, "v", 1, 1, &iv) != 0) goto done;
    if (jfield_hex(o, "group_id", out->group_id, NC_GROUP_ID_LEN) != 0) goto done;
    if (jfield_hex(o, "invite_id", out->invite_id, NC_GROUP_INVITE_ID_LEN) != 0) goto done;
    if (out->type == NC_GROUP_JSON_INVITE || out->type == NC_GROUP_JSON_WELCOME) {
        if (jfield_hex(o, "owner", out->owner_fp, NC_GROUP_FP_LEN) != 0) goto done;
    }
    if (out->type == NC_GROUP_JSON_INVITE) {
        json_object *jn = NULL;
        if (!json_object_object_get_ex(o, "name", &jn) ||
            !json_object_is_type(jn, json_type_string))
            goto done;
        int nl = json_object_get_string_len(jn);
        const char *ns = json_object_get_string(jn);
        if (nl < 0 || nl > NC_GROUP_NAME_MAX || (nl && memchr(ns, 0, (size_t)nl))) goto done;
        memcpy(out->name, ns, (size_t)nl);
        out->name[nl] = '\0';
        out->name_len = (size_t)nl;
    }
    if (out->type == NC_GROUP_JSON_WELCOME) {
        int64_t kv;
        if (jfield_hex(o, "addr_secret", out->addr_secret, NC_GROUP_SECRET_LEN) != 0) goto done;
        if (jfield_int(o, "key_version", 1, (int64_t)UINT32_MAX, &kv) != 0) goto done;
        out->key_version = (uint32_t)kv;
        if (jfield_hex(o, "kp_digest", out->kp_digest, NC_GROUP_DIGEST_LEN) != 0) goto done;
    }
    rc = NC_GROUP_OK;

done:
    if (o) {
        jfield_wipe(o, "addr_secret");
        json_object_put(o);
    }
    if (rc != NC_GROUP_OK) qgp_secure_memzero(out, sizeof(*out));
    return rc;
}
