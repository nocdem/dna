/**
 * @file shared/dnac/valbind_wire.c
 * @brief HF-6 slice 1 — consent message, consent signature, validator_id
 *        (contract: valbind_wire.h; design 2026-10-03-hf5-validator-owner
 *        -stake §6.1, §6.2, rev 6 §11.3 for consent op 3). INERT: no
 *        consensus path calls anything here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "valbind_wire.h"

#include <string.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

/** "NDS.VALID.v1" (12 chars) + 4 zero bytes — design §6.2; collision scan
 *  recorded in design §6 (0 hits, 2026-10-08). */
static const uint8_t TAG_VALID[DNA_VALBIND_TAG_LEN] = {
    'N','D','S','.','V','A','L','I','D','.','v','1', 0, 0, 0, 0
};

/** "NDS.VALMIG.v1" (13 chars) + 3 zero bytes — design §6.2. */
static const uint8_t TAG_VALMIG[DNA_VALBIND_TAG_LEN] = {
    'N','D','S','.','V','A','L','M','I','G','.','v','1', 0, 0, 0
};

/* Layout arithmetic is pinned, not assumed. */
_Static_assert(sizeof(DNA_VALBIND_CTX) - 1 == DNA_VALBIND_CTX_LEN,
               "valbind ctx must be exactly 16 ASCII bytes");
_Static_assert(DNA_VALBIND_CTX_LEN <= QGP_DSA87_CTX_MAX_BYTES,
               "valbind ctx exceeds the FIPS 204 ctx limit");
_Static_assert(DNA_VALBIND_OFF_CHAIN   == DNA_VALBIND_OFF_VERSION + 4,
               "consent layout drifted (chain)");
_Static_assert(DNA_VALBIND_OFF_OP      == DNA_VALBIND_OFF_CHAIN +
                                          DNA_VALBIND_CHAIN_LEN,
               "consent layout drifted (op)");
_Static_assert(DNA_VALBIND_OFF_SUBJECT == DNA_VALBIND_OFF_OP + 1,
               "consent layout drifted (subject)");
_Static_assert(DNA_VALBIND_OFF_OWNER   == DNA_VALBIND_OFF_SUBJECT +
                                          DNA_VALBIND_SUBJECT_LEN,
               "consent layout drifted (owner)");
_Static_assert(DNA_VALBIND_OFF_PUBKEY  == DNA_VALBIND_OFF_OWNER +
                                          DNA_VALBIND_OWNER_FP_LEN,
               "consent layout drifted (pubkey)");
_Static_assert(DNA_VALBIND_OFF_EXPIRY  == DNA_VALBIND_OFF_PUBKEY +
                                          DNA_VALBIND_PUBKEY_LEN,
               "consent layout drifted (expiry)");
_Static_assert(DNA_VALBIND_MSG_LEN     == DNA_VALBIND_OFF_EXPIRY + 8,
               "consent layout drifted (total)");
_Static_assert(DNA_VALBIND_MSG_LEN == 2765,
               "consent message length drifted (design §6.1)");
_Static_assert(DNA_VALBIND_PUBKEY_LEN == QGP_DSA87_PUBLICKEYBYTES,
               "consensus_pk is not an ML-DSA-87 public key");
_Static_assert(DNA_VALBIND_SECKEY_LEN == QGP_DSA87_SECRETKEYBYTES,
               "secret key is not an ML-DSA-87 secret key");
_Static_assert(DNA_VALBIND_SIG_LEN == QGP_DSA87_SIGNATURE_BYTES,
               "signature is not an ML-DSA-87 signature");
_Static_assert(DNA_VALBIND_ID_PREIMAGE_LEN ==
                   DNA_VALBIND_TAG_LEN + DNA_VALBIND_CHAIN_LEN + 64,
               "validator_id preimage drifted");
_Static_assert(DNA_VALBIND_ID_PREIMAGE_LEN == 112,
               "validator_id preimage length drifted (design §6.2)");
_Static_assert(DNA_VALBIND_ID_LEN == QGP_SHA3_512_DIGEST_LENGTH &&
                   DNA_VALBIND_INTENT_ID_LEN == QGP_SHA3_512_DIGEST_LENGTH,
               "validator_id / intent_id are SHA3-512 digests");

/* ── Fixed-width big-endian helpers ─────────────────────────────────── */

static void put_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != 0) return 0;
    return 1;
}

/* ── Consent ────────────────────────────────────────────────────────── */

int dna_valbind_consent_msg(uint8_t out[DNA_VALBIND_MSG_LEN],
                            const uint8_t chain32[DNA_VALBIND_CHAIN_LEN],
                            uint8_t op,
                            const uint8_t subject[DNA_VALBIND_SUBJECT_LEN],
                            const uint8_t owner_fp[DNA_VALBIND_OWNER_FP_LEN],
                            const uint8_t consensus_pk[DNA_VALBIND_PUBKEY_LEN],
                            uint64_t expiry_height) {
    if (!out || !chain32 || !subject || !owner_fp || !consensus_pk)
        return -1;

    /* Every rule runs BEFORE the first byte of `out` is written. */
    const int zero_subject = all_zero(subject, DNA_VALBIND_SUBJECT_LEN);
    if (op == DNA_VALBIND_OP_STAKE ||
        op == DNA_VALBIND_OP_STORAGE_REGISTER) {
        if (!zero_subject) return -1;   /* STAKE / STORAGE_REGISTER subject
                                         * is 64 × 0x00 (§6.1, §11.3) */
    } else if (op == DNA_VALBIND_OP_ROTATE) {
        if (zero_subject) return -1;    /* ROTATE names a validator_id */
    } else {
        return -1;
    }

    put_be32(DNA_VALBIND_VERSION, out + DNA_VALBIND_OFF_VERSION);
    memcpy(out + DNA_VALBIND_OFF_CHAIN, chain32, DNA_VALBIND_CHAIN_LEN);
    out[DNA_VALBIND_OFF_OP] = op;
    memcpy(out + DNA_VALBIND_OFF_SUBJECT, subject, DNA_VALBIND_SUBJECT_LEN);
    memcpy(out + DNA_VALBIND_OFF_OWNER, owner_fp, DNA_VALBIND_OWNER_FP_LEN);
    memcpy(out + DNA_VALBIND_OFF_PUBKEY, consensus_pk, DNA_VALBIND_PUBKEY_LEN);
    put_be64(expiry_height, out + DNA_VALBIND_OFF_EXPIRY);
    return 0;
}

int dna_valbind_expiry_ok(uint64_t h, uint64_t expiry) {
    /* expiry >= h first, so the subtraction never wraps; h + 720 is never
     * formed (it would wrap near UINT64_MAX). */
    if (expiry < h) return 0;
    return (expiry - h) <= DNA_VALBIND_MAX_EXPIRY_BLOCKS ? 1 : 0;
}

/**
 * The structural rules dna_valbind_consent_msg enforces, re-applied to a
 * received 2765-byte message: version == 1, op ∈ {STAKE, ROTATE,
 * STORAGE_REGISTER}, STAKE / STORAGE_REGISTER subject all-zero, ROTATE
 * subject not all-zero.
 * @return 0 if well-formed, -1 otherwise.
 */
static int consent_parse_ok(const uint8_t msg[DNA_VALBIND_MSG_LEN]) {
    const uint32_t version =
        ((uint32_t)msg[DNA_VALBIND_OFF_VERSION + 0] << 24) |
        ((uint32_t)msg[DNA_VALBIND_OFF_VERSION + 1] << 16) |
        ((uint32_t)msg[DNA_VALBIND_OFF_VERSION + 2] << 8)  |
         (uint32_t)msg[DNA_VALBIND_OFF_VERSION + 3];
    if (version != DNA_VALBIND_VERSION) return -1;

    const uint8_t op = msg[DNA_VALBIND_OFF_OP];
    const int zero_subject =
        all_zero(msg + DNA_VALBIND_OFF_SUBJECT, DNA_VALBIND_SUBJECT_LEN);
    if (op == DNA_VALBIND_OP_STAKE)  return zero_subject ? 0 : -1;
    if (op == DNA_VALBIND_OP_STORAGE_REGISTER)
                                     return zero_subject ? 0 : -1;
    if (op == DNA_VALBIND_OP_ROTATE) return zero_subject ? -1 : 0;
    return -1;
}

int dna_valbind_consent_sign(uint8_t sig[DNA_VALBIND_SIG_LEN], size_t *siglen,
                             const uint8_t msg[DNA_VALBIND_MSG_LEN],
                             const uint8_t sk[DNA_VALBIND_SECKEY_LEN]) {
    if (!sig || !siglen || !msg || !sk) return -1;
    if (consent_parse_ok(msg) != 0) return -1;   /* never sign a malformed one */
    size_t len = 0;
    if (qgp_dsa87_sign_ctx(sig, &len, msg, DNA_VALBIND_MSG_LEN,
                           (const uint8_t *)DNA_VALBIND_CTX,
                           DNA_VALBIND_CTX_LEN, sk) != 0)
        return -1;
    *siglen = len;
    return 0;
}

int dna_valbind_consent_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t msg[DNA_VALBIND_MSG_LEN]) {
    if (!sig || !msg) return -1;
    if (consent_parse_ok(msg) != 0) return -1;
    /* Signer binding (design §6.1): the consenting key IS the embedded
     * consensus_pk — there is no caller-supplied key to substitute. */
    return qgp_dsa87_verify_ctx(sig, siglen, msg, DNA_VALBIND_MSG_LEN,
                                (const uint8_t *)DNA_VALBIND_CTX,
                                DNA_VALBIND_CTX_LEN,
                                msg + DNA_VALBIND_OFF_PUBKEY) == 0 ? 0 : -1;
}

/* ── validator_id ───────────────────────────────────────────────────── */

/** SHA3-512(tag ‖ chain32 ‖ tail64) over the 112-byte preimage. */
static int valbind_id(uint8_t out[DNA_VALBIND_ID_LEN],
                      const uint8_t tag[DNA_VALBIND_TAG_LEN],
                      const uint8_t chain32[DNA_VALBIND_CHAIN_LEN],
                      const uint8_t tail[64]) {
    uint8_t pre[DNA_VALBIND_ID_PREIMAGE_LEN];
    uint8_t h[DNA_VALBIND_ID_LEN];
    memcpy(pre, tag, DNA_VALBIND_TAG_LEN);
    memcpy(pre + DNA_VALBIND_TAG_LEN, chain32, DNA_VALBIND_CHAIN_LEN);
    memcpy(pre + DNA_VALBIND_TAG_LEN + DNA_VALBIND_CHAIN_LEN, tail, 64);
    if (qgp_sha3_512(pre, sizeof(pre), h) != 0) return -1;
    memcpy(out, h, DNA_VALBIND_ID_LEN);   /* no partial output on failure */
    return 0;
}

int dna_validator_id_new(uint8_t out[DNA_VALBIND_ID_LEN],
                         const uint8_t chain32[DNA_VALBIND_CHAIN_LEN],
                         const uint8_t intent_id[DNA_VALBIND_INTENT_ID_LEN]) {
    if (!out || !chain32 || !intent_id) return -1;
    return valbind_id(out, TAG_VALID, chain32, intent_id);
}

int dna_validator_id_migrated(uint8_t out[DNA_VALBIND_ID_LEN],
                              const uint8_t chain32[DNA_VALBIND_CHAIN_LEN],
                              const uint8_t old_pubkey[DNA_VALBIND_PUBKEY_LEN]) {
    if (!out || !chain32 || !old_pubkey) return -1;
    uint8_t pkh[QGP_SHA3_512_DIGEST_LENGTH];
    if (qgp_sha3_512(old_pubkey, DNA_VALBIND_PUBKEY_LEN, pkh) != 0) return -1;
    return valbind_id(out, TAG_VALMIG, chain32, pkh);
}
