/**
 * @file shared/dnac/qc_v2.c
 * @brief Ledger V2 Season 3 — QC V2 codec + historical verification.
 *
 * INACTIVE: no consensus path calls anything here. The legacy 144-byte
 * cert path (nodus/src/witness/nodus_witness_cert.{h,c}) stays live and
 * byte-identical. See qc_v2.h for the tag, preimage and wire layout.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "qc_v2.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/sign/qgp_dilithium.h"

/* Tag is EXACTLY 16 bytes, zero-padded ASCII. */
static const uint8_t TAG_CERT_V2[DNA_CERT_V2_TAG_LEN] = "DNA.CERT.v2\0\0\0\0";

/* Preimage arithmetic is pinned, not assumed. */
_Static_assert(DNA_CERT_V2_PREIMAGE_LEN ==
                   DNA_CERT_V2_TAG_LEN + DNA_CERT_V2_BLOCK_ID_LEN +
                   DNA_CERT_V2_VOTER_ID_LEN + 8 + DNA_CHAIN_ID_LEN +
                   DNA_CERT_V2_VSET_HASH_LEN,
               "QC V2 preimage layout drifted from 216 bytes");
_Static_assert(DNA_QC_V2_CERT_LEN == 4659, "QC V2 cert record drifted");
_Static_assert(DNA_QC_V2_MAX_ENC_LEN == 2 + 128 * 4659,
               "QC V2 max encoding drifted");
/* The signature width must match the primitive we verify with. */
_Static_assert(DNA_CERT_V2_SIG_LEN == QGP_DSA87_SIGNATURE_BYTES,
               "QC V2 signature width != Dilithium5 signature width");
_Static_assert(DNA_VSET_PUBKEY_LEN == QGP_DSA87_PUBLICKEYBYTES,
               "snapshot pubkey width != Dilithium5 public key width");

/* ── Fixed-width big-endian helpers ─────────────────────────────────── */

static void put_be16(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint16_t get_be16(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

/* ── Preimage ───────────────────────────────────────────────────────── */

int dna_cert_v2_preimage(const uint8_t block_id[DNA_CERT_V2_BLOCK_ID_LEN],
                         const uint8_t voter_id[DNA_CERT_V2_VOTER_ID_LEN],
                         uint64_t height,
                         const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                         const uint8_t vset_hash[DNA_CERT_V2_VSET_HASH_LEN],
                         uint8_t out[DNA_CERT_V2_PREIMAGE_LEN]) {
    if (!block_id || !voter_id || !chain_id || !vset_hash || !out) return -1;

    uint8_t *p = out;
    memcpy(p, TAG_CERT_V2, DNA_CERT_V2_TAG_LEN); p += DNA_CERT_V2_TAG_LEN;
    memcpy(p, block_id, DNA_CERT_V2_BLOCK_ID_LEN);
    p += DNA_CERT_V2_BLOCK_ID_LEN;
    memcpy(p, voter_id, DNA_CERT_V2_VOTER_ID_LEN);
    p += DNA_CERT_V2_VOTER_ID_LEN;
    put_be64(height, p); p += 8;
    memcpy(p, chain_id, DNA_CHAIN_ID_LEN); p += DNA_CHAIN_ID_LEN;
    memcpy(p, vset_hash, DNA_CERT_V2_VSET_HASH_LEN);
    p += DNA_CERT_V2_VSET_HASH_LEN;

    if ((size_t)(p - out) != (size_t)DNA_CERT_V2_PREIMAGE_LEN) return -1;
    return 0;
}

/* ── Structural validation (shared by encode, decode and verify) ────── */

/**
 * Strictly ascending voter_id. "Strictly" is load-bearing: equal
 * neighbours are the duplicate-signer case, so one predicate closes both
 * canonicality and double-counting.
 * @return 0 if valid, -1 otherwise.
 */
static int qc_check(const dna_qc_v2_t *qc) {
    if (!qc || !qc->certs) return -1;
    if (qc->n_certs == 0 || qc->n_certs > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    for (size_t i = 1; i < (size_t)qc->n_certs; i++) {
        if (memcmp(qc->certs[i - 1].voter_id, qc->certs[i].voter_id,
                   DNA_CERT_V2_VOTER_ID_LEN) >= 0)
            return -1;
    }
    return 0;
}

/* ── Lifecycle ──────────────────────────────────────────────────────── */

dna_qc_v2_t *dna_qc_v2_alloc(uint16_t n_certs) {
    if (n_certs == 0 || n_certs > DNA_MAX_ACTIVE_VALIDATORS) return NULL;
    dna_qc_v2_t *qc = calloc(1, sizeof(*qc));
    if (!qc) return NULL;
    qc->certs = calloc((size_t)n_certs, sizeof(*qc->certs));
    if (!qc->certs) { free(qc); return NULL; }
    qc->n_certs = n_certs;
    return qc;
}

void dna_qc_v2_free(dna_qc_v2_t **qc) {
    if (!qc || !*qc) return;
    free((*qc)->certs);
    free(*qc);
    *qc = NULL;
}

/* ── Codec ──────────────────────────────────────────────────────────── */

size_t dna_qc_v2_encoded_len(const dna_qc_v2_t *qc) {
    if (qc_check(qc) != 0) return 0;
    /* n_certs <= 128 ⇒ bounded by DNA_QC_V2_MAX_ENC_LEN, no overflow. */
    return (size_t)DNA_QC_V2_HDR_LEN +
           (size_t)qc->n_certs * (size_t)DNA_QC_V2_CERT_LEN;
}

int dna_qc_v2_encode(const dna_qc_v2_t *qc,
                     uint8_t *dst, size_t cap, size_t *written) {
    if (!dst) return -1;
    size_t need = dna_qc_v2_encoded_len(qc);   /* 0 == structurally bad */
    if (need == 0 || cap < need) return -1;

    uint8_t *p = dst;
    put_be16(qc->n_certs, p); p += DNA_QC_V2_HDR_LEN;
    for (size_t i = 0; i < (size_t)qc->n_certs; i++) {
        memcpy(p, qc->certs[i].voter_id, DNA_CERT_V2_VOTER_ID_LEN);
        p += DNA_CERT_V2_VOTER_ID_LEN;
        memcpy(p, qc->certs[i].sig, DNA_CERT_V2_SIG_LEN);
        p += DNA_CERT_V2_SIG_LEN;
    }

    if ((size_t)(p - dst) != need) return -1;   /* layout drift guard */
    if (written) *written = need;
    return 0;
}

int dna_qc_v2_decode(const uint8_t *src, size_t len, dna_qc_v2_t **out) {
    if (!src || !out) return -1;

    /* Bounds + exact length BEFORE allocation. */
    if (len < (size_t)DNA_QC_V2_HDR_LEN) return -1;
    uint16_t n = get_be16(src);
    if (n == 0 || n > DNA_MAX_ACTIVE_VALIDATORS) return -1;

    size_t need = (size_t)DNA_QC_V2_HDR_LEN +
                  (size_t)n * (size_t)DNA_QC_V2_CERT_LEN;
    if (len != need) return -1;   /* truncation AND trailing bytes reject */

    dna_qc_v2_t *qc = dna_qc_v2_alloc(n);
    if (!qc) return -1;

    const uint8_t *p = src + DNA_QC_V2_HDR_LEN;
    for (size_t i = 0; i < (size_t)n; i++) {
        memcpy(qc->certs[i].voter_id, p, DNA_CERT_V2_VOTER_ID_LEN);
        p += DNA_CERT_V2_VOTER_ID_LEN;
        memcpy(qc->certs[i].sig, p, DNA_CERT_V2_SIG_LEN);
        p += DNA_CERT_V2_SIG_LEN;
    }

    if (qc_check(qc) != 0) {   /* unsorted or duplicate signer */
        dna_qc_v2_free(&qc);
        return -1;
    }
    *out = qc;
    return 0;
}

/* ── Verification ───────────────────────────────────────────────────── */

int dna_qc_v2_verify(const dna_qc_v2_t *qc,
                     const uint8_t block_id[DNA_CERT_V2_BLOCK_ID_LEN],
                     uint64_t height,
                     const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                     const uint8_t header_vset_hash[DNA_CERT_V2_VSET_HASH_LEN],
                     const dna_vset_snapshot_t *snapshot) {
    if (!qc || !block_id || !chain_id || !header_vset_hash || !snapshot)
        return -1;

    /* ── 1. The snapshot is trusted ONLY if it IS the committed set. ── */
    uint8_t computed[DNA_VSET_HASH_LEN];
    if (dna_vset_hash(snapshot, computed) != 0) return -1;
    if (memcmp(computed, header_vset_hash, DNA_VSET_HASH_LEN) != 0) return -1;

    /* ── 2. Quorum is derived from the SNAPSHOT's size, never from a
     *      compile-time committee constant. ── */
    uint16_t n_set = snapshot->active_count;
    if (n_set == 0 || n_set > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    uint32_t quorum = dna_bft_quorum((uint32_t)n_set);

    /* ── 3. Cert count band. ── */
    if ((uint32_t)qc->n_certs < quorum) return -1;
    if (qc->n_certs > n_set) return -1;

    /* ── 4. Strictly sorted + distinct (cheap; verify must not rely on
     *      having come through decode). ── */
    if (qc_check(qc) != 0) return -1;

    for (size_t i = 0; i < (size_t)qc->n_certs; i++) {
        const dna_qc_v2_cert_t *c = &qc->certs[i];

        /* ── 5. Membership: the signer must be IN the committed set. ── */
        const dna_vset_entry_t *member = NULL;
        for (size_t j = 0; j < (size_t)n_set; j++) {
            if (memcmp(snapshot->entries[j].voter_id, c->voter_id,
                       DNA_CERT_V2_VOTER_ID_LEN) == 0) {
                member = &snapshot->entries[j];
                break;
            }
        }
        if (!member) return -1;     /* non-member ⇒ reject the whole QC */

        /* ── 6. Signature over THIS cert's preimage, against the pubkey
         *      COMMITTED IN THE SNAPSHOT (never a live table lookup) —
         *      that is what makes historical verification key-rotation
         *      safe. Any failure rejects the whole QC. ── */
        uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
        if (dna_cert_v2_preimage(block_id, c->voter_id, height, chain_id,
                                 header_vset_hash, pre) != 0)
            return -1;
        if (qgp_dsa87_verify(c->sig, DNA_CERT_V2_SIG_LEN,
                             pre, DNA_CERT_V2_PREIMAGE_LEN,
                             member->pubkey) != 0)
            return -1;
    }

    /* Stake was never read: one validator = one vote. */
    return 0;
}
