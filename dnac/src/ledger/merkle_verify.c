/**
 * @file merkle_verify.c
 * @brief Client-side Merkle proof verification (RFC 6962, SHA3-512).
 *
 * See dnac/src/ledger/MERKLE_DIRECTION_CONVENTION.md for the exact
 * direction-bit semantics shared with nodus_witness_merkle.c. The
 * convention is LOCKED and must not drift — if this verifier ever
 * disagrees with the server-side build_proof on a single bit, every
 * anchored proof in the chain fails silently.
 *
 * RFC 6962 domain tags:
 *   leaf_hash(data)    = SHA3-512(0x00 || data)
 *   inner_hash(L, R)   = SHA3-512(0x01 || L || R)
 *
 * Direction convention (server ↔ client):
 *   proof->directions[i] == 1  →  sibling LEFT  →  parent = inner_hash(sibling, cur)
 *   proof->directions[i] == 0  →  sibling RIGHT →  parent = inner_hash(cur, sibling)
 */

#include "dnac/ledger.h"

#include <openssl/evp.h>
#include <string.h>
#include <stdbool.h>

/**
 * Tagged SHA3-512 helper — concatenates tag || a || b and returns the digest.
 * `a` and `b` may be NULL/0 for the leaf case (single-input hash).
 */
static int sha3_512_tagged(uint8_t tag,
                            const uint8_t *a, size_t alen,
                            const uint8_t *b, size_t blen,
                            uint8_t out[DNAC_MERKLE_ROOT_SIZE]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;

    int ok =
        (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1) &&
        (EVP_DigestUpdate(md, &tag, 1) == 1) &&
        (alen == 0 || EVP_DigestUpdate(md, a, alen) == 1) &&
        (blen == 0 || EVP_DigestUpdate(md, b, blen) == 1);

    unsigned int hash_len = 0;
    if (ok) {
        ok = (EVP_DigestFinal_ex(md, out, &hash_len) == 1) &&
             (hash_len == DNAC_MERKLE_ROOT_SIZE);
    }

    EVP_MD_CTX_free(md);
    return ok ? 0 : -1;
}

bool dnac_merkle_verify_proof(const dnac_merkle_proof_t *proof) {
    if (!proof) return false;
    if (proof->proof_length < 0 ||
        proof->proof_length > DNAC_MERKLE_MAX_DEPTH) {
        return false;
    }

    /* Apply the RFC 6962 leaf tag (0x00) to the composite digest. The
     * composite digest is whatever the server's build_proof passed as
     * `target_leaf` — for UTXOs, the output of merkle_leaf_hash. */
    uint8_t cur[DNAC_MERKLE_ROOT_SIZE];
    if (sha3_512_tagged(0x00,
                         proof->leaf_hash, DNAC_MERKLE_ROOT_SIZE,
                         NULL, 0,
                         cur) != 0) {
        return false;
    }

    /* Walk leaf → root, applying inner_hash(0x01 || L || R) with
     * direction-aware ordering at each level. */
    for (int i = 0; i < proof->proof_length; i++) {
        const uint8_t *sib = proof->siblings[i];
        uint8_t parent[DNAC_MERKLE_ROOT_SIZE];
        int rc;

        if (proof->directions[i] == 1) {
            /* Sibling on LEFT, current on RIGHT */
            rc = sha3_512_tagged(0x01,
                                  sib, DNAC_MERKLE_ROOT_SIZE,
                                  cur, DNAC_MERKLE_ROOT_SIZE,
                                  parent);
        } else {
            /* Sibling on RIGHT, current on LEFT */
            rc = sha3_512_tagged(0x01,
                                  cur, DNAC_MERKLE_ROOT_SIZE,
                                  sib, DNAC_MERKLE_ROOT_SIZE,
                                  parent);
        }

        if (rc != 0) return false;
        memcpy(cur, parent, DNAC_MERKLE_ROOT_SIZE);
    }

    /* Constant-time comparison not strictly required here (proofs are
     * public data), but memcmp is fine for correctness. */
    return memcmp(cur, proof->root, DNAC_MERKLE_ROOT_SIZE) == 0;
}

/* ============================================================================
 * UTXO composite leaf hash
 *
 * Byte-for-byte mirror of nodus_witness_merkle_leaf_hash in
 * nodus/src/witness/nodus_witness_merkle.c. Drift here silently breaks
 * every anchored UTXO proof — do not "refactor" the field layout without
 * updating both sides in lockstep and re-running test_anchored_proofs.
 * ========================================================================== */

int dnac_utxo_compute_leaf_hash(const uint8_t *nullifier,
                                 const char *owner,
                                 uint64_t amount,
                                 const uint8_t *token_id,
                                 const uint8_t *tx_hash,
                                 uint32_t output_index,
                                 uint8_t out[DNAC_MERKLE_ROOT_SIZE]) {
    if (!nullifier || !owner || !token_id || !tx_hash || !out) return -1;

    /* Owner is a NUL-terminated 128-char hex fingerprint. Server hashes
     * exactly 128 bytes with zero-padding — match that exactly. */
    size_t owner_len = strlen(owner);
    if (owner_len > 128) owner_len = 128;

    uint8_t owner_buf[128];
    memset(owner_buf, 0, sizeof(owner_buf));
    memcpy(owner_buf, owner, owner_len);

    /* Little-endian scalar encodings (must match enc_u64_le / enc_u32_le
     * in nodus witness). */
    uint8_t amount_le[8];
    for (int i = 0; i < 8; i++) {
        amount_le[i] = (uint8_t)((amount >> (8 * i)) & 0xFF);
    }
    uint8_t oi_le[4];
    for (int i = 0; i < 4; i++) {
        oi_le[i] = (uint8_t)((output_index >> (8 * i)) & 0xFF);
    }

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;

    int ok =
        (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1) &&
        (EVP_DigestUpdate(md, nullifier, 64) == 1) &&
        (EVP_DigestUpdate(md, owner_buf, 128) == 1) &&
        (EVP_DigestUpdate(md, amount_le, 8) == 1) &&
        (EVP_DigestUpdate(md, token_id, 64) == 1) &&
        (EVP_DigestUpdate(md, tx_hash, 64) == 1) &&
        (EVP_DigestUpdate(md, oi_le, 4) == 1);

    unsigned int hash_len = 0;
    if (ok) {
        ok = (EVP_DigestFinal_ex(md, out, &hash_len) == 1) &&
             (hash_len == DNAC_MERKLE_ROOT_SIZE);
    }

    EVP_MD_CTX_free(md);
    return ok ? 0 : -1;
}
