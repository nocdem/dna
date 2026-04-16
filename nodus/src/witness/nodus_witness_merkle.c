/**
 * Nodus — Witness Merkle Tree Implementation
 *
 * See nodus_witness_merkle.h for design and determinism rules.
 *
 * @file nodus_witness_merkle.c
 */

#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_db.h"
#include "nodus/nodus_types.h"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "MERKLE"

/* ── Little-endian encoders (endianness-independent) ───────────────── */

static void enc_u32_le(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v & 0xff);
    out[1] = (uint8_t)((v >> 8) & 0xff);
    out[2] = (uint8_t)((v >> 16) & 0xff);
    out[3] = (uint8_t)((v >> 24) & 0xff);
}

static void enc_u64_le(uint64_t v, uint8_t out[8]) {
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)((v >> (i * 8)) & 0xff);
}

/* ── SHA3-512 helpers ──────────────────────────────────────────────── */

static int sha3_512_init(EVP_MD_CTX **md_out) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md) return -1;
    if (EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    *md_out = md;
    return 0;
}

static int sha3_512_final(EVP_MD_CTX *md, uint8_t out[64]) {
    unsigned int hash_len = 0;
    int ok = EVP_DigestFinal_ex(md, out, &hash_len);
    EVP_MD_CTX_free(md);
    return (ok == 1 && hash_len == 64) ? 0 : -1;
}

/* The legacy untagged sha3_512_pair() helper was removed by Phase 2 /
 * Task 2.6. All Merkle paths (root, build_proof, verify_proof) now go
 * through inner_hash() which prepends the 0x01 RFC 6962 internal-node
 * domain tag. */

/* ── RFC 6962 domain-tagged primitives (Phase 2 / Tasks 2.1, 2.2) ──
 *
 * RFC 6962 §2.1 requires every Merkle node to carry a 1-byte domain tag
 * so leaves and internal nodes hash to disjoint preimages, closing
 * CVE-2012-2459 (a tree of {A,B,C} and a tree of {A,B,C,C} produced
 * the same root under the legacy duplicate-odd-sibling rule because
 * leaves and pairs were indistinguishable).
 *
 *   leaf_hash(d)        = SHA-512(0x00 || d)
 *   inner_hash(L, R)    = SHA-512(0x01 || L || R)
 *
 * These are static helpers — the public wrapper merkle_tx_root applies
 * leaf_hash to its inputs before passing them to merkle_root_rfc6962.
 */

static int leaf_hash(const uint8_t *data, size_t len, uint8_t out[64]) {
    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) return -1;
    const uint8_t prefix = 0x00;
    if (EVP_DigestUpdate(md, &prefix, 1) != 1 ||
        (len > 0 && EVP_DigestUpdate(md, data, len) != 1)) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    return sha3_512_final(md, out);
}

static int inner_hash(const uint8_t L[64], const uint8_t R[64], uint8_t out[64]) {
    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) return -1;
    const uint8_t prefix = 0x01;
    if (EVP_DigestUpdate(md, &prefix, 1) != 1 ||
        EVP_DigestUpdate(md, L, 64) != 1 ||
        EVP_DigestUpdate(md, R, 64) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    return sha3_512_final(md, out);
}

/* RFC 6962 §2.1 Merkle root recursion.
 *
 *   MTH({})       = leaf_hash("")          -- empty tree
 *   MTH({d0})     = leaves[0]              -- caller pre-applies leaf_hash
 *   MTH(D[0..n]) = inner_hash( MTH(D[0..k]), MTH(D[k..n]) )
 *
 * with k = largest power of 2 strictly less than n.
 *
 * Contract: the `leaves` buffer holds n already-hashed leaves of 64
 * bytes each. The caller (merkle_tx_root) is responsible for applying
 * leaf_hash() to raw inputs first. The buffer is read-only here.
 */
static int merkle_root_rfc6962(const uint8_t *leaves, size_t n, uint8_t out[64]) {
    if (n == 0) {
        return leaf_hash(NULL, 0, out);
    }
    if (n == 1) {
        memcpy(out, leaves, 64);
        return 0;
    }

    size_t k = 1;
    while (k * 2 < n) k *= 2;

    uint8_t left[64];
    uint8_t right[64];
    if (merkle_root_rfc6962(leaves, k, left) != 0) return -1;
    if (merkle_root_rfc6962(leaves + k * 64, n - k, right) != 0) return -1;
    return inner_hash(left, right, out);
}

/* ── Leaf hash ─────────────────────────────────────────────────────── */

int nodus_witness_merkle_leaf_hash(const uint8_t *nullifier,
                                     const char *owner,
                                     uint64_t amount,
                                     const uint8_t *token_id,
                                     const uint8_t *tx_hash,
                                     uint32_t output_index,
                                     uint8_t *leaf_out) {
    if (!nullifier || !owner || !token_id || !tx_hash || !leaf_out) return -1;

    /* Owner fingerprint is a null-terminated 128-char hex string. Hash
     * exactly 128 bytes so length is implicit in the preimage format.
     * Shorter owners are padded-hashed as stored (strncpy to 128). */
    size_t owner_len = strlen(owner);
    if (owner_len > 128) owner_len = 128;

    uint8_t owner_buf[128];
    memset(owner_buf, 0, sizeof(owner_buf));
    memcpy(owner_buf, owner, owner_len);

    uint8_t amount_le[8];
    enc_u64_le(amount, amount_le);
    uint8_t oi_le[4];
    enc_u32_le(output_index, oi_le);

    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) return -1;

    if (EVP_DigestUpdate(md, nullifier, 64) != 1 ||
        EVP_DigestUpdate(md, owner_buf, 128) != 1 ||
        EVP_DigestUpdate(md, amount_le, 8) != 1 ||
        EVP_DigestUpdate(md, token_id, 64) != 1 ||
        EVP_DigestUpdate(md, tx_hash, 64) != 1 ||
        EVP_DigestUpdate(md, oi_le, 4) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }

    return sha3_512_final(md, leaf_out);
}

/* ── Load all UTXO leaves into a sorted array ──────────────────────── */

/* Output: caller-owned heap buffer, leaves_out[i * 64] = leaf i.
 * Leaves are sorted by nullifier (enforced by ORDER BY in SQL). */
static int load_utxo_leaves(nodus_witness_t *w,
                            uint8_t **leaves_out,
                            size_t *count_out) {
    *leaves_out = NULL;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT nullifier, owner, amount, token_id, tx_hash, output_index "
        "FROM utxo_set ORDER BY nullifier ASC", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: utxo scan prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 64;
    size_t n = 0;
    uint8_t *buf = malloc(cap * 64);
    if (!buf) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n >= cap) {
            size_t new_cap = cap * 2;
            uint8_t *new_buf = realloc(buf, new_cap * 64);
            if (!new_buf) {
                free(buf);
                sqlite3_finalize(stmt);
                return -1;
            }
            buf = new_buf;
            cap = new_cap;
        }

        const uint8_t *nullifier = sqlite3_column_blob(stmt, 0);
        int nlen = sqlite3_column_bytes(stmt, 0);
        const char *owner = (const char *)sqlite3_column_text(stmt, 1);
        uint64_t amount = (uint64_t)sqlite3_column_int64(stmt, 2);
        const uint8_t *token_id = sqlite3_column_blob(stmt, 3);
        int tlen = sqlite3_column_bytes(stmt, 3);
        const uint8_t *tx_hash = sqlite3_column_blob(stmt, 4);
        int thlen = sqlite3_column_bytes(stmt, 4);
        uint32_t output_index = (uint32_t)sqlite3_column_int(stmt, 5);

        if (!nullifier || nlen != 64 ||
            !owner ||
            !token_id || tlen != 64 ||
            !tx_hash || thlen != 64) {
            fprintf(stderr, "%s: utxo row malformed, skipping\n", LOG_TAG);
            continue;
        }

        if (nodus_witness_merkle_leaf_hash(nullifier, owner, amount,
                                             token_id, tx_hash,
                                             output_index,
                                             buf + n * 64) != 0) {
            free(buf);
            sqlite3_finalize(stmt);
            return -1;
        }
        n++;
    }

    sqlite3_finalize(stmt);
    *leaves_out = buf;
    *count_out = n;
    return 0;
}

/* The legacy duplicate-odd-sibling reduce_to_root() and its helper
 * sha3_512_once() were removed by Phase 2 / Task 2.5. The new
 * compute_utxo_root pre-hashes leaves with leaf_hash() and reduces
 * through merkle_root_rfc6962 instead. */

/* ── Public: tx_root over a list of TX hashes (Phase 2 / Task 2.4) ──
 *
 * Applies the RFC 6962 leaf domain tag (0x00 prefix) to every input
 * before reducing through merkle_root_rfc6962. Caller passes raw TX
 * hashes; the wrapper does the leaf-hashing internally. CVE-2012-2459
 * is closed by domain separation — see test_merkle_domain_tags.c.
 *
 * Per-call stack budget for the prehash buffer is bounded by
 * NODUS_W_MAX_BLOCK_TXS (currently 10) * 64 = 640 bytes. Comfortable
 * even on a 16 KB embedded stack.
 */
int nodus_witness_merkle_tx_root(const uint8_t *tx_hashes, size_t n, uint8_t out[64]) {
    if (!out) return -1;
    if (n == 0) return merkle_root_rfc6962(NULL, 0, out);
    if (!tx_hashes) return -1;
    if (n > NODUS_W_MAX_BLOCK_TXS) return -1;

    uint8_t leaves[NODUS_W_MAX_BLOCK_TXS][64];
    for (size_t i = 0; i < n; i++) {
        if (leaf_hash(tx_hashes + i * 64, 64, leaves[i]) != 0) return -1;
    }
    return merkle_root_rfc6962((const uint8_t *)leaves, n, out);
}

/* ── Public: compute UTXO root (Phase 2 / Task 2.5) ────────────────
 *
 * Pipeline:
 *   1. SQL: load every UTXO row, build a 64-byte composite digest
 *      from (nullifier || owner || amount || token_id || tx_hash ||
 *      output_index) — this is the existing nodus_witness_merkle_leaf_hash.
 *   2. RFC 6962 leaf_hash: prepend 0x00 to every composite digest so
 *      leaves cannot collide with internal nodes (closes CVE-2012-2459
 *      for the UTXO Merkle as well as the TX Merkle).
 *   3. merkle_root_rfc6962: §2.1 recursion with k = largest pow2 < n.
 *
 * The double SHA3-512 application (composite digest, then leaf_hash
 * domain tag) is intentional. The first hash compresses the variable-
 * length UTXO tuple into a fixed 64 bytes; the second applies the RFC
 * 6962 domain tag.
 *
 * Replaces the legacy reduce_to_root(duplicate-odd-sibling) collapse.
 * The state_root VALUE produced by this function is bit-different
 * from the pre-Phase-2 root — that is intentional, the chain wipe
 * resets the state_root format. Phase 11 references this as the
 * v2.0 state_root.
 */
int nodus_witness_merkle_compute_utxo_root(nodus_witness_t *w,
                                             uint8_t *root_out) {
    if (!w || !w->db || !root_out) return -1;

    uint8_t *leaves = NULL;
    size_t n = 0;
    if (load_utxo_leaves(w, &leaves, &n) != 0) return -1;

    if (n == 0) {
        free(leaves);
        return merkle_root_rfc6962(NULL, 0, root_out);
    }

    /* Apply the leaf domain tag in place: leaves[i] = leaf_hash(leaves[i]).
     * load_utxo_leaves already wrote 64 bytes per leaf, so we hash that
     * 64-byte block with the 0x00 prefix and overwrite in place. */
    for (size_t i = 0; i < n; i++) {
        uint8_t prehashed[64];
        if (leaf_hash(leaves + i * 64, 64, prehashed) != 0) {
            free(leaves);
            return -1;
        }
        memcpy(leaves + i * 64, prehashed, 64);
    }

    int rc = merkle_root_rfc6962(leaves, n, root_out);
    free(leaves);
    return rc;
}

/* ── Proof generation (RFC 6962, Phase 2 / Task 2.6) ──────────────────
 *
 * The proof structure follows RFC 6962 §2.1.1: walk the recursive split
 * from root to leaf, recording the OPPOSITE subtree's root at every
 * level. The verifier walks the same path bottom-up, combining current
 * with each sibling via inner_hash.
 *
 * Position bit i (LSB = leaf level): 1 means "sibling on the left, we
 * are right", 0 means "sibling on the right, we are left". The bit
 * order matches verify_proof.
 */

/* Recursive helper: walks the RFC 6962 split for `idx` in `leaves[0..n]`,
 * appending one sibling per level to siblings_out and one bit per level
 * to *positions_out. Depth grows as we recurse INTO a subtree; the leaf
 * level is the deepest call. We collect siblings on the way IN so that
 * the verifier (which walks bottom-up) sees them in the right order.
 *
 * Returns 0 on success. The caller must zero *depth_out / *positions_out
 * before the first call.
 */
static int rfc6962_path(const uint8_t *leaves, size_t n, size_t idx,
                         uint8_t *siblings_out, uint32_t *positions_out,
                         int *depth_out, int max_depth) {
    if (n <= 1) return 0;  /* leaf level — nothing to record */

    if (*depth_out >= max_depth) return -1;

    size_t k = 1;
    while (k * 2 < n) k *= 2;

    /* The current level's split point is k. The opposite subtree is the
     * sibling for THIS level. We record it as MTH of that subtree. */
    uint8_t sibling[64];
    int sibling_is_left;
    int rc;

    if (idx < k) {
        /* Target is in the left subtree; sibling = MTH(leaves[k..n]). */
        rc = merkle_root_rfc6962(leaves + k * 64, n - k, sibling);
        sibling_is_left = 0;
    } else {
        /* Target is in the right subtree; sibling = MTH(leaves[0..k]). */
        rc = merkle_root_rfc6962(leaves, k, sibling);
        sibling_is_left = 1;
    }
    if (rc != 0) return -1;

    int level = *depth_out;
    memcpy(siblings_out + level * 64, sibling, 64);
    if (sibling_is_left) *positions_out |= (1u << level);
    (*depth_out)++;

    /* Recurse into the subtree containing the target. */
    if (idx < k) {
        return rfc6962_path(leaves, k, idx,
                            siblings_out, positions_out, depth_out, max_depth);
    } else {
        return rfc6962_path(leaves + k * 64, n - k, idx - k,
                            siblings_out, positions_out, depth_out, max_depth);
    }
}

/* The position bits collected by rfc6962_path are root-to-leaf, but
 * verify_proof walks leaf-to-root, so we reverse the bit order before
 * returning. Same for the sibling array. */
static void reverse_proof(uint8_t *siblings, uint32_t *positions, int depth) {
    /* Reverse sibling array in place */
    for (int i = 0, j = depth - 1; i < j; i++, j--) {
        uint8_t tmp[64];
        memcpy(tmp, siblings + i * 64, 64);
        memcpy(siblings + i * 64, siblings + j * 64, 64);
        memcpy(siblings + j * 64, tmp, 64);
    }
    /* Reverse the bit field across `depth` bits */
    uint32_t in = *positions;
    uint32_t out = 0;
    for (int i = 0; i < depth; i++) {
        if (in & (1u << i)) out |= (1u << (depth - 1 - i));
    }
    *positions = out;
}

int nodus_witness_merkle_build_proof(nodus_witness_t *w,
                                       const uint8_t *target_leaf,
                                       uint8_t *siblings_out,
                                       uint32_t *positions_out,
                                       int max_depth,
                                       int *depth_out,
                                       uint8_t *root_out) {
    if (!w || !w->db || !target_leaf || !siblings_out || !positions_out ||
        !depth_out || max_depth <= 0) return -1;

    *depth_out = 0;
    *positions_out = 0;

    /* Caller's target_leaf is the 64-byte composite digest produced by
     * nodus_witness_merkle_leaf_hash (UTXO row → digest). build_proof
     * leaf-hashes that digest internally to match the prehash compute_root
     * applies in Task 2.5. */
    uint8_t target_prehashed[64];
    if (leaf_hash(target_leaf, 64, target_prehashed) != 0) return -1;

    uint8_t *leaves = NULL;
    size_t n = 0;
    if (load_utxo_leaves(w, &leaves, &n) != 0) return -1;

    if (n == 0) {
        free(leaves);
        return -1; /* target cannot be in empty set */
    }

    /* Apply the leaf domain tag in place, then locate the target. */
    for (size_t i = 0; i < n; i++) {
        uint8_t prehashed[64];
        if (leaf_hash(leaves + i * 64, 64, prehashed) != 0) {
            free(leaves);
            return -1;
        }
        memcpy(leaves + i * 64, prehashed, 64);
    }

    ssize_t target_idx = -1;
    for (size_t i = 0; i < n; i++) {
        if (memcmp(leaves + i * 64, target_prehashed, 64) == 0) {
            target_idx = (ssize_t)i;
            break;
        }
    }
    if (target_idx < 0) {
        free(leaves);
        return -1;
    }

    /* Single-leaf tree: empty proof, root == leaf. */
    if (n == 1) {
        if (root_out) memcpy(root_out, leaves, 64);
        free(leaves);
        return 0;
    }

    if (rfc6962_path(leaves, n, (size_t)target_idx,
                      siblings_out, positions_out, depth_out, max_depth) != 0) {
        free(leaves);
        return -1;
    }

    /* rfc6962_path collects root-to-leaf; flip to leaf-to-root for the
     * verifier. */
    reverse_proof(siblings_out, positions_out, *depth_out);

    if (root_out) {
        if (merkle_root_rfc6962(leaves, n, root_out) != 0) {
            free(leaves);
            return -1;
        }
    }

    free(leaves);
    return 0;
}

/* ── Public: build inclusion proof for a TX in a block's tx_root ─────
 *
 * Symmetric to nodus_witness_merkle_build_proof but scoped to a single
 * block's tx_root tree. Fetches committed TX hashes for block_height
 * in commit order (tx_index ASC) — mirrors the ordering used by
 * nodus_witness_block_txs_get() and therefore by tx_root computation.
 * Applies the RFC 6962 leaf domain tag (0x00 prefix) to each raw
 * tx_hash, locates target_tx_hash, and drives the same rfc6962_path
 * recursion used for UTXO inclusion proofs.
 */
int nodus_witness_merkle_build_tx_proof(nodus_witness_t *w,
                                          uint64_t block_height,
                                          const uint8_t *target_tx_hash,
                                          uint8_t *siblings_out,
                                          uint32_t *positions_out,
                                          int max_depth,
                                          int *depth_out,
                                          uint8_t *root_out) {
    if (!w || !w->db || !target_tx_hash || !siblings_out || !positions_out ||
        !depth_out || max_depth <= 0) return -1;

    *depth_out = 0;
    *positions_out = 0;

    /* Load raw tx_hashes for the block in commit order. Cap at
     * NODUS_W_MAX_BLOCK_TXS so the leaves stack buffer stays bounded
     * (10 * 64 = 640 bytes). */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT tx_hash FROM committed_transactions "
        "WHERE block_height = ? "
        "ORDER BY tx_index ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: build_tx_proof prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)block_height);

    uint8_t leaves[NODUS_W_MAX_BLOCK_TXS][64];
    size_t n = 0;
    ssize_t target_idx = -1;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n >= NODUS_W_MAX_BLOCK_TXS) {
            sqlite3_finalize(stmt);
            return -1; /* block exceeds per-block cap */
        }
        const void *hash_blob = sqlite3_column_blob(stmt, 0);
        int hash_len = sqlite3_column_bytes(stmt, 0);
        if (!hash_blob || hash_len != 64) continue;

        /* Match target against the raw tx_hash BEFORE leaf-tagging so
         * the caller-provided hash is compared in its natural form. */
        if (target_idx < 0 &&
            memcmp(hash_blob, target_tx_hash, 64) == 0) {
            target_idx = (ssize_t)n;
        }

        if (leaf_hash((const uint8_t *)hash_blob, 64, leaves[n]) != 0) {
            sqlite3_finalize(stmt);
            return -1;
        }
        n++;
    }
    sqlite3_finalize(stmt);

    if (n == 0 || target_idx < 0) return -1;

    /* Single-leaf tree: empty proof, root == the one leaf. */
    if (n == 1) {
        if (root_out) memcpy(root_out, leaves[0], 64);
        return 0;
    }

    if (rfc6962_path((const uint8_t *)leaves, n, (size_t)target_idx,
                      siblings_out, positions_out, depth_out, max_depth) != 0) {
        return -1;
    }

    /* rfc6962_path collects root-to-leaf; flip to leaf-to-root for the
     * verifier (same convention as nodus_witness_merkle_build_proof). */
    reverse_proof(siblings_out, positions_out, *depth_out);

    if (root_out) {
        if (merkle_root_rfc6962((const uint8_t *)leaves, n, root_out) != 0) {
            return -1;
        }
    }
    return 0;
}

/* ── Proof verification (pure function, RFC 6962) ───────────────────── */

int nodus_witness_merkle_verify_proof(const uint8_t *leaf,
                                        const uint8_t *siblings,
                                        uint32_t positions,
                                        int depth,
                                        const uint8_t *expected_root) {
    if (!leaf || !expected_root) return -1;
    if (depth < 0 || depth > NODUS_MERKLE_MAX_DEPTH) return -1;
    if (depth > 0 && !siblings) return -1;

    /* Caller passes the same composite-digest leaf that build_proof
     * received; verify_proof leaf-hashes it before walking. */
    uint8_t cur[64];
    if (leaf_hash(leaf, 64, cur) != 0) return -1;

    for (int i = 0; i < depth; i++) {
        const uint8_t *sib = siblings + i * 64;
        uint8_t parent[64];
        if (positions & (1u << i)) {
            /* Sibling on LEFT, cur on RIGHT — RFC 6962 inner_hash. */
            if (inner_hash(sib, cur, parent) != 0) return -1;
        } else {
            if (inner_hash(cur, sib, parent) != 0) return -1;
        }
        memcpy(cur, parent, 64);
    }

    return memcmp(cur, expected_root, 64) == 0 ? 0 : -1;
}
