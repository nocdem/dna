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
#include "nodus/nodus_chain_config.h"  /* Hard-Fork v1: chain_config_root in compute_state_root */
#include "crypto/utils/qgp_bench.h"    /* perf harness — ((void)0) in production */
#include "crypto/utils/qgp_log.h"      /* QGP_LOG_* (new code; legacy lines use fprintf) */

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

    /* rc carries the step result out of the loop — a mid-scan SQLITE_IOERR
     * / SQLITE_CORRUPT / SQLITE_FULL truncates the leaf set, and a
     * truncated leaf set is a silently divergent state_root (chain split
     * with no Byzantine actor). Same shape as
     * nodus_chain_config_compute_root (nodus_witness_chain_config.c:293). */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
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

        /* Fail close, never skip: two nodes holding different corrupt
         * rows would otherwise each drop a DIFFERENT leaf and report
         * success, producing two different state_roots from the same
         * chain. A malformed row is an unusable UTXO set, not a row to
         * step over. */
        if (!nullifier || nlen != 64 ||
            !owner ||
            !token_id || tlen != 64 ||
            !tx_hash || thlen != 64) {
            QGP_LOG_ERROR(LOG_TAG, "utxo row malformed (nlen=%d tlen=%d "
                          "thlen=%d owner=%s) — failing utxo leaf load",
                          nlen, tlen, thlen, owner ? "present" : "NULL");
            free(buf);
            sqlite3_finalize(stmt);
            return -1;
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

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "utxo scan step failed rc=%d — leaf set "
                      "truncated, refusing to report success", rc);
        free(buf);
        return -1;
    }

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

    /* rc carries the step result out of the loop — see load_utxo_leaves.
     * A truncated TX list yields a proof against a tx_root the block
     * never had. */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= NODUS_W_MAX_BLOCK_TXS) {
            sqlite3_finalize(stmt);
            return -1; /* block exceeds per-block cap */
        }
        /* Fail close, never skip. Skipping a row shifts every LATER leaf
         * down one index, so the proof would be built against a leaf
         * ordering the block never had — the emitted proof verifies
         * against nothing, or worse, against a tx_root a peer computed
         * from the intact table. Same class as the three loader fixes
         * above; committed_transactions.tx_hash is always written
         * full-length, so a short blob is corruption, not a legal state. */
        const void *hash_blob = sqlite3_column_blob(stmt, 0);
        int hash_len = sqlite3_column_bytes(stmt, 0);
        if (!hash_blob || hash_len != 64) {
            QGP_LOG_ERROR(LOG_TAG, "build_tx_proof: malformed tx_hash "
                          "(len=%d) at index %zu — refusing to build a proof "
                          "over a re-indexed leaf set", hash_len, n);
            sqlite3_finalize(stmt);
            return -1;
        }

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

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "build_tx_proof step failed rc=%d — TX list "
                      "truncated, refusing to build a proof", rc);
        return -1;
    }

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

/* ── Tree-tag domain-separated leaf helpers (witness stake v1) ──────
 *
 * Per §3.1 of the stake v1 design. Each helper is a 2-write stream
 * (tag byte, then payload) into a fresh SHA3-512 context. No heap
 * allocation, no logging. On OpenSSL failure the output buffer is
 * zeroed so a caller that ignores the (absent) return code cannot
 * silently consume uninitialised data.
 *
 * We use the module's existing EVP wrappers (sha3_512_init /
 * sha3_512_final) rather than the shared qgp_sha3 one-shot API so
 * the tag byte and payload can be hashed without an intermediate
 * concat buffer. This matches the style of leaf_hash / inner_hash
 * above.
 */

static void merkle_tag_hash_zero_on_fail(uint8_t out[64]) {
    memset(out, 0, 64);
}

void nodus_merkle_leaf_key(uint8_t tree_tag,
                           const uint8_t *raw_key, size_t raw_len,
                           uint8_t out_key[64]) {
    if (!out_key) return;
    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) {
        merkle_tag_hash_zero_on_fail(out_key);
        return;
    }
    if (EVP_DigestUpdate(md, &tree_tag, 1) != 1 ||
        (raw_len > 0 && raw_key != NULL &&
         EVP_DigestUpdate(md, raw_key, raw_len) != 1)) {
        EVP_MD_CTX_free(md);
        merkle_tag_hash_zero_on_fail(out_key);
        return;
    }
    if (sha3_512_final(md, out_key) != 0) {
        merkle_tag_hash_zero_on_fail(out_key);
    }
}

void nodus_merkle_leaf_value_hash(uint8_t tree_tag,
                                  const uint8_t *cbor, size_t cbor_len,
                                  uint8_t out_hash[64]) {
    if (!out_hash) return;
    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) {
        merkle_tag_hash_zero_on_fail(out_hash);
        return;
    }
    if (EVP_DigestUpdate(md, &tree_tag, 1) != 1 ||
        (cbor_len > 0 && cbor != NULL &&
         EVP_DigestUpdate(md, cbor, cbor_len) != 1)) {
        EVP_MD_CTX_free(md);
        merkle_tag_hash_zero_on_fail(out_hash);
        return;
    }
    if (sha3_512_final(md, out_hash) != 0) {
        merkle_tag_hash_zero_on_fail(out_hash);
    }
}

/* Returns 0 / -1 (2026-07-31). The zero-fill on failure is kept so a
 * caller that drops the code still sees deterministic bytes, but those
 * bytes are a sentinel, not a root — every state_root-path caller now
 * propagates the -1. */
int nodus_merkle_empty_root(uint8_t tree_tag, uint8_t out_root[64]) {
    if (!out_root) return -1;
    const uint8_t zero = 0x00;
    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) {
        merkle_tag_hash_zero_on_fail(out_root);
        return -1;
    }
    if (EVP_DigestUpdate(md, &tree_tag, 1) != 1 ||
        EVP_DigestUpdate(md, &zero, 1) != 1) {
        EVP_MD_CTX_free(md);
        merkle_tag_hash_zero_on_fail(out_root);
        return -1;
    }
    if (sha3_512_final(md, out_root) != 0) {
        merkle_tag_hash_zero_on_fail(out_root);
        return -1;
    }
    return 0;
}

/* ── Composite state_root combiner — LEGACY 4-input (pre Hard-Fork v1) ──
 *
 * Retained for archive-replay / forensic reconstruction of pre-Hard-Fork-v1
 * chain histories only (Q3 / CC-OPS-007 mitigation). NOT called on the
 * live chain post-activation. Marked cold so the hot-path TLB/icache is
 * not polluted.
 *
 * state_root_v1 = SHA3-512(utxo_root || validator_root || delegation_root
 *                           || reward_root)
 */
__attribute__((cold))
void nodus_merkle_combine_state_root_v1_legacy(const uint8_t utxo_root[64],
                                                const uint8_t validator_root[64],
                                                const uint8_t delegation_root[64],
                                                const uint8_t reward_root[64],
                                                uint8_t out_state_root[64]) {
    if (!out_state_root) return;
    if (!utxo_root || !validator_root || !delegation_root || !reward_root) {
        merkle_tag_hash_zero_on_fail(out_state_root);
        return;
    }

    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) {
        merkle_tag_hash_zero_on_fail(out_state_root);
        return;
    }
    if (EVP_DigestUpdate(md, utxo_root,       64) != 1 ||
        EVP_DigestUpdate(md, validator_root,  64) != 1 ||
        EVP_DigestUpdate(md, delegation_root, 64) != 1 ||
        EVP_DigestUpdate(md, reward_root,     64) != 1) {
        EVP_MD_CTX_free(md);
        merkle_tag_hash_zero_on_fail(out_state_root);
        return;
    }
    if (sha3_512_final(md, out_state_root) != 0) {
        merkle_tag_hash_zero_on_fail(out_state_root);
    }
}

/* Source-compat alias so older callers / tests referring to the unversioned
 * name resolve to the legacy formula. New code MUST call the _v2 variant
 * below (prefixed with the NODUS_STATE_ROOT_VERSION_V1 version byte would
 * break the legacy byte-for-byte KAT, so the alias points at _v1_legacy). */
void nodus_merkle_combine_state_root(const uint8_t utxo_root[64],
                                     const uint8_t validator_root[64],
                                     const uint8_t delegation_root[64],
                                     const uint8_t reward_root[64],
                                     uint8_t out_state_root[64]) {
    nodus_merkle_combine_state_root_v1_legacy(utxo_root, validator_root,
                                                delegation_root, reward_root,
                                                out_state_root);
}

/* ── Composite state_root combiner — 5-input (Hard-Fork v1) ──────────
 *
 * state_root_v2 = SHA3-512( NODUS_STATE_ROOT_VERSION_V2 (1 byte)
 *                           || utxo_root(64) || validator_root(64)
 *                           || delegation_root(64) || reward_root(64)
 *                           || chain_config_root(64) )
 *
 * v0.16 note: superseded by combine_v3 (which replaces reward_root with
 * epoch_state_root). Retained __attribute__((cold)) purely for archive-
 * replay of pre-wipe blocks. Live hot-path callers use combine_v3.
 *
 * Pure function; safe to call from any thread.
 */
__attribute__((cold))
void nodus_merkle_combine_state_root_v2(const uint8_t utxo_root[64],
                                         const uint8_t validator_root[64],
                                         const uint8_t delegation_root[64],
                                         const uint8_t reward_root[64],
                                         const uint8_t chain_config_root[64],
                                         uint8_t out_state_root[64]) {
    if (!out_state_root) return;
    if (!utxo_root || !validator_root || !delegation_root ||
        !reward_root || !chain_config_root) {
        merkle_tag_hash_zero_on_fail(out_state_root);
        return;
    }

    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) {
        merkle_tag_hash_zero_on_fail(out_state_root);
        return;
    }
    const uint8_t version = NODUS_STATE_ROOT_VERSION_V2;
    if (EVP_DigestUpdate(md, &version,          1)  != 1 ||
        EVP_DigestUpdate(md, utxo_root,         64) != 1 ||
        EVP_DigestUpdate(md, validator_root,    64) != 1 ||
        EVP_DigestUpdate(md, delegation_root,   64) != 1 ||
        EVP_DigestUpdate(md, reward_root,       64) != 1 ||
        EVP_DigestUpdate(md, chain_config_root, 64) != 1) {
        EVP_MD_CTX_free(md);
        merkle_tag_hash_zero_on_fail(out_state_root);
        return;
    }
    if (sha3_512_final(md, out_state_root) != 0) {
        merkle_tag_hash_zero_on_fail(out_state_root);
    }
}

/* ── Composite state_root combiner — 5-input v3 (v0.16 reward redesign) ──
 *
 * state_root_v3 = SHA3-512( NODUS_STATE_ROOT_VERSION_V3 (1 byte)
 *                           || utxo_root(64) || validator_root(64)
 *                           || delegation_root(64) || epoch_state_root(64)
 *                           || chain_config_root(64) )
 *
 * Replaces v2's reward_root with epoch_state_root — the push-settlement
 * model keeps no per-validator reward accumulator state, only the current
 * epoch's pool + snapshot. Domain-separation byte 0x03 prevents replay
 * against v1/v2 roots. combine_v2 stays available as __attribute__((cold))
 * for archive-replay of pre-wipe blocks.
 */
/* Returns 0 / -1 (2026-07-31) — see the header. The byte-for-byte
 * formula is UNCHANGED; only the failure signalling is new, so every
 * existing state_root KAT still holds. */
int nodus_merkle_combine_state_root_v3(const uint8_t utxo_root[64],
                                        const uint8_t validator_root[64],
                                        const uint8_t delegation_root[64],
                                        const uint8_t epoch_state_root[64],
                                        const uint8_t chain_config_root[64],
                                        uint8_t out_state_root[64]) {
    if (!out_state_root) return -1;
    if (!utxo_root || !validator_root || !delegation_root ||
        !epoch_state_root || !chain_config_root) {
        merkle_tag_hash_zero_on_fail(out_state_root);
        return -1;
    }

    EVP_MD_CTX *md = NULL;
    if (sha3_512_init(&md) != 0) {
        merkle_tag_hash_zero_on_fail(out_state_root);
        return -1;
    }
    const uint8_t version = NODUS_STATE_ROOT_VERSION_V3;
    if (EVP_DigestUpdate(md, &version,          1)  != 1 ||
        EVP_DigestUpdate(md, utxo_root,         64) != 1 ||
        EVP_DigestUpdate(md, validator_root,    64) != 1 ||
        EVP_DigestUpdate(md, delegation_root,   64) != 1 ||
        EVP_DigestUpdate(md, epoch_state_root,  64) != 1 ||
        EVP_DigestUpdate(md, chain_config_root, 64) != 1) {
        EVP_MD_CTX_free(md);
        merkle_tag_hash_zero_on_fail(out_state_root);
        return -1;
    }
    if (sha3_512_final(md, out_state_root) != 0) {
        merkle_tag_hash_zero_on_fail(out_state_root);
        return -1;
    }
    return 0;
}

/* O15J Faz 3 — the 6-input v4 combiner (which appended the Ledger V2
 * activation-authority tree under NODUS_STATE_ROOT_VERSION_V4) is DELETED
 * with the activation ceremony. It was emitted only by the rehearsal
 * builds of the compile-gated ceremony, which never shipped, so no chain
 * in existence carries a v4 state_root and there is nothing to verify
 * historically. v3 above is once again the ONLY composition this tree
 * emits. The version byte 0x04 is retired, never reused
 * (nodus/include/nodus/nodus_types.h). */

/* ── Stage B.5 — validator_root (real) ─────────────────────────────── */

/* Write a big-endian u64 into `out` (8 bytes). */
static void be64_into(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

/* Validator leaf value hash:
 *   SHA3-512( 0x02                      // tag
 *          || pubkey[2592]
 *          || self_stake[8 BE]
 *          || total_delegated[8 BE]
 *          || external_delegated[8 BE]
 *          || commission_bps[2 BE]
 *          || pending_commission_bps[2 BE]
 *          || pending_effective_block[8 BE]
 *          || status[1]
 *          || active_since_block[8 BE]
 *          || unstake_commit_block[8 BE]
 *          || unstake_destination_fp[128 ASCII]
 *          || unstake_destination_pubkey[2592]
 *          || last_validator_update_block[8 BE]
 *          || consecutive_missed_epochs[8 BE]
 *          || last_signed_block[8 BE]
 *          || signed_blocks_this_epoch[8 BE] )
 * Canonical: ORDER BY pubkey ASC. */
static int load_validator_leaves(nodus_witness_t *w,
                                  uint8_t **leaves_out,
                                  size_t *count_out) {
    *leaves_out = NULL;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT pubkey, self_stake, total_delegated, external_delegated,"
        "       commission_bps, pending_commission_bps,"
        "       pending_effective_block, status, active_since_block,"
        "       unstake_commit_block, unstake_destination_fp,"
        "       unstake_destination_pubkey, last_validator_update_block,"
        "       consecutive_missed_epochs, last_signed_block,"
        "       signed_blocks_this_epoch "
        "FROM validators ORDER BY pubkey ASC", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: validator scan prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 16, n = 0;
    uint8_t *buf = malloc(cap * 64);
    if (!buf) { sqlite3_finalize(stmt); return -1; }

    /* rc carries the step result out of the loop — see load_utxo_leaves. */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t new_cap = cap * 2;
            uint8_t *new_buf = realloc(buf, new_cap * 64);
            if (!new_buf) { free(buf); sqlite3_finalize(stmt); return -1; }
            buf = new_buf; cap = new_cap;
        }

        EVP_MD_CTX *md = NULL;
        if (sha3_512_init(&md) != 0) {
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        const uint8_t tag = NODUS_TREE_TAG_VALIDATOR;
        EVP_DigestUpdate(md, &tag, 1);

        /* Fail close, never skip — see load_utxo_leaves. */
        const void *pubkey = sqlite3_column_blob(stmt, 0);
        int pk_len = sqlite3_column_bytes(stmt, 0);
        if (!pubkey || pk_len != DNAC_PUBKEY_SIZE) {
            EVP_MD_CTX_free(md);
            QGP_LOG_ERROR(LOG_TAG, "validator row: bad pubkey (len=%d) — "
                          "failing validator leaf load", pk_len);
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        EVP_DigestUpdate(md, pubkey, DNAC_PUBKEY_SIZE);

        uint8_t be[8];
        be64_into((uint64_t)sqlite3_column_int64(stmt, 1), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 2), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 3), be);
        EVP_DigestUpdate(md, be, 8);

        uint16_t u16 = (uint16_t)sqlite3_column_int(stmt, 4);
        uint8_t be2[2] = { (uint8_t)(u16 >> 8), (uint8_t)(u16 & 0xff) };
        EVP_DigestUpdate(md, be2, 2);
        u16 = (uint16_t)sqlite3_column_int(stmt, 5);
        be2[0] = (uint8_t)(u16 >> 8); be2[1] = (uint8_t)(u16 & 0xff);
        EVP_DigestUpdate(md, be2, 2);

        be64_into((uint64_t)sqlite3_column_int64(stmt, 6), be);
        EVP_DigestUpdate(md, be, 8);
        uint8_t st = (uint8_t)sqlite3_column_int(stmt, 7);
        EVP_DigestUpdate(md, &st, 1);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 8), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 9), be);
        EVP_DigestUpdate(md, be, 8);

        /* unstake_destination_fp: up to 128 ASCII hex chars (fingerprint),
         * hashed as a fixed zero-padded 128-byte window — that window IS
         * the canonical leaf encoding (see the leaf-format comment above).
         *
         * Fail close on a SQL NULL and on an over-long value. Both used to
         * be silent value substitutions of exactly the kind D2/D3 exist to
         * remove: a NULL hashed 128 zeros, and anything past byte 128 was
         * truncated away, so two different rows produced the same leaf.
         *
         * The NULL test goes through sqlite3_column_type, NOT through the
         * returned pointer. sqlite3 returns a NULL pointer for a
         * ZERO-LENGTH value (documented for sqlite3_column_blob), so a
         * pointer test cannot distinguish "absent" from "empty" — and
         * here the two must be treated differently. column_type is the
         * unambiguous signal.
         *
         * On an honest chain DB a SQL NULL is in fact UNREACHABLE: the
         * schema declares this column NOT NULL (nodus_witness.c:158) and
         * there is no `ALTER TABLE validators` anywhere in nodus/src, so
         * the constraint cannot have been bypassed by a migration. The
         * check is defence against a restored/corrupted file, not against
         * a live writer.
         *
         * An EMPTY fp, by contrast, IS reachable and stays legal. It does
         * NOT come from "never requested unstaking" — an earlier version
         * of this comment claimed that and it is FALSE: the fp is chosen
         * at STAKE time and is always a full 128-char hex string
         * (nodus_witness_bft.c:1455-1456 via qgp_fp_raw_to_hex), and it is
         * immutable thereafter (dnac/include/dnac/transaction.h:142-144,
         * "IMMUTABLE post-STAKE (Rule T)"). The field that IS left zero
         * for a validator that never requested unstaking is
         * unstake_destination_pubkey (nodus_witness_bft.c:1458-1465) —
         * see its own check below.
         * The one production path that yields an empty fp is a genesis
         * chain_def whose iv_fp begins with a NUL byte: the seeder copies
         * it verbatim (nodus_witness_genesis_seed.c:117) and
         * nodus_witness_validator.c:64-66 binds it with length -1
         * (strlen), storing an empty TEXT value. That row must keep
         * loading, and it hashes to the same 128 zeros it always did — no
         * honest leaf changes value here. */
        uint8_t fp_buf[128];
        memset(fp_buf, 0, sizeof(fp_buf));
        if (sqlite3_column_type(stmt, 10) == SQLITE_NULL) {
            EVP_MD_CTX_free(md);
            QGP_LOG_ERROR(LOG_TAG, "validator row: unstake_destination_fp is "
                          "NULL — refusing to hash a substituted value");
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        {
            const char *fp = (const char *)sqlite3_column_text(stmt, 10);
            size_t fp_len = fp ? strlen(fp) : 0;
            if (fp_len > sizeof(fp_buf)) {
                EVP_MD_CTX_free(md);
                QGP_LOG_ERROR(LOG_TAG, "validator row: unstake_destination_fp "
                              "too long (%zu > %zu) — refusing to truncate "
                              "inside a state_root leaf",
                              fp_len, sizeof(fp_buf));
                free(buf); sqlite3_finalize(stmt); return -1;
            }
            if (fp_len > 0) memcpy(fp_buf, fp, fp_len);
        }
        EVP_DigestUpdate(md, fp_buf, sizeof(fp_buf));

        /* unstake_destination_pubkey: always written full-length —
         * nodus_witness_validator.c:67-69 binds DNAC_PUBKEY_SIZE from a
         * fixed-size array. This IS the field that stays all-zero for a
         * validator whose unstake destination is not its own signer key
         * (nodus_witness_bft.c:1458-1465 populates it only on a match),
         * but all-zero is still 2592 bytes on disk. So a NULL or a short
         * blob is corruption, not a legitimate empty state, and hashing
         * 2592 substituted zeros for it made two nodes with different
         * corruption agree on nothing. */
        const void *upk = sqlite3_column_blob(stmt, 11);
        int upk_len = sqlite3_column_bytes(stmt, 11);
        if (!upk || upk_len != DNAC_PUBKEY_SIZE) {
            EVP_MD_CTX_free(md);
            QGP_LOG_ERROR(LOG_TAG, "validator row: bad "
                          "unstake_destination_pubkey (len=%d) — failing "
                          "validator leaf load", upk_len);
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        EVP_DigestUpdate(md, upk, DNAC_PUBKEY_SIZE);

        be64_into((uint64_t)sqlite3_column_int64(stmt, 12), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 13), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 14), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 15), be);
        EVP_DigestUpdate(md, be, 8);

        if (sha3_512_final(md, buf + n * 64) != 0) {
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        n++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "validator scan step failed rc=%d — leaf set "
                      "truncated, refusing to report success", rc);
        free(buf);
        return -1;
    }

    *leaves_out = buf;
    *count_out  = n;
    return 0;
}

int nodus_witness_merkle_compute_validator_root(nodus_witness_t *w,
                                                 uint8_t *root_out) {
    if (!w || !w->db || !root_out) return -1;
    uint8_t *leaves = NULL;
    size_t n = 0;
    if (load_validator_leaves(w, &leaves, &n) != 0) return -1;

    if (n == 0) {
        free(leaves);
        /* The sentinel is a REAL root that lands in state_root — a failed
         * digest here must fail the subtree, not pass 64 zeros through. */
        return nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR, root_out);
    }

    /* RFC 6962 leaf-hash prefix per CVE-2012-2459 closure. */
    for (size_t i = 0; i < n; i++) {
        uint8_t prehashed[64];
        if (leaf_hash(leaves + i * 64, 64, prehashed) != 0) {
            free(leaves); return -1;
        }
        memcpy(leaves + i * 64, prehashed, 64);
    }
    int rc = merkle_root_rfc6962(leaves, n, root_out);
    free(leaves);
    return rc;
}

/* ── Stage B.6 — delegation_root (real) ────────────────────────────── */

/* Delegation leaf value hash:
 *   SHA3-512( 0x03 || delegator_pubkey[2592] || validator_pubkey[2592]
 *          || amount[8 BE] || delegated_at_block[8 BE] )
 * Canonical: ORDER BY validator_pubkey ASC, delegator_pubkey ASC. */
static int load_delegation_leaves(nodus_witness_t *w,
                                   uint8_t **leaves_out,
                                   size_t *count_out) {
    *leaves_out = NULL;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT delegator_pubkey, validator_pubkey, amount, delegated_at_block "
        "FROM delegations "
        "ORDER BY validator_pubkey ASC, delegator_pubkey ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: delegation scan prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 16, n = 0;
    uint8_t *buf = malloc(cap * 64);
    if (!buf) { sqlite3_finalize(stmt); return -1; }

    /* rc carries the step result out of the loop — see load_utxo_leaves. */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t new_cap = cap * 2;
            uint8_t *new_buf = realloc(buf, new_cap * 64);
            if (!new_buf) { free(buf); sqlite3_finalize(stmt); return -1; }
            buf = new_buf; cap = new_cap;
        }

        EVP_MD_CTX *md = NULL;
        if (sha3_512_init(&md) != 0) {
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        const uint8_t tag = NODUS_TREE_TAG_DELEGATION;
        EVP_DigestUpdate(md, &tag, 1);

        /* Fail close, never skip — see load_utxo_leaves. */
        const void *dpk = sqlite3_column_blob(stmt, 0);
        const void *vpk = sqlite3_column_blob(stmt, 1);
        int dpk_len = sqlite3_column_bytes(stmt, 0);
        int vpk_len = sqlite3_column_bytes(stmt, 1);
        if (!dpk || dpk_len != DNAC_PUBKEY_SIZE ||
            !vpk || vpk_len != DNAC_PUBKEY_SIZE) {
            EVP_MD_CTX_free(md);
            QGP_LOG_ERROR(LOG_TAG, "delegation row: bad pubkey "
                          "(dlen=%d vlen=%d) — failing delegation leaf load",
                          dpk_len, vpk_len);
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        EVP_DigestUpdate(md, dpk, DNAC_PUBKEY_SIZE);
        EVP_DigestUpdate(md, vpk, DNAC_PUBKEY_SIZE);

        uint8_t be[8];
        be64_into((uint64_t)sqlite3_column_int64(stmt, 2), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 3), be);
        EVP_DigestUpdate(md, be, 8);

        if (sha3_512_final(md, buf + n * 64) != 0) {
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        n++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "delegation scan step failed rc=%d — leaf set "
                      "truncated, refusing to report success", rc);
        free(buf);
        return -1;
    }

    *leaves_out = buf;
    *count_out  = n;
    return 0;
}

int nodus_witness_merkle_compute_delegation_root(nodus_witness_t *w,
                                                  uint8_t *root_out) {
    if (!w || !w->db || !root_out) return -1;
    uint8_t *leaves = NULL;
    size_t n = 0;
    if (load_delegation_leaves(w, &leaves, &n) != 0) return -1;

    if (n == 0) {
        free(leaves);
        /* See compute_validator_root — the sentinel is state_root input. */
        return nodus_merkle_empty_root(NODUS_TREE_TAG_DELEGATION, root_out);
    }

    for (size_t i = 0; i < n; i++) {
        uint8_t prehashed[64];
        if (leaf_hash(leaves + i * 64, 64, prehashed) != 0) {
            free(leaves); return -1;
        }
        memcpy(leaves + i * 64, prehashed, 64);
    }
    int rc = merkle_root_rfc6962(leaves, n, root_out);
    free(leaves);
    return rc;
}

/* ── Stage B.4 — epoch_state_root (real) ───────────────────────────── */

/* epoch_state leaf value hash:
 *   SHA3-512( 0x06 || epoch_start_height[8 BE] || epoch_pool_accum[8 BE]
 *          || snapshot_hash[64] || total_minted[8 BE] || total_burned[8 BE] )
 *
 * total_minted + total_burned come from supply_tracking (global, not
 * per-epoch) — embedding them in every epoch_state leaf provides
 * state_root coverage for the supply-invariant counters without adding
 * a separate supply_root subtree.
 *
 * Canonical: ORDER BY epoch_start_height ASC. */
static int load_epoch_state_leaves(nodus_witness_t *w,
                                    uint8_t **leaves_out,
                                    size_t *count_out) {
    *leaves_out = NULL;
    *count_out = 0;

    /* Fetch global total_minted + total_burned once — same for every leaf. */
    nodus_witness_supply_t supply;
    memset(&supply, 0, sizeof(supply));
    int sup_rc = nodus_witness_supply_get(w, &supply);
    if (sup_rc < 0) {
        /* D3 (2026-07-31) — FAIL CLOSE. These counters are hashed into
         * every epoch_state leaf below (be64 total_minted/total_burned),
         * so they are inside state_root. Hashing zeros on a DB fault made
         * this witness emit a structurally valid but DIFFERENT root than
         * its peers — a chain split with no Byzantine actor. */
        QGP_LOG_ERROR(LOG_TAG,
                      "epoch_state leaves: supply_get DB error — refusing "
                      "to substitute zeroed supply counters");
        return -1;
    }
    /* sup_rc == 1: the supply_tracking row is genuinely absent (pre-genesis).
     * Zeroed counters are then the honest value — nothing has been minted or
     * burned yet — and `supply` is already zeroed above. The old comment
     * claimed the epoch_state table "is also empty" so the sentinel path
     * would be taken anyway; that only holds pre-genesis, and it was the
     * justification a DB error borrowed to hide behind. */

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT epoch_start_height, epoch_pool_accum, snapshot_hash "
        "FROM epoch_state ORDER BY epoch_start_height ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: epoch_state scan prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    size_t cap = 4, n = 0;
    uint8_t *buf = malloc(cap * 64);
    if (!buf) { sqlite3_finalize(stmt); return -1; }

    /* rc carries the step result out of the loop — see load_utxo_leaves. */
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t new_cap = cap * 2;
            uint8_t *new_buf = realloc(buf, new_cap * 64);
            if (!new_buf) { free(buf); sqlite3_finalize(stmt); return -1; }
            buf = new_buf; cap = new_cap;
        }

        EVP_MD_CTX *md = NULL;
        if (sha3_512_init(&md) != 0) {
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        const uint8_t tag = NODUS_TREE_TAG_EPOCH_STATE;
        EVP_DigestUpdate(md, &tag, 1);

        uint8_t be[8];
        be64_into((uint64_t)sqlite3_column_int64(stmt, 0), be);
        EVP_DigestUpdate(md, be, 8);
        be64_into((uint64_t)sqlite3_column_int64(stmt, 1), be);
        EVP_DigestUpdate(md, be, 8);

        /* snapshot_hash is always written full-length —
         * nodus_witness_epoch.c:58-59 binds NODUS_EPOCH_SNAPSHOT_HASH_LEN
         * (64, nodus_witness_epoch.h:30) — so a NULL or short blob is
         * corruption, not a legitimate empty state. Substituting 64 zeros
         * for it put a value in the leaf that no peer could reproduce.
         * Note sqlite3_column_blob() returns NULL for a zero-length blob,
         * so `!snap` and "empty" are the same signal here; both are
         * rejected, which is correct because empty is never written. */
        const void *snap = sqlite3_column_blob(stmt, 2);
        int snap_len = sqlite3_column_bytes(stmt, 2);
        if (!snap || snap_len != 64) {
            EVP_MD_CTX_free(md);
            QGP_LOG_ERROR(LOG_TAG, "epoch_state row: bad snapshot_hash "
                          "(len=%d) — failing epoch_state leaf load",
                          snap_len);
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        EVP_DigestUpdate(md, snap, 64);

        be64_into(supply.total_minted, be);
        EVP_DigestUpdate(md, be, 8);
        be64_into(supply.total_burned, be);
        EVP_DigestUpdate(md, be, 8);

        if (sha3_512_final(md, buf + n * 64) != 0) {
            free(buf); sqlite3_finalize(stmt); return -1;
        }
        n++;
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "epoch_state scan step failed rc=%d — leaf set "
                      "truncated, refusing to report success", rc);
        free(buf);
        return -1;
    }

    *leaves_out = buf;
    *count_out  = n;
    return 0;
}

int nodus_witness_merkle_compute_epoch_state_root(nodus_witness_t *w,
                                                   uint8_t *root_out) {
    if (!w || !w->db || !root_out) return -1;
    uint8_t *leaves = NULL;
    size_t n = 0;
    if (load_epoch_state_leaves(w, &leaves, &n) != 0) return -1;

    if (n == 0) {
        free(leaves);
        /* See compute_validator_root — the sentinel is state_root input. */
        return nodus_merkle_empty_root(NODUS_TREE_TAG_EPOCH_STATE, root_out);
    }

    for (size_t i = 0; i < n; i++) {
        uint8_t prehashed[64];
        if (leaf_hash(leaves + i * 64, 64, prehashed) != 0) {
            free(leaves); return -1;
        }
        memcpy(leaves + i * 64, prehashed, 64);
    }
    int rc = merkle_root_rfc6962(leaves, n, root_out);
    free(leaves);
    return rc;
}

/* ── Composite state_root: compute-from-witness wrapper ──────────────
 *
 * v0.16 (Stage B.7): state_root_v3 combines utxo + validator + delegation
 * + epoch_state + chain_config. The reward-tree slot from v2 is retired
 * with the accumulator reward system. validator and delegation subtrees
 * are now computed from real table scans (Stages B.5 + B.6), not empty
 * sentinels. epoch_state subtree is new (Stage B.4).
 *
 * compute_utxo_root remains the authoritative UTXO subtree; proofs built
 * via nodus_witness_merkle_build_proof still anchor there.
 *
 * Returns 0 with root_out written, or -1 with root_out UNTOUCHED. There
 * is exactly one way to emit a state_root: all five subtrees computed
 * from real data (D2, 2026-07-31). A caller that gets -1 has no root and
 * must not advertise, vote, or commit one.
 */
int nodus_witness_merkle_compute_state_root(nodus_witness_t *w,
                                            uint8_t *root_out) {
    if (!w || !root_out) return -1;
    QGP_BENCH_START(QGP_BENCH_MERKLE_COMPUTE);

    uint8_t utxo_root[64];
    if (nodus_witness_merkle_compute_utxo_root(w, utxo_root) != 0) {
        QGP_BENCH_END(QGP_BENCH_MERKLE_COMPUTE);
        return -1;
    }

    /* D2 (2026-07-31) — every subtree fails CLOSED, symmetric with the
     * utxo branch above. The four tagged-empty sentinel fallbacks that
     * used to live here converted a transient DB fault into a
     * structurally valid but DIVERGENT state_root: the faulting witness
     * voted a root none of its peers could reproduce. No root at all is
     * strictly safer than a substituted one — under BFT with 7 witnesses
     * a silent node is tolerated (f = 2), a lying one forks the chain. */
    uint8_t validator_root[64];
    if (nodus_witness_merkle_compute_validator_root(w, validator_root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "compute_state_root: validator_root failed");
        QGP_BENCH_END(QGP_BENCH_MERKLE_COMPUTE);
        return -1;
    }

    uint8_t delegation_root[64];
    if (nodus_witness_merkle_compute_delegation_root(w, delegation_root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "compute_state_root: delegation_root failed");
        QGP_BENCH_END(QGP_BENCH_MERKLE_COMPUTE);
        return -1;
    }

    uint8_t epoch_state_root[64];
    if (nodus_witness_merkle_compute_epoch_state_root(w, epoch_state_root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "compute_state_root: epoch_state_root failed");
        QGP_BENCH_END(QGP_BENCH_MERKLE_COMPUTE);
        return -1;
    }

    uint8_t chain_config_root[64];
    if (nodus_chain_config_compute_root(w, chain_config_root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "compute_state_root: chain_config_root failed");
        QGP_BENCH_END(QGP_BENCH_MERKLE_COMPUTE);
        return -1;
    }

    /* The combiner is the last fabrication hole: on a digest failure it
     * writes 64 zero bytes into its output, and returning 0 here
     * regardless would have handed the caller that sentinel as a
     * state_root.
     *
     * Combine into a LOCAL buffer and copy out only on success, so the
     * "root_out is UNTOUCHED on failure" guarantee this function
     * documents holds for the combiner leg too — not just for the five
     * subtree legs, which return before writing anything. A caller's
     * pre-existing buffer contents are then never silently replaced by
     * the zero sentinel. */
    uint8_t combined[64];
    /* O15J Faz 3 — ONE composition, unconditionally. The v4 leg (the
     * activation-authority tree, emitted only by the ceremony's rehearsal
     * builds) is deleted with the ceremony, so there is again exactly one
     * way this tree emits a state_root. */
    if (nodus_merkle_combine_state_root_v3(utxo_root,
                                            validator_root,
                                            delegation_root,
                                            epoch_state_root,
                                            chain_config_root,
                                            combined) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "compute_state_root: combine_v3 failed — "
                      "no root emitted");
        QGP_BENCH_END(QGP_BENCH_MERKLE_COMPUTE);
        return -1;
    }
    memcpy(root_out, combined, 64);
    QGP_BENCH_END(QGP_BENCH_MERKLE_COMPUTE);
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
