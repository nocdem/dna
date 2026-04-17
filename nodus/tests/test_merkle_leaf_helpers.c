/* Test: Merkle leaf key / value hash / empty root helpers produce
 * deterministic, tree-tagged SHA3-512 outputs. Pinned byte vectors
 * lock the F-CRYPTO-04 domain-separation contract. Any change to
 * these bytes invalidates every computed state_root.
 *
 * Uses explicit CHECK_BYTES (no assert()) for NDEBUG safety — nodus
 * tests must survive Release builds.
 *
 * KAT provenance: all expected outputs were computed with Python
 * hashlib.sha3_512(...) at development time. See the comment above
 * each `want_*` array for the exact preimage.
 */
#include "witness/nodus_witness_merkle.h"
#include "nodus/nodus_types.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int check_bytes(const char *label, const uint8_t got[64], const uint8_t want[64]) {
    if (memcmp(got, want, 64) != 0) {
        fprintf(stderr, "test_merkle_leaf_helpers: FAIL - %s\n  got:  ", label);
        for (int i = 0; i < 64; i++) fprintf(stderr, "%02x", got[i]);
        fprintf(stderr, "\n  want: ");
        for (int i = 0; i < 64; i++) fprintf(stderr, "%02x", want[i]);
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}

int main(void) {
    uint8_t out[64];

    /* ---- 1. Cross-tree collision rejection: same pubkey bytes,
     * different tree tags produce DIFFERENT keys. This is the core
     * domain-separation property — without the tree_tag prefix a
     * validator pubkey and a reward-tree pubkey would collide. */
    uint8_t pubkey_bytes[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t key_validator[64], key_reward[64];
    nodus_merkle_leaf_key(NODUS_TREE_TAG_VALIDATOR, pubkey_bytes, sizeof(pubkey_bytes), key_validator);
    nodus_merkle_leaf_key(NODUS_TREE_TAG_REWARD,    pubkey_bytes, sizeof(pubkey_bytes), key_reward);
    if (memcmp(key_validator, key_reward, 64) == 0) {
        fprintf(stderr, "test_merkle_leaf_helpers: FAIL - validator vs reward leaf_key collide on same pubkey\n");
        return 1;
    }

    /* Same property across every pairing of the four tags. */
    uint8_t k_utxo[64], k_val[64], k_del[64], k_rew[64];
    nodus_merkle_leaf_key(NODUS_TREE_TAG_UTXO,       pubkey_bytes, sizeof(pubkey_bytes), k_utxo);
    nodus_merkle_leaf_key(NODUS_TREE_TAG_VALIDATOR,  pubkey_bytes, sizeof(pubkey_bytes), k_val);
    nodus_merkle_leaf_key(NODUS_TREE_TAG_DELEGATION, pubkey_bytes, sizeof(pubkey_bytes), k_del);
    nodus_merkle_leaf_key(NODUS_TREE_TAG_REWARD,     pubkey_bytes, sizeof(pubkey_bytes), k_rew);
    if (memcmp(k_utxo, k_val, 64) == 0 ||
        memcmp(k_utxo, k_del, 64) == 0 ||
        memcmp(k_utxo, k_rew, 64) == 0 ||
        memcmp(k_val, k_del, 64) == 0 ||
        memcmp(k_val, k_rew, 64) == 0 ||
        memcmp(k_del, k_rew, 64) == 0) {
        fprintf(stderr, "test_merkle_leaf_helpers: FAIL - cross-tree leaf_key collision on same bytes\n");
        return 1;
    }

    /* ---- 2. Empty-root KAT: tag-specific pinned values.
     * Computed with:
     *   python3 -c "import hashlib; print(hashlib.sha3_512(bytes([0xNN, 0x00])).hexdigest())"
     * for NN = 0x01 (UTXO), 0x02 (VALIDATOR), 0x03 (DELEGATION), 0x04 (REWARD).
     */

    /* SHA3-512(0x01 || 0x00) */
    uint8_t want_empty_utxo[64] = {
        0x28, 0xd8, 0x6c, 0x11, 0xcf, 0x45, 0xb5, 0x2a,
        0xb8, 0x3e, 0x9b, 0x34, 0x32, 0x6a, 0xf0, 0x99,
        0x08, 0x45, 0x67, 0x90, 0xda, 0xfe, 0x80, 0x63,
        0xe4, 0xdd, 0xf6, 0x14, 0x40, 0x34, 0x27, 0x36,
        0xfa, 0x16, 0x8f, 0xcd, 0x84, 0x60, 0x29, 0xa2,
        0x0f, 0x08, 0x8d, 0xdb, 0x11, 0xe2, 0x12, 0x64,
        0xf0, 0xbe, 0x98, 0x03, 0x0f, 0xdb, 0xcf, 0x5f,
        0x94, 0x70, 0x9a, 0x34, 0x91, 0xf4, 0x7e, 0x62,
    };

    /* SHA3-512(0x02 || 0x00) */
    uint8_t want_empty_validator[64] = {
        0x27, 0x66, 0x25, 0xbb, 0x45, 0x7a, 0x52, 0x59,
        0xd8, 0x60, 0x07, 0xb4, 0xda, 0x7d, 0x17, 0x23,
        0x6c, 0xf7, 0x9c, 0x79, 0xb7, 0x9e, 0x6c, 0x8d,
        0x49, 0x43, 0x01, 0x7f, 0x1c, 0x19, 0x33, 0x35,
        0xc1, 0xc0, 0x89, 0x9f, 0x72, 0xb2, 0xdc, 0xf0,
        0xff, 0x4e, 0x23, 0x88, 0xca, 0xf1, 0xb0, 0xe5,
        0x4a, 0x41, 0x38, 0xf7, 0x8f, 0xdd, 0x0b, 0xf9,
        0xaa, 0xfb, 0x33, 0x55, 0xb7, 0x5d, 0xc4, 0xb1,
    };

    /* SHA3-512(0x03 || 0x00) */
    uint8_t want_empty_delegation[64] = {
        0x1e, 0xda, 0x48, 0x36, 0xb6, 0xd1, 0x80, 0x15,
        0x42, 0x1a, 0xba, 0x08, 0xb6, 0x35, 0x78, 0xaf,
        0xae, 0xc0, 0x7f, 0xc5, 0x38, 0x72, 0x19, 0x55,
        0x18, 0xc7, 0x94, 0xb9, 0xef, 0xa2, 0xd6, 0x8e,
        0xdf, 0xa3, 0xae, 0xce, 0x49, 0x8f, 0xf6, 0x48,
        0x2a, 0xe0, 0xb9, 0x13, 0x58, 0x11, 0x3e, 0x26,
        0xbb, 0x4c, 0x2a, 0x60, 0x36, 0x20, 0x06, 0xd4,
        0xf2, 0xa3, 0x37, 0x4a, 0xf2, 0x58, 0x8c, 0x4c,
    };

    /* SHA3-512(0x04 || 0x00) */
    uint8_t want_empty_reward[64] = {
        0x22, 0xf9, 0x7a, 0xd8, 0x94, 0x25, 0x56, 0x20,
        0xbc, 0xc5, 0x14, 0xbf, 0xde, 0xc6, 0xb7, 0xb5,
        0x67, 0xe8, 0x2f, 0x87, 0x9e, 0x78, 0xe7, 0x70,
        0x45, 0x3e, 0xd6, 0x6c, 0xdc, 0xdf, 0x29, 0x9e,
        0x41, 0x6b, 0x32, 0x10, 0xf6, 0xbc, 0xce, 0x59,
        0x72, 0x8e, 0xed, 0xd1, 0xa5, 0x22, 0x9a, 0x87,
        0x59, 0x36, 0x56, 0x04, 0x09, 0xc2, 0x1e, 0x7b,
        0x39, 0xef, 0x87, 0xdd, 0x30, 0x1b, 0x2b, 0x0d,
    };

    nodus_merkle_empty_root(NODUS_TREE_TAG_UTXO, out);
    if (check_bytes("empty_root(UTXO)", out, want_empty_utxo)) return 1;

    nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR, out);
    if (check_bytes("empty_root(VALIDATOR)", out, want_empty_validator)) return 1;

    nodus_merkle_empty_root(NODUS_TREE_TAG_DELEGATION, out);
    if (check_bytes("empty_root(DELEGATION)", out, want_empty_delegation)) return 1;

    nodus_merkle_empty_root(NODUS_TREE_TAG_REWARD, out);
    if (check_bytes("empty_root(REWARD)", out, want_empty_reward)) return 1;

    /* All four empty roots must be pairwise distinct — same property
     * that F-CRYPTO-04 relies on for subtree isolation. */
    if (memcmp(want_empty_utxo, want_empty_validator, 64) == 0 ||
        memcmp(want_empty_utxo, want_empty_delegation, 64) == 0 ||
        memcmp(want_empty_utxo, want_empty_reward, 64) == 0 ||
        memcmp(want_empty_validator, want_empty_delegation, 64) == 0 ||
        memcmp(want_empty_validator, want_empty_reward, 64) == 0 ||
        memcmp(want_empty_delegation, want_empty_reward, 64) == 0) {
        fprintf(stderr, "test_merkle_leaf_helpers: FAIL - empty roots collide across tags\n");
        return 1;
    }

    /* ---- 3. leaf_value_hash KAT.
     * Computed with:
     *   python3 -c "import hashlib; print(hashlib.sha3_512(bytes([0x02]) + b'hello').hexdigest())"
     * = 36c354f4d18c0a2ad831ac882ac1fae0847d10723fa86acfd8f074cc0c8ce4db
     *   46bc778a4c5ecc8167760985ce7362dd7c7688ecb63c43eb762d7e6998ed61d4
     */
    const uint8_t sample_cbor[5] = { 'h', 'e', 'l', 'l', 'o' };
    uint8_t want_lvh_validator_hello[64] = {
        0x36, 0xc3, 0x54, 0xf4, 0xd1, 0x8c, 0x0a, 0x2a,
        0xd8, 0x31, 0xac, 0x88, 0x2a, 0xc1, 0xfa, 0xe0,
        0x84, 0x7d, 0x10, 0x72, 0x3f, 0xa8, 0x6a, 0xcf,
        0xd8, 0xf0, 0x74, 0xcc, 0x0c, 0x8c, 0xe4, 0xdb,
        0x46, 0xbc, 0x77, 0x8a, 0x4c, 0x5e, 0xcc, 0x81,
        0x67, 0x76, 0x09, 0x85, 0xce, 0x73, 0x62, 0xdd,
        0x7c, 0x76, 0x88, 0xec, 0xb6, 0x3c, 0x43, 0xeb,
        0x76, 0x2d, 0x7e, 0x69, 0x98, 0xed, 0x61, 0xd4,
    };
    nodus_merkle_leaf_value_hash(NODUS_TREE_TAG_VALIDATOR, sample_cbor, 5, out);
    if (check_bytes("leaf_value_hash(VALIDATOR, \"hello\")", out, want_lvh_validator_hello)) return 1;

    /* Cross-tree property for leaf_value_hash too: same CBOR bytes,
     * different tags must diverge. */
    uint8_t lvh_utxo[64], lvh_val[64];
    nodus_merkle_leaf_value_hash(NODUS_TREE_TAG_UTXO,      sample_cbor, 5, lvh_utxo);
    nodus_merkle_leaf_value_hash(NODUS_TREE_TAG_VALIDATOR, sample_cbor, 5, lvh_val);
    if (memcmp(lvh_utxo, lvh_val, 64) == 0) {
        fprintf(stderr, "test_merkle_leaf_helpers: FAIL - leaf_value_hash collides across tags\n");
        return 1;
    }

    /* ---- 4. Determinism: calling the same helper twice gives the
     * same output. (Guards against accidental RNG / timestamp leakage.) */
    uint8_t a[64], b[64];
    nodus_merkle_leaf_key(NODUS_TREE_TAG_VALIDATOR, pubkey_bytes, sizeof(pubkey_bytes), a);
    nodus_merkle_leaf_key(NODUS_TREE_TAG_VALIDATOR, pubkey_bytes, sizeof(pubkey_bytes), b);
    if (memcmp(a, b, 64) != 0) {
        fprintf(stderr, "test_merkle_leaf_helpers: FAIL - leaf_key non-deterministic\n");
        return 1;
    }

    /* ---- 5. Zero-length raw input is accepted (no NULL deref for n=0). */
    nodus_merkle_leaf_key(NODUS_TREE_TAG_VALIDATOR, NULL, 0, out);
    /* Should equal SHA3-512(0x02) — just check it didn't crash and
     * diverges from the empty-root which is SHA3-512(0x02 || 0x00). */
    if (memcmp(out, want_empty_validator, 64) == 0) {
        fprintf(stderr, "test_merkle_leaf_helpers: FAIL - leaf_key(tag, NULL, 0) collides with empty_root\n");
        return 1;
    }

    printf("test_merkle_leaf_helpers: PASS\n");
    return 0;
}
