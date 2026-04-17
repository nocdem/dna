/**
 * Nodus — Witness Transaction Verification Tests
 *
 * Tests the nodus_witness_verify module with real crypto:
 *   - Valid spend TX (correct hash + signature + UTXO balance)
 *   - Tampered tx_hash → reject
 *   - Invalid sender signature → reject
 *   - Insufficient balance → reject
 *   - Fee too low → reject
 *   - Duplicate nullifiers → reject
 *   - Genesis TX → skips sig/balance/fee checks
 *   - Truncated tx_data → reject
 *
 * Uses in-memory SQLite DB and real Dilithium5 keypairs.
 */

#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_db.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Wire format constants (must match nodus_witness_verify.c) */
#define TX_HASH_LEN     64
#define NULLIFIER_LEN   64
#define TOKEN_ID_LEN    64
#define FP_LEN          129
#define SEED_LEN        32

/* ── Helper: create in-memory witness context ─────────────────────── */

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));

    int rc = sqlite3_open(":memory:", &w->db);
    if (rc != SQLITE_OK) return -1;

    const char *schema =
        "CREATE TABLE IF NOT EXISTS nullifiers ("
        "  nullifier BLOB PRIMARY KEY,"
        "  tx_hash BLOB NOT NULL,"
        "  added_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL DEFAULT x'"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000',"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  created_at INTEGER NOT NULL DEFAULT 0"
        ");";

    char *err = NULL;
    rc = sqlite3_exec(w->db, schema, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "schema error: %s\n", err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void cleanup_witness(nodus_witness_t *w) {
    if (w->db) sqlite3_close(w->db);
    memset(w, 0, sizeof(*w));
}

/* ── Helper: build serialized tx_data ─────────────────────────────── */

/* Build a minimal serialized transaction in wire format.
 * Returns allocated buffer (caller frees), sets *out_len. */
static uint8_t *build_tx_data(uint8_t version, uint8_t type, uint64_t timestamp,
                                uint8_t *nullifiers, int input_count,
                                uint64_t *input_amounts,
                                uint8_t *output_fps, int output_count,
                                uint64_t *output_amounts,
                                const uint8_t *sender_pubkey,
                                uint32_t *out_len) {
    /* Calculate size */
    size_t size = 10 + TX_HASH_LEN;  /* version+type+timestamp+tx_hash */
    size += 1;  /* input_count */
    size += input_count * (NULLIFIER_LEN + 8 + TOKEN_ID_LEN);
    size += 1;  /* output_count */
    /* Each output: version(1)+fp(129)+amount(8)+token_id(64)+seed(32)+memo_len(1) = 235 */
    size += output_count * (1 + FP_LEN + 8 + TOKEN_ID_LEN + SEED_LEN + 1);
    /* Witnesses: count(1) + 0 witnesses */
    size += 1;
    /* Signers: count(1) + [pubkey(2592) + sig(4627)] * (sender ? 1 : 0) */
    size += 1;
    if (sender_pubkey) size += NODUS_PK_BYTES + NODUS_SIG_BYTES;

    uint8_t *buf = calloc(1, size);
    if (!buf) return NULL;

    uint8_t *p = buf;

    /* Header: version + type + timestamp */
    *p++ = version;
    *p++ = type;
    memcpy(p, &timestamp, 8);
    p += 8;

    /* tx_hash placeholder (64 bytes of zeros — will be filled later) */
    p += TX_HASH_LEN;

    /* Inputs */
    *p++ = (uint8_t)input_count;
    for (int i = 0; i < input_count; i++) {
        memcpy(p, nullifiers + i * NULLIFIER_LEN, NULLIFIER_LEN);
        p += NULLIFIER_LEN;
        memcpy(p, &input_amounts[i], 8);
        p += 8;
        /* token_id: 64 bytes of zeros (native DNAC) */
        p += TOKEN_ID_LEN;
    }

    /* Outputs */
    *p++ = (uint8_t)output_count;
    for (int i = 0; i < output_count; i++) {
        *p++ = 1;  /* output version */
        if (output_fps) {
            memcpy(p, output_fps + i * FP_LEN, FP_LEN);
        }
        p += FP_LEN;
        memcpy(p, &output_amounts[i], 8);
        p += 8;
        /* token_id: 64 bytes of zeros (native DNAC) */
        p += TOKEN_ID_LEN;
        /* nullifier_seed: 32 bytes of zeros */
        p += SEED_LEN;
        *p++ = 0;  /* memo_len = 0 */
    }

    /* Witnesses: count=0 */
    *p++ = 0;

    /* Signers — signature placeholder, caller patches after signing tx_hash.
     * Signer sig starts at offset (p - buf) + 1 + NODUS_PK_BYTES. */
    if (sender_pubkey) {
        *p++ = 1;  /* signer_count */
        memcpy(p, sender_pubkey, NODUS_PK_BYTES);
        p += NODUS_PK_BYTES;
        /* signature zeros — caller must patch via embed_signer_sig() */
        p += NODUS_SIG_BYTES;
    } else {
        *p++ = 0;  /* signer_count = 0 (genesis) */
    }

    *out_len = (uint32_t)(p - buf);

    /* Now compute the correct tx_hash and embed it */
    uint8_t hash[64];
    /* Use sender pubkey as single signer for hash (0 signers for genesis) */
    uint8_t signer_count = sender_pubkey ? 1 : 0;
    if (nodus_witness_recompute_tx_hash(buf, *out_len, sender_pubkey, signer_count, hash) == 0) {
        memcpy(buf + 10, hash, TX_HASH_LEN);
    }

    return buf;
}

/* Embed signer signature into serialized tx_data.
 * Walks the wire format to find the signer signature slot. */
static void embed_signer_sig(uint8_t *tx_data, uint32_t tx_len,
                              const uint8_t *sig_bytes) {
    /* Skip: header(74) + inputs + outputs + witnesses → signer_count(1) + pubkey → sig */
    const uint8_t *p = tx_data + 74;  /* after header */
    size_t remaining = tx_len - 74;

    /* Skip inputs */
    uint8_t ic = *p++; remaining--;
    size_t isz = (size_t)ic * (64 + 8 + 64);
    p += isz; remaining -= isz;

    /* Skip outputs */
    uint8_t oc = *p++; remaining--;
    for (int i = 0; i < oc; i++) {
        uint8_t ml = p[1 + 129 + 8 + 64 + 32];  /* memo_len at fixed offset */
        size_t os = (1 + 129 + 8 + 64 + 32 + 1) + ml;
        p += os; remaining -= os;
    }

    /* Skip witnesses */
    uint8_t wc = *p++; remaining--;
    size_t wsz = (size_t)wc * (32 + NODUS_SIG_BYTES + 8 + NODUS_PK_BYTES);
    p += wsz; remaining -= wsz;

    /* signer_count */
    uint8_t sc = *p++; remaining--;
    if (sc == 0) return;

    /* Skip pubkey, write signature */
    size_t sig_offset = (p - tx_data) + NODUS_PK_BYTES;
    memcpy(tx_data + sig_offset, sig_bytes, NODUS_SIG_BYTES);
}

/* Add a UTXO to the witness DB */
static int add_utxo(nodus_witness_t *w, const uint8_t *nullifier,
                     const char *owner, uint64_t amount) {
    uint8_t fake_hash[64] = {0};
    return nodus_witness_utxo_add(w, nullifier, owner, amount, fake_hash, 0, 0, NULL);
}

/* Add a spent nullifier to the witness DB */
static int add_nullifier(nodus_witness_t *w, const uint8_t *nullifier) {
    uint8_t fake_hash[64] = {0};
    return nodus_witness_nullifier_add(w, nullifier, fake_hash);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Valid spend transaction
 * ══════════════════════════════════════════════════════════════════ */

static void test_valid_spend(void) {
    TEST("valid spend TX passes all checks");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    /* Generate sender keypair */
    nodus_identity_t sender;
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    nodus_identity_from_seed(seed, &sender);

    /* Compute sender fingerprint for UTXO ownership */
    char sender_fp[129];
    nodus_fingerprint_hex(&sender.pk, sender_fp);

    /* Create nullifier */
    uint8_t nullifier[NULLIFIER_LEN];
    memset(nullifier, 0xAA, NULLIFIER_LEN);

    /* Add UTXO: 1000 units (owned by sender) */
    add_utxo(&w, nullifier, sender_fp, 1000);

    /* Output: 999 units (fee = 1, min fee for 999 = 1) */
    uint64_t in_amt = 1000;
    uint64_t out_amt = 999;
    uint64_t fee = 1;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0xBB, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 1, 12345678ULL,
                                      nullifier, 1, &in_amt,
                                      out_fp, 1, &out_amt,
                                      sender.pk.bytes, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    /* Get the embedded hash */
    uint8_t tx_hash[64];
    memcpy(tx_hash, tx_data + 10, 64);

    /* Sign the tx_hash with sender's key and embed in signer section */
    nodus_sig_t sig;
    if (nodus_sign(&sig, tx_hash, 64, &sender.sk) != 0) {
        FAIL("sign"); free(tx_data); cleanup_witness(&w); return;
    }
    embed_signer_sig(tx_data, tx_len, sig.bytes);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, tx_hash,
                  1, nullifier, 1, sender.pk.bytes, sig.bytes, fee,
                  reason, sizeof(reason));

    if (rc == 0) {
        PASS();
    } else {
        FAIL(reason);
    }

    free(tx_data);
    nodus_identity_clear(&sender);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Tampered tx_hash
 * ══════════════════════════════════════════════════════════════════ */

static void test_tampered_hash(void) {
    TEST("tampered tx_hash is rejected");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    nodus_identity_t sender;
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));
    nodus_identity_from_seed(seed, &sender);

    uint8_t nullifier[NULLIFIER_LEN];
    memset(nullifier, 0xCC, NULLIFIER_LEN);
    add_utxo(&w, nullifier, "owner", 1000);

    uint64_t in_amt = 1000, out_amt = 999;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0xDD, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 1, 100ULL,
                                      nullifier, 1, &in_amt,
                                      out_fp, 1, &out_amt,
                                      sender.pk.bytes, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    /* Tamper with the hash */
    uint8_t bad_hash[64];
    memset(bad_hash, 0xFF, 64);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, bad_hash,
                  1, nullifier, 1, sender.pk.bytes, NULL, 1,
                  reason, sizeof(reason));

    if (rc == -1 && strstr(reason, "tx_hash mismatch")) {
        PASS();
    } else {
        FAIL(reason[0] ? reason : "wrong return code");
    }

    free(tx_data);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Invalid sender signature
 * ══════════════════════════════════════════════════════════════════ */

static void test_invalid_signature(void) {
    TEST("invalid sender signature is rejected");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    nodus_identity_t sender;
    uint8_t seed[32];
    memset(seed, 0x55, sizeof(seed));
    nodus_identity_from_seed(seed, &sender);

    uint8_t nullifier[NULLIFIER_LEN];
    memset(nullifier, 0xEE, NULLIFIER_LEN);
    add_utxo(&w, nullifier, "owner", 1000);

    uint64_t in_amt = 1000, out_amt = 999;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0x11, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 1, 200ULL,
                                      nullifier, 1, &in_amt,
                                      out_fp, 1, &out_amt,
                                      sender.pk.bytes, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    uint8_t tx_hash[64];
    memcpy(tx_hash, tx_data + 10, 64);

    /* Create a bad signature (sign wrong data) */
    nodus_sig_t bad_sig;
    uint8_t wrong_data[64];
    memset(wrong_data, 0xFF, 64);
    nodus_sign(&bad_sig, wrong_data, 64, &sender.sk);
    embed_signer_sig(tx_data, tx_len, bad_sig.bytes);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, tx_hash,
                  1, nullifier, 1, sender.pk.bytes, bad_sig.bytes, 1,
                  reason, sizeof(reason));

    if (rc == -1 && strstr(reason, "signature invalid")) {
        PASS();
    } else {
        FAIL(reason[0] ? reason : "wrong return code");
    }

    free(tx_data);
    nodus_identity_clear(&sender);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Insufficient balance
 * ══════════════════════════════════════════════════════════════════ */

static void test_insufficient_balance(void) {
    TEST("insufficient balance is rejected");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    nodus_identity_t sender;
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));
    nodus_identity_from_seed(seed, &sender);

    /* Compute sender fingerprint for UTXO ownership */
    char sender_fp[129];
    nodus_fingerprint_hex(&sender.pk, sender_fp);

    uint8_t nullifier[NULLIFIER_LEN];
    memset(nullifier, 0x22, NULLIFIER_LEN);
    /* UTXO has only 100 units (owned by sender) */
    add_utxo(&w, nullifier, sender_fp, 100);

    /* Try to spend 500 (more than 100) */
    uint64_t in_amt = 500;  /* client claims 500 but UTXO only has 100 */
    uint64_t out_amt = 499;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0x33, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 1, 300ULL,
                                      nullifier, 1, &in_amt,
                                      out_fp, 1, &out_amt,
                                      sender.pk.bytes, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    uint8_t tx_hash[64];
    memcpy(tx_hash, tx_data + 10, 64);

    nodus_sig_t sig;
    nodus_sign(&sig, tx_hash, 64, &sender.sk);
    embed_signer_sig(tx_data, tx_len, sig.bytes);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, tx_hash,
                  1, nullifier, 1, sender.pk.bytes, sig.bytes, 1,
                  reason, sizeof(reason));

    if (rc == -1 && strstr(reason, "balance")) {
        PASS();
    } else {
        FAIL(reason[0] ? reason : "wrong return code");
    }

    free(tx_data);
    nodus_identity_clear(&sender);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Fee too low
 * ══════════════════════════════════════════════════════════════════ */

static void test_fee_too_low(void) {
    TEST("fee too low is rejected");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    nodus_identity_t sender;
    uint8_t seed[32];
    memset(seed, 0x88, sizeof(seed));
    nodus_identity_from_seed(seed, &sender);

    /* Compute sender fingerprint for UTXO ownership */
    char sender_fp[129];
    nodus_fingerprint_hex(&sender.pk, sender_fp);

    uint8_t nullifier[NULLIFIER_LEN];
    memset(nullifier, 0x44, NULLIFIER_LEN);
    /* UTXO has 100000 units (owned by sender) */
    add_utxo(&w, nullifier, sender_fp, 100000);

    /* Output: 99999 (fee = 1, but min fee for 99999 = 99999*10/10000 = 99) */
    uint64_t in_amt = 100000;
    uint64_t out_amt = 99999;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0x55, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 1, 400ULL,
                                      nullifier, 1, &in_amt,
                                      out_fp, 1, &out_amt,
                                      sender.pk.bytes, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    uint8_t tx_hash[64];
    memcpy(tx_hash, tx_data + 10, 64);

    nodus_sig_t sig;
    nodus_sign(&sig, tx_hash, 64, &sender.sk);
    embed_signer_sig(tx_data, tx_len, sig.bytes);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, tx_hash,
                  1, nullifier, 1, sender.pk.bytes, sig.bytes, 1,
                  reason, sizeof(reason));

    if (rc == -1 && strstr(reason, "fee too low")) {
        PASS();
    } else {
        FAIL(reason[0] ? reason : "wrong return code");
    }

    free(tx_data);
    nodus_identity_clear(&sender);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Duplicate nullifiers in TX
 * ══════════════════════════════════════════════════════════════════ */

static void test_duplicate_nullifiers(void) {
    TEST("duplicate nullifiers within TX are rejected");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    /* Two identical nullifiers */
    uint8_t nullifiers[2 * NULLIFIER_LEN];
    memset(nullifiers, 0x66, NULLIFIER_LEN);
    memset(nullifiers + NULLIFIER_LEN, 0x66, NULLIFIER_LEN);

    /* Fake tx_data — just needs to pass minimum length check */
    uint8_t tx_hash[64];
    memset(tx_hash, 0, 64);

    /* Build some tx_data that will pass hash check for the duplicate nullifier test */
    uint64_t in_amts[2] = {500, 500};
    uint64_t out_amt = 999;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0x77, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 1, 500ULL,
                                      nullifiers, 2, in_amts,
                                      out_fp, 1, &out_amt,
                                      NULL, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    memcpy(tx_hash, tx_data + 10, 64);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, tx_hash,
                  1, nullifiers, 2, NULL, NULL, 1, reason, sizeof(reason));

    if (rc == -1 && strstr(reason, "duplicate nullifier")) {
        PASS();
    } else {
        FAIL(reason[0] ? reason : "wrong return code");
    }

    free(tx_data);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Genesis TX skips sig/balance/fee
 * ══════════════════════════════════════════════════════════════════ */

static void test_genesis_skips_checks(void) {
    TEST("genesis TX skips sig/balance/fee, verifies hash only");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    /* Genesis has no inputs */
    uint64_t out_amt = 1000000;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0x99, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 0 /* GENESIS */, 999ULL,
                                      NULL, 0, NULL,
                                      out_fp, 1, &out_amt,
                                      NULL, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    uint8_t tx_hash[64];
    memcpy(tx_hash, tx_data + 10, 64);

    char reason[256] = {0};
    /* No pubkey, no sig, no fee — should pass for genesis */
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, tx_hash,
                  0 /* GENESIS */, NULL, 0, NULL, NULL, 0,
                  reason, sizeof(reason));

    if (rc == 0) {
        PASS();
    } else {
        FAIL(reason);
    }

    free(tx_data);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Truncated tx_data
 * ══════════════════════════════════════════════════════════════════ */

static void test_truncated_tx_data(void) {
    TEST("truncated tx_data is rejected");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    /* Only 50 bytes — less than minimum header (74+1) */
    uint8_t short_data[50];
    memset(short_data, 0, sizeof(short_data));

    uint8_t tx_hash[64];
    memset(tx_hash, 0, 64);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, short_data, 50, tx_hash,
                  1, NULL, 0, NULL, NULL, 0, reason, sizeof(reason));

    if (rc == -1 && strstr(reason, "truncated")) {
        PASS();
    } else {
        FAIL(reason[0] ? reason : "wrong return code");
    }

    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════
 * Test: Double-spend returns -2
 * ══════════════════════════════════════════════════════════════════ */

static void test_double_spend(void) {
    TEST("double-spend returns -2");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("db setup"); return; }

    nodus_identity_t sender;
    uint8_t seed[32];
    memset(seed, 0x99, sizeof(seed));
    nodus_identity_from_seed(seed, &sender);

    /* Compute sender fingerprint for UTXO ownership */
    char sender_fp[129];
    nodus_fingerprint_hex(&sender.pk, sender_fp);

    uint8_t nullifier[NULLIFIER_LEN];
    memset(nullifier, 0xBB, NULLIFIER_LEN);

    /* Add UTXO AND mark nullifier as spent (owned by sender) */
    add_utxo(&w, nullifier, sender_fp, 1000);
    add_nullifier(&w, nullifier);

    uint64_t in_amt = 1000;
    uint64_t out_amt = 999;
    uint64_t fee = 1;
    uint8_t out_fp[FP_LEN];
    memset(out_fp, 0xCC, FP_LEN);

    uint32_t tx_len;
    uint8_t *tx_data = build_tx_data(1, 1, 600ULL,
                                      nullifier, 1, &in_amt,
                                      out_fp, 1, &out_amt,
                                      sender.pk.bytes, &tx_len);
    if (!tx_data) { FAIL("build_tx_data"); cleanup_witness(&w); return; }

    uint8_t tx_hash[64];
    memcpy(tx_hash, tx_data + 10, 64);

    nodus_sig_t sig;
    nodus_sign(&sig, tx_hash, 64, &sender.sk);
    embed_signer_sig(tx_data, tx_len, sig.bytes);

    char reason[256] = {0};
    int rc = nodus_witness_verify_transaction(&w, tx_data, tx_len, tx_hash,
                  1, nullifier, 1, sender.pk.bytes, sig.bytes, fee,
                  reason, sizeof(reason));

    if (rc == -2 && strstr(reason, "double-spend")) {
        PASS();
    } else {
        char msg[300];
        snprintf(msg, sizeof(msg), "rc=%d reason=%s", rc, reason);
        FAIL(msg);
    }

    free(tx_data);
    nodus_identity_clear(&sender);
    cleanup_witness(&w);
}

/* ══════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== Witness Transaction Verification Tests ===\n");

    test_valid_spend();
    test_tampered_hash();
    test_invalid_signature();
    test_insufficient_balance();
    test_fee_too_low();
    test_duplicate_nullifiers();
    test_genesis_skips_checks();
    test_truncated_tx_data();
    test_double_spend();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
