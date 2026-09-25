/**
 * @file test_mlkem_rollout.c
 * @brief KEM Faz 1 (dual-key ML-KEM-1024 rollout) — unit tests for package M1.
 *
 * Covers the 7 test groups from the dispatch (f1-dispatch-m1.md):
 *   1. Seal alg 2/3 encrypt-decrypt matrix, header byte validation, multi-recipient.
 *   2. Identity record mlkem_pubkey: signature preimage exclusion, old-client
 *      re-serialize-and-verify compatibility.
 *   3. keyserver_cache: pre-migration schema -> ADD COLUMN migration, put/get.
 *   4. IKP v2 unchanged, v3 round-trip, v3 mixed-alg entries.
 *   6. Call INVITE "alg" field: encode with/without, parse default-0.
 *   7. mnemonic.v2.enc save/load round-trip, mnemonic_storage_exists(EITHER).
 *
 * Group 5 (salt agreement) is DELIBERATELY PARTIAL — see the comment above
 * test_salt_agreement() for why "assert on the version bytes" cannot be
 * done without a live nodus instance through the public API, and what this
 * file checks instead (documented limitation, not a shortcut).
 *
 * Governing records: docs/plans/decisions/2026-09-23-kem-mlkem-migration.md,
 * docs/plans/2026-09-23-mlkem-fips203-migration-design.md.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#include "../dna_api.h"
#include "../dht/client/dna_profile.h"
#include "../database/keyserver_cache.h"
#include "../dht/shared/dht_salt_agreement.h"
#include "../messenger/gek.h"
#include "crypto/key/seed_storage.h"
#include "crypto/key/bip39/bip39.h"   /* BIP39_MAX_MNEMONIC_LENGTH */
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/enc/aes_keywrap.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_types.h"
#include "dna_call_crypto.h"   /* resolved via -I ${DNA_ROOT}/src/api/engine, matches test_call_signal.c */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, name) do { \
    if (cond) { printf("  PASS: %s\n", name); g_pass++; } \
    else { printf("  FAIL: %s\n", name); g_fail++; } \
} while (0)

/* ============================================================================
 * Helpers
 * ============================================================================ */

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
}

/* Remove `"key":"value",` (or `"key":"value"` right before a closing `}`)
 * from a JSON string in place. Used to simulate an OLD client that never
 * heard of the new field re-serializing a record that had it. */
static void strip_json_field_inplace(char *json, const char *key) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
    char *start = strstr(json, pattern);
    if (!start) return;
    char *value_start = start + strlen(pattern);
    char *end = strstr(value_start, "\",");
    if (end) {
        end += 2; /* skip closing quote + comma */
        memmove(start, end, strlen(end) + 1);
        return;
    }
    end = strstr(value_start, "\"}");
    if (end) {
        end += 1; /* keep the closing brace, drop through the closing quote */
        memmove(start, end, strlen(end) + 1);
    }
}

/* ============================================================================
 * Group 1 — Seal: alg 2/3 matrix, header byte validation, multi-recipient
 * ============================================================================ */

static void test_seal_alg_matrix(void) {
    printf("test_seal_alg_matrix\n");

    uint8_t r3_pub[QGP_KEM1024_PUBLICKEYBYTES], r3_priv[QGP_KEM1024_SECRETKEYBYTES];
    uint8_t mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES], mlkem_priv[QGP_MLKEM1024_SECRETKEYBYTES];
    uint8_t dsa_pub[QGP_DSA87_PUBLICKEYBYTES], dsa_priv[QGP_DSA87_SECRETKEYBYTES];

    CHECK(qgp_kem1024_keypair(r3_pub, r3_priv) == 0, "round-3 keypair generated");
    CHECK(qgp_mlkem1024_keypair(mlkem_pub, mlkem_priv) == 0, "ML-KEM-1024 keypair generated");
    CHECK(qgp_dsa87_keypair(dsa_pub, dsa_priv) == 0, "Dilithium5 keypair generated");

    dna_context_t *ctx = dna_context_new();
    CHECK(ctx != NULL, "context created");
    if (!ctx) return;

    const char *msg = "seal alg matrix test message";
    size_t msg_len = strlen(msg);

    /* alg 2 encrypt -> decrypt with (legacy sk, NULL) OK and (legacy sk, mlkem dk) OK */
    {
        uint8_t *enc = NULL; size_t enc_len = 0;
        int rc = dna_encrypt_message_raw_alg(ctx, (const uint8_t*)msg, msg_len,
                                             r3_pub, dsa_pub, dsa_priv,
                                             (uint64_t)time(NULL),
                                             (uint8_t)QGP_KEY_TYPE_KEM1024,
                                             &enc, &enc_len);
        CHECK(rc == DNA_OK, "alg2 encrypt OK");

        if (rc == DNA_OK) {
            uint8_t *pt = NULL; size_t pt_len = 0;
            uint8_t *fp = NULL; size_t fp_len = 0;
            uint8_t *sig = NULL; size_t sig_len = 0;
            uint64_t ts = 0;

            int drc = dna_decrypt_message_raw_alg(ctx, enc, enc_len, r3_priv, NULL,
                                                  &pt, &pt_len, &fp, &fp_len,
                                                  &sig, &sig_len, &ts);
            CHECK(drc == DNA_OK && pt_len == msg_len && memcmp(pt, msg, msg_len) == 0,
                  "alg2 decrypt with (legacy sk, NULL) OK");
            free(pt); free(fp); free(sig);

            pt = NULL; fp = NULL; sig = NULL;
            drc = dna_decrypt_message_raw_alg(ctx, enc, enc_len, r3_priv, mlkem_priv,
                                              &pt, &pt_len, &fp, &fp_len,
                                              &sig, &sig_len, &ts);
            CHECK(drc == DNA_OK && pt_len == msg_len && memcmp(pt, msg, msg_len) == 0,
                  "alg2 decrypt with (legacy sk, mlkem dk) OK — mlkem dk unused, ignored");
            free(pt); free(fp); free(sig);
        }
        free(enc);
    }

    /* alg 3 encrypt -> decrypt with (legacy sk, mlkem dk) OK, (legacy sk, NULL) -> DNA_ERROR_DECRYPT */
    {
        uint8_t *enc = NULL; size_t enc_len = 0;
        int rc = dna_encrypt_message_raw_alg(ctx, (const uint8_t*)msg, msg_len,
                                             mlkem_pub, dsa_pub, dsa_priv,
                                             (uint64_t)time(NULL),
                                             (uint8_t)QGP_KEY_TYPE_MLKEM1024,
                                             &enc, &enc_len);
        CHECK(rc == DNA_OK, "alg3 encrypt OK");

        if (rc == DNA_OK) {
            uint8_t *pt = NULL; size_t pt_len = 0;
            uint8_t *fp = NULL; size_t fp_len = 0;
            uint8_t *sig = NULL; size_t sig_len = 0;
            uint64_t ts = 0;

            int drc = dna_decrypt_message_raw_alg(ctx, enc, enc_len, r3_priv, mlkem_priv,
                                                  &pt, &pt_len, &fp, &fp_len,
                                                  &sig, &sig_len, &ts);
            CHECK(drc == DNA_OK && pt_len == msg_len && memcmp(pt, msg, msg_len) == 0,
                  "alg3 decrypt with (legacy sk, mlkem dk) OK");
            free(pt); free(fp); free(sig);

            pt = NULL; fp = NULL; sig = NULL;
            drc = dna_decrypt_message_raw_alg(ctx, enc, enc_len, r3_priv, NULL,
                                              &pt, &pt_len, &fp, &fp_len,
                                              &sig, &sig_len, &ts);
            CHECK(drc == DNA_ERROR_DECRYPT, "alg3 decrypt with (legacy sk, NULL) -> DNA_ERROR_DECRYPT");
        }

        /* header byte 4 (unknown enc_key_type) -> DNA_ERROR_DECRYPT.
         * dna_enc_header_t.enc_key_type is byte offset 9 (magic[8] + version[1]),
         * per PROTOCOL.md's Seal header layout. */
        if (enc && enc_len > 9) {
            uint8_t *corrupt = malloc(enc_len);
            memcpy(corrupt, enc, enc_len);
            corrupt[9] = 4; /* neither 2 nor 3 */

            uint8_t *pt = NULL; size_t pt_len = 0;
            uint8_t *fp = NULL; size_t fp_len = 0;
            uint8_t *sig = NULL; size_t sig_len = 0;
            uint64_t ts = 0;
            int drc = dna_decrypt_message_raw_alg(ctx, corrupt, enc_len, r3_priv, mlkem_priv,
                                                  &pt, &pt_len, &fp, &fp_len,
                                                  &sig, &sig_len, &ts);
            CHECK(drc == DNA_ERROR_DECRYPT, "header byte 4 (unknown enc_key_type) -> DNA_ERROR_DECRYPT");
            free(corrupt);
        }
        free(enc);
    }

    dna_context_free(ctx);
}

/* Multi-recipient alg 3: messenger_encrypt_multi_recipient is `static` in
 * messages.c, not exported — this exercises the SAME wire format at the
 * dna_api layer (dna_encrypt_message_raw_alg is single-recipient by design;
 * multi-recipient behavior is messages.c's own header+entries loop, which
 * this test cannot reach without duplicating messages.c's static function).
 * What IS testable here: two independent alg-3 Seals to two different
 * recipients both decrypt correctly with their own dk — proving alg 3
 * ciphertexts for different recipients don't cross-decrypt. */
static void test_seal_alg3_multi_recipient(void) {
    printf("test_seal_alg3_multi_recipient\n");

    uint8_t mlkem_pub_a[QGP_MLKEM1024_PUBLICKEYBYTES], mlkem_priv_a[QGP_MLKEM1024_SECRETKEYBYTES];
    uint8_t mlkem_pub_b[QGP_MLKEM1024_PUBLICKEYBYTES], mlkem_priv_b[QGP_MLKEM1024_SECRETKEYBYTES];
    uint8_t dsa_pub[QGP_DSA87_PUBLICKEYBYTES], dsa_priv[QGP_DSA87_SECRETKEYBYTES];

    CHECK(qgp_mlkem1024_keypair(mlkem_pub_a, mlkem_priv_a) == 0, "recipient A ML-KEM keypair");
    CHECK(qgp_mlkem1024_keypair(mlkem_pub_b, mlkem_priv_b) == 0, "recipient B ML-KEM keypair");
    CHECK(qgp_dsa87_keypair(dsa_pub, dsa_priv) == 0, "sender Dilithium5 keypair");

    dna_context_t *ctx = dna_context_new();
    if (!ctx) { CHECK(0, "context created"); return; }

    const char *msg = "multi-recipient alg3 message";
    size_t msg_len = strlen(msg);

    uint8_t *enc_a = NULL, *enc_b = NULL;
    size_t enc_a_len = 0, enc_b_len = 0;
    int rc_a = dna_encrypt_message_raw_alg(ctx, (const uint8_t*)msg, msg_len,
                                           mlkem_pub_a, dsa_pub, dsa_priv,
                                           (uint64_t)time(NULL),
                                           (uint8_t)QGP_KEY_TYPE_MLKEM1024, &enc_a, &enc_a_len);
    int rc_b = dna_encrypt_message_raw_alg(ctx, (const uint8_t*)msg, msg_len,
                                           mlkem_pub_b, dsa_pub, dsa_priv,
                                           (uint64_t)time(NULL),
                                           (uint8_t)QGP_KEY_TYPE_MLKEM1024, &enc_b, &enc_b_len);
    CHECK(rc_a == DNA_OK && rc_b == DNA_OK, "both alg3 recipient Seals encrypt OK");

    if (rc_a == DNA_OK && rc_b == DNA_OK) {
        uint8_t *pt = NULL; size_t pt_len = 0, fp_len = 0, sig_len = 0;
        uint8_t *fp = NULL, *sig = NULL;
        uint64_t ts = 0;

        int drc = dna_decrypt_message_raw_alg(ctx, enc_a, enc_a_len, NULL, mlkem_priv_a,
                                              &pt, &pt_len, &fp, &fp_len, &sig, &sig_len, &ts);
        CHECK(drc == DNA_OK && pt_len == msg_len && memcmp(pt, msg, msg_len) == 0,
              "recipient A decrypts its own Seal with its own dk");
        free(pt); free(fp); free(sig);

        pt = NULL; fp = NULL; sig = NULL;
        drc = dna_decrypt_message_raw_alg(ctx, enc_a, enc_a_len, NULL, mlkem_priv_b,
                                          &pt, &pt_len, &fp, &fp_len, &sig, &sig_len, &ts);
        CHECK(drc != DNA_OK, "recipient B's dk does NOT decrypt recipient A's Seal");
        free(pt); free(fp); free(sig);
    }

    free(enc_a); free(enc_b);
    dna_context_free(ctx);
}

/* ============================================================================
 * Group 2 — Identity record: mlkem_pubkey outside signature preimage
 * ============================================================================ */

static void test_identity_record_mlkem_pubkey(void) {
    printf("test_identity_record_mlkem_pubkey\n");

    uint8_t dsa_pub[QGP_DSA87_PUBLICKEYBYTES], dsa_priv[QGP_DSA87_SECRETKEYBYTES];
    uint8_t mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES];
    uint8_t mlkem_priv[QGP_MLKEM1024_SECRETKEYBYTES];
    CHECK(qgp_dsa87_keypair(dsa_pub, dsa_priv) == 0, "Dilithium5 keypair generated");
    /* ORCHESTRATOR fix (M1 delta 1 run): the record parser now runs
     * qgp_mlkem1024_ek_check at intake (D9), so the pubkey must be a REAL
     * ML-KEM-1024 ek — random bytes fail the modulus check (12-bit
     * coefficients >= q = 3329 are near-certain in 1536 random bytes) and
     * the parser correctly reports has_mlkem_pubkey == false. That
     * negative case is covered separately below (bad_identity). */
    CHECK(qgp_mlkem1024_keypair(mlkem_pub, mlkem_priv) == 0, "ML-KEM-1024 keypair generated (real ek for the record)");

    dna_unified_identity_t *identity = dna_identity_create();
    CHECK(identity != NULL, "identity created");
    if (!identity) return;

    memcpy(identity->fingerprint,
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
           128); /* identity->fingerprint is 129 bytes, calloc'd by dna_identity_create() -> [128] stays '\0' */
    memcpy(identity->dilithium_pubkey, dsa_pub, sizeof(identity->dilithium_pubkey));
    identity->has_registered_name = true;
    strncpy(identity->registered_name, "kemf1test", sizeof(identity->registered_name) - 1);
    identity->timestamp = (uint64_t)time(NULL);
    identity->version = 1;
    memcpy(identity->mlkem_pubkey, mlkem_pub, sizeof(identity->mlkem_pubkey));
    identity->has_mlkem_pubkey = true;

    /* Sign via the production path: qgp_dsa87_sign over
     * dna_identity_to_json_unsigned(identity) — same as
     * keyserver_publish.c's dht_keyserver_publish/_update and
     * keyserver_profiles.c's dna_update_profile. */
    char *json_unsigned = dna_identity_to_json_unsigned(identity);
    CHECK(json_unsigned != NULL, "unsigned JSON serialized");
    CHECK(json_unsigned && strstr(json_unsigned, "mlkem_pubkey") == NULL,
          "dna_identity_to_json_unsigned does NOT contain mlkem_pubkey");

    size_t siglen = sizeof(identity->signature);
    int sign_rc = qgp_dsa87_sign(identity->signature, &siglen,
                                 (uint8_t*)json_unsigned, strlen(json_unsigned), dsa_priv);
    CHECK(sign_rc == 0, "production-path signing succeeded");
    free(json_unsigned);

    char *json_full = dna_identity_to_json(identity);
    CHECK(json_full != NULL, "full (signed) JSON serialized");
    CHECK(json_full && strstr(json_full, "mlkem_pubkey") != NULL,
          "full JSON contains mlkem_pubkey");

    /* Parse the full JSON back -> field present */
    dna_unified_identity_t *parsed = NULL;
    int parse_rc = dna_identity_from_json(json_full, &parsed);
    CHECK(parse_rc == 0 && parsed != NULL, "full JSON parsed back");
    if (parsed) {
        CHECK(parsed->has_mlkem_pubkey, "parsed identity has_mlkem_pubkey == true");
        CHECK(memcmp(parsed->mlkem_pubkey, mlkem_pub, sizeof(mlkem_pub)) == 0,
              "parsed mlkem_pubkey matches original");

        /* Re-verify the signature exactly as keyserver_lookup.c:112-121 does */
        char *reverify_unsigned = dna_identity_to_json_unsigned(parsed);
        int vr = qgp_dsa87_verify(parsed->signature, sizeof(parsed->signature),
                                  (uint8_t*)reverify_unsigned, strlen(reverify_unsigned),
                                  parsed->dilithium_pubkey);
        CHECK(vr == 0, "re-verify (keyserver_lookup.c pattern) -> VALID with mlkem_pubkey present");
        free(reverify_unsigned);
        dna_identity_free(parsed);
    }

    /* Parse the SAME JSON with the field removed -> signature still VALID
     * (proves the old-client path: an old client that never heard of
     * mlkem_pubkey drops it, re-serializes the SAME unsigned JSON, and its
     * verification is unaffected). */
    char *json_stripped = strdup(json_full);
    strip_json_field_inplace(json_stripped, "mlkem_pubkey");
    CHECK(strstr(json_stripped, "mlkem_pubkey") == NULL, "mlkem_pubkey removed from stripped JSON");

    dna_unified_identity_t *old_client_view = NULL;
    parse_rc = dna_identity_from_json(json_stripped, &old_client_view);
    CHECK(parse_rc == 0 && old_client_view != NULL, "stripped JSON parsed (old-client view)");
    if (old_client_view) {
        CHECK(!old_client_view->has_mlkem_pubkey, "old-client view has_mlkem_pubkey == false");
        char *old_unsigned = dna_identity_to_json_unsigned(old_client_view);
        int vr2 = qgp_dsa87_verify(old_client_view->signature, sizeof(old_client_view->signature),
                                   (uint8_t*)old_unsigned, strlen(old_unsigned),
                                   old_client_view->dilithium_pubkey);
        CHECK(vr2 == 0, "old-client path: signature still VALID after dropping mlkem_pubkey");
        free(old_unsigned);
        dna_identity_free(old_client_view);
    }

    /* D9 (M1 delta 1, MED — verifier own finding, lens B F6; design D4 "ek
     * check at intake"): a record whose mlkem_pubkey has one 12-bit
     * coefficient patched to >= q=3329 must parse with
     * has_mlkem_pubkey == false — never a hard parse error, same fallback
     * as an absent field, so ONE malformed key served by a single node
     * cannot block a Seal/rekey that includes that peer. */
    {
        uint8_t bad_mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES];
        memcpy(bad_mlkem_pub, mlkem_pub, sizeof(bad_mlkem_pub));
        /* FIPS 203 ByteEncode(12): coefficient 0 is packed as
         * bad_mlkem_pub[0] (its low 8 bits) | low nibble of [1] (its high
         * 4 bits). Force it to 0xFFF (4095 >= q), an invalid
         * encapsulation-key coefficient (fips203.txt:2035-2050). */
        bad_mlkem_pub[0] = 0xFF;
        bad_mlkem_pub[1] |= 0x0F;
        CHECK(qgp_mlkem1024_ek_check(bad_mlkem_pub) != 0,
              "sanity: patched coefficient actually fails ek_check directly");

        dna_unified_identity_t *bad_identity = dna_identity_create();
        CHECK(bad_identity != NULL, "bad_identity created");
        if (bad_identity) {
            memcpy(bad_identity->fingerprint,
                   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                   128);
            memcpy(bad_identity->dilithium_pubkey, dsa_pub, sizeof(bad_identity->dilithium_pubkey));
            bad_identity->has_registered_name = true;
            strncpy(bad_identity->registered_name, "kemf1bad", sizeof(bad_identity->registered_name) - 1);
            bad_identity->timestamp = (uint64_t)time(NULL);
            bad_identity->version = 1;
            memcpy(bad_identity->mlkem_pubkey, bad_mlkem_pub, sizeof(bad_identity->mlkem_pubkey));
            bad_identity->has_mlkem_pubkey = true;

            char *bad_unsigned = dna_identity_to_json_unsigned(bad_identity);
            size_t bad_siglen = sizeof(bad_identity->signature);
            int bad_sign_rc = qgp_dsa87_sign(bad_identity->signature, &bad_siglen,
                                             (uint8_t*)bad_unsigned, strlen(bad_unsigned), dsa_priv);
            CHECK(bad_sign_rc == 0, "bad-record signing succeeded");
            free(bad_unsigned);

            char *bad_json = dna_identity_to_json(bad_identity);
            CHECK(bad_json != NULL, "bad record JSON serialized");

            dna_unified_identity_t *bad_parsed = NULL;
            int bad_parse_rc = dna_identity_from_json(bad_json, &bad_parsed);
            CHECK(bad_parse_rc == 0 && bad_parsed != NULL,
                  "bad record JSON parsed (parse itself does not hard-fail)");
            if (bad_parsed) {
                CHECK(!bad_parsed->has_mlkem_pubkey,
                      "D9: mlkem_pubkey failing ek_check -> has_mlkem_pubkey == false (treated as absent)");
                dna_identity_free(bad_parsed);
            }
            if (bad_json) free(bad_json);
            dna_identity_free(bad_identity);
        }
    }

    free(json_stripped);
    free(json_full);
    dna_identity_free(identity);
}

/* ============================================================================
 * Group 3 — keyserver_cache: pre-migration schema -> migration, put/get
 * ============================================================================ */

#define TEST_CACHE_DB_PATH "/tmp/test_mlkem_rollout_keyserver_cache.db"

static bool sqlite_table_has_column(const char *db_path, const char *table, const char *column) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return false;

    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table);
    sqlite3_stmt *stmt = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *name = (const char*)sqlite3_column_text(stmt, 1);
            if (name && strcmp(name, column) == 0) { found = true; break; }
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return found;
}

static void test_keyserver_cache_migration(void) {
    printf("test_keyserver_cache_migration\n");

    remove(TEST_CACHE_DB_PATH);

    /* Create the PRE-migration schema (without mlkem_pubkey), matching
     * keyserver_cache.c's CACHE_SCHEMA before MIGRATION_ADD_MLKEM. */
    {
        sqlite3 *db = NULL;
        int rc = sqlite3_open_v2(TEST_CACHE_DB_PATH, &db,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        CHECK(rc == SQLITE_OK, "pre-migration DB created");
        if (rc == SQLITE_OK) {
            const char *old_schema =
                "CREATE TABLE IF NOT EXISTS keyserver_cache ("
                "    identity TEXT PRIMARY KEY,"
                "    dilithium_pubkey BLOB NOT NULL,"
                "    kyber_pubkey BLOB NOT NULL,"
                "    cached_at INTEGER NOT NULL,"
                "    ttl_seconds INTEGER NOT NULL DEFAULT 604800"
                ");"
                "CREATE TABLE IF NOT EXISTS name_cache ("
                "    fingerprint TEXT PRIMARY KEY,"
                "    display_name TEXT NOT NULL,"
                "    avatar_base64 TEXT,"
                "    cached_at INTEGER NOT NULL,"
                "    ttl_seconds INTEGER NOT NULL DEFAULT 604800"
                ");";
            char *errmsg = NULL;
            rc = sqlite3_exec(db, old_schema, NULL, NULL, &errmsg);
            CHECK(rc == SQLITE_OK, "pre-migration schema (no mlkem_pubkey column) applied");
            if (errmsg) sqlite3_free(errmsg);
            sqlite3_close(db);
        }
    }
    CHECK(!sqlite_table_has_column(TEST_CACHE_DB_PATH, "keyserver_cache", "mlkem_pubkey"),
          "pre-migration DB confirmed: mlkem_pubkey column absent");

    /* keyserver_cache_init runs MIGRATION_ADD_MLKEM (ALTER TABLE ADD COLUMN) */
    int init_rc = keyserver_cache_init(TEST_CACHE_DB_PATH);
    CHECK(init_rc == 0, "keyserver_cache_init on pre-migration DB succeeded");
    CHECK(sqlite_table_has_column(TEST_CACHE_DB_PATH, "keyserver_cache", "mlkem_pubkey"),
          "mlkem_pubkey column exists after init (migration ran)");

    /* put/get WITH mlkem */
    uint8_t dil_pub[QGP_DSA87_PUBLICKEYBYTES], kyber_pub[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES];
    fill_random(dil_pub, sizeof(dil_pub));
    fill_random(kyber_pub, sizeof(kyber_pub));
    fill_random(mlkem_pub, sizeof(mlkem_pub));

    int put_rc = keyserver_cache_put("fp-with-mlkem", dil_pub, sizeof(dil_pub),
                                     kyber_pub, sizeof(kyber_pub),
                                     mlkem_pub, sizeof(mlkem_pub), 0);
    CHECK(put_rc == 0, "put WITH mlkem_pubkey succeeded");

    keyserver_cache_entry_t *entry = NULL;
    int get_rc = keyserver_cache_get("fp-with-mlkem", &entry);
    CHECK(get_rc == 0 && entry != NULL, "get WITH mlkem_pubkey succeeded");
    if (entry) {
        CHECK(entry->mlkem_pubkey != NULL && entry->mlkem_pubkey_len == sizeof(mlkem_pub) &&
              memcmp(entry->mlkem_pubkey, mlkem_pub, sizeof(mlkem_pub)) == 0,
              "retrieved mlkem_pubkey matches stored value");
        keyserver_cache_free_entry(entry);
    }

    /* put/get WITHOUT mlkem (cache symmetry: hit and miss both read back NULL) */
    put_rc = keyserver_cache_put("fp-without-mlkem", dil_pub, sizeof(dil_pub),
                                 kyber_pub, sizeof(kyber_pub), NULL, 0, 0);
    CHECK(put_rc == 0, "put WITHOUT mlkem_pubkey succeeded");

    entry = NULL;
    get_rc = keyserver_cache_get("fp-without-mlkem", &entry);
    CHECK(get_rc == 0 && entry != NULL, "get WITHOUT mlkem_pubkey succeeded");
    if (entry) {
        CHECK(entry->mlkem_pubkey == NULL && entry->mlkem_pubkey_len == 0,
              "retrieved mlkem_pubkey is NULL (cache symmetry: absent field -> NULL, same as miss)");
        keyserver_cache_free_entry(entry);
    }

    /* D2 (M1 delta 1, HIGH — verifier C7a, lens A F2, lens B F4): the exact
     * self-migration scenario. A pre-migration row for fp X has NO
     * mlkem_pubkey (same shape messenger_register_name writes with a
     * 365-day TTL before an identity migrates); dna_kem_f1_migrate_to_mlkem
     * must refresh that SAME row in place with the new mlkem_pubkey right
     * after saving identity.mlkem, so a subsequent get() sees it — a cache
     * HIT must not disagree with what a fresh miss+fetch would return. */
    put_rc = keyserver_cache_put("fp-migrating", dil_pub, sizeof(dil_pub),
                                 kyber_pub, sizeof(kyber_pub), NULL, 0, 365 * 24 * 60 * 60);
    CHECK(put_rc == 0, "D2: pre-migration put (no mlkem_pubkey, 365d TTL) succeeded");

    entry = NULL;
    get_rc = keyserver_cache_get("fp-migrating", &entry);
    CHECK(get_rc == 0 && entry != NULL, "D2: pre-migration get succeeded");
    if (entry) {
        CHECK(entry->mlkem_pubkey == NULL, "D2: pre-migration row confirmed to lack mlkem_pubkey");
        keyserver_cache_free_entry(entry);
    }

    /* Migration refresh — same call shape as dna_kem_f1_migrate_to_mlkem's
     * new keyserver_cache_put() (dna_engine_identity.c). */
    put_rc = keyserver_cache_put("fp-migrating", dil_pub, sizeof(dil_pub),
                                 kyber_pub, sizeof(kyber_pub),
                                 mlkem_pub, sizeof(mlkem_pub), 365 * 24 * 60 * 60);
    CHECK(put_rc == 0, "D2: migration-refresh put (WITH mlkem_pubkey) succeeded");

    entry = NULL;
    get_rc = keyserver_cache_get("fp-migrating", &entry);
    CHECK(get_rc == 0 && entry != NULL, "D2: post-migration get succeeded");
    if (entry) {
        CHECK(entry->mlkem_pubkey != NULL && entry->mlkem_pubkey_len == sizeof(mlkem_pub) &&
              memcmp(entry->mlkem_pubkey, mlkem_pub, sizeof(mlkem_pub)) == 0,
              "D2: post-migration get returns the refreshed mlkem_pubkey immediately (no stale year-long miss)");
        keyserver_cache_free_entry(entry);
    }

    keyserver_cache_cleanup();
    remove(TEST_CACHE_DB_PATH);
}

/* ============================================================================
 * Group 4 — IKP: v2 unchanged, v3 round-trip, v3 mixed-alg entries
 * ============================================================================ */

static const char *TEST_GROUP_UUID = "11111111-2222-3333-4444-555555555555";

static void test_ikp_v2_unchanged(void) {
    printf("test_ikp_v2_unchanged\n");

    uint8_t owner_pub[QGP_DSA87_PUBLICKEYBYTES], owner_priv[QGP_DSA87_SECRETKEYBYTES];
    CHECK(qgp_dsa87_keypair(owner_pub, owner_priv) == 0, "owner Dilithium5 keypair");

    uint8_t member_kyber_pub[QGP_KEM1024_PUBLICKEYBYTES], member_kyber_priv[QGP_KEM1024_SECRETKEYBYTES];
    CHECK(qgp_kem1024_keypair(member_kyber_pub, member_kyber_priv) == 0, "member round-3 keypair");

    gek_member_entry_t member = {0};
    fill_random(member.fingerprint, sizeof(member.fingerprint));
    member.kyber_pubkey = member_kyber_pub;
    member.mlkem_pubkey = NULL; /* -> ikp_build must choose v2 (old code path) */

    uint8_t gek[GEK_KEY_SIZE];
    uint8_t dht_salt[IKP_DHT_SALT_SIZE];
    fill_random(gek, sizeof(gek));
    fill_random(dht_salt, sizeof(dht_salt));

    uint8_t *packet = NULL;
    size_t packet_size = 0;
    int rc = ikp_build(TEST_GROUP_UUID, 1, gek, dht_salt, &member, 1, owner_priv,
                       &packet, &packet_size);
    CHECK(rc == 0 && packet != NULL, "ikp_build (no mlkem) succeeded");

    if (packet) {
        uint32_t magic_be;
        memcpy(&magic_be, packet, 4);
        CHECK(ntohl(magic_be) == (uint32_t)IKP_MAGIC, "packet built with v2 magic (IKP_MAGIC), unchanged");

        uint8_t gek_out[GEK_KEY_SIZE];
        uint32_t version_out = 0;
        uint8_t salt_out[IKP_DHT_SALT_SIZE];
        rc = ikp_extract(packet, packet_size, member.fingerprint, member_kyber_priv,
                         gek_out, &version_out, salt_out);
        CHECK(rc == 0 && memcmp(gek_out, gek, sizeof(gek)) == 0,
              "old ikp_extract() still unpacks a v2 packet built by the old code path");
        CHECK(memcmp(salt_out, dht_salt, sizeof(dht_salt)) == 0, "v2 dht_salt extracted correctly");

        free(packet);
    }
}

static void test_ikp_v3_roundtrip(void) {
    printf("test_ikp_v3_roundtrip\n");

    uint8_t owner_pub[QGP_DSA87_PUBLICKEYBYTES], owner_priv[QGP_DSA87_SECRETKEYBYTES];
    CHECK(qgp_dsa87_keypair(owner_pub, owner_priv) == 0, "owner Dilithium5 keypair");

    uint8_t m1_mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES], m1_mlkem_priv[QGP_MLKEM1024_SECRETKEYBYTES];
    uint8_t m2_mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES], m2_mlkem_priv[QGP_MLKEM1024_SECRETKEYBYTES];
    CHECK(qgp_mlkem1024_keypair(m1_mlkem_pub, m1_mlkem_priv) == 0, "member1 ML-KEM keypair");
    CHECK(qgp_mlkem1024_keypair(m2_mlkem_pub, m2_mlkem_priv) == 0, "member2 ML-KEM keypair");

    gek_member_entry_t members[2] = {0};
    fill_random(members[0].fingerprint, sizeof(members[0].fingerprint));
    members[0].mlkem_pubkey = m1_mlkem_pub;
    members[0].kyber_pubkey = NULL; /* unused when mlkem_pubkey present for this member */
    fill_random(members[1].fingerprint, sizeof(members[1].fingerprint));
    members[1].mlkem_pubkey = m2_mlkem_pub;
    members[1].kyber_pubkey = NULL;

    uint8_t gek[GEK_KEY_SIZE];
    uint8_t dht_salt[IKP_DHT_SALT_SIZE];
    fill_random(gek, sizeof(gek));
    fill_random(dht_salt, sizeof(dht_salt));

    uint8_t *packet = NULL;
    size_t packet_size = 0;
    int rc = ikp_build(TEST_GROUP_UUID, 2, gek, dht_salt, members, 2, owner_priv,
                       &packet, &packet_size);
    CHECK(rc == 0 && packet != NULL, "ikp_build (both members have ML-KEM) succeeded");

    if (packet) {
        uint32_t magic_be;
        memcpy(&magic_be, packet, 4);
        CHECK(ntohl(magic_be) == (uint32_t)IKP_MAGIC_V3,
              "packet built with v3 magic (all-or-nothing gate: both members have ML-KEM)");

        uint8_t gek_out[GEK_KEY_SIZE];
        uint32_t version_out = 0;
        uint8_t salt_out[IKP_DHT_SALT_SIZE];

        rc = ikp_extract_alg(packet, packet_size, members[0].fingerprint,
                             NULL, m1_mlkem_priv, gek_out, &version_out, salt_out);
        CHECK(rc == 0 && memcmp(gek_out, gek, sizeof(gek)) == 0,
              "member1 extracts GEK from v3 packet via ikp_extract_alg + its ML-KEM dk");

        memset(gek_out, 0, sizeof(gek_out));
        rc = ikp_extract_alg(packet, packet_size, members[1].fingerprint,
                             NULL, m2_mlkem_priv, gek_out, &version_out, salt_out);
        CHECK(rc == 0 && memcmp(gek_out, gek, sizeof(gek)) == 0,
              "member2 extracts GEK from v3 packet via ikp_extract_alg + its ML-KEM dk");

        /* ikp_extract() (old signature, no mlkem key) still parses/finds the
         * entry structurally but can't decapsulate an alg=3 entry. */
        memset(gek_out, 0, sizeof(gek_out));
        rc = ikp_extract(packet, packet_size, members[0].fingerprint, m1_mlkem_priv /* wrong slot on purpose */,
                         gek_out, &version_out, salt_out);
        CHECK(rc != 0, "old ikp_extract() (v2-only signature) cannot decapsulate a v3 alg=3 entry");

        free(packet);
    }
}

/* Hand-construct a v3 packet with ONE alg=2 entry and ONE alg=3 entry, using
 * the exact wire layout this dispatch defines (gek.h IKP_MEMBER_ENTRY_SIZE_V3
 * = fp(64) || alg(1) || ct(1568) || wrapped_gek(40)) — ikp_build's own gate
 * never produces a mixed packet (all-or-nothing), so this tests the READER's
 * per-entry alg dispatch directly against a packet ikp_build would not itself
 * emit but the format allows. */
static void test_ikp_v3_mixed_alg_entries(void) {
    printf("test_ikp_v3_mixed_alg_entries\n");

    uint8_t owner_pub[QGP_DSA87_PUBLICKEYBYTES], owner_priv[QGP_DSA87_SECRETKEYBYTES];
    CHECK(qgp_dsa87_keypair(owner_pub, owner_priv) == 0, "owner Dilithium5 keypair");

    uint8_t r3_pub[QGP_KEM1024_PUBLICKEYBYTES], r3_priv[QGP_KEM1024_SECRETKEYBYTES];
    uint8_t mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES], mlkem_priv[QGP_MLKEM1024_SECRETKEYBYTES];
    CHECK(qgp_kem1024_keypair(r3_pub, r3_priv) == 0, "member A round-3 keypair");
    CHECK(qgp_mlkem1024_keypair(mlkem_pub, mlkem_priv) == 0, "member B ML-KEM keypair");

    uint8_t fp_a[64], fp_b[64];
    fill_random(fp_a, sizeof(fp_a));
    fill_random(fp_b, sizeof(fp_b));

    uint8_t gek[GEK_KEY_SIZE];
    uint8_t dht_salt[IKP_DHT_SALT_SIZE];
    fill_random(gek, sizeof(gek));
    fill_random(dht_salt, sizeof(dht_salt));

    size_t packet_size = IKP_HEADER_SIZE + (IKP_MEMBER_ENTRY_SIZE_V3 * 2) + IKP_SIGNATURE_SIZE;
    uint8_t *packet = malloc(packet_size);
    CHECK(packet != NULL, "packet buffer allocated");
    if (!packet) return;

    size_t offset = 0;
    uint32_t magic_be = htonl((uint32_t)IKP_MAGIC_V3);
    memcpy(packet + offset, &magic_be, 4); offset += 4;
    memcpy(packet + offset, TEST_GROUP_UUID, 36); offset += 36;
    uint32_t version_be = htonl(3);
    memcpy(packet + offset, &version_be, 4); offset += 4;
    packet[offset] = 2; offset += 1; /* member_count */
    memcpy(packet + offset, dht_salt, IKP_DHT_SALT_SIZE); offset += IKP_DHT_SALT_SIZE;

    /* Entry A: alg 2 (round-3) */
    memcpy(packet + offset, fp_a, 64); offset += 64;
    packet[offset] = IKP_ALG_KYBER_R3; offset += 1;
    {
        uint8_t ct[QGP_KEM1024_CIPHERTEXTBYTES], kek[QGP_KEM1024_SHAREDSECRET_BYTES];
        int rc = qgp_kem1024_encapsulate(ct, kek, r3_pub);
        CHECK(rc == 0, "entry A (alg2) encapsulate succeeded");
        memcpy(packet + offset, ct, 1568); offset += 1568;
        uint8_t wrapped[40];
        rc = aes256_wrap_key(gek, GEK_KEY_SIZE, kek, wrapped);
        CHECK(rc == 0, "entry A (alg2) key-wrap succeeded");
        memcpy(packet + offset, wrapped, 40); offset += 40;
    }

    /* Entry B: alg 3 (ML-KEM-1024) */
    memcpy(packet + offset, fp_b, 64); offset += 64;
    packet[offset] = IKP_ALG_MLKEM1024; offset += 1;
    {
        uint8_t ct[QGP_MLKEM1024_CIPHERTEXTBYTES], kek[QGP_MLKEM1024_SHAREDSECRET_BYTES];
        int rc = qgp_mlkem1024_encapsulate(ct, kek, mlkem_pub);
        CHECK(rc == 0, "entry B (alg3) encapsulate succeeded");
        memcpy(packet + offset, ct, 1568); offset += 1568;
        uint8_t wrapped[40];
        rc = aes256_wrap_key(gek, GEK_KEY_SIZE, kek, wrapped);
        CHECK(rc == 0, "entry B (alg3) key-wrap succeeded");
        memcpy(packet + offset, wrapped, 40); offset += 40;
    }

    /* Sign the data portion (header + both entries) */
    size_t data_len = offset;
    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];
    size_t sig_len = 0;
    int sign_rc = qgp_dsa87_sign(signature, &sig_len, packet, data_len, owner_priv);
    CHECK(sign_rc == 0, "mixed-alg packet signed");

    packet[offset] = 23; offset += 1; /* Dilithium5 sig type, matches ikp_build */
    uint16_t sig_size_be = htons((uint16_t)sig_len);
    memcpy(packet + offset, &sig_size_be, 2); offset += 2;
    memcpy(packet + offset, signature, sig_len); offset += sig_len;
    size_t actual_packet_size = offset;

    /* Verify signature (proves the packet is well-formed per ikp_verify's
     * own v2/v3-aware entry-size accounting). */
    int verify_rc = ikp_verify(packet, actual_packet_size, owner_pub);
    CHECK(verify_rc == 0, "ikp_verify accepts the hand-built mixed-alg v3 packet");

    /* Member A (alg2 entry) extracts via its round-3 dk */
    uint8_t gek_out[GEK_KEY_SIZE];
    uint32_t version_out = 0;
    uint8_t salt_out[IKP_DHT_SALT_SIZE];
    int rc = ikp_extract_alg(packet, actual_packet_size, fp_a, r3_priv, NULL,
                             gek_out, &version_out, salt_out);
    CHECK(rc == 0 && memcmp(gek_out, gek, sizeof(gek)) == 0,
          "mixed packet: alg2 entry (member A) extracts with round-3 dk");

    /* Member B (alg3 entry) extracts via its ML-KEM dk */
    memset(gek_out, 0, sizeof(gek_out));
    rc = ikp_extract_alg(packet, actual_packet_size, fp_b, r3_priv, mlkem_priv,
                         gek_out, &version_out, salt_out);
    CHECK(rc == 0 && memcmp(gek_out, gek, sizeof(gek)) == 0,
          "mixed packet: alg3 entry (member B) extracts with ML-KEM dk");

    free(packet);
}

/* ============================================================================
 * Group 5 — Salt agreement
 * ============================================================================
 * LIMITATION (documented, not a shortcut): salt_agreement_publish()/_v2()
 * and salt_agreement_fetch()/_v2() are the ONLY exported entry points for
 * this module, and every one of them calls into nodus_ops_put_str /
 * nodus_ops_get_all_str (dht_salt_agreement.c). Inside those, do_put()/
 * do_get() (nodus_ops.c) call nodus_singleton_get() + nodus_client_is_ready()
 * and return -1 WITHOUT crashing when no nodus client is running — verified
 * by reading nodus_ops.c:79-83 — so this test process (no live nodus) can
 * safely call these functions, but the actual v1-vs-v2 packet bytes are
 * built INSIDE a `static` function (salt_agreement_publish_internal) and
 * are never returned to the caller — they are signed and handed straight to
 * nodus_ops_put_str. There is no public API that returns the built packet,
 * so "assert on the version bytes" from the dispatch's test item 5 cannot be
 * done through the public API without a live nodus instance (out of scope
 * for a compile-only dispatch). This test instead checks what IS observable
 * from outside: both the v1 and v2 entry points behave safely (no crash,
 * deterministic -1) with no live DHT, and salt_agreement_make_key() (the one
 * pure sub-function) is deterministic and symmetric in its two callers.
 * NOT DONE / reported as a limitation, not asserted as proof of the gate. */
static void test_salt_agreement(void) {
    printf("test_salt_agreement (partial — see comment above, DHT-dependent)\n");

    const char *fp_a =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *fp_b =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    char key_ab[300], key_ba[300];
    int rc1 = salt_agreement_make_key(fp_a, fp_b, key_ab, sizeof(key_ab));
    int rc2 = salt_agreement_make_key(fp_b, fp_a, key_ba, sizeof(key_ba));
    CHECK(rc1 == 0 && rc2 == 0, "salt_agreement_make_key succeeds both directions");
    CHECK(strcmp(key_ab, key_ba) == 0, "salt_agreement_make_key is symmetric (order-independent)");

    uint8_t salt[SALT_AGREEMENT_SIZE];
    uint8_t kyber_pub_a[QGP_KEM1024_PUBLICKEYBYTES], kyber_pub_b[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t mlkem_pub_a[QGP_MLKEM1024_PUBLICKEYBYTES], mlkem_pub_b[QGP_MLKEM1024_PUBLICKEYBYTES];
    uint8_t dsa_priv[QGP_DSA87_SECRETKEYBYTES];
    fill_random(salt, sizeof(salt));
    fill_random(kyber_pub_a, sizeof(kyber_pub_a));
    fill_random(kyber_pub_b, sizeof(kyber_pub_b));
    fill_random(mlkem_pub_a, sizeof(mlkem_pub_a));
    fill_random(mlkem_pub_b, sizeof(mlkem_pub_b));
    fill_random(dsa_priv, sizeof(dsa_priv)); /* not a valid Dilithium key — publish never reaches signing failure path meaningfully without a live DHT anyway */

    /* No live nodus in this test process: both must fail safely (-1), not crash. */
    int pub_v1 = salt_agreement_publish(fp_a, fp_b, salt, kyber_pub_a, kyber_pub_b, dsa_priv);
    CHECK(pub_v1 != 0, "salt_agreement_publish (v1) fails safely with no live nodus (no crash)");

    int pub_v2 = salt_agreement_publish_v2(fp_a, fp_b, salt, kyber_pub_a, kyber_pub_b,
                                          mlkem_pub_a, mlkem_pub_b, dsa_priv);
    CHECK(pub_v2 != 0, "salt_agreement_publish_v2 (both ML-KEM) fails safely with no live nodus (no crash)");

    int pub_v2_partial = salt_agreement_publish_v2(fp_a, fp_b, salt, kyber_pub_a, kyber_pub_b,
                                                   mlkem_pub_a, NULL, dsa_priv);
    CHECK(pub_v2_partial != 0,
          "salt_agreement_publish_v2 (one party lacking ML-KEM) fails safely with no live nodus (no crash)");
}

/* ============================================================================
 * Group 6 — Calls: INVITE "alg" field encode/parse
 * ============================================================================ */

static void test_call_invite_alg_field(void) {
    printf("test_call_invite_alg_field\n");

    static uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN];
    fill_random(eph_pk, sizeof(eph_pk));

    const char *call_id = "0102030405060708090a0b0c0d0e0f10";
    const char *caller_fp =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /* D18 (M1 delta 1): the approved decision record
     * (docs/plans/decisions/2026-09-23-kem-mlkem-migration.md:59, "Yeni
     * adlar") and design §5.7 specify "alg":"mlkem1024" as a STRING, not
     * the integer "alg":1 the brief's R10 text and this test previously
     * used — the record is the contract. */

    /* alg = 1 (ML-KEM) -> "alg":"mlkem1024" present */
    {
        dna_call_signal_t s = {0};
        s.kind = DNA_CALL_KIND_INVITE;
        s.call_id_hex = call_id;
        s.seq = 1;
        s.caller_fp_hex = caller_fp;
        s.eph_pk = eph_pk;
        s.alg = 1;

        char out[DNA_CALL_SIG_MAX_BODY];
        size_t out_len = 0;
        int rc = dna_call_build_body(&s, out, sizeof(out), &out_len);
        CHECK(rc == DNA_CALL_OK, "build INVITE with alg=1 succeeded");
        CHECK(strstr(out, "\"alg\":\"mlkem1024\"") != NULL, "encoded body contains \"alg\":\"mlkem1024\"");

        dna_call_parsed_t p;
        rc = dna_call_parse_body(out, out_len, &p);
        CHECK(rc == DNA_CALL_OK, "parse INVITE with alg=\"mlkem1024\" succeeded");
        CHECK(p.alg == 1, "parsed alg == 1");
    }

    /* An unrecognized "alg" string degrades to round-3 (0), never a hard
     * parse error — same rule as "alg" absent. Build a genuinely valid
     * alg=1 body (correct-length base64 eph_pk and all), then swap the
     * 9-char "mlkem1024" for another 9-char string in place so the rest of
     * the body (and its length) stays byte-identical and still parses. */
    {
        dna_call_signal_t s = {0};
        s.kind = DNA_CALL_KIND_INVITE;
        s.call_id_hex = call_id;
        s.seq = 3;
        s.caller_fp_hex = caller_fp;
        s.eph_pk = eph_pk;
        s.alg = 1;

        char out[DNA_CALL_SIG_MAX_BODY];
        size_t out_len = 0;
        int rc = dna_call_build_body(&s, out, sizeof(out), &out_len);
        CHECK(rc == DNA_CALL_OK, "build INVITE with alg=1 succeeded (for the unknown-alg-string case)");

        char *alg_val = strstr(out, "mlkem1024");
        CHECK(alg_val != NULL, "built body contains the mlkem1024 alg value to overwrite");
        if (alg_val) {
            memcpy(alg_val, "future999", 9);   /* same 9-byte length as "mlkem1024" */
        }

        dna_call_parsed_t p;
        rc = dna_call_parse_body(out, out_len, &p);
        CHECK(rc == DNA_CALL_OK, "parse INVITE with unrecognized alg string still succeeds overall");
        CHECK(p.alg == 0, "unrecognized alg string parses back to 0 (round-3), not a hard error");
    }

    /* alg = 0 (default, round-3) -> "alg" absent, parses back to 0 */
    {
        dna_call_signal_t s = {0};
        s.kind = DNA_CALL_KIND_INVITE;
        s.call_id_hex = call_id;
        s.seq = 2;
        s.caller_fp_hex = caller_fp;
        s.eph_pk = eph_pk;
        s.alg = 0;

        char out[DNA_CALL_SIG_MAX_BODY];
        size_t out_len = 0;
        int rc = dna_call_build_body(&s, out, sizeof(out), &out_len);
        CHECK(rc == DNA_CALL_OK, "build INVITE with alg=0 succeeded");
        CHECK(strstr(out, "\"alg\"") == NULL, "encoded body omits \"alg\" entirely when 0 (byte-identical to pre-R10)");

        dna_call_parsed_t p;
        rc = dna_call_parse_body(out, out_len, &p);
        CHECK(rc == DNA_CALL_OK, "parse INVITE without alg succeeded");
        CHECK(p.alg == 0, "parsed alg defaults to 0 when field absent");
    }
}

/* ============================================================================
 * Group 7 — mnemonic v2 save/load round-trip, mnemonic_storage_exists
 * ============================================================================ */

#define TEST_MNEMONIC_DIR "/tmp/test_mlkem_rollout_mnemonic_dir"

static void test_mnemonic_v2_roundtrip(void) {
    printf("test_mnemonic_v2_roundtrip\n");

    /* Clean slate */
    remove(TEST_MNEMONIC_DIR "/mnemonic.v2.enc");
    remove(TEST_MNEMONIC_DIR "/mnemonic.enc");
    (void)system("mkdir -p " TEST_MNEMONIC_DIR);

    CHECK(!mnemonic_storage_exists(TEST_MNEMONIC_DIR),
          "mnemonic_storage_exists() false before any file written");

    uint8_t mlkem_pub[QGP_MLKEM1024_PUBLICKEYBYTES], mlkem_priv[QGP_MLKEM1024_SECRETKEYBYTES];
    CHECK(qgp_mlkem1024_keypair(mlkem_pub, mlkem_priv) == 0, "ML-KEM keypair for mnemonic v2 test");

    const char *mnemonic = "abandon ability able about above absent absorb abstract absurd abuse access accident";

    int save_rc = mnemonic_storage_save_v2(mnemonic, mlkem_pub, TEST_MNEMONIC_DIR);
    CHECK(save_rc == 0, "mnemonic_storage_save_v2 succeeded");
    CHECK(mnemonic_storage_v2_exists(TEST_MNEMONIC_DIR), "mnemonic.v2.enc exists after save");

    /* mnemonic_storage_exists() true with ONLY the v2 file (no legacy mnemonic.enc) */
    CHECK(mnemonic_storage_exists(TEST_MNEMONIC_DIR),
          "mnemonic_storage_exists() true with only mnemonic.v2.enc present (R4)");

    char loaded[BIP39_MAX_MNEMONIC_LENGTH] = {0};
    int load_rc = mnemonic_storage_load_v2(loaded, sizeof(loaded), mlkem_priv, TEST_MNEMONIC_DIR);
    CHECK(load_rc == 0, "mnemonic_storage_load_v2 succeeded");
    CHECK(strcmp(loaded, mnemonic) == 0, "loaded v2 mnemonic matches saved value");

    /* Wrong key must not decrypt */
    uint8_t wrong_pub[QGP_MLKEM1024_PUBLICKEYBYTES], wrong_priv[QGP_MLKEM1024_SECRETKEYBYTES];
    CHECK(qgp_mlkem1024_keypair(wrong_pub, wrong_priv) == 0, "second ML-KEM keypair generated");
    char loaded_wrong[BIP39_MAX_MNEMONIC_LENGTH] = {0};
    int wrong_rc = mnemonic_storage_load_v2(loaded_wrong, sizeof(loaded_wrong), wrong_priv, TEST_MNEMONIC_DIR);
    CHECK(wrong_rc != 0, "mnemonic_storage_load_v2 with the WRONG private key fails");

    remove(TEST_MNEMONIC_DIR "/mnemonic.v2.enc");
    (void)system("rmdir " TEST_MNEMONIC_DIR " 2>/dev/null");
}

/* ============================================================================
 * Main
 * ============================================================================ */

int main(void) {
    srand((unsigned int)time(NULL));

    printf("=== KEM Faz 1 (M1) rollout tests ===\n\n");

    test_seal_alg_matrix();
    test_seal_alg3_multi_recipient();
    test_identity_record_mlkem_pubkey();
    test_keyserver_cache_migration();
    test_ikp_v2_unchanged();
    test_ikp_v3_roundtrip();
    test_ikp_v3_mixed_alg_entries();
    test_salt_agreement();
    test_call_invite_alg_field();
    test_mnemonic_v2_roundtrip();

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
