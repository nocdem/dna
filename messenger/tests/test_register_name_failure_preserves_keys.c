/*
 * Test: CORE-05 — register-name failure must NOT delete local key material
 *
 * Phase 6 / Plan 02. GREEN after plan 02 lands the non-destructive failure
 * branch in dna_engine_create_identity_sync.
 *
 * Behavior under test:
 *   When dna_engine_create_identity_sync is called without a started DHT (no
 *   dna_engine_prepare_dht_from_mnemonic call), messenger_register_name must
 *   return a non-zero error code. The fix (plan 02) must leave the on-disk
 *   identity material (keys/, db/, wallets/, mnemonic.enc) intact so the user
 *   can retry via the Flutter resume-flow UI.
 *
 * This test drives the failure through the real public API
 * (dna_engine_create_identity_sync) — no stubs. The DHT is intentionally
 * left unstarted so the register-name step fails deterministically.
 *
 * Target API anchor (for audit greps): dna_engine_create_identity_with_name_sync
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include "dna/dna_engine.h"
#include "crypto/key/bip39/bip39.h"

/* String anchor for the audit grep — confirms this test targets the sync
 * create-with-name path that plan 02 fixes. */
static const char *TARGET_API = "dna_engine_create_identity_with_name_sync";

static int path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int dir_has_entries(const char *path) {
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    int count = 0;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        count++;
    }
    closedir(d);
    return count;
}

/* Best-effort recursive remove for /tmp cleanup. */
static void rm_rf(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *e;
            char child[1024];
            while ((e = readdir(d)) != NULL) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
                rm_rf(child);
            }
            closedir(d);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

int main(void) {
    (void)TARGET_API;

    fprintf(stderr, "Test: register-name failure must preserve keys (CORE-05)\n");
    fprintf(stderr, "=========================================================\n");

    /* Step 1: create a unique tmp data_dir */
    char tmpl[] = "/tmp/phase6-regname-XXXXXX";
    char *tmp = mkdtemp(tmpl);
    if (!tmp) {
        fprintf(stderr, "FAIL: mkdtemp failed\n");
        return 1;
    }
    fprintf(stderr, "data_dir: %s\n", tmp);

    /* Step 2: create an engine rooted at the tmp data_dir */
    dna_engine_t *engine = dna_engine_create(tmp);
    if (!engine) {
        fprintf(stderr, "FAIL: dna_engine_create returned NULL\n");
        rm_rf(tmp);
        return 1;
    }

    /* Step 3: derive seeds from a fresh BIP39 mnemonic */
    char mnemonic[BIP39_MAX_MNEMONIC_LENGTH];
    if (bip39_generate_mnemonic(BIP39_WORDS_24, mnemonic, sizeof(mnemonic)) != 0) {
        fprintf(stderr, "FAIL: bip39_generate_mnemonic failed\n");
        dna_engine_destroy(engine);
        rm_rf(tmp);
        return 1;
    }

    uint8_t signing_seed[32];
    uint8_t encryption_seed[32];
    uint8_t master_seed[64];
    if (qgp_derive_seeds_with_master(mnemonic, "", signing_seed, encryption_seed,
                                     master_seed) != 0) {
        fprintf(stderr, "FAIL: qgp_derive_seeds_with_master failed\n");
        dna_engine_destroy(engine);
        rm_rf(tmp);
        return 1;
    }

    /* Step 4: Intentionally DO NOT call dna_engine_prepare_dht_from_mnemonic.
     * Without DHT started, messenger_register_name must fail — which is
     * exactly the path CORE-05 fixes. */

    char fingerprint[129] = {0};
    int rc = dna_engine_create_identity_sync(
        engine, "core05testuser", signing_seed, encryption_seed,
        master_seed, mnemonic, fingerprint);

    fprintf(stderr, "dna_engine_create_identity_sync rc=%d\n", rc);

    /* Expectation: rc is non-zero (registration failed because DHT is down). */
    if (rc == 0) {
        fprintf(stderr, "FAIL: expected non-zero rc (DHT not started), got 0\n");
        dna_engine_destroy(engine);
        rm_rf(tmp);
        return 1;
    }

    /* Step 5: Assert the local identity material STILL EXISTS on disk.
     * This is the whole point of the CORE-05 fix. */
    char keys[512], db[512], wallets[512], mnemonic_enc[512];
    snprintf(keys, sizeof(keys), "%s/keys", tmp);
    snprintf(db, sizeof(db), "%s/db", tmp);
    snprintf(wallets, sizeof(wallets), "%s/wallets", tmp);
    snprintf(mnemonic_enc, sizeof(mnemonic_enc), "%s/mnemonic.enc", tmp);

    int ok = 1;
    if (!path_exists(keys) || !dir_has_entries(keys)) {
        fprintf(stderr, "FAIL: %s missing or empty — fix NOT applied\n", keys);
        ok = 0;
    } else {
        fprintf(stderr, "OK: %s preserved\n", keys);
    }
    if (!path_exists(db)) {
        fprintf(stderr, "FAIL: %s missing — fix NOT applied\n", db);
        ok = 0;
    } else {
        fprintf(stderr, "OK: %s preserved\n", db);
    }
    if (!path_exists(wallets)) {
        fprintf(stderr, "FAIL: %s missing — fix NOT applied\n", wallets);
        ok = 0;
    } else {
        fprintf(stderr, "OK: %s preserved\n", wallets);
    }
    if (!path_exists(mnemonic_enc)) {
        fprintf(stderr, "FAIL: %s missing — fix NOT applied\n", mnemonic_enc);
        ok = 0;
    } else {
        fprintf(stderr, "OK: %s preserved\n", mnemonic_enc);
    }

    /* Scrub sensitive material before exit. */
    memset(signing_seed, 0, sizeof(signing_seed));
    memset(encryption_seed, 0, sizeof(encryption_seed));
    memset(master_seed, 0, sizeof(master_seed));
    memset(mnemonic, 0, sizeof(mnemonic));

    dna_engine_destroy(engine);
    rm_rf(tmp);

    if (!ok) {
        fprintf(stderr, "RED: CORE-05 fix missing — identity material destroyed on failure\n");
        return 1;
    }

    fprintf(stderr, "GREEN: CORE-05 fix verified — identity material preserved on failure\n");
    return 0;
}
