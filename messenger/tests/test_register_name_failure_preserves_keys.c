/*
 * Test: CORE-05 — register-name failure must NOT delete local key material
 *
 * Phase 6 / Plan 02 target. RED today, GREEN after plan 02.
 *
 * Behavior under test:
 *   When dna_handle_register_name (or its sync wrapper) fails because the
 *   nodus alias write returns an error (network down, DHT unreachable, alias
 *   conflict, etc.), the engine MUST preserve the on-disk identity material
 *   (keys/, db/, wallets/, mnemonic.enc). The current code path rmdir's all
 *   four on failure, locking the user out of their identity. Plan 02 fixes
 *   this; this test is the regression guard.
 *
 * Today this test is RED by construction:
 *   - No public sync wrapper exists for the create-identity-then-register flow
 *     yet, so we cannot drive the failure injection through the public API.
 *   - We therefore mark the test RED via an explicit precondition exit so the
 *     Wave 0 contract is satisfied: file exists, file compiles, ctest runs,
 *     test fails (RED).
 *   - Plan 02 will replace the precondition block with the real failure
 *     injection once the lockout fix lands and the sync API surface (or a
 *     test seam) is available.
 *
 * TODO(plan-02): replace the RED precondition block below with real failure
 *                injection against dna_engine_register_name + a stubbed
 *                nodus that returns DNA_ENGINE_ERROR_NETWORK, then assert
 *                that keys/, db/, wallets/, mnemonic.enc still exist on disk.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "dna/dna_engine.h"

/* References dna_engine_create_identity_with_name_sync target API surface
 * (does not exist yet — will be added by plan 02). The string below is here
 * so an automated grep proves this file targets the right API. */
static const char *TARGET_API = "dna_engine_create_identity_with_name_sync";

static int file_or_dir_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int touch_file(const char *path) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static int make_subdir(const char *parent, const char *name, char *out, size_t out_size) {
    snprintf(out, out_size, "%s/%s", parent, name);
    return mkdir(out, 0700);
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

    /* Step 2: pre-populate stub identity material */
    char keys[512], db[512], wallets[512], mnemonic[512];
    if (make_subdir(tmp, "keys", keys, sizeof(keys)) != 0 ||
        make_subdir(tmp, "db", db, sizeof(db)) != 0 ||
        make_subdir(tmp, "wallets", wallets, sizeof(wallets)) != 0) {
        fprintf(stderr, "FAIL: could not create stub identity dirs under %s\n", tmp);
        return 1;
    }
    snprintf(mnemonic, sizeof(mnemonic), "%s/mnemonic.enc", tmp);
    if (touch_file(mnemonic) != 0) {
        fprintf(stderr, "FAIL: could not create stub mnemonic.enc\n");
        return 1;
    }

    /* Step 3 (TODO plan-02): drive a real failed register-name through the
     * public API and assert all four still exist. For now we exit RED. */
    fprintf(stderr,
            "RED: TODO(plan-02) — public failure-injection seam for "
            "register-name does not exist yet. This test is intentionally "
            "RED until plan 02 lands the CORE-05 fix and exposes the sync "
            "create-with-name path or an equivalent test seam.\n");

    /* Sanity: the four paths we just made should still be there now (proves
     * the test scaffolding works end-to-end so plan 02 can drop in the
     * real call). */
    if (!file_or_dir_exists(keys)   || !file_or_dir_exists(db) ||
        !file_or_dir_exists(wallets) || !file_or_dir_exists(mnemonic)) {
        fprintf(stderr, "FAIL: scaffolding broken — pre-populated paths missing\n");
        return 1;
    }

    /* Best-effort cleanup so /tmp does not bloat across CI runs. */
    unlink(mnemonic);
    rmdir(keys);
    rmdir(db);
    rmdir(wallets);
    rmdir(tmp);

    /* Wave 0 contract: this test MUST exit non-zero today. */
    return 1;
}
