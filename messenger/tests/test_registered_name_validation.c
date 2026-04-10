/*
 * Test: dht_keyserver_is_valid_registered_name
 *
 * Verifies the validator rejects fingerprint-format strings (the legacy bug
 * where reverse_lookup returned "<16-hex>..." on lookup failure) and accepts
 * real DNA names.
 *
 * Regression guard for the fix to keyserver_lookup.c where the "no candidate"
 * and "verification failed" branches used to set *identity_out to a shortened
 * fingerprint string and return 0 (success), causing startup backfill in
 * Flutter to cache that as the user's registered name and bypass the
 * registration gate in main.dart.
 */

#include "dht/core/dht_keyserver.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, bool expected, const char *desc) {
    bool got = dht_keyserver_is_valid_registered_name(name);
    const char *name_str = name ? name : "(null)";
    if (got == expected) {
        printf("  PASS: %-40s  (%s)\n", desc, name_str);
    } else {
        printf("  FAIL: %-40s  (%s)  expected=%d got=%d\n",
               desc, name_str, expected, got);
        failures++;
    }
}

int main(void) {
    printf("Test: dht_keyserver_is_valid_registered_name\n");
    printf("=============================================\n\n");

    printf("Rejected inputs:\n");
    check(NULL,                                      false, "NULL pointer");
    check("",                                        false, "empty string");
    check("f8ebbbb9cb834ab8...",                     false, "legacy fingerprint fallback (16 hex + ...)");
    check("abcdef0123456789...",                     false, "another 16-hex + ...");
    check("name...",                                 false, "trailing ... on short name");
    check("f8ebbbb9cb834ab8",                        false, "bare 16 hex (looks like fp prefix)");
    check("f8ebbbb9cb834ab8fcc826f5b9e56316",        false, "32 hex chars (fingerprint-like)");
    check("0123456789abcdef0123456789abcdef",        false, "all-hex long string");
    check("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", false, "overlong (>=64 chars)");

    printf("\nAccepted inputs:\n");
    check("nocdem",      true,  "normal short name");
    check("punk",        true,  "short alnum");
    check("alice",       true,  "alphabetic");
    check("user123",     true,  "mixed alnum");
    check("nocdem-test", true,  "with dash");
    check("a",           true,  "single char");
    check("f8ebbbb9cb",  true,  "10 hex chars (below threshold)");
    check("abc",         true,  "3 hex chars");
    check("test_user",   true,  "with underscore");

    printf("\n");
    if (failures == 0) {
        printf("All %d checks passed.\n", 18);
        return 0;
    } else {
        printf("FAILED: %d checks failed.\n", failures);
        return 1;
    }
}
