/*
 * Unit tests for reaction JSON helpers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dna/reaction_json.h"

static int g_failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_failures++; \
    } \
} while (0)

static void test_build_parse_roundtrip(void) {
    char json[256];
    int rc = dna_reaction_build_json(
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "\xe2\x9d\xa4\xef\xb8\x8f", /* ❤️ in UTF-8 */
        "add", json, sizeof(json));
    CHECK(rc == 0);
    CHECK(strstr(json, "\"target\":\"abcdef") != NULL);
    CHECK(strstr(json, "\"op\":\"add\"") != NULL);

    char target[65] = {0};
    CHECK(dna_reaction_parse_target(json, target, sizeof(target)) == 0);
    CHECK(strlen(target) == 64);
    CHECK(strncmp(target, "abcdef0123456789", 16) == 0);

    char emoji[8] = {0};
    CHECK(dna_reaction_parse_emoji(json, emoji, sizeof(emoji)) == 0);
    CHECK(strcmp(emoji, "\xe2\x9d\xa4\xef\xb8\x8f") == 0);

    char op[8] = {0};
    CHECK(dna_reaction_parse_op(json, op, sizeof(op)) == 0);
    CHECK(strcmp(op, "add") == 0);

    printf("test_build_parse_roundtrip: %s\n", g_failures ? "FAIL" : "PASS");
}

static void test_parse_target_too_short(void) {
    int before = g_failures;
    char target[65];
    CHECK(dna_reaction_parse_target("{\"target\":\"deadbeef\"}", target, sizeof(target)) == -1);
    printf("test_parse_target_too_short: %s\n", g_failures > before ? "FAIL" : "PASS");
}

static void test_parse_target_non_hex(void) {
    int before = g_failures;
    char target[65];
    CHECK(dna_reaction_parse_target(
        "{\"target\":\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"}",
        target, sizeof(target)) == -1);
    printf("test_parse_target_non_hex: %s\n", g_failures > before ? "FAIL" : "PASS");
}

static void test_parse_null_inputs(void) {
    int before = g_failures;
    char buf[65];
    CHECK(dna_reaction_parse_target(NULL, buf, sizeof(buf)) == -1);
    CHECK(dna_reaction_parse_emoji(NULL, buf, sizeof(buf)) == -1);
    CHECK(dna_reaction_parse_op(NULL, buf, sizeof(buf)) == -1);
    CHECK(dna_reaction_build_json(NULL, "x", "add", buf, sizeof(buf)) == -1);
    printf("test_parse_null_inputs: %s\n", g_failures > before ? "FAIL" : "PASS");
}

static void test_remove_op(void) {
    int before = g_failures;
    char json[256];
    CHECK(dna_reaction_build_json(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "\xf0\x9f\x94\xa5", /* 🔥 */
        "remove", json, sizeof(json)) == 0);
    char op[8];
    CHECK(dna_reaction_parse_op(json, op, sizeof(op)) == 0);
    CHECK(strcmp(op, "remove") == 0);
    printf("test_remove_op: %s\n", g_failures > before ? "FAIL" : "PASS");
}

static void test_buffer_too_small(void) {
    int before = g_failures;
    char small[10];
    CHECK(dna_reaction_build_json(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "x", "add", small, sizeof(small)) == -1);
    printf("test_buffer_too_small: %s\n", g_failures > before ? "FAIL" : "PASS");
}

int main(void) {
    test_build_parse_roundtrip();
    test_parse_target_too_short();
    test_parse_target_non_hex();
    test_parse_null_inputs();
    test_remove_op();
    test_buffer_too_small();
    if (g_failures == 0) {
        printf("All reaction tests passed (6/6).\n");
        return 0;
    }
    printf("Reaction tests FAILED: %d check(s) failed.\n", g_failures);
    return 1;
}
