/**
 * test_ruleset_pins — the checked-in generated header matches the node
 *
 * Governing record: docs/plans/decisions/2026-09-25-web-wallet-nodus-send-
 * transport.md, addendum 2026-09-29 "Yol 2": the browser wallet reads the
 * CORE ruleset identity and the SYSTEM metering policy from a GENERATED
 * header (nodus/include/nodus/nodus_ruleset_pins.h); a ctest regenerates it
 * on every run and compares it byte for byte with the node's table.
 *
 * What it proves:
 *   R1  a fresh render of the header (nodus_ruleset_pins_render, the same
 *       function the gen_ruleset_pins tool writes with) is BYTE-IDENTICAL to
 *       the checked-in file. Any ruleset / policy change in
 *       nodus_witness_runtime.c without a regenerated header fails here.
 *       The fresh render is also written to a temp file whose path is
 *       printed, so a failure can be diffed.
 *   R2  the header's own policy fields rebuild a policy whose
 *       dna_meter_policy_digest equals the header's digest — the exact
 *       self-check the browser module must run at start-up, done here on
 *       the native side so the recipe itself is proven.
 *   R3  the header's CORE tuple resolves in the production table
 *       (nodus_runtime_lookup) — the identity a CORE leg will carry is one
 *       the node accepts.
 *   R4  the header's SYSTEM tuple (added for the staking builder,
 *       nodus/src/client/nodus_v2_stake.c) resolves in the production table
 *       AND equals the table's SYSTEM entry (version + hash) — R1 already
 *       byte-compares it; R4 checks it names the SYSTEM domain's row.
 *
 * What it requires: default build. NODUS_RULESET_PINS_HEADER_PATH (the
 * checked-in header, absolute) is set by CMake. No environment, no ports.
 * What it leaves behind: one file in the system temp dir
 * (test_ruleset_pins_XXXXXX), removed on PASS, kept on FAIL for the diff.
 * How it can lie: R1 compares against the table of THIS build — a build
 * with different compile-time constants than the shipped node compares
 * against its own values, not the shipped ones.
 */

#include "nodus/nodus_ruleset_pins.h"
#include "witness/nodus_witness_runtime.h"
#include "dnac/res_meter.h"
#include "dnac/domain_wire.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef NODUS_RULESET_PINS_HEADER_PATH
#error "NODUS_RULESET_PINS_HEADER_PATH must be defined by CMake"
#endif

/* Defined in nodus/tools/gen_ruleset_pins.c, linked into this test with
 * GEN_RULESET_PINS_NO_MAIN (the tool has no header of its own). */
int nodus_ruleset_pins_render(char **out, size_t *out_len);

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    while (buf) {
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (len < cap) break;
        char *nb = realloc(buf, cap * 2);
        if (!nb) { free(buf); buf = NULL; break; }
        buf = nb;
        cap *= 2;
    }
    fclose(f);
    if (buf) *len_out = len;
    return buf;
}

static void test_render_matches_checked_in(void) {
    TEST("R1 fresh render == checked-in nodus_ruleset_pins.h (bytes)");

    char *fresh = NULL;
    size_t fresh_len = 0;
    if (nodus_ruleset_pins_render(&fresh, &fresh_len) != 0 || !fresh) {
        FAIL("render failed (runtime selfcheck or policy digest)");
        return;
    }

    char tmp_path[] = "/tmp/test_ruleset_pins_XXXXXX";
    int fd = mkstemp(tmp_path);
    bool tmp_ok = false;
    if (fd >= 0) {
        FILE *f = fdopen(fd, "wb");
        if (f) {
            tmp_ok = fwrite(fresh, 1, fresh_len, f) == fresh_len;
            if (fclose(f) != 0) tmp_ok = false;
        } else {
            close(fd);
        }
    }

    size_t have_len = 0;
    char *have = read_file(NODUS_RULESET_PINS_HEADER_PATH, &have_len);
    if (!have) {
        FAIL("cannot read the checked-in header");
        free(fresh);
        return;
    }

    size_t min = have_len < fresh_len ? have_len : fresh_len;
    size_t diff_at = min;
    for (size_t i = 0; i < min; i++)
        if (have[i] != fresh[i]) { diff_at = i; break; }

    if (have_len == fresh_len && diff_at == min) {
        PASS();
        if (tmp_ok) unlink(tmp_path);
    } else {
        FAIL("header is stale — run the regen_ruleset_pins target");
        printf("      first difference at byte %zu (checked-in %zu B, fresh %zu B)\n",
               diff_at, have_len, fresh_len);
        if (tmp_ok)
            printf("      diff %s %s\n", NODUS_RULESET_PINS_HEADER_PATH, tmp_path);
    }
    free(have);
    free(fresh);
}

static void test_policy_self_check_recipe(void) {
    TEST("R2 header policy fields rebuild the header policy digest");

    static const uint32_t ops[NODUS_PIN_SYS_METER_OP_COUNT] = NODUS_PIN_SYS_METER_OPS_INIT;
    static const uint64_t wts[NODUS_PIN_SYS_METER_OP_COUNT] = NODUS_PIN_SYS_METER_OP_WEIGHTS_INIT;
    static const uint8_t want[DNA_DOM_HASH_LEN] = NODUS_PIN_SYS_METER_POLICY_DIGEST_INIT;

    dna_meter_policy_t *p = calloc(1, sizeof(*p));
    if (!p) { FAIL("alloc"); return; }
    p->policy_version      = NODUS_PIN_SYS_METER_POLICY_VERSION;
    p->w_base              = NODUS_PIN_SYS_METER_W_BASE;
    p->w_callbyte          = NODUS_PIN_SYS_METER_W_CALLBYTE;
    p->w_authbyte          = NODUS_PIN_SYS_METER_W_AUTHBYTE;
    p->w_effect            = NODUS_PIN_SYS_METER_W_EFFECT;
    p->w_effectbyte        = NODUS_PIN_SYS_METER_W_EFFECTBYTE;
    p->w_read              = NODUS_PIN_SYS_METER_W_READ;
    p->w_write             = NODUS_PIN_SYS_METER_W_WRITE;
    p->max_block_env_bytes = NODUS_PIN_SYS_METER_MAX_BLOCK_ENV_BYTES;
    bool ok = true;
    for (uint32_t i = 0; i < NODUS_PIN_SYS_METER_OP_COUNT; i++)
        if (dna_meter_op_set(p, ops[i], wts[i]) != 0) ok = false;

    uint8_t got[DNA_DOM_HASH_LEN];
    ok = ok && dna_meter_policy_seal(p) == 0 &&
         dna_meter_policy_digest(p, got) == 0 &&
         memcmp(got, want, DNA_DOM_HASH_LEN) == 0;
    free(p);
    if (ok) PASS(); else FAIL("digest recomputed from the header fields differs");
}

static void test_core_tuple_resolves(void) {
    TEST("R3 header CORE tuple resolves in the production runtime table");
    static const uint8_t h[DNA_DOM_HASH_LEN] = NODUS_PIN_CORE_RULESET_HASH_INIT;
    const nodus_domain_runtime_t *rt =
        nodus_runtime_lookup(NODUS_PIN_CORE_DOMAIN_ID,
                             (uint8_t)NODUS_PIN_CORE_RUNTIME_KIND,
                             NODUS_PIN_CORE_RUNTIME_ABI,
                             NODUS_PIN_CORE_RULESET_VERSION, h);
    if (rt) PASS(); else FAIL("the node would not resolve this CORE identity");
}

static void test_sys_tuple_resolves(void) {
    TEST("R4 header SYSTEM tuple resolves and equals the table's SYSTEM entry");
    static const uint8_t h[DNA_DOM_HASH_LEN] = NODUS_PIN_SYS_RULESET_HASH_INIT;
    const nodus_domain_runtime_t *rt =
        nodus_runtime_lookup(NODUS_PIN_SYS_DOMAIN_ID,
                             (uint8_t)NODUS_PIN_SYS_RUNTIME_KIND,
                             NODUS_PIN_SYS_RUNTIME_ABI,
                             NODUS_PIN_SYS_RULESET_VERSION, h);
    size_t n = 0;
    const nodus_domain_runtime_t *t = nodus_runtime_builtin_table(&n);
    const nodus_domain_runtime_t *sys = NULL;
    for (size_t i = 0; t && i < n; i++)
        if (t[i].domain_id == DNA_DOMAIN_SYSTEM) sys = &t[i];
    if (!rt) { FAIL("the node would not resolve this SYSTEM identity"); return; }
    if (!sys || NODUS_PIN_SYS_DOMAIN_ID != DNA_DOMAIN_SYSTEM ||
        sys->ruleset_version != NODUS_PIN_SYS_RULESET_VERSION ||
        memcmp(sys->ruleset_hash, h, DNA_DOM_HASH_LEN) != 0) {
        FAIL("the pinned SYSTEM tuple is not the table's SYSTEM entry");
        return;
    }
    PASS();
}

int main(void) {
    printf("=== Generated ruleset pins header (Yol 2) ===\n");
    test_render_matches_checked_in();
    test_policy_self_check_recipe();
    test_core_tuple_resolves();
    test_sys_tuple_resolves();
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
