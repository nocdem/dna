/**
 * @file test_conf_txbind.c
 * @brief B1 Stage-1 — tx_binding gate (rejection map + tx-bound root, SEC-5).
 *
 * (map)   64-byte sighash → 4 Goldilocks via the challenger rejection convention:
 *         a ≥p group is SKIPPED, first 4 canonical taken; all-≥p ⇒ fail-close.
 * (bind)  tx1 ⇒ bound_root R1, tx2 ⇒ R2, R1 ≠ R2 — a proof bound to tx1 does not
 *         transfer to tx2 (the SEC-5 replay-resistance mechanism).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "../conf_txbind.h"

#define GOLD_P ((uint64_t)0xFFFFFFFF00000001ULL)

static int fails = 0;
static void ok(const char *name, int cond) {
    printf("  [%s] %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond) fails++;
}

static void put_le(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
}

int main(void) {
    /* --- map: a ≥p group is SKIPPED, first 4 canonical taken --- */
    {
        uint8_t sh[64];
        memset(sh, 0, sizeof(sh));
        memset(sh, 0xFF, 8);          /* group 0 = 0xFFFF...FF ≥ p → skip */
        put_le(sh + 8, 100);
        put_le(sh + 16, 200);
        put_le(sh + 24, 300);
        put_le(sh + 32, 400);
        uint64_t out[4];
        int r = conf_txbind_map(sh, out);
        ok("map accepts (skips 1 ≥p group)", r);
        ok("map skipped the ≥p group 0",
           out[0] == 100 && out[1] == 200 && out[2] == 300 && out[3] == 400);
        /* every output is canonical */
        int canon = 1;
        for (int i = 0; i < 4; i++) if (out[i] >= GOLD_P) canon = 0;
        ok("map outputs canonical (< p)", canon);
    }

    /* --- map: all groups ≥ p ⇒ fail-close --- */
    {
        uint8_t sh[64];
        memset(sh, 0xFF, sizeof(sh)); /* every 8-byte group = 0xFFFF...FF ≥ p */
        uint64_t out[4];
        ok("map fail-close when < 4 canonical", conf_txbind_map(sh, out) == false);
    }

    /* --- map determinism --- */
    {
        uint8_t sh[64];
        for (int i = 0; i < 64; i++) sh[i] = (uint8_t)(i * 7 + 1);
        uint64_t a[4], b[4];
        int ra = conf_txbind_map(sh, a), rb = conf_txbind_map(sh, b);
        ok("map deterministic", ra && rb && memcmp(a, b, sizeof(a)) == 0);
    }

    /* --- sandbox sighash: deterministic + domain-separated --- */
    {
        const uint8_t ctx[] = {1, 2, 3, 4, 5};
        uint8_t h1[64], h2[64];
        conf_txbind_sandbox_sighash(ctx, sizeof(ctx), h1);
        conf_txbind_sandbox_sighash(ctx, sizeof(ctx), h2);
        ok("sandbox sighash deterministic", memcmp(h1, h2, 64) == 0);
        const uint8_t ctx2[] = {1, 2, 3, 4, 6};
        uint8_t h3[64];
        conf_txbind_sandbox_sighash(ctx2, sizeof(ctx2), h3);
        ok("different ctx ⇒ different sighash", memcmp(h1, h3, 64) != 0);
    }

    /* --- tx-bound root: proof bound to tx1 does not transfer to tx2 --- */
    {
        const uint64_t commitment_root[4] = {11, 22, 33, 44};
        const uint8_t ctx1[] = "tx-alpha";
        const uint8_t ctx2[] = "tx-beta";
        uint8_t sh1[64], sh2[64];
        conf_txbind_sandbox_sighash(ctx1, sizeof(ctx1), sh1);
        conf_txbind_sandbox_sighash(ctx2, sizeof(ctx2), sh2);
        uint64_t tb1[4], tb2[4];
        ok("map(tx1)", conf_txbind_map(sh1, tb1));
        ok("map(tx2)", conf_txbind_map(sh2, tb2));

        uint64_t r1[4], r2[4];
        conf_txbind_bound_root(commitment_root, tb1, r1);
        conf_txbind_bound_root(commitment_root, tb2, r2);
        ok("tx1 ≠ tx2 ⇒ different bound root (no replay)", memcmp(r1, r2, sizeof(r1)) != 0);

        uint64_t r1b[4];
        conf_txbind_bound_root(commitment_root, tb1, r1b);
        ok("bound root deterministic", memcmp(r1, r1b, sizeof(r1)) == 0);

        /* different commitment set ⇒ different bound root too */
        const uint64_t root2[4] = {99, 22, 33, 44};
        uint64_t r3[4];
        conf_txbind_bound_root(root2, tb1, r3);
        ok("different commitment root ⇒ different bound", memcmp(r1, r3, sizeof(r1)) != 0);
    }

    if (fails) { printf("conf_txbind: %d FAIL\n", fails); return 1; }
    printf("conf_txbind: rejection map (grounded) + sandbox sighash + tx-bound "
           "root (SEC-5 replay mechanism) — PASS\n");
    return 0;
}
