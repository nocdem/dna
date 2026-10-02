/**
 * @file nodus/tests/test_hf4_genesis.c
 * @brief HF-4 part A1 — GENESIS INVARIANCE: a version-3 genesis derived
 *        by this (HF-4) build is byte-identical to the one the pre-HF-4
 *        build derives, through the derivation AND the bundle-join path.
 *
 * Design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.1 and §3
 * ("genesis invariance"); red-team round 3 R3-4 F1. Live nodes never
 * recompute genesis (nodus_witness_v2_apply.c genesis entry), so a drift
 * in generation-1 seeding (nodus_witness_domreg_init_genesis, which the
 * derivation and the bundle joiner both reach) would go unnoticed until a
 * joiner — or a wipe + pin recovery — derived a different chain.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. The fixed fixture genesis (v2_genesis_fixture.h v2x_cfg_make, salt
 *     0) derived by THIS build has the chain id, committed global root
 *     and domain-registry root captured from the PRE-HF-4 build.
 *  2. The registry this build seeds holds exactly the genesis-generation
 *     tuples (nodus_runtime_builtin_table — SYSTEM v6, CORE v4).
 *  3. A fresh joiner adopting the source's bundle with the PRE-HF-4 chain
 *     id as its pin succeeds and stores that chain id: the bundle path
 *     (nodus_witness_v2_bundle.c → domreg_init_genesis) re-derives the
 *     same genesis.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none (the literals were captured from a DEFAULT build;
 * a short-epoch build derives a different chain and FAILS section 1 —
 * a different fixture, not a defect). Environment: none.
 * DELIBERATELY written against APIs that exist on the base commit
 * 30010235 (no HF-4 symbol is used), so the ORCHESTRATOR can compile this
 * same file against the base tree to capture the three literals: the
 * test prints the computed values on every run.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp directories (source chain, joiner), removed at the end.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Until the ORCHESTRATOR fills the three HF4-ORACLE literals below
 *    (captured from the base build, NOT from the python oracle), section
 *    1 fails, and section 3 pins to the unfilled value and fails too.
 *  - It pins ONE fixture genesis. The live testnet genesis document is
 *    not in this tree; a seeding drift that only a different config
 *    exercises would pass here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_runtime.h"
#include "dnac/dnac.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while (0)

/* HF4-ORACLE: filled by ORCHESTRATOR — captured by building and running
 * THIS file against the pre-HF-4 base 30010235 (default build), never
 * from this build's own output. */
static const uint8_t HF4_GENESIS_CHAIN32_PRE[32] = {
    /* HF4-ORACLE: filled by ORCHESTRATOR (base-build chain id) */
    0
};
static const uint8_t HF4_GENESIS_GLOBAL_ROOT_PRE[64] = {
    /* HF4-ORACLE: filled by ORCHESTRATOR (base-build committed global
     * root of the same fixture) */
    0
};
static const uint8_t HF4_GENESIS_DOMREG_ROOT_PRE[64] = {
    /* HF4-ORACLE: filled by ORCHESTRATOR (base-build domain-registry
     * root of the same fixture) */
    0
};

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    fprintf(stderr, "  %-18s ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}

int main(void) {
    v2x_chain_t c;
    CHECK(v2x_chain_open(&c, "hf4gen", 0) == 0);

    /* ── 1. the derived genesis, against the pre-HF-4 capture ────── */
    uint8_t groot[64], droot[64];
    CHECK(nodus_witness_v2_committed_global_root(c.w, groot) == 0);
    CHECK(nodus_witness_domreg_root(c.w, droot) == 0);
    fprintf(stderr, "test_hf4_genesis: this build derived\n");
    print_hex("chain32", c.chain32, 32);
    print_hex("global_root", groot, 64);
    print_hex("domreg_root", droot, 64);
    CHECK(memcmp(c.chain32, HF4_GENESIS_CHAIN32_PRE, 32) == 0);
    CHECK(memcmp(groot, HF4_GENESIS_GLOBAL_ROOT_PRE, 64) == 0);
    CHECK(memcmp(droot, HF4_GENESIS_DOMREG_ROOT_PRE, 64) == 0);

    /* ── 2. the registry holds the genesis-generation tuples ──────── */
    {
        size_t n = 0;
        const nodus_domain_runtime_t *g = nodus_runtime_builtin_table(&n);
        CHECK(g && n == 2);
        for (size_t i = 0; i < n; i++) {
            dna_domain_manifest_t m;
            CHECK(nodus_witness_domreg_get(c.w, g[i].domain_id, NULL, &m,
                                           NULL) == 0);
            CHECK(m.runtime_kind == g[i].runtime_kind);
            CHECK(m.runtime_abi == g[i].runtime_abi);
            CHECK(m.ruleset_version == g[i].ruleset_version);
            CHECK(memcmp(m.ruleset_hash, g[i].ruleset_hash, 64) == 0);
        }
        CHECK(g[0].ruleset_version == 6 && g[1].ruleset_version == 4);
    }

    /* ── 3. the bundle-join path, pinned to the pre-HF-4 chain id ─── */
    {
        uint8_t *bundle = NULL;
        size_t blen = 0;
        CHECK(nodus_witness_v2_bundle_get(c.w, &bundle, &blen) == 0 &&
              bundle && blen > 0);

        char jdir[128];
        snprintf(jdir, sizeof(jdir), "/tmp/test_hf4_genesis_join_XXXXXX");
        CHECK(mkdtemp(jdir) != NULL);
        nodus_witness_t *jw = calloc(1, sizeof(*jw));
        CHECK(jw != NULL);
        jw->cached_committee_epoch_start = UINT64_MAX;
        snprintf(jw->data_path, sizeof(jw->data_path), "%s", jdir);
        {
            uint8_t id16[16];
            memset(id16, 0xAA, sizeof(id16));
            CHECK(nodus_witness_create_chain_db(jw, id16) == 0);
        }
        CHECK(nodus_witness_v2_bundle_apply(jw, bundle, blen,
                                            HF4_GENESIS_CHAIN32_PRE) == 0);
        uint8_t jchain[NODUS_V2_GEN_CHAIN_ID_LEN];
        CHECK(nodus_witness_v2_gen_stored_chain_id(jw, jchain) == 0);
        CHECK(memcmp(jchain, HF4_GENESIS_CHAIN32_PRE, 32) == 0);
        uint8_t jdroot[64];
        CHECK(nodus_witness_domreg_root(jw, jdroot) == 0);
        CHECK(memcmp(jdroot, HF4_GENESIS_DOMREG_ROOT_PRE, 64) == 0);

        free(bundle);
        if (jw->db) sqlite3_close(jw->db);
        free(jw);
        char cmd[200];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", jdir);
        if (system(cmd) != 0) { /* best effort */ }
    }

    v2x_chain_close(&c);
    printf("test_hf4_genesis: ALL CHECKS PASSED\n");
    return 0;
}
