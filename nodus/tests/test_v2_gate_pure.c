/**
 * @file nodus/tests/test_v2_gate_pure.c
 * @brief Ledger V2 O15J Faz 3 — the activation gate on a PURE-V2 chain,
 *        proven in a DEFAULT build.
 *
 * ═══ THE REGRESSION THIS EXISTS TO CATCH ════════════════════════════════
 * O15J removes the activation ceremony. Before it, the ONE non-test arm of
 * `nodus_witness_v2_gate_authority_present()` was compiled under
 * NODUS_V2_ACTIVATION_AUTHORITY, so a default build returned a constant 0.
 * Deleting the ceremony without replacing that arm leaves exactly that
 * constant behind, and the consequence is silent and total:
 *
 *   authority 0  → gate NO_AUTHORITY  (nodus_witness_v2_gate.c)
 *                → nodus_witness_v2_ingress_arm() refuses
 *                → w->v2_ingress_armed stays false
 *                → v2sync_ready() false at every handler
 *                     (nodus_witness_v2_sync2.c)
 *                → A PURE-V2 CHAIN IS BORN INERT.
 *
 * It boots, it has a genesis, it answers nothing. No test in this suite
 * would have failed. This one does.
 *
 * ═══ WHY IT MUST NOT CARRY THE TEST FIXTURE ═════════════════════════════
 * `nodus_witness_v2_gate_test_arm()` (NODUS_V2_TEST_AUTHORITY) grants
 * synthetic authority. A test that grants itself authority cannot observe
 * whether authority is DERIVED, which is the only thing this file is for —
 * it would pass against the very constant-0 regression above.
 *
 * This season already lost a defect exactly that way: a fixture hard-set
 * the flag production was supposed to derive, and the suite still reported
 * PASS (the assert-not-assign note at test_v2_gen.c's `open_chain`).
 *
 * The requirement is therefore STRUCTURAL, not a comment: the #error
 * guards below make it a BUILD FAILURE for this target to carry either
 * authority macro. If a future edit adds one to make a red test green, the
 * build stops instead.
 *
 * ═══ WHAT AUTHORITY MEANS NOW ═══════════════════════════════════════════
 * Authority is a property of the chain's OWN COMMITTED STATE: the
 * height-0 genesis manifest in `v2_manifests`, decoding with
 * dist_present == 1 and source_tag == NODUS_V2_GEN_SOURCE_TAG
 * ("DNA.GENESIS.v1", nodus_witness_v2_gen.h). Nothing local, nothing
 * wire-settable, nothing an operator can flip — the same discipline the
 * gate was built with, now with a committed fact behind it.
 *
 * ═══ AND A FAULT IS NOT AN ANSWER ═══════════════════════════════════════
 * "The manifest could not be read" must NEVER collapse into "this is not a
 * pure chain". They are different operator states and only one is a bug.
 * `nodus_witness_v2_gen_is_pure()` already draws that line explicitly
 * (absent → 0, undecodable/unreadable → -1); the gate must draw the same
 * one, mapping a fault to NODUS_V2_GATE_FAULT rather than to a silent
 * NO_AUTHORITY. §3 pins it, and every section asserts the gate and the
 * probe AGREE about the same database.
 *
 * ── DETERMINISM ─────────────────────────────────────────────────────────
 * Every chain here is derived by the REAL builder from a compile-time
 * constant config. No clock, no network, no randomness, no readdir order
 * reaching an answer. Each section derives its OWN chain in its OWN
 * temporary directory, so no section can depend on another's cleanup or
 * leave an armed handle behind.
 *
 * ── ANTI-VACUITY ────────────────────────────────────────────────────────
 * §2b and §3 mutate the manifest of a REAL derived chain and change
 * NOTHING else, so the source_tag (§2b) and the decodability (§3) are
 * isolated as the only differences from the §1 chain that OPENS.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE   /* mkdtemp under -std=c11 */

/* ── THE BUILD-CONFIGURATION GUARD (see the header block) ─────────────── */
#ifdef NODUS_V2_TEST_AUTHORITY
#error "test_v2_gate_pure MUST be built WITHOUT NODUS_V2_TEST_AUTHORITY: the whole point is that authority is DERIVED from committed state, and the fixture would grant it synthetically. Register this target with register_witness_test()."
#endif
#ifdef NODUS_V2_ACTIVATION_AUTHORITY
#error "test_v2_gate_pure MUST be built WITHOUT NODUS_V2_ACTIVATION_AUTHORITY: the activation ceremony is gone (O15J Faz 3) and this test pins the DEFAULT build's behaviour."
#endif

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_preflight.h"
#include "witness/nodus_witness_emission.h"  /* DNAC_BLOCKS_PER_YEAR,
                                              * DNAC_DECIMAL_UNIT        */

#include "dnac/dnac.h"
#include "dnac/manifest_wire.h"

#include "crypto/hash/qgp_sha3.h"

static int g_fail = 0;
static int g_checks = 0;
#define CHECK(cond, msg) do {                                            \
    g_checks++;                                                          \
    if (!(cond)) {                                                       \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,         \
                __LINE__, (msg));                                        \
        g_fail = 1;                                                      \
    } } while (0)
#define OK() do { if (g_fail) return 1; } while (0)

/* ── the §0 composition (mirrors test_v2_gen.c's) ────────────────────── */

#define TREASURY_RAW   93000000000000000ULL          /* 930,000,000 DNAC */
#define N_VAL          ((uint16_t)DNAC_COMMITTEE_SIZE)

/* ── helpers ─────────────────────────────────────────────────────────── */

static void rmrf(const char *dir) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static void hex_lower_fp(const uint8_t *src, size_t src_len, uint8_t *out129) {
    static const char hexd[] = "0123456789abcdef";
    uint8_t d[64];
    qgp_sha3_512(src, src_len, d);
    for (int i = 0; i < 64; i++) {
        out129[2 * i]     = (uint8_t)hexd[d[i] >> 4];
        out129[2 * i + 1] = (uint8_t)hexd[d[i] & 0x0F];
    }
    out129[128] = 0;
}

/* ── config construction ─────────────────────────────────────────────── */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b) {
    if (!b) return;
    free(b->cfg);
    free(b->allocs);
    b->cfg = NULL;
    b->allocs = NULL;
}

/**
 * One treasury allocation totalling TREASURY_RAW plus DNAC_COMMITTEE_SIZE
 * validators each bonding DNAC_SELF_STAKE_AMOUNT — exactly
 * DNAC_DEFAULT_TOTAL_SUPPLY. The same composition test_v2_gen.c derives
 * from, so this file pins the GATE's reading of a chain the builder's own
 * test already proves is complete.
 *
 * The config is ~160 KB — heap-allocated, never on the stack
 * (nodus_witness_v2_gen.h).
 */
static int cfg_make(cfgbox_t *b) {
    memset(b, 0, sizeof(*b));

    b->cfg    = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 1ULL;
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = N_VAL;

    for (uint16_t i = 0; i < N_VAL; i++) {
        nodus_v2_gen_validator_t *v = &c->validators[i];
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->pubkey[bb] = (uint8_t)(0x11 * (i + 1) + (bb & 0x3F));
            v->unstake_destination_pubkey[bb] = (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                     v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }

    {
        nodus_v2_gen_alloc_t *a = &b->allocs[0];
        memset(a->source_id, 0, sizeof(a->source_id));
        a->source_id[0] = 0x30;
        uint8_t owner[DNAC_PUBKEY_SIZE];
        for (size_t bb = 0; bb < sizeof(owner); bb++)
            owner[bb] = (uint8_t)(0xA0 + (bb & 0x1F));
        qgp_sha3_512(owner, sizeof(owner), a->dest_binding);
        a->amount = TREASURY_RAW;
    }

    c->n_allocs = 1;
    c->allocs   = b->allocs;
    return 0;
}

/* ── chain-db discovery / open ───────────────────────────────────────── */

/* 0 found, 1 none, -1 fault. Mirrors test_v2_gen.c's find_chain: the
 * filename IS the chain id, and the handle's id must come from it or the
 * preflight reports CHAIN_ID_DISAGREEMENT. */
static int find_chain(const char *dir, char out_path[600], uint8_t out16[16]) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int found = 1;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len != 8 + 32 + 3 || strcmp(e->d_name + len - 3, ".db") != 0)
            continue;
        snprintf(out_path, 600, "%s/%s", dir, e->d_name);
        for (int i = 0; i < 16; i++) {
            unsigned bv = 0;
            if (sscanf(e->d_name + 8 + i * 2, "%2x", &bv) != 1) {
                closedir(d);
                return -1;
            }
            out16[i] = (uint8_t)bv;
        }
        found = 0;
        break;
    }
    closedir(d);
    return found;
}

/**
 * Derive a fresh pure-V2 chain into a fresh temp dir.
 *
 * @param dir      [out] the temp directory (caller rmrf's it).
 * @param db_path  [out] the derived chain database path.
 * @return 0 on success.
 */
static int derive_chain(const char *tag, char dir[128], char db_path[600]) {
    cfgbox_t box;
    if (cfg_make(&box) != 0) return -1;

    snprintf(dir, 128, "/tmp/test_v2_gate_pure_%s_XXXXXX", tag);
    if (!mkdtemp(dir)) { cfg_free(&box); return -1; }

    int rc = nodus_witness_v2_gen_derive(dir, box.cfg, NULL);
    cfg_free(&box);
    if (rc != 0) return -1;

    uint8_t id16[16];
    return find_chain(dir, db_path, id16) == 0 ? 0 : -1;
}

/**
 * Open the single chain DB in `dir` through the PRODUCTION open path.
 *
 * The `v2_successor` flag is ASSERTED, never assigned: production's own
 * role derivation runs inside nodus_witness_create_chain_db, and a
 * fixture that assigned the flag would mask exactly the class of defect
 * this file exists to catch (test_v2_gen.c's open_chain carries the same
 * note, for the same reason).
 */
static nodus_witness_t *open_chain(const char *dir) {
    uint8_t id16[16];
    char path[600];
    if (find_chain(dir, path, id16) != 0) return NULL;

    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB — never stack */
    if (!w) return NULL;
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    if (nodus_witness_create_chain_db(w, id16) != 0) { free(w); return NULL; }

    if (!w->v2_successor) {
        fprintf(stderr, "open_chain: production role derivation did NOT "
                        "recognise the pure-V2 chain at %s\n", path);
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

static void close_chain(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) { sqlite3_close(w->db); w->db = NULL; }
    free(w);
}

/**
 * Open a chain database WITHOUT the production post-open gate.
 *
 * §2b and §3 deliberately hold a foreign / damaged chain, and
 * nodus_witness_create_chain_db legitimately REFUSES those: the pure-V2
 * probe's -1 rejects the database outright (nodus_witness_v2_gen.c's
 * chain-role probe, "this probe's -1 REFUSES the database at
 * witness_post_open_gate"). Going through it would leave those sections
 * with no handle and silently skip the very assertions they exist for —
 * a test that cannot reach its subject is a test that proves nothing.
 *
 * So those sections attach a minimal handle directly. That is legitimate
 * here precisely because the subject is the GATE, not the open path: the
 * gate reads `w->db` and nothing else on the authority leg.
 */
static nodus_witness_t *open_db_raw(const char *dir) {
    uint8_t id16[16];
    char path[600];
    if (find_chain(dir, path, id16) != 0) return NULL;

    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB — never stack */
    if (!w) return NULL;
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    if (sqlite3_open(path, &w->db) != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

/* ── manifest surgery (§2b, §3) ──────────────────────────────────────── */

/* Replace the height-0 genesis manifest blob with `blob`/`len`. `len == 0`
 * writes a zero-length blob — the "present but unreadable" case that
 * nodus_witness_v2_gen_is_pure() classifies as a FAULT, not a clean no. */
static int manifest_overwrite(const char *db_path, const uint8_t *blob,
                              size_t len) {
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db,
            "UPDATE v2_manifests SET manifest = ?1 "
            "WHERE committed_height = 0", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, blob, (int)len, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db) == 1)
            rc = 0;
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return rc;
}

/* Read the height-0 genesis manifest blob. Caller free()s *out. */
static int manifest_read(const char *db_path, uint8_t **out, size_t *out_len) {
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT manifest FROM v2_manifests WHERE committed_height = 0 "
            "ORDER BY manifest_seq ASC LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const void *mb = sqlite3_column_blob(st, 0);
            int ml = sqlite3_column_bytes(st, 0);
            if (mb && ml > 0) {
                *out = malloc((size_t)ml);
                if (*out) {
                    memcpy(*out, mb, (size_t)ml);
                    *out_len = (size_t)ml;
                    rc = 0;
                }
            }
        }
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return rc;
}

/* Print every preflight issue by name — a red §1 must say WHY, not just
 * "not OPEN" (the same courtesy the deleted seam test paid). */
static void dump_preflight(nodus_witness_t *w) {
    nodus_v2_preflight_report_t rep;
    if (nodus_witness_v2_preflight(w, &rep) != 0) {
        fprintf(stderr, "  preflight could not be run at all\n");
        return;
    }
    fprintf(stderr, "  preflight ready=%d, %zu issue(s):\n", rep.ready,
            rep.n_issues);
    for (size_t i = 0; i < rep.n_issues; i++)
        fprintf(stderr, "    - %s\n",
                nodus_witness_v2_preflight_issue_name(rep.issues[i]));
}

/* ════════════════════════════════════════════════════════════════════
 * §1 — A REAL PURE-V2 CHAIN OPENS THE GATE AND ARMS
 *
 * The anti-regression assertion. Everything else in this file is here to
 * stop this one from passing for the wrong reason.
 * ══════════════════════════════════════════════════════════════════ */

static int test_pure_chain_opens(void) {
    printf("§1 a real pure-V2 chain: gate OPEN, ingress ARMS\n");

    char dir[128], db_path[600];
    CHECK(derive_chain("open", dir, db_path) == 0,
          "the REAL builder derives a pure-V2 chain");
    OK();

    /* The production probe and the gate must agree about this database. */
    CHECK(nodus_witness_v2_gen_is_pure(db_path) == 1,
          "the production probe classifies it PURE");

    nodus_witness_t *w = open_chain(dir);
    CHECK(w != NULL, "the derived chain opens through the production path");
    if (!w) { rmrf(dir); return 1; }

    nodus_v2_gate_state_t s = nodus_witness_v2_gate_state(w);
    if (s != NODUS_V2_GATE_OPEN) {
        fprintf(stderr,
            "\n  *** THE PURE-V2 CHAIN DID NOT OPEN THE GATE — it is %s.\n"
            "  *** A chain born from its own config MUST be able to arm;\n"
            "  *** otherwise it boots, holds a genesis, and answers nothing.\n",
            nodus_witness_v2_gate_state_name(s));
        dump_preflight(w);
    }
    CHECK(s == NODUS_V2_GATE_OPEN,
          "A PURE-V2 CHAIN'S OWN COMMITTED GENESIS IS ACTIVATION AUTHORITY "
          "— the gate must be OPEN in a DEFAULT build");
    CHECK(nodus_witness_v2_activation_permitted(w) == 1,
          "and activation is permitted");

    /* The consequence that actually matters: a node that cannot arm is a
     * node whose V2 handlers never answer.
     *
     * The production open path ARMS BY ITSELF. nodus_witness.c:466 calls
     * nodus_witness_v2_ingress_arm() on every open and treats a refusal
     * as "ingress remains CLOSED" — a log line, not an error. Before
     * O15J Faz 3 that call could never succeed (authority was a
     * structural 0), so a node always came up unarmed and this test's
     * first assertion originally read `is_armed == 0`. That is precisely
     * the behaviour Faz 3 exists to end: on a pure-V2 chain there is no
     * ceremony, no activation event and no operator command that would
     * ever arm the node afterwards, so if the open path did not arm it,
     * nothing would, and the chain would hold a genesis and answer
     * nothing. ARMED-on-open IS the anti-inert property. */
    CHECK(nodus_witness_v2_ingress_is_armed(w) == 1,
          "THE PRODUCTION OPEN PATH ARMS A PURE-V2 CHAIN BY ITSELF");
    CHECK(nodus_witness_v2_ingress_arm(w) == 0,
          "and an explicit re-arm still succeeds (idempotent)");
    CHECK(nodus_witness_v2_ingress_is_armed(w) == 1,
          "leaving the node ARMED");

    /* An armed node whose gate is genuinely OPEN is the ACTIVATED
     * configuration, not the forbidden one — issue 13 must stay silent, or
     * the preflight would condemn every correctly activated node. */
    {
        nodus_v2_preflight_report_t rep;
        CHECK(nodus_witness_v2_preflight(w, &rep) == 0, "preflight ran");
        int saw_ingress = 0;
        for (size_t i = 0; i < rep.n_issues; i++)
            if (rep.issues[i] == NODUS_V2_PF_INGRESS_ENABLED) saw_ingress = 1;
        CHECK(!saw_ingress,
              "issue 13 must NOT fire when ingress is armed with an OPEN "
              "gate — that is activation, not the state 13 guards");
    }

    nodus_witness_v2_ingress_disarm(w);
    CHECK(nodus_witness_v2_ingress_is_armed(w) == 0, "disarm clears it");

    close_chain(w);
    rmrf(dir);
    OK();
    printf("  ok: OPEN + armed on a chain nobody granted authority to\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §2 — NOT A PURE-V2 CHAIN ⇒ NO_AUTHORITY, AND ARMING REFUSES
 *
 * NO_AUTHORITY no longer means "this binary has no ceremony compiled in".
 * It means "this database is not a chain this gate may open".
 * ══════════════════════════════════════════════════════════════════ */

/* (a) A fresh chain database: no v2_manifests genesis row at all. */
static int test_plain_db_no_authority(void) {
    printf("§2a a fresh (non-pure) chain database: NO_AUTHORITY\n");

    char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/test_v2_gate_pure_plain_XXXXXX");
    CHECK(mkdtemp(dir) != NULL, "tmpdir");
    OK();

    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL, "alloc");
    if (!w) { rmrf(dir); return 1; }
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    uint8_t cid16[16];
    memset(cid16, 0x3c, sizeof(cid16));
    CHECK(nodus_witness_create_chain_db(w, cid16) == 0, "fresh chain db");
    OK();

    CHECK(nodus_witness_v2_gate_state(w) == NODUS_V2_GATE_NO_AUTHORITY,
          "a database that is not a pure-V2 chain has NO_AUTHORITY");
    CHECK(nodus_witness_v2_activation_permitted(w) == 0,
          "activation is not permitted");
    CHECK(nodus_witness_v2_ingress_arm(w) != 0, "ARMING IS REFUSED");
    CHECK(nodus_witness_v2_ingress_is_armed(w) == 0,
          "a refused arm leaves the node UNARMED — there is no partial "
          "arming");

    close_chain(w);
    rmrf(dir);
    OK();
    printf("  ok: no genesis manifest ⇒ NO_AUTHORITY, arming refused\n");
    return 0;
}

/* (b) A REAL pure-V2 chain whose manifest carries a DIFFERENT source tag.
 *
 * Everything else about the chain is byte-identical to §1's, so the tag is
 * isolated as the only difference — and a manifest that decodes cleanly to
 * another tag is a genuine "not ours" (0), never a fault. */
static int test_foreign_tag_no_authority(void) {
    printf("§2b a real chain with a FOREIGN source_tag: NO_AUTHORITY\n");

    char dir[128], db_path[600];
    CHECK(derive_chain("tag", dir, db_path) == 0, "derive");
    OK();

    uint8_t *blob = NULL;
    size_t blen = 0;
    CHECK(manifest_read(db_path, &blob, &blen) == 0, "read the real manifest");
    OK();

    dna_gman_t m;
    CHECK(dna_gman_decode(blob, blen, &m) == 0, "it decodes");
    free(blob);
    OK();

    CHECK(m.source_tag_len == NODUS_V2_GEN_SOURCE_TAG_LEN &&
          memcmp(m.source_tag, NODUS_V2_GEN_SOURCE_TAG,
                 NODUS_V2_GEN_SOURCE_TAG_LEN) == 0,
          "the pristine manifest carries DNA.GENESIS.v1");

    /* Flip ONLY the tag, then re-encode with the real codec. */
    static const char FOREIGN[] = "DNA.SOMEONE.ELSE.v1";
    m.source_tag_len = (uint16_t)(sizeof(FOREIGN) - 1);
    memset(m.source_tag, 0, sizeof(m.source_tag));
    memcpy(m.source_tag, FOREIGN, sizeof(FOREIGN) - 1);

    size_t need = dna_gman_encoded_len(&m);
    CHECK(need > 0, "re-encode length");
    OK();
    uint8_t *re = malloc(need);
    CHECK(re != NULL, "alloc");
    if (!re) { rmrf(dir); return 1; }
    size_t written = 0;
    CHECK(dna_gman_encode(&m, re, need, &written) == 0, "re-encodes");
    CHECK(manifest_overwrite(db_path, re, written) == 0, "manifest replaced");
    free(re);
    OK();

    /* The probe and the gate must agree: a decodable foreign tag is a
     * clean NO, not a fault. */
    CHECK(nodus_witness_v2_gen_is_pure(db_path) == 0,
          "the production probe says NOT PURE (a clean 0, not -1)");

    nodus_witness_t *w = open_db_raw(dir);
    CHECK(w != NULL, "the foreign chain db attaches");
    if (!w) { rmrf(dir); return 1; }

    CHECK(nodus_witness_v2_gate_state(w) == NODUS_V2_GATE_NO_AUTHORITY,
          "a foreign source_tag is NOT authority");
    CHECK(nodus_witness_v2_activation_permitted(w) == 0,
          "activation is not permitted");
    CHECK(nodus_witness_v2_ingress_arm(w) != 0, "ARMING IS REFUSED");
    CHECK(nodus_witness_v2_ingress_is_armed(w) == 0,
          "and the node is left UNARMED");

    close_chain(w);
    rmrf(dir);
    OK();
    printf("  ok: foreign tag ⇒ clean NO_AUTHORITY (not a fault)\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §3 — A FAULT IS NOT AN ANSWER
 *
 * A manifest row that is present but cannot be read must reach
 * NODUS_V2_GATE_FAULT. Collapsing it into NO_AUTHORITY would report a
 * damaged chain as a perfectly ordinary non-V2 one — the same
 * absent-vs-failed conflation nodus_witness_v2_gen_is_pure() was fixed for
 * (O15J review R2-F4), where it silently produced a second chain beside a
 * damaged first one.
 * ══════════════════════════════════════════════════════════════════ */

static int fault_case(const char *tag, const uint8_t *blob, size_t len,
                      const char *what) {
    char dir[128], db_path[600];
    CHECK(derive_chain(tag, dir, db_path) == 0, "derive");
    OK();

    CHECK(manifest_overwrite(db_path, blob, len) == 0, "manifest replaced");
    OK();

    /* The probe's verdict is -1 ("could not classify"), and the gate must
     * reach the SAME conclusion rather than a comfortable 0. */
    CHECK(nodus_witness_v2_gen_is_pure(db_path) == -1,
          "the production probe reports a FAULT (-1), not a clean 0");

    nodus_witness_t *w = open_db_raw(dir);
    CHECK(w != NULL, "the damaged chain db attaches");
    if (!w) { rmrf(dir); return 1; }

    nodus_v2_gate_state_t s = nodus_witness_v2_gate_state(w);
    if (s != NODUS_V2_GATE_FAULT)
        fprintf(stderr, "  gate reported %s\n",
                nodus_witness_v2_gate_state_name(s));
    CHECK(s == NODUS_V2_GATE_FAULT, what);
    CHECK(s != NODUS_V2_GATE_NO_AUTHORITY,
          "A FAULT MUST NOT BE REPORTED AS 'not a pure chain' — the two "
          "call for different operator responses");
    CHECK(nodus_witness_v2_activation_permitted(w) == 0,
          "a fault never permits activation");
    CHECK(nodus_witness_v2_ingress_arm(w) != 0, "ARMING IS REFUSED");
    CHECK(nodus_witness_v2_ingress_is_armed(w) == 0,
          "and the node is left UNARMED");

    close_chain(w);
    rmrf(dir);
    return 0;
}

static int test_unreadable_manifest_faults(void) {
    printf("§3 an unreadable genesis manifest: FAULT, never NO_AUTHORITY\n");

    /* (a) present but EMPTY — the NULL/zero-length blob case. */
    {
        static const uint8_t empty[1] = { 0 };
        if (fault_case("empty", empty, 0,
                       "AN EMPTY MANIFEST BLOB IS A FAULT") != 0)
            return 1;
    }

    /* (b) present but UNDECODABLE — real bytes the codec rejects. */
    {
        uint8_t garbage[96];
        memset(garbage, 0xA5, sizeof(garbage));
        if (fault_case("garbage", garbage, sizeof(garbage),
                       "AN UNDECODABLE MANIFEST IS A FAULT") != 0)
            return 1;
    }

    OK();
    printf("  ok: empty and undecodable manifests both FAULT\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== O15J Faz 3 — the activation gate on a PURE-V2 chain "
           "(DEFAULT build) ===\n\n");

    /* Run every section (accumulate) so a failing run shows the FULL
     * failure set rather than just the first. */
    int rc = 0;
    rc |= test_pure_chain_opens();
    rc |= test_plain_db_no_authority();
    rc |= test_foreign_tag_no_authority();
    rc |= test_unreadable_manifest_faults();

    if (rc || g_fail) {
        printf("\nSOME O15J PURE-GATE TESTS FAILED\n");
        return 1;
    }
    printf("\ntest_v2_gate_pure: ALL %d checks passed\n", g_checks);
    return 0;
}
