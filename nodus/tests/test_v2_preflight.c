/**
 * @file nodus/tests/test_v2_preflight.c
 * @brief O15A obligation 7 (+ obligation 8's fail-closed gate) — the
 *        activation-readiness preflight is deterministic, read-only, and
 *        cannot activate anything.
 *
 * The properties worth testing are not "does it find problem X" — that is
 * the easy half. They are:
 *   - it does not WRITE (proven by a whole-database digest, not by
 *     reading the code and believing it);
 *   - it is DETERMINISTIC (same database, byte-identical report, twice);
 *   - it reports EVERY issue in canonical order rather than stopping at
 *     the first, because an operator needs the whole list;
 *   - it can NEVER report ready while Rule N has no attendance source,
 *     which is how O15A closes that obligation without inventing an
 *     attendance oracle.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <dirent.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_preflight.h"
#include "witness/nodus_witness_v2_gen.h"       /* R3 W3 — the v3 fixture */
#include "witness/nodus_witness_cmt_store.h"    /* R3 W3 — corrupt the doc */
#include "witness/nodus_witness_cmt_host.h"     /* delta 8 — nodus_abci_*,
                                                  * the FinalizeBlock request
                                                  * shape */
#include "witness/nodus_witness_cmt_app.h"      /* delta 8 — the REAL
                                                  * FinalizeBlock/Commit
                                                  * app entry points */
#include "witness/nodus_witness_emission.h"     /* DNAC_BLOCKS_PER_YEAR :34,
                                                  * DNAC_DECIMAL_UNIT :42 */
#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"                    /* DNA_DOMAIN_CORE */
#include "dnac/cmt_genesis.h"                   /* delta 8 — cmt_genesis_doc_t */
#include "dnac/cmt_state.h"                     /* delta 8 — cmt_state_make_* */
#include "dnac/cmt_block.h"                     /* delta 8 — cmt_block_t,
                                                  * cmt_block_make_part_set */
#include "dnac/cmt_part_set.h"                  /* delta 8 — cmt_part_set_t */
#include "crypto/hash/qgp_sha3.h"

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

typedef struct { char dir[256]; nodus_witness_t *w; } fx_t;

static int fx_open(fx_t *f, const char *tag) {
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_v2_pf_%s_XXXXXX", tag);
    if (!mkdtemp(f->dir)) return -1;
    f->w = calloc(1, sizeof(*f->w));
    if (!f->w) return -1;
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t cid[16];
    memset(cid, 0x77, sizeof(cid));
    return nodus_witness_create_chain_db(f->w, cid);
}

static void fx_close(fx_t *f) {
    if (!f->w) return;
    if (f->w->db) sqlite3_close(f->w->db);
    free(f->w);
    f->w = NULL;
}

/* Whole-database logical digest: every table, every row, in a stable
 * order — including sqlite_sequence, which a NOT LIKE 'sqlite_%' filter
 * would silently drop along with the AUTOINCREMENT counters. */
static int db_digest(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *tq = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "ORDER BY name", -1, &tq, NULL) != SQLITE_OK)
        return -1;
    uint8_t acc[64];
    memset(acc, 0, sizeof(acc));
    while (sqlite3_step(tq) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(tq, 0);
        char sql[512];
        snprintf(sql, sizeof(sql),
                 "SELECT quote(t.*) FROM (SELECT * FROM \"%s\") t", t);
        sqlite3_stmt *rq = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK) {
            /* Fall back to a row count so an unquotable table still
             * contributes rather than being silently skipped. */
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM \"%s\"", t);
            if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK)
                continue;
        }
        while (sqlite3_step(rq) == SQLITE_ROW) {
            const unsigned char *v = sqlite3_column_text(rq, 0);
            uint8_t buf[64];
            if (v) {
                qgp_sha3_512(v, strlen((const char *)v), buf);
                for (int i = 0; i < 64; i++) acc[i] ^= buf[i];
            }
        }
        sqlite3_finalize(rq);
        uint8_t nb[64];
        qgp_sha3_512((const uint8_t *)t, strlen(t), nb);
        for (int i = 0; i < 64; i++) acc[i] ^= nb[i];
    }
    sqlite3_finalize(tq);
    memcpy(out, acc, 64);
    return 0;
}

static int has_issue(const nodus_v2_preflight_report_t *r,
                     nodus_v2_pf_issue_t id) {
    for (size_t i = 0; i < r->n_issues; i++)
        if (r->issues[i] == id) return 1;
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * R3 W3 — the v3 GENESIS DOCUMENT checks (D-17 rev 10 (8)):
 * GENESIS_ABSENT / GENESIS_MALFORMED / GENESIS_APP_HASH_MISMATCH (17) /
 * CHAIN_ID_DISAGREEMENT, each on a REAL derived v3 chain, each proving
 * the preflight stays read-only across the corrupted call. Per the
 * ORCHESTRATOR's instruction this fixture is DUPLICATED from
 * test_v2_bundle.c's v3cfg_make, not shared (no new file).
 * ══════════════════════════════════════════════════════════════════ */

#define V3PF_N_VAL 7
#define V3PF_TREASURY_RAW 93000000000000000ULL /* V3PF_N_VAL self-bonds +
                                                 * this == DNAC_DEFAULT_
                                                 * TOTAL_SUPPLY */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} v3pf_cfgbox_t;

static void v3pf_cfg_free(v3pf_cfgbox_t *b) {
    if (!b) return;
    free(b->cfg);
    free(b->allocs);
    b->cfg = NULL;
    b->allocs = NULL;
}

static void v3pf_hex_lower_fp(const uint8_t *src, size_t src_len,
                              uint8_t *out129) {
    static const char hexd[] = "0123456789abcdef";
    uint8_t fpr[64];
    qgp_sha3_512(src, src_len, fpr);
    for (int i = 0; i < 64; i++) {
        out129[2 * i]     = (uint8_t)hexd[fpr[i] >> 4];
        out129[2 * i + 1] = (uint8_t)hexd[fpr[i] & 0xF];
    }
    out129[128] = '\0';
}

static int v3pf_cfg_make(v3pf_cfgbox_t *b, uint8_t salt) {
    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { v3pf_cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;   /* tokenomics-v3 P2: RETIRED,
                                        * the only legal value is 0 */
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = V3PF_N_VAL;

    for (uint16_t i = 0; i < V3PF_N_VAL; i++) {
        nodus_v2_gen_validator_t *v = &c->validators[i];
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->pubkey[bb] = (uint8_t)(0x11 * (i + 1) + (bb & 0x3F) + salt);
            v->unstake_destination_pubkey[bb] =
                (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        v3pf_hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                          v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }

    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    {
        uint8_t owner[DNAC_PUBKEY_SIZE];
        for (size_t bb = 0; bb < sizeof(owner); bb++)
            owner[bb] = (uint8_t)(0xA0 + (bb & 0x1F) + salt);
        qgp_sha3_512(owner, sizeof(owner), b->allocs[0].dest_binding);
    }
    b->allocs[0].amount = V3PF_TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        v3pf_cfg_free(b);
        return -1;
    }
    /* tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve;
     * this fixture's allocation spends the whole supply and it is not a
     * reward test — no pool reserved. */
    c->reward_pool_initial = 0;
    c->genesis_time_ms = 1700000000000ULL;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) {
        v3pf_cfg_free(b);
        return -1;
    }
    return 0;
}

static int v3pf_mkdir_tmp(char dir[256], const char *tag) {
    snprintf(dir, 256, "/tmp/test_v2_pf_v3_%s_XXXXXX", tag);
    return mkdtemp(dir) ? 0 : -1;
}

static int v3pf_rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    return system(cmd);
}

static int v3pf_derive(const char *dir, uint8_t out_chain32[32],
                       uint8_t salt) {
    v3pf_cfgbox_t box;
    if (v3pf_cfg_make(&box, salt) != 0) return -1;
    int rc = nodus_witness_v2_gen_derive_v3(dir, box.cfg, out_chain32);
    v3pf_cfg_free(&box);
    return rc;
}

/* Open the single chain database `derive_v3` landed in `dir`,
 * READ-WRITE, WITHOUT going through nodus_witness_create_chain_db —
 * that function's role-derivation refuses a version-3 chain on REOPEN
 * today (nodus_witness_v2_gen.h's own doc comment on
 * nodus_witness_v2_gen_stored_chain_id names it a W3/C1c obligation
 * this package does not own). The preflight and the corruption steps
 * below both need only `w->db`; `w->chain_id` is set explicitly by the
 * caller below, the same 16-bytes-then-zero layout
 * nodus_witness_set_chain_id uses (nodus_witness.c:286-295) — that
 * function itself is not declared in the public header, so the layout
 * is reproduced here rather than called. */
static nodus_witness_t *v3pf_open(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return NULL;
    struct dirent *e;
    char path[600];
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        found = 1;
        break;
    }
    closedir(d);
    if (!found) return NULL;

    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open_v2(path, &w->db, SQLITE_OPEN_READWRITE, NULL)
        != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

static void v3pf_close(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) sqlite3_close(w->db);
    free(w);
}

static int v3pf_run_sql(sqlite3 *db, const char *sql) {
    char *e = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &e);
    if (e) sqlite3_free(e);
    return rc == SQLITE_OK ? 0 : -1;
}

static int test_v3_documents(void) {
    printf("=== R3 W3 — the v3 genesis document checks (D-17 rev 10 (8)) "
           "===\n");

    /* ── (1) a freshly derived v3 chain is READY (no issues), and the
     * preflight is READ-ONLY across the call. ─────────────────────── */
    {
        char dir[256];
        CHECK(v3pf_mkdir_tmp(dir, "ready") == 0, "tmpdir");
        uint8_t chain32[32];
        CHECK(v3pf_derive(dir, chain32, 0x00) == 0, "derive v3");
        nodus_witness_t *w = v3pf_open(dir);
        CHECK(w != NULL, "open v3 chain read-write");
        /* the handle's own chain id, set the way a real open sets it
         * (nodus_witness_set_chain_id's layout) — matching the derived
         * document's chain_id, so section 6 (CHAIN_ID_DISAGREEMENT)
         * does not fire spuriously. */
        memcpy(w->chain_id, chain32, 16);
        memset(w->chain_id + 16, 0, 16);

        uint8_t before[64], after[64];
        CHECK(db_digest(w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(w, &r) == 0, "preflight runs");
        CHECK(db_digest(w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "the preflight wrote to a derived v3 chain");
        CHECK(r.ready == 1, "a freshly derived v3 chain must be READY");
        CHECK(r.n_issues == 0, "a ready report carries no issues");

        v3pf_close(w);
        v3pf_rmrf(dir);
    }

    /* ── (2) deleting the "genesisDoc" row → GENESIS_ABSENT. ────────── */
    {
        char dir[256];
        CHECK(v3pf_mkdir_tmp(dir, "absent") == 0, "tmpdir");
        uint8_t chain32[32];
        CHECK(v3pf_derive(dir, chain32, 0x10) == 0, "derive v3");
        nodus_witness_t *w = v3pf_open(dir);
        CHECK(w != NULL, "open");
        memcpy(w->chain_id, chain32, 16);
        memset(w->chain_id + 16, 0, 16);

        CHECK(v3pf_run_sql(w->db,
                  "DELETE FROM cmt_state WHERE key = CAST('genesisDoc' "
                  "AS BLOB)") == 0, "delete the document row");

        uint8_t before[64], after[64];
        CHECK(db_digest(w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(w, &r) == 0, "preflight runs");
        CHECK(db_digest(w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "the preflight wrote across a GENESIS_ABSENT report");
        CHECK(has_issue(&r, NODUS_V2_PF_GENESIS_ABSENT),
              "a chain with no stored genesis document reports "
              "GENESIS_ABSENT");
        CHECK(r.ready == 0, "not ready");

        v3pf_close(w);
        v3pf_rmrf(dir);
    }

    /* ── (3) flipping one byte of the stored document bytes →
     * GENESIS_MALFORMED (the canonical-strict reader refuses it —
     * whichever of its four checks the flipped byte happens to break,
     * this preflight reports the same id for all of them). ─────────── */
    {
        char dir[256];
        CHECK(v3pf_mkdir_tmp(dir, "malformed") == 0, "tmpdir");
        uint8_t chain32[32];
        CHECK(v3pf_derive(dir, chain32, 0x20) == 0, "derive v3");
        nodus_witness_t *w = v3pf_open(dir);
        CHECK(w != NULL, "open");
        memcpy(w->chain_id, chain32, 16);
        memset(w->chain_id + 16, 0, 16);

        {
            nodus_cmt_store_t s;
            CHECK(nodus_cmt_store_init(&s, w->db, false) == CMT_OK,
                  "store init");
            const uint8_t *val = NULL;
            size_t vlen = 0;
            CHECK(nodus_cmt_store_get(&s, /*state_table=*/true,
                      "genesisDoc", &val, &vlen) == CMT_OK &&
                  val && vlen > 100, "read the document");
            uint8_t *flipped = malloc(vlen);
            CHECK(flipped != NULL, "alloc");
            memcpy(flipped, val, vlen);
            flipped[vlen / 2] ^= 0xFF;   /* somewhere in the middle */
            int srv = nodus_cmt_store_set(&s, true, "genesisDoc",
                                          flipped, vlen);
            nodus_cmt_store_release(&s);
            CHECK(srv == CMT_OK, "write back the flipped document");
            free(flipped);
        }

        uint8_t before[64], after[64];
        CHECK(db_digest(w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(w, &r) == 0, "preflight runs");
        CHECK(db_digest(w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "the preflight wrote across a GENESIS_MALFORMED report");
        CHECK(has_issue(&r, NODUS_V2_PF_GENESIS_MALFORMED),
              "a flipped document byte reports GENESIS_MALFORMED");
        CHECK(r.ready == 0, "not ready");

        v3pf_close(w);
        v3pf_rmrf(dir);
    }

    /* ── (4) app_hash mismatch → issue 17 (GENESIS_APP_HASH_MISMATCH).
     *
     * CHOSEN MECHANISM: the LEDGER side, not the document side. Editing
     * the document's app_hash field would also change its OWN
     * self-hash (app_hash is inside the chain_id preimage,
     * nodus_witness_v2_gen.h's layout), so a document-side edit — even
     * one that re-signs itself consistently — produces a DIFFERENT
     * chain_id and would ALSO trip CHAIN_ID_DISAGREEMENT (section 6),
     * confounding the very issue this case wants to isolate. Corrupting
     * the LEDGER instead — one byte of the committed CORE domain head
     * (v2_domain_heads.head, schema at nodus_witness_v2_schema.c:40-45)
     * — leaves the document completely untouched (chain_id check
     * passes) while `nodus_witness_v2_committed_global_root` recomputes
     * a DIFFERENT root from the corrupted head, so ONLY the app_hash
     * comparison fails.
     *
     * WHICH BYTE (delta 6 fix): the head BLOB's own encoding is
     * `id(4)+root(64)+h(8)+lu(8)+rv(4)+st(1)` = DNA_V2_DOMHEAD_ENC_LEN
     * (shared/dnac/ledger_roots_v2.h:216) — and `head_load`
     * (nodus_witness_v2_apply.c:211-237) re-checks the DECODED
     * domain_id/domain_height/last_updated_global_height against the
     * row's own separate columns before returning it, failing CLOSED
     * (return -1, a fault, not "not found") on any disagreement.
     * Flipping byte 0 lands inside the 4-byte `id` field: it trips that
     * self-consistency check instead of surviving decode, so
     * `doms_load`/`nodus_witness_v2_committed_global_root` returns a
     * FAULT and this preflight correctly reports INSPECTION_FAULT, not
     * issue 17 — the earlier version of this case asserted the wrong
     * outcome. Byte 4 is the first byte of the 64-byte `root` field
     * (`domain_state_root`), which is NOT cross-checked against
     * anything and feeds `dna_v2_domains_root` directly — flipping it
     * changes the computed committed root without disturbing decode,
     * which is the isolated app_hash-only defect this case wants. */
    {
        char dir[256];
        CHECK(v3pf_mkdir_tmp(dir, "apphash") == 0, "tmpdir");
        uint8_t chain32[32];
        CHECK(v3pf_derive(dir, chain32, 0x30) == 0, "derive v3");
        nodus_witness_t *w = v3pf_open(dir);
        CHECK(w != NULL, "open");
        memcpy(w->chain_id, chain32, 16);
        memset(w->chain_id + 16, 0, 16);

        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(w->db,
                      "SELECT head FROM v2_domain_heads WHERE domain_id=?1",
                      -1, &st, NULL) == SQLITE_OK, "prep");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)DNA_DOMAIN_CORE);
            CHECK(sqlite3_step(st) == SQLITE_ROW, "CORE head row");
            int hl = sqlite3_column_bytes(st, 0);
            CHECK(hl > 4, "head is long enough to hold id(4)+root(64)");
            uint8_t *head = malloc((size_t)hl);
            CHECK(head != NULL, "alloc");
            memcpy(head, sqlite3_column_blob(st, 0), (size_t)hl);
            sqlite3_finalize(st);
            /* Byte 4 = first byte of `root` (domain_state_root) — inside
             * the encoded head but OUTSIDE the id/domain_height/
             * last_updated_global_height fields head_load cross-checks
             * against the row's own columns, so decode still succeeds
             * and only the recomputed committed root changes. */
            head[4] ^= 0xFF;

            sqlite3_stmt *up = NULL;
            CHECK(sqlite3_prepare_v2(w->db,
                      "UPDATE v2_domain_heads SET head=?1 WHERE domain_id=?2",
                      -1, &up, NULL) == SQLITE_OK, "prep update");
            sqlite3_bind_blob(up, 1, head, hl, SQLITE_TRANSIENT);
            sqlite3_bind_int64(up, 2, (sqlite3_int64)DNA_DOMAIN_CORE);
            CHECK(sqlite3_step(up) == SQLITE_DONE, "flip the CORE head");
            sqlite3_finalize(up);
            free(head);
        }

        uint8_t before[64], after[64];
        CHECK(db_digest(w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(w, &r) == 0, "preflight runs");
        CHECK(db_digest(w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "the preflight wrote across an app_hash-mismatch report");
        CHECK(has_issue(&r, NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH),
              "a corrupted committed domain head reports issue 17 — the "
              "document's app_hash no longer matches the committed "
              "global root");
        CHECK(!has_issue(&r, NODUS_V2_PF_GENESIS_MALFORMED),
              "the document itself is untouched — no GENESIS_MALFORMED");
        CHECK(!has_issue(&r, NODUS_V2_PF_CHAIN_ID_DISAGREEMENT),
              "the document's chain_id is untouched and still matches "
              "the handle — no confounding CHAIN_ID_DISAGREEMENT");
        CHECK(r.ready == 0, "not ready");

        v3pf_close(w);
        v3pf_rmrf(dir);
    }

    /* ── (5) a different handle chain id → CHAIN_ID_DISAGREEMENT. ───── */
    {
        char dir[256];
        CHECK(v3pf_mkdir_tmp(dir, "chainid") == 0, "tmpdir");
        uint8_t chain32[32];
        CHECK(v3pf_derive(dir, chain32, 0x40) == 0, "derive v3");
        nodus_witness_t *w = v3pf_open(dir);
        CHECK(w != NULL, "open");
        /* deliberately WRONG: not the derived chain's own id */
        memset(w->chain_id, 0xEE, 16);
        memset(w->chain_id + 16, 0, 16);

        uint8_t before[64], after[64];
        CHECK(db_digest(w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(w, &r) == 0, "preflight runs");
        CHECK(db_digest(w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "the preflight wrote across a CHAIN_ID_DISAGREEMENT report");
        CHECK(has_issue(&r, NODUS_V2_PF_CHAIN_ID_DISAGREEMENT),
              "a handle chain id that disagrees with the stored "
              "document reports CHAIN_ID_DISAGREEMENT");
        CHECK(r.ready == 0, "not ready");

        v3pf_close(w);
        v3pf_rmrf(dir);
    }

    printf("test_v3_documents: ALL OK\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * R3 W3 delta 8 — HEIGHT-AWARE check 5, the LIVE defect the Genesis
 * Protocol harness found at production constants (evidence kept at
 * /tmp/stagef-20260917T012620Z): every fleet node refused every
 * `w_v2_gbundle_q` once it had committed past height 0, because check 5
 * compared the document's app_hash against the CURRENT committed global
 * root unconditionally, and this ledger's global root changes at every
 * block (Rule N attendance). test_v3_documents's cases above never
 * caught this because every one of them runs on a FRESHLY DERIVED chain
 * — no committed block, tip 0 — which is exactly the case the old code
 * got right.
 *
 * This fixture commits ONE real Comet block (height 1, zero txs) through
 * the REAL apply lane, so section 5's NEW tip>=1 branch has a genuine
 * `v2_blocks` row AND a genuine Comet blockstore BlockMeta at height 1
 * to read.
 *
 * `nodus_cmt_app_finalize_block` + `nodus_cmt_app_commit` alone do NOT
 * populate `cmt_blockstore` — verified by reading the tree: the ONLY
 * caller of `nodus_cmt_bs_save_block` anywhere in this repository is
 * `shared/dnac/cmt_cs.c:2913`, the consensus round driver, which this
 * fixture does not run (that is a full multi-node BFT round, far beyond
 * one preflight case). So this fixture calls `nodus_cmt_bs_save_block`
 * directly too — a REAL, production store function, not a mock of one —
 * from the SAME block, BlockID and part-set the ledger apply used, so
 * the ledger's own bookkeeping and the Comet blockstore stay consistent
 * with each other exactly as a running server keeps them. The "seen
 * commit" this needs carries ZERO signatures: `nodus_cmt_bs_save_block`
 * (`save_block_to_batch`, nodus_witness_cmt_store.c) never verifies a
 * seen commit's signatures, only its height, so this is the honest
 * minimum rather than a faked verification result. */
typedef struct {
    nodus_witness_t          *w;
    v3pf_cfgbox_t              box;
    char                       dir[256];
    uint8_t                    chain32[32];
    cmt_genesis_doc_t          doc;
    cmt_genesis_validator_t    gvals[V3PF_N_VAL];
    nodus_cmt_store_t         *store;
    cmt_state_storage_t       *stor;
    cmt_state_t               *state;
    cmt_valset_scratch_t      *vscratch;
    cmt_state_block_scratch_t *bscratch;
    cmt_block_t               *blk;
    cmt_commit_t               last_commit;   /* borrowed by pointer into
                                               * blk — MUST outlive it */
    uint8_t                   *part_scratch;
    size_t                     part_scratch_cap;
    cmt_part_t                *parts;
    size_t                     parts_cap;
    uint8_t                    meta_scratch[4096];
} pf8_fx_t;

static void pf8_close(pf8_fx_t *x) {
    if (!x) return;
    if (x->store) { nodus_cmt_store_release(x->store); free(x->store); }
    if (x->w) v3pf_close(x->w);
    v3pf_cfg_free(&x->box);
    free(x->stor);
    free(x->state);
    free(x->vscratch);
    free(x->bscratch);
    free(x->blk);
    free(x->parts);
    free(x->part_scratch);
    memset(x, 0, sizeof(*x));
}

/* Derive + open a fresh v3 chain and complete a cometbft State from its
 * OWN genesis document — the same projection
 * `nodus_witness_v2_gen_to_cmt_doc` performs, with the app_hash the
 * derivation actually committed (`nodus_witness_v2_committed_global_root`,
 * the tip<1 reader, matching test_cmt_app.c's `gfx_doc`). */
static int pf8_open(pf8_fx_t *x, const char *tag, uint8_t salt) {
    memset(x, 0, sizeof(*x));
    if (v3pf_cfg_make(&x->box, salt) != 0) return -1;
    if (v3pf_mkdir_tmp(x->dir, tag) != 0) return -1;
    if (nodus_witness_v2_gen_derive_v3(x->dir, x->box.cfg, x->chain32) != 0)
        return -1;
    x->w = v3pf_open(x->dir);
    if (!x->w) return -1;
    memcpy(x->w->chain_id, x->chain32, 16);
    memset(x->w->chain_id + 16, 0, 16);
    x->w->v2_successor = true;
    memcpy(x->w->v2_chain32, x->chain32, 32);

    if (nodus_witness_v2_committed_global_root(x->w, x->box.cfg->app_hash)
            != 0)
        return -1;
    if (nodus_witness_v2_gen_to_cmt_doc(x->box.cfg, &x->doc, x->gvals,
                                        V3PF_N_VAL) != 0)
        return -1;

    x->store    = calloc(1, sizeof(*x->store));
    x->stor     = calloc(1, sizeof(*x->stor));
    x->state    = calloc(1, sizeof(*x->state));
    x->vscratch = calloc(1, sizeof(*x->vscratch));
    x->bscratch = calloc(1, sizeof(*x->bscratch));
    x->blk      = calloc(1, sizeof(*x->blk));
    x->parts_cap        = 8;
    x->parts            = calloc(x->parts_cap, sizeof(*x->parts));
    x->part_scratch_cap = (size_t)8 * CMT_BLOCK_PART_SIZE_BYTES;
    x->part_scratch     = malloc(x->part_scratch_cap);
    if (!x->store || !x->stor || !x->state || !x->vscratch || !x->bscratch ||
        !x->blk || !x->parts || !x->part_scratch)
        return -1;

    if (nodus_cmt_store_init(x->store, x->w->db, false) != CMT_OK) return -1;
    if (cmt_state_init(x->state, x->stor) != CMT_OK) return -1;
    if (cmt_state_make_genesis(&x->doc, NULL, NULL, x->vscratch, x->state)
            != CMT_OK)
        return -1;
    return 0;
}

/* Commit ONE empty block at height 1 through the real apply lane
 * (finalize_block + commit) AND record it in the Comet blockstore
 * (bs_save_block) — see the fixture's own header comment for why both
 * halves are needed. */
static int pf8_commit_block1(pf8_fx_t *x) {
    /* validator[0]'s identity, reproduced exactly as v3pf_cfg_make built
     * it for index 0 under this SAME salt. Historically (O15C) Rule N
     * attendance credited this proposer identity and moved the global
     * root from height 1 on; tokenomics-v3 P1 relocated attendance
     * out-of-root (D-4), so this identity is now cosmetic — it still
     * becomes the block's `proposer_address` header field, but no
     * longer moves anything a preflight check compares against. */
    uint8_t proposer[32];
    {
        uint8_t digest[64];
        if (qgp_sha3_512(x->box.cfg->validators[0].pubkey, DNAC_PUBKEY_SIZE,
                         digest) != 0)
            return -1;
        memcpy(proposer, digest, 32);
    }

    cmt_data_t data;
    memset(&data, 0, sizeof(data));
    memset(&x->last_commit, 0, sizeof(x->last_commit));

    if (cmt_state_make_block(x->state, 1, &data, &x->last_commit, NULL,
                             proposer, sizeof(proposer),
                             x->bscratch, x->blk) != CMT_OK)
        return -1;

    cmt_block_id_t bid;
    memset(&bid, 0, sizeof(bid));
    if (cmt_block_hash(x->blk, bid.hash) != CMT_OK) return -1;
    bid.hash_len = CMT_TMHASH_SIZE;
    cmt_part_set_t ps;
    if (cmt_block_make_part_set(x->blk, CMT_BLOCK_PART_SIZE_BYTES,
                                x->part_scratch, x->part_scratch_cap,
                                x->parts, x->parts_cap, &ps) != CMT_OK)
        return -1;
    if (cmt_part_set_header(&ps, &bid.part_set_header) != CMT_OK) return -1;

    nodus_abci_request_finalize_block_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.hash, bid.hash, bid.hash_len);
    req.hash_len = bid.hash_len;
    memcpy(req.next_validators_hash, x->blk->header.next_validators_hash,
           x->blk->header.next_validators_hash_len);
    req.next_validators_hash_len = x->blk->header.next_validators_hash_len;
    memcpy(req.proposer_address, x->blk->header.proposer_address,
           x->blk->header.proposer_address_len);
    req.proposer_address_len = x->blk->header.proposer_address_len;
    req.height = x->blk->header.height;
    req.time = x->blk->header.time;
    req.txs = x->blk->data.txs;
    req.txs_len = x->blk->data.txs_len;

    nodus_cmt_app_ledger_t *app = calloc(1, sizeof(*app));
    if (!app) return -1;
    int rc = -1;
    if (nodus_cmt_app_ledger_init(app, x->w, &x->doc) == CMT_OK &&
        v3pf_run_sql(x->w->db, "BEGIN IMMEDIATE") == 0) {
        nodus_abci_response_finalize_block_t resp;
        nodus_abci_response_commit_t cresp;
        memset(&resp, 0, sizeof(resp));
        memset(&cresp, 0, sizeof(cresp));
        if (nodus_cmt_app_finalize_block(app, &req, &resp) == CMT_OK &&
            nodus_cmt_app_commit(app, &cresp) == CMT_OK) {
            rc = 0;
        }
    }
    free(app);
    if (rc != 0) return -1;

    cmt_commit_t seen_commit;
    memset(&seen_commit, 0, sizeof(seen_commit));
    seen_commit.height = 1;
    seen_commit.round = 0;
    seen_commit.block_id = bid;
    if (nodus_cmt_bs_save_block(x->store, x->blk, &ps, &seen_commit,
                               x->meta_scratch, sizeof(x->meta_scratch))
            != CMT_OK)
        return -1;
    return 0;
}

/* ── (a) READY after the first block: the property the harness broke.
 * At the time this delta landed, RED TODAY meant exactly issue 17 —
 * before the fix, section 5 unconditionally compared the document's
 * app_hash against the CURRENT committed global root, which the O15C
 * proposer-credit Rule N writer had already moved past the genesis
 * value by height 1.
 *
 * tokenomics-v3 P1 NOTE: that specific discriminator is GONE — attendance
 * is out-of-root now (D-4), so an EMPTY block (this fixture's own
 * `pf8_commit_block1`, no envelopes, no claims) no longer moves the root
 * at all, and this case can no longer tell the fixed comparison from the
 * old buggy one by root movement alone. It still proves a real,
 * independent property: a healthy chain one block past genesis reports
 * READY with zero issues and the preflight itself writes nothing. The
 * "reads block 1's header, not the current root" property that issue 17
 * actually turns on is proved by `test_pf_app_hash_mismatch_after_first_
 * block` below via direct corruption, independent of whether the root
 * naturally moved — that sibling case is the one still pinned to the
 * mechanism. Making THIS case move the root again would need a real
 * transaction in the fixture's block; not done here (P1 whitelist did
 * not include rebuilding this fixture's envelope path). */
static int test_pf_ready_after_first_block(void) {
    printf("=== R3 W3 delta 8 — READY after the first committed block "
           "===\n");

    pf8_fx_t x;
    CHECK(pf8_open(&x, "pf8_ready", 0x50) == 0,
          "v3 chain + cometbft State fixture");
    CHECK(pf8_commit_block1(&x) == 0,
          "one real empty block commits at height 1 (finalize_block + "
          "commit + bs_save_block)");
    {
        sqlite3_int64 n = 0;
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(x.w->db,
                  "SELECT COUNT(*) FROM v2_blocks", -1, &st, NULL)
                  == SQLITE_OK, "prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "step");
        n = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        CHECK(n == 1, "the ledger committed exactly one block row");
    }

    uint8_t before[64], after[64];
    CHECK(db_digest(x.w, before) == 0, "digest before");
    nodus_v2_preflight_report_t r;
    CHECK(nodus_witness_v2_preflight(x.w, &r) == 0, "preflight runs");
    CHECK(db_digest(x.w, after) == 0, "digest after");
    CHECK(memcmp(before, after, 64) == 0,
          "the preflight wrote nothing — committing the block was the "
          "only write, and it happened BEFORE this digest pair");
    CHECK(!has_issue(&r, NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH),
          "no app_hash mismatch reported one block past genesis — "
          "post-tokenomics-v3-P1 this empty block does not move the "
          "root at all (attendance is out-of-root, D-4), so this "
          "assertion no longer discriminates the historical bug by "
          "itself; test_pf_app_hash_mismatch_after_first_block below "
          "does, via direct corruption of block 1's header app_hash");
    CHECK(r.n_issues == 0, "a healthy chain one block past genesis is "
          "READY with zero issues");
    CHECK(r.ready == 1, "ready");

    {
        /* ORCHESTRATOR (integration): pf8_close zeroes the fixture, so
         * the directory name must be taken BEFORE it — otherwise rmrf
         * runs on "" and the temp chain is left behind. */
        char dir[256];
        snprintf(dir, sizeof(dir), "%s", x.dir);
        pf8_close(&x);
        v3pf_rmrf(dir);
    }
    printf("test_pf_ready_after_first_block: ALL OK\n");
    return 0;
}

/* ── (b) the check keeps its teeth past height 0: a genesis whose BLOCK
 * 1 does not carry the document's claimed app_hash still reports issue
 * 17. The corruption is NOT the stored document (flipping its app_hash
 * would also change the document's OWN self-hash — app_hash sits inside
 * the chain_id preimage, nodus_witness_v2_gen.h's layout — confounding
 * this case with GENESIS_MALFORMED or CHAIN_ID_DISAGREEMENT, exactly
 * the confound test_v3_documents case (4) was written to avoid for the
 * tip<1 branch). The tip>=1 branch's own ledger-side equivalent is
 * BLOCK 1's header app_hash, so THAT is what is corrupted here — the
 * cometbft State's tracked `app_hash` is flipped AFTER
 * `cmt_state_make_genesis` completes it from the (untouched) document
 * but BEFORE `cmt_state_make_block` copies it into the built block's
 * header, so the committed block 1 carries a WRONG app_hash while the
 * stored document is byte-for-byte what a correct derivation wrote. */
static int test_pf_app_hash_mismatch_after_first_block(void) {
    printf("=== R3 W3 delta 8 — app_hash mismatch survives past height 0 "
           "===\n");

    pf8_fx_t x;
    CHECK(pf8_open(&x, "pf8_mismatch", 0x60) == 0,
          "v3 chain + cometbft State fixture");
    x.state->app_hash[0] ^= 0xFF;   /* THE TAMPER: block 1 will carry this */
    CHECK(pf8_commit_block1(&x) == 0,
          "the ledger applies the block regardless — FinalizeBlock's own "
          "app_hash is the ledger's REAL committed root, independent of "
          "what this test wrote into the block header");

    uint8_t before[64], after[64];
    CHECK(db_digest(x.w, before) == 0, "digest before");
    nodus_v2_preflight_report_t r;
    CHECK(nodus_witness_v2_preflight(x.w, &r) == 0, "preflight runs");
    CHECK(db_digest(x.w, after) == 0, "digest after");
    CHECK(memcmp(before, after, 64) == 0,
          "the preflight wrote nothing across the mismatch report");
    CHECK(has_issue(&r, NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH),
          "block 1's header app_hash disagrees with the stored "
          "document's — issue 17 fires past height 0 too, so the "
          "height-aware fix did not just delete the check's teeth");
    CHECK(!has_issue(&r, NODUS_V2_PF_GENESIS_MALFORMED),
          "the stored document itself is untouched — no GENESIS_MALFORMED");
    CHECK(!has_issue(&r, NODUS_V2_PF_CHAIN_ID_DISAGREEMENT),
          "the document's chain_id is untouched and still matches the "
          "handle — no confounding CHAIN_ID_DISAGREEMENT");
    CHECK(r.ready == 0, "not ready");

    {
        char dir[256];   /* same as above: read the name before the close */
        snprintf(dir, sizeof(dir), "%s", x.dir);
        pf8_close(&x);
        v3pf_rmrf(dir);
    }
    printf("test_pf_app_hash_mismatch_after_first_block: ALL OK\n");
    return 0;
}

int main(void) {
    printf("=== O15A obligation 7 — activation-readiness preflight ===\n");

    fx_t f = {0};
    CHECK(fx_open(&f, "main") == 0, "fixture");

    /* ── 1. READ-ONLY, proven by digest. This is the property that makes
     * the preflight a preflight rather than a migration. */
    {
        uint8_t before[64], after[64];
        CHECK(db_digest(f.w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "preflight runs");
        CHECK(db_digest(f.w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "THE PREFLIGHT WROTE TO THE DATABASE");
    }

    /* ── 2. DETERMINISTIC: the same database yields a byte-identical
     * report. Without this a report could not be compared across nodes
     * or across restarts, which is the whole point of having one. */
    {
        nodus_v2_preflight_report_t a, b;
        CHECK(nodus_witness_v2_preflight(f.w, &a) == 0, "run a");
        CHECK(nodus_witness_v2_preflight(f.w, &b) == 0, "run b");
        CHECK(a.n_issues == b.n_issues, "issue count differs between runs");
        CHECK(memcmp(a.issues, b.issues,
                     a.n_issues * sizeof(a.issues[0])) == 0,
              "issue LIST differs between runs");
        CHECK(a.ready == b.ready, "ready differs between runs");
    }

    /* ── 3. CANONICAL ORDER: issues ascend by id, so the report is a
     * function of the database and not of check-execution order. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        for (size_t i = 1; i < r.n_issues; i++)
            CHECK((int)r.issues[i - 1] < (int)r.issues[i],
                  "issues are not in strictly ascending canonical order");
    }

    /* ── 4. MULTIPLE issues are reported together, not just the first.
     * A fresh chain database is missing several prerequisites at once. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(r.n_issues >= 2,
              "a fresh database must report MORE than one issue");
        CHECK(r.ready == 0, "a fresh database must not be ready");
    }

    /* ── 5. O15C — issue 12 is RETIRED, and stays retired.
     * O15A raised RULE_N_ATTENDANCE_SOURCE_ABSENT unconditionally
     * because the build had no V2 attendance writer; O15C shipped a
     * first writer, and tokenomics-v3 P1 replaced it with
     * `nodus_witness_v2_attendance_credit` (real signature attendance
     * from cometbft's decided_last_commit) + the rewritten Rule N
     * (`v2ep_rule_n`) — the issue's own documented removal condition is
     * still met. It must never be raised again — a resurrected raise
     * would mean the writer was lost. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(!has_issue(&r, NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT),
              "issue 12 is retired — the V2 attendance writer exists in "
              "this build");
        CHECK(r.ready == 0,
              "a fresh database is still not ready (schema/genesis)");
    }

    /* ── 6. SCHEMA: R3 W3 (D-17 rev 10 (8)) — THE LIVE SCHEMA FLIP,
     * tokenomics-v3 P1 moved the accepted value S14 -> S15, tokenomics-v3
     * P2 moved it S15 -> S16. Before R3 W3
     * S10 (O15C's activation version) cleared this issue; the flip
     * narrows the accepted set to ONE value, because the old lane's
     * consensus schemas (S10-S12) are closed (D-17 rev 10 (9)) and this
     * build derives version-3 chains only. v9 and v12 — a version this
     * function used to ACCEPT — must now BOTH be reported UNSUPPORTED;
     * only landing at S16 clears it — and S15, the previous live rung,
     * no longer does. This is the mirror pin: the narrowing is real in
     * both directions, not just "S16 was added". */
    {
        nodus_v2_preflight_report_t before_mig, at_v9, at_v12, at_s15,
                                    at_s16;
        CHECK(nodus_witness_v2_preflight(f.w, &before_mig) == 0, "run");
        CHECK(has_issue(&before_mig, NODUS_V2_PF_SCHEMA_UNSUPPORTED),
              "pre-migration schema must be reported unsupported");

        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0, "migrate to v9");
        CHECK(nodus_witness_v2_preflight(f.w, &at_v9) == 0, "run");
        CHECK(has_issue(&at_v9, NODUS_V2_PF_SCHEMA_UNSUPPORTED),
              "v9 must be UNSUPPORTED (never accepted, before or after "
              "the flip)");

        CHECK(nodus_witness_db_migrate_v2s12(f.w) == 0, "migrate to v12");
        CHECK(nodus_witness_v2_preflight(f.w, &at_v12) == 0, "run");
        CHECK(has_issue(&at_v12, NODUS_V2_PF_SCHEMA_UNSUPPORTED),
              "v12 must be UNSUPPORTED since R3 W3 — it was accepted "
              "before the flip and is not any more (D-17 rev 10 (9): "
              "the old lane's schemas are closed)");

        CHECK(nodus_witness_db_migrate_v2s15(f.w) == 0, "migrate to S15");
        CHECK(nodus_witness_v2_preflight(f.w, &at_s15) == 0, "run");
        CHECK(has_issue(&at_s15, NODUS_V2_PF_SCHEMA_UNSUPPORTED),
              "S15 must be UNSUPPORTED since tokenomics-v3 P2 — the "
              "reward tables are guaranteed only at S16");

        CHECK(nodus_witness_db_migrate_v2s16(f.w) == 0, "migrate to S16");
        CHECK(nodus_witness_v2_preflight(f.w, &at_s16) == 0, "run");
        CHECK(!has_issue(&at_s16, NODUS_V2_PF_SCHEMA_UNSUPPORTED),
              "S16 must clear the schema issue — it is the only accepted "
              "version now");
        CHECK(at_s16.ready == 0, "still not ready (no genesis document yet)");
    }

    /* ── 7. GENESIS ABSENT is detected on a migrated-but-empty chain. */
    {
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(has_issue(&r, NODUS_V2_PF_GENESIS_ABSENT),
              "an empty v2_blocks must report GENESIS_ABSENT");
    }

    /* ── 8. READ-ONLY again, now on a migrated database with more state
     * to touch — the first digest check ran on a nearly empty one. */
    {
        uint8_t before[64], after[64];
        CHECK(db_digest(f.w, before) == 0, "digest before");
        nodus_v2_preflight_report_t r;
        CHECK(nodus_witness_v2_preflight(f.w, &r) == 0, "run");
        CHECK(db_digest(f.w, after) == 0, "digest after");
        CHECK(memcmp(before, after, 64) == 0,
              "the preflight wrote to a migrated database");
    }

    /* ── 9. NULL handling: an inspection that cannot run is NOT ready.
     * "-1" must never be mistaken for a clean bill of health. */
    {
        nodus_v2_preflight_report_t r;
        memset(&r, 0xff, sizeof(r));
        CHECK(nodus_witness_v2_preflight(NULL, &r) == -1, "NULL witness");
        CHECK(r.ready == 0, "a failed inspection must not report ready");
        CHECK(nodus_witness_v2_preflight(f.w, NULL) == -1, "NULL report");
    }

    /* ── 10. Every issue id has a stable name (tooling pins these).
     *
     * DRIFT REPAIR: this loop stopped at NODUS_V2_PF_INSPECTION_FAULT
     * (14) since before ids 15/16 (O15J's retired values) existed,
     * silently never checking them — found while adding id 17
     * (R3 W3, GENESIS_APP_HASH_MISMATCH) here. The bound is now the
     * actual highest declared id. */
    {
        for (int id = 1; id <= NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH; id++) {
            const char *n =
                nodus_witness_v2_preflight_issue_name((nodus_v2_pf_issue_t)id);
            CHECK(n != NULL && strcmp(n, "UNKNOWN") != 0,
                  "every declared issue id needs a stable name");
        }
    }

    fx_close(&f);

    if (test_v3_documents() != 0) return 1;
    if (test_pf_ready_after_first_block() != 0) return 1;
    if (test_pf_app_hash_mismatch_after_first_block() != 0) return 1;

    printf("test_v2_preflight: ALL %d checks passed\n", checks);
    return 0;
}
