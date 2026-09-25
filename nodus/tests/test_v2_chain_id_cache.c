/**
 * @file test_v2_chain_id_cache.c
 * @brief Nodus — the chain-id cache of nodus_witness_v2_chain_id
 *        (capacity measurements 2026-09-25, §5 item A; nodus 0.19.79).
 *
 * WHAT IT PROVES — each property would be false if the case failed:
 *   (a) On a REAL version-3 chain opened through the PRODUCTION open path
 *       (v2x_chain_open: nodus_witness_v2_gen_derive_v3 →
 *       nodus_witness_create_chain_db → witness_post_open_gate), the gate
 *       marks the cache valid, and nodus_witness_v2_chain_id returns the
 *       SAME 32 bytes nodus_witness_v2_gen_stored_chain_id derives from
 *       the stored document. A second open of the same handle re-arms
 *       the cache with the same bytes.
 *   (b) With the cache valid, nodus_witness_v2_chain_id answers WITHOUT
 *       reading the document: after the "genesisDoc" row is deleted
 *       underneath the open handle it still returns the chain id, while
 *       the underlying derivation, a handle that never passed the gate,
 *       and the same handle with the flag cleared all FAIL CLOSED. A
 *       re-open of the document-less database is refused by the gate
 *       and leaves the flag false. THIS CASE FAILS WITHOUT THE CACHE (the
 *       per-call derivation returns -1 once the row is gone). It is also
 *       the honest statement of the one thing the cache gives up: a
 *       document altered after open is no longer caught per call — only
 *       at the next open.
 *   (c) A handle that never passed the gate — flag false by calloc —
 *       still derives from the document, even with `v2_successor` set
 *       and `v2_chain32` holding garbage or zeros (the shape every
 *       scratch and hand-built test handle has). This is the guard
 *       against keying the cache on `v2_successor` (the WRONG first
 *       design §5 A records): under that design this case returns the
 *       garbage/zeros instead of the chain id.
 *   (d) The JOINER's re-derivation shape (nodus_witness_v2_join.c
 *       join_adopt: calloc'd handle → create_chain_db on an empty
 *       scratch dir → v2_successor = 1 by hand → S16 + chain_config
 *       migrations → nodus_witness_v2_bundle_apply(pin) →
 *       nodus_witness_v2_chain_id == pin) still reaches the pin with the
 *       flag false. Under a v2_successor-keyed cache this returns zeros
 *       and every join is refused. join_adopt itself is static and
 *       network-driven; the full path runs only in the Genesis Protocol
 *       harness (stagef tests/test_v2_join.sh). The derivation's own
 *       scratch handle (nodus_witness_v2_gen.c, v2_successor set by hand)
 *       is exercised by every v2x_chain_open below.
 *
 * WHAT IT REQUIRES: a default Debug build of the nodus tree. No compile
 * flags beyond register_witness_test's NODUS_WITNESS_INTERNAL_API, no
 * environment variables.
 *
 * WHAT IT LEAVES BEHIND: nothing — every mkdtemp directory under /tmp
 * (v2x_chidc_*, v2x_chidj_*, v2x_chids_*) is removed on the success path.
 * A failed CHECK returns early and may leave them.
 *
 * HOW IT CAN LIE:
 *   - (b) is honest only because (a) first ASSERTS the gate set the flag
 *     (v2x_chain_open additionally asserts v2_successor / v2_chain32 came
 *     from the gate). If a future fixture set the flag by hand, (b) would
 *     prove the accessor, not the gate's lifecycle.
 *   - (d) mirrors join_adopt's sequence line by line but does not call
 *     it; a reordering inside join_adopt is not caught here.
 *   - Nothing here measures speed; the ~35% busy-time figure that
 *     motivated the cache is a local stack-sampling profile (capacity
 *     measurements §2c), not a live measurement.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_cmt_store.h"
#include "nodus/nodus_chain_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void rm_dir(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

/* A handle that never passed the gate, sharing `db` — the pattern of
 * test_v2_gen.c's raw readers. `db` is NOT owned: the caller NULLs it
 * before freeing. */
static nodus_witness_t *raw_handle(sqlite3 *db) {
    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB: heap */
    if (!w) return NULL;
    w->cached_committee_epoch_start = UINT64_MAX;
    w->db = db;
    return w;
}

static int delete_genesis_doc(sqlite3 *db) {
    nodus_cmt_store_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    int rc = -1;
    if (nodus_cmt_store_init(s, db, false) == CMT_OK) {
        rc = nodus_cmt_store_delete(s, /*state_table=*/true,
                                    NODUS_V2_GEN_GENESIS_DOC_KEY) == CMT_OK
                 ? 0 : -1;
        nodus_cmt_store_release(s);
    }
    free(s);
    return rc;
}

/* ── (a) + (b) + (c) on one chain ───────────────────────────────────── */
static int t_cache_on_gated_chain(void) {
    v2x_chain_t ch;
    CHECK(v2x_chain_open(&ch, "chidc", 0x00) == 0,
          "version-3 chain (derive + production open)"); OK();

    /* (a) the gate armed the cache with the document's id */
    CHECK(ch.w->v2_chain32_valid,
          "the post-open gate marks the chain-id cache valid"); OK();
    uint8_t derived[32], got[32];
    CHECK(nodus_witness_v2_gen_stored_chain_id(ch.w, derived) == 0,
          "the stored document derives"); OK();
    CHECK(memcmp(derived, ch.chain32, 32) == 0,
          "the document derives to the chain the ceremony produced"); OK();
    memset(got, 0xAB, sizeof(got));
    CHECK(nodus_witness_v2_chain_id(ch.w, got) == 0, "chain id"); OK();
    CHECK(memcmp(got, derived, 32) == 0,
          "the cached answer is byte-identical to the derivation"); OK();

    /* a second open of the SAME handle: the flag is cleared with the old
     * handle and re-armed by the gate from the same document */
    CHECK(nodus_witness_create_chain_db(ch.w, ch.chain32) == 0,
          "re-open through the production path"); OK();
    CHECK(ch.w->v2_chain32_valid, "the re-open re-arms the cache"); OK();
    memset(got, 0xAB, sizeof(got));
    CHECK(nodus_witness_v2_chain_id(ch.w, got) == 0 &&
          memcmp(got, derived, 32) == 0,
          "and it answers the same id"); OK();

    /* (c) never-gated handles derive — whatever v2_successor/v2_chain32
     * say. Garbage first, then the scratch shape (successor, zeros). */
    nodus_witness_t *raw = raw_handle(ch.w->db);
    CHECK(raw != NULL, "alloc"); OK();
    CHECK(!raw->v2_chain32_valid, "calloc leaves the flag false"); OK();
    raw->v2_successor = true;
    memset(raw->v2_chain32, 0xEE, 32);
    memset(got, 0xAB, sizeof(got));
    CHECK(nodus_witness_v2_chain_id(raw, got) == 0 &&
          memcmp(got, derived, 32) == 0,
          "a never-gated handle answers from the DOCUMENT, not from a "
          "hand-set v2_chain32"); OK();
    memset(raw->v2_chain32, 0, 32);
    memset(got, 0xAB, sizeof(got));
    CHECK(nodus_witness_v2_chain_id(raw, got) == 0 &&
          memcmp(got, derived, 32) == 0,
          "the scratch shape (v2_successor set, v2_chain32 zero) still "
          "derives — the cache is not keyed on v2_successor"); OK();

    /* (b) the row goes; only the gated, flagged handle still answers */
    CHECK(delete_genesis_doc(ch.w->db) == 0,
          "the stored genesis document is removed under the open handle");
    OK();
    CHECK(nodus_witness_v2_gen_stored_chain_id(ch.w, got) != 0,
          "precondition: the document is really gone"); OK();
    memset(got, 0xAB, sizeof(got));
    CHECK(nodus_witness_v2_chain_id(ch.w, got) == 0 &&
          memcmp(got, derived, 32) == 0,
          "with the cache valid the id is answered WITHOUT the document "
          "(fails without the cache)"); OK();

    memset(got, 0xAB, sizeof(got));
    CHECK(nodus_witness_v2_chain_id(raw, got) != 0,
          "a never-gated handle fails closed on the same database"); OK();
    {
        uint8_t untouched[32];
        memset(untouched, 0xAB, sizeof(untouched));
        CHECK(memcmp(got, untouched, 32) == 0,
              "and its buffer was not written"); OK();
    }
    raw->db = NULL;
    free(raw);

    ch.w->v2_chain32_valid = false;
    memset(got, 0xAB, sizeof(got));
    CHECK(nodus_witness_v2_chain_id(ch.w, got) != 0,
          "the same handle with the flag cleared fails closed"); OK();

    /* the next open is where a missing/altered document is caught */
    ch.w->v2_chain32_valid = true;       /* a stale flag must not survive */
    CHECK(nodus_witness_create_chain_db(ch.w, ch.chain32) != 0,
          "the gate refuses the document-less database on re-open"); OK();
    CHECK(ch.w->db == NULL, "and closed it"); OK();
    CHECK(!ch.w->v2_chain32_valid,
          "and the refused open left the cache invalid"); OK();
    CHECK(nodus_witness_v2_chain_id(ch.w, got) != 0,
          "no handle, no id"); OK();

    v2x_chain_close(&ch);
    return 0;
}

/* ── (d) the joiner's re-derivation shape ───────────────────────────── */
static int t_joiner_shape(void) {
    v2x_chain_t src;
    CHECK(v2x_chain_open(&src, "chids", 0x10) == 0,
          "source version-3 chain"); OK();
    uint8_t *bundle = NULL;
    size_t   blen = 0;
    CHECK(nodus_witness_v2_bundle_get(src.w, &bundle, &blen) == 0 &&
          bundle && blen > 0, "the derivation persisted a bundle"); OK();

    char jdir[128];
    snprintf(jdir, sizeof(jdir), "/tmp/v2x_chidj_XXXXXX");
    CHECK(mkdtemp(jdir) != NULL, "joiner tmpdir"); OK();

    /* join_adopt (nodus_witness_v2_join.c) — the same steps, in order */
    nodus_witness_t *w2 = calloc(1, sizeof(*w2));
    CHECK(w2 != NULL, "alloc"); OK();
    w2->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w2->data_path, sizeof(w2->data_path), "%s", jdir);
    uint8_t prov16[16];
    memcpy(prov16, src.chain32, 16);
    CHECK(nodus_witness_create_chain_db(w2, prov16) == 0,
          "scratch chain db"); OK();
    CHECK(!w2->v2_chain32_valid && !w2->v2_successor,
          "the gate on an empty scratch arms nothing"); OK();
    w2->v2_successor = 1;
    CHECK(nodus_witness_db_migrate_v2s16(w2) == 0, "S16"); OK();
    CHECK(nodus_chain_config_db_migrate(w2) == 0, "chain config"); OK();
    CHECK(nodus_witness_v2_bundle_apply(w2, bundle, blen, src.chain32) == 0,
          "the bundle re-derives to the pin"); OK();
    CHECK(!w2->v2_chain32_valid,
          "the joiner's scratch handle never has a valid cache"); OK();
    uint8_t chain32[32];
    memset(chain32, 0, sizeof(chain32));
    CHECK(nodus_witness_v2_chain_id(w2, chain32) == 0,
          "the joiner's chain id derives"); OK();
    CHECK(memcmp(chain32, src.chain32, 32) == 0,
          "and equals the pin (a v2_successor-keyed cache would answer "
          "zeros here)"); OK();

    sqlite3_close(w2->db);
    w2->db = NULL;
    free(w2);
    rm_dir(jdir);
    free(bundle);
    v2x_chain_close(&src);
    return 0;
}

int main(void) {
    if (t_cache_on_gated_chain() != 0) return 1;
    if (t_joiner_shape() != 0) return 1;
    printf("test_v2_chain_id_cache: %d checks OK\n", g_checks);
    return 0;
}
