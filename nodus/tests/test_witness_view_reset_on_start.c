/**
 * Nodus — O15P Faz 1 — the view counter comes up at 0, the prepared
 *                      certificate comes back
 *
 * WHAT THIS PROVES.
 *   nodus_witness_db_load_pbft_state (nodus_witness_db.c) gives the two
 *   fields of the pbft_state row OPPOSITE answers, and both halves are
 *   load-bearing:
 *
 *     - `current_view` is DISCARDED. A witness enters consensus at view 0
 *       no matter what is stored, so a fleet-wide restart converges
 *       because the CODE says so rather than because an operator
 *       remembered `DELETE FROM pbft_state` (docs/DEPLOY_RUNBOOK.md
 *       §2.1). That runbook step and the memory-only `w->viewok_proof`
 *       (nodus/BUGS.md O15N-R2) were load-bearing TOGETHER; this removes
 *       the dependency on the human half of the pair.
 *
 *     - `last_prepared` is RESTORED, byte for byte. It is the
 *       prepared-value lock's memory, and the quorum-intersection safety
 *       argument depends on that lock surviving a restart.
 *
 *   The property that would be false if §1's view assertion failed: a
 *   restarted witness re-enters consensus holding a view it can no longer
 *   prove, and a fleet restarted together comes up split.
 *
 *   The property that would be false if §1's certificate assertions
 *   failed: the view reset silently disabled the O15O Faz 6 safety
 *   refusal, and a restarted node would stop refusing a value that
 *   conflicts with one it had itself prepared — which is the refusal that
 *   makes a fork unreachable. §1 asserts this at the LOCK
 *   (nodus_witness_bft_prepared_lock_blocks), not merely at the struct
 *   fields, because the lock is what consensus actually consults.
 *
 *   EVERY SECTION IS A PAIR ON ONE FIXTURE SHAPE. The view assertion
 *   alone proves little — a witness that never loaded anything is also at
 *   view 0. Each section therefore asserts, on the SAME reopened handle,
 *   that the certificate DID come back; and §1 additionally asserts the
 *   stored ROW still holds its non-zero number, which is the only direct
 *   evidence that the loader read a row and chose to ignore that column
 *   rather than never having seen one.
 *
 *   ALL FIVE SECTIONS RUN UNCONDITIONALLY. There is no UNREACHED row in
 *   this file and no rc=99 skip: every section runs or the binary exits
 *   non-zero.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro. Nothing
 *   here depends on DNAC_EPOCH_LENGTH: no committee is resolved, no block
 *   is committed and no epoch boundary is crossed, so every assertion
 *   holds identically at the shipped 720 and at the harness's 15.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no pre-exported variable. The one filesystem dependency
 *   is a writable /tmp for mkdtemp.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Each section builds its chain database in its own mkdtemp()
 *   directory under /tmp — which also collects the `archive/`
 *   subdirectory and the partial-wipe genesis marker that
 *   nodus_witness_create_chain_db writes — and removes the whole
 *   directory with `rm -rf` before returning. Every witness handle is
 *   closed through nodus_witness_close, so no sqlite handle and no WAL
 *   file outlives a section. No processes, no arm files, no restarted
 *   nodes, no network ports.
 *
 * HOW IT CAN LIE.
 *   - VIEW 0 IS ALSO THE UNTOUCHED DEFAULT. `w->current_view == 0` on a
 *     freshly calloc'd witness proves nothing on its own — a build whose
 *     loader was deleted outright would pass that assertion. Every
 *     section is therefore paired with a certificate assertion on the
 *     SAME handle (the loader demonstrably ran), and §1 further asserts
 *     the stored row still reads 9 (the loader saw a row and discarded
 *     that column). §4 closes the remaining gap from the other side: it
 *     sets a NON-ZERO view in memory and requires the loader to pull it
 *     down, which no absent loader can do.
 *   - THE REOPEN COULD NOT BE A REOPEN. If nodus_witness_create_chain_db
 *     ever started with an empty database instead of the existing one,
 *     §1-§3 would be testing a fresh chain and the certificate would come
 *     back absent — so the certificate assertion, not the view assertion,
 *     is what detects that. The reopen is a REAL second open of the same
 *     file: the same 16-byte chain id produces the same filename, and
 *     witness_archive_stale_chain_dbs keeps every file whose name matches
 *     that basename prefix, including its -wal and -shm
 *     (nodus_witness.c, the keep_filename branch). The same reopen shape
 *     is used by test_v2_restart_gate.c and test_v2_pools.c.
 *   - §5 COULD PASS FOR THE WRONG REASON. `DROP TABLE pbft_state` makes
 *     the loader's prepare fail, and a witness that never had a view set
 *     would read 0 either way — so §5 sets current_view to a non-zero
 *     value FIRST and requires the loader to have zeroed it despite
 *     returning -1. It also requires the -1 itself, so a build that
 *     stopped reporting the failure fails here.
 *   - WHAT IT CANNOT SEE. This file exercises the loader through
 *     nodus_witness_create_chain_db, which is one of the two production
 *     entrances to a chain database. The other — the restart scan
 *     (nodus_witness_scan_chain_db) — reaches the SAME
 *     witness_db_open_attempt and the same single load call site
 *     (nodus_witness.c:533), but this file does not drive it: the scan
 *     needs a data directory laid out the way a live node's is. §4
 *     compensates by pinning the reset inside the CALLEE, so any
 *     entrance that calls the loader at all inherits it.
 *   - IT PROVES NOTHING ABOUT THE PULL. That a node which comes up
 *     behind then RECOVERS by requesting a VIEW_OK proof
 *     (nodus_witness_bft.c:5746, :10411) is the other half of the
 *     argument and is not exercised here; it is covered by the VIEW_OK
 *     handler tests, and this file deliberately does not restate it.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"   /* nodus_witness_bft_prepared_lock_blocks */
#include "witness/nodus_witness_db.h"    /* save/load pbft_state — the subject */
#include "protocol/nodus_tier3.h"
#include "nodus/nodus_types.h"           /* NODUS_T3_* lengths, NODUS_SIG_BYTES */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAIL %s:%d — %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    printf("  ok: %s\n", msg); \
} while (0)

/* ═══════════════════════════════════════════════════════════════════
 * Fixture
 *
 * nodus_witness_t is multi-MB: heap, never stack (repo discipline).
 * v2_successor is NEVER hard-set — nodus_witness_create_chain_db derives
 * the chain role itself inside its post-open gate, and a test that set
 * the flag by hand would mask exactly the kind of defect that derivation
 * exists to catch (test_v2_gen.c:307).
 * ═══════════════════════════════════════════════════════════════════ */

static nodus_witness_t *fixture(const char *dir) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { fprintf(stderr, "fixture alloc\n"); exit(1); }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    /* The per-epoch committee cache has no invalidation hook and is keyed
     * on e_start, so a calloc'd 0 would read as a HIT for epoch 0 before
     * anything had been computed. Reset the sentinel exactly as the
     * production init path does. Nothing here resolves a committee, but
     * the fixture must not differ from production in a way a future
     * assertion could trip over. */
    w->cached_committee_epoch_start = UINT64_MAX;
    return w;
}

/* THE OPEN — and, on a second call with the same id, THE RESTART.
 *
 * nodus_witness_create_chain_db is the production creator: it archives
 * non-matching chain files, opens witness_<hex>.db, applies the schema
 * (CREATE TABLE IF NOT EXISTS throughout), runs the idempotent migration
 * umbrella that installs pbft_state, calls
 * nodus_witness_db_load_pbft_state — the function under test — and then
 * runs the post-open integrity gate. Nothing in that sequence is
 * destructive to an existing database, which is what makes calling it
 * twice on one directory a faithful restart rather than a re-creation. */
static void open_chain(nodus_witness_t *w, uint8_t tag) {
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0 || !w->db) {
        fprintf(stderr, "create_chain_db failed\n");
        exit(1);
    }
}

static void close_fixture(nodus_witness_t *w) {
    if (!w) return;
    nodus_witness_close(w);   /* closes the sqlite handle */
    free(w);
}

static void make_dir(char *tmpl) {
    if (mkdtemp(tmpl) == NULL) { fprintf(stderr, "mkdtemp failed\n"); exit(1); }
}

static void rm_dir(const char *dir) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* best-effort cleanup */ }
}

/* ═══════════════════════════════════════════════════════════════════
 * The pbft_state row, read directly — the evidence that the loader saw a
 * row and IGNORED its view column, rather than never having seen one.
 *
 * Same shape as test_witness_pbft_save_fault.c's pbft_row, and kept
 * separate from the loader on purpose: a helper that called the loader
 * could not distinguish "the row says 9" from "the loader says 0".
 *
 *  1 = the singleton row exists (view / has_blob filled)
 *  0 = the table is there and the row is not
 * -1 = the table itself is gone
 * ═══════════════════════════════════════════════════════════════════ */
static int pbft_row(nodus_witness_t *w, uint32_t *view, bool *has_blob) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT current_view, last_prepared_blob FROM pbft_state "
            "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int out = 0;
    if (rc == SQLITE_ROW) {
        if (view) *view = (uint32_t)sqlite3_column_int64(st, 0);
        if (has_blob) *has_blob = sqlite3_column_type(st, 1) != SQLITE_NULL;
        out = 1;
    }
    sqlite3_finalize(st);
    return out;
}

/* ═══════════════════════════════════════════════════════════════════
 * The prepared certificate — seeded deterministically, checked byte for
 * byte.
 *
 * The whole struct is memset to 0 first and then filled, so the SAVED
 * bytes are fully determined by (height, view, tag, n_sigs) — including
 * every slot past n_sigs. That is what lets the reload be checked with a
 * single memcmp over the entire struct: the blob is persisted as raw
 * struct bytes (nodus_witness_db_save_pbft_state), so a byte-exact
 * comparison is the tightest statement available, and the field-by-field
 * checks beside it exist only to make a failure readable.
 *
 * No real signatures: this file tests a database round trip, not
 * signature verification, and nothing it calls verifies a signature.
 * ═══════════════════════════════════════════════════════════════════ */

#define CERT_SIGS 3

static void seed_cert(nodus_witness_t *w, uint64_t height, uint32_t view,
                      uint8_t tag) {
    memset(&w->last_prepared, 0, sizeof(w->last_prepared));
    w->last_prepared.present = true;
    w->last_prepared.height  = height;
    w->last_prepared.view    = view;
    w->last_prepared.round   = view + 100u;
    for (int i = 0; i < NODUS_T3_TX_HASH_LEN; i++)
        w->last_prepared.tx_hash[i] = (uint8_t)(tag + i);
    w->last_prepared.n_sigs = CERT_SIGS;
    for (int k = 0; k < CERT_SIGS; k++) {
        for (int i = 0; i < NODUS_T3_WITNESS_ID_LEN; i++)
            w->last_prepared.sigs[k].voter_id[i] = (uint8_t)(tag + k * 7 + i);
        for (int i = 0; i < NODUS_SIG_BYTES; i++)
            w->last_prepared.sigs[k].signature[i] = (uint8_t)(tag ^ (k + i));
    }
}

/* The tx_hash seed_cert produced, rebuilt without a witness — used to
 * drive the prepared-value lock after the restart. */
static void cert_tx_hash(uint8_t out[NODUS_T3_TX_HASH_LEN], uint8_t tag) {
    for (int i = 0; i < NODUS_T3_TX_HASH_LEN; i++)
        out[i] = (uint8_t)(tag + i);
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — A STORED VIEW OF 9 COMES BACK AS 0, AND THE CERTIFICATE COMES
 *      BACK WHOLE.
 *
 * The pair that carries this file. One thing moves between the two
 * handles: the process restarted. The stored view is high enough that no
 * default could be mistaken for it, and the certificate's OWN view (7) is
 * deliberately DIFFERENT from the counter (9) so a build that copied one
 * into the other could not pass.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_stored_view_discarded(void) {
    printf("\n§1 stored view 9 -> 0, prepared certificate intact\n");

    char dir[] = "/tmp/nodus_viewreset1_XXXXXX";
    make_dir(dir);

    const uint64_t CERT_H    = 41;
    const uint32_t CERT_VIEW = 7;
    const uint32_t STORED    = 9;
    const uint8_t  TAG       = 0x5A;

    /* Kept outside the witness so the comparison survives the free. */
    void *saved = malloc(sizeof(((nodus_witness_t *)0)->last_prepared));
    if (!saved) { fprintf(stderr, "saved alloc\n"); exit(1); }

    /* ── the first life ───────────────────────────────────────────── */
    {
        nodus_witness_t *w = fixture(dir);
        open_chain(w, TAG);

        uint32_t rv = 0; bool rb = false;
        CHECK(pbft_row(w, &rv, &rb) == 0,
              "precondition: a fresh chain DB has the pbft_state table and "
              "no row");

        w->current_view = STORED;
        seed_cert(w, CERT_H, CERT_VIEW, TAG);
        memcpy(saved, &w->last_prepared, sizeof(w->last_prepared));

        CHECK(nodus_witness_db_save_pbft_state(w) == 0,
              "the save reports success");
        CHECK(pbft_row(w, &rv, &rb) == 1 && rv == STORED && rb,
              "the row landed with current_view 9 and a non-NULL blob");

        close_fixture(w);
    }

    /* ── THE RESTART ──────────────────────────────────────────────── */
    {
        nodus_witness_t *w = fixture(dir);
        open_chain(w, TAG);   /* load_pbft_state runs inside this call */

        /* ── the assertion this file exists for ───────────────────── */
        CHECK(w->current_view == 0,
              "THE VIEW COUNTER IS 0 after a restart that had 9 stored — "
              "the node enters consensus at 0 and pulls a proof from a "
              "peer that is ahead");

        /* ── and the assertion that stops the fix from quietly
         *    disabling the O15O Faz 6 safety lock ──────────────────── */
        CHECK(w->last_prepared.present,
              "the prepared certificate came back PRESENT — the reset did "
              "NOT clear it");
        CHECK(w->last_prepared.height == CERT_H,
              "certificate height survived");
        CHECK(w->last_prepared.view == CERT_VIEW,
              "certificate view survived, and it is the cert's OWN view (7) "
              "— not the discarded counter (9), and not 0");
        CHECK(w->last_prepared.round == CERT_VIEW + 100u,
              "certificate round survived");
        CHECK(w->last_prepared.n_sigs == CERT_SIGS,
              "all three signature slots survived");
        CHECK(memcmp(&w->last_prepared, saved,
                     sizeof(w->last_prepared)) == 0,
              "the certificate round-tripped BYTE FOR BYTE — tx_hash, every "
              "voter_id, every one of the 4627-byte signatures, and every "
              "slot past n_sigs");

        /* ── the lock itself, which is what consensus consults ─────── */
        uint8_t prepared_hash[NODUS_T3_TX_HASH_LEN];
        uint8_t other_hash[NODUS_T3_TX_HASH_LEN];
        cert_tx_hash(prepared_hash, TAG);
        memset(other_hash, 0xEE, sizeof(other_hash));

        CHECK(nodus_witness_bft_prepared_lock_blocks(w, CERT_H, other_hash),
              "THE PREPARED-VALUE LOCK IS STILL ARMED after the restart: a "
              "conflicting value at height 41 is REFUSED");
        CHECK(!nodus_witness_bft_prepared_lock_blocks(w, CERT_H,
                                                      prepared_hash),
              "and the value this node itself prepared is still PERMITTED");
        CHECK(!nodus_witness_bft_prepared_lock_blocks(w, CERT_H + 1,
                                                      other_hash),
              "the lock is height-gated, unchanged: it says nothing about "
              "height 42");

        /* ── the loader did not become the runbook's DELETE ────────── */
        uint32_t rv = 0; bool rb = false;
        CHECK(pbft_row(w, &rv, &rb) == 1 && rv == STORED && rb,
              "THE ROW IS UNTOUCHED — it still reads 9. The loader READS; "
              "it does not clear the row, which is what keeps re-entry "
              "after a failed open attempt safe and keeps the operator's "
              "view-change evidence on disk");

        close_fixture(w);
    }

    free(saved);
    rm_dir(dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — A STORED VIEW OF 0 IS STILL 0. No crash, no change.
 *
 * The ordinary case: the overwhelming majority of restarts are of nodes
 * that never moved. The certificate is seeded anyway, so this section
 * also shows the certificate path does not depend on the view being
 * non-zero.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_stored_view_zero(void) {
    printf("\n§2 stored view 0 -> 0, certificate still intact\n");

    char dir[] = "/tmp/nodus_viewreset2_XXXXXX";
    make_dir(dir);

    const uint64_t CERT_H    = 12;
    const uint32_t CERT_VIEW = 0;
    const uint8_t  TAG       = 0x21;

    void *saved = malloc(sizeof(((nodus_witness_t *)0)->last_prepared));
    if (!saved) { fprintf(stderr, "saved alloc\n"); exit(1); }

    {
        nodus_witness_t *w = fixture(dir);
        open_chain(w, TAG);

        w->current_view = 0;
        seed_cert(w, CERT_H, CERT_VIEW, TAG);
        memcpy(saved, &w->last_prepared, sizeof(w->last_prepared));

        CHECK(nodus_witness_db_save_pbft_state(w) == 0,
              "the save reports success");
        uint32_t rv = 99; bool rb = false;
        CHECK(pbft_row(w, &rv, &rb) == 1 && rv == 0 && rb,
              "the row landed with current_view 0 and a non-NULL blob");

        close_fixture(w);
    }

    {
        nodus_witness_t *w = fixture(dir);
        open_chain(w, TAG);

        CHECK(w->current_view == 0,
              "a stored 0 loads as 0 — the ordinary restart is unchanged");
        CHECK(w->last_prepared.present &&
              memcmp(&w->last_prepared, saved,
                     sizeof(w->last_prepared)) == 0,
              "and the certificate still round-tripped byte for byte, so "
              "the certificate path does not depend on a non-zero view");

        close_fixture(w);
    }

    free(saved);
    rm_dir(dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — NO ROW AT ALL. The fresh-chain case, and the one the runbook
 *      produces today after its DELETE.
 *
 * A genuine second open of a database that was NEVER saved to, so the
 * SELECT steps to SQLITE_DONE rather than SQLITE_ROW.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_no_row(void) {
    printf("\n§3 no pbft_state row -> view 0, no certificate\n");

    char dir[] = "/tmp/nodus_viewreset3_XXXXXX";
    make_dir(dir);

    const uint8_t TAG = 0x33;

    {
        nodus_witness_t *w = fixture(dir);
        open_chain(w, TAG);
        uint32_t rv = 0; bool rb = false;
        CHECK(pbft_row(w, &rv, &rb) == 0,
              "precondition: the chain DB is created and nothing ever "
              "saved a pbft_state row");
        close_fixture(w);
    }

    {
        nodus_witness_t *w = fixture(dir);
        open_chain(w, TAG);

        CHECK(w->current_view == 0,
              "no row loads as view 0 — the documented fresh-DB state, and "
              "the state the runbook's DELETE leaves behind");
        CHECK(!w->last_prepared.present,
              "and no certificate is invented out of an absent row");

        uint32_t rv = 0; bool rb = false;
        CHECK(pbft_row(w, &rv, &rb) == 0,
              "the loader did not CREATE a row either — it is read-only in "
              "both directions");

        close_fixture(w);
    }

    rm_dir(dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — THE RESET LIVES IN THE LOADER, NOT AT ITS CALL SITE.
 *
 * WHY THIS ROW EXISTS, stated plainly so a future reader can decide
 * whether it still should. nodus_witness_db_load_pbft_state has exactly
 * ONE production call site (nodus_witness.c:533, inside
 * witness_db_open_attempt), but that call site is reached from BOTH
 * database entrances — the restart scan and
 * nodus_witness_create_chain_db. Putting the reset in the CALLEE means a
 * future third entrance inherits it instead of having to remember to
 * copy a line. This section pins that placement: it calls the loader
 * DIRECTLY on a witness that is already holding a non-zero view, which is
 * a thing no reset implemented beside the call site could satisfy.
 *
 * ⚠ SO IT IS DELIBERATELY BRITTLE IN ONE DIRECTION: if the reset is ever
 * MOVED to the call site as a design decision, this section goes red and
 * that is correct — the decision should be visible, not silent. §1-§3
 * would all still pass, because they go through the real open path.
 *
 * It also covers the two live paths on which the loader runs against a
 * witness that is NOT freshly allocated, and which therefore may reach it
 * holding a non-zero view: nodus_witness_bootstrap.c:998 and
 * nodus_witness_bft.c:12358 (inside nodus_witness_commit_genesis, behind
 * its `if (!w->db)` guard) both hand create_chain_db the LIVE witness.
 * On the scratch-witness callers (nodus_witness_v2_join.c:132,
 * nodus_witness_v2_gen.c:1208) the reset is a no-op, because a calloc'd
 * handle is at 0 already — so those two are the only ones where this
 * section's shape occurs in production.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_loader_resets_in_place(void) {
    printf("\n§4 the loader itself pulls a live non-zero view down to 0\n");

    char dir[] = "/tmp/nodus_viewreset4_XXXXXX";
    make_dir(dir);

    const uint64_t CERT_H    = 77;
    const uint32_t CERT_VIEW = 4;
    const uint8_t  TAG       = 0x6C;

    nodus_witness_t *w = fixture(dir);
    open_chain(w, TAG);

    w->current_view = 12;
    seed_cert(w, CERT_H, CERT_VIEW, TAG);
    CHECK(nodus_witness_db_save_pbft_state(w) == 0, "the save reports success");

    /* The witness is LIVE and holding 12 — no restart, no reallocation,
     * nothing zeroed by calloc. Only the loader runs. */
    CHECK(w->current_view == 12,
          "precondition: the witness is holding a non-zero view in memory");

    CHECK(nodus_witness_db_load_pbft_state(w) == 0,
          "the loader reports success");
    CHECK(w->current_view == 0,
          "THE LOADER ITSELF pulled the live view 12 down to 0 — the reset "
          "is in the callee, so every entrance to the database inherits it");
    CHECK(w->last_prepared.present &&
          w->last_prepared.height == CERT_H &&
          w->last_prepared.view == CERT_VIEW,
          "and the same call left the certificate in place");

    uint32_t rv = 0; bool rb = false;
    CHECK(pbft_row(w, &rv, &rb) == 1 && rv == 12 && rb,
          "the row still reads 12 — READ, not cleared");

    close_fixture(w);
    rm_dir(dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §5 — A LOADER THAT CANNOT READ THE ROW STILL LEAVES THE NODE AT 0.
 *
 * The reset sits BEFORE the query, so the "comes up at 0" guarantee does
 * not depend on the read succeeding. Without that placement a node whose
 * pbft_state was unreadable — a corrupt page, a revoked permission —
 * would keep whatever view happened to be in memory and re-enter
 * consensus holding a position it cannot prove, which is precisely the
 * state this season removes.
 *
 * The fault is a real DROP TABLE, the same injection
 * test_witness_pbft_save_fault.c uses: sqlite3_prepare_v2 inside the
 * loader genuinely returns "no such table". No mock, no stub, no build
 * flag. The witness schema declares no FOREIGN KEY, so the drop cannot
 * cascade.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_unreadable_row(void) {
    printf("\n§5 an unreadable pbft_state still leaves the node at view 0\n");

    char dir[] = "/tmp/nodus_viewreset5_XXXXXX";
    make_dir(dir);

    nodus_witness_t *w = fixture(dir);
    open_chain(w, 0x44);

    char *err = NULL;
    if (sqlite3_exec(w->db, "DROP TABLE pbft_state;", NULL, NULL, &err)
            != SQLITE_OK) {
        fprintf(stderr, "DROP TABLE pbft_state: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        exit(1);
    }
    /* The injection is PROVEN, not assumed. */
    CHECK(pbft_row(w, NULL, NULL) == -1,
          "the injection took: the pbft_state table is gone");

    w->current_view = 5;
    CHECK(nodus_witness_db_load_pbft_state(w) == -1,
          "the loader REPORTS the failure rather than swallowing it");
    CHECK(w->current_view == 0,
          "and the node is at view 0 ANYWAY — the reset is before the "
          "query, so an unreadable row cannot leave a node holding a view "
          "it can no longer prove");

    close_fixture(w);
    rm_dir(dir);
}

int main(void) {
    printf("\nO15P Faz 1 — the view counter comes up at 0, the prepared "
           "certificate comes back\n");

    section_stored_view_discarded();
    section_stored_view_zero();
    section_no_row();
    section_loader_resets_in_place();
    section_unreadable_row();

    printf("\nO15P Faz 1 PASS (5 sections; no UNREACHED rows, no skips)\n");
    return 0;
}
