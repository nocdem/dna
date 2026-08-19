/**
 * Nodus — O15C-D.1 — the C5 reproposal rule must arm on the path a node
 * actually takes through a view change.
 *
 * ── The defect ────────────────────────────────────────────────────────
 *
 * `reproposal_required` was set in exactly ONE place: handle_newview,
 * inside `if (nv->new_view > w->current_view)`. But every node advances
 * its OWN view the moment it reaches view-change quorum
 * (bft_vc_check_quorum, nodus_witness_bft.c). By the time the new
 * leader's NEW_VIEW arrives, `nv->new_view == w->current_view`, the
 * guard is false, and the whole accept block — the binding with it — is
 * skipped silently, with no log line on either side.
 *
 * Measured on the live seven-node cluster before the fix: 7/7 nodes
 * logged "view change quorum!", ZERO logged "accepted NEW_VIEW", zero
 * logged a NEW_VIEW rejection, and the C5 gate in handle_propose never
 * evaluated once. The rule that exists to stop a new leader substituting
 * a different value for a prepared one was not being enforced at all on
 * the common path.
 *
 * ── The repair under test ─────────────────────────────────────────────
 *
 * nodus_witness_bft_bind_reproposal_from_view_changes() applies the C5
 * selection to the node itself at quorum, and the leader's NEW_VIEW
 * payload is built from the same result so the broadcast binding and the
 * enforced binding cannot diverge. BIND-OR-CLEAR: with no prepared cert
 * among the records the binding is explicitly cleared, because a stale
 * binding from an earlier view would reject every later proposal.
 *
 * These are unit-level checks of the selection and the lifecycle. The
 * multi-node proof that the gate now actually evaluates is
 * tests/integration/stagef/tests/test_med28_reproposal.sh.
 *
 * Scenarios:
 *   (1) binds the HIGHEST-height prepared cert, copying height + digest
 *   (2) records without a prepared cert are ignored
 *   (3) no prepared cert anywhere ⇒ binding CLEARED, not left stale
 *   (4) a pre-existing stale binding is cleared by an empty selection
 *   (5) only records below view_change_count are considered
 *   (6) the selection is a pure function of the records — repeating it
 *       yields the same binding
 *   (7) NULL guard
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

/* Seed one VIEW_CHANGE record in the state handle_viewchg leaves it in
 * AFTER the incoming cert has already been verified and met quorum —
 * has_prepared is the post-verification flag, so no signature machinery
 * is needed to exercise the selection. */
static void seed_vc(nodus_witness_t *w, int slot, bool has_prepared,
                    uint64_t height, uint32_t view, uint8_t hash_byte) {
    w->view_changes[slot].target_view = view;
    w->view_changes[slot].prepared.has_prepared = has_prepared;
    w->view_changes[slot].prepared.height = height;
    w->view_changes[slot].prepared.view = view;
    memset(w->view_changes[slot].prepared.tx_hash, hash_byte,
           NODUS_T3_TX_HASH_LEN);
    /* sigs stays NULL / n_sigs 0 — the selection never reads them, and
     * the ownership contract requires n_sigs == 0 whenever sigs == NULL. */
}

static bool hash_all(const uint8_t *h, uint8_t b) {
    for (int i = 0; i < NODUS_T3_TX_HASH_LEN; i++)
        if (h[i] != b) return false;
    return true;
}

int main(void) {
    /* nodus_witness_t is multi-MB — heap, never stack. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);

    /* ── T1: binds the highest-height prepared cert ────────────────── */
    {
        seed_vc(w, 0, true,  10, 0, 0xA0);
        seed_vc(w, 1, true,  42, 0, 0xB0);   /* highest */
        seed_vc(w, 2, true,  17, 0, 0xC0);
        w->view_change_count = 3;

        nodus_witness_bft_bind_reproposal_from_view_changes(w);

        CHECK(w->reproposal_required);
        CHECK_EQ(w->reproposal_height, 42);
        CHECK(hash_all(w->reproposal_tx_hash, 0xB0));
        printf("[ok] T1 binds the highest-height prepared cert\n");
    }

    /* ── T2: records with no prepared cert are skipped ─────────────── */
    {
        memset(w->view_changes, 0, sizeof(w->view_changes[0]) * 4);
        seed_vc(w, 0, false, 99, 0, 0xD0);   /* higher, but NO cert */
        seed_vc(w, 1, true,  12, 0, 0xE0);
        w->view_change_count = 2;

        nodus_witness_bft_bind_reproposal_from_view_changes(w);

        CHECK(w->reproposal_required);
        CHECK_EQ(w->reproposal_height, 12);   /* not 99 */
        CHECK(hash_all(w->reproposal_tx_hash, 0xE0));
        printf("[ok] T2 a record without a prepared cert cannot bind\n");
    }

    /* ── T3: no cert at all ⇒ CLEARED (this is the bind-OR-CLEAR half) ─ */
    {
        memset(w->view_changes, 0, sizeof(w->view_changes[0]) * 4);
        seed_vc(w, 0, false, 5, 0, 0x11);
        seed_vc(w, 1, false, 6, 0, 0x22);
        w->view_change_count = 2;

        nodus_witness_bft_bind_reproposal_from_view_changes(w);

        CHECK(!w->reproposal_required);
        CHECK_EQ(w->reproposal_height, 0);
        CHECK(hash_all(w->reproposal_tx_hash, 0x00));
        printf("[ok] T3 no prepared cert clears the binding\n");
    }

    /* ── T4: a STALE binding must not survive an empty selection ───── */
    {
        /* Leave a binding behind from an earlier view, then enter a view
         * whose records carry nothing. Left set, it would reject every
         * proposal at every later height. */
        w->reproposal_required = true;
        w->reproposal_height = 77;
        memset(w->reproposal_tx_hash, 0x55, NODUS_T3_TX_HASH_LEN);

        memset(w->view_changes, 0, sizeof(w->view_changes[0]) * 4);
        w->view_change_count = 0;

        nodus_witness_bft_bind_reproposal_from_view_changes(w);

        CHECK(!w->reproposal_required);
        CHECK_EQ(w->reproposal_height, 0);
        CHECK(hash_all(w->reproposal_tx_hash, 0x00));
        printf("[ok] T4 a stale binding is cleared, never carried forward\n");
    }

    /* ── T5: only records below view_change_count are considered ───── */
    {
        memset(w->view_changes, 0, sizeof(w->view_changes[0]) * 4);
        seed_vc(w, 0, true, 20, 0, 0x33);
        seed_vc(w, 1, true, 90, 0, 0x44);   /* beyond the count */
        w->view_change_count = 1;

        nodus_witness_bft_bind_reproposal_from_view_changes(w);

        CHECK(w->reproposal_required);
        CHECK_EQ(w->reproposal_height, 20);   /* not 90 */
        CHECK(hash_all(w->reproposal_tx_hash, 0x33));
        printf("[ok] T5 records beyond view_change_count are not selected\n");
    }

    /* ── T6: the selection is a pure function of the records ───────── */
    {
        /* The leader broadcasts a NEW_VIEW built from this same result;
         * if the selection were not repeatable, the binding it announced
         * and the binding it enforces could differ. */
        memset(w->view_changes, 0, sizeof(w->view_changes[0]) * 4);
        seed_vc(w, 0, true, 31, 0, 0x66);
        seed_vc(w, 1, true, 64, 0, 0x77);
        seed_vc(w, 2, true, 12, 0, 0x88);
        w->view_change_count = 3;

        nodus_witness_bft_bind_reproposal_from_view_changes(w);
        uint64_t h1 = w->reproposal_height;
        uint8_t  d1[NODUS_T3_TX_HASH_LEN];
        memcpy(d1, w->reproposal_tx_hash, sizeof(d1));

        nodus_witness_bft_bind_reproposal_from_view_changes(w);

        CHECK(w->reproposal_required);
        CHECK_EQ(w->reproposal_height, h1);
        CHECK_EQ(memcmp(w->reproposal_tx_hash, d1, sizeof(d1)), 0);
        CHECK_EQ(h1, 64);
        printf("[ok] T6 selection is repeatable — broadcast and enforced "
               "bindings cannot diverge\n");
    }

    /* ── T7: NULL guard ───────────────────────────────────────────── */
    {
        nodus_witness_bft_bind_reproposal_from_view_changes(NULL);
        printf("[ok] T7 NULL guard\n");
    }

    free(w);
    printf("PASS test_witness_c5_self_bind\n");
    return 0;
}
