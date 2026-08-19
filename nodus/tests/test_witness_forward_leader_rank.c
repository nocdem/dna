/**
 * Nodus — O15C-D — the pre-genesis SPEND-FORWARDING path must resolve a
 * leader SLOT through the sorted rank, never through the arrival index.
 *
 * Background. nodus_witness_bft_leader_index(epoch, view, n) returns a
 * slot in the witness set ordered by witness_id. Two sites already
 * resolved that slot correctly via nodus_witness_roster_sorted_find()
 * (nodus_witness_bft_is_leader, and the PROPOSE leader check). The
 * forwarding branch in nodus_witness_handlers.c did NOT: it indexed
 * w->roster.witnesses[leader_slot] directly and compared against
 * nodus_witness_roster_find(&w->roster, w->my_id) — both ARRIVAL
 * positions. The roster is arrival-ordered between the 60 s epoch
 * rebuilds (nodus_witness_roster_add appends; only the rebuild qsorts),
 * so a node whose peers authenticated in a different order forwarded
 * the client's spend to a witness that was NOT the leader. That witness
 * accepted it into its mempool and never proposed it, no w_fwd_rsp was
 * ever produced, and the forwarder's pending_forward expired 30 s later
 * — the exact symptom recorded as MED-27.
 *
 * This is therefore the regression for BOTH the arrival-order record and
 * MED-27's observed mechanism.
 *
 * Fix under test: nodus_witness_roster_sorted_at() — the inverse of
 * sorted_find, mapping a rank back to the array index holding it.
 *
 * Scenarios:
 *   (1) sorted_at is the exact inverse of sorted_find on every member,
 *       for two different arrival orders of the same set.
 *   (2) The pre-fix expression (witnesses[leader_slot]) and the post-fix
 *       expression (witnesses[sorted_at(leader_slot)]) DISAGREE on an
 *       unsorted roster — pinning that the old code really could select
 *       a different witness, i.e. this test fails against the old
 *       resolution rule rather than merely restating the new one.
 *   (3) Across every arrival permutation of a 7-member set, the witness
 *       chosen by rank is identical — so all honest nodes forward to the
 *       same leader.
 *   (4) A node's own "am I the leader" test must use the same rank, or a
 *       node can believe it is not the leader while the set says it is.
 *   (5) Out-of-range / NULL ranks.
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

#define N 7

/* Deterministic distinct witness_ids: id[k] = {k+1, ...} so memcmp
 * order follows k. */
static void mk_id(uint8_t *out, unsigned k) {
    memset(out, (int)(k + 1), NODUS_T3_WITNESS_ID_LEN);
}

/* Mirrors nodus_witness_roster_add's storage effect: append, no sort. */
static void roster_append(nodus_witness_roster_t *r, const uint8_t *id) {
    memcpy(r->witnesses[r->n_witnesses].witness_id, id,
           NODUS_T3_WITNESS_ID_LEN);
    r->witnesses[r->n_witnesses].active = true;
    r->n_witnesses++;
}

static void build(nodus_witness_roster_t *r,
                  uint8_t id[N][NODUS_T3_WITNESS_ID_LEN],
                  const int *order) {
    memset(r, 0, sizeof(*r));
    for (int k = 0; k < N; k++) roster_append(r, id[order[k]]);
}

int main(void) {
    uint8_t id[N][NODUS_T3_WITNESS_ID_LEN];
    for (unsigned k = 0; k < N; k++) mk_id(id[k], k);

    static const int sorted_order[N]   = { 0, 1, 2, 3, 4, 5, 6 };
    /* node7's shape: sorted 5-prefix, then two late appends with the
     * globally smallest id arriving LAST. */
    static const int unsorted_order[N] = { 1, 2, 3, 4, 5, 6, 0 };

    nodus_witness_roster_t sorted_r, unsorted_r;
    build(&sorted_r,   id, sorted_order);
    build(&unsorted_r, id, unsorted_order);

    /* ── (1) sorted_at is the exact inverse of sorted_find ─────────── */
    const nodus_witness_roster_t *rosters[2] = { &sorted_r, &unsorted_r };
    for (int ri = 0; ri < 2; ri++) {
        for (int k = 0; k < N; k++) {
            int rank = nodus_witness_roster_sorted_find(rosters[ri], id[k]);
            CHECK(rank >= 0);
            int idx = nodus_witness_roster_sorted_at(rosters[ri], rank);
            CHECK(idx >= 0);
            /* the array slot sorted_at names must hold exactly id[k] */
            CHECK_EQ(memcmp(rosters[ri]->witnesses[idx].witness_id,
                            id[k], NODUS_T3_WITNESS_ID_LEN), 0);
        }
    }
    printf("[ok] T1 sorted_at inverts sorted_find on both arrival orders\n");

    /* ── (2) old rule vs new rule DISAGREE on the unsorted roster ─── */
    {
        /* leader_index(epoch=0, view=0, n=7) == 0 → rank 0 → id[0],
         * which on the unsorted roster sits at ARRIVAL index 6. The
         * pre-fix code would have selected witnesses[0] == id[1]. */
        int leader_slot = nodus_witness_bft_leader_index(0, 0, N);
        CHECK_EQ(leader_slot, 0);

        const uint8_t *pre_fix =
            unsorted_r.witnesses[leader_slot].witness_id;      /* OLD */
        int idx = nodus_witness_roster_sorted_at(&unsorted_r, leader_slot);
        const uint8_t *post_fix =
            unsorted_r.witnesses[idx].witness_id;              /* NEW */

        CHECK_EQ(idx, 6);
        CHECK_EQ(memcmp(post_fix, id[0], NODUS_T3_WITNESS_ID_LEN), 0);
        CHECK_EQ(memcmp(pre_fix,  id[1], NODUS_T3_WITNESS_ID_LEN), 0);
        /* The two rules really do name different witnesses — this is the
         * mis-forward that starved the pending_forward. */
        CHECK(memcmp(pre_fix, post_fix, NODUS_T3_WITNESS_ID_LEN) != 0);
    }
    printf("[ok] T2 arrival-index rule selects a DIFFERENT witness "
           "(the mis-forward)\n");

    /* ── (3) every arrival permutation agrees on the forward target ── */
    {
        int order[N];
        for (int k = 0; k < N; k++) order[k] = k;

        /* All 7! = 5040 permutations, generated deterministically by
         * repeated next_permutation-style ascent — no RNG. */
        long perms = 0;
        for (;;) {
            nodus_witness_roster_t r;
            build(&r, id, order);

            for (uint32_t view = 0; view < 3; view++) {
                int slot = nodus_witness_bft_leader_index(0, view, N);
                int idx  = nodus_witness_roster_sorted_at(&r, slot);
                CHECK(idx >= 0);
                /* ids were built ascending, so rank k <=> id[k] */
                CHECK_EQ(memcmp(r.witnesses[idx].witness_id, id[slot],
                                NODUS_T3_WITNESS_ID_LEN), 0);
            }
            perms++;

            /* next lexicographic permutation of `order` */
            int i = N - 2;
            while (i >= 0 && order[i] >= order[i + 1]) i--;
            if (i < 0) break;
            int j = N - 1;
            while (order[j] <= order[i]) j--;
            int t = order[i]; order[i] = order[j]; order[j] = t;
            for (int lo = i + 1, hi = N - 1; lo < hi; lo++, hi--) {
                t = order[lo]; order[lo] = order[hi]; order[hi] = t;
            }
        }
        CHECK_EQ(perms, 5040);
        printf("[ok] T3 all %ld arrival permutations pick the same "
               "forward target\n", perms);
    }

    /* ── (4) self-check must use the same rank ────────────────────── */
    {
        /* Suppose we are id[0] and hold the unsorted roster. By rank we
         * ARE the view-0 leader; by arrival index we are not. The
         * forwarding path must not conclude "we are not the leader" and
         * ship the spend elsewhere. */
        int my_rank    = nodus_witness_roster_sorted_find(&unsorted_r, id[0]);
        int my_arrival = nodus_witness_roster_find(&unsorted_r, id[0]);
        int leader_slot = nodus_witness_bft_leader_index(0, 0, N);

        CHECK_EQ(my_rank, 0);
        CHECK_EQ(my_arrival, 6);
        CHECK_EQ(leader_slot, my_rank);        /* rank rule: we ARE leader */
        CHECK(leader_slot != my_arrival);      /* arrival rule: we are not */
    }
    printf("[ok] T4 self-identification agrees with the set, not arrival\n");

    /* ── (5) bounds ───────────────────────────────────────────────── */
    CHECK_EQ(nodus_witness_roster_sorted_at(&sorted_r, -1), -1);
    CHECK_EQ(nodus_witness_roster_sorted_at(&sorted_r, N), -1);
    CHECK_EQ(nodus_witness_roster_sorted_at(NULL, 0), -1);
    {
        nodus_witness_roster_t empty;
        memset(&empty, 0, sizeof(empty));
        CHECK_EQ(nodus_witness_roster_sorted_at(&empty, 0), -1);
    }
    printf("[ok] T5 bounds\n");

    printf("PASS test_witness_forward_leader_rank\n");
    return 0;
}
