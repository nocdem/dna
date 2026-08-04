/**
 * Nodus — pre-genesis leader selection must not depend on roster
 * ARRIVAL ORDER (BUGS.md 2026-08-04 second-data-point entry).
 *
 * The pre-genesis bootstrap fallback used to map a witness to its index
 * in the LOCAL gossip roster (arrival-ordered: self first, peers in
 * authentication order). Two nodes holding the SAME witness set in a
 * different arrival order then disagree about who
 * leader = (epoch + view) % n is — reproduced live 2026-08-04: node7
 * held a sorted 5-prefix plus 2 unsorted late appends, saw the proposer
 * at index 6 while every fully-sorted peer saw it at index 0, rejected
 * the genesis PROPOSE and missed the voting round.
 *
 * Fix under test: nodus_witness_roster_sorted_find() — the rank of a
 * witness_id in the SET (count of strictly-smaller ids), independent of
 * storage order. Both fallback sites (nodus_witness_bft_is_leader and
 * the PROPOSE leader check) consult this rank; this test pins the
 * rank's order-independence and the node7 counterexample shape.
 *
 * Scenarios:
 *   (1) Same 7-member set, two different arrival orders → identical
 *       rank for every member.
 *   (2) Rank agrees with a qsort-by-witness_id reference ordering.
 *   (3) node7 counterexample: sorted 5-prefix + 2 unsorted appends;
 *       the globally-smallest id arrives LAST (arrival index 6) but
 *       must rank 0 — so leader_index(0,0,7)==0 maps to the same
 *       witness on every node.
 *   (4) Unknown id → -1; single-entry roster → rank 0.
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

/* Deterministic distinct witness_ids: id[k] = {k+1, k+1, ...} so the
 * memcmp order of id[k] follows k. */
static void mk_id(uint8_t *out, unsigned k) {
    memset(out, (int)(k + 1), NODUS_T3_WITNESS_ID_LEN);
}

static void roster_append(nodus_witness_roster_t *r, const uint8_t *id) {
    /* Mirrors nodus_witness_roster_add's storage effect without needing
     * a full nodus_witness_t: append at the tail, no sort. */
    memcpy(r->witnesses[r->n_witnesses].witness_id, id,
           NODUS_T3_WITNESS_ID_LEN);
    r->witnesses[r->n_witnesses].active = true;
    r->n_witnesses++;
}

int main(void) {
    uint8_t id[7][NODUS_T3_WITNESS_ID_LEN];
    for (unsigned k = 0; k < 7; k++) mk_id(id[k], k);

    /* ── (1) same set, two arrival orders → identical ranks ──────── */
    nodus_witness_roster_t a, b;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    static const int order_a[7] = { 0, 1, 2, 3, 4, 5, 6 };
    static const int order_b[7] = { 4, 6, 1, 0, 5, 3, 2 };
    for (unsigned k = 0; k < 7; k++) roster_append(&a, id[order_a[k]]);
    for (unsigned k = 0; k < 7; k++) roster_append(&b, id[order_b[k]]);

    for (unsigned k = 0; k < 7; k++) {
        int ra = nodus_witness_roster_sorted_find(&a, id[k]);
        int rb = nodus_witness_roster_sorted_find(&b, id[k]);
        CHECK(ra >= 0);
        CHECK_EQ(ra, rb);
        /* ── (2) rank == position in id order (ids built ascending) ── */
        CHECK_EQ(ra, (int)k);
    }
    printf("[ok] T1/T2 order-independent ranks, 7-member set\n");

    /* ── (3) node7 counterexample: smallest id arrives LAST ───────── */
    nodus_witness_roster_t c;
    memset(&c, 0, sizeof(c));
    /* sorted 5-prefix of {1..5} (ids id[1]..id[5]), then id[6], then
     * id[0] — the globally smallest — appended last (arrival idx 6). */
    for (unsigned k = 1; k <= 5; k++) roster_append(&c, id[k]);
    roster_append(&c, id[6]);
    roster_append(&c, id[0]);

    CHECK_EQ(nodus_witness_roster_find(&c, id[0]), 6);        /* arrival */
    CHECK_EQ(nodus_witness_roster_sorted_find(&c, id[0]), 0); /* rank   */
    /* leader_index(epoch=0, view=0, n=7) == 0 must therefore map to
     * id[0] on THIS roster exactly as it does on a fully-sorted one. */
    CHECK_EQ(nodus_witness_bft_leader_index(0, 0, 7), 0);
    printf("[ok] T3 node7 counterexample: arrival idx 6, rank 0\n");

    /* ── (4) edge cases ───────────────────────────────────────────── */
    uint8_t ghost[NODUS_T3_WITNESS_ID_LEN];
    memset(ghost, 0xEE, sizeof(ghost));
    CHECK_EQ(nodus_witness_roster_sorted_find(&c, ghost), -1);
    CHECK_EQ(nodus_witness_roster_sorted_find(NULL, id[0]), -1);
    CHECK_EQ(nodus_witness_roster_sorted_find(&c, NULL), -1);

    nodus_witness_roster_t solo;
    memset(&solo, 0, sizeof(solo));
    roster_append(&solo, id[3]);
    CHECK_EQ(nodus_witness_roster_sorted_find(&solo, id[3]), 0);
    printf("[ok] T4 edge cases\n");

    printf("PASS test_witness_roster_sorted_leader\n");
    return 0;
}
