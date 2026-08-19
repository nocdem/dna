/**
 * Nodus — O15C-D — MED-28: a timed-out batch must survive the round
 * that produced it, because a NEW_VIEW can bind the next PROPOSE to its
 * digest and nothing else on the network holds the bytes.
 *
 * Grounded mechanism (not a use-after-free).
 *   1. A round times out in PREVOTE/PRECOMMIT. The pre-fix code called
 *      round_state_free_batch() and transitioned to VIEW_CHANGE — the
 *      batch entries were FREED on every node that held them, and they
 *      had already been removed from the mempool when the batch was
 *      built, so no copy remained anywhere.
 *   2. If PREVOTE quorum had been reached, w->last_prepared holds the
 *      cert — height, view, tx_hash and 2f+1 signatures — but NO
 *      transaction bytes (nodus_witness.h, last_prepared).
 *   3. VIEW_CHANGE carries that cert. The new leader's NEW_VIEW binds
 *      (height, tx_root) per the C5 reproposal rule.
 *   4. Followers set reproposal_required and reject every PROPOSE at
 *      that height whose tx_root differs. reproposal_required clears
 *      ONLY on a matching PROPOSE — which no node can now construct.
 *   ⇒ the height wedges permanently. Clients whose spends were in that
 *      batch also got no reply, since the entries were freed with their
 *      client_conn still attached.
 *
 * Repair under test: nodus_witness_retained_batch_take() MOVES the
 * entries into w->retained_batch instead of freeing them, and the
 * NEW_VIEW leader re-proposes them via
 * nodus_witness_bft_start_round_from_entries(). That function recomputes
 * the block hash as SHA3-512 over the batch's tx_hashes IN ORDER, so
 * preserving the exact entries in the exact order is precisely what
 * makes the reproposal's tx_root equal the bound digest. T3 below pins
 * that preservation property, which is the load-bearing one.
 *
 * Against the pre-fix source T1 fails immediately: retained_batch did
 * not exist and the entries were freed rather than moved.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_bft_internal.h"
#include "witness/nodus_witness_mempool.h"

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

/* Build a heap mempool entry with a deterministic tx_hash and payload,
 * shaped like the ones a real batch holds (tx_data heap-owned, so a
 * double free or a missed free shows up under ASan). */
static nodus_witness_mempool_entry_t *mk_entry(unsigned k) {
    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    CHECK(e != NULL);
    memset(e->tx_hash, (int)(k + 1), NODUS_T3_TX_HASH_LEN);
    e->tx_len = 32;
    e->tx_data = malloc(e->tx_len);
    CHECK(e->tx_data != NULL);
    memset(e->tx_data, (int)(k + 1), e->tx_len);
    e->tx_type = NODUS_W_TX_SPEND;
    e->client_txn_id = 1000 + k;
    return e;
}

/* Populate round_state as a round in flight would hold it. */
static void seed_round(nodus_witness_t *w, int count, uint64_t height,
                       uint8_t root_byte) {
    for (int i = 0; i < count; i++)
        w->round_state.batch_entries[i] = mk_entry((unsigned)i);
    w->round_state.batch_count = count;
    w->round_state.block_height = height;
    memset(w->round_state.tx_root, root_byte, NODUS_T3_TX_HASH_LEN);
}

int main(void) {
    /* nodus_witness_t is multi-MB — heap, never stack. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);

    /* ── T1: take() MOVES the batch, it does not free it ───────────── */
    {
        seed_round(w, 3, 42, 0xAB);

        /* Remember the exact pointers and payload identities. */
        nodus_witness_mempool_entry_t *before[3];
        uint8_t hash0[NODUS_T3_TX_HASH_LEN];
        for (int i = 0; i < 3; i++) before[i] = w->round_state.batch_entries[i];
        memcpy(hash0, before[0]->tx_hash, NODUS_T3_TX_HASH_LEN);

        nodus_witness_retained_batch_take(w);

        CHECK(w->retained_batch.present);
        CHECK_EQ(w->retained_batch.count, 3);
        CHECK_EQ(w->retained_batch.height, 42);
        for (int i = 0; i < NODUS_T3_TX_HASH_LEN; i++)
            CHECK_EQ(w->retained_batch.tx_root[i], 0xAB);

        /* Ownership left round_state — the reset that follows in
         * production must have nothing left to free. */
        CHECK_EQ(w->round_state.batch_count, 0);
        for (int i = 0; i < 3; i++)
            CHECK(w->round_state.batch_entries[i] == NULL);

        /* The SAME objects, still live and unmodified. */
        for (int i = 0; i < 3; i++)
            CHECK(w->retained_batch.entries[i] == before[i]);
        CHECK_EQ(memcmp(w->retained_batch.entries[0]->tx_hash, hash0,
                        NODUS_T3_TX_HASH_LEN), 0);
        CHECK(w->retained_batch.entries[0]->tx_data != NULL);
        printf("[ok] T1 round timeout retains the batch instead of "
               "freeing it\n");
    }

    /* ── T2: a newer timeout supersedes the older retention ────────── */
    {
        seed_round(w, 2, 43, 0xCD);
        nodus_witness_retained_batch_take(w);   /* frees the height-42 set */

        CHECK(w->retained_batch.present);
        CHECK_EQ(w->retained_batch.count, 2);
        CHECK_EQ(w->retained_batch.height, 43);
        for (int i = 0; i < NODUS_T3_TX_HASH_LEN; i++)
            CHECK_EQ(w->retained_batch.tx_root[i], 0xCD);
        /* Slots beyond the new count must not dangle into the old set. */
        CHECK(w->retained_batch.entries[2] == NULL);
        printf("[ok] T2 newer timeout supersedes (binds the HIGHEST "
               "prepared height)\n");
    }

    /* ── T3: order and content preserved ⇒ the reproposal's tx_root
     *        reproduces the bound digest ────────────────────────────── */
    {
        nodus_witness_retained_batch_clear(w);
        seed_round(w, 5, 44, 0x11);

        uint8_t expect[5][NODUS_T3_TX_HASH_LEN];
        for (int i = 0; i < 5; i++)
            memcpy(expect[i], w->round_state.batch_entries[i]->tx_hash,
                   NODUS_T3_TX_HASH_LEN);

        nodus_witness_retained_batch_take(w);

        CHECK_EQ(w->retained_batch.count, 5);
        /* start_round_from_entries hashes tx_hashes IN ARRAY ORDER, so
         * identical hashes in identical positions is exactly the
         * condition for the recomputed tx_root to match the digest the
         * NEW_VIEW bound. */
        for (int i = 0; i < 5; i++)
            CHECK_EQ(memcmp(w->retained_batch.entries[i]->tx_hash,
                            expect[i], NODUS_T3_TX_HASH_LEN), 0);
        printf("[ok] T3 entry order and tx_hashes preserved for the "
               "reproposal\n");
    }

    /* ── T4: clear() releases everything and is idempotent ─────────── */
    {
        nodus_witness_retained_batch_clear(w);
        CHECK(!w->retained_batch.present);
        CHECK_EQ(w->retained_batch.count, 0);
        CHECK_EQ(w->retained_batch.height, 0);
        for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++)
            CHECK(w->retained_batch.entries[i] == NULL);

        nodus_witness_retained_batch_clear(w);   /* idempotent */
        nodus_witness_retained_batch_clear(NULL);
        printf("[ok] T4 clear releases the retention and is idempotent\n");
    }

    /* ── T5: no batch in flight ⇒ take() is a no-op ────────────────── */
    {
        CHECK_EQ(w->round_state.batch_count, 0);
        nodus_witness_retained_batch_take(w);
        CHECK(!w->retained_batch.present);

        nodus_witness_retained_batch_take(NULL);
        printf("[ok] T5 take() on an empty round is a no-op\n");
    }

    /* ── T6: a retention still held at teardown must not leak ──────── */
    {
        seed_round(w, 4, 45, 0x22);
        nodus_witness_retained_batch_take(w);
        CHECK(w->retained_batch.present);
        nodus_witness_retained_batch_clear(w);   /* what shutdown does */
        CHECK(!w->retained_batch.present);
        printf("[ok] T6 teardown path releases a live retention\n");
    }

    /* ── T7: reproposal we do NOT hold → silent, retention intact ─── */
    {
        nodus_witness_retained_batch_clear(w);
        seed_round(w, 3, 50, 0x33);
        nodus_witness_retained_batch_take(w);

        uint8_t other_root[NODUS_T3_TX_HASH_LEN];
        memset(other_root, 0x99, sizeof(other_root));

        /* wrong digest, right height */
        CHECK_EQ(nodus_witness_try_repropose_retained(w, 50, other_root), -1);
        CHECK(w->retained_batch.present);
        CHECK_EQ(w->retained_batch.count, 3);

        /* right digest, wrong height */
        uint8_t right_root[NODUS_T3_TX_HASH_LEN];
        memset(right_root, 0x33, sizeof(right_root));
        CHECK_EQ(nodus_witness_try_repropose_retained(w, 51, right_root), -1);
        CHECK(w->retained_batch.present);
        CHECK_EQ(w->retained_batch.count, 3);

        /* guards must not disturb the holder either */
        CHECK_EQ(nodus_witness_try_repropose_retained(NULL, 50, right_root), -1);
        CHECK_EQ(nodus_witness_try_repropose_retained(w, 50, NULL), -1);
        CHECK(w->retained_batch.present);
        printf("[ok] T7 a binding we do not hold leaves the retention "
               "untouched\n");
    }

    /* ── T8: match, but the round refuses → freed exactly once ────── */
    {
        /* This bare fixture is not a leader (no committee, empty
         * roster), so start_round_from_entries refuses. That is the
         * failure path where a second owner would double-free or a
         * missed owner would leak — ASan is the judge here. */
        uint8_t root[NODUS_T3_TX_HASH_LEN];
        memset(root, 0x33, sizeof(root));

        CHECK(w->retained_batch.present);
        CHECK_EQ(nodus_witness_try_repropose_retained(w, 50, root), -1);

        /* The holder was emptied before the handoff and the entries were
         * released by the refusal path — nothing is retained, nothing
         * dangles. */
        CHECK(!w->retained_batch.present);
        CHECK_EQ(w->retained_batch.count, 0);
        for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++)
            CHECK(w->retained_batch.entries[i] == NULL);

        /* A second call must be a clean no-op, not a re-release. */
        CHECK_EQ(nodus_witness_try_repropose_retained(w, 50, root), -1);
        printf("[ok] T8 refused reproposal releases the entries exactly "
               "once\n");
    }

    /* ── T9: the holder is emptied BEFORE the round-start call ─────── */
    {
        /* Two owners of one entry is precisely the double-free this
         * repair exists to avoid, so the handoff must be a move. T8
         * proved the post-state; this pins that the emptying is not
         * conditional on the round succeeding — the refusal path above
         * left the holder empty, which is only possible if the memset
         * ran before start_round_from_entries was called. */
        nodus_witness_retained_batch_clear(w);
        seed_round(w, 2, 60, 0x44);
        nodus_witness_retained_batch_take(w);
        nodus_witness_mempool_entry_t *held[2];
        held[0] = w->retained_batch.entries[0];
        held[1] = w->retained_batch.entries[1];
        CHECK(held[0] != NULL && held[1] != NULL);

        uint8_t root[NODUS_T3_TX_HASH_LEN];
        memset(root, 0x44, sizeof(root));
        CHECK_EQ(nodus_witness_try_repropose_retained(w, 60, root), -1);
        CHECK(!w->retained_batch.present);
        CHECK(w->retained_batch.entries[0] == NULL);
        CHECK(w->retained_batch.entries[1] == NULL);
        printf("[ok] T9 ownership handoff is a move, not a copy\n");
    }

    free(w);
    printf("PASS test_witness_retained_batch\n");
    return 0;
}
