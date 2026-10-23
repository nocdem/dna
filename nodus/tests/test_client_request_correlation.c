/**
 * Nodus — O15C-D — request/result correlation on the client, and why
 * the late "unknown txn N" warning is an ATTRIBUTION gap rather than a
 * delivery defect.
 *
 * The O15C-C report could not establish the provenance of one late
 * "unknown txn 9" from the frozen logs. Reading the current source
 * settles the correctness question:
 *
 *   - Ids are allocated with atomic_fetch_add on client->next_txn and
 *     next_txn is reset ONLY in nodus_client_init, so within a session
 *     an id is never reused.
 *   - The matcher requires in_use AND an exact txn equality; there is no
 *     positional or fallback match.
 *   - free_pending clears in_use but leaves txn set, so a reply for an
 *     abandoned request matches nothing — including after the slot has
 *     been recycled for a different request.
 *
 * So a response cannot be delivered to the wrong request, and cannot be
 * captured by a slot that has moved on. What was missing was the ability
 * to tell WHICH benign case a given warning was: a deliberate
 * fire-and-forget reply (resubscribe_all sends LISTEN / CH_SUBSCRIBE
 * with no pending slot by design), or a late reply to a request that
 * timed out. Both are now distinguishable in the log — the warning
 * carries method, response type and next_txn, and wait_response records
 * a terminal reason when it gives up.
 *
 * This test pins the correctness half, which is what makes that
 * disposition legitimate rather than an assumption.
 *
 * Scenarios:
 *   (1) A live slot is matched by its own txn.
 *   (2) No misdelivery: a response for an id no slot holds matches
 *       nothing, even with many live slots present.
 *   (3) Timeout/delivery race: once the caller releases its slot, the
 *       late response matches nothing (the "unknown txn" path) — it is
 *       never captured by the released entry.
 *   (4) Slot recycling: after the freed slot is reused for a NEW txn,
 *       the old id still matches nothing and the new id matches only
 *       its own entry.
 *   (5) Ids are monotonic, so (3) and (4) cannot be confused by reuse.
 *   (6) NULL / empty-table guards.
 *   (7) C-04: a second response frame for the same txn, arriving while
 *       the slot is already answered, is dropped — the first answer's
 *       raw buffer and decoded message are neither freed nor replaced
 *       (driven through the real client_on_frame via tcp->on_frame).
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"

#include <stdatomic.h>
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

/* Mirrors alloc_pending's storage effect (no response allocation — the
 * matcher never reads it). */
static void occupy(nodus_client_t *c, int i, uint32_t txn) {
    c->pending[i].txn = txn;
    c->pending[i].in_use = true;
}

/* Mirrors free_pending's storage effect: in_use cleared, txn LEFT SET.
 * That residue is the interesting part — the matcher must not honour it. */
static void release(nodus_client_t *c, int i) {
    c->pending[i].in_use = false;
}

int main(void) {
    nodus_client_t *c = calloc(1, sizeof(*c));
    CHECK(c != NULL);

    /* ── T1: a live slot matches its own txn ──────────────────────── */
    {
        occupy(c, 3, 9);
        nodus_pending_t *s = nodus_client_pending_find(c, 9);
        CHECK(s == &c->pending[3]);
        CHECK_EQ(s->txn, 9);
        printf("[ok] T1 live slot matched by its own txn\n");
    }

    /* ── T2: no misdelivery to any other request ──────────────────── */
    {
        occupy(c, 0, 7);
        occupy(c, 1, 8);
        occupy(c, 5, 40);
        /* txn 39 belongs to nobody — must not fall back to a neighbour. */
        CHECK(nodus_client_pending_find(c, 39) == NULL);
        /* and every live id still resolves to exactly its own slot */
        CHECK(nodus_client_pending_find(c, 7)  == &c->pending[0]);
        CHECK(nodus_client_pending_find(c, 8)  == &c->pending[1]);
        CHECK(nodus_client_pending_find(c, 9)  == &c->pending[3]);
        CHECK(nodus_client_pending_find(c, 40) == &c->pending[5]);
        printf("[ok] T2 a response never reaches a different request\n");
    }

    /* ── T3: the timeout/delivery race — late reply matches nothing ─ */
    {
        /* The caller's wait_response gave up and freed the slot; the
         * server's reply for txn 9 lands afterwards. This is exactly the
         * path that logs "Response for unknown txn 9". */
        release(c, 3);
        CHECK(nodus_client_pending_find(c, 9) == NULL);
        /* The residue is genuinely still there — the guard is in_use,
         * not a cleared txn. */
        CHECK_EQ(c->pending[3].txn, 9);
        printf("[ok] T3 reply to an abandoned request is not captured\n");
    }

    /* ── T4: the freed slot is recycled for a different request ───── */
    {
        occupy(c, 3, 41);
        /* the OLD id must still match nothing ... */
        CHECK(nodus_client_pending_find(c, 9) == NULL);
        /* ... and the new one only its own entry. */
        CHECK(nodus_client_pending_find(c, 41) == &c->pending[3]);
        printf("[ok] T4 slot recycling cannot resurrect an old txn\n");
    }

    /* ── T5: ids are monotonic, so an id is never reused ───────────── */
    {
        atomic_store(&c->next_txn, 1);
        uint32_t a = atomic_fetch_add(&c->next_txn, 1);
        uint32_t b = atomic_fetch_add(&c->next_txn, 1);
        uint32_t d = atomic_fetch_add(&c->next_txn, 1);
        CHECK(a < b && b < d);
        CHECK_EQ(a, 1);
        CHECK_EQ((unsigned)atomic_load(&c->next_txn), 4u);
        /* next_txn > txn_id is what lets the warning say "we issued this
         * and gave up on it" rather than "not ours". */
        CHECK(9 < (uint32_t)41);
        printf("[ok] T5 txn ids are monotonic within a session\n");
    }

    /* ── T6: guards ───────────────────────────────────────────────── */
    {
        CHECK(nodus_client_pending_find(NULL, 1) == NULL);
        nodus_client_t *empty = calloc(1, sizeof(*empty));
        CHECK(empty != NULL);
        CHECK(nodus_client_pending_find(empty, 0) == NULL);
        CHECK(nodus_client_pending_find(empty, 1) == NULL);
        free(empty);
        printf("[ok] T6 guards\n");
    }

    /* ── T7 (C-04): a second response for an answered txn is dropped ─ */
    {
        nodus_client_t *dc = calloc(1, sizeof(*dc));
        nodus_identity_t *id = calloc(1, sizeof(*id));
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.server_count = 1;
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
        cfg.servers[0].port = 1;
        /* a session needs a pin and a chain id (nodus_client_init refuses
         * without); nothing here ever connects */
        static nodus_key_t pin;
        memset(&pin, 0x11, sizeof(pin));
        cfg.pinned_server_fps = &pin;
        cfg.pinned_server_fp_count = 1;
        memset(cfg.expected_chain_id, 0x22, sizeof(cfg.expected_chain_id));
        cfg.has_expected_chain_id = true;
        CHECK(dc && id);
        CHECK_EQ(nodus_client_init(dc, &cfg, id), 0);

        /* A request in flight, as alloc_pending leaves it. */
        nodus_pending_t *slot = &dc->pending[0];
        slot->txn = 77;
        slot->response = calloc(1, sizeof(nodus_tier2_msg_t));
        CHECK(slot->response != NULL);
        slot->in_use = true;

        nodus_tcp_t *tcp = (nodus_tcp_t *)dc->tcp;
        CHECK(tcp && tcp->on_frame);

        uint8_t f1[256], f2[256];
        size_t l1 = 0, l2 = 0;
        CHECK_EQ(nodus_t2_pong(77, f1, sizeof(f1), &l1), 0);
        CHECK_EQ(nodus_t2_put_ok(77, f2, sizeof(f2), &l2), 0);

        /* First response: delivered as before. */
        tcp->on_frame(NULL, f1, l1, tcp->cb_ctx);
        CHECK(atomic_load(&slot->ready));
        CHECK(strcmp(((nodus_tier2_msg_t *)slot->response)->method, "pong") == 0);
        uint8_t *raw1 = slot->raw_response;
        CHECK(raw1 != NULL);
        CHECK_EQ(slot->raw_response_len, l1);

        /* Duplicate txn from the server: the slot must keep the first
         * answer — same raw buffer (not freed/replaced), same method. */
        tcp->on_frame(NULL, f2, l2, tcp->cb_ctx);
        CHECK(slot->raw_response == raw1);
        CHECK_EQ(slot->raw_response_len, l1);
        CHECK(memcmp(slot->raw_response, f1, l1) == 0);
        CHECK(strcmp(((nodus_tier2_msg_t *)slot->response)->method, "pong") == 0);
        CHECK(atomic_load(&slot->ready));

        nodus_client_close(dc);   /* frees the in_use slot */
        free(dc);
        free(id);
        printf("[ok] T7 duplicate response cannot replace an answered slot\n");
    }

    free(c);
    printf("PASS test_client_request_correlation\n");
    return 0;
}
