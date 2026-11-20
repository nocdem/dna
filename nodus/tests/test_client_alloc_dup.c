/**
 * Nodus — client pending slots: out-of-memory publication (C-07) and a
 * duplicate reply on the channel client (C-08)
 *
 * What it proves:
 *   A1  alloc_pending, reply buffer cannot be allocated: returns NULL and
 *       leaves every slot free (not in use, no response pointer). Before the
 *       fix the slot was published (in_use) with response == NULL, and a
 *       matching frame made client_on_frame write through NULL.
 *   A2  ch_conn_alloc_pending (channel client): same.
 *   A3  (controls) with the allocation working, both return a slot whose
 *       response buffer exists.
 *   D1  channel client: a second reply for a txn whose slot is already
 *       answered is dropped — the first reply (method "pong", same response
 *       buffer) is neither freed nor replaced. Before the fix the second
 *       reply freed and overwrote it while a waiter may be reading it.
 *
 * Seam: nodus_client.c is compiled INTO this test with NODUS_CLIENT_TEST_SEAM=1
 * (see nodus/CMakeLists.txt) so the two static allocators are callable, and
 * the target links with -Wl,--wrap=calloc: the first calloc of exactly one
 * nodus_tier2_msg_t made by the calling thread after t_fail_next is set
 * returns NULL. Environment: none. Leaves behind: nothing.
 *
 * How it can lie: the wrap fails the first matching calloc; if the allocator
 * made another calloc of that size first, A1/A2 would fail the wrong one
 * (the slot-free assertions still hold, but they would not prove the
 * publication path). D1 drives the real ch_conn_on_frame through the
 * transport's on_frame pointer with hand-built frames; it shows the first
 * reply survives, not that no waiter ever races (that needs a sanitizer run).
 */

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defined in nodus_client.c under NODUS_CLIENT_TEST_SEAM. */
nodus_pending_t *nodus_client_test_alloc_pending(nodus_client_t *client, uint32_t txn);
nodus_ch_pending_t *nodus_client_test_ch_alloc_pending(nodus_ch_conn_t *ch, uint32_t txn);

extern void *__real_calloc(size_t n, size_t sz);
static __thread int t_fail_next = 0;

void *__wrap_calloc(size_t n, size_t sz) {
    if (t_fail_next && n == 1 && sz == sizeof(nodus_tier2_msg_t)) {
        t_fail_next = 0;
        return NULL;
    }
    return __real_calloc(n, sz);
}

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

int main(void) {
    nodus_identity_t *id = calloc(1, sizeof(*id));
    CHECK(id && nodus_identity_generate(id) == 0);

    /* ── main client ──────────────────────────────────────────────── */
    nodus_client_t *dc = calloc(1, sizeof(*dc));
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.server_count = 1;
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "127.0.0.1");
    cfg.servers[0].port = 1;
    static const nodus_key_t k_unused_pin = {{0x01}};
    cfg.pinned_server_fps = &k_unused_pin;
    cfg.pinned_server_fp_count = 1;
    cfg.has_chain_id = true;
    CHECK(dc && nodus_client_init(dc, &cfg, id) == 0);

    t_fail_next = 1;
    CHECK(nodus_client_test_alloc_pending(dc, 5) == NULL);
    t_fail_next = 0;
    for (int i = 0; i < NODUS_MAX_PENDING; i++) {
        CHECK(!dc->pending[i].in_use);
        CHECK(dc->pending[i].response == NULL);
    }
    printf("[ok] A1 alloc_pending: allocation failure publishes no slot\n");

    nodus_pending_t *p = nodus_client_test_alloc_pending(dc, 6);
    CHECK(p != NULL && p->in_use && p->response != NULL && p->txn == 6);
    nodus_client_close(dc);          /* frees the in-use slot */
    free(dc);

    /* ── channel client ───────────────────────────────────────────── */
    nodus_ch_conn_t *ch = calloc(1, sizeof(*ch));
    CHECK(ch && nodus_channel_init(ch, "127.0.0.1", 1, id, NULL, NULL) == 0);

    t_fail_next = 1;
    CHECK(nodus_client_test_ch_alloc_pending(ch, 5) == NULL);
    t_fail_next = 0;
    for (int i = 0; i < NODUS_CH_MAX_PENDING; i++) {
        CHECK(!ch->pending[i].in_use);
        CHECK(ch->pending[i].response == NULL);
    }
    printf("[ok] A2 ch_conn_alloc_pending: allocation failure publishes no slot\n");

    nodus_ch_pending_t *cp = nodus_client_test_ch_alloc_pending(ch, 7);
    CHECK(cp != NULL && cp->in_use && cp->response != NULL && cp->txn == 7);
    printf("[ok] A3 both allocators work when memory is available\n");

    /* D1: the slot just allocated (txn 7) is answered twice. */
    nodus_tcp_t *tcp = (nodus_tcp_t *)ch->tcp;
    CHECK(tcp && tcp->on_frame);
    uint8_t f1[256], f2[256];
    size_t l1 = 0, l2 = 0;
    CHECK(nodus_t2_pong(7, f1, sizeof(f1), &l1) == 0);
    CHECK(nodus_t2_put_ok(7, f2, sizeof(f2), &l2) == 0);

    tcp->on_frame(NULL, f1, l1, tcp->cb_ctx);
    CHECK(atomic_load(&cp->ready));
    void *first = cp->response;
    CHECK(strcmp(((nodus_tier2_msg_t *)cp->response)->method, "pong") == 0);

    tcp->on_frame(NULL, f2, l2, tcp->cb_ctx);          /* duplicate txn */
    CHECK(cp->response == first);
    CHECK(strcmp(((nodus_tier2_msg_t *)cp->response)->method, "pong") == 0);
    CHECK(atomic_load(&cp->ready));
    printf("[ok] D1 channel client: a duplicate reply cannot replace the first\n");

    nodus_channel_close(ch);
    free(ch);
    nodus_identity_clear(id);
    free(id);
    printf("PASS test_client_alloc_dup\n");
    return 0;
}
