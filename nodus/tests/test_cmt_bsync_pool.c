/**
 * Nodus — cometbft @709fd12b C port, blocksync: the block pool of
 * `shared/dnac/cmt_bsync_pool.c` (blocksync/pool.go), driven by a fake
 * clock and a recording host.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the pool asks the right peer for the right height at the right
 * time and reacts to silence, lies and bad blocks as pool.go does. If
 * this file failed, one of these would be false:
 *   · nothing is requested before `peerConnWait` (3 s) has passed since
 *     start (:126-132), and the tick reports that instant as its deadline;
 *   · after it, one requester is made per 2 ms tick (:151-153) up to the
 *     highest reported peer height (:139, :147-148), each asking a peer
 *     whose [base, height] covers it (:490-492), and — within
 *     minBlocksForSingleRequest of the pool height — a SECOND peer too
 *     (:845-848, :806-826);
 *   · a peer is named by its p2p ID everywhere: a block from an ID that
 *     was not asked is refused with WRONG_SENDER naming THAT ID (:338-342);
 *     two peers with different IDs are distinct peers;
 *   · PeekTwoBlocks / PopRequest walk the heights in order and hand the
 *     popped block to the caller (:225-267);
 *   · `peerTimeout` (15 s) of silence after a request raises TIMEOUT for
 *     that peer and marks it timed out (:597-603, :623-631); the next
 *     pick removes it (:483-485);
 *   · the 30 s `retryTimer` of a requester whose peer never answered
 *     resets it and asks again (:862-868) — with peerTimeout pushed out
 *     of the way the way pool_test.go overrides the `var` (:57);
 *   · RemovePeerAndRedoAllPeerRequests (:269-282) removes and BANS the
 *     peer that delivered the block; a banned ID's StatusResponse is
 *     ignored for 60 s and accepted after (:387-390, :461-465); the
 *     requester that had asked a second peer keeps waiting for it and
 *     takes its block (:869-881);
 *   · a peer that reports a LOWER height than before is removed and
 *     banned (:374-383);
 *   · a block above the pool height with no requester is UNEXPECTED
 *     (:328-333); one below it is only "already committed" (:335);
 *   · IsCaughtUp is false with no peers (:209-212) and true once the pool
 *     height reaches maxPeerHeight − 1 (:220);
 *   · after Stop nothing is requested and the requesters are gone (BS-3).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION` (every cmt_* target). A DEFAULT
 *   BUILD is enough.
 * ENVIRONMENT: nothing. The clock is a variable in this file; no network,
 *   no files, no randomness. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The blocks here are EMPTY HOLDERS with only a height and a size: the
 *     pool never looks inside a block, and decoding is the reactor's
 *     (test_cmt_bsync_reactor sends real ones).
 *  2. The receive-rate rule (minRecvRate, :158-191) is NOT driven: the
 *     Monitor starts at REMA = 128 KB/s × e (:593-594) and would need a
 *     measured slow stream to fall below the minimum. Only its presence is
 *     implied by the peers surviving the other cases.
 *  3. The reference's own pool_test.go (UNPINNED — not in the reference
 *     tarball's pin list) is not ported line by line; these cases are
 *     built from pool.go's lines named above.
 *
 * @file test_cmt_bsync_pool.c
 */

#include "dnac/cmt_bsync_pool.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define MS  ((int64_t)1000000)
#define SEC ((int64_t)1000000000)
#define T0  ((int64_t)1700000000 * SEC)

/* ══ the recording host ═══════════════════════════════════════════════ */

#define REC_MAX 512

typedef struct {
    int64_t height;
    char    peer[CMT_P2P_ID_CAP];
} req_t;

typedef struct {
    char                 peer[CMT_P2P_ID_CAP];
    cmt_bsync_peer_err_t err;
} err_t;

static req_t  g_req[REC_MAX];
static size_t g_nreq;
static err_t  g_err[REC_MAX];
static size_t g_nerr;

static void h_send_request(void *ctx, int64_t height, const char *peer_id)
{
    (void)ctx;
    if (g_nreq < REC_MAX) {
        g_req[g_nreq].height = height;
        snprintf(g_req[g_nreq].peer, CMT_P2P_ID_CAP, "%s", peer_id);
        g_nreq++;
    }
}

static void h_send_error(void *ctx, const char *peer_id, cmt_bsync_peer_err_t err)
{
    (void)ctx;
    if (g_nerr < REC_MAX) {
        snprintf(g_err[g_nerr].peer, CMT_P2P_ID_CAP, "%s", peer_id);
        g_err[g_nerr].err = err;
        g_nerr++;
    }
}

static void rec_reset(void)
{
    g_nreq = 0;
    g_nerr = 0;
}

static size_t count_req(int64_t height, const char *peer)
{
    size_t i, n = 0;

    for (i = 0; i < g_nreq; i++) {
        if (g_req[i].height == height && strcmp(g_req[i].peer, peer) == 0) {
            n++;
        }
    }
    return n;
}

static bool has_err(const char *peer, cmt_bsync_peer_err_t err)
{
    size_t i;

    for (i = 0; i < g_nerr; i++) {
        if (g_err[i].err == err && strcmp(g_err[i].peer, peer) == 0) {
            return true;
        }
    }
    return false;
}

static int pool_new(cmt_bsync_pool_t *pool, int64_t start)
{
    cmt_bsync_pool_host_t h;

    h.ctx = NULL;
    h.send_request = h_send_request;
    h.send_error = h_send_error;
    rec_reset();
    return cmt_bsync_pool_init(pool, start, &h);
}

/* An empty holder: height and size only (header, "HOW IT CAN LIE" 1). */
static cmt_bsync_block_t *blk(int64_t height)
{
    cmt_bsync_block_t *b = (cmt_bsync_block_t *)calloc(1, sizeof(*b));

    if (b != NULL) {
        b->block.header.height = height;
        b->size = 1000;
    }
    return b;
}

/* Tick every 2 ms from `from` to `to` inclusive. */
static int run(cmt_bsync_pool_t *pool, int64_t from, int64_t to)
{
    int64_t t;

    for (t = from; t <= to; t += 2 * MS) {
        if (cmt_bsync_pool_tick(pool, t, NULL) != CMT_OK) {
            return 1;
        }
    }
    return 0;
}

#define PA "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define PB "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define PX "cccccccccccccccccccccccccccccccccccccccc"

/* ══ cases ════════════════════════════════════════════════════════════ */

static int t_conn_wait_and_requests(void)
{
    cmt_bsync_pool_t   pool;
    int64_t            dl = 0;
    cmt_bsync_block_t *f, *s, *popped = NULL;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, T0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 5, T0) == CMT_OK, "peer A"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, T0 + 1 * SEC, &dl) == CMT_OK, "tick"); OK();
    CHECK(g_nreq == 0, "nothing before peerConnWait (:126-132)"); OK();
    CHECK(dl == T0 + 3 * SEC, "the deadline is start + 3 s"); OK();

    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 20 * MS) == 0, "run"); OK();
    CHECK(pool.n_requesters == 5, "requesters up to maxPeerHeight (:139)"); OK();
    CHECK(count_req(1, PA) == 1 && count_req(5, PA) == 1,
          "each height asked of A once"); OK();
    CHECK(count_req(6, PA) == 0, "nothing above the peer's height"); OK();
    CHECK(!cmt_bsync_pool_is_caught_up(&pool, T0 + 4 * SEC),
          "height 1 < 5 − 1: not caught up"); OK();

    /* blocks arrive from A, in any order */
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(2), T0 + 4 * SEC) == CMT_OK, "add 2"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), T0 + 4 * SEC) == CMT_OK, "add 1"); OK();
    cmt_bsync_pool_peek_two_blocks(&pool, &f, &s);
    CHECK(f != NULL && s != NULL && f->block.header.height == 1 &&
          s->block.header.height == 2, "peek 1 and 2 (:236-242)"); OK();
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK && popped == f,
          "pop hands the first block over"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_height(&pool) == 2, "height advanced (:260)"); OK();

    /* a block from an ID that was not asked: WRONG_SENDER naming it */
    CHECK(cmt_bsync_pool_add_block(&pool, PX, blk(3), T0 + 4 * SEC) == CMT_REJECT,
          "refused"); OK();
    CHECK(has_err(PX, CMT_BSYNC_PEER_ERR_WRONG_SENDER),
          "the error names the sender's ID (:339-341)"); OK();
    /* a block above the height with no requester: UNEXPECTED */
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(9), T0 + 4 * SEC) == CMT_REJECT &&
          has_err(PA, CMT_BSYNC_PEER_ERR_UNEXPECTED), "unexpected (:328-333)"); OK();
    /* a block below the height: already committed, no error */
    g_nerr = 0;
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), T0 + 4 * SEC) == CMT_REJECT &&
          g_nerr == 0, "already committed (:335)"); OK();

    cmt_bsync_pool_stop(&pool);
    CHECK(pool.n_requesters == 0 && !cmt_bsync_pool_is_running(&pool),
          "stop frees the requesters (BS-3)"); OK();
    g_nreq = 0;
    CHECK(run(&pool, T0 + 5 * SEC, T0 + 5 * SEC + 10 * MS) == 0 && g_nreq == 0,
          "nothing is requested after stop"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

static int t_second_peer_and_redo(void)
{
    cmt_bsync_pool_t   pool;
    char               removed[CMT_P2P_ID_CAP];
    cmt_bsync_block_t *f, *s;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, T0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 2, T0) == CMT_OK, "A"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PB, 1, 2, T0) == CMT_OK, "B"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) + count_req(1, PB) == 2 &&
          count_req(1, PA) == 1 && count_req(1, PB) == 1,
          "height 1 asked of BOTH peers (:845-848)"); OK();

    /* B answers height 1 first; A answers too (not an error, :690). */
    CHECK(cmt_bsync_pool_add_block(&pool, PB, blk(1), T0 + 4 * SEC) == CMT_OK, "B's 1"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), T0 + 4 * SEC) == CMT_OK,
          "A's 1 is not an error"); OK();
    CHECK(strcmp(cmt_bsync_pool_requester(&pool, 1)->got_block_from, PB) == 0,
          "the first copy is kept (:688-695)"); OK();

    /* the block from B was bad: B removed, banned, 1 redone */
    CHECK(cmt_bsync_pool_remove_peer_and_redo_all_peer_requests(
              &pool, 1, T0 + 5 * SEC, removed) == CMT_OK, "redo"); OK();
    CHECK(strcmp(removed, PB) == 0, "the deliverer's ID (:277)"); OK();
    CHECK(cmt_bsync_pool_peer(&pool, PB) == NULL, "B removed (:279)"); OK();
    CHECK(cmt_bsync_pool_is_peer_banned(&pool, PB, T0 + 5 * SEC), "B banned (:280)"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, T0 + 5 * SEC, NULL) == CMT_OK, "tick"); OK();
    cmt_bsync_pool_peek_two_blocks(&pool, &f, &s);
    CHECK(f == NULL, "B's block is gone (:751-757)"); OK();
    CHECK(cmt_bsync_pool_requester(&pool, 1)->peer_id[0] == '\0' &&
          strcmp(cmt_bsync_pool_requester(&pool, 1)->second_peer_id, PA) == 0,
          "B's slot is cleared, A (the second peer) is kept and waited for "
          "(:759-763, :878)"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), T0 + 5 * SEC) == CMT_OK,
          "A answers"); OK();
    cmt_bsync_pool_peek_two_blocks(&pool, &f, &s);
    CHECK(f != NULL && strcmp(cmt_bsync_pool_requester(&pool, 1)->got_block_from,
                              PA) == 0, "height 1 now comes from A"); OK();

    /* B's status while banned is ignored; after 60 s it is accepted */
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PB, 1, 2, T0 + 30 * SEC) == CMT_OK &&
          cmt_bsync_pool_peer(&pool, PB) == NULL, "ignored while banned (:387-390)"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PB, 1, 2, T0 + 66 * SEC) == CMT_OK &&
          cmt_bsync_pool_peer(&pool, PB) != NULL, "accepted after 60 s (:464)"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

static int t_peer_timeout(void)
{
    cmt_bsync_pool_t pool;
    int64_t          t;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, T0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 3, T0) == CMT_OK, "A"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) == 1, "asked"); OK();
    t = T0 + 3 * SEC + 10 * MS + 15 * SEC;
    CHECK(cmt_bsync_pool_tick(&pool, t, NULL) == CMT_OK, "tick"); OK();
    CHECK(has_err(PA, CMT_BSYNC_PEER_ERR_TIMEOUT),
          "15 s of silence → TIMEOUT for A (:623-631)"); OK();
    CHECK(cmt_bsync_pool_peer(&pool, PA) != NULL &&
          cmt_bsync_pool_peer(&pool, PA)->did_timeout, "marked"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

static int t_retry_timer(void)
{
    cmt_bsync_pool_t pool;
    int64_t          t;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    pool.peer_timeout_ns = 3600 * SEC;   /* pool.go:57 is a var the tests override */
    CHECK(cmt_bsync_pool_start(&pool, T0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 1, T0) == CMT_OK, "A"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 4 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) == 1, "asked once"); OK();
    t = T0 + 3 * SEC + 29 * SEC;
    CHECK(cmt_bsync_pool_tick(&pool, t, NULL) == CMT_OK && count_req(1, PA) == 1,
          "not yet at 29 s"); OK();
    t = T0 + 3 * SEC + 31 * SEC;
    CHECK(cmt_bsync_pool_tick(&pool, t, NULL) == CMT_OK && count_req(1, PA) == 2,
          "retryTimer at 30 s asks again (:862-868)"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

static int t_lower_height_and_caught_up(void)
{
    cmt_bsync_pool_t   pool;
    cmt_bsync_block_t *popped = NULL;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, T0) == CMT_OK, "start"); OK();
    CHECK(!cmt_bsync_pool_is_caught_up(&pool, T0 + 10 * SEC),
          "no peers → not caught up (:209-212)"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 2, T0) == CMT_OK, "A at 2"); OK();
    CHECK(cmt_bsync_pool_is_caught_up(&pool, T0 + 10 * SEC),
          "height 1 >= 2 − 1 (:220)"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 4, T0) == CMT_OK &&
          cmt_bsync_pool_max_peer_height(&pool) == 4, "A moves up to 4"); OK();
    CHECK(!cmt_bsync_pool_is_caught_up(&pool, T0 + 10 * SEC), "1 < 3"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), T0 + 4 * SEC) == CMT_OK &&
          cmt_bsync_pool_add_block(&pool, PA, blk(2), T0 + 4 * SEC) == CMT_OK &&
          cmt_bsync_pool_add_block(&pool, PA, blk(3), T0 + 4 * SEC) == CMT_OK,
          "three blocks"); OK();
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop 1"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop 2"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_is_caught_up(&pool, T0 + 4 * SEC),
          "height 3 >= 4 − 1 → caught up"); OK();

    /* A reports a LOWER height: removed and banned (:374-383) */
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 2, T0 + 5 * SEC) == CMT_OK,
          "lower report"); OK();
    CHECK(cmt_bsync_pool_peer(&pool, PA) == NULL &&
          cmt_bsync_pool_is_peer_banned(&pool, PA, T0 + 5 * SEC),
          "removed and banned"); OK();
    CHECK(cmt_bsync_pool_max_peer_height(&pool) == 0,
          "maxPeerHeight recomputed with no peers (:443-452)"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

typedef struct {
    const char *name;
    int (*fn)(void);
} s_case_t;

int main(void)
{
    static const s_case_t cases[] = {
        { "peerConnWait, requests, peek/pop, sender checks", t_conn_wait_and_requests },
        { "second peer, RemovePeerAndRedo, ban",             t_second_peer_and_redo },
        { "peerTimeout (onTimeout)",                         t_peer_timeout },
        { "retryTimer",                                      t_retry_timer },
        { "lower height report, IsCaughtUp",                 t_lower_height_and_caught_up },
    };
    size_t i;
    size_t failed = 0u;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (cases[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", cases[i].name);
            failed++;
        } else {
            printf("ok   %s\n", cases[i].name);
        }
    }
    printf("%d checks, %zu case(s) failed\n", g_checks, failed);
    return failed == 0u ? 0 : 1;
}
