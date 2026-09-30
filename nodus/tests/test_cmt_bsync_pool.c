/**
 * Nodus — cometbft C port (pin v0.38.26), blocksync: the block pool of
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
 *   · after Stop nothing is requested and the requesters are gone (BS-3);
 *   · R1-2 / BS-10 (the labelled OWN FIX, decision
 *     2026-09-30-cometbft-pin-v0.38.26.md; the reference is unchanged in
 *     v0.38.26, pool.go:360-364, :712-733, :643-651): a peer that re-sends
 *     a block it already delivered changes NO counter, is NOT blamed and
 *     does NOT push its timeout out — the timeout fires 15 s after its
 *     FIRST delivery; when both peers of a requester deliver, each peer
 *     is decremented once and the pool counter only for the stored copy,
 *     and a third copy changes nothing. Without BS-10 the copy at +10 s
 *     re-arms the timeout to +25 s and the +15 s TIMEOUT check fails;
 *     the pool counter reaches 0 after A's copy and −1 after B's third;
 *   · v0.38.26 upstream cases (pkgA_tests.diff): a StatusResponse with
 *     base > height bans the peer, known or not (pool.go:388-396); a peer
 *     whose base is above the pool height is left out of maxPeerHeight
 *     until PopRequest reaches its base (:275-276, :468-482);
 *     HasPendingRequestFrom sees both peer slots and forgets popped
 *     requesters (:202-213).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION` (every cmt_* target). A DEFAULT
 *   BUILD is enough.
 * ENVIRONMENT: nothing. The two clocks are values in this file (T0/M0,
 *   `MONO()`); no network, no files, no randomness. Safe under `ctest -j`.
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
 *     built from pool.go's lines named above. The three v0.38.26 cases ARE
 *     ported from pool_test.go's new tests, with the requesters made by
 *     the pool's own ticks instead of written into the map by hand.
 *  4. Cites not marked v0.38.26 name cometbft @709fd12b pool.go lines
 *     (the pin moved to v0.38.26 on 2026-09-30; renumbering is pending).
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
/* TWO clocks (cmt_bsync_pool.h "THE CLOCK"; decision
 * 2026-09-30-monotonic-waits.md). Every case writes its instants on ONE
 * timeline based at T0; the WALL reading of an instant is the instant
 * itself (the ban list, the rate monitors), its MONOTONIC reading is
 * `MONO(t)`, the same offset from a DISJOINT base M0 (7 s against
 * ~1.7e9 s). So a function that took a wall value where the reference
 * reads the monotonic clock — or the reverse — is off by ~54 years and
 * fails its case. `t_clock_split` moves the two apart on purpose. */
#define T0  ((int64_t)1700000000 * SEC)
#define M0  ((int64_t)7 * SEC)
#define MONO(t) ((t) - T0 + M0)

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
        if (cmt_bsync_pool_tick(pool, MONO(t), t, NULL) != CMT_OK) {
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
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 5, T0) == CMT_OK, "peer A"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, MONO(T0 + 1 * SEC), T0 + 1 * SEC, &dl) == CMT_OK,
          "tick"); OK();
    CHECK(g_nreq == 0, "nothing before peerConnWait (:126-132)"); OK();
    CHECK(dl == M0 + 3 * SEC, "the deadline is start + 3 s, monotonic"); OK();

    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 20 * MS) == 0, "run"); OK();
    CHECK(pool.n_requesters == 5, "requesters up to maxPeerHeight (:139)"); OK();
    CHECK(count_req(1, PA) == 1 && count_req(5, PA) == 1,
          "each height asked of A once"); OK();
    CHECK(count_req(6, PA) == 0, "nothing above the peer's height"); OK();
    CHECK(!cmt_bsync_pool_is_caught_up(&pool, MONO(T0 + 4 * SEC)),
          "height 1 < 5 − 1: not caught up"); OK();

    /* blocks arrive from A, in any order */
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(2), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK, "add 2"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK, "add 1"); OK();
    cmt_bsync_pool_peek_two_blocks(&pool, &f, &s);
    CHECK(f != NULL && s != NULL && f->block.header.height == 1 &&
          s->block.header.height == 2, "peek 1 and 2 (:236-242)"); OK();
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK && popped == f,
          "pop hands the first block over"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_height(&pool) == 2, "height advanced (:260)"); OK();

    /* a block from an ID that was not asked: WRONG_SENDER naming it */
    CHECK(cmt_bsync_pool_add_block(&pool, PX, blk(3), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_REJECT,
          "refused"); OK();
    CHECK(has_err(PX, CMT_BSYNC_PEER_ERR_WRONG_SENDER),
          "the error names the sender's ID (:339-341)"); OK();
    /* a block above the height with no requester: UNEXPECTED */
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(9), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_REJECT &&
          has_err(PA, CMT_BSYNC_PEER_ERR_UNEXPECTED), "unexpected (:328-333)"); OK();
    /* a block below the height: already committed, no error */
    g_nerr = 0;
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_REJECT &&
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
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 2, T0) == CMT_OK, "A"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PB, 1, 2, T0) == CMT_OK, "B"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) + count_req(1, PB) == 2 &&
          count_req(1, PA) == 1 && count_req(1, PB) == 1,
          "height 1 asked of BOTH peers (:845-848)"); OK();

    /* B answers height 1 first; A answers too (not an error, :690). */
    CHECK(cmt_bsync_pool_add_block(&pool, PB, blk(1), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK, "B's 1"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK,
          "A's 1 is not an error"); OK();
    CHECK(strcmp(cmt_bsync_pool_requester(&pool, 1)->got_block_from, PB) == 0,
          "the first copy is kept (:688-695)"); OK();

    /* the block from B was bad: B removed, banned, 1 redone */
    CHECK(cmt_bsync_pool_remove_peer_and_redo_all_peer_requests(
              &pool, 1, T0 + 5 * SEC, removed) == CMT_OK, "redo"); OK();
    CHECK(strcmp(removed, PB) == 0, "the deliverer's ID (:277)"); OK();
    CHECK(cmt_bsync_pool_peer(&pool, PB) == NULL, "B removed (:279)"); OK();
    CHECK(cmt_bsync_pool_is_peer_banned(&pool, PB, T0 + 5 * SEC), "B banned (:280)"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, MONO(T0 + 5 * SEC), T0 + 5 * SEC, NULL) == CMT_OK,
          "tick"); OK();
    cmt_bsync_pool_peek_two_blocks(&pool, &f, &s);
    CHECK(f == NULL, "B's block is gone (:751-757)"); OK();
    CHECK(cmt_bsync_pool_requester(&pool, 1)->peer_id[0] == '\0' &&
          strcmp(cmt_bsync_pool_requester(&pool, 1)->second_peer_id, PA) == 0,
          "B's slot is cleared, A (the second peer) is kept and waited for "
          "(:759-763, :878)"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(T0 + 5 * SEC), T0 + 5 * SEC) == CMT_OK,
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
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 3, T0) == CMT_OK, "A"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) == 1, "asked"); OK();
    t = T0 + 3 * SEC + 10 * MS + 15 * SEC;
    CHECK(cmt_bsync_pool_tick(&pool, MONO(t), t, NULL) == CMT_OK, "tick"); OK();
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
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 1, T0) == CMT_OK, "A"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 4 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) == 1, "asked once"); OK();
    t = T0 + 3 * SEC + 29 * SEC;
    CHECK(cmt_bsync_pool_tick(&pool, MONO(t), t, NULL) == CMT_OK && count_req(1, PA) == 1,
          "not yet at 29 s"); OK();
    t = T0 + 3 * SEC + 31 * SEC;
    CHECK(cmt_bsync_pool_tick(&pool, MONO(t), t, NULL) == CMT_OK && count_req(1, PA) == 2,
          "retryTimer at 30 s asks again (:862-868)"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

static int t_lower_height_and_caught_up(void)
{
    cmt_bsync_pool_t   pool;
    cmt_bsync_block_t *popped = NULL;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(!cmt_bsync_pool_is_caught_up(&pool, MONO(T0 + 10 * SEC)),
          "no peers → not caught up (:209-212)"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 2, T0) == CMT_OK, "A at 2"); OK();
    CHECK(cmt_bsync_pool_is_caught_up(&pool, MONO(T0 + 10 * SEC)),
          "height 1 >= 2 − 1 (:220)"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 4, T0) == CMT_OK &&
          cmt_bsync_pool_max_peer_height(&pool) == 4, "A moves up to 4"); OK();
    CHECK(!cmt_bsync_pool_is_caught_up(&pool, MONO(T0 + 10 * SEC)), "1 < 3"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK &&
          cmt_bsync_pool_add_block(&pool, PA, blk(2), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK &&
          cmt_bsync_pool_add_block(&pool, PA, blk(3), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK,
          "three blocks"); OK();
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop 1"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop 2"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_is_caught_up(&pool, MONO(T0 + 4 * SEC)),
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

/* ══ R1-2 — the labelled OWN FIX (cmt_bsync_pool.h, BS-10) ═══════════ */

static int32_t peer_pending(const cmt_bsync_pool_t *pool, const char *id)
{
    const cmt_bsync_peer_t *p = cmt_bsync_pool_peer(pool, id);

    return p != NULL ? p->num_pending : -999;
}

static int32_t pool_pending(const cmt_bsync_pool_t *pool)
{
    int32_t np = -999;

    cmt_bsync_pool_get_status(pool, NULL, &np, NULL);
    return np;
}

/* One peer re-sends a block it already delivered. In the reference
 * (v0.38.26 pool.go:360-364 + :643-651, unchanged since 709fd12b) every copy
 * decrements both counters and re-arms the peer's timeout, so a peer that
 * repeats one block every < 15 s is never timed out. With BS-10 the copy
 * changes nothing and the timeout fires 15 s after the FIRST delivery. */
static int t_duplicate_same_peer(void)
{
    cmt_bsync_pool_t        pool;
    const cmt_bsync_peer_t *pa;
    int64_t                 t1 = T0 + 4 * SEC;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 3, T0) == CMT_OK, "A 1..3"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) == 1 && count_req(2, PA) == 1 && count_req(3, PA) == 1,
          "1..3 asked of A, the only peer"); OK();
    CHECK(peer_pending(&pool, PA) == 3 && pool_pending(&pool) == 3,
          "A pending 3, pool pending 3"); OK();

    /* the first, real delivery */
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(t1), t1) == CMT_OK,
          "blk 1"); OK();
    pa = cmt_bsync_pool_peer(&pool, PA);
    CHECK(pa != NULL && pa->num_pending == 2 && pool_pending(&pool) == 2,
          "one real delivery: both counters −1"); OK();
    CHECK(pa->timeout_armed && pa->timeout_at_ns == MONO(t1) + 15 * SEC,
          "timeout re-armed at the delivery (:649), monotonic"); OK();

    /* the same block again at +10 s: nothing changes, nobody is blamed */
    g_nerr = 0;
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(t1 + 10 * SEC),
                                   t1 + 10 * SEC) == CMT_OK,
          "copy at +10 s is dropped silently"); OK();
    CHECK(pa->num_pending == 2 && pool_pending(&pool) == 2,
          "copy: counters unchanged (BS-10)"); OK();
    CHECK(pa->timeout_armed && pa->timeout_at_ns == MONO(t1) + 15 * SEC,
          "copy: the timeout is NOT pushed out"); OK();
    CHECK(g_nerr == 0, "copy: no send_error (an honest slow peer may resend)"); OK();

    /* the timeout fires 15 s after the first delivery */
    CHECK(cmt_bsync_pool_tick(&pool, MONO(t1 + 15 * SEC - 1 * MS),
                              t1 + 15 * SEC - 1 * MS, NULL) == CMT_OK &&
          !has_err(PA, CMT_BSYNC_PEER_ERR_TIMEOUT), "not yet at 14.999 s"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, MONO(t1 + 15 * SEC), t1 + 15 * SEC,
                              NULL) == CMT_OK &&
          has_err(PA, CMT_BSYNC_PEER_ERR_TIMEOUT),
          "TIMEOUT 15 s after the first real delivery (:653-661)"); OK();

    /* a copy after the timeout: still nothing */
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(t1 + 20 * SEC),
                                   t1 + 20 * SEC) == CMT_OK &&
          pa->num_pending == 2 && pool_pending(&pool) == 2 && !pa->timeout_armed,
          "copy at +20 s: counters unchanged, the spent timer not re-armed"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

/* Both peers of one requester deliver (pool.go:720 "getting a block from
 * both peers is not an error"): each peer −1 once; the pool counter −1
 * only for the copy that is stored; a third copy changes nothing. */
static int t_two_peers_both_deliver(void)
{
    cmt_bsync_pool_t pool;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 2, T0) == CMT_OK, "A"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PB, 1, 2, T0) == CMT_OK, "B"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    CHECK(count_req(1, PA) == 1 && count_req(1, PB) == 1 &&
          count_req(2, PA) == 1 && count_req(2, PB) == 1,
          "1 and 2 asked of both (:876-878)"); OK();
    CHECK(peer_pending(&pool, PA) == 2 && peer_pending(&pool, PB) == 2 &&
          pool_pending(&pool) == 2, "A 2, B 2, pool 2"); OK();

    g_nerr = 0;
    CHECK(cmt_bsync_pool_add_block(&pool, PB, blk(1), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK,
          "B's 1 stored"); OK();
    CHECK(peer_pending(&pool, PB) == 1 && pool_pending(&pool) == 1,
          "B −1, pool −1"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(T0 + 4 * SEC), T0 + 4 * SEC) == CMT_OK,
          "A's 1 is not an error (:720)"); OK();
    CHECK(peer_pending(&pool, PA) == 1 && pool_pending(&pool) == 1,
          "A −1 once; the pool counter NOT again (nothing stored)"); OK();
    CHECK(cmt_bsync_pool_add_block(&pool, PB, blk(1), MONO(T0 + 5 * SEC), T0 + 5 * SEC) == CMT_OK &&
          cmt_bsync_pool_add_block(&pool, PA, blk(1), MONO(T0 + 5 * SEC), T0 + 5 * SEC) == CMT_OK,
          "third and fourth copies accepted as no-ops"); OK();
    CHECK(peer_pending(&pool, PA) == 1 && peer_pending(&pool, PB) == 1 &&
          pool_pending(&pool) == 1, "third copy dropped: nothing changes"); OK();
    CHECK(pool_pending(&pool) >= 0, "pool pending never below zero"); OK();
    CHECK(g_nerr == 0, "no send_error for any copy"); OK();
    CHECK(strcmp(cmt_bsync_pool_requester(&pool, 1)->got_block_from, PB) == 0,
          "the first copy is the one kept (:718-725)"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

/* ══ upstream v0.38.26 pool_test.go cases (pkgA_tests.diff) ═════════ */

/* TestBlockPoolBansPeerWithBaseGreaterThanHeight (v0.38.26
 * blocksync/pool.go:388-396). Not reachable from the wire here —
 * ValidateMsg already refuses a StatusResponse with base > height
 * (msgs.go:47-49, the peer is stopped) — but SetPeerRange is ported with
 * its own guard, as upstream has both. */
static int t_bans_base_greater_than_height(void)
{
    cmt_bsync_pool_t pool;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PX, 500, 100, T0) == CMT_OK, "bad"); OK();
    CHECK(cmt_bsync_pool_is_peer_banned(&pool, PX, T0),
          "peer reporting base > height must be banned"); OK();
    CHECK(cmt_bsync_pool_peer(&pool, PX) == NULL &&
          cmt_bsync_pool_max_peer_height(&pool) == 0,
          "banned peer must not raise maxPeerHeight"); OK();

    /* a KNOWN peer that turns base > height is removed and banned too */
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 10, T0) == CMT_OK &&
          cmt_bsync_pool_max_peer_height(&pool) == 10, "A at 10"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 20, 10, T0) == CMT_OK &&
          cmt_bsync_pool_peer(&pool, PA) == NULL &&
          cmt_bsync_pool_is_peer_banned(&pool, PA, T0) &&
          cmt_bsync_pool_max_peer_height(&pool) == 0,
          "known peer: removed (:391-393), banned (:394)"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

/* TestBlockPoolMaxPeerHeightRefreshesOnPopRequest (v0.38.26
 * blocksync/pool.go:275-276, :468-482). */
static int t_max_peer_height_refreshes_on_pop(void)
{
    cmt_bsync_pool_t   pool;
    cmt_bsync_block_t *popped = NULL;
    int                i;

    CHECK(pool_new(&pool, 10) == CMT_OK, "init at 10"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 20, T0) == CMT_OK, "A 1..20"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PB, 15, 100, T0) == CMT_OK, "B 15..100"); OK();
    CHECK(cmt_bsync_pool_max_peer_height(&pool) == 20,
          "B is pruned ahead of pool.height and must not contribute yet"); OK();

    /* requesters for 10.. so PopRequest has something to pop */
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 20 * MS) == 0, "run"); OK();
    for (i = 0; i < 4; i++) {
        CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop"); OK();
        cmt_bsync_block_free(popped);
    }
    CHECK(cmt_bsync_pool_height(&pool) == 14 &&
          cmt_bsync_pool_max_peer_height(&pool) == 20, "at 14 B still excluded"); OK();
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop to 15"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_height(&pool) == 15 &&
          cmt_bsync_pool_max_peer_height(&pool) == 100,
          "B must contribute once pool.height reaches its base, without "
          "re-sending status"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

/* TestBlockPoolHasPendingRequestFrom (v0.38.26 blocksync/pool.go:202-213). */
static int t_has_pending_request_from(void)
{
    cmt_bsync_pool_t   pool;
    cmt_bsync_block_t *popped = NULL;

    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(!cmt_bsync_pool_has_pending_request_from(&pool, PA) &&
          !cmt_bsync_pool_has_pending_request_from(&pool, PB) &&
          !cmt_bsync_pool_has_pending_request_from(&pool, PX), "initial state"); OK();
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 2, T0) == CMT_OK, "A 1..2"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PB, 1, 2, T0) == CMT_OK, "B 1..2"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    /* B entered the sorted list last, at the FRONT (:419-422): B is the
     * first peer of both requesters and A the second (:876-878). */
    CHECK(strcmp(cmt_bsync_pool_requester(&pool, 1)->peer_id, PB) == 0 &&
          strcmp(cmt_bsync_pool_requester(&pool, 1)->second_peer_id, PA) == 0 &&
          strcmp(cmt_bsync_pool_requester(&pool, 2)->peer_id, PB) == 0 &&
          strcmp(cmt_bsync_pool_requester(&pool, 2)->second_peer_id, PA) == 0,
          "B first, A second at 1 and 2"); OK();
    CHECK(cmt_bsync_pool_has_pending_request_from(&pool, PB),
          "requested peer should be reported as pending"); OK();
    CHECK(cmt_bsync_pool_has_pending_request_from(&pool, PA),
          "secondary peer slot should count as pending"); OK();
    CHECK(!cmt_bsync_pool_has_pending_request_from(&pool, PX),
          "non-requested peer must not be reported as pending"); OK();

    /* removing both requesters drops the pending state */
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop 1"); OK();
    cmt_bsync_block_free(popped);
    CHECK(cmt_bsync_pool_pop_request(&pool, &popped) == CMT_OK, "pop 2"); OK();
    cmt_bsync_block_free(popped);
    CHECK(!cmt_bsync_pool_has_pending_request_from(&pool, PA) &&
          !cmt_bsync_pool_has_pending_request_from(&pool, PB), "none left"); OK();
    cmt_bsync_pool_free(&pool);
    return 0;
}

/* Decision 2026-09-30-monotonic-waits.md — the reference's split, held
 * apart: the peer timeout (pool.go:629 `time.AfterFunc`, a runtime timer)
 * follows the MONOTONIC clock whatever the wall clock does; the ban
 * (v0.38.26 :500 stamp `cmttime.Now()`, :494 `time.Since` of it) follows
 * the WALL clock whatever the monotonic clock does — both directions.
 * Against 21afb561: does not compile (the pool took ONE `now_ns`); with
 * two parameters but a reader taking the wrong one — the timeout armed
 * or checked on the wall value, or the ban on the mono value — a check
 * here is off by ~54 years (the disjoint bases) and fails. */
static int t_clock_split(void)
{
    cmt_bsync_pool_t        pool;
    const cmt_bsync_peer_t *pa;
    int64_t                 at;

    /* ── the peer timeout: monotonic ─────────────────────────────── */
    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PA, 1, 3, T0) == CMT_OK, "A"); OK();
    CHECK(run(&pool, T0 + 3 * SEC, T0 + 3 * SEC + 10 * MS) == 0, "run"); OK();
    pa = cmt_bsync_pool_peer(&pool, PA);
    CHECK(pa != NULL && pa->timeout_armed, "A was asked: its timeout is armed"); OK();
    at = pa->timeout_at_ns;
    CHECK(at > M0 + 3 * SEC + 15 * SEC - 1 * MS && at <= M0 + 3 * SEC + 10 * MS + 15 * SEC,
          "armed at a MONOTONIC instant + 15 s (pool.go:629)"); OK();
    g_nerr = 0;
    CHECK(cmt_bsync_pool_tick(&pool, at - 1, T0 + 3600 * SEC, NULL) == CMT_OK &&
          !has_err(PA, CMT_BSYNC_PEER_ERR_TIMEOUT),
          "wall +1 h, mono 1 ns short: no TIMEOUT"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, at - 1, T0 - 3600 * SEC, NULL) == CMT_OK &&
          !has_err(PA, CMT_BSYNC_PEER_ERR_TIMEOUT),
          "wall −1 h, mono 1 ns short: no TIMEOUT"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, at, T0 - 3600 * SEC, NULL) == CMT_OK &&
          has_err(PA, CMT_BSYNC_PEER_ERR_TIMEOUT),
          "mono at the deadline: TIMEOUT, with the wall clock an hour behind"); OK();
    cmt_bsync_pool_free(&pool);

    /* ── the ban: wall ───────────────────────────────────────────── */
    CHECK(pool_new(&pool, 1) == CMT_OK, "init"); OK();
    CHECK(cmt_bsync_pool_start(&pool, M0) == CMT_OK, "start"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PX, 500, 100, T0) == CMT_OK &&
          pool.n_banned == 1, "X banned at wall T0 (v0.38.26 :388-396)"); OK();
    /* With no peers `maxRequestersCreated` holds (0 >= 0, :136), so the
     * makeRequesters step alternates: one tick arms removeTimedoutPeers
     * (:145), the next — 2 ms of MONO later — runs it (:146), which
     * purges the expired bans (:184-188) against the WALL instant. */
    CHECK(cmt_bsync_pool_tick(&pool, M0 + 3 * SEC, T0, NULL) == CMT_OK,
          "arm removeTimedoutPeers"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, M0 + 3 * SEC + 2 * MS + 3600 * SEC,
                              T0 + 30 * SEC, NULL) == CMT_OK &&
          pool.n_banned == 1 && cmt_bsync_pool_is_peer_banned(&pool, PX, T0 + 30 * SEC),
          "mono +1 h, wall +30 s: the 60 s ban still holds"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, M0 + 3 * SEC + 4 * MS + 3600 * SEC,
                              T0 - 3600 * SEC, NULL) == CMT_OK &&
          cmt_bsync_pool_tick(&pool, M0 + 3 * SEC + 6 * MS + 3600 * SEC,
                              T0 - 3600 * SEC, NULL) == CMT_OK &&
          pool.n_banned == 1,
          "wall stepped an hour BACK: time.Since is negative, still banned"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PX, 1, 5, T0 + 30 * SEC) == CMT_OK &&
          cmt_bsync_pool_peer(&pool, PX) == NULL,
          "a StatusResponse at wall +30 s is ignored (:387-390)"); OK();
    CHECK(cmt_bsync_pool_tick(&pool, M0 + 3 * SEC + 8 * MS + 3600 * SEC,
                              T0 + 61 * SEC, NULL) == CMT_OK &&
          cmt_bsync_pool_tick(&pool, M0 + 3 * SEC + 10 * MS + 3600 * SEC,
                              T0 + 61 * SEC, NULL) == CMT_OK &&
          pool.n_banned == 0,
          "wall +61 s: the ban expired and was purged (:184-188)"); OK();
    CHECK(cmt_bsync_pool_set_peer_range(&pool, PX, 1, 5, T0 + 61 * SEC) == CMT_OK &&
          cmt_bsync_pool_peer(&pool, PX) != NULL,
          "and X's StatusResponse is accepted again"); OK();
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
        { "R1-2: one peer re-sends one block (BS-10)",       t_duplicate_same_peer },
        { "R1-2: both peers deliver, third copy (BS-10)",    t_two_peers_both_deliver },
        { "v0.38.26: base > height is banned",               t_bans_base_greater_than_height },
        { "v0.38.26: maxPeerHeight refreshed on pop",        t_max_peer_height_refreshes_on_pop },
        { "v0.38.26: HasPendingRequestFrom",                 t_has_pending_request_from },
        { "clock split: timeout mono, ban wall",             t_clock_split },
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
