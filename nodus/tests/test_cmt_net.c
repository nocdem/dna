/**
 * @file nodus/tests/test_cmt_net.c
 * @brief The transport glue (nodus_witness_cmt_net.{h,c}) — the p2p.Switch
 *        / p2p.Peer stand-in wiring cmt_conr_t and cmt_memr_t over the
 *        witness peer table. R3 wave W3 package C2b. Deltas 1-2 folded
 *        in (stop_peer's real disconnect, memr peer_height's real
 *        reactor read, the persistent/unconditional correction, and
 *        the receive-arena runway + telemetry); delta 3 (host tables
 *        embedded in the glue, not borrowed from a test's stack);
 *        delta 5 (the peer-set scan also runs at the top of
 *        `nodus_cmt_net_receive`, and BOTH the scan and the receive
 *        lookup key off the SAME `net_slot_up` predicate); delta 6
 *        (the socket close `stop_peer_for_error` used to run
 *        synchronously is now DEFERRED to the next tick, closing a
 *        use-after-free in `nodus_tcp`'s own frame-reading loop); delta
 *        7 / the verifier round (item C: the scan and receive wait for
 *        BOTH reactors to be `running`; item D: `net_send` also keys
 *        off `net_slot_up`; item G: the receive lookup separates "find
 *        the slot" from "classify why it is not routable"; item H: a
 *        failing clock is a node-local send fault, never a 0 stamp;
 *        item I: `net_send` refuses to sign with an all-zero
 *        `v2_chain32`); delta 8 (a LIVE port defect, found by the
 *        Genesis Protocol harness at production constants: the scan
 *        never reserved a mempool peer id for a newly up slot, so
 *        every peer read as sender id 0 — the same id the client lane
 *        stamps an RPC-submitted tx with — and a locally admitted
 *        transaction was never gossiped to the fleet at all).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *   · The peer-set scan (nodus_cmt_net_tick, part (a)) tracks
 *     `w->peers[]` correctly: a slot with a connection and `identified`
 *     is added to BOTH reactors AS A PERSISTENT (not unconditional) mempool
 *     peer and its broadcast routine is RUNNING at once at the default
 *     config; losing either condition removes it from BOTH; a
 *     connection-pointer change while still "up" is read as a reconnect
 *     (remove, then re-add), never as a silent no-op.
 *   · `send` (the row both host tables share) returns false for a DOWN
 *     slot and never reaches `nodus_tcp_send` — proven by construction:
 *     the row returns before touching `w->peers[idx].conn` for anything
 *     but the up/down test itself.
 *   · `nodus_cmt_net_receive` routes a verb-35 envelope's `m` to
 *     `cmt_conr_receive` on the State channel and a verb-39 envelope's
 *     `m` to `cmt_memr_receive`, observed through each reactor's own
 *     PUBLIC surface (the peer's round state via `cmt_ps_get_round_state`
 *     for the consensus side; the mempool host row's OWN `peer_height`
 *     for the other, read from `net.memr_host` — the EMBEDDED table
 *     (delta 3) cmt_memr_init was actually given, never a private
 *     symbol) — never by re-implementing what the reactor does.
 *   · An unidentified sender is dropped (CMT_OK, no route) and a
 *     malformed `m` from a KNOWN peer is dropped by the reactor's own
 *     decode gate, which this glue turns into `stop_peer_for_error` —
 *     observed as the peer leaving both reactors' tables.
 *   · THE RECEIVE ARENA IS RESET EVERY RECEIVE, AND CAN NEVER EXHAUST FOR
 *     AN ADMITTED MESSAGE (package C2e, register R3-A-5, CLOSING):
 *     `nodus_cmt_net_receive` -> `cmt_conr_receive` resets `.used` to 0
 *     before every decode, and the arena is sized to exactly
 *     `CMT_CONR_MAX_MSG_SIZE` — the SAME bound the channel already
 *     enforces on the wire — so many full-size BlockPart messages in a
 *     row never disconnect the peer and `recv_arena.used` never exceeds
 *     one message's decoded size (`test_recv_arena_bounded_per_message`,
 *     which REPLACES the old `test_recv_arena_exhausted` pin — that pin
 *     is exactly what this package was built to invalidate); the
 *     50%/90% telemetry latches (still fed by direct field pokes, not
 *     real traffic) fire exactly once each, in order, as usage crosses
 *     them, and are now DEAD-BY-PROOF regression latches — real
 *     messages never approach either threshold.
 *   · A FRAME CAN ARRIVE BEFORE THE NEXT TICK (delta 5): a peer marked
 *     up with NO prior `nodus_cmt_net_tick` call still reaches both
 *     reactors correctly, because `nodus_cmt_net_receive` runs the
 *     identical peer-set scan first — closing the live-node ordering
 *     hazard where the server dispatches a frame before its own tick
 *     next runs (`test_receive_before_tick`).
 *   · A STOPPED SLOT'S SOCKET CLOSE IS DEFERRED, NEVER SYNCHRONOUS
 *     (delta 6): `stop_peer_for_error` clears both reactors' tables at
 *     once but only marks the connection `close_pending`; the slot
 *     stays refused by BOTH the scan and a subsequent receive until
 *     the next tick's close pass runs (or discovers a NEW connection
 *     already took the slot, in which case the flag clears and the new
 *     connection is added as a fresh peer, never touched by the close)
 *     — closing a use-after-free in `nodus_tcp`'s frame-reading loop
 *     that a synchronous disconnect from inside a frame callback would
 *     hit (`test_receive_routing` (d),
 *     `test_close_pending_cleared_on_reconnect`; package C2e removed the
 *     arena-exhaustion trigger this list used to cite here —
 *     `test_recv_arena_bounded_per_message` no longer disconnects
 *     anyone, by design).
 *   · A PEER IS NEVER ADDED BEFORE BOTH REACTORS ARE RUNNING (item C):
 *     a tick with one reactor not yet started adds NOTHING to either
 *     table and does not even record the slot as `slot_up`, matching
 *     switch.go's `OnStart` starting every reactor before
 *     `acceptRoutine` admits a peer; the very next tick after the
 *     missing reactor starts adds the peer correctly, with no retry
 *     logic needed (`test_scan_waits_for_running`).
 *   · A NEWLY UP SLOT GETS A REAL MEMPOOL PEER ID, NEVER 0 (delta 8): a
 *     locally admitted transaction (client-lane style, sender id 0) is
 *     gossiped to every up peer, each with its OWN reserved id, and a
 *     receiving node stamps it with ITS OWN reserved id for that slot —
 *     never with 0, the RPC/unknown-sender id — pinning the live defect
 *     where every peer read as sender 0 and a client-submitted tx was
 *     never broadcast at all (`test_memr_peer_ids_reserved_and_rpc_tx_gossiped`).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: none beyond a default build (`CMT_SOFTWARE_VERSION`,
 *   already required by every cmt_* target). ENVIRONMENT: none.
 * Heap: one `tc_t` fixture (~6 MB, test_cmt_common.h), one `cmt_conr_t`
 *   over `net.recv_arena` at `NODUS_CMT_NET_RECV_ARENA_BYTES` (package
 *   C2e: exactly `CMT_CONR_MAX_MSG_SIZE`, 1 MiB — see that macro's
 *   comment for the bound proof), one `cmt_mem_t` + `cmt_memr_t` at the
 *   default mempool config (~10 MB decode arena, cmt_memr.h's own
 *   figure). Freed at the end of every test.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing: no files, no sockets, no environment changes. `w` is
 * heap-allocated per `feedback_heap_alloc_test_fixture` and freed by
 * `fx_teardown`.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. THE STORE BEHIND `net.store` IS A ZEROED STAND-IN, NEVER A REAL
 *     BLOCK STORE. `nodus_cmt_net_init` requires a non-NULL
 *     `nodus_cmt_store_t *`; this file gives it a `calloc`'d, never
 *     `nodus_cmt_store_init`'d struct. That is SAFE for every scenario
 *     this file drives — read, not assumed, in shared/dnac/cmt_conr.c:
 *     every gossip-routine branch that would dereference the store
 *     through `bs_load_block_part` / `bs_load_block_commit` /
 *     `bs_load_block_extended_commit` is guarded by `store_base > 0`
 *     (:1275, :1563) or by cmt_conr.c:1779's four-term AND
 *     (`prs.catchup_commit_round != -1 && prs.height > 0 && ...`) — item
 *     E CORRECTION: `prs.height` is NOT always zero here, since
 *     `test_receive_routing`'s NewRoundStep sets it to 5 through
 *     `nodus_cmt_net_receive`; what actually closes :1779 in every test
 *     this file runs is `prs.catchup_commit_round`, initialized to -1
 *     by `cmt_ps_init` (cmt_ps.c:240) and never changed by anything
 *     this file sends — `!= -1` evaluates false, short-circuiting the
 *     AND regardless of `prs.height`. `bs_base`/`bs_height` themselves
 *     read a
 *     cached field with no dereference of anything the zeroed struct
 *     lacks (`nodus_witness_cmt_store.c:610-618`). CONSEQUENCE: this
 *     file does NOT exercise `net_bs_load_block_meta_block_id` or
 *     `net_bs_load_block_part` at all — see the wave report's item (5).
 *  2. `net.now` is `tc_now` over the FROZEN `tc.now` — no wall clock, and
 *     nothing here advances it. A defect that only shows up once real
 *     time (or `cmt_conr_tick`'s sleep/deadline bookkeeping) has moved
 *     is invisible here.
 *  3. THE PEER NEVER ACTUALLY CONNECTS. `w->peers[i].conn` is a
 *     dummy non-NULL pointer this file invents and never dereferences
 *     (`nodus_cmt_net_tick`'s scan only compares it, never reads through
 *     it) — the "up" send path (an actual `nodus_tcp_send` over a real
 *     connection) is NOT exercised by this file.
 *  4. `cmt_conr_start` runs with `wait_sync = true`, so `cmt_cs_start`
 *     is never called and the state machine underneath `net`'s `conr`
 *     never actually produces a proposal or a vote. A defect reachable
 *     only once the state machine is live is invisible here — that is
 *     `test_cmt_conr.c`'s and `test_cmt_cs.c`'s ground.
 *  5. THE REJECT CASE TESTED IS A DECODE FAILURE, NOT A LITERAL
 *     CMT_REJECT RETURN. `cmt_conr_receive`'s own contract (cmt_conr.h)
 *     answers a malformed message with CMT_OK (the reference's Receive
 *     "consumed" the bytes and told the host to stop the peer) — this
 *     file's "REJECT logged and dropped" and "arena exhausted" cases
 *     observe exactly that: the glue's `stop_peer_for_error` removes
 *     the peer. It does not drive the state-machine-queue-full
 *     CMT_REJECT (deviation R3-A-2, cmt_conr.h), which needs a live,
 *     started state machine.
 *  6. `w->server` IS DELIBERATELY NULL THROUGHOUT THIS FILE, so the
 *     real `nodus_tcp_disconnect` call never runs here. Since delta 6
 *     that call lives in `net_close_pass`, run from
 *     `nodus_cmt_net_tick` — NOT in `net_stop_peer` itself, which only
 *     marks a slot `close_pending` (see that struct field's doc
 *     comment, nodus_witness_cmt_net.h). `net_close_pass`'s own guard
 *     (`nodus_witness_cmt_net.c:655`, `if (net->w->server)`) is
 *     exercised — every tick after a stop takes its `else` branch — but
 *     the disconnect ITSELF is not, because this file's peer
 *     connections are dummy pointers (HOW IT CAN LIE (3)) and
 *     `nodus_tcp_disconnect`'s `conn_free` (`nodus_tcp.c:209-249`)
 *     dereferences `conn->fd` immediately — a fake pointer there is a
 *     crash, not a refusal. Confirmed by reading `conn_free`, not
 *     assumed. This cannot be unit-tested without a live socket (delta
 *     1's own conclusion, still true after delta 6 moved WHERE the call
 *     happens); every `stop_peer_for_error` case here proves the
 *     TABLES are cleared and the close is correctly DEFERRED and
 *     QUARANTINED (delta 6, HOW IT CAN LIE (8)), never that the
 *     connection actually closes.
 *  7. AN EARLIER VERSION OF THIS FILE PUT THE TWO HOST TABLES ON
 *     `fx_setup`'S OWN STACK, NOT IN `fx_t` — and it was NOT green by
 *     luck. `cmt_memr_init` borrows its host table by pointer for the
 *     reactor's entire lifetime (nodus_witness_cmt_net.h's struct
 *     comment has the exact citations); a stack local passed to it
 *     dangles the moment `fx_setup` returns, so `fx->memr.host` pointed
 *     into a dead frame for the rest of every test. This was
 *     GREEN-BY-LUCK IMPOSSIBLE: it failed immediately, at the very
 *     first `nodus_cmt_net_tick` in every test that reached one
 *     (`cmt_memr_tick` reading garbage rows and returning CMT_FAULT) —
 *     which is exactly what surfaced the borrow-vs-copy asymmetry
 *     between `cmt_memr_init` and `cmt_conr_init` (delta 3). The fix
 *     embeds `conr_host` / `memr_host` as fields of `nodus_cmt_net_t`
 *     itself, filled once by `nodus_cmt_net_init`, so the table this
 *     file hands to both `_init` calls lives exactly as long as `net`
 *     does — the same fix protects package C2a's production wiring
 *     from the identical trap, since production also owns its
 *     `nodus_cmt_net_t` for the reactor's whole lifetime.
 *  8. DELTA 6'S DEFERRED CLOSE NEVER ACTUALLY CLOSES ANYTHING IN THIS
 *     FILE. `w->server` is NULL throughout (HOW IT CAN LIE (6)), so
 *     every `nodus_cmt_net_tick`'s close pass takes the "no server"
 *     branch: `close_pending[i]` stays set, `nodus_tcp_disconnect` is
 *     never called, and `w->peers[i].conn`/`.identified` are left
 *     exactly as this file set them. What the close_pending/close_conn
 *     assertions in `test_receive_routing`
 *     and `test_close_pending_cleared_on_reconnect` prove is the
 *     QUARANTINE BOOKKEEPING — that a stopped slot stays refused by
 *     both `net_scan_peers` and `nodus_cmt_net_receive` until either a
 *     real close runs or a different connection takes the slot — never
 *     that the socket itself closes. That needs a live `nodus_tcp_t`,
 *     out of this file's scope (same boundary as HOW IT CAN LIE (6)).
 *  9. RESIDUAL, KNOWN, NOT FIXED HERE (item K): the deferred close pass
 *     compares connection POINTERS (`net_close_pass`,
 *     nodus_witness_cmt_net.c). Within ONE epoll batch a freed
 *     connection's address can be handed back by `conn_alloc`'s plain
 *     `calloc` (nodus_tcp.c:172-179) to a brand-new accept, and if that
 *     new connection's IDENT frame is processed in the SAME batch, the
 *     same witness can re-occupy the slot with `conn` equal to the
 *     value `net_close_pass` is still watching for — causing one
 *     spurious disconnect of a peer that reconnected inside the same
 *     batch (not a use-after-free: the pointer is live and owned at
 *     that moment). This file cannot exercise that window at all — its
 *     peer connections are dummy pointers, never real sockets (HOW IT
 *     CAN LIE (3)), and it drives one `nodus_cmt_net_tick`/`_receive`
 *     call at a time, never a real epoll batch. The real fix is a
 *     transport-side deferred-close API (a generation counter or
 *     equivalent on the connection/peer-table entry) — a later wave's
 *     work, not this one's.
 *  10. THE DELTA-8 TEST'S `spy_memr_send` REPLACES `net_send` ENTIRELY.
 *      It never builds a T3 envelope, never signs, never touches
 *      `w->server` or `v2_chain32`, and never calls `nodus_tcp_send` —
 *      what it proves is that the MEMPOOL REACTOR calls `host->send`
 *      with the right bytes, for the right peers, on the right
 *      channel; it does NOT prove those bytes ever leave the process
 *      on a live node (that is `net_send`'s own contract, exercised
 *      nowhere in this file — HOW IT CAN LIE (3)). The "channel 0x30"
 *      asserted is `routine_pass`'s own `CMT_MEM_CHANNEL` argument to
 *      the host row, never `net_channel_to_type`'s output — this test
 *      does not exercise that mapping at all.
 */

#include "witness/nodus_witness_cmt_net.h"

#include "dnac/cmt_mem.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_msgs.h"
#include "dnac/cmt_pb.h"

#include "test_cmt_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_PASS(name) fprintf(stderr, "  PASS: %s\n", name)
#define TEST_FAIL(name, msg) do { \
    fprintf(stderr, "  FAIL: %s — %s\n", name, msg); \
    failures++; \
} while (0)

static int failures = 0;

/* ── The accept-everything mempool application (cmt_mem_app_t) ──────
 *
 * The mempool needs SOME AppConnMempool to construct; this file does
 * not test application-level tx validation (that is test_cmt_mem.c's),
 * so every check_tx accepts. */
static int app_error(void *ctx) { (void)ctx; return CMT_OK; }

static int app_check_tx(void *ctx, const cmt_mem_request_check_tx_t *req,
                        cmt_mem_response_check_tx_t *res) {
    (void)ctx; (void)req;
    res->code       = CMT_MEM_CODE_TYPE_OK;
    res->gas_wanted = 0;
    res->gas_used   = 0;
    return CMT_OK;
}

static int app_flush(void *ctx) { (void)ctx; return CMT_OK; }

/* ── The fixture: one tc_t (the real cmt_cs_t), one real cmt_conr_t,
 *    one real cmt_mem_t + cmt_memr_t, one nodus_cmt_net_t over a bare
 *    nodus_witness_t whose peers[] this file drives by hand. ─────────── */

typedef struct {
    tc_t tc;

    cmt_conr_t     conr;

    cmt_mem_app_t        app_if;
    cmt_mempool_config_t mem_cfg;
    cmt_mem_t            mem;
    cmt_memr_t           memr;

    /* SEE "HOW IT CAN LIE" (1): zeroed, never nodus_cmt_store_init'd —
     * safe for every path this file drives, exercises neither
     * net_bs_load_block_meta_block_id nor net_bs_load_block_part. */
    nodus_cmt_store_t dummy_store;

    nodus_cmt_net_t net;

    /* `w->server` is deliberately left NULL (see "HOW IT CAN LIE" (6),
     * delta 1/2): the only thing it would let this fixture exercise is
     * net_send's "up" path (needs a live nodus_tcp_conn_t, out of
     * scope) and net_close_pass's real nodus_tcp_disconnect call
     * (delta 6 moved this out of net_stop_peer — see that function's
     * doc comment), which would dereference this file's DUMMY conn
     * pointers as if they were real heap objects and crash. Both
     * guards (`!net->w->server` / `if (net->w->server)`) are read, not
     * assumed — nodus_witness_cmt_net.c:186 (net_send), :655
     * (net_close_pass). */
    nodus_witness_t *w;
} fx_t;

/**
 * @param start_conr false skips `cmt_conr_start` ONLY — item C's
 *        `test_scan_waits_for_running` needs exactly one reactor left
 *        not-running to prove `net_scan_peers`'s new guard checks BOTH
 *        (`||`, not one). `cmt_memr_start` always runs; a fixture that
 *        skipped both would not distinguish "checks both" from "checks
 *        either one alone", which this file does not need to prove
 *        beyond what the guard's own `||` already states.
 */
static int fx_setup_ex(fx_t *fx, bool start_conr) {
    memset(fx, 0, sizeof(*fx));

    if (tc_setup(&fx->tc, 1, 0, 0) != 0) return -1;

    /* heap-allocated fixture (feedback_heap_alloc_test_fixture) */
    fx->w = (nodus_witness_t *)calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    memset(fx->w->my_id, 0x01, NODUS_T3_WITNESS_ID_LEN);
    memset(fx->w->v2_chain32, 0x02, 32);

    /* nodus_cmt_net_init allocates net.recv_arena at
     * NODUS_CMT_NET_RECV_ARENA_BYTES; THAT arena — not a second,
     * test-owned one — is what gets handed to cmt_conr_init below, so
     * a test that pokes net.recv_arena.used is poking the SAME arena
     * cmt_conr_receive decodes into. */
    if (nodus_cmt_net_init(&fx->net, fx->w, &fx->dummy_store, tc_now,
                           &fx->tc) != CMT_OK) {
        return -1;
    }

    if (cmt_conr_init(&fx->conr, fx->tc.cs, true /* wait_sync */,
                      &fx->net.conr_host, &fx->net, &fx->net.recv_arena)
        != CMT_OK) {
        return -1;
    }
    if (start_conr) {
        if (cmt_conr_start(&fx->conr) != CMT_OK) return -1;
    }

    fx->app_if.ctx      = NULL;
    fx->app_if.error    = app_error;
    fx->app_if.check_tx = app_check_tx;
    fx->app_if.flush    = app_flush;
    if (cmt_mempool_config_default(&fx->mem_cfg) != CMT_OK) return -1;
    if (cmt_mem_init(&fx->mem, &fx->mem_cfg, &fx->app_if, 0, NULL, NULL)
        != CMT_OK) {
        return -1;
    }

    if (cmt_memr_init(&fx->memr, &fx->mem_cfg, &fx->mem, &fx->net.memr_host)
        != CMT_OK) {
        return -1;
    }
    if (cmt_memr_start(&fx->memr) != CMT_OK) return -1;

    if (nodus_cmt_net_bind(&fx->net, &fx->conr, &fx->memr) != CMT_OK) {
        return -1;
    }
    return 0;
}

static int fx_setup(fx_t *fx) {
    return fx_setup_ex(fx, true);
}

static void fx_teardown(fx_t *fx) {
    cmt_memr_free(&fx->memr);
    cmt_mem_free(&fx->mem);
    cmt_conr_free(&fx->conr);
    nodus_cmt_net_free(&fx->net);
    free(fx->w);
    tc_teardown(&fx->tc);
}

/* ── (2) the peer-set scan ──────────────────────────────────────────── */

static void test_peer_scan(void) {
    const char *name = "peer_scan";
    /* heap-allocated fixture (feedback_heap_alloc_test_fixture) */
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    /* Dummy, never-dereferenced connection pointers — the scan only
     * compares them (HOW IT CAN LIE (3)). */
    struct nodus_tcp_conn *conn_a = (struct nodus_tcp_conn *)(size_t)0x1000;
    struct nodus_tcp_conn *conn_b = (struct nodus_tcp_conn *)(size_t)0x2000;

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup(fx) != 0) { TEST_FAIL(name, "fixture setup"); free(fx); return; }

    memset(fx->w->peers[0].witness_id, 0x11, NODUS_T3_WITNESS_ID_LEN);
    fx->w->peers[0].conn       = NULL;
    fx->w->peers[0].identified = false;

    /* down -> down: no transition. */
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (down)"); goto out;
    }
    if (fx->conr.peers[0].in_set || fx->memr.peers[0].present) {
        TEST_FAIL(name, "slot present while down"); goto out;
    }

    /* down -> up. */
    fx->w->peers[0].conn       = conn_a;
    fx->w->peers[0].identified = true;
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (up)"); goto out;
    }
    if (!fx->conr.peers[0].in_set || !fx->conr.peers[0].started) {
        TEST_FAIL(name, "slot not in the reactor after up"); goto out;
    }
    if (!fx->memr.peers[0].present) {
        TEST_FAIL(name, "slot not present in memr after up"); goto out;
    }
    /* Q3 (delta 1 correction): roster peers are PERSISTENT, not
     * UNCONDITIONAL, and — because the default mempool config's
     * persistent-peer gossip cap is 0, which choose_semaphore
     * (cmt_memr.c:27-41) reads as "no limit", not "no admission" —
     * the routine must already be RUNNING, not WAITING. */
    if (fx->memr.peers[0].is_unconditional) {
        TEST_FAIL(name, "roster peer classified unconditional"); goto out;
    }
    if (!fx->memr.peers[0].is_persistent) {
        TEST_FAIL(name, "roster peer not classified persistent"); goto out;
    }
    if (cmt_memr_peer_routine_state(&fx->memr, 0) != CMT_MEMR_ROUTINE_RUNNING) {
        TEST_FAIL(name, "roster peer's mempool routine did not start "
                        "at the default config"); goto out;
    }

    /* up -> up, SAME conn: idempotent, no re-add. */
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (still up)"); goto out;
    }
    if (!fx->conr.peers[0].in_set || !fx->memr.peers[0].present) {
        TEST_FAIL(name, "slot dropped on a no-op tick"); goto out;
    }

    /* up -> up, DIFFERENT conn: a reconnect (remove, then re-add). */
    fx->w->peers[0].conn = conn_b;
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (reconnect)"); goto out;
    }
    if (!fx->conr.peers[0].in_set || !fx->memr.peers[0].present) {
        TEST_FAIL(name, "slot not re-added after reconnect"); goto out;
    }

    /* up -> down. */
    fx->w->peers[0].conn       = NULL;
    fx->w->peers[0].identified = false;
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (down again)"); goto out;
    }
    if (fx->conr.peers[0].in_set || fx->memr.peers[0].present) {
        TEST_FAIL(name, "slot not removed after down"); goto out;
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/* ── (3) send on a down slot never touches the conn ───────────────── */

static void test_send_down(void) {
    const char *name = "send_down";
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    static const uint8_t bytes[4] = { 1, 2, 3, 4 };

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup(fx) != 0) { TEST_FAIL(name, "fixture setup"); free(fx); return; }

    memset(fx->w->peers[0].witness_id, 0x22, NODUS_T3_WITNESS_ID_LEN);
    fx->w->peers[0].conn       = NULL;   /* DOWN */
    fx->w->peers[0].identified = false;

    /* fx->net.conr_host directly (delta 3): the embedded field IS the
     * table cmt_conr_init was given, not a copy of it. */
    /* The whole point: a false return, and — because conn is NULL —
     * nodus_tcp_send was never reached (it would have dereferenced a
     * NULL conn and crashed this test if it had been). */
    if (fx->net.conr_host.send(&fx->net, 0, CMT_CONR_STATE_CHANNEL, bytes,
                               sizeof(bytes))) {
        TEST_FAIL(name, "send accepted on a down slot"); goto out;
    }
    if (fx->net.conr_host.try_send(&fx->net, 0, CMT_CONR_VOTE_CHANNEL, bytes,
                                   sizeof(bytes))) {
        TEST_FAIL(name, "try_send accepted on a down slot"); goto out;
    }
    /* identified but no conn: still down. */
    fx->w->peers[0].identified = true;
    if (fx->net.conr_host.send(&fx->net, 0, CMT_CONR_DATA_CHANNEL, bytes,
                               sizeof(bytes))) {
        TEST_FAIL(name, "send accepted with no conn"); goto out;
    }
    /* An out-of-range slot: also false, never touches peers[]. */
    if (fx->net.conr_host.send(&fx->net, NODUS_T3_MAX_WITNESSES,
                               CMT_CONR_STATE_CHANNEL, bytes, sizeof(bytes))) {
        TEST_FAIL(name, "send accepted an out-of-range slot"); goto out;
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/* ── (4) receive routing ──────────────────────────────────────────── */

/* A real marshalled NewRoundStep (cmt_msg_to_proto + proto marshal),
 * the same idiom test_cmt_conr.c's r_marshal uses. */
static int build_new_round_step(uint8_t *out, size_t cap, size_t *out_len) {
    cmt_msg_t             msg;
    cmt_pb_cons_message_t pb;

    memset(&msg, 0, sizeof(msg));
    msg.kind                          = CMT_PB_CONS_MSG_NEW_ROUND_STEP;
    msg.u.new_round_step.height       = 5;
    msg.u.new_round_step.round        = 0;
    msg.u.new_round_step.step         = CMT_ROUND_STEP_NEW_HEIGHT;
    /* height (5) is above the fixture's initial_height (1): ValidateHeight
     * REJECTs last_commit_round < 0 in that case (cmt_conr.c:1916-1919,
     * reactor.go:1569) — only the initial height may carry -1. */
    msg.u.new_round_step.last_commit_round = 0;

    cmt_pb_cons_message_init(&pb);
    if (cmt_msg_to_proto(&msg, &pb) != CMT_OK) return -1;
    return cmt_pb_cons_message_marshal(&pb, out, cap, out_len) == CMT_OK
           ? 0 : -1;
}

/**
 * A real marshalled BlockPartMessage (Data channel, verb 36 —
 * NODUS_T3_CMT_DATA), used by the receive-arena bound test (package
 * C2e, register R3-A-5) — `payload`/`payload_len` let that test drive
 * CMT_BLOCK_PART_SIZE_BYTES-sized parts, not just a handful of bytes.
 *
 * NOT a verb-35 (State channel) message, and this is a deliberate,
 * VERIFIED correction: `cons_message_merge` (shared/dnac/cmt_pb.c:
 * 5058-5085) hands the arena to `block_part_merge` (BLOCK_PART) and
 * `cons_vote_merge` (VOTE) ONLY — `nrs_merge` (NEW_ROUND_STEP) takes no
 * arena argument at all, because `cmt_new_round_step_msg_t` has no
 * variable-length field (cmt_msgs.h:111-117: height/round/step/
 * seconds_since_start_time/last_commit_round, all fixed scalars).
 * Filling `net.recv_arena` and driving a verb-35 NewRoundStep through
 * it would decode successfully regardless of the arena's state and
 * prove nothing about R3-A-5. A BlockPart's `.bytes` (`cmt_pb.h`:
 * "up to BlockPartSizeBytes and lives in the arena") is the field that
 * actually calls `r_copy_arena`, so this is the verb that exercises it.
 * The part's `proof` is left zeroed: `cmt_part_to_proto`
 * (cmt_part_set.c:60-67) is a plain struct copy with no validation,
 * so ValidateBasic (`cmt_part_validate_basic`, total=0/index=0 default)
 * passes regardless.
 */
static int build_block_part(uint8_t *out, size_t cap, size_t *out_len,
                            const uint8_t *payload, size_t payload_len) {
    cmt_msg_t               msg;
    cmt_pb_cons_message_t   pb;

    memset(&msg, 0, sizeof(msg));
    msg.kind                          = CMT_PB_CONS_MSG_BLOCK_PART;
    msg.u.block_part.height           = 5;
    msg.u.block_part.round            = 0;
    msg.u.block_part.part.index       = 0;
    msg.u.block_part.part.bytes.data  = payload;
    msg.u.block_part.part.bytes.len   = payload_len;

    /* DELTA 1 FIX (package C2e): a ONE-PART set — proof.total = 1,
     * index = 0, no aunts, leaf_hash the REAL leaf hash of the payload
     * (cmt_merkle_leaf_hash, hash.go:11's 0x00 leaf prefix). The
     * previous version of this helper left the whole proof zeroed
     * (leaf_hash_len 0), and `cmt_part_from_proto` (part_set.c, called
     * from `cmt_msg_from_proto`'s BlockPart branch) ENDS IN
     * ValidateBasic (`cmt_part_validate_basic` -> `cmt_proof_validate_
     * basic`, which refuses any `leaf_hash_len != CMT_TMHASH_SIZE`) —
     * so every message this helper built failed at DECODE, before the
     * arena was ever the thing under test. `cmt_part_set_add_part`'s
     * own proof VERIFY never runs on this glue's path (the fixture has
     * no part set to add into — nodus_cmt_net_receive only reaches the
     * reactor's decode + peer-state update), so total=1/index=0/no
     * aunts is sufficient: it need only pass ValidateBasic's SHAPE
     * check, not a real Merkle verification against a set's root. */
    msg.u.block_part.part.proof.total = 1;
    msg.u.block_part.part.proof.index = 0;
    if (cmt_merkle_leaf_hash(payload, payload_len,
                             msg.u.block_part.part.proof.leaf_hash) !=
        CMT_OK) {
        return -1;
    }
    msg.u.block_part.part.proof.leaf_hash_len = (size_t)CMT_TMHASH_SIZE;
    msg.u.block_part.part.proof.aunts_len     = 0u;

    cmt_pb_cons_message_init(&pb);
    if (cmt_msg_to_proto(&msg, &pb) != CMT_OK) return -1;
    return cmt_pb_cons_message_marshal(&pb, out, cap, out_len) == CMT_OK
           ? 0 : -1;
}

static void test_receive_routing(void) {
    const char *name = "receive_routing";
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t known_id[32], unknown_id[32];
    uint8_t bytes[4096];
    size_t  len = 0;
    nodus_t3_msg_t msg;
    cmt_prs_t prs;

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup(fx) != 0) { TEST_FAIL(name, "fixture setup"); free(fx); return; }

    memset(known_id, 0x33, sizeof(known_id));
    memset(unknown_id, 0x44, sizeof(unknown_id));
    memcpy(fx->w->peers[0].witness_id, known_id, 32);
    fx->w->peers[0].identified = true;
    fx->w->peers[0].conn       = (struct nodus_tcp_conn *)(size_t)0x3000;

    /* Bring the slot into BOTH reactors the same way the scan would. */
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick to add the peer"); goto out;
    }

    /* (a) verb 35 (State channel) reaches cmt_conr_receive: a real
     * NewRoundStep updates the PEER's own round state, observed
     * through cmt_ps_get_round_state — the reactor's public accessor. */
    if (build_new_round_step(bytes, sizeof(bytes), &len) != 0) {
        TEST_FAIL(name, "build NewRoundStep"); goto out;
    }
    memset(&msg, 0, sizeof(msg));
    msg.type       = NODUS_T3_CMT_STATE;
    msg.w_cmt.m     = bytes;
    msg.w_cmt.m_len = len;
    if (nodus_cmt_net_receive(&fx->net, known_id, &msg) != CMT_OK) {
        TEST_FAIL(name, "receive verb 35"); goto out;
    }
    cmt_ps_get_round_state(&fx->conr.peers[0].ps, &prs);
    if (prs.height != 5 || prs.round != 0) {
        TEST_FAIL(name, "verb 35 did not reach the consensus reactor"); goto out;
    }

    /* Q2: the mempool host's OWN peer_height row (fx->net.memr_host is
     * the EMBEDDED table cmt_memr_init was actually given, delta 3 —
     * never a private symbol) now answers "known", height 5 — reading
     * the SAME PeerState the NewRoundStep above just updated, through
     * the reactor's own cmt_conr_t.peers[] / cmt_ps_get_height public
     * surface. */
    {
        bool    known = false;
        int64_t h;

        h = fx->net.memr_host.peer_height(&fx->net, 0, &known);
        if (!known || h != 5) {
            TEST_FAIL(name, "memr peer_height did not read the reactor's "
                            "own PeerState"); goto out;
        }
    }

    /* (b) verb 39 (mempool channel): an EMPTY Txs message is a valid,
     * observably-accepted frame (mempool/reactor.go:145-148 logs and
     * ignores it — no disconnect, which IS the accept signal here). */
    {
        cmt_pb_mempool_message_t pbm;
        uint8_t mbytes[64];
        size_t  mlen = 0;

        /* cmt_pb_mempool_message_init READS txs.txs/txs.txs_cap to
         * preserve them (cmt_pb_mempool.h), so they are set BEFORE
         * init, exactly like cmt_memr_get_channels's own construction
         * (shared/dnac/cmt_memr.c). */
        pbm.txs.txs     = NULL;
        pbm.txs.txs_cap = 0;
        cmt_pb_mempool_message_init(&pbm);
        pbm.sum         = CMT_PB_MEMPOOL_MSG_TXS;
        pbm.txs.txs_len = 0;
        if (cmt_pb_mempool_message_marshal(&pbm, mbytes, sizeof(mbytes), &mlen)
            != CMT_OK) {
            TEST_FAIL(name, "build empty Txs"); goto out;
        }
        memset(&msg, 0, sizeof(msg));
        msg.type        = NODUS_T3_CMT_TXS;
        msg.w_cmt.m     = mbytes;
        msg.w_cmt.m_len = mlen;
        if (nodus_cmt_net_receive(&fx->net, known_id, &msg) != CMT_OK) {
            TEST_FAIL(name, "receive verb 39"); goto out;
        }
        /* the peer must still be present: an empty Txs is not an error */
        if (!fx->memr.peers[0].present) {
            TEST_FAIL(name, "verb 39 disconnected the peer on an empty Txs");
            goto out;
        }
    }

    /* (c) an unidentified/unknown sender is dropped, not faulted. */
    memset(&msg, 0, sizeof(msg));
    msg.type        = NODUS_T3_CMT_STATE;
    msg.w_cmt.m     = bytes;
    msg.w_cmt.m_len = len;
    if (nodus_cmt_net_receive(&fx->net, unknown_id, &msg) != CMT_OK) {
        TEST_FAIL(name, "unknown sender was not dropped cleanly"); goto out;
    }

    /* (d) a malformed `m` from a KNOWN peer: the reactor's own decode
     * gate rejects it and this glue's stop_peer_for_error removes the
     * peer from BOTH tables (HOW IT CAN LIE (5) — this is a decode
     * failure, not a literal CMT_REJECT return). Delta 6: the SOCKET
     * close is now DEFERRED to the next tick — see the close_pending
     * assertions below, and HOW IT CAN LIE (8). */
    {
        static const uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        struct nodus_tcp_conn *conn_before = fx->w->peers[0].conn;

        memset(&msg, 0, sizeof(msg));
        msg.type        = NODUS_T3_CMT_STATE;
        msg.w_cmt.m     = garbage;
        msg.w_cmt.m_len = sizeof(garbage);
        if (nodus_cmt_net_receive(&fx->net, known_id, &msg) != CMT_OK) {
            TEST_FAIL(name, "malformed m returned FAULT, not OK"); goto out;
        }
        if (fx->conr.peers[0].in_set || fx->memr.peers[0].present) {
            TEST_FAIL(name, "peer was not removed after a malformed frame");
            goto out;
        }
        if (!fx->net.close_pending[0] || fx->net.close_conn[0] != conn_before) {
            TEST_FAIL(name, "close was not deferred (close_pending/close_conn)");
            goto out;
        }

        /* w->server is NULL throughout this file (HOW IT CAN LIE (6)),
         * so this tick's close pass takes the "no server" branch:
         * close_pending[0] STAYS set, and conn/identified are UNCHANGED
         * (nothing here ever runs the real nodus_tcp_disconnect). What
         * this proves is the quarantine bookkeeping, not the close
         * itself — see HOW IT CAN LIE (8). */
        if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
            TEST_FAIL(name, "tick after a deferred close"); goto out;
        }
        if (!fx->net.close_pending[0]) {
            TEST_FAIL(name, "close_pending cleared with no server to close through");
            goto out;
        }
        if (fx->conr.peers[0].in_set || fx->memr.peers[0].present) {
            TEST_FAIL(name, "a quarantined slot was re-added by the scan");
            goto out;
        }
        if (!fx->w->peers[0].conn || !fx->w->peers[0].identified) {
            TEST_FAIL(name, "conn/identified changed with no real disconnect");
            goto out;
        }

        /* A frame from the same sender is still dropped, not routed —
         * net_slot_up refuses a close_pending slot outright. */
        if (nodus_cmt_net_receive(&fx->net, known_id, &msg) != CMT_OK) {
            TEST_FAIL(name, "receive on a quarantined slot returned FAULT");
            goto out;
        }
        if (fx->conr.peers[0].in_set || fx->memr.peers[0].present) {
            TEST_FAIL(name, "a quarantined slot was routed into by receive");
            goto out;
        }
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/* ── (package C2e, register R3-A-5) the receive arena: reset every
 *    receive, exhaustion unreachable for an admitted message ────────── */

/**
 * PACKAGE C2e (register R3-A-5, CLOSING) replaces the old exhaustion
 * pin: `nodus_cmt_net_receive` -> `cmt_conr_receive` now resets
 * `recv_arena->used = 0` at the top of EVERY call, so this drives many
 * full-size (`CMT_BLOCK_PART_SIZE_BYTES`) BlockPart messages in a row
 * and asserts `nodus_cmt_net_recv_arena_used` never exceeds one
 * message's decoded size and the peer is NEVER disconnected — the
 * opposite of what the pin this replaces asserted.
 *
 * RED ON THE OLD CODE (no reset): after `NODUS_CMT_NET_RECV_ARENA_BYTES`
 * / `CMT_BLOCK_PART_SIZE_BYTES` = 1 048 576 / 65 536 = 16 messages, the
 * 17th's `r_copy_arena` finds no room left, and `cmt_conr_receive` turns
 * that into `stop_peer_for_error(CMT_CONR_STOP_DECODE)`: the loop's
 * 17th-iteration assertion that the peer is still present would be the
 * first to fail.
 */
static void test_recv_arena_bounded_per_message(void) {
    const char *name = "recv_arena_bounded_per_message";
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t known_id[32];
    static uint8_t payload[CMT_BLOCK_PART_SIZE_BYTES];
    static uint8_t bytes[(size_t)CMT_BLOCK_PART_SIZE_BYTES + 4096u];
    size_t  len = 0;
    nodus_t3_msg_t msg;
    size_t  i;
    /* Comfortably above the old 16-message exhaustion horizon. */
    const size_t n_messages = 64u;

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup(fx) != 0) { TEST_FAIL(name, "fixture setup"); free(fx); return; }

    memset(known_id, 0x55, sizeof(known_id));
    memcpy(fx->w->peers[0].witness_id, known_id, 32);
    fx->w->peers[0].identified = true;
    fx->w->peers[0].conn       = (struct nodus_tcp_conn *)(size_t)0x4000;
    memset(payload, 0x5A, sizeof(payload));

    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick to add the peer"); goto out;
    }

    for (i = 0; i < n_messages; i++) {
        if (build_block_part(bytes, sizeof(bytes), &len, payload,
                             sizeof(payload)) != 0) {
            TEST_FAIL(name, "build BlockPart"); goto out;
        }
        memset(&msg, 0, sizeof(msg));
        msg.type        = NODUS_T3_CMT_DATA;
        msg.w_cmt.m     = bytes;
        msg.w_cmt.m_len = len;
        if (nodus_cmt_net_receive(&fx->net, known_id, &msg) != CMT_OK) {
            TEST_FAIL(name, "receive of a well-formed BlockPart"); goto out;
        }
        if (nodus_cmt_net_recv_arena_used(&fx->net) >
            sizeof(payload) + 4096u) {
            TEST_FAIL(name, "recv_arena usage exceeded one message's size");
            goto out;
        }
        if (!fx->conr.peers[0].in_set || !fx->memr.peers[0].present) {
            TEST_FAIL(name, "peer was disconnected — arena exhaustion is "
                            "no longer reachable for an admitted message");
            goto out;
        }
        if (fx->net.close_pending[0]) {
            TEST_FAIL(name, "a close was queued with no decode failure");
            goto out;
        }
    }

    /* DELTA 1 (package C2e): an explicit "no Error decoding message ever
     * happened" check. close_pending is only ACTED ON at tick time
     * (net_close_pass, delta 6); asserting it stays false after a
     * post-loop tick too — not just after each receive — closes the gap
     * between "nothing was queued for close" and "nothing was ever
     * ACTUALLY closed". */
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick after the loop"); goto out;
    }
    if (fx->net.close_pending[0]) {
        TEST_FAIL(name, "close_pending set after the loop — a decode "
                        "error happened somewhere in the run");
        goto out;
    }
    if (!fx->conr.peers[0].in_set || !fx->memr.peers[0].present) {
        TEST_FAIL(name, "peer missing after the post-loop tick");
        goto out;
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/**
 * The 50%/90% telemetry latches (delta 2): fire exactly once each, in
 * order, as `nodus_cmt_net_tick` observes `recv_arena.used` cross the
 * thresholds — read through `nodus_cmt_net_recv_arena_used` (the
 * public accessor), the latch state through the struct's own public
 * fields (no private symbol).
 */
static void test_recv_arena_latches(void) {
    const char *name = "recv_arena_latches";
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    size_t cap;

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup(fx) != 0) { TEST_FAIL(name, "fixture setup"); free(fx); return; }

    cap = nodus_cmt_net_recv_arena_used(&fx->net);
    if (cap != 0) { TEST_FAIL(name, "used nonzero before any traffic"); goto out; }
    cap = fx->net.recv_arena.cap;
    if (cap != (size_t)NODUS_CMT_NET_RECV_ARENA_BYTES) {
        TEST_FAIL(name, "recv_arena.cap is not the runway constant"); goto out;
    }

    /* Below 50%: neither latch fires. */
    fx->net.recv_arena.used = cap / 4;
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (25%)"); goto out;
    }
    if (fx->net.recv_arena_warned_50 || fx->net.recv_arena_warned_90) {
        TEST_FAIL(name, "a latch fired below its threshold"); goto out;
    }

    /* Cross 50%: only the 50% latch fires. */
    fx->net.recv_arena.used = cap / 2;
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (50%)"); goto out;
    }
    if (!fx->net.recv_arena_warned_50 || fx->net.recv_arena_warned_90) {
        TEST_FAIL(name, "the 50%% latch did not fire alone at 50%%"); goto out;
    }

    /* Stay at 50%: the latch does not un-fire or re-fire (no repeat
     * mechanism to observe here beyond "still true, still false"). */
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (still 50%)"); goto out;
    }
    if (!fx->net.recv_arena_warned_50 || fx->net.recv_arena_warned_90) {
        TEST_FAIL(name, "latch state changed with no new crossing"); goto out;
    }

    /* Cross 90%: the 90% latch fires; the 50% latch is still set.
     * Divide before multiply for Windows portability — package C2e
     * shrank the bound to CMT_CONR_MAX_MSG_SIZE (1 MiB), so cap * 95
     * fits a 32-bit size_t either way now, but the safer form costs
     * nothing and needs no re-litigating if the bound ever changes
     * again. */
    {
        size_t used_95 = (cap / 100u) * 95u;

        fx->net.recv_arena.used = used_95;
        if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
            TEST_FAIL(name, "tick (95%)"); goto out;
        }
        if (!fx->net.recv_arena_warned_50 || !fx->net.recv_arena_warned_90) {
            TEST_FAIL(name, "the 90%% latch did not fire at 95%%"); goto out;
        }
        if (nodus_cmt_net_recv_arena_used(&fx->net) != used_95) {
            TEST_FAIL(name, "the accessor did not report the current usage");
            goto out;
        }
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/* ── (delta 5) receive before the next tick ever runs ──────────────── */

/**
 * On a live node the very first cometbft frame from a freshly
 * identified peer can arrive before `nodus_cmt_net_tick` next runs (see
 * `nodus_cmt_net_receive`'s doc comment in the header for the ordering
 * hazard, with its nodus_server.c / nodus_witness_peer.c citations).
 * This drives exactly that: a peer marked up WITHOUT any prior
 * `nodus_cmt_net_tick` call, then a receive. It must succeed — the
 * peer-set scan `nodus_cmt_net_receive` now runs first adds the slot to
 * both reactors before the lookup, matching switch.go:813-860's
 * InitPeer/AddPeer-before-Receive order.
 *
 * WHAT MAKES THIS RED: reverting the fix (removing the
 * `net_scan_peers` call from `nodus_cmt_net_receive`, delta 5's item 2)
 * turns this CMT_FAULT — `cmt_conr_receive` hits `cmt_conr.c:795-801`'s
 * "Peer %d has no state" on the absent slot, the reference's own panic
 * path (reactor_test.go:278-305).
 */
static void test_receive_before_tick(void) {
    const char *name = "receive_before_tick";
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t known_id[32];
    uint8_t bytes[256];
    size_t  len = 0;
    nodus_t3_msg_t msg;
    cmt_prs_t prs;

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup(fx) != 0) { TEST_FAIL(name, "fixture setup"); free(fx); return; }

    memset(known_id, 0x66, sizeof(known_id));
    memcpy(fx->w->peers[0].witness_id, known_id, 32);
    fx->w->peers[0].identified = true;
    fx->w->peers[0].conn       = (struct nodus_tcp_conn *)(size_t)0x5000;

    /* Deliberately NO nodus_cmt_net_tick call here — the slot has never
     * been through the scan when the receive below runs. */

    if (build_new_round_step(bytes, sizeof(bytes), &len) != 0) {
        TEST_FAIL(name, "build NewRoundStep"); goto out;
    }
    memset(&msg, 0, sizeof(msg));
    msg.type       = NODUS_T3_CMT_STATE;
    msg.w_cmt.m     = bytes;
    msg.w_cmt.m_len = len;
    if (nodus_cmt_net_receive(&fx->net, known_id, &msg) != CMT_OK) {
        TEST_FAIL(name, "receive before any tick returned FAULT, not OK");
        goto out;
    }

    if (!fx->conr.peers[0].in_set || !fx->conr.peers[0].started) {
        TEST_FAIL(name, "consensus reactor slot not added/started by receive");
        goto out;
    }
    if (!fx->memr.peers[0].present) {
        TEST_FAIL(name, "mempool reactor slot not added by receive");
        goto out;
    }
    cmt_ps_get_round_state(&fx->conr.peers[0].ps, &prs);
    if (prs.height != 5 || prs.round != 0) {
        TEST_FAIL(name, "NewRoundStep did not reach the consensus reactor");
        goto out;
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/* ── (delta 6) a reconnect clears a pending close without disconnecting
 *    the NEW connection ─────────────────────────────────────────────── */

/**
 * `net_stop_peer` captures `close_conn[i]` at stop time so that if a
 * DIFFERENT connection takes the slot before the deferred close runs,
 * the tick's close pass recognises the mismatch and clears the flag
 * WITHOUT touching the new connection (item 3 of delta 6's close pass:
 * `conn != close_conn[i]` — "already gone, or a NEW connection took
 * the slot"). The freshly-cleared slot is then a plain down->up
 * transition to `net_scan_peers`, run right after in the same tick, so
 * it is added as a NEW peer.
 */
static void test_close_pending_cleared_on_reconnect(void) {
    const char *name = "close_pending_cleared_on_reconnect";
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));
    uint8_t known_id[32];
    static const uint8_t garbage[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    struct nodus_tcp_conn *conn_old = (struct nodus_tcp_conn *)(size_t)0x6000;
    struct nodus_tcp_conn *conn_new = (struct nodus_tcp_conn *)(size_t)0x7000;
    nodus_t3_msg_t msg;

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup(fx) != 0) { TEST_FAIL(name, "fixture setup"); free(fx); return; }

    memset(known_id, 0x77, sizeof(known_id));
    memcpy(fx->w->peers[0].witness_id, known_id, 32);
    fx->w->peers[0].identified = true;
    fx->w->peers[0].conn       = conn_old;

    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick to add the peer"); goto out;
    }
    if (!fx->conr.peers[0].in_set || !fx->memr.peers[0].present) {
        TEST_FAIL(name, "peer not added before the stop"); goto out;
    }

    /* Trigger the deferred stop (a malformed frame, same as
     * test_receive_routing (d)). */
    memset(&msg, 0, sizeof(msg));
    msg.type        = NODUS_T3_CMT_STATE;
    msg.w_cmt.m     = garbage;
    msg.w_cmt.m_len = sizeof(garbage);
    if (nodus_cmt_net_receive(&fx->net, known_id, &msg) != CMT_OK) {
        TEST_FAIL(name, "malformed m returned FAULT, not OK"); goto out;
    }
    if (!fx->net.close_pending[0] || fx->net.close_conn[0] != conn_old) {
        TEST_FAIL(name, "close was not deferred against the OLD conn");
        goto out;
    }

    /* A reconnect before the close pass ever runs: a DIFFERENT
     * connection takes the slot (the witness peer table's own upsert
     * would do this on a fresh IDENT — not re-derived here, this file
     * drives w->peers[] by hand throughout). */
    fx->w->peers[0].conn = conn_new;

    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick after the reconnect"); goto out;
    }
    if (fx->net.close_pending[0] || fx->net.close_conn[0] != NULL) {
        TEST_FAIL(name, "close_pending was not cleared on a reconnect");
        goto out;
    }
    /* The NEW connection was never touched by the close pass: it is
     * still exactly what this test set it to, and the peer is a fresh
     * add, not a leftover. */
    if (fx->w->peers[0].conn != conn_new) {
        TEST_FAIL(name, "the close pass touched the NEW connection");
        goto out;
    }
    if (!fx->conr.peers[0].in_set || !fx->conr.peers[0].started) {
        TEST_FAIL(name, "reconnect was not added as a new peer (conr)");
        goto out;
    }
    if (!fx->memr.peers[0].present) {
        TEST_FAIL(name, "reconnect was not added as a new peer (memr)");
        goto out;
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/* ── (item C) the scan waits for BOTH reactors to be running ────────── */

/**
 * p2p/switch.go `OnStart` (:234-247) starts every reactor BEFORE it
 * starts `acceptRoutine` (:244), the goroutine that admits peers — a
 * peer can only be InitPeer'd/AddPeer'd once every reactor is already
 * running. This drives the fixture with `cmt_conr_start` skipped
 * (`fx_setup_ex(fx, false)`; `cmt_memr_start` still runs, so the
 * `||` in `net_scan_peers`'s guard is exercised by exactly one reactor
 * being the reason, not both): a peer marked up, one tick — must add
 * NOTHING to either reactor and must NOT touch `net.slot_up[0]` — then
 * `cmt_conr_start` runs and a second tick must add the peer normally.
 *
 * WHAT MAKES THIS RED: removing the `if (!net->conr->running ||
 * !net->memr->running) return CMT_OK;` guard from `net_scan_peers`
 * turns the FIRST tick's assertions red — `cmt_conr_init_peer` does not
 * check `running` at all (cmt_conr.c:570-605) and would set `in_set`
 * true, then `cmt_conr_add_peer`'s own `!running` guard
 * (cmt_conr.c:615-617) would leave `started` false while `slot_up[0]`
 * is still recorded true by the scan — the exact stuck-forever defect
 * item C closes.
 */
static void test_scan_waits_for_running(void) {
    const char *name = "scan_waits_for_running";
    fx_t *fx = (fx_t *)calloc(1, sizeof(*fx));

    if (!fx) { TEST_FAIL(name, "alloc fixture"); return; }
    if (fx_setup_ex(fx, false) != 0) {
        TEST_FAIL(name, "fixture setup"); free(fx); return;
    }
    if (fx->conr.running) {
        TEST_FAIL(name, "fixture started conr — test proves nothing"); goto out;
    }
    if (!fx->memr.running) {
        TEST_FAIL(name, "fixture did not start memr"); goto out;
    }

    memset(fx->w->peers[0].witness_id, 0x88, NODUS_T3_WITNESS_ID_LEN);
    fx->w->peers[0].conn       = (struct nodus_tcp_conn *)(size_t)0x8000;
    fx->w->peers[0].identified = true;

    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (conr not running)"); goto out;
    }
    if (fx->conr.peers[0].in_set || fx->memr.peers[0].present) {
        TEST_FAIL(name, "peer added before both reactors were running");
        goto out;
    }
    if (fx->net.slot_up[0]) {
        TEST_FAIL(name, "slot_up recorded true while the scan was a no-op");
        goto out;
    }

    if (cmt_conr_start(&fx->conr) != CMT_OK) {
        TEST_FAIL(name, "cmt_conr_start"); goto out;
    }
    if (nodus_cmt_net_tick(&fx->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick (both running)"); goto out;
    }
    if (!fx->conr.peers[0].in_set || !fx->conr.peers[0].started) {
        TEST_FAIL(name, "peer not added to conr once both reactors run");
        goto out;
    }
    if (!fx->memr.peers[0].present) {
        TEST_FAIL(name, "peer not added to memr once both reactors run");
        goto out;
    }

    TEST_PASS(name);
out:
    fx_teardown(fx);
    free(fx);
}

/* ── (delta 8) mempool peer-id reservation + RPC tx gossip ──────────── */

/**
 * Captures every call the mempool row would make to `net_send`, one
 * slot per `peer_idx`, WITHOUT `net_send`'s real T3 envelope /
 * signature / `w->server` path — this spy REPLACES `memr_host.send`
 * entirely for the duration of the test below. Overwriting
 * `fx->net.memr_host.send` AFTER `fx_setup` works because
 * `cmt_memr_init` BORROWS its host table by pointer (delta 3's own
 * finding, `cmt_memr.c:170` `memR->host = host;`): the reactor reads
 * whatever this struct field holds at the moment it calls
 * `host->send`, never a copy taken at init time. What lands in
 * `bytes`/`len` is exactly the marshalled `cmt_pb_mempool_message_t`
 * `routine_pass` builds (`cmt_memr.c:534-551`) — the SAME bytes
 * `nodus_cmt_net_receive` expects as `msg->w_cmt.m` on the other end,
 * with no T3 wrapping on either side of this capture.
 */
typedef struct {
    bool    sent[NODUS_T3_MAX_WITNESSES];
    uint8_t channel[NODUS_T3_MAX_WITNESSES];
    uint8_t bytes[NODUS_T3_MAX_WITNESSES][512];
    size_t  len[NODUS_T3_MAX_WITNESSES];
    int     count;
} send_capture_t;

static send_capture_t g_send_capture;

static bool spy_memr_send(void *ctx, int peer_idx, uint8_t channel_id,
                          const uint8_t *bytes, size_t len)
{
    (void)ctx;
    if (peer_idx < 0 || peer_idx >= NODUS_T3_MAX_WITNESSES) return false;
    if (len > sizeof(g_send_capture.bytes[0])) return false;
    g_send_capture.sent[peer_idx]    = true;
    g_send_capture.channel[peer_idx] = channel_id;
    memcpy(g_send_capture.bytes[peer_idx], bytes, len);
    g_send_capture.len[peer_idx]     = len;
    g_send_capture.count++;
    /* Pretend the send succeeded: a false here would make
     * `routine_pass` (cmt_memr.c:555-559) put the peer to sleep and
     * retry, which tests something unrelated to the id-reservation
     * defect this case exists to pin. */
    return true;
}

/**
 * DELTA 8 — LIVE PORT DEFECT, found by the Genesis Protocol harness at
 * production constants and pinned on a running node with gdb (a
 * dprintf inside `routine_pass`, every peer slot): a claim submitted
 * through the client lane on one node was included ONLY when that SAME
 * node became proposer again, 6-7 heights later, and NO other node
 * ever received it — `cmt_memr_receive` never entered anywhere in the
 * fleet. gdb trace, every slot: `SENDER-CHECK slot=N peer_id=0
 * is_sender=1` -> `WAIT-NEXT`.
 *
 * ROOT CAUSE: `net_scan_peers` never called `cmt_memr_init_peer`
 * (mempool/reactor.go:50-53's `InitPeer`, `ids.ReserveForPeer`), so
 * `cmt_mem_ids_get_for_peer` answered 0 for every slot — which is ALSO
 * `CMT_MEM_UNKNOWN_PEER_ID`, the id the reference reserves for exactly
 * ONE sender: the RPC/CheckTx submitter itself (mempool/ids.go:69,
 * `nextID: 1, // reserve unknownPeerID(0)`). `routine_start`
 * (cmt_memr.c:146) cached that same 0 into `p->peer_id` for every
 * slot, so `cmt_mem_tx_is_sender(tx, 0)` read true for every peer and
 * `routine_pass`'s sender check (cmt_memr.c:533) refused to gossip to
 * anyone.
 *
 * THREE PARTS, each RED on the pre-fix code (see each assertion's own
 * FAIL message for the exact old-code behaviour):
 * (a) after the tick that adds two peer slots on node A, both slots'
 *     mempool ids must be non-zero and distinct.
 * (b) admitting ONE tx through `cmt_mem_check_tx` exactly as the
 *     client lane does (`sender_id = 0`), then ONE
 *     `nodus_cmt_net_tick`, must produce exactly one captured
 *     CMT_MEM_CHANNEL send to EACH up slot.
 * (c) feeding slot 0's captured bytes into a SECOND, independent
 *     fixture node's `nodus_cmt_net_receive` must land the tx in that
 *     node's mempool, stamped as sent by THAT node's own reserved id
 *     for slot 0 — never by id 0.
 */
static void test_memr_peer_ids_reserved_and_rpc_tx_gossiped(void) {
    const char *name = "memr_peer_ids_reserved_and_rpc_tx_gossiped";
    fx_t *fxA = (fx_t *)calloc(1, sizeof(*fxA));
    fx_t *fxB = (fx_t *)calloc(1, sizeof(*fxB));
    uint16_t id0, id1;
    static const uint8_t tx_bytes[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
    cmt_mem_tx_info_t info;
    cmt_clist_elem_t *front;
    const cmt_mem_tx_t *tx;

    if (!fxA || !fxB) {
        TEST_FAIL(name, "alloc fixtures"); free(fxA); free(fxB); return;
    }
    if (fx_setup(fxA) != 0) {
        TEST_FAIL(name, "fixture A setup"); free(fxA); free(fxB); return;
    }
    if (fx_setup(fxB) != 0) {
        TEST_FAIL(name, "fixture B setup");
        fx_teardown(fxA); free(fxA); free(fxB); return;
    }

    /* Two up slots on node A — the sending/fleet side. */
    memset(fxA->w->peers[0].witness_id, 0xA0, NODUS_T3_WITNESS_ID_LEN);
    fxA->w->peers[0].conn       = (struct nodus_tcp_conn *)(size_t)0xA000;
    fxA->w->peers[0].identified = true;
    memset(fxA->w->peers[1].witness_id, 0xA1, NODUS_T3_WITNESS_ID_LEN);
    fxA->w->peers[1].conn       = (struct nodus_tcp_conn *)(size_t)0xA001;
    fxA->w->peers[1].identified = true;

    if (nodus_cmt_net_tick(&fxA->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "tick to add both peers"); goto out;
    }

    /* (a) mempool ids reserved and distinct — ascending scan gives 1
     * then 2 deterministically (mempool/ids.go's nextID starts at 1,
     * reserving 0 for the RPC/unknown sender). */
    id0 = cmt_mem_ids_get_for_peer(&fxA->memr.ids, 0);
    id1 = cmt_mem_ids_get_for_peer(&fxA->memr.ids, 1);
    if (id0 == 0 || id1 == 0) {
        TEST_FAIL(name, "(a) peer id not reserved (0) — cmt_memr_init_peer "
                        "never called (the delta-8 defect)");
        goto out;
    }
    if (id0 == id1) {
        TEST_FAIL(name, "(a) both slots share one mempool id"); goto out;
    }

    /* (b) admit ONE tx exactly as the client lane does — sender_id = 0,
     * no p2p witness attached — then ONE tick must gossip it to BOTH
     * up slots. */
    memset(&g_send_capture, 0, sizeof(g_send_capture));
    fxA->net.memr_host.send = spy_memr_send;
    memset(&info, 0, sizeof(info));   /* sender_id = 0: the client lane's
                                       * own idiom (RPC submission). */
    if (cmt_mem_check_tx(&fxA->mem, tx_bytes, sizeof(tx_bytes), &info,
                         NULL, NULL) != CMT_OK) {
        TEST_FAIL(name, "(b) cmt_mem_check_tx did not admit the tx"); goto out;
    }
    if (nodus_cmt_net_tick(&fxA->net, NULL) != CMT_OK) {
        TEST_FAIL(name, "(b) tick after admitting the tx"); goto out;
    }
    if (g_send_capture.count != 2 || !g_send_capture.sent[0] ||
        !g_send_capture.sent[1]) {
        TEST_FAIL(name, "(b) the tx was not gossiped to both up slots — "
                        "pre-fix this is 0 sends: every peer's id read 0 "
                        "and cmt_mem_tx_is_sender(tx, 0) was already true "
                        "(gdb: SENDER-CHECK slot=N peer_id=0 is_sender=1)");
        goto out;
    }
    if (g_send_capture.channel[0] != (uint8_t)CMT_MEM_CHANNEL ||
        g_send_capture.channel[1] != (uint8_t)CMT_MEM_CHANNEL) {
        TEST_FAIL(name, "(b) gossiped on the wrong channel"); goto out;
    }

    /* (c) feed slot 0's captured bytes into an INDEPENDENT node's
     * receive path — that node's OWN reserved id for the slot, not 0,
     * must be what gets stamped as the sender. */
    memset(fxB->w->peers[0].witness_id, 0xA0, NODUS_T3_WITNESS_ID_LEN);
    fxB->w->peers[0].conn       = (struct nodus_tcp_conn *)(size_t)0xB000;
    fxB->w->peers[0].identified = true;
    {
        nodus_t3_msg_t msg;
        uint8_t        sender_id[32];

        memset(sender_id, 0xA0, sizeof(sender_id));
        memset(&msg, 0, sizeof(msg));
        msg.type        = NODUS_T3_CMT_TXS;
        msg.w_cmt.m     = g_send_capture.bytes[0];
        msg.w_cmt.m_len = g_send_capture.len[0];
        /* nodus_cmt_net_receive runs its own peer-set scan first
         * (delta 5), which — with THIS delta's fix — reserves node B's
         * OWN mempool id for slot 0 before cmt_memr_receive ever runs. */
        if (nodus_cmt_net_receive(&fxB->net, sender_id, &msg) != CMT_OK) {
            TEST_FAIL(name, "(c) receive on node B returned FAULT"); goto out;
        }
    }
    front = cmt_mem_txs_front(&fxB->mem);
    if (front == NULL) {
        TEST_FAIL(name, "(c) node B's mempool did not receive the tx");
        goto out;
    }
    tx = (const cmt_mem_tx_t *)cmt_clist_elem_value(front);
    if (tx == NULL) {
        TEST_FAIL(name, "(c) node B's clist element has no value"); goto out;
    }
    {
        uint16_t b_id0 = cmt_mem_ids_get_for_peer(&fxB->memr.ids, 0);

        if (b_id0 == 0) {
            TEST_FAIL(name, "(c) node B never reserved an id for slot 0 — "
                            "the SAME delta-8 defect on the receive side");
            goto out;
        }
        if (!cmt_mem_tx_is_sender(tx, b_id0)) {
            TEST_FAIL(name, "(c) the tx is not stamped as sent by node "
                            "B's OWN reserved id for slot 0");
            goto out;
        }
        if (cmt_mem_tx_is_sender(tx, 0)) {
            TEST_FAIL(name, "(c) the tx is stamped as sent by id 0 — the "
                            "receive side stamped the RPC/unknown sender "
                            "instead of the actual peer");
            goto out;
        }
    }

    TEST_PASS(name);
out:
    fx_teardown(fxA);
    fx_teardown(fxB);
    free(fxA);
    free(fxB);
}

int main(void) {
    fprintf(stderr, "=== nodus_witness_cmt_net tests ===\n");

    test_peer_scan();
    test_send_down();
    test_receive_routing();
    test_recv_arena_bounded_per_message();
    test_recv_arena_latches();
    test_receive_before_tick();
    test_close_pending_cleared_on_reconnect();
    test_scan_waits_for_running();
    test_memr_peer_ids_reserved_and_rpc_tx_gossiped();

    fprintf(stderr, "\n%d test(s) failed\n", failures);
    return failures > 0 ? 1 : 0;
}
