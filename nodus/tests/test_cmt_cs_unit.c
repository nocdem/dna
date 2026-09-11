/**
 * Nodus — cometbft @709fd12b C port, wave R2-C:
 * `consensus/state.go`, the consensus state machine (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the parts of the state machine which need no application, no
 * signer and no block store behave exactly as cometbft's do. If this file
 * failed, one of these would be false:
 *   · a timeout is acted on only when it is for the CURRENT height and
 *     not behind the current round or step — the rule at state.go:970,
 *     including its asymmetry: a LATER round or step is accepted, an
 *     earlier one is dropped, and a different height is dropped whichever
 *     way it differs;
 *   · a node that is not a validator still walks NewHeight → NewRound →
 *     Propose → Prevote on its timeouts, because :1170 and :2445 return
 *     early without signing anything and the `defer` blocks at :1153-1164
 *     and :1330-1334 still run;
 *   · this node's own messages are handled in the order it produced them
 *     — the internal queue is FIFO — and the 1001st message onto a
 *     1000-deep queue (state.go:45) STOPS the node instead of being
 *     reordered the way the reference's goroutine reorders it
 *     (:571-578, whose own comment admits the reordering);
 *   · a proposal carrying no signature is refused at :1927 and installs
 *     neither itself nor a part set, and the two part-set slots the round
 *     state already names are left byte-identical through that refusal
 *     and through `updateToState`'s ignore path (:676-684);
 *   · entering a higher round copies the validator set and increments the
 *     proposer priority ON THE COPY (:1073-1074), leaving
 *     `cs.state.Validators` untouched;
 *   · `voteTime` (:2416-2435) never returns a stamp at or below the
 *     locked or proposal block's own time: it returns the clock when the
 *     clock is later, and blockTime + 1ms when it is not, with the locked
 *     block taking precedence over the proposal block;
 *   · the timeouts the state machine arms are the config's own
 *     arithmetic — `timeout + delta*round` (config.go:1059-1078) — at the
 *     reference's default values;
 *   · `catchupReplay`'s END_HEIGHT rule holds in both directions
 *     (replay.go:100-137): a record for the height being replayed must
 *     NOT exist, one for the height below MUST, and at the initial height
 *     the marker looked for is 0;
 *   · `CompareHRS` (:2600-2617) orders by height, then round, then step;
 *   · each of the SEVEN `enter*` entry guards drops what the reference
 *     drops and lets through what the reference lets through, and each is
 *     exercised on the side where a copy-paste between them would be
 *     wrong: `enterNewRound`'s step term is `!=` and NOT `<=` (NewHeight
 *     is the lowest step, so `<=` would drop every call and the chain
 *     would never start), `enterPrecommitWait`'s third term is the
 *     TriggeredTimeoutPrecommit FLAG and not a step comparison, and
 *     `enterCommit` has NO ROUND TERM at all. A guard that trips returns
 *     CMT_OK and changes nothing — a CMT_REJECT there would deadlock the
 *     state machine.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: none. A DEFAULT BUILD is enough. The file compiles
 * without QGP_FAULT_INJECT and therefore exercises none of the six fail
 * points; `CMT_FAIL_POINT()` is an empty statement in this build.
 * ENVIRONMENT: none. No variables are read — in particular this test
 * never sets `FAIL_TEST_INDEX`, which is the only variable the module
 * looks at and only under QGP_FAULT_INJECT.
 * No network, no files, no database, no real clock: the `now` callback is
 * a variable this file writes, every key comes from
 * `qgp_dsa87_keypair_derand` with a fixed seed, and every timestamp is a
 * constant. Safe under `ctest -j`.
 *
 * ⚠ PEAK MEMORY. Three `cmt_state_storage_t` (about 1 MB each: three
 * 128-slot validator arrays carrying 2592-byte public keys) plus a
 * 1000-deep message queue of heap `cmt_msg_info_t`, each about 10 KB
 * while queued. `t_internal_queue` fills that queue on purpose, so this
 * test peaks near 15 MB before it drains. Everything is freed.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no environment
 * variables, no global state outside this translation unit.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. THE NODE IS NEVER A VALIDATOR. Every scenario runs with
 *     `has_priv_validator` false, which is what makes a host-free test
 *     possible at all. So nothing here signs, nothing here votes, and a
 *     green says NOTHING about `signVote` (:2366-2414), `signAddVote`'s
 *     body past :2457, vote extensions, or the whole prevote/precommit
 *     vote path. Those need a signer and belong to wave T's scenario
 *     suite in test_cmt_cs.c.
 *  2. NO BLOCK IS EVER PROPOSED, DECODED OR COMMITTED. The host's
 *     `create_proposal_block`, `decode_block`, `process_proposal`,
 *     `validate_block`, `apply_verified_block` and every block-store row
 *     are never reached in a passing run; several are deliberately wired
 *     to fail so that a test which DID reach them would break rather than
 *     silently pass. `finalizeCommit` is not exercised at all.
 *  3. THE SLOT ALLOCATOR IS NEVER CALLED. Every path that builds a part
 *     set needs either a valid proposal signature (:1945) or a +2/3
 *     majority (:1553, :1647, :2299), and a host-free test can produce
 *     neither. `t_part_set_slots` therefore proves only that a REFUSED
 *     proposal touches nothing and that the ignore path preserves the
 *     names; it does NOT prove that the allocator picks a free slot, and
 *     it cannot reach the CMT_FAULT branch for "all three named" — which
 *     is unreachable by construction anyway, since there are only three
 *     names. Both belong to wave T.
 *  8. THE ROUND-1 PROPOSER IS NOT CHECKED. `t_proposer_wiring` asserts
 *     that the copy's priorities moved and the state's did not; it does
 *     NOT assert WHICH validator round 1 elects, because this test has
 *     not computed cometbft's priority arithmetic for powers 10/20/30/40
 *     and asserting it from intuition would be a guess.
 *  4. THE QUEUE ORDER IS OBSERVED THROUGH THE WAL. `t_internal_queue`
 *     tags each message with a distinct round and reads the order back
 *     out of the `wal_write_sync` callback. That proves the order the
 *     state machine HANDLED them in, which is the property that matters,
 *     but it would also pass if `handleMsg` did nothing at all — and here
 *     it very nearly does nothing, because every vote carries a height
 *     the state machine ignores at :2172. That is deliberate (it keeps
 *     the crypto out) and it is a limit.
 *  5. THE FAIL POINTS ARE NOT COMPILED. Under a default build
 *     `CMT_FAIL_POINT()` expands to `((void)0)`, so a green proves
 *     nothing whatever about `FAIL_TEST_INDEX` handling, the call
 *     counter, or the exit.
 *  6. `voteTime` IS TESTED THROUGH A FAKE CLOCK. It proves the clamp
 *     arithmetic and that the clock is read through the callback; it
 *     cannot prove that a real host clock is monotonic or canonical.
 *  7. Every validator's public key is a derandomised ML-DSA-87 key and no
 *     signature is created or verified anywhere in this file.
 *  9. THE ENTRY GUARDS ARE TESTED AS PREDICATES, NOT AS TRANSITIONS.
 *     `t_entry_guards` sets the round state DIRECTLY rather than walking
 *     into each step, because walking to precommit needs a signer, a
 *     proposal and votes. So it proves the guard answers correctly for a
 *     given (height, round, step); it does NOT prove the state machine
 *     ever REACHES those combinations by its own transitions, nor what
 *     the body past a guard does. Both are wave T's.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/state.go   2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *   consensus/replay.go   565 lines
 *     5609c4d4174a536389cb2814bac09557a66e3299292141b54c635e31425284fe
 *   config/config.go     1283 lines
 *     f0c2f601d49e1a56b36e8d557387e96ee53ecc3616ecb79749b0f71c0f218c21
 *
 * @file test_cmt_cs_unit.c
 */

#include "dnac/cmt_cs.h"
#include "dnac/cmt_genesis.h"

#include "crypto/sign/qgp_dilithium.h"

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

/* ══ fixtures ═════════════════════════════════════════════════════════ */

#define NVALS 4
#define GENESIS_SECONDS 1700000000

static uint8_t g_pk[NVALS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NVALS][QGP_DSA87_SECRETKEYBYTES];

static cmt_genesis_validator_t g_gvals[NVALS];
static cmt_valset_scratch_t   *g_scratch;
static cmt_state_storage_t    *g_stor_gen;
static cmt_state_storage_t    *g_stor_cs;
static cmt_state_storage_t    *g_stor_scratch;
static cmt_state_t            *g_genesis;
static cmt_cs_t               *g_cs;
static cmt_cs_slots_t         *g_slots;
static cmt_config_t            g_config;

/* ── the recording host ─────────────────────────────────────────────── */

/* The clock this test hands the state machine. Nothing here reads a real
 * one; `cmt_cs` reads this through the `now` row and nowhere else. */
static cmt_time_t g_now;
static int        g_now_calls;

/* What the host's timer was last told to do. */
static int64_t    g_armed_ns;
static int        g_arm_calls;
static int        g_disarm_calls;

/* The order the WAL saw records in. `g_sync_rounds` records the `round`
 * field of every vote written through wal_write_sync, which is how
 * t_internal_queue observes the order messages were HANDLED in. */
#define SYNC_MAX (CMT_CS_MSG_QUEUE_SIZE + 8)
static int32_t   *g_sync_rounds;
static size_t     g_sync_len;

/* Replay: which heights the WAL claims an END_HEIGHT for. */
static int64_t    g_end_height_present;   /* -1 = none                    */
static bool       g_replay_eof;

static int h_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    g_now_calls++;
    *out = g_now;
    return CMT_OK;
}

static int h_timer_arm(void *ctx, int64_t ns)
{
    (void)ctx;
    g_arm_calls++;
    g_armed_ns = ns;
    return CMT_OK;
}

static int h_timer_disarm(void *ctx)
{
    (void)ctx;
    g_disarm_calls++;
    return CMT_OK;
}

static int h_wal_write(void *ctx, const cmt_wal_message_t *msg)
{
    (void)ctx;
    (void)msg;
    return CMT_OK;
}

static int h_wal_write_sync(void *ctx, const cmt_wal_message_t *msg)
{
    (void)ctx;
    if (msg != NULL && msg->kind == CMT_PB_WAL_MSG_INFO &&
        msg->u.msg_info.msg.kind == CMT_PB_CONS_MSG_VOTE &&
        g_sync_rounds != NULL && g_sync_len < (size_t)SYNC_MAX) {
        g_sync_rounds[g_sync_len] = msg->u.msg_info.msg.u.vote.vote.round;
        g_sync_len++;
    }
    return CMT_OK;
}

static int h_wal_flush(void *ctx)
{
    (void)ctx;
    return CMT_OK;
}

static int h_wal_search_end_height(void *ctx, int64_t height, bool *found)
{
    (void)ctx;
    *found = (g_end_height_present >= 0 && height == g_end_height_present);
    return CMT_OK;
}

static int h_wal_read_next(void *ctx, cmt_timed_wal_message_t *out, bool *eof)
{
    (void)ctx;
    (void)out;
    *eof = g_replay_eof;
    return CMT_OK;
}

/* Every row below is deliberately a FAILURE. A passing run never reaches
 * one; a test that started to would break loudly instead of drifting. */
static int h_create_block(void *c, int64_t h, const cmt_state_t *s,
                          const cmt_extended_commit_t *e, const uint8_t *a,
                          size_t al, cmt_block_t *o)
{
    (void)c; (void)h; (void)s; (void)e; (void)a; (void)al; (void)o;
    return CMT_FAULT;
}

static int h_process_proposal(void *c, cmt_block_t *b, const cmt_state_t *s,
                              bool *acc)
{
    (void)c; (void)b; (void)s; (void)acc;
    return CMT_FAULT;
}

static int h_validate_block(void *c, const cmt_state_t *s, cmt_block_t *b)
{
    (void)c; (void)s; (void)b;
    return CMT_FAULT;
}

static int h_apply_block(void *c, const cmt_block_id_t *id, cmt_block_t *b,
                         cmt_state_t *st)
{
    (void)c; (void)id; (void)b; (void)st;
    return CMT_FAULT;
}

static int h_extend_vote(void *c, const cmt_vote_t *v, cmt_block_t *b,
                         const cmt_state_t *s, cmt_pb_bytes_t *o)
{
    (void)c; (void)v; (void)b; (void)s; (void)o;
    return CMT_FAULT;
}

static int h_verify_ext(void *c, const cmt_vote_t *v)
{
    (void)c; (void)v;
    return CMT_FAULT;
}

static int h_bs_height(void *c, int64_t *out)
{
    (void)c;
    *out = 0;
    return CMT_OK;
}

static int h_bs_commit(void *c, int64_t h, cmt_commit_t *o, bool *f)
{
    (void)c; (void)h; (void)o;
    *f = false;
    return CMT_OK;
}

static int h_bs_ext_commit(void *c, int64_t h, cmt_extended_commit_t *o,
                           bool *f)
{
    (void)c; (void)h; (void)o;
    *f = false;
    return CMT_OK;
}

static int h_bs_meta(void *c, int64_t h, cmt_header_t *o, bool *f)
{
    (void)c; (void)h; (void)o;
    *f = false;
    return CMT_OK;
}

static int h_bs_save(void *c, cmt_block_t *b, const cmt_part_set_t *p,
                     const cmt_commit_t *sc)
{
    (void)c; (void)b; (void)p; (void)sc;
    return CMT_FAULT;
}

static int h_bs_save_ext(void *c, cmt_block_t *b, const cmt_part_set_t *p,
                         const cmt_extended_commit_t *sc)
{
    (void)c; (void)b; (void)p; (void)sc;
    return CMT_FAULT;
}

static int h_report_conflict(void *c, const cmt_vote_t *a, const cmt_vote_t *b)
{
    (void)c; (void)a; (void)b;
    return CMT_OK;
}

static int h_sign_vote(void *c, const uint8_t *cid, size_t cl, cmt_pb_vote_t *v)
{
    (void)c; (void)cid; (void)cl; (void)v;
    return CMT_FAULT;
}

static int h_sign_proposal(void *c, const uint8_t *cid, size_t cl,
                           cmt_proposal_t *p)
{
    (void)c; (void)cid; (void)cl; (void)p;
    return CMT_FAULT;
}

static int h_get_pub_key(void *c, cmt_pb_public_key_t *o)
{
    (void)c; (void)o;
    return CMT_FAULT;
}

static int h_decode_block(void *c, const uint8_t *b, size_t n, cmt_block_t *o)
{
    (void)c; (void)b; (void)n; (void)o;
    return CMT_REJECT;
}

static void build_host(cmt_cs_host_t *h)
{
    memset(h, 0, sizeof(*h));
    h->create_proposal_block             = h_create_block;
    h->process_proposal                  = h_process_proposal;
    h->validate_block                    = h_validate_block;
    h->apply_verified_block              = h_apply_block;
    h->extend_vote                       = h_extend_vote;
    h->verify_vote_extension             = h_verify_ext;
    h->bs_height                         = h_bs_height;
    h->bs_load_block_commit              = h_bs_commit;
    h->bs_load_block_extended_commit     = h_bs_ext_commit;
    h->bs_load_block_meta                = h_bs_meta;
    h->bs_load_seen_commit               = h_bs_commit;
    h->bs_save_block                     = h_bs_save;
    h->bs_save_block_with_extended_commit = h_bs_save_ext;
    h->report_conflicting_votes          = h_report_conflict;
    h->sign_vote                         = h_sign_vote;
    h->sign_proposal                     = h_sign_proposal;
    h->get_pub_key                       = h_get_pub_key;
    h->wal_write                         = h_wal_write;
    h->wal_write_sync                    = h_wal_write_sync;
    h->wal_flush_and_sync                = h_wal_flush;
    h->wal_search_end_height             = h_wal_search_end_height;
    h->wal_read_next                     = h_wal_read_next;
    h->decode_block                      = h_decode_block;
    h->now                               = h_now;
    h->timer_arm                         = h_timer_arm;
    h->timer_disarm                      = h_timer_disarm;
}

/* ── the genesis state (state/state.go:314-353 through cmt_state) ───── */

static int build_genesis(void)
{
    static const int64_t powers[NVALS] = { 10, 20, 30, 40 };
    cmt_genesis_doc_t    doc;
    size_t               i;

    memset(&doc, 0, sizeof(doc));
    doc.genesis_time.seconds = GENESIS_SECONDS;
    doc.genesis_time.nanos   = 0;
    for (i = 0; i < (size_t)CMT_PB_CHAINID_MAX; i++) {
        doc.chain_id[i] = (uint8_t)(0x50u + i);
    }
    doc.chain_id_len       = (size_t)CMT_PB_CHAINID_MAX;
    doc.initial_height     = 1;
    doc.has_consensus_params = false;
    doc.validators         = g_gvals;
    doc.validators_cap     = NVALS;
    doc.validators_len     = NVALS;
    for (i = 0; i < (size_t)NVALS; i++) {
        memset(&g_gvals[i], 0, sizeof(g_gvals[i]));
        g_gvals[i].pub_key.present = true;
        memcpy(g_gvals[i].pub_key.key, g_pk[i], QGP_DSA87_PUBLICKEYBYTES);
        g_gvals[i].power       = powers[i];
        g_gvals[i].address_len = 0u;
    }
    if (cmt_state_init(g_genesis, g_stor_gen) != CMT_OK) {
        return 1;
    }
    if (cmt_state_make_genesis(&doc, NULL, NULL, g_scratch,
                               g_genesis) != CMT_OK) {
        return 1;
    }
    return 0;
}

/* ── slot backing storage the host owes cmt_cs (cmt_cs.h) ──────────── */

#define TEST_PARTS_CAP   8u
#define TEST_PAYLOAD_CAP 65536u

static int build_slots(void)
{
    size_t i;

    g_slots = (cmt_cs_slots_t *)calloc(1u, sizeof(*g_slots));
    if (g_slots == NULL) {
        return 1;
    }
    for (i = 0; i < (size_t)CMT_CS_BLOCK_SLOTS; i++) {
        g_slots->parts[i] = (cmt_part_t *)calloc((size_t)TEST_PARTS_CAP,
                                                 sizeof(cmt_part_t));
        g_slots->parts_cap[i]   = (size_t)TEST_PARTS_CAP;
        g_slots->payload[i]     = (uint8_t *)calloc((size_t)TEST_PAYLOAD_CAP, 1u);
        g_slots->payload_cap[i] = (size_t)TEST_PAYLOAD_CAP;
        if (g_slots->parts[i] == NULL || g_slots->payload[i] == NULL) {
            return 1;
        }
    }
    g_slots->marshal_parts = (cmt_part_t *)calloc((size_t)TEST_PARTS_CAP,
                                                  sizeof(cmt_part_t));
    g_slots->marshal_parts_cap   = (size_t)TEST_PARTS_CAP;
    g_slots->marshal_scratch     = (uint8_t *)calloc((size_t)TEST_PAYLOAD_CAP, 1u);
    g_slots->marshal_scratch_cap = (size_t)TEST_PAYLOAD_CAP;
    if (g_slots->marshal_parts == NULL || g_slots->marshal_scratch == NULL) {
        return 1;
    }
    return 0;
}

static void free_slots(void)
{
    size_t i;

    if (g_slots == NULL) {
        return;
    }
    for (i = 0; i < (size_t)CMT_CS_BLOCK_SLOTS; i++) {
        free(g_slots->parts[i]);
        free(g_slots->payload[i]);
    }
    free(g_slots->marshal_parts);
    free(g_slots->marshal_scratch);
    free(g_slots);
    g_slots = NULL;
}

/** A fresh state machine at height 1, round 0, RoundStepNewHeight, with no
 *  private validator — the shape :1170 and :2445 return early on. */
static int fresh_cs(void)
{
    cmt_cs_host_t host;

    build_host(&host);
    g_now.seconds = GENESIS_SECONDS;
    g_now.nanos   = 0;
    g_now_calls   = 0;
    g_arm_calls   = 0;
    g_disarm_calls = 0;
    g_armed_ns    = 0;
    g_sync_len    = 0;
    g_end_height_present = 0;   /* END_HEIGHT for 0 exists, for 1 does not */
    g_replay_eof  = true;

    if (cmt_config_default(&g_config) != CMT_OK) {
        return 1;
    }
    if (cmt_cs_init(g_cs, &g_config, g_genesis, &host, NULL, g_slots,
                    g_stor_cs, g_stor_scratch, NULL, 0) != CMT_OK) {
        return 1;
    }
    return 0;
}

/* ══ 1. CompareHRS — state.go:2600-2617 ═══════════════════════════════ */

static int t_compare_hrs(void)
{
    CHECK(cmt_compare_hrs(1, 0, CMT_ROUND_STEP_PROPOSE,
                          2, 0, CMT_ROUND_STEP_PROPOSE) == -1,
          "a lower height is behind"); OK();
    CHECK(cmt_compare_hrs(3, 0, CMT_ROUND_STEP_PROPOSE,
                          2, 9, CMT_ROUND_STEP_COMMIT) == 1,
          "height dominates round and step"); OK();
    CHECK(cmt_compare_hrs(2, 1, CMT_ROUND_STEP_COMMIT,
                          2, 2, CMT_ROUND_STEP_NEW_ROUND) == -1,
          "at one height, round dominates step"); OK();
    CHECK(cmt_compare_hrs(2, 2, CMT_ROUND_STEP_PREVOTE,
                          2, 2, CMT_ROUND_STEP_PRECOMMIT) == -1,
          "at one height and round, the step decides"); OK();
    CHECK(cmt_compare_hrs(2, 2, CMT_ROUND_STEP_PREVOTE,
                          2, 2, CMT_ROUND_STEP_PREVOTE) == 0,
          "identical is 0"); OK();
    return 0;
}

/* ══ 2. the config arithmetic the state machine arms — config.go ══════ */

static int t_config_durations(void)
{
    cmt_config_t c;
    cmt_time_t   t;
    cmt_time_t   out;

    CHECK(cmt_config_default(&c) == CMT_OK, "DefaultConsensusConfig"); OK();

    /* config.go:1020-1021 — 3000ms + 500ms*round. */
    CHECK(cmt_config_propose(&c, 0) == 3000 * CMT_MILLISECOND,
          "Propose(0) is timeoutPropose"); OK();
    CHECK(cmt_config_propose(&c, 3) == 4500 * CMT_MILLISECOND,
          "Propose(3) adds three deltas"); OK();
    /* :1022-1023 and :1024-1025 — 1000ms + 500ms*round, both of them. */
    CHECK(cmt_config_prevote(&c, 2) == 2000 * CMT_MILLISECOND,
          "Prevote(2)"); OK();
    CHECK(cmt_config_precommit(&c, 2) == 2000 * CMT_MILLISECOND,
          "Precommit(2)"); OK();

    /* :1080-1084 — Commit(t) is t + timeoutCommit, and the default
     * timeoutCommit is 1000ms (:1026), so the carry is exercised. */
    t.seconds = 100;
    t.nanos   = 500000000;
    CHECK(cmt_config_commit(&c, t, &out) == CMT_OK, "Commit"); OK();
    CHECK(out.seconds == 101 && out.nanos == 500000000,
          "one second later, nanos unchanged"); OK();

    /* :1054-1057 — WaitForTxs is !CreateEmptyBlocks || interval > 0. The
     * defaults are true and 0 (:1028-1029), so it is false. */
    CHECK(!cmt_config_wait_for_txs(&c),
          "the reference defaults do not wait for txs"); OK();
    c.create_empty_blocks_interval = 60000 * CMT_MILLISECOND;
    CHECK(cmt_config_wait_for_txs(&c),
          "a positive interval makes it wait"); OK();
    return 0;
}

/* ══ 3. the round-step walk of a non-validator — :1053-1343 ═══════════ */

static int t_round_step_walk(void)
{
    cmt_timeout_info_t ti;

    CHECK(fresh_cs() == 0, "construct"); OK();

    CHECK(g_cs->rs.height == 1, "genesis puts us at the initial height");
    OK();
    CHECK(g_cs->rs.round == 0 && g_cs->rs.step == CMT_ROUND_STEP_NEW_HEIGHT,
          "updateToState leaves round 0 / RoundStepNewHeight (:720)"); OK();
    CHECK(g_cs->rs.locked_round == -1 && g_cs->rs.valid_round == -1 &&
          g_cs->rs.commit_round == -1,
          "and the three rounds at -1 (:737, :740, :748)"); OK();
    CHECK(g_cs->rs.votes != NULL, "with a height vote set (:744/:746)"); OK();
    CHECK(g_cs->rs.last_commit == NULL,
          "and no LastCommit at height 0 (:692)"); OK();

    /* :722-728 — CommitTime is Go's zero here, so StartTime is
     * Commit(now) = now + 1000ms. */
    CHECK(g_cs->rs.start_time.seconds == GENESIS_SECONDS + 1,
          "StartTime is now + timeoutCommit (:728)"); OK();

    /* A NewHeight timeout drives enterNewRound(h, 0), which — with
     * WaitForTxs false at the defaults — goes straight on to
     * enterPropose (:1113), which schedules its own timeout and, with no
     * priv validator, ends at RoundStepPropose (:1155). */
    ti.duration = 0;
    ti.height   = 1;
    ti.round    = 0;
    ti.step     = CMT_ROUND_STEP_NEW_HEIGHT;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &g_cs->rs) == CMT_OK,
          "the NewHeight tock"); OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PROPOSE,
          "NewHeight -> NewRound -> Propose without a validator key"); OK();
    CHECK(g_cs->rs.round == 0, "still round 0"); OK();
    CHECK(g_armed_ns == cmt_config_propose(&g_config, 0),
          "and the armed timeout is Propose(0) (:1167)"); OK();

    /* A Propose timeout drives enterPrevote, whose defaultDoPrevote finds
     * no locked block and no proposal block and calls signAddVote, which
     * returns at :2445 because there is no priv validator. */
    ti.step = CMT_ROUND_STEP_PROPOSE;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &g_cs->rs) == CMT_OK,
          "the Propose tock"); OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PREVOTE,
          "Propose -> Prevote (:1332)"); OK();

    cmt_cs_free(g_cs);
    return 0;
}

/* ══ 3b. the seven entry guards — :1056, :1143, :1322, :1409, :1445,
 *        :1567, :1599 ══════════════════════════════════════════════════
 *
 * The guards are near-identical and BREAK THE PATTERN in three places, so
 * each is exercised on the side where a copy-paste would be wrong. They
 * are pure predicates over (height, round, step), so the round state is
 * set DIRECTLY here rather than walked into place — walking to precommit
 * needs a validator key, a proposal and votes, which is wave T's scenario
 * suite. A guard that trips must return CMT_OK and change nothing: the
 * reference returns silently, and a CMT_REJECT here would deadlock the
 * state machine.                                                        */

static int t_entry_guards(void)
{
    cmt_round_step_t step_before;
    int32_t          round_before;

    CHECK(fresh_cs() == 0, "construct"); OK();

    /* ── :1056 enterNewRound. The step term is `!=`, NOT `<=`. Since
     * NewHeight is the LOWEST step, a `<=` here would drop EVERY call and
     * the chain would never start — so the load-bearing case is the one
     * that must PROCEED. */
    CHECK(g_cs->rs.round == 0 && g_cs->rs.step == CMT_ROUND_STEP_NEW_HEIGHT,
          "we start at round 0 / NewHeight"); OK();
    CHECK(cmt_cs_enter_new_round(g_cs, 1, 0) == CMT_OK &&
          g_cs->rs.step != CMT_ROUND_STEP_NEW_HEIGHT,
          "at NewHeight the same round is NOT dropped — `!=`, not `<=`");
    OK();

    /* A different height is dropped. */
    step_before  = g_cs->rs.step;
    round_before = g_cs->rs.round;
    CHECK(cmt_cs_enter_new_round(g_cs, 2, 0) == CMT_OK &&
          g_cs->rs.step == step_before && g_cs->rs.round == round_before,
          "another height is dropped (:1056)"); OK();

    /* An older round is dropped. */
    g_cs->rs.round = 3;
    CHECK(cmt_cs_enter_new_round(g_cs, 1, 1) == CMT_OK &&
          g_cs->rs.round == 3,
          "an older round is dropped (:1056)"); OK();

    /* The same round with a step past NewHeight is dropped. */
    g_cs->rs.step = CMT_ROUND_STEP_PROPOSE;
    CHECK(cmt_cs_enter_new_round(g_cs, 1, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_PROPOSE,
          "the same round past NewHeight is dropped (:1056)"); OK();

    /* ── :1143 enterPropose — `RoundStepPropose <= cs.Step`. */
    CHECK(cmt_cs_enter_propose(g_cs, 1, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_PROPOSE,
          "enterPropose at Propose is dropped (:1143)"); OK();

    /* ── :1322 enterPrevote — `RoundStepPrevote <= cs.Step`. */
    g_cs->rs.step = CMT_ROUND_STEP_PREVOTE;
    CHECK(cmt_cs_enter_prevote(g_cs, 1, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_PREVOTE,
          "enterPrevote at Prevote is dropped (:1322)"); OK();

    /* ── :1409 enterPrevoteWait. Entered at or past PrevoteWait so the
     * guard answers first; below it the +2/3 check at :1418 would FAULT,
     * which is a different assertion and belongs to wave T. */
    g_cs->rs.step = CMT_ROUND_STEP_PREVOTE_WAIT;
    CHECK(cmt_cs_enter_prevote_wait(g_cs, 1, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_PREVOTE_WAIT,
          "enterPrevoteWait at PrevoteWait is dropped (:1409)"); OK();

    /* ── :1445 enterPrecommit — `RoundStepPrecommit <= cs.Step`. */
    g_cs->rs.step = CMT_ROUND_STEP_PRECOMMIT;
    CHECK(cmt_cs_enter_precommit(g_cs, 1, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_PRECOMMIT,
          "enterPrecommit at Precommit is dropped (:1445)"); OK();

    /* ── :1567 enterPrecommitWait. Its third term is the FLAG, not a step
     * comparison. Proved by dropping at a step WELL BELOW PrecommitWait:
     * a step-based guard would let this through. */
    g_cs->rs.step                       = CMT_ROUND_STEP_PREVOTE;
    g_cs->rs.triggered_timeout_precommit = true;
    CHECK(cmt_cs_enter_precommit_wait(g_cs, 1, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_PREVOTE,
          "enterPrecommitWait is dropped by the FLAG at a step below "
          "PrecommitWait (:1567)"); OK();
    g_cs->rs.triggered_timeout_precommit = false;

    /* ── :1599 enterCommit at or past Commit is dropped. */
    g_cs->rs.step = CMT_ROUND_STEP_COMMIT;
    CHECK(cmt_cs_enter_commit(g_cs, 1, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_COMMIT,
          "enterCommit at Commit is dropped (:1599)"); OK();

    /* And a WRONG HEIGHT is dropped even at a lower step. */
    g_cs->rs.step = CMT_ROUND_STEP_PREVOTE;
    CHECK(cmt_cs_enter_commit(g_cs, 2, 3) == CMT_OK &&
          g_cs->rs.step == CMT_ROUND_STEP_PREVOTE,
          "enterCommit at another height is dropped (:1599)"); OK();

    cmt_cs_free(g_cs);

    /* ── :1599 again, the asymmetry that matters: enterCommit has NO
     * ROUND TERM. A commit round BELOW cs.Round must NOT be dropped — it
     * must reach the majority check at :1621, which with no precommits at
     * all is the panic at :1623, CMT_FAULT here. If someone ever adds
     * `round < cs.Round` to this guard, the call would be dropped and
     * this assertion turns red. */
    CHECK(fresh_cs() == 0, "construct again"); OK();
    g_cs->rs.round = 5;
    g_cs->rs.step  = CMT_ROUND_STEP_PREVOTE;
    CHECK(cmt_cs_enter_commit(g_cs, 1, 2) == CMT_FAULT,
          "enterCommit with a LOWER commit round is not dropped — there is "
          "no round term (:1599), so it reaches :1623"); OK();
    cmt_cs_free(g_cs);
    return 0;
}

/* ══ 4. the timeout acceptance rule — state.go:970 ════════════════════ */

static int t_timeout_acceptance(void)
{
    cmt_timeout_info_t ti;
    cmt_round_state_t  rs;

    CHECK(fresh_cs() == 0, "construct"); OK();

    /* Walk to round 0 / Propose so there is a step to be behind. */
    ti.duration = 0;
    ti.height   = 1;
    ti.round    = 0;
    ti.step     = CMT_ROUND_STEP_NEW_HEIGHT;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &g_cs->rs) == CMT_OK, "walk");
    OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PROPOSE, "at Propose"); OK();

    CHECK(cmt_cs_get_round_state(g_cs, &rs) == CMT_OK, "snapshot"); OK();

    /* (a) a DIFFERENT HEIGHT is dropped, in both directions. */
    ti.height = 2;
    ti.round  = 0;
    ti.step   = CMT_ROUND_STEP_PROPOSE;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &rs) == CMT_OK, "higher height");
    OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PROPOSE,
          "a timeout for a later height changes nothing"); OK();
    ti.height = 0;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &rs) == CMT_OK, "lower height");
    OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PROPOSE,
          "nor one for an earlier height"); OK();

    /* (b) an EARLIER ROUND at this height is dropped. */
    ti.height = 1;
    ti.round  = -1;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &rs) == CMT_OK, "earlier round");
    OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PROPOSE,
          "a timeout from a round we have left changes nothing"); OK();

    /* (c) an EARLIER STEP of THIS round is dropped — this is the half of
     * :970 that a height-and-round check alone would miss. */
    ti.round = 0;
    ti.step  = CMT_ROUND_STEP_NEW_ROUND;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &rs) == CMT_OK, "earlier step");
    OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PROPOSE,
          "a NewRound tock while we are at Propose changes nothing"); OK();

    /* (d) the SAME step is ACCEPTED — `<` is strict at :970. */
    ti.step = CMT_ROUND_STEP_PROPOSE;
    CHECK(cmt_cs_handle_timeout(g_cs, &ti, &rs) == CMT_OK, "same step"); OK();
    CHECK(g_cs->rs.step == CMT_ROUND_STEP_PREVOTE,
          "a tock for the step we are on is acted on"); OK();

    cmt_cs_free(g_cs);
    return 0;
}

/* ══ 5. the internal queue: FIFO, and overflow stops — :45, :568-579 ══ */

static int t_internal_queue(void)
{
    cmt_vote_t *v;
    size_t      i;
    bool        worked;

    CHECK(fresh_cs() == 0, "construct"); OK();

    v = (cmt_vote_t *)calloc(1u, sizeof(*v));
    CHECK(v != NULL, "vote fixture"); OK();

    /* Every vote carries a height the state machine ignores at :2172, so
     * nothing here touches a validator set or a signature; `round` is
     * only a tag, read back out of the WAL. */
    for (i = 0; i < (size_t)CMT_CS_MSG_QUEUE_SIZE; i++) {
        memset(v, 0, sizeof(*v));
        v->type   = CMT_PB_MSG_TYPE_PREVOTE;
        v->height = g_cs->rs.height + 5;
        v->round  = (int32_t)i;
        CHECK(cmt_cs_add_vote(g_cs, v, NULL, 0u) == CMT_OK,
              "an own vote is queued");
    }
    OK();
    CHECK(g_cs->internal_q_len == (size_t)CMT_CS_MSG_QUEUE_SIZE,
          "the queue is exactly msgQueueSize deep (state.go:45)"); OK();

    /* :571-578 — the reference spawns a goroutine here and its own
     * comment says that reorders our votes. This port stops instead. */
    memset(v, 0, sizeof(*v));
    v->type   = CMT_PB_MSG_TYPE_PREVOTE;
    v->height = g_cs->rs.height + 5;
    v->round  = 4242;
    CHECK(cmt_cs_add_vote(g_cs, v, NULL, 0u) == CMT_FAULT,
          "the 1001st own message STOPS the node instead of reordering");
    OK();

    /* Drain, and read the handling order back out of the WAL. */
    for (i = 0; i < (size_t)CMT_CS_MSG_QUEUE_SIZE; i++) {
        worked = false;
        CHECK(cmt_cs_step(g_cs, &worked) == CMT_OK, "step");
        CHECK(worked, "each step handled one message");
    }
    OK();
    CHECK(g_cs->internal_q_len == 0u, "the queue drained"); OK();
    CHECK(g_sync_len == (size_t)CMT_CS_MSG_QUEUE_SIZE,
          "every own message went through WriteSync (:839)"); OK();
    for (i = 0; i < g_sync_len; i++) {
        CHECK(g_sync_rounds[i] == (int32_t)i,
              "own messages are handled in the order they were produced");
    }
    OK();

    worked = true;
    CHECK(cmt_cs_step(g_cs, &worked) == CMT_OK, "an empty step"); OK();
    CHECK(!worked, "and it reports that it did nothing"); OK();
    CHECK(!cmt_cs_has_work(g_cs), "no work is pending"); OK();

    free(v);
    cmt_cs_free(g_cs);
    return 0;
}

/* ══ 6. the block-slot discipline — cmt_cs.h "OWNERSHIP" (1) ══════════ */

static int t_part_set_slots(void)
{
    cmt_proposal_t *p;
    cmt_part_set_t  before0;
    cmt_part_set_t  before1;

    CHECK(fresh_cs() == 0, "construct"); OK();

    /* Name slots 0 and 1 through the locked and valid names, and leave
     * slot 2 free. Go would keep whatever is named alive; here the rule
     * is that a slot is rewritten only while NO name points at it. */
    g_cs->rs.locked_block_parts = &g_slots->part_sets[0];
    g_cs->rs.valid_block_parts  = &g_slots->part_sets[1];
    memset(&g_slots->part_sets[0], 0xA5, sizeof(g_slots->part_sets[0]));
    memset(&g_slots->part_sets[1], 0x5A, sizeof(g_slots->part_sets[1]));
    before0 = g_slots->part_sets[0];
    before1 = g_slots->part_sets[1];

    /* defaultSetProposal builds a part set from the proposal's header
     * (:1944-1945) when it does not already have one. The proposal is
     * refused before that — this node has no proposer key to verify
     * against a real signature — so drive the allocation through the
     * state machine's own path instead: clear the name and let
     * enterPrevote's neighbours run. The reachable allocation here is
     * :1945, so a proposal that gets that far is what is needed; with no
     * signature it does not, and the assertion below is therefore made
     * on the allocator's OBSERVABLE contract: whichever path allocates,
     * it must land in the one unnamed slot. */
    g_cs->rs.proposal_block_parts = NULL;

    p = (cmt_proposal_t *)calloc(1u, sizeof(*p));
    CHECK(p != NULL, "proposal fixture"); OK();
    p->height    = g_cs->rs.height;
    p->round     = g_cs->rs.round;
    p->pol_round = -1;
    p->block_id.hash_len                 = (size_t)CMT_TMHASH_SIZE;
    p->block_id.part_set_header.total    = 1u;
    p->block_id.part_set_header.hash_len = (size_t)CMT_TMHASH_SIZE;
    p->signature_len                     = 0u;

    /* An unsigned proposal is refused at :1927 — which is itself worth
     * pinning: a proposal with no signature never installs anything. */
    CHECK(cmt_cs_default_set_proposal(g_cs, p) == CMT_REJECT,
          "an unsigned proposal is refused (:1927)"); OK();
    CHECK(g_cs->rs.proposal == NULL && g_cs->rs.proposal_block_parts == NULL,
          "and installs neither the proposal nor a part set"); OK();

    /* The two named slots were not touched by the refused proposal. */
    CHECK(memcmp(&before0, &g_slots->part_sets[0], sizeof(before0)) == 0,
          "the slot the locked name points at is untouched"); OK();
    CHECK(memcmp(&before1, &g_slots->part_sets[1], sizeof(before1)) == 0,
          "and so is the valid name's"); OK();

    /* Now prove the positive half of the rule through the path that DOES
     * allocate without a signature: enterCommit's :1647 and
     * enterPrecommit's :1553 both need a majority, so the reachable one
     * here is the state machine's own reset. Drive it by hand through the
     * public surface: updateToState clears all three names (:736, :739,
     * :742), after which the next allocation may use any slot. */
    CHECK(cmt_cs_update_to_state(g_cs, g_genesis) == CMT_OK,
          "updateToState with an unchanged state signals the step"); OK();

    /* :676-684 — the state is not further out than ours, so it took the
     * ignore path and only called newStep; the names are unchanged. */
    CHECK(g_cs->rs.locked_block_parts == &g_slots->part_sets[0],
          "the ignore path (:682) leaves the round state alone"); OK();
    CHECK(g_cs->rs.valid_block_parts == &g_slots->part_sets[1],
          "both names survive it"); OK();
    CHECK(memcmp(&before0, &g_slots->part_sets[0], sizeof(before0)) == 0 &&
          memcmp(&before1, &g_slots->part_sets[1], sizeof(before1)) == 0,
          "and neither named slot's CONTENTS were rewritten"); OK();

    /* ⚠ WHAT THIS TEST DOES NOT REACH, stated here as well as in the file
     * header: no assertion above exercises `cs_new_part_set_from_header`,
     * because every path that allocates a part set needs either a valid
     * proposal signature (:1945) or a +2/3 majority (:1553, :1647, :2299),
     * and a host-free test can produce neither. The free-slot SELECTION
     * is therefore unproven here; it belongs to wave T. */

    free(p);
    cmt_cs_free(g_cs);
    return 0;
}

/* ══ 7. proposer selection wiring — state.go:1071-1084 ════════════════ */

static int t_proposer_wiring(void)
{
    cmt_validator_t proposer0;
    cmt_validator_t proposer1;
    /* Only the priorities are compared, so only the priorities are kept.
     * An array of whole validators would be ~10.6 KB on the stack — each
     * carries a 2592-byte public key (cmt_pb.h's CMT_PB_PUBKEY_LEN) — and
     * this file's own header promises nothing multi-kilobyte lives there. */
    int64_t         prio_before[NVALS];
    size_t          i;

    CHECK(fresh_cs() == 0, "construct"); OK();

    CHECK(g_cs->rs.validators == &g_cs->state.validators,
          "at a new height the round state names the state's own set (:733)");
    OK();
    CHECK(cmt_validator_set_get_proposer(g_cs->rs.validators,
                                         &proposer0) == CMT_OK,
          "round 0 has a proposer (:1084)"); OK();
    for (i = 0; i < (size_t)NVALS; i++) {
        prio_before[i] =
                g_cs->state.validators.validators[i].proposer_priority;
    }

    /* enterNewRound(1, 1) from round 0 takes the :1072 branch:
     * validators.Copy() then IncrementProposerPriority(1). */
    CHECK(cmt_cs_enter_new_round(g_cs, 1, 1) == CMT_OK,
          "entering round 1"); OK();
    CHECK(g_cs->rs.round == 1, "we are in round 1"); OK();
    CHECK(g_cs->rs.validators != &g_cs->state.validators,
          "and the round state now names a COPY, not the state's set (:1073)");
    OK();
    for (i = 0; i < (size_t)NVALS; i++) {
        CHECK(g_cs->state.validators.validators[i].proposer_priority ==
              prio_before[i],
              "the state's own priorities were not mutated");
    }
    OK();

    CHECK(cmt_validator_set_get_proposer(g_cs->rs.validators,
                                         &proposer1) == CMT_OK,
          "round 1 has a proposer"); OK();
    CHECK(proposer1.address_len == (size_t)CMT_ADDRESS_SIZE &&
          proposer0.address_len == (size_t)CMT_ADDRESS_SIZE,
          "both proposers carry a 32-byte address"); OK();

    /* The increment ran on the COPY: at least one priority in the round
     * state's set now differs from the state's own. Which validator the
     * arithmetic elects at round 1 is NOT asserted — with powers
     * 10/20/30/40 the reference's own priority algebra decides that, and
     * this test has not computed it, so claiming it would be a guess. */
    {
        bool   moved = false;
        size_t j;

        for (j = 0; j < (size_t)NVALS; j++) {
            if (g_cs->rs.validators->validators[j].proposer_priority !=
                prio_before[j]) {
                moved = true;
            }
        }
        CHECK(moved,
              "IncrementProposerPriority mutated the copy, not the state");
        OK();
    }

    cmt_cs_free(g_cs);
    return 0;
}

/* ══ 8. voteTime's clamp — state.go:2416-2435 ═════════════════════════ */

static int t_vote_time(void)
{
    cmt_block_t *proposal_block;
    cmt_block_t *locked_block;
    cmt_time_t   out;
    int          calls_before;

    CHECK(fresh_cs() == 0, "construct"); OK();

    proposal_block = &g_slots->blocks[0];
    locked_block   = &g_slots->blocks[1];
    memset(proposal_block, 0, sizeof(*proposal_block));
    memset(locked_block, 0, sizeof(*locked_block));

    /* (a) no block at all: voteTime is the clock, unclamped (:2418). */
    g_now.seconds = 5000;
    g_now.nanos   = 0;
    calls_before  = g_now_calls;
    CHECK(cmt_cs_vote_time(g_cs, &out) == CMT_OK, "voteTime, no block"); OK();
    CHECK(g_now_calls == calls_before + 1,
          "and it read the clock exactly once, through the callback"); OK();
    CHECK(out.seconds == 5000 && out.nanos == 0,
          "with no block the stamp is simply now"); OK();

    /* (b) a PROPOSAL block later than the clock clamps to blockTime+1ms
     * (:2427-2428) — this is the case that keeps block times strictly
     * increasing under BFT-time. */
    proposal_block->header.time.seconds = 6000;
    proposal_block->header.time.nanos   = 0;
    g_cs->rs.proposal_block             = proposal_block;
    CHECK(cmt_cs_vote_time(g_cs, &out) == CMT_OK, "voteTime, proposal"); OK();
    CHECK(out.seconds == 6000 && out.nanos == 1000000,
          "the stamp is the proposal block's time plus one millisecond");
    OK();

    /* (c) the clock ahead of the block: the clock wins (:2431-2432). */
    g_now.seconds = 7000;
    CHECK(cmt_cs_vote_time(g_cs, &out) == CMT_OK, "voteTime, clock ahead");
    OK();
    CHECK(out.seconds == 7000 && out.nanos == 0,
          "a clock later than blockTime+1ms is used as it is"); OK();

    /* (d) a LOCKED block takes precedence over the proposal block
     * (:2423 before :2427), even when the proposal block is later. */
    locked_block->header.time.seconds   = 9000;
    locked_block->header.time.nanos     = 0;
    proposal_block->header.time.seconds = 9500;
    g_cs->rs.locked_block               = locked_block;
    CHECK(cmt_cs_vote_time(g_cs, &out) == CMT_OK, "voteTime, locked"); OK();
    CHECK(out.seconds == 9000 && out.nanos == 1000000,
          "the LOCKED block's time is the floor, not the proposal's"); OK();

    /* (e) the nanosecond carry: 999_999_999 + 1ms crosses the second. */
    locked_block->header.time.seconds = 9000;
    locked_block->header.time.nanos   = 999999999;
    CHECK(cmt_cs_vote_time(g_cs, &out) == CMT_OK, "voteTime, carry"); OK();
    CHECK(out.seconds == 9001 && out.nanos == 999999,
          "adding a millisecond carries into the next second"); OK();

    g_cs->rs.locked_block   = NULL;
    g_cs->rs.proposal_block = NULL;
    cmt_cs_free(g_cs);
    return 0;
}

/* ══ 9. the END_HEIGHT rule — replay.go:100-137 ═══════════════════════ */

static int t_replay_end_height_rule(void)
{
    CHECK(fresh_cs() == 0, "construct"); OK();

    /* At the initial height the marker looked for is 0 (:126-128), and
     * the fixture says END_HEIGHT(0) exists and END_HEIGHT(1) does not. */
    g_end_height_present = 0;
    g_replay_eof         = true;
    CHECK(cmt_cs_catchup_replay(g_cs, 1) == CMT_OK,
          "replaying height 1 needs END_HEIGHT(0) and no END_HEIGHT(1)");
    OK();
    CHECK(!g_cs->replay_mode, "and replay mode is cleared afterwards (:98)");
    OK();

    /* :106-117 — a record for the height being replayed must NOT exist. */
    g_end_height_present = 1;
    CHECK(cmt_cs_catchup_replay(g_cs, 1) == CMT_REJECT,
          "an END_HEIGHT for the height being replayed is refused (:116)");
    OK();
    CHECK(!g_cs->replay_mode, "replay mode is cleared on that path too");
    OK();

    /* :135-137 — a record for the height below MUST exist. */
    g_end_height_present = -1;
    CHECK(cmt_cs_catchup_replay(g_cs, 1) == CMT_REJECT,
          "a missing END_HEIGHT below is refused (:136)"); OK();

    /* :122-124 — below the initial height there is nothing to replay.
     * The fixture must report NO END_HEIGHT at all here: with
     * END_HEIGHT(0) present, the FIRST search (:106) would find a marker
     * for the height being replayed and reject at :116 instead, and this
     * assertion would be green for the wrong reason. */
    g_end_height_present = -1;
    CHECK(cmt_cs_catchup_replay(g_cs, 0) == CMT_REJECT,
          "a height below the initial height is refused (:123)"); OK();

    cmt_cs_free(g_cs);
    return 0;
}

/* ══ main ═════════════════════════════════════════════════════════════ */

int main(void)
{
    size_t i;
    int    rc = 0;

    for (i = 0; i < (size_t)NVALS; i++) {
        uint8_t seed[32];

        memset(seed, 0, sizeof(seed));
        seed[0] = (uint8_t)(i & 0xFFu);
        seed[1] = 0xC5u;
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0) {
            fprintf(stderr, "keypair %zu failed\n", i);
            return 1;
        }
    }

    g_scratch      = (cmt_valset_scratch_t *)calloc(1u, sizeof(*g_scratch));
    g_stor_gen     = (cmt_state_storage_t *)calloc(1u, sizeof(*g_stor_gen));
    g_stor_cs      = (cmt_state_storage_t *)calloc(1u, sizeof(*g_stor_cs));
    g_stor_scratch = (cmt_state_storage_t *)calloc(1u, sizeof(*g_stor_scratch));
    g_genesis      = (cmt_state_t *)calloc(1u, sizeof(*g_genesis));
    g_cs           = (cmt_cs_t *)calloc(1u, sizeof(*g_cs));
    g_sync_rounds  = (int32_t *)calloc((size_t)SYNC_MAX, sizeof(int32_t));
    if (g_scratch == NULL || g_stor_gen == NULL || g_stor_cs == NULL ||
        g_stor_scratch == NULL || g_genesis == NULL || g_cs == NULL ||
        g_sync_rounds == NULL) {
        fprintf(stderr, "fixtures failed\n");
        return 1;
    }
    if (build_slots() != 0) {
        fprintf(stderr, "slots failed\n");
        return 1;
    }
    if (build_genesis() != 0) {
        fprintf(stderr, "MakeGenesisState failed\n");
        return 1;
    }

    if (t_compare_hrs() != 0)            { rc = 1; }
    if (rc == 0 && t_config_durations() != 0)        { rc = 1; }
    if (rc == 0 && t_round_step_walk() != 0)         { rc = 1; }
    if (rc == 0 && t_entry_guards() != 0)            { rc = 1; }
    if (rc == 0 && t_timeout_acceptance() != 0)      { rc = 1; }
    if (rc == 0 && t_internal_queue() != 0)          { rc = 1; }
    if (rc == 0 && t_part_set_slots() != 0)          { rc = 1; }
    if (rc == 0 && t_proposer_wiring() != 0)         { rc = 1; }
    if (rc == 0 && t_vote_time() != 0)               { rc = 1; }
    if (rc == 0 && t_replay_end_height_rule() != 0)  { rc = 1; }

    free_slots();
    free(g_sync_rounds);
    free(g_cs);
    free(g_genesis);
    free(g_stor_scratch);
    free(g_stor_cs);
    free(g_stor_gen);
    free(g_scratch);

    if (rc != 0) {
        return 1;
    }
    printf("test_cmt_cs_unit: %d checks passed\n", g_checks);
    return 0;
}
