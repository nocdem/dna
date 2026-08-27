/**
 * @file nodus/tests/test_v2_gate.c
 * @brief O15B — the activation gate, ingress reachability, and the network
 *        result algebra.
 *
 * ── WHAT THIS TEST IS FOR ─────────────────────────────────────────────
 * The claim that makes the Ledger V2 network surface safe is narrow and
 * checkable:
 *
 *   1. The gate stays SHUT on a database that is not a Ledger V2 chain,
 *      and no input reaches it that could change that.
 *   2. Ingress is unreachable unless the gate opened.
 *   3. A V2 frame on an unarmed node produces NOT_ACTIVE with no peer
 *      judgement, no acknowledgement, no queue entry and no state change.
 *   4. NOT_ACTIVE, INTERNAL_FAULT and NOT_YET_LINKABLE never blame a peer.
 *
 * Each is asserted against the real production entry points, and the
 * "no state change" half is proven by a whole-database digest across the
 * call rather than by inspection.
 *
 * ⚠ WHAT NO_AUTHORITY MEANS SINCE O15J Faz 3 ──────────────────────────
 * The activation ceremony is GONE, and with it the reading of
 * NO_AUTHORITY this file was written under ("this binary has no
 * activation authority compiled in"). Authority is now a property of the
 * DATABASE: a chain whose committed height-0 genesis manifest carries the
 * pure-V2 source tag IS its own authority, and such a chain opens the
 * gate in an ORDINARY build.
 *
 * Every fixture here is a bare `nodus_witness_create_chain_db` database —
 * NOT a pure-V2 chain — so every "the gate is shut" assertion below still
 * holds, but it now means "this database is not a V2 chain", not "this
 * software cannot activate V2 at all".
 *
 * The other half of the contract — that a REAL pure-V2 chain DOES open
 * the gate and DOES arm, in a build carrying no authority macro at all —
 * is `test_v2_gate_pure.c`. It must never be merged into this file: this
 * target compiles the synthetic-authority fixture in, and a test that can
 * grant itself authority cannot prove authority is derived.
 *
 * ── ON THE TEST-ONLY AUTHORITY FIXTURE ────────────────────────────────
 * `nodus_witness_v2_gate_test_arm()` exists only under
 * NODUS_V2_TEST_AUTHORITY, which CMake defines on test targets that
 * compile the gate TU in, and on no library or server target.
 * `test_v2_gate_linked` proves its absence from the shipped binaries with
 * `nm`. Using it here is what lets the ARMED paths be exercised on a
 * database that could never open the gate on its own merits.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_ingress.h"
#include "witness/nodus_witness_v2_sync2.h"
#include "witness/nodus_witness_v2_preflight.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_result.h"
#include "dnac/blockmsg_v2.h"
#include "v2_genesis_fixture.h"   /* the shipped whole-DB digest oracle */

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)

typedef struct {
    char             dir[256];
    nodus_witness_t *w;
} fx_t;

static int fx_open(fx_t *f, const char *tag) {
    snprintf(f->dir, sizeof(f->dir), "/tmp/test_v2_gate_%s_XXXXXX", tag);
    if (!mkdtemp(f->dir)) return -1;
    f->w = calloc(1, sizeof(*f->w));    /* multi-MB — never on the stack */
    if (!f->w) return -1;
    snprintf(f->w->data_path, sizeof(f->w->data_path), "%s", f->dir);
    uint8_t chain_id16[16];
    memset(chain_id16, 0x3c, sizeof(chain_id16));
    if (nodus_witness_create_chain_db(f->w, chain_id16) != 0) return -1;
    return 0;
}

static void fx_close(fx_t *f) {
    if (f->w) {
        nodus_witness_v2_ingress_queue_clear(f->w);
        if (f->w->db) sqlite3_close(f->w->db);
        free(f->w);
        f->w = NULL;
    }
}

/* Whole-database digest.
 *
 * Uses the SHIPPED oracle `v2x_db_digest` (v2_genesis_fixture.h), which
 * hashes every user table's rows ORDERED, column by column, with storage
 * types, plus `sqlite_sequence`.
 *
 * An earlier version of this file rolled its own and was WRONG in a way
 * that mattered: it built `SELECT quote(*) FROM (SELECT * FROM "t")`, but
 * `quote()` takes exactly one argument and `*` is legal only for
 * `count()`. Every prepare failed, control always fell to the `COUNT(*)`
 * fallback, and the "whole-DB digest" was really a table-name-and-row-count
 * digest — blind to any in-place UPDATE. A NOT_ACTIVE path that bumped a
 * counter or stamped a column would have passed the side-effect assertion.
 * Review R3 caught it; the correct oracle already existed in this tree and
 * simply was not used. */
static unsigned long long db_digest(nodus_witness_t *w) {
    uint8_t d[64];
    if (v2x_db_digest(w, d) != 0) return 0;
    unsigned long long h = 1469598103934665603ULL;   /* FNV-1a offset */
    for (int i = 0; i < 64; i++) { h ^= d[i]; h *= 1099511628211ULL; }
    return h;
}

/* A structurally valid BlockMessage v1 whose CONTENT is meaningless.
 *
 * That is exactly right for these tests: every assertion here is about
 * what happens BEFORE content matters. A frame that decodes proves the
 * refusal came from the gate and not from the codec — a malformed frame
 * would be rejected either way and would prove nothing. */
static size_t make_frame(uint8_t *buf, size_t cap) {
    static uint8_t header[DNA_BH2_ENC_SIZE];
    static uint8_t qc[DNA_QC_V2_HDR_LEN];
    memset(header, 0, sizeof(header));
    header[0] = 3;                       /* header_version v3            */
    memset(qc, 0, sizeof(qc));           /* n_certs = 0                  */

    dnac_blkmsg_v2_t m;
    memset(&m, 0, sizeof(m));
    m.msg_version  = DNA_BLKW_VERSION;
    m.body_version = DNA_BLKW_BODY_VERSION;
    m.header       = header;
    m.qc           = qc;
    m.qc_len       = (uint32_t)sizeof(qc);
    m.env_count    = 0;
    m.timestamp    = 1234;

    size_t n = 0;
    if (dnac_blkmsg_v2_encode(&m, buf, cap, &n) != DNAC_BLKW_OK) return 0;
    return n;
}

int main(void) {
    printf("=== O15B — activation gate, ingress reachability, result algebra ===\n");

    /* ── 1. THE GATE IS CLOSED, AND CLOSED FOR THE RIGHT REASON ────────
     * NO_AUTHORITY, not NOT_READY: the distinction is what tells an
     * operator "this database is not a Ledger V2 chain, so nothing here
     * could ever activate" apart from "this is a V2 chain but it is not
     * ready yet". This fixture is a bare chain database with no committed
     * genesis manifest, so the first is the correct answer. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "closed") == 0, "fixture open");
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_NO_AUTHORITY,
              "a database that is not a Ledger V2 chain must report "
              "NO_AUTHORITY");
        CHECK(nodus_witness_v2_activation_permitted(f.w) == 0,
              "activation must not be permitted");
        CHECK(strcmp(nodus_witness_v2_gate_state_name(
                         NODUS_V2_GATE_NO_AUTHORITY), "NO_AUTHORITY") == 0,
              "state name is stable");
        fx_close(&f);
    }

    /* ── 2. A NULL / DATABASE-LESS HANDLE IS A FAULT, NOT A STATE ──────
     * "We could not tell" must never be reported as "not ready": the two
     * call for different operator responses, and only one of them is a
     * bug. */
    {
        CHECK(nodus_witness_v2_gate_state(NULL) == NODUS_V2_GATE_FAULT,
              "NULL handle is a FAULT");
        CHECK(nodus_witness_v2_activation_permitted(NULL) == 0,
              "NULL handle never permits activation");
    }

    /* ── 3. THE PREFLIGHT IS NOT READY ON A FRESH DATABASE ─────────────
     * O15C: issue 12 is RETIRED (the V2 attendance writer exists in this
     * build), so the standing unconditional issue is gone — but a fresh
     * database is still blocked by real findings (schema, genesis), and
     * the retired id must never reappear. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "pf") == 0, "fixture open");
        nodus_v2_preflight_report_t rep;
        CHECK(nodus_witness_v2_preflight(f.w, &rep) == 0, "preflight ran");
        CHECK(rep.ready == 0, "a fresh database must not be ready");
        int saw_rule_n = 0;
        for (size_t i = 0; i < rep.n_issues; i++)
            if (rep.issues[i] == NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT)
                saw_rule_n = 1;
        CHECK(!saw_rule_n,
              "retired issue 12 must never be raised again");
        fx_close(&f);
    }

    /* ── 4. INGRESS CANNOT BE ARMED WHILE THE GATE IS SHUT ─────────────
     * And a refused arm leaves the node UNARMED — there is no partial
     * arming, so a failed attempt cannot leave a half-open door. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "arm") == 0, "fixture open");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 0,
              "a fresh node starts UNARMED");
        CHECK(nodus_witness_v2_ingress_arm(f.w) != 0,
              "arming must be refused while the gate is shut");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 0,
              "a refused arm leaves the node UNARMED");
        fx_close(&f);
    }

    /* ── 5. A V2 FRAME ON A PRODUCTION NODE: NOT_ACTIVE, AND NOTHING ELSE
     *
     * The whole dormancy claim, asserted at the real entry point. The
     * frame is well-formed on purpose (see make_frame): the refusal must
     * come from the gate, not from the codec.
     *
     * "No database mutation" is proven by a whole-DB digest across the
     * call, not by reading the code. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "notactive") == 0, "fixture open");

        uint8_t frame[4096];
        size_t flen = make_frame(frame, sizeof(frame));
        CHECK(flen > 0, "fixture frame encodes");

        unsigned long long before = db_digest(f.w);
        CHECK(before != 0, "the digest oracle produced a value (a 0 would "
                           "mean it failed, and two failures compare equal)");

        uint8_t peer[32];
        memset(peer, 0x77, sizeof(peer));
        nodus_v2_ingress_outcome_t oc;
        int rc = nodus_witness_v2_ingress_block(f.w, peer, frame, flen, &oc);

        CHECK(rc == NODUS_V2_NOT_ACTIVE, "result is NOT_ACTIVE");
        CHECK(oc.result == NODUS_V2_NOT_ACTIVE, "outcome carries NOT_ACTIVE");
        CHECK(oc.peer == NODUS_V2_PEER_NONE,
              "THE PEER MUST NOT BE BLAMED for our own inactivity");
        CHECK(oc.ack == 0, "nothing is acknowledged");
        CHECK(oc.queued == 0,
              "an inactive node must not spend memory queueing V2 traffic");
        CHECK(oc.want_catchup == 0, "an inactive node does not want catch-up");

        uint32_t qn = 99; uint64_t qb = 99;
        nodus_witness_v2_ingress_queue_stats(f.w, &qn, &qb);
        CHECK(qn == 0 && qb == 0, "the queue is empty");

        unsigned long long after = db_digest(f.w);
        CHECK(before == after,
              "NOT_ACTIVE MUST NOT TOUCH THE DATABASE (whole-DB digest)");
        fx_close(&f);
    }

    /* ── 6. NOT_ACTIVE IS NOT ANY OTHER CLASS ─────────────────────────
     * The classifiers are the contract every network caller routes on, so
     * the separations are pinned by value rather than trusted. */
    {
        CHECK(NODUS_V2_NOT_ACTIVE == -6, "NOT_ACTIVE has its pinned value");
        CHECK(!nodus_v2_result_is_accepted(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE is not an acceptance");
        CHECK(!nodus_v2_result_is_verdict(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE IS NOT A VERDICT");
        CHECK(!nodus_v2_result_is_undecided(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE is not 'tried and could not decide'");
        CHECK(nodus_v2_result_is_not_active(NODUS_V2_NOT_ACTIVE),
              "NOT_ACTIVE has its own predicate");
        /* The values O15A pinned must not have moved. */
        CHECK(NODUS_V2_ACCEPTED == 0 && NODUS_V2_IDEMPOTENT_REPLAY == 1 &&
              NODUS_V2_ACCEPTED_PRECACHE == 2 &&
              NODUS_V2_CONSENSUS_INVALID == -1 &&
              NODUS_V2_INTERNAL_FAULT == -2 &&
              NODUS_V2_NOT_YET_LINKABLE == -3 &&
              NODUS_V2_RETIRED_VERSION == -4 &&
              NODUS_V2_UNSUPPORTED_VERSION == -5,
              "the O15A result values are UNMOVED");
    }

    /* ── 7. WHO MAY BE BLAMED — the single peer-policy predicate ───────
     * The three "never blame" rows of the ingress table are the point of
     * the whole algebra, so they are asserted directly. */
    {
        CHECK(nodus_v2_result_blames_peer(NODUS_V2_CONSENSUS_INVALID),
              "a deterministic verdict may be held against a peer");
        CHECK(nodus_v2_result_blames_peer(NODUS_V2_RETIRED_VERSION),
              "a retired version is a verdict");
        CHECK(nodus_v2_result_blames_peer(NODUS_V2_UNSUPPORTED_VERSION),
              "an unsupported version is a verdict");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_NOT_YET_LINKABLE),
              "A PEER IS NEVER BLAMED FOR OUR OWN LAG");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_INTERNAL_FAULT),
              "A PEER IS NEVER BLAMED FOR OUR OWN FAULT");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_NOT_ACTIVE),
              "A PEER IS NEVER BLAMED FOR OUR OWN INACTIVITY");
        CHECK(!nodus_v2_result_blames_peer(NODUS_V2_ACCEPTED),
              "an accepted block blames nobody");
    }

    /* ── 8. SYNC AND RESTART ARE GATED TOO ─────────────────────────────
     * §12 requires that no production path advertises, accepts, syncs or
     * replays while the gate is shut — not merely the live-block path. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "sync") == 0, "fixture open");

        nodus_v2_head_hint_t hint;
        memset(&hint, 0, sizeof(hint));
        hint.protocol_version = DNA_BLKW_VERSION;
        hint.head_height      = 1000;

        uint64_t from = 0; uint32_t cnt = 0;
        CHECK(nodus_witness_v2_sync_plan_range(f.w, &hint, &from, &cnt)
                  == NODUS_V2_NOT_ACTIVE,
              "range planning is gated");
        CHECK(cnt == 0, "a gated plan requests nothing");

        nodus_v2_sync_range_result_t rr;
        const uint8_t *frames[1] = { NULL };
        const size_t   lens[1]   = { 0 };
        CHECK(nodus_witness_v2_sync_apply_range(f.w, NULL, frames, lens, 1, &rr)
                  == NODUS_V2_NOT_ACTIVE,
              "range application is gated");
        CHECK(rr.applied == 0 && rr.duplicates == 0,
              "a gated range applies nothing");

        CHECK(nodus_witness_v2_sync_restart_check(f.w, NULL)
                  == NODUS_V2_NOT_ACTIVE,
              "the restart check is gated");
        fx_close(&f);
    }

    /* ── 9. AN INCOMPATIBLE PEER IS NEVER WORTH SYNCING FROM ───────────
     * Compatibility is established before any block is exchanged, and an
     * inability to establish it is NOT compatibility. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "peer") == 0, "fixture open");
        nodus_v2_head_hint_t hint;
        memset(&hint, 0, sizeof(hint));

        CHECK(nodus_witness_v2_sync_peer_compatible(f.w, NULL) == 0,
              "a NULL hint is not compatible");
        hint.protocol_version = DNA_BLKW_VERSION + 1u;
        CHECK(nodus_witness_v2_sync_peer_compatible(f.w, &hint) == 0,
              "an unimplemented protocol version is not compatible");
        hint.protocol_version = DNA_BLKW_VERSION;
        memset(hint.genesis_block_id, 0xab, sizeof(hint.genesis_block_id));
        memset(hint.chain_id, 0xcd, sizeof(hint.chain_id));
        CHECK(nodus_witness_v2_sync_peer_compatible(f.w, &hint) == 0,
              "a hint whose chain_id does not derive from its genesis id "
              "is not compatible");
        fx_close(&f);
    }

#ifdef NODUS_V2_TEST_AUTHORITY
    /* ── 10. THE ARMED PATH ON A DATABASE THAT COULD NEVER OPEN ────────
     *
     * This fixture is NOT a Ledger V2 chain, so the only way it reaches
     * the armed ingress/queue/sync code is the synthetic fixture — and
     * without this section that code would ship unexercised on this
     * database shape, which is its own hazard. The fixture grants exactly
     * the authority half and nothing more, and the two halves of the gate
     * stay separately controllable so a test cannot silently conflate
     * them.
     *
     * A chain that opens the gate on its OWN committed authority is a
     * different test entirely (test_v2_gate_pure.c) — and it must stay
     * different, because it is only meaningful in a build where this
     * fixture does not exist.
     */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "armed") == 0, "fixture open");

        /* Authority alone is NOT enough — readiness is still evaluated for
         * real, and this bare fixture database has genuine blocking
         * findings (no V2 schema, no committed genesis). */
        nodus_witness_v2_gate_test_arm(f.w, 0);
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_NOT_READY,
              "authority WITHOUT readiness is NOT_READY, not OPEN");
        CHECK(nodus_witness_v2_ingress_arm(f.w) != 0,
              "authority alone must not permit arming");

        /* Both halves — the only configuration that can arm. */
        nodus_witness_v2_gate_test_arm(f.w, 1);
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_OPEN,
              "authority AND readiness is OPEN");
        CHECK(nodus_witness_v2_ingress_arm(f.w) == 0, "arming succeeds");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 1, "node is armed");

        /* ISSUE 13 IS NOW A REAL COMPUTED CHECK. With the readiness half
         * forced, the preflight sees an ARMED node whose authority is
         * synthetic — the state that must never occur — and says so.
         * O15A could not raise this at all; it argued from a structural
         * claim that O15B's own code retired. */
        nodus_witness_v2_gate_test_arm(f.w, 0);      /* readiness back on */
        nodus_v2_preflight_report_t rep;
        CHECK(nodus_witness_v2_preflight(f.w, &rep) == 0, "preflight ran");
        int saw_ingress = 0;
        for (size_t i = 0; i < rep.n_issues; i++)
            if (rep.issues[i] == NODUS_V2_PF_INGRESS_ENABLED) saw_ingress = 1;
        CHECK(saw_ingress,
              "ISSUE 13 MUST BE RAISED when ingress is armed and the gate "
              "is not open");
        CHECK(rep.ready == 0, "and the report is not ready");

        /* Disarm clears it — the check tracks the ACTUAL state, it is not
         * a latch that stays set once tripped. */
        nodus_witness_v2_ingress_disarm(f.w);
        CHECK(nodus_witness_v2_preflight(f.w, &rep) == 0, "preflight ran");
        saw_ingress = 0;
        for (size_t i = 0; i < rep.n_issues; i++)
            if (rep.issues[i] == NODUS_V2_PF_INGRESS_ENABLED) saw_ingress = 1;
        CHECK(!saw_ingress, "issue 13 clears when ingress is disarmed");

        nodus_witness_v2_gate_test_clear(f.w);
        CHECK(nodus_witness_v2_gate_state(f.w) == NODUS_V2_GATE_NO_AUTHORITY,
              "clearing the fixture restores the DERIVED state — and for "
              "this database that is NO_AUTHORITY, because it is not a "
              "Ledger V2 chain");
        CHECK(nodus_witness_v2_ingress_is_armed(f.w) == 0,
              "clearing the fixture disarms");
        fx_close(&f);
    }

    /* ── 11. AN ARMED NODE STILL REFUSES A MALFORMED FRAME, AND SAYS SO
     * WITHOUT CONFUSING IT WITH A CONSENSUS VERDICT.
     *
     * Also the proof that section 5's NOT_ACTIVE came from the GATE: the
     * same well-formed frame now gets past the gate and fails later, so
     * the two refusals are genuinely different code paths. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "malformed") == 0, "fixture open");
        nodus_witness_v2_gate_test_arm(f.w, 1);
        CHECK(nodus_witness_v2_ingress_arm(f.w) == 0, "armed");

        nodus_v2_ingress_outcome_t oc;

        /* Truncated. */
        uint8_t tiny[3] = { DNA_BLKW_VERSION, DNA_BLKW_BODY_VERSION, 0 };
        (void)nodus_witness_v2_ingress_block(f.w, NULL, tiny, sizeof(tiny), &oc);
        CHECK(oc.peer == NODUS_V2_PEER_MALFORMED,
              "a truncated frame is MALFORMED, not a consensus verdict");
        CHECK(oc.ack == 0 && oc.queued == 0, "and nothing is acked or queued");

        /* Over the LOCAL frame budget — refused BEFORE decode, and
         * WITHOUT judging the peer.
         *
         * NODUS_V2_ING_MAX_FRAME_BYTES is this node's resource policy, not
         * consensus: a node with a larger budget accepts the same block.
         * Reporting it as a verdict would let two honest nodes issue
         * different peer judgements for identical bytes — the same defect
         * class as blaming a peer for our own lag. Review R2 found the
         * original code doing exactly that. */
        static uint8_t big[NODUS_V2_ING_MAX_FRAME_BYTES + 16];
        memset(big, 0, sizeof(big));
        (void)nodus_witness_v2_ingress_block(f.w, NULL, big, sizeof(big), &oc);
        CHECK(oc.result == NODUS_V2_INTERNAL_FAULT,
              "an over-budget frame is OUR refusal, not a verdict");
        CHECK(oc.peer == NODUS_V2_PEER_NONE,
              "AN OVER-BUDGET FRAME MUST NOT BLAME THE PEER — the cap is "
              "local policy, not a property of the bytes");
        CHECK(oc.ack == 0 && oc.queued == 0,
              "and nothing is acked or queued");

        /* Trailing garbage after a valid message. */
        uint8_t frame[4096];
        size_t flen = make_frame(frame, sizeof(frame) - 1);
        CHECK(flen > 0, "fixture frame encodes");
        frame[flen] = 0xff;
        (void)nodus_witness_v2_ingress_block(f.w, NULL, frame, flen + 1, &oc);
        CHECK(oc.peer == NODUS_V2_PEER_MALFORMED,
              "TRAILING BYTES ARE REJECTED");
        CHECK(oc.codec_status != DNAC_BLKW_OK, "and the codec says why");

        nodus_witness_v2_gate_test_clear(f.w);
        fx_close(&f);
    }
#endif /* NODUS_V2_TEST_AUTHORITY */

#ifdef NODUS_V2_TEST_AUTHORITY
    /* ── 12. RESTART INTEGRITY — the armed path ───────────────────────
     *
     * Added because the §17 mutation campaign showed this code had NO
     * coverage at all: `restart_check` is gated, so every earlier section
     * stopped at NOT_ACTIVE and the whole scan — including the row-key and
     * parent-linkage checks review R2 asked for — was never executed by
     * any test. A defence nothing exercises is a defence nobody can trust.
     */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "restart") == 0, "fixture open");
        nodus_witness_v2_gate_test_arm(f.w, 1);

        /* The V2 tables must exist before a V2 integrity check means
         * anything. On a database WITHOUT them the check returns -2 ("could
         * not be performed"), which is the correct fail-closed answer and
         * is itself worth pinning: "we could not look" must never be
         * reported as "intact". */
        {
            uint64_t nb = 0;
            CHECK(nodus_witness_v2_sync_restart_check(f.w, &nb) == -2,
                  "a database with no v2_blocks reports COULD-NOT-PERFORM, "
                  "never 'intact'");
        }
        CHECK(nodus_witness_db_migrate_v2s9(f.w) == 0, "migrate to schema v9");

        /* A chain with no V2 blocks is INTACT, not broken — the check must
         * not invent corruption out of an empty table. */
        uint64_t bad = 999;
        CHECK(nodus_witness_v2_sync_restart_check(f.w, &bad) == 0,
              "an empty v2_blocks is intact");
        CHECK(bad == 0, "and reports no bad height");

        /* A row whose stored header is the wrong WIDTH is corrupt. This is
         * the first thing the scan checks, and it must stop rather than
         * skip — a skipped bad record is a silent acceptance. */
        {
            sqlite3_stmt *st = NULL;
            const char *sql =
                "INSERT INTO v2_blocks (global_height, block_id, "
                " prev_block_id, epoch, tx_root, domain_updates_root, "
                " domains_root, global_root, vset_hash, tx_count, header) "
                "VALUES (1, ?1, ?2, 0, ?2, ?2, ?2, ?2, ?2, 0, ?3)";
            if (sqlite3_prepare_v2(f.w->db, sql, -1, &st, NULL) == SQLITE_OK) {
                uint8_t id[64], zero[64], shorthdr[10];
                memset(id, 0x11, sizeof(id));
                memset(zero, 0, sizeof(zero));
                memset(shorthdr, 0, sizeof(shorthdr));
                sqlite3_bind_blob(st, 1, id, 64, SQLITE_STATIC);
                sqlite3_bind_blob(st, 2, zero, 64, SQLITE_STATIC);
                sqlite3_bind_blob(st, 3, shorthdr, (int)sizeof(shorthdr),
                                  SQLITE_STATIC);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                CHECK(rc == SQLITE_DONE, "planted a malformed v2_blocks row");
            } else {
                CHECK(0, "could not prepare the v2_blocks insert");
            }

            bad = 0;
            CHECK(nodus_witness_v2_sync_restart_check(f.w, &bad) == -1,
                  "A WRONG-WIDTH STORED HEADER IS CORRUPTION — the scan "
                  "stops rather than skipping the record");
            CHECK(bad == 1, "and names the first bad height");
        }

        /* A VALID, well-formed header filed under the WRONG ROW KEY.
         *
         * This case exists because the mutation campaign showed the
         * row-key check had no coverage: the wrong-WIDTH row above dies at
         * the width guard, so deleting `hdr.block_height != h` changed
         * nothing any test could see. Here the header is a real 413-byte
         * encode that decodes cleanly and reproduces its own BlockID — the
         * ONLY thing wrong is where it is stored. Review R2 asked for this
         * check; this is what makes it real. */
        {
            (void)sqlite3_exec(f.w->db, "DELETE FROM v2_blocks", NULL, NULL, NULL);

            dna_block_header_v2_t h;
            memset(&h, 0, sizeof(h));
            h.header_version = 3;
            h.block_height   = 7;          /* the header says 7 ...        */
            h.epoch          = 7 / DNAC_EPOCH_LENGTH;
            uint8_t enc[DNA_BH2_ENC_SIZE], hid[DNA_BH2_ID_LEN];
            CHECK(dna_bh2_encode(&h, enc) == 0, "encoded a valid v3 header");
            CHECK(dna_bh2_block_id(&h, hid) == 0, "derived its real BlockID");

            sqlite3_stmt *st = NULL;
            const char *sql =
                "INSERT INTO v2_blocks (global_height, block_id, "
                " prev_block_id, epoch, tx_root, domain_updates_root, "
                " domains_root, global_root, vset_hash, tx_count, header) "
                "VALUES (1, ?1, ?2, 0, ?2, ?2, ?2, ?2, ?2, 0, ?3)";
            if (sqlite3_prepare_v2(f.w->db, sql, -1, &st, NULL) == SQLITE_OK) {
                uint8_t zero[64];
                memset(zero, 0, sizeof(zero));
                sqlite3_bind_blob(st, 1, hid, DNA_BH2_ID_LEN, SQLITE_STATIC);
                sqlite3_bind_blob(st, 2, zero, 64, SQLITE_STATIC);
                sqlite3_bind_blob(st, 3, enc, (int)sizeof(enc), SQLITE_STATIC);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                CHECK(rc == SQLITE_DONE,
                      "planted a valid height-7 header under row key 1");
            } else {
                CHECK(0, "could not prepare the row-key-mismatch insert");
            }

            bad = 0;
            CHECK(nodus_witness_v2_sync_restart_check(f.w, &bad) == -1,
                  "A VALID HEADER FILED UNDER THE WRONG KEY IS CORRUPTION — "
                  "reproducing its own BlockID is not enough; where it is "
                  "stored is part of the claim");
            CHECK(bad == 1, "and names the offending row key");
        }

        nodus_witness_v2_gate_test_clear(f.w);
        fx_close(&f);
    }

    /* ── 13. THE WITNESS UTXO READ FAILS CLOSED ON A MALFORMED ROW ────
     *
     * Also added from the mutation campaign: nothing exercised the
     * negative-height guard, so a mutant that let a negative stored
     * `unlock_block` wrap to a huge u64 survived. A wrapped value reads as
     * "unlocked long ago", which is the WRONG direction — it is exactly
     * the coin consensus refuses. */
    {
        fx_t f = {0};
        CHECK(fx_open(&f, "utxoneg") == 0, "fixture open");

        static const char *OWNER =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        sqlite3_stmt *st = NULL;
        const char *sql =
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            " tx_hash, output_index, block_height, created_at, unlock_block) "
            /* -5, NOT -1.
             *
             * The mutation campaign killed an earlier version of this test
             * for being a tautology: with -1, the guard's UINT64_MAX and
             * the unguarded `(uint64_t)ub` produce the SAME value, so
             * deleting the guard changed nothing observable. -5 casts to
             * 0xFFFF...FB, which differs from UINT64_MAX — so the
             * assertion below can only pass if the guard actually ran. */
            "VALUES (?1, ?2, 100, ?3, ?4, 0, 1, 0, -5)";
        if (sqlite3_prepare_v2(f.w->db, sql, -1, &st, NULL) == SQLITE_OK) {
            uint8_t nf[64], tok[64], txh[64];
            memset(nf, 0x21, sizeof(nf));
            memset(tok, 0, sizeof(tok));
            memset(txh, 0x22, sizeof(txh));
            sqlite3_bind_blob(st, 1, nf, 64, SQLITE_STATIC);
            sqlite3_bind_text(st, 2, OWNER, -1, SQLITE_STATIC);
            sqlite3_bind_blob(st, 3, tok, 64, SQLITE_STATIC);
            sqlite3_bind_blob(st, 4, txh, 64, SQLITE_STATIC);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            CHECK(rc == SQLITE_DONE, "planted a NEGATIVE unlock_block row");

            nodus_witness_utxo_entry_t rows[4];
            int n = 0;
            CHECK(nodus_witness_utxo_by_owner(f.w, OWNER, rows, 4, &n) == 0,
                  "the query succeeds");
            CHECK(n == 1, "one row returned");
            CHECK(rows[0].unlock_block == UINT64_MAX,
                  "A NEGATIVE STORED HEIGHT READS AS LOCKED-FOREVER — it "
                  "must never wrap to a huge value that reads as spendable");
        } else {
            CHECK(0, "could not prepare the utxo_set insert");
        }
        fx_close(&f);
    }
#endif /* NODUS_V2_TEST_AUTHORITY */

    printf("test_v2_gate: ALL %d checks passed\n", checks);
    return 0;
}
