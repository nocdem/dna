/**
 * Nodus — O15O Faz 3 — a lost pbft_state write is never silent
 *
 * WHAT THIS PROVES.
 *   nodus_witness_db_save_pbft_state returns -1 when its prepare or its
 *   step fails (nodus_witness_db.c, nodus_witness_db_save_pbft_state —
 *   both of its -1 returns). Four callers in nodus_witness_bft.c
 *   discarded that code, so a failed write was invisible: the node came
 *   back from a restart at a LOWER view than it had reached, or without
 *   the prepared certificate it had been protecting a value with, and
 *   nothing in the log said so. Bug ref: nodus/BUGS.md O15N-L6.
 *
 *   The property that would be false if any FAULTED leg here failed: a
 *   witness whose pbft_state write did not land SAYS SO, at ERROR, naming
 *   WHICH of the four facts it lost.
 *
 *   The property that would be false if any control-flow assertion here
 *   failed: it says so and CARRIES ON. The owner decided this explicitly —
 *   a transient disk fault must not remove a node from consensus — so the
 *   round still advances, the view still moves, the commit still
 *   completes, and safety_halt is NOT latched. Half of this file exists to
 *   prove that "log, not halt" was implemented rather than "halt": under a
 *   patch that halted instead, the substring assertions would still pass
 *   and only these would go red.
 *
 *   EVERY SITE GETS A PAIR ON ONE FIXTURE SHAPE, and the pair is the
 *   whole point. A FAULTED leg alone proves nothing: an error line can be
 *   printed by a site that was never reached, and a fixture can refuse for
 *   a dozen reasons unrelated to the save. The HEALTHY leg excludes them —
 *   same fixture, same call, with pbft_state present — and additionally
 *   asserts the ROW LANDED, which is the only direct evidence that the
 *   save under test actually ran rather than being skipped.
 *
 *   ALL FOUR SITES ARE COVERED. There is no UNREACHED row in this file
 *   and no rc=99 skip anywhere: every section runs unconditionally or the
 *   binary exits non-zero.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro, and no
 *   short-epoch DNAC_EPOCH_LENGTH: every fixture chain stays inside epoch
 *   0, so each assertion holds identically at the shipped 720 and at the
 *   harness's 15. §3's committee priming COMPUTES its epoch start from
 *   DNAC_EPOCH_LENGTH rather than assuming a value.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no pre-exported variable. The one filesystem dependency
 *   is a writable /tmp for mkdtemp/mkstemp; §4's database is
 *   sqlite ":memory:" and touches no file at all.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. §1-§3 build their chain database in their own mkdtemp()
 *   directory under /tmp — which also collects the partial-wipe genesis
 *   marker nodus_witness_create_chain_db writes — and remove the whole
 *   directory with `rm -rf` before returning. §4's database is in memory
 *   and is closed. The stderr-capture files are created with mkstemp and
 *   unlinked immediately, so they exist only as an open descriptor and
 *   vanish when it closes. No processes, no arm files, no restarted
 *   nodes.
 *
 *   Heap deliberately not reclaimed: any prepared-signature block the
 *   PRODUCTION code attaches to a view-change record during §3's move is
 *   released by that fixture's teardown loop over
 *   nodus_witness_vc_record_clear; the batch §2 hands to round_state is
 *   freed through round_state's own file-static helper, which a test must
 *   not race. The residue is bounded by the number of sections and dies
 *   with the process.
 *
 * HOW IT CAN LIE.
 *   - THE FAULT COULD HEAL. The fault is a real `DROP TABLE pbft_state`,
 *     so sqlite3_prepare_v2 inside the save genuinely returns "no such
 *     table" — no mock, no stub, no compile-time switch, no injected
 *     predicate. If a future migration re-created the table behind the
 *     save's back, every faulted leg would test a healthy write. So
 *     break_pbft_state PROVES the injection took by calling the exported
 *     save directly and requiring -1, and every faulted leg additionally
 *     asserts the table is still absent afterwards.
 *   - THE ERROR LINE COULD COME FROM SOMEWHERE ELSE. All four sites are
 *     reached from a witness that logs a great deal, so each leg asserts
 *     the substring UNIQUE TO ITS OWN SITE and each healthy leg asserts
 *     the ABSENCE of that same substring. The two "cleared prepared slot"
 *     messages are deliberately prefixed differently ("successor commit:"
 *     vs "commit_batch:") because they are otherwise the same sentence.
 *   - THE STDERR ASSERTIONS ARE TEXT MATCHES, and text can be edited.
 *     That is brittleness, not a lie: an edited message fails this test
 *     loudly instead of letting it pass quietly. The substrings are
 *     ASCII-only (the production messages contain em-dashes).
 *   - A HEALTHY LEG COULD PASS WITHOUT THE SAVE RUNNING. "No error line"
 *     is also what a build that deleted the call entirely would produce.
 *     Each healthy leg therefore asserts the pbft_state row goes from
 *     ABSENT (checked as a precondition — a fresh chain DB has the table
 *     and no row) to PRESENT with the expected current_view, which only a
 *     save that actually ran can do.
 *   - WHAT IT CANNOT SEE. This file proves the return code is READ and
 *     the loss is REPORTED. It does not prove the underlying write is
 *     durable: the connection runs synchronous=NORMAL under WAL
 *     (nodus_witness.c:486-487), so a row that returned SQLITE_DONE can
 *     still be lost to a power cut, and no unit test can inject that.
 *     That residual is the reason the log exists, not something the log
 *     removes.
 *   - §2 AND §3 DEPEND ON REACHING A QUORUM ARM. If a future change made
 *     the C5 capture or the view move unreachable on this fixture, the
 *     HEALTHY leg's "the row landed" assertion goes red rather than the
 *     section passing empty — the row cannot appear unless the site ran.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_bft_internal.h"  /* nodus_witness_commit_batch */
#include "witness/nodus_witness_db.h"            /* save_pbft_state (the probe) */
#include "witness/nodus_witness_mempool.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"                   /* nodus_random / prepared sign */
#include "transport/nodus_tcp.h"                 /* nodus_time_now */
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"          /* DNAC_EPOCH_LENGTH, DNAC_PUBKEY_SIZE */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAIL %s:%d — %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    printf("  ok: %s\n", msg); \
} while (0)

/* Seven is the shipped devnet size and, more to the point, it is well
 * above NODUS_T3_MIN_WITNESSES — so nodus_witness_bft_consensus_active is
 * true and §2's quorum arm is reachable at all. dna_bft_quorum(7) = 5. */
#define N_PEERS   7
#define Q_HEALTHY 5

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_witness_height_fault_consumers.c and
 * test_witness_quorum_vacuum.c, this season's own models, trimmed to
 * what these four sections touch.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of this file, so the seven
 * identities are generated ONCE in main and reused by every section.
 * Nothing in a section mutates them; §3's identity swap restores what it
 * borrows. */
static peer_t g_peers[N_PEERS];

static void peer_make(peer_t *p) {
    if (qgp_dsa87_keypair(p->pk, p->sk) != 0) {
        fprintf(stderr, "keygen failed\n"); exit(1);
    }
    uint8_t d[64];
    if (qgp_sha3_512(p->pk, NODUS_PK_BYTES, d) != 0) {
        fprintf(stderr, "witness id derive failed\n"); exit(1);
    }
    memcpy(p->id, d, NODUS_T3_WITNESS_ID_LEN);
}

static void roster_put(nodus_witness_t *w, const peer_t *p) {
    uint32_t i = w->roster.n_witnesses++;
    memcpy(w->roster.witnesses[i].witness_id, p->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->roster.witnesses[i].pubkey, p->pk, NODUS_PK_BYTES);
    w->roster.witnesses[i].active = true;
}

/* g_peers[0] is always this node, and the roster is filled in array order
 * so `g_peers` and `w->roster.witnesses` share indices — which the
 * leader helpers rely on.
 *
 * nodus_witness_t is multi-MB: heap, never stack (repo discipline). */
static nodus_witness_t *fixture(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!w || !srv) { fprintf(stderr, "fixture alloc\n"); exit(1); }

    memcpy(srv->identity.pk.bytes, g_peers[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, g_peers[0].sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, g_peers[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i < N_PEERS; i++) roster_put(w, &g_peers[i]);

    w->bft_config.n_witnesses      = N_PEERS;
    w->bft_config.quorum           = Q_HEALTHY;
    w->bft_config.round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
    w->bft_config.viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;

    /* The per-epoch committee cache has no invalidation hook and is keyed
     * on e_start, so a calloc'd 0 would read as a HIT for epoch 0 before
     * anything had been computed. Reset the sentinel exactly as the
     * production init path does. */
    w->cached_committee_epoch_start = UINT64_MAX;
    return w;
}

/* Give the fixture a real chain database through the PRODUCTION creator,
 * which is what installs pbft_state (nodus_witness.c witness_db_open_path
 * -> nodus_witness_db_migrate_v12 -> migrate_v16_pbft_state). A hand-built
 * schema would have to copy that DDL and could drift away from it.
 *
 * `tag` becomes the 16-byte chain_id; set_chain_id zero-fills it to 32, so
 * it is nonzero and verify_chain_id's "we hold an identity, we enforce it"
 * row applies — which is what lets every crafted message carry
 * w->chain_id and pass. */
static void chain_db_open(nodus_witness_t *w, char *dir_template, uint8_t tag)
{
    if (mkdtemp(dir_template) == NULL) {
        fprintf(stderr, "mkdtemp failed\n"); exit(1);
    }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_template);
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0 || !w->db) {
        fprintf(stderr, "create_chain_db failed\n"); exit(1);
    }
}

static void fixture_free(nodus_witness_t *w, const char *dir) {
    if (w) {
        /* The ONLY correct reset for a view-change record: a bare free of
         * the witness would leak every heap-owned prepared-sig block,
         * including the ones bft_self_record_view_change attaches during
         * §3's move. */
        for (int i = 0; i < DNAC_MAX_ACTIVE_VALIDATORS; i++)
            nodus_witness_vc_record_clear(&w->view_changes[i]);
        nodus_witness_close(w);
        free(w->server);
        free(w);
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* best-effort cleanup */ }
}

/* ═══════════════════════════════════════════════════════════════════
 * The pbft_state row — the direct evidence that a save RAN.
 * ═══════════════════════════════════════════════════════════════════ */

/*  1 = the singleton row exists (view / has_blob filled)
 *  0 = the table is there and the row is not
 * -1 = the table itself is gone (the injected fault is still in force)   */
static int pbft_row(nodus_witness_t *w, uint32_t *view, bool *has_blob) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT current_view, last_prepared_blob FROM pbft_state "
            "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int out = 0;
    if (rc == SQLITE_ROW) {
        if (view) *view = (uint32_t)sqlite3_column_int64(st, 0);
        if (has_blob)
            *has_blob = sqlite3_column_type(st, 1) != SQLITE_NULL;
        out = 1;
    }
    sqlite3_finalize(st);
    return out;
}

/* THE FAULT. A real DROP TABLE, so sqlite3_prepare_v2 inside
 * nodus_witness_db_save_pbft_state returns SQLITE_ERROR "no such table:
 * pbft_state" — the same failure a corrupt page or a revoked file
 * permission produces, reached without a mock, a stub or a build flag.
 *
 * The witness schema declares no FOREIGN KEY anywhere, so dropping this
 * table cannot cascade into another; and pbft_state has exactly two
 * readers in the tree (save and load), so nothing else in any section's
 * path can notice it is gone.
 *
 * The injection is PROVEN, not assumed: the exported save is called
 * directly and must answer -1. That probe writes the db layer's own
 * "[H-5] prepare save_pbft_state failed" line to stderr, which is why it
 * runs OUTSIDE every capture window — it must not be mistaken for the
 * caller-side line a section is asserting on. */
static void break_pbft_state(nodus_witness_t *w) {
    char *err = NULL;
    if (sqlite3_exec(w->db, "DROP TABLE pbft_state;", NULL, NULL, &err)
            != SQLITE_OK) {
        fprintf(stderr, "break_pbft_state: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        exit(1);
    }
    if (nodus_witness_db_save_pbft_state(w) == 0) {
        fprintf(stderr, "break_pbft_state: the save did NOT fail after the "
                        "DROP — the injection is broken, not the code\n");
        exit(1);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-site resolution.
 *
 * Two of the four sites log with QGP_LOG_ERROR and two with a bare
 * fprintf, each matching its own neighbourhood. In a nodus build
 * QGP_LOG_* resolves to nodus/src/nodus_log_shim.c, whose qgp_log_ring_add
 * writes straight to stderr, so fd 2 carries both.
 *
 * The window wraps ONLY the call under test and stderr is restored BEFORE
 * anything is asserted: a CHECK that failed inside the window would write
 * its diagnosis into the temp file and the binary would exit 1 saying
 * nothing. Copied from test_witness_height_fault_consumers.c.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_pbft_save_XXXXXX";
    g_cap_fd = mkstemp(tmpl);
    if (g_cap_fd < 0) { fprintf(stderr, "mkstemp failed\n"); exit(1); }
    if (unlink(tmpl) != 0) {    /* leaves nothing behind */
        fprintf(stderr, "unlink failed\n"); exit(1);
    }
    fflush(stderr);
    g_cap_saved = dup(2);
    if (g_cap_saved < 0) { fprintf(stderr, "dup(2) failed\n"); exit(1); }
    if (dup2(g_cap_fd, 2) < 0) {
        fprintf(stderr, "dup2 failed\n"); exit(1);
    }
}

#define CAP_BUF 32768

/* Restore fd 2 and copy the captured window into CALLER-OWNED storage —
 * a shared static buffer would let a faulted leg overwrite the healthy
 * leg's text that the same section is still asserting on. */
static void cap_end(char *dst, size_t cap) {
    fflush(stderr);
    if (g_cap_saved >= 0) {
        if (dup2(g_cap_saved, 2) < 0) {
            /* Nothing can be reported once this fails — the descriptor
             * the report would use is the one that is gone. */
            _exit(1);
        }
        close(g_cap_saved);
        g_cap_saved = -1;
    }
    dst[0] = '\0';
    if (g_cap_fd >= 0) {
        if (lseek(g_cap_fd, 0, SEEK_SET) == 0) {
            ssize_t n = read(g_cap_fd, dst, cap - 1);
            if (n < 0) n = 0;
            dst[n] = '\0';
        }
        close(g_cap_fd);
        g_cap_fd = -1;
    }
}

static bool said(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

/* The four site-unique substrings, ASCII-only and each naming the FACT
 * its site loses. Kept together so the next reader can see at a glance
 * that the two "cleared prepared slot" lines are distinguished by their
 * prefix and nothing else. */
#define SAY_SUCCESSOR \
    "successor commit: the CLEARED prepared slot was NOT persisted"
#define SAY_CERT      "the PREPARED CERTIFICATE was NOT persisted"
#define SAY_VIEW      "the NEW VIEW was NOT persisted"
#define SAY_COMMIT    \
    "commit_batch: the CLEARED prepared slot was NOT persisted"

/* ═══════════════════════════════════════════════════════════════════
 * Message builders
 * ═══════════════════════════════════════════════════════════════════ */

/* A fresh header. The nonce is re-randomised on every call because
 * is_replay() keys on (sender_id, nonce) in a PROCESS-GLOBAL table: a
 * second message reusing the first one's nonce dies at the replay gate,
 * above every site in this file. */
static void fill_header(nodus_t3_msg_t *m, nodus_witness_t *w,
                        const peer_t *from, uint64_t round, uint32_t view) {
    m->header.round = round;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
}

/* O15N Faz 2A — the 116-byte PREPARED preimage:
 *   "prepared"(8) ‖ chain_id(32) ‖ view(4 BE) ‖ height(8 BE) ‖ tx_hash(64)
 * Identical to sign_prepared in test_witness_quorum_vacuum.c; the layout
 * is compute_prepared_preimage's, which is file-static in the
 * implementation and so cannot be called from here. */
static void sign_prepared(uint8_t out[NODUS_SIG_BYTES], const peer_t *p,
                          uint32_t view, uint64_t height,
                          const uint8_t *tx_hash, const uint8_t *chain_id) {
    uint8_t pre[116];
    memcpy(pre, "prepared", 8);
    memcpy(pre + 8, chain_id, 32);
    pre[40] = (uint8_t)(view >> 24); pre[41] = (uint8_t)(view >> 16);
    pre[42] = (uint8_t)(view >> 8);  pre[43] = (uint8_t)view;
    for (int i = 0; i < 8; i++)
        pre[44 + i] = (uint8_t)(height >> ((7 - i) * 8));
    memcpy(pre + 52, tx_hash, NODUS_T3_TX_HASH_LEN);

    nodus_sig_t sig;
    nodus_seckey_t sk;
    memcpy(sk.bytes, p->sk, sizeof(sk.bytes));
    if (nodus_sign_prepared_vote(&sig, pre, sizeof(pre), &sk) != 0) {
        fprintf(stderr, "prepared sign failed\n"); exit(1);
    }
    memcpy(out, sig.bytes, NODUS_SIG_BYTES);
}

/* Put the fixture into a live PREVOTE round with ONLY our own approval
 * recorded. The self-vote matters: it means peers 1..4 take the count to
 * exactly Q_HEALTHY, so §2's quorum arm fires on the LAST of them. */
static void enter_round(nodus_witness_t *w, uint64_t round, uint64_t height,
                        const uint8_t *tx_hash) {
    w->current_round = round;
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.round = round;
    w->round_state.view = w->current_view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    w->round_state.block_height = height;
    memcpy(w->round_state.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.prevotes[0].voter_id, g_peers[0].id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->round_state.prevotes[0].pubkey, g_peers[0].pk, NODUS_PK_BYTES);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;
    w->round_state.phase_start_time = nodus_time_now() * 1000ULL;
}

/* One APPROVE PREVOTE from peer `idx`, carrying a REAL prepared cert_sig
 * over the round's own anchor — the C5 gate in bft_handle_vote_inner
 * verifies it and drops the whole vote if it does not check out, so a
 * forged signature here would make §2 refuse for the wrong reason. */
static void send_prevote(nodus_witness_t *w, int idx) {
    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_PREVOTE;
    fill_header(&m, w, &g_peers[idx], w->round_state.round,
                w->round_state.view);
    m.vote.vote = NODUS_W_VOTE_APPROVE;
    memcpy(m.vote.vote_target, w->round_state.tx_hash, NODUS_T3_TX_HASH_LEN);
    sign_prepared(m.vote.cert_sig, &g_peers[idx], w->current_view,
                  w->round_state.block_height, w->round_state.tx_hash,
                  w->chain_id);
    (void)nodus_witness_bft_handle_vote(w, &m);
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — the CLEARED prepared slot after a SUCCESSOR commit
 *      (nodus_witness_bft.c, nodus_witness_bft_after_successor_commit).
 *
 * WHAT IS LOST: the cleared slot. On restart a stale prepared certificate
 * may re-attach to a VIEW_CHANGE — the exact O15H D4 shape, in which 14
 * of 20 nodes carried a height-41 cert into a view change after every one
 * of them had already committed height 41.
 *
 * The helper is called DIRECTLY: it is exported
 * (nodus_witness_bft.h:448) and takes only the witness, so no successor
 * chain state has to be manufactured to reach it. v2_successor is never
 * set anywhere in this file — a genuine successor needs the V2 schema
 * installed through the migration, never a hand-set flag.
 * ═══════════════════════════════════════════════════════════════════ */

/* Both legs are identical up to the injection, so they are one function
 * with one switch — a copy-pasted pair is how two legs silently drift
 * into testing different things. */
static void successor_leg(bool faulted, uint8_t tag, char *dir,
                          char *out, size_t out_cap,
                          nodus_witness_t **w_out) {
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, tag);

    /* A fresh chain DB has the table and no row: that is the precondition
     * that makes "the row landed" mean the save RAN. */
    CHECK(pbft_row(w, NULL, NULL) == 0,
          "precondition: pbft_state exists and is empty on a fresh chain "
          "database");

    /* The stale certificate the clear is retiring. Its height and view are
     * what the error line must name. */
    w->current_view = 3;
    w->last_prepared.present = true;
    w->last_prepared.height  = 41;
    w->last_prepared.view    = 3;

    /* ARMED, so the disarm below is an observable event rather than a
     * value that was already 0. This is the control-flow witness: it is
     * written AFTER the save, so it can only be 0 if execution continued
     * past a failed save. */
    w->awaiting_propose_deadline_ms = 999999ULL;

    /* ZEROED for the same reason, and it is the SECOND control-flow
     * witness — the one that sits past the chain-height read as well as
     * past the save. The fixture chain has an empty validators table, so
     * load_committee_at_height resolves count 0 and
     * refresh_bft_config_from_committee takes its F17 A5 fallback to the
     * roster size: 7 witnesses, quorum 5. Left at the fixture's own 7/5
     * these assertions would hold without the refresh ever running. */
    w->bft_config.n_witnesses = 0;
    w->bft_config.quorum = 0;

    if (faulted) break_pbft_state(w);

    cap_begin();
    nodus_witness_bft_after_successor_commit(w);
    cap_end(out, out_cap);

    *w_out = w;
}

static void section_successor_commit(void) {
    printf("\n§1 successor commit — the cleared prepared slot\n");

    /* ── HEALTHY LEG ─────────────────────────────────────────────── */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_pbft_succ_ok_XXXXXX";
        nodus_witness_t *w = NULL;
        successor_leg(false, 0x11, dir, out, sizeof(out), &w);

        uint32_t v = 0xFFFFFFFFu;
        bool blob = true;
        CHECK(pbft_row(w, &v, &blob) == 1,
              "HEALTHY: the save RAN and wrote the pbft_state row");
        CHECK(v == 3,
              "and the row carries the current view");
        CHECK(!blob,
              "with a NULL prepared blob — the cleared slot is what was "
              "persisted");
        CHECK(!said(out, SAY_SUCCESSOR),
              "and NOTHING was reported lost");

        CHECK(w->awaiting_propose_deadline_ms == 0,
              "control: the propose-wait deadman was disarmed");
        CHECK(!w->safety_halt,
              "control: safety_halt is not latched");
        CHECK(w->bft_config.n_witnesses == N_PEERS &&
              w->bft_config.quorum == Q_HEALTHY,
              "control: the post-commit bft_config refresh ran to the end");

        fixture_free(w, dir);
    }

    /* ── FAULTED LEG ─────────────────────────────────────────────────
     * Same fixture, same call. The four control assertions are repeated
     * verbatim, and they are the half that proves "log, not halt": under
     * a patch that latched safety_halt or returned early they go red
     * while the substring assertion still passes. */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_pbft_succ_fault_XXXXXX";
        nodus_witness_t *w = NULL;
        successor_leg(true, 0x12, dir, out, sizeof(out), &w);

        CHECK(pbft_row(w, NULL, NULL) == -1,
              "the injected fault is still in force — pbft_state is gone");
        CHECK(said(out, SAY_SUCCESSOR),
              "FAULTED: the loss is REPORTED, and the line names the "
              "cleared prepared slot as the thing lost");
        CHECK(said(out, "height=41") && said(out, "view=3"),
              "and it names the stale certificate that will survive the "
              "restart, so an operator knows which one");
        CHECK(said(out, "re-attach to a VIEW_CHANGE"),
              "and states the consequence rather than only the failure");

        CHECK(w->awaiting_propose_deadline_ms == 0,
              "control: the propose-wait deadman was STILL disarmed — "
              "execution continued past the failed save");
        CHECK(!w->safety_halt,
              "control: safety_halt is NOT latched — this is a log, not a "
              "halt, and a transient disk fault does not remove this node "
              "from consensus");
        CHECK(w->bft_config.n_witnesses == N_PEERS &&
              w->bft_config.quorum == Q_HEALTHY,
              "control: the post-commit bft_config refresh still ran to "
              "the end, exactly as in the healthy leg");

        fixture_free(w, dir);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — the C5 PREPARED CERTIFICATE
 *      (nodus_witness_bft.c, bft_handle_vote_inner, the PREVOTE-quorum
 *      arm, immediately after w->last_prepared.n_sigs is written).
 *
 * WHAT IS LOST: the certificate itself. On restart this node cannot prove
 * the value it prepared at that height, so a VIEW_CHANGE it initiates
 * carries no evidence for a value it is in fact bound to.
 *
 * Driven through the wire handler, not by hand: the round is entered with
 * our own approval and peers 1..4 vote, so the fifth approval reaches
 * quorum 5 and the arm fires. Shape copied from
 * test_witness_quorum_vacuum.c §1, which is this season's proof that this
 * arm is reachable from a fixture.
 * ═══════════════════════════════════════════════════════════════════ */
static void cert_leg(bool faulted, uint8_t tag, char *dir,
                     char *out, size_t out_cap, nodus_witness_t **w_out) {
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, tag);

    CHECK(pbft_row(w, NULL, NULL) == 0,
          "precondition: pbft_state exists and is empty on a fresh chain "
          "database");

    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0xA1, sizeof(txh));
    enter_round(w, /*round*/ 4, /*height*/ 1, txh);
    CHECK(w->round_state.prevote_approve_count == 1,
          "precondition: the round opens with our own approval only");

    /* Dropped BEFORE the votes: pbft_state has exactly two readers in the
     * tree (save and load) and neither is on the vote path above the
     * quorum arm, so nothing between here and the arm can notice. */
    if (faulted) break_pbft_state(w);

    /* Peers 1..3 take the count to 4 — below the quorum, so the arm must
     * NOT have fired yet. Asserting that here is what stops a build where
     * the arm fires on the first vote from passing this section. */
    for (int i = 1; i <= 3; i++) send_prevote(w, i);
    CHECK(w->round_state.prevote_approve_count == 4,
          "three peer approvals were counted (4 of 5)");
    CHECK(!w->last_prepared.present,
          "and no certificate has been captured yet — 4 is below the "
          "quorum");

    cap_begin();
    send_prevote(w, 4);          /* the fifth approval — the quorum arm */
    cap_end(out, out_cap);

    *w_out = w;
}

static void section_prepared_cert(void) {
    printf("\n§2 PREVOTE quorum — the C5 prepared certificate\n");

    /* ── HEALTHY LEG ─────────────────────────────────────────────── */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_pbft_cert_ok_XXXXXX";
        nodus_witness_t *w = NULL;
        cert_leg(false, 0x21, dir, out, sizeof(out), &w);

        uint32_t v = 0xFFFFFFFFu;
        bool blob = false;
        CHECK(pbft_row(w, &v, &blob) == 1,
              "HEALTHY: the save RAN and wrote the pbft_state row");
        CHECK(blob,
              "and the row carries a prepared blob — a certificate, not an "
              "empty slot");
        CHECK(v == w->current_view,
              "at the current view");
        CHECK(!said(out, SAY_CERT),
              "and NOTHING was reported lost");

        CHECK(w->last_prepared.present && w->last_prepared.n_sigs == 5,
              "control: the certificate was captured with five signatures");
        CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
              "control: the round advanced to PRECOMMIT");
        CHECK(said(out, "C5 prepared cert captured"),
              "control: the site ran to its own announcement");

        fixture_free(w, dir);
    }

    /* ── FAULTED LEG ─────────────────────────────────────────────── */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_pbft_cert_fault_XXXXXX";
        nodus_witness_t *w = NULL;
        cert_leg(true, 0x22, dir, out, sizeof(out), &w);

        CHECK(pbft_row(w, NULL, NULL) == -1,
              "the injected fault is still in force — pbft_state is gone");
        CHECK(said(out, SAY_CERT),
              "FAULTED: the loss is REPORTED, and the line names the "
              "prepared certificate as the thing lost");
        CHECK(said(out, "n_sigs=5"),
              "and names the certificate that will not survive the restart");
        CHECK(said(out, "cannot prove the value it prepared here"),
              "and states the consequence rather than only the failure");

        CHECK(w->last_prepared.present && w->last_prepared.n_sigs == 5,
              "control: the certificate is STILL held in memory — the "
              "failed save did not discard it");
        CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
              "control: the round STILL advanced to PRECOMMIT — the round "
              "was not abandoned over a failed bookkeeping write");
        CHECK(said(out, "C5 prepared cert captured"),
              "control: execution continued past the failed save to the "
              "site's own announcement");
        CHECK(!w->safety_halt,
              "control: safety_halt is NOT latched — this is a log, not a "
              "halt");

        fixture_free(w, dir);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — the NEW VIEW
 *      (nodus_witness_bft.c, bft_view_move_finish, after
 *      bind_reproposal_from_view_changes).
 *
 * WHAT IS LOST: the view. On restart this node may come back at a LOWER
 * view than it reached — and since O15N Faz 2C2 this is the ONLY site
 * that arms C5 on a view change, so the reproposal binding computed here
 * is the safety evidence that goes with it.
 *
 * REACHED THROUGH THE VIEW_OK PROOF PATH, exactly as
 * test_witness_quorum_vacuum.c §3 reaches it: bft_viewok_apply is the
 * caller that does not consult the local config, so one fixture and one
 * verified proof carry us into a view we lead. BOTH LEGS ARE OTHERWISE
 * IDENTICAL — same quorum, same five prepared signatures — so the faulted
 * capture differs from the healthy one by exactly the new error line, and
 * no pre-existing guard can fire in one leg and not the other.
 * ═══════════════════════════════════════════════════════════════════ */

/* Does the PRODUCTION predicate call us the leader at `view`? Probing
 * must not be an edit, so current_view is restored. */
static bool is_leader_at(nodus_witness_t *w, uint32_t view) {
    uint32_t saved = w->current_view;
    w->current_view = view;
    bool is_l = nodus_witness_bft_is_leader(w);
    w->current_view = saved;
    return is_l;
}

/* The lowest view > 0 at which we lead. Witness ids are SHA3-512 over
 * freshly generated keys, so our seat is DIFFERENT ON EVERY RUN: a
 * hard-coded view would make the leader precondition a coin flip that
 * still printed PASS. Over v = 1..n the modulus visits every seat exactly
 * once, so such a view always exists. */
static uint32_t pick_leader_view(nodus_witness_t *w) {
    for (uint32_t v = 1; v <= N_PEERS; v++)
        if (is_leader_at(w, v)) return v;
    fprintf(stderr, "pick_leader_view: we never lead\n");
    exit(1);
}

/* Prime the legacy committee resolver's per-epoch cache with all seven
 * peers. nodus_committee_get_for_block answers from this cache before it
 * touches the database, so the committee governing both the VIEW_OK proof
 * and is_leader becomes a deterministic, DB-free input whose ORDER the
 * test controls — which matters because the VIEW_OK set hash commits seat
 * positions.
 *
 * Parametric in DNAC_EPOCH_LENGTH: the epoch start is COMPUTED, never
 * assumed, so a short-epoch build primes the same set. */
static void prime_committee(nodus_witness_t *w, uint64_t height, int n) {
    uint64_t e = (uint64_t)DNAC_EPOCH_LENGTH;
    w->cached_committee_epoch_start = (height / e) * e;
    w->cached_committee_count = n;
    for (int i = 0; i < n; i++) {
        memcpy(w->cached_committee_pubkeys[i], g_peers[i].pk,
               DNAC_PUBKEY_SIZE);
        w->cached_committee_stakes[i]         = 1000000ULL + (uint64_t)i;
        w->cached_committee_self_stakes[i]    = 1000000000000000ULL;
        w->cached_committee_commission_bps[i] = 100;
    }
}

/* Make the fixture SIGN A VIEW_OK AS peer `idx`, through the production
 * producer. nodus_witness_bft_sign_view_ok reads the signer identity from
 * `w` and never takes it as an argument — deliberately, so a statement
 * cannot be minted for another signer. Swapping the identity in and back
 * is the only way one fixture can stand in for several nodes, and it
 * exercises the REAL producer rather than a test-side re-implementation. */
static int sign_viewok_as(nodus_witness_t *w, int idx,
                          uint64_t height, uint32_t view,
                          uint8_t set_hash_out[64], nodus_sig_t *sig_out) {
    uint8_t saved_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t saved_sk[sizeof(w->server->identity.sk.bytes)];
    uint8_t saved_pk[NODUS_PK_BYTES];
    memcpy(saved_id, w->my_id, sizeof(saved_id));
    memcpy(saved_sk, w->server->identity.sk.bytes, sizeof(saved_sk));
    memcpy(saved_pk, w->server->identity.pk.bytes, sizeof(saved_pk));

    memcpy(w->my_id, g_peers[idx].id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->server->identity.sk.bytes, g_peers[idx].sk, sizeof(saved_sk));
    memcpy(w->server->identity.pk.bytes, g_peers[idx].pk, NODUS_PK_BYTES);

    int rc = nodus_witness_bft_sign_view_ok(w, height, view,
                                            set_hash_out, sig_out);

    memcpy(w->my_id, saved_id, sizeof(saved_id));
    memcpy(w->server->identity.sk.bytes, saved_sk, sizeof(saved_sk));
    memcpy(w->server->identity.pk.bytes, saved_pk, NODUS_PK_BYTES);
    return rc;
}

/* Attach a view-change record from peer `idx` at `target`, carrying a
 * prepared certificate of `n_sigs` REAL prepared signatures. Built by
 * hand because the wire path that normally admits one runs its own quorum
 * verify, a DIFFERENT guard from the one this section is about. */
static void attach_vc_record(nodus_witness_t *w, int idx, uint32_t target,
                             uint64_t prep_height, uint32_t prep_view,
                             const uint8_t *prep_txh, uint32_t n_sigs) {
    int slot = w->view_change_count++;
    nodus_witness_vc_record_t *r = &w->view_changes[slot];
    r->target_view = target;
    memcpy(r->voter_id, g_peers[idx].id, NODUS_T3_WITNESS_ID_LEN);
    r->last_committed_round = w->last_committed_round;
    r->prepared.has_prepared = true;
    r->prepared.height = prep_height;
    r->prepared.view = prep_view;
    memcpy(r->prepared.tx_hash, prep_txh, NODUS_T3_TX_HASH_LEN);
    r->prepared.n_sigs = n_sigs;
    r->prepared.sigs = calloc(n_sigs, sizeof(*r->prepared.sigs));
    if (!r->prepared.sigs) { fprintf(stderr, "sigs alloc\n"); exit(1); }
    for (uint32_t i = 0; i < n_sigs; i++) {
        memcpy(r->prepared.sigs[i].voter_id, g_peers[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        sign_prepared(r->prepared.sigs[i].signature, &g_peers[i],
                      prep_view, prep_height, prep_txh, w->chain_id);
    }
}

static void newview_leg(bool faulted, uint8_t tag, char *dir,
                        char *out, size_t out_cap,
                        nodus_witness_t **w_out, uint32_t *view_out) {
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, tag);

    CHECK(pbft_row(w, NULL, NULL) == 0,
          "precondition: pbft_state exists and is empty on a fresh chain "
          "database");

    /* Height 1 keeps every lookup inside epoch 0 whatever
     * DNAC_EPOCH_LENGTH is. */
    const uint64_t H = 1;
    prime_committee(w, H, N_PEERS);

    uint32_t V = pick_leader_view(w);

    uint8_t prep_txh[NODUS_T3_TX_HASH_LEN];
    memset(prep_txh, 0xC3, sizeof(prep_txh));
    attach_vc_record(w, 1, V, /*prep_height*/ H, /*prep_view*/ 0,
                     prep_txh, /*n_sigs*/ Q_HEALTHY);

    /* THE PROOF. Three DISTINCT statements: verify_view_proof requires
     * f+1 of the committee governing the carried height, which for seven
     * members is ((5-1)/2)+1 = 3. Signed through the production producer,
     * so the set hash is the one the verifier recomputes. */
    nodus_t3_msg_t vm;
    memset(&vm, 0, sizeof(vm));
    vm.type = NODUS_T3_VIEWOK;
    fill_header(&vm, w, &g_peers[1], /*round*/ 0, /*view*/ 0);
    vm.viewok.height = H;
    vm.viewok.view = V;
    vm.viewok.n_entries = 3;
    for (int i = 0; i < 3; i++) {
        uint8_t sh[64];
        nodus_sig_t sg;
        if (sign_viewok_as(w, i + 1, H, V, sh, &sg) != 0) {
            fprintf(stderr, "sign_view_ok failed for peer %d\n", i + 1);
            exit(1);
        }
        memcpy(vm.viewok.set_hash, sh, 64);
        memcpy(vm.viewok.entries[i].voter_id, g_peers[i + 1].id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(vm.viewok.entries[i].signature, sg.bytes, NODUS_SIG_BYTES);
    }

    if (faulted) break_pbft_state(w);

    cap_begin();
    (void)nodus_witness_bft_handle_viewok(w, &vm);
    cap_end(out, out_cap);

    /* The proof must actually have moved us, or every assertion the
     * caller makes would be about a path never taken. Asserted AFTER the
     * capture closed, so a failure is visible. */
    if (w->current_view != V) {
        fprintf(stderr, "newview_leg: the VIEW_OK proof did NOT move the "
                        "view (still %u, wanted %u) — the leg tested "
                        "nothing\n%s\n", w->current_view, V, out);
        exit(1);
    }

    *w_out = w;
    *view_out = V;
}

static void section_new_view(void) {
    printf("\n§3 view move — the new view\n");

    /* ── HEALTHY LEG ─────────────────────────────────────────────── */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_pbft_view_ok_XXXXXX";
        nodus_witness_t *w = NULL;
        uint32_t V = 0;
        newview_leg(false, 0x31, dir, out, sizeof(out), &w, &V);

        uint32_t v = 0xFFFFFFFFu;
        CHECK(pbft_row(w, &v, NULL) == 1,
              "HEALTHY: the save RAN and wrote the pbft_state row");
        CHECK(v == V,
              "and the row carries the view just entered — which is the "
              "whole point of persisting it");
        CHECK(!said(out, SAY_VIEW),
              "and NOTHING was reported lost");

        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "control: the move completed — the round returned to IDLE");
        CHECK(!w->view_change_in_progress,
              "control: the view-change latch was released");
        CHECK(said(out, "we are new leader for view"),
              "control: the leader half of the move ran");
        CHECK(said(out, "C5 NEW_VIEW reproposal"),
              "control: the C5 reproposal went out with the NEW_VIEW");

        fixture_free(w, dir);
    }

    /* ── FAULTED LEG ─────────────────────────────────────────────────
     * Identical in every input to the healthy leg — same quorum, same
     * five prepared signatures — so the capture differs by exactly the
     * new error line. */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_pbft_view_fault_XXXXXX";
        nodus_witness_t *w = NULL;
        uint32_t V = 0;
        newview_leg(true, 0x32, dir, out, sizeof(out), &w, &V);

        CHECK(pbft_row(w, NULL, NULL) == -1,
              "the injected fault is still in force — pbft_state is gone");
        CHECK(said(out, SAY_VIEW),
              "FAULTED: the loss is REPORTED, and the line names the new "
              "view as the thing lost");
        CHECK(said(out, "come back at a LOWER view than it reached"),
              "and states the consequence rather than only the failure");

        CHECK(w->current_view == V,
              "control: the view STILL moved in memory — the node did not "
              "refuse the view it was proved into");
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "control: the move STILL completed — the round returned to "
              "IDLE");
        CHECK(!w->view_change_in_progress,
              "control: the view-change latch was STILL released");
        CHECK(said(out, "we are new leader for view"),
              "control: execution continued past the failed save into the "
              "leader half of the move");
        CHECK(said(out, "C5 NEW_VIEW reproposal"),
              "control: the C5 reproposal STILL went out — exactly as in "
              "the healthy leg");
        CHECK(!w->safety_halt,
              "control: safety_halt is NOT latched — this is a log, not a "
              "halt");

        fixture_free(w, dir);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — the CLEARED prepared slot after a LEGACY commit
 *      (nodus_witness_bft.c, nodus_witness_commit_batch, inside the
 *      commit_rc == 0 block).
 *
 * WHAT IS LOST: the same fact §1 loses, on the other lane — the cleared
 * slot, and with it the guarantee that a post-commit restart cannot
 * re-attach a stale prepared cert to a future VIEW_CHANGE.
 *
 * ⚠ THIS SECTION USES A HAND-BUILT SCHEMA, AND DELIBERATELY. The
 * composition "commit_batch returns 0" is proven in-tree only on this
 * schema (tests/test_commit_atomicity.c's happy path, and
 * tests/test_witness_bft_config_refresh.c with the same roster fallback);
 * it has never been driven on a full production chain database. Copying
 * the proven schema and APPENDING the one table this file is about
 * composes two established facts instead of asserting a new one. The
 * appended DDL is copied verbatim from nodus_witness_db.c,
 * nodus_witness_db_migrate_v16_pbft_state, so a future column change
 * shows up here as a mismatch rather than as silent drift.
 *
 * The roster is 7 with an EMPTY validators table, so
 * load_committee_at_height returns count 0 and
 * refresh_bft_config_from_committee takes its F17 A5 fallback to the
 * roster size — the same path test_witness_bft_config_refresh.c pins.
 * That is what makes bft_config.n_witnesses a usable control-flow
 * witness for the post-commit tail.
 * ═══════════════════════════════════════════════════════════════════ */

/* Copied VERBATIM from tests/test_commit_atomicity.c's setup_witness, the
 * fixture that proves commit_batch reaches rc = 0, plus pbft_state. */
static const char *SCHEMA_LEGACY_COMMIT =
    "CREATE TABLE nullifiers ("
    "  nullifier BLOB PRIMARY KEY,"
    "  tx_hash BLOB NOT NULL,"
    "  added_at INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE utxo_set ("
    "  nullifier BLOB PRIMARY KEY,"
    "  owner TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  token_id BLOB NOT NULL DEFAULT x'"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "',"
    "  tx_hash BLOB NOT NULL,"
    "  output_index INTEGER NOT NULL,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL DEFAULT 0,"
    "  unlock_block INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE blocks (height INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  tx_root BLOB NOT NULL, tx_count INTEGER NOT NULL DEFAULT 1,"
    "  timestamp INTEGER NOT NULL, proposer_id BLOB,"
    "  prev_hash BLOB NOT NULL DEFAULT x'',"
    "  state_root BLOB NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT 0, chain_def_blob BLOB);"
    "CREATE TABLE supply_state (id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  genesis_supply INTEGER NOT NULL DEFAULT 0,"
    "  total_burned INTEGER NOT NULL DEFAULT 0, genesis_tx_hash BLOB);"
    "CREATE TABLE tokens (token_id BLOB PRIMARY KEY, name TEXT NOT NULL,"
    "  symbol TEXT NOT NULL, decimals INTEGER NOT NULL DEFAULT 8,"
    "  supply INTEGER NOT NULL, creator_fp TEXT NOT NULL,"
    "  flags INTEGER NOT NULL DEFAULT 0,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  timestamp INTEGER NOT NULL DEFAULT 0);"
    /* The state_root subtree tables. compute_state_root fails CLOSED on
     * every subtree, so finalize_block cannot produce a root without
     * them; all are left EMPTY, which yields each subtree's tagged-empty
     * sentinel and leaves record_attendance matching nothing. */
    "CREATE TABLE IF NOT EXISTS validators ("
    "  pubkey_hash BLOB PRIMARY KEY,"
    "  pubkey BLOB NOT NULL,"
    "  self_stake INTEGER NOT NULL,"
    "  total_delegated INTEGER NOT NULL DEFAULT 0,"
    "  external_delegated INTEGER NOT NULL DEFAULT 0,"
    "  commission_bps INTEGER NOT NULL,"
    "  pending_commission_bps INTEGER NOT NULL DEFAULT 0,"
    "  pending_effective_block INTEGER NOT NULL DEFAULT 0,"
    "  status INTEGER NOT NULL,"
    "  active_since_block INTEGER NOT NULL,"
    "  unstake_commit_block INTEGER NOT NULL DEFAULT 0,"
    "  unstake_destination_fp TEXT NOT NULL,"
    "  unstake_destination_pubkey BLOB NOT NULL,"
    "  last_validator_update_block INTEGER NOT NULL DEFAULT 0,"
    "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0,"
    "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
    "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS delegations ("
    "  delegator_hash BLOB,"
    "  validator_hash BLOB,"
    "  delegator_pubkey BLOB NOT NULL,"
    "  validator_pubkey BLOB NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  delegated_at_block INTEGER NOT NULL,"
    "  PRIMARY KEY (delegator_hash, validator_hash)"
    ");"
    "CREATE TABLE IF NOT EXISTS epoch_state ("
    "  epoch_start_height INTEGER PRIMARY KEY,"
    "  epoch_pool_accum   INTEGER NOT NULL DEFAULT 0,"
    "  snapshot_hash      BLOB NOT NULL,"
    "  snapshot_blob      BLOB"
    ");"
    "CREATE TABLE IF NOT EXISTS supply_tracking ("
    "  id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  genesis_supply INTEGER NOT NULL,"
    "  total_burned INTEGER NOT NULL DEFAULT 0,"
    "  total_minted INTEGER NOT NULL DEFAULT 0,"
    "  current_supply INTEGER NOT NULL,"
    "  last_tx_hash BLOB NOT NULL,"
    "  last_sequence INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS chain_config_history ("
    "    param_id          INTEGER NOT NULL,"
    "    new_value         INTEGER NOT NULL,"
    "    effective_block   INTEGER NOT NULL,"
    "    commit_block      INTEGER NOT NULL,"
    "    tx_hash           BLOB    NOT NULL,"
    "    proposal_nonce    INTEGER NOT NULL,"
    "    created_at_unix   INTEGER NOT NULL,"
    "    PRIMARY KEY (param_id, effective_block)"
    ");"
    /* THE TABLE THIS FILE IS ABOUT. Copied verbatim from
     * nodus_witness_db.c, nodus_witness_db_migrate_v16_pbft_state. */
    "CREATE TABLE IF NOT EXISTS pbft_state ("
    "  id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  current_view INTEGER,"
    "  last_prepared_blob BLOB"
    ");";

static int count_rows(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int n = 0;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static void commit_leg(bool faulted, char *out, size_t out_cap,
                       nodus_witness_t **w_out, int *rc_out) {
    /* nodus_witness_t is multi-MB — heap, never stack (repo discipline).
     * No server is attached, matching the composition
     * test_commit_atomicity.c proves; commit_batch's legacy path does not
     * reach through w->server. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { fprintf(stderr, "fixture alloc\n"); exit(1); }
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) {
        fprintf(stderr, "sqlite3_open failed\n"); exit(1);
    }
    char *err = NULL;
    if (sqlite3_exec(w->db, SCHEMA_LEGACY_COMMIT, NULL, NULL, &err)
            != SQLITE_OK) {
        fprintf(stderr, "schema: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        exit(1);
    }

    CHECK(pbft_row(w, NULL, NULL) == 0,
          "precondition: pbft_state exists and is empty");

    /* Empty validators table -> committee count 0 -> the refresh falls
     * back to the roster size, which is the post-commit control witness. */
    w->roster.n_witnesses = N_PEERS;

    /* The stale certificate the clear is retiring, and the armed deadman
     * whose disarm proves execution continued past the save. */
    w->current_view = 2;
    w->last_prepared.present = true;
    w->last_prepared.height  = 7;
    w->last_prepared.view    = 2;
    w->awaiting_propose_deadline_ms = 888888ULL;

    if (faulted) break_pbft_state(w);

    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { fprintf(stderr, "entry alloc\n"); exit(1); }
    memset(e->tx_hash, 0x4B, NODUS_T3_TX_HASH_LEN);
    e->tx_type = NODUS_W_TX_SPEND;
    e->nullifier_count = 0;
    e->tx_data = NULL;
    e->tx_len = 0;
    nodus_witness_mempool_entry_t *entries[1] = { e };

    uint8_t proposer[32];
    memset(proposer, 0x42, sizeof(proposer));

    cap_begin();
    int rc = nodus_witness_commit_batch(w, entries, 1, /*bh*/ 1,
                                        1700000000, proposer, NULL);
    cap_end(out, out_cap);

    free(e);
    *w_out = w;
    *rc_out = rc;
}

static void commit_fixture_free(nodus_witness_t *w) {
    if (!w) return;
    sqlite3_close(w->db);
    free(w);
}

static void section_commit_batch(void) {
    printf("\n§4 legacy commit — the cleared prepared slot\n");

    /* ── HEALTHY LEG ─────────────────────────────────────────────── */
    {
        static char out[CAP_BUF];
        nodus_witness_t *w = NULL;
        int rc = -1;
        commit_leg(false, out, sizeof(out), &w, &rc);

        CHECK(rc == 0,
              "HEALTHY: the block committed");
        uint32_t v = 0xFFFFFFFFu;
        bool blob = true;
        CHECK(pbft_row(w, &v, &blob) == 1,
              "and the save RAN and wrote the pbft_state row");
        CHECK(v == 2,
              "carrying the current view");
        CHECK(!blob,
              "with a NULL prepared blob — the cleared slot is what was "
              "persisted");
        CHECK(!said(out, SAY_COMMIT),
              "and NOTHING was reported lost");

        CHECK(count_rows(w, "SELECT COUNT(*) FROM blocks") == 1,
              "control: the block is durable");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "control: the propose-wait deadman was disarmed");
        CHECK(w->bft_config.n_witnesses == N_PEERS &&
              w->bft_config.quorum == Q_HEALTHY,
              "control: the post-commit bft_config refresh ran to the end");
        CHECK(!w->safety_halt,
              "control: safety_halt is not latched");

        commit_fixture_free(w);
    }

    /* ── FAULTED LEG ─────────────────────────────────────────────────
     * rc == 0 is THE assertion of this section: the commit still
     * completes. Under a patch that halted or returned -1 here, the
     * substring assertion below would still pass and only this would go
     * red. */
    {
        static char out[CAP_BUF];
        nodus_witness_t *w = NULL;
        int rc = -1;
        commit_leg(true, out, sizeof(out), &w, &rc);

        CHECK(pbft_row(w, NULL, NULL) == -1,
              "the injected fault is still in force — pbft_state is gone");
        CHECK(said(out, SAY_COMMIT),
              "FAULTED: the loss is REPORTED, and the line names the "
              "cleared prepared slot as the thing lost");
        CHECK(said(out, "height=7") && said(out, "view=2"),
              "and names the stale certificate that will survive the "
              "restart");
        CHECK(said(out, "re-attach to a VIEW_CHANGE"),
              "and states the consequence rather than only the failure");

        CHECK(rc == 0,
              "control: the commit STILL completed — a lost bookkeeping "
              "row does not undo a durable block");
        CHECK(count_rows(w, "SELECT COUNT(*) FROM blocks") == 1,
              "control: the block is STILL durable — no rollback");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "control: the propose-wait deadman was STILL disarmed — "
              "execution continued past the failed save");
        CHECK(w->bft_config.n_witnesses == N_PEERS &&
              w->bft_config.quorum == Q_HEALTHY,
              "control: the post-commit bft_config refresh STILL ran to "
              "the end, exactly as in the healthy leg");
        CHECK(!w->safety_halt,
              "control: safety_halt is NOT latched — this is a log, not a "
              "halt, and a transient disk fault does not remove this node "
              "from consensus");

        commit_fixture_free(w);
    }
}

int main(void) {
    printf("\nO15O Faz 3 — a lost pbft_state write is never silent\n");

    for (int i = 0; i < N_PEERS; i++) peer_make(&g_peers[i]);

    section_successor_commit();
    section_prepared_cert();
    section_new_view();
    section_commit_batch();

    printf("\nO15O Faz 3 PASS (all 4 save sites covered; no UNREACHED "
           "rows)\n");
    return 0;
}
