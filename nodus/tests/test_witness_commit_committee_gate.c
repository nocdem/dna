/**
 * Nodus — O15O Faz 4 — a COMMIT is authorized by the COMMITTEE, not the
 *                      transport roster
 *
 * WHAT THIS PROVES.
 *   nodus_witness_bft_handle_commit had NO sender-committee check of any
 *   kind. Five of the six T3 consumers in nodus_witness_bft.c already
 *   resolved the chain-derived committee and measured the sender against
 *   it (handle_propose, bft_handle_vote_inner, handle_viewchg,
 *   handle_viewok, handle_viewok_req, handle_newview); this one authorized
 *   its sender on w->roster alone, at the dispatch layer
 *   (nodus_witness.c:2035-2083). The roster is fed from self-published DHT
 *   `nodus:pk` records whose only admission tests are signature validity,
 *   expiry and dedup — no committee filter (nodus_witness_peer.c) — so a
 *   T3 sender identity costs one Dilithium keypair plus one DHT put.
 *   Bug ref: nodus/BUGS.md O15N-L4.
 *
 *   The property that would be false if any section here failed: a COMMIT
 *   frame influences this node's state only if its sender belongs to the
 *   committee governing the height the frame CARRIES — and, where no
 *   committee exists yet, only if the sender is on the roster, because the
 *   GENESIS block's COMMIT travels through this same handler and refusing
 *   it would stop the chain from ever starting.
 *
 *   EVERY SECTION IS A PAIR ON ONE FIXTURE, and the pair is the whole
 *   point. "It refused" proves nothing on its own: this handler refuses
 *   for a dozen reasons that have nothing to do with the committee — a
 *   replayed nonce, a wrong chain id, a height that is not ours, a batch
 *   transaction that does not verify. Each section therefore runs the SAME
 *   message twice, moving exactly one thing between the legs (the sender,
 *   the carried height, or the committee state), and asserts the SITE of
 *   the refusal from the diagnostic line rather than from the return code,
 *   which is -1 either way.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro.
 *   DNAC_EPOCH_LENGTH is READ, never assumed: §2 computes its far height
 *   from the macro, so the file behaves identically at the shipped 720 and
 *   at the harness's 15.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no pre-exported variable. The one filesystem dependency
 *   is a writable /tmp for mkdtemp/mkstemp.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Every section builds its chain database in its own mkdtemp()
 *   directory under /tmp and removes it with `rm -rf` before returning.
 *   The stderr-capture files are created with mkstemp and unlinked
 *   immediately, so they exist only as an open descriptor and vanish when
 *   it closes. No processes, no arm files, no restarted nodes. Nothing
 *   here writes to any path outside its own temporary directory.
 *
 * HOW IT CAN LIE.
 *   - THE OBSERVABLE FOR "cert_note WAS NOT REACHED" IS INDIRECT, AND THIS
 *     IS THE FILE'S MOST IMPORTANT CAVEAT. The gate's stated purpose is to
 *     sit ABOVE nodus_witness_v2_cert_note, the first state mutation on
 *     this path. The DIRECT observable would be the certificate pool
 *     (w->v2_certpool), and it is NOT AVAILABLE HERE: cert_note returns
 *     immediately unless w->v2_successor is set
 *     (nodus_witness_v2_produce.c:234), its call site is guarded on the
 *     same flag (nodus_witness_bft.c:7222 — the `if` above the call), and
 *     the flag is legitimately
 *     reachable only by opening a pure-V2 genesis chain
 *     (nodus_witness.c:743-766). Hand-setting it is precisely the masking
 *     that nodus_witness.c:736-738 records a previous test committing, so
 *     this file does not do it — which means BOTH legs of every pair would
 *     show an untouched pool and the assertion would measure nothing.
 *     What is asserted instead is the pair:
 *       (a) the ADMITTED leg travels PAST the gate and prints a line from
 *           a site strictly BELOW cert_note (the F02 batch re-verify,
 *           nodus_witness_bft.c:7447 — the same marker
 *           test_witness_height_fault_consumers.c §4 uses, and reached
 *           only by passing everything above it);
 *       (b) the REFUSED leg prints the gate's own line and NONE of the
 *           lines below it.
 *     The gate returns immediately after printing, and its refusal lines
 *     are textually above the cert_note call (gate 7102-7211, cert_note
 *     7222), so (b) plus that ordering is what pins "no residue". It is a
 *     weaker instrument than reading the pool, it is named as such, and it
 *     would NOT catch a future edit that moved cert_note above the gate.
 *   - THE VACUITY TRAP. A gate that refused everything would pass every
 *     refusal leg in this file. The admitted legs are what exclude it, and
 *     §3 is the load-bearing one: it asserts that a roster member with NO
 *     committee at all is ADMITTED. A build that fails §3 while passing
 *     §1 and §4 is a build in which no chain can reach block 1.
 *   - THE HEIGHT SOURCE COULD BE INVISIBLE. At a carried height inside
 *     epoch 0 the gate's answer is identical whether it resolves at the
 *     carried height or at the local tip, because both land in epoch 0.
 *     §2 exists only to separate them and is the sole section whose
 *     verdict depends on the height ARGUMENT rather than on the sender.
 *   - THE REPLAY TRAP. Every section delivers several COMMITs. is_replay()
 *     keys on (sender_id, nonce) in a PROCESS-GLOBAL table, so every
 *     message must carry a fresh nonce or it dies at the replay gate ABOVE
 *     the committee gate and the section proves nothing. fill_header
 *     re-randomises on every call; nothing here reuses a filled header.
 *   - THE STDERR ASSERTIONS ARE TEXT MATCHES, and text can be edited. That
 *     is brittleness, not a lie: an edited message fails this test loudly
 *     instead of letting it pass quietly. The substrings are ASCII-only
 *     (the production lines contain em-dashes) and unique to the guard
 *     they name.
 *   - THE ADMITTED LEGS ALL END IN -1, and that is the PRE-EXISTING
 *     outcome for this fixture, not a new expectation. A genuine ACCEPT is
 *     out of reach for a unit fixture: past the gate the handler
 *     re-verifies every batch transaction through
 *     nodus_witness_verify_transaction in VALIDATION mode, which demands
 *     real Dilithium5-signed spend payloads or a complete genesis
 *     transaction. test_witness_height_fault_consumers.c §4 declined to
 *     build one for the same reason and drew its pair one step earlier;
 *     this file does the same, and "admitted" here means exactly "reached
 *     the F02 verify", never "committed a block".
 *   - WHAT IT CANNOT SEE. The dispatch-layer wsig verify is still bound to
 *     the roster and is NOT covered here — that residual is deliberate and
 *     recorded at nodus_witness.c:2047. Nothing in this file exercises a
 *     real T3 frame decode, a socket, or the successor (V2) commit path.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"             /* nodus_random               */
#include "transport/nodus_tcp.h"           /* nodus_time_now             */
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"        /* DNAC_EPOCH_LENGTH, DNAC_PROTOCOL_VERSION */
#include "dnac/vset_wire.h"   /* DNA_VSET_HASH_LEN — the fault row        */

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

/* Seven seated peers is the shipped devnet size and sits above
 * NODUS_T3_MIN_WITNESSES, so the fixture's bft_config is one the
 * production initialiser would actually serve. The committee primed over
 * it is FIVE, which leaves peers 5 and 6 on the roster and outside the
 * committee — the exact identity class this gate exists to refuse. Peer 7
 * is never seated at all and is the "unknown sender" control. */
#define N_ROSTER    7
#define N_COMMITTEE 5
#define P_MEMBER    1   /* roster AND committee                            */
#define P_OUTSIDER  5   /* roster, NOT committee — the attacker's identity */
#define P_UNSEATED  7   /* not even on the roster                          */
#define N_KEYS      8

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_witness_quorum_vacuum.c and
 * test_witness_height_fault_consumers.c, this season's own models.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of this file, so the identities
 * are generated ONCE in main and reused by every section. Nothing in a
 * section mutates them. */
static peer_t g_peers[N_KEYS];

static void peer_make(peer_t *p) {
    if (qgp_dsa87_keypair(p->pk, p->sk) != 0) {
        fprintf(stderr, "keygen failed\n"); exit(1);
    }
    /* The production voter-id derivation: SHA3-512(pubkey)[0..31]
     * (nodus_identity.c:42). */
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
 * "(roster %d, ...)" assertion in §2 relies on.
 *
 * nodus_witness_t is multi-MB: heap, never stack (repo discipline). The
 * chain database is REAL and its validator table is EMPTY, which is the
 * (rc 0, count 0) pre-genesis answer §3 depends on. */
static nodus_witness_t *fixture(char *dir_template, uint8_t tag) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!w || !srv) { fprintf(stderr, "fixture alloc\n"); exit(1); }

    memcpy(srv->identity.pk.bytes, g_peers[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, g_peers[0].sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, g_peers[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i < N_ROSTER; i++) roster_put(w, &g_peers[i]);

    /* `tag` becomes the 16-byte chain_id (zero-filled to 32 by
     * set_chain_id), so it is NONZERO and verify_chain_id's "we hold an
     * identity, we enforce it" row applies — which is what lets every
     * crafted message carry w->chain_id and reach the committee gate. */
    if (mkdtemp(dir_template) == NULL) {
        fprintf(stderr, "mkdtemp failed\n"); exit(1);
    }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_template);
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0 || !w->db) {
        fprintf(stderr, "create_chain_db failed\n"); exit(1);
    }

    /* THE CACHE SENTINEL, and it is load-bearing: a calloc'd witness has
     * cached_committee_epoch_start == 0, and most sections here query
     * epoch 0. Left at the zero, nodus_committee_get_for_block takes its
     * cache-HIT branch and answers (rc 0, count 0) without ever reading
     * the database — §4's armed fault would silently become a second
     * pre-genesis control. Production sets this to UINT64_MAX at init for
     * the same reason. Set AFTER create_chain_db so nothing it does can
     * undo it. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;

    /* Nothing on the COMMIT path reads the quorum above the gate, but the
     * F02 batch re-verify below it runs against a real config; initialise
     * it through the PRODUCTION initialiser rather than by hand. */
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);
    return w;
}

static void fixture_free(nodus_witness_t *w, const char *dir) {
    if (w) {
        /* handle_commit appends no view-change record, so this loop is
         * defensive rather than required; it is the only correct reset if
         * a future section ever drives one. */
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

/* Prime the legacy committee resolver's per-epoch cache with peers [0..n)
 * for the epoch CONTAINING `height`. nodus_committee_get_for_block answers
 * from this cache before it touches the database, and
 * load_committee_at_height_alloc — the resolver the gate under test calls
 * — goes through that accessor. So this makes the governing committee a
 * deterministic, DB-free input whose membership the test controls.
 *
 * Parametric in DNAC_EPOCH_LENGTH: the epoch start is COMPUTED, never
 * assumed, so a short-epoch build primes the same set. Copied from
 * prime_committee in test_witness_quorum_vacuum.c. */
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

/** Invalidate the per-epoch cache so the NEXT lookup reads the database. */
static void cache_reset(nodus_witness_t *w) {
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;
}

/** ARM a committee LOAD FAULT: a validator_set_snapshots row for
 *  `epoch_start` whose stored hash does not match its stored blob.
 *  nodus_committee_get_for_block turns that into its documented
 *  fail-closed -1 (nodus_witness_committee.c:618-627) and explicitly
 *  refuses to recompute a substitute set.
 *
 *  ⚠ THIS IS NOT A `DROP TABLE`, DELIBERATELY. A dropped table is
 *  ABSENCE, and absence of a snapshot is a documented, legitimate answer
 *  here — the loader falls through to the legacy recompute
 *  (nodus_witness_committee.c:628) and returns a COMMITTED "no committee"
 *  rather than a fault, which is a different section's subject entirely
 *  (§3). A corrupt row is the repo's own proven committee-load fault and
 *  it is REVERSIBLE, which is what lets §4 be an A/B on one fixture.
 *  Copied from arm_committee_fault in test_bft_roster_committee.c:339. */
static void arm_committee_fault(nodus_witness_t *w, uint64_t epoch_start) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO validator_set_snapshots "
            "(epoch_start, active_count, snapshot_hash, snapshot_blob, "
            " created_at_height) VALUES (?, 1, ?, ?, 0)", -1, &st, NULL)
        != SQLITE_OK) {
        fprintf(stderr, "arm prepare failed\n"); exit(1);
    }
    uint8_t bad_hash[DNA_VSET_HASH_LEN];
    memset(bad_hash, 0xF0, sizeof(bad_hash));
    uint8_t blob[16];
    memset(blob, 0x5A, sizeof(blob));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    sqlite3_bind_blob (st, 2, bad_hash, (int)sizeof(bad_hash), SQLITE_STATIC);
    sqlite3_bind_blob (st, 3, blob, (int)sizeof(blob), SQLITE_STATIC);
    if (sqlite3_step(st) != SQLITE_DONE) {
        fprintf(stderr, "arm step failed\n"); exit(1);
    }
    sqlite3_finalize(st);
    cache_reset(w);
}

/** DISARM: delete the corrupt row, restoring the pre-genesis answer. */
static void disarm_committee_fault(nodus_witness_t *w, uint64_t epoch_start) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "DELETE FROM validator_set_snapshots WHERE epoch_start = ?",
            -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "disarm prepare failed\n"); exit(1);
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    if (sqlite3_step(st) != SQLITE_DONE) {
        fprintf(stderr, "disarm step failed\n"); exit(1);
    }
    sqlite3_finalize(st);
    cache_reset(w);
}

/** Ask the loader directly what the gate is about to be told. */
static int committee_probe(nodus_witness_t *w, uint64_t height,
                             int *count_out) {
    nodus_committee_member_t *tmp =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*tmp));
    if (!tmp) { fprintf(stderr, "probe alloc\n"); exit(1); }
    int rc = nodus_committee_get_for_block(w, height, tmp,
                                             DNAC_MAX_ACTIVE_VALIDATORS,
                                             count_out);
    free(tmp);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-guard resolution.
 *
 * Every refusal on this path returns -1, so the return code alone cannot
 * say WHICH guard fired. The refusal line can. In a nodus build QGP_LOG_*
 * resolves to nodus/src/nodus_log_shim.c, whose qgp_log_ring_add writes
 * straight to stderr, and the gate under test uses a bare fprintf(stderr,
 * ...) anyway — so fd 2 carries both.
 *
 * The window wraps ONLY the call under test and stderr is restored BEFORE
 * anything is asserted: a CHECK that failed inside the window would write
 * its diagnosis into the temp file and the binary would exit 1 saying
 * nothing. Copied from test_witness_quorum_vacuum.c.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_ccg_XXXXXX";
    g_cap_fd = mkstemp(tmpl);
    if (g_cap_fd < 0) { fprintf(stderr, "mkstemp failed\n"); exit(1); }
    if (unlink(tmpl) != 0) {          /* leaves nothing behind */
        fprintf(stderr, "unlink failed\n"); exit(1);
    }
    fflush(stderr);
    g_cap_saved = dup(2);
    if (g_cap_saved < 0) { fprintf(stderr, "dup(2) failed\n"); exit(1); }
    if (dup2(g_cap_fd, 2) < 0) { fprintf(stderr, "dup2 failed\n"); exit(1); }
}

#define CAP_BUF 65536

/* Restore fd 2 and copy the window's output into `dst`.
 *
 * ⚠ THE DESTINATION IS CALLER-OWNED ON PURPOSE. Every section holds one
 * leg's text while capturing the next; a shared static buffer would
 * silently overwrite the first, and every "the admitted leg did NOT say X"
 * assertion would then be made against the wrong output. */
static void cap_end(char *dst, size_t cap) {
    fflush(stderr);
    if (g_cap_saved >= 0) {
        if (dup2(g_cap_saved, 2) < 0) _exit(1);
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

/* ── The lines the assertions key on. ASCII only: the production messages
 *    carry em-dashes, which must never appear in a needle. ───────────── */
#define L_NONMEMBER "COMMIT from non-committee sender"
#define L_UNKNOWN   "COMMIT from unknown sender_id"
#define L_LOADFAULT "CANNOT ESTABLISH THE COMMITTEE at height"
/* The marker for "the frame travelled BELOW nodus_witness_v2_cert_note".
 * Emitted by the F02 batch re-verify (nodus_witness_bft.c:7447), which is
 * reachable only by passing every guard above it — the same marker
 * test_witness_height_fault_consumers.c:809 uses for the same purpose. */
#define L_BELOW     "commit-path verify rejected batch TX"
/* The A2 height guard's loud line (nodus_witness_bft.c). §2 asserts its
 * ABSENCE: a gate resolving the LOCAL tip would have admitted §2's far
 * COMMIT and let it reach this guard instead. */
#define L_MISMATCH  "height mismatch"

/* ═══════════════════════════════════════════════════════════════════
 * Message builder
 * ═══════════════════════════════════════════════════════════════════ */

/* A transaction well-formed enough to REACH the F02 verify and be rejected
 * there BY NAME. The version byte is deliberately one past the accepted
 * one, so the reject is the cheap wire-version gate rather than a
 * NULL-pointer path — deterministic, and it depends on no signature
 * material. Taken from test_witness_height_fault_consumers.c:777-779. */
static uint8_t g_bogus_tx[8];

/* One COMMIT frame from `from`, carrying `bh` as its block height. The
 * nonce is re-randomised on every call because is_replay() keys on
 * (sender_id, nonce) in a PROCESS-GLOBAL table: a second message reusing
 * the first one's nonce dies at the replay gate, ABOVE the committee gate,
 * and the section would prove nothing. */
static void build_commit(nodus_t3_msg_t *m, const nodus_witness_t *w,
                         const peer_t *from, uint64_t bh) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_COMMIT;
    m->header.round = 1;          /* > last_committed_round (0)            */
    m->header.view = 0;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    if (nodus_random((uint8_t *)&m->header.nonce,
                     sizeof(m->header.nonce)) != 0) {
        fprintf(stderr, "nonce failed\n"); exit(1);
    }

    m->commit.block_height = bh;
    m->commit.batch_count = 1;
    m->commit.n_precommits = 0;   /* below the bh>=2 cert-quorum gate      */
    m->commit.proposal_timestamp = nodus_time_now();
    memcpy(m->commit.proposer_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memset(m->commit.tx_root, 0xC5, NODUS_T3_TX_HASH_LEN);
    memset(m->commit.batch_txs[0].tx_hash, 0xC4, NODUS_T3_TX_HASH_LEN);
    m->commit.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    m->commit.batch_txs[0].tx_data = g_bogus_tx;
    m->commit.batch_txs[0].tx_len = (uint32_t)sizeof(g_bogus_tx);
}

/* Deliver one COMMIT and capture the window. */
static int deliver(nodus_witness_t *w, const peer_t *from, uint64_t bh,
                   char *out, size_t cap) {
    nodus_t3_msg_t m;
    build_commit(&m, w, from, bh);
    cap_begin();
    int rc = nodus_witness_bft_handle_commit(w, &m);
    cap_end(out, cap);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — THE PAIR. One committee, two senders, one message shape.
 *
 * The committee at the carried height is peers [0..5). Peer 1 is in it;
 * peer 5 is on the ROSTER and outside it — the identity an attacker mints
 * for one keypair and one DHT put. Before this gate the two were
 * indistinguishable to this handler.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_member_vs_outsider(void) {
    printf("\n§1 the pair — a roster member outside the committee is "
           "refused, above the first state mutation\n");

    char dir[] = "/tmp/test_ccg_pair_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x11);

    /* An empty chain: tip 0, so the carried height 1 is also OUR next
     * height and the A2 height guard below cannot be what refuses. */
    CHECK(nodus_witness_block_height(w) == 0,
          "precondition: the fixture chain is empty, so height 1 is our "
          "own next block and no height guard can fire");

    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: the governing committee at height 1 has five "
          "members, so the gate has a real set to measure against");

    static char out_member[CAP_BUF];
    static char out_outsider[CAP_BUF];

    /* ── ADMITTED LEG. The anti-vacuity control: without it, a gate that
     * refused every COMMIT would pass the refusal leg below. */
    int rc_member = deliver(w, &g_peers[P_MEMBER], 1,
                            out_member, sizeof(out_member));
    CHECK(rc_member == -1,
          "ADMITTED: the committee member's COMMIT still ends in -1 — the "
          "PRE-EXISTING outcome for this fixture, refused by the batch "
          "verify no unit fixture can satisfy (see the file header)");
    CHECK(said(out_member, L_BELOW),
          "and it GOT THERE: reaching the F02 batch re-verify is possible "
          "only by passing the committee gate, and that site is BELOW "
          "nodus_witness_v2_cert_note");
    CHECK(!said(out_member, L_NONMEMBER) && !said(out_member, L_LOADFAULT) &&
          !said(out_member, L_UNKNOWN),
          "and no committee gate fired on it");

    /* ── REFUSED LEG. Same fixture, same committee, same message shape,
     * same carried height — the SENDER is the only thing that moved.
     *
     * The committee is re-established and re-probed rather than assumed to
     * have survived the leg above. The admitted leg runs a batch verify
     * whose internals this file does not own, and the per-epoch cache is a
     * single slot with no invalidation hook: if anything down there had
     * reset it, this leg would silently resolve count 0, take the
     * pre-genesis bootstrap and ADMIT — and the section would report a
     * failure whose cause is the fixture, not the gate. Making the input
     * explicit removes that unstated dependency. */
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "the committee governing this leg is the SAME five-member set "
          "the admitted leg ran against");

    int rc_outsider = deliver(w, &g_peers[P_OUTSIDER], 1,
                              out_outsider, sizeof(out_outsider));
    CHECK(rc_outsider == -1,
          "REFUSED: a roster member outside the committee is turned away");
    CHECK(said(out_outsider, L_NONMEMBER),
          "and the refusal NAMES the committee gate — not the height gate, "
          "not the batch verify");
    CHECK(!said(out_outsider, L_BELOW),
          "IT NEVER REACHED THE F02 VERIFY, which sits below "
          "nodus_witness_v2_cert_note — so nothing below the gate ran");
    /* NOT asserted here: the absence of the height-guard lines. At this
     * carried height they cannot fire on EITHER leg (bh == tip + 1 and
     * bh != 0), so the assertion would hold with the gate deleted. §2 is
     * where the height guards are separated from the committee gate. */

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — THE HEIGHT IS THE ONE THE MESSAGE CARRIES, not this node's tip.
 *
 * Authority comes from the evidence, not from where the reader stands:
 * two nodes at different tips must not reach different verdicts on
 * identical bytes. Inside epoch 0 that distinction is INVISIBLE, because
 * the carried height and the local tip+1 land in the same epoch and the
 * gate answers identically either way. This section is the only place the
 * two are separated, and it is the revert-detector for the height
 * ARGUMENT specifically.
 *
 * The construction: the committee is primed for the epoch containing
 * E+1 (E = DNAC_EPOCH_LENGTH, read from the macro) and EXCLUDES peer 5.
 * The local tip stays 0, so tip+1 is 1, which is epoch 0 — an epoch with
 * NO primed committee and an EMPTY validator table, i.e. the pre-genesis
 * answer that ADMITS any roster member. A gate reading the local tip
 * therefore admits peer 5; a gate reading the carried height refuses it.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_carried_height(void) {
    printf("\n§2 the height source — the gate resolves at the CARRIED "
           "height\n");

    char dir[] = "/tmp/test_ccg_height_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x22);

    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t bh_far = E + 1ULL;      /* epoch start E, never epoch 0 */

    CHECK(nodus_witness_block_height(w) == 0,
          "precondition: the local tip is 0, so a tip-reading gate would "
          "resolve epoch 0 while the carried height resolves epoch E");

    prime_committee(w, bh_far, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, bh_far, &count) == 0 && count == N_COMMITTEE,
          "precondition: the FAR epoch has a five-member committee");

    static char out_far[CAP_BUF];
    static char out_near[CAP_BUF];

    /* ── The far leg FIRST. Running the near leg first would overwrite the
     * single-slot epoch cache with epoch 0 and this leg would then miss,
     * read the empty database and admit — the very outcome it must not
     * produce. Order is load-bearing and is why it is stated here. */
    int rc_far = deliver(w, &g_peers[P_OUTSIDER], bh_far,
                         out_far, sizeof(out_far));
    CHECK(rc_far == -1,
          "CARRIED: a COMMIT naming a height whose committee excludes the "
          "sender is refused");
    CHECK(said(out_far, L_NONMEMBER),
          "and the refusal is the committee gate's");

    /* The gate prints the height it RESOLVED AT. Asserting the number is
     * what separates "refused" from "refused for the right reason": a gate
     * reading the local tip would have printed 1. */
    char needle[64];
    snprintf(needle, sizeof(needle), "height %llu)",
             (unsigned long long)bh_far);
    CHECK(said(out_far, needle),
          "and it NAMES THE CARRIED HEIGHT — the number in the diagnostic "
          "is the message's, not this node's tip+1");
    CHECK(!said(out_far, L_MISMATCH),
          "it never reached the A2 height guard, which is where a carried "
          "height far from our tip would otherwise have been caught");

    /* ── THE SAME SENDER AT THE LOCAL-TIP EPOCH IS ADMITTED. This is the
     * half that makes the leg above mean something: peer 5 is not
     * intrinsically refused, it is refused AT THAT HEIGHT. A gate wired to
     * the local tip would have produced this outcome for BOTH legs. */
    int rc_near = deliver(w, &g_peers[P_OUTSIDER], 1,
                          out_near, sizeof(out_near));
    CHECK(rc_near == -1,
          "NEAR: the same sender at height 1 also ends in -1 — but the "
          "reason is what this leg is about");
    CHECK(!said(out_near, L_NONMEMBER),
          "THE SAME SENDER IS ADMITTED at the local-tip epoch, where the "
          "validator table is empty and the pre-genesis bootstrap applies "
          "— so the far refusal is a function of the CARRIED HEIGHT alone");
    CHECK(said(out_near, L_BELOW),
          "and it travelled below the gate, to the F02 verify");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — PRE-GENESIS: THE GENESIS COMMIT IS NOT BLOCKED.
 *
 * ⚠ THE MOST IMPORTANT SECTION IN THIS FILE. The GENESIS block's COMMIT
 * travels through this handler, and pre-genesis every node resolves an
 * EMPTY committee — at the same moment, because they are all in that
 * state at once. A gate that dropped on count == 0 (which is what
 * handle_viewok deliberately does for its own, different reason,
 * nodus_witness_bft.c:9401-9413) would therefore not fail one node: it
 * would mean no chain could ever reach block 1, on every node
 * simultaneously.
 *
 * The F17 A5 bootstrap is the documented authorization here: roster
 * membership. Genesis security comes from genesis_verify (Rule P —
 * distinct pubkeys, supply invariant) and honest majority, not from
 * committee gating.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_pregenesis_bootstrap(void) {
    printf("\n§3 pre-genesis — an empty committee does NOT block genesis\n");

    char dir[] = "/tmp/test_ccg_pregen_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x33);

    /* No prime_committee anywhere in this section: the validator table is
     * empty, which is a COMMITTED answer, not a fault. */
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == 0,
          "precondition: an empty validator table is a COMMITTED "
          "'no committee yet' answer — rc 0 with count 0, NOT a fault");

    static char out_member[CAP_BUF];
    static char out_outsider[CAP_BUF];
    static char out_unseated[CAP_BUF];

    /* The genesis block's own height. */
    int rc_member = deliver(w, &g_peers[P_MEMBER], 1,
                            out_member, sizeof(out_member));
    CHECK(rc_member == -1,
          "the COMMIT at the genesis height still ends in -1 — the batch "
          "verify, which is as far as any unit fixture reaches");
    CHECK(!said(out_member, L_NONMEMBER) && !said(out_member, L_LOADFAULT),
          "NO COMMITTEE GATE FIRED: with no committee to measure against, "
          "the gate must not refuse — dropping here is a cluster-wide "
          "stall at block 1, not a node-local one");
    CHECK(said(out_member, L_BELOW),
          "and the frame travelled BELOW the gate, to the F02 verify");

    /* The peer that §1 refuses. Pre-genesis there is no committee to be
     * outside OF, so it must be admitted here — which is exactly what
     * makes the bootstrap a bootstrap and not a narrower whitelist. */
    int rc_outsider = deliver(w, &g_peers[P_OUTSIDER], 1,
                              out_outsider, sizeof(out_outsider));
    CHECK(rc_outsider == -1 && !said(out_outsider, L_NONMEMBER) &&
          said(out_outsider, L_BELOW),
          "the SAME sender §1 refuses is ADMITTED pre-genesis: the "
          "bootstrap admits every roster member, so a genesis round is not "
          "narrowed to some subset of the cluster");

    /* ── THE ANTI-VACUITY CONTROL. Without it, a gate deleted outright
     * would pass both legs above. An identity that is not on the roster at
     * all is still refused, so the gate IS live in this fixture. */
    int rc_unseated = deliver(w, &g_peers[P_UNSEATED], 1,
                              out_unseated, sizeof(out_unseated));
    CHECK(rc_unseated == -1 && said(out_unseated, L_UNKNOWN),
          "CONTROL: an identity absent from the roster is refused even "
          "pre-genesis — the gate is present and running, so the two "
          "admissions above are decisions, not an absent check");
    CHECK(!said(out_unseated, L_BELOW),
          "and it never reached the F02 verify");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — A LOAD FAULT IS THE ABSENCE OF AN ANSWER, AND FAILS CLOSED.
 *
 * rc != 0 from load_committee_at_height_alloc is NOT an empty committee:
 * it is a node that cannot NAME its authority (nodus_witness_bft.c:628-665
 * separates the two). Accepting a COMMIT there would authorize the sender
 * on the transport roster — G4's exact prohibition — reached through a
 * disk fault rather than through a forged message.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_load_fault(void) {
    printf("\n§4 a committee LOAD FAULT refuses the commit\n");

    char dir[] = "/tmp/test_ccg_fault_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x44);

    static char out_before[CAP_BUF];
    static char out_armed[CAP_BUF];
    static char out_after[CAP_BUF];

    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == 0,
          "BASELINE: the loader answers the pre-genesis case cleanly");

    int rc_before = deliver(w, &g_peers[P_MEMBER], 1,
                            out_before, sizeof(out_before));
    CHECK(rc_before == -1 && said(out_before, L_BELOW) &&
          !said(out_before, L_LOADFAULT),
          "CONTROL: on a readable chain the COMMIT passes the gate and "
          "reaches the F02 verify");

    arm_committee_fault(w, /*epoch_start*/ 0);
    count = -1;
    CHECK(committee_probe(w, 1, &count) == -1,
          "ARMED: a committed snapshot row that fails its own hash "
          "cross-check is a FAULT — the loader fails closed and never "
          "recomputes a substitute set");

    int rc_armed = deliver(w, &g_peers[P_MEMBER], 1,
                           out_armed, sizeof(out_armed));
    CHECK(rc_armed == -1,
          "FAULTED: a node that cannot establish its committee refuses "
          "the commit");
    CHECK(said(out_armed, L_LOADFAULT),
          "and the refusal NAMES the load fault and the height, rather "
          "than falling back to the transport roster");
    CHECK(!said(out_armed, L_BELOW),
          "it never reached the F02 verify — so nothing below the gate "
          "ran on an unauthorizable frame");

    disarm_committee_fault(w, /*epoch_start*/ 0);
    int rc_after = deliver(w, &g_peers[P_MEMBER], 1,
                           out_after, sizeof(out_after));
    CHECK(rc_after == -1 && said(out_after, L_BELOW) &&
          !said(out_after, L_LOADFAULT),
          "the refusal is a function of the FAULT, not a latched flag — "
          "clearing it restores the admitted path");

    fixture_free(w, dir);
}

int main(void) {
    printf("\nO15O Faz 4 — the COMMIT sender is authorized by the "
           "COMMITTEE\n");

    for (int i = 0; i < N_KEYS; i++) peer_make(&g_peers[i]);

    memset(g_bogus_tx, 0, sizeof(g_bogus_tx));
    g_bogus_tx[0] = (uint8_t)(DNAC_PROTOCOL_VERSION + 1);

    section_member_vs_outsider();
    section_carried_height();
    section_pregenesis_bootstrap();
    section_load_fault();

    printf("\nO15O Faz 4 PASS — all four sections ran; no section is "
           "skipped and none is UNREACHED\n");
    return 0;
}
