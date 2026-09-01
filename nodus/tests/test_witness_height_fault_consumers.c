/**
 * Nodus — O15O Faz 1 — the CONSUMERS refuse when the chain height faults
 *
 * WHAT THIS PROVES.
 *   test_witness_block_height_checked pins the ACCESSOR's two-valued
 *   contract. This file pins the thing that contract exists FOR: that
 *   the consensus call sites converted in O15O Faz 1 actually READ the
 *   return code and refuse on it. Those two are independent facts, and
 *   only the first was covered — a build with every fault return in
 *   nodus_witness_block_height_checked reverted to the old fail-open
 *   (`*out = 0; return 0;`) turned exactly ONE test of 215 red, the
 *   accessor's own. Every converted consumer passed. This file is what
 *   makes that build fail.
 *
 *   The property that would be false if any section here failed: a
 *   witness whose chain-height query does not run still refuses to lead,
 *   to open a round, to accept a proposal, to apply a remote COMMIT and
 *   to authorize a view change — instead of proceeding as though its
 *   chain were at genesis and resolving the committee, the quorum, the
 *   leader index and the signed PREPARED anchor for height 1.
 *
 *   EVERY CONSUMER GETS A PAIR ON THE SAME FIXTURE, and the pair is the
 *   whole point. "The call returned -1" proves nothing on its own: a
 *   witness fixture can refuse for a dozen reasons that have nothing to
 *   do with the height read — a phase that is not IDLE, a sender that is
 *   not the leader, a view that does not match, a replayed nonce. The
 *   HEALTHY leg is what excludes all of them: the same fixture, the same
 *   message, the same call, with the chain readable — and the consumer
 *   does its normal thing. Only then does the FAULTED leg's refusal mean
 *   what it says.
 *
 *   THE CHAIN IS DELIBERATELY EMPTY (tip 0), and that is the second
 *   half of the design. It makes the FAIL-OPEN ANSWER EQUAL THE TRUE
 *   ANSWER: a build that answers 0 on a fault answers exactly what the
 *   healthy leg answers, so no downstream height comparison — not the
 *   A2 `prop->block_height == local + 1` check, not the COMMIT height
 *   symmetry check, not the epoch that selects the leader index — can
 *   rescue it by rejecting for some other reason. The faulted leg can
 *   only stay green if the consumer genuinely distinguishes the RETURN
 *   CODE from the value. This is the exact opposite of the choice
 *   test_bft_view_change_hardening.c's §11 had to make (it needed a
 *   NONZERO tip, because P1's guard is `block_height != 0` and a tip of
 *   0 made every P1 assertion pass for the wrong reason). The two
 *   fixtures want opposite things because they are testing opposite
 *   halves; neither is a shortcut.
 *
 *   Bug ref: nodus/BUGS.md O15N-L2. Rule: nodus/CLAUDE.md, "A DB failure
 *   is never a value."
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro, no
 *   short-epoch DNAC_EPOCH_LENGTH. Every assertion here holds at the
 *   shipped 720 and at the harness's 15 alike, because the fixture chain
 *   never leaves epoch 0.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no
 *   node directories, no pre-exported variable. The one filesystem
 *   dependency is a writable /tmp for mkdtemp/mkstemp.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Each section creates its chain database in its own
 *   mkdtemp() directory under /tmp and removes it with `rm -rf` before
 *   returning. The stderr-capture files are created with mkstemp and
 *   unlinked immediately, so they exist only as an open descriptor and
 *   vanish when it closes. No processes, no arm files, no restarted
 *   nodes.
 *
 *   Deliberately NOT freed: the mempool entries §3 hands to the
 *   follower round-entry path, and any batch §2's leader path still
 *   owns. Ownership of a batch transfers to round_state, whose free
 *   helper is file-static in the implementation, so a test cannot
 *   reclaim them without guessing which leg took them. The leak is
 *   bounded by the number of sections and dies with the process; a wrong
 *   guess would be a double free, which is worse.
 *
 * HOW IT CAN LIE.
 *   - THE VACUITY TRAP, named because it is the one this file exists to
 *     avoid: a consumer that refuses for an unrelated reason is
 *     BYTE-IDENTICAL, at the return code, to one that refuses for the
 *     right one. Every faulted leg here is therefore paired with a
 *     healthy leg on the SAME fixture, and every section additionally
 *     asserts the stderr line that names the SITE of the refusal. Drop
 *     either and the section can pass while testing nothing.
 *   - THE PHASE RESIDUE TRAP. §2 and §3 leave the round in PREVOTE after
 *     their healthy leg, and both start_round and handle_propose refuse
 *     any round that is not IDLE. Without the explicit reset each makes
 *     before its faulted leg, the faulted leg would refuse at the PHASE
 *     gate — under the correct code AND under a fail-open revert — and
 *     the section would be permanently, invisibly green. The resets are
 *     load-bearing and are commented as such at their sites.
 *   - THE REPLAY TRAP. §3, §4 and §5 deliver two messages from the same
 *     handler. is_replay() keys on (sender_id, nonce) in a
 *     process-global table, so the second message MUST carry a fresh
 *     nonce or it dies at the replay gate before the height read is ever
 *     reached. Each site re-randomises.
 *   - THE FAULT COULD HEAL. The fault is a real `DROP TABLE blocks`, so
 *     sqlite3_prepare_v2 genuinely returns "no such table" — no mock, no
 *     stub, no compile-time switch, no injected predicate. If a future
 *     schema change let something re-create `blocks` behind the
 *     accessor's back, the prepare would succeed and every faulted leg
 *     would test nothing. Each section's stderr assertion is the guard:
 *     a healed fault produces a different line (or none) and the section
 *     goes red rather than passing.
 *   - THE STDERR ASSERTIONS ARE TEXT MATCHES, and text can be edited.
 *     That is a brittleness, not a lie: an edited message fails this
 *     test loudly instead of letting it pass quietly. The substrings are
 *     chosen ASCII-only (the messages contain em-dashes) and unique to
 *     the FIRST height gate of each consumer, which is what gives them
 *     per-line resolution.
 *   - WHAT IT CANNOT SEE. handle_propose reads the height at FOUR gates
 *     and start_round at TWO. A table-drop fault is deterministic, so
 *     the FIRST gate always fires and the later ones are unreachable —
 *     no fault can land between two reads of the same dropped table.
 *     Reverting a single later gate in isolation would NOT turn this
 *     file red. It is red for a reverted ACCESSOR (the whole substance
 *     of the phase) and for a reverted FIRST gate at each consumer; the
 *     later gates are covered by argument, not by this test.
 *   - There is no skip path and no rc=99. Every section runs
 *     unconditionally or the binary exits non-zero.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"      /* block_height_checked        */
#include "witness/nodus_witness_mempool.h" /* §2 — entry alloc/free       */
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"             /* nodus_hash / nodus_random   */
#include "transport/nodus_tcp.h"           /* nodus_time_now              */
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"   /* DNAC_EPOCH_LENGTH, DNAC_PROTOCOL_VERSION */

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

/* The cluster this file builds. 7 is the shipped devnet size and, more
 * to the point, it is >= NODUS_T3_MIN_WITNESSES, so
 * refresh_bft_config_from_committee yields a nonzero quorum and
 * nodus_witness_bft_consensus_active is true — without which §2's
 * healthy leg would be refused before it ever reached the height gate. */
#define N_PEERS 7

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_bft_view_change_hardening.c, trimmed to
 * what these five sections actually touch.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of this file, so the seven
 * identities are generated ONCE in main and reused by every section.
 * Nothing in a section mutates them. */
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

/* g_peers[0] is always this node. The roster is filled in array order so
 * `g_peers` and `w->roster.witnesses` share indices — which
 * leader_at() relies on when it resolves a sorted rank back to a peer.
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

    /* §5 reads the quorum directly (handle_viewchg never refreshes the
     * config); §1-§4 have it rewritten from the committee on their first
     * call. 5 is dna_bft_quorum(7). */
    w->bft_config.n_witnesses = N_PEERS;
    w->bft_config.quorum = 5;
    w->bft_config.round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
    w->bft_config.viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;

    /* The per-epoch committee cache has no invalidation hook and is keyed
     * on e_start, so a calloc'd 0 would read as a HIT for epoch 0 before
     * anything had been computed. Reset the sentinel exactly as the
     * production init path does. */
    w->cached_committee_epoch_start = UINT64_MAX;
    return w;
}

/* Create the chain database the section will break. `tag` becomes the
 * 16-byte chain_id; set_chain_id copies 16 and zero-fills to 32, so the
 * result is nonzero and the DG-1 pre-genesis arm of the accessor is NOT
 * the branch under test here — the prepare failure is. */
static void chain_db_open(nodus_witness_t *w, char *dir_template, uint8_t tag)
{
    if (mkdtemp(dir_template) == NULL) {
        fprintf(stderr, "mkdtemp failed\n"); exit(1);
    }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_template);
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0) {
        fprintf(stderr, "create_chain_db failed\n"); exit(1);
    }
}

static void chain_db_drop(nodus_witness_t *w, const char *dir) {
    nodus_witness_close(w);
    free(w->server);
    free(w);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* best-effort cleanup */ }
}

/* THE FAULT. A real DROP TABLE, so sqlite3_prepare_v2 inside
 * nodus_witness_block_height_checked returns SQLITE_ERROR "no such
 * table: blocks" — the same failure a corrupt page or a revoked file
 * permission produces, reached without a mock, a stub or a build flag.
 *
 * v2_blocks is dropped too when the witness is a successor, because that
 * is the table the accessor reads there. No section in this file sets
 * v2_successor (a genuine successor needs the V2 schema installed
 * through nodus_witness_db_migrate_v2s9, never a hand-set flag — a
 * fixture that hand-set it is what this season had to repair), so the
 * second DROP is a guard for a future section rather than live code
 * today. It is written with IF EXISTS so it is a no-op on a legacy
 * chain.
 *
 * The witness schema declares no FOREIGN KEY anywhere (grep
 * nodus_witness.c), so dropping a table cannot cascade into another. */
static void break_chain(nodus_witness_t *w) {
    char *err = NULL;
    const char *sql = w->v2_successor
        ? "DROP TABLE IF EXISTS v2_blocks; DROP TABLE IF EXISTS blocks;"
        : "DROP TABLE blocks;";
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "break_chain: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        exit(1);
    }
    /* Prove the fault is REAL before any consumer is asked about it. If
     * this ever answers 0, every faulted leg below would be testing a
     * healthy chain and would pass for the wrong reason. */
    uint64_t probe = 0xDEADBEEFULL;
    if (nodus_witness_block_height_checked(w, &probe) != 0 &&
        probe == 0xDEADBEEFULL)
        return;
    fprintf(stderr, "break_chain: the accessor did NOT fault after the "
                    "DROP — the injection is broken, not the code\n");
    exit(1);
}

/* The fixture chain must be EMPTY for the fail-open-equals-truth
 * argument in the file header to hold. Asserted, never assumed. */
static void assert_tip_zero(nodus_witness_t *w) {
    uint64_t tip = 0xDEADBEEFULL;
    if (nodus_witness_block_height_checked(w, &tip) != 0 || tip != 0) {
        fprintf(stderr, "fixture chain is not empty (tip=%llu) — the "
                        "fail-open value would differ from the true one\n",
                (unsigned long long)tip);
        exit(1);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Leader helpers — the production predicate answers, never a
 * re-implemented modulus.
 *
 * Witness ids are SHA3-512 over freshly generated ML-DSA keys, so this
 * node's sorted rank is DIFFERENT ON EVERY RUN. A hard-coded view would
 * be a coin flip: the "we lead" leg would silently become the "we do not
 * lead" leg on six runs in seven and the suite would still print PASS.
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

/* Lowest view > 0 at which is_leader answers `want_leader`. Over
 * v = 1..n the modulus visits every seat exactly once, so both answers
 * exist for any roster. */
static uint32_t pick_view(nodus_witness_t *w, bool want_leader) {
    for (uint32_t v = 1; v <= w->roster.n_witnesses; v++) {
        if (is_leader_at(w, v) == want_leader) return v;
    }
    fprintf(stderr, "pick_view: no view with is_leader==%d\n",
            (int)want_leader);
    exit(1);
}

/* The peer that IS the leader at `view` on an empty-committee fixture.
 *
 * ⚠ THE ROSTER FALLBACK IS VERIFIED, NOT ASSUMED. is_leader ranks this
 * node inside the COMMITTEE when a validator-set snapshot exists and
 * inside the SORTED gossip roster when it does not (F17 A5). No section
 * here writes a snapshot, so the second rule applies — but a helper that
 * merely believed that would silently name the wrong peer if it ever
 * stopped being true, and every "the sender is the leader" precondition
 * would be false while the section still printed PASS. So the answer is
 * cross-checked against the production predicate: the peer named here
 * must be US exactly when is_leader says we lead.
 *
 * The rank is resolved through nodus_witness_roster_sorted_at, never by
 * indexing witnesses[] with the seat — that confusion is BUGS.md
 * 2026-08-04. */
static const peer_t *leader_at(nodus_witness_t *w, uint32_t view) {
    uint64_t tip = 0;
    if (nodus_witness_block_height_checked(w, &tip) != 0) {
        fprintf(stderr, "leader_at: height read faulted\n"); exit(1);
    }
    uint64_t next_bh = tip + 1;
    uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;

    int seat = nodus_witness_bft_leader_index(epoch, view,
                                              (int)w->roster.n_witnesses);
    int arr = nodus_witness_roster_sorted_at(&w->roster, seat);
    if (arr < 0 || arr >= N_PEERS) {
        fprintf(stderr, "leader_at: no roster entry at seat %d\n", seat);
        exit(1);
    }
    const peer_t *l = &g_peers[arr];

    bool self_is_leader = is_leader_at(w, view);
    bool named_is_self =
        (memcmp(l->id, w->my_id, NODUS_T3_WITNESS_ID_LEN) == 0);
    if (self_is_leader != named_is_self) {
        fprintf(stderr, "leader_at: disagrees with nodus_witness_bft_is_"
                        "leader at view %u — the committee/roster split "
                        "moved under this helper\n", view);
        exit(1);
    }
    return l;
}

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-gate resolution.
 *
 * Every consumer below refuses with -1 (or `false`) whether it refused
 * at the height gate or three gates later, so the return code alone
 * cannot say WHICH gate fired. The refusal line can. In a nodus build
 * QGP_LOG_* resolves to nodus/src/nodus_log_shim.c, whose
 * qgp_log_ring_add writes straight to stderr, and every gate under test
 * here uses a bare fprintf(stderr, ...) anyway — so fd 2 carries both.
 *
 * The window wraps ONLY the call under test and stderr is restored
 * BEFORE anything is asserted: a CHECK that failed inside the window
 * would write its diagnosis into the temp file and the binary would exit
 * 1 saying nothing.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_hfc_XXXXXX";
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

/* Storage for one captured window. Generously sized: every line these
 * sections assert on is printed at the point of refusal, which is early,
 * so a truncated tail cannot hide one. */
#define CAP_BUF 32768

/* Restore fd 2 and copy everything the window captured into `dst`.
 *
 * ⚠ THE DESTINATION IS CALLER-OWNED ON PURPOSE. An earlier shape returned
 * a pointer into ONE static buffer, and §3-§5 each hold their healthy-leg
 * text while capturing the faulted leg — so the healthy text would have
 * been silently overwritten by the faulted text, and every "the healthy
 * leg did NOT report a height fault" assertion would have been made
 * against the wrong output. Separate storage per leg makes that
 * impossible instead of merely unlikely. */
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

/* ═══════════════════════════════════════════════════════════════════
 * Message builders
 * ═══════════════════════════════════════════════════════════════════ */

/* A fresh header. The nonce is re-randomised on every call because
 * is_replay() keys on (sender_id, nonce) in a PROCESS-GLOBAL table: a
 * second message reusing the first one's nonce dies at the replay gate,
 * above every height gate in this file, and the section it belongs to
 * would then be green for a reason that has nothing to do with O15O. */
static void fill_header(nodus_t3_msg_t *m, nodus_witness_t *w,
                        const peer_t *from, uint64_t round, uint32_t view) {
    m->header.round = round;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
}

/* A heap mempool entry for the leader path. `tag` seeds tx_hash. */
static nodus_witness_mempool_entry_t *mkentry(uint8_t tag) {
    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { fprintf(stderr, "entry alloc\n"); exit(1); }
    memset(e->tx_hash, tag, NODUS_T3_TX_HASH_LEN);
    e->tx_type = NODUS_W_TX_SPEND;
    e->nullifier_count = 0;
    e->tx_len = 8;
    e->tx_data = calloc(1, e->tx_len);
    if (!e->tx_data) { fprintf(stderr, "entry tx_data alloc\n"); exit(1); }
    e->fee = 0;
    return e;
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — nodus_witness_bft_is_leader (bft.c:860)
 *
 * The height read here picks the committee AND, through
 * `epoch = next_bh / DNAC_EPOCH_LENGTH`, the leader index. Answering 0
 * on a failed read used to resolve the committee for height 1 at epoch
 * 0 on a chain that may be thousands of blocks along, so a node with a
 * transient DB fault could conclude it was the leader and PROPOSE.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_is_leader(void) {
    printf("\n§1 is_leader — a node that cannot read its height does not "
           "lead\n");

    nodus_witness_t *w = fixture();
    char dir[] = "/tmp/test_hfc_leader_XXXXXX";
    chain_db_open(w, dir, 0x91);
    assert_tip_zero(w);

    /* HEALTHY LEG. The view is chosen by asking the production
     * predicate, so "we lead here" is a fact about this process rather
     * than an assumption about a run-varying key. */
    uint32_t v_lead = pick_view(w, true);
    w->current_view = v_lead;
    CHECK(nodus_witness_bft_is_leader(w) == true,
          "HEALTHY: with the chain readable we ARE the leader at the "
          "chosen view");

    break_chain(w);

    /* FAULTED LEG. Same witness, same view, same call. Nothing else
     * moved: the committee for epoch 0 is already cached from the
     * healthy leg, so a fail-open build would resolve the SAME committee
     * at the SAME epoch and answer `true` again — which is precisely why
     * this assertion is not vacuous. */
    static char out[CAP_BUF];
    cap_begin();
    bool faulted = nodus_witness_bft_is_leader(w);
    cap_end(out, sizeof(out));

    CHECK(faulted == false,
          "FAULTED: with the chain-height query broken we REFUSE to lead");
    CHECK(said(out, "CANNOT READ THE CHAIN HEIGHT"),
          "and the refusal names the height read as the cause — not the "
          "committee gate that sits below it");

    chain_db_drop(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — bft_start_round_internal (bft.c:4415 first gate, :4493 anchor),
 *      reached through its public wrapper
 *      nodus_witness_bft_start_round_from_entries.
 *
 * A fault at the first gate would set the round's QUORUM from the
 * committee at height 1; a fault at the anchor would make this leader
 * sign a PREPARED preimage no follower can reproduce. Both must abort
 * the round START, leaving `current_round` where it was.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_start_round(void) {
    printf("\n§2 start_round — a round is never opened against an unknown "
           "tip\n");

    nodus_witness_t *w = fixture();
    char dir[] = "/tmp/test_hfc_round_XXXXXX";
    chain_db_open(w, dir, 0x92);
    assert_tip_zero(w);

    uint32_t v_lead = pick_view(w, true);
    w->current_view = v_lead;

    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "precondition: the fixture round is IDLE");
    uint64_t round_before_healthy = w->current_round;

    /* HEALTHY LEG. */
    nodus_witness_mempool_entry_t *e_ok = mkentry(0xA1);
    nodus_witness_mempool_entry_t *entries_ok[1] = { e_ok };
    CHECK(nodus_witness_bft_start_round_from_entries(w, entries_ok, 1) == 0,
          "HEALTHY: with the chain readable the leader OPENS the round");
    CHECK(w->current_round == round_before_healthy + 1,
          "the round counter advanced — the round really was opened, not "
          "merely reported");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
          "and the round entered PREVOTE");
    CHECK(w->round_state.block_height == 1,
          "anchored at tip+1 — the anchor gate's READ produced the value "
          "every cert_sig preimage in this round is signed over");

    /* ⚠ LOAD-BEARING RESET, and the reason is the whole section.
     * start_round refuses any round that is not IDLE (bft.c, the
     * `round_state.phase != NODUS_W_PHASE_IDLE` gate), and that gate sits
     * BELOW the first height gate but ABOVE the round-counter increment.
     * Left in PREVOTE, the faulted leg below would be refused at the
     * PHASE gate under the correct code AND under a fail-open revert —
     * both assertions would pass forever and this section would test
     * nothing.
     *
     * The batch is detached at the same time and freed here, because
     * ownership of the entry array transfers to round_state and the next
     * accepted start_round would free it. Detaching makes that free a
     * no-op, so exactly one owner exists on every path. */
    w->round_state.batch_count = 0;
    w->round_state.batch_entries[0] = NULL;
    w->round_state.phase = NODUS_W_PHASE_IDLE;
    nodus_witness_mempool_entry_free(e_ok);

    uint64_t round_before_fault = w->current_round;

    break_chain(w);

    /* FAULTED LEG. */
    nodus_witness_mempool_entry_t *e_fault = mkentry(0xA2);
    nodus_witness_mempool_entry_t *entries_fault[1] = { e_fault };

    static char out[CAP_BUF];
    cap_begin();
    int rc = nodus_witness_bft_start_round_from_entries(w, entries_fault, 1);
    cap_end(out, sizeof(out));

    CHECK(rc == -1,
          "FAULTED: with the chain-height query broken the leader REFUSES "
          "to open the round");
    CHECK(w->current_round == round_before_fault,
          "and `current_round` is UNCHANGED — the refusal happened before "
          "any round state was touched");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "the round is still IDLE, so the next tick can re-enter cleanly");
    CHECK(said(out, "refusing to open a round against an unknown tip"),
          "and the refusal names the FIRST height gate — the one that "
          "feeds refresh_bft_config_from_committee");

    /* Asserted first, freed second, deliberately: on a fail-open build
     * the call above SUCCEEDS and round_state takes ownership of
     * e_fault, so freeing it would be a double free. The CHECK on rc
     * exits the process before this line is ever reached in that case. */
    nodus_witness_mempool_entry_free(e_fault);

    chain_db_drop(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — nodus_witness_bft_handle_propose (bft.c:5207 first gate, then
 *      :5237, :5376, :5412).
 *
 * The proposal shape is test_bft_view_change_hardening.c §12f's: a
 * single batch entry whose tx_root is the SHA3-512 the handler
 * recomputes. The batch's transaction is not verifiable, which is fine
 * and is what §12f relies on too — the round ENTRY runs before the
 * batch's contents are judged, so the handler still returns 0 and enters
 * PREVOTE. This section is about the round entry, not about transaction
 * validity.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_handle_propose(void) {
    printf("\n§3 handle_propose — a proposal is never judged against an "
           "unknown tip\n");

    nodus_witness_t *w = fixture();
    char dir[] = "/tmp/test_hfc_propose_XXXXXX";
    chain_db_open(w, dir, 0x93);
    assert_tip_zero(w);

    /* A view at which we are NOT the leader, and the peer that is. */
    uint32_t v_follow = pick_view(w, false);
    const peer_t *leader = leader_at(w, v_follow);
    w->current_view = v_follow;
    CHECK(memcmp(leader->id, w->my_id, NODUS_T3_WITNESS_ID_LEN) != 0,
          "precondition: the proposal's sender is a peer, not ourselves");

    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD3, sizeof(ptx));

    nodus_t3_msg_t pm;
    memset(&pm, 0, sizeof(pm));
    pm.type = NODUS_T3_PROPOSE;
    fill_header(&pm, w, leader, /*round*/ 9, v_follow);
    pm.propose.batch_count = 1;
    pm.propose.block_height = 1;           /* == our tip (0) + 1 */
    memcpy(pm.propose.batch_txs[0].tx_hash, ptx, NODUS_T3_TX_HASH_LEN);
    pm.propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    {
        /* tx_root is SHA3-512 over the batch's tx_hashes — the same
         * derivation the handler recomputes before it will accept. */
        nodus_key_t bh;
        if (nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) != 0) {
            fprintf(stderr, "tx_root hash failed\n"); exit(1);
        }
        memcpy(pm.propose.tx_root, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }

    /* HEALTHY LEG. Each leg captures into its OWN buffer — see cap_end. */
    static char out_ok[CAP_BUF];
    static char out_fault[CAP_BUF];

    cap_begin();
    int rc_ok = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out_ok, sizeof(out_ok));

    CHECK(rc_ok == 0,
          "HEALTHY: with the chain readable the leader's proposal is "
          "ACCEPTED into a round");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
          "we entered PREVOTE — every height gate in the handler was "
          "passed, not merely skipped");
    CHECK(w->round_state.block_height == 1,
          "and the round is anchored at the leader-claimed height, which "
          "the A2 check just confirmed equals our own tip+1");
    CHECK(!said(out_ok, "chain-height read faulted"),
          "nothing on the accepted path reported a height fault");

    /* ⚠ LOAD-BEARING RESET — same argument as §2. handle_propose refuses
     * any round that is not IDLE, and that gate sits between the first
     * and second height gates. Left in PREVOTE, the faulted leg would be
     * refused at the PHASE gate on a correct build and on a fail-open
     * one alike, and this section could never go red.
     *
     * The batch entries the handler allocated are left attached: the
     * next accepted PROPOSE frees them through round_state's own helper,
     * and that helper is file-static, so the test must not race it. */
    w->round_state.phase = NODUS_W_PHASE_IDLE;

    break_chain(w);

    /* FAULTED LEG. Fresh nonce — see fill_header. The proposal is
     * otherwise byte-identical, and on a fail-open build it would be
     * accepted exactly as above: the fixture tip is 0, so the fail-open
     * answer and the true answer agree, and the A2 height check cannot
     * reject it for us. */
    fill_header(&pm, w, leader, /*round*/ 9, v_follow);

    cap_begin();
    int rc_fault = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out_fault, sizeof(out_fault));

    CHECK(rc_fault == -1,
          "FAULTED: with the chain-height query broken the proposal is "
          "REFUSED");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "and no round was entered — the refusal is before any round "
          "state is written");
    CHECK(said(out_fault, "refusing rather than refreshing the quorum"),
          "and the refusal names the FIRST height gate — the one feeding "
          "the committee the vote's quorum comes from");

    chain_db_drop(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — nodus_witness_bft_handle_commit (bft.c:7008).
 *
 * This is the guard that stopped US-1's h=114 divergence: it refuses a
 * COMMIT whose height is not ours. A fault answering 0 would make
 * expected_height 1, so a COMMIT at height 1 would be APPLIED on a long
 * chain.
 *
 * ⚠ THE HEALTHY LEG HERE IS WEAKER THAN THE OTHER FOUR, AND SAYS SO. A
 * genuine ACCEPT is out of reach for a unit fixture: past the height
 * gate the handler re-verifies every batch transaction through
 * nodus_witness_verify_transaction in VALIDATION mode (the F02
 * re-verify), which demands real Dilithium5-signed spend payloads or a
 * complete genesis transaction — a builder this file does not have and
 * that test_witness_commit_height_match.c explicitly declined to write
 * for the same reason. The alternatives are all dead ends: batch_count
 * == 0 skips the height gate entirely, and the already-committed early
 * return sits ABOVE it.
 *
 * So the pair is drawn one step earlier and is still a real pair: the
 * healthy leg proves the handler REACHED THE F02 VERIFY, which is only
 * possible by passing the height gate on a readable chain; the faulted
 * leg proves it stopped AT the height gate. Both return -1, so the
 * discrimination is entirely in the diagnostic — which is why both legs
 * assert the presence of one line and the ABSENCE of the other.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_handle_commit(void) {
    printf("\n§4 handle_commit — a remote COMMIT is never applied against "
           "an unknown tip\n");

    nodus_witness_t *w = fixture();
    char dir[] = "/tmp/test_hfc_commit_XXXXXX";
    chain_db_open(w, dir, 0x94);
    assert_tip_zero(w);

    /* A transaction that is well-formed enough to reach the F02 verify
     * and be rejected there by NAME. The version byte is deliberately
     * one past the accepted one, so the reject is the cheap wire-version
     * gate rather than a NULL-pointer path — deterministic, and it does
     * not depend on any signature material. */
    static uint8_t bogus_tx[8];
    memset(bogus_tx, 0, sizeof(bogus_tx));
    bogus_tx[0] = (uint8_t)(DNAC_PROTOCOL_VERSION + 1);

    const peer_t *sender = &g_peers[1];

    nodus_t3_msg_t cm;
    memset(&cm, 0, sizeof(cm));
    cm.type = NODUS_T3_COMMIT;
    fill_header(&cm, w, sender, /*round*/ 1, /*view*/ 0);
    cm.commit.batch_count = 1;
    cm.commit.block_height = 1;            /* == our tip (0) + 1 */
    cm.commit.n_precommits = 0;            /* below the h>=2 cert gate */
    cm.commit.proposal_timestamp = nodus_time_now();
    memcpy(cm.commit.proposer_id, sender->id, NODUS_T3_WITNESS_ID_LEN);
    memset(cm.commit.batch_txs[0].tx_hash, 0xC4, NODUS_T3_TX_HASH_LEN);
    cm.commit.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    cm.commit.batch_txs[0].tx_data = bogus_tx;
    cm.commit.batch_txs[0].tx_len = (uint32_t)sizeof(bogus_tx);
    memset(cm.commit.tx_root, 0xC5, NODUS_T3_TX_HASH_LEN);

    /* HEALTHY LEG. Each leg captures into its OWN buffer — see cap_end. */
    static char out_ok[CAP_BUF];
    static char out_fault[CAP_BUF];

    cap_begin();
    int rc_ok = nodus_witness_bft_handle_commit(w, &cm);
    cap_end(out_ok, sizeof(out_ok));

    CHECK(rc_ok == -1,
          "HEALTHY: the COMMIT is refused — by the batch verify, which "
          "this fixture cannot satisfy (see the section header)");
    CHECK(said(out_ok, "commit-path verify rejected batch TX"),
          "and it got THERE: reaching the F02 re-verify is only possible "
          "by passing the height gate on a readable chain");
    CHECK(!said(out_ok, "chain-height read faulted"),
          "the height gate did not fire on the healthy chain");

    break_chain(w);

    /* FAULTED LEG. Fresh nonce; the round number is unchanged because
     * nothing committed, so `last_committed_round` is still 0 and the
     * already-committed early return above the gate cannot swallow it. */
    fill_header(&cm, w, sender, /*round*/ 1, /*view*/ 0);

    cap_begin();
    int rc_fault = nodus_witness_bft_handle_commit(w, &cm);
    cap_end(out_fault, sizeof(out_fault));

    CHECK(rc_fault == -1,
          "FAULTED: with the chain-height query broken the COMMIT is "
          "REFUSED");
    CHECK(said(out_fault, "commit rejected") &&
          said(out_fault, "chain-height read faulted"),
          "and it stopped AT the height gate, naming it");
    CHECK(!said(out_fault, "commit-path verify rejected batch TX"),
          "it never reached the batch verify — so the refusal is the "
          "height gate's, not the verify's");

    chain_db_drop(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §5 — nodus_witness_bft_handle_viewchg (bft.c:7853).
 *
 * The worst shape of the five before O15L Faz 4: a committee-load
 * failure did not fall back to anything, it ACCEPTED. The height read
 * that selects that committee is the gate here — a fault answering 0
 * would authorize the sender against the height-1 committee and let it
 * drive this node's view rotation from the wrong authority.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_handle_viewchg(void) {
    printf("\n§5 handle_viewchg — a view change is never authorized "
           "against an unknown tip\n");

    nodus_witness_t *w = fixture();
    char dir[] = "/tmp/test_hfc_viewchg_XXXXXX";
    chain_db_open(w, dir, 0x95);
    assert_tip_zero(w);

    CHECK(w->current_view == 0 && w->view_change_count == 0,
          "precondition: no view change has been recorded yet");

    /* HEALTHY LEG — one peer asks for the next view. With quorum 5 the
     * f+1 join threshold is 3, so a single vote records and nothing
     * else happens: no adoption broadcast, no rotation, nothing that
     * would make the faulted leg refuse for a second reason. */
    nodus_t3_msg_t vc;
    memset(&vc, 0, sizeof(vc));
    vc.type = NODUS_T3_VIEWCHG;
    fill_header(&vc, w, &g_peers[1], /*round*/ 0, /*view*/ 0);
    vc.viewchg.new_view = 1;
    vc.viewchg.last_committed_round = w->last_committed_round;

    /* Each leg captures into its OWN buffer — see cap_end. */
    static char out_ok[CAP_BUF];
    static char out_fault[CAP_BUF];

    cap_begin();
    int rc_ok = nodus_witness_bft_handle_viewchg(w, &vc);
    cap_end(out_ok, sizeof(out_ok));

    CHECK(rc_ok == 0,
          "HEALTHY: with the chain readable the peer's VIEW_CHANGE is "
          "ACCEPTED");
    CHECK(w->view_change_count == 1,
          "and it was RECORDED — a return code alone could not tell an "
          "accepted vote from a silently dropped one");
    CHECK(!said(out_ok, "chain-height read faulted"),
          "nothing on the accepted path reported a height fault");

    break_chain(w);

    /* FAULTED LEG — a DIFFERENT peer, so the record it would take is a
     * new slot rather than an update of the first one; that is what
     * makes `view_change_count` a usable witness below. Fresh nonce. */
    memset(&vc, 0, sizeof(vc));
    vc.type = NODUS_T3_VIEWCHG;
    fill_header(&vc, w, &g_peers[2], /*round*/ 0, /*view*/ 0);
    vc.viewchg.new_view = 1;
    vc.viewchg.last_committed_round = w->last_committed_round;

    cap_begin();
    int rc_fault = nodus_witness_bft_handle_viewchg(w, &vc);
    cap_end(out_fault, sizeof(out_fault));

    CHECK(rc_fault == -1,
          "FAULTED: with the chain-height query broken the VIEW_CHANGE is "
          "REFUSED");
    CHECK(w->view_change_count == 1,
          "and NOTHING was recorded — the second voter never took a slot");
    CHECK(said(out_fault,
               "refusing the view change rather than authorizing the "
               "sender"),
          "and the refusal names the height gate, not the committee gate "
          "below it");

    chain_db_drop(w, dir);
}

int main(void) {
    printf("\nO15O Faz 1 — the consumers of "
           "nodus_witness_block_height_checked\n");

    for (int i = 0; i < N_PEERS; i++) peer_make(&g_peers[i]);

    section_is_leader();
    section_start_round();
    section_handle_propose();
    section_handle_commit();
    section_handle_viewchg();

    printf("\nO15O Faz 1 consumers PASS\n");
    return 0;
}
