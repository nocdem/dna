/**
 * Nodus — O15O Faz 6 — the PREPARED-VALUE LOCK is CONSULTED, not merely
 *                      compiled
 *
 * WHAT THIS PROVES.
 *   nodus_witness_bft_prepared_lock_blocks — whose own header calls it
 *   "the refusal the quorum-intersection safety argument depends on" —
 *   had ZERO production callers. It was defined in nodus_witness_bft.c,
 *   declared in nodus_witness_bft.h:116, and called from ONE unit test
 *   (test_witness_newview_convergence.c, which exercises the predicate in
 *   isolation and never routes a proposal through it). Nothing in
 *   nodus/src consulted it. Bug ref: nodus/BUGS.md O15N-L3.
 *
 *   The property that would be false if §1 failed: a witness that has
 *   PREPARED a value at a height REFUSES to prevote a DIFFERENT value at
 *   that same height. PRECOMMIT is sent only on locally observed prevote
 *   quorum and `last_prepared` is captured in that same block
 *   (nodus_witness_bft.c:6600-6628), so PRECOMMITTER ⇒ CARRIER: any
 *   committed value has >= 2f+1 carriers, hence >= f+1 honest carriers in
 *   every quorum-sized set. If those carriers do not refuse, a conflicting
 *   value reaches quorum and the chain forks.
 *
 *   THE STATE IS NOT HYPOTHETICAL. Both batch-abort branches in
 *   nodus_witness_bft.c set `round_state.phase = NODUS_W_PHASE_IDLE` and
 *   DELIBERATELY leave `last_prepared` intact — the own-quorum cert-gate
 *   failure (:6876-6893) and the commit_batch rollback (:6906-6954), each
 *   saying in as many words that clearing it is a separate consensus
 *   decision. Setting IDLE is also what stops check_timeout from firing a
 *   VIEW_CHANGE, so no view change arms `reproposal_required`. The same
 *   leader, in the same view, then proposes a different value at the same
 *   height and walks every gate: phase (we are IDLE), committee/leader
 *   (same leader, same epoch, same view), the O15N view-equality gate, the
 *   C5 gate (SKIPPED — `reproposal_required` is false) and the A2 height
 *   check. Before this phase the node accepted it.
 *
 *   FOUR ROWS ON ONE FIXTURE SHAPE, exactly one thing moving between
 *   them, because "it refused" proves nothing on its own — handle_propose
 *   refuses for a dozen unrelated reasons (a replayed nonce, a wrong
 *   chain id, a non-leader sender, a view mismatch, a height that is not
 *   ours), and every one of them returns -1 just like the lock does:
 *     §1 prepared at H, CONFLICTING proposal at H          → REFUSED
 *     §2 prepared at H, MATCHING proposal at H             → ACCEPTED
 *     §3 the lock RELEASED, the SAME conflicting proposal  → ACCEPTED
 *     §4 prepared at H+1, conflicting proposal at H        → ACCEPTED
 *   §2 and §3 are the anti-vacuity controls: §2 excludes "it refuses
 *   every proposal", §3 excludes "the proposal was malformed". §4 pins the
 *   height gate, so the lock cannot become a blanket refusal on a node
 *   that learned its block through SYNC (which never clears
 *   `last_prepared` — no reference in nodus_witness_sync.c).
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro, no
 *   short-epoch DNAC_EPOCH_LENGTH.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no variable that must be exported before the run. The one
 *   filesystem dependency is a writable /tmp for mkdtemp/mkstemp.
 *   DNAC_EPOCH_LENGTH is READ, never assumed: every fixture chain stays
 *   inside epoch 0 (tip 3, heights 4 and 5), so each assertion holds
 *   identically at the shipped 720 and at the harness's 15. The epoch a
 *   section computes is derived from the macro, never written as a
 *   literal.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Every section builds its chain database in its own mkdtemp()
 *   directory under /tmp and removes it with `rm -rf` before returning.
 *   The stderr-capture files are created with mkstemp and unlinked
 *   immediately, so they exist only as an open descriptor and vanish when
 *   it closes. No processes, no arm files, no restarted or halted nodes,
 *   nothing written outside each section's own temporary directory.
 *
 * HOW IT CAN LIE.
 *   - ⚠ THE ABORT BRANCH IS NOT DRIVEN, AND THAT IS THIS FILE'S BIGGEST
 *     LIMIT. `last_prepared` is armed through the PRODUCTION capture — a
 *     real prevote quorum delivered through nodus_witness_bft_handle_vote,
 *     so the lock's input is written by nodus_witness_bft.c:6600-6628 and
 *     not by this test. But the RESET TO IDLE that makes the conflicting
 *     proposal reachable is then performed BY HAND. Driving the real abort
 *     needs a precommit quorum followed by a commit_batch failure, and
 *     past that point the handler re-verifies every batch transaction in
 *     VALIDATION mode, which demands real Dilithium5-signed spend payloads
 *     or a complete genesis transaction — the same wall
 *     test_witness_commit_committee_gate.c and
 *     test_witness_height_fault_consumers.c §4 both declined to climb.
 *     SO: this file does NOT prove that the abort paths leave the lock
 *     armed. That claim rests on the source comments at
 *     nodus_witness_bft.c:6886-6887 and :6942-6947, cited by line, and on
 *     the absence of any `last_prepared` write between the abort and the
 *     return. If someone later makes an abort branch CLEAR
 *     `last_prepared`, every section here still passes while the defect
 *     this file exists for becomes unreachable — that change would need
 *     its own test, and it is a consensus decision, not a cleanup.
 *   - THE VACUITY TRAP, twice. A gate that refused every proposal would
 *     pass §1 alone; §2, §3 and §4 are what exclude it, and all three
 *     additionally assert the lock's stderr token is ABSENT, so an
 *     acceptance that happened to print the refusal cannot pass.
 *   - §3 CLEARS ONLY THE `present` BIT, deliberately leaving the stale
 *     tx_hash bytes in the struct — exactly as the commit-success clear
 *     does (nodus_witness_bft.c:12268 sets `present = false` and nothing
 *     else). An implementation that ignored `.present` and went straight
 *     to memcmp would therefore fail §3 loudly instead of passing.
 *   - THE REPLAY TRAP. Several messages leave one handler per section.
 *     is_replay() keys on (sender_id, nonce) in a PROCESS-GLOBAL table, so
 *     every message must carry a fresh nonce or it dies at the replay gate
 *     ABOVE the lock and the section proves nothing. fill_header
 *     re-randomises on every call; nothing here reuses a filled header.
 *   - THE LEADER IS DIFFERENT ON EVERY RUN. Witness ids are SHA3-512 over
 *     freshly generated ML-DSA-87 keys, so this node's sorted rank — and
 *     therefore which peer leads at a given view — changes per process. A
 *     hard-coded view would make the leader precondition a coin flip that
 *     still printed PASS. The view is CHOSEN AT RUNTIME and the selected
 *     leader is asserted before it is used.
 *   - THE STDERR ASSERTION IS A TEXT MATCH, and text can be edited. That
 *     is brittleness, not a lie: an edited message fails this test loudly
 *     rather than letting it pass quietly. The asserted substring is
 *     ASCII-only (the production line contains an ellipsis and an
 *     em-dash) and unique to this guard.
 *   - "ACCEPTED" MEANS ENTERED PREVOTE, NEVER COMMITTED. handle_propose
 *     returns 0 even when the batch is unverifiable — tx_invalid produces
 *     a REJECT prevote and the handler still returns 0
 *     (nodus_witness_bft.c:5891). The accepting
 *     sections therefore assert the ROUND ENTRY (rc 0, phase PREVOTE,
 *     current_round advanced, proposer recorded), which is the
 *     PRE-EXISTING outcome for this fixture shape and the same one
 *     test_bft_view_change_hardening.c §12f asserts. Nothing here commits
 *     a block, opens a socket, or decodes a real T3 frame.
 *   - NOTHING HERE SETS w->v2_successor. The successor batch seam is
 *     consequently not on the path, and no section pretends otherwise.
 *   - WHAT IT CANNOT SEE. The lock is exercised at ITS OWN call site
 *     only. That handle_propose is the ONLY place a conflicting value can
 *     enter — that the vote and commit handlers need no second gate — is
 *     an argument made in the production comment, not asserted here.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"      /* nodus_hash, nodus_random, sign_prepared */
#include "transport/nodus_tcp.h"    /* nodus_time_now                          */
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

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAIL %s:%d — %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    printf("  ok: %s\n", msg); \
} while (0)

/* Seven is the shipped devnet size and is well above
 * NODUS_T3_MIN_WITNESSES, so nodus_witness_bft_config_init serves a real
 * quorum of 5 for it — the value handle_propose's own
 * refresh_bft_config_from_committee recomputes on every call
 * (nodus_witness_bft.c:751-754, the pre-genesis roster arm, since no
 * section here primes a committee). Hand-setting the same number keeps
 * the round drive and the handler in agreement. */
#define N_PEERS   7
#define Q_HEALTHY 5             /* dna_bft_quorum(7), and config_init(7) */

/* The chain is seeded to this tip, so the height A2 demands of every
 * proposal is TIP_BLOCKS + 1. Both stay far inside epoch 0 at any
 * DNAC_EPOCH_LENGTH >= 2. */
#define TIP_BLOCKS 3

/* The ASCII-only, guard-unique token from the refusal this file is about
 * (nodus_witness_bft.c, the O15O Faz 6 gate). The production line also
 * carries an ellipsis and an em-dash; neither is matched on. */
#define LOCK_TOKEN "PREPARED-VALUE LOCK: refusing a conflicting value"

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_witness_quorum_vacuum.c, this season's own
 * model, trimmed to what these four sections touch.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of this file, so the identities
 * are generated ONCE in main and reused by every section. Nothing here
 * mutates them. */
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
 * so g_peers and w->roster.witnesses share indices.
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

    w->bft_config.n_witnesses = N_PEERS;
    w->bft_config.quorum = Q_HEALTHY;
    w->bft_config.round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
    w->bft_config.viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;

    /* The per-epoch committee cache has no invalidation hook and is keyed
     * on e_start, so a calloc'd 0 would read as a HIT for epoch 0 before
     * anything had been computed. Reset the sentinel exactly as the
     * production init path does. No section primes a committee: every
     * committee lookup here takes the F17 A5 pre-genesis roster arm, which
     * keeps these sections about the LOCK rather than about committee
     * resolution. */
    w->cached_committee_epoch_start = UINT64_MAX;
    return w;
}

/* Give the fixture a real chain database. `tag` becomes the 16-byte
 * chain_id (zero-filled to 32 by set_chain_id), so it is nonzero and
 * verify_chain_id's "we hold an identity, we enforce it" row applies —
 * which is what lets every crafted message carry w->chain_id and pass.
 *
 * ⚠ REQUIRED BEFORE THE ROUND DRIVE, not merely tidy: the prevote-quorum
 * arm that captures `last_prepared` persists it through
 * nodus_witness_db_save_pbft_state (nodus_witness_bft.c:6637). */
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

/* Append TIP_BLOCKS blocks through the PRODUCTION writer and return the
 * tip it produced. The tip is READ BACK rather than assumed: blocks.height
 * is INTEGER PRIMARY KEY AUTOINCREMENT, so a caller that computed it
 * itself could silently be testing against a tip of 0 — the one value
 * that makes A2 demand height 1 and every section below vacuous. Callers
 * assert on the returned number. Copied from seed_blocks in
 * test_bft_view_change_hardening.c. */
static uint64_t seed_blocks(nodus_witness_t *w, int n) {
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    uint8_t state_root[NODUS_T3_TX_HASH_LEN];
    for (int i = 0; i < n; i++) {
        memset(tx_root, (uint8_t)(0xA0 + i), sizeof(tx_root));
        memset(state_root, (uint8_t)(0xB0 + i), sizeof(state_root));
        if (nodus_witness_block_add(w, tx_root, 1, (uint64_t)(1000 + i),
                                    w->my_id, state_root, NULL, 0) != 0) {
            fprintf(stderr, "block_add %d\n", i); exit(1);
        }
    }
    return nodus_witness_block_height(w);
}

/* ═══════════════════════════════════════════════════════════════════
 * Leadership — asked of the PRODUCTION code, never re-implemented.
 * ═══════════════════════════════════════════════════════════════════ */

/* The peer that IS the leader at `view`, resolved the way handle_propose
 * resolves it.
 *
 * ⚠ IT MUST ASK THE SAME QUESTION handle_propose ASKS, AND THAT QUESTION
 * HAS TWO ANSWERS. With a validator-set snapshot the sender is ranked
 * inside the COMMITTEE; with none it falls back to the SORTED gossip
 * roster (F17 A5). No section here primes a committee, so the fallback is
 * the live arm — but that is ASSERTED rather than assumed, because a
 * helper that silently answered from the wrong arm would pick the wrong
 * peer and every "the sender is the leader" precondition would be false
 * while the section still printed PASS. Modelled on p2_leader_at in
 * test_bft_view_change_hardening.c. */
static const peer_t *leader_at(nodus_witness_t *w, uint32_t view) {
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;

    nodus_committee_member_t *cm = NULL;
    int count = 0;
    if (nodus_committee_get_for_block_alloc(w, next_bh, &cm, &count) != 0) {
        fprintf(stderr, "leader_at: committee load failed\n"); exit(1);
    }
    free(cm);
    if (count != 0) {
        fprintf(stderr, "leader_at: a committee of %d exists — this file's "
                        "fixtures are built for the pre-genesis roster arm "
                        "and would rank the sender in the wrong set\n", count);
        exit(1);
    }

    int slot = nodus_witness_bft_leader_index(epoch, view,
                                              (int)w->roster.n_witnesses);
    int arr = nodus_witness_roster_sorted_at(&w->roster, slot);
    if (arr < 0 || arr >= (int)w->roster.n_witnesses) {
        fprintf(stderr, "leader_at: sorted seat %d out of range\n", slot);
        exit(1);
    }
    /* The roster was filled in g_peers order, so the arrival index maps
     * straight back — but the SEAT came from the sorted rank, never from
     * the arrival index (BUGS.md 2026-08-04: node7 saw the honest proposer
     * at arrival index 6 and every sorted peer at rank 0). */
    return &g_peers[arr];
}

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-guard resolution.
 *
 * handle_propose refuses with -1 at a dozen gates, so the return code
 * alone cannot say WHICH one fired. The refusal line can. In a nodus build
 * QGP_LOG_* resolves to nodus/src/nodus_log_shim.c, whose qgp_log_ring_add
 * writes straight to stderr, and every gate in handle_propose uses a bare
 * fprintf(stderr, ...) anyway — so fd 2 carries both.
 *
 * The window wraps ONLY the call under test and stderr is restored BEFORE
 * anything is asserted: a CHECK that failed inside the window would write
 * its diagnosis into the temp file and the binary would exit 1 saying
 * nothing. Copied from test_witness_quorum_vacuum.c.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_plock_XXXXXX";
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

/* Generously sized: the asserted line is printed at the point of refusal,
 * which is early, so a truncated tail cannot hide one. */
#define CAP_BUF 65536

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

/* ═══════════════════════════════════════════════════════════════════
 * Message builders
 * ═══════════════════════════════════════════════════════════════════ */

/* A fresh header. The nonce is re-randomised on every call because
 * is_replay() keys on (sender_id, nonce) in a PROCESS-GLOBAL table: a
 * second message reusing the first one's nonce dies at the replay gate,
 * above every gate this file tests. */
static void fill_header(nodus_t3_msg_t *m, nodus_witness_t *w,
                        const peer_t *from, uint64_t round, uint32_t view) {
    m->header.round = round;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
}

/* The 116-byte PREPARED preimage (O15N Faz 2A):
 *   "prepared"(8) ‖ chain_id(32) ‖ view(4 BE) ‖ height(8 BE) ‖ tx_hash(64)
 * Identical to sign_prepared in test_witness_quorum_vacuum.c and
 * test_bft_view_change_hardening.c; the layout is
 * compute_prepared_preimage's, which is file-static in the implementation
 * and so cannot be called from here. */
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
 * recorded, as enter_round does in test_witness_quorum_vacuum.c. The
 * self-vote matters: it means four PEER approvals take the count to
 * exactly Q_HEALTHY. */
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
 * forged signature here would leave the quorum one short and no
 * `last_prepared` would be captured at all. */
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

/* ⚠ THE HEART OF THIS FILE: arm the lock the way PRODUCTION arms it.
 *
 * Drive a real prevote quorum at (`height`, `txh`) so
 * nodus_witness_bft.c:6600-6628 — the capture that runs at the instant the
 * node observes prevote quorum — writes `last_prepared` itself. Nothing
 * here assigns that struct. Every field the lock reads (present, height,
 * tx_hash) therefore comes from the production path.
 *
 * THEN RESET THE PHASE TO IDLE BY HAND, and that half is NOT production:
 * see the file header's "HOW IT CAN LIE". The two abort branches do
 * exactly this (nodus_witness_bft.c:6891 and :6954) and deliberately leave
 * `last_prepared` alone; driving them needs a commit_batch failure behind
 * a full VALIDATION-mode batch re-verify, which is out of reach here. What
 * is simulated is the phase reset, not the lock's contents. */
static void arm_lock(nodus_witness_t *w, uint64_t round, uint64_t height,
                     const uint8_t *txh) {
    enter_round(w, round, height, txh);
    CHECK(w->round_state.prevote_approve_count == 1,
          "precondition: the round opens with our own approval only");

    for (int i = 1; i <= 4; i++) send_prevote(w, i);

    CHECK(w->round_state.prevote_approve_count == Q_HEALTHY,
          "the four peer approvals were counted — a real prevote QUORUM, "
          "not a hand-written struct");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
          "and the round advanced to PRECOMMIT, so the quorum arm really "
          "ran");
    CHECK(w->last_prepared.present,
          "PRODUCTION captured last_prepared (bft.c:6600-6628) — this test "
          "never assigns it");
    CHECK(w->last_prepared.height == height,
          "and it names the ROUND ANCHOR as its height, which is the domain "
          "the lock compares prop->block_height against");
    CHECK(memcmp(w->last_prepared.tx_hash, txh, NODUS_T3_TX_HASH_LEN) == 0,
          "and it carries the value we prepared, copied from "
          "round_state.tx_hash (bft.c:6606)");

    /* What the abort branches do, and the ONLY reason a second proposal at
     * this height is reachable at all: phase IDLE also silences
     * check_timeout, so no VIEW_CHANGE fires and `reproposal_required`
     * stays false — which is what makes the C5 gate skip. */
    w->round_state.phase = NODUS_W_PHASE_IDLE;
    CHECK(!w->reproposal_required,
          "and no view change armed the C5 binding, so the C5 gate is "
          "SKIPPED for the proposal below — the lock is the only thing that "
          "could refuse it");
}

/* Build a PROPOSE for `height` from `leader` at `view`, carrying one
 * batch TX whose hash is `ptx`. tx_root is SHA3-512 over the batch's
 * tx_hashes, the same derivation handle_propose recomputes, so the
 * proposal is well-formed all the way down to the batch check that sits
 * BELOW the lock. Returns the tx_root through `tx_root_out`, because §2
 * has to prepare that exact value. */
static void build_propose(nodus_t3_msg_t *pm, nodus_witness_t *w,
                          const peer_t *leader, uint64_t round, uint32_t view,
                          uint64_t height, const uint8_t *ptx,
                          uint8_t tx_root_out[NODUS_T3_TX_HASH_LEN]) {
    memset(pm, 0, sizeof(*pm));
    pm->type = NODUS_T3_PROPOSE;
    fill_header(pm, w, leader, round, view);
    pm->propose.batch_count = 1;
    pm->propose.block_height = height;
    memcpy(pm->propose.batch_txs[0].tx_hash, ptx, NODUS_T3_TX_HASH_LEN);
    pm->propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;

    nodus_key_t bh;
    if (nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) != 0) {
        fprintf(stderr, "tx_root hash failed\n"); exit(1);
    }
    memcpy(pm->propose.tx_root, bh.bytes, NODUS_T3_TX_HASH_LEN);
    if (tx_root_out)
        memcpy(tx_root_out, bh.bytes, NODUS_T3_TX_HASH_LEN);
}

/* Everything a section needs to stand up: seven peers, a chain seeded to
 * TIP_BLOCKS, a view we can name a leader for, and that leader. The view
 * is chosen at RUNTIME (view 1, then whatever the production index
 * answers) and the resulting leader is returned rather than guessed. */
typedef struct {
    nodus_witness_t *w;
    uint64_t tip;
    uint32_t view;
    const peer_t *leader;
} scene_t;

static scene_t scene_open(char *dir, uint8_t tag) {
    scene_t s;
    s.w = fixture();
    chain_db_open(s.w, dir, tag);

    s.tip = seed_blocks(s.w, TIP_BLOCKS);
    CHECK(s.tip == (uint64_t)TIP_BLOCKS,
          "the seeded chain tip is what the writer reports, so A2 will "
          "demand tip+1 and not height 1");

    /* Any view will do — what matters is that the sender we use IS the
     * leader for it, which leader_at answers from the production index. */
    s.view = 1;
    s.w->current_view = s.view;
    s.leader = leader_at(s.w, s.view);
    return s;
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — THE DEFECT. Prepared at H, a CONFLICTING proposal at H.
 *
 * This is the row that is red without the gate. Every other gate in
 * handle_propose passes: we are IDLE, the sender is the leader for the
 * view we hold, the view matches, C5 is not armed, and the height is
 * exactly tip+1. Before O15O Faz 6 the node entered PREVOTE on a value
 * conflicting with the one its own PRECOMMIT is behind.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_conflict_refused(void) {
    printf("\n§1 prepared at H, CONFLICTING proposal at H — REFUSED\n");

    char dir[] = "/tmp/test_plock_conflict_XXXXXX";
    scene_t s = scene_open(dir, 0x61);
    nodus_witness_t *w = s.w;
    const uint64_t H = s.tip + 1;

    /* The value we PREPARE. Unrelated to the proposal's tx_root below, so
     * the two conflict — asserted rather than assumed. */
    uint8_t prepared_txh[NODUS_T3_TX_HASH_LEN];
    memset(prepared_txh, 0x11, sizeof(prepared_txh));
    arm_lock(w, /*round*/ 40, H, prepared_txh);

    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD1, sizeof(ptx));
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    nodus_t3_msg_t pm;
    build_propose(&pm, w, s.leader, /*round*/ 41, s.view, H, ptx, tx_root);

    CHECK(memcmp(tx_root, prepared_txh, NODUS_T3_TX_HASH_LEN) != 0,
          "precondition: the proposal's tx_root CONFLICTS with the value we "
          "prepared — without this the section would test the matching row");
    CHECK(pm.propose.block_height == H &&
          nodus_witness_block_height(w) + 1 == H,
          "precondition: the proposal's height is exactly tip+1, so the A2 "
          "gate above the lock passes and cannot be the refuser");
    CHECK(pm.header.view == w->current_view,
          "precondition: the view matches, so the O15N view-equality gate "
          "cannot be the refuser");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "precondition: we are IDLE, so the round-in-progress gate cannot "
          "be the refuser");

    static char out[CAP_BUF];
    cap_begin();
    int rc = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out, sizeof(out));

    CHECK(rc == -1, "the conflicting proposal was REFUSED");
    CHECK(said(out, LOCK_TOKEN),
          "and the refusal names THE LOCK — not the height gate, not C5, "
          "not the leader gate");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "no round was entered: the phase is still IDLE, so the refusal "
          "sits ABOVE the round-state initialisation");
    CHECK(w->current_round == 40,
          "and current_round still names the OLD round — handle_propose "
          "writes it at the round-state init, which was never reached");
    CHECK(w->last_prepared.present &&
          memcmp(w->last_prepared.tx_hash, prepared_txh,
                 NODUS_T3_TX_HASH_LEN) == 0,
          "and the lock is untouched by the refusal — the gate reads it, it "
          "does not clear it (clearing is a separate consensus decision)");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — ANTI-VACUITY. Prepared at H, the MATCHING proposal at H.
 *
 * Without this row §1 proves only that SOMETHING refuses. Exactly one
 * thing moves from §1: the value that was prepared. The proposal is built
 * FIRST so its tx_root can be the value the round then prepares.
 *
 * "ACCEPTED" here means the ROUND WAS ENTERED, never that a block was
 * committed — see the file header. handle_propose returns 0 even when the
 * batch fails VALIDATION-mode re-verify, because that produces a REJECT
 * prevote rather than a refusal; the round entry is the observable, and it
 * is the same one test_bft_view_change_hardening.c §12f asserts.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_match_accepted(void) {
    printf("\n§2 prepared at H, MATCHING proposal at H — ACCEPTED\n");

    char dir[] = "/tmp/test_plock_match_XXXXXX";
    scene_t s = scene_open(dir, 0x62);
    nodus_witness_t *w = s.w;
    const uint64_t H = s.tip + 1;

    /* Build the proposal FIRST — its tx_root is what must be prepared. */
    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD1, sizeof(ptx));
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    nodus_t3_msg_t pm;
    build_propose(&pm, w, s.leader, /*round*/ 41, s.view, H, ptx, tx_root);

    arm_lock(w, /*round*/ 40, H, tx_root);
    CHECK(memcmp(w->last_prepared.tx_hash, pm.propose.tx_root,
                 NODUS_T3_TX_HASH_LEN) == 0,
          "precondition: we prepared EXACTLY the value this proposal "
          "carries — the only thing that differs from §1");

    static char out[CAP_BUF];
    cap_begin();
    int rc = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out, sizeof(out));

    CHECK(rc == 0, "the matching proposal was ACCEPTED into a round");
    CHECK(!said(out, LOCK_TOKEN),
          "and the lock did NOT fire — it is not a blanket refusal");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
          "we entered PREVOTE, so execution really passed the lock and "
          "reached the round-state initialisation below it");
    CHECK(w->current_round == 41,
          "and current_round advanced to the proposal's round");
    CHECK(memcmp(w->round_state.proposer_id, s.leader->id,
                 NODUS_T3_WITNESS_ID_LEN) == 0,
          "and the round records the proposer — state written only on the "
          "accepting path");
    CHECK(w->round_state.block_height == H,
          "and the round is anchored at the proposal's height");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — ANTI-VACUITY. The lock RELEASED, the SAME conflicting proposal.
 *
 * Proves §1's refusal comes from the LOCK and not from anything about the
 * proposal itself: the bytes here are built exactly as §1's are, at the
 * same height, from the same leader, in the same view.
 *
 * Exactly one BIT moves from §1 — `last_prepared.present` — and it is
 * cleared the way a SUCCESSFUL COMMIT clears it (nodus_witness_bft.c:12268
 * sets `present = false` and nothing else). The stale tx_hash bytes stay
 * in the struct on purpose: an implementation that ignored `.present` and
 * went straight to memcmp would fail this section loudly.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_no_lock_accepted(void) {
    printf("\n§3 lock RELEASED, the same conflicting proposal — ACCEPTED\n");

    char dir[] = "/tmp/test_plock_released_XXXXXX";
    scene_t s = scene_open(dir, 0x63);
    nodus_witness_t *w = s.w;
    const uint64_t H = s.tip + 1;

    uint8_t prepared_txh[NODUS_T3_TX_HASH_LEN];
    memset(prepared_txh, 0x11, sizeof(prepared_txh));
    arm_lock(w, /*round*/ 40, H, prepared_txh);

    /* The commit-success clear, and ONLY that: present goes false, the
     * value stays behind. */
    w->last_prepared.present = false;
    CHECK(memcmp(w->last_prepared.tx_hash, prepared_txh,
                 NODUS_T3_TX_HASH_LEN) == 0,
          "the STALE prepared value is still in the struct — only the "
          "`present` bit was cleared, exactly as a successful commit does");

    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD1, sizeof(ptx));
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    nodus_t3_msg_t pm;
    build_propose(&pm, w, s.leader, /*round*/ 41, s.view, H, ptx, tx_root);
    CHECK(memcmp(tx_root, prepared_txh, NODUS_T3_TX_HASH_LEN) != 0,
          "and this is the SAME conflicting proposal §1 refused — same "
          "height, same leader, same view, same conflict");

    static char out[CAP_BUF];
    cap_begin();
    int rc = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out, sizeof(out));

    CHECK(rc == 0,
          "with no prepared value held, the proposal is ACCEPTED — so §1's "
          "refusal was the lock's and not the proposal's malformity");
    CHECK(!said(out, LOCK_TOKEN),
          "and the lock did NOT fire: it reads `present`, it does not "
          "memcmp stale bytes");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
          "we entered PREVOTE");
    CHECK(w->current_round == 41,
          "and current_round advanced to the proposal's round");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — THE HEIGHT GATE. Prepared at H+1, a conflicting proposal at H.
 *
 * The lock MUST NOT become a blanket refusal. It is height-gated on
 * purpose: `last_prepared` is cleared on commit_batch success but NOT on
 * the sync/replay path (no reference in nodus_witness_sync.c), so a node
 * that learned a block through SYNC would otherwise carry a stale lock
 * forever and reject every later proposal — a permanent, node-local
 * liveness death.
 *
 * The value conflicts exactly as §1's does; only the HEIGHT it was
 * prepared at moves. Preparing at an anchor that is not tip+1 is a
 * known-reachable state — test_precommit_cert_verify_lazy.c asserts
 * `last_prepared.height != head_next` for the same reason.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_other_height_accepted(void) {
    printf("\n§4 prepared at a DIFFERENT height — the lock stays silent\n");

    char dir[] = "/tmp/test_plock_height_XXXXXX";
    scene_t s = scene_open(dir, 0x64);
    nodus_witness_t *w = s.w;
    const uint64_t H = s.tip + 1;       /* what A2 demands of the proposal */
    const uint64_t H_OTHER = s.tip + 2; /* where we hold a prepared value  */

    uint8_t prepared_txh[NODUS_T3_TX_HASH_LEN];
    memset(prepared_txh, 0x11, sizeof(prepared_txh));
    arm_lock(w, /*round*/ 40, H_OTHER, prepared_txh);
    CHECK(w->last_prepared.height != H,
          "precondition: the prepared value sits at a height that is NOT "
          "the one this proposal carries");

    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD1, sizeof(ptx));
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    nodus_t3_msg_t pm;
    build_propose(&pm, w, s.leader, /*round*/ 41, s.view, H, ptx, tx_root);
    CHECK(memcmp(tx_root, prepared_txh, NODUS_T3_TX_HASH_LEN) != 0,
          "and the value still CONFLICTS — the height is the only thing "
          "that moved from §1");

    static char out[CAP_BUF];
    cap_begin();
    int rc = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out, sizeof(out));

    CHECK(rc == 0,
          "a conflicting value at a DIFFERENT height is ACCEPTED — the lock "
          "is height-gated, so a block learned through SYNC leaves no stale "
          "refusal to strand this node");
    CHECK(!said(out, LOCK_TOKEN), "and the lock did NOT fire");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
          "we entered PREVOTE");
    CHECK(w->last_prepared.present && w->last_prepared.height == H_OTHER,
          "and the prepared value at the other height is still held — "
          "entering this round did not silently drop it");

    fixture_free(w, dir);
}

int main(void) {
    printf("=== O15O Faz 6 — the PREPARED-VALUE LOCK is consulted ===\n");
    printf("Roster %d, quorum %d, chain seeded to tip %d, epoch length %d\n",
           N_PEERS, Q_HEALTHY, TIP_BLOCKS, (int)DNAC_EPOCH_LENGTH);

    for (int i = 0; i < N_PEERS; i++) peer_make(&g_peers[i]);

    section_conflict_refused();
    section_match_accepted();
    section_no_lock_accepted();
    section_other_height_accepted();

    printf("\n=== ALL SECTIONS PASSED ===\n");
    printf("NOTE: the abort branches that leave the lock armed "
           "(bft.c:6891, :6954) are NOT driven by this file — the phase "
           "reset is simulated. See the header's HOW IT CAN LIE.\n");
    return 0;
}
