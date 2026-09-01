/**
 * Nodus — O15P Faz 3 — A COLLAPSED ROUND LEAVES THE PREPARED-VALUE LOCK
 *                      ARMED
 *
 * WHAT THIS PROVES.
 *   One property, stated as the thing that would be FALSE if either
 *   section here failed:
 *
 *     When nodus_witness_commit_batch fails and the block is rolled
 *     back, the round is reset to NODUS_W_PHASE_IDLE **and**
 *     `w->last_prepared` is STILL ARMED — same height, same value.
 *
 *   THIS IS THE PREMISE test_witness_prepared_lock.c COULD NOT REACH.
 *   That file proves the lock refuses a conflicting value once the
 *   memory is armed and the phase is IDLE, but its own header says the
 *   phase reset is "performed BY HAND" and that "this file does NOT
 *   prove the abort paths leave the lock armed". Without the premise the
 *   whole O15O Faz 6 safety argument rests on two source comments:
 *   nodus_witness_bft.c's own-quorum cert-gate abort and its
 *   commit_batch-rollback abort, each saying in as many words that
 *   `last_prepared` is deliberately NOT cleared. This file drives the
 *   SECOND of those two for real.
 *
 *   WHY IT MATTERS. PRECOMMIT is sent only on locally observed prevote
 *   quorum and `last_prepared` is captured in that same block, so
 *   PRECOMMITTER => CARRIER: any committed value has >= 2f+1 carriers,
 *   hence >= f+1 honest carriers inside every quorum-sized set. Each of
 *   those must refuse a conflicting value at that height or the chain
 *   forks. The state in which that refusal is needed is EXACTLY this
 *   one — a round that prepared a value, collapsed, and went back to
 *   IDLE without a view change. If the collapse cleared the lock, the
 *   refusal could never fire and O15O Faz 6 would be decorative.
 *
 *   TWO SECTIONS, TWO DIFFERENT FAILURE EXITS INSIDE commit_batch, ONE
 *   ABORT BRANCH — because "the lock survived" proves much more when it
 *   is a property of the BRANCH rather than of one injection:
 *
 *     §1  the attendance write fails inside the batch transaction
 *         (nodus_witness_record_attendance -> rollback -> -1)
 *     §2  the M-1 TOCTOU height guard fires inside the batch
 *         transaction (expected_height != local_next -> rollback -> -1)
 *
 *   Each section asserts, on the SAME stderr window, that its OWN exit
 *   fired and that the other section's exit did NOT — so neither can be
 *   passing for the other's reason, and neither can be passing because
 *   the handler returned somewhere above commit_batch entirely.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro, no
 *   short-epoch DNAC_EPOCH_LENGTH.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no variable that must be exported before the run. The
 *   one filesystem dependency is a writable /tmp for mkdtemp/mkstemp.
 *   DNAC_EPOCH_LENGTH is READ, never assumed: each section primes the
 *   committee cache for the epoch CONTAINING its own round anchor, using
 *   the macro, so both sections behave identically at the shipped 720 and
 *   at the harness's 15.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Each section builds its chain database in its own mkdtemp()
 *   directory under /tmp and removes it with `rm -rf` before returning.
 *   The stderr-capture files are created with mkstemp and unlinked
 *   immediately, so they exist only as an open descriptor. No processes,
 *   no arm files, no restarted or halted nodes.
 *
 *   ⚠ IT DOES LEAVE ENTRIES IN THE PROCESS-GLOBAL REPLAY-NONCE TABLE.
 *   is_replay()/nonce_record() key on (sender_id, nonce) in a file-scope
 *   static inside nodus_witness_bft.c with no reset hook. Every message
 *   this file builds carries a FRESHLY RANDOMISED nonce (fill_header),
 *   and both sections generate brand-new ML-DSA-87 identities per
 *   process, so nothing here can be refused as a replay and nothing here
 *   can consume another test binary's capacity — each ctest executable is
 *   its own process.
 *
 * HOW IT CAN LIE.
 *   - THE INJECTION MUST LAND *INSIDE* commit_batch, AND THAT IS THE
 *     WHOLE DIFFICULTY. bft_handle_vote_inner has its own gates above the
 *     call (round/view equality, vote_target equality, phase, roster
 *     membership, pubkey dedup, the committee gate, the per-vote
 *     PRECOMMIT cert verify, the quorum test) and then ONE more gate
 *     between the phase advance and the call: the O15L Faz 3 own-quorum
 *     CERT GATE (nodus_witness_verify_certs_snapshot). Any of those
 *     firing instead would ALSO leave a refusal that looks superficially
 *     like the one under test — and the cert gate in particular also sets
 *     phase IDLE and also leaves `last_prepared` alone, so it would make
 *     both assertions pass for entirely the wrong reason. Every section
 *     therefore asserts the ABSENCE of that gate's message
 *     ("OWN-QUORUM CERT GATE") and the PRESENCE of BOTH the abort
 *     branch's own line ("BATCH COMMIT FAILED round") and the exit
 *     INSIDE commit_batch that produced it. That is how "we landed inside
 *     commit_batch" is established rather than assumed.
 *   - THE ROLLED-BACK CLIENT STRING IS NOT ASSERTED, and the reason is at
 *     its #define below: bft_emit_batch_replies passes `error_msg` only to
 *     the per-entry senders, and this fixture's entry has no client
 *     connection, so that string never reaches stderr. Asserting it would
 *     fail for a reason unrelated to the abort branch. The emission is
 *     pinned by its own line plus the DNAC_STATUS_ERROR it carries.
 *   - THE CERT GATE IS SATISFIED WITH REAL SIGNATURES, NOT BYPASSED.
 *     nodus_witness_verify_certs_snapshot resolves the committing
 *     committee from committed chain state and counts UNIQUE VALID
 *     signers against dna_bft_quorum(n). The fixture primes the committee
 *     cache with seven members and every PRECOMMIT carries a genuine
 *     Dilithium5 signature over the 144-byte cert preimage; our own
 *     (slot 0) is signed by the production code itself in the
 *     prevote-quorum arm. dna_bft_quorum(7) == 5 == the five precommits
 *     the round collects, so the gate passes with no margin to spare —
 *     if a single peer signature were wrong the gate would fail and the
 *     section would go red naming that gate, not pass quietly.
 *   - "THE LOCK IS STILL ARMED" IS NOT A TAUTOLOGY, BUT IT IS ALSO NOT A
 *     PROOF THAT ANYTHING EVER CLEARS IT. This file pins the CURRENT
 *     behaviour of the abort branch. It does NOT exercise a clearing
 *     path: commit_batch clears `last_prepared` only after a SUCCESSFUL
 *     db_commit, and driving a successful commit here would need
 *     finalize_block to pass (epoch-boundary transitions, emission,
 *     merkle state_root, the supply invariant) on a hand-seeded chain —
 *     out of scope, and out of proportion to the claim. What excludes the
 *     vacuous reading is the ARMING half: `last_prepared` is written by
 *     PRODUCTION (the prevote-quorum capture in bft_handle_vote_inner)
 *     and every field the assertion reads is checked immediately after
 *     that capture, before the abort is driven. If someone later makes
 *     an abort branch CLEAR the lock, this file goes red — which is
 *     exactly the alarm it exists to raise, because that is a consensus
 *     decision and not a cleanup.
 *   - THE PHASE ASSERTION HAS ITS OWN ANTI-VACUITY. "phase == IDLE" is
 *     the calloc'd default, so it is asserted to be PRECOMMIT
 *     immediately BEFORE the last precommit is delivered and IDLE
 *     immediately after. Without the before-leg the assertion would pass
 *     on a build where the round never started.
 *   - THE ROLLBACK IS ASSERTED ON THE CHAIN, NOT ONLY ON stderr. Both
 *     sections check that nodus_witness_block_height(w) is UNCHANGED
 *     afterwards. A "failure" that had actually committed a block would
 *     be caught there even if every log line matched.
 *   - THE ENTRIES ARE FREED BY THE CODE UNDER TEST. The abort branch
 *     calls bft_emit_batch_replies, which calls round_state_free_batch
 *     and releases the mempool entry this file allocated. So the sections
 *     assert batch_count == 0 afterwards (a second, non-stderr witness
 *     that the abort branch really ran) and NEVER free that entry
 *     themselves — doing so would be a double free.
 *   - §1's INJECTION IS A REAL `DROP TABLE validators`, the technique
 *     test_witness_block_height_checked.c and test_delegator_cap.c use.
 *     It makes record_attendance's sqlite3_prepare_v2 fail with "no such
 *     table", which is a genuine -1 from that function and not a test
 *     hook. It is applied AFTER the lock is armed and BEFORE the
 *     precommits, so nothing the arming half reads is affected: the
 *     committee comes from the primed per-epoch cache (no DB read at
 *     all), the height guards read `blocks`, and the pbft-state persist
 *     writes its own table. The fault cannot heal — the table is gone for
 *     the rest of the section.
 *   - §2's INJECTION IS A ROUND ANCHOR ONE BLOCK AHEAD OF THE CHAIN, and
 *     that state is reachable in production: the anchor is set from the
 *     leader's proposal (handle_propose's A2 fix) and the M-1 guard
 *     inside commit_batch exists precisely because the head can move
 *     between the caller's check and the transaction. bft_handle_vote_
 *     inner itself never compares the anchor to the local tip, so no gate
 *     above commit_batch can catch it — asserted by the absence of every
 *     one of that function's refusal messages in the window.
 *   - THE STDERR ASSERTIONS ARE TEXT MATCHES, and text can be edited.
 *     That is brittleness, not a lie: an edited message fails this test
 *     loudly rather than letting it pass quietly. Every needle is
 *     ASCII-only (the production lines carry em-dashes, which are never
 *     matched on).
 *   - NOTHING HERE SETS w->v2_successor. The successor batch seam
 *     (nodus_witness_v2_produce_commit) is therefore not on the path and
 *     no section pretends otherwise; the abort branch this file drives is
 *     the LEGACY own-quorum one.
 *   - WHAT IT CANNOT SEE. The OTHER abort branch — the own-quorum cert
 *     gate's "certificate quorum not established" — is not driven here;
 *     it is asserted ABSENT, which is the opposite obligation. The
 *     genesis arm (commit_genesis) and the remote-COMMIT arm are not
 *     driven either. Nothing here opens a socket, decodes a real T3
 *     frame, or commits a block.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_mempool.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"      /* nodus_random, nodus_sign_prepared_vote */
#include "transport/nodus_tcp.h"    /* nodus_time_now                        */
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"              /* DNAC_EPOCH_LENGTH, DNAC_PUBKEY_SIZE */

#include <sqlite3.h>

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

/* Seven is the shipped devnet size. It is above NODUS_T3_MIN_WITNESSES,
 * so nodus_witness_bft_config_init serves quorum 5 for it — and, which is
 * what makes the own-quorum cert gate satisfiable at all, dna_bft_quorum(7)
 * is ALSO 5. The five precommits the round collects (our own plus four
 * peers) are therefore exactly the number that gate demands. */
#define N_PEERS   7
#define Q_HEALTHY 5

/* The chain is seeded to this tip through the production writer. §1's
 * round is anchored at TIP_BLOCKS + 1 (the height commit_batch agrees
 * with) and §2's at TIP_BLOCKS + 2 (the height it refuses). */
#define TIP_BLOCKS 3

/* ── The lines the assertions key on. ASCII only: the production
 *    messages carry em-dashes, which must never appear in a needle. ─── */

/* The abort branch itself — the thing this file is about. */
#define L_ABORT_LOG  "BATCH COMMIT FAILED round"
/* bft_emit_batch_replies, which the abort branch calls and which is what
 * releases the batch entries. */
#define L_EMIT       "emitting client replies for round"
/* ...and the STATUS it emitted them with. The abort branch passes
 * DNAC_STATUS_ERROR; the success path passes DNAC_STATUS_APPROVED, so
 * this distinguishes the two emissions on their own line.
 *
 * ⚠ THE 2 MIRRORS DNAC_STATUS_ERROR in nodus_witness_bft.c. That is a
 * #define inside a .c file and cannot be included. A divergence cannot
 * pass quietly: the needle simply would not match and both sections go
 * red naming this assertion.
 *
 * ⚠ THE WIRE STRING "batch commit failed - block rolled back" IS NOT
 * ASSERTED, deliberately, and the reason is worth writing down because it
 * is the obvious thing to reach for. bft_emit_batch_replies prints the
 * line above but passes `error_msg` only to
 * nodus_witness_send_spend_result / the forwarder path, and this
 * fixture's batch entry has client_conn == NULL and is_forwarded ==
 * false — so neither runs and that string never reaches stderr. An
 * assertion on it would fail for a reason that has nothing to do with the
 * abort branch. */
#define L_EMIT_ERR   "entries, status=2)"

/* §1's exit, inside commit_batch. */
#define L_ATTEND     "commit_batch: record_attendance failed"
/* §2's exit, inside commit_batch. */
#define L_TOCTOU     "commit_batch height mismatch"

/* Exits that MUST NOT fire — each would make the two assertions pass for
 * the wrong reason. */
#define L_CERTGATE   "OWN-QUORUM CERT GATE"
#define L_SUCCESS    "BATCH COMMITTED round"
#define L_APPLYFAIL  "apply_tx failed"
#define L_CBHEIGHT   "chain-height read faulted inside the transaction"
#define L_PCVERIFY   "PRECOMMIT cert_sig verify FAILED"
#define L_NONMEMBER  "vote from non-committee member"
#define L_UNKNOWN    "vote from unknown sender"
#define L_COMMFAULT  "cannot establish the committee at height"
#define L_DIFFHASH   "vote for different tx_hash"
#define L_VACUOUS    "vacuous quorum"

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_witness_prepared_lock.c, this season's own
 * model, plus the primed committee that file deliberately does without.
 *
 * ⚠ THE COMMITTEE IS THE ONE REAL DIFFERENCE, AND IT IS FORCED.
 * test_witness_prepared_lock.c runs on the F17 A5 pre-genesis roster arm
 * (no committee), which keeps its sections about the lock. That arm is
 * not available here: nodus_witness_verify_certs_snapshot fails CLOSED on
 * an empty committee (nodus_witness_cert.c — "an empty committee is not
 * an authority we may verify against"), so the own-quorum cert gate would
 * abort ABOVE commit_batch and this file would never reach its subject.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of the setup, so the identities
 * are generated ONCE in main and reused. Nothing in a section mutates
 * them. */
static peer_t g_peers[N_PEERS];

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
 * so g_peers and w->roster.witnesses share indices.
 *
 * nodus_witness_t is multi-MB: heap, never stack (repo discipline).
 * w->v2_successor is NEVER touched — a fixture that hard-set it is what
 * this season had to repair. */
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

    /* THE CACHE SENTINEL, load-bearing: a calloc'd witness has
     * cached_committee_epoch_start == 0, so left at that zero the
     * resolver would take its cache-HIT branch for epoch 0 and answer
     * (rc 0, count 0) — the empty-committee arm the cert gate fails
     * closed on. Production sets UINT64_MAX at init for the same reason;
     * prime_committee() below installs the real key. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;

    /* The quorum this round votes under, from the PRODUCTION initialiser
     * rather than by hand: n = 7 gives quorum 5, the same number
     * dna_bft_quorum(7) hands the own-quorum cert gate. */
    nodus_witness_bft_config_init(&w->bft_config, N_PEERS);
    return w;
}

/* Give the fixture a real chain database. `tag` becomes the 16-byte
 * chain_id (zero-filled to 32 by set_chain_id), so it is NONZERO and
 * verify_chain_id's "we hold an identity, we enforce it" row applies —
 * which is what lets every crafted message carry w->chain_id and reach
 * the gates below it.
 *
 * ⚠ REQUIRED BEFORE THE ROUND DRIVE, not merely tidy: the prevote-quorum
 * arm that captures `last_prepared` persists it through
 * nodus_witness_db_save_pbft_state. */
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

/* Append `n` blocks through the PRODUCTION writer and return the tip it
 * produced. The tip is READ BACK rather than assumed: blocks.height is
 * INTEGER PRIMARY KEY AUTOINCREMENT, so a caller that computed it itself
 * could silently be testing against a tip of 0. Copied from seed_blocks
 * in test_witness_prepared_lock.c. */
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

/* Prime the committee resolver's per-epoch cache with all seven peers for
 * the epoch CONTAINING `height`. nodus_committee_get_for_block answers
 * from this cache before it touches the database, and BOTH consumers on
 * this path go through that accessor — load_committee_at_height_alloc
 * (the vote handler's membership gate) and
 * nodus_committee_get_for_block_alloc (the own-quorum cert gate's
 * authority) — so the governing committee is a deterministic, DB-free
 * input and the `DROP TABLE` in §1 cannot disturb it.
 *
 * Parametric in DNAC_EPOCH_LENGTH: the epoch start is COMPUTED, never
 * assumed. Copied from prime_committee in test_witness_replay_cache.c. */
static void prime_committee(nodus_witness_t *w, uint64_t height) {
    uint64_t e = (uint64_t)DNAC_EPOCH_LENGTH;
    w->cached_committee_epoch_start = (height / e) * e;
    w->cached_committee_count = N_PEERS;
    for (int i = 0; i < N_PEERS; i++) {
        memcpy(w->cached_committee_pubkeys[i], g_peers[i].pk,
               DNAC_PUBKEY_SIZE);
        w->cached_committee_stakes[i]         = 1000000ULL + (uint64_t)i;
        w->cached_committee_self_stakes[i]    = 1000000000000000ULL;
        w->cached_committee_commission_bps[i] = 100;
    }
}

/** Ask the loader directly what the gates are about to be told. */
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

/** THE §1 INJECTION. A real DROP, so sqlite3_prepare_v2 inside
 *  nodus_witness_record_attendance fails with "no such table: validators"
 *  and that function returns -1 — the genuine failure exit, not a hook. */
static void exec_or_die(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql failed (%s): %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        exit(1);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-exit resolution.
 *
 * Every refusal on this path returns -1, so the return code alone cannot
 * say WHICH exit fired; the messages can. In a nodus build QGP_LOG_*
 * resolves to nodus/src/nodus_log_shim.c, whose qgp_log_ring_add writes
 * straight to stderr, and the guards use bare fprintf(stderr, ...)
 * anyway — so fd 2 carries both.
 *
 * The window wraps ONLY the call under test and stderr is restored BEFORE
 * anything is asserted: a CHECK that failed inside the window would write
 * its diagnosis into the temp file and the binary would exit 1 saying
 * nothing. Copied from test_witness_prepared_lock.c.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_plsa_XXXXXX";
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

/* Generously sized: the commit arm is chatty (the vote tally line, the
 * quorum line, the emit line, the abort line), and a truncated tail could
 * otherwise hide the very message a section asserts is ABSENT. */
#define CAP_BUF 262144

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
 * above every gate this file drives. */
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
 * Identical to sign_prepared in test_witness_prepared_lock.c; the layout
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

/* The 144-byte PRECOMMIT cert signature, over the PRODUCTION preimage
 * builder (nodus_witness_compute_cert_preimage) so signer and verifier
 * cannot drift.
 *
 * ⚠ RAW qgp_dsa87_sign, NOT the tagged prepared-vote wrapper. Both the
 * per-vote check in bft_handle_vote_inner and
 * nodus_witness_verify_certs_snapshot call qgp_dsa87_verify directly, and
 * the production sign side does the same — the cert lane is deliberately
 * untagged because the DNAC client verifies these very signatures. */
static void sign_cert(uint8_t out[NODUS_SIG_BYTES], const peer_t *p,
                      const uint8_t *tx_hash, uint64_t height,
                      const uint8_t *chain_id) {
    uint8_t pre[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    if (nodus_witness_compute_cert_preimage(tx_hash, p->id, height,
                                            chain_id, pre) != 0) {
        fprintf(stderr, "cert preimage failed\n"); exit(1);
    }
    size_t sl = 0;
    if (qgp_dsa87_sign(out, &sl, pre, sizeof(pre), p->sk) != 0 ||
        sl > NODUS_SIG_BYTES) {
        fprintf(stderr, "cert sign failed\n"); exit(1);
    }
    if (sl < NODUS_SIG_BYTES)
        memset(out + sl, 0, NODUS_SIG_BYTES - sl);
}

/* Put the fixture into a live PREVOTE round with ONLY our own approval
 * recorded, and with a real batch attached so the COMMIT arm has
 * something to commit.
 *
 * ⚠ tx_root AND tx_hash CARRY THE SAME VALUE, and that is not
 * cosmetic. The per-vote PRECOMMIT check signs/verifies over
 * round_state.tx_hash; the own-quorum cert gate verifies the same
 * certificates over round_state.tx_root. Production keeps them equal by
 * construction ("tx_hash mirrors block_hash ... the two values are equal
 * by construction", nodus_witness.h round state; and the cert-gate
 * comment states "tx_hash == tx_root"). A fixture that set only one would
 * make the gate fail and the section land on the WRONG abort branch.
 *
 * ⚠ THE BATCH ENTRY IS HEAP AND IS NOT FREED HERE. The abort branch
 * releases it through bft_emit_batch_replies -> round_state_free_batch.
 * Freeing it in the section would be a double free. It carries tx_data
 * NULL / tx_len 0 deliberately: apply_tx_to_state then does its
 * nullifier-free, UTXO-free walk and returns 0, so the batch loop cannot
 * be the exit and the injection below is the first thing that can fail. */
static void enter_round(nodus_witness_t *w, uint64_t round, uint64_t height,
                        const uint8_t *tx_hash) {
    w->current_round = round;
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.round = round;
    w->round_state.view = w->current_view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    w->round_state.block_height = height;
    memcpy(w->round_state.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.tx_root, tx_hash, NODUS_T3_TX_HASH_LEN);
    w->round_state.tx_type = NODUS_W_TX_SPEND;
    w->round_state.proposal_timestamp = nodus_time_now();
    memcpy(w->round_state.proposer_id, g_peers[0].id,
           NODUS_T3_WITNESS_ID_LEN);

    memcpy(w->round_state.prevotes[0].voter_id, g_peers[0].id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->round_state.prevotes[0].pubkey, g_peers[0].pk, NODUS_PK_BYTES);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;
    w->round_state.phase_start_time = nodus_time_now() * 1000ULL;

    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { fprintf(stderr, "entry alloc\n"); exit(1); }
    memset(e->tx_hash, 0xE1, NODUS_T3_TX_HASH_LEN);
    e->tx_type = NODUS_W_TX_SPEND;
    e->tx_data = NULL;
    e->tx_len = 0;
    w->round_state.batch_entries[0] = e;
    w->round_state.batch_count = 1;
}

/* One APPROVE PREVOTE from peer `idx`, carrying a REAL prepared cert_sig
 * over the round's own anchor — the C5 gate verifies it and drops the
 * whole vote if it does not check out, so a forged signature here would
 * leave the quorum one short and no `last_prepared` would be captured. */
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

/* One APPROVE PRECOMMIT from peer `idx`, carrying a REAL 144-byte cert
 * signature. Both consumers verify it: the per-vote check in
 * bft_handle_vote_inner (which would drop the vote) and the own-quorum
 * cert gate (which would abort ABOVE commit_batch). */
static void build_precommit(nodus_t3_msg_t *m, nodus_witness_t *w, int idx) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_PRECOMMIT;
    fill_header(m, w, &g_peers[idx], w->round_state.round,
                w->round_state.view);
    m->vote.vote = NODUS_W_VOTE_APPROVE;
    memcpy(m->vote.vote_target, w->round_state.tx_hash, NODUS_T3_TX_HASH_LEN);
    sign_cert(m->vote.cert_sig, &g_peers[idx], w->round_state.tx_hash,
              w->round_state.block_height, w->chain_id);
}

static void send_precommit(nodus_witness_t *w, int idx) {
    nodus_t3_msg_t m;
    build_precommit(&m, w, idx);
    (void)nodus_witness_bft_handle_vote(w, &m);
}

/* ⚠ THE ARMING HALF, AND IT IS PRODUCTION'S. Drive a real prevote quorum
 * at (`height`, `txh`) so the capture that runs at the instant the node
 * observes prevote quorum writes `last_prepared` itself. Nothing here
 * assigns that struct; every field the later assertion reads (present,
 * height, tx_hash) comes from the production path.
 *
 * This is the same helper shape test_witness_prepared_lock.c uses — the
 * difference is what happens NEXT. That file resets the phase to IDLE by
 * hand; this one drives the abort that does it for real. */
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
          "PRODUCTION captured last_prepared in that same arm — this test "
          "never assigns it");
    CHECK(w->last_prepared.height == height,
          "and it names the ROUND ANCHOR as its height, which is the "
          "domain the lock compares a later proposal against");
    CHECK(memcmp(w->last_prepared.tx_hash, txh, NODUS_T3_TX_HASH_LEN) == 0,
          "and it carries the value we prepared, copied from "
          "round_state.tx_hash");
    CHECK(w->round_state.precommit_count == 1 &&
          w->round_state.precommit_approve_count == 1,
          "and our OWN precommit is already in slot 0, signed for real by "
          "the production path — it is one of the five certificates the "
          "own-quorum cert gate will count");
}

/* Deliver the precommits that carry the round into COMMIT. Peers 1..3 go
 * in quietly; peer 4 is the one that reaches quorum and therefore the one
 * that runs the whole commit arm, so ONLY that call is captured.
 *
 * Returns the handler's rc; `out` receives the window. */
static int drive_to_commit(nodus_witness_t *w, char *out, size_t cap) {
    for (int i = 1; i <= 3; i++) send_precommit(w, i);

    CHECK(w->round_state.precommit_approve_count == Q_HEALTHY - 1,
          "four precommits are in (ours plus three peers) — one short of "
          "quorum, so the round has NOT yet reached the commit arm");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
          "and the phase is still PRECOMMIT — the IDLE asserted after the "
          "abort is therefore a MOVE, not the calloc'd default");

    nodus_t3_msg_t m;
    build_precommit(&m, w, 4);
    cap_begin();
    int rc = nodus_witness_bft_handle_vote(w, &m);
    cap_end(out, cap);
    return rc;
}

/* Everything both sections assert about the abort branch itself. Kept in
 * one place so the two injections cannot drift apart in what they claim.
 *
 * `tip` is the height the chain MUST still be at afterwards. */
static void assert_aborted(nodus_witness_t *w, int rc, const char *out,
                           uint64_t tip, uint64_t H, const uint8_t *txh) {
    CHECK(rc == -1,
          "the commit arm returned -1 — the diagnostic return the abort "
          "branch uses where the fall-through returns 0");
    CHECK(said(out, L_ABORT_LOG),
          "THE ABORT BRANCH RAN: it named itself in the log");
    CHECK(said(out, L_EMIT) && said(out, L_EMIT_ERR),
          "and it emitted the client replies with DNAC_STATUS_ERROR — the "
          "call that also releases the batch entries, and the status that "
          "separates it from the success path's APPROVED emission");
    CHECK(!said(out, L_SUCCESS),
          "and the SUCCESS branch did not run — no block was committed");
    CHECK(!said(out, L_CERTGATE),
          "THE OTHER ABORT BRANCH DID NOT FIRE: the own-quorum cert gate "
          "passed, so execution really entered commit_batch. Without this "
          "leg the section would pass on that gate's refusal, which also "
          "sets IDLE and also leaves last_prepared alone");
    CHECK(!said(out, L_PCVERIFY) && !said(out, L_NONMEMBER) &&
          !said(out, L_UNKNOWN) && !said(out, L_COMMFAULT) &&
          !said(out, L_DIFFHASH) && !said(out, L_VACUOUS),
          "and no gate of the CALLING handler refused the vote — the "
          "precommit was counted and it is what carried the round into "
          "the commit arm");

    CHECK(nodus_witness_block_height(w) == tip,
          "THE BLOCK WAS ROLLED BACK: the chain tip is unchanged, which is "
          "asserted on the DATABASE and not on a log line");
    CHECK(w->round_state.batch_count == 0 &&
          w->round_state.batch_entries[0] == NULL,
          "and the batch entries were released by the abort branch itself "
          "— a second, non-stderr witness that it ran");

    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "THE ROUND WAS RESET TO IDLE — which is what stops "
          "check_timeout from firing a VIEW_CHANGE for a height that "
          "never landed, and what makes a second proposal at this height "
          "reachable at all");
    CHECK(w->round_state.client_conn == NULL,
          "and the client session was cleared, mirroring the fall-through "
          "reset");

    CHECK(w->last_prepared.present,
          "AND THE PREPARED-VALUE LOCK IS STILL ARMED. This is the premise "
          "the whole O15O Faz 6 refusal rests on and the one "
          "test_witness_prepared_lock.c could not reach: a collapsed round "
          "keeps the memory that makes the lock able to refuse");
    CHECK(w->last_prepared.height == H,
          "it still names the height the round was anchored at, so the "
          "lock's height gate can still match a proposal for that height");
    CHECK(memcmp(w->last_prepared.tx_hash, txh, NODUS_T3_TX_HASH_LEN) == 0,
          "and it still carries the value we prepared, so a CONFLICTING "
          "proposal at that height is still distinguishable from a "
          "matching one");

    CHECK(!w->safety_halt,
          "and no safety halt was latched — a rolled-back local commit is "
          "a liveness event, not a permanent removal from consensus");
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — THE ATTENDANCE WRITE FAILS INSIDE THE BATCH TRANSACTION.
 *
 * nodus_witness_record_attendance runs inside commit_batch's outer
 * transaction, BEFORE finalize_block, and its own header says a -1 there
 * is "a block REJECT: db_rollback runs and the block never lands. A
 * GUARD." Dropping the `validators` table makes its sqlite3_prepare_v2
 * fail with "no such table", which is a genuine -1 from that function.
 *
 * WHY THIS INJECTION AND NOT ANOTHER: it lands BELOW every check the
 * calling handler performs and below commit_batch's own height guards,
 * and it leaves the tables those guards read (`blocks`) intact. The
 * committee both gates resolve comes from the primed per-epoch cache, so
 * the drop cannot reach it either.
 *
 * THE DROP IS APPLIED AFTER THE LOCK IS ARMED. The prevote-quorum arm
 * persists the prepared certificate through
 * nodus_witness_db_save_pbft_state; doing the drop first would put a
 * second, unrelated failure on the arming half.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_attendance_abort(void) {
    printf("\n§1 the attendance write fails inside the batch transaction — "
           "the round collapses and the lock survives\n");

    char dir[] = "/tmp/test_plsa_attend_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x71);

    uint64_t tip = seed_blocks(w, TIP_BLOCKS);
    CHECK(tip == (uint64_t)TIP_BLOCKS,
          "the seeded chain tip is what the writer reports");

    const uint64_t H = tip + 1;   /* the height commit_batch AGREES with */
    prime_committee(w, H);
    int count = -1;
    CHECK(committee_probe(w, H, &count) == 0 && count == N_PEERS,
          "precondition: the committee governing the round's height has "
          "seven members, so every voter is authorized and the own-quorum "
          "cert gate has an authority to verify against");

    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x11, sizeof(txh));
    arm_lock(w, /*round*/ 40, H, txh);

    /* THE INJECTION. */
    exec_or_die(w->db, "DROP TABLE validators;");
    CHECK(nodus_witness_block_height(w) == tip,
          "the drop left the `blocks` table alone — the height guards "
          "above and inside commit_batch still read a healthy chain, so "
          "they cannot be the exit");

    static char out[CAP_BUF];
    int rc = drive_to_commit(w, out, sizeof(out));

    CHECK(said(out, L_ATTEND),
          "THE EXIT IS NAMED: commit_batch reported record_attendance's "
          "-1, so the failure happened INSIDE the batch transaction and "
          "below every gate the calling handler owns");
    CHECK(!said(out, L_TOCTOU) && !said(out, L_CBHEIGHT) &&
          !said(out, L_APPLYFAIL),
          "and it is not one of commit_batch's EARLIER exits — not the "
          "TOCTOU height guard, not the in-transaction height read, not "
          "the per-TX apply");

    assert_aborted(w, rc, out, tip, H, txh);

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — THE M-1 TOCTOU HEIGHT GUARD FIRES INSIDE THE BATCH TRANSACTION.
 *
 * The SAME abort branch, reached through a DIFFERENT failure exit, so the
 * conclusion is a property of the branch and not of §1's injection.
 *
 * The round is anchored one block AHEAD of the chain. That is a reachable
 * production state, not a contrivance: round_state.block_height is set
 * from the leader's proposal (handle_propose's A2 fix), and commit_batch
 * re-reads the head under its own transaction precisely because the head
 * can move between the caller's check and the write — the guard exists
 * for the live h=114 divergence (audit M-1).
 *
 * NOTHING ABOVE commit_batch CAN CATCH IT. bft_handle_vote_inner compares
 * the anchor against nothing: its gates are round/view equality,
 * vote_target equality, phase, roster membership, pubkey dedup, committee
 * membership AT THE ANCHOR, the per-vote cert verify AT THE ANCHOR, and
 * the quorum count. Every one of those is satisfied at height tip+2
 * because the committee is primed there and the certificates are signed
 * there. The assertions below prove that by name.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_toctou_abort(void) {
    printf("\n§2 the TOCTOU height guard fires inside the batch "
           "transaction — same abort branch, different exit\n");

    char dir[] = "/tmp/test_plsa_toctou_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x72);

    uint64_t tip = seed_blocks(w, TIP_BLOCKS);
    CHECK(tip == (uint64_t)TIP_BLOCKS,
          "the seeded chain tip is what the writer reports");

    /* THE INJECTION: the round anchor is tip + 2, so commit_batch's
     * local_next (tip + 1) disagrees with the expected_height it is
     * handed. */
    const uint64_t H = tip + 2;
    prime_committee(w, H);
    int count = -1;
    CHECK(committee_probe(w, H, &count) == 0 && count == N_PEERS,
          "precondition: the committee is primed at the ROUND ANCHOR, so "
          "the vote gate and the cert gate both resolve there and neither "
          "can be the refuser");
    CHECK(H != nodus_witness_block_height(w) + 1,
          "precondition: the anchor is NOT the chain's next height — this "
          "is the one thing that differs from §1");

    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x22, sizeof(txh));
    arm_lock(w, /*round*/ 50, H, txh);

    static char out[CAP_BUF];
    int rc = drive_to_commit(w, out, sizeof(out));

    CHECK(said(out, L_TOCTOU),
          "THE EXIT IS NAMED: commit_batch's own height guard refused "
          "under the transaction, so the failure happened INSIDE it");
    CHECK(!said(out, L_ATTEND) && !said(out, L_CBHEIGHT) &&
          !said(out, L_APPLYFAIL),
          "and it is a DIFFERENT exit from §1's — the attendance write "
          "was never reached, so the two sections cannot be passing for "
          "one another's reason");

    assert_aborted(w, rc, out, tip, H, txh);

    fixture_free(w, dir);
}

int main(void) {
    printf("=== O15P Faz 3 — a collapsed round leaves the PREPARED-VALUE "
           "LOCK armed ===\n");
    printf("Roster %d, quorum %d, chain seeded to tip %d, epoch length %d\n",
           N_PEERS, Q_HEALTHY, TIP_BLOCKS, (int)DNAC_EPOCH_LENGTH);

    for (int i = 0; i < N_PEERS; i++) peer_make(&g_peers[i]);

    /* The order is free: each section builds its own fixture, its own
     * chain database and its own identities are the same seven peers used
     * against DIFFERENT chain_ids, and neither leaves process state the
     * other reads. The replay-nonce table is the one process-global here,
     * and every message carries a randomised nonce. */
    section_attendance_abort();
    section_toctou_abort();

    printf("\n=== ALL SECTIONS PASSED ===\n");
    printf("NOTE: this file proves the abort branch LEAVES the lock armed. "
           "It does NOT exercise any path that CLEARS it — commit_batch's "
           "post-commit clear needs a successful finalize_block and is out "
           "of scope. See the header's HOW IT CAN LIE.\n");
    return 0;
}
