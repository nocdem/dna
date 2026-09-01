/**
 * Nodus — O15O Faz 2 — a quorum of 0 is refused, not obeyed
 *
 * WHAT THIS PROVES.
 *   nodus_witness_bft_config_init writes `quorum = 0` for any validator
 *   count below NODUS_T3_MIN_WITNESSES and calls that branch "consensus
 *   disabled". The value is ALSO the sentinel
 *   nodus_witness_bft_consensus_active reads, so it must stay 0 — and
 *   that is exactly what made it dangerous, because every threshold in
 *   this tree is written `x < quorum`, and `x < 0` is FALSE for every x.
 *   A value meaning "I take no part" was therefore the single most
 *   PERMISSIVE input the consensus code could receive.
 *
 *   The property that would be false if any section here failed: a
 *   witness whose quorum is 0 declines every decision that a threshold
 *   would have governed — it does not advance a round phase, does not
 *   certify that a view change reached quorum, does not accept a prepared
 *   certificate, does not claim a reproposal it cannot prove, and does
 *   not accept a synced block's certificates. Before O15O Faz 2 it did
 *   ALL of those on the strength of a single message, or of none.
 *
 *   EVERY SITE GETS A PAIR ON ONE FIXTURE, and the pair is the whole
 *   point. "It refused" proves nothing on its own: a witness refuses for
 *   a dozen reasons that have nothing to do with the quorum — a phase
 *   that is not IDLE, a sender outside the committee, a replayed nonce, a
 *   signature that does not verify. The HEALTHY leg excludes all of them:
 *   the same fixture, the same call, with a REAL quorum in force, and the
 *   site behaves normally — reaching its threshold only AT the threshold,
 *   never before it. Only then does the VACUUM leg's refusal mean what it
 *   says. Several sections carry TWO healthy legs for that reason: one
 *   just below the threshold (refused) and one at it (accepted), because
 *   a guard that refused everything would also pass a single-leg test.
 *
 *   WHERE THE 0 COMES FROM IS NOT ALWAYS HAND-SET. §4 reaches it through
 *   the PRODUCTION initialiser — a four-member roster handed to
 *   nodus_witness_bft_config_init — so that section proves the state is
 *   reachable without a test-only assignment. The other sections set the
 *   field directly, which is what their call sites see at runtime anyway:
 *   handle_vote, handle_viewchg and the VIEW_OK move path all read
 *   bft_config without refreshing it.
 *
 *   Bug ref: nodus/BUGS.md (the view-change threshold row). Rule:
 *   nodus/CLAUDE.md, PRIMARY OBJECTIVE: DETERMINISM — two nodes with
 *   different quorums in force are two chains.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro, and no
 *   short-epoch DNAC_EPOCH_LENGTH: every fixture chain stays inside epoch
 *   0, so each assertion holds identically at the shipped 720 and at the
 *   harness's 15. The committee primings below are computed FROM
 *   DNAC_EPOCH_LENGTH rather than assuming a value.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no pre-exported variable. The one filesystem dependency
 *   is a writable /tmp for mkdtemp/mkstemp.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Every section builds its chain database in its own mkdtemp()
 *   directory under /tmp and removes it with `rm -rf` before returning.
 *   The stderr-capture files are created with mkstemp and unlinked
 *   immediately, so they exist only as an open descriptor and vanish when
 *   it closes. No processes, no arm files, no restarted nodes.
 *
 *   Heap deliberately not reclaimed: the prepared-signature blocks §3
 *   hands to a view-change record are released through
 *   nodus_witness_vc_record_clear in each fixture's teardown, but any
 *   record the PRODUCTION code appended (bft_self_record_view_change) is
 *   cleared by that same loop, so the only residue is bounded by the
 *   record array and dies with the process.
 *
 * HOW IT CAN LIE.
 *   - THE VACUITY TRAP, which is this file's own subject twice over: a
 *     site that refuses for an unrelated reason is byte-identical, at the
 *     return code, to one that refuses because the quorum is 0. Every
 *     vacuum leg is therefore paired with a healthy leg on the same
 *     fixture AND asserts the stderr line naming the SITE of the refusal.
 *     Drop either and the section can pass while measuring nothing.
 *   - THE THRESHOLD COULD BE DEAD IN BOTH DIRECTIONS. A guard written as
 *     "refuse always" would pass every vacuum leg. The healthy legs are
 *     what exclude it, and the ones that assert ACCEPTANCE at the exact
 *     threshold (§1's fifth approval, §4's fourth signature, §5's fifth
 *     voter, §6's five certs) are the load-bearing half. A section with
 *     only a "refused below threshold" healthy leg would not catch it.
 *   - THE REPLAY TRAP. §1, §5 and §6 deliver several messages from one
 *     handler. is_replay() keys on (sender_id, nonce) in a PROCESS-GLOBAL
 *     table, so every message must carry a fresh nonce or it dies at the
 *     replay gate above every quorum test in this file. fill_header
 *     re-randomises on every call; nothing here reuses a filled header.
 *   - THE STDERR ASSERTIONS ARE TEXT MATCHES, and text can be edited.
 *     That is brittleness, not a lie: an edited message fails this test
 *     loudly instead of letting it pass quietly. The substrings are
 *     ASCII-only (the production messages contain em-dashes) and unique
 *     to the guard they name.
 *   - §2 IS NOT TESTED, AND THAT IS REPORTED RATHER THAN HIDDEN. The
 *     fork-detection DB drop in nodus_witness_sync_check cannot be
 *     reached from a unit fixture — see the section's own comment for the
 *     proof. It prints an explicit UNREACHED notice. It is not counted as
 *     coverage and there is no rc=99 skip anywhere: every other section
 *     runs unconditionally or the binary exits non-zero.
 *   - WHAT IT CANNOT SEE. Each guard is tested at its OWN call site. The
 *     interaction between them — that guarding §5 is what makes §3
 *     reachable only through the VIEW_OK proof path — is argued in §3's
 *     header and exercised by construction there, not asserted directly.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_sync.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_cert.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"          /* DNAC_EPOCH_LENGTH, DNAC_PUBKEY_SIZE */
#include "dnac/ledger_ids.h"    /* dna_bft_quorum — the OTHER answer    */

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
 * above NODUS_T3_MIN_WITNESSES — so the HEALTHY legs get a quorum the
 * production initialiser would actually serve (dna_bft_quorum(7) = 5),
 * and the VACUUM legs are a deliberate departure from it rather than an
 * accident of a too-small fixture. §4 additionally uses 4 and 5, because
 * the boundary between them is its subject. */
#define N_PEERS   7
#define Q_HEALTHY 5             /* dna_bft_quorum(7) */

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_witness_height_fault_consumers.c, which
 * is this season's own model, trimmed to what these sections touch.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of this file, so the identities
 * are generated ONCE in main and reused by every section. Nothing in a
 * section mutates them, and §3's identity swap restores what it borrows.
 * Seven is the largest roster any section seats, so the pool is sized to
 * that; §4's four- and five-member rosters are prefixes of it. */
#define N_KEYS 7
static peer_t g_peers[N_KEYS];

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
 * so `g_peers` and `w->roster.witnesses` share indices.
 *
 * nodus_witness_t is multi-MB: heap, never stack (repo discipline). */
static nodus_witness_t *fixture(int n_roster) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!w || !srv) { fprintf(stderr, "fixture alloc\n"); exit(1); }

    memcpy(srv->identity.pk.bytes, g_peers[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, g_peers[0].sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, g_peers[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i < n_roster; i++) roster_put(w, &g_peers[i]);

    /* The per-epoch committee cache has no invalidation hook and is keyed
     * on e_start, so a calloc'd 0 would read as a HIT for epoch 0 before
     * anything had been computed. Reset the sentinel exactly as the
     * production init path does. Sections that WANT a committee re-arm it
     * deliberately through prime_committee below. */
    w->cached_committee_epoch_start = UINT64_MAX;
    return w;
}

/* Give the fixture a real chain database. `tag` becomes the 16-byte
 * chain_id (zero-filled to 32 by set_chain_id), so it is nonzero and
 * verify_chain_id's "we hold an identity, we enforce it" row applies —
 * which is what lets every crafted message carry w->chain_id and pass. */
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
         * including the ones §3 attaches by hand and the ones
         * bft_self_record_view_change attaches during the move. */
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

/* Prime the legacy committee resolver's per-epoch cache with peers
 * [0..n). nodus_committee_get_for_block answers from this cache before it
 * touches the database, and load_committee_at_height_alloc — the resolver
 * every committee gate in nodus_witness_bft.c calls — goes through that
 * accessor. So this makes the governing committee a deterministic, DB-free
 * input whose ORDER the test controls, which matters because the VIEW_OK
 * set hash commits seat positions.
 *
 * Parametric in DNAC_EPOCH_LENGTH: the epoch start is COMPUTED, never
 * assumed, so a short-epoch build primes the same set. Copied from
 * vp_prime in test_view_proof.c. */
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

/* ═══════════════════════════════════════════════════════════════════
 * Signing helpers — the PRODUCTION preimages, byte for byte.
 * ═══════════════════════════════════════════════════════════════════ */

/* O15N Faz 2A — the 116-byte PREPARED preimage:
 *   "prepared"(8) ‖ chain_id(32) ‖ view(4 BE) ‖ height(8 BE) ‖ tx_hash(64)
 * Identical to sign_prepared in test_bft_view_change_hardening.c and to
 * gate_sign_prepared in test_bft_roster_committee.c; the layout is
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

/* The 144-byte COMMIT cert preimage, built by the PRODUCTION function
 * (nodus_witness_compute_cert_preimage is exported through
 * nodus_witness_cert.h, unlike the prepared one) and signed RAW, matching
 * the sign side and both cert verifiers. */
static void sign_cert(uint8_t out[NODUS_SIG_BYTES], const peer_t *p,
                      const uint8_t *block_hash, uint64_t height,
                      const uint8_t *chain_id) {
    uint8_t pre[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    if (nodus_witness_compute_cert_preimage(block_hash, p->id, height,
                                             chain_id, pre) != 0) {
        fprintf(stderr, "cert preimage failed\n"); exit(1);
    }
    size_t siglen = 0;
    if (qgp_dsa87_sign(out, &siglen, pre, sizeof(pre), p->sk) != 0 ||
        siglen > NODUS_SIG_BYTES) {
        fprintf(stderr, "cert sign failed\n"); exit(1);
    }
    /* Pad to the fixed wire size exactly as the production sign side
     * does — a detached ML-DSA-87 signature may be shorter than the
     * slot, and the verifier reads the whole slot. */
    if (siglen < NODUS_SIG_BYTES)
        memset(out + siglen, 0, NODUS_SIG_BYTES - siglen);
}

/* Make the fixture SIGN A VIEW_OK AS peer `idx`, through the production
 * producer. nodus_witness_bft_sign_view_ok reads the signer identity from
 * `w` and never takes it as an argument — deliberately, so a statement
 * cannot be minted for another signer. Swapping the identity in and back
 * is the only way one fixture can stand in for several nodes, and it
 * exercises the REAL producer rather than a test-side re-implementation.
 * Copied from vp_sign_as in test_view_proof.c. */
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

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-guard resolution.
 *
 * Every guard here refuses with the same value its neighbours already
 * refuse with (0, -1, false, or a bare return), so the return code alone
 * cannot say WHICH guard fired. The refusal line can. In a nodus build
 * QGP_LOG_* resolves to nodus/src/nodus_log_shim.c, whose
 * qgp_log_ring_add writes straight to stderr, and every guard under test
 * uses a bare fprintf(stderr, ...) anyway — so fd 2 carries both.
 *
 * The window wraps ONLY the call under test and stderr is restored BEFORE
 * anything is asserted: a CHECK that failed inside the window would write
 * its diagnosis into the temp file and the binary would exit 1 saying
 * nothing. Copied from test_witness_height_fault_consumers.c.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_qv_XXXXXX";
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

/* Generously sized: every line asserted on is printed at the point of
 * refusal, which is early, so a truncated tail cannot hide one. */
#define CAP_BUF 65536

/* Restore fd 2 and copy the window's output into `dst`.
 *
 * ⚠ THE DESTINATION IS CALLER-OWNED ON PURPOSE. Several sections hold one
 * leg's text while capturing the next; a shared static buffer would
 * silently overwrite the first, and every "the healthy leg did NOT say X"
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

/* ═══════════════════════════════════════════════════════════════════
 * Message builders
 * ═══════════════════════════════════════════════════════════════════ */

/* A fresh header. The nonce is re-randomised on every call because
 * is_replay() keys on (sender_id, nonce) in a PROCESS-GLOBAL table: a
 * second message reusing the first one's nonce dies at the replay gate,
 * above every quorum test in this file. */
static void fill_header(nodus_t3_msg_t *m, nodus_witness_t *w,
                        const peer_t *from, uint64_t round, uint32_t view) {
    m->header.round = round;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
}

/* Put the fixture into a live PREVOTE round with ONLY our own approval
 * recorded, exactly as enter_round does in
 * test_bft_view_change_hardening.c. The self-vote matters: it means the
 * first PEER approval takes the count to 2, so a build that reverted §1's
 * guard advances the phase on a count that is visibly not a quorum. */
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
 * forged signature here would make every section below refuse for the
 * wrong reason. */
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

/* One VIEW_CHANGE from peer `idx` asking for `new_view`, carrying NO
 * prepared cert (has_prepared stays false), which is all §5 needs: its
 * subject is the TALLY threshold, not certificate selection. */
static void send_viewchg(nodus_witness_t *w, int idx, uint32_t new_view) {
    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_VIEWCHG;
    fill_header(&m, w, &g_peers[idx], w->round_state.round, w->current_view);
    m.viewchg.new_view = new_view;
    m.viewchg.last_committed_round = w->last_committed_round;
    (void)nodus_witness_bft_handle_viewchg(w, &m);
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — the VOTE quorum (nodus_witness_bft.c, bft_handle_vote_inner:
 *      `required = w->bft_config.quorum` / `*approve_count < required`).
 *
 * THE WORST OF THE SIX. `*approve_count` is at least 1 when the
 * comparison runs, so at quorum 0 the FIRST vote to arrive declares
 * quorum and advances the round phase. The advance is irreversible:
 * every later vote of that type is dropped by the expected_phase gate, so
 * a node reaches COMMIT having observed one approval.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_vote_quorum(void) {
    printf("\n§1 vote quorum — the phase does not advance on a quorum of "
           "0\n");

    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0xA1, sizeof(txh));

    /* ── HEALTHY LEG ─────────────────────────────────────────────────
     * A real quorum of 5 over a 7-member roster. The round starts with
     * our own approval, so peers 1..3 take it to 4 — below — and peer 4
     * takes it to 5, exactly at. Both halves are asserted: a guard that
     * refused unconditionally would pass the first and fail the second. */
    {
        nodus_witness_t *w = fixture(N_PEERS);
        char dir[] = "/tmp/test_qv_vote_ok_XXXXXX";
        chain_db_open(w, dir, 0x11);
        w->bft_config.n_witnesses = N_PEERS;
        w->bft_config.quorum = Q_HEALTHY;

        enter_round(w, /*round*/ 4, /*height*/ 1, txh);
        CHECK(w->round_state.prevote_approve_count == 1,
              "precondition: the round opens with our own approval only");

        for (int i = 1; i <= 3; i++) send_prevote(w, i);
        CHECK(w->round_state.prevote_approve_count == 4,
              "HEALTHY: three peer approvals were counted (4 of 5)");
        CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
              "and the phase has NOT advanced — 4 is below the quorum, and "
              "the threshold is genuinely enforced in this direction");

        send_prevote(w, 4);
        CHECK(w->round_state.prevote_approve_count == 5,
              "HEALTHY: the fifth approval arrives");
        CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
              "and NOW the phase advances — the guard is not a blanket "
              "refusal, it lets a real quorum through at its real value");
        CHECK(w->last_prepared.present,
              "and the C5 prepared certificate was captured, so the "
              "quorum arm really ran rather than being skipped");

        fixture_free(w, dir);
    }

    /* ── VACUUM LEG ──────────────────────────────────────────────────
     * Same fixture shape, same round, same vote — only the quorum
     * differs. One peer approval takes the count to 2, and on a build
     * without the guard `2 < 0` is false, so the phase advances here. */
    {
        nodus_witness_t *w = fixture(N_PEERS);
        char dir[] = "/tmp/test_qv_vote_vac_XXXXXX";
        chain_db_open(w, dir, 0x12);
        w->bft_config.n_witnesses = N_PEERS;
        w->bft_config.quorum = 0;

        enter_round(w, /*round*/ 4, /*height*/ 1, txh);

        static char out[CAP_BUF];
        cap_begin();
        send_prevote(w, 1);
        cap_end(out, sizeof(out));

        CHECK(w->round_state.prevote_approve_count == 2,
              "VACUUM: the peer's approval was still COUNTED — the vote is "
              "well-formed and the refusal is not a drop");
        CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
              "but the phase did NOT advance: with quorum 0 the round "
              "cannot conclude anything from two approvals");
        CHECK(!w->last_prepared.present,
              "and no prepared certificate was captured — the quorum arm "
              "never ran");
        CHECK(said(out, "vacuous quorum — refusing to advance the phase"),
              "and the refusal names THIS guard, not some other gate");
        CHECK(!said(out, "QUORUM! approve="),
              "the site did not announce a quorum it cannot count");

        fixture_free(w, dir);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — the fork-detection DB DROP (nodus_witness_sync.c, in
 *      nodus_witness_sync_check: `disagree_count >= bft_config.quorum`,
 *      whose true branch calls drop_witness_db).
 *
 * ⚠ NOT TESTED. THE ROW IS UNREACHABLE FROM A UNIT FIXTURE, AND FROM
 * PRODUCTION, FOR THE SAME REASON — SO IT IS REPORTED, NOT FAKED.
 *
 * The guard sits inside `if (peer_height == local_height && local_height
 * > 0)`. `peer_idx` comes from nodus_witness_sync_find_peer, which starts
 * `best_height = local_height` and only records a peer whose
 * remote_height is STRICTLY GREATER (nodus_witness_sync.c, the
 * find_peer loop). So the peer it returns always satisfies
 * peer_height > local_height, and the equality that opens the
 * fork-detection block cannot hold on the value taken from that peer.
 *
 * ⚠ THE CLAIM IS "NOT REACHABLE FROM A FIXTURE", NOT "PROVABLY DEAD", AND
 * THE DIFFERENCE IS WRITTEN DOWN RATHER THAN ROUNDED OFF. sync_check
 * reads the local height TWICE — once inside find_peer and once at the
 * comparison — through nodus_witness_block_height, the FAIL-OPEN wrapper
 * that answers 0 on a query failure. If the first read faulted (0, so any
 * peer above 0 is selected) and the second succeeded at a value equal to
 * that peer's height, the equality holds and the branch runs. That needs
 * a TRANSIENT fault landing between two calls inside one function, and
 * there is no seam a unit test can inject it at: the deterministic fault
 * this repo uses elsewhere (DROP TABLE) makes BOTH reads fail. So the
 * honest statement is that no fixture can drive it, not that no execution
 * can.
 *
 * There is no second entry point: the block is inline in sync_check and
 * nothing else calls it (grep drop_witness_db — the only other caller is
 * the tx_root fork path in nodus_witness_sync_handle_rsp, which does not
 * read the quorum).
 *
 * The guard was still written, and deliberately: the code is compiled,
 * the comparison is live, and the moment find_peer is changed to return
 * same-height peers — which is plainly what this block was written to
 * consume — the hole opens with a chain database deletion at the end of
 * it. What CANNOT be done honestly is to reach in and call it anyway; a
 * test that hand-called an inlined branch would prove the guard compiles
 * and nothing else. This section therefore reports absent coverage.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_sync_fork_drop_unreached(void) {
    printf("\n§2 sync fork DB drop — UNREACHED, coverage did NOT happen\n");
    printf("  UNREACHED: nodus_witness_sync_check's same-height fork branch "
           "cannot be driven\n");
    printf("             from a fixture. nodus_witness_sync_find_peer only "
           "returns peers\n");
    printf("             STRICTLY ahead of local_height, so "
           "`peer_height == local_height` is\n");
    printf("             false for the peer it selects. It could still be "
           "entered by a\n");
    printf("             TRANSIENT height-read fault between the function's "
           "two reads —\n");
    printf("             no fixture can inject one there. The guard is "
           "compiled and\n");
    printf("             correct; it is not exercised. Do NOT count this row "
           "as tested.\n");
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — the NEW_VIEW reproposal signature count (nodus_witness_bft.c,
 *      bft_view_move_finish: `take < w->bft_config.quorum`).
 *
 * `take` is clamped to the quorum, so at 0 it is 0 and `0 < 0` is false:
 * the guard that exists to stop us claiming a reproposal we cannot prove
 * is bypassed by the one value meaning we can prove nothing. The node
 * broadcasts a NEW_VIEW with has_reproposal = true and ZERO signatures.
 *
 * ⚠ HOW THIS SITE IS REACHED AT QUORUM 0, AND WHY THAT IS THE POINT.
 * bft_view_move_finish has two callers. One is bft_vc_check_quorum's
 * pre-genesis arm — and §5's guard now stops that path at quorum 0, so it
 * cannot deliver us here. The other is bft_viewok_apply, on a VERIFIED
 * VIEW_OK proof, and that path is deliberately NOT gated on the local
 * config: it is the recovery ladder for exactly the node whose config is
 * broken, and it derives its own f+1 threshold from the committee at the
 * height the proof carries. So a node with quorum 0 can still be carried
 * into a new view by a proof, find itself leader, and reach this line.
 * Both legs below therefore arrive through the proof path — the same
 * call, on the same fixture, with only bft_config.quorum differing.
 *
 * The prepared signatures attached to the source record are not
 * cryptographically checked anywhere on this path: bind_reproposal
 * selects on has_prepared and height alone, and the sender COPIES the
 * sigs onto the wire. They are real signatures anyway, so the section
 * does not depend on that remaining true.
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
 * hard-coded view would make this section's leader precondition a coin
 * flip that still printed PASS. Over v = 1..n the modulus visits every
 * seat exactly once, so such a view always exists. */
static uint32_t pick_leader_view(nodus_witness_t *w) {
    for (uint32_t v = 1; v <= N_PEERS; v++)
        if (is_leader_at(w, v)) return v;
    fprintf(stderr, "pick_leader_view: we never lead\n");
    exit(1);
}

/* Attach a view-change record from peer `idx` at `target`, carrying a
 * prepared certificate of `n_sigs` REAL prepared signatures. Built by
 * hand because the wire path that normally admits one (handle_viewchg)
 * runs its own quorum verify, which is a DIFFERENT guard from the one
 * this section is about — routing through it would make the section
 * measure §4 instead. */
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

/* Drive one leg: build a fixture at `quorum`, seat a committee, attach a
 * source record with `n_sigs`, and deliver a VIEW_OK proof that moves us
 * into a view we lead. The captured stderr is the verdict. */
static void newview_leg(uint32_t quorum, uint32_t n_sigs, uint8_t tag,
                        char *dir, char *out, size_t out_cap) {
    nodus_witness_t *w = fixture(N_PEERS);
    chain_db_open(w, dir, tag);

    /* The committee governs BOTH the VIEW_OK proof (verify_view_proof
     * resolves at the carried height) and is_leader. Height 1 keeps every
     * lookup inside epoch 0 whatever DNAC_EPOCH_LENGTH is. */
    const uint64_t H = 1;
    prime_committee(w, H, N_PEERS);

    w->bft_config.n_witnesses = N_PEERS;
    w->bft_config.quorum = quorum;
    w->bft_config.round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
    w->bft_config.viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;

    uint32_t V = pick_leader_view(w);

    uint8_t prep_txh[NODUS_T3_TX_HASH_LEN];
    memset(prep_txh, 0xC3, sizeof(prep_txh));
    attach_vc_record(w, 1, V, /*prep_height*/ H, /*prep_view*/ 0,
                     prep_txh, n_sigs);

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

    cap_begin();
    (void)nodus_witness_bft_handle_viewok(w, &vm);
    cap_end(out, out_cap);

    /* The proof must actually have moved us, or every assertion the
     * caller makes about the NEW_VIEW would be about a path never taken.
     * Asserted AFTER the capture closed, so a failure is visible. */
    if (w->current_view != V) {
        fprintf(stderr, "newview_leg: the VIEW_OK proof did NOT move the "
                        "view (still %u, wanted %u) — the leg tested "
                        "nothing\n%s\n", w->current_view, V, out);
        exit(1);
    }
    fixture_free(w, dir);
}

static void section_newview_reproposal(void) {
    printf("\n§3 NEW_VIEW reproposal — no reproposal is claimed on a quorum "
           "of 0\n");

    /* ── HEALTHY LEG A — at the threshold, the NEW_VIEW carries sigs. */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_qv_nv_ok_XXXXXX";
        newview_leg(Q_HEALTHY, /*n_sigs*/ Q_HEALTHY, 0x31, dir,
                    out, sizeof(out));
        CHECK(said(out, "C5 NEW_VIEW reproposal"),
              "HEALTHY: with quorum 5 and five prepared signatures the new "
              "leader DOES send a NEW_VIEW reproposal");
        CHECK(said(out, "carrying 5 sigs"),
              "and it carries all five — the guard passes a provable "
              "reproposal through at its real value");
    }

    /* ── HEALTHY LEG B — one short, and the existing guard fires. This is
     * the anti-vacuity control for the guard itself: it proves the
     * threshold is still enforced in the ordinary direction. */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_qv_nv_short_XXXXXX";
        newview_leg(Q_HEALTHY, /*n_sigs*/ 3, 0x32, dir, out, sizeof(out));
        CHECK(said(out, "C5 cannot prove the reproposal"),
              "HEALTHY: three signatures against a quorum of 5 is refused "
              "by the pre-existing guard, unchanged");
        CHECK(!said(out, "C5 NEW_VIEW reproposal"),
              "and no NEW_VIEW reproposal went out");
    }

    /* ── VACUUM LEG — same call, quorum 0. Without the new guard `take`
     * is clamped to 0, `0 < 0` is false, and a NEW_VIEW goes out claiming
     * a reproposal with zero attached signatures. */
    {
        static char out[CAP_BUF];
        char dir[] = "/tmp/test_qv_nv_vac_XXXXXX";
        newview_leg(0, /*n_sigs*/ 3, 0x33, dir, out, sizeof(out));
        CHECK(said(out, "C5 vacuous quorum — refusing to claim a "
                        "reproposal"),
              "VACUUM: with quorum 0 the reproposal is refused, and the "
              "refusal names THIS guard");
        CHECK(!said(out, "C5 NEW_VIEW reproposal"),
              "and no NEW_VIEW was sent — in particular not one claiming a "
              "reproposal it attaches zero signatures for");
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — the PREPARED CERTIFICATE threshold
 *      (nodus_witness_bft_verify_prepared_cert:
 *       `required = have_committee ? dna_bft_quorum(c_count)
 *                                  : w->bft_config.quorum`).
 *
 * `verified >= 0` is true for every input, INCLUDING verified == 0 — a
 * certificate in which not one signature checked out. The function's own
 * contract promises the opposite ("Anything short of that ... is false,
 * i.e. fail-closed").
 *
 * ⚠ THIS SECTION REACHES QUORUM 0 THROUGH THE PRODUCTION INITIALISER, not
 * a hand-set field: a four-member roster handed to
 * nodus_witness_bft_config_init takes its "below NODUS_T3_MIN_WITNESSES —
 * consensus disabled" branch. That is what makes the state real rather
 * than a fixture artefact. Note the shape of the disagreement the two
 * comments added in this phase describe: dna_bft_quorum(4) is 3 while the
 * initialiser says 0 for the same n, and the section asserts BOTH so the
 * next reader does not "reconcile" them.
 *
 * No committee is primed, so have_committee is false and the F17 A5
 * pre-genesis roster arm — the one that must be preserved, not deleted —
 * is the arm under test.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_prepared_cert(void) {
    printf("\n§4 prepared cert — a threshold of 0 verifies nothing\n");

    const uint64_t H = 3;
    const uint32_t V = 2;
    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x44, sizeof(txh));

    /* ── HEALTHY LEG — five roster members, the smallest count the
     * production initialiser will actually serve. quorum = (2*5)/3+1 = 4,
     * and BOTH directions are asserted: four real signatures verify,
     * three do not. */
    {
        nodus_witness_t *w = fixture(5);
        char dir[] = "/tmp/test_qv_cert_ok_XXXXXX";
        chain_db_open(w, dir, 0x41);
        nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);

        CHECK(w->bft_config.quorum == 4,
              "precondition: a five-member roster yields quorum 4 from the "
              "production initialiser, not the consensus-disabled zero");

        nodus_t3_cert_entry_t cert[4];
        memset(cert, 0, sizeof(cert));
        for (int i = 0; i < 4; i++) {
            memcpy(cert[i].voter_id, g_peers[i].id, NODUS_T3_WITNESS_ID_LEN);
            sign_prepared(cert[i].signature, &g_peers[i], V, H, txh,
                          w->chain_id);
        }

        CHECK(nodus_witness_bft_verify_prepared_cert(w, H, V, txh, cert, 4),
              "HEALTHY: four real signatures resolve through the documented "
              "pre-genesis roster arm and the certificate VERIFIES");
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H, V, txh, cert, 3),
              "and three do not — the threshold is genuinely enforced, so "
              "the acceptance above is not a blanket yes");

        fixture_free(w, dir);
    }

    /* ── VACUUM LEG — four roster members. The SAME initialiser now takes
     * its consensus-disabled branch, and the pre-genesis arm has a
     * threshold of 0 to offer. */
    {
        nodus_witness_t *w = fixture(4);
        char dir[] = "/tmp/test_qv_cert_vac_XXXXXX";
        chain_db_open(w, dir, 0x42);
        nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);

        CHECK(w->bft_config.quorum == 0,
              "precondition: a four-member roster yields quorum 0 — the "
              "production initialiser's consensus-disabled branch, reached "
              "without a test-only assignment");
        CHECK(dna_bft_quorum(4) == 3,
              "and dna_bft_quorum(4) still answers 3 for the same n: the "
              "two functions answer DIFFERENT questions and the "
              "disagreement is deliberate (see both comments)");

        /* THE CERTIFICATE THAT MUST NOT PASS: four entries whose
         * signatures are junk, so `verified` is 0. On a build without the
         * guard, `0 >= 0` accepts it. */
        nodus_t3_cert_entry_t junk[4];
        memset(junk, 0, sizeof(junk));
        for (int i = 0; i < 4; i++) {
            memcpy(junk[i].voter_id, g_peers[i].id, NODUS_T3_WITNESS_ID_LEN);
            memset(junk[i].signature, 0x5A, NODUS_SIG_BYTES);
        }

        static char out[CAP_BUF];
        cap_begin();
        bool ok_junk = nodus_witness_bft_verify_prepared_cert(w, H, V, txh,
                                                              junk, 4);
        cap_end(out, sizeof(out));

        CHECK(!ok_junk,
              "VACUUM: a certificate in which NOT ONE signature verifies is "
              "REFUSED — before the guard, a threshold of 0 accepted it");
        CHECK(said(out, "C5 vacuous quorum — refusing the certificate"),
              "and the refusal names THIS guard, not the committee-load "
              "fault arm above it");

        /* The cost of the refusal, asserted rather than left implicit: at
         * quorum 0 even a certificate whose signatures are all REAL is
         * refused, because there is no threshold to measure it against.
         * That is the intended fail-closed behaviour, and the caller's
         * response is to rotate the view. */
        nodus_t3_cert_entry_t real[4];
        memset(real, 0, sizeof(real));
        for (int i = 0; i < 4; i++) {
            memcpy(real[i].voter_id, g_peers[i].id, NODUS_T3_WITNESS_ID_LEN);
            sign_prepared(real[i].signature, &g_peers[i], V, H, txh,
                          w->chain_id);
        }
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H, V, txh, real, 4),
              "and so is a certificate of four REAL signatures — fail-closed "
              "means the answer is 'no', not 'yes if they happen to check "
              "out against nothing'");

        fixture_free(w, dir);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §5 — the VIEW-CHANGE quorum (nodus_witness_bft.c, bft_vc_check_quorum:
 *      `bft_vc_tally(target) < w->bft_config.quorum`).
 *
 * The next step after this test is bft_viewok_emit_own, which SIGNS a
 * VIEW_OK statement and broadcasts it — and a VIEW_OK means "I observed a
 * view-change quorum for this view". At quorum 0 a node signs that claim
 * having observed one message, and peers COUNT those statements toward
 * the f+1 that moves their own view.
 *
 * ⚠ THE VACUUM LEG IS NOT DRIVEN BY ONE MESSAGE, AND THAT IS NOT A
 * WEAKENING. bft_vc_join_threshold already floors itself at 2, so a
 * single VIEW_CHANGE cannot make this node adopt a target at all — the
 * one place in the file that defended itself before this phase. Two peer
 * messages clear that floor, the f+1 join then self-records, and the
 * tally reaches 3 against a quorum that should be 5. Three is what the
 * old code called a quorum.
 *
 * No committee is primed: handle_viewchg's authorization takes the
 * pre-genesis roster arm, which keeps this section about the TALLY
 * threshold rather than about committee resolution.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_view_change_quorum(void) {
    printf("\n§5 view-change quorum — no VIEW_OK is signed on a quorum of "
           "0\n");

    /* ── HEALTHY LEG — quorum 5. The f+1 join threshold is
     * ((5-1)/2)+1 = 3, so peers 1-2 only record; peer 3 triggers our own
     * join (tally 4 with our self-record); peer 4 takes it to 5. The
     * quorum is declared at 5 and NOT before. */
    {
        nodus_witness_t *w = fixture(N_PEERS);
        char dir[] = "/tmp/test_qv_vc_ok_XXXXXX";
        chain_db_open(w, dir, 0x51);
        w->bft_config.n_witnesses = N_PEERS;
        w->bft_config.quorum = Q_HEALTHY;
        w->bft_config.round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
        w->bft_config.viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;

        CHECK(w->current_view == 0 && w->view_change_count == 0,
              "precondition: no view change has been recorded yet");

        static char out_below[CAP_BUF];
        cap_begin();
        send_viewchg(w, 1, 1);
        send_viewchg(w, 2, 1);
        send_viewchg(w, 3, 1);
        cap_end(out_below, sizeof(out_below));

        CHECK(!said(out_below, "view change quorum!"),
              "HEALTHY: four voters (three peers plus our own f+1 join) do "
              "NOT reach a quorum of 5 — the threshold is enforced");
        CHECK(w->view_change_in_progress,
              "but the join DID happen, so the tally is genuinely "
              "accumulating and the leg is not passing by inaction");

        static char out_at[CAP_BUF];
        cap_begin();
        send_viewchg(w, 4, 1);
        cap_end(out_at, sizeof(out_at));

        CHECK(said(out_at, "view change quorum!"),
              "HEALTHY: the fifth voter reaches it and the quorum IS "
              "declared — the guard is not a blanket refusal");

        fixture_free(w, dir);
    }

    /* ── VACUUM LEG — quorum 0. Two peers clear the floored join
     * threshold, our self-record makes three, and on a build without the
     * guard `3 < 0` is false: quorum declared, VIEW_OK signed. */
    {
        nodus_witness_t *w = fixture(N_PEERS);
        char dir[] = "/tmp/test_qv_vc_vac_XXXXXX";
        chain_db_open(w, dir, 0x52);
        w->bft_config.n_witnesses = N_PEERS;
        w->bft_config.quorum = 0;
        w->bft_config.round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
        w->bft_config.viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;

        static char out[CAP_BUF];
        cap_begin();
        send_viewchg(w, 1, 1);
        send_viewchg(w, 2, 1);
        cap_end(out, sizeof(out));

        CHECK(w->view_change_in_progress,
              "VACUUM: the two peers DID pull us into a view change — the "
              "f+1 join floor of 2 is unchanged by this phase, so the "
              "refusal below is the quorum guard's and not the join's");
        CHECK(said(out, "vacuous quorum — refusing to declare a "
                        "view-change quorum"),
              "and the quorum check refused, naming THIS guard");
        CHECK(!said(out, "view change quorum!"),
              "no quorum was declared on three voters");
        CHECK(w->current_view == 0,
              "and the view did NOT move — the pre-genesis bootstrap arm "
              "below the guard, which moves the view on this very tally, "
              "was never reached");

        fixture_free(w, dir);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §6 — the SYNC CERT threshold (nodus_witness_sync.c,
 *      nodus_witness_sync_handle_rsp: arm (4)
 *      `sync_quorum = w->bft_config.quorum`).
 *
 * nodus_witness_verify_sync_certs' only threshold test is
 * `verified < quorum`, so at 0 a block is accepted with ZERO verified
 * certificates and replayed straight into this node's chain. O15G
 * confined this leg to db_height == 1 — genesis replay — which is where a
 * joining node has the fewest defences.
 *
 * The fixture reaches arm (4) the way a real joiner does: a fresh chain
 * database has the validator_set_snapshots table but no row (arm 1
 * declines), no validators to recompute a historical committee from (arm
 * 2 declines), and a genesis TX whose bytes carry no parseable chain_def
 * (arm 3 declines). Nothing is stubbed.
 * ═══════════════════════════════════════════════════════════════════ */

/* Build the height-1 sync response, with `n_certs` REAL commit
 * certificates over the block hash the receiver will recompute.
 *
 * ⚠ THE CERT CHAIN_ID IS ALL ZEROS, not w->chain_id: at db_height == 1
 * the handler verifies against cert_chain_id_zero, mirroring the genesis
 * signer whose chain_id was still unset at PRECOMMIT time. Signing with
 * the fixture's real chain_id would make every certificate fail and the
 * healthy leg would be green for the wrong reason. */
static void build_sync_rsp(nodus_witness_t *w, nodus_t3_msg_t *m,
                           uint8_t *tx_data, uint32_t tx_len, int n_certs) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_SYNC_RSP;
    fill_header(m, w, &g_peers[1], /*round*/ 0, /*view*/ 0);

    nodus_t3_sync_rsp_t *r = &m->sync_rsp;
    r->found = true;
    r->height = 1;
    r->timestamp = nodus_time_now();
    r->tx_count = 1;
    memcpy(r->proposer_id, g_peers[1].id, NODUS_T3_WITNESS_ID_LEN);
    memset(r->prev_hash, 0, NODUS_T3_TX_HASH_LEN);   /* genesis: zeros */

    memset(r->batch_txs[0].tx_hash, 0x61, NODUS_T3_TX_HASH_LEN);
    r->batch_txs[0].tx_type = NODUS_W_TX_GENESIS;
    r->batch_txs[0].tx_data = tx_data;
    r->batch_txs[0].tx_len  = tx_len;

    /* tx_root is the MERKLE root the receiver recomputes; the cert
     * preimage's block_hash is SHA3-512 over the same concatenation. The
     * two are different derivations of the same bytes and both are
     * produced by the production functions here. */
    if (nodus_witness_merkle_tx_root(r->batch_txs[0].tx_hash, 1,
                                     r->tx_root) != 0) {
        fprintf(stderr, "tx_root compute failed\n"); exit(1);
    }
    uint8_t block_hash[NODUS_T3_TX_HASH_LEN];
    {
        nodus_key_t bh;
        if (nodus_hash(r->batch_txs[0].tx_hash, NODUS_T3_TX_HASH_LEN,
                       &bh) != 0) {
            fprintf(stderr, "block_hash compute failed\n"); exit(1);
        }
        memcpy(block_hash, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }

    uint8_t zero_cid[32];
    memset(zero_cid, 0, sizeof(zero_cid));
    r->cert_count = (uint32_t)n_certs;
    for (int i = 0; i < n_certs; i++) {
        memcpy(r->certs[i].voter_id, g_peers[i].id, NODUS_T3_WITNESS_ID_LEN);
        sign_cert(r->certs[i].signature, &g_peers[i], block_hash,
                  /*height*/ 1, zero_cid);
    }
}

static void section_sync_cert_quorum(void) {
    printf("\n§6 sync cert threshold — a synced block is not accepted "
           "against a threshold of 0\n");

    /* A genesis TX body that is deliberately NOT a parseable chain_def,
     * so arm (3) declines and arm (4) is the one under test. Eight bytes
     * of zeros carry no chain_def trailer. */
    static uint8_t tx_body[8];
    memset(tx_body, 0, sizeof(tx_body));

    /* ── HEALTHY LEG A — quorum 5, five real certificates. The cert gate
     * PASSES (the block then fails later, at genesis replay, which this
     * fixture cannot satisfy — asserted by name so the leg cannot be
     * confused with a refusal at the gate). */
    {
        nodus_witness_t *w = fixture(N_PEERS);
        char dir[] = "/tmp/test_qv_sync_ok_XXXXXX";
        chain_db_open(w, dir, 0x61);
        w->bft_config.n_witnesses = N_PEERS;
        w->bft_config.quorum = Q_HEALTHY;
        w->sync_state.syncing = true;
        w->sync_state.sync_current_height = 1;
        w->sync_state.sync_target_height = 1;

        nodus_t3_msg_t m;
        build_sync_rsp(w, &m, tx_body, (uint32_t)sizeof(tx_body), 5);

        static char out[CAP_BUF];
        cap_begin();
        (void)nodus_witness_sync_handle_rsp(w, &m);
        cap_end(out, sizeof(out));

        CHECK(said(out, "certs verified: 5/5 (quorum=5)"),
              "HEALTHY: five real certificates meet a quorum of 5 and the "
              "cert gate PASSES");
        CHECK(said(out, "block replay failed at height 1"),
              "and the block was refused one step LATER, at genesis replay "
              "— so the gate really was passed, not skipped");
        CHECK(!said(out, "vacuous quorum"),
              "no vacuum guard fired on the healthy path");

        fixture_free(w, dir);
    }

    /* ── HEALTHY LEG B — quorum 5, three certificates. The pre-existing
     * threshold refuses, which is the anti-vacuity control: it proves the
     * comparison still works in the ordinary direction. */
    {
        nodus_witness_t *w = fixture(N_PEERS);
        char dir[] = "/tmp/test_qv_sync_short_XXXXXX";
        chain_db_open(w, dir, 0x62);
        w->bft_config.n_witnesses = N_PEERS;
        w->bft_config.quorum = Q_HEALTHY;
        w->sync_state.syncing = true;
        w->sync_state.sync_current_height = 1;
        w->sync_state.sync_target_height = 1;

        nodus_t3_msg_t m;
        build_sync_rsp(w, &m, tx_body, (uint32_t)sizeof(tx_body), 3);

        static char out[CAP_BUF];
        cap_begin();
        int rc = nodus_witness_sync_handle_rsp(w, &m);
        cap_end(out, sizeof(out));

        CHECK(rc == -1, "HEALTHY: three certificates against a quorum of 5 "
                        "is refused");
        CHECK(said(out, "cert verify FAILED at height 1"),
              "and the refusal is the pre-existing threshold's, unchanged");
        CHECK(!said(out, "block replay failed"),
              "the block never reached replay");

        fixture_free(w, dir);
    }

    /* ── VACUUM LEG — quorum 0 and ZERO certificates. Without the guard,
     * verify_sync_certs is handed a threshold of 0, `0 < 0` is false, and
     * the block is accepted and replayed with nothing proving it. */
    {
        nodus_witness_t *w = fixture(N_PEERS);
        char dir[] = "/tmp/test_qv_sync_vac_XXXXXX";
        chain_db_open(w, dir, 0x63);
        w->bft_config.n_witnesses = N_PEERS;
        w->bft_config.quorum = 0;
        w->sync_state.syncing = true;
        w->sync_state.sync_current_height = 1;
        w->sync_state.sync_target_height = 1;

        nodus_t3_msg_t m;
        build_sync_rsp(w, &m, tx_body, (uint32_t)sizeof(tx_body), 0);

        static char out[CAP_BUF];
        cap_begin();
        int rc = nodus_witness_sync_handle_rsp(w, &m);
        cap_end(out, sizeof(out));

        CHECK(rc == -1,
              "VACUUM: a block offering ZERO certificates is REFUSED");
        CHECK(said(out, "vacuous quorum — refusing to verify block"),
              "and the refusal names THIS guard");
        CHECK(!said(out, "certs verified: 0/0"),
              "the site did not report a cert set it never measured");
        CHECK(!said(out, "block replay failed"),
              "and the block never reached replay — the refusal is BEFORE "
              "any state mutation");
        CHECK(!w->sync_state.syncing,
              "the sync latch was released, so the next tick can retry "
              "once an authority exists");

        fixture_free(w, dir);
    }
}

int main(void) {
    printf("\nO15O Faz 2 — a quorum of 0 is refused, not obeyed\n");

    for (int i = 0; i < N_KEYS; i++) peer_make(&g_peers[i]);

    section_vote_quorum();
    section_sync_fork_drop_unreached();
    section_newview_reproposal();
    section_prepared_cert();
    section_view_change_quorum();
    section_sync_cert_quorum();

    printf("\nO15O Faz 2 quorum-vacuum PASS (5 of 6 sites covered; §2 "
           "UNREACHED — see its section comment)\n");
    return 0;
}
