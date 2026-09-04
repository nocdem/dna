/**
 * Nodus — O15R B′ + D — THE VIEW BOUNDARY IS NO LONGER A HOLE
 *
 * WHAT THIS PROVES.
 *   Nodes cross a view boundary at DIFFERENT INSTANTS. Each moves its own
 *   `current_view` only after independently verifying an f+1 VIEW_OK proof
 *   (nodus_witness_bft.c, bft_viewok_apply is the one writer), so a node
 *   still holding view V while the rest of the cluster opens V+1 is the
 *   ORDINARY case, not a fault. Consensus frames are broadcast EXACTLY
 *   ONCE — there is no re-send path anywhere in this tree — so everything
 *   such a node refused in that window is gone for good:
 *
 *     1. the new leader's PROPOSE, refused at the phase gate as "round in
 *        progress" ABOVE the view gate, so the node never even reached the
 *        proof request that would have moved it;
 *     2. every PREVOTE/PRECOMMIT for V+1, dropped at the round/view
 *        equality test in bft_handle_vote_inner;
 *     3. and then, having moved on a proof and finding itself IDLE with
 *        nothing pending, the node waited a full round timeout — or worse,
 *        P3 fired immediately against a leader that had not had one tick.
 *
 *   THE PROPERTY THAT WOULD BE FALSE IF THIS FILE FAILED: a witness that
 *   is one view behind still ARRIVES in the new view holding the round —
 *   it enters PREVOTE on the leader's proposal and counts the votes cast
 *   for that view — instead of arriving empty-handed.
 *
 *   WHY IT IS FATAL AT N=20 AND INVISIBLE AT N=7. A round needs `quorum`
 *   prevotes. With 20 validators and 6 stopped, the 14 survivors ARE the
 *   quorum: 14 of 14, no slack whatever. One node a boundary behind is one
 *   vote the round can never collect, which makes it unwinnable — and then
 *   the timeout rotates the view and the same thing happens again.
 *   Measured at one stuck height (nodus/BUGS.md, N=20 entry): PREVOTE
 *   quorum reached 74 times, PRECOMMIT quorum ZERO times, ZERO commits;
 *   495 votes dropped of which 486 — 98% — involved a VIEW disagreement
 *   rather than a round one; 45 proposals refused as "round in progress",
 *   35 of them from a view AHEAD of the refusing node. Of the 28 views
 *   that height passed through, 21 had a live leader that really opened a
 *   round, so this is NOT the dead-leader problem O15I already closed.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro, and no
 *   short-epoch DNAC_EPOCH_LENGTH — every fixture chain stays inside
 *   epoch 0 (tip 3, height 4), so each assertion holds identically at the
 *   shipped 720 and at the harness's 15. Every epoch a section needs is
 *   DERIVED from the macro; none is written as a literal.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, nothing that must be exported before the run. The one
 *   filesystem dependency is a writable /tmp for mkdtemp/mkstemp.
 *
 * WHAT IT LEAVES BEHIND.
 *   Nothing. Every section builds its chain database in its own mkdtemp()
 *   directory under /tmp and removes it with `rm -rf` before returning.
 *   The stderr-capture file is created with mkstemp and unlinked
 *   immediately, so it exists only as an open descriptor. No processes, no
 *   arm files, no restarted or halted nodes, nothing outside the section's
 *   own temporary directory.
 *
 * HOW IT CAN LIE.
 *   - THE VACUITY TRAP, and it is the main one here. "The vote was not
 *     counted" is the state BEFORE this season as well as after — the
 *     difference is that it is now PARKED rather than destroyed. So §1
 *     never asserts a refusal alone: it asserts the buffer entry exists
 *     with the right view, and then that the SAME vote is COUNTED once the
 *     node holds that view. A change that merely dropped votes differently
 *     would fail the second half loudly.
 *   - §2b IS THE ANTI-VACUITY CONTROL FOR THE PARK. A slot that accepted
 *     any sender would pass §2a. §2b sends the identical proposal from a
 *     non-leader and requires the slot to stay EMPTY, which is what pins
 *     the park to the leader/committee block it sits below.
 *   - §3's SECOND HALF is the anti-vacuity control for the P3 change:
 *     without it, simply disabling P3 would pass the first half.
 *   - THE LEADER IS DIFFERENT ON EVERY RUN. Witness ids are SHA3-512 over
 *     freshly generated ML-DSA-87 keys, so this node's rank — and
 *     therefore who leads at a given view — changes per process. Every
 *     view used here is CHOSEN AT RUNTIME by asking the production
 *     predicate, and the selected leader is ASSERTED before it is used. A
 *     hard-coded view would be a coin flip that still printed PASS.
 *   - THE REPLAY TRAP. is_replay() keys on (sender_id, nonce) in a
 *     PROCESS-GLOBAL table, so every message must carry a fresh nonce or
 *     it dies at the replay gate above everything under test. fill_header
 *     re-randomises on every call and nothing here reuses a filled header.
 *   - §2 DRIVES THE REAL DISPATCHER for the store, not the store helper by
 *     hand: nodus_witness_dispatch_t3 with a signed, encoded frame and
 *     conn == NULL. That is what makes "the handler returned 1 AND the
 *     dispatcher parked the bytes" one fact instead of two hopes. The rc
 *     itself is additionally pinned by a direct call on a SEPARATE frame
 *     (its own nonce), because the slot alone cannot distinguish rc 1 from
 *     some future rc 2.
 *   - ⚠ §2d's REPLAY MEETS ITS OWN C5 BINDING, NOT THE LEADER'S. A
 *     NEW_VIEW arriving while we are behind only triggers the proof
 *     request; its carried certificate is adopted only at an equal view.
 *     These fixtures' VIEW_CHANGEs carry NO prepared certificate, so
 *     bind_reproposal_from_view_changes clears the binding and the C5 gate
 *     is SKIPPED. The section therefore does NOT prove the replay survives
 *     a C5 binding — that residual is documented in the production comment
 *     and in docs/MEMPOOL_BLOCK_TIME.md, and it is fail-closed (a
 *     divergent binding refuses the replay and the view rotates).
 *   - §2d's PHASE ASSERTION DEPENDS ON THE QUORUM. The replayed round
 *     ends in PREVOTE rather than PRECOMMIT only because three approvals
 *     are below dna_bft_quorum(COMMITTEE_N) = (2*5)/3+1 = 4. Were that
 *     formula or COMMITTEE_N to change so the threshold became 3, the
 *     drain would advance the phase and the assertion would fail for a
 *     reason that has nothing to do with the boundary. The CHECK on
 *     `w->bft_config.quorum` immediately before it is what makes that a
 *     STATED precondition instead of a silent accident.
 *   - "ACCEPTED" MEANS ENTERED PREVOTE, NEVER COMMITTED. handle_propose
 *     returns 0 even when the batch is unverifiable — tx_invalid produces
 *     a REJECT prevote and the handler still returns 0. The accepting
 *     sections assert the ROUND ENTRY (phase, round_state.view,
 *     current_round), which is the same outcome
 *     test_bft_view_change_hardening.c §12f and
 *     test_witness_prepared_lock.c assert. Nothing here commits a block or
 *     opens a socket.
 *   - WHAT IT CANNOT SEE. Nothing here runs two nodes. That the two sides
 *     of a boundary AGREE — that the parked frame is the same one the
 *     ahead-node is serving — is an argument about one node's behaviour
 *     repeated, not a measurement of a cluster. The cluster measurement is
 *     tests/integration/stagef/tests/test_v2_grow_7_20.sh.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_mempool.h"
/* Included EXPLICITLY rather than relied on transitively: no other
 * witness header pulls it in, and nodus_witness_vset_insert is what
 * seed_committee writes the snapshot with. */
#include "witness/nodus_witness_vset.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "transport/nodus_tcp.h"    /* nodus_time_now */
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"          /* DNAC_EPOCH_LENGTH, DNAC_PUBKEY_SIZE */
#include "dnac/vset_wire.h"
#include "dnac/ledger_ids.h"    /* dna_bft_quorum */

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

/* Seven is the shipped devnet size and is above NODUS_T3_MIN_WITNESSES,
 * so the modulus has every slot to land on when a section looks for a
 * view it does not lead. The quorum of 3 is the value
 * test_bft_view_change_hardening.c's §12 fixtures use, and it is chosen
 * for the VIEW-CHANGE arithmetic rather than for the round: with quorum 3
 * the f+1 join threshold is 2, so two peer VIEW_CHANGEs plus our own
 * self-record complete the quorum exactly. */
#define N_PEERS   6                 /* plus self = 7 in the roster */
#define QUORUM    3
#define ROUND_TO  15000
#define VC_TO     10000

/* The committee snapshot size for the sections that move a view.
 * FIVE, and four would have been a trap: nodus_witness_bft_config_init
 * ZEROES the quorum and both timeouts below NODUS_T3_MIN_WITNESSES (5), so
 * a four-member snapshot leaves the node with quorum 0 the moment anything
 * calls refresh_bft_config_from_committee — and handle_propose does, on
 * every proposal. dna_bft_quorum(5) = 4, so the verifier's f+1 is
 * ((4-1)/2)+1 = 2: our own VIEW_OK statement plus ONE peer's is a proof,
 * which matches the join threshold above so no attempt is wasted. */
#define COMMITTEE_N 5

/* The chain is seeded to this tip, so A2 demands height TIP_BLOCKS + 1 of
 * every proposal. Both stay far inside epoch 0 at any
 * DNAC_EPOCH_LENGTH >= 2. */
#define TIP_BLOCKS 3

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_bft_view_change_hardening.c, trimmed.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

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

/* ML-DSA-87 keygen is the expensive part of this file, so the identities
 * are generated ONCE in main and reused. `g_all[0]` is always this node,
 * and the roster is filled in array order so g_all and
 * w->roster.witnesses share indices. */
static peer_t g_all[N_PEERS + 1];

/* nodus_witness_t is multi-MB: heap, never stack (repo discipline). */
static nodus_witness_t *fixture(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!w || !srv) { fprintf(stderr, "fixture alloc\n"); exit(1); }

    memcpy(srv->identity.pk.bytes, g_all[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, g_all[0].sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, g_all[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i <= N_PEERS; i++) roster_put(w, &g_all[i]);

    w->bft_config.n_witnesses = w->roster.n_witnesses;
    w->bft_config.quorum = QUORUM;
    w->bft_config.round_timeout_ms = ROUND_TO;
    w->bft_config.viewchg_timeout_ms = VC_TO;

    /* The per-epoch committee cache is keyed on e_start with no
     * invalidation hook, so a calloc'd 0 would read as a HIT for epoch 0
     * before anything had been computed. Reset the sentinel exactly as
     * the production init path does. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->running = true;
    return w;
}

static void chain_db_open(nodus_witness_t *w, char *dir_template, uint8_t tag)
{
    if (mkdtemp(dir_template) == NULL) {
        fprintf(stderr, "mkdtemp failed\n"); exit(1);
    }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_template);
    /* 16 bytes is the canonical chain_id width; set_chain_id copies 16
     * and zero-fills to 32, so w->chain_id is NONZERO and
     * verify_chain_id's "we hold an identity, we enforce it" row applies
     * — which is what lets every crafted message carry w->chain_id and
     * pass. */
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0 || !w->db) {
        fprintf(stderr, "create_chain_db failed\n"); exit(1);
    }
}

static void scene_close(nodus_witness_t *w, const char *dir) {
    if (w) {
        nodus_witness_mempool_clear(&w->mempool);
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
 * tip it produced. READ BACK rather than assumed: blocks.height is
 * INTEGER PRIMARY KEY AUTOINCREMENT, so a caller that computed it itself
 * could silently be testing against a tip of 0 — the value that makes A2
 * demand height 1 and every proposal section vacuous. */
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

/* ── Committee snapshot ──────────────────────────────────────────────
 *
 * Written DIRECTLY rather than computed. That is not a shortcut around
 * the production path: a persisted snapshot IS the committee authority
 * for its epoch (nodus_witness_committee.c), and writing it lets these
 * sections vary exactly one thing without dragging in stake ranking,
 * minimum tenure and the sortition seed — none of which this file is
 * about. Copied from put_snapshot in test_bft_view_change_hardening.c. */
static void put_snapshot(nodus_witness_t *w, uint64_t epoch,
                         const peer_t *members, int n) {
    dna_vset_snapshot_t *snap = dna_vset_alloc((uint16_t)n);
    if (!snap) { fprintf(stderr, "vset alloc\n"); exit(1); }
    snap->epoch = epoch;
    snap->active_count = (uint16_t)n;
    /* TOPN_V1 rejects any nonzero seed byte (vset_wire.h encode
     * contract) — the seed belongs to a sortition ruleset that does not
     * ship. */
    memset(snap->sortition_seed, 0, sizeof(snap->sortition_seed));
    for (int i = 0; i < n; i++) {
        memcpy(snap->entries[i].voter_id, members[i].id,
               DNA_VSET_VOTER_ID_LEN);
        memcpy(snap->entries[i].pubkey, members[i].pk, DNA_VSET_PUBKEY_LEN);
        snap->entries[i].total_stake    = 10000000ULL;
        snap->entries[i].self_bond      = 10000000ULL;
        snap->entries[i].commission_bps = 0;
    }
    size_t need = dna_vset_encoded_len(snap);
    uint8_t *blob = malloc(need);
    if (!blob) { fprintf(stderr, "blob alloc\n"); exit(1); }
    size_t wrote = 0;
    if (dna_vset_encode(snap, blob, need, &wrote) != 0) {
        fprintf(stderr, "vset encode\n"); exit(1);
    }
    uint8_t h[DNA_VSET_HASH_LEN];
    if (dna_vset_hash_bytes(blob, wrote, h) != 0) {
        fprintf(stderr, "vset hash\n"); exit(1);
    }
    if (nodus_witness_vset_insert(w, epoch, blob, wrote, h, epoch) != 0) {
        fprintf(stderr, "vset insert\n"); exit(1);
    }
    free(blob);
    dna_vset_free(&snap);
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;
}

/* Seed the committee governing THIS node's next block height, and PROVE
 * it resolves. Without a committee nothing that moves a view can happen
 * at all: sign_view_ok refuses on an empty set and verify_view_proof
 * answers -2, so the view could never move and every rotation assertion
 * would pass or fail for the wrong reason.
 *
 * The e_start is DERIVED, never assumed: the resolver keys on
 * (height / DNAC_EPOCH_LENGTH) * DNAC_EPOCH_LENGTH, and that constant is
 * a build flag (720 shipped, 15 on short-epoch harness builds), so a
 * literal would silently miss on one of them. */
static void seed_committee(nodus_witness_t *w, int n) {
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    uint64_t e_start = (next_bh / (uint64_t)DNAC_EPOCH_LENGTH) *
                       (uint64_t)DNAC_EPOCH_LENGTH;
    put_snapshot(w, e_start, g_all, n);

    nodus_committee_member_t *cm = NULL;
    int count = 0;
    CHECK(nodus_committee_get_for_block_alloc(w, next_bh, &cm, &count) == 0,
          "the committee governing our next block height loads");
    CHECK(count == n,
          "and it is exactly the set just written — so every gate below "
          "runs against a REAL committee, not the pre-genesis fallback");
    bool self_in = false;
    for (int i = 0; i < count; i++)
        if (memcmp(cm[i].pubkey, w->server->identity.pk.bytes,
                   DNAC_PUBKEY_SIZE) == 0) self_in = true;
    CHECK(self_in, "and WE are in it — otherwise our own VIEW_OK statement "
                   "would be skipped by the verifier and f+1 could never "
                   "be met");
    free(cm);
}

/* ═══════════════════════════════════════════════════════════════════
 * Leadership — asked of the PRODUCTION code, never re-implemented.
 * ═══════════════════════════════════════════════════════════════════ */

/* Does the production predicate call US the leader at `view`?
 * `current_view` is restored — probing must not be an edit. */
static bool is_leader_at(nodus_witness_t *w, uint32_t view) {
    uint32_t saved = w->current_view;
    w->current_view = view;
    bool is_l = nodus_witness_bft_is_leader(w);
    w->current_view = saved;
    return is_l;
}

/* The peer that IS the leader at `view`, resolved the way handle_propose
 * resolves it.
 *
 * ⚠ IT MUST ASK THE SAME QUESTION handle_propose ASKS, AND THAT QUESTION
 * HAS TWO ANSWERS. With a validator-set snapshot the sender is ranked
 * inside the COMMITTEE; with none it falls back to the SORTED gossip
 * roster (F17 A5). Sections here use both, so a helper that knew only one
 * arm would pick the wrong peer and every "the sender is the leader"
 * precondition would be false while the section still printed PASS.
 *
 * The committee seat is resolved back to g_all BY PUBKEY, never by
 * indexing witnesses[] with the slot — the exact confusion BUGS.md
 * 2026-08-04 records (node7 saw the honest proposer at arrival index 6
 * and every sorted peer at rank 0). */
static const peer_t *leader_at(nodus_witness_t *w, uint32_t view) {
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;

    nodus_committee_member_t *cm = NULL;
    int count = 0;
    if (nodus_committee_get_for_block_alloc(w, next_bh, &cm, &count) != 0) {
        fprintf(stderr, "leader_at: committee load failed\n"); exit(1);
    }
    if (count > 0) {
        int slot = nodus_witness_bft_leader_index(epoch, view, count);
        if (slot < 0 || slot >= count) {
            fprintf(stderr, "leader_at: seat %d of %d\n", slot, count);
            exit(1);
        }
        for (int i = 0; i <= N_PEERS; i++) {
            if (memcmp(g_all[i].pk, cm[slot].pubkey, DNAC_PUBKEY_SIZE) == 0) {
                free(cm);
                return &g_all[i];
            }
        }
        fprintf(stderr, "leader_at: committee seat %d not in g_all\n", slot);
        exit(1);
    }
    free(cm);

    int slot = nodus_witness_bft_leader_index(epoch, view,
                                              (int)w->roster.n_witnesses);
    int arr = nodus_witness_roster_sorted_at(&w->roster, slot);
    if (arr < 0 || arr > N_PEERS) {
        fprintf(stderr, "leader_at: sorted seat %d out of range\n", slot);
        exit(1);
    }
    return &g_all[arr];
}

/* The lowest view > 0 at which we are NOT the leader AND we are not the
 * leader at the NEXT view either. Both halves are needed: every section
 * below drives a boundary from V to V+1 in which some PEER leads V+1, and
 * a section that accidentally selected itself as that leader would take
 * the i_am_leader branch of bft_view_move_finish and prove nothing. */
static uint32_t pick_follower_pair(nodus_witness_t *w) {
    uint32_t lim = w->roster.n_witnesses * 2 + 2;
    for (uint32_t v = 1; v + 1 <= lim; v++)
        if (!is_leader_at(w, v) && !is_leader_at(w, v + 1))
            return v;
    fprintf(stderr, "pick_follower_pair: no consecutive pair we do not "
                    "lead\n");
    exit(1);
}

/* ═══════════════════════════════════════════════════════════════════
 * Message builders
 * ═══════════════════════════════════════════════════════════════════ */

/* A fresh header. The nonce is re-randomised on EVERY call because
 * is_replay() keys on (sender_id, nonce) in a PROCESS-GLOBAL table: a
 * second message reusing the first one's nonce dies at the replay gate,
 * above every gate this file tests. */
static void fill_header(nodus_t3_msg_t *m, nodus_witness_t *w,
                        const peer_t *from, uint64_t round, uint32_t view) {
    m->header.version = NODUS_T3_BFT_PROTOCOL_VER;
    m->header.round = round;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
}

/* The 116-byte PREPARED preimage (O15N Faz 2A):
 *   "prepared"(8) ‖ chain_id(32) ‖ view(4 BE) ‖ height(8 BE) ‖ tx_hash(64)
 * compute_prepared_preimage is file-static in the implementation and so
 * cannot be called from here; this mirrors it, identically to
 * test_witness_prepared_lock.c and test_bft_view_change_hardening.c.
 *
 * ⚠ THE VIEW MATTERS FOR THIS FILE MORE THAN FOR ANY OTHER. The verifier
 * builds the preimage with `w->current_view` — the view the node holds AT
 * DRAIN TIME, not the one it held when the vote arrived — so a parked
 * vote must be signed over the view it is FOR. Signing over the sender's
 * old view would make every parked vote fail the C5 cert check and the
 * section would look like a park that does not work. */
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

/* The 148-byte purpose-0x08 VIEW_OK preimage (compute_view_ok_preimage):
 * "viewok\0\0"(8) ‖ chain_id(32) ‖ height(8 BE) ‖ view(4 BE) ‖
 * set_hash(64) ‖ voter_id(32). */
static void sign_viewok(uint8_t out[NODUS_SIG_BYTES], const peer_t *p,
                        uint64_t height, uint32_t view,
                        const uint8_t set_hash[64], const uint8_t *chain_id) {
    uint8_t pre[148];
    memset(pre, 0, sizeof(pre));
    memcpy(pre, "viewok", 6);                 /* [6..7] stay NUL */
    memcpy(pre + 8, chain_id, 32);
    for (int i = 0; i < 8; i++)
        pre[40 + i] = (uint8_t)(height >> ((7 - i) * 8));
    pre[48] = (uint8_t)(view >> 24); pre[49] = (uint8_t)(view >> 16);
    pre[50] = (uint8_t)(view >> 8);  pre[51] = (uint8_t)view;
    memcpy(pre + 52, set_hash, 64);
    memcpy(pre + 116, p->id, NODUS_T3_WITNESS_ID_LEN);

    nodus_sig_t sig;
    nodus_seckey_t sk;
    memcpy(sk.bytes, p->sk, sizeof(sk.bytes));
    if (nodus_sign_view_ok(&sig, pre, sizeof(pre), &sk) != 0) {
        fprintf(stderr, "viewok sign failed\n"); exit(1);
    }
    memcpy(out, sig.bytes, NODUS_SIG_BYTES);
}

/* One VIEW_OK statement from `from`, through the production handler.
 *
 * ⚠ THE SET HASH IS NEVER RECOMPUTED HERE. compute_committee_set_hash is
 * static in nodus_witness_bft.c, and a second implementation in this file
 * would be a second answer to a question the production code already
 * settles — the two would drift and the drift would look like a consensus
 * bug. Callers read the hash the node itself signed under, out of
 * w->viewok_acc.set_hash, AFTER driving the node to its own quorum. */
static int viewok_deliver1(nodus_witness_t *w, const peer_t *from,
                           uint64_t height, uint32_t view,
                           const uint8_t set_hash[64]) {
    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_VIEWOK;
    fill_header(&m, w, from, w->round_state.round, w->current_view);
    m.viewok.height = height;
    m.viewok.view = view;
    memcpy(m.viewok.set_hash, set_hash, 64);
    m.viewok.n_entries = 1;
    memcpy(m.viewok.entries[0].voter_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    sign_viewok(m.viewok.entries[0].signature, from, height, view, set_hash,
                w->chain_id);
    return nodus_witness_bft_handle_viewok(w, &m);
}

static void fill_viewchg(nodus_t3_msg_t *m, nodus_witness_t *w,
                         const peer_t *from, uint32_t new_view) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWCHG;
    fill_header(m, w, from, w->round_state.round, w->current_view);
    m->viewchg.new_view = new_view;
    m->viewchg.last_committed_round = w->last_committed_round;
}

/* ⚠ THE BATCH-TX POINTER FIELDS MUST BE NON-NULL IN THIS FILE, AND THAT
 * IS THE ONE WAY THIS BUILDER DIFFERS FROM ITS SIBLINGS.
 *
 * `nodus_t3_batch_tx_t` carries `nullifiers[]`, `tx_data`, `client_pubkey`
 * and `client_sig` as POINTERS (nodus_tier3.h:174-179), and `enc_batch_tx`
 * writes the last two UNCONDITIONALLY at a fixed length:
 *
 *     cbor_encode_bstr(enc, tx->client_pubkey, NODUS_PK_BYTES);   :162-163
 *     cbor_encode_bstr(enc, tx->client_sig,   NODUS_SIG_BYTES);   :164-165
 *
 * with no NULL check, and cbor_encode_bstr reaches memcpy through enc_raw
 * (nodus_cbor.c:59-65). test_bft_view_change_hardening.c and
 * test_witness_prepared_lock.c leave both NULL and are RIGHT to: they hand
 * the struct straight to nodus_witness_bft_handle_propose, which never
 * encodes it and whose decode-side copies ARE NULL-guarded
 * (nodus_witness_bft.c:6300-6303). THIS file must go through the real
 * nodus_t3_encode / nodus_witness_dispatch_t3 path — the park stores RAW
 * FRAME BYTES, so nothing else exercises the store — and that path
 * dereferences both. Leaving them NULL segfaults inside the encoder before
 * a single assertion runs.
 *
 * NOT A PRODUCTION DEFECT: the only production writers are
 * nodus_witness_bft.c:5068 and :8004, both `btx->client_pubkey =
 * e->client_pubkey` where that field is an ARRAY on the mempool entry
 * (nodus_witness_mempool.h:33), so a leader always passes the address of
 * an array. The missing encoder guard is a latent robustness gap, recorded
 * separately; this file must not paper over it by pretending the field is
 * optional.
 *
 * Zero-filled is the right content: the batch is REJECT-voted either way
 * (see "ACCEPTED MEANS ENTERED PREVOTE" in the header), and these bytes
 * only have to EXIST for the encoder to read them. */
static const uint8_t g_zero_pk[NODUS_PK_BYTES];
static const uint8_t g_zero_sig[NODUS_SIG_BYTES];
static const uint8_t g_zero_txd[8];

/* Build a PROPOSE for `height` from `leader` at `view`, carrying one batch
 * TX whose hash is `ptx`. tx_root is SHA3-512 over the batch's tx_hashes —
 * the same derivation handle_propose recomputes — so the proposal is
 * well-formed all the way down to the batch check below the view gate. */
static void build_propose(nodus_t3_msg_t *pm, nodus_witness_t *w,
                          const peer_t *leader, uint64_t round, uint32_t view,
                          uint64_t height, const uint8_t *ptx,
                          uint8_t tx_root_out[NODUS_T3_TX_HASH_LEN]) {
    memset(pm, 0, sizeof(*pm));
    pm->type = NODUS_T3_PROPOSE;
    pm->txn_id = 1;
    fill_header(pm, w, leader, round, view);
    pm->propose.batch_count = 1;
    pm->propose.block_height = height;
    memcpy(pm->propose.batch_txs[0].tx_hash, ptx, NODUS_T3_TX_HASH_LEN);
    pm->propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;

    /* nullifier_count stays 0, so enc_batch_tx's `nls` loop
     * (nodus_tier3.c:157-159) never dereferences the nullifiers[] pointer
     * array. Any future section that raises the count MUST fill those
     * pointers too — same crash, same reason. */
    pm->propose.batch_txs[0].nullifier_count = 0;
    /* tx_len stays 0, so the decode side's `btx->tx_len > 0` guard skips
     * the copy and nothing changes about what the batch check decides. The
     * pointer is still made non-NULL because enc_raw's memcpy runs even at
     * length 0, where a NULL source is undefined behaviour rather than a
     * fault — the one remaining way this builder could be quietly wrong. */
    pm->propose.batch_txs[0].tx_data = g_zero_txd;
    pm->propose.batch_txs[0].tx_len  = 0;
    pm->propose.batch_txs[0].client_pubkey = g_zero_pk;
    pm->propose.batch_txs[0].client_sig    = g_zero_sig;

    nodus_key_t bh;
    if (nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) != 0) {
        fprintf(stderr, "tx_root hash failed\n"); exit(1);
    }
    memcpy(pm->propose.tx_root, bh.bytes, NODUS_T3_TX_HASH_LEN);
    if (tx_root_out) memcpy(tx_root_out, bh.bytes, NODUS_T3_TX_HASH_LEN);
}

/* Sign, encode and push a message through the REAL dispatch entry point —
 * which is where the parked-PROPOSE store lives, and therefore the only
 * way to prove the store is actually wired to the handler's return value.
 *
 * conn == NULL: nodus_witness_peer_ensure is conn-guarded, so this needs
 * no socket. Copied from dispatch_prevote in
 * test_witness_protocol_version_gate.c. */
static void dispatch_msg(nodus_witness_t *w, const peer_t *from,
                         const nodus_t3_msg_t *m) {
    static uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;
    nodus_seckey_t sk;
    memcpy(sk.bytes, from->sk, sizeof(sk.bytes));
    if (nodus_t3_encode(m, &sk, buf, sizeof(buf), &len) != 0 || len == 0) {
        fprintf(stderr, "t3 encode failed\n"); exit(1);
    }
    nodus_witness_dispatch_t3(w, NULL, buf, len);
}

/* Deliver one APPROVE PREVOTE at an arbitrary (round, view), carrying a
 * cert_sig over `cert_view`. Returns the prevote_count delta so callers
 * can assert "counted" and "not counted" as a measurement rather than as
 * an inference from a return code. */
static int deliver_prevote(nodus_witness_t *w, const peer_t *from,
                           uint64_t round, uint32_t view, uint32_t cert_view,
                           uint64_t height, const uint8_t *tx_hash) {
    int before = w->round_state.prevote_count;
    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_PREVOTE;
    fill_header(&m, w, from, round, view);
    m.vote.vote = NODUS_W_VOTE_APPROVE;
    memcpy(m.vote.vote_target, tx_hash, NODUS_T3_TX_HASH_LEN);
    sign_prepared(m.vote.cert_sig, from, cert_view, height, tx_hash,
                  w->chain_id);
    (void)nodus_witness_bft_handle_vote(w, &m);
    return w->round_state.prevote_count - before;
}

/* Put the fixture into a live PREVOTE round with only our own approval
 * recorded. */
static void enter_round(nodus_witness_t *w, uint64_t round, uint32_t view,
                        uint64_t height, const uint8_t *tx_hash) {
    w->current_round = round;
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.round = round;
    w->round_state.view = view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    w->round_state.block_height = height;
    memcpy(w->round_state.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.prevotes[0].voter_id, g_all[0].id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->round_state.prevotes[0].pubkey, g_all[0].pk, NODUS_PK_BYTES);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;
    w->round_state.phase_start_time = nodus_time_now() * 1000ULL;
}

/* ── Vote-buffer inspection ─────────────────────────────────────────── */

static int buf_used(const nodus_witness_t *w) {
    int n = 0;
    for (int i = 0; i < NODUS_W_VOTE_BUFFER_CAP; i++)
        if (w->vote_buffer[i].used) n++;
    return n;
}

static int buf_used_at_view(const nodus_witness_t *w, uint32_t view) {
    int n = 0;
    for (int i = 0; i < NODUS_W_VOTE_BUFFER_CAP; i++)
        if (w->vote_buffer[i].used && w->vote_buffer[i].view == view) n++;
    return n;
}

static bool buf_has(const nodus_witness_t *w, uint32_t view, uint64_t round) {
    for (int i = 0; i < NODUS_W_VOTE_BUFFER_CAP; i++)
        if (w->vote_buffer[i].used && w->vote_buffer[i].view == view &&
            w->vote_buffer[i].round == round) return true;
    return false;
}

/* ── stderr capture — per-guard resolution ───────────────────────────
 *
 * handle_propose refuses at a dozen gates and every one of them returns
 * -1, so a return code alone cannot say WHICH fired. §2c needs to
 * distinguish "fell through the phase gate" from "was refused by it", and
 * the log line is the only discriminator. The window wraps ONLY the call
 * under test and stderr is restored BEFORE anything is asserted: a CHECK
 * failing inside the window would write its diagnosis into the temp file
 * and the binary would exit 1 saying nothing. Copied from
 * test_witness_prepared_lock.c. */
static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_vbound_XXXXXX";
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

/* ASCII-only, guard-unique tokens. The production lines carry em-dashes
 * and ellipses; neither is matched on. */
#define TOK_IN_PROGRESS "proposal rejected — round in progress"
#define TOK_PARKED      "parked the PROPOSE for view"

/* ═══════════════════════════════════════════════════════════════════
 * §1 — CHANGE 1: a vote for the NEXT view is PARKED, then COUNTED.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_vote_parked_then_counted(void) {
    printf("\n§1 a PREVOTE for view V+1 is parked while we hold V, and "
           "counted once we hold V+1\n");

    char dir[] = "/tmp/test_vbound_t1_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x71);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);
    CHECK(tip == (uint64_t)TIP_BLOCKS,
          "the seeded chain tip is what the writer reports");

    const uint32_t V = 4;
    const uint64_t R = 40;
    const uint64_t H = tip + 1;
    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x11, sizeof(txh));

    w->current_view = V;
    enter_round(w, R, V, H, txh);

    CHECK(w->round_state.prevote_count == 1,
          "precondition: the live round at (R, V) holds only our own "
          "approval");
    CHECK(buf_used(w) == 0, "precondition: the vote buffer is empty");

    /* THE VOTE. Same round as the live one — so the pre-existing
     * `future_round` admission cannot be what catches it — one view
     * ahead, and its cert is signed over V+1 because the verifier builds
     * the preimage with w->current_view AT DRAIN TIME. */
    int delta = deliver_prevote(w, &g_all[1], R, V + 1, /*cert_view*/ V + 1,
                                H, txh);

    CHECK(delta == 0,
          "the tally did NOT move — a vote for a view we do not hold is "
          "never counted, and the park changes nothing about that");
    CHECK(buf_used(w) == 1,
          "but ONE buffer entry now exists. RED before this season: the "
          "vote died at the round/view equality test and the buffer "
          "stayed empty");
    CHECK(buf_used_at_view(w, V + 1) == 1,
          "and it is filed under view V+1 — the view it is FOR, not the "
          "one we hold");
    CHECK(buf_has(w, V + 1, R),
          "carrying the round it named, unaltered");

    /* THE MOVE, by hand: §2d drives the production rotation. Here the
     * subject is the BUFFER, so the view is set directly and the round is
     * entered at the new view exactly as the replayed PROPOSE would enter
     * it. */
    w->current_view = V + 1;
    enter_round(w, R, V + 1, H, txh);
    CHECK(w->round_state.prevote_count == 1,
          "the round at (R, V+1) again starts with our approval alone");

    nodus_witness_bft_drain_vote_buffer(w);

    CHECK(w->round_state.prevote_count == 2,
          "and the PARKED vote was COUNTED — this is the half a 'drop it "
          "differently' change could not pass");
    CHECK(buf_used(w) == 0,
          "the entry was consumed: one chance, taken");

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §1b — the stale-round_state shape: moved already, still IDLE.
 *
 * bft_view_move_finish sets phase = IDLE and NEVER touches
 * round_state.view, so a node that has just moved carries a
 * round_state.view BELOW its current_view. That is the second of the two
 * states the `> round_state.view` half of the admission exists for, and
 * it is unreachable by §1's shape.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_vote_parked_while_idle(void) {
    printf("\n§1b a node that has moved but is IDLE parks the vote too\n");

    char dir[] = "/tmp/test_vbound_t1b_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x72);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);

    const uint32_t V = 4;
    const uint64_t R = 40;
    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x12, sizeof(txh));

    /* The post-move shape, built by hand: current_view already at V+1,
     * round_state left behind at V, phase IDLE. */
    enter_round(w, R, V, tip + 1, txh);
    w->round_state.phase = NODUS_W_PHASE_IDLE;
    w->current_view = V + 1;

    CHECK(w->round_state.view == V && w->current_view == V + 1,
          "precondition: the two view fields disagree, which is exactly "
          "what bft_view_move_finish leaves behind");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "precondition: and we are IDLE, so no round can count anything");

    /* Round R, the same number round_state holds, so `future_round`
     * (hdr->round > cur) is FALSE and only the view admission can be
     * what parks this. */
    int delta = deliver_prevote(w, &g_all[1], R, V + 1, V + 1, tip + 1, txh);

    CHECK(delta == 0, "nothing was counted — we hold no round");
    CHECK(buf_used_at_view(w, V + 1) == 1,
          "and the vote was PARKED rather than dropped. RED before this "
          "season: round_state.view == the vote's view was false, "
          "hdr->round > cur was false, and the vote was destroyed");

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §1c — the per-sender bound, and the eviction ORDER.
 *
 * TWO LEGS, and the second is the one that matters. Leg (a) is the plain
 * bound at one view. Leg (b) spans the boundary, where "lowest round" and
 * "lowest (view, round)" give DIFFERENT answers — and only the second is
 * correct, because the next view's leader opens from its own counter and
 * can therefore carry a LOWER round number than the view we are leaving.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_per_sender_bound(void) {
    printf("\n§1c a single sender holds at most %d entries, and the STALEST "
           "is the one evicted\n", NODUS_W_VOTE_BUFFER_ROUND_AHEAD);

    /* ── (a) three rounds at ONE view ──────────────────────────────── */
    {
        char dir[] = "/tmp/test_vbound_t1c_a_XXXXXX";
        nodus_witness_t *w = fixture();
        chain_db_open(w, dir, 0x73);
        uint64_t tip = seed_blocks(w, TIP_BLOCKS);

        const uint32_t V = 4;
        uint8_t txh[NODUS_T3_TX_HASH_LEN];
        memset(txh, 0x13, sizeof(txh));

        w->current_view = V;
        /* round_state.round is 100 and the votes name 10/11/12, so every
         * one of them is BELOW the live round: `future_round` is false
         * for all three and the view admission is the only door. */
        enter_round(w, 100, V, tip + 1, txh);
        CHECK(w->last_committed_round == 0,
              "precondition: nothing is settled, so the round prune "
              "cannot be what removes an entry below");

        for (uint64_t r = 10; r <= 12; r++)
            (void)deliver_prevote(w, &g_all[1], r, V + 1, V + 1, tip + 1, txh);

        CHECK(buf_used(w) == NODUS_W_VOTE_BUFFER_ROUND_AHEAD,
              "three votes from one sender leave exactly two entries — the "
              "bound holds");
        CHECK(!buf_has(w, V + 1, 10),
              "and round 10, the STALEST, is the one that went");
        CHECK(buf_has(w, V + 1, 11) && buf_has(w, V + 1, 12),
              "while the two newer rounds survive");

        scene_close(w, dir);
    }

    /* ── (b) across the boundary: a LOWER round at a HIGHER view ─────
     *
     * ⚠ THIS IS THE LEG THAT DISCRIMINATES. Evicting by lowest ROUND
     * would drop (view V+1, round 5) — the FRESHEST entry, and the exact
     * vote the whole season exists to keep. Evicting by lowest
     * (view, round) drops (view V, round 100), which is genuinely
     * staler. Both orders pass leg (a); only one passes this. */
    {
        char dir[] = "/tmp/test_vbound_t1c_b_XXXXXX";
        nodus_witness_t *w = fixture();
        chain_db_open(w, dir, 0x74);
        uint64_t tip = seed_blocks(w, TIP_BLOCKS);

        const uint32_t V = 4;
        uint8_t txh[NODUS_T3_TX_HASH_LEN];
        memset(txh, 0x14, sizeof(txh));

        /* The post-move shape again: round_state parked at V-1 so that a
         * vote AT V is already "one view ahead" of the round, while
         * current_view is V so a vote at V+1 is within the ceiling. */
        enter_round(w, 200, V - 1, tip + 1, txh);
        w->round_state.phase = NODUS_W_PHASE_IDLE;
        w->current_view = V;

        (void)deliver_prevote(w, &g_all[1], 100, V,     V,     tip + 1, txh);
        (void)deliver_prevote(w, &g_all[1],   5, V + 1, V + 1, tip + 1, txh);
        CHECK(buf_has(w, V, 100) && buf_has(w, V + 1, 5),
              "precondition: one sender holds a HIGH round at the LOW view "
              "and a LOW round at the HIGH view — the shape a boundary "
              "really produces");

        (void)deliver_prevote(w, &g_all[1],   6, V + 1, V + 1, tip + 1, txh);

        CHECK(buf_used(w) == NODUS_W_VOTE_BUFFER_ROUND_AHEAD,
              "the third vote did not grow the sender's occupancy");
        CHECK(!buf_has(w, V, 100),
              "and the evicted entry is the one at the LOWER VIEW, whatever "
              "its round number");
        CHECK(buf_has(w, V + 1, 5) && buf_has(w, V + 1, 6),
              "both next-view entries survive — a lowest-ROUND rule would "
              "have thrown away round 5, the newest vote in the buffer");

        scene_close(w, dir);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §1d — the healthy path is not starved by the new admission or bound.
 *
 * Three consecutive rounds at ONE stable view, each with an early vote
 * from the SAME sender, each drained before the next arrives. This is the
 * ORDINARY `future_round` park — the pre-existing path — and it must
 * still work unchanged.
 *
 * ⚠ HONEST LABEL: this is a smoke test, not a discriminator. The drain
 * clears `used` before feeding an entry, so consumed entries cannot be
 * counted by the per-sender scan and the bound is never actually reached
 * here. What it excludes is the new view admission or the new bound
 * accidentally REJECTING an ordinary near-future vote — a regression
 * strictly worse than the defect being fixed, and one that no other
 * section in this file would catch.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_healthy_path_not_starved(void) {
    printf("\n§1d three early votes across three rounds at a stable view "
           "are ALL counted\n");

    char dir[] = "/tmp/test_vbound_t1d_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x75);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);

    const uint32_t V = 4;
    w->current_view = V;

    for (uint64_t r = 10; r <= 12; r++) {
        uint8_t txh[NODUS_T3_TX_HASH_LEN];
        memset(txh, (uint8_t)(0x20 + r), sizeof(txh));

        /* The ordinary early-vote shape: we are still settling round r-1
         * when round r's PREVOTE arrives, so it parks through the
         * pre-existing `future_round` admission. */
        enter_round(w, r - 1, V, tip + 1, txh);
        int delta = deliver_prevote(w, &g_all[1], r, V, V, tip + 1, txh);
        CHECK(delta == 0, "the early vote is not counted against the old "
                          "round");
        CHECK(buf_has(w, V, r), "it is parked for the round it names");

        enter_round(w, r, V, tip + 1, txh);
        nodus_witness_bft_drain_vote_buffer(w);
        CHECK(w->round_state.prevote_count == 2,
              "and it is COUNTED when that round opens — every round in "
              "the sequence, so the per-sender bound never starves the "
              "path it does not govern");
    }

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §1e — a parked vote the view ran away from is never counted.
 *
 * The park must not become a way for a vote cast in a view nobody is in
 * to be counted later. Two views on, the entry is inert; it leaves the
 * buffer by the ROUND prune, which is the release this buffer has always
 * had and which the view admission deliberately did not replace.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_parked_vote_expires(void) {
    printf("\n§1e a vote parked for V+1 is never counted once we are at "
           "V+3\n");

    char dir[] = "/tmp/test_vbound_t1e_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x76);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);

    const uint32_t V = 4;
    const uint64_t R = 40;
    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x15, sizeof(txh));

    w->current_view = V;
    enter_round(w, R, V, tip + 1, txh);
    (void)deliver_prevote(w, &g_all[1], R, V + 1, V + 1, tip + 1, txh);
    CHECK(buf_has(w, V + 1, R), "precondition: the vote is parked for V+1");

    /* The view runs away — a proof carried this node past V+1. */
    w->current_view = V + 3;
    enter_round(w, R, V + 3, tip + 1, txh);
    nodus_witness_bft_drain_vote_buffer(w);

    CHECK(w->round_state.prevote_count == 1,
          "the stale entry was NOT counted into the round at V+3 — the "
          "drain requires the entry's view to equal the ROUND's view, so a "
          "vote cast in an abandoned view can never re-enter consensus");
    CHECK(buf_has(w, V + 1, R),
          "it is still held: there is no view-based release, deliberately "
          "— a view prune would also evict live entries on a healthy chain "
          "sitting at one stable view");

    /* And the release it DOES have: the round prune, once the chain
     * settles that round. This is what stops an abandoned view's entries
     * accumulating for the life of the process. */
    w->last_committed_round = R;
    nodus_witness_bft_drain_vote_buffer(w);
    CHECK(!buf_has(w, V + 1, R),
          "and the ROUND prune releases it once that round is settled — "
          "the pre-existing release, still the only one");

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2a — CHANGE 2: a PROPOSE for the next view is PARKED.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_propose_parked(void) {
    printf("\n§2a a PROPOSE for V+1 from that view's leader returns 1 and is "
           "parked\n");

    char dir[] = "/tmp/test_vbound_t2a_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x77);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);

    uint32_t V = pick_follower_pair(w);
    w->current_view = V;
    const peer_t *leader = leader_at(w, V + 1);
    CHECK(memcmp(leader->id, w->my_id, NODUS_T3_WITNESS_ID_LEN) != 0,
          "precondition: the leader for V+1 is a peer, not us");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "precondition: we are IDLE, so the phase gate is not in play");
    CHECK(!w->parked_propose.present, "precondition: the slot is empty");

    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD1, sizeof(ptx));
    nodus_t3_msg_t pm;

    /* THE RETURN CODE, on its own frame. The slot alone cannot tell rc 1
     * from some future rc 2, and this is the value witness.c switches on. */
    build_propose(&pm, w, leader, 21, V + 1, tip + 1, ptx, NULL);
    CHECK(nodus_witness_bft_handle_propose(w, &pm) == 1,
          "the handler answers 1 — 'park me' — for exactly the next view");
    CHECK(w->current_view == V,
          "and the view counter did NOT move: one leader's word is not a "
          "proof, and the park changes nothing about that");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "no round was entered");

    /* THE WIRING, through the real dispatcher on a SECOND frame with its
     * own nonce — a replay of the first would die at the replay gate. */
    build_propose(&pm, w, leader, 22, V + 1, tip + 1, ptx, NULL);
    static char out[CAP_BUF];
    cap_begin();
    dispatch_msg(w, leader, &pm);
    cap_end(out, sizeof(out));

    CHECK(said(out, TOK_PARKED),
          "the store's own log line fired — the frame took the park path "
          "and not some other branch that happens to leave a slot set");
    CHECK(w->parked_propose.present,
          "and the DISPATCHER stored the frame — the store is wired to the "
          "handler's return value, not merely present in the tree");
    CHECK(w->parked_propose.view == V + 1,
          "filed under the view it is FOR");
    CHECK(w->parked_propose.height == tip + 1,
          "carrying the height it proposes");
    CHECK(memcmp(w->parked_propose.sender_id, leader->id,
                 NODUS_T3_WITNESS_ID_LEN) == 0,
          "and the sender recorded is that view's expected leader");
    CHECK(w->parked_propose.len > 0 && w->parked_propose.bytes != NULL,
          "the RAW FRAME BYTES were kept — not the decoded struct, whose "
          "batch entries alias a transport buffer that does not outlive "
          "the dispatch call");

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2b — ANTI-VACUITY: a non-leader cannot take the slot.
 *
 * Without this, §2a passes for a park placed at the phase gate, where any
 * roster member could fill the single slot and starve the real leader's
 * proposal. The park is only reachable BELOW the leader/committee block,
 * and this is what pins it there.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_non_leader_refused(void) {
    printf("\n§2b the same proposal from a NON-leader is refused and parks "
           "nothing\n");

    char dir[] = "/tmp/test_vbound_t2b_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x78);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);

    uint32_t V = pick_follower_pair(w);
    w->current_view = V;
    const peer_t *leader = leader_at(w, V + 1);

    /* Any roster peer that is NOT the leader for V+1 and is not us. */
    const peer_t *impostor = NULL;
    for (int i = 1; i <= N_PEERS; i++)
        if (memcmp(g_all[i].id, leader->id, NODUS_T3_WITNESS_ID_LEN) != 0) {
            impostor = &g_all[i];
            break;
        }
    CHECK(impostor != NULL, "precondition: a non-leader peer exists");

    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD2, sizeof(ptx));
    nodus_t3_msg_t pm;

    build_propose(&pm, w, impostor, 23, V + 1, tip + 1, ptx, NULL);
    CHECK(nodus_witness_bft_handle_propose(w, &pm) == -1,
          "the impostor's proposal is REFUSED — the leader gate sits ABOVE "
          "the park decision");

    build_propose(&pm, w, impostor, 24, V + 1, tip + 1, ptx, NULL);
    dispatch_msg(w, impostor, &pm);
    CHECK(!w->parked_propose.present,
          "and the slot stayed EMPTY through the real dispatcher — a park "
          "any roster member could fill would let one peer starve the "
          "leader's proposal every boundary");

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2c — the phase gate no longer refuses the view we are moving to.
 *
 * THIS IS THE MEASURED DEFECT. At the stuck height, 35 of the 45
 * "round in progress" refusals came from a view AHEAD of the refusing
 * node — and because that gate sits ABOVE the view gate, the node never
 * reached the proof request that would have moved it. It blocked its own
 * remedy.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_phase_gate_lets_next_view_through(void) {
    printf("\n§2c a PROPOSE for V+1 arriving during VIEW_CHANGE is not "
           "'round in progress'\n");

    char dir[] = "/tmp/test_vbound_t2c_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x79);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);

    uint32_t V = pick_follower_pair(w);
    w->current_view = V;

    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x16, sizeof(txh));
    enter_round(w, 30, V, tip + 1, txh);
    w->round_state.phase = NODUS_W_PHASE_VIEW_CHANGE;

    CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE &&
          w->round_state.view == V && w->current_view == V,
          "precondition: we are ASKING for a new leader, holding a round "
          "at the view we are in — the exact state the log line recorded");

    const peer_t *leader = leader_at(w, V + 1);
    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD3, sizeof(ptx));
    nodus_t3_msg_t pm;
    build_propose(&pm, w, leader, 31, V + 1, tip + 1, ptx, NULL);

    static char out[CAP_BUF];
    cap_begin();
    int rc = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out, sizeof(out));

    CHECK(rc == 1,
          "the proposal for the NEXT view falls through to the view gate "
          "and asks to be parked. RED before this season: -1, refused at "
          "the phase gate");
    CHECK(!said(out, TOK_IN_PROGRESS),
          "and the 'round in progress' refusal did NOT fire — the node no "
          "longer blocks the very leader it is asking for");
    CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
          "the in-flight view change is untouched: falling through the "
          "phase gate writes no round state");
    CHECK(w->current_view == V, "and the view counter did not move");

    /* THE CONVERSE, and it is what stops this becoming a hole: a
     * SAME-view proposal during VIEW_CHANGE is still refused. */
    const peer_t *same_leader = leader_at(w, V);
    build_propose(&pm, w, same_leader, 32, V, tip + 1, ptx, NULL);
    cap_begin();
    rc = nodus_witness_bft_handle_propose(w, &pm);
    cap_end(out, sizeof(out));

    CHECK(rc == -1 && said(out, TOK_IN_PROGRESS),
          "a proposal at the view we ALREADY hold is still refused as "
          "'round in progress' — the duplicate-proposal guard this check "
          "was written to be is intact");

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2d — THE WHOLE BOUNDARY, end to end.
 *
 * A PROPOSE and its votes arrive for V+1 while we hold V; the view change
 * then completes through the PRODUCTION path (peer VIEW_CHANGEs to our
 * own quorum, then a peer VIEW_OK statement completing f+1). What used to
 * follow was an IDLE node with nothing pending. What must follow now is a
 * node in PREVOTE at V+1 with the peers' votes counted.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_boundary_end_to_end(void) {
    printf("\n§2d the parked PROPOSE is replayed at the move, and the "
           "parked votes are counted\n");

    char dir[] = "/tmp/test_vbound_t2d_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x7A);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);
    seed_committee(w, COMMITTEE_N);

    uint32_t V = pick_follower_pair(w);
    w->current_view = V;
    const uint32_t T = V + 1;
    CHECK(!is_leader_at(w, T),
          "precondition: we do NOT lead the view we are moving to, so "
          "bft_view_move_finish takes its follower branch");

    const peer_t *leader = leader_at(w, T);
    CHECK(memcmp(leader->id, w->my_id, NODUS_T3_WITNESS_ID_LEN) != 0,
          "precondition: some PEER leads it");

    /* ── the leader's PROPOSE, arriving one boundary early ─────────── */
    const uint64_t R = 55;
    const uint64_t H = tip + 1;
    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0xD4, sizeof(ptx));
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    nodus_t3_msg_t pm;
    build_propose(&pm, w, leader, R, T, H, ptx, tx_root);
    dispatch_msg(w, leader, &pm);
    CHECK(w->parked_propose.present && w->parked_propose.view == T,
          "precondition: the proposal is parked for the incoming view");

    /* ── and two of its peers' PREVOTEs, likewise early ─────────────
     *
     * They name the round the PROPOSE names, because that is the round
     * the replay will open — and their certs are signed over T, the view
     * the verifier will hold when they are drained. Both senders are in
     * the committee, so the vote handler's committee gate passes. */
    for (int i = 1; i <= 2; i++) {
        (void)deliver_prevote(w, &g_all[i], R, T, T, H, tx_root);
        CHECK(buf_has(w, T, R),
              "a peer PREVOTE for the incoming view is parked");
    }
    CHECK(buf_used_at_view(w, T) == 2, "both peers' votes are held");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "and nothing has entered a round: we are still at the old view");

    /* ── the production rotation ────────────────────────────────────
     *
     * TWO EVENTS, and that separation is the point of O15N Faz 2C2.
     * Reaching our own view-change quorum only makes this node SIGN AND
     * BROADCAST one VIEW_OK statement; the counter moves later, when
     * f+1 verified statements exist. Modelled on p2_complete_vc in
     * test_bft_view_change_hardening.c — but NOT reusing its final
     * assertion, which requires IDLE after the move. Being no longer
     * IDLE is precisely what this section is about. */
    /* ⚠ THREE PEER VIEW_CHANGEs HERE, WHERE
     * test_bft_view_change_hardening.c's p2_complete_vc NEEDS ONLY TWO —
     * and the difference is caused by this section's own subject.
     *
     * Parking the PROPOSE ran bft_handle_propose_inner, which refreshes
     * bft_config from the committee at tip+1 (nodus_witness_bft.c:5711 →
     * refresh_bft_config_from_committee → nodus_witness_bft_config_init).
     * That REPLACES the fixture's quorum of 3 with the committee's own
     * dna_bft_quorum(5) = 4. bft_vc_check_quorum tests the per-target
     * tally against exactly that number, and handle_viewchg does NOT
     * refresh (the only refresh sites are :4813 round start, :5711
     * propose, :6917 successor commit, :13695 commit_batch) — so two
     * peers plus our own self-record is 3, one short, and no VIEW_OK
     * would ever be emitted. The §12 fixtures never call handle_propose
     * before rotating, which is why two suffices there.
     *
     * Asserted rather than assumed, so a future change to the formula or
     * to COMMITTEE_N fails HERE with a reason instead of hanging the
     * rotation. */
    CHECK(w->bft_config.quorum == dna_bft_quorum(COMMITTEE_N),
          "parking the proposal refreshed bft_config to the committee's "
          "own quorum — which is what the tally below must reach");

    uint64_t txn_before = w->next_txn_id;
    nodus_t3_msg_t vc;
    fill_viewchg(&vc, w, &g_all[1], T);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
          "first peer VIEW_CHANGE recorded");
    fill_viewchg(&vc, w, &g_all[2], T);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
          "second peer VIEW_CHANGE recorded — this one crosses the f+1 "
          "join threshold, so we self-record and the tally becomes 3");
    fill_viewchg(&vc, w, &g_all[3], T);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
          "third peer VIEW_CHANGE recorded — the tally reaches the "
          "committee quorum of 4");
    CHECK(w->current_view == V,
          "reaching our OWN quorum did NOT move the view");
    CHECK(w->next_txn_id > txn_before,
          "but it DID emit our VIEW_OK statement");
    CHECK(w->viewok_acc.active && w->viewok_acc.view == T,
          "and the accumulator is anchored on the target we observed");

    CHECK(viewok_deliver1(w, &g_all[1], w->viewok_acc.height, T,
                          w->viewok_acc.set_hash) == 0,
          "a peer's VIEW_OK statement was accepted");
    CHECK(w->current_view == T,
          "f+1 verified statements MOVED the view — the one writer");

    /* ── what must now be true ─────────────────────────────────────── */
    CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
          "WE ARE IN THE ROUND. RED before this season: the node returned "
          "to IDLE holding nothing, and waited a full round timeout for a "
          "proposal that had already been sent once and would never be "
          "sent again");
    CHECK(w->round_state.view == T,
          "and the round is the one at the NEW view");
    CHECK(w->round_state.round == R && w->current_round == R,
          "carrying the round number the leader's own proposal named");
    CHECK(w->round_state.block_height == H,
          "at the height it proposed");
    CHECK(memcmp(w->round_state.proposer_id, leader->id,
                 NODUS_T3_WITNESS_ID_LEN) == 0,
          "and the proposer recorded is that view's leader");

    /* ⚠ THE PHASE ASSERTION ABOVE DEPENDS ON THE QUORUM, so the quorum is
     * asserted rather than assumed. handle_propose refreshes bft_config
     * from the committee on every proposal, so by the time the drain runs
     * the threshold is dna_bft_quorum(COMMITTEE_N) = (2*5)/3+1 = 4. Three
     * approvals is BELOW it, which is why the round is still in PREVOTE
     * and has not advanced to PRECOMMIT. Were that ever to change, this
     * line fails first and names the reason. */
    CHECK(w->bft_config.quorum == dna_bft_quorum(COMMITTEE_N),
          "the round is running under the committee's own quorum");
    /* The cast is deliberate: prevote_approve_count is `int` and quorum is
     * `uint32_t`, and a bare `<` between them is a -Wsign-compare warning
     * this project does not ship. */
    CHECK((uint32_t)w->round_state.prevote_approve_count <
          w->bft_config.quorum,
          "and three approvals are below it — so the phase assertion above "
          "is about the round being ENTERED, not about it failing to "
          "advance for some other reason");

    CHECK(w->round_state.prevote_count == 3,
          "AND THE PARKED VOTES WERE COUNTED — our own approval plus the "
          "two peers'. The round entry's drain is what collects them, "
          "which is why no drain call was added at the view move: a node "
          "that has just moved is IDLE, and drain eligibility needs a "
          "live round");
    CHECK(buf_used_at_view(w, T) == 0,
          "the buffer entries were consumed");
    CHECK(!w->parked_propose.present,
          "and the PROPOSE slot was released — one replay attempt, one "
          "outcome, whatever it was");

    scene_close(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — CHANGE D: the P3 window restarts at the view move.
 *
 * P3 rotates the view when the committed tip has stood still for longer
 * than a round while demand is pending. Its window has exactly three
 * writers, all inside check_timeout's IDLE branch, and NONE of them is a
 * view move — so on a frozen tip a node whose last stamp is already older
 * than the round timeout fired on its FIRST idle tick after the move,
 * against a leader that had not had one tick to propose. P2, on the same
 * path, gives that leader a full round_timeout_ms. This makes the two
 * agree.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_p3_window_restarts(void) {
    printf("\n§3 P3 gives the NEW leader the same window P2 gives it\n");

    char dir[] = "/tmp/test_vbound_t3_XXXXXX";
    nodus_witness_t *w = fixture();
    chain_db_open(w, dir, 0x7B);
    uint64_t tip = seed_blocks(w, TIP_BLOCKS);
    seed_committee(w, COMMITTEE_N);

    uint32_t V = pick_follower_pair(w);
    w->current_view = V;
    const uint32_t T = V + 1;
    CHECK(!is_leader_at(w, T),
          "precondition: we are NOT the leader at the view we move to — a "
          "leader never evaluates P3's fire gate");

    /* LIVE DEMAND. One pooled entry whose nullifier the chain has not
     * decided, which is what bft_p3_live_demand answers true on. */
    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { fprintf(stderr, "entry alloc\n"); exit(1); }
    memset(e->tx_hash, 0xC1, NODUS_T3_TX_HASH_LEN);
    e->tx_type = NODUS_W_TX_SPEND;
    e->nullifier_count = 1;
    memset(e->nullifiers[0], 0xC1, NODUS_T3_NULLIFIER_LEN);
    e->tx_len = 8;
    e->tx_data = calloc(1, e->tx_len);
    if (!e->tx_data) { fprintf(stderr, "tx_data alloc\n"); exit(1); }
    e->fee = 100;
    if (nodus_witness_mempool_add(&w->mempool, e) != 0 ||
        w->mempool.count != 1) {
        fprintf(stderr, "mempool_add rejected the fixture entry\n"); exit(1);
    }
    CHECK(!nodus_witness_nullifier_exists(w, e->nullifiers[0]),
          "precondition: the pooled entry is LIVE — the chain has not "
          "decided it, so it really is demand");

    /* THE STUCK WINDOW: the tip this node last observed, frozen well
     * beyond a round. Written by name rather than by ticking, so the age
     * is exact; time_ms() is nodus_time_now()*1000, one-second
     * resolution, and 20 s is a whole number of seconds. */
    w->last_seen_tip = tip;
    w->tip_since_ms = nodus_time_now() * 1000ULL - 20000ULL;
    CHECK(w->tip_since_ms + w->bft_config.round_timeout_ms <
          nodus_time_now() * 1000ULL,
          "precondition: the window is ALREADY past the fire point, so "
          "without the restart the very next idle tick rotates the view");

    /* THE MOVE, through the production path.
     *
     * TWO peer VIEW_CHANGEs suffice here where §2d needs three, and the
     * reason is worth stating because it is invisible otherwise: this
     * section never calls handle_propose, so nothing has refreshed
     * bft_config from the committee and the quorum is still the fixture's
     * 3 — two peers plus our own self-record. Asserted, so that if a
     * refresh ever creeps onto this path the failure names its cause
     * instead of silently never rotating. */
    CHECK(w->bft_config.quorum == QUORUM,
          "no committee refresh has run on this path, so the view-change "
          "quorum is still the fixture's — two peers plus ourselves");

    nodus_t3_msg_t vc;
    fill_viewchg(&vc, w, &g_all[1], T);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0, "peer VC 1");
    fill_viewchg(&vc, w, &g_all[2], T);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0, "peer VC 2");
    CHECK(viewok_deliver1(w, &g_all[1], w->viewok_acc.height, T,
                          w->viewok_acc.set_hash) == 0, "peer VIEW_OK");
    CHECK(w->current_view == T, "the view moved");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "and we are IDLE — no PROPOSE was parked in this section, so "
          "nothing replays and P3's branch is the one under test");
    CHECK(w->awaiting_propose_deadline_ms != 0,
          "P2 armed a full round_timeout_ms for the new leader");

    /* ── HALF ONE: P3 must now agree with P2 ───────────────────────── */
    nodus_witness_bft_check_timeout(w);

    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "the tick left us IDLE. RED before this season: P3's window was "
          "still 20 s old across the move, so this tick rotated the view "
          "away from a leader that had existed for no time at all");
    CHECK(!w->view_change_in_progress,
          "no view change was started against the brand-new leader");
    CHECK(w->current_view == T, "and the view counter did not move");

    /* ── HALF TWO: P3 IS STILL ARMED ────────────────────────────────
     *
     * Without this leg, deleting P3 outright would pass half one. Age the
     * window again — i.e. give the new leader its full window and let it
     * elapse — and P3 must fire.
     *
     * P2 IS DISARMED FIRST, ON PURPOSE. P2 sits above P3 in the same IDLE
     * branch and returns when it fires, so an expired P2 would produce
     * the same VIEW_CHANGE phase and this leg would attribute P3's
     * behaviour to the wrong deadman. Zeroing it leaves P3 as the only
     * thing that can act. */
    w->awaiting_propose_deadline_ms = 0;
    w->tip_since_ms = nodus_time_now() * 1000ULL - 20000ULL;
    uint32_t view_before = w->current_view;

    nodus_witness_bft_check_timeout(w);

    CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
          "P3 DOES still fire once the new leader has had its window and "
          "spent it — the change moved WHEN this node asks, it did not "
          "disable the asking");
    CHECK(w->current_view == view_before,
          "and current_view is UNTOUCHED — only a verified VIEW_OK proof "
          "may advance it");

    scene_close(w, dir);
}

int main(void) {
    printf("=== O15R B′ + D — the view boundary ===\n");

    for (int i = 0; i <= N_PEERS; i++) peer_make(&g_all[i]);

    section_vote_parked_then_counted();
    section_vote_parked_while_idle();
    section_per_sender_bound();
    section_healthy_path_not_starved();
    section_parked_vote_expires();
    section_propose_parked();
    section_non_leader_refused();
    section_phase_gate_lets_next_view_through();
    section_boundary_end_to_end();
    section_p3_window_restarts();

    printf("\nALL SECTIONS PASSED\n");
    return 0;
}
