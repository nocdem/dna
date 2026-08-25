/**
 * Nodus — O15H boundary view-change hardening regressions.
 *
 * Every section here reproduces a defect that was LIVE and that the
 * 20-node grow rehearsal could NOT discriminate. That last part is the
 * reason this file exists: the 2026-08-25 run crossed the growth
 * boundary with round == height + 1, so BOTH landed in the same epoch
 * and the pre-fix committee lookup would have answered correctly by
 * accident. A green rehearsal is therefore not evidence for D1, and
 * "it passed on the harness" is not a regression test.
 *
 *  D1 — the vote committee gate resolved the committee at the ROUND
 *       NUMBER instead of the round's BLOCK HEIGHT. Both are uint64 and
 *       both look like "a chain position", but
 *       load_committee_at_height_alloc converts its argument to an epoch
 *       (nodus_witness_committee.c: e_start = h / E * E), so feeding it a
 *       round fed it a different scale. Observed at the 7→20 growth
 *       boundary: 11 joiner PREVOTEs rejected as "non-committee" while
 *       bft_config.quorum was already 14 — a quorum that could not be
 *       reached by construction.
 *
 *  D2 — the view-change timeout was measured from the ROUND's start,
 *       because phase_start_time was never re-stamped when the phase
 *       moved to NODUS_W_PHASE_VIEW_CHANGE. With viewchg_timeout_ms
 *       SHORTER than round_timeout_ms the budget was already spent when
 *       the view change began, so the next tick aborted it and wiped the
 *       tally.
 *
 *  D5 — that abort returned the node to IDLE with current_view
 *       unchanged, which is a dead end: check_timeout returns at its
 *       first branch from IDLE, the leader has not moved, and nothing
 *       re-initiates.
 *
 *  D5b — the escalation alone leapfrogs. A node that ADOPTED a higher
 *        target must vote there (immediately at f+1, or at its own
 *        timeout) rather than jump past it.
 *
 * Fixture style follows test_bft_liveness.c: heap witness (multi-MB),
 * real ML-DSA-87 keys so PREVOTE cert_sig verification is the production
 * check rather than a stub.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_vset.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "nodus/nodus_types.h"

#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/vset_wire.h"
#include "dnac/env_wire.h"       /* §7 — DNA_ENV_MAX_TOTAL_LEN */
#include "dnac/ledger_ids.h"     /* §7/§8 — dna_bft_quorum      */

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

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

static void peer_make(peer_t *p) {
    if (qgp_dsa87_keypair(p->pk, p->sk) != 0) { fprintf(stderr, "keygen\n"); exit(1); }
    uint8_t d[64];
    if (qgp_sha3_512(p->pk, NODUS_PK_BYTES, d) != 0) { fprintf(stderr, "id\n"); exit(1); }
    memcpy(p->id, d, NODUS_T3_WITNESS_ID_LEN);
}

static void roster_put(nodus_witness_t *w, const peer_t *p) {
    uint32_t i = w->roster.n_witnesses++;
    memcpy(w->roster.witnesses[i].witness_id, p->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->roster.witnesses[i].pubkey, p->pk, NODUS_PK_BYTES);
    w->roster.witnesses[i].active = true;
}

/* No-DB fixture: committee lookups take the documented pre-genesis
 * gossip-roster fallback (F17 A5), which is what the view-change
 * sections want — they are about the CLOCK and the TARGET, not about
 * committee resolution. §6 builds its own DB-backed fixture. */
static nodus_witness_t *fixture(const peer_t *self, const peer_t *peers,
                                int n_peers, uint32_t quorum,
                                uint32_t round_to_ms, uint32_t vc_to_ms) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!w || !srv) { fprintf(stderr, "fixture alloc\n"); exit(1); }
    memcpy(srv->identity.pk.bytes, self->pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, self->sk, sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, self->id, NODUS_T3_WITNESS_ID_LEN);
    roster_put(w, self);
    for (int i = 0; i < n_peers; i++) roster_put(w, &peers[i]);
    w->bft_config.n_witnesses = w->roster.n_witnesses;
    w->bft_config.quorum = quorum;
    w->bft_config.round_timeout_ms = round_to_ms;
    w->bft_config.viewchg_timeout_ms = vc_to_ms;
    w->cached_committee_epoch_start = UINT64_MAX;
    return w;
}

static void fixture_free(nodus_witness_t *w) {
    if (!w) return;
    for (int i = 0; i < DNAC_MAX_ACTIVE_VALIDATORS; i++)
        nodus_witness_vc_record_clear(&w->view_changes[i]);
    free(w->server);
    free(w);
}

static void sign_prepared(uint8_t out_sig[NODUS_SIG_BYTES], const peer_t *p,
                          uint32_t view, uint64_t height,
                          const uint8_t *tx_hash) {
    uint8_t pre[76];
    pre[0] = (uint8_t)(view >> 24); pre[1] = (uint8_t)(view >> 16);
    pre[2] = (uint8_t)(view >> 8);  pre[3] = (uint8_t)view;
    for (int i = 0; i < 8; i++)
        pre[4 + i] = (uint8_t)(height >> ((7 - i) * 8));
    memcpy(pre + 12, tx_hash, NODUS_T3_TX_HASH_LEN);
    nodus_sig_t sig;
    nodus_seckey_t sk;
    memcpy(sk.bytes, p->sk, sizeof(sk.bytes));
    if (nodus_sign_prepared_vote(&sig, pre, sizeof(pre), &sk) != 0) {
        fprintf(stderr, "prepared sign\n"); exit(1);
    }
    memcpy(out_sig, sig.bytes, NODUS_SIG_BYTES);
}

static void enter_round(nodus_witness_t *w, const peer_t *self,
                        uint64_t round, uint64_t height,
                        const uint8_t *tx_hash) {
    w->current_round = round;
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.round = round;
    w->round_state.view = w->current_view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    w->round_state.block_height = height;
    memcpy(w->round_state.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.prevotes[0].voter_id, self->id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->round_state.prevotes[0].pubkey, self->pk, NODUS_PK_BYTES);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;
    w->round_state.phase_start_time = nodus_time_now() * 1000ULL;
}

static void fill_viewchg(nodus_t3_msg_t *m, nodus_witness_t *w,
                         const peer_t *from, uint32_t new_view) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWCHG;
    m->header.round = w->round_state.round;
    m->header.view = w->current_view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
    m->viewchg.new_view = new_view;
    m->viewchg.last_committed_round = w->last_committed_round;
}

/* Count the voters currently sitting at `target`. Mirrors bft_vc_tally,
 * which is static in the implementation; recomputing it here from the
 * public record fields keeps the test measuring the STATE rather than
 * trusting the same helper the code under test uses. */
static uint32_t tally_at(const nodus_witness_t *w, uint32_t target) {
    uint32_t n = 0;
    for (int i = 0; i < w->view_change_count; i++)
        if (w->view_changes[i].target_view == target) n++;
    return n;
}

/* Push phase_start_time `age_ms` into the past. time_ms() is
 * nodus_time_now()*1000 — ONE-SECOND resolution — so every age used here
 * is a whole number of seconds; a sub-second offset would be invisible. */
static void age_phase(nodus_witness_t *w, uint64_t age_ms) {
    w->round_state.phase_start_time = nodus_time_now() * 1000ULL - age_ms;
}

/* ═══════════════════════════════════════════════════════════════════
 * §6 helpers — a chain DB carrying TWO DIFFERENT committee snapshots.
 *
 * The snapshots are written DIRECTLY rather than computed. That is not a
 * shortcut around the production path: a persisted snapshot IS the
 * committee authority for its epoch (nodus_witness_committee.c), and
 * writing it lets this section vary exactly ONE thing — which epoch the
 * gate resolves — without also dragging in stake ranking, minimum
 * tenure, the sortition seed's block lookback and the bootstrap window,
 * none of which D1 is about.
 * ═══════════════════════════════════════════════════════════════════ */
static void put_snapshot(nodus_witness_t *w, uint64_t epoch,
                         const peer_t *members, int n)
{
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
    /* The per-epoch committee cache is keyed on e_start and has no
     * invalidation hook, so a lookup made BEFORE this write would still
     * be served from the cache. Reset the sentinel exactly as the
     * production init path does. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;
}

/* Deliver one APPROVE PREVOTE from `from` into the current round and
 * report whether the vote was RECORDED. The committee gate rejects with
 * -1; a recorded vote also moves prevote_count, and both are asserted
 * together so a change in one return convention cannot silently turn
 * this into a vacuous test. */
static bool deliver_prevote(nodus_witness_t *w, const peer_t *from,
                            const uint8_t *tx_hash)
{
    int before = w->round_state.prevote_count;
    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_PREVOTE;
    m.header.round = w->round_state.round;
    m.header.view  = w->round_state.view;
    memcpy(m.header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m.header.chain_id, w->chain_id, sizeof(m.header.chain_id));
    m.header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m.header.nonce, sizeof(m.header.nonce));
    memcpy(m.vote.vote_target, tx_hash, NODUS_T3_TX_HASH_LEN);
    m.vote.vote = NODUS_W_VOTE_APPROVE;
    sign_prepared(m.vote.cert_sig, from, w->current_view,
                  w->round_state.block_height, tx_hash);

    int rc = nodus_witness_bft_handle_vote(w, &m);
    int after = w->round_state.prevote_count;
    if (rc == 0 && after == before + 1) return true;
    if (rc < 0 && after == before)      return false;
    fprintf(stderr, "deliver_prevote: inconsistent (rc=%d %d->%d)\n",
            rc, before, after);
    exit(1);
}

int main(void) {
    peer_t self;
    peer_make(&self);
    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(tx_hash, 0xC5, sizeof(tx_hash));

    /* ── §1 D2 — the round timeout STAMPS the view-change clock ────── */
    printf("§1 D2 — entering VIEW_CHANGE re-stamps phase_start_time\n");
    {
        peer_t b, c; peer_make(&b); peer_make(&c);
        /* viewchg budget SHORTER than the round budget — the production
         * relationship (10 s vs 15 s) and the whole reason the bug bit. */
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 5,
                                     15000, 10000);
        enter_round(w, &self, 6, 41, tx_hash);
        age_phase(w, 16000);

        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "round timeout moved the phase to VIEW_CHANGE");
        CHECK(w->view_change_in_progress, "view change started");
        int after_start = w->view_change_count;
        uint32_t target_at_start = w->view_change_target;
        CHECK(after_start >= 1, "our own vote is recorded");

        /* The very next tick. Pre-fix, elapsed was still measured from
         * the ROUND's start (16000 > 10000) so the view-change budget
         * was already spent and this call ended the attempt.
         *
         * ⚠ THE TARGET IS THE DISCRIMINATING ASSERTION, not the phase
         * and not the tally. A mutation campaign proved why: with D5 in
         * place the "budget spent" branch no longer returns to IDLE, it
         * ESCALATES — so a missing clock stamp leaves the phase at
         * VIEW_CHANGE and, after clearing and re-self-recording, leaves
         * the tally back at 1. Both of those looked healthy. Only the
         * target moves (1 -> 2), and a view change that silently
         * advances its target every tick can never accumulate a
         * quorum. */
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "the next tick does NOT abort the view change");
        CHECK(w->view_change_target == target_at_start,
              "the next tick does NOT escalate — the window really restarted");
        CHECK(w->view_change_count == after_start,
              "the vote tally survives the next tick");
        fixture_free(w);
    }

    /* ── §2 D2b — adopting a HIGHER target restarts the clock ──────── */
    printf("§2 D2b — a higher adopted target restarts the window\n");
    {
        peer_t p[4];
        for (int i = 0; i < 4; i++) peer_make(&p[i]);
        /* quorum 5 → join threshold 3, so raising the target needs THREE
         * backers (O15H D9); one message must never move it. */
        nodus_witness_t *w = fixture(&self, p, 4, 5, 15000, 10000);
        enter_round(w, &self, 6, 41, tx_hash);
        age_phase(w, 16000);
        nodus_witness_bft_check_timeout(w);      /* → VIEW_CHANGE, target 1 */
        CHECK(w->view_change_target == 1, "target 1 after our timeout");

        /* Burn most of the new window, then let f+1 peers ask for 2. */
        age_phase(w, 9000);
        nodus_t3_msg_t vc;
        for (int i = 0; i < 3; i++) {
            fill_viewchg(&vc, w, &p[i], 2);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                  "peer VIEW_CHANGE for a higher view accepted");
        }
        CHECK(w->view_change_target == 2, "target raised to 2 by f+1 peers");

        uint64_t now_ms = nodus_time_now() * 1000ULL;
        CHECK(w->round_state.phase_start_time >= now_ms - 1000ULL,
              "the clock restarted with the new target");
        fixture_free(w);
    }

    /* ── §3 D5 — a stalled view change ESCALATES, never goes IDLE ──── */
    printf("§3 D5 — stalled view change escalates instead of dying\n");
    {
        peer_t b, c; peer_make(&b); peer_make(&c);
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 5,
                                     15000, 10000);
        enter_round(w, &self, 6, 41, tx_hash);
        age_phase(w, 16000);
        nodus_witness_bft_check_timeout(w);
        CHECK(w->view_change_target == 1 && w->view_change_voted,
              "we voted at target 1");
        uint32_t view_before = w->current_view;

        age_phase(w, 11000);                     /* blow the 10 s budget */
        nodus_witness_bft_check_timeout(w);

        CHECK(w->view_change_target == 2, "target escalated 1 -> 2");
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "still in VIEW_CHANGE (pre-fix: IDLE)");
        CHECK(w->view_change_in_progress,
              "still in progress (pre-fix: cleared)");
        CHECK(w->current_view == view_before,
              "current_view did NOT move — only quorum may advance it");
        CHECK(w->view_change_voted, "we voted at the escalated target");
        fixture_free(w);
    }

    /* ── §4 D9 — we FOLLOW the f+1-supported target, never run alone ── */
    printf("§4 D9 — a node ahead of the cluster is pulled back to f+1\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        /* quorum 5 → threshold 3. */
        nodus_witness_t *w = fixture(&self, p, 6, 5, 15000, 10000);
        enter_round(w, &self, 6, 41, tx_hash);

        /* Escalate ourselves twice, alone: 0 -> 1 -> 2. Nobody backs us. */
        age_phase(w, 16000);
        nodus_witness_bft_check_timeout(w);
        CHECK(w->view_change_target == 1, "alone at target 1");
        age_phase(w, 11000);
        nodus_witness_bft_check_timeout(w);
        CHECK(w->view_change_target == 2, "alone at target 2");

        /* Meanwhile f+1 of the cluster are at view 1. Without the
         * follow-in-either-direction rule we would sit at 2 forever
         * while they sit at 1: they cannot raise us (they are lower) and
         * nothing lowers us. */
        nodus_t3_msg_t vc;
        for (int i = 0; i < 3; i++) {
            fill_viewchg(&vc, w, &p[i], 1);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                  "peer at view 1 recorded");
        }
        CHECK(w->view_change_target == 1,
              "we came DOWN to the view f+1 validators actually back");
        CHECK(w->view_change_voted,
              "and we voted there — our record moved with us");
        CHECK(w->current_view == 0,
              "current_view never moved: only quorum advances it");

        /* And when a HIGHER target gains f+1, the highest supported one
         * wins — a deterministic tie-break every node computes alike. */
        for (int i = 3; i < 6; i++) {
            fill_viewchg(&vc, w, &p[i], 4);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                  "peer at view 4 recorded");
        }
        CHECK(w->view_change_target == 4,
              "the HIGHEST f+1-supported target wins");

        /* ⚠ THE OTHER HALF, and the one that deadlocked a live cluster.
         * D9 lets a node that ran ahead follow the f+1 target back DOWN,
         * so peers MUST be able to record that move. An upsert rule of
         * "may raise, never lower" discards the announcement as stale,
         * keeps counting the voter at the target it abandoned, and the
         * tally at the real target can never reach quorum —
         * test_newview_convergence with k=2 drops (margin exactly zero)
         * hung at "chain did not advance past 1 within 240 s". A record
         * holds its voter's LATEST target, in either direction. */
        fill_viewchg(&vc, w, &p[3], 2);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "a voter announcing a LOWER target is accepted");
        {
            int s = -1;
            for (int i = 0; i < w->view_change_count; i++)
                if (memcmp(w->view_changes[i].voter_id, p[3].id,
                           NODUS_T3_WITNESS_ID_LEN) == 0) s = i;
            CHECK(s >= 0 && w->view_changes[s].target_view == 2,
                  "and it is now counted at the LOWER target, not the old one");
        }
        fixture_free(w);
    }

    /* ── §5 D5b — the f+1 join threshold, and it is never 1 ────────── */
    printf("§5 D5b — join at f+1 peers, never at one\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        /* quorum 5 → threshold ((5-1)/2)+1 = 3. */
        nodus_witness_t *w = fixture(&self, p, 6, 5, 15000, 10000);
        enter_round(w, &self, 6, 41, tx_hash);

        nodus_t3_msg_t vc;
        fill_viewchg(&vc, w, &p[0], 1);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0, "peer 1 vc");
        CHECK(!w->view_change_voted,
              "ONE peer does not make us speak (amplification guard)");

        fill_viewchg(&vc, w, &p[1], 1);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0, "peer 2 vc");
        CHECK(!w->view_change_voted, "two peers is still below f+1");

        fill_viewchg(&vc, w, &p[2], 1);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0, "peer 3 vc");
        CHECK(w->view_change_voted, "f+1 = 3 peers — we join immediately");
        fixture_free(w);
    }
    {
        /* The floor. A degenerate quorum makes ((q-1)/2)+1 collapse to 1,
         * and one message must never be able to make this node speak. */
        peer_t b, c; peer_make(&b); peer_make(&c);
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 2,
                                     15000, 10000);
        enter_round(w, &self, 6, 41, tx_hash);
        nodus_t3_msg_t vc;
        fill_viewchg(&vc, w, &b, 1);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0, "peer vc");
        /* ⚠ current_view IS THE ASSERTION HERE. `view_change_voted` is
         * NOT: a mutation campaign showed that with the floor removed
         * the node votes, its self-record completes the quorum of 2, and
         * bft_vc_check_quorum CLEARS view_change_voted on the way out —
         * so the flag reads false either way. What must be impossible is
         * the OUTCOME: one message from one peer moving this node into a
         * new view. */
        CHECK(w->current_view == 0,
              "quorum 2: one peer message cannot advance the view");
        CHECK(!w->view_change_voted,
              "quorum 2: the threshold floors at 2, one message is silent");
        fixture_free(w);
    }

    /* ── §6 D1 — the committee is resolved at the BLOCK HEIGHT ─────── */
    printf("§6 D1 — committee resolved at block height, not round\n");
    {
        const uint64_t E   = (uint64_t)DNAC_EPOCH_LENGTH;
        const uint64_t EA  = 3 * E;          /* the ROUND's epoch  */
        const uint64_t EB  = 4 * E;          /* the HEIGHT's epoch */
        const uint64_t RND = EA + 1;         /* e_start(RND) == EA  */
        const uint64_t HGT = EB + 1;         /* e_start(HGT) == EB  */

        peer_t only_a, only_b, common;
        peer_make(&only_a); peer_make(&only_b); peer_make(&common);

        nodus_witness_t *w = fixture(&self, (peer_t[]){only_a, only_b, common},
                                     3, 7, 15000, 10000);

        char dir[] = "/tmp/test_bft_vch_XXXXXX";
        CHECK(mkdtemp(dir) != NULL, "temp dir");
        snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
        uint8_t chain_id[16];
        memset(chain_id, 0x77, sizeof(chain_id));
        CHECK(nodus_witness_create_chain_db(w, chain_id) == 0, "chain db");

        /* Two epochs, two DIFFERENT committees. `common` is in both, so a
         * rejection can never be explained by "the DB path rejects
         * everything". */
        put_snapshot(w, EA, (peer_t[]){self, only_a, common}, 3);
        put_snapshot(w, EB, (peer_t[]){self, only_b, common}, 3);

        /* Sanity: the two epochs really do resolve differently, or this
         * section proves nothing. */
        {
            nodus_committee_member_t m[8];
            int n = 0;
            CHECK(nodus_committee_get_for_block(w, RND, m, 8, &n) == 0 && n == 3,
                  "committee at the ROUND's epoch loads");
            bool a_in = false;
            for (int i = 0; i < n; i++)
                if (memcmp(m[i].pubkey, only_a.pk, DNAC_PUBKEY_SIZE) == 0)
                    a_in = true;
            CHECK(a_in, "only_a is in the ROUND's committee");
            w->cached_committee_epoch_start = UINT64_MAX;
            CHECK(nodus_committee_get_for_block(w, HGT, m, 8, &n) == 0 && n == 3,
                  "committee at the HEIGHT's epoch loads");
            bool b_in = false;
            for (int i = 0; i < n; i++)
                if (memcmp(m[i].pubkey, only_b.pk, DNAC_PUBKEY_SIZE) == 0)
                    b_in = true;
            CHECK(b_in, "only_b is in the HEIGHT's committee");
            w->cached_committee_epoch_start = UINT64_MAX;
        }

        enter_round(w, &self, RND, HGT, tx_hash);

        /* The control leg: a member of BOTH committees is accepted under
         * either reading, so it isolates the variable. */
        CHECK(deliver_prevote(w, &common, tx_hash),
              "a member of BOTH committees votes (control)");

        /* THE ASSERTION. only_b is in the committee governing the
         * round's BLOCK HEIGHT and absent from the one governing its
         * ROUND NUMBER. Pre-fix this was "vote from non-committee
         * member" — the exact log line the 20-node rehearsal produced 11
         * times at the growth boundary. */
        CHECK(deliver_prevote(w, &only_b, tx_hash),
              "a member of the HEIGHT's committee is ACCEPTED");

        /* The converse, so the section cannot pass by accepting
         * everything: a member of the ROUND's committee only must be
         * REFUSED. Pre-fix this vote was accepted. */
        CHECK(!deliver_prevote(w, &only_a, tx_hash),
              "a member of only the ROUND's committee is REJECTED");

        nodus_witness_close(w);
        fixture_free(w);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
        if (system(cmd) != 0) { /* best effort cleanup */ }
    }

    /* ── §7 D8 — the tx size bound is FAMILY-AWARE ─────────────────── */
    printf("§7 D8 — family-aware transaction size bound\n");
    {
        /* The marker, written out here independently of the header's
         * copy so the test would notice if either moved. */
        uint8_t env[64];
        memset(env, 0xAB, sizeof(env));
        memcpy(env, "DNA.ENVWIRE.v1", 14);
        env[14] = 0; env[15] = 0;

        uint8_t legacy[64];
        memset(legacy, 0xAB, sizeof(legacy));

        CHECK(nodus_t3_tx_size_limit(env, sizeof(env)) ==
              (uint32_t)DNA_ENV_MAX_TOTAL_LEN,
              "a V2 envelope is bounded by the V2 capacity constant");
        CHECK(nodus_t3_tx_size_limit(legacy, sizeof(legacy)) ==
              (uint32_t)NODUS_T3_MAX_TX_SIZE,
              "anything else keeps the legacy ceiling, byte-identical");
        CHECK(nodus_t3_tx_size_limit(env, 15) ==
              (uint32_t)NODUS_T3_MAX_TX_SIZE,
              "a buffer too short to CARRY the marker is not an envelope");
        CHECK(nodus_t3_tx_size_limit(NULL, 64) ==
              (uint32_t)NODUS_T3_MAX_TX_SIZE,
              "NULL is not an envelope");

        /* One byte of the marker flipped must lose the larger bound —
         * otherwise the classification is not really the marker. */
        uint8_t near = env[3];
        env[3] = (uint8_t)(near ^ 0x01);
        CHECK(nodus_t3_tx_size_limit(env, sizeof(env)) ==
              (uint32_t)NODUS_T3_MAX_TX_SIZE,
              "one flipped marker byte falls back to the legacy ceiling");
        env[3] = near;

        /* THE ARITHMETIC THAT MADE THIS A BUG, pinned from the field
         * widths rather than from the observed run: an auth_kind-2
         * CHAIN_CONFIG envelope carries `quorum` approvals of
         * (snapshot_index u16 + ML-DSA-87 sig) bytes each, plus the
         * kind-1 submitter body. At N=20 the committee quorum is 14 and
         * the result exceeds the legacy ceiling — which is exactly the
         * refusal the rehearsal hit (72,142 bytes, NODUS_ERR_TOO_LARGE),
         * and exactly why governance was impossible above N=17. */
        const uint32_t APPROVAL = 2u + (uint32_t)NODUS_SIG_BYTES;
        const uint32_t SUBMITTER = 1u + (uint32_t)NODUS_PK_BYTES +
                                        (uint32_t)NODUS_SIG_BYTES;
        const uint32_t FRAME = 43u + 30u + 41u + 2u;   /* head+leg+call+cnt */
        uint32_t q20 = dna_bft_quorum(20);
        uint32_t q17 = dna_bft_quorum(17);
        CHECK(q20 == 14 && q17 == 12, "quorum(20)=14, quorum(17)=12");
        uint32_t need20 = FRAME + SUBMITTER + q20 * APPROVAL;
        uint32_t need17 = FRAME + SUBMITTER + q17 * APPROVAL;
        CHECK(need20 > (uint32_t)NODUS_T3_MAX_TX_SIZE,
              "N=20 governance does NOT fit the legacy ceiling");
        CHECK(need17 <= (uint32_t)NODUS_T3_MAX_TX_SIZE,
              "N=17 did fit — which is why the ceiling looked harmless");
        CHECK(need20 <= (uint32_t)DNA_ENV_MAX_TOTAL_LEN,
              "and it fits the V2 bound the family-aware gate now uses");
    }

    /* ── §8 C5 — prepared-cert authority is the prepared_height set ── */
    printf("§8 C5 — prepared-cert quorum and membership from its height\n");
    {
        const uint64_t E  = (uint64_t)DNAC_EPOCH_LENGTH;
        const uint64_t EP = 5 * E;
        const uint64_t H  = EP + 1;          /* e_start(H) == EP */

        peer_t m[7], outsider;
        for (int i = 0; i < 7; i++) peer_make(&m[i]);
        peer_make(&outsider);

        /* bft_config.quorum is deliberately 14 — the POST-GROWTH quorum.
         * The certificate below was formed under the 7-member committee
         * governing H, whose quorum is 5. Pre-fix the threshold came
         * from bft_config and the cert was discarded; that discard is
         * what C5 exists to prevent, because the value may already have
         * been committed. */
        nodus_witness_t *w = fixture(&m[0], &m[1], 6, 14, 15000, 10000);
        roster_put(w, &outsider);
        w->bft_config.n_witnesses = w->roster.n_witnesses;

        char dir[] = "/tmp/test_bft_c5_XXXXXX";
        CHECK(mkdtemp(dir) != NULL, "temp dir");
        snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
        uint8_t chain_id[16];
        memset(chain_id, 0x33, sizeof(chain_id));
        CHECK(nodus_witness_create_chain_db(w, chain_id) == 0, "chain db");
        put_snapshot(w, EP, m, 7);
        CHECK(dna_bft_quorum(7) == 5, "quorum of the height's committee is 5");

        uint8_t cert_hash[NODUS_T3_TX_HASH_LEN];
        memset(cert_hash, 0x5C, sizeof(cert_hash));
        const uint32_t VIEW = 3;

        nodus_t3_cert_entry_t sigs[8];
        memset(sigs, 0, sizeof(sigs));
        for (int i = 0; i < 7; i++) {
            memcpy(sigs[i].voter_id, m[i].id, NODUS_T3_WITNESS_ID_LEN);
            sign_prepared(sigs[i].signature, &m[i], VIEW, H, cert_hash);
        }

        CHECK(nodus_witness_bft_verify_prepared_cert(w, H, VIEW, cert_hash,
                                                     sigs, 5),
              "5 signers of the HEIGHT's committee meet ITS quorum "
              "(pre-fix: measured against 14 and discarded)");
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H, VIEW, cert_hash,
                                                      sigs, 4),
              "4 do not — the threshold is real, not merely lowered");

        /* Duplicate voters must not inflate the count. This is the hole
         * the handle_viewchg copy had: one valid signature repeated
         * quorum-many times proved a certificate one validator signed. */
        nodus_t3_cert_entry_t dup[5];
        for (int i = 0; i < 5; i++) dup[i] = sigs[0];
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H, VIEW, cert_hash,
                                                      dup, 5),
              "one signature repeated 5 times proves nothing");

        /* Membership authority: a signer in the gossip ROSTER but not in
         * the committee governing H must not count. Four committee
         * members plus the outsider is five signatures and still below
         * the quorum of five committee members. */
        nodus_t3_cert_entry_t mixed[5];
        for (int i = 0; i < 4; i++) mixed[i] = sigs[i];
        memcpy(mixed[4].voter_id, outsider.id, NODUS_T3_WITNESS_ID_LEN);
        sign_prepared(mixed[4].signature, &outsider, VIEW, H, cert_hash);
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H, VIEW, cert_hash,
                                                      mixed, 5),
              "a roster member outside the height's committee does not count");

        /* And the cert must be bound to ITS OWN (height, view, value):
         * the signatures verify over the PREPARED preimage, so changing
         * any of the three must break it. */
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H + 1, VIEW,
                                                      cert_hash, sigs, 5),
              "the same signatures do not prove another height");
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H, VIEW + 1,
                                                      cert_hash, sigs, 5),
              "nor another view");
        uint8_t other_hash[NODUS_T3_TX_HASH_LEN];
        memset(other_hash, 0x5D, sizeof(other_hash));
        CHECK(!nodus_witness_bft_verify_prepared_cert(w, H, VIEW,
                                                      other_hash, sigs, 5),
              "nor another value");

        nodus_witness_close(w);
        fixture_free(w);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
        if (system(cmd) != 0) { /* best effort cleanup */ }
    }

    /* ── §9 D9 — one Byzantine node cannot reset anyone's tally ────── */
    printf("§9 D9 — the view-change tally is not resettable by one peer\n");
    {
        peer_t honest[6], evil;
        for (int i = 0; i < 6; i++) peer_make(&honest[i]);
        peer_make(&evil);
        /* quorum 5, threshold 3. */
        nodus_witness_t *w = fixture(&self, honest, 6, 5, 15000, 10000);
        roster_put(w, &evil);
        w->bft_config.n_witnesses = w->roster.n_witnesses;
        enter_round(w, &self, 6, 41, tx_hash);

        nodus_t3_msg_t vc;
        /* Four honest validators converge on view 1. */
        for (int i = 0; i < 4; i++) {
            fill_viewchg(&vc, w, &honest[i], 1);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                  "honest peer at view 1");
        }
        CHECK(w->view_change_target == 1, "the cluster is at view 1");
        int progress = w->view_change_count;
        CHECK(progress >= 4, "four honest records held");

        /* THE ATTACK. Pre-D9 each of these single messages named a
         * higher view, REPLACED the target and CLEARED the array — one
         * message per reset, repeatable forever, and the honest majority
         * could never accumulate a quorum. */
        for (uint32_t v = 2; v <= 40; v++) {
            fill_viewchg(&vc, w, &evil, v);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0 ||
                  true, "attacker message accepted or ignored");
        }
        CHECK(w->view_change_target == 1,
              "39 attacker messages did NOT move the target");
        CHECK(tally_at(w, 1) >= 4,
              "and did NOT erase a single honest vote");
        CHECK(w->view_change_count <= progress + 1,
              "the attacker occupies at most ONE record slot, "
              "however many views it names");

        /* The honest cluster still completes, exactly as if the attacker
         * had never spoken. */
        fill_viewchg(&vc, w, &honest[4], 1);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "fifth honest vote at view 1");
        CHECK(w->current_view == 1,
              "quorum reached and the view advanced, attack notwithstanding");
        fixture_free(w);
    }

    /* ── §10 D9 — a LOWER target's certificate must not bind a HIGHER
     *            view. This is the safety property the removed
     *            array-wipe used to provide, and a mutation campaign
     *            caught it with ZERO coverage: deleting the target
     *            filter left all 204 tests green. ─────────────────── */
    printf("§10 D9 — a lower target's prepared cert cannot bind a higher view\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        /* No DB: the cert verifier takes the documented pre-genesis
         * roster path and its threshold is bft_config.quorum, so five
         * roster signatures make a valid certificate here. */
        nodus_witness_t *w = fixture(&self, p, 6, 5, 15000, 10000);
        enter_round(w, &self, 6, 41, tx_hash);

        const uint64_t CH = 41;
        const uint32_t CV = 0;
        uint8_t cert_hash[NODUS_T3_TX_HASH_LEN];
        memset(cert_hash, 0x9E, sizeof(cert_hash));

        /* p[0] asks for view 1 and carries a prepared cert for it. */
        nodus_t3_msg_t vc;
        fill_viewchg(&vc, w, &p[0], 1);
        vc.viewchg.has_prepared = true;
        vc.viewchg.prepared_height = CH;
        vc.viewchg.prepared_view = CV;
        memcpy(vc.viewchg.prepared_tx_hash, cert_hash, NODUS_T3_TX_HASH_LEN);
        vc.viewchg.prepared_n_sigs = 5;
        for (int i = 0; i < 5; i++) {
            memcpy(vc.viewchg.prepared_sigs[i].voter_id, p[i].id,
                   NODUS_T3_WITNESS_ID_LEN);
            sign_prepared(vc.viewchg.prepared_sigs[i].signature, &p[i],
                          CV, CH, cert_hash);
        }
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "peer VIEW_CHANGE with a prepared cert recorded");
        int cert_slot = -1;
        for (int i = 0; i < w->view_change_count; i++)
            if (w->view_changes[i].prepared.has_prepared) cert_slot = i;
        CHECK(cert_slot >= 0, "the certificate really was admitted");
        CHECK(w->view_changes[cert_slot].target_view == 1,
              "and it is attached to target 1");

        /* Sanity, and the anti-vacuity leg: AT target 1 the cert binds. */
        w->view_change_target = 1;
        nodus_witness_bft_bind_reproposal_from_view_changes(w);
        CHECK(w->reproposal_required && w->reproposal_height == CH,
              "at its OWN target the certificate binds");

        /* Now f+1 validators move the cluster to view 2. p[0] does not
         * re-send, so its record stays at target 1 — exactly the state
         * the old wipe destroyed and D9 deliberately keeps. */
        for (int i = 1; i <= 3; i++) {
            fill_viewchg(&vc, w, &p[i], 2);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                  "peer at view 2 recorded");
        }
        CHECK(w->view_change_target == 2, "the cluster moved to view 2");
        CHECK(w->view_changes[cert_slot].target_view == 1 &&
              w->view_changes[cert_slot].prepared.has_prepared,
              "the old record SURVIVED (that is the point of D9)");

        /* THE ASSERTION. Binding at view 2 must ignore a certificate
         * that only view 1 ever backed. Letting it through would bind
         * the new view to a value the new view's voters never prepared —
         * the leak the wipe existed to prevent. */
        nodus_witness_bft_bind_reproposal_from_view_changes(w);
        CHECK(!w->reproposal_required,
              "at a HIGHER target the lower target's certificate is ignored");
        fixture_free(w);
    }

    printf("PASS test_bft_view_change_hardening\n");
    return 0;
}
