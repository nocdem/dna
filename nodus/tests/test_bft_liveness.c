/**
 * Nodus — O15C-C BFT liveness regressions (2026-08-19 rehearsal round 20).
 *
 * Two grounded production defects, both observed in the frozen
 * stagef-20260819T020450Z evidence and root-caused from source:
 *
 *  D2 — a PREVOTE/PRECOMMIT arriving BEFORE this node initialized the
 *       round it belongs to (or, for PRECOMMIT, while the node was still
 *       in PREVOTE phase of the same round) was dropped SILENTLY by
 *       handle_vote's round/phase equality checks
 *       (nodus_witness_bft.c:4797 / :4832 pre-fix). Under timing skew
 *       three of seven nodes each missed prevote quorum by one vote and
 *       the round could never commit.
 *
 *  D1 — a node whose view_change_in_progress was set by RECEIVING a
 *       peer's VIEW_CHANGE (handle_viewchg join path) never broadcast or
 *       self-recorded its own view-change vote when its OWN round
 *       timeout later fired: initiate_view_change returned early on the
 *       in_progress guard (nodus_witness_bft.c:5740 pre-fix). Six of
 *       seven votes were never sent; view-change quorum (5) was
 *       structurally unreachable (observed 1/5 everywhere).
 *
 * The witness fixture is heap-allocated (multi-MB struct) and uses no
 * chain DB — committee lookups take the documented pre-genesis
 * gossip-roster fallback (F17 A5), and w->chain_id is never set, so it
 * stays all-zero: the pre-genesis row of the O15L identity matrix, which
 * is why verify_chain_id lets these frames through.
 *
 * ── EVERY VOTE THIS FILE INJECTS CARRIES A REAL SIGNATURE (O15L Faz 3) ──
 *
 * D2.a's PREVOTEs always did, because C5 verifies a PREVOTE's cert_sig per
 * vote. D2.b's PRECOMMITs did NOT: they were built with cert_sig zeroed,
 * which was harmless while a PRECOMMIT's certificate was copied into the
 * vote slot unverified.
 *
 * O15L Faz 3 ended that. A PRECOMMIT is now verified at tally time exactly
 * as a PREVOTE is, and an APPROVE whose cert_sig does not verify drops the
 * ENTIRE vote — so the zeroed fixture stopped injecting a vote at all and
 * D2.b asserted on something that was no longer there ("C precommit
 * accepted", with the handler logging "PRECOMMIT cert_sig verify FAILED …
 * height=7"). The fixture now signs the 144-byte cert preimage with each
 * sender's own key (sign_cert below).
 *
 * This changed the FIXTURE, not the PROPERTY. D2.b still proves only that
 * an early PRECOMMIT is buffered and later counted; the signature is the
 * precondition for that vote to exist, not a new subject. Anyone adding a
 * PRECOMMIT to this file must sign it the same way — an unsigned one is
 * silently dropped and will make its section assert on a vote that never
 * landed, which is precisely how this file broke.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_cert.h"   /* O15L Faz 3 — the 144-byte
                                           * PRECOMMIT cert preimage the
                                           * D2.b fixture must now sign. */
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "nodus/nodus_types.h"

#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAIL %s:%d — %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    fprintf(stderr, "  ok: %s\n", msg); \
} while (0)

/* One test peer: real ML-DSA-87 keys so PREVOTE cert_sig verification is
 * the production check, not a stub. */
typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

static void peer_make(peer_t *p) {
    CHECK(qgp_dsa87_keypair(p->pk, p->sk) == 0, "keygen");
    uint8_t d[64];
    CHECK(qgp_sha3_512(p->pk, NODUS_PK_BYTES, d) == 0, "id hash");
    memcpy(p->id, d, NODUS_T3_WITNESS_ID_LEN);
}

static void roster_put(nodus_witness_t *w, const peer_t *p) {
    uint32_t i = w->roster.n_witnesses++;
    memcpy(w->roster.witnesses[i].witness_id, p->id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->roster.witnesses[i].pubkey, p->pk, NODUS_PK_BYTES);
    w->roster.witnesses[i].active = true;
}

/* Fresh fixture: self + peers in the gossip roster, no DB, quorum from
 * the caller so quorum side effects fire only where the section wants
 * them. */
static nodus_witness_t *fixture(const peer_t *self, const peer_t *peers,
                                int n_peers, uint32_t quorum) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL, "fixture alloc");
    /* The broadcast path signs T3 envelopes with w->server->identity;
     * give the fixture a heap server (multi-MB struct) carrying the
     * self keypair. Zero peers means broadcasts reach nobody, which is
     * exactly what these state assertions need. */
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    CHECK(srv != NULL, "server alloc");
    memcpy(srv->identity.pk.bytes, self->pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, self->sk, sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, self->id, NODUS_T3_WITNESS_ID_LEN);
    roster_put(w, self);
    for (int i = 0; i < n_peers; i++) roster_put(w, &peers[i]);
    w->bft_config.n_witnesses = w->roster.n_witnesses;
    w->bft_config.quorum = quorum;
    w->bft_config.round_timeout_ms = 16000;
    w->bft_config.viewchg_timeout_ms = 16000;
    return w;
}

static void fill_vote_msg(nodus_t3_msg_t *m, uint8_t type,
                          const peer_t *from, uint64_t round,
                          uint32_t view, const uint8_t *target) {
    memset(m, 0, sizeof(*m));
    m->type = type;
    m->header.round = round;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
    memcpy(m->vote.vote_target, target, NODUS_T3_TX_HASH_LEN);
    m->vote.vote = 0; /* APPROVE */
}

/* Sign the C5 PREPARED preimage (view ‖ height ‖ tx_hash, 76 B — the
 * layout documented at nodus_witness_bft.c:104) with a peer's key. */
static void sign_prepared(uint8_t out_sig[NODUS_SIG_BYTES],
                          const peer_t *p, uint32_t view, uint64_t height,
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
    CHECK(nodus_sign_prepared_vote(&sig, pre, sizeof(pre), &sk) == 0,
          "prepared sign");
    memcpy(out_sig, sig.bytes, NODUS_SIG_BYTES);
}

/* Sign the Phase 7.5 PRECOMMIT cert preimage (144 B — domain tag ‖
 * block_hash ‖ voter_id ‖ height ‖ chain_id, nodus_witness_cert.h) with a
 * peer's key. The counterpart of sign_prepared above, and needed for the
 * same reason: since O15L Faz 3 an APPROVE PRECOMMIT whose cert_sig does
 * not verify is dropped WHOLE, so a fixture that leaves it zeroed no
 * longer injects a vote at all.
 *
 * The signer always names its OWN witness_id, because that is what the
 * production sign path does and what the tally reconstructs with — it
 * rebuilds the preimage from the message's sender_id, never from anything
 * the vote carries. RAW qgp_dsa87_sign, zero-padded to the fixed wire
 * width: the cert is untagged on both sides, unlike the NDS1-wrapped
 * PREPARED vote above. */
static void sign_cert(uint8_t out_sig[NODUS_SIG_BYTES], const peer_t *p,
                      const uint8_t *tx_hash, uint64_t height,
                      const uint8_t *chain_id) {
    uint8_t pre[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    CHECK(nodus_witness_compute_cert_preimage(tx_hash, p->id, height,
                                                chain_id, pre) == 0,
          "cert preimage");
    size_t siglen = 0;
    CHECK(qgp_dsa87_sign(out_sig, &siglen, pre, sizeof(pre), p->sk) == 0,
          "cert sign");
    CHECK(siglen <= NODUS_SIG_BYTES, "cert sig fits the wire width");
    if (siglen < NODUS_SIG_BYTES)
        memset(out_sig + siglen, 0, NODUS_SIG_BYTES - siglen);
}

/* Bring the fixture into round R exactly the way the follower round-init
 * does (handle_propose :4506-4510 + self prevote record), without
 * driving a full signed proposal through the wire layer. */
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
}

int main(void) {
    static peer_t self, b, c;   /* static: 7.5 KB each */
    peer_make(&self);
    peer_make(&b);
    peer_make(&c);

    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(tx_hash, 0xA7, sizeof(tx_hash));

    /* ── D2.a — early PREVOTE (arrives before the round starts) ────── */
    fprintf(stderr, "SECTION D2.a — early PREVOTE is counted\n");
    {
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 5);
        /* Post-commit shape: previous round settled, no live round. */
        w->last_committed_round = 5;
        w->current_round = 5;
        w->round_state.round = 5;
        w->round_state.phase = NODUS_W_PHASE_IDLE;

        nodus_t3_msg_t m;
        fill_vote_msg(&m, NODUS_T3_PREVOTE, &b, 6, 0, tx_hash);
        sign_prepared(m.vote.cert_sig, &b, 0, 7, tx_hash);
        (void)nodus_witness_bft_handle_vote(w, &m);
        CHECK(w->round_state.prevote_count == 0,
              "early vote not counted into the stale round");

        enter_round(w, &self, 6, 7, tx_hash);

        /* An in-round vote from C arrives — the ordinary path. Post-fix
         * the buffered early vote from B must be drained and counted
         * alongside it. */
        fill_vote_msg(&m, NODUS_T3_PREVOTE, &c, 6, 0, tx_hash);
        sign_prepared(m.vote.cert_sig, &c, 0, 7, tx_hash);
        CHECK(nodus_witness_bft_handle_vote(w, &m) == 0, "C vote accepted");

        CHECK(w->round_state.prevote_approve_count == 3,
              "early PREVOTE from B was buffered and counted (self+B+C)");
        free(w);
    }

    /* ── D2.b — PRECOMMIT arriving while still in PREVOTE phase ────── */
    fprintf(stderr, "SECTION D2.b — early PRECOMMIT is counted\n");
    {
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 5);
        enter_round(w, &self, 6, 7, tx_hash);

        /* O15L Faz 3 — both PRECOMMITs below carry a REAL cert now.
         *
         * This section's subject is unchanged and is NOT certificate
         * verification: it is that a PRECOMMIT arriving while this node is
         * still in PREVOTE gets BUFFERED and then counted after the phase
         * flips. But a vote can only demonstrate that if it survives to be
         * counted at all, and since Faz 3 an APPROVE PRECOMMIT whose
         * cert_sig does not verify is dropped whole — so the zeroed
         * cert_sig this fixture used to send made the section assert on a
         * vote that no longer existed. Signing restores the precondition;
         * it does not move the goalposts. D2.a already signs its PREVOTEs
         * for exactly the same reason (C5 verifies those per vote), and
         * this is the same pattern one phase later.
         *
         * The height and chain_id are READ FROM THE FIXTURE rather than
         * written as literals, because they must equal what the tally
         * reconstructs with: it rebuilds the preimage from
         * w->round_state.block_height (enter_round put 7 there) and
         * w->chain_id (all-zero here — this fixture has no chain DB and
         * never sets one, which is the pre-genesis row of the identity
         * matrix, so verify_chain_id lets these frames through). Reading
         * both from w keeps this correct if either ever changes. */
        nodus_t3_msg_t m;
        fill_vote_msg(&m, NODUS_T3_PRECOMMIT, &b, 6, 0, tx_hash);
        sign_cert(m.vote.cert_sig, &b, tx_hash,
                  w->round_state.block_height, w->chain_id);
        (void)nodus_witness_bft_handle_vote(w, &m);
        CHECK(w->round_state.precommit_count == 0,
              "early precommit not counted while in PREVOTE");

        /* Simulate the PREVOTE-quorum flip the way handle_vote does —
         * including the certificate, which that arm signs into slot 0
         * before broadcasting. Leaving it zeroed would make the simulated
         * state something the production path cannot produce, and would be
         * a trap for anyone who later lowers this section's quorum far
         * enough to reach the own-quorum certificate gate. */
        w->round_state.phase = NODUS_W_PHASE_PRECOMMIT;
        memcpy(w->round_state.precommits[0].voter_id, self.id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(w->round_state.precommits[0].pubkey, self.pk,
               NODUS_PK_BYTES);
        w->round_state.precommits[0].vote = NODUS_W_VOTE_APPROVE;
        sign_cert(w->round_state.precommits[0].signature, &self, tx_hash,
                  w->round_state.block_height, w->chain_id);
        w->round_state.precommit_count = 1;
        w->round_state.precommit_approve_count = 1;

        fill_vote_msg(&m, NODUS_T3_PRECOMMIT, &c, 6, 0, tx_hash);
        sign_cert(m.vote.cert_sig, &c, tx_hash,
                  w->round_state.block_height, w->chain_id);
        CHECK(nodus_witness_bft_handle_vote(w, &m) == 0,
              "C precommit accepted");
        CHECK(w->round_state.precommit_approve_count == 3,
              "early PRECOMMIT from B was buffered and counted (self+B+C)");
        free(w);
    }

    /* ── D1.a — joined node still broadcasts its own view-change vote ─ */
    fprintf(stderr, "SECTION D1.a — join then timeout still votes\n");
    {
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 5);
        enter_round(w, &self, 6, 7, tx_hash);

        /* B's VIEW_CHANGE arrives BEFORE our round timeout (the join
         * path) — exactly what happened on six of seven nodes. */
        nodus_t3_msg_t vc;
        memset(&vc, 0, sizeof(vc));
        vc.type = NODUS_T3_VIEWCHG;
        vc.header.round = 6;
        vc.header.view = 0;
        memcpy(vc.header.sender_id, b.id, NODUS_T3_WITNESS_ID_LEN);
        vc.header.timestamp = nodus_time_now();
        nodus_random((uint8_t *)&vc.header.nonce, sizeof(vc.header.nonce));
        vc.viewchg.new_view = 1;
        vc.viewchg.last_committed_round = 5;
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "peer view change accepted");
        /* O15H D9 — ONE peer message no longer commits this node to the
         * view; adoption needs f+1 backers (a single Byzantine node must
         * not be able to drag or reset the cluster). The vote is still
         * RECORDED, which is what this section's property depends on:
         * the node must go on to cast and broadcast its OWN vote at its
         * own timeout, and that is what the assertions below check. */
        CHECK(!w->view_change_in_progress,
              "one peer message records but does not commit us to the view");
        CHECK(w->view_change_count == 1, "peer vote recorded");

        /* Our own round timeout fires. Pre-fix: initiate_view_change is
         * a silent no-op (in_progress guard) — count stays 1 and our
         * vote is never recorded or sent. */
        w->round_state.phase_start_time =
            nodus_time_now() * 1000ULL - 20000ULL;
        nodus_witness_bft_check_timeout(w);

        CHECK(w->view_change_count == 2,
              "own view-change vote recorded after joining (peer + self)");
        bool self_found = false;
        for (int i = 0; i < w->view_change_count; i++)
            if (memcmp(w->view_changes[i].voter_id, self.id,
                       NODUS_T3_WITNESS_ID_LEN) == 0)
                self_found = true;
        CHECK(self_found, "self vote present in view_changes[]");
        free(w);
    }

    /* ── D1.b — self vote can complete the quorum ──────────────────── */
    fprintf(stderr, "SECTION D1.b — join + timeout completes quorum\n");
    {
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 2);
        enter_round(w, &self, 6, 7, tx_hash);

        nodus_t3_msg_t vc;
        memset(&vc, 0, sizeof(vc));
        vc.type = NODUS_T3_VIEWCHG;
        vc.header.round = 6;
        vc.header.view = 0;
        memcpy(vc.header.sender_id, c.id, NODUS_T3_WITNESS_ID_LEN);
        vc.header.timestamp = nodus_time_now();
        nodus_random((uint8_t *)&vc.header.nonce, sizeof(vc.header.nonce));
        vc.viewchg.new_view = 1;
        vc.viewchg.last_committed_round = 5;
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "peer view change accepted");
        CHECK(w->current_view == 0, "quorum 2 not yet reached");

        w->round_state.phase_start_time =
            nodus_time_now() * 1000ULL - 20000ULL;
        nodus_witness_bft_check_timeout(w);

        CHECK(w->current_view == 1,
              "self vote completed the view-change quorum (view 0 -> 1)");
        CHECK(!w->view_change_in_progress,
              "view change closed after completion");
        free(w);
    }

    fprintf(stderr, "test_bft_liveness: ALL SECTIONS PASSED\n");
    return 0;
}
