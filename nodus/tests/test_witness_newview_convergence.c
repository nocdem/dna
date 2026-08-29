/**
 * Nodus — O15C-D.3 — NEW_VIEW adoption convergence and the prepared-value
 * lock.
 *
 * ── The record this closes ────────────────────────────────────────────
 *
 * O15C-D.2 filed: honest validators may obtain different valid first-2f+1
 * VIEW_CHANGE collections, and a deterministic comparator cannot make
 * different INPUT SETS converge. It classified the consequence as
 * "liveness cost only, fail-closed". Source says otherwise.
 *
 * ── The reachable defect (SAFETY, not liveness) ───────────────────────
 *
 * Three facts, all from source:
 *
 *  1. NEW_VIEW carries NO proof — only new_view / n_proofs / the
 *     reproposal digest (nodus_tier3.h, enc_newview_args). Its own
 *     comment: "quorum is established client-side from the follower's
 *     own view_changes[] log, NOT from wire-carried proofs."
 *  2. Collection FREEZES at first quorum: once bft_vc_check_quorum sets
 *     current_view = target, every later VIEW_CHANGE for that view hits
 *     `if (vc->new_view <= w->current_view) return 0`
 *     (nodus_witness_bft.c) and is dropped. Differing subsets are
 *     permanent — they do not self-heal.
 *  3. The self-record — the ONLY path by which a node's own
 *     `last_prepared` enters `view_changes[]` — exists solely in
 *     initiate_view_change. A node that reaches view-change quorum from
 *     PEER messages before its own round timer fires never runs it, and
 *     afterwards targets current_view + 1.
 *
 * Consequently a node that itself prepared Y at height H can enter the
 * new view with its C5 gate UNARMED at that height — and nothing else in
 * the tree consults `last_prepared` at propose/vote time. It will then
 * vote a conflicting value X at H, which is exactly the refusal the
 * quorum-intersection safety argument depends on. With <= f Byzantine
 * assisting, X can commit at H while another node holds Y at H: a fork.
 *
 * ── The repair ────────────────────────────────────────────────────────
 *
 * (a) A PREPARED-VALUE LOCK keyed on the node's OWN `last_prepared`,
 *     which is authoritative local evidence, rather than on the
 *     subset-derived view_changes[]. Height-gated against the committed
 *     head, because `last_prepared` is cleared on commit_batch but NOT on
 *     the sync/replay path.
 * (b) The join-quorum path self-records, exactly as initiate does, so a
 *     node's own evidence can never be missing from its own decision.
 * (c) NEW_VIEW carries the SELECTED CERTIFICATE in full, so every
 *     validator verifies the same decision instead of consulting its own
 *     frozen subset.
 *
 * Sections:
 *   §1 a node reaches genuine prevote quorum and captures last_prepared
 *   §2 THE DEFECT STATE: join-quorum leaves its own evidence out
 *   §3 the prepared-value lock refuses a conflicting value at a prepared
 *      height, and admits an outranking one
 *   §4 the lock is height-gated (a value already committed via sync must
 *      not leave a stale lock)
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "nodus/nodus_types.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

#define NVAL 7
#define QUORUM 5

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

static void peer_make(peer_t *p) {
    CHECK(qgp_dsa87_keypair(p->pk, p->sk) == 0);
    uint8_t d[64];
    CHECK(qgp_sha3_512(p->pk, NODUS_PK_BYTES, d) == 0);
    memcpy(p->id, d, NODUS_T3_WITNESS_ID_LEN);
}

static void roster_put(nodus_witness_t *w, const peer_t *p) {
    uint32_t i = w->roster.n_witnesses++;
    memcpy(w->roster.witnesses[i].witness_id, p->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->roster.witnesses[i].pubkey, p->pk, NODUS_PK_BYTES);
    w->roster.witnesses[i].active = true;
}

/* No chain DB — committee lookups take the pre-genesis gossip-roster
 * fallback (F17 A5), the shape test_bft_liveness established. */
static nodus_witness_t *fixture(const peer_t *self, const peer_t *peers,
                                int n_peers) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    CHECK(srv != NULL);
    memcpy(srv->identity.pk.bytes, self->pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, self->sk, sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, self->id, NODUS_T3_WITNESS_ID_LEN);
    roster_put(w, self);
    for (int i = 0; i < n_peers; i++) roster_put(w, &peers[i]);
    w->bft_config.n_witnesses = w->roster.n_witnesses;
    w->bft_config.quorum = QUORUM;
    w->bft_config.round_timeout_ms = 16000;
    w->bft_config.viewchg_timeout_ms = 16000;
    return w;
}

static void free_fixture(nodus_witness_t *w) { free(w->server); free(w); }

/* O15N Faz 2A — 116-byte PREPARED preimage: "prepared"(8) ‖ chain_id(32) ‖
 * view(4 BE) ‖ height(8 BE) ‖ tx_hash(64), mirroring
 * compute_prepared_preimage. chain_id comes from the fixture; this file's
 * fixture() callocs and never creates a chain DB, so it is all-zero and
 * IDENTICAL across the P and Q witnesses §2 compares — which is required,
 * since §2's whole subject is that both reach the same binding from the
 * same certificate. */
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
    CHECK(nodus_sign_prepared_vote(&sig, pre, sizeof(pre), &sk) == 0);
    memcpy(out, sig.bytes, NODUS_SIG_BYTES);
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
}

static void fill_vote(nodus_t3_msg_t *m, uint8_t type, const peer_t *from,
                      uint64_t round, uint32_t view, const uint8_t *target) {
    memset(m, 0, sizeof(*m));
    m->type = type;
    m->header.round = round;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
    memcpy(m->vote.vote_target, target, NODUS_T3_TX_HASH_LEN);
    m->vote.vote = 0;
}

/* A VIEW_CHANGE that carries NO prepared certificate. */
static void fill_vc_bare(nodus_t3_msg_t *m, const peer_t *from,
                         uint32_t target_view) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWCHG;
    m->header.view = target_view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
    m->viewchg.new_view = target_view;
    m->viewchg.has_prepared = false;
}

int main(void) {
    static peer_t val[NVAL];
    for (int i = 0; i < NVAL; i++) peer_make(&val[i]);

    uint8_t Y[NODUS_T3_TX_HASH_LEN], X[NODUS_T3_TX_HASH_LEN];
    memset(Y, 0xAA, sizeof(Y));
    memset(X, 0xBB, sizeof(X));
    const uint64_t H = 7;

    /* ── §1 genuine prevote quorum captures last_prepared ──────────── */
    nodus_witness_t *w = fixture(&val[0], &val[1], NVAL - 1);
    {
        enter_round(w, &val[0], 6, H, Y);
        /* Four real peer PREVOTEs → 5 with our own → quorum. Every
         * cert_sig is verified by the production handler. */
        for (int i = 1; i <= 4; i++) {
            nodus_t3_msg_t m;
            fill_vote(&m, NODUS_T3_PREVOTE, &val[i], 6, 0, Y);
            sign_prepared(m.vote.cert_sig, &val[i], 0, H, Y, w->chain_id);
            CHECK_EQ(nodus_witness_bft_handle_vote(w, &m), 0);
        }
        CHECK(w->round_state.prevote_approve_count >= QUORUM);
        CHECK(w->last_prepared.present);
        CHECK_EQ(memcmp(w->last_prepared.tx_hash, Y, sizeof(Y)), 0);
        printf("[ok] §1 prevote quorum reached; this node PREPARED Y at "
               "height %llu (view %u)\n",
               (unsigned long long)w->last_prepared.height,
               w->last_prepared.view);
    }
    const uint64_t PREP_H = w->last_prepared.height;

    /* ── §2 join-quorum: does our own evidence reach our decision? ─── */
    {
        /* Five peer VIEW_CHANGEs for view 1, NONE carrying a prepared
         * cert — the carrier-count-of-one case. Our own timer has not
         * fired, so initiate_view_change never runs. */
        for (int i = 1; i <= QUORUM; i++) {
            nodus_t3_msg_t m;
            fill_vc_bare(&m, &val[i], 1);
            CHECK_EQ(nodus_witness_bft_handle_viewchg(w, &m), 0);
        }
        CHECK_EQ(w->current_view, 1);          /* we self-advanced */

        int own = 0, with_cert = 0;
        for (int i = 0; i < w->view_change_count; i++) {
            if (memcmp(w->view_changes[i].voter_id, val[0].id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) own++;
            if (w->view_changes[i].prepared.has_prepared) with_cert++;
        }
        printf("[info] §2 view_change_count=%d own_record=%d with_cert=%d "
               "reproposal_required=%d (we hold last_prepared for h=%llu)\n",
               w->view_change_count, own, with_cert,
               (int)w->reproposal_required, (unsigned long long)PREP_H);

#ifdef O15CD3_PREFIX_PROBE
        /* PRE-FIX: our own prepared cert is absent from our own decision
         * and the C5 gate is UNARMED at a height we prepared. */
        CHECK_EQ(own, 0);
        CHECK_EQ(with_cert, 0);
        CHECK(!w->reproposal_required);
        printf("[DEFECT OBSERVED] §2 the node PREPARED Y at h=%llu yet "
               "entered view 1 with its C5 gate UNARMED and its own "
               "certificate absent from view_changes[]\n",
               (unsigned long long)PREP_H);
#else
        /* POST-FIX (b): the join path self-records, so our own evidence
         * is in our own decision and the gate is armed to OUR value. */
        CHECK_EQ(own, 1);
        CHECK_EQ(with_cert, 1);
        CHECK(w->reproposal_required);
        CHECK_EQ(w->reproposal_height, PREP_H);
        CHECK_EQ(memcmp(w->reproposal_tx_hash, Y, sizeof(Y)), 0);
        printf("[ok] §2 join-quorum self-recorded our own certificate; the "
               "gate is armed to OUR prepared value\n");
#endif
    }

#ifndef O15CD3_PREFIX_PROBE
    /* ── §3 the prepared-value lock ────────────────────────────────── */
    {
        /* Conflicting value at a height we prepared: REFUSED. */
        CHECK(nodus_witness_bft_prepared_lock_blocks(w, PREP_H, X));
        /* Our own value: allowed. */
        CHECK(!nodus_witness_bft_prepared_lock_blocks(w, PREP_H, Y));
        /* A different height is not ours to lock. */
        CHECK(!nodus_witness_bft_prepared_lock_blocks(w, PREP_H + 1, X));
        /* Guards. */
        CHECK(!nodus_witness_bft_prepared_lock_blocks(NULL, PREP_H, X));
        CHECK(!nodus_witness_bft_prepared_lock_blocks(w, PREP_H, NULL));
        printf("[ok] §3 prepared-value lock refuses a conflicting value at "
               "a height this node prepared\n");
    }

    /* ── §4 the lock is height-gated against the committed head ────── */
    {
        /* last_prepared is cleared on commit_batch but NOT on the
         * sync/replay path, so a node that learned this height via SYNC
         * would otherwise carry a stale lock forever and reject every
         * later proposal. */
        CHECK(nodus_witness_bft_prepared_lock_blocks(w, PREP_H, X));
        w->last_prepared.present = false;      /* what a commit does */
        CHECK(!nodus_witness_bft_prepared_lock_blocks(w, PREP_H, X));
        printf("[ok] §4 a cleared/committed prepared value leaves no stale "
               "lock\n");
    }
#endif

    /* ── §5 THE PRINCIPAL PROOF: genuinely different subsets converge ── */
    {
        /* Two honest nodes are given DIFFERENT admissible VIEW_CHANGE
         * subsets for the same target view — the state O15C-D.2 filed as
         * unresolvable by a comparator. Node P's subset carries the
         * certificate; node Q's does not. Both then receive the SAME
         * NEW_VIEW carrying that certificate. Post-fix they must reach
         * the SAME binding, which is what "verify the same decision"
         * means. */
        nodus_witness_t *P = fixture(&val[0], &val[1], NVAL - 1);
        nodus_witness_t *Q = fixture(&val[0], &val[1], NVAL - 1);

        uint8_t cert_sigs_raw[QUORUM][NODUS_SIG_BYTES];
        nodus_t3_cert_entry_t cert[QUORUM];
        memset(cert, 0, sizeof(cert));
        for (int i = 0; i < QUORUM; i++) {
            /* P->chain_id and Q->chain_id are the same all-zero value
             * (both came from the same calloc'ing fixture), so one
             * certificate is verifiable by both — which is the point. */
            sign_prepared(cert_sigs_raw[i], &val[i], 0, H, Y, P->chain_id);
            memcpy(cert[i].voter_id, val[i].id, NODUS_T3_WITNESS_ID_LEN);
            memcpy(cert[i].signature, cert_sigs_raw[i], NODUS_SIG_BYTES);
        }

        /* P: one peer's VIEW_CHANGE carries the cert. */
        for (int i = 1; i <= QUORUM; i++) {
            nodus_t3_msg_t m;
            fill_vc_bare(&m, &val[i], 1);
            if (i == 1) {
                m.viewchg.has_prepared = true;
                m.viewchg.prepared_height = H;
                m.viewchg.prepared_view = 0;
                memcpy(m.viewchg.prepared_tx_hash, Y, sizeof(Y));
                m.viewchg.prepared_n_sigs = QUORUM;
                for (int k = 0; k < QUORUM; k++)
                    m.viewchg.prepared_sigs[k] = cert[k];
            }
            CHECK_EQ(nodus_witness_bft_handle_viewchg(P, &m), 0);
        }
        /* Q: the SAME five voters, none carrying the cert. */
        for (int i = 1; i <= QUORUM; i++) {
            nodus_t3_msg_t m;
            fill_vc_bare(&m, &val[i], 1);
            CHECK_EQ(nodus_witness_bft_handle_viewchg(Q, &m), 0);
        }

        CHECK_EQ(P->current_view, 1);
        CHECK_EQ(Q->current_view, 1);
        /* Non-vacuity: the subsets really do differ. */
        CHECK(P->reproposal_required);
        CHECK(!Q->reproposal_required);
        printf("[info] §5 divergent bindings BEFORE adoption: "
               "P=%d Q=%d — the differing-subset state\n",
               (int)P->reproposal_required, (int)Q->reproposal_required);

        /* The leader's NEW_VIEW, carrying the verified certificate. */
        nodus_t3_msg_t nvm;
        memset(&nvm, 0, sizeof(nvm));
        nvm.type = NODUS_T3_NEWVIEW;
        nvm.header.view = 1;
        /* Leader for (epoch 0, view 1) by sorted rank — resolve it the
         * way the production check does, so the sender is accepted. */
        {
            int slot = nodus_witness_bft_leader_index(0, 1, NVAL);
            int idx = nodus_witness_roster_sorted_at(&P->roster, slot);
            CHECK(idx >= 0);
            memcpy(nvm.header.sender_id, P->roster.witnesses[idx].witness_id,
                   NODUS_T3_WITNESS_ID_LEN);
        }
        nvm.header.timestamp = nodus_time_now();
        nodus_random((uint8_t *)&nvm.header.nonce, sizeof(nvm.header.nonce));
        nvm.newview.new_view = 1;
        nvm.newview.has_reproposal = true;
        nvm.newview.reproposal_height = H;
        nvm.newview.reproposal_prepared_view = 0;
        memcpy(nvm.newview.reproposal_tx_hash, Y, sizeof(Y));
        nvm.newview.reproposal_n_sigs = QUORUM;
        for (int k = 0; k < QUORUM; k++)
            nvm.newview.reproposal_sigs[k] = cert[k];

        nodus_t3_msg_t nvq = nvm;
        nodus_random((uint8_t *)&nvq.header.nonce, sizeof(nvq.header.nonce));

        CHECK_EQ(nodus_witness_bft_handle_newview(P, &nvm), 0);
        CHECK_EQ(nodus_witness_bft_handle_newview(Q, &nvq), 0);

        /* CONVERGENCE: identical bindings from different subsets. */
        CHECK(P->reproposal_required);
        CHECK(Q->reproposal_required);
        CHECK_EQ(P->reproposal_height, Q->reproposal_height);
        CHECK_EQ(P->reproposal_prepared_view, Q->reproposal_prepared_view);
        CHECK_EQ(memcmp(P->reproposal_tx_hash, Q->reproposal_tx_hash,
                        NODUS_T3_TX_HASH_LEN), 0);
        CHECK_EQ(memcmp(Q->reproposal_tx_hash, Y, sizeof(Y)), 0);
        printf("[ok] §5 DIFFERENT valid subsets CONVERGED on the same "
               "binding via the carried certificate\n");

        /* §11 replay is idempotent. */
        nodus_t3_msg_t again = nvm;
        nodus_random((uint8_t *)&again.header.nonce, sizeof(again.header.nonce));
        CHECK_EQ(nodus_witness_bft_handle_newview(Q, &again), 0);
        CHECK(Q->reproposal_required);
        CHECK_EQ(Q->reproposal_height, H);
        CHECK_EQ(memcmp(Q->reproposal_tx_hash, Y, sizeof(Y)), 0);
        printf("[ok] §11 a replayed NEW_VIEW is inert\n");

        /* ── §6-§9 adversarial certificates, all fail closed ───────── */
        /* invalid signature */
        CHECK(!nodus_witness_bft_verify_prepared_cert(Q, H, 0, Y, cert, 0));
        {
            nodus_t3_cert_entry_t bad[QUORUM];
            memcpy(bad, cert, sizeof(bad));
            bad[2].signature[10] ^= 0xFF;
            CHECK(!nodus_witness_bft_verify_prepared_cert(Q, H, 0, Y, bad,
                                                            QUORUM));
            printf("[ok] §8 an invalid signature drops the cert below "
                   "quorum — rejected\n");
        }
        /* insufficient signatures */
        CHECK(!nodus_witness_bft_verify_prepared_cert(Q, H, 0, Y, cert,
                                                        QUORUM - 1));
        printf("[ok] §9 quorum-1 signatures — rejected\n");
        /* duplicate voter cannot inflate quorum */
        {
            nodus_t3_cert_entry_t dup[QUORUM];
            for (int k = 0; k < QUORUM; k++) dup[k] = cert[0];
            CHECK(!nodus_witness_bft_verify_prepared_cert(Q, H, 0, Y, dup,
                                                            QUORUM));
            printf("[ok] §5.dup one signature repeated cannot manufacture "
                   "quorum\n");
        }
        /* substitution: same sigs, different claimed value/height/view */
        CHECK(!nodus_witness_bft_verify_prepared_cert(Q, H, 0, X, cert,
                                                        QUORUM));
        CHECK(!nodus_witness_bft_verify_prepared_cert(Q, H + 1, 0, Y, cert,
                                                        QUORUM));
        CHECK(!nodus_witness_bft_verify_prepared_cert(Q, H, 9, Y, cert,
                                                        QUORUM));
        printf("[ok] §13 substituted value / height / prepared-view — all "
               "rejected (the signatures do not cover them)\n");

        /* §12 leader omits evidence we hold: has_reproposal=false while
         * we still hold an uncommitted prepared value. */
        {
            nodus_witness_t *R = fixture(&val[0], &val[1], NVAL - 1);
            R->last_prepared.present = true;
            R->last_prepared.height = H;
            R->last_prepared.view = 0;
            memcpy(R->last_prepared.tx_hash, Y, sizeof(Y));
            nodus_t3_msg_t omit;
            memset(&omit, 0, sizeof(omit));
            omit.type = NODUS_T3_NEWVIEW;
            omit.header.view = 1;
            {
                int slot = nodus_witness_bft_leader_index(0, 1, NVAL);
                int idx = nodus_witness_roster_sorted_at(&R->roster, slot);
                memcpy(omit.header.sender_id,
                       R->roster.witnesses[idx].witness_id,
                       NODUS_T3_WITNESS_ID_LEN);
            }
            omit.header.timestamp = nodus_time_now();
            nodus_random((uint8_t *)&omit.header.nonce,
                         sizeof(omit.header.nonce));
            omit.newview.new_view = 1;
            omit.newview.has_reproposal = false;
            CHECK_EQ(nodus_witness_bft_handle_newview(R, &omit), -1);
            printf("[ok] §12 a leader discarding evidence we hold is "
                   "rejected\n");
            free_fixture(R);
        }

        free_fixture(P);
        free_fixture(Q);
    }

    free_fixture(w);
#ifdef O15CD3_PREFIX_PROBE
    printf("PASS test_witness_newview_convergence [PRE-FIX PROBE — the "
           "assertions above document the DEFECT]\n");
#else
    printf("PASS test_witness_newview_convergence\n");
#endif
    return 0;
}
