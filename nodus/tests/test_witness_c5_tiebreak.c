/**
 * Nodus — O15C-D.2 — the C5 prepared-certificate selection must be a
 * CANONICAL TOTAL ORDER, not arrival order.
 *
 * ── The record this closes ────────────────────────────────────────────
 *
 * O15C-D.1 filed: "C5 selection breaks equal-ranked ties using
 * first-wins over an arrival-ordered array." The inherited rule ranked
 * only by `prepared.height`, so two prepared certificates at the SAME
 * height fell back to whichever VIEW_CHANGE happened to arrive first.
 *
 * ── Why the tie is REACHABLE (Path B) ─────────────────────────────────
 *
 * A prepared certificate is captured only by a node that LOCALLY
 * observed prevote quorum (`last_prepared`, nodus_witness_bft.c). A node
 * that prevoted but never collected quorum carries nothing — so the
 * number of cert CARRIERS can be as low as one. With a single carrier,
 * most nodes' first-2f+1 VIEW_CHANGE collections lack that cert, they
 * bind-or-clear to nothing, and a DIFFERENT value can legally prepare at
 * the same height in the next view. Both certs then circulate: same
 * height, different views, different hashes, each carrying 2f+1 valid
 * signatures. Equal-height ties are therefore reachable, and before this
 * repair two honest nodes holding the identical set could bind to
 * different values purely because their messages arrived in a different
 * order.
 *
 * ── The rule under test ───────────────────────────────────────────────
 *
 *     (prepared.height, prepared.view, prepared.tx_hash)  strictly DESC
 *
 * `view` is the PBFT-canonical discriminator (Castro-Liskov selects the
 * highest-VIEW prepared cert per sequence number) and is authenticated:
 * it is bytes [0..3] of the signed PREPARED preimage, so it is covered
 * by the same 2f+1 signatures that admit the certificate. `tx_hash` is a
 * total-order backstop that quorum intersection should make unreachable
 * (see §6).
 *
 * ── Scope, honestly ───────────────────────────────────────────────────
 *
 * This proves determinism for nodes holding the SAME candidate set.
 * Nodes whose first-2f+1 collections genuinely DIFFER can still bind
 * differently under any comparator; that is a NEW_VIEW-adoption design
 * question, filed separately in nodus/BUGS.md and deliberately NOT
 * addressed here.
 *
 * Sections:
 *   §1 exhaustive permutations, mixed heights and views
 *   §2 the equal-height tie: higher VIEW wins, from every ordering
 *   §3 duplicates do not change the result
 *   §4 non-prepared records never participate
 *   §5 a lower-ranked cert cannot defeat a higher-ranked one
 *   §6 the (height, view) tie falls to the tx_hash backstop, totally
 *   §7 TWO INDEPENDENT WITNESS INSTANCES, real ML-DSA-87 certificates,
 *      the identical VIEW_CHANGE set delivered in OPPOSITE orders
 *      through the real handle_viewchg path — both must bind identically
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

/* ── candidate description, independent of storage order ─────────── */
typedef struct {
    bool     has;
    uint64_t height;
    uint32_t view;
    uint8_t  hash_byte;
} cand_t;

static void seed(nodus_witness_t *w, int slot, const cand_t *c) {
    w->view_changes[slot].prepared.has_prepared = c->has;
    w->view_changes[slot].prepared.height = c->height;
    w->view_changes[slot].prepared.view = c->view;
    memset(w->view_changes[slot].prepared.tx_hash, c->hash_byte,
           NODUS_T3_TX_HASH_LEN);
    /* sigs stays NULL / n_sigs 0 — the selection never reads them, and
     * the ownership contract requires n_sigs == 0 when sigs == NULL. */
}

/* Load a permutation of `cands` and run the production selection. */
static void select_perm(nodus_witness_t *w, const cand_t *cands, int n,
                        const int *order) {
    for (int i = 0; i < n; i++) seed(w, i, &cands[order[i]]);
    w->view_change_count = n;
    nodus_witness_bft_bind_reproposal_from_view_changes(w);
}

/* Every permutation of n items, lexicographic, no RNG. */
static bool next_perm(int *a, int n) {
    int i = n - 2;
    while (i >= 0 && a[i] >= a[i + 1]) i--;
    if (i < 0) return false;
    int j = n - 1;
    while (a[j] <= a[i]) j--;
    int t = a[i]; a[i] = a[j]; a[j] = t;
    for (int lo = i + 1, hi = n - 1; lo < hi; lo++, hi--) {
        t = a[lo]; a[lo] = a[hi]; a[hi] = t;
    }
    return true;
}

/* Run all permutations; assert every one yields the SAME binding. */
static long all_perms_agree(nodus_witness_t *w, const cand_t *cands, int n,
                            bool expect_bound, uint64_t exp_h,
                            uint8_t exp_hash_byte) {
    int order[8];
    for (int i = 0; i < n; i++) order[i] = i;
    long perms = 0;
    do {
        select_perm(w, cands, n, order);
        CHECK_EQ(w->reproposal_required, expect_bound);
        if (expect_bound) {
            CHECK_EQ(w->reproposal_height, exp_h);
            for (int k = 0; k < NODUS_T3_TX_HASH_LEN; k++)
                CHECK_EQ(w->reproposal_tx_hash[k], exp_hash_byte);
        }
        perms++;
    } while (next_perm(order, n));
    return perms;
}

/* ── §7 fixture: real keys, real signatures, real handler ────────── */
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

/* No chain DB — committee lookups take the documented pre-genesis
 * gossip-roster fallback (F17 A5), the same shape test_bft_liveness uses. */
static nodus_witness_t *fixture(const peer_t *self, const peer_t *peers,
                                int n_peers, uint32_t quorum) {
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
    w->bft_config.quorum = quorum;
    w->bft_config.round_timeout_ms = 16000;
    w->bft_config.viewchg_timeout_ms = 16000;
    return w;
}

/* O15N Faz 2A — 116-byte PREPARED preimage: "prepared"(8) ‖ chain_id(32) ‖
 * view(4 BE) ‖ height(8 BE) ‖ tx_hash(64), mirroring
 * compute_prepared_preimage. */
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

/* One VIEW_CHANGE carrying a REAL 2f+1-signed prepared certificate.
 * chain_id is supplied by the caller from the witness that will VERIFY
 * this certificate, because that is what the verifier rebuilds the
 * preimage with (O15N Faz 2A). */
static void make_viewchg(nodus_t3_msg_t *m, const peer_t *from,
                         uint32_t target_view, uint32_t prep_view,
                         uint64_t prep_height, uint8_t hash_byte,
                         const peer_t *signers, int n_signers,
                         const uint8_t *chain_id)
{
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWCHG;
    m->header.view = target_view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));

    m->viewchg.new_view = target_view;
    m->viewchg.has_prepared = true;
    m->viewchg.prepared_height = prep_height;
    m->viewchg.prepared_view = prep_view;
    memset(m->viewchg.prepared_tx_hash, hash_byte, NODUS_T3_TX_HASH_LEN);
    m->viewchg.prepared_n_sigs = (uint32_t)n_signers;
    for (int i = 0; i < n_signers; i++) {
        memcpy(m->viewchg.prepared_sigs[i].voter_id, signers[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        sign_prepared(m->viewchg.prepared_sigs[i].signature, &signers[i],
                      prep_view, prep_height, m->viewchg.prepared_tx_hash,
                      chain_id);
    }
}

int main(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);

    /* ── §1 mixed heights and views, every permutation ─────────────── */
    {
        const cand_t c[4] = {
            { true, 10, 3, 0xA1 },
            { true, 42, 0, 0xB2 },   /* highest HEIGHT wins outright */
            { true, 42 - 1, 9, 0xC3 },
            { true,  7, 1, 0xD4 },
        };
        long p = all_perms_agree(w, c, 4, true, 42, 0xB2);
        CHECK_EQ(p, 24);
        printf("[ok] §1 %ld permutations agree — height is still primary\n", p);
    }

    /* ── §2 THE TIE: equal height, different views ─────────────────── */
    {
        /* This is the case the record is about. Pre-fix, the answer was
         * whichever record sat earliest in the array. */
        const cand_t c[3] = {
            { true, 100, 0, 0x11 },   /* older view */
            { true, 100, 5, 0x22 },   /* NEWER view — must win */
            { true,  99, 9, 0x33 },   /* higher view, lower height */
        };
        long p = all_perms_agree(w, c, 3, true, 100, 0x22);
        CHECK_EQ(p, 6);
        printf("[ok] §2 equal-height tie: highest VIEW wins in all %ld "
               "orderings\n", p);
    }

    /* ── §3 duplicates do not change the result ────────────────────── */
    {
        /* The same certificate reported by several voters is the NORMAL
         * case — every carrier relays it. */
        const cand_t c[4] = {
            { true, 55, 2, 0x77 },
            { true, 55, 2, 0x77 },
            { true, 55, 2, 0x77 },
            { true, 50, 8, 0x88 },
        };
        long p = all_perms_agree(w, c, 4, true, 55, 0x77);
        CHECK_EQ(p, 24);
        printf("[ok] §3 duplicate certificates do not change the selection "
               "(%ld permutations)\n", p);
    }

    /* ── §4 non-prepared records never participate ─────────────────── */
    {
        const cand_t c[4] = {
            { false, 999, 9, 0xEE },   /* would dominate if it counted */
            { true,   30, 1, 0x44 },
            { false, 998, 8, 0xDD },
            { true,   20, 7, 0x55 },
        };
        long p = all_perms_agree(w, c, 4, true, 30, 0x44);
        CHECK_EQ(p, 24);
        printf("[ok] §4 records without a prepared cert never participate "
               "(%ld permutations)\n", p);

        /* ...and a set with none at all CLEARS, in every ordering. */
        const cand_t none[3] = {
            { false, 5, 1, 0x01 }, { false, 6, 2, 0x02 }, { false, 7, 3, 0x03 },
        };
        long q = all_perms_agree(w, none, 3, false, 0, 0);
        CHECK_EQ(q, 6);
        printf("[ok] §4 no prepared cert clears the binding (%ld "
               "permutations)\n", q);
    }

    /* ── §5 a lower-ranked cert cannot defeat a higher-ranked one ──── */
    {
        /* Lower height but much higher view — height dominates. */
        const cand_t c[2] = {
            { true, 200, 0, 0x61 },
            { true, 199, 99, 0x62 },
        };
        long p = all_perms_agree(w, c, 2, true, 200, 0x61);
        CHECK_EQ(p, 2);
        printf("[ok] §5 a higher view cannot defeat a higher height "
               "(%ld permutations)\n", p);
    }

    /* ── §6 the (height, view) backstop is TOTAL ───────────────────── */
    {
        /* Reaching this needs two 2f+1 prevote sets in ONE view, whose
         * intersection of >= f+1 forces an honest double-prevote — so it
         * should be unreachable with <= f Byzantine validators. The
         * comparator still resolves it deterministically rather than
         * silently reverting to arrival order at exactly the moment the
         * protocol is under attack. Larger hash byte wins (memcmp). */
        const cand_t c[3] = {
            { true, 77, 4, 0x10 },
            { true, 77, 4, 0xF0 },   /* same height AND view */
            { true, 77, 4, 0x90 },
        };
        long p = all_perms_agree(w, c, 3, true, 77, 0xF0);
        CHECK_EQ(p, 6);
        printf("[ok] §6 same (height,view) resolves totally by tx_hash "
               "(%ld permutations)\n", p);
    }

    free(w);

    /* ── §7 two instances, real signatures, opposite arrival orders ── */
    {
        /* Four validators; quorum 3 = dna_bft_quorum(4). Two DIFFERENT
         * prepared certificates at the SAME height from different views,
         * each signed by 3 real keys over the real PREPARED preimage.
         * Both nodes receive the IDENTICAL set — only the order differs. */
        peer_t all[4];
        for (int i = 0; i < 4; i++) peer_make(&all[i]);

        const uint64_t H = 40;
        const uint32_t TARGET_VIEW = 1;

        /* Node A: old cert first.  Node B: new cert first. Both are built
         * BEFORE the certificates, because the certificates must be
         * signed over the chain_id these two will verify against. Both
         * come from the same calloc'ing fixture and neither creates a
         * chain DB, so a->chain_id == b->chain_id (all-zero) and ONE
         * certificate is verifiable by both — which is the precondition
         * for "the same candidate set, different arrival order". */
        nodus_witness_t *a = fixture(&all[0], &all[1], 3, 3);
        nodus_witness_t *b = fixture(&all[0], &all[1], 3, 3);
        CHECK(memcmp(a->chain_id, b->chain_id, sizeof(a->chain_id)) == 0);

        nodus_t3_msg_t vc_old, vc_new;   /* prepared in view 0 / view 3 */
        make_viewchg(&vc_old, &all[1], TARGET_VIEW, 0, H, 0x31, all, 3,
                     a->chain_id);
        make_viewchg(&vc_new, &all[2], TARGET_VIEW, 3, H, 0x32, all, 3,
                     a->chain_id);

        for (int i = 0; i < 2; i++) {
            nodus_witness_t *w2 = (i == 0) ? a : b;
            w2->view_change_in_progress = true;
            w2->view_change_target = TARGET_VIEW;
        }

        /* The replay-prevention nonce table is process-global
         * (nodus_witness_bft.c, `nonce_buckets`), so the very same
         * envelope cannot be delivered twice inside one test process.
         * Node B therefore gets copies with fresh envelope nonces — the
         * PREPARED CERTIFICATE BYTES (height, view, tx_hash and all
         * signatures) are byte-identical, which is what "the same
         * candidate set" means here. Only the transport envelope and the
         * arrival ORDER differ, which is exactly the variable under
         * test. */
        nodus_t3_msg_t vc_old_b = vc_old, vc_new_b = vc_new;
        nodus_random((uint8_t *)&vc_old_b.header.nonce,
                     sizeof(vc_old_b.header.nonce));
        nodus_random((uint8_t *)&vc_new_b.header.nonce,
                     sizeof(vc_new_b.header.nonce));
        CHECK_EQ(memcmp(vc_old_b.viewchg.prepared_tx_hash,
                        vc_old.viewchg.prepared_tx_hash,
                        NODUS_T3_TX_HASH_LEN), 0);
        CHECK_EQ(memcmp(vc_new_b.viewchg.prepared_sigs[0].signature,
                        vc_new.viewchg.prepared_sigs[0].signature,
                        NODUS_SIG_BYTES), 0);

        CHECK_EQ(nodus_witness_bft_handle_viewchg(a, &vc_old), 0);
        CHECK_EQ(nodus_witness_bft_handle_viewchg(a, &vc_new), 0);

        CHECK_EQ(nodus_witness_bft_handle_viewchg(b, &vc_new_b), 0);
        CHECK_EQ(nodus_witness_bft_handle_viewchg(b, &vc_old_b), 0);

        /* Both must have ADMITTED both certs — otherwise the orderings
         * are not comparable and this section proves nothing.
         *
         * O15H D5b — the count is 2 PEER records plus OUR OWN. quorum
         * here is 3, so the join threshold is ((3-1)/2)+1 = 2: the second
         * peer VIEW_CHANGE makes f+1 validators asking for this view, and
         * the node correctly casts its own vote instead of waiting for
         * its round timeout. The self-record carries no prepared cert
         * (this fixture never sets last_prepared), so it cannot enter the
         * selection under test — and slots 0 and 1 are still the two peer
         * records, in arrival order, which is the variable §7 varies. */
        CHECK_EQ(a->view_change_count, 3);
        CHECK_EQ(b->view_change_count, 3);
        int a_prep = 0, b_prep = 0;
        for (int i = 0; i < 2; i++) {
            if (a->view_changes[i].prepared.has_prepared) a_prep++;
            if (b->view_changes[i].prepared.has_prepared) b_prep++;
        }
        CHECK_EQ(a_prep, 2);
        CHECK_EQ(b_prep, 2);
        /* The self-record must be inert here, or the section's claim
         * ("both bound to the higher-view cert") could be satisfied by
         * our own evidence rather than by the ordering-independent
         * comparator. */
        CHECK(!a->view_changes[2].prepared.has_prepared);
        CHECK(!b->view_changes[2].prepared.has_prepared);

        /* The arrays really are in opposite orders — otherwise a passing
         * result would be vacuous. */
        CHECK(a->view_changes[0].prepared.view !=
              b->view_changes[0].prepared.view);

        nodus_witness_bft_bind_reproposal_from_view_changes(a);
        nodus_witness_bft_bind_reproposal_from_view_changes(b);

        CHECK(a->reproposal_required);
        CHECK(b->reproposal_required);
        CHECK_EQ(a->reproposal_height, b->reproposal_height);
        CHECK_EQ(memcmp(a->reproposal_tx_hash, b->reproposal_tx_hash,
                        NODUS_T3_TX_HASH_LEN), 0);
        /* ...and it is the HIGHER-VIEW certificate, not merely "equal". */
        CHECK_EQ(a->reproposal_height, H);
        for (int k = 0; k < NODUS_T3_TX_HASH_LEN; k++)
            CHECK_EQ(a->reproposal_tx_hash[k], 0x32);

        printf("[ok] §7 two instances, identical REAL-signature cert set in "
               "opposite orders, both bound to the higher-view cert\n");

        free(a->server); free(a);
        free(b->server); free(b);
    }

    printf("PASS test_witness_c5_tiebreak\n");
    return 0;
}
