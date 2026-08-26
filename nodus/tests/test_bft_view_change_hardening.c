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
 *  P1 — a node whose round or view change never completes was trapped
 *       out of consensus FOREVER. handle_propose refuses every proposal
 *       while the phase is not IDLE, and the only phase->IDLE reset on
 *       the remote-COMMIT path is gated on the round NUMBER matching —
 *       which a node left behind never does. handle_commit has no phase
 *       gate, so such a node keeps applying remote commits and its DB
 *       tip advances normally while its phase stays pinned. Observed on
 *       the 20-node rehearsal: three validators at DB tip 42 with
 *       round_state.block_height frozen at 36 and phase 5, rejecting
 *       every PROPOSE; the participating set fell below quorum and the
 *       chain halted permanently. §11 covers the release, its converse,
 *       and the height normalization that keeps the release from
 *       killing a view change joined from IDLE.
 *
 *  P2 — a COMPLETED view change returned the node to IDLE with NO timer
 *       armed, and check_timeout returns at its first branch from IDLE.
 *       So a rotation onto a leader that is dead or simply silent left
 *       EVERY node waiting forever: nothing re-initiates, and only the
 *       leader leaves IDLE on its own (nodus_witness.c:1153-1162). The
 *       chain halts with no recovery path — the observed 20-node
 *       terminal state. §12 covers the arm, the fire, both converses,
 *       the leader exclusion (which is TWO separate guards), the
 *       NEW_VIEW re-arm/disarm rule on both the view-ADVANCE path and
 *       the self-advanced `==` path, and the PROPOSE disarm.
 *
 *  P3 — P2 only ever arms in the AFTERMATH of a completed view change,
 *       and the 20-node terminal state had no view change at all.
 *       `leader = (epoch + view) % n` with `epoch = height /
 *       DNAC_EPOCH_LENGTH` gives ONE node an entire epoch — 720 heights
 *       in production — and only the leader leaves IDLE on its own. So
 *       when the EPOCH leader died, every node sat IDLE at view 0 and
 *       nothing ever asked for a rotation: height 43 of that run
 *       recorded zero consensus events of any kind. P3 is the missing
 *       spontaneous initiation — a follower that holds work the chain is
 *       not consuming, with a committed tip that has not moved for a
 *       full round, asks for the next view. §13 covers the fire, both
 *       converses (no demand, and a moving tip), the leader exclusion,
 *       the P3(b) intake scope on legacy vs successor, and the P3(c)
 *       drain that had to stop wiping the demand this all rests on.
 *
 * Fixture style follows test_bft_liveness.c: heap witness (multi-MB),
 * real ML-DSA-87 keys so PREVOTE cert_sig verification is the production
 * check rather than a stub.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_db.h"   /* §11 — block_add / block_height,
                                         * §13 — nullifier_add / _exists   */
#include "witness/nodus_witness_peer.h" /* §13 — handle_fwd_req            */
#include "witness/nodus_witness_v2_gate.h" /* §13e2 — ingress_is_armed     */
#include "witness/nodus_witness_vset.h"
/* §13e3 — the successor-chain fixture (test_v2_claim_ingress.c's shape). */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
#include "nodus/nodus_chain_config.h"
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
#include "dnac/transaction.h"    /* §13e — DNAC_TX_HEADER_SIZE  */
#include "dnac/manifest_wire.h"  /* §13e3 — GenesisManifest + claim codec */
#include "dnac/domain_wire.h"    /* §13e3 — dna_domman_hash               */

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

/* ═══════════════════════════════════════════════════════════════════
 * §11 helpers — a fixture with a REAL committed tip.
 *
 * P1's whole trigger is nodus_witness_block_height(), which answers from
 * the chain DB (nodus_witness_db.c:785-821). The no-DB fixture above
 * therefore reports a tip of 0 forever, and EVERY P1 assertion made on
 * it would pass for the wrong reason: the release's `block_height != 0`
 * guard alone would carry it, with or without the code under test. §11
 * needs a DB, and needs the tip to be a number it chose.
 *
 * No vset snapshot is written here. With no committee rows the committee
 * gates take the documented pre-genesis roster fallback (F17 A5) —
 * exactly what §1-§5 rely on — so §11 varies the HEIGHT and nothing
 * else. Contrast §6, which exists to vary committee resolution.
 * ═══════════════════════════════════════════════════════════════════ */
static void chain_db_open(nodus_witness_t *w, char *dir_template, uint8_t tag)
{
    if (mkdtemp(dir_template) == NULL) {
        fprintf(stderr, "mkdtemp\n"); exit(1);
    }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_template);
    /* 16 bytes is the canonical chain_id width; set_chain_id
     * (nodus_witness.c:290-291) copies 16 and zero-fills to 32. */
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0) {
        fprintf(stderr, "chain db\n"); exit(1);
    }
}

static void chain_db_drop(nodus_witness_t *w, const char *dir) {
    nodus_witness_close(w);
    fixture_free(w);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* best effort cleanup */ }
}

/* Append `n` blocks through the PRODUCTION writer and return the tip it
 * produced. The tip is READ BACK rather than assumed: `blocks.height` is
 * INTEGER PRIMARY KEY AUTOINCREMENT (nodus_witness.c:97-98) and
 * nodus_witness_block_height answers from v2_blocks instead when
 * v2_successor is set, so a caller that computed the tip itself could
 * silently be testing against a tip of 0 — the one value that makes
 * every §11 assertion vacuous. Callers assert on the returned number. */
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
 * §12 helpers — O15I P2, the post-view-change PROPOSE-wait deadman.
 *
 * Every P2 assertion turns on WHO THE LEADER IS, and leadership here is
 * `(epoch + view) % n` against this node's SORTED rank in the roster
 * (nodus_witness_bft.c:494-509, the pre-genesis fallback these fixtures
 * take). Witness ids are SHA3-512 of freshly generated ML-DSA keys, so
 * that rank is DIFFERENT ON EVERY RUN. A hard-coded view would therefore
 * be a coin flip: the "leader" leg would silently become the "follower"
 * leg on ~6 runs in 7 and the suite would still print PASS.
 *
 * So the view is CHOSEN AT RUNTIME by asking the production predicate,
 * and every section then asserts the leadership it selected. That makes
 * the precondition a fact about THIS process instead of an assumption.
 * ═══════════════════════════════════════════════════════════════════ */

/* Lowest view > 0 at which nodus_witness_bft_is_leader answers
 * `want_leader`. `current_view` is restored before returning — probing
 * must not be an edit. Over v = 1..n the modulus visits every slot
 * exactly once, so both answers exist for any roster. */
static uint32_t p2_pick_view(nodus_witness_t *w, bool want_leader) {
    uint32_t saved = w->current_view;
    for (uint32_t v = 1; v <= w->roster.n_witnesses; v++) {
        w->current_view = v;
        bool is_l = nodus_witness_bft_is_leader(w);
        if (is_l == want_leader) {
            w->current_view = saved;
            return v;
        }
    }
    w->current_view = saved;
    fprintf(stderr, "p2_pick_view: no view with is_leader==%d\n",
            (int)want_leader);
    exit(1);
}

/* The peer that IS the leader at `view`. `all` must be in ROSTER ORDER
 * (the fixture appends self first, then the peers), and the leader SLOT
 * is resolved through nodus_witness_roster_sorted_at — never by indexing
 * witnesses[] with the slot, which is the exact confusion BUGS.md
 * 2026-08-04 records. */
static const peer_t *p2_leader_at(nodus_witness_t *w, const peer_t *all,
                                  uint32_t view) {
    uint64_t epoch = (nodus_witness_block_height(w) + 1) /
                     (uint64_t)DNAC_EPOCH_LENGTH;
    int slot = nodus_witness_bft_leader_index(epoch, view,
                                              (int)w->roster.n_witnesses);
    int arr = nodus_witness_roster_sorted_at(&w->roster, slot);
    if (arr < 0) { fprintf(stderr, "p2_leader_at: no slot %d\n", slot); exit(1); }
    return &all[arr];
}

/* Drive a view change all the way to QUORUM at `target`, using only
 * inbound peer messages — the production path, not a hand-set field.
 *
 * With quorum 3 the join threshold is 2 (bft_vc_join_threshold), so the
 * SECOND peer VIEW_CHANGE both raises the target and pulls us in via the
 * f+1 join; initiate_view_change then self-records, and its own tail
 * call to bft_vc_check_quorum sees 3/3 and completes. The post-condition
 * is asserted here so no §12 section can build on a view change that
 * quietly failed to complete. */
static void p2_complete_vc(nodus_witness_t *w, const peer_t *a,
                           const peer_t *b, uint32_t target) {
    nodus_t3_msg_t vc;
    fill_viewchg(&vc, w, a, target);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
          "first peer VIEW_CHANGE recorded");
    fill_viewchg(&vc, w, b, target);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
          "second peer VIEW_CHANGE recorded");
    CHECK(w->current_view == target,
          "view-change QUORUM completed — current_view advanced");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "and the completion put us back to IDLE (where nothing used "
          "to be armed)");
}

/* Push the deadman's ABSOLUTE deadline into the past. age_phase cannot
 * do this: the deadline lives on the witness, not in round_state, and it
 * is an absolute instant rather than a start stamp. */
static void p2_expire(nodus_witness_t *w) {
    w->awaiting_propose_deadline_ms = nodus_time_now() * 1000ULL - 1000ULL;
}

static void p2_fill_newview(nodus_t3_msg_t *m, nodus_witness_t *w,
                            const peer_t *from, uint32_t new_view) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_NEWVIEW;
    m->header.round = w->round_state.round;
    m->header.view = w->current_view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
    m->newview.new_view = new_view;
    m->newview.has_reproposal = false;
}

/* Attach a REAL prepared certificate: `n` distinct roster members sign
 * the same 76-byte purpose-0x07 preimage that
 * nodus_witness_bft_verify_prepared_cert rebuilds. Signing it for real
 * matters — the has_reproposal branch of handle_newview is fail-closed,
 * so a stubbed cert would make every "re-arm" assertion vacuous by
 * never reaching the accept at all. */
static void p2_add_reproposal(nodus_t3_msg_t *m, const peer_t *all, int n,
                              uint64_t height, uint32_t prep_view,
                              const uint8_t *tx_hash) {
    m->newview.has_reproposal = true;
    m->newview.reproposal_height = height;
    m->newview.reproposal_prepared_view = prep_view;
    memcpy(m->newview.reproposal_tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    m->newview.reproposal_n_sigs = (uint32_t)n;
    for (int i = 0; i < n; i++) {
        memcpy(m->newview.reproposal_sigs[i].voter_id, all[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        sign_prepared(m->newview.reproposal_sigs[i].signature, &all[i],
                      prep_view, height, tx_hash);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * §13 helpers — O15I P3, the demand-armed follower deadman.
 *
 * P3 reads the COMMITTED TIP on every armed tick, so §13 uses the §11 DB
 * fixture throughout for the reason §12 does: without a chain DB
 * nodus_witness_block_height answers 0 forever, the epoch the leader
 * arithmetic uses is pinned at 0, and — worse for this section — the tip
 * could never be made to MOVE, which is the whole subject of §13c.
 * ═══════════════════════════════════════════════════════════════════ */

/* A heap mempool entry. `tag` seeds tx_hash AND the nullifiers, so an
 * entry's nullifier is derivable from its tag and a test can commit it.
 * `n_nul == 0` builds the successor-envelope shape: an entry the
 * committed-nullifier predicate has nothing to say about. */
static nodus_witness_mempool_entry_t *p3_mkentry(uint8_t tag, uint64_t fee,
                                                 int n_nul) {
    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { fprintf(stderr, "p3 entry alloc\n"); exit(1); }
    memset(e->tx_hash, tag, NODUS_T3_TX_HASH_LEN);
    e->tx_type = NODUS_W_TX_SPEND;
    e->nullifier_count = (uint8_t)n_nul;
    for (int i = 0; i < n_nul; i++)
        memset(e->nullifiers[i], (uint8_t)(tag + i), NODUS_T3_NULLIFIER_LEN);
    e->tx_len = 8;
    e->tx_data = calloc(1, e->tx_len);
    if (!e->tx_data) { fprintf(stderr, "p3 tx_data alloc\n"); exit(1); }
    e->fee = fee;
    return e;
}

/* Pool an entry and assert it landed — a silent -1 (full / duplicate)
 * would leave the mempool empty and make every "it fired" assertion
 * below fail for a reason that has nothing to do with P3. */
static void p3_pool(nodus_witness_t *w, nodus_witness_mempool_entry_t *e) {
    int before = w->mempool.count;
    if (nodus_witness_mempool_add(&w->mempool, e) != 0 ||
        w->mempool.count != before + 1) {
        fprintf(stderr, "p3_pool: mempool_add rejected the fixture entry\n");
        exit(1);
    }
}

/* The nullifier p3_mkentry(tag, ...) put in slot 0. */
static void p3_nul_of(uint8_t tag, uint8_t out[NODUS_T3_NULLIFIER_LEN]) {
    memset(out, tag, NODUS_T3_NULLIFIER_LEN);
}

/* Push the demand window's start `age_ms` into the past. age_phase cannot
 * do this: the window lives on the witness (last_seen_tip / tip_since_ms),
 * not in round_state, and it is P3's clock rather than the round's.
 * time_ms() is nodus_time_now()*1000 — ONE-SECOND resolution — so every
 * age used here is a whole number of seconds. */
static void p3_age_window(nodus_witness_t *w, uint64_t age_ms) {
    w->tip_since_ms = nodus_time_now() * 1000ULL - age_ms;
}

/* Was `stamp` written during this test tick? The one-second clock means
 * a stamp taken moments ago reads as `now` or, across a second boundary,
 * `now - 1000`. Mirrors the §12a phase-clock assertion. */
static bool p3_stamped_now(uint64_t stamp) {
    return stamp != 0 && stamp >= nodus_time_now() * 1000ULL - 1000ULL;
}

/* ═══════════════════════════════════════════════════════════════════
 * §13e3 fixture — a REAL successor chain carrying an ADMISSIBLE entry.
 *
 * WHY THIS EXISTS AT ALL. §13e2 below proves a successor non-leader
 * pools NOTHING that fails admission — but that is a NEGATIVE, and both
 * the old leader-only gate and the new admission gate answer -1 for
 * bytes admission would refuse. §13e2 therefore does NOT fail if the
 * P3(b) intake change is reverted. Only POOLING can distinguish them,
 * and pooling requires an entry that genuinely passes the successor
 * ADMISSION lane. Hence a real V2 successor chain.
 *
 * THE SHAPE IS test_v2_claim_ingress.c's, deliberately unchanged: a
 * present-distribution GenesisManifest over the REAL registry domain
 * manifests, with a 3-leaf CORE-native snapshot, so a class-201 CLAIM is
 * admissible. Every ordering hazard in that sequence is load-bearing and
 * already resolved there —
 *   supply + CORE utxo  BEFORE  the registry commits genesis roots,
 *   validator rows + vset snapshot BEFORE domreg_init_genesis (they feed
 *   the SYSTEM payload root that genesis re-derives and BYTE-COMPARES),
 * — so it is reproduced rather than re-derived.
 *
 * ONE DEVIATION, and it is in the safe direction: the validator set is
 * seeded from THIS file's own ML-DSA-87 peers rather than from separate
 * deterministic keys, so the committee and the gossip roster are the
 * same seven identities. That is what lets p2_pick_view keep working —
 * it probes nodus_witness_bft_is_leader over v = 1..roster.n_witnesses,
 * and a fixture whose committee and roster disagreed in SIZE could make
 * the probe miss a leader view entirely and exit(1).
 * ═══════════════════════════════════════════════════════════════════ */

#define P3C_LEAVES 3

typedef struct {
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];
    uint8_t  manifest_hash[64];
    uint8_t  leaf_pk[P3C_LEAVES][QGP_DSA87_PUBLICKEYBYTES];
    uint8_t  leaf_sk[P3C_LEAVES][QGP_DSA87_SECRETKEYBYTES];
    dna_dist_leaf_t leaf[P3C_LEAVES];
    uint8_t  leaf_hash[P3C_LEAVES][64];
    uint8_t  snapshot_root[64];
} p3c_chain_t;

/* CORE's native asset is the all-zero token id. */
static const uint8_t p3c_native_asset[64] = {0};

/* conv 3/2 FLOOR: 10->15, 5->7, 7->10; Σ = 32 = total_claimable. */
static const uint64_t p3c_src_amount[P3C_LEAVES] = { 10, 5, 7 };
static const char *p3c_src_id[P3C_LEAVES] = {
    "src-alpha", "src-beta", "src-gamma"
};

static void p3c_die(const char *what) {
    fprintf(stderr, "p3c fixture: %s\n", what);
    exit(1);
}

static void p3c_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    if (rc != SQLITE_OK) p3c_die("seed SQL");
}

/* genesis(1000) = CORE utxo(968) + unclaimed distribution(32). The utxo
 * row is what the CORE supply invariant balances against; without it
 * genesis refuses its own manifest. */
static void p3c_seed_supply(nodus_witness_t *w) {
    p3c_sql(w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "total_minted, current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, 1000, 0, 0, 968, x'00', 0)");
    p3c_sql(w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (zeroblob(63)||x'01', 'genesis', 968, zeroblob(64), "
        "zeroblob(63)||x'aa', 0, 0, 0, 0, 1)");
}

/* self_stake MUST be 0: the CORE supply invariant counts Σ self_stake,
 * so a bonded validator would unbalance the seeded supply above. The
 * fingerprint is 128 lowercase hex chars + NUL — the validator merkle
 * leaf loader fails CLOSED on a malformed row, and that would take the
 * SYSTEM payload root (and therefore genesis) down with it. */
static void p3c_seed_validators(nodus_witness_t *w, const peer_t *all,
                                int n) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, all[i].pk, DNAC_PUBKEY_SIZE);
        v.self_stake         = 0;
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        uint8_t fpr[64];
        if (qgp_sha3_512(all[i].pk, DNAC_PUBKEY_SIZE, fpr) != 0)
            p3c_die("validator fingerprint");
        for (int b = 0; b < 64; b++) {
            v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
            v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
        }
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(w, &v) != 0)
            p3c_die("validator insert");
    }
}

/* Deterministic distribution leaves + the snapshot root the manifest
 * commits. dna_dist_check_totals is asserted here rather than trusted:
 * a conversion that did not total 32 would be refused at genesis, and
 * the failure would surface as an unexplained genesis error. */
static void p3c_leaves_init(p3c_chain_t *cx) {
    for (int i = 0; i < P3C_LEAVES; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x90 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(cx->leaf_pk[i], cx->leaf_sk[i],
                                     seed) != 0)
            p3c_die("leaf keygen");
        memset(&cx->leaf[i], 0, sizeof(cx->leaf[i]));
        cx->leaf[i].leaf_version  = DNA_DIST_VERSION;
        cx->leaf[i].source_id_len = (uint16_t)strlen(p3c_src_id[i]);
        memcpy(cx->leaf[i].source_id, p3c_src_id[i],
               cx->leaf[i].source_id_len);
        cx->leaf[i].source_amount = p3c_src_amount[i];
        if (qgp_sha3_512(cx->leaf_pk[i], QGP_DSA87_PUBLICKEYBYTES,
                         cx->leaf[i].dest_binding) != 0)
            p3c_die("leaf dest binding");
        if (dna_dist_leaf_hash(&cx->leaf[i], cx->leaf_hash[i]) != 0)
            p3c_die("leaf hash");
    }
    if (dna_dist_snapshot_root(cx->leaf, P3C_LEAVES,
                               cx->snapshot_root) != 0)
        p3c_die("snapshot root");
    if (dna_dist_check_totals(cx->leaf, P3C_LEAVES, 3, 2,
                              DNA_DISTROUND_FLOOR, 32) != 0)
        p3c_die("distribution totals");
}

static void p3c_build_manifest(nodus_witness_t *w, p3c_chain_t *cx,
                               uint8_t *out, size_t cap, size_t *out_len) {
    dna_domain_manifest_t dm;
    /* Zeroed so no -Wmaybe-uninitialized path exists: p3c_die exits, but
     * a compiler that has not inferred that still sees the memcpys. */
    uint8_t sys_h[64] = {0}, core_h[64] = {0};
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &dm, NULL) != 0 ||
        dna_domman_hash(&dm, sys_h) != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &dm, NULL) != 0 ||
        dna_domman_hash(&dm, core_h) != 0)
        p3c_die("registry manifest hashes");

    dna_gman_t m;
    memset(&m, 0, sizeof(m));
    m.manifest_version   = DNA_GMAN_VERSION;
    m.genesis_supply_raw = 1000;
    m.domain_count       = 2;
    m.domains[0].domain_id = DNA_DOMAIN_SYSTEM;
    memcpy(m.domains[0].manifest_hash, sys_h, 64);
    m.domains[1].domain_id = DNA_DOMAIN_CORE;
    memcpy(m.domains[1].manifest_hash, core_h, 64);

    m.dist_present       = 1;
    m.dist_version       = DNA_DIST_VERSION;
    m.target_domain_id   = DNA_DOMAIN_CORE;
    m.target_asset_len   = 64;
    memcpy(m.target_asset_ref, p3c_native_asset, 64);
    m.source_tag_len     = (uint16_t)strlen("testnet-generic");
    memcpy(m.source_tag, "testnet-generic", m.source_tag_len);
    m.source_commit_len  = 16;
    memset(m.source_commit, 0x77, 16);
    memcpy(m.snapshot_root, cx->snapshot_root, 64);
    m.leaf_count         = P3C_LEAVES;
    m.conv_numerator     = 3;
    m.conv_denominator   = 2;
    m.rounding_mode      = DNA_DISTROUND_FLOOR;
    m.excluded_amount    = 4;
    m.total_claimable    = 32;
    m.claim_start_height = 1;
    m.claim_end_height   = 1000000;
    m.auth_mode          = DNA_CLAIMAUTH_DNA_NATIVE;
    m.fee_mode           = DNA_CLAIMFEE_NONE;
    m.post_deadline_mode = DNA_POSTDL_RETAIN;

    if (dna_gman_hash(&m, cx->manifest_hash) != 0 ||
        dna_gman_encode(&m, out, cap, out_len) != 0)
        p3c_die("genesis manifest encode");
}

/* Turn the §11 legacy fixture's open DB into a committed V2 SUCCESSOR
 * chain. Call order is the load-bearing part; see the block comment. */
static void p3c_make_successor(nodus_witness_t *w, const peer_t *all, int n,
                               p3c_chain_t *cx) {
    /* ⚠ The two shipped V2 fixtures (test_v2_produce.c, and
     * test_v2_claim_ingress.c) both commit genesis with w->server still
     * NULL and attach the identity afterwards. This fixture inherits a
     * server from fixture() because is_leader needs one, so the pointer
     * is parked across the genesis call — the sequence that is proven to
     * work is reproduced exactly rather than assumed to be insensitive
     * to it. */
    struct nodus_server *saved_srv = w->server;
    w->server = NULL;

    if (nodus_chain_config_db_migrate(w) != 0) p3c_die("cc migrate");
    if (nodus_witness_db_migrate_v2s9(w) != 0) p3c_die("v2s9 migrate");

    p3c_seed_supply(w);
    p3c_seed_validators(w, all, n);
    if (nodus_witness_vset_commit_genesis(w, 1) != 0)
        p3c_die("vset genesis");
    if (nodus_witness_domreg_init_genesis(w) != 0)
        p3c_die("domreg genesis");

    p3c_leaves_init(cx);

    uint8_t mbytes[8192];
    size_t mlen = 0;
    p3c_build_manifest(w, cx, mbytes, sizeof(mbytes), &mlen);

    /* Genesis binds validator_set_hash into the chain identity and the
     * engine requires it to EQUAL the committed epoch-0 authority, so
     * the COMMITTED hash is read back rather than chosen. */
    uint8_t vsh[DNA_VSET_HASH_LEN];
    memset(vsh, 0x77, sizeof(vsh));   /* never read unset — p3c_die exits */
    {
        dna_vset_snapshot_t *s0 = NULL;
        uint32_t sn = 0, sq = 0;
        if (nodus_witness_v2_epoch_authority_for_height(w, 0, &s0, &sn,
                                                        &sq) != 0 || !s0) {
            dna_vset_free(&s0);
            p3c_die("committed epoch-0 authority");
        }
        int hrc = dna_vset_hash(s0, vsh);
        dna_vset_free(&s0);
        if (hrc != 0) p3c_die("vset hash");
    }

    if (nodus_witness_v2_genesis_ex(w, NULL, vsh, 0, mbytes, mlen) != 0)
        p3c_die("v2 genesis");

    w->server = saved_srv;

    /* The PRODUCTION derivation of the chain id, not a hand-read blob. */
    if (nodus_witness_v2_chain_id(w, cx->chain_id) != 0)
        p3c_die("derived chain id");

    w->v2_successor = true;
    memcpy(w->v2_chain32, cx->chain_id, 32);
    w->v2_ingress_armed = true;
}

/* A signed, admissible claim on leaf `leaf`. Heap: dna_claim_t carries a
 * 2592-byte pubkey plus a 4627-byte signature plus the proof path. */
static dna_claim_t *p3c_make_claim(const p3c_chain_t *cx, int leaf) {
    dna_claim_t *c = calloc(1, sizeof(*c));
    if (!c) { p3c_die("claim alloc"); return NULL; }
    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, cx->chain_id, DNA_CHAIN_ID_LEN);
    memcpy(c->manifest_hash, cx->manifest_hash, 64);
    c->leaf_index    = (uint64_t)leaf;
    c->source_id_len = cx->leaf[leaf].source_id_len;
    memcpy(c->source_id, cx->leaf[leaf].source_id, c->source_id_len);
    c->source_amount = cx->leaf[leaf].source_amount;
    memcpy(c->dest_binding, cx->leaf[leaf].dest_binding, 64);

    uint16_t ns = 0;
    if (dna_dist_proof_build((const uint8_t (*)[64])cx->leaf_hash,
                             P3C_LEAVES, (uint64_t)leaf, c->siblings,
                             &ns) != 0)
        p3c_die("claim proof");
    c->n_siblings = ns;
    c->auth_mode  = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(c->pubkey, cx->leaf_pk[leaf], QGP_DSA87_PUBLICKEYBYTES);

    uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
    size_t pre_len = 0;
    if (dna_claim_preimage(c, pre, &pre_len) != 0) p3c_die("claim preimage");
    size_t siglen = 0;
    if (qgp_dsa87_sign(c->signature, &siglen, pre, pre_len,
                       cx->leaf_sk[leaf]) != 0 || siglen != DNA_CLAIM_SIG_LEN)
        p3c_die("claim signature");
    return c;
}

/* The committed nullifier consensus derives for this claim — the same
 * value nodus_witness_v2_claim_entry_nullifier must record at intake. */
static void p3c_claim_nullifier(const dna_claim_t *c, uint8_t nul[64]) {
    dna_dist_leaf_t leaf;
    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version  = DNA_DIST_VERSION;
    leaf.source_id_len = c->source_id_len;
    memcpy(leaf.source_id, c->source_id, c->source_id_len);
    leaf.source_amount = c->source_amount;
    memcpy(leaf.dest_binding, c->dest_binding, 64);
    uint8_t lh[64];
    if (dna_dist_leaf_hash(&leaf, lh) != 0) p3c_die("claim leaf hash");
    if (dna_claim_nullifier(c->chain_id, c->manifest_hash, DNA_DOMAIN_CORE,
                            p3c_native_asset, 64, lh, nul) != 0)
        p3c_die("claim nullifier");
}

/* Canonical wire bytes + the SHA3-512 the admission lane demands as the
 * submitted tx_hash. Caller owns the buffer. */
static uint8_t *p3c_encode_claim(const dna_claim_t *c, size_t *out_len,
                                 uint8_t hash[64]) {
    size_t need = dna_claim_encoded_len(c);
    if (need == 0) p3c_die("claim encoded_len");
    uint8_t *b = malloc(need);
    if (!b) { p3c_die("claim wire alloc"); return NULL; }
    size_t wr = 0;
    if (dna_claim_encode(c, b, need, &wr) != 0 || wr != need)
        p3c_die("claim encode");
    if (qgp_sha3_512(b, wr, hash) != 0) p3c_die("claim wire hash");
    *out_len = wr;
    return b;
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

    /* ── §11 P1 — a round whose height the chain already committed is
     *            RELEASED, so the node can take the next proposal ──── */
    printf("§11 P1 — the moot-round release\n");
    {
        peer_t b, c; peer_make(&b); peer_make(&c);
        /* A quorum of 5 against a 3-node roster can never be met, so the
         * view change started below CANNOT complete. That matters: within
         * this section's closed world — no messages are delivered, only
         * check_timeout is called — bft_vc_check_quorum (bft.c:6933) is
         * the one OTHER reachable path back to IDLE, and the quorum puts
         * it structurally out of reach. So P1 is the only remaining
         * explanation for an IDLE phase at the end of this section.
         * (Globally there are more IDLE resets — the commit reset at
         * :6254-6257 and handle_newview's — but neither can fire here:
         * both need an inbound message.) */
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 5,
                                     15000, 10000);
        char dir[] = "/tmp/test_bft_p1_rel_XXXXXX";
        chain_db_open(w, dir, 0x11);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 — NONZERO, which is what "
                        "keeps this section from passing on the "
                        "`block_height != 0` guard alone");
        const uint64_t H = tip + 1;     /* the height this round decides */

        enter_round(w, &self, 6, H, tx_hash);
        age_phase(w, 16000);
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "round timeout moved the phase to VIEW_CHANGE");
        CHECK(w->view_change_in_progress && w->view_change_voted,
              "the view change is live and we voted");
        /* P1(a) IDEMPOTENCE. A round already anchored at tip+1 must come
         * back out of initiate_view_change unchanged; a normalization
         * that bumped unconditionally would push this to tip+2 and quietly
         * break every height-anchored check downstream. */
        CHECK(w->round_state.block_height == H,
              "P1(a) left an already-correct anchor alone (H, not H+1)");
        uint32_t view_before   = w->current_view;
        uint32_t target_before = w->view_change_target;

        /* The chain reaches H by some OTHER route — a remote COMMIT at a
         * round number we no longer match, or a SYNC. Neither resets our
         * phase: the reset at bft.c:6254-6257 requires the round numbers
         * to be EQUAL, and that is the whole trap. */
        CHECK(seed_blocks(w, 1) == H, "the chain committed height H");

        /* ONE tick, deliberately NOT aged. The view-change budget is
         * untouched (10 s, stamped a moment ago), so the escalation
         * branch cannot be what moves anything here. */
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "P1 released the moot round to IDLE — precisely the state "
              "handle_propose (bft.c:4503) demands before it will accept "
              "a proposal at all");
        CHECK(!w->view_change_in_progress,
              "view_change_in_progress cleared with it");
        CHECK(!w->view_change_voted,
              "and view_change_voted, so a later target can be voted for");
        /* ⚠ THE SAFETY ASSERTION. A release that also moved current_view
         * would be changing the leader without a quorum ever asking —
         * the one thing a liveness fix must not buy its liveness with. */
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");
        CHECK(w->view_change_target == target_before,
              "and the target is left for the record set to decide");

        chain_db_drop(w, dir);
    }

    /* ── §11b P1 converse — the release must not fire ONE BLOCK EARLY ─
     *
     * Identical to §11 except that the chain never reaches H. The two
     * sections differ by exactly one committed block, which is what pins
     * the trigger at `tip >= block_height` rather than at anything
     * looser. Without this leg a release that fired unconditionally
     * would pass §11 and destroy every view change in production. ── */
    printf("§11b P1 converse — no release while the height is still open\n");
    {
        peer_t b, c; peer_make(&b); peer_make(&c);
        nodus_witness_t *w = fixture(&self, (peer_t[]){b, c}, 2, 5,
                                     15000, 10000);
        char dir[] = "/tmp/test_bft_p1_conv_XXXXXX";
        chain_db_open(w, dir, 0x12);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (nonzero — see §11)");
        const uint64_t H = tip + 1;

        enter_round(w, &self, 6, H, tx_hash);
        age_phase(w, 16000);
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "round timeout moved the phase to VIEW_CHANGE");

        /* THE ONE DIFFERENCE: no block is added. */
        CHECK(nodus_witness_block_height(w) == H - 1,
              "the chain is still ONE block short of H");

        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "at tip == H-1 the view change SURVIVES the tick");
        CHECK(w->view_change_in_progress,
              "and is still in progress");
        CHECK(w->view_change_voted,
              "and our vote still stands");

        chain_db_drop(w, dir);
    }

    /* ── §11c P1(a) — a view change JOINED FROM IDLE survives the tick ─
     *
     * handle_viewchg has no phase gate, so its f+1 join can pull a node
     * in straight from IDLE. An IDLE node's round_state still carries the
     * height it LAST worked on — which is <= the committed tip — so
     * without the P1(a) normalization the joiner enters VIEW_CHANGE
     * already matching the release's condition and the very next tick
     * throws it back out. It would be silenced exactly as O15C-C D1
     * silenced it, one mechanism further along. ─────────────────────── */
    printf("§11c P1(a) — a view change joined from IDLE is not released\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        /* quorum 5 → join threshold 3. Three peer votes plus our own
         * self-record is 4, still short of 5 — so the view change stays
         * OPEN and P1 remains the only thing that could close it. */
        nodus_witness_t *w = fixture(&self, p, 6, 5, 15000, 10000);
        char dir[] = "/tmp/test_bft_p1_join_XXXXXX";
        chain_db_open(w, dir, 0x13);

        uint64_t T = seed_blocks(w, 3);
        CHECK(T == 3, "seeded chain tip is 3 (nonzero — see §11)");

        /* An IDLE node that JUST COMMITTED height T. The commit reset
         * (bft.c:6254-6257) puts the phase back to IDLE but leaves the
         * finished round's height in round_state — so block_height == T
         * == tip, which is exactly the shape the release matches. */
        memset(&w->round_state, 0, sizeof(w->round_state));
        w->round_state.round = 6;
        w->round_state.block_height = T;
        w->round_state.phase = NODUS_W_PHASE_IDLE;
        /* Stamp the clock fresh, so the ONLY thing that could move the
         * phase on the tick below is the P1 release. */
        w->round_state.phase_start_time = nodus_time_now() * 1000ULL;

        nodus_t3_msg_t vc;
        for (int i = 0; i < 3; i++) {
            fill_viewchg(&vc, w, &p[i], 1);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                  "peer VIEW_CHANGE at view 1 recorded");
        }
        CHECK(w->view_change_voted,
              "f+1 pulled us into the view change from IDLE");
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "and moved our phase to VIEW_CHANGE");

        /* ⚠ THE DISCRIMINATING ASSERTION. Pre-P1(a) the joiner keeps the
         * committed height T here, and `tip >= block_height` is already
         * true before it has said a word. */
        CHECK(w->round_state.block_height == T + 1,
              "P1(a) re-anchored the joined view change at tip+1");

        /* Re-stamp immediately before the tick. initiate_view_change does
         * NOT stamp the phase clock, and the adoption block only does so
         * when the phase is ALREADY VIEW_CHANGE (bft.c:6807-6808) — which
         * it was not, since we joined from IDLE. So the joiner inherits
         * whatever clock it had, and this test would otherwise be relying
         * on a 10 s margin instead of on a fact. With the stamp here the
         * escalation branch is unreachable BY CONSTRUCTION, and the P1
         * release is the only thing left that could move the phase. */
        w->round_state.phase_start_time = nodus_time_now() * 1000ULL;
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "the tick did NOT release the freshly joined view change");
        CHECK(w->view_change_in_progress && w->view_change_voted,
              "our vote at the joined target still stands");
        CHECK(w->current_view == 0,
              "and current_view never moved: only quorum advances it");

        chain_db_drop(w, dir);
    }

    /* ── §12 P2 — the post-view-change PROPOSE-wait deadman ──────────
     *
     * Every section below uses the §11 DB fixture. P2's fire site calls
     * nodus_witness_bft_is_leader on every armed tick and its arm site
     * calls it once per completed view change; both resolve a committee
     * from the chain DB before falling back to the roster, and
     * nodus_witness_block_height answers 0 forever without one — which
     * would pin the epoch at 0 and make the leader arithmetic a
     * different question from the one production asks. A roster of 7
     * (self + 6) gives the modulus every slot to land on. ────────────── */

    /* ── §12a — the deadman ARMS on a non-leader and FIRES ──────────── */
    printf("§12a P2 — a non-leader arms after the view change and fires\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        /* quorum 3 → join threshold 2, so two peer VIEW_CHANGEs plus our
         * own self-record complete the quorum exactly. */
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p2_fire_XXXXXX";
        chain_db_open(w, dir, 0x21);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 — a real committed tip, so "
                        "the epoch the leader arithmetic uses is the one "
                        "production would compute");

        uint32_t V = p2_pick_view(w, false);
        p2_complete_vc(w, &p[0], &p[1], V);
        CHECK(!nodus_witness_bft_is_leader(w),
              "we are NOT the new leader at the view we completed");

        /* THE ARM. Pre-P2 this field does not exist and the node sits
         * IDLE with nothing pending — the terminal state. */
        CHECK(w->awaiting_propose_deadline_ms != 0,
              "P2 armed the PROPOSE-wait deadman");

        uint32_t view_before = w->current_view;
        p2_expire(w);
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "the expired deadman initiated a view change from IDLE — "
              "the branch that used to be an unconditional dead end");
        CHECK(w->view_change_target == view_before + 1,
              "target is the ORDINARY current_view + 1 — P2 invents no "
              "target rule of its own");
        /* ⚠ THE SAFETY ASSERTION, the same one §11 makes: a liveness fix
         * must not buy liveness by moving the leader without a quorum. */
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");
        CHECK(w->view_change_in_progress && w->view_change_voted,
              "and we actually voted, so peers can count us");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "the spent deadline disarmed — it must not re-fire every tick");
        /* The D2 discipline: initiate_view_change does NOT stamp the
         * phase clock and the adoption block only stamps when the phase
         * is ALREADY VIEW_CHANGE (bft.c:6807-6808), so entering from
         * IDLE without a stamp here would leave the view change
         * measuring its age from a round that ended long ago and
         * escalating the target on the very next tick, forever. */
        CHECK(w->round_state.phase_start_time >=
                  nodus_time_now() * 1000ULL - 1000ULL,
              "the phase clock was re-stamped at the fire (D2 discipline)");

        chain_db_drop(w, dir);
    }

    /* ── §12b — the converse: it must NOT fire before the deadline ────
     *
     * Without this leg an UNCONDITIONAL fire would pass §12a and would
     * put the whole cluster into permanent view churn. ─────────────── */
    printf("§12b P2 converse — an unexpired deadman does not fire\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p2_conv_XXXXXX";
        chain_db_open(w, dir, 0x22);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");

        uint32_t V = p2_pick_view(w, false);
        p2_complete_vc(w, &p[0], &p[1], V);
        CHECK(w->awaiting_propose_deadline_ms != 0, "armed");
        uint64_t armed_at = w->awaiting_propose_deadline_ms;

        /* THE ONE DIFFERENCE FROM §12a: the deadline is not expired. */
        CHECK(armed_at > nodus_time_now() * 1000ULL,
              "the deadline is still in the FUTURE");

        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — no premature rotation");
        CHECK(w->awaiting_propose_deadline_ms == armed_at,
              "and the deadline is untouched, still counting down");
        CHECK(w->current_view == V,
              "current_view never moved");

        chain_db_drop(w, dir);
    }

    /* ── §12c — the LEADER is excluded, by TWO independent guards ─────
     *
     * The new leader's job is to SEND: it broadcasts NEW_VIEW and may
     * re-propose the retained bytes. A leader that armed would time out
     * against itself and rotate away from the view it was about to
     * serve. The exclusion is asserted at BOTH guards, because they fail
     * independently: the arm-side one in bft_vc_check_quorum, and the
     * fire-side one in check_timeout that catches a node which became
     * leader while already armed (IDENT view adoption,
     * nodus_witness_peer.c:783). ─────────────────────────────────────── */
    printf("§12c P2 — the new leader neither arms nor fires\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p2_leader_XXXXXX";
        chain_db_open(w, dir, 0x23);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");

        /* The ONLY difference from §12a: the view we complete is one at
         * which WE are the leader. */
        uint32_t V = p2_pick_view(w, true);
        p2_complete_vc(w, &p[0], &p[1], V);
        CHECK(nodus_witness_bft_is_leader(w),
              "we ARE the new leader at the view we completed");

        /* GUARD 1 — the arm site. */
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "the new leader did NOT arm the deadman");

        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "and an unarmed leader tick moves nothing");

        /* GUARD 2 — the fire site, reached only by force-arming. This is
         * a state the arm site cannot produce, but IDENT view adoption
         * can: it moves current_view under an IDLE node, so a node armed
         * as a follower can BECOME the leader while still armed. */
        p2_expire(w);
        CHECK(w->awaiting_propose_deadline_ms != 0,
              "force-armed and expired, standing in for a view adopted "
              "under us after we armed");
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "an EXPIRED deadman on the leader still does not fire — "
              "the leader must send, not rotate away from itself");
        CHECK(w->current_view == view_before,
              "current_view untouched");

        chain_db_drop(w, dir);
    }

    /* ── §12d — NEW_VIEW on the view-ADVANCE path: re-arm vs disarm ───
     *
     * Both legs PRE-ARM by hand, to a value chosen so that the wrong
     * branch cannot produce the expected answer:
     *   - re-arm leg starts from an ALREADY-EXPIRED deadline, so "still
     *     armed" is not enough — the assertion demands a FRESH window.
     *   - disarm leg starts from a FUTURE deadline, so only an actual
     *     write of 0 satisfies it.
     * Inverting the branch fails both. ──────────────────────────────── */
    printf("§12d P2 — NEW_VIEW re-arms when it binds a reproposal, "
           "disarms when it does not\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p2_nv_XXXXXX";
        chain_db_open(w, dir, 0x24);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");

        /* A view we do NOT lead — otherwise the sender could not be the
         * expected leader and the message would be refused at :7112. */
        uint32_t V = p2_pick_view(w, false);
        const peer_t *leader = p2_leader_at(w, all, V);
        CHECK(memcmp(leader->id, w->my_id, NODUS_T3_WITNESS_ID_LEN) != 0,
              "the NEW_VIEW's leader is someone else, as the accept "
              "path requires");

        /* ── LEG 1: has_reproposal = true → RE-ARM. */
        nodus_t3_msg_t nv;
        p2_fill_newview(&nv, w, leader, V);
        p2_add_reproposal(&nv, all, (int)w->bft_config.quorum, tip + 1, 0,
                          tx_hash);
        p2_expire(w);                       /* armed, ALREADY expired */
        CHECK(nodus_witness_bft_handle_newview(w, &nv) == 0,
              "NEW_VIEW carrying a verifiable prepared cert accepted");
        CHECK(w->current_view == V,
              "and it advanced the view (the `>` accept really ran)");
        CHECK(w->reproposal_required,
              "the C5 binding is set — a PROPOSE is now MANDATORY, and "
              "handle_propose refuses every other one at this height");
        /* THE ASSERTION: a FULL FRESH window, not the expired value we
         * started from. The binding is released only by a matching
         * PROPOSE or by the chain reaching its height
         * (nodus_witness.c:1141-1152) — and in a halt the chain reaches
         * nothing, so without this re-arm the node wedges silently. */
        CHECK(w->awaiting_propose_deadline_ms > nodus_time_now() * 1000ULL,
              "P2 RE-ARMED with a fresh window for the bound PROPOSE");

        /* ── LEG 2: has_reproposal = false → DISARM. A second, higher
         * view so the `>` accept runs again. */
        w->reproposal_required = false;
        uint32_t V2 = 0;
        for (uint32_t v = V + 1; v <= V + w->roster.n_witnesses; v++) {
            uint32_t saved = w->current_view;
            w->current_view = v;
            bool is_l = nodus_witness_bft_is_leader(w);
            w->current_view = saved;
            if (!is_l) { V2 = v; break; }
        }
        CHECK(V2 > V, "found a higher view we do not lead");
        const peer_t *leader2 = p2_leader_at(w, all, V2);

        p2_fill_newview(&nv, w, leader2, V2);   /* has_reproposal = false */
        w->awaiting_propose_deadline_ms =
            nodus_time_now() * 1000ULL + 60000ULL;   /* FUTURE */
        CHECK(nodus_witness_bft_handle_newview(w, &nv) == 0,
              "NEW_VIEW with no reproposal accepted");
        CHECK(w->current_view == V2, "and it advanced the view again");
        CHECK(!w->reproposal_required, "no C5 binding was set");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "P2 DISARMED — the leader proved liveness and owes nothing, "
              "so a demand-driven stall is a different mechanism's job");

        chain_db_drop(w, dir);
    }

    /* ── §12e — the SELF-ADVANCED path, which is the COMMON one ───────
     *
     * O15C-D.1 measured that every node advances its own view the moment
     * it reaches view-change quorum (bft.c:6900), so when the leader's
     * NEW_VIEW finally arrives `new_view == current_view` and the whole
     * `>` accept block of §12d is a silent no-op — 7/7 nodes
     * self-advanced with ZERO logged "accepted NEW_VIEW"
     * (bft.c:6910-6927).
     *
     * ⚠ SO §12d ALONE PROVES NOTHING ABOUT PRODUCTION. If the disarm
     * lived only in the accept block, a self-advanced follower would arm
     * at the quorum, receive the live leader's NEW_VIEW, never disarm,
     * and on a quiet chain (no mempool → no PROPOSE is due) fire after
     * one window → rotate → arm again: permanent view churn behind a
     * perfectly healthy leader. This section is that path. ──────────── */
    printf("§12e P2 — a NEW_VIEW at our OWN view disarms; a bound one "
           "does not extend the window\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p2_nveq_XXXXXX";
        chain_db_open(w, dir, 0x25);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");

        uint32_t V = p2_pick_view(w, false);
        const peer_t *leader = p2_leader_at(w, all, V);

        /* Reach V through the PRODUCTION quorum path, exactly as the
         * live cluster does — which is what makes new_view == current_view
         * when the leader's message lands. */
        p2_complete_vc(w, &p[0], &p[1], V);
        CHECK(w->awaiting_propose_deadline_ms != 0,
              "self-advancing to V armed us");
        uint64_t armed_at = w->awaiting_propose_deadline_ms;

        /* ── LEG 1: has_reproposal = false at `==` → DISARM. */
        nodus_t3_msg_t nv;
        p2_fill_newview(&nv, w, leader, V);
        CHECK(nv.newview.new_view == w->current_view,
              "the NEW_VIEW names the view we ALREADY advanced to — the "
              "measured common case, where the `>` accept never runs");
        CHECK(nodus_witness_bft_handle_newview(w, &nv) == 0,
              "the NEW_VIEW is accepted");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "P2 disarmed on the SELF-ADVANCED path — without this the "
              "healthy-leader case churns views forever");

        /* ── LEG 2: has_reproposal = true at `==` → LEAVE ALONE. We
         * already armed a full window against this same leader at the
         * quorum. Re-arming here would be exploitable: this handler has
         * no replay guard, so a peer replaying one stored NEW_VIEW per
         * window could postpone the deadman indefinitely. */
        w->awaiting_propose_deadline_ms = armed_at;
        p2_fill_newview(&nv, w, leader, V);
        p2_add_reproposal(&nv, all, (int)w->bft_config.quorum, tip + 1, 0,
                          tx_hash);
        CHECK(!w->reproposal_required,
              "no binding yet — leg 1 carried none, so leg 2's effect on "
              "this field is unambiguous");
        CHECK(nodus_witness_bft_handle_newview(w, &nv) == 0,
              "a bound NEW_VIEW at our own view is accepted");
        /* ⚠ ANTI-VACUITY. "The deadline did not change" is ALSO what a
         * message REJECTED upstream would leave behind, and every
         * rejection path here returns before the P2 code. The `==`
         * adoption block (bft.c:7221-7226) is the one thing that only a
         * validated, bound NEW_VIEW at our own view can set — so this
         * assertion is what separates "processed, and the timer was
         * deliberately left alone" from "bounced before P2 was ever
         * reached". */
        CHECK(w->reproposal_required,
              "the bound NEW_VIEW really was processed at `==` (its cert "
              "verified and the C5 adoption ran)");
        CHECK(w->awaiting_propose_deadline_ms == armed_at,
              "the deadline is EXACTLY as it was — not extended, not "
              "cleared: a replay must not postpone the deadman");

        chain_db_drop(w, dir);
    }

    /* ── §12f — an accepted PROPOSE disarms ──────────────────────────
     *
     * The PROPOSE is what the deadman was waiting for, so its arrival
     * ends the wait. The disarm sits at the follower's round entry
     * (bft.c:4620-4640), which runs BEFORE the batch's TX contents are
     * validated — so a batch this fixture cannot make valid still proves
     * the point, and the section stays about the ROUND ENTRY rather than
     * about transaction validity. Reaching PREVOTE at all means the
     * proposal passed the leader check, the height check and the C5
     * gate. ─────────────────────────────────────────────────────────── */
    printf("§12f P2 — an accepted PROPOSE disarms the deadman\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p2_prop_XXXXXX";
        chain_db_open(w, dir, 0x26);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");

        uint32_t V = p2_pick_view(w, false);
        const peer_t *leader = p2_leader_at(w, all, V);
        w->current_view = V;

        /* Armed AND already expired, deliberately: this is the state in
         * which a missing disarm is not merely untidy but live — the
         * very next IDLE tick would rotate the view away from a leader
         * that just proved itself by proposing. */
        p2_expire(w);

        uint8_t ptx[NODUS_T3_TX_HASH_LEN];
        memset(ptx, 0xD2, sizeof(ptx));

        nodus_t3_msg_t pm;
        memset(&pm, 0, sizeof(pm));
        pm.type = NODUS_T3_PROPOSE;
        pm.header.round = 9;
        pm.header.view = V;
        memcpy(pm.header.sender_id, leader->id, NODUS_T3_WITNESS_ID_LEN);
        memcpy(pm.header.chain_id, w->chain_id, sizeof(pm.header.chain_id));
        pm.header.timestamp = nodus_time_now();
        nodus_random((uint8_t *)&pm.header.nonce, sizeof(pm.header.nonce));
        pm.propose.batch_count = 1;
        pm.propose.block_height = tip + 1;
        memcpy(pm.propose.batch_txs[0].tx_hash, ptx, NODUS_T3_TX_HASH_LEN);
        pm.propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
        /* tx_root is SHA3-512 over the batch's tx_hashes, the same
         * derivation handle_propose recomputes (bft.c:4657-4672). */
        {
            nodus_key_t bh;
            if (nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) != 0) {
                fprintf(stderr, "tx_root hash\n"); exit(1);
            }
            memcpy(pm.propose.tx_root, bh.bytes, NODUS_T3_TX_HASH_LEN);
        }

        CHECK(nodus_witness_bft_handle_propose(w, &pm) == 0,
              "the leader's PROPOSE was accepted into a round");
        CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
              "we entered PREVOTE — the round-entry path the disarm "
              "sits on really ran");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "P2 disarmed: the PROPOSE the deadman waited for arrived");

        chain_db_drop(w, dir);
    }

    /* ── §13 P3 — the DEMAND-ARMED follower deadman ───────────────────
     *
     * P2 (§12) only ever arms in the aftermath of a COMPLETED view
     * change. The 20-node terminal state had NO view change at all:
     * `leader = (epoch + view) % n` with `epoch = height /
     * DNAC_EPOCH_LENGTH` gives one node an entire epoch (720 heights in
     * production), only the leader leaves IDLE on its own, and so with
     * that leader dead every node sat IDLE at view 0 while height 43
     * recorded zero consensus events of any kind. P3 is the spontaneous
     * initiation that was missing.
     *
     * EVERY SECTION BELOW ASSERTS awaiting_propose_deadline_ms == 0
     * BEFORE THE TICK. Without that, a VIEW_CHANGE observed after the
     * tick could have come from P2's fire site, and §13 would be
     * measuring the section above it. ───────────────────────────────── */

    /* ── §13a — demand + a frozen tip rotates the view ───────────────── */
    printf("§13a P3 — a follower with pending demand and a frozen tip "
           "initiates a view change\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_fire_XXXXXX";
        chain_db_open(w, dir, 0x31);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 — a real committed tip, so "
                        "the frozen-tip test below is about a number this "
                        "test chose rather than about an absent DB");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w),
              "we are NOT the leader at the view under test");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "P2 is NOT armed — any rotation below is attributable to P3");

        p3_pool(w, p3_mkentry(0x71, 100, 1));
        CHECK(w->mempool.count == 1, "one pending entry — this node has "
                                     "demand the leader is not serving");

        /* TICK 1 — the FIRST observation may only ARM. A node that has
         * just noticed a frozen tip has not yet waited for anything. */
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the first observation arms the window; it does not fire");
        CHECK(w->last_seen_tip == tip,
              "and it recorded the REAL committed tip, not a guess");
        CHECK(p3_stamped_now(w->tip_since_ms),
              "the window is now running");

        /* TICK 2 — the same tip, one full round_timeout_ms later. */
        p3_age_window(w, 16000);
        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "the expired demand window initiated a view change from "
              "IDLE — the state in which 20 nodes previously sat forever");
        CHECK(w->view_change_target == view_before + 1,
              "target is the ORDINARY current_view + 1 — P3 invents no "
              "target rule of its own");
        /* ⚠ THE SAFETY ASSERTION, the same one §11 and §12a make: a
         * liveness fix must not buy liveness by moving the leader
         * without a quorum. */
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");
        CHECK(w->view_change_in_progress && w->view_change_voted,
              "and we actually voted, so peers can count us toward f+1");
        CHECK(p3_stamped_now(w->round_state.phase_start_time),
              "the phase clock was re-stamped at the fire (D2 discipline: "
              "initiate_view_change does not stamp it, and the adoption "
              "stamp only fires from an ALREADY-VIEW_CHANGE phase)");
        CHECK(p3_stamped_now(w->tip_since_ms),
              "the demand window was re-stamped too — a second rotation "
              "must wait another full window, not fire on the next tick");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13b — NO demand, so it never fires ─────────────────────────
     *
     * The anti-churn property, and the reason P3 is safe to run on every
     * IDLE tick of every node. A quiet chain's tip is frozen by
     * definition; without the demand gate this section's aged window
     * would rotate the view, and 20 healthy nodes would churn views
     * forever. Delete the gate and this section fails. ─────────────── */
    printf("§13b P3 converse — no demand, no rotation, ever\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_quiet_XXXXXX";
        chain_db_open(w, dir, 0x32);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0, "P2 is NOT armed");
        CHECK(w->mempool.count == 0 && w->pending_forward_count == 0,
              "and there is NOTHING pending — a quiet, healthy chain");

        /* THE ONE DIFFERENCE FROM §13a: no entry. The window is aged
         * BY HAND to exactly the state §13a fired from, so the only
         * thing that can stop the rotation is the demand gate. */
        w->last_seen_tip = tip;
        p3_age_window(w, 16000);
        uint64_t aged = w->tip_since_ms;
        CHECK(aged != 0 && aged + w->bft_config.round_timeout_ms <
                               nodus_time_now() * 1000ULL,
              "the window is force-aged well past round_timeout_ms — "
              "§13a fired from exactly this much elapsed time");

        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — a quiet chain never rotates");
        /* ⚠ THIS is the assertion that makes the section discriminating,
         * not the IDLE one above it. Delete only the OUTER demand gate
         * and bft_p3_live_demand still answers false on an empty pool,
         * so "still IDLE" would survive — but the would-fire path
         * re-stamps the window to NOW rather than clearing it, so this
         * line fails in exactly that world. */
        CHECK(w->tip_since_ms == 0,
              "and the window was DISARMED rather than aged further — "
              "demand arriving later gets a full fresh window, so the "
              "leader is never rotated away from on its first block");
        CHECK(!w->view_change_in_progress,
              "no view change was started");

        chain_db_drop(w, dir);
    }

    /* ── §13c — a MOVING tip never fires ─────────────────────────────
     *
     * The other half of the conjunction. Without the tip comparison a
     * busy chain would rotate away from a leader that is producing
     * perfectly well, once per round_timeout_ms, purely because its
     * mempool is never empty. ──────────────────────────────────────── */
    printf("§13c P3 converse — a chain that is ADVANCING never rotates\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_moving_XXXXXX";
        chain_db_open(w, dir, 0x33);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0, "P2 is NOT armed");

        p3_pool(w, p3_mkentry(0x73, 100, 1));
        nodus_witness_bft_check_timeout(w);
        CHECK(w->last_seen_tip == 3, "the window is anchored at tip 3");

        /* Age it to exactly §13a's firing state, then let the chain do
         * the one thing that proves the leader is alive. */
        p3_age_window(w, 16000);
        uint64_t moved = seed_blocks(w, 1);
        CHECK(moved == 4, "the chain ADVANCED inside the window");

        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — demand alone is not a stall");
        CHECK(w->last_seen_tip == 4,
              "the observation followed the chain to the new tip");
        CHECK(p3_stamped_now(w->tip_since_ms),
              "and the window RESTARTED from the advance, so the next "
              "rotation would need a full further round of silence");
        CHECK(!w->view_change_in_progress, "no view change was started");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13d — the LEADER is excluded ───────────────────────────────
     *
     * A leader with demand and a frozen tip is the node that should be
     * PRODUCING, and the tick's block timer is about to make it do so.
     * If it rotated instead it would time out against itself and hand
     * the epoch to someone else on every block.
     *
     * The vacuity trap here is real: "still IDLE" is also what a node
     * that never reached the decision looks like. So the section also
     * asserts that the would-fire point WAS reached, by checking that
     * the window it aged came back re-stamped. ─────────────────────── */
    printf("§13d P3 — the leader evaluates and declines; it never rotates "
           "away from itself\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_leader_XXXXXX";
        chain_db_open(w, dir, 0x34);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        /* The ONLY difference from §13a: a view at which WE lead. */
        w->current_view = p2_pick_view(w, true);
        CHECK(nodus_witness_bft_is_leader(w),
              "we ARE the leader at the view under test");
        CHECK(w->awaiting_propose_deadline_ms == 0, "P2 is NOT armed");

        p3_pool(w, p3_mkentry(0x74, 100, 1));
        nodus_witness_bft_check_timeout(w);
        CHECK(w->last_seen_tip == tip, "the window is anchored at the tip");

        p3_age_window(w, 16000);
        uint64_t aged = w->tip_since_ms;
        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "an EXPIRED window on the leader does not fire — the leader "
              "must produce, not rotate");
        CHECK(w->current_view == view_before, "current_view untouched");
        CHECK(!w->view_change_in_progress, "no view change was started");
        /* ⚠ THE ANTI-VACUITY ASSERTION. Had the tick bailed before the
         * decision — wrong branch, missing demand, unread tip — the
         * window would still hold the hand-aged value. It does not, so
         * the leader test is provably what stopped the rotation. */
        CHECK(w->tip_since_ms != aged && p3_stamped_now(w->tip_since_ms),
              "the would-fire point WAS reached and re-stamped: the "
              "leader check is what declined, not an earlier bail-out");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13e — P3(b) INTAKE: who may pool a forwarded entry ─────────
     *
     * A forwarded transaction used to reach the leader and NOWHERE else,
     * which is why a dead leader stalls the chain: the demand exists on
     * exactly one node, and one is far below the f+1 join threshold.
     *
     * LEGACY IS UNCHANGED, and this section pins that to the LEADERSHIP
     * TEST rather than to input validity: the identical bytes are
     * offered twice, differing only in the view — and therefore only in
     * whether this node is the leader. A reject that came from the wire
     * layout instead would refuse both. ─────────────────────────────── */
    printf("§13e P3(b) — the legacy forward gate is still leader-only, "
           "byte-identically\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_legacy_XXXXXX";
        chain_db_open(w, dir, 0x35);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor,
              "this fixture is a LEGACY chain — the lane P3(b) must leave "
              "exactly as it found it");

        /* A structurally valid legacy SPEND: header, then one input of
         * nullifier(64) + amount(8) + token_id(64), which is what the
         * legacy nullifier walk in handle_fwd_req reads. */
        uint8_t ltx[DNAC_TX_HEADER_SIZE + 1 + 136];
        memset(ltx, 0, sizeof(ltx));
        ltx[1] = NODUS_W_TX_SPEND;
        ltx[DNAC_TX_HEADER_SIZE] = 1;                  /* input_count */
        memset(ltx + DNAC_TX_HEADER_SIZE + 1, 0x7E, NODUS_T3_NULLIFIER_LEN);

        uint8_t lhash[NODUS_T3_TX_HASH_LEN];
        memset(lhash, 0x7F, sizeof(lhash));

        nodus_t3_msg_t fm;
        memset(&fm, 0, sizeof(fm));
        fm.type = NODUS_T3_FWD_REQ;
        memcpy(fm.fwd_req.tx_hash, lhash, NODUS_T3_TX_HASH_LEN);
        fm.fwd_req.tx_data = ltx;
        fm.fwd_req.tx_len = (uint32_t)sizeof(ltx);
        fm.fwd_req.fee = 1000;
        memcpy(fm.fwd_req.forwarder_id, p[0].id, NODUS_T3_WITNESS_ID_LEN);

        /* LEG 1 — NON-leader. */
        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == -1,
              "a legacy non-leader REFUSES the forward, as before");
        CHECK(w->mempool.count == 0,
              "and nothing was pooled — the legacy intake at this site is "
              "structural only (no signature verify, no double-spend "
              "check), so pooling there would widen a trust boundary");

        /* LEG 2 — the SAME bytes, the only change being leadership. */
        w->current_view = p2_pick_view(w, true);
        CHECK(nodus_witness_bft_is_leader(w), "we ARE the leader now");
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "the identical bytes are accepted by the LEADER — so leg 1's "
              "refusal came from the leadership test, not from the wire");
        CHECK(w->mempool.count == 1, "and the leader pooled them");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13e2 — P3(b) on a SUCCESSOR: a RAW forward is never pooled ──
     *
     * The successor lane is the one P3(b) opens to non-leaders, and the
     * property that makes that safe is that NOTHING reaches the mempool
     * without passing the ADMISSION lane first — the same gate a direct
     * client submission takes. This section offers a non-leader bytes
     * that admission refuses and asserts the pool stays empty.
     *
     * The ingress gate is ARMED deliberately: with it closed
     * verify_v2_successor_tx refuses at its first line and the section
     * would pass without the admission lane ever running — a textbook
     * vacuous pass. Armed, the refusal below is the wire-family check
     * inside admission, which is the code this section is about.
     *
     * ⚠ THE LIMIT OF THIS SECTION, stated rather than hidden: it is a
     * SUPPORTING NEGATIVE and it does NOT fail if the P3(b) intake
     * change is reverted. Both the old leader-only gate and the new
     * admission gate answer -1 for bytes admission would refuse; the two
     * are distinguishable only by an entry that PASSES. §13e3 is the leg
     * that fails on a revert. ───────────────────────────────────────── */
    printf("§13e2 P3(b) — a successor non-leader pools NOTHING that fails "
           "admission\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_succ_XXXXXX";
        chain_db_open(w, dir, 0x36);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        w->v2_successor = true;
        w->v2_ingress_armed = true;
        CHECK(nodus_witness_v2_ingress_is_armed(w) == 1,
              "the successor ingress is ARMED — admission really runs, so "
              "the refusal below cannot come from a closed gate");

        /* Bytes with no V2 wire-family marker: admission's envelope lane
         * refuses them, and the claim lane refuses them as non-canonical. */
        uint8_t raw[256];
        memset(raw, 0x5A, sizeof(raw));

        nodus_t3_msg_t fm;
        memset(&fm, 0, sizeof(fm));
        fm.type = NODUS_T3_FWD_REQ;
        memset(fm.fwd_req.tx_hash, 0x5B, NODUS_T3_TX_HASH_LEN);
        fm.fwd_req.tx_data = raw;
        fm.fwd_req.tx_len = (uint32_t)sizeof(raw);
        fm.fwd_req.fee = 1000;
        memcpy(fm.fwd_req.forwarder_id, p[0].id, NODUS_T3_WITNESS_ID_LEN);

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) != 0,
              "a successor non-leader refuses bytes that fail ADMISSION");
        CHECK(w->mempool.count == 0,
              "and pooled nothing — a RAW, unverified forward never "
              "enters a follower's mempool");

        /* The SAME bytes on the LEADER are refused identically: P3(b)
         * moved the gate from leadership to admission, so both roles
         * now give the same answer for the same bytes. */
        w->current_view = p2_pick_view(w, true);
        CHECK(nodus_witness_bft_is_leader(w), "we ARE the leader now");
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) != 0,
              "the leader refuses the identical bytes — the verdict on a "
              "successor is admission's, not leadership's");
        CHECK(w->mempool.count == 0, "still nothing pooled");

        chain_db_drop(w, dir);
    }

    /* ── §13e3 — P3(b) POSITIVE: a successor NON-LEADER pools an entry
     *            that passes admission ────────────────────────────────
     *
     * THE LEG THAT FAILS IF P3(b) IS REVERTED. Everything else in §13e
     * observes a -1 that both the old and the new gate produce; only a
     * successful POOL distinguishes them. Pre-P3(b) this call returns -1
     * at the leader gate and the mempool stays empty.
     *
     * The chain is a REAL committed V2 successor with a present
     * distribution (see the §13e3 fixture block), and the entry is a
     * REAL signed class-201 claim, so "it was pooled" means it survived
     * the whole ADMISSION lane: canonical re-encode, SHA3-512 tx_hash
     * binding, distribution proof against the committed snapshot root,
     * the leaf's own ML-DSA-87 signature, the claim window, and the
     * cross-block spent check. There is no way for this section to pass
     * vacuously — a fixture that failed to arm anything would fail
     * admission and pool nothing. ─────────────────────────────────── */
    printf("§13e3 P3(b) — a successor NON-LEADER pools an admissible "
           "forwarded entry\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_pool_XXXXXX";
        chain_db_open(w, dir, 0x39);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));   /* ~25 KB — heap */
        if (!cx) { fprintf(stderr, "p3c chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);

        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR");
        CHECK(nodus_witness_v2_ingress_is_armed(w) == 1,
              "and its ingress is ARMED, so admission really runs");

        dna_claim_t *c = p3c_make_claim(cx, 0);
        size_t clen = 0;
        uint8_t chash[64];
        uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);

        uint8_t want_nul[64];
        p3c_claim_nullifier(c, want_nul);

        nodus_t3_msg_t fm;
        memset(&fm, 0, sizeof(fm));
        fm.type = NODUS_T3_FWD_REQ;
        memcpy(fm.fwd_req.tx_hash, chash, NODUS_T3_TX_HASH_LEN);
        fm.fwd_req.tx_data = cbytes;
        fm.fwd_req.tx_len = (uint32_t)clen;
        fm.fwd_req.fee = 0;
        memcpy(fm.fwd_req.forwarder_id, p[0].id, NODUS_T3_WITNESS_ID_LEN);

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w),
              "we are NOT the leader — pre-P3(b) this call ended here");
        CHECK(w->mempool.count == 0, "and the pool starts empty");

        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "the forwarded claim was ACCEPTED by a non-leader");
        CHECK(w->mempool.count == 1,
              "and POOLED — the dead leader is no longer the only node "
              "that can hold this work");

        /* The pooled SHAPE, not just the count. */
        CHECK(w->mempool.entries[0]->tx_type == NODUS_W_TX_V2_CLAIM,
              "pooled as the byte-classified entry class (201)");
        CHECK(w->mempool.entries[0]->is_forwarded,
              "marked forwarded, so the commit path answers the FORWARDER");
        CHECK(w->mempool.entries[0]->client_conn == NULL,
              "with no client connection of its own");
        CHECK(memcmp(w->mempool.entries[0]->forwarder_id, p[0].id,
                     NODUS_T3_WITNESS_ID_LEN) == 0,
              "and the forwarder id carried through, so a w_fwd_rsp from "
              "whichever node commits it reaches the client's node");
        CHECK(w->mempool.entries[0]->nullifier_count == 1,
              "the claim's committed nullifier was recorded");
        CHECK(memcmp(w->mempool.entries[0]->nullifiers[0], want_nul, 64) == 0,
              "and it is the value consensus derives — batch dedup and the "
              "P3(c) drain both key on exactly this");

        /* The duplicate guard is untouched by P3(b). */
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) != 0,
              "the same claim offered twice is refused");
        CHECK(w->mempool.count == 1, "and did not double-pool");

        free(cbytes);
        free(c);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13f — P3(c): the drain evicts the DECIDED, keeps the LIVE ───
     *
     * What used to stand in the tick was an unconditional
     * mempool_clear() on any non-leader once per epoch. Under P3(b) that
     * deletes, once a minute and mid-stall, exactly the entries that arm
     * the P3(a) deadman.
     *
     * The SURVIVAL half is what makes this discriminating: an eviction
     * that dropped everything — which is also what a MISSING DB produces,
     * since nodus_witness_nullifier_exists is fail-closed — would pass
     * the "stale entry is gone" half on its own. The DB state both
     * entries depend on is therefore asserted BEFORE the call.
     *
     * Driven by calling the function directly rather than through
     * nodus_witness_tick: the full tick also runs the epoch roster
     * rebuild, the peer mesh and the bootstrap machine, none of which
     * this section is about. ───────────────────────────────────────── */
    printf("§13f P3(c) — the follower drain evicts committed entries and "
           "keeps the pending ones\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_drain_XXXXXX";
        chain_db_open(w, dir, 0x37);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        /* Fees are chosen so the DECIDED entry sits at index 0 and the
         * LIVE one behind it: the survivor therefore has to be MOVED,
         * which exercises the compaction rather than a lucky no-op. */
        p3_pool(w, p3_mkentry(0x81, 500, 1));   /* decided, head */
        p3_pool(w, p3_mkentry(0x82, 100, 1));   /* live, behind it */
        p3_pool(w, p3_mkentry(0x83, 50, 0));    /* no nullifiers at all */
        CHECK(w->mempool.count == 3, "three entries pooled");
        CHECK(w->mempool.entries[0]->fee == 500 &&
              w->mempool.entries[1]->fee == 100 &&
              w->mempool.entries[2]->fee == 50,
              "and they are in fee order, decided one first");

        uint8_t n_decided[NODUS_T3_NULLIFIER_LEN];
        uint8_t n_live[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0x81, n_decided);
        p3_nul_of(0x82, n_live);

        uint8_t ctx[NODUS_T3_TX_HASH_LEN];
        memset(ctx, 0x81, sizeof(ctx));
        CHECK(nodus_witness_nullifier_add(w, n_decided, ctx) == 0,
              "the first entry's nullifier is COMMITTED on this chain");

        /* ⚠ THE ANTI-VACUITY PAIR. nodus_witness_nullifier_exists is
         * fail-closed — it answers "spent" on a missing DB or a failed
         * query — so without pinning BOTH answers here, a fixture with
         * no usable DB would evict everything and the "decided entry is
         * gone" assertion would pass for entirely the wrong reason. */
        CHECK(nodus_witness_nullifier_exists(w, n_decided),
              "the DB really says the first entry is spent");
        CHECK(!nodus_witness_nullifier_exists(w, n_live),
              "and really says the second is NOT — so the DB is live and "
              "discriminating, not failing closed on everything");

        int dropped = nodus_witness_mempool_evict_committed(w);

        CHECK(dropped == 1, "exactly ONE entry was evicted");
        CHECK(w->mempool.count == 2, "two survive");
        CHECK(w->mempool.entries[0]->fee == 100,
              "the LIVE entry survived and was compacted to the head — "
              "this is the half the old unconditional clear destroyed");
        CHECK(w->mempool.entries[1]->fee == 50,
              "and the entry with NO nullifiers survived too: a predicate "
              "that cannot judge an entry must not delete it (that is "
              "every successor class-200 envelope)");
        CHECK(w->mempool.entries[2] == NULL,
              "the vacated slot was cleared");

        /* Idempotent: nothing further is decided, so nothing further goes. */
        CHECK(nodus_witness_mempool_evict_committed(w) == 0,
              "a second pass evicts nothing — the drain reacts to the "
              "chain's verdict, not to being called");
        CHECK(w->mempool.count == 2, "and the survivors are still there");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    printf("PASS test_bft_view_change_hardening\n");
    return 0;
}
