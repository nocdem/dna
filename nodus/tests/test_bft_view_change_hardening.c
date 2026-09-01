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
 *  O15I follow-up — the three defects an independent verifier found in
 *  the sections above, each with the coverage that was missing:
 *
 *  V3 — bft_p3_live_demand had NO test: no fixture anywhere held a
 *       NON-EMPTY pool whose entries were ALL decided at an aged window,
 *       which is the one state the predicate exists to distinguish.
 *       §13g pins it, §13h is the converse that stops §13g passing for a
 *       predicate that always answers false.
 *
 *  V1 — a successor class-200 ENVELOPE is pooled with nullifier_count
 *       == 0 and NOTHING could remove it, so a FINISHED envelope read as
 *       live demand and churned the view against a healthy leader
 *       forever. Both consumers now ask nodus_witness_v2_entry_verdict
 *       and collapse it through the ONE shared
 *       nodus_witness_v2_entry_is_decided rule. §13i covers the
 *       COMMITTED door, §13k the EXPIRED one (the residual the first cut
 *       left open by treating every non-OK preflight status as a node
 *       fault), each with an unfinished envelope carried through as the
 *       survival half.
 *
 *  V2 — bft_config is zero on a calloc'd witness and whenever
 *       n < NODUS_T3_MIN_WITNESSES, which made both IDLE-branch deadmen
 *       fire every second. Both are gated on
 *       nodus_witness_bft_consensus_active; §13j pins each, with its own
 *       in-fixture converse.
 *
 *  O15K — the LEGACY lane opens, and two defects that are live on the
 *  devnet close with it. §13e (rewritten) and §13l-§13q assert behaviour
 *  that does NOT exist yet: they are RED until the O15K change lands,
 *  which is the only reason they are worth writing. §13r and §13s are the
 *  deliberate exceptions — KEEP-DIRECTION GUARDS that pass today and say
 *  so in their own headers; see the §3.5 entry below for why a guard
 *  against a deletion the code cannot yet perform cannot be red.
 *  The two rules each obeys, both learned the expensive way and recorded
 *  at §13e2's own limit note:
 *
 *    1. THE ENTRY UNDER TEST ENTERS THROUGH A GATE THE FIX CHANGES —
 *       nodus_witness_pool_local_demand or
 *       nodus_witness_peer_handle_fwd_req. p3_pool calls
 *       nodus_witness_mempool_add DIRECTLY and bypasses every intake gate
 *       O15K touches, so a case that pools with it and then observes the
 *       deadman is asserting SHIPPED behaviour. p3_pool appears below only
 *       where the pooled entry is the INSTRUMENT rather than the subject,
 *       and each such use says so.
 *    2. EVERY REFUSAL CARRIES A POSITIVE CONTROL. "It was refused" is
 *       indistinguishable from the pre-fix early returns —
 *       pool_local_demand's -1 (nodus_witness_handlers.c) and the legacy
 *       non-leader refusal (nodus_witness_peer.c) both mean "not pooled"
 *       for the WRONG reason. So every refusal sits beside an entry that
 *       DOES pool, and the assertion is on w->mempool.count changing, not
 *       on a return code alone.
 *
 *  §3.1 — a legacy client's demand may be pooled locally (§13l).
 *  §3.2 / V-1 — the legacy forward intake ran NO admission verify, so a
 *       legacy LEADER pooled structurally-walkable but cryptographically
 *       UNVERIFIED bytes. One invalid-signature transaction from any
 *       remote client therefore poisons the leader's next batch. LIVE ON
 *       THE DEVNET. §13e (rewritten) and §13n.
 *  §3.3 — the P3 fire disseminated NOTHING on a legacy chain, so the one
 *       node holding the work could never recruit the f+1 backers a
 *       rotation needs (§13p).
 *  §3.4 / V-8 — a wire input_count byte of 0 walks the legacy structural
 *       loop zero times and is pooled with nullifier_count == 0: an entry
 *       no reaper can evict and that reads as live demand forever, i.e.
 *       the O15I V1 churn re-entering through the legacy door. LIVE ON
 *       THE DEVNET. §13o.
 *  §3.5 / V-3 — a successor CLAIM commit writes v2_claims_spent while
 *       every "is this decided?" question walks the legacy `nullifiers`
 *       table, so a committed class-201 claim is never reaped (§13q).
 *       This is the ONE O15K item that teaches the code to DELETE, so
 *       §13r and §13s assert the KEEP direction: an uncommitted claim and
 *       a claim judged under a DB fault must both survive. Both are
 *       GUARDS — they pass today, and they say so — because a wrong
 *       deletion silently loses work a client is waiting on.
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
#include "witness/nodus_witness_peer.h" /* §13 — handle_fwd_req,
                                         * §14b — peer_conn_closed         */
#include "witness/nodus_witness_handlers.h" /* §14a — handle_dnac          */
#include "witness/nodus_witness_verify.h"   /* §13e/§13l-§13o — the
                                             * canonical legacy tx_hash    */
#include "witness/nodus_witness_v2_gate.h" /* §13e2 — ingress_is_armed     */
#include "witness/nodus_witness_vset.h"
/* §13e3 — the successor-chain fixture (test_v2_claim_ingress.c's shape). */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
/* §13i — O15I V1: the committed-INTENT authority. runtime.h supplies the
 * SYSTEM ruleset op + auth-kind the envelope leg declares; v2_produce.h
 * the entry classifier and the V2 tip the candidate height comes from. */
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_produce.h"
#include "nodus/nodus_chain_config.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"  /* §14a — the dnac_spend request encoder */
#include "crypto/nodus_sign.h"
#include "nodus/nodus_types.h"

#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"           /* §13e/§13l-§13o — DNAC_PROTOCOL_VERSION,
                                  *                  DNAC_MIN_FEE_RAW      */
#include "dnac/vset_wire.h"
#include "dnac/env_wire.h"       /* §7 — DNA_ENV_MAX_TOTAL_LEN */
#include "dnac/env_preflight.h"  /* §13i — the derived intent_id           */
#include "dnac/ledger_ids.h"     /* §7/§8 — dna_bft_quorum      */
#include "dnac/transaction.h"    /* §13e — DNAC_TX_HEADER_SIZE  */
#include "dnac/manifest_wire.h"  /* §13e3 — GenesisManifest + claim codec */
#include "dnac/domain_wire.h"    /* §13e3 — dna_domman_hash               */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>  /* §15e — socketpair for a conn that can really
                          * send; nodus_tcp's poll_write is send(2), which
                          * fails ENOTSOCK on an ordinary file */

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

/* O15N Faz 2A — 116-byte PREPARED preimage: "prepared"(8) ‖ chain_id(32) ‖
 * view(4 BE) ‖ height(8 BE) ‖ tx_hash(64). chain_id is passed in by every
 * caller from w->chain_id, because that is what the verifier rebuilds
 * with; the §11/§12 fixtures DO create a chain DB (0x77 / 0x33), so a
 * zero literal here would fail those sections and only those. */
static void sign_prepared(uint8_t out_sig[NODUS_SIG_BYTES], const peer_t *p,
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
                  w->round_state.block_height, tx_hash, w->chain_id);

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
/* Does the PRODUCTION predicate call us the leader at `view`?
 * `current_view` is restored before returning — probing must not be an
 * edit. Factored out so a section that needs a PAIR of views can ask the
 * same question p2_pick_view asks, instead of re-implementing the
 * modulus and drifting from is_leader's committee-vs-roster split. */
static bool p2_is_leader_at(nodus_witness_t *w, uint32_t view) {
    uint32_t saved = w->current_view;
    w->current_view = view;
    bool is_l = nodus_witness_bft_is_leader(w);
    w->current_view = saved;
    return is_l;
}

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
 * (the fixture appends self first, then the peers).
 *
 * ⚠ IT MUST ASK THE SAME QUESTION nodus_witness_bft_is_leader ASKS, AND
 * THAT QUESTION HAS TWO ANSWERS. When a validator-set snapshot exists,
 * is_leader ranks the node inside the COMMITTEE the snapshot defines;
 * with no snapshot it falls back to the SORTED gossip roster (F17 A5).
 * §15 writes snapshots (O15N Faz 2C2 needs a committee — a VIEW_OK
 * statement cannot be signed without one), while §12d/§12f do not, so a
 * helper that only knew one of the two would silently pick the wrong
 * peer in the other and every "the sender is the expected leader"
 * precondition would be false while the section still printed PASS.
 *
 * The committee seat is resolved back to `all[]` BY PUBKEY, never by
 * indexing witnesses[] with the slot — the exact confusion BUGS.md
 * 2026-08-04 records. */
static const peer_t *p2_leader_at(nodus_witness_t *w, const peer_t *all,
                                  uint32_t view) {
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;

    nodus_committee_member_t *cm = NULL;
    int count = 0;
    if (nodus_committee_get_for_block_alloc(w, next_bh, &cm, &count) != 0) {
        fprintf(stderr, "p2_leader_at: committee load failed\n"); exit(1);
    }
    if (count > 0) {
        int slot = nodus_witness_bft_leader_index(epoch, view, count);
        if (slot < 0 || slot >= count) {
            fprintf(stderr, "p2_leader_at: seat %d out of %d\n", slot, count);
            exit(1);
        }
        for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
            if (memcmp(all[i].pk, cm[slot].pubkey, DNAC_PUBKEY_SIZE) == 0) {
                free(cm);
                return &all[i];
            }
        }
        fprintf(stderr, "p2_leader_at: committee seat %d is not in all[]\n",
                slot);
        exit(1);
    }
    free(cm);

    int slot = nodus_witness_bft_leader_index(epoch, view,
                                              (int)w->roster.n_witnesses);
    int arr = nodus_witness_roster_sorted_at(&w->roster, slot);
    if (arr < 0) { fprintf(stderr, "p2_leader_at: no slot %d\n", slot); exit(1); }
    return &all[arr];
}

/* ═══════════════════════════════════════════════════════════════════
 * §15 helpers — O15N Faz 2C2, VIEW_OK statements.
 *
 * A statement is one node's signed claim that IT observed a view-change
 * quorum for (height, view) under the committee whose set hash it
 * carries. f+1 distinct statements are a PROOF, and a verified proof for
 * a higher view is now the ONE thing that moves `current_view`.
 *
 * ⚠ THE SET HASH IS NEVER RECOMPUTED HERE. compute_committee_set_hash is
 * static in nodus_witness_bft.c, and a second implementation in this
 * file would be a second answer to a question the production code
 * already settles — the two would drift and the drift would look like a
 * consensus bug. Instead, every section reads the hash the node itself
 * signed under, out of `w->viewok_acc.set_hash`, AFTER driving the node
 * to its own quorum. That also makes the sections fail loudly if the
 * emission never happened, which is the state that would otherwise make
 * every VIEW_OK assertion below vacuous.
 * ═══════════════════════════════════════════════════════════════════ */

/* The 148-byte purpose-0x08 VIEW_OK preimage
 * (compute_view_ok_preimage, nodus_witness_bft.c):
 * "viewok\0\0"(8) ‖ chain_id(32) ‖ height(8 BE) ‖ view(4 BE) ‖
 * set_hash(64) ‖ voter_id(32). */
static void sign_viewok(uint8_t out_sig[NODUS_SIG_BYTES], const peer_t *p,
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
        fprintf(stderr, "viewok sign\n"); exit(1);
    }
    memcpy(out_sig, sig.bytes, NODUS_SIG_BYTES);
}

/* Build a `w_viewok` bundle carrying `n` statements, sent by
 * `signers[0]`. Every signer signs the SAME anchor, so the bundle is
 * exactly what a broadcast (n == 1) or a `w_viewok_q` answer (n == f+1)
 * looks like on the wire. */
static void vok_fill(nodus_t3_msg_t *m, nodus_witness_t *w,
                     uint64_t height, uint32_t view,
                     const uint8_t set_hash[64],
                     const peer_t *signers, int n) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWOK;
    m->header.round = w->round_state.round;
    m->header.view = w->current_view;
    memcpy(m->header.sender_id, signers[0].id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
    m->viewok.height = height;
    m->viewok.view = view;
    memcpy(m->viewok.set_hash, set_hash, 64);
    m->viewok.n_entries = (uint32_t)n;
    for (int i = 0; i < n; i++) {
        memcpy(m->viewok.entries[i].voter_id, signers[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        sign_viewok(m->viewok.entries[i].signature, &signers[i],
                    height, view, set_hash, w->chain_id);
    }
}

/* One statement from `from`, delivered through the production handler. */
static int vok_deliver1(nodus_witness_t *w, const peer_t *from,
                        uint64_t height, uint32_t view,
                        const uint8_t set_hash[64]) {
    nodus_t3_msg_t m;
    vok_fill(&m, w, height, view, set_hash, from, 1);
    return nodus_witness_bft_handle_viewok(w, &m);
}

/* Write the validator-set snapshot that governs THIS node's NEXT block
 * height, and PROVE it resolves.
 *
 * ⚠ WITHOUT A COMMITTEE NOTHING IN §12/§15 CAN HAPPEN AT ALL.
 * nodus_witness_bft_sign_view_ok refuses when the committee at the
 * height is empty, and nodus_witness_bft_verify_view_proof answers -2
 * there — so on the pre-genesis fixture §1-§5 use, the view can never
 * move and every assertion about a rotation would pass or fail for the
 * wrong reason. This helper is what turns those fixtures into ones the
 * O15N Faz 2C2 machinery can actually run on.
 *
 * ⚠ THE SIZE IS NOT FREE, AND FOUR WOULD HAVE BEEN A TRAP.
 * nodus_witness_bft_config_init ZEROES quorum AND both timeouts when
 * n < NODUS_T3_MIN_WITNESSES, which is 5 (nodus_types.h). A four-member
 * snapshot therefore looks fine until something calls
 * refresh_bft_config_from_committee — handle_propose does, on every
 * proposal — and from that moment the node has quorum 0 and
 * nodus_witness_bft_consensus_active is false, which is exactly the
 * O15I V2 state where both IDLE-branch deadmen misbehave. FIVE is the
 * smallest size that does not walk into it.
 *
 * The numbers five gives: dna_bft_quorum(5) = 4, so the verifier's f+1
 * is ((4-1)/2)+1 = 2 — this node's own statement plus ONE peer's is a
 * proof. That also matches bft_vc_join_threshold at the quorum of 3 the
 * §12 fixtures hand bft_config, so the local pre-gate and the verifier's
 * real threshold agree and no attempt is wasted. §15b deliberately uses
 * SEVEN instead, where f+1 is 3, because a boundary of "one statement vs
 * two" is one a broken threshold of 1 could still pass.
 *
 * The e_start is DERIVED, not assumed: nodus_committee_get_for_block
 * keys on (height / DNAC_EPOCH_LENGTH) * DNAC_EPOCH_LENGTH, and that
 * constant is a build flag (720 shipped, 15 on the short-epoch harness
 * builds), so a literal here would silently miss on one of them. */
static void vok_seed_committee(nodus_witness_t *w, const peer_t *members,
                               int n) {
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    uint64_t e_start = (next_bh / (uint64_t)DNAC_EPOCH_LENGTH) *
                       (uint64_t)DNAC_EPOCH_LENGTH;
    put_snapshot(w, e_start, members, n);

    /* ANTI-VACUITY, and it is not decoration: a snapshot the resolver
     * does not serve drops every gate below onto the documented
     * pre-genesis roster fallback, where the committee count is 0 — the
     * one state in which no VIEW_OK exists and no section here can mean
     * what it says. */
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
    CHECK(self_in, "and WE are in it — otherwise our own statement would "
                   "be skipped by the verifier and f+1 could never be met");
    free(cm);
}

/* Drive a view change to QUORUM at `target` using only inbound peer
 * messages — the production path, not a hand-set field — and then
 * complete the MOVE with peer statements.
 *
 * ⚠ THIS IS TWO EVENTS NOW, AND THAT IS THE WHOLE POINT OF O15N Faz
 * 2C2. Reaching quorum used to write `current_view` on the spot; it now
 * only makes the node SIGN AND BROADCAST one VIEW_OK statement. The
 * counter moves later, when f+1 distinct statements have been verified.
 * Both halves are asserted here so no §12 section can build on a
 * rotation that quietly failed at either step.
 *
 * With quorum 3 the join threshold is 2 (bft_vc_join_threshold), so the
 * SECOND peer VIEW_CHANGE both raises the target and pulls us in via the
 * f+1 join; initiate_view_change self-records and its tail call to
 * bft_vc_check_quorum sees 3/3 and emits. Under the five-member
 * committee vok_seed_committee writes, the verifier's f+1 is 2 and our
 * own statement is one of them — so ONE peer statement completes the
 * proof, and `a` supplies it.
 *
 * BOTH `a` AND `b` MUST BE IN THE COMMITTEE SNAPSHOT and must not be
 * this node: `b`'s VIEW_CHANGE has to pass the committee gate in
 * handle_viewchg, and `a`'s VIEW_OK statement has to be resolvable by
 * the verifier, which skips a non-member outright. */
static void p2_complete_vc(nodus_witness_t *w, const peer_t *a,
                           const peer_t *b, uint32_t target)
{
    uint32_t view_before = w->current_view;
    uint64_t txn_before = w->next_txn_id;

    nodus_t3_msg_t vc;
    fill_viewchg(&vc, w, a, target);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
          "first peer VIEW_CHANGE recorded");
    fill_viewchg(&vc, w, b, target);
    CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
          "second peer VIEW_CHANGE recorded");

    /* HALF ONE — we observed our own quorum and SPOKE, without moving. */
    CHECK(w->current_view == view_before,
          "reaching our OWN view-change quorum did NOT move the view");
    CHECK(w->next_txn_id > txn_before,
          "but it DID emit — a statement was broadcast (txn_id delta; a "
          "peer-less fixture sends to zero connections, so the delta is "
          "the only honest evidence)");
    CHECK(w->viewok_acc.active && w->viewok_acc.view == target,
          "the accumulator is anchored on the target we observed");

    /* HALF TWO — one peer statement completes f+1 and the view moves. */
    CHECK(vok_deliver1(w, a, w->viewok_acc.height, target,
                       w->viewok_acc.set_hash) == 0,
          "a peer's VIEW_OK statement was accepted");
    CHECK(w->current_view == target,
          "f+1 verified statements MOVED the view — the one writer");
    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
          "and the post-move block put us back to IDLE (where nothing "
          "used to be armed)");
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
 * the same 116-byte purpose-0x07 preimage that
 * nodus_witness_bft_verify_prepared_cert rebuilds. Signing it for real
 * matters — the has_reproposal branch of handle_newview is fail-closed,
 * so a stubbed cert would make every "re-arm" assertion vacuous by
 * never reaching the accept at all. */
static void p2_add_reproposal(nodus_t3_msg_t *m, const peer_t *all, int n,
                              uint64_t height, uint32_t prep_view,
                              const uint8_t *tx_hash,
                              const uint8_t *chain_id) {
    m->newview.has_reproposal = true;
    m->newview.reproposal_height = height;
    m->newview.reproposal_prepared_view = prep_view;
    memcpy(m->newview.reproposal_tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    m->newview.reproposal_n_sigs = (uint32_t)n;
    for (int i = 0; i < n; i++) {
        memcpy(m->newview.reproposal_sigs[i].voter_id, all[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        sign_prepared(m->newview.reproposal_sigs[i].signature, &all[i],
                      prep_view, height, tx_hash, chain_id);
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
 * §13e / §13l-§13o fixture — a REAL, ADMISSIBLE LEGACY transaction.
 *
 * WHY THIS HAD TO EXIST. Every O15K legacy case turns on the difference
 * between bytes the legacy ADMISSION lane accepts and bytes it refuses,
 * and until now this file had no admissible legacy transaction at all:
 * §13e's `ltx` is a zero-filled header with one nullifier glued on, which
 * the pre-O15K structural walk accepts and which admission refuses at its
 * FIRST check (wrong wire version). A case built on those bytes could
 * only ever observe a refusal, and a refusal is exactly what the pre-fix
 * early returns already produce — the vacuity trap §13e2 records.
 *
 * THE RECIPE IS NOT INVENTED. It is test_witness_verify.c's
 * build_tx_data / embed_signer_sig, reproduced field for field, because
 * that fixture is the shipped proof that these bytes pass
 * nodus_witness_verify_transaction in ADMISSION mode
 * (test_witness_verify.c: "valid spend TX passes all checks"). The wire
 * layout it encodes is the one nodus_witness_verify.c walks:
 *
 *   version(1) type(1) timestamp(8) tx_hash(64) committed_fee(8 BE)
 *   input_count(1)  [ nullifier(64) amount(8) token_id(64) ] * n
 *   output_count(1) [ version(1) fp(129) amount(8) token_id(64)
 *                     seed(32) memo_len(1) ] * m
 *   witness_count(1) = 0
 *   signer_count(1)  [ pubkey(2592) signature(4627) ] * s
 *
 * ONE DELIBERATE DIFFERENCE FROM THE REFERENCE, and it is load-bearing:
 * the tx_hash is recomputed over w->chain_id, not over a zero chain id.
 * test_witness_verify.c memsets its whole witness and hashes an explicit
 * 32-byte zero chain id; chain_db_open here writes 16 tag bytes,
 * zero-filled to the field's 32 (nodus_witness.c set_chain_id). Hashing
 * the wrong chain id would fail Check 2 ("tx_hash mismatch") and every
 * §13e/§13l-§13o accept would silently become a refusal — the whole suite
 * green for the wrong reason.
 *
 * DETERMINISM: the timestamp is derived from the tag, never from the
 * clock, so two runs build byte-identical transactions.
 * ═══════════════════════════════════════════════════════════════════ */

/* Σin − Σout = 1,000,000 = NODUS_W_BASE_TX_FEE exactly — the deterministic
 * floor Check 5 applies in BOTH verify modes. The ADMISSION surge on top
 * of it is `BASE * (1 + mempool.count / NODUS_W_FEE_SURGE_STEP)`, so every
 * section below keeps the pool under NODUS_W_FEE_SURGE_STEP entries while
 * admitting; a fuller pool would raise the bar and turn an intended ACCEPT
 * into a fee rejection. */
#define P3L_INPUT_AMOUNT   3000000ULL
#define P3L_OUTPUT_AMOUNT  2000000ULL

typedef struct {
    uint8_t  *tx;                            /* wire bytes — heap        */
    uint32_t  len;
    uint8_t   hash[NODUS_T3_TX_HASH_LEN];    /* the recomputed tx_hash   */
    uint8_t   nul[NODUS_T3_NULLIFIER_LEN];   /* input 0's nullifier      */
    uint64_t  fee;                           /* Σin − Σout, the ONE fee  */
} p3l_tx_t;

static void p3l_die(const char *what) {
    fprintf(stderr, "p3l fixture: %s\n", what);
    exit(1);
}

/* Build a legacy SPEND signed by `signer`.
 *
 * `n_inputs`   1 = the ordinary shape; 0 = the V-8 shape, whose wire
 *              input_count byte is 0 and whose structural walk therefore
 *              executes zero times.
 * `valid_sig`  false corrupts the signature AFTER the tx_hash is fixed.
 *              The legacy preimage hashes the CALLER-SUPPLIED signer
 *              pubkeys and length-walks the wire signers section without
 *              hashing it (nodus_witness_verify.c on
 *              dnac_txw_legacy_tx_hash), so flipping signature bytes
 *              leaves the tx_hash — and therefore every structural check
 *              — intact. The ONLY thing wrong with those bytes is the
 *              cryptography, which is precisely the V-1 shape. */
static void p3l_make(nodus_witness_t *w, const peer_t *signer, uint8_t tag,
                     int n_inputs, bool valid_sig, p3l_tx_t *out) {
    const size_t IN_SZ  = NODUS_T3_NULLIFIER_LEN + 8 + 64;      /* 136 */
    const size_t OUT_SZ = 1 + 129 + 8 + 64 + 32 + 1;            /* 235 */

    memset(out, 0, sizeof(*out));
    size_t size = DNAC_TX_HEADER_SIZE
                + 1 + (size_t)n_inputs * IN_SZ
                + 1 + OUT_SZ
                + 1                                   /* witness_count 0 */
                + 1 + NODUS_PK_BYTES + NODUS_SIG_BYTES;
    /* The explicit return after p3l_die follows p3c_make_claim's
     * convention: the die helper is not declared noreturn, so without it a
     * compiler still sees a NULL walk below. */
    uint8_t *buf = calloc(1, size);
    if (!buf) { p3l_die("tx alloc"); return; }

    uint8_t *p = buf;
    *p++ = DNAC_PROTOCOL_VERSION;
    *p++ = NODUS_W_TX_SPEND;
    uint64_t ts = 1700000000ULL + (uint64_t)tag;   /* derived, not a clock */
    memcpy(p, &ts, 8); p += 8;
    p += NODUS_T3_TX_HASH_LEN;                     /* filled after hashing */
    for (int i = 7; i >= 0; i--)                   /* committed_fee, BE    */
        *p++ = (uint8_t)((DNAC_MIN_FEE_RAW >> (i * 8)) & 0xFF);

    /* Inputs. The nullifier is derived from the tag exactly as p3_nul_of
     * derives one, so a test can fund it and later commit it. */
    *p++ = (uint8_t)n_inputs;
    memset(out->nul, tag, sizeof(out->nul));
    for (int i = 0; i < n_inputs; i++) {
        memcpy(p, out->nul, NODUS_T3_NULLIFIER_LEN);
        p += NODUS_T3_NULLIFIER_LEN;
        uint64_t amt = P3L_INPUT_AMOUNT;
        memcpy(p, &amt, 8); p += 8;
        p += 64;                                   /* token_id = native   */
    }

    /* One output to a fingerprint that is NOT the signer's, so the whole
     * P3L_OUTPUT_AMOUNT counts as a transfer rather than as change. */
    *p++ = 1;
    *p++ = 1;                                      /* output version      */
    memset(p, 0xBB, 129); p += 129;
    uint64_t oamt = P3L_OUTPUT_AMOUNT;
    memcpy(p, &oamt, 8); p += 8;
    p += 64;                                       /* token_id = native   */
    p += 32;                                       /* nullifier_seed      */
    *p++ = 0;                                      /* memo_len            */

    *p++ = 0;                                      /* witness_count       */
    *p++ = 1;                                      /* signer_count        */
    memcpy(p, signer->pk, NODUS_PK_BYTES); p += NODUS_PK_BYTES;
    uint8_t *sig_slot = p; p += NODUS_SIG_BYTES;

    out->tx  = buf;
    out->len = (uint32_t)(p - buf);
    if ((size_t)out->len != size) p3l_die("wire length drift");

    if (nodus_witness_recompute_tx_hash(w->chain_id, buf, out->len,
                                        signer->pk, 1, out->hash) != 0)
        p3l_die("tx_hash recompute");
    memcpy(buf + 10, out->hash, NODUS_T3_TX_HASH_LEN);

    nodus_sig_t sig;
    nodus_seckey_t sk;
    memcpy(sk.bytes, signer->sk, sizeof(sk.bytes));
    if (nodus_sign(&sig, out->hash, NODUS_T3_TX_HASH_LEN, &sk) != 0)
        p3l_die("tx signature");
    memcpy(sig_slot, sig.bytes, NODUS_SIG_BYTES);
    if (!valid_sig) sig_slot[0] = (uint8_t)(sig_slot[0] ^ 0xFF);

    /* The declared fee the wire and the caller must BOTH agree with:
     * Check 5's `actual_fee != declared_fee` is deterministic and runs in
     * both modes, so a mismatch here would refuse the transaction for a
     * reason no section below is about. For the zero-input shape the value
     * is carried unchanged and is irrelevant — that transaction never
     * reaches the balance arithmetic. */
    out->fee = P3L_INPUT_AMOUNT - P3L_OUTPUT_AMOUNT;
}

static void p3l_free(p3l_tx_t *t) {
    free(t->tx);
    t->tx = NULL;
    t->len = 0;
}

/* Put the UTXO the transaction spends into the committed set, owned by
 * the SIGNER's fingerprint. Check 4 rejects an input whose owner matches
 * no signer (CRITICAL-4), so funding it to anyone else would make every
 * "it pooled" assertion below fail for an ownership reason. */
static void p3l_fund(nodus_witness_t *w, const peer_t *signer,
                     const p3l_tx_t *t) {
    nodus_pubkey_t pk;
    memcpy(pk.bytes, signer->pk, NODUS_PK_BYTES);
    char fp[129];
    if (nodus_fingerprint_hex(&pk, fp) != 0) p3l_die("signer fingerprint");
    uint8_t src[NODUS_T3_TX_HASH_LEN];
    memset(src, 0x6C, sizeof(src));
    if (nodus_witness_utxo_add(w, t->nul, fp, P3L_INPUT_AMOUNT, src,
                               0, 0, NULL) != 0)
        p3l_die("utxo insert");
}

/* Is the funding UTXO really there, with the amount the balance check
 * needs? The §13f anti-vacuity discipline applied to the INPUT side: a
 * fixture whose utxo_add silently failed would make every accept below
 * fail as "UTXO not found in set", which reads identically to the
 * pre-O15K gate refusing. */
static bool p3l_funded(nodus_witness_t *w, const p3l_tx_t *t) {
    uint64_t amt = 0;
    char owner[129] = {0};
    if (nodus_witness_utxo_lookup_ex(w, t->nul, &amt, owner, NULL, NULL) != 0)
        return false;
    return amt == P3L_INPUT_AMOUNT && owner[0] != '\0';
}

/* A w_fwd_req carrying `t`, forwarded by `from`. The declared fee is the
 * transaction's own Σin − Σout, which is what Check 5 compares against.
 * client_pubkey / client_sig stay NULL: the LEGACY admission lane never
 * reads either parameter (nodus_witness_verify.c casts them to void only
 * on the successor branch, and the legacy branch verifies the WIRE signer
 * section instead), so a forward that carries them and one that does not
 * are judged identically. */
static void p3l_fwd(nodus_t3_msg_t *m, const p3l_tx_t *t, const peer_t *from) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_FWD_REQ;
    memcpy(m->fwd_req.tx_hash, t->hash, NODUS_T3_TX_HASH_LEN);
    m->fwd_req.tx_data = t->tx;
    m->fwd_req.tx_len  = t->len;
    m->fwd_req.fee     = t->fee;
    memcpy(m->fwd_req.forwarder_id, from->id, NODUS_T3_WITNESS_ID_LEN);
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

/* ═══════════════════════════════════════════════════════════════════
 * §13q-§13s helpers — V-3, the spent-claim table nothing reads.
 *
 * A successor CLAIM commit records its nullifier in `v2_claims_spent`
 * (nodus_witness_v2_claims.c, the spend insert). Every "is this pooled
 * entry decided?" question instead walks the LEGACY `nullifiers` table —
 * nodus_witness_nullifier_exists, whose only writer is the legacy commit
 * path — and nodus_witness_v2_entry_verdict's class gate answers UNJUDGED
 * for anything that is not a class-200 ENVELOPE. Both halves therefore say
 * "not decided" about a claim the chain has already committed, so it is
 * never reaped and reads as live demand forever: the O15I V1 shape in a
 * lane whose own comments assert it is closed.
 * ═══════════════════════════════════════════════════════════════════ */

/* Commit a claim through the PRODUCTION execute stages, in their locked
 * order: the target runtime's claim_apply output, the v2_claims_spent
 * insert, then the checked distribution decrement. Writing the row by hand
 * would let this fixture disagree with what a real commit leaves behind —
 * and the disagreement between two writers is exactly what V-3 is. */
static void p3c_commit_claim(nodus_witness_t *w, const dna_claim_t *c) {
    uint64_t h = nodus_witness_block_height(w) + 1;
    nodus_v2_claim_admit_t adm;
    memset(&adm, 0, sizeof(adm));
    if (nodus_witness_v2_claim_admit(w, c, h, &adm) != 0)
        p3c_die("claim admit");
    uint8_t out_id[64];
    if (nodus_witness_v2_claim_output_create(w, c, &adm, h, out_id) != 0)
        p3c_die("claim output create");
    if (nodus_witness_v2_claim_spend_insert(w, c, &adm, out_id, h) != 0)
        p3c_die("claim spend insert");
    if (nodus_witness_v2_claim_state_update(w, adm.manifest_hash,
                                            adm.converted) != 0)
        p3c_die("claim distribution decrement");
}

/* Ask the SPENT-CLAIM table directly — p3c_intent_in_index's discipline,
 * applied to the other half of V-3. Both answers are pinned before any
 * production predicate is consulted, so a fixture whose commit silently
 * did nothing cannot make "not reaped" look like a verdict.
 *
 * A prepare failure here is a FIXTURE bug and dies; §13s, which breaks the
 * table on purpose, uses p3c_claims_table_readable below instead. */
static bool p3c_claim_is_spent(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_claims_spent WHERE nullifier = ?1",
            -1, &st, NULL) != SQLITE_OK) {
        p3c_die("claims_spent probe prepare");
        return false;
    }
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    bool found = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return found;
}

/* Can the spent-claim table be QUERIED AT ALL? §13s drops it to produce a
 * genuine DB fault, and needs to OBSERVE the fault rather than exit on it.
 * Kept separate from the probe above precisely so that the "this is a
 * fixture bug" and "this is the fault under test" cases cannot be
 * confused. */
static bool p3c_claims_table_readable(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT 1 FROM v2_claims_spent LIMIT 1",
                           -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_finalize(st);
    return true;
}

/* ═══════════════════════════════════════════════════════════════════
 * §14 helpers — O15J A, driving the REAL dnac_spend entry point.
 *
 * WHY THE PRODUCTION ENTRY POINT AND NOT JUST THE HELPER. A §14 that
 * only called nodus_witness_pool_local_demand would still pass with the
 * call site DELETED from handle_dnac_spend's non-leader branch — the
 * change would be entirely inert and every assertion would stay green.
 * §14a therefore builds a real CBOR dnac_spend request and dispatches it
 * through nodus_witness_handle_dnac.
 * ═══════════════════════════════════════════════════════════════════ */

/* ⚠ ZEROED ON PURPOSE, and this is a safety property, not laziness.
 * nodus_conn_state_t has NODUS_CONN_CLOSED == 0
 * (src/transport/nodus_tcp.h), and nodus_tcp_send_progress returns -1 on
 * a CLOSED conn BEFORE it touches conn->fd. So every send_error the
 * handler emits on this conn — including the O15J B "leader not
 * reachable" answer — is a safe no-op, and a zeroed fd is never written
 * to. `auth_required` is 0 too, so nodus_tcp_send takes no queueing
 * branch either.
 *
 * Its OTHER job is pointer identity: §14b needs one conn value that both
 * a control mempool entry and nodus_witness_peer_conn_closed can name. */
static nodus_tcp_conn_t o15j_fake_conn;

/* A real dnac_spend T2 request body: {"a": {"tx":bstr,"hash":bstr,"fee":u}}.
 * The shape is handle_dnac_spend's own (see its header comment); "pk" and
 * "sig" are omitted because the SUCCESSOR admission lane casts both to
 * void (nodus_witness_verify.c), so a successor request that carries them
 * and one that does not are judged identically. Caller owns the buffer. */
static uint8_t *o15j_spend_payload(const uint8_t *tx, size_t tx_len,
                                   const uint8_t hash[NODUS_T3_TX_HASH_LEN],
                                   uint64_t fee, size_t *out_len) {
    size_t cap = tx_len + 1024;
    uint8_t *buf = malloc(cap);
    if (!buf) { fprintf(stderr, "o15j payload alloc\n"); exit(1); }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "a");
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "tx");
    cbor_encode_bstr(&enc, tx, tx_len);
    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, hash, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(&enc, "fee");
    cbor_encode_uint(&enc, fee);

    *out_len = cbor_encoder_len(&enc);
    if (*out_len == 0) { fprintf(stderr, "o15j payload encode\n"); exit(1); }
    return buf;
}

/* ═══════════════════════════════════════════════════════════════════
 * §13i helpers — O15I V1, the committed-INTENT verdict on a class-200
 * successor ENVELOPE.
 *
 * WHY AN ENVELOPE AND NOT THE §13e3 CLAIM. A class-201 claim is pooled
 * WITH its committed nullifier (nodus_witness_peer.c re-derives it at
 * intake), so the legacy predicate already judges it. The class-200
 * ENVELOPE is the shape nothing could judge: intake takes the successor
 * branch, the legacy nullifier walk is skipped, and the entry lands with
 * nullifier_count == 0. That entry is what V1 is about, so the fixture
 * has to produce a real one.
 *
 * WHAT THESE ENVELOPES ARE NOT. They are NOT admissible transactions and
 * they are deliberately not made so: `auth_data` is filler, and no
 * committee approval is built. That is sound because the property under
 * test is the DERIVATION, and the preflight explicitly decides nothing
 * about authorization (env_preflight.h, "HONEST LABEL: what the preflight
 * does NOT decide"). intent_id excludes every authorization byte by
 * construction (env_wire.h, "DNA.ENVINTID.v1"), so filler auth cannot
 * change the value under test. The entries are therefore POOLED DIRECTLY
 * rather than offered to handle_fwd_req — §13e3 already owns the
 * admission-lane proof.
 *
 * `expiry_height` is 0 (= never expires) so the preflight's one height
 * comparison can never turn this fixture's verdict into a rejection: the
 * section is about the INDEX answer, not about expiry.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  intent_id[64];
} p3c_env_t;

/* A canonical 1-leg SYSTEM envelope plus the intent_id consensus derives
 * for it. `tag` seeds call_data, so two tags are two DIFFERENT semantic
 * transactions and therefore two different intent ids — the section
 * asserts that rather than assuming it.
 *
 * `expiry_height` 0 means "never expires" (the codec's own convention).
 * Any non-zero value at or below the committed tip produces an envelope
 * the production path will judge EXPIRED, which is what §13k needs. */
static void p3c_make_env(nodus_witness_t *w, const p3c_chain_t *cx,
                         uint8_t tag, uint64_t expiry_height,
                         p3c_env_t *out) {
    memset(out, 0, sizeof(*out));

    /* The CONTEXTUAL ruleset identity is read from the committed registry
     * — the same place nodus_witness_v2_entry_verdict reads it. A
     * hand-picked version/hash would make the two derivations disagree
     * and the production helper would answer ERR_CTX_*, not "committed". */
    /* Zeroed for p3c_build_manifest's reason: p3c_die exits, but it is not
     * declared noreturn, so a compiler that has not inferred that still
     * sees the reads below. */
    dna_domain_manifest_t sys;
    memset(&sys, 0, sizeof(sys));
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL) != 0) {
        p3c_die("SYSTEM manifest");
        return;
    }

    uint8_t call[32], auth[16];
    memset(call, tag, sizeof(call));
    memset(auth, (uint8_t)(tag ^ 0xFF), sizeof(auth));

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version      = sys.ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_CC_V1;
    leg.hdr.call_len             = (uint32_t)sizeof(call);
    leg.hdr.auth_len             = (uint32_t)sizeof(auth);
    leg.hdr.res_max_effects      = 4;
    leg.hdr.res_max_effect_bytes = 4096;
    leg.call_data = call;
    leg.auth_data = auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = expiry_height;
    in.fee_amount          = 0;
    in.res_max_total_units = 200000;
    in.leg_count           = 1;
    in.legs                = &leg;

    size_t need = 0;
    if (dna_env_encoded_size(&leg, 1, &need) != 0 || need == 0) {
        p3c_die("env size");
        return;
    }
    out->bytes = malloc(need);
    if (!out->bytes) { p3c_die("env alloc"); return; }
    size_t used = 0;
    if (dna_env_encode(&in, out->bytes, need, &used) != 0 || used != need)
        p3c_die("env encode");
    out->len = used;

    uint64_t tip = 0;
    if (nodus_witness_v2_tip_height(w, &tip) != 0) p3c_die("v2 tip");

    /* THE HEIGHT USED HERE IS FOR THE DERIVATION ONLY, and for an expired
     * envelope it deliberately is NOT the production candidate.
     *
     * intent_id is height-independent — the height enters dna_env_preflight
     * at exactly one place, the expiry comparison (env_preflight.h step 3)
     * — so preflighting at a height where this envelope is still valid
     * yields the SAME intent_id the production path derives at tip + 1.
     * That is what lets the fixture build an envelope which is expired
     * from the chain's point of view while still learning its identity.
     * `expiry_height == H` is accepted by the locked rule (only
     * `expiry_height < H` rejects), so the expiry height itself is the
     * natural choice. */
    uint64_t pf_height = tip + 1;
    if (expiry_height != 0 && expiry_height < tip + 1)
        pf_height = expiry_height;

    dna_env_leg_ctx_t lctx;
    lctx.domain_id       = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, DNA_ENV_RULESET_HASH_LEN);

    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));   /* ~15 KB — heap */
    if (!pf) { p3c_die("preflight alloc"); return; }
    if (dna_env_preflight(out->bytes, out->len, cx->chain_id, pf_height,
                          &lctx, 1, pf) != DNA_ENV_PF_OK) {
        free(pf);
        p3c_die("env preflight");
        return;
    }
    memcpy(out->intent_id, pf->intent_id, 64);
    free(pf);
}

/* Record an intent as COMMITTED, the way the apply engine's index phase
 * does. tx_id is UNIQUE in the schema, so each call needs its own. */
static void p3c_commit_intent(nodus_witness_t *w, const uint8_t intent[64],
                              uint8_t tx_tag, uint64_t height) {
    uint8_t txid[64];
    memset(txid, tx_tag, sizeof(txid));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_intent_index (intent_id, tx_id, global_height, "
            "global_index) VALUES (?1, ?2, ?3, 0)", -1, &st, NULL)
        != SQLITE_OK) {
        p3c_die("intent insert prepare");
        return;
    }
    sqlite3_bind_blob(st, 1, intent, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, txid, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) p3c_die("intent insert");
}

/* Ask the index DIRECTLY. §13f's anti-vacuity discipline: both answers
 * are pinned here before any production predicate is consulted, so a
 * fixture whose index was empty (or whose migration never ran) cannot
 * make "not committed" look like a verdict. */
static bool p3c_intent_in_index(nodus_witness_t *w, const uint8_t intent[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_intent_index WHERE intent_id = ?1",
            -1, &st, NULL) != SQLITE_OK) {
        p3c_die("intent probe prepare");
        return false;
    }
    sqlite3_bind_blob(st, 1, intent, 64, SQLITE_TRANSIENT);
    bool found = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return found;
}

/* A heap mempool entry carrying the envelope bytes, in EXACTLY the shape
 * the successor intake produces: class 200, nullifier_count 0, forwarded,
 * no client connection. */
static nodus_witness_mempool_entry_t *p3c_env_entry(const p3c_env_t *e,
                                                    uint64_t fee) {
    nodus_witness_mempool_entry_t *m = calloc(1, sizeof(*m));
    if (!m) { p3c_die("env entry alloc"); return NULL; }
    if (qgp_sha3_512(e->bytes, e->len, m->tx_hash) != 0)
        p3c_die("env entry hash");
    m->tx_type         = NODUS_W_TX_V2_ENVELOPE;
    m->nullifier_count = 0;
    m->tx_data = malloc(e->len);
    if (!m->tx_data) { p3c_die("env entry bytes"); return NULL; }
    memcpy(m->tx_data, e->bytes, e->len);
    m->tx_len       = (uint32_t)e->len;
    m->fee          = fee;
    m->is_forwarded = true;
    m->client_conn  = NULL;
    return m;
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
        /* ⚠ current_view IS THE ASSERTION HERE. `view_change_voted` was
         * NOT, historically: a mutation campaign showed that with the
         * floor removed the node voted, its self-record completed the
         * quorum of 2, and bft_vc_check_quorum CLEARED view_change_voted
         * on its way out — so the flag read false either way and could
         * not discriminate. O15N Faz 2C2 moved that clear into
         * bft_view_move_finish, which now runs only at the proof site, so
         * on this pre-genesis fixture (no committee → no statement can be
         * signed → no proof) the flag WOULD stay true under that
         * mutation and the second assertion has become discriminating
         * again. It is kept either way; the first is the one that must
         * never be reducible to a flag. What must be impossible is the
         * OUTCOME: one message from one peer moving this node into a new
         * view. */
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
            sign_prepared(sigs[i].signature, &m[i], VIEW, H, cert_hash,
                          w->chain_id);
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
        sign_prepared(mixed[4].signature, &outsider, VIEW, H, cert_hash,
                      w->chain_id);
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

        /* The honest cluster still reaches its quorum, exactly as if the
         * attacker had never spoken. */
        fill_viewchg(&vc, w, &honest[4], 1);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "fifth honest vote at view 1");
        CHECK(tally_at(w, 1) >= w->bft_config.quorum,
              "the tally at view 1 reached QUORUM, attack notwithstanding — "
              "which is what D9 exists to protect and what this section "
              "measures");
        /* ⚠ O15N Faz 2C2 CHANGED WHAT COMES NEXT, TWICE, AND THE SECOND
         * CHANGE IS THE ONE TO READ.
         *
         * Originally this read `w->current_view == 1`, because reaching
         * quorum WROTE the counter on the spot. Faz 2C2 removed that
         * write, and a first draft of this file inverted the assertion
         * to `== 0` on the reasoning that this no-DB fixture has an
         * EMPTY committee, so no VIEW_OK can be signed and no proof can
         * exist. That reasoning was correct about the code as written —
         * and it was encoding a HALT as expected behaviour: on a
         * pre-genesis chain the view could then never move at all, so a
         * fresh cluster whose genesis round landed on a silent leader
         * could never rotate away from it.
         *
         * That is now fixed. When no committee exists at the height,
         * sign_view_ok answers 1 (a committed "there is nobody to
         * certify against") rather than -1, and bft_vc_check_quorum
         * takes the PRE-GENESIS BOOTSTRAP path: the node's own observed
         * quorum moves the view, exactly as it did before Faz 2C2, on
         * the same gossip-roster authority this tree already documents
         * for leader election and prepared-cert resolution in this same
         * window. So the ORIGINAL assertion is correct again, and it is
         * restored here deliberately rather than by accident.
         *
         * The tally above is D9's subject; §15 owns the counter under a
         * real committee, where the proof rule is the only rule. */
        CHECK(w->current_view == 1,
              "the counter moved on the PRE-GENESIS BOOTSTRAP path — with "
              "no committee to certify against, the node's own observed "
              "quorum is the authority, and a fresh cluster can still "
              "rotate off a silent genesis leader");
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
                          CV, CH, cert_hash, w->chain_id);
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
         * check_timeout is called — bft_vc_check_quorum is
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
         * phase: the reset at the round-equality reset in handle_commit requires the round numbers
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

    /* ── §11c — a view change JOINED FROM IDLE survives the tick ──────
     *
     * WHAT IT PROVES — two properties of the SAME entry, either of which
     * alone would silence a joiner:
     *
     *   P1(a), the HEIGHT. handle_viewchg has no phase gate, so its f+1
     *     join can pull a node in straight from IDLE. An IDLE node's
     *     round_state still carries the height it LAST worked on — which
     *     is <= the committed tip — so without the normalization inside
     *     nodus_witness_bft_initiate_view_change the joiner enters
     *     VIEW_CHANGE already matching the P1 release's condition and the
     *     very next tick throws it back out. It would be silenced exactly
     *     as O15C-C D1 silenced it, one mechanism further along.
     *
     *   O15M, the CLOCK. That same entry inherits whatever
     *     phase_start_time its last round left behind, and of the five
     *     callers of initiate_view_change the f+1 join is the ONE that
     *     does not stamp the clock itself before calling. If
     *     initiate_view_change does not stamp it either, the escalation
     *     branch measures this view change's age from the finished round,
     *     finds the 10 s budget already spent, and walks the TARGET away
     *     from the one the cluster is converging on — the O15H D2 shape,
     *     reached through the join door.
     *
     * WHAT IT REQUIRES: nothing beyond a default build. No compile flag
     * (no QGP_FAULT_INJECT, no DNAC_EPOCH_LENGTH override) and no
     * environment variable (no STAGEF_*, no NODUS_FAULT_*). The two
     * budgets are the fixture's own arguments — round 15000 / viewchg
     * 10000, the production relationship — and the chain is this
     * section's own temporary database.
     *
     * WHAT IT LEAVES BEHIND: nothing. chain_db_drop removes the
     * /tmp/test_bft_p1_join_* directory and frees the witness. No node is
     * restarted, no file is armed, no process-wide state is touched.
     *
     * HOW IT CAN LIE, two ways, both closed below:
     *   - If the f+1 join never fires, the tick has no view change to
     *     escalate and every assertion here passes vacuously. The two
     *     CHECKs immediately after the join loop are the anti-vacuity
     *     guards — we actually voted, and the phase actually moved — and
     *     they MUST stay in front of the tick.
     *   - If the clock were aged by less than a second it would be
     *     invisible: time_ms() is nodus_time_now()*1000, so a sub-second
     *     offset rounds away and the escalation would not fire even on
     *     the parent tree. The age below is whole seconds for that
     *     reason. ──────────────────────────────────────────────────── */
    printf("§11c — a view change joined from IDLE is not released\n");
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
         * (the round-equality reset in handle_commit) puts the phase back to IDLE but leaves the
         * finished round's height in round_state — so block_height == T
         * == tip, which is exactly the shape the release matches. */
        memset(&w->round_state, 0, sizeof(w->round_state));
        w->round_state.round = 6;
        w->round_state.block_height = T;
        w->round_state.phase = NODUS_W_PHASE_IDLE;
        /* AGE THE CLOCK PAST THE VIEW-CHANGE BUDGET, BEFORE THE JOIN.
         * This is what makes the section discriminate. On the parent
         * tree nothing on the join path stamps the phase clock, so the
         * joiner INHERITS this aged value and the tick below computes
         * elapsed == 12000 > the 10000 ms view-change budget: the
         * escalation fires and moves the target off 1. With the O15M
         * stamp at view-change entry, the joiner starts a fresh window
         * instead and the same tick escalates nothing.
         *
         * 12000 is a whole number of seconds because time_ms() has
         * ONE-SECOND resolution (nodus_time_now()*1000 — see age_phase's
         * own note): a sub-second offset would be invisible and this
         * section would then pass on BOTH trees. It clears the 10000 ms
         * budget by two full seconds and stays under the 15000 ms round
         * budget, so no assertion here rides on a margin. */
        age_phase(w, 12000);

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

        /* ⚠ DISCRIMINATING ASSERTION #1 — P1(a), the HEIGHT. Without the
         * normalization the joiner keeps the committed height T here,
         * and `tip >= block_height` is already true before it has said a
         * word. */
        CHECK(w->round_state.block_height == T + 1,
              "P1(a) re-anchored the joined view change at tip+1");

        nodus_witness_bft_check_timeout(w);

        /* ⚠ DISCRIMINATING ASSERTION #2 — O15M, the CLOCK, and it is the
         * only assertion in this section that separates the two trees on
         * the stamp. On the parent tree the joiner inherits the 12 s-old
         * stamp aged above, the escalation branch finds
         * `elapsed > viewchg_timeout_ms` and moves the target 1 -> 2, so
         * THIS LINE FAILS THERE. It can only pass because
         * nodus_witness_bft_initiate_view_change now stamps
         * phase_start_time at view-change entry, beside the write that
         * moves the phase.
         *
         * The target is what has to be asserted, for the reason §1
         * already records: escalation leaves the phase at VIEW_CHANGE and
         * re-self-records, so phase, in_progress and voted all look
         * healthy either way. Only the target moves — and a view change
         * that silently advances its target can never accumulate a
         * quorum. */
        CHECK(w->view_change_target == 1,
              "the tick did NOT escalate — the joiner's window started at "
              "the join, not at the round that ended before it");

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
        /* O15N Faz 2C2 — a view cannot move without a committee to sign
         * statements under. See vok_seed_committee. */
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

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
              "current_view is UNTOUCHED — only a verified VIEW_OK proof "
              "may advance it");
        CHECK(w->view_change_in_progress && w->view_change_voted,
              "and we actually voted, so peers can count us");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "the spent deadline disarmed — it must not re-fire every tick");
        /* The D2 discipline: while the phase is VIEW_CHANGE,
         * phase_start_time must be the age of the CURRENT target's
         * window, never one inherited from a round that ended long ago —
         * otherwise the escalation branch spends the whole budget on the
         * first tick and walks the target forever. Since O15M,
         * initiate_view_change stamps the clock itself beside the phase
         * write; P2's own stamp before the call covers the one state that
         * entry cannot reach, the early return on flags left true by a
         * dead episode. The assertion below is the same property either
         * way, asked of the STATE rather than of a code path. */
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
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

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
     * leader while already armed (as of O15N Faz 2C2 that is a verified
     * VIEW_OK proof arriving under an IDLE node — handle_newview's
     * accept, which this used to name, no longer writes the view, and
     * the IDENT view adoption was DELETED in v0.19.24). ─────────────── */
    printf("§12c P2 — the new leader neither arms nor fires\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p2_leader_XXXXXX";
        chain_db_open(w, dir, 0x23);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

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
         * a state the arm site cannot produce, but a verified VIEW_OK
         * proof can: it moves current_view under an IDLE node, so a node
         * armed as a follower can BECOME the leader while still armed. */
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

    /* ── §12d — O15N Faz 2C2: A NEW_VIEW DOES NOT MOVE THE COUNTER ────
     *
     * ⚠ THIS SECTION USED TO ASSERT THE OPPOSITE, AND THAT IS THE POINT.
     * It read "NEW_VIEW re-arms when it binds a reproposal, disarms when
     * it does not", and both legs turned on `w->current_view == V` after
     * the handler ran — i.e. on the `>` accept block ADVANCING the view
     * on ONE node's signature. That block is deleted. handle_newview has
     * no replay guard and cannot safely be given one (the measured O15M
     * note at the top of the handler), so a captured, validly-signed
     * NEW_VIEW frame could be re-sent at a chosen moment against a
     * chosen subset and move their views while others stayed put — with
     * `current_view` deciding leader election.
     *
     * WHAT IT ASSERTS NOW: the counter does not move, in EITHER
     * direction, however well-formed the message is. Both legs carry a
     * REAL verified prepared certificate so that "nothing happened"
     * cannot be an upstream rejection — the C5 adoption is the positive
     * control that proves the message was fully processed.
     *
     * The deadman rules that used to live in the `>` block are NOT
     * re-asserted here: they now exist only at `==`, which is §12e's
     * subject, and re-arming at `==` is deliberately forbidden (a
     * replayer could otherwise postpone the deadman forever). ───────── */
    printf("§12d — a NEW_VIEW above our view does NOT advance the "
           "counter, and one below does not lower it\n");
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
         * expected leader and the message would be refused before it
         * ever reached the code under test. */
        uint32_t V = p2_pick_view(w, false);
        const peer_t *leader = p2_leader_at(w, all, V);
        CHECK(memcmp(leader->id, w->my_id, NODUS_T3_WITNESS_ID_LEN) != 0,
              "the NEW_VIEW's leader is someone else, as the handler "
              "requires");
        CHECK(V > w->current_view,
              "and the view it names is ABOVE ours — the direction the "
              "deleted `>` accept used to follow");

        /* ── LEG 1: a fully valid, higher NEW_VIEW. */
        nodus_t3_msg_t nv;
        p2_fill_newview(&nv, w, leader, V);
        p2_add_reproposal(&nv, all, (int)w->bft_config.quorum, tip + 1, 0,
                          tx_hash, w->chain_id);
        uint32_t view_before = w->current_view;
        w->awaiting_propose_deadline_ms = 0;
        CHECK(nodus_witness_bft_handle_newview(w, &nv) == 0,
              "the NEW_VIEW carrying a verifiable prepared cert is "
              "processed, not bounced");
        /* ⚠ THE ASSERTION THIS SECTION EXISTS FOR. */
        CHECK(w->current_view == view_before,
              "current_view did NOT move — one leader's signature can no "
              "longer install a view; only a verified VIEW_OK proof can");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "and the deleted block's re-arm did not survive: a message "
              "that cannot advance the view must not start a window for a "
              "PROPOSE that will now never be accepted");

        /* ── LEG 2, THE OPEN-2 DIRECTION: a NEW_VIEW BELOW our view.
         * Reached by moving to a proven view first, so "below" is a real
         * state rather than an impossible one. */
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

        /* BOTH views are chosen at runtime and BOTH must be views we do
         * NOT lead, or the message would be refused as non-leader and
         * "the counter did not move" would be an upstream bounce rather
         * than the rule under test. Searching for the PAIR (rather than
         * picking one and hoping a lower one exists) is what stops this
         * from silently degenerating to VL == VH == 0. */
        uint32_t VL = 0, VH = 0;
        {
            bool found = false;
            uint32_t lim = w->roster.n_witnesses * 2 + 2;
            for (uint32_t a = 1; a <= lim && !found; a++) {
                if (p2_is_leader_at(w, a)) continue;
                for (uint32_t b = a + 1; b <= lim && !found; b++) {
                    if (p2_is_leader_at(w, b)) continue;
                    VL = a; VH = b; found = true;
                }
            }
            CHECK(found, "found a PAIR of views, both led by someone else, "
                         "with one strictly below the other");
        }
        p2_complete_vc(w, &p[0], &p[1], VH);
        CHECK(w->current_view == VH && VH > VL,
              "we hold a PROVEN view strictly above VL, so a lower "
              "NEW_VIEW is a state that can actually occur");

        const peer_t *leader_low = p2_leader_at(w, all, VL);
        CHECK(memcmp(leader_low->id, w->my_id, NODUS_T3_WITNESS_ID_LEN) != 0,
              "and the lower view's leader is someone else, so the "
              "message reaches the rule under test");
        p2_fill_newview(&nv, w, leader_low, VL);   /* no reproposal */
        uint32_t held = w->current_view;
        CHECK(nodus_witness_bft_handle_newview(w, &nv) == 0,
              "the lower NEW_VIEW is processed");
        CHECK(w->current_view == held,
              "and the counter did NOT go backwards — the regression "
              "direction, which no code path may take");

        chain_db_drop(w, dir);
    }

    /* ── §12e — the `==` path, which is now the ONLY one ──────────────
     *
     * O15C-D.1 measured that every node reaches the new view on its own
     * evidence before the leader's NEW_VIEW lands, so `new_view ==
     * current_view` and any `>`-guarded block is a silent no-op — 7/7
     * nodes advanced with ZERO logged "accepted NEW_VIEW".
     *
     * ⚠ AS OF O15N Faz 2C2 THIS IS NOT MERELY THE COMMON PATH, IT IS THE
     * ONLY PATH THAT DOES ANYTHING. NEW_VIEW no longer writes the view
     * (§12d), so the C5 adoption and the P2 disarm asserted below are
     * the handler's entire remaining effect. If the disarm lived
     * anywhere else, a node that had just been moved by a proof would
     * arm, receive the live leader's NEW_VIEW, never disarm, and on a
     * quiet chain (no mempool → no PROPOSE is due) fire after one window
     * → rotate → arm again: permanent view churn behind a perfectly
     * healthy leader. This section is that path. ────────────────────── */
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
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);
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
        /* ⚠ THE CERT'S QUORUM IS THE COMMITTEE'S, NOT `bft_config`'s, AND
         * THE DIFFERENCE IS THE RULE — NOT A FIXTURE BUG.
         *
         * This once read `(int)w->bft_config.quorum` and shipped THREE
         * signatures at a gate that wanted FOUR, so the NEW_VIEW was
         * refused for a reason that has nothing to do with what §12e
         * measures. `verify_prepared_cert` derives its threshold from the
         * committee governing the cert's HEIGHT (`dna_bft_quorum(c_count)`)
         * — the O15H C5 rule, installed precisely because measuring a cert
         * formed under one committee against another node's current quorum
         * discards values that may already have committed.
         * `w->bft_config.quorum` is a different authority and answering a
         * cert question with it is the defect that rule removed.
         *
         * The committee seeded above has FIVE members, so the number is
         * dna_bft_quorum(5). Spelled from the seed rather than read back
         * from the witness, so a fixture that silently seeded a different
         * set fails here instead of quietly agreeing with itself. */
        p2_add_reproposal(&nv, all, (int)dna_bft_quorum(5), tip + 1, 0,
                          tx_hash, w->chain_id);
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
              "in VIEW_CHANGE the clock is the CURRENT target's window, "
              "never one inherited from a round that already ended)");
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

    /* ── §13e — P3(b) INTAKE on LEGACY: the verdict is ADMISSION's ────
     *
     * ⚠ REWRITTEN FOR O15K, NOT PATCHED, AND THE OLD SECTION'S POINT NO
     * LONGER EXISTS. What stood here offered ONE set of bytes at two
     * views and pinned the difference to the LEADERSHIP TEST: leg 1
     * refused because we were not the leader, leg 2 accepted because we
     * were. Its leg 2 therefore PROVED that a legacy leader pools
     * structurally-walkable but cryptographically UNVERIFIED bytes —
     * V-1, a defect live on the devnet, asserted as a requirement. And
     * its leg 1 rationale ("the legacy intake at this site is structural
     * only … so pooling there would widen a trust boundary") became the
     * argument FOR §3.2 rather than against it.
     *
     * Flipping leg 2's expectation to -1 was rejected: with both legs at
     * -1 the two refusals are indistinguishable by return value, and the
     * section's whole subject — telling a LEADERSHIP refusal apart from a
     * BYTE refusal — is destroyed. So the subject is re-founded on what
     * O15K makes true, and the observable that separates the two answers
     * is w->mempool.count, not a return code:
     *
     *   the answer a legacy forward gets is ADMISSION's, and it is the
     *   SAME from both roles.
     *
     * Legs 1 and 2 offer the IDENTICAL unverifiable bytes at both views,
     * so a difference between them could only come from leadership; leg 3
     * is the POSITIVE CONTROL that stops "refused twice" from meaning
     * "this node refuses everything", and it is the assertion that
     * distinguishes the two refusals — the pool MOVES for admissible
     * bytes and does not move for these.
     *
     * The successor half of the same statement is §13e2's; §13m and §13n
     * carry the two legacy halves separately, each anchored to its own
     * defect. ────────────────────────────────────────────────────────── */
    printf("§13e P3(b) — a LEGACY forward gets ADMISSION's verdict, the "
           "same one from both roles\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        peer_t client; peer_make(&client);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_legacy_XXXXXX";
        chain_db_open(w, dir, 0x35);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor,
              "this fixture is a LEGACY chain — the lane O15K opens");

        /* The unverifiable transaction is structurally PERFECT: correct
         * wire version, correct committed_fee, a funded input, a parseable
         * signer section. The ONE thing wrong with it is that the
         * signature does not verify — so a refusal below can only have
         * come from Check 3, and never from the wire layout. */
        p3l_tx_t bad, good;
        p3l_make(w, &client, 0x35, 1, false, &bad);
        p3l_make(w, &client, 0x36, 1, true,  &good);
        p3l_fund(w, &client, &bad);
        p3l_fund(w, &client, &good);
        CHECK(p3l_funded(w, &bad) && p3l_funded(w, &good),
              "BOTH inputs are really in the committed UTXO set — so a "
              "refusal below is never 'UTXO not found', which would read "
              "exactly like the pre-O15K gate declining");
        CHECK(memcmp(bad.hash, good.hash, NODUS_T3_TX_HASH_LEN) != 0,
              "and the two carry DIFFERENT tx_hashes, so mempool_add's "
              "duplicate rejection can never stand in for a refusal");

        /* ONE message object, re-filled per leg. nodus_t3_msg_t's union is
         * dominated by the 128-slot certificate arrays, so it is a large
         * stack object; bft_p3_broadcast_demand hoists a single one out of
         * its loop for exactly this reason and every section here keeps
         * that property. */
        nodus_t3_msg_t fm;

        /* LEG 1 — NON-leader, unverifiable bytes. */
        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        p3l_fwd(&fm, &bad, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == -1,
              "a non-leader refuses bytes whose signature does not verify");
        CHECK(w->mempool.count == 0, "and pooled nothing");

        /* LEG 2 — the SAME bytes, the only change being leadership. This
         * is the leg the fix turns from ACCEPT to REFUSE: today this call
         * returns 0 and the pool holds one entry no node has verified. */
        w->current_view = p2_pick_view(w, true);
        CHECK(nodus_witness_bft_is_leader(w), "we ARE the leader now");
        p3l_fwd(&fm, &bad, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == -1,
              "the LEADER refuses the IDENTICAL bytes — the verdict on a "
              "legacy forward is admission's, not leadership's");
        CHECK(w->mempool.count == 0,
              "and pooled nothing either: one mempool, ONE intake gate");

        /* LEG 3 — THE POSITIVE CONTROL. Without it legs 1-2 are satisfied
         * by a node that refuses everything, which is precisely what the
         * pre-O15K non-leader did and what a mis-placed verify would do to
         * both roles. The pool MOVING is the discriminator. */
        p3l_fwd(&fm, &good, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "an ADMISSIBLE forward is accepted");
        CHECK(w->mempool.count == 1,
              "and POOLED — so legs 1-2 refused THESE BYTES, not every "
              "byte; the difference between the two answers is the "
              "cryptography, which is the only difference between the "
              "two transactions");
        CHECK(memcmp(w->mempool.entries[0]->tx_hash, good.hash,
                     NODUS_T3_TX_HASH_LEN) == 0,
              "and the single pooled entry is the VALID one — the "
              "unverifiable transaction is nowhere in the pool");

        p3l_free(&bad);
        p3l_free(&good);
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

        /* ── ⚠ WHY THIS BUILDS A REAL SUCCESSOR AND DOES NOT JUST SET THE
         *      FLAG — the shortcut this section used to take. ───────────
         *
         * What stood here was:
         *
         *     uint64_t tip = seed_blocks(w, 3);   // LEGACY blocks table
         *     w->v2_successor    = true;          // ...claim it is V2
         *     w->v2_ingress_armed = true;
         *
         * — a chain seeded through the LEGACY `blocks` table, then
         * declared a V2 successor by hand. `v2_blocks` was never created,
         * so the object this section described did not exist. THAT STATE
         * IS NOT PRODUCTION-REACHABLE: nodus_witness.c:756-762 sets
         * v2_successor only when nodus_witness_v2_gen_is_pure() answers 1,
         * and :744-751 refuses the database outright when that probe
         * faults. A real successor HAS a v2_blocks table.
         *
         * WHY IT PASSED ANYWAY, until it didn't. Every read of the chain
         * height went through nodus_witness_block_height, which answered 0
         * for "no such table: v2_blocks" exactly as it answered 0 for an
         * empty chain. The missing table was therefore INVISIBLE — the
         * fixture looked like a successor at genesis. O15O Faz 1 made that
         * read report the fault instead of absorbing it, is_leader now
         * declines to lead when it cannot read its height, and
         * p2_pick_view could no longer find any view where this node
         * leads. The failure was the fixture's, surfaced by the accessor.
         *
         * ⚠ SECOND TIME, SAME SHORTCUT. nodus_witness.c:735-739 records
         * the first: "the first non-bootstrap epoch halts because the
         * committee seed reads the empty `blocks` table. Review R2 found
         * it; the season's own test had MASKED it by hard-setting the flag
         * after create_chain_db." Do not hard-set v2_successor. Build the
         * chain — p3c_make_successor installs the V2 schema
         * (nodus_witness_db_migrate_v2s9), seeds the validator set,
         * commits a real V2 genesis and derives the chain id through the
         * production path, which is what the other §13e sections already
         * do. The chain is left AT genesis, so the v2 tip is 0 and the
         * candidate height is 1; nothing below depends on a deeper tip. */
        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));   /* ~25 KB — heap */
        if (!cx) { fprintf(stderr, "p3c chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);

        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR");
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

        free(cx);
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

    /* ── §13g — V3: a pool of entries the chain has ALREADY DECIDED is
     *            not demand ──────────────────────────────────────────
     *
     * THE COVERAGE bft_p3_live_demand never had. §13b proves an EMPTY
     * pool does not fire, but an empty pool never reaches the predicate
     * at all — the outer `mempool.count > 0` gate takes the disarm
     * branch. Nothing anywhere held a NON-EMPTY pool whose every entry
     * was decided at an aged window, which is the single state the
     * predicate exists to distinguish. Delete `bft_p3_live_demand(w) &&`
     * from the fire condition and every other §13 section still passes;
     * this one fails.
     *
     * THE ANTI-VACUITY ASSERTION is the tip_since_ms re-stamp, §13d's
     * device: "still IDLE" is also what a node that never reached the
     * decision looks like. The re-stamp happens at the top of the
     * would-fire branch (before the predicate), so seeing it proves the
     * verdict was actually taken and the ONLY thing that stopped the
     * rotation was the predicate's answer. ────────────────────────── */
    printf("§13g P3 — a pool whose entries are ALL already decided is not "
           "demand\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_stale_XXXXXX";
        chain_db_open(w, dir, 0x38);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "P2 is NOT armed — any rotation below is attributable to P3");
        CHECK(w->pending_forward_count == 0,
              "and NO pending forward — that alone would answer 'live' "
              "unconditionally and make this section vacuous");

        p3_pool(w, p3_mkentry(0x91, 500, 1));
        p3_pool(w, p3_mkentry(0x92, 100, 2));
        CHECK(w->mempool.count == 2,
              "TWO entries pooled — the pool is NOT empty, so this is not "
              "§13b's disarm path");

        uint8_t n1[NODUS_T3_NULLIFIER_LEN], n2[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0x91, n1);
        p3_nul_of(0x92, n2);
        uint8_t ctx[NODUS_T3_TX_HASH_LEN];
        memset(ctx, 0x91, sizeof(ctx));
        CHECK(nodus_witness_nullifier_add(w, n1, ctx) == 0,
              "the first entry's nullifier is COMMITTED");
        memset(ctx, 0x92, sizeof(ctx));
        CHECK(nodus_witness_nullifier_add(w, n2, ctx) == 0,
              "the second entry's nullifier is COMMITTED too — EVERY entry "
              "in the pool is now decided");

        /* ⚠ THE ANTI-VACUITY PAIR, §13f's. nullifier_exists is fail-closed,
         * so a fixture with no usable DB answers "spent" to everything and
         * would produce this section's verdict for entirely the wrong
         * reason. The negative control is what rules that out. */
        uint8_t n_never[NODUS_T3_NULLIFIER_LEN];
        memset(n_never, 0x9F, sizeof(n_never));
        CHECK(nodus_witness_nullifier_exists(w, n1) &&
              nodus_witness_nullifier_exists(w, n2),
              "the DB really says both pooled entries are spent");
        CHECK(!nodus_witness_nullifier_exists(w, n_never),
              "and really says an uncommitted nullifier is NOT — so the DB "
              "is discriminating, not failing closed on everything");

        /* TICK 1 arms the window; TICK 2, a full round later, decides. */
        nodus_witness_bft_check_timeout(w);
        CHECK(w->last_seen_tip == tip, "the window is anchored at the tip");
        p3_age_window(w, 16000);
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — a pool of SETTLED work is not a "
              "reason to rotate away from a healthy leader");
        CHECK(!w->view_change_in_progress && !w->view_change_voted,
              "no view change was started and no vote was cast");
        /* ⚠ THE DISCRIMINATING LINE. Without it, deleting the predicate
         * from the fire condition would still have to be caught by the
         * IDLE assertion alone — and a node that never reached the
         * decision is also IDLE. This proves the branch RAN. */
        CHECK(p3_stamped_now(w->tip_since_ms),
              "and the would-fire point WAS reached (the window was "
              "re-stamped) — the rotation was declined on the predicate's "
              "verdict, not skipped");
        CHECK(w->mempool.count == 2,
              "check_timeout evicts nothing — the reaper is the tick's job, "
              "so the next section starts from the same pool shape");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13h — V3 converse: ONE undecided entry is still demand ──────
     *
     * WITHOUT THIS SECTION §13g PASSES TRIVIALLY for a predicate that
     * always answered false — which would be a worse bug than the one
     * §13g pins, because it disables the whole P3 deadman. The fixture is
     * §13g's, one extra entry, and that entry is the only difference.
     * ──────────────────────────────────────────────────────────────── */
    printf("§13h P3 converse — ONE undecided entry in an otherwise settled "
           "pool still rotates\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_p3_onelive_XXXXXX";
        chain_db_open(w, dir, 0x3D);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0, "P2 is NOT armed");
        CHECK(w->pending_forward_count == 0, "and NO pending forward");

        p3_pool(w, p3_mkentry(0x91, 500, 1));   /* decided, as in §13g */
        p3_pool(w, p3_mkentry(0x93, 100, 1));   /* THE ONE DIFFERENCE   */
        CHECK(w->mempool.count == 2, "two entries pooled");

        uint8_t n1[NODUS_T3_NULLIFIER_LEN], n_live[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0x91, n1);
        p3_nul_of(0x93, n_live);
        uint8_t ctx[NODUS_T3_TX_HASH_LEN];
        memset(ctx, 0x91, sizeof(ctx));
        CHECK(nodus_witness_nullifier_add(w, n1, ctx) == 0,
              "the FIRST entry's nullifier is committed, exactly as §13g");
        CHECK(nodus_witness_nullifier_exists(w, n1),
              "and the DB confirms it");
        CHECK(!nodus_witness_nullifier_exists(w, n_live),
              "while the SECOND entry is genuinely still includable — this "
              "is the only thing that differs from §13g");

        nodus_witness_bft_check_timeout(w);
        CHECK(w->last_seen_tip == tip, "the window is anchored at the tip");
        p3_age_window(w, 16000);
        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "it DID rotate — so §13g's silence is the predicate finding "
              "no live entry, not the predicate being dead");
        CHECK(w->view_change_target == view_before + 1,
              "target is the ordinary current_view + 1");
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13i — V1: a COMMITTED successor envelope is neither demand nor
     *            a permanent resident ────────────────────────────────
     *
     * THE WORST OF THE THREE DEFECTS. A follower pools a successor
     * class-200 envelope with nullifier_count == 0 (the legacy nullifier
     * walk is gated on !v2_successor), and NOTHING could ever remove it:
     * pop_batch is leader-only, remove_by_conn needs a client_conn a
     * forwarded entry does not have, mempool_clear is teardown, and the
     * reaper's nullifier loop never even executed for it. bft_p3_live_
     * demand then answered "live" for it unconditionally — so once the
     * chain went quiet, that one follower initiated a view change every
     * round_timeout_ms FOREVER against a perfectly healthy leader, and
     * with 1 < f+1 nobody joined.
     *
     * Both call sites are exercised HERE, in one fixture, because the
     * whole point of V1 is that they agree: what the reaper deletes must
     * not be demand, and what it keeps must be.
     *
     * THE SURVIVAL HALF IS WHAT MAKES IT DISCRIMINATING. A helper that
     * always answered "committed" would silence P3 and empty the pool —
     * and would pass every "the settled one is gone" assertion on its
     * own. So an UNCOMMITTED envelope is carried through both halves and
     * asserted to survive both. ───────────────────────────────────── */
    printf("§13i V1 — a committed-intent successor ENVELOPE is not demand "
           "and IS reaped; an uncommitted one survives both\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_v1_intent_XXXXXX";
        chain_db_open(w, dir, 0x3A);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));   /* ~25 KB — heap */
        if (!cx) { fprintf(stderr, "p3c chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);
        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR — the "
                               "only chain on which class-200 exists");
        /* Asserted rather than assumed: the genesis sequence above is a
         * lot of machinery, and if any of it refreshed bft_config the
         * 16000 ms ageing below would stop meaning "a full round". */
        CHECK(w->bft_config.round_timeout_ms == 15000 &&
              nodus_witness_bft_consensus_active(w),
              "the fixture's BFT config survived genesis, so the ageing "
              "below really does exceed one round");

        /* BOTH carry expiry_height 0 — never expires — and that is why
         * this section is INDEPENDENT of the tip, unlike §13k. Height
         * enters dna_env_preflight at exactly ONE place, the expiry
         * comparison (env_preflight.h step 3), and 0 "is accepted at
         * every H" (:192). So these two verdicts are the same whether
         * the chain sits at genesis (tip 0, candidate 1) or anywhere
         * later, and §13k's genesis problem cannot reach here. */
        p3c_env_t ea, eb;
        p3c_make_env(w, cx, 0x21, 0, &ea);   /* this one will be COMMITTED */
        p3c_make_env(w, cx, 0x22, 0, &eb);   /* this one will NOT be       */
        CHECK(memcmp(ea.intent_id, eb.intent_id, 64) != 0,
              "the two envelopes carry DIFFERENT intents — otherwise the "
              "survival half below would be testing one value twice");
        CHECK(nodus_witness_v2_classify_entry(ea.bytes,
                                              (uint32_t)ea.len) ==
              NODUS_W_TX_V2_ENVELOPE &&
              nodus_witness_v2_classify_entry(eb.bytes,
                                              (uint32_t)eb.len) ==
              NODUS_W_TX_V2_ENVELOPE,
              "and both classify as class-200 ENVELOPEs — the shape whose "
              "nullifier_count is 0 and which nothing could judge");

        p3c_commit_intent(w, ea.intent_id, 0xE1, 1);

        /* ⚠ THE ANTI-VACUITY PAIR. Pin BOTH index answers with a direct
         * query BEFORE consulting the production predicate: an empty
         * index — or a migration that never created the table — would
         * make "not committed" the answer for everything, and the
         * survival half would pass for the wrong reason. */
        CHECK(p3c_intent_in_index(w, ea.intent_id),
              "the index really holds the first envelope's intent");
        CHECK(!p3c_intent_in_index(w, eb.intent_id),
              "and really does NOT hold the second's — the index is live "
              "and discriminating");

        /* (0) THE PREDICATE ITSELF, before either consumer. The exact
         *     verdict is asserted, not just the collapsed boolean: an
         *     entry dropped as EXPIRED and one dropped as COMMITTED are
         *     different facts, and §13k depends on being able to tell
         *     them apart. */
        CHECK(nodus_witness_v2_entry_verdict(w, ea.bytes, (uint32_t)ea.len) ==
              NODUS_W_ENTRY_COMMITTED,
              "the production helper derives the SAME intent the index "
              "holds — the derivation matches consensus, not just itself");
        CHECK(nodus_witness_v2_entry_verdict(w, eb.bytes, (uint32_t)eb.len) ==
              NODUS_W_ENTRY_LIVE,
              "and answers LIVE — not merely 'not committed' — for the "
              "uncommitted one, so the fixture is judged, not unjudgeable");

        /* (a) NOT DEMAND — through nodus_witness_bft_check_timeout, the
         *     wired path, with ONLY the committed envelope pooled. */
        p3_pool(w, p3c_env_entry(&ea, 500));
        CHECK(w->mempool.count == 1, "the settled envelope is pooled");
        CHECK(w->mempool.entries[0]->nullifier_count == 0,
              "with nullifier_count 0 — the exact shape successor intake "
              "produces, and the shape the legacy predicate cannot judge");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0, "P2 is NOT armed");
        CHECK(w->pending_forward_count == 0, "and NO pending forward");

        nodus_witness_bft_check_timeout(w);
        uint64_t anchored = w->last_seen_tip;
        CHECK(p3_stamped_now(w->tip_since_ms),
              "the demand window armed on the non-empty pool");
        p3_age_window(w, 16000);
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — a SETTLED envelope is not demand. "
              "Pre-V1 this is the tick that rotated the view, and it did "
              "so again every round_timeout_ms forever");
        CHECK(!w->view_change_in_progress,
              "no view change was started against the healthy leader");
        CHECK(w->last_seen_tip == anchored && p3_stamped_now(w->tip_since_ms),
              "and the would-fire point WAS reached (window re-stamped at "
              "the same frozen tip) — declined on the verdict, not skipped");

        /* (b) STILL DEMAND — add the UNCOMMITTED envelope and it fires.
         *     This is what stops (a) passing for a helper that answered
         *     'committed' to everything. */
        p3_pool(w, p3c_env_entry(&eb, 100));
        CHECK(w->mempool.count == 2, "the uncommitted envelope joins it");
        p3_age_window(w, 16000);
        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "NOW it rotates — an envelope the chain has not committed is "
              "real demand, and P3 still catches a dead leader");
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");

        /* (c) THE REAPER, the other consumer, over the same two entries.
         *     Fee order puts the committed one at the head, so the
         *     survivor has to be MOVED — the compaction runs, as in §13f. */
        CHECK(w->mempool.entries[0]->fee == 500 &&
              w->mempool.entries[1]->fee == 100,
              "committed first, uncommitted behind it");
        int dropped = nodus_witness_mempool_evict_committed(w);
        CHECK(dropped == 1, "exactly ONE entry was evicted");
        CHECK(w->mempool.count == 1, "one survives");
        CHECK(w->mempool.entries[0]->fee == 100,
              "and it is the UNCOMMITTED one, compacted to the head — the "
              "survival half; a helper answering 'committed' to everything "
              "fails here");
        CHECK(w->mempool.entries[1] == NULL, "the vacated slot was cleared");
        CHECK(nodus_witness_mempool_evict_committed(w) == 0,
              "a second pass evicts nothing — the reaper reacts to the "
              "chain's verdict, not to being called");
        CHECK(w->mempool.count == 1, "and the survivor is still there");

        free(ea.bytes);
        free(eb.bytes);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13j — V2: a ZERO bft_config fires nothing ───────────────────
     *
     * nodus_witness_bft_config_init writes round_timeout_ms = 0 AND
     * viewchg_timeout_ms = 0 whenever n < NODUS_T3_MIN_WITNESSES, and
     * bft_config is never initialised at witness creation — so a calloc'd
     * witness carries all-zero until its first refresh. check_timeout has
     * no consensus-active guard of its own and the tick calls it
     * unconditionally.
     *
     * P2 and P3 are the first IDLE-branch actors to use those fields as
     * THRESHOLDS. At 0 an armed P2 deadline is already expired and
     * `now - tip_since_ms > 0` is true at the first one-second boundary,
     * so a non-leader would rotate every second and then escalate every
     * second. Both are gated on nodus_witness_bft_consensus_active — the
     * predicate that already decides whether this node may start a round
     * at all.
     *
     * EACH CASE CARRIES ITS OWN CONVERSE in the same fixture: restore a
     * real config and the IDENTICAL state fires. Without that, "still
     * IDLE" would not distinguish "the gate stopped it" from "this
     * fixture was never fire-ready", and the section would pass with the
     * gate deleted. ──────────────────────────────────────────────────── */
    printf("§13j V2 — a zero/uninitialised bft_config arms no IDLE-branch "
           "deadman (P2 and P3)\n");
    {
        /* ── case A: P2's armed deadline ─────────────────────────────── */
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_v2_zerocfg_p2_XXXXXX";
        chain_db_open(w, dir, 0x3B);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->mempool.count == 0 && w->pending_forward_count == 0,
              "and NOTHING is pending — so P3 cannot fire and every verdict "
              "below is attributable to P2");

        /* Exactly what bft_config_init writes below NODUS_T3_MIN_WITNESSES,
         * and exactly what a calloc'd witness carries before its first
         * refresh. */
        w->bft_config.quorum             = 0;
        w->bft_config.f_tolerance        = 0;
        w->bft_config.round_timeout_ms   = 0;
        w->bft_config.viewchg_timeout_ms = 0;
        CHECK(!nodus_witness_bft_consensus_active(w),
              "consensus is NOT active at this config");

        /* Armed AFTER the zeroing, for case B's reason: the whole sequence
         * under test runs at the zero config, never at the fixture's. */
        p2_expire(w);
        CHECK(w->awaiting_propose_deadline_ms != 0,
              "P2 IS armed and its deadline is in the past — the fire "
              "condition's other two tests are satisfied");

        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — a node that may not run a round may "
              "not rotate the view either");
        /* ⚠ THE DISCRIMINATING LINE for case A: the fire path ZEROES the
         * spent deadline before initiating, so a deadline that is still
         * set proves the fire path was not taken. */
        CHECK(w->awaiting_propose_deadline_ms != 0,
              "and the deadline was NOT spent — the fire path zeroes it, so "
              "this fails the moment the consensus_active gate is removed");
        CHECK(!w->view_change_in_progress, "no view change was started");

        /* THE CONVERSE, same fixture, same armed deadline: a real config
         * fires. This is what proves the silence above came from the gate
         * and not from an unarmable fixture. */
        w->bft_config.quorum             = 3;
        w->bft_config.round_timeout_ms   = 15000;
        w->bft_config.viewchg_timeout_ms = 10000;
        CHECK(nodus_witness_bft_consensus_active(w),
              "consensus is active again");
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "the IDENTICAL state now rotates — only the config changed");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "and the deadline WAS spent this time");

        chain_db_drop(w, dir);
    }
    {
        /* ── case B: P3's demand window ──────────────────────────────── */
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_v2_zerocfg_p3_XXXXXX";
        chain_db_open(w, dir, 0x3C);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "P2 is NOT armed — every verdict below is attributable to P3");

        /* LIVE demand: an entry whose nullifier the chain has NOT
         * committed. A settled entry would make this section vacuous —
         * removing the gate would not fire either, because
         * bft_p3_live_demand would answer false on its own. */
        p3_pool(w, p3_mkentry(0xA1, 100, 1));
        uint8_t na[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0xA1, na);
        CHECK(w->mempool.count == 1, "one entry pooled");
        CHECK(!nodus_witness_nullifier_exists(w, na),
              "and it is genuinely UNDECIDED — real demand, so the only "
              "thing that can stop the rotation is the config gate");

        w->bft_config.quorum             = 0;
        w->bft_config.f_tolerance        = 0;
        w->bft_config.round_timeout_ms   = 0;
        w->bft_config.viewchg_timeout_ms = 0;
        CHECK(!nodus_witness_bft_consensus_active(w),
              "consensus is NOT active at this config");

        /* The window is armed AFTER the zeroing, deliberately: on a
         * genuinely uninitialised witness the very first tick that sees a
         * non-empty pool arms, and the next one-second boundary fires. The
         * whole sequence under test therefore runs at the zero config,
         * never at the fixture's. */
        nodus_witness_bft_check_timeout(w);
        CHECK(w->last_seen_tip == tip,
              "the window armed at the tip — and it armed UNDER the zero "
              "config, which is the sequence an uninitialised witness runs");

        /* TWO seconds, not one: time_ms() has one-second granularity, so a
         * 1000 ms age would still read as "stamped now" afterwards and the
         * re-stamp assertion below could not tell the two worlds apart. */
        p3_age_window(w, 2000);
        CHECK(w->tip_since_ms + w->bft_config.round_timeout_ms <
              nodus_time_now() * 1000ULL,
              "and the window is now past a round_timeout_ms of ZERO — the "
              "age comparison is TRUE, which is the whole defect");

        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — at a zero timeout this would "
              "otherwise fire on every one-second boundary, forever");
        CHECK(!w->view_change_in_progress, "no view change was started");
        /* ⚠ THE DISCRIMINATING LINE for case B: the re-stamp sits ABOVE
         * the gate, so it proves the would-fire point was reached and the
         * gate is the only thing that declined. */
        CHECK(p3_stamped_now(w->tip_since_ms),
              "and the would-fire point WAS reached (window re-stamped) — "
              "so the silence is the gate's doing, not an unaged window");

        /* THE CONVERSE, same fixture, same entry. */
        w->bft_config.quorum             = 3;
        w->bft_config.round_timeout_ms   = 15000;
        w->bft_config.viewchg_timeout_ms = 10000;
        CHECK(nodus_witness_bft_consensus_active(w),
              "consensus is active again");
        p3_age_window(w, 16000);
        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "the IDENTICAL state now rotates — only the config changed");
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13k — V1 (second door): an EXPIRED envelope is FINISHED ─────
     *
     * THE RESIDUAL THE FIRST CUT OF V1 LEFT OPEN. That version collapsed
     * every non-OK preflight outcome to "not committed", which was right
     * for ERR_HASH and wrong for ERR_EXPIRED: an envelope whose
     * expiry_height fell below the candidate could never commit, could
     * never be judged committed, and so was never evicted and counted as
     * live demand forever — the identical churn V1 exists to remove,
     * reached through a different status code.
     *
     * WHY EXPIRY IS A VERDICT AND ERR_HASH IS NOT — the source draws the
     * line, this section only pins it. env_preflight.h:91 defines
     * ERR_EXPIRED as "expiry_height below the candidate", a property of
     * the envelope's own committed bytes against a tip that only
     * advances; every honest node at the same tip agrees, and once
     * expired it stays expired everywhere. ERR_HASH, by contrast, is
     * documented at :100-110 as "THIS NODE could not compute" with an
     * explicit "MUST NOT translate it into a transaction rejection".
     *
     * THE SURVIVAL HALF, again, is what makes this discriminating: a
     * verdict function that answered EXPIRED to everything would empty
     * the pool and silence P3, and would pass the "expired one is gone"
     * assertion on its own. ─────────────────────────────────────────── */
    printf("§13k V1 — an EXPIRED successor ENVELOPE is not demand and IS "
           "reaped; an unexpired one survives both\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_v1_expiry_XXXXXX";
        chain_db_open(w, dir, 0x3E);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));   /* ~25 KB — heap */
        if (!cx) { fprintf(stderr, "p3c chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);
        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR");

        /* ── ADVANCE THE TIP OFF GENESIS, and why it is REQUIRED ───────
         *
         * p3c_make_successor leaves the chain AT genesis, so the v2 tip
         * is 0 and the production candidate height is 1. The locked
         * expiry rule is `expiry_height != 0 && expiry_height < H`
         * (env_preflight.h:188), and 0 is the never-expires sentinel
         * (:192) — so at H = 1 the only value strictly below the
         * candidate is the one value that means "no expiry". AN EXPIRED
         * ENVELOPE IS NOT CONSTRUCTIBLE AT GENESIS. The guard below
         * caught exactly that on the first run of this section.
         *
         * One committed block moves the tip to 1 and the candidate to 2,
         * which makes expiry_height = 1 genuinely expired. The block is
         * produced through the PRODUCTION engine entry point with a REAL
         * signed class-201 claim — test_v2_claim_ingress.c's proven
         * sequence, and the same claim shape §13e3 already admits — not
         * a hand-written v2_blocks row. A claim-only batch is supported
         * by construction: produce_commit sets blk->envs = NULL when the
         * envelope subset is empty and feeds blk->claims instead. */
        {
            dna_claim_t *c = p3c_make_claim(cx, 0);
            size_t clen = 0;
            uint8_t chash[64];
            uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);

            nodus_witness_mempool_entry_t *ce = calloc(1, sizeof(*ce));
            if (!ce) { fprintf(stderr, "p3k entry alloc\n"); exit(1); }
            memcpy(ce->tx_hash, chash, NODUS_T3_TX_HASH_LEN);
            ce->tx_type = NODUS_W_TX_V2_CLAIM;
            ce->tx_data = cbytes;   /* entry takes ownership */
            ce->tx_len  = (uint32_t)clen;

            nodus_witness_mempool_entry_t *b1[1] = { ce };
            nodus_v2_produce_out_t o;
            CHECK(nodus_witness_v2_produce_commit(w, b1, 1, 1, 42,
                      w->my_id, NULL, &o) == 0,
                  "one successor block commits through the production "
                  "engine — the chain is no longer at genesis");

            nodus_witness_mempool_entry_free(ce);   /* frees cbytes too */
            free(c);
        }

        /* The production candidate is v2 tip + 1, and the locked expiry
         * rule rejects only `expiry_height < H`. With the tip at 1 the
         * candidate is 2, so an envelope expiring at height 1 is expired
         * at the candidate and nowhere earlier — the tightest expired
         * fixture available. */
        uint64_t v2tip = 0;
        CHECK(nodus_witness_v2_tip_height(w, &v2tip) == 0 && v2tip >= 1,
              "the successor chain has a committed v2 tip of at least 1, so "
              "a NON-ZERO expiry height at or below it exists (0 would mean "
              "'never expires' and the section would test nothing)");
        /* Asserted AFTER the commit, not before: this is the config the
         * 16000 ms ageing below actually runs against, and producing a
         * block is exactly the kind of machinery that could refresh it. */
        CHECK(w->bft_config.round_timeout_ms == 15000 &&
              nodus_witness_bft_consensus_active(w),
              "and the fixture's BFT config survived genesis AND the block "
              "commit, so the ageing below really does exceed one round");

        p3c_env_t eexp, elive;
        p3c_make_env(w, cx, 0x31, v2tip, &eexp);  /* expires AT the tip */
        p3c_make_env(w, cx, 0x32, 0,     &elive); /* never expires      */
        CHECK(memcmp(eexp.intent_id, elive.intent_id, 64) != 0,
              "the two envelopes carry DIFFERENT intents");

        /* ⚠ ANTI-VACUITY: neither intent is in the index. Without this,
         * an eviction below could be coming from the COMMITTED branch and
         * the section would not be about expiry at all. */
        CHECK(!p3c_intent_in_index(w, eexp.intent_id) &&
              !p3c_intent_in_index(w, elive.intent_id),
              "NEITHER intent is committed — so every verdict below is "
              "about EXPIRY and nothing else");

        /* (0) THE VERDICTS, named rather than collapsed. */
        CHECK(nodus_witness_v2_entry_verdict(w, eexp.bytes,
                                             (uint32_t)eexp.len) ==
              NODUS_W_ENTRY_EXPIRED,
              "the expired envelope is judged EXPIRED — not UNJUDGED, which "
              "is what the first cut of V1 returned and what left it "
              "undeletable forever");
        CHECK(nodus_witness_v2_entry_verdict(w, elive.bytes,
                                             (uint32_t)elive.len) ==
              NODUS_W_ENTRY_LIVE,
              "and the unexpired one is judged LIVE");
        CHECK(nodus_witness_v2_entry_is_decided(NODUS_W_ENTRY_EXPIRED) &&
              !nodus_witness_v2_entry_is_decided(NODUS_W_ENTRY_LIVE) &&
              !nodus_witness_v2_entry_is_decided(NODUS_W_ENTRY_UNJUDGED),
              "and the SHARED collapse puts EXPIRED on the finished side "
              "while both keep-side answers stay off it — this is the one "
              "rule both consumers use, so they cannot drift");

        /* (a) NOT DEMAND — only the expired envelope pooled. */
        p3_pool(w, p3c_env_entry(&eexp, 500));
        CHECK(w->mempool.count == 1, "the expired envelope is pooled");
        CHECK(w->mempool.entries[0]->nullifier_count == 0,
              "with nullifier_count 0 — the shape the legacy predicate "
              "cannot judge");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0, "P2 is NOT armed");
        CHECK(w->pending_forward_count == 0, "and NO pending forward");

        nodus_witness_bft_check_timeout(w);
        uint64_t anchored = w->last_seen_tip;
        CHECK(p3_stamped_now(w->tip_since_ms), "the demand window armed");
        p3_age_window(w, 16000);
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — an envelope that can never be "
              "included is not a reason to rotate the view");
        CHECK(!w->view_change_in_progress, "no view change was started");
        CHECK(w->last_seen_tip == anchored && p3_stamped_now(w->tip_since_ms),
              "and the would-fire point WAS reached (window re-stamped at "
              "the same frozen tip) — declined on the verdict, not skipped");

        /* (b) STILL DEMAND — the unexpired envelope fires. */
        p3_pool(w, p3c_env_entry(&elive, 100));
        CHECK(w->mempool.count == 2, "the unexpired envelope joins it");
        p3_age_window(w, 16000);
        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "NOW it rotates — so (a)'s silence is the expiry verdict, not "
              "a verdict function that calls everything finished");
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");

        /* (c) THE REAPER, the other consumer, over the same two entries. */
        CHECK(w->mempool.entries[0]->fee == 500 &&
              w->mempool.entries[1]->fee == 100,
              "expired first, unexpired behind it — so the survivor has to "
              "be MOVED and the compaction really runs");
        int dropped = nodus_witness_mempool_evict_committed(w);
        CHECK(dropped == 1, "exactly ONE entry was evicted");
        CHECK(w->mempool.count == 1, "one survives");
        CHECK(w->mempool.entries[0]->fee == 100,
              "and it is the UNEXPIRED one — the survival half; a verdict "
              "function answering EXPIRED to everything fails here");
        CHECK(w->mempool.entries[1] == NULL, "the vacated slot was cleared");
        CHECK(nodus_witness_mempool_evict_committed(w) == 0,
              "a second pass evicts nothing");

        free(eexp.bytes);
        free(elive.bytes);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13l — O15K §3.1: a LEGACY client's demand is pooled locally ─
     *
     * THE HALT THIS OPENS. On a legacy chain the ONE node a client is
     * talking to had nowhere to put the work: the non-leader intake took
     * a pending_forwards slot carrying no transaction bytes, and when the
     * leader could not be reached it RELEASED the slot and discarded the
     * request. So `mempool.count > 0 || pending_forward_count > 0` — the
     * predicate the entire P3 deadman arms on — read zero on the only
     * node that knew a client was waiting.
     *
     * ROUTED THROUGH A CHANGED GATE (rule 1): the entry enters through
     * nodus_witness_pool_local_demand, whose `!w->v2_successor → -1` early
     * return §3.1 deletes. Pooling it with p3_pool would assert nothing —
     * that call bypasses this gate entirely.
     *
     * THE POSITIVE CONTROL IS LEG 2 (rule 2), and it is what makes leg 1
     * mean something. Pre-O15K BOTH legs answer -1 with an EMPTY reason
     * string, because the gate declines before admission runs (that is
     * §14d's whole assertion). Post-O15K they answer 0 and -2, with a
     * reason string only on the second — so the pair proves both that the
     * lane opened and that it opened ONLY to work the chain would accept.
     *
     * HOW THIS COULD LIE: if p3l_fund silently failed, leg 1 would answer
     * -2 ("UTXO not found in set") and look like a gate refusal. p3l_funded
     * rules that out before either call. ────────────────────────────── */
    printf("§13l O15K §3.1 — a LEGACY client submission is POOLED as local "
           "demand; unverifiable bytes still are not\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        peer_t client; peer_make(&client);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_local_XXXXXX";
        chain_db_open(w, dir, 0x51);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor,
              "this fixture is a LEGACY chain — the lane §3.1 opens");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w),
              "we are NOT the leader — the node a stalled client reaches");
        CHECK(w->mempool.count == 0, "and the pool starts empty");

        p3l_tx_t good, bad;
        p3l_make(w, &client, 0x51, 1, true,  &good);
        p3l_make(w, &client, 0x52, 1, false, &bad);
        p3l_fund(w, &client, &good);
        p3l_fund(w, &client, &bad);
        CHECK(p3l_funded(w, &good) && p3l_funded(w, &bad),
              "BOTH inputs are in the committed UTXO set — so neither "
              "verdict below can be 'UTXO not found in set'");
        CHECK(memcmp(good.hash, bad.hash, NODUS_T3_TX_HASH_LEN) != 0,
              "and the two carry DIFFERENT tx_hashes, so the helper's "
              "already-held pre-check can never answer for the second");

        /* LEG 1 — the admissible submission. */
        char why[256] = {0};
        int prc = nodus_witness_pool_local_demand(w, good.tx, good.len,
                      good.hash, NODUS_W_TX_SPEND, good.nul, 1,
                      NULL, NULL, good.fee, why, sizeof(why));
        CHECK(prc == 0,
              "a LEGACY client's admissible spend is ACCEPTED as local "
              "demand — today this returns -1 at the successor gate");
        CHECK(w->mempool.count == 1,
              "and the COUNT MOVED: the node the client is talking to now "
              "holds the work, so the P3 deadman can finally see it");

        /* THE ORPHAN SHAPE — §14a's three fields, for §14a's reasons: the
         * entry must outlive the client disconnect it exists to survive,
         * and it must route a remote leader's reply back to US. */
        CHECK(w->mempool.entries[0]->client_conn == NULL,
              "pooled with NO client connection, so the CLI's disconnect "
              "cannot delete it one step after it was created");
        CHECK(w->mempool.entries[0]->is_forwarded &&
              memcmp(w->mempool.entries[0]->forwarder_id, w->my_id,
                     NODUS_T3_WITNESS_ID_LEN) == 0,
              "and named US as the forwarder — we hold the client");
        CHECK(w->mempool.entries[0]->nullifier_count == 1 &&
              memcmp(w->mempool.entries[0]->nullifiers[0], good.nul,
                     NODUS_T3_NULLIFIER_LEN) == 0,
              "carrying the input's nullifier — the ONE handle the P3(c) "
              "reaper and batch selection both key on");

        /* LEG 2 — THE POSITIVE CONTROL'S CONVERSE. Identical shape, one
         * corrupted signature. */
        why[0] = '\0';
        int brc = nodus_witness_pool_local_demand(w, bad.tx, bad.len,
                      bad.hash, NODUS_W_TX_SPEND, bad.nul, 1,
                      NULL, NULL, bad.fee, why, sizeof(why));
        CHECK(brc == -2,
              "an UNVERIFIABLE spend is refused BY ADMISSION (-2), not by "
              "an applicability gate (-1) — G3 is satisfied by the verify "
              "this helper already ran, so opening the lane widened no "
              "trust boundary");
        CHECK(why[0] != '\0',
              "and a rejection REASON was produced, which proves admission "
              "actually RAN: the pre-O15K -1 leaves this string empty "
              "because nothing was ever judged (§14d)");
        CHECK(w->mempool.count == 1,
              "and the pool is UNCHANGED — the count is the discriminator, "
              "not the return code");

        p3l_free(&good);
        p3l_free(&bad);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13m — O15K §3.2: a legacy NON-LEADER pools a forward ────────
     *
     * THE FOURTH EDIT SITE. A design that opens only pool_local_demand,
     * the forward verify and the disseminator still ships a system in
     * which EVERY legacy recipient refuses w_fwd_req: the deadman fires,
     * the broadcast goes out, nobody pools, f+1 never assembles and the
     * halt persists — with every other unit case still green. The refusal
     * lives on its own line in nodus_witness_peer.c
     * (`!is_leader && !v2_successor → -1`), and this section is what fails
     * if that line survives.
     *
     * WHAT IT ADDS OVER §13e: §13e offers the SAME bytes at both roles to
     * show the answer no longer depends on the role. This section is about
     * the ACCEPT specifically — a non-leader's pool GROWING — which is the
     * half that puts the work where the next leader can find it.
     *
     * HOW IT COULD LIE: if the fixture were accidentally a successor
     * chain, leg 1 would pass on the ALREADY-OPEN successor path and
     * prove nothing. The !v2_successor assertion rules that out. ─────── */
    printf("§13m O15K §3.2 — a LEGACY NON-LEADER pools an admissible "
           "forwarded entry\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        peer_t client; peer_make(&client);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_follower_XXXXXX";
        chain_db_open(w, dir, 0x52);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor,
              "this fixture is a LEGACY chain — not the successor lane "
              "§13e3 already covers, which would pass here for free");

        p3l_tx_t good, bad;
        p3l_make(w, &client, 0x53, 1, true,  &good);
        p3l_make(w, &client, 0x54, 1, false, &bad);
        p3l_fund(w, &client, &good);
        p3l_fund(w, &client, &bad);
        CHECK(p3l_funded(w, &good) && p3l_funded(w, &bad),
              "both inputs are in the committed UTXO set");

        nodus_t3_msg_t fm;      /* ONE large object, re-filled — see §13e */

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w),
              "we are NOT the leader — pre-O15K this call ended at the "
              "leadership line and nothing else ran");
        CHECK(w->mempool.count == 0, "and the pool starts empty");

        p3l_fwd(&fm, &good, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "the forwarded spend was ACCEPTED by a non-leader");
        CHECK(w->mempool.count == 1,
              "and POOLED — the dead leader is no longer the only node "
              "that can hold this work, which is what makes an f+1 join "
              "reachable at all");
        CHECK(w->mempool.entries[0]->is_forwarded &&
              memcmp(w->mempool.entries[0]->forwarder_id, p[0].id,
                     NODUS_T3_WITNESS_ID_LEN) == 0,
              "with the forwarder id carried through, so a w_fwd_rsp from "
              "whichever node commits it reaches the client's node");
        CHECK(w->mempool.entries[0]->client_conn == NULL,
              "and no client connection of its own");
        CHECK(w->mempool.entries[0]->nullifier_count == 1 &&
              memcmp(w->mempool.entries[0]->nullifiers[0], good.nul,
                     NODUS_T3_NULLIFIER_LEN) == 0,
              "the structural walk's nullifier was recorded — the reaper "
              "and batch dedup both key on exactly this");

        /* THE POSITIVE CONTROL'S CONVERSE: the newly opened door admits
         * only what admission accepts. Pre-O15K this is refused too — by
         * the leadership line — so it is the accept above, not this, that
         * discriminates. Stated rather than hidden. */
        p3l_fwd(&fm, &bad, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == -1,
              "the SAME non-leader refuses a forward whose signature does "
              "not verify — opening the door did not open it to anything");
        CHECK(w->mempool.count == 1,
              "and the pool is unchanged: a follower's mempool never "
              "receives bytes no node has verified");

        p3l_free(&good);
        p3l_free(&bad);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13n — V-1: the legacy LEADER stops pooling unverified bytes ─
     *
     * THE DEFECT, AND IT IS LIVE ON THE DEVNET TODAY. The legacy branch of
     * nodus_witness_peer_handle_fwd_req performs a STRUCTURAL nullifier
     * walk and nothing else — no signature verification, no double-spend
     * check — and then pools. The successor branch verifies; the legacy
     * branch never did. So one remote client, with NO roster membership,
     * plants an invalid-signature transaction in the leader's mempool; the
     * leader proposes a batch containing it; and a single rejected
     * transaction drops the ENTIRE batch at validation. Legacy block
     * production stalls for the cost of one malformed submission.
     *
     * WHAT IT ADDS OVER §13e: §13e proves the ANSWER is the same from both
     * roles. This section is about the LEADER specifically, because the
     * leader is the only role that pools these bytes today — a non-leader
     * refusal proves nothing, since the pre-fix code refuses every
     * non-leader forward regardless of the bytes.
     *
     * HOW IT COULD LIE: if the bad transaction were malformed in any way
     * BESIDES the signature, the refusal could come from the structural
     * walk and would be green today. p3l_make corrupts one signature byte
     * AFTER the tx_hash is fixed and the input is funded, so the wire is
     * byte-valid and the UTXO exists. Leg 2 is what proves the leader is
     * not simply refusing everything. ──────────────────────────────── */
    printf("§13n O15K V-1 — the legacy LEADER REFUSES a forward whose "
           "signature does not verify\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        peer_t client; peer_make(&client);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_v1_XXXXXX";
        chain_db_open(w, dir, 0x53);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor, "this fixture is a LEGACY chain");

        p3l_tx_t bad, good;
        p3l_make(w, &client, 0x55, 1, false, &bad);
        p3l_make(w, &client, 0x56, 1, true,  &good);
        p3l_fund(w, &client, &bad);
        p3l_fund(w, &client, &good);
        CHECK(p3l_funded(w, &bad) && p3l_funded(w, &good),
              "both inputs are funded, so the ONLY defect in the first "
              "transaction is its signature");
        CHECK(!nodus_witness_nullifier_exists(w, bad.nul) &&
              !nodus_witness_nullifier_exists(w, good.nul),
              "and neither input is already spent — so no refusal below "
              "can be the double-spend check answering instead");

        nodus_t3_msg_t fm;      /* ONE large object, re-filled — see §13e */

        w->current_view = p2_pick_view(w, true);
        CHECK(nodus_witness_bft_is_leader(w),
              "we ARE the leader — the ONLY role that pools a legacy "
              "forward today, and therefore the only one where a refusal "
              "can discriminate");
        CHECK(w->mempool.count == 0, "and the pool starts empty");

        p3l_fwd(&fm, &bad, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == -1,
              "the leader REFUSED it — today this returns 0");
        CHECK(w->mempool.count == 0,
              "and pooled NOTHING. Today this pool holds one entry that no "
              "node has verified, and the leader's next batch dies on it");

        /* THE POSITIVE CONTROL. Without it the section is satisfied by a
         * verify placed so early, or passed such wrong arguments, that it
         * rejects EVERY legacy forward — a silent no-op that would leave
         * the halt in place while every refusal assertion stayed green. */
        p3l_fwd(&fm, &good, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "while an admissible forward from the same peer is accepted");
        CHECK(w->mempool.count == 1,
              "and pooled — so the refusal above is a verdict on the "
              "bytes, not an admission call that refuses everything");
        CHECK(memcmp(w->mempool.entries[0]->tx_hash, good.hash,
                     NODUS_T3_TX_HASH_LEN) == 0,
              "and the one pooled entry is the VALID transaction");

        p3l_free(&bad);
        p3l_free(&good);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13o — V-8: a wire input_count byte of 0 is refused ──────────
     *
     * THE DEFECT, AND IT IS ALSO LIVE ON THE DEVNET. The legacy structural
     * walk reads `nullifier_count = tx_data[input_count_offset]`, bounds it
     * against NODUS_T3_MAX_TX_INPUTS, and loops. A wire byte of 0 skips
     * the loop, nothing rejects it, and the entry is pooled with
     * nullifier_count == 0. Such an entry is PERMANENTLY unremovable:
     *   - the P3(c) reaper's nullifier walk has nothing to iterate;
     *   - nodus_witness_v2_entry_verdict answers UNJUDGED for any legacy
     *     chain, so the second half keeps it too;
     *   - mempool_pop_batch is leader-only and remove_by_conn needs a
     *     client_conn a forwarded entry does not have.
     * bft_p3_live_demand therefore reads it as live demand FOREVER, and
     * the node initiates a view change every round_timeout_ms against a
     * perfectly healthy leader until the process restarts. It is the O15I
     * V1 churn, re-entered through the legacy door.
     *
     * ⚠ THIS IS WHY §3.4's GUARD IS LOAD-BEARING AND NOT DEFENCE IN DEPTH.
     * The argument that legacy admission already rejects zero-input
     * non-genesis transactions covers only paths that RUN admission, and
     * this one does not run it at all.
     *
     * HOW IT COULD LIE: if the zero-input transaction were malformed in
     * some OTHER way, its refusal would be structural and green today.
     * The assertion on the wire byte pins that the ONLY anomaly is the
     * count, and leg 2 pins that the leader still accepts real work.
     * ────────────────────────────────────────────────────────────────── */
    printf("§13o O15K V-8 — a legacy forward whose wire input_count is 0 "
           "is refused, by BOTH roles\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        peer_t client; peer_make(&client);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_v8_XXXXXX";
        chain_db_open(w, dir, 0x54);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor, "this fixture is a LEGACY chain");

        p3l_tx_t zero_a, zero_b, good;
        p3l_make(w, &client, 0x57, 0, true, &zero_a);
        p3l_make(w, &client, 0x58, 0, true, &zero_b);
        p3l_make(w, &client, 0x59, 1, true, &good);
        p3l_fund(w, &client, &good);
        CHECK(zero_a.tx[DNAC_TX_HEADER_SIZE] == 0 &&
              zero_b.tx[DNAC_TX_HEADER_SIZE] == 0,
              "the wire input_count byte really is 0 — the ONE byte V-8 "
              "turns on, at the offset the structural walk reads");
        CHECK(good.tx[DNAC_TX_HEADER_SIZE] == 1 && p3l_funded(w, &good),
              "while the control carries one funded input, so the two "
              "differ in that byte and in nothing else that matters");
        CHECK(memcmp(zero_a.hash, zero_b.hash, NODUS_T3_TX_HASH_LEN) != 0,
              "the two zero-input transactions are DISTINCT, so leg 3's "
              "refusal cannot be mempool_add's duplicate rejection");

        nodus_t3_msg_t fm;      /* ONE large object, re-filled — see §13e */

        /* LEG 1 — the LEADER, the role that pools it today. */
        w->current_view = p2_pick_view(w, true);
        CHECK(nodus_witness_bft_is_leader(w), "we ARE the leader");
        CHECK(w->mempool.count == 0, "and the pool starts empty");
        p3l_fwd(&fm, &zero_a, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == -1,
              "the leader REFUSES a zero-input forward — today this "
              "returns 0");
        CHECK(w->mempool.count == 0,
              "and pools NOTHING. Today this pool holds an entry with "
              "nullifier_count == 0 that no reaper on this node can ever "
              "remove and that arms the deadman every round, forever");

        /* LEG 2 — THE POSITIVE CONTROL. */
        p3l_fwd(&fm, &good, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "while a one-input admissible forward is accepted");
        CHECK(w->mempool.count == 1 &&
              w->mempool.entries[0]->nullifier_count == 1,
              "and pooled WITH its nullifier — so the refusal above is "
              "about the zero count, not about legacy forwards in general");

        /* LEG 3 — A GUARD, AND IT IS GREEN TODAY: the pre-O15K non-leader
         * refuses every forward, so this leg discriminates only in the
         * POST-fix world. Its job is to catch a guard placed inside the
         * leader branch instead of at the intake door — which would leave
         * the newly opened non-leader path (§13m) admitting exactly the
         * shape V-8 is about. */
        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader now");
        p3l_fwd(&fm, &zero_b, &p[0]);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == -1,
              "and a NON-leader refuses the zero-input shape too — the "
              "guard belongs to the intake door, not to one role");
        CHECK(w->mempool.count == 1,
              "the pool is unchanged: §13m's newly opened path did not "
              "become V-8's new door");

        p3l_free(&zero_a);
        p3l_free(&zero_b);
        p3l_free(&good);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13p — O15K §3.3: the fire DISSEMINATES on a legacy chain ────
     *
     * WHY P3(a) ALONE FIXES NOTHING. A forwarded transaction reaches the
     * leader and nowhere else, so when the leader is dead the demand lives
     * on exactly ONE node. That node initiates a view change and 1 is far
     * below the f+1 join threshold, so nobody joins it: the rotation never
     * completes and the halt is permanent. Dissemination at the fire is
     * what makes the rotation assemblable — and today
     * bft_p3_broadcast_demand returns at its first line on a legacy chain.
     *
     * ⚠ THE OBSERVABLE, AND WHY IT IS NOT A LOG LINE. In this peer-less
     * fixture nodus_witness_bft_broadcast sends to zero connections, so
     * `sent` stays 0 and the disseminator's summary line never prints —
     * EVEN AFTER THE FIX. A stderr-grep assertion would therefore be RED
     * post-fix, which is worse than vacuous. The one honest in-process
     * discriminator is `++w->next_txn_id`, taken once per LIVE entry
     * BEFORE the broadcast call, so it is charged whether or not anything
     * goes on the wire. nodus_witness_bft_initiate_view_change takes one
     * on the same tick, so only a DELTA separates the two worlds:
     *   pre-fix  = 1                      (the VIEW_CHANGE alone)
     *   post-fix = 1 + live entries       (+ one per disseminated entry)
     *
     * ⚠ p3_pool IS USED HERE ON PURPOSE, and this is the one place in the
     * O15K sections where rule 1 is deliberately not applied. The pooled
     * entries are the INSTRUMENT, not the subject: the subject is the
     * disseminator's early return. Pooling them through
     * pool_local_demand would make the section RED at its first CHECK for
     * a §3.1 reason and it would never reach the delta at all, so the
     * delta would stop being attributable to §3.3. p3_pool makes the pool
     * BYTE-IDENTICAL in both worlds, which is what leaves the delta as the
     * only difference.
     *
     * HOW IT COULD LIE: an entry the chain has already decided is SKIPPED
     * by the disseminator and charges no id, so a fixture whose entries
     * were committed would show a delta of 1 even after the fix and read
     * as a failure of §3.3. Both nullifiers are asserted uncommitted.
     * A tick that never fired would also show a delta of 0-1, so the
     * VIEW_CHANGE phase is asserted as well. ───────────────────────── */
    printf("§13p O15K §3.3 — the P3 fire disseminates pooled demand on a "
           "LEGACY chain\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_gossip_XXXXXX";
        chain_db_open(w, dir, 0x55);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor,
              "this fixture is a LEGACY chain — the lane on which the "
              "disseminator is a no-op today");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");
        CHECK(w->awaiting_propose_deadline_ms == 0,
              "P2 is NOT armed — every id consumed below is attributable "
              "to the P3 fire path");
        CHECK(w->pending_forward_count == 0,
              "and NO pending forward, which would answer 'live' without "
              "any pooled entry and make the count below meaningless");

        p3_pool(w, p3_mkentry(0x5A, 200, 1));
        p3_pool(w, p3_mkentry(0x5B, 100, 1));
        CHECK(w->mempool.count == 2, "TWO entries are pooled");

        uint8_t n1[NODUS_T3_NULLIFIER_LEN], n2[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0x5A, n1);
        p3_nul_of(0x5B, n2);
        CHECK(!nodus_witness_nullifier_exists(w, n1) &&
              !nodus_witness_nullifier_exists(w, n2),
              "and BOTH are LIVE — a decided entry is skipped by the "
              "disseminator and charges no transaction id, which would "
              "make the delta below wrong for a reason that is not §3.3");

        /* TICK 1 — arms the window and consumes nothing from the fire
         * path, which is why the counter is sampled AFTER it. */
        nodus_witness_bft_check_timeout(w);
        CHECK(w->last_seen_tip == tip, "the window is anchored at the tip");
        CHECK(p3_stamped_now(w->tip_since_ms), "and it is running");

        p3_age_window(w, 16000);
        uint32_t txn_before  = w->next_txn_id;
        uint32_t view_before = w->current_view;

        /* TICK 2 — the fire. */
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "the deadman FIRED — without this the delta below could be "
              "measuring a tick that decided nothing");
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — only quorum may advance it");
        CHECK(w->next_txn_id - txn_before == 3,
              "the fire consumed THREE transaction ids: ONE PER LIVE "
              "POOLED ENTRY disseminated, plus the VIEW_CHANGE itself. "
              "Today the disseminator returns at its first line on a "
              "legacy chain and this delta is exactly 1 — the lone view "
              "change nobody can join");

        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13q — V-3: a COMMITTED class-201 claim becomes reapable ─────
     *
     * THE DEFECT. A claim's nullifier is committed to `v2_claims_spent`.
     * Every "is this entry decided?" question walks the LEGACY `nullifiers`
     * table instead — nodus_witness_nullifier_exists, whose only writer is
     * the legacy commit path, which a successor commit bypasses — and
     * nodus_witness_v2_entry_verdict's class gate answers UNJUDGED for a
     * 201. Both halves say "not decided", so the entry is never reaped and
     * reads as live demand forever: the O15I V1 shape in a lane whose own
     * comments assert it is closed. Successor lane, not live today, but
     * the V2 cutover inherits it.
     *
     * ROUTED THROUGH A GATE (rule 1): both claims enter through
     * nodus_witness_peer_handle_fwd_req on a NON-LEADER, so each is pooled
     * with the committed nullifier consensus derives rather than one this
     * test chose. The commit itself runs the PRODUCTION execute stages.
     *
     * THE ANTI-VACUITY PAIR IS THE TWO TABLES, named separately, because
     * naming only one is how V-3 was written in the first place: the
     * spent-claim table must hold the first nullifier and NOT the second,
     * and the legacy table must hold NEITHER. If it held either, the
     * eviction below would be the legacy walk answering and the section
     * would not be about V-3 at all.
     *
     * HOW IT COULD LIE: nodus_witness_nullifier_exists is FAIL-CLOSED — it
     * answers "spent" on a missing DB — so a fixture with no usable
     * database would evict everything and pass the delete half on its own.
     * The survivor assertion is what rules that out. ──────────────────── */
    printf("§13q O15K V-3 — a COMMITTED class-201 claim is REAPED; the "
           "uncommitted one beside it survives\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_v3_XXXXXX";
        chain_db_open(w, dir, 0x56);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));   /* ~25 KB — heap */
        if (!cx) { fprintf(stderr, "p3c chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);
        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR");
        CHECK(nodus_witness_v2_ingress_is_armed(w) == 1,
              "and its ingress is ARMED, so the intake below really runs "
              "admission rather than declining at a closed gate");

        /* TWO claims on TWO leaves — two different committed nullifiers,
         * so one can be committed while the other stays live. */
        dna_claim_t *c0 = p3c_make_claim(cx, 0);
        dna_claim_t *c1 = p3c_make_claim(cx, 1);
        size_t l0 = 0, l1 = 0;
        uint8_t h0[64], h1[64];
        uint8_t *b0 = p3c_encode_claim(c0, &l0, h0);
        uint8_t *b1 = p3c_encode_claim(c1, &l1, h1);
        uint8_t nul0[64], nul1[64];
        p3c_claim_nullifier(c0, nul0);
        p3c_claim_nullifier(c1, nul1);
        CHECK(memcmp(nul0, nul1, 64) != 0,
              "the two claims carry DIFFERENT committed nullifiers");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");

        /* Pooled BEFORE the commit: admission's own cross-block spent
         * check would refuse a claim the chain has already taken. Fees put
         * the doomed entry at the head, so the survivor has to be MOVED
         * and the compaction really runs (§13f's device). */
        nodus_t3_msg_t fm;      /* ONE large object, re-filled — see §13e */
        memset(&fm, 0, sizeof(fm));
        fm.type = NODUS_T3_FWD_REQ;
        memcpy(fm.fwd_req.tx_hash, h0, NODUS_T3_TX_HASH_LEN);
        fm.fwd_req.tx_data = b0;
        fm.fwd_req.tx_len  = (uint32_t)l0;
        fm.fwd_req.fee     = 500;
        memcpy(fm.fwd_req.forwarder_id, p[0].id, NODUS_T3_WITNESS_ID_LEN);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "the claim about to be committed is pooled through the "
              "production intake");

        memcpy(fm.fwd_req.tx_hash, h1, NODUS_T3_TX_HASH_LEN);
        fm.fwd_req.tx_data = b1;
        fm.fwd_req.tx_len  = (uint32_t)l1;
        fm.fwd_req.fee     = 100;
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "and so is the one that must survive it");
        CHECK(w->mempool.count == 2 &&
              w->mempool.entries[0]->fee == 500 &&
              w->mempool.entries[1]->fee == 100,
              "two entries, the one about to be committed at the head");
        CHECK(w->mempool.entries[0]->tx_type == NODUS_W_TX_V2_CLAIM &&
              w->mempool.entries[0]->nullifier_count == 1 &&
              memcmp(w->mempool.entries[0]->nullifiers[0], nul0, 64) == 0,
              "class 201, carrying the nullifier CONSENSUS derives — not "
              "one this test chose");

        /* THE CHAIN COMMITS THE FIRST CLAIM, through the production
         * execute stages. */
        p3c_commit_claim(w, c0);

        /* ⚠ THE V-3 ANTI-VACUITY SET — three facts, because V-3 is exactly
         * a disagreement between two tables. */
        CHECK(p3c_claim_is_spent(w, nul0),
              "v2_claims_spent really holds the committed claim");
        CHECK(!p3c_claim_is_spent(w, nul1),
              "and really does NOT hold the other — so the table is "
              "discriminating, not answering yes to everything");
        CHECK(!nodus_witness_nullifier_exists(w, nul0) &&
              !nodus_witness_nullifier_exists(w, nul1),
              "while the LEGACY nullifiers table has nothing to say about "
              "EITHER. This IS V-3: the commit wrote one table and every "
              "decided-ness question reads the other");
        CHECK(nodus_witness_v2_entry_verdict(w, b0, (uint32_t)l0) ==
              NODUS_W_ENTRY_UNJUDGED,
              "and the class-200 verdict lane answers UNJUDGED for a 201, "
              "so the reaper's second half is silent too — which is why "
              "nothing removes this entry today");

        int dropped = nodus_witness_mempool_evict_committed(w);
        CHECK(dropped == 1,
              "exactly ONE entry was reaped. Today this is 0: the walk "
              "reads `nullifiers`, the commit wrote `v2_claims_spent`, and "
              "the entry stays in the pool arming the deadman forever");
        CHECK(w->mempool.count == 1, "one survives");
        CHECK(w->mempool.entries[0]->fee == 100 &&
              memcmp(w->mempool.entries[0]->nullifiers[0], nul1, 64) == 0,
              "and it is the UNCOMMITTED claim, compacted to the head — "
              "the survival half; a reaper that dropped everything, or a "
              "fail-closed DB answering 'spent' to all, fails here");
        CHECK(w->mempool.entries[1] == NULL, "the vacated slot was cleared");
        CHECK(nodus_witness_mempool_evict_committed(w) == 0,
              "a second pass reaps nothing — the reaper reacts to the "
              "chain's verdict, not to being called");

        free(b0); free(b1);
        free(c0); free(c1);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13r — V-3 NEGATIVE: an UNCOMMITTED claim SURVIVES a reap ────
     *
     * ⚠ A KEEP-DIRECTION GUARD, AND IT PASSES TODAY. Said plainly rather
     * than dressed up: pre-O15K nothing asks `v2_claims_spent` at all, so
     * this section cannot discriminate against HEAD. It exists for the
     * fix, not against the defect.
     *
     * WHY IT IS NEVERTHELESS THE MOST IMPORTANT SECTION IN THIS SET. Every
     * other O15K item teaches the code to REFUSE, and a wrong refusal
     * costs a client one retry. V-3 teaches it to DELETE, and a wrong
     * deletion silently loses a transaction a client is waiting on. The
     * same fact — "is this nullifier in v2_claims_spent?" — serves two
     * questions whose safe answers point in OPPOSITE directions:
     *   admission asks "may I admit this?"  → a fault must answer SPENT;
     *   the reaper asks "may I delete this?" → a fault must answer NOT
     *   SPENT.
     * A helper returning a bare bool would hand one of the two callers the
     * dangerous direction. This section pins the reaper's side for the
     * ordinary "no row" answer; §13s pins it for the fault.
     *
     * IT IS NOT VACUOUS EVEN SO. A legacy entry the chain HAS decided sits
     * beside the claim and IS evicted in the same call, so the section
     * fails if the reaper silently stopped running, stopped compacting, or
     * lost its legacy walk. What it cannot do is fail on HEAD. ───────── */
    printf("§13r O15K V-3 (keep-direction guard) — an UNCOMMITTED claim "
           "survives a reap that evicts a decided entry beside it\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_v3keep_XXXXXX";
        chain_db_open(w, dir, 0x57);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));
        if (!cx) { fprintf(stderr, "p3c chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);
        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR");

        dna_claim_t *c = p3c_make_claim(cx, 0);
        size_t clen = 0;
        uint8_t chash[64];
        uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);
        uint8_t want_nul[64];
        p3c_claim_nullifier(c, want_nul);

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");

        /* THE ENTRY UNDER TEST enters through the production intake. */
        nodus_t3_msg_t fm;
        memset(&fm, 0, sizeof(fm));
        fm.type = NODUS_T3_FWD_REQ;
        memcpy(fm.fwd_req.tx_hash, chash, NODUS_T3_TX_HASH_LEN);
        fm.fwd_req.tx_data = cbytes;
        fm.fwd_req.tx_len  = (uint32_t)clen;
        fm.fwd_req.fee     = 100;
        memcpy(fm.fwd_req.forwarder_id, p[0].id, NODUS_T3_WITNESS_ID_LEN);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "the uncommitted claim is pooled the production way");

        /* THE ANTI-VACUITY CONTROL is an entry the chain HAS decided, at a
         * higher fee so it sits at the head and the survivor must MOVE.
         * p3_pool is correct for it: it is the instrument that proves the
         * reaper ran, not the subject of the section. */
        p3_pool(w, p3_mkentry(0x5C, 500, 1));
        CHECK(w->mempool.count == 2 &&
              w->mempool.entries[0]->fee == 500 &&
              w->mempool.entries[1]->fee == 100,
              "two entries, the decided control at the head");

        uint8_t n_ctl[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0x5C, n_ctl);
        uint8_t ctx[NODUS_T3_TX_HASH_LEN];
        memset(ctx, 0x5C, sizeof(ctx));
        CHECK(nodus_witness_nullifier_add(w, n_ctl, ctx) == 0,
              "the control's nullifier is COMMITTED on this chain");
        CHECK(nodus_witness_nullifier_exists(w, n_ctl),
              "and the legacy table really says so");
        CHECK(!nodus_witness_nullifier_exists(w, want_nul),
              "while it says NOTHING about the claim — so the DB is "
              "discriminating rather than failing closed on everything");
        CHECK(!p3c_claim_is_spent(w, want_nul),
              "and v2_claims_spent has no row for the claim either: the "
              "chain has NOT decided it, by either authority");

        int dropped = nodus_witness_mempool_evict_committed(w);
        CHECK(dropped == 1,
              "exactly ONE entry went — so the reaper RAN and is still "
              "discriminating; without this the section would pass for a "
              "reaper that had stopped working entirely");
        CHECK(w->mempool.count == 1, "one survives");
        CHECK(w->mempool.entries[0]->tx_type == NODUS_W_TX_V2_CLAIM &&
              memcmp(w->mempool.entries[0]->nullifiers[0], want_nul, 64) == 0,
              "and it is the UNCOMMITTED CLAIM. A reaper that asked "
              "v2_claims_spent but mapped 'no row' to DELETE would lose a "
              "client's pending work exactly here");
        CHECK(w->mempool.entries[1] == NULL, "the vacated slot was cleared");

        free(cbytes);
        free(c);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §13s — V-3 NEGATIVE: a DB FAULT leaves the entry alone ───────
     *
     * ⚠ ALSO A KEEP-DIRECTION GUARD, AND ALSO GREEN TODAY, for the same
     * reason: pre-O15K no caller touches `v2_claims_spent`, so breaking it
     * changes nothing HEAD does. It cannot be made red with the existing
     * signatures, and pretending otherwise would be worse than saying so.
     *
     * WHAT IT PINS. The reaper's existing contract is fail-closed in the
     * KEEP direction — "anything this node cannot judge answers false,
     * still live" — and V-3 must not change that. The natural mistake is a
     * helper that returns a bare bool: a query that cannot even PREPARE
     * then collapses to `false` at admission (where the safe answer is
     * SPENT, reject) or to `true` at the reaper (where the safe answer is
     * NOT SPENT, keep). One tri-state, mapped by each caller, is the only
     * shape that serves both.
     *
     * THE FAULT IS REAL, NOT SIMULATED: the table is DROPPED, so the
     * production statement genuinely fails to prepare — the same outcome a
     * corrupted or partially migrated database produces. It is dropped
     * AFTER the claim is pooled, because admission reads the same table
     * and would refuse the intake otherwise.
     *
     * ANTI-VACUITY: the decided legacy entry beside it must still be
     * evicted, so the section fails if the fault took the whole reaper
     * down rather than one of its two questions. ───────────────────── */
    printf("§13s O15K V-3 (keep-direction guard) — a v2_claims_spent DB "
           "fault leaves the pooled claim alone\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15k_v3fault_XXXXXX";
        chain_db_open(w, dir, 0x58);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));
        if (!cx) { fprintf(stderr, "p3c chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);
        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR");

        dna_claim_t *c = p3c_make_claim(cx, 0);
        size_t clen = 0;
        uint8_t chash[64];
        uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);
        uint8_t want_nul[64];
        p3c_claim_nullifier(c, want_nul);

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");

        nodus_t3_msg_t fm;
        memset(&fm, 0, sizeof(fm));
        fm.type = NODUS_T3_FWD_REQ;
        memcpy(fm.fwd_req.tx_hash, chash, NODUS_T3_TX_HASH_LEN);
        fm.fwd_req.tx_data = cbytes;
        fm.fwd_req.tx_len  = (uint32_t)clen;
        fm.fwd_req.fee     = 100;
        memcpy(fm.fwd_req.forwarder_id, p[0].id, NODUS_T3_WITNESS_ID_LEN);
        CHECK(nodus_witness_peer_handle_fwd_req(w, &fm) == 0,
              "the claim is pooled the production way, BEFORE the fault — "
              "admission reads the same table and would refuse it after");

        p3_pool(w, p3_mkentry(0x5D, 500, 1));
        uint8_t n_ctl[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0x5D, n_ctl);
        uint8_t ctx[NODUS_T3_TX_HASH_LEN];
        memset(ctx, 0x5D, sizeof(ctx));
        CHECK(nodus_witness_nullifier_add(w, n_ctl, ctx) == 0 &&
              nodus_witness_nullifier_exists(w, n_ctl),
              "a DECIDED legacy entry sits beside it, at the head");
        CHECK(w->mempool.count == 2 &&
              w->mempool.entries[0]->fee == 500 &&
              w->mempool.entries[1]->fee == 100,
              "two entries, the decided one first");

        /* THE FAULT. */
        CHECK(p3c_claims_table_readable(w),
              "the spent-claim table is readable BEFORE the fault — so the "
              "difference below is the fault and not a fixture that never "
              "had the table");
        p3c_sql(w->db, "DROP TABLE v2_claims_spent");
        CHECK(!p3c_claims_table_readable(w),
              "and the spent-claim query now FAILS TO PREPARE: this is a "
              "genuine DB fault, the same one a corrupt or half-migrated "
              "database produces");

        int dropped = nodus_witness_mempool_evict_committed(w);
        CHECK(dropped == 1,
              "the reaper still RAN and still evicted the entry the LEGACY "
              "table decides — the fault took one question down, not the "
              "whole reaper");
        CHECK(w->mempool.count == 1, "one survives");
        CHECK(w->mempool.entries[0]->tx_type == NODUS_W_TX_V2_CLAIM &&
              memcmp(w->mempool.entries[0]->nullifiers[0], want_nul, 64) == 0,
              "and it is the CLAIM. A spent-check that answered SPENT on a "
              "fault — the direction that is CORRECT for admission — would "
              "have deleted a client's pending work right here");
        CHECK(w->mempool.entries[1] == NULL, "the vacated slot was cleared");

        free(cbytes);
        free(c);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §14 O15J A — POOL-THEN-FORWARD ───────────────────────────────
     *
     * THE DEFECT. §13 built the whole P3 deadman on the predicate
     * `mempool.count > 0 || pending_forward_count > 0`. On the ONE node a
     * client is actually talking to, BOTH halves read zero: the
     * non-leader intake took a pending_forwards slot (which carries no
     * transaction bytes — see the struct in nodus_witness.h) and, when the
     * leader could not be reached, RELEASED the slot and discarded the
     * work. Measured on the 20-node rehearsal: after block 42 committed,
     * node1 made 44 forward attempts with 0 successes and "P3 committed
     * tip frozen" fired ZERO times; no round for height 43 was ever opened
     * by any of the 14 alive nodes.
     *
     * This is PBFT's own client protocol, half-implemented. §4.4's "a
     * backup starts a timer on a request" was there; §4.1's "the request
     * reaches enough replicas" was not.
     *
     * WHY THE SECTIONS ARE SHAPED THIS WAY. §14a drives the REAL
     * production entry point (nodus_witness_handle_dnac with a CBOR
     * dnac_spend payload) rather than the pooling helper, because a
     * helper-only test would still pass with the call site DELETED — the
     * season's recurring vacuity. §14b is the discriminating one for the
     * ORPHAN shape. ─────────────────────────────────────────────────── */

    /* ── §14a — the CALL SITE: a non-leader intake pools, orphaned ─────
     *
     * The fake conn is ZEROED on purpose: nodus_conn_state_t has
     * NODUS_CONN_CLOSED == 0, and nodus_tcp_send_progress returns -1 on a
     * CLOSED conn BEFORE it touches the fd, so every send_error on this
     * path is a safe no-op and no byte is ever written to fd 0.
     *
     * The fixture has peer_count == 0, so the leader-conn lookup finds
     * nothing and the intake takes the O15J B "leader not reachable"
     * exit — the exact path that used to discard the work. ─────────── */
    printf("§14a O15J A — a successor NON-LEADER pools the client's entry "
           "before forwarding, and keeps it when the forward fails\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15j_call_XXXXXX";
        chain_db_open(w, dir, 0x41);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));   /* ~25 KB — heap */
        if (!cx) { fprintf(stderr, "o15j chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);

        CHECK(w->v2_successor, "the chain is a committed V2 SUCCESSOR");
        CHECK(nodus_witness_v2_ingress_is_armed(w) == 1,
              "and its ingress is ARMED, so admission really runs — a "
              "closed gate would refuse everything and the pool would stay "
              "empty for a reason that has nothing to do with O15J");

        dna_claim_t *c = p3c_make_claim(cx, 0);
        size_t clen = 0;
        uint8_t chash[64];
        uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);

        uint8_t want_nul[64];
        p3c_claim_nullifier(c, want_nul);

        size_t plen = 0;
        uint8_t *pl = o15j_spend_payload(cbytes, clen, chash, 0, &plen);

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w),
              "we are NOT the leader — this is the branch that used to "
              "forward-and-forget");
        CHECK(w->mempool.count == 0, "the pool starts EMPTY");
        CHECK(w->pending_forward_count == 0, "and no forward is pending");
        CHECK(w->peer_count == 0,
              "no peer connections exist, so the leader can NOT be reached "
              "— the discard path, reproduced");

        /* THE PRODUCTION ENTRY POINT, not the helper. */
        nodus_witness_handle_dnac(w, &o15j_fake_conn, pl, plen,
                                  "dnac_spend", 4242);

        CHECK(w->mempool.count == 1,
              "the client's entry is POOLED on the node the client is "
              "talking to — this is the assertion that fails if the "
              "nodus_witness_pool_local_demand call is deleted from the "
              "non-leader branch of handle_dnac_spend");
        CHECK(w->pending_forward_count == 0,
              "and the pending_forwards slot was released, exactly as "
              "before — the forward still failed; what changed is that the "
              "WORK no longer died with it");

        /* THE ORPHAN SHAPE — see §14b for why each field is this value. */
        nodus_witness_mempool_entry_t *e0 = w->mempool.entries[0];
        CHECK(e0->client_conn == NULL,
              "pooled with NO client connection (the orphan form)");
        CHECK(e0->is_forwarded,
              "marked forwarded, so the commit path answers a forwarder id "
              "rather than a client conn it does not have");
        CHECK(memcmp(e0->forwarder_id, w->my_id,
                     NODUS_T3_WITNESS_ID_LEN) == 0,
              "and the forwarder id is OUR id — we hold the client "
              "connection, so whichever node commits this answers us");
        CHECK(e0->tx_type == NODUS_W_TX_V2_CLAIM,
              "pooled as the byte-classified entry class (201)");
        CHECK(memcmp(e0->tx_hash, chash, NODUS_T3_TX_HASH_LEN) == 0,
              "keyed on the submitted tx_hash");
        CHECK(e0->tx_len == (uint32_t)clen &&
              memcmp(e0->tx_data, cbytes, clen) == 0,
              "carrying the transaction BYTES — the thing a "
              "pending_forwards slot never held, and the reason the stall "
              "detector could not see this client");
        CHECK(e0->nullifier_count == 1 &&
              memcmp(e0->nullifiers[0], want_nul, 64) == 0,
              "with the committed nullifier consensus derives (O15F) — "
              "§14e is what this is for");

        /* THE CLIENT RETRY, which is the other half of O15J B. The entry
         * is already ours, so the tx_hash pre-check answers ALREADY HELD
         * and nothing is double-pooled. See §14c for why that pre-check
         * exists rather than falling through to mempool_add: on the CLAIM
         * lane admission's own pending-mempool dedup fires first, so the
         * two entry classes would otherwise answer a retry differently. */
        nodus_witness_handle_dnac(w, &o15j_fake_conn, pl, plen,
                                  "dnac_spend", 4243);
        CHECK(w->mempool.count == 1,
              "a client retry while we hold the entry does not double-pool");
        CHECK(w->mempool.entries[0] == e0,
              "and it is the SAME entry object — the retry neither "
              "replaced nor duplicated the work we are already carrying");
        CHECK(w->pending_forward_count == 0, "and leaks no forward slot");

        free(pl);
        free(cbytes);
        free(c);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §14b — DISCONNECT IMMUNITY: the discriminating section ────────
     *
     * THE TRAP THIS PINS. nodus_witness_peer_conn_closed runs for CLIENT
     * connections, not only peer ones: it clears pending_forwards by
     * client_conn and then calls nodus_witness_mempool_remove_by_conn.
     * An entry pooled with the LIVE client conn would therefore be deleted
     * the moment the CLI disconnects — one step after §14a pooled it — and
     * the entire fix would silently undo itself while every count-based
     * assertion above still passed.
     *
     * ⚠ BOTH ENTRIES ARE IN THE POOL FOR ONE conn_closed CALL, and that is
     * what makes this discriminating rather than merely true. The control
     * entry carries the conn and MUST die; the O15J entry carries NULL and
     * MUST live. A dead eviction path — a fixture where remove_by_conn
     * never ran at all — fails on the control half, so "it survived"
     * cannot pass for the wrong reason. ───────────────────────────────── */
    printf("§14b O15J A — the pooled entry SURVIVES the client disconnect; "
           "an entry holding the conn does not\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15j_disc_XXXXXX";
        chain_db_open(w, dir, 0x42);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));
        if (!cx) { fprintf(stderr, "o15j chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);

        dna_claim_t *c = p3c_make_claim(cx, 0);
        size_t clen = 0;
        uint8_t chash[64];
        uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");

        /* THE CONTROL entry: identical in every way that matters EXCEPT
         * that it holds the client conn. Fee 500 puts it at the head, so
         * the survivor below has to be MOVED and the compaction really
         * runs. */
        nodus_witness_mempool_entry_t *ctl = p3_mkentry(0xC1, 500, 1);
        ctl->client_conn = &o15j_fake_conn;
        p3_pool(w, ctl);

        /* THE O15J entry, pooled the production way. */
        char why[256] = {0};
        int prc = nodus_witness_pool_local_demand(w, cbytes, (uint32_t)clen,
                      chash, NODUS_W_TX_V2_CLAIM, NULL, 0, NULL, NULL, 0,
                      why, sizeof(why));
        CHECK(prc == 0, "the admissible claim was pooled");
        CHECK(w->mempool.count == 2, "both entries are in the pool");
        CHECK(w->mempool.entries[0]->client_conn == &o15j_fake_conn,
              "the control entry HOLDS the client conn");
        CHECK(w->mempool.entries[1]->client_conn == NULL,
              "the O15J entry holds NULL — this single field is the whole "
              "difference between the two");

        /* ONE call, both entries exposed to it. */
        nodus_witness_peer_conn_closed(w, &o15j_fake_conn);

        CHECK(w->mempool.count == 1,
              "exactly one entry was evicted — so remove_by_conn really "
              "ran; a dead eviction path would leave both and make the "
              "survival half below meaningless");
        CHECK(w->mempool.entries[0]->tx_type == NODUS_W_TX_V2_CLAIM &&
              memcmp(w->mempool.entries[0]->tx_hash, chash,
                     NODUS_T3_TX_HASH_LEN) == 0,
              "and the SURVIVOR is the O15J entry, compacted to the head. "
              "This is the assertion that fails if the helper pools with "
              "the live conn instead of NULL — the client's disconnect "
              "would then delete the demand the stall detector needs");
        CHECK(w->mempool.entries[1] == NULL, "the vacated slot was cleared");

        /* And the same disconnect a second time changes nothing. */
        nodus_witness_peer_conn_closed(w, &o15j_fake_conn);
        CHECK(w->mempool.count == 1,
              "an orphaned entry is unreachable by conn-based eviction, on "
              "every call — by design; the O15I P3(c) reaper is what "
              "removes it, and §14e proves it still does");

        free(cbytes);
        free(c);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §14c — ADMISSION still gates what a follower will hold ────────
     *
     * The property that makes pooling on a non-leader safe at all: the
     * bytes pass the SAME NODUS_WITNESS_VERIFY_ADMISSION lane a direct
     * client submission takes, so nothing unverified enters the pool.
     *
     * THE POSITIVE CONTROL IS IN THE SAME FIXTURE, deliberately: a
     * negative alone would also pass for a helper that pools NOTHING,
     * which is the pre-O15J behaviour. ──────────────────────────────── */
    printf("§14c O15J A — bytes that fail admission are NOT pooled, while "
           "admissible bytes in the same fixture are\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15j_adm_XXXXXX";
        chain_db_open(w, dir, 0x43);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));
        if (!cx) { fprintf(stderr, "o15j chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);

        CHECK(nodus_witness_v2_ingress_is_armed(w) == 1,
              "the ingress is ARMED — the refusal below is admission's "
              "verdict on the bytes, not a closed gate (the §13e2 rule)");

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");

        /* Bytes with no V2 wire-family marker. */
        uint8_t raw[256];
        memset(raw, 0x5A, sizeof(raw));
        uint8_t rhash[64];
        memset(rhash, 0x5B, sizeof(rhash));

        char why[256] = {0};
        /* Classified the way the production intake classifies it — a
         * hand-picked tx_type would test a path handle_dnac_spend never
         * produces. */
        int rrc = nodus_witness_pool_local_demand(w, raw, (uint32_t)sizeof(raw),
                      rhash,
                      nodus_witness_v2_classify_entry(raw, (uint32_t)sizeof(raw)),
                      NULL, 0, NULL, NULL, 0, why, sizeof(why));
        CHECK(rrc == -2 || rrc == -3,
              "admission REFUSED the unverified bytes");
        CHECK(why[0] != '\0',
              "with a reason, so the follower's log says why it declined");
        CHECK(w->mempool.count == 0,
              "and NOTHING was pooled — this is the assertion that fails "
              "if the `if (vrc != 0)` admission gate is removed from "
              "nodus_witness_pool_local_demand");

        /* THE POSITIVE CONTROL — same fixture, same call, real claim. */
        dna_claim_t *c = p3c_make_claim(cx, 0);
        size_t clen = 0;
        uint8_t chash[64];
        uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);

        CHECK(nodus_witness_pool_local_demand(w, cbytes, (uint32_t)clen,
                  chash, NODUS_W_TX_V2_CLAIM, NULL, 0, NULL, NULL, 0,
                  why, sizeof(why)) == 0,
              "an ADMISSIBLE entry in the same fixture IS pooled — so the "
              "refusal above came from the bytes, not from a helper that "
              "never pools anything");
        CHECK(w->mempool.count == 1, "and it is the only thing in the pool");

        /* ── THE RETRY ANSWER, and a correction to the dispatch's premise.
         *
         * "A client retry meets mempool_add's duplicate rejection" holds
         * on the ENVELOPE lane only. For a class-201 CLAIM the successor
         * admission lane has its OWN pending-mempool dedup, in ADMISSION
         * mode, keyed on the claim NULLIFIER rather than on tx_hash
         * (nodus_witness_verify.c, "claim nullifier already pending in
         * mempool") — so a retried claim is refused THERE and never
         * reaches mempool_add. Left alone, an envelope retry would answer
         * 1 and a claim retry -2, and O15J B would then tell a retrying
         * claim client its work was NOT queued when it is.
         *
         * The tx_hash pre-check at the top of the helper is what makes the
         * two classes agree. THIS assertion is what fails if it is
         * removed: the claim below would come back -2, not 1. ────────── */
        memset(why, 0, sizeof(why));
        CHECK(nodus_witness_pool_local_demand(w, cbytes, (uint32_t)clen,
                  chash, NODUS_W_TX_V2_CLAIM, NULL, 0, NULL, NULL, 0,
                  why, sizeof(why)) == 1,
              "offering the SAME claim twice reports ALREADY HELD (1), not "
              "an admission refusal — the work is visible either way, and "
              "the O15J B client-retry answer depends on this being 1");
        CHECK(why[0] == '\0',
              "and no rejection reason was produced — nothing was judged, "
              "because the pre-check answered before admission ran");
        CHECK(w->mempool.count == 1, "and did not double-pool");

        free(cbytes);
        free(c);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ── §14d — O15K §3.1 SUPERSEDED O15J A's "legacy untouched" ───────
     *
     * ⚠ THIS SECTION'S CONTRACT WAS DELIBERATELY INVERTED, and the old
     * text is kept below so the change is auditable rather than silent.
     *
     * O15J A shipped `pool_local_demand` with a `!w->v2_successor → -1`
     * gate and this section asserted it: -1 was NOT APPLICABLE, the
     * successor gate declining before admission ran, and legacy stayed
     * byte-identical to before. The reasoning was that a legacy peer
     * refuses a non-leader forward anyway, so pooled legacy demand could
     * never recruit the f+1 backers a rotation needs.
     *
     * O15K DELETED THAT GATE ON PURPOSE, because the premise turned out
     * to be the bug rather than a safeguard. Leaving legacy unpooled is
     * precisely why a dead leader halts the chain indefinitely: the one
     * node a client reached had nowhere to put the work, so the predicate
     * the P3 deadman arms on read zero everywhere. §3.2 removes the peer
     * refusal (`nodus_witness_peer.c:883`) in the same change, so the
     * f+1 argument above no longer holds either. See
     * docs/plans/2026-08-27-dead-leader-liveness-design.md §3.1-§3.4, and
     * the two live defects the same change closes (V-1, V-8).
     *
     * ⚠ THE ASSERTION IS STILL ON THE EXACT CODE, not merely on an empty
     * pool — only the expected code moved. A -1 here now means the O15K
     * gate deletion was REVERTED and the halt is back; an
     * `mempool.count == 0` assertion alone would pass either way and pin
     * nothing. These particular bytes are a zero-filled SPEND with no
     * signer section, so admission must REFUSE them — which is the point:
     * the lane is open, and it is open only to work the chain would
     * accept. ─────────────────────────────────────────────────────── */
    printf("§14d O15K §3.1 — a LEGACY chain declines THROUGH admission, "
           "not before it; a -1 here means the fix was reverted\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15j_legacy_XXXXXX";
        chain_db_open(w, dir, 0x44);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §13a)");
        CHECK(!w->v2_successor,
              "this fixture is a LEGACY chain — the lane O15J must leave "
              "exactly as it found it");

        /* §13e's structurally valid legacy SPEND. */
        uint8_t ltx[DNAC_TX_HEADER_SIZE + 1 + 136];
        memset(ltx, 0, sizeof(ltx));
        ltx[1] = NODUS_W_TX_SPEND;
        ltx[DNAC_TX_HEADER_SIZE] = 1;                  /* input_count */
        memset(ltx + DNAC_TX_HEADER_SIZE + 1, 0x7E, NODUS_T3_NULLIFIER_LEN);

        uint8_t lhash[NODUS_T3_TX_HASH_LEN];
        memset(lhash, 0x7F, sizeof(lhash));
        uint8_t lnul[NODUS_T3_NULLIFIER_LEN];
        memset(lnul, 0x7E, sizeof(lnul));

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");

        char why[256] = {0};
        int lrc = nodus_witness_pool_local_demand(w, ltx, (uint32_t)sizeof(ltx),
                      lhash, NODUS_W_TX_SPEND, lnul, 1, NULL, NULL, 1000,
                      why, sizeof(why));
        CHECK(lrc != -1,
              "the NOT APPLICABLE gate is GONE — a -1 here means O15K "
              "§3.1 was reverted and the dead-leader halt is back");
        CHECK(lrc == -2,
              "and the answer is admission's own refusal (-2): these "
              "bytes carry no signer section, so the LEGACY admission "
              "lane ran and rejected them. This is the half that proves "
              "the lane opened ONLY to work the chain would accept");
        CHECK(w->mempool.count == 0, "and nothing unverifiable was pooled");
        CHECK(why[0] != '\0',
              "with a rejection reason — something was JUDGED, which is "
              "exactly what distinguishes admission's refusal from the "
              "old gate's silent decline");

        /* The successor gate lives in exactly ONE place — this helper — so
         * the call site in handle_dnac_spend cannot drift away from it. */
        chain_db_drop(w, dir);
    }

    /* ── §14e — (B) SILENCE: the verdict machinery still governs the
     *            newly pooled entries ────────────────────────────────
     *
     * THE DOOR O15I V1 CLOSED, RE-OPENED FROM A NEW SIDE. O15J pools a
     * class-201 CLAIM on a follower, and a claim's verdict is UNJUDGED by
     * construction (nodus_witness_v2_entry_verdict's class gate answers
     * only for a class-200 ENVELOPE). The ONLY thing that can ever judge
     * a pooled claim is its committed NULLIFIER — which exists on the
     * entry solely because the helper re-derives it (O15F). Delete that
     * re-derivation and the claim is pooled with nullifier_count == 0:
     * the reaper's nullifier walk cannot see it, the verdict answers
     * UNJUDGED, NOTHING removes it, and it arms the P3 deadman against a
     * healthy leader forever — the exact O15I V1 shape, through a new
     * door. Both (a) and (c) below fail in that case.
     *
     * The order is §13k's, for §13k's reason: the rotation in (b) leaves
     * the phase in VIEW_CHANGE, so it has to come after the IDLE-branch
     * observation in (a). ───────────────────────────────────────────── */
    printf("§14e O15J A — a pooled entry the chain has DECIDED is not "
           "demand and IS reaped\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_o15j_reap_XXXXXX";
        chain_db_open(w, dir, 0x45);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        p3c_chain_t *cx = calloc(1, sizeof(*cx));
        if (!cx) { fprintf(stderr, "o15j chain alloc\n"); exit(1); }
        p3c_make_successor(w, all, 7, cx);

        dna_claim_t *c = p3c_make_claim(cx, 0);
        size_t clen = 0;
        uint8_t chash[64];
        uint8_t *cbytes = p3c_encode_claim(c, &clen, chash);
        uint8_t want_nul[64];
        p3c_claim_nullifier(c, want_nul);

        w->current_view = p2_pick_view(w, false);
        CHECK(!nodus_witness_bft_is_leader(w), "we are NOT the leader");

        /* Pooled while the claim is still UNSPENT — admission's cross-block
         * spent check would refuse it after the commit below. fee 500 puts
         * it at the head so the §14e(c) survivor has to be MOVED. */
        char why[256] = {0};
        CHECK(nodus_witness_pool_local_demand(w, cbytes, (uint32_t)clen,
                  chash, NODUS_W_TX_V2_CLAIM, NULL, 0, NULL, NULL, 500,
                  why, sizeof(why)) == 0,
              "the claim is pooled the production way");
        CHECK(w->mempool.count == 1 &&
              w->mempool.entries[0]->nullifier_count == 1 &&
              memcmp(w->mempool.entries[0]->nullifiers[0], want_nul, 64) == 0,
              "carrying the committed nullifier consensus derives — the "
              "ONE handle anything has on a pooled class-201 claim");
        CHECK(nodus_witness_v2_entry_verdict(w, cbytes, (uint32_t)clen) ==
              NODUS_W_ENTRY_UNJUDGED,
              "and the class-200 verdict lane says UNJUDGED about it, as "
              "its class gate must — which is exactly why the nullifier "
              "above is load-bearing and not decoration");

        /* ⚠ O15K V-3 — THE FIXTURE CHANGED, AND ITS OLD GREEN WAS THE BUG.
         *
         * This section used to decide the claim with
         * nodus_witness_nullifier_add(), i.e. by writing the LEGACY
         * `nullifiers` table, and then asserted the reaper removed it.
         * That passed — and passing was the defect. A class-201 claim's
         * nullifier is committed to `v2_claims_spent`
         * (nodus_witness_v2_claim_spend_insert); the legacy table's ONLY
         * writer is apply_tx_to_state, which a successor commit never
         * reaches (nodus_witness_bft.c: the successor branch runs
         * nodus_witness_v2_produce_commit, and its own comment records
         * that commit_batch is not on that path). So the fixture was
         * simulating a row that cannot exist on a real successor chain,
         * and the old assertion proved only that the reaper agreed with
         * an impossible state.
         *
         * The chain now decides the claim THE PRODUCTION WAY —
         * p3c_commit_claim runs admit → output create → spend insert →
         * distribution decrement — so the row lands where consensus
         * really puts it, and the reaper's V-3 routing is what has to
         * find it.
         *
         * ⚠ ANTI-VACUITY PAIR, §13f's, now asked of the RIGHT table:
         * both answers are pinned before and after, so a fixture whose
         * commit silently did nothing cannot make "not reaped" look like
         * a verdict. */
        CHECK(!p3c_claim_is_spent(w, want_nul),
              "the chain has NOT yet decided this claim");
        CHECK(nodus_witness_mempool_evict_committed(w) == 0,
              "so the reaper takes nothing — an undecided entry is kept");
        CHECK(w->mempool.count == 1, "and it is still pooled");

        /* THE CHAIN DECIDES IT — through the real commit steps. */
        p3c_commit_claim(w, c);
        CHECK(p3c_claim_is_spent(w, want_nul),
              "and v2_claims_spent really says so — the fixture is "
              "discriminating, not failing closed on everything");
        CHECK(!nodus_witness_nullifier_exists(w, want_nul),
              "while the LEGACY table stays empty, which is the whole "
              "point of V-3: a claim never appears there, so the walk "
              "that used to be asked could never have found it");

        /* (a) NOT DEMAND — the P3 deadman declines. */
        nodus_witness_bft_check_timeout(w);
        uint64_t anchored = w->last_seen_tip;
        CHECK(p3_stamped_now(w->tip_since_ms), "the demand window armed");
        CHECK(w->pending_forward_count == 0,
              "and NO pending forward — so the predicate below is about "
              "the POOLED entry and nothing else");
        p3_age_window(w, 16000);
        nodus_witness_bft_check_timeout(w);

        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the tick left us IDLE — a claim the chain has already "
              "decided is not a reason to rotate the view, and O15J did "
              "NOT re-open the O15I V1 churn door");
        CHECK(!w->view_change_in_progress, "no view change was started");
        CHECK(w->last_seen_tip == anchored && p3_stamped_now(w->tip_since_ms),
              "and the would-fire point WAS reached (window re-stamped at "
              "the same frozen tip) — declined on the verdict, not skipped");

        /* (b) STILL DEMAND — one undecided entry and it fires. Without
         * this, (a) passes for a predicate that never fires at all, which
         * would disable the whole P3 deadman. */
        p3_pool(w, p3_mkentry(0xC5, 100, 1));
        CHECK(w->mempool.count == 2, "an UNDECIDED entry joins the pool");
        uint8_t n_undecided[NODUS_T3_NULLIFIER_LEN];
        p3_nul_of(0xC5, n_undecided);
        CHECK(!nodus_witness_nullifier_exists(w, n_undecided),
              "and the chain has NOT decided IT — so the fire below is "
              "this entry, and the DB is still discriminating");
        p3_age_window(w, 16000);
        uint32_t view_before = w->current_view;
        nodus_witness_bft_check_timeout(w);
        CHECK(w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE,
              "NOW it rotates — so (a)'s silence is the committed-nullifier "
              "verdict on the O15J entry, not a dead predicate");
        CHECK(w->current_view == view_before,
              "current_view is UNTOUCHED — O15J adds none of its write "
              "sites; only a verified VIEW_OK proof may advance it");

        /* (c) THE REAPER, the other consumer, over the same two entries. */
        CHECK(w->mempool.entries[0]->fee == 500 &&
              w->mempool.entries[1]->fee == 100,
              "the decided O15J entry is at the head and the undecided one "
              "behind it — so the survivor has to be MOVED");
        int dropped = nodus_witness_mempool_evict_committed(w);
        CHECK(dropped == 1,
              "exactly ONE entry was reaped. An orphaned entry is "
              "unreachable by remove_by_conn BY DESIGN (§14b), so this "
              "reaper is the ONLY thing that removes what O15J pools — if "
              "the O15F nullifier re-derivation were dropped from the "
              "helper, this would evict 0 and the entry would leak forever");
        CHECK(w->mempool.count == 1, "one survives");
        CHECK(w->mempool.entries[0]->fee == 100,
              "and it is the UNDECIDED one, compacted to the head — the "
              "survival half; a reaper that dropped everything fails here");
        CHECK(w->mempool.entries[1] == NULL, "the vacated slot was cleared");
        CHECK(nodus_witness_mempool_evict_committed(w) == 0,
              "a second pass reaps nothing");

        free(cbytes);
        free(c);
        free(cx);
        nodus_witness_mempool_clear(&w->mempool);
        chain_db_drop(w, dir);
    }

    /* ══════════════════════════════════════════════════════════════════
     * §15 — O15N Faz 2C2: THE VIEW COUNTER MOVES ONLY ON A PROOF
     *
     * Before this slice `w->current_view` had four writers in
     * nodus_witness_bft.c and only ONE was backed by a proven majority:
     * a PROPOSE copied the leader's claimed view UNCONDITIONALLY in
     * either direction, a NEW_VIEW raised it on a `>` guard and one
     * signature, and reaching one's own view-change quorum set it. After
     * it there is exactly one — a VIEW_OK proof that
     * nodus_witness_bft_verify_view_proof accepted.
     *
     * EVERY SECTION BELOW NEEDS A COMMITTEE, and that is not a fixture
     * convenience. nodus_witness_bft_sign_view_ok refuses when the
     * committee at the height is EMPTY, so on the pre-genesis fixture
     * §1-§5 use, no statement can be signed, no proof can exist, and the
     * view can never move at all. vok_seed_committee both writes the
     * snapshot and PROVES it resolves, because a silent fall-through to
     * the pre-genesis path would make every assertion here vacuous.
     * ══════════════════════════════════════════════════════════════════ */

    /* ── §15a — reaching our OWN quorum SPEAKS; it does not MOVE ───────
     *
     * The write this replaces sat immediately after the "view change
     * quorum!" log in bft_vc_check_quorum. Reverting that one line —
     * putting `w->current_view = w->view_change_target;` back — turns
     * the first assertion below red.
     *
     * THE EMISSION IS MEASURED BY A txn_id DELTA, not by a log line: the
     * fixture has zero peer connections, so nodus_witness_bft_broadcast
     * sends to nobody and prints nothing either way. The delta is taken
     * across the ONE message that completes the quorum, with the
     * previous message (which does not) as the converse — so a build
     * that emitted on every VIEW_CHANGE would fail the converse and one
     * that never emitted would fail the positive. ─────────────────── */
    printf("§15a O15N — our own view-change quorum emits a statement and "
           "does NOT move the view\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_vok_emit_XXXXXX";
        chain_db_open(w, dir, 0x41);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

        /* ANTI-VACUITY: the numbers this section reasons about, asserted
         * before anything depends on them. */
        CHECK(w->bft_config.quorum == 3,
              "view-change quorum is 3 — so our self-record plus TWO peer "
              "votes is exactly the threshold, with no slack");
        CHECK(w->view_change_count == 0 && !w->viewok_acc.active,
              "and we start from a clean slate: no records, nothing said");

        uint32_t view_before = w->current_view;

        /* We start our own view change: self-record + one broadcast. */
        CHECK(nodus_witness_bft_initiate_view_change(w) == 0,
              "we initiated a view change");
        CHECK(w->view_change_target == view_before + 1,
              "at the ordinary current_view + 1");
        CHECK(tally_at(w, w->view_change_target) == 1,
              "one voter so far: us");

        nodus_t3_msg_t vc;
        fill_viewchg(&vc, w, &p[0], w->view_change_target);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "first peer vote recorded");
        CHECK(tally_at(w, w->view_change_target) == 2, "two voters");

        /* THE CONVERSE, measured on the message BELOW the threshold. */
        uint64_t txn_below = w->next_txn_id;
        CHECK(!w->viewok_acc.active,
              "BELOW the quorum nothing has been said — the accumulator "
              "is still empty, so the emission below is caused by the "
              "quorum and not by merely receiving a VIEW_CHANGE");

        /* THE MESSAGE THAT COMPLETES THE QUORUM. */
        fill_viewchg(&vc, w, &p[1], w->view_change_target);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "second peer vote recorded — quorum reached");
        CHECK(tally_at(w, w->view_change_target) == 3,
              "three voters: the quorum, exactly");

        /* ⚠ THE ASSERTION THIS SECTION EXISTS FOR. */
        CHECK(w->current_view == view_before,
              "reaching our OWN quorum did NOT move the view — reverting "
              "the deleted `w->current_view = w->view_change_target;` in "
              "bft_vc_check_quorum turns this red");
        CHECK(w->next_txn_id == txn_below + 1,
              "and EXACTLY ONE message was emitted: the VIEW_OK statement");
        CHECK(w->viewok_acc.active && w->viewok_acc.n_entries == 1,
              "the accumulator holds exactly one statement");
        CHECK(memcmp(w->viewok_acc.entries[0].voter_id, w->my_id,
                     NODUS_T3_WITNESS_ID_LEN) == 0,
              "and it is OURS");
        CHECK(w->viewok_acc.view == w->view_change_target &&
              w->viewok_acc.height == tip + 1,
              "anchored on (our next height, the target view) — the same "
              "height every committee gate in the handler resolves at");

        /* EXACTLY ONCE. bft_vc_check_quorum re-runs on every VIEW_CHANGE
         * that arrives after the quorum; without the latch in
         * bft_viewok_emit_own each of those would broadcast again, and
         * the f+1 rule rests on an honest node speaking once. */
        uint64_t txn_after = w->next_txn_id;
        fill_viewchg(&vc, w, &p[2], w->view_change_target);
        CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
              "a FOURTH voter arrives after the quorum");
        CHECK(tally_at(w, w->view_change_target) == 4, "the tally grew");
        CHECK(w->next_txn_id == txn_after,
              "but NOTHING was sent — the exactly-once latch held; "
              "deleting the own-slot check in bft_viewok_emit_own turns "
              "this red");
        CHECK(w->viewok_acc.n_entries == 1, "and no second slot was taken");

        chain_db_drop(w, dir);
    }

    /* ── §15b — f+1 statements MOVE the view; f do not ─────────────────
     *
     * A SEVEN-MEMBER committee, deliberately: dna_bft_quorum(7) = 5 and
     * the verifier's threshold is ((5-1)/2)+1 = 3, so "f" is 2 and "f+1"
     * is 3. At the four-member committee the other sections use, f would
     * be 1 and the boundary would be "one statement vs two" — a test
     * that a broken threshold of 1 could still pass.
     *
     * Reverting the `verified < required` return in
     * nodus_witness_bft_verify_view_proof turns the f leg red; reverting
     * the `w->current_view = view;` write in bft_viewok_apply turns the
     * f+1 leg red. ──────────────────────────────────────────────────── */
    printf("§15b O15N — f+1 statements move the view, f do not\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 5, 15000, 10000);
        char dir[] = "/tmp/test_bft_vok_f1_XXXXXX";
        chain_db_open(w, dir, 0x42);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");
        vok_seed_committee(w,
            (peer_t[]){self, p[0], p[1], p[2], p[3], p[4], p[5]}, 7);
        CHECK(w->bft_config.quorum == 5,
              "view-change quorum is 5 over a committee of 7 — so f is 2 "
              "and f+1 is 3, which is what makes this section stronger "
              "than a four-member one");

        uint32_t view_before = w->current_view;
        CHECK(nodus_witness_bft_initiate_view_change(w) == 0, "we initiate");
        uint32_t T = w->view_change_target;
        nodus_t3_msg_t vc;
        for (int i = 0; i < 4; i++) {
            fill_viewchg(&vc, w, &p[i], T);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                  "peer vote recorded");
        }
        CHECK(tally_at(w, T) == 5, "the view-change quorum of 5 is met");
        CHECK(w->viewok_acc.n_entries == 1 && w->current_view == view_before,
              "we spoke once and did not move");

        uint64_t H = w->viewok_acc.height;
        uint8_t sh[64];
        memcpy(sh, w->viewok_acc.set_hash, 64);

        /* f = 2 — NOT ENOUGH. */
        CHECK(vok_deliver1(w, &p[0], H, T, sh) == 0,
              "a second statement is folded");
        CHECK(w->viewok_acc.n_entries == 2, "two statements held");
        CHECK(w->current_view == view_before,
              "TWO statements (f) did NOT move the view");

        /* f+1 = 3 — ENOUGH. */
        CHECK(vok_deliver1(w, &p[1], H, T, sh) == 0,
              "a third statement is folded");
        CHECK(w->viewok_acc.n_entries == 3, "three statements held");
        CHECK(w->current_view == T,
              "THREE statements (f+1) MOVED the view — the one writer");
        CHECK(w->viewok_proof.active && w->viewok_proof.view == T &&
              w->viewok_proof.n_entries == 3,
              "and the proof that moved us was RETAINED, so we can rescue "
              "a node behind us");

        /* THE POST-MOVE BLOCK RAN — the C5 self-bind, the persist and the
         * phase reset that used to sit inline in bft_vc_check_quorum. */
        CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "the post-move block returned us to IDLE");
        CHECK(!w->view_change_in_progress && !w->view_change_voted,
              "and cleared the view-change flags — proof that the whole "
              "extracted block ran, not just the write");

        /* ── ASSERTION 5: a proof for a view we already hold is INERT.
         * Both observables are checked because the post-move block has
         * two different visible effects: a non-leader ARMS the deadman
         * and a leader BROADCASTS a NEW_VIEW. Re-running it would move
         * one or the other, whichever role this run landed on. */
        w->awaiting_propose_deadline_ms = 0;
        uint64_t txn_before_replay = w->next_txn_id;
        /* ONE large object, re-filled — the convention §13e set. A second
         * nodus_t3_msg_t automatic in the same block is ~600 KB of stack
         * for no reason. */
        vok_fill(&vc, w, H, T, sh, (peer_t[]){p[0], p[1], p[2]}, 3);
        CHECK(nodus_witness_bft_handle_viewok(w, &vc) == 0,
              "the SAME proof is replayed and processed");
        CHECK(w->current_view == T, "the view is unchanged");
        CHECK(w->awaiting_propose_deadline_ms == 0 &&
              w->next_txn_id == txn_before_replay,
              "and the post-move block did NOT re-run — a proof for a view "
              "we already hold is inert; deleting the `view <= "
              "w->current_view` guard in bft_viewok_apply turns this red");

        chain_db_drop(w, dir);
    }

    /* ── §15c — a PROPOSE at a different view is REFUSED, BOTH ways ────
     *
     * ⚠ THE LOWER DIRECTION IS THE DEFECT THE SEASON EXISTS TO CLOSE.
     * handle_propose used to execute `w->current_view = hdr->view;`
     * unconditionally, so the correct leader for a view the cluster had
     * already LEFT could drag this node back to it — and `current_view`
     * is what leader election reads.
     *
     * ORDER IS LOAD-BEARING: both refusals run while the phase is IDLE,
     * and the POSITIVE CONTROL runs last. A control that ran first would
     * put us in PREVOTE, and every later proposal would then be refused
     * by the round-in-progress check instead of by the view gate — the
     * two refusals would look identical and prove nothing. ──────────── */
    printf("§15c O15N — a PROPOSE at any other view is refused, in both "
           "directions, and the counter never moves\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_vok_prop_XXXXXX";
        chain_db_open(w, dir, 0x43);

        peer_t all[7];
        all[0] = self;
        for (int i = 0; i < 6; i++) all[i + 1] = p[i];

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

        /* Three consecutive views, none of them led by us, so every
         * message below passes the leader gate and reaches the view gate
         * that is under test. */
        uint32_t VL = 0, VC = 0, VH = 0;
        {
            bool found = false;
            uint32_t lim = w->roster.n_witnesses * 2 + 2;
            for (uint32_t a = 1; a + 2 <= lim && !found; a++) {
                if (p2_is_leader_at(w, a) || p2_is_leader_at(w, a + 1) ||
                    p2_is_leader_at(w, a + 2))
                    continue;
                VL = a; VC = a + 1; VH = a + 2; found = true;
            }
            CHECK(found, "found three consecutive views, none led by us");
        }
        w->current_view = VC;

        uint8_t ptx[NODUS_T3_TX_HASH_LEN];
        memset(ptx, 0xD4, sizeof(ptx));
        uint8_t proot[NODUS_T3_TX_HASH_LEN];
        {
            nodus_key_t bh;
            if (nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) != 0) {
                fprintf(stderr, "tx_root hash\n"); exit(1);
            }
            memcpy(proot, bh.bytes, NODUS_T3_TX_HASH_LEN);
        }

        /* One PROPOSE builder, three views — so the ONLY thing that
         * varies between the legs is hdr.view. */
        nodus_t3_msg_t pm;
        for (int leg = 0; leg < 3; leg++) {
            uint32_t V = (leg == 0) ? VH : (leg == 1) ? VL : VC;
            const peer_t *leader = p2_leader_at(w, all, V);
            CHECK(memcmp(leader->id, w->my_id,
                         NODUS_T3_WITNESS_ID_LEN) != 0,
                  "the proposal's sender is the expected leader for its "
                  "own view and is not us");

            memset(&pm, 0, sizeof(pm));
            pm.type = NODUS_T3_PROPOSE;
            pm.header.round = 11 + (uint64_t)leg;
            pm.header.view = V;
            memcpy(pm.header.sender_id, leader->id, NODUS_T3_WITNESS_ID_LEN);
            memcpy(pm.header.chain_id, w->chain_id,
                   sizeof(pm.header.chain_id));
            pm.header.timestamp = nodus_time_now();
            nodus_random((uint8_t *)&pm.header.nonce, sizeof(pm.header.nonce));
            pm.propose.batch_count = 1;
            pm.propose.block_height = tip + 1;
            memcpy(pm.propose.batch_txs[0].tx_hash, ptx,
                   NODUS_T3_TX_HASH_LEN);
            pm.propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
            memcpy(pm.propose.tx_root, proot, NODUS_T3_TX_HASH_LEN);

            uint32_t held = w->current_view;
            int rc = nodus_witness_bft_handle_propose(w, &pm);

            if (leg == 0) {
                CHECK(rc == -1,
                      "a PROPOSE at a HIGHER view is REFUSED");
                CHECK(w->current_view == held,
                      "and the counter did not RISE — one leader's word is "
                      "not a proof");
                CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
                      "nothing was written: no round was entered");
            } else if (leg == 1) {
                CHECK(rc == -1,
                      "a PROPOSE at a LOWER view is REFUSED — the OPEN-2 "
                      "regression, where the leader of a view we already "
                      "left used to drag us back to it");
                CHECK(w->current_view == held,
                      "and the counter did not FALL");
                CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE,
                      "nothing was written");
            } else {
                /* ⚠ THE POSITIVE CONTROL. Without it both refusals above
                 * are indistinguishable from a fixture that cannot make
                 * ANY proposal pass. */
                CHECK(rc == 0,
                      "a PROPOSE at EXACTLY our view is ACCEPTED — so the "
                      "two refusals above are the view gate, not a broken "
                      "fixture");
                CHECK(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
                      "and we entered the round");
                CHECK(w->current_view == held,
                      "while the counter STILL did not move: the accepted "
                      "path writes nothing either");
                CHECK(w->round_state.view == held,
                      "and round_state.view records the view we hold");
            }
        }

        chain_db_drop(w, dir);
    }

    /* ── §15d — the verifier's -2 is a FAULT, not a verdict ────────────
     *
     * nodus_witness_bft_verify_view_proof answers -2 when this node
     * resolves a DIFFERENT committee than the one the signers used. That
     * is not "the proof is bad" — it is "I cannot judge" — so it must
     * neither move the view nor destroy the evidence, which would have
     * to be re-collected from scratch once the blind spot cleared.
     *
     * The trigger is a DOCTORED set hash: the peers sign under bytes
     * this node cannot resolve, so step 2 of the verifier fails. The
     * POSITIVE CONTROL that follows uses the REAL hash at the SAME view
     * and DOES move the view — which also exercises the direct path,
     * because the accumulator is by then anchored on the doctored hash
     * and would ignore a same-view bundle under a different one.
     * ─────────────────────────────────────────────────────────────── */
    printf("§15d O15N — a set-hash mismatch is a FAULT: no move, and the "
           "accumulator survives\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_vok_fault_XXXXXX";
        chain_db_open(w, dir, 0x44);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

        /* Drive our own quorum only to LEARN THE REAL SET HASH from the
         * production signer — never by recomputing it here. */
        CHECK(nodus_witness_bft_initiate_view_change(w) == 0, "we initiate");
        uint32_t T = w->view_change_target;
        nodus_t3_msg_t vc;
        for (int i = 0; i < 2; i++) {
            fill_viewchg(&vc, w, &p[i], T);
            CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0, "peer vote");
        }
        CHECK(w->viewok_acc.active && w->viewok_acc.n_entries == 1,
              "we emitted our own statement, so the set hash below is the "
              "one the PRODUCTION signer used");
        uint64_t H = w->viewok_acc.height;
        uint8_t real_sh[64];
        memcpy(real_sh, w->viewok_acc.set_hash, 64);

        uint8_t bad_sh[64];
        memcpy(bad_sh, real_sh, 64);
        bad_sh[0] ^= 0xFF;              /* the ONE varying byte */
        CHECK(memcmp(bad_sh, real_sh, 64) != 0, "the hashes really differ");

        /* A view ABOVE the one being collected, so the doctored bundle
         * RESETS the accumulator and is genuinely the thing being
         * judged. */
        uint32_t VF = T + 5;
        uint32_t view_before = w->current_view;
        CHECK(vok_deliver1(w, &p[0], H, VF, bad_sh) == 0,
              "a doctored statement is folded (it resets the accumulator "
              "to the higher view)");
        CHECK(vok_deliver1(w, &p[1], H, VF, bad_sh) == 0,
              "a second doctored statement reaches the local threshold");
        CHECK(w->viewok_acc.view == VF && w->viewok_acc.n_entries == 2,
              "so the verifier really was asked — two statements at the "
              "higher view; without this the assertions below would pass "
              "for a bundle nobody judged");
        CHECK(w->current_view == view_before,
              "the FAULT did not move the view");
        CHECK(w->viewok_acc.active && w->viewok_acc.n_entries == 2,
              "and it did NOT clear the accumulator — deleting the -2 "
              "branch in bft_viewok_try_accumulator, or making it discard, "
              "turns this red");

        /* ⚠ THE POSITIVE CONTROL, and the direct path in one. Same view,
         * REAL hash, delivered as a two-entry bundle. The accumulator is
         * anchored on the doctored hash at VF and would ignore it, so
         * only the "a bundle that is already a proof is judged on its
         * own" branch in handle_viewok can accept this.
         *
         * ONE large object, re-filled — the convention §13e set. */
        vok_fill(&vc, w, H, VF, real_sh, (peer_t[]){p[0], p[1]}, 2);
        CHECK(nodus_witness_bft_handle_viewok(w, &vc) == 0,
              "the same signers under the REAL set hash are accepted");
        CHECK(w->current_view == VF,
              "and the view MOVED — so the -2 above was the set hash and "
              "nothing else, AND a complete bundle is judged on its own "
              "merits even when the accumulator is anchored elsewhere");

        chain_db_drop(w, dir);
    }

    /* ── §15e — the retained proof answers a request; none answers ─────
     *
     * A node that has never moved holds no proof, and answering NOTHING
     * is the correct answer there rather than an error — the requester
     * asks the next peer and its own escalation ladder keeps running.
     *
     * THE CONNECTION IS REAL ENOUGH TO SEND ON, AND IT HAS TO BE A
     * SOCKET. A zeroed nodus_tcp_conn_t has state == NODUS_CONN_CLOSED
     * and nodus_tcp_send_progress refuses one before it touches the fd,
     * so with a zeroed conn BOTH legs would return -1 and the section
     * would prove nothing. The write itself is `send(2)`
     * (nodus_tcp.c's poll_write macro), which fails ENOTSOCK on an
     * ordinary file — so the fd below is one end of a socketpair. The
     * response is ~9 KB, well inside the default AF_UNIX socket buffer,
     * so it completes in one write with no reader attached. ────────── */
    printf("§15e O15N — a held proof answers a w_viewok_q; a node holding "
           "none answers nothing\n");
    {
        peer_t p[6];
        for (int i = 0; i < 6; i++) peer_make(&p[i]);
        nodus_witness_t *w = fixture(&self, p, 6, 3, 15000, 10000);
        char dir[] = "/tmp/test_bft_vok_req_XXXXXX";
        chain_db_open(w, dir, 0x45);

        uint64_t tip = seed_blocks(w, 3);
        CHECK(tip == 3, "seeded chain tip is 3 (see §12a)");
        vok_seed_committee(w, (peer_t[]){self, p[0], p[1], p[2], p[3]}, 5);

        int sp[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
              "a socketpair for the response to be written into");
        nodus_tcp_conn_t conn;
        memset(&conn, 0, sizeof(conn));
        conn.state = NODUS_CONN_CONNECTED;
        conn.fd = sp[0];

        nodus_t3_msg_t q;
        memset(&q, 0, sizeof(q));
        q.type = NODUS_T3_VIEWOK_REQ;
        memcpy(q.header.sender_id, p[0].id, NODUS_T3_WITNESS_ID_LEN);
        memcpy(q.header.chain_id, w->chain_id, sizeof(q.header.chain_id));
        q.header.timestamp = nodus_time_now();
        nodus_random((uint8_t *)&q.header.nonce, sizeof(q.header.nonce));
        q.viewok_q.height_hint = tip + 1;

        /* The requester's ROSTER SLOT is deterministic and is asserted,
         * because the rate-limit stamps are indexed by it: the fixture
         * appends self first and then the peers, so p[0] is slot 1.
         * Asserting "slot 0 or slot 1 moved" would pass for a limiter
         * keyed on the wrong thing. */
        int rq_slot = nodus_witness_roster_find(&w->roster, p[0].id);
        CHECK(rq_slot == 1, "the requester occupies roster slot 1");

        /* LEG 1 — WE HOLD NOTHING. */
        CHECK(!w->viewok_proof.active, "we have never moved, so no proof");
        CHECK(nodus_witness_bft_handle_viewok_req(w, &conn, &q) == -1,
              "the request is answered with NOTHING");
        CHECK(!w->safety_halt,
              "and holding no proof is not an error state — nothing was "
              "latched, nothing was blamed");
        CHECK(w->viewok_rsp_sent_ms[rq_slot] == 0,
              "and no response stamp was taken, so a later request from "
              "the same peer is not rate-limited out — a limiter that "
              "stamped on the empty answer would make LEG 2 unreachable");

        /* Now MOVE, through the production path, so a proof exists. The
         * VIEW_CHANGE message lives in its own scope: a second
         * nodus_t3_msg_t automatic is ~600 KB, and `q` has to outlive
         * it. */
        uint32_t T = 0;
        {
            CHECK(nodus_witness_bft_initiate_view_change(w) == 0,
                  "we initiate");
            T = w->view_change_target;
            nodus_t3_msg_t vc;
            for (int i = 0; i < 2; i++) {
                fill_viewchg(&vc, w, &p[i], T);
                CHECK(nodus_witness_bft_handle_viewchg(w, &vc) == 0,
                      "peer vote");
            }
        }
        CHECK(w->viewok_acc.active && w->viewok_acc.n_entries == 1,
              "our own statement was emitted at the quorum");
        CHECK(vok_deliver1(w, &p[0], w->viewok_acc.height, T,
                           w->viewok_acc.set_hash) == 0,
              "a peer statement completes f+1");
        CHECK(w->current_view == T, "the view moved");
        CHECK(w->viewok_proof.active && w->viewok_proof.view == T,
              "and the proof was retained");

        /* LEG 2 — WE HOLD ONE. A fresh nonce: the handler is replay
         * checked, and reusing leg 1's would be refused as a duplicate
         * and look like the "nothing to say" answer. */
        nodus_random((uint8_t *)&q.header.nonce, sizeof(q.header.nonce));
        CHECK(nodus_witness_bft_handle_viewok_req(w, &conn, &q) == 0,
              "NOW the request is answered with the retained proof");
        CHECK(w->viewok_rsp_sent_ms[rq_slot] != 0,
              "and the response stamp was taken at the REQUESTER's roster "
              "slot");

        free(conn.wbuf);
        close(sp[0]);
        close(sp[1]);
        chain_db_drop(w, dir);
    }

    printf("PASS test_bft_view_change_hardening\n");
    return 0;
}
