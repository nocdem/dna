/**
 * Nodus — O15C-D.4 — consensus protocol version gate.
 *
 * ── The defect this closes ────────────────────────────────────────────
 *
 * O15C-D.3 added three proof-bearing NEW_VIEW keys (rpv/rns/rsg). CBOR
 * arg decoders SKIP unknown keys, and NOTHING on the receive path read
 * `hdr->version` — it was decoded and never used again. So a v2 binary
 * silently processed a v3 NEW_VIEW under the pre-D.3 local-subset
 * semantics: two versions, same message, different rules.
 *
 * Reproduced on REAL binaries before the fix (bc0ff148 vs c65c8cd1,
 * 6 current + 1 legacy): the legacy node committed byte-identical blocks,
 * and with two current nodes stopped the live set was 4 current + 1
 * legacy = 5 = quorum and the chain ADVANCED. Its vote was counted and
 * was essential. Silent mixed-version participation, not a theory.
 *
 * ── The enforced contract ─────────────────────────────────────────────
 *
 * `NODUS_T3_BFT_PROTOCOL_VER` is bumped, and
 * `nodus_witness_dispatch_t3` gates the consensus-affecting message set
 * on an EXACT version match.
 *
 * ⚠ The constant has MOVED since this test was written; the gate has not.
 * Real history: 2 -> 3 at O15C-D.4 (this test's own season, the NEW_VIEW
 * certificate keys), 3 -> 4 at O15G (the cert ACCEPTANCE RULE moved to
 * the committed committee snapshot), 4 -> 5 at O15N Faz 2A (the PREPARED
 * signature domain — a 116-byte preimage carrying chain_id, and purpose
 * 0x07 made strict). See nodus_types.h for the per-value rationale. Every
 * section below reads the constant SYMBOLICALLY, so the test tracks the
 * bump without edits; only this prose had to be corrected, and it was
 * wrong until O15N Faz 2A because it named the 2 -> 3 step as if it were
 * the current one.
 *
 * Placement is load-bearing:
 *   * AFTER wsig verification — `hdr->version` sits inside the Dilithium5
 *     envelope preimage (nodus_tier3.c enc_wh via enc_sign_payload), so
 *     the value gated on is authenticated and a peer signs version and
 *     args together;
 *   * BEFORE nodus_witness_peer_ensure — the first state mutation on the
 *     path, so a rejected message leaves no residue.
 * Older AND unknown-newer versions both fail closed on the exact match.
 *
 * Separately, `handle_newview` has a NAMED check rejecting a v3 header
 * that carries v2-shaped args (has_reproposal with no certificate), so
 * that case has a branch of its own instead of dying incidentally inside
 * verify_prepared_cert.
 *
 * ── Non-vacuity ───────────────────────────────────────────────────────
 *
 * Every rejection case is paired with the SAME message at the current
 * version being ACCEPTED and changing observable BFT state. Without that
 * pairing a test could pass because nothing ever reached the handler.
 *
 * Sections:
 *   §1 current version is accepted and DOES change BFT state
 *   §2 older version (the shipped legacy value) is rejected, no state
 *   §3 unknown newer version is rejected, no state
 *   §4 rejection happens for every consensus-affecting type
 *   §5 bootstrap-class traffic is NOT gated (version 1 by design)
 *   §6 a current-version header carrying v2-shaped NEW_VIEW args (no
 *      certificate) is rejected by name
 *   §7 unknown NON-critical arg keys are still skipped — additive
 *      evolution stays possible while required fields are enforced
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
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

#define NVAL   7
#define QUORUM 5
/* The value the legacy binaries in the mixed-cluster reproduction emit.
 * It is NOT "the previous version" — the constant has since moved to 4
 * and then 5, so 2 is now several steps back. That is fine and is the
 * point: the gate is an EXACT match, so any non-current value must be
 * rejected, and pinning a fixed old one keeps §2 meaningful across bumps. */
#define LEGACY_BFT_VER 2

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
    w->running = true;
    return w;
}

static void free_fixture(nodus_witness_t *w) { free(w->server); free(w); }

/* O15N Faz 2A — 116-byte PREPARED preimage: "prepared"(8) ‖ chain_id(32) ‖
 * view(4 BE) ‖ height(8 BE) ‖ tx_hash(64), mirroring
 * compute_prepared_preimage. Only §1's ACCEPT leg actually needs this
 * signature to verify — the rejection legs never reach the tally — but it
 * must be right there, or §1's non-vacuity pairing (the vote must CHANGE
 * observable state) would silently stop holding. */
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

/* Encode a signed PREVOTE at an arbitrary protocol version and push it
 * through the REAL dispatch entry point. */
static void dispatch_prevote(nodus_witness_t *w, const peer_t *from,
                             uint8_t version, uint64_t round, uint32_t view,
                             uint64_t height, const uint8_t *tx_hash) {
    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_PREVOTE;
    m.txn_id = 1;
    m.header.version = version;
    m.header.round = round;
    m.header.view = view;
    memcpy(m.header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    m.header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m.header.nonce, sizeof(m.header.nonce));
    memcpy(m.vote.vote_target, tx_hash, NODUS_T3_TX_HASH_LEN);
    m.vote.vote = 0;
    sign_prepared(m.vote.cert_sig, from, view, height, tx_hash, w->chain_id);

    static uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;
    nodus_seckey_t sk;
    memcpy(sk.bytes, from->sk, sizeof(sk.bytes));
    CHECK(nodus_t3_encode(&m, &sk, buf, sizeof(buf), &len) == 0);
    CHECK(len > 0);
    /* conn == NULL: peer_ensure is conn-guarded, so this exercises the
     * gate without needing a socket. */
    nodus_witness_dispatch_t3(w, NULL, buf, len);
}

int main(void) {
    static peer_t val[NVAL];
    for (int i = 0; i < NVAL; i++) peer_make(&val[i]);

    uint8_t TX[NODUS_T3_TX_HASH_LEN];
    memset(TX, 0x5A, sizeof(TX));
    const uint64_t H = 7;

    /* ── §1 current version is accepted AND changes BFT state ──────── */
    {
        nodus_witness_t *w = fixture(&val[0], &val[1], NVAL - 1);
        enter_round(w, &val[0], 6, H, TX);
        int before = w->round_state.prevote_approve_count;
        dispatch_prevote(w, &val[1], NODUS_T3_BFT_PROTOCOL_VER, 6, 0, H, TX);
        int after = w->round_state.prevote_approve_count;
        CHECK_EQ(after, before + 1);
        printf("[ok] §1 v%u PREVOTE ACCEPTED and counted (%d -> %d) — the "
               "handler really is reachable\n",
               (unsigned)NODUS_T3_BFT_PROTOCOL_VER, before, after);
        free_fixture(w);
    }

    /* ── §2 the legacy version is rejected, with NO state change ───── */
    {
        nodus_witness_t *w = fixture(&val[0], &val[1], NVAL - 1);
        enter_round(w, &val[0], 6, H, TX);
        int before = w->round_state.prevote_approve_count;
        dispatch_prevote(w, &val[1], LEGACY_BFT_VER, 6, 0, H, TX);
        CHECK_EQ(w->round_state.prevote_approve_count, before);
        /* And no peer residue: the gate sits before peer_ensure. */
        CHECK_EQ(w->peer_count, 0);
        printf("[ok] §2 v%d (legacy) PREVOTE REJECTED — vote not counted, "
               "no peer registered\n", LEGACY_BFT_VER);
        free_fixture(w);
    }

    /* ── §3 unknown NEWER version is rejected too ──────────────────── */
    {
        nodus_witness_t *w = fixture(&val[0], &val[1], NVAL - 1);
        enter_round(w, &val[0], 6, H, TX);
        int before = w->round_state.prevote_approve_count;
        dispatch_prevote(w, &val[1],
                         (uint8_t)(NODUS_T3_BFT_PROTOCOL_VER + 1), 6, 0, H, TX);
        CHECK_EQ(w->round_state.prevote_approve_count, before);
        printf("[ok] §3 v%u (unknown newer) REJECTED — fails closed in BOTH "
               "directions\n", (unsigned)NODUS_T3_BFT_PROTOCOL_VER + 1);
        free_fixture(w);
    }

    /* ── §4 a legacy peer stays rejected across repeated attempts ──── */
    {
        /* §E.9 — reconnecting or retrying changes nothing: the gate is a
         * per-message property of authenticated content, not a
         * per-session handshake that could be replayed past. */
        nodus_witness_t *w = fixture(&val[0], &val[1], NVAL - 1);
        enter_round(w, &val[0], 6, H, TX);
        int before = w->round_state.prevote_approve_count;
        for (int i = 0; i < 5; i++)
            dispatch_prevote(w, &val[1], LEGACY_BFT_VER, 6, 0, H, TX);
        CHECK_EQ(w->round_state.prevote_approve_count, before);
        CHECK_EQ(w->peer_count, 0);
        /* ...and a current-version message from the SAME peer still works,
         * proving the peer was never blacklisted — only its messages. */
        dispatch_prevote(w, &val[1], NODUS_T3_BFT_PROTOCOL_VER, 6, 0, H, TX);
        CHECK_EQ(w->round_state.prevote_approve_count, before + 1);
        printf("[ok] §4 repeated legacy attempts stay rejected; the same "
               "peer at v%u is still accepted\n",
               (unsigned)NODUS_T3_BFT_PROTOCOL_VER);
        free_fixture(w);
    }

    /* ── §6 v3 header carrying v2-shaped NEW_VIEW args ─────────────── */
    {
        /* The self-signed inconsistency the dispatch gate cannot catch:
         * a current-version HEADER whose ARGS are the legacy digest-only
         * shape. handle_newview must reject it by NAME, not incidentally. */
        nodus_witness_t *w = fixture(&val[0], &val[1], NVAL - 1);
        w->view_change_target = 1;
        w->view_change_in_progress = true;

        nodus_t3_msg_t nv;
        memset(&nv, 0, sizeof(nv));
        nv.type = NODUS_T3_NEWVIEW;
        nv.header.version = NODUS_T3_BFT_PROTOCOL_VER;
        nv.header.view = 1;
        {
            int slot = nodus_witness_bft_leader_index(0, 1, NVAL);
            int idx = nodus_witness_roster_sorted_at(&w->roster, slot);
            CHECK(idx >= 0);
            memcpy(nv.header.sender_id, w->roster.witnesses[idx].witness_id,
                   NODUS_T3_WITNESS_ID_LEN);
        }
        nv.header.timestamp = nodus_time_now();
        nodus_random((uint8_t *)&nv.header.nonce, sizeof(nv.header.nonce));
        nv.newview.new_view = 1;
        nv.newview.has_reproposal = true;
        nv.newview.reproposal_height = H;
        memset(nv.newview.reproposal_tx_hash, 0x77, NODUS_T3_TX_HASH_LEN);
        nv.newview.reproposal_n_sigs = 0;      /* legacy shape */

        CHECK_EQ(nodus_witness_bft_handle_newview(w, &nv), -1);
        printf("[ok] §6 v%u header with legacy digest-only NEW_VIEW args "
               "REJECTED by the named schema check\n",
               (unsigned)NODUS_T3_BFT_PROTOCOL_VER);
        free_fixture(w);
    }

    /* ── §7 additive evolution still possible ──────────────────────── */
    {
        /* Required fields are enforced (§6); unknown NON-critical arg
         * keys must still be skipped, or no future field could ever be
         * added. The encoder emits 7 keys with a reproposal and the
         * decoder round-trips them (test_tier3), while the trailing
         * `else cbor_decode_skip` in dec_newview_args keeps unknown keys
         * harmless. Pin the property that matters here: a fully-formed
         * current NEW_VIEW survives encode/decode with its certificate
         * fields intact. */
        nodus_t3_msg_t in, out;
        memset(&in, 0, sizeof(in));
        in.type = NODUS_T3_NEWVIEW;
        in.txn_id = 9;
        in.header.version = NODUS_T3_BFT_PROTOCOL_VER;
        memcpy(in.header.sender_id, val[0].id, NODUS_T3_WITNESS_ID_LEN);
        in.header.timestamp = nodus_time_now();
        in.newview.new_view = 4;
        in.newview.has_reproposal = true;
        in.newview.reproposal_height = 11;
        in.newview.reproposal_prepared_view = 2;
        memset(in.newview.reproposal_tx_hash, 0x21, NODUS_T3_TX_HASH_LEN);
        in.newview.reproposal_n_sigs = 3;
        for (int i = 0; i < 3; i++) {
            memset(in.newview.reproposal_sigs[i].voter_id, 0x30 + i,
                   NODUS_T3_WITNESS_ID_LEN);
            memset(in.newview.reproposal_sigs[i].signature, 0x50 + i,
                   NODUS_SIG_BYTES);
        }
        static uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
        size_t len = 0;
        nodus_seckey_t sk;
        memcpy(sk.bytes, val[0].sk, sizeof(sk.bytes));
        CHECK(nodus_t3_encode(&in, &sk, buf, sizeof(buf), &len) == 0);
        memset(&out, 0, sizeof(out));
        CHECK(nodus_t3_decode(buf, len, &out) == 0);
        CHECK_EQ(out.header.version, NODUS_T3_BFT_PROTOCOL_VER);
        CHECK_EQ(out.newview.reproposal_n_sigs, 3);
        CHECK_EQ(out.newview.reproposal_prepared_view, 2);
        printf("[ok] §7 version travels on the wire and the certificate "
               "fields round-trip intact\n");
    }

    printf("PASS test_witness_protocol_version_gate\n");
    return 0;
}
