/**
 * Nodus — O15L Faz 3 — a PRECOMMIT certificate is checked before it can
 * move consensus, and the own-quorum commit route checks the set it is
 * about to commit on.
 *
 * WHAT THIS PROVES (the properties that would be FALSE if it failed)
 *
 *   §1  A PRECOMMIT APPROVE whose `cert_sig` does not verify never
 *       reaches `precommit_approve_count`. Before O15L Faz 3 that
 *       signature was copied into the vote slot unverified while its
 *       APPROVE still incremented the count that ALONE drives the phase
 *       advance — so a node could reach `approve_count == quorum` holding
 *       fewer than quorum valid certificates, and whether it did depended
 *       on vote ARRIVAL ORDER. That is the determinism defect (design
 *       F-13), not merely a missing check, and §1 is what pins it shut.
 *       §1 also pins the four preimage fields individually, because a
 *       verifier that reconstructs the WRONG preimage rejects every
 *       certificate and stops the chain: the 144-byte cert preimage (not
 *       PREVOTE's 116-byte PREPARED one), the sender's own voter_id, the
 *       verifier's chain_id, and the ROUND ANCHOR height.
 *
 *   §2  The own-quorum commit route — reached by ANY witness that
 *       accumulates a local precommit quorum, not just the leader —
 *       refuses to call `nodus_witness_commit_batch` unless the
 *       certificates it holds verify against the committed committee
 *       snapshot, mirroring what the remote-COMMIT and sync-replay routes
 *       already demanded (design DG-5). And when it refuses, it resets
 *       the round to IDLE rather than returning with the phase still at
 *       COMMIT (design F-12) — the shape the sibling batch_failed path
 *       already documents as a real, previously-fixed regression, because
 *       a phase left at COMMIT makes check_timeout fire a VIEW_CHANGE
 *       carrying a stale prepared cert for a height that never landed.
 *
 *   The §2 A/B pair is the load-bearing part: the two runs are identical
 *   fixtures differing in ONE flipped signature byte, and the only thing
 *   that differs in the outcome is whether commit_batch was reached at
 *   all. Without that pair the section would be vacuous — a bare
 *   "returns -1 and phase is IDLE" assertion passes with or without the
 *   gate, because the batch_failed path produces the same two values.
 *
 *   §3  The SIGN side reads the same round anchor the verify side does.
 *       §1d pins the verifier; §3 pins the signer, and only both together
 *       make the invariant the round-init code declares — "all cert_sig
 *       signing/verification within this round reads from
 *       round_state.block_height" — a tested statement instead of a
 *       comment. It drives the REAL PREVOTE-quorum arm (not a fixture
 *       imitation of it) in a witness whose head+1 differs from the
 *       anchor, then checks both the certificate that arm signed and the
 *       `last_prepared.height` it captured. Both assertions are made in
 *       both directions — must verify at the anchor, must NOT verify at
 *       head+1 — so neither can pass vacuously. This matters because a
 *       signer on its own shifted head would have its vote DROPPED by the
 *       check §1 introduces, and because `last_prepared.height` goes out
 *       on the wire in a VIEW_CHANGE, where the receiver rebuilds the
 *       116-byte PREPARED preimage from it.
 *
 * WHAT IT REQUIRES
 *
 *   Compile flags: none beyond a default `cd nodus/build && cmake .. &&
 *   make`. Registered through register_witness_test, which supplies
 *   -DNODUS_WITNESS_INTERNAL_API; no -DQGP_FAULT_INJECT, no
 *   -DO15H_DIAG, no short -DDNAC_EPOCH_LENGTH. It is deliberately
 *   PARAMETRIC in DNAC_EPOCH_LENGTH: the committee cache is primed at
 *   the epoch start the height actually resolves to, so the harness's
 *   short-epoch builds behave identically.
 *
 *   Environment: none. No STAGEF_*, no NODUS_FAULT_*, nothing exported
 *   before the run.
 *
 * WHAT IT LEAVES BEHIND
 *
 *   §2 creates a real chain DB under a mkdtemp directory
 *   (/tmp/test_pccert_*) and removes it, including the -wal/-shm
 *   siblings, before returning. Nothing else: no node dirs, no arm
 *   files, no network, no processes. The fixtures are heap-allocated and
 *   freed.
 *
 * HOW IT CAN LIE
 *
 *   - §2 proves the gate is WIRED by observing that commit_batch's
 *     rollback did not happen. It does NOT prove the gate's verdict
 *     function is correct — that is nodus_witness_verify_certs_snapshot,
 *     covered by test_cert_verify_snapshot.c. If that verifier ever
 *     returned success unconditionally, §2B would fail (the hook would
 *     fire), so the two tests are not independent, but neither replaces
 *     the other.
 *   - §2 reaches commit_batch's EARLY exit (the TOCTOU height check),
 *     not a real block commit. It says nothing about whether a block
 *     that passes the gate is otherwise valid.
 *   - Neither section exercises the gate's PASS path on a chain that can
 *     actually commit, and §2 never reaches the successor or genesis
 *     arms — both are deliberately ungated, and both are outside this
 *     unit's reach.
 *   - §2's `precommits[0]` self-certificate is built by this file rather
 *     than produced by the PREVOTE-quorum arm that signs it in
 *     production. §3 covers that arm directly, so a drift introduced
 *     there is caught — but by §3, not by §2.
 *   - §1 and §3 run without a chain DB, so `nodus_witness_block_height(w)
 *     + 1` is 1 while the round anchor is 7. That asymmetry is USED on
 *     purpose (§1d, §3) as a stand-in for a head that moved mid-round.
 *     It is a stand-in: no section actually moves a head between round
 *     start and the signature, so the ORDER of events in a real drift is
 *     not exercised, only the disagreement it produces.
 *   - §3 asserts the height fields of the prepared certificate but does
 *     not put a VIEW_CHANGE on the wire, so the downstream
 *     nodus_witness_bft_verify_prepared_cert path is reasoned about
 *     here, not executed.
 *   - A skip is not a pass: this test has no skip path. It either runs
 *     every section or exits non-zero.
 *
 * SUPERSEDES the file's previous contents, which asserted that
 * `nodus_witness_verify_sync_certs` was linkable and described itself as
 * "RED state — failing test by design until Faz 3.6". Both statements
 * had stopped being true: the test was registered and passing, and the
 * lazy-verify design it recorded is what O15L Faz 3 deliberately
 * reverses for the per-vote case. The perf objection it raised —
 * "up to 7x Dilithium5 verifies on the epoll thread per COMMIT" — was
 * about the REMOTE path, where a whole cert set arrives at once; it does
 * not apply to one verify per vote event, which is exactly what PREVOTE
 * has paid since C5.
 *
 * @file test_precommit_cert_verify_lazy.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_db.h"   /* nodus_witness_block_height — §1's
                                         * premise reads the chain head
                                         * directly (same include the sibling
                                         * BFT tests use). */
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "nodus/nodus_types.h"

#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAIL %s:%d — %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    fprintf(stderr, "  ok: %s\n", msg); \
} while (0)

/* The round anchor every section signs and verifies against. Chosen
 * DIFFERENT from nodus_witness_block_height(w)+1 in the DB-less fixture
 * (which is 1) so §1d can tell the two apart. */
#define ANCHOR_H   7ULL
#define ROUND_N    6ULL

/* ── One test witness: real ML-DSA-87 keys, so every signature check on
 * these paths is the production one and never a stub. ─────────────── */
typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/** witness_id = SHA3-512(pubkey)[0..31] — the SAME derivation
 *  nodus_chain_config_derive_witness_id uses, which is what the cert
 *  verifier re-derives its committee members' ids with. */
static void peer_make(peer_t *p, uint8_t seed_byte) {
    uint8_t seed[32];
    memset(seed, seed_byte, sizeof(seed));
    /* Deterministic keys — no RNG in the identity material, so a failure
     * reproduces byte-for-byte on the next run. */
    CHECK(qgp_dsa87_keypair_derand(p->pk, p->sk, seed) == 0, "keygen");
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

/** Heap fixture — nodus_witness_t and nodus_server_t are both multi-MB,
 *  never stack objects. */
static nodus_witness_t *fixture(const peer_t *self, const peer_t *peers,
                                int n_peers, uint32_t quorum,
                                const uint8_t chain_id[32]) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL, "fixture alloc");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    CHECK(srv != NULL, "server alloc");
    memcpy(srv->identity.pk.bytes, self->pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, self->sk, sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, self->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->chain_id, chain_id, 32);
    roster_put(w, self);
    for (int i = 0; i < n_peers; i++) roster_put(w, &peers[i]);
    w->bft_config.n_witnesses = w->roster.n_witnesses;
    w->bft_config.quorum = quorum;
    w->bft_config.round_timeout_ms = 16000;
    w->bft_config.viewchg_timeout_ms = 16000;
    return w;
}

static void fixture_free(nodus_witness_t *w) {
    if (!w) return;
    free(w->server);
    free(w);
}

/* ── O15L Faz 4 — §1 AND §3 NEED AN (EMPTY) CHAIN DATABASE ────────────
 *
 * These two sections used to run on a witness with an identity and NO
 * database, and their comments called that "the documented pre-genesis
 * case, (rc 0, count 0)". That was true when it was written and O15L
 * Faz 4 made it false.
 *
 * `load_committee_at_height` now separates the two nodes that both hold a
 * NULL handle: an all-zero chain_id is genuine pre-genesis and still
 * answers (rc 0, count 0), while a NON-zero chain_id with no handle is
 * DG-1 row 2 — a node that HOLDS a chain and cannot read it — and answers
 * -1, the absence of an answer. The O15J committee gate in handle_vote
 * then fails closed on that -1 and drops the vote:
 *
 *     cannot establish the committee at height 7 (rc=-1) — refusing the
 *     vote rather than authorising it on the transport roster alone
 *
 * That is the CORRECT production behaviour and it is the whole point of
 * the season; these fixtures were sitting in the one state it makes
 * inert. So the fixture moves to DG-1 row 1 — identity AND an open
 * database — which is what a healthy witness actually looks like.
 *
 * Why row 1 and not a zeroed chain_id: §1's stated purpose is that
 * verify_chain_id ENFORCES, so these votes pass the same identity gate a
 * production node applies (§1e signs a cert over a DIFFERENT chain_id and
 * requires refusal). Zeroing the identity would take the EXEMPT row and
 * delete that property. An empty database keeps ENFORCE and, with no
 * validators and no snapshot row, still yields the count-0 answer the
 * gossip-roster bootstrap authorization depends on — so the committee
 * gate remains what these sections do NOT measure.
 *
 * The chain stays at height 0, so the §1d / §3 premise "local head+1
 * differs from the round anchor" (1 != ANCHOR_H) is untouched. */
static void rmrf(const char *path);   /* defined below, with §2's fixture */

static void attach_empty_chain(nodus_witness_t *w, char *dir_out,
                               size_t dir_cap, const uint8_t chain16[16]) {
    snprintf(dir_out, dir_cap, "/tmp/test_pccert_row1_XXXXXX");
    CHECK(mkdtemp(dir_out) != NULL, "chain dir");
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_out);
    CHECK(nodus_witness_create_chain_db(w, chain16) == 0,
          "an EMPTY chain database — DG-1 row 1, the healthy shape");
    CHECK(w->db != NULL, "row 1 means the handle is actually open");
    /* create_chain_db installs the 32-byte identity itself. It MUST equal
     * the one this section signs its certificates with, or every cert
     * preimage would silently drift from what the verifier rebuilds. */
    CHECK(memcmp(w->chain_id, chain16, 16) == 0,
          "the installed identity is the one the section signs with");
    /* Force a real committee read rather than the calloc'd cache sentinel
     * accidentally hitting at epoch 0: an empty validator table and no
     * snapshot row must produce the count-0 answer on the MISS path, not
     * only on a hit. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;
}

static void detach_chain(nodus_witness_t *w, const char *dir) {
    if (w && w->db) { sqlite3_close(w->db); w->db = NULL; }
    if (dir && dir[0]) rmrf(dir);
}

/** The 144-byte PRECOMMIT cert signature, built exactly the way the
 *  production sign path builds it (the PREVOTE-quorum arm of
 *  bft_handle_vote_inner): compute_cert_preimage over
 *  (block_hash, voter_id, height, chain_id), RAW qgp_dsa87_sign, then
 *  zero-pad out to the fixed wire width. Every field is a parameter so a
 *  section can vary exactly one of them. */
static void sign_cert(uint8_t out[NODUS_SIG_BYTES], const peer_t *signer,
                      const uint8_t *block_hash, const uint8_t *voter_id,
                      uint64_t height, const uint8_t chain_id[32]) {
    uint8_t pre[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    CHECK(nodus_witness_compute_cert_preimage(block_hash, voter_id, height,
                                              chain_id, pre) == 0,
          "cert preimage");
    size_t siglen = 0;
    CHECK(qgp_dsa87_sign(out, &siglen, pre, sizeof(pre), signer->sk) == 0,
          "cert sign");
    CHECK(siglen <= NODUS_SIG_BYTES, "cert sig fits the wire width");
    if (siglen < NODUS_SIG_BYTES)
        memset(out + siglen, 0, NODUS_SIG_BYTES - siglen);
}

/** The 116-byte C5 PREPARED signature — PREVOTE's preimage, NOT
 *  PRECOMMIT's. §1c feeds one of these as a PRECOMMIT cert_sig to prove
 *  the two preimages are not interchangeable. Layout mirrors
 *  compute_prepared_preimage (O15N Faz 2A): "prepared"(8B ASCII) ||
 *  chain_id(32B) || view(4B BE) || height(8B BE) || tx_hash(64B).
 *
 *  chain_id is passed by the caller from w->chain_id. This file's fixture
 *  DOES set one (row 1 of the DG-1 identity matrix, :271), so a zero
 *  literal here would break every section rather than the one under
 *  test — and §1e's "a cert over a different chain_id is refused" leg
 *  only means something if the honest legs use the fixture's real one. */
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
    CHECK(nodus_sign_prepared_vote(&sig, pre, sizeof(pre), &sk) == 0,
          "prepared sign");
    memcpy(out, sig.bytes, NODUS_SIG_BYTES);
}

/** A PRECOMMIT on the wire. chain_id is copied from the witness so the
 *  handler's verify_chain_id gate (DG-1 rows 1/2 — we always hold an
 *  identity in these fixtures) passes and the vote reaches the tally. */
static void fill_precommit(nodus_t3_msg_t *m, const nodus_witness_t *w,
                           const peer_t *from, const uint8_t *target,
                           uint32_t vote) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_PRECOMMIT;
    m->header.round = ROUND_N;
    m->header.view = 0;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, 32);
    m->header.timestamp = nodus_time_now();
    /* Random nonce: the replay table is a process-wide static shared by
     * every section, so reused nonces would make a later section drop a
     * vote for the wrong reason. */
    nodus_random((uint8_t *)&m->header.nonce, sizeof(m->header.nonce));
    memcpy(m->vote.vote_target, target, NODUS_T3_TX_HASH_LEN);
    m->vote.vote = vote;
}

/** A PREVOTE on the wire. Every field a vote carries at this layer is
 *  identical to a PRECOMMIT's — round, view, sender, chain_id, nonce,
 *  target — and only the type differs, so this delegates to the builder
 *  above instead of keeping a second copy that could drift from it. The
 *  caller fills cert_sig with a PREPARED signature. */
static void fill_prevote(nodus_t3_msg_t *m, const nodus_witness_t *w,
                         const peer_t *from, const uint8_t *target) {
    fill_precommit(m, w, from, target, NODUS_W_VOTE_APPROVE);
    m->type = NODUS_T3_PREVOTE;
}

/** Verify a certificate the way the production tally does: rebuild the
 *  144-byte preimage and RAW-verify. Returns true when it checks out. */
static bool cert_ok(const uint8_t *sig, const uint8_t *pk,
                    const uint8_t *block_hash, const uint8_t *voter_id,
                    uint64_t height, const uint8_t chain_id[32]) {
    uint8_t pre[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    if (nodus_witness_compute_cert_preimage(block_hash, voter_id, height,
                                            chain_id, pre) != 0)
        return false;
    return qgp_dsa87_verify(sig, NODUS_SIG_BYTES, pre, sizeof(pre), pk) == 0;
}

/** Put the fixture in PREVOTE phase of round ROUND_N at ANCHOR_H with our
 *  own PREVOTE already recorded — the state the leader's round init and
 *  handle_propose both leave behind. §3 drives the real PREVOTE-quorum
 *  arm out of this, which is the only way to exercise the PRODUCTION
 *  cert-signing path rather than a fixture's imitation of it. */
static void enter_prevote(nodus_witness_t *w, const peer_t *self,
                          const uint8_t *tx_hash) {
    w->current_round = ROUND_N;
    w->current_view = 0;
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.round = ROUND_N;
    w->round_state.view = 0;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    w->round_state.block_height = ANCHOR_H;
    memcpy(w->round_state.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.tx_root, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.prevotes[0].voter_id, self->id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->round_state.prevotes[0].pubkey, self->pk, NODUS_PK_BYTES);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    /* Our own PREPARED signature, over the anchor — the same value the
     * round-init path signs, so the cert this round captures is built
     * from a coherent set. */
    sign_prepared(w->round_state.prevotes[0].signature, self, 0, ANCHOR_H,
                  tx_hash, w->chain_id);
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;
}

/** Put the fixture in PRECOMMIT phase of round ROUND_N at ANCHOR_H, with
 *  our own precommit already in slot 0 — the state the PREVOTE-quorum arm
 *  leaves behind. `self_sig` is the slot-0 certificate; pass NULL to
 *  leave it zeroed (§1 never reaches the gate, so slot 0's signature is
 *  not read there). */
static void enter_precommit(nodus_witness_t *w, const peer_t *self,
                            const uint8_t *tx_hash,
                            const uint8_t *self_sig) {
    w->current_round = ROUND_N;
    w->current_view = 0;
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.round = ROUND_N;
    w->round_state.view = 0;
    w->round_state.phase = NODUS_W_PHASE_PRECOMMIT;
    w->round_state.block_height = ANCHOR_H;
    memcpy(w->round_state.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.tx_root, tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.precommits[0].voter_id, self->id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->round_state.precommits[0].pubkey, self->pk, NODUS_PK_BYTES);
    w->round_state.precommits[0].vote = NODUS_W_VOTE_APPROVE;
    if (self_sig)
        memcpy(w->round_state.precommits[0].signature, self_sig,
               NODUS_SIG_BYTES);
    w->round_state.precommit_count = 1;
    w->round_state.precommit_approve_count = 1;
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — the tally-time certificate check (F-13)
 * ═══════════════════════════════════════════════════════════════════ */

static void section1(void) {
    fprintf(stderr, "\nSECTION 1 — an unverifiable PRECOMMIT cert never "
                    "reaches approve_count\n");

    static peer_t self, b, c, d, e, f;
    peer_make(&self, 0x11); peer_make(&b, 0x22); peer_make(&c, 0x33);
    peer_make(&d, 0x44);    peer_make(&e, 0x55); peer_make(&f, 0x66);

    /* The canonical layout nodus_witness_set_chain_id writes: 16
     * significant bytes, bytes 16-31 always zero. Non-zero, so
     * verify_chain_id ENFORCES — which is what puts these votes through
     * the same identity gate a production node applies. */
    uint8_t chain[32];
    memset(chain, 0x5A, 16);
    memset(chain + 16, 0, 16);
    uint8_t T[NODUS_T3_TX_HASH_LEN];
    memset(T, 0xA7, sizeof(T));

    /* Six-member roster, quorum 5. Nothing in this section can reach it
     * (at most three APPROVEs are ever accepted), so no section-1 case
     * can trip the phase advance and drag us into the commit path. */
    peer_t others[5] = { b, c, d, e, f };
    nodus_witness_t *w = fixture(&self, others, 5, dna_bft_quorum(6), chain);

    /* DG-1 row 1 — identity AND an open (empty) database. See
     * attach_empty_chain: since O15L Faz 4 an identity WITHOUT a database
     * is row 2, which the committee gate makes inert, and this section
     * would then measure a refusal instead of the certificate rule it is
     * about. With an empty validator table the lookup still answers
     * (rc 0, count 0), so the gossip roster remains the vote
     * authorization and the committee gate remains out of scope here. */
    char s1_dir[256];
    attach_empty_chain(w, s1_dir, sizeof(s1_dir), chain);
    CHECK(nodus_witness_block_height(w) + 1ULL != ANCHOR_H,
          "fixture head+1 differs from the round anchor (the §1d premise) "
          "— an EMPTY chain reads height 0, so attaching the database "
          "does not disturb this premise");

    enter_precommit(w, &self, T, NULL);

    nodus_t3_msg_t m;

    /* ── §1a — invalid cert_sig drops the WHOLE vote ─────────────────
     * This is the property F-13 is about: not "the cert is remembered as
     * bad", but "the vote never happened", so approve_count — the number
     * that alone drives the phase advance — cannot be inflated by it. */
    fill_precommit(&m, w, &b, T, NODUS_W_VOTE_APPROVE);
    memset(m.vote.cert_sig, 0x11, NODUS_SIG_BYTES);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == -1,
          "§1a APPROVE with a garbage cert_sig is rejected");
    CHECK(w->round_state.precommit_count == 1,
          "§1a the vote was not recorded");
    CHECK(w->round_state.precommit_approve_count == 1,
          "§1a approve_count did not move");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
          "§1a the phase did not advance");

    /* ── §1b — the same sender's VALID cert is counted ───────────────
     * Also pins that a dropped vote leaves no residue: the pubkey dedup
     * loop runs BEFORE the certificate check, so B still gets its one
     * legitimate chance after the forgery was refused. */
    fill_precommit(&m, w, &b, T, NODUS_W_VOTE_APPROVE);
    sign_cert(m.vote.cert_sig, &b, T, b.id, ANCHOR_H, chain);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == 0,
          "§1b APPROVE with a valid cert is accepted");
    CHECK(w->round_state.precommit_count == 2, "§1b the vote was recorded");
    CHECK(w->round_state.precommit_approve_count == 2,
          "§1b approve_count moved");

    /* ── §1c — the PREPARED preimage is NOT the cert preimage ────────
     * A valid 116-byte PREVOTE signature offered as a PRECOMMIT cert_sig
     * must be refused. Copying PREVOTE's verify call into the PRECOMMIT
     * arm is the single most likely way to get this change wrong, and it
     * would silently accept certificates the remote-COMMIT gate rejects. */
    fill_precommit(&m, w, &c, T, NODUS_W_VOTE_APPROVE);
    sign_prepared(m.vote.cert_sig, &c, 0, ANCHOR_H, T, w->chain_id);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == -1,
          "§1c a valid PREPARED (116B) signature is not a valid cert");
    CHECK(w->round_state.precommit_approve_count == 2,
          "§1c approve_count did not move");

    /* ── §1d — the VERIFY side reads the ROUND ANCHOR ────────────────
     * The fixture's chain DB is EMPTY, so nodus_witness_block_height(w)+1
     * is 1 while round_state.block_height is ANCHOR_H. A cert signed over
     * 1 must be REFUSED and one signed over the anchor ACCEPTED. (The
     * database was attached by O15L Faz 4 — see attach_empty_chain — and
     * being empty it reads height 0 exactly as the handle-less fixture
     * this replaced did, so this premise is unchanged.)
     *
     * This is the assertion that fails if anyone reverts this side to a
     * fresh block_height(w)+1 read: it would then accept certificates
     * that the remote-COMMIT gate — which verifies at the leader's
     * round_state.block_height — rejects, and that is the DG-5 break.
     * §3 pins the SIGN side of the same anchor; the two together are
     * what make "both sides read round_state.block_height" testable
     * rather than merely asserted in a comment. */
    fill_precommit(&m, w, &c, T, NODUS_W_VOTE_APPROVE);
    sign_cert(m.vote.cert_sig, &c, T, c.id,
              nodus_witness_block_height(w) + 1ULL, chain);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == -1,
          "§1d a cert over local head+1 is refused");
    CHECK(w->round_state.precommit_approve_count == 2,
          "§1d approve_count did not move");

    fill_precommit(&m, w, &c, T, NODUS_W_VOTE_APPROVE);
    sign_cert(m.vote.cert_sig, &c, T, c.id, ANCHOR_H, chain);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == 0,
          "§1d a cert over the round anchor is accepted");
    CHECK(w->round_state.precommit_approve_count == 3,
          "§1d approve_count moved");

    /* ── §1e — the chain_id is bound ─────────────────────────────────
     * The non-malicious trigger F-13 names: a peer in the O15K zeroed-
     * chain_id state signs its certificate over a chain_id no healthy
     * verifier reconstructs. Its vote must not count. */
    uint8_t other_chain[32];
    memset(other_chain, 0x00, sizeof(other_chain));
    fill_precommit(&m, w, &d, T, NODUS_W_VOTE_APPROVE);
    sign_cert(m.vote.cert_sig, &d, T, d.id, ANCHOR_H, other_chain);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == -1,
          "§1e a cert over a different chain_id is refused");
    CHECK(w->round_state.precommit_approve_count == 3,
          "§1e approve_count did not move");

    /* ── §1f — the voter_id is the SENDER's ──────────────────────────
     * E signs a well-formed cert that names B as the voter. The
     * verifier reconstructs the preimage with the SENDER's id, so this
     * cannot verify — which is what stops a signature being replayed
     * under another identity's slot. */
    fill_precommit(&m, w, &e, T, NODUS_W_VOTE_APPROVE);
    sign_cert(m.vote.cert_sig, &e, T, b.id, ANCHOR_H, chain);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == -1,
          "§1f a cert naming another voter_id is refused");
    CHECK(w->round_state.precommit_approve_count == 3,
          "§1f approve_count did not move");

    /* ── §1g — REJECT is out of scope, exactly as for PREVOTE ────────
     * A REJECT precommit contributes to no certificate and carries
     * cert_sig = 0. It must still be RECORDED, or the new check would
     * have quietly widened into a second, undocumented gate. */
    fill_precommit(&m, w, &f, T, NODUS_W_VOTE_REJECT);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == 0,
          "§1g a REJECT precommit with no cert_sig is still accepted");
    CHECK(w->round_state.precommit_count == 4, "§1g the REJECT was recorded");
    CHECK(w->round_state.precommit_approve_count == 3,
          "§1g approve_count did not move");
    CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
          "§1 the round never advanced past PRECOMMIT");

    detach_chain(w, s1_dir);
    fixture_free(w);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — the own-quorum certificate gate (DG-5) and its round reset (F-12)
 * ═══════════════════════════════════════════════════════════════════ */

/* commit_batch opens a DB transaction and rolls it back when its TOCTOU
 * height check fails. The rollback hook is therefore a precise, timing-
 * free answer to the ONE question §2 must decide: was commit_batch
 * reached at all? Nothing before it on this path opens a transaction —
 * the committee resolution the gate performs is served from the primed
 * epoch cache and touches no statement. */
static void rollback_seen(void *ctx) { *(int *)ctx = 1; }

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
} db_fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

/** Prime the legacy committee resolver's per-epoch cache with `n`
 *  members. nodus_committee_get_for_block answers from this cache before
 *  it touches the database, and nodus_witness_verify_certs_snapshot's
 *  legacy arm resolves its authority through exactly that accessor — so
 *  this makes the committing committee a deterministic, DB-free input.
 *  Parametric in DNAC_EPOCH_LENGTH so a short-epoch build behaves the
 *  same. */
static void prime_committee(nodus_witness_t *w, uint64_t height,
                            const peer_t *members, int n) {
    uint64_t e = (uint64_t)DNAC_EPOCH_LENGTH;
    w->cached_committee_epoch_start = (height / e) * e;
    w->cached_committee_count = n;
    for (int i = 0; i < n; i++) {
        memcpy(w->cached_committee_pubkeys[i], members[i].pk,
               DNAC_PUBKEY_SIZE);
        w->cached_committee_stakes[i] = 1000000ULL + (uint64_t)i;
        w->cached_committee_self_stakes[i] = 1000000000000000ULL;
        w->cached_committee_commission_bps[i] = 100;
    }
}

/** A witness with a REAL chain DB at height 0. The DB exists only so
 *  commit_batch can get past nodus_witness_db_begin and reach its
 *  rollback — the block itself is never committed. */
static int db_fixture_open(db_fixture_t *fx, const char *tag,
                           const peer_t *self, const peer_t *peers,
                           int n_peers, uint32_t quorum) {
    memset(fx, 0, sizeof(*fx));
    uint8_t zero_chain[32] = {0};
    fx->w = fixture(self, peers, n_peers, quorum, zero_chain);
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_pccert_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) return -1;
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t chain16[16];
    memset(chain16, 0x4E, sizeof(chain16));
    if (nodus_witness_create_chain_db(fx->w, chain16) != 0) return -1;
    /* create_chain_db installs the 32-byte identity itself; every cert
     * this section signs uses that exact value, which is also what the
     * verifier reconstructs with. */
    return 0;
}

static void db_fixture_close(db_fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
        fixture_free(fx->w);
        fx->w = NULL;
    }
    if (fx->dir[0]) rmrf(fx->dir);
}

/** Drive one §2 run to the precommit quorum. `corrupt_b` flips a byte of
 *  B's recorded certificate AFTER it has been tallied — the only
 *  difference between run A and run B. Returns handle_vote's rc and
 *  reports through *hook whether commit_batch was reached. */
static int run_gate(const char *tag, int corrupt_b, int *hook,
                    nodus_witness_phase_t *phase_out, int *batch_left)
{
    static peer_t self, b, c;
    peer_make(&self, 0x71); peer_make(&b, 0x72); peer_make(&c, 0x73);
    peer_t others[2] = { b, c };

    db_fixture_t fx;
    /* Committee of three, so the snapshot quorum dna_bft_quorum(3) is 3
     * and EVERY certificate must verify — the tightest setting, and the
     * one where a single corrupted signature is decisive. */
    CHECK(db_fixture_open(&fx, tag, &self, others, 2, 3) == 0,
          "chain DB fixture opened");
    nodus_witness_t *w = fx.w;
    CHECK(w->db != NULL, "fixture has a chain DB");
    CHECK(nodus_witness_block_height(w) == 0, "fresh chain, head 0");

    uint8_t T[NODUS_T3_TX_HASH_LEN];
    memset(T, 0xB4, sizeof(T));

    peer_t committee[3] = { self, b, c };
    prime_committee(w, ANCHOR_H, committee, 3);

    /* Our own precommit, carrying a real certificate over the same four
     * fields the production sign path uses. */
    uint8_t self_sig[NODUS_SIG_BYTES];
    sign_cert(self_sig, &self, T, self.id, ANCHOR_H, w->chain_id);
    enter_precommit(w, &self, T, self_sig);

    /* One batch entry, SPEND (not GENESIS) and not a successor round, so
     * the quorum lands on the legacy own-quorum arm the gate guards. */
    nodus_witness_mempool_entry_t *entry = calloc(1, sizeof(*entry));
    CHECK(entry != NULL, "batch entry alloc");
    memcpy(entry->tx_hash, T, NODUS_T3_TX_HASH_LEN);
    entry->tx_type = NODUS_W_TX_SPEND;
    w->round_state.batch_entries[0] = entry;
    w->round_state.batch_count = 1;

    nodus_t3_msg_t m;
    fill_precommit(&m, w, &b, T, NODUS_W_VOTE_APPROVE);
    sign_cert(m.vote.cert_sig, &b, T, b.id, ANCHOR_H, w->chain_id);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == 0, "B precommit accepted");
    CHECK(w->round_state.precommit_approve_count == 2, "approve 2/3");

    if (corrupt_b) {
        /* B's certificate passed the tally check and is now in the vote
         * slot. Corrupting it here models the ONE class of failure the
         * gate still has to catch after the tally check exists: the
         * locally held certificate set no longer proves the quorum. */
        w->round_state.precommits[1].signature[0] ^= 0xFF;
    }

    *hook = 0;
    sqlite3_rollback_hook(w->db, rollback_seen, hook);

    fill_precommit(&m, w, &c, T, NODUS_W_VOTE_APPROVE);
    sign_cert(m.vote.cert_sig, &c, T, c.id, ANCHOR_H, w->chain_id);
    int rc = nodus_witness_bft_handle_vote(w, &m);

    sqlite3_rollback_hook(w->db, NULL, NULL);
    *phase_out = w->round_state.phase;
    *batch_left = w->round_state.batch_count;
    db_fixture_close(&fx);
    return rc;
}

static void section2(void) {
    fprintf(stderr, "\nSECTION 2 — the own-quorum route verifies its own "
                    "certificates, and resets the round when it cannot\n");

    int hook_a = 0, hook_b = 0;
    int batch_a = -1, batch_b = -1;
    nodus_witness_phase_t phase_a = NODUS_W_PHASE_COMMIT;
    nodus_witness_phase_t phase_b = NODUS_W_PHASE_COMMIT;

    /* ── §2A — three valid certs: the gate passes and commit_batch is
     * reached (where it fails on its own height check, which is all this
     * fixture can offer). */
    int rc_a = run_gate("A", 0, &hook_a, &phase_a, &batch_a);
    CHECK(hook_a == 1,
          "§2A a full set of valid certs lets the round reach commit_batch");
    CHECK(rc_a == -1, "§2A commit_batch failed on its height check");
    CHECK(phase_a == NODUS_W_PHASE_IDLE, "§2A round reset to IDLE");
    CHECK(batch_a == 0, "§2A the batch was released");

    /* ── §2B — one certificate corrupted after it was tallied: the gate
     * refuses and commit_batch is NEVER reached. Identical to §2A in
     * every other byte, which is what makes hook_b == 0 evidence about
     * the gate rather than about the fixture. */
    int rc_b = run_gate("B", 1, &hook_b, &phase_b, &batch_b);
    CHECK(hook_b == 0,
          "§2B the gate refused BEFORE commit_batch (no transaction opened)");
    CHECK(rc_b == -1, "§2B the round did not commit");
    CHECK(phase_b == NODUS_W_PHASE_IDLE,
          "§2B F-12: phase reset to IDLE, not left at COMMIT");
    CHECK(batch_b == 0, "§2B the batch was released to its clients");

    /* The pair, stated as one property: same inputs except one flipped
     * signature byte, opposite answers about whether the block was
     * allowed to reach the commit path. */
    CHECK(hook_a != hook_b,
          "§2 the gate is what decides, not the surrounding failure path");
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — the SIGN side reads the round anchor too
 * ═══════════════════════════════════════════════════════════════════ */

static void section3(void) {
    fprintf(stderr, "\nSECTION 3 — the production PREVOTE-quorum arm signs "
                    "over the round anchor, not a fresh head read\n");

    static peer_t self, b, c;
    peer_make(&self, 0x81); peer_make(&b, 0x82); peer_make(&c, 0x83);
    peer_t others[2] = { b, c };

    uint8_t chain[32];
    memset(chain, 0x7C, 16);
    memset(chain + 16, 0, 16);
    uint8_t T[NODUS_T3_TX_HASH_LEN];
    memset(T, 0xD2, sizeof(T));

    nodus_witness_t *w = fixture(&self, others, 2, 3, chain);

    /* DG-1 row 1 — identity AND an open, EMPTY database (see
     * attach_empty_chain). Since O15L Faz 4 an identity with no database
     * is row 2, which the committee gate makes inert, so the PREVOTEs
     * below would be refused before they could reach the quorum arm this
     * section measures.
     *
     * The section's premise is unchanged by that move, and it is the
     * reason an EMPTY chain is used rather than a seeded one: an empty
     * chain still reads height 0, so a fresh
     * nodus_witness_block_height(w)+1 is 1 while the round anchor is
     * ANCHOR_H. Every assertion below is vacuous if these are equal, so
     * the premise is asserted, not assumed. */
    char s3_dir[256];
    attach_empty_chain(w, s3_dir, sizeof(s3_dir), chain);
    const uint64_t head_next = nodus_witness_block_height(w) + 1ULL;
    CHECK(head_next != ANCHOR_H,
          "§3 premise: local head+1 differs from the round anchor");

    enter_prevote(w, &self, T);

    /* Two real peer PREVOTEs carry us to quorum 3 (self + B + C) and the
     * PRODUCTION arm runs: it captures last_prepared, signs our cert and
     * records it in precommits[0]. Nothing here is a fixture imitation of
     * that path — it IS that path. */
    nodus_t3_msg_t m;
    fill_prevote(&m, w, &b, T);
    sign_prepared(m.vote.cert_sig, &b, 0, ANCHOR_H, T, w->chain_id);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == 0, "§3 B prevote accepted");

    fill_prevote(&m, w, &c, T);
    sign_prepared(m.vote.cert_sig, &c, 0, ANCHOR_H, T, w->chain_id);
    CHECK(nodus_witness_bft_handle_vote(w, &m) == 0, "§3 C prevote accepted");

    CHECK(w->round_state.phase == NODUS_W_PHASE_PRECOMMIT,
          "§3 prevote quorum advanced the phase");

    /* ── the certificate this node signed ────────────────────────────
     * Both directions, so the assertion cannot pass vacuously: it must
     * verify at the anchor AND fail at the head+1 the code used to
     * read. */
    CHECK(cert_ok(w->round_state.precommits[0].signature, self.pk,
                  T, self.id, ANCHOR_H, chain),
          "§3 our own PRECOMMIT cert is signed over the round anchor");
    CHECK(!cert_ok(w->round_state.precommits[0].signature, self.pk,
                   T, self.id, head_next, chain),
          "§3 it is NOT signed over a fresh local head+1");

    /* ── the prepared cert's height ──────────────────────────────────
     * last_prepared.height names the height whose PREPARED signatures it
     * carries, and those were signed over the anchor. A VIEW_CHANGE puts
     * this number on the wire and the receiver rebuilds the 116-byte
     * PREPARED preimage from it, so a drifted value would make the whole
     * C5 safety certificate unverifiable on every peer. */
    CHECK(w->last_prepared.present, "§3 prepared cert captured");
    CHECK(w->last_prepared.height == ANCHOR_H,
          "§3 last_prepared.height is the round anchor");
    CHECK(w->last_prepared.height != head_next,
          "§3 last_prepared.height is not a fresh local head+1");
    CHECK(w->last_prepared.n_sigs == 3,
          "§3 all three APPROVE prevote signatures were collected");

    detach_chain(w, s3_dir);
    fixture_free(w);
}

int main(void) {
    fprintf(stderr,
            "O15L Faz 3 — PRECOMMIT certificate verification\n"
            "==============================================\n");
    section1();
    section2();
    section3();
    fprintf(stderr, "\ntest_precommit_cert_verify_lazy: ALL SECTIONS PASSED\n");
    return 0;
}
