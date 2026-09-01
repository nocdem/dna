/**
 * Nodus — O15O Faz 5 — THE REPLAY CACHE IS PER SENDER, AND ITS ORDER IS
 *                      NODE-LOCAL
 *
 * WHAT THIS PROVES.
 *   One property, stated as the thing that would be FALSE if any section
 *   here failed:
 *
 *     A sender can consume, and can evict, only its OWN share of the
 *     replay-nonce cache; and a frame pays for a slot only once it has
 *     been AUTHORIZED.
 *
 *   Two shipped defects made that false, and they are one mechanism seen
 *   from two sides (both in nodus/BUGS.md):
 *
 *   O15N-L1 — the table held 10000 entries GLOBALLY and, at capacity,
 *     freed an ENTIRE BUCKET selected by the smallest `timestamp`. That
 *     field came straight from `hdr->timestamp`, which the SENDER chooses
 *     and signs. One sender could therefore decide WHICH honest entries
 *     left the table, re-opening replay of captured frames. And all six
 *     T3 consumers inserted BEFORE their own chain_id and committee
 *     checks, so an unauthorised sender consumed the capacity that was
 *     supposed to protect authorised ones.
 *
 *   "the replay cache can be exhausted by HONEST traffic" — at the
 *     governance minimum block interval of 1 s (DNAC_CFG_MIN_BLOCK_
 *     INTERVAL_SEC, dnac/include/dnac/dnac.h:341) and ~4 broadcasts per
 *     node per round, one honest sender produces ~1200 nonces per 300 s
 *     TTL window. Against a global 10000 that overflows at 9 seats. The
 *     cache evicted under NORMAL operation, with no attacker at all —
 *     which is why the fix sizes the budget PER SENDER and derives the
 *     total from it, rather than dividing a fixed total by n.
 *
 *   The five sections below are named in EXECUTION order, and that order
 *   is load-bearing — see HOW IT CAN LIE.
 *
 *     §1  an ordinary repeat is still refused and a fresh nonce is still
 *         accepted                              (the anti-vacuity floor)
 *     §2  a frame the committee gate refuses consumes NO slot
 *                                             (record-after-the-gates)
 *     §3  "oldest" is the insert ORDER, not the wire timestamp
 *     §4  a flooder evicts ONLY ITSELF
 *     §5  THE ATTACK: a flood cannot evict an honest sender's nonce
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro.
 *   DNAC_EPOCH_LENGTH is never assumed: every fixture chain stays at tip
 *   0 and every frame carries height 1, so all lookups land in epoch 0
 *   and the file behaves identically at the shipped 720 and at the
 *   harness's 15.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no pre-exported variable. The one filesystem dependency
 *   is a writable /tmp for mkdtemp/mkstemp.
 *   Runtime: ~14 600 handler calls (§3 2047, §4 2048, §5 10500, plus a
 *   handful). Each is one SQLite height read and one committee lookup
 *   served from the primed cache; measured expectation is low seconds.
 *   The one time-sensitive quantity is named under HOW IT CAN LIE.
 *
 * WHAT IT LEAVES BEHIND.
 *   On disk: nothing. Every section builds its chain database in its own
 *   mkdtemp() directory under /tmp and removes it with `rm -rf` before
 *   returning. The stderr-capture files are created with mkstemp and
 *   unlinked immediately, so they exist only as an open descriptor.
 *
 *   IN PROCESS: THE NONCE TABLE IS FILE-SCOPE STATIC IN libnodus AND IS
 *   NOT RESET BETWEEN SECTIONS. It cannot be — it is `static` inside
 *   nodus_witness_bft.c with no exported handle, and this phase's file
 *   whitelist contains no header to add one to. So this file leaves the
 *   table holding roughly 4 100 entries (§3's and §4's capped shares plus
 *   a handful) when it reaches §5, and ~6 100 when it exits. That is
 *   DELIBERATE and is handled as follows, which is the answer to "which
 *   did you choose, a reset helper or a documented ordering":
 *
 *     DOCUMENTED ORDERING PLUS DISJOINT IDENTITIES.
 *     (a) Every section uses sender identities used by no other section
 *         (g_peers indices are partitioned: §1→7, §2→8, §3→5, §4→3,4,
 *         §5→1,2). The cache is keyed on (sender_id, nonce) and the
 *         budget is per sender, so one section's residue can neither be
 *         mistaken for another section's entry nor consume its capacity.
 *     (b) Every nonce is a DETERMINISTIC constant, not a random draw,
 *         which removes any birthday risk of a flood nonce colliding
 *         with a crafted one and making an eviction count come out
 *         wrong. It does NOT make the run byte-identical: the identities
 *         come from qgp_dsa87_keypair, so each sender_id — and therefore
 *         which BUCKET each entry lands in — differs every run. Nothing
 *         here depends on bucket placement; the only per-bucket operation
 *         is the TTL sweep, which frees expired entries only, and no
 *         entry in this file is expired while it is being asserted on.
 *     (c) The execution order §1..§5 is REQUIRED, but only for the
 *         REVERTED direction — see HOW IT CAN LIE.
 *
 * HOW IT CAN LIE.
 *   - THE OBSERVABLE FOR "REFUSED AS A REPLAY" IS INDIRECT, and this is
 *     the file's most important caveat. The replay check returns -1 and
 *     prints NOTHING, so it is identified by rc == -1 together with an
 *     EMPTY capture. What else could produce that pair?
 *     nodus_witness_bft_handle_commit's only earlier exits are the
 *     !w || !msg null guard (unreachable here) and the safety_halt
 *     refusal, WHICH PRINTS. Every guard below the replay check also
 *     prints. So on this fixture the pair is unambiguous — but it is
 *     weaker than a dedicated marker would be, and a future edit that
 *     added a silent early return above the check would fool it. It is
 *     named rather than papered over; no production log line was added
 *     for the test's benefit, because a line on the replay path is an
 *     attacker-triggerable log-amplification surface.
 *   - "ADMITTED" MEANS "REACHED THE F02 BATCH RE-VERIFY", NEVER
 *     "COMMITTED A BLOCK". Every admitted leg still returns -1: past the
 *     committee gate the handler re-verifies each batch transaction in
 *     VALIDATION mode, which demands real Dilithium5-signed payloads. The
 *     same wall test_witness_commit_committee_gate.c and
 *     test_witness_height_fault_consumers.c §4 declined to climb, and the
 *     marker used here (L_BELOW) is the one those files use.
 *   - THE EXECUTION ORDER IS LOAD-BEARING FOR THE REVERT DIRECTION ONLY,
 *     AND THE ASYMMETRY IS THE ARGUMENT. Under the FIXED code no section
 *     can affect another: budgets are per sender and the identities are
 *     disjoint, so the order is free. Under a REVERTED build the single
 *     global 10000-entry cap is shared, and a section that ran after a
 *     big flood would find the table already at capacity — its own small
 *     flood would then trigger evictions for a reason that has nothing to
 *     do with what it is testing, and the victim would be whichever
 *     bucket happened to hold the smallest wire timestamp. That is
 *     exactly the non-determinism this project forbids. So the sections
 *     are ordered SMALL FLOODS FIRST and the one big flood LAST:
 *       * when §3 and §4 run, the reverted table holds ~5 and ~2 060
 *         entries, both far below 10000, so a reverted build performs NO
 *         eviction at all and their "it was evicted" assertions go red
 *         deterministically;
 *       * §5 runs last and its flood of 10500 exceeds the reverted cap
 *         even from an EMPTY table, so it reaches the eviction path no
 *         matter what preceded it; and its honest entry is stamped
 *         `now - 150`, the ONLY past-stamped entry in the entire file, so
 *         it is the unique global minimum by wire timestamp and the
 *         reverted rule frees ITS bucket first. Deterministic, not
 *         probabilistic.
 *   - THE FLOOD SIZES MIRROR A PRODUCTION CONSTANT. CAP_MIRROR below must
 *     equal NONCE_MAX_PER_SENDER in nodus_witness_bft.c. There is no way
 *     to include it (it is a #define in a .c file). A mismatch cannot
 *     pass quietly: too small a flood means no eviction and the
 *     "it was evicted" legs go red; too large means a second eviction and
 *     the "it survived" leg in §3 goes red.
 *   - §3 AND §4 DEPEND ON AN EXACT EVICTION COUNT. Each is sized so that
 *     EXACTLY ONE eviction fires. The arithmetic is written out at each
 *     site. If it is wrong the section fails loudly; it cannot pass
 *     vacuously, because both legs of each pair are asserted.
 *   - ONE TIME-SENSITIVE QUANTITY, NAMED. §5's honest entry is stamped
 *     `now - 150`, so it has 150 s of TTL life. §5's flood must finish
 *     and its assertion must run inside that window. At an expected
 *     ~150 µs per handler call the 10500-frame flood takes under two
 *     seconds; the margin is ~75x. If a machine were slow enough to
 *     exhaust it, the section fails — it does not silently pass. The
 *     stamp is not a tuned timeout: it is the minimum age that makes the
 *     entry the unique global timestamp minimum for the revert argument
 *     above, and it is the LARGEST such value this file uses.
 *   - FUTURE-STAMPED FLOODS WOULD MAKE §5 VACUOUS, AND THIS IS WHY THE
 *     FLOOD IS STAMPED AT `now`. The TTL comparison is
 *     `now - n->timestamp >= NONCE_TTL_SECS` on uint64 values
 *     (nodus_witness_bft.c, nonce_evict_bucket). For a timestamp in the
 *     FUTURE that subtraction underflows to ~2^64 and the entry is
 *     treated as ALREADY EXPIRED — so future-stamped entries are purged
 *     by the next sweep of their bucket and never accumulate. A flood of
 *     far-future frames therefore never fills a reverted table, no
 *     eviction ever fires, and the section would pass on the reverted
 *     build while proving nothing. Stamping the flood at `now` is what
 *     makes it a real flood. (O15N-L1's own write-up names far-future
 *     stamps as the mechanism; that half of the entry does not survive
 *     contact with the TTL line, while its CONCLUSION — the sender picks
 *     the victim — does, via a PAST stamp that ranks the sender's frame
 *     oldest.)
 *   - WHAT IT CANNOT SEE. Only ONE of the six record sites is exercised
 *     (handle_commit). The other five are placed by inspection, each
 *     immediately below the same committee gate, and are not driven here.
 *     Nothing in this file exercises a real T3 frame decode, a socket, a
 *     vote-buffer drain, the 128-slot sender-table overflow path, or the
 *     malloc-failure path in nonce_record.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "protocol/nodus_tier3.h"
#include "transport/nodus_tcp.h"           /* nodus_time_now             */
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"        /* DNAC_EPOCH_LENGTH, DNAC_PROTOCOL_VERSION */

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

/* ⚠ MUST EQUAL NONCE_MAX_PER_SENDER in nodus_witness_bft.c. It is a
 * #define inside a .c file, so it cannot be included; a divergence fails
 * this test loudly rather than quietly (see HOW IT CAN LIE). */
#define CAP_MIRROR   2048

/* §5's flood. Sized to exceed the 10000-entry GLOBAL cap this phase
 * deleted ON ITS OWN — before counting the ~4100 entries §1..§4 leave in
 * the shared table — so a reverted build reaches its eviction path no
 * matter what preceded it, and the claim does not rest on a residue
 * count that a later edit could change. */
#define FLOOD_BIG    10500

/* Ten seated peers; the committee primed over them is EIGHT, which
 * leaves peers 8 and 9 on the roster and outside it — the identity class
 * §2 needs. Peer 9 is never used and exists only so the roster is
 * strictly larger than the widened committee of §2. */
#define N_ROSTER          10
#define N_COMMITTEE        8
#define N_COMMITTEE_WIDE   9   /* §2's second leg — now includes peer 8 */
#define N_KEYS            10

/* Identity partition — no index appears in two sections. */
#define P_FLOOD_BIG     1   /* §5 flooder                                */
#define P_HONEST_BIG    2   /* §5 victim                                 */
#define P_FLOOD_SELF    3   /* §4 flooder                                */
#define P_HONEST_SELF   4   /* §4 bystander                              */
#define P_ORDER         5   /* §3                                        */
#define P_VACUITY       7   /* §1                                        */
#define P_OUTSIDER      8   /* §2 — roster, outside the BASE committee   */

/* Nonce space. Deterministic on purpose: a re-run feeds byte-identical
 * inputs, and no flood nonce can collide with a crafted one. Floods take
 * the high range; crafted nonces are small and distinct. */
#define N_VAC_A      0x0000000000000101ULL
#define N_VAC_B      0x0000000000000102ULL
#define N_GATE       0x0000000000000201ULL
#define N_ORDER_A    0x0000000000000301ULL
#define N_ORDER_B    0x0000000000000302ULL
#define N_SELF_FIRST 0x0000000000000401ULL
#define N_SELF_HON   0x0000000000000402ULL
#define N_BIG_HON    0x0000000000000501ULL
#define N_BIG_FRESH  0x0000000000000502ULL
#define N_FLOOD_BASE 0x4000000000000000ULL

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_witness_commit_committee_gate.c, this
 * season's own model.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of the setup, so the identities
 * are generated ONCE in main and reused. Nothing in a section mutates
 * them. */
static peer_t g_peers[N_KEYS];

static void peer_make(peer_t *p) {
    if (qgp_dsa87_keypair(p->pk, p->sk) != 0) {
        fprintf(stderr, "keygen failed\n"); exit(1);
    }
    /* The production voter-id derivation: SHA3-512(pubkey)[0..31]
     * (nodus_identity.c:42). */
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
 * so g_peers and w->roster.witnesses share indices.
 *
 * nodus_witness_t is multi-MB: heap, never stack (repo discipline).
 * w->v2_successor is NEVER touched — the masking that
 * nodus_witness.c:736-738 records a previous test committing. */
static nodus_witness_t *fixture(char *dir_template, uint8_t tag) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!w || !srv) { fprintf(stderr, "fixture alloc\n"); exit(1); }

    memcpy(srv->identity.pk.bytes, g_peers[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, g_peers[0].sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, g_peers[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i < N_ROSTER; i++) roster_put(w, &g_peers[i]);

    /* `tag` becomes the 16-byte chain_id (zero-filled to 32 by
     * set_chain_id), so it is NONZERO and verify_chain_id's "we hold an
     * identity, we enforce it" row applies — which is what lets every
     * crafted message carry w->chain_id and reach the committee gate. */
    if (mkdtemp(dir_template) == NULL) {
        fprintf(stderr, "mkdtemp failed\n"); exit(1);
    }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_template);
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0 || !w->db) {
        fprintf(stderr, "create_chain_db failed\n"); exit(1);
    }

    /* THE CACHE SENTINEL, load-bearing: a calloc'd witness has
     * cached_committee_epoch_start == 0 and every query here is in epoch
     * 0, so left at the zero the resolver would take its cache-HIT branch
     * and answer (rc 0, count 0) without reading the database. Production
     * sets UINT64_MAX at init for the same reason. Set AFTER
     * create_chain_db so nothing it does can undo it. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;

    /* Nothing above the record reads the quorum, but the F02 batch
     * re-verify below it runs against a real config; initialise it
     * through the PRODUCTION initialiser rather than by hand. */
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);
    return w;
}

static void fixture_free(nodus_witness_t *w, const char *dir) {
    if (w) {
        /* handle_commit appends no view-change record; defensive, and the
         * only correct reset if a future section ever drives one. */
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

/* Prime the committee resolver's per-epoch cache with peers [0..n) for
 * the epoch CONTAINING `height`. nodus_committee_get_for_block answers
 * from this cache before it touches the database, and
 * load_committee_at_height_alloc goes through that accessor — so this
 * makes the governing committee a deterministic, DB-free input.
 *
 * Parametric in DNAC_EPOCH_LENGTH: the epoch start is COMPUTED, never
 * assumed. Copied from prime_committee in
 * test_witness_commit_committee_gate.c. */
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

/** Ask the loader directly what the gate is about to be told. */
static int committee_probe(nodus_witness_t *w, uint64_t height,
                             int *count_out) {
    nodus_committee_member_t *tmp =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*tmp));
    if (!tmp) { fprintf(stderr, "probe alloc\n"); exit(1); }
    int rc = nodus_committee_get_for_block(w, height, tmp,
                                             DNAC_MAX_ACTIVE_VALIDATORS,
                                             count_out);
    free(tmp);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-guard resolution.
 *
 * Every refusal on this path returns -1, so the return code alone cannot
 * say WHICH guard fired; the refusal line can, and its ABSENCE is what
 * identifies the silent replay check. In a nodus build QGP_LOG_* resolves
 * to nodus/src/nodus_log_shim.c, whose qgp_log_ring_add writes straight
 * to stderr, and the guards use bare fprintf(stderr, ...) anyway.
 *
 * The window wraps ONLY the call under test and stderr is restored BEFORE
 * anything is asserted: a CHECK that failed inside the window would write
 * its diagnosis into the temp file and the binary would exit 1 saying
 * nothing. Copied from test_witness_commit_committee_gate.c.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_rpc_XXXXXX";
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

/* Restore fd 2 and copy the window's output into `dst`.
 *
 * ⚠ THE DESTINATION IS CALLER-OWNED ON PURPOSE. Several sections hold one
 * leg's text while capturing the next; a shared static buffer would
 * silently overwrite the first. */
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

/** THE REPLAY OBSERVABLE. The check prints nothing, so a refusal by it is
 *  rc == -1 with a completely empty window. See HOW IT CAN LIE. */
static bool silent(const char *hay) { return hay[0] == '\0'; }

/* ── The lines the assertions key on. ASCII only: the production messages
 *    carry em-dashes, which must never appear in a needle. ───────────── */
#define L_NONMEMBER "COMMIT from non-committee sender"
#define L_UNKNOWN   "COMMIT from unknown sender_id"
#define L_LOADFAULT "CANNOT ESTABLISH THE COMMITTEE at height"
/* The marker for "the frame travelled BELOW the committee gate and below
 * the nonce_record that follows it". Emitted by the F02 batch re-verify,
 * reachable only by passing every guard above it — the same marker
 * test_witness_commit_committee_gate.c and
 * test_witness_height_fault_consumers.c use for the same purpose. */
#define L_BELOW     "commit-path verify rejected batch TX"

/* ═══════════════════════════════════════════════════════════════════
 * Message builder
 * ═══════════════════════════════════════════════════════════════════ */

/* A transaction well-formed enough to REACH the F02 verify and be
 * rejected there BY NAME. The version byte is deliberately one past the
 * accepted one, so the reject is the cheap wire-version gate rather than
 * a NULL-pointer path — deterministic, and it depends on no signature
 * material. Taken from test_witness_commit_committee_gate.c. */
static uint8_t g_bogus_tx[8];

/* One COMMIT frame from `from` at height `bh`, carrying an EXPLICIT nonce
 * and an EXPLICIT wire timestamp. Both are explicit because this file is
 * about exactly those two fields: the nonce is the cache key and the
 * timestamp is the field the shipped eviction rule let the sender
 * choose. */
static void build_commit(nodus_t3_msg_t *m, const nodus_witness_t *w,
                         const peer_t *from, uint64_t bh,
                         uint64_t nonce, uint64_t ts) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_COMMIT;
    m->header.round = 1;          /* > last_committed_round (0)            */
    m->header.view = 0;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = ts;
    m->header.nonce = nonce;

    m->commit.block_height = bh;
    m->commit.batch_count = 1;
    m->commit.n_precommits = 0;   /* below the bh>=2 cert-quorum gate      */
    m->commit.proposal_timestamp = ts;
    memcpy(m->commit.proposer_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memset(m->commit.tx_root, 0xC5, NODUS_T3_TX_HASH_LEN);
    memset(m->commit.batch_txs[0].tx_hash, 0xC4, NODUS_T3_TX_HASH_LEN);
    m->commit.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    m->commit.batch_txs[0].tx_data = g_bogus_tx;
    m->commit.batch_txs[0].tx_len = (uint32_t)sizeof(g_bogus_tx);
}

/** Deliver one COMMIT and capture the window. */
static int deliver(nodus_witness_t *w, const peer_t *from, uint64_t nonce,
                   uint64_t ts, char *out, size_t cap) {
    nodus_t3_msg_t m;
    build_commit(&m, w, from, /*bh*/ 1, nonce, ts);
    cap_begin();
    int rc = nodus_witness_bft_handle_commit(w, &m);
    cap_end(out, cap);
    return rc;
}

/** `n` admitted COMMITs from one sender, all at the SAME wire timestamp,
 *  each with a fresh deterministic nonce.
 *
 *  The message is built ONCE and only its nonce moves: nodus_t3_msg_t is
 *  a large union and re-memsetting it 10500 times would dominate the
 *  section's runtime for no benefit. handle_commit takes it by const
 *  pointer and never writes through it.
 *
 *  The whole flood runs inside ONE capture window and the text is thrown
 *  away — otherwise the ctest log would carry ~14600 handler diagnostics.
 *  A window is not a nested one: cap_begin/cap_end are strictly paired
 *  here and around every deliver(). */
static void flood(nodus_witness_t *w, const peer_t *from, uint64_t ts,
                  uint64_t nonce_base, int n) {
    static char scratch[4096];
    nodus_t3_msg_t m;
    build_commit(&m, w, from, /*bh*/ 1, nonce_base, ts);
    cap_begin();
    for (int i = 0; i < n; i++) {
        m.header.nonce = nonce_base + (uint64_t)i;
        (void)nodus_witness_bft_handle_commit(w, &m);
    }
    cap_end(scratch, sizeof(scratch));
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — THE ANTI-VACUITY FLOOR.
 *
 * Runs first and asserts the two things every later section's meaning
 * rests on: an ordinary honest nonce IS refused on a genuine repeat, and
 * a fresh nonce IS still accepted. Without this pair a build in which the
 * cache refused EVERYTHING, or recorded NOTHING, would pass several of
 * the sections below.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_vacuity_floor(void) {
    printf("\n§1 the floor — a genuine repeat is refused, a fresh nonce "
           "is accepted\n");

    char dir[] = "/tmp/test_rpc_floor_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x11);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: the governing committee at height 1 has eight "
          "members, so every frame here is from an authorized sender");
    CHECK(nodus_witness_block_height(w) == 0,
          "precondition: the fixture chain is empty, so height 1 is our "
          "own next block and no height guard can fire");

    static char out_first[CAP_BUF];
    static char out_repeat[CAP_BUF];
    static char out_fresh[CAP_BUF];

    int rc1 = deliver(w, &g_peers[P_VACUITY], N_VAC_A, now,
                      out_first, sizeof(out_first));
    CHECK(rc1 == -1 && said(out_first, L_BELOW),
          "ADMITTED: a first-time nonce from a committee member travels "
          "past the committee gate to the F02 batch re-verify (-1 there "
          "is the pre-existing outcome for any unit fixture)");
    CHECK(!said(out_first, L_NONMEMBER) && !said(out_first, L_UNKNOWN) &&
          !said(out_first, L_LOADFAULT),
          "and no committee guard fired on it");

    int rc2 = deliver(w, &g_peers[P_VACUITY], N_VAC_A, now,
                      out_repeat, sizeof(out_repeat));
    CHECK(rc2 == -1 && silent(out_repeat),
          "REFUSED AS A REPLAY: the very same (sender, nonce) is turned "
          "away silently, above every guard that prints — so the record "
          "the admitted leg made is real and the cache still works");

    int rc3 = deliver(w, &g_peers[P_VACUITY], N_VAC_B, now,
                      out_fresh, sizeof(out_fresh));
    CHECK(rc3 == -1 && said(out_fresh, L_BELOW),
          "AND IT IS NOT REFUSING EVERYTHING: a different nonce from the "
          "same sender is admitted — the refusal above is a decision "
          "about the KEY, not a wall");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — RECORD AFTER THE GATES: a refused frame consumes NO slot.
 *
 * THE DEFECT: all six T3 consumers inserted the nonce ABOVE their own
 * chain_id and committee checks, so an unauthorised sender spent the
 * capacity that protects authorised ones — and, as the O15M note in
 * handle_newview names, a frame refused for a TRANSIENT reason burned the
 * nonce of the delivery that would have succeeded.
 *
 * THE OBSERVABLE, named as the header demands: the SAME (sender, nonce)
 * is delivered TWICE, and the only thing that moves between the legs is
 * the COMMITTEE. Leg 1 is refused by the gate; leg 2, with the sender now
 * seated, must reach the F02 verify. Under the shipped record-above-the-
 * gate order leg 2 would instead be refused SILENTLY as a replay — so
 * this section is a residue-independent revert detector, and the third
 * leg proves leg 2 did record.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_record_after_gates(void) {
    printf("\n§2 record-after-the-gates — a refused frame consumes no "
           "slot\n");

    char dir[] = "/tmp/test_rpc_gate_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x22);

    uint64_t now = nodus_time_now();

    /* BASE committee: peers [0..8). Peer 8 is on the roster and outside
     * it — one Dilithium keypair plus one DHT put, per BUGS.md O15N-L4. */
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: the committee at height 1 EXCLUDES the sender "
          "this leg uses");

    static char out_refused[CAP_BUF];
    static char out_seated[CAP_BUF];
    static char out_third[CAP_BUF];

    int rc1 = deliver(w, &g_peers[P_OUTSIDER], N_GATE, now,
                      out_refused, sizeof(out_refused));
    CHECK(rc1 == -1 && said(out_refused, L_NONMEMBER),
          "REFUSED BY THE COMMITTEE GATE: a roster member outside the "
          "committee is turned away, and the refusal NAMES that gate");
    CHECK(!said(out_refused, L_BELOW),
          "and nothing below the gate ran");

    /* THE ONE THING THAT MOVES. Same sender, same nonce, same timestamp,
     * same height — the committee now seats peer 8. */
    prime_committee(w, /*height*/ 1, N_COMMITTEE_WIDE);
    count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE_WIDE,
          "the committee is widened to nine and now CONTAINS that sender "
          "— the only difference between the two legs");

    int rc2 = deliver(w, &g_peers[P_OUTSIDER], N_GATE, now,
                      out_seated, sizeof(out_seated));
    CHECK(rc2 == -1 && said(out_seated, L_BELOW),
          "THE DEFECT IS CLOSED: the SAME (sender, nonce) is now admitted "
          "all the way to the F02 verify — so the refusal above consumed "
          "no slot in the replay cache");
    CHECK(!silent(out_seated) && !said(out_seated, L_NONMEMBER),
          "and it was NOT refused silently, which is what the shipped "
          "record-above-the-gate order would have produced");

    /* CONTROL. Without it, a build that recorded NOTHING anywhere would
     * pass the leg above. */
    int rc3 = deliver(w, &g_peers[P_OUTSIDER], N_GATE, now,
                      out_third, sizeof(out_third));
    CHECK(rc3 == -1 && silent(out_third),
          "CONTROL: a THIRD delivery of the same (sender, nonce) IS "
          "refused as a replay — so the admitted leg did record, and the "
          "admission is a decision about authorization, not a cache that "
          "has stopped writing");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — "OLDEST" IS THE INSERT ORDER, NOT THE WIRE TIMESTAMP.
 *
 * One sender inserts two entries in a KNOWN order with INVERTED wire
 * timestamps:
 *
 *     A  inserted FIRST,  stamped now - 50   (the NEWER wire stamp)
 *     B  inserted SECOND, stamped now - 100  (the OLDER wire stamp)
 *
 * The sender is then driven to exactly ONE eviction. Ranking by the
 * node-local sequence evicts A; ranking by the wire timestamp — the
 * shipped rule, and the field the sender chooses — would evict B. The
 * pair separates the two, and B's leg is the one that goes red if the
 * ordering key is ever put back on the timestamp.
 *
 * ARITHMETIC, so the "exactly one eviction" claim can be checked: after A
 * and B the sender holds 2 entries. nonce_record evicts when the count
 * BEFORE the insert is already at CAP_MIRROR, so flood frame i sees a
 * count of i + 1 and the first eviction is at i == CAP_MIRROR - 1. A
 * flood of exactly CAP_MIRROR - 1 frames therefore fires exactly one.
 *
 * ORDER OF THE TWO ASSERTIONS IS LOAD-BEARING: re-delivering A re-records
 * it, which puts the sender back at its cap and evicts the new oldest —
 * which is B. So B must be asserted FIRST.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_ordering_is_local(void) {
    printf("\n§3 the ordering key — insert order, not the wire "
           "timestamp\n");

    char dir[] = "/tmp/test_rpc_order_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x33);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: the sender is a committee member, so every frame "
          "here reaches the record");

    static char out_a[CAP_BUF];
    static char out_b[CAP_BUF];
    static char out_b2[CAP_BUF];
    static char out_a2[CAP_BUF];

    int rc_a = deliver(w, &g_peers[P_ORDER], N_ORDER_A, now - 50,
                       out_a, sizeof(out_a));
    CHECK(rc_a == -1 && said(out_a, L_BELOW),
          "A is recorded FIRST and carries the NEWER wire stamp "
          "(now - 50)");

    int rc_b = deliver(w, &g_peers[P_ORDER], N_ORDER_B, now - 100,
                       out_b, sizeof(out_b));
    CHECK(rc_b == -1 && said(out_b, L_BELOW),
          "B is recorded SECOND and carries the OLDER wire stamp "
          "(now - 100) — the two orders now disagree");

    flood(w, &g_peers[P_ORDER], now, N_FLOOD_BASE, CAP_MIRROR - 1);

    /* B FIRST — see the header note on assertion order. */
    int rc_b2 = deliver(w, &g_peers[P_ORDER], N_ORDER_B, now - 100,
                        out_b2, sizeof(out_b2));
    CHECK(rc_b2 == -1 && silent(out_b2),
          "B SURVIVED and is still refused as a replay — the entry with "
          "the OLDEST WIRE STAMP was NOT the victim, so the sender's own "
          "timestamp does not decide what leaves the cache");

    int rc_a2 = deliver(w, &g_peers[P_ORDER], N_ORDER_A, now - 50,
                        out_a2, sizeof(out_a2));
    CHECK(rc_a2 == -1 && said(out_a2, L_BELOW),
          "A WAS EVICTED and is admitted again — the entry inserted FIRST "
          "is the one that left, which is the node-local sequence and "
          "nothing else");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — A FLOODER EVICTS ONLY ITSELF.
 *
 * The bystander records one nonce; the flooder records one (its oldest)
 * and then floods its whole share. Exactly one eviction fires and it must
 * land on the FLOODER's own first entry, never on the bystander's.
 *
 * ARITHMETIC: after its first entry the flooder holds 1, so flood frame i
 * sees a count of i and the first eviction is at i == CAP_MIRROR. A flood
 * of exactly CAP_MIRROR frames fires exactly one.
 *
 * BOTH LEGS ARE REQUIRED. "The bystander survived" alone would pass on a
 * build that evicts nothing at all; "the flooder's oldest came back"
 * alone would pass on a build that evicts indiscriminately.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_flooder_evicts_itself(void) {
    printf("\n§4 a flooder evicts ONLY ITSELF\n");

    char dir[] = "/tmp/test_rpc_self_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x44);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: BOTH senders are committee members — the flooder "
          "is an authorized insider, which is the only sender class that "
          "can reach the record at all");

    static char out_h[CAP_BUF];
    static char out_f[CAP_BUF];
    static char out_h2[CAP_BUF];
    static char out_f2[CAP_BUF];

    int rc_h = deliver(w, &g_peers[P_HONEST_SELF], N_SELF_HON, now,
                       out_h, sizeof(out_h));
    CHECK(rc_h == -1 && said(out_h, L_BELOW),
          "the bystander records one nonce");

    int rc_f = deliver(w, &g_peers[P_FLOOD_SELF], N_SELF_FIRST, now,
                       out_f, sizeof(out_f));
    CHECK(rc_f == -1 && said(out_f, L_BELOW),
          "the flooder records one nonce — this is the entry it is about "
          "to destroy");

    flood(w, &g_peers[P_FLOOD_SELF], now, N_FLOOD_BASE, CAP_MIRROR);

    int rc_h2 = deliver(w, &g_peers[P_HONEST_SELF], N_SELF_HON, now,
                        out_h2, sizeof(out_h2));
    CHECK(rc_h2 == -1 && silent(out_h2),
          "THE BYSTANDER IS UNTOUCHED: its nonce is still refused as a "
          "replay after a full share has been flooded past it");

    int rc_f2 = deliver(w, &g_peers[P_FLOOD_SELF], N_SELF_FIRST, now,
                        out_f2, sizeof(out_f2));
    CHECK(rc_f2 == -1 && said(out_f2, L_BELOW),
          "AND THE EVICTION REALLY HAPPENED: the FLOODER's own oldest "
          "nonce is admitted again — it paid for its flood out of its own "
          "budget");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §5 — THE ATTACK (BUGS.md O15N-L1). RUNS LAST, AND IT IS THE ROW THAT
 *      MUST GO RED IF THE PRODUCTION CHANGE IS REVERTED.
 *
 * The victim records one nonce, stamped `now - 150` — the ONLY
 * past-stamped entry in this whole file, which makes it the unique global
 * minimum by wire timestamp. The attacker then floods FLOOD_BIG frames,
 * enough to exceed the 10000-entry GLOBAL cap this phase deleted even
 * from an empty table.
 *
 * On the shipped code that flood drives nonce_evict_oldest, which frees
 * the entire bucket holding the smallest wire timestamp — the victim's —
 * and the victim's captured frame becomes replayable. On the fixed code
 * the attacker can only spend its own share, and the victim's entry is
 * untouchable.
 *
 * WHY THE FLOOD IS STAMPED AT `now` AND NOT IN THE FUTURE: see the note
 * in HOW IT CAN LIE. A future stamp underflows the TTL subtraction and
 * the entry is purged on the next sweep of its bucket, so a far-future
 * flood never fills a table and this section would pass on the reverted
 * build while proving nothing.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_the_attack(void) {
    printf("\n§5 THE ATTACK — a flood cannot evict an honest sender's "
           "nonce\n");

    char dir[] = "/tmp/test_rpc_attack_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x55);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: attacker and victim are BOTH committee members "
          "— the strongest form of the attack, since the committee gate "
          "cannot help here");

    static char out_v1[CAP_BUF];
    static char out_v2[CAP_BUF];
    static char out_v3[CAP_BUF];
    static char out_v4[CAP_BUF];

    int rc1 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_HON, now - 150,
                      out_v1, sizeof(out_v1));
    CHECK(rc1 == -1 && said(out_v1, L_BELOW),
          "the victim's frame is admitted and recorded");

    int rc2 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_HON, now - 150,
                      out_v2, sizeof(out_v2));
    CHECK(rc2 == -1 && silent(out_v2),
          "BEFORE THE FLOOD: replaying the victim's captured frame is "
          "refused — this is the protection the attack exists to remove");

    flood(w, &g_peers[P_FLOOD_BIG], now, N_FLOOD_BASE, FLOOD_BIG);

    int rc3 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_HON, now - 150,
                      out_v3, sizeof(out_v3));
    CHECK(rc3 == -1 && silent(out_v3),
          "AFTER THE FLOOD: the victim's captured frame is STILL refused "
          "as a replay — the attacker spent its own share and could not "
          "reach the victim's. THIS IS THE DEFECT; on the shipped code "
          "the flood freed the victim's bucket and this replay succeeded");

    int rc4 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_FRESH, now,
                      out_v4, sizeof(out_v4));
    CHECK(rc4 == -1 && said(out_v4, L_BELOW),
          "AND THE VICTIM IS NOT LOCKED OUT: a fresh nonce from the same "
          "sender is still admitted, so the flood did not simply wall the "
          "cache off");

    fixture_free(w, dir);
}

int main(void) {
    printf("\nO15O Faz 5 — the replay cache is per sender, and its order "
           "is node-local\n");

    for (int i = 0; i < N_KEYS; i++) peer_make(&g_peers[i]);

    memset(g_bogus_tx, 0, sizeof(g_bogus_tx));
    g_bogus_tx[0] = (uint8_t)(DNAC_PROTOCOL_VERSION + 1);

    /* ⚠ THE ORDER IS REQUIRED. Small floods first, the one big flood
     * last. The nonce table is a process-global static with no reset
     * hook; under the FIXED code the order is irrelevant because budgets
     * are per sender and the identities are disjoint, but under a
     * REVERTED build a preceding big flood would leave the shared table
     * at its global cap and every later section would evict for reasons
     * unrelated to its subject. See the file header. */
    section_vacuity_floor();
    section_record_after_gates();
    section_ordering_is_local();
    section_flooder_evicts_itself();
    section_the_attack();

    printf("\nO15O Faz 5 PASS — all five sections ran; no section is "
           "skipped and none is UNREACHED\n");
    return 0;
}
