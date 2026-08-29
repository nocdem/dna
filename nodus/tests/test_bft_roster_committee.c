/**
 * Nodus — Task 59 BFT roster sourced from committee snapshot.
 *
 * Verifies nodus_witness_peer_current_set() returns the same set as
 * nodus_committee_get_for_block() and transitions at the epoch boundary.
 *
 * Scenarios:
 *   (1) Fresh DB (no validators): helper returns count=0.
 *   (2) Validator table seeded with 7 entries: helper returns 7 members,
 *       matches direct committee call.
 *   (3) Cross-epoch transition — before and after block_height crosses an
 *       EPOCH boundary, the committee cache key differs, so a mid-epoch
 *       stake bump is reflected in the NEXT epoch but NOT the current one.
 *   (4) A mid-epoch stake mutation within the SAME epoch is ignored by
 *       the cache: the committee stays frozen per §3.6.
 *
 * Uses the bootstrap path by passing INT64_MAX-style lookback through
 * nodus_committee_bootstrap_for_epoch (e_start < EPOCH_LENGTH+1), which
 * keeps the test standalone — no genesis block required.
 *
 * ══════════════════════════════════════════════════════════════════════
 * O15L Faz 4 (scenarios 5-10) — A COMMITTEE-LOAD FAULT IS NOT AN EMPTY
 * COMMITTEE, AT ANY OF THE FIVE GATES.
 * ══════════════════════════════════════════════════════════════════════
 *
 * WHAT SCENARIOS 5-10 PROVE. `load_committee_at_height_alloc` answers two
 * different things with two different codes, and five consumers used to
 * collapse them into one `else`:
 *
 *   rc 0, count 0   a COMMITTED answer — this chain has no committee yet
 *                   (pre-genesis). The gossip roster is the documented
 *                   bootstrap authority (F17 A5), and every one of the
 *                   five falls back to it. THIS MUST KEEP WORKING.
 *   rc != 0         the ABSENCE of an answer. Falling back to the gossip
 *                   roster here promotes the transport layer — admitted
 *                   from self-signed DHT registrations with no committee
 *                   check — to consensus-membership authority, which is
 *                   the authority O15G/O15H removed (design G4 / DG-4).
 *
 * Both halves are asserted at every gate, deliberately: a test that only
 * checked the refusal would pass just as happily on an implementation
 * that refused EVERYTHING, which would be a cluster-wide halt rather than
 * a fix.
 *
 * HOW THE FAULT IS INJECTED — REAL, NOT MOCKED. There is no seam to stub
 * in this tree, so the fault is produced through the production code
 * path: a row is written into `validator_set_snapshots` for the epoch the
 * gate will query, carrying a `snapshot_hash` that does not match its
 * `snapshot_blob`. nodus_witness_vset_get re-derives the hash on every
 * read and returns -1 on the mismatch
 * (nodus_witness_vset.c, "Integrity BEFORE trust"), and
 * nodus_committee_get_for_block turns that into its documented fail-
 * closed -1 rather than a recompute ("Row exists but is corrupt / DB
 * fault: never fall back"). That is exactly the SHARED fault the design's
 * F-10 names — a committed row that fails its own cross-check, identical
 * on every node — so the injected condition is the one the season is
 * actually about, not a convenient stand-in.
 *
 * Scenario 5 pins the injector itself in both directions before any gate
 * is measured; without it, a gate refusing under a fault that never
 * happened would read as a pass.
 *
 * WHAT THEY REQUIRE. A default build. No compile flag, no environment
 * variable, no chain state beyond a freshly created chain database with
 * an empty validator table. WHAT THEY LEAVE BEHIND: one mkdtemp directory
 * per scenario, all removed on the way out.
 *
 * HOW THEY COULD LIE, AND WHAT IS DONE ABOUT IT.
 *   - A crafted message that never reaches the committee gate would make
 *     the refusal arm pass for the wrong reason. Every message therefore
 *     carries the fixture's own chain_id (verify_chain_id runs first and
 *     this fixture HOLDS an identity), a sender that is on the gossip
 *     roster, a fresh nonce and a current timestamp — and the control arm
 *     asserts the SAME message is ACCEPTED when the fault is disarmed. It
 *     is one message, two committee states.
 *   - Scenario 8 (PROPOSE) cannot isolate its own gate: the bft_config
 *     refresh earlier in the same handler calls the same loader at the
 *     same height, so on a deterministic fault the handler has already
 *     refused before the gate is reached. The scenario measures the
 *     HANDLER's fail-closed behaviour and says so; the gate edit itself
 *     is defence in depth and is NOT claimed as independently covered.
 *
 * NO TIMING. Nothing here sleeps, measures elapsed time, or asserts on a
 * duration. Message timestamps use the wall clock only to satisfy the
 * handlers' ±300 s replay window, which is not what any assertion is on.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"

/* ── O15L Faz 4 — the five committee-authorization gates under test ── */
#include "witness/nodus_witness_bft.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "transport/nodus_tcp.h"     /* nodus_time_now for message headers */
#include "server/nodus_server.h"     /* the fixture's identity lives here  */

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"          /* DNA_VSET_HASH_LEN — the fault row  */

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "nodus/nodus_types.h"

#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %llu != %llu\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

static void init_validator(dnac_validator_record_t *v, uint8_t pub_fill,
                            uint64_t active_since, uint64_t self_stake) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = self_stake;
    v->total_delegated         = 0;
    v->external_delegated      = 0;
    v->commission_bps          = 500;
    v->status                  = DNAC_VALIDATOR_ACTIVE;
    v->active_since_block      = active_since;
    uint8_t fp_raw[64];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v->unstake_destination_fp[2*i]     = hex_digits[fp_raw[i] >> 4];
        v->unstake_destination_fp[2*i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
}

/* Insert a block row so nodus_witness_block_get(height) succeeds. */
static void insert_block_row(nodus_witness_t *w, uint64_t height,
                              const uint8_t state_seed[64]) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO blocks "
        "(height, tx_root, tx_count, timestamp, proposer_id, "
        " prev_hash, state_root) VALUES (?, ?, 0, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    uint8_t zeros[64] = {0};
    uint8_t proposer[NODUS_T3_WITNESS_ID_LEN];
    memset(proposer, 0xBB, sizeof(proposer));
    sqlite3_bind_int64(stmt, 1, (int64_t)height);
    sqlite3_bind_blob (stmt, 2, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, 1000);
    sqlite3_bind_blob (stmt, 4, proposer, sizeof(proposer), SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 5, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 6, state_seed, 64, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

/* Locate a pubkey with the given fill byte in an array of committee
 * members; return its index or -1. */
static int find_pubkey(const nodus_committee_member_t *arr, int count,
                        uint8_t pub_fill) {
    uint8_t needle[DNAC_PUBKEY_SIZE];
    memset(needle, pub_fill, sizeof(needle));
    for (int i = 0; i < count; i++) {
        if (memcmp(arr[i].pubkey, needle, DNAC_PUBKEY_SIZE) == 0) return i;
    }
    return -1;
}

/* Direct stake mutation (bypass STAKE TX path). */
static void set_self_stake(nodus_witness_t *w, const uint8_t *pubkey,
                            uint64_t val) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET self_stake = ? WHERE pubkey = ?",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, (int64_t)val);
    sqlite3_bind_blob (stmt, 2, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

/* ══════════════════════════════════════════════════════════════════════
 * O15L Faz 4 helpers — see the file header for what these prove and how
 * the fault is produced.
 * ══════════════════════════════════════════════════════════════════════ */

#define CHECK_WHY(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n    (%s)\n", \
                __FILE__, __LINE__, (msg), #cond); \
        exit(1); \
    } } while (0)

/** One consensus participant with REAL ML-DSA-87 keys — the prepared-cert
 *  scenario verifies production signatures, never a stub. */
typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} gate_peer_t;

static void gate_peer_make(gate_peer_t *p) {
    CHECK_WHY(qgp_dsa87_keypair(p->pk, p->sk) == 0, "keygen");
    uint8_t d[64];
    CHECK_WHY(qgp_sha3_512(p->pk, NODUS_PK_BYTES, d) == 0, "witness id hash");
    memcpy(p->id, d, NODUS_T3_WITNESS_ID_LEN);
}

/** Heap fixture — nodus_witness_t and nodus_server_t are both multi-MB,
 *  never stack objects. members[0] is US. The chain database is REAL and
 *  its validator table is EMPTY, which is the (rc 0, count 0) pre-genesis
 *  answer every control arm below depends on. */
static nodus_witness_t *gate_fixture(const gate_peer_t *members, int n,
                                       const char *dir,
                                       const uint8_t cid16[16]) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK_WHY(w != NULL, "witness alloc");
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    CHECK_WHY(srv != NULL, "server alloc");
    memcpy(srv->identity.pk.bytes, members[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, members[0].sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, members[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i < n; i++) {
        uint32_t s = w->roster.n_witnesses++;
        memcpy(w->roster.witnesses[s].witness_id, members[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(w->roster.witnesses[s].pubkey, members[i].pk,
               DNAC_PUBKEY_SIZE);
        w->roster.witnesses[s].active = true;
    }

    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    CHECK_WHY(nodus_witness_create_chain_db(w, cid16) == 0, "create chain db");
    CHECK_WHY(w->db != NULL, "the fixture must hold an OPEN database — the "
                             "whole point is a chain that CAN be read until "
                             "the fault is armed");

    /* THE CACHE SENTINEL, and it is load-bearing: a calloc'd witness has
     * cached_committee_epoch_start == 0, and every gate below queries
     * epoch 0. Left at the zero, nodus_committee_get_for_block takes its
     * cache-HIT branch, answers (rc 0, count 0) and never reads the
     * corrupt row — the fault arm would silently become a second control
     * arm. Production sets this to UINT64_MAX at init for the same
     * reason. Set AFTER create_chain_db so nothing it does can undo it. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;

    /* ⚠ THE QUORUM THIS PRODUCES CAN LEGITIMATELY BE ZERO, and a caller
     * that depends on it must seat enough members.
     *
     * nodus_witness_bft_config_init refuses to derive a quorum for a
     * roster below NODUS_T3_MIN_WITNESSES (5, nodus_types.h:153) — its
     * "Below minimum — consensus disabled" branch zeroes quorum,
     * f_tolerance and both timeouts. That is production behaviour, not a
     * fixture defect, and it is left alone here so small-roster scenarios
     * exercise the real initialiser.
     *
     * Scenarios 6, 7, 8 and 10 seat 1-2 members deliberately, to pin
     * leader arithmetic at a size where the sorted rank is unambiguous;
     * none of them reads bft_config.quorum, so a zero is harmless there.
     * Scenario 9 is the one that DOES read it (verify_prepared_cert's
     * threshold when there is no committee) and therefore seats 5. A new
     * scenario that touches the quorum must do the same — with fewer, the
     * threshold is 0 and every certificate verifies, which is a test that
     * passes while measuring nothing. */
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);
    return w;
}

static void gate_fixture_free(nodus_witness_t *w, const char *dir) {
    if (!w) return;
    if (w->db) { sqlite3_close(w->db); w->db = NULL; }
    free(w->server);
    free(w);
    rmrf(dir);
}

/** Invalidate the per-epoch committee cache so the NEXT lookup reads the
 *  database. On a fault the production code already leaves the cache
 *  invalid; this makes the arm/disarm transitions explicit rather than
 *  dependent on that. */
static void gate_cache_reset(nodus_witness_t *w) {
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;
}

/** ARM the fault: a validator_set_snapshots row for `epoch_start` whose
 *  stored hash does not match its stored blob. See the file header. */
static void arm_committee_fault(nodus_witness_t *w, uint64_t epoch_start) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO validator_set_snapshots "
        "(epoch_start, active_count, snapshot_hash, snapshot_blob, "
        " created_at_height) VALUES (?, 1, ?, ?, 0)", -1, &st, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    uint8_t bad_hash[DNA_VSET_HASH_LEN];
    memset(bad_hash, 0xF0, sizeof(bad_hash));
    uint8_t blob[16];
    memset(blob, 0x5A, sizeof(blob));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    sqlite3_bind_blob (st, 2, bad_hash, (int)sizeof(bad_hash), SQLITE_STATIC);
    sqlite3_bind_blob (st, 3, blob, (int)sizeof(blob), SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(st), SQLITE_DONE);
    sqlite3_finalize(st);
    gate_cache_reset(w);
}

/** DISARM: delete the corrupt row, restoring the pre-genesis answer. The
 *  arm/disarm pair is what makes every scenario an A/B on ONE fixture and
 *  ONE message — the committee state is the only thing that moves. */
static void disarm_committee_fault(nodus_witness_t *w, uint64_t epoch_start) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "DELETE FROM validator_set_snapshots WHERE epoch_start = ?",
        -1, &st, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    CHECK_EQ(sqlite3_step(st), SQLITE_DONE);
    sqlite3_finalize(st);
    gate_cache_reset(w);
}

/** Ask the loader directly what the gates are about to be told. */
static int committee_probe(nodus_witness_t *w, uint64_t height,
                             int *count_out) {
    nodus_committee_member_t *tmp =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*tmp));
    CHECK_WHY(tmp != NULL, "probe alloc");
    int rc = nodus_committee_get_for_block(w, height, tmp,
                                             DNAC_MAX_ACTIVE_VALIDATORS,
                                             count_out);
    free(tmp);
    return rc;
}

/** The 116-byte C5 PREPARED preimage (O15N Faz 2A) — "prepared"(8B ASCII)
 *  ‖ chain_id(32B) ‖ view(4B BE) ‖ height(8B BE) ‖ tx_hash(64B), the
 *  layout compute_prepared_preimage produces — signed with a peer's own
 *  key. chain_id comes from the fixture (this one DOES hold a chain
 *  identity: gate_fill_header below relies on the same field), because
 *  nodus_witness_bft_verify_prepared_cert rebuilds the preimage from
 *  w->chain_id. */
static void gate_sign_prepared(uint8_t out[NODUS_SIG_BYTES],
                                 const gate_peer_t *p, uint32_t view,
                                 uint64_t height, const uint8_t *tx_hash,
                                 const uint8_t *chain_id) {
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
    CHECK_WHY(nodus_sign_prepared_vote(&sig, pre, sizeof(pre), &sk) == 0,
              "prepared sign");
    memcpy(out, sig.bytes, NODUS_SIG_BYTES);
}

/** Common header fields every crafted BFT message needs to REACH its
 *  committee gate: our chain identity (verify_chain_id runs first and
 *  this fixture holds one), a current timestamp and a fresh nonce (the
 *  ±300 s replay window and the nonce cache both precede the gate). */
static void gate_fill_header(nodus_t3_msg_t *m, const nodus_witness_t *w,
                               const gate_peer_t *from, uint32_t view) {
    memset(m, 0, sizeof(*m));
    m->header.round = 1;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = nodus_time_now();
    CHECK_WHY(nodus_random((uint8_t *)&m->header.nonce,
                             sizeof(m->header.nonce)) == 0,
              "fresh nonce — a repeat is dropped by is_replay before the "
              "committee gate and the arm would prove nothing");
}

/* ── Scenario 5 — the injector itself, both directions ─────────────── */
static void gate_scenario_fault_injector(void) {
    printf("  (5) the injected fault is REAL and REVERSIBLE\n");

    static gate_peer_t self;
    gate_peer_make(&self);

    char dir[] = "/tmp/test_o15l_probe_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    uint8_t cid[16]; memset(cid, 0xA5, sizeof(cid));
    nodus_witness_t *w = gate_fixture(&self, 1, dir, cid);

    /* An empty chain: height 0, so every gate below queries height 1,
     * which resolves to epoch_start 0. */
    CHECK_EQ(nodus_witness_block_height(w), 0);

    int count = -1;
    CHECK_WHY(committee_probe(w, 1, &count) == 0 && count == 0,
              "BASELINE: an empty validator table is a COMMITTED answer — "
              "rc 0 with count 0, the pre-genesis case every fallback arm "
              "below relies on");

    arm_committee_fault(w, 0);
    count = -1;
    CHECK_WHY(committee_probe(w, 1, &count) == -1,
              "ARMED: a committed snapshot row that fails its own hash "
              "cross-check is a FAULT — the loader must fail closed and "
              "never recompute a substitute set");

    disarm_committee_fault(w, 0);
    count = -1;
    CHECK_WHY(committee_probe(w, 1, &count) == 0 && count == 0,
              "DISARMED: the same fixture answers pre-genesis again — the "
              "arm/disarm pair moves the committee state and nothing else");

    gate_fixture_free(w, dir);
}

/* ── Scenario 6 — GATE 1: nodus_witness_bft_is_leader ──────────────── */
static void gate_scenario_is_leader(void) {
    printf("  (6) GATE 1 is_leader — a fault does not elect a leader from "
           "the transport roster\n");

    static gate_peer_t self;
    gate_peer_make(&self);

    char dir[] = "/tmp/test_o15l_leader_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    uint8_t cid[16]; memset(cid, 0xB6, sizeof(cid));
    nodus_witness_t *w = gate_fixture(&self, 1, dir, cid);

    /* Sole roster member ⇒ sorted rank 0; next height 1 ⇒ epoch 0; view 0
     * ⇒ leader_index(0, 0, 1) == 0. The pre-genesis fallback elects US. */
    CHECK_WHY(nodus_witness_bft_is_leader(w),
              "CONTROL: with a committed 'no committee yet' answer the "
              "gossip-roster bootstrap still elects a leader — without "
              "this half, a blanket 'always false' would pass");

    arm_committee_fault(w, 0);
    CHECK_WHY(!nodus_witness_bft_is_leader(w),
              "FAULT: a node that cannot establish its committee must not "
              "lead — leading on sorted gossip rank is how a non-member "
              "proposes (G4)");

    disarm_committee_fault(w, 0);
    CHECK_WHY(nodus_witness_bft_is_leader(w),
              "the refusal is a function of the FAULT, not a latched flag "
              "— clearing it restores leadership");

    gate_fixture_free(w, dir);
}

/* ── Scenario 7 — GATE 3: handle_viewchg ───────────────────────────── */
static void gate_scenario_viewchg(void) {
    printf("  (7) GATE 3 VIEW_CHANGE — a fault no longer ACCEPTS\n");

    static gate_peer_t self, b;
    gate_peer_make(&self); gate_peer_make(&b);
    gate_peer_t members[2] = { self, b };

    char dir[] = "/tmp/test_o15l_viewchg_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    uint8_t cid[16]; memset(cid, 0xC7, sizeof(cid));
    nodus_witness_t *w = gate_fixture(members, 2, dir, cid);

    /* new_view 0 is not greater than current_view 0, so the handler
     * returns 0 IMMEDIATELY after the committee gate. That makes the
     * return value a direct read-out of the gate and nothing downstream:
     * 0 means "passed the gate", -1 means "refused at it". */
    nodus_t3_msg_t m;

    gate_fill_header(&m, w, &b, 0);
    m.type = NODUS_T3_VIEWCHG;
    m.viewchg.new_view = 0;
    CHECK_WHY(nodus_witness_bft_handle_viewchg(w, &m) == 0,
              "CONTROL: pre-genesis, a roster peer's VIEW_CHANGE passes the "
              "gate — the F17 A5 bootstrap authorization is preserved");

    arm_committee_fault(w, 0);
    gate_fill_header(&m, w, &b, 0);
    m.type = NODUS_T3_VIEWCHG;
    m.viewchg.new_view = 0;
    CHECK_WHY(nodus_witness_bft_handle_viewchg(w, &m) == -1,
              "FAULT: THE WORST OF THE FIVE — the fault used to leave "
              "`reject` at false, so a committee-load failure ACCEPTED the "
              "view change outright; it must now refuse it");

    disarm_committee_fault(w, 0);
    gate_fill_header(&m, w, &b, 0);
    m.type = NODUS_T3_VIEWCHG;
    m.viewchg.new_view = 0;
    CHECK_WHY(nodus_witness_bft_handle_viewchg(w, &m) == 0,
              "the same message is accepted again once the fault clears — "
              "one message, two committee states");

    gate_fixture_free(w, dir);
}

/* ── Scenario 8 — GATE 4: handle_newview ───────────────────────────── */
static void gate_scenario_newview(void) {
    printf("  (8) GATE 4 NEW_VIEW — a fault does not rank its sender in "
           "the transport roster\n");

    static gate_peer_t self, b;
    gate_peer_make(&self); gate_peer_make(&b);
    gate_peer_t members[2] = { self, b };

    char dir[] = "/tmp/test_o15l_newview_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    uint8_t cid[16]; memset(cid, 0xD8, sizeof(cid));
    nodus_witness_t *w = gate_fixture(members, 2, dir, cid);

    /* Under the pre-genesis fallback the expected leader is sorted rank
     * (epoch + new_view) % 2 = 0. WHICH of the two random ids sorts first
     * is not ours to assume, so it is resolved at run time. */
    int rank0 = nodus_witness_roster_sorted_at(&w->roster, 0);
    CHECK_WHY(rank0 >= 0, "sorted rank 0 resolves to a roster slot");
    gate_peer_t *sender = (memcmp(w->roster.witnesses[rank0].witness_id,
                                    self.id, NODUS_T3_WITNESS_ID_LEN) == 0)
                              ? &self : &b;

    /* has_reproposal = false and no local prepared value, so the handler
     * runs to its terminal `return 0` — again making the return value a
     * read-out of the committee gate. */
    nodus_t3_msg_t m;

    gate_fill_header(&m, w, sender, 0);
    m.type = NODUS_T3_NEWVIEW;
    m.newview.new_view = 0;
    m.newview.has_reproposal = false;
    CHECK_WHY(nodus_witness_bft_handle_newview(w, &m) == 0,
              "CONTROL: pre-genesis, the sorted-rank leader's NEW_VIEW is "
              "accepted — the bootstrap fallback is preserved");

    arm_committee_fault(w, 0);
    gate_fill_header(&m, w, sender, 0);
    m.type = NODUS_T3_NEWVIEW;
    m.newview.new_view = 0;
    m.newview.has_reproposal = false;
    CHECK_WHY(nodus_witness_bft_handle_newview(w, &m) == -1,
              "FAULT: ranking the sender in the gossip roster during a "
              "fault is how a non-member becomes 'the expected leader' and "
              "installs a view (G4)");

    disarm_committee_fault(w, 0);
    gate_fill_header(&m, w, sender, 0);
    m.type = NODUS_T3_NEWVIEW;
    m.newview.new_view = 0;
    m.newview.has_reproposal = false;
    CHECK_WHY(nodus_witness_bft_handle_newview(w, &m) == 0,
              "and accepted again once the fault clears");

    gate_fixture_free(w, dir);
}

/* ── Scenario 9 — GATE 5: verify_prepared_cert (the C5 path) ───────── */
static void gate_scenario_prepared_cert(void) {
    printf("  (9) GATE 5 C5 prepared cert — a fault does not resolve voter "
           "keys from the transport roster\n");

    /* ── FIVE members, and the number is NOT arbitrary ─────────────────
     *
     * This is the ONLY gate scenario whose subject depends on
     * w->bft_config.quorum: with no committee, verify_prepared_cert takes
     * its threshold from there ("required = have_committee ?
     * dna_bft_quorum(c_count) : w->bft_config.quorum").
     *
     * nodus_witness_bft_config_init REFUSES to derive a quorum for a
     * roster below NODUS_T3_MIN_WITNESSES (5, nodus/include/nodus/
     * nodus_types.h:153): that branch is labelled "Below minimum —
     * consensus disabled" and zeroes quorum, f_tolerance and both
     * timeouts. A four-member roster therefore yields quorum 0 — and a
     * threshold of 0 makes EVERY certificate verify, including the forged
     * one this scenario exists to refuse. The danger was never that the
     * test failed; it is that a test built on quorum 0 PASSES while
     * measuring nothing.
     *
     * So the roster is seated at the minimum the production initialiser
     * will actually serve. quorum = (2*5)/3 + 1 = 4, and four real
     * signatures are supplied. */
    static gate_peer_t self, b, c, d, e;
    gate_peer_make(&self); gate_peer_make(&b);
    gate_peer_make(&c);    gate_peer_make(&d);
    gate_peer_make(&e);
    gate_peer_t members[5] = { self, b, c, d, e };

    char dir[] = "/tmp/test_o15l_c5_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    uint8_t cid[16]; memset(cid, 0xE9, sizeof(cid));
    nodus_witness_t *w = gate_fixture(members, 5, dir, cid);

    /* Asserted in three parts so a future regression names itself instead
     * of surfacing as a mystifying count mismatch: the roster really was
     * seated before bft_config_init ran, the quorum is not the
     * consensus-disabled zero, and it is the value the PBFT formula gives
     * for this n. */
    CHECK_EQ(w->roster.n_witnesses, 5);
    CHECK_WHY(w->bft_config.quorum > 0,
              "a quorum of 0 means bft_config_init took its 'below "
              "NODUS_T3_MIN_WITNESSES — consensus disabled' branch, and "
              "every assertion below would then pass vacuously against a "
              "threshold nothing can fail");
    CHECK_EQ(w->bft_config.quorum, 4);   /* (2*5)/3 + 1 */

    const uint64_t H = 5;      /* epoch_start 0, the armed row's epoch */
    const uint32_t V = 2;
    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x77, sizeof(txh));

    nodus_t3_cert_entry_t cert[4];
    memset(cert, 0, sizeof(cert));
    const gate_peer_t *signers[4] = { &self, &b, &c, &d };
    for (int i = 0; i < 4; i++) {
        memcpy(cert[i].voter_id, signers[i]->id, NODUS_T3_WITNESS_ID_LEN);
        gate_sign_prepared(cert[i].signature, signers[i], V, H, txh,
                           w->chain_id);
    }

    CHECK_WHY(nodus_witness_bft_verify_prepared_cert(w, H, V, txh, cert, 4),
              "CONTROL: pre-genesis, quorum-many REAL signatures resolve "
              "through the documented roster bootstrap and the cert "
              "verifies");

    /* Second control, in the other direction: the same fixture must still
     * REJECT a broken certificate, or 'always true' would pass above. */
    {
        nodus_t3_cert_entry_t tampered[4];
        memcpy(tampered, cert, sizeof(tampered));
        tampered[1].signature[0] ^= 0xFF;
        CHECK_WHY(!nodus_witness_bft_verify_prepared_cert(w, H, V, txh,
                                                            tampered, 4),
                  "CONTROL: one broken signature drops below quorum and the "
                  "cert is refused — the accept above is not a blanket yes");
    }

    arm_committee_fault(w, 0);
    CHECK_WHY(!nodus_witness_bft_verify_prepared_cert(w, H, V, txh, cert, 4),
              "FAULT: the HIGHEST-VALUE gate (F-1) — a committee-load fault "
              "used to resolve voter pubkeys from the gossip roster while "
              "taking the threshold from bft_config, so quorum-many "
              "self-registered DHT keys could forge a prepared cert and "
              "bind a faulting node to a value nobody prepared");

    disarm_committee_fault(w, 0);
    CHECK_WHY(nodus_witness_bft_verify_prepared_cert(w, H, V, txh, cert, 4),
              "the identical certificate verifies again once the fault "
              "clears — the refusal is the FAULT's, not the cert's");

    gate_fixture_free(w, dir);
}

/* ── Scenario 10 — GATE 2: handle_propose ──────────────────────────── */
static void gate_scenario_propose(void) {
    printf("  (10) GATE 2 PROPOSE — a fault refuses the proposal and "
           "mutates no round state\n");

    static gate_peer_t self, b;
    gate_peer_make(&self); gate_peer_make(&b);
    gate_peer_t members[2] = { self, b };

    char dir[] = "/tmp/test_o15l_propose_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    uint8_t cid[16]; memset(cid, 0xFA, sizeof(cid));
    nodus_witness_t *w = gate_fixture(members, 2, dir, cid);

    int rank0 = nodus_witness_roster_sorted_at(&w->roster, 0);
    CHECK_WHY(rank0 >= 0, "sorted rank 0 resolves to a roster slot");
    gate_peer_t *leader = (memcmp(w->roster.witnesses[rank0].witness_id,
                                   self.id, NODUS_T3_WITNESS_ID_LEN) == 0)
                              ? &self : &b;
    gate_peer_t *follower = (leader == &self) ? &b : &self;

    uint8_t ptx[NODUS_T3_TX_HASH_LEN];
    memset(ptx, 0x33, sizeof(ptx));

    nodus_t3_msg_t pm;

    /* ── FAULT FIRST, so the control cannot be credited to leftover state.
     *
     * ⚠ HONEST LABEL. This arm exercises the HANDLER, not the gate edit in
     * isolation: refresh_bft_config_from_committee earlier in the same
     * function calls the SAME loader at the SAME height, so on a
     * deterministic fault the handler refuses there and the committee gate
     * is never reached. There is no in-process way to make one succeed and
     * the other fail without a mock this tree does not have. The gate edit
     * is defence in depth and is NOT claimed as independently covered. */
    arm_committee_fault(w, 0);
    gate_fill_header(&pm, w, leader, 0);
    pm.type = NODUS_T3_PROPOSE;
    pm.propose.batch_count = 1;
    pm.propose.block_height = 1;
    memcpy(pm.propose.batch_txs[0].tx_hash, ptx, NODUS_T3_TX_HASH_LEN);
    pm.propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    {
        nodus_key_t bh;
        CHECK_WHY(nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) == 0,
                  "tx_root hash");
        memcpy(pm.propose.tx_root, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }
    CHECK_WHY(nodus_witness_bft_handle_propose(w, &pm) == -1,
              "FAULT: the proposal is refused");
    CHECK_WHY(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "and NOTHING was mutated — a refusal that had already entered "
              "the round would leave a phase the timeout path would then "
              "have to unwind");

    /* ── CONTROL A — the fallback still ENFORCES. Cleared fault, but the
     * proposal comes from the NON-leader: the pre-genesis branch ranks it
     * by sorted rank and refuses. This runs BEFORE control B because it
     * leaves the round IDLE, and it is what stops control B from reading
     * as "accepts anything once the fault is gone". */
    disarm_committee_fault(w, 0);
    gate_fill_header(&pm, w, follower, 0);
    pm.type = NODUS_T3_PROPOSE;
    pm.propose.batch_count = 1;
    pm.propose.block_height = 1;
    memcpy(pm.propose.batch_txs[0].tx_hash, ptx, NODUS_T3_TX_HASH_LEN);
    pm.propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    {
        nodus_key_t bh;
        CHECK_WHY(nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) == 0,
                  "tx_root hash");
        memcpy(pm.propose.tx_root, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }
    CHECK_WHY(nodus_witness_bft_handle_propose(w, &pm) == -1,
              "CONTROL A: the pre-genesis fallback still RANKS — a proposal "
              "from the non-leader is refused at the same branch");
    CHECK_WHY(w->round_state.phase == NODUS_W_PHASE_IDLE,
              "CONTROL A left the round untouched, so CONTROL B starts from "
              "the same state the fault arm did");

    /* ── CONTROL B — the identical proposal from the sorted-rank LEADER is
     * accepted into a round, which is what proves the pre-genesis fallback
     * at this site is alive rather than uniformly refusing. Deliberately
     * LAST: it enters a round, and nothing after it needs a clean one. */
    gate_fill_header(&pm, w, leader, 0);
    pm.type = NODUS_T3_PROPOSE;
    pm.propose.batch_count = 1;
    pm.propose.block_height = 1;
    memcpy(pm.propose.batch_txs[0].tx_hash, ptx, NODUS_T3_TX_HASH_LEN);
    pm.propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    {
        nodus_key_t bh;
        CHECK_WHY(nodus_hash(ptx, NODUS_T3_TX_HASH_LEN, &bh) == 0,
                  "tx_root hash");
        memcpy(pm.propose.tx_root, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }
    (void)nodus_witness_bft_handle_propose(w, &pm);
    CHECK_WHY(w->round_state.phase == NODUS_W_PHASE_PREVOTE,
              "CONTROL B: the sorted-rank leader's proposal passed the "
              "committee gate and entered the round — the F17 A5 bootstrap "
              "fallback still works. (The return code is deliberately NOT "
              "asserted: past the gate the handler goes on to validate the "
              "batch, which is a different subject; round entry is this "
              "gate's read-out and the batch verdict is not.)");
    CHECK_EQ(w->round_state.block_height, 1);

    gate_fixture_free(w, dir);
}

int main(void) {
    char data_path[] = "/tmp/test_bft_roster_committee_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    /* Cache sentinel mirrors the production init path. */
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0x59, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* ── Scenario 1: no validators yet ───────────────────────────── */
    printf("  (1) empty validator table → empty committee\n");
    nodus_committee_member_t roster0[DNAC_COMMITTEE_SIZE];
    int count0 = -1;
    /* Use a block_height inside the bootstrap range (e_start < EPOCH+1)
     * so the helper takes the bootstrap path; this avoids needing to
     * seed a lookback block row for the empty case. */
    CHECK_EQ(nodus_witness_peer_current_set(&w, 1, roster0,
                                              DNAC_COMMITTEE_SIZE, &count0), 0);
    CHECK_EQ(count0, 0);

    /* ── Scenario 2: seed 7 validators ───────────────────────────── */
    printf("  (2) 7 seeded validators → committee of 7\n");
    /* Active since block 1; bootstrap path ignores MIN_TENURE, so all
     * 7 are immediately eligible. */
    for (int i = 0; i < 7; i++) {
        dnac_validator_record_t v;
        /* Stakes increase by index so ordering is distinguishable. */
        init_validator(&v, /*pub_fill=*/(uint8_t)(0x10 + i),
                        /*active_since=*/1,
                        /*self_stake=*/1000000ULL + (uint64_t)i * 100);
        CHECK_EQ(nodus_validator_insert(&w, &v), 0);
    }

    /* block_height = 5 → e_start = 0 → bootstrap path. Fresh cache. */
    w.cached_committee_epoch_start = UINT64_MAX;
    w.cached_committee_count = 0;

    nodus_committee_member_t roster_bft[DNAC_COMMITTEE_SIZE];
    int count_bft = -1;
    CHECK_EQ(nodus_witness_peer_current_set(&w, 5, roster_bft,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_bft), 0);
    CHECK_EQ(count_bft, 7);

    /* Direct committee call MUST return the same members. */
    nodus_committee_member_t roster_cm[DNAC_COMMITTEE_SIZE];
    int count_cm = -1;
    CHECK_EQ(nodus_committee_get_for_block(&w, 5, roster_cm,
                                             DNAC_COMMITTEE_SIZE,
                                             &count_cm), 0);
    CHECK_EQ(count_cm, count_bft);
    for (int i = 0; i < count_bft; i++) {
        CHECK(memcmp(roster_bft[i].pubkey, roster_cm[i].pubkey,
                     DNAC_PUBKEY_SIZE) == 0);
        CHECK_EQ(roster_bft[i].total_stake, roster_cm[i].total_stake);
    }

    /* Validator with fill 0x16 (highest stake) must be in top-7. */
    CHECK(find_pubkey(roster_bft, count_bft, 0x16) >= 0);

    /* ── Scenario 3: cross-epoch transition ──────────────────────── */
    printf("  (3) epoch boundary transition — mid-epoch mutation "
           "applies to next epoch only\n");
    /* Seed block rows so the non-bootstrap path can compute committees
     * for later epochs. Math is parametric on DNAC_EPOCH_LENGTH:
     *   epoch 4 (e_start=4*EPOCH): lookback = 4*EPOCH - EPOCH - 1 = 3*EPOCH - 1
     *   epoch 5 (e_start=5*EPOCH): lookback = 4*EPOCH - 1
     * Both lookbacks are >= MIN_TENURE (2*EPOCH) past active_since=1,
     * so all 7 validators remain eligible without the bootstrap carve-out. */
    const uint64_t epoch_len = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t e_a = epoch_len * 4;
    const uint64_t lookback_a = e_a - epoch_len - 1;
    const uint64_t e_b = epoch_len * 5;
    const uint64_t lookback_b = e_b - epoch_len - 1;
    uint8_t seed_a[64]; memset(seed_a, 0xA1, sizeof(seed_a));
    uint8_t seed_b[64]; memset(seed_b, 0xB2, sizeof(seed_b));
    insert_block_row(&w, lookback_a, seed_a);
    insert_block_row(&w, lookback_b, seed_b);

    /* Fresh cache so the next call hits the lookback path. */
    w.cached_committee_epoch_start = UINT64_MAX;
    w.cached_committee_count = 0;

    /* Within epoch A — should pick up lookback_a's seed. */
    nodus_committee_member_t roster_a[DNAC_COMMITTEE_SIZE];
    int count_a = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_a + 10, roster_a,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_a), 0);
    CHECK_EQ(count_a, 7);
    CHECK_EQ(w.cached_committee_epoch_start, e_a);

    /* Cross into epoch B — different e_start → recompute. We also push
     * a new stake on validator 0x10 so the ordering changes visibly. */
    uint8_t pk10[DNAC_PUBKEY_SIZE];
    memset(pk10, 0x10, sizeof(pk10));
    set_self_stake(&w, pk10, 9999999ULL);

    nodus_committee_member_t roster_b[DNAC_COMMITTEE_SIZE];
    int count_b = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_b + 10, roster_b,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_b), 0);
    CHECK_EQ(count_b, 7);
    CHECK_EQ(w.cached_committee_epoch_start, e_b);
    /* 0x10 now the top-stake entry (9_999_999 > every other stake). */
    CHECK(find_pubkey(roster_b, count_b, 0x10) == 0);

    /* ── Scenario 4: mid-epoch mutation ignored by cache ─────────── */
    printf("  (4) mid-epoch stake bump does not shift cached roster\n");
    /* Re-query epoch A → fresh DB read (cache pinned on B), so we see
     * the mutation. But a second query within epoch A returns the
     * cached result even after another mutation — that is the frozen
     * epoch guarantee we rely on for BFT roster stability. */
    w.cached_committee_epoch_start = UINT64_MAX;
    w.cached_committee_count = 0;

    nodus_committee_member_t roster_a2[DNAC_COMMITTEE_SIZE];
    int count_a2 = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_a + 5, roster_a2,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_a2), 0);
    CHECK_EQ(count_a2, 7);
    /* Snapshot 0x10's cached total_stake. */
    int idx10 = find_pubkey(roster_a2, count_a2, 0x10);
    CHECK(idx10 >= 0);
    uint64_t snap_0x10 = roster_a2[idx10].total_stake;

    /* Double 0x10's stake — any recompute would move it. */
    set_self_stake(&w, pk10, snap_0x10 * 2ULL);

    nodus_committee_member_t roster_a3[DNAC_COMMITTEE_SIZE];
    int count_a3 = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_a + 50, roster_a3,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_a3), 0);
    CHECK_EQ(count_a3, count_a2);
    int idx10b = find_pubkey(roster_a3, count_a3, 0x10);
    CHECK(idx10b >= 0);
    /* Cache intact — stake for 0x10 unchanged. */
    CHECK_EQ(roster_a3[idx10b].total_stake, snap_0x10);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    /* ── O15L Faz 4 — the five committee-authorization gates ─────────
     * Each scenario builds its OWN heap fixture and its own chain
     * database, so a fault armed by one cannot bleed into the next. */
    printf("\nO15L Faz 4 — a committee-load FAULT is not an empty "
           "committee\n");
    gate_scenario_fault_injector();
    gate_scenario_is_leader();
    gate_scenario_viewchg();
    gate_scenario_newview();
    gate_scenario_prepared_cert();
    gate_scenario_propose();

    printf("\nAll Task 59 BFT roster committee + O15L Faz 4 gate tests "
           "passed.\n");
    return 0;
}
