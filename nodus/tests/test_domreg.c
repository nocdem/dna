/**
 * Nodus — Ledger V2 S4: domain registry, readiness and the staged
 * activation scheduler (INACTIVE layer).
 *
 * Runs against a REAL witness chain DB (temp directory, production schema
 * via nodus_witness_create_chain_db — the test_vset_persist fixture
 * pattern; nodus_witness_t is multi-MB, ALWAYS heap). Readiness signals
 * use REAL Dilithium5 keys (qgp_dsa87_keypair_derand, fixed seeds —
 * deterministic, never wall-clock or entropy dependent).
 *
 * Sections (E = DNAC_EPOCH_LENGTH, ep(k) = k*E):
 *   1. Genesis registry: SYSTEM + DNA_CORE ACTIVE, idempotent re-init,
 *      manifests bound to the compiled runtime table, root != empty,
 *      close/reopen identity.
 *   2. Registration: test-only third domain (id 7, types 20/21); duplicate
 *      id rejects; type-ownership collision rejects.
 *   3. Readiness replay-protection axes at N=7: wrong chain / domain /
 *      ruleset version / one-bit hash / proposal / epoch / non-member /
 *      forged signature all reject; identical duplicate is a no-op and
 *      never increases the count; a conflicting second signal is
 *      first-wins (-2).
 *   4. Quorum arithmetic: N=7 needs 5 (4 fails, 5 schedules); N=9 needs 7
 *      (6 fails, 7 schedules — separate domain 8); stake never weights a
 *      readiness vote. Epoch pins: deadline == sched + 2E; activation
 *      earlier than the deadline rejects; double-schedule rejects.
 *   5. Stage D/E boundary: quorum alone CANNOT activate (5/7 ready →
 *      postpone); membership churn on the boundary → postpone even when
 *      all-ready; repeated postponement (+E, count++) with no partial
 *      activation; all-ready + same-set → ACTIVATE (SCHEDULED→ACTIVE);
 *      snapshot-authority pin (wrong-epoch snapshots reject).
 *   6. Upgrade path (DNA_CORE): propose new manifest with the SAME
 *      builtin tuple → build_signal PASSES the local-runtime gate;
 *      a target with an absent tuple → build_signal REFUSES; activation
 *      promotes pending→current.
 *   7. Cancellation: signals deleted; an old-proposal signal rejects
 *      after re-proposal (digest changed).
 *   8. Stage C: exclusions_at lists exactly the unready members; floor
 *      guard returns 2 and excludes nobody; filter_snapshot preserves
 *      order and never touches the DB (non-slashing by construction).
 *   9. Restart during every scheduler stage reconstructs identical state
 *      (registry root byte-compare across close/reopen).
 *  10. Invalid transitions leave the stored record byte-unchanged.
 *
 * @file test_domreg.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_schema.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define E   ((uint64_t)DNAC_EPOCH_LENGTH)
#define ep(k) ((uint64_t)(k) * E)

/* ── fs helpers ─────────────────────────────────────────────────────── */
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

/* ── keys / snapshots ───────────────────────────────────────────────── */
typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static void derive_voter(const uint8_t *pk, uint8_t out[32]) {
    uint8_t full[64];
    qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, full);
    memcpy(out, full, 32);
}

static int make_keys(keyset_t *ks, int n) {
    for (int i = 0; i < n; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(ks[i].pk, ks[i].sk, seed) != 0)
            return -1;
        derive_voter(ks[i].pk, ks[i].voter);
    }
    return 0;
}

/* Stakes deliberately WILD (i multiplies) so any stake-weighted counting
 * would be caught instantly. */
static dna_vset_snapshot_t *make_snapshot(const keyset_t *ks, int n,
                                          uint64_t epoch) {
    dna_vset_snapshot_t *s = dna_vset_alloc((uint16_t)n);
    if (!s) return NULL;
    s->epoch = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    for (int i = 0; i < n; i++) {
        memcpy(s->entries[i].voter_id, ks[i].voter, 32);
        memcpy(s->entries[i].pubkey, ks[i].pk, QGP_DSA87_PUBLICKEYBYTES);
        s->entries[i].total_stake = 1000000000000000ULL * (uint64_t)(i + 1);
        s->entries[i].self_bond   = 1000000000000000ULL;
        s->entries[i].commission_bps = 100;
    }
    return s;
}

/* ── witness fixture ────────────────────────────────────────────────── */
typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_domreg_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x11, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    /* S7: the genesis registry path runs the runtimes' activation-time
     * state_init hooks (the CORE hook creates its configured pool),
     * which require the v7 schema — exactly as production V2 genesis
     * does. */
    if (nodus_witness_db_migrate_v2s7(fx->w) != 0) {
        sqlite3_close(fx->w->db);
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    return 0;
}

static int fx_reopen(fixture_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/* Raw stored record bytes — for "state unchanged" assertions. */
static int record_blob(nodus_witness_t *w, uint32_t id,
                       uint8_t out[DNA_DOMREG_REC_ENC_LEN]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT record FROM domain_registry WHERE domain_id = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)id);
    int rc = sqlite3_step(st);
    int out_rc = -1;
    if (rc == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_DOMREG_REC_ENC_LEN) {
        memcpy(out, sqlite3_column_blob(st, 0), DNA_DOMREG_REC_ENC_LEN);
        out_rc = 0;
    }
    sqlite3_finalize(st);
    return out_rc;
}

/* Build + sign one readiness signal by hand (op_signal's counterpart). */
static int hand_signal(dna_readiness_signal_t *out,
                       const uint8_t chain[32], const keyset_t *k,
                       uint32_t domain_id,
                       const dna_domain_manifest_t *tgt,
                       const uint8_t digest[64], uint64_t epoch) {
    memset(out, 0, sizeof(*out));
    out->msg_version = DNA_DOMRDY_MSG_VERSION;
    memcpy(out->chain_id, chain, 32);
    memcpy(out->voter_id, k->voter, 32);
    out->domain_id = domain_id;
    out->runtime_kind = tgt->runtime_kind;
    out->runtime_abi = tgt->runtime_abi;
    out->ruleset_version = tgt->ruleset_version;
    memcpy(out->ruleset_hash, tgt->ruleset_hash, 64);
    memcpy(out->proposal_digest, digest, 64);
    out->signal_epoch = epoch;
    uint8_t pre[DNA_DOMRDY_PREIMAGE_LEN];
    if (dna_domrdy_preimage(out, pre) != 0) return -1;
    size_t siglen = 0;
    if (qgp_dsa87_sign(out->signature, &siglen, pre, sizeof(pre),
                       k->sk) != 0 || siglen != DNA_DOM_SIG_LEN)
        return -1;
    return 0;
}

/* The test-only third-domain manifest (types 20/21, fabricated tuple). */
static void third_manifest(dna_domain_manifest_t *m, uint32_t id,
                           const uint8_t *types, uint16_t n_types) {
    memset(m, 0, sizeof(*m));
    m->manifest_version = 1;
    m->domain_id = id;
    memcpy(m->name, "TEST_DOMAIN", 11);
    m->name[11] = (uint8_t)('0' + (id % 10));
    m->runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    m->runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1;
    m->ruleset_version = 1;
    memset(m->ruleset_hash, 0x77 + id, 64);   /* NOT in the builtin table */
    m->tx_type_count = n_types;
    memcpy(m->tx_types, types, n_types);
    m->fee_policy = DNA_FEEPOL_GLOBAL_BURN;
    m->upgrade_authority = DNA_UPGAUTH_CHAIN_CONFIG;
    m->readiness_policy = DNA_RDYPOL_STAGED_V1;
}

int main(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture open"); OK();

    uint8_t chain[32];
    memset(chain, 0x11, 32);

    keyset_t *ks = calloc(9, sizeof(*ks));
    CHECK(ks && make_keys(ks, 9) == 0, "keygen"); OK();

    /* ── 1. genesis registry ────────────────────────────────────────── */
    uint8_t empty_root[64], root0[64], root1[64];
    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_DOMREG, empty_root) == 0, "empty");
    CHECK(nodus_witness_domreg_root(fx.w, root0) == 0, "root pre-genesis");
    CHECK(memcmp(root0, empty_root, 64) == 0,
          "pre-genesis root != frozen empty"); OK();

    CHECK(nodus_witness_domreg_init_genesis(fx.w) == 0, "init genesis");
    OK();
    CHECK(nodus_witness_domreg_init_genesis(fx.w) == 0,
          "genesis re-init not idempotent"); OK();

    CHECK(nodus_witness_domreg_root(fx.w, root1) == 0, "root post-genesis");
    CHECK(memcmp(root1, empty_root, 64) != 0, "genesis root == empty"); OK();

    dna_domreg_record_t rec;
    dna_domain_manifest_t man;
    CHECK(nodus_witness_domreg_get(fx.w, DNA_DOMAIN_SYSTEM, &rec, &man,
                                   NULL) == 0, "get SYSTEM"); OK();
    CHECK(rec.status == DNA_DOMST_ACTIVE, "SYSTEM not ACTIVE"); OK();
    size_t nrt = 0;
    const nodus_domain_runtime_t *rt_tab = nodus_runtime_builtin_table(&nrt);
    CHECK(memcmp(man.ruleset_hash, rt_tab[0].ruleset_hash, 64) == 0,
          "SYSTEM manifest hash != runtime table"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, DNA_DOMAIN_CORE, &rec, &man,
                                   NULL) == 0, "get CORE"); OK();
    /* S9 W4: CORE owns {1,2,3,11,12,13} — the genesis manifest copies the
     * runtime descriptor verbatim (nodus_witness_domreg.c), so this count
     * tracks the descriptor. 12/13 are OWNED but REJECT-unconditional. */
    CHECK(man.tx_type_count == 6 && man.tx_types[3] == 11 &&
          man.tx_types[4] == 12 && man.tx_types[5] == 13,
          "CORE ownership drifted"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 99, &rec, NULL, NULL) == 1,
          "phantom domain found"); OK();

    /* close/reopen identity */
    CHECK(fx_reopen(&fx) == 0, "reopen 1");
    uint8_t root1b[64];
    CHECK(nodus_witness_domreg_root(fx.w, root1b) == 0, "root reopen");
    CHECK(memcmp(root1, root1b, 64) == 0, "reopen root diverged"); OK();

    /* ── 2. registration ────────────────────────────────────────────── */
    static const uint8_t T7[2] = { 20, 21 };
    static const uint8_t T8[1] = { 30 };
    dna_domain_manifest_t m7, m8;
    third_manifest(&m7, 7, T7, 2);
    third_manifest(&m8, 8, T8, 1);

    CHECK(nodus_witness_domreg_op_register(fx.w, &m7) == 0, "register 7");
    OK();
    CHECK(nodus_witness_domreg_op_register(fx.w, &m7) != 0,
          "duplicate id registered"); OK();

    dna_domain_manifest_t mbad;
    static const uint8_t TBAD[1] = { 1 };       /* owned by DNA_CORE      */
    third_manifest(&mbad, 9, TBAD, 1);
    CHECK(nodus_witness_domreg_op_register(fx.w, &mbad) != 0,
          "ownership collision registered"); OK();

    CHECK(nodus_witness_domreg_op_register(fx.w, &m8) == 0, "register 8");
    OK();

    /* ── 3. readiness replay axes (domain 7, N=7, epoch ep(10)) ─────── */
    CHECK(nodus_witness_domreg_op_propose(fx.w, chain, 7, NULL, 1, ep(10))
          == 0, "propose 7"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 7, &rec, &man, NULL) == 0, "get 7");
    uint8_t dig7[64];
    memcpy(dig7, rec.proposal_digest, 64);

    dna_vset_snapshot_t *snap7 = make_snapshot(ks, 7, ep(10));
    CHECK(snap7 != NULL, "snap7");

    dna_readiness_signal_t sig;
    /* correct signal counts once */
    CHECK(hand_signal(&sig, chain, &ks[0], 7, &man, dig7, ep(10)) == 0,
          "sig build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap7) == 0,
          "signal 0 rejected"); OK();
    uint32_t cnt = 0;
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig7, snap7, &cnt)
          == 0 && cnt == 1, "count != 1"); OK();

    /* identical duplicate: no-op, count still 1 */
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap7) == 0,
          "identical dup rejected"); OK();
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig7, snap7, &cnt)
          == 0 && cnt == 1, "dup increased count"); OK();

    /* conflicting different signal, same key: first-wins (-2) */
    dna_readiness_signal_t sig2;
    CHECK(hand_signal(&sig2, chain, &ks[0], 7, &man, dig7, ep(10)) == 0,
          "sig2 build");
    if (memcmp(sig2.signature, sig.signature, DNA_DOM_SIG_LEN) != 0) {
        CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7)
              == -2, "conflicting dup not -2"); OK();
        CHECK(nodus_witness_domreg_readiness_count(fx.w, dig7, snap7, &cnt)
              == 0 && cnt == 1, "conflict increased count"); OK();
    }

    /* wrong chain */
    uint8_t chain2[32];
    memcpy(chain2, chain, 32); chain2[0] ^= 1;
    CHECK(hand_signal(&sig2, chain2, &ks[1], 7, &man, dig7, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "wrong chain accepted"); OK();
    /* wrong domain (8 has no proposal) */
    CHECK(hand_signal(&sig2, chain, &ks[1], 8, &man, dig7, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "wrong domain accepted"); OK();
    /* wrong ruleset version */
    dna_domain_manifest_t mwrong = man;
    mwrong.ruleset_version = 9;
    CHECK(hand_signal(&sig2, chain, &ks[1], 7, &mwrong, dig7, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "wrong rsver accepted"); OK();
    /* one-bit ruleset hash */
    mwrong = man; mwrong.ruleset_hash[5] ^= 0x04;
    CHECK(hand_signal(&sig2, chain, &ks[1], 7, &mwrong, dig7, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "flipped hash accepted"); OK();
    /* wrong proposal digest */
    uint8_t digx[64];
    memcpy(digx, dig7, 64); digx[0] ^= 1;
    CHECK(hand_signal(&sig2, chain, &ks[1], 7, &man, digx, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "wrong proposal accepted"); OK();
    /* wrong epoch (freshness) */
    CHECK(hand_signal(&sig2, chain, &ks[1], 7, &man, dig7, ep(11)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "stale epoch accepted"); OK();
    /* non-member voter (ks[7] not in snap7) */
    CHECK(hand_signal(&sig2, chain, &ks[7], 7, &man, dig7, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "non-member accepted"); OK();
    /* forged signature: ks[1]'s fields signed with ks[2]'s key */
    CHECK(hand_signal(&sig2, chain, &ks[2], 7, &man, dig7, ep(10)) == 0,
          "build");
    memcpy(sig2.voter_id, ks[1].voter, 32);
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig2, snap7) != 0,
          "forged signature accepted"); OK();
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig7, snap7, &cnt)
          == 0 && cnt == 1, "reject axis leaked into count"); OK();

    /* ── 4. quorum arithmetic ───────────────────────────────────────── */
    /* bring domain 7 to 4 signals: quorum(7)=5 must fail */
    for (int i = 1; i < 4; i++) {
        CHECK(hand_signal(&sig, chain, &ks[i], 7, &man, dig7, ep(10)) == 0,
              "build");
        CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap7) == 0,
              "signal add");
    }
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig7, snap7, &cnt)
          == 0 && cnt == 4, "count != 4"); OK();
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 7, dig7, ep(10), ep(12),
                                           snap7) != 0,
          "scheduled below quorum"); OK();

    /* 5th signal → schedule succeeds; epoch pins checked */
    CHECK(hand_signal(&sig, chain, &ks[4], 7, &man, dig7, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap7) == 0,
          "signal 5");
    /* activation before the deadline must reject */
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 7, dig7, ep(10),
                                           ep(11), snap7) != 0,
          "activation before deadline accepted"); OK();
    /* non-multiple epochs reject */
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 7, dig7, ep(10) + 1,
                                           ep(12), snap7) != 0,
          "non-boundary sched accepted"); OK();
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 7, dig7, ep(10), ep(12),
                                           snap7) == 0,
          "quorum schedule failed"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 7, &rec, NULL, NULL) == 0, "get");
    CHECK(rec.status == DNA_DOMST_SCHEDULED, "not SCHEDULED"); OK();
    CHECK(rec.readiness_deadline_epoch == ep(10) + 2 * E,
          "deadline != sched + 2E"); OK();
    CHECK(rec.scheduled_activation_epoch == ep(12), "activation pin"); OK();
    /* double-schedule rejects */
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 7, dig7, ep(10), ep(13),
                                           snap7) != 0,
          "double schedule accepted"); OK();

    /* N=9 arithmetic on domain 8: quorum(9) = 7 */
    CHECK(nodus_witness_domreg_op_propose(fx.w, chain, 8, NULL, 1, ep(10))
          == 0, "propose 8"); OK();
    dna_domain_manifest_t man8;
    CHECK(nodus_witness_domreg_get(fx.w, 8, &rec, &man8, NULL) == 0, "get");
    uint8_t dig8[64];
    memcpy(dig8, rec.proposal_digest, 64);
    dna_vset_snapshot_t *snap9 = make_snapshot(ks, 9, ep(10));
    CHECK(snap9 != NULL, "snap9");
    for (int i = 0; i < 6; i++) {
        CHECK(hand_signal(&sig, chain, &ks[i], 8, &man8, dig8, ep(10)) == 0,
              "build");
        CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap9) == 0,
              "signal add 8");
    }
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 8, dig8, ep(10), ep(30),
                                           snap9) != 0,
          "N=9 scheduled at 6"); OK();
    CHECK(hand_signal(&sig, chain, &ks[6], 8, &man8, dig8, ep(10)) == 0,
          "build");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap9) == 0,
          "signal 7 of 9");
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig8, snap9, &cnt)
          == 0 && cnt == 7, "N=9 count"); OK();
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 8, dig8, ep(10), ep(30),
                                           snap9) == 0,
          "N=9 quorum schedule failed"); OK();
    /* membership churn: count against a snapshot missing ks[0..1] */
    dna_vset_snapshot_t *snap9b = make_snapshot(ks + 2, 7, ep(11));
    CHECK(snap9b != NULL, "snap9b");
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig8, snap9b, &cnt)
          == 0 && cnt == 5, "churn recount wrong"); OK();
    dna_vset_free(&snap9b);

    /* ── 5. boundary: postpone / separation / activate (domain 7) ───── */
    dna_vset_snapshot_t *now12 = make_snapshot(ks, 7, ep(12));
    dna_vset_snapshot_t *prev11 = make_snapshot(ks, 7, ep(11));
    CHECK(now12 && prev11, "snaps");

    /* snapshot-authority pin: wrong epochs reject */
    CHECK(nodus_witness_domreg_on_boundary(fx.w, ep(12), prev11, now12,
                                           NULL, NULL) != 0,
          "authority pin missing"); OK();

    /* 5/7 ready = quorum but NOT all-active → postpone */
    uint32_t acted = 0, post = 0;
    CHECK(nodus_witness_domreg_on_boundary(fx.w, ep(12), now12, prev11,
                                           &acted, &post) == 0, "bnd 12");
    CHECK(acted == 0 && post >= 1, "quorum activated (must postpone)"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 7, &rec, NULL, NULL) == 0, "get");
    CHECK(rec.scheduled_activation_epoch == ep(13) &&
          rec.postpone_count == 1 &&
          rec.status == DNA_DOMST_SCHEDULED,
          "postpone arithmetic wrong"); OK();

    /* complete readiness (6th, 7th signals) at epoch 13 */
    dna_vset_snapshot_t *snap13 = make_snapshot(ks, 7, ep(13));
    CHECK(snap13 != NULL, "snap13");
    CHECK(nodus_witness_domreg_get(fx.w, 7, NULL, &man, NULL) == 0, "get");
    for (int i = 5; i < 7; i++) {
        CHECK(hand_signal(&sig, chain, &ks[i], 7, &man, dig7, ep(13)) == 0,
              "build");
        CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap13)
              == 0, "late signal");
    }
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig7, snap13, &cnt)
          == 0 && cnt == 7, "not all ready"); OK();

    /* all-ready BUT membership changed on the boundary → postpone
     * (Stage D separation): snap_now drops ks[6], adds nobody */
    dna_vset_snapshot_t *now13_churn = make_snapshot(ks, 6, ep(13));
    dna_vset_snapshot_t *prev12 = make_snapshot(ks, 7, ep(12));
    CHECK(now13_churn && prev12, "snaps");
    CHECK(nodus_witness_domreg_on_boundary(fx.w, ep(13), now13_churn,
                                           prev12, &acted, &post) == 0,
          "bnd 13 churn");
    CHECK(acted == 0 && post >= 1, "activated across set change"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 7, &rec, NULL, NULL) == 0, "get");
    CHECK(rec.scheduled_activation_epoch == ep(14) &&
          rec.postpone_count == 2, "second postpone wrong"); OK();

    /* all-ready + same membership → ACTIVATE */
    dna_vset_snapshot_t *now14 = make_snapshot(ks, 7, ep(14));
    dna_vset_snapshot_t *prev13 = make_snapshot(ks, 7, ep(13));
    CHECK(now14 && prev13, "snaps");
    CHECK(nodus_witness_domreg_on_boundary(fx.w, ep(14), now14, prev13,
                                           &acted, &post) == 0, "bnd 14");
    CHECK(acted >= 1, "did not activate"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 7, &rec, NULL, NULL) == 0, "get");
    CHECK(rec.status == DNA_DOMST_ACTIVE &&
          rec.proposal_present == 0 &&
          rec.scheduled_activation_epoch == 0 &&
          rec.postpone_count == 0, "activation did not clear state"); OK();
    /* its readiness signals are gone */
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig7, snap13, &cnt)
          == 0 && cnt == 0, "signals survived activation"); OK();

    /* ── 6. upgrade path on DNA_CORE ────────────────────────────────── */
    dna_domain_manifest_t core_cur, core_new;
    CHECK(nodus_witness_domreg_get(fx.w, DNA_DOMAIN_CORE, &rec, &core_cur,
                                   NULL) == 0, "get CORE");
    core_new = core_cur;
    core_new.quota_tx_per_block = 5;     /* same tuple, different content  */
    core_new.quota_verify_cost = 10;     /* exercised by the admission     */
    CHECK(nodus_witness_domreg_op_propose(fx.w, chain, DNA_DOMAIN_CORE,
                                          &core_new, 2, ep(20)) == 0,
          "propose CORE upgrade"); OK();
    /* build_signal PASSES the local gate (tuple is in the builtin table) */
    dna_readiness_signal_t bsig;
    CHECK(nodus_witness_domreg_build_signal(fx.w, chain, DNA_DOMAIN_CORE,
                                            ep(20), ks[0].voter, ks[0].sk,
                                            &bsig) == 0,
          "local gate refused a supported tuple"); OK();
    dna_vset_snapshot_t *snap20 = make_snapshot(ks, 7, ep(20));
    CHECK(snap20 != NULL, "snap20");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &bsig, snap20) == 0,
          "built signal rejected"); OK();

    /* an ABSENT tuple must be refused by the local gate: cancel, then
     * re-propose with ruleset_version 3 (not compiled in — the burn
     * season made v2 the compiled CORE version) */
    CHECK(nodus_witness_domreg_get(fx.w, DNA_DOMAIN_CORE, &rec, NULL, NULL)
          == 0, "get");
    uint8_t digc[64];
    memcpy(digc, rec.proposal_digest, 64);
    CHECK(nodus_witness_domreg_op_cancel(fx.w, DNA_DOMAIN_CORE, digc) == 0,
          "cancel CORE"); OK();
    dna_domain_manifest_t core_v2 = core_cur;
    core_v2.ruleset_version = 3;
    core_v2.quota_verify_cost = 9;
    CHECK(nodus_witness_domreg_op_propose(fx.w, chain, DNA_DOMAIN_CORE,
                                          &core_v2, 3, ep(20)) == 0,
          "propose v2"); OK();
    CHECK(nodus_witness_domreg_build_signal(fx.w, chain, DNA_DOMAIN_CORE,
                                            ep(20), ks[0].voter, ks[0].sk,
                                            &bsig) != 0,
          "local gate passed an ABSENT tuple"); OK();

    /* drive the v2-upgrade to activation is impossible honestly (no local
     * runtime) — cancel it and re-run the SUPPORTED upgrade end-to-end. */
    CHECK(nodus_witness_domreg_get(fx.w, DNA_DOMAIN_CORE, &rec, NULL, NULL)
          == 0, "get");
    memcpy(digc, rec.proposal_digest, 64);
    CHECK(nodus_witness_domreg_op_cancel(fx.w, DNA_DOMAIN_CORE, digc) == 0,
          "cancel v2"); OK();
    CHECK(nodus_witness_domreg_op_propose(fx.w, chain, DNA_DOMAIN_CORE,
                                          &core_new, 4, ep(20)) == 0,
          "re-propose supported upgrade"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, DNA_DOMAIN_CORE, &rec, NULL, NULL)
          == 0, "get");
    memcpy(digc, rec.proposal_digest, 64);
    uint8_t new_hash[64];
    CHECK(dna_domman_hash(&core_new, new_hash) == 0, "hash new");
    CHECK(memcmp(rec.pending_manifest_hash, new_hash, 64) == 0,
          "pending hash wrong"); OK();

    for (int i = 0; i < 7; i++) {
        CHECK(hand_signal(&sig, chain, &ks[i], DNA_DOMAIN_CORE, &core_new,
                          digc, ep(20)) == 0, "build");
        CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap20)
              == 0, "upgrade signal");
    }
    CHECK(nodus_witness_domreg_op_schedule(fx.w, DNA_DOMAIN_CORE, digc,
                                           ep(20), ep(22), snap20) == 0,
          "schedule upgrade"); OK();
    dna_vset_snapshot_t *now22 = make_snapshot(ks, 7, ep(22));
    dna_vset_snapshot_t *prev21 = make_snapshot(ks, 7, ep(21));
    CHECK(now22 && prev21, "snaps");
    CHECK(nodus_witness_domreg_on_boundary(fx.w, ep(22), now22, prev21,
                                           &acted, &post) == 0, "bnd 22");
    CHECK(acted == 1, "upgrade did not activate"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, DNA_DOMAIN_CORE, &rec, &man, NULL)
          == 0, "get");
    CHECK(memcmp(rec.current_manifest_hash, new_hash, 64) == 0,
          "pending not promoted"); OK();
    CHECK(man.quota_tx_per_block == 5 && rec.pending_present == 0 &&
          rec.status == DNA_DOMST_ACTIVE, "promoted manifest wrong"); OK();

    /* ── 7. cancellation kills old signals (domain 8 still SCHEDULED) ─ */
    CHECK(nodus_witness_domreg_op_cancel(fx.w, 8, dig8) == 0, "cancel 8");
    OK();
    CHECK(nodus_witness_domreg_get(fx.w, 8, &rec, &man8, NULL) == 0, "get");
    CHECK(rec.status == DNA_DOMST_REGISTERED && rec.proposal_present == 0 &&
          rec.scheduled_activation_epoch == 0, "cancel left state"); OK();
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig8, snap9, &cnt)
          == 0 && cnt == 0, "cancel left signals"); OK();
    /* re-propose (new nonce) → an OLD-digest signal must reject */
    CHECK(nodus_witness_domreg_op_propose(fx.w, chain, 8, NULL, 99, ep(10))
          == 0, "re-propose 8"); OK();
    CHECK(hand_signal(&sig, chain, &ks[0], 8, &man8, dig8, ep(10)) == 0,
          "build old-digest");
    CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap9) != 0,
          "cancelled-proposal signal accepted"); OK();

    /* ── 8. Stage C exclusions (domain 8's NEW proposal) ────────────── */
    CHECK(nodus_witness_domreg_get(fx.w, 8, &rec, &man8, NULL) == 0, "get");
    memcpy(dig8, rec.proposal_digest, 64);
    for (int i = 0; i < 7; i++) {       /* 7 of 9 sign — ks[7], ks[8] not */
        CHECK(hand_signal(&sig, chain, &ks[i], 8, &man8, dig8, ep(10)) == 0,
              "build");
        CHECK(nodus_witness_domreg_op_signal(fx.w, chain, &sig, snap9) == 0,
              "sig add");
    }
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 8, dig8, ep(10), ep(30),
                                           snap9) == 0, "schedule 8"); OK();

    uint8_t excl[16][32];
    size_t n_excl = 0;
    /* deadline = ep(12); candidate = all 9 → ks[7], ks[8] unready */
    CHECK(nodus_witness_domreg_exclusions_at(fx.w, ep(12), snap9, 7,
                                             excl, 16, &n_excl) == 0,
          "exclusions"); OK();
    CHECK(n_excl == 2 &&
          memcmp(excl[0], ks[7].voter, 32) == 0 &&
          memcmp(excl[1], ks[8].voter, 32) == 0,
          "exclusion list wrong"); OK();
    /* floor guard: min 8 would leave 7 < 8 → no exclusion, rc 2 */
    CHECK(nodus_witness_domreg_exclusions_at(fx.w, ep(12), snap9, 8,
                                             excl, 16, &n_excl) == 2 &&
          n_excl == 0, "floor guard failed"); OK();

    /* filter: order preserved, bonds untouched, DB untouched */
    uint8_t reg_before[64];
    CHECK(nodus_witness_domreg_root(fx.w, reg_before) == 0, "root");
    CHECK(nodus_witness_domreg_exclusions_at(fx.w, ep(12), snap9, 7,
                                             excl, 16, &n_excl) == 0, "ex");
    dna_vset_snapshot_t *filtered =
        nodus_witness_domreg_filter_snapshot(
            snap9, (const uint8_t (*)[32])excl, n_excl);
    CHECK(filtered != NULL && filtered->active_count == 7, "filter"); OK();
    for (int i = 0; i < 7; i++) {
        CHECK(memcmp(filtered->entries[i].voter_id, ks[i].voter, 32) == 0,
              "filter order broken");
        CHECK(filtered->entries[i].self_bond ==
              snap9->entries[i].self_bond,
              "filter touched a bond (slashing?!)");
    }
    OK();
    uint8_t reg_after[64];
    CHECK(nodus_witness_domreg_root(fx.w, reg_after) == 0, "root");
    CHECK(memcmp(reg_before, reg_after, 64) == 0,
          "exclusion computation mutated registry state"); OK();
    dna_vset_free(&filtered);

    /* ── 9. restart mid-stage reconstructs identical state ──────────── */
    uint8_t r_before[64];
    CHECK(nodus_witness_domreg_root(fx.w, r_before) == 0, "root");
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig8, snap9, &cnt)
          == 0 && cnt == 7, "pre-restart count");
    CHECK(fx_reopen(&fx) == 0, "reopen mid-stage");
    uint8_t r_after[64];
    CHECK(nodus_witness_domreg_root(fx.w, r_after) == 0, "root");
    CHECK(memcmp(r_before, r_after, 64) == 0, "restart root diverged"); OK();
    CHECK(nodus_witness_domreg_readiness_count(fx.w, dig8, snap9, &cnt)
          == 0 && cnt == 7, "restart lost signals"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 8, &rec, NULL, NULL) == 0, "get");
    CHECK(rec.status == DNA_DOMST_SCHEDULED &&
          rec.scheduled_activation_epoch == ep(30),
          "restart lost scheduler state"); OK();

    /* ── 10. invalid transitions leave the record byte-unchanged ────── */
    uint8_t before[DNA_DOMREG_REC_ENC_LEN], after[DNA_DOMREG_REC_ENC_LEN];
    CHECK(record_blob(fx.w, 8, before) == 0, "blob");
    /* wrong-digest schedule */
    CHECK(nodus_witness_domreg_op_schedule(fx.w, 8, digx, ep(12), ep(14),
                                           snap9) != 0, "bad sched"); OK();
    /* wrong-digest cancel */
    CHECK(nodus_witness_domreg_op_cancel(fx.w, 8, digx) != 0, "bad cancel");
    OK();
    /* pause with a live proposal */
    CHECK(nodus_witness_domreg_op_pause(fx.w, 8) != 0, "pause w/ proposal");
    OK();
    /* propose while SCHEDULED */
    CHECK(nodus_witness_domreg_op_propose(fx.w, chain, 8, NULL, 100,
                                          ep(11)) != 0,
          "propose on SCHEDULED"); OK();
    CHECK(record_blob(fx.w, 8, after) == 0, "blob");
    CHECK(memcmp(before, after, sizeof(before)) == 0,
          "failed op mutated the record"); OK();

    /* ── 11. V2 semantic admission routing (INACTIVE layer) ─────────── */
    dna_exec_context_t ctx;
    uint32_t cost = 0;

    /* correct: SPEND (type 1) in ACTIVE DNA_CORE, pool 0, ruleset 2
     * (burn season: CORE ruleset v2) */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE, DNA_POOL_NONE,
                                1, 3, 2, 0) == 0, "ctx init");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, &cost)
          == 0 && cost == 1, "SPEND admission failed"); OK();
    /* the RETIRED CORE ruleset v1 no longer admits anything */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE, DNA_POOL_NONE,
                                1, 3, 1, 0) == 0, "ctx init");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "retired CORE ruleset v1 admitted"); OK();
    /* SYSTEM STAKE admits (SYSTEM is ruleset v2 since the capacity
     * season; a v1 SYSTEM context resolves nothing — pinned below) */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_SYSTEM,
                                DNA_POOL_NONE, 4, 3, 2, 0) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          == 0, "STAKE admission failed"); OK();
    /* the RETIRED SYSTEM ruleset v1 no longer admits anything */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_SYSTEM,
                                DNA_POOL_NONE, 4, 3, 1, 0) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "retired SYSTEM ruleset v1 admitted"); OK();

    /* wrong chain */
    CHECK(dna_exec_context_init(&ctx, chain2, DNA_DOMAIN_CORE,
                                DNA_POOL_NONE, 1, 3, 2, 0) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "wrong chain admitted"); OK();
    /* wrong domain/type combination (SPEND routed to SYSTEM) */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_SYSTEM,
                                DNA_POOL_NONE, 1, 3, 2, 0) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "cross-domain type admitted"); OK();
    /* unknown domain */
    CHECK(dna_exec_context_init(&ctx, chain, 42, DNA_POOL_NONE, 1, 3, 1, 0)
          == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "unknown domain admitted"); OK();

    /* TYPE 11 stays rejected — the C3 hard stop through the V2 boundary */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE,
                                DNAC_SHIELDED_POOL_V1, 11, 3, 2, 0) == 0,
          "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "TYPE 11 ADMITTED — C3 stop broken"); OK();
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE,
                                DNA_POOL_NONE, 11, 3, 2, 0) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "TYPE 11 (pool 0) ADMITTED"); OK();
    /* types 12/13/14 remain unavailable */
    for (uint8_t t = 12; t <= 14; t++) {
        CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE,
                                    DNA_POOL_NONE, t, 3, 2, 0) == 0, "ctx");
        CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
              != 0, "reserved type admitted");
    }
    OK();

    /* ruleset_version mismatch (a FUTURE version — v2 is committed) */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE,
                                DNA_POOL_NONE, 1, 3, 3, 0) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "wrong ruleset admitted"); OK();
    /* statement_version nonzero on a transparent type */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE,
                                DNA_POOL_NONE, 1, 3, 2, 7) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "ghost statement admitted"); OK();
    /* illegal pool on a transparent type */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE,
                                DNAC_SHIELDED_POOL_V1, 1, 3, 2, 0) == 0,
          "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "pooled SPEND admitted"); OK();

    /* quotas: CORE's upgraded manifest pins tx/block = 5, cost = 10 */
    CHECK(dna_exec_context_init(&ctx, chain, DNA_DOMAIN_CORE,
                                DNA_POOL_NONE, 1, 3, 2, 0) == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 4, 0, NULL)
          == 0, "under-quota rejected"); OK();
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 5, 0, NULL)
          != 0, "tx quota exceeded but admitted"); OK();
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 9, NULL)
          == 0, "cost 9+1 <= 10 rejected"); OK();
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 10, NULL)
          != 0, "cost quota exceeded but admitted"); OK();
    /* used_tx_count WRAPAROUND matrix (execution-season fix): the old
     * `used + 1 > quota` predicate wrapped at UINT32_MAX (used+1 == 0)
     * and admitted past a full quota. The predicate is now `used >=
     * quota` — same meaning everywhere in range, no wrap at the top.
     * Admission is read-only, so byte-identical state is proven by
     * digesting the registry around the calls. */
    {
        uint8_t d0[64], d1[64];
        CHECK(nodus_witness_domreg_root(fx.w, d0) == 0, "digest");
        CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx,
                                            UINT32_MAX - 1, 0, NULL)
              != 0, "UINT32_MAX-1 over a quota of 5 admitted"); OK();
        CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx,
                                            UINT32_MAX, 0, NULL)
              != 0, "UINT32_MAX wrapped past the quota"); OK();
        CHECK(nodus_witness_domreg_root(fx.w, d1) == 0 &&
              memcmp(d0, d1, 64) == 0,
              "admission rejection mutated state"); OK();
    }

    /* paused domain rejects its transactions */
    CHECK(nodus_witness_domreg_op_pause(fx.w, DNA_DOMAIN_CORE) == 0,
          "pause CORE");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "PAUSED domain admitted"); OK();
    CHECK(nodus_witness_domreg_op_resume(fx.w, DNA_DOMAIN_CORE) == 0,
          "resume CORE");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          == 0, "resume did not restore admission"); OK();

    /* an ACTIVE domain whose runtime is NOT locally compiled admits
     * nothing (domain 7's fabricated tuple) — missing runtime can
     * neither signal, activate, nor execute */
    CHECK(dna_exec_context_init(&ctx, chain, 7, DNA_POOL_NONE, 20, 3, 1, 0)
          == 0, "ctx");
    CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0, NULL)
          != 0, "runtime-less domain admitted"); OK();

    /* pause/resume/retire happy path on domain 7 (now ACTIVE, no prop) */
    CHECK(nodus_witness_domreg_op_pause(fx.w, 7) == 0, "pause 7"); OK();
    CHECK(nodus_witness_domreg_get(fx.w, 7, &rec, NULL, NULL) == 0, "get");
    CHECK(rec.status == DNA_DOMST_PAUSED, "not paused"); OK();
    CHECK(nodus_witness_domreg_op_resume(fx.w, 7) == 0, "resume 7"); OK();
    CHECK(nodus_witness_domreg_op_retire(fx.w, 7) == 0, "retire 7"); OK();
    CHECK(nodus_witness_domreg_op_retire(fx.w, 7) != 0, "retire twice");
    OK();

    /* ── 12. cross-node determinism: a SECOND independently initialized
     * node running the same op sequence lands on byte-identical registry,
     * SYSTEM and global roots ─────────────────────────────────────────── */
    fixture_t fx2;
    CHECK(fx_open(&fx2) == 0, "fixture 2 open"); OK();
    CHECK(nodus_witness_domreg_init_genesis(fx2.w) == 0, "init 2");

    fixture_t fx3;   /* third node — same sequence, fresh dir again */
    CHECK(fx_open(&fx3) == 0, "fixture 3 open");
    CHECK(nodus_witness_domreg_init_genesis(fx3.w) == 0, "init 3");

    uint8_t ra[64], rb[64];
    CHECK(nodus_witness_domreg_root(fx2.w, ra) == 0, "root 2");
    CHECK(nodus_witness_domreg_root(fx3.w, rb) == 0, "root 3");
    CHECK(memcmp(ra, rb, 64) == 0, "genesis registry roots diverge"); OK();

    /* same follow-up ops on both nodes */
    dna_domain_manifest_t md;
    third_manifest(&md, 7, T7, 2);
    CHECK(nodus_witness_domreg_op_register(fx2.w, &md) == 0, "reg 2");
    CHECK(nodus_witness_domreg_op_register(fx3.w, &md) == 0, "reg 3");
    CHECK(nodus_witness_domreg_op_propose(fx2.w, chain, 7, NULL, 5, ep(10))
          == 0, "prop 2");
    CHECK(nodus_witness_domreg_op_propose(fx3.w, chain, 7, NULL, 5, ep(10))
          == 0, "prop 3");
    CHECK(nodus_witness_domreg_root(fx2.w, ra) == 0, "root 2b");
    CHECK(nodus_witness_domreg_root(fx3.w, rb) == 0, "root 3b");
    CHECK(memcmp(ra, rb, 64) == 0, "post-op registry roots diverge"); OK();

    /* the registry leg propagates identically into SYSTEM + global roots */
    uint8_t g2[64], g3[64], s2[64], s3[64];
    CHECK(nodus_witness_global_root_v2(fx2.w, g2, NULL, s2, NULL) == 0,
          "global 2"); OK();
    CHECK(nodus_witness_global_root_v2(fx3.w, g3, NULL, s3, NULL) == 0,
          "global 3");
    CHECK(memcmp(s2, s3, 64) == 0, "system roots diverge"); OK();
    CHECK(memcmp(g2, g3, 64) == 0, "global roots diverge"); OK();

    /* and the registry leg actually CHANGES the system root vs empty:
     * a fresh node WITHOUT genesis init keeps the placeholder root */
    fixture_t fx4;
    CHECK(fx_open(&fx4) == 0, "fixture 4 open");
    uint8_t s4r[64], g4r[64];
    CHECK(nodus_witness_global_root_v2(fx4.w, g4r, NULL, s4r, NULL) == 0,
          "system 4");
    CHECK(memcmp(s4r, s2, 64) != 0,
          "registry leg inert in system root"); OK();
    fx_close(&fx4);
    fx_close(&fx3);
    fx_close(&fx2);

    dna_vset_free(&snap7);
    dna_vset_free(&snap9);
    dna_vset_free(&now12);
    dna_vset_free(&prev11);
    dna_vset_free(&snap13);
    dna_vset_free(&now13_churn);
    dna_vset_free(&prev12);
    dna_vset_free(&now14);
    dna_vset_free(&prev13);
    dna_vset_free(&snap20);
    dna_vset_free(&now22);
    dna_vset_free(&prev21);
    free(ks);
    fx_close(&fx);
    printf("test_domreg: ALL %d checks passed\n", g_checks);
    return 0;
}
