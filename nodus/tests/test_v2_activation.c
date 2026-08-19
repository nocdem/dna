/**
 * @file tests/test_v2_activation.c
 * @brief Ledger V2 O15C — committed activation authority: codecs,
 *        digests, schema v10, type-15/16 apply, the boundary state
 *        machine, terminal refusal, Stage C, the attendance writer and
 *        state_root v4.
 *
 * Runs in BOTH build variants: the module functions under test are
 * always compiled; only their production call sites are
 * NODUS_V2_ACTIVATION_AUTHORITY-gated (asserted by the flag-ON ctest
 * run of this same binary plus the O15C rehearsal).
 */

#define _DEFAULT_SOURCE   /* mkdtemp under -std=c11 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_activation.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_merkle.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "dnac/activation_wire.h"
#include "dnac/tx_wire.h"
#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                msg); \
        g_fail = 1; \
    } } while (0)
#define OK() do { if (g_fail) return 1; } while (0)

#define E ((uint64_t)DNAC_EPOCH_LENGTH)
#define NKEYS 4

static uint8_t g_pk[NKEYS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NKEYS][QGP_DSA87_SECRETKEYBYTES];

typedef struct {
    nodus_witness_t *w;
    char dir[128];
} fx_t;

static void rmrf(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)system(cmd);
}

static int fx_open(fx_t *fx, const char *tag) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_act_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t cid16[16];
    memset(cid16, 0x5a, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    /* create_chain_db installs the chain id on the handle itself. A
     * calloc'd handle's committee cache reads as "epoch 0, 0 members" —
     * invalidate it the way the real witness init does. */
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    if (nodus_witness_db_migrate_v2s10(fx->w) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    return 0;
}

static void fx_close(fx_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/* Seed NKEYS real-key ACTIVE validators + the genesis snapshots. */
static int fx_seed_committee(fx_t *fx) {
    for (int i = 0; i < NKEYS; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_pk[i], sizeof(g_pk[i]));
        v.self_stake = 0;
        v.status = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        memset(v.unstake_destination_fp, '7',
               sizeof(v.unstake_destination_fp) - 1);
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }
    return nodus_witness_vset_commit_genesis(fx->w, 1);
}

/* ── minimal legacy tx carriers (apply-layer walk only) ─────────────── */

static size_t mk_tx_shell(uint8_t *buf, size_t cap, uint8_t type) {
    /* header(82) ‖ in 0 ‖ out 0 ‖ wit 0 ‖ signers 1 (zeroed) */
    size_t need = 82 + 1 + 1 + 1 + 1 + (2592 + 4627);
    if (cap < need) return 0;
    memset(buf, 0, need);
    buf[0] = 2;                     /* wire version */
    buf[1] = type;
    buf[82] = 0;                    /* input_count  */
    buf[83] = 0;                    /* output_count */
    buf[84] = 0;                    /* witness_count*/
    buf[85] = 1;                    /* signer_count */
    return need;
}

static int mk_tx15(uint8_t *buf, size_t cap, size_t *len_out,
                   const dna_act15_wire_t *f) {
    size_t off = mk_tx_shell(buf, cap, 15);
    if (!off) return -1;
    size_t wrote = 0;
    if (dna_act15_wire_encode(f, buf + off, cap - off, &wrote) != 0)
        return -1;
    *len_out = off + wrote;
    return 0;
}

static int mk_tx16(uint8_t *buf, size_t cap, size_t *len_out,
                   const dna_act16_wire_t *f) {
    size_t off = mk_tx_shell(buf, cap, 16);
    if (!off) return -1;
    size_t wrote = 0;
    if (dna_act16_wire_encode(f, buf + off, cap - off, &wrote) != 0)
        return -1;
    *len_out = off + wrote;
    return 0;
}

/* Quorum-signed SCHEDULE fields for `w`'s chain at commit height. */
static int mk_sched(fx_t *fx, dna_act15_wire_t *f,
                    const uint8_t target[64], uint64_t h_act,
                    uint64_t nonce, uint64_t commit_h, int votes) {
    memset(f, 0, sizeof(*f));
    f->record_version = DNA_ACT_RECORD_VERSION;
    f->op = DNA_ACT_OP_SCHEDULE;
    memcpy(f->target, target, 64);
    f->activation_height = h_act;
    f->proposal_nonce = nonce;
    f->signed_at_block = commit_h ? commit_h : 1;
    f->valid_before_block = h_act + 10 * E;
    uint8_t digest[64];
    if (dna_act_sched_digest(fx->w->chain_id, f->record_version, f->target,
                             h_act, nonce, f->signed_at_block,
                             f->valid_before_block, digest) != 0)
        return -1;
    f->vote_count = (uint8_t)votes;
    for (int i = 0; i < votes; i++) {
        if (nodus_chain_config_derive_witness_id(
                g_pk[i], f->votes[i].witness_id) != 0)
            return -1;
        size_t sl = 0;
        if (qgp_dsa87_sign(f->votes[i].signature, &sl, digest, 64,
                           g_sk[i]) != 0 || sl != DNA_ACT_SIG_LEN)
            return -1;
    }
    return 0;
}

static int mk_ready(fx_t *fx, dna_act16_wire_t *f, int key,
                    uint64_t signal_epoch) {
    nodus_v2_act_record_t rec;
    if (nodus_witness_v2_activation_get(fx->w, &rec) != 0) return -1;
    memset(f, 0, sizeof(*f));
    f->signal_version = DNA_ACT_SIGNAL_VERSION;
    memcpy(f->schedule_digest, rec.schedule_digest, 64);
    memcpy(f->target, rec.target, 64);
    if (nodus_chain_config_derive_witness_id(g_pk[key], f->voter_id) != 0)
        return -1;
    f->signal_epoch = signal_epoch;
    memcpy(f->pubkey, g_pk[key], sizeof(g_pk[key]));
    uint8_t digest[64];
    if (dna_act_ready_digest(f->signal_version, fx->w->chain_id,
                             f->schedule_digest, f->target, f->voter_id,
                             f->signal_epoch, digest) != 0)
        return -1;
    size_t sl = 0;
    if (qgp_dsa87_sign(f->signature, &sl, digest, 64, g_sk[key]) != 0 ||
        sl != DNA_ACT_SIG_LEN)
        return -1;
    return 0;
}

static int apply15(fx_t *fx, const dna_act15_wire_t *f, uint64_t h) {
    static uint8_t buf[700000];
    size_t len = 0;
    if (mk_tx15(buf, sizeof(buf), &len, f) != 0) return -99;
    return nodus_witness_v2_activation_apply(fx->w, buf, (uint32_t)len, h);
}

static int apply16(fx_t *fx, const dna_act16_wire_t *f, uint64_t h) {
    static uint8_t buf[32768];
    size_t len = 0;
    if (mk_tx16(buf, sizeof(buf), &len, f) != 0) return -99;
    return nodus_witness_v2_activation_apply_ready(fx->w, buf,
                                                   (uint32_t)len, h);
}

/* ════════════════════════════════════════════════════════════════════ */

static int test_wire(void) {
    printf("§1 wire codecs + digests\n");

    dna_act15_wire_t *a = calloc(1, sizeof(*a)), *b = calloc(1, sizeof(*b));
    CHECK(a && b, "alloc");
    a->record_version = 1;
    a->op = DNA_ACT_OP_SCHEDULE;
    memset(a->target, 0xAB, 64);
    a->activation_height = 4 * E;
    a->proposal_nonce = 7;
    a->signed_at_block = 3;
    a->valid_before_block = 99999;
    a->vote_count = 2;
    memset(a->votes[0].witness_id, 0x01, 32);
    memset(a->votes[0].signature, 0x02, DNA_ACT_SIG_LEN);
    memset(a->votes[1].witness_id, 0x03, 32);
    memset(a->votes[1].signature, 0x04, DNA_ACT_SIG_LEN);

    uint8_t buf[32768];
    size_t wrote = 0, used = 0;
    CHECK(dna_act15_wire_encoded_size(a) ==
              DNA_ACT15_WIRE_FIXED_LEN + 2u * DNA_ACT15_WIRE_PER_VOTE,
          "encoded size");
    CHECK(dna_act15_wire_encode(a, buf, sizeof(buf), &wrote) == 0, "enc");
    CHECK(dna_act15_wire_decode(buf, wrote, b, &used) == 0 &&
              used == wrote, "dec");
    CHECK(memcmp(a, b, sizeof(*a)) == 0, "type-15 round trip");
    /* truncation and over-count reject */
    CHECK(dna_act15_wire_decode(buf, wrote - 1, b, NULL) != 0, "trunc");
    CHECK(dna_act15_wire_decode(buf, DNA_ACT15_WIRE_FIXED_LEN - 1, b,
                                NULL) != 0, "short fixed");
    {
        uint8_t evil[DNA_ACT15_WIRE_FIXED_LEN];
        memcpy(evil, buf, sizeof(evil));
        evil[DNA_ACT15_WIRE_FIXED_LEN - 1] = 255;  /* count > cap */
        CHECK(dna_act15_wire_decode(evil, sizeof(evil), b, NULL) != 0,
              "count over cap");
    }
    free(a); free(b);

    dna_act16_wire_t r, r2;
    memset(&r, 0, sizeof(r));
    r.signal_version = 1;
    memset(r.schedule_digest, 0x11, 64);
    memset(r.target, 0x22, 64);
    memset(r.voter_id, 0x33, 32);
    r.signal_epoch = 3 * E;
    memset(r.pubkey, 0x44, sizeof(r.pubkey));
    memset(r.signature, 0x55, sizeof(r.signature));
    CHECK(dna_act16_wire_encode(&r, buf, sizeof(buf), &wrote) == 0 &&
              wrote == (size_t)DNA_ACT16_WIRE_LEN, "enc16");
    CHECK(dna_act16_wire_decode(buf, wrote, &r2, &used) == 0 &&
              used == wrote, "dec16");
    CHECK(memcmp(&r, &r2, sizeof(r)) == 0, "type-16 round trip");
    CHECK(dna_act16_wire_decode(buf, wrote - 1, &r2, NULL) != 0,
          "type-16 truncation rejects");

    /* Digest field sensitivity: every semantic field moves the digest. */
    uint8_t chain[32], t[64], d0[64], d1[64];
    memset(chain, 0x66, 32);
    memset(t, 0x77, 64);
    CHECK(dna_act_sched_digest(chain, 1, t, 4 * E, 7, 3, 999, d0) == 0,
          "sched digest");
    CHECK(dna_act_sched_digest(chain, 1, t, 5 * E, 7, 3, 999, d1) == 0 &&
              memcmp(d0, d1, 64) != 0, "H_act moves the digest");
    CHECK(dna_act_sched_digest(chain, 1, t, 4 * E, 8, 3, 999, d1) == 0 &&
              memcmp(d0, d1, 64) != 0, "nonce moves the digest");
    chain[0] ^= 1;
    CHECK(dna_act_sched_digest(chain, 1, t, 4 * E, 7, 3, 999, d1) == 0 &&
              memcmp(d0, d1, 64) != 0, "chain id moves the digest");
    chain[0] ^= 1;

    uint8_t v[32], rd0[64], rd1[64];
    memset(v, 0x01, 32);
    CHECK(dna_act_ready_digest(1, chain, t, t, v, E, rd0) == 0, "rdy");
    CHECK(dna_act_ready_digest(1, chain, t, t, v, 2 * E, rd1) == 0 &&
              memcmp(rd0, rd1, 64) != 0, "signal_epoch moves the digest");
    CHECK(dna_act_cancel_digest(chain, t, 7, 3, 999, d0) == 0 &&
              memcmp(d0, rd0, 64) != 0 &&
          dna_act_sched_digest(chain, 1, t, 4 * E, 7, 3, 999, d1) == 0 &&
              memcmp(d0, d1, 64) != 0,
          "cancel/schedule/ready digests are domain-separated");

    /* Terminal source commitment binds all four facts. */
    uint8_t bid[64], sr[64], sc0[168], sc1[168];
    memset(bid, 0x10, 64);
    memset(sr, 0x20, 64);
    CHECK(dna_act_source_commit(chain, bid, sr, 4 * E, sc0) == 0, "sc");
    CHECK(dna_act_source_commit(chain, bid, sr, 4 * E + 1, sc1) == 0 &&
              memcmp(sc0, sc1, 168) != 0, "height bound");
    bid[0] ^= 1;
    CHECK(dna_act_source_commit(chain, bid, sr, 4 * E, sc1) == 0 &&
              memcmp(sc0, sc1, 168) != 0, "block id bound");
    OK();
    printf("  ok: round trips, negatives, digest sensitivity\n");
    return 0;
}

static int test_target(void) {
    printf("§2 compiled target digest D\n");
    uint8_t d0[64], d1[64], zero[64];
    memset(zero, 0, 64);
    CHECK(nodus_witness_v2_activation_compiled_target(d0) == 0, "derive");
    CHECK(memcmp(d0, zero, 64) != 0, "D is never all-zero");
    CHECK(nodus_witness_v2_activation_compiled_target(d1) == 0 &&
              memcmp(d0, d1, 64) == 0, "D is deterministic");

    /* A different target tuple set yields a different D. */
    dna_act_target_rt_t rt[1];
    memset(rt, 0, sizeof(rt));
    rt[0].domain_id = 0;
    rt[0].ruleset_version = 1;
    memset(rt[0].ruleset_hash, 0x99, 64);
    CHECK(dna_act_target_digest(1, 3, 10, rt, 1, d1) == 0 &&
              memcmp(d0, d1, 64) != 0, "tuple set moves D");
    /* Unsorted / duplicate domains reject. */
    dna_act_target_rt_t bad[2];
    memset(bad, 0, sizeof(bad));
    bad[0].domain_id = 1;
    bad[1].domain_id = 0;
    CHECK(dna_act_target_digest(1, 3, 10, bad, 2, d1) != 0,
          "unsorted domains reject");
    bad[1].domain_id = 1;
    CHECK(dna_act_target_digest(1, 3, 10, bad, 2, d1) != 0,
          "duplicate domains reject");
    OK();
    printf("  ok: nonzero, deterministic, tuple-sensitive\n");
    return 0;
}

static int test_schema(void) {
    printf("§3 schema v10\n");
    fx_t f = {0};
    /* fx_open migrates to v10 already — prove idempotency + shape. */
    CHECK(fx_open(&f, "sch") == 0, "open");
    uint32_t ver = 0;
    CHECK(nodus_witness_db_schema_version(f.w, &ver) == 0 && ver == 10,
          "user_version is 10");
    CHECK(nodus_witness_db_migrate_v2s10(f.w) == 0, "idempotent re-run");

    /* Unknown newer version fails closed. */
    CHECK(sqlite3_exec(f.w->db, "PRAGMA user_version = 11", NULL, NULL,
                       NULL) == SQLITE_OK, "poke 11");
    CHECK(nodus_witness_db_migrate_v2s10(f.w) != 0, "v11 refuses");
    CHECK(sqlite3_exec(f.w->db, "PRAGMA user_version = 10", NULL, NULL,
                       NULL) == SQLITE_OK, "restore");
    fx_close(&f);

    /* Fault stages leave a VALID version-9 database. */
    fx_t g = {0};
    g.w = calloc(1, sizeof(*g.w));
    CHECK(g.w != NULL, "alloc");
    snprintf(g.dir, sizeof(g.dir), "/tmp/test_v2_act_mig_XXXXXX");
    CHECK(mkdtemp(g.dir) != NULL, "mkdtemp");
    snprintf(g.w->data_path, sizeof(g.w->data_path), "%s", g.dir);
    uint8_t cid[16];
    memset(cid, 0x5b, 16);
    CHECK(nodus_witness_create_chain_db(g.w, cid) == 0, "create");
    CHECK(nodus_witness_db_migrate_v2s9(g.w) == 0, "to v9");
    static const nodus_v2s10_mig_fail_t stages[] = {
        V2S10MIG_FAIL_AFTER_BEGIN, V2S10MIG_FAIL_AFTER_REVALIDATE,
        V2S10MIG_FAIL_AFTER_TABLES, V2S10MIG_FAIL_AFTER_VERIFY,
        V2S10MIG_FAIL_BEFORE_COMMIT
    };
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        CHECK(nodus_witness_db_migrate_v2s10_ex(g.w, stages[i]) == -1,
              "injected stage aborts");
        uint32_t v9 = 0;
        CHECK(nodus_witness_db_schema_version(g.w, &v9) == 0 && v9 == 9,
              "rollback leaves version 9");
    }
    CHECK(nodus_witness_db_migrate_v2s10(g.w) == 0, "clean run lands 10");
    fx_close(&g);
    OK();
    printf("  ok: migrate/idempotent/fault-rollback/v11-refuse\n");
    return 0;
}

static int test_record_root(void) {
    printf("§4 record + activation_root\n");
    fx_t f = {0};
    CHECK(fx_open(&f, "root") == 0, "open");

    nodus_v2_act_record_t rec;
    CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 1, "no record");

    uint8_t empty[64], expect_empty[64], r0[64], r1[64];
    CHECK(nodus_witness_v2_activation_root(f.w, empty) == 0, "root");
    CHECK(nodus_merkle_empty_root(NODUS_TREE_TAG_ACTIVATION,
                                  expect_empty) == 0 &&
              memcmp(empty, expect_empty, 64) == 0,
          "no record = the tagged empty root");

    /* Plant a valid row directly (root-shape unit; the apply path is §5). */
    CHECK(sqlite3_exec(f.w->db,
            "INSERT INTO v2_activation VALUES (1, 1, 1,"
            " x'5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
            "00000000000000000000000000000000',"
            " zeroblob(64), 2880, 2880, 1440, zeroblob(64), 5, 3, 0)",
            NULL, NULL, NULL) == SQLITE_OK, "plant record");
    CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0 &&
              rec.state == DNA_ACT_STATE_SCHEDULED &&
              rec.activation_height == 2880, "read back");
    CHECK(nodus_witness_v2_activation_root(f.w, r0) == 0 &&
              memcmp(r0, empty, 64) != 0, "record moves the root");

    CHECK(sqlite3_exec(f.w->db,
            "INSERT INTO v2_activation_readiness VALUES (zeroblob(64),"
            " zeroblob(32), 1, 0, zeroblob(2592), zeroblob(4627))",
            NULL, NULL, NULL) == SQLITE_OK, "plant readiness");
    CHECK(nodus_witness_v2_activation_root(f.w, r1) == 0 &&
              memcmp(r0, r1, 64) != 0, "readiness moves the root");

    /* Malformed committed rows are FAULTS, never 'no record'. */
    CHECK(sqlite3_exec(f.w->db,
            "UPDATE v2_activation SET state = 9", NULL, NULL, NULL)
              == SQLITE_OK, "poke state");
    CHECK(nodus_witness_v2_activation_get(f.w, &rec) == -1,
          "unknown state is a FAULT");
    CHECK(sqlite3_exec(f.w->db,
            "UPDATE v2_activation SET state = 1, record_version = 9",
            NULL, NULL, NULL) == SQLITE_OK, "poke version");
    CHECK(nodus_witness_v2_activation_get(f.w, &rec) == -1,
          "unknown record_version is a FAULT");
    fx_close(&f);
    OK();
    printf("  ok: empty tag, root sensitivity, malformed = fault\n");
    return 0;
}

static int test_schedule_apply(void) {
    printf("§5 type-15 apply matrix\n");
    fx_t f = {0};
    CHECK(fx_open(&f, "s15") == 0, "open");
    CHECK(fx_seed_committee(&f) == 0, "committee");

    uint8_t D[64];
    CHECK(nodus_witness_v2_activation_compiled_target(D) == 0, "D");
    uint64_t lead = 2 * E > (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS
                        ? 2 * E
                        : (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    uint64_t h_act = ((10 + (lead + E - 1) / E)) * E;  /* aligned, > lead */
    uint64_t commit_h = 10;

    dna_act15_wire_t *s = calloc(1, sizeof(*s));
    CHECK(s != NULL, "alloc");

    /* negatives first — each digest-proven not to commit a record */
    CHECK(mk_sched(&f, s, D, h_act + 1, 1, commit_h, 3) == 0, "mk");
    CHECK(apply15(&f, s, commit_h) == -1, "unaligned H_act rejects");
    CHECK(mk_sched(&f, s, D, ((commit_h + lead) / E) * E, 1, commit_h, 3)
              == 0, "mk short");
    CHECK(apply15(&f, s, commit_h) == -1, "short lead rejects");
    CHECK(mk_sched(&f, s, D, h_act, 1, commit_h, 2) == 0, "mk q-1");
    CHECK(apply15(&f, s, commit_h) == -1, "quorum-1 rejects (q=3 of 4)");
    {
        CHECK(mk_sched(&f, s, D, h_act, 1, commit_h, 3) == 0, "mk dup");
        memcpy(s->votes[1].witness_id, s->votes[0].witness_id, 32);
        memcpy(s->votes[1].signature, s->votes[0].signature,
               DNA_ACT_SIG_LEN);
        CHECK(apply15(&f, s, commit_h) == -1, "duplicate vote id rejects");
    }
    {
        CHECK(mk_sched(&f, s, D, h_act, 1, commit_h, 3) == 0, "mk sig");
        s->votes[2].signature[100] ^= 1;
        CHECK(apply15(&f, s, commit_h) == -1, "bad signature rejects");
    }
    {
        CHECK(mk_sched(&f, s, D, h_act, 1, commit_h, 3) == 0, "mk mem");
        memset(s->votes[2].witness_id, 0xEE, 32);
        CHECK(apply15(&f, s, commit_h) == -1, "non-member vote rejects");
    }
    {
        uint8_t zero[64];
        memset(zero, 0, 64);
        CHECK(mk_sched(&f, s, zero, h_act, 1, commit_h, 3) == 0, "mk z");
        CHECK(apply15(&f, s, commit_h) == -1, "all-zero target rejects");
    }
    {
        CHECK(mk_sched(&f, s, D, h_act, 1, commit_h, 3) == 0, "mk v");
        s->record_version = 2;
        CHECK(apply15(&f, s, commit_h) == -1,
              "unknown record_version rejects");
        s->record_version = 1;
        s->op = 3;
        CHECK(apply15(&f, s, commit_h) == -1, "unknown op rejects");
    }
    {
        CHECK(mk_sched(&f, s, D, h_act, 1, commit_h, 3) == 0, "mk w");
        s->signed_at_block = 0;
        CHECK(apply15(&f, s, commit_h) == -1, "window shape rejects");
        CHECK(mk_sched(&f, s, D, h_act, 1, commit_h, 3) == 0, "mk fr");
        CHECK(apply15(&f, s, s->valid_before_block + 1) == -1,
              "stale (freshness) rejects");
    }
    {
        nodus_v2_act_record_t rec;
        CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 1,
              "no record after every negative");
    }

    /* the positive */
    CHECK(mk_sched(&f, s, D, h_act, 5, commit_h, 3) == 0, "mk pos");
    CHECK(apply15(&f, s, commit_h) == 0, "SCHEDULE commits");
    {
        nodus_v2_act_record_t rec;
        CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0 &&
                  rec.state == DNA_ACT_STATE_SCHEDULED &&
                  rec.activation_height == h_act &&
                  rec.original_height == h_act &&
                  rec.deadline_height == h_act - 2 * E &&
                  rec.proposal_nonce == 5 &&
                  rec.commit_height == commit_h &&
                  rec.postpone_count == 0,
              "record fields as scheduled");
    }
    /* replay of the same tx: state is SCHEDULED now → reject */
    CHECK(apply15(&f, s, commit_h + 1) == -1, "replay rejects");
    /* a conflicting second schedule rejects (must CANCEL first) */
    {
        dna_act15_wire_t *s2 = calloc(1, sizeof(*s2));
        CHECK(s2 != NULL, "alloc2");
        CHECK(mk_sched(&f, s2, D, h_act + E, 6, commit_h + 1, 3) == 0,
              "mk2");
        CHECK(apply15(&f, s2, commit_h + 1) == -1,
              "conflicting live schedule rejects");
        free(s2);
    }

    /* CANCEL: wrong digest rejects; right digest cancels; readiness
     * rows die with it; a fresh SCHEDULE then needs a HIGHER nonce. */
    {
        nodus_v2_act_record_t rec;
        CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0, "rec");
        dna_act15_wire_t *c = calloc(1, sizeof(*c));
        CHECK(c != NULL, "allocc");
        memset(c, 0, sizeof(*c));
        c->record_version = 1;
        c->op = DNA_ACT_OP_CANCEL;
        memset(c->target, 0xDD, 64);         /* wrong digest */
        c->proposal_nonce = 9;
        c->signed_at_block = commit_h + 1;
        c->valid_before_block = commit_h + 100;
        c->vote_count = 3;
        uint8_t digest[64];
        CHECK(dna_act_cancel_digest(f.w->chain_id, c->target, 9,
                                    c->signed_at_block,
                                    c->valid_before_block, digest) == 0,
              "cxl digest");
        for (int i = 0; i < 3; i++) {
            CHECK(nodus_chain_config_derive_witness_id(
                      g_pk[i], c->votes[i].witness_id) == 0, "wid");
            size_t sl = 0;
            CHECK(qgp_dsa87_sign(c->votes[i].signature, &sl, digest, 64,
                                 g_sk[i]) == 0, "sign");
        }
        CHECK(apply15(&f, c, commit_h + 2) == -1, "wrong digest rejects");

        memcpy(c->target, rec.schedule_digest, 64);
        CHECK(dna_act_cancel_digest(f.w->chain_id, c->target, 9,
                                    c->signed_at_block,
                                    c->valid_before_block, digest) == 0,
              "cxl digest 2");
        for (int i = 0; i < 3; i++) {
            size_t sl = 0;
            CHECK(qgp_dsa87_sign(c->votes[i].signature, &sl, digest, 64,
                                 g_sk[i]) == 0, "sign2");
        }
        CHECK(apply15(&f, c, commit_h + 2) == 0, "CANCEL commits");
        CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0 &&
                  rec.state == DNA_ACT_STATE_CANCELLED, "CANCELLED");
        CHECK(apply15(&f, c, commit_h + 3) == -1,
              "cancel of a cancelled record rejects");
        free(c);

        /* nonce must strictly increase after CANCELLED */
        CHECK(mk_sched(&f, s, D, h_act, 5, commit_h + 3, 3) == 0, "mk n");
        CHECK(apply15(&f, s, commit_h + 3) == -1,
              "re-schedule with a non-increasing nonce rejects");
        CHECK(mk_sched(&f, s, D, h_act, 6, commit_h + 3, 3) == 0, "mk n2");
        CHECK(apply15(&f, s, commit_h + 3) == 0,
              "re-schedule with a higher nonce commits");
    }
    free(s);
    fx_close(&f);
    OK();
    printf("  ok: full schedule/cancel consensus matrix\n");
    return 0;
}

static int test_ready_apply(void) {
    printf("§6 type-16 apply matrix\n");
    fx_t f = {0};
    CHECK(fx_open(&f, "s16") == 0, "open");
    CHECK(fx_seed_committee(&f) == 0, "committee");

    uint8_t D[64];
    CHECK(nodus_witness_v2_activation_compiled_target(D) == 0, "D");
    uint64_t lead = 2 * E > (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS
                        ? 2 * E
                        : (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    uint64_t h_act = ((10 + (lead + E - 1) / E)) * E;

    dna_act16_wire_t r;
    /* no schedule yet */
    memset(&r, 0, sizeof(r));
    r.signal_version = 1;
    CHECK(apply16(&f, &r, 5) == -1, "ready with no schedule rejects");

    dna_act15_wire_t *s = calloc(1, sizeof(*s));
    CHECK(s && mk_sched(&f, s, D, h_act, 1, 10, 3) == 0 &&
              apply15(&f, s, 10) == 0, "schedule");
    free(s);

    /* stale epoch: heights 11.. are epoch 0, so signal_epoch must be 0 */
    CHECK(mk_ready(&f, &r, 0, E) == 0, "mk stale");
    CHECK(apply16(&f, &r, 11) == -1, "stale signal_epoch rejects");

    CHECK(mk_ready(&f, &r, 0, 0) == 0, "mk r0");
    {
        dna_act16_wire_t evil = r;
        evil.schedule_digest[0] ^= 1;
        CHECK(apply16(&f, &evil, 11) == -1, "wrong digest rejects");
        evil = r;
        evil.target[0] ^= 1;
        CHECK(apply16(&f, &evil, 11) == -1, "wrong target rejects");
        evil = r;
        evil.signature[50] ^= 1;
        CHECK(apply16(&f, &evil, 11) == -1, "bad signature rejects");
        evil = r;
        evil.voter_id[0] ^= 1;
        CHECK(apply16(&f, &evil, 11) == -1,
              "voter_id != H(pubkey) rejects");
        evil = r;
        evil.signal_version = 2;
        CHECK(apply16(&f, &evil, 11) == -1, "unknown version rejects");
    }
    CHECK(apply16(&f, &r, 11) == 0, "READY commits");
    CHECK(apply16(&f, &r, 12) == 0, "byte-identical duplicate = no-op");
    {
        /* Equivocation: same voter, different bytes → first wins. */
        dna_act16_wire_t r2;
        CHECK(mk_ready(&f, &r2, 0, 0) == 0, "mk eq");
        /* Dilithium signing is randomized: same fields, fresh sig. If
         * the bytes came out identical this would be the duplicate
         * case; assert they differ so the check below means something. */
        CHECK(memcmp(r2.signature, r.signature, DNA_ACT_SIG_LEN) != 0,
              "fresh signature differs");
        CHECK(apply16(&f, &r2, 12) == -1,
              "conflicting signal (first wins) rejects");
    }
    {
        /* A non-member key: generate a 5th key. */
        static uint8_t xpk[QGP_DSA87_PUBLICKEYBYTES];
        static uint8_t xsk[QGP_DSA87_SECRETKEYBYTES];
        CHECK(qgp_dsa87_keypair(xpk, xsk) == 0, "keygen x");
        dna_act16_wire_t rx;
        nodus_v2_act_record_t rec;
        CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0, "rec");
        memset(&rx, 0, sizeof(rx));
        rx.signal_version = 1;
        memcpy(rx.schedule_digest, rec.schedule_digest, 64);
        memcpy(rx.target, rec.target, 64);
        CHECK(nodus_chain_config_derive_witness_id(xpk, rx.voter_id) == 0,
              "wid x");
        rx.signal_epoch = 0;
        memcpy(rx.pubkey, xpk, sizeof(xpk));
        uint8_t digest[64];
        CHECK(dna_act_ready_digest(1, f.w->chain_id, rx.schedule_digest,
                                   rx.target, rx.voter_id, 0, digest) == 0,
              "digest x");
        size_t sl = 0;
        CHECK(qgp_dsa87_sign(rx.signature, &sl, digest, 64, xsk) == 0,
              "sign x");
        CHECK(apply16(&f, &rx, 12) == -1, "non-member signer rejects");
    }
    {
        /* readiness_count over the governing snapshot */
        nodus_v2_act_record_t rec;
        dna_vset_snapshot_t *snap = NULL;
        CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0, "rec");
        CHECK(nodus_witness_vset_get(f.w, 0, &snap, NULL) == 0 && snap,
              "snap 0");
        uint32_t n = 99;
        CHECK(nodus_witness_v2_activation_readiness_count(
                  f.w, rec.schedule_digest, snap, &n) == 0 && n == 1,
              "one committed signal counts once");
        dna_vset_free(&snap);
    }
    fx_close(&f);
    OK();
    printf("  ok: full readiness matrix incl. equivocation\n");
    return 0;
}

/* Boundary driver: chain snapshots forward so every boundary the state
 * machine consults has committed authority (commit_next freezes h+E).
 * The committee builder's state-seed tiebreak reads the LEGACY blocks
 * row at e_start − E − 1 (committee.c:116-125), so each lookback row is
 * planted first — the test_v2_native §16 pattern. */
static int drive_snapshots_to(fx_t *fx, uint64_t upto) {
    for (uint64_t h = E; h + E <= upto + E; h += E) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(fx->w->db,
                "INSERT OR IGNORE INTO blocks (height, tx_root, tx_count,"
                " timestamp, proposer_id, prev_hash, state_root) VALUES "
                "(?1, zeroblob(64), 1, 1, zeroblob(32), zeroblob(64),"
                " zeroblob(64))", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (int64_t)(h - 1));
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
        if (nodus_witness_vset_commit_next(fx->w, h) != 0) return -1;
    }
    return 0;
}

static int test_boundary(void) {
    printf("§7 boundary machine + terminal refusal\n");
    fx_t f = {0};
    CHECK(fx_open(&f, "bnd") == 0, "open");
    CHECK(fx_seed_committee(&f) == 0, "committee");

    uint8_t D[64];
    CHECK(nodus_witness_v2_activation_compiled_target(D) == 0, "D");
    uint64_t lead = 2 * E > (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS
                        ? 2 * E
                        : (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    uint64_t h_act = ((2 + (lead + E - 1) / E)) * E;

    dna_act15_wire_t *s = calloc(1, sizeof(*s));
    CHECK(s && mk_sched(&f, s, D, h_act, 1, 2, 3) == 0 &&
              apply15(&f, s, 2) == 0, "schedule");
    free(s);
    CHECK(drive_snapshots_to(&f, h_act) == 0, "snapshots");

    /* incomplete readiness: boundary leaves SCHEDULED */
    int act = -1;
    CHECK(nodus_witness_v2_activation_on_boundary(f.w, E, &act) == 0 &&
              act == 0, "boundary E");
    nodus_v2_act_record_t rec;
    CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0 &&
              rec.state == DNA_ACT_STATE_SCHEDULED,
          "incomplete readiness stays SCHEDULED");

    /* all four sign inside epoch 1 (heights E..2E-1, epoch key E) */
    for (int k = 0; k < NKEYS; k++) {
        dna_act16_wire_t r;
        CHECK(mk_ready(&f, &r, k, E) == 0, "mk k");
        CHECK(apply16(&f, &r, E + 1 + (uint64_t)k) == 0, "ready k");
    }
    CHECK(nodus_witness_v2_activation_on_boundary(f.w, 2 * E, &act) == 0 &&
              act == 0, "boundary 2E");
    CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0 &&
              rec.state == DNA_ACT_STATE_READY,
          "complete readiness flips READY");

    /* every intermediate boundary re-evaluates; then Stage E fires */
    for (uint64_t h = 3 * E; h < h_act; h += E) {
        CHECK(nodus_witness_v2_activation_on_boundary(f.w, h, &act) == 0 &&
                  act == 0, "intermediate boundary");
    }
    CHECK(nodus_witness_v2_activation_on_boundary(f.w, h_act, &act) == 0 &&
              act == 1, "Stage E activates at H_act");
    CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0 &&
              rec.state == DNA_ACT_STATE_ACTIVE, "ACTIVE");

    /* terminal refusal — including the pre-genesis regression the first
     * rehearsal bring-up found: a handle with NO database is a
     * pre-genesis node; no committed record can exist, so nothing may
     * be refused (the old fail-closed here blocked genesis itself). */
    {
        nodus_witness_t *bare = calloc(1, sizeof(*bare));
        CHECK(bare != NULL, "alloc bare");
        CHECK(nodus_witness_v2_activation_refuses_height(bare, 1) == 0,
              "a pre-genesis (no-db) node refuses NOTHING");
        CHECK(nodus_witness_v2_activation_refuses_height(NULL, 1) == 1,
              "a NULL handle still fails closed");
        free(bare);
    }
    CHECK(nodus_witness_v2_activation_refuses_height(f.w, h_act) == 0,
          "H_act itself is permitted");
    CHECK(nodus_witness_v2_activation_refuses_height(f.w, h_act + 1) == 1,
          "H_act + 1 refused");
    CHECK(nodus_witness_v2_activation_refuses_height(f.w,
              h_act + 12345) == 1, "far heights refused");

    /* ACTIVE is terminal: further boundaries are no-ops */
    CHECK(nodus_witness_v2_activation_on_boundary(f.w, h_act + E, &act)
              == 0 && act == 0, "post-active boundary no-op");
    fx_close(&f);
    OK();
    printf("  ok: SCHEDULED→READY→ACTIVE + terminal refusal\n");
    return 0;
}

static int test_postpone(void) {
    printf("§8 postpone loop + auto-cancel\n");
    fx_t f = {0};
    CHECK(fx_open(&f, "pp") == 0, "open");
    CHECK(fx_seed_committee(&f) == 0, "committee");

    uint8_t D[64];
    CHECK(nodus_witness_v2_activation_compiled_target(D) == 0, "D");
    uint64_t lead = 2 * E > (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS
                        ? 2 * E
                        : (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    uint64_t h_act = ((2 + (lead + E - 1) / E)) * E;

    dna_act15_wire_t *s = calloc(1, sizeof(*s));
    CHECK(s && mk_sched(&f, s, D, h_act, 1, 2, 3) == 0 &&
              apply15(&f, s, 2) == 0, "schedule");
    free(s);
    uint64_t last = h_act + ((uint64_t)DNA_ACT_MAX_POSTPONES + 2) * E;
    CHECK(drive_snapshots_to(&f, last) == 0, "snapshots");

    /* nobody signs: every H_act boundary postpones, then auto-cancel */
    nodus_v2_act_record_t rec;
    for (uint32_t i = 0; i <= DNA_ACT_MAX_POSTPONES; i++) {
        uint64_t h = h_act + (uint64_t)i * E;
        int act = -1;
        /* run the intermediate boundaries too — the machine is
         * evaluated at EVERY boundary */
        CHECK(nodus_witness_v2_activation_on_boundary(f.w, h, &act) == 0 &&
                  act == 0, "postpone boundary");
        CHECK(nodus_witness_v2_activation_get(f.w, &rec) == 0, "rec");
        if (i < DNA_ACT_MAX_POSTPONES) {
            CHECK(rec.state == DNA_ACT_STATE_SCHEDULED &&
                      rec.activation_height == h + E &&
                      rec.postpone_count == i + 1,
                  "postponed exactly one epoch");
            CHECK(rec.deadline_height == h_act - 2 * E &&
                      rec.original_height == h_act,
                  "original/deadline heights never move");
        } else {
            CHECK(rec.state == DNA_ACT_STATE_CANCELLED,
                  "postpone cap auto-cancels");
        }
    }
    /* readiness signals were deleted with the auto-cancel */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(f.w->db,
                  "SELECT COUNT(*) FROM v2_activation_readiness", -1, &st,
                  NULL) == SQLITE_OK, "prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 0,
              "cancelled signals are gone");
        sqlite3_finalize(st);
    }
    fx_close(&f);
    OK();
    printf("  ok: bounded postponement, auto-cancel, immutable anchors\n");
    return 0;
}

static int test_stage_c(void) {
    printf("§9 Stage C exclusions\n");
    fx_t f = {0};
    CHECK(fx_open(&f, "sc") == 0, "open");
    CHECK(fx_seed_committee(&f) == 0, "committee");

    uint8_t D[64];
    CHECK(nodus_witness_v2_activation_compiled_target(D) == 0, "D");
    uint64_t lead = 2 * E > (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS
                        ? 2 * E
                        : (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    uint64_t h_act = ((2 + (lead + E - 1) / E)) * E;

    dna_act15_wire_t *s = calloc(1, sizeof(*s));
    CHECK(s && mk_sched(&f, s, D, h_act, 1, 2, 3) == 0 &&
              apply15(&f, s, 2) == 0, "schedule");
    free(s);

    dna_vset_snapshot_t *snap = NULL;
    CHECK(nodus_witness_vset_get(f.w, 0, &snap, NULL) == 0 && snap,
          "candidate snapshot");

    uint8_t excl[NKEYS][DNA_ACT_VOTER_ID_LEN];
    size_t n = 99;

    /* not applicable off the deadline boundary */
    CHECK(nodus_witness_v2_activation_exclusions(f.w, h_act - E, snap, 1,
              excl, NKEYS, &n) == 1 && n == 0, "wrong boundary: N/A");

    /* at the deadline: nobody signed → floor guard when min_count high */
    CHECK(nodus_witness_v2_activation_exclusions(f.w, h_act - 2 * E, snap,
              (uint16_t)NKEYS, excl, NKEYS, &n) == 2 && n == 0,
          "floor guard blocks a full wipe");

    /* two sign; the other two are excludable above a floor of 2 */
    for (int k = 0; k < 2; k++) {
        dna_act16_wire_t r;
        CHECK(mk_ready(&f, &r, k, 0) == 0, "mk");
        CHECK(apply16(&f, &r, 5 + (uint64_t)k) == 0, "ready");
    }
    CHECK(nodus_witness_v2_activation_exclusions(f.w, h_act - 2 * E, snap,
              2, excl, NKEYS, &n) == 0 && n == 2,
          "exactly the unready members are excluded");
    dna_vset_free(&snap);
    fx_close(&f);
    OK();
    printf("  ok: N/A, floor guard, exclusion list\n");
    return 0;
}

static int test_attendance(void) {
    printf("§10 the V2 attendance writer (Rule N source)\n");
    fx_t f = {0};
    CHECK(fx_open(&f, "att") == 0, "open");
    CHECK(fx_seed_committee(&f) == 0, "committee");

    uint8_t pid[32], full[64], zero[32];
    memset(zero, 0, 32);
    qgp_sha3_512(g_pk[1], sizeof(g_pk[1]), full);
    memcpy(pid, full, 32);

    int credited = -1;
    CHECK(nodus_witness_v2_record_attendance(f.w, 0, pid, &credited) == 0 &&
              credited == 0, "height 0 is a no-op");
    CHECK(nodus_witness_v2_record_attendance(f.w, 5, zero, &credited) == 0 &&
              credited == 0, "all-zero proposer is a no-op");
    CHECK(nodus_witness_v2_record_attendance(f.w, 5, pid, &credited) == 0 &&
              credited == 1, "the proposer is credited");
    {
        dnac_validator_record_t v;
        CHECK(nodus_validator_get(f.w, g_pk[1], &v) == 0 &&
                  v.last_signed_block == 5 &&
                  v.signed_blocks_this_epoch == 1,
              "watermark + counter written");
    }
    CHECK(nodus_witness_v2_record_attendance(f.w, 5, pid, &credited) == 0 &&
              credited == 0, "monotonic: same height is a no-op");
    CHECK(nodus_witness_v2_record_attendance(f.w, 4, pid, &credited) == 0 &&
              credited == 0, "monotonic: lower height is a no-op");
    CHECK(nodus_witness_v2_record_attendance(f.w, 9, pid, &credited) == 0 &&
              credited == 1, "a later block credits again");
    {
        uint8_t unknown[32];
        memset(unknown, 0xAB, 32);
        CHECK(nodus_witness_v2_record_attendance(f.w, 11, unknown,
                  &credited) == 0 && credited == 0,
              "unknown proposer is a clean skip");
    }
    fx_close(&f);
    OK();
    printf("  ok: credit / monotonic / zero / unknown\n");
    return 0;
}

static int test_root_v4(void) {
    printf("§11 state_root v4\n");
    uint8_t a[64], b[64], c[64], d[64], e[64], act[64];
    memset(a, 1, 64); memset(b, 2, 64); memset(c, 3, 64);
    memset(d, 4, 64); memset(e, 5, 64); memset(act, 6, 64);

    uint8_t v3[64], v4[64], v4b[64];
    CHECK(nodus_merkle_combine_state_root_v3(a, b, c, d, e, v3) == 0, "v3");
    CHECK(nodus_merkle_combine_state_root_v4(a, b, c, d, e, act, v4) == 0,
          "v4");
    CHECK(memcmp(v3, v4, 64) != 0, "v4 is domain-separated from v3");
    act[0] ^= 1;
    CHECK(nodus_merkle_combine_state_root_v4(a, b, c, d, e, act, v4b) == 0 &&
              memcmp(v4, v4b, 64) != 0,
          "the activation leg moves the root");
    CHECK(nodus_merkle_combine_state_root_v4(a, b, c, d, e, NULL, v4b)
              == -1, "NULL leg fails closed");
    OK();
    printf("  ok: separation, leg sensitivity, fail-closed\n");
    return 0;
}

int main(void) {
    printf("=== Ledger V2 O15C — committed activation authority ===\n\n");
    for (int i = 0; i < NKEYS; i++) {
        if (qgp_dsa87_keypair(g_pk[i], g_sk[i]) != 0) {
            fprintf(stderr, "keygen failed\n");
            return 1;
        }
    }
    if (test_wire()) return 1;
    if (test_target()) return 1;
    if (test_schema()) return 1;
    if (test_record_root()) return 1;
    if (test_schedule_apply()) return 1;
    if (test_ready_apply()) return 1;
    if (test_boundary()) return 1;
    if (test_postpone()) return 1;
    if (test_stage_c()) return 1;
    if (test_attendance()) return 1;
    if (test_root_v4()) return 1;
    printf("\nALL O15C ACTIVATION TESTS PASSED\n");
    return 0;
}
