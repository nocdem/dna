/**
 * Nodus — Task 53 committee cache tests.
 *
 * Verifies nodus_committee_get_for_block() caches the committee per
 * epoch and recomputes on epoch-start change.
 *
 * Scenarios:
 *   (1) First call populates the cache; epoch_start matches lookup.
 *   (2) Second call within the same epoch reads cached values — even
 *       after we mutate a validator's underlying stake the cached
 *       ranking does NOT refresh (committee is frozen per epoch).
 *   (3) Call for a different epoch forces recompute; new ordering picks
 *       up the mutated stake.
 *   (4) Init sentinel: freshly zeroed witness has
 *       cached_committee_epoch_start == UINT64_MAX before any lookup.
 *
 * tokenomics-v3 P3-1 ("okuma B"): the recompute ranks by the FROZEN copy
 * of the epoch its lookback block lies in — copy(e_start − 2E) — not the
 * live stake (nodus_committee_compute_for_epoch). The fixture therefore
 * writes copy(2E) (for e_start 4E) from the live rows before (1), and
 * copy(3E) (for e_start 5E) after (2)'s mutation, standing for the copy
 * the boundary AFTER the mutation would have frozen. (3b) changed
 * meaning: going back to epoch 4E re-queries, and the re-query follows
 * the FROZEN copy(2E) — which the live mutation did not move — so v2 is
 * still first (pre-P3 the live re-read put v1 first).
 *
 * HF-6 slice 5b (design 2026-10-03-hf5-validator-owner-stake rev 6 §5;
 * plan tasks/hf6-slice5-plan.md §2 "5b", ORCHESTRATOR decision D5):
 * nodus_committee_member_t.power must be identical on a cache HIT and a
 * cache MISS (root rule "Verify cache symmetry"). Stakes are whole coins
 * (× DNAC_DECIMAL_UNIT) so a hit that left `power` at 0 would fail.
 *   (1)-(3b) the recompute arm: power = total_stake / 10^8 on the miss,
 *       the same value on the hit;
 *   (5) the snapshot-served arm: a stored ruleset-1 snapshot for 6E
 *       (raw 7·10^8, 3·10^8 + 5, 10^8 − 1) serves powers [7, 3, 0] in
 *       snapshot order (nodus_witness_vset_powers, identity) on the miss,
 *       and a hit returns the identical members;
 *   (6) [NODUS_EVM_ENABLED only — generation 4 exists only there] a
 *       second DB: at generation 1 a row-less epoch (0, bootstrap) is
 *       recomputed (positive control); after the registry is switched
 *       to NODUS_RT_GEN_STORAGE the same lookup FAULTS (-1, cache left
 *       invalid) — the bootstrap recompute itself would have succeeded,
 *       so only the D5 refusal can produce the -1 — while an epoch
 *       served from its snapshot row still answers.
 * Written by the slice-5b builder; NOT run by the author. */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_v2_econ.h"   /* P3-1: the frozen copy */
#include "witness/nodus_witness_vset.h"      /* HF-6 5b: snapshot rows */
#include "witness/nodus_witness_emission.h"  /* DNAC_DECIMAL_UNIT      */
#include "witness/nodus_witness_domreg.h"    /* HF-6 5b (6): registry  */
#include "witness/nodus_witness_runtime.h"   /* NODUS_RT_GEN_STORAGE   */
#include "witness/nodus_witness_v2_epoch.h"  /* key generation         */
#include "witness/nodus_witness_v2_schema.h" /* v7 schema for (6)      */
#include "nodus/nodus_chain_config.h"        /* witness_id derivation  */

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"
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

/* P3-1: (re)write copy(epoch) from the live rows (strict-insert writer,
 * so the epoch's old rows go first). */
static void refresh_copy(nodus_witness_t *w, uint64_t epoch) {
    sqlite3_stmt *stmt = NULL;
    CHECK_EQ(sqlite3_prepare_v2(w->db,
        "DELETE FROM v2_balance_copy WHERE epoch_start = ?", -1, &stmt,
        NULL), SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, (int64_t)epoch);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
    CHECK_EQ(nodus_witness_v2_balance_copy_write(w, epoch), 0);
}

#define UNIT DNAC_DECIMAL_UNIT

/* HF-6 5b: two members are the same member, field by field (the struct
 * has padding, so no memcmp over it). */
static void check_member_eq(const nodus_committee_member_t *a,
                            const nodus_committee_member_t *b) {
    CHECK(memcmp(a->pubkey, b->pubkey, DNAC_PUBKEY_SIZE) == 0);
    CHECK_EQ(a->total_stake, b->total_stake);
    CHECK_EQ(a->self_stake, b->self_stake);
    CHECK_EQ(a->commission_bps, b->commission_bps);
    CHECK_EQ(a->power, b->power);
}

/* HF-6 5b: store a ruleset-1 snapshot for `epoch` whose entry i has
 * pubkey fill fills[i] and raw total_stake raw[i] (self_bond = raw,
 * commission 100). Exactly the bytes vset_build_and_store would store
 * for such a set: legacy encode + legacy hash + vset_insert. */
static void store_v1_snapshot(nodus_witness_t *w, uint64_t epoch,
                              const uint8_t *fills, const uint64_t *raw,
                              uint16_t n) {
    dna_vset_snapshot_t *s = dna_vset_alloc(n);
    CHECK(s != NULL);
    s->epoch = epoch;
    for (uint16_t i = 0; i < n; i++) {
        dna_vset_entry_t *e = &s->entries[i];
        memset(e->pubkey, fills[i], DNA_VSET_PUBKEY_LEN);
        CHECK_EQ(nodus_chain_config_derive_witness_id(e->pubkey,
                                                      e->voter_id), 0);
        e->total_stake    = raw[i];
        e->self_bond      = raw[i];
        e->commission_bps = 100;
    }
    size_t need = dna_vset_encoded_len(s);
    CHECK(need > 0);
    uint8_t *blob = malloc(need);
    CHECK(blob != NULL);
    size_t written = 0;
    CHECK_EQ(dna_vset_encode(s, blob, need, &written), 0);
    CHECK_EQ(written, need);
    uint8_t hash[DNA_VSET_HASH_LEN];
    CHECK_EQ(dna_vset_hash_bytes(blob, written, hash), 0);
    CHECK_EQ(nodus_witness_vset_insert(w, epoch, blob, written, hash,
                                       epoch - (uint64_t)DNAC_EPOCH_LENGTH),
             0);
    free(blob);
    dna_vset_free(&s);
}

static int find_pubkey(const nodus_committee_member_t *arr, int count,
                        uint8_t pub_fill) {
    uint8_t needle[DNAC_PUBKEY_SIZE];
    memset(needle, pub_fill, sizeof(needle));
    for (int i = 0; i < count; i++) {
        if (memcmp(arr[i].pubkey, needle, DNAC_PUBKEY_SIZE) == 0) return i;
    }
    return -1;
}

int main(void) {
    /* ── Scenario 4 first: init sentinel (use a fresh, un-opened struct) ── */
    printf("  (4) init sentinel — cached_committee_epoch_start == UINT64_MAX\n");
    static nodus_witness_t w_init;  /* multi-MB — static storage, not stack */
    memset(&w_init, 0, sizeof(w_init));
    /* The production path runs nodus_witness_init which sets the
     * sentinel. We simulate the relevant bit here without the full
     * server fixture to keep the test standalone. */
    w_init.cached_committee_epoch_start = UINT64_MAX;
    w_init.cached_committee_count = 0;
    CHECK_EQ(w_init.cached_committee_epoch_start, (uint64_t)UINT64_MAX);
    CHECK_EQ(w_init.cached_committee_count, 0);

    char data_path[] = "/tmp/test_committee_cache_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    /* Apply the same sentinel init the production path does. */
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0xC4, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* Seed two lookback blocks so we can exercise two different epochs. */
    const uint64_t epoch_len = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t e_start_a = epoch_len * 4;                 /* 480 */
    const uint64_t lookback_a = e_start_a - epoch_len - 1;    /* 359 */
    const uint64_t e_start_b = epoch_len * 5;                 /* 600 */
    const uint64_t lookback_b = e_start_b - epoch_len - 1;    /* 479 */

    uint8_t seed_a[64]; memset(seed_a, 0x11, sizeof(seed_a));
    uint8_t seed_b[64]; memset(seed_b, 0x22, sizeof(seed_b));
    insert_block_row(&w, lookback_a, seed_a);
    insert_block_row(&w, lookback_b, seed_b);

    /* Two validators active_since=1 — clear MIN_TENURE against both
     * lookbacks (1 + 240 = 241 <= 359). */
    dnac_validator_record_t v1, v2;
    /* HF-6 5b: whole coins, so the recompute power (total / 10^8) is
     * nonzero and a hit that dropped it would be caught. */
    init_validator(&v1, 0x11, 1, 100 * UNIT);
    init_validator(&v2, 0x22, 1, 200 * UNIT);
    CHECK_EQ(nodus_validator_insert(&w, &v1), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v2), 0);
    /* P3-1: freeze copy(2E), the copy epoch 4E ranks by */
    refresh_copy(&w, e_start_a - 2 * epoch_len);

    /* ── Scenario 1: first call populates cache ──────────────────── */
    printf("  (1) first call within epoch — populates cache\n");
    /* Block height anywhere in [e_start_a, e_start_a + epoch_len) maps
     * to epoch e_start_a. Pick e_start_a + 10. */
    uint64_t blk_in_a = e_start_a + 10;
    nodus_committee_member_t out1[DNAC_COMMITTEE_SIZE];
    int count1 = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_a, out1,
                                             DNAC_COMMITTEE_SIZE, &count1), 0);
    CHECK_EQ(count1, 2);
    CHECK_EQ(w.cached_committee_epoch_start, e_start_a);
    CHECK_EQ(w.cached_committee_count, 2);
    /* v2 (200) before v1 (100) by stake. */
    CHECK(find_pubkey(out1, count1, 0x22) == 0);
    CHECK(find_pubkey(out1, count1, 0x11) == 1);
    /* HF-6 5b: the recompute arm's power = total / 10^8 */
    CHECK_EQ(out1[0].power, 200);
    CHECK_EQ(out1[1].power, 100);
    CHECK_EQ(w.cached_committee_powers[0], 200);
    CHECK_EQ(w.cached_committee_powers[1], 100);

    /* ── Scenario 2: second call returns cached — ignores mutation ── */
    printf("  (2) cached call ignores mid-epoch stake mutation\n");
    /* Mutate v1 to beat v2 in raw stake — 999 > 200. If the committee
     * were recomputed, v1 would rank first. Cached call MUST return
     * the unchanged ordering. */
    set_self_stake(&w, v1.pubkey, 999 * UNIT);

    nodus_committee_member_t out2[DNAC_COMMITTEE_SIZE];
    int count2 = 0;
    uint64_t blk_in_a_later = e_start_a + 50;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_a_later, out2,
                                             DNAC_COMMITTEE_SIZE, &count2), 0);
    CHECK_EQ(count2, count1);
    /* Ordering is the SAME as before the mutation, and (HF-6 5b) every
     * field — the voting power included — equals the miss's member. */
    for (int i = 0; i < count1; i++) {
        CHECK(memcmp(out1[i].pubkey, out2[i].pubkey, DNAC_PUBKEY_SIZE) == 0);
        CHECK_EQ(out1[i].total_stake, out2[i].total_stake);
        check_member_eq(&out1[i], &out2[i]);
    }
    /* The cached total_stake for v2 is still 200 — NOT refreshed. */
    int idx_v2 = find_pubkey(out2, count2, 0x22);
    CHECK(idx_v2 >= 0);
    CHECK_EQ(out2[idx_v2].total_stake, 200 * UNIT);
    CHECK_EQ(out2[idx_v2].power, 200);

    /* ── Scenario 3: new epoch forces recompute ──────────────────── */
    printf("  (3) epoch change triggers recompute\n");
    /* P3-1: the mutation reaches a set only through a LATER frozen copy —
     * copy(3E), the one epoch 5E ranks by */
    refresh_copy(&w, e_start_b - 2 * epoch_len);
    uint64_t blk_in_b = e_start_b + 5;
    nodus_committee_member_t out3[DNAC_COMMITTEE_SIZE];
    int count3 = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_b, out3,
                                             DNAC_COMMITTEE_SIZE, &count3), 0);
    CHECK_EQ(count3, 2);
    CHECK_EQ(w.cached_committee_epoch_start, e_start_b);
    /* v1 (999) now beats v2 (200). */
    CHECK(find_pubkey(out3, count3, 0x11) == 0);
    CHECK(find_pubkey(out3, count3, 0x22) == 1);
    int idx_v1 = find_pubkey(out3, count3, 0x11);
    CHECK_EQ(out3[idx_v1].total_stake, 999 * UNIT);
    CHECK_EQ(out3[idx_v1].power, 999);
    CHECK_EQ(out3[find_pubkey(out3, count3, 0x22)].power, 200);

    /* Going BACK to the old epoch re-queries; because the cache key
     * only stores one epoch, this triggers another recompute.
     * tokenomics-v3 P3-1: the recompute ranks by the FROZEN copy(2E),
     * which the live mutation did not touch, so v2 (200) is still on top
     * — the pre-P3 live re-read put v1 (999) first. The cache still pins
     * ONE epoch at a time; ping-ponging re-queries (in production this
     * never happens — block_height is monotonic). */
    printf("  (3b) back to old epoch — re-query from its frozen copy\n");
    nodus_committee_member_t out4[DNAC_COMMITTEE_SIZE];
    int count4 = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_a, out4,
                                             DNAC_COMMITTEE_SIZE, &count4), 0);
    CHECK_EQ(w.cached_committee_epoch_start, e_start_a);
    CHECK(find_pubkey(out4, count4, 0x22) == 0);
    CHECK_EQ(out4[0].total_stake, 200 * UNIT);
    CHECK_EQ(out4[0].power, 200);

    /* ── Scenario 5 (HF-6 5b): the snapshot-served arm ─────────────── */
    printf("  (5) snapshot-served epoch — power from the helper, hit == miss\n");
    const uint64_t e_start_c = epoch_len * 6;
    {
        const uint8_t  fills[3] = { 0x31, 0x32, 0x33 };
        const uint64_t raw[3]   = { 7 * UNIT, 3 * UNIT + 5, UNIT - 1 };
        store_v1_snapshot(&w, e_start_c, fills, raw, 3);

        nodus_committee_member_t miss[DNAC_COMMITTEE_SIZE];
        nodus_committee_member_t hit[DNAC_COMMITTEE_SIZE];
        int n_miss = 0, n_hit = 0;
        CHECK_EQ(nodus_committee_get_for_block(&w, e_start_c + 3, miss,
                                               DNAC_COMMITTEE_SIZE, &n_miss),
                 0);
        CHECK_EQ(n_miss, 3);
        CHECK_EQ(w.cached_committee_epoch_start, e_start_c);
        /* snapshot order, ruleset-1 identity: total / 10^8, zero kept */
        for (int i = 0; i < 3; i++) {
            CHECK(find_pubkey(miss, n_miss, fills[i]) == i);
            CHECK_EQ(miss[i].total_stake, raw[i]);
            CHECK_EQ(miss[i].self_stake, raw[i]);
            CHECK_EQ(miss[i].commission_bps, 100);
            CHECK_EQ(miss[i].power, raw[i] / UNIT);
            CHECK_EQ(w.cached_committee_powers[i], raw[i] / UNIT);
        }
        CHECK_EQ(miss[0].power, 7);
        CHECK_EQ(miss[1].power, 3);
        CHECK_EQ(miss[2].power, 0);

        CHECK_EQ(nodus_committee_get_for_block(&w, e_start_c + 9, hit,
                                               DNAC_COMMITTEE_SIZE, &n_hit),
                 0);
        CHECK_EQ(n_hit, n_miss);
        for (int i = 0; i < n_miss; i++) check_member_eq(&miss[i], &hit[i]);
    }

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

#ifdef NODUS_EVM_ENABLED
    /* ── Scenario 6 (HF-6 5b, decision D5): generation 4 refuses the
     * row-less recompute ─────────────────────────────────────────────
     * A fresh DB at the v7 schema (the runtimes' state_init hooks need
     * it — the test_domreg fixture), the genesis registry (generation 1)
     * written BEFORE any validator exists, one ACTIVE validator. */
    printf("  (6) generation 4: a row-less epoch faults, a served one answers\n");
    {
        char data_path2[] = "/tmp/test_committee_cache_g4_XXXXXX";
        CHECK(mkdtemp(data_path2) != NULL);
        static nodus_witness_t w4;   /* multi-MB — static storage */
        memset(&w4, 0, sizeof(w4));
        snprintf(w4.data_path, sizeof(w4.data_path), "%s", data_path2);
        w4.cached_committee_epoch_start = UINT64_MAX;
        uint8_t chain_id2[16];
        memset(chain_id2, 0xC6, sizeof(chain_id2));
        CHECK_EQ(nodus_witness_create_chain_db(&w4, chain_id2), 0);
        CHECK_EQ(nodus_witness_db_migrate_v2s7(&w4), 0);
        CHECK_EQ(nodus_witness_domreg_init_genesis(&w4), 0);

        dnac_validator_record_t v4;
        init_validator(&v4, 0x44, 1, 50 * UNIT);
        CHECK_EQ(nodus_validator_insert(&w4, &v4), 0);

        uint32_t gen = 0;
        CHECK_EQ(nodus_witness_v2_key_generation(&w4, &gen), 0);
        CHECK_EQ(gen, NODUS_RT_GEN_1);

        /* positive control: generation 1, epoch 0 has no snapshot row →
         * the bootstrap recompute answers, power = total / 10^8 */
        nodus_committee_member_t g1[DNAC_COMMITTEE_SIZE];
        int n_g1 = 0;
        CHECK_EQ(nodus_committee_get_for_block(&w4, 5, g1,
                                               DNAC_COMMITTEE_SIZE, &n_g1), 0);
        CHECK_EQ(n_g1, 1);
        CHECK_EQ(g1[0].power, 50);

        /* the registry moves to generation 4 (the edge's transform) */
        CHECK_EQ(sqlite3_exec(w4.db, "BEGIN IMMEDIATE", NULL, NULL, NULL),
                 SQLITE_OK);
        CHECK_EQ(nodus_witness_domreg_generation_switch(&w4, NODUS_RT_GEN_1,
                                                        NODUS_RT_GEN_STORAGE),
                 0);
        CHECK_EQ(sqlite3_exec(w4.db, "COMMIT", NULL, NULL, NULL), SQLITE_OK);
        CHECK_EQ(nodus_witness_v2_key_generation(&w4, &gen), 0);
        CHECK_EQ(gen, NODUS_RT_GEN_STORAGE);

        /* the same row-less lookup now FAULTS; the cache stays invalid */
        w4.cached_committee_epoch_start = UINT64_MAX;
        w4.cached_committee_count = 0;
        nodus_committee_member_t g4[DNAC_COMMITTEE_SIZE];
        int n_g4 = 7;
        CHECK(nodus_committee_get_for_block(&w4, 5, g4,
                                            DNAC_COMMITTEE_SIZE, &n_g4) == -1);
        CHECK_EQ(n_g4, 0);
        CHECK_EQ(w4.cached_committee_epoch_start, (uint64_t)UINT64_MAX);
        CHECK_EQ(w4.cached_committee_count, 0);

        /* an epoch served from its snapshot row is unaffected */
        const uint8_t  fills[2] = { 0x51, 0x52 };
        const uint64_t raw[2]   = { 12 * UNIT, 4 * UNIT };
        store_v1_snapshot(&w4, e_start_c, fills, raw, 2);
        nodus_committee_member_t sv[DNAC_COMMITTEE_SIZE];
        int n_sv = 0;
        CHECK_EQ(nodus_committee_get_for_block(&w4, e_start_c + 1, sv,
                                               DNAC_COMMITTEE_SIZE, &n_sv), 0);
        CHECK_EQ(n_sv, 2);
        CHECK_EQ(sv[0].power, 12);
        CHECK_EQ(sv[1].power, 4);

        sqlite3_close(w4.db);
        w4.db = NULL;
        rmrf(data_path2);
    }
#endif

    printf("\nAll Task 53 committee cache tests passed.\n");
    return 0;
}
