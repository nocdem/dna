/**
 * Bench: the Nodus EVM measurement gate, part (b) — EVM blocks through the
 * node's REAL apply path.
 *
 * MEASUREMENT TOOL ONLY. CLOCK_MONOTONIC timing; not consensus code, not
 * linked into a node.
 *
 * Governing records: docs/plans/2026-10-04-nodus-evm-chain-integration-
 * design.md §8 ("Faz 3 kapısı": measure the worst cost per gas;
 * EVM_BLOCK_GAS_LIMIT's voted value is derived from it), decision
 * 2026-10-04-nodus-evm-kurultay-k2-summary.md item 3 (the gas limits await
 * this gate). Changes no placeholder value.
 *
 * WHAT IT MEASURES. Blocks whose EVM transactions fill --block-gas
 * (default 30 000 000) with ONE worst-case workload each — the same
 * hand-assembled contracts as the bare-engine bench
 * (shared/evm/bench/evm_bench_wl.c, compiled into this binary) — applied
 * by nodus_witness_v2_apply_block, the entry FinalizeBlock calls
 * (nodus_witness_cmt_app.c:2594 inside nodus_cmt_app_finalize_block,
 * :2331): envelope preflight + both legs' ML-DSA-87 signature checks, the
 * CORE fee leg, the EVM engine over the SQLite-backed reader, the
 * per-mutation state-trie update, receipts, logs, the roots and the
 * supply gates. The host's COMMIT (nodus_witness_cmt_host.c:1794
 * nodus_cmt_host_apply_verified_block holds the transaction) is timed
 * SEPARATELY. NOT timed: the Comet block-store record the host saves
 * first (v2x_cmt_store_block — a node has it before FinalizeBlock),
 * envelope signing, the row counts.
 *
 *   wall ms        apply (nodus_witness_v2_apply_block) and commit
 *   ns/gas         (apply + commit) / Σ EVM gas used (receipts)
 *   db growth      PRAGMA page_count x page_size, after commit - before
 *   rows           evm_slots and evm_trie_nodes row-count deltas
 *   MPT root time  NOT SEPARABLE through any exported function: the
 *                  state trie is updated per mutation inside the apply
 *                  (nodus_witness_rt_evm.c trie_update, static) and the
 *                  domain root is read from the META row
 *                  (nodus_rt_evm_state_root). It is inside "apply".
 *
 * The workloads (default set; --workload picks others):
 *   (ii)  sstore-fresh   distinct never-written slots, 22 100 gas each;
 *   (i)   sload-present  distinct EXISTING slots, 2 100 gas each — the
 *                        slots are written first by --prefill-blocks
 *                        untimed sstore-fresh blocks (default 11: ~14 900
 *                        slots at 30 M, more than one 30 M-gas tx reads);
 *   (iii) op-jumpdest    the interpreter-dispatch loop;
 *   (iv)  every pc-* precompile workload (the engine bench names the
 *         worst by ns/gas; --workload narrows this to it).
 *
 * THE CHAIN. The test_v2_evm.c fixture shape, copied (that file is not
 * modified): a SEEDED version-3 genesis (v2_genesis_fixture.h, spendable
 * UTXOs — V2X_SEED_NOT_REAL_UTXOS), HF-2 and HF-3 on from height 1, the
 * generation-2 vote effective at 3, the EVM_ACTIVE vote at 5 and a
 * param-15 EVM_BLOCK_GAS_LIMIT row = --block-gas at 5 and a param-5 gas
 * price of 121 from height 1 (red-team 1 D1 stops the EVM at price 0; fee
 * coins are sized above every ceiling × 121), all written before
 * genesis; idle blocks 1..4. Every EVM transaction is the production
 * envelope shape [CORE EVMFUND fee leg] + [EVM CALL], both legs REALLY
 * signed by one ML-DSA-87 key; one key per transaction slot of a block
 * (design §8: one pending EVM tx per sender) plus a deployer. Contracts
 * are deployed by real CREATE envelopes (untimed blocks).
 *
 * Usage:
 *   bench_evm_apply [--block-gas G] [--tx-gas T] [--reps R]
 *                   [--prefill-blocks P] [--workload a,b,...] [--list]
 *   defaults: G 30 000 000, T = min(G, NODUS_RT_EVM_TX_GAS_CAP), R 3,
 *   P 11. A block carries ceil(G / T) transactions (the last one takes
 *   the remainder), their declared gas summing to exactly G.
 *
 * Leaves behind: one /tmp/bench_evm_apply_XXXXXX directory, removed at
 * the end (left behind if the process is killed or a step fails).
 *
 * HOW IT CAN LIE
 *   - One machine, one disk, a HOT page cache (the database was just
 *     written); a node reading cold pages pays the disk on top.
 *   - The database holds only this bench's state: a mainnet-sized
 *     evm_slots / evm_trie_nodes / utxo_set has deeper B-trees.
 *   - The seeded genesis, the pre-genesis votes and the empty Comet
 *     block-store Data are fixture departures (v2_genesis_fixture.h
 *     "HOW IT CAN LIE"); no consensus round, no gossip, no WAL replay.
 *   - acct-balance / acct-extcodesize here read ABSENT accounts (the
 *     engine bench pre-fills existing ones).
 *   - A refused item, a non-SUCCESS receipt or a loop that exits early
 *     is PRINTED (WARN / FAIL) — read every line, not only the summary.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_evm.h"
#include "witness/nodus_witness_domreg.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"

#include "v2_genesis_fixture.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/res_meter.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "evm/evm_precompile.h"
#include "evm/bench/evm_bench_wl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>

/* nodus_witness_cmt_node.c:1794 timeout_commit = 4000 ms (:1795
 * create_empty_blocks_interval = 60 000 ms) */
#define CMT_TIMEOUT_COMMIT_MS 4000.0

#define D2       ((uint64_t)DNAC_CFG_RULESET_GEN2_D2)
#define DEVM     ((uint64_t)DNAC_CFG_EVM_ACTIVE_D)
/* Red-team 1 D1 (operator decision 2026-10-05-nodus-evm-redteam1-
 * operator.md): an EVM CALL / CREATE / DEPOSIT is refused while the gas
 * price is 0, so the bench chain runs at BENCH_PRICE (the harness
 * chain's 121 raw per unit) from height 1. Every envelope's fee is one
 * FEE-exact coin with no change, so FEE must cover the largest
 * res_max_total_units × BENCH_PRICE the bench builds: static (≤ the
 * stream caps, 16 384 effects + 4 MiB, + the CORE leg) + 30 000 000 gas
 * + FAIL_RESERVE + 2 000 000 < 5 × 10^7 units; build_env refuses loudly
 * should a ceiling ever exceed FEE / BENCH_PRICE. */
#define BENCH_PRICE 121ull
#define FEE      (BENCH_PRICE * 50000000ull)
#define H2       3ull                 /* generation-2 effective height  */
#define HE       5ull                 /* EVM_ACTIVE effective height    */
#define AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)

#define MAX_WL   128

/* ══ machine / clock ══════════════════════════════════════════════════ */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static double peak_rss_mib(void) {
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1.0;
    return (double)ru.ru_maxrss / 1024.0;          /* Linux: KiB */
}

static void print_machine(void) {
    char model[256] = "unknown";
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *c = strchr(line, ':');
                if (c) {
                    c++;
                    while (*c == ' ' || *c == '\t') c++;
                    size_t n = strcspn(c, "\n");
                    if (n >= sizeof(model)) n = sizeof(model) - 1;
                    memcpy(model, c, n);
                    model[n] = '\0';
                }
                break;
            }
        }
        fclose(f);
    }
    printf("machine: cpu \"%s\", nproc %ld\n", model,
           sysconf(_SC_NPROCESSORS_ONLN));
}

/* ══ keys and coins ═══════════════════════════════════════════════════ */

typedef struct {
    uint8_t  pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t  sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t  fp[64];                  /* SHA3-512(pk): fp; [0..32] = the EVM
                                       * sender (design §2)              */
    char     hex[129];
    uint64_t nonce;                   /* EVM nonce                       */
    int      next_coin;
} bkey_t;

static bkey_t *g_k;
static int     g_nk;
static int     g_ncoin;               /* FEE-exact coins per key         */

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(int n) {
    g_k = calloc((size_t)n, sizeof(*g_k));
    if (!g_k) return -1;
    g_nk = n;
    for (int i = 0; i < n; i++) {
        uint8_t seed[32];
        memset(seed, 0x71, sizeof(seed));
        seed[0] = (uint8_t)(i >> 8);
        seed[1] = (uint8_t)i;
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, QGP_DSA87_PUBLICKEYBYTES, g_k[i].fp) != 0)
            return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* coin `idx` of key k: nullifier = SHA3-512(owner hex ‖ seed) (the
 * test_v2_evm.c coin_nul shape, wider seed: 2-byte key and index) */
static int coin_nul(int k, int idx, uint8_t out[64]) {
    uint8_t pre[160], s[32];
    memset(s, 0x5a, 32);
    s[0] = 0xB0;
    s[1] = (uint8_t)(k >> 8);
    s[2] = (uint8_t)k;
    s[3] = (uint8_t)(idx >> 8);
    s[4] = (uint8_t)idx;
    memcpy(pre, g_k[k].hex, 128);
    memcpy(pre + 128, s, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int seed_coins(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        goto fail;
    for (int k = 0; k < g_nk; k++) {
        for (int i = 0; i < g_ncoin; i++) {
            uint8_t nul[64];
            if (coin_nul(k, i, nul) != 0) goto fail;
            sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, g_k[k].hex, 128, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)FEE);
            if (sqlite3_step(st) != SQLITE_DONE) goto fail;
            sqlite3_reset(st);
        }
    }
    sqlite3_finalize(st);
    return sqlite3_exec(w->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK
               ? 0 : -1;
fail:
    sqlite3_finalize(st);
    sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

/* ══ the fixture (test_v2_evm.c fx_open_ex shape) ═════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
    uint64_t         h;              /* the next block height             */
} fixture_t;

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

/* ══ the timed host (v2x_cmt_host, v2_genesis_fixture.h, with clocks) ═ */

typedef struct {
    uint64_t apply_ns, commit_ns;
} blk_time_t;

/* BEGIN IMMEDIATE, the block-store record (untimed), the engine (timed),
 * COMMIT (timed). @return the engine rc (0 committed). */
static int host_apply(fixture_t *fx, const nodus_v2_envelope_t *v, size_t n,
                      nodus_v2_tx_result_t *res, blk_time_t *t) {
    nodus_witness_t *w = fx->w;
    nodus_v2_block_t *b = calloc(1, sizeof(*b));
    if (!b) return V2X_CMT_FIXTURE_ERR;
    mk_block(b, fx->h, v, n);
    memset(res, 0, n * sizeof(*res));
    b->cmt.on = true;
    b->cmt.results = res;
    b->cmt.results_cap = n;
    if (sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) !=
        SQLITE_OK) {
        free(b);
        return V2X_CMT_FIXTURE_ERR;
    }
    uint8_t hash[64], nvh[64], prop[32];
    uint64_t secs = 0;
    int src = v2x_cmt_store_block(w, b->global_height, hash, nvh, prop,
                                  &secs);
    if (src < 0) {
        (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        free(b);
        return V2X_CMT_FIXTURE_ERR;
    }
    if (src == 0) {
        memcpy(b->cmt.block_hash, hash, 64);
        memcpy(b->cmt.validators_hash, nvh, 64);
        memcpy(b->proposer_id, prop, 32);
        b->timestamp = secs;
    } else {
        v2x_cmt_probe_ids(w, b);
    }
    uint64_t t0 = now_ns();
    int rc = nodus_witness_v2_apply_block(w, b);
    uint64_t t1 = now_ns();
    if (rc != 0) {
        (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        fprintf(stderr, "apply: height %llu rc %d: %s\n",
                (unsigned long long)b->global_height, rc, b->out_reason);
        free(b);
        return rc;
    }
    uint64_t t2 = now_ns();
    if (sqlite3_exec(w->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        free(b);
        return V2X_CMT_FIXTURE_ERR;
    }
    uint64_t t3 = now_ns();
    if (t) {
        t->apply_ns = t1 - t0;
        t->commit_ns = t3 - t2;
    }
    fx->h++;
    free(b);
    return 0;
}

static int fx_to(fixture_t *fx, uint64_t target) {
    nodus_v2_tx_result_t r[1];
    while (fx->h < target)
        if (host_apply(fx, NULL, 0, r, NULL) != 0) return -1;
    return 0;
}

/* HF-2 + HF-3 from 1, generation 2 at H2, EVM_ACTIVE at HE, param 15 =
 * block_gas at HE, the coins; genesis; idle blocks to HE */
static int fx_open(fixture_t *fx, uint64_t block_gas) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/bench_evm_apply_XXXXXX");
    if (!mkdtemp(fx->dir)) {
        free(fx->w);
        fx->w = NULL;
        return -1;
    }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x45, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
            != 0 ||
        cc_row(fx->w, DNAC_CFG_HF3_ACTIVE, DNAC_CFG_HF3_ACTIVE_ON, 1, 12)
            != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN2, D2, H2, 13) != 0 ||
        cc_row(fx->w, DNAC_CFG_EVM_ACTIVE, DEVM, HE, 14) != 0 ||
        cc_row(fx->w, DNAC_CFG_EVM_BLOCK_GAS_LIMIT, block_gas, HE, 15) != 0 ||
        /* D1: a non-zero gas price from height 1 (see BENCH_PRICE) */
        cc_row(fx->w, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, BENCH_PRICE, 1, 16)
            != 0)
        return -1;
    if (seed_coins(fx->w) != 0) return -1;
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL) != 0)
        return -1;
    fx->h = 1;
    return fx_to(fx, HE);
}

/* ══ envelopes (test_v2_evm.c build_tx, FEE role, one FEE-exact coin) ═ */

static size_t put_be(uint8_t *p, uint64_t v, int n) {
    for (int i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    return (size_t)n;
}

/* design §2 CALL encoding (test_v2_evm.c enc_call, value 0, no access
 * list) */
static size_t enc_call(uint8_t *d, const uint8_t to[32], uint64_t gas,
                       uint64_t nonce, const uint8_t *data, uint32_t dl) {
    size_t o = 0;
    d[o++] = 1;
    memcpy(d + o, to, 32); o += 32;
    memset(d + o, 0, 32); o += 32;              /* value 0 */
    o += put_be(d + o, gas, 8);
    o += put_be(d + o, nonce, 8);
    o += put_be(d + o, 0, 2);                   /* no access list */
    o += put_be(d + o, dl, 4);
    if (dl) memcpy(d + o, data, dl);
    return o + dl;
}

static size_t enc_create(uint8_t *d, uint64_t gas, uint64_t nonce,
                         const uint8_t *init, uint32_t il) {
    size_t o = 0;
    d[o++] = 1;
    memset(d + o, 0, 32); o += 32;              /* value 0 */
    o += put_be(d + o, gas, 8);
    o += put_be(d + o, nonce, 8);
    o += put_be(d + o, 0, 2);
    o += put_be(d + o, il, 4);
    memcpy(d + o, init, il);
    return o + il;
}

static const nodus_domain_runtime_t *gevm(uint32_t dom) {
    return nodus_runtime_for_generation(NODUS_RT_GEN_EVM, dom);
}

/**
 * One [CORE EVMFUND fee] + [EVM op] envelope from key k at the next
 * height. The EVM leg declares the streamed-leg maxima
 * (DNA_METER_STREAM_MAX_EFFECTS / _EFFECT_BYTES) so a slot-heavy leg
 * fits; the ceiling = static units + gas x DNA_METER_EVM_W_GAS +
 * DNA_METER_EVM_FAIL_RESERVE + 2 000 000 read headroom (test_v2_evm.c's
 * non-exact ceiling). @return 0 / -1.
 */
static int build_env(fixture_t *fx, int k, uint32_t evm_op,
                     const uint8_t *call, uint32_t call_len, uint64_t gas,
                     uint8_t **bytes, size_t *len) {
    static uint8_t ccall[2 + 1 + 64 + 1];
    static uint8_t auth[2][AUTH_LEN];
    if (g_k[k].next_coin >= g_ncoin) {
        fprintf(stderr, "key %d: out of fee coins\n", k);
        return -1;
    }
    uint8_t coin[64];
    if (coin_nul(k, g_k[k].next_coin++, coin) != 0) return -1;

    dna_env_leg_in_t legs[2];
    dna_env_leg_ctx_t lctx[2];
    memset(legs, 0, sizeof(legs));
    memset(lctx, 0, sizeof(lctx));

    /* leg 0: CORE EVMFUND, role FEE, one input, no change */
    size_t off = 0;
    ccall[off++] = NODUS_RT_EVMFUND_CALL_VER;
    ccall[off++] = NODUS_RT_EVMFUND_ROLE_FEE;
    ccall[off++] = 1;
    memcpy(ccall + off, coin, 64); off += 64;
    ccall[off++] = 0;
    dna_domain_manifest_t core;
    if (nodus_witness_domreg_get(fx->w, DNA_DOMAIN_CORE, NULL, &core, NULL)
        != 0)
        return -1;
    /* the exact result: SET pool + DELETE input */
    const uint32_t neff = 2;
    legs[0].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[0].hdr.runtime_op = DNA_CORERULE_EVMFUND;
    legs[0].hdr.ruleset_version = core.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = (uint32_t)off;
    legs[0].hdr.auth_len = AUTH_LEN;
    legs[0].hdr.res_max_effects = neff;
    legs[0].hdr.res_max_effect_bytes =
        (uint32_t)DNA_EFFECT_FIXED_HEAD +
        (uint32_t)DNA_EFFECT_RECORD_LEN * neff + (1u + 8u) + 64u;
    legs[0].call_data = ccall;
    memset(auth[0], 0, AUTH_LEN);
    legs[0].auth_data = auth[0];
    lctx[0].domain_id = DNA_DOMAIN_CORE;
    lctx[0].ruleset_version = core.ruleset_version;
    memcpy(lctx[0].ruleset_hash, core.ruleset_hash, 64);

    /* leg 1: EVM */
    dna_domain_manifest_t em;
    if (nodus_witness_domreg_get(fx->w, DNA_DOMAIN_EVM, NULL, &em, NULL) != 0)
        return -1;
    legs[1].hdr.domain_id = DNA_DOMAIN_EVM;
    legs[1].hdr.runtime_op = evm_op;
    legs[1].hdr.ruleset_version = em.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = call_len;
    legs[1].hdr.auth_len = AUTH_LEN;
    legs[1].hdr.res_max_effects = DNA_METER_STREAM_MAX_EFFECTS;
    legs[1].hdr.res_max_effect_bytes = DNA_METER_STREAM_MAX_EFFECT_BYTES;
    legs[1].call_data = call;
    memset(auth[1], 0, AUTH_LEN);
    legs[1].auth_data = auth[1];
    lctx[1].domain_id = DNA_DOMAIN_EVM;
    lctx[1].ruleset_version = em.ruleset_version;
    memcpy(lctx[1].ruleset_hash, em.ruleset_hash, 64);

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.leg_count = 2;
    in.legs = legs;

    /* the static units under the EVM generation's policy */
    const nodus_domain_runtime_t *sys = gevm(DNA_DOMAIN_SYSTEM);
    if (!sys || !sys->meter_policy) return -1;
    in.res_max_total_units = (uint64_t)INT32_MAX;
    size_t elen = 0, used = 0;
    if (dna_env_encoded_size(legs, 2, &elen) != 0) return -1;
    uint8_t *tmp = malloc(elen);
    dna_env_view_t *view = calloc(1, sizeof(*view));
    dna_meter_plan_t *plan = calloc(1, sizeof(*plan));
    int ok = -1;
    if (tmp && view && plan &&
        dna_env_encode(&in, tmp, elen, &used) == 0 && used == elen &&
        dna_env_decode(tmp, elen, view) == 0 &&
        dna_meter_plan_build_ex(sys->meter_policy, view, 2, plan) ==
            DNA_METER_OK)
        ok = 0;
    uint64_t stat = plan ? plan->static_total : 0;
    free(tmp);
    free(view);
    free(plan);
    if (ok != 0) {
        fprintf(stderr, "build_env: the meter plan refused the envelope\n");
        return -1;
    }
    in.res_max_total_units = stat + gas * DNA_METER_EVM_W_GAS +
                             DNA_METER_EVM_FAIL_RESERVE + 2000000ull;
    if (in.res_max_total_units > FEE / BENCH_PRICE) {
        fprintf(stderr, "build_env: ceiling %llu units x price %llu exceeds "
                "the fee coin %llu\n",
                (unsigned long long)in.res_max_total_units,
                (unsigned long long)BENCH_PRICE, (unsigned long long)FEE);
        return -1;
    }

    uint8_t *auths[2] = { auth[0], auth[1] };
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    nodus_v2_spend_err_t err;
    memset(&err, 0, sizeof(err));
    int rc = nodus_v2_env_sign_one_key(&in, auths, lctx, fx->w->v2_chain32,
                                       fx->h - 1u, g_k[k].pk, g_k[k].sk,
                                       bytes, len, pf, &err);
    free(pf);
    if (rc != NODUS_V2_SPEND_OK) {
        fprintf(stderr, "build_env: signing failed (rc %d, leg %d)\n", rc,
                err.leg);
        return -1;
    }
    return 0;
}

/* ══ observations ═════════════════════════════════════════════════════ */

/** Receipt (design §7): status u8 @16 (1 = success), gas u64 @18. */
static int receipt_at(nodus_witness_t *w, uint64_t h, size_t item,
                      int *status, uint64_t *gas, uint8_t created[32]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT receipt FROM evm_receipts WHERE global_height = ?1 "
            "AND item_index = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)item);
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) >= 58) {
        const uint8_t *r = sqlite3_column_blob(st, 0);
        uint64_t g = 0;
        for (int i = 0; i < 8; i++) g = (g << 8) | r[18 + i];
        *status = r[16];
        *gas = g;
        if (created) memcpy(created, r + 26, 32);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/* the committed EVM nonce of a sender (test_v2_evm.c acct_nonce): 0 when
 * the account does not exist yet, UINT64_MAX on a read failure */
static uint64_t acct_nonce(nodus_witness_t *w, const uint8_t addr[32]) {
    sqlite3_stmt *st = NULL;
    uint64_t v = UINT64_MAX;
    if (sqlite3_prepare_v2(w->db,
            "SELECT nonce FROM evm_accounts WHERE addr = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return v;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) v = (uint64_t)sqlite3_column_int64(st, 0);
    else if (rc == SQLITE_DONE) v = 0;
    sqlite3_finalize(st);
    return v;
}

static int64_t q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int64_t v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int64_t db_bytes(nodus_witness_t *w) {
    int64_t pc = q1(w, "PRAGMA page_count");
    int64_t ps = q1(w, "PRAGMA page_size");
    return (pc < 0 || ps < 0) ? -1 : pc * ps;
}

static int64_t slots_of(nodus_witness_t *w, const uint8_t addr[32]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM evm_slots WHERE "
                           "addr = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int64_t v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* ══ contracts ════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *code;
    size_t   len;
    uint8_t  addr[32];
} deployed_t;

static deployed_t g_dep[MAX_WL];
static int        g_ndep;

static int deploy(fixture_t *fx, const uint8_t *rt, size_t rl,
                  uint64_t block_gas, uint8_t addr_out[32]) {
    for (int i = 0; i < g_ndep; i++)
        if (g_dep[i].len == rl && memcmp(g_dep[i].code, rt, rl) == 0) {
            memcpy(addr_out, g_dep[i].addr, 32);
            return 0;
        }
    if (g_ndep >= MAX_WL) return -1;
    uint8_t *init = NULL, *call = NULL, *env = NULL;
    size_t il = 0, envl = 0;
    int ret = -1;
    uint64_t gas = 200000u + 260u * (uint64_t)rl;
    if (gas > NODUS_RT_EVM_TX_GAS_CAP) gas = NODUS_RT_EVM_TX_GAS_CAP;
    if (gas > block_gas) gas = block_gas;
    if (wl_initcode(rt, rl, &init, &il) != 0) return -1;
    call = malloc(100 + il);
    if (!call) goto out;
    size_t cl = enc_create(call, gas, g_k[0].nonce, init, (uint32_t)il);
    if (build_env(fx, 0, NODUS_RT_EVM_CREATE, call, (uint32_t)cl, gas, &env,
                  &envl) != 0)
        goto out;
    nodus_v2_envelope_t v = { env, envl };
    nodus_v2_tx_result_t res[1];
    uint64_t h = fx->h;
    if (host_apply(fx, &v, 1, res, NULL) != 0 ||
        res[0].code != NODUS_V2_TX_OK) {
        fprintf(stderr, "deploy: the CREATE item was refused (code %u)\n",
                (unsigned)res[0].code);
        goto out;
    }
    g_k[0].nonce++;
    int status = 0;
    uint64_t g = 0;
    if (receipt_at(fx->w, h, 0, &status, &g, addr_out) != 0 || status != 1) {
        fprintf(stderr, "deploy: CREATE did not succeed (receipt status "
                "%d)\n", status);
        goto out;
    }
    g_dep[g_ndep].code = malloc(rl);
    if (!g_dep[g_ndep].code) goto out;
    memcpy(g_dep[g_ndep].code, rt, rl);
    g_dep[g_ndep].len = rl;
    memcpy(g_dep[g_ndep].addr, addr_out, 32);
    g_ndep++;
    ret = 0;
out:
    free(init);
    free(call);
    free(env);
    return ret;
}

/* ══ one block of one workload ════════════════════════════════════════ */

typedef struct {
    uint64_t block_gas, tx_gas, last_gas;
    int      n_tx;
} shape_t;

typedef struct {
    double   apply_ms, commit_ms, ns_per_gas;
    uint64_t evm_gas;
    int64_t  db_growth, slots_delta, trie_delta;
    int      ok_receipts;
} blk_res_t;

/* the storage workloads' next fresh slot / per-tx read stride */
static uint64_t g_next_slot;

static int run_block(fixture_t *fx, const shape_t *sh, wl_inst_t *full,
                     wl_inst_t *last, const uint8_t to[32], int timed,
                     blk_res_t *out) {
    int n = sh->n_tx;
    nodus_v2_envelope_t *v = calloc((size_t)n, sizeof(*v));
    nodus_v2_tx_result_t *res = calloc((size_t)n, sizeof(*res));
    uint8_t **bytes = calloc((size_t)n, sizeof(*bytes));
    int ret = -1;
    memset(out, 0, sizeof(*out));
    if (!v || !res || !bytes) goto done;

    const char *nm = full->def->name;
    const int is_sstore = (strcmp(nm, "sstore-fresh") == 0);
    const int is_present = (strcmp(nm, "sload-present") == 0);
    const int is_absent = (strcmp(nm, "sload-absent") == 0);
    for (int i = 0; i < n; i++) {
        wl_inst_t *wi = (i == n - 1) ? last : full;
        uint64_t gas = (i == n - 1) ? sh->last_gas : sh->tx_gas;
        if (is_sstore) {
            /* a tx writes < gas / 22 100 slots (22 100 + loop overhead
             * each), so the next tx starts past them: the written slots
             * are contiguous but for a gap of a few slots per tx */
            wl_set_slot_base(wi, g_next_slot);
            g_next_slot += gas / 22100u + 1u;
        } else if (is_present) {
            /* tx i reads [i x stride, ...): distinct per tx, from 0 */
            wl_set_slot_base(wi, (uint64_t)i * (gas / 2100u + 64u));
        } else if (is_absent) {
            /* far above every written slot */
            wl_set_slot_base(wi, (1ull << 48) +
                                 (uint64_t)i * (gas / 2100u + 64u));
        }
        int k = 1 + i;
        uint8_t *call = malloc(100 + wi->data_len);
        if (!call) goto done;
        size_t cl = enc_call(call, to, gas, g_k[k].nonce, wi->data,
                             (uint32_t)wi->data_len);
        size_t el = 0;
        int rc = build_env(fx, k, NODUS_RT_EVM_CALL, call, (uint32_t)cl, gas,
                           &bytes[i], &el);
        free(call);
        if (rc != 0) goto done;
        v[i].env_bytes = bytes[i];
        v[i].env_len = el;
    }

    int64_t slots0 = 0, trie0 = 0, db0 = 0;
    if (timed) {
        slots0 = q1(fx->w, "SELECT COUNT(*) FROM evm_slots");
        trie0 = q1(fx->w, "SELECT COUNT(*) FROM evm_trie_nodes");
        db0 = db_bytes(fx->w);
    }
    uint64_t h = fx->h;
    if (timed && h % (uint64_t)DNAC_EPOCH_LENGTH == 0)
        printf("    WARN height %llu is an epoch boundary (E = %llu): the "
               "block also carries the epoch work\n",
               (unsigned long long)h, (unsigned long long)DNAC_EPOCH_LENGTH);
    blk_time_t t;
    memset(&t, 0, sizeof(t));
    if (host_apply(fx, v, (size_t)n, res, &t) != 0) {
        printf("    FAIL height %llu: the block did not commit\n",
               (unsigned long long)h);
        goto done;
    }
    /* the senders' nonces from the committed state: an applied item moved
     * its sender's nonce, a refused one did not */
    for (int i = 0; i < n; i++) {
        uint64_t nn = acct_nonce(fx->w, g_k[1 + i].fp);
        if (nn == UINT64_MAX) {
            printf("    FAIL height %llu: sender %d nonce unreadable\n",
                   (unsigned long long)h, 1 + i);
            goto done;
        }
        g_k[1 + i].nonce = nn;
    }
    for (int i = 0; i < n; i++) {
        if (res[i].code != NODUS_V2_TX_OK) {
            printf("    FAIL height %llu item %d refused (code %u) — the "
                   "workload is aborted\n",
                   (unsigned long long)h, i, (unsigned)res[i].code);
            goto done;
        }
        int status = 0;
        uint64_t g = 0;
        if (receipt_at(fx->w, h, (size_t)i, &status, &g, NULL) != 0) {
            printf("    FAIL height %llu item %d: no receipt\n",
                   (unsigned long long)h, i);
            goto done;
        }
        if (status == 1) out->ok_receipts++;
        out->evm_gas += g;
    }
    out->apply_ms = (double)t.apply_ns / 1e6;
    out->commit_ms = (double)t.commit_ns / 1e6;
    out->ns_per_gas = out->evm_gas
        ? (double)(t.apply_ns + t.commit_ns) / (double)out->evm_gas : 0.0;
    if (timed) {
        out->slots_delta = q1(fx->w, "SELECT COUNT(*) FROM evm_slots") - slots0;
        out->trie_delta = q1(fx->w, "SELECT COUNT(*) FROM evm_trie_nodes") -
                          trie0;
        out->db_growth = db_bytes(fx->w) - db0;
    }
    ret = 0;
done:
    if (bytes)
        for (int i = 0; i < n; i++) free(bytes[i]);
    free(bytes);
    free(v);
    free(res);
    return ret;
}

/* ══ driver ═══════════════════════════════════════════════════════════ */

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

typedef struct {
    const wl_def_t *def;
    double med_apply, med_commit, med_nspg;
    uint64_t evm_gas;
    int ran;
} sum_t;

static int cmp_sum(const void *a, const void *b) {
    const sum_t *x = a, *y = b;
    if (x->med_nspg < y->med_nspg) return 1;
    if (x->med_nspg > y->med_nspg) return -1;
    return 0;
}

static void usage(void) {
    printf("usage: bench_evm_apply [--block-gas G] [--tx-gas T] [--reps R] "
           "[--prefill-blocks P] [--workload a,b,...] [--list]\n");
}

int main(int argc, char **argv) {
    uint64_t block_gas = DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT;
    uint64_t tx_gas = 0;
    unsigned reps = 3, prefill = 11;
    const wl_def_t *sel[MAX_WL];
    size_t n_sel = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--block-gas") == 0 && i + 1 < argc) {
            block_gas = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--tx-gas") == 0 && i + 1 < argc) {
            tx_gas = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--reps") == 0 && i + 1 < argc) {
            reps = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--prefill-blocks") == 0 && i + 1 < argc) {
            prefill = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--workload") == 0 && i + 1 < argc) {
            for (char *tok = strtok(argv[++i], ","); tok;
                 tok = strtok(NULL, ",")) {
                const wl_def_t *d = wl_find(tok);
                if (!d || !d->node_ok) {
                    printf("unknown or engine-only workload: %s (--list)\n",
                           tok);
                    return 2;
                }
                if (n_sel < MAX_WL) sel[n_sel++] = d;
            }
        } else if (strcmp(argv[i], "--list") == 0) {
            for (size_t k = 0; k < wl_count(); k++)
                if (wl_get(k)->node_ok)
                    printf("%-24s %s\n", wl_get(k)->name, wl_get(k)->why);
            return 0;
        } else {
            usage();
            return 2;
        }
    }
    if (tx_gas == 0)
        tx_gas = block_gas < NODUS_RT_EVM_TX_GAS_CAP
                     ? block_gas : NODUS_RT_EVM_TX_GAS_CAP;
    if (block_gas < DNAC_CFG_MIN_EVM_BLOCK_GAS ||
        block_gas > DNAC_CFG_MAX_EVM_BLOCK_GAS ||
        tx_gas < 100000u || tx_gas > NODUS_RT_EVM_TX_GAS_CAP ||
        tx_gas > block_gas || reps == 0 || reps > 1000) {
        printf("bad parameters: block gas must be a votable value "
               "[%llu, %llu], tx gas in [100000, min(block gas, %llu)]\n",
               (unsigned long long)DNAC_CFG_MIN_EVM_BLOCK_GAS,
               (unsigned long long)DNAC_CFG_MAX_EVM_BLOCK_GAS,
               (unsigned long long)NODUS_RT_EVM_TX_GAS_CAP);
        return 2;
    }
    if (n_sel == 0) {
        sel[n_sel++] = wl_find("sstore-fresh");
        sel[n_sel++] = wl_find("sload-present");
        sel[n_sel++] = wl_find("op-jumpdest");
        for (size_t k = 0; k < wl_count() && n_sel < MAX_WL; k++)
            if (wl_get(k)->group == WL_GROUP_PRECOMPILE)
                sel[n_sel++] = wl_get(k);
    }

    shape_t sh;
    sh.block_gas = block_gas;
    sh.tx_gas = tx_gas;
    sh.n_tx = (int)((block_gas + tx_gas - 1) / tx_gas);
    sh.last_gas = block_gas - (uint64_t)(sh.n_tx - 1) * tx_gas;
    if (sh.n_tx + 1 > 60000) {
        printf("too many transactions per block\n");
        return 2;
    }

    printf("Nodus EVM measurement gate (b): EVM blocks through "
           "nodus_witness_v2_apply_block (the FinalizeBlock entry)\n");
    print_machine();
    printf("block gas %llu (param 15 row), %d tx/block of %llu gas (last "
           "%llu), reps %u, prefill %u blocks; EVM_TX_GAS_CAP %llu; "
           "DNAC_EPOCH_LENGTH %llu; Comet timeout_commit %.0f ms "
           "(nodus_witness_cmt_node.c:1794)\n",
           (unsigned long long)block_gas, sh.n_tx,
           (unsigned long long)tx_gas, (unsigned long long)sh.last_gas, reps,
           prefill, (unsigned long long)NODUS_RT_EVM_TX_GAS_CAP,
           (unsigned long long)DNAC_EPOCH_LENGTH, CMT_TIMEOUT_COMMIT_MS);
    if (evm_precompile_selftest() != 0) {
        printf("FAIL: evm_precompile_selftest\n");
        return 1;
    }

    /* instances: one per (workload, gas) — precompile sizing runs once */
    wl_inst_t *ifull = calloc(n_sel, sizeof(*ifull));
    wl_inst_t *ilast = calloc(n_sel, sizeof(*ilast));
    int *usable = calloc(n_sel, sizeof(int));
    wl_inst_t pre_full, pre_last;
    memset(&pre_full, 0, sizeof(pre_full));
    memset(&pre_last, 0, sizeof(pre_last));
    if (!ifull || !ilast || !usable) return 1;
    for (size_t s = 0; s < n_sel; s++) {
        char msg[256];
        wl_params_t pf = { tx_gas, 0 }, pl = { sh.last_gas, 0 };
        int r1 = wl_build(sel[s], &pf, &ifull[s], msg, sizeof(msg));
        int r2 = r1 == 0 ? wl_build(sel[s], &pl, &ilast[s], msg, sizeof(msg))
                         : r1;
        if (r1 != 0 || r2 != 0) {
            printf("%-24s %s at tx gas %llu / %llu: %s\n", sel[s]->name,
                   (r1 == -1 || r2 == -1) ? "SKIP" : "FAIL",
                   (unsigned long long)tx_gas,
                   (unsigned long long)sh.last_gas, msg);
            if (r1 == 0) wl_inst_free(&ifull[s]);
            continue;
        }
        usable[s] = 1;
    }
    int need_prefill = 0;
    for (size_t s = 0; s < n_sel; s++)
        if (usable[s] && strcmp(sel[s]->name, "sload-present") == 0)
            need_prefill = 1;
    if (need_prefill && prefill > 0) {
        char msg[256];
        wl_params_t pf = { tx_gas, 0 }, pl = { sh.last_gas, 0 };
        if (wl_build(wl_find("sstore-fresh"), &pf, &pre_full, msg,
                     sizeof(msg)) != 0 ||
            wl_build(wl_find("sstore-fresh"), &pl, &pre_last, msg,
                     sizeof(msg)) != 0) {
            printf("FAIL: prefill instance: %s\n", msg);
            return 1;
        }
    }

    /* keys: 0 = deployer, 1..n_tx = one per transaction slot; coins: one
     * per block a key sends in (+ deploys for key 0) */
    unsigned total_blocks = (need_prefill ? prefill : 0) + MAX_WL + 8;
    for (size_t s = 0; s < n_sel; s++)
        if (usable[s]) total_blocks += reps;
    if (total_blocks > 65000) {
        printf("too many blocks\n");
        return 2;
    }
    g_ncoin = (int)total_blocks;
    uint64_t t_setup = now_ns();
    if (keys_make(sh.n_tx + 1) != 0) {
        printf("FAIL: key generation\n");
        return 1;
    }
    fixture_t fx;
    if (fx_open(&fx, block_gas) != 0) {
        printf("FAIL: fixture (seeded genesis / activation blocks)\n");
        fx_close(&fx);
        return 1;
    }
    printf("setup: %d keys x %d fee coins, chain at height %llu, %.1f s\n",
           g_nk, g_ncoin, (unsigned long long)fx.h,
           (double)(now_ns() - t_setup) / 1e9);

    /* deploy every contract (deduplicated by code) */
    uint8_t (*to)[32] = calloc(n_sel, 32);
    if (!to) return 1;
    for (size_t s = 0; s < n_sel; s++) {
        if (!usable[s]) continue;
        if (deploy(&fx, ifull[s].code, ifull[s].code_len, block_gas,
                   to[s]) != 0) {
            printf("%-24s FAIL deploy\n", sel[s]->name);
            usable[s] = 0;
        }
    }
    int failed = 0;
    uint8_t store_addr[32];
    memset(store_addr, 0, 32);
    if (need_prefill && prefill > 0) {
        if (deploy(&fx, pre_full.code, pre_full.code_len, block_gas,
                   store_addr) != 0) {
            printf("FAIL: deploy of the storage contract\n");
            fx_close(&fx);
            return 1;
        }
        uint64_t t0 = now_ns();
        for (unsigned b = 0; b < prefill; b++) {
            blk_res_t br;
            if (run_block(&fx, &sh, &pre_full, &pre_last, store_addr, 0,
                          &br) != 0) {
                printf("FAIL: prefill block %u\n", b);
                fx_close(&fx);
                return 1;
            }
        }
        printf("prefill: %u sstore-fresh blocks, %lld slots present, %.1f s"
               "\n", prefill, (long long)slots_of(fx.w, store_addr),
               (double)(now_ns() - t0) / 1e9);
    }
    fflush(stdout);

    sum_t *sum = calloc(n_sel, sizeof(*sum));
    double *a_ms = calloc(reps, sizeof(double));
    double *c_ms = calloc(reps, sizeof(double));
    double *nspg = calloc(reps, sizeof(double));
    if (!sum || !a_ms || !c_ms || !nspg) return 1;
    size_t n_sum = 0;
    for (size_t s = 0; s < n_sel; s++) {
        if (!usable[s]) continue;
        const wl_def_t *d = sel[s];
        printf("\n%s — %s\n", d->name, d->why);
        if (strcmp(d->name, "sload-present") == 0)
            printf("  present slots %lld (written by the prefill and any "
                   "sstore-fresh blocks); tx i reads ~%llu distinct slots "
                   "from slot i x %llu — reads past the present count are "
                   "misses\n",
                   (long long)slots_of(fx.w, to[s]),
                   (unsigned long long)(tx_gas / 2145u),
                   (unsigned long long)(tx_gas / 2100u + 64u));
        if (ifull[s].pc_addr)
            printf("  precompile 0x%02x: %llu bytes/call, k %llu, exact cost "
                   "%llu gas/call\n", ifull[s].pc_addr,
                   (unsigned long long)ifull[s].pc_input_len,
                   (unsigned long long)ifull[s].pc_k,
                   (unsigned long long)ifull[s].pc_cost);
        unsigned done = 0;
        uint64_t gas_last = 0;
        for (unsigned r = 0; r < reps; r++) {
            blk_res_t br;
            uint64_t h = fx.h;
            if (run_block(&fx, &sh, &ifull[s], &ilast[s], to[s], 1, &br)
                != 0) {
                failed = 1;
                break;
            }
            printf("  h %-6llu txs %d ok %d  evm_gas %10llu  apply %9.2f ms"
                   "  commit %8.2f ms  ns/gas %8.3f  db +%lld B  slots +%lld"
                   "  trie_nodes +%lld\n",
                   (unsigned long long)h, sh.n_tx, br.ok_receipts,
                   (unsigned long long)br.evm_gas, br.apply_ms, br.commit_ms,
                   br.ns_per_gas, (long long)br.db_growth,
                   (long long)br.slots_delta, (long long)br.trie_delta);
            if (br.ok_receipts != sh.n_tx)
                printf("    WARN %d of %d receipts are not SUCCESS — the "
                       "number measures a failure path\n",
                       sh.n_tx - br.ok_receipts, sh.n_tx);
            if (br.evm_gas + (uint64_t)sh.n_tx * (ifull[s].slack + 50000u) <
                block_gas)
                printf("    WARN the block used less gas than its limit "
                       "minus one loop iteration per tx\n");
            a_ms[done] = br.apply_ms;
            c_ms[done] = br.commit_ms;
            nspg[done] = br.ns_per_gas;
            gas_last = br.evm_gas;
            done++;
        }
        if (done == 0) continue;
        qsort(a_ms, done, sizeof(double), cmp_dbl);
        qsort(c_ms, done, sizeof(double), cmp_dbl);
        qsort(nspg, done, sizeof(double), cmp_dbl);
        sum[n_sum].def = d;
        sum[n_sum].med_apply = a_ms[done / 2];
        sum[n_sum].med_commit = c_ms[done / 2];
        sum[n_sum].med_nspg = nspg[done / 2];
        sum[n_sum].evm_gas = gas_last;
        sum[n_sum].ran = 1;
        n_sum++;
        printf("  median apply %.2f ms, commit %.2f ms, ns/gas %.3f; process "
               "peak RSS %.1f MiB (cumulative)\n", a_ms[done / 2],
               c_ms[done / 2], nspg[done / 2], peak_rss_mib());
        fflush(stdout);
    }

    qsort(sum, n_sum, sizeof(*sum), cmp_sum);
    printf("\nSUMMARY (worst ns/gas first; ns/gas = (apply + commit) / EVM "
           "gas used). \"ms@block\" = median apply + commit of one %llu-gas "
           "block, to compare with timeout_commit %.0f ms\n",
           (unsigned long long)block_gas, CMT_TIMEOUT_COMMIT_MS);
    printf("%-24s %10s %12s %12s %12s\n", "workload", "ns/gas", "apply_ms",
           "commit_ms", "ms@block");
    for (size_t i = 0; i < n_sum; i++)
        printf("%-24s %10.3f %12.2f %12.2f %12.2f\n", sum[i].def->name,
               sum[i].med_nspg, sum[i].med_apply, sum[i].med_commit,
               sum[i].med_apply + sum[i].med_commit);

    for (size_t s = 0; s < n_sel; s++)
        if (usable[s]) {
            wl_inst_free(&ifull[s]);
            wl_inst_free(&ilast[s]);
        }
    wl_inst_free(&pre_full);
    wl_inst_free(&pre_last);
    for (int i = 0; i < g_ndep; i++) free(g_dep[i].code);
    free(ifull);
    free(ilast);
    free(usable);
    free(to);
    free(sum);
    free(a_ms);
    free(c_ms);
    free(nspg);
    free(g_k);
    fx_close(&fx);
    return failed ? 1 : 0;
}
