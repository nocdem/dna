/* dna_bench_native.c — in-process TPS bench, one nodus client per wallet.
 *
 * Architecture (2026-04-28 rewrite): no fork-exec per send. Each wallet
 * runs in its own thread with its own nodus_client_t, its own loaded
 * Dilithium keypair, and its own UTXO chain state. Sends build TX
 * structs via dnac_tx_*, sign with qgp_dsa87_sign, submit via
 * nodus_client_dnac_spend. All directly via libdna.so (which re-exports
 * libdnac + libnodus + qgp_dsa symbols).
 *
 * Per-wallet round_dt drops from ~14-21s (fork-exec) to ~1-3s (just the
 * witness BFT commit window). 1+ TPS sustained achievable.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <dnac/dnac.h>
#include <dnac/transaction.h>
#include <nodus/nodus.h>
#include <nodus/nodus_types.h>
#include "crypto/nodus_identity.h"   /* nodus_identity_import/clear */

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_types.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* All external APIs declared via headers above. */

/* ── Per-wallet state ──────────────────────────────────────────── */

#define MAX_WALLETS 256

struct bench_wallet {
    int     idx;
    char    data_dir[1024];   /* <pool>/wXX/.dna */
    char    fp[160];          /* 128 hex + nul */
    nodus_identity_t identity;
    qgp_key_t *dsa_key;       /* signs DNAC TXs (private + public) */
    nodus_client_t client;
    bool    client_ready;

    /* Current spendable UTXO (in-memory chain). */
    pthread_mutex_t state_mu;
    uint8_t  cur_tx_hash[64];
    uint32_t cur_output_index;
    uint64_t cur_amount;
    uint8_t  cur_nullifier[64];

    /* Counters. */
    atomic_int submit;
    atomic_int commit;
    atomic_int fail;
    char     last_error[256];
    pthread_mutex_t err_mu;
};

static struct bench_wallet g_wallets[MAX_WALLETS];
static int g_wallet_count = 0;

/* Global counters (atomic for live-tick reads). */
static atomic_int g_total_submit  = 0;
static atomic_int g_total_commit  = 0;
static atomic_int g_total_fail    = 0;
static atomic_int g_run_done      = 0;
static uint64_t   g_run_started_ns = 0;

/* Recipient pool (for mesh) — array of FPs. Set by main. */
static char g_recipients[MAX_WALLETS][160];
static int  g_recipient_count = 0;

/* Output paths. */
static char g_run_dir[1024];
static char g_tx_hashes_path[1280];
static FILE *g_tx_hashes_fp = NULL;
static pthread_mutex_t g_tx_mu = PTHREAD_MUTEX_INITIALIZER;

/* Chain identity, queried once via nodus_client_dnac_supply at startup.
 * Bound into every TX preimage via tx->chain_id (32 bytes). */
static uint8_t g_chain_id[32] = {0};
static bool    g_chain_id_set = false;

/* ── Time helpers ──────────────────────────────────────────────── */

static uint64_t now_ns_native(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void iso_utc_native(char *buf, size_t n, time_t t) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* ── Wallet init ───────────────────────────────────────────────── */

/* Read entire file into heap buffer. Caller frees. Returns NULL on error. */
static uint8_t *read_file_all(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (r != (size_t)sz) { free(buf); return NULL; }
    *len_out = (size_t)sz;
    return buf;
}

/* Query chain (post-connect) for biggest unspent native UTXO.
 * Local DB is unreliable across bench runs (change UTXOs from prior
 * runs land on chain but never sync into the wallet's dnac.db).
 *
 * Retries up to LOAD_INITIAL_UTXO_MAX_ATTEMPTS times with 2 s backoff
 * when the chain query reports zero UTXOs. The witness this client
 * is talking to may not have applied the most recent fund TX yet —
 * either it propagated to a different leader for that round, or the
 * commit just landed and replication hasn't fanned out to all 7
 * nodes. Empirically (2026-05-03) this prevents the systemic
 * 2-of-27 startup miss seen on a 1 TPS × 10 min real-cluster run
 * where `wallets refund` had succeeded for those wallets but the
 * single startup query landed on a witness that hadn't applied
 * those refund TXs yet.
 *
 * Returns 0 on success. */
#define LOAD_INITIAL_UTXO_MAX_ATTEMPTS  5
#define LOAD_INITIAL_UTXO_BACKOFF_USEC  2000000  /* 2 s */

static int load_initial_utxo_from_chain(struct bench_wallet *w) {
    nodus_dnac_utxo_result_t r = {0};
    int attempts = 0;
    static const uint8_t zero_token[64] = {0};

    while (attempts++ < LOAD_INITIAL_UTXO_MAX_ATTEMPTS) {
        memset(&r, 0, sizeof(r));
        if (nodus_client_dnac_utxo(&w->client, w->fp, 100, &r) != 0) {
            fprintf(stderr, "[w%02d] dnac_utxo query failed (attempt %d/%d)\n",
                    w->idx, attempts, LOAD_INITIAL_UTXO_MAX_ATTEMPTS);
            if (r.entries) { free(r.entries); r.entries = NULL; }
            if (attempts < LOAD_INITIAL_UTXO_MAX_ATTEMPTS) {
                usleep(LOAD_INITIAL_UTXO_BACKOFF_USEC);
                continue;
            }
            return -1;
        }
        if (r.count > 0) break;  /* got UTXOs, drop to picker below */

        /* Zero count: maybe the witness we asked hasn't applied a recent
         * fund TX yet. Sleep + retry; nodus_client may pick a different
         * leader or the missing replication completes in the gap. */
        if (r.entries) { free(r.entries); r.entries = NULL; }
        if (attempts >= LOAD_INITIAL_UTXO_MAX_ATTEMPTS) {
            fprintf(stderr, "[w%02d] no on-chain UTXOs after %d attempts "
                            "(real drain or unreplicated fund)\n",
                    w->idx, attempts);
            return -1;
        }
        fprintf(stderr, "[w%02d] no UTXOs (attempt %d/%d) — retrying in 2s\n",
                w->idx, attempts, LOAD_INITIAL_UTXO_MAX_ATTEMPTS);
        usleep(LOAD_INITIAL_UTXO_BACKOFF_USEC);
    }

    /* Pick the largest native (token_id all zero) UTXO. */
    int best = -1;
    uint64_t best_amount = 0;
    for (int i = 0; i < r.count; i++) {
        if (memcmp(r.entries[i].token_id, zero_token, 64) != 0) continue;
        if (r.entries[i].amount > best_amount) {
            best = i;
            best_amount = r.entries[i].amount;
        }
    }
    if (best < 0) {
        fprintf(stderr, "[w%02d] no native UTXO\n", w->idx);
        if (r.entries) free(r.entries);
        return -1;
    }
    memcpy(w->cur_tx_hash, r.entries[best].tx_hash, 64);
    memcpy(w->cur_nullifier, r.entries[best].nullifier, 64);
    w->cur_output_index = r.entries[best].output_index;
    w->cur_amount = r.entries[best].amount;
    if (r.entries) free(r.entries);
    return 0;
}

static int wallet_init(struct bench_wallet *w, int idx, const char *wallet_dir,
                       const char *fp) {
    memset(w, 0, sizeof(*w));
    w->idx = idx;
    snprintf(w->data_dir, sizeof(w->data_dir), "%s/.dna", wallet_dir);
    snprintf(w->fp, sizeof(w->fp), "%s", fp);
    pthread_mutex_init(&w->state_mu, NULL);
    pthread_mutex_init(&w->err_mu, NULL);

    /* UTXO state is loaded AFTER client connect (chain query). */

    /* 1. Import nodus identity from cached dht_identity.bin. */
    char id_path[1280];
    snprintf(id_path, sizeof(id_path), "%s/dht_identity.bin", w->data_dir);
    size_t id_len = 0;
    uint8_t *id_buf = read_file_all(id_path, &id_len);
    if (!id_buf) {
        fprintf(stderr, "[w%02d] dht_identity.bin missing at %s\n",
                w->idx, id_path);
        return -1;
    }
    int rc = nodus_identity_import(id_buf, id_len, &w->identity);
    free(id_buf);
    if (rc != 0) {
        fprintf(stderr, "[w%02d] nodus_identity_import rc=%d\n", w->idx, rc);
        return -1;
    }

    /* 3. Load DSA private key for TX signing. */
    char dsa_path[1280];
    snprintf(dsa_path, sizeof(dsa_path), "%s/keys/identity.dsa", w->data_dir);
    if (qgp_key_load(dsa_path, &w->dsa_key) != 0 || !w->dsa_key) {
        fprintf(stderr, "[w%02d] qgp_key_load failed: %s\n",
                w->idx, dsa_path);
        nodus_identity_clear(&w->identity);
        return -1;
    }
    return 0;
}

/* ── Nodus client connect ──────────────────────────────────────── */

extern int nodus_messenger_get_known_servers(char addrs[][64], int max);

static int wallet_client_connect(struct bench_wallet *w) {
    /* Hard-coded production node list (see operational_reference). */
    static const char *PROD_NODES[] = {
        "154.38.182.161:4001",
        "164.68.105.227:4001",
        "164.68.116.180:4001",
        "161.97.85.25:4001",
        "156.67.24.125:4001",
        "156.67.25.251:4001",
        "75.119.141.51:4001",
        NULL
    };

    nodus_client_config_t cfg = {0};
    /* Spread wallets across nodes by index for connection diversity. */
    int n_nodes = 0;
    for (int i = 0; PROD_NODES[i]; i++) n_nodes++;
    int start = w->idx % n_nodes;
    int j = 0;
    for (int i = 0; i < n_nodes && j < (int)(sizeof(cfg.servers)/sizeof(cfg.servers[0])); i++) {
        const char *addr = PROD_NODES[(start + i) % n_nodes];
        const char *colon = strchr(addr, ':');
        if (!colon) continue;
        size_t hostlen = (size_t)(colon - addr);
        if (hostlen >= sizeof(cfg.servers[0].ip)) continue;
        memcpy(cfg.servers[j].ip, addr, hostlen);
        cfg.servers[j].ip[hostlen] = '\0';
        cfg.servers[j].port = (uint16_t)atoi(colon + 1);
        j++;
    }
    cfg.server_count = j;
    cfg.connect_timeout_ms = 5000;
    cfg.request_timeout_ms = 60000;
    cfg.auto_reconnect = true;

    if (nodus_client_init(&w->client, &cfg, &w->identity) != 0) {
        fprintf(stderr, "[w%02d] nodus_client_init failed\n", w->idx);
        return -1;
    }
    if (nodus_client_connect(&w->client) != 0) {
        fprintf(stderr, "[w%02d] nodus_client_connect failed\n", w->idx);
        return -1;
    }
    w->client_ready = true;
    return 0;
}

/* ── Send loop ─────────────────────────────────────────────────── */

#ifndef DNAC_MIN_FEE_RAW
#define DNAC_MIN_FEE_RAW 1000000ULL
#endif

/* Pick a mesh recipient FP (any wallet other than self). */
static const char *pick_mesh_recipient(int self_idx, unsigned *rng_state) {
    if (g_recipient_count <= 1) return g_recipients[0];
    int j;
    do {
        *rng_state = (*rng_state) * 1664525u + 1013904223u;
        j = (int)(*rng_state % (unsigned)g_recipient_count);
    } while (j == self_idx);
    return g_recipients[j];
}

/* Append tx_hash hex to global tx_hashes.txt. */
static void record_tx_hash(const uint8_t *txh) {
    if (!g_tx_hashes_fp) return;
    char hex[129];
    for (int i = 0; i < 64; i++) snprintf(&hex[i*2], 3, "%02x", txh[i]);
    pthread_mutex_lock(&g_tx_mu);
    fprintf(g_tx_hashes_fp, "%s\n", hex);
    fflush(g_tx_hashes_fp);
    pthread_mutex_unlock(&g_tx_mu);
}

/* Build, sign, submit one TX. Returns 0 on success (commit). */
static int do_one_send(struct bench_wallet *w, unsigned *rng_state,
                       int round_no) {
    /* Snapshot current UTXO under lock. */
    pthread_mutex_lock(&w->state_mu);
    dnac_utxo_t input_utxo = {0};
    input_utxo.version = 1;
    memcpy(input_utxo.tx_hash, w->cur_tx_hash, 64);
    input_utxo.output_index = w->cur_output_index;
    input_utxo.amount = w->cur_amount;
    memcpy(input_utxo.nullifier, w->cur_nullifier, 64);
    snprintf(input_utxo.owner_fingerprint, sizeof(input_utxo.owner_fingerprint),
             "%s", w->fp);
    input_utxo.status = 0;
    pthread_mutex_unlock(&w->state_mu);

    if (input_utxo.amount < DNAC_MIN_FEE_RAW + 1) {
        return -1;  /* exhausted */
    }

    const char *recipient = pick_mesh_recipient(w->idx, rng_state);
    if (!recipient) return -1;

    /* Build TX. */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    if (!tx) return -1;

    if (dnac_tx_add_input(tx, &input_utxo) != 0) goto err;
    /* recipient gets 1 raw — discard their nullifier_seed (we don't spend it) */
    uint8_t recip_seed[32];
    if (dnac_tx_add_output(tx, recipient, 1, recip_seed) != 0) goto err;
    /* change to self — capture nullifier_seed so we know NEXT input nullifier. */
    uint64_t fee = DNAC_MIN_FEE_RAW;
    uint64_t change = input_utxo.amount - 1ULL - fee;
    uint8_t change_seed[32];
    if (dnac_tx_add_output(tx, w->fp, change, change_seed) != 0) goto err;

    /* committed_fee + chain_id MUST be set before finalize: both fields
     * are bound into the preimage that dnac_tx_compute_hash digests
     * (and dnac_tx_finalize calls compute_hash internally before
     * signing). Witness recomputes the same preimage and rejects with
     * PROTOCOL_ERROR if either is missing. */
    tx->committed_fee = fee;
    if (g_chain_id_set) memcpy(tx->chain_id, g_chain_id, 32);

    /* Finalize: sign with our DSA key. */
    if (dnac_tx_finalize(tx,
                         w->dsa_key->private_key,
                         w->dsa_key->public_key) != 0) goto err;

    /* Serialize. */
    static __thread uint8_t tx_buf[131072];
    size_t tx_len = 0;
    if (dnac_tx_serialize(tx, tx_buf, sizeof(tx_buf), &tx_len) != 0) goto err;

    /* Submit. */
    nodus_pubkey_t pk;
    memcpy(pk.bytes, tx->signers[0].pubkey, 2592);
    nodus_sig_t sig;
    memcpy(sig.bytes, tx->signers[0].signature, 4627);

    nodus_dnac_spend_result_t result = {0};
    int rc = nodus_client_dnac_spend(&w->client,
                                      tx->tx_hash, tx_buf, (uint32_t)tx_len,
                                      &pk, &sig, fee, &result);
    if (rc != 0) {
        pthread_mutex_lock(&w->err_mu);
        snprintf(w->last_error, sizeof(w->last_error),
                 "spend rc=%d round=%d", rc, round_no);
        pthread_mutex_unlock(&w->err_mu);
        dnac_free_transaction(tx);
        return -1;
    }
    if (result.status != NODUS_DNAC_APPROVED) {
        pthread_mutex_lock(&w->err_mu);
        snprintf(w->last_error, sizeof(w->last_error),
                 "rejected status=%d round=%d", result.status, round_no);
        pthread_mutex_unlock(&w->err_mu);
        dnac_free_transaction(tx);
        return -1;
    }

    /* Success: record tx_hash, advance UTXO state to change output. */
    record_tx_hash(tx->tx_hash);

    pthread_mutex_lock(&w->state_mu);
    memcpy(w->cur_tx_hash, tx->tx_hash, 64);
    /* change output is index 1 (recipient is 0). */
    w->cur_output_index = 1;
    w->cur_amount = change;
    /* Compute new nullifier: SHA3-512(owner_fp_str || nullifier_seed_32). */
    uint8_t nul_data[256];
    size_t fp_len = strlen(w->fp);
    memcpy(nul_data, w->fp, fp_len);
    memcpy(nul_data + fp_len, change_seed, 32);
    qgp_sha3_512(nul_data, fp_len + 32, w->cur_nullifier);
    pthread_mutex_unlock(&w->state_mu);

    dnac_free_transaction(tx);
    return 0;

err:
    if (tx) dnac_free_transaction(tx);
    return -1;
}

/* ── Per-wallet thread ─────────────────────────────────────────── */

struct thread_args {
    struct bench_wallet *w;
    int    target_tps_total;
    int    pool_size;
    uint64_t deadline_ns;
};

static void *wallet_thread(void *arg) {
    struct thread_args *ta = arg;
    struct bench_wallet *w = ta->w;
    unsigned rng = (unsigned)(time(NULL) ^ (uintptr_t)w);

    /* Per-wallet pace: total_tps / pool_size sends per second, so each
     * wallet sleeps pool_size/total_tps seconds between sends. */
    double per_wallet_period_s = (ta->target_tps_total > 0)
        ? ((double)ta->pool_size / (double)ta->target_tps_total)
        : 0.0;

    /* Stagger thread starts so requests trickle into the cluster at the
     * target_tps rate from t=0 rather than bursting all wallets at
     * once (which causes BFT mempool overflow + timeouts). */
    if (per_wallet_period_s > 0 && ta->pool_size > 0) {
        double offset_s = per_wallet_period_s
                        * ((double)w->idx / (double)ta->pool_size);
        if (offset_s > 0.001) {
            struct timespec ts;
            ts.tv_sec  = (time_t)offset_s;
            ts.tv_nsec = (long)((offset_s - (time_t)offset_s) * 1e9);
            nanosleep(&ts, NULL);
        }
    }

    int round = 0;
    while (!atomic_load(&g_run_done) && now_ns_native() < ta->deadline_ns) {
        round++;
        atomic_fetch_add(&w->submit, 1);
        atomic_fetch_add(&g_total_submit, 1);
        uint64_t t0 = now_ns_native();
        int rc = do_one_send(w, &rng, round);
        (void)t0;
        if (rc == 0) {
            atomic_fetch_add(&w->commit, 1);
            atomic_fetch_add(&g_total_commit, 1);
        } else {
            atomic_fetch_add(&w->fail, 1);
            atomic_fetch_add(&g_total_fail, 1);
            if (round <= 3) {
                pthread_mutex_lock(&w->err_mu);
                fprintf(stderr, "[w%02d] r%d: %s\n",
                        w->idx, round, w->last_error);
                pthread_mutex_unlock(&w->err_mu);
            }
        }
        if (per_wallet_period_s > 0) {
            struct timespec ts;
            ts.tv_sec  = (time_t)per_wallet_period_s;
            ts.tv_nsec = (long)((per_wallet_period_s - (time_t)per_wallet_period_s) * 1e9);
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

/* ── Live tick ─────────────────────────────────────────────────── */

static void *tick_thread_native(void *arg) {
    int interval = (int)(intptr_t)arg;
    while (!atomic_load(&g_run_done)) {
        for (int i = 0; i < interval * 10 && !atomic_load(&g_run_done); i++) {
            struct timespec ts = {0, 100 * 1000 * 1000L};
            nanosleep(&ts, NULL);
        }
        if (atomic_load(&g_run_done)) break;
        uint64_t elapsed_ns = now_ns_native() - g_run_started_ns;
        double secs = (double)elapsed_ns / 1.0e9;
        if (secs < 1) secs = 1;
        int submit = atomic_load(&g_total_submit);
        int commit = atomic_load(&g_total_commit);
        int fail   = atomic_load(&g_total_fail);
        fprintf(stderr,
            "[dna-bench %4ds] submit=%d commit=%d fail=%d "
            "tps_submit=%.2f tps_commit=%.2f\n",
            (int)secs, submit, commit, fail,
            submit / secs, commit / secs);
        fflush(stderr);
    }
    return NULL;
}

/* ── Public entry: replaces fork-exec run ──────────────────────── */

int dna_bench_native_run(struct dna_bench_run_cfg *cfg,
                         void *pool_entries, int pool_size,
                         const char *run_dir) {
    /* pool_entries layout matches the existing struct in run.c:
     *   { int idx; char fp[160]; char data_dir[1024]; } pool[N]
     * We re-derive wallet_dir from data_dir by stripping the trailing
     * "/.dna" so wallet_init can rebuild it canonically. */
    struct legacy_pool {
        int idx;
        char fp[160];
        char data_dir[1024];
    };
    struct legacy_pool *pool = (struct legacy_pool *)pool_entries;

    if (pool_size > MAX_WALLETS) pool_size = MAX_WALLETS;
    g_wallet_count = 0;
    g_recipient_count = 0;

    snprintf(g_run_dir, sizeof(g_run_dir), "%s", run_dir);
    snprintf(g_tx_hashes_path, sizeof(g_tx_hashes_path),
             "%s/tx_hashes.txt", g_run_dir);
    g_tx_hashes_fp = fopen(g_tx_hashes_path, "w");

    fprintf(stderr, "[dna-bench] loading %d wallet(s) (in-process)...\n",
            pool_size);
    fflush(stderr);
    for (int i = 0; i < pool_size; i++) {
        char wallet_dir[1024];
        snprintf(wallet_dir, sizeof(wallet_dir), "%s", pool[i].data_dir);
        /* Strip trailing /.dna if present. */
        size_t L = strlen(wallet_dir);
        if (L > 5 && strcmp(wallet_dir + L - 5, "/.dna") == 0) {
            wallet_dir[L - 5] = '\0';
        }
        if (wallet_init(&g_wallets[g_wallet_count], pool[i].idx,
                        wallet_dir, pool[i].fp) == 0) {
            snprintf(g_recipients[g_recipient_count],
                     sizeof(g_recipients[0]), "%s", g_wallets[g_wallet_count].fp);
            g_recipient_count++;
            g_wallet_count++;
        }
    }
    if (g_wallet_count == 0) {
        fprintf(stderr, "[dna-bench] no usable wallets — try refunding pool\n");
        if (g_tx_hashes_fp) fclose(g_tx_hashes_fp);
        return 1;
    }
    fprintf(stderr, "[dna-bench] %d wallet(s) loaded, connecting to cluster...\n",
            g_wallet_count);
    fflush(stderr);

    /* Connect each wallet's nodus client (parallel via pthread). */
    pthread_t connect_threads[MAX_WALLETS];
    for (int i = 0; i < g_wallet_count; i++) {
        struct bench_wallet *w = &g_wallets[i];
        pthread_create(&connect_threads[i], NULL,
            (void *(*)(void *))wallet_client_connect, w);
    }
    for (int i = 0; i < g_wallet_count; i++) {
        pthread_join(connect_threads[i], NULL);
    }
    int connected = 0;
    for (int i = 0; i < g_wallet_count; i++) {
        if (g_wallets[i].client_ready) connected++;
    }
    fprintf(stderr, "[dna-bench] %d/%d wallets connected\n",
            connected, g_wallet_count);
    fflush(stderr);
    if (connected == 0) {
        if (g_tx_hashes_fp) fclose(g_tx_hashes_fp);
        return 1;
    }

    /* Query chain_id once via the first connected wallet's client. The
     * 32-byte chain_id is bound into every TX preimage; without it the
     * witness rejects with PROTOCOL_ERROR. */
    for (int i = 0; i < g_wallet_count && !g_chain_id_set; i++) {
        if (!g_wallets[i].client_ready) continue;
        nodus_dnac_supply_result_t sr = {0};
        if (nodus_client_dnac_supply(&g_wallets[i].client, &sr) == 0) {
            memcpy(g_chain_id, sr.chain_id, 32);
            g_chain_id_set = true;
            char hex[65];
            for (int j = 0; j < 32; j++) snprintf(&hex[j*2], 3, "%02x", g_chain_id[j]);
            fprintf(stderr, "[dna-bench] chain_id=%s\n", hex);
        }
    }
    if (!g_chain_id_set) {
        fprintf(stderr, "[dna-bench] WARN: chain_id query failed; TXs will fail\n");
    }
    fflush(stderr);

    /* Bootstrap each wallet's UTXO state from the chain (parallel). */
    int utxo_ok = 0;
    for (int i = 0; i < g_wallet_count; i++) {
        if (!g_wallets[i].client_ready) continue;
        if (load_initial_utxo_from_chain(&g_wallets[i]) == 0) utxo_ok++;
    }
    fprintf(stderr, "[dna-bench] %d/%d wallets have a usable on-chain UTXO\n",
            utxo_ok, connected);
    fflush(stderr);
    if (utxo_ok == 0) {
        if (g_tx_hashes_fp) fclose(g_tx_hashes_fp);
        return 1;
    }

    /* Spawn per-wallet send threads. */
    g_run_started_ns = now_ns_native();
    char started_at[32];
    iso_utc_native(started_at, sizeof(started_at), time(NULL));
    fprintf(stderr,
        "[dna-bench] mode=sustained tps=%d duration=%ds wallets=%d run_dir=%s\n"
        "[dna-bench] starting send threads at %s\n",
        cfg->tps_target, cfg->duration_s, g_wallet_count,
        g_run_dir, started_at);
    fflush(stderr);

    pthread_t tick;
    int interval = (cfg->status_interval_s > 0) ? cfg->status_interval_s : 5;
    pthread_create(&tick, NULL, tick_thread_native, (void *)(intptr_t)interval);

    pthread_t threads[MAX_WALLETS];
    struct thread_args ta_arr[MAX_WALLETS];
    uint64_t deadline_ns = g_run_started_ns
                         + (uint64_t)cfg->duration_s * 1000000000ULL;
    for (int i = 0; i < g_wallet_count; i++) {
        if (!g_wallets[i].client_ready) {
            threads[i] = 0;
            continue;
        }
        ta_arr[i].w = &g_wallets[i];
        ta_arr[i].target_tps_total = cfg->tps_target;
        ta_arr[i].pool_size = connected;
        ta_arr[i].deadline_ns = deadline_ns;
        pthread_create(&threads[i], NULL, wallet_thread, &ta_arr[i]);
    }
    for (int i = 0; i < g_wallet_count; i++) {
        if (threads[i]) pthread_join(threads[i], NULL);
    }
    atomic_store(&g_run_done, 1);
    pthread_join(tick, NULL);

    /* Final report. */
    int submit = atomic_load(&g_total_submit);
    int commit = atomic_load(&g_total_commit);
    int fail   = atomic_load(&g_total_fail);
    int actual_s = (int)((now_ns_native() - g_run_started_ns) / 1000000000ULL);
    if (actual_s < 1) actual_s = 1;
    char ended_at[32];
    iso_utc_native(ended_at, sizeof(ended_at), time(NULL));

    char run_json_path[1280];
    snprintf(run_json_path, sizeof(run_json_path), "%s/run.json", g_run_dir);
    FILE *rf = fopen(run_json_path, "w");
    if (rf) {
        fprintf(rf,
"{\"schema_version\":2,\"tool_version\":\"%s\","
"\"started_at\":\"%s\",\"ended_at\":\"%s\","
"\"config\":{\"mode\":\"sustained\",\"tps_target\":%d,\"duration_s\":%d,"
"\"wallets\":%d,\"recipient\":\"mesh\"},"
"\"totals\":{\"submit\":%d,\"commit_h\":%d,\"fail\":%d,"
"\"tps_submit\":%.3f,\"tps_commit_h\":%.3f,"
"\"submit_success_rate\":%.4f},"
"\"actual_duration_s\":%d,\"reconciled\":false,"
"\"architecture\":\"in_process_libnodus\"}\n",
            DNA_BENCH_TOOL_VERSION, started_at, ended_at,
            cfg->tps_target, cfg->duration_s, connected,
            submit, commit, fail,
            (double)submit / actual_s,
            (double)commit / actual_s,
            submit > 0 ? (double)commit / (double)submit : 0.0,
            actual_s);
        fclose(rf);
    }
    if (g_tx_hashes_fp) {
        fclose(g_tx_hashes_fp);
        g_tx_hashes_fp = NULL;
    }

    fprintf(stderr,
        "\n[dna-bench] DONE: submit=%d commit=%d fail=%d "
        "tps_commit=%.2f duration=%ds run_dir=%s\n",
        submit, commit, fail, (double)commit / actual_s, actual_s, g_run_dir);
    fflush(stderr);

    /* Cleanup. */
    for (int i = 0; i < g_wallet_count; i++) {
        if (g_wallets[i].client_ready) {
            nodus_client_close(&g_wallets[i].client);
        }
        if (g_wallets[i].dsa_key) {
            qgp_key_free(g_wallets[i].dsa_key);
            g_wallets[i].dsa_key = NULL;
        }
        nodus_identity_clear(&g_wallets[i].identity);
        pthread_mutex_destroy(&g_wallets[i].state_mu);
        pthread_mutex_destroy(&g_wallets[i].err_mu);
    }
    return 0;
}
