/* dna_bench_internal.h — shared types + decls across dna_bench_*.c.
 *
 * dna-bench is a fork/exec orchestrator: every wallet operation shells
 * out to dna-connect-cli (resolved via $BENCH_CLI_BIN, default
 * /opt/dna/messenger/build/cli/dna-connect-cli). The binary is pure C99
 * + POSIX, no libdna link, no ASan footprint.
 *
 * See nodus/docs/plans/2026-04-27-dna-bench-design.md (local-only).
 */

#ifndef DNA_BENCH_INTERNAL_H
#define DNA_BENCH_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define DNA_BENCH_TOOL_VERSION   "0.1.0"
#define DNA_BENCH_SCHEMA_VERSION 2

/* Dispatch return codes. EXIT_NOT_IMPLEMENTED matches the convention
 * used by GNU coreutils for stub functionality. */
#define DNA_BENCH_EXIT_OK              0
#define DNA_BENCH_EXIT_USAGE           1
#define DNA_BENCH_EXIT_PUNK_LOCKED     2
#define DNA_BENCH_EXIT_INTERRUPTED   130
#define DNA_BENCH_EXIT_NOT_IMPLEMENTED 88

/* Operator safety caps (red-team C3, C4). Pass --allow-large /
 * --allow-stress / --allow-long to bypass the relevant cap. */
#define DNA_BENCH_MAX_WALLETS_DEFAULT 200
#define DNA_BENCH_MAX_WALLETS_HARD   1000
#define DNA_BENCH_MAX_DURATION_S     (48 * 3600)
#define DNA_BENCH_BURST_DEFAULT_TPS  50

/* Funding / send constants. */
#define DNA_BENCH_DEFAULT_FUND_RAW   100000000ULL  /* 1 DNAC */
#define DNA_BENCH_SPEND_AMOUNT_RAW   1ULL          /* min positive raw */
#define DNA_BENCH_FUND_TIMEOUT_S     45
#define DNA_BENCH_CHILD_TIMEOUT_S    60

/* Pool metadata persisted to ~/.dna_bench/pool.json. */
struct dna_bench_pool {
    int     count;
    uint64_t fund_per_wallet_raw;
    char    created_at[32];      /* ISO-8601 UTC */
    char    chain_genesis_id[129]; /* hex genesis ID, optional */
};

/* ── Pool / paths (dna_bench_pool.c) ───────────────────────────── */

/* Returns malloc'd path. Honors $BENCH_HOME for tests; default ~/.dna_bench. */
char *dna_bench_root(void);

/* Returns ~/.dna_bench/wallets/wNN. Caller free's. */
char *dna_bench_wallet_dir(int idx);

/* Returns ~/.dna_bench/wallets/wNN/fp.txt. Caller free's. */
char *dna_bench_wallet_fp_path(int idx);

/* Returns ~/.dna_bench/pool.json. Caller free's. */
char *dna_bench_pool_metadata_path(void);

/* Returns ~/.dna_bench/runs/<UTC-ts>. Creates parent if missing. Caller free's. */
char *dna_bench_run_dir_new(void);

/* Loads pool metadata. Returns 0 ok, -1 missing, -2 malformed. */
int dna_bench_pool_load(struct dna_bench_pool *out);

/* Saves pool metadata. Returns 0 ok, -1 io error. */
int dna_bench_pool_save(const struct dna_bench_pool *p);

/* True if pool.json exists. */
bool dna_bench_pool_exists(void);

/* mkdir -p with mode 0700 for every path component under root. */
int dna_bench_mkdir_p_secure(const char *path);

/* Read first line of file, strip trailing \n. Returns malloc'd buffer or NULL. */
char *dna_bench_read_first_line(const char *path);

/* Locate dna-connect-cli (env BENCH_CLI_BIN > default path > $PATH). */
const char *dna_bench_cli_bin(void);

/* ── Wallet ops (dna_bench_wallets.c) ──────────────────────────── */

/* Wallet helpers. Inline from steps in plan 1.B.2.b/c. */
int dna_bench_wallet_init(int idx, char *fp_out, size_t fp_n);
int dna_bench_wallet_fund(int idx, const char *fp, uint64_t amount_raw);
int dna_bench_wallet_balance(int idx, uint64_t *raw_out);

/* Subcommand handlers (called from main dispatch). */
int cmd_wallets(int argc, char **argv);
int cmd_run(int argc, char **argv);
int cmd_reconcile(int argc, char **argv);
int cmd_observe(int argc, char **argv);

/* ── Run modes (dna_bench_run.c) ───────────────────────────────── */

enum dna_bench_mode {
    DNA_BENCH_MODE_INVALID = 0,
    DNA_BENCH_MODE_BURST,
    DNA_BENCH_MODE_SUSTAINED,
    DNA_BENCH_MODE_RAMPUP,
    DNA_BENCH_MODE_SOAK,         /* alias for sustained */
};

struct dna_bench_run_cfg {
    enum dna_bench_mode mode;
    int      tps_target;
    int      duration_s;
    int      ramp_start;
    int      ramp_end;
    int      ramp_step;
    int      ramp_hold_s;
    int      max_tps_cap;        /* 0 = uncapped (--allow-stress) */
    int      status_interval_s;
    bool     allow_stress;
    bool     allow_long;
    bool     fixed_recipient;
    char     recipient_fp[260];  /* 129 hex + slack; only used if fixed */
    char     stream_path[1024];
    char     output_path[1024];
    double   abort_on_fail_rate; /* 0 = disabled */
};

int dna_bench_run_main(struct dna_bench_run_cfg *cfg);

/* ── Output (dna_bench_output.c) ───────────────────────────────── */

struct dna_bench_round_stats {
    int      round;
    const char *phase;       /* "burst" | "sustained" | "rampup_step" | "soak" */
    int      tps_target;
    int      submit;
    int      commit_h;
    int      fail;
    uint64_t round_dt_ms;
    uint64_t min_dt_ms, p50_dt_ms, p95_dt_ms, max_dt_ms;
};

struct dna_bench_run_totals {
    int      rounds;
    uint64_t submit;
    uint64_t commit_h;
    uint64_t fail;
    uint64_t rate_limited;
    double   tps_submit;
    double   tps_commit_h;
    uint64_t latency_us_min, latency_us_p50, latency_us_p95, latency_us_p99, latency_us_max;
};

struct dna_bench_wallet_post {
    int      idx;
    char     fp_short[32];
    int64_t  balance_raw;     /* -1 = unknown */
    uint64_t tx_sent;
    uint64_t tx_recv;
    uint64_t fail;
};

void dna_bench_print_iso_utc(char *buf, size_t n, time_t t);

/* JSONL stream — open/append/close. fp may be NULL (stream disabled). */
typedef struct dna_bench_stream dna_bench_stream_t;
dna_bench_stream_t *dna_bench_stream_open(const char *path);
void dna_bench_stream_round(dna_bench_stream_t *s,
                            const struct dna_bench_round_stats *r);
void dna_bench_stream_close(dna_bench_stream_t *s);

/* Live stderr tick — start/stop a worker thread that prints rolling stats. */
struct dna_bench_live_counters {
    /* Plain counters; stderr tick reads under a mutex. C99 portable. */
    uint64_t submit, commit_h, fail;
    uint64_t started_ns;
    int      tps_target;
    int      pool_size;
    const char *phase;
};

void dna_bench_live_start(struct dna_bench_live_counters *c, int interval_s);
void dna_bench_live_stop(void);
void dna_bench_live_record(uint64_t submit, uint64_t commit_h, uint64_t fail);

/* Final JSON written to stdout + --output path. */
struct dna_bench_final_args {
    const char *started_at;
    const char *ended_at;
    const struct dna_bench_run_cfg *cfg;
    const struct dna_bench_run_totals *totals;
    const struct dna_bench_wallet_post *wallets_post;
    int      pool_size;
    bool     interrupted;
    int      actual_duration_s;
    const char *output_path;
};
int dna_bench_final_emit(const struct dna_bench_final_args *a);

/* ── Reconcile (dna_bench_reconcile.c) ─────────────────────────── */

int dna_bench_reconcile_main(const char *run_json_path);

/* ── Signals (dna_bench.c) ─────────────────────────────────────── */

extern volatile int g_dna_bench_shutdown;

#endif /* DNA_BENCH_INTERNAL_H */
