/**
 * @file evm_bench.c
 * @brief Nodus EVM measurement gate, part (a): the BARE engine (shared/evm) —
 *        wall time and memory of N gas of worst-case EVM work.
 *
 * MEASUREMENT TOOL ONLY. It reads CLOCK_MONOTONIC to time runs; nothing
 * here is consensus code and nothing here is linked into a node.
 *
 * Governing records: docs/plans/2026-10-04-nodus-evm-chain-integration-
 * design.md §8 ("Faz 3 kapısı": the worst cost per gas of loop opcodes,
 * KECCAK, modexp, BLS pairing, bn254 pairing, memory and reads is
 * measured, and EVM_BLOCK_GAS_LIMIT is derived from it), decision
 * 2026-10-04-nodus-evm-kurultay-k2-summary.md item 3 (the gas limits await
 * this gate). It changes no placeholder value.
 *
 * WHAT IT DOES. For every workload of evm_bench_wl.c (one call
 * transaction of a hand-assembled contract, sized to --gas): an in-memory
 * backend (tests/evm_membackend.c — the conformance tests' backend,
 * binary-search lookups, no I/O) holds the sender, the workload contract
 * and any pre-filled slots / accounts; each of --reps runs is a FRESH
 * overlay (evm_state_new) on that backend, so every run starts cold in
 * the engine. Timed: evm_tx_apply (validity, intrinsic gas, execution,
 * refunds) and, separately, evm_state_visit_changes (the canonical
 * change-set walk a node runs after execution). Not timed: backend
 * construction, evm_state_free, the precompile sizing run.
 *
 * Profile: the Nodus profile of tests/test_nodus_profile.c — 32-byte
 * addresses, base fee and gas price 0, Prague precompile set.
 *
 * Each workload runs in a forked child so the reported peak RSS
 * (getrusage ru_maxrss) is that workload's own high-water mark (plus the
 * parent's pre-fork footprint, printed first); --no-fork runs them in one
 * process and the RSS column becomes cumulative.
 *
 * Usage:
 *   evm_bench [--gas N] [--reps R] [--only name[,name...]] [--no-fork]
 *             [--list]
 *   defaults: --gas 30000000 --reps 5, every workload.
 *
 * HOW IT CAN LIE
 *   - The backend is memory: sload/acct numbers are the ENGINE's cost per
 *     read, not SQLite's — the node bench (nodus/tests/bench/
 *     bench_evm_apply.c) measures the real storage path.
 *   - A workload whose loop exits early uses less gas than --gas; every
 *     line prints gas_used and its share, and WARN marks a share below
 *     gas - slack (one loop iteration).
 *   - ns/gas is wall time / gas_used of THIS machine and THIS build
 *     (-O2, the Makefile's flags); the gate asks for the weakest
 *     supported validator.
 *   - Timings are single-threaded and include whatever the OS does
 *     meanwhile; min / median / max over --reps are all printed.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "evm.h"
#include "evm_precompile.h"
#include "evm_membackend.h"
#include "evm_bench_wl.h"
#include "crypto/hash/keccak256.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_GAS  30000000ull
#define DEFAULT_REPS 5u
#define MAX_REPS     1000u

/* the Comet commit timeout this build runs with, for the comparison
 * column: nodus/src/witness/nodus_witness_cmt_node.c:1794
 * (timeout_commit = 4000 ms); :1795 create_empty_blocks_interval 60 s */
#define CMT_TIMEOUT_COMMIT_MS 4000.0

/* ── machine ──────────────────────────────────────────────────────────── */

static void print_machine(void)
{
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
    long np = sysconf(_SC_NPROCESSORS_ONLN);
    printf("machine: cpu \"%s\", nproc %ld\n", model, np);
#ifdef __VERSION__
    printf("compiler: %s\n", __VERSION__);
#endif
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static long peak_rss_kib(void)
{
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
    return ru.ru_maxrss;                           /* Linux: KiB */
}

/* ── engine setup (tests/test_nodus_profile.c make_cfg / make_env) ───── */

static void chain_id_of(evm_u256 *out)
{
    uint8_t b[32];
    for (int i = 0; i < 32; i++) b[i] = (uint8_t)(0xA0 + i);
    evm_u256_from_be(out, b);
}

static void make_cfg(evm_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->fork = EVM_FORK_PRAGUE;
    cfg->addr_bytes = 32;
    chain_id_of(&cfg->chain_id);
    cfg->precompile_mask = EVM_PRECOMPILES_PRAGUE;
    cfg->nodus_profile = 1;
    memset(cfg->ticket_addr.b, 0xEE, 32);
    evm_u256_from_u64(&cfg->ticket_unit, 10000000000ull);   /* q = 10^10 */
    cfg->ticket_gas = 25000;
}

static const uint8_t SENDER_TAG   = 0x5E;
static const uint8_t CONTRACT_TAG = 0xC0;

/* ── change-set walk (timed; counts what a node would persist) ───────── */

typedef struct {
    uint64_t accounts, slots;
} visit_t;

static int vis_account(void *ctx, const evm_account_change_t *c)
{
    (void)c;
    ((visit_t *)ctx)->accounts++;
    return 0;
}

static int vis_storage(void *ctx, const evm_addr *addr, const evm_bytes32 *k,
                       const evm_bytes32 *v)
{
    (void)addr;
    (void)k;
    (void)v;
    ((visit_t *)ctx)->slots++;
    return 0;
}

/* ── one workload ────────────────────────────────────────────────────── */

typedef struct {
    int      idx;
    int      state;            /* 1 ran, 0 skipped, -1 failed            */
    int      status;           /* evm_exec_status_t of the last run      */
    uint64_t gas_used;
    double   med_ms, min_ms, max_ms, visit_ms;
    double   ns_per_gas, mgas_s;
    long     rss_kib;
    int      early;
} result_t;

static const char *status_name(int s)
{
    static const char *const n[] = {
        "SUCCESS", "REVERT", "OUT_OF_GAS", "INVALID_OPCODE",
        "STACK_UNDERFLOW", "STACK_OVERFLOW", "BAD_JUMP", "STATIC_VIOLATION",
        "RETURNDATA_OOB", "CREATE_COLLISION", "CODE_TOO_LARGE",
        "INVALID_CODE_PREFIX", "PRECOMPILE_FAILURE", "BUDGET"
    };
    return (s >= 0 && (size_t)s < sizeof(n) / sizeof(n[0])) ? n[s] : "?";
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static int backend_build(const wl_inst_t *w, evm_membackend *mb)
{
    evm_addr a;
    uint8_t bal[32];
    evm_mem_account *acc = NULL;
    evm_membackend_init(mb);

    memset(bal, 0, 32);
    bal[23] = 1;                                   /* 2^64 wei             */
    memset(a.b, SENDER_TAG, 32);
    if (evm_membackend_add_account(mb, &a, 0, bal, NULL, 0, NULL, NULL) != 0)
        return -2;

    memset(bal, 0, 32);
    memset(a.b, CONTRACT_TAG, 32);
    if (evm_membackend_add_account(mb, &a, 1, bal, w->code, w->code_len,
                                   NULL, &acc) != 0)
        return -2;
    for (uint64_t i = 0; i < w->prefill_slots; i++) {
        evm_bytes32 k, v;
        memset(&k, 0, sizeof(k));
        memset(&v, 0, sizeof(v));
        for (int b = 0; b < 8; b++) k.b[31 - b] = (uint8_t)(i >> (8 * b));
        v.b[31] = 1;
        if (evm_mem_account_add_slot(acc, &k, &v) != 0) return -2;
    }

    if (w->prefill_accounts) {
        uint8_t *code = NULL;
        evm_bytes32 h;
        if (w->prefill_code_len) {
            code = calloc(1, w->prefill_code_len);
            if (!code) return -2;
            if (keccak256(code, w->prefill_code_len, h.b) != 0) {
                free(code);
                return -2;
            }
        }
        memset(bal, 0, 32);
        bal[31] = 1;
        for (uint64_t i = 0; i < w->prefill_accounts; i++) {
            memcpy(a.b, w->acct_base, 32);
            for (int b = 0; b < 8; b++) a.b[31 - b] = (uint8_t)(i >> (8 * b));
            if (evm_membackend_add_account(mb, &a, code ? 1 : 0, bal, code,
                                           w->prefill_code_len,
                                           code ? &h : NULL, NULL) != 0) {
                free(code);
                return -2;
            }
        }
        free(code);
    }
    return evm_membackend_finalize(mb) == 0 ? 0 : -2;
}

static void run_one(size_t idx, uint64_t gas, unsigned reps, result_t *r)
{
    const wl_def_t *d = wl_get(idx);
    wl_inst_t w;
    wl_params_t p = { gas, 0 };
    char msg[256];
    memset(r, 0, sizeof(*r));
    r->idx = (int)idx;

    int rc = wl_build(d, &p, &w, msg, sizeof(msg));
    if (rc == -1) {
        printf("%-24s SKIP (%s)\n", d->name, msg);
        r->state = 0;
        return;
    }
    if (rc != 0) {
        printf("%-24s FAIL build: %s\n", d->name, msg);
        r->state = -1;
        return;
    }

    evm_membackend mb;
    if (backend_build(&w, &mb) != 0) {
        printf("%-24s FAIL backend (allocation)\n", d->name);
        evm_membackend_free(&mb);
        wl_inst_free(&w);
        r->state = -1;
        return;
    }
    evm_backend_t be;
    evm_membackend_bind(&mb, &be);
    evm_config_t cfg;
    make_cfg(&cfg);
    evm_block_env_t env;
    memset(&env, 0, sizeof(env));
    env.number = 100;
    env.timestamp = 1000;
    env.gas_limit = gas;

    evm_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.type = 0;
    memset(tx.sender.b, SENDER_TAG, 32);
    memset(tx.to.b, CONTRACT_TAG, 32);
    tx.nonce = 0;
    tx.gas_limit = gas;
    tx.data = w.data;
    tx.data_len = w.data_len;
    tx.has_chain_id = 1;
    chain_id_of(&tx.chain_id);
    for (int k = 0; k < 64; k++) tx.intent_id[k] = (uint8_t)(0x40 + k);

    uint64_t *t_apply = calloc(reps, sizeof(uint64_t));
    uint64_t *t_visit = calloc(reps, sizeof(uint64_t));
    visit_t vis = { 0, 0 };
    size_t n_logs = 0;
    int ok = (t_apply && t_visit) ? 1 : 0;
    for (unsigned i = 0; i < reps && ok; i++) {
        evm_state_t *st = evm_state_new(&cfg, &be);
        evm_tx_result_t res;
        memset(&res, 0, sizeof(res));
        if (!st) {
            ok = 0;
            break;
        }
        uint64_t t0 = now_ns();
        rc = evm_tx_apply(st, &env, &tx, &res);
        uint64_t t1 = now_ns();
        if (rc != 0) {
            printf("%-24s FAIL evm_tx_apply rc %d (tx_error %d)\n", d->name,
                   rc, (int)res.tx_error);
            evm_tx_result_free(&res);
            evm_state_free(st);
            ok = 0;
            break;
        }
        memset(&vis, 0, sizeof(vis));
        evm_change_visitor_t v = { vis_account, vis_storage, &vis };
        uint64_t t2 = now_ns();
        int vrc = evm_state_visit_changes(st, &v);
        uint64_t t3 = now_ns();
        if (vrc != 0) {
            printf("%-24s FAIL evm_state_visit_changes rc %d\n", d->name, vrc);
            ok = 0;
        }
        t_apply[i] = t1 - t0;
        t_visit[i] = t3 - t2;
        r->gas_used = res.gas_used;
        r->status = (int)res.status;
        n_logs = res.n_logs;
        evm_tx_result_free(&res);
        evm_state_free(st);
    }

    if (ok) {
        uint64_t med_visit;
        qsort(t_apply, reps, sizeof(uint64_t), cmp_u64);
        qsort(t_visit, reps, sizeof(uint64_t), cmp_u64);
        r->min_ms = (double)t_apply[0] / 1e6;
        r->max_ms = (double)t_apply[reps - 1] / 1e6;
        r->med_ms = (double)t_apply[reps / 2] / 1e6;
        med_visit = t_visit[reps / 2];
        r->visit_ms = (double)med_visit / 1e6;
        r->ns_per_gas = r->gas_used ? (double)t_apply[reps / 2] /
                                          (double)r->gas_used : 0.0;
        r->mgas_s = r->ns_per_gas > 0 ? 1000.0 / r->ns_per_gas : 0.0;
        r->rss_kib = peak_rss_kib();
        r->early = (r->gas_used + w.slack + 50000u < gas) ? 1 : 0;
        r->state = 1;
        printf("%-24s %-10s gas_used %10llu (%5.1f%%)  apply ms med %9.2f "
               "min %9.2f max %9.2f  ns/gas %8.3f  Mgas/s %8.2f  "
               "visit ms %7.2f  changes accts %llu slots %llu logs %zu  "
               "peak_rss %.1f MiB\n",
               d->name, status_name(r->status),
               (unsigned long long)r->gas_used,
               100.0 * (double)r->gas_used / (double)gas, r->med_ms,
               r->min_ms, r->max_ms, r->ns_per_gas, r->mgas_s, r->visit_ms,
               (unsigned long long)vis.accounts,
               (unsigned long long)vis.slots, n_logs,
               (double)r->rss_kib / 1024.0);
        if (w.pc_addr)
            printf("%-24s   precompile 0x%02x: %llu bytes/call, k %llu, exact "
                   "cost %llu gas/call (evm_precompile_run), ~%llu calls\n",
                   "", w.pc_addr, (unsigned long long)w.pc_input_len,
                   (unsigned long long)w.pc_k,
                   (unsigned long long)w.pc_cost,
                   (unsigned long long)(w.pc_cost
                                            ? r->gas_used / w.pc_cost : 0));
        if (r->status != EVM_EXEC_SUCCESS)
            printf("%-24s   WARN execution did not end in SUCCESS — the "
                   "number measures a failure path\n", "");
        if (r->early)
            printf("%-24s   WARN used less than gas - slack (%llu): the loop "
                   "exited early\n", "", (unsigned long long)w.slack);
    } else {
        r->state = -1;
    }
    free(t_apply);
    free(t_visit);
    evm_membackend_free(&mb);
    wl_inst_free(&w);
}

/* ── driver ──────────────────────────────────────────────────────────── */

static int selected(const char *name, char **only, size_t n_only)
{
    if (n_only == 0) return 1;
    for (size_t i = 0; i < n_only; i++)
        if (strcmp(only[i], name) == 0) return 1;
    return 0;
}

static int cmp_res(const void *a, const void *b)
{
    const result_t *x = a, *y = b;
    if (x->ns_per_gas < y->ns_per_gas) return 1;
    if (x->ns_per_gas > y->ns_per_gas) return -1;
    return x->idx - y->idx;
}

static void usage(void)
{
    printf("usage: evm_bench [--gas N] [--reps R] [--only name[,name...]] "
           "[--no-fork] [--list]\n");
}

int main(int argc, char **argv)
{
    uint64_t gas = DEFAULT_GAS;
    unsigned reps = DEFAULT_REPS;
    int fork_each = 1;
    char *only[256];
    size_t n_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--gas") == 0 && i + 1 < argc) {
            gas = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--reps") == 0 && i + 1 < argc) {
            reps = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--no-fork") == 0) {
            fork_each = 0;
        } else if (strcmp(argv[i], "--only") == 0 && i + 1 < argc) {
            char *s = argv[++i];
            for (char *tok = strtok(s, ","); tok && n_only < 256;
                 tok = strtok(NULL, ","))
                only[n_only++] = tok;
        } else if (strcmp(argv[i], "--list") == 0) {
            for (size_t k = 0; k < wl_count(); k++)
                printf("%-24s %s\n", wl_get(k)->name, wl_get(k)->why);
            return 0;
        } else {
            usage();
            return 2;
        }
    }
    if (gas < 100000u || reps == 0 || reps > MAX_REPS) {
        usage();
        return 2;
    }
    for (size_t i = 0; i < n_only; i++)
        if (!wl_find(only[i])) {
            printf("unknown workload: %s (see --list)\n", only[i]);
            return 2;
        }

    printf("Nodus EVM measurement gate (a): bare engine, in-memory backend\n");
    print_machine();
    printf("gas per tx %llu, reps %u, %s; Comet timeout_commit %.0f ms "
           "(nodus_witness_cmt_node.c:1794)\n",
           (unsigned long long)gas, reps,
           fork_each ? "one forked child per workload (RSS per workload)"
                     : "single process (RSS cumulative)",
           CMT_TIMEOUT_COMMIT_MS);

    /* forces every precompile library's one-time initialisation (KZG
     * setup, mcl; SHA-256 / RIPEMD-160 are pinned code with none) before
     * anything is timed */
    if (evm_precompile_selftest() != 0) {
        printf("FAIL: evm_precompile_selftest\n");
        return 1;
    }
    printf("parent peak RSS after init: %.1f MiB\n\n",
           (double)peak_rss_kib() / 1024.0);
    fflush(stdout);

    result_t *all = calloc(wl_count(), sizeof(result_t));
    if (!all) return 1;
    size_t n_all = 0;
    int failed = 0;

    for (size_t i = 0; i < wl_count(); i++) {
        if (!selected(wl_get(i)->name, only, n_only)) continue;
        result_t r;
        memset(&r, 0, sizeof(r));
        r.idx = (int)i;
        if (!fork_each) {
            run_one(i, gas, reps, &r);
        } else {
            int fd[2];
            if (pipe(fd) != 0) return 1;
            fflush(stdout);
            pid_t pid = fork();
            if (pid < 0) return 1;
            if (pid == 0) {
                close(fd[0]);
                run_one(i, gas, reps, &r);
                fflush(stdout);
                ssize_t wn = write(fd[1], &r, sizeof(r));
                close(fd[1]);
                _exit(wn == (ssize_t)sizeof(r) ? 0 : 1);
            }
            close(fd[1]);
            ssize_t rn = read(fd[0], &r, sizeof(r));
            close(fd[0]);
            int wst = 0;
            while (waitpid(pid, &wst, 0) < 0 && errno == EINTR) {}
            if (rn != (ssize_t)sizeof(r) || !WIFEXITED(wst) ||
                WEXITSTATUS(wst) != 0) {
                printf("%-24s FAIL child ended abnormally (%s %d)\n",
                       wl_get(i)->name,
                       WIFSIGNALED(wst) ? "signal" : "exit",
                       WIFSIGNALED(wst) ? WTERMSIG(wst) : WEXITSTATUS(wst));
                memset(&r, 0, sizeof(r));
                r.idx = (int)i;
                r.state = -1;
            }
        }
        if (r.state < 0) failed = 1;
        all[n_all++] = r;
        fflush(stdout);
    }

    /* summary: ran workloads, worst ns/gas first */
    size_t n_ran = 0;
    for (size_t i = 0; i < n_all; i++)
        if (all[i].state == 1) all[n_ran++] = all[i];
    qsort(all, n_ran, sizeof(result_t), cmp_res);
    printf("\nSUMMARY (worst ns/gas first). \"ms@30M\" = ns/gas x 30 000 000"
           " — the engine time of a 30 M-gas block of only this work, to "
           "compare with timeout_commit %.0f ms\n", CMT_TIMEOUT_COMMIT_MS);
    printf("%-24s %10s %10s %10s %10s %8s %s\n", "workload", "ns/gas",
           "Mgas/s", "ms@30M", "gas_used", "rss_MiB", "status");
    for (size_t i = 0; i < n_ran; i++) {
        const result_t *r = &all[i];
        printf("%-24s %10.3f %10.2f %10.1f %10llu %8.1f %s%s\n",
               wl_get((size_t)r->idx)->name, r->ns_per_gas, r->mgas_s,
               r->ns_per_gas * 30.0, (unsigned long long)r->gas_used,
               (double)r->rss_kib / 1024.0, status_name(r->status),
               r->early ? " EARLY-EXIT" : "");
    }
    free(all);
    return failed ? 1 : 0;
}
