/**
 * test_faucet_stub.c — shared fixture of the nodus-faucet tests.
 *
 * NOT a build target: test_faucet_decision.c, test_faucet_state.c and
 * test_faucet_http.c `#include` this file (the whitelist of the package is
 * `tests/test_faucet_*.c`). It provides
 *   - stub_t: a scriptable node behind faucet_node_t (canned answers,
 *     counters, the bytes of the last submit),
 *   - env_t: stub + config + one faucet identity + a journal in a mkdtemp
 *     directory + a faucet_core_t, with env_reopen() to simulate a restart
 *     (journal closed and opened again from the same file, a NEW core),
 *   - small helpers (deterministic randomness, addresses, coins).
 *
 * HOW IT CAN LIE: the stub answers what the test tells it to; it proves the
 * faucet's logic against those answers, not the node's behaviour. It does
 * not wait, so it records the deadline of each call (last_deadline) instead
 * of honouring it. The
 * builder and planner are the REAL ones (nodus_v2_spend_*) with the newest
 * pinned rule-set generation, so a built envelope is a real signed envelope.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/nodus_identity.h"
#include "faucet_core.h"
#include "faucet_journal.h"
#include "faucet_node.h"
#include "nodus/nodus_v2_spend.h"

/* Each including test uses a different subset of the helpers marked so. */
#define FT_MAYBE_UNUSED __attribute__((unused))

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── deterministic randomness (xorshift64*, fixed seed) ────────────── */
static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static int test_rand(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    for (size_t i = 0; i < len; i++) {
        g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27;
        buf[i] = (uint8_t)((g_rng * 0x2545F4914F6CDD1DULL) >> 56);
    }
    return 0;
}

/* ── the stub node ──────────────────────────────────────────────────── */
typedef struct {
    uint8_t  chain[32];
    int      chain_rc;
    nodus_dnac_ruleset_info_t ri;
    int      ri_rc;
    uint64_t gas;
    int      gas_rc;
    int      name_rc, name_found;
    char     name[37];
    uint64_t name_ch;
    int      name_ch_off_calls;      /* the first N name_of calls report ch+1 */
    int      name_ch_off_always;     /* every call reports ch+1               */
    int      bal_rc;
    uint64_t bal_tip, bal_native;    /* any owner but the faucet               */
    char     self_hex[129];
    int      self_rc;
    uint64_t self_native, self_token;
    faucet_coin_list_t nat, tok;
    int      nat_rc, tok_rc;
    uint64_t applied_height;         /* 0 = never applied                      */
    uint8_t  applied_intent[64];
    uint64_t not_held_below;         /* heights below this: NOT_HELD           */
    uint64_t err_height;             /* this height: ERR                       */
    int      submit_rc;
    int      submit_calls;
    uint8_t *last_env;
    size_t   last_env_len;
    int      name_calls, bal_calls, scan_calls;
    int      node_calls;              /* every call of any kind                */
    uint64_t last_deadline;           /* the deadline of the latest call       */
    uint64_t scan_max_seen;
    int      scan_pages;              /* >0: a block has this many pages     */
    int      scan_budget_pages;       /* pages one scan call may read        */
    int      scan_found_page;         /* the page holding the applied item   */
    int      pages_read;              /* pages read over all calls           */
    int      scan_from_zero;          /* calls that started at page 0        */
} stub_t;

/* The stub does not wait, so it cannot honour a deadline; it records what
 * the core handed down (the deadline plumbing is what the tests pin). */
#define STUB_NOTE(s, dl) do { (s)->node_calls++; (s)->last_deadline = (dl); } while (0)

static int s_chain(void *c, uint8_t out[32], uint64_t dl) {
    stub_t *s = c;
    STUB_NOTE(s, dl);
    if (s->chain_rc) return s->chain_rc;
    memcpy(out, s->chain, 32);
    return 0;
}
static int s_ri(void *c, nodus_dnac_ruleset_info_t *out, uint64_t dl) {
    stub_t *s = c;
    STUB_NOTE(s, dl);
    if (s->ri_rc) return s->ri_rc;
    *out = s->ri;
    return 0;
}
static int s_gas(void *c, uint64_t *out, uint64_t dl) {
    stub_t *s = c;
    STUB_NOTE(s, dl);
    if (s->gas_rc) return s->gas_rc;
    *out = s->gas;
    return 0;
}
static int s_name(void *c, const char *owner, nodus_dnac_name_result_t *out,
                  uint64_t dl) {
    stub_t *s = c;
    (void)owner;
    STUB_NOTE(s, dl);
    s->name_calls++;
    if (s->name_rc) return s->name_rc;
    memset(out, 0, sizeof(*out));
    out->found = s->name_found != 0;
    if (s->name_found) snprintf(out->name, sizeof(out->name), "%s", s->name);
    out->committed_height = s->name_ch;
    if (s->name_ch_off_always || s->name_calls <= s->name_ch_off_calls)
        out->committed_height += 1;
    return 0;
}
static int s_balance(void *c, const char *owner, const uint8_t token[64],
                     uint64_t *tip, uint64_t *total, uint64_t dl) {
    stub_t *s = c;
    static const uint8_t zero[64] = {0};
    STUB_NOTE(s, dl);
    int native = memcmp(token, zero, 64) == 0;
    if (!strcmp(owner, s->self_hex)) {
        if (s->self_rc) return s->self_rc;
        *tip = s->bal_tip;
        *total = native ? s->self_native : s->self_token;
        return 0;
    }
    s->bal_calls++;
    if (s->bal_rc) return s->bal_rc;
    *tip = s->bal_tip;
    *total = native ? s->bal_native : 0;
    return 0;
}
static int s_coins(void *c, const uint8_t token[64], faucet_coin_list_t *out,
                   uint64_t dl) {
    stub_t *s = c;
    static const uint8_t zero[64] = {0};
    STUB_NOTE(s, dl);
    if (memcmp(token, zero, 64) == 0) {
        if (s->nat_rc) return s->nat_rc;
        *out = s->nat;
    } else {
        if (s->tok_rc) return s->tok_rc;
        *out = s->tok;
    }
    return 0;
}
static int s_scan(void *c, uint64_t h, const uint8_t intent[64], uint32_t *from,
                  int *found, uint64_t dl) {
    stub_t *s = c;
    STUB_NOTE(s, dl);
    s->scan_calls++;
    if (h > s->scan_max_seen) s->scan_max_seen = h;
    if (s->err_height && h == s->err_height) return FAUCET_NODE_ERR;
    if (s->not_held_below && h < s->not_held_below) return FAUCET_NODE_NOT_HELD;
    int applied = (s->applied_height == h && memcmp(intent, s->applied_intent, 64) == 0);
    if (s->scan_pages <= 0) {                 /* one page: the whole block   */
        *found = applied;
        return 0;
    }
    /* a slow block: `scan_pages` pages, only `scan_budget_pages` readable
     * per call (the adapter's time budget). `*from` is the page index. */
    if (*from == 0) s->scan_from_zero++;
    int budget = s->scan_budget_pages;
    while ((int)*from < s->scan_pages) {
        if (budget-- <= 0) return FAUCET_NODE_ERR;      /* out of time       */
        s->pages_read++;
        if (applied && (int)*from == s->scan_found_page) *found = 1;
        (*from)++;
    }
    return 0;
}
static int s_submit(void *c, const uint8_t wire[64], const uint8_t *env,
                    size_t len, char *msg, size_t cap, uint64_t dl) {
    stub_t *s = c;
    (void)wire;
    STUB_NOTE(s, dl);
    s->submit_calls++;
    free(s->last_env);
    s->last_env = malloc(len);
    memcpy(s->last_env, env, len);
    s->last_env_len = len;
    if (cap) snprintf(msg, cap, "stub");
    return s->submit_rc;
}

static void stub_vt(stub_t *s, faucet_node_t *vt) {
    memset(vt, 0, sizeof(*vt));
    vt->ctx = s;
    vt->chain_id32 = s_chain;
    vt->ruleset_info = s_ri;
    vt->gas_price = s_gas;
    vt->name_of = s_name;
    vt->balance = s_balance;
    vt->coins = s_coins;
    vt->scan_block = s_scan;
    vt->submit = s_submit;
}

/* ── helpers ────────────────────────────────────────────────────────── */
static void make_addr(char out[129], int seed) {
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 128; i++) out[i] = d[(seed * 7 + i * 3 + (i >> 3)) & 15];
    out[0] = d[1 + (seed & 7)];          /* never all-zero */
    out[128] = '\0';
}

static void add_coin(faucet_coin_list_t *l, int seed, uint64_t amount) {
    faucet_coin_t *c = &l->c[l->n++];
    memset(c, 0, sizeof(*c));
    for (int i = 0; i < 64; i++) c->nul[i] = (uint8_t)(seed * 31 + i);
    c->amount = amount;
    c->unlock_block = 0;
}

/* ── the environment ────────────────────────────────────────────────── */
typedef struct {
    stub_t           st;
    faucet_node_t    vt;
    faucet_cfg_t     cfg;
    faucet_journal_t *j;
    faucet_core_t    core;
    char             dir[64];
    char             jpath[96];
} env_t;

static nodus_identity_t *g_id;   /* one faucet key for the whole test file */

static void ensure_id(void) {
    if (g_id) return;
    g_id = calloc(1, sizeof(*g_id));
    if (!g_id || nodus_identity_generate(g_id) != 0) {
        printf("FATAL: identity generation failed\n");
        exit(2);
    }
}

static void env_wire(env_t *e) {
    stub_vt(&e->st, &e->vt);
    if (faucet_core_init(&e->core, &e->cfg, &e->vt, e->j, g_id->pk.bytes,
                         g_id->sk.bytes, test_rand, NULL) != 0) {
        printf("FATAL: core init failed\n");
        exit(2);
    }
    snprintf(e->st.self_hex, sizeof(e->st.self_hex), "%s", e->core.self_hex);
    faucet_core_check_chain(&e->core);
    faucet_core_refresh_status(&e->core);   /* /status answers from this cache */
}

/* A funded faucet at tip 1000 on the newest pinned generation. */
static void env_open(env_t *e, uint64_t storage_ceiling) {
    ensure_id();
    memset(e, 0, sizeof(*e));
    snprintf(e->dir, sizeof(e->dir), "/tmp/faucet_test_XXXXXX");
    if (!mkdtemp(e->dir)) { printf("FATAL: mkdtemp\n"); exit(2); }
    snprintf(e->jpath, sizeof(e->jpath), "%s/journal.db", e->dir);

    faucet_cfg_defaults(&e->cfg);
    for (int i = 0; i < 32; i++) e->cfg.chain_id[i] = (uint8_t)(0xC0 + i);
    for (int i = 0; i < 64; i++) e->cfg.token_id[i] = (uint8_t)(0x71 + i);
    snprintf(e->cfg.node_host, sizeof(e->cfg.node_host), "127.0.0.1");
    e->cfg.queue_cap = 4;

    stub_t *s = &e->st;
    memcpy(s->chain, e->cfg.chain_id, 32);
    uint32_t gen = nodus_v2_pins_generation_count();
    s->ri.tip = 1000;
    s->ri.generation = gen;
    nodus_v2_pins_tuples(gen, &s->ri.sys_version, s->ri.sys_hash,
                         &s->ri.core_version, s->ri.core_hash);
    s->gas = 0;
    s->bal_tip = 1000;
    s->name_ch = 1000;
    s->self_native = 20000000000000ULL;      /* 200 000 NODUS */
    s->self_token  = 500000000ULL;           /* 500 tUSDT     */
    add_coin(&s->nat, 1, 20000000000000ULL);
    add_coin(&s->tok, 2, 500000000ULL);
    s->nat.tip = s->tok.tip = 1000;

    if (faucet_journal_open(e->jpath, storage_ceiling, &e->j) != 0) {
        printf("FATAL: journal open\n");
        exit(2);
    }
    env_wire(e);
}

/* A restart: the journal is closed and opened again from the same file and
 * a NEW core is wired; the stub (the node's world) is kept. */
FT_MAYBE_UNUSED static void env_reopen(env_t *e) {
    faucet_journal_close(e->j);
    e->j = NULL;
    if (faucet_journal_open(e->jpath, e->cfg.storage_ceiling, &e->j) != 0) {
        printf("FATAL: journal reopen\n");
        exit(2);
    }
    env_wire(e);
}

static void env_close(env_t *e) {
    faucet_journal_close(e->j);
    free(e->st.last_env);
    char p[160];
    snprintf(p, sizeof(p), "%s/journal.db", e->dir); unlink(p);
    snprintf(p, sizeof(p), "%s/journal.db-wal", e->dir); unlink(p);
    snprintf(p, sizeof(p), "%s/journal.db-shm", e->dir); unlink(p);
    rmdir(e->dir);
}

/* The head claim as the API shows it, or NULL-state when there is none. */
FT_MAYBE_UNUSED static int head_state(env_t *e, char *state, size_t cap) {
    faucet_claim_t c;
    int r = faucet_journal_head(e->j, &c);
    if (r == 0) snprintf(state, cap, "%s", c.state);
    else snprintf(state, cap, "none");
    return r;
}

/* Create a claim through the API for a fresh address. @return the answer. */
FT_MAYBE_UNUSED static faucet_answer_t api_claim(env_t *e, const char *addr) {
    faucet_answer_t a;
    faucet_api_claim(&e->core, addr, FAUCET_NODE_NO_DEADLINE, &a);
    return a;
}
