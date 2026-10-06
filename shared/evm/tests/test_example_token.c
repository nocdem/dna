/**
 * @file test_example_token.c
 * @brief The Nodus EVM example token (nodus/tools/evm/examples/NodusToken.sol)
 *        runs as an ERC-20-style token in the engine's 32-byte mode.
 *
 * Governing records: docs/plans/decisions/2026-10-06-evm-dev-tooling.md item 1
 * (developer pack: guide + example token), 2026-10-04-nodus-evm-domain.md
 * decision 3 (32-byte addresses), and the semantic rules of
 * nodus/tools/evm/solc/README.md.
 *
 * WHAT IT PROVES
 *   For both committed compiler configurations of the example (default =
 *   exactly what `nodus-cli evm deploy --solc` compiles, and --optimize), the
 *   token deployed from its committed creation bytecode, with accounts whose
 *   HIGH 12 bytes are non-zero:
 *   - deploys at the engine's CREATE address of (deployer32, nonce), runs the
 *     constructor (whole supply to the deployer, Transfer(0, deployer, S)),
 *     and its deployed code equals the committed runtime bytecode;
 *   - answers name / symbol / decimals / totalSupply / INITIAL_SUPPLY;
 *   - transfer moves balances between full 32-byte accounts and emits
 *     Transfer(from, to, value);
 *   - approve sets allowance(owner32, spender32) and emits
 *     Approval(owner, spender, value);
 *   - transferFrom spends the allowance, moves the balance and emits Transfer;
 *   - every event has exactly 3 topics: topic0 = keccak256 of the event
 *     signature, topics 1-2 = the FULL 32-byte addresses, data = the amount;
 *   - the raw storage slots hold the balances at keccak256(addr32 ‖ 1) and
 *     the allowance at keccak256(spender32 ‖ keccak256(owner32 ‖ 2)).
 *   Negative controls, one per class: every address result is also checked
 *   to differ from the 160-bit-masked value (12 zero bytes ‖ low 20); the
 *   TWIN of each account (same low 20 bytes, different high 12) has balance
 *   0 and allowance 0, and its raw slot is untouched; a transfer above the
 *   balance and one to address(0) revert with their reason and no log; a
 *   transferFrom above the allowance reverts; the spender's TWIN cannot spend
 *   the spender's allowance (revert); balances / allowances are unchanged
 *   after each revert.
 *
 * WHAT IT REQUIRES
 *   The COMMITTED outputs nodus/tools/evm/examples/out/<config>/
 *   NodusToken.{creation,runtime}.hex (written by examples/build.sh with the
 *   Nodus solc); no solc at test time. Directory: argv[1], else
 *   EXAMPLES_OUT (default "../../nodus/tools/evm/examples/out", relative to
 *   shared/evm, where `make test` runs it). A missing or malformed .hex is a
 *   FAIL, never a skip. No compile flags, no environment variables.
 *
 * ENGINE PROFILE
 *   As nodus_witness_rt_evm.c builds it (addr_bytes 32, nodus_profile 1,
 *   Prague precompiles, ticket unit 10^10, ticket gas 25000, base fee 0,
 *   gas price 0, type-1 txs, 32-byte chain id, coinbase zero). The ticket
 *   address is a fixed high-byte constant, not the production SHA3-512
 *   derivation (no ticket is created by this test).
 *
 * EXPECTED VALUES
 *   Fixed inputs below; the supply 10^24 = 0xd3c21bcecceda1000000 (computed
 *   outside the engine); CREATE = keccak256(rlp([sender32, nonce])) (engine
 *   design §2), the helper SELF-CHECKED at startup against the committed
 *   oracle vectors of tests/addr32_oracle.py (addr32_vectors.h); event topic0
 *   and selectors = keccak256 of the Solidity signatures.
 *
 * WHAT IT LEAVES BEHIND
 *   Nothing (in-memory backend, no files written).
 *
 * HOW IT CAN LIE
 *   - It tests the bytecode in out/, i.e. whatever solc wrote it; check
 *     out/VERSION.txt (build.sh refuses a solc without the nodus.addr256 tag).
 *     A source edit without re-running build.sh leaves out/ stale: nothing
 *     here compares the .sol with the .hex.
 *   - The engine is the shared/evm engine itself: an engine defect that
 *     mirrors a compiler defect would cancel out (test_addr32.c pins the
 *     engine's 32-byte rules separately).
 *   - The chain's envelope, fee and receipt path (nodus-cli / the node) is
 *     not exercised — only the EVM execution of the token.
 *
 * Standalone harness: exit 0 = every assertion in every configuration
 * passed, 1 = an assertion failed (or a .hex is missing), 2 = engine fault.
 */
#include "evm.h"
#include "evm_membackend.h"
#include "addr32_vectors.h"
#include "crypto/hash/keccak256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EXAMPLES_OUT
#define EXAMPLES_OUT "../../nodus/tools/evm/examples/out"
#endif

#define TX_GAS     10000000ull
#define BLOCK_GAS  30000000ull
#define FUND_EOA   1000000ull

/* ── fixed inputs: HIGH 12 bytes non-zero ──────────────────────────────── */

/* hi = byte for bytes 0..11, lo = byte for bytes 12..31 */
static void mk_addr(uint8_t out[32], uint8_t hi, uint8_t lo)
{
    memset(out, hi, 12);
    memset(out + 12, lo, 20);
}

static uint8_t OWNER[32];       /* deployer: 0xa1*12 ‖ 0x11*20           */
static uint8_t OWNER_TWIN[32];  /* 0xc1*12 ‖ 0x11*20                     */
static uint8_t ALICE[32];       /* 0xa2*12 ‖ 0x22*20                     */
static uint8_t ALICE_TWIN[32];  /* 0xc2*12 ‖ 0x22*20                     */
static uint8_t BOB[32];         /* the spender: 0xa3*12 ‖ 0x33*20        */
static uint8_t BOB_TWIN[32];    /* funded EOA, same low 20 as BOB        */
static uint8_t CAROL[32];       /* recipient, absent before: 0xa4 ‖ 0x44 */
static uint8_t TICKET[32];      /* ticket address (config only): 0x7e*32 */

/* 10^24 = 1 000 000 tokens × 10^18 = 0xd3c21bcecceda1000000 */
static uint8_t SUPPLY[32];

static void init_inputs(void)
{
    static const uint8_t s[10] = { 0xd3, 0xc2, 0x1b, 0xce, 0xcc, 0xed, 0xa1,
                                   0x00, 0x00, 0x00 };
    mk_addr(OWNER, 0xa1, 0x11);
    mk_addr(OWNER_TWIN, 0xc1, 0x11);
    mk_addr(ALICE, 0xa2, 0x22);
    mk_addr(ALICE_TWIN, 0xc2, 0x22);
    mk_addr(BOB, 0xa3, 0x33);
    mk_addr(BOB_TWIN, 0xc3, 0x33);
    mk_addr(CAROL, 0xa4, 0x44);
    memset(TICKET, 0x7e, 32);
    memset(SUPPLY, 0, 32);
    memcpy(SUPPLY + 22, s, 10);
}

/* ── small helpers ─────────────────────────────────────────────────────── */

static void fatal(const char *what)
{
    fprintf(stderr, "FATAL: %s\n", what);
    exit(2);
}

static void word_u64(uint8_t out[32], uint64_t v)
{
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(v >> (8 * i));
}

/* out = a - v (big-endian 256-bit, a >= v by construction) */
static void word_sub_u64(uint8_t out[32], const uint8_t a[32], uint64_t v)
{
    unsigned borrow = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned sub = (31 - i < 8) ? (unsigned)((v >> (8 * (31 - i))) & 0xff) : 0;
        int d = (int)a[i] - (int)sub - (int)borrow;
        borrow = d < 0;
        out[i] = (uint8_t)(d < 0 ? d + 256 : d);
    }
    if (borrow) fatal("word_sub_u64 underflow");
}

static void mask20(uint8_t out[32], const uint8_t in[32])
{
    memset(out, 0, 12);
    memcpy(out + 12, in + 12, 20);
}

static int high_nonzero(const uint8_t a[32])
{
    for (int i = 0; i < 12; i++)
        if (a[i]) return 1;
    return 0;
}

static void kec(const uint8_t *d, size_t n, uint8_t out[32])
{
    if (keccak256(d, n, out) != 0) fatal("keccak256");
}

static void print_word(const char *label, const uint8_t w[32])
{
    fprintf(stderr, "      %s ", label);
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", w[i]);
    fprintf(stderr, "\n");
}

/* CREATE = keccak256(rlp([sender32, nonce])) (engine design §2) */
static void create_addr(uint8_t out[32], const uint8_t sender[32], uint64_t nonce)
{
    uint8_t buf[64];
    uint8_t nb[8];
    size_t nl = 0, p = 0;
    for (int i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)(nonce >> (8 * i));
        if (nl || b) nb[nl++] = b;
    }
    size_t nenc = (nl == 1 && nb[0] < 0x80) ? 1 : 1 + nl;
    buf[p++] = (uint8_t)(0xc0 + 33 + nenc);
    buf[p++] = 0xa0;
    memcpy(buf + p, sender, 32);
    p += 32;
    if (nl == 1 && nb[0] < 0x80) {
        buf[p++] = nb[0];
    } else {
        buf[p++] = (uint8_t)(0x80 + nl);
        memcpy(buf + p, nb, nl);
        p += nl;
    }
    kec(buf, p, out);
}

/* The CREATE helper against the committed oracle vectors. Nonce 0 (the
 * deployment here) encodes as 0x80, the multi-byte branch with nl == 0. */
static int self_check_rules(void)
{
    struct { const uint8_t *s; uint64_t n; const uint8_t *want; } v[] = {
        { ADDR32_FACTORY, 0x7f, ADDR32_EXP_CREATE_FACTORY_N7F },
        { ADDR32_FACTORY, 0x80, ADDR32_EXP_CREATE_FACTORY_N80 },
        { ADDR32_CREATOR0, ADDR32_NONCE_CREATOR0, ADDR32_EXP_TXCREATE_CREATOR0 },
        { ADDR32_CREATOR1, ADDR32_NONCE_CREATOR1, ADDR32_EXP_TXCREATE_CREATOR1 },
        { ADDR32_EF_FACTORY, ADDR32_NONCE_EF_FACTORY, ADDR32_EXP_CREATE_EF_FACTORY_N1 },
    };
    int bad = 0;
    uint8_t got[32];
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        create_addr(got, v[i].s, v[i].n);
        if (memcmp(got, v[i].want, 32) != 0) {
            fprintf(stderr, "  [FAIL] oracle: CREATE vector %u\n", (unsigned)i);
            bad = 1;
        }
    }
    fprintf(stderr, "oracle self-check of the CREATE helper: %s\n",
            bad ? "FAIL" : "PASS");
    return bad;
}

/* ── .hex loading ──────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *b;
    size_t   n;
} blob_t;

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* @return 0, -1 missing / unreadable / malformed (message printed) */
static int load_hex(const char *dir, const char *cfg, const char *kind,
                    blob_t *out)
{
    char path[1024];
    out->b = NULL;
    out->n = 0;
    int pn = snprintf(path, sizeof(path), "%s/%s/NodusToken.%s.hex", dir, cfg, kind);
    if (pn < 0 || (size_t)pn >= sizeof(path)) {
        fprintf(stderr, "  [FAIL] %s: path too long\n", cfg);
        return -1;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "  [FAIL] %s: missing %s\n", cfg, path);
        return -1;
    }
    size_t cap = 4096, n = 0;
    char *txt = malloc(cap);
    if (!txt) fatal("oom");
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (n + 1 >= cap) {
            cap *= 2;
            char *x = realloc(txt, cap);
            if (!x) fatal("oom");
            txt = x;
        }
        txt[n++] = (char)c;
    }
    fclose(f);
    if (n == 0 || n % 2 != 0) {
        fprintf(stderr, "  [FAIL] %s: %s is empty or has an odd length\n", cfg, path);
        free(txt);
        return -1;
    }
    out->b = malloc(n / 2);
    if (!out->b) fatal("oom");
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(txt[2 * i]), lo = hexval(txt[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "  [FAIL] %s: %s is not hex\n", cfg, path);
            free(txt);
            free(out->b);
            out->b = NULL;
            return -1;
        }
        out->b[i] = (uint8_t)(hi * 16 + lo);
    }
    out->n = n / 2;
    free(txt);
    return 0;
}

/* ── per-configuration context ─────────────────────────────────────────── */

/* the transaction senders and their next nonces */
enum { S_OWNER, S_ALICE, S_BOB, S_BOB_TWIN, S_COUNT };

typedef struct {
    const char     *cfg;
    unsigned        pass, fail;
    blob_t          creation, runtime;
    uint8_t         token[32];            /* deployed address */
    evm_membackend  mb;
    evm_backend_t   be;
    evm_config_t    ec;
    evm_block_env_t env;
    evm_state_t    *st;
    uint64_t        nonce[S_COUNT];
} ctx_t;

static const uint8_t *sender_addr(int s)
{
    switch (s) {
    case S_OWNER: return OWNER;
    case S_ALICE: return ALICE;
    case S_BOB:   return BOB;
    default:      return BOB_TWIN;
    }
}

static void ck(ctx_t *c, int cond, const char *what)
{
    if (cond) {
        c->pass++;
    } else {
        c->fail++;
        fprintf(stderr, "  [FAIL] %s: %s\n", c->cfg, what);
    }
}

/* One assertion: got == want, want has non-zero high bytes, and got is NOT
 * the 160-bit-masked value (the negative control of every address check). */
static void ck_addr(ctx_t *c, const uint8_t got[32], const uint8_t want[32],
                    const char *what)
{
    uint8_t masked[32];
    mask20(masked, want);
    int eq = memcmp(got, want, 32) == 0;
    int hi = high_nonzero(want);
    int not_masked = memcmp(got, masked, 32) != 0;
    if (eq && hi && not_masked) {
        c->pass++;
        return;
    }
    c->fail++;
    fprintf(stderr, "  [FAIL] %s: %s%s%s%s\n", c->cfg, what,
            eq ? "" : " (value differs)",
            hi ? "" : " (expected value has zero high bytes: premise broken)",
            not_masked ? "" : " (equals the 160-bit-masked value)");
    print_word("got ", got);
    print_word("want", want);
}

static void ck_word(ctx_t *c, const uint8_t got[32], const uint8_t want[32],
                    const char *what)
{
    if (memcmp(got, want, 32) == 0) {
        c->pass++;
        return;
    }
    c->fail++;
    fprintf(stderr, "  [FAIL] %s: %s\n", c->cfg, what);
    print_word("got ", got);
    print_word("want", want);
}

static void ck_u64(ctx_t *c, const uint8_t got[32], uint64_t want, const char *what)
{
    uint8_t w[32];
    word_u64(w, want);
    ck_word(c, got, w, what);
}

/* ── calldata ──────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t b[256];
    size_t  n;
} cd_t;

static void cd_sel(cd_t *d, const char *sig)
{
    uint8_t h[32];
    kec((const uint8_t *)sig, strlen(sig), h);
    memcpy(d->b, h, 4);
    d->n = 4;
}

static void cd_word(cd_t *d, const uint8_t w[32])
{
    if (d->n + 32 > sizeof(d->b)) fatal("calldata overflow");
    memcpy(d->b + d->n, w, 32);
    d->n += 32;
}

static void cd_u64(cd_t *d, uint64_t v)
{
    uint8_t w[32];
    word_u64(w, v);
    cd_word(d, w);
}

/* ── transactions ──────────────────────────────────────────────────────── */

/* type-1 tx from sender s, gas price 0 (Nodus profile); to NULL = create.
 * @return evm_tx_apply's rc; a fault is fatal. */
static int send_tx(ctx_t *c, int s, const uint8_t *to, const uint8_t *data,
                   size_t len, evm_tx_result_t *res)
{
    evm_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    memset(res, 0, sizeof(*res));
    tx.type = 1;
    memcpy(tx.sender.b, sender_addr(s), 32);
    if (to) memcpy(tx.to.b, to, 32);
    else tx.is_create = 1;
    tx.nonce = c->nonce[s];
    tx.gas_limit = TX_GAS;
    tx.data = data;
    tx.data_len = len;
    tx.has_chain_id = 1;
    tx.chain_id = c->ec.chain_id;
    for (int i = 0; i < 64; i++)
        tx.intent_id[i] = (uint8_t)((unsigned)s * 0x40u + c->nonce[s] + (uint64_t)i);
    int rc = evm_tx_apply(c->st, &c->env, &tx, res);
    if (rc == -2) fatal("evm_tx_apply fault");
    if (rc == 0) c->nonce[s]++;
    return rc;
}

/* Call that must SUCCEED with at least min_words output words.
 * @return 1 ok (res owned by caller), 0 failed (assertion counted, res freed). */
static int call_ok(ctx_t *c, int s, const cd_t *d, size_t min_words,
                   evm_tx_result_t *res, const char *what)
{
    int rc = send_tx(c, s, c->token, d->b, d->n, res);
    if (rc == 0 && res->status == EVM_EXEC_SUCCESS &&
        res->output_len >= 32 * min_words) {
        c->pass++;
        return 1;
    }
    c->fail++;
    fprintf(stderr, "  [FAIL] %s: %s: rc %d status %d output %u bytes "
            "(want >= %u)\n", c->cfg, what, rc, (int)res->status,
            (unsigned)res->output_len, (unsigned)(32 * min_words));
    evm_tx_result_free(res);
    return 0;
}

/* A word-returning view: balanceOf(a) / allowance(o, s) / totalSupply() ... */
static void view_word(ctx_t *c, const cd_t *d, uint8_t out[32], const char *what)
{
    evm_tx_result_t r;
    memset(out, 0xee, 32);                 /* never equals an expected value */
    if (call_ok(c, S_OWNER, d, 1, &r, what)) {
        memcpy(out, r.output, 32);
        evm_tx_result_free(&r);
    }
}

static void balance_of(ctx_t *c, const uint8_t a[32], uint8_t out[32])
{
    cd_t d;
    cd_sel(&d, "balanceOf(address)");
    cd_word(&d, a);
    view_word(c, &d, out, "balanceOf(address)");
}

static void allowance_of(ctx_t *c, const uint8_t o[32], const uint8_t s[32],
                         uint8_t out[32])
{
    cd_t d;
    cd_sel(&d, "allowance(address,address)");
    cd_word(&d, o);
    cd_word(&d, s);
    view_word(c, &d, out, "allowance(address,address)");
}

/* The output of a `returns (string)` view: offset 0x20, length, bytes. */
static void ck_string(ctx_t *c, const char *sig, const char *want)
{
    cd_t d;
    evm_tx_result_t r;
    char what[96];
    size_t wl = strlen(want);
    cd_sel(&d, sig);
    snprintf(what, sizeof(what), "%s returns \"%s\"", sig, want);
    if (!call_ok(c, S_OWNER, &d, 3, &r, what)) return;
    uint8_t w[32];
    word_u64(w, 32);
    int ok = memcmp(r.output, w, 32) == 0;
    word_u64(w, wl);
    ok = ok && memcmp(r.output + 32, w, 32) == 0 && r.output_len >= 64 + wl &&
         memcmp(r.output + 64, want, wl) == 0;
    ck(c, ok, what);
    evm_tx_result_free(&r);
}

/* A call that must REVERT with Error(string) `reason` and leave no log. */
static void ck_revert(ctx_t *c, int s, const cd_t *d, const char *reason,
                      const char *what)
{
    evm_tx_result_t r;
    int rc = send_tx(c, s, c->token, d->b, d->n, &r);
    size_t rl = strlen(reason);
    uint8_t sel[32], w[32];
    kec((const uint8_t *)"Error(string)", 13, sel);
    int ok = rc == 0 && r.status == EVM_EXEC_REVERT && r.n_logs == 0 &&
             r.output_len >= 4 + 64 + rl && memcmp(r.output, sel, 4) == 0;
    if (ok) {
        word_u64(w, 32);
        ok = memcmp(r.output + 4, w, 32) == 0;
        word_u64(w, rl);
        ok = ok && memcmp(r.output + 36, w, 32) == 0 &&
             memcmp(r.output + 68, reason, rl) == 0;
    }
    if (ok) {
        c->pass++;
    } else {
        c->fail++;
        fprintf(stderr, "  [FAIL] %s: %s: rc %d status %d logs %u output %u bytes "
                "(want REVERT \"%s\", no log)\n", c->cfg, what, rc, (int)r.status,
                (unsigned)r.n_logs, (unsigned)r.output_len, reason);
    }
    evm_tx_result_free(&r);
}

/* The single log of a successful write: emitter = the token, 3 topics,
 * topic0 = keccak256(sig), topics 1-2 the full 32-byte addresses (`a1` may
 * be the zero address — the mint), data = one word `value`. */
static void ck_event(ctx_t *c, const evm_tx_result_t *r, const char *sig,
                     const uint8_t a1[32], const uint8_t a2[32],
                     const uint8_t value[32], const char *what)
{
    char m[160];
    uint8_t t0[32];
    static const uint8_t Z[32];
    kec((const uint8_t *)sig, strlen(sig), t0);
    int shape = r->n_logs == 1 && r->logs[0].n_topics == 3 &&
                r->logs[0].data_len == 32;
    snprintf(m, sizeof(m), "%s: one log, 3 topics, 32 data bytes", what);
    ck(c, shape, m);
    if (!shape) return;
    const evm_log_t *l = &r->logs[0];
    snprintf(m, sizeof(m), "%s: emitter = the token", what);
    ck_addr(c, l->addr.b, c->token, m);
    snprintf(m, sizeof(m), "%s: topic0 = keccak256(\"%s\")", what, sig);
    ck_word(c, l->topics[0].b, t0, m);
    snprintf(m, sizeof(m), "%s: topic1 = the full 32-byte address", what);
    if (memcmp(a1, Z, 32) == 0) ck_word(c, l->topics[1].b, Z, m);
    else ck_addr(c, l->topics[1].b, a1, m);
    snprintf(m, sizeof(m), "%s: topic2 = the full 32-byte address", what);
    ck_addr(c, l->topics[2].b, a2, m);
    snprintf(m, sizeof(m), "%s: data = the amount", what);
    ck_word(c, l->data, value, m);
}

/* ── post-state (change set over the pre-state) ────────────────────────── */

typedef struct {
    evm_addr  addr;
    int       code_changed;
    uint8_t  *code;
    size_t    code_len;
} acc_rec;

typedef struct {
    evm_addr    addr;
    evm_bytes32 key;
    evm_bytes32 val;
} slot_rec;

typedef struct {
    acc_rec  *acc;
    size_t    na, cap_a;
    slot_rec *sl;
    size_t    ns, cap_s;
} post_t;

static int cb_account(void *ctx, const evm_account_change_t *ch)
{
    post_t *p = ctx;
    if (p->na == p->cap_a) {
        size_t nc = p->cap_a ? p->cap_a * 2 : 16;
        acc_rec *x = realloc(p->acc, nc * sizeof(*x));
        if (!x) fatal("oom");
        p->acc = x;
        p->cap_a = nc;
    }
    acc_rec *r = &p->acc[p->na++];
    memset(r, 0, sizeof(*r));
    r->addr = ch->addr;
    r->code_changed = ch->code_changed;
    if (ch->code_changed && ch->code_len) {
        r->code = malloc(ch->code_len);
        if (!r->code) fatal("oom");
        memcpy(r->code, ch->code, ch->code_len);
        r->code_len = ch->code_len;
    }
    return 0;
}

static int cb_storage(void *ctx, const evm_addr *addr, const evm_bytes32 *key,
                      const evm_bytes32 *value)
{
    post_t *p = ctx;
    if (p->ns == p->cap_s) {
        size_t nc = p->cap_s ? p->cap_s * 2 : 32;
        slot_rec *x = realloc(p->sl, nc * sizeof(*x));
        if (!x) fatal("oom");
        p->sl = x;
        p->cap_s = nc;
    }
    slot_rec *s = &p->sl[p->ns++];
    s->addr = *addr;
    s->key = *key;
    s->val = *value;
    return 0;
}

static void post_collect(const ctx_t *c, post_t *p)
{
    memset(p, 0, sizeof(*p));
    evm_change_visitor_t v;
    v.account = cb_account;
    v.storage = cb_storage;
    v.ctx = p;
    if (evm_state_visit_changes(c->st, &v) != 0) fatal("visit_changes");
}

static void post_free(post_t *p)
{
    for (size_t i = 0; i < p->na; i++) free(p->acc[i].code);
    free(p->acc);
    free(p->sl);
    memset(p, 0, sizeof(*p));
}

/* @return 1 when the txs wrote the slot (value in out), else 0 (out = 0) */
static int post_slot(const post_t *p, const uint8_t a[32], const uint8_t key[32],
                     uint8_t out[32])
{
    for (size_t i = 0; i < p->ns; i++)
        if (memcmp(p->sl[i].addr.b, a, 32) == 0 &&
            memcmp(p->sl[i].key.b, key, 32) == 0) {
            memcpy(out, p->sl[i].val.b, 32);
            return 1;
        }
    memset(out, 0, 32);
    return 0;
}

/* key = keccak256(k32 ‖ word) — the mapping slot rule */
static void slot_map(uint8_t key[32], const uint8_t k[32], const uint8_t slot[32])
{
    uint8_t buf[64];
    memcpy(buf, k, 32);
    memcpy(buf + 32, slot, 32);
    kec(buf, 64, key);
}

/* ── setup ─────────────────────────────────────────────────────────────── */

static void chain_id_word(evm_u256 *out)
{
    uint8_t b[32];
    for (int i = 0; i < 32; i++) b[i] = (uint8_t)(0xc0 + i);
    evm_u256_from_be(out, b);
}

static void add_eoa(evm_membackend *mb, const uint8_t a[32], uint64_t bal)
{
    uint8_t w[32];
    evm_addr x;
    word_u64(w, bal);
    memcpy(x.b, a, 32);
    if (evm_membackend_add_account(mb, &x, 0, w, NULL, 0, NULL, NULL) != 0)
        fatal("membackend add");
}

static int ctx_open(ctx_t *c, const char *dir, const char *cfg)
{
    memset(c, 0, sizeof(*c));
    c->cfg = cfg;
    int missing = 0;
    if (load_hex(dir, cfg, "creation", &c->creation) != 0) missing++;
    if (load_hex(dir, cfg, "runtime", &c->runtime) != 0) missing++;
    if (missing) {
        c->fail += (unsigned)missing;
        return -1;
    }

    evm_membackend_init(&c->mb);
    for (int s = 0; s < S_COUNT; s++) add_eoa(&c->mb, sender_addr(s), FUND_EOA);
    if (evm_membackend_finalize(&c->mb) != 0) fatal("membackend finalize");
    evm_membackend_bind(&c->mb, &c->be);

    /* nodus_witness_rt_evm.c (the node's EVM configuration) */
    c->ec.fork = EVM_FORK_PRAGUE;
    c->ec.addr_bytes = 32;
    chain_id_word(&c->ec.chain_id);
    c->ec.precompile_mask = EVM_PRECOMPILES_PRAGUE;
    c->ec.nodus_profile = 1;
    memcpy(c->ec.ticket_addr.b, TICKET, 32);
    evm_u256_from_u64(&c->ec.ticket_unit, 10000000000ull);
    c->ec.ticket_gas = 25000;

    /* coinbase zero, as in production */
    c->env.number = 1000;
    c->env.timestamp = 1760000000ull;
    c->env.gas_limit = BLOCK_GAS;
    evm_u256_zero(&c->env.base_fee);

    c->st = evm_state_new(&c->ec, &c->be);
    if (!c->st) fatal("evm_state_new");
    return 0;
}

static void ctx_close(ctx_t *c)
{
    free(c->creation.b);
    free(c->runtime.b);
    if (c->st) evm_state_free(c->st);
    evm_membackend_free(&c->mb);
}

/* ── the scenario ──────────────────────────────────────────────────────── */

static int scenario_deploy(ctx_t *c)
{
    static const uint8_t Z[32];
    uint8_t want[32];
    evm_tx_result_t r;
    create_addr(want, OWNER, c->nonce[S_OWNER]);
    int rc = send_tx(c, S_OWNER, NULL, c->creation.b, c->creation.n, &r);
    if (rc != 0 || r.status != EVM_EXEC_SUCCESS) {
        c->fail++;
        fprintf(stderr, "  [FAIL] %s: deploy NodusToken: rc %d status %d\n",
                c->cfg, rc, (int)r.status);
        evm_tx_result_free(&r);
        return -1;
    }
    c->pass++;
    ck_addr(c, r.created.b, want, "token address = CREATE rule (deployer32, nonce 0)");
    memcpy(c->token, want, 32);
    ck_event(c, &r, "Transfer(address,address,uint256)", Z, OWNER, SUPPLY,
             "constructor mint Transfer(0, deployer, supply)");
    evm_tx_result_free(&r);
    return 0;
}

static void scenario_views(ctx_t *c)
{
    cd_t d;
    uint8_t got[32];
    ck_string(c, "name()", "Nodus Example Token");
    ck_string(c, "symbol()", "NXT");
    cd_sel(&d, "decimals()");
    view_word(c, &d, got, "decimals()");
    ck_u64(c, got, 18, "decimals() = 18");
    cd_sel(&d, "totalSupply()");
    view_word(c, &d, got, "totalSupply()");
    ck_word(c, got, SUPPLY, "totalSupply() = 10^24");
    cd_sel(&d, "INITIAL_SUPPLY()");
    view_word(c, &d, got, "INITIAL_SUPPLY()");
    ck_word(c, got, SUPPLY, "INITIAL_SUPPLY() = 10^24");

    uint8_t proj[32];
    balance_of(c, OWNER, got);
    ck_word(c, got, SUPPLY, "balanceOf(deployer) = the whole supply");
    balance_of(c, OWNER_TWIN, got);
    ck_u64(c, got, 0, "balanceOf(deployer's twin, same low 20 bytes) = 0");
    mask20(proj, OWNER);
    balance_of(c, proj, got);
    ck_u64(c, got, 0, "balanceOf(deployer's 20-byte projection) = 0");
}

static void scenario_transfer(ctx_t *c)
{
    cd_t d;
    evm_tx_result_t r;
    uint8_t got[32], w[32], rest[32];

    cd_sel(&d, "transfer(address,uint256)");
    cd_word(&d, ALICE);
    cd_u64(&d, 1000);
    if (call_ok(c, S_OWNER, &d, 1, &r, "transfer(alice, 1000) from the deployer")) {
        ck_u64(c, r.output, 1, "transfer returns true");
        word_u64(w, 1000);
        ck_event(c, &r, "Transfer(address,address,uint256)", OWNER, ALICE, w,
                 "transfer");
        evm_tx_result_free(&r);
    }
    word_sub_u64(rest, SUPPLY, 1000);
    balance_of(c, OWNER, got);
    ck_word(c, got, rest, "balanceOf(deployer) = supply - 1000");
    balance_of(c, ALICE, got);
    ck_u64(c, got, 1000, "balanceOf(alice) = 1000");
    balance_of(c, ALICE_TWIN, got);
    ck_u64(c, got, 0, "balanceOf(alice's twin) = 0");

    /* negative controls: above the balance, to address(0) */
    cd_sel(&d, "transfer(address,uint256)");
    cd_word(&d, CAROL);
    cd_u64(&d, 1001);
    ck_revert(c, S_ALICE, &d, "NodusToken: balance too low",
              "transfer(carol, 1001) from alice (balance 1000) reverts");
    static const uint8_t Z[32];
    cd_sel(&d, "transfer(address,uint256)");
    cd_word(&d, Z);
    cd_u64(&d, 1);
    ck_revert(c, S_ALICE, &d, "NodusToken: transfer to the zero address",
              "transfer(address(0), 1) reverts");
    balance_of(c, ALICE, got);
    ck_u64(c, got, 1000, "balanceOf(alice) unchanged after the reverts");
    balance_of(c, CAROL, got);
    ck_u64(c, got, 0, "balanceOf(carol) unchanged after the revert");
}

static void scenario_allowance(ctx_t *c)
{
    cd_t d;
    evm_tx_result_t r;
    uint8_t got[32], w[32], proj[32];

    cd_sel(&d, "approve(address,uint256)");
    cd_word(&d, BOB);
    cd_u64(&d, 600);
    if (call_ok(c, S_ALICE, &d, 1, &r, "approve(bob, 600) from alice")) {
        ck_u64(c, r.output, 1, "approve returns true");
        word_u64(w, 600);
        ck_event(c, &r, "Approval(address,address,uint256)", ALICE, BOB, w,
                 "approve");
        evm_tx_result_free(&r);
    }
    allowance_of(c, ALICE, BOB, got);
    ck_u64(c, got, 600, "allowance(alice, bob) = 600");
    allowance_of(c, ALICE, BOB_TWIN, got);
    ck_u64(c, got, 0, "allowance(alice, bob's twin) = 0");
    allowance_of(c, ALICE_TWIN, BOB, got);
    ck_u64(c, got, 0, "allowance(alice's twin, bob) = 0");

    /* negative control: the spender's twin cannot spend bob's allowance */
    cd_sel(&d, "transferFrom(address,address,uint256)");
    cd_word(&d, ALICE);
    cd_word(&d, CAROL);
    cd_u64(&d, 1);
    ck_revert(c, S_BOB_TWIN, &d, "NodusToken: allowance too low",
              "transferFrom(alice, carol, 1) sent by bob's twin reverts");

    cd_sel(&d, "transferFrom(address,address,uint256)");
    cd_word(&d, ALICE);
    cd_word(&d, CAROL);
    cd_u64(&d, 400);
    if (call_ok(c, S_BOB, &d, 1, &r, "transferFrom(alice, carol, 400) by bob")) {
        ck_u64(c, r.output, 1, "transferFrom returns true");
        word_u64(w, 400);
        ck_event(c, &r, "Transfer(address,address,uint256)", ALICE, CAROL, w,
                 "transferFrom");
        evm_tx_result_free(&r);
    }
    allowance_of(c, ALICE, BOB, got);
    ck_u64(c, got, 200, "allowance(alice, bob) = 600 - 400");
    balance_of(c, ALICE, got);
    ck_u64(c, got, 600, "balanceOf(alice) = 1000 - 400");
    balance_of(c, CAROL, got);
    ck_u64(c, got, 400, "balanceOf(carol) = 400");
    mask20(proj, CAROL);
    balance_of(c, proj, got);
    ck_u64(c, got, 0, "balanceOf(carol's 20-byte projection) = 0");

    /* negative control: above the remaining allowance */
    cd_sel(&d, "transferFrom(address,address,uint256)");
    cd_word(&d, ALICE);
    cd_word(&d, CAROL);
    cd_u64(&d, 201);
    ck_revert(c, S_BOB, &d, "NodusToken: allowance too low",
              "transferFrom(alice, carol, 201) by bob (allowance 200) reverts");
    allowance_of(c, ALICE, BOB, got);
    ck_u64(c, got, 200, "allowance(alice, bob) unchanged after the revert");
}

static void post_checks(ctx_t *c)
{
    post_t p;
    uint8_t key[32], got[32], slot[32], inner[32], rest[32];
    post_collect(c, &p);

    word_u64(slot, 0);
    post_slot(&p, c->token, slot, got);
    ck_word(c, got, SUPPLY, "raw slot 0 = totalSupply");

    word_u64(slot, 1);
    word_sub_u64(rest, SUPPLY, 1000);
    slot_map(key, OWNER, slot);
    post_slot(&p, c->token, key, got);
    ck_word(c, got, rest, "raw slot keccak256(deployer32 ‖ 1) = its balance");
    slot_map(key, ALICE, slot);
    post_slot(&p, c->token, key, got);
    ck_u64(c, got, 600, "raw slot keccak256(alice32 ‖ 1) = 600");
    slot_map(key, CAROL, slot);
    post_slot(&p, c->token, key, got);
    ck_u64(c, got, 400, "raw slot keccak256(carol32 ‖ 1) = 400");
    slot_map(key, ALICE_TWIN, slot);
    ck(c, !post_slot(&p, c->token, key, got),
       "raw slot keccak256(alice_twin32 ‖ 1) never written");
    mask20(inner, CAROL);
    slot_map(key, inner, slot);
    ck(c, !post_slot(&p, c->token, key, got),
       "raw slot keccak256(carol_projection32 ‖ 1) never written");

    word_u64(slot, 2);
    slot_map(inner, ALICE, slot);
    slot_map(key, BOB, inner);
    post_slot(&p, c->token, key, got);
    ck_u64(c, got, 200,
           "raw slot keccak256(bob32 ‖ keccak256(alice32 ‖ 2)) = the allowance");
    slot_map(key, BOB_TWIN, inner);
    ck(c, !post_slot(&p, c->token, key, got),
       "raw allowance slot of bob's twin never written");

    int code_ok = 0;
    for (size_t i = 0; i < p.na; i++)
        if (memcmp(p.acc[i].addr.b, c->token, 32) == 0 && p.acc[i].code_changed)
            code_ok = p.acc[i].code_len == c->runtime.n &&
                      memcmp(p.acc[i].code, c->runtime.b, c->runtime.n) == 0;
    ck(c, code_ok, "deployed code = the committed runtime.hex");
    post_free(&p);
}

static void run_config(ctx_t *c)
{
    if (scenario_deploy(c) != 0) return;
    scenario_views(c);
    scenario_transfer(c);
    scenario_allowance(c);
    post_checks(c);
}

int main(int argc, char **argv)
{
    static const char *const CFGS[2] = { "default", "optimize" };
    const char *dir = argc > 1 ? argv[1] : EXAMPLES_OUT;
    int failed = 0;

    init_inputs();
    if (self_check_rules() != 0) failed = 1;
    fprintf(stderr, "bytecode: %s\n", dir);
    for (int i = 0; i < 2; i++) {
        ctx_t c;
        if (ctx_open(&c, dir, CFGS[i]) == 0) run_config(&c);
        fprintf(stderr, "config %-9s: %u passed, %u failed\n", CFGS[i], c.pass, c.fail);
        if (c.fail || c.pass == 0) failed = 1;
        ctx_close(&c);
    }
    if (failed) {
        fprintf(stderr, "test_example_token: FAILED\n");
        return 1;
    }
    fprintf(stderr, "test_example_token: all configurations passed\n");
    return 0;
}
