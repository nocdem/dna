/**
 * @file test_solc_exec.c
 * @brief Execution evidence for the Nodus EVM solc (32-byte addresses):
 *        compiled Solidity, run in the engine's 32-byte mode.
 *
 * Governing records: docs/plans/decisions/2026-10-06-kurultay-9-evm-address-
 * width-summary.md (Astra's pre-vote gate: compiler execution evidence —
 * high-byte addresses through storage / ABI / conversion / call in every
 * pipeline + optimizer setting), docs/plans/kurultay/2026-10-06-9-evm-address-
 * width/astra-r2.md item 6, and the semantic rules 1-9 of
 * nodus/tools/evm/solc/README.md.
 *
 * WHAT IT PROVES
 *   For each of the four compiler configurations (legacy, legacy --optimize,
 *   --via-ir, --via-ir --optimize; evm prague; optimizer runs 200) the code
 *   the patched solc emitted for the sources in nodus/tools/evm/solc/tests/
 *   exec/ (AddrStore, AbiConv, Calls, Factory .sol) keeps
 *   all 32 bytes of an address whose HIGH 12 bytes are non-zero through:
 *   a state variable (and its raw slot), a constructor argument, an
 *   immutable, a mapping key (raw slot = keccak256(key32 ‖ slot)) and value,
 *   a storage struct, a dynamic storage array, memory struct/array, abi.encode
 *   / abi.encodePacked (32 bytes) / abi.decode (calldata and memory), calldata
 *   struct and address[] parameters, address <-> uint256 / bytes32
 *   conversions, ==, !=, <, msg.sender / tx.origin / address(this) /
 *   block.coinbase, high-level and low-level external calls (the callee's
 *   msg.sender), address.balance and value transfer (transfer / send /
 *   call{value}), EXTCODESIZE / EXTCODEHASH of an address, DELEGATECALL into a
 *   library, the library's 32-byte deploy-time self address (rule 7: a direct
 *   CALL of a non-view library function reverts), CREATE and CREATE2 from a
 *   contract (address = the engine rule, computed here), and an event's
 *   indexed address topic. Every deployed contract address is checked against
 *   the engine's create rule and must itself have non-zero high bytes.
 *   Every address assertion also checks that the result is NOT the value a
 *   160-bit mask would produce (12 zero bytes ‖ the low 20 bytes), and each
 *   class has a twin-address control (same low 20 bytes, different high 12):
 *   mapping lookup of the twin key is zero, eq(x, twin) is false, the twin's
 *   / the 20-byte projection's balance and code are untouched.
 *
 * WHAT IT REQUIRES
 *   The COMMITTED outputs nodus/tools/evm/solc/tests/exec/out/<config>/
 *   <Contract>.{creation,runtime}.hex (written by tests/exec/build.sh with the
 *   patched solc); no solc at test time. Directory: argv[1], else
 *   SOLC_EXEC_OUT (default "../../nodus/tools/evm/solc/tests/exec/out",
 *   relative to shared/evm, where `make test` runs it).
 *   A missing or malformed .hex is a FAIL, never a skip. No compile flags, no
 *   environment variables.
 *
 * ENGINE PROFILE
 *   As nodus_witness_rt_evm.c builds it (addr_bytes 32, nodus_profile 1,
 *   Prague precompiles, ticket unit 10^10, ticket gas 25000, base fee 0,
 *   gas price 0, type-1 txs, 32-byte chain id), with ONE deviation: the block
 *   coinbase is a high-byte address (production uses zero, design §10) so
 *   that block.coinbase is exercised. The ticket address here is a fixed
 *   high-byte constant, not the production SHA3-512 derivation (no ticket is
 *   created by this test).
 *
 * EXPECTED VALUES
 *   Fixed inputs (high-byte addresses below, ADDR32_SENDER / ADDR32_COINBASE
 *   from tests/addr32_vectors.h) and the engine's address rules: CREATE =
 *   keccak256(rlp([sender32, nonce])), CREATE2 = keccak256(0xff ‖ sender32 ‖
 *   salt ‖ keccak256(init)) (engine design §2). The two helpers here are
 *   SELF-CHECKED at startup against the committed oracle vectors of
 *   tests/addr32_oracle.py (addr32_vectors.h: CREATE at nonces 0, 0x7f,
 *   0x80, 0x0100, CREATE2) — oracle-checked, not oracle-generated.
 *
 * WHAT IT LEAVES BEHIND
 *   Nothing (in-memory backend, no files written).
 *
 * HOW IT CAN LIE
 *   - It tests the bytecode in out/, i.e. whatever solc wrote it. A .hex
 *     regenerated with another compiler silently tests that compiler; check
 *     out/VERSION.txt (build.sh refuses a solc without the nodus.addr256 tag).
 *   - It covers the constructs listed above only; a construct not listed
 *     (inline assembly masks, external function types, linked libraries,
 *     ecrecover, other optimizer run counts) is not exercised.
 *   - The engine is the shared/evm engine itself: an engine defect that
 *     mirrors a compiler defect would cancel out. The engine's 32-byte rules
 *     are pinned separately by test_addr32.c.
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

#ifndef SOLC_EXEC_OUT
#define SOLC_EXEC_OUT "../../nodus/tools/evm/solc/tests/exec/out"
#endif

#define TX_GAS     10000000ull
#define BLOCK_GAS  30000000ull

/* ── fixed inputs: HIGH 12 bytes non-zero unless named *_PROJ ──────────── */

/* hi = byte for bytes 0..11, lo = byte for bytes 12..31 */
static void mk_addr(uint8_t out[32], uint8_t hi, uint8_t lo)
{
    memset(out, hi, 12);
    memset(out + 12, lo, 20);
}

static uint8_t X[32];       /* 0xab*12 ‖ 0x11*20                          */
static uint8_t X_TWIN[32];  /* 0xcd*12 ‖ 0x11*20: same low 20 as X        */
static uint8_t Y[32];       /* 0xba*12 ‖ 0x22*20                          */
static uint8_t T[32];       /* pay target, absent before: 0xa7*12 ‖ 0x77  */
static uint8_t T_TWIN[32];  /* pre-funded twin of T: 0xcd*12 ‖ 0x77       */
static uint8_t T_PROJ[32];  /* 20-byte projection of T: 0*12 ‖ 0x77       */
static uint8_t TICKET[32];  /* ticket address (config only): 0x7e*32      */
static uint8_t SALT[32];    /* CREATE2 salt with non-zero high bytes      */

#define BAL_SENDER_HI  0x0100000000000000ull /* balance word byte 23 set  */
#define BAL_T_TWIN     0x5555ull
#define FUND_CALLER    1000000ull

static void init_inputs(void)
{
    mk_addr(X, 0xab, 0x11);
    mk_addr(X_TWIN, 0xcd, 0x11);
    mk_addr(Y, 0xba, 0x22);
    mk_addr(T, 0xa7, 0x77);
    mk_addr(T_TWIN, 0xcd, 0x77);
    mk_addr(T_PROJ, 0x00, 0x77);
    memset(TICKET, 0x7e, 32);
    for (int i = 0; i < 32; i++) SALT[i] = (uint8_t)(0xf0 ^ i);
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

/* CREATE2 = keccak256(0xff ‖ sender32 ‖ salt ‖ keccak256(init)) */
static void create2_addr(uint8_t out[32], const uint8_t sender[32],
                         const uint8_t salt[32], const uint8_t *init,
                         size_t init_len)
{
    uint8_t buf[1 + 32 + 32 + 32];
    buf[0] = 0xff;
    memcpy(buf + 1, sender, 32);
    memcpy(buf + 33, salt, 32);
    kec(init, init_len, buf + 65);
    kec(buf, sizeof(buf), out);
}

/* The helpers above against the committed oracle vectors. */
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
    create2_addr(got, ADDR32_FACTORY, ADDR32_SALT, ADDR32_INITCODE,
                 sizeof(ADDR32_INITCODE));
    if (memcmp(got, ADDR32_EXP_CREATE2_FACTORY, 32) != 0) {
        fprintf(stderr, "  [FAIL] oracle: CREATE2 vector\n");
        bad = 1;
    }
    fprintf(stderr, "oracle self-check of the CREATE/CREATE2 helpers: %s\n",
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
static int load_hex(const char *dir, const char *cfg, const char *name,
                    const char *kind, blob_t *out)
{
    char path[1024];
    out->b = NULL;
    out->n = 0;
    int pn = snprintf(path, sizeof(path), "%s/%s/%s.%s.hex", dir, cfg, name, kind);
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
            fprintf(stderr, "  [FAIL] %s: %s is not hex (an unlinked library "
                    "placeholder?)\n", cfg, path);
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

enum { C_ADDRSTORE, C_ABICONV, C_CALLEE, C_CALLER, C_SELFLIB, C_FACTORY,
       C_CHILD, C_COUNT };
static const char *const CNAME[C_COUNT] = {
    "AddrStore", "AbiConv", "Callee", "Caller", "SelfLib", "Factory", "Child" };

typedef struct {
    const char     *cfg;
    unsigned        pass, fail;
    blob_t          creation[C_COUNT];
    blob_t          runtime[C_COUNT];
    uint8_t         at[C_COUNT][32];      /* deployed addresses */
    evm_membackend  mb;
    evm_backend_t   be;
    evm_config_t    ec;
    evm_block_env_t env;
    evm_state_t    *st;
    uint64_t        nonce;                /* SENDER's next nonce */
} ctx_t;

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
    uint8_t b[2048];
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

/* type-1 tx from ADDR32_SENDER, gas price 0 (Nodus profile); to NULL =
 * create. @return evm_tx_apply's rc; a fault is fatal. */
static int send_tx(ctx_t *c, const uint8_t *to, uint64_t value,
                   const uint8_t *data, size_t len, evm_tx_result_t *res)
{
    evm_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    memset(res, 0, sizeof(*res));
    tx.type = 1;
    memcpy(tx.sender.b, ADDR32_SENDER, 32);
    if (to) memcpy(tx.to.b, to, 32);
    else tx.is_create = 1;
    tx.nonce = c->nonce;
    tx.gas_limit = TX_GAS;
    evm_u256_from_u64(&tx.value, value);
    tx.data = data;
    tx.data_len = len;
    tx.has_chain_id = 1;
    tx.chain_id = c->ec.chain_id;
    for (int i = 0; i < 64; i++) tx.intent_id[i] = (uint8_t)(c->nonce + (uint64_t)i);
    int rc = evm_tx_apply(c->st, &c->env, &tx, res);
    if (rc == -2) fatal("evm_tx_apply fault");
    if (rc == 0) c->nonce++;
    return rc;
}

/* Call that must SUCCEED; output must hold at least min_words words.
 * @return 1 ok (res owned by caller), 0 failed (assertion counted, res freed). */
static int call_ok(ctx_t *c, const uint8_t *to, uint64_t value, const cd_t *d,
                   size_t min_words, evm_tx_result_t *res, const char *what)
{
    int rc = send_tx(c, to, value, d ? d->b : NULL, d ? d->n : 0, res);
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

static const uint8_t *ow(const evm_tx_result_t *res, size_t i)
{
    return res->output + 32 * i;
}

/* ── post-state (change set over the pre-state) ────────────────────────── */

typedef struct {
    evm_addr  addr;
    int       deleted;
    uint8_t   balance[32];
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
        size_t nc = p->cap_a ? p->cap_a * 2 : 32;
        acc_rec *x = realloc(p->acc, nc * sizeof(*x));
        if (!x) fatal("oom");
        p->acc = x;
        p->cap_a = nc;
    }
    acc_rec *r = &p->acc[p->na++];
    memset(r, 0, sizeof(*r));
    r->addr = ch->addr;
    r->deleted = ch->deleted;
    evm_u256_to_be(r->balance, &ch->balance);
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
        size_t nc = p->cap_s ? p->cap_s * 2 : 64;
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

static const acc_rec *post_acc(const post_t *p, const uint8_t a[32])
{
    for (size_t i = 0; i < p->na; i++)
        if (memcmp(p->acc[i].addr.b, a, 32) == 0) return &p->acc[i];
    return NULL;
}

/* balance after the txs (change set, else pre-state, else 0) */
static void post_balance(const ctx_t *c, const post_t *p, const uint8_t a[32],
                         uint8_t out[32])
{
    const acc_rec *r = post_acc(p, a);
    if (r) {
        if (r->deleted) memset(out, 0, 32);
        else memcpy(out, r->balance, 32);
        return;
    }
    evm_addr x;
    memcpy(x.b, a, 32);
    const evm_mem_account *m = evm_membackend_find(&c->mb, &x);
    if (m) memcpy(out, m->balance, 32);
    else memset(out, 0, 32);
}

/* slot value written by the txs (every slot used here starts at zero) */
static void post_slot(const post_t *p, const uint8_t a[32], const uint8_t key[32],
                      uint8_t out[32])
{
    for (size_t i = 0; i < p->ns; i++)
        if (memcmp(p->sl[i].addr.b, a, 32) == 0 &&
            memcmp(p->sl[i].key.b, key, 32) == 0) {
            memcpy(out, p->sl[i].val.b, 32);
            return;
        }
    memset(out, 0, 32);
}

static void slot_u64(uint8_t key[32], uint64_t s)
{
    word_u64(key, s);
}

/* key = keccak256(k32 ‖ uint256(slot)) — the mapping slot rule */
static void slot_map(uint8_t key[32], const uint8_t k[32], uint64_t slot)
{
    uint8_t buf[64];
    memcpy(buf, k, 32);
    word_u64(buf + 32, slot);
    kec(buf, 64, key);
}

/* key = keccak256(uint256(slot)) + i — the dynamic array element rule */
static void slot_arr(uint8_t key[32], uint64_t slot, unsigned i)
{
    uint8_t buf[32];
    word_u64(buf, slot);
    kec(buf, 32, key);
    unsigned carry = i;
    for (int j = 31; j >= 0 && carry; j--) {
        unsigned s = key[j] + (carry & 0xff);
        key[j] = (uint8_t)s;
        carry = (carry >> 8) + (s >> 8);
    }
}

/* deployed code == runtime, except 32-byte windows where the runtime holds
 * zeros and the deployed code holds `fill` (immutables / library self
 * address). @return the number of filled windows, or -1 on a mismatch. */
static int code_matches(const uint8_t *code, size_t code_len,
                        const blob_t *rt, const uint8_t *fill)
{
    static const uint8_t Z[32];
    if (code_len != rt->n) return -1;
    int filled = 0;
    size_t i = 0;
    while (i < code_len) {
        if (fill && i + 32 <= code_len && memcmp(rt->b + i, Z, 32) == 0 &&
            memcmp(code + i, fill, 32) == 0) {
            filled++;
            i += 32;
            continue;
        }
        if (code[i] != rt->b[i]) return -1;
        i++;
    }
    return filled;
}

/* ── setup ─────────────────────────────────────────────────────────────── */

static void chain_id_word(evm_u256 *out)
{
    uint8_t b[32];
    for (int i = 0; i < 32; i++) b[i] = (uint8_t)(0xc0 + i);
    evm_u256_from_be(out, b);
}

static void add_eoa(evm_membackend *mb, const uint8_t a[32], uint64_t bal_lo,
                    uint64_t bal_hi)
{
    uint8_t bal[32];
    evm_addr x;
    memset(bal, 0, 32);
    for (int i = 0; i < 8; i++) {
        bal[31 - i] = (uint8_t)(bal_lo >> (8 * i));
        bal[23 - i] = (uint8_t)(bal_hi >> (8 * i));
    }
    memcpy(x.b, a, 32);
    if (evm_membackend_add_account(mb, &x, 0, bal, NULL, 0, NULL, NULL) != 0)
        fatal("membackend add");
}

static int ctx_open(ctx_t *c, const char *dir, const char *cfg)
{
    memset(c, 0, sizeof(*c));
    c->cfg = cfg;
    int missing = 0;
    for (int i = 0; i < C_COUNT; i++) {
        if (load_hex(dir, cfg, CNAME[i], "creation", &c->creation[i]) != 0) missing++;
        if (load_hex(dir, cfg, CNAME[i], "runtime", &c->runtime[i]) != 0) missing++;
    }
    if (missing) {
        c->fail += (unsigned)missing;
        return -1;
    }

    evm_membackend_init(&c->mb);
    add_eoa(&c->mb, ADDR32_SENDER, 0, BAL_SENDER_HI);
    add_eoa(&c->mb, T_TWIN, BAL_T_TWIN, 0);
    if (evm_membackend_finalize(&c->mb) != 0) fatal("membackend finalize");
    evm_membackend_bind(&c->mb, &c->be);

    /* nodus_witness_rt_evm.c:1062-1105 */
    c->ec.fork = EVM_FORK_PRAGUE;
    c->ec.addr_bytes = 32;
    chain_id_word(&c->ec.chain_id);
    c->ec.precompile_mask = EVM_PRECOMPILES_PRAGUE;
    c->ec.nodus_profile = 1;
    memcpy(c->ec.ticket_addr.b, TICKET, 32);
    evm_u256_from_u64(&c->ec.ticket_unit, 10000000000ull);
    c->ec.ticket_gas = 25000;

    memcpy(c->env.coinbase.b, ADDR32_COINBASE, 32);   /* production: zero */
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
    for (int i = 0; i < C_COUNT; i++) {
        free(c->creation[i].b);
        free(c->runtime[i].b);
    }
    if (c->st) evm_state_free(c->st);
    evm_membackend_free(&c->mb);
}

/* ── the scenario ──────────────────────────────────────────────────────── */

static int deploy(ctx_t *c, int k, const uint8_t *arg)
{
    uint8_t want[32];
    uint8_t data[8192];
    size_t n = c->creation[k].n;
    char what[96];
    if (n + 32 > sizeof(data)) fatal("creation code too large for the buffer");
    memcpy(data, c->creation[k].b, n);
    if (arg) {
        memcpy(data + n, arg, 32);
        n += 32;
    }
    create_addr(want, ADDR32_SENDER, c->nonce);
    evm_tx_result_t res;
    int rc = send_tx(c, NULL, 0, data, n, &res);
    snprintf(what, sizeof(what), "deploy %s", CNAME[k]);
    if (rc != 0 || res.status != EVM_EXEC_SUCCESS) {
        c->fail++;
        fprintf(stderr, "  [FAIL] %s: %s: rc %d status %d\n", c->cfg, what, rc,
                (int)res.status);
        evm_tx_result_free(&res);
        return -1;
    }
    c->pass++;
    snprintf(what, sizeof(what), "%s address = CREATE rule (sender32, nonce)", CNAME[k]);
    ck_addr(c, res.created.b, want, what);
    memcpy(c->at[k], want, 32);
    evm_tx_result_free(&res);
    return 0;
}

static void scenario_store(ctx_t *c)
{
    const uint8_t *A = c->at[C_ADDRSTORE];
    evm_tx_result_t r;
    cd_t d;

    cd_sel(&d, "initArg()");
    if (call_ok(c, A, 0, &d, 1, &r, "initArg()")) {
        ck_addr(c, ow(&r, 0), X, "constructor argument (CODECOPY decoder) kept 32 bytes");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "deployer()");
    if (call_ok(c, A, 0, &d, 1, &r, "deployer()")) {
        ck_addr(c, ow(&r, 0), ADDR32_SENDER, "immutable = msg.sender at construction");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "setA(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 0, &r, "setA(X) (calldata decoder accepts high bytes)"))
        evm_tx_result_free(&r);
    cd_sel(&d, "getA()");
    if (call_ok(c, A, 0, &d, 1, &r, "getA()")) {
        ck_addr(c, ow(&r, 0), X, "state variable read back");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "a()");
    if (call_ok(c, A, 0, &d, 1, &r, "a()")) {
        ck_addr(c, ow(&r, 0), X, "public getter of the state variable");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "setM(address,address)");
    cd_word(&d, X);
    cd_word(&d, Y);
    if (call_ok(c, A, 0, &d, 0, &r, "setM(X, Y)")) evm_tx_result_free(&r);
    cd_sel(&d, "getM(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 1, &r, "getM(X)")) {
        ck_addr(c, ow(&r, 0), Y, "mapping value under key X");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "getM(address)");
    cd_word(&d, X_TWIN);
    if (call_ok(c, A, 0, &d, 1, &r, "getM(X_TWIN)")) {
        ck_u64(c, ow(&r, 0), 0, "mapping: the twin key (same low 20 bytes) is a different key");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "m(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 1, &r, "m(X)")) {
        ck_addr(c, ow(&r, 0), Y, "mapping public getter");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "setS(address)");
    cd_word(&d, Y);
    if (call_ok(c, A, 0, &d, 0, &r, "setS(Y)")) evm_tx_result_free(&r);
    cd_sel(&d, "getS()");
    if (call_ok(c, A, 0, &d, 3, &r, "getS()")) {
        ck_u64(c, ow(&r, 0), 7, "struct tag before the address");
        ck_addr(c, ow(&r, 1), Y, "struct member address");
        ck_u64(c, ow(&r, 2), 9, "struct tag after the address");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "push(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 0, &r, "push(X)")) evm_tx_result_free(&r);
    cd_sel(&d, "push(address)");
    cd_word(&d, X_TWIN);
    if (call_ok(c, A, 0, &d, 0, &r, "push(X_TWIN)")) evm_tx_result_free(&r);
    cd_sel(&d, "len()");
    if (call_ok(c, A, 0, &d, 1, &r, "len()")) {
        ck_u64(c, ow(&r, 0), 2, "dynamic array length");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "at(uint256)");
    cd_u64(&d, 0);
    if (call_ok(c, A, 0, &d, 1, &r, "at(0)")) {
        ck_addr(c, ow(&r, 0), X, "dynamic array element 0");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "at(uint256)");
    cd_u64(&d, 1);
    if (call_ok(c, A, 0, &d, 1, &r, "at(1)")) {
        ck_addr(c, ow(&r, 0), X_TWIN, "dynamic array element 1 (the twin)");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "memRound(address,address)");
    cd_word(&d, X);
    cd_word(&d, Y);
    if (call_ok(c, A, 0, &d, 3, &r, "memRound(X, Y)")) {
        ck_addr(c, ow(&r, 0), X, "memory array element");
        ck_addr(c, ow(&r, 1), Y, "memory struct member");
        ck_addr(c, ow(&r, 2), Y, "memory array element 2");
        evm_tx_result_free(&r);
    }
}

static void scenario_abi(ctx_t *c)
{
    const uint8_t *A = c->at[C_ABICONV];
    evm_tx_result_t r;
    cd_t d;

    cd_sel(&d, "enc(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 3, &r, "enc(X)")) {
        ck_u64(c, ow(&r, 1), 32, "abi.encode(address) length = 32");
        ck_addr(c, ow(&r, 2), X, "abi.encode(address) word");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "encPacked(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 3, &r, "encPacked(X)")) {
        ck_u64(c, ow(&r, 1), 32, "abi.encodePacked(address) length = 32 (rule 1)");
        ck_addr(c, ow(&r, 2), X, "abi.encodePacked(address) bytes");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "packedLen(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 1, &r, "packedLen(X)")) {
        ck_u64(c, ow(&r, 0), 32, "abi.encodePacked(address).length = 32");
        evm_tx_result_free(&r);
    }
    /* bytes argument: offset 0x20, length 32, X */
    static const char *const decs[2] = { "dec(bytes)", "decMem(bytes)" };
    for (int i = 0; i < 2; i++) {
        cd_sel(&d, decs[i]);
        cd_u64(&d, 32);
        cd_u64(&d, 32);
        cd_word(&d, X);
        if (call_ok(c, A, 0, &d, 1, &r, decs[i])) {
            ck_addr(c, ow(&r, 0), X, i ? "abi.decode from memory bytes"
                                       : "abi.decode from calldata bytes");
            evm_tx_result_free(&r);
        }
    }
    cd_sel(&d, "roundTrip(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 1, &r, "roundTrip(X)")) {
        ck_addr(c, ow(&r, 0), X, "abi.decode(abi.encode(x))");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "echoP((uint8,address))");
    cd_u64(&d, 5);
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 2, &r, "echoP((5, X))")) {
        ck_u64(c, ow(&r, 0), 5, "calldata struct tag");
        ck_addr(c, ow(&r, 1), X, "calldata struct address member");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "echoArr(address[])");
    cd_u64(&d, 32);
    cd_u64(&d, 3);
    cd_word(&d, X);
    cd_word(&d, X_TWIN);
    cd_word(&d, Y);
    if (call_ok(c, A, 0, &d, 5, &r, "echoArr([X, X_TWIN, Y])")) {
        ck_u64(c, ow(&r, 1), 3, "address[] length");
        ck_addr(c, ow(&r, 2), X, "address[] element 0");
        ck_addr(c, ow(&r, 3), X_TWIN, "address[] element 1");
        ck_addr(c, ow(&r, 4), Y, "address[] element 2");
        evm_tx_result_free(&r);
    }
    static const char *const convs[4] = {
        "toU(address)", "fromU(uint256)", "toB(address)", "fromB(bytes32)" };
    for (int i = 0; i < 4; i++) {
        cd_sel(&d, convs[i]);
        cd_word(&d, X);
        if (call_ok(c, A, 0, &d, 1, &r, convs[i])) {
            ck_addr(c, ow(&r, 0), X, convs[i]);
            evm_tx_result_free(&r);
        }
    }
    cd_sel(&d, "convIdentity(address)");
    cd_word(&d, X);
    if (call_ok(c, A, 0, &d, 1, &r, "convIdentity(X)")) {
        ck_u64(c, ow(&r, 0), 1, "address(uint256(x)) == x etc. (rule 3)");
        evm_tx_result_free(&r);
    }
    struct { const char *sig; const uint8_t *a, *b; uint64_t want; const char *what; } cmp[] = {
        { "eq(address,address)", X, X_TWIN, 0, "eq(X, X_TWIN) is false (differ only in high bytes)" },
        { "eq(address,address)", X, X, 1, "eq(X, X) is true" },
        { "ne(address,address)", X, X_TWIN, 1, "ne(X, X_TWIN) is true" },
        { "lt(address,address)", X, X_TWIN, 1, "lt(X, X_TWIN) (0xab.. < 0xcd..)" },
        { "lt(address,address)", X_TWIN, X, 0, "lt(X_TWIN, X) is false" },
    };
    for (size_t i = 0; i < sizeof(cmp) / sizeof(cmp[0]); i++) {
        cd_sel(&d, cmp[i].sig);
        cd_word(&d, cmp[i].a);
        cd_word(&d, cmp[i].b);
        if (call_ok(c, A, 0, &d, 1, &r, cmp[i].what)) {
            ck_u64(c, ow(&r, 0), cmp[i].want, cmp[i].what);
            evm_tx_result_free(&r);
        }
    }
    cd_sel(&d, "env()");
    if (call_ok(c, A, 0, &d, 4, &r, "env()")) {
        ck_addr(c, ow(&r, 0), ADDR32_SENDER, "msg.sender");
        ck_addr(c, ow(&r, 1), ADDR32_SENDER, "tx.origin");
        ck_addr(c, ow(&r, 2), A, "address(this)");
        ck_addr(c, ow(&r, 3), ADDR32_COINBASE, "block.coinbase");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "emitSeen(address,address)");
    cd_word(&d, X);
    cd_word(&d, Y);
    if (call_ok(c, A, 0, &d, 0, &r, "emitSeen(X, Y)")) {
        uint8_t topic0[32];
        const char *ev = "Seen(address,address,uint256)";
        kec((const uint8_t *)ev, strlen(ev), topic0);
        int shape = r.n_logs == 1 && r.logs[0].n_topics == 2 &&
                    r.logs[0].data_len == 64;
        ck(c, shape, "event: one log, two topics, 64 data bytes");
        if (shape) {
            ck_addr(c, r.logs[0].addr.b, A, "log emitter address");
            ck_word(c, r.logs[0].topics[0].b, topic0, "event topic 0 = keccak(signature)");
            ck_addr(c, r.logs[0].topics[1].b, X, "indexed address topic = full 32 bytes");
            ck_addr(c, r.logs[0].data, Y, "non-indexed address in log data");
            ck_u64(c, r.logs[0].data + 32, 42, "log data uint256");
        }
        evm_tx_result_free(&r);
    }
}

static void scenario_calls(ctx_t *c)
{
    const uint8_t *CE = c->at[C_CALLEE];
    const uint8_t *CR = c->at[C_CALLER];
    const uint8_t *LB = c->at[C_SELFLIB];
    uint8_t ce_proj[32];
    evm_tx_result_t r;
    cd_t d;
    mask20(ce_proj, CE);

    /* fund the Caller through receive() */
    if (call_ok(c, CR, FUND_CALLER, NULL, 0, &r, "fund Caller (receive)"))
        evm_tx_result_free(&r);

    cd_sel(&d, "callWho(address)");
    cd_word(&d, CE);
    if (call_ok(c, CR, 0, &d, 2, &r, "callWho(Callee)")) {
        ck_addr(c, ow(&r, 0), CR, "callee's msg.sender = the calling contract");
        ck_addr(c, ow(&r, 1), ADDR32_SENDER, "callee's tx.origin");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "callHit(address)");
    cd_word(&d, CE);
    if (call_ok(c, CR, 1000, &d, 2, &r, "callHit(Callee){value: 1000}")) {
        ck_addr(c, ow(&r, 0), CR, "high-level call: returned msg.sender");
        ck_addr(c, ow(&r, 1), CR, "high-level call: callee stored msg.sender");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "callLow(address)");
    cd_word(&d, CE);
    if (call_ok(c, CR, 0, &d, 2, &r, "callLow(Callee)")) {
        ck_u64(c, ow(&r, 0), 1, "low-level call succeeded");
        ck_addr(c, ow(&r, 1), CR, "low-level call: returned msg.sender");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "callLow(address)");
    cd_word(&d, ce_proj);
    if (call_ok(c, CR, 0, &d, 2, &r, "callLow(projection of Callee)")) {
        ck_u64(c, ow(&r, 0), 1, "call to the 20-byte projection succeeds (empty account)");
        ck_u64(c, ow(&r, 1), 0, "the 20-byte projection is not the Callee (no return data)");
        evm_tx_result_free(&r);
    }
    struct { const uint8_t *a; uint64_t want; const char *what; } bal0[] = {
        { T_TWIN, BAL_T_TWIN, "balance of the pre-funded twin" },
        { T_PROJ, 0, "balance of the 20-byte projection = 0" },
        { T, 0, "balance of the target before payment = 0" },
        { CE, 1000, "Callee balance = the value forwarded by callHit" },
    };
    for (size_t i = 0; i < sizeof(bal0) / sizeof(bal0[0]); i++) {
        cd_sel(&d, "balanceOf(address)");
        cd_word(&d, bal0[i].a);
        if (call_ok(c, CR, 0, &d, 1, &r, bal0[i].what)) {
            ck_u64(c, ow(&r, 0), bal0[i].want, bal0[i].what);
            evm_tx_result_free(&r);
        }
    }
    cd_sel(&d, "payTransfer(address,uint256)");
    cd_word(&d, T);
    cd_u64(&d, 100);
    if (call_ok(c, CR, 0, &d, 0, &r, "payTransfer(T, 100)")) evm_tx_result_free(&r);
    cd_sel(&d, "paySend(address,uint256)");
    cd_word(&d, T);
    cd_u64(&d, 50);
    if (call_ok(c, CR, 0, &d, 1, &r, "paySend(T, 50)")) {
        ck_u64(c, ow(&r, 0), 1, "send returned true");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "payCall(address,uint256)");
    cd_word(&d, T);
    cd_u64(&d, 25);
    if (call_ok(c, CR, 0, &d, 1, &r, "payCall(T, 25)")) {
        ck_u64(c, ow(&r, 0), 1, "call{value} returned true");
        evm_tx_result_free(&r);
    }
    struct { const uint8_t *a; uint64_t want; const char *what; } bal1[] = {
        { T, 175, "target balance after transfer + send + call = 175" },
        { T_TWIN, BAL_T_TWIN, "twin balance unchanged by the payments" },
        { T_PROJ, 0, "projection balance unchanged by the payments" },
    };
    for (size_t i = 0; i < sizeof(bal1) / sizeof(bal1[0]); i++) {
        cd_sel(&d, "balanceOf(address)");
        cd_word(&d, bal1[i].a);
        if (call_ok(c, CR, 0, &d, 1, &r, bal1[i].what)) {
            ck_u64(c, ow(&r, 0), bal1[i].want, bal1[i].what);
            evm_tx_result_free(&r);
        }
    }
    cd_sel(&d, "selfBalance()");
    if (call_ok(c, CR, 0, &d, 1, &r, "selfBalance()")) {
        ck_u64(c, ow(&r, 0), FUND_CALLER - 175, "address(this).balance after paying 175");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "codeSize(address)");
    cd_word(&d, CE);
    if (call_ok(c, CR, 0, &d, 1, &r, "codeSize(Callee)")) {
        ck_u64(c, ow(&r, 0), c->runtime[C_CALLEE].n, "EXTCODESIZE of the Callee");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "codeSize(address)");
    cd_word(&d, ce_proj);
    if (call_ok(c, CR, 0, &d, 1, &r, "codeSize(projection)")) {
        ck_u64(c, ow(&r, 0), 0, "EXTCODESIZE of the 20-byte projection = 0");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "codeHash(address)");
    cd_word(&d, CE);
    if (call_ok(c, CR, 0, &d, 1, &r, "codeHash(Callee)")) {
        uint8_t h[32];
        kec(c->runtime[C_CALLEE].b, c->runtime[C_CALLEE].n, h);
        ck_word(c, ow(&r, 0), h, "EXTCODEHASH of the Callee = keccak256(runtime)");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "codeHash(address)");
    cd_word(&d, ce_proj);
    if (call_ok(c, CR, 0, &d, 1, &r, "codeHash(projection)")) {
        ck_u64(c, ow(&r, 0), 0, "EXTCODEHASH of the absent projection = 0");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "viaDelegate(address,uint256)");
    cd_word(&d, LB);
    cd_u64(&d, 41);
    if (call_ok(c, CR, 0, &d, 2, &r, "viaDelegate(SelfLib, 41)")) {
        ck_u64(c, ow(&r, 0), 1, "DELEGATECALL into the library succeeded");
        ck_u64(c, ow(&r, 1), 42, "library bump(41) via DELEGATECALL = 42");
        evm_tx_result_free(&r);
    }
    /* rule 7: direct CALL of a non-view library function must revert */
    cd_sel(&d, "bump(uint256)");
    cd_u64(&d, 41);
    {
        int rc = send_tx(c, LB, 0, d.b, d.n, &r);
        ck(c, rc == 0 && r.status == EVM_EXEC_REVERT,
           "direct CALL of SelfLib.bump reverts (32-byte deploy-time self address)");
        evm_tx_result_free(&r);
    }
    cd_sel(&d, "pureOne(uint256)");
    cd_u64(&d, 41);
    if (call_ok(c, LB, 0, &d, 1, &r, "direct CALL of SelfLib.pureOne")) {
        ck_u64(c, ow(&r, 0), 42, "pure library function callable directly");
        evm_tx_result_free(&r);
    }
}

static void scenario_factory(ctx_t *c)
{
    const uint8_t *F = c->at[C_FACTORY];
    uint8_t want[32];
    evm_tx_result_t r;
    cd_t d;

    /* a contract's first CREATE uses nonce 1 (EIP-161) */
    create_addr(want, F, 1);
    memcpy(c->at[C_CHILD], want, 32);
    cd_sel(&d, "make()");
    if (call_ok(c, F, 0, &d, 3, &r, "make()")) {
        ck_addr(c, ow(&r, 0), want, "new Child() address = CREATE rule (factory32, 1)");
        ck_addr(c, ow(&r, 1), F, "Child constructor saw msg.sender = factory");
        ck_addr(c, ow(&r, 2), want, "Child's address(this)");
        evm_tx_result_free(&r);
    }
    create2_addr(want, F, SALT, c->creation[C_CHILD].b, c->creation[C_CHILD].n);
    cd_sel(&d, "make2(bytes32)");
    cd_word(&d, SALT);
    if (call_ok(c, F, 0, &d, 3, &r, "make2(SALT)")) {
        ck_addr(c, ow(&r, 0), want, "new Child{salt}() address = CREATE2 rule");
        ck_addr(c, ow(&r, 1), want, "in-contract CREATE2 prediction = CREATE2 rule");
        ck_addr(c, ow(&r, 2), F, "CREATE2 Child saw msg.sender = factory");
        evm_tx_result_free(&r);
    }
}

/* the change set after all txs: raw storage words, codes, balances */
static void post_checks(ctx_t *c)
{
    post_t p;
    uint8_t key[32], got[32], child2[32];
    post_collect(c, &p);
    const uint8_t *A = c->at[C_ADDRSTORE];

    slot_u64(key, 0);
    post_slot(&p, A, key, got);
    ck_u64(c, got, 0x5a, "raw slot 0 = small only (the address is not packed into it)");
    slot_u64(key, 1);
    post_slot(&p, A, key, got);
    ck_addr(c, got, X, "raw slot 1 = the state variable, 32 bytes");
    slot_u64(key, 2);
    post_slot(&p, A, key, got);
    ck_addr(c, got, X, "raw slot 2 = the constructor argument, 32 bytes");
    slot_map(key, X, 3);
    post_slot(&p, A, key, got);
    ck_addr(c, got, Y, "raw slot keccak256(X32 ‖ 3) = the mapping value");
    slot_map(key, X_TWIN, 3);
    post_slot(&p, A, key, got);
    ck_u64(c, got, 0, "raw slot keccak256(X_TWIN32 ‖ 3) untouched");
    slot_u64(key, 5);
    post_slot(&p, A, key, got);
    ck_addr(c, got, Y, "raw slot 5 = the struct's address member (own slot)");
    slot_arr(key, 7, 0);
    post_slot(&p, A, key, got);
    ck_addr(c, got, X, "raw slot keccak256(7) + 0 = array element 0");
    slot_arr(key, 7, 1);
    post_slot(&p, A, key, got);
    ck_addr(c, got, X_TWIN, "raw slot keccak256(7) + 1 = array element 1");

    slot_u64(key, 0);
    post_slot(&p, c->at[C_CALLEE], key, got);
    ck_addr(c, got, c->at[C_CALLER], "Callee raw slot 0 = lastSender (the Caller)");
    slot_u64(key, 0);
    post_slot(&p, c->at[C_CHILD], key, got);
    ck_addr(c, got, c->at[C_FACTORY], "CREATE child raw slot 0 = creator (the Factory)");
    create2_addr(child2, c->at[C_FACTORY], SALT, c->creation[C_CHILD].b,
                 c->creation[C_CHILD].n);
    post_slot(&p, child2, key, got);
    ck_addr(c, got, c->at[C_FACTORY], "CREATE2 child raw slot 0 = creator (the Factory)");

    post_balance(c, &p, T, got);
    ck_u64(c, got, 175, "engine post-state: target balance 175");
    post_balance(c, &p, T_TWIN, got);
    ck_u64(c, got, BAL_T_TWIN, "engine post-state: twin balance unchanged");
    post_balance(c, &p, T_PROJ, got);
    ck_u64(c, got, 0, "engine post-state: projection balance 0");
    ck(c, post_acc(&p, T_PROJ) == NULL, "engine post-state: the projection was never touched");

    /* deployed code = the compiled runtime (fill = immutable / self address) */
    struct { int k; const uint8_t *addr; const uint8_t *fill; int min_fill; } cc[] = {
        { C_ABICONV, c->at[C_ABICONV], NULL, 0 },
        { C_CALLEE, c->at[C_CALLEE], NULL, 0 },
        { C_CALLER, c->at[C_CALLER], NULL, 0 },
        { C_FACTORY, c->at[C_FACTORY], NULL, 0 },
        { C_CHILD, c->at[C_CHILD], NULL, 0 },
        { C_CHILD, child2, NULL, 0 },
        { C_ADDRSTORE, c->at[C_ADDRSTORE], ADDR32_SENDER, 1 },
        { C_SELFLIB, c->at[C_SELFLIB], c->at[C_SELFLIB], 1 },
    };
    for (size_t i = 0; i < sizeof(cc) / sizeof(cc[0]); i++) {
        char what[128];
        const acc_rec *ar = post_acc(&p, cc[i].addr);
        int m = (ar && ar->code_changed)
              ? code_matches(ar->code, ar->code_len, &c->runtime[cc[i].k], cc[i].fill)
              : -1;
        snprintf(what, sizeof(what), "%s deployed code = runtime.hex%s", CNAME[cc[i].k],
                 cc[i].fill ? " with the 32-byte immutable / self address filled in" : "");
        ck(c, m >= cc[i].min_fill, what);
    }
    post_free(&p);
}

static void run_config(ctx_t *c)
{
    for (int k = 0; k < C_COUNT; k++) {
        if (k == C_CHILD) continue;                 /* created by Factory */
        if (deploy(c, k, k == C_ADDRSTORE ? X : NULL) != 0) return;
    }
    scenario_store(c);
    scenario_abi(c);
    scenario_calls(c);
    scenario_factory(c);
    post_checks(c);
}

int main(int argc, char **argv)
{
    static const char *const CFGS[4] = { "legacy", "legacy-opt", "viair", "viair-opt" };
    const char *dir = argc > 1 ? argv[1] : SOLC_EXEC_OUT;
    int failed = 0;

    init_inputs();
    if (self_check_rules() != 0) failed = 1;
    fprintf(stderr, "bytecode: %s\n", dir);
    for (int i = 0; i < 4; i++) {
        ctx_t c;
        if (ctx_open(&c, dir, CFGS[i]) == 0) run_config(&c);
        fprintf(stderr, "config %-10s: %u passed, %u failed\n", CFGS[i], c.pass, c.fail);
        if (c.fail || c.pass == 0) failed = 1;
        ctx_close(&c);
    }
    if (failed) {
        fprintf(stderr, "test_solc_exec: FAILED\n");
        return 1;
    }
    fprintf(stderr, "test_solc_exec: all configurations passed\n");
    return 0;
}
