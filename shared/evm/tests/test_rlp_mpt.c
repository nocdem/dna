/**
 * @file test_rlp_mpt.c
 * @brief Known-answer checks for the test-only RLP and MPT code used by the
 *        state-test harness. Standalone: needs no engine (links evm_rlp,
 *        evm_mpt, keccak256 and the qgp shim only).
 *
 * Every expected value is copied from a pinned source, cited per vector:
 *   [R]  execution-specs @a87891f7 (scratchpad execution-specs/)
 *   [F]  execution-spec-tests v5.4.0 fixtures_stable (scratchpad
 *        eest/fixtures/state_tests/)
 * The fixture state roots are the strongest check here: the root of an
 * official post-state `state` dump must equal that entry's `hash`, which
 * exercises RLP (short and long strings and lists), hex-prefix encoding,
 * node embedding/hashing, the secure trie and the account encoding.
 */
#include "evm_rlp.h"
#include "evm_mpt.h"
#include "crypto/hash/keccak256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;

#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) {                                                         \
            printf("ok   %s\n", what);                                      \
        } else {                                                            \
            printf("FAIL %s (%s:%d)\n", what, __FILE__, __LINE__);          \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse hex (optional 0x, any length; odd length gets a leading 0) into a
 * right-aligned buffer of exactly `n` bytes. @return 0 or -1. */
static int hex_right(const char *s, uint8_t *out, size_t n)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    size_t len = strlen(s);
    memset(out, 0, n);
    size_t bytes = (len + 1) / 2;
    while (bytes > n) {                       /* allow leading zero digits */
        if (*s != '0') return -1;
        s++;
        len--;
        bytes = (len + 1) / 2;
    }
    size_t o = n - bytes;
    size_t i = 0;
    if (len % 2) {
        int v = hexval(s[0]);
        if (v < 0) return -1;
        out[o++] = (uint8_t)v;
        i = 1;
    }
    for (; i < len; i += 2) {
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[o++] = (uint8_t)(hi * 16 + lo);
    }
    return 0;
}

/* Exact-length hex -> bytes; returns length or -1. */
static long hex_exact(const char *s, uint8_t *out, size_t cap)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    size_t len = strlen(s);
    if (len % 2 || len / 2 > cap) return -1;
    for (size_t i = 0; i < len; i += 2) {
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)(hi * 16 + lo);
    }
    return (long)(len / 2);
}

static int eq_hex(const uint8_t *got, size_t got_len, const char *want)
{
    uint8_t w[256];
    long wl = hex_exact(want, w, sizeof(w));
    return wl >= 0 && (size_t)wl == got_len && memcmp(got, w, got_len) == 0;
}

/* ── RLP integers: [R] tests/json_loader/test_rlp.py:20-24 ────────────── */
static void test_rlp_uint(void)
{
    static const struct { uint64_t v; const char *enc; } vec[] = {
        { 0x00,   "80"     },   /* zero-empty-string  (test_rlp.py:20) */
        { 0x01,   "01"     },   /* one                (test_rlp.py:21) */
        { 0x7f,   "7f"     },   /* single-byte-max    (test_rlp.py:22) */
        { 0x80,   "8180"   },   /* smallest-prefixed  (test_rlp.py:23) */
        { 0x0100, "820100" },   /* two-bytes          (test_rlp.py:24) */
    };
    for (size_t i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
        char what[96];
        evm_rlp_buf b = {0};
        int rc = evm_rlp_put_u64(&b, vec[i].v);
        snprintf(what, sizeof(what), "rlp encode uint 0x%llx -> %s",
                 (unsigned long long)vec[i].v, vec[i].enc);
        CHECK(rc == 0 && eq_hex(b.p, b.len, vec[i].enc), what);

        evm_rlp_item it;
        uint64_t back = ~(uint64_t)0;
        rc = evm_rlp_decode_item(b.p, b.len, &it);
        if (rc == 0) rc = evm_rlp_item_to_u64(&it, &back);
        snprintf(what, sizeof(what), "rlp decode %s -> 0x%llx", vec[i].enc,
                 (unsigned long long)vec[i].v);
        CHECK(rc == 0 && it.total == b.len && back == vec[i].v, what);
        evm_rlp_buf_free(&b);
    }

    /* non-canonical integers are rejected (test_rlp.py:40-42) */
    static const char *bad[] = { "00", "820001", "83000001" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint8_t raw[8];
        long n = hex_exact(bad[i], raw, sizeof(raw));
        evm_rlp_item it;
        uint64_t v;
        int rc = (n < 0) ? -1 : evm_rlp_decode_item(raw, (size_t)n, &it);
        if (rc == 0) rc = evm_rlp_item_to_u64(&it, &v);
        char what[96];
        snprintf(what, sizeof(what), "rlp reject non-canonical uint %s",
                 bad[i]);
        CHECK(rc != 0, what);
    }
}

/* ── keccak256 link sanity: [R] packages/testing/src/execution_testing/
 *    base_types/tests/test_keccak_dispatch.py:29-36 ──────────────────── */
static void test_keccak(void)
{
    uint8_t h[32];
    int rc = keccak256((const uint8_t *)"", 0, h);
    CHECK(rc == 0 && eq_hex(h, 32,
          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
          "keccak256(\"\") (test_keccak_dispatch.py:29-32)");
    rc = keccak256((const uint8_t *)"abc", 3, h);
    CHECK(rc == 0 && eq_hex(h, 32,
          "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
          "keccak256(\"abc\") (test_keccak_dispatch.py:33-36)");

    /* Rate boundary and multi-block absorb (red-team 1: the Keccak-f[1600]
     * permutation of keccak256.c was replaced by XKCP's unrolled one).
     * Input byte i = (7i + 3) mod 256. Expected values from the
     * independent FIPS 202 oracle in tests/addr32_oracle.py (keccak256(),
     * rho offsets and round constants derived, not tabulated):
     *   python3 -c "import importlib.util as u; s=u.spec_from_file_location(
     *     'o','tests/addr32_oracle.py'); o=u.module_from_spec(s);
     *     s.loader.exec_module(o); print(o.keccak256(bytes(((i*7+3)&255)
     *     for i in range(N))).hex())"                                       */
    static const struct { size_t n; const char *hex; } multi[] = {
        { 135,  "00ef96af9cf4b24c7f269d922294444a197d0a33638c2e56634c57e892103a8f" },
        { 136,  "742061bcad767ed4c4f5883b1dcb1aad11afdcc140dc469d953759b127b9f9ed" },
        { 137,  "e3371f61e770abf254c34239c3b0099ad90594507415bc81dd0a10b9692bbf2a" },
        { 272,  "ac141fd7b0a0ffcd2e967254d508da3ec616596493c36fa304425647d90e6de5" },
        { 1000, "80cdc8dd52cbb3dbaea8f383209893fa2bb52efbd5aedbb4b26dcfe307fcdc9b" },
    };
    uint8_t in[1000];
    for (size_t i = 0; i < sizeof(in); i++) in[i] = (uint8_t)(i * 7 + 3);
    for (size_t k = 0; k < sizeof(multi) / sizeof(multi[0]); k++) {
        char what[64];
        snprintf(what, sizeof(what), "keccak256(%zu-byte pattern) (oracle)",
                 multi[k].n);
        rc = keccak256(in, multi[k].n, h);
        CHECK(rc == 0 && eq_hex(h, 32, multi[k].hex), what);
    }
}

/* ── keccak(rlp([])): [R] src/ethereum/forks/london/fork.py:79
 *    EMPTY_OMMER_HASH = keccak256(rlp.encode([])), value in
 *    packages/testing/src/execution_testing/base_types/constants.py:19-21.
 *    This is also the `logs` hash of every fixture entry without logs. ── */
static void test_empty_list_hash(void)
{
    evm_rlp_buf b = {0};
    int rc = evm_rlp_wrap_list(&b, 0);
    uint8_t h[32];
    CHECK(rc == 0 && eq_hex(b.p, b.len, "c0"), "rlp([]) = c0");
    rc = (rc == 0) ? keccak256(b.p, b.len, h) : -1;
    CHECK(rc == 0 && eq_hex(h, 32,
          "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
          "keccak256(rlp([])) (constants.py:19-21)");
    evm_rlp_buf_free(&b);
}

/* ── empty trie: [R] src/ethereum/merkle_patricia_trie.py:71-75 ──────── */
static void test_empty_trie(void)
{
    uint8_t r[32];
    int rc = evm_mpt_root(NULL, 0, 1, r);
    CHECK(rc == 0 && eq_hex(r, 32,
          "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
          "empty trie root (merkle_patricia_trie.py:71-75)");
}

/* ── fixture post-state roots ─────────────────────────────────────────── */
typedef struct { const char *key, *val; } slot_vec;
typedef struct {
    const char *addr, *nonce, *balance, *code;
    slot_vec    slots[4];
    size_t      n_slots;
} acct_vec;

/* storage root of one account (secured, value = rlp(uint)) */
static int vec_storage_root(const acct_vec *a, uint8_t root[32])
{
    uint8_t keys[4][32];
    evm_rlp_buf vals[4] = {{0}};
    evm_mpt_kv kv[4];
    int rc = 0;
    for (size_t i = 0; i < a->n_slots && rc == 0; i++) {
        uint8_t v[32];
        if (hex_right(a->slots[i].key, keys[i], 32) != 0 ||
            hex_right(a->slots[i].val, v, 32) != 0) { rc = -1; break; }
        rc = evm_rlp_put_uint_be(&vals[i], v, 32);
        kv[i].key = keys[i];
        kv[i].key_len = 32;
        kv[i].val = vals[i].p;
        kv[i].val_len = vals[i].len;
    }
    if (rc == 0) rc = evm_mpt_root(kv, a->n_slots, 1, root);
    for (size_t i = 0; i < 4; i++) evm_rlp_buf_free(&vals[i]);
    return rc;
}

/* state root over a vector of accounts (state_mpt.py:82-120,
 * merkle_patricia_trie.py:193-210) */
static int vec_state_root(const acct_vec *accts, size_t n, uint8_t root[32])
{
    uint8_t addrs[8][20];
    evm_rlp_buf vals[8] = {{0}};
    evm_mpt_kv kv[8];
    int rc = (n <= 8) ? 0 : -1;
    for (size_t i = 0; i < n && rc == 0; i++) {
        const acct_vec *a = &accts[i];
        uint8_t nonce[8], bal[32], code[64], sroot[32], chash[32];
        long clen = hex_exact(a->code, code, sizeof(code));
        if (hex_right(a->addr, addrs[i], 20) != 0 ||
            hex_right(a->nonce, nonce, 8) != 0 ||
            hex_right(a->balance, bal, 32) != 0 || clen < 0) { rc = -1; break; }
        if ((rc = vec_storage_root(a, sroot)) != 0) break;
        if (keccak256(clen ? code : (const uint8_t *)"", (size_t)clen,
                      chash) != 0) { rc = -2; break; }
        if (evm_rlp_put_uint_be(&vals[i], nonce, 8) != 0 ||
            evm_rlp_put_uint_be(&vals[i], bal, 32) != 0 ||
            evm_rlp_put_bytes(&vals[i], sroot, 32) != 0 ||
            evm_rlp_put_bytes(&vals[i], chash, 32) != 0 ||
            evm_rlp_wrap_list(&vals[i], 0) != 0) { rc = -2; break; }
        kv[i].key = addrs[i];
        kv[i].key_len = 20;
        kv[i].val = vals[i].p;
        kv[i].val_len = vals[i].len;
    }
    if (rc == 0) rc = evm_mpt_root(kv, n, 1, root);
    for (size_t i = 0; i < 8; i++) evm_rlp_buf_free(&vals[i]);
    return rc;
}

static void test_fixture_roots(void)
{
    /* [F] static/state_tests/stRevertTest/RevertInCreateInInit_Paris.json,
     * key "tests/static/state_tests/stRevertTest/RevertInCreateInInit_Paris
     * Filler.json::RevertInCreateInInit_Paris[fork_Prague-state_test-]",
     * post.Prague[0].state / .hash */
    static const acct_vec v1[] = {
        { "0x585f75c10ed2fcf2b3e63ccc35b175322ccef93a", "0x01",
          "0x63ffec2cc4", "0x", {{0}}, 0 },
        { "0x4db58b0f3a4921166333a88b945c9f460aeb9d78", "0x00", "0x0a", "0x",
          {{ "0x00", "0x01" }}, 1 },
        { "0xb88b3553c57a853ccdff28dd2c357c9cba295c20", "0x02", "0x00", "0x",
          {{ "0x00", "0x20" }, { "0x01", "0x112233" }}, 2 },
    };
    uint8_t r[32];
    int rc = vec_state_root(v1, 3, r);
    CHECK(rc == 0 && eq_hex(r, 32,
          "7326d795472c88d6c24482b0bb566eac54de3fd4d18dc55e5f1949a1b47b804c"),
          "fixture root RevertInCreateInInit_Paris[Prague][0]");

    /* [F] paris/eip7610_create_collision/test_init_collision_create_tx.json,
     * key "tests/paris/eip7610_create_collision/test_initcollision.py::
     * test_init_collision_create_tx[fork_Prague-tx_type_0-state_test-
     * non-empty-code-correct-initcode]", post.Prague[0].state / .hash */
    static const acct_vec v2[] = {
        { "0x7a2e68e12a5895764c4a090a9268132394082248", "0x01",
          "0x3635c9adc5de817b80", "0x", {{0}}, 0 },
        { "0x6d7015fc59e81bfc2287c77c50eb7ba268b763e6", "0x00", "0x00", "0x00",
          {{ "0x01", "0x01" }}, 1 },
        { "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba", "0x00", "0x0927c0",
          "0x", {{0}}, 0 },
    };
    rc = vec_state_root(v2, 3, r);
    CHECK(rc == 0 && eq_hex(r, 32,
          "f51c1cc0ca4eb07940d838dc30bdd3aabcf8231a9c6145db893db1f707b4340a"),
          "fixture root test_init_collision_create_tx[Prague][0]");

    /* order independence: same leaves, reversed input order */
    const acct_vec v2r[] = { v2[2], v2[1], v2[0] };
    uint8_t r2[32];
    rc = vec_state_root(v2r, 3, r2);
    CHECK(rc == 0 && memcmp(r, r2, 32) == 0, "root independent of input order");
}

/* ── RLP decode of a fixture txbytes (long-form list, chain id from v) ──
 * [F] same entry as v2 above, post.Prague[0].txbytes. Legacy layout
 * nonce, gas_price, gas, to, value, data, v, r, s
 * ([R] src/ethereum/forks/prague/transactions.py LegacyTransaction);
 * chain id = (v - 35) >> 1 (transactions.py:660-675). */
static void test_txbytes_decode(void)
{
    static const char *tx =
        "f862800a83030d408080966001600055600060015561000160008160158239f300"
        "26a09495fb62a52069023612ba664cd15f3739075ea1a1dafb01e34b9161d57fa9"
        "74a051b066f449494b0311c60f4f7af0c2e90f03197082804127d3a55c45b34cfb8f";
    uint8_t raw[128];
    long n = hex_exact(tx, raw, sizeof(raw));
    evm_rlp_item list, v, to;
    uint64_t vv = 0;
    int rc = (n < 0) ? -1 : evm_rlp_decode_item(raw, (size_t)n, &list);
    CHECK(rc == 0 && list.is_list && list.total == (size_t)n && list.len == 0x62,
          "decode long-form legacy tx list");
    if (rc == 0) rc = evm_rlp_list_get(&list, 3, &to);
    CHECK(rc == 0 && !to.is_list && to.len == 0, "tx.to empty (create)");
    if (rc == 0) rc = evm_rlp_list_get(&list, 6, &v);
    if (rc == 0) rc = evm_rlp_item_to_u64(&v, &vv);
    CHECK(rc == 0 && vv == 0x26 && ((vv - 35) >> 1) == 1, "tx.v = 0x26 -> chain id 1");
    evm_rlp_item none;
    CHECK(evm_rlp_list_get(&list, 9, &none) != 0, "list index past end rejected");
}

int main(void)
{
    test_rlp_uint();
    test_keccak();
    test_empty_list_hash();
    test_empty_trie();
    test_fixture_roots();
    test_txbytes_decode();
    printf("%s: %d failure(s)\n", g_fail ? "FAILED" : "PASSED", g_fail);
    return g_fail ? 1 : 0;
}
