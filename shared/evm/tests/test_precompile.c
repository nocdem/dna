/**
 * @file test_precompile.c
 * @brief Direct known-answer tests of the Nodus EVM precompiles — TEST-ONLY.
 *
 * Usage:
 *   test_precompile [<execution-specs>/tests]
 *
 * 1. evm_precompile_selftest() must return 0 (one vector per family, the
 *    sources are listed in evm_precompile.c next to PC_KATS), and
 *    evm_precompile_selftest_report(&what) must return 0 with what = NULL
 *    (the form nodus_witness_init calls at start, red-team 1 F2).
 * 1a. Precompiles 0x02 (SHA-256, blst) and 0x03 (RIPEMD-160,
 *    trezor-crypto) against published known answers (sources cited at
 *    DIGEST_KATS), through evm_precompile_run, checking the 32-byte
 *    precompile output. Always runs.
 * 2. With the execution-specs tests directory (pinned commit a87891f7)
 *    given, every vector file below is run through evm_precompile_run:
 *    prague/eip2537_bls_12_381_precompiles/vectors/
 *      <op>_bls.json       {Input, Expected, Gas}: run with gas = Gas
 *                          exactly -> EVM_PC_OK, output == Expected,
 *                          gas_left == 0; run again with Gas - 1 ->
 *                          EVM_PC_OOG. (Pins the EIP-2537 gas formula,
 *                          including the MSM discount table, to the
 *                          reference's numbers.)
 *      fail-<op>_bls.json  {Input, ExpectedError}: must not be EVM_PC_OK.
 *    cancun/eip4844_blobs/point_evaluation_vectors/
 *      go_kzg_4844_verify_kzg_proof.json  {input{commitment,z,y,proof},
 *                          output}: the 192-byte precompile input is built
 *                          with the correct versioned hash; output true ->
 *                          EVM_PC_OK with FIELD_ELEMENTS_PER_BLOB ‖
 *                          BLS_MODULUS, anything else -> EVM_PC_INVALID.
 *                          Entries whose fields do not have the precompile's
 *                          fixed sizes cannot be expressed as a call and are
 *                          COUNTED AS NOT RUN (printed), never as passes.
 * Without the directory only steps 1 and 1a run, and the program says so.
 *
 * Exit 0 only if every executed check passes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include "evm_internal.h"
#include "evm_precompile.h"

static int g_fail, g_pass, g_notrun;

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* "0x"-optional hex -> fresh buffer (n may be 0); NULL if malformed */
static uint8_t *unhex(const char *s, size_t *n)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    size_t hl = strlen(s);
    if (hl % 2) return NULL;
    *n = hl / 2;
    uint8_t *b = malloc(*n ? *n : 1);
    if (!b) return NULL;
    for (size_t i = 0; i < *n; i++) {
        int hi = hexval((unsigned char)s[2 * i]), lo = hexval((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(b);
            return NULL;
        }
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    return b;
}

static int run(uint8_t addr, const uint8_t *in, size_t len, uint64_t gas,
               evm_pc_result_t *res, uint8_t **out, size_t *out_len,
               uint64_t *gas_left)
{
    evm_addr a;
    memset(&a, 0, sizeof(a));
    a.b[31] = addr;
    *gas_left = gas;
    return evm_precompile_run(&a, in, len, gas_left, res, out, out_len);
}

static void check(int ok, const char *file, const char *name, const char *what)
{
    if (ok) {
        g_pass++;
    } else {
        g_fail++;
        printf("FAIL %s %s: %s\n", file, name, what);
    }
}

/* ── 0x02 sha256 / 0x03 ripemd160: published known answers ───────── */

/* RIPEMD-160: the RIPEMD-160 authors' page, table "Hash result using
 * RIPEMD-160" and its footnotes 1-3,
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 * (fetched 2026-10-05, page sha256
 * 2c93056656682146eedb9cc4848f22b100f5b078226c990c02081db9b972f2d7).
 * SHA-256:
 *   "abc", "abcdbcde...nopq", 1 million x "a": RFC 6234 §8.5 (the test
 *   driver), TEST1 / TEST2_1 / TEST3 and the "SHA256" hash table entries
 *   1-3, https://www.rfc-editor.org/rfc/rfc6234.txt (fetched 2026-10-05,
 *   sha256 8f39f02a57bfd1da15634706724a585766e6223f77ecdaf243cad16cd3a1aa1b);
 *   "": NIST CAVP SHAVS byte-oriented vectors, SHA256ShortMsg.rsp
 *   "Len = 0", https://csrc.nist.gov/CSRC/media/Projects/
 *   Cryptographic-Algorithm-Validation-Program/documents/shs/
 *   shabytetestvectors.zip (fetched 2026-10-05, zip sha256
 *   929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8).
 * Each message is `text` repeated `reps` times; the digest is checked as
 * the precompile's 32-byte output (0x03: 12 zero bytes, then the 20-byte
 * digest). */
typedef struct {
    uint8_t     addr;
    const char *text;
    size_t      reps;
    const char *digest;
} digest_kat_t;

static const digest_kat_t DIGEST_KATS[] = {
    { 0x03, "", 1, "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
    { 0x03, "a", 1, "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe" },
    { 0x03, "abc", 1, "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
    { 0x03, "message digest", 1,
      "5d0689ef49d2fae572b881b123a85ffa21595f36" },
    { 0x03, "abcdefghijklmnopqrstuvwxyz", 1,
      "f71c27109c692c1b56bbdceb5b9d2865b3708dbc" },
    { 0x03, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
      "12a053384a9c0c88e405a06c27dcf49ada62eb2b" },
    { 0x03, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
      "b0e20b6e3116640286ed3a87a5713079b21f5189" },
    { 0x03, "1234567890", 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb" },
    { 0x03, "a", 1000000, "52783243c1697bdbe16d37f97f68f08325dc1528" },
    { 0x02, "", 1,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { 0x02, "abc", 1,
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" },
    { 0x02, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
      "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1" },
    { 0x02, "a", 1000000,
      "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0" },
};

static void digest_kats(void)
{
    for (size_t k = 0; k < sizeof(DIGEST_KATS) / sizeof(DIGEST_KATS[0]); k++) {
        const digest_kat_t *t = &DIGEST_KATS[k];
        const char *file = t->addr == 0x02 ? "sha256" : "ripemd160";
        size_t tl = strlen(t->text), len = tl * t->reps;
        size_t dl = 0, out_len = 0;
        uint8_t *msg = malloc(len ? len : 1);
        uint8_t *digest = unhex(t->digest, &dl);
        uint8_t want[32], *out = NULL;
        evm_pc_result_t res = EVM_PC_INVALID;
        uint64_t gas_left;
        if (!msg || !digest || (dl != 32 && dl != 20)) {
            check(0, file, t->text, "test setup");
            free(msg);
            free(digest);
            continue;
        }
        for (size_t r = 0; r < t->reps; r++) memcpy(msg + r * tl, t->text, tl);
        memset(want, 0, sizeof(want));
        memcpy(want + 32 - dl, digest, dl);
        /* "" goes in as data = NULL, len = 0 (an empty call): the
         * precompile must not hand NULL to a library that asserts on it */
        int rc = run(t->addr, len ? msg : NULL, len, 100000000u, &res, &out,
                     &out_len, &gas_left);
        check(rc == 0 && res == EVM_PC_OK && out_len == 32 &&
                  memcmp(out, want, 32) == 0,
              file, t->reps > 1 ? "repeated" : t->text, "digest mismatch");
        free(msg);
        free(digest);
        free(out);
    }
}

static const struct {
    const char *stem;
    uint8_t addr;
} BLS_FILES[] = {
    { "add_G1_bls", 0x0b }, { "mul_G1_bls", 0x0c }, { "msm_G1_bls", 0x0c },
    { "add_G2_bls", 0x0d }, { "mul_G2_bls", 0x0e }, { "msm_G2_bls", 0x0e },
    { "pairing_check_bls", 0x0f }, { "map_fp_to_G1_bls", 0x10 },
    { "map_fp2_to_G2_bls", 0x11 },
};

static void bls_file(const char *dir, const char *stem, uint8_t addr, int fail)
{
    char path[4096];
    snprintf(path, sizeof(path),
             "%s/prague/eip2537_bls_12_381_precompiles/vectors/%s%s.json",
             dir, fail ? "fail-" : "", stem);
    json_object *root = json_object_from_file(path);
    if (!root) {
        /* not every op has a fail- file: report, do not count */
        printf("note: %s not readable\n", path);
        return;
    }
    size_t n = json_object_array_length(root);
    for (size_t i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(root, i), *v;
        const char *name = json_object_object_get_ex(e, "Name", &v)
                               ? json_object_get_string(v) : "?";
        size_t in_len = 0, want_len = 0, out_len = 0;
        uint8_t *in = NULL, *want = NULL, *out = NULL;
        evm_pc_result_t res;
        uint64_t gas_left;
        if (!json_object_object_get_ex(e, "Input", &v) ||
            !(in = unhex(json_object_get_string(v), &in_len))) {
            check(0, stem, name, "unreadable Input");
            continue;
        }
        if (fail) {
            int rc = run(addr, in, in_len, 100000000u, &res, &out, &out_len, &gas_left);
            check(rc == 0 && res != EVM_PC_OK, stem, name, "accepted an invalid input");
        } else {
            uint64_t gas = 0;
            if (json_object_object_get_ex(e, "Gas", &v))
                gas = (uint64_t)json_object_get_int64(v);
            if (!json_object_object_get_ex(e, "Expected", &v) ||
                !(want = unhex(json_object_get_string(v), &want_len)) || gas == 0) {
                check(0, stem, name, "unreadable Expected/Gas");
                free(in);
                free(want);
                continue;
            }
            int rc = run(addr, in, in_len, gas, &res, &out, &out_len, &gas_left);
            check(rc == 0 && res == EVM_PC_OK && gas_left == 0 &&
                  out_len == want_len && memcmp(out, want, want_len) == 0,
                  stem, name, "output or gas differs (gas = Gas)");
            free(out);
            out = NULL;
            rc = run(addr, in, in_len, gas - 1, &res, &out, &out_len, &gas_left);
            check(rc == 0 && res == EVM_PC_OOG, stem, name, "not OOG at Gas - 1");
        }
        free(in);
        free(want);
        free(out);
    }
    json_object_put(root);
}

static void kzg_file(const char *dir)
{
    static const uint8_t ret_ok[64] = {
        [30] = 0x10, [31] = 0x00,                      /* 4096 */
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
        0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
        0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
    };
    char path[4096];
    snprintf(path, sizeof(path),
             "%s/cancun/eip4844_blobs/point_evaluation_vectors/"
             "go_kzg_4844_verify_kzg_proof.json", dir);
    json_object *root = json_object_from_file(path);
    if (!root) {
        check(0, "kzg", path, "not readable");
        return;
    }
    size_t n = json_object_array_length(root);
    for (size_t i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(root, i), *v, *inp, *o;
        const char *name = json_object_object_get_ex(e, "name", &v)
                               ? json_object_get_string(v) : "?";
        static const char *const keys[4] = { "z", "y", "commitment", "proof" };
        static const size_t sizes[4] = { 32, 32, 48, 48 };
        uint8_t call[192], *part[4] = { NULL, NULL, NULL, NULL };
        size_t plen[4] = { 0, 0, 0, 0 };
        int expressible = json_object_object_get_ex(e, "input", &inp);
        for (int k = 0; k < 4 && expressible; k++) {
            if (!json_object_object_get_ex(inp, keys[k], &v) ||
                !(part[k] = unhex(json_object_get_string(v), &plen[k])) ||
                plen[k] != sizes[k])
                expressible = 0;
        }
        if (expressible) {
            uint8_t *out = NULL;
            size_t out_len = 0;
            evm_pc_result_t res;
            uint64_t gas_left;
            /* versioned hash = 0x01 ‖ sha256(commitment)[1:], via the
             * sha256 precompile itself */
            uint8_t *h = NULL;
            size_t hl = 0;
            int rc = run(0x02, part[2], 48, 1000000u, &res, &h, &hl, &gas_left);
            if (rc != 0 || res != EVM_PC_OK || hl != 32) {
                check(0, "kzg", name, "sha256 precompile failed");
            } else {
                memcpy(call, h, 32);
                call[0] = 0x01;
                memcpy(call + 32, part[0], 32);
                memcpy(call + 64, part[1], 32);
                memcpy(call + 96, part[2], 48);
                memcpy(call + 144, part[3], 48);
                int want_ok = json_object_object_get_ex(e, "output", &o) &&
                              json_object_get_type(o) == json_type_boolean &&
                              json_object_get_boolean(o);
                rc = run(0x0a, call, 192, 50000u, &res, &out, &out_len, &gas_left);
                if (want_ok)
                    check(rc == 0 && res == EVM_PC_OK && gas_left == 0 &&
                          out_len == 64 && memcmp(out, ret_ok, 64) == 0,
                          "kzg", name, "valid proof not accepted");
                else
                    check(rc == 0 && res == EVM_PC_INVALID, "kzg", name,
                          "invalid proof not refused");
            }
            free(h);
            free(out);
        } else {
            g_notrun++;
            printf("not run (not expressible as a 192-byte call): kzg %s\n", name);
        }
        for (int k = 0; k < 4; k++) free(part[k]);
    }
    json_object_put(root);
}

int main(int argc, char **argv)
{
    check(evm_precompile_selftest() == 0, "selftest", "evm_precompile_selftest", "!= 0");
    {
        /* the start-up form (nodus_witness_init): 0 and no capability
         * named on success; the out-pointer is always written */
        static const char sentinel[] = "unset";
        const char *missing = sentinel;
        check(evm_precompile_selftest_report(&missing) == 0 && missing == NULL,
              "selftest", "evm_precompile_selftest_report",
              "!= 0 or a capability named");
    }
    digest_kats();
    if (argc > 1) {
        for (size_t f = 0; f < sizeof(BLS_FILES) / sizeof(BLS_FILES[0]); f++) {
            bls_file(argv[1], BLS_FILES[f].stem, BLS_FILES[f].addr, 0);
            bls_file(argv[1], BLS_FILES[f].stem, BLS_FILES[f].addr, 1);
        }
        kzg_file(argv[1]);
    } else {
        printf("no execution-specs tests directory given: vector files NOT run\n");
    }
    printf("passed %d, failed %d, not run %d\n", g_pass, g_fail, g_notrun);
    return g_fail == 0 ? 0 : 1;
}
