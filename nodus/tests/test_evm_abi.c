/**
 * Nodus — the EVM contract-ABI text layer (src/client/nodus_evm_abi.c),
 * moved out of tools/nodus-cli.c; behind `evm encode|send|call|deploy|attest`.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. the parser is STRICTLY CANONICAL (Kurultay #40, Astra finding A1,
 *     docs/plans/decisions/2026-10-22-kurultay-40-mldsa-companion-library-
 *     summary.md): an integer width / bytes size that is not plain decimal
 *     digits, or does not fit before narrowing, is REFUSED —
 *     `uint4294967552` (which a 32-bit narrowing used to read as 256),
 *     `uint+8`, `uint 8`, `bytes+1`, `bytes 1`, `uint08`, widths outside
 *     8..256 / not a multiple of 8, bytes0 / bytes33 — and a function name
 *     must be a Solidity identifier (`1Approve`, `Approve(uint256 id)`).
 *  2. canonicalisation is kept: `uint` -> `uint256`, `int` -> `int256`,
 *     spaces around a list element are trimmed, the canonical text is
 *     rebuilt from the validated numbers.
 *  3. valid inputs keep their selectors and encodings: three well-known
 *     ERC-20 selectors (a9059cbb, 70a08231, 095ea7b3 — keccak256 of the
 *     canonical text, independent of this tree), and hand-written head/tail
 *     encodings of static, signed, fixed-bytes, string and T[] arguments.
 *  4. an out-of-range value is refused with a message.
 *
 * ── REQUIRES ────────────────────────────────────────────────────────────
 * The EVM build (keccak256 is linked only there). No compile flag beyond
 * the default, no environment, no network.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 * Nothing (no files, no processes).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The pinned encodings are written by hand from the ABI spec here, by the
 *    same author as the encoder; the selectors are the only values taken
 *    from outside the tree. A shared misreading of the spec would pass.
 *  - Only the listed refused inputs are exercised; another malformed width
 *    is covered only through the same digit rule.
 *  - Address checksum handling (mixed case) is not exercised here.
 */

#include "client/nodus_evm_abi.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void hexs(const uint8_t *b, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[b[i] >> 4];
        out[2 * i + 1] = hx[b[i] & 15];
    }
    out[2 * n] = '\0';
}

/* 1 when the signature is refused */
static int sig_refused(const char *sig) {
    nodus_evm_abi_sig_t g;
    char err[256];
    return nodus_evm_abi_sig(sig, &g, err, sizeof(err)) != 0;
}

/* canonical text of a valid signature ("" when refused) */
static const char *canon_of(const char *sig) {
    static nodus_evm_abi_sig_t g;
    char err[256];
    if (nodus_evm_abi_sig(sig, &g, err, sizeof(err)) != 0) return "";
    return g.canon;
}

/* encode `sig`'s arguments (vals) into lowercase hex ("REFUSED" on failure) */
static const char *enc_hex(const char *sig, char **vals, int n_vals) {
    static char out[1024];
    nodus_evm_abi_sig_t g;
    char err[256];
    if (nodus_evm_abi_sig(sig, &g, err, sizeof(err)) != 0 || g.n_in != n_vals)
        return "REFUSED";
    uint8_t *enc = NULL;
    size_t len = 0;
    if (nodus_evm_abi_encode(g.in, g.n_in, vals, &enc, &len, err,
                             sizeof(err)) != 0) {
        snprintf(out, sizeof(out), "REFUSED");
        return out;
    }
    if (len * 2 + 1 > sizeof(out)) { free(enc); return "TOO LONG"; }
    hexs(enc, len, out);
    free(enc);
    return out;
}

static void rep(char *dst, const char *word, int n) {
    dst[0] = '\0';
    for (int i = 0; i < n; i++) strcat(dst, word);
}

static void test_parser_refusals(void) {
    TEST("the K40 parser regressions are refused");
    static const char *bad[] = {
        "Approve(uint4294967552)",      /* narrowed to 256 before the range check */
        "Approve(uint+8)",              /* strtoul took the sign */
        "Approve(uint 8)",              /* ... and the space */
        "Approve(bytes+1)",
        "Approve(bytes 1)",
        "1Approve(uint256)",            /* a leading digit in the name */
        "Approve(uint256 id)",          /* parameter names are not types */
        "Approve(uint08)",              /* leading zero */
        "Approve(uint7)", "Approve(uint264)", "Approve(uint0)",
        "Approve(uint1000)",
        "Approve(int4294967552)",
        "Approve(uint-8)", "Approve(uint0x8)",
        "Approve(bytes0)", "Approve(bytes33)", "Approve(bytes01)",
        "Approve(bytes4294967297)",
        "Appro ve(uint256)", "Appr-ove(uint256)",
        NULL
    };
    for (int i = 0; bad[i]; i++) {
        if (!sig_refused(bad[i])) {
            printf("FAIL: accepted %s\n", bad[i]);
            failed++;
            return;
        }
    }
    PASS();
}

static void test_name_rules(void) {
    TEST("names: identifier chars; empty only as a constructor");
    nodus_evm_abi_sig_t g;
    char err[256];
    if (sig_refused("_a$9(uint256)") || sig_refused("$x()") ||
        sig_refused("A1()")) { FAIL("a valid identifier refused"); return; }
    if (!sig_refused("9a()")) { FAIL("a leading digit accepted"); return; }
    if (nodus_evm_abi_sig("(uint256,address)", &g, err, sizeof(err)) != 0 ||
        !g.is_ctor || strcmp(g.canon, "(uint256,address)") != 0) {
        FAIL("a constructor list refused or not flagged");
        return;
    }
    if (nodus_evm_abi_sig("f(uint256)", &g, err, sizeof(err)) != 0 ||
        g.is_ctor) { FAIL("a named signature flagged as a constructor"); return; }
    PASS();
}

static void test_canonicalisation(void) {
    TEST("uint->uint256, int->int256, canon rebuilt, spaces trimmed");
    if (strcmp(canon_of("f(uint)"), "f(uint256)") ||
        strcmp(canon_of("f(int)"), "f(int256)") ||
        strcmp(canon_of("f( uint , address )"), "f(uint256,address)") ||
        strcmp(canon_of("f(uint8,int128,bytes32,bytes,string,bool,address,"
                        "uint16[])"),
               "f(uint8,int128,bytes32,bytes,string,bool,address,uint16[])") ||
        strcmp(canon_of("f(uint256)(bool,bytes4)"), "f(uint256)")) {
        FAIL("canonical text differs");
        return;
    }
    nodus_evm_abi_sig_t g;
    char err[256];
    if (nodus_evm_abi_sig("f(uint)(bool,bytes4)", &g, err, sizeof(err)) != 0 ||
        !g.has_out || g.n_out != 2 || g.n_in != 1) {
        FAIL("return list");
        return;
    }
    if (!sig_refused("f(uint[])(uint256[])") || !sig_refused("f(uint[2])") ||
        !sig_refused("f((uint256))") || !sig_refused("f(uint,)")) {
        FAIL("a refused shape accepted");
        return;
    }
    PASS();
}

static void test_selectors(void) {
    TEST("three well-known ERC-20 selectors");
    struct { const char *sig, *hex; } k[] = {
        { "transfer(address,uint256)", "a9059cbb" },
        { "balanceOf(address)",        "70a08231" },
        { "approve(address,uint256)",  "095ea7b3" },
    };
    for (size_t i = 0; i < 3; i++) {
        uint8_t sel[4];
        char h[9];
        if (nodus_evm_abi_selector(canon_of(k[i].sig), sel) != 0) {
            FAIL("selector failed");
            return;
        }
        hexs(sel, 4, h);
        if (strcmp(h, k[i].hex) != 0) { FAIL(k[i].sig); return; }
    }
    PASS();
}

static void test_encodings(void) {
    TEST("hand-written head/tail encodings");
    char z31[200], f32[200], want[1024];
    rep(z31, "00", 31);
    rep(f32, "ff", 32);

    char *v1[] = { (char *)"1" };
    snprintf(want, sizeof(want), "%s01", z31);
    if (strcmp(enc_hex("f(uint256)", v1, 1), want)) { FAIL("uint256 1"); return; }

    char *v2[] = { (char *)"-1" };
    if (strcmp(enc_hex("f(int8)", v2, 1), f32)) { FAIL("int8 -1"); return; }

    char *v3[] = { (char *)"deadbeef" };
    char z28[200];
    rep(z28, "00", 28);
    snprintf(want, sizeof(want), "deadbeef%s", z28);
    if (strcmp(enc_hex("f(bytes4)", v3, 1), want)) { FAIL("bytes4"); return; }

    char *v4[] = { (char *)"abc" };
    char z29[200];
    rep(z29, "00", 29);
    /* offset 0x20, length 3, "abc" right-padded to 32 bytes */
    snprintf(want, sizeof(want), "%s20%s03616263%s", z31, z31, z29);
    if (strcmp(enc_hex("f(string)", v4, 1), want)) { FAIL("string"); return; }

    char *v5[] = { (char *)"[1,2]" };
    snprintf(want, sizeof(want), "%s20%s02%s01%s02", z31, z31, z31, z31);
    if (strcmp(enc_hex("f(uint8[])", v5, 1), want)) { FAIL("uint8[]"); return; }

    char *v6[] = { (char *)"256" };
    if (strcmp(enc_hex("f(uint8)", v6, 1), "REFUSED")) {
        FAIL("uint8 256 accepted");
        return;
    }
    PASS();
}

static void test_encode_error_text(void) {
    TEST("an out-of-range value leaves a message in err");
    nodus_evm_abi_sig_t g;
    char err[256] = "x";
    char *v[] = { (char *)"256" };
    uint8_t *enc = NULL;
    size_t len = 0;
    if (nodus_evm_abi_sig("f(uint8)", &g, err, sizeof(err)) != 0 ||
        nodus_evm_abi_encode(g.in, g.n_in, v, &enc, &len, err,
                             sizeof(err)) == 0 ||
        strstr(err, "argument 1") == NULL || enc != NULL) {
        free(enc);
        FAIL("no message / output set");
        return;
    }
    nodus_evm_abi_sig_t t;
    if (nodus_evm_abi_sig("f((uint256))", &t, err, sizeof(err)) == 0 ||
        strstr(err, "tuples are not supported") == NULL) {
        FAIL("tuple refusal text");
        return;
    }
    PASS();
}

static void test_numbers(void) {
    TEST("u256 decimal text round-trips; 2^256 refused; hex rules");
    const char *max =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    const char *over =
        "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    uint8_t w[32], v[32];
    char dec[80];
    if (nodus_evm_u256_dec(max, w) != 0) { FAIL("2^256-1 refused"); return; }
    for (int i = 0; i < 32; i++)
        if (w[i] != 0xff) { FAIL("2^256-1 bytes"); return; }
    nodus_evm_u256_to_dec(w, dec);
    if (strcmp(dec, max) != 0) { FAIL("to_dec"); return; }
    if (nodus_evm_u256_dec(over, v) == 0 || nodus_evm_u256_dec("", v) == 0 ||
        nodus_evm_u256_dec("1a", v) == 0 || nodus_evm_u256_dec("-1", v) == 0) {
        FAIL("a bad decimal accepted");
        return;
    }
    size_t n = 0;
    uint8_t b[4];
    if (nodus_evm_hex_bytes("0xdeadbeef", b, 4, &n) != 0 || n != 4 ||
        b[0] != 0xde || nodus_evm_hex_bytes("abc", b, 4, &n) == 0 ||
        nodus_evm_hex_bytes("zz", b, 4, &n) == 0 ||
        nodus_evm_hex_bytes("0102030405", b, 4, &n) == 0) {
        FAIL("hex_bytes");
        return;
    }
    PASS();
}

static void test_addr_of_pk(void) {
    TEST("addr_of_pk = SHA3-512(pk)[0..32]");
    uint8_t seed[32], pk[QGP_DSA87_PUBLICKEYBYTES],
            sk[QGP_DSA87_SECRETKEYBYTES], fp[64], a[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x30 + i);
    if (qgp_dsa87_keypair_derand(pk, sk, seed) != 0 ||
        qgp_sha3_512(pk, sizeof(pk), fp) != 0 ||
        nodus_evm_addr_of_pk(pk, a) != 0 || memcmp(a, fp, 32) != 0) {
        FAIL("address differs from the fingerprint prefix");
        return;
    }
    uint8_t p[32];
    char h[65];
    hexs(a, 32, h);
    if (nodus_evm_addr_parse(h, p) != 0 || memcmp(p, a, 32) != 0) {
        FAIL("lowercase address round trip");
        return;
    }
    PASS();
}

int main(void) {
    printf("test_evm_abi\n");
    test_parser_refusals();
    test_name_rules();
    test_canonicalisation();
    test_selectors();
    test_encodings();
    test_encode_error_text();
    test_numbers();
    test_addr_of_pk();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
