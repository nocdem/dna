/**
 * Nodus — the ML-DSA-87 companion library's attested message and signature
 * (src/client/nodus_evm_attest.c), behind `nodus-cli evm attest`.
 *
 * Design: docs/plans/2026-10-22-mldsa87-companion-library-design.md rev 2
 * §1.3, §1.6, §1.7, §5 "CLI"; decisions 2026-10-21-mldsa87-evm-precompile.md
 * (item 2: context "nodus.evm.attest.v1", 19 bytes; TAG_ATTEST_V1) and
 * 2026-10-22-kurultay-40-mldsa-companion-library-summary.md.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. the builder reproduces BOTH cases of the message fixture
 *     (nodus/tools/evm/contracts/test/fixtures/attest_v1.txt: a static-only
 *     action and one with a dynamic `bytes`) byte for byte — message,
 *     actionType and canonical action text — so the CLI and the oracle
 *     (which encodes the ABI by hand) agree; and TAG_ATTEST_V1 computed here
 *     equals the decision's bytes 99e805e3...a43d.
 *  2. the refusals: a 10th parameter (before the tuple is filled), an empty
 *     name, an invalid name, a return list, a value-count mismatch, an
 *     expiry that does not fit uint64, a nonce above 2^256-1, a message
 *     above 65536 bytes — and the boundary cases that must still pass
 *     (9 parameters, expiry 2^64-1, a 65536-byte message).
 *  3. the signature of a fixed-seed identity is exactly 4627 bytes, verifies
 *     under the context "nodus.evm.attest.v1" (19 bytes), and does NOT verify
 *     under the empty context, a different context, or over a changed
 *     message; signing a message over 65536 bytes is refused and leaves the
 *     signature buffer zeroed.
 *
 * ── REQUIRES ────────────────────────────────────────────────────────────
 * The EVM build. The fixture path is compiled in by CMake
 * (NODUS_ATTEST_FIXTURE); the file must exist in the source tree. No
 * environment, no network.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Signing is hedged (dsa/sign.c): the signature BYTES differ per run, so
 *    only outcomes are asserted (length, accept / reject) — never bytes.
 *  - The fixture pins the ABI LAYOUT. Its two hash words are copied inputs;
 *    TAG is also checked here against the literal of the decision, but the
 *    compiler's own keccak256 (a separate implementation) is compared only
 *    in the engine test (shared/evm/tests/test_contract_lib.c), not here.
 *  - If the fixture file lacks a case, that case is not exercised: the test
 *    fails when fewer than two cases are read, rather than passing on one.
 */

#include "client/nodus_evm_abi.h"
#include "client/nodus_evm_attest.h"

#include "crypto/nodus_identity.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NODUS_ATTEST_FIXTURE
#error "NODUS_ATTEST_FIXTURE must name tools/evm/contracts/test/fixtures/attest_v1.txt"
#endif

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

static int unhex(const char *h, uint8_t *out, size_t n) {
    size_t got = 0;
    return nodus_evm_hex_bytes(h, out, n, &got) == 0 && got == n ? 0 : -1;
}

/* ── the fixture ─────────────────────────────────────────────────────── */

typedef struct {
    char name[16];
    char action[256], actiontype[80], chain[80], contract[80], nonce[100];
    char expiry[40], signer[80], args[1024];
    char *message;                       /* heap hex */
} fx_case_t;

#define FX_MAX 8
static fx_case_t fx[FX_MAX];
static int fx_n = 0;

static void fx_free(void) {
    for (int i = 0; i < fx_n; i++) free(fx[i].message);
}

/* "key value" lines; `case` opens a block, a blank line closes it */
static int fx_load(void) {
    FILE *f = fopen(NODUS_ATTEST_FIXTURE, "r");
    if (!f) return -1;
    char *line = malloc(1 << 18);
    if (!line) { fclose(f); return -1; }
    fx_case_t *cur = NULL;
    while (fgets(line, 1 << 18, f)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        if (!l || line[0] == '#') { if (!l) cur = NULL; continue; }
        char *sp = strchr(line, ' ');
        const char *val = sp ? sp + 1 : "";
        if (sp) *sp = '\0';
        if (!strcmp(line, "case")) {
            if (fx_n >= FX_MAX) { free(line); fclose(f); return -1; }
            cur = &fx[fx_n++];
            memset(cur, 0, sizeof(*cur));
            snprintf(cur->name, sizeof(cur->name), "%s", val);
        } else if (cur) {
            if (!strcmp(line, "action")) snprintf(cur->action, sizeof(cur->action), "%s", val);
            else if (!strcmp(line, "actiontype")) snprintf(cur->actiontype, sizeof(cur->actiontype), "%s", val);
            else if (!strcmp(line, "chain")) snprintf(cur->chain, sizeof(cur->chain), "%s", val);
            else if (!strcmp(line, "contract")) snprintf(cur->contract, sizeof(cur->contract), "%s", val);
            else if (!strcmp(line, "nonce")) snprintf(cur->nonce, sizeof(cur->nonce), "%s", val);
            else if (!strcmp(line, "expiry")) snprintf(cur->expiry, sizeof(cur->expiry), "%s", val);
            else if (!strcmp(line, "signer")) snprintf(cur->signer, sizeof(cur->signer), "%s", val);
            else if (!strcmp(line, "args")) snprintf(cur->args, sizeof(cur->args), "%s", val);
            else if (!strcmp(line, "message")) cur->message = strdup(val);
        }
    }
    free(line);
    fclose(f);
    return 0;
}

/* split `args` (space separated, in place) into vals; @return the count */
static int fx_split(char *args, char **vals, int cap) {
    int n = 0;
    for (char *p = strtok(args, " "); p && n < cap; p = strtok(NULL, " "))
        vals[n++] = p;
    return n;
}

static void test_fixture(void) {
    TEST("both fixture cases reproduced byte for byte");
    if (fx_load() != 0) { FAIL("cannot read the fixture file"); return; }
    if (fx_n < 2) { FAIL("fewer than two cases in the fixture"); return; }
    for (int i = 0; i < fx_n; i++) {
        fx_case_t *c = &fx[i];
        uint8_t chain[32], contract[32], signer[32];
        if (!c->message || unhex(c->chain, chain, 32) != 0 ||
            unhex(c->contract, contract, 32) != 0 ||
            unhex(c->signer, signer, 32) != 0) {
            FAIL("a fixture field is malformed");
            return;
        }
        char *vals[16];
        int nv = fx_split(c->args, vals, 16);
        nodus_evm_attest_msg_t m;
        char err[256] = "";
        if (nodus_evm_attest_build(c->action, chain, contract, c->nonce,
                                   c->expiry, signer, vals, nv, &m, err,
                                   sizeof(err)) != 0) {
            printf("FAIL: %s refused: %s\n", c->name, err);
            failed++;
            return;
        }
        char *got = malloc(m.message_len * 2 + 1);
        char at[65];
        if (!got) { nodus_evm_attest_msg_free(&m); FAIL("oom"); return; }
        hexs(m.message, m.message_len, got);
        hexs(m.action_type, 32, at);
        int same = !strcmp(got, c->message) && !strcmp(at, c->actiontype) &&
                   !strcmp(m.canon, c->action);
        free(got);
        nodus_evm_attest_msg_free(&m);
        if (!same) {
            printf("FAIL: case %s differs from the fixture\n", c->name);
            failed++;
            return;
        }
    }
    PASS();
}

static void test_tag(void) {
    TEST("TAG_ATTEST_V1 = the decision's 99e805e3...a43d");
    uint8_t tag[32];
    char h[65];
    if (nodus_evm_attest_tag(tag) != 0) { FAIL("keccak256"); return; }
    hexs(tag, 32, h);
    if (strcmp(h, "99e805e35026bce860f6bbcda7466a18fd6a7bfe81d1524494fe541c9488a43d")) {
        FAIL(h);
        return;
    }
    PASS();
}

/* ── the refusals ────────────────────────────────────────────────────── */

static const uint8_t CH[32] = { 1 }, CT[32] = { 2 }, SG[32] = { 3 };

/* @return 0 built (message freed) / -1 refused, err filled */
static int try_build(const char *action, const char *nonce, const char *expiry,
                     char **vals, int nv, char *err, size_t errcap) {
    nodus_evm_attest_msg_t m;
    int rc = nodus_evm_attest_build(action, CH, CT, nonce, expiry, SG, vals,
                                    nv, &m, err, errcap);
    if (rc == 0) {
        if (!m.message || m.message_len < 224) rc = -1;
        nodus_evm_attest_msg_free(&m);
    } else if (m.message) {
        rc = -2;                          /* a refusal must leave nothing */
    }
    return rc;
}

static void test_param_limit(void) {
    TEST("9 parameters pass, a 10th is refused before the tuple is filled");
    char *v[10];
    for (int i = 0; i < 10; i++) v[i] = (char *)"1";
    char err[256] = "";
    if (try_build("F(uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8)",
                  "0", "1", v, 9, err, sizeof(err)) != 0) {
        FAIL("nine parameters refused");
        return;
    }
    err[0] = '\0';
    if (try_build("F(uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8,"
                  "uint8)", "0", "1", v, 10, err, sizeof(err)) != -1 ||
        strstr(err, "at most 9") == NULL) {
        FAIL("a 10th parameter was accepted / no message");
        return;
    }
    PASS();
}

static void test_name_and_shape_refusals(void) {
    TEST("empty / invalid name, return list, count mismatch refused");
    char *v[2] = { (char *)"1", (char *)"1" };
    char err[256];
    struct { const char *action; int nv; } bad[] = {
        { "(uint256)", 1 },                 /* empty name */
        { "1Approve(uint256)", 1 },         /* leading digit */
        { "Approve(uint256 id)", 1 },       /* a parameter name */
        { "Approve(uint+8)", 1 },
        { "Approve(uint256)(bool)", 1 },    /* a return list */
        { "Approve", 0 },                   /* no parentheses */
        { "Approve(uint256)", 0 },          /* too few values */
        { "Approve(uint256)", 2 },          /* too many values */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        err[0] = '\0';
        if (try_build(bad[i].action, "0", "1", v, bad[i].nv, err,
                      sizeof(err)) != -1) {            /* -2: leaked output */
            printf("FAIL: accepted %s\n", bad[i].action);
            failed++;
            return;
        }
        if (!err[0]) {
            printf("FAIL: no message for %s\n", bad[i].action);
            failed++;
            return;
        }
    }
    PASS();
}

static void test_number_refusals(void) {
    TEST("expiry must fit uint64, nonce uint256; the maxima pass");
    char *v[1] = { (char *)"1" };
    char err[256];
    const char *u64max = "18446744073709551615";
    const char *u64over = "18446744073709551616";
    const char *u256max =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    const char *u256over =
        "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    if (try_build("F(uint8)", u256max, u64max, v, 1, err, sizeof(err)) != 0) {
        FAIL("the maxima were refused");
        return;
    }
    if (try_build("F(uint8)", "0", u64over, v, 1, err, sizeof(err)) == 0 ||
        strstr(err, "uint64") == NULL) {
        FAIL("an expiry of 2^64 was accepted");
        return;
    }
    if (try_build("F(uint8)", u256over, "1", v, 1, err, sizeof(err)) == 0 ||
        try_build("F(uint8)", "-1", "1", v, 1, err, sizeof(err)) == 0 ||
        try_build("F(uint8)", "0", "", v, 1, err, sizeof(err)) == 0 ||
        try_build("F(uint8)", "", "1", v, 1, err, sizeof(err)) == 0) {
        FAIL("a bad nonce / expiry was accepted");
        return;
    }
    PASS();
}

static void test_message_bound(void) {
    TEST("a message of exactly 65536 bytes passes, 65537+ is refused");
    /* F(bytes): 7 header words + offset word + length word = 288 bytes, then
     * the data padded to a multiple of 32. 65536 - 288 = 65248 data bytes
     * gives exactly 65536; one more byte pads to 65568. */
    size_t ok_n = 65536 - 288, over_n = ok_n + 1;
    char *h = malloc(over_n * 2 + 1);
    if (!h) { FAIL("oom"); return; }
    memset(h, 'a', over_n * 2);
    char err[256] = "";
    char *v[1] = { h };
    h[ok_n * 2] = '\0';
    int rc_ok = try_build("F(bytes)", "0", "1", v, 1, err, sizeof(err));
    h[ok_n * 2] = 'a';
    h[over_n * 2] = '\0';
    err[0] = '\0';
    int rc_over = try_build("F(bytes)", "0", "1", v, 1, err, sizeof(err));
    free(h);
    if (rc_ok != 0) { FAIL("the 65536-byte message was refused"); return; }
    if (rc_over == 0 || strstr(err, "65536") == NULL) {
        FAIL("a message over 65536 bytes was accepted");
        return;
    }
    PASS();
}

/* ── the signature ───────────────────────────────────────────────────── */

static void test_signature(void) {
    TEST("fixed-seed identity: 4627 bytes, verifies under the context only");
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x41 + i);
    nodus_identity_t id;
    if (nodus_identity_from_seed(seed, &id) != 0) { FAIL("identity"); return; }

    uint8_t signer[32];
    if (nodus_evm_addr_of_pk(id.pk.bytes, signer) != 0) { FAIL("addr"); return; }
    char *v[2] = { (char *)"1000", (char *)"deadbeef01" };
    nodus_evm_attest_msg_t m;
    char err[256] = "";
    if (nodus_evm_attest_build("Submit(uint256,bytes)", CH, CT, "7",
                               "1800000000", signer, v, 2, &m, err,
                               sizeof(err)) != 0) {
        FAIL(err);
        return;
    }

    uint8_t sig[NODUS_EVM_ATTEST_SIG_LEN];
    int ok = 0;
    if (nodus_evm_attest_sign(m.message, m.message_len, id.sk.bytes,
                              id.pk.bytes, sig) != 0) {
        FAIL("signing failed");
    } else if (sizeof(sig) != 4627u || NODUS_EVM_ATTEST_CTX_LEN != 19u ||
               strlen(NODUS_EVM_ATTEST_CTX) != 19u) {
        FAIL("size / context constants");
    } else if (qgp_dsa87_verify_ctx(sig, sizeof(sig), m.message,
                                    m.message_len,
                                    (const uint8_t *)"nodus.evm.attest.v1", 19,
                                    id.pk.bytes) != 0) {
        FAIL("does not verify under the context");
    } else if (qgp_dsa87_verify_ctx(sig, sizeof(sig), m.message, m.message_len,
                                    NULL, 0, id.pk.bytes) == 0) {
        FAIL("verifies under the EMPTY context");
    } else if (qgp_dsa87_verify_ctx(sig, sizeof(sig), m.message, m.message_len,
                                    (const uint8_t *)"nodus.evm.attest.v2", 19,
                                    id.pk.bytes) == 0) {
        FAIL("verifies under another context");
    } else {
        m.message[m.message_len - 1] ^= 1;
        if (qgp_dsa87_verify_ctx(sig, sizeof(sig), m.message, m.message_len,
                                 (const uint8_t *)"nodus.evm.attest.v1", 19,
                                 id.pk.bytes) == 0)
            FAIL("verifies over a changed message");
        else
            ok = 1;
        m.message[m.message_len - 1] ^= 1;
    }
    nodus_evm_attest_msg_free(&m);
    if (ok) PASS();
}

static void test_sign_refusals(void) {
    TEST("signing refuses an over-long message / a wrong key pair");
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x61 + i);
    nodus_identity_t a, b;
    if (nodus_identity_from_seed(seed, &a) != 0) { FAIL("identity a"); return; }
    seed[0] ^= 0xff;
    if (nodus_identity_from_seed(seed, &b) != 0) { FAIL("identity b"); return; }

    uint8_t msg[NODUS_EVM_ATTEST_MSG_MAX + 1];
    memset(msg, 7, sizeof(msg));
    uint8_t sig[NODUS_EVM_ATTEST_SIG_LEN];
    memset(sig, 0xAB, sizeof(sig));
    if (nodus_evm_attest_sign(msg, sizeof(msg), a.sk.bytes, a.pk.bytes,
                              sig) == 0) {
        FAIL("a 65537-byte message was signed");
        return;
    }
    for (size_t i = 0; i < sizeof(sig); i++)
        if (sig[i]) { FAIL("the signature buffer was not zeroed"); return; }
    /* a secret key whose public key is not the one given: the re-verify fails */
    if (nodus_evm_attest_sign(msg, 64, a.sk.bytes, b.pk.bytes, sig) == 0) {
        FAIL("signed with a mismatched key pair");
        return;
    }
    if (nodus_evm_attest_sign(msg, 64, a.sk.bytes, a.pk.bytes, sig) != 0) {
        FAIL("a 64-byte message was refused");
        return;
    }
    PASS();
}

int main(void) {
    printf("test_evm_attest\n");
    test_fixture();
    test_tag();
    test_param_limit();
    test_name_and_shape_refusals();
    test_number_refusals();
    test_message_bound();
    test_signature();
    test_sign_refusals();
    fx_free();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
