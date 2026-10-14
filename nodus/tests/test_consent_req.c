/**
 * Nodus — consent request code + node config reader tests
 *
 * The module behind `nodus-cli consent <code>` (src/client/nodus_consent_req.c,
 * decision docs/plans/decisions/2026-10-14-consent-request-code.md):
 *   - a valid storage code and a valid witness code parse to the right
 *     fields;
 *   - every malformed code is refused (prefix/version, role, hex case and
 *     length, expiry leading zero / 0 / overflow, extra field, whitespace,
 *     empty fields, NULL);
 *   - the config reader takes identity_path + tcp_port, leaves the port
 *     alone when the key is absent, and refuses a missing identity_path,
 *     an out-of-range or non-integer port, non-JSON and a missing file;
 *   - the confirmation answer accepts only y / yes (any case).
 * Temp files are created with mkstemp under /tmp and removed. No network.
 */

#include "client/nodus_consent_req.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* 128 / 64 lowercase hex, distinct digits so a field swap shows */
static char OWNER[129];
static char CHAIN[65];

static void fill_hex(char *dst, size_t n, unsigned seed) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) dst[i] = hx[(i * 7u + seed) % 16u];
    dst[n] = '\0';
}

static void mk_code(char *buf, size_t cap, const char *role,
                    const char *owner, const char *expiry, const char *chain) {
    snprintf(buf, cap, "nodus-consent-v1:%s:%s:%s:%s", role, owner, expiry,
             chain);
}

/* 1 when parse refuses the code, zeroes the struct and writes a message */
static int refused(const char *code) {
    nodus_consent_req_t r;
    char err[256] = "";
    memset(&r, 0xAB, sizeof(r));
    if (nodus_consent_req_parse(code, &r, err, sizeof(err)) != -1) return 0;
    if (err[0] == '\0') return 0;
    const unsigned char *b = (const unsigned char *)&r;
    for (size_t i = 0; i < sizeof(r); i++)
        if (b[i] != 0) return 0;
    return 1;
}

/* ── Parse: valid ─────────────────────────────────────────────────── */

static void test_valid_storage(void) {
    TEST("valid storage code parses to its fields");
    char code[400];
    mk_code(code, sizeof(code), "storage", OWNER, "123456", CHAIN);
    nodus_consent_req_t r;
    char err[256] = "";
    if (nodus_consent_req_parse(code, &r, err, sizeof(err)) != 0) {
        FAIL(err); return;
    }
    if (r.storage == 1 && strcmp(r.owner_hex, OWNER) == 0 &&
        r.expiry == 123456u && strcmp(r.expiry_dec, "123456") == 0 &&
        strcmp(r.chain_hex, CHAIN) == 0)
        PASS();
    else
        FAIL("fields differ");
}

static void test_valid_witness(void) {
    TEST("valid witness code parses to its fields");
    char code[400];
    mk_code(code, sizeof(code), "witness", OWNER, "7", CHAIN);
    nodus_consent_req_t r;
    char err[256] = "";
    if (nodus_consent_req_parse(code, &r, err, sizeof(err)) != 0) {
        FAIL(err); return;
    }
    if (r.storage == 0 && strcmp(r.owner_hex, OWNER) == 0 &&
        r.expiry == 7u && strcmp(r.expiry_dec, "7") == 0 &&
        strcmp(r.chain_hex, CHAIN) == 0)
        PASS();
    else
        FAIL("fields differ");
}

static void test_valid_uint64_max(void) {
    TEST("expiry UINT64_MAX (20 digits) is accepted");
    char code[400];
    mk_code(code, sizeof(code), "storage", OWNER, "18446744073709551615",
            CHAIN);
    nodus_consent_req_t r;
    char err[256] = "";
    if (nodus_consent_req_parse(code, &r, err, sizeof(err)) == 0 &&
        r.expiry == UINT64_MAX &&
        strcmp(r.expiry_dec, "18446744073709551615") == 0)
        PASS();
    else
        FAIL(err[0] ? err : "not accepted");
}

/* ── Parse: refused ───────────────────────────────────────────────── */

static void test_refuse_prefix(void) {
    TEST("refuse: wrong prefix / version");
    char code[400];
    int ok = 1;
    snprintf(code, sizeof(code), "nodus-consent-v2:storage:%s:5:%s", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent:storage:%s:5:%s", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "Nodus-consent-v1:storage:%s:5:%s", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "xnodus-consent-v1:storage:%s:5:%s", OWNER,
             CHAIN);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_role(void) {
    TEST("refuse: unknown role");
    char code[400];
    int ok = 1;
    mk_code(code, sizeof(code), "validator", OWNER, "5", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "Storage", OWNER, "5", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storag", OWNER, "5", CHAIN);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_upper_hex(void) {
    TEST("refuse: uppercase hex in owner / chain");
    char code[400], o[129], c[65];
    int ok = 1;
    memcpy(o, OWNER, sizeof(o));
    o[10] = 'A';
    mk_code(code, sizeof(code), "storage", o, "5", CHAIN);
    ok &= refused(code);
    memcpy(c, CHAIN, sizeof(c));
    c[63] = 'F';
    mk_code(code, sizeof(code), "storage", OWNER, "5", c);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_owner_len(void) {
    TEST("refuse: 127 / 129-char owner, non-hex owner");
    char code[400], o[131];
    int ok = 1;
    memcpy(o, OWNER, 127); o[127] = '\0';
    mk_code(code, sizeof(code), "storage", o, "5", CHAIN);
    ok &= refused(code);
    memcpy(o, OWNER, 128); o[128] = 'a'; o[129] = '\0';
    mk_code(code, sizeof(code), "storage", o, "5", CHAIN);
    ok &= refused(code);
    memcpy(o, OWNER, 129); o[0] = 'g';
    mk_code(code, sizeof(code), "storage", o, "5", CHAIN);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_chain_len(void) {
    TEST("refuse: 63 / 65-char chain");
    char code[400], c[67];
    int ok = 1;
    memcpy(c, CHAIN, 63); c[63] = '\0';
    mk_code(code, sizeof(code), "storage", OWNER, "5", c);
    ok &= refused(code);
    memcpy(c, CHAIN, 64); c[64] = '0'; c[65] = '\0';
    mk_code(code, sizeof(code), "storage", OWNER, "5", c);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_expiry(void) {
    TEST("refuse: expiry leading zero, 0, sign, overflow, non-digit");
    char code[400];
    int ok = 1;
    mk_code(code, sizeof(code), "storage", OWNER, "0123", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "0", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "00", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "+5", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "-5", CHAIN);
    ok &= refused(code);
    /* UINT64_MAX + 1: 20 digits, strtoull ERANGE */
    mk_code(code, sizeof(code), "storage", OWNER, "18446744073709551616",
            CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "99999999999999999999",
            CHAIN);
    ok &= refused(code);
    /* 21+ digits */
    mk_code(code, sizeof(code), "storage", OWNER,
            "100000000000000000000000", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "12a", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "0x10", CHAIN);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_extra(void) {
    TEST("refuse: trailing ':' / extra field / too few fields");
    char code[400];
    int ok = 1;
    snprintf(code, sizeof(code), "nodus-consent-v1:storage:%s:5:%s:", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent-v1:storage:%s:5:%s:x", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent-v1:storage:%s:5", OWNER);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent-v1:storage:%s:%s", OWNER,
             CHAIN);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_space(void) {
    TEST("refuse: whitespace anywhere");
    char code[400];
    int ok = 1;
    snprintf(code, sizeof(code), " nodus-consent-v1:storage:%s:5:%s", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent-v1:storage:%s:5:%s ", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent-v1:storage:%s:5:%s\n", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent-v1:storage: %s:5:%s", OWNER,
             CHAIN);
    ok &= refused(code);
    snprintf(code, sizeof(code), "nodus-consent-v1:storage:%s:5 :%s", OWNER,
             CHAIN);
    ok &= refused(code);
    char o[129];
    memcpy(o, OWNER, sizeof(o));
    o[64] = ' ';
    mk_code(code, sizeof(code), "storage", o, "5", CHAIN);
    ok &= refused(code);
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_empty(void) {
    TEST("refuse: empty fields, empty code, prefix only");
    char code[400];
    int ok = 1;
    mk_code(code, sizeof(code), "", OWNER, "5", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", "", "5", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "", CHAIN);
    ok &= refused(code);
    mk_code(code, sizeof(code), "storage", OWNER, "5", "");
    ok &= refused(code);
    ok &= refused("");
    ok &= refused("nodus-consent-v1:");
    ok &= refused("nodus-consent-v1::::");
    if (ok) PASS(); else FAIL("accepted");
}

static void test_refuse_null(void) {
    TEST("refuse: NULL code / NULL out");
    nodus_consent_req_t r;
    char err[128] = "";
    char code[400];
    mk_code(code, sizeof(code), "storage", OWNER, "5", CHAIN);
    if (nodus_consent_req_parse(NULL, &r, err, sizeof(err)) == -1 &&
        err[0] != '\0' &&
        nodus_consent_req_parse(code, NULL, NULL, 0) == -1)
        PASS();
    else
        FAIL("accepted");
}

/* ── Config reader ────────────────────────────────────────────────── */

/* write text to a fresh /tmp file; path out; 0 ok */
static int tmp_write(char *path, size_t cap, const char *text) {
    snprintf(path, cap, "/tmp/test_consent_req_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    const size_t n = strlen(text);
    const ssize_t w = write(fd, text, n);
    close(fd);
    if (w < 0 || (size_t)w != n) { unlink(path); return -1; }
    return 0;
}

#ifdef NODUS_HAS_JSONC

/* rc of read_config over text; idp / port out */
static int cfg_rc(const char *text, char *idp, size_t cap, uint16_t *port,
                  char *err, size_t errcap) {
    char path[64];
    if (tmp_write(path, sizeof(path), text) != 0) return -2;
    const int rc = nodus_consent_req_read_config(path, idp, cap, port, err,
                                                 errcap);
    unlink(path);
    return rc;
}

static void test_cfg_both(void) {
    TEST("config: identity_path + tcp_port both read");
    char idp[256] = "", err[256] = "";
    uint16_t port = 4001;
    const int rc = cfg_rc("{ \"udp_port\": 4000, \"tcp_port\": 14001,\n"
                          "  \"identity_path\": \"/var/lib/nodus/id\" }\n",
                          idp, sizeof(idp), &port, err, sizeof(err));
    if (rc == 0 && strcmp(idp, "/var/lib/nodus/id") == 0 && port == 14001)
        PASS();
    else
        FAIL(err[0] ? err : "wrong values");
}

static void test_cfg_no_port(void) {
    TEST("config: no tcp_port leaves the port unchanged");
    char idp[256] = "", err[256] = "";
    uint16_t port = 4321;
    const int rc = cfg_rc("{\"identity_path\": \"/etc/nodus/identity\"}",
                          idp, sizeof(idp), &port, err, sizeof(err));
    if (rc == 0 && strcmp(idp, "/etc/nodus/identity") == 0 && port == 4321)
        PASS();
    else
        FAIL(err[0] ? err : "wrong values");
}

static void test_cfg_refusals(void) {
    TEST("config: refusals (identity_path, tcp_port, not JSON)");
    char idp[256], err[256];
    uint16_t port;
    int ok = 1;
    static const char *const bad[] = {
        "{\"tcp_port\": 4001}",                              /* no identity  */
        "{\"identity_path\": \"\"}",                         /* empty        */
        "{\"identity_path\": 7}",                            /* not a string */
        "{\"identity_path\": \"/x\", \"tcp_port\": 0}",
        "{\"identity_path\": \"/x\", \"tcp_port\": 70000}",
        "{\"identity_path\": \"/x\", \"tcp_port\": -1}",
        "{\"identity_path\": \"/x\", \"tcp_port\": \"4001\"}",
        "{\"identity_path\": \"/x\", \"tcp_port\": 4001.5}",
        "identity_path = /x",                                /* not JSON     */
        "[\"identity_path\", \"/x\"]",                       /* not object   */
        "",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        snprintf(idp, sizeof(idp), "untouched");
        port = 4001;
        err[0] = '\0';
        const int rc = cfg_rc(bad[i], idp, sizeof(idp), &port, err,
                              sizeof(err));
        if (rc != -1 || err[0] == '\0' || port != 4001 ||
            strcmp(idp, "untouched") != 0) {
            printf("[case %zu] ", i);
            ok = 0;
        }
    }
    if (ok) PASS(); else FAIL("accepted or touched the outputs");
}

static void test_cfg_too_long(void) {
    TEST("config: identity_path longer than cap is refused");
    char idp[8] = "", err[256] = "";
    uint16_t port = 4001;
    const int rc = cfg_rc("{\"identity_path\": \"/var/lib/nodus\"}",
                          idp, sizeof(idp), &port, err, sizeof(err));
    if (rc == -1 && err[0] != '\0') PASS(); else FAIL("accepted");
}

#else  /* !NODUS_HAS_JSONC */

static void test_cfg_no_jsonc(void) {
    TEST("config: without json-c the reader refuses (give -i)");
    char path[64], idp[256] = "", err[256] = "";
    uint16_t port = 4001;
    if (tmp_write(path, sizeof(path), "{\"identity_path\": \"/x\"}") != 0) {
        FAIL("mkstemp"); return;
    }
    const int rc = nodus_consent_req_read_config(path, idp, sizeof(idp),
                                                 &port, err, sizeof(err));
    unlink(path);
    if (rc == -1 && strstr(err, "give -i") != NULL) PASS();
    else FAIL("not refused");
}

#endif /* NODUS_HAS_JSONC */

static void test_cfg_missing_file(void) {
    TEST("config: missing file is refused");
    char path[64], idp[256] = "", err[256] = "";
    uint16_t port = 4001;
    /* a name mkstemp handed out, then removed: certainly absent */
    if (tmp_write(path, sizeof(path), "") != 0) { FAIL("mkstemp"); return; }
    unlink(path);
    if (nodus_consent_req_read_config(path, idp, sizeof(idp), &port, err,
                                      sizeof(err)) == -1 &&
        err[0] != '\0' && port == 4001)
        PASS();
    else
        FAIL("accepted");
}

/* ── Confirmation answer ──────────────────────────────────────────── */

static void test_answer(void) {
    TEST("answer: only y / yes (any case) proceed");
    int ok = 1;
    static const char *const yes[] = { "y", "Y", "yes", "YES", "Yes",
                                       "y\n", "yes\r\n" };
    static const char *const no[]  = { "", "\n", "n", "no", "ye", "yess",
                                       " y", "y ", "yes please", "1" };
    for (size_t i = 0; i < sizeof(yes) / sizeof(yes[0]); i++)
        ok &= nodus_consent_req_answer_yes(yes[i]) == 1;
    for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++)
        ok &= nodus_consent_req_answer_yes(no[i]) == 0;
    ok &= nodus_consent_req_answer_yes(NULL) == 0;
    if (ok) PASS(); else FAIL("wrong answer");
}

int main(void) {
    fill_hex(OWNER, 128, 3);
    fill_hex(CHAIN, 64, 11);

    printf("consent request code tests\n");
    test_valid_storage();
    test_valid_witness();
    test_valid_uint64_max();
    test_refuse_prefix();
    test_refuse_role();
    test_refuse_upper_hex();
    test_refuse_owner_len();
    test_refuse_chain_len();
    test_refuse_expiry();
    test_refuse_extra();
    test_refuse_space();
    test_refuse_empty();
    test_refuse_null();
#ifdef NODUS_HAS_JSONC
    test_cfg_both();
    test_cfg_no_port();
    test_cfg_refusals();
    test_cfg_too_long();
#else
    test_cfg_no_jsonc();
#endif
    test_cfg_missing_file();
    test_answer();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
