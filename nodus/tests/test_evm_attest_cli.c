/**
 * Nodus — the executable `nodus-cli evm attest` (offline signing of the
 * ML-DSA-87 companion library's attestation), driven as a child process.
 *
 * Design: docs/plans/2026-10-22-mldsa87-companion-library-design.md rev 2
 * §1.6, §5 "CLI"; decisions docs/plans/decisions/2026-10-21-mldsa87-evm-
 * precompile.md (item 2: context "nodus.evm.attest.v1", 19 bytes, no
 * fallback; "Companion library: the actionType"). The module itself is
 * pinned by test_evm_attest.c / test_evm_abi.c; this test pins what only
 * the executable does: argument handling, the offline dispatch in main(),
 * the identity load from --keys, the printed fields and the exit status.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. Offline, `evm attest "Approve(uint256, address)" <contract> 7
 *     1800000000 1000 <address> --keys <dir> --chain-id <chain>` exits 0 and
 *     prints action / actionType / chain / contract / nonce / expiry /
 *     signer / message / pubkey / signature, where: action is the canonical
 *     text (space removed); actionType equals the fixture's static case;
 *     chain, contract, nonce and expiry echo the inputs; signer is
 *     SHA3-512(pk)[0..32] computed here; pubkey is the identity's key;
 *     message equals nodus_evm_attest_build's output for the same inputs;
 *     the signature is 4627 bytes, verifies under the 19-byte context
 *     "nodus.evm.attest.v1" and does NOT verify under the empty context.
 *  2. Each refusal exits non-zero, writes a non-empty message to stderr and
 *     NOTHING to stdout: a 10-parameter action, a name starting with a
 *     digit, `bytes+1`, an expiry of 2^64, a malformed --chain-id, and
 *     neither --chain-id nor -s.
 *
 * ── REQUIRES ────────────────────────────────────────────────────────────
 * The EVM build (the executable is the EVM-enabled nodus-cli) and that
 * built nodus-cli: CMake passes its path (NODUS_CLI_PATH, the target file
 * of nodus-cli) and makes this test depend on it. The fixture path is
 * compiled in (NODUS_ATTEST_FIXTURE); the file must exist in the source
 * tree. No environment, no network, no shell: the child is started with
 * fork/execv and an argv array.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 * Nothing. The temporary identity directory (mkdtemp under $TMPDIR or
 * /tmp) is removed recursively on every path, including the files
 * nodus_identity_load adds to it.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Signing is hedged: the signature BYTES differ per run, so only
 *    outcomes are asserted (length, accept / reject) — never bytes.
 *  - The refusal checks assert "non-zero exit + stderr text + empty
 *    stdout", not WHICH reason: a refusal that fires for a different
 *    reason than the one intended (e.g. a mistyped contract) would still
 *    pass. The positive run proves the same argument shape is otherwise
 *    accepted, and each refusal changes exactly one input from it.
 *  - If NODUS_CLI_PATH names a stale binary the test checks that stale
 *    binary; the add_dependencies in CMake is what prevents it.
 *  - The fixture is read for its static case only; if that case were
 *    missing the test fails rather than passing on defaults.
 */

#define _XOPEN_SOURCE 700              /* nftw, mkdtemp */
#define _DEFAULT_SOURCE

#include "client/nodus_evm_abi.h"
#include "client/nodus_evm_attest.h"

#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <errno.h>
#include <ftw.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NODUS_ATTEST_FIXTURE
#error "NODUS_ATTEST_FIXTURE must name tools/evm/contracts/test/fixtures/attest_v1.txt"
#endif
#ifndef NODUS_CLI_PATH
#error "NODUS_CLI_PATH must name the built nodus-cli"
#endif

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* ── the fixture's static case ───────────────────────────────────────── */

static char fx_action[256], fx_actiontype[80], fx_chain[80], fx_contract[80];
static char fx_args[1024];

/* @return 0 when the static case supplied all five fields */
static int fx_load(void) {
    FILE *f = fopen(NODUS_ATTEST_FIXTURE, "r");
    if (!f) return -1;
    char *line = malloc(1 << 18);
    if (!line) { fclose(f); return -1; }
    int in_static = 0, got = 0;
    while (fgets(line, 1 << 18, f)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = '\0';
        if (!l) { if (in_static) break; continue; }
        if (line[0] == '#') continue;
        char *sp = strchr(line, ' ');
        const char *val = sp ? sp + 1 : "";
        if (sp) *sp = '\0';
        if (!strcmp(line, "case")) { in_static = !strcmp(val, "static"); continue; }
        if (!in_static) continue;
        if (!strcmp(line, "action")) { snprintf(fx_action, sizeof(fx_action), "%s", val); got |= 1; }
        else if (!strcmp(line, "actiontype")) { snprintf(fx_actiontype, sizeof(fx_actiontype), "%s", val); got |= 2; }
        else if (!strcmp(line, "chain")) { snprintf(fx_chain, sizeof(fx_chain), "%s", val); got |= 4; }
        else if (!strcmp(line, "contract")) { snprintf(fx_contract, sizeof(fx_contract), "%s", val); got |= 8; }
        else if (!strcmp(line, "args")) { snprintf(fx_args, sizeof(fx_args), "%s", val); got |= 16; }
    }
    free(line);
    fclose(f);
    return got == 31 ? 0 : -1;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

static void hexs(const uint8_t *b, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = hx[b[i] >> 4];
        out[2 * i + 1] = hx[b[i] & 15];
    }
    out[2 * n] = '\0';
}

static int rm_cb(const char *path, const struct stat *sb, int type,
                 struct FTW *ftw) {
    (void)sb; (void)type; (void)ftw;
    return remove(path);
}

static void rm_tree(const char *dir) {
    (void)nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

typedef struct {
    char  *out, *err;
    size_t out_len, err_len;
    int    status;                 /* exit code, or -1 (signal / failure) */
} run_t;

static void run_free(run_t *r) { free(r->out); free(r->err); }

/* append `n` bytes to a NUL-terminated heap buffer. @return 0 / -1 */
static int buf_add(char **b, size_t *len, const char *data, size_t n) {
    char *nb = realloc(*b, *len + n + 1);
    if (!nb) return -1;
    memcpy(nb + *len, data, n);
    *len += n;
    nb[*len] = '\0';
    *b = nb;
    return 0;
}

/* Run NODUS_CLI_PATH with argv (NULL-terminated, argv[0] set here); stdout
 * and stderr captured separately; stdin is /dev/null. @return 0 / -1 */
static int run_cli(char *const *args, run_t *r) {
    memset(r, 0, sizeof(*r));
    r->status = -1;
    r->out = calloc(1, 1);
    r->err = calloc(1, 1);
    if (!r->out || !r->err) return -1;

    int po[2], pe[2];
    if (pipe(po) != 0) return -1;
    if (pipe(pe) != 0) { close(po[0]); close(po[1]); return -1; }
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        return -1;
    }
    if (pid == 0) {
        if (dup2(po[1], 1) < 0 || dup2(pe[1], 2) < 0) _exit(127);
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        if (!freopen("/dev/null", "r", stdin)) _exit(127);
        execv(NODUS_CLI_PATH, args);
        _exit(127);
    }
    close(po[1]);
    close(pe[1]);
    struct pollfd p[2] = { { po[0], POLLIN, 0 }, { pe[0], POLLIN, 0 } };
    int open_n = 2, rc = 0;
    char tmp[65536];
    while (open_n > 0) {
        if (poll(p, 2, -1) < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }
        for (int i = 0; i < 2; i++) {
            if (p[i].fd < 0 || !(p[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            ssize_t n = read(p[i].fd, tmp, sizeof(tmp));
            if (n > 0) {
                if (i == 0 ? buf_add(&r->out, &r->out_len, tmp, (size_t)n)
                           : buf_add(&r->err, &r->err_len, tmp, (size_t)n)) {
                    rc = -1;
                }
            } else if (n == 0 || errno != EINTR) {
                close(p[i].fd);
                p[i].fd = -1;
                open_n--;
            }
        }
        if (rc) break;
    }
    for (int i = 0; i < 2; i++) if (p[i].fd >= 0) close(p[i].fd);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (rc == 0 && WIFEXITED(st)) r->status = WEXITSTATUS(st);
    return rc;
}

/* the value of the line "<key> <value>" in `text`, copied to a heap string;
 * NULL when absent. The key must start a line. */
static char *field(const char *text, const char *key) {
    size_t kl = strlen(key);
    const char *p = text;
    while (p && *p) {
        if (!strncmp(p, key, kl) && p[kl] == ' ') {
            const char *v = p + kl + 1;
            const char *e = strchr(v, '\n');
            size_t n = e ? (size_t)(e - v) : strlen(v);
            char *s = malloc(n + 1);
            if (!s) return NULL;
            memcpy(s, v, n);
            s[n] = '\0';
            return s;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return NULL;
}

static int hex_eq(const char *a, const char *b) { return a && b && !strcmp(a, b); }

/* ── the test ────────────────────────────────────────────────────────── */

static char keydir[1024];
static nodus_identity_t id;

#define FIELDS 10
static const char *const FNAME[FIELDS] = {
    "action", "actionType", "chain", "contract", "nonce", "expiry", "signer",
    "message", "pubkey", "signature"
};

static void test_positive(void) {
    TEST("evm attest offline: exit 0, ten fields, all consistent");
    char *vals[FIELDS] = { 0 };
    uint8_t *sig = NULL, *msg_expected_buf = NULL;
    run_t r;
    memset(&r, 0, sizeof(r));
    nodus_evm_attest_msg_t m;
    memset(&m, 0, sizeof(m));
    const char *why = NULL;

    char fx_args_copy[1024];
    snprintf(fx_args_copy, sizeof(fx_args_copy), "%s", fx_args);
    char *a1 = strtok(fx_args_copy, " ");
    char *a2 = strtok(NULL, " ");
    if (!a1 || !a2) { FAIL("fixture args"); return; }

    char *args[] = { (char *)"nodus-cli", (char *)"evm", (char *)"attest",
                     (char *)"Approve(uint256, address)", fx_contract,
                     (char *)"7", (char *)"1800000000", a1, a2,
                     (char *)"--keys", keydir, (char *)"--chain-id",
                     fx_chain, NULL };
    if (run_cli(args, &r) != 0) { FAIL("cannot run nodus-cli"); goto out; }
    if (r.status != 0) { why = "non-zero exit"; goto bad; }
    for (int i = 0; i < FIELDS; i++) {
        vals[i] = field(r.out, FNAME[i]);
        if (!vals[i]) { why = FNAME[i]; goto bad; }
    }

    uint8_t pkh[64];
    char want[65], pk_hex[NODUS_PK_BYTES * 2 + 1];
    if (qgp_sha3_512(id.pk.bytes, NODUS_PK_BYTES, pkh) != 0) {
        why = "sha3";
        goto bad;
    }
    hexs(pkh, 32, want);                       /* SHA3-512(pk)[0..32] */
    hexs(id.pk.bytes, NODUS_PK_BYTES, pk_hex);

    if (strcmp(vals[0], "Approve(uint256,address)") != 0 ||
        strcmp(vals[0], fx_action) != 0) { why = "action not canonical"; goto bad; }
    if (!hex_eq(vals[1], fx_actiontype)) { why = "actionType"; goto bad; }
    if (!hex_eq(vals[2], fx_chain)) { why = "chain"; goto bad; }
    if (!hex_eq(vals[3], fx_contract)) { why = "contract"; goto bad; }
    if (strcmp(vals[4], "7") != 0) { why = "nonce"; goto bad; }
    if (strcmp(vals[5], "1800000000") != 0) { why = "expiry"; goto bad; }
    if (!hex_eq(vals[6], want)) { why = "signer != SHA3-512(pk)[0..32]"; goto bad; }
    if (!hex_eq(vals[8], pk_hex)) { why = "pubkey != identity pk"; goto bad; }

    /* message == the module's build for the same inputs */
    uint8_t chain[32], contract[32], signer[32];
    size_t got = 0;
    if (nodus_evm_hex_bytes(fx_chain, chain, 32, &got) != 0 || got != 32 ||
        nodus_evm_hex_bytes(fx_contract, contract, 32, &got) != 0 || got != 32 ||
        nodus_evm_hex_bytes(vals[6], signer, 32, &got) != 0 || got != 32) {
        why = "hex parse";
        goto bad;
    }
    char *bv[2] = { a1, a2 };
    char err[256] = "";
    if (nodus_evm_attest_build("Approve(uint256,address)", chain, contract,
                               "7", "1800000000", signer, bv, 2, &m, err,
                               sizeof(err)) != 0) {
        why = "module build refused";
        goto bad;
    }
    msg_expected_buf = malloc(m.message_len * 2 + 1);
    if (!msg_expected_buf) { why = "oom"; goto bad; }
    hexs(m.message, m.message_len, (char *)msg_expected_buf);
    if (!hex_eq(vals[7], (char *)msg_expected_buf)) {
        why = "message differs from nodus_evm_attest_build";
        goto bad;
    }

    /* the signature */
    if (strlen(vals[9]) != 2 * NODUS_EVM_ATTEST_SIG_LEN) {
        why = "signature is not 4627 bytes";
        goto bad;
    }
    sig = malloc(NODUS_EVM_ATTEST_SIG_LEN);
    if (!sig) { why = "oom"; goto bad; }
    if (nodus_evm_hex_bytes(vals[9], sig, NODUS_EVM_ATTEST_SIG_LEN, &got) != 0 ||
        got != NODUS_EVM_ATTEST_SIG_LEN) {
        why = "signature hex";
        goto bad;
    }
    if (strlen(NODUS_EVM_ATTEST_CTX) != 19u) { why = "context constant"; goto bad; }
    if (qgp_dsa87_verify_ctx(sig, NODUS_EVM_ATTEST_SIG_LEN, m.message,
                             m.message_len,
                             (const uint8_t *)"nodus.evm.attest.v1", 19,
                             id.pk.bytes) != 0) {
        why = "signature does not verify under nodus.evm.attest.v1";
        goto bad;
    }
    if (qgp_dsa87_verify_ctx(sig, NODUS_EVM_ATTEST_SIG_LEN, m.message,
                             m.message_len, NULL, 0, id.pk.bytes) == 0) {
        why = "signature verifies under the EMPTY context";
        goto bad;
    }
    PASS();
    goto out;
bad:
    FAIL(why);
out:
    for (int i = 0; i < FIELDS; i++) free(vals[i]);
    free(sig);
    free(msg_expected_buf);
    nodus_evm_attest_msg_free(&m);
    run_free(&r);
}

/* one refusal: `tail` replaces the positional/option arguments after
 * "evm attest"; the run must exit non-zero, speak on stderr only. */
static void refusal(const char *label, char *const *args) {
    TEST(label);
    run_t r;
    if (run_cli(args, &r) != 0) { FAIL("cannot run nodus-cli"); run_free(&r); return; }
    if (r.status == 0 || r.status == 127 || r.status < 0)
        FAIL(r.status == 0 ? "exit status 0" : "did not run / died on a signal");
    else if (r.err_len == 0)
        FAIL("empty stderr");
    else if (r.out_len != 0)
        FAIL("something on stdout");
    else
        PASS();
    run_free(&r);
}

static void test_refusals(void) {
    char *ten[] = { (char *)"nodus-cli", (char *)"evm", (char *)"attest",
        (char *)"F(uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8)",
        fx_contract, (char *)"7", (char *)"1800000000",
        (char *)"1", (char *)"1", (char *)"1", (char *)"1", (char *)"1",
        (char *)"1", (char *)"1", (char *)"1", (char *)"1", (char *)"1",
        (char *)"--keys", keydir, (char *)"--chain-id", fx_chain, NULL };
    refusal("refused: a 10-parameter action", ten);

    char *digit[] = { (char *)"nodus-cli", (char *)"evm", (char *)"attest",
        (char *)"1Approve(uint256)", fx_contract, (char *)"7",
        (char *)"1800000000", (char *)"1000", (char *)"--keys", keydir,
        (char *)"--chain-id", fx_chain, NULL };
    refusal("refused: a name starting with a digit", digit);

    char *plus[] = { (char *)"nodus-cli", (char *)"evm", (char *)"attest",
        (char *)"Approve(bytes+1)", fx_contract, (char *)"7",
        (char *)"1800000000", (char *)"1", (char *)"--keys", keydir,
        (char *)"--chain-id", fx_chain, NULL };
    refusal("refused: Approve(bytes+1)", plus);

    char *exp[] = { (char *)"nodus-cli", (char *)"evm", (char *)"attest",
        (char *)"Approve(uint256)", fx_contract, (char *)"7",
        (char *)"18446744073709551616", (char *)"1000", (char *)"--keys",
        keydir, (char *)"--chain-id", fx_chain, NULL };
    refusal("refused: expiry 18446744073709551616 (2^64)", exp);

    char *badchain[] = { (char *)"nodus-cli", (char *)"evm", (char *)"attest",
        (char *)"Approve(uint256)", fx_contract, (char *)"7",
        (char *)"1800000000", (char *)"1000", (char *)"--keys", keydir,
        (char *)"--chain-id", (char *)"not-a-chain-id", NULL };
    refusal("refused: malformed --chain-id", badchain);

    char *nochain[] = { (char *)"nodus-cli", (char *)"evm", (char *)"attest",
        (char *)"Approve(uint256)", fx_contract, (char *)"7",
        (char *)"1800000000", (char *)"1000", (char *)"--keys", keydir, NULL };
    refusal("refused: neither --chain-id nor -s", nochain);
}

int main(void) {
    printf("nodus-cli evm attest (executable)\n");
    if (fx_load() != 0) {
        printf("  FAIL: cannot read the fixture's static case\n");
        return 1;
    }

    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    int n = snprintf(keydir, sizeof(keydir), "%s/nodus_attest_cli_XXXXXX", tmp);
    if (n < 0 || (size_t)n >= sizeof(keydir) || !mkdtemp(keydir)) {
        printf("  FAIL: mkdtemp\n");
        return 1;
    }

    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x41 + i);
    int ok = nodus_identity_from_seed(seed, &id) == 0 &&
             nodus_identity_save(&id, keydir) == 0;
    if (!ok) {
        printf("  FAIL: identity from seed / save\n");
        rm_tree(keydir);
        return 1;
    }

    test_positive();
    test_refusals();

    nodus_identity_clear(&id);
    rm_tree(keydir);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
