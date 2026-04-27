/*
 * test_cli_send_bench.c — error-path contract for `dna send --bench`.
 *
 * Phase 0 prerequisite for the upcoming dna-bench tool. The bench tool
 * fork/execs `dna-connect-cli dna send <fp> <amount> <memo> --bench`
 * per wallet and parses one JSON line per child. This test pins the
 * error-path output contract: when --bench is set and the CLI rejects
 * the request locally (e.g. invalid amount), stdout must carry a
 * single-line JSON object with an "error" field, not a human-readable
 * stderr message.
 *
 * Success-path coverage is intentionally left manual — a real success
 * requires an unlocked identity, a funded wallet, and a live cluster
 * connection, none of which the messenger test infra mocks. The error
 * path is deterministic (amount=0 fails in cli_dna_chain.c:198-201
 * before any network or identity work) and exercises the same
 * bench-mode output plumbing as success.
 *
 * Skip semantics: returns 77 (CTest SKIP_RETURN_CODE) if the
 * dna-connect-cli binary is not built. The CMake test registration
 * sets SKIP_RETURN_CODE=77 to honor this.
 */

#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUF_CAP   8192
#define EXIT_SKIP 77

/* fork+exec `cli` with argv. Captures child stdout into out (NUL-term).
 * Stderr is discarded to keep ctest output clean. Returns child's
 * exit status, or -1 on infrastructure error. */
static int run_cli_capture_stdout(const char *cli, char *const argv[],
                                  char *out, size_t n) {
    int pfd[2];
    if (pipe(pfd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }

    if (pid == 0) {
        /* Child. */
        close(pfd[0]);
        dup2(pfd[1], STDOUT_FILENO);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
        close(pfd[1]);
        execv(cli, argv);
        _exit(127);
    }

    /* Parent. */
    close(pfd[1]);
    size_t got = 0;
    while (got + 1 < n) {
        ssize_t r = read(pfd[0], out + got, n - got - 1);
        if (r <= 0) break;
        got += (size_t)r;
    }
    out[got] = '\0';
    close(pfd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

/* Resolve the dna-connect-cli binary location. Honors $DNA_CONNECT_CLI
 * env override (CI may set it to an out-of-tree build). */
static const char *resolve_cli(void) {
    const char *env = getenv("DNA_CONNECT_CLI");
    if (env && *env) return env;
    return "/opt/dna/messenger/build/cli/dna-connect-cli";
}

/* Test: --bench + amount=0 must emit a single-line JSON error on
 * stdout, with non-zero exit. */
static void test_bench_flag_emits_json_error_on_invalid_amount(void) {
    const char *cli = resolve_cli();
    if (access(cli, X_OK) != 0) {
        fprintf(stderr, "SKIP: dna-connect-cli not built at %s\n", cli);
        exit(EXIT_SKIP);
    }

    /* 129 hex chars — passes length checks; never resolved because
     * the amount check at cli_dna_chain.c:198-201 fires first. */
    static char fp[130];
    memset(fp, 'a', 129);
    fp[129] = '\0';

    char *argv[] = {
        (char *)cli,
        "dna",
        "send",
        fp,
        "0",        /* invalid — strtoull(...)==0 → reject */
        "memo",
        "--bench",
        NULL
    };

    char buf[BUF_CAP] = {0};
    int rc = run_cli_capture_stdout(cli, argv, buf, sizeof(buf));

    /* Contract: bench mode + local rejection = a single-line JSON object
     * present on stdout, exit != 0. Note: engine init prints noise to
     * stdout before the JSON line lands; the bench parent (and this
     * test) parse via the LAST `{`. */
    assert(rc != 0 && "expected non-zero exit on invalid amount");

    char *json = strrchr(buf, '{');
    assert(json != NULL && "stdout must contain a JSON object");
    assert(strstr(json, "\"error\"") != NULL
           && "JSON line must contain \"error\" key");
    assert(strstr(json, "\"invalid_amount\"") != NULL
           && "error code must be \"invalid_amount\" for amount=0");

    /* JSON line is the trailing line: from json to end is exactly
     * '{...}\n' (one '\n', at the end). */
    char *nl = strchr(json, '\n');
    assert(nl != NULL && "JSON line must end with newline");
    assert(*(nl + 1) == '\0'
           && "JSON line must be the final line of stdout");

    printf("PASS test_bench_flag_emits_json_error_on_invalid_amount\n");
}

int main(void) {
    test_bench_flag_emits_json_error_on_invalid_amount();
    return 0;
}
