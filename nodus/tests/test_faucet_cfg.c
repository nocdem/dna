/**
 * test_faucet_cfg.c — the nodus-faucet configuration parser.
 *
 * WHAT IT PROVES: the operator's defaults (decision 2026-10-22-testnet-test-
 * tokens-faucet-dex.md: 100 000 NODUS = 10^13, 100 tUSDT = 10^8, 10 NODUS =
 * 10^9, fee ceiling 0.1 NODUS = 10^7) are what an unset key means; the file
 * is STRICT — an unknown key, a duplicate key, a malformed value, a missing
 * required key or an out-of-range value refuses the whole file.
 * ALSO: the key directory preparation (faucet_prepare_key_dir) succeeds and
 * fsyncs the directory AND its parent, and fails on a missing / non-directory
 * parent; the gas-price presence decoder (nodus_dnac_fee_info_decode_ex with a
 * flag) walks the result map structurally (nested values, repeated keys,
 * non-text keys, truncation).
 * WHAT IT REQUIRES: a default build; no environment, no network. The key-dir
 * cases use a mkdtemp directory under /tmp.
 * LEAVES BEHIND: nothing (the temp directory is removed).
 * HOW IT CAN LIE: it parses strings; it does not prove the service reads the
 * values it parsed (test_faucet_state covers the use of amounts and ceiling).
 * The fsync calls are checked for their result, not for actual durability
 * (a power loss cannot be simulated here).
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "faucet_cfg.h"
#include "nodus/nodus.h"

static int g_failures = 0;
#define CHECK(cond, what)                                                    \
    do {                                                                     \
        if (cond) printf("  ok    %s\n", what);                              \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

#define FP64  "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" "aa" \
              "aa" "aa" "aa" "aa"
#define CH32  "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" \
              "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb" \
              "bb" "bb" "bb" "bb" "bb" "bb" "bb" "bb"

#define MINIMAL                                   \
    "node_host = 127.0.0.1\n"                     \
    "node_port = 4001\n"                          \
    "node_fp = " FP64 "\n"                        \
    "chain_id = " CH32 "\n"                       \
    "key_dir = /var/lib/nodus-faucet/keys\n"      \
    "journal_path = /var/lib/nodus-faucet/j.db\n" \
    "token_id = " FP64 "\n"                       \
    "listen_port = 4010\n"

static int parse(const char *text, faucet_cfg_t *c) {
    char err[160];
    return faucet_cfg_parse(text, c, err, sizeof(err));
}

int main(void) {
    printf("test_faucet_cfg\n");
    faucet_cfg_t c;

    CHECK(parse(MINIMAL, &c) == 0, "C1 the minimal required file parses");
    CHECK(c.full_native == 10000000000000ULL, "C1 default full_native = 10^13 (100 000 NODUS)");
    CHECK(c.full_token == 100000000ULL, "C1 default full_token = 10^8 (100 tUSDT, 6 decimals)");
    CHECK(c.start_native == 1000000000ULL, "C1 default start_native = 10^9 (10 NODUS)");
    CHECK(c.fee_ceiling == 10000000ULL, "C1 default fee ceiling = 10^7 (0.1 NODUS)");
    CHECK(c.expiry_ahead == 90, "C1 default expiry margin = tip + 90");
    CHECK(c.listen_port == 4010 && c.node_port == 4001, "C1 ports parsed");
    CHECK(c.chain_id[0] == 0xbb && c.node_fp[63] == 0xaa, "C1 hex keys decoded");

    CHECK(parse(MINIMAL "fee_ceiling = 5000000\nqueue_cap = 8\n", &c) == 0 &&
          c.fee_ceiling == 5000000 && c.queue_cap == 8, "C2 optional keys override defaults");
    CHECK(parse(MINIMAL "# comment\n\n  poll_ms = 2000  \n", &c) == 0 && c.poll_ms == 2000,
          "C2 comments, blank lines and padding are fine");

    CHECK(parse(MINIMAL "bogus = 1\n", &c) != 0, "C3 an unknown key refuses the file");
    CHECK(parse(MINIMAL "listen_port = 4011\n", &c) != 0, "C3 a duplicate required key refuses");
    CHECK(parse(MINIMAL "queue_cap = 4\nqueue_cap = 5\n", &c) != 0, "C3 a duplicate optional key refuses");
    CHECK(parse("node_host = x\n", &c) != 0, "C4 a missing required key refuses");
    CHECK(parse(MINIMAL "fee_ceiling = 12abc\n", &c) != 0, "C5 a malformed number refuses");
    CHECK(parse(MINIMAL "fee_ceiling = -1\n", &c) != 0, "C5 a negative number refuses");
    CHECK(parse(MINIMAL "fee_ceiling = 0\n", &c) != 0, "C5 a zero fee ceiling refuses");
    CHECK(parse(MINIMAL "full_native = 18446744073709551615\n", &c) != 0,
          "C5 an amount that could overflow capacity arithmetic refuses");
    CHECK(parse(MINIMAL "expiry_ahead = 95\n", &c) != 0, "C6 expiry margin above 90 refuses (mempool admits tip + 100)");
    CHECK(parse(MINIMAL "expiry_ahead = 5\n", &c) != 0, "C6 expiry margin below 10 refuses");
    CHECK(parse(MINIMAL "storage_ceiling = 1000\n", &c) != 0, "C6 a storage ceiling below 1 MiB refuses");
    CHECK(parse(MINIMAL "queue_cap = 0\n", &c) != 0, "C6 queue_cap 0 refuses");
    CHECK(parse(MINIMAL "conn_cap = 1000\n", &c) != 0, "C6 conn_cap above 256 refuses");

    {
        char bad[2048];
        snprintf(bad, sizeof(bad), "%s", MINIMAL);
        char *p = strstr(bad, "chain_id = ") + 11;
        p[0] = 'B';                           /* uppercase hex */
        CHECK(parse(bad, &c) != 0, "C7 uppercase hex refuses");
        snprintf(bad, sizeof(bad), "%s", MINIMAL);
        p = strstr(bad, "chain_id = ") + 11;
        p[63] = '\n';                         /* short chain id */
        CHECK(parse(bad, &c) != 0, "C7 a short chain id refuses");
    }

    /* ── K: the key directory is made durable before anything uses it ── */
    {
        char root[64], kd[128], kd2[128], deep[160], fl[128];
        snprintf(root, sizeof(root), "/tmp/faucet_cfg_XXXXXX");
        if (!mkdtemp(root)) { printf("FATAL: mkdtemp\n"); return 2; }
        snprintf(kd, sizeof(kd), "%s/keys", root);
        struct stat sb;
        CHECK(faucet_prepare_key_dir(kd) == 0 && stat(kd, &sb) == 0 &&
              S_ISDIR(sb.st_mode) && (sb.st_mode & 0777) == 0700,
              "K1 creates the key directory 0700 and fsyncs it and its parent (success path)");
        CHECK(faucet_prepare_key_dir(kd) == 0, "K2 an existing key directory is accepted (parent fsynced again)");
        snprintf(kd2, sizeof(kd2), "%s/keys2/", root);
        CHECK(faucet_prepare_key_dir(kd2) == 0, "K3 a trailing slash still resolves the parent");
        snprintf(deep, sizeof(deep), "%s/missing/keys", root);
        errno = 0;
        CHECK(faucet_prepare_key_dir(deep) != 0 && errno == ENOENT && stat(deep, &sb) != 0,
              "K4 a missing PARENT fails (nothing is created, the caller refuses to continue)");
        snprintf(fl, sizeof(fl), "%s/afile", root);
        FILE *f = fopen(fl, "w");
        if (f) fclose(f);
        snprintf(deep, sizeof(deep), "%s/afile/keys", root);
        CHECK(faucet_prepare_key_dir(deep) != 0, "K5 a parent that is not a directory fails");
        CHECK(faucet_prepare_key_dir("") != 0 && faucet_prepare_key_dir(NULL) != 0,
              "K6 an empty / NULL path fails");
        CHECK(faucet_fsync_dir(root) == 0 && faucet_fsync_dir(fl) != 0,
              "K7 faucet_fsync_dir: a directory yes, a file no");
        rmdir(kd);
        snprintf(kd2, sizeof(kd2), "%s/keys2", root);
        rmdir(kd2);
        unlink(fl);
        rmdir(root);
    }

    /* ── G: the gas-price presence decoder walks the map structurally ── */
    {
        /* {"r": {"base_fee": {"gas_price": 0}, "gas_price": 7}} */
        static const uint8_t nested[] = {
            0xA1, 0x61, 'r', 0xA2,
            0x68, 'b','a','s','e','_','f','e','e', 0xA1,
                  0x69, 'g','a','s','_','p','r','i','c','e', 0x00,
            0x69, 'g','a','s','_','p','r','i','c','e', 0x07 };
        nodus_dnac_fee_info_t fi;
        bool has = false;
        CHECK(nodus_dnac_fee_info_decode_ex(nested, sizeof(nested), &fi, &has) == 0 &&
              has && fi.gas_price == 7,
              "G1 a nested {\"gas_price\":0} inside base_fee is NOT the top-level price: present, 7");
        /* {"r": {"base_fee": {"gas_price": 0}}} — the only gas_price is nested */
        static const uint8_t only_nested[] = {
            0xA1, 0x61, 'r', 0xA1,
            0x68, 'b','a','s','e','_','f','e','e', 0xA1,
                  0x69, 'g','a','s','_','p','r','i','c','e', 0x00 };
        has = true;
        CHECK(nodus_dnac_fee_info_decode_ex(only_nested, sizeof(only_nested), &fi, &has) == 0 &&
              !has && fi.gas_price == 0,
              "G2 a gas_price that exists only inside a nested value is NOT reported (never a present 0)");
        /* {"r": {"gas_price": 0}} — a real top-level 0 is present */
        static const uint8_t zero[] = {
            0xA1, 0x61, 'r', 0xA1, 0x69, 'g','a','s','_','p','r','i','c','e', 0x00 };
        CHECK(nodus_dnac_fee_info_decode_ex(zero, sizeof(zero), &fi, &has) == 0 &&
              has && fi.gas_price == 0, "G3 a top-level price 0 is present (rule off)");
        /* {"r": {"gas_price": 1, "gas_price": 2}} — repeated key */
        static const uint8_t dup[] = {
            0xA1, 0x61, 'r', 0xA2, 0x69, 'g','a','s','_','p','r','i','c','e', 0x01,
                                   0x69, 'g','a','s','_','p','r','i','c','e', 0x02 };
        CHECK(nodus_dnac_fee_info_decode_ex(dup, sizeof(dup), &fi, &has) != 0 && !has,
              "G4 a repeated gas_price refuses the reply");
        /* {"r": {1: 2, "gas_price": 3}} — a non-text key */
        static const uint8_t intkey[] = {
            0xA1, 0x61, 'r', 0xA2, 0x01, 0x02, 0x69, 'g','a','s','_','p','r','i','c','e', 0x03 };
        CHECK(nodus_dnac_fee_info_decode_ex(intkey, sizeof(intkey), &fi, &has) != 0 && !has,
              "G5 a non-text key refuses the reply");
        /* declared two entries, the second value is missing */
        static const uint8_t trunc[] = {
            0xA1, 0x61, 'r', 0xA2, 0x69, 'g','a','s','_','p','r','i','c','e', 0x03,
                                   0x67, 'm','i','n','_','f','e','e' };
        CHECK(nodus_dnac_fee_info_decode_ex(trunc, sizeof(trunc), &fi, &has) != 0 && !has,
              "G6 END where a declared value is missing refuses the reply");
        /* the legacy (NULL flag) path is unchanged: it still returns the fields */
        CHECK(nodus_dnac_fee_info_decode_ex(zero, sizeof(zero), &fi, NULL) == 0 &&
              fi.gas_price == 0, "G7 the legacy path (no flag) still decodes");
    }

    printf("%s (%d failure(s))\n", g_failures ? "FAILED" : "PASSED", g_failures);
    return g_failures ? 1 : 0;
}
