/* Native parity vector for the NODUS send module (web wallet package (c3);
 * design docs/plans/2026-09-25-web-wallet-nodus-send-design.md §2, test
 * plan item 2).
 *
 * Builds ONE CORE SPEND envelope offline with the SAME function the browser
 * module runs (nsw_offline_build in nodus-send-wasm.c, compiled here with
 * -DNODUS_SEND_OFFLINE_ONLY -DNODUS_SEND_TEST_FIXED_RANDOM), from explicit
 * inputs: a captured coin list, the tip, the gas price and the chain id a
 * node reported, the sender's 32-byte ML-DSA-87 seed, the output seeds and
 * the signature randomness. It opens no socket and reads no clock.
 *
 * Usage (every value as the wallet would pass it; hex lowercase):
 *   nodus-send-native-vector --seed <64hex> --chain <64hex> --tip <dec>
 *     --gas <dec> --to <128hex> --amount <dec> --expiry <dec>
 *     --coin <128hex>:<dec> [--coin ...] --out-seeds <hex, 32 B per output>
 *     --sign-random <hex, the bytes qgp_platform_random returns in order>
 *
 * Output (stdout), one `key=value` per line, in this order:
 *   envelope, wire_id, intent_id, chain_id, recipient, amount, fee, change,
 *   expiry, then one `input=` per input (ascending, as on the wire).
 * Exit 0 on success; 1 with one line on stderr otherwise.
 *
 * What the ORCHESTRATOR compares:
 *   - against the TEST wasm build fed the same inputs: every line equal;
 *   - against the shipped wasm (hedged signature): intent_id and every
 *     decoded field equal, wire_id and envelope different;
 *   - against `nodus-cli v2-envelope spend --dry-run`: intent_id only if
 *     the CLI can be given the same coin list, tip and output seeds (its
 *     output seeds are drawn from the CSPRNG — nodus-cli.c cli_rand).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* nodus-send-wasm.c entry points this program calls (that file has no
 * header: see its include block). */
uint8_t *nsw_seed_buf(void);
uint8_t *nsw_out_seed_buf(void);
int nsw_out_seed_load(int len);
uint8_t *nsw_test_random_buf(void);
int nsw_test_random_load(int len);
void nsw_req_reset(void);
int nsw_req_add_coin(const char *nullifier_hex, const char *amount_dec);
int nsw_offline_build(const char *chain_hex, const char *tip_dec,
                      const char *gas_dec, const char *to_hex,
                      const char *amount_dec, const char *expiry_dec);
const char *nsw_error(void);
const uint8_t *nsw_built_env(void);
int nsw_built_env_len(void);
const char *nsw_built_intent(void);
const char *nsw_built_wire(void);
const char *nsw_built_chain(void);
const char *nsw_built_recipient(void);
const char *nsw_built_amount(void);
const char *nsw_built_fee(void);
const char *nsw_built_change(void);
const char *nsw_built_expiry(void);
int nsw_built_n_in(void);
const char *nsw_built_in(int i);

/* This program's only output channels are its stdout lines and one stderr
 * line on failure (the build's QGP_LOG_* calls go through
 * nodus/src/nodus_log_shim.c). */
static int fail(const char *what) {
    fputs("nodus-send-native-vector: ", stderr);
    fputs(what, stderr);
    fputc('\n', stderr);
    return 1;
}

static void line(const char *key, const char *value) {
    fputs(key, stdout);
    fputc('=', stdout);
    fputs(value, stdout);
    fputc('\n', stdout);
}

/* Lowercase hex, even length, at most `cap` bytes, into `out`. */
static int unhex(const char *s, uint8_t *out, size_t cap, size_t *len_out) {
    size_t n = strlen(s);
    if (n % 2 != 0 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = s[2 * i + (size_t)j];
            int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
            if (d < 0) return -1;
            v = v << 4 | d;
        }
        out[i] = (uint8_t)v;
    }
    *len_out = n / 2;
    return 0;
}

int main(int argc, char **argv) {
    const char *seed = NULL, *chain = NULL, *tip = NULL, *gas = NULL,
               *to = NULL, *amount = NULL, *expiry = NULL,
               *out_seeds = NULL, *sign_random = NULL;
    nsw_req_reset();
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) return fail("every option takes a value");
        i++;
        if      (!strcmp(a, "--seed"))        seed = v;
        else if (!strcmp(a, "--chain"))       chain = v;
        else if (!strcmp(a, "--tip"))         tip = v;
        else if (!strcmp(a, "--gas"))         gas = v;
        else if (!strcmp(a, "--to"))          to = v;
        else if (!strcmp(a, "--amount"))      amount = v;
        else if (!strcmp(a, "--expiry"))      expiry = v;
        else if (!strcmp(a, "--out-seeds"))   out_seeds = v;
        else if (!strcmp(a, "--sign-random")) sign_random = v;
        else if (!strcmp(a, "--coin")) {
            char nul[129];
            const char *colon = strchr(v, ':');
            if (!colon || colon - v != 128) return fail("--coin is <128hex>:<amount>");
            memcpy(nul, v, 128);
            nul[128] = '\0';
            if (nsw_req_add_coin(nul, colon + 1) != 0) return fail(nsw_error());
        } else {
            return fail("unknown option (see the usage in nodus-send-native-vector.c)");
        }
    }
    if (!seed || !chain || !tip || !gas || !to || !amount || !expiry ||
        !out_seeds || !sign_random)
        return fail("--seed --chain --tip --gas --to --amount --expiry "
                    "--out-seeds --sign-random are all required");

    size_t n = 0;
    if (unhex(seed, nsw_seed_buf(), 32, &n) != 0 || n != 32)
        return fail("--seed is 32 bytes of lowercase hex");
    if (unhex(out_seeds, nsw_out_seed_buf(), 96, &n) != 0 ||
        nsw_out_seed_load((int)n) != 0)
        return fail("--out-seeds is 32, 64 or 96 bytes of lowercase hex");
    if (unhex(sign_random, nsw_test_random_buf(), 4096, &n) != 0 ||
        nsw_test_random_load((int)n) != 0)
        return fail("--sign-random is at most 4096 bytes of lowercase hex");

    if (nsw_offline_build(chain, tip, gas, to, amount, expiry) != 0)
        return fail(nsw_error());

    const int env_len = nsw_built_env_len();
    char *env_hex = malloc((size_t)env_len * 2 + 1);
    if (!env_hex) return fail("out of memory");
    static const char digits[] = "0123456789abcdef";
    const uint8_t *env = nsw_built_env();
    for (int i = 0; i < env_len; i++) {
        env_hex[2 * i]     = digits[env[i] >> 4];
        env_hex[2 * i + 1] = digits[env[i] & 15];
    }
    env_hex[2 * env_len] = '\0';
    line("envelope", env_hex);
    free(env_hex);
    line("wire_id", nsw_built_wire());
    line("intent_id", nsw_built_intent());
    line("chain_id", nsw_built_chain());
    line("recipient", nsw_built_recipient());
    line("amount", nsw_built_amount());
    line("fee", nsw_built_fee());
    line("change", nsw_built_change());
    line("expiry", nsw_built_expiry());
    for (int i = 0; i < nsw_built_n_in(); i++) line("input", nsw_built_in(i));
    return 0;
}
