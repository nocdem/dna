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
 * GENESIS CLAIM (0.1.26) — two more modes, chosen by the FIRST argument:
 *
 *   nodus-send-native-vector claim-manifest --base <manifest hex>
 *     --seed <64hex> --self-leaf <srcid hex>:<amount>
 *     [--leaf <srcid hex>:<128hex dest>:<amount> ...]
 *   Makes a SYNTHETIC manifest for the claim parity: the base manifest
 *   (e.g. the testnet's) decoded with the shared codec, its snapshot_root,
 *   leaf_count and total_claimable replaced by those of the given leaves
 *   (the --self-leaf's destination = SHA3-512 of the --seed's ML-DSA-87
 *   public key), re-encoded (dna_gman_encode). Output: manifest=,
 *   manifest_hash=, then one `leaf=<srcid>:<dest>:<amount>` per leaf in
 *   canonical order. No chain ever committed it; it only gives the parity
 *   a tree this seed can claim from.
 *
 *   nodus-send-native-vector claim --seed <64hex> --chain <64hex>
 *     --manifest <hex> --manifest-hash <128hex>
 *     --leaf <srcid hex>:<128hex dest>:<amount> [--leaf ...]
 *     --sign-random <hex, the bytes qgp_platform_random returns in order>
 *   Loads the claim data (nsw_claim_set_manifest / _add_leaf / _seal) and
 *   builds the claim with nsw_claim_offline_build — the function every
 *   wasm build runs. Output, in this order: claim (the bytes), claim_id
 *   (SHA3-512 of the bytes), nullifier, output_id, recipient, amount,
 *   chain_id, leaf_index.
 *   Compared like the spend: TEST wasm == native line for line; shipped
 *   wasm equal on nullifier, output_id, recipient, amount, chain_id,
 *   leaf_index, different claim / claim_id (hedged signature).
 *
 * STAKING (0.1.29) — one more mode:
 *
 *   nodus-send-native-vector stake --op stake|delegate|undelegate
 *     [--gen <dec>] --seed <64hex> --chain <64hex> --tip <dec> --gas <dec>
 *     [--validator <5184hex pubkey>] [--validator-id <128hex>]
 *     --amount <dec> [--commission <bps>]
 *     --expiry <dec> --coin <128hex>:<dec> [--coin ...]
 *     --sign-random <hex, the bytes qgp_platform_random returns in order>
 *   Builds with nsw_stake_offline_build (the shared builder
 *   nodus/src/client/nodus_v2_stake.c, the function every wasm build
 *   runs) for rule-set generation --gen (default 1). HF-6 slice 7b: at
 *   --gen 4 a delegate / undelegate takes the generation-4 layout and
 *   needs --validator-id (the target) besides --validator (its key, the
 *   recipient fingerprint); below 4 --validator-id is refused, and stake at
 *   --gen 4 is refused (it needs a node consent: the hf6 mode). No
 *   --out-seeds: the builder draws none (its change seed is SHA3-512 of the
 *   inputs). Output, in this order: envelope, wire_id, intent_id, chain_id,
 *   op, gen4 (1 = the generation-4 layout), validator_id ("" below it),
 *   recipient (the validator's fingerprint, or the staker's own for stake),
 *   amount, commission, fee, change, expiry, then one `input=` per input.
 *   Compared like the spend.
 *
 * SMART CONTRACTS (0.1.64) — one more mode:
 *
 *   nodus-send-native-vector evm --op call|create|deposit|withdraw|redeem
 *     --gen <dec> --seed <64hex> --chain <64hex> --tip <dec> --gas-price <dec>
 *     --evm-ver <dec> --evm-hash <128hex> [--to <64hex>] [--value <64hex>]
 *     [--gas <dec>] [--nonce <dec>] [--amount <dec>] [--dest <128hex>]
 *     [--ticket <128hex>] [--data <hex>] [--access <64hex>:<64hex keys...>]
 *     [--units <dec>] --expiry <dec> --coin <128hex>:<dec> [--coin ...]
 *     --sign-random <hex, the bytes qgp_platform_random returns in order>
 *   Builds with nsw_evm_offline_build (the shared builder
 *   nodus/src/client/nodus_v2_evm.c, the function every wasm build runs).
 *   An option not given is absent ("" / "0"), as the builder requires for
 *   the fields an op does not carry. Two legs are signed: --sign-random
 *   needs 64 bytes. Output, in this order: envelope, wire_id, intent_id,
 *   chain_id, op, to, value, gas, nonce, units, amount, dest, ticket,
 *   data_len, created, recipient, fee, change, expiry, then one `input=`
 *   per input. Compared like the spend.
 *
 * HF-6 (design docs/plans/2026-10-12-connect-hf6-screens-design.md) — two
 * more modes:
 *
 *   nodus-send-native-vector hf6-consent --op stake|rotate|storage
 *     --node-seed <64hex> --chain <64hex> [--subject <128hex>]
 *     (--owner <128hex> | --owner-seed <64hex>) --expiry <dec>
 *     --sign-random <hex, the bytes qgp_platform_random returns in order>
 *   The NODE's side, as nodus-cli `validator consent` / `storage consent`
 *   makes it (cmd_validator_consent): the node key from --node-seed, the
 *   §6.1 message (dna_valbind_consent_msg), its signature
 *   (dna_valbind_consent_sign, ctx "nodus.valbind.v1", 32 bytes of
 *   --sign-random) and the text container (nodus_v2_consent_text_encode).
 *   --subject only for rotate (the validator_id); --owner-seed gives the
 *   owner as SHA3-512 of that seed's ML-DSA-87 public key. Output:
 *   consent (the text, as lowercase hex of its bytes), node_fp, owner.
 *
 *   nodus-send-native-vector hf6 --gen <dec>
 *     --op stake|rotate|storage-register|storage-exit --seed <64hex>
 *     --chain <64hex> --tip <dec> --gas <dec> [--consent <hex of the text>]
 *     [--target <128hex>] [--amount <dec>] [--commission <bps>]
 *     --expiry <dec> --coin <128hex>:<dec> [--coin ...]
 *     --sign-random <hex, the bytes qgp_platform_random returns in order>
 *   Builds with nsw_hf6_offline_build (the shared builder at the given
 *   generation, the consent re-checked by the codec — the function every
 *   wasm build runs). --target: rotate the validator_id, storage-exit the
 *   node_fp. Two legs are signed: --sign-random needs 64 bytes. Output, in
 *   this order: envelope, wire_id, intent_id, chain_id, op, gen4,
 *   recipient, node_fp, validator_id, amount, commission, consent_expiry,
 *   fee, change, expiry, then one `input=` per input. Compared like the
 *   staking mode.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnac/manifest_wire.h"
#include "dnac/valbind_wire.h"
#include "client/nodus_v2_stake.h"          /* the consent text container */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

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
int nsw_claim_reset(void);
int nsw_claim_set_manifest(const char *manifest_hex, const char *hash_hex);
int nsw_claim_add_leaf(const char *source_id_hex, const char *dest_hex,
                       const char *amount_dec);
int nsw_claim_seal(void);
int nsw_claim_offline_build(const char *chain_hex);
const uint8_t *nsw_claim_built_bytes(void);
int nsw_claim_built_len(void);
const char *nsw_claim_built_id(void);
const char *nsw_claim_built_nullifier(void);
const char *nsw_claim_built_output(void);
const char *nsw_claim_built_recipient(void);
const char *nsw_claim_built_chain(void);
const char *nsw_claim_built_amount(void);
const char *nsw_claim_built_leaf(void);
int nsw_stake_offline_build(int gen, int op, const char *chain_hex,
                            const char *tip_dec, const char *gas_dec,
                            const char *validator_hex,
                            const char *validator_id_hex,
                            const char *amount_dec, const char *commission_dec,
                            const char *expiry_dec);
int nsw_built_op(void);
const char *nsw_built_commission(void);
int nsw_hf6_offline_build(int gen, int op, const char *chain_hex,
                          const char *tip_dec, const char *gas_dec,
                          const char *consent_text, const char *target_hex,
                          const char *amount_dec, const char *commission_dec,
                          const char *expiry_dec);
int nsw_built_gen4(void);
const char *nsw_built_node_fp(void);
const char *nsw_built_validator_id(void);
const char *nsw_built_consent_expiry(void);
uint8_t *nsw_evm_data_alloc(int len);
void nsw_evm_access_reset(void);
int nsw_evm_access_add(const char *addr_hex, const char *keys_hex);
int nsw_evm_offline_build(int gen, int op, const char *chain_hex,
                          const char *tip_dec, const char *gas_price_dec,
                          const char *evm_ver_dec, const char *evm_hash_hex,
                          const char *to_hex, const char *value_hex,
                          const char *gas_dec, const char *nonce_dec,
                          const char *amount_dec, const char *dest_hex,
                          const char *ticket_hex, const char *units_dec,
                          const char *expiry_dec);
int nsw_evm_built_op(void);
const char *nsw_evm_built_to(void);
const char *nsw_evm_built_value(void);
const char *nsw_evm_built_gas(void);
const char *nsw_evm_built_nonce(void);
const char *nsw_evm_built_units(void);
const char *nsw_evm_built_amount(void);
const char *nsw_evm_built_dest(void);
const char *nsw_evm_built_ticket(void);
int nsw_evm_built_data_len(void);
const char *nsw_evm_built_created(void);

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

static int hex_line(const char *key, const uint8_t *bytes, size_t n) {
    static const char digits[] = "0123456789abcdef";
    char *hex = malloc(n * 2 + 1);
    if (!hex) return fail("out of memory");
    for (size_t i = 0; i < n; i++) {
        hex[2 * i]     = digits[bytes[i] >> 4];
        hex[2 * i + 1] = digits[bytes[i] & 15];
    }
    hex[2 * n] = '\0';
    line(key, hex);
    free(hex);
    return 0;
}

/* Splits "<a>:<b>[:<c>]" into exactly `want` parts, in `scratch`. */
static int split(const char *v, char *scratch, size_t cap, char **parts, int want) {
    size_t n = strlen(v);
    if (n + 1 > cap) return -1;
    memcpy(scratch, v, n + 1);
    int got = 0;
    char *p = scratch;
    while (got < want) {
        parts[got++] = p;
        char *colon = strchr(p, ':');
        if (!colon) break;
        *colon = '\0';
        p = colon + 1;
    }
    return got == want && !strchr(parts[want - 1], ':') ? 0 : -1;
}

static int parse_dec(const char *s, uint64_t *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 20 || (n > 1 && s[0] == '0')) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10u) return -1;
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

static int leaf_qcmp(const void *a, const void *b) {
    return dna_dist_leaf_cmp((const dna_dist_leaf_t *)a, (const dna_dist_leaf_t *)b);
}

#define VEC_MAX_LEAVES 256
#define VEC_MANIFEST_MAX 8192

static int main_claim_manifest(int argc, char **argv) {
    const char *base = NULL, *seed = NULL, *self_leaf = NULL;
    const char *others[VEC_MAX_LEAVES];
    int n_others = 0;
    for (int i = 2; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) return fail("every option takes a value");
        if      (!strcmp(a, "--base"))      base = v;
        else if (!strcmp(a, "--seed"))      seed = v;
        else if (!strcmp(a, "--self-leaf")) self_leaf = v;
        else if (!strcmp(a, "--leaf")) {
            if (n_others >= VEC_MAX_LEAVES - 1) return fail("too many --leaf");
            others[n_others++] = v;
        } else return fail("unknown option (see the usage in nodus-send-native-vector.c)");
    }
    if (!base || !seed || !self_leaf)
        return fail("claim-manifest needs --base --seed --self-leaf");

    static uint8_t buf[VEC_MANIFEST_MAX];
    static dna_gman_t m;
    static dna_dist_leaf_t leaves[VEC_MAX_LEAVES];
    uint8_t seed32[32];
    size_t n = 0;
    if (unhex(base, buf, sizeof(buf), &n) != 0 || dna_gman_decode(buf, n, &m) != 0 ||
        m.dist_present != 1)
        return fail("--base is not a manifest with a distribution section");
    if (unhex(seed, seed32, 32, &n) != 0 || n != 32)
        return fail("--seed is 32 bytes of lowercase hex");
    uint8_t *pk = malloc(QGP_DSA87_PUBLICKEYBYTES), *sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    uint8_t self_dest[64];
    int krc = !pk || !sk || qgp_dsa87_keypair_derand(pk, sk, seed32) != 0 ||
              qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, self_dest) != 0;
    free(pk);
    free(sk);
    if (krc) return fail("key derivation failed");

    size_t count = 0;
    for (int i = -1; i < n_others; i++) {
        char scratch[512], *parts[3];
        dna_dist_leaf_t *L = &leaves[count];
        memset(L, 0, sizeof(*L));
        L->leaf_version = DNA_DIST_VERSION;
        const char *amount;
        size_t sl = 0, dl = 0;
        if (i < 0) {
            if (split(self_leaf, scratch, sizeof(scratch), parts, 2) != 0)
                return fail("--self-leaf is <srcid hex>:<amount>");
            memcpy(L->dest_binding, self_dest, 64);
            amount = parts[1];
        } else {
            if (split(others[i], scratch, sizeof(scratch), parts, 3) != 0 ||
                unhex(parts[1], L->dest_binding, 64, &dl) != 0 || dl != 64)
                return fail("--leaf is <srcid hex>:<128hex dest>:<amount>");
            amount = parts[2];
        }
        if (unhex(parts[0], L->source_id, DNA_DIST_SRCID_MAX, &sl) != 0 || sl == 0 ||
            parse_dec(amount, &L->source_amount) != 0 || L->source_amount == 0)
            return fail("invalid leaf source id or amount");
        L->source_id_len = (uint16_t)sl;
        count++;
    }
    qsort(leaves, count, sizeof(leaves[0]), leaf_qcmp);
    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t conv = 0;
        if ((i > 0 && dna_dist_leaf_cmp(&leaves[i - 1], &leaves[i]) >= 0) ||
            dna_dist_converted(leaves[i].source_amount, m.conv_numerator,
                               m.conv_denominator, m.rounding_mode, &conv) != 0 ||
            conv > UINT64_MAX - total)
            return fail("duplicate leaf or amount out of range");
        total += conv;
    }
    if (dna_dist_snapshot_root(leaves, count, m.snapshot_root) != 0)
        return fail("snapshot root failed");
    m.leaf_count = count;
    m.total_claimable = total;
    uint8_t hash[64];
    size_t len = dna_gman_encoded_len(&m), written = 0;
    if (len == 0 || len > sizeof(buf) ||
        dna_gman_encode(&m, buf, sizeof(buf), &written) != 0 || written != len ||
        dna_gman_hash(&m, hash) != 0)
        return fail("the synthetic manifest does not encode");
    if (hex_line("manifest", buf, len) || hex_line("manifest_hash", hash, 64)) return 1;
    for (size_t i = 0; i < count; i++) {
        char src[2 * DNA_DIST_SRCID_MAX + 1], dest[129], amt[21], out[2 * DNA_DIST_SRCID_MAX + 1 + 129 + 21 + 2];
        static const char digits[] = "0123456789abcdef";
        for (size_t k = 0; k < leaves[i].source_id_len; k++) {
            src[2 * k] = digits[leaves[i].source_id[k] >> 4];
            src[2 * k + 1] = digits[leaves[i].source_id[k] & 15];
        }
        src[2 * leaves[i].source_id_len] = '\0';
        for (size_t k = 0; k < 64; k++) {
            dest[2 * k] = digits[leaves[i].dest_binding[k] >> 4];
            dest[2 * k + 1] = digits[leaves[i].dest_binding[k] & 15];
        }
        dest[128] = '\0';
        snprintf(amt, sizeof(amt), "%llu", (unsigned long long)leaves[i].source_amount);
        snprintf(out, sizeof(out), "%s:%s:%s", src, dest, amt);
        line("leaf", out);
    }
    return 0;
}

static int main_claim(int argc, char **argv) {
    const char *seed = NULL, *chain = NULL, *manifest = NULL, *mhash = NULL,
               *sign_random = NULL;
    if (nsw_claim_reset() != 0) return fail(nsw_error());
    int have_manifest = 0;
    for (int i = 2; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) return fail("every option takes a value");
        if      (!strcmp(a, "--seed"))          seed = v;
        else if (!strcmp(a, "--chain"))         chain = v;
        else if (!strcmp(a, "--manifest"))      manifest = v;
        else if (!strcmp(a, "--manifest-hash")) mhash = v;
        else if (!strcmp(a, "--sign-random"))   sign_random = v;
        else if (!strcmp(a, "--leaf")) {
            char scratch[512], *parts[3];
            if (!have_manifest) {
                if (!manifest || !mhash) return fail("give --manifest and --manifest-hash before --leaf");
                if (nsw_claim_set_manifest(manifest, mhash) != 0) return fail(nsw_error());
                have_manifest = 1;
            }
            if (split(v, scratch, sizeof(scratch), parts, 3) != 0)
                return fail("--leaf is <srcid hex>:<128hex dest>:<amount>");
            if (nsw_claim_add_leaf(parts[0], parts[1], parts[2]) != 0) return fail(nsw_error());
        } else return fail("unknown option (see the usage in nodus-send-native-vector.c)");
    }
    if (!seed || !chain || !have_manifest || !sign_random)
        return fail("claim needs --seed --chain --manifest --manifest-hash --leaf --sign-random");
    if (nsw_claim_seal() != 0) return fail(nsw_error());
    size_t n = 0;
    if (unhex(seed, nsw_seed_buf(), 32, &n) != 0 || n != 32)
        return fail("--seed is 32 bytes of lowercase hex");
    if (unhex(sign_random, nsw_test_random_buf(), 4096, &n) != 0 ||
        nsw_test_random_load((int)n) != 0)
        return fail("--sign-random is at most 4096 bytes of lowercase hex");
    if (nsw_claim_offline_build(chain) != 0) return fail(nsw_error());
    if (hex_line("claim", nsw_claim_built_bytes(), (size_t)nsw_claim_built_len())) return 1;
    line("claim_id", nsw_claim_built_id());
    line("nullifier", nsw_claim_built_nullifier());
    line("output_id", nsw_claim_built_output());
    line("recipient", nsw_claim_built_recipient());
    line("amount", nsw_claim_built_amount());
    line("chain_id", nsw_claim_built_chain());
    line("leaf_index", nsw_claim_built_leaf());
    return 0;
}

/* Prints the envelope nsw_built_* holds (the spend and staking modes). */
static int print_env(void) {
    return hex_line("envelope", nsw_built_env(), (size_t)nsw_built_env_len());
}

static int main_stake(int argc, char **argv) {
    const char *op_s = NULL, *gen_s = "1", *seed = NULL, *chain = NULL,
               *tip = NULL, *gas = NULL, *validator = "", *validator_id = "",
               *amount = NULL, *commission = "0", *expiry = NULL,
               *sign_random = NULL;
    nsw_req_reset();
    for (int i = 2; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) return fail("every option takes a value");
        if      (!strcmp(a, "--op"))          op_s = v;
        else if (!strcmp(a, "--gen"))         gen_s = v;
        else if (!strcmp(a, "--seed"))        seed = v;
        else if (!strcmp(a, "--chain"))       chain = v;
        else if (!strcmp(a, "--tip"))         tip = v;
        else if (!strcmp(a, "--gas"))         gas = v;
        else if (!strcmp(a, "--validator"))   validator = v;
        else if (!strcmp(a, "--validator-id")) validator_id = v;
        else if (!strcmp(a, "--amount"))      amount = v;
        else if (!strcmp(a, "--commission"))  commission = v;
        else if (!strcmp(a, "--expiry"))      expiry = v;
        else if (!strcmp(a, "--sign-random")) sign_random = v;
        else if (!strcmp(a, "--coin")) {
            char nul[129];
            const char *colon = strchr(v, ':');
            if (!colon || colon - v != 128) return fail("--coin is <128hex>:<amount>");
            memcpy(nul, v, 128);
            nul[128] = '\0';
            if (nsw_req_add_coin(nul, colon + 1) != 0) return fail(nsw_error());
        } else return fail("unknown option (see the usage in nodus-send-native-vector.c)");
    }
    int op = !op_s ? 0 : !strcmp(op_s, "stake") ? 1 : !strcmp(op_s, "delegate") ? 2
           : !strcmp(op_s, "undelegate") ? 4 : 0;
    uint64_t gen = 0;
    if (!op || !seed || !chain || !tip || !gas || !amount || !expiry || !sign_random ||
        parse_dec(gen_s, &gen) != 0 || gen < 1 || gen > 255)
        return fail("stake needs --op stake|delegate|undelegate --seed --chain --tip "
                    "--gas --amount --expiry --coin --sign-random (--validator for "
                    "delegate / undelegate, --validator-id for them at --gen 4, "
                    "--commission for stake; --gen 1..255, default 1)");
    size_t n = 0;
    if (unhex(seed, nsw_seed_buf(), 32, &n) != 0 || n != 32)
        return fail("--seed is 32 bytes of lowercase hex");
    if (unhex(sign_random, nsw_test_random_buf(), 4096, &n) != 0 ||
        nsw_test_random_load((int)n) != 0)
        return fail("--sign-random is at most 4096 bytes of lowercase hex");
    if (nsw_stake_offline_build((int)gen, op, chain, tip, gas, validator,
                                validator_id, amount, commission, expiry) != 0)
        return fail(nsw_error());
    if (print_env()) return 1;
    line("wire_id", nsw_built_wire());
    line("intent_id", nsw_built_intent());
    line("chain_id", nsw_built_chain());
    char op_dec[4];
    snprintf(op_dec, sizeof(op_dec), "%d", nsw_built_op());
    line("op", op_dec);
    line("gen4", nsw_built_gen4() ? "1" : "0");
    line("validator_id", nsw_built_validator_id());
    line("recipient", nsw_built_recipient());
    line("amount", nsw_built_amount());
    line("commission", nsw_built_commission());
    line("fee", nsw_built_fee());
    line("change", nsw_built_change());
    line("expiry", nsw_built_expiry());
    for (int i = 0; i < nsw_built_n_in(); i++) line("input", nsw_built_in(i));
    return 0;
}

/* The NODE's consent (see the usage above): what nodus-cli
 * cmd_validator_consent makes, from explicit inputs. */
static int main_hf6_consent(int argc, char **argv) {
    const char *op_s = NULL, *node_seed = NULL, *chain = NULL, *subject = NULL,
               *owner = NULL, *owner_seed = NULL, *expiry = NULL,
               *sign_random = NULL;
    for (int i = 2; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) return fail("every option takes a value");
        if      (!strcmp(a, "--op"))          op_s = v;
        else if (!strcmp(a, "--node-seed"))   node_seed = v;
        else if (!strcmp(a, "--chain"))       chain = v;
        else if (!strcmp(a, "--subject"))     subject = v;
        else if (!strcmp(a, "--owner"))       owner = v;
        else if (!strcmp(a, "--owner-seed"))  owner_seed = v;
        else if (!strcmp(a, "--expiry"))      expiry = v;
        else if (!strcmp(a, "--sign-random")) sign_random = v;
        else return fail("unknown option (see the usage in nodus-send-native-vector.c)");
    }
    const uint8_t op = !op_s ? 0 : !strcmp(op_s, "stake") ? DNA_VALBIND_OP_STAKE
                     : !strcmp(op_s, "rotate") ? DNA_VALBIND_OP_ROTATE
                     : !strcmp(op_s, "storage") ? DNA_VALBIND_OP_STORAGE_REGISTER : 0;
    if (!op || !node_seed || !chain || !expiry || !sign_random ||
        (!owner == !owner_seed) || ((op == DNA_VALBIND_OP_ROTATE) != (subject != NULL)))
        return fail("hf6-consent needs --op stake|rotate|storage --node-seed --chain "
                    "(--owner | --owner-seed) --expiry --sign-random (--subject for rotate)");
    static nodus_v2_consent_t c;
    static uint8_t node_pk[QGP_DSA87_PUBLICKEYBYTES], node_sk[QGP_DSA87_SECRETKEYBYTES];
    static uint8_t msg[DNA_VALBIND_MSG_LEN];
    uint8_t seed32[32];
    size_t n = 0;
    memset(&c, 0, sizeof(c));
    c.op = op;
    if (unhex(node_seed, seed32, 32, &n) != 0 || n != 32 ||
        qgp_dsa87_keypair_derand(node_pk, node_sk, seed32) != 0)
        return fail("--node-seed is 32 bytes of lowercase hex");
    memcpy(c.consensus_pk, node_pk, sizeof(node_pk));
    if (unhex(chain, c.chain32, sizeof(c.chain32), &n) != 0 || n != sizeof(c.chain32))
        return fail("--chain is 32 bytes of lowercase hex");
    if (subject && (unhex(subject, c.subject, 64, &n) != 0 || n != 64))
        return fail("--subject is 64 bytes of lowercase hex");
    if (owner) {
        if (unhex(owner, c.owner_fp, 64, &n) != 0 || n != 64)
            return fail("--owner is 64 bytes of lowercase hex");
    } else {
        static uint8_t opk[QGP_DSA87_PUBLICKEYBYTES], osk[QGP_DSA87_SECRETKEYBYTES];
        if (unhex(owner_seed, seed32, 32, &n) != 0 || n != 32 ||
            qgp_dsa87_keypair_derand(opk, osk, seed32) != 0 ||
            qgp_sha3_512(opk, sizeof(opk), c.owner_fp) != 0)
            return fail("--owner-seed is 32 bytes of lowercase hex");
    }
    if (parse_dec(expiry, &c.expiry) != 0) return fail("--expiry is a decimal height");
    if (unhex(sign_random, nsw_test_random_buf(), 4096, &n) != 0 ||
        nsw_test_random_load((int)n) != 0)
        return fail("--sign-random is at most 4096 bytes of lowercase hex");
    size_t sl = 0;
    if (dna_valbind_consent_msg(msg, c.chain32, c.op, c.subject, c.owner_fp,
                                c.consensus_pk, c.expiry) != 0 ||
        dna_valbind_consent_sign(c.sig, &sl, msg, node_sk) != 0 ||
        sl != DNA_VALBIND_SIG_LEN)
        return fail("the consent could not be signed");
    char *text = NULL;
    size_t tl = 0;
    if (nodus_v2_consent_text_encode(&c, &text, &tl) != NODUS_V2_SPEND_OK)
        return fail("the consent could not be encoded");
    int rc = hex_line("consent", (const uint8_t *)text, tl);
    free(text);
    if (rc) return 1;
    uint8_t fp[64];
    if (qgp_sha3_512(node_pk, sizeof(node_pk), fp) != 0) return fail("hash failed");
    if (hex_line("node_fp", fp, 64) || hex_line("owner", c.owner_fp, 64)) return 1;
    return 0;
}

static int main_hf6(int argc, char **argv) {
    const char *op_s = NULL, *gen_s = NULL, *seed = NULL, *chain = NULL,
               *tip = NULL, *gas = NULL, *consent_hex = "", *target = "",
               *amount = "0", *commission = "0", *expiry = NULL,
               *sign_random = NULL;
    nsw_req_reset();
    for (int i = 2; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) return fail("every option takes a value");
        if      (!strcmp(a, "--op"))          op_s = v;
        else if (!strcmp(a, "--gen"))         gen_s = v;
        else if (!strcmp(a, "--seed"))        seed = v;
        else if (!strcmp(a, "--chain"))       chain = v;
        else if (!strcmp(a, "--tip"))         tip = v;
        else if (!strcmp(a, "--gas"))         gas = v;
        else if (!strcmp(a, "--consent"))     consent_hex = v;
        else if (!strcmp(a, "--target"))      target = v;
        else if (!strcmp(a, "--amount"))      amount = v;
        else if (!strcmp(a, "--commission"))  commission = v;
        else if (!strcmp(a, "--expiry"))      expiry = v;
        else if (!strcmp(a, "--sign-random")) sign_random = v;
        else if (!strcmp(a, "--coin")) {
            char nul[129];
            const char *colon = strchr(v, ':');
            if (!colon || colon - v != 128) return fail("--coin is <128hex>:<amount>");
            memcpy(nul, v, 128);
            nul[128] = '\0';
            if (nsw_req_add_coin(nul, colon + 1) != 0) return fail(nsw_error());
        } else return fail("unknown option (see the usage in nodus-send-native-vector.c)");
    }
    int op = !op_s ? 0 : !strcmp(op_s, "stake") ? 1 : !strcmp(op_s, "rotate") ? 10
           : !strcmp(op_s, "storage-register") ? 7
           : !strcmp(op_s, "storage-exit") ? 8 : 0;
    uint64_t gen = 0;
    if (!op || !gen_s || parse_dec(gen_s, &gen) != 0 || gen < 1 || gen > 255 ||
        !seed || !chain || !tip || !gas || !expiry || !sign_random)
        return fail("hf6 needs --gen --op stake|rotate|storage-register|storage-exit "
                    "--seed --chain --tip --gas --expiry --coin --sign-random "
                    "(and the op's own fields)");
    /* the consent text, from its hex (16384 bytes at most, the CLI's bound) */
    static char consent[16385];
    size_t n = 0;
    if (unhex(consent_hex, (uint8_t *)consent, sizeof(consent) - 1, &n) != 0)
        return fail("--consent is the consent text as lowercase hex");
    consent[n] = '\0';
    if (unhex(seed, nsw_seed_buf(), 32, &n) != 0 || n != 32)
        return fail("--seed is 32 bytes of lowercase hex");
    if (unhex(sign_random, nsw_test_random_buf(), 4096, &n) != 0 ||
        nsw_test_random_load((int)n) != 0)
        return fail("--sign-random is at most 4096 bytes of lowercase hex");
    if (nsw_hf6_offline_build((int)gen, op, chain, tip, gas, consent, target,
                              amount, commission, expiry) != 0)
        return fail(nsw_error());
    if (print_env()) return 1;
    line("wire_id", nsw_built_wire());
    line("intent_id", nsw_built_intent());
    line("chain_id", nsw_built_chain());
    char dec[24];
    snprintf(dec, sizeof(dec), "%d", nsw_built_op());
    line("op", dec);
    snprintf(dec, sizeof(dec), "%d", nsw_built_gen4());
    line("gen4", dec);
    line("recipient", nsw_built_recipient());
    line("node_fp", nsw_built_node_fp());
    line("validator_id", nsw_built_validator_id());
    line("amount", nsw_built_amount());
    line("commission", nsw_built_commission());
    line("consent_expiry", nsw_built_consent_expiry());
    line("fee", nsw_built_fee());
    line("change", nsw_built_change());
    line("expiry", nsw_built_expiry());
    for (int i = 0; i < nsw_built_n_in(); i++) line("input", nsw_built_in(i));
    return 0;
}

#define VEC_EVM_DATA_MAX 49152               /* evm_call_wire.h DNA_EVM_MAX_INITCODE */

static int main_evm(int argc, char **argv) {
    const char *op_s = NULL, *gen_s = NULL, *seed = NULL, *chain = NULL,
               *tip = NULL, *gas_price = NULL, *evm_ver = NULL, *evm_hash = NULL,
               *to = "", *value = "", *gas = "0", *nonce = "0", *amount = "0",
               *dest = "", *ticket = "", *data = "", *units = "0",
               *expiry = NULL, *sign_random = NULL;
    nsw_req_reset();
    nsw_evm_access_reset();
    for (int i = 2; i < argc; i += 2) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!v) return fail("every option takes a value");
        if      (!strcmp(a, "--op"))          op_s = v;
        else if (!strcmp(a, "--gen"))         gen_s = v;
        else if (!strcmp(a, "--seed"))        seed = v;
        else if (!strcmp(a, "--chain"))       chain = v;
        else if (!strcmp(a, "--tip"))         tip = v;
        else if (!strcmp(a, "--gas-price"))   gas_price = v;
        else if (!strcmp(a, "--evm-ver"))     evm_ver = v;
        else if (!strcmp(a, "--evm-hash"))    evm_hash = v;
        else if (!strcmp(a, "--to"))          to = v;
        else if (!strcmp(a, "--value"))       value = v;
        else if (!strcmp(a, "--gas"))         gas = v;
        else if (!strcmp(a, "--nonce"))       nonce = v;
        else if (!strcmp(a, "--amount"))      amount = v;
        else if (!strcmp(a, "--dest"))        dest = v;
        else if (!strcmp(a, "--ticket"))      ticket = v;
        else if (!strcmp(a, "--data"))        data = v;
        else if (!strcmp(a, "--units"))       units = v;
        else if (!strcmp(a, "--expiry"))      expiry = v;
        else if (!strcmp(a, "--sign-random")) sign_random = v;
        else if (!strcmp(a, "--access")) {
            char addr[65];
            const char *colon = strchr(v, ':');
            if (!colon || colon - v != 64) return fail("--access is <64hex>:<64hex storage keys, concatenated>");
            memcpy(addr, v, 64);
            addr[64] = '\0';
            if (nsw_evm_access_add(addr, colon + 1) != 0) return fail(nsw_error());
        } else if (!strcmp(a, "--coin")) {
            char nul[129];
            const char *colon = strchr(v, ':');
            if (!colon || colon - v != 128) return fail("--coin is <128hex>:<amount>");
            memcpy(nul, v, 128);
            nul[128] = '\0';
            if (nsw_req_add_coin(nul, colon + 1) != 0) return fail(nsw_error());
        } else return fail("unknown option (see the usage in nodus-send-native-vector.c)");
    }
    int op = !op_s ? 0 : !strcmp(op_s, "call") ? 1 : !strcmp(op_s, "create") ? 2
           : !strcmp(op_s, "deposit") ? 3 : !strcmp(op_s, "withdraw") ? 4
           : !strcmp(op_s, "redeem") ? 5 : 0;
    uint64_t gen = 0;
    if (!op || !gen_s || parse_dec(gen_s, &gen) != 0 || gen > 255 || !seed ||
        !chain || !tip || !gas_price || !evm_ver || !evm_hash || !expiry ||
        !sign_random)
        return fail("evm needs --op call|create|deposit|withdraw|redeem --gen "
                    "--seed --chain --tip --gas-price --evm-ver --evm-hash "
                    "--expiry --coin --sign-random (and the op's own fields)");
    size_t n = 0;
    const size_t data_len = strlen(data) / 2;
    if (data_len > VEC_EVM_DATA_MAX) return fail("--data is at most 49152 bytes");
    if (data_len) {
        uint8_t *buf = nsw_evm_data_alloc((int)data_len);
        if (!buf || unhex(data, buf, data_len, &n) != 0 || n != data_len)
            return fail("--data is lowercase hex");
    } else {
        nsw_evm_data_alloc(0);
    }
    if (unhex(seed, nsw_seed_buf(), 32, &n) != 0 || n != 32)
        return fail("--seed is 32 bytes of lowercase hex");
    if (unhex(sign_random, nsw_test_random_buf(), 4096, &n) != 0 ||
        nsw_test_random_load((int)n) != 0)
        return fail("--sign-random is at most 4096 bytes of lowercase hex");
    if (nsw_evm_offline_build((int)gen, op, chain, tip, gas_price, evm_ver,
                              evm_hash, to, value, gas, nonce, amount, dest,
                              ticket, units, expiry) != 0)
        return fail(nsw_error());
    if (print_env()) return 1;
    line("wire_id", nsw_built_wire());
    line("intent_id", nsw_built_intent());
    line("chain_id", nsw_built_chain());
    char dec[24];
    snprintf(dec, sizeof(dec), "%d", nsw_evm_built_op());
    line("op", dec);
    line("to", nsw_evm_built_to());
    line("value", nsw_evm_built_value());
    line("gas", nsw_evm_built_gas());
    line("nonce", nsw_evm_built_nonce());
    line("units", nsw_evm_built_units());
    line("amount", nsw_evm_built_amount());
    line("dest", nsw_evm_built_dest());
    line("ticket", nsw_evm_built_ticket());
    snprintf(dec, sizeof(dec), "%d", nsw_evm_built_data_len());
    line("data_len", dec);
    line("created", nsw_evm_built_created());
    line("recipient", nsw_built_recipient());
    line("fee", nsw_built_fee());
    line("change", nsw_built_change());
    line("expiry", nsw_built_expiry());
    for (int i = 0; i < nsw_built_n_in(); i++) line("input", nsw_built_in(i));
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "evm")) return main_evm(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "claim-manifest")) return main_claim_manifest(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "claim")) return main_claim(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "stake")) return main_stake(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "hf6-consent")) return main_hf6_consent(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "hf6")) return main_hf6(argc, argv);
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
