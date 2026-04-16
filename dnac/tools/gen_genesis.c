/**
 * @file gen_genesis.c
 * @brief Operator utility: build a DNAC genesis block + print its chain_id.
 *
 * Run once per hard fork. Feed the output chain_id into
 * dnac/src/ledger/genesis_anchor.c's DNAC_KNOWN_CHAINS[] array, commit,
 * rebuild the client, and deploy.
 *
 * Usage:
 *   gen_genesis --chain-name NAME --witnesses N --pubkey-file FILE
 *               --supply RAW [--recipient FP|burn] [--message MSG]
 *               [--block-interval SECS] [--max-active N]
 *               [--token-symbol STR] [--token-decimals N]
 *               [--output PATH] [--timestamp TS] [--parent-chain HEX]
 *
 * The pubkey file must contain exactly N * DNAC_PUBKEY_SIZE (2592) bytes,
 * concatenating N Dilithium5 public keys.
 *
 * Build:
 *   Integrated via dnac/CMakeLists.txt as the `gen_genesis` executable.
 *   Manual:
 *     gcc -I dnac/include -I messenger/include -I shared \
 *         dnac/tools/gen_genesis.c messenger/build/libdna.so -lcrypto \
 *         -Wl,-rpath,messenger/build -o gen_genesis
 */

#include "dnac/block.h"
#include "dnac/chain_def_codec.h"
#include "dnac/dnac.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

static int parse_hex(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --chain-name NAME --witnesses N --pubkey-file FILE --supply RAW [options]\n"
        "\n"
        "Required:\n"
        "  --chain-name NAME       Chain name (max %d chars, e.g. \"main\")\n"
        "  --witnesses N           Number of witness pubkeys in FILE (1..%d)\n"
        "  --pubkey-file FILE      Binary file of N * %d bytes (Dilithium5 pubkeys)\n"
        "  --supply RAW            Initial supply in raw units (uint64)\n"
        "\n"
        "Optional:\n"
        "  --recipient FP          32-byte fee_recipient (hex) or 'burn' (default: burn)\n"
        "  --message MSG           Genesis vanity message (max %d chars)\n"
        "  --block-interval SECS   Default: 5\n"
        "  --max-active N          Default: 21\n"
        "  --token-symbol STR      Default: \"DNAC\" (max %d chars)\n"
        "  --token-decimals N      Default: 8\n"
        "  --output PATH           Default: ./genesis.bin\n"
        "  --timestamp TS          Unix timestamp (default: now)\n"
        "  --parent-chain HEX      Parent chain_id hex (default: zeros)\n",
        argv0,
        (int)(DNAC_CHAIN_NAME_LEN - 1),
        (int)DNAC_MAX_WITNESSES_COMPILE_CAP,
        (int)DNAC_PUBKEY_SIZE,
        (int)(DNAC_GENESIS_MESSAGE_LEN - 1),
        (int)(DNAC_TOKEN_SYMBOL_LEN - 1));
}

int main(int argc, char **argv) {
    const char *chain_name = NULL;
    long witnesses = 0;
    const char *pubkey_file = NULL;
    uint64_t supply = 0;
    const char *recipient = "burn";
    const char *message = NULL;
    uint32_t block_interval = 5;
    uint32_t max_active = 21;
    const char *token_symbol = "DNAC";
    int token_decimals = 8;
    const char *output = "./genesis.bin";
    uint64_t timestamp = (uint64_t)time(NULL);
    const char *parent_hex = NULL;

    enum {
        OPT_CHAIN_NAME = 1000,
        OPT_WITNESSES,
        OPT_PUBKEY_FILE,
        OPT_SUPPLY,
        OPT_RECIPIENT,
        OPT_MESSAGE,
        OPT_BLOCK_INTERVAL,
        OPT_MAX_ACTIVE,
        OPT_TOKEN_SYMBOL,
        OPT_TOKEN_DECIMALS,
        OPT_OUTPUT,
        OPT_TIMESTAMP,
        OPT_PARENT_CHAIN,
        OPT_HELP,
    };

    static const struct option long_opts[] = {
        {"chain-name",     required_argument, NULL, OPT_CHAIN_NAME},
        {"witnesses",      required_argument, NULL, OPT_WITNESSES},
        {"pubkey-file",    required_argument, NULL, OPT_PUBKEY_FILE},
        {"supply",         required_argument, NULL, OPT_SUPPLY},
        {"recipient",      required_argument, NULL, OPT_RECIPIENT},
        {"message",        required_argument, NULL, OPT_MESSAGE},
        {"block-interval", required_argument, NULL, OPT_BLOCK_INTERVAL},
        {"max-active",     required_argument, NULL, OPT_MAX_ACTIVE},
        {"token-symbol",   required_argument, NULL, OPT_TOKEN_SYMBOL},
        {"token-decimals", required_argument, NULL, OPT_TOKEN_DECIMALS},
        {"output",         required_argument, NULL, OPT_OUTPUT},
        {"timestamp",      required_argument, NULL, OPT_TIMESTAMP},
        {"parent-chain",   required_argument, NULL, OPT_PARENT_CHAIN},
        {"help",           no_argument,       NULL, OPT_HELP},
        {NULL, 0, NULL, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (c) {
            case OPT_CHAIN_NAME:     chain_name = optarg; break;
            case OPT_WITNESSES:      witnesses = strtol(optarg, NULL, 10); break;
            case OPT_PUBKEY_FILE:    pubkey_file = optarg; break;
            case OPT_SUPPLY:         supply = strtoull(optarg, NULL, 10); break;
            case OPT_RECIPIENT:      recipient = optarg; break;
            case OPT_MESSAGE:        message = optarg; break;
            case OPT_BLOCK_INTERVAL: block_interval = (uint32_t)strtoul(optarg, NULL, 10); break;
            case OPT_MAX_ACTIVE:     max_active = (uint32_t)strtoul(optarg, NULL, 10); break;
            case OPT_TOKEN_SYMBOL:   token_symbol = optarg; break;
            case OPT_TOKEN_DECIMALS: token_decimals = (int)strtol(optarg, NULL, 10); break;
            case OPT_OUTPUT:         output = optarg; break;
            case OPT_TIMESTAMP:      timestamp = strtoull(optarg, NULL, 10); break;
            case OPT_PARENT_CHAIN:   parent_hex = optarg; break;
            case OPT_HELP:           usage(argv[0]); return 0;
            default:                 usage(argv[0]); return 1;
        }
    }

    /* Validate required */
    if (!chain_name || witnesses <= 0 || !pubkey_file || supply == 0) {
        fprintf(stderr, "error: missing required argument\n");
        usage(argv[0]);
        return 1;
    }
    if (witnesses > DNAC_MAX_WITNESSES_COMPILE_CAP) {
        fprintf(stderr, "error: --witnesses must be <= %d\n",
                (int)DNAC_MAX_WITNESSES_COMPILE_CAP);
        return 1;
    }
    if (strlen(chain_name) >= DNAC_CHAIN_NAME_LEN) {
        fprintf(stderr, "error: --chain-name too long (max %d)\n",
                (int)(DNAC_CHAIN_NAME_LEN - 1));
        return 1;
    }
    if (token_decimals < 0 || token_decimals > 255) {
        fprintf(stderr, "error: --token-decimals out of range (0..255)\n");
        return 1;
    }
    if (strlen(token_symbol) >= DNAC_TOKEN_SYMBOL_LEN) {
        fprintf(stderr, "error: --token-symbol too long (max %d)\n",
                (int)(DNAC_TOKEN_SYMBOL_LEN - 1));
        return 1;
    }

    /* Read pubkey file */
    FILE *pf = fopen(pubkey_file, "rb");
    if (!pf) {
        fprintf(stderr, "error: cannot open pubkey file '%s': ", pubkey_file);
        perror(NULL);
        return 1;
    }
    static uint8_t pubkeys[DNAC_MAX_WITNESSES_COMPILE_CAP][DNAC_PUBKEY_SIZE];
    size_t want = (size_t)witnesses;
    size_t got = fread(pubkeys, DNAC_PUBKEY_SIZE, want, pf);
    /* Check for trailing bytes (file too long) */
    int trailing = (fgetc(pf) != EOF);
    fclose(pf);
    if (got != want) {
        fprintf(stderr, "error: pubkey file: expected %zu pubkeys (%zu bytes), got %zu\n",
                want, want * DNAC_PUBKEY_SIZE, got);
        return 1;
    }
    if (trailing) {
        fprintf(stderr, "error: pubkey file has trailing bytes after %zu pubkeys\n", want);
        return 1;
    }

    /* Build genesis block */
    dnac_block_t genesis;
    memset(&genesis, 0, sizeof genesis);
    genesis.block_height = 0;
    /* prev_block_hash: zeros (genesis) */
    /* state_root: zeros (empty initial UTXO set, no genesis TX yet) */
    /* tx_root: zeros (empty TX set) */
    genesis.tx_count = 0;
    genesis.timestamp = timestamp;
    /* proposer_id: zeros (genesis has no proposer) */

    dnac_chain_definition_t cd;
    memset(&cd, 0, sizeof cd);

    strncpy(cd.chain_name, chain_name, DNAC_CHAIN_NAME_LEN - 1);
    cd.protocol_version = 1;

    if (parent_hex) {
        if (parse_hex(parent_hex, cd.parent_chain_id, DNAC_BLOCK_HASH_SIZE) != 0) {
            fprintf(stderr, "error: invalid --parent-chain hex (need %d bytes)\n",
                    (int)(DNAC_BLOCK_HASH_SIZE * 2));
            return 1;
        }
    }

    char default_msg[DNAC_GENESIS_MESSAGE_LEN];
    if (!message) {
        snprintf(default_msg, sizeof default_msg,
                 "DNAC genesis %s %llu",
                 chain_name, (unsigned long long)timestamp);
        message = default_msg;
    }
    if (strlen(message) >= DNAC_GENESIS_MESSAGE_LEN) {
        fprintf(stderr, "error: --message too long (max %d)\n",
                (int)(DNAC_GENESIS_MESSAGE_LEN - 1));
        return 1;
    }
    strncpy(cd.genesis_message, message, DNAC_GENESIS_MESSAGE_LEN - 1);

    cd.witness_count = (uint32_t)witnesses;
    cd.max_active_witnesses = max_active;
    for (long i = 0; i < witnesses; i++) {
        memcpy(cd.witness_pubkeys[i], pubkeys[i], DNAC_PUBKEY_SIZE);
    }

    cd.block_interval_sec = block_interval;
    cd.max_txs_per_block = 10;
    cd.view_change_timeout_ms = 5000;

    strncpy(cd.token_symbol, token_symbol, DNAC_TOKEN_SYMBOL_LEN - 1);
    cd.token_decimals = (uint8_t)token_decimals;
    cd.initial_supply_raw = supply;
    /* native_token_id: zeros (native DNAC convention) */

    if (strcmp(recipient, "burn") == 0) {
        /* fee_recipient already zeros */
    } else {
        if (parse_hex(recipient, cd.fee_recipient, DNAC_FEE_RECIPIENT_SIZE) != 0) {
            fprintf(stderr, "error: invalid --recipient hex (need %d bytes) or 'burn'\n",
                    (int)(DNAC_FEE_RECIPIENT_SIZE * 2));
            return 1;
        }
    }

    /* Mark genesis and copy chain_def */
    if (dnac_block_set_genesis_def(&genesis, &cd) != 0) {
        fprintf(stderr, "error: dnac_block_set_genesis_def failed\n");
        return 1;
    }

    /* Compute block_hash (= chain_id for genesis) */
    if (dnac_block_compute_hash(&genesis) != 0) {
        fprintf(stderr, "error: dnac_block_compute_hash failed\n");
        return 1;
    }

    /* Encode to wire bytes */
    static uint8_t buf[131072];
    size_t len = 0;
    if (dnac_block_encode(&genesis, buf, sizeof buf, &len) != 0) {
        fprintf(stderr, "error: dnac_block_encode failed\n");
        return 1;
    }

    /* Write output file */
    FILE *of = fopen(output, "wb");
    if (!of) {
        fprintf(stderr, "error: cannot open output '%s': ", output);
        perror(NULL);
        return 1;
    }
    if (fwrite(buf, 1, len, of) != len) {
        perror("fwrite");
        fclose(of);
        return 1;
    }
    fclose(of);

    /* Report */
    printf("New chain_id: ");
    print_hex(genesis.block_hash, DNAC_BLOCK_HASH_SIZE);
    printf("\n\n");

    printf("C array literal for dnac/src/ledger/genesis_anchor.c:\n\n");
    printf("    {\n");
    printf("        .name = \"%s\",\n", chain_name);
    printf("        .chain_id = {\n");
    for (int i = 0; i < DNAC_BLOCK_HASH_SIZE; i++) {
        if (i % 8 == 0) printf("            ");
        printf("0x%02x,", genesis.block_hash[i]);
        if (i % 8 == 7) printf("\n");
        else printf(" ");
    }
    printf("        },\n");
    printf("    },\n\n");

    printf("Wrote %zu bytes to %s\n", len, output);
    return 0;
}
