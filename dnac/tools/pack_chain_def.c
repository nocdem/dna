/**
 * @file pack_chain_def.c
 * @brief Operator tool: pack a dnac_chain_definition_t into a binary file
 *
 * Reads chain parameters from the command line + a witness pubkey file
 * (N × 2592 byte Dilithium5 pubkeys concatenated), builds the chain_def
 * struct, calls dnac_chain_def_encode, and writes the resulting bytes
 * to stdout or --output <path>.
 *
 * The output file is then passed to `dna genesis-create ... --chain-def-file`
 * so the genesis TX carries the chain_def trailer and witnesses embed it
 * into the genesis block hash preimage.
 *
 * Usage:
 *   pack_chain_def --chain-name NAME --witnesses N --pubkey-file FILE \
 *                  --supply RAW [optional flags] --output chain_def.bin
 *
 * Required:
 *   --chain-name NAME       Chain name (max 31 chars)
 *   --witnesses N           Number of witness pubkeys in the file (1..21)
 *   --pubkey-file FILE      Binary concat of N * 2592 byte Dilithium5 pubkeys
 *   --supply RAW            Initial supply in raw units (uint64)
 *
 * Optional:
 *   --recipient FP          32-byte fingerprint for fee_recipient (hex or 'burn')
 *   --message MSG           Genesis message (max 63 chars)
 *   --block-interval SECS   Default: 5
 *   --max-active N          Default: 21
 *   --token-symbol STR      Default: "DNAC"
 *   --token-decimals N      Default: 8
 *   --output PATH           Default: "./chain_def.bin"
 *   --parent-chain HEX      Parent chain_id hex (64 bytes = 128 hex chars)
 */

#include "dnac/block.h"
#include "dnac/chain_def_codec.h"

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_hex(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
      "Usage: %s --chain-name NAME --witnesses N --pubkey-file FILE --supply RAW\n"
      "          [--recipient FP|burn] [--message MSG]\n"
      "          [--block-interval SECS] [--max-active N]\n"
      "          [--token-symbol STR] [--token-decimals N]\n"
      "          [--parent-chain HEX64B] [--output PATH]\n", argv0);
}

int main(int argc, char **argv) {
    const char *chain_name = NULL;
    int witnesses = 0;
    const char *pubkey_file = NULL;
    uint64_t supply = 0;
    const char *recipient = "burn";
    const char *message = NULL;
    uint32_t block_interval = 5;
    uint32_t max_active = 21;
    const char *token_symbol = "DNAC";
    int token_decimals = 8;
    const char *output = "./chain_def.bin";
    const char *parent_hex = NULL;

    static struct option opts[] = {
        {"chain-name",      required_argument, 0, 0},
        {"witnesses",       required_argument, 0, 0},
        {"pubkey-file",     required_argument, 0, 0},
        {"supply",          required_argument, 0, 0},
        {"recipient",       required_argument, 0, 0},
        {"message",         required_argument, 0, 0},
        {"block-interval",  required_argument, 0, 0},
        {"max-active",      required_argument, 0, 0},
        {"token-symbol",    required_argument, 0, 0},
        {"token-decimals",  required_argument, 0, 0},
        {"output",          required_argument, 0, 0},
        {"parent-chain",    required_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int long_idx = 0;
    int c;
    while ((c = getopt_long(argc, argv, "", opts, &long_idx)) != -1) {
        if (c != 0) { usage(argv[0]); return 1; }
        const char *name = opts[long_idx].name;
        if      (!strcmp(name, "chain-name"))      chain_name = optarg;
        else if (!strcmp(name, "witnesses"))       witnesses = atoi(optarg);
        else if (!strcmp(name, "pubkey-file"))     pubkey_file = optarg;
        else if (!strcmp(name, "supply"))          supply = strtoull(optarg, NULL, 10);
        else if (!strcmp(name, "recipient"))       recipient = optarg;
        else if (!strcmp(name, "message"))         message = optarg;
        else if (!strcmp(name, "block-interval"))  block_interval = (uint32_t)atoi(optarg);
        else if (!strcmp(name, "max-active"))      max_active = (uint32_t)atoi(optarg);
        else if (!strcmp(name, "token-symbol"))    token_symbol = optarg;
        else if (!strcmp(name, "token-decimals"))  token_decimals = atoi(optarg);
        else if (!strcmp(name, "output"))          output = optarg;
        else if (!strcmp(name, "parent-chain"))    parent_hex = optarg;
    }

    if (!chain_name || witnesses <= 0 || !pubkey_file || supply == 0) {
        usage(argv[0]);
        return 1;
    }
    if (witnesses > DNAC_MAX_WITNESSES_COMPILE_CAP) {
        fprintf(stderr, "witnesses %d exceeds compile cap %d\n",
                witnesses, DNAC_MAX_WITNESSES_COMPILE_CAP);
        return 1;
    }
    if (token_decimals < 0 || token_decimals > 255) {
        fprintf(stderr, "token-decimals out of range\n");
        return 1;
    }

    /* Read pubkey file: N × 2592 bytes */
    FILE *pf = fopen(pubkey_file, "rb");
    if (!pf) { perror("fopen pubkey-file"); return 1; }
    fseek(pf, 0, SEEK_END);
    long pk_size = ftell(pf);
    fseek(pf, 0, SEEK_SET);
    long expected = (long)witnesses * DNAC_PUBKEY_SIZE;
    if (pk_size != expected) {
        fprintf(stderr, "pubkey file size %ld != expected %ld (%d pubkeys × %d bytes)\n",
                pk_size, expected, witnesses, DNAC_PUBKEY_SIZE);
        fclose(pf);
        return 1;
    }
    dnac_chain_definition_t cd;
    memset(&cd, 0, sizeof(cd));
    for (int i = 0; i < witnesses; i++) {
        if (fread(cd.witness_pubkeys[i], 1, DNAC_PUBKEY_SIZE, pf)
            != (size_t)DNAC_PUBKEY_SIZE) {
            fprintf(stderr, "short read on witness %d\n", i);
            fclose(pf);
            return 1;
        }
    }
    fclose(pf);

    /* Populate chain_def */
    strncpy(cd.chain_name, chain_name, DNAC_CHAIN_NAME_LEN - 1);
    cd.protocol_version = 1;

    if (parent_hex) {
        if (parse_hex(parent_hex, cd.parent_chain_id, DNAC_BLOCK_HASH_SIZE) != 0) {
            fprintf(stderr, "invalid --parent-chain hex (must be 128 hex chars)\n");
            return 1;
        }
    }

    if (message) {
        strncpy(cd.genesis_message, message, DNAC_GENESIS_MESSAGE_LEN - 1);
    } else {
        snprintf(cd.genesis_message, DNAC_GENESIS_MESSAGE_LEN,
                  "DNAC %s genesis", chain_name);
    }

    cd.witness_count = (uint32_t)witnesses;
    cd.max_active_witnesses = max_active;

    cd.block_interval_sec = block_interval;
    cd.max_txs_per_block = 10;
    cd.view_change_timeout_ms = 5000;

    strncpy(cd.token_symbol, token_symbol, DNAC_TOKEN_SYMBOL_LEN - 1);
    cd.token_decimals = (uint8_t)token_decimals;
    cd.initial_supply_raw = supply;
    /* native_token_id stays zeros (all-zeros convention for native token) */

    if (strcmp(recipient, "burn") != 0) {
        if (parse_hex(recipient, cd.fee_recipient, DNAC_FEE_RECIPIENT_SIZE) != 0) {
            fprintf(stderr, "invalid --recipient hex (must be 64 hex chars or 'burn')\n");
            return 1;
        }
    }

    /* Encode */
    size_t cap = dnac_chain_def_max_size();
    uint8_t *buf = malloc(cap);
    if (!buf) { fprintf(stderr, "malloc failed\n"); return 1; }
    size_t enc_len = 0;
    if (dnac_chain_def_encode(&cd, buf, cap, &enc_len) != 0) {
        fprintf(stderr, "dnac_chain_def_encode failed\n");
        free(buf);
        return 1;
    }

    /* Write output */
    FILE *of = fopen(output, "wb");
    if (!of) { perror("fopen output"); free(buf); return 1; }
    if (fwrite(buf, 1, enc_len, of) != enc_len) {
        perror("fwrite");
        fclose(of);
        free(buf);
        return 1;
    }
    fclose(of);
    free(buf);

    printf("chain_def packed:\n");
    printf("  chain_name      : %s\n", cd.chain_name);
    printf("  witnesses       : %u\n", cd.witness_count);
    printf("  max_active      : %u\n", cd.max_active_witnesses);
    printf("  supply (raw)    : %llu\n", (unsigned long long)cd.initial_supply_raw);
    printf("  token_symbol    : %s\n", cd.token_symbol);
    printf("  token_decimals  : %u\n", (unsigned)cd.token_decimals);
    printf("  message         : %s\n", cd.genesis_message);
    printf("  output          : %s (%zu bytes)\n", output, enc_len);
    return 0;
}
