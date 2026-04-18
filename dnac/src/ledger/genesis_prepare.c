/**
 * @file genesis_prepare.c
 * @brief Phase 12 Task 58 — build a chain_def blob from an operator config.
 */

#include "dnac/genesis_prepare.h"
#include "dnac/block.h"
#include "dnac/chain_def_codec.h"
#include "dnac/dnac.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex2u8(char c, uint8_t *out) {
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return 0; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(10 + c - 'a'); return 0; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(10 + c - 'A'); return 0; }
    return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t len) {
    if (!hex || !out) return -1;
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        uint8_t hi, lo;
        if (hex2u8(hex[2*i], &hi) || hex2u8(hex[2*i + 1], &lo)) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void trim_trailing(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' ||
                     s[n-1] == ' '  || s[n-1] == '\t')) {
        s[--n] = '\0';
    }
}

static void seterr(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* Config keys we understand. Anything else triggers an unknown-key error. */
typedef struct {
    /* Global chain params. */
    char     chain_name[DNAC_CHAIN_NAME_LEN];
    uint32_t protocol_version;
    uint32_t witness_count;
    uint32_t max_active_witnesses;
    uint32_t block_interval_sec;
    uint32_t max_txs_per_block;
    uint32_t view_change_timeout_ms;
    char     token_symbol[DNAC_TOKEN_SYMBOL_LEN];
    uint8_t  token_decimals;
    uint64_t initial_supply_raw;
    char     genesis_message[DNAC_GENESIS_MESSAGE_LEN];
    uint8_t  parent_chain_id[DNAC_BLOCK_HASH_SIZE];
    uint8_t  parent_chain_id_present;

    /* Per-validator (indices 0..6). Bit mask of populated fields so we
     * can diagnose a missing key with a precise error. */
    uint8_t  validator_present[DNAC_COMMITTEE_SIZE];
    dnac_chain_initial_validator_t validators[DNAC_COMMITTEE_SIZE];
} op_config_t;

static int set_indexed_validator_field(op_config_t *c, int idx,
                                        const char *field, const char *value,
                                        char *err, size_t err_cap) {
    if (idx < 0 || idx >= DNAC_COMMITTEE_SIZE) {
        seterr(err, err_cap, "validator index %d out of range [0,%d]",
               idx, DNAC_COMMITTEE_SIZE - 1);
        return -1;
    }
    dnac_chain_initial_validator_t *v = &c->validators[idx];

    if (strcmp(field, "pubkey") == 0) {
        if (parse_hex(value, v->pubkey, DNAC_PUBKEY_SIZE) != 0) {
            seterr(err, err_cap, "validator_%d_pubkey: expected %d hex chars",
                   idx, (int)(DNAC_PUBKEY_SIZE * 2));
            return -1;
        }
        c->validator_present[idx] |= 0x1;
    } else if (strcmp(field, "fp") == 0) {
        size_t vlen = strlen(value);
        if (vlen >= DNAC_FINGERPRINT_SIZE) {
            seterr(err, err_cap,
                   "validator_%d_fp: too long (%zu >= %d)",
                   idx, vlen, DNAC_FINGERPRINT_SIZE);
            return -1;
        }
        memset(v->unstake_destination_fp, 0, DNAC_FINGERPRINT_SIZE);
        memcpy(v->unstake_destination_fp, value, vlen);
        c->validator_present[idx] |= 0x2;
    } else if (strcmp(field, "commission_bps") == 0) {
        char *end = NULL;
        long bps = strtol(value, &end, 10);
        if (!end || *end != '\0' || bps < 0 || bps > 10000) {
            seterr(err, err_cap,
                   "validator_%d_commission_bps: expected 0..10000, got '%s'",
                   idx, value);
            return -1;
        }
        v->commission_bps = (uint16_t)bps;
        c->validator_present[idx] |= 0x4;
    } else if (strcmp(field, "endpoint") == 0) {
        size_t vlen = strlen(value);
        if (vlen >= 128 /* DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN */) {
            seterr(err, err_cap, "validator_%d_endpoint: too long (%zu >= 128)",
                   idx, vlen);
            return -1;
        }
        memset(v->endpoint, 0, 128);
        memcpy(v->endpoint, value, vlen);
        c->validator_present[idx] |= 0x8;
    } else {
        seterr(err, err_cap,
               "validator_%d_%s: unknown field (pubkey|fp|commission_bps|endpoint)",
               idx, field);
        return -1;
    }
    return 0;
}

static int apply_key(op_config_t *c, const char *key, const char *value,
                      char *err, size_t err_cap) {
    if (strncmp(key, "validator_", 10) == 0) {
        /* validator_<idx>_<field> */
        const char *p = key + 10;
        char *idx_end = NULL;
        long idx = strtol(p, &idx_end, 10);
        if (!idx_end || *idx_end != '_') {
            seterr(err, err_cap, "malformed validator key '%s'", key);
            return -1;
        }
        return set_indexed_validator_field(c, (int)idx, idx_end + 1,
                                             value, err, err_cap);
    }

    if (strcmp(key, "chain_name") == 0) {
        size_t vlen = strlen(value);
        if (vlen >= DNAC_CHAIN_NAME_LEN) {
            seterr(err, err_cap, "chain_name too long (%zu >= %d)",
                   vlen, DNAC_CHAIN_NAME_LEN);
            return -1;
        }
        memset(c->chain_name, 0, DNAC_CHAIN_NAME_LEN);
        memcpy(c->chain_name, value, vlen);
        return 0;
    }
    if (strcmp(key, "protocol_version") == 0) {
        c->protocol_version = (uint32_t)strtoul(value, NULL, 10);
        return 0;
    }
    if (strcmp(key, "witness_count") == 0) {
        unsigned long v = strtoul(value, NULL, 10);
        if (v > 21) { seterr(err, err_cap, "witness_count %lu > 21", v); return -1; }
        c->witness_count = (uint32_t)v;
        return 0;
    }
    if (strcmp(key, "max_active_witnesses") == 0) {
        c->max_active_witnesses = (uint32_t)strtoul(value, NULL, 10);
        return 0;
    }
    if (strcmp(key, "block_interval_sec") == 0) {
        c->block_interval_sec = (uint32_t)strtoul(value, NULL, 10);
        return 0;
    }
    if (strcmp(key, "max_txs_per_block") == 0) {
        c->max_txs_per_block = (uint32_t)strtoul(value, NULL, 10);
        return 0;
    }
    if (strcmp(key, "view_change_timeout_ms") == 0) {
        c->view_change_timeout_ms = (uint32_t)strtoul(value, NULL, 10);
        return 0;
    }
    if (strcmp(key, "token_symbol") == 0) {
        size_t vlen = strlen(value);
        if (vlen >= DNAC_TOKEN_SYMBOL_LEN) {
            seterr(err, err_cap, "token_symbol too long (%zu >= %d)",
                   vlen, DNAC_TOKEN_SYMBOL_LEN);
            return -1;
        }
        memset(c->token_symbol, 0, DNAC_TOKEN_SYMBOL_LEN);
        memcpy(c->token_symbol, value, vlen);
        return 0;
    }
    if (strcmp(key, "token_decimals") == 0) {
        c->token_decimals = (uint8_t)strtoul(value, NULL, 10);
        return 0;
    }
    if (strcmp(key, "initial_supply_raw") == 0) {
        c->initial_supply_raw = strtoull(value, NULL, 10);
        return 0;
    }
    if (strcmp(key, "genesis_message") == 0) {
        size_t vlen = strlen(value);
        if (vlen >= DNAC_GENESIS_MESSAGE_LEN) {
            seterr(err, err_cap, "genesis_message too long (%zu >= %d)",
                   vlen, DNAC_GENESIS_MESSAGE_LEN);
            return -1;
        }
        memset(c->genesis_message, 0, DNAC_GENESIS_MESSAGE_LEN);
        memcpy(c->genesis_message, value, vlen);
        return 0;
    }
    if (strcmp(key, "parent_chain_id") == 0) {
        if (parse_hex(value, c->parent_chain_id, DNAC_BLOCK_HASH_SIZE) != 0) {
            seterr(err, err_cap, "parent_chain_id: expected %d hex chars",
                   (int)(DNAC_BLOCK_HASH_SIZE * 2));
            return -1;
        }
        c->parent_chain_id_present = 1;
        return 0;
    }

    seterr(err, err_cap, "unknown key '%s'", key);
    return -1;
}

int dnac_cli_genesis_prepare_blob(const char *config_path,
                                    uint8_t *blob_out,
                                    size_t blob_cap,
                                    size_t *blob_len_out,
                                    char *err_out,
                                    size_t err_cap) {
    if (!config_path || !blob_out || !blob_len_out) {
        seterr(err_out, err_cap, "NULL argument");
        return -1;
    }

    FILE *f = fopen(config_path, "r");
    if (!f) {
        seterr(err_out, err_cap, "fopen(%s): %s", config_path, strerror(errno));
        return -1;
    }

    op_config_t c;
    memset(&c, 0, sizeof(c));
    /* Sensible defaults so minimal configs work. */
    c.protocol_version       = 1;
    c.max_active_witnesses   = 21;
    c.block_interval_sec     = 5;
    c.max_txs_per_block      = 10;
    c.view_change_timeout_ms = 5000;
    memcpy(c.token_symbol, "DNAC", 4);
    c.token_decimals         = 8;
    c.initial_supply_raw     = DNAC_DEFAULT_TOTAL_SUPPLY;

    char line[8192];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        trim_trailing(line);

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;

        char *eq = strchr(p, '=');
        if (!eq) {
            seterr(err_out, err_cap, "line %d: missing '='", lineno);
            fclose(f);
            return -1;
        }
        *eq = '\0';
        char *key = p;
        char *value = eq + 1;
        while (*value == ' ' || *value == '\t') value++;
        char *key_end = eq - 1;
        while (key_end > key && (*key_end == ' ' || *key_end == '\t')) {
            *key_end-- = '\0';
        }

        if (apply_key(&c, key, value, err_out, err_cap) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);

    /* Every validator slot must have all 4 fields set. */
    for (int i = 0; i < DNAC_COMMITTEE_SIZE; i++) {
        if (c.validator_present[i] != 0xF) {
            uint8_t miss = (uint8_t)(~c.validator_present[i] & 0xF);
            const char *which =
                (miss & 0x1) ? "pubkey" :
                (miss & 0x2) ? "fp" :
                (miss & 0x4) ? "commission_bps" : "endpoint";
            seterr(err_out, err_cap,
                   "validator_%d_%s missing", i, which);
            return -1;
        }
    }

    /* Pairwise-distinct pubkey check (Rule P.3 canary — matches verify). */
    for (int i = 0; i < DNAC_COMMITTEE_SIZE; i++) {
        for (int j = i + 1; j < DNAC_COMMITTEE_SIZE; j++) {
            if (memcmp(c.validators[i].pubkey,
                       c.validators[j].pubkey,
                       DNAC_PUBKEY_SIZE) == 0) {
                seterr(err_out, err_cap,
                       "duplicate pubkey at validator_%d and validator_%d",
                       i, j);
                return -1;
            }
        }
    }

    /* Populate chain_def and encode. */
    dnac_chain_definition_t cd;
    memset(&cd, 0, sizeof(cd));
    memcpy(cd.chain_name, c.chain_name, DNAC_CHAIN_NAME_LEN);
    cd.protocol_version = c.protocol_version;
    if (c.parent_chain_id_present) {
        memcpy(cd.parent_chain_id, c.parent_chain_id, DNAC_BLOCK_HASH_SIZE);
    }
    memcpy(cd.genesis_message, c.genesis_message, DNAC_GENESIS_MESSAGE_LEN);
    cd.witness_count         = c.witness_count;
    cd.max_active_witnesses  = c.max_active_witnesses;
    cd.block_interval_sec    = c.block_interval_sec;
    cd.max_txs_per_block     = c.max_txs_per_block;
    cd.view_change_timeout_ms= c.view_change_timeout_ms;
    memcpy(cd.token_symbol, c.token_symbol, DNAC_TOKEN_SYMBOL_LEN);
    cd.token_decimals        = c.token_decimals;
    cd.initial_supply_raw    = c.initial_supply_raw;
    /* native_token_id stays zero (native DNAC). fee_recipient stays zero (burn). */

    cd.initial_validator_count = DNAC_COMMITTEE_SIZE;
    memcpy(cd.initial_validators, c.validators,
           sizeof(cd.initial_validators));

    size_t need = dnac_chain_def_encoded_size(&cd);
    if (need == 0) {
        seterr(err_out, err_cap, "dnac_chain_def_encoded_size returned 0");
        return -1;
    }
    if (blob_cap < need) {
        seterr(err_out, err_cap, "blob_cap %zu < required %zu", blob_cap, need);
        return -1;
    }

    if (dnac_chain_def_encode(&cd, blob_out, blob_cap, blob_len_out) != 0) {
        seterr(err_out, err_cap, "dnac_chain_def_encode failed");
        return -1;
    }
    return 0;
}
