/**
 * @file eth_eip712.c
 * @brief EIP-712 Typed Data Signing Implementation
 *
 * Generic EIP-712 utilities extracted from CoW Protocol integration.
 * Provides domain separator computation and typed data signing.
 *
 * @author DNA Messenger Team
 */

#include "eth_eip712.h"
#include "crypto/hash/keccak256.h"
#include "crypto/sign/secp256k1_sign.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>
#include <stdio.h>

#define LOG_TAG "ETH_EIP712"

int eth_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    const char *p = hex;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    size_t hex_len = strlen(p);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(p + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

void eth_decimal_to_uint256(const char *str, uint8_t out[32]) {
    memset(out, 0, 32);
    __uint128_t val = 0;
    for (const char *p = str; *p; p++) {
        if (*p >= '0' && *p <= '9') val = val * 10 + (uint8_t)(*p - '0');
    }
    for (int i = 0; i < 16; i++) {
        out[31 - i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

int eip712_compute_domain_separator(
    const char *name,
    const char *version,
    uint64_t chain_id,
    const char *verifying_contract,
    uint8_t domain_hash_out[32]
) {
    if (!name || !version || !verifying_contract || !domain_hash_out) return -1;

    uint8_t buf[5 * 32];  /* 5 fields x 32 bytes */

    /* Type hash */
    const char *type_str = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    keccak256((const uint8_t *)type_str, strlen(type_str), buf);

    /* keccak256(name) */
    keccak256((const uint8_t *)name, strlen(name), buf + 32);

    /* keccak256(version) */
    keccak256((const uint8_t *)version, strlen(version), buf + 64);

    /* chainId as uint256 */
    memset(buf + 96, 0, 32);
    for (int i = 0; i < 8; i++) {
        buf[127 - i] = (uint8_t)((chain_id >> (i * 8)) & 0xFF);
    }

    /* verifyingContract (address, left-padded to 32 bytes) */
    memset(buf + 128, 0, 32);
    if (eth_hex_to_bytes(verifying_contract, buf + 128 + 12, 20) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid verifying contract: %s", verifying_contract);
        return -1;
    }

    keccak256(buf, sizeof(buf), domain_hash_out);
    return 0;
}

int eip712_sign_typed_data(
    const uint8_t private_key[32],
    const uint8_t domain_separator[32],
    const uint8_t struct_hash[32],
    uint8_t sig_out[65]
) {
    if (!private_key || !domain_separator || !struct_hash || !sig_out) return -1;

    /* EIP-712 message: "\x19\x01" || domainSeparator || structHash */
    uint8_t msg[66];
    msg[0] = 0x19;
    msg[1] = 0x01;
    memcpy(msg + 2, domain_separator, 32);
    memcpy(msg + 34, struct_hash, 32);

    uint8_t msg_hash[32];
    keccak256(msg, 66, msg_hash);

    /* Sign with secp256k1 */
    if (secp256k1_sign_hash(private_key, msg_hash, sig_out, NULL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "EIP-712 signing failed");
        return -1;
    }

    return 0;
}
