/**
 * @file secp256k1_sign.c
 * @brief secp256k1 ECDSA recoverable signing utility
 *
 * Replaces duplicate inline signing blocks in eth_tx.c, trx_tx.c, eth_eip712.c.
 */

#include "crypto/sign/secp256k1_sign.h"
#include "crypto/utils/qgp_log.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <string.h>

#define LOG_TAG "SECP256K1_SIGN"

int secp256k1_sign_hash(
    const uint8_t private_key[32],
    const uint8_t hash[32],
    uint8_t sig_out[65],
    int *recovery_id_out
) {
    if (!private_key || !hash || !sig_out) {
        return -1;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create secp256k1 context");
        return -1;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash, private_key, NULL, NULL) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "secp256k1 recoverable sign failed");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    uint8_t sig_data[64];
    int recovery_id;
    if (secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_data, &recovery_id, &sig) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize signature");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    secp256k1_context_destroy(ctx);

    /* r(32) + s(32) + v(1) */
    memcpy(sig_out, sig_data, 64);
    sig_out[64] = (uint8_t)(27 + recovery_id);

    if (recovery_id_out) {
        *recovery_id_out = recovery_id;
    }

    return 0;
}
