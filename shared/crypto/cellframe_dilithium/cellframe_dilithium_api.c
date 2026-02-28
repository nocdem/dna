#include "cellframe_dilithium_api.h"
#include "dilithium_sign.h"
#include "dilithium_params.h"
#include <stdlib.h>
#include <string.h>

int pqcrystals_cellframe_dilithium_signature(uint8_t *sig, size_t *siglen,
                                              const uint8_t *m, size_t mlen,
                                              const uint8_t *ctx, size_t ctxlen,
                                              const uint8_t *sk) {
    if (!sig || !siglen || !m || !sk) {
        return -1;
    }

    // Create Cellframe dilithium structures
    dilithium_private_key_t private_key = {
        .kind = MODE_1,
        .data = (unsigned char*)sk  // Cast away const
    };

    dilithium_signature_t signature = {0};

    // Sign the message
    int ret = dilithium_crypto_sign(&signature, m, mlen, &private_key);
    if (ret != 0) {
//         fprintf(stderr, "[DILITHIUM API] dilithium_crypto_sign failed: %d\n", ret);
        return ret;
    }

    // fprintf(stderr, "[DILITHIUM API] Signature created: sig_len=%zu, buffer_size=%zu, mlen=%zu\n",
    //         signature.sig_len, *siglen, mlen);

    // Return ATTACHED signature (signature + message) as Cellframe expects
    // dilithium_crypto_sign creates: sig_data = [signature | message]
    // Cellframe verification requires ATTACHED format (sig_len = CRYPTO_BYTES + mlen)
    if (signature.sig_len > *siglen) {
        // Output buffer too small
        // fprintf(stderr, "[DILITHIUM API] Buffer too small: need %zu, have %zu\n",
        //         signature.sig_len, *siglen);
        if (signature.sig_data) {
            free(signature.sig_data);
        }
        return -1;
    }

    // Copy the full attached signature (signature + message)
    memcpy(sig, signature.sig_data, signature.sig_len);
    *siglen = signature.sig_len;

    // Free signature
    if (signature.sig_data) {
        free(signature.sig_data);
    }

    return 0;
}

int pqcrystals_cellframe_dilithium_verify(const uint8_t *sig, size_t siglen,
                                           const uint8_t *m, size_t mlen,
                                           const uint8_t *ctx, size_t ctxlen,
                                           const uint8_t *pk) {
    if (!sig || !m || !pk) {
        return -1;
    }

    // Create Cellframe dilithium structures
    dilithium_public_key_t public_key = {
        .kind = MODE_1,
        .data = (unsigned char*)pk  // Cast away const
    };

    dilithium_signature_t signature = {
        .kind = MODE_1,
        .sig_data = (unsigned char*)sig,  // Cast away const
        .sig_len = siglen
    };

    // Verify the signature
    unsigned char *msg_out = malloc(mlen);
    if (!msg_out) {
        return -1;
    }

    int ret = dilithium_crypto_sign_open(msg_out, mlen, &signature, &public_key);

    free(msg_out);
    return ret;
}
