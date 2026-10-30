#include "crypto/sign/dsa/sign.h"
#include "qgp_mldsa.h"

int DILITHIUM_NAMESPACE(get_params)(qgp_mldsa_params *out)
{
    out->public_key_bytes = CRYPTO_PUBLICKEYBYTES;
    out->secret_key_bytes = CRYPTO_SECRETKEYBYTES;
    out->signature_bytes = CRYPTO_BYTES;
    out->seed_bytes = SEEDBYTES;
    out->random_bytes = RNDBYTES;
    return 0;
}
