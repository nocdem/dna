/* Key-generation bridge: public keys, plus one restricted secret-key export.
 * Selectors are application routing, not wire IDs.
 * Input/output/secret storage is shared by calls; callers must serialize operations.
 * The only secret accessors are pq_receive_secret and pq_receive_secret_size, and
 * they serve kind 2 / parameter 512 (Tidecoin Falcon-512, 1281-byte secret key) only:
 * the native Tidecoin hardened child step consumes the parent secret key. After a
 * successful kind 2 / parameter 512 derivation the secret stays in the shared
 * storage until pq_receive_clear (or the next pq_receive_derive call). An error,
 * and every other kind and parameter, wipes the secret before the call returns.
 * Clear after copying the public key and, for Tidecoin, the secret key.
 */
#include "crypto/sign/algorand_falcon/qgp_algorand_falcon.h"
#include "crypto/sign/tidecoin_falcon/qgp_tidecoin_falcon.h"
#include "crypto/sign/mldsa/qgp_mldsa.h"
#include "crypto/sign/slhdsa/qgp_slhdsa.h"

static uint8_t input[96];
static uint8_t output[1952];
/* ML-DSA-65 is the largest supported secret key. */
static uint8_t secret[4032];

static void wipe(uint8_t *data, size_t length)
{
    volatile uint8_t *p = data;
    while (length--) *p++ = 0;
}

static int sizes(int kind, int param, size_t *seed, size_t *pk, size_t *sk)
{
    qgp_mldsa_params m;
    qgp_slhdsa_params s;
    if (kind == 1 && param == 1024) {
        *seed = 32;
        *pk = QGP_ALGORAND_FALCON_PUBLIC_KEY_SIZE;
        *sk = QGP_ALGORAND_FALCON_SECRET_KEY_SIZE;
    } else if (kind == 2 && param == 512) {
        *seed = QGP_TIDECOIN_FALCON_SEEDBYTES;
        *pk = QGP_TIDECOIN_FALCON_PUBLICKEYBYTES;
        *sk = QGP_TIDECOIN_FALCON_SECRETKEYBYTES;
    } else if (kind == 3 && (param == 44 || param == 65)) {
        if (qgp_mldsa_get_params(param, &m)) return -1;
        *seed = m.seed_bytes;
        *pk = m.public_key_bytes;
        *sk = m.secret_key_bytes;
    } else if (kind == 4 && param >= 0 && param <= 11) {
        if (qgp_slhdsa_get_params(param, &s)) return -1;
        *seed = s.seed_bytes;
        *pk = s.public_key_bytes;
        *sk = s.secret_key_bytes;
    } else {
        return -1;
    }
    if (!*seed || !*pk || !*sk || *seed > sizeof input ||
        *pk > sizeof output || *sk > sizeof secret) return -1;
    return 0;
}

uint8_t *pq_receive_input(void) { return input; }
uint8_t *pq_receive_output(void) { return output; }
uint8_t *pq_receive_secret(void) { return secret; }

/* Secret-key size of the restricted export: nonzero for kind 2 / parameter 512 only. */
int pq_receive_secret_size(int kind, int param)
{
    size_t seed, pk, sk;
    if (kind != 2 || param != 512 || sizes(kind, param, &seed, &pk, &sk)) return 0;
    return (int)sk;
}

int pq_receive_seed_size(int kind, int param)
{
    size_t seed, pk, sk;
    return sizes(kind, param, &seed, &pk, &sk) ? 0 : (int)seed;
}

int pq_receive_public_size(int kind, int param)
{
    size_t seed, pk, sk;
    return sizes(kind, param, &seed, &pk, &sk) ? 0 : (int)pk;
}

void pq_receive_clear(void)
{
    wipe(input, sizeof input);
    wipe(output, sizeof output);
    wipe(secret, sizeof secret);
}

int pq_receive_derive(int kind, int param, int seed_len)
{
    size_t seed, pk, sk;
    int result = -1;
    wipe(output, sizeof output);
    wipe(secret, sizeof secret);
    if (sizes(kind, param, &seed, &pk, &sk) || seed_len < 0 ||
        (size_t)seed_len != seed) goto cleanup;
    switch (kind) {
    case 1:
        result = qgp_algorand_falcon_keypair_from_seed(output, pk,
            secret, sk, input, seed);
        break;
    case 2:
        result = qgp_tidecoin_falcon_keypair_from_seed(output, pk,
            secret, sk, input, seed);
        break;
    case 3:
        result = qgp_mldsa_keypair_from_seed(param, output, pk,
            secret, sk, input, seed);
        break;
    case 4:
        result = qgp_slhdsa_keypair_from_seed(param, output, pk,
            secret, sk, input, seed);
        break;
    }
cleanup:
    wipe(input, sizeof input);
    /* Only a successful kind 2 / parameter 512 derivation keeps its secret. */
    if (result || kind != 2 || param != 512) wipe(secret, sizeof secret);
    if (result) wipe(output, sizeof output);
    return result;
}
