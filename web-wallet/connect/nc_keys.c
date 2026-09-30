/* Nodus Connect thin core — identity derivation (design rev 5 §1.5).
 *
 * Only calls the primitives the frozen app calls, in the same order and
 * with the same inputs (see nc_core.h nc_keys_from_words). keygen.c itself
 * is not compiled: it writes key files.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include "crypto/key/bip39/bip39.h"
#include "crypto/enc/kyber_r3_legacy.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/nodus_identity.h"

#include <string.h>

#define LOG_TAG "NC_KEYS"

extern void qgp_secure_memzero(void *ptr, size_t len);

int nc_keys_from_words(const char *words, nc_keys_t *out) {
    if (!words || !out) return NC_ERR_ARG;
    memset(out, 0, sizeof(*out));

    uint8_t signing_seed[32], encryption_seed[32];
    uint8_t master_seed[BIP39_SEED_SIZE];
    uint8_t mlkem_coins[QGP_MLKEM1024_COINS_BYTES];
    int rc = NC_ERR_INTERNAL;

    /* passphrase "": messenger/messenger/init.c:122, cli_commands.c:382 */
    if (qgp_derive_seeds_with_master(words, "", signing_seed, encryption_seed,
                                     master_seed) != 0) {
        QGP_LOG_WARN(LOG_TAG, "seed derivation refused the words");
        rc = NC_ERR_ARG;
        goto done;
    }
    /* ML-DSA-87 identity = nodus session identity (init.c:120-134). */
    if (nodus_identity_from_seed(signing_seed, &out->id) != 0) goto done;
    memcpy(out->fp, out->id.fingerprint, NC_FP_HEX_LEN);
    out->fp[NC_FP_HEX_LEN] = '\0';
    /* round-3 Kyber1024 from the encryption seed (keygen.c:217). */
    if (kyber_r3_keypair_derand(out->kyber_pk, out->kyber_sk,
                                encryption_seed) != 0) goto done;
    /* ML-KEM-1024 from the master seed (keygen.c:288-289). */
    if (qgp_derive_mlkem1024_coins(master_seed, mlkem_coins) != 0) goto done;
    if (qgp_mlkem1024_keypair_derand(out->mlkem_pk, out->mlkem_sk,
                                     mlkem_coins) != 0) goto done;
    rc = NC_OK;

done:
    qgp_secure_memzero(signing_seed, sizeof(signing_seed));
    qgp_secure_memzero(encryption_seed, sizeof(encryption_seed));
    qgp_secure_memzero(master_seed, sizeof(master_seed));
    qgp_secure_memzero(mlkem_coins, sizeof(mlkem_coins));
    if (rc != NC_OK) nc_keys_wipe(out);
    return rc;
}

void nc_keys_wipe(nc_keys_t *k) {
    if (!k) return;
    nodus_identity_clear(&k->id);
    qgp_secure_memzero(k, sizeof(*k));
}
