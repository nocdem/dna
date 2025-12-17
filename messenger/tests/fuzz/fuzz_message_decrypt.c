/**
 * @file fuzz_message_decrypt.c
 * @brief libFuzzer harness for DNA message decryption
 *
 * Fuzzes dna_decrypt_message_raw() which parses and decrypts
 * v0.08 encrypted messages.
 *
 * Message Format:
 * [8-byte magic "PQSIGENC"][1-byte version][1-byte enc_key_type]
 * [1-byte recipient_count][1-byte message_type]
 * [Per recipient: kyber_ct(1568) + wrapped_dek(40)]
 * [12-byte nonce][ciphertext][16-byte GCM tag][signature]
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "dna_api.h"
#include "fuzz_common.h"

/* Static fake keys and context - initialized once for determinism */
static uint8_t s_kyber_privkey[FUZZ_KYBER1024_PRIVKEY_SIZE];
static dna_context_t *s_ctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /*
     * Minimum message size estimate:
     * header(12) + 1 recipient entry(1608) + nonce(12) + tag(16) = ~1648 bytes
     * Use smaller threshold to test header parsing edge cases
     */
    if (size < 16) {
        return 0;
    }

    /* One-time initialization */
    if (!s_ctx) {
        s_ctx = dna_context_new();
        fuzz_generate_fake_kyber_privkey(s_kyber_privkey, 12345);
    }

    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint8_t *sender_pubkey = NULL;
    size_t sender_pubkey_len = 0;
    uint8_t *signature = NULL;
    size_t signature_len = 0;
    uint64_t timestamp = 0;

    /* This should handle malformed ciphertext gracefully */
    dna_error_t result = dna_decrypt_message_raw(
        s_ctx,
        data, size,
        s_kyber_privkey,
        &plaintext, &plaintext_len,
        &sender_pubkey, &sender_pubkey_len,
        &signature, &signature_len,
        &timestamp
    );

    /* Free any allocated memory */
    if (plaintext) free(plaintext);
    if (sender_pubkey) free(sender_pubkey);
    if (signature) free(signature);

    (void)result;  /* Suppress unused variable warning */
    return 0;
}
