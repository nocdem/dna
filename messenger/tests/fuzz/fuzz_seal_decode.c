/**
 * @file fuzz_seal_decode.c
 * @brief libFuzzer harness: Seal (1:1 message envelope) decode, including
 *        the part behind a successful key decapsulation.
 *
 * Entry points (exported, compiled into this target unchanged from
 * messenger/dna_api.c so libFuzzer sees their coverage):
 *   dna_decrypt_message_raw_alg   dna_api.c:468
 *   dna_verify_seal_authorship    dna_api.c:725
 *   dna_encrypt_message_raw_alg   dna_api.c (harness init only)
 *
 * Why two modes. The existing fuzz_message_decrypt feeds random bytes with a
 * fake key: decapsulation + key unwrap never succeed, so every check after
 * `found_entry` (dna_api.c, "Read nonce, encrypted data, tag" onwards: the
 * encrypted_size / signature_size bounds checks, signature deserialize,
 * AES-GCM, payload split) is unreachable. Any SENDER can reach them — the
 * recipient's public key is public — so this target builds a real Seal to
 * its own ML-KEM-1024 key at start-up and lets the input edit it.
 *
 * Input byte 0 selects the mode (low bit):
 *   0  raw:     bytes 1.. are the whole Seal, decrypted with the local
 *               round-3 and ML-KEM-1024 private keys (fuzz_keys.h).
 *   1  overlay: bytes 1..10 overwrite Seal header bytes 10..19
 *               (recipient_count, message_type, encrypted_size,
 *               signature_size — header layout dna_api.c:62-74, packed);
 *               bytes 11.. replace everything after the first recipient
 *               entry (nonce, ciphertext, tag, signature). With no bytes
 *               after 10 the real tail is kept, so a size-field edit is
 *               tested against an otherwise valid message.
 *
 * On success the returned signature is checked against the local signing
 * key the way every caller does (dna_verify_seal_authorship).
 *
 * The real Seal is re-encrypted at every process start with fresh random
 * DEK / nonce / KEM coins (qgp_randombytes); its structure and lengths are
 * the same every run, so a crash input reproduces.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "dna_api.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"
#include "fuzz_keys.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* dna_api.c:62-74: magic(8) version(1) enc_key_type(1) recipient_count(1)
 * message_type(1) encrypted_size(4) signature_size(4) */
#define SEAL_HEADER_BYTES        20
#define SEAL_PATCH_OFFSET        10   /* recipient_count onwards */
#define SEAL_PATCH_BYTES         10
/* dna_recipient_entry_t: KEM ciphertext(1568) + wrapped DEK(40) */
#define SEAL_RECIPIENT_ENTRY     (1568 + 40)

static fuzz_identity_t *s_self;
static dna_context_t   *s_ctx;
static uint8_t         *s_seal;
static size_t           s_seal_len;

static int init_once(void) {
    if (s_ctx) {
        return 0;
    }
    qgp_log_set_level(QGP_LOG_LEVEL_NONE);

    s_self = calloc(1, sizeof(*s_self));
    if (!s_self || fuzz_identity_derive(s_self, FUZZ_ID_SELF) != 0) {
        abort();
    }
    s_ctx = dna_context_new();
    if (!s_ctx) {
        abort();
    }
    static const char msg[] = "fuzz_seal_decode reference plaintext";
    if (dna_encrypt_message_raw_alg(s_ctx, (const uint8_t *)msg, sizeof(msg) - 1,
                                    s_self->mlkem_pk, s_self->sign_pk, s_self->sign_sk,
                                    1700000000ull, (uint8_t)QGP_KEY_TYPE_MLKEM1024,
                                    &s_seal, &s_seal_len) != DNA_OK
        || s_seal_len < SEAL_HEADER_BYTES + SEAL_RECIPIENT_ENTRY) {
        abort();
    }
    return 0;
}

static void decode(const uint8_t *msg, size_t len) {
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    uint8_t *sender_fp = NULL;
    size_t sender_fp_len = 0;
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    uint64_t ts = 0;

    dna_error_t rc = dna_decrypt_message_raw_alg(s_ctx, msg, len,
                                                 s_self->kyber_sk, s_self->mlkem_sk,
                                                 &plaintext, &plaintext_len,
                                                 &sender_fp, &sender_fp_len,
                                                 &sig, &sig_len, &ts);
    if (rc == DNA_OK && plaintext && sender_fp && sender_fp_len == 64 && sig) {
        (void)dna_verify_seal_authorship(plaintext, plaintext_len, sig, sig_len,
                                         s_self->sign_pk, FUZZ_SIGN_PK_BYTES,
                                         sender_fp, NULL);
    }
    free(plaintext);
    free(sender_fp);
    free(sig);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    init_once();

    if ((data[0] & 1) == 0) {
        /* raw: exact-size copy so ASan sees the real end of the message */
        size_t len = size - 1;
        uint8_t *msg = malloc(len ? len : 1);
        if (!msg) {
            return 0;
        }
        if (len) {
            memcpy(msg, data + 1, len);
        }
        decode(msg, len);
        free(msg);
        return 0;
    }

    /* overlay */
    size_t patch = size - 1 < SEAL_PATCH_BYTES ? size - 1 : SEAL_PATCH_BYTES;
    const uint8_t *tail = data + 1 + patch;
    size_t tail_len = size - 1 - patch;
    size_t keep = SEAL_HEADER_BYTES + SEAL_RECIPIENT_ENTRY;
    size_t len = tail_len ? keep + tail_len : s_seal_len;

    uint8_t *msg = malloc(len);
    if (!msg) {
        return 0;
    }
    if (tail_len) {
        memcpy(msg, s_seal, keep);
        memcpy(msg + keep, tail, tail_len);
    } else {
        memcpy(msg, s_seal, s_seal_len);
    }
    memcpy(msg + SEAL_PATCH_OFFSET, data + 1, patch);
    decode(msg, len);
    free(msg);
    return 0;
}
