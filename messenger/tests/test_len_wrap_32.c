/*
 * test_len_wrap_32 — length checks that must not wrap with a 32-bit size_t.
 *
 * Regression for the two 2026-09-30 NC-5 fuzz findings (messenger/BUGS.md):
 *
 *   A. Seal decode, dna_decrypt_message_raw_alg (dna_api.c): the checks were
 *        offset + 12 + encrypted_size + 16 > ciphertext_len
 *        offset + signature_size <= ciphertext_len
 *      with encrypted_size / signature_size taken from uint32_t header fields.
 *   B. Contact-list blob, dht_contactlist_fetch (dht/client/dht_contactlist.c):
 *        offset + encrypted_len + 4 > blob_size
 *        offset + sig_len != blob_size
 *      with encrypted_len / sig_len taken from big-endian uint32_t fields.
 *
 * With a 64-bit size_t (this build) none of those sums can wrap, so the old
 * and the new code both reject every crafted input here and this test passes
 * on both — on 64-bit it pins that the rewrite (remaining-length form) keeps
 * the same accept/reject on valid, truncated and oversized inputs. With a
 * 32-bit size_t (-m32, wasm32) the old code FAILS it:
 *
 *   seal_encrypted_size_wrap   encrypted_size = 2^32 - (offset + 28): the old
 *                              sum is 0 and passes; offset then wraps behind
 *                              the buffer (16 bytes before it) and the tag
 *                              memcpy reads out of bounds — ASan (Debug)
 *                              reports a heap-buffer-overflow there. Without
 *                              ASan the rc assertion likely still passes (the
 *                              signature parse then sees "PQ" as type/size and
 *                              returns DECRYPT), so only ASan catches this
 *                              case. (The reproduced wasm32 crash, READ 4627
 *                              in qgp_signature_deserialize, came from a
 *                              different fuzz input.)
 *   seal_signature_size_wrap   signature_size = 2^32 - offset + 1: the old
 *                              sum is 1 and passes; qgp_signature_deserialize
 *                              bounds itself by the signature's OWN embedded
 *                              size, so no out-of-bounds read — decryption
 *                              then succeeds and returns DNA_OK: the
 *                              rc == DNA_ERROR_DECRYPT assertion fails
 *                              deterministically on old 32-bit code.
 *                              (qgp_signature.c:152-187, read by the agent
 *                              after committing; wording fixed at O7.)
 *   contactlist_len_wrap       encrypted_len = 2^32 - 16: the old sum is 13
 *                              and passes; offset wraps back to 9 (inside the
 *                              timestamp), sig_len is read from bytes the
 *                              test chose so that offset + sig_len ==
 *                              blob_size, and the Seal at byte 25 is handed
 *                              to the decrypt with a ~4 GB length. The Seal
 *                              is a real self-sealed contact list, so the old
 *                              code decrypts it, the authorship check passes
 *                              and dht_contactlist_fetch returns 0 on a
 *                              malformed blob: the rc == -1 assertion fails
 *                              deterministically, no sanitizer needed.
 *
 * dht_contactlist.c is compiled into this executable together with
 * tests/fuzz/fuzz_dht_stub.c, so its nodus_ops_get_str / _put_str_exclusive
 * calls reach the in-memory stub (the executable's definitions take
 * precedence over libdna.so's) — no network, no DHT.
 *
 * Seal header layout (dna_api.c dna_enc_header_t, packed, host byte order):
 * magic(8) version(1) enc_key_type(1) recipient_count(1) message_type(1)
 * encrypted_size(4 @12) signature_size(4 @16); recipient entry = 1568 + 40.
 * Contact-list blob (dht_contactlist.c publish/fetch): magic(4) version(1)
 * timestamp(8) expiry(8) enc_len(4 BE @21) seal(enc_len) sig_len(4 BE) sig.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dna_api.h"
#include "dht/client/dht_contactlist.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "fuzz_dht_stub.h"

#define SEAL_HEADER_BYTES     20
#define SEAL_RCPT_COUNT_OFF   10
#define SEAL_ENC_SIZE_OFF     12
#define SEAL_SIG_SIZE_OFF     16
#define SEAL_RECIPIENT_ENTRY  (1568 + 40)
#define SEAL_NONCE_TAG        (12 + 16)

#define CL_ENC_LEN_OFF        21
#define CL_SEAL_OFF           25

static int g_failures = 0;

#define CHECK(cond, name) do {                                   \
    if (cond) { printf("  PASS  %s\n", name); }                  \
    else { printf("  FAIL  %s\n", name); g_failures++; }         \
} while (0)

static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Decrypt `len` bytes from an exact-size heap copy (so ASan sees the real
 * end of the message). Returns the rc; *all_null is set when every output
 * pointer is still NULL (the error path must not hand anything back). */
static dna_error_t seal_decode(dna_context_t *ctx, const uint8_t *msg, size_t len,
                               const uint8_t *kyber_priv, int *all_null) {
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy) {
        return DNA_ERROR_MEMORY;
    }
    memcpy(copy, msg, len);

    uint8_t *pt = NULL, *fp = NULL, *sig = NULL;
    size_t pt_len = 0, fp_len = 0, sig_len = 0;
    uint64_t ts = 0;
    dna_error_t rc = dna_decrypt_message_raw(ctx, copy, len, kyber_priv,
                                             &pt, &pt_len, &fp, &fp_len,
                                             &sig, &sig_len, &ts);
    if (all_null) {
        *all_null = (pt == NULL && fp == NULL && sig == NULL);
    }
    free(pt);
    free(fp);
    free(sig);
    free(copy);
    return rc;
}

static int test_seal(dna_context_t *ctx,
                     const uint8_t *kyber_pub, const uint8_t *kyber_priv,
                     const uint8_t *dsa_pub, const uint8_t *dsa_priv) {
    printf("Seal decode (dna_decrypt_message_raw_alg)\n");

    static const char msg[] = "len-wrap regression plaintext";
    uint8_t *seal = NULL;
    size_t seal_len = 0;
    if (dna_encrypt_message_raw(ctx, (const uint8_t *)msg, sizeof(msg) - 1,
                                kyber_pub, dsa_pub, dsa_priv,
                                (uint64_t)time(NULL), &seal, &seal_len) != DNA_OK) {
        printf("  FAIL  setup: encrypt\n");
        return -1;
    }
    size_t body_off = SEAL_HEADER_BYTES +
                      (size_t)seal[SEAL_RCPT_COUNT_OFF] * SEAL_RECIPIENT_ENTRY;
    uint32_t enc_size = 0;
    memcpy(&enc_size, seal + SEAL_ENC_SIZE_OFF, 4);
    if (seal_len < body_off + SEAL_NONCE_TAG + enc_size) {
        printf("  FAIL  setup: unexpected seal layout\n");
        free(seal);
        return -1;
    }
    size_t tail_off = body_off + SEAL_NONCE_TAG + enc_size;   /* signature start */

    int all_null = 0;
    CHECK(seal_decode(ctx, seal, seal_len, kyber_priv, NULL) == DNA_OK,
          "seal_valid_roundtrip (unchanged: accepted)");

    CHECK(seal_decode(ctx, seal, seal_len - 1, kyber_priv, &all_null) == DNA_ERROR_DECRYPT
          && all_null,
          "seal_truncated_by_one (unchanged: rejected)");

    uint8_t *m = malloc(seal_len);
    if (!m) {
        free(seal);
        return -1;
    }

    /* encrypted_size one byte too large: must still be rejected */
    memcpy(m, seal, seal_len);
    uint32_t v = (uint32_t)(seal_len - body_off - SEAL_NONCE_TAG) + 1u;
    memcpy(m + SEAL_ENC_SIZE_OFF, &v, 4);
    CHECK(seal_decode(ctx, m, seal_len, kyber_priv, &all_null) == DNA_ERROR_DECRYPT
          && all_null,
          "seal_encrypted_size_past_end (unchanged: rejected)");

    /* encrypted_size so that offset + 28 + encrypted_size == 2^32 */
    memcpy(m, seal, seal_len);
    v = (uint32_t)(0u - (uint32_t)(body_off + SEAL_NONCE_TAG));
    memcpy(m + SEAL_ENC_SIZE_OFF, &v, 4);
    CHECK(seal_decode(ctx, m, seal_len, kyber_priv, &all_null) == DNA_ERROR_DECRYPT
          && all_null,
          "seal_encrypted_size_wrap (32-bit old code: tag read out of bounds, ASan)");

    /* signature_size so that offset + signature_size == 2^32 + 1 */
    memcpy(m, seal, seal_len);
    v = (uint32_t)(0u - (uint32_t)tail_off) + 1u;
    memcpy(m + SEAL_SIG_SIZE_OFF, &v, 4);
    CHECK(seal_decode(ctx, m, seal_len, kyber_priv, &all_null) == DNA_ERROR_DECRYPT
          && all_null,
          "seal_signature_size_wrap (32-bit old code: accepted, returns DNA_OK)");

    free(m);
    free(seal);
    return 0;
}

/* Load `blob` as the stored value and fetch. Returns the fetch rc; on
 * success *count_out is the number of contacts returned. */
static int cl_fetch(const uint8_t *blob, size_t blob_len, const char *identity,
                    const uint8_t *kyber_priv, const uint8_t *dsa_pub,
                    size_t *count_out) {
    const uint8_t *vals[1] = { blob };
    size_t lens[1] = { blob_len };
    fuzz_dht_stub_load(vals, lens, 1);

    char **contacts = NULL;
    size_t count = 0;
    uint8_t **salts = NULL;
    int rc = dht_contactlist_fetch(identity, &contacts, &count, &salts,
                                   kyber_priv, dsa_pub);
    if (rc == 0) {
        dht_contactlist_free_salts(salts, count);
        dht_contactlist_free_contacts(contacts, count);
    }
    if (count_out) {
        *count_out = count;
    }
    fuzz_dht_stub_reset();
    return rc;
}

static int test_contactlist(const uint8_t *kyber_pub, const uint8_t *kyber_priv,
                            const uint8_t *dsa_pub, const uint8_t *dsa_priv,
                            const uint8_t *contact_dsa_pub) {
    printf("Contact-list blob (dht_contactlist_fetch)\n");

    char identity[129];
    char contact_fp[129];
    if (qgp_sha3_512_fingerprint(dsa_pub, QGP_DSA87_PUBLICKEYBYTES, identity) != 0 ||
        qgp_sha3_512_fingerprint(contact_dsa_pub, QGP_DSA87_PUBLICKEYBYTES, contact_fp) != 0) {
        printf("  FAIL  setup: fingerprints\n");
        return -1;
    }

    /* One real publish, captured by the stub */
    const char *contacts[1] = { contact_fp };
    fuzz_dht_stub_reset();
    if (dht_contactlist_publish(identity, contacts, 1, NULL,
                                kyber_pub, kyber_priv, dsa_pub, dsa_priv, 0) != 0) {
        printf("  FAIL  setup: publish\n");
        return -1;
    }
    size_t pub_len = 0;
    const uint8_t *pub = fuzz_dht_stub_last_put(&pub_len);
    if (!pub || pub_len < CL_SEAL_OFF + 4) {
        printf("  FAIL  setup: no published blob\n");
        return -1;
    }
    uint8_t *real = malloc(pub_len);
    if (!real) {
        return -1;
    }
    memcpy(real, pub, pub_len);
    uint32_t enc_len = ((uint32_t)real[CL_ENC_LEN_OFF] << 24) |
                       ((uint32_t)real[CL_ENC_LEN_OFF + 1] << 16) |
                       ((uint32_t)real[CL_ENC_LEN_OFF + 2] << 8) |
                       (uint32_t)real[CL_ENC_LEN_OFF + 3];
    if ((size_t)CL_SEAL_OFF + enc_len + 4 > pub_len) {
        printf("  FAIL  setup: unexpected blob layout\n");
        free(real);
        return -1;
    }

    size_t count = 0;
    CHECK(cl_fetch(real, pub_len, identity, kyber_priv, dsa_pub, &count) == 0 && count == 1,
          "contactlist_valid_roundtrip (unchanged: accepted, 1 contact)");

    CHECK(cl_fetch(real, pub_len - 1, identity, kyber_priv, dsa_pub, NULL) == -1,
          "contactlist_truncated_by_one (unchanged: rejected)");

    uint8_t *b = malloc(pub_len);
    if (!b) {
        free(real);
        return -1;
    }

    /* encrypted_len one byte past what the blob can hold: rejected */
    memcpy(b, real, pub_len);
    wr_be32(b + CL_ENC_LEN_OFF, (uint32_t)(pub_len - CL_SEAL_OFF - 4) + 1u);
    CHECK(cl_fetch(b, pub_len, identity, kyber_priv, dsa_pub, NULL) == -1,
          "contactlist_encrypted_len_past_end (unchanged: rejected)");

    /* The BUGS.md mechanism: blob = header(25) + the real Seal, nothing else.
     * encrypted_len = 2^32 - 16 -> on 32-bit the old offset lands on 9 and
     * reads sig_len from blob[9..12]; set it so 13 + sig_len == blob_size. */
    size_t crafted_len = CL_SEAL_OFF + enc_len;
    uint8_t *c = malloc(crafted_len);
    if (!c) {
        free(b);
        free(real);
        return -1;
    }
    memcpy(c, real, CL_SEAL_OFF);
    memcpy(c + CL_SEAL_OFF, real + CL_SEAL_OFF, enc_len);
    wr_be32(c + CL_ENC_LEN_OFF, 0xFFFFFFF0u);
    wr_be32(c + 9, (uint32_t)(crafted_len - 13));
    CHECK(cl_fetch(c, crafted_len, identity, kyber_priv, dsa_pub, NULL) == -1,
          "contactlist_len_wrap (32-bit old code: accepted, ~4 GB decrypt length)");

    free(c);
    free(b);
    free(real);
    return 0;
}

int main(void) {
    printf("=== test_len_wrap_32 (sizeof(size_t) = %zu) ===\n", sizeof(size_t));

    uint8_t *kyber_pub = malloc(QGP_KEM1024_PUBLICKEYBYTES);
    uint8_t *kyber_priv = malloc(QGP_KEM1024_SECRETKEYBYTES);
    uint8_t *dsa_pub = malloc(QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *dsa_priv = malloc(QGP_DSA87_SECRETKEYBYTES);
    uint8_t *contact_pub = malloc(QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *contact_priv = malloc(QGP_DSA87_SECRETKEYBYTES);
    dna_context_t *ctx = dna_context_new();
    int rc = 1;

    if (!kyber_pub || !kyber_priv || !dsa_pub || !dsa_priv ||
        !contact_pub || !contact_priv || !ctx) {
        printf("FAIL: setup allocation\n");
        goto out;
    }
    if (qgp_kem1024_keypair(kyber_pub, kyber_priv) != 0 ||
        qgp_dsa87_keypair(dsa_pub, dsa_priv) != 0 ||
        qgp_dsa87_keypair(contact_pub, contact_priv) != 0) {
        printf("FAIL: setup keypairs\n");
        goto out;
    }

    if (test_seal(ctx, kyber_pub, kyber_priv, dsa_pub, dsa_priv) != 0 ||
        test_contactlist(kyber_pub, kyber_priv, dsa_pub, dsa_priv, contact_pub) != 0) {
        goto out;
    }

    if (g_failures == 0) {
        printf("=== ALL PASS ===\n");
        rc = 0;
    } else {
        printf("=== %d FAILED ===\n", g_failures);
    }

out:
    if (ctx) {
        dna_context_free(ctx);
    }
    free(kyber_pub);
    free(kyber_priv);
    free(dsa_pub);
    free(dsa_priv);
    free(contact_pub);
    free(contact_priv);
    return rc;
}
