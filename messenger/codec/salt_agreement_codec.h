/**
 * @file salt_agreement_codec.h
 * @brief Per-contact salt agreement: key derivation + packet parse helpers
 *
 * NC-1 (Web Connect design rev 5 §1.3, operator decision 2026-09-30 Q2 = a):
 * moved verbatim out of dht/shared/dht_salt_agreement.c (which also does the
 * DHT put/get and the contacts-DB reconcile). The packet layout macros moved
 * here from that file unchanged. The four helpers were `static` there; they
 * are external now and carry the `salt_agreement_` prefix so libdna does not
 * export generic names (fp_hex_to_bin, packet_*). Bodies are unchanged.
 *
 * salt_agreement_make_key is declared in dht_salt_agreement.h (unchanged).
 * NC-1b: the packet BUILD, formerly inline in salt_agreement_publish_internal
 * (dht_salt_agreement.c), moved here as salt_agreement_build_packet.
 */

#ifndef DNA_CODEC_SALT_AGREEMENT_CODEC_H
#define DNA_CODEC_SALT_AGREEMENT_CODEC_H

#include <stddef.h>
#include <stdint.h>
#include "dht/shared/dht_salt_agreement.h"
#include "messenger/gek.h"
#include "crypto/sign/qgp_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Fingerprint binary size (SHA3-512 = 64 bytes) */
#define FP_BIN_SIZE 64

/* Packet layout sizes (v1) */
#define PACKET_VERSION_SIZE   2
#define PACKET_ENTRY_SIZE     (FP_BIN_SIZE + GEK_ENC_TOTAL_SIZE)  /* 64 + 1628 = 1692 */
#define PACKET_DATA_SIZE      (PACKET_VERSION_SIZE + 2 * PACKET_ENTRY_SIZE)  /* 2 + 3384 = 3386 */
#define PACKET_TOTAL_SIZE     (PACKET_DATA_SIZE + QGP_DSA87_SIGNATURE_BYTES)  /* 3386 + 4627 = 8013 */

/* Packet layout sizes (v2, KEM Faz 1, R9) — each entry gains a 1-byte alg
 * field between the fingerprint and the GEK_ENC blob. */
#define PACKET_ENTRY_SIZE_V2  (FP_BIN_SIZE + 1 + GEK_ENC_TOTAL_SIZE)  /* 64 + 1 + 1628 = 1693 */
#define PACKET_DATA_SIZE_V2   (PACKET_VERSION_SIZE + 2 * PACKET_ENTRY_SIZE_V2)  /* 2 + 3386 = 3388 */
#define PACKET_TOTAL_SIZE_V2  (PACKET_DATA_SIZE_V2 + QGP_DSA87_SIGNATURE_BYTES)  /* 3388 + 4627 = 8015 */

/** Convert 128-char hex fingerprint to 64-byte binary (was static fp_hex_to_bin) */
int salt_agreement_fp_hex_to_bin(const char *hex, uint8_t bin[FP_BIN_SIZE]);

/**
 * Data-portion size for a packet's version field (v1 or v2); 0 for an
 * unsupported version. (was static packet_data_size_for_version)
 */
size_t salt_agreement_packet_data_size_for_version(uint16_t version);

/**
 * Try to decrypt the salt from a parsed packet for the given fingerprint
 * (v1 and v2). 0 on success, -1 otherwise. (was static packet_decrypt_salt)
 */
int salt_agreement_packet_decrypt_salt(
    const uint8_t *data,
    size_t data_len,
    const uint8_t my_fp_bin[FP_BIN_SIZE],
    const uint8_t *my_kyber_priv,
    const uint8_t *my_mlkem_priv,
    uint8_t salt_out[SALT_AGREEMENT_SIZE]
);

/**
 * Verify the packet signature against either party's ML-DSA-87 pubkey.
 * 0 if valid for either, -1 otherwise. (was static packet_verify_signature)
 */
int salt_agreement_packet_verify_signature(
    const uint8_t *data,
    size_t data_len,
    size_t data_size,
    const uint8_t *sign_pub_a,
    const uint8_t *sign_pub_b
);

/**
 * The two entry fingerprints of a packet (v1 or v2), in packet order: the
 * 64 bytes at the start of entry 1 and of entry 2, at the same offsets
 * salt_agreement_packet_decrypt_salt reads. Pure; no signature check (the
 * caller verifies the signature over the data part first). Added for the
 * web thin core's pair binding (a packet is accepted only for the pair it
 * names); no existing function changed. 0, or -1 for a short packet or an
 * unsupported version.
 */
int salt_agreement_packet_entry_fps(
    const uint8_t *data,
    size_t data_len,
    uint8_t fp1_out[FP_BIN_SIZE],
    uint8_t fp2_out[FP_BIN_SIZE]
);

/**
 * Build the signed salt-agreement packet (NC-1b, moved out of
 * salt_agreement_publish_internal): version (BE), then the lower and the
 * higher fingerprint (strcmp order) each followed by [alg byte, v2 only] and
 * the KEM-wrapped salt for that party, then the ML-DSA-87 signature over
 * the data part. v2 (ML-KEM-1024 for both) ONLY when both my_mlkem_pub and
 * contact_mlkem_pub are non-NULL, else v1 (round-3 Kyber) — all-or-nothing.
 * `packet` is zeroed and filled; *total_size_out = data part + signature.
 * The KEM wrap and the signature are randomized. 0 / -1.
 */
int salt_agreement_build_packet(
    const char *my_fp,
    const char *contact_fp,
    const uint8_t salt[SALT_AGREEMENT_SIZE],
    const uint8_t *my_kyber_pub,
    const uint8_t *contact_kyber_pub,
    const uint8_t *my_mlkem_pub,
    const uint8_t *contact_mlkem_pub,
    const uint8_t *my_dilithium_priv,
    uint8_t packet[PACKET_TOTAL_SIZE_V2],
    size_t *total_size_out
);

#ifdef __cplusplus
}
#endif

#endif /* DNA_CODEC_SALT_AGREEMENT_CODEC_H */
