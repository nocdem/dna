/**
 * @file gsk_packet.c
 * @brief GSK Packet Builder Implementation
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#include "gsk_packet.h"
#include "../crypto/utils/aes_keywrap.h"
#include "../crypto/utils/qgp_random.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define LOG_TAG "MSG_GSK"

/**
 * Calculate expected packet size
 */
size_t gsk_packet_calculate_size(size_t member_count) {
    return GSK_PACKET_HEADER_SIZE + (GSK_MEMBER_ENTRY_SIZE * member_count) + GSK_SIGNATURE_SIZE;
}

/**
 * Build Initial Key Packet
 */
int gsk_packet_build(const char *group_uuid,
                     uint32_t version,
                     const uint8_t gsk[GSK_KEY_SIZE],
                     const gsk_member_entry_t *members,
                     size_t member_count,
                     const uint8_t *owner_dilithium_privkey,
                     uint8_t **packet_out,
                     size_t *packet_size_out) {
    if (!group_uuid || !gsk || !members || member_count == 0 ||
        !owner_dilithium_privkey || !packet_out || !packet_size_out) {
        QGP_LOG_ERROR(LOG_TAG, "build: NULL parameter\n");
        return -1;
    }

    // Calculate packet size
    size_t packet_size = gsk_packet_calculate_size(member_count);
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    if (!packet) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate packet buffer\n");
        return -1;
    }

    size_t offset = 0;

    // === HEADER ===
    // Group UUID (37 bytes: 36 + null terminator)
    memcpy(packet + offset, group_uuid, 37);
    offset += 37;

    // GSK version (4 bytes, network byte order)
    uint32_t version_net = htonl(version);
    memcpy(packet + offset, &version_net, 4);
    offset += 4;

    // Member count (1 byte)
    packet[offset] = (uint8_t)member_count;
    offset += 1;

    QGP_LOG_INFO(LOG_TAG, "Building packet for group %s v%u with %zu members\n",
           group_uuid, version, member_count);

    // === PER-MEMBER ENTRIES ===
    for (size_t i = 0; i < member_count; i++) {
        const gsk_member_entry_t *member = &members[i];

        // Fingerprint (64 bytes binary)
        memcpy(packet + offset, member->fingerprint, 64);
        offset += 64;

        // Kyber1024 encapsulation: (GSK -> KEK, ciphertext)
        uint8_t kyber_ct[QGP_KEM1024_CIPHERTEXTBYTES];  // 1568 bytes
        uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];     // 32 bytes

        int ret = qgp_kem1024_encapsulate(kyber_ct, kek, member->kyber_pubkey);

        if (ret != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Kyber1024 encapsulation failed for member %zu\n", i);
            free(packet);
            return -1;
        }

        memcpy(packet + offset, kyber_ct, 1568);
        offset += 1568;

        // AES key wrap: Wrap GSK with KEK
        uint8_t wrapped_gsk[40];  // AES-wrap output: 32-byte key -> 40 bytes
        if (aes256_wrap_key(gsk, GSK_KEY_SIZE, kek, wrapped_gsk) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "AES key wrap failed for member %zu\n", i);
            free(packet);
            return -1;
        }

        memcpy(packet + offset, wrapped_gsk, 40);
        offset += 40;

        QGP_LOG_INFO(LOG_TAG, "Member %zu: Kyber+Wrap OK\n", i);
    }

    // === SIGNATURE ===
    // Sign the packet up to this point (header + entries)
    size_t data_to_sign_len = offset;
    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];  // Pre-allocated buffer (4627 bytes)
    size_t sig_len = 0;

    int ret = qgp_dsa87_sign(signature, &sig_len, packet, data_to_sign_len,
                              owner_dilithium_privkey);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Dilithium5 signing failed\n");
        free(packet);
        return -1;
    }

    // Signature type (1 byte: 23 = Dilithium5 / ML-DSA-87)
    packet[offset] = 23;
    offset += 1;

    // Signature size (2 bytes, network byte order)
    uint16_t sig_size_net = htons((uint16_t)sig_len);
    memcpy(packet + offset, &sig_size_net, 2);
    offset += 2;

    // Signature bytes
    memcpy(packet + offset, signature, sig_len);
    offset += sig_len;

    QGP_LOG_INFO(LOG_TAG, "Packet built: %zu bytes (signed)\n", offset);

    *packet_out = packet;
    *packet_size_out = offset;
    return 0;
}

/**
 * Extract GSK from packet
 */
int gsk_packet_extract(const uint8_t *packet,
                       size_t packet_size,
                       const uint8_t *my_fingerprint_bin,
                       const uint8_t *my_kyber_privkey,
                       uint8_t gsk_out[GSK_KEY_SIZE],
                       uint32_t *version_out) {
    if (!packet || packet_size < GSK_PACKET_HEADER_SIZE ||
        !my_fingerprint_bin || !my_kyber_privkey || !gsk_out) {
        QGP_LOG_ERROR(LOG_TAG, "extract: Invalid parameter\n");
        return -1;
    }

    size_t offset = 0;

    // === PARSE HEADER ===
    // Group UUID (37 bytes)
    char group_uuid[37];
    memcpy(group_uuid, packet + offset, 37);
    offset += 37;

    // GSK version (4 bytes)
    uint32_t version;
    memcpy(&version, packet + offset, 4);
    version = ntohl(version);
    offset += 4;

    if (version_out) {
        *version_out = version;
    }

    // Member count (1 byte)
    uint8_t member_count = packet[offset];
    offset += 1;

    QGP_LOG_INFO(LOG_TAG, "Extracting from packet: group=%s v%u members=%u\n",
           group_uuid, version, member_count);

    // === SEARCH FOR MY ENTRY ===
    for (size_t i = 0; i < member_count; i++) {
        // Read fingerprint (64 bytes)
        if (offset + 64 > packet_size) {
            QGP_LOG_ERROR(LOG_TAG, "Packet truncated at member %zu\n", i);
            return -1;
        }

        const uint8_t *entry_fingerprint = packet + offset;

        // Check if this is my entry
        if (memcmp(entry_fingerprint, my_fingerprint_bin, 64) == 0) {
            QGP_LOG_INFO(LOG_TAG, "Found my entry at position %zu\n", i);

            offset += 64;

            // Kyber1024 ciphertext (1568 bytes)
            if (offset + 1568 > packet_size) {
                QGP_LOG_ERROR(LOG_TAG, "Packet truncated at kyber_ct\n");
                return -1;
            }
            const uint8_t *kyber_ct = packet + offset;
            offset += 1568;

            // Wrapped GSK (40 bytes)
            if (offset + 40 > packet_size) {
                QGP_LOG_ERROR(LOG_TAG, "Packet truncated at wrapped_gsk\n");
                return -1;
            }
            const uint8_t *wrapped_gsk = packet + offset;

            // Kyber1024 decapsulation: ciphertext -> KEK
            uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];  // 32 bytes
            int ret = qgp_kem1024_decapsulate(kek, kyber_ct, my_kyber_privkey);

            if (ret != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Kyber1024 decapsulation failed\n");
                return -1;
            }

            // AES key unwrap: wrapped_gsk + KEK -> GSK
            if (aes256_unwrap_key(wrapped_gsk, 40, kek, gsk_out) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "AES key unwrap failed\n");
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG, "Successfully extracted GSK\n");
            return 0;
        }

        // Not my entry, skip to next
        offset += 64 + 1568 + 40;  // fingerprint + kyber_ct + wrapped_gsk
    }

    QGP_LOG_ERROR(LOG_TAG, "My fingerprint not found in packet\n");
    return -1;
}

/**
 * Verify packet signature
 */
int gsk_packet_verify(const uint8_t *packet,
                      size_t packet_size,
                      const uint8_t *owner_dilithium_pubkey) {
    if (!packet || packet_size < GSK_PACKET_HEADER_SIZE ||
        !owner_dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "verify: Invalid parameter\n");
        return -1;
    }

    // Parse header to get member count
    uint8_t member_count = packet[GSK_PACKET_HEADER_SIZE - 1];

    // Calculate where signature starts
    size_t signature_offset = GSK_PACKET_HEADER_SIZE + (GSK_MEMBER_ENTRY_SIZE * member_count);

    if (signature_offset + 3 > packet_size) {
        QGP_LOG_ERROR(LOG_TAG, "Packet too small for signature\n");
        return -1;
    }

    // Parse signature block
    uint8_t sig_type = packet[signature_offset];
    if (sig_type != 23) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature type: %u (expected 23)\n", sig_type);
        return -1;
    }

    uint16_t sig_size;
    memcpy(&sig_size, packet + signature_offset + 1, 2);
    sig_size = ntohs(sig_size);

    const uint8_t *signature = packet + signature_offset + 3;

    if (signature_offset + 3 + sig_size > packet_size) {
        QGP_LOG_ERROR(LOG_TAG, "Signature size mismatch\n");
        return -1;
    }

    // Verify signature (signed data is everything before signature)
    int ret = qgp_dsa87_verify(signature, sig_size, packet, signature_offset,
                                owner_dilithium_pubkey);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature verification FAILED\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Signature verification OK\n");
    return 0;
}
