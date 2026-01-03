/**
 * @file gsk_packet.h
 * @brief GSK Packet Builder - Initial Key Packet Distribution
 *
 * Builds, extracts, and verifies Initial Key Packets for GSK distribution.
 * Each packet contains the GSK wrapped with Kyber1024 for each group member.
 *
 * Packet Format:
 * [group_uuid(37) || version(4) || member_count(1)]
 * [For each member: fingerprint(64) || kyber_ct(1568) || wrapped_gsk(40)]
 * [signature_type(1) || sig_size(2) || signature(~4627)]
 *
 * Total: 42 + (1672 × N) + 4630 bytes
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#ifndef GSK_PACKET_H
#define GSK_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include "gsk.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum number of members per group
 * Prevents memory exhaustion from malicious packets claiming large member counts
 */
#define GSK_MAX_MEMBERS 16

/**
 * Per-member entry size in Initial Key Packet
 * fingerprint(64) + kyber_ct(1568) + wrapped_gsk(40) = 1672 bytes
 */
#define GSK_MEMBER_ENTRY_SIZE 1672

/**
 * Packet header size
 * group_uuid(37) + version(4) + member_count(1) = 42 bytes
 */
#define GSK_PACKET_HEADER_SIZE 42

/**
 * Signature block size (approximate)
 * type(1) + size(2) + Dilithium5_sig(~4627) ≈ 4630 bytes
 */
#define GSK_SIGNATURE_SIZE 4630

/**
 * Member entry for packet building
 */
typedef struct {
    uint8_t fingerprint[64];        // SHA3-512 fingerprint (binary)
    const uint8_t *kyber_pubkey;    // Kyber1024 public key (1568 bytes)
} gsk_member_entry_t;

/**
 * Build Initial Key Packet for GSK distribution
 *
 * Creates a packet containing the GSK wrapped with Kyber1024 for each member.
 * The packet is signed with the owner's Dilithium5 key for authentication.
 *
 * @param group_uuid Group UUID (36-char UUID v4 string)
 * @param version GSK version number
 * @param gsk GSK to distribute (32 bytes)
 * @param members Array of member entries (fingerprint + kyber pubkey)
 * @param member_count Number of members
 * @param owner_dilithium_privkey Owner's Dilithium5 private key (4896 bytes) for signing
 * @param packet_out Output buffer for packet (allocated by function, caller must free)
 * @param packet_size_out Output for packet size
 * @return 0 on success, -1 on error
 */
int gsk_packet_build(const char *group_uuid,
                     uint32_t version,
                     const uint8_t gsk[GSK_KEY_SIZE],
                     const gsk_member_entry_t *members,
                     size_t member_count,
                     const uint8_t *owner_dilithium_privkey,
                     uint8_t **packet_out,
                     size_t *packet_size_out);

/**
 * Extract GSK from received Initial Key Packet
 *
 * Finds the entry matching my_fingerprint, performs Kyber1024 decapsulation
 * to get KEK, then unwraps the GSK.
 *
 * @param packet Received packet buffer
 * @param packet_size Packet size in bytes
 * @param my_fingerprint_bin My fingerprint (64 bytes binary)
 * @param my_kyber_privkey My Kyber1024 private key (3168 bytes)
 * @param gsk_out Output buffer for extracted GSK (32 bytes)
 * @param version_out Output for GSK version (optional, can be NULL)
 * @return 0 on success, -1 on error (entry not found or decryption failed)
 */
int gsk_packet_extract(const uint8_t *packet,
                       size_t packet_size,
                       const uint8_t *my_fingerprint_bin,
                       const uint8_t *my_kyber_privkey,
                       uint8_t gsk_out[GSK_KEY_SIZE],
                       uint32_t *version_out);

/**
 * Verify Initial Key Packet signature
 *
 * Verifies the Dilithium5 signature on the packet using the owner's public key.
 *
 * @param packet Packet buffer
 * @param packet_size Packet size in bytes
 * @param owner_dilithium_pubkey Owner's Dilithium5 public key (2592 bytes)
 * @return 0 on success (signature valid), -1 on error or invalid signature
 */
int gsk_packet_verify(const uint8_t *packet,
                      size_t packet_size,
                      const uint8_t *owner_dilithium_pubkey);

/**
 * Calculate expected packet size for a given member count
 *
 * Useful for pre-allocating buffers or validating packet sizes.
 *
 * @param member_count Number of group members
 * @return Expected packet size in bytes
 */
size_t gsk_packet_calculate_size(size_t member_count);

#ifdef __cplusplus
}
#endif

#endif // GSK_PACKET_H
