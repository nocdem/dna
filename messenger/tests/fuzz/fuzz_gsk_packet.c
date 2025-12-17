/**
 * @file fuzz_gsk_packet.c
 * @brief libFuzzer harness for GSK packet extraction
 *
 * Fuzzes gsk_packet_extract() which parses Initial Key Packets
 * for Group Symmetric Key distribution.
 *
 * Packet Format:
 * [group_uuid(37) || version(4) || member_count(1)]
 * [For each member: fingerprint(64) || kyber_ct(1568) || wrapped_gsk(40)]
 * [signature_type(1) || sig_size(2) || signature(~4627)]
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "messenger/gsk_packet.h"
#include "fuzz_common.h"

/* Static fake keys - initialized once for determinism */
static uint8_t s_kyber_privkey[FUZZ_KYBER1024_PRIVKEY_SIZE];
static uint8_t s_fingerprint[FUZZ_FINGERPRINT_SIZE];
static int s_initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Minimum header size check */
    if (size < GSK_PACKET_HEADER_SIZE) {
        return 0;
    }

    /* One-time initialization with deterministic fake keys */
    if (!s_initialized) {
        fuzz_generate_fake_kyber_privkey(s_kyber_privkey, 42);
        fuzz_generate_fake_fingerprint(s_fingerprint, 42);
        s_initialized = 1;
    }

    uint8_t gsk_out[32];  /* GSK_KEY_SIZE = 32 */
    uint32_t version_out = 0;

    /* This function should handle malformed packets gracefully */
    gsk_packet_extract(data, size, s_fingerprint,
                       s_kyber_privkey, gsk_out, &version_out);

    return 0;
}
