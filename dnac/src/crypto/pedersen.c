/**
 * @file pedersen.c
 * @brief Pedersen commitment implementation
 *
 * TODO: Implement using secp256k1 or libsodium
 */

#include "dnac/commitment.h"
#include <string.h>

static int g_initialized = 0;

int dnac_pedersen_init(void) {
    if (g_initialized) return 0;
    /* TODO: Initialize secp256k1 context and generator points */
    g_initialized = 1;
    return 0;
}

void dnac_pedersen_shutdown(void) {
    g_initialized = 0;
}

int dnac_pedersen_commit(uint64_t value,
                         const uint8_t *blinding,
                         uint8_t *commitment_out,
                         uint8_t *blinding_out) {
    /* TODO: Implement C = g^v * h^r */
    (void)value;
    (void)blinding;
    if (commitment_out) memset(commitment_out, 0, DNAC_PEDERSEN_COMMITMENT_SIZE);
    if (blinding_out) memset(blinding_out, 0, DNAC_PEDERSEN_BLINDING_SIZE);
    return -1; /* Not implemented */
}

int dnac_pedersen_add(const uint8_t *c1,
                      const uint8_t *c2,
                      uint8_t *result_out) {
    (void)c1;
    (void)c2;
    (void)result_out;
    return -1;
}

int dnac_pedersen_sub(const uint8_t *c1,
                      const uint8_t *c2,
                      uint8_t *result_out) {
    (void)c1;
    (void)c2;
    (void)result_out;
    return -1;
}

int dnac_pedersen_blind_add(const uint8_t *b1,
                            const uint8_t *b2,
                            uint8_t *result_out) {
    (void)b1;
    (void)b2;
    (void)result_out;
    return -1;
}

int dnac_pedersen_blind_sub(const uint8_t *b1,
                            const uint8_t *b2,
                            uint8_t *result_out) {
    (void)b1;
    (void)b2;
    (void)result_out;
    return -1;
}

int dnac_pedersen_blind_negate(const uint8_t *blinding,
                               uint8_t *result_out) {
    (void)blinding;
    (void)result_out;
    return -1;
}

bool dnac_pedersen_verify(const uint8_t *commitment,
                          uint64_t value,
                          const uint8_t *blinding) {
    (void)commitment;
    (void)value;
    (void)blinding;
    return false;
}

int dnac_pedersen_random_blinding(uint8_t *blinding_out) {
    (void)blinding_out;
    return -1;
}

int dnac_pedersen_compute_excess(const uint8_t (*input_blindings)[32],
                                 int input_count,
                                 const uint8_t (*output_blindings)[32],
                                 int output_count,
                                 uint8_t *excess_out) {
    (void)input_blindings;
    (void)input_count;
    (void)output_blindings;
    (void)output_count;
    (void)excess_out;
    return -1;
}
