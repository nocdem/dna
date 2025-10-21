/*
 * cellframe_tx_json_to_binary.h - Parse JSON transaction and build binary
 */

#ifndef CELLFRAME_TX_JSON_TO_BINARY_H
#define CELLFRAME_TX_JSON_TO_BINARY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build binary transaction from JSON file
 *
 * Reads unsigned transaction JSON (same format as cellframe-tool-sign input)
 * and constructs binary transaction data using Cellframe's format.
 *
 * @param json_file - Path to unsigned transaction JSON file
 * @param tx_out - Output binary transaction data (caller must free)
 * @param tx_size_out - Output transaction size
 * @param timestamp_out - Output timestamp (from JSON or current time)
 * @return 0 on success, -1 on error
 */
int cellframe_tx_from_json(const char *json_file,
                           uint8_t **tx_out, size_t *tx_size_out,
                           uint64_t *timestamp_out);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_TX_JSON_TO_BINARY_H */
