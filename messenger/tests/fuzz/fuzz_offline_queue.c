/**
 * @file fuzz_offline_queue.c
 * @brief libFuzzer harness for DHT offline queue message deserialization
 *
 * Fuzzes dht_deserialize_messages() which parses binary-formatted
 * offline message queues from the DHT.
 *
 * Message Format (v2):
 * [4-byte count]
 * [Per message: magic(4) + version(1) + seq_num(8) + timestamp(8) + expiry(8)
 *  + sender_len(2) + recipient_len(2) + ciphertext_len(4)
 *  + sender string + recipient string + ciphertext bytes]
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "dht/shared/dht_offline_queue.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    dht_offline_message_t *messages = NULL;
    size_t count = 0;

    /* This function should handle malformed input gracefully */
    int result = dht_deserialize_messages(data, size, &messages, &count);

    if (result == 0 && messages != NULL) {
        dht_offline_messages_free(messages, count);
    }

    return 0;
}
