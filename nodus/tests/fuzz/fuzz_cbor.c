/**
 * @file fuzz_cbor.c
 * @brief libFuzzer harness: the nodus CBOR decoder on arbitrary bytes.
 *
 * Entry points (all exported, none modified), src/protocol/nodus_cbor.h:
 *   cbor_decoder_init, cbor_decode_next, cbor_decode_peek, cbor_decode_int,
 *   cbor_decode_skip, cbor_decode_skip_signed, cbor_map_find
 *
 * Three passes over the same input:
 *   1. skip_signed every top-level item until error or end (the recursive
 *      path bounded by CBOR_MAX_DEPTH / NODUS_CBOR_MAX_ITEMS);
 *   2. a flat walk with peek / next / int, reading every byte of every
 *      bstr / tstr slice the decoder returns — a slice whose ptr+len runs
 *      past the input is reported by ASan here, not by a later consumer;
 *   3. if the first item is a map, cbor_map_find for the tier-2 method key
 *      "q" (nodus_tier2.c encodes it in every request/response header).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "protocol/nodus_cbor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Upper bound on items per walk: the decoder itself caps containers at
 * NODUS_CBOR_MAX_ITEMS, this only keeps one input's run time bounded. */
#define FUZZ_CBOR_WALK_BUDGET 65536

static volatile uint8_t g_sink;

static void touch(const uint8_t *p, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc ^= p[i];
    }
    g_sink ^= acc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cbor_decoder_t dec;

    /* Pass 1: skip every top-level item */
    cbor_decoder_init(&dec, data, size);
    bool saw_negint = false;
    for (size_t n = 0; n < FUZZ_CBOR_WALK_BUDGET && !dec.error && dec.pos < dec.len; n++) {
        size_t before = dec.pos;
        cbor_decode_skip_signed(&dec, &saw_negint);
        if (dec.pos == before) {
            break;
        }
    }

    /* Pass 2: flat walk */
    cbor_decoder_init(&dec, data, size);
    for (size_t n = 0; n < FUZZ_CBOR_WALK_BUDGET && !dec.error; n++) {
        cbor_item_type_t t = cbor_decode_peek(&dec);
        if (t == CBOR_ITEM_END) {
            break;
        }
        if (t == CBOR_ITEM_ERROR) {
            /* Major type 1 is only readable through cbor_decode_int */
            int64_t v = 0;
            if (!cbor_decode_int(&dec, &v)) {
                break;
            }
            g_sink ^= (uint8_t)v;
            continue;
        }
        cbor_item_t it = cbor_decode_next(&dec);
        if (dec.error) {
            break;
        }
        if (it.type == CBOR_ITEM_BSTR) {
            touch(it.bstr.ptr, it.bstr.len);
        } else if (it.type == CBOR_ITEM_TSTR) {
            touch((const uint8_t *)it.tstr.ptr, it.tstr.len);
        }
    }

    /* Pass 3: map key lookup from the start of a top-level map */
    cbor_decoder_init(&dec, data, size);
    cbor_item_t top = cbor_decode_next(&dec);
    if (!dec.error && top.type == CBOR_ITEM_MAP) {
        cbor_item_t v = cbor_map_find(&dec, top.count, "q");
        if (v.type == CBOR_ITEM_TSTR) {
            touch((const uint8_t *)v.tstr.ptr, v.tstr.len);
        } else if (v.type == CBOR_ITEM_BSTR) {
            touch(v.bstr.ptr, v.bstr.len);
        }
    }

    return 0;
}
