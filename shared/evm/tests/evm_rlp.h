/**
 * @file evm_rlp.h
 * @brief Minimal RLP encoder/decoder — TEST-ONLY (state-test harness).
 *
 * Used only to verify the engine against the official state tests: account
 * leaf encoding, Merkle Patricia Trie node encoding, the logs hash, and
 * reading the chain id out of a fixture's `txbytes`. Not linked into the
 * engine (design 2026-10-04-nodus-evm-engine-design.md §3, tests/).
 *
 * Encoding rules (the RLP the reference uses through `ethereum_rlp`; the
 * integer form is pinned by execution-specs @a87891f7
 * tests/json_loader/test_rlp.py:20-24 — zero is the empty string, integers
 * are big-endian without leading zero bytes):
 *   - string of 1 byte < 0x80          -> the byte itself
 *   - string of len 0..55              -> 0x80+len, bytes
 *   - string of len > 55               -> 0xb7+len(len), len (BE), bytes
 *   - list with payload len 0..55      -> 0xc0+len, payload
 *   - list with payload len > 55       -> 0xf7+len(len), len (BE), payload
 *
 * All functions are deterministic and allocation-checked. Return
 * convention: 0 ok, -1 malformed input, -2 allocation failure.
 */
#ifndef EVM_TEST_RLP_H
#define EVM_TEST_RLP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Growable output buffer. Zero-initialise, then use; free with
 *  evm_rlp_buf_free. After any -2 the buffer content is unspecified. */
typedef struct {
    uint8_t *p;
    size_t   len;
    size_t   cap;
} evm_rlp_buf;

void evm_rlp_buf_free(evm_rlp_buf *b);

/** Append raw bytes without any RLP header (for pre-encoded items). */
int evm_rlp_put_raw(evm_rlp_buf *b, const uint8_t *data, size_t len);

/** Append an RLP byte string. */
int evm_rlp_put_bytes(evm_rlp_buf *b, const uint8_t *data, size_t len);

/** Append an RLP unsigned integer given as big-endian bytes of any length
 *  (leading zeros are stripped; all-zero -> empty string 0x80). */
int evm_rlp_put_uint_be(evm_rlp_buf *b, const uint8_t *be, size_t len);

/** Append an RLP unsigned integer from a uint64. */
int evm_rlp_put_u64(evm_rlp_buf *b, uint64_t v);

/** Turn everything appended since offset `start` into one RLP list item
 *  (inserts the list header at `start`). */
int evm_rlp_wrap_list(evm_rlp_buf *b, size_t start);

/* ── decoding ──────────────────────────────────────────────────────── */

typedef struct {
    int            is_list;
    const uint8_t *payload;   /* points into the input                  */
    size_t         len;       /* payload length                         */
    size_t         total;     /* header + payload length                */
} evm_rlp_item;

/** Decode the single item at the start of `in` (canonical form required:
 *  single bytes < 0x80 must not be wrapped, long-form lengths must be
 *  > 55 and without leading zeros). @return 0 or -1. */
int evm_rlp_decode_item(const uint8_t *in, size_t in_len, evm_rlp_item *out);

/** Get element `index` of a list item. @return 0, or -1 if the list is
 *  malformed or shorter than index+1. */
int evm_rlp_list_get(const evm_rlp_item *list, size_t index,
                     evm_rlp_item *out);

/** Interpret a string item as a canonical unsigned integer that fits in
 *  64 bits (no leading zero byte). @return 0 or -1. */
int evm_rlp_item_to_u64(const evm_rlp_item *it, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TEST_RLP_H */
