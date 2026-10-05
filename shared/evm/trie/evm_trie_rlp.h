/**
 * @file evm_trie_rlp.h
 * @brief Minimal RLP encoder/decoder for the Nodus EVM state trie (production).
 *
 * Copied from the test-only shared/evm/tests/evm_rlp.{h,c} (same rules,
 * renamed prefix so the two can be linked into one binary) and cut down to
 * what the trie needs. The trie stores node bytes; this is the code that
 * writes them and reads them back, so it is consensus code: a decode that
 * accepted two spellings of one node would let two stores disagree on the
 * bytes behind a digest.
 *
 * Encoding rules (the RLP execution-specs @a87891f7 uses through
 * `ethereum_rlp`; merkle_patricia_trie.py:245 `rlp.encode(unencoded)`):
 *   - string of 1 byte < 0x80          -> the byte itself
 *   - string of len 0..55              -> 0x80+len, bytes
 *   - string of len > 55               -> 0xb7+len(len), len (BE), bytes
 *   - list with payload len 0..55      -> 0xc0+len, payload
 *   - list with payload len > 55       -> 0xf7+len(len), len (BE), payload
 * The decoder accepts the canonical form only: a single byte < 0x80 must
 * not be wrapped, a long-form length must be > 55 and carry no leading
 * zero byte, and the declared length must fit in the input.
 *
 * Return convention: 0 ok, -1 malformed input, -2 allocation failure.
 */
#ifndef EVM_TRIE_RLP_H
#define EVM_TRIE_RLP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Growable output buffer. Zero-initialise, then use; free with
 *  evm_trie_rlp_buf_free. After any -2 the content is unspecified. */
typedef struct {
    uint8_t *p;
    size_t   len;
    size_t   cap;
} evm_trie_rlp_buf;

void evm_trie_rlp_buf_free(evm_trie_rlp_buf *b);

/** Append raw bytes without any RLP header (a pre-encoded item). */
int evm_trie_rlp_put_raw(evm_trie_rlp_buf *b, const uint8_t *data, size_t len);

/** Append an RLP byte string (data may be NULL when len == 0). */
int evm_trie_rlp_put_bytes(evm_trie_rlp_buf *b, const uint8_t *data,
                           size_t len);

/** Turn everything appended since offset `start` into one RLP list item
 *  (inserts the list header at `start`). @return 0, -1 (start > len), -2. */
int evm_trie_rlp_wrap_list(evm_trie_rlp_buf *b, size_t start);

/** One decoded item; `payload` points into the decoded input. */
typedef struct {
    int            is_list;
    const uint8_t *payload;
    size_t         len;       /* payload length          */
    size_t         total;     /* header + payload length */
} evm_trie_rlp_item;

/** Decode the single item at the start of `in` (canonical form only).
 *  The item may be followed by more bytes; `total` says how many it used.
 *  @return 0 or -1. */
int evm_trie_rlp_decode_item(const uint8_t *in, size_t in_len,
                             evm_trie_rlp_item *out);

#ifdef __cplusplus
}
#endif

#endif /* EVM_TRIE_RLP_H */
