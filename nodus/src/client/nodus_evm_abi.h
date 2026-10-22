/**
 * @file nodus/src/client/nodus_evm_abi.h
 * @brief The Nodus EVM contract-ABI text layer — type parser, signature
 *        parser, selector, argument encoder and the number / address text
 *        helpers — moved out of tools/nodus-cli.c, I/O-free, so the CLI's
 *        `evm encode|send|call|deploy|attest` and the companion-library
 *        message builder (nodus_evm_attest.c) compile the same code.
 *
 * ABI (web-wallet/src/evm/abi.js, the same rules): Solidity 0.8.30's
 * contract ABI with the Nodus difference that `address` is a full 32-byte
 * word (nodus/tools/evm/solc/README.md "Semantic rules" 1, 2, 10).
 * Supported types: uint<M>, int<M>, bool, address, bytes<M>, bytes,
 * string, and a one-dimensional dynamic array T[] of a static one. A
 * signature is `name(t1,t2)` with an optional return list
 * `name(t1,t2)(r1,r2)`; a constructor's is `(t1,t2)`.
 *
 * STRICTLY CANONICAL (Kurultay #40, Astra finding A1): an integer width
 * and a bytes size are plain decimal digits (no sign, no space, no leading
 * zero) and are range-checked as text BEFORE any narrowing; the canonical
 * text of a type is rebuilt from the validated number, never copied from
 * the input; a function name is a Solidity identifier (a letter, `_` or
 * `$` first, then letters, digits, `_`, `$`) or empty for a constructor.
 * Only `uint` -> `uint256` and `int` -> `int256` are rewritten.
 *
 * No printing: every refusal leaves its text in the caller's `err`
 * buffer (empty when the refusal has no specific message).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_EVM_ABI_H
#define NODUS_EVM_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Most values / types in one list (also bounds a whole attest tuple). */
#define NODUS_EVM_ABI_MAX_ARGS 16

typedef enum {
    NODUS_EVM_ABI_UINT, NODUS_EVM_ABI_INT, NODUS_EVM_ABI_BOOL,
    NODUS_EVM_ABI_ADDR, NODUS_EVM_ABI_FBYTES, NODUS_EVM_ABI_BYTES,
    NODUS_EVM_ABI_STRING
} nodus_evm_abi_kind_t;

typedef struct {
    nodus_evm_abi_kind_t k;
    unsigned             bits;   /* uint / int                              */
    unsigned             size;   /* bytes<M>                                */
    unsigned             arr;    /* 1: T[] of the static element type above */
} nodus_evm_abi_type_t;

typedef struct {
    char                 canon[512];   /* name(t1,t2)                       */
    nodus_evm_abi_type_t in[NODUS_EVM_ABI_MAX_ARGS];
    int                  n_in;
    nodus_evm_abi_type_t out[NODUS_EVM_ABI_MAX_ARGS];
    int                  n_out;
    int                  has_out;
    int                  is_ctor;      /* the name is empty: "(t1,t2)"      */
} nodus_evm_abi_sig_t;

/* ── 256-bit big-endian integers and byte / address text ─────────────── */

/** out = decimal string `s` (digits only). @return 0 / -1 (empty, a
 *  non-digit, or above 2^256 - 1). */
int nodus_evm_u256_dec(const char *s, uint8_t out[32]);

/** Decimal text of a 32-byte big-endian unsigned value (out >= 80). */
void nodus_evm_u256_to_dec(const uint8_t in[32], char *out);

/** Hex (optional 0x) -> bytes. @return 0 / -1 (odd, a non-hex, too long). */
int nodus_evm_hex_bytes(const char *hex, uint8_t *out, size_t cap,
                        size_t *len);

/** A 32-byte EVM address from text: 64 hex digits (optional 0x). Mixed
 *  case must carry the Nodus 64-digit EIP-55 checksum (solc README rule
 *  4). @return 0 / -1. */
int nodus_evm_addr_parse(const char *s, uint8_t out[32]);

/** The EVM address of a Nodus key: SHA3-512(pk)[0..32] (pk is the 2592-byte
 *  ML-DSA-87 public key). @return 0 / -1. */
int nodus_evm_addr_of_pk(const uint8_t *pk, uint8_t out[32]);

/* ── signature, selector, encoder ────────────────────────────────────── */

/** `name(t1,..)[(r1,..)]`, or `(t1,..)` for a constructor (is_ctor = 1).
 *  @return 0 / -1 (err may carry a message). */
int nodus_evm_abi_sig(const char *sig, nodus_evm_abi_sig_t *g,
                      char *err, size_t errcap);

/** selector = keccak256(canon)[0..4]. @return 0 / -1. */
int nodus_evm_abi_selector(const char *canon, uint8_t sel[4]);

/** enc((v1..vn)) — the head/tail encoding of a sequence of values
 *  (abi-spec "Formal Specification of the Encoding"). *out is heap
 *  (free()), one spare byte past the length. @return 0 / -1 (err set). */
int nodus_evm_abi_encode(const nodus_evm_abi_type_t *ts, int n, char **vals,
                         uint8_t **out, size_t *out_len,
                         char *err, size_t errcap);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_EVM_ABI_H */
