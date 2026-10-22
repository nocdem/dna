/**
 * @file nodus/src/client/nodus_evm_attest.h
 * @brief The ML-DSA-87 companion library's off-chain half — the attested
 *        message (`MLDSA87Attested`'s `message`) and its signature, I/O-free;
 *        `nodus-cli evm attest` and the tests compile the same file.
 *
 * Design: docs/plans/2026-10-22-mldsa87-companion-library-design.md rev 2
 * §1.3 (the message), §1.6 (the command). Decisions:
 * docs/plans/decisions/2026-10-21-mldsa87-evm-precompile.md (item 2: the
 * fixed FIPS 204 context "nodus.evm.attest.v1", 19 bytes, no terminator,
 * no fallback; item 8; TAG_ATTEST_V1; "Companion library: the actionType")
 * and 2026-10-22-kurultay-40-mldsa-companion-library-summary.md.
 *
 *   message = abi.encode(
 *       bytes32 TAG_ATTEST_V1,   // keccak256("nodus.evm.attest.message.v1")
 *       uint256 chainid,         // the full 32-byte Nodus chain id
 *       address contract,        // 32-byte address of the consuming contract
 *       bytes32 actionType,      // keccak256(canonical "Name(t1,...,tn)")
 *       uint256 nonce,
 *       uint64  expiry,
 *       address signer,          // SHA3-512(pk)[0..32]
 *       p1, ..., pn)             // the action's parameters, declared order
 *
 * ONE encode over the 7+n tuple, so an action has at most 9 parameters
 * (the encoder's NODUS_EVM_ABI_MAX_ARGS = 16).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_EVM_ATTEST_H
#define NODUS_EVM_ATTEST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The FIPS 204 context of every attestation signature (19 bytes). */
#define NODUS_EVM_ATTEST_CTX         "nodus.evm.attest.v1"
#define NODUS_EVM_ATTEST_CTX_LEN     19u
/** Most action parameters (7 header words + 9 = the encoder's 16). */
#define NODUS_EVM_ATTEST_MAX_PARAMS  9
/** The precompile's message bound (evm.h EVM_MLDSA87_MSG_MAX). */
#define NODUS_EVM_ATTEST_MSG_MAX     65536u
/** The ML-DSA-87 signature length every signature must have. */
#define NODUS_EVM_ATTEST_SIG_LEN     4627u

typedef struct {
    char     canon[512];         /* the canonical action text Name(t1,..)  */
    uint8_t  action_type[32];    /* keccak256(canon)                       */
    uint8_t *message;            /* heap, message_len bytes (free with
                                  * nodus_evm_attest_msg_free)             */
    size_t   message_len;
} nodus_evm_attest_msg_t;

/**
 * Build the attested message.
 *
 * @param action      "Name(t1,...,tn)" — types only, a Solidity identifier
 *                    name; canonicalised (`uint` -> `uint256`) in `canon`.
 *                    An empty name, a return list and more than
 *                    NODUS_EVM_ATTEST_MAX_PARAMS parameters are refused.
 * @param chain32     the 32-byte chain id (a full uint256 word).
 * @param contract32  the consuming contract's 32-byte address.
 * @param nonce_dec   decimal uint256.
 * @param expiry_dec  decimal; must fit uint64.
 * @param signer32    the expected signer's 32-byte EVM address (an input:
 *                    SHA3-512(pk)[0..32] for a signing identity).
 * @param vals        n_vals parameter values as `evm encode` takes them;
 *                    n_vals must equal the action's parameter count.
 * @param out         filled on success; release with nodus_evm_attest_msg_free.
 * @param err         refusal text (may be NULL / errcap 0).
 * @return 0 / -1. Refused: a message over NODUS_EVM_ATTEST_MSG_MAX bytes.
 */
int nodus_evm_attest_build(const char *action,
                           const uint8_t chain32[32],
                           const uint8_t contract32[32],
                           const char *nonce_dec, const char *expiry_dec,
                           const uint8_t signer32[32],
                           char **vals, int n_vals,
                           nodus_evm_attest_msg_t *out,
                           char *err, size_t errcap);

void nodus_evm_attest_msg_free(nodus_evm_attest_msg_t *m);

/** TAG_ATTEST_V1 = keccak256("nodus.evm.attest.message.v1"). @return 0 / -1. */
int nodus_evm_attest_tag(uint8_t tag[32]);

/**
 * Sign `msg` under NODUS_EVM_ATTEST_CTX with the ML-DSA-87 secret key `sk`
 * (4896 bytes). Fails closed: the signature must be exactly
 * NODUS_EVM_ATTEST_SIG_LEN bytes and must verify under the same context
 * with `pk` (2592 bytes) before 0 is returned; `sig` is zeroed on failure.
 * Hedged signing: the signature bytes differ per call.
 * @return 0 / -1.
 */
int nodus_evm_attest_sign(const uint8_t *msg, size_t msg_len,
                          const uint8_t *sk, const uint8_t *pk,
                          uint8_t sig[NODUS_EVM_ATTEST_SIG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_EVM_ATTEST_H */
