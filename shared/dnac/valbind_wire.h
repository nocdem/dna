/**
 * @file shared/dnac/valbind_wire.h
 * @brief HF-6 slice 1 — validator node-consent message, consent signature
 *        and validator_id derivation (INERT: no consensus path calls it).
 *
 * Governing record: design docs/plans/2026-10-03-hf5-validator-owner-stake
 * -design.md §6.1 (consent) and §6.2 (validator_id), bytes APPROVED by the
 * operator 2026-10-08; signature domain = FIPS 204 ctx only (operator
 * decision 2026-10-08 "evet yalnız ctx", recorded in that design §6.1).
 *
 * Conventions (identical discipline to shared/dnac/vset_wire.h):
 *   - SHA3-512 everywhere (qgp_sha3_512);
 *   - every hash preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, BIG-ENDIAN;
 *   - every failure path returns -1 and produces NO partial output.
 *
 * ── Consent message (DNA_VALBIND_MSG_LEN = 2765 bytes, §6.1) ───────────
 *   off    field          len
 *      0   version u32 BE   4   = DNA_VALBIND_VERSION (1)
 *      4   chain_id        32   = v2_chain32
 *     36   op u8            1   1 = STAKE, 2 = ROTATE, 3 = STORAGE_REGISTER
 *     37   subject         64   STAKE / STORAGE_REGISTER → 64 × 0x00;
 *                               ROTATE → validator_id
 *    101   owner_fp        64
 *    165   consensus_pk  2592   the key that signs (and verifies) consent;
 *                               for STORAGE_REGISTER it is the storage
 *                               node_pk (design rev 6 §11.3)
 *   2757   expiry u64 BE    8
 *
 * Op 3 (STORAGE_REGISTER) was added in design rev 6 §6.1 / §11.3
 * (Kurultay #16, operator 2026-10-09 "approved"): same layout, same ctx,
 * same expiry rule; only the set of legal op values grew.
 *
 * Signer binding: consent_verify takes no key argument — it verifies
 * under the consensus_pk at offset 165 of the message itself.
 *
 * Signature: ML-DSA-87 over the 2765 message bytes with FIPS 204
 * ctx = ASCII "nodus.valbind.v1" (16 bytes, no NUL). The library forms
 * pre = 0 ‖ 16 ‖ ctx and passes it alongside msg (shared/crypto/sign/dsa/
 * sign.c:262-295, verify :439-458). The ctx is NOT part of the message;
 * there is no fallback to an empty-ctx signature.
 *
 * Expiry rule: accepted at height h iff expiry ≥ h AND expiry − h ≤ 720
 * (DNA_VALBIND_MAX_EXPIRY_BLOCKS, a FIXED number — not the epoch length).
 * Written without h + 720, so it cannot overflow.
 *
 * ── validator_id (64 bytes, §6.2) ──────────────────────────────────────
 *   new:      SHA3-512("NDS.VALID.v1"  + 4×0x00 ‖ chain32 ‖ intent_id[64])
 *   migrated: SHA3-512("NDS.VALMIG.v1" + 3×0x00 ‖ chain32 ‖
 *                      SHA3-512(old_pubkey)[64])
 *   Both preimages are 16 + 32 + 64 = 112 bytes.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_VALBIND_WIRE_H
#define SHARED_DNAC_VALBIND_WIRE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── FIPS 204 context ───────────────────────────────────────────────── */
#define DNA_VALBIND_CTX       "nodus.valbind.v1"   /* pass with CTX_LEN    */
#define DNA_VALBIND_CTX_LEN   16                   /* the trailing NUL of
                                                    * the literal is NOT ctx */

/* ── Field widths ───────────────────────────────────────────────────── */
#define DNA_VALBIND_TAG_LEN        16
#define DNA_VALBIND_CHAIN_LEN      32
#define DNA_VALBIND_SUBJECT_LEN    64
#define DNA_VALBIND_OWNER_FP_LEN   64
#define DNA_VALBIND_PUBKEY_LEN   2592   /* ML-DSA-87 public key  */
#define DNA_VALBIND_SECKEY_LEN   4896   /* ML-DSA-87 secret key  */
#define DNA_VALBIND_SIG_LEN      4627   /* ML-DSA-87 signature   */
#define DNA_VALBIND_ID_LEN         64   /* validator_id          */
#define DNA_VALBIND_INTENT_ID_LEN  64

/* ── Consent message ────────────────────────────────────────────────── */
#define DNA_VALBIND_VERSION        ((uint32_t)1)
#define DNA_VALBIND_OP_STAKE       ((uint8_t)1)
#define DNA_VALBIND_OP_ROTATE      ((uint8_t)2)
#define DNA_VALBIND_OP_STORAGE_REGISTER ((uint8_t)3)   /* rev 6 §11.3 */

#define DNA_VALBIND_OFF_VERSION     0
#define DNA_VALBIND_OFF_CHAIN       4
#define DNA_VALBIND_OFF_OP         36
#define DNA_VALBIND_OFF_SUBJECT    37
#define DNA_VALBIND_OFF_OWNER     101
#define DNA_VALBIND_OFF_PUBKEY    165
#define DNA_VALBIND_OFF_EXPIRY   2757
#define DNA_VALBIND_MSG_LEN      2765

/** Largest accepted expiry − h. FIXED (design §6.1), not DNAC_EPOCH_LENGTH. */
#define DNA_VALBIND_MAX_EXPIRY_BLOCKS ((uint64_t)720)

/* ── validator_id preimages ─────────────────────────────────────────── */
#define DNA_VALBIND_ID_PREIMAGE_LEN 112   /* 16 + 32 + 64 */

/**
 * Build the 2765-byte consent message (layout above).
 *
 * Rejects (-1, out untouched): any NULL argument; op ∉ {STAKE, ROTATE,
 * STORAGE_REGISTER}; op STAKE or STORAGE_REGISTER with a subject that is
 * not all-zero; op ROTATE with an all-zero subject. expiry_height is written as given (the expiry rule is
 * dna_valbind_expiry_ok, applied by the caller at its height).
 */
int dna_valbind_consent_msg(uint8_t out[DNA_VALBIND_MSG_LEN],
                            const uint8_t chain32[DNA_VALBIND_CHAIN_LEN],
                            uint8_t op,
                            const uint8_t subject[DNA_VALBIND_SUBJECT_LEN],
                            const uint8_t owner_fp[DNA_VALBIND_OWNER_FP_LEN],
                            const uint8_t consensus_pk[DNA_VALBIND_PUBKEY_LEN],
                            uint64_t expiry_height);

/**
 * @return 1 iff expiry >= h && expiry - h <= DNA_VALBIND_MAX_EXPIRY_BLOCKS,
 *         else 0. Overflow-free for every (h, expiry).
 */
int dna_valbind_expiry_ok(uint64_t h, uint64_t expiry);

/**
 * Sign a consent message with ctx DNA_VALBIND_CTX.
 * Refuses (-1) a malformed message: version != 1, op ∉ {STAKE, ROTATE,
 * STORAGE_REGISTER}, or a subject that breaks the op rule (same parse as
 * verify).
 * Does NOT check that sk belongs to the embedded consensus_pk; a
 * mismatched key yields a signature that consent_verify rejects.
 * @param sig    [out] DNA_VALBIND_SIG_LEN bytes
 * @param siglen [out] signature length
 * @param msg    exactly DNA_VALBIND_MSG_LEN bytes
 * @param sk     ML-DSA-87 secret key of the consenting consensus key
 * @return 0 / -1.
 */
int dna_valbind_consent_sign(uint8_t sig[DNA_VALBIND_SIG_LEN], size_t *siglen,
                             const uint8_t msg[DNA_VALBIND_MSG_LEN],
                             const uint8_t sk[DNA_VALBIND_SECKEY_LEN]);

/**
 * Verify a consent signature over a DNA_VALBIND_MSG_LEN-byte message with
 * ctx DNA_VALBIND_CTX. The verifying key is the consensus_pk EMBEDDED at
 * DNA_VALBIND_OFF_PUBKEY (signer binding, §6.1) — no separate key is
 * accepted. The message is parsed first: version == 1, op ∈ {STAKE,
 * ROTATE, STORAGE_REGISTER}, and the op/subject rule; a malformed message
 * is rejected. The op byte is signed, so a consent for one op never
 * verifies as a consent for another.
 * @return 0 if valid, -1 otherwise.
 */
int dna_valbind_consent_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t msg[DNA_VALBIND_MSG_LEN]);

/** validator_id of a new validator (§6.2). @return 0 / -1. */
int dna_validator_id_new(uint8_t out[DNA_VALBIND_ID_LEN],
                         const uint8_t chain32[DNA_VALBIND_CHAIN_LEN],
                         const uint8_t intent_id[DNA_VALBIND_INTENT_ID_LEN]);

/** validator_id of a migrated (pre-HF-6) validator row (§6.2). @return 0/-1. */
int dna_validator_id_migrated(uint8_t out[DNA_VALBIND_ID_LEN],
                              const uint8_t chain32[DNA_VALBIND_CHAIN_LEN],
                              const uint8_t old_pubkey[DNA_VALBIND_PUBKEY_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_VALBIND_WIRE_H */
