/**
 * @file shared/dnac/msig_wire.h
 * @brief General multisig (M-of-N address) — the canonical DESCRIPTOR
 *        codec and the multisig ADDRESS derivation.
 *
 * Decision: docs/plans/decisions/2026-09-29-general-multisig.md (operator,
 * APPROVED 2026-09-29). Design: docs/plans/2026-09-29-general-multisig-
 * design.md §7 rev 2 (the contract). Independent vector oracle:
 * shared/dnac/tests/multisig_oracle.py.
 *
 * PROVENANCE — HONEST LABEL: this layout is the project's own adaptation
 * of the Bitcoin P2SH / P2WSH pattern (BIP-16 / BIP-141: address =
 * hash(locking script), the script is revealed at spend time in a
 * witness field). There is NO pinned external reference for these exact
 * bytes. The C here and the python oracle implement the SAME written
 * layout ("self-consistent, not externally audited").
 *
 * ── THE DESCRIPTOR ───────────────────────────────────────────────────
 *   tag      16   "DNA.MSIG.v1" zero-padded (11 chars + 5 zero bytes)
 *   M        u8   1 .. N           (signatures required)
 *   N        u8   2 .. 7           (DNA_MSIG_MIN_N .. DNA_MSIG_MAX_N)
 *   N × pubkey[2592]               ML-DSA-87 public keys, STRICTLY
 *                                  ascending (memcmp) — duplicates and
 *                                  disorder REJECT, so exactly ONE
 *                                  encoding exists per (M, key set)
 * Length is EXACTLY 18 + N × 2592 (no trailing byte). A key whose first
 * 32 bytes are all zero is a NULL key and REJECTS — the SAME zero-key
 * rule the auth_kind-1 signer section applies
 * (nodus_witness_rt_native.c rtn_auth_submitters, the verify.c:657
 * discipline; design §7 last bullet).
 *
 * ── THE ADDRESS ──────────────────────────────────────────────────────
 *   address = SHA3-512(descriptor)                              (64 B)
 * The same width as an ordinary single-key address SHA3-512(pubkey),
 * so the UTXO owner field is unchanged. The two forms are separated by
 * length (18 + N×2592 vs 2592) and by the leading tag; a collision
 * between them needs a SHA3-512 collision.
 *
 * ── PURITY ───────────────────────────────────────────────────────────
 * No allocation, no clock, no RNG, no nodus dependency (the ledger_ids.h
 * rule: shared/dnac never includes a nodus header). Every function is a
 * pure function of its byte inputs.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNA_MSIG_WIRE_H
#define DNA_MSIG_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The 16-byte zero-padded tag slot (the repository's tagged-preimage
 *  idiom). */
#define DNA_MSIG_TAG_LEN        16u
/** One ML-DSA-87 public key — restated standalone (DNAC_PUBKEY_SIZE,
 *  dnac.h; NODUS_CC_PUBKEY_SIZE, nodus_chain_config.h); the consumers
 *  _Static_assert the equality on their side. */
#define DNA_MSIG_PUBKEY_LEN     2592u
/** Smallest N: a one-key "multisig" is an ordinary address. */
#define DNA_MSIG_MIN_N          2u
/** Largest N per address — operator decision 2026-09-29 ("maksimum 7
 *  anahtar"), design §7 rev 2. */
#define DNA_MSIG_MAX_N          7u
/** tag ‖ M ‖ N. */
#define DNA_MSIG_HDR_LEN        (DNA_MSIG_TAG_LEN + 2u)
/** Exact descriptor length for N keys. */
#define DNA_MSIG_DESC_LEN(n)    (DNA_MSIG_HDR_LEN + (size_t)(n) * DNA_MSIG_PUBKEY_LEN)
/** The longest descriptor: 18 + 7 × 2592 = 18162 (fits the u16 dlen
 *  field of auth_kind 3). */
#define DNA_MSIG_MAX_DESC_LEN   (DNA_MSIG_HDR_LEN + DNA_MSIG_MAX_N * DNA_MSIG_PUBKEY_LEN)
/** A multisig address: SHA3-512 digest. */
#define DNA_MSIG_ADDR_LEN       64u

/**
 * Encode a descriptor. The caller's keys are taken AS GIVEN — the
 * encoder never sorts (a caller that passes an unsorted set is refused,
 * so the one canonical encoding is the only thing it can produce).
 *
 * @param m        signatures required, 1 .. n
 * @param n        key count, DNA_MSIG_MIN_N .. DNA_MSIG_MAX_N
 * @param pubkeys  n × DNA_MSIG_PUBKEY_LEN contiguous bytes, strictly
 *                 ascending, none a zero key
 * @param out      receives DNA_MSIG_DESC_LEN(n) bytes
 * @param out_cap  capacity of out
 * @param out_len  receives the written length
 * @return 0 / -1 (NULL, a bound, order, zero key, capacity).
 */
int dna_msig_desc_encode(uint8_t m, uint8_t n, const uint8_t *pubkeys,
                         uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * STRICT parse + validate of one descriptor of exactly `len` bytes: the
 * tag, 2 <= N <= 7, 1 <= M <= N, len == 18 + N × 2592, strictly
 * ascending keys, no zero key.
 *
 * @param m_out     optional, receives M
 * @param n_out     optional, receives N
 * @param keys_out  optional, receives a pointer INTO `d` at the first key
 * @return 0 valid / -1 invalid.
 */
int dna_msig_desc_parse(const uint8_t *d, size_t len, uint8_t *m_out,
                        uint8_t *n_out, const uint8_t **keys_out);

/**
 * address = SHA3-512(descriptor). The descriptor is VALIDATED first
 * (dna_msig_desc_parse): an invalid descriptor has no address.
 * @return 0 / -1 invalid descriptor / -2 hash backend failure.
 */
int dna_msig_address(const uint8_t *d, size_t len,
                     uint8_t out[DNA_MSIG_ADDR_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* DNA_MSIG_WIRE_H */
