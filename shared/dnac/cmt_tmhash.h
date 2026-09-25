/**
 * @file shared/dnac/cmt_tmhash.h
 * @brief cometbft @709fd12b `crypto/tmhash` ported to the DNA hash.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-A of the cometbft → C consensus port. Nothing in the running
 * chain calls anything in this file; it is additive only. The live witness
 * BFT and the QC V2 path are byte-identically untouched. (The T3 wave-1
 * modules tm_commit / tm_vote / tm_wal that R1 left in place were deleted
 * in R2 — atlas-dec-a309a65984f1709149b40db9cb5b38a7.)
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── The one substitution ───────────────────────────────────────────────
 * The reference hashes with SHA-256 (`crypto/tmhash/hash.go:9`,
 * `Size = sha256.Size` = 32). This port hashes with SHA3-512 and a 64-byte
 * digest, per the APPROVED substitution table (umbrella rev 3,
 * atlas-dec-d5e766defde138eb6dd02e5b81e735a8, item 4). NOTHING ELSE about
 * the construction changes: the same bytes are fed in the same order, so
 * every Merkle prefix, every preimage and every field order below is the
 * reference's.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `tmhash.New` (:14-16), `sha256trunc` (:42-64), `NewTruncated`
 *     (:67-71) — an incremental hash.Hash object. This port has only the
 *     one-shot `qgp_sha3_512`, and every reference call site that used the
 *     incremental form (`leafHashOpt`, `innerHashOpt`) collapses into the
 *     one-shot form here, producing identical bytes.
 *   · `sha256trunc.Sum` (:48-51) as an incremental object — same reason as
 *     `New`/`NewTruncated` above. The one-shot `cmt_tmhash_sum_truncated`
 *     below produces the same bytes.
 *
 * ── CORRECTION (wave R1-D): the truncation IS this tree's address ───────
 * This bullet previously read: "`TruncatedSize` (:39) and `SumTruncated`
 * (:74-77) — the reference truncates a hash to 20 bytes to make a validator
 * ADDRESS. DNA does not: a validator identity is an independent 32-byte
 * witness id (`ledger_ids.h`), never a truncation of a key hash."
 *
 * THE SECOND HALF OF THAT SENTENCE IS FALSE, and wave R1-A wrote it without
 * reading the code. This tree derives its witness identity by exactly that
 * construction:
 *
 *     witness_id = SHA3-512(pubkey)[0..31]
 *
 * — `nodus_chain_config_derive_witness_id`, defined at
 * `nodus/src/witness/nodus_witness_chain_config.c:637-652` and declared at
 * `nodus/include/nodus/nodus_chain_config.h:319-326`, whose body is one EVP
 * SHA3-512 over the 2592-byte key followed by a 32-byte `memcpy`;
 * `shared/dnac/vset_wire.h:121` and `shared/dnac/domain_wire.h:118` both
 * document the same derivation. Waves R1-B and R1-C each wrote the
 * truncation independently (`cmt_vote.c` `cmt_pubkey_address`,
 * `cmt_validator_set.c` `cmt_pub_key_address`) and each reported the
 * discrepancy rather than editing this header. R1-D resolves it: the
 * truncation lives HERE, once, as `cmt_address_hash`, and those two remain
 * as typed wrappers that delegate to it.
 *
 * Reference @709fd12b: crypto/tmhash/hash.go (77 lines, SHA-256
 * 100a1604856e0d1154e242540c7a460e2d576a387ad4af8f62ba46a1f1fbac68),
 * crypto/crypto.go (54 lines, SHA-256
 * 60a32ee2c8f9a1090968ff9fcd3410f0099d21da8c7625b1b03f23d2647a1ceb).
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_TMHASH_H
#define SHARED_DNAC_CMT_TMHASH_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/** cometbft@709fd12b crypto/tmhash/hash.go:9 — `Size = sha256.Size`.
 *  Here: the SHA3-512 digest length. Every hash, Merkle node and BlockID
 *  in the port is this wide. */
#define CMT_TMHASH_SIZE 64

/**
 * cometbft@709fd12b crypto/tmhash/hash.go:39 — `TruncatedSize = 20`.
 * Here 32, the DNA witness-id width, per the APPROVED substitution table
 * (umbrella rev 3, atlas-dec-d5e766defde138eb6dd02e5b81e735a8, item 4:
 * "32-byte validator identity as the address"). `crypto.AddressSize` is
 * defined as this constant (crypto/crypto.go:8-11), so widening the
 * address and widening the truncation are the same change — which is why
 * there is ONE constant here and not two.
 *
 * The literal 32 is written out rather than spelled `CMT_PB_ADDRESS_MAX`
 * because cmt_pb.h includes THIS header. The two must stay equal, and that
 * is not left to a comment: cmt_block.h carries a `_Static_assert` tying
 * this constant to `CMT_ADDRESS_SIZE`, so a change to either one that
 * forgets the other fails to compile.
 */
#define CMT_TMHASH_TRUNCATED_SIZE 32

/** Return codes shared by every cmt_* module, identical to the contract
 *  of shared/dnac/qc_v2.h (and of the deleted tm_commit.h before it):
 *    0  accept
 *   -1  REJECT — the input is bad. Deterministic: every honest node
 *       reaches the same verdict on the same bytes.
 *   -2  FAULT  — THIS process could not decide (allocation, hash backend).
 *       A caller MUST NOT count -2 as a negative vote or as invalid input. */
#define CMT_OK      0
#define CMT_REJECT (-1)
#define CMT_FAULT  (-2)

/** One piece of a multi-part preimage. */
typedef struct {
    const uint8_t *data;
    size_t         len;
} cmt_tmhash_part_t;

/** Concatenations at or below this length are built on the stack. 256 is
 *  chosen so the hot path — innerHash's 1 + 64 + 64 = 129 bytes — never
 *  allocates. Nothing about the output depends on this number. */
#define CMT_TMHASH_STACK_SCRATCH 256

/**
 * cometbft@709fd12b crypto/tmhash/hash.go:19-22 — `Sum(bz)`.
 * @return CMT_OK, or CMT_FAULT if the hash backend fails.
 */
static inline int cmt_tmhash_sum(const uint8_t *bz, size_t len,
                                 uint8_t out[CMT_TMHASH_SIZE])
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    /* A zero-length input with a NULL pointer is the reference's
     * `tmhash.Sum([]byte{})` (hash.go:17) and must hash the empty string,
     * not fail. qgp_sha3_512 is fed a valid pointer either way. */
    static const uint8_t empty = 0;
    if (len == 0) {
        bz = &empty;
    } else if (bz == NULL) {
        return CMT_FAULT;
    }
    if (qgp_sha3_512(bz, len, out) != 0) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

/**
 * cometbft@709fd12b crypto/tmhash/hash.go:27-34 — `SumMany(data, rest...)`.
 * Hashes the parts as if they were one joined slice. The reference streams
 * them into an incremental hasher; with a one-shot backend they are joined
 * first, which produces the same digest by definition of the sponge.
 * @return CMT_OK, CMT_FAULT on allocation failure or a hash backend error.
 */
static inline int cmt_tmhash_sum_many(const cmt_tmhash_part_t *parts,
                                      size_t nparts,
                                      uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t  stack[CMT_TMHASH_STACK_SCRATCH];
    uint8_t *buf = stack;
    uint8_t *heap = NULL;
    size_t   total = 0;
    size_t   off = 0;
    size_t   i;
    int      rc;

    if (out == NULL || (parts == NULL && nparts != 0)) {
        return CMT_FAULT;
    }
    for (i = 0; i < nparts; i++) {
        if (parts[i].len != 0 && parts[i].data == NULL) {
            return CMT_FAULT;
        }
        /* Explicit overflow check: Go's slice append would have panicked
         * long before this, C would wrap silently (INVARIANT 7495d337). */
        if (parts[i].len > (size_t)-1 - total) {
            return CMT_FAULT;
        }
        total += parts[i].len;
    }
    if (total > sizeof(stack)) {
        heap = (uint8_t *)malloc(total);
        if (heap == NULL) {
            return CMT_FAULT;
        }
        buf = heap;
    }
    for (i = 0; i < nparts; i++) {
        if (parts[i].len != 0) {
            memcpy(buf + off, parts[i].data, parts[i].len);
            off += parts[i].len;
        }
    }
    rc = cmt_tmhash_sum(buf, total, out);
    if (heap != NULL) {
        free(heap);
    }
    return rc;
}

/**
 * cometbft@709fd12b crypto/tmhash/hash.go:73-77 — `SumTruncated(bz)`.
 * "Returns the first TruncatedSize bytes of the hash of bz." The reference
 * hashes with SHA-256 and keeps 20; this hashes with SHA3-512 and keeps 32
 * (the one substitution, above). The truncation is a plain prefix — the
 * reference's `hash[:TruncatedSize]` — not a re-hash and not a fold.
 *
 * @param out receives CMT_TMHASH_TRUNCATED_SIZE bytes.
 * @return CMT_OK, or CMT_FAULT on NULL or a hash backend failure.
 */
static inline int cmt_tmhash_sum_truncated(
        const uint8_t *bz, size_t len,
        uint8_t out[CMT_TMHASH_TRUNCATED_SIZE])
{
    uint8_t full[CMT_TMHASH_SIZE];
    int     rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_tmhash_sum(bz, len, full);
    if (rc != CMT_OK) {
        return rc;
    }
    memcpy(out, full, (size_t)CMT_TMHASH_TRUNCATED_SIZE);   /* hash.go:76 */
    return CMT_OK;
}

/**
 * cometbft@709fd12b crypto/crypto.go:18-20 — `AddressHash(bz)`.
 *
 * THE ONE PLACE IN THIS PORT WHERE A PUBLIC KEY BECOMES AN ADDRESS. The
 * reference's body is exactly `Address(tmhash.SumTruncated(bz))`, so this
 * is `cmt_tmhash_sum_truncated` under another name — and the name matters,
 * because the reference's `crypto.PubKey.Address()` implementations
 * (e.g. crypto/ed25519/ed25519.go:156-161) call this function, not the
 * hash package.
 *
 * Under the approved substitutions the result is SHA3-512(pubkey)[0..31],
 * which is the derivation this tree ALREADY uses for a witness identity —
 * see "CORRECTION (wave R1-D)" in the file header for the citations. It is
 * REPRODUCED on `qgp_sha3_512` rather than calling
 * `nodus_chain_config_derive_witness_id`, because `shared/` must not depend
 * on `nodus/`; the bytes are identical, and nothing about the derivation is
 * invented here.
 *
 * `cmt_pubkey_address` (cmt_vote.h) and `cmt_pub_key_address`
 * (cmt_validator_set.h) are the two typed wrappers over this function; both
 * delegate, so there is exactly ONE computation of an address in the tree.
 *
 * @return CMT_OK, or CMT_FAULT on NULL or a hash backend failure.
 */
static inline int cmt_address_hash(const uint8_t *bz, size_t len,
                                   uint8_t out[CMT_TMHASH_TRUNCATED_SIZE])
{
    return cmt_tmhash_sum_truncated(bz, len, out);         /* crypto.go:19 */
}

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_TMHASH_H */
