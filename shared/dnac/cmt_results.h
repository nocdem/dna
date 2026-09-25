/**
 * @file shared/dnac/cmt_results.h
 * @brief cometbft @709fd12b `types/results.go` ported to C — the ABCI
 *        result list whose Merkle root is LastResultsHash.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-C of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── What this produces ─────────────────────────────────────────────────
 * `LastResultsHash` — the Merkle root over the marshalled deterministic
 * `ExecTxResult`s of the PREVIOUS block (D-19 rev 6 item 7,
 * atlas-dec-d106407a31d7d16d49d51990b75c36c6; the reference's own site is
 * state/execution.go:658). The first block's is H(""), the empty tree's
 * root, because the list is empty there (consensus/replay.go:368 via
 * crypto/merkle/tree.go:16-18).
 *
 * ── Why only four fields ───────────────────────────────────────────────
 * `deterministicExecTxResult` (results.go:47-54) keeps Code, Data,
 * GasWanted and GasUsed and DROPS Log, Info, Events and Codespace, because
 * those four are application text that two honest nodes may legitimately
 * write differently — and this root is inside a header, so a difference
 * would be a chain split. `cmt_pb_exec_tx_result_t` (cmt_pb.h:415-420)
 * already carries only the surviving four, so in C the deterministic copy
 * is the IDENTITY; it is ported anyway so the reference row has a C
 * counterpart and so the reasoning is recorded where it applies.
 *
 * A result that is entirely zero marshals to ZERO BYTES (K-1 rev 2 rule a:
 * every field is omit-zero), and a zero-length leaf hashes to H(0x00)
 * (crypto/merkle/hash.go:21-23). That is not a degenerate case to guard
 * against — it is the encoding of a successful transaction that consumed
 * no gas and returned no data, and it is what the reference hashes too.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Pure functions of the list. No clock, no randomness, no map, no
 * allocation: the leaf bytes go into a caller-supplied scratch buffer and
 * the leaf descriptors into a caller-supplied array, in list order. The
 * list order is the caller's — this module never sorts, exactly as the
 * reference never sorts (the results are in transaction order).
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 * Nothing. All five rows of the reference file (`NewResults` :13,
 * `Hash` :22, `ProveResult` :27, `toByteSlices` :32,
 * `deterministicExecTxResult` :47) have a counterpart below.
 * `ProveResult` has zero consumers in the reference's own consensus path
 * and is recorded in the port map as such; it is ported because the rule
 * is the reference in everything, and the test exercises it.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   types/results.go 54 lines
 *     74de33a8e62eb9755258363b621d5b2137d834ead605b2acb97f004cbd35f830
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_RESULTS_H
#define SHARED_DNAC_CMT_RESULTS_H

#include <stdint.h>
#include <stddef.h>

#include "cmt_tmhash.h"
#include "cmt_merkle.h"
#include "cmt_pb.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cometbft@709fd12b types/results.go:9 — `type ABCIResults`.
 * Caller-owned storage: `results_cap` slots of which `results_len` are
 * used. The reference's slice is `[]*abci.ExecTxResult`; a nil element
 * would make `toByteSlices` dereference nil and panic, which in C is
 * simply not representable here — the array holds values.
 */
typedef struct {
    cmt_pb_exec_tx_result_t *results;
    size_t                   results_cap;
    size_t                   results_len;
} cmt_abci_results_t;

/**
 * cometbft@709fd12b types/results.go:47-54 —
 * `deterministicExecTxResult()`. Keeps {Code, Data, GasWanted, GasUsed}.
 *
 * ⚠ THE IDENTITY IN THIS PORT, and deliberately so: the four fields the
 * reference strips are not present in `cmt_pb_exec_tx_result_t` at all
 * (cmt_pb.h:399-420 records that as a stated deviation — the decoder
 * REFUSES them rather than parsing and discarding them). Ported so the
 * reference row is accounted for and so a later wave that adds a field to
 * the struct is forced to decide, here, whether it is deterministic.
 *
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_deterministic_exec_tx_result(const cmt_pb_exec_tx_result_t *response,
                                     cmt_pb_exec_tx_result_t *out);

/**
 * cometbft@709fd12b types/results.go:13-19 — `NewResults()`.
 * Maps `deterministicExecTxResult` over the responses into `out`, whose
 * storage the caller supplies.
 * @return CMT_OK, CMT_REJECT if `n` exceeds `out->results_cap`,
 *         CMT_FAULT on NULL.
 */
int cmt_new_results(const cmt_pb_exec_tx_result_t *responses, size_t n,
                    cmt_abci_results_t *out);

/**
 * cometbft@709fd12b types/results.go:32-43 — `toByteSlices()`.
 * Marshals every result into `scratch`, back to back, and fills `items`
 * with a descriptor per leaf. The reference panics on a marshal failure
 * (:37-39); here that is the return code.
 *
 * @param scratch_cap must hold the sum of the marshalled lengths. Each
 *        result costs at most 5 (code) + 11 (gas_wanted) + 11 (gas_used)
 *        + 1 + uvarint(len(data)) + len(data) bytes, so a bound is
 *        `results_len * 33 + total_data_bytes` — `data` is application
 *        payload of unbounded length and only the caller knows it.
 * @param items_cap must be at least `results_len`.
 * @return CMT_OK, CMT_REJECT if it does not fit, CMT_FAULT on NULL.
 */
int cmt_abci_results_to_byte_slices(const cmt_abci_results_t *a,
                                    uint8_t *scratch, size_t scratch_cap,
                                    cmt_merkle_item_t *items,
                                    size_t items_cap);

/**
 * cometbft@709fd12b types/results.go:22-24 — `Hash()`.
 * The Merkle root over the marshalled results — LastResultsHash. An empty
 * list gives H(""), the empty tree's root.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_abci_results_hash(const cmt_abci_results_t *a,
                          uint8_t *scratch, size_t scratch_cap,
                          cmt_merkle_item_t *items, size_t items_cap,
                          uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@709fd12b types/results.go:27-30 — `ProveResult()`.
 * The inclusion proof of result `i`.
 *
 * The reference indexes `proofs[i]` with no bounds check (:29) — a Go
 * index panic for an out-of-range i, made an explicit CMT_REJECT here
 * (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07). An EMPTY list
 * has no proofs at all, so every i rejects.
 *
 * @param proofs scratch for `results_len` proofs; the one at index `i` is
 *        also copied to `out`.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_abci_results_prove_result(const cmt_abci_results_t *a, size_t i,
                                  uint8_t *scratch, size_t scratch_cap,
                                  cmt_merkle_item_t *items, size_t items_cap,
                                  cmt_proof_t *proofs, size_t proofs_cap,
                                  cmt_proof_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_RESULTS_H */
