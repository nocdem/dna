/* exp_extract — DNAC Explorer: dnac_v3_block pages -> index rows.
 *
 * The node decodes every item with its own runtime decoders and answers
 * the effects already derived (dnac_v3_block, nodus/include/nodus/nodus.h;
 * design docs/plans/2026-09-28-scan-v3-design.md item 1). This module
 * therefore deserializes nothing: it copies one decoded page
 * (nodus_dnac_v3_block_result_t) into the explorer's row shapes
 * (exp_db.h exp_block_batch_t) and checks that consecutive pages form ONE
 * block — no second implementation of any consensus encoding lives here.
 *
 * Nodus EVM P4-C: an applied EVM item's "ev"/"ri"/"ro" (nodus.h) become one
 * exp_evm_row_t in batch->evms, copied as-is; keys outside their rules
 * (on a refused item, a reserve move without "ev", both directions, a
 * created address on a failed item, a cut-short flag beside a short
 * ticket list) refuse the page.
 *
 * Determinism (index reproducibility): the rows are a pure function of the
 * page content; items keep the block's own index order, io rows keep the
 * node's call order (consumed, then created, per item).
 */
#ifndef EXP_EXTRACT_H
#define EXP_EXTRACT_H

#include <stdint.h>

#include "exp_db.h"
#include "nodus/nodus.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Refusal ceiling on a block's item count ("n"): a first page announcing
 * more is refused before anything is collected. The chain's own per-class
 * admission caps (NODUS_V2_ENV_BATCH_MAX 3 209 envelopes plus the claim
 * cap, nodus/src/witness/nodus_witness_cmt_app.h) keep a real block far
 * below it; the bound exists so a hostile server cannot make the explorer
 * accumulate an unbounded block. Rows grow with pages actually received,
 * never with the announced "n". */
#define EXP_BLOCK_MAX_ITEMS 16384u

/* Append one page to `batch`.
 *
 * The first page (batch->have_header == 0) sets the block header; every
 * later page must carry the SAME header (height, block id, previous id,
 * time, proposer, global root, applied count, item count) — a page from a
 * different block, or from a server that disagrees after a rotate, is
 * refused. The page's items must continue exactly where the batch ends
 * (items[0].index == batch->n_items, then +1 each).
 *
 * The whole page is checked before anything is appended: on -1 the batch
 * is left exactly as it was.
 *
 * @return 0 appended; -1 refused (mismatched header, index gap, a bound
 *         exceeded, allocation failure)
 */
int exp_extract_page(const nodus_dnac_v3_block_result_t *page, exp_block_batch_t *batch);

#ifdef __cplusplus
}
#endif

#endif /* EXP_EXTRACT_H */
