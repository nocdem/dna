/**
 * @file shared/dnac/ledger_roots_v2.h
 * @brief Ledger V2 Season 2 — the tagged state-root hierarchy (INACTIVE).
 *
 * Canonical hashing for the V2 hierarchy: SYSTEM/CORE composition, the
 * generic DomainHead + domains_root Merkle, global_state_root, supply_root
 * and token_root.
 *
 * ACTIVATION: this hierarchy IS the version-3 (cometbft) chain's state
 * root — global_state_root is the app_hash every block commits
 * (nodus_witness_cmt_app.c `resp->app_hash = blk->out_global_root`), and
 * the SYSTEM / CORE runtimes' state roots are nodus_witness_system_root_v2
 * / nodus_witness_core_root_v2 (nodus_witness_v2_claims.c). The legacy
 * five-input state_root (nodus_witness_merkle.c combine_v3) and the
 * `epoch_state` leg are DELETED by the tokenomics-v3 root-layout round
 * (docs/plans/decisions/2026-09-25-root-layout-round.md K2/K3).
 *
 * Conventions (architecture report §5.1, S2 charter §1):
 *   - SHA3-512 everywhere (qgp_sha3_512 — same digest in both trees);
 *   - every preimage starts with a FIXED 16-byte zero-padded ASCII tag;
 *   - fixed-width unsigned integers, big-endian;
 *   - no native struct serialization;
 *   - iterated collections sorted by their canonical key, duplicates reject;
 *   - EMPTY subtrees are TAGGED roots (SHA3-512 of the tag alone), never
 *     all-zero placeholders;
 *   - any missing/unreadable component fails the whole computation (-1) —
 *     no partial or fallback root is ever produced.
 *
 * ── TAG TABLE (each exactly 16 bytes, zero-padded) ────────────────────
 *   composition   "NDS.SYS.v4"      system_state_root (final pre-testnet
 *                                   wipe, package W-A: the treasury_root
 *                                   leg APPENDED as the 8th leg — a
 *                                   changed preimage is never hashed
 *                                   under the old tag; "NDS.SYS.v3" is
 *                                   HISTORY, the 7-leg composition of
 *                                   the root-layout round, "NDS.SYS.v2"
 *                                   the 8-leg composition of P1 (with
 *                                   epoch_state, no treasury) and
 *                                   "NDS.SYS.v1" the 7-leg one before
 *                                   it)
 *                 "NDS.CORE.v2"     core_state_root (tokenomics-v3 P2
 *                                   added the accrual_root leg — a
 *                                   changed preimage is never hashed
 *                                   under the old tag; "NDS.CORE.v1" is
 *                                   HISTORY, the 6-leg composition
 *                                   before P2)
 *                 "NDS.GLOBAL.v1"   global_state_root
 *   supply        "NDS.SUPPLY.v2"   supply_root (leafless single hash;
 *                                   P2 added reward_pool — "NDS.SUPPLY.v1"
 *                                   is HISTORY, the 3-counter preimage)
 *   accrual (P2)  "NDS.ACLEAF.v1"   reward-accrual leaf
 *                 "NDS.ACNODE.v1"   reward-accrual Merkle inner node
 *   tokens        "NDS.TOKLEAF.v1"  token leaf
 *                 "NDS.TOKNODE.v1"  token Merkle inner node
 *   treasury      "NDS.TRLEAF.v1"   treasury-pool leaf (W-A)
 *   (W-A)         "NDS.TRNODE.v1"   treasury-pool Merkle inner node
 *   genesis       "NDS.SYSPAYL.v3"  system_payload_root (W-A: 5 legs,
 *   payload                         treasury_root APPENDED last;
 *                                   "NDS.SYSPAYL.v2" is HISTORY, the
 *                                   4-leg form of the root-layout round,
 *                                   "NDS.SYSPAYL.v1" the 5-leg form with
 *                                   epoch_state before it)
 *   RETIRED       "NDS.EPOCH.v2" / "NDS.EPNODE.v2" / "NDS.E.EPOCH.v2" —
 *                 the epoch_state leg's leaf / inner node / empty root,
 *                 DELETED with the leg (root-layout round K2). Never
 *                 reused for another preimage.
 *   domains      "NDS.DOMHEAD.v1"  DomainHead hash
 *                 "NDS.DOMNODE.v1"  domains Merkle inner node
 *   vset (S3)     "NDS.VSLEAF.v1"   validator-set snapshot leaf
 *                 "NDS.VSNODE.v1"   validator-set Merkle inner node
 *   attendance    "NDS.ATTEP.v1"    per-epoch attendance digest (P1, S-2)
 *   (P1, S-2)     "NDS.ATLEAF.v1"   attendance leg leaf
 *                 "NDS.ATNODE.v1"   attendance leg Merkle inner node
 *   empty roots   "NDS.E.VSET.v1"   validator_set_root   (EMPTY vset table)
 *                 "NDS.E.DOMREG.v1" domain_registry_root (until S4)
 *                 "NDS.E.MANIF.v1"  manifest_root        (until S6)
 *                 "NDS.E.POOLS.v1"  pools_root           (until S7)
 *                 "NDS.E.CLAIMS.v1" claims_root          (until S6)
 *                 "NDS.E.NAMES.v1"  name_root            (timing open, O-7)
 *                 "NDS.E.TOKENS.v1" token_root of an EMPTY registry
 *                 "NDS.E.ATTND.v1" attendance_root of an EMPTY
 *                                   v2_attendance_epoch table (P1)
 *                 "NDS.E.ACCRU.v1"  accrual_root of an EMPTY
 *                                   v2_reward_accrual table (P2)
 *                 "NDS.E.TREAS.v1"  treasury_root of an EMPTY
 *                                   v2_treasury table (W-A)
 *   Collision scan (W-A): `git grep -n "NDS\.TR\|NDS\.E\.TREAS\|TRLEAF\|
 *   TRNODE"` over the whole tree found NO prior use of the three W-A
 *   tags before adoption. SELF-CONSISTENT, not externally referenced —
 *   the P1 ATTEP / P2 ACLEAF precedent; the proof is an INDEPENDENT
 *   oracle KAT over this contract (author != auditor).
 *   storage       "NDS.SYS.v5"      system_state_root v5 (9 legs, the
 *   (storage      "NDS.STOR.v2"     storage_root APPENDED last) and the
 *    reward v1)                     storage leg composition (4 legs —
 *                                   archive reward; "NDS.STOR.v1", the
 *                                   3-leg form, was replaced before any
 *                                   activation and is retired, never
 *                                   reused)
 *                 "NDS.STLEAF.v2"   storage registry leaf (fail_streak
 *                                   and, K9, grace_until appended;
 *                                   "NDS.STLEAF.v1" retired the same
 *                                   way)
 *                 "NDS.STRNODE.v1"  storage registry Merkle inner node
 *                 "NDS.STSET.v1"    frozen storage set hash S(H)
 *                 "NDS.STSLEAF.v1"  frozen-sets leaf
 *                 "NDS.STSNODE.v1"  frozen-sets Merkle inner node
 *                 "NDS.STREP.v1"    storage report leaf
 *                 "NDS.STRPNODE.v1" storage report Merkle inner node
 *                 "NDS.STEXIT.v1"   storage exit release UTXO identity
 *                 "NDS.E.STREG.v1"  registry_root of an EMPTY registry
 *                 "NDS.E.STSET.v1"  sets_root with NO frozen set
 *                 "NDS.E.STREP.v1"  reports_root with NO report
 *   Storage tags: decision 2026-10-04-storage-reward-approved.md (bytes
 *   doc docs/plans/2026-10-04-storage-reward-bytes.md items 1-6).
 *   Collision scan 2026-10-04: `git grep -F` of each tag over the whole
 *   tree and every branch — no prior use. SELF-CONSISTENT, not
 *   externally referenced; proven by an INDEPENDENT oracle KAT before
 *   merge (author != auditor). "NDS.STPROBE.v1" (bytes item 7) is an
 *   OFF-CHAIN probe seed and is NOT defined here.
 *   archive       "NDS.STSEG.v1"    segment root Root(k) (a PLAIN hash
 *   (storage                        over 17,280 header hashes)
 *    reward v1    "NDS.STSGLEAF.v1" segment list leaf
 *    rev 4)       "NDS.STSGNODE.v1" segment list Merkle inner node
 *                 "NDS.E.STSEG.v1"  segments_root with NO segment
 *                 "NDS.STASGN.v1"   assignment key A(k)
 *                 "NDS.STSAMP.v1"   OFF-CHAIN probe sample x_i (never a
 *                                   consensus input; here so the probe
 *                                   client and the KAT share ONE
 *                                   implementation)
 *   Archive tags: decision 2026-10-05-archive-reward-bytes-approved.md
 *   (bytes doc docs/plans/2026-10-05-archive-reward-bytes.md items 1-5,
 *   §6). Collision scan 2026-10-05: `git grep -E` of each new tag over
 *   the tree (oracle vectors excluded) — no prior use. SELF-CONSISTENT,
 *   not externally referenced; the independent oracle
 *   nodus/tests/vectors/archive_reward_oracle.py is the KAT.
 *   "NDS.STPROBE.v2" (the off-chain probe REQUEST, bytes §6) is a wire
 *   of the probe client and is NOT defined here.
 *   (domains_root has NO empty tag: SYSTEM must always be present — an
 *    empty domain list is a hard error, not an empty tree.)
 *
 * ── Composition preimages (exact) ─────────────────────────────────────
 *   system_state_root = SHA3-512("NDS.SYS.v4"  ‖ validator_root[64]
 *       ‖ delegation_root[64] ‖ chain_config_root[64]
 *       ‖ validator_set_root[64] ‖ domain_registry_root[64]
 *       ‖ manifest_root[64] ‖ attendance_root[64]
 *       ‖ treasury_root[64])                            — 8 legs
 *     tokenomics-v3 P1 (D-4, S-2) added the attendance leg ("NDS.SYS.v1"
 *     -> "NDS.SYS.v2"); the root-layout round (K2, 2026-09-25) removed
 *     the epoch_state leg — its table had no writer left after P2 — and
 *     moved the tag again ("NDS.SYS.v2" -> "NDS.SYS.v3"); the final
 *     pre-testnet wipe (package W-A, 2026-09-28/29, decision
 *     2026-09-28-treasury-pools-and-exact-self-stake.md answers 9 + 12)
 *     APPENDS treasury_root as the 8th and LAST leg ("NDS.SYS.v3" ->
 *     "NDS.SYS.v4"): a changed composition is a new tag, never the same
 *     tag over different bytes. `system_payload_root` below moved with
 *     it ("NDS.SYSPAYL.v3", 5 legs) — the treasury is SEEDED at genesis,
 *     so unlike attendance/domreg/manifest it IS a payload leg.
 *   treasury leaf (W-A) = SHA3-512("NDS.TRLEAF.v1" ‖ pool_id(4 BE)
 *       ‖ balance(8 BE))  — one per `v2_treasury` row; 16 + 4 + 8 = 28
 *       preimage bytes.
 *   treasury_root (W-A) = tagged Merkle over the treasury leaves,
 *       STRICTLY ascending pool_id (duplicates reject), inner
 *       "NDS.TRNODE.v1", n == 0 -> DNA_V2_EMPTY_TREASURY
 *       (SHA3-512("NDS.E.TREAS.v1" zero-padded to 16 bytes)). The pools
 *       are keyless and locked (pool ids 1..9 in the tokenomics §1 table
 *       order: 1 Storage, 2 Compute, 3 VPN/Bandwidth, 4 Future services,
 *       5 Security/bug bounty, 6 Liquidity, 7 Ecosystem grants,
 *       8 Foundation, 9 Community airdrop); this function commits
 *       whatever rows it is given and does not itself bound pool_id.
 *   core_state_root   = SHA3-512("NDS.CORE.v2" ‖ utxo_root[64]
 *       ‖ token_root[64] ‖ pools_root[64] ‖ claims_root[64]
 *       ‖ name_root[64] ‖ supply_root[64] ‖ accrual_root[64])
 *     tokenomics-v3 P2 (design §7 P2-8): the 7th leg `accrual_root`
 *     (the per-recipient reward accrual, v2_reward_accrual) and a NEW
 *     composition tag ("NDS.CORE.v1" -> "NDS.CORE.v2").
 *   global_state_root = SHA3-512("NDS.GLOBAL.v1" ‖ domains_root[64])
 *   supply_root       = SHA3-512("NDS.SUPPLY.v2" ‖ genesis_supply_raw(8 BE)
 *       ‖ total_minted_raw(8 BE) ‖ total_burned_raw(8 BE)
 *       ‖ reward_pool_raw(8 BE))
 *     tokenomics-v3 P2 (design §7 P2-8, "supply yaprağı reward_pool
 *     alanını içerir"): the reward pool is a committed counter of the
 *     native asset exactly like the three before it, so it joins THIS
 *     leaf rather than a leg of its own; the tag moves to "v2" because
 *     the preimage changed.
 *   accrual leaf (P2) = SHA3-512("NDS.ACLEAF.v1" ‖ owner_fp[64]
 *       ‖ amount(8 BE))   — one per `v2_reward_accrual` row, owner_fp
 *       = the recipient's raw 64-byte SHA3-512(pubkey).
 *   accrual_root (P2) = tagged Merkle over the accrual leaves, STRICTLY
 *       ascending owner_fp (duplicates reject), inner "NDS.ACNODE.v1",
 *       n == 0 -> DNA_V2_EMPTY_ACCRUAL.
 *
 *   SUPPLY OWNERSHIP (genericity correction, locked): the native DNAC
 *   issuance counters (genesis/minted/burned) are the NATIVE ASSET's
 *   commitment and the native asset belongs to the DNA_CORE runtime —
 *   supply_root is therefore a leg of core_state_root, NOT of
 *   system_state_root. This is a property of the CORE runtime's OWN
 *   root composition, not a framework rule: no generic structure
 *   assumes every domain has a supply leg; a future runtime commits
 *   its own asset state however its state root defines it.
 *   DomainHead hash   = SHA3-512("NDS.DOMHEAD.v1" ‖ domain_id(4 BE)
 *       ‖ domain_state_root[64] ‖ domain_height(8 BE)
 *       ‖ last_updated_global_height(8 BE) ‖ ruleset_version(4 BE)
 *       ‖ status(1))                                  — 105-byte payload
 *   token leaf hash   = SHA3-512("NDS.TOKLEAF.v1" ‖ token_id[64]
 *       ‖ decimals(1) ‖ flags(1) ‖ supply(8 BE) ‖ block_height(8 BE)
 *       ‖ name_len(2 BE) ‖ name ‖ symbol_len(2 BE) ‖ symbol
 *       ‖ creator_len(2 BE) ‖ creator_fp)
 *     (tokens.timestamp is EXCLUDED: it is bound from the LOCAL wall clock
 *      at apply time (nodus_witness_db.c token_add time(NULL)) and is
 *      therefore node-divergent — hashing it would fork the root.)
 *   vset leaf (S3)    = SHA3-512("NDS.VSLEAF.v1" ‖ epoch(8 BE)
 *       ‖ snapshot_hash[64])       — `epoch` is the EPOCH START HEIGHT and
 *       `snapshot_hash` is dna_vset_hash of the canonical snapshot bytes
 *       (shared/dnac/vset_wire.h). The snapshot BODY is never re-hashed
 *       here: the leaf binds the already-tagged snapshot commitment.
 *   attendance digest (P1, S-2) = SHA3-512("NDS.ATTEP.v1" ‖
 *       epoch_start(8 BE) ‖ n(4 BE) ‖
 *       Σ_{rows ASC by voter_id} (voter_id[32] ‖ signed_count(8 BE) ‖
 *                                 last_signed_height(8 BE)))
 *     `epoch_start` is the epoch that JUST ENDED at the boundary writing
 *     this digest (H - E); the sum ranges over EVERY row of the
 *     out-of-root `v2_attendance` table (no status join — any divergence
 *     anywhere in that table is caught, not just among seated
 *     validators). Rows MUST be strictly ascending by voter_id
 *     (duplicates reject). This is a PLAIN hash, not a Merkle tree — one
 *     digest per epoch, stored in `v2_attendance_epoch.digest`.
 *   attendance leaf (P1, S-2)   = SHA3-512("NDS.ATLEAF.v1" ‖
 *       epoch_start(8 BE) ‖ digest[64])   — the leaf of `attendance_root`
 *     below, one per row of `v2_attendance_epoch`.
 *
 *   ── storage reward v1 (bytes doc items 1-6; every tag 16 B padded) ──
 *   system_state_root v5 = SHA3-512("NDS.SYS.v5" ‖ validator_root[64]
 *       ‖ delegation_root[64] ‖ chain_config_root[64]
 *       ‖ validator_set_root[64] ‖ domain_registry_root[64]
 *       ‖ manifest_root[64] ‖ attendance_root[64]
 *       ‖ treasury_root[64] ‖ storage_root[64])          — 9 legs
 *     the 8 v4 legs in v4 order, storage_root APPENDED last (the W-A
 *     precedent). Used from the storage activation height on; before it
 *     "NDS.SYS.v4" above, unchanged. "NDS.SYSPAYL.v3" is unchanged —
 *     storage is not seeded at genesis.
 *   storage_root = SHA3-512("NDS.STOR.v2" ‖ registry_root[64]
 *       ‖ sets_root[64] ‖ reports_root[64] ‖ segments_root[64])
 *       (archive bytes item 5 — replaces the 3-leg "NDS.STOR.v1")
 *   registry leaf = SHA3-512("NDS.STLEAF.v2" ‖ node_fp[64] ‖ payee_fp[64]
 *       ‖ bond(8 BE) ‖ status(1) ‖ registered_height(8 BE)
 *       ‖ exit_height(8 BE) ‖ fail_streak(4 BE) ‖ grace_until(8 BE))
 *       — status 1 ACTIVE, 2 EXITING, 3 RELEASED (0 and > 3 invalid:
 *       refused, never hashed); 16 + 165 = 181 B (archive bytes item 4;
 *       grace_until appended by K9 before any activation, the tag
 *       stays "NDS.STLEAF.v2").
 *   ── archive reward (bytes doc 2026-10-05 items 1-3, §6) ──
 *   Root(k) = SHA3-512("NDS.STSEG.v1" ‖ k(8 BE) ‖ count(4 BE) = 17280
 *       ‖ hash[(k−1)·17280 + 1] ‖ … ‖ hash[k·17280])  — hash[h] the
 *       64-byte v2_blocks.block_id at height h, ascending; k >= 1 and
 *       k·17280 <= UINT64_MAX. A PLAIN hash (1,105,948-byte preimage).
 *   segment leaf = SHA3-512("NDS.STSGLEAF.v1" ‖ k(8 BE) ‖ Root(k)[64])
 *   segments_root = tagged Merkle over the segment leaves, STRICTLY
 *       ascending k, inner "NDS.STSGNODE.v1", n == 0 ->
 *       DNA_V2_EMPTY_STORAGE_SEGS ("NDS.E.STSEG.v1").
 *   A(k) = SHA3-512("NDS.STASGN.v1" ‖ Root(k)[64])
 *   holders(k) = the DNA_V2_STORAGE_HOLDERS (3) members with
 *       fail_streak < DNA_V2_STORAGE_FAIL_LIMIT (3) of smallest
 *       A(k) XOR node_fp read as a 64-byte big-endian integer (memcmp
 *       order); fewer eligible -> all eligible; duplicates refused.
 *   x_i = SHA3-512("NDS.STSAMP.v1" ‖ nonce[32] ‖ target_fp[64] ‖ i(4 BE))
 *       (OFF-CHAIN); block index = BE u64 x_i[0..8) mod B, part index =
 *       BE u32 x_i[8..12) mod parts_total; B == 0 / parts_total == 0
 *       refused.
 *   registry_root = tagged Merkle over the registry leaves, STRICTLY
 *       ascending node_fp (duplicates reject), inner "NDS.STRNODE.v1",
 *       n == 0 -> DNA_V2_EMPTY_STORAGE_REG ("NDS.E.STREG.v1").
 *   S(H) = SHA3-512("NDS.STSET.v1" ‖ epoch_start H(8 BE) ‖ count(4 BE)
 *       ‖ node_fp[0] ‖ … ‖ node_fp[count−1])   — node_fp STRICTLY
 *       ascending (duplicates reject); count 0 allowed (hashes over the
 *       empty list, no special case); count > DNA_V2_STORAGE_SET_MAX
 *       refused. A PLAIN hash, not a Merkle tree.
 *   sets leaf = SHA3-512("NDS.STSLEAF.v1" ‖ H(8 BE) ‖ S(H)[64])
 *   sets_root = tagged Merkle over the sets leaves, STRICTLY ascending H,
 *       inner "NDS.STSNODE.v1", n == 0 -> DNA_V2_EMPTY_STORAGE_SETS
 *       ("NDS.E.STSET.v1").
 *   report leaf = SHA3-512("NDS.STREP.v1" ‖ epoch_start(8 BE) ‖ seat(4 BE)
 *       ‖ S(H)[64] ‖ bitmap_len(2 BE) ‖ bitmap[bitmap_len])  — bitmap_len
 *       == ceil(count/8) is the CALLER's check; this layer only refuses
 *       bitmap_len > DNA_V2_STORAGE_BITMAP_MAX (32).
 *   reports_root = tagged Merkle over the report leaves, STRICTLY
 *       ascending (epoch_start, seat) (equal pair rejects), inner
 *       "NDS.STRPNODE.v1", n == 0 -> DNA_V2_EMPTY_STORAGE_REPORTS
 *       ("NDS.E.STREP.v1").
 *   exit_id = SHA3-512("NDS.STEXIT.v1" ‖ chain_id[32]
 *       ‖ DNA_DOMAIN_CORE(4 BE) ‖ release_height(8 BE) ‖ node_fp[64])
 *   exit nullifier = SHA3-512(exit_id[64] ‖ 0x11 ‖ u32be(201))  — the
 *       EPGRAD shape (nodus_witness_v2_epoch.c) with its own kind byte
 *       DNA_V2_STORAGE_EXIT_KIND and output index
 *       DNA_V2_STORAGE_EXIT_OUT_IDX. node_fp = SHA3-512(node_pk), taken
 *       AS GIVEN (no 0x02 tree-tag prefix, unlike EPGRAD's pubkey_hash).
 *
 * ── Merkle construction (RFC6962-style, per tree) ─────────────────────
 *   leaves  = the already-tagged 64-byte hashes (DomainHead / token leaf /
 *             vset / attendance / accrual / treasury leaf), in strictly
 *             ascending
 *             canonical-key order;
 *   inner   = SHA3-512(NODE_TAG[16] ‖ left[64] ‖ right[64]);
 *   an unpaired (odd) node is PROMOTED to the next level unchanged —
 *   the final leaf is NEVER duplicated;
 *   n == 1  → root = the single leaf hash;
 *   n == 0  → the tree's tagged EMPTY root (tokens/vset/...) or an error
 *             (domains — SYSTEM mandatory).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_LEDGER_ROOTS_V2_H
#define SHARED_DNAC_LEDGER_ROOTS_V2_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"
#include "dnac/dnac.h"   /* DNAC_EPOCH_LENGTH (DNA_V2_SEGMENT_BLOCKS)  */

#ifdef __cplusplus
extern "C" {
#endif

#define DNA_V2_ROOT_LEN 64

/* ── Tagged empty roots ─────────────────────────────────────────────── */
typedef enum {
    DNA_V2_EMPTY_VSET = 0,     /* validator_set_root   (S3)  */
    DNA_V2_EMPTY_DOMREG,       /* domain_registry_root (S4)  */
    DNA_V2_EMPTY_MANIFEST,     /* manifest_root        (S6)  */
    DNA_V2_EMPTY_POOLS,        /* pools_root           (S7)  */
    DNA_V2_EMPTY_CLAIMS,       /* claims_root          (S6)  */
    DNA_V2_EMPTY_NAMES,        /* name_root            (O-7) */
    DNA_V2_EMPTY_TOKENS,       /* empty token registry       */
    /* root-layout round (K2): DNA_V2_EMPTY_EPOCH_V2 ("NDS.E.EPOCH.v2")
     * DELETED with the epoch_state leg. The enum is an index into the
     * tag table only — no value of it is hashed or sent — so the members
     * below shifting down one changes no byte of any root. */
    /* tokenomics-v3 P1 (D-4, S-2) — APPENDED. */
    DNA_V2_EMPTY_ATTENDANCE,   /* empty v2_attendance_epoch  */
    /* tokenomics-v3 P2 (P2-8) — APPENDED. */
    DNA_V2_EMPTY_ACCRUAL,      /* empty v2_reward_accrual    */
    /* final pre-testnet wipe, W-A — APPENDED. */
    DNA_V2_EMPTY_TREASURY,     /* empty v2_treasury          */
    /* storage reward v1 (bytes doc items 1-3) — APPENDED. */
    DNA_V2_EMPTY_STORAGE_REG,     /* "NDS.E.STREG.v1" registry   */
    DNA_V2_EMPTY_STORAGE_SETS,    /* "NDS.E.STSET.v1" frozen sets */
    DNA_V2_EMPTY_STORAGE_REPORTS, /* "NDS.E.STREP.v1" reports    */
    /* archive reward (2026-10-05 bytes item 2) — APPENDED. */
    DNA_V2_EMPTY_STORAGE_SEGS,    /* "NDS.E.STSEG.v1" segments   */
    DNA_V2_EMPTY__COUNT
} dna_v2_empty_kind_t;

/** SHA3-512 of the kind's 16-byte tag alone. @return 0 / -1. */
int dna_v2_empty_root(dna_v2_empty_kind_t kind, uint8_t out[DNA_V2_ROOT_LEN]);

/* ── supply_root ────────────────────────────────────────────────────── */
/** tokenomics-v3 P2: gained `reward_pool_raw` and the tag "NDS.SUPPLY.v2"
 *  (was "NDS.SUPPLY.v1" over the three counters). */
int dna_v2_supply_root(uint64_t genesis_supply_raw,
                       uint64_t total_minted_raw,
                       uint64_t total_burned_raw,
                       uint64_t reward_pool_raw,
                       uint8_t out[DNA_V2_ROOT_LEN]);

/** Nodus EVM (design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
 *  rev 3 §5): the supply leaf of the EVM generation's CORE runtime —
 *    SHA3-512( DNA_V2_SUPPLY_TAG_EVM (16 bytes, zero-padded)
 *              ‖ genesis ‖ minted ‖ burned ‖ reward_pool
 *              ‖ evm_reserve_raw )                 (u64 BE each)
 *  The leaf GAINS the CORE EVM reserve bucket, so it is hashed under a NEW
 *  tag (a changed preimage is never hashed under the old one). Selected
 *  ONLY by a CORE runtime of generation >= the EVM generation
 *  (nodus_rt_core_state_root): every older generation keeps
 *  dna_v2_supply_root, byte-identical. The tag string is ONE definition
 *  (renumber at merge with another root change) — PROPOSED here, by the
 *  NDS.SUPPLY.vN precedent; collision scan: no other "NDS.SUPPLY.v3" in
 *  the tree. Operator approval of the tag is pending (the decision
 *  2026-10-02-onchain-names.md item 18 precedent). @return 0 / -1. */
#define DNA_V2_SUPPLY_TAG_EVM "NDS.SUPPLY.v3"
int dna_v2_supply_root_evm(uint64_t genesis_supply_raw,
                           uint64_t total_minted_raw,
                           uint64_t total_burned_raw,
                           uint64_t reward_pool_raw,
                           uint64_t evm_reserve_raw,
                           uint8_t out[DNA_V2_ROOT_LEN]);

/* ── accrual_root (tokenomics-v3 P2, P2-8) ─────────────────────────────
 * The per-recipient reward accrual (`v2_reward_accrual`): what each
 * owner has earned at past epoch boundaries and not yet been paid. A leg
 * of core_state_root. */

/** leaf = SHA3-512("NDS.ACLEAF.v1" ‖ owner_fp[64] ‖ amount(8 BE)).
 *  @return 0 / -1. */
int dna_v2_accrual_leaf_hash(const uint8_t owner_fp[DNA_V2_ROOT_LEN],
                             uint64_t amount,
                             uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * accrual_root over `v2_reward_accrual` rows, STRICTLY ASCENDING owner_fp
 * (byte-lexicographic; equal or descending neighbours reject — insertion
 * order can never reach the root); inner = SHA3-512("NDS.ACNODE.v1" ‖
 * left ‖ right); odd node promoted; n == 1 the single leaf; n == 0 ->
 * DNA_V2_EMPTY_ACCRUAL.
 * @return 0 / -1 (NULL, bad order, allocation or digest failure).
 */
int dna_v2_accrual_root(const uint8_t (*owner_fps)[DNA_V2_ROOT_LEN],
                        const uint64_t *amounts, size_t n,
                        uint8_t out[DNA_V2_ROOT_LEN]);

/* ── name_root (HF-4) ──────────────────────────────────────────────────
 * The on-chain names (`v2_names`, design docs/plans/2026-10-02-onchain-
 * names-design.md rev 4 §2 "name_root"; tags approved by decision
 * 2026-10-02-onchain-names.md item 18). The EXISTING 5th leg of
 * core_state_root (it was the tagged-empty placeholder since S2), so the
 * composition tag "NDS.CORE.v2" does not change: an empty table is
 * byte-identical to every pre-H root. */

/** Longest name the leaf accepts (DNAC_NAME_MAX_LEN, dnac.h). */
#define DNA_V2_NAME_MAX_LEN 36u

typedef struct {
    uint8_t  name_len;                      /* 1..DNA_V2_NAME_MAX_LEN     */
    uint8_t  name[DNA_V2_NAME_MAX_LEN];
    uint8_t  owner[DNA_V2_ROOT_LEN];        /* 64 raw bytes               */
    uint64_t registered_height;
} dna_v2_name_row_t;

/** leaf = SHA3-512("NDS.NMLEAF.v1" ‖ name_len u8 ‖ name ‖ owner[64]
 *  ‖ registered_height u64 BE). @return 0 / -1 (NULL, length 0 or over
 *  DNA_V2_NAME_MAX_LEN). */
int dna_v2_name_leaf_hash(const dna_v2_name_row_t *row,
                          uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * name_root over `v2_names` rows in STRICTLY ascending BINARY name order
 * (memcmp over the common prefix, then the shorter first — "abc" < "abcd"
 * < "abd"; equal or descending neighbours reject); inner =
 * SHA3-512("NDS.NMNODE.v1" ‖ left ‖ right); odd node promoted; n == 1 the
 * single leaf; n == 0 -> DNA_V2_EMPTY_NAMES ("NDS.E.NAMES.v1").
 * @return 0 / -1.
 */
int dna_v2_names_root(const dna_v2_name_row_t *rows, size_t n,
                      uint8_t out[DNA_V2_ROOT_LEN]);

/** BINARY name order (SQLite's default BLOB collation): <0 / 0 / >0. */
int dna_v2_name_cmp(const uint8_t *a, size_t a_len,
                    const uint8_t *b, size_t b_len);

/* ── treasury_root (final pre-testnet wipe, W-A) ───────────────────────
 * The keyless, locked treasury pools (`v2_treasury`): one balance per
 * pool id, seeded from the genesis document. A leg of system_state_root
 * (the 8th, last) and of system_payload_root (the 5th, last). */

/** leaf = SHA3-512("NDS.TRLEAF.v1" ‖ pool_id(4 BE) ‖ balance(8 BE)).
 *  @return 0 / -1. */
int dna_v2_treasury_leaf_hash(uint32_t pool_id, uint64_t balance,
                              uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * treasury_root over `v2_treasury` rows, STRICTLY ASCENDING pool_id
 * (equal or descending neighbours reject — insertion order can never
 * reach the root); inner = SHA3-512("NDS.TRNODE.v1" ‖ left ‖ right);
 * odd node promoted; n == 1 the single leaf; n == 0 ->
 * DNA_V2_EMPTY_TREASURY.
 * @return 0 / -1 (NULL, bad order, allocation or digest failure).
 */
int dna_v2_treasury_root(const uint32_t *pool_ids, const uint64_t *balances,
                         size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/* ── token_root ─────────────────────────────────────────────────────── */
#define DNA_V2_TOKEN_ID_LEN   64
#define DNA_V2_TOKEN_STR_MAX  1024  /* per-string sanity cap (name/symbol/fp) */

typedef struct {
    uint8_t     token_id[DNA_V2_TOKEN_ID_LEN];  /* canonical key */
    const char *name;        size_t name_len;
    const char *symbol;      size_t symbol_len;
    const char *creator_fp;  size_t creator_fp_len;
    uint8_t     decimals;
    uint8_t     flags;
    uint64_t    supply;
    uint64_t    block_height;
} dna_v2_token_leaf_t;

/** Leaf hash per the header table. @return 0 / -1 (NULL, over-cap string). */
int dna_v2_token_leaf_hash(const dna_v2_token_leaf_t *leaf,
                           uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * token_root over leaves that MUST be strictly ascending by token_id
 * (byte-lexicographic). Equal or descending neighbors reject (duplicate /
 * non-canonical order — insertion order can never influence the root
 * because the only accepted order is the sorted one). n == 0 yields the
 * tagged empty-tokens root. @return 0 / -1.
 */
int dna_v2_token_root(const dna_v2_token_leaf_t *leaves, size_t n,
                      uint8_t out[DNA_V2_ROOT_LEN]);

/* ── validator_set_root (S3) ────────────────────────────────────────── */

/**
 * Merkle root over the per-epoch validator-set snapshot commitments.
 *
 * leaf  = SHA3-512("NDS.VSLEAF.v1" ‖ epoch(8 BE) ‖ snapshot_hash[64])
 * inner = SHA3-512("NDS.VSNODE.v1" ‖ left[64] ‖ right[64])
 *
 * Same Merkle rules as every other tree here: `epochs` must be STRICTLY
 * ASCENDING (equal or descending neighbours reject — that covers both a
 * duplicate epoch and a non-canonical order, so insertion order can never
 * influence the root); an unpaired odd node is PROMOTED unchanged, never
 * duplicated; n == 1 yields the single leaf; n == 0 yields the existing
 * tagged empty root DNA_V2_EMPTY_VSET.
 *
 * `snapshot_hashes[i]` is the dna_vset_hash of the snapshot governing
 * epoch `epochs[i]`. This function never decodes a snapshot — it commits
 * to the hash the persistence layer already verified.
 *
 * @return 0 / -1 (NULL args, bad order, allocation or digest failure).
 */
int dna_v2_vset_root(const uint64_t *epochs,
                     const uint8_t (*snapshot_hashes)[DNA_V2_ROOT_LEN],
                     size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/* ── attendance_root (tokenomics-v3 P1, D-4 / S-2) ─────────────────────
 *
 * Two layers, matching the vset leg's shape exactly:
 *   1. `dna_v2_attendance_digest` — ONE plain hash per epoch over every
 *      `v2_attendance` row (voter_id ASC), computed by the witness at
 *      the epoch boundary and stored in `v2_attendance_epoch.digest`.
 *   2. `dna_v2_attendance_root` — a Merkle root over EVERY committed
 *      `v2_attendance_epoch` row (epoch_start ASC), the leg this file
 *      composes into `system_state_root`.
 * Same Merkle rules as every other tree here: strictly ascending
 * epoch_start (duplicates reject); an unpaired odd node PROMOTED, never
 * duplicated; n == 1 yields the single leaf; n == 0 yields the tagged
 * empty root DNA_V2_EMPTY_ATTENDANCE.
 */

/** One `v2_attendance` row, canonical order = voter_id ASC. */
typedef struct {
    uint8_t  voter_id[32];
    uint64_t signed_count;
    uint64_t last_signed_height;
} dna_v2_attendance_row_t;

/**
 * The per-epoch digest: SHA3-512("NDS.ATTEP.v1" ‖ epoch_start(8 BE) ‖
 * n(4 BE) ‖ Σ_{rows ASC} (voter_id[32] ‖ signed_count(8 BE) ‖
 * last_signed_height(8 BE))). `rows` MUST be strictly ascending by
 * voter_id (duplicates reject) — n == 0 is legal (an epoch with no
 * attendance row yet) and hashes over zero rows, no special case.
 * @return 0 / -1 (NULL out, bad order, digest failure).
 */
int dna_v2_attendance_digest(uint64_t epoch_start,
                             const dna_v2_attendance_row_t *rows, size_t n,
                             uint8_t out[DNA_V2_ROOT_LEN]);

/** leaf = SHA3-512("NDS.ATLEAF.v1" ‖ epoch_start(8 BE) ‖ digest[64]). */
int dna_v2_attendance_leaf_hash(uint64_t epoch_start,
                                const uint8_t digest[DNA_V2_ROOT_LEN],
                                uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * attendance_root over `v2_attendance_epoch` rows, STRICTLY ASCENDING
 * epoch_start (duplicates reject); inner = SHA3-512("NDS.ATNODE.v1" ‖
 * left ‖ right); n == 0 -> DNA_V2_EMPTY_ATTENDANCE.
 * @return 0 / -1.
 */
int dna_v2_attendance_root(const uint64_t *epoch_starts,
                           const uint8_t (*digests)[DNA_V2_ROOT_LEN],
                           size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/* ── storage_root (storage reward v1) ──────────────────────────────────
 * Decision 2026-10-04-storage-reward-approved.md; exact bytes
 * docs/plans/2026-10-04-storage-reward-bytes.md items 1-6 (copied in the
 * "Composition preimages" block above). Archive reward (decision
 * 2026-10-05-archive-reward-bytes-approved.md; bytes doc
 * docs/plans/2026-10-05-archive-reward-bytes.md items 1-5): FOUR trees —
 * the registry (leaf v2), the frozen storage sets, the reports, the
 * published segment list — composed into ONE leg, storage_root
 * ("NDS.STOR.v2"), which is the 9th leg of system_state_root v5. Same
 * Merkle rules as every other tree here. Pure; no database. */

/** The storage set cap (design rev 2.2 F3: storage set max 256). */
#define DNA_V2_STORAGE_SET_MAX     256u
/** Longest report bitmap: ceil(DNA_V2_STORAGE_SET_MAX / 8). */
#define DNA_V2_STORAGE_BITMAP_MAX  32u

/** Registry row status byte (bytes doc item 1; 0 is invalid). */
#define DNA_V2_STORAGE_ACTIVE      ((uint8_t)1)
#define DNA_V2_STORAGE_EXITING     ((uint8_t)2)
#define DNA_V2_STORAGE_RELEASED    ((uint8_t)3)

/** The exit release UTXO's synthetic slot (bytes doc item 6). Kind 0x11
 *  and index 201 were repo-scanned 2026-10-04: the kinds in use are 0x01
 *  (UNDELEGATE release), 0x10 (graduation), 0x20/0x21 (retired), 0x22
 *  (payday), 0x23 (graduation delegation release); the indices are
 *  0..15 (wire outputs), 100, 200, 400 + i, [2^30, 2^31). */
#define DNA_V2_STORAGE_EXIT_KIND     ((uint8_t)0x11)
#define DNA_V2_STORAGE_EXIT_OUT_IDX  ((uint32_t)201)

/** One storage registry row; canonical order = node_fp ASC. */
typedef struct {
    uint8_t  node_fp[DNA_V2_ROOT_LEN];   /* SHA3-512(node_pk)           */
    uint8_t  payee_fp[DNA_V2_ROOT_LEN];
    uint64_t bond;
    uint8_t  status;                     /* DNA_V2_STORAGE_ACTIVE..     */
    uint64_t registered_height;
    uint64_t exit_height;
    uint32_t fail_streak;                /* archive bytes item 4        */
    uint64_t grace_until;                /* K9: no probe / no pay while
                                          * the epoch start < this     */
} dna_v2_storage_node_row_t;

/** leaf = SHA3-512("NDS.STLEAF.v2" ‖ node_fp[64] ‖ payee_fp[64] ‖
 *  bond(8 BE) ‖ status(1) ‖ registered_height(8 BE) ‖ exit_height(8 BE)
 *  ‖ fail_streak(4 BE) ‖ grace_until(8 BE)) — archive bytes item 4
 *  (replaces the v1 leaf; grace_until per K9, decision 2026-10-05-
 *  storage-reward-is-for-archive.md, any u64 encoded as given).
 *  @return 0 / -1 (NULL, status outside 1..3). */
int dna_v2_storage_node_leaf_hash(const dna_v2_storage_node_row_t *row,
                                  uint8_t out[DNA_V2_ROOT_LEN]);

/** registry_root over rows STRICTLY ascending by node_fp (equal or
 *  descending neighbours reject); inner "NDS.STRNODE.v1"; odd node
 *  promoted; n == 1 the leaf; n == 0 -> DNA_V2_EMPTY_STORAGE_REG.
 *  @return 0 / -1. */
int dna_v2_storage_registry_root(const dna_v2_storage_node_row_t *rows,
                                 size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/** S(H) = SHA3-512("NDS.STSET.v1" ‖ epoch_start(8 BE) ‖ count(4 BE) ‖
 *  node_fps[0..count−1]). node_fps STRICTLY ascending (duplicates
 *  reject); count 0 legal (node_fps may be NULL); count >
 *  DNA_V2_STORAGE_SET_MAX refused. @return 0 / -1. */
int dna_v2_storage_set_hash(uint64_t epoch_start,
                            const uint8_t (*node_fps)[DNA_V2_ROOT_LEN],
                            size_t count, uint8_t out[DNA_V2_ROOT_LEN]);

/** sets leaf = SHA3-512("NDS.STSLEAF.v1" ‖ epoch_start(8 BE) ‖
 *  set_hash[64]). @return 0 / -1. */
int dna_v2_storage_sets_leaf_hash(uint64_t epoch_start,
                                  const uint8_t set_hash[DNA_V2_ROOT_LEN],
                                  uint8_t out[DNA_V2_ROOT_LEN]);

/** sets_root over (epoch_start, S(H)) pairs, STRICTLY ascending
 *  epoch_start; inner "NDS.STSNODE.v1"; n == 0 ->
 *  DNA_V2_EMPTY_STORAGE_SETS. @return 0 / -1. */
int dna_v2_storage_sets_root(const uint64_t *epoch_starts,
                             const uint8_t (*set_hashes)[DNA_V2_ROOT_LEN],
                             size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/** One committed storage report; canonical order = (epoch_start, seat)
 *  ASC. bitmap[bitmap_len..] is not hashed. */
typedef struct {
    uint64_t epoch_start;
    uint32_t seat;
    uint8_t  set_hash[DNA_V2_ROOT_LEN];  /* S(H)                        */
    uint16_t bitmap_len;                 /* 0..DNA_V2_STORAGE_BITMAP_MAX */
    uint8_t  bitmap[DNA_V2_STORAGE_BITMAP_MAX];
} dna_v2_storage_report_t;

/** leaf = SHA3-512("NDS.STREP.v1" ‖ epoch_start(8 BE) ‖ seat(4 BE) ‖
 *  set_hash[64] ‖ bitmap_len(2 BE) ‖ bitmap[bitmap_len]). Takes the
 *  bytes as given: bitmap_len == ceil(count/8) and zero unused bits are
 *  the CALLER's checks. @return 0 / -1 (NULL, bitmap_len >
 *  DNA_V2_STORAGE_BITMAP_MAX). */
int dna_v2_storage_report_leaf_hash(const dna_v2_storage_report_t *rep,
                                    uint8_t out[DNA_V2_ROOT_LEN]);

/** reports_root over reports STRICTLY ascending by (epoch_start, seat)
 *  (an equal pair or a descending neighbour rejects); inner
 *  "NDS.STRPNODE.v1"; n == 0 -> DNA_V2_EMPTY_STORAGE_REPORTS.
 *  @return 0 / -1. */
int dna_v2_storage_reports_root(const dna_v2_storage_report_t *reps,
                                size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/** storage_root = SHA3-512("NDS.STOR.v2" ‖ registry_root ‖ sets_root ‖
 *  reports_root ‖ segments_root) — archive bytes item 5 (the 3-leg
 *  "NDS.STOR.v1" form is replaced). @return 0 / -1. */
int dna_v2_storage_root(const uint8_t registry_root[DNA_V2_ROOT_LEN],
                        const uint8_t sets_root[DNA_V2_ROOT_LEN],
                        const uint8_t reports_root[DNA_V2_ROOT_LEN],
                        const uint8_t segments_root[DNA_V2_ROOT_LEN],
                        uint8_t out[DNA_V2_ROOT_LEN]);

/* ── archive reward (storage reward v1 rev 4) ──────────────────────────
 * Decision 2026-10-05-archive-reward-bytes-approved.md; design
 * docs/plans/2026-10-05-archive-reward-design.md rev 4; bytes
 * docs/plans/2026-10-05-archive-reward-bytes.md items 1-3 and §6 (copied
 * in the "Composition preimages" block above). Pure; no database. */

/** Blocks per segment P = one payday period of 24 epochs (design rev 4:
 *  "each payday period (17,280 blocks) is one file"; decision 2026-10-05-
 *  storage-reward-is-for-archive.md item 2). A compile-time CONSTANT of
 *  the preimage (bytes item 1: count = 17280), not a chain parameter: at
 *  the shipped DNAC_EPOCH_LENGTH (720) it is exactly 17280 — asserted in
 *  ledger_roots_v2.c — so production bytes are unchanged. It follows the
 *  epoch length only so the Genesis Protocol short-epoch build
 *  (-DDNAC_EPOCH_LENGTH=15: P = 360) can publish a segment inside a
 *  harness run; the KATs are production-E only. */
#define DNA_V2_SEGMENT_BLOCKS        (24u * DNAC_EPOCH_LENGTH)
/** Holders per segment R (decision 2026-10-05-storage-reward-is-for-
 *  archive.md K4: R = 3). */
#define DNA_V2_STORAGE_HOLDERS       3u
/** fail_streak at which a member is skipped for placement (K2: 3). */
#define DNA_V2_STORAGE_FAIL_LIMIT    3u
/** Probe samples per target per epoch (K3: 3) — off-chain. */
#define DNA_V2_STORAGE_SAMPLES       3u
/** The probe nonce length (bytes §6). */
#define DNA_V2_STORAGE_NONCE_LEN     32u

/** Root(k) over EXACTLY DNA_V2_SEGMENT_BLOCKS 64-byte header hashes
 *  hashes[0] = hash[(k−1)·P + 1] … hashes[P−1] = hash[k·P] (bytes item
 *  1). Refuses k == 0 and a k whose last height k·P overflows u64.
 *  @return 0 / -1 (NULL, bad k, allocation). */
int dna_v2_segment_root(uint64_t k,
                        const uint8_t (*hashes)[DNA_V2_ROOT_LEN],
                        uint8_t out[DNA_V2_ROOT_LEN]);

/** segment leaf = SHA3-512("NDS.STSGLEAF.v1" ‖ k(8 BE) ‖ root[64]).
 *  @return 0 / -1. */
int dna_v2_segment_leaf_hash(uint64_t k,
                             const uint8_t root[DNA_V2_ROOT_LEN],
                             uint8_t out[DNA_V2_ROOT_LEN]);

/** segments_root over (k, Root(k)) pairs STRICTLY ascending k (an equal
 *  or descending neighbour rejects); inner "NDS.STSGNODE.v1"; odd node
 *  promoted; n == 1 the leaf; n == 0 -> DNA_V2_EMPTY_STORAGE_SEGS.
 *  @return 0 / -1. */
int dna_v2_segments_root(const uint64_t *ks,
                         const uint8_t (*roots)[DNA_V2_ROOT_LEN],
                         size_t n, uint8_t out[DNA_V2_ROOT_LEN]);

/** A(k) = SHA3-512("NDS.STASGN.v1" ‖ root[64]) (bytes item 3).
 *  @return 0 / -1. */
int dna_v2_segment_assign_key(const uint8_t root[DNA_V2_ROOT_LEN],
                              uint8_t out[DNA_V2_ROOT_LEN]);

/** holders(k) (bytes item 3): among the n members (node_fps[i] =
 *  SHA3-512(node_pk), fail_streaks[i] its frozen streak), the at most
 *  DNA_V2_STORAGE_HOLDERS with fail_streak < DNA_V2_STORAGE_FAIL_LIMIT
 *  whose A XOR node_fp is smallest as a 64-byte big-endian integer.
 *  out_idx[0..*n_out) receives their indices into node_fps in ASCENDING
 *  distance (rank 0 = closest); *n_out = min(3, eligible members), 0
 *  when none is eligible. The input order does not matter. Two equal
 *  node_fps anywhere in the list are refused (no tie rule exists — the
 *  registry key makes them impossible). n <= DNA_V2_STORAGE_SET_MAX.
 *  @return 0 / -1. */
int dna_v2_segment_holders(const uint8_t a_key[DNA_V2_ROOT_LEN],
                           const uint8_t (*node_fps)[DNA_V2_ROOT_LEN],
                           const uint32_t *fail_streaks, size_t n,
                           size_t out_idx[DNA_V2_STORAGE_HOLDERS],
                           size_t *n_out);

/** OFF-CHAIN probe sample (bytes §6): x_i = SHA3-512("NDS.STSAMP.v1" ‖
 *  nonce[32] ‖ target_fp[64] ‖ i(4 BE)). Never a consensus input — the
 *  ONE implementation the probe client and the KAT share.
 *  @return 0 / -1. */
int dna_v2_storage_sample_x(const uint8_t nonce[DNA_V2_STORAGE_NONCE_LEN],
                            const uint8_t target_fp[DNA_V2_ROOT_LEN],
                            uint32_t i, uint8_t out[DNA_V2_ROOT_LEN]);

/** OFF-CHAIN probe sample indices (bytes §6 + Clarifications): block
 *  index = BE u64 of x_i[0..8) mod B — a 0-based POSITION in the target's
 *  eligible blocks in ascending height (not a height); part index = BE
 *  u32 of x_i[8..12) mod parts_total, 0-based. B == 0 (no eligible block
 *  → no probe, bit 0) and parts_total == 0 (impossible: a block has >= 1
 *  part) are refused. Either out pointer may be NULL.
 *  @return 0 / -1. */
int dna_v2_storage_sample_index(const uint8_t x[DNA_V2_ROOT_LEN],
                                uint64_t eligible_blocks,
                                uint32_t parts_total,
                                uint64_t *block_index,
                                uint32_t *part_index);

/** exit_id = SHA3-512("NDS.STEXIT.v1" ‖ chain_id[32] ‖
 *  u32be(DNA_DOMAIN_CORE) ‖ release_height(8 BE) ‖ node_fp[64]).
 *  @return 0 / -1. */
int dna_v2_storage_exit_id(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                           uint64_t release_height,
                           const uint8_t node_fp[DNA_V2_ROOT_LEN],
                           uint8_t out[DNA_V2_ROOT_LEN]);

/** nullifier = SHA3-512(exit_id[64] ‖ DNA_V2_STORAGE_EXIT_KIND ‖
 *  u32be(DNA_V2_STORAGE_EXIT_OUT_IDX)). @return 0 / -1. */
int dna_v2_storage_exit_nullifier(const uint8_t exit_id[DNA_V2_ROOT_LEN],
                                  uint8_t out[DNA_V2_ROOT_LEN]);

/* ── DomainHead + domains_root ──────────────────────────────────────── */
typedef struct {
    uint32_t domain_id;
    uint8_t  domain_state_root[DNA_V2_ROOT_LEN];
    uint64_t domain_height;
    uint64_t last_updated_global_height;
    uint32_t ruleset_version;
    uint8_t  status;
} dna_v2_domain_head_t;

#define DNA_V2_DOMHEAD_ENC_LEN 89  /* id(4)+root(64)+h(8)+lu(8)+rv(4)+st(1) */

/** Canonical 89-byte field encoding (no tag; the tag joins in the hash). */
int dna_v2_domain_head_encode(const dna_v2_domain_head_t *head,
                              uint8_t out[DNA_V2_DOMHEAD_ENC_LEN]);

/** SHA3-512("NDS.DOMHEAD.v1" ‖ the 89 encoded bytes). */
int dna_v2_domain_head_hash(const dna_v2_domain_head_t *head,
                            uint8_t out[DNA_V2_ROOT_LEN]);

/**
 * domains_root over a GENERIC domain list (any count ≥ 1 — never
 * hard-coded to two): strictly ascending domain_id (duplicates reject),
 * heads[0].domain_id MUST be DNA_DOMAIN_SYSTEM (SYSTEM always present).
 * Leaves are the DomainHead hashes; tree per the header's Merkle rules
 * with the "NDS.DOMNODE.v1" inner tag. @return 0 / -1.
 */
int dna_v2_domains_root(const dna_v2_domain_head_t *heads, size_t n,
                        uint8_t out[DNA_V2_ROOT_LEN]);

/* ── Composition ────────────────────────────────────────────────────── */
/** 8 legs under "NDS.SYS.v4" (W-A: treasury_root appended LAST; was 7
 *  legs under "NDS.SYS.v3", root-layout round K2). */
int dna_v2_system_root(const uint8_t validator_root[64],
                       const uint8_t delegation_root[64],
                       const uint8_t chain_config_root[64],
                       const uint8_t validator_set_root[64],
                       const uint8_t domain_registry_root[64],
                       const uint8_t manifest_root[64],
                       const uint8_t attendance_root[64],
                       const uint8_t treasury_root[64],
                       uint8_t out[DNA_V2_ROOT_LEN]);

/** storage reward v1: 9 legs under "NDS.SYS.v5" — the 8 legs of
 *  dna_v2_system_root in the same order, storage_root APPENDED last.
 *  A NEW function: dna_v2_system_root ("NDS.SYS.v4") is unchanged and
 *  stays the composition before the storage activation height. */
int dna_v2_system_root_v5(const uint8_t validator_root[64],
                          const uint8_t delegation_root[64],
                          const uint8_t chain_config_root[64],
                          const uint8_t validator_set_root[64],
                          const uint8_t domain_registry_root[64],
                          const uint8_t manifest_root[64],
                          const uint8_t attendance_root[64],
                          const uint8_t treasury_root[64],
                          const uint8_t storage_root[64],
                          uint8_t out[DNA_V2_ROOT_LEN]);

/** tokenomics-v3 P2 (P2-8): gained the 7th leg `accrual_root` and a new
 *  composition tag "NDS.CORE.v2" (was "NDS.CORE.v1"). */
int dna_v2_core_root(const uint8_t utxo_root[64],
                     const uint8_t token_root[64],
                     const uint8_t pools_root[64],
                     const uint8_t claims_root[64],
                     const uint8_t name_root[64],
                     const uint8_t supply_root[64],
                     const uint8_t accrual_root[64],
                     uint8_t out[DNA_V2_ROOT_LEN]);

int dna_v2_global_root(const uint8_t domains_root[64],
                       uint8_t out[DNA_V2_ROOT_LEN]);

/* ── SYSTEM runtime-owned genesis payload root (Ledger V2 S5) ─────────
 *
 * Tag "NDS.SYSPAYL.v3" (16 bytes, zero-padded — S5 JUDGMENT tag; the
 * root-layout round K2 moved it from "NDS.SYSPAYL.v1" to "v2" because
 * the epoch_state leg left the preimage; W-A moved it to "v3" because
 * treasury_root joined it).
 *
 *   system_payload_root = SHA3-512("NDS.SYSPAYL.v3" ‖ validator_root
 *       ‖ delegation_root ‖ chain_config_root ‖ validator_set_root
 *       ‖ treasury_root)                                     — 5 legs
 *
 * This is dna_v2_system_root MINUS the THREE container-lifetime legs
 * (domain_registry_root, manifest_root, attendance_root) under a
 * DISTINCT tag. attendance_root is empty at genesis exactly like
 * domreg/manifest, so it is excluded for the same reason and the
 * genesis-cycle argument below is unchanged. treasury_root is SEEDED at
 * genesis from the document (W-A) and commits no manifest, so it is a
 * runtime payload leg — appended LAST, the same position it takes in
 * the full composition. It exists to break the
 * genesis cycle: a DomainManifest's `genesis_state_root` is defined as
 * the domain's RUNTIME-OWNED genesis payload root — it never covers a
 * structure that commits that domain's own manifest, so
 *   payload → manifest hash → registry root → FINAL system root
 * is a DAG, not a cycle. (The native supply_root is NOT a leg here:
 * issuance belongs to DNA_CORE, whose payload root IS its full
 * core_state_root — no self-reference exists for CORE, so the generic
 * rule holds trivially.) The FINAL SYSTEM DomainHead.state_root remains
 * the full 8-leg dna_v2_system_root. At domain ACTIVATION the payload
 * root is the value compared against the registry-committed
 * genesis_state_root (the runtime's optional payload_root hook —
 * nodus_witness_runtime.h; a runtime without the hook compares its
 * state_root directly). */
int dna_v2_system_payload_root(const uint8_t validator_root[64],
                               const uint8_t delegation_root[64],
                               const uint8_t chain_config_root[64],
                               const uint8_t validator_set_root[64],
                               const uint8_t treasury_root[64],
                               uint8_t out[DNA_V2_ROOT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_LEDGER_ROOTS_V2_H */
