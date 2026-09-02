/**
 * @file nodus/tools/nodus_v2_gen_config.h
 * @brief O16A / D2 — the operator-facing TEXT form of a pure-V2 genesis
 *        config, and the parser that turns it into the struct the
 *        builder consumes.
 *
 * The struct this produces (`nodus_v2_gen_config_t`,
 * nodus_witness_v2_gen.h:251-280) has existed and been tested since
 * O15J Faz 1, but nothing outside the test suite could construct one:
 * there was no way for an operator to EXPRESS a genesis config. This
 * module is that expression, and nothing more. It decides no value, it
 * validates no genesis rule, and it applies no default to any field
 * that reaches `source_commit`.
 *
 * ── WHY A HAND-WRITTEN TEXT FORMAT AND NOT JSON ─────────────────────
 * The server's JSON loader is compiled only when json-c was found
 * (`NODUS_HAS_JSONC`, nodus/tools/nodus-server.c:101,
 * nodus/CMakeLists.txt:1797-1800). json-c is an OPTIONAL dependency.
 * A genesis ceremony that is performed exactly once, on seven hosts,
 * must not depend on which optional library each host's build happened
 * to find, so the format is parsed by this file and by nothing else.
 *
 * ── DETERMINISM (design invariant D-I5) ─────────────────────────────
 * The parser is a PURE FUNCTION OF THE FILE'S BYTES: the same file
 * produces the same struct on every machine, every locale and every
 * build. That is not a nicety here — `source_commit` is
 * SHA3-512(canonical encoding of this struct), it feeds the genesis
 * BlockID and therefore the chain id (nodus_witness_v2_gen.h:66-70), so
 * two operators whose parsers disagreed by one byte would derive two
 * chains and could never join each other. Every rule in the
 * implementation that exists to hold that property says so at its site.
 *
 * The consequences an operator sees, all of them deliberate:
 *   - Every malformed input is a REFUSAL naming the line number. There
 *     is no clamping, no truncation, no "best effort" value.
 *   - A duplicate key refuses. Not last-wins, not first-wins: two
 *     plausible precedence rules are two chains.
 *   - An unknown key refuses. A typo'd key must not derive a chain with
 *     a structural default sitting in the slot the operator meant to
 *     fill.
 *   - A missing key refuses. Absent is never zero.
 *
 * ── THE THREE FIELDS THE FILE MAY NOT NAME ──────────────────────────
 * `config_version`, `claim_start_height` and `claim_end_height` are set
 * by this parser and are NOT settable from the file; naming any of them
 * is an unknown key. This is NOT a hidden default. Each has exactly one
 * legal value and `gen_plan_build` refuses every other one — the
 * version at nodus_witness_v2_gen.c:467-472 and the claim window at
 * :544-553 — so there is no alternative value a silent default could be
 * masking. A settable field with a one-element domain would only give
 * the operator a way to fail later, in the builder, instead of never.
 *
 * ── THE FORMAT ──────────────────────────────────────────────────────
 * Line-oriented ASCII. `#` begins a comment that runs to end of line.
 * Blank lines are ignored. `key = value`, with optional ' ' / '\t'
 * around the `=`. `[validator]` and `[allocation]` open a repeated
 * block; every key of the open block must appear exactly once before
 * the next block header or EOF. The five top-level keys must appear
 * before the first block header (after a header the open scope is the
 * block, and a top-level key is then simply not one of that block's
 * keys — i.e. an unknown key).
 *
 * A complete, minimal example — one validator block shown; a derivable
 * config needs exactly DNAC_COMMITTEE_SIZE of them (Rule P.1,
 * nodus_witness_v2_gen.c:559-564), and at least one allocation:
 *
 *     # DNA Chain — Ledger V2 genesis config
 *     total_supply_raw      = 100000000000000000
 *     epoch_length          = 720
 *     blocks_per_year       = 6307200
 *     decimal_unit          = 100000000
 *     inflation_start_block = 0          # 0 = emission never runs
 *
 *     [validator]
 *     pubkey                     = <5184 lowercase hex chars>
 *     unstake_destination_pubkey = <5184 lowercase hex chars>
 *     unstake_destination_fp     = <128 lowercase hex chars>
 *     self_stake                 = 1000000000000000
 *     commission_bps             = 500
 *
 *     [allocation]
 *     source_id    = <128 lowercase hex chars>
 *     dest_binding = <128 lowercase hex chars>
 *     amount       = 5000000000000
 *
 * `unstake_destination_fp` MUST be SHA3-512(unstake_destination_pubkey)
 * rendered as lowercase hex. The parser only checks its SHAPE; the
 * DERIVATION is checked by the builder (gen_plan_build), because that
 * is the one place every producer of a config passes through.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_V2_GEN_CONFIG_H
#define NODUS_V2_GEN_CONFIG_H

#include "witness/nodus_witness_v2_gen.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parse `path` into a heap-allocated config.
 *
 * The config struct is ~160 KB and its allocation array is variable
 * length; BOTH are allocated here and BOTH are owned by the returned
 * pointer (the struct's `allocs` field is declared const because the
 * BUILDER never writes through it, nodus_witness_v2_gen.h:279 — it is
 * not a statement about ownership). Release with
 * nodus_v2_gen_config_free and nothing else.
 *
 * On failure `*out_cfg` is left NULL, everything allocated so far is
 * released, and the reason — with the line number it was found on — has
 * been written to stderr. The file is typed by hand, once, by a human
 * under ceremony conditions: a refusal that does not name the line is a
 * refusal that costs an hour.
 *
 * This function performs NO genesis validation. A successfully parsed
 * config is a WELL-FORMED one, not a derivable one; the genesis rules
 * belong to nodus_witness_v2_gen_config_validate and to
 * nodus_witness_v2_gen_derive, which are the single authority on them.
 *
 * @param path     the config file.
 * @param out_cfg  receives the parsed config on success.
 * @return 0 parsed; -1 refused (the reason is on stderr).
 */
int nodus_v2_gen_config_parse_file(const char *path,
                                   nodus_v2_gen_config_t **out_cfg);

/** Release a config produced by nodus_v2_gen_config_parse_file.
 *  NULL is a no-op. */
void nodus_v2_gen_config_free(nodus_v2_gen_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_GEN_CONFIG_H */
