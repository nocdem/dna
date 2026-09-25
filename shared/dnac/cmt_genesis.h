/**
 * @file shared/dnac/cmt_genesis.h
 * @brief cometbft @709fd12b `types/genesis.go` ported to C — the genesis
 *        document's validation and its validator hash.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R1-C of the cometbft → C consensus port. No consensus path calls
 * anything here yet; the module is additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── What is ported, and what is the host's ─────────────────────────────
 * The JSON and the file I/O are NOT here: `SaveAs` (:49-55),
 * `GenesisDocFromJSON` (:112-124) and `GenesisDocFromFile` (:127-137) are
 * host work. What those three WRAP — `ValidateAndComplete` (:69-106), the
 * function that decides whether a genesis document is usable and fills in
 * its defaults — is entirely here, together with `ValidatorHash` (:58-65).
 *
 * ── The clock ──────────────────────────────────────────────────────────
 * `ValidateAndComplete` contains ONE clock read: a zero GenesisTime is
 * replaced with `cmttime.Now()` (:101-103). Under the APPROVED clock
 * POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc) every clock read in
 * a ported body goes through one host callback, so this function takes a
 * `cmt_now_fn` (cmt_time.h:100). Nothing in this file links a clock.
 *
 * ⚠ AND THIS CHAIN NEVER TAKES THAT BRANCH. D-18 rev 2
 * (atlas-dec-4e84dbb5629353b78af6d04d704bd744, APPROVED) makes
 * `genesis_time` MANDATORY in our genesis config and says so in exactly
 * these terms: "the reference fills a zero genesis time with 'now'
 * (types/genesis.go:101-102) — not mirrored: derivation must be
 * deterministic, the operator supplies the value". The branch is ported
 * anyway, because the rule is the reference in everything and because a
 * function that silently lacked it would be a lie about what was ported.
 * The host simply never presents a zero time. If it does and no callback
 * was supplied, this returns CMT_FAULT — it does NOT invent a time.
 *
 * ⚠ ZERO MEANS 0001-01-01, NOT THE UNIX EPOCH. Go's `time.Time.IsZero()`
 * tests against year one, which in this port's representation is
 * CMT_TIME_ZERO = {CMT_TIME_MIN_SECONDS, 0} — see cmt_time.h:19-27. A
 * memset-zeroed `cmt_time_t` is 1970 and is NOT zero by this test, which
 * is the correct reading of the reference.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Every function is pure except for the one clock branch above, which is
 * the host's and which this chain does not take. No randomness, no map, no
 * allocation. `ValidatorHash` builds the set through
 * `cmt_validator_set_new`, so its leaf order is the set's own
 * ValidatorsByVotingPower order, not the document's listing order — the
 * same as the reference, and the reason two documents listing the same
 * validators in different orders hash alike.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   types/genesis.go 137 lines
 *     3f3bd9169368cbd0757a1d6cd88f279569dfa652ca059bb503072b17c16065f4
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc),
 * D-18 rev 2 (atlas-dec-4e84dbb5629353b78af6d04d704bd744),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_GENESIS_H
#define SHARED_DNAC_CMT_GENESIS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"
#include "cmt_time.h"
#include "cmt_pb.h"
#include "cmt_params.h"
#include "cmt_validator_set.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * cometbft@709fd12b types/genesis.go:20 — `MaxChainIDLen = 50`.
 *
 * NOTE: this port's chain id is 32 RAW BYTES (CMT_PB_CHAINID_MAX, the
 * derived V2 chain id), so `chain_id_len` can never exceed 32 and the
 * reference's check at :73-75 can never fire. It is implemented anyway —
 * the constant is the reference's and a later widening of the buffer must
 * meet it.
 */
#define CMT_GENESIS_MAX_CHAIN_ID_LEN 50

/** The longest validator `Name` this port stores, including the NUL. The
 *  reference's field is an unbounded Go string used only for display. */
#define CMT_GENESIS_NAME_MAX 64

/**
 * cometbft@709fd12b types/genesis.go:30-35 — `GenesisValidator`.
 *
 * `address_len` is 0 for the reference's EMPTY address, which
 * ValidateAndComplete FILLS IN from the key (:96-98) rather than
 * rejecting — that is the one field of a genesis document the reference
 * completes for you.
 */
typedef struct {
    uint8_t             address[CMT_PB_ADDRESS_MAX];   /* :31 */
    size_t              address_len;
    cmt_pb_public_key_t pub_key;                       /* :32 */
    int64_t             power;                         /* :33 */
    char                name[CMT_GENESIS_NAME_MAX];    /* :34 */
} cmt_genesis_validator_t;

/**
 * cometbft@709fd12b types/genesis.go:38-46 — `GenesisDoc`.
 *
 * `validators` is CALLER-OWNED storage. `AppState` (:45,
 * `json.RawMessage`) has no counterpart: it is opaque application bytes
 * that this module never reads, hashes or validates, and it belongs with
 * the JSON layer, which is the host's.
 */
typedef struct {
    cmt_time_t               genesis_time;         /* :39 */
    uint8_t                  chain_id[CMT_PB_CHAINID_MAX];  /* :40 */
    size_t                   chain_id_len;
    int64_t                  initial_height;       /* :41 */
    bool                     has_consensus_params; /* :42, POINTER */
    cmt_consensus_params_t   consensus_params;
    cmt_genesis_validator_t *validators;           /* :43, caller-owned */
    size_t                   validators_cap;
    size_t                   validators_len;
    uint8_t                  app_hash[CMT_PB_HASH_MAX];     /* :44 */
    size_t                   app_hash_len;
} cmt_genesis_doc_t;

/* `cmt_time_is_zero` — the predicate `genesis.go:101` applies — was
 * DECLARED here through wave R1-C. Wave R1-D moved it to its subject's own
 * module, cmt_time.h, which this header includes above; it is a property of
 * a time, not of a genesis document, and cmt_block.c had been keeping a
 * private second copy of it. Nothing about its behaviour changed, and this
 * header still resolves the name for its callers. */

/**
 * cometbft@709fd12b types/genesis.go:58-65 — `ValidatorHash()`.
 *
 * Builds a `Validator` per genesis entry with `NewValidator(v.PubKey,
 * v.Power)` (:61) — so the ADDRESS IS DERIVED FROM THE KEY here, and the
 * document's own `Address` field is not used — puts them through
 * `NewValidatorSet` (:63) and returns that set's `Hash()` (:64).
 *
 * ⚠ Consequence worth stating: because it goes through NewValidatorSet,
 * this hash is over the set in ValidatorsByVotingPower order and after one
 * `IncrementProposerPriority(1)`. The priorities do not enter the leaves
 * (validator.go:115-117), so the hash is stable; the ORDER does, and it is
 * the set's order rather than the document's.
 *
 * ZERO CONSUMERS in the reference's consensus path — the port map lists
 * `genesis.go:58` among the zero-consumer PORT rows. Ported because the
 * rule is the reference in everything.
 *
 * @param vals_storage storage for `validators_len` validators.
 * @param scratch the change-set working storage NewValidatorSet needs.
 * @param hash_scratch/items the leaf buffer and descriptors
 *        `cmt_validator_set_hash` needs.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_genesis_doc_validator_hash(const cmt_genesis_doc_t *gen_doc,
                                   cmt_validator_t *vals_storage,
                                   size_t vals_cap,
                                   cmt_valset_scratch_t *scratch,
                                   uint8_t *hash_scratch,
                                   size_t hash_scratch_cap,
                                   cmt_merkle_item_t *items, size_t items_cap,
                                   uint8_t out[CMT_TMHASH_SIZE]);

/**
 * cometbft@709fd12b types/genesis.go:69-106 — `ValidateAndComplete()`.
 * MUTATES the document: it fills in the defaults the reference fills in.
 *
 * In the reference's own order: a non-empty chain id (:70-72); a chain id
 * at most MaxChainIDLen (:73-75); a non-negative initial height (:76-78),
 * with 0 COMPLETED to 1 (:79-81); consensus params defaulted when absent
 * and otherwise ValidateBasic'd (:83-87); then per validator, a non-zero
 * power (:90-92), an address that matches the key when one is given
 * (:93-95) and an address FILLED IN from the key when none is (:96-98);
 * and finally a zero genesis time COMPLETED from the clock (:101-103).
 *
 * NOTE which check is absent, because it is easy to assume otherwise: the
 * reference does NOT reject a NEGATIVE power here — only a zero one. A
 * negative power is caught later, by `Validator.ValidateBasic`
 * (validator.go:45-47) on the way through `ValidatorHash` /
 * `NewValidatorSet`. Not adding the check is the port being faithful.
 *
 * @param now may be NULL. It is consulted ONLY when `genesis_time` is Go's
 *        zero time; a zero time with no callback is CMT_FAULT — this
 *        function never invents a time. See the file header for why this
 *        chain never reaches that branch (D-18 rev 2).
 * @param now_ctx passed through to `now`.
 * @return CMT_OK, CMT_REJECT, CMT_FAULT.
 */
int cmt_genesis_doc_validate_and_complete(cmt_genesis_doc_t *gen_doc,
                                          cmt_now_fn now, void *now_ctx);

/* ── taşınmadı (not ported), with the reason ────────────────────────────
 *  · :49-55  `SaveAs`             — HOST: JSON marshalling plus a file
 *                                   write (cmtjson, cmtos.WriteFile).
 *  · :112-124 `GenesisDocFromJSON` — HOST for the JSON half; the half
 *                                   that matters, its call to
 *                                   ValidateAndComplete at :119, is above.
 *  · :127-137 `GenesisDocFromFile` — HOST: os.ReadFile plus the above.
 *  · :45 `AppState json.RawMessage` — opaque application bytes; nothing
 *        in this module reads or hashes them, and they travel with the
 *        JSON layer.
 */

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_GENESIS_H */
