/* Hard-Fork v1 — CHAIN_CONFIG TX verify-rule tests (design §6.3).
 *
 * Local rules covered (client-side, no DB):
 *   - signer_count == 1
 *   - param_id in {1..DNAC_CFG_PARAM_MAX_ID}
 *   - param_id read by the running consensus (0.20.3,
 *     dnac_cfg_param_read_by_consensus: 4, 5 and — final pre-testnet
 *     wipe W-C — 6)
 *   - new_value in per-param range
 *   - signed_at_block > 0
 *   - valid_before_block > effective_block_height
 *   - valid_before_block > signed_at_block
 *   - committee_sig_count in [5, 7]
 *   - committee_votes[].witness_id pairwise distinct
 *
 * Witness-side rules (committee membership, sig verify against pubkeys,
 * epoch grace, freshness, monotonicity, exclusive block) are Stage B and
 * NOT exercised here.
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

#define CHECK_OK(expr) do { \
    int _rc = (expr); \
    if (_rc != DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_OK fail at %s:%d: %s -> %d (expected DNAC_SUCCESS)\n", \
            __FILE__, __LINE__, #expr, _rc); exit(1); } } while(0)

#define CHECK_ERR(expr) do { \
    int _rc = (expr); \
    if (_rc == DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_ERR fail at %s:%d: %s returned DNAC_SUCCESS (expected error)\n", \
            __FILE__, __LINE__, #expr); exit(1); } } while(0)

static void build_valid_chain_config(dnac_transaction_t *tx,
                                      uint8_t param_id,
                                      uint64_t new_value) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_CHAIN_CONFIG;
    tx->timestamp = 1745000000ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;
    cc->param_id               = param_id;
    cc->new_value              = new_value;
    cc->effective_block_height = 5000ULL;
    cc->proposal_nonce         = 0x5EADBEEFCAFEBABEULL;  /* <= INT64_MAX */
    cc->signed_at_block        = 4800ULL;
    cc->valid_before_block     = 5100ULL;
    cc->committee_sig_count    = 5;
    for (int i = 0; i < 5; i++) {
        /* Distinct witness_ids per slot. */
        memset(cc->committee_votes[i].witness_id, 0x10 + i, 32);
        memset(cc->committee_votes[i].signature, 0x80 + i, DNAC_SIGNATURE_SIZE);
    }
}

int main(void) {
    dnac_transaction_t tx;

    /* R3 W4-C delta 3 (whitelist extension over delta 2's operator
     * "kaldır" ruling; atlas-dec-5b7568512b95e6d2e671c4eaad2c1879 rev 1):
     * MAX_TXS_PER_BLOCK (id 1) is RETIRED — verify_chain_config_rules'
     * switch refuses it unconditionally, before signed_at/valid_before/
     * committee_sig_count/duplicate-witness are ever reached (verify.c).
     * 0.20.3: BLOCK_INTERVAL_SEC (id 2), the vehicle that replaced id 1,
     * is itself refused now — the running consensus does not read it
     * (dnac_cfg_param_read_by_consensus). Every "any valid param" vehicle
     * below that is NOT specifically testing param_id itself moves to
     * TARGET_ACTIVE_COUNT (id 4, a parameter the consensus reads; value
     * 9 inside [DNAC_CFG_MIN_TARGET_ACTIVE, DNAC_CFG_MAX_TARGET_ACTIVE])
     * so it keeps isolating what it claims to isolate. */
#define VEH_PARAM  ((uint8_t)DNAC_CFG_TARGET_ACTIVE_COUNT)
#define VEH_VALUE  9ULL

    /* 1. Baseline: valid TARGET_ACTIVE_COUNT proposal, 5 sigs. */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));

    /* 2. Wrong tx_type → INVALID_TX_TYPE. */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_chain_config_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* 3. NULL tx → INVALID_PARAM. */
    CHECK(dnac_tx_verify_chain_config_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    /* 4. signer_count != 1. */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 5. param_id bounds — 0 and >MAX_ID rejected; ids 1
     * (MAX_TXS_PER_BLOCK) and 3 (INFLATION_START_BLOCK) are IN
     * [1, MAX_ID] but RETIRED (cases 6 and 8 below, not here), id 2 is
     * not read by the running consensus (case 7); the governable id this
     * case checks accepts a valid value. */
    build_valid_chain_config(&tx, 0, 5);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_PARAM_MAX_ID + 1, 0);   /* 14 (HF-4) */
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    CHECK(DNAC_CFG_PARAM_MAX_ID + 1 == 14);
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));

    /* 5a. HF3_ACTIVE (id 8, HF-3): EXACTLY 1 — the mirror of the
     * witness-side scalar_rules (nodus_witness_chain_config.c). 0 (an
     * "off" vote) and 2 refuse. */
    build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_HF3_ACTIVE,
                             DNAC_CFG_HF3_ACTIVE_ON);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_HF3_ACTIVE, 0);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_HF3_ACTIVE, 2);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 5a'. RULESET_GEN2 (id 9, HF-4): EXACTLY the dnac.h literal D2 — the
     * mirror of the witness-side scalar_rules. D2 ± 1, 0 (when D2 is not
     * 0), 1 and UINT64_MAX refuse. The witness's stateful rules (single
     * use, HF-2, epoch boundary) are NOT mirrored — no chain state here
     * (design 2026-10-02-onchain-names-design.md rev 4 §1.2). MUTANT
     * KILLED: dropping the case (default refuses D2), comparing against
     * anything but the literal. NOTE: while DNAC_CFG_RULESET_GEN2_D2 is
     * the unfilled oracle placeholder 0, the "0 refuses" probe is skipped
     * by its own guard and D2 - 1 wraps to UINT64_MAX (still refused). */
    build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_RULESET_GEN2,
                             DNAC_CFG_RULESET_GEN2_D2);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_RULESET_GEN2,
                             DNAC_CFG_RULESET_GEN2_D2 + 1u);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_RULESET_GEN2,
                             DNAC_CFG_RULESET_GEN2_D2 - 1u);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_RULESET_GEN2, UINT64_MAX);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    if (DNAC_CFG_RULESET_GEN2_D2 != 0u) {
        build_valid_chain_config(&tx, (uint8_t)DNAC_CFG_RULESET_GEN2, 0);
        CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    }
    CHECK(DNAC_CFG_RULESET_GEN2_D2 <= (uint64_t)INT64_MAX);
    CHECK(DNAC_RULESET_SWITCH_SPEC_VERSION == 1u);

    /* 5a''. NAME_PRICE_3P..6P (ids 10-13, HF-4): [10^8, 10^15] — both
     * ends inclusive, one past either end refuses; and the compiled
     * no-row defaults are 10^11 / 5*10^10 / 10^10 / 10^8 (decision
     * 2026-10-02-onchain-names.md items 6 and 10). The "generation 2
     * judges" rule is witness-side only. MUTANT KILLED: an off-by-one
     * bound, a missing id, a default drift. */
    {
        const uint8_t ids[4] = { (uint8_t)DNAC_CFG_NAME_PRICE_3P,
                                 (uint8_t)DNAC_CFG_NAME_PRICE_4P,
                                 (uint8_t)DNAC_CFG_NAME_PRICE_5P,
                                 (uint8_t)DNAC_CFG_NAME_PRICE_6P };
        for (int k = 0; k < 4; k++) {
            CHECK(ids[k] == 10 + k);
            build_valid_chain_config(&tx, ids[k], DNAC_CFG_MIN_NAME_PRICE);
            CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
            build_valid_chain_config(&tx, ids[k], DNAC_CFG_MAX_NAME_PRICE);
            CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
            build_valid_chain_config(&tx, ids[k], DNAC_CFG_MIN_NAME_PRICE - 1u);
            CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
            build_valid_chain_config(&tx, ids[k], DNAC_CFG_MAX_NAME_PRICE + 1u);
            CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
            build_valid_chain_config(&tx, ids[k], 0);
            CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
        }
        CHECK(DNAC_CFG_MIN_NAME_PRICE == 100000000ULL);
        CHECK(DNAC_CFG_MAX_NAME_PRICE == 1000000000000000ULL);
        CHECK(DNAC_NAME_PRICE_3P_DEFAULT == 100000000000ULL);
        CHECK(DNAC_NAME_PRICE_4P_DEFAULT == 50000000000ULL);
        CHECK(DNAC_NAME_PRICE_5P_DEFAULT == 10000000000ULL);
        CHECK(DNAC_NAME_PRICE_6P_DEFAULT == 100000000ULL);
    }

    /* 5b. The read list itself: exactly {4, 5, 6, 7, 8, 9..13} of the governed
     * id space are read by the running consensus (id 8 = HF3_ACTIVE, read
     * by the engine's env_hf3_active — HF-3, 2026-10-02; id 7 =
     * HF2_ACTIVE, read by the engine's env_hf2_active, 2026-09-30).
     * Before HF-2: exactly {4, 5, 6} of the governed id
     * space are read by the running consensus. Id 6
     * (TOKEN_CREATE_FEE_RAW) joined with its consensus reader in the
     * final pre-testnet wipe W-C: the engine reads the committed row into
     * the exec context and the CORE TOKEN_CREATE exec enforces it
     * (nodus_witness_v2_apply.c env_token_create_fee,
     * nodus_witness_rt_native.c rtn_tc_exec). MUTANT KILLED: adding an id
     * to dnac_cfg_param_read_by_consensus without a reader, or dropping
     * 4/5/6 (the witness-side scalar_rules consumes the same
     * predicate). */
    for (unsigned id = 0; id <= 255u; id++) {
        const bool want = (id == DNAC_CFG_TARGET_ACTIVE_COUNT ||
                           id == DNAC_CFG_GAS_PRICE_RAW_PER_UNIT ||
                           id == DNAC_CFG_TOKEN_CREATE_FEE_RAW ||
                           id == DNAC_CFG_HF2_ACTIVE ||
                           id == DNAC_CFG_HF3_ACTIVE ||
                           /* HF-4: 9 read by phase 6b' and
                            * env_ruleset_gen2_voted; 10-13 by the
                            * generation-2 name price (gated by the
                            * witness's generation rule until then) */
                           id == DNAC_CFG_RULESET_GEN2 ||
                           id == DNAC_CFG_NAME_PRICE_3P ||
                           id == DNAC_CFG_NAME_PRICE_4P ||
                           id == DNAC_CFG_NAME_PRICE_5P ||
                           id == DNAC_CFG_NAME_PRICE_6P);
        CHECK(dnac_cfg_param_read_by_consensus((uint8_t)id) == want);
    }

    /* 6. MAX_TXS_PER_BLOCK (id 1) is RETIRED: every value refuses, even
     * the shapes that used to be the valid [1,10] range — the hard cap
     * itself (DNAC_CFG_MAX_TXS_HARD_CAP) is gone, so 1 and 10 below are
     * now arbitrary in-range-shaped literals, not a bound being probed. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 0);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 10);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 11);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 7. BLOCK_INTERVAL_SEC (id 2) is NOT READ by the running consensus
     * (0.20.3; decision file 2026-09-23-height-activated-upgrades-before-
     * testnet.md item 1): refused for EVERY value — including the whole
     * [1, 15] range this case used to ACCEPT (1, 5, 15), so a restored
     * range check or a restored read-list entry fails here. RED on the
     * pre-0.20.3 tree: 1, 5 and 15 passed. */
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 5);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 15);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 0);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 7b. TARGET_ACTIVE_COUNT (id 4) range [DNAC_CFG_MIN_TARGET_ACTIVE,
     * DNAC_CFG_MAX_TARGET_ACTIVE] = [7, 128] on the client mirror (the
     * version-3 lane narrows the ceiling to 32 witness-side,
     * NODUS_V2_ACTIVE_SET_MAX — not a client rule). Both edges and one
     * past each. */
    build_valid_chain_config(&tx, DNAC_CFG_TARGET_ACTIVE_COUNT,
                             DNAC_CFG_MIN_TARGET_ACTIVE - 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_TARGET_ACTIVE_COUNT,
                             DNAC_CFG_MIN_TARGET_ACTIVE);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_TARGET_ACTIVE_COUNT,
                             DNAC_CFG_MAX_TARGET_ACTIVE);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_TARGET_ACTIVE_COUNT,
                             DNAC_CFG_MAX_TARGET_ACTIVE + 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 8. INFLATION_START_BLOCK (id 3) is RETIRED (tokenomics-v3 P2, P2-4;
     * decision file 2026-09-22-nodus-tokenomics-v3-operator.md §3 S-4):
     * dnac_tx_verify_chain_config_rules refuses it for EVERY value
     * (verify.c, the id-3 case), mirroring the witness-side
     * nodus_chain_config_scalar_rules. The values below are the shapes
     * the retired [0, 2^48] range used to ACCEPT — 0, an ordinary
     * height, and the former upper bound itself — so a restored range
     * check fails here. The bound macro (DNAC_CFG_MAX_INFLATION_START_
     * BLOCK) is deleted, hence the literal 2^48. */
    build_valid_chain_config(&tx, DNAC_CFG_INFLATION_START_BLOCK, 0);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_INFLATION_START_BLOCK, 12345);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_INFLATION_START_BLOCK,
                             281474976710656ULL);           /* 2^48 */
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 8b. GAS_PRICE_RAW_PER_UNIT (id 5, HF-1 — decision
     * 2026-09-25-gas-price.md, "HF-1 O4"): [0, DNAC_CFG_MAX_GAS_PRICE].
     * 0 is LEGAL (it switches the price rule off again); MAX + 1 is the
     * first refused value. Mirrors the witness-side scalar_rules. RED on
     * the pre-HF-1 tree: id 5 was > DNAC_CFG_PARAM_MAX_ID (4), so the
     * three accepting lines below failed. */
    build_valid_chain_config(&tx, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, 0);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, 121);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
                             DNAC_CFG_MAX_GAS_PRICE);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
                             DNAC_CFG_MAX_GAS_PRICE + 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 8c. TOKEN_CREATE_FEE_RAW (id 6, final pre-testnet wipe W-C —
     * decision 2026-09-28-token-create-fee-governance.md):
     * [DNAC_CFG_MIN_TOKEN_CREATE_FEE, DNAC_CFG_MAX_TOKEN_CREATE_FEE] =
     * [10^8, 10^15]. Mirrors the witness-side scalar_rules. RED on the
     * pre-W-C tree: id 6 was > DNAC_CFG_PARAM_MAX_ID (5), so the three
     * accepting lines failed. */
    build_valid_chain_config(&tx, DNAC_CFG_TOKEN_CREATE_FEE_RAW,
                             DNAC_CFG_MIN_TOKEN_CREATE_FEE - 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_TOKEN_CREATE_FEE_RAW,
                             DNAC_CFG_MIN_TOKEN_CREATE_FEE);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_TOKEN_CREATE_FEE_RAW,
                             100000000000ULL);          /* genesis 10^11 */
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_TOKEN_CREATE_FEE_RAW,
                             DNAC_CFG_MAX_TOKEN_CREATE_FEE);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_TOKEN_CREATE_FEE_RAW,
                             DNAC_CFG_MAX_TOKEN_CREATE_FEE + 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 9. signed_at_block == 0 rejected (CC-AUDIT-008). */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.chain_config_fields.signed_at_block = 0;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 10. valid_before <= effective rejected. */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.chain_config_fields.valid_before_block = tx.chain_config_fields.effective_block_height;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.chain_config_fields.valid_before_block =
        tx.chain_config_fields.effective_block_height - 1;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 11. valid_before <= signed_at rejected. */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.chain_config_fields.signed_at_block = tx.chain_config_fields.valid_before_block + 1;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 12. committee_sig_count boundaries. */
    for (uint8_t n = 0; n < DNAC_CHAIN_CONFIG_MIN_SIGS; n++) {
        build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
        tx.chain_config_fields.committee_sig_count = n;
        CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    }
    /* Accepted: 5, 6, 7. */
    for (uint8_t n = DNAC_CHAIN_CONFIG_MIN_SIGS; n <= DNAC_CHAIN_CONFIG_MAX_SIGS; n++) {
        build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
        tx.chain_config_fields.committee_sig_count = n;
        /* Extend distinct witness_ids up to n. */
        for (uint8_t i = 0; i < n; i++) {
            memset(tx.chain_config_fields.committee_votes[i].witness_id, 0x10 + i, 32);
        }
        CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    }
    /* n > 7 rejected. */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    tx.chain_config_fields.committee_sig_count = DNAC_CHAIN_CONFIG_MAX_SIGS + 1;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 13. Duplicate witness_ids rejected. */
    build_valid_chain_config(&tx, VEH_PARAM, VEH_VALUE);
    /* Make votes[0] and votes[3] collide. */
    memcpy(tx.chain_config_fields.committee_votes[3].witness_id,
           tx.chain_config_fields.committee_votes[0].witness_id, 32);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    printf("test_chain_config_verify: ALL CHECKS PASSED\n");
    return 0;
}
