/**
 * Nodus — Nodus EVM: the EVM domain through the cometbft lane, on the REAL
 * activation path (the activation package; package 1 drove the runtime
 * through a scripted test table — that table could not carry the
 * pairing rule, the CORE reserve or the vote, so this file was rewritten
 * onto the production tables).
 *
 * Design: docs/plans/2026-10-04-nodus-evm-chain-integration-design.md rev 3
 * §2 (pairing), §4 (failure boundary), §5 (reserve, movement table,
 * invariants), §8 (fee↔gas, block gas sum, mempool), §9 (activation).
 * Decisions: 2026-10-04-nodus-evm-kurultay-k1.md (operator 1: CORE-funded
 * ceiling fee to the reward pool; 3: q = 10^10; 4: explicit recipient +
 * tickets), 2026-10-04-nodus-evm-kurultay-k2-summary.md (one pending per
 * sender; the EVM gas sum is the one block limit).
 *
 * THE FIXTURE: a seeded version-3 chain, PRODUCTION runtime tables, HF-2
 * and HF-3 on from height 1, a gas price of 1 raw per unit from height 1
 * (red-team 1 D1 stops the EVM at price 0; FEE = 10^9 pays every ceiling
 * built here — only the D1 case votes the price back to 0), the
 * generation-2 vote (D2) effective H2 = 3
 * and — where the case says so — the EVM_ACTIVE vote (D) effective
 * HE = 5, all committed BEFORE the engine genesis (the test_hf4_switch
 * shape); three real ML-DSA-87 keys; per key FEE-exact coins and a few
 * FEE + 1000 coins. Every EVM envelope is EXACTLY [CORE EVMFUND] + [EVM
 * op], both legs REALLY signed by one key (nodus_v2_env_sign_one_key).
 * Idle blocks 1..4 bring the chain to the EVM generation: block 2 is the
 * generation-2 edge, block 4 the EVM edge (6b'').
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  1. shape: selfcheck (incl. the EVM generation's pins and the D
 *     literal), the EVM generation's three entries, the ABI-2 hooks
 *     check, the pairing rule, the call-head decoder, the block-gas share
 *     and the conflict keys over hand-made views.
 *  2. the EDGE: before it an EVM leg is a CONTEXT refusal; at block 4 the
 *     registry gains the EVM record ACTIVE with exactly the manifest the
 *     D literal hashed, SYSTEM v8 / CORE v6, the EVM head (domain height
 *     0, root = the empty EVM root), the empty META and the reserve 0;
 *     CORE's root moves to the reserved supply leaf (its DomainUpdate pre
 *     != post) and equals nodus_witness_core_root_v2_evm, not the old
 *     formula; committed == recomputed; block 5 does not switch again. A
 *     NO-VOTE TWIN: at heights 1..3 the CORE roots, the CORE registry
 *     record and the head versions are byte-identical, and the SYSTEM
 *     manifests are equal in every field but genesis_state_root. SYSTEM's
 *     root, its genesis_state_root and hence the registry root differ
 *     ONLY by construction (the fixture writes the vote row — a
 *     chain_config leg — before genesis), so they are not compared
 *     equal. FAULTs: the edge
 *     with the registry not at the base generation; the edge below S17.
 *  3. vote rules: the stateful matrix of param 14 (each prerequisite
 *     alone refuses; red-team 1 F5: the first BLOCKHASH window on the
 *     chain — initial 1: 256 refused / 257 legal, initial 100: 355 / 356,
 *     an underived 0 and an overflowing initial refuse), param 15 none;
 *     the 5-argument form refuses 14; the
 *     scalar rules (exact D, the param-15 range) and SAFETY grace.
 *  4. execution (package 1's cases, now paired and fee-paying): deploy,
 *     CALL with Data on the EVM item and none on a CORE SPEND item in the
 *     same block, REVERT / OOG / over-ceiling / read-budget exhaustion
 *     APPLIED (nonce + 1, fee paid to the reward pool, the FEE coin
 *     consumed), the units inequality, and the pre-execution refusals
 *     (wrong nonce, trailing byte, gas above the cap, unpayable failure)
 *     — refused items leave the ledger and their coin untouched.
 *  5. bridge: DEPOSIT (coin → change + reserve + EVM balance), WITHDRAW
 *     (reserve → a CORE UTXO to the explicit recipient), a contract
 *     ticket, REDEEM (by a THIRD key — anyone may redeem) paying the
 *     ticket's recipient, the double redeem refused; both invariants
 *     (the supply gate runs the CORE and the EVM ones) after every block;
 *     the reserve equals Σ deposits − Σ releases.
 *  6. pairing refusals: an orphan EVM leg, an orphan EVMFUND leg, a
 *     DEPOSIT under role FEE, a CALL under role RELEASE — each refused on
 *     an EVM-active chain, nothing moved.
 *  7. the block gas sum: the seam ProcessProposal runs (and
 *     PrepareProposal's drop loop) refuses a batch over EVM_BLOCK_GAS_LIMIT
 *     naming the first envelope past it (CAPACITY_UNITS); bridge ops count
 *     21 000; exactly at the limit passes; FinalizeBlock FAULTs on such a
 *     block.
 *  8. CheckTx: the dry run (new) of an EVM CALL admits it with the
 *     synthetic (sender, nonce) key and NO EVM effect row; a second CALL
 *     of the same sender carries the SAME key (the pending set admits one);
 *     a gapped nonce is refused; the RECHECK form (no VM) admits / refuses
 *     the same way and refuses a stale nonce after a block. Red-team 1
 *     F1: the no-VM mode (what CheckTx now runs for NEW entries too) with
 *     a recording pending-conflict probe — probed once with exactly
 *     (sender, nonce) under domain 2; a conflict is -1 EXEC with no key
 *     filed; a probe failure -2; a gapped nonce reaches the probe first
 *     (it runs BEFORE the pre-validation); a CORE-only envelope is never
 *     probed. Red-team 1 F3: one access entry + one key at gas exactly
 *     21 000 + 2 400 + 1 900 is admitted in both modes, one below refused
 *     (the intrinsic floor is never stricter than the engine). F5: the
 *     genesis-derived initial height of the fixture reads 1.
 *     8d. (red-team 1 D1) the pure judge: price 0 refuses CALL / CREATE /
 *     DEPOSIT (FEE), passes WITHDRAW / REDEEM and non-EVM envelopes;
 *     price > 0 unchanged. End to end with the price voted to 0 at
 *     HE + 2: CheckTx refuses DEPOSIT / CALL / CREATE (FEE) and admits a
 *     WITHDRAW and a CORE SPEND; FinalizeBlock refuses the CALL (FEE) and
 *     applies the WITHDRAW.
 *     8b. the CheckTx block time (design §10): the ONE tip-time read
 *     (nodus_witness_v2_tip_block_time) answers the tip block's non-zero
 *     header seconds; a TIMESTAMP-gated contract succeeds at that value
 *     and reverts at 0; with the tip's block-store record deleted the
 *     EVM CALL's dry run FAULTs while its recheck and a CORE envelope's
 *     dry run still pass (only an executing EVM leg reads the store).
 *     8c. CheckTx of the nodus-cli SHAPE: on an EVM chain whose gas price
 *     is 121 from height HE + 4 (the harness's price), DEPOSIT, WITHDRAW
 *     (explicit recipient), REDEEM (of a contract ticket, by a third
 *     key), CREATE and CALL built by the SHARED builder
 *     (client/nodus_v2_evm.c — what nodus-cli `evm` and the web wallet
 *     use) with nodus-cli evm_tx_run's inputs are each fed to the CheckTx
 *     dry run (new) AND its recheck; code + reason are PRINTED to stdout
 *     ("cli <OP>: ...") and acceptance is asserted; the DEPOSIT and the
 *     REDEEM then APPLY in one block (FinalizeBlock), with the reserve,
 *     the ticket, the nonce, both invariants and the roots checked. The
 *     DEPOSIT is pinned to the harness line (inputs 1, units 16028, fee
 *     1939388, change 9999899998060612) — a bridge op reserves no
 *     FAIL_RESERVE on its reads (design §4/§8). NEGATIVE: a CALL whose
 *     ceiling is the VM floor − 1, or the floor − FAIL_RESERVE, is still
 *     refused (code 7). A PROBE (not a CLI shape: the DEPOSIT at its
 *     minimum ceiling + FAIL_RESERVE) is printed, never asserted.
 *  9. the storage trie against the independent full rebuild
 *     (evm_trie_full.c, design I4), restart, a determinism twin (the SAME
 *     envelope bytes applied to two chains — signing is hedged, so
 *     separately built envelopes would be different inputs).
 * 10. upgrade: an S16 version-3 database (the EVM tables and the reserve
 *     dropped, user_version 16) reopened through the production open path
 *     is migrated to S17 (empty tables, reserve (1, 0), the evm_logs
 *     height index) with its
 *     committed and recomputed global roots and its CORE root unchanged,
 *     and keeps applying. A generation-2 chain applies byte-identically
 *     with the compiled table and with a table holding generations 1-2
 *     only (in-binary — see HOW IT CAN LIE).
 * 11. scan + address index (Nodus EVM P4-C): nodus_rt_native_describe_leg on
 *     APPLIED DEPOSIT / WITHDRAW / CALL envelopes (role, reserve move, the
 *     funding coin consumed, the change and the release coin created —
 *     the release id is a LIVE utxo_set key, so the describer's id is the
 *     exec's; the EVM leg describes with no native effect),
 *     nodus_rt_native_committed_signer_fp (the EVM sender), and the
 *     node-local address index with its flag ON writing the EVMFUND rows
 *     (fee row; (recipient, release, amount) — also to the signer itself)
 *     instead of failing the block.
 * 12. the per-leg trie batch (red-team-1 F6): (a) ROOT IDENTITY — one
 *     fixed two-leg effect list (ACCT CREATE/SET/DELETE, SLOT
 *     CREATE/SET/DELETE over two storage tries, one emptied, TICKET
 *     CREATE/DELETE, META SET) through the EVM adapter's mutate on two
 *     chains: batched (nodus_rt_evm_leg_begin … flush, one commit per
 *     trie per leg) and per-effect (no batch: every mutation commits).
 *     After each leg the account root, tickets root, every storage_root
 *     and the EVM root are byte-equal, and equal to the full-rebuild
 *     oracle (evm_trie_full.c) over the rows; the batched chain holds
 *     strictly fewer trie nodes. (b) DISCARD — inside a savepoint, a
 *     batch of mutations writes NO trie node and moves no root column
 *     before its flush, state_root refuses while it is open, discard
 *     closes it, and the savepoint rollback leaves the whole database
 *     byte-identical; the next batch then lands the same roots as the
 *     per-effect chain (no in-memory residue). A failed mutation inside a
 *     batch makes its flush refuse; a begin over a leftover batch is
 *     refused and the one after it opens. (c) THROUGH THE ENGINE — a
 *     block whose EVM CALL writes a slot (flushed inside the leg) and
 *     then FAULTs before commit (V2AP_FAIL_BEFORE_COMMIT) leaves the
 *     whole database byte-identical and no batch open; the same envelope
 *     then applies, its storage root matching the full rebuild.
 * 12b. the bridge's sender-code refusal (Kurultay #9 item 1, EVM ruleset
 *     v2): a control first (key K deposits, then withdraws — no code);
 *     then code is SEEDED at K's derived address through the adapter (a
 *     synthetic collision, nonce and balance kept) and another key's
 *     DEPOSIT re-anchors the EVM head (committed == recomputed after it).
 *     (a) a WITHDRAW and (b) a DEPOSIT signed by K are refused by CheckTx
 *     (new entry and recheck) and by the block, the ledger byte-identical
 *     (EVM accounts, META, CORE outputs, the reserve); (c) after the
 *     refusals a codeless sender's WITHDRAW (the other key) is admitted
 *     and lands, K untouched (the adapter refuses an ACCT SET that strips
 *     live code, so K's own codeless case is the control at the top).
 *  Section 1 also proves the address width is in D (Kurultay #9 item 2):
 *     a restatement of EVM_ACT_CONSTS re-derives the D literal, and the
 *     same vector with a width of 20 — or without the width entry — does
 *     not.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * The default standalone nodus build with the EVM runtime
 * (NODUS_EVM_ENABLED — nodus/CMakeLists.txt builds this test only
 * there). DNAC_EPOCH_LENGTH > 64 (checked: no epoch boundary among the
 * heights used; the production 720 — NOT the harness's 15). Environment:
 * none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_v2_evm_* directory per fixture, removed at its end (left
 * behind when a CHECK aborts — section 8c closes its fixture BEFORE its
 * acceptance CHECKs, so a refused CLI envelope leaves nothing).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The genesis is SEEDED with spendable UTXOs (V2X_SEED_NOT_REAL_UTXOS)
 *    and the votes are chain_config rows written before genesis — the
 *    approval path of a real vote (committee quorum, the 0x71 responder)
 *    is not exercised; section 3 tests the vote RULES as pure functions.
 *  - The D literal and the EVM generation's pins are SELF-DERIVED
 *    (shared/dnac/tests/nodus_evm_activation_oracle.py, written by the
 *    implementing agent): section 1's selfcheck proves C encoder ==
 *    that file, NOT independence. Its width check restates the constant
 *    vector by hand; the restatement is tied to the compiled one only by
 *    re-deriving the D literal (a vector edited in both places at once
 *    would still pass).
 *  - Section 12b computes no address collision: it WRITES the state one
 *    would produce, outside any block, and relies on an EVM-touching
 *    block to re-anchor the head. If that re-anchoring DEPOSIT fails
 *    ("O deposits"), the seam broke, not the bridge rule.
 *  - Section 8's probe is a test double: the real CheckTx probe
 *    (nodus_witness_cmt_app.c app_pend_probe — the pending set's
 *    other-owner rule, so a recheck of an admitted entry passes) and
 *    CheckTx's choice of the no-VM mode for a NEW entry are not driven
 *    here (nodus_cmt_app_check_tx is test_cmt_app.c's subject).
 *  - Section 8 cannot observe that the recheck runs NO VM: it observes
 *    the pre-validation's answers (admit, gapped / stale nonce refused)
 *    and the key list; the absence of execution is the code path
 *    (nodus_witness_v2_apply.c exec_evm_leg's dry_novm branch).
 *  - Section 8b cannot see the dry run's own TIMESTAMP: a reverted CALL
 *    is a paid failure the dry run admits like a success. It proves the
 *    value (the read + the engine at that value) and the wiring (the
 *    FAULT without the record) separately; that the dry run hands that
 *    value to the engine is the code path (nodus_witness_v2_apply.c
 *    nodus_witness_v2_env_dry_run_ex, blk->timestamp).
 *  - The §18 RPC per-height simulation budget (nodus_witness_handlers.c
 *    evm_sim_once) is not reached here: it is a static of the handler
 *    file behind a TCP connection.
 *  - Section 7 drives the seam, not nodus_cmt_app_prepare_proposal: the
 *    pack's gas skip (nodus_witness_cmt_app.c app_prep_pack) is not
 *    exercised here.
 *  - Section 10's "unchanged" is IN-BINARY (two tables, one build) and
 *    over the dropped-then-recreated empty tables; byte-identity to the
 *    PREVIOUS binary (LastResultsHash / app hash of a non-EVM block) is
 *    the orchestrator's parent-vs-this comparison.
 *  - The CORE fee sponsor ≠ EVM sender case (design §2) is not built:
 *    every envelope here is signed by one key.
 *  - Section 11 turns the address index on with a bare host (zeroed
 *    identity, only the flag set) on the engine fixture, not through the
 *    real host pipeline test_addr_index.c drives; a REDEEM's release row
 *    and a CREATE are not indexed here (same code path as WITHDRAW /
 *    CALL).
 *  - Section 8c RESTATES the node's evm_estimate (a static of
 *    nodus_witness_handlers.c handle_evm_call) and nodus-cli evm_tx_run's
 *    parameter gathering in test code: a later change to either is
 *    invisible here until this restatement is updated. It builds with the
 *    node's compiled generation table in-process, not with the CLI
 *    binary, and lists ONE coin to the builder (the harness wallet's
 *    shape) where the CLI lists every unlocked native coin. The 10^16
 *    coin / 10^11 deposit are INFERRED from the harness line's change +
 *    fee; the harness's own coin amount was not printed.
 *  - Section 12 (a)/(b) drive the adapter's mutate directly with a
 *    hand-made effect list (no VM, no meter, rows the invariant would
 *    refuse); the account and tickets leaf encodings of the oracle are
 *    RESTATED here from design §6. A mutation failing MID-leg inside the
 *    engine (exec_evm_leg's discard at `done`) is not injectable: (b)
 *    proves discard on the adapter, (c) the engine's flush + rollback.
 *    The node-count drop is asserted as "fewer", not a measured size.
 *
 * @file test_v2_evm.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_rt_evm.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_rt_native.h"    /* 11: the describer      */
#include "witness/nodus_witness_addr_index.h"   /* 11: the address index  */
#include "witness/nodus_witness_host.h"         /* 11: the index flag     */
#include "witness/nodus_witness_cmt_app.h"      /* 12: real FinalizeBlock */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_evm.h"            /* 8c: the CLI's builder     */

#include "v2_genesis_fixture.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/res_meter.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/hash/keccak256.h"
#include "crypto/sign/qgp_dilithium.h"

#include "evm/trie/evm_trie.h"
#include "evm/trie/evm_trie_full.h"
#include "evm/trie/evm_trie_rlp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define D2       ((uint64_t)DNAC_CFG_RULESET_GEN2_D2)
#define DEVM     ((uint64_t)DNAC_CFG_EVM_ACTIVE_D)
/* The fixture's fee per envelope. Red-team 1 D1 (operator decision
 * 2026-10-05-nodus-evm-redteam1-operator.md: "Fiyat 0 iken EVM durur")
 * refuses EVM CALL / CREATE / DEPOSIT while the gas price is 0, so the
 * fixture runs at FIX_PRICE (1 raw per unit) from height 1 — the price
 * the real EVM_ACTIVE vote requires anyway (stateful rule (d)) — and
 * every envelope must pay res_max_total_units × 1. The largest ceiling
 * built here is section 7's CALL one gas over the cap: static +
 * 30 000 001 × w_gas (1) + FAIL_RESERVE + 2 000 000 ≈ 3.3 × 10^7; FEE =
 * 10^9 covers it with headroom and stays above the flat floor 10^6. */
#define FEE      1000000000ull
#define FIX_PRICE 1ull
#define BIG      (FEE + 1000ull)
#define H2       3ull                 /* generation-2 effective height  */
#define HE       5ull                 /* EVM_ACTIVE effective height    */
#define AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define OUT_LEN  232u                 /* one transfer-section output     */
#define UTXO_LEN 284u                 /* the CORE UTXO record            */
#define Q        NODUS_RT_EVM_Q

/* the default EVM-leg declaration of an ordinary CALL / CREATE */
#define EVM_MAXEFF    256u
#define EVM_MAXBYTES  65536u

/* ══ keys and coins ═══════════════════════════════════════════════════ */

#define N_KEYS 3
#define NF     48                     /* FEE-exact coins per key         */
#define NB     6                      /* FEE + 1000 coins per key        */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];                   /* SHA3-512(pk): the verdict fp    */
    char    hex[129];
} tkey_t;

static tkey_t g_k[N_KEYS];

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x71 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, QGP_DSA87_PUBLICKEYBYTES, g_k[i].fp)
            != 0)
            return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* the EVM sender of key k: SHA3-512(pk)[0..32] (design §2) */
static const uint8_t *sender_of(int k) { return g_k[k].fp; }

/* coin `idx` of kind `big` (0 FEE-exact / 1 FEE + 1000) of key k */
static void coin_seed(int k, int big, int idx, uint8_t s[32]) {
    memset(s, 0x5a, 32);
    s[0] = (uint8_t)(0xE0 | k);
    s[1] = (uint8_t)big;
    s[2] = (uint8_t)idx;
}

static int coin_nul(int k, int big, int idx, uint8_t out[64]) {
    uint8_t pre[160], s[32];
    coin_seed(k, big, idx, s);
    memcpy(pre, g_k[k].hex, 128);
    memcpy(pre + 128, s, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

/* a coin of kind `big` (seed byte 1) and an explicit amount */
static int seed_coin_amount(nodus_witness_t *w, int k, int big, int idx,
                            uint64_t amount) {
    uint8_t nul[64];
    if (coin_nul(k, big, idx, nul) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_k[k].hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int seed_coin(nodus_witness_t *w, int k, int big, int idx) {
    return seed_coin_amount(w, k, big, idx, big ? BIG : FEE);
}

/* Section 11 (the nodus-cli shape): ONE large native coin per key — the
 * wallet shape of the harness run (one listed coin, inputs=1) — under a
 * seed kind no other coin or change output uses (0/1 the seeded coins,
 * 2 build_tx change, 3 spend_tx change). 10^16 raw with a 10^11 deposit
 * reproduces the harness line's change 9999899998060612 + fee 1939388
 * (INFERRED: 10^16 − 9999899998060612 − 1939388 = 10^11; the harness's
 * coin amount itself was not printed). */
#define CLI_KIND    4
#define CLI_COIN    10000000000000000ull
#define CLI_DEPOSIT 100000000000ull
#define CLI_PRICE   121ull                /* the harness chain's price   */

/* ══ the fixture ══════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
    uint64_t         h;              /* the next block height             */
    int              nf[N_KEYS];     /* next FEE coin per key             */
    int              nb[N_KEYS];     /* next big coin per key             */
} fixture_t;

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* HF-2 + HF-3 on from 1, the generation-2 vote at H2 (gen2 != 0), the
 * EVM vote at HE (evm != 0), the coins — all BEFORE the engine genesis */
static int fx_open_ex(fixture_t *fx, const char *tag, int gen2, int evm,
                      uint64_t evm_gas, uint64_t gas_price_h,
                      uint64_t price0_h);

static int fx_open(fixture_t *fx, const char *tag, int gen2, int evm) {
    return fx_open_ex(fx, tag, gen2, evm, 0, 0, 0);
}

/* Always: a GAS_PRICE_RAW_PER_UNIT row (param 5) of FIX_PRICE effective
 * at height 1 (the genesis row is price 0 — v2_genesis_fixture.h
 * v2x_cfg_make — and red-team 1 D1 stops the EVM at price 0).
 * evm_gas != 0: an EVM_BLOCK_GAS_LIMIT row (param 15) effective at HE.
 * gas_price_h != 0: a param-5 row of CLI_PRICE effective at that height,
 * and one CLI_COIN coin per key.
 * price0_h != 0 (the D1 case only): a param-5 row of 0 effective at that
 * height — the price voted back to 0 after the EVM edge. */
static int fx_open_ex(fixture_t *fx, const char *tag, int gen2, int evm,
                      uint64_t evm_gas, uint64_t gas_price_h,
                      uint64_t price0_h) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_evm_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x45, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
            != 0 ||
        cc_row(fx->w, DNAC_CFG_HF3_ACTIVE, DNAC_CFG_HF3_ACTIVE_ON, 1, 12)
            != 0)
        return -1;
    if (gen2 && cc_row(fx->w, DNAC_CFG_RULESET_GEN2, D2, H2, 13) != 0)
        return -1;
    if (evm && cc_row(fx->w, DNAC_CFG_EVM_ACTIVE, DEVM, HE, 14) != 0)
        return -1;
    if (evm_gas &&
        cc_row(fx->w, DNAC_CFG_EVM_BLOCK_GAS_LIMIT, evm_gas, HE, 15) != 0)
        return -1;
    if (gas_price_h &&
        cc_row(fx->w, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, CLI_PRICE,
               gas_price_h, 16) != 0)
        return -1;
    if (cc_row(fx->w, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, FIX_PRICE, 1, 17) !=
            0)
        return -1;
    if (price0_h &&
        cc_row(fx->w, DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, 0, price0_h, 18) != 0)
        return -1;
    for (int k = 0; k < N_KEYS; k++) {
        for (int i = 0; i < NF; i++)
            if (seed_coin(fx->w, k, 0, i) != 0) return -1;
        for (int i = 0; i < NB; i++)
            if (seed_coin(fx->w, k, 1, i) != 0) return -1;
        if (gas_price_h &&
            seed_coin_amount(fx->w, k, CLI_KIND, 0, CLI_COIN) != 0)
            return -1;
    }
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL) != 0)
        return -1;
    fx->h = 1;
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int fx_reopen(fixture_t *fx) {
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    fx->w->chain_config_cache_warm = false;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    return nodus_witness_create_chain_db(fx->w, fx->chain16);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

/* idle blocks until the next height is `target` */
static int fx_to(fixture_t *fx, uint64_t target) {
    while (fx->h < target) {
        nodus_v2_block_t b;
        mk_block(&b, fx->h, NULL, 0);
        if (v2x_cmt_apply_ok(fx->w, &b) != 0) return -1;
        fx->h++;
    }
    return 0;
}

/* a chain past the EVM edge: blocks 1..HE-1 applied, next height HE */
static int fx_evm_ready_gas(fixture_t *fx, const char *tag,
                            uint64_t evm_gas) {
    if (fx_open_ex(fx, tag, 1, 1, evm_gas, 0, 0) != 0) return -1;
    return fx_to(fx, HE);
}

static int fx_evm_ready(fixture_t *fx, const char *tag) {
    return fx_evm_ready_gas(fx, tag, 0);
}

static uint64_t q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static const nodus_domain_runtime_t *gevm(uint32_t dom) {
    return nodus_runtime_for_generation(NODUS_RT_GEN_EVM, dom);
}

/* ══ envelopes ════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *bytes;
    size_t   len;
    uint8_t  intent[64];
    uint8_t  coin[64];               /* the CORE input (zero when none)   */
} tx_t;

static void tx_free(tx_t *t) {
    free(t->bytes);
    memset(t, 0, sizeof(*t));
}

typedef struct {
    int            key;              /* the ONE signer of every leg       */
    int            with_core;        /* the CORE EVMFUND leg              */
    int            with_evm;         /* the EVM leg                       */
    uint8_t        role;             /* 0 = the op's own role             */
    int            big;              /* fund with a FEE + 1000 coin       */
    uint64_t       lock;             /* DEPOSIT: what the coin locks      */
    uint32_t       evm_op;
    const uint8_t *call;
    uint32_t       call_len;
    uint32_t       evm_eff, evm_bytes;
    int            exact;            /* ceiling = static + gas + FAIL_RES */
    int64_t        delta;            /* added to the ceiling              */
} spec_t;

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* the role an EVM op's CORE sibling declares (test-side restatement) */
static uint8_t role_of(uint32_t op) {
    if (op == NODUS_RT_EVM_CALL || op == NODUS_RT_EVM_CREATE)
        return NODUS_RT_EVMFUND_ROLE_FEE;
    if (op == NODUS_RT_EVM_DEPOSIT) return NODUS_RT_EVMFUND_ROLE_DEPOSIT;
    return NODUS_RT_EVMFUND_ROLE_RELEASE;
}

/* the declared gas of an EVM call (test-side restatement of design §2) */
static uint64_t gas_of(uint32_t op, const uint8_t *c) {
    uint64_t g = 0;
    size_t off = (op == NODUS_RT_EVM_CALL) ? 65 :
                 (op == NODUS_RT_EVM_CREATE) ? 33 : 0;
    if (!off) return 0;
    for (int i = 0; i < 8; i++) g = (g << 8) | c[off + i];
    return g;
}

/**
 * Build one EVM envelope per `s` at the fixture's next height: leg 0 the
 * CORE EVMFUND (one coin, change back to the signer when the coin is
 * larger than FEE + lock), leg 1 the EVM op; the ruleset tuples from the
 * registry's CURRENT manifests; the ceiling from the plan's static units
 * (dna_meter_plan_build_ex under the EVM generation's policy); both legs
 * REALLY signed by key s->key. @return 0 / -1.
 */
static int build_tx(fixture_t *fx, const spec_t *s, tx_t *out) {
    static uint8_t ccall[2 + 1 + 64 + 1 + OUT_LEN];
    static uint8_t auth[2][AUTH_LEN];
    memset(out, 0, sizeof(*out));
    const int k = s->key;
    const uint8_t role = s->role ? s->role : role_of(s->evm_op);
    const int rsv = (role != NODUS_RT_EVMFUND_ROLE_FEE);

    dna_env_leg_in_t legs[2];
    dna_env_leg_ctx_t lctx[2];
    uint16_t n = 0, evm_leg = 0;
    memset(legs, 0, sizeof(legs));
    memset(lctx, 0, sizeof(lctx));

    if (s->with_core) {
        int big = s->big;
        int idx = big ? fx->nb[k]++ : fx->nf[k]++;
        if ((big && idx >= NB) || (!big && idx >= NF)) return -1;
        uint64_t amount = big ? BIG : FEE;
        if (coin_nul(k, big, idx, out->coin) != 0) return -1;
        uint64_t lock = (role == NODUS_RT_EVMFUND_ROLE_DEPOSIT) ? s->lock : 0;
        if (amount < FEE + lock) return -1;
        uint64_t change = amount - FEE - lock;
        size_t off = 0;
        ccall[off++] = NODUS_RT_EVMFUND_CALL_VER;
        ccall[off++] = role;
        ccall[off++] = 1;
        memcpy(ccall + off, out->coin, 64);   off += 64;
        ccall[off++] = change ? 1u : 0u;
        if (change) {
            uint8_t seed[32];
            coin_seed(k, 2, idx + (big ? 100 : 0), seed);
            seed[3] = (uint8_t)(fx->h & 0xff);
            nodus_v2_xfer_out_put(ccall + off, g_k[k].hex, change, NULL,
                                  seed);
            off += OUT_LEN;
        }
        dna_domain_manifest_t core;
        if (nodus_witness_domreg_get(fx->w, DNA_DOMAIN_CORE, NULL, &core,
                                     NULL) != 0)
            return -1;
        /* the EXACT result: CREATE(change, release) + SET pool (+ SET
         * reserve) + DELETE input */
        uint32_t creates = (change ? 1u : 0u) +
                           (role == NODUS_RT_EVMFUND_ROLE_RELEASE ? 1u : 0u);
        uint32_t neff = creates + 1u + (rsv ? 1u : 0u) + 1u;
        dna_env_leg_in_t *L = &legs[n];
        L->hdr.domain_id = DNA_DOMAIN_CORE;
        L->hdr.runtime_op = DNA_CORERULE_EVMFUND;
        L->hdr.ruleset_version = core.ruleset_version;
        L->hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        L->hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        L->hdr.call_len = (uint32_t)off;
        L->hdr.auth_len = AUTH_LEN;
        L->hdr.res_max_effects = neff;
        L->hdr.res_max_effect_bytes =
            (uint32_t)DNA_EFFECT_FIXED_HEAD +
            (uint32_t)DNA_EFFECT_RECORD_LEN * neff +
            creates * (64u + UTXO_LEN) + (1u + 8u) * (rsv ? 2u : 1u) + 64u;
        L->call_data = ccall;
        memset(auth[n], 0, AUTH_LEN);
        L->auth_data = auth[n];
        lctx[n].domain_id = DNA_DOMAIN_CORE;
        lctx[n].ruleset_version = core.ruleset_version;
        memcpy(lctx[n].ruleset_hash, core.ruleset_hash, 64);
        n++;
    }
    if (s->with_evm) {
        dna_domain_manifest_t em;
        if (nodus_witness_domreg_get(fx->w, DNA_DOMAIN_EVM, NULL, &em,
                                     NULL) != 0) {
            /* before the edge: the EVM generation's compiled tuple */
            const nodus_domain_runtime_t *e = gevm(DNA_DOMAIN_EVM);
            if (!e) return -1;
            em.ruleset_version = e->ruleset_version;
            memcpy(em.ruleset_hash, e->ruleset_hash, 64);
        }
        dna_env_leg_in_t *L = &legs[n];
        L->hdr.domain_id = DNA_DOMAIN_EVM;
        L->hdr.runtime_op = s->evm_op;
        L->hdr.ruleset_version = em.ruleset_version;
        L->hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        L->hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        L->hdr.call_len = s->call_len;
        L->hdr.auth_len = AUTH_LEN;
        L->hdr.res_max_effects = s->evm_eff ? s->evm_eff : EVM_MAXEFF;
        L->hdr.res_max_effect_bytes = s->evm_bytes ? s->evm_bytes
                                                   : EVM_MAXBYTES;
        L->call_data = s->call;
        memset(auth[n], 0, AUTH_LEN);
        L->auth_data = auth[n];
        lctx[n].domain_id = DNA_DOMAIN_EVM;
        lctx[n].ruleset_version = em.ruleset_version;
        memcpy(lctx[n].ruleset_hash, em.ruleset_hash, 64);
        evm_leg = (uint16_t)(n + 1u);
        n++;
    }
    if (n == 0) return -1;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.leg_count = n;
    in.legs = legs;

    /* the static units under the EVM generation's policy */
    const nodus_domain_runtime_t *sys = gevm(DNA_DOMAIN_SYSTEM);
    if (!sys || !sys->meter_policy) return -1;
    in.res_max_total_units = (uint64_t)INT32_MAX;
    size_t len = 0, used = 0;
    if (dna_env_encoded_size(legs, n, &len) != 0) return -1;
    uint8_t *tmp = malloc(len);
    dna_env_view_t *view = calloc(1, sizeof(*view));
    dna_meter_plan_t *plan = calloc(1, sizeof(*plan));
    int ok = -1;
    if (tmp && view && plan &&
        dna_env_encode(&in, tmp, len, &used) == 0 && used == len &&
        dna_env_decode(tmp, len, view) == 0 &&
        dna_meter_plan_build_ex(sys->meter_policy, view, evm_leg, plan) ==
            DNA_METER_OK)
        ok = 0;
    uint64_t stat = plan ? plan->static_total : 0;
    free(tmp);
    free(view);
    free(plan);
    if (ok != 0) return -1;
    uint64_t gas = s->with_evm ? gas_of(s->evm_op, s->call) : 0;
    uint64_t ceiling = s->exact
        ? stat + gas * DNA_METER_EVM_W_GAS + DNA_METER_EVM_FAIL_RESERVE
        : stat + gas * DNA_METER_EVM_W_GAS + DNA_METER_EVM_FAIL_RESERVE +
              2000000ull;
    in.res_max_total_units = (uint64_t)((int64_t)ceiling + s->delta);

    uint8_t *auths[2] = { auth[0], auth[1] };
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    nodus_v2_spend_err_t err;
    memset(&err, 0, sizeof(err));
    int rc = nodus_v2_env_sign_one_key(&in, auths, lctx, fx->w->v2_chain32,
                                       fx->h - 1u, g_k[k].pk, g_k[k].sk,
                                       &out->bytes, &out->len, pf, &err);
    if (rc == NODUS_V2_SPEND_OK) memcpy(out->intent, pf->intent_id, 64);
    free(pf);
    return rc == NODUS_V2_SPEND_OK ? 0 : -1;
}

/* the common paired shape: key k, op, call bytes */
static int evm_tx(fixture_t *fx, int k, uint32_t op, const uint8_t *call,
                  uint32_t cl, tx_t *out) {
    spec_t s;
    memset(&s, 0, sizeof(s));
    s.key = k;
    s.with_core = 1;
    s.with_evm = 1;
    s.evm_op = op;
    s.call = call;
    s.call_len = cl;
    return build_tx(fx, &s, out);
}

/* a CORE SPEND of one big coin back to its owner (a non-EVM item) */
static int spend_tx(fixture_t *fx, int k, tx_t *out) {
    static uint8_t call[1 + 64 + 1 + OUT_LEN];
    static uint8_t auth[AUTH_LEN];
    memset(out, 0, sizeof(*out));
    int idx = fx->nb[k]++;
    if (idx >= NB) return -1;
    if (coin_nul(k, 1, idx, out->coin) != 0) return -1;
    size_t off = 0;
    call[off++] = 1;
    memcpy(call + off, out->coin, 64);  off += 64;
    call[off++] = 1;
    uint8_t seed[32];
    coin_seed(k, 3, idx, seed);
    nodus_v2_xfer_out_put(call + off, g_k[k].hex, BIG - FEE, NULL, seed);
    off += OUT_LEN;
    dna_domain_manifest_t core;
    if (nodus_witness_domreg_get(fx->w, DNA_DOMAIN_CORE, NULL, &core, NULL)
        != 0)
        return -1;
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_CORE;
    leg.hdr.runtime_op = DNA_CORERULE_SPEND;
    leg.hdr.ruleset_version = core.ruleset_version;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len = (uint32_t)off;
    leg.hdr.auth_len = AUTH_LEN;
    nodus_v2_spend_effect_decl(1, 1, &leg.hdr.res_max_effects,
                               &leg.hdr.res_max_effect_bytes);
    leg.call_data = call;
    memset(auth, 0, sizeof(auth));
    leg.auth_data = auth;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.leg_count = 1;
    in.legs = &leg;
    in.res_max_total_units = 1000000ull;
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id = DNA_DOMAIN_CORE;
    lctx.ruleset_version = core.ruleset_version;
    memcpy(lctx.ruleset_hash, core.ruleset_hash, 64);
    uint8_t *auths[1] = { auth };
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    nodus_v2_spend_err_t err;
    memset(&err, 0, sizeof(err));
    int rc = nodus_v2_env_sign_one_key(&in, auths, &lctx, fx->w->v2_chain32,
                                       fx->h - 1u, g_k[k].pk, g_k[k].sk,
                                       &out->bytes, &out->len, pf, &err);
    if (rc == NODUS_V2_SPEND_OK) memcpy(out->intent, pf->intent_id, 64);
    free(pf);
    return rc == NODUS_V2_SPEND_OK ? 0 : -1;
}

/* ── call bytes (design §2) — a test-side encoder ──────────────────── */

static size_t put_be(uint8_t *p, uint64_t v, int n) {
    for (int i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    return (size_t)n;
}

/** value_wei given as a u64 (enough for every test amount). */
static size_t enc_call(uint8_t *d, const uint8_t to[32], uint64_t value_wei,
                       uint64_t gas, uint64_t nonce, const uint8_t *data,
                       uint32_t dl, const uint8_t acc_addr[32],
                       const uint8_t acc_key[32]) {
    size_t o = 0;
    d[o++] = 1;
    memcpy(d + o, to, 32); o += 32;
    memset(d + o, 0, 24); o += 24;
    o += put_be(d + o, value_wei, 8);
    o += put_be(d + o, gas, 8);
    o += put_be(d + o, nonce, 8);
    if (acc_addr) {
        o += put_be(d + o, 1, 2);
        memcpy(d + o, acc_addr, 32); o += 32;
        o += put_be(d + o, acc_key ? 1 : 0, 2);
        if (acc_key) { memcpy(d + o, acc_key, 32); o += 32; }
    } else {
        o += put_be(d + o, 0, 2);
    }
    o += put_be(d + o, dl, 4);
    if (dl) memcpy(d + o, data, dl);
    return o + dl;
}

static size_t enc_create(uint8_t *d, uint64_t gas, uint64_t nonce,
                         const uint8_t *init, uint32_t il) {
    size_t o = 0;
    d[o++] = 1;
    memset(d + o, 0, 32); o += 32;              /* value 0 */
    o += put_be(d + o, gas, 8);
    o += put_be(d + o, nonce, 8);
    o += put_be(d + o, 0, 2);                   /* no access list */
    o += put_be(d + o, il, 4);
    memcpy(d + o, init, il);
    return o + il;
}

static size_t enc_deposit(uint8_t *d, uint64_t amount, uint64_t nonce) {
    d[0] = 1;
    put_be(d + 1, amount, 8);
    put_be(d + 9, nonce, 8);
    return 17;
}

static size_t enc_withdraw(uint8_t *d, uint64_t amount, uint64_t nonce,
                           const uint8_t dest[64]) {
    d[0] = 1;
    put_be(d + 1, amount, 8);
    put_be(d + 9, nonce, 8);
    memcpy(d + 17, dest, 64);
    return 81;
}

static size_t enc_redeem(uint8_t *d, const uint8_t tid[64], uint64_t amount,
                         const uint8_t dest[64]) {
    d[0] = 1;
    memcpy(d + 1, tid, 64);
    put_be(d + 65, amount, 8);
    memcpy(d + 73, dest, 64);
    return 137;
}

/* ── hand-assembled contracts (Prague opcodes) ──────────────────────── */

/* STORE: SSTORE(calldata[0..32] = key, calldata[32..64] = value):
 *   PUSH1 0x20 CALLDATALOAD  PUSH1 0x00 CALLDATALOAD  SSTORE  STOP */
static const uint8_t RT_STORE[] = { 0x60, 0x20, 0x35, 0x60, 0x00, 0x35,
                                    0x55, 0x00 };
/* REVERT: PUSH1 0 PUSH1 0 REVERT */
static const uint8_t RT_REVERT[] = { 0x60, 0x00, 0x60, 0x00, 0xfd };
/* FIVE: SSTORE(k, 1) for k = 1..5, STOP */
static const uint8_t RT_FIVE[] = {
    0x60, 0x01, 0x60, 0x01, 0x55, 0x60, 0x01, 0x60, 0x02, 0x55,
    0x60, 0x01, 0x60, 0x03, 0x55, 0x60, 0x01, 0x60, 0x04, 0x55,
    0x60, 0x01, 0x60, 0x05, 0x55, 0x00 };
/* SLOADS: SLOAD slots 400 .. 1 (distinct cold reads):
 *   PUSH2 400; L: JUMPDEST DUP1 SLOAD POP PUSH1 1 SWAP1 SUB DUP1 PUSH1 3
 *   JUMPI STOP */
static const uint8_t RT_SLOADS[] = {
    0x61, 0x01, 0x90, 0x5b, 0x80, 0x54, 0x50, 0x60, 0x01, 0x90, 0x03,
    0x80, 0x60, 0x03, 0x57, 0x00 };

/* TICKET: CALLDATACOPY(0, 0, 64); CALL(GAS, ticket_addr, CALLVALUE,
 * 0, 64, 64, 64); POP; STOP — the address is patched in at build. */
static uint8_t g_rt_ticket[7 + 9 + 1 + 32 + 2 + 2];
static size_t g_rt_ticket_len;

static int rt_ticket_build(void) {
    uint8_t ta[32];
    if (nodus_rt_evm_ticket_addr(ta) != 0) return -1;
    size_t o = 0;
    static const uint8_t pre[] = {
        0x60, 0x40, 0x60, 0x00, 0x60, 0x00, 0x37,   /* CALLDATACOPY      */
        0x60, 0x40, 0x60, 0x40, 0x60, 0x40, 0x60, 0x00, /* ret/args      */
        0x34 };                                     /* CALLVALUE         */
    memcpy(g_rt_ticket + o, pre, sizeof(pre)); o += sizeof(pre);
    g_rt_ticket[o++] = 0x7f;                        /* PUSH32 ticket addr*/
    memcpy(g_rt_ticket + o, ta, 32); o += 32;
    g_rt_ticket[o++] = 0x5a;                        /* GAS               */
    g_rt_ticket[o++] = 0xf1;                        /* CALL              */
    g_rt_ticket[o++] = 0x50;                        /* POP               */
    g_rt_ticket[o++] = 0x00;                        /* STOP              */
    g_rt_ticket_len = o;
    return o <= sizeof(g_rt_ticket) ? 0 : -1;
}

/** initcode = CODECOPY the runtime into memory and RETURN it. */
static size_t mk_initcode(uint8_t *d, const uint8_t *rt, size_t rl) {
    const uint8_t hdr[12] = { 0x60, (uint8_t)rl, 0x60, 12, 0x60, 0x00, 0x39,
                              0x60, (uint8_t)rl, 0x60, 0x00, 0xf3 };
    memcpy(d, hdr, 12);
    memcpy(d + 12, rt, rl);
    return 12 + rl;
}

/* ══ observations ═════════════════════════════════════════════════════ */

static uint64_t acct_nonce(nodus_witness_t *w, const uint8_t addr[32]) {
    sqlite3_stmt *st = NULL;
    uint64_t v = UINT64_MAX;
    if (sqlite3_prepare_v2(w->db,
            "SELECT nonce FROM evm_accounts WHERE addr = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return v;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) v = (uint64_t)sqlite3_column_int64(st, 0);
    else if (rc == SQLITE_DONE) v = 0;
    sqlite3_finalize(st);
    return v;
}

/** The low 8 bytes of an account's balance (the test amounts fit). */
static uint64_t acct_balance_lo(nodus_witness_t *w, const uint8_t addr[32]) {
    sqlite3_stmt *st = NULL;
    uint64_t v = UINT64_MAX;
    if (sqlite3_prepare_v2(w->db,
            "SELECT balance FROM evm_accounts WHERE addr = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return v;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32) {
        const uint8_t *b = sqlite3_column_blob(st, 0);
        v = 0;
        for (int i = 24; i < 32; i++) v = (v << 8) | b[i];
    } else if (rc == SQLITE_DONE) {
        v = 0;
    }
    sqlite3_finalize(st);
    return v;
}

static uint64_t slot_lo(nodus_witness_t *w, const uint8_t addr[32],
                        uint8_t slot_last) {
    uint8_t slot[32] = { 0 };
    slot[31] = slot_last;
    sqlite3_stmt *st = NULL;
    uint64_t v = UINT64_MAX;
    if (sqlite3_prepare_v2(w->db,
            "SELECT value FROM evm_slots WHERE addr = ?1 AND slot = ?2",
            -1, &st, NULL) != SQLITE_OK)
        return v;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, slot, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32) {
        const uint8_t *b = sqlite3_column_blob(st, 0);
        v = 0;
        for (int i = 24; i < 32; i++) v = (v << 8) | b[i];
    } else if (rc == SQLITE_DONE) {
        v = 0;
    }
    sqlite3_finalize(st);
    return v;
}

static int receipt_of(nodus_witness_t *w, uint64_t h, size_t item,
                      uint8_t *buf, size_t cap, size_t *len,
                      uint8_t digest[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT receipt, digest FROM evm_receipts WHERE "
            "global_height = ?1 AND item_index = ?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)item);
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        if (n > 0 && (size_t)n <= cap && sqlite3_column_bytes(st, 1) == 64) {
            memcpy(buf, sqlite3_column_blob(st, 0), (size_t)n);
            memcpy(digest, sqlite3_column_blob(st, 1), 64);
            *len = (size_t)n;
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/** Receipt layout (design §7): tag 16 ‖ status u8 @16 ‖ op u8 @17 ‖
 *  gas u64 @18 ‖ created[32] @26 ‖ ... */
static uint64_t rcpt_gas(const uint8_t *r) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | r[18 + i];
    return v;
}

static uint64_t pool_of(nodus_witness_t *w) {
    return q1(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1");
}

static uint64_t reserve_of(nodus_witness_t *w) {
    return q1(w, "SELECT reserve_raw FROM v2_evm_reserve WHERE id = 1");
}

static int coin_live(nodus_witness_t *w, const uint8_t nul[64]) {
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                           "nullifier = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

/* live UTXOs of key k with exactly `amount` */
static int owned_with(nodus_witness_t *w, int k, uint64_t amount) {
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM utxo_set WHERE "
                           "owner = ?1 AND amount = ?2", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, g_k[k].hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)amount);
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return n;
}

static int evm_root(nodus_witness_t *w, uint8_t out[64]) {
    const nodus_domain_runtime_t *e = gevm(DNA_DOMAIN_EVM);
    return e ? e->state_root(e, (struct nodus_witness *)w, out) : -1;
}

static int core_root_now(nodus_witness_t *w, uint8_t out[64]) {
    const nodus_domain_runtime_t *c = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &c) != 0 || !c)
        return -1;
    return c->state_root(c, (struct nodus_witness *)w, out);
}

static int roots_ok(nodus_witness_t *w) {
    uint8_t c[64], f[64];
    if (nodus_witness_v2_committed_global_root(w, c) != 0 ||
        nodus_witness_global_root_v2(w, f, NULL, NULL, NULL) != 0)
        return -1;
    return memcmp(c, f, 64) == 0 ? 0 : -1;
}

/* both invariants: the supply gate dispatches CORE (+ evm_reserve under
 * the EVM generation) and the EVM one */
static int invariants_ok(nodus_witness_t *w) {
    return nodus_witness_v2_supply_check(w) == 0 ? 1 : 0;
}

/* ══ block helpers ═══════════════════════════════════════════════════ */

#define MAXB 8

/* The determinism twin's second chain: when set, every block apply_txs
 * commits is applied to it too with the SAME envelope bytes, and the two
 * results must match field for field. ML-DSA-87 signing here is HEDGED
 * (shared/crypto/sign/dsa/config.h:6 DILITHIUM_RANDOMIZED_SIGNING →
 * sign.c:288 draws fresh randomness), so envelopes built separately for
 * two chains carry different signatures and wire ids — different inputs,
 * not a determinism check. */
static fixture_t *g_mirror = NULL;

static int results_equal(const nodus_v2_tx_result_t *a,
                         const nodus_v2_tx_result_t *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (a[i].code != b[i].code || a[i].gas_used != b[i].gas_used ||
            a[i].gas_wanted != b[i].gas_wanted ||
            a[i].data_len != b[i].data_len ||
            memcmp(a[i].data, b[i].data, a[i].data_len) != 0)
            return -1;
    return 0;
}

/** Apply one block of `n` txs at the next height with its own results.
 *  @return the engine's rc (0 = committed); codes in res[]. */
static int apply_txs(fixture_t *fx, tx_t *t, size_t n,
                     nodus_v2_tx_result_t *res) {
    nodus_v2_envelope_t v[MAXB];
    nodus_v2_block_t b;
    if (n > MAXB) return -1;
    for (size_t i = 0; i < n; i++) {
        v[i].env_bytes = t[i].bytes;
        v[i].env_len = t[i].len;
    }
    memset(res, 0, n * sizeof(*res));
    mk_block(&b, fx->h, v, n);
    b.cmt.results = res;
    b.cmt.results_cap = n;
    int rc = v2x_cmt_apply(fx->w, &b);
    if (rc == 0) fx->h++;
    if (g_mirror && g_mirror != fx) {
        nodus_v2_tx_result_t mres[MAXB];
        nodus_v2_block_t mb;
        if (g_mirror->h != b.global_height) return -1;
        memset(mres, 0, sizeof(mres));
        mk_block(&mb, g_mirror->h, v, n);
        mb.cmt.results = mres;
        mb.cmt.results_cap = n;
        int mrc = v2x_cmt_apply(g_mirror->w, &mb);
        if (mrc == 0) g_mirror->h++;
        if (mrc != rc || (rc == 0 && results_equal(res, mres, n) != 0)) {
            fprintf(stderr, "twin: block %llu diverged (rc %d / %d)\n",
                    (unsigned long long)b.global_height, rc, mrc);
            return -1;
        }
    }
    return rc;
}

/** One tx in its own block: its code (99 = the block did not commit). */
static uint32_t apply_one(fixture_t *fx, tx_t *t, nodus_v2_tx_result_t *r) {
    nodus_v2_tx_result_t res[1];
    if (apply_txs(fx, t, 1, res) != 0) return 99;
    if (r) *r = res[0];
    return res[0].code;
}

/** One tx that must be REFUSED, the ledger byte-unchanged; code out. */
static int refused_one(fixture_t *fx, tx_t *t, uint32_t *code) {
    nodus_v2_envelope_t v = { t->bytes, t->len };
    nodus_v2_tx_result_t res[1];
    nodus_v2_block_t b;
    mk_block(&b, fx->h, &v, 1);
    b.cmt.results = res;
    b.cmt.results_cap = 1;
    int rc = v2x_cmt_refused(fx->w, &b, 0, code);
    if (rc == 0) fx->h++;
    return rc == 0 && res[0].data_len == 0 ? 0 : -1;
}

/** Deploy `rt` from key k at nonce `nonce`; the created address from the
 *  receipt. @return 0 / -1. */
static int deploy(fixture_t *fx, int k, uint64_t nonce, const uint8_t *rt,
                  size_t rl, uint8_t addr_out[32]) {
    uint8_t init[128], call[256];
    size_t il = mk_initcode(init, rt, rl);
    size_t cl = enc_create(call, 300000, nonce, init, (uint32_t)il);
    tx_t t;
    if (evm_tx(fx, k, NODUS_RT_EVM_CREATE, call, (uint32_t)cl, &t) != 0)
        return -1;
    uint64_t h = fx->h;
    uint32_t code = apply_one(fx, &t, NULL);
    tx_free(&t);
    if (code != NODUS_V2_TX_OK) return -1;
    uint8_t rc[4096], dg[64];
    size_t rlen = 0;
    if (receipt_of(fx->w, h, 0, rc, sizeof(rc), &rlen, dg) != 0) return -1;
    if (rc[16] != 1) return -1;                /* status success         */
    memcpy(addr_out, rc + 26, 32);
    return 0;
}

/* ══ 1. shape ═════════════════════════════════════════════════════════ */

static int view_of(uint8_t *buf, size_t cap, uint32_t core_op,
                   uint8_t role, uint32_t evm_dom, uint32_t evm_op,
                   const uint8_t *evm_call, uint32_t evm_len,
                   dna_env_view_t *v) {
    /* a minimal decoded view (no signatures — the pure rules only) */
    uint8_t ccall[2] = { NODUS_RT_EVMFUND_CALL_VER, role };
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    uint8_t a = 0;
    legs[0].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[0].hdr.runtime_op = core_op;
    legs[0].hdr.ruleset_version = 6;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = 1;
    legs[0].hdr.call_len = 2;
    legs[0].hdr.auth_len = 1;
    legs[0].call_data = ccall;
    legs[0].auth_data = &a;
    legs[1].hdr.domain_id = evm_dom;
    legs[1].hdr.runtime_op = evm_op;
    legs[1].hdr.ruleset_version = NODUS_RT_EVM_RULESET_VERSION_GEVM;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = 1;
    legs[1].hdr.call_len = evm_len;
    legs[1].hdr.auth_len = 1;
    legs[1].call_data = evm_call;
    legs[1].auth_data = &a;
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.res_max_total_units = 1;
    in.leg_count = 2;
    in.legs = legs;
    size_t used = 0;
    if (dna_env_encode(&in, buf, cap, &used) != 0) return -1;
    return dna_env_decode(buf, used, v);
}

static int test_shape(void) {
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "selfcheck (generations 1-3, the D literal)"); OK();
    /* storage reward v1 (main merge order, QEVM first): GEN_STORAGE (4)
     * is built on the EVM generation and is the newest compiled one */
    CHECK(nodus_runtime_generation_count() == NODUS_RT_GEN_STORAGE &&
          NODUS_RT_GEN_STORAGE == NODUS_RT_GEN_EVM + 1u &&
          NODUS_RT_GEN_EVM == 3u && NODUS_RT_GEN_EVM_BASE == NODUS_RT_GEN_2,
          "the EVM generation is 3 on base 2 in this tree"); OK();
    size_t n = 0;
    const nodus_domain_runtime_t *g3 =
        nodus_runtime_generation_table(NODUS_RT_GEN_EVM, &n);
    CHECK(g3 && n == 3 && g3[0].domain_id == DNA_DOMAIN_SYSTEM &&
          g3[1].domain_id == DNA_DOMAIN_CORE &&
          g3[2].domain_id == DNA_DOMAIN_EVM, "the EVM slice"); OK();
    CHECK(g3[0].ruleset_version == 8 && g3[1].ruleset_version == 6 &&
          g3[2].ruleset_version == 2, "SYSTEM v8 / CORE v6 / EVM v2"); OK();
    CHECK(g3[1].descriptor.rule_count == 9 &&
          g3[1].descriptor.rule_ids[8] == DNA_CORERULE_EVMFUND,
          "CORE owns rule 9"); OK();
    {
        uint64_t w = 0;
        for (uint32_t op = 1; op <= 9; op++)
            CHECK(dna_meter_op_weight(g3[0].meter_policy, op, &w) == 0,
                  "the EVM generation prices ops 1..9");
        CHECK(dna_meter_op_weight(g3[0].meter_policy, 10, &w) != 0,
              "and nothing else"); OK();
    }
    CHECK(g3[2].runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2 &&
          g3[2].exec_evm == nodus_rt_evm_exec &&
          g3[2].prevalidate_evm == nodus_rt_evm_prevalidate &&
          g3[2].allowed_auth_kinds ==
              NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1) &&
          nodus_runtime_hooks_check(&g3[2]) == 0, "the EVM entry"); OK();
    {
        nodus_domain_runtime_t tb;
        CHECK(nodus_rt_evm_runtime_build(&tb) == 0 &&
              memcmp(tb.ruleset_hash, g3[2].ruleset_hash, 64) == 0 &&
              tb.ruleset_version == g3[2].ruleset_version,
              "the test builder resolves to the production tuple"); OK();
        nodus_domain_runtime_t bad = tb;
        bad.prevalidate_evm = NULL;
        CHECK(nodus_runtime_hooks_check(&bad) != 0,
              "ABI 2 without prevalidate_evm is broken"); OK();
        bad = g3[1];
        bad.prevalidate_evm = nodus_rt_evm_prevalidate;
        CHECK(nodus_runtime_hooks_check(&bad) != 0,
              "ABI 1 with prevalidate_evm is broken"); OK();
    }
    {
        uint64_t d = 0;
        dna_domain_manifest_t m;
        uint8_t er[64];
        CHECK(nodus_runtime_evm_activation_digest(&d, &m) == 0 &&
              d == DEVM, "D re-derives from the compiled generation"); OK();
        CHECK(nodus_rt_evm_empty_state_root(er) == 0 &&
              memcmp(m.genesis_state_root, er, 64) == 0 &&
              m.domain_id == DNA_DOMAIN_EVM && m.quota_verify_cost == 0,
              "the D manifest: the empty EVM root, quota 0"); OK();

        /* Kurultay #9 (docs/plans/decisions/2026-10-06-kurultay-9-evm-
         * address-width-summary.md item 2): D commits the address width.
         * The test restates nodus_witness_runtime.c EVM_ACT_CONSTS (file-
         * local) in its order; leg 1 proves the restatement IS the
         * compiled vector (it re-derives DEVM), leg 2 that the width
         * entry changes D — two binaries differing only in width vote
         * different values. */
        uint64_t cv[] = {
            NODUS_RT_EVM_Q, NODUS_RT_EVM_TICKET_GAS, NODUS_RT_EVM_TX_GAS_CAP,
            NODUS_RT_EVM_READS_BASE, NODUS_RT_EVM_MAX_READ_BYTES,
            DNA_METER_EVM_W_GAS, DNA_METER_EVM_FAIL_RESERVE,
            DNA_METER_EVM_FAIL_EFFECTS, DNA_METER_EVM_FAIL_BYTES,
            DNA_METER_STREAM_MAX_EFFECTS, DNA_METER_STREAM_MAX_EFFECT_BYTES,
            NODUS_RT_EVM_BRIDGE_GAS, DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT,
            DNAC_CFG_MIN_EVM_BLOCK_GAS, DNAC_CFG_MAX_EVM_BLOCK_GAS,
            NODUS_RT_EVM_ADDR_BYTES
        };
        const uint32_t ncv = (uint32_t)(sizeof(cv) / sizeof(cv[0]));
        const nodus_domain_runtime_t *rs =
            nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_SYSTEM);
        const nodus_domain_runtime_t *rco =
            nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_CORE);
        const nodus_domain_runtime_t *re =
            nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_EVM);
        uint8_t mh[DNA_DOM_HASH_LEN];
        uint64_t d32 = 0, d20 = 0;
        CHECK(rs && rco && re && dna_domman_hash(&m, mh) == 0, "D inputs");
        CHECK(NODUS_RT_EVM_ADDR_BYTES == 32u && cv[ncv - 1] == 32u,
              "the committed width is the 32 the engine runs with"); OK();
        CHECK(dna_evm_activation_digest(NODUS_RT_GEN_EVM,
                                        NODUS_RT_GEN_EVM_BASE,
                                        rs->ruleset_hash, rco->ruleset_hash,
                                        re->ruleset_hash, mh,
                                        DNAC_EVM_ACTIVATION_SPEC_VERSION,
                                        cv, ncv, &d32) == 0 &&
              d32 == DEVM,
              "the restated constant vector (width last) re-derives D");
        OK();
        cv[ncv - 1] = 20u;
        CHECK(dna_evm_activation_digest(NODUS_RT_GEN_EVM,
                                        NODUS_RT_GEN_EVM_BASE,
                                        rs->ruleset_hash, rco->ruleset_hash,
                                        re->ruleset_hash, mh,
                                        DNAC_EVM_ACTIVATION_SPEC_VERSION,
                                        cv, ncv, &d20) == 0 &&
              d20 != DEVM,
              "a 20-byte width in the vector gives a different D"); OK();
        CHECK(dna_evm_activation_digest(NODUS_RT_GEN_EVM,
                                        NODUS_RT_GEN_EVM_BASE,
                                        rs->ruleset_hash, rco->ruleset_hash,
                                        re->ruleset_hash, mh,
                                        DNAC_EVM_ACTIVATION_SPEC_VERSION,
                                        cv, ncv - 1, &d20) == 0 &&
              d20 != DEVM,
              "a vector WITHOUT the width (the v1 shape) does not give D");
        OK();
    }

    /* the pairing rule (both runtimes apply it) */
    {
        static uint8_t buf[4096];
        dna_env_view_t v;
        uint8_t dep[17];
        enc_deposit(dep, 5, 0);
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_EVMFUND,
                      NODUS_RT_EVMFUND_ROLE_DEPOSIT, DNA_DOMAIN_EVM,
                      NODUS_RT_EVM_DEPOSIT, dep, 17, &v) == 0 &&
              nodus_rt_evm_pair_check(&v) == 0, "a paired DEPOSIT"); OK();
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_EVMFUND,
                      NODUS_RT_EVMFUND_ROLE_FEE, DNA_DOMAIN_EVM,
                      NODUS_RT_EVM_DEPOSIT, dep, 17, &v) == 0 &&
              nodus_rt_evm_pair_check(&v) == -1, "role FEE + DEPOSIT"); OK();
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_SYSFUND,
                      NODUS_RT_EVMFUND_ROLE_DEPOSIT, DNA_DOMAIN_EVM,
                      NODUS_RT_EVM_DEPOSIT, dep, 17, &v) == 0 &&
              nodus_rt_evm_pair_check(&v) == -1, "CORE op 7"); OK();
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_EVMFUND,
                      NODUS_RT_EVMFUND_ROLE_DEPOSIT, 3,
                      NODUS_RT_EVM_DEPOSIT, dep, 17, &v) == 0 &&
              nodus_rt_evm_pair_check(&v) == -1, "domain 3"); OK();
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_EVMFUND,
                      NODUS_RT_EVMFUND_ROLE_DEPOSIT, DNA_DOMAIN_EVM,
                      9, dep, 17, &v) == 0 &&
              nodus_rt_evm_pair_check(&v) == -1, "EVM op 9"); OK();
        v.leg_count = 1;
        CHECK(nodus_rt_evm_pair_check(&v) == -1, "one leg"); OK();

        /* the block-gas share and the conflict keys */
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_EVMFUND,
                      NODUS_RT_EVMFUND_ROLE_DEPOSIT, DNA_DOMAIN_EVM,
                      NODUS_RT_EVM_DEPOSIT, dep, 17, &v) == 0 &&
              nodus_rt_evm_env_block_gas(&v, DNA_DOMAIN_EVM) ==
                  NODUS_RT_EVM_BRIDGE_GAS &&
              nodus_rt_evm_env_block_gas(&v, 5) == 0,
              "a bridge op counts 21 000"); OK();
        uint8_t call[256], to[32];
        memset(to, 0x33, sizeof(to));
        size_t cl = enc_call(call, to, 0, 777777, 4, NULL, 0, NULL, NULL);
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_EVMFUND,
                      NODUS_RT_EVMFUND_ROLE_FEE, DNA_DOMAIN_EVM,
                      NODUS_RT_EVM_CALL, call, (uint32_t)cl, &v) == 0 &&
              nodus_rt_evm_env_block_gas(&v, DNA_DOMAIN_EVM) == 777777,
              "a CALL counts its declared gas"); OK();
        nodus_rt_auth_verdict_t av;
        memset(&av, 0, sizeof(av));
        av.n_signers = 1;
        memset(av.signer_fp[0], 0xAB, 64);
        nodus_rt_v2_keys_t keys;
        CHECK(nodus_rt_evm_conflict_keys(&v, 1, &av, &keys) == 0 &&
              keys.n == 1 &&
              keys.k[0].op_id == NODUS_RT_EVM_KEY_SENDER_NONCE &&
              keys.k[0].key_len == 40 && keys.k[0].key[0] == 0xAB &&
              keys.k[0].key[39] == 4, "(sender32, nonce) key"); OK();
        /* a head that does not decode counts 0 and has no key */
        call[0] = 2;
        CHECK(view_of(buf, sizeof(buf), DNA_CORERULE_EVMFUND,
                      NODUS_RT_EVMFUND_ROLE_FEE, DNA_DOMAIN_EVM,
                      NODUS_RT_EVM_CALL, call, (uint32_t)cl, &v) == 0 &&
              nodus_rt_evm_env_block_gas(&v, DNA_DOMAIN_EVM) == 0 &&
              nodus_rt_evm_conflict_keys(&v, 1, &av, &keys) == -1,
              "wrong ver: no share, no key"); OK();
    }
    return 0;
}

/* ══ 2. the activation edge, the no-vote twin, the edge FAULTs ═══════ */

static int head_of(nodus_witness_t *w, uint32_t dom, uint32_t *rv,
                   uint64_t *dh, uint64_t *lu, uint8_t root[64]) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head, domain_height, "
                           "last_updated_global FROM v2_domain_heads WHERE "
                           "domain_id = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        const uint8_t *h = sqlite3_column_blob(st, 0);
        if (root) memcpy(root, h + 4, 64);
        if (rv) *rv = ((uint32_t)h[84] << 24) | ((uint32_t)h[85] << 16) |
                      ((uint32_t)h[86] << 8) | h[87];
        if (dh) *dh = (uint64_t)sqlite3_column_int64(st, 1);
        if (lu) *lu = (uint64_t)sqlite3_column_int64(st, 2);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

static int upd_at(nodus_witness_t *w, uint64_t gh, uint32_t dom,
                  dna_domain_update_t *u) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT upd FROM v2_domain_updates WHERE "
                           "global_height = ?1 AND domain_id = ?2", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)gh);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        dna_dupd_decode(sqlite3_column_blob(st, 0),
                        (size_t)sqlite3_column_bytes(st, 0), u) == 0)
        ok = 0;
    sqlite3_finalize(st);
    return ok;
}

static int test_edge(void) {
    fixture_t A, B;
    CHECK((HE - 1u) % E_LEN != 0 && (H2 - 1u) % E_LEN != 0,
          "no edge on an epoch boundary in this build");
    CHECK(fx_open(&A, "edgeA", 1, 1) == 0, "A: EVM vote at HE"); OK();
    CHECK(fx_open(&B, "edgeB", 1, 0) == 0, "B: no EVM vote"); OK();
    {
        uint32_t ver = 0;
        CHECK(nodus_witness_db_schema_version(A.w, &ver) == 0 &&
              ver == NODUS_V2_SCHEMA_VERSION_S17,
              "the reopened seeded chain is S17 (the at-open rung)"); OK();
    }

    /* heights 1..3: the twins agree on everything the vote row is not */
    for (uint64_t h = 1; h <= HE - 2u; h++) {
        CHECK(fx_to(&A, h + 1) == 0 && fx_to(&B, h + 1) == 0,
              "idle block on both");
        uint8_t ca[64], cb[64];
        CHECK(core_root_now(A.w, ca) == 0 && core_root_now(B.w, cb) == 0 &&
              memcmp(ca, cb, 64) == 0, "CORE roots equal before the edge");
        /* The REGISTRY ROOT is not compared: SYSTEM's genesis manifest
         * binds genesis_state_root = the SYSTEM payload root
         * (nodus_witness_domreg.c:338 → nodus_witness_runtime.c:1470),
         * which includes the chain_config root (nodus_witness_roots_v2.c
         * :524) — and this fixture writes A's vote row BEFORE genesis, so
         * the two SYSTEM manifests differ by construction (a fixture
         * artefact: a live vote lands after genesis). What MUST hold: the
         * CORE registry records are byte-equal, and the SYSTEM manifests
         * are equal in every field but genesis_state_root. */
        {
            dna_domreg_record_t rca, rcb;
            dna_domain_manifest_t msa, msb, mca, mcb;
            CHECK(nodus_witness_domreg_get(A.w, DNA_DOMAIN_CORE, &rca, &mca,
                                           NULL) == 0 &&
                  nodus_witness_domreg_get(B.w, DNA_DOMAIN_CORE, &rcb, &mcb,
                                           NULL) == 0 &&
                  memcmp(&rca, &rcb, sizeof(rca)) == 0,
                  "CORE registry records equal");
            CHECK(nodus_witness_domreg_get(A.w, DNA_DOMAIN_SYSTEM, NULL,
                                           &msa, NULL) == 0 &&
                  nodus_witness_domreg_get(B.w, DNA_DOMAIN_SYSTEM, NULL,
                                           &msb, NULL) == 0 &&
                  memcmp(msa.genesis_state_root, msb.genesis_state_root, 64)
                      != 0, "SYSTEM genesis roots differ (the vote row)");
            uint8_t ha[64], hb[64];
            memcpy(msa.genesis_state_root, msb.genesis_state_root, 64);
            CHECK(dna_domman_hash(&msa, ha) == 0 &&
                  dna_domman_hash(&msb, hb) == 0 && memcmp(ha, hb, 64) == 0,
                  "SYSTEM manifests equal but for genesis_state_root");
        }
        uint32_t ra = 0, rb = 0;
        CHECK(head_of(A.w, DNA_DOMAIN_CORE, &ra, NULL, NULL, NULL) == 0 &&
              head_of(B.w, DNA_DOMAIN_CORE, &rb, NULL, NULL, NULL) == 0 &&
              ra == rb, "CORE head versions equal");
        CHECK(q1(A.w, "SELECT COUNT(*) FROM domain_registry") == 2,
              "no EVM record before the edge");
        CHECK(roots_ok(A.w) == 0 && roots_ok(B.w) == 0,
              "committed == recomputed");
    }
    OK();

    /* before the edge an EVM leg is a CONTEXT refusal */
    {
        uint8_t call[32];
        size_t cl = enc_deposit(call, 5, 0);
        tx_t t;
        CHECK(evm_tx(&A, 0, NODUS_RT_EVM_DEPOSIT, call, (uint32_t)cl, &t)
                  == 0, "env");
        /* the next block (HE-1) IS the edge block — so the pre-edge
         * refusal is observed through the dry run against tip HE-2 (no
         * height consumed) */
        nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
        char why[256];
        CHECK(d && nodus_witness_v2_env_dry_run(A.w, t.bytes, t.len, NULL, d,
                                               why, sizeof why) == -1 &&
              d->code == NODUS_V2_TX_ERR_CONTEXT,
              "an EVM leg before the edge: CONTEXT"); OK();
        nodus_witness_v2_env_dry_run_free(d);
        free(d);
        tx_free(&t);
    }

    /* block HE-1: THE EDGE (A); idle (B) */
    uint8_t core_pre[64];
    CHECK(core_root_now(A.w, core_pre) == 0, "CORE root before the edge");
    CHECK(fx_to(&A, HE) == 0 && fx_to(&B, HE) == 0, "the edge block");
    {
        dna_domreg_record_t r;
        dna_domain_manifest_t m, want;
        uint64_t d = 0;
        CHECK(nodus_witness_domreg_get(A.w, DNA_DOMAIN_EVM, &r, &m, NULL)
                  == 0 && r.status == DNA_DOMST_ACTIVE,
              "the EVM record is ACTIVE"); OK();
        CHECK(nodus_runtime_evm_activation_digest(&d, &want) == 0, "want");
        uint8_t h1[64], h2[64];
        CHECK(dna_domman_hash(&m, h1) == 0 && dna_domman_hash(&want, h2) == 0
              && memcmp(h1, h2, 64) == 0,
              "its manifest is the one the D literal hashed"); OK();
        dna_domain_manifest_t ms, mc;
        CHECK(nodus_witness_domreg_get(A.w, DNA_DOMAIN_SYSTEM, NULL, &ms,
                                       NULL) == 0 &&
              nodus_witness_domreg_get(A.w, DNA_DOMAIN_CORE, NULL, &mc, NULL)
                  == 0 && ms.ruleset_version == 8 && mc.ruleset_version == 6
              && memcmp(ms.ruleset_hash, gevm(DNA_DOMAIN_SYSTEM)->ruleset_hash,
                        64) == 0 &&
              memcmp(mc.ruleset_hash, gevm(DNA_DOMAIN_CORE)->ruleset_hash, 64)
                  == 0, "SYSTEM v8 / CORE v6"); OK();
        uint32_t rv = 0;
        uint64_t dh = 1, lu = 0;
        uint8_t hr[64], er[64];
        CHECK(head_of(A.w, DNA_DOMAIN_EVM, &rv, &dh, &lu, hr) == 0 &&
              rv == NODUS_RT_EVM_RULESET_VERSION_GEVM && dh == 0 &&
              lu == HE - 1u &&
              nodus_rt_evm_empty_state_root(er) == 0 &&
              memcmp(hr, er, 64) == 0,
              "the EVM head: v2, height 0, at HE-1, the empty root"); OK();
        CHECK(q1(A.w, "SELECT COUNT(*) FROM evm_meta") == 1 &&
              reserve_of(A.w) == 0, "empty META, reserve 0"); OK();
        dna_domain_update_t uc, us;
        CHECK(upd_at(A.w, HE - 1u, DNA_DOMAIN_CORE, &uc) == 0 &&
              upd_at(A.w, HE - 1u, DNA_DOMAIN_SYSTEM, &us) == 0 &&
              memcmp(uc.pre_root, uc.post_root, 64) != 0 &&
              memcmp(us.pre_root, us.post_root, 64) != 0 &&
              uc.ruleset_version == 6 && us.ruleset_version == 8,
              "CORE and SYSTEM updated at the edge; CORE's root moved"); OK();
        dna_domain_update_t ue;
        CHECK(upd_at(A.w, HE - 1u, DNA_DOMAIN_EVM, &ue) != 0,
              "the activated EVM domain writes no update"); OK();
        uint8_t cn[64], c2[64], c3[64];
        CHECK(core_root_now(A.w, cn) == 0 &&
              nodus_witness_core_root_v2_evm(A.w, c3) == 0 &&
              nodus_witness_core_root_v2(A.w, c2) == 0 &&
              memcmp(cn, c3, 64) == 0 && memcmp(cn, c2, 64) != 0 &&
              memcmp(c2, core_pre, 64) == 0,
              "CORE root = the reserved formula; the old formula of the same "
              "state = the pre-edge root"); OK();
        const nodus_domain_runtime_t *re = NULL;
        CHECK(nodus_witness_v2_runtime_for(A.w, DNA_DOMAIN_EVM, 1, &re) == 0
              && re == gevm(DNA_DOMAIN_EVM), "the EVM runtime resolves"); OK();
        CHECK(roots_ok(A.w) == 0 && invariants_ok(A.w),
              "committed == recomputed; both invariants"); OK();
    }
    {
        dna_domain_manifest_t mc;
        CHECK(nodus_witness_domreg_get(B.w, DNA_DOMAIN_EVM, NULL, NULL, NULL)
                  == 1 &&
              nodus_witness_domreg_get(B.w, DNA_DOMAIN_CORE, NULL, &mc, NULL)
                  == 0 && mc.ruleset_version == 5,
              "the twin stays generation 2 without the EVM domain"); OK();
    }
    /* block HE: no second edge */
    {
        uint8_t r0[64], r1[64];
        CHECK(nodus_witness_domreg_root(A.w, r0) == 0, "registry before");
        CHECK(fx_to(&A, HE + 1u) == 0, "block HE applies");
        CHECK(nodus_witness_domreg_root(A.w, r1) == 0 &&
              memcmp(r0, r1, 64) == 0, "no second edge"); OK();
    }
    fx_close(&A);
    fx_close(&B);

    /* FAULT: the EVM vote's edge with the registry not at the base
     * generation (no generation-2 vote) */
    {
        fixture_t F;
        CHECK(fx_open(&F, "edgeF1", 0, 1) == 0, "EVM vote, no gen-2 vote");
        CHECK(fx_to(&F, HE - 1u) == 0, "blocks before the edge");
        nodus_v2_block_t b;
        mk_block(&b, HE - 1u, NULL, 0);
        CHECK(v2x_cmt_fault(F.w, &b) == 0,
              "the edge FAULTs, the database byte-unchanged"); OK();
        fx_close(&F);
    }
    /* FAULT: the edge below S17 */
    {
        fixture_t F;
        CHECK(fx_open(&F, "edgeF2", 1, 1) == 0, "both votes");
        CHECK(sqlite3_exec(F.w->db, "PRAGMA user_version = 16", NULL, NULL,
                           NULL) == SQLITE_OK, "S16");
        CHECK(fx_to(&F, HE - 1u) == 0, "S16 applies before the edge");
        nodus_v2_block_t b;
        mk_block(&b, HE - 1u, NULL, 0);
        CHECK(v2x_cmt_fault(F.w, &b) == 0, "the edge below S17 FAULTs");
        OK();
        fx_close(&F);
    }
    return 0;
}

/* ══ 3. the vote rules ════════════════════════════════════════════════ */

static int test_vote_rules(void) {
    /* ok_eff - 1 off-boundary (k × E_LEN + 4, 4 < E_LEN), and at or above
     * the first-window floor initial (1) + 256 of red-team 1 F5 (g) —
     * k = 2 at the production 720, larger for a short test epoch */
    uint64_t ok_k = 2u;
    while (ok_k * E_LEN + 5u < 257u) ok_k++;
    const uint64_t ok_eff = ok_k * E_LEN + 5u;
    nodus_cc_state_facts_t f;
    memset(&f, 0, sizeof(f));
    f.hf2_active = 1;
    f.hf3_active = 1;
    f.gas_price_on = 1;
    f.judging_generation = NODUS_RT_GEN_EVM_BASE;
    f.chain_initial_height = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &f) == 0,
          "every prerequisite met: legal"); OK();
    nodus_cc_state_facts_t g;
    /* red-team 1 F5 (g): the first execution window [eff-256, eff-1] lies
     * on the chain — eff >= initial + 256; off-boundary values chosen so
     * rule (f) never decides (E_LEN > 64, checked by main) */
    g = f; g.chain_initial_height = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(14, 256, &g) == -1 &&
          nodus_chain_config_stateful_rules_ex(14, 257, &g) ==
              (((256u % E_LEN) == 0) ? -1 : 0),
          "initial 1: effective 256 refused (window reaches height 0), "
          "257 legal"); OK();
    g = f; g.chain_initial_height = 100;
    CHECK(nodus_chain_config_stateful_rules_ex(14, 355, &g) == -1 &&
          nodus_chain_config_stateful_rules_ex(14, 356, &g) ==
              (((355u % E_LEN) == 0) ? -1 : 0),
          "initial 100: 355 refused, 356 legal"); OK();
    g = f; g.chain_initial_height = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "an underived initial height (0) refuses — fail closed"); OK();
    g = f; g.chain_initial_height = UINT64_MAX - 10u;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "initial + 256 overflowing u64 refuses"); OK();
    g = f; g.chain_initial_height = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(9, ok_eff, &g) ==
              nodus_chain_config_stateful_rules(9, ok_eff, 1, 0,
                                                NODUS_RT_GEN_EVM_BASE),
          "param 9 never reads the initial height"); OK();
    g = f; g.evm_active_voted = 1;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "a second vote"); OK();
    g = f; g.hf2_active = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "HF-2 off"); OK();
    g = f; g.hf3_active = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "HF-3 off"); OK();
    g = f; g.gas_price_on = 0;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "a zero gas price"); OK();
    g = f; g.judging_generation = NODUS_RT_GEN_1;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "the registry at generation 1"); OK();
    g = f; g.judging_generation = NODUS_RT_GEN_EVM;
    CHECK(nodus_chain_config_stateful_rules_ex(14, ok_eff, &g) == -1,
          "the registry already at the EVM generation"); OK();
    CHECK(nodus_chain_config_stateful_rules_ex(14, E_LEN + 1u, &f) == -1 &&
          nodus_chain_config_stateful_rules_ex(14, 0, &f) == -1,
          "H-1 on an epoch boundary / H = 0"); OK();
    CHECK(nodus_chain_config_stateful_rules_ex(15, ok_eff, &g) == 0 &&
          nodus_chain_config_stateful_rules_ex(16, ok_eff, &f) == -1,
          "param 15 has no stateful rule; 16 is unknown"); OK();
    CHECK(nodus_chain_config_stateful_rules(14, ok_eff, 1, 0, 2) == -1,
          "the 5-argument form refuses EVM_ACTIVE (no HF-3 fact)"); OK();
    /* ids 1..13 answer as before through _ex (spot: param 9) */
    g = f; g.judging_generation = NODUS_RT_GEN_1;
    CHECK(nodus_chain_config_stateful_rules_ex(9, ok_eff, &g) ==
              nodus_chain_config_stateful_rules(9, ok_eff, 1, 0, 1),
          "param 9 unchanged"); OK();

    /* scalar rules */
    CHECK(nodus_chain_config_scalar_rules(14, DEVM, 1, ok_eff + 10, ok_eff,
                                          1) == 0 &&
          nodus_chain_config_scalar_rules(14, DEVM + 1u, 1, ok_eff + 10,
                                          ok_eff, 1) == -1 &&
          nodus_chain_config_scalar_rules(14, 0, 1, ok_eff + 10, ok_eff,
                                          1) == -1,
          "EVM_ACTIVE: exactly D"); OK();
    CHECK(nodus_chain_config_scalar_rules(15, DNAC_CFG_MIN_EVM_BLOCK_GAS, 1,
                                          ok_eff + 10, ok_eff, 1) == 0 &&
          nodus_chain_config_scalar_rules(15, DNAC_CFG_MAX_EVM_BLOCK_GAS, 1,
                                          ok_eff + 10, ok_eff, 1) == 0 &&
          nodus_chain_config_scalar_rules(15, DNAC_CFG_MIN_EVM_BLOCK_GAS - 1,
                                          1, ok_eff + 10, ok_eff, 1) == -1 &&
          nodus_chain_config_scalar_rules(15, DNAC_CFG_MAX_EVM_BLOCK_GAS + 1,
                                          1, ok_eff + 10, ok_eff, 1) == -1,
          "EVM_BLOCK_GAS_LIMIT range"); OK();
    CHECK(nodus_chain_config_scalar_rules(16, 1, 1, ok_eff + 10, ok_eff, 1)
              == -1, "id 16 unknown"); OK();
    CHECK(nodus_chain_config_grace_for_param(14) ==
              (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS &&
          nodus_chain_config_grace_for_param(15) ==
              (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS,
          "SAFETY grace"); OK();
    return 0;
}

/* ══ 4. execution ═════════════════════════════════════════════════════ */

static int test_exec(void) {
    fixture_t fx;
    /* EVM_BLOCK_GAS_LIMIT voted to 2 × the per-tx cap: at the default
     * limit (DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT == NODUS_RT_EVM_TX_GAS_CAP)
     * a CALL over the per-tx cap is over the BLOCK limit too and phase 0c
     * FAULTs its block before the item is judged — the per-tx refusal is
     * reachable only where the block limit exceeds the cap (section 7
     * asserts the default-limit behaviour). */
    CHECK(fx_evm_ready_gas(&fx, "exec", 2u * NODUS_RT_EVM_TX_GAS_CAP) == 0,
          "EVM chain"); OK();
    const int A = 0;
    const uint8_t *sa = sender_of(A);
    uint64_t na = 0;

    uint8_t store[32], rev[32], five[32], sloads[32];
    uint64_t pool0 = pool_of(fx.w);
    CHECK(deploy(&fx, A, na++, RT_STORE, sizeof(RT_STORE), store) == 0,
          "deploy STORE"); OK();
    CHECK(pool_of(fx.w) == pool0 + FEE,
          "the CREATE's fee went to the reward pool (no burn)"); OK();
    CHECK(deploy(&fx, A, na++, RT_REVERT, sizeof(RT_REVERT), rev) == 0 &&
          deploy(&fx, A, na++, RT_FIVE, sizeof(RT_FIVE), five) == 0 &&
          deploy(&fx, A, na++, RT_SLOADS, sizeof(RT_SLOADS), sloads) == 0,
          "deploy REVERT, FIVE, SLOADS"); OK();
    CHECK(acct_nonce(fx.w, sa) == na, "deployer nonce"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_code_refs") == 4 &&
          q1(fx.w, "SELECT COUNT(*) FROM evm_code") == 4, "code stored");
    OK();
    CHECK(invariants_ok(fx.w), "invariants"); OK();

    /* CALL STORE(7, 0x2a) beside a CORE SPEND in one block: the EVM item
     * carries Data (64 B), the SPEND item none */
    {
        uint8_t data[64] = { 0 }, call[256], key7[32] = { 0 };
        data[31] = 7;
        data[63] = 0x2a;
        key7[31] = 7;
        size_t cl = enc_call(call, store, 0, 100000, na, data, 64, store,
                             key7);
        tx_t t[2];
        CHECK(spend_tx(&fx, 1, &t[0]) == 0 &&
              evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t[1])
                  == 0, "envs");
        nodus_v2_tx_result_t r[2];
        uint64_t h = fx.h;
        uint64_t p0 = pool_of(fx.w);
        CHECK(apply_txs(&fx, t, 2, r) == 0 &&
              r[0].code == NODUS_V2_TX_OK && r[1].code == NODUS_V2_TX_OK,
              "both applied"); OK();
        CHECK(r[0].data_len == 0 && r[1].data_len == 64,
              "Data on the EVM item only"); OK();
        CHECK(pool_of(fx.w) == p0 + 2u * FEE, "two fees to the pool"); OK();
        uint8_t rc[4096], dg[64], mine[64];
        size_t rl = 0;
        CHECK(receipt_of(fx.w, h, 1, rc, sizeof(rc), &rl, dg) == 0 &&
              qgp_sha3_512(rc, rl, mine) == 0 && memcmp(mine, dg, 64) == 0 &&
              memcmp(r[1].data, dg, 64) == 0, "Data = SHA3-512(receipt)");
        OK();
        CHECK(rc[16] == 1 && rc[17] == NODUS_RT_EVM_CALL, "status/op"); OK();
        na++;
        CHECK(slot_lo(fx.w, store, 7) == 0x2a && acct_nonce(fx.w, sa) == na &&
              coin_live(fx.w, t[1].coin) == 0, "slot, nonce, coin spent");
        OK();
        tx_free(&t[0]);
        tx_free(&t[1]);
    }

    /* red-team 1 F12 — the simulation's PRE-refund work counter: a CALL
     * that CLEARS slot 7 (0x2a → 0) earns the EIP-3529 clear refund
     * (evm_interp.c SSTORE: orig != 0, cur != 0, new == 0 → +4800), so
     * the engine's pre-refund work (what the §18 budget charges) is
     * strictly above the refunded figure, while the receipt-facing
     * gas_used stays the engine's refunded figure; a CALL that SETS a
     * fresh slot earns no refund and its work equals its gas. */
    {
        const nodus_domain_runtime_t *ert = NULL;
        uint8_t chain32[32];
        uint64_t gas_lim = 0;
        char why[160];
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_EVM, 1, &ert) == 0 &&
              ert && nodus_witness_v2_chain_id(fx.w, chain32) == 0 &&
              nodus_witness_v2_evm_block_gas_limit(fx.w, fx.h, &gas_lim, why,
                                                   sizeof(why)) == 0,
              "the simulation environment"); OK();
        uint8_t data[64] = { 0 };
        data[31] = 7;                       /* STORE(7, 0): a clear      */
        nodus_rt_evm_sim_req_t rq;
        memset(&rq, 0, sizeof(rq));
        rq.from = sa;
        rq.to = store;
        rq.data = data;
        rq.data_len = 64;
        rq.gas_limit = 100000;
        rq.chain_id = chain32;
        rq.global_height = fx.h;
        rq.evm_block_gas_limit = gas_lim;
        nodus_rt_evm_sim_res_t r;
        CHECK(nodus_rt_evm_simulate(ert, fx.w, &rq, &r) == 0 && r.executed &&
              r.success == 1, "the clearing CALL simulates"); OK();
        CHECK(r.engine_work_gas > r.engine_gas_used &&
              r.gas_used == r.engine_gas_used,
              "pre-refund work above the refunded gas; the receipt figure "
              "is the refunded one"); OK();
        nodus_rt_evm_sim_res_free(&r);
        data[31] = 8;                       /* STORE(8, 1): a fresh set  */
        data[63] = 1;
        CHECK(nodus_rt_evm_simulate(ert, fx.w, &rq, &r) == 0 && r.executed &&
              r.success == 1 && r.engine_work_gas == r.engine_gas_used &&
              r.engine_work_gas > 0,
              "no refund: the work equals the gas"); OK();
        nodus_rt_evm_sim_res_free(&r);
        CHECK(slot_lo(fx.w, store, 7) == 0x2a && slot_lo(fx.w, store, 8) == 0,
              "a simulation writes nothing"); OK();
    }

    /* REVERT: applied, pays, nonce + 1, nothing else moves */
    {
        uint8_t call[256];
        size_t cl = enc_call(call, rev, 0, 50000, na, NULL, 0, NULL, NULL);
        tx_t t;
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0,
              "env");
        uint64_t h = fx.h, p0 = pool_of(fx.w);
        nodus_v2_tx_result_t r;
        CHECK(apply_one(&fx, &t, &r) == NODUS_V2_TX_OK, "REVERT applied");
        na++;
        CHECK(acct_nonce(fx.w, sa) == na && pool_of(fx.w) == p0 + FEE &&
              coin_live(fx.w, t.coin) == 0,
              "REVERT: nonce + 1, the fee paid"); OK();
        uint8_t rc[4096], dg[64];
        size_t rl = 0;
        CHECK(receipt_of(fx.w, h, 0, rc, sizeof(rc), &rl, dg) == 0 &&
              rc[16] == 0 && rcpt_gas(rc) == 50000 && r.data_len == 64 &&
              memcmp(r.data, dg, 64) == 0,
              "REVERT receipt: status 0, gas = gas_limit"); OK();
        CHECK(r.gas_used > 50000, "REVERT consumed the gas units"); OK();
        tx_free(&t);
    }

    /* OUT OF GAS: applied, nonce + 1, the slot NOT written */
    {
        uint8_t data[64] = { 0 }, call[256];
        data[31] = 9;
        data[63] = 1;
        size_t cl = enc_call(call, store, 0, 30000, na, data, 64, NULL, NULL);
        tx_t t;
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0,
              "env");
        uint64_t h = fx.h;
        CHECK(apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "OOG applied");
        na++;
        CHECK(acct_nonce(fx.w, sa) == na && slot_lo(fx.w, store, 9) == 0,
              "OOG: nonce + 1, storage unchanged"); OK();
        uint8_t rc[4096], dg[64];
        size_t rl = 0;
        CHECK(receipt_of(fx.w, h, 0, rc, sizeof(rc), &rl, dg) == 0 &&
              rc[16] == 0 && rcpt_gas(rc) == 30000, "OOG receipt"); OK();
        tx_free(&t);
    }

    /* OVER-CEILING STREAM (design §4 N2): 7 effects against a declared
     * res_max_effects of 2 — the failure path, decided before any page */
    {
        uint8_t call[256];
        size_t cl = enc_call(call, five, 0, 200000, na, NULL, 0, NULL, NULL);
        spec_t s;
        memset(&s, 0, sizeof(s));
        s.key = A; s.with_core = 1; s.with_evm = 1;
        s.evm_op = NODUS_RT_EVM_CALL; s.call = call; s.call_len = (uint32_t)cl;
        s.evm_eff = 2; s.evm_bytes = 4096;
        tx_t t;
        CHECK(build_tx(&fx, &s, &t) == 0, "env");
        uint64_t h = fx.h;
        CHECK(apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK,
              "over-ceiling applied");
        na++;
        CHECK(acct_nonce(fx.w, sa) == na && slot_lo(fx.w, five, 1) == 0 &&
              slot_lo(fx.w, five, 5) == 0,
              "over-ceiling: nonce + 1, no slot"); OK();
        uint8_t rc[4096], dg[64];
        size_t rl = 0;
        CHECK(receipt_of(fx.w, h, 0, rc, sizeof(rc), &rl, dg) == 0 &&
              rc[16] == 0 && rcpt_gas(rc) == 200000,
              "over-ceiling receipt"); OK();
        tx_free(&t);
    }

    /* READ-BUDGET EXHAUSTION (design §3): the ceiling is EXACTLY static +
     * gas + FAIL_RESERVE and both legs declare their exact effects, so the
     * EVM reads may spend only its declared effect reservation (~300
     * units): 400 cold SLOADs hit BUDGET inside execution — APPLIED */
    {
        uint8_t call[256];
        const uint64_t gas = 1000000;
        size_t cl = enc_call(call, sloads, 0, gas, na, NULL, 0, NULL, NULL);
        spec_t s;
        memset(&s, 0, sizeof(s));
        s.key = A; s.with_core = 1; s.with_evm = 1;
        s.evm_op = NODUS_RT_EVM_CALL; s.call = call; s.call_len = (uint32_t)cl;
        s.evm_eff = 1; s.evm_bytes = 300; s.exact = 1;
        tx_t t;
        CHECK(build_tx(&fx, &s, &t) == 0, "env");
        uint64_t h = fx.h;
        nodus_v2_tx_result_t r;
        CHECK(apply_one(&fx, &t, &r) == NODUS_V2_TX_OK,
              "budget exhaustion applied");
        na++;
        CHECK(acct_nonce(fx.w, sa) == na, "budget: nonce + 1"); OK();
        uint8_t rc[4096], dg[64];
        size_t rl = 0;
        CHECK(receipt_of(fx.w, h, 0, rc, sizeof(rc), &rl, dg) == 0 &&
              rc[16] == 0 && rcpt_gas(rc) == gas, "budget receipt"); OK();
        CHECK(r.gas_used <= r.gas_wanted, "budget: within the reservation");
        OK();
        tx_free(&t);
        /* one unit below the units inequality: refused BEFORE execution */
        cl = enc_call(call, sloads, 0, gas, na, NULL, 0, NULL, NULL);
        s.call_len = (uint32_t)cl;
        s.delta = -1;
        CHECK(build_tx(&fx, &s, &t) == 0, "env2");
        uint32_t code = 0;
        CHECK(refused_one(&fx, &t, &code) == 0 &&
              code == NODUS_V2_TX_ERR_EXEC && coin_live(fx.w, t.coin) == 1,
              "gas units unpriced: refused, the coin kept"); OK();
        tx_free(&t);
    }

    /* PRE-EXECUTION REFUSALS — item refusals, the ledger unchanged */
    {
        uint8_t data[64] = { 0 }, call[256];
        uint32_t code = 0;
        tx_t t;
        size_t cl = enc_call(call, store, 0, 100000, na + 5, data, 64, NULL,
                             NULL);
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0
              && refused_one(&fx, &t, &code) == 0 &&
              code == NODUS_V2_TX_ERR_EXEC, "wrong nonce refused"); OK();
        tx_free(&t);

        cl = enc_call(call, store, 0, 100000, na, data, 64, NULL, NULL);
        call[cl] = 0xEE;                         /* one trailing byte     */
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl + 1, &t)
                  == 0 && refused_one(&fx, &t, &code) == 0 &&
              code == NODUS_V2_TX_ERR_EXEC, "trailing byte refused"); OK();
        tx_free(&t);

        cl = enc_call(call, store, 0, NODUS_RT_EVM_TX_GAS_CAP + 1, na, data,
                      64, NULL, NULL);
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0
              && refused_one(&fx, &t, &code) == 0 &&
              code == NODUS_V2_TX_ERR_EXEC, "gas above the cap"); OK();
        tx_free(&t);

        /* declared effect bytes too small to carry the 287-byte failure
         * result: refused before execution (a failure must be payable) */
        cl = enc_call(call, store, 0, 100000, na, data, 64, NULL, NULL);
        spec_t s;
        memset(&s, 0, sizeof(s));
        s.key = A; s.with_core = 1; s.with_evm = 1;
        s.evm_op = NODUS_RT_EVM_CALL; s.call = call; s.call_len = (uint32_t)cl;
        s.evm_eff = EVM_MAXEFF; s.evm_bytes = DNA_METER_EVM_FAIL_BYTES - 1;
        CHECK(build_tx(&fx, &s, &t) == 0 && refused_one(&fx, &t, &code) == 0
              && code == NODUS_V2_TX_ERR_EXEC, "unpayable failure refused");
        OK();
        tx_free(&t);
    }
    CHECK(invariants_ok(fx.w) && roots_ok(fx.w) == 0, "invariants, roots");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══ 5. bridge ════════════════════════════════════════════════════════ */

static int deposit_tx(fixture_t *fx, int k, uint64_t amount, uint64_t nonce,
                      tx_t *t) {
    uint8_t call[32];
    size_t cl = enc_deposit(call, amount, nonce);
    spec_t s;
    memset(&s, 0, sizeof(s));
    s.key = k; s.with_core = 1; s.with_evm = 1; s.big = 1; s.lock = amount;
    s.evm_op = NODUS_RT_EVM_DEPOSIT; s.call = call; s.call_len = (uint32_t)cl;
    return build_tx(fx, &s, t);
}

static int test_bridge(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "bridge") == 0, "EVM chain"); OK();
    const int B = 0, R = 1, X = 2;
    const uint8_t *sb = sender_of(B);
    uint64_t nb = 0;
    uint8_t call[512];
    size_t cl;
    uint32_t code = 0;
    tx_t t;

    /* refusals first: zero amount, wrong nonce, overdraw — the CORE half
     * is rolled back with the EVM half (atomic principal) */
    CHECK(deposit_tx(&fx, B, 0, nb, &t) == 0 &&
          refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC,
          "zero deposit refused"); OK();
    tx_free(&t);
    CHECK(deposit_tx(&fx, B, 5, nb + 1, &t) == 0 &&
          refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC &&
          coin_live(fx.w, t.coin) == 1 && reserve_of(fx.w) == 0,
          "wrong-nonce deposit refused, coin and reserve untouched"); OK();
    tx_free(&t);
    cl = enc_withdraw(call, 1, nb, g_k[R].fp);
    CHECK(evm_tx(&fx, B, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &t) == 0
          && refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC,
          "overdraw refused"); OK();
    tx_free(&t);
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_accounts") == 0,
          "refusals left no account"); OK();

    /* DEPOSIT 10 raw: coin (FEE + 1000) → change 990 + reserve 10 + fee */
    uint64_t p0 = pool_of(fx.w);
    CHECK(deposit_tx(&fx, B, 10, nb, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "deposit"); OK();
    nb++;
    CHECK(coin_live(fx.w, t.coin) == 0 && owned_with(fx.w, B, 990) == 1 &&
          reserve_of(fx.w) == 10 && pool_of(fx.w) == p0 + FEE,
          "CORE: the coin spent, change 990, reserve 10, the fee pooled");
    OK();
    CHECK(acct_balance_lo(fx.w, sb) == 10ull * Q && acct_nonce(fx.w, sb) == nb,
          "EVM: balance 10 q, nonce 1"); OK();
    CHECK(invariants_ok(fx.w) && roots_ok(fx.w) == 0,
          "both invariants after the deposit"); OK();
    tx_free(&t);

    /* WITHDRAW 3 raw to key R (an explicit recipient) */
    p0 = pool_of(fx.w);
    cl = enc_withdraw(call, 3, nb, g_k[R].fp);
    CHECK(evm_tx(&fx, B, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &t) == 0
          && apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "withdraw"); OK();
    nb++;
    CHECK(owned_with(fx.w, R, 3) == 1 && reserve_of(fx.w) == 7 &&
          pool_of(fx.w) == p0 + FEE &&
          acct_balance_lo(fx.w, sb) == 7ull * Q,
          "a UTXO of 3 to R, reserve 7, balance 7 q, the fee pooled"); OK();
    CHECK(invariants_ok(fx.w), "invariants after the withdraw"); OK();
    tx_free(&t);

    /* a contract opens a ticket of 2 raw for R */
    CHECK(rt_ticket_build() == 0, "ticket contract");
    uint8_t tc[32];
    CHECK(deploy(&fx, B, nb++, g_rt_ticket, g_rt_ticket_len, tc) == 0,
          "deploy TICKET"); OK();
    cl = enc_call(call, tc, 2ull * Q, 200000, nb, g_k[R].fp, 64, NULL, NULL);
    CHECK(evm_tx(&fx, B, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "open ticket"); OK();
    nb++;
    tx_free(&t);
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_tickets") == 1 &&
          q1(fx.w, "SELECT amount_raw FROM evm_tickets") == 2 &&
          acct_balance_lo(fx.w, sb) == 5ull * Q && reserve_of(fx.w) == 7,
          "ticket row; the caller debited; the reserve still 7"); OK();
    CHECK(invariants_ok(fx.w), "invariants after the ticket"); OK();

    uint8_t tid[64];
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT ticket_id FROM evm_tickets", -1, &st, NULL)
                  == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == 64, "ticket id");
        memcpy(tid, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
    }
    /* REDEEM names the ticket EXACTLY: a wrong amount is refused — the
     * CORE release in the same item rolls back with it */
    cl = enc_redeem(call, tid, 3, g_k[R].fp);
    CHECK(evm_tx(&fx, X, NODUS_RT_EVM_REDEEM, call, (uint32_t)cl, &t) == 0 &&
          refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC &&
          owned_with(fx.w, R, 3) == 1, "wrong amount refused"); OK();
    tx_free(&t);
    /* a wrong recipient is refused too */
    cl = enc_redeem(call, tid, 2, g_k[X].fp);
    CHECK(evm_tx(&fx, X, NODUS_RT_EVM_REDEEM, call, (uint32_t)cl, &t) == 0 &&
          refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC,
          "wrong recipient refused"); OK();
    tx_free(&t);
    /* key X (neither owner nor recipient) redeems for R */
    cl = enc_redeem(call, tid, 2, g_k[R].fp);
    CHECK(evm_tx(&fx, X, NODUS_RT_EVM_REDEEM, call, (uint32_t)cl, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "redeem"); OK();
    tx_free(&t);
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_tickets") == 0 &&
          owned_with(fx.w, R, 2) == 1 && reserve_of(fx.w) == 5,
          "ticket consumed; a UTXO of 2 to R; reserve 5"); OK();
    CHECK(invariants_ok(fx.w) && roots_ok(fx.w) == 0,
          "invariants after the redeem"); OK();
    /* a SECOND redeem of the same ticket (another key: another intent) */
    CHECK(evm_tx(&fx, B, NODUS_RT_EVM_REDEEM, call, (uint32_t)cl, &t) == 0 &&
          refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC,
          "double redeem refused"); OK();
    tx_free(&t);
    CHECK(reserve_of(fx.w) == 10u - 3u - 2u,
          "reserve = Σ deposits − Σ releases"); OK();
    fx_close(&fx);
    return 0;
}

/* ══ 6. pairing refusals ══════════════════════════════════════════════ */

static int test_pairing(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "pair") == 0, "EVM chain"); OK();
    uint8_t call[256];
    uint32_t code = 0;
    tx_t t;
    spec_t s;
    size_t cl = enc_deposit(call, 5, 0);

    memset(&s, 0, sizeof(s));
    s.key = 0; s.with_evm = 1; s.evm_op = NODUS_RT_EVM_DEPOSIT;
    s.call = call; s.call_len = (uint32_t)cl;
    CHECK(build_tx(&fx, &s, &t) == 0 && refused_one(&fx, &t, &code) == 0 &&
          code == NODUS_V2_TX_ERR_EXEC, "an orphan EVM leg"); OK();
    tx_free(&t);

    memset(&s, 0, sizeof(s));
    s.key = 0; s.with_core = 1; s.big = 1; s.lock = 5;
    s.evm_op = NODUS_RT_EVM_DEPOSIT;       /* only the role is taken */
    CHECK(build_tx(&fx, &s, &t) == 0 && refused_one(&fx, &t, &code) == 0 &&
          code == NODUS_V2_TX_ERR_EXEC && coin_live(fx.w, t.coin) == 1,
          "an orphan EVMFUND leg"); OK();
    tx_free(&t);

    memset(&s, 0, sizeof(s));
    s.key = 0; s.with_core = 1; s.with_evm = 1;
    s.role = NODUS_RT_EVMFUND_ROLE_FEE;
    s.evm_op = NODUS_RT_EVM_DEPOSIT; s.call = call; s.call_len = (uint32_t)cl;
    CHECK(build_tx(&fx, &s, &t) == 0 && refused_one(&fx, &t, &code) == 0 &&
          code == NODUS_V2_TX_ERR_EXEC, "a DEPOSIT under role FEE"); OK();
    tx_free(&t);

    uint8_t to[32];
    memset(to, 0x44, sizeof(to));
    cl = enc_call(call, to, 0, 50000, 0, NULL, 0, NULL, NULL);
    memset(&s, 0, sizeof(s));
    s.key = 0; s.with_core = 1; s.with_evm = 1;
    s.role = NODUS_RT_EVMFUND_ROLE_RELEASE;
    s.evm_op = NODUS_RT_EVM_CALL; s.call = call; s.call_len = (uint32_t)cl;
    CHECK(build_tx(&fx, &s, &t) == 0 && refused_one(&fx, &t, &code) == 0 &&
          code == NODUS_V2_TX_ERR_EXEC, "a CALL under role RELEASE"); OK();
    tx_free(&t);
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_accounts") == 0 &&
          reserve_of(fx.w) == 0, "nothing moved"); OK();
    fx_close(&fx);
    return 0;
}

/* ══ 7. the block gas sum ═════════════════════════════════════════════ */

static int seam_of(fixture_t *fx, tx_t *t, int n, int *fi,
                   nodus_v2_batch_check_result_t *res) {
    nodus_witness_batch_item_t items[4];
    for (int i = 0; i < n; i++) {
        items[i].tx_data = t[i].bytes;
        items[i].tx_len = t[i].len;
        items[i].tx_type = nodus_witness_v2_classify_entry(
            t[i].bytes, (uint32_t)t[i].len);
    }
    memset(res, 0, sizeof(*res));
    *fi = -1;
    return nodus_witness_v2_produce_batch_check_capped(fx->w, items, n, 16,
                                                       fi, res);
}

static int call_gas_tx(fixture_t *fx, int k, uint64_t gas, tx_t *t) {
    static uint8_t call[128];
    uint8_t to[32];
    memset(to, 0x55, sizeof(to));
    size_t cl = enc_call(call, to, 0, gas, 0, NULL, 0, NULL, NULL);
    spec_t s;
    memset(&s, 0, sizeof(s));
    s.key = k; s.with_core = 1; s.with_evm = 1;
    s.evm_op = NODUS_RT_EVM_CALL; s.call = call; s.call_len = (uint32_t)cl;
    s.exact = 1;
    return build_tx(fx, &s, t);
}

static int test_gas_sum(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "gas") == 0, "EVM chain"); OK();
    const uint64_t lim = DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT;
    tx_t t[2];
    int fi = -1;
    nodus_v2_batch_check_result_t res;

    CHECK(call_gas_tx(&fx, 0, 20000000, &t[0]) == 0 &&
          call_gas_tx(&fx, 1, 20000000, &t[1]) == 0, "two 20M CALLs");
    CHECK(seam_of(&fx, &t[0], 1, &fi, &res) == 0 &&
          seam_of(&fx, &t[1], 1, &fi, &res) == 0, "each alone fits"); OK();
    CHECK(seam_of(&fx, t, 2, &fi, &res) == -1 && fi == 1 &&
          res.kind == NODUS_V2_BATCH_FAIL_CAPACITY_UNITS,
          "together: refused at the second (ProcessProposal REJECT)"); OK();
    {
        nodus_v2_envelope_t v[2] = { { t[0].bytes, t[0].len },
                                     { t[1].bytes, t[1].len } };
        nodus_v2_block_t b;
        mk_block(&b, fx.h, v, 2);
        CHECK(v2x_cmt_fault(fx.w, &b) == 0,
              "a decided block over the limit: FinalizeBlock FAULTs"); OK();
    }
    tx_free(&t[0]);
    tx_free(&t[1]);

    /* a bridge op counts 21 000: (lim − 21 000) + DEPOSIT fits exactly,
     * one gas more does not */
    CHECK(call_gas_tx(&fx, 0, lim - NODUS_RT_EVM_BRIDGE_GAS, &t[0]) == 0 &&
          deposit_tx(&fx, 1, 5, 0, &t[1]) == 0, "CALL + DEPOSIT");
    CHECK(seam_of(&fx, t, 2, &fi, &res) == 0, "exactly the limit"); OK();
    tx_free(&t[0]);
    CHECK(call_gas_tx(&fx, 0, lim - NODUS_RT_EVM_BRIDGE_GAS + 1, &t[0]) == 0,
          "one gas more");
    CHECK(seam_of(&fx, t, 2, &fi, &res) == -1 && fi == 1,
          "one gas over the limit: refused"); OK();
    tx_free(&t[0]);
    tx_free(&t[1]);

    /* at the default limit (== the per-tx cap) ONE CALL over the cap is
     * over the block limit: the seam refuses it at index 0 and a decided
     * block holding it FAULTs — the per-tx refusal is never reached */
    CHECK(DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT == NODUS_RT_EVM_TX_GAS_CAP,
          "this build: default block limit == per-tx cap");
    CHECK(call_gas_tx(&fx, 0, NODUS_RT_EVM_TX_GAS_CAP + 1u, &t[0]) == 0,
          "a CALL over the cap");
    CHECK(seam_of(&fx, t, 1, &fi, &res) == -1 && fi == 0 &&
          res.kind == NODUS_V2_BATCH_FAIL_CAPACITY_UNITS,
          "over the cap at the default limit: the seam refuses at 0"); OK();
    {
        nodus_v2_envelope_t v1 = { t[0].bytes, t[0].len };
        nodus_v2_block_t b;
        mk_block(&b, fx.h, &v1, 1);
        CHECK(v2x_cmt_fault(fx.w, &b) == 0,
              "and FinalizeBlock FAULTs such a block"); OK();
    }
    tx_free(&t[0]);
    fx_close(&fx);
    return 0;
}

/* ══ 8. CheckTx: the dry run and its VM-less recheck ═════════════════ */

static int dry_ex(nodus_witness_t *w, const tx_t *t, int recheck,
                  nodus_v2_env_dry_run_t *d) {
    char why[256];
    why[0] = '\0';
    memset(d, 0, sizeof(*d));
    return nodus_witness_v2_env_dry_run_ex(w, t->bytes, t->len, NULL,
                                           recheck, NULL, NULL, d, why,
                                           sizeof(why));
}

/* red-team 1 F1 — a RECORDING pending-conflict probe: answers `ret`,
 * counts its calls, keeps the last rows it was offered */
typedef struct {
    int                    ret;
    int                    calls;
    size_t                 n;
    nodus_v2_dry_run_row_t rows[NODUS_RT_V2_MAX_KEYS];
} rec_probe_t;

static int rec_probe(void *ctx, const nodus_v2_dry_run_row_t *rows,
                     size_t n) {
    rec_probe_t *p = (rec_probe_t *)ctx;
    p->calls++;
    p->n = n;
    for (size_t i = 0; i < n && i < NODUS_RT_V2_MAX_KEYS; i++)
        p->rows[i] = rows[i];
    return p->ret;
}

/* the dry run in CheckTx's mode (no VM) with a probe; the reason kept */
static int dry_probe(nodus_witness_t *w, const tx_t *t, rec_probe_t *p,
                     nodus_v2_env_dry_run_t *d, char *why, size_t why_sz) {
    why[0] = '\0';
    memset(d, 0, sizeof(*d));
    return nodus_witness_v2_env_dry_run_ex(w, t->bytes, t->len, NULL, 1,
                                           rec_probe, p, d, why, why_sz);
}

/* the row of (domain, op, key) — count */
static int dry_rows(const nodus_v2_env_dry_run_t *d, uint32_t dom,
                    uint32_t op, const uint8_t *key, uint16_t kl) {
    int n = 0;
    for (size_t i = 0; i < d->n_rows; i++)
        if (d->rows[i].domain_id == dom && d->rows[i].op_id == op &&
            (!key || (d->rows[i].key_len == kl &&
                      memcmp(d->rows[i].key, key, kl) == 0)))
            n++;
    return n;
}

static int evm_effect_rows(const nodus_v2_env_dry_run_t *d) {
    int n = 0;
    for (size_t i = 0; i < d->n_rows; i++)
        if (d->rows[i].domain_id == DNA_DOMAIN_EVM &&
            d->rows[i].op_id < 0x80000000u)
            n++;
    return n;
}

/* the CORE adapter's DELETE-of-a-utxo_set-row op id — file-local in
 * nodus_witness_rt_native.c (RTN_CORE_OP_UTXDEL 2u), restated here */
#define CORE_OP_UTXDEL 2u

static int test_checktx(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "ctx") == 0, "EVM chain"); OK();
    {
        /* red-team 1 F5: the genesis-derived first height the EVM_ACTIVE
         * rule reads — the fixture's document says 1 (v2x_cfg_make) */
        uint64_t ih = 0;
        CHECK(nodus_witness_v2_chain_initial_height(fx.w, &ih) == 0 &&
              ih == 1, "the chain's initial height, from its document");
        OK();
        /* the once-per-open cache: the post-open gate fills it on a
         * reopen, and the accessor's answer is unchanged (cache hit ==
         * derivation) */
        CHECK(fx_reopen(&fx) == 0 && fx.w->v2_chain32_valid &&
              fx.w->v2_initial_height == 1,
              "the gate cached the initial height on open");
        OK();
        ih = 0;
        CHECK(nodus_witness_v2_chain_initial_height(fx.w, &ih) == 0 &&
              ih == 1, "a cache hit answers the derivation's value"); OK();
    }
    const int A = 0;
    tx_t t;
    CHECK(deposit_tx(&fx, A, 10, 0, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "fund A (nonce 1)");
    tx_free(&t);

    uint8_t to[32], call[256], data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    memset(to, 0x66, sizeof(to));
    uint8_t key1[40];
    memcpy(key1, sender_of(A), 32);
    put64(key1 + 32, 1);

    tx_t c1, c2, cg;
    size_t cl = enc_call(call, to, 0, 60000, 1, NULL, 0, NULL, NULL);
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &c1) == 0,
          "CALL nonce 1");
    cl = enc_call(call, to, 0, 60000, 1, data, 8, NULL, NULL);
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &c2) == 0,
          "another CALL nonce 1");
    cl = enc_call(call, to, 0, 60000, 2, NULL, 0, NULL, NULL);
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &cg) == 0,
          "CALL nonce 2 (gapped)");

    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
    CHECK(d != NULL, "alloc");
    CHECK(dry_ex(fx.w, &c1, 0, d) == 0 && d->code == NODUS_V2_TX_OK,
          "CheckTx admits the CALL (probe-only execution)"); OK();
    CHECK(dry_rows(d, DNA_DOMAIN_EVM, NODUS_RT_EVM_KEY_SENDER_NONCE, key1,
                   40) == 1 && evm_effect_rows(d) == 0 &&
          dry_rows(d, DNA_DOMAIN_CORE, CORE_OP_UTXDEL, c1.coin, 64) == 1,
          "keys: (sender, nonce), the CORE input; NO EVM effect row"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &c2, 0, d) == 0 &&
          dry_rows(d, DNA_DOMAIN_EVM, NODUS_RT_EVM_KEY_SENDER_NONCE, key1,
                   40) == 1,
          "a second CALL of the sender carries the SAME key — the pending "
          "set admits one"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &cg, 0, d) == -1 && d->code == NODUS_V2_TX_ERR_EXEC,
          "a gapped nonce is refused (tip-nonce admission)"); OK();
    nodus_witness_v2_env_dry_run_free(d);

    /* RECHECK — the shared pre-validation only */
    CHECK(dry_ex(fx.w, &c1, 1, d) == 0 &&
          dry_rows(d, DNA_DOMAIN_EVM, NODUS_RT_EVM_KEY_SENDER_NONCE, key1,
                   40) == 1 && evm_effect_rows(d) == 0,
          "recheck admits with the same key"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &cg, 1, d) == -1, "recheck refuses the gap"); OK();
    nodus_witness_v2_env_dry_run_free(d);

    /* red-team 1 F1 — the pending-conflict PROBE, after authorization and
     * before any leg pre-validates or executes */
    {
        rec_probe_t pr;
        char why[256];
        memset(&pr, 0, sizeof(pr));
        pr.ret = 0;
        CHECK(dry_probe(fx.w, &c1, &pr, d, why, sizeof(why)) == 0 &&
              pr.calls == 1 && pr.n == 1 &&
              pr.rows[0].domain_id == DNA_DOMAIN_EVM &&
              pr.rows[0].op_id == NODUS_RT_EVM_KEY_SENDER_NONCE &&
              pr.rows[0].key_len == 40 &&
              memcmp(pr.rows[0].key, key1, 40) == 0 &&
              dry_rows(d, DNA_DOMAIN_EVM, NODUS_RT_EVM_KEY_SENDER_NONCE,
                       key1, 40) == 1,
              "no conflict: probed once with exactly (sender, nonce) under "
              "domain 2, then the run files the same key"); OK();
        nodus_witness_v2_env_dry_run_free(d);
        memset(&pr, 0, sizeof(pr));
        pr.ret = 1;
        CHECK(dry_probe(fx.w, &c1, &pr, d, why, sizeof(why)) == -1 &&
              d->code == NODUS_V2_TX_ERR_EXEC && pr.calls == 1 &&
              d->n_rows == 0 && strstr(why, "pending") != NULL,
              "a conflict is a -1 EXEC verdict and no key is filed"); OK();
        nodus_witness_v2_env_dry_run_free(d);
        memset(&pr, 0, sizeof(pr));
        pr.ret = -2;
        CHECK(dry_probe(fx.w, &c1, &pr, d, why, sizeof(why)) == -2,
              "a probe failure is a node FAULT, never a verdict"); OK();
        nodus_witness_v2_env_dry_run_free(d);
        /* ORDER: the gapped nonce would be refused by the pre-validation;
         * a conflicting probe is reached first (calls == 1) and its own
         * verdict is the reason */
        memset(&pr, 0, sizeof(pr));
        pr.ret = 1;
        CHECK(dry_probe(fx.w, &cg, &pr, d, why, sizeof(why)) == -1 &&
              pr.calls == 1 && strstr(why, "pending") != NULL,
              "the probe runs BEFORE the pre-validation"); OK();
        nodus_witness_v2_env_dry_run_free(d);
        /* a CORE-only envelope has no ABI-2 leg: never probed */
        tx_t sp;
        CHECK(spend_tx(&fx, 1, &sp) == 0, "a CORE SPEND");
        memset(&pr, 0, sizeof(pr));
        pr.ret = 1;
        CHECK(dry_probe(fx.w, &sp, &pr, d, why, sizeof(why)) == 0 &&
              pr.calls == 0, "a CORE-only envelope is never probed"); OK();
        nodus_witness_v2_env_dry_run_free(d);
        tx_free(&sp);
    }

    /* red-team 1 F3 — the access-list intrinsic floor (TX_BASE + 2400 /
     * address + 1900 / key, checked before allocation) is never stricter
     * than the engine's intrinsic check: one entry with one key, no data,
     * gas EXACTLY 21 000 + 2 400 + 1 900 is admitted in both modes, one
     * gas below is refused in both (the same -1 the engine gives) */
    {
        uint8_t aa[32], ak[32];
        memset(aa, 0x77, sizeof(aa));
        memset(ak, 0x78, sizeof(ak));
        const uint64_t ic = 21000u + 2400u + 1900u;
        tx_t at, ab;
        size_t al = enc_call(call, to, 0, ic, 1, NULL, 0, aa, ak);
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)al, &at) == 0,
              "CALL with gas == its intrinsic cost");
        al = enc_call(call, to, 0, ic - 1u, 1, NULL, 0, aa, ak);
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)al, &ab) == 0,
              "CALL with gas one below");
        for (int mode = 0; mode <= 1; mode++) {
            CHECK(dry_ex(fx.w, &at, mode, d) == 0 &&
                  d->code == NODUS_V2_TX_OK,
                  "exactly the intrinsic cost: admitted"); OK();
            nodus_witness_v2_env_dry_run_free(d);
            CHECK(dry_ex(fx.w, &ab, mode, d) == -1 &&
                  d->code == NODUS_V2_TX_ERR_EXEC,
                  "one gas below: refused"); OK();
            nodus_witness_v2_env_dry_run_free(d);
        }
        tx_free(&at);
        tx_free(&ab);
    }

    /* c1 commits: c2 (nonce 1) is stale on recheck */
    CHECK(apply_one(&fx, &c1, NULL) == NODUS_V2_TX_OK, "c1 commits");
    CHECK(dry_ex(fx.w, &c2, 1, d) == -1 && d->code == NODUS_V2_TX_ERR_EXEC,
          "recheck refuses the stale nonce"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &cg, 1, d) == 0, "and admits the next one"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    free(d);
    tx_free(&c1);
    tx_free(&c2);
    tx_free(&cg);
    fx_close(&fx);
    return 0;
}

/* runtime: REVERT iff TIMESTAMP == 0, else STOP —
 *   0 TIMESTAMP · 1 ISZERO · 2 PUSH1 6 · 4 JUMPI · 5 STOP ·
 *   6 JUMPDEST · 7 PUSH1 0 · 9 DUP1 · 10 REVERT(0, 0) */
static const uint8_t RT_TS_NONZERO[] = { 0x42, 0x15, 0x60, 0x06, 0x57, 0x00,
                                         0x5b, 0x60, 0x00, 0x80, 0xfd };

/* 8b. the CheckTx block time (design §10 "CheckTx simülasyonu tip
 * bloğunun zamanını kullanır"). The dry run's verdict CANNOT observe a
 * REVERT — a CALL is failable, so a reverted call is a paid failure the
 * dry run admits like a success (nodus_witness_rt_evm.c rtevm_exec,
 * out->failable = 1) and nodus_v2_env_dry_run_t carries no outcome. So
 * this section pins the two halves separately:
 *  (a) the ONE read (nodus_witness_v2_tip_block_time) answers the tip
 *      block's non-zero header seconds, and a TIMESTAMP-gated contract
 *      SUCCEEDS at that value and REVERTS at 0 (the old dry-run value) —
 *      through the same engine entry the RPC uses;
 *  (b) the dry run is WIRED to that read: with the tip's block-store
 *      record deleted, the dry run of an EVM CALL FAULTs (-2), while its
 *      VM-less recheck and an ordinary CORE envelope still pass (they
 *      read no block store). */
static int test_checktx_time(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "ctt") == 0, "EVM chain"); OK();
    const int A = 0;
    uint8_t ts[32];
    CHECK(deploy(&fx, A, 0, RT_TS_NONZERO, sizeof(RT_TS_NONZERO), ts) == 0,
          "deploy the TIMESTAMP-gated contract (nonce 0)"); OK();

    /* (a) */
    uint64_t secs = 0;
    CHECK(nodus_witness_v2_tip_block_time(fx.w, fx.h - 1, &secs) == 0 &&
          secs != 0, "the tip block's header seconds, non-zero"); OK();
    const nodus_domain_runtime_t *ert = NULL;
    uint8_t chain32[32];
    uint64_t gas_lim = 0;
    char why[160];
    CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_EVM, 1, &ert) == 0 &&
          ert && nodus_witness_v2_chain_id(fx.w, chain32) == 0 &&
          nodus_witness_v2_evm_block_gas_limit(fx.w, fx.h, &gas_lim, why,
                                               sizeof(why)) == 0,
          "the simulation environment"); OK();
    nodus_rt_evm_sim_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.from = sender_of(A);
    rq.to = ts;
    rq.gas_limit = 100000;
    rq.chain_id = chain32;
    rq.global_height = fx.h;
    rq.evm_block_gas_limit = gas_lim;
    nodus_rt_evm_sim_res_t r;
    rq.block_time_s = secs;
    CHECK(nodus_rt_evm_simulate(ert, fx.w, &rq, &r) == 0 && r.executed &&
          r.success == 1, "at the tip time the call succeeds"); OK();
    nodus_rt_evm_sim_res_free(&r);
    rq.block_time_s = 0;
    CHECK(nodus_rt_evm_simulate(ert, fx.w, &rq, &r) == 0 && r.executed &&
          r.success == 0, "at TIMESTAMP 0 it reverts (the contract "
          "discriminates)"); OK();
    nodus_rt_evm_sim_res_free(&r);

    /* (b) */
    uint8_t call[256];
    size_t cl = enc_call(call, ts, 0, 100000, 1, NULL, 0, NULL, NULL);
    tx_t c, sp;
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &c) == 0 &&
          spend_tx(&fx, 1, &sp) == 0, "a CALL (nonce 1) and a CORE SPEND");
    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
    CHECK(d != NULL, "alloc");
    CHECK(dry_ex(fx.w, &c, 0, d) == 0 && d->code == NODUS_V2_TX_OK,
          "the dry run admits the CALL with the tip time read"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    {
        nodus_cmt_store_t s;
        CHECK(nodus_cmt_store_init(&s, fx.w->db, false) == CMT_OK,
              "store");
        int drc = nodus_cmt_bs_delete_latest_block(&s);
        nodus_cmt_store_release(&s);
        CHECK(drc == CMT_OK, "the tip's block-store record deleted");
    }
    CHECK(nodus_witness_v2_tip_block_time(fx.w, fx.h - 1, &secs) == -1,
          "the tip time is now unreadable"); OK();
    CHECK(dry_ex(fx.w, &c, 0, d) == -2,
          "the EVM CALL's dry run FAULTs — it reads the tip time"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &c, 1, d) == 0,
          "its recheck (no VM) reads no block store"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &sp, 0, d) == 0 && d->code == NODUS_V2_TX_OK,
          "an ordinary CORE envelope reads no block store"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    free(d);
    tx_free(&c);
    tx_free(&sp);
    fx_close(&fx);
    return 0;
}

/* ══ 8d. red-team 1 D1 — gas price 0 stops the EVM, the exits stay open ═
 * Operator decision 2026-10-05-nodus-evm-redteam1-operator.md D1 + scope:
 * while the price in force is 0, an envelope with an EVM CALL, CREATE or
 * DEPOSIT leg is refused (code FEE) — in CheckTx and in FinalizeBlock,
 * through the ONE judge (nodus_witness_v2_gas_price_judge); WITHDRAW and
 * REDEEM, and every non-EVM envelope, pass the judge as before. */

static int judge2(uint16_t n, uint32_t d0, uint32_t o0, uint32_t d1,
                  uint32_t o1, uint64_t price, uint64_t fee,
                  uint32_t *code) {
    static dna_env_view_t v;
    char why[256];
    memset(&v, 0, sizeof(v));
    v.leg_count = n;
    v.leg[0].domain_id = d0;
    v.leg[0].runtime_op = o0;
    if (n > 1) {
        v.leg[1].domain_id = d1;
        v.leg[1].runtime_op = o1;
    }
    v.fee_amount = fee;
    v.res_max_total_units = 1000;
    *code = NODUS_V2_TX_OK;
    return nodus_witness_v2_gas_price_judge(&v, price, code, why,
                                            sizeof(why));
}

static int test_d1_price0(void) {
    uint32_t code = 0;
    const uint32_t C = DNA_DOMAIN_CORE, E = DNA_DOMAIN_EVM;
    const uint32_t F = DNA_CORERULE_EVMFUND;

    /* the pure judge */
    CHECK(judge2(2, C, F, E, NODUS_RT_EVM_CALL, 0, FEE, &code) == -1 &&
              code == NODUS_V2_TX_ERR_FEE &&
          judge2(2, C, F, E, NODUS_RT_EVM_CREATE, 0, FEE, &code) == -1 &&
              code == NODUS_V2_TX_ERR_FEE &&
          judge2(2, C, F, E, NODUS_RT_EVM_DEPOSIT, 0, FEE, &code) == -1 &&
              code == NODUS_V2_TX_ERR_FEE,
          "price 0: CALL / CREATE / DEPOSIT refused (FEE)"); OK();
    CHECK(judge2(2, C, F, E, NODUS_RT_EVM_WITHDRAW, 0, FEE, &code) == 0 &&
          judge2(2, C, F, E, NODUS_RT_EVM_REDEEM, 0, FEE, &code) == 0,
          "price 0: WITHDRAW / REDEEM pass (the exits)"); OK();
    CHECK(judge2(1, C, DNA_CORERULE_SPEND, 0, 0, 0, 0, &code) == 0 &&
          judge2(1, DNA_DOMAIN_SYSTEM, 1, 0, 0, 0, 0, &code) == 0,
          "price 0: a CORE / SYSTEM envelope passes, even with fee 0 (the "
          "rule is off for it, as before)"); OK();
    CHECK(judge2(2, C, F, E, NODUS_RT_EVM_CALL, 1, FEE, &code) == 0 &&
          judge2(2, C, F, E, NODUS_RT_EVM_CALL, 1, 10, &code) == -1 &&
              code == NODUS_V2_TX_ERR_FEE,
          "price > 0: the fee rule exactly as before"); OK();

    /* end to end: price FIX_PRICE until HE + 1, 0 from HE + 2 */
    fixture_t fx;
    CHECK(fx_open_ex(&fx, "d1", 1, 1, 0, 0, HE + 2) == 0 &&
          fx_to(&fx, HE) == 0, "EVM chain, the price back to 0 at HE + 2");
    OK();
    const int A = 0;
    tx_t t;
    CHECK(deposit_tx(&fx, A, 10, 0, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK,
          "fund A at the priced height (nonce 0 -> 1)"); OK();
    tx_free(&t);
    CHECK(fx_to(&fx, HE + 2) == 0, "to the first price-0 height");
    {
        uint64_t p = 1;
        char why[160];
        CHECK(nodus_witness_v2_gas_price_at(fx.w, fx.h, &p, why,
                                            sizeof(why)) == 0 && p == 0,
              "the price at tip + 1 is 0"); OK();
    }
    uint8_t call[256], to[32];
    static const uint8_t init1[1] = { 0x00 };
    memset(to, 0x66, sizeof(to));
    tx_t dep, cal, cre, wdr, sp;
    size_t cl = enc_deposit(call, 5, 1);
    {
        spec_t s;
        memset(&s, 0, sizeof(s));
        s.key = A; s.with_core = 1; s.with_evm = 1; s.big = 1; s.lock = 5;
        s.evm_op = NODUS_RT_EVM_DEPOSIT; s.call = call;
        s.call_len = (uint32_t)cl;
        CHECK(build_tx(&fx, &s, &dep) == 0, "DEPOSIT nonce 1");
    }
    cl = enc_call(call, to, 0, 60000, 1, NULL, 0, NULL, NULL);
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &cal) == 0,
          "CALL nonce 1");
    cl = enc_create(call, 100000, 1, init1, 1);
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CREATE, call, (uint32_t)cl, &cre) == 0,
          "CREATE nonce 1");
    cl = enc_withdraw(call, 3, 1, g_k[1].fp);
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &wdr) ==
              0, "WITHDRAW 3 raw nonce 1");
    CHECK(spend_tx(&fx, 1, &sp) == 0, "a CORE SPEND");

    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
    CHECK(d != NULL, "alloc");
    const tx_t *refused[3] = { &dep, &cal, &cre };
    for (int i = 0; i < 3; i++) {
        CHECK(dry_ex(fx.w, refused[i], 1, d) == -1 &&
              d->code == NODUS_V2_TX_ERR_FEE,
              "CheckTx: DEPOSIT / CALL / CREATE refused at price 0 (FEE)");
        OK();
        nodus_witness_v2_env_dry_run_free(d);
    }
    CHECK(dry_ex(fx.w, &wdr, 1, d) == 0 && d->code == NODUS_V2_TX_OK,
          "CheckTx: WITHDRAW admitted at price 0"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &sp, 1, d) == 0 && d->code == NODUS_V2_TX_OK,
          "CheckTx: a CORE SPEND admitted at price 0"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    free(d);

    /* FinalizeBlock: the same verdict through the item loop */
    CHECK(refused_one(&fx, &cal, &code) == 0 &&
          code == NODUS_V2_TX_ERR_FEE,
          "FinalizeBlock: the CALL is refused (FEE), the ledger unchanged");
    OK();
    CHECK(apply_one(&fx, &wdr, NULL) == NODUS_V2_TX_OK,
          "FinalizeBlock: the WITHDRAW applies at price 0"); OK();
    tx_free(&dep);
    tx_free(&cal);
    tx_free(&cre);
    tx_free(&wdr);
    tx_free(&sp);
    fx_close(&fx);
    return 0;
}

/* ══ 8c. CheckTx of the nodus-cli shape ══════════════════════════════ */

/* Every other section builds its envelopes with build_tx (above), whose
 * ceiling always carries FAIL_RESERVE + 2 000 000 spare units and whose
 * fee is FEE. nodus-cli `evm` and the web wallet build with the SHARED
 * builder (client/nodus_v2_evm.c nodus_v2_evm_build) at the smallest
 * ceiling it computes and fee = units × price. This section builds
 * exactly that — the inputs of nodus-cli.c evm_tx_run (:7150-7385), each
 * from the node-side source the RPC the CLI asks would read — and feeds
 * each envelope to the CheckTx dry run (new, not recheck), printing the
 * verdict and its reason. */

/* the CLI's expiry margin: CLI_ENV_EXPIRY_AHEAD (nodus-cli.c:106-107);
 * an EVM-generation envelope takes the plain margin (cli_env_expiry,
 * nodus-cli.c:1251-1270: the H-1 cap is for generation 1 only) */
#define CLI_EXPIRY_AHEAD ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD - 10u)
/* evm_estimate's probe bound (nodus_witness_handlers.c:4339 —
 * EVM_EST_MAX_PROBES, file-local there) */
#define RPC_EST_MAX_PROBES 16

typedef struct {
    uint64_t ge, ue, fe;
    int      success;
} cli_est_t;

/**
 * evm_estimate, RESTATED from nodus_witness_handlers.c handle_evm_call
 * (:4732-4858, estimate = 1) — a static of the handler file behind a TCP
 * connection, so it cannot be called here. Inputs as nodus-cli sends them
 * (nodus-cli.c:7237-7246): f = the sender, t = the target (NULL =
 * CREATE), v = 32 zero bytes (the CLI always sends call->value_wei), d =
 * the data, NO g (o->gas 0 → nodus_client.c:7318 omits it → gas =
 * NODUS_RT_EVM_TX_GAS_CAP, handlers.c:4741). Block environment at tip + 1
 * (:4762-4782). The per-height simulation budget (evm_sim_once) is not
 * modelled: it only refuses, it never changes an answer.
 * @return 0 (the RPC would answer) / -1 (the RPC would answer an error).
 */
static int cli_estimate(nodus_witness_t *w, uint64_t tip,
                        const uint8_t from[32], const uint8_t *to,
                        const uint8_t *data, uint32_t dl, cli_est_t *e) {
    static const uint8_t zero_value[32];
    memset(e, 0, sizeof(*e));
    const nodus_domain_runtime_t *ert = NULL, *srt = NULL, *crt = NULL;
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    uint64_t btime = 0, gas_lim = 0, price = 0;
    char why[160];
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_EVM, 1, &ert) != 0 ||
        !ert || nodus_witness_v2_chain_id(w, chain32) != 0 ||
        nodus_witness_v2_tip_block_time(w, tip, &btime) != 0 ||
        nodus_witness_v2_evm_block_gas_limit(w, tip + 1, &gas_lim, why,
                                             sizeof(why)) != 0)
        return -1;
    const uint64_t gas = NODUS_RT_EVM_TX_GAS_CAP;
    nodus_rt_evm_sim_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.from = from;
    rq.to = to;
    rq.value = zero_value;
    rq.data = data;
    rq.data_len = dl;
    rq.chain_id = chain32;
    rq.global_height = tip + 1;
    rq.block_time_s = btime;
    rq.evm_block_gas_limit = gas_lim;

    nodus_rt_evm_sim_res_t at_g, best;
    memset(&at_g, 0, sizeof(at_g));
    memset(&best, 0, sizeof(best));
    rq.gas_limit = gas;
    int rc = nodus_rt_evm_simulate(ert, (struct nodus_witness *)w, &rq,
                                   &at_g);
    if (rc != 0 || !at_g.executed) {
        if (rc == 0) nodus_rt_evm_sim_res_free(&at_g);
        return -1;
    }

    /* the binary search for the smallest successful limit (:4800-4853) */
    uint64_t ge = gas;
    const nodus_rt_evm_sim_res_t *rep = &at_g;
    if (at_g.success) {
        uint64_t lo = 0, hi = gas;
        const uint64_t first = at_g.engine_gas_used;
        int probes = 0, fault = 0;
        if (first > 0 && first < gas) {
            nodus_rt_evm_sim_res_t r;
            memset(&r, 0, sizeof(r));
            rq.gas_limit = first;
            int prc = nodus_rt_evm_simulate(ert, (struct nodus_witness *)w,
                                            &rq, &r);
            probes++;
            if (prc == 0 && r.executed && r.success) {
                hi = first;
                best = r;
            } else {
                if (prc == 0) nodus_rt_evm_sim_res_free(&r);
                else if (prc != -1) fault = 1;
                lo = first;
            }
        }
        while (!fault && hi != first && probes < RPC_EST_MAX_PROBES &&
               hi - lo > (hi / 64 > 1 ? hi / 64 : 1)) {
            uint64_t mid = lo + (hi - lo) / 2;
            nodus_rt_evm_sim_res_t r;
            memset(&r, 0, sizeof(r));
            rq.gas_limit = mid;
            int prc = nodus_rt_evm_simulate(ert, (struct nodus_witness *)w,
                                            &rq, &r);
            probes++;
            if (prc == 0 && r.executed && r.success) {
                hi = mid;
                nodus_rt_evm_sim_res_free(&best);
                best = r;
            } else {
                if (prc == 0) nodus_rt_evm_sim_res_free(&r);
                else if (prc != -1) { fault = 1; break; }
                lo = mid;
            }
        }
        if (fault) {
            nodus_rt_evm_sim_res_free(&best);
            nodus_rt_evm_sim_res_free(&at_g);
            return -1;
        }
        ge = hi;
        if (hi != gas) rep = &best;
    }

    /* ue / fe (:4855-4884) */
    uint64_t ref = 0, ru = 0, ue = 0, fe = 0;
    const uint64_t floor_fee = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                                   ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
    int ok =
        nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &srt) == 0 &&
        nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &crt) == 0 &&
        srt && crt && srt->meter_policy &&
        nodus_witness_v2_gas_price_at(w, tip + 1, &price, why,
                                      sizeof(why)) == 0 &&
        nodus_v2_evm_ref_units(srt->meter_policy, crt->ruleset_version,
                               to ? DNA_EVM_OP_CALL : DNA_EVM_OP_CREATE,
                               dl, ge, &ref) == NODUS_V2_SPEND_OK &&
        dna_ck_mul_u64(rep->reads, srt->meter_policy->w_read, &ru) == 0 &&
        dna_ck_add_u64(ref, ru, &ue) == 0;
    if (ok) {
        fe = floor_fee;
        uint64_t g = 0;
        if (price != 0) {
            if (dna_ck_mul_u64(ue, price, &g) != 0) ok = 0;
            else if (g > fe) fe = g;
        }
    }
    e->ge = ge;
    e->ue = ue;
    e->fe = fe;
    e->success = rep->success;
    nodus_rt_evm_sim_res_free(&best);
    nodus_rt_evm_sim_res_free(&at_g);
    return ok ? 0 : -1;
}

typedef struct {
    const char          *name;
    nodus_v2_evm_built_t built;
    int                  brc;        /* the builder's rc (-999: not reached) */
    int                  drc;        /* the dry run's rc (-999: not run)     */
    uint32_t             code;       /* the dry run's item code             */
    char                 why[512];   /* the dry run's reason                */
    int                  rdrc;       /* the RECHECK's rc (-999: not run)    */
    uint32_t             rcode;      /* the RECHECK's item code             */
} cli_case_t;

static const char *cli_op_name(uint32_t op) {
    return op == DNA_EVM_OP_CALL ? "CALL" :
           op == DNA_EVM_OP_CREATE ? "CREATE" :
           op == DNA_EVM_OP_DEPOSIT ? "DEPOSIT" :
           op == DNA_EVM_OP_WITHDRAW ? "WITHDRAW" : "REDEEM";
}

/**
 * nodus-cli.c evm_tx_run (:7150-7385) without the socket, key k signing:
 *   generation  the EVM generation's compiled entries, after checking the
 *               registry runs that CORE tuple (cli_select_runtimes,
 *               :1176-1212; the generation gate :7205-7218)
 *   nonce       the committed EVM nonce (:7220-7229; evm_account)
 *   gas, units  CALL / CREATE: the estimate above; gas_limit = ge
 *               (:7264), read units = ue − ref_units(op, data_len, ge)
 *               (:7265-7274)
 *   coins       ONE native coin, CLI_COIN (:7283-7311 lists every
 *               unlocked native coin of the key; the harness wallet held
 *               one — inputs=1 — so the fixture's small coins are left out)
 *   gas_price   GAS_PRICE_RAW_PER_UNIT at tip + 1 — dnac_fee_info's own
 *               read (handlers.c:488-490), the CLI's source (:7312-7317)
 *   req         :7319-7335; chain32 = w->v2_chain32 (dnac_chain_id32,
 *               handlers.c:410-412); tip = the committed tip (:7290)
 * `units` != 0 is NOT a CLI shape (the CLI never sets req.units): the
 * fixed-ceiling probe. Then the CheckTx dry run, NEW (recheck 0).
 * @return 0 the case ran to a dry-run answer / -1 it stopped before.
 */
static int cli_build_dry(fixture_t *fx, int k, dna_evm_call_t *call,
                         uint64_t units, cli_case_t *cc) {
    cc->brc = -999;
    cc->drc = -999;
    cc->rdrc = -999;
    cc->why[0] = '\0';
    const uint64_t tip = fx->h - 1u;
    const nodus_domain_runtime_t *sys_rt = gevm(DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *core_rt = gevm(DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *evm_rt = gevm(DNA_DOMAIN_EVM);
    dna_domain_manifest_t core_m;
    if (!sys_rt || !core_rt || !evm_rt || !sys_rt->meter_policy ||
        core_rt->generation < NODUS_RT_GEN_EVM ||
        nodus_witness_domreg_get(fx->w, DNA_DOMAIN_CORE, NULL, &core_m,
                                 NULL) != 0 ||
        core_m.ruleset_version != core_rt->ruleset_version ||
        memcmp(core_m.ruleset_hash, core_rt->ruleset_hash, 64) != 0) {
        printf("cli %s: the node does not run the EVM generation's CORE "
               "tuple — nothing was built\n", cc->name);
        return -1;
    }
    if (call->op != DNA_EVM_OP_REDEEM)
        call->nonce = acct_nonce(fx->w, sender_of(k));

    uint64_t read_units = 0;
    if (call->op == DNA_EVM_OP_CALL || call->op == DNA_EVM_OP_CREATE) {
        cli_est_t es;
        if (cli_estimate(fx->w, tip, sender_of(k),
                         call->op == DNA_EVM_OP_CALL ? call->to : NULL,
                         call->data, call->data_len, &es) != 0) {
            printf("cli %s: evm_estimate would answer an error — nothing "
                   "was built\n", cc->name);
            return -1;
        }
        if (!es.success) {
            printf("cli %s: the simulation FAILS — the CLI builds nothing "
                   "without --force\n", cc->name);
            return -1;
        }
        call->gas_limit = es.ge;
        uint64_t ref = 0;
        if (nodus_v2_evm_ref_units(sys_rt->meter_policy,
                                   core_rt->ruleset_version, call->op,
                                   call->data_len, es.ge, &ref) !=
                NODUS_V2_SPEND_OK) {
            printf("cli %s: could not price the reference shape\n",
                   cc->name);
            return -1;
        }
        read_units = es.ue > ref ? es.ue - ref : 0;
        printf("cli %s estimate: gas %llu, node-suggested units %llu, fee "
               "%llu raw, read units %llu\n", cc->name,
               (unsigned long long)es.ge, (unsigned long long)es.ue,
               (unsigned long long)es.fe, (unsigned long long)read_units);
    }

    nodus_v2_coin_t coin;
    memset(&coin, 0, sizeof(coin));
    if (coin_nul(k, CLI_KIND, 0, coin.nul) != 0) return -1;
    coin.amount = CLI_COIN;
    uint64_t gas_price = 0;
    if (nodus_chain_config_get_u64(fx->w,
                                   (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
                                   tip + 1, 0ULL, &gas_price) < 0)
        return -1;

    nodus_v2_ruleset_id_t rs;
    memset(&rs, 0, sizeof(rs));
    rs.core_ruleset_version = core_rt->ruleset_version;
    memcpy(rs.core_ruleset_hash, core_rt->ruleset_hash, 64);
    rs.meter_policy = sys_rt->meter_policy;
    nodus_v2_evm_req_t req;
    memset(&req, 0, sizeof(req));
    req.expiry_height       = tip + CLI_EXPIRY_AHEAD;
    req.rs                  = &rs;
    req.evm_ruleset_version = evm_rt->ruleset_version;
    req.evm_ruleset_hash    = evm_rt->ruleset_hash;
    req.chain32             = fx->w->v2_chain32;
    req.tip                 = tip;
    req.gas_price           = gas_price;
    req.pk                  = g_k[k].pk;
    req.sk                  = g_k[k].sk;
    req.call                = *call;
    req.units               = units;
    req.evm_read_units      = read_units;
    req.coins               = &coin;
    req.n_coins             = 1;
    nodus_v2_evm_err_t ee;
    cc->brc = nodus_v2_evm_build(&req, &cc->built, &ee);
    if (cc->brc != NODUS_V2_SPEND_OK) {
        printf("cli %s: the builder refused (rc %d, meter %d, need %llu, "
               "fee %llu, units %llu, min %llu)\n", cc->name, cc->brc,
               ee.meter_status, (unsigned long long)ee.need,
               (unsigned long long)ee.fee, (unsigned long long)ee.units,
               (unsigned long long)ee.min_units);
        return -1;
    }
    /* the CLI's own line (nodus-cli.c:7367-7379) */
    printf("cli %s: evm %s: nonce=%llu gas=%llu units=%llu fee=%llu "
           "inputs=%d change=%llu expiry=%llu generation=%u (min units "
           "%llu)\n", cc->name, cli_op_name(call->op),
           (unsigned long long)cc->built.dec.nonce,
           (unsigned long long)cc->built.dec.gas_limit,
           (unsigned long long)cc->built.units,
           (unsigned long long)cc->built.fee, cc->built.n_in,
           (unsigned long long)cc->built.change,
           (unsigned long long)req.expiry_height,
           (unsigned)core_rt->generation,
           (unsigned long long)cc->built.min_units);

    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
    if (!d) return -1;
    cc->drc = nodus_witness_v2_env_dry_run(fx->w, cc->built.env,
                                           cc->built.env_len, NULL, d,
                                           cc->why, sizeof(cc->why));
    cc->code = d->code;
    nodus_witness_v2_env_dry_run_free(d);
    printf("cli %s: CheckTx dry run (new): rc=%d code=%u reason=\"%s\"\n",
           cc->name, cc->drc, (unsigned)cc->code, cc->why);
    /* the mempool's RECHECK of the same bytes (no VM; the same reader
     * rule — nodus_witness_v2_apply.c exec_evm_leg) */
    char rwhy[512];
    rwhy[0] = '\0';
    cc->rdrc = nodus_witness_v2_env_dry_run_ex(fx->w, cc->built.env,
                                               cc->built.env_len, NULL, 1,
                                               NULL, NULL, d, rwhy,
                                               sizeof(rwhy));
    cc->rcode = d->code;
    nodus_witness_v2_env_dry_run_free(d);
    free(d);
    printf("cli %s: CheckTx RECHECK: rc=%d code=%u reason=\"%s\"\n",
           cc->name, cc->rdrc, (unsigned)cc->rcode, rwhy);
    fflush(stdout);
    return 0;
}

static int test_checktx_cli(void) {
    fixture_t fx;
    /* the EVM chain, the price CLI_PRICE from HE + 4: blocks HE .. HE + 3
     * run at the fixture's FIX_PRICE (red-team 1 D1: not 0, which stops
     * the EVM), which the fixture's own FEE-paying builders pay, so they
     * can fund A, deploy and open a ticket; every CLI-shaped envelope is
     * judged at tip + 1 = HE + 4, the first CLI-priced height */
    CHECK(fx_open_ex(&fx, "cli", 1, 1, 0, HE + 4, 0) == 0 &&
          fx_to(&fx, HE) == 0, "EVM chain with a gas price at HE + 4");
    OK();
    const int A = 0, R = 1, X = 2;
    tx_t t;
    CHECK(deposit_tx(&fx, A, 1000, 0, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK,
          "fund A's EVM balance: 1000 raw (nonce 0 -> 1)");
    tx_free(&t);
    OK();
    uint8_t store[32];
    CHECK(deploy(&fx, A, 1, RT_STORE, sizeof(RT_STORE), store) == 0,
          "deploy STORE (nonce 1 -> 2)"); OK();

    /* NEGATIVE (FIX_PRICE here, which FEE covers, so the fee rule cannot
     * be the reason): a
     * CALL whose ceiling is below the VM floor static + gas × w_gas +
     * FAIL_RESERVE (design §8; nodus_witness_v2_apply.c v2rd_declare_gas)
     * is still REFUSED before execution — the bridge-op headroom change
     * does not reach a VM leg. Two ceilings: the floor − 1, and the floor
     * − FAIL_RESERVE (the builder's minimum WITHOUT the reserve). */
    {
        uint8_t call[256], data[64];
        memset(data, 0, sizeof(data));
        data[31] = 1;
        data[63] = 7;
        size_t cl = enc_call(call, store, 0, 60000, 2, data, 64, NULL,
                             NULL);
        const int64_t deltas[2] = { -1,
                                    -(int64_t)DNA_METER_EVM_FAIL_RESERVE };
        for (int i = 0; i < 2; i++) {
            spec_t s;
            memset(&s, 0, sizeof(s));
            s.key = A;
            s.with_core = 1;
            s.with_evm = 1;
            s.evm_op = NODUS_RT_EVM_CALL;
            s.call = call;
            s.call_len = (uint32_t)cl;
            s.exact = 1;
            s.delta = deltas[i];
            tx_t n;
            CHECK(build_tx(&fx, &s, &n) == 0, "the under-floor CALL");
            nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
            char why[512];
            why[0] = '\0';
            CHECK(d != NULL, "alloc");
            int drc = nodus_witness_v2_env_dry_run(fx.w, n.bytes, n.len,
                                                   NULL, d, why,
                                                   sizeof(why));
            uint32_t code = d->code;
            nodus_witness_v2_env_dry_run_free(d);
            free(d);
            tx_free(&n);
            printf("cli NEG-CALL floor%lld: CheckTx dry run (new): rc=%d "
                   "code=%u reason=\"%s\"\n", (long long)deltas[i], drc,
                   (unsigned)code, why);
            fflush(stdout);
            CHECK(drc == -1 && code == NODUS_V2_TX_ERR_EXEC,
                  "a CALL under the VM floor is refused"); OK();
        }
    }

    /* a contract opens a ticket of 2 raw for R (test_bridge's shape) */
    CHECK(rt_ticket_build() == 0, "ticket contract");
    uint8_t tc[32];
    CHECK(deploy(&fx, A, 2, g_rt_ticket, g_rt_ticket_len, tc) == 0,
          "deploy TICKET (nonce 2 -> 3)"); OK();
    {
        uint8_t call[256];
        size_t cl = enc_call(call, tc, 2ull * Q, 200000, 3, g_k[R].fp, 64,
                             NULL, NULL);
        CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) ==
                  0 && apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK,
              "open the ticket (nonce 3 -> 4)");
        tx_free(&t);
        OK();
    }
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_tickets") == 1,
          "one pending ticket"); OK();
    CHECK(fx.h == HE + 4, "the next height is the first priced one"); OK();
    {
        uint64_t p = 0;
        char why[160];
        CHECK(nodus_witness_v2_gas_price_at(fx.w, fx.h, &p, why,
                                            sizeof(why)) == 0 &&
              p == CLI_PRICE, "the price at tip + 1 is the harness's");
        OK();
    }
    CHECK(acct_nonce(fx.w, sender_of(A)) == 4, "A's committed nonce 4");
    OK();

    enum { C_DEP, C_WD, C_REDEEM, C_CREATE, C_CALL, C_PROBE, C_N };
    cli_case_t *cs = calloc(C_N, sizeof(*cs));
    CHECK(cs != NULL, "alloc");
    cs[C_DEP].name    = "DEPOSIT";
    cs[C_WD].name     = "WITHDRAW";
    cs[C_REDEEM].name = "REDEEM";
    cs[C_CREATE].name = "CREATE";
    cs[C_CALL].name   = "CALL";
    cs[C_PROBE].name  = "PROBE-DEPOSIT+FAIL_RESERVE";
    for (int i = 0; i < C_N; i++) {
        cs[i].brc = -999;
        cs[i].drc = -999;
    }
    dna_evm_call_t c;

    /* `evm deposit 100000000000` (nodus-cli.c:7669-7676) */
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_DEPOSIT;
    c.amount_raw = CLI_DEPOSIT;
    cli_build_dry(&fx, A, &c, 0, &cs[C_DEP]);

    /* `evm withdraw 500 --to <R's address>` (nodus-cli.c:7677-7681: the
     * 64-byte raw fingerprint of --to) */
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_WITHDRAW;
    c.amount_raw = 500;
    memcpy(c.dest_fp, g_k[R].fp, 64);
    cli_build_dry(&fx, A, &c, 0, &cs[C_WD]);

    /* `evm redeem <ticket_id>` by key X — anyone may redeem
     * (nodus-cli.c:7697-7728: the call names the ticket EXACTLY, its
     * amount and recipient read back through evm_ticket, whose source is
     * `SELECT amount_raw, dest_fp FROM evm_tickets WHERE ticket_id = ?1`,
     * nodus_witness_handlers.c:4672) */
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_REDEEM;
    {
        sqlite3_stmt *st = NULL;
        int got = 0;
        if (sqlite3_prepare_v2(fx.w->db,
                "SELECT ticket_id, amount_raw, dest_fp FROM evm_tickets",
                -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW &&
            sqlite3_column_bytes(st, 0) == 64 &&
            sqlite3_column_bytes(st, 2) == 64) {
            memcpy(c.ticket_id, sqlite3_column_blob(st, 0), 64);
            c.amount_raw = (uint64_t)sqlite3_column_int64(st, 1);
            memcpy(c.dest_fp, sqlite3_column_blob(st, 2), 64);
            got = 1;
        }
        sqlite3_finalize(st);
        if (got) {
            printf("cli REDEEM ticket: %llu raw\n",
                   (unsigned long long)c.amount_raw);
            cli_build_dry(&fx, X, &c, 0, &cs[C_REDEEM]);
        } else {
            printf("cli REDEEM: the pending ticket could not be read\n");
        }
    }

    /* `evm deploy <initcode hex>` (nodus-cli.c:7575-7641, no --args): the
     * STORE initcode */
    uint8_t init[128];
    size_t il = mk_initcode(init, RT_STORE, sizeof(RT_STORE));
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_CREATE;
    c.data = init;
    c.data_len = (uint32_t)il;
    cli_build_dry(&fx, A, &c, 0, &cs[C_CREATE]);

    /* `evm send <store> "set(uint256,uint256)" 1 7` (nodus-cli.c:7642-
     * 7668: selector = keccak256(canon)[0..4] ‖ two ABI words) */
    uint8_t data[4 + 64];
    {
        static const char canon[] = "set(uint256,uint256)";
        uint8_t h[32];
        CHECK(keccak256((const uint8_t *)canon, sizeof(canon) - 1, h) == 0,
              "selector");
        memcpy(data, h, 4);
        memset(data + 4, 0, 64);
        data[4 + 31] = 1;
        data[4 + 63] = 7;
    }
    memset(&c, 0, sizeof(c));
    c.op = DNA_EVM_OP_CALL;
    memcpy(c.to, store, 32);
    c.data = data;
    c.data_len = (uint32_t)sizeof(data);
    cli_build_dry(&fx, A, &c, 0, &cs[C_CALL]);

    /* PROBE — NOT a CLI shape: the DEPOSIT once more with a FIXED ceiling
     * of its minimum + DNA_METER_EVM_FAIL_RESERVE. The node keeps
     * w_read + FAIL_RESERVE + gas × w_gas free on every new read of an
     * ABI-2 leg (nodus_witness_v2_apply.c v2rd_read); the builder adds
     * FAIL_RESERVE only for CALL / CREATE (nodus_v2_evm.c
     * nodus_v2_evm_min_units). Accepted here and refused above = that
     * headroom is the DEPOSIT's refusal. Printed, not asserted. */
    if (cs[C_DEP].brc == NODUS_V2_SPEND_OK) {
        memset(&c, 0, sizeof(c));
        c.op = DNA_EVM_OP_DEPOSIT;
        c.amount_raw = CLI_DEPOSIT;
        cli_build_dry(&fx, A, &c,
                      cs[C_DEP].built.min_units + DNA_METER_EVM_FAIL_RESERVE,
                      &cs[C_PROBE]);
    }

    /* every answer is printed above; now the assertions */
    int ok_dep_shape = cs[C_DEP].brc == NODUS_V2_SPEND_OK &&
                       cs[C_DEP].built.n_in == 1 &&
                       cs[C_DEP].built.units == 16028u &&
                       cs[C_DEP].built.fee == 1939388u &&
                       cs[C_DEP].built.change == 9999899998060612ull;
    int ok[C_PROBE];
    for (int i = 0; i < C_PROBE; i++)
        ok[i] = cs[i].brc == NODUS_V2_SPEND_OK && cs[i].drc == 0 &&
                cs[i].code == NODUS_V2_TX_OK && cs[i].rdrc == 0 &&
                cs[i].rcode == NODUS_V2_TX_OK;

    /* FinalizeBlock: the CLI-built DEPOSIT (A) and REDEEM (X — another
     * signer, other coins, the ticket) APPLY in one block — the bridge
     * reader rule is the same there (exec_evm_leg creates every reader) */
    uint32_t fb_code[2] = { 99, 99 };
    int fb_rc = -999;
    uint64_t rsv0 = reserve_of(fx.w);
    if (ok[C_DEP] && ok[C_REDEEM]) {
        tx_t b[2];
        memset(b, 0, sizeof(b));
        b[0].bytes = cs[C_DEP].built.env;          /* borrowed: never   */
        b[0].len = cs[C_DEP].built.env_len;        /* tx_free'd          */
        b[1].bytes = cs[C_REDEEM].built.env;
        b[1].len = cs[C_REDEEM].built.env_len;
        nodus_v2_tx_result_t res[2];
        fb_rc = apply_txs(&fx, b, 2, res);
        fb_code[0] = res[0].code;
        fb_code[1] = res[1].code;
        printf("cli FinalizeBlock: rc=%d DEPOSIT code=%u REDEEM code=%u\n",
               fb_rc, (unsigned)fb_code[0], (unsigned)fb_code[1]);
        fflush(stdout);
    }
    int fb_ok = fb_rc == 0 && fb_code[0] == NODUS_V2_TX_OK &&
                fb_code[1] == NODUS_V2_TX_OK &&
                reserve_of(fx.w) == rsv0 + CLI_DEPOSIT - 2u &&
                q1(fx.w, "SELECT COUNT(*) FROM evm_tickets") == 0 &&
                acct_nonce(fx.w, sender_of(A)) == 5 &&
                invariants_ok(fx.w) && roots_ok(fx.w) == 0;
    for (int i = 0; i < C_N; i++) nodus_v2_evm_built_free(&cs[i].built);
    free(cs);
    fx_close(&fx);

    CHECK(ok_dep_shape, "the DEPOSIT is the harness's (inputs 1, units "
          "16028, fee 1939388, change 9999899998060612)"); OK();
    CHECK(ok[C_DEP], "CheckTx (new + recheck) admits the CLI-built "
          "DEPOSIT"); OK();
    CHECK(ok[C_WD], "CheckTx (new + recheck) admits the CLI-built "
          "WITHDRAW"); OK();
    CHECK(ok[C_REDEEM], "CheckTx (new + recheck) admits the CLI-built "
          "REDEEM"); OK();
    CHECK(ok[C_CREATE], "CheckTx (new + recheck) admits the CLI-built "
          "CREATE"); OK();
    CHECK(ok[C_CALL], "CheckTx (new + recheck) admits the CLI-built "
          "CALL"); OK();
    CHECK(fb_ok, "FinalizeBlock applies the CLI-built DEPOSIT + REDEEM: "
          "reserve + 10^11 − 2, the ticket consumed, A's nonce 5, both "
          "invariants, committed == recomputed root"); OK();
    return 0;
}

/* ══ 9. the storage trie vs the full rebuild; restart; twin ══════════ */

static int full_storage_root(nodus_witness_t *w, const uint8_t addr[32],
                             uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT slot, value FROM evm_slots WHERE addr = ?1 "
            "ORDER BY slot", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    evm_trie_full_kv kv[64];
    uint8_t keys[64][32];
    evm_trie_rlp_buf vals[64];
    memset(vals, 0, sizeof(vals));
    size_t n = 0;
    int ret = -1;
    while (sqlite3_step(st) == SQLITE_ROW && n < 64) {
        const uint8_t *k = sqlite3_column_blob(st, 0);
        const uint8_t *v = sqlite3_column_blob(st, 1);
        memcpy(keys[n], k, 32);
        size_t z = 0;
        while (z < 32 && v[z] == 0) z++;
        if (evm_trie_rlp_put_bytes(&vals[n], v + z, 32 - z) != 0) goto out;
        kv[n].key = keys[n];
        kv[n].key_len = 32;
        kv[n].val = vals[n].p;
        kv[n].val_len = vals[n].len;
        n++;
    }
    if (n == 0) ret = evm_trie_empty_root(out);
    else ret = evm_trie_full_root(kv, n, 1, EVM_TRIE_FULL_SHA3_512, out);
out:
    for (size_t i = 0; i < 64; i++) evm_trie_rlp_buf_free(&vals[i]);
    sqlite3_finalize(st);
    return ret;
}

static int stored_storage_root(nodus_witness_t *w, const uint8_t addr[32],
                               uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT storage_root FROM evm_accounts WHERE addr = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/** deploy STORE, write 12 slots across 4 blocks (an overwrite and a
 *  delete among them), then a deposit; every item's code and Data out. */
static int scenario(fixture_t *fx, uint8_t store_out[32],
                    uint32_t codes[32], uint8_t datas[32][64],
                    size_t *n_out) {
    const int C = 1;
    uint64_t nc = 0;
    size_t n = 0;
    if (deploy(fx, C, nc++, RT_STORE, sizeof(RT_STORE), store_out) != 0)
        return -1;
    static uint8_t calls[3][256];
    for (int blk = 0; blk < 4; blk++) {
        tx_t t[3];
        for (int i = 0; i < 3; i++) {
            uint8_t data[64] = { 0 };
            data[31] = (uint8_t)(blk * 3 + i + 1);       /* slot           */
            data[63] = (uint8_t)(0x10 + blk * 3 + i);   /* value          */
            if (blk == 3 && i == 0) { data[31] = 2; data[63] = 0x99; }
            if (blk == 3 && i == 1) { data[31] = 3; data[63] = 0; }
            size_t cl = enc_call(calls[i], store_out, 0, 100000, nc++, data,
                                 64, NULL, NULL);
            if (evm_tx(fx, C, NODUS_RT_EVM_CALL, calls[i], (uint32_t)cl,
                       &t[i]) != 0)
                return -1;
        }
        nodus_v2_tx_result_t r[3];
        int rc = apply_txs(fx, t, 3, r);
        for (int i = 0; i < 3; i++) tx_free(&t[i]);
        if (rc != 0) return -1;
        for (int i = 0; i < 3; i++) {
            codes[n] = r[i].code;
            memcpy(datas[n], r[i].data, 64);
            n++;
        }
    }
    tx_t td;
    if (deposit_tx(fx, 2, 4, 0, &td) != 0) return -1;
    nodus_v2_tx_result_t r;
    codes[n] = apply_one(fx, &td, &r);
    memcpy(datas[n], r.data, 64);
    tx_free(&td);
    n++;
    *n_out = n;
    return 0;
}

static int test_trie_restart(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "trie") == 0, "EVM chain"); OK();
    uint8_t store[32];
    uint32_t codes[32];
    uint8_t datas[32][64];
    size_t n = 0;
    CHECK(scenario(&fx, store, codes, datas, &n) == 0, "scenario"); OK();
    for (size_t i = 0; i < n; i++)
        CHECK(codes[i] == NODUS_V2_TX_OK, "scenario item applied");
    OK();
    CHECK(slot_lo(fx.w, store, 2) == 0x99 && slot_lo(fx.w, store, 3) == 0 &&
          q1(fx.w, "SELECT COUNT(*) FROM evm_slots") == 9,
          "overwrite + delete landed"); OK();
    uint8_t inc[64], full[64];
    CHECK(stored_storage_root(fx.w, store, inc) == 0 &&
          full_storage_root(fx.w, store, full) == 0 &&
          memcmp(inc, full, 64) == 0,
          "incremental storage root == full rebuild (I4)"); OK();
    uint8_t er0[64], g0[64], er1[64], g1[64];
    CHECK(evm_root(fx.w, er0) == 0 &&
          nodus_witness_global_root_v2(fx.w, g0, NULL, NULL, NULL) == 0,
          "roots before");
    CHECK(fx_reopen(&fx) == 0, "reopen");
    CHECK(evm_root(fx.w, er1) == 0 &&
          nodus_witness_global_root_v2(fx.w, g1, NULL, NULL, NULL) == 0 &&
          memcmp(er0, er1, 64) == 0 && memcmp(g0, g1, 64) == 0,
          "restart reproduces the EVM and global roots"); OK();
    {
        uint8_t data[64] = { 0 }, call[256];
        data[31] = 0x30;
        data[63] = 1;
        size_t cl = enc_call(call, store, 0, 100000, 13, data, 64, NULL,
                             NULL);
        tx_t t;
        CHECK(evm_tx(&fx, 1, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0
              && apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK,
              "apply after restart"); OK();
        tx_free(&t);
        CHECK(stored_storage_root(fx.w, store, inc) == 0 &&
              full_storage_root(fx.w, store, full) == 0 &&
              memcmp(inc, full, 64) == 0, "I4 after restart"); OK();
    }
    CHECK(invariants_ok(fx.w), "invariants"); OK();
    fx_close(&fx);
    return 0;
}

static int test_twin(void) {
    fixture_t fa, fb;
    CHECK(fx_evm_ready(&fa, "twinA") == 0 && fx_evm_ready(&fb, "twinB") == 0,
          "two chains");
    /* the scenario's envelopes are built ONCE (on A) and every block is
     * applied to both chains byte for byte (g_mirror, above); apply_txs
     * fails on any rc / code / gas / Data difference */
    uint8_t sa[32];
    uint32_t ca[32];
    uint8_t da[32][64];
    size_t na = 0;
    g_mirror = &fb;
    int src = scenario(&fa, sa, ca, da, &na);
    g_mirror = NULL;
    CHECK(src == 0, "scenario on A mirrored to B: identical results and "
          "Data per block"); OK();
    CHECK(fa.h == fb.h, "same height"); OK();
    uint8_t ra[64], rb[64], ga[64], gb[64], la[64], lb[64];
    CHECK(evm_root(fa.w, ra) == 0 && evm_root(fb.w, rb) == 0 &&
          memcmp(ra, rb, 64) == 0, "identical EVM roots"); OK();
    CHECK(nodus_witness_global_root_v2(fa.w, ga, NULL, NULL, NULL) == 0 &&
          nodus_witness_global_root_v2(fb.w, gb, NULL, NULL, NULL) == 0 &&
          memcmp(ga, gb, 64) == 0, "identical global roots"); OK();
    CHECK(v2x_ledger_digest(fa.w, la) == 0 && v2x_ledger_digest(fb.w, lb) == 0
          && memcmp(la, lb, 64) == 0, "identical ledgers"); OK();
    fx_close(&fa);
    fx_close(&fb);
    return 0;
}

/* ══ 10. S16 → S17 at open; generation 2 unchanged ═══════════════════ */

static int test_upgrade(void) {
    /* (a) an S16 version-3 database: the EVM tables and the reserve do
     * not exist, user_version 16 — the production open path migrates it
     * and no root moves */
    {
        fixture_t fx;
        CHECK(fx_open(&fx, "s16", 1, 0) == 0, "a generation-2 chain");
        CHECK(fx_to(&fx, 4) == 0, "three blocks");
        static const char *const tables[] = {
            "evm_accounts", "evm_slots", "evm_code", "evm_code_refs",
            "evm_tickets", "evm_meta", "evm_trie_nodes", "evm_receipts",
            "evm_logs", "v2_evm_reserve" };
        for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
            char sql[96];
            snprintf(sql, sizeof(sql), "DROP TABLE %s", tables[i]);
            CHECK(sqlite3_exec(fx.w->db, sql, NULL, NULL, NULL) == SQLITE_OK,
                  "drop an S17 table");
        }
        CHECK(sqlite3_exec(fx.w->db, "PRAGMA user_version = 16", NULL, NULL,
                           NULL) == SQLITE_OK, "user_version 16");
        uint8_t g0[64], c0[64];
        CHECK(nodus_witness_v2_committed_global_root(fx.w, g0) == 0 &&
              core_root_now(fx.w, c0) == 0, "S16 roots");
        CHECK(fx_reopen(&fx) == 0, "the production open path"); OK();
        uint32_t ver = 0;
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 &&
              ver == NODUS_V2_SCHEMA_VERSION_S17, "migrated to S17"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_meta") == 0 &&
              q1(fx.w, "SELECT COUNT(*) FROM evm_accounts") == 0 &&
              q1(fx.w, "SELECT COUNT(*) FROM v2_evm_reserve") == 1 &&
              reserve_of(fx.w) == 0, "empty tables, reserve (1, 0)"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "type='index' AND name='evm_logs_by_height' AND "
                       "tbl_name='evm_logs'") == 1,
              "the evm_logs height index exists"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "type='index' AND name IN ('evm_receipts_by_pos', "
                       "'evm_logs_by_addr')") == 2,
              "the S17 rung creates the two cursor-scan indexes"); OK();
        uint8_t g1[64], c1[64], f1[64];
        CHECK(nodus_witness_v2_committed_global_root(fx.w, g1) == 0 &&
              nodus_witness_global_root_v2(fx.w, f1, NULL, NULL, NULL) == 0 &&
              core_root_now(fx.w, c1) == 0 && memcmp(g0, g1, 64) == 0 &&
              memcmp(g1, f1, 64) == 0 && memcmp(c0, c1, 64) == 0,
              "no root moved"); OK();
        CHECK(fx_to(&fx, 5) == 0 && roots_ok(fx.w) == 0,
              "the chain keeps applying"); OK();
        fx_close(&fx);
    }
    /* (a2) red-team 1 F4 — a database ALREADY at S17 built before the
     * cursor-scan indexes existed (the S17 migration returns early at 17,
     * v2_schema.c): the at-open ensure step (nodus_witness.c, after the
     * S17 rung) creates both with their exact key columns, the version
     * stays 17, a receipt row and every root are untouched, the chain
     * keeps applying; a second open is a no-op. An index of the SAME
     * NAME and another shape refuses the database (fail closed). */
    {
        fixture_t fx;
        CHECK(fx_open(&fx, "s17ix", 1, 0) == 0, "a generation-2 chain");
        CHECK(fx_to(&fx, 4) == 0, "three blocks");
        CHECK(sqlite3_exec(fx.w->db,
                  "DROP INDEX evm_receipts_by_pos; DROP INDEX evm_logs_by_addr;"
                  "INSERT INTO evm_receipts (intent_id, global_height, "
                  "item_index, receipt, digest) VALUES (zeroblob(64), 3, 0, "
                  "x'01', zeroblob(64))", NULL, NULL, NULL) == SQLITE_OK,
              "the previous build's S17: no scan indexes, one receipt row");
        uint8_t g0[64], c0[64];
        CHECK(nodus_witness_v2_committed_global_root(fx.w, g0) == 0 &&
              core_root_now(fx.w, c0) == 0, "S17 roots");
        CHECK(fx_reopen(&fx) == 0, "the production open path"); OK();
        uint32_t ver = 0;
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 &&
              ver == NODUS_V2_SCHEMA_VERSION_S17, "still S17"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM pragma_index_info("
                       "'evm_receipts_by_pos')") == 2 &&
              q1(fx.w, "SELECT COUNT(*) FROM pragma_index_info("
                       "'evm_receipts_by_pos') WHERE (seqno = 0 AND name = "
                       "'global_height') OR (seqno = 1 AND name = "
                       "'item_index')") == 2,
              "evm_receipts_by_pos (global_height, item_index)"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM pragma_index_info("
                       "'evm_logs_by_addr')") == 4 &&
              q1(fx.w, "SELECT COUNT(*) FROM pragma_index_info("
                       "'evm_logs_by_addr') WHERE (seqno = 0 AND name = "
                       "'addr') OR (seqno = 1 AND name = 'global_height') OR "
                       "(seqno = 2 AND name = 'intent_id') OR (seqno = 3 AND "
                       "name = 'log_index')") == 4,
              "evm_logs_by_addr (addr, global_height, intent_id, "
              "log_index)"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM evm_receipts") == 1,
              "the receipt row is untouched"); OK();
        uint8_t g1[64], c1[64];
        CHECK(nodus_witness_v2_committed_global_root(fx.w, g1) == 0 &&
              core_root_now(fx.w, c1) == 0 && memcmp(g0, g1, 64) == 0 &&
              memcmp(c0, c1, 64) == 0 && roots_ok(fx.w) == 0,
              "no root moved"); OK();
        CHECK(fx_reopen(&fx) == 0 &&
              nodus_witness_db_ensure_v2s17_indexes(fx.w) == 0,
              "a second open / ensure is a no-op"); OK();
        CHECK(sqlite3_exec(fx.w->db, "DELETE FROM evm_receipts", NULL, NULL,
                           NULL) == SQLITE_OK, "the test row removed");
        CHECK(fx_to(&fx, 5) == 0 && roots_ok(fx.w) == 0,
              "the chain keeps applying"); OK();
        CHECK(sqlite3_exec(fx.w->db,
                  "DROP INDEX evm_logs_by_addr; CREATE INDEX evm_logs_by_addr "
                  "ON evm_logs(addr)", NULL, NULL, NULL) == SQLITE_OK,
              "an index of the same name, another shape");
        CHECK(fx_reopen(&fx) != 0 && fx.w->db == NULL,
              "the database is refused (fail closed)"); OK();
        fx_close(&fx);
    }
    /* (b) a generation-2 chain: the compiled table vs a table holding
     * generations 1-2 only — every block byte-identical (in-binary) */
    {
        fixture_t fa, fb;
        static nodus_domain_runtime_t g12[4];
        size_t n_all = 0;
        const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n_all);
        CHECK(all && n_all >= 4, "the compiled table");
        memcpy(g12, all, sizeof(g12));
        CHECK(fx_open(&fa, "g2A", 1, 0) == 0 && fx_open(&fb, "g2B", 1, 0) == 0,
              "two generation-2 chains");
        fb.w->v2_runtime_table = g12;
        fb.w->v2_runtime_table_n = 4;
        for (uint64_t h = 1; h <= 4; h++) {
            nodus_v2_tx_result_t ra[1], rb[1];
            if (h == 4) {
                tx_t t;
                CHECK(spend_tx(&fa, 0, &t) == 0, "a SPEND");
                fb.nb[0]++;                 /* the same coin on B        */
                CHECK(apply_txs(&fa, &t, 1, ra) == 0 &&
                      apply_txs(&fb, &t, 1, rb) == 0, "both apply");
                CHECK(ra[0].code == NODUS_V2_TX_OK &&
                      ra[0].code == rb[0].code &&
                      ra[0].gas_used == rb[0].gas_used &&
                      ra[0].data_len == 0 && rb[0].data_len == 0,
                      "identical results, no Data");
                tx_free(&t);
            } else {
                CHECK(fx_to(&fa, h + 1) == 0 && fx_to(&fb, h + 1) == 0,
                      "idle");
            }
            uint8_t ga[64], gb[64];
            CHECK(nodus_witness_v2_committed_global_root(fa.w, ga) == 0 &&
                  nodus_witness_v2_committed_global_root(fb.w, gb) == 0 &&
                  memcmp(ga, gb, 64) == 0, "identical global roots");
        }
        OK();
        uint8_t la[64], lb[64];
        CHECK(v2x_ledger_digest(fa.w, la) == 0 &&
              v2x_ledger_digest(fb.w, lb) == 0 && memcmp(la, lb, 64) == 0,
              "identical ledgers"); OK();
        fx_close(&fa);
        fx_close(&fb);
    }
    return 0;
}

/* ══ 11. scan describer + the node-local address index (Nodus EVM P4-C) ═ */

/* One addr_history row of height h, (i, seq) order position `pos`.
 * @return 1 found / 0 none / -1 error. */
typedef struct {
    uint8_t  owner[64];
    char     kind[24];
    uint64_t amount;
    uint64_t fee;
    int      has_peer;
} ai_row_t;

static int ai_row_at(nodus_witness_t *w, uint64_t h, int pos, ai_row_t *r) {
    sqlite3_stmt *st = NULL;
    int ret = -1, rc;
    memset(r, 0, sizeof(*r));
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, kind, amount, fee, peer IS NOT NULL "
            "FROM addr_history WHERE h = ?1 ORDER BY i, seq "
            "LIMIT 1 OFFSET ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pos);
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { ret = 0; goto done; }
    if (rc != SQLITE_ROW || sqlite3_column_bytes(st, 0) != 64 ||
        sqlite3_column_bytes(st, 1) <= 0 ||
        sqlite3_column_bytes(st, 1) >= (int)sizeof(r->kind))
        goto done;
    memcpy(r->owner, sqlite3_column_blob(st, 0), 64);
    memcpy(r->kind, sqlite3_column_text(st, 1),
           (size_t)sqlite3_column_bytes(st, 1));
    r->amount = (uint64_t)sqlite3_column_int64(st, 2);
    r->fee = (uint64_t)sqlite3_column_int64(st, 3);
    r->has_peer = sqlite3_column_int(st, 4);
    ret = 1;
done:
    sqlite3_finalize(st);
    return ret;
}

static uint64_t ai_rows_at(nodus_witness_t *w, uint64_t h) {
    char sql[96];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM addr_history WHERE h = %llu",
             (unsigned long long)h);
    return q1(w, sql);
}

/* describe both legs of an applied EVM envelope */
static int describe_both(const tx_t *t, uint64_t h, dna_env_view_t *v,
                         nodus_rt_leg_desc_t *core,
                         nodus_rt_leg_desc_t *evm) {
    memset(v, 0, sizeof(*v));
    if (dna_env_decode(t->bytes, t->len, v) != 0 || v->leg_count != 2)
        return -1;
    if (nodus_rt_native_describe_leg(v, 0, h, t->intent, core) != 0)
        return -1;
    if (nodus_rt_native_describe_leg(v, 1, h, t->intent, evm) != 0)
        return -1;
    return 0;
}

/*
 * The scan describer (nodus_rt_native_describe_leg) on APPLIED EVM
 * envelopes, and the address index (nodus_witness_addr_index_env) writing
 * their rows instead of failing the block:
 *  - DEPOSIT 10: CORE leg = role DEPOSIT, reserve_in 10, the funding coin
 *    consumed, the 990 change created; the EVM leg describes with no
 *    native effect; the committed signer fp of the EVM leg is the key's
 *    (the EVM sender = its first 32 bytes); the index holds ONE row, the
 *    payer's fee row (no kind names a reserve lock).
 *  - WITHDRAW 3 to R: role RELEASE, reserve_out 3, the release coin LAST
 *    with owner R and amount 3 — its id is a LIVE utxo_set key (the
 *    describer and the exec share rtn_evmfund_release_coin); the index
 *    holds (R, release, 3, no peer) and the payer's fee row.
 *  - WITHDRAW 2 to the SIGNER itself: the release row is still written
 *    (it is not change) and carries the fee.
 *  - a CALL: role FEE, no reserve move; the index holds the fee row only.
 */
static int test_describe_addr_index(void) {
    static nodus_witness_host_t host;
    static nodus_identity_t     ident;
    fixture_t fx;
    const int B = 0, R = 1;
    uint64_t nb = 0, h;
    uint8_t call[512];
    size_t cl;
    tx_t t;
    ai_row_t r;
    char hexr[129], hexb[129];
    dna_env_view_t *v = calloc(1, sizeof(*v));
    nodus_rt_leg_desc_t *core = calloc(1, sizeof(*core));
    nodus_rt_leg_desc_t *evm  = calloc(1, sizeof(*evm));
    CHECK(v && core && evm, "alloc");

    CHECK(fx_evm_ready(&fx, "ai") == 0, "EVM chain"); OK();
    memset(&host, 0, sizeof(host));
    memset(&ident, 0, sizeof(ident));
    host.identity = &ident;
    host.config.addr_history_index = true;
    fx.w->host = &host;
    CHECK(nodus_witness_addr_index_enabled(fx.w) &&
          nodus_witness_addr_index_migrate(fx.w) == 0, "index on"); OK();
    hex_of(g_k[R].fp, hexr);
    hex_of(g_k[B].fp, hexb);

    /* DEPOSIT 10 */
    h = fx.h;
    CHECK(deposit_tx(&fx, B, 10, nb, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "deposit applied");
    OK();
    nb++;
    CHECK(describe_both(&t, h, v, core, evm) == 0, "deposit describes"); OK();
    CHECK(core->runtime_op == DNA_CORERULE_EVMFUND &&
          core->evm_role == NODUS_RT_EVMFUND_ROLE_DEPOSIT &&
          core->reserve_in == 10 && core->reserve_out == 0 &&
          core->n_consumed == 1 &&
          memcmp(core->consumed[0], t.coin, 64) == 0 &&
          core->n_created == 1 && core->created[0].amount == 990 &&
          memcmp(core->created[0].owner_hex, hexb, 128) == 0 &&
          coin_live(fx.w, core->created[0].id) == 1,
          "deposit: role, reserve_in, coin consumed, live change"); OK();
    CHECK(evm->domain_id == DNA_DOMAIN_EVM && evm->n_consumed == 0 &&
          evm->n_created == 0 && evm->evm_role == 0 &&
          evm->rec == NODUS_RT_DESC_REC_NONE,
          "the EVM leg moves no native coin"); OK();
    {
        uint8_t fp[64];
        uint16_t ns = 0;
        CHECK(nodus_rt_native_committed_signer_fp(v, 1, fp, &ns) == 0 &&
              ns == 1 && memcmp(fp, g_k[B].fp, 64) == 0 &&
              memcmp(fp, sender_of(B), 32) == 0,
              "committed signer fp = the key; [0..32] = the EVM sender");
        OK();
    }
    CHECK(ai_rows_at(fx.w, h) == 1 && ai_row_at(fx.w, h, 0, &r) == 1 &&
          memcmp(r.owner, g_k[B].fp, 64) == 0 &&
          strcmp(r.kind, "fee") == 0 && r.fee == FEE && r.amount == 0,
          "deposit indexed: the payer's fee row only"); OK();
    tx_free(&t);

    /* WITHDRAW 3 to R */
    h = fx.h;
    cl = enc_withdraw(call, 3, nb, g_k[R].fp);
    CHECK(evm_tx(&fx, B, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &t) == 0
          && apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "withdraw applied");
    OK();
    nb++;
    CHECK(describe_both(&t, h, v, core, evm) == 0, "withdraw describes");
    OK();
    CHECK(core->evm_role == NODUS_RT_EVMFUND_ROLE_RELEASE &&
          core->reserve_out == 3 && core->reserve_in == 0 &&
          core->n_created >= 1, "withdraw: role, reserve_out"); OK();
    {
        const nodus_rt_desc_coin_t *rel = &core->created[core->n_created - 1];
        CHECK(memcmp(rel->owner_hex, hexr, 128) == 0 && rel->amount == 3 &&
              rel->unlock_block == 0 && coin_live(fx.w, rel->id) == 1,
              "the release coin: R, 3, unlocked, the exec's utxo_set key");
        OK();
    }
    CHECK(ai_rows_at(fx.w, h) == 2, "withdraw: two rows"); OK();
    CHECK(ai_row_at(fx.w, h, 0, &r) == 1 &&
          memcmp(r.owner, g_k[R].fp, 64) == 0 &&
          strcmp(r.kind, "release") == 0 && r.amount == 3 && r.fee == 0 &&
          !r.has_peer, "(R, release, 3)"); OK();
    CHECK(ai_row_at(fx.w, h, 1, &r) == 1 &&
          memcmp(r.owner, g_k[B].fp, 64) == 0 &&
          strcmp(r.kind, "fee") == 0 && r.fee == FEE,
          "the payer's fee row"); OK();
    tx_free(&t);

    /* WITHDRAW 2 to the signer itself — not change */
    h = fx.h;
    cl = enc_withdraw(call, 2, nb, g_k[B].fp);
    CHECK(evm_tx(&fx, B, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &t) == 0
          && apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "self withdraw");
    OK();
    nb++;
    CHECK(ai_rows_at(fx.w, h) == 1 && ai_row_at(fx.w, h, 0, &r) == 1 &&
          memcmp(r.owner, g_k[B].fp, 64) == 0 &&
          strcmp(r.kind, "release") == 0 && r.amount == 2 && r.fee == FEE,
          "self withdraw: the release row, the fee on it"); OK();
    tx_free(&t);

    /* a CALL (to an empty account): role FEE, only the fee row */
    {
        uint8_t to[32];
        memset(to, 0x77, sizeof(to));
        h = fx.h;
        cl = enc_call(call, to, 0, 50000, nb, NULL, 0, NULL, NULL);
        CHECK(evm_tx(&fx, B, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0
              && apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "call applied");
        OK();
        nb++;
        CHECK(describe_both(&t, h, v, core, evm) == 0 &&
              core->evm_role == NODUS_RT_EVMFUND_ROLE_FEE &&
              core->reserve_in == 0 && core->reserve_out == 0,
              "call: role FEE, no reserve move"); OK();
        CHECK(ai_rows_at(fx.w, h) == 1 && ai_row_at(fx.w, h, 0, &r) == 1 &&
              strcmp(r.kind, "fee") == 0 && r.fee == FEE,
              "call indexed: the fee row only"); OK();
        tx_free(&t);
    }

    fx.w->host = NULL;
    fx_close(&fx);
    free(v);
    free(core);
    free(evm);
    return 0;
}

/* ══ 12. the per-leg trie batch (red-team-1 F6)════════════════════════ */

/** One effect through the EVM adapter's mutate. @return 0 / -1. */
static int tb_eff(nodus_witness_t *w, uint32_t op, uint8_t kind,
                  const uint8_t *key, uint16_t kl, const uint8_t *val,
                  uint32_t vl) {
    const nodus_adapter_op_t *o =
        nodus_adapter_op_lookup(&NODUS_RT_EVM_ADAPTER, op);
    if (!o) return -1;
    return NODUS_RT_EVM_ADAPTER.mutate(&NODUS_RT_EVM_ADAPTER,
                                       (struct nodus_witness *)w,
                                       DNA_DOMAIN_EVM, o, kind, key, kl,
                                       vl ? val : NULL, vl) ==
                   NODUS_ADAPTER_OK ? 0 : -1;
}

static void tb_addr(uint8_t a[32], uint8_t tag) { memset(a, tag, 32); }

static void tb_acct(uint8_t v[NODUS_RT_EVM_ACCT_LEN], uint64_t nonce,
                    uint8_t bal, uint64_t scount) {
    memset(v, 0, NODUS_RT_EVM_ACCT_LEN);
    put64(v, nonce);
    v[8 + 31] = bal;                          /* balance_wei (BE)       */
    memset(v + 40, 0xc5, 32);                 /* code_hash: code_size 0 */
    memset(v + 76, 0xa7, 64);                 /* code_digest            */
    put64(v + 140, scount);
}

static void tb_slot_key(uint8_t k[64], uint8_t tag, uint8_t slot) {
    tb_addr(k, tag);
    memset(k + 32, 0, 32);
    k[63] = slot;
}

static void tb_ticket(uint8_t id[64], uint8_t v[NODUS_RT_EVM_TICKET_LEN],
                      uint8_t n) {
    memset(id, 0, 64);
    id[0] = 0x7e;
    id[63] = n;
    memset(v, 0, NODUS_RT_EVM_TICKET_LEN);
    put64(v, 1000u + n);
    memset(v + 8, (int)(0x40 + n), 64);
}

/** Leg `leg` (0 or 1) of the fixed effect list, in the stream's
 *  (kind, op, key) order. Accounts 0x11 (40 slots), 0x22 (5 slots,
 *  emptied in leg 1), 0x33 (no slot, deleted in leg 1); tickets 1-4
 *  created, 1-2 deleted, 5 created; one META SET. */
static int tb_leg(nodus_witness_t *w, int leg) {
    uint8_t a[32], k[64], v[NODUS_RT_EVM_ACCT_LEN], s[32], id[64],
            tv[NODUS_RT_EVM_TICKET_LEN];
    if (leg == 0) {
        static const uint8_t tags[3] = { 0x11, 0x22, 0x33 };
        for (int i = 0; i < 3; i++) {
            tb_addr(a, tags[i]);
            tb_acct(v, 0, (uint8_t)(i + 1), i == 0 ? 40u : (i == 1 ? 5u : 0u));
            if (tb_eff(w, NODUS_RT_EVM_OP_ACCT, DNA_EFFECT_CREATE, a, 32, v,
                       NODUS_RT_EVM_ACCT_LEN) != 0)
                return -1;
        }
        for (int t = 0; t < 2; t++) {
            int n = t == 0 ? 40 : 5;
            for (int i = 1; i <= n; i++) {
                tb_slot_key(k, t == 0 ? 0x11 : 0x22, (uint8_t)i);
                memset(s, 0, 32);
                s[31] = (uint8_t)(0x80 + i);
                if (i % 7 == 0) s[0] = 0x01;         /* a 32-byte value    */
                if (tb_eff(w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_CREATE, k, 64,
                           s, 32) != 0)
                    return -1;
            }
        }
        for (uint8_t n = 1; n <= 4; n++) {
            tb_ticket(id, tv, n);
            if (tb_eff(w, NODUS_RT_EVM_OP_TICKET, DNA_EFFECT_CREATE, id, 64,
                       tv, NODUS_RT_EVM_TICKET_LEN) != 0)
                return -1;
        }
        uint8_t m[NODUS_RT_EVM_META_LEN];
        memset(m, 0, sizeof(m));
        m[31] = 0x21;                                /* wei_live           */
        m[63] = 0x09;                                /* wei_tickets        */
        uint8_t mk = 0x01;
        return tb_eff(w, NODUS_RT_EVM_OP_META, DNA_EFFECT_SET, &mk, 1, m,
                      NODUS_RT_EVM_META_LEN);
    }
    tb_ticket(id, tv, 5);
    if (tb_eff(w, NODUS_RT_EVM_OP_TICKET, DNA_EFFECT_CREATE, id, 64, tv,
               NODUS_RT_EVM_TICKET_LEN) != 0)
        return -1;
    tb_addr(a, 0x11);
    tb_acct(v, 1, 0x55, 29);
    if (tb_eff(w, NODUS_RT_EVM_OP_ACCT, DNA_EFFECT_SET, a, 32, v,
               NODUS_RT_EVM_ACCT_LEN) != 0)
        return -1;
    for (int i = 1; i <= 10; i++) {
        tb_slot_key(k, 0x11, (uint8_t)i);
        memset(s, 0, 32);
        s[31] = (uint8_t)(0x10 + i);
        if (tb_eff(w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_SET, k, 64, s, 32) != 0)
            return -1;
    }
    tb_addr(a, 0x33);
    if (tb_eff(w, NODUS_RT_EVM_OP_ACCT, DNA_EFFECT_DELETE, a, 32, NULL, 0)
            != 0)
        return -1;
    for (int i = 30; i <= 40; i++) {
        tb_slot_key(k, 0x11, (uint8_t)i);
        if (tb_eff(w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_DELETE, k, 64, NULL, 0)
                != 0)
            return -1;
    }
    for (int i = 1; i <= 5; i++) {
        tb_slot_key(k, 0x22, (uint8_t)i);
        if (tb_eff(w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_DELETE, k, 64, NULL, 0)
                != 0)
            return -1;
    }
    for (uint8_t n = 1; n <= 2; n++) {
        tb_ticket(id, tv, n);
        if (tb_eff(w, NODUS_RT_EVM_OP_TICKET, DNA_EFFECT_DELETE, id, 64, NULL,
                   0) != 0)
            return -1;
    }
    return 0;
}

/** RLP of a big-endian unsigned integer, minimal (design §6). */
static int tb_rlp_uint(evm_trie_rlp_buf *b, const uint8_t *be, size_t n) {
    size_t z = 0;
    while (z < n && be[z] == 0) z++;
    return evm_trie_rlp_put_bytes(b, be + z, n - z);
}

/** The account (`tickets` 0) or tickets (`tickets` 1) trie root rebuilt
 *  from the rows by the full-rebuild port, the leaves restated from
 *  design §6. @return 0 / -1. */
static int tb_full_root(nodus_witness_t *w, int tickets, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    const char *sql = tickets
        ? "SELECT ticket_id, amount_raw, dest_fp FROM evm_tickets "
          "ORDER BY ticket_id"
        : "SELECT addr, nonce, balance, code_hash, code_size, code_digest, "
          "storage_count, storage_root FROM evm_accounts ORDER BY addr";
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    enum { CAP = 16 };
    evm_trie_full_kv kv[CAP];
    uint8_t keys[CAP][64];
    evm_trie_rlp_buf vals[CAP];
    memset(vals, 0, sizeof(vals));
    size_t n = 0;
    int ret = -1, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n == CAP) goto out;
        evm_trie_rlp_buf *b = &vals[n];
        uint8_t u[8];
        size_t kl = tickets ? 64 : 32;
        memcpy(keys[n], sqlite3_column_blob(st, 0), kl);
        if (tickets) {
            put64(u, (uint64_t)sqlite3_column_int64(st, 1));
            if (tb_rlp_uint(b, u, 8) != 0 ||
                evm_trie_rlp_put_bytes(b, sqlite3_column_blob(st, 2), 64) != 0
                || evm_trie_rlp_wrap_list(b, 0) != 0)
                goto out;
        } else {
            uint8_t cs[4];
            uint64_t csz = (uint64_t)sqlite3_column_int64(st, 4);
            for (int i = 0; i < 4; i++)
                cs[i] = (uint8_t)(csz >> (24 - 8 * i));
            put64(u, (uint64_t)sqlite3_column_int64(st, 1));
            if (tb_rlp_uint(b, u, 8) != 0 ||
                tb_rlp_uint(b, sqlite3_column_blob(st, 2), 32) != 0 ||
                evm_trie_rlp_put_bytes(b, sqlite3_column_blob(st, 7), 64) != 0
                || evm_trie_rlp_put_bytes(b, sqlite3_column_blob(st, 3), 32)
                       != 0 ||
                tb_rlp_uint(b, cs, 4) != 0 ||
                evm_trie_rlp_put_bytes(b, sqlite3_column_blob(st, 5), 64) != 0)
                goto out;
            put64(u, (uint64_t)sqlite3_column_int64(st, 6));
            if (tb_rlp_uint(b, u, 8) != 0 || evm_trie_rlp_wrap_list(b, 0) != 0)
                goto out;
        }
        kv[n].key = keys[n];
        kv[n].key_len = kl;
        kv[n].val = b->p;
        kv[n].val_len = b->len;
        n++;
    }
    if (rc != SQLITE_DONE) goto out;
    ret = n == 0 ? evm_trie_empty_root(out)
                 : evm_trie_full_root(kv, n, 1, EVM_TRIE_FULL_SHA3_512, out);
out:
    for (size_t i = 0; i < CAP; i++) evm_trie_rlp_buf_free(&vals[i]);
    sqlite3_finalize(st);
    return ret;
}

/** The META row's two committed trie roots. @return 0 / -1. */
static int tb_meta_roots(nodus_witness_t *w, uint8_t acct[64],
                         uint8_t tkt[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT account_trie_root, tickets_root FROM evm_meta "
            "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int ret = -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == 64 && sqlite3_column_bytes(st, 1) == 64) {
        memcpy(acct, sqlite3_column_blob(st, 0), 64);
        memcpy(tkt, sqlite3_column_blob(st, 1), 64);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/** Every root of the two chains equal, and equal to the full rebuild.
 *  @return 0 / -1. */
static int tb_same_roots(nodus_witness_t *wa, nodus_witness_t *wb) {
    uint8_t aa[64], at[64], ba[64], bt[64], fa[64], ft[64];
    if (tb_meta_roots(wa, aa, at) != 0 || tb_meta_roots(wb, ba, bt) != 0 ||
        memcmp(aa, ba, 64) != 0 || memcmp(at, bt, 64) != 0)
        return -1;
    if (tb_full_root(wa, 0, fa) != 0 || tb_full_root(wa, 1, ft) != 0 ||
        memcmp(aa, fa, 64) != 0 || memcmp(at, ft, 64) != 0)
        return -1;
    static const uint8_t tags[2] = { 0x11, 0x22 };
    for (int i = 0; i < 2; i++) {
        uint8_t a[32], sa[64], sb[64], sf[64];
        tb_addr(a, tags[i]);
        if (stored_storage_root(wa, a, sa) != 0 ||
            stored_storage_root(wb, a, sb) != 0 ||
            full_storage_root(wa, a, sf) != 0 ||
            memcmp(sa, sb, 64) != 0 || memcmp(sa, sf, 64) != 0)
            return -1;
    }
    uint8_t ea[64], eb[64];
    if (evm_root(wa, ea) != 0 || evm_root(wb, eb) != 0 ||
        memcmp(ea, eb, 64) != 0)
        return -1;
    return 0;
}

static int test_trie_batch(void) {
    /* (a) root identity: batched (A) vs per-effect (B) */
    fixture_t fa, fb;
    CHECK(fx_evm_ready(&fa, "tbA") == 0 && fx_evm_ready(&fb, "tbB") == 0,
          "two EVM chains");
    for (int leg = 0; leg < 2; leg++) {
        CHECK(nodus_rt_evm_leg_begin((struct nodus_witness *)fa.w) == 0 &&
              nodus_rt_evm_leg_open((struct nodus_witness *)fa.w) == 1,
              "batch opens");
        CHECK(tb_leg(fa.w, leg) == 0, "the leg's effects (batched)");
        CHECK(nodus_rt_evm_leg_flush((struct nodus_witness *)fa.w) == 0 &&
              nodus_rt_evm_leg_open((struct nodus_witness *)fa.w) == 0,
              "flush commits and closes");
        CHECK(nodus_rt_evm_leg_open((struct nodus_witness *)fb.w) == 0 &&
              tb_leg(fb.w, leg) == 0, "the leg's effects (per effect)");
        OK();
        CHECK(tb_same_roots(fa.w, fb.w) == 0,
              "batched == per-effect == full rebuild: account, tickets, "
              "storage and EVM roots"); OK();
    }
    {
        uint8_t er[64], a[32], sr[64];
        tb_addr(a, 0x22);
        CHECK(evm_trie_empty_root(er) == 0 &&
              stored_storage_root(fa.w, a, sr) == 0 && memcmp(er, sr, 64) == 0,
              "the emptied storage trie is the empty root"); OK();
        tb_addr(a, 0x33);
        CHECK(stored_storage_root(fa.w, a, sr) != 0, "the deleted account "
              "has no row"); OK();
    }
    uint64_t na = q1(fa.w, "SELECT COUNT(*) FROM evm_trie_nodes");
    uint64_t nb = q1(fb.w, "SELECT COUNT(*) FROM evm_trie_nodes");
    CHECK(na != UINT64_MAX && nb != UINT64_MAX && na < nb,
          "the batched chain wrote fewer trie nodes (no intermediate "
          "roots)"); OK();

    /* (b) discard: nothing written, nothing left */
    {
        uint8_t d0[64], d1[64], ra[64], rt[64], ra1[64], rt1[64], er[64];
        uint64_t n0 = q1(fa.w, "SELECT COUNT(*) FROM evm_trie_nodes");
        CHECK(v2x_db_digest(fa.w, d0) == 0 &&
              tb_meta_roots(fa.w, ra, rt) == 0, "before");
        CHECK(sqlite3_exec(fa.w->db, "SAVEPOINT tb", NULL, NULL, NULL) ==
              SQLITE_OK, "savepoint");
        CHECK(nodus_rt_evm_leg_begin((struct nodus_witness *)fa.w) == 0,
              "batch opens");
        uint8_t k[64], s[32], id[64], tv[NODUS_RT_EVM_TICKET_LEN];
        for (int i = 41; i <= 60; i++) {
            tb_slot_key(k, 0x11, (uint8_t)i);
            memset(s, 0, 32);
            s[31] = (uint8_t)i;
            CHECK(tb_eff(fa.w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_CREATE, k, 64,
                         s, 32) == 0, "slot in the batch");
        }
        tb_ticket(id, tv, 9);
        CHECK(tb_eff(fa.w, NODUS_RT_EVM_OP_TICKET, DNA_EFFECT_CREATE, id, 64,
                     tv, NODUS_RT_EVM_TICKET_LEN) == 0, "ticket in the batch");
        OK();
        CHECK(q1(fa.w, "SELECT COUNT(*) FROM evm_trie_nodes") == n0 &&
              tb_meta_roots(fa.w, ra1, rt1) == 0 &&
              memcmp(ra, ra1, 64) == 0 && memcmp(rt, rt1, 64) == 0,
              "an open batch wrote no trie node and moved no root"); OK();
        CHECK(evm_root(fa.w, er) != 0, "state_root refuses while a batch "
              "is open"); OK();
        nodus_rt_evm_leg_discard((struct nodus_witness *)fa.w);
        CHECK(nodus_rt_evm_leg_open((struct nodus_witness *)fa.w) == 0,
              "discard closes the batch"); OK();
        CHECK(sqlite3_exec(fa.w->db, "ROLLBACK TO tb; RELEASE tb", NULL, NULL,
                           NULL) == SQLITE_OK &&
              v2x_db_digest(fa.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "rollback: the database is byte-identical"); OK();
        /* no residue: the same next leg on both chains lands equal roots */
        CHECK(nodus_rt_evm_leg_begin((struct nodus_witness *)fa.w) == 0,
              "a new batch opens");
        for (int i = 41; i <= 45; i++) {
            tb_slot_key(k, 0x22, (uint8_t)i);
            memset(s, 0, 32);
            s[31] = (uint8_t)i;
            CHECK(tb_eff(fa.w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_CREATE, k, 64,
                         s, 32) == 0 &&
                  tb_eff(fb.w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_CREATE, k, 64,
                         s, 32) == 0, "slot on both chains");
        }
        CHECK(nodus_rt_evm_leg_flush((struct nodus_witness *)fa.w) == 0 &&
              tb_same_roots(fa.w, fb.w) == 0,
              "after a discard the next batch matches the per-effect chain");
        OK();
        /* a failed mutation poisons its batch */
        CHECK(nodus_rt_evm_leg_begin((struct nodus_witness *)fa.w) == 0,
              "batch opens");
        tb_slot_key(k, 0x44, 1);                     /* no such account   */
        memset(s, 0, 32);
        s[31] = 1;
        CHECK(tb_eff(fa.w, NODUS_RT_EVM_OP_SLOT, DNA_EFFECT_CREATE, k, 64, s,
                     32) != 0, "a slot of a missing account is refused");
        CHECK(nodus_rt_evm_leg_flush((struct nodus_witness *)fa.w) != 0 &&
              nodus_rt_evm_leg_open((struct nodus_witness *)fa.w) == 0,
              "the poisoned batch does not commit and is closed"); OK();
        /* a leftover batch: begin refuses once, then opens */
        CHECK(nodus_rt_evm_leg_begin((struct nodus_witness *)fa.w) == 0 &&
              nodus_rt_evm_leg_begin((struct nodus_witness *)fa.w) != 0 &&
              nodus_rt_evm_leg_open((struct nodus_witness *)fa.w) == 0 &&
              nodus_rt_evm_leg_begin((struct nodus_witness *)fa.w) == 0,
              "begin over a leftover refuses and drops it");
        nodus_rt_evm_leg_discard((struct nodus_witness *)fa.w);
        OK();
    }
    fx_close(&fa);
    fx_close(&fb);

    /* (c) through the engine: flushed inside the leg, rolled back with
     * the block */
    {
        fixture_t fx;
        CHECK(fx_evm_ready(&fx, "tbC") == 0, "EVM chain");
        uint8_t store[32];
        CHECK(deploy(&fx, 1, 0, RT_STORE, sizeof(RT_STORE), store) == 0,
              "deploy STORE");
        uint8_t data[64] = { 0 }, call[256];
        data[31] = 0x05;
        data[63] = 0x77;
        size_t cl = enc_call(call, store, 0, 100000, 1, data, 64, NULL, NULL);
        tx_t t;
        CHECK(evm_tx(&fx, 1, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0,
              "CALL");
        nodus_v2_envelope_t v = { t.bytes, t.len };
        nodus_v2_tx_result_t res[1];
        nodus_v2_block_t b;
        mk_block(&b, fx.h, &v, 1);
        b.cmt.results = res;
        b.cmt.results_cap = 1;
        b.fail_at = V2AP_FAIL_BEFORE_COMMIT;
        CHECK(v2x_cmt_fault(fx.w, &b) == 0,
              "a block FAULTing after the EVM leg's flush leaves the database "
              "byte-identical"); OK();
        CHECK(nodus_rt_evm_leg_open((struct nodus_witness *)fx.w) == 0,
              "no batch is left open"); OK();
        CHECK(apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK &&
              slot_lo(fx.w, store, 5) == 0x77, "the same CALL then applies");
        OK();
        tx_free(&t);
        uint8_t inc[64], full[64];
        CHECK(stored_storage_root(fx.w, store, inc) == 0 &&
              full_storage_root(fx.w, store, full) == 0 &&
              memcmp(inc, full, 64) == 0 && roots_ok(fx.w) == 0 &&
              invariants_ok(fx.w),
              "storage root == full rebuild; committed == recomputed; "
              "invariants"); OK();
        fx_close(&fx);
    }
    return 0;
}

/* ══ 12b. the bridge refuses a sender that carries code (Kurultay #9) ══ */

/** SYNTHETIC COLLISION (Kurultay #9 item 1, docs/plans/decisions/
 *  2026-10-06-kurultay-9-evm-address-width-summary.md; the seam Astra
 *  named, astra-r1.md Q3): rewrite the EXISTING account at `addr` so its
 *  code fields name `code` (cl 0 = the empty code), its nonce, balance and
 *  storage count kept — no address collision is computed, the state one
 *  would produce is written. Outside any block, through the EVM adapter
 *  (tb_eff); the code chunk is stored first when absent. The domain head
 *  still holds the old root: the caller applies an EVM-touching block
 *  next, which re-anchors it. @return 0 / -1. */
static int seed_code(nodus_witness_t *w, const uint8_t addr[32],
                     const uint8_t *code, size_t cl) {
    static const uint8_t none[1] = { 0 };
    if (!code) code = none;
    sqlite3_stmt *st = NULL;
    uint8_t v[NODUS_RT_EVM_ACCT_LEN];
    memset(v, 0, sizeof(v));
    if (sqlite3_prepare_v2(w->db,
            "SELECT nonce, balance, storage_count FROM evm_accounts "
            "WHERE addr = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 1) == 32;
    if (ok) {
        put64(v, (uint64_t)sqlite3_column_int64(st, 0));
        memcpy(v + 8, sqlite3_column_blob(st, 1), 32);
        put64(v + 140, (uint64_t)sqlite3_column_int64(st, 2));
    }
    sqlite3_finalize(st);
    if (!ok) return -1;
    if (keccak256(code, cl, v + 40) != 0) return -1;
    v[72] = (uint8_t)(cl >> 24); v[73] = (uint8_t)(cl >> 16);
    v[74] = (uint8_t)(cl >> 8);  v[75] = (uint8_t)cl;
    if (qgp_sha3_512(code, cl, v + 76) != 0) return -1;
    if (cl > 0) {
        uint8_t ck[65];
        memcpy(ck, v + 76, 64);
        ck[64] = 0;
        if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM evm_code WHERE "
                               "digest = ?1", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, ck, 64, SQLITE_TRANSIENT);
        int have = sqlite3_step(st) == SQLITE_ROW ?
                   sqlite3_column_int(st, 0) : -1;
        sqlite3_finalize(st);
        if (have < 0) return -1;
        if (have == 0 &&
            tb_eff(w, NODUS_RT_EVM_OP_CODE, DNA_EFFECT_CREATE, ck, 65, code,
                   (uint32_t)cl) != 0)
            return -1;
    }
    return tb_eff(w, NODUS_RT_EVM_OP_ACCT, DNA_EFFECT_SET, addr, 32, v,
                  NODUS_RT_EVM_ACCT_LEN);
}

static int test_bridge_sender_code(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "bcode") == 0, "EVM chain"); OK();
    const int K = 0, O = 1, R = 2;
    const uint8_t *sk = sender_of(K);
    uint8_t call[512];
    size_t cl;
    uint32_t code = 0;
    tx_t t;
    nodus_v2_env_dry_run_t *d = calloc(1, sizeof(*d));
    CHECK(d != NULL, "alloc");

    /* control, no code: K deposits 10 and withdraws 1 to R */
    CHECK(deposit_tx(&fx, K, 10, 0, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK,
          "K deposits 10 (no code)"); OK();
    tx_free(&t);
    cl = enc_withdraw(call, 1, 1, g_k[R].fp);
    CHECK(evm_tx(&fx, K, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &t) == 0
          && apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK &&
          owned_with(fx.w, R, 1) == 1, "K withdraws 1 to R (no code)"); OK();
    tx_free(&t);
    CHECK(acct_nonce(fx.w, sk) == 2 && acct_balance_lo(fx.w, sk) == 9ull * Q,
          "K: nonce 2, balance 9 q"); OK();

    /* K's derived address now carries code (the synthetic collision);
     * O's DEPOSIT touches the EVM domain and re-anchors its head */
    CHECK(seed_code(fx.w, sk, RT_REVERT, sizeof(RT_REVERT)) == 0,
          "code seeded at K's derived address"); OK();
    CHECK(deposit_tx(&fx, O, 5, 0, &t) == 0 &&
          apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK,
          "O deposits (the EVM head re-anchors)"); OK();
    tx_free(&t);
    CHECK(invariants_ok(fx.w) && roots_ok(fx.w) == 0 &&
          acct_nonce(fx.w, sk) == 2 && acct_balance_lo(fx.w, sk) == 9ull * Q,
          "the seeded state is coherent: both invariants, committed root "
          "== recomputed, K's nonce and balance kept"); OK();
    const uint64_t r0 = reserve_of(fx.w);

    /* (a) WITHDRAW signed by K: refused by CheckTx (new entry + recheck)
     * and by the block, the ledger byte-identical (refused_one: EVM
     * accounts, META, CORE outputs, the reserve) */
    cl = enc_withdraw(call, 1, 2, g_k[R].fp);
    CHECK(evm_tx(&fx, K, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &t) == 0,
          "WITHDRAW built");
    CHECK(dry_ex(fx.w, &t, 0, d) == -1 && d->code == NODUS_V2_TX_ERR_EXEC,
          "CheckTx refuses a WITHDRAW from a sender with code"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &t, 1, d) == -1,
          "recheck refuses it too (the same pre-validation)"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC &&
          coin_live(fx.w, t.coin) == 1,
          "the block refuses it; the ledger is byte-identical"); OK();
    tx_free(&t);
    CHECK(acct_nonce(fx.w, sk) == 2 && acct_balance_lo(fx.w, sk) == 9ull * Q
          && owned_with(fx.w, R, 1) == 1 && reserve_of(fx.w) == r0,
          "K's account, R's outputs and the reserve unchanged"); OK();

    /* (b) DEPOSIT signed by K: refused likewise */
    CHECK(deposit_tx(&fx, K, 5, 2, &t) == 0, "DEPOSIT built");
    CHECK(dry_ex(fx.w, &t, 0, d) == -1 && d->code == NODUS_V2_TX_ERR_EXEC,
          "CheckTx refuses a DEPOSIT to a sender with code"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &t, 1, d) == -1, "recheck refuses it too"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(refused_one(&fx, &t, &code) == 0 && code == NODUS_V2_TX_ERR_EXEC &&
          coin_live(fx.w, t.coin) == 1,
          "the block refuses it; the coin stays live"); OK();
    tx_free(&t);
    CHECK(acct_nonce(fx.w, sk) == 2 && acct_balance_lo(fx.w, sk) == 9ull * Q
          && reserve_of(fx.w) == r0,
          "K's account and the reserve unchanged"); OK();

    /* (c) control on the same chain, after the refusals: a codeless
     * sender's WITHDRAW (O, nonce 1, 1 to R) is admitted by CheckTx and
     * lands — the refusals above were the code's alone, not a bridge that
     * stopped working. (The adapter refuses an ACCT SET that removes live
     * code — "ACCT SET replaces live code" — so the code is not stripped
     * from K's account; the codeless case of K itself is the control at
     * the top of this test.) */
    cl = enc_withdraw(call, 1, 1, g_k[R].fp);
    CHECK(evm_tx(&fx, O, NODUS_RT_EVM_WITHDRAW, call, (uint32_t)cl, &t) == 0,
          "O's WITHDRAW built");
    CHECK(dry_ex(fx.w, &t, 0, d) == 0 && d->code == NODUS_V2_TX_OK,
          "CheckTx admits a codeless sender's WITHDRAW"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(dry_ex(fx.w, &t, 1, d) == 0, "recheck admits it too"); OK();
    nodus_witness_v2_env_dry_run_free(d);
    CHECK(apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK &&
          owned_with(fx.w, R, 1) == 2 && acct_nonce(fx.w, sk) == 2 &&
          acct_balance_lo(fx.w, sk) == 9ull * Q &&
          reserve_of(fx.w) == r0 - 1u,
          "O's WITHDRAW lands; K untouched"); OK();
    tx_free(&t);
    CHECK(invariants_ok(fx.w) && roots_ok(fx.w) == 0,
          "invariants and roots at the end"); OK();
    free(d);
    fx_close(&fx);
    return 0;
}

/* ══ 13. the receipt index's BLOCK position (red-team 1 F12) ══════════ */

/* LOG1: MSTORE(0, 0x2a); LOG1(offset 0, size 32, topic 7); STOP */
static const uint8_t RT_LOG1[] = { 0x60, 0x2a, 0x60, 0x00, 0x52,
                                   0x60, 0x07, 0x60, 0x20, 0x60, 0x00, 0xa1,
                                   0x00 };

/*
 * One block through the REAL nodus_cmt_app_finalize_block (the host's
 * shape, v2x_cmt_host: BEGIN IMMEDIATE, the block-store record, the
 * request fields from it, COMMIT), with `n` raw items in block order.
 * codes[i] = ExecTxResult.code of position i. @return 0 committed / -1.
 */
static int finalize_items(fixture_t *fx, const uint8_t *const *items,
                          const size_t *lens, size_t n, uint32_t *codes) {
    nodus_cmt_app_ledger_t *app = calloc(1, sizeof(*app));
    cmt_genesis_doc_t *doc = calloc(1, sizeof(*doc));
    cmt_pb_bytes_t txs[8];
    nodus_abci_request_finalize_block_t req;
    nodus_abci_response_finalize_block_t resp;
    uint8_t hash[64], nvh[64], prop[32];
    uint64_t secs = 0;
    int ret = -1, open = 0;
    if (!app || !doc || n > 8) goto out;
    /* the one genesis input FinalizeBlock's bounds read: Block.MaxBytes
     * (nodus_cmt_app_ledger_init) — the reference default 22 020 096 */
    doc->has_consensus_params = true;
    doc->consensus_params.block.max_bytes = 22020096;
    if (nodus_cmt_app_ledger_init(app, fx->w, doc) != CMT_OK) goto out;
    if (sqlite3_exec(fx->w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
        != SQLITE_OK)
        goto out;
    open = 1;
    if (v2x_cmt_store_block(fx->w, fx->h, hash, nvh, prop, &secs) != 0)
        goto out;
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    for (size_t i = 0; i < n; i++) {
        txs[i].data = (uint8_t *)items[i];
        txs[i].len = lens[i];
    }
    req.txs = txs;
    req.txs_len = n;
    req.height = (int64_t)fx->h;
    req.time.seconds = (int64_t)secs;
    memcpy(req.hash, hash, 64);
    req.hash_len = 64;
    memcpy(req.next_validators_hash, nvh, 64);
    req.next_validators_hash_len = 64;
    memcpy(req.proposer_address, prop, 32);
    req.proposer_address_len = 32;
    if (nodus_cmt_app_finalize_block(app, &req, &resp) != CMT_OK ||
        resp.tx_results_len != n)
        goto out;
    for (size_t i = 0; i < n; i++) codes[i] = resp.tx_results[i].det.code;
    if (sqlite3_exec(fx->w->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto out;
    open = 0;
    fx->h++;
    ret = 0;
out:
    if (open) (void)sqlite3_exec(fx->w->db, "ROLLBACK", NULL, NULL, NULL);
    if (app) nodus_cmt_app_ledger_release(app);
    free(app);
    free(doc);
    return ret;
}

/*
 * An EVM CALL that logs, placed at block position 2 BEHIND two items that
 * are not envelopes (bytes nodus_witness_v2_classify_entry does not call
 * an envelope: FinalizeBlock codes them, the engine never sees them).
 * Through the REAL FinalizeBlock the envelope is the engine's envelope 0
 * but the block's item 2: evm_receipts.item_index — what evm_receipt
 * answers as "x" (handle_evm_receipt reads the row's item_index) — and
 * the evm_logs scan's "x" (nodus_witness_evm_logs_scan, the evm_logs
 * handler's rows) are 2, NOT the envelope ordinal 0; the receipt digest
 * equals the item's ExecTxResult.Data either way (item_index enters no
 * digest). Control: the engine lane WITHOUT the map (env_block_pos NULL,
 * every non-cometbft caller) keeps the ordinal.
 */
static int test_block_position(void) {
    fixture_t fx;
    CHECK(fx_evm_ready(&fx, "bpos") == 0, "EVM chain"); OK();
    const int A = 0;
    uint64_t na = 0;
    uint8_t logc[32];
    CHECK(deploy(&fx, A, na++, RT_LOG1, sizeof(RT_LOG1), logc) == 0,
          "deploy LOG1"); OK();

    uint8_t call[256];
    size_t cl = enc_call(call, logc, 0, 100000, na++, NULL, 0, NULL, NULL);
    tx_t t;
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0,
          "the logging CALL");
    static const uint8_t junk0[3] = { 0x00, 0x01, 0x02 };
    static const uint8_t junk1[5] = { 0xff, 0xfe, 0xfd, 0xfc, 0xfb };
    CHECK(nodus_witness_v2_classify_entry(junk0, sizeof(junk0)) !=
              NODUS_W_TX_V2_ENVELOPE &&
          nodus_witness_v2_classify_entry(junk1, sizeof(junk1)) !=
              NODUS_W_TX_V2_ENVELOPE,
          "the two leading items are not envelopes"); OK();
    const uint8_t *items[3] = { junk0, junk1, t.bytes };
    const size_t lens[3] = { sizeof(junk0), sizeof(junk1), t.len };
    uint32_t codes[3] = { 0, 0, 0 };
    uint64_t h = fx.h;
    CHECK(finalize_items(&fx, items, lens, 3, codes) == 0,
          "the block commits through FinalizeBlock"); OK();
    CHECK(codes[0] != 0 && codes[1] != 0 && codes[2] == NODUS_V2_TX_OK,
          "positions 0 and 1 refused, the CALL at 2 applied"); OK();

    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT item_index FROM evm_receipts WHERE "
             "global_height = %llu", (unsigned long long)h);
    CHECK(q1(fx.w, sql) == 2,
          "evm_receipt \"x\" (item_index) = the block position 2"); OK();
    {
        nodus_evm_logs_scan_t q;
        memset(&q, 0, sizeof(q));
        q.from.h = h;
        q.th = h;
        q.lim = 10;
        q.max_examined = 100;
        q.max_bytes = 1u << 20;
        q.gas_cap = UINT64_MAX / 4;
        nodus_evm_logs_page_t pg;
        CHECK(nodus_witness_evm_logs_scan(fx.w, &q, &pg) == 0 &&
              pg.n == 1 && pg.rows[0].h == h && pg.rows[0].x == 2 &&
              pg.rows[0].li == 0 && !pg.truncated &&
              pg.rows[0].n_topics == 1 && pg.rows[0].topics[0][31] == 7 &&
              pg.rows[0].data_len == 32 && pg.rows[0].data[31] == 0x2a,
              "evm_logs \"x\" = the block position 2"); OK();
        nodus_witness_evm_logs_page_free(&pg);
    }
    {
        uint8_t rc[4096], dg[64], mine[64];
        size_t rl = 0;
        CHECK(receipt_of(fx.w, h, 2, rc, sizeof(rc), &rl, dg) == 0 &&
              qgp_sha3_512(rc, rl, mine) == 0 && memcmp(mine, dg, 64) == 0 &&
              rc[16] == 1, "the receipt at (h, 2) hashes to its digest");
        OK();
    }
    tx_free(&t);

    /* control: the engine lane without the map keeps the ordinal */
    cl = enc_call(call, logc, 0, 100000, na++, NULL, 0, NULL, NULL);
    CHECK(evm_tx(&fx, A, NODUS_RT_EVM_CALL, call, (uint32_t)cl, &t) == 0,
          "a second logging CALL");
    h = fx.h;
    CHECK(apply_one(&fx, &t, NULL) == NODUS_V2_TX_OK, "engine lane");
    snprintf(sql, sizeof(sql), "SELECT item_index FROM evm_receipts WHERE "
             "global_height = %llu", (unsigned long long)h);
    CHECK(q1(fx.w, sql) == 0, "no map: the envelope ordinal 0"); OK();
    tx_free(&t);
    fx_close(&fx);
    return 0;
}

int main(void) {
    if (E_LEN <= 64) {
        fprintf(stderr, "test_v2_evm: needs DNAC_EPOCH_LENGTH > 64 (this "
                "build: %llu) — NOT RUN\n", (unsigned long long)E_LEN);
        return 1;
    }
    if (keys_make() != 0) {
        fprintf(stderr, "test_v2_evm: key generation failed\n");
        return 1;
    }
    int fails = 0;
    fails += test_shape();
    fails += test_edge();
    fails += test_vote_rules();
    fails += test_exec();
    fails += test_bridge();
    fails += test_pairing();
    fails += test_gas_sum();
    fails += test_checktx();
    fails += test_checktx_time();
    fails += test_d1_price0();
    fails += test_checktx_cli();
    fails += test_trie_restart();
    fails += test_twin();
    fails += test_upgrade();
    fails += test_describe_addr_index();
    fails += test_trie_batch();
    fails += test_bridge_sender_code();
    fails += test_block_position();
    if (fails) {
        fprintf(stderr, "test_v2_evm: %d section(s) FAILED (%d checks "
                "passed)\n", fails, g_checks);
        return 1;
    }
    printf("test_v2_evm: all %d checks passed\n", g_checks);
    return 0;
}
