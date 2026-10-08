/**
 * Nodus — DNAC Client Handlers
 *
 * Post-auth Tier 2 handlers for DNAC client methods.
 * Each handler decodes CBOR args from the raw payload, queries
 * witness DB, and sends a CBOR response via TCP.
 *
 * R3 W4 — dnac_spend is now SYNCHRONOUS on a version-3 chain: the Comet
 * mempool's CheckTx verdict IS the answer (see handle_dnac_spend below).
 * The closed lane's async COMMIT-triggered receipt (send_spend_result,
 * the leader/forward machinery) is deleted with it.
 *
 * Ported from dnac/src/witness/bft_main.c handler functions.
 */

#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_p2p.h"    /* bonded set + signed ADDR (F5) */
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_committee.h"
/* FLEET-TM-R3 W3 (package C2a, item 6) — the cometbft startup table's
 * mempool, for the CheckTx-immediate client-submit lane. */
#include "witness/nodus_witness_cmt_node.h"
#include "dnac/cmt_mem.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_tier3.h"   /* nodus_t3_tx_size_limit (was via peer.h) */
#include "transport/nodus_tcp.h"
#include "witness/nodus_witness_host.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_u128.h"
#include "crypto/utils/qgp_log.h"
#include "witness/nodus_witness_spend_preimage.h"
#include "nodus/nodus_chain_config.h"       /* HF-1: dnac_fee_info gas_price */
#include "dnac/dnac.h"                      /* DNAC_CFG_GAS_PRICE_RAW_PER_UNIT */
/* scan-v3 — dnac_v3_block: the wire's bounds (nodus.h, shared with the
 * client decoder), the version-3 tip and item classifier, the claim
 * nullifier derivation, the read-only leg describer and the envelope /
 * claim codecs. */
#include "nodus/nodus.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_rt_native.h"
#include "witness/nodus_witness_addr_index.h"   /* dnac_addr_history     */
#include "witness/nodus_witness_v2_claims.h"    /* HF-4: runtime_for     */
#include "witness/nodus_witness_runtime.h"      /* HF-4: generation      */
#include "witness/nodus_witness_v2_storage.h"   /* dnac_storage_status   */
#include "dnac/env_wire.h"
#include "dnac/manifest_wire.h"
#include "dnac/msig_wire.h"                 /* dnac_msig_* member gate */
#include "dnac/ledger_ids.h"
/* Nodus EVM P4-C — dnac_v3_block's "ev": the shared call / receipt codec
 * (always compiled, nodus/CMakeLists.txt — no EVM engine needed) */
#include "dnac/evm_call_wire.h"
#ifdef NODUS_EVM_ENABLED
/* Nodus EVM §18 — the EVM read RPC (the "Nodus EVM §18" section below) */
#include "witness/nodus_witness_rt_evm.h"
#include "client/nodus_v2_evm.h"
#include "dnac/evm_call_wire.h"
#include "evm/evm.h"
#include "evm/evm_gas.h"                     /* the rows/bytes → gas pins */
#include "crypto/hash/keccak256.h"
#include "witness/nodus_witness_v2_schema.h" /* the evm_logs cursor scan  */
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-DNAC"

/* Max UTXOs per query response */
#define DNAC_MAX_UTXO_RESULTS   100

/* Max ledger range entries per query */
#define DNAC_MAX_RANGE_RESULTS  100

/* Max history entries per owner query */
#define DNAC_MAX_HISTORY_RESULTS 100

/* Spend result status codes */
#define DNAC_STATUS_APPROVED   0
#define DNAC_STATUS_REJECTED   1
#define DNAC_STATUS_ERROR      2

/* Max validator entries returned per validator_list_query. Page size cap. */
#define DNAC_VALIDATOR_LIST_MAX_RESULTS   256

/* Max delegation rows returned per dnac_delegations query. Expected real-world
 * cardinality per delegator is small; 256 covers v1 scale with headroom. */
#define DNAC_MAX_DELEGATIONS_RESULTS      256

/* ── CBOR response helpers ───────────────────────────────────────── */

/**
 * Encode DNAC T2 response header:
 *   {"t": txn_id, "y": "r", "q": method, "r": { ... }}
 * Caller provides map_count for the "r" map.
 */
static void enc_dnac_response(cbor_encoder_t *enc, uint32_t txn_id,
                                const char *method, size_t r_map_count) {
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "t");  cbor_encode_uint(enc, txn_id);
    cbor_encode_cstr(enc, "y");  cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q");  cbor_encode_cstr(enc, method);
    cbor_encode_cstr(enc, "r");
    cbor_encode_map(enc, r_map_count);
}

/** Send CBOR error response using standard T2 format. */
static void send_error(struct nodus_tcp_conn *conn, uint32_t txn_id,
                         int code, const char *msg) {
    uint8_t buf[512];
    size_t len = 0;
    if (nodus_t2_error(txn_id, code, msg, buf, sizeof(buf), &len) == 0)
        nodus_tcp_send(conn, buf, len);
}

/* ── CBOR arg decoding helpers ───────────────────────────────────── */

/**
 * Decode a CBOR "a" (args) map from raw T2 payload.
 * Positions the decoder at the start of the args map entries.
 *
 * @param payload   Raw CBOR T2 message
 * @param len       Payload length
 * @param dec       [out] Decoder positioned at args map entries
 * @param args_count [out] Number of entries in args map
 * @return 0 on success, -1 if "a" key not found
 */
static int decode_args(const uint8_t *payload, size_t len,
                        cbor_decoder_t *dec, size_t *args_count) {
    cbor_decoder_init(dec, payload, len);

    cbor_item_t top = cbor_decode_next(dec);
    if (top.type != CBOR_ITEM_MAP) return -1;

    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) {
            cbor_decode_skip(dec);
            continue;
        }

        if (key.tstr.len == 1 && key.tstr.ptr[0] == 'a') {
            cbor_item_t args = cbor_decode_next(dec);
            if (args.type != CBOR_ITEM_MAP) return -1;
            *args_count = args.count;
            return 0;
        }

        cbor_decode_skip(dec);
    }

    return -1;  /* "a" key not found */
}

/** Match a CBOR text key against a C string. */
static bool key_match(const cbor_item_t *key, const char *name) {
    size_t nlen = strlen(name);
    return key->type == CBOR_ITEM_TSTR &&
           key->tstr.len == nlen &&
           memcmp(key->tstr.ptr, name, nlen) == 0;
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_nullifier — Check nullifier spend status
 *
 * Request:  "a": {"nullifier": bstr(64)}
 * Response: "r": {"spent": bool}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_nullifier(nodus_witness_t *w,
                                    struct nodus_tcp_conn *conn,
                                    const uint8_t *payload, size_t len,
                                    uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    const uint8_t *nullifier = NULL;
    size_t nullifier_len = 0;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "nullifier")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_NULLIFIER_LEN) {
                nullifier = val.bstr.ptr;
                nullifier_len = val.bstr.len;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!nullifier || nullifier_len != NODUS_T3_NULLIFIER_LEN) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing or invalid nullifier");
        return;
    }

    bool spent = nodus_witness_nullifier_exists(w, nullifier);

    /* Encode response */
    uint8_t buf[256];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_nullifier", 1);
    cbor_encode_cstr(&enc, "spent");
    cbor_encode_bool(&enc, spent);

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_ledger — Query ledger entry by tx_hash
 *
 * Request:  "a": {"hash": bstr(64)}
 * Response: "r": {"found":bool, "seq":N, "hash":bstr, "type":N,
 *                  "epoch":N, "ts":N, "nc":N}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_ledger(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 const uint8_t *payload, size_t len,
                                 uint32_t txn_id) {
    /* Auth gate (red-team F-S1, design 2026-05-09-cli-lookup-tx-design.md):
     * close enumeration leak — only authenticated peers may probe ledger. */
    if (!conn->peer_id_set) {
        send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                    "session not authenticated");
        return;
    }

    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    const uint8_t *hash = NULL;
    size_t hash_len = 0;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "hash")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN) {
                hash = val.bstr.ptr;
                hash_len = val.bstr.len;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!hash || hash_len != NODUS_T3_TX_HASH_LEN) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing or invalid tx_hash");
        return;
    }

    nodus_witness_ledger_entry_t entry;
    int rc = nodus_witness_ledger_get_by_hash(w, hash, &entry);

    uint8_t buf[512];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    if (rc != 0) {
        enc_dnac_response(&enc, txn_id, "dnac_ledger", 1);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, false);
    } else {
        enc_dnac_response(&enc, txn_id, "dnac_ledger", 7);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, true);
        cbor_encode_cstr(&enc, "seq");
        cbor_encode_uint(&enc, entry.sequence);
        cbor_encode_cstr(&enc, "hash");
        cbor_encode_bstr(&enc, entry.tx_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "type");
        cbor_encode_uint(&enc, entry.tx_type);
        cbor_encode_cstr(&enc, "epoch");
        cbor_encode_uint(&enc, entry.epoch);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, entry.timestamp);
        cbor_encode_cstr(&enc, "nc");
        cbor_encode_uint(&enc, entry.nullifier_count);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_supply — Query supply state
 *
 * Request:  "a": {}
 * Response: "r": {"genesis":N, "burned":N, "current":N, "last_seq":N,
 *                 "chain_id":bstr[32] (legacy, 16 real bytes + 16 zeros),
 *                 "chain_id32":bstr[32] (D-16 rev 7, W4-CC — ADDITIVE,
 *                 present only when w->v2_successor: the full 32-byte
 *                 derived chain id, the SAME value the T3 wire's
 *                 verbs 35-41 bind as their frame's chain_id. This is a
 *                 client-server RPC field only — no consensus wire
 *                 carries it. nodus-cli's `chain-config propose` reads
 *                 it so the operator never has to paste a chain id by
 *                 hand.),
 *                 "tip":N (scan-v3, ADDITIVE, successor only: the
 *                 committed version-3 height MAX(v2_blocks.global_height)
 *                 — the explorer's sync bound),
 *                 "reward_pool":N, "treasury":[N × 9], "unclaimed":N
 *                 (decision 2026-09-30-scan-supply-buckets.md, ADDITIVE,
 *                 successor only and only when the supply row exists:
 *                 the validator reward reserve left, v2_treasury.balance
 *                 of pool 1..9 in order, and the native coin's unclaimed
 *                 distribution total — wire and meaning in nodus.h
 *                 beside nodus_client_dnac_supply_buckets)}
 *
 * Reply size, successor arm, worst case (every uint 9 bytes, txn_id 5):
 * envelope 29 + genesis 17 + burned 16 + current 17 + last_seq 18 +
 * chain_id 43 + chain_id32 45 + tip 13 + reward_pool 21 + treasury 91 +
 * unclaimed 19 = 329 bytes of the 512-byte buffer.
 * ════════════════════════════════════════════════════════════════════ */

_Static_assert(NODUS_WITNESS_SUPPLY_TREASURY_POOLS == NODUS_DNAC_TREASURY_POOLS,
               "the dnac_supply treasury array is the public pool count");

static void handle_dnac_supply(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 uint32_t txn_id) {
    nodus_witness_supply_t supply;
    nodus_witness_supply_view_t view;
    int rc;

    memset(&view, 0, sizeof(view));
    if (w->v2_successor) {
        /* scan-v3 "tip" (decision 2026-09-28-scan-v3-query.md (2)) and
         * the supply buckets (decision 2026-09-30-scan-supply-buckets.md)
         * are read with the supply row at ONE reading moment
         * (nodus_witness_supply_view_get), so `current` and the buckets
         * can be subtracted from each other. A fault answers an error,
         * never zeros: a 0 tip would tell the explorer the chain has no
         * blocks, a 0 bucket would inflate the circulating figure. */
        if (nodus_witness_supply_view_get(w, &view) != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "supply state unreadable");
            return;
        }
        supply = view.supply;
        rc = view.has_supply ? 0 : 1;
    } else {
        rc = nodus_witness_supply_get(w, &supply);
    }
    /* No supply row (pre-genesis): there is no reward_pool to report, so
     * the bucket keys are left out rather than sent as zeros. */
    bool buckets = w->v2_successor && rc == 0;
    size_t rcount = w->v2_successor ? (buckets ? 10 : 7) : 5;

    uint8_t buf[512];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    if (rc != 0) {
        enc_dnac_response(&enc, txn_id, "dnac_supply", rcount);
        cbor_encode_cstr(&enc, "genesis");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "burned");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "current");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "last_seq");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "chain_id");
        cbor_encode_bstr(&enc, w->chain_id, 32);
    } else {
        enc_dnac_response(&enc, txn_id, "dnac_supply", rcount);
        cbor_encode_cstr(&enc, "genesis");
        cbor_encode_uint(&enc, supply.genesis_supply);
        cbor_encode_cstr(&enc, "burned");
        cbor_encode_uint(&enc, supply.total_burned);
        cbor_encode_cstr(&enc, "current");
        cbor_encode_uint(&enc, supply.current_supply);
        cbor_encode_cstr(&enc, "last_seq");
        cbor_encode_uint(&enc, supply.last_sequence);
        cbor_encode_cstr(&enc, "chain_id");
        cbor_encode_bstr(&enc, w->chain_id, 32);
    }
    if (w->v2_successor) {
        cbor_encode_cstr(&enc, "chain_id32");
        cbor_encode_bstr(&enc, w->v2_chain32, 32);
        cbor_encode_cstr(&enc, "tip");
        cbor_encode_uint(&enc, view.tip);
    }
    if (buckets) {
        cbor_encode_cstr(&enc, "reward_pool");
        cbor_encode_uint(&enc, view.supply.reward_pool);
        cbor_encode_cstr(&enc, "treasury");
        cbor_encode_array(&enc, NODUS_WITNESS_SUPPLY_TREASURY_POOLS);
        for (size_t i = 0; i < NODUS_WITNESS_SUPPLY_TREASURY_POOLS; i++)
            cbor_encode_uint(&enc, view.treasury[i]);
        cbor_encode_cstr(&enc, "unclaimed");
        cbor_encode_uint(&enc, view.unclaimed);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }
}

/* ══════════════════════���═════════════════════════════════════════════
 * dnac_fee_info — Return current dynamic fee parameters
 *
 * Response: { base_fee, mempool, min_fee, gas_price, token_create_fee }
 * Client uses min_fee directly when building TX.
 *
 * token_create_fee (final pre-testnet wipe W-C, decision 2026-09-28-
 * token-create-fee-governance.md) = the committed TOKEN_CREATE_FEE_RAW
 * (chain_config param 6) active at tip + 1; with no row active, the
 * compiled NODUS_W_TOKEN_CREATE_FEE (a version-4 genesis always writes
 * the height-0 row, so that arm is a pre-genesis node or an older
 * chain). Same fault rule as gas_price: a read fault is an error, never
 * a fabricated value. An older client decoder skips the unknown key.
 *
 * gas_price (HF-1, decision 2026-09-25-gas-price.md "HF-1 O4": the CLI
 * price source) = the committed GAS_PRICE_RAW_PER_UNIT active at tip + 1
 * — the height the next envelope is judged at by CheckTx — 0 when no row
 * is active (the rule is off). A client builds fee = max(min_fee,
 * res_max_total_units × gas_price). An older server sends no such key;
 * the client decoder then leaves it 0, which again means "rule off".
 * A height or price READ FAULT answers an error, never a gas_price of 0:
 * a fabricated 0 would tell the client the rule is off and it would
 * build an envelope every node refuses.
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_fee_info(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn,
                                  uint32_t txn_id) {
    /* R3 W4 — there is no local mempool on the version-3 lane (the Comet
     * mempool replaces it, and its depth is not a fee input — CheckTx
     * admission does not read it either). The surge term is therefore
     * always 0 and min_fee always equals base_fee; kept as a formula
     * rather than folded to a constant so the wire shape (the "mempool"
     * key) and the surge-step constant stay meaningful if a future engine
     * re-derives this from the Comet mempool's own size. */
    int mp_count = 0;
    uint64_t base_fee = NODUS_W_BASE_TX_FEE;
    uint64_t min_fee = base_fee * (1 + (uint64_t)mp_count / NODUS_W_FEE_SURGE_STEP);

    /* HF-1: the price at tip + 1, read on the CHECKED height accessor
     * (the fail-open nodus_witness_block_height answers 0 on a fault,
     * which would ask for the price at height 1). A node with no chain
     * open yet (pre-genesis: chain_id all zero, db NULL — the checked
     * accessor's first arm) holds no chain_config rows at all: 0 is the
     * true answer there, and get_u64 would refuse a NULL db. */
    uint64_t gas_price = 0;
    uint64_t tip = 0;
    if (nodus_witness_block_height_checked(w, &tip) != 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "chain height unreadable");
        return;
    }
    if (w->db &&
        nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
                                   tip + 1, 0ULL, &gas_price) < 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "gas price unreadable");
        return;
    }
    /* W-C: the token-creation fee at tip + 1, the same accessor and the
     * same fault rule. The default is the compiled floor, never 0. */
    uint64_t token_create_fee = NODUS_W_TOKEN_CREATE_FEE;
    if (w->db &&
        nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_TOKEN_CREATE_FEE_RAW,
                                   tip + 1, NODUS_W_TOKEN_CREATE_FEE,
                                   &token_create_fee) < 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "token-create fee unreadable");
        return;
    }

    /* HF-4 (design §2 Price: "dnac_fee_info returns the computed tier
     * prices and any scheduled price row"): "np" = the four COMPUTED
     * prices at tip + 1 for names of 3 / 4 / 5 / 6+ characters (the
     * engine's own fold, dnac_name_price_for_len over params 10-13 with
     * the compiled defaults); "ns" = the committed params-10..13 rows
     * whose effective height is above tip + 1, ascending (effective,
     * param), at most NODUS_DNAC_NAME_SCHED_MAX — each {"p" u8, "v" u64,
     * "e" u64}. Same fault rule: unreadable = an error reply. Older
     * clients skip the two unknown keys. */
    uint64_t tiers[4] = { DNAC_NAME_PRICE_3P_DEFAULT,
                          DNAC_NAME_PRICE_4P_DEFAULT,
                          DNAC_NAME_PRICE_5P_DEFAULT,
                          DNAC_NAME_PRICE_6P_DEFAULT };
    struct { uint8_t p; uint64_t v, e; } sched[NODUS_DNAC_NAME_SCHED_MAX];
    size_t n_sched = 0;
    if (w->db) {
        for (int k = 0; k < 4; k++) {
            if (nodus_chain_config_get_u64(
                    w, (uint8_t)(DNAC_CFG_NAME_PRICE_3P + k), tip + 1,
                    tiers[k], &tiers[k]) < 0) {
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                           "name price unreadable");
                return;
            }
        }
        sqlite3_stmt *st = NULL;
        int ok = 0;
        if (sqlite3_prepare_v2(w->db,
                "SELECT param_id, new_value, effective_block FROM "
                "chain_config_history WHERE param_id BETWEEN ?1 AND ?2 "
                "AND effective_block > ?3 "
                "ORDER BY effective_block ASC, param_id ASC LIMIT ?4",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int(st, 1, (int)DNAC_CFG_NAME_PRICE_3P);
            sqlite3_bind_int(st, 2, (int)DNAC_CFG_NAME_PRICE_6P);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)(tip + 1));
            sqlite3_bind_int(st, 4, (int)NODUS_DNAC_NAME_SCHED_MAX);
            int rc;
            ok = 1;
            while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
                sqlite3_int64 v = sqlite3_column_int64(st, 1);
                sqlite3_int64 e = sqlite3_column_int64(st, 2);
                if (v < 0 || e < 0) { ok = 0; break; }
                sched[n_sched].p = (uint8_t)sqlite3_column_int(st, 0);
                sched[n_sched].v = (uint64_t)v;
                sched[n_sched].e = (uint64_t)e;
                n_sched++;
            }
            if (ok && rc != SQLITE_DONE) ok = 0;
        }
        sqlite3_finalize(st);
        if (!ok) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                       "scheduled name prices unreadable");
            return;
        }
    }

    /* 7 keys: the 5 scalar keys (well inside 256 bytes) + "np" (4 × 9)
     * + "ns" (up to NODUS_DNAC_NAME_SCHED_MAX × ~25 bytes); the rlen
     * check below still refuses an overflow rather than sending a
     * truncated map. */
    uint8_t buf[256 + 64 + NODUS_DNAC_NAME_SCHED_MAX * 32];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    enc_dnac_response(&enc, txn_id, "dnac_fee_info", 7);
    cbor_encode_cstr(&enc, "base_fee");
    cbor_encode_uint(&enc, base_fee);
    cbor_encode_cstr(&enc, "mempool");
    cbor_encode_uint(&enc, (uint64_t)mp_count);
    cbor_encode_cstr(&enc, "min_fee");
    cbor_encode_uint(&enc, min_fee);
    cbor_encode_cstr(&enc, "gas_price");
    cbor_encode_uint(&enc, gas_price);
    cbor_encode_cstr(&enc, "token_create_fee");
    cbor_encode_uint(&enc, token_create_fee);
    cbor_encode_cstr(&enc, "np");
    cbor_encode_array(&enc, 4);
    for (size_t len_i = 3; len_i <= 6; len_i++)
        cbor_encode_uint(&enc, dnac_name_price_for_len(tiers, len_i));
    cbor_encode_cstr(&enc, "ns");
    cbor_encode_array(&enc, n_sched);
    for (size_t k = 0; k < n_sched; k++) {
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "p"); cbor_encode_uint(&enc, sched[k].p);
        cbor_encode_cstr(&enc, "v"); cbor_encode_uint(&enc, sched[k].v);
        cbor_encode_cstr(&enc, "e"); cbor_encode_uint(&enc, sched[k].e);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_utxo — Query UTXOs by owner fingerprint
 *
 * Request:  "a": {"owner": cstr, "max": uint}
 * Response: "r": {"count":N, "utxos":[{...},...]}
 * ════════════════════════════════════════════════════════════════════ */

static void dnac_utxo_answer_send(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn,
                                  uint32_t txn_id, const char *method,
                                  const nodus_witness_utxo_entry_t *utxos,
                                  int count, bool with_trunc, bool trunc);

static void handle_dnac_utxo(nodus_witness_t *w,
                               struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len,
                               uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    char owner[256] = {0};
    int max_results = DNAC_MAX_UTXO_RESULTS;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "owner")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_TSTR && val.tstr.len > 0) {
                size_t clen = val.tstr.len < sizeof(owner) - 1
                              ? val.tstr.len : sizeof(owner) - 1;
                memcpy(owner, val.tstr.ptr, clen);
                owner[clen] = '\0';
            }
        } else if (key_match(&key, "max")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                max_results = (int)val.uint_val;
                if (max_results <= 0 || max_results > DNAC_MAX_UTXO_RESULTS)
                    max_results = DNAC_MAX_UTXO_RESULTS;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (owner[0] == '\0') {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing owner field");
        return;
    }

    /* C11 fix: require owner == authenticated session fingerprint */
    if (!conn->peer_id_set) {
        send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                    "session not authenticated");
        return;
    }
    {
        char session_hex[NODUS_KEY_HEX_LEN];
        for (int i = 0; i < NODUS_KEY_BYTES; i++)
            snprintf(session_hex + i * 2, NODUS_KEY_HEX_LEN - i * 2, "%02x",
                     conn->peer_id.bytes[i]);
        session_hex[128] = '\0';
        if (strcmp(owner, session_hex) != 0) {
            send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                        "owner must match authenticated session fingerprint");
            return;
        }
    }

    nodus_witness_utxo_entry_t *utxos = calloc((size_t)max_results,
                                                  sizeof(nodus_witness_utxo_entry_t));
    if (!utxos) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    int count = 0;
    int utxo_rc = nodus_witness_utxo_by_owner(w, owner, utxos, max_results, &count);
    QGP_LOG_DEBUG(LOG_TAG, "dnac_utxo: owner=%.16s... db=%p rc=%d count=%d",
                  owner, (void*)w->db, utxo_rc, count);

    dnac_utxo_answer_send(w, conn, txn_id, "dnac_utxo", utxos, count,
                          false, false);
    free(utxos);
}

/* The dnac_utxo answer body, shared by dnac_utxo and dnac_msig_utxo so
 * the two answer the same keys with the same per-entry encoding. Encodes
 * the T2 response for `count` entries of `utxos` under method name
 * `method` and sends it (or an INTERNAL_ERROR). `with_trunc` false =
 * exactly the three top-level keys dnac_utxo has always sent; true = the
 * same three, then a fourth, "trunc" (bool) = `trunc`, LAST, so the first
 * three are positionally identical. Does not free `utxos`. */
static void dnac_utxo_answer_send(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn,
                                  uint32_t txn_id, const char *method,
                                  const nodus_witness_utxo_entry_t *utxos,
                                  int count, bool with_trunc, bool trunc) {
    /* Phase 2 / Task 38 defined a per-UTXO proof block. Its wire keys
     * STAY (short CBOR keys to match existing conventions "n", "tid",
     * "bh"):
     *   pr_s : bstr — flat sibling buffer (depth * 64 bytes)
     *   pr_p : uint — position bitfield
     *   pr_d : uint — proof depth
     *   sr   : bstr — 64-byte root
     * but since the root-layout round (K3) they always carry depth 0, an
     * empty pr_s and an all-zero sr — see the loop below. The top-level
     * response still carries the latest committed block_height. */
    uint64_t latest_height = nodus_witness_block_height(w);

    /* Per UTXO we encode at worst:
     *   8 base fields  ≈ 256 B (O15B §7 added "ub", a u64 ⇒ ≤ 12 B more;
     *                   the 256 B line item already had ample slack and the
     *                   2560 B per-entry round-up is unchanged)
     *   pr_s siblings  ≤ 32 * 64  = 2048 B (always 0 B since the
     *                   root-layout round; the budget is left as it was)
     *   pr_p / pr_d    ≈ 16 B
     *   sr             ≈ 70 B
     *   CBOR overhead  ≈ 64 B
     * ⇒ round to 2560 B per entry, plus 512 B top-level overhead. */
    size_t buf_size = 512 + ((size_t)count * 2560);
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, method, with_trunc ? 4 : 3);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);

    cbor_encode_cstr(&enc, "block_height");
    cbor_encode_uint(&enc, latest_height);

    cbor_encode_cstr(&enc, "utxos");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        /* Root-layout round (K3, 2026-09-25): the proof fields STAY on the
         * wire but always carry the degraded entry this handler already
         * emitted when no proof could be built — depth 0, no siblings,
         * zero positions, all-zero root. The proof it used to build
         * (nodus_witness_merkle_build_proof) anchored to the legacy
         * five-input state_root, which no block header carries, and the
         * client verifies only when depth > 0 AND a verified anchor is
         * installed (dnac/src/nodus/tcp_client.c) — no code installs
         * one. A client therefore stores the coin unverified, exactly as
         * before. A real UTXO proof needs a new design bound to the V2
         * global root (design doc, Threat Model "out of scope"). */
        uint8_t state_root[NODUS_MERKLE_HASH_LEN];
        memset(state_root, 0, sizeof(state_root));

        /* O15B §7 — 12 entries: the 11 shipped fields plus "ub".
         *
         * "ub" is the coin's unlock_block. Adding it is a client-server RPC
         * change only: no consensus wire, no transaction format, no block
         * header, no root. It is a pure ADDITION to a CBOR map, so an older
         * client that iterates keys and skips unknown ones is unaffected.
         *
         * It is required because the response already carries the chain's
         * "block_height" but gave the client nothing to compare it against,
         * so a wallet could not implement the very rule consensus enforces
         * (Rule D, nodus_witness_verify.c:730). */
        cbor_encode_map(&enc, 12);
        cbor_encode_cstr(&enc, "n");
        cbor_encode_bstr(&enc, utxos[i].nullifier, NODUS_T3_NULLIFIER_LEN);
        cbor_encode_cstr(&enc, "owner");
        cbor_encode_cstr(&enc, utxos[i].owner);
        cbor_encode_cstr(&enc, "amount");
        cbor_encode_uint(&enc, utxos[i].amount);
        cbor_encode_cstr(&enc, "tid");
        cbor_encode_bstr(&enc, utxos[i].token_id, 64);
        cbor_encode_cstr(&enc, "hash");
        cbor_encode_bstr(&enc, utxos[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "idx");
        cbor_encode_uint(&enc, utxos[i].output_index);
        cbor_encode_cstr(&enc, "bh");
        cbor_encode_uint(&enc, utxos[i].block_height);
        cbor_encode_cstr(&enc, "ub");
        cbor_encode_uint(&enc, utxos[i].unlock_block);
        /* pr_s: a zero-length bstr (depth 0 ⇒ no siblings). A non-NULL
         * pointer is passed so the zero-byte copy never sees NULL. */
        cbor_encode_cstr(&enc, "pr_s");
        cbor_encode_bstr(&enc, state_root, 0);
        cbor_encode_cstr(&enc, "pr_p");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "pr_d");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "sr");
        cbor_encode_bstr(&enc, state_root, NODUS_MERKLE_HASH_LEN);
    }

    if (with_trunc) {
        cbor_encode_cstr(&enc, "trunc");
        cbor_encode_bool(&enc, trunc);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_msig_utxo / dnac_msig_addr_history — a multisig VAULT MEMBER
 * reads the vault address's coins and history.
 *
 * Design docs/plans/2026-09-29-general-multisig-design.md §8 + §8.6 rev 2
 * (Kurultay #15, approved by the operator 2026-10-08:
 * docs/plans/decisions/2026-10-08-kurultay-15-vault-member-query-
 * summary.md). The wire is specified ONCE, in include/nodus/nodus.h
 * beside nodus_client_dnac_msig_utxo / nodus_client_dnac_msig_addr_
 * history. dnac_utxo and dnac_addr_history are NOT changed (C11,
 * d40b89d1): separate methods, so a node without them answers
 * PROTOCOL_ERROR "unknown DNAC method" — distinguishable from "not a
 * member" (NOT_AUTHENTICATED).
 *
 * THE GATE (msig_query_open, shared by both), in this order:
 *  a. the session is authenticated (conn->peer_id_set) — before any
 *     argument is decoded or anything is hashed;
 *  b. every argument decoded STRICTLY: each known key at most once, the
 *     right type, in bounds; unknown keys skipped; `owner` exactly 128
 *     lowercase hex; `msig` a bstr of 1..DNA_MSIG_MAX_DESC_LEN bytes —
 *     a bad `msig` is refused, never treated as absent → PROTOCOL_ERROR;
 *  c. ONCE, after the loop: dna_msig_desc_parse(msig) == 0,
 *     dna_msig_address(msig) == owner (64 raw bytes), and the session's
 *     authenticated public key (conn->peer_pk: nodus_auth.c on the
 *     client port, nodus_witness_ipc.c's ipc_hello in a split node) is
 *     byte-equal to one of the descriptor's N keys → else
 *     NOT_AUTHENTICATED with ONE message whichever step failed. Step c
 *     is nodus_witness_msig_member_ok (nodus_witness_addr_index.c), the
 *     same function nodus_witness_msig_addr_history_build runs itself,
 *     so the history store cannot be reached without it;
 *  d. only then the store is read, for the canonical owner text.
 * Bounded work: ≤ 18162 B parsed, one SHA3-512, ≤ 7 memcmp of 2592 B.
 * Read-only, committed state only; no consensus path calls this (D8.1).
 * ════════════════════════════════════════════════════════════════════ */

_Static_assert(NODUS_DNAC_MSIG_MAX_DESC_LEN == DNA_MSIG_MAX_DESC_LEN,
               "nodus.h restates the longest multisig descriptor");

typedef struct {
    char           owner[NODUS_KEY_HEX_LEN];   /* 128 lowercase hex + NUL */
    uint8_t        owner_raw[64];
    const uint8_t *msig;                       /* points into the payload */
    size_t         msig_len;
    bool           have_max, have_limit, have_before, have_bi, have_bq;
    uint64_t       max, limit, before, bi, bq;
} msig_query_args_t;

/* THE GATE (a → b → c above). `history` selects the method's own keys:
 * false = dnac_msig_utxo ("max"), true = dnac_msig_addr_history
 * ("limit", "before", "bi", "bq"); a key of the other method is an
 * unknown key (skipped). @return 0 = `a` filled and the session is a
 * member; -1 = the error was SENT. */
static int msig_query_open(struct nodus_tcp_conn *conn,
                           const uint8_t *payload, size_t len,
                           uint32_t txn_id, bool history,
                           msig_query_args_t *a) {
    cbor_decoder_t dec;
    size_t         args_count;
    bool           have_owner = false, have_msig = false;

    memset(a, 0, sizeof(*a));
    if (!conn->peer_id_set) {
        send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                   "session not authenticated");
        return -1;
    }
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing args map");
        return -1;
    }
    for (size_t k = 0; k < args_count; k++) {
        cbor_item_t key = cbor_decode_next(&dec);
        cbor_item_t val;
        bool       *seen = NULL;
        uint64_t   *slot = NULL;

        if (key.type != CBOR_ITEM_TSTR) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "truncated or malformed args map");
            return -1;
        }
        if (key_match(&key, "owner")) {
            val = cbor_decode_next(&dec);
            if (have_owner || val.type != CBOR_ITEM_TSTR ||
                val.tstr.len != 128 ||
                nodus_witness_owner_hex_to_raw(val.tstr.ptr, val.tstr.len,
                                               a->owner_raw) != 0) {
                send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                           "owner must be one 128-character lowercase "
                           "hex string");
                return -1;
            }
            memcpy(a->owner, val.tstr.ptr, 128);
            a->owner[128] = '\0';
            have_owner = true;
            continue;
        }
        if (key_match(&key, "msig")) {
            val = cbor_decode_next(&dec);
            if (have_msig || val.type != CBOR_ITEM_BSTR ||
                val.bstr.len < 1 || val.bstr.len > DNA_MSIG_MAX_DESC_LEN) {
                send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                           "msig must be one byte string of 1..18162 "
                           "bytes");   /* DNA_MSIG_MAX_DESC_LEN */
                return -1;
            }
            a->msig     = val.bstr.ptr;
            a->msig_len = val.bstr.len;
            have_msig = true;
            continue;
        }
        if (!history && key_match(&key, "max")) {
            seen = &a->have_max;    slot = &a->max;
        } else if (history && key_match(&key, "limit")) {
            seen = &a->have_limit;  slot = &a->limit;
        } else if (history && key_match(&key, "before")) {
            seen = &a->have_before; slot = &a->before;
        } else if (history && key_match(&key, "bi")) {
            seen = &a->have_bi;     slot = &a->bi;
        } else if (history && key_match(&key, "bq")) {
            seen = &a->have_bq;     slot = &a->bq;
        }
        if (!seen) {
            cbor_decode_skip(&dec);
            continue;
        }
        val = cbor_decode_next(&dec);
        if (*seen || val.type != CBOR_ITEM_UINT) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       history ? "limit / before / bi / bq must each be "
                                 "one uint"
                               : "max must be one uint");
            return -1;
        }
        *seen = true;
        *slot = val.uint_val;
    }
    if (dec.error || !have_owner || !have_msig) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid owner / msig");
        return -1;
    }
    if (history) {
        if (!a->have_limit || a->limit < 1 ||
            a->limit > NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT ||
            ((a->have_bi || a->have_bq) && !a->have_before) ||
            a->bi > UINT32_MAX || a->bq > UINT32_MAX) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "invalid cursor or limit");
            return -1;
        }
    } else if (a->have_max &&
               (a->max < 1 || a->max > DNAC_MAX_UTXO_RESULTS)) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "max must be 1..100");
        return -1;
    }

    /* step c — the same test the history builder runs itself */
    if (!nodus_witness_msig_member_ok(conn->peer_pk.bytes, a->owner_raw,
                                      a->msig, a->msig_len)) {
        send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                   NODUS_WITNESS_MSIG_NOT_MEMBER);
        return -1;
    }
    return 0;
}

static void handle_dnac_msig_utxo(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn,
                                  const uint8_t *payload, size_t len,
                                  uint32_t txn_id) {
    msig_query_args_t a;
    if (msig_query_open(conn, payload, len, txn_id, false, &a) != 0)
        return;

    int max_results = a.have_max ? (int)a.max : DNAC_MAX_UTXO_RESULTS;

    /* One more than the page: a (max + 1)-th row is what "trunc" means.
     * nodus_witness_utxo_by_owner orders by (amount DESC, nullifier ASC),
     * a total order, so the first `max` rows are the ones dnac_utxo would
     * have answered with the same max. */
    nodus_witness_utxo_entry_t *utxos =
        calloc((size_t)max_results + 1u, sizeof(nodus_witness_utxo_entry_t));
    if (!utxos) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "allocation failed");
        return;
    }

    int count = 0;
    if (nodus_witness_utxo_by_owner(w, a.owner, utxos, max_results + 1,
                                    &count) != 0) {
        /* §8.6 item 7: a store fault is never an empty list here */
        free(utxos);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "coin list unreadable");
        return;
    }
    bool trunc = count > max_results;
    if (trunc) count = max_results;

    dnac_utxo_answer_send(w, conn, txn_id, "dnac_msig_utxo", utxos, count,
                          true, trunc);
    free(utxos);
}

static void handle_dnac_msig_addr_history(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const uint8_t *payload,
                                          size_t len, uint32_t txn_id) {
    msig_query_args_t a;
    if (msig_query_open(conn, payload, len, txn_id, true, &a) != 0)
        return;

    nodus_witness_addr_cursor_t cur;
    cur.h = a.before;
    cur.i = (uint32_t)a.bi;
    cur.q = (uint32_t)a.bq;

    uint8_t *frame = NULL;
    size_t   frame_len = 0;
    int      ecode = 0;
    char     emsg[128];
    if (nodus_witness_msig_addr_history_build(
            w, txn_id, conn->peer_pk.bytes, a.msig, a.msig_len, a.owner,
            a.have_before ? &cur : NULL,
            (uint32_t)a.limit, &frame, &frame_len, &ecode, emsg,
            sizeof(emsg)) != 0) {
        send_error(conn, txn_id, ecode ? ecode : NODUS_ERR_INTERNAL_ERROR,
                   emsg);
        return;
    }
    nodus_tcp_send(conn, frame, frame_len);
    free(frame);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_balance — one owner's TRANSPARENT balance, per token (scan-v3)
 *
 * Decision docs/plans/decisions/2026-09-28-scan-v3-query.md item 3a
 * (operator, 2026-09-28). The wire (request arg, response keys, bounds,
 * error codes) is specified ONCE, in include/nodus/nodus.h beside
 * nodus_client_dnac_balance.
 *
 * TRANSPARENT COINS ONLY. The answer is summed from `utxo_set`, CORE
 * domain (DNA_DOMAIN_CORE) — coins whose owner and amount every block
 * already publishes, which is why this query is PUBLIC (no session-owner
 * gate) by decision 3a while dnac_utxo / dnac_history keep theirs (C11,
 * d40b89d1): it answers totals only — no coin ids, no history. It must
 * NEVER be extended to a shielded pool: a pool's notes live in v2_pools,
 * are not in utxo_set, and a per-owner total of them is unknowable to
 * the node — and must stay so.
 *
 * Sources:
 *   tip        nodus_witness_v2_tip_height (MAX(v2_blocks.global_height))
 *   per token  nodus_witness_utxo_balance_by_owner (nodus_witness_db.c):
 *              total / coins over the owner's CORE rows; spendable = the
 *              rows with unlock_block < tip + 1. That is the native exec's
 *              lock gate judged for the NEXT block: rtn_xfer_exec refuses
 *              an input with `unlock >= ctx->global_height`
 *              (nodus_witness_rt_native.c, the "inputs: exist, unlocked"
 *              loop), ctx->global_height = blk->global_height
 *              (nodus_witness_v2_apply.c) = the FinalizeBlock request's
 *              height (nodus_witness_cmt_app.c), and the next block's
 *              height is tip + 1. A coin already consumed by an envelope
 *              still waiting in the mempool counts until that block
 *              commits — this is the committed state, nothing else.
 *
 * PURE READ: no write, no clock, no cache. FAIL-CLOSED: a tip or row
 * fault, an overflow, or a malformed stored row answers an error — never
 * a zero, never a partial list. BOUNDED: at most
 * NODUS_DNAC_BALANCE_MAX_TOKENS tokens; an owner holding more answers
 * NODUS_ERR_TOO_LARGE (never a truncated list that would read as
 * complete).
 * ════════════════════════════════════════════════════════════════════ */

/* One token entry encodes in at most 1 (map) + 2+66 ("t") + 3×(2+9)
 * ("a"/"s"/"c") = 102 B; the T2 envelope + "r" framing + "tip" < 128 B. */
#define NODUS_BALANCE_ENTRY_MAX_BYTES  112u
#define NODUS_BALANCE_HDR_MAX_BYTES    256u

_Static_assert((size_t)NODUS_BALANCE_HDR_MAX_BYTES +
                   (size_t)NODUS_DNAC_BALANCE_MAX_TOKENS *
                       NODUS_BALANCE_ENTRY_MAX_BYTES <
               (size_t)NODUS_MAX_FRAME_TCP,
               "a dnac_balance answer must fit the tier-2 frame");

static void balance_err(int *err_code, char *err_msg, size_t err_cap,
                        int code, const char *msg)
{
    if (err_code) *err_code = code;
    if (err_msg && err_cap) snprintf(err_msg, err_cap, "%s", msg);
}

int nodus_witness_dnac_balance_build(nodus_witness_t *w, uint32_t txn_id,
                                     const char *owner,
                                     uint8_t **out, size_t *out_len,
                                     int *err_code, char *err_msg,
                                     size_t err_cap)
{
    if (err_code) *err_code = 0;
    if (err_msg && err_cap) err_msg[0] = '\0';
    if (!w || !owner || !out || !out_len) {
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                    "invalid arguments");
        return -1;
    }
    *out = NULL;
    *out_len = 0;

    /* the owner: exactly 128 lowercase hex characters (the utxo_set owner
     * format, dnac_utxo's "owner") — anything else is refused, never
     * normalised */
    size_t olen = strnlen(owner, NODUS_KEY_HEX_LEN);
    bool   ok = (olen == 128);
    for (size_t i = 0; ok && i < 128; i++) {
        char ch = owner[i];
        ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }
    if (!ok) {
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_PROTOCOL_ERROR,
                    "owner must be 128 lowercase hex characters");
        return -1;
    }

    if (!w->v2_successor || !w->db) {
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_NOT_FOUND,
                    "this node serves no version-3 chain");
        return -1;
    }

    uint64_t tip = 0;
    if (nodus_witness_v2_tip_height(w, &tip) != 0) {
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                    "chain height unreadable");
        return -1;
    }
    /* stored unlock_block values are non-negative int64: tip + 1 is
     * formed only where it cannot wrap */
    if (tip >= (uint64_t)INT64_MAX) {
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                    "chain height out of range");
        return -1;
    }

    nodus_witness_balance_entry_t *ent =
        calloc(NODUS_DNAC_BALANCE_MAX_TOKENS, sizeof(*ent));
    if (!ent) {
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return -1;
    }
    int count = 0;
    int rc = nodus_witness_utxo_balance_by_owner(
                 w, owner, tip + 1, ent, (int)NODUS_DNAC_BALANCE_MAX_TOKENS,
                 &count);
    if (rc == NODUS_WITNESS_BALANCE_TOO_MANY) {
        free(ent);
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_TOO_LARGE,
                    "owner holds more tokens than one answer carries");
        return -1;
    }
    if (rc != 0 || count < 0 ||
        count > (int)NODUS_DNAC_BALANCE_MAX_TOKENS) {
        free(ent);
        QGP_LOG_WARN(LOG_TAG, "dnac_balance owner=%.16s...: coin set "
                     "unreadable (rc=%d)", owner, rc);
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                    "coin set unreadable");
        return -1;
    }

    size_t cap = NODUS_BALANCE_HDR_MAX_BYTES +
                 (size_t)count * NODUS_BALANCE_ENTRY_MAX_BYTES;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        free(ent);
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return -1;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_dnac_response(&enc, txn_id, "dnac_balance", 2);
    cbor_encode_cstr(&enc, "tip");
    cbor_encode_uint(&enc, tip);
    cbor_encode_cstr(&enc, "tk");
    cbor_encode_array(&enc, (size_t)count);
    for (int i = 0; i < count; i++) {
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "t");
        cbor_encode_bstr(&enc, ent[i].token_id, 64);
        cbor_encode_cstr(&enc, "a");
        cbor_encode_uint(&enc, ent[i].total);
        cbor_encode_cstr(&enc, "s");
        cbor_encode_uint(&enc, ent[i].spendable);
        cbor_encode_cstr(&enc, "c");
        cbor_encode_uint(&enc, ent[i].coins);
    }
    free(ent);

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen == 0) {                     /* the size bound above is broken */
        free(buf);
        balance_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
        return -1;
    }
    *out = buf;
    *out_len = rlen;
    return 0;
}

/* Request:  "a": {"owner": tstr} — exactly one "owner" key; a duplicate,
 *           a non-text value or a truncated args map is refused.
 * Response: the frame nodus_witness_dnac_balance_build encodes; an error
 *           reply when it refuses. NO session-owner gate (decision 3a —
 *           see the block comment above). */
static void handle_dnac_balance(nodus_witness_t *w,
                                struct nodus_tcp_conn *conn,
                                const uint8_t *payload, size_t len,
                                uint32_t txn_id)
{
    cbor_decoder_t dec;
    size_t args_count;
    char   owner[NODUS_KEY_HEX_LEN];
    bool   have_owner = false;

    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing args map");
        return;
    }
    memset(owner, 0, sizeof(owner));
    for (size_t k = 0; k < args_count; k++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type == CBOR_ITEM_END || key.type == CBOR_ITEM_ERROR) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "truncated args map");
            return;
        }
        if (key_match(&key, "owner")) {
            cbor_item_t val = cbor_decode_next(&dec);
            /* 128 characters exactly; the content is checked by the
             * builder */
            if (have_owner || val.type != CBOR_ITEM_TSTR ||
                val.tstr.len != 128) {
                send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                           "owner must be one 128-character string");
                return;
            }
            memcpy(owner, val.tstr.ptr, 128);
            owner[128] = '\0';
            have_owner = true;
        } else {
            cbor_decode_skip(&dec);
        }
    }
    if (dec.error || !have_owner) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid owner");
        return;
    }

    uint8_t *frame = NULL;
    size_t   frame_len = 0;
    int      ecode = 0;
    char     emsg[128];
    if (nodus_witness_dnac_balance_build(w, txn_id, owner, &frame,
                                         &frame_len, &ecode, emsg,
                                         sizeof(emsg)) != 0) {
        send_error(conn, txn_id, ecode ? ecode : NODUS_ERR_INTERNAL_ERROR,
                   emsg);
        return;
    }
    nodus_tcp_send(conn, frame, frame_len);
    free(frame);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_ledger_range — Query range of ledger entries
 *
 * Request:  "a": {"from": uint, "to": uint}
 * Response: "r": {"total":N, "count":N, "entries":[{...},...]}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_ledger_range(nodus_witness_t *w,
                                       struct nodus_tcp_conn *conn,
                                       const uint8_t *payload, size_t len,
                                       uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    uint64_t from_seq = 0, to_seq = 0;
    bool has_from = false, has_to = false;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "from")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                from_seq = val.uint_val;
                has_from = true;
            }
        } else if (key_match(&key, "to")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                to_seq = val.uint_val;
                has_to = true;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!has_from || !has_to) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing from/to sequence");
        return;
    }

    nodus_witness_ledger_entry_t entries[DNAC_MAX_RANGE_RESULTS];
    int count = 0;

    nodus_witness_ledger_get_range(w, from_seq, to_seq,
                                     entries, DNAC_MAX_RANGE_RESULTS,
                                     &count);

    uint64_t total = nodus_witness_ledger_count(w);

    /* Encode response */
    size_t buf_size = 512 + ((size_t)count * 256);
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_ledger_range", 3);

    cbor_encode_cstr(&enc, "total");
    cbor_encode_uint(&enc, total);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);

    cbor_encode_cstr(&enc, "entries");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        cbor_encode_map(&enc, 6);
        cbor_encode_cstr(&enc, "seq");
        cbor_encode_uint(&enc, entries[i].sequence);
        cbor_encode_cstr(&enc, "hash");
        cbor_encode_bstr(&enc, entries[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "type");
        cbor_encode_uint(&enc, entries[i].tx_type);
        cbor_encode_cstr(&enc, "epoch");
        cbor_encode_uint(&enc, entries[i].epoch);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, entries[i].timestamp);
        cbor_encode_cstr(&enc, "nc");
        cbor_encode_uint(&enc, entries[i].nullifier_count);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_roster — Return witness roster
 *
 * Request:  "a": {}
 * Response: "r": {"version":N, "count":N, "witnesses":[{...},...]}
 * ════════════════════════════════════════════════════════════════════ */

/* P2P-PORT F5 — the reply's source. The transport roster this used to
 * serve (built from the DHT `nodus:pk` registry, IDENT and ROST_R —
 * HEAD nodus_witness_peer.c nodus_witness_rebuild_roster_from_peers) is
 * deleted. Its CONTENT rules are kept (fix round 1):
 *   · THIS node is always listed, at its configured address —
 *     external_ip, else bind_ip, with the witness port (HEAD
 *     nodus_witness_peer.c:300-313, the same expression);
 *   · every BONDED identity (validators ACTIVE / ELIGIBLE ∪ the tip ± 1
 *     committees, nodus_witness_p2p.h) is listed, with the address its
 *     validator-signed ADDR record names (R-P2P-4) — or an EMPTY address
 *     when this node holds no record for it, as HEAD listed a registry
 *     entry without ip/port (HEAD :396-398);
 *   · the list is sorted by witness id (HEAD roster_cmp, :473-476 — the
 *     self-first insertion there is re-sorted too, so "first" was the
 *     build order, never the reply order).
 * Same reply shape (wid, pk, addr "ip:port", active=true), at most
 * NODUS_T3_MAX_WITNESSES entries (the client's array bound,
 * nodus_types.h nodus_dnac_roster_result_t). `version` is the chain height
 * the reply was built at (HEAD: a roster rebuild counter). */
typedef struct {
    uint8_t wid[NODUS_T3_WITNESS_ID_LEN];
    uint8_t pk[NODUS_PK_BYTES];
    char    addr[CMT_P2P_NETADDR_STR_MAX];
} roster_row_t;

static int roster_row_cmp(const void *a, const void *b) {
    return memcmp(((const roster_row_t *)a)->wid, ((const roster_row_t *)b)->wid,
                  NODUS_T3_WITNESS_ID_LEN);
}

/* The address a roster / committee reply names for `pk`: this node's own
 * configured witness address (HEAD nodus_witness_peer.c:300-313), else
 * the member's signed ADDR record, else "" (no record held). */
static void witness_reply_addr(nodus_witness_t *w, const uint8_t *pk,
                               char *out, size_t cap) {
    out[0] = '\0';
    if (w->host &&
        memcmp(pk, w->host->identity->pk.bytes, NODUS_PK_BYTES) == 0) {
        const char *my_ip = w->host->config.external_ip[0]
                          ? w->host->config.external_ip
                          : w->host->config.bind_ip;
        uint16_t my_wport = w->host->config.witness_port
                          ? w->host->config.witness_port
                          : NODUS_DEFAULT_WITNESS_PORT;
        snprintf(out, cap, "%s:%u", my_ip, (unsigned)my_wport);
        return;
    }
    if (!w->p2p || !nodus_witness_p2p_signed_addr(w->p2p, pk, out, cap))
        out[0] = '\0';
}

static void handle_dnac_roster(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 uint32_t txn_id) {
    roster_row_t *rows = calloc(NODUS_T3_MAX_WITNESSES, sizeof(*rows));
    uint32_t n_rows = 0;
    uint64_t version = 0;

    if (!rows) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }
    /* This node, always. */
    if (w->host) {
        uint8_t fp[64];
        roster_row_t *r = &rows[n_rows];
        memcpy(r->pk, w->host->identity->pk.bytes, NODUS_PK_BYTES);
        if (qgp_sha3_512(r->pk, NODUS_PK_BYTES, fp) == 0) {
            memcpy(r->wid, fp, NODUS_T3_WITNESS_ID_LEN);
            witness_reply_addr(w, r->pk, r->addr, sizeof(r->addr));
            n_rows++;
        }
    }
    /* Every bonded identity (self already listed). */
    if (w->p2p) {
        int nb = nodus_witness_p2p_bonded_count(w->p2p);
        for (int i = 0; i < nb && n_rows < NODUS_T3_MAX_WITNESSES; i++) {
            roster_row_t *r = &rows[n_rows];
            uint8_t fp[64];
            if (!nodus_witness_p2p_bonded_at(w->p2p, i, NULL, r->pk) ||
                (w->host && memcmp(r->pk, w->host->identity->pk.bytes,
                                     NODUS_PK_BYTES) == 0) ||
                qgp_sha3_512(r->pk, NODUS_PK_BYTES, fp) != 0)
                continue;
            memcpy(r->wid, fp, NODUS_T3_WITNESS_ID_LEN);
            witness_reply_addr(w, r->pk, r->addr, sizeof(r->addr));
            n_rows++;
        }
    }
    if (n_rows > 1)
        qsort(rows, n_rows, sizeof(*rows), roster_row_cmp);
    if (w->db)
        (void)nodus_witness_block_height_checked(w, &version);

    /* Encode response */
    size_t buf_size = 512 + ((size_t)n_rows * (64 + NODUS_PK_BYTES + 256));
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(rows);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_roster", 3);

    cbor_encode_cstr(&enc, "version");
    cbor_encode_uint(&enc, version);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, n_rows);

    cbor_encode_cstr(&enc, "witnesses");
    cbor_encode_array(&enc, n_rows);

    for (uint32_t i = 0; i < n_rows; i++) {
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "wid");
        cbor_encode_bstr(&enc, rows[i].wid, NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(&enc, "pk");
        cbor_encode_bstr(&enc, rows[i].pk, NODUS_PK_BYTES);
        cbor_encode_cstr(&enc, "addr");
        cbor_encode_cstr(&enc, rows[i].addr);
        cbor_encode_cstr(&enc, "active");
        cbor_encode_bool(&enc, true);
    }
    free(rows);

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_tx — Query full transaction data by hash
 *
 * Request:  "a": {"hash": bstr(64)}
 * Response: "r": {"found":bool, "hash":bstr, "type":N, "tx":bstr,
 *                  "len":N, "bh":N, "ts":N}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_tx(nodus_witness_t *w,
                              struct nodus_tcp_conn *conn,
                              const uint8_t *payload, size_t len,
                              uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    const uint8_t *hash = NULL;
    size_t hash_len = 0;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "hash")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN) {
                hash = val.bstr.ptr;
                hash_len = val.bstr.len;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!hash || hash_len != NODUS_T3_TX_HASH_LEN) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing or invalid tx_hash");
        return;
    }

    uint8_t tx_type = 0;
    uint8_t *tx_data = NULL;
    uint32_t tx_len = 0;
    uint64_t block_height = 0;
    int rc = nodus_witness_tx_get(w, hash, &tx_type, &tx_data,
                                    &tx_len, &block_height);

    if (rc != 0 || !tx_data) {
        uint8_t buf[256];
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        enc_dnac_response(&enc, txn_id, "dnac_tx", 1);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, false);
        size_t rlen = cbor_encoder_len(&enc);
        if (rlen > 0) {
            nodus_tcp_send(conn, buf, rlen);
        } else {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "response buffer overflow");
        }
        return;
    }

    /* Encode response — variable size due to tx_data */
    size_t buf_size = 512 + (size_t)tx_len;
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(tx_data);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_tx", 7);

    cbor_encode_cstr(&enc, "found");
    cbor_encode_bool(&enc, true);
    cbor_encode_cstr(&enc, "hash");
    cbor_encode_bstr(&enc, hash, NODUS_T3_TX_HASH_LEN);
    cbor_encode_cstr(&enc, "type");
    cbor_encode_uint(&enc, tx_type);
    cbor_encode_cstr(&enc, "tx");
    cbor_encode_bstr(&enc, tx_data, tx_len);
    cbor_encode_cstr(&enc, "len");
    cbor_encode_uint(&enc, tx_len);
    cbor_encode_cstr(&enc, "bh");
    cbor_encode_uint(&enc, block_height);
    cbor_encode_cstr(&enc, "ts");
    cbor_encode_uint(&enc, (uint64_t)time(NULL));

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(tx_data);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_spend_replay — Re-emit spndrslt receipt for a committed TX
 *
 * Fix #4 B: a client that timed out waiting for its dnac_spend response
 * may re-query the receipt via this method. The server looks up the
 * committed TX and, if present, builds a *fresh* spndrslt receipt using
 * the same preimage scheme as the live commit path (nodus_witness_send_
 * spend_result). The signature is a NEW signature over a fresh timestamp
 * — the existing spndrslt sigs are not persisted — but the committed
 * (block_height, tx_index, chain_id) are recovered verbatim from the
 * ledger, so the client can bind the TX to its exact on-chain position.
 *
 * Request:  "a": {"h": bstr(64)}
 * Response: "r": {"found":bool,
 *                  [if found] "status", "wid", "wpk", "ts",
 *                  "bnr", "ti", "cid", "wsig"}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_spend_replay(nodus_witness_t *w,
                                       struct nodus_tcp_conn *conn,
                                       const uint8_t *payload, size_t len,
                                       uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    const uint8_t *hash = NULL;
    size_t hash_len = 0;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "h")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_T3_TX_HASH_LEN) {
                hash = val.bstr.ptr;
                hash_len = val.bstr.len;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!hash || hash_len != NODUS_T3_TX_HASH_LEN) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing or invalid tx_hash");
        return;
    }

    uint64_t block_height = 0;
    uint32_t tx_index = 0;
    int rc = nodus_witness_get_committed_coords(w, hash,
                                                  &block_height, &tx_index);

    /* Not committed → respond with found:false, nothing else. */
    if (rc != 0) {
        uint8_t buf[64];
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        enc_dnac_response(&enc, txn_id, "dnac_spend_replay", 1);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, false);
        size_t rlen = cbor_encoder_len(&enc);
        if (rlen > 0) {
            nodus_tcp_send(conn, buf, rlen);
        } else {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "response buffer overflow");
        }
        return;
    }

    /* Committed → rebuild the spndrslt preimage and sign it fresh: the
     * same 8-byte 'spndrslt' domain tag, tx_hash, witness_id,
     * SHA3-512(witness_pubkey), chain_id, status, timestamp, block_height
     * and tx_index the closed lane's COMMIT-triggered receipt used to
     * sign (221-byte fixed layout, dnac_compute_spend_result_preimage). */
    uint64_t ts = (uint64_t)time(NULL);

    uint8_t wpk_hash[64];
    qgp_sha3_512(w->host->identity->pk.bytes, NODUS_PK_BYTES, wpk_hash);

    uint8_t preimage[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    dnac_compute_spend_result_preimage(hash, w->my_id, wpk_hash,
                                         w->chain_id, ts,
                                         block_height, tx_index,
                                         (uint8_t)DNAC_STATUS_APPROVED,
                                         preimage);

    nodus_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    /* CERT domain kept RAW — DNAC client (dnac/src/transaction/builder.c:518)
     * verifies witness cert sigs via qgp_dsa87_verify on the raw preimage.
     * Adding domain tag here would break messenger-side verify without
     * cross-repo migration. Deferred to a future lockstep nodus+dnac change.
     * Preimage is 221B (block_hash + voter_id + height + chain_id + tx_index
     * + status) — rich context, no overlap with other sign domains. */
    nodus_sign(&sig, preimage, sizeof(preimage), &w->host->identity->sk);

    uint8_t buf[8192];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_spend_replay", 9);

    cbor_encode_cstr(&enc, "found");
    cbor_encode_bool(&enc, true);

    cbor_encode_cstr(&enc, "status");
    cbor_encode_uint(&enc, (uint64_t)DNAC_STATUS_APPROVED);

    cbor_encode_cstr(&enc, "wid");
    cbor_encode_bstr(&enc, w->my_id, NODUS_T3_WITNESS_ID_LEN);

    cbor_encode_cstr(&enc, "wpk");
    cbor_encode_bstr(&enc, w->host->identity->pk.bytes, NODUS_PK_BYTES);

    cbor_encode_cstr(&enc, "ts");
    cbor_encode_uint(&enc, ts);

    cbor_encode_cstr(&enc, "bnr");
    cbor_encode_uint(&enc, block_height);

    cbor_encode_cstr(&enc, "ti");
    cbor_encode_uint(&enc, (uint64_t)tx_index);

    cbor_encode_cstr(&enc, "cid");
    cbor_encode_bstr(&enc, w->chain_id, 32);

    cbor_encode_cstr(&enc, "wsig");
    cbor_encode_bstr(&enc, sig.bytes, NODUS_SIG_BYTES);

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_block — Query block by height
 *
 * Request:  "a": {"height": uint}
 * Response: "r": {"found":bool, "height":N, "hash":bstr, "type":N,
 *                  "ts":N, "proposer":bstr}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_block(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 const uint8_t *payload, size_t len,
                                 uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    uint64_t height = 0;
    bool has_height = false;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "height")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                height = val.uint_val;
                has_height = true;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!has_height) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing height");
        return;
    }

    nodus_witness_block_t blk;
    int rc = nodus_witness_block_get(w, height, &blk);

    /* Phase 2 / Task 37: response now carries the block's commit
     * certificate (2f+1 PRECOMMIT APPROVE signatures) so clients
     * can verify anchored merkle proofs without trusting a single
     * witness. Certs can be large (up to NODUS_T3_MAX_WITNESSES ×
     * NODUS_SIG_BYTES ≈ 600 KiB worst case), so the response buffer
     * is heap-allocated. */
    nodus_witness_vote_record_t certs[NODUS_T3_MAX_WITNESSES];
    int cert_count = 0;
    if (rc == 0) {
        if (nodus_witness_cert_get(w, height, certs,
                                     NODUS_T3_MAX_WITNESSES,
                                     &cert_count) != 0) {
            cert_count = 0;
        }
    }

    size_t buf_cap = 1024 + (size_t)cert_count *
                             (NODUS_SIG_BYTES + NODUS_T3_WITNESS_ID_LEN + 64);
    uint8_t *buf = (uint8_t *)malloc(buf_cap);
    if (!buf) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "out of memory");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_cap);

    if (rc != 0) {
        enc_dnac_response(&enc, txn_id, "dnac_block", 1);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, false);
    } else {
        /* Phase 1 / Task 1.2: blocks table dropped tx_type; per-TX type
         * lives on committed_transactions. The dnac_block response keeps
         * the "type" key for client compatibility but reports 0 here —
         * Phase 13 client receipt API will report the per-TX type via
         * the new tx_index/block_height path. The "hash" key now carries
         * the block's tx_root (single-TX path: bytes equal to the tx
         * hash; multi-TX path: bytes equal to the Merkle root).
         *
         * Phase 2 / Task 37: adds "commit_cert" — array of maps with
         * {signer_id: bstr(32), sig: bstr(4627)} for each 2f+1
         * PRECOMMIT APPROVE signer. Empty array if no cert was stored
         * (e.g., pre-BFT seeded genesis).
         *
         * 2026-07-29: adds "state_root", read straight from the stored
         * `blocks` row (`blk.state_root`, below) — this handler does not
         * compute it. R3 W4 deleted nodus_witness_compute_block_hash_ex,
         * the V1 block-hash helper that used to PRODUCE this value at
         * legacy commit time, along with the legacy commit path itself;
         * a version-3 chain never writes this legacy table, so the field
         * this handler serves is frozen historical data on chains that
         * ran the closed lane, not a live value. The client decoder has
         * parsed this key since Phase 7 (nodus_client.c dnac_block
         * state_root arm).
         *
         * 2026-08-04: adds an explicit "tx_root" key. The client decoder
         * fills result.tx_root ONLY from a key named "tx_root"
         * (nodus_client.c dnac_block tx_root arm) — the legacy "hash"
         * key lands in result.tx_hash, so without this key every parsed
         * tx_root was all-zero and the explorer both displayed zero
         * tx_roots and computed a WRONG tip block hash (tx_root is part
         * of the block-hash preimage). "hash" stays for compatibility. */
        enc_dnac_response(&enc, txn_id, "dnac_block", 11);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, true);
        cbor_encode_cstr(&enc, "height");
        cbor_encode_uint(&enc, blk.height);
        cbor_encode_cstr(&enc, "hash");
        cbor_encode_bstr(&enc, blk.tx_root, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "tx_count");
        cbor_encode_uint(&enc, blk.tx_count);
        cbor_encode_cstr(&enc, "type");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, blk.timestamp);
        cbor_encode_cstr(&enc, "proposer");
        cbor_encode_bstr(&enc, blk.proposer_id, NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(&enc, "prev_hash");
        cbor_encode_bstr(&enc, blk.prev_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "state_root");
        cbor_encode_bstr(&enc, blk.state_root, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "tx_root");
        cbor_encode_bstr(&enc, blk.tx_root, NODUS_T3_TX_HASH_LEN);

        cbor_encode_cstr(&enc, "commit_cert");
        cbor_encode_array(&enc, (size_t)cert_count);
        for (int i = 0; i < cert_count; i++) {
            cbor_encode_map(&enc, 2);
            cbor_encode_cstr(&enc, "signer_id");
            cbor_encode_bstr(&enc, certs[i].voter_id,
                              NODUS_T3_WITNESS_ID_LEN);
            cbor_encode_cstr(&enc, "sig");
            cbor_encode_bstr(&enc, certs[i].signature, NODUS_SIG_BYTES);
        }
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }
    free(buf);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_block_range — Query range of blocks
 *
 * Request:  "a": {"from": uint, "to": uint}
 * Response: "r": {"total":N, "count":N, "blocks":[{...},...]}
 * ════════════════════════════════════════════════════════════════════ */

/* Max blocks per range query */
#define DNAC_MAX_BLOCK_RANGE_RESULTS  100

static void handle_dnac_block_range(nodus_witness_t *w,
                                       struct nodus_tcp_conn *conn,
                                       const uint8_t *payload, size_t len,
                                       uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    uint64_t from_h = 0, to_h = 0;
    bool has_from = false, has_to = false;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "from")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                from_h = val.uint_val;
                has_from = true;
            }
        } else if (key_match(&key, "to")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                to_h = val.uint_val;
                has_to = true;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!has_from || !has_to) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing from/to height");
        return;
    }

    nodus_witness_block_t blocks[DNAC_MAX_BLOCK_RANGE_RESULTS];
    int count = 0;

    nodus_witness_block_get_range(w, from_h, to_h,
                                    blocks, DNAC_MAX_BLOCK_RANGE_RESULTS,
                                    &count);

    uint64_t total = nodus_witness_block_height(w);

    /* Encode response (400 per block to fit prev_hash + tx_root) */
    size_t buf_size = 512 + ((size_t)count * 400);
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_block_range", 3);

    cbor_encode_cstr(&enc, "total");
    cbor_encode_uint(&enc, total);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);

    cbor_encode_cstr(&enc, "blocks");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        /* Phase 1 / Task 1.2: blocks table dropped tx_type; "type" key
         * kept at 0 for client compatibility. New tx_count carries the
         * block's TX count.
         * 2026-08-04: adds "tx_root" — same key-mismatch fix as
         * handle_dnac_block above ("hash" parses into result.tx_hash,
         * the tx_root arm needs a literal "tx_root" key). */
        cbor_encode_map(&enc, 8);
        cbor_encode_cstr(&enc, "height");
        cbor_encode_uint(&enc, blocks[i].height);
        cbor_encode_cstr(&enc, "hash");
        cbor_encode_bstr(&enc, blocks[i].tx_root, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "tx_count");
        cbor_encode_uint(&enc, blocks[i].tx_count);
        cbor_encode_cstr(&enc, "type");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, blocks[i].timestamp);
        cbor_encode_cstr(&enc, "proposer");
        cbor_encode_bstr(&enc, blocks[i].proposer_id,
                          NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(&enc, "prev_hash");
        cbor_encode_bstr(&enc, blocks[i].prev_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "tx_root");
        cbor_encode_bstr(&enc, blocks[i].tx_root, NODUS_T3_TX_HASH_LEN);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_genesis — Return the genesis block fields + chain_def blob
 *
 * Phase 2 / Task 36 — clients fetch the genesis block from any peer
 * to verify their hardcoded chain_id. The response carries the raw
 * header fields plus the serialized chain_def blob; the client
 * reassembles a dnac_block_t, computes the block hash, and compares
 * against its hardcoded chain_id.
 *
 * Request:  "a": {} (no args)
 * Response: "r": {"found":bool, "height":uint, "prev_hash":bstr,
 *                  "state_root":bstr, "tx_root":bstr, "tx_count":uint,
 *                  "ts":uint, "proposer":bstr, "chain_def":bstr}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_genesis(nodus_witness_t *w,
                                   struct nodus_tcp_conn *conn,
                                   uint32_t txn_id) {
    nodus_witness_block_t blk;
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc = nodus_witness_block_get_genesis(w, &blk, &blob, &blob_len);

    /* Response buffer sized to comfortably hold header fields plus a
     * full chain_def blob (dnac_chain_def_encoded_size is bounded by
     * compile-time witness cap; worst-case well under 64 KiB). */
    size_t buf_cap = 65536;
    uint8_t *buf = (uint8_t *)malloc(buf_cap);
    if (!buf) {
        free(blob);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "out of memory");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_cap);

    if (rc != 0 || blob == NULL || blob_len == 0) {
        /* No genesis row, or genesis row with no chain_def_blob —
         * client cannot verify chain_id without the blob, so treat
         * as not found. */
        enc_dnac_response(&enc, txn_id, "dnac_genesis", 1);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, false);
    } else {
        enc_dnac_response(&enc, txn_id, "dnac_genesis", 9);
        cbor_encode_cstr(&enc, "found");
        cbor_encode_bool(&enc, true);
        cbor_encode_cstr(&enc, "height");
        cbor_encode_uint(&enc, blk.height);
        cbor_encode_cstr(&enc, "prev_hash");
        cbor_encode_bstr(&enc, blk.prev_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "state_root");
        cbor_encode_bstr(&enc, blk.state_root, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "tx_root");
        cbor_encode_bstr(&enc, blk.tx_root, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "tx_count");
        cbor_encode_uint(&enc, blk.tx_count);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, blk.timestamp);
        cbor_encode_cstr(&enc, "proposer");
        cbor_encode_bstr(&enc, blk.proposer_id, NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(&enc, "chain_def");
        cbor_encode_bstr(&enc, blob, blob_len);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(blob);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_history — Query transaction history for an owner fingerprint
 *
 * Request:  "a": {"owner": tstr, "limit": uint}
 * Response: "r": {"count":N, "entries":[{hash,type,sender,receiver,
 *                  amount,fee,bh,ts}, ...]}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_history(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn,
                                  const uint8_t *payload, size_t len,
                                  uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    char owner[256] = {0};
    int max_results = DNAC_MAX_HISTORY_RESULTS;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "owner")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_TSTR && val.tstr.len > 0) {
                size_t clen = val.tstr.len < sizeof(owner) - 1
                              ? val.tstr.len : sizeof(owner) - 1;
                memcpy(owner, val.tstr.ptr, clen);
                owner[clen] = '\0';
            }
        } else if (key_match(&key, "limit")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                max_results = (int)val.uint_val;
                if (max_results <= 0 || max_results > DNAC_MAX_HISTORY_RESULTS)
                    max_results = DNAC_MAX_HISTORY_RESULTS;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (owner[0] == '\0') {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing owner field");
        return;
    }

    /* C11 fix: require owner == authenticated session fingerprint */
    if (!conn->peer_id_set) {
        send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                    "session not authenticated");
        return;
    }
    {
        char session_hex[NODUS_KEY_HEX_LEN];
        for (int i = 0; i < NODUS_KEY_BYTES; i++)
            snprintf(session_hex + i * 2, NODUS_KEY_HEX_LEN - i * 2, "%02x",
                     conn->peer_id.bytes[i]);
        session_hex[128] = '\0';
        if (strcmp(owner, session_hex) != 0) {
            send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                        "owner must match authenticated session fingerprint");
            return;
        }
    }

    nodus_witness_tx_history_entry_t *entries = calloc((size_t)max_results,
                                                        sizeof(nodus_witness_tx_history_entry_t));
    if (!entries) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    int count = 0;
    nodus_witness_tx_by_owner(w, owner, entries, max_results, &count);

    /* Task 39: each historical TX ships a per-block tx_root Merkle inclusion
     * proof so clients can verify the TX is anchored in the committed block
     * identified by `bh`. The proof follows Task 38's CBOR convention:
     *   pr_s : bstr — flat siblings (depth * 64 bytes)
     *   pr_p : uint — position bitfield
     *   pr_d : uint — proof depth
     *   tr   : bstr — 64-byte tx_root (matches block.tx_root)
     *
     * Degraded case (build_tx_proof fails — e.g. block not yet fully
     * committed, TX missing from tx_root): emit pr_d=0, empty siblings,
     * zeroed tr. Client-side verify rejects and retries. */
    #define DNAC_HISTORY_PROOF_MAX_DEPTH 32

    /* Encode response.
     * Per-entry budget: ~300B metadata + up to NODUS_WITNESS_MAX_TX_OUTPUTS
     * outputs × ~260B (128-char fp + token_id + amount + index) +
     * proof fields (~2048B siblings + 64B root + overhead).
     * 6656B per entry covers 8+ outputs plus full proof. */
    size_t buf_size = 1024 + ((size_t)count * 6656);
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(entries);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_history", 2);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);

    cbor_encode_cstr(&enc, "entries");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        /* Build per-TX tx_root proof anchored to the committing block.
         * On failure emit a degraded empty proof so the entry structure
         * stays valid — client verify will reject the degraded entry. */
        uint8_t siblings[DNAC_HISTORY_PROOF_MAX_DEPTH * NODUS_MERKLE_HASH_LEN];
        uint8_t tx_root[NODUS_MERKLE_HASH_LEN];
        uint32_t positions = 0;
        int depth = 0;
        bool have_proof = false;

        memset(siblings, 0, sizeof(siblings));
        memset(tx_root, 0, sizeof(tx_root));

        if (nodus_witness_merkle_build_tx_proof(w,
                                                  entries[i].block_height,
                                                  entries[i].tx_hash,
                                                  siblings, &positions,
                                                  DNAC_HISTORY_PROOF_MAX_DEPTH,
                                                  &depth, tx_root) == 0) {
            have_proof = true;
        }
        if (!have_proof) {
            positions = 0;
            depth = 0;
            memset(siblings, 0, sizeof(siblings));
            memset(tx_root, 0, sizeof(tx_root));
        }

        size_t sibs_len = (size_t)depth * NODUS_MERKLE_HASH_LEN;

        cbor_encode_map(&enc, 11);
        cbor_encode_cstr(&enc, "hash");
        cbor_encode_bstr(&enc, entries[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "type");
        cbor_encode_uint(&enc, entries[i].tx_type);
        cbor_encode_cstr(&enc, "sender");
        cbor_encode_cstr(&enc, entries[i].sender_fp);
        cbor_encode_cstr(&enc, "fee");
        cbor_encode_uint(&enc, entries[i].fee);
        cbor_encode_cstr(&enc, "bh");
        cbor_encode_uint(&enc, entries[i].block_height);
        cbor_encode_cstr(&enc, "ts");
        cbor_encode_uint(&enc, entries[i].timestamp);
        cbor_encode_cstr(&enc, "pr_s");
        cbor_encode_bstr(&enc, siblings, sibs_len);
        cbor_encode_cstr(&enc, "pr_p");
        cbor_encode_uint(&enc, (uint64_t)positions);
        cbor_encode_cstr(&enc, "pr_d");
        cbor_encode_uint(&enc, (uint64_t)depth);
        cbor_encode_cstr(&enc, "tr");
        cbor_encode_bstr(&enc, tx_root, NODUS_MERKLE_HASH_LEN);

        /* Per-output array. Output map carries an optional `memo` key —
         * clients that don't know the key ignore it, older witnesses
         * that don't send it leave the client field empty. */
        cbor_encode_cstr(&enc, "outputs");
        cbor_encode_array(&enc, (size_t)entries[i].output_count);
        for (int j = 0; j < entries[i].output_count; j++) {
            const uint8_t memo_len = entries[i].outputs[j].memo_len;
            cbor_encode_map(&enc, memo_len > 0 ? 5 : 4);
            cbor_encode_cstr(&enc, "fp");
            cbor_encode_cstr(&enc, entries[i].outputs[j].owner_fp);
            cbor_encode_cstr(&enc, "amt");
            cbor_encode_uint(&enc, entries[i].outputs[j].amount);
            cbor_encode_cstr(&enc, "idx");
            cbor_encode_uint(&enc, entries[i].outputs[j].output_index);
            cbor_encode_cstr(&enc, "tid");
            cbor_encode_bstr(&enc, entries[i].outputs[j].token_id, 64);
            if (memo_len > 0) {
                cbor_encode_cstr(&enc, "memo");
                cbor_encode_bstr(&enc,
                                  (const uint8_t *)entries[i].outputs[j].memo,
                                  memo_len);
            }
        }
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(entries);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_addr_history — the session owner's history from the node-local
 * address index (decision docs/plans/decisions/2026-10-01-node-address-
 * history-index.md rev 2). The wire is specified once, in
 * include/nodus/nodus.h beside nodus_client_dnac_addr_history; the
 * answer is nodus_witness_addr_history_build's
 * (nodus_witness_addr_index.c). This handler only decodes the args
 * STRICTLY (a duplicate key, a wrong type or a truncated map is refused)
 * and hands over the session fingerprint for the C11 check — the same
 * conn->peer_id dnac_history compares against. dnac_history itself is
 * unchanged (libdna reads its shape).
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_addr_history(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     const uint8_t *payload, size_t len,
                                     uint32_t txn_id)
{
    cbor_decoder_t dec;
    size_t   args_count;
    char     owner[NODUS_KEY_HEX_LEN];
    bool     have_owner = false, have_limit = false, have_before = false,
             have_bi = false, have_bq = false;
    uint64_t limit = 0, bi = 0, bq = 0;
    nodus_witness_addr_cursor_t cur;

    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing args map");
        return;
    }
    memset(owner, 0, sizeof(owner));
    memset(&cur, 0, sizeof(cur));
    for (size_t k = 0; k < args_count; k++) {
        cbor_item_t key = cbor_decode_next(&dec);
        cbor_item_t val;
        bool       *seen = NULL;

        if (key.type != CBOR_ITEM_TSTR) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "truncated or malformed args map");
            return;
        }
        if (key_match(&key, "owner")) {
            val = cbor_decode_next(&dec);
            if (have_owner || val.type != CBOR_ITEM_TSTR ||
                val.tstr.len != 128) {
                send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                           "owner must be one 128-character string");
                return;
            }
            memcpy(owner, val.tstr.ptr, 128);
            owner[128] = '\0';
            have_owner = true;
            continue;
        }
        if (key_match(&key, "limit"))       seen = &have_limit;
        else if (key_match(&key, "before")) seen = &have_before;
        else if (key_match(&key, "bi"))     seen = &have_bi;
        else if (key_match(&key, "bq"))     seen = &have_bq;
        if (!seen) {
            cbor_decode_skip(&dec);
            continue;
        }
        val = cbor_decode_next(&dec);
        if (*seen || val.type != CBOR_ITEM_UINT) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "limit / before / bi / bq must each be one uint");
            return;
        }
        *seen = true;
        if (seen == &have_limit)       limit = val.uint_val;
        else if (seen == &have_before) cur.h = val.uint_val;
        else if (seen == &have_bi)     bi    = val.uint_val;
        else                           bq    = val.uint_val;
    }
    if (dec.error || !have_owner || !have_limit) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid owner / limit");
        return;
    }
    if (((have_bi || have_bq) && !have_before) ||
        bi > UINT32_MAX || bq > UINT32_MAX ||
        limit > NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "invalid cursor or limit");
        return;
    }
    cur.i = (uint32_t)bi;
    cur.q = (uint32_t)bq;

    uint8_t *frame = NULL;
    size_t   frame_len = 0;
    int      ecode = 0;
    char     emsg[128];
    if (nodus_witness_addr_history_build(
            w, txn_id, conn->peer_id_set ? conn->peer_id.bytes : NULL,
            owner, have_before ? &cur : NULL, (uint32_t)limit, &frame,
            &frame_len, &ecode, emsg, sizeof(emsg)) != 0) {
        send_error(conn, txn_id, ecode ? ecode : NODUS_ERR_INTERNAL_ERROR,
                   emsg);
        return;
    }
    nodus_tcp_send(conn, frame, frame_len);
    free(frame);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_delegations — Query active delegations for the caller
 *
 * Request:  "a": {"pubkey": bstr(2592), "limit": uint}
 * Response: "r": {"count": N, "entries": [{"validator": tstr(128),
 *                  "amount": uint, "block": uint}, ...]}
 *
 * Auth (C11): SHA3-512(pubkey) must match the authenticated session
 * fingerprint (conn->peer_id). A user can only query their own
 * delegations — privacy by design.
 *
 * Lookup uses the existing nodus_delegation_list_by_delegator() helper
 * which computes delegator_hash = SHA3-512(0x03 || pubkey) and hits
 * the idx_delegator index. No schema change.
 *
 * validator_fp in the response is derived server-side from the stored
 * validator_pubkey BLOB via SHA3-512(validator_pubkey), rendered as
 * 128 lowercase hex — the same fingerprint formula the validator_list /
 * committee query handlers use, so downstream UI can correlate against
 * validator list entries.
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_delegations(nodus_witness_t *w,
                                      struct nodus_tcp_conn *conn,
                                      const uint8_t *payload, size_t len,
                                      uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    const uint8_t *req_pubkey = NULL;
    size_t req_pubkey_len = 0;
    int max_results = DNAC_MAX_DELEGATIONS_RESULTS;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "pubkey")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR) {
                req_pubkey = val.bstr.ptr;
                req_pubkey_len = val.bstr.len;
            }
        } else if (key_match(&key, "limit")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT) {
                max_results = (int)val.uint_val;
                if (max_results <= 0 ||
                    max_results > DNAC_MAX_DELEGATIONS_RESULTS)
                    max_results = DNAC_MAX_DELEGATIONS_RESULTS;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!req_pubkey || req_pubkey_len != DNAC_PUBKEY_SIZE) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing or malformed pubkey field");
        return;
    }

    /* C11: require SHA3-512(pubkey) == authenticated session fingerprint */
    if (!conn->peer_id_set) {
        send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                    "session not authenticated");
        return;
    }
    {
        uint8_t fp_from_pubkey[QGP_SHA3_512_DIGEST_LENGTH];
        if (qgp_sha3_512(req_pubkey, DNAC_PUBKEY_SIZE,
                          fp_from_pubkey) != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "fp hash failed");
            return;
        }
        if (memcmp(fp_from_pubkey, conn->peer_id.bytes,
                    NODUS_KEY_BYTES) != 0) {
            send_error(conn, txn_id, NODUS_ERR_NOT_AUTHENTICATED,
                        "pubkey does not match authenticated session fingerprint");
            return;
        }
    }

    dnac_delegation_record_t *entries =
        calloc((size_t)max_results, sizeof(dnac_delegation_record_t));
    if (!entries) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    int count = 0;
    int list_rc = nodus_delegation_list_by_delegator(w, req_pubkey,
                                                       entries,
                                                       max_results,
                                                       &count);
    if (list_rc != 0) {
        free(entries);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "delegations query failed");
        return;
    }

    /* Response buffer: per-entry budget = 128-char fp + amount + block +
     * CBOR keys/overhead ≈ 200B. 1 KB header + 256B per entry is ample. */
    size_t buf_size = 1024 + ((size_t)count * 256);
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(entries);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_delegations", 2);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);

    cbor_encode_cstr(&enc, "entries");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        /* Derive validator_fp server-side from stored validator_pubkey.
         * Same helper used in BFT roster / chain_def paths. */
        uint8_t v_fp_raw[QGP_SHA3_512_DIGEST_LENGTH];
        char    v_fp_hex[NODUS_KEY_HEX_LEN];

        if (qgp_sha3_512(entries[i].validator_pubkey, DNAC_PUBKEY_SIZE,
                          v_fp_raw) != 0) {
            /* Should not happen — defensive fallback: empty fp so the
             * row is recognizably malformed client-side. */
            memset(v_fp_hex, '0', 128);
            v_fp_hex[128] = '\0';
        } else {
            for (int b = 0; b < NODUS_KEY_BYTES; b++)
                snprintf(v_fp_hex + b * 2, NODUS_KEY_HEX_LEN - b * 2,
                         "%02x", v_fp_raw[b]);
            v_fp_hex[128] = '\0';
        }

        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "validator");
        cbor_encode_cstr(&enc, v_fp_hex);
        cbor_encode_cstr(&enc, "amount");
        cbor_encode_uint(&enc, entries[i].amount);
        cbor_encode_cstr(&enc, "block");
        cbor_encode_uint(&enc, entries[i].delegated_at_block);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(entries);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_spend — Submit TX for BFT consensus
 *
 * Request:  "a": {"tx":bstr, "hash":bstr(64), "pk":bstr(2592),
 *                  "sig":bstr(4627), "fee":uint}
 * Response: on a version-3 chain, SYNCHRONOUS — the Comet mempool's
 * CheckTx verdict is the whole answer (see the early return below).
 * On any other chain: refused — this node runs no consensus lane for it
 * (R3 W4 — the closed lane's pool-then-forward / leader-forward /
 * COMMIT-triggered async receipt are deleted).
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_spend(nodus_witness_t *w,
                                struct nodus_tcp_conn *conn,
                                const uint8_t *payload, size_t len,
                                uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    const uint8_t *tx_data = NULL;
    size_t tx_len = 0;
    const uint8_t *tx_hash = NULL;
    size_t hash_len = 0;
    const uint8_t *client_pk = NULL;
    const uint8_t *client_sig = NULL;
    uint64_t fee = 0;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);

        if (key_match(&key, "tx")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR) {
                tx_data = val.bstr.ptr;
                tx_len = val.bstr.len;
            }
        } else if (key_match(&key, "hash")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR) {
                tx_hash = val.bstr.ptr;
                hash_len = val.bstr.len;
            }
        } else if (key_match(&key, "pk")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_PK_BYTES) {
                client_pk = val.bstr.ptr;
            }
        } else if (key_match(&key, "sig")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR &&
                val.bstr.len == NODUS_SIG_BYTES) {
                client_sig = val.bstr.ptr;
            }
        } else if (key_match(&key, "fee")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_UINT)
                fee = val.uint_val;
        } else {
            cbor_decode_skip(&dec);
        }
    }

    /* Validate required fields */
    if (!tx_data || tx_len == 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing tx data");
        return;
    }
    if (!tx_hash || hash_len != NODUS_T3_TX_HASH_LEN) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing or invalid tx_hash");
        return;
    }
    /* O15H D8 — family-aware. This gate is the one the 2026-08-25
     * rehearsal died on: a 72,142-byte CHAIN_CONFIG envelope carrying
     * the N=20 quorum's 14 approvals, refused with NODUS_ERR_TOO_LARGE
     * against the LEGACY 65,536 ceiling, which made governance
     * impossible above N=17. Legacy transactions keep that ceiling
     * exactly. */
    if (tx_len > nodus_t3_tx_size_limit(tx_data, tx_len)) {
        send_error(conn, txn_id, NODUS_ERR_TOO_LARGE,
                    "transaction too large");
        return;
    }

    /* ── FLEET-TM-R3 W3 (D-23 rev 7 item 22, package C2a) — ON A
     * VERSION-3 CHAIN, THE COMET MEMPOOL'S CheckTx IS THE WHOLE ANSWER.
     * The reference's `broadcast_tx_sync` shape: the client learns the
     * CheckTx code AT ONCE — APPROVED means accepted into the mempool,
     * REJECTED carries the reason — and NOTHING BELOW THIS BLOCK RUNS:
     * no leader/follower branch, no forward-to-leader (there is no
     * leader; the mempool reactor floods), no pending-forward slot, no
     * committed-block receipt. The client learns the commit by query
     * (dnac_tx, block height) — this response carries no `bnr`/`ti`/
     * `wsig`: there is no committed block yet to certify, and signing a
     * receipt for one would be inventing a fact. `witness->cmt_node`
     * NULL here would mean `v2_successor` is true but the startup
     * table failed to build at init (already refused init in that
     * case) or has not finished constructing (unreachable on a running
     * server) — refuse defensively rather than fall through to what
     * follows this block, which R3 W4 reduced to a single unreachable
     * defensive error once the legacy lane it used to run was deleted. */
    if (w->v2_successor) {
        nodus_cmt_node_t *node = (nodus_cmt_node_t *)w->cmt_node;
        if (!node || !node->mem_ready) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "the cometbft mempool is not available");
            return;
        }

        cmt_mem_tx_info_t          info;
        cmt_mem_response_check_tx_t res;
        cmt_mem_error_t             err;
        memset(&info, 0, sizeof(info));   /* sender_id 0 = unknown (RPC) */

        int rc = cmt_mem_check_tx(node->mem, tx_data, tx_len, &info,
                                  &res, &err);
        if (rc == CMT_FAULT) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "CheckTx faulted");
            return;
        }
        if (rc == CMT_REJECT) {
            /* Same wording the legacy leader branch used to send for the
             * equivalent admission outcomes (that branch is deleted with
             * the closed consensus lane, R3 W4) — kept here so an
             * existing client still sees familiar text. */
            switch (err.kind) {
            case CMT_MEM_ERR_TX_TOO_LARGE:
                send_error(conn, txn_id, NODUS_ERR_TOO_LARGE,
                            "transaction too large");
                break;
            case CMT_MEM_ERR_TX_IN_CACHE:
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "duplicate transaction");
                break;
            case CMT_MEM_ERR_MEMPOOL_IS_FULL:
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "mempool full");
                break;
            default:
                send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                            "CheckTx admission refused");
                break;
            }
            return;
        }
        /* rc == CMT_OK: the application WAS called. res.code == 0 is
         * acceptance; any other code is the application's own refusal
         * (nodus_witness_cmt_app.c's check_tx row), never a mempool
         * error — both are answered here, at once. */
        if (res.code != CMT_MEM_CODE_TYPE_OK) {
            /* "CheckTx code N" stays the prefix (a client that reads
             * "CheckTx code %u" still parses); ": <log>" follows when the
             * application wrote a reason — abci types.proto:265
             * ResponseCheckTx.log, which the reference returns to the
             * submitter (rpc/core/mempool.go:52). Node-local text, never
             * a verdict. 25 + (CMT_MEM_CHECK_TX_LOG_MAX - 1) bytes at
             * most: the receiver keeps 127 (nodus_tier2.h error_msg). */
            char msg[25 + CMT_MEM_CHECK_TX_LOG_MAX];
            _Static_assert(sizeof(msg) <= 128,
                           "the CheckTx answer must fit error_msg[128]");
            res.log[sizeof(res.log) - 1] = '\0';
            if (res.log[0] != '\0') {
                snprintf(msg, sizeof(msg), "CheckTx code %u: %s",
                         (unsigned)res.code, res.log);
            } else {
                snprintf(msg, sizeof(msg), "CheckTx code %u",
                         (unsigned)res.code);
            }
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR, msg);
            return;
        }

        uint8_t buf[128];
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        enc_dnac_response(&enc, txn_id, "dnac_spend", 1);
        cbor_encode_cstr(&enc, "status");
        cbor_encode_uint(&enc, (uint64_t)DNAC_STATUS_APPROVED);
        size_t rlen = cbor_encoder_len(&enc);
        if (rlen > 0) {
            nodus_tcp_send(conn, buf, rlen);
        } else {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "response buffer overflow");
        }
        return;
    }

    /* R3 W4 — on a non-version-3 chain this node runs no consensus lane
     * for it: the gate at open (witness_post_open_gate) already refused
     * every chain that is not version-3, so this is unreachable defence,
     * not a live path. Everything the legacy genesis precheck, nullifier
     * extraction, leader/follower branch, forward-to-leader and the
     * legacy mempool add used to do below this point is deleted with
     * the closed consensus lane. */
    send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                "this node runs no consensus lane for this chain");
    (void)client_pk;
    (void)client_sig;
    (void)fee;
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_token_list — List all registered tokens
 *
 * Request:  "a": {}
 * Response: "r": {"count":N, "tokens":[{tid,name,sym,dec,supply,creator},...]}
 * ════════════════════════════════════════════════════════════════════ */

#define DNAC_MAX_TOKEN_RESULTS 100

static void handle_dnac_token_list(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     uint32_t txn_id) {
    nodus_witness_token_entry_t *tokens = calloc(DNAC_MAX_TOKEN_RESULTS,
                                                   sizeof(nodus_witness_token_entry_t));
    if (!tokens) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    int count = 0;
    nodus_witness_token_list(w, tokens, DNAC_MAX_TOKEN_RESULTS, &count);

    size_t buf_size = 512 + ((size_t)count * 512);
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(tokens);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_token_list", 2);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);

    cbor_encode_cstr(&enc, "tokens");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        cbor_encode_map(&enc, 6);
        cbor_encode_cstr(&enc, "tid");
        cbor_encode_bstr(&enc, tokens[i].token_id, 64);
        cbor_encode_cstr(&enc, "name");
        cbor_encode_cstr(&enc, tokens[i].name);
        cbor_encode_cstr(&enc, "sym");
        cbor_encode_cstr(&enc, tokens[i].symbol);
        cbor_encode_cstr(&enc, "dec");
        cbor_encode_uint(&enc, tokens[i].decimals);
        cbor_encode_cstr(&enc, "supply");
        cbor_encode_uint(&enc, tokens[i].supply);
        cbor_encode_cstr(&enc, "creator");
        cbor_encode_cstr(&enc, tokens[i].creator_fp);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(tokens);
}

/* ════════════════════════════════════════════════════════════════════
 * HF-4 queries (design docs/plans/2026-10-02-onchain-names-design.md
 * rev 4 §1.6, §2 "Queries"; wire: include/nodus/nodus.h beside the
 * client functions). Every statement is finalized before the reply is
 * sent; a store fault is an error reply, never a fabricated value.
 * ════════════════════════════════════════════════════════════════════ */

/* The committed tip of the version-3 chain, and "a v3 chain is open". */
static int hf4_tip(nodus_witness_t *w, uint64_t *tip) {
    if (!w->db) return -1;
    return nodus_witness_v2_tip_height(w, tip) == 0 ? 0 : -1;
}

/* dnac_ruleset_info — the rule-set GENERATION governing tip + 1, read
 * from the REGISTRY (the committed SYSTEM and CORE manifests, never the
 * heads — the switch rewrites the registry at the end of H-1).
 * Response "r": {"tip" u64, "gen" u32, "sv" u32 SYSTEM ruleset_version,
 *   "sh" bstr64 SYSTEM ruleset_hash, "cv" u32, "ch" bstr64 (CORE),
 *   "pd" bstr64 the SYSTEM meter-policy digest of that generation,
 *   "H" u64 the earliest committed param-9 effective height (0 = none),
 *   "d2" u64 this build's DNAC_CFG_RULESET_GEN2_D2}. */
static void handle_dnac_ruleset_info(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     uint32_t txn_id) {
    uint64_t tip = 0, H = 0;
    const nodus_domain_runtime_t *rs = NULL, *rc = NULL;
    if (hf4_tip(w, &tip) != 0) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "no version-3 chain on this node");
        return;
    }
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &rs) != 0 ||
        nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &rc) != 0 ||
        !rs || !rc || rs->generation != rc->generation ||
        rs->generation == 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "the registry does not resolve one compiled generation");
        return;
    }
    {
        sqlite3_stmt *st = NULL;
        int ok = 0;
        if (sqlite3_prepare_v2(w->db,
                "SELECT MIN(effective_block) FROM chain_config_history "
                "WHERE param_id = ?1", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_int(st, 1, (int)DNAC_CFG_RULESET_GEN2);
            if (sqlite3_step(st) == SQLITE_ROW) {
                if (sqlite3_column_type(st, 0) == SQLITE_NULL) {
                    H = 0;
                    ok = 1;
                } else {
                    sqlite3_int64 v = sqlite3_column_int64(st, 0);
                    if (v > 0) { H = (uint64_t)v; ok = 1; }
                }
            }
        }
        sqlite3_finalize(st);
        if (!ok) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                       "RULESET_GEN2 history unreadable");
            return;
        }
    }

    uint8_t buf[512];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_ruleset_info", 9);
    cbor_encode_cstr(&enc, "tip"); cbor_encode_uint(&enc, tip);
    cbor_encode_cstr(&enc, "gen"); cbor_encode_uint(&enc, rs->generation);
    cbor_encode_cstr(&enc, "sv");  cbor_encode_uint(&enc, rs->ruleset_version);
    cbor_encode_cstr(&enc, "sh");  cbor_encode_bstr(&enc, rs->ruleset_hash, 64);
    cbor_encode_cstr(&enc, "cv");  cbor_encode_uint(&enc, rc->ruleset_version);
    cbor_encode_cstr(&enc, "ch");  cbor_encode_bstr(&enc, rc->ruleset_hash, 64);
    cbor_encode_cstr(&enc, "pd");
    cbor_encode_bstr(&enc, rs->descriptor.meter_policy_digest, 64);
    cbor_encode_cstr(&enc, "H");   cbor_encode_uint(&enc, H);
    cbor_encode_cstr(&enc, "d2");
    cbor_encode_uint(&enc, (uint64_t)DNAC_CFG_RULESET_GEN2_D2);
    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) nodus_tcp_send(conn, buf, rlen);
    else send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
}

/* Decode the single text argument `name_key` of a request. 0 / -1. */
static int hf4_tstr_arg(const uint8_t *payload, size_t len,
                        const char *name_key, const char **out,
                        size_t *out_len) {
    cbor_decoder_t dec;
    size_t args_count;
    int found = 0;
    if (decode_args(payload, len, &dec, &args_count) != 0) return -1;
    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, name_key)) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (found || val.type != CBOR_ITEM_TSTR) return -1;
            *out = val.tstr.ptr;
            *out_len = val.tstr.len;
            found = 1;
        } else {
            cbor_decode_skip(&dec);
        }
    }
    return found ? 0 : -1;
}

static void hf4_hex128(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 0x0F];
    }
    out[128] = '\0';
}

/* dnac_name_lookup — Request "a": {"name": tstr} (LOWERCASE only — the
 * consensus byte rule dnac_name_bytes_ok; a client lower-cases with an
 * ASCII-only mapping). Response "r": {"found" bool, "owner" tstr128 hex
 * (found), "rh" u64 registered_height (found), "ch" u64 the committed
 * height the answer is from}. */
static void handle_dnac_name_lookup(nodus_witness_t *w,
                                    struct nodus_tcp_conn *conn,
                                    const uint8_t *payload, size_t len,
                                    uint32_t txn_id) {
    const char *name = NULL;
    size_t nl = 0;
    uint64_t tip = 0;
    if (hf4_tstr_arg(payload, len, "name", &name, &nl) != 0 ||
        !dnac_name_bytes_ok((const uint8_t *)name, nl)) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid name (3-36 of a-z0-9, lowercase)");
        return;
    }
    if (hf4_tip(w, &tip) != 0) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "no version-3 chain on this node");
        return;
    }
    sqlite3_stmt *st = NULL;
    int found = 0, ok = 0;
    uint8_t owner[64];
    uint64_t rh = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, registered_height FROM v2_names WHERE name = ?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, name, (int)nl, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) {
            ok = 1;
        } else if (rc == SQLITE_ROW &&
                   sqlite3_column_bytes(st, 0) == 64 &&
                   sqlite3_column_int64(st, 1) >= 1) {
            memcpy(owner, sqlite3_column_blob(st, 0), 64);
            rh = (uint64_t)sqlite3_column_int64(st, 1);
            found = ok = 1;
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "names store unreadable");
        return;
    }
    uint8_t buf[512];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_name_lookup", found ? 4 : 2);
    cbor_encode_cstr(&enc, "found"); cbor_encode_bool(&enc, found != 0);
    if (found) {
        char hex[129];
        hf4_hex128(owner, hex);
        cbor_encode_cstr(&enc, "owner"); cbor_encode_cstr(&enc, hex);
        cbor_encode_cstr(&enc, "rh");    cbor_encode_uint(&enc, rh);
    }
    cbor_encode_cstr(&enc, "ch"); cbor_encode_uint(&enc, tip);
    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) nodus_tcp_send(conn, buf, rlen);
    else send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
}

/* dnac_name_of — Request "a": {"owner": tstr, exactly 128 lowercase
 * hex}. Response "r": {"found" bool, "name" tstr (found), "rh" u64
 * (found), "ch" u64 committed height}. */
static void handle_dnac_name_of(nodus_witness_t *w,
                                struct nodus_tcp_conn *conn,
                                const uint8_t *payload, size_t len,
                                uint32_t txn_id) {
    const char *hex = NULL;
    size_t hl = 0;
    uint8_t owner[64];
    uint64_t tip = 0;
    int bad = hf4_tstr_arg(payload, len, "owner", &hex, &hl) != 0 ||
              hl != 128;
    for (size_t i = 0; !bad && i < 64; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else { bad = 1; break; }
            v = (v << 4) | d;
        }
        owner[i] = (uint8_t)v;
    }
    if (bad) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid owner (128 lowercase hex)");
        return;
    }
    if (hf4_tip(w, &tip) != 0) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "no version-3 chain on this node");
        return;
    }
    sqlite3_stmt *st = NULL;
    int found = 0, ok = 0;
    char name[37];
    uint64_t rh = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name, registered_height FROM v2_names WHERE owner = ?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, owner, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) {
            ok = 1;
        } else if (rc == SQLITE_ROW) {
            int nl = sqlite3_column_bytes(st, 0);
            const uint8_t *nm = sqlite3_column_blob(st, 0);
            if (nm && dnac_name_bytes_ok(nm, (size_t)nl) &&
                sqlite3_column_int64(st, 1) >= 1) {
                memcpy(name, nm, (size_t)nl);
                name[nl] = '\0';
                rh = (uint64_t)sqlite3_column_int64(st, 1);
                found = ok = 1;
            }
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "names store unreadable");
        return;
    }
    uint8_t buf[256];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_name_of", found ? 4 : 2);
    cbor_encode_cstr(&enc, "found"); cbor_encode_bool(&enc, found != 0);
    if (found) {
        cbor_encode_cstr(&enc, "name"); cbor_encode_cstr(&enc, name);
        cbor_encode_cstr(&enc, "rh");   cbor_encode_uint(&enc, rh);
    }
    cbor_encode_cstr(&enc, "ch"); cbor_encode_uint(&enc, tip);
    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) nodus_tcp_send(conn, buf, rlen);
    else send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_storage_status — storage reward v1, package B2b-CLI (decision
 * docs/plans/decisions/2026-10-05-storage-reward-is-for-archive.md; wire:
 * include/nodus/nodus.h beside nodus_client_dnac_storage_status).
 *
 * Request "a": {"fp": tstr, exactly 128 lowercase hex = SHA3-512(node_pk)}.
 * Response "r" (READ-ONLY, committed tables only: v2_storage_nodes,
 * v2_storage_sets / _set_members, v2_storage_segments):
 *   "ch" u64 committed tip; "es" u64 H = ch − ch mod E, the boundary whose
 *   frozen storage_set(H) governs epoch (H, H+E] (0: none yet);
 *   "found" bool — the registry row exists; when found: "st" u8 status
 *   (1 ACTIVE / 2 EXITING / 3 RELEASED), "bond" u64, "fs" u32 fail_streak,
 *   "gu" u64 grace_until (K9: epoch (H, H+E] is in grace while H < gu),
 *   "rh" u64 registered_height, "xh" u64 exit_height, "payee" tstr128;
 *   "set" bool storage_set(H) exists; "sc" u32 its member count; "mem"
 *   bool the node is a member; "ns" u64 how many segments are ELIGIBLE for
 *   it in (H, H+E] (nodus_witness_storage_eligible_segments); "segs" the
 *   first min(ns, NODUS_DNAC_STORAGE_SEG_MAX) of them, k ascending.
 * The last SETTLED outcome is not in the reply: the settlement records no
 * per-member verdict (nodus_witness_v2_storage.c st_settle writes only
 * fail_streak and the payee accrual, and st_prune deletes the epoch's
 * reports at the same boundary) — fail_streak is its only committed trace.
 * A store fault is an error reply, never a partial answer.
 * ════════════════════════════════════════════════════════════════════ */

_Static_assert(NODUS_DNAC_STORAGE_SET_MAX == DNA_V2_STORAGE_SET_MAX,
               "the status wire's set bound is the chain's");

/* The registry row of `fp`. @return 1 found / 0 absent / -1 fault. */
static int st_status_row(nodus_witness_t *w, const uint8_t fp[64],
                         nodus_dnac_storage_status_t *o) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db,
            "SELECT payee_fp, bond, status, registered_height, exit_height, "
            "fail_streak, grace_until FROM v2_storage_nodes "
            "WHERE node_fp = ?1",
            -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW &&
               sqlite3_column_type(st, 0) == SQLITE_BLOB &&
               sqlite3_column_bytes(st, 0) == 64 &&
               sqlite3_column_blob(st, 0) != NULL) {
        int ok = 1;
        for (int c = 1; c <= 6; c++)
            if (sqlite3_column_type(st, c) != SQLITE_INTEGER) ok = 0;
        sqlite3_int64 bond = 0, stv = 0, rh = 0, xh = 0, fs = 0, gu = 0;
        if (ok) {
            bond = sqlite3_column_int64(st, 1);
            stv  = sqlite3_column_int64(st, 2);
            rh   = sqlite3_column_int64(st, 3);
            xh   = sqlite3_column_int64(st, 4);
            fs   = sqlite3_column_int64(st, 5);
            gu   = sqlite3_column_int64(st, 6);
        }
        if (ok && bond >= 0 && stv >= DNA_V2_STORAGE_ACTIVE &&
            stv <= DNA_V2_STORAGE_RELEASED && rh >= 1 && xh >= 0 &&
            fs >= 0 && fs <= (sqlite3_int64)UINT32_MAX && gu >= 0) {
            hf4_hex128(sqlite3_column_blob(st, 0), o->payee);
            o->bond = (uint64_t)bond;
            o->status = (uint8_t)stv;
            o->registered_height = (uint64_t)rh;
            o->exit_height = (uint64_t)xh;
            o->fail_streak = (uint32_t)fs;
            o->grace_until = (uint64_t)gu;
            ret = 1;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

static void handle_dnac_storage_status(nodus_witness_t *w,
                                       struct nodus_tcp_conn *conn,
                                       const uint8_t *payload, size_t len,
                                       uint32_t txn_id) {
    const char *hex = NULL;
    size_t hl = 0;
    uint8_t fp[64];
    uint64_t tip = 0;
    int bad = hf4_tstr_arg(payload, len, "fp", &hex, &hl) != 0 || hl != 128;
    for (size_t i = 0; !bad && i < 64; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else { bad = 1; break; }
            v = (v << 4) | d;
        }
        fp[i] = (uint8_t)v;
    }
    if (bad) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid fp (128 lowercase hex)");
        return;
    }
    if (hf4_tip(w, &tip) != 0) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "no version-3 chain on this node");
        return;
    }

    nodus_dnac_storage_status_t *o = calloc(1, sizeof(*o));
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    uint64_t *ks = NULL;
    uint8_t *buf = NULL;
    const char *fault = NULL;
    if (!o || !set) { fault = "out of memory"; goto done; }
    o->committed_height = tip;

    /* ── the registry row ─────────────────────────────────────────── */
    {
        int rr = st_status_row(w, fp, o);
        if (rr < 0) { fault = "storage registry unreadable"; goto done; }
        o->found = (rr == 1);
    }

    /* ── storage_set(H) for the current epoch (H, H+E] ────────────── */
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    o->epoch_start = tip - tip % E;
    if (o->epoch_start != 0) {
        int sr = nodus_witness_storage_set_get(w, o->epoch_start, set);
        if (sr < 0) { fault = "storage set unreadable"; goto done; }
        if (sr == 0) {
            o->set_exists = true;
            o->set_count = set->count;
            for (uint32_t i = 0; i < set->count; i++)
                if (memcmp(set->fps[i], fp, 64) == 0) o->member = true;
        }
    }
    if (o->member && !o->found) {        /* registry rows never vanish   */
        fault = "a storage set member has no registry row";
        goto done;
    }

    /* ── its eligible segments in (H, H+E] — every published segment k
     *    has k·P <= tip, so tip / P + 1 bounds the list ─────────────── */
    if (o->member) {
        const size_t cap = (size_t)(tip / (uint64_t)DNA_V2_SEGMENT_BLOCKS) + 1u;
        size_t n = 0;
        ks = calloc(cap, sizeof(*ks));
        if (!ks) { fault = "out of memory"; goto done; }
        if (nodus_witness_storage_eligible_segments(w, o->epoch_start, fp,
                                                    ks, cap, &n) != 0) {
            fault = "eligible segments unreadable";
            goto done;
        }
        o->n_segments = n;
        o->n_listed = n < NODUS_DNAC_STORAGE_SEG_MAX
                    ? n : (size_t)NODUS_DNAC_STORAGE_SEG_MAX;
        memcpy(o->segments, ks, o->n_listed * sizeof(*ks));
    }

    /* ── the reply ────────────────────────────────────────────────── */
    {
        const size_t cap = 4096;
        buf = malloc(cap);
        if (!buf) { fault = "out of memory"; goto done; }
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf, cap);
        enc_dnac_response(&enc, txn_id, "dnac_storage_status",
                          o->found ? 15 : 8);
        cbor_encode_cstr(&enc, "ch");    cbor_encode_uint(&enc, tip);
        cbor_encode_cstr(&enc, "es");    cbor_encode_uint(&enc, o->epoch_start);
        cbor_encode_cstr(&enc, "found"); cbor_encode_bool(&enc, o->found);
        if (o->found) {
            cbor_encode_cstr(&enc, "st");    cbor_encode_uint(&enc, o->status);
            cbor_encode_cstr(&enc, "bond");  cbor_encode_uint(&enc, o->bond);
            cbor_encode_cstr(&enc, "fs");
            cbor_encode_uint(&enc, o->fail_streak);
            cbor_encode_cstr(&enc, "gu");
            cbor_encode_uint(&enc, o->grace_until);
            cbor_encode_cstr(&enc, "rh");
            cbor_encode_uint(&enc, o->registered_height);
            cbor_encode_cstr(&enc, "xh");
            cbor_encode_uint(&enc, o->exit_height);
            cbor_encode_cstr(&enc, "payee");
            cbor_encode_cstr(&enc, o->payee);
        }
        cbor_encode_cstr(&enc, "set");   cbor_encode_bool(&enc, o->set_exists);
        cbor_encode_cstr(&enc, "sc");    cbor_encode_uint(&enc, o->set_count);
        cbor_encode_cstr(&enc, "mem");   cbor_encode_bool(&enc, o->member);
        cbor_encode_cstr(&enc, "ns");    cbor_encode_uint(&enc, o->n_segments);
        cbor_encode_cstr(&enc, "segs");
        cbor_encode_array(&enc, o->n_listed);
        for (size_t i = 0; i < o->n_listed; i++)
            cbor_encode_uint(&enc, o->segments[i]);
        size_t rlen = cbor_encoder_len(&enc);
        if (rlen > 0) nodus_tcp_send(conn, buf, rlen);
        else fault = "response buffer overflow";
    }

done:
    if (fault) {
        QGP_LOG_WARN(LOG_TAG, "dnac_storage_status: %s", fault);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, fault);
    }
    free(buf);
    free(ks);
    free(set);
    free(o);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_token_info — Query single token by token_id
 *
 * Request:  "a": {"tid": bstr(64)}
 * Response: "r": {"tid":bstr, "name":str, "sym":str, "dec":N, "supply":N, "creator":str}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_token_info(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     const uint8_t *payload, size_t len,
                                     uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing args map");
        return;
    }

    uint8_t token_id[64] = {0};
    bool has_tid = false;

    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "tid")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 64) {
                memcpy(token_id, val.bstr.ptr, 64);
                has_tid = true;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }

    if (!has_tid) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "missing tid field");
        return;
    }

    char name[64] = {0}, symbol[16] = {0}, creator[129] = {0};
    uint8_t decimals = 0;
    uint64_t supply = 0;

    int rc = nodus_witness_token_get(w, token_id, name, symbol,
                                       &decimals, &supply, creator);
    if (rc != 0) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                    "token not found");
        return;
    }

    uint8_t buf[512];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_token_info", 6);

    cbor_encode_cstr(&enc, "tid");
    cbor_encode_bstr(&enc, token_id, 64);
    cbor_encode_cstr(&enc, "name");
    cbor_encode_cstr(&enc, name);
    cbor_encode_cstr(&enc, "sym");
    cbor_encode_cstr(&enc, symbol);
    cbor_encode_cstr(&enc, "dec");
    cbor_encode_uint(&enc, decimals);
    cbor_encode_cstr(&enc, "supply");
    cbor_encode_uint(&enc, supply);
    cbor_encode_cstr(&enc, "creator");
    cbor_encode_cstr(&enc, creator);

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }
}

/* v0.16: dnac_pending_rewards_query RPC + nodus_witness_compute_pending_rewards
 * removed — push-settlement distributes rewards as UTXOs at each epoch
 * boundary so the client has no pending-balance to query. Rate-limit
 * state (g_pr_rate_table, pr_rate_check) retired with this handler. */

/* ════════════════════════════════════════════════════════════════════
 * dnac_committee_query — Phase 14 / Task 62.
 *
 * Returns the committee that governs the NEXT block (height+1), which
 * matches what the BFT layer actually uses for PROPOSE/PREVOTE/PRECOMMIT.
 * Each entry reports pubkey + stake + commission; status is resolved from
 * the validator table (so CLI/UI can surface RETIRING vs ACTIVE). The
 * endpoint field is best-effort: when the committee pubkey matches a
 * witness in the server's roster we populate the address, otherwise
 * leave it empty so the client falls back to the DHT/roster path.
 *
 * Request:  "a": {}
 * Response: "r": {"block_height": u64,
 *                 "epoch_start":  u64,
 *                 "committee": [
 *                   {"pk": bstr(2592), "stake": u64,
 *                    "comm": u16, "status": u8, "addr": tstr},
 *                   ... one entry per seat of the epoch's active set
 *                 ]}
 *
 * S3: the array is COUNT-DRIVEN on the wire, so a governance-widened
 * committee needs no wire change here — the encoder emits `count`
 * entries and the client decoder stops at its own struct capacity
 * (nodus_client.c nodus_client_dnac_committee). The client-side result
 * struct nodus_dnac_committee_result_t holds NODUS_T3_MAX_WITNESSES
 * entries (~370 KB — heap-only; its consumers in libdna, the CLI and
 * nodus-cli were all heapified in the same change), so every seat of a
 * governance-widened set is visible end-to-end.
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_committee_query(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          uint32_t txn_id) {
    uint64_t height      = nodus_witness_block_height(w);
    uint64_t target_h    = height + 1;   /* committee that signs next block */
    uint64_t epoch_start = (target_h / (uint64_t)DNAC_EPOCH_LENGTH) *
                             (uint64_t)DNAC_EPOCH_LENGTH;

    /* S3: heap — a DNAC_MAX_ACTIVE_VALIDATORS committee is ~334 KB. */
    nodus_committee_member_t *committee = NULL;
    int count = 0;
    int rc = nodus_committee_get_for_block_alloc(w, target_h, &committee,
                                                   &count);
    if (rc != 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "committee lookup failed");
        return;
    }

    /* Response: 3 top-level keys; each committee entry packs ~2700 bytes
     * (2592 pubkey + address 256 + overhead).
     *
     * S3: budgeted from DNAC_MAX_ACTIVE_VALIDATORS, the largest set this
     * release can elect, so a governance-widened committee cannot overrun
     * the encoder. The encoder is bounds-checked anyway
     * (cbor_encoder_len returns 0 on overflow and the caller reports the
     * error), but sizing to the real ceiling means the answer is a
     * response rather than an error. ~410 KB, malloc'd and freed on every
     * path — never the stack. */
    size_t buf_size = 512 + (size_t)DNAC_MAX_ACTIVE_VALIDATORS * 3200;
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(committee);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "alloc failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_committee_query", 3);

    cbor_encode_cstr(&enc, "block_height");
    cbor_encode_uint(&enc, target_h);

    cbor_encode_cstr(&enc, "epoch_start");
    cbor_encode_uint(&enc, epoch_start);

    cbor_encode_cstr(&enc, "committee");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        /* Status defaults to ACTIVE (0); pull real status from validator row. */
        uint8_t status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
        dnac_validator_record_t v_rec;
        if (nodus_validator_get(w, committee[i].pubkey, &v_rec) == 0) {
            status = v_rec.status;
        }

        /* Endpoint lookup (P2P-PORT F5): the roster's own rule
         * (witness_reply_addr) — this node's configured witness address
         * for itself, else the address the member's signed ADDR record
         * names (R-P2P-4), else an empty addr, as a roster miss was. */
        char addr[CMT_P2P_NETADDR_STR_MAX];
        witness_reply_addr(w, committee[i].pubkey, addr, sizeof(addr));

        cbor_encode_map(&enc, 5);
        cbor_encode_cstr(&enc, "pk");
        cbor_encode_bstr(&enc, committee[i].pubkey, DNAC_PUBKEY_SIZE);
        cbor_encode_cstr(&enc, "stake");
        cbor_encode_uint(&enc, committee[i].total_stake);
        cbor_encode_cstr(&enc, "comm");
        cbor_encode_uint(&enc, committee[i].commission_bps);
        cbor_encode_cstr(&enc, "status");
        cbor_encode_uint(&enc, status);
        cbor_encode_cstr(&enc, "addr");
        cbor_encode_cstr(&enc, addr);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(committee);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_validator_list_query — Phase 14 / Task 63.
 *
 * Paged, status-filtered view of the validators table for CLI/UI.
 *
 * Request:  "a": {"status": i8 (-1 = all, 0..3 = specific),
 *                  "limit":  u16 (1..DNAC_VALIDATOR_LIST_MAX_RESULTS),
 *                  "offset": u16}
 * Response: "r": {"count": u16, "total": u16,
 *                 "validators": [
 *                   {"pk":bstr(2592), "self":u64, "total":u64,
 *                    "ext":u64, "comm":u16, "status":u8,
 *                    "since":u64, "dlg":u32}, ... ]}
 *
 * Ordering: (self_stake + external_delegated) DESC, pubkey ASC. Same
 * ordering as top_n so rankings remain stable regardless of filter.
 *
 * `total` reports the total matching-filter row count (pre-pagination)
 * so clients can drive "next page" UIs.
 *
 * `dlg` (added after nodus 0.23.12) is how many of the validator's
 * NODUS_MAX_DELEGATORS_PER_VALIDATOR slots are filled: the number of
 * `delegations` rows whose validator_hash is this validator, read by
 * nodus_delegation_count_by_validator — the same
 * `SELECT COUNT(*) FROM delegations WHERE validator_hash = ?` the chain
 * decides the cap from (nodus_witness_rt_native.c rtn_sys_delegcnt_fetch,
 * gated in rtn_delegate_exec). Every count is read BEFORE encoding starts;
 * a count that cannot be read fails the whole reply (a DB failure is
 * never a value — never a 0). The counts are separate statements after
 * the page read, the same discipline nodus_validator_list_paged already
 * uses for its own COUNT and page (no wrapping transaction). This is a
 * node-local read for display; nothing in consensus reads this reply.
 * Older clients skip the unknown entry key
 * (nodus_client.c entry loop `else cbor_decode_skip`).
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_validator_list_query(nodus_witness_t *w,
                                                struct nodus_tcp_conn *conn,
                                                const uint8_t *payload, size_t len,
                                                uint32_t txn_id) {
    cbor_decoder_t dec;
    size_t args_count = 0;

    int filter_status = -1;
    int limit         = DNAC_VALIDATOR_LIST_MAX_RESULTS;
    int offset        = 0;

    /* Args map is optional — treat missing "a" as "defaults". */
    if (decode_args(payload, len, &dec, &args_count) == 0) {
        for (size_t i = 0; i < args_count; i++) {
            cbor_item_t key = cbor_decode_next(&dec);
            if (key_match(&key, "status")) {
                cbor_item_t val = cbor_decode_next(&dec);
                /* Encoded as UINT (0..3 for specific filter) or absent /
                 * non-UINT meaning "all statuses". This decoder does not
                 * surface CBOR NINT separately — clients that want "all"
                 * should either omit the key entirely or pass a NULL /
                 * boolean tombstone; a non-UINT value is treated as
                 * "all". */
                if (val.type == CBOR_ITEM_UINT) filter_status = (int)val.uint_val;
                else                            filter_status = -1;
            } else if (key_match(&key, "limit")) {
                cbor_item_t val = cbor_decode_next(&dec);
                if (val.type == CBOR_ITEM_UINT) {
                    limit = (int)val.uint_val;
                }
            } else if (key_match(&key, "offset")) {
                cbor_item_t val = cbor_decode_next(&dec);
                if (val.type == CBOR_ITEM_UINT) {
                    offset = (int)val.uint_val;
                }
            } else {
                cbor_decode_skip(&dec);
            }
        }
    }

    /* Cap + sanitize. */
    if (limit <= 0 || limit > DNAC_VALIDATOR_LIST_MAX_RESULTS) {
        limit = DNAC_VALIDATOR_LIST_MAX_RESULTS;
    }
    if (offset < 0) offset = 0;

    dnac_validator_record_t *vals =
        calloc((size_t)limit, sizeof(*vals));
    if (!vals) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "alloc failed");
        return;
    }

    int count = 0, total = 0;
    if (nodus_validator_list_paged(w, filter_status, offset, limit,
                                     vals, &count, &total) != 0) {
        free(vals);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "validator list query failed");
        return;
    }

    /* Delegator counts, all read before a byte is encoded (see the block
     * comment: a failed count is an error reply, never a 0). */
    int *dlg = NULL;
    if (count > 0) {
        dlg = calloc((size_t)count, sizeof(*dlg));
        if (!dlg) {
            free(vals);
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "alloc failed");
            return;
        }
    }
    for (int i = 0; i < count; i++) {
        if (nodus_delegation_count_by_validator(w, vals[i].pubkey,
                                                &dlg[i]) != 0 ||
            dlg[i] < 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "validator_list: delegator count read failed");
            free(dlg);
            free(vals);
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "delegator count query failed");
            return;
        }
    }

    /* Each entry ships pubkey (2592B) + 8 small ints. Budget 2800B. */
    size_t buf_size = 256 + (size_t)count * 2800;
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(dlg);
        free(vals);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "alloc failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_validator_list_query", 3);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);
    cbor_encode_cstr(&enc, "total");
    cbor_encode_uint(&enc, (uint64_t)total);

    cbor_encode_cstr(&enc, "validators");
    cbor_encode_array(&enc, (size_t)count);
    for (int i = 0; i < count; i++) {
        cbor_encode_map(&enc, 8);
        cbor_encode_cstr(&enc, "pk");
        cbor_encode_bstr(&enc, vals[i].pubkey, DNAC_PUBKEY_SIZE);
        cbor_encode_cstr(&enc, "self");
        cbor_encode_uint(&enc, vals[i].self_stake);
        cbor_encode_cstr(&enc, "total");
        cbor_encode_uint(&enc, vals[i].total_delegated);
        cbor_encode_cstr(&enc, "ext");
        cbor_encode_uint(&enc, vals[i].external_delegated);
        cbor_encode_cstr(&enc, "comm");
        cbor_encode_uint(&enc, vals[i].commission_bps);
        cbor_encode_cstr(&enc, "status");
        cbor_encode_uint(&enc, vals[i].status);
        cbor_encode_cstr(&enc, "since");
        cbor_encode_uint(&enc, vals[i].active_since_block);
        cbor_encode_cstr(&enc, "dlg");
        cbor_encode_uint(&enc, (uint64_t)dlg[i]);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(dlg);
    free(vals);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_v3_block — one committed version-3 block, paged (scan-v3)
 *
 * Decision docs/plans/decisions/2026-09-28-scan-v3-query.md; design
 * docs/plans/2026-09-28-scan-v3-design.md item 1. The wire (request
 * args, every response key, the budget and page bounds) is specified
 * ONCE, in include/nodus/nodus.h beside the client call
 * (nodus_client_dnac_v3_block); this comment names only where each
 * answered value COMES FROM:
 *
 *   h / tip          the request / nodus_witness_v2_tip_height
 *                    (MAX(v2_blocks.global_height))
 *   bid / pb / gr    v2_blocks.block_id / prev_block_id / global_root
 *                    (bid is cross-checked against the block store's
 *                    BlockMeta.block_id.hash — the cometbft header hash)
 *   ac               v2_blocks.tx_count (applied ENVELOPES — apply.c
 *                    phase 13 counts the applied wire ids only)
 *   tm / pa          BlockMeta.header.time / .proposer_address
 *                    (nodus_cmt_bs_load_block_meta)
 *   n                the block's Data.Txs count (nodus_cmt_bs_load_block)
 *   item "k"         nodus_witness_v2_classify_entry (200 → 1, 201 → 2,
 *                    an empty item → 0)
 *   item "c"         the STORED FinalizeBlock response,
 *                    tx_results[index].code
 *                    (nodus_cmt_ss_load_finalize_block_response); absent
 *                    → the request fails
 *   item "w"/"in"    applied envelope: v2_tx_index.tx_id and
 *                    v2_intent_index.intent_id at (h, global_index), with
 *                    global_index = the count of APPLIED envelopes before
 *                    it (apply.c cmt_item_index's `gidx`); a claim that
 *                    decodes: SHA3-512 of its bytes — the claim_hash
 *                    v2_claim_bytes stores (checked for an applied claim)
 *   item "f"/"op"    dna_env_decode (pure) — fee_amount and the legs'
 *                    (domain, runtime_op)
 *   effects          applied items only: an envelope's legs through
 *                    nodus_rt_native_describe_leg (the apply engine's own
 *                    decoders, nodus_witness_rt_native.c); a claim's coin
 *                    from its v2_claims_spent row (output_id, amount),
 *                    the id re-derived by dna_claim_utxo_id and the owner
 *                    = the claim's dest_binding (nodus_rt_core_claim_apply)
 *   Nodus EVM ri / ro     the CORE EVMFUND leg's describer (reserve_in /
 *                    reserve_out, from the sibling EVM call head)
 *   Nodus EVM ev          applied EVM items: evm_receipts (intent_id) at this
 *                    height, its SHA3-512 equal to the row's digest AND
 *                    the stored response's tx_results[i].data; decoded by
 *                    dna_evm_rcpt_decode; to / v / dst from
 *                    dna_evm_call_decode; fr = the EVM leg's committed
 *                    signer fp [0..32] (nodus_rt_native_committed_signer_fp)
 *
 * PURE READ (G1): no write, no transaction, no clock, no cache — the
 * answer is a function of the committed stores at `h`. FAIL-CLOSED: any
 * store/decode fault, a stored row that contradicts another, or an
 * applied item this build cannot describe answers an ERROR, never a
 * partial or zeroed page (nodus/CLAUDE.md "A DB failure is never a
 * value"). BOUNDED (G2): one block per request; the page's item bytes
 * stay within the clamped budget (a page always carries at least one
 * item, which alone is at most NODUS_V3_BLOCK_ITEM_MAX_BYTES), at most
 * NODUS_DNAC_V3_BLOCK_PAGE_MAX_ITEMS items; the decode storage is sized
 * from the block's own BlockMeta (block_size / num_txs), refused above
 * this node's executor limits.
 * ════════════════════════════════════════════════════════════════════ */

/* The largest one encoded item can be: 15 consumed ids (15 × 67 B),
 * 17 created coins (17 × ~300 B), the record map (~560 B) and the fixed
 * keys (~250 B) come to ~6.9 KB; a Nodus EVM item adds "ri"/"ro" (~20 B) and
 * "ev" (~420 B + NODUS_DNAC_V3_EVM_MAX_TICKETS × 67 B ≈ 2.6 KB) and
 * carries no record map, so ~9.5 KB at most; 16 KiB leaves headroom and
 * an item that does not fit is a node-local invariant broken → INTERNAL. */
#define NODUS_V3_BLOCK_ITEM_MAX_BYTES  16384u
/* The header keys, the "r" framing and the T2 envelope (~420 B). */
#define NODUS_V3_BLOCK_HDR_MAX_BYTES   1024u

_Static_assert((size_t)NODUS_DNAC_V3_BLOCK_BUDGET_MAX +
                   NODUS_V3_BLOCK_ITEM_MAX_BYTES +
                   NODUS_V3_BLOCK_HDR_MAX_BYTES <
               (size_t)NODUS_MAX_FRAME_TCP,
               "a dnac_v3_block page must fit the tier-2 frame");
_Static_assert(NODUS_RT_DESC_MAX_IN == NODUS_DNAC_V3_ITEM_MAX_IN &&
               NODUS_RT_DESC_MAX_OUT == NODUS_DNAC_V3_ITEM_MAX_OUT,
               "the wire's per-item bounds are the describer's");
_Static_assert((int)NODUS_RT_DESC_REC_STAKE ==
                   NODUS_DNAC_V3_REC_STAKE &&
               (int)NODUS_RT_DESC_REC_DELEGATE ==
                   NODUS_DNAC_V3_REC_DELEGATE &&
               (int)NODUS_RT_DESC_REC_UNSTAKE ==
                   NODUS_DNAC_V3_REC_UNSTAKE &&
               (int)NODUS_RT_DESC_REC_UNDELEGATE ==
                   NODUS_DNAC_V3_REC_UNDELEGATE &&
               (int)NODUS_RT_DESC_REC_VALIDATOR_UPDATE ==
                   NODUS_DNAC_V3_REC_VALIDATOR_UPDATE &&
               (int)NODUS_RT_DESC_REC_CHAIN_CONFIG ==
                   NODUS_DNAC_V3_REC_CHAIN_CONFIG,
               "the wire's record kinds are the describer's");

/** Everything one request allocates; released by v3b_free. */
typedef struct {
    nodus_witness_t               *w;
    nodus_cmt_store_t             *store;
    uint64_t                       height;
    /* the block */
    nodus_cmt_block_meta_t        *meta;
    uint8_t                       *dec_buf;
    cmt_pb_arena_t                 dec_arena;
    nodus_cmt_block_decode_t       dec;
    cmt_block_t                   *blk;
    /* the stored FinalizeBlock response */
    cmt_pb_response_finalize_block_t *resp;
    cmt_pb_rfb_storage_t           rst;
    cmt_pb_arena_t                 rst_arena;
    /* per-item scratch */
    dna_env_view_t                *view;
    dna_claim_t                   *claim;
    nodus_rt_leg_desc_t           *desc_core;
    nodus_rt_leg_desc_t           *desc_sys;
    nodus_rt_leg_desc_t           *desc_evm;    /* Nodus EVM: the EVM leg */
    /* prepared reads, finalized by v3b_free */
    sqlite3_stmt                  *st_ids;
    sqlite3_stmt                  *st_claim;
    sqlite3_stmt                  *st_cbytes;
    sqlite3_stmt                  *st_rcpt;     /* Nodus EVM: prepared on the
                                                 * first EVM item       */
    /* the outcome of a refusal */
    int                            err_code;
    char                           err_msg[128];
} v3b_ctx_t;

static void v3b_free(v3b_ctx_t *c)
{
    if (c->st_ids)    sqlite3_finalize(c->st_ids);
    if (c->st_claim)  sqlite3_finalize(c->st_claim);
    if (c->st_cbytes) sqlite3_finalize(c->st_cbytes);
    if (c->st_rcpt)   sqlite3_finalize(c->st_rcpt);
    free(c->meta);
    free(c->dec_buf);
    free(c->dec_arena.buf);
    free(c->dec.txs);
    free(c->dec.pb_evidence);
    free(c->dec.evidence);
    free(c->dec.pb_sigs);
    free(c->dec.sigs);
    free(c->blk);
    free(c->resp);
    free(c->rst.events);
    free(c->rst.attributes);
    free(c->rst.tx_results);
    free(c->rst.validator_updates);
    free(c->rst_arena.buf);
    free(c->view);
    free(c->claim);
    free(c->desc_core);
    free(c->desc_sys);
    free(c->desc_evm);
    memset(c, 0, sizeof(*c));
}

/* Record the refusal (first one wins) and return -1. A node-side fault
 * is logged at WARN; a refusal the CLIENT caused (bad height, bad index,
 * not held) only at DEBUG, so a client cannot make the node log at will. */
static int v3b_fail(v3b_ctx_t *c, int code, const char *msg)
{
    if (c->err_code == 0) {
        c->err_code = code;
        snprintf(c->err_msg, sizeof(c->err_msg), "%s", msg);
        if (code == NODUS_ERR_INTERNAL_ERROR)
            QGP_LOG_WARN(LOG_TAG, "dnac_v3_block h=%llu: %s",
                         (unsigned long long)c->height, msg);
        else
            QGP_LOG_DEBUG(LOG_TAG, "dnac_v3_block h=%llu: %s",
                          (unsigned long long)c->height, msg);
    }
    return -1;
}

static void v3b_hex64(const uint8_t raw[64], char out[129])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hexd[raw[i] >> 4];
        out[2 * i + 1] = hexd[raw[i] & 0x0F];
    }
    out[128] = '\0';
}

/* The op name an envelope's legs name — a mapping of the (domain,
 * runtime_op) constants of nodus_witness_runtime.h, no call byte read.
 * A SYSTEM or EVM leg names the envelope (its CORE sibling is the funding
 * leg); otherwise the CORE leg does. NULL = no name this build knows. */
static const char *v3b_op_name(const dna_env_view_t *v)
{
    const char *core = NULL;
    for (uint16_t l = 0; l < v->leg_count; l++) {
        uint32_t d = v->leg[l].domain_id, op = v->leg[l].runtime_op;
        if (d == DNA_DOMAIN_EVM) {
            switch (op) {
            case NODUS_RT_EVM_CALL:     return "evm_call";
            case NODUS_RT_EVM_CREATE:   return "evm_create";
            case NODUS_RT_EVM_DEPOSIT:  return "evm_deposit";
            case NODUS_RT_EVM_WITHDRAW: return "evm_withdraw";
            case NODUS_RT_EVM_REDEEM:   return "evm_redeem";
            default:                    return NULL;
            }
        }
        if (d == DNA_DOMAIN_SYSTEM) {
            switch (op) {
            case DNA_SYSRULE_STAKE:            return "stake";
            case DNA_SYSRULE_DELEGATE:         return "delegate";
            case DNA_SYSRULE_UNSTAKE:          return "unstake";
            case DNA_SYSRULE_UNDELEGATE:       return "undelegate";
            case DNA_SYSRULE_VALIDATOR_UPDATE: return "validator_update";
            case DNA_SYSRULE_CHAIN_CONFIG:     return "chain_config";
            default:                           return NULL;
            }
        }
        if (d == DNA_DOMAIN_CORE) {
            switch (op) {
            case DNA_CORERULE_SPEND:        core = "spend";        break;
            case DNA_CORERULE_BURN:         core = "burn";         break;
            case DNA_CORERULE_TOKEN_CREATE: core = "token_create"; break;
            case DNA_CORERULE_SYSFUND:      core = "sysfund";      break;
            case DNA_CORERULE_NAME_REGISTER: core = "name_register"; break;
            default:                        core = NULL;           break;
            }
        }
    }
    return core;
}

/* The block, its meta and the stored response, sized from the block's
 * OWN meta and refused above this node's executor limits. */
static int v3b_load(v3b_ctx_t *c, const nodus_cmt_host_limits_t *limits,
                    const uint8_t v2_block_id[64])
{
    bool   found = false;
    size_t bsize, ntx;
    int    rc;

    if (c->height < (uint64_t)nodus_cmt_bs_base(c->store) ||
        c->height > (uint64_t)nodus_cmt_bs_height(c->store))
        return v3b_fail(c, NODUS_ERR_NOT_FOUND,
                        "block not held by this node's block store");

    c->meta = calloc(1, sizeof(*c->meta));
    if (!c->meta)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR, "allocation failed");
    if (nodus_cmt_bs_load_block_meta(c->store, (int64_t)c->height, c->meta,
                                     &found) != CMT_OK || !found)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "block meta unreadable at a committed height");
    if (c->meta->block_size <= 0 || c->meta->num_txs < 0 ||
        (uint64_t)c->meta->block_size > (uint64_t)limits->tx_arena_cap ||
        (uint64_t)c->meta->num_txs > (uint64_t)limits->max_txs)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "block meta outside this node's executor limits");
    if (c->meta->block_id.hash_len != 64 ||
        memcmp(c->meta->block_id.hash, v2_block_id, 64) != 0)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "block store and ledger disagree on the block id");
    bsize = (size_t)c->meta->block_size;
    ntx   = (size_t)c->meta->num_txs;

    /* the LoadBlock storage — the handshaker's shape
     * (nodus_cmt_handshaker_init), sized to THIS block */
    c->dec_buf           = malloc(bsize);
    c->dec_arena.buf     = malloc(bsize);
    c->dec_arena.cap     = bsize;
    c->dec.arena         = &c->dec_arena;
    c->dec.txs           = calloc(ntx ? ntx : 1, sizeof(cmt_pb_bytes_t));
    c->dec.txs_cap       = ntx;
    c->dec.pb_evidence   = calloc(limits->max_evidence ? limits->max_evidence
                                                       : 1,
                                  sizeof(cmt_pb_evidence_t));
    c->dec.pb_evidence_cap = limits->max_evidence;
    c->dec.evidence      = calloc(limits->max_evidence ? limits->max_evidence
                                                       : 1,
                                  sizeof(cmt_pb_evidence_t));
    c->dec.evidence_cap  = limits->max_evidence;
    c->dec.pb_sigs       = calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    c->dec.pb_sigs_cap   = CMT_VALSET_MAX;
    c->dec.sigs          = calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    c->dec.sigs_cap      = CMT_VALSET_MAX;
    c->blk               = calloc(1, sizeof(*c->blk));
    if (!c->dec_buf || !c->dec_arena.buf || !c->dec.txs ||
        !c->dec.pb_evidence || !c->dec.evidence || !c->dec.pb_sigs ||
        !c->dec.sigs || !c->blk)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR, "allocation failed");
    found = false;
    if (nodus_cmt_bs_load_block(c->store, (int64_t)c->height, c->dec_buf,
                                bsize, &c->dec, c->blk, &found) != CMT_OK ||
        !found)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "block unreadable at a committed height");
    if (c->blk->data.txs_len != ntx)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "block and its meta disagree on the item count");

    /* the stored response — nodus_cmt_mock_app_open's pool shape, sized
     * to this block's item count */
    {
        size_t n_events = ntx + 8u;
        size_t n_attrs  = 4u * n_events;
        size_t acap     = (64u * 1024u) + (256u * ntx);

        c->resp = calloc(1, sizeof(*c->resp));
        c->rst.events = calloc(n_events, sizeof(cmt_pb_event_t));
        c->rst.events_cap = n_events;
        c->rst.attributes = calloc(n_attrs, sizeof(cmt_pb_event_attribute_t));
        c->rst.attributes_cap = n_attrs;
        c->rst.tx_results = calloc(ntx ? ntx : 1,
                                   sizeof(cmt_pb_stored_exec_tx_result_t));
        c->rst.tx_results_cap = ntx;
        c->rst.validator_updates = calloc(CMT_VALSET_MAX,
                                          sizeof(cmt_pb_validator_update_t));
        c->rst.validator_updates_cap = CMT_VALSET_MAX;
        c->rst_arena.buf = malloc(acap);
        c->rst_arena.cap = acap;
        c->rst.arena = &c->rst_arena;
        if (!c->resp || !c->rst.events || !c->rst.attributes ||
            !c->rst.tx_results || !c->rst.validator_updates ||
            !c->rst_arena.buf)
            return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                            "allocation failed");
    }
    rc = nodus_cmt_ss_load_finalize_block_response(c->store,
                                                   (int64_t)c->height,
                                                   &c->rst, c->resp);
    if (rc != CMT_OK)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "no stored FinalizeBlock response at a committed "
                        "height");
    if (c->resp->tx_results_len != ntx)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "stored response and block disagree on the item "
                        "count");
    return 0;
}

/* The applied envelope's two stored identities at (h, gidx). */
static int v3b_env_ids(v3b_ctx_t *c, uint32_t gidx, uint8_t wire[64],
                       uint8_t intent[64])
{
    int rc;

    sqlite3_reset(c->st_ids);
    sqlite3_bind_int64(c->st_ids, 1, (sqlite3_int64)c->height);
    sqlite3_bind_int64(c->st_ids, 2, (sqlite3_int64)gidx);
    rc = sqlite3_step(c->st_ids);
    if (rc != SQLITE_ROW ||
        sqlite3_column_bytes(c->st_ids, 0) != 64 ||
        sqlite3_column_bytes(c->st_ids, 1) != 64 ||
        sqlite3_column_bytes(c->st_ids, 2) != 64 ||
        memcmp(sqlite3_column_blob(c->st_ids, 0),
               sqlite3_column_blob(c->st_ids, 1), 64) != 0) {
        sqlite3_reset(c->st_ids);
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "applied envelope has no consistent index rows");
    }
    memcpy(wire, sqlite3_column_blob(c->st_ids, 0), 64);
    memcpy(intent, sqlite3_column_blob(c->st_ids, 2), 64);
    rc = sqlite3_step(c->st_ids);
    sqlite3_reset(c->st_ids);
    if (rc != SQLITE_DONE)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "applied envelope index rows are ambiguous");
    return 0;
}

static void v3b_enc_coin(cbor_encoder_t *e, const uint8_t id[64],
                         const uint8_t owner_hex[128], uint64_t amount,
                         const uint8_t token[64], uint64_t unlock)
{
    cbor_encode_map(e, 5);
    cbor_encode_cstr(e, "id"); cbor_encode_bstr(e, id, 64);
    cbor_encode_cstr(e, "o");  cbor_encode_tstr(e, (const char *)owner_hex,
                                                128);
    cbor_encode_cstr(e, "a");  cbor_encode_uint(e, amount);
    cbor_encode_cstr(e, "t");  cbor_encode_bstr(e, token, 64);
    cbor_encode_cstr(e, "u");  cbor_encode_uint(e, unlock);
}

static void v3b_enc_record(cbor_encoder_t *e, const nodus_rt_leg_desc_t *d)
{
    char   fp[129];
    size_t n = 1;

    switch (d->rec) {
    case NODUS_RT_DESC_REC_STAKE:            n += 4; break; /* v ds a cm  */
    case NODUS_RT_DESC_REC_DELEGATE:
    case NODUS_RT_DESC_REC_UNDELEGATE:       n += 3; break; /* v d a      */
    case NODUS_RT_DESC_REC_UNSTAKE:          n += 1; break; /* v          */
    case NODUS_RT_DESC_REC_VALIDATOR_UPDATE: n += 2; break; /* v cm       */
    case NODUS_RT_DESC_REC_CHAIN_CONFIG:     n += 3; break; /* p nv ef    */
    default:                                 break;
    }
    cbor_encode_map(e, n);
    cbor_encode_cstr(e, "k");
    cbor_encode_uint(e, (uint64_t)d->rec);
    if (d->rec == NODUS_RT_DESC_REC_CHAIN_CONFIG) {
        cbor_encode_cstr(e, "p");  cbor_encode_uint(e, d->cc_param_id);
        cbor_encode_cstr(e, "nv"); cbor_encode_uint(e, d->cc_new_value);
        cbor_encode_cstr(e, "ef"); cbor_encode_uint(e, d->cc_effective);
        return;
    }
    v3b_hex64(d->rec_validator_fp, fp);
    cbor_encode_cstr(e, "v"); cbor_encode_tstr(e, fp, 128);
    if (d->rec == NODUS_RT_DESC_REC_DELEGATE ||
        d->rec == NODUS_RT_DESC_REC_UNDELEGATE) {
        v3b_hex64(d->rec_delegator_fp, fp);
        cbor_encode_cstr(e, "d"); cbor_encode_tstr(e, fp, 128);
    }
    if (d->rec == NODUS_RT_DESC_REC_STAKE) {
        v3b_hex64(d->rec_dest_fp, fp);
        cbor_encode_cstr(e, "ds"); cbor_encode_tstr(e, fp, 128);
    }
    if (d->rec == NODUS_RT_DESC_REC_STAKE ||
        d->rec == NODUS_RT_DESC_REC_DELEGATE ||
        d->rec == NODUS_RT_DESC_REC_UNDELEGATE) {
        cbor_encode_cstr(e, "a"); cbor_encode_uint(e, d->rec_amount);
    }
    if (d->rec == NODUS_RT_DESC_REC_STAKE ||
        d->rec == NODUS_RT_DESC_REC_VALIDATOR_UPDATE) {
        cbor_encode_cstr(e, "cm"); cbor_encode_uint(e, d->rec_commission_bps);
    }
}

/* Nodus EVM P4-C — the facts of one APPLIED EVM item, all from stored bytes:
 * the receipt row (evm_receipts, written in the item's savepoint by
 * apply.c v2evm_index), the decoded call and the committed signer. */
typedef struct {
    uint8_t  status;
    uint64_t gas_used;
    uint8_t  from[32];
    bool     has_to, has_ca, has_v, has_dst;
    uint8_t  to[32];
    uint8_t  ca[32];
    uint8_t  value[32];
    uint8_t  dst[64];
    uint32_t n_logs;
    uint8_t  n_tk;
    bool     tk_more;
    uint8_t  tk[NODUS_DNAC_V3_EVM_MAX_TICKETS][64];
    uint8_t  wd[32];
    uint8_t  dg[64];
} v3b_evm_t;

/**
 * Read the EVM facts of block item `i`, whose EVM leg is leg `l` of
 * c->view and whose intent id is `intent`. FAIL-CLOSED: an applied EVM
 * item without a receipt row at this height, a receipt whose SHA3-512 is
 * not both the row's digest and the block's committed ExecTxResult.Data,
 * a receipt or call that does not decode, or a receipt naming another op
 * is a node-local invariant broken → INTERNAL, never a partial item.
 * @return 0 / -1 (the refusal recorded in `c`).
 */
static int v3b_evm_facts(v3b_ctx_t *c, uint32_t i, uint16_t l,
                         const uint8_t intent[64], v3b_evm_t *ev)
{
    const dna_env_view_t *v = c->view;
    const cmt_pb_bytes_t *data = &c->resp->tx_results[i].det.data;
    dna_evm_call_t call;
    dna_evm_rcpt_t r;
    uint8_t  fp[64], dg[64];
    uint16_t ns = 0;
    const uint8_t *blob;
    int      blen, rc;

    memset(ev, 0, sizeof(*ev));
    if (dna_evm_call_decode(v->leg[l].runtime_op, v->buf + v->call_off[l],
                            v->leg[l].call_len, &call) != 0)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "an applied EVM leg's call does not decode");
    rc = nodus_rt_native_committed_signer_fp(v, l, fp, &ns);
    if (rc != 0 || ns != 1)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        rc == -2 ? "hash backend failed" :
                        "an applied EVM leg has no single signer");
    memcpy(ev->from, fp, 32);            /* design §2: fp[0..32]          */

    if (!c->st_rcpt &&
        sqlite3_prepare_v2(c->w->db,
            "SELECT global_height, receipt, digest, item_index "
            "FROM evm_receipts WHERE intent_id = ?1", -1, &c->st_rcpt, NULL)
            != SQLITE_OK)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "receipt index unreadable");
    sqlite3_reset(c->st_rcpt);
    sqlite3_bind_blob(c->st_rcpt, 1, intent, 64, SQLITE_TRANSIENT);
    rc = sqlite3_step(c->st_rcpt);
    /* red-team 1 F12: the row's item_index is THIS block position i
     * (FinalizeBlock's env_block_pos) — the RPC's "x" names the same
     * item this page does */
    if (rc != SQLITE_ROW ||
        (uint64_t)sqlite3_column_int64(c->st_rcpt, 0) != c->height ||
        sqlite3_column_int64(c->st_rcpt, 3) != (sqlite3_int64)i ||
        sqlite3_column_bytes(c->st_rcpt, 2) != 64) {
        sqlite3_reset(c->st_rcpt);
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "an applied EVM item has no receipt at this height "
                        "and block position");
    }
    blob = sqlite3_column_blob(c->st_rcpt, 1);
    blen = sqlite3_column_bytes(c->st_rcpt, 1);
    if (!blob || blen <= 0 ||
        qgp_sha3_512(blob, (size_t)blen, dg) != 0 ||
        memcmp(dg, sqlite3_column_blob(c->st_rcpt, 2), 64) != 0 ||
        data->len != 64 || !data->data || memcmp(dg, data->data, 64) != 0 ||
        dna_evm_rcpt_decode(blob, (size_t)blen, &r) != 0 ||
        (uint32_t)r.op != v->leg[l].runtime_op) {
        sqlite3_reset(c->st_rcpt);
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "a stored EVM receipt is not the block's committed "
                        "receipt");
    }
    /* copy every fact out before the row is released */
    ev->status   = r.status;
    ev->gas_used = r.gas_used;
    ev->n_logs   = r.n_logs;
    memcpy(ev->wd, r.wei_destroyed, 32);
    memcpy(ev->dg, dg, 64);
    if (r.status == 1 && call.op == NODUS_RT_EVM_CREATE) {
        ev->has_ca = true;
        memcpy(ev->ca, r.created, 32);
    }
    ev->n_tk = (uint8_t)(r.n_tickets > NODUS_DNAC_V3_EVM_MAX_TICKETS
                             ? NODUS_DNAC_V3_EVM_MAX_TICKETS : r.n_tickets);
    ev->tk_more = r.n_tickets > NODUS_DNAC_V3_EVM_MAX_TICKETS;
    if (ev->n_tk) memcpy(ev->tk, r.tickets, (size_t)ev->n_tk * 64);
    sqlite3_reset(c->st_rcpt);

    if (call.op == NODUS_RT_EVM_CALL) {
        ev->has_to = true;
        memcpy(ev->to, call.to, 32);
    }
    if (call.op == NODUS_RT_EVM_CALL || call.op == NODUS_RT_EVM_CREATE) {
        ev->has_v = true;
        memcpy(ev->value, call.value_wei, 32);
    }
    if (call.op == NODUS_RT_EVM_WITHDRAW || call.op == NODUS_RT_EVM_REDEEM) {
        ev->has_dst = true;
        memcpy(ev->dst, call.dest_fp, 64);
    }
    return 0;
}

static void v3b_enc_evm(cbor_encoder_t *e, const v3b_evm_t *ev)
{
    size_t n = 6;                                 /* s gu fr nl wd dg     */
    n += ev->has_to ? 1 : 0;
    n += ev->has_ca ? 1 : 0;
    n += ev->has_v ? 1 : 0;
    n += ev->has_dst ? 1 : 0;
    n += ev->n_tk ? 1 : 0;
    n += ev->tk_more ? 1 : 0;
    cbor_encode_map(e, n);
    cbor_encode_cstr(e, "s");  cbor_encode_uint(e, ev->status);
    cbor_encode_cstr(e, "gu"); cbor_encode_uint(e, ev->gas_used);
    cbor_encode_cstr(e, "fr"); cbor_encode_bstr(e, ev->from, 32);
    if (ev->has_to)  { cbor_encode_cstr(e, "to");
                       cbor_encode_bstr(e, ev->to, 32); }
    if (ev->has_ca)  { cbor_encode_cstr(e, "ca");
                       cbor_encode_bstr(e, ev->ca, 32); }
    if (ev->has_v)   { cbor_encode_cstr(e, "v");
                       cbor_encode_bstr(e, ev->value, 32); }
    if (ev->has_dst) { cbor_encode_cstr(e, "dst");
                       cbor_encode_bstr(e, ev->dst, 64); }
    cbor_encode_cstr(e, "nl"); cbor_encode_uint(e, ev->n_logs);
    if (ev->n_tk) {
        cbor_encode_cstr(e, "tk");
        cbor_encode_array(e, ev->n_tk);
        for (uint8_t k = 0; k < ev->n_tk; k++)
            cbor_encode_bstr(e, ev->tk[k], 64);
    }
    if (ev->tk_more) { cbor_encode_cstr(e, "tkm"); cbor_encode_bool(e, true); }
    cbor_encode_cstr(e, "wd"); cbor_encode_bstr(e, ev->wd, 32);
    cbor_encode_cstr(e, "dg"); cbor_encode_bstr(e, ev->dg, 64);
}

/**
 * Encode item `i` into `e`. `*gidx` is the global index the NEXT applied
 * envelope holds; it advances when this item is one.
 * @return 0 / -1 (the refusal recorded in `c`).
 */
static int v3b_item(v3b_ctx_t *c, uint32_t i, uint32_t *gidx,
                    cbor_encoder_t *e)
{
    const cmt_pb_bytes_t *t = &c->blk->data.txs[i];
    uint32_t code = c->resp->tx_results[i].det.code;
    bool     applied = (code == 0);
    uint8_t  kind = 0;
    bool     has_w = false, has_in = false, has_f = false;
    uint8_t  wire[64], intent[64];
    uint64_t fee = 0;
    const char *op = NULL;
    /* effects (applied items only) */
    bool     eff = false;
    const nodus_rt_leg_desc_t *core = NULL, *sys = NULL, *evm = NULL;
    v3b_evm_t evf;                      /* Nodus EVM: an applied EVM item's */
    bool     has_ev = false;            /* facts ("ev")                  */
    uint8_t  cl_id[64], cl_owner[128];
    uint64_t cl_amount = 0;
    bool     cl_coin = false;
    static const uint8_t native_token[64] = {0};
    size_t   n_keys;

    if (t->len > 0 && t->data) {
        kind = nodus_witness_v2_classify_entry(t->data, (uint32_t)t->len)
                   == NODUS_W_TX_V2_ENVELOPE
                   ? NODUS_DNAC_V3_KIND_ENVELOPE : NODUS_DNAC_V3_KIND_CLAIM;
    }
    if (applied && kind == NODUS_DNAC_V3_KIND_EMPTY)
        return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                        "an empty item carries the applied code");

    if (kind == NODUS_DNAC_V3_KIND_ENVELOPE) {
        memset(c->view, 0, sizeof(*c->view));
        if (dna_env_decode(t->data, t->len, c->view) == 0) {
            has_f = true;
            fee = c->view->fee_amount;
            op = v3b_op_name(c->view);
        } else if (applied) {
            return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                            "an applied envelope does not decode");
        }
        if (applied) {
            if (v3b_env_ids(c, *gidx, wire, intent) != 0) return -1;
            has_w = has_in = true;
            (*gidx)++;
            for (uint16_t l = 0; l < c->view->leg_count; l++) {
                uint32_t dom = c->view->leg[l].domain_id;
                nodus_rt_leg_desc_t *d =
                    dom == DNA_DOMAIN_CORE ? c->desc_core :
                    dom == DNA_DOMAIN_EVM  ? c->desc_evm  : c->desc_sys;
                if ((d == c->desc_core && core) || (d == c->desc_sys && sys) ||
                    (d == c->desc_evm && evm))
                    return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                                    "an applied envelope repeats a domain");
                int drc = nodus_rt_native_describe_leg(c->view, l, c->height,
                                                       intent, d);
                if (drc != 0)
                    return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                                    drc == -2
                                        ? "hash backend failed describing "
                                          "an applied envelope"
                                        : "this build cannot describe an "
                                          "applied envelope");
                if (d == c->desc_core) core = d;
                else if (d == c->desc_evm) {
                    /* Nodus EVM: the EVM leg moves no native coin; its facts
                     * are the stored receipt's */
                    evm = d;
                    if (v3b_evm_facts(c, i, l, intent, &evf) != 0)
                        return -1;
                    has_ev = true;
                } else sys = d;
            }
            eff = true;
        }
    } else if (kind == NODUS_DNAC_V3_KIND_CLAIM) {
        memset(c->claim, 0, sizeof(*c->claim));
        if (dna_claim_decode(t->data, t->len, c->claim) == 0) {
            if (qgp_sha3_512(t->data, t->len, wire) != 0)
                return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                                "hash backend failed");
            has_w = true;
            op = "claim";
        } else if (applied) {
            return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                            "an applied claim does not decode");
        }
        if (applied) {
            uint8_t nul[64], want[64];
            int     rc;

            if (nodus_witness_v2_claim_nullifier(c->w, t->data, t->len,
                                                 nul) != 0)
                return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                                "an applied claim's nullifier is "
                                "underivable");
            sqlite3_reset(c->st_claim);
            sqlite3_bind_blob(c->st_claim, 1, nul, 64, SQLITE_TRANSIENT);
            rc = sqlite3_step(c->st_claim);
            if (rc != SQLITE_ROW ||
                sqlite3_column_bytes(c->st_claim, 0) != 64 ||
                sqlite3_column_int64(c->st_claim, 1) <= 0 ||
                (uint64_t)sqlite3_column_int64(c->st_claim, 2) !=
                    c->height) {
                sqlite3_reset(c->st_claim);
                return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                                "an applied claim has no spent-claim row "
                                "at this height");
            }
            memcpy(cl_id, sqlite3_column_blob(c->st_claim, 0), 64);
            cl_amount = (uint64_t)sqlite3_column_int64(c->st_claim, 1);
            sqlite3_reset(c->st_claim);
            /* the native CORE hook's own identity (claim_apply) */
            if (dna_claim_utxo_id(nul, want) != 0 ||
                memcmp(want, cl_id, 64) != 0)
                return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                                "an applied claim's output is not the "
                                "native CORE coin");
            {
                char oh[129];
                v3b_hex64(c->claim->dest_binding, oh);
                memcpy(cl_owner, oh, 128);
            }
            /* the canonical bytes the apply stored (phase 12c). That
             * phase stores EVERY decoded claim of the block, refused ones
             * included (apply.c phase 12c loops over blk->n_claims), so a
             * block carrying a byte-identical duplicate (refused as an
             * in-block duplicate) holds two rows with this hash: the
             * check is "present", never "exactly once". */
            sqlite3_reset(c->st_cbytes);
            sqlite3_bind_int64(c->st_cbytes, 1, (sqlite3_int64)c->height);
            sqlite3_bind_blob(c->st_cbytes, 2, wire, 64, SQLITE_TRANSIENT);
            rc = sqlite3_step(c->st_cbytes);
            if (rc != SQLITE_ROW || sqlite3_column_int64(c->st_cbytes, 0) < 1) {
                sqlite3_reset(c->st_cbytes);
                return v3b_fail(c, NODUS_ERR_INTERNAL_ERROR,
                                "an applied claim's bytes are not the "
                                "stored claim");
            }
            sqlite3_reset(c->st_cbytes);
            cl_coin = true;
            eff = true;
        }
    }

    /* the item map */
    n_keys = 3;                                   /* i k c */
    n_keys += has_w ? 1 : 0;
    n_keys += has_in ? 1 : 0;
    n_keys += has_f ? 1 : 0;
    n_keys += op ? 1 : 0;
    if (eff) {
        n_keys += 2;                              /* sp cr */
        n_keys += (core && core->burned) ? 1 : 0;
        n_keys += (sys && sys->rec != NODUS_RT_DESC_REC_NONE) ? 1 : 0;
        n_keys += (core && core->name_len) ? 2 : 0;   /* HF-4: nm pr  */
        n_keys += (core && core->reserve_in) ? 1 : 0;  /* Nodus EVM: ri    */
        n_keys += (core && core->reserve_out) ? 1 : 0; /* Nodus EVM: ro    */
        n_keys += has_ev ? 1 : 0;                      /* Nodus EVM: ev    */
    }
    cbor_encode_map(e, n_keys);
    cbor_encode_cstr(e, "i"); cbor_encode_uint(e, i);
    cbor_encode_cstr(e, "k"); cbor_encode_uint(e, kind);
    cbor_encode_cstr(e, "c"); cbor_encode_uint(e, code);
    if (has_w)  { cbor_encode_cstr(e, "w");  cbor_encode_bstr(e, wire, 64); }
    if (has_in) { cbor_encode_cstr(e, "in"); cbor_encode_bstr(e, intent, 64); }
    if (has_f)  { cbor_encode_cstr(e, "f");  cbor_encode_uint(e, fee); }
    if (op)     { cbor_encode_cstr(e, "op"); cbor_encode_cstr(e, op); }
    if (eff) {
        cbor_encode_cstr(e, "sp");
        cbor_encode_array(e, core ? core->n_consumed : 0);
        for (uint8_t k = 0; core && k < core->n_consumed; k++)
            cbor_encode_bstr(e, core->consumed[k], 64);
        cbor_encode_cstr(e, "cr");
        if (cl_coin) {
            cbor_encode_array(e, 1);
            v3b_enc_coin(e, cl_id, cl_owner, cl_amount, native_token, 0);
        } else {
            cbor_encode_array(e, core ? core->n_created : 0);
            for (uint8_t k = 0; core && k < core->n_created; k++)
                v3b_enc_coin(e, core->created[k].id,
                             core->created[k].owner_hex,
                             core->created[k].amount,
                             core->created[k].token_id,
                             core->created[k].unlock_block);
        }
        if (core && core->burned) {
            cbor_encode_cstr(e, "bu"); cbor_encode_uint(e, core->burned);
        }
        /* HF-4 (design §1.7): a NAME_REGISTER carries two OPTIONAL keys —
         * the name and the price paid into the reward pool. No new record
         * kind (old decoders bound rec_kind); old decoders skip unknown
         * keys. The price is never reported as "bu". */
        if (core && core->name_len) {
            cbor_encode_cstr(e, "nm");
            cbor_encode_tstr(e, (const char *)core->name, core->name_len);
            cbor_encode_cstr(e, "pr"); cbor_encode_uint(e, core->name_price);
        }
        /* Nodus EVM (P4-C): the CORE EVMFUND reserve move and the EVM facts —
         * OPTIONAL keys, an older decoder skips them */
        if (core && core->reserve_in) {
            cbor_encode_cstr(e, "ri"); cbor_encode_uint(e, core->reserve_in);
        }
        if (core && core->reserve_out) {
            cbor_encode_cstr(e, "ro"); cbor_encode_uint(e, core->reserve_out);
        }
        if (has_ev) {
            cbor_encode_cstr(e, "ev");
            v3b_enc_evm(e, &evf);
        }
        if (sys && sys->rec != NODUS_RT_DESC_REC_NONE) {
            cbor_encode_cstr(e, "rc");
            v3b_enc_record(e, sys);
        }
    }
    return 0;
}

int nodus_witness_v3_block_build(nodus_witness_t *w, nodus_cmt_store_t *store,
                                 const nodus_cmt_host_limits_t *limits,
                                 uint32_t txn_id, uint64_t height,
                                 uint32_t from_index, uint32_t budget,
                                 uint8_t **out, size_t *out_len,
                                 int *err_code, char *err_msg,
                                 size_t err_cap)
{
    v3b_ctx_t     c;
    uint64_t      tip = 0;
    uint8_t       bid[64], pbid[64], groot[64];
    uint64_t      applied_count = 0;
    uint8_t      *items = NULL, *scratch = NULL, *frame = NULL;
    size_t        items_len = 0, n_page = 0;
    uint32_t      n_items, gidx = 0, i;
    bool          has_next = false;
    uint32_t      next = 0;
    int           rc = -1;

    memset(&c, 0, sizeof(c));
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!w || !w->db || !store || !limits || !out || !out_len ||
        !err_code || !err_msg || err_cap == 0)
        return -1;
    c.w = w;
    c.store = store;
    c.height = height;

    if (budget == 0) budget = NODUS_DNAC_V3_BLOCK_BUDGET_MAX;
    if (budget < NODUS_DNAC_V3_BLOCK_BUDGET_MIN)
        budget = NODUS_DNAC_V3_BLOCK_BUDGET_MIN;
    if (budget > NODUS_DNAC_V3_BLOCK_BUDGET_MAX)
        budget = NODUS_DNAC_V3_BLOCK_BUDGET_MAX;

    if (height == 0) {
        v3b_fail(&c, NODUS_ERR_PROTOCOL_ERROR, "height must be >= 1");
        goto done;
    }
    /* Only COMMITTED state is an answer: a ledger transaction open on
     * this connection (the host's FinalizeBlock..Commit bracket) would
     * let these reads see a block that is not committed yet. The host
     * closes its bracket inside one apply call, so this refuses nothing
     * in practice — it makes "committed only" checked, not assumed. */
    if (sqlite3_get_autocommit(w->db) == 0) {
        v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR,
                 "a ledger transaction is in progress");
        goto done;
    }
    if (nodus_witness_v2_tip_height(w, &tip) != 0) {
        v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR, "chain height unreadable");
        goto done;
    }
    if (height > tip) {
        v3b_fail(&c, NODUS_ERR_NOT_FOUND, "height not committed");
        goto done;
    }

    /* the ledger's row for the height */
    {
        sqlite3_stmt *st = NULL;
        int srow;

        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id, prev_block_id, global_root, tx_count "
                "FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK) {
            v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR, "ledger unreadable");
            goto done;
        }
        sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
        srow = sqlite3_step(st);
        if (srow != SQLITE_ROW ||
            sqlite3_column_bytes(st, 0) != 64 ||
            sqlite3_column_bytes(st, 1) != 64 ||
            sqlite3_column_bytes(st, 2) != 64 ||
            sqlite3_column_int64(st, 3) < 0) {
            sqlite3_finalize(st);
            v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR,
                     "no well-formed ledger row at a committed height");
            goto done;
        }
        memcpy(bid, sqlite3_column_blob(st, 0), 64);
        memcpy(pbid, sqlite3_column_blob(st, 1), 64);
        memcpy(groot, sqlite3_column_blob(st, 2), 64);
        applied_count = (uint64_t)sqlite3_column_int64(st, 3);
        sqlite3_finalize(st);
    }

    if (v3b_load(&c, limits, bid) != 0) goto done;
    n_items = (uint32_t)c.blk->data.txs_len;
    if (from_index > n_items || (n_items > 0 && from_index == n_items)) {
        v3b_fail(&c, NODUS_ERR_PROTOCOL_ERROR, "item index out of range");
        goto done;
    }
    if (c.meta->header.time.seconds < 0 ||
        c.meta->header.time.nanos < 0 ||
        c.meta->header.proposer_address_len == 0 ||
        c.meta->header.proposer_address_len >
            sizeof(c.meta->header.proposer_address)) {
        v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR, "block header malformed");
        goto done;
    }

    c.view      = calloc(1, sizeof(*c.view));
    c.claim     = calloc(1, sizeof(*c.claim));
    c.desc_core = calloc(1, sizeof(*c.desc_core));
    c.desc_sys  = calloc(1, sizeof(*c.desc_sys));
    c.desc_evm  = calloc(1, sizeof(*c.desc_evm));
    items       = malloc((size_t)budget + NODUS_V3_BLOCK_ITEM_MAX_BYTES);
    scratch     = malloc(NODUS_V3_BLOCK_ITEM_MAX_BYTES);
    if (!c.view || !c.claim || !c.desc_core || !c.desc_sys || !c.desc_evm ||
        !items || !scratch) {
        v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR, "allocation failed");
        goto done;
    }
    if (sqlite3_prepare_v2(w->db,
            "SELECT t.tx_id, i.tx_id, i.intent_id FROM v2_tx_index t "
            "JOIN v2_intent_index i ON i.global_height = t.global_height "
            "AND i.global_index = t.global_index "
            "WHERE t.global_height = ?1 AND t.global_index = ?2",
            -1, &c.st_ids, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(w->db,
            "SELECT output_id, amount, claimed_height FROM v2_claims_spent "
            "WHERE nullifier = ?1", -1, &c.st_claim, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM v2_claim_bytes "
            "WHERE global_height = ?1 AND claim_hash = ?2",
            -1, &c.st_cbytes, NULL) != SQLITE_OK) {
        v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR, "ledger unreadable");
        goto done;
    }

    /* the applied envelopes BEFORE the page — the global index the
     * page's first applied envelope holds */
    for (i = 0; i < from_index; i++) {
        const cmt_pb_bytes_t *t = &c.blk->data.txs[i];
        if (c.resp->tx_results[i].det.code == 0 && t->len > 0 && t->data &&
            nodus_witness_v2_classify_entry(t->data, (uint32_t)t->len) ==
                NODUS_W_TX_V2_ENVELOPE)
            gidx++;
    }

    for (i = from_index; i < n_items; i++) {
        cbor_encoder_t ie;
        size_t         ilen;
        uint32_t       gidx_before = gidx;

        cbor_encoder_init(&ie, scratch, NODUS_V3_BLOCK_ITEM_MAX_BYTES);
        if (v3b_item(&c, i, &gidx, &ie) != 0) goto done;
        ilen = cbor_encoder_len(&ie);
        if (ilen == 0) {
            v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR,
                     "an item exceeds the per-item bound");
            goto done;
        }
        if (n_page > 0 &&
            (items_len + ilen > budget ||
             n_page >= NODUS_DNAC_V3_BLOCK_PAGE_MAX_ITEMS)) {
            gidx = gidx_before;
            has_next = true;
            next = i;
            break;
        }
        memcpy(items + items_len, scratch, ilen);
        items_len += ilen;
        n_page++;
    }

    /* the frame: the header keys, then "it" LAST so the item bytes
     * follow the array head verbatim */
    {
        size_t         cap = NODUS_V3_BLOCK_HDR_MAX_BYTES + items_len;
        cbor_encoder_t fe;
        size_t         hlen;
        uint64_t       tm_ms;

        frame = malloc(cap);
        if (!frame) {
            v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR, "allocation failed");
            goto done;
        }
        tm_ms = (uint64_t)c.meta->header.time.seconds * 1000u +
                (uint64_t)c.meta->header.time.nanos / 1000000u;
        cbor_encoder_init(&fe, frame, cap);
        enc_dnac_response(&fe, txn_id, "dnac_v3_block",
                          has_next ? 11 : 10);
        cbor_encode_cstr(&fe, "h");   cbor_encode_uint(&fe, height);
        cbor_encode_cstr(&fe, "bid"); cbor_encode_bstr(&fe, bid, 64);
        cbor_encode_cstr(&fe, "pb");  cbor_encode_bstr(&fe, pbid, 64);
        cbor_encode_cstr(&fe, "tm");  cbor_encode_uint(&fe, tm_ms);
        cbor_encode_cstr(&fe, "pa");
        cbor_encode_bstr(&fe, c.meta->header.proposer_address,
                         c.meta->header.proposer_address_len);
        cbor_encode_cstr(&fe, "gr");  cbor_encode_bstr(&fe, groot, 64);
        cbor_encode_cstr(&fe, "ac");  cbor_encode_uint(&fe, applied_count);
        cbor_encode_cstr(&fe, "n");   cbor_encode_uint(&fe, n_items);
        cbor_encode_cstr(&fe, "tip"); cbor_encode_uint(&fe, tip);
        if (has_next) {
            cbor_encode_cstr(&fe, "nx"); cbor_encode_uint(&fe, next);
        }
        cbor_encode_cstr(&fe, "it");  cbor_encode_array(&fe, n_page);
        hlen = cbor_encoder_len(&fe);
        if (hlen == 0 || hlen + items_len > cap) {
            v3b_fail(&c, NODUS_ERR_INTERNAL_ERROR,
                     "response buffer overflow");
            goto done;
        }
        memcpy(frame + hlen, items, items_len);
        *out = frame;
        *out_len = hlen + items_len;
        frame = NULL;
    }
    rc = 0;

done:
    if (rc != 0) {
        *err_code = c.err_code ? c.err_code : NODUS_ERR_INTERNAL_ERROR;
        snprintf(err_msg, err_cap, "%s",
                 c.err_msg[0] ? c.err_msg : "internal error");
    }
    free(frame);
    free(items);
    free(scratch);
    v3b_free(&c);
    return rc;
}

/* Request:  "a": {"h": u64, "i": u32 (optional), "b": u32 (optional)}
 * Response: the frame nodus_witness_v3_block_build encodes; an error
 *           reply when it refuses. */
static void handle_dnac_v3_block(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 const uint8_t *payload, size_t len,
                                 uint32_t txn_id)
{
    cbor_decoder_t dec;
    size_t   args_count;
    uint64_t h = 0;
    uint64_t from = 0, budget = 0;
    bool     have_h = false;

    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing args map");
        return;
    }
    for (size_t k = 0; k < args_count; k++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key.type == CBOR_ITEM_END || key.type == CBOR_ITEM_ERROR) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "truncated args map");
            return;
        }
        if (key_match(&key, "h") || key_match(&key, "i") ||
            key_match(&key, "b")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type != CBOR_ITEM_UINT) {
                send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                           "argument is not an unsigned integer");
                return;
            }
            if (key_match(&key, "h")) {
                h = val.uint_val;
                have_h = true;
            } else if (key_match(&key, "i")) {
                from = val.uint_val;
            } else {
                budget = val.uint_val;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }
    if (dec.error || !have_h || from > UINT32_MAX) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid height / item index");
        return;
    }
    if (budget > UINT32_MAX) budget = UINT32_MAX;   /* clamped below MAX */

    nodus_cmt_node_t *n = (nodus_cmt_node_t *)w->cmt_node;
    if (!w->v2_successor || !n || !n->store_ready) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "this node serves no version-3 chain");
        return;
    }

    uint8_t *frame = NULL;
    size_t   frame_len = 0;
    int      ecode = 0;
    char     emsg[128];
    if (nodus_witness_v3_block_build(w, &n->store, &n->limits, txn_id, h,
                                     (uint32_t)from, (uint32_t)budget,
                                     &frame, &frame_len, &ecode, emsg,
                                     sizeof(emsg)) != 0) {
        send_error(conn, txn_id, ecode ? ecode : NODUS_ERR_INTERNAL_ERROR,
                   emsg);
        return;
    }
    nodus_tcp_send(conn, frame, frame_len);
    free(frame);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_cc_collect — the node-side governance approval collection
 * (decision docs/plans/decisions/2026-09-26-cc-approval-via-own-node.md)
 *
 * Request:  "a": {"e": bstr — the pre-auth SYSTEM-governance envelope,
 *                  <= NODUS_T3_CC_APPR_E_MAX}
 * Response: "r": {"res": [ one entry per seat but this node's own ]}
 *           (nodus_witness_chain_config.c cc_collect_encode_reply) — sent
 *           when every asked seat answered or NODUS_CC_COLLECT_DEADLINE_MS
 *           passed; an error reply at once when the request is refused.
 *
 * Reached from nodus_server.c with the requesting session's identity —
 * the only dnac_* method that receives it (it is served to this node's
 * own identity only, decision (2)).
 * ════════════════════════════════════════════════════════════════════ */

void nodus_witness_handle_cc_collect(nodus_witness_t *w,
                                     struct nodus_tcp_conn *conn,
                                     const uint8_t client_pk[NODUS_PK_BYTES],
                                     const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                                     const uint8_t *payload, size_t len,
                                     uint32_t txn_id) {
    if (!w || !conn || !client_pk || !token || !payload) return;

    cbor_decoder_t dec;
    size_t args_count;
    if (decode_args(payload, len, &dec, &args_count) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR, "missing args map");
        return;
    }
    const uint8_t *e = NULL;
    size_t e_len = 0;
    for (size_t i = 0; i < args_count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (key_match(&key, "e")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (val.type == CBOR_ITEM_BSTR) {
                e = val.bstr.ptr;
                e_len = val.bstr.len;
            }
        } else {
            cbor_decode_skip(&dec);
        }
    }
    if (!e || e_len == 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR, "missing e");
        return;
    }
    if (e_len > NODUS_T3_CC_APPR_E_MAX) {
        send_error(conn, txn_id, NODUS_ERR_TOO_LARGE, "envelope too large");
        return;
    }

    char err[160] = "";
    if (nodus_witness_cc_collect_start(w, client_pk, token, txn_id, e, e_len,
                                       nodus_p2p_mono_ns(NULL) / 1000000,
                                       err, sizeof(err)) != 0) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   err[0] ? err : "approval collection refused");
    }
}

/* ════════════════════════════════════════════════════════════════════
 * Nodus EVM §18 — the EVM read RPC (design docs/plans/2026-10-04-nodus-evm-chain-
 * integration-design.md rev 3 §18; §8 rev 4 for the simulation bound).
 *
 * Every method answers from THIS node's COMMITTED tip state, read-only;
 * every reply's "h" is the committed tip EXCEPT evm_receipt's and each
 * evm_logs entry's, which are the INCLUSION height (the receipt's item
 * index "x" — the item's position in the decided block's tx list, claims
 * and undecodable items counted (red-team 1 F12) — and its digest "dg"
 * are meaningful only against the block
 * that holds them, and "dg" is bound by the NEXT block's
 * LastResultsHash — §7). Node-local; nothing here enters block validity.
 * The EVM domain must be ACTIVE in the registry (nodus_witness_v2_
 * runtime_for, require_active) — otherwise NOT_FOUND "the EVM domain is
 * not active". A build without the EVM runtime (the messenger tree,
 * Windows) answers every evm_* "not compiled into this build".
 *
 *   evm_account {a:addr32} → {n, b:bstr32, ch:bstr32, cs, h}
 *       (no account: n 0, b 0, ch keccak256(""), cs 0)
 *   evm_code    {a}        → {c:bstr, h}
 *   evm_storage {a, k:bstr32} → {v:bstr32, h}
 *   evm_call    {f:addr32, t?:addr32 (absent = CREATE), v?:bstr32,
 *                d:bstr, g?:u64 (absent = NODUS_RT_EVM_TX_GAS_CAP)}
 *                          → {s:0/1, o:bstr, gu, h}
 *       o = return data, or the REVERT data when s = 0 (a stored
 *       receipt of a failed transaction carries no output — §4 — so this
 *       is where a revert reason is read); gu = what a receipt would say
 *       (the engine's gas on success, the gas limit on failure — §4).
 *       A call refused BEFORE execution (nonce / value > balance /
 *       intrinsic gas / EIP-3607) is a PROTOCOL_ERROR reply, not s = 0.
 *   evm_estimate = evm_call + {ge, ue, fe}:
 *       ge — the smallest gas_limit that succeeds, by BINARY SEARCH over
 *            [engine gas used, g]: the engine's own figure is tried first;
 *            otherwise at most EVM_EST_MAX_PROBES further simulations,
 *            stopping when the interval is within 1/64 of its upper end
 *            (the EIP-150 63/64 retention is the usual reason the engine
 *            figure alone fails) — ge is the smallest SUCCESSFUL limit
 *            seen. On a failure at g, ge = g (nothing succeeds to search).
 *       ue — res_max_total_units for the REFERENCE SHAPE
 *            (client/nodus_v2_evm.h nodus_v2_evm_ref_units: one funding
 *            input, one change output, the default effect declaration, no
 *            access list) at ge, + the logical reads the run at ge made ×
 *            w_read of the generation's SYSTEM policy. A client building
 *            another shape takes the read units as ue − ref_units(same op,
 *            data length, ge) and adds them to its own minimum.
 *       fe — max(floor, ue × GAS_PRICE_RAW_PER_UNIT at tip + 1), floor =
 *            max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE) (rtn_evmfund_exec).
 *       NOT modelled: a success stream over the envelope's effect
 *       declaration (the paid failure path, §4) — a call has none.
 *   evm_receipt {i:bstr64 intent_id} → {h (inclusion), x, s, op, gu,
 *       cr? (a successful CREATE), o, logs:[{a, t:[bstr32], d}],
 *       wd:bstr32, tk:[bstr64], dg:bstr64} — or {} when this node has no
 *       receipt for it. The stored bytes are re-hashed and must equal the
 *       stored digest (a mismatch is an INTERNAL_ERROR, never an answer).
 *   evm_logs {fh, th, a?, t0..t3?, lim, c?:[h, x, li]} →
 *       {logs:[{h, x, li, a, t, d, i}], more:bool, c?:[h, x, li]};
 *       th >= fh, th − fh < 10 000 (at most 10 000 blocks),
 *       1 <= lim <= 1000; ordered (height, item index, log index). The
 *       request's "c" resumes a scan (fh <= c.h <= th; the cursor a
 *       previous reply returned); without it the scan starts at (fh, 0,
 *       0). A CURSOR SCAN (nodus_witness_evm_logs_scan, v2_schema.h):
 *       index-ordered, at most EVM_LOGS_MAX_EXAMINED rows EXAMINED per
 *       request (matches or not), the reply estimate stops at
 *       EVM_LOGS_REPLY_BUDGET bytes past the first log, every examined
 *       row and returned byte charged to the work budget below. A reply
 *       that stops before th (lim reached, a bound, the budget) carries
 *       more = true AND "c" — the first position not yet examined; a
 *       reply with more = true may hold no log (the bound was spent on
 *       non-matching rows) — ask again from "c". Resuming from "c" skips
 *       no match and repeats none.
 *   evm_ticket {id:bstr64} → {p:bool, amt, dst:bstr64} (p false: no such
 *       pending ticket — never existed or already redeemed; amt 0, dst 0).
 *
 * WORK BOUND (§8 rev 4 / §18 rev 5, red-team 1 F4: no clock is read): the
 * handlers run INLINE on the witness's one event loop (dnac_spend's
 * CheckTx is inline too) — a request runs to completion before the loop
 * serves anything else, consensus messages included. ONE per-HEIGHT gas
 * budget (NODUS_RT_EVM_SIM_GAS_PER_HEIGHT) covers EVERY evm_* read: it
 * belongs to the committed tip height and resets when the tip moves.
 *   - every request that passes the gate pays EVM_RPC_BASE_GAS (one
 *     examined row) — a miss, an absent account, a refusal included;
 *   - evm_code pays its chunk rows and code bytes, evm_receipt its row
 *     and the stored receipt's bytes — BEFORE either is copied or hashed;
 *   - evm_logs pays every examined row and returned byte (gas(e, b) of
 *     the scan), within what the budget has left;
 *   - a simulation (the ONE funnel, evm_sim_once) charges its gas_limit
 *     up front (a run cannot be pre-empted) and keeps the engine's
 *     PRE-refund work (engine_work_gas — a refund lowers what a sender
 *     pays, not what this node ran); a refusal before execution keeps its
 *     reads × NODUS_EVM_RPC_GAS_PER_ROW, a fault one row — never zero.
 * Rows → gas is NODUS_EVM_RPC_GAS_PER_ROW, bytes → gas
 * NODUS_EVM_RPC_GAS_PER_BYTE (both nodus_witness_v2_schema.h, with their
 * reference). What does not fit is not run: RATE_LIMITED until the next
 * block (evm_logs: a shorter page with its cursor). So between two blocks
 * this node spends at most that much work, whatever the number of
 * sessions or requests. evm_estimate runs at most 2 + EVM_EST_MAX_PROBES
 * simulations, each through the funnel; a probe refused for budget
 * refuses the whole request (no partial estimate). The budget is
 * node-local — no block, vote or root reads it. Committed state only:
 * refused while the witness's database holds an open transaction.
 *
 * REPLY SIZE: a reply over EVM_REPLY_MAX (the transport's frame bound
 * less the channel overhead) is answered TOO_LARGE, never dropped; a send
 * that fails for any other reason (a closed connection) is logged.
 * ════════════════════════════════════════════════════════════════════ */

#ifdef NODUS_EVM_ENABLED

#define EVM_EST_MAX_PROBES       16
#define EVM_LOGS_MAX_SPAN        10000u
#define EVM_LOGS_MAX_LIM         NODUS_EVM_LOGS_SCAN_MAX_LIM
#define EVM_LOGS_REPLY_BUDGET    ((size_t)1024 * 1024)
/* examined rows per evm_logs request (red-team 1 F4): at
 * NODUS_EVM_RPC_GAS_PER_ROW each, 21 M of the 60 M per-height budget */
#define EVM_LOGS_MAX_EXAMINED    10000u
/* a request pays at least one examined row (red-team 1 F4: misses and
 * refusals are never free) */
#define EVM_RPC_BASE_GAS         ((uint64_t)NODUS_EVM_RPC_GAS_PER_ROW)
/* the largest reply sent: the transport refuses a payload over
 * NODUS_MAX_FRAME_TCP (nodus_tcp.c send_progress_locked) and an
 * established channel adds NODUS_CHANNEL_OVERHEAD (28 bytes,
 * nodus_channel_crypto.h:28) — 64 bytes of margin cover it */
#define EVM_REPLY_MAX            ((size_t)NODUS_MAX_FRAME_TCP - 64u)
#define EVM_SIM_BUDGET_MSG \
    "the node's EVM read budget for this block is used; ask again " \
    "after the next block"

_Static_assert(NODUS_EVM_RPC_GAS_PER_ROW == EVM_G_COLD_STORAGE_ACCESS,
               "rows -> gas is the cold storage read (v2_schema.h)");
_Static_assert(NODUS_EVM_RPC_GAS_PER_BYTE == EVM_G_OPCODE_LOG_DATA_PER_BYTE,
               "bytes -> gas is the log data byte (v2_schema.h)");
_Static_assert((uint64_t)EVM_LOGS_MAX_EXAMINED * NODUS_EVM_RPC_GAS_PER_ROW +
               (uint64_t)EVM_LOGS_REPLY_BUDGET * NODUS_EVM_RPC_GAS_PER_BYTE <
               NODUS_RT_EVM_SIM_GAS_PER_HEIGHT,
               "one full evm_logs page fits the per-height budget");

/* The per-height work budget (WORK BOUND above): the committed tip height
 * it belongs to and the gas charged against it so far. File-static and
 * unlocked because the witness is single-threaded — every evm_* handler
 * runs on its one event loop. Node-local. */
static uint64_t g_evm_work_tip = 0;
static uint64_t g_evm_work_charged = 0;

/* The budget left at `tip` (a new tip: a new budget). */
static uint64_t evm_work_left(uint64_t tip) {
    if (tip != g_evm_work_tip) {
        g_evm_work_tip = tip;
        g_evm_work_charged = 0;
    }
    return NODUS_RT_EVM_SIM_GAS_PER_HEIGHT - g_evm_work_charged;
}

/* Charge `gas` at `tip`. @return 0 charged / 1 it does not fit (nothing
 * charged). */
static int evm_work_charge(uint64_t tip, uint64_t gas) {
    if (gas > evm_work_left(tip)) return 1;
    g_evm_work_charged += gas;
    return 0;
}

/* The arguments every evm_* method may carry (§18 keys). Unknown keys are
 * skipped; a repeated key or a wrong type refuses the request. */
typedef struct {
    const uint8_t *a, *k, *f, *t, *v, *d, *i, *id;
    size_t         d_len;
    int            has_d, has_g, has_fh, has_th, has_lim, has_c;
    uint64_t       g, fh, th, lim;
    uint64_t       c[3];               /* evm_logs cursor (h, x, li)      */
    const uint8_t *tp[4];
} evm_args_t;

static int evm_bstr_arg(cbor_decoder_t *dec, const uint8_t **slot,
                        size_t want) {
    cbor_item_t val = cbor_decode_next(dec);
    if (*slot || val.type != CBOR_ITEM_BSTR || val.bstr.len != want)
        return -1;
    *slot = val.bstr.ptr;
    return 0;
}

static int evm_uint_arg(cbor_decoder_t *dec, int *has, uint64_t *slot) {
    cbor_item_t val = cbor_decode_next(dec);
    if (*has || val.type != CBOR_ITEM_UINT) return -1;
    *slot = val.uint_val;
    *has = 1;
    return 0;
}

/** @return 0 / -1 (malformed). */
static int evm_args_parse(const uint8_t *payload, size_t len,
                          evm_args_t *x) {
    cbor_decoder_t dec;
    size_t n = 0;
    memset(x, 0, sizeof(*x));
    if (decode_args(payload, len, &dec, &n) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        int rc = 0;
        if (key_match(&key, "a"))        rc = evm_bstr_arg(&dec, &x->a, 32);
        else if (key_match(&key, "k"))   rc = evm_bstr_arg(&dec, &x->k, 32);
        else if (key_match(&key, "f"))   rc = evm_bstr_arg(&dec, &x->f, 32);
        else if (key_match(&key, "t"))   rc = evm_bstr_arg(&dec, &x->t, 32);
        else if (key_match(&key, "v"))   rc = evm_bstr_arg(&dec, &x->v, 32);
        else if (key_match(&key, "i"))   rc = evm_bstr_arg(&dec, &x->i, 64);
        else if (key_match(&key, "id"))  rc = evm_bstr_arg(&dec, &x->id, 64);
        else if (key_match(&key, "t0"))  rc = evm_bstr_arg(&dec, &x->tp[0], 32);
        else if (key_match(&key, "t1"))  rc = evm_bstr_arg(&dec, &x->tp[1], 32);
        else if (key_match(&key, "t2"))  rc = evm_bstr_arg(&dec, &x->tp[2], 32);
        else if (key_match(&key, "t3"))  rc = evm_bstr_arg(&dec, &x->tp[3], 32);
        else if (key_match(&key, "g"))   rc = evm_uint_arg(&dec, &x->has_g, &x->g);
        else if (key_match(&key, "fh"))  rc = evm_uint_arg(&dec, &x->has_fh, &x->fh);
        else if (key_match(&key, "th"))  rc = evm_uint_arg(&dec, &x->has_th, &x->th);
        else if (key_match(&key, "lim")) rc = evm_uint_arg(&dec, &x->has_lim, &x->lim);
        else if (key_match(&key, "c")) {
            /* the evm_logs cursor: exactly [h, x, li], three uints */
            cbor_item_t arr = cbor_decode_next(&dec);
            if (x->has_c || arr.type != CBOR_ITEM_ARRAY || arr.count != 3) {
                rc = -1;
            } else {
                for (int k = 0; k < 3 && rc == 0; k++) {
                    cbor_item_t u = cbor_decode_next(&dec);
                    if (u.type != CBOR_ITEM_UINT) rc = -1;
                    else x->c[k] = u.uint_val;
                }
                x->has_c = 1;
            }
        } else if (key_match(&key, "d")) {
            cbor_item_t val = cbor_decode_next(&dec);
            if (x->has_d || val.type != CBOR_ITEM_BSTR ||
                val.bstr.len > (size_t)DNA_ENV_MAX_TOTAL_LEN)
                rc = -1;
            else {
                x->d = val.bstr.ptr;
                x->d_len = val.bstr.len;
                x->has_d = 1;
            }
        } else {
            cbor_decode_skip(&dec);
        }
        if (rc != 0 || dec.error) return -1;
    }
    return 0;
}

/* The gate of every evm_* method: a version-3 chain, its committed tip,
 * committed state only, the EVM domain ACTIVE — then EVM_RPC_BASE_GAS
 * from the work budget (WORK BOUND above: a miss is never free).
 * @return 0 / -1 (an error reply was sent). */
static int evm_gate(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                    uint32_t txn_id, uint64_t *tip,
                    const nodus_domain_runtime_t **evm_rt) {
    if (hf4_tip(w, tip) != 0) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "no version-3 chain on this node");
        return -1;
    }
    if (!sqlite3_get_autocommit(w->db)) {
        send_error(conn, txn_id, NODUS_ERR_RATE_LIMITED,
                   "a block is being applied; ask again");
        return -1;
    }
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_EVM, 1, evm_rt) != 0 ||
        !*evm_rt) {
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "the EVM domain is not active on this chain");
        return -1;
    }
    if (evm_work_charge(*tip, EVM_RPC_BASE_GAS) != 0) {
        send_error(conn, txn_id, NODUS_ERR_RATE_LIMITED, EVM_SIM_BUDGET_MSG);
        return -1;
    }
    return 0;
}

/* Send one encoded reply. An encoder overflow is INTERNAL_ERROR; a reply
 * over EVM_REPLY_MAX is TOO_LARGE (an answer the client can act on —
 * narrow the request — never a silently missing reply); any other send
 * failure is a connection that cannot take a frame (closed, upgrading)
 * and is logged: there is nobody to answer. */
static void evm_send(struct nodus_tcp_conn *conn, uint32_t txn_id,
                     const cbor_encoder_t *enc, const uint8_t *buf) {
    size_t rlen = cbor_encoder_len(enc);
    if (rlen == 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "response buffer overflow");
        return;
    }
    if (rlen > EVM_REPLY_MAX) {
        send_error(conn, txn_id, NODUS_ERR_TOO_LARGE,
                   "the reply is over the frame bound; narrow the request");
        return;
    }
    /* nodus_tcp_send answers 0 for a written, buffered or queued frame
     * (nodus_tcp.c send_progress_locked) and -1 only when the frame was
     * not taken: a closed or failed connection, or a full pending queue */
    if (nodus_tcp_send(conn, buf, rlen) != 0)
        QGP_LOG_WARN(LOG_TAG, "evm reply (txn %u, %zu bytes) not sent: the "
                     "connection is closed / failed or its queue is full",
                     (unsigned)txn_id, rlen);
}

/* ── evm_account / evm_code / evm_storage / evm_ticket ────────────── */

/* The evm_accounts row of `addr`. @return 1 found / 0 absent / -1 fault. */
static int evm_acct_row(nodus_witness_t *w, const uint8_t addr[32],
                        uint64_t *nonce, uint8_t bal[32], uint8_t ch[32],
                        uint32_t *cs, uint8_t digest[64]) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db,
            "SELECT nonce, balance, code_hash, code_size, code_digest "
            "FROM evm_accounts WHERE addr = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, addr, 32, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        ret = 0;
    } else if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 1) == 32 &&
               sqlite3_column_bytes(st, 2) == 32 &&
               sqlite3_column_bytes(st, 4) == 64 &&
               sqlite3_column_int64(st, 3) >= 0 &&
               sqlite3_column_int64(st, 3) <= (sqlite3_int64)EVM_MAX_CODE_SIZE) {
        *nonce = (uint64_t)sqlite3_column_int64(st, 0);
        memcpy(bal, sqlite3_column_blob(st, 1), 32);
        memcpy(ch, sqlite3_column_blob(st, 2), 32);
        *cs = (uint32_t)sqlite3_column_int64(st, 3);
        memcpy(digest, sqlite3_column_blob(st, 4), 64);
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

static void handle_evm_account(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len,
                               uint32_t txn_id) {
    evm_args_t x;
    uint64_t tip = 0;
    const nodus_domain_runtime_t *ert = NULL;
    if (evm_args_parse(payload, len, &x) != 0 || !x.a) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid a (32-byte address)");
        return;
    }
    if (evm_gate(w, conn, txn_id, &tip, &ert) != 0) return;
    uint64_t nonce = 0;
    uint8_t bal[32] = { 0 }, ch[32], digest[64];
    uint32_t cs = 0;
    int f = evm_acct_row(w, x.a, &nonce, bal, ch, &cs, digest);
    if (f < 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "EVM account store unreadable");
        return;
    }
    if (f == 0) {
        static const uint8_t none[1] = { 0 };
        if (keccak256(none, 0, ch) != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "hash");
            return;
        }
    }
    uint8_t buf[256];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "evm_account", 5);
    cbor_encode_cstr(&enc, "n");  cbor_encode_uint(&enc, nonce);
    cbor_encode_cstr(&enc, "b");  cbor_encode_bstr(&enc, bal, 32);
    cbor_encode_cstr(&enc, "ch"); cbor_encode_bstr(&enc, ch, 32);
    cbor_encode_cstr(&enc, "cs"); cbor_encode_uint(&enc, cs);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, tip);
    evm_send(conn, txn_id, &enc, buf);
}

static void handle_evm_code(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                            const uint8_t *payload, size_t len,
                            uint32_t txn_id) {
    evm_args_t x;
    uint64_t tip = 0;
    const nodus_domain_runtime_t *ert = NULL;
    if (evm_args_parse(payload, len, &x) != 0 || !x.a) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid a (32-byte address)");
        return;
    }
    if (evm_gate(w, conn, txn_id, &tip, &ert) != 0) return;
    uint64_t nonce = 0;
    uint8_t bal[32], ch[32], digest[64];
    uint32_t cs = 0;
    int f = evm_acct_row(w, x.a, &nonce, bal, ch, &cs, digest);
    if (f < 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "EVM account store unreadable");
        return;
    }
    uint8_t *code = NULL;
    size_t off = 0;
    if (f == 1 && cs > 0) {
        /* the work before it is done: its chunk rows and code bytes
         * (cs <= EVM_MAX_CODE_SIZE, evm_acct_row) */
        uint64_t rows = ((uint64_t)cs + NODUS_RT_EVM_CODE_CHUNK - 1) /
                        NODUS_RT_EVM_CODE_CHUNK;
        if (evm_work_charge(tip, rows * NODUS_EVM_RPC_GAS_PER_ROW +
                                 (uint64_t)cs * NODUS_EVM_RPC_GAS_PER_BYTE)
            != 0) {
            send_error(conn, txn_id, NODUS_ERR_RATE_LIMITED,
                       EVM_SIM_BUDGET_MSG);
            return;
        }
        code = malloc(cs);
        if (!code) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "allocation");
            return;
        }
        /* the chunks of the digest, in order, exactly code_size bytes,
         * checked against both digests (the runtime's be_get_code rule) */
        sqlite3_stmt *st = NULL;
        int ok = 0;
        if (sqlite3_prepare_v2(w->db,
                "SELECT chunk, bytes FROM evm_code WHERE digest = ?1 "
                "ORDER BY chunk", -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(st, 1, digest, 64, SQLITE_TRANSIENT);
            uint32_t want_chunk = 0;
            ok = 1;
            int rc = SQLITE_ERROR;
            while (ok && (rc = sqlite3_step(st)) == SQLITE_ROW) {
                int n = sqlite3_column_bytes(st, 1);
                if (sqlite3_column_int64(st, 0) != (sqlite3_int64)want_chunk ||
                    n <= 0 || (size_t)n > cs - off)
                    ok = 0;
                else {
                    memcpy(code + off, sqlite3_column_blob(st, 1), (size_t)n);
                    off += (size_t)n;
                    want_chunk++;
                }
            }
            if (ok && rc != SQLITE_DONE) ok = 0;
        }
        sqlite3_finalize(st);
        uint8_t d[64], k[32];
        if (!ok || off != cs || qgp_sha3_512(code, off, d) != 0 ||
            keccak256(code, off, k) != 0 || memcmp(d, digest, 64) != 0 ||
            memcmp(k, ch, 32) != 0) {
            free(code);
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                       "stored contract code does not match its digests");
            return;
        }
    }
    size_t cap = off + 128;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        free(code);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "allocation");
        return;
    }
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_dnac_response(&enc, txn_id, "evm_code", 2);
    cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, code, off);
    cbor_encode_cstr(&enc, "h"); cbor_encode_uint(&enc, tip);
    evm_send(conn, txn_id, &enc, buf);
    free(buf);
    free(code);
}

static void handle_evm_storage(nodus_witness_t *w,
                               struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len,
                               uint32_t txn_id) {
    evm_args_t x;
    uint64_t tip = 0;
    const nodus_domain_runtime_t *ert = NULL;
    if (evm_args_parse(payload, len, &x) != 0 || !x.a || !x.k) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid a / k (32 bytes each)");
        return;
    }
    if (evm_gate(w, conn, txn_id, &tip, &ert) != 0) return;
    uint8_t v[32] = { 0 };
    sqlite3_stmt *st = NULL;
    int ok = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT value FROM evm_slots WHERE addr = ?1 AND slot = ?2",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, x.a, 32, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, x.k, 32, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) {
            ok = 1;                         /* zero = no row (design §6) */
        } else if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 32) {
            memcpy(v, sqlite3_column_blob(st, 0), 32);
            ok = 1;
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "EVM storage unreadable");
        return;
    }
    uint8_t buf[128];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "evm_storage", 2);
    cbor_encode_cstr(&enc, "v"); cbor_encode_bstr(&enc, v, 32);
    cbor_encode_cstr(&enc, "h"); cbor_encode_uint(&enc, tip);
    evm_send(conn, txn_id, &enc, buf);
}

static void handle_evm_ticket(nodus_witness_t *w,
                              struct nodus_tcp_conn *conn,
                              const uint8_t *payload, size_t len,
                              uint32_t txn_id) {
    evm_args_t x;
    uint64_t tip = 0;
    const nodus_domain_runtime_t *ert = NULL;
    if (evm_args_parse(payload, len, &x) != 0 || !x.id) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid id (64-byte ticket id)");
        return;
    }
    if (evm_gate(w, conn, txn_id, &tip, &ert) != 0) return;
    uint8_t dst[64] = { 0 };
    uint64_t amt = 0;
    int present = 0, ok = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount_raw, dest_fp FROM evm_tickets WHERE ticket_id = ?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, x.id, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) {
            ok = 1;
        } else if (rc == SQLITE_ROW && sqlite3_column_int64(st, 0) > 0 &&
                   sqlite3_column_bytes(st, 1) == 64) {
            amt = (uint64_t)sqlite3_column_int64(st, 0);
            memcpy(dst, sqlite3_column_blob(st, 1), 64);
            present = ok = 1;
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "EVM ticket store unreadable");
        return;
    }
    uint8_t buf[192];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "evm_ticket", 3);
    cbor_encode_cstr(&enc, "p");   cbor_encode_bool(&enc, present != 0);
    cbor_encode_cstr(&enc, "amt"); cbor_encode_uint(&enc, amt);
    cbor_encode_cstr(&enc, "dst"); cbor_encode_bstr(&enc, dst, 64);
    evm_send(conn, txn_id, &enc, buf);
}

/* ── evm_call / evm_estimate ─────────────────────────────────────────── */

/* One simulation through the per-height budget — THE funnel every
 * evm_call / evm_estimate simulation goes through (WORK BOUND above).
 * `tip` is the committed tip the request was gated at.
 * @return as nodus_rt_evm_simulate, or 1 when the budget refused it (it
 * did not run; *res untouched). */
static int evm_sim_once(nodus_witness_t *w, const nodus_domain_runtime_t *ert,
                        uint64_t tip, nodus_rt_evm_sim_req_t *rq,
                        uint64_t gas, nodus_rt_evm_sim_res_t *res) {
    /* gas <= NODUS_RT_EVM_TX_GAS_CAP (the caller's bound), charged <=
     * the budget: no overflow */
    if (evm_work_charge(tip, gas) != 0) return 1;   /* up front: no pre-
                                                     * emption           */
    rq->gas_limit = gas;
    int rc = nodus_rt_evm_simulate(ert, (struct nodus_witness *)w, rq, res);
    /* keep the work it did, refund the rest:
     *   ran        — the engine's PRE-refund work (engine_work_gas; the
     *                calldata floor when that is higher): an EIP-3529
     *                refund lowers the sender's bill, not this node's run;
     *   refused before execution — its reads, one row each (the sender's
     *                account at least);
     *   out of bounds (-1, it did not run) — one row;
     *   a node fault (-2) — ALL of it: a fault may come after the
     *                engine ran (the output copy's malloc,
     *                nodus_witness_rt_evm.c simulate) and the result,
     *                work counters included, is cleared on that exit, so
     *                nothing tells how much ran (red-team 2, Astra #3).
     * Never zero (red-team 1 F4 / F12); never above what was charged. */
    uint64_t used;
    if (rc == 0 && res->executed)
        used = res->engine_work_gas > res->engine_gas_used
                   ? res->engine_work_gas : res->engine_gas_used;
    else if (rc == 0)
        used = res->reads > gas / NODUS_EVM_RPC_GAS_PER_ROW
                   ? gas : res->reads * NODUS_EVM_RPC_GAS_PER_ROW;
    else if (rc == -1)
        used = NODUS_EVM_RPC_GAS_PER_ROW;
    else
        used = gas;
    if (used == 0) used = NODUS_EVM_RPC_GAS_PER_ROW;
    if (used > gas) used = gas;
    g_evm_work_charged -= gas - used;
    return rc;
}

static void handle_evm_call(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                            const uint8_t *payload, size_t len,
                            uint32_t txn_id, int estimate) {
    const char *method = estimate ? "evm_estimate" : "evm_call";
    evm_args_t x;
    uint64_t tip = 0;
    const nodus_domain_runtime_t *ert = NULL;
    if (evm_args_parse(payload, len, &x) != 0 || !x.f || !x.has_d) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid f (32-byte sender) / d (data)");
        return;
    }
    const uint64_t gas = x.has_g ? x.g : NODUS_RT_EVM_TX_GAS_CAP;
    if (gas == 0 || gas > NODUS_RT_EVM_TX_GAS_CAP) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "g must be between 1 and the per-transaction gas cap");
        return;
    }
    if (!x.t && x.d_len > EVM_MAX_INITCODE_SIZE) {
        send_error(conn, txn_id, NODUS_ERR_TOO_LARGE,
                   "initcode over 49152 bytes (EIP-3860)");
        return;
    }
    if (evm_gate(w, conn, txn_id, &tip, &ert) != 0) return;
    /* red-team 1 D1 (decision 2026-10-05-nodus-evm-redteam1-operator.md):
     * while the price at tip + 1 is 0 the chain refuses every CALL /
     * CREATE (nodus_witness_v2_gas_price_judge), so no fee is estimated
     * for one — refused before any simulation budget is spent */
    if (estimate) {
        uint64_t p0 = 0;
        char why[160];
        why[0] = '\0';
        if (nodus_witness_v2_gas_price_at(w, tip + 1, &p0, why,
                                          sizeof(why)) != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                       "the gas price is unreadable on this node");
            return;
        }
        if (p0 == 0) {
            send_error(conn, txn_id, NODUS_ERR_UNAVAILABLE,
                       "the gas price is 0: EVM CALL / CREATE are stopped "
                       "on this chain until a non-zero price is voted");
            return;
        }
    }

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    uint64_t btime = 0, gas_lim = 0;
    char reason[160];
    reason[0] = '\0';
    if (nodus_witness_v2_chain_id(w, chain32) != 0 ||
        nodus_witness_v2_tip_block_time(w, tip, &btime) != 0 ||
        nodus_witness_v2_evm_block_gas_limit(w, tip + 1, &gas_lim, reason,
                                             sizeof(reason)) != 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "the block environment is unreadable on this node");
        return;
    }
    nodus_rt_evm_sim_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.from = x.f;
    rq.to = x.t;
    rq.value = x.v;
    rq.data = x.d;
    rq.data_len = (uint32_t)x.d_len;
    rq.chain_id = chain32;
    rq.global_height = tip + 1;
    rq.block_time_s = btime;
    rq.evm_block_gas_limit = gas_lim;

    nodus_rt_evm_sim_res_t at_g, best;
    memset(&best, 0, sizeof(best));
    int rc = evm_sim_once(w, ert, tip, &rq, gas, &at_g);
    if (rc == 1) {
        send_error(conn, txn_id, NODUS_ERR_RATE_LIMITED, EVM_SIM_BUDGET_MSG);
        return;
    }
    if (rc == -1 || (rc == 0 && !at_g.executed)) {
        nodus_rt_evm_sim_res_free(&at_g);
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "refused before execution (value above the balance, "
                   "intrinsic gas above the limit, a sender with code, or "
                   "a read budget)");
        return;
    }
    if (rc != 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "the simulation faulted on this node");
        return;
    }

    /* evm_estimate: the binary search for the smallest successful limit */
    uint64_t ge = gas, ue = 0, fe = 0;
    const nodus_rt_evm_sim_res_t *rep = &at_g;
    if (estimate && at_g.success) {
        uint64_t lo = 0, hi = gas;          /* lo fails (or untried), hi ok */
        uint64_t first = at_g.engine_gas_used;
        /* fault: 1 the simulation faulted; 2 the per-height budget refused
         * a probe — the whole request is refused (no partial estimate) */
        int probes = 0, fault = 0;
        if (first > 0 && first < gas) {
            nodus_rt_evm_sim_res_t r;
            int prc = evm_sim_once(w, ert, tip, &rq, first, &r);
            probes++;
            if (prc == 1) {
                fault = 2;                  /* did not run: r untouched  */
            } else if (prc == 0 && r.executed && r.success) {
                hi = first;
                best = r;
            } else {
                if (prc == 0) nodus_rt_evm_sim_res_free(&r);
                else if (prc != -1) fault = 1;
                lo = first;
            }
        }
        while (!fault && hi != first && probes < EVM_EST_MAX_PROBES &&
               hi - lo > (hi / 64 > 1 ? hi / 64 : 1)) {
            uint64_t mid = lo + (hi - lo) / 2;
            nodus_rt_evm_sim_res_t r;
            int prc = evm_sim_once(w, ert, tip, &rq, mid, &r);
            probes++;
            if (prc == 1) { fault = 2; break; }
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
            if (fault == 2)
                send_error(conn, txn_id, NODUS_ERR_RATE_LIMITED,
                           EVM_SIM_BUDGET_MSG);
            else
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                           "the simulation faulted on this node");
            return;
        }
        ge = hi;
        if (hi != gas) rep = &best;
    }
    if (estimate) {
        const nodus_domain_runtime_t *srt = NULL, *crt = NULL;
        uint64_t price = 0, ref = 0, ru = 0;
        uint64_t floor_fee = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                                 ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
        int ok =
            nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &srt) == 0 &&
            nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &crt) == 0 &&
            srt && crt && srt->meter_policy &&
            nodus_witness_v2_gas_price_at(w, tip + 1, &price, reason,
                                          sizeof(reason)) == 0 &&
            nodus_v2_evm_ref_units(srt->meter_policy, crt->ruleset_version,
                                   x.t ? DNA_EVM_OP_CALL : DNA_EVM_OP_CREATE,
                                   (uint32_t)x.d_len, ge, &ref) ==
                NODUS_V2_SPEND_OK &&
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
        if (!ok) {
            nodus_rt_evm_sim_res_free(&best);
            nodus_rt_evm_sim_res_free(&at_g);
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                       "the units / fee could not be priced on this node");
            return;
        }
    }

    size_t cap = rep->output_len + 256;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        nodus_rt_evm_sim_res_free(&best);
        nodus_rt_evm_sim_res_free(&at_g);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "allocation");
        return;
    }
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    enc_dnac_response(&enc, txn_id, method, estimate ? 7 : 4);
    cbor_encode_cstr(&enc, "s");  cbor_encode_uint(&enc, rep->success ? 1 : 0);
    cbor_encode_cstr(&enc, "o");
    cbor_encode_bstr(&enc, rep->output, rep->output_len);
    cbor_encode_cstr(&enc, "gu"); cbor_encode_uint(&enc, rep->gas_used);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, tip);
    if (estimate) {
        cbor_encode_cstr(&enc, "ge"); cbor_encode_uint(&enc, ge);
        cbor_encode_cstr(&enc, "ue"); cbor_encode_uint(&enc, ue);
        cbor_encode_cstr(&enc, "fe"); cbor_encode_uint(&enc, fe);
    }
    evm_send(conn, txn_id, &enc, buf);
    free(buf);
    nodus_rt_evm_sim_res_free(&best);
    nodus_rt_evm_sim_res_free(&at_g);
}

/* ── evm_receipt ─────────────────────────────────────────────────────── */

static void handle_evm_receipt(nodus_witness_t *w,
                               struct nodus_tcp_conn *conn,
                               const uint8_t *payload, size_t len,
                               uint32_t txn_id) {
    evm_args_t x;
    uint64_t tip = 0;
    const nodus_domain_runtime_t *ert = NULL;
    if (evm_args_parse(payload, len, &x) != 0 || !x.i) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "missing or invalid i (64-byte intent id)");
        return;
    }
    if (evm_gate(w, conn, txn_id, &tip, &ert) != 0) return;
    sqlite3_stmt *st = NULL;
    int found = 0, ok = 0, over = 0;
    uint64_t gh = 0, item = 0;
    uint8_t *rc_bytes = NULL, dg[64];
    size_t rc_len = 0;
    /* length(receipt) first — SQLite does not load a blob's content for
     * length() (v2_schema.h, the evm_logs scan) — so the receipt's bytes
     * are charged to the work budget BEFORE a second statement reads,
     * copies or hashes them */
    if (sqlite3_prepare_v2(w->db,
            "SELECT global_height, item_index, length(receipt), digest "
            "FROM evm_receipts WHERE intent_id = ?1",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, x.i, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) {
            ok = 1;
        } else if (rc == SQLITE_ROW && sqlite3_column_int64(st, 0) >= 0 &&
                   sqlite3_column_int64(st, 1) >= 0 &&
                   sqlite3_column_int64(st, 1) <= (sqlite3_int64)UINT32_MAX &&
                   sqlite3_column_type(st, 2) == SQLITE_INTEGER &&
                   sqlite3_column_int64(st, 2) > 0 &&
                   sqlite3_column_int64(st, 2) <= (sqlite3_int64)INT32_MAX &&
                   sqlite3_column_bytes(st, 3) == 64) {
            gh = (uint64_t)sqlite3_column_int64(st, 0);
            item = (uint64_t)sqlite3_column_int64(st, 1);
            rc_len = (size_t)sqlite3_column_int64(st, 2);
            memcpy(dg, sqlite3_column_blob(st, 3), 64);
            if (evm_work_charge(tip, (uint64_t)rc_len *
                                     NODUS_EVM_RPC_GAS_PER_BYTE) != 0)
                over = 1;
            else
                found = 1;
        }
    }
    sqlite3_finalize(st);
    st = NULL;
    if (found) {
        /* the charged bytes: exactly rc_len of them */
        if (sqlite3_prepare_v2(w->db,
                "SELECT receipt FROM evm_receipts WHERE intent_id = ?1",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_blob(st, 1, x.i, 64, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW &&
                sqlite3_column_bytes(st, 0) == (int)rc_len &&
                (rc_bytes = malloc(rc_len)) != NULL) {
                memcpy(rc_bytes, sqlite3_column_blob(st, 0), rc_len);
                ok = 1;
            }
        }
        sqlite3_finalize(st);
    }
    if (over) {
        send_error(conn, txn_id, NODUS_ERR_RATE_LIMITED, EVM_SIM_BUDGET_MSG);
        return;
    }
    if (!ok) {
        free(rc_bytes);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "EVM receipt store unreadable");
        return;
    }
    if (!found) {
        uint8_t buf[96];
        cbor_encoder_t enc;
        cbor_encoder_init(&enc, buf, sizeof(buf));
        enc_dnac_response(&enc, txn_id, "evm_receipt", 0);
        evm_send(conn, txn_id, &enc, buf);
        return;
    }
    dna_evm_rcpt_t r;
    uint8_t d2[64];
    if (dna_evm_rcpt_decode(rc_bytes, rc_len, &r) != 0 ||
        qgp_sha3_512(rc_bytes, rc_len, d2) != 0 || memcmp(d2, dg, 64) != 0) {
        free(rc_bytes);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "a stored receipt does not match its digest");
        return;
    }
    const int has_cr = (r.status == 1 && r.op == DNA_EVM_OP_CREATE);
    size_t cap = 2 * rc_len + 1024;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        free(rc_bytes);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "allocation");
        return;
    }
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    /* h x s op gu [cr] o logs wd tk dg — 10 entries, 11 with "cr" (the
     * count was one high until harness run 4: every client refused the
     * reply, nodus_client.c evm_reply_map) */
    enc_dnac_response(&enc, txn_id, "evm_receipt", has_cr ? 11 : 10);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, gh);
    cbor_encode_cstr(&enc, "x");  cbor_encode_uint(&enc, item);
    cbor_encode_cstr(&enc, "s");  cbor_encode_uint(&enc, r.status);
    cbor_encode_cstr(&enc, "op"); cbor_encode_uint(&enc, r.op);
    cbor_encode_cstr(&enc, "gu"); cbor_encode_uint(&enc, r.gas_used);
    if (has_cr) {
        cbor_encode_cstr(&enc, "cr"); cbor_encode_bstr(&enc, r.created, 32);
    }
    cbor_encode_cstr(&enc, "o");
    cbor_encode_bstr(&enc, r.output, r.output_len);
    cbor_encode_cstr(&enc, "logs");
    cbor_encode_array(&enc, r.n_logs);
    size_t cur = 0;
    int bad = 0;
    for (uint32_t i = 0; i < r.n_logs && !bad; i++) {
        const uint8_t *addr = NULL, *tp = NULL, *data = NULL;
        uint8_t nt = 0;
        uint32_t dl = 0;
        if (dna_evm_rcpt_log_next(&r, &cur, &addr, &nt, &tp, &data,
                                  &dl) != 0) {
            bad = 1;
            break;
        }
        cbor_encode_map(&enc, 3);
        cbor_encode_cstr(&enc, "a"); cbor_encode_bstr(&enc, addr, 32);
        cbor_encode_cstr(&enc, "t"); cbor_encode_array(&enc, nt);
        for (uint8_t k = 0; k < nt; k++)
            cbor_encode_bstr(&enc, tp + (size_t)k * 32, 32);
        cbor_encode_cstr(&enc, "d"); cbor_encode_bstr(&enc, data, dl);
    }
    cbor_encode_cstr(&enc, "wd"); cbor_encode_bstr(&enc, r.wei_destroyed, 32);
    cbor_encode_cstr(&enc, "tk"); cbor_encode_array(&enc, r.n_tickets);
    for (uint16_t k = 0; k < r.n_tickets; k++)
        cbor_encode_bstr(&enc, r.tickets + (size_t)k * 64, 64);
    cbor_encode_cstr(&enc, "dg"); cbor_encode_bstr(&enc, dg, 64);
    if (bad)
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "a stored receipt's log section is malformed");
    else
        evm_send(conn, txn_id, &enc, buf);
    free(buf);
    free(rc_bytes);
}

/* ── evm_logs ────────────────────────────────────────────────────────── */

static void handle_evm_logs(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                            const uint8_t *payload, size_t len,
                            uint32_t txn_id) {
    evm_args_t x;
    uint64_t tip = 0;
    const nodus_domain_runtime_t *ert = NULL;
    if (evm_args_parse(payload, len, &x) != 0 || !x.has_fh || !x.has_th ||
        !x.has_lim || x.th < x.fh || x.th - x.fh >= EVM_LOGS_MAX_SPAN ||
        x.lim < 1 || x.lim > EVM_LOGS_MAX_LIM ||
        x.fh > (uint64_t)INT64_MAX || x.th > (uint64_t)INT64_MAX ||
        (x.has_c && (x.c[0] < x.fh || x.c[0] > x.th ||
                     x.c[1] > NODUS_EVM_LOG_POS_MAX ||
                     x.c[2] > NODUS_EVM_LOG_POS_MAX))) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                   "fh <= th, th - fh < 10000, 1 <= lim <= 1000, "
                   "fh <= c.h <= th required");
        return;
    }
    if (evm_gate(w, conn, txn_id, &tip, &ert) != 0) return;

    /* the scan may spend what the budget has left, at most one full page
     * (EVM_LOGS_MAX_EXAMINED rows + EVM_LOGS_REPLY_BUDGET bytes); below
     * a minimal page (one height seek, one receipt, one log, its data
     * read) nothing is scanned */
    const uint64_t left = evm_work_left(tip);
    if (left < 4u * (uint64_t)NODUS_EVM_RPC_GAS_PER_ROW) {
        send_error(conn, txn_id, NODUS_ERR_RATE_LIMITED, EVM_SIM_BUDGET_MSG);
        return;
    }
    nodus_evm_logs_scan_t q;
    memset(&q, 0, sizeof(q));
    q.from.h = x.has_c ? x.c[0] : x.fh;
    q.from.x = x.has_c ? x.c[1] : 0;
    q.from.li = x.has_c ? x.c[2] : 0;
    q.th = x.th;
    q.addr = x.a;
    for (int k = 0; k < 4; k++) q.topic[k] = x.tp[k];
    q.lim = (uint32_t)x.lim;
    q.max_examined = EVM_LOGS_MAX_EXAMINED;
    q.max_bytes = EVM_LOGS_REPLY_BUDGET;
    q.gas_cap = left;
    nodus_evm_logs_page_t pg;
    int src = nodus_witness_evm_logs_scan(w, &q, &pg);
    /* the work is charged whatever the outcome (gas <= left by the scan's
     * own bound) */
    (void)evm_work_charge(tip, pg.gas <= left ? pg.gas : left);
    if (src != 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                   "EVM log index unreadable");
        return;
    }
    size_t cap = pg.bytes + 384;
    uint8_t *buf = malloc(cap);
    if (!buf) {
        nodus_witness_evm_logs_page_free(&pg);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, "allocation");
        return;
    }
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    /* logs more [c] — "c" exactly when the scan stopped before th */
    enc_dnac_response(&enc, txn_id, "evm_logs", pg.truncated ? 3 : 2);
    cbor_encode_cstr(&enc, "logs");
    cbor_encode_array(&enc, pg.n);
    for (size_t k = 0; k < pg.n; k++) {
        const nodus_evm_log_row_t *e = &pg.rows[k];
        cbor_encode_map(&enc, 7);
        cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, e->h);
        cbor_encode_cstr(&enc, "x");  cbor_encode_uint(&enc, e->x);
        cbor_encode_cstr(&enc, "li"); cbor_encode_uint(&enc, e->li);
        cbor_encode_cstr(&enc, "a");  cbor_encode_bstr(&enc, e->addr, 32);
        cbor_encode_cstr(&enc, "t");  cbor_encode_array(&enc, e->n_topics);
        for (uint8_t t = 0; t < e->n_topics; t++)
            cbor_encode_bstr(&enc, e->topics[t], 32);
        cbor_encode_cstr(&enc, "d");
        cbor_encode_bstr(&enc, e->data, e->data_len);
        cbor_encode_cstr(&enc, "i");  cbor_encode_bstr(&enc, e->intent_id, 64);
    }
    cbor_encode_cstr(&enc, "more"); cbor_encode_bool(&enc, pg.truncated != 0);
    if (pg.truncated) {
        cbor_encode_cstr(&enc, "c");
        cbor_encode_array(&enc, 3);
        cbor_encode_uint(&enc, pg.next.h);
        cbor_encode_uint(&enc, pg.next.x);
        cbor_encode_uint(&enc, pg.next.li);
    }
    evm_send(conn, txn_id, &enc, buf);
    free(buf);
    nodus_witness_evm_logs_page_free(&pg);
}

/** Route one evm_* method. @return 1 handled / 0 not an evm_* method. */
static int evm_dispatch(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                        const uint8_t *payload, size_t len,
                        const char *method, uint32_t txn_id) {
    if (strcmp(method, "evm_account") == 0)
        handle_evm_account(w, conn, payload, len, txn_id);
    else if (strcmp(method, "evm_code") == 0)
        handle_evm_code(w, conn, payload, len, txn_id);
    else if (strcmp(method, "evm_storage") == 0)
        handle_evm_storage(w, conn, payload, len, txn_id);
    else if (strcmp(method, "evm_call") == 0)
        handle_evm_call(w, conn, payload, len, txn_id, 0);
    else if (strcmp(method, "evm_estimate") == 0)
        handle_evm_call(w, conn, payload, len, txn_id, 1);
    else if (strcmp(method, "evm_receipt") == 0)
        handle_evm_receipt(w, conn, payload, len, txn_id);
    else if (strcmp(method, "evm_logs") == 0)
        handle_evm_logs(w, conn, payload, len, txn_id);
    else if (strcmp(method, "evm_ticket") == 0)
        handle_evm_ticket(w, conn, payload, len, txn_id);
    else
        return 0;
    return 1;
}

#endif /* NODUS_EVM_ENABLED */

/* ════════════════════════════════════════════════════════════════════
 * Dispatch router
 * ════════════════════════════════════════════════════════════════════ */

void nodus_witness_handle_dnac(nodus_witness_t *w,
                                struct nodus_tcp_conn *conn,
                                const uint8_t *payload, size_t len,
                                const char *method, uint32_t txn_id) {
    if (!w || !conn || !payload || !method) return;

    if (strcmp(method, "dnac_spend") == 0) {
        handle_dnac_spend(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_nullifier") == 0) {
        handle_dnac_nullifier(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_ledger") == 0) {
        handle_dnac_ledger(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_supply") == 0) {
        handle_dnac_supply(w, conn, txn_id);
    } else if (strcmp(method, "dnac_utxo") == 0) {
        handle_dnac_utxo(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_msig_utxo") == 0) {
        handle_dnac_msig_utxo(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_balance") == 0) {
        handle_dnac_balance(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_ledger_range") == 0) {
        handle_dnac_ledger_range(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_roster") == 0) {
        handle_dnac_roster(w, conn, txn_id);
    } else if (strcmp(method, "dnac_tx") == 0) {
        handle_dnac_tx(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_spend_replay") == 0) {
        handle_dnac_spend_replay(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_block") == 0) {
        handle_dnac_block(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_block_range") == 0) {
        handle_dnac_block_range(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_v3_block") == 0) {
        handle_dnac_v3_block(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_genesis") == 0) {
        handle_dnac_genesis(w, conn, txn_id);
    } else if (strcmp(method, "dnac_history") == 0) {
        handle_dnac_history(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_addr_history") == 0) {
        handle_dnac_addr_history(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_msig_addr_history") == 0) {
        handle_dnac_msig_addr_history(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_delegations") == 0) {
        handle_dnac_delegations(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_token_list") == 0) {
        handle_dnac_token_list(w, conn, txn_id);
    } else if (strcmp(method, "dnac_token_info") == 0) {
        handle_dnac_token_info(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_fee_info") == 0) {
        handle_dnac_fee_info(w, conn, txn_id);
    } else if (strcmp(method, "dnac_ruleset_info") == 0) {
        handle_dnac_ruleset_info(w, conn, txn_id);
    } else if (strcmp(method, "dnac_name_lookup") == 0) {
        handle_dnac_name_lookup(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_name_of") == 0) {
        handle_dnac_name_of(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_storage_status") == 0) {
        handle_dnac_storage_status(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_committee_query") == 0) {
        handle_dnac_committee_query(w, conn, txn_id);
    } else if (strcmp(method, "dnac_validator_list_query") == 0) {
        handle_dnac_validator_list_query(w, conn, payload, len, txn_id);
    } else if (strncmp(method, "evm_", 4) == 0) {
        /* Nodus EVM §18 — routed here by nodus_chain_method_routed */
#ifdef NODUS_EVM_ENABLED
        if (!evm_dispatch(w, conn, payload, len, method, txn_id))
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       "unknown EVM method");
#else
        send_error(conn, txn_id, NODUS_ERR_NOT_FOUND,
                   "the EVM is not compiled into this build");
#endif
    } else {
        /* the text is a client contract (nodus.h): it is how a newer
         * client tells "this node lacks the method" from a refusal */
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    NODUS_DNAC_UNKNOWN_METHOD_MSG);
    }
}
