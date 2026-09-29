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
#include "server/nodus_server.h"
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
#include "dnac/env_wire.h"
#include "dnac/manifest_wire.h"
#include "dnac/ledger_ids.h"

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
 *                 — the explorer's sync bound)}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_supply(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 uint32_t txn_id) {
    nodus_witness_supply_t supply;
    int rc = nodus_witness_supply_get(w, &supply);
    /* scan-v3 (decision 2026-09-28-scan-v3-query.md (2)) — "tip", the
     * committed version-3 height (MAX(v2_blocks.global_height)), rides
     * the successor arm beside chain_id32: ADDITIVE, an older client
     * skips the unknown key. Read on the fail-closed accessor — a fault
     * answers an error, never a tip of 0 (a 0 would tell the explorer
     * the chain has no blocks). */
    uint64_t tip = 0;
    if (w->v2_successor && nodus_witness_v2_tip_height(w, &tip) != 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "chain height unreadable");
        return;
    }
    size_t rcount = w->v2_successor ? 7 : 5;

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
        cbor_encode_uint(&enc, tip);
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

    /* 5 keys: the longest reply is 1 map header + "dnac_fee_info"
     * framing (enc_dnac_response) + 5 short keys (the longest,
     * "token_create_fee", 17 bytes with its head) + 5 uint64 values at
     * 9 bytes each — well inside 256; the rlen check below still
     * refuses an overflow rather than sending a truncated map. */
    uint8_t buf[256];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    enc_dnac_response(&enc, txn_id, "dnac_fee_info", 5);
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
        free(utxos);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_utxo", 3);

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

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
    free(utxos);
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
    if (w->server &&
        memcmp(pk, w->server->identity.pk.bytes, NODUS_PK_BYTES) == 0) {
        const char *my_ip = w->server->config.external_ip[0]
                          ? w->server->config.external_ip
                          : w->server->config.bind_ip;
        uint16_t my_wport = w->server->config.witness_port
                          ? w->server->config.witness_port
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
    if (w->server) {
        uint8_t fp[64];
        roster_row_t *r = &rows[n_rows];
        memcpy(r->pk, w->server->identity.pk.bytes, NODUS_PK_BYTES);
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
                (w->server && memcmp(r->pk, w->server->identity.pk.bytes,
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
    qgp_sha3_512(w->server->identity.pk.bytes, NODUS_PK_BYTES, wpk_hash);

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
    nodus_sign(&sig, preimage, sizeof(preimage), &w->server->identity.sk);

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
    cbor_encode_bstr(&enc, w->server->identity.pk.bytes, NODUS_PK_BYTES);

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
            char msg[64];
            snprintf(msg, sizeof(msg), "CheckTx code %u",
                     (unsigned)res.code);
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
 *                    "since":u64}, ... ]}
 *
 * Ordering: (self_stake + external_delegated) DESC, pubkey ASC. Same
 * ordering as top_n so rankings remain stable regardless of filter.
 *
 * `total` reports the total matching-filter row count (pre-pagination)
 * so clients can drive "next page" UIs.
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

    /* Each entry ships pubkey (2592B) + ~7 small ints. Budget 2700B. */
    size_t buf_size = 256 + (size_t)count * 2800;
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
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
        cbor_encode_map(&enc, 7);
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
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0) {
        nodus_tcp_send(conn, buf, rlen);
    } else {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "response buffer overflow");
    }

    free(buf);
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
 * keys (~250 B) come to ~6.9 KB; 16 KiB leaves headroom and an item that
 * does not fit is a node-local invariant broken → INTERNAL. */
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
    /* prepared reads, finalized by v3b_free */
    sqlite3_stmt                  *st_ids;
    sqlite3_stmt                  *st_claim;
    sqlite3_stmt                  *st_cbytes;
    /* the outcome of a refusal */
    int                            err_code;
    char                           err_msg[128];
} v3b_ctx_t;

static void v3b_free(v3b_ctx_t *c)
{
    if (c->st_ids)    sqlite3_finalize(c->st_ids);
    if (c->st_claim)  sqlite3_finalize(c->st_claim);
    if (c->st_cbytes) sqlite3_finalize(c->st_cbytes);
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
 * A SYSTEM leg names the envelope (its CORE sibling is the funding leg);
 * otherwise the CORE leg does. NULL = no name this build knows. */
static const char *v3b_op_name(const dna_env_view_t *v)
{
    const char *core = NULL;
    for (uint16_t l = 0; l < v->leg_count; l++) {
        uint32_t d = v->leg[l].domain_id, op = v->leg[l].runtime_op;
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
    const nodus_rt_leg_desc_t *core = NULL, *sys = NULL;
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
                nodus_rt_leg_desc_t *d =
                    c->view->leg[l].domain_id == DNA_DOMAIN_CORE
                        ? c->desc_core : c->desc_sys;
                if ((d == c->desc_core && core) || (d == c->desc_sys && sys))
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
                if (d == c->desc_core) core = d; else sys = d;
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
    items       = malloc((size_t)budget + NODUS_V3_BLOCK_ITEM_MAX_BYTES);
    scratch     = malloc(NODUS_V3_BLOCK_ITEM_MAX_BYTES);
    if (!c.view || !c.claim || !c.desc_core || !c.desc_sys || !items ||
        !scratch) {
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
    } else if (strcmp(method, "dnac_delegations") == 0) {
        handle_dnac_delegations(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_token_list") == 0) {
        handle_dnac_token_list(w, conn, txn_id);
    } else if (strcmp(method, "dnac_token_info") == 0) {
        handle_dnac_token_info(w, conn, payload, len, txn_id);
    } else if (strcmp(method, "dnac_fee_info") == 0) {
        handle_dnac_fee_info(w, conn, txn_id);
    } else if (strcmp(method, "dnac_committee_query") == 0) {
        handle_dnac_committee_query(w, conn, txn_id);
    } else if (strcmp(method, "dnac_validator_list_query") == 0) {
        handle_dnac_validator_list_query(w, conn, payload, len, txn_id);
    } else {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "unknown DNAC method");
    }
}
