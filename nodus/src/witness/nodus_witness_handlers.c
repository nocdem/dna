/**
 * Nodus — DNAC Client Handlers
 *
 * Post-auth Tier 2 handlers for DNAC client methods.
 * Each handler decodes CBOR args from the raw payload, queries
 * witness DB, and sends a CBOR response via TCP.
 *
 * Spend requests are asynchronous — the response is sent after
 * BFT consensus COMMIT via nodus_witness_send_spend_result().
 *
 * Ported from dnac/src/witness/bft_main.c handler functions.
 */

#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_peer.h"
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_mempool.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_committee.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "dnac/transaction.h"   /* DNAC_TX_HEADER_SIZE (v0.17.1) */
#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_u128.h"
#include "witness/nodus_witness_spend_preimage.h"

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
 * Response: "r": {"genesis":N, "burned":N, "current":N, "last_seq":N, "chain_id":bstr}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_supply(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 uint32_t txn_id) {
    nodus_witness_supply_t supply;
    int rc = nodus_witness_supply_get(w, &supply);

    uint8_t buf[512];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    if (rc != 0) {
        enc_dnac_response(&enc, txn_id, "dnac_supply", 5);
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
        enc_dnac_response(&enc, txn_id, "dnac_supply", 5);
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
 * Response: { base_fee, mempool_count, min_fee }
 * Client uses min_fee directly when building TX.
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_fee_info(nodus_witness_t *w,
                                  struct nodus_tcp_conn *conn,
                                  uint32_t txn_id) {
    int mp_count = w->mempool.count;
    uint64_t base_fee = NODUS_W_BASE_TX_FEE;
    uint64_t min_fee = base_fee * (1 + (uint64_t)mp_count / NODUS_W_FEE_SURGE_STEP);

    uint8_t buf[256];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    enc_dnac_response(&enc, txn_id, "dnac_fee_info", 3);
    cbor_encode_cstr(&enc, "base_fee");
    cbor_encode_uint(&enc, base_fee);
    cbor_encode_cstr(&enc, "mempool");
    cbor_encode_uint(&enc, (uint64_t)mp_count);
    cbor_encode_cstr(&enc, "min_fee");
    cbor_encode_uint(&enc, min_fee);

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
    fprintf(stderr, "WITNESS_UTXO: owner=%.16s... db=%p rc=%d count=%d\n",
            owner, (void*)w->db, utxo_rc, count);

    /* Phase 2 / Task 38: each UTXO ships with an anchored Merkle inclusion
     * proof against the current state_root. The top-level response also
     * carries the latest committed block_height so the client can fetch the
     * matching block anchor via dnac_block.
     *
     * Proof wire format per UTXO (short CBOR keys to match existing
     * conventions "n", "tid", "bh"):
     *   pr_s : bstr — flat sibling buffer (depth * 64 bytes)
     *   pr_p : uint — position bitfield
     *   pr_d : uint — proof depth
     *   sr   : bstr — 64-byte state_root (matches block.state_root)
     *
     * build_proof is O(N_utxos) per call; for N results in one response
     * this is O(N^2). Acceptable for the current 100-UTXO cap — revisit
     * in Phase 11+ if it becomes hot. */
    #define DNAC_UTXO_PROOF_MAX_DEPTH 32
    uint64_t latest_height = nodus_witness_block_height(w);

    /* Per UTXO we encode at worst:
     *   7 base fields  ≈ 256 B (existing budget)
     *   pr_s siblings  ≤ 32 * 64  = 2048 B
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
        /* Build the anchored state_root proof for this UTXO. On failure
         * (e.g. empty tree, leaf not yet committed) emit depth=0 empty
         * proof and a zeroed state_root so the client sees a degraded —
         * but still structurally valid — entry rather than losing the
         * UTXO entirely. Client verifies proof before trusting anchor. */
        uint8_t leaf[NODUS_MERKLE_HASH_LEN];
        uint8_t siblings[DNAC_UTXO_PROOF_MAX_DEPTH * NODUS_MERKLE_HASH_LEN];
        uint8_t state_root[NODUS_MERKLE_HASH_LEN];
        uint32_t positions = 0;
        int depth = 0;
        bool have_proof = false;

        memset(siblings, 0, sizeof(siblings));
        memset(state_root, 0, sizeof(state_root));

        if (nodus_witness_merkle_leaf_hash(utxos[i].nullifier,
                                             utxos[i].owner,
                                             utxos[i].amount,
                                             utxos[i].token_id,
                                             utxos[i].tx_hash,
                                             utxos[i].output_index,
                                             leaf) == 0) {
            if (nodus_witness_merkle_build_proof(w, leaf, siblings, &positions,
                                                   DNAC_UTXO_PROOF_MAX_DEPTH,
                                                   &depth, state_root) == 0) {
                have_proof = true;
            }
        }
        if (!have_proof) {
            /* Degraded: zeroed proof + root. Client-side verify will
             * reject — caller must retry once the witness is caught up. */
            positions = 0;
            depth = 0;
            memset(siblings, 0, sizeof(siblings));
            memset(state_root, 0, sizeof(state_root));
        }

        size_t sibs_len = (size_t)depth * NODUS_MERKLE_HASH_LEN;

        cbor_encode_map(&enc, 11);
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
        cbor_encode_cstr(&enc, "pr_s");
        cbor_encode_bstr(&enc, siblings, sibs_len);
        cbor_encode_cstr(&enc, "pr_p");
        cbor_encode_uint(&enc, (uint64_t)positions);
        cbor_encode_cstr(&enc, "pr_d");
        cbor_encode_uint(&enc, (uint64_t)depth);
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

static void handle_dnac_roster(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 uint32_t txn_id) {
    /* Encode response */
    size_t buf_size = 512 + (w->roster.n_witnesses * (64 + NODUS_PK_BYTES + 256));
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_roster", 3);

    cbor_encode_cstr(&enc, "version");
    cbor_encode_uint(&enc, w->roster.version);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, w->roster.n_witnesses);

    cbor_encode_cstr(&enc, "witnesses");
    cbor_encode_array(&enc, w->roster.n_witnesses);

    for (uint32_t i = 0; i < w->roster.n_witnesses; i++) {
        cbor_encode_map(&enc, 4);
        cbor_encode_cstr(&enc, "wid");
        cbor_encode_bstr(&enc, w->roster.witnesses[i].witness_id,
                          NODUS_T3_WITNESS_ID_LEN);
        cbor_encode_cstr(&enc, "pk");
        cbor_encode_bstr(&enc, w->roster.witnesses[i].pubkey,
                          NODUS_PK_BYTES);
        cbor_encode_cstr(&enc, "addr");
        cbor_encode_cstr(&enc, w->roster.witnesses[i].address);
        cbor_encode_cstr(&enc, "active");
        cbor_encode_bool(&enc, w->roster.witnesses[i].active);
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

    /* Committed → rebuild the spndrslt preimage and sign it fresh.
     * Fields sourced identically to nodus_witness_send_spend_result(). */
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
         * (e.g., pre-BFT seeded genesis). */
        enc_dnac_response(&enc, txn_id, "dnac_block", 9);
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

    /* Encode response (320 per block to fit prev_hash) */
    size_t buf_size = 512 + ((size_t)count * 320);
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
         * block's TX count. */
        cbor_encode_map(&enc, 7);
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
 * dnac_spend — Submit TX for BFT consensus
 *
 * Request:  "a": {"tx":bstr, "hash":bstr(64), "pk":bstr(2592),
 *                  "sig":bstr(4627), "fee":uint}
 * Response: (async, sent on BFT COMMIT via nodus_witness_send_spend_result)
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
    if (tx_len > NODUS_T3_MAX_TX_SIZE) {
        send_error(conn, txn_id, NODUS_ERR_TOO_LARGE,
                    "transaction too large");
        return;
    }

    /* Note: tx_hash is computed by the DNAC client from structured fields
     * (version, type, timestamp, inputs, outputs) — NOT from the serialized
     * blob. The client signs tx_hash with Dilithium5. BFT prevote verifies
     * the signature. We trust the client-provided tx_hash here because:
     * 1) It is signed (integrity guaranteed by sig verification)
     * 2) DNAC hashing is deterministic from the TX fields */

    /* Extract tx_type from tx_data.
     * DNAC serialization: [version(1)] [type(1)] [timestamp(8)] ... */
    if (tx_len < 2) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "tx_data too short for header");
        return;
    }
    uint8_t tx_type = tx_data[1];

    /* Genesis pre-check */
    bool genesis_exists = nodus_witness_genesis_exists(w);
    if (!genesis_exists && tx_type != NODUS_W_TX_GENESIS) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "no genesis yet — only GENESIS transactions allowed");
        return;
    }
    if (genesis_exists && tx_type == NODUS_W_TX_GENESIS) {
        send_error(conn, txn_id, NODUS_ERR_ALREADY_EXISTS,
                    "genesis already exists");
        return;
    }

    /* Extract nullifiers from tx_data.
     * DNAC v0.17.1 serialization:
     *   [version(1)] [type(1)] [timestamp(8)] [tx_hash(64)] [committed_fee(8)]
     *   [input_count(1)] [inputs...]
     * Each input: [nullifier(64)] [amount(8)] [token_id(64)]
     * For GENESIS: input_count == 0. Offset comes from the canonical
     * dnac/transaction.h DNAC_TX_HEADER_SIZE so libnodus and libdna stay
     * wire-identical. */
    uint8_t nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
    uint8_t nullifier_count = 0;

    const size_t input_count_offset = DNAC_TX_HEADER_SIZE;

    if (tx_type != NODUS_W_TX_GENESIS) {
        if (tx_len < input_count_offset + 1) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "tx_data too short for inputs");
            return;
        }

        nullifier_count = tx_data[input_count_offset];
        if (nullifier_count > NODUS_T3_MAX_TX_INPUTS) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                        "too many nullifiers");
            return;
        }

        /* Extract nullifiers from input data */
        size_t offset = input_count_offset + 1;  /* past header + input_count */
        for (int i = 0; i < nullifier_count; i++) {
            if (offset + NODUS_T3_NULLIFIER_LEN > tx_len) {
                send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                            "tx_data truncated");
                return;
            }
            memcpy(nullifiers[i], tx_data + offset,
                   NODUS_T3_NULLIFIER_LEN);
            /* Skip rest of input: nullifier(64) + amount(8) + token_id(64) */
            offset += NODUS_T3_NULLIFIER_LEN + 8 + 64;
        }
    }

    /* F17 A2 — transport-layer roster swap. BFT config is refreshed
     * from the chain-derived committee at round-start, not here. */
    if (w->pending_roster_ready &&
        w->pending_roster.n_witnesses != w->roster.n_witnesses) {
        memcpy(&w->roster, &w->pending_roster, sizeof(w->roster));
        w->pending_roster_ready = false;
        fprintf(stderr, "%s: force roster swap on spend: %u witnesses "
                "(transport)\n", LOG_TAG, w->roster.n_witnesses);
    }

    /* Check if we are leader */
    bool is_leader = nodus_witness_bft_is_leader(w);

    if (is_leader) {
        /* Phase 7 / Task 7.5 — genesis goes through the same batch-of-1
         * BFT round as every other TX. The Phase 6 commit_genesis
         * dispatch (Task 7.6) bootstraps the chain DB at commit time,
         * so genesis no longer needs its own round entrypoint. */
        if (tx_type == NODUS_W_TX_GENESIS) {
            fprintf(stderr, "%s: dnac_spend — genesis TX, batch-of-1 BFT path\n",
                    LOG_TAG);

            nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
            if (!e) {
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "out of memory");
                return;
            }
            memcpy(e->tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
            e->tx_type = tx_type;
            e->nullifier_count = nullifier_count;
            for (int i = 0; i < nullifier_count; i++)
                memcpy(e->nullifiers[i], nullifiers[i],
                       NODUS_T3_NULLIFIER_LEN);
            e->tx_data = malloc(tx_len);
            if (!e->tx_data) {
                free(e);
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "out of memory");
                return;
            }
            memcpy(e->tx_data, tx_data, tx_len);
            e->tx_len = (uint32_t)tx_len;
            if (client_pk)
                memcpy(e->client_pubkey, client_pk, NODUS_PK_BYTES);
            if (client_sig)
                memcpy(e->client_sig, client_sig, NODUS_SIG_BYTES);
            e->fee = fee;
            e->client_conn = conn;
            e->client_txn_id = txn_id;
            e->is_forwarded = false;

            nodus_witness_mempool_entry_t *entries[1] = { e };
            int rc = nodus_witness_bft_start_round_from_entries(w, entries, 1);
            if (rc != 0) {
                /* On failure, free the entry — round didn't take ownership */
                nodus_witness_mempool_entry_free(e);
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "genesis BFT round failed");
            }
            /* On success, ownership transfers to round_state.batch_entries
             * and the commit path frees it. */
            return;
        }

        fprintf(stderr, "%s: dnac_spend — we are leader, adding to mempool\n",
                LOG_TAG);

        /* Pre-verify TX before adding to mempool */
        char reject_reason[256] = {0};
        int vrc = nodus_witness_verify_transaction(w, tx_data, (uint32_t)tx_len,
                      tx_hash, tx_type,
                      (const uint8_t *)nullifiers, nullifier_count,
                      client_pk, client_sig, fee,
                      reject_reason, sizeof(reject_reason));
        if (vrc == -2) {
            send_error(conn, txn_id, NODUS_ERR_DOUBLE_SPEND,
                        "nullifier already spent (double-spend)");
            return;
        }
        if (vrc != 0) {
            send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR, reject_reason);
            return;
        }

        /* Create mempool entry */
        nodus_witness_mempool_entry_t *entry = calloc(1, sizeof(*entry));
        if (!entry) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "allocation failed");
            return;
        }

        memcpy(entry->tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
        entry->nullifier_count = nullifier_count;
        for (int i = 0; i < nullifier_count; i++)
            memcpy(entry->nullifiers[i], nullifiers[i], NODUS_T3_NULLIFIER_LEN);
        entry->tx_type = tx_type;
        entry->tx_data = malloc(tx_len);
        if (!entry->tx_data) {
            free(entry);
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "allocation failed");
            return;
        }
        memcpy(entry->tx_data, tx_data, tx_len);
        entry->tx_len = (uint32_t)tx_len;
        if (client_pk)
            memcpy(entry->client_pubkey, client_pk, NODUS_PK_BYTES);
        if (client_sig)
            memcpy(entry->client_sig, client_sig, NODUS_SIG_BYTES);
        entry->fee = fee;
        entry->client_conn = conn;
        entry->client_txn_id = txn_id;
        entry->is_forwarded = false;

        int rc = nodus_witness_mempool_add(&w->mempool, entry);
        if (rc != 0) {
            const char *msg = (rc == -2) ? "duplicate transaction" : "mempool full";
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR, msg);
            nodus_witness_mempool_entry_free(entry);
        }
        /* Response sent asynchronously when block timer fires and COMMIT completes */
    } else {
        fprintf(stderr, "%s: dnac_spend — forwarding to leader\n", LOG_TAG);

        /* Find a free pending_forward slot */
        int pf_slot = -1;
        for (int i = 0; i < NODUS_W_MAX_PENDING_FWD; i++) {
            if (!w->pending_forwards[i].active) {
                pf_slot = i;
                break;
            }
        }
        if (pf_slot < 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "too many pending forwards");
            return;
        }

        /* Track pending forward so we can route response back */
        w->pending_forwards[pf_slot].active = true;
        memcpy(w->pending_forwards[pf_slot].tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
        w->pending_forwards[pf_slot].client_conn = conn;
        w->pending_forwards[pf_slot].client_txn_id = txn_id;
        w->pending_forwards[pf_slot].started_at = (uint64_t)time(NULL);
        w->pending_forward_count++;

        /* F17 A4 — find the chain-committee-derived leader for the next
         * block, then resolve its peer connection. F17 A5 bootstrap —
         * if committee empty (pre-genesis), fall back to gossip-roster-
         * based leader lookup so genesis forwarding works. */
        struct nodus_tcp_conn *leader_conn = NULL;
        {
            uint64_t next_bh = nodus_witness_block_height(w) + 1;
            nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
            int cm_count = 0;
            (void)nodus_committee_get_for_block(w, next_bh, committee,
                                                  DNAC_COMMITTEE_SIZE,
                                                  &cm_count);

            /* C7 fix: block-height epoch — cluster-agreed, no clock-skew fork risk */
            uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;
            const uint8_t *leader_pk = NULL;
            int leader_roster_idx = -1;

            if (cm_count > 0) {
                /* Post-genesis: committee-derived leader. */
                int leader_slot = nodus_witness_bft_leader_index(
                    epoch, w->current_view, cm_count);
                if (leader_slot < 0) {
                    send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "no leader available");
                    w->pending_forwards[pf_slot].active = false;
                    w->pending_forward_count--;
                    return;
                }
                leader_pk = committee[leader_slot].pubkey;
                if (memcmp(leader_pk, w->server->identity.pk.bytes,
                            DNAC_PUBKEY_SIZE) == 0) {
                    send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "we are the leader, nothing to forward");
                    w->pending_forwards[pf_slot].active = false;
                    w->pending_forward_count--;
                    return;
                }
            } else {
                /* Pre-genesis bootstrap: gossip-roster-based leader. */
                int gossip_count = (int)w->roster.n_witnesses;
                if (gossip_count == 0) {
                    send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "no witnesses known");
                    w->pending_forwards[pf_slot].active = false;
                    w->pending_forward_count--;
                    return;
                }
                leader_roster_idx = nodus_witness_bft_leader_index(
                    epoch, w->current_view, gossip_count);
                int my_roster_idx = nodus_witness_roster_find(
                    &w->roster, w->my_id);
                if (leader_roster_idx < 0 ||
                    leader_roster_idx == my_roster_idx) {
                    send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "we are the leader (bootstrap)");
                    w->pending_forwards[pf_slot].active = false;
                    w->pending_forward_count--;
                    return;
                }
                leader_pk = w->roster.witnesses[leader_roster_idx].pubkey;
            }

            /* Find peer connection whose roster pubkey matches leader_pk. */
            for (int i = 0; i < w->peer_count; i++) {
                int ri = nodus_witness_roster_find(
                    &w->roster, w->peers[i].witness_id);
                if (ri < 0) continue;
                if (memcmp(w->roster.witnesses[ri].pubkey, leader_pk,
                            DNAC_PUBKEY_SIZE) == 0 &&
                    w->peers[i].conn && w->peers[i].identified) {
                    leader_conn = w->peers[i].conn;
                    break;
                }
            }
        }

        if (!leader_conn) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "leader not connected");
            w->pending_forwards[pf_slot].active = false;
            w->pending_forward_count--;
            return;
        }

        /* Build and send w_fwd_req T3 message */
        nodus_t3_msg_t fwd;
        memset(&fwd, 0, sizeof(fwd));
        fwd.type = NODUS_T3_FWD_REQ;
        fwd.txn_id = ++w->next_txn_id;
        snprintf(fwd.method, sizeof(fwd.method), "w_fwd_req");

        memcpy(fwd.fwd_req.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
        fwd.fwd_req.tx_data = (uint8_t *)tx_data;
        fwd.fwd_req.tx_len = (uint32_t)tx_len;
        fwd.fwd_req.client_pubkey = (uint8_t *)client_pk;
        fwd.fwd_req.client_sig = (uint8_t *)client_sig;
        fwd.fwd_req.fee = fee;
        memcpy(fwd.fwd_req.forwarder_id, w->my_id,
               NODUS_T3_WITNESS_ID_LEN);

        /* Fill header and sign */
        fwd.header.version = NODUS_T3_BFT_PROTOCOL_VER;
        fwd.header.round = w->current_round;
        fwd.header.view = w->current_view;
        memcpy(fwd.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
        fwd.header.timestamp = (uint64_t)time(NULL);
        nodus_random((uint8_t *)&fwd.header.nonce,
                      sizeof(fwd.header.nonce));
        memcpy(fwd.header.chain_id, w->chain_id, 32);

        uint8_t fwd_buf[NODUS_T3_MAX_MSG_SIZE];
        size_t fwd_len = 0;

        if (nodus_t3_encode(&fwd, &w->server->identity.sk,
                             fwd_buf, sizeof(fwd_buf), &fwd_len) != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "failed to encode forward request");
            w->pending_forwards[pf_slot].active = false;
            w->pending_forward_count--;
            return;
        }

        if (nodus_tcp_send(leader_conn, fwd_buf, fwd_len) != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "failed to send to leader");
            w->pending_forwards[pf_slot].active = false;
            w->pending_forward_count--;
            return;
        }

        fprintf(stderr, "%s: forwarded spend to committee leader (slot %d)\n",
                LOG_TAG, pf_slot);
        /* Response will arrive via w_fwd_rsp */
    }
}

/* ════════════════════════════════════════════════════════════════════
 * Spend result — sent on BFT COMMIT (async response to dnac_spend)
 * ════════════════════════════════════════════════════════════════════ */

/* Phase 12 / Task 12.2 spec moved to nodus_witness_spend_preimage.h
 * along with the testable preimage builder. The live signer below
 * uses dnac_compute_spend_result_preimage(); the spec stays exported
 * so test fixtures bind to the same authoritative layout. */

void nodus_witness_send_spend_result(nodus_witness_t *w,
                                       nodus_witness_mempool_entry_t *entry,
                                       int status,
                                       const char *error_msg) {
    if (!w || !entry) return;

    struct nodus_tcp_conn *conn = entry->client_conn;
    uint32_t txn_id = entry->client_txn_id;

    if (!conn) return;

    if (status != DNAC_STATUS_APPROVED && error_msg) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR, error_msg);
        return;
    }

    /* Phase 12 / Task 12.1 — single time(NULL) call reused for wire field
     * AND signed preimage. Eliminates TOCTOU between the two values. */
    uint64_t ts = (uint64_t)time(NULL);

    /* Phase 12 / Task 12.3 — bind the wire wpk field via SHA3-512(wpk).
     * Without this, an attacker could swap the pk field in the response
     * and the sig would still validate over the bare tx_hash/wid/ts. */
    uint8_t wpk_hash[64];
    qgp_sha3_512(w->server->identity.pk.bytes, NODUS_PK_BYTES, wpk_hash);

    uint8_t preimage[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    dnac_compute_spend_result_preimage(entry->tx_hash, w->my_id, wpk_hash,
                                         w->chain_id, ts,
                                         entry->committed_block_height,
                                         entry->committed_tx_index,
                                         (uint8_t)status, preimage);

    nodus_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    /* CERT domain kept RAW — see dnac_spend_replay handler above for rationale
     * (DNAC client cross-repo coupling, deferred to future migration). */
    nodus_sign(&sig, preimage, sizeof(preimage), &w->server->identity.sk);

    /* Build response with extended fields (status, wid, wpk, ts, bnr, ti,
     * cid, wsig). Phase 13 / Task 13.2 pulls block_height + tx_index +
     * chain_id onto the client API. */
    uint8_t buf[8192];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_spend", 8);

    cbor_encode_cstr(&enc, "status");
    cbor_encode_uint(&enc, (uint64_t)status);

    cbor_encode_cstr(&enc, "wid");
    cbor_encode_bstr(&enc, w->my_id, NODUS_T3_WITNESS_ID_LEN);

    cbor_encode_cstr(&enc, "wpk");
    cbor_encode_bstr(&enc, w->server->identity.pk.bytes, NODUS_PK_BYTES);

    cbor_encode_cstr(&enc, "ts");
    cbor_encode_uint(&enc, ts);

    cbor_encode_cstr(&enc, "bnr");
    cbor_encode_uint(&enc, entry->committed_block_height);

    cbor_encode_cstr(&enc, "ti");
    cbor_encode_uint(&enc, (uint64_t)entry->committed_tx_index);

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

    fprintf(stderr, "%s: sent spend result (status=%d, txn_id=%u, "
            "block=%llu, tx_index=%u)\n",
            LOG_TAG, status, txn_id,
            (unsigned long long)entry->committed_block_height,
            entry->committed_tx_index);
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
 *                   ... up to DNAC_COMMITTEE_SIZE
 *                 ]}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_committee_query(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          uint32_t txn_id) {
    uint64_t height      = nodus_witness_block_height(w);
    uint64_t target_h    = height + 1;   /* committee that signs next block */
    uint64_t epoch_start = (target_h / (uint64_t)DNAC_EPOCH_LENGTH) *
                             (uint64_t)DNAC_EPOCH_LENGTH;

    nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
    int count = 0;
    int rc = nodus_committee_get_for_block(w, target_h, committee,
                                             DNAC_COMMITTEE_SIZE, &count);
    if (rc != 0) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "committee lookup failed");
        return;
    }

    /* Response: 3 top-level keys; each committee entry packs ~2700 bytes
     * (2592 pubkey + address 256 + overhead). Budget comfortably. */
    size_t buf_size = 512 + (size_t)DNAC_COMMITTEE_SIZE * 3200;
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
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

        /* Roster endpoint lookup: committee pubkey matches a witness
         * pubkey when the committee member is running a witness node.
         * Every committee member MUST be running a witness node for
         * BFT to work, but during rollout we tolerate no-match and
         * ship empty addr. */
        const char *addr = "";
        for (uint32_t j = 0; j < w->roster.n_witnesses; j++) {
            if (memcmp(w->roster.witnesses[j].pubkey, committee[i].pubkey,
                       DNAC_PUBKEY_SIZE) == 0) {
                addr = w->roster.witnesses[j].address;
                break;
            }
        }

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
    } else if (strcmp(method, "dnac_genesis") == 0) {
        handle_dnac_genesis(w, conn, txn_id);
    } else if (strcmp(method, "dnac_history") == 0) {
        handle_dnac_history(w, conn, payload, len, txn_id);
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
