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
#include "witness/nodus_witness_v2_produce.h"  /* O15F class 201 helpers */
#include "witness/nodus_witness_mempool.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_o15h_diag.h"  /* O15H TEMPORARY — revert list in that header */
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
     *   8 base fields  ≈ 256 B (O15B §7 added "ub", a u64 ⇒ ≤ 12 B more;
     *                   the 256 B line item already had ample slack and the
     *                   2560 B per-entry round-up is unchanged)
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
         * (e.g., pre-BFT seeded genesis).
         *
         * 2026-07-29: adds "state_root" so read-only clients (explorer)
         * can recompute the block's own hash via the canonical preimage
         * (nodus_witness_compute_block_hash_ex) without waiting for the
         * child block's prev_hash. The client decoder has parsed this
         * key since Phase 7 (nodus_client.c dnac_block state_root arm).
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
 * 128 lowercase hex. Matches the fp formula used in BFT roster code
 * (nodus_witness_bft.c:1379) so downstream UI can correlate against
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
 * O15J A — POOL-THEN-FORWARD
 *
 * The full contract, the PBFT §4.1 citation and the determinism argument
 * live on the declaration in witness/nodus_witness.h. What follows is why
 * the CODE is shaped this way.
 *
 * IT IS THE LEADER BRANCH'S CONSTRUCTION, not a second one. The admission
 * call, the class-201 nullifier re-derivation and the entry fill below are
 * the same steps handle_dnac_spend's leader branch performs; only the
 * three routing fields differ, and they differ deliberately — see the
 * ORPHAN block. A second, subtly different construction is exactly how the
 * pooled shape would drift away from what the commit path expects.
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_pool_local_demand(nodus_witness_t *w,
                                      const uint8_t *tx_data, uint32_t tx_len,
                                      const uint8_t *tx_hash, uint8_t tx_type,
                                      const uint8_t *nullifiers,
                                      uint8_t nullifier_count,
                                      const uint8_t *client_pk,
                                      const uint8_t *client_sig,
                                      uint64_t fee,
                                      char *reject_reason, size_t reason_size) {
    if (!w || !tx_data || tx_len == 0 || !tx_hash) {
        if (reject_reason && reason_size)
            snprintf(reject_reason, reason_size, "null parameter");
        return -2;
    }

    /* ── O15K §3.1 — THE SUCCESSOR-ONLY GATE IS GONE ──────────────────
     * `if (!w->v2_successor) return -1;` stood here. Its argument: a
     * legacy peer refuses a non-leader w_fwd_req byte-identically
     * (nodus_witness_peer.c:883), so legacy demand pooled here could
     * never recruit the f+1 backers a rotation needs, and would only
     * drive lone view changes nobody joins.
     *
     * THE PREMISE WAS THE BUG, NOT A SAFEGUARD. That peer-side refusal is
     * removed in this same change, and leaving legacy unpooled is exactly
     * what let a dead leader wedge the chain INDEFINITELY rather than for
     * one epoch: a halted tip freezes the epoch, and the leader is
     * `(epoch + view) % n` (nodus_witness_bft.c:461,504), so leadership
     * stays pinned on the dead node until a view change — which nothing
     * could start, because the P3 deadman arms on
     * `mempool.count > 0 || pending_forward_count > 0`
     * (nodus_witness_bft.c:8682) and BOTH inputs read zero on the one
     * node the client was actually talking to: this gate zeroed the
     * first, and the `!leader_conn` branch in handle_dnac_spend below
     * releases the forward slot in the same call, zeroing the second.
     *
     * THE MODE STAYS NODUS_WITNESS_VERIFY_ADMISSION (below), and that is
     * a decision, not an oversight. This is a DIRECT client submission —
     * the client chose this node, so the node-local fee surge
     * (nodus_witness_verify.c:1154) is a meaningful intake policy here.
     * §3.3a's VALIDATION exemption is scoped to FORWARDED / rebroadcast
     * intake, where the surge would throttle the cluster's own
     * replication; that is a different door, in a different file.
     *
     * ── O15K §3.4 — A LEGACY ENTRY WITH NO NULLIFIER IS NOT DEMAND ────
     * A legacy entry's ONLY handle is its nullifiers. The O15I P3(c)
     * reaper evicts through a committed-nullifier walk, and
     * nodus_witness_v2_entry_verdict answers UNJUDGED for every legacy
     * chain (nodus_witness.c:1112-1114). Pool one with no nullifier and
     * NOTHING can ever remove it: it reads as live demand forever and
     * fires a view change every round_timeout_ms against a HEALTHY
     * leader — the O15I V1 defect class, re-entering through the legacy
     * door. The orphan shape below makes it worse, deliberately:
     * remove_by_conn cannot reach a client_conn == NULL entry either.
     *
     * ⚠ THIS IS NOT PURELY BELT-AND-BRACES ON THIS PATH. For an ordinary
     * legacy type the admission call below refuses the shape itself
     * (Check 4, nodus_witness_verify.c:989-991) and the guard is
     * redundant — but a legacy GENESIS returns 0 from admission BEFORE
     * Check 4 ever runs (nodus_witness_verify.c:952-955), carries no
     * nullifiers by construction (handle_dnac_spend's extraction skips
     * it), and a NON-LEADER is reachable with one while the chain is
     * still pre-genesis. For that entry this guard is the only refusal
     * there is. The condition mirrors Check 4's exactly, `!nullifiers`
     * included, so the two cannot drift and the copy loop below can
     * never walk a NULL array on this lane.
     *
     * SCOPED TO LEGACY, AND THAT IS LOAD-BEARING. A successor class-200
     * ENVELOPE is pooled with nullifier_count == 0 by contract, and a
     * class-201 CLAIM re-derives its committed nullifier further down.
     * An unscoped guard would revert O15I and O15J.
     *
     * REFUSED AS -2, NEVER THE RETIRED -1. The caller's -1 branch was
     * deliberately silent so legacy logs stayed byte-identical, so a
     * repurposed -1 would make a real refusal invisible; -2 is also what
     * admission itself answers for this shape on every path that runs
     * Check 4 (verify returns -1, mapped to -2 below). The forward is
     * NOT stopped — an admission refusal never stopped it — so a
     * pre-genesis GENESIS submission still reaches the leader exactly as
     * it did before. */
    if (!w->v2_successor && (!nullifiers || nullifier_count == 0)) {
        if (reject_reason && reason_size)
            snprintf(reject_reason, reason_size,
                     "legacy entry carries no usable nullifier — nothing "
                     "could ever evict it from the pool");
        return -2;
    }

    /* ── ALREADY OURS? ────────────────────────────────────────────────
     * Asked FIRST, on the same tx_hash key nodus_witness_mempool_add
     * dedups on, and it is not merely an optimisation.
     *
     * ⚠ THE DISPATCH'S ASSUMPTION DOES NOT HOLD FOR EVERY ENTRY CLASS.
     * "A client retry meets mempool_add's duplicate rejection" is true
     * only on the ENVELOPE lane. For a class-201 CLAIM the successor
     * admission lane has its OWN pending-mempool dedup, in ADMISSION mode
     * only, keyed on the claim NULLIFIER rather than on tx_hash
     * (nodus_witness_verify.c, "claim nullifier already pending in
     * mempool") — so a retry is refused THERE and never reaches
     * mempool_add at all. Without this pre-check the two classes would
     * answer a retry differently: 1 (already held) for an envelope, -2
     * (admission refused) for a claim, and O15J B would then tell a
     * retrying claim client that its work was NOT queued when it is.
     *
     * It also removes real work: a client retrying in a loop during a
     * stall would otherwise re-run the full claim admission — decode,
     * canonical re-encode, SHA3-512, distribution proof, ML-DSA-87 leaf
     * verify — on every attempt, for an entry we already hold. */
    for (int i = 0; i < w->mempool.count; i++) {
        const nodus_witness_mempool_entry_t *held = w->mempool.entries[i];
        if (held && memcmp(held->tx_hash, tx_hash,
                           NODUS_T3_TX_HASH_LEN) == 0)
            return 1;
    }

    /* THE SAME ADMISSION GATE the leader branch runs on a direct client
     * submission, and the same one a successor peer runs on a forward. It
     * is what keeps this from widening any trust boundary: nothing
     * unverified ever reaches a follower's pool. On a successor the lane
     * ignores pk/sig/fee/nullifiers by contract
     * (nodus_witness_verify.c), so this node's verdict on these bytes is
     * identical to the one every other successor node reaches. */
    char local_reason[256] = {0};
    int vrc = nodus_witness_verify_transaction(w, tx_data, tx_len,
                  tx_hash, tx_type,
                  nullifiers, nullifier_count,
                  client_pk, client_sig, fee,
                  NODUS_WITNESS_VERIFY_ADMISSION,
                  local_reason, sizeof(local_reason));
    if (vrc != 0) {
        if (reject_reason && reason_size)
            snprintf(reject_reason, reason_size, "%s", local_reason);
        return (vrc == -2) ? -3 : -2;
    }

    nodus_witness_mempool_entry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return -4;

    memcpy(entry->tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    entry->nullifier_count = nullifier_count;
    for (int i = 0; i < nullifier_count; i++)
        memcpy(entry->nullifiers[i], nullifiers + (size_t)i * NODUS_T3_NULLIFIER_LEN,
               NODUS_T3_NULLIFIER_LEN);
    entry->tx_type = tx_type;
    entry->tx_data = malloc(tx_len);
    if (!entry->tx_data) {
        free(entry);
        return -4;
    }
    memcpy(entry->tx_data, tx_data, tx_len);
    entry->tx_len = tx_len;

    /* O15F Task 3 — record the CLAIM's committed nullifier, the same
     * re-derivation the leader branch and the forward intake both do.
     * WITHOUT IT THIS WHOLE CHANGE WOULD LEAK: a 201 pooled with
     * nullifier_count == 0 is invisible to the P3(c) reaper's nullifier
     * walk AND unjudgeable by nodus_witness_v2_entry_verdict (whose class
     * gate answers UNJUDGED for everything that is not a class-200
     * envelope), so nothing could ever remove it once the chain committed
     * it — the O15I V1 shape, re-entering through a new door. Fail-closed:
     * a derivation failure pools nothing at all. */
    if (tx_type == NODUS_W_TX_V2_CLAIM) {
        if (nodus_witness_v2_claim_entry_nullifier(w, entry->tx_data,
                entry->tx_len, entry->nullifiers[0]) != 0) {
            nodus_witness_mempool_entry_free(entry);
            return -4;
        }
        entry->nullifier_count = 1;
    }

    if (client_pk)
        memcpy(entry->client_pubkey, client_pk, NODUS_PK_BYTES);
    if (client_sig)
        memcpy(entry->client_sig, client_sig, NODUS_SIG_BYTES);
    entry->fee = fee;

    /* ── THE ORPHAN SHAPE — the three fields that are not the leader's ──
     * client_conn = NULL is what makes the entry SURVIVE the client
     * disconnect this function exists to outlive.
     * nodus_witness_peer_conn_closed runs for client connections and calls
     * nodus_witness_mempool_remove_by_conn, which matches
     * `client_conn == conn` and early-returns on a NULL conn. Pooling with
     * the live conn would have the CLI's disconnect delete this entry one
     * step after we created it, and the demand would vanish again.
     *
     * is_forwarded + forwarder_id = OUR id: this is the routing the commit
     * path already understands (bft_emit_batch_replies answers
     * forwarder_id), and WE are the node holding the client connection, so
     * a w_fwd_rsp from whichever node commits this comes back here. It is
     * byte-identically the shape nodus_witness_peer_handle_fwd_req pools
     * a forwarded entry in, so nothing downstream meets a new kind of
     * entry. */
    entry->client_conn  = NULL;
    entry->client_txn_id = 0;
    entry->is_forwarded = true;
    memcpy(entry->forwarder_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);

    int rc = nodus_witness_mempool_add(&w->mempool, entry);
    if (rc == -2) {
        /* A client retry for work we are ALREADY carrying. The demand is
         * visible either way, so this is not a failure — it is the
         * duplicate rejection doing its job. */
        nodus_witness_mempool_entry_free(entry);
        return 1;
    }
    if (rc != 0) {
        nodus_witness_mempool_entry_free(entry);
        return -4;
    }
    return 0;
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

    /* ── Ledger V2 O15D — SUCCESSOR submission lane ───────────────────
     * A successor chain has its genesis in v2_blocks, not in the legacy
     * genesis_state table, so the legacy genesis prechecks below would
     * refuse everything ("no genesis yet") — or worse, admit a LEGACY
     * GENESIS into the successor database. Neither lane exists here:
     * every submission is classified as a V2 envelope entry and the
     * successor admission lane (nodus_witness_verify_transaction's
     * divert) is the sole authority — it verifies the wire-family
     * marker, the derived wire_id and the committed-state bindings.
     * Legacy nullifier extraction is skipped (envelopes carry none).
     *
     * O15F Task 3 — the entry class is BYTE-DRIVEN: the wire-family marker
     * at offset 0 selects ENVELOPE (200), everything else CLAIM (201).
     * The successor admission lane decides validity for both. */
    if (w->v2_successor) {
        tx_type = nodus_witness_v2_classify_entry(tx_data, (uint32_t)tx_len);
    } else {
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

    if (!w->v2_successor && tx_type != NODUS_W_TX_GENESIS) {
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

        /* Pre-verify TX before adding to mempool.
         * ADMISSION mode: this is the leader's local intake gate for a
         * client-submitted TX, the one place where the node-local
         * mempool fee surge is meaningful (and where the client can
         * still be told to raise its fee). No peer's verdict depends on
         * the outcome here. */
        char reject_reason[256] = {0};
        int vrc = nodus_witness_verify_transaction(w, tx_data, (uint32_t)tx_len,
                      tx_hash, tx_type,
                      (const uint8_t *)nullifiers, nullifier_count,
                      client_pk, client_sig, fee,
                      NODUS_WITNESS_VERIFY_ADMISSION,
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
        /* O15F Task 3 — record the CLAIM's committed nullifier so batch
         * selection dedups claims semantically. Verify already admitted it
         * (so this re-derivation cannot fail on an honest submission); a
         * failure here is fail-closed — never enqueue a class-201 entry
         * with nullifier_count == 0 (batch dedup would silently lose it). */
        if (w->v2_successor && tx_type == NODUS_W_TX_V2_CLAIM) {
            if (nodus_witness_v2_claim_entry_nullifier(w, entry->tx_data,
                    entry->tx_len, entry->nullifiers[0]) != 0) {
                nodus_witness_mempool_entry_free(entry);
                send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                            "claim nullifier derivation failed");
                return;
            }
            entry->nullifier_count = 1;
        }
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

        /* ── O15J A — POOL, THEN FORWARD ──────────────────────────────
         *
         * BEFORE the forward and INDEPENDENTLY of whether it succeeds.
         * Full rationale + the PBFT §4.1 citation: the contract on
         * nodus_witness_pool_local_demand in witness/nodus_witness.h.
         *
         * THE ORDERING IS LOAD-BEARING, and not only for the
         * !leader_conn exit below. EVERY early return between here and
         * the send is a path that used to DISCARD the client's work: the
         * pending_forwards table being full, "no leader available", the
         * empty roster, the encode failure, the send failure. Pooling
         * first makes the demand visible on all of them.
         *
         * ON EVERY NON-LEADER INTAKE, not only when the leader is
         * unreachable. A leader whose TCP is alive but whose witness is
         * WEDGED accepts the forward and never proposes — that is the
         * trapped-validator shape the 20-node rehearsal actually
         * produced (three validators at DB tip 42 with
         * round_state.block_height frozen at 36, rejecting every
         * PROPOSE), and a `!leader_conn`-only pool would miss it
         * entirely.
         *
         * AN ADMISSION REFUSAL DOES NOT STOP THE FORWARD. This node may
         * simply be behind: converting a follower's local verdict into a
         * client-visible rejection would refuse transactions the LEADER
         * would have accepted. The leader stays the authority for the
         * client's answer; all that is lost is our local copy. */
        char pool_reason[256] = {0};
        int pool_rc = nodus_witness_pool_local_demand(w, tx_data,
                          (uint32_t)tx_len, tx_hash, tx_type,
                          (const uint8_t *)nullifiers, nullifier_count,
                          client_pk, client_sig, fee,
                          pool_reason, sizeof(pool_reason));
        bool pooled_locally = (pool_rc >= 0);
        if (pool_rc == 0)
            fprintf(stderr, "%s: pooled the client's entry locally before "
                    "forwarding — a dead or wedged leader is no longer the "
                    "only node that knows a client is waiting "
                    "(mempool=%d)\n", LOG_TAG, w->mempool.count);
        else if (pool_rc == 1)
            fprintf(stderr, "%s: client retry for an entry we already hold "
                    "(mempool=%d)\n", LOG_TAG, w->mempool.count);
        else if (pool_rc == -2 || pool_rc == -3)
            fprintf(stderr, "%s: not pooled locally (admission: %s) — "
                    "forwarding anyway; the leader is the authority for "
                    "the client's answer\n", LOG_TAG,
                    pool_rc == -3 ? "nullifier already spent" : pool_reason);
        else if (pool_rc == -4)
            fprintf(stderr, "%s: not pooled locally (pool full or "
                    "allocation failed) — forwarding anyway\n", LOG_TAG);
        /* O15K §3.1 — there is no -1 branch to write any more. The
         * successor-only gate that produced it is deleted, so a legacy
         * chain no longer declines silently: it now either pools (0 / 1
         * above) or reports admission's own verdict (-2 / -3), and the
         * legacy log gains exactly the lines the successor lane already
         * had. -1 is retired, not reassigned. */

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
#ifdef O15H_DIAG_ENABLED
        /* O15H TEMPORARY DIAGNOSTIC — see nodus_witness_o15h_diag.h.
         * Every failure branch below answers the client with the same
         * NODUS_ERR_INTERNAL_ERROR (rc=8) and prints nothing, so the
         * observed "44 forwards, 0 successes" could not be attributed to
         * a branch. This local carries the elected slot out to the
         * emit point. */
        int o15h_slot = -1;
#endif
        {
            uint64_t next_bh = nodus_witness_block_height(w) + 1;
            /* S3: heap — a DNAC_MAX_ACTIVE_VALIDATORS committee is
             * ~334 KB. Freed on every exit path in this block. */
            nodus_committee_member_t *committee = NULL;
            int cm_count = 0;
            (void)nodus_committee_get_for_block_alloc(w, next_bh, &committee,
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
                    free(committee);
                    send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "no leader available");
                    w->pending_forwards[pf_slot].active = false;
                    w->pending_forward_count--;
                    return;
                }
                /* NOTE: leader_pk borrows the heap committee below, so the
                 * free() has to wait until the peer-lookup loop is done. */
                leader_pk = committee[leader_slot].pubkey;
#ifdef O15H_DIAG_ENABLED
                o15h_slot = leader_slot;
#endif
                if (memcmp(leader_pk, w->server->identity.pk.bytes,
                            DNAC_PUBKEY_SIZE) == 0) {
                    free(committee);
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
                    free(committee);
                    send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                                "no witnesses known");
                    w->pending_forwards[pf_slot].active = false;
                    w->pending_forward_count--;
                    return;
                }
                /* O15C-D — leader_index yields a SLOT in the sorted set,
                 * not an array position. Resolving it with the arrival
                 * index made this the last leader-selection site that
                 * disagreed with nodus_witness_bft_is_leader: a node
                 * whose roster had a different arrival order forwarded
                 * the spend to a non-leader, which mempooled it and
                 * never proposed, so the pending_forward expired with
                 * no w_fwd_rsp (MED-27's observed symptom). */
                int leader_slot = nodus_witness_bft_leader_index(
                    epoch, w->current_view, gossip_count);
                leader_roster_idx = nodus_witness_roster_sorted_at(
                    &w->roster, leader_slot);
                int my_slot = nodus_witness_roster_sorted_find(
                    &w->roster, w->my_id);
                if (leader_roster_idx < 0 || leader_slot < 0 ||
                    leader_slot == my_slot) {
                    free(committee);
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
            /* O15H TEMPORARY DIAGNOSTIC — who the elected leader for
             * next_bh is, and whether this node can reach it. `tally`
             * carries the committee size and `quorum` the elected slot;
             * both are borrowed fields, not their production meaning. */
            O15H_DIAG(w, "fwd_leader", leader_pk, next_bh, w->current_view,
                      w->view_change_target, w->round_state.phase,
                      epoch, 0, "w_fwd_req", 0,
                      (unsigned)cm_count, (unsigned)(o15h_slot + 1),
                      leader_conn ? "leader resolved and connected"
                                  : "leader NOT connected — forward fails");

            /* leader_pk is dead from here on. */
            free(committee);
            committee = NULL;
            leader_pk = NULL;
        }

        if (!leader_conn) {
            /* O15J B — the CLIENT'S ANSWER on the unreachable-leader
             * path. The work is no longer discarded here (it was pooled
             * above), so the message that says it was is now false. The
             * ERROR CODE IS DELIBERATELY UNCHANGED: NODUS_ERR_* is wire
             * surface, every deployed client maps these numerically, and
             * a new code would be a breaking change for a message-only
             * improvement. Only the human-readable text differs.
             *
             * CONDITIONAL ON HAVING ACTUALLY POOLED, and claiming
             * otherwise would be telling the client something untrue.
             * O15K §3.1 opened this lane to legacy chains too, so the
             * true branch is now the ordinary one on BOTH lanes; the
             * false branch is what admission refused (-2 / -3) or what
             * would not fit (-4), never a whole chain class.
             *
             * The client is answered IMMEDIATELY rather than left on the
             * 30 s pending_forwards timeout: the slot is released on this
             * path, so nothing would ever answer it. A retry while the
             * entry sits in our pool meets the ordinary duplicate
             * rejection in nodus_witness_mempool_add, which is correct
             * and needs no special case. */
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        pooled_locally
                          ? "leader not reachable — request accepted and "
                            "queued on this node; it will be proposed once "
                            "the cluster elects a reachable leader"
                          : "leader not connected");
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

        /* O15H D8 — HEAP, at the 1 MB bound, not a 128 KB stack array.
         * This is the ONE stack buffer in the tree that encodes a
         * message CARRYING a transaction, so it is the one that has to
         * grow with the family-aware limit above; a V2 envelope may now
         * legitimately exceed NODUS_T3_MAX_MSG_SIZE, and 1 MB of stack
         * is not an option. The bound is the same one
         * nodus_witness_bft_broadcast and nodus_t3_verify already use
         * for PROPOSE/COMMIT, so producer and verifier agree. */
        uint8_t *fwd_buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
        if (!fwd_buf) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "failed to allocate forward request");
            w->pending_forwards[pf_slot].active = false;
            w->pending_forward_count--;
            return;
        }
        size_t fwd_len = 0;

        if (nodus_t3_encode(&fwd, &w->server->identity.sk,
                             fwd_buf, NODUS_W_MAX_SYNC_RSP_SIZE,
                             &fwd_len) != 0) {
            free(fwd_buf);
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "failed to encode forward request");
            w->pending_forwards[pf_slot].active = false;
            w->pending_forward_count--;
            return;
        }

        int send_rc = nodus_tcp_send(leader_conn, fwd_buf, fwd_len);
        free(fwd_buf);          /* O15H D8 — heap buffer, every path */
        if (send_rc != 0) {
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
