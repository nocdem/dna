/**
 * Nodus v5 — DNAC Client Handlers
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
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define LOG_TAG "WITNESS-DNAC"

/* Max UTXOs per query response */
#define DNAC_MAX_UTXO_RESULTS   100

/* Max ledger range entries per query */
#define DNAC_MAX_RANGE_RESULTS  100

/* Spend result status codes */
#define DNAC_STATUS_APPROVED   0
#define DNAC_STATUS_REJECTED   1
#define DNAC_STATUS_ERROR      2

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
    if (rlen > 0)
        nodus_tcp_send(conn, buf, rlen);
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
    if (rlen > 0)
        nodus_tcp_send(conn, buf, rlen);
}

/* ════════════════════════════════════════════════════════════════════
 * dnac_supply — Query supply state
 *
 * Request:  "a": {}
 * Response: "r": {"genesis":N, "burned":N, "current":N, "last_seq":N}
 * ════════════════════════════════════════════════════════════════════ */

static void handle_dnac_supply(nodus_witness_t *w,
                                 struct nodus_tcp_conn *conn,
                                 uint32_t txn_id) {
    nodus_witness_supply_t supply;
    int rc = nodus_witness_supply_get(w, &supply);

    uint8_t buf[256];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));

    if (rc != 0) {
        enc_dnac_response(&enc, txn_id, "dnac_supply", 4);
        cbor_encode_cstr(&enc, "genesis");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "burned");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "current");
        cbor_encode_uint(&enc, 0);
        cbor_encode_cstr(&enc, "last_seq");
        cbor_encode_uint(&enc, 0);
    } else {
        enc_dnac_response(&enc, txn_id, "dnac_supply", 4);
        cbor_encode_cstr(&enc, "genesis");
        cbor_encode_uint(&enc, supply.genesis_supply);
        cbor_encode_cstr(&enc, "burned");
        cbor_encode_uint(&enc, supply.total_burned);
        cbor_encode_cstr(&enc, "current");
        cbor_encode_uint(&enc, supply.current_supply);
        cbor_encode_cstr(&enc, "last_seq");
        cbor_encode_uint(&enc, supply.last_sequence);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0)
        nodus_tcp_send(conn, buf, rlen);
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

    nodus_witness_utxo_entry_t *utxos = calloc((size_t)max_results,
                                                  sizeof(nodus_witness_utxo_entry_t));
    if (!utxos) {
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    int count = 0;
    nodus_witness_utxo_by_owner(w, owner, utxos, max_results, &count);

    /* Encode response — size depends on count */
    size_t buf_size = 512 + ((size_t)count * 256);
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        free(utxos);
        send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                    "allocation failed");
        return;
    }

    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, buf_size);
    enc_dnac_response(&enc, txn_id, "dnac_utxo", 2);

    cbor_encode_cstr(&enc, "count");
    cbor_encode_uint(&enc, (uint64_t)count);

    cbor_encode_cstr(&enc, "utxos");
    cbor_encode_array(&enc, (size_t)count);

    for (int i = 0; i < count; i++) {
        cbor_encode_map(&enc, 6);
        cbor_encode_cstr(&enc, "n");
        cbor_encode_bstr(&enc, utxos[i].nullifier, NODUS_T3_NULLIFIER_LEN);
        cbor_encode_cstr(&enc, "owner");
        cbor_encode_cstr(&enc, utxos[i].owner);
        cbor_encode_cstr(&enc, "amount");
        cbor_encode_uint(&enc, utxos[i].amount);
        cbor_encode_cstr(&enc, "hash");
        cbor_encode_bstr(&enc, utxos[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        cbor_encode_cstr(&enc, "idx");
        cbor_encode_uint(&enc, utxos[i].output_index);
        cbor_encode_cstr(&enc, "bh");
        cbor_encode_uint(&enc, utxos[i].block_height);
    }

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0)
        nodus_tcp_send(conn, buf, rlen);

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
    if (rlen > 0)
        nodus_tcp_send(conn, buf, rlen);

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
    if (rlen > 0)
        nodus_tcp_send(conn, buf, rlen);

    free(buf);
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
     * DNAC serialization: [version(1)] [type(1)] [timestamp(8)] [tx_hash(64)]
     *                     [input_count(1)] [inputs...]
     * Each input: [nullifier(64)] [amount(8)]
     * For GENESIS: input_count == 0 */
    uint8_t nullifiers[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
    uint8_t nullifier_count = 0;

    /* Header: version(1) + type(1) + timestamp(8) + tx_hash(64) = 74 bytes */
    const size_t input_count_offset = 1 + 1 + 8 + NODUS_T3_TX_HASH_LEN;

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
            /* Skip rest of input: nullifier(64) + amount(8) */
            offset += NODUS_T3_NULLIFIER_LEN + 8;
        }
    }

    /* Check if we are leader */
    bool is_leader = nodus_witness_bft_is_leader(w);

    if (is_leader) {
        fprintf(stderr, "%s: dnac_spend — we are leader, starting BFT\n",
                LOG_TAG);

        /* Store client connection for async response */
        w->round_state.client_conn = conn;
        w->round_state.client_txn_id = txn_id;
        w->round_state.is_forwarded = false;

        int rc = nodus_witness_bft_start_round(w, tx_hash,
                                                  nullifiers,
                                                  nullifier_count,
                                                  tx_type,
                                                  tx_data,
                                                  (uint32_t)tx_len,
                                                  client_pk,
                                                  client_sig,
                                                  fee);

        if (rc == -2) {
            /* Double-spend: send immediate error */
            send_error(conn, txn_id, NODUS_ERR_DOUBLE_SPEND,
                        "nullifier already spent (double-spend)");
        } else if (rc != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "transaction verification failed");
        }
        /* If rc == 0: response sent asynchronously on COMMIT */
    } else {
        fprintf(stderr, "%s: dnac_spend — forwarding to leader\n", LOG_TAG);

        /* Track pending forward so we can route response back */
        w->pending_forward.active = true;
        memcpy(w->pending_forward.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
        w->pending_forward.client_conn = conn;
        w->pending_forward.client_txn_id = txn_id;

        /* Find leader peer */
        uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
        int leader_idx = nodus_witness_bft_leader_index(
            epoch, w->current_view, w->roster.n_witnesses);

        if (leader_idx < 0 || leader_idx == w->my_index) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "no leader available");
            w->pending_forward.active = false;
            return;
        }

        /* Find peer connection for leader */
        struct nodus_tcp_conn *leader_conn = NULL;
        for (int i = 0; i < w->peer_count; i++) {
            int ri = nodus_witness_roster_find(
                &w->roster, w->peers[i].witness_id);
            if (ri == leader_idx && w->peers[i].conn &&
                w->peers[i].identified) {
                leader_conn = w->peers[i].conn;
                break;
            }
        }

        if (!leader_conn) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "leader not connected");
            w->pending_forward.active = false;
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
            w->pending_forward.active = false;
            return;
        }

        if (nodus_tcp_send(leader_conn, fwd_buf, fwd_len) != 0) {
            send_error(conn, txn_id, NODUS_ERR_INTERNAL_ERROR,
                        "failed to send to leader");
            w->pending_forward.active = false;
            return;
        }

        fprintf(stderr, "%s: forwarded spend to leader (roster %d)\n",
                LOG_TAG, leader_idx);
        /* Response will arrive via w_fwd_rsp */
    }
}

/* ════════════════════════════════════════════════════════════════════
 * Spend result — sent on BFT COMMIT (async response to dnac_spend)
 * ════════════════════════════════════════════════════════════════════ */

void nodus_witness_send_spend_result(nodus_witness_t *w,
                                       int status,
                                       const char *error_msg) {
    if (!w) return;

    struct nodus_tcp_conn *conn = w->round_state.client_conn;
    uint32_t txn_id = w->round_state.client_txn_id;

    if (!conn) return;

    if (status != DNAC_STATUS_APPROVED && error_msg) {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR, error_msg);
        return;
    }

    /* Build spend response with witness attestation */
    uint8_t buf[8192];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    enc_dnac_response(&enc, txn_id, "dnac_spend", 5);

    cbor_encode_cstr(&enc, "status");
    cbor_encode_uint(&enc, (uint64_t)status);

    cbor_encode_cstr(&enc, "wid");
    cbor_encode_bstr(&enc, w->my_id, NODUS_T3_WITNESS_ID_LEN);

    cbor_encode_cstr(&enc, "wpk");
    cbor_encode_bstr(&enc, w->server->identity.pk.bytes, NODUS_PK_BYTES);

    cbor_encode_cstr(&enc, "ts");
    cbor_encode_uint(&enc, (uint64_t)time(NULL));

    /* Sign: tx_hash + witness_id + timestamp */
    uint8_t signed_data[NODUS_T3_TX_HASH_LEN + NODUS_T3_WITNESS_ID_LEN + 8];
    memcpy(signed_data, w->round_state.tx_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(signed_data + NODUS_T3_TX_HASH_LEN, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    uint64_t ts = (uint64_t)time(NULL);
    memcpy(signed_data + NODUS_T3_TX_HASH_LEN + NODUS_T3_WITNESS_ID_LEN,
           &ts, 8);

    nodus_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    nodus_sign(&sig, signed_data, sizeof(signed_data),
                &w->server->identity.sk);

    cbor_encode_cstr(&enc, "wsig");
    cbor_encode_bstr(&enc, sig.bytes, NODUS_SIG_BYTES);

    size_t rlen = cbor_encoder_len(&enc);
    if (rlen > 0)
        nodus_tcp_send(conn, buf, rlen);

    fprintf(stderr, "%s: sent spend result (status=%d, txn_id=%u)\n",
            LOG_TAG, status, txn_id);
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
    } else {
        send_error(conn, txn_id, NODUS_ERR_PROTOCOL_ERROR,
                    "unknown DNAC method");
    }
}
