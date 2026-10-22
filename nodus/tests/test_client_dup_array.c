/**
 * Nodus — client DNAC response decoders vs. repeated keys (P0-B, 2026-09-28)
 *
 * What it proves (a hostile or broken server cannot corrupt client memory):
 *   - dnac_utxo: a second "utxos" array is refused (NODUS_ERR_PROTOCOL_ERROR,
 *     result freed). Before the fix it re-calloc'd entries without resetting
 *     count and wrote at entries[count] — with a 3-entry first array and a
 *     1-entry second one that is a write 3 slots past a 1-slot allocation.
 *   - Well-formed replies of the shape the node's handler writes
 *     (nodus_witness_handlers.c) still decode with the expected counts.
 * (The dnac_ledger_range and dnac_block cases are deleted with those
 * client functions and RPCs, 2026-10-15.)
 *
 * Seam: the decoder is static in nodus_client.c. This target
 * compiles nodus_client.c itself with NODUS_CLIENT_TEST_SEAM=1, which adds
 * the nodus_client_test_parse_* wrappers declared below (they decode bytes
 * and bypass nothing); libnodus is static, so its own nodus_client.o is
 * never pulled — see nodus/CMakeLists.txt.
 *
 * Requires: a default standalone nodus build; no environment.
 * Leaves behind: nothing.
 * How it can lie: the return-code and count checks would fail on the
 * pre-fix decoders (they returned 0 for every reply here); the
 * out-of-bounds write itself is only OBSERVED under ASan. Only the split
 * dnac_utxo decoder is exercised here — the others (delegations,
 * token_list, committee, roster) carry the same fix inline in their
 * request functions and have no seam; validator_list has its own test
 * (test_client_validator_list.c).
 */

#include "nodus/nodus.h"
#include "protocol/nodus_cbor.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TEST_CLIENT_DUP"

/* Defined in nodus_client.c under NODUS_CLIENT_TEST_SEAM. */
int nodus_client_test_parse_utxo(const uint8_t *raw, size_t raw_len,
                                 nodus_dnac_utxo_result_t *out);

static int passed = 0;
static int failed = 0;

#define CHECK(cond, name) do {                                          \
    if (cond) { passed++; }                                             \
    else { failed++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s (%s:%d): %s",      \
                                   (name), __FILE__, __LINE__, #cond); } \
} while (0)

static uint8_t g_frame[131072];

/* {t, y:"r", q:method, r:{ <r_count entries follow> }} */
static void reply_head(cbor_encoder_t *e, const char *method, size_t r_count) {
    cbor_encoder_init(e, g_frame, sizeof(g_frame));
    cbor_encode_map(e, 4);
    cbor_encode_cstr(e, "t"); cbor_encode_uint(e, 42);
    cbor_encode_cstr(e, "y"); cbor_encode_cstr(e, "r");
    cbor_encode_cstr(e, "q"); cbor_encode_cstr(e, method);
    cbor_encode_cstr(e, "r");
    cbor_encode_map(e, r_count);
}

/* ── dnac_utxo ───────────────────────────────────────────────────── */

static void enc_utxo_array(cbor_encoder_t *e, size_t n, uint64_t amount0) {
    uint8_t nul[NODUS_T3_NULLIFIER_LEN];
    uint8_t tid[64];
    memset(tid, 0xA1, sizeof(tid));
    cbor_encode_cstr(e, "utxos");
    cbor_encode_array(e, n);
    for (size_t i = 0; i < n; i++) {
        memset(nul, (int)(0x10 + i), sizeof(nul));
        /* every entry carries its "tid": the decoder refuses an entry
         * without one (C-11), exactly as the server always sends it */
        cbor_encode_map(e, 3);
        cbor_encode_cstr(e, "n");      cbor_encode_bstr(e, nul, sizeof(nul));
        cbor_encode_cstr(e, "amount"); cbor_encode_uint(e, amount0 + i);
        cbor_encode_cstr(e, "tid");    cbor_encode_bstr(e, tid, sizeof(tid));
    }
}

/* One "utxos" list of one entry {"amount": 5, <tid shape>}, wrapped as a
 * dnac_utxo reply. shape: 0 = no "tid", 1 = 63-byte "tid", 2 = "tid" twice
 * (64 bytes each), 3 = a good 64-byte "tid". */
static size_t craft_tid_reply(cbor_encoder_t *e, int shape) {
    uint8_t tid[64];
    memset(tid, 0xA1, sizeof(tid));
    reply_head(e, "dnac_utxo", 2);
    cbor_encode_cstr(e, "count"); cbor_encode_uint(e, 1);
    cbor_encode_cstr(e, "utxos");
    cbor_encode_array(e, 1);
    cbor_encode_map(e, shape == 0 ? 1 : shape == 2 ? 3 : 2);
    cbor_encode_cstr(e, "amount"); cbor_encode_uint(e, 5);
    if (shape == 1) {
        cbor_encode_cstr(e, "tid"); cbor_encode_bstr(e, tid, 63);
    } else if (shape >= 2) {
        cbor_encode_cstr(e, "tid"); cbor_encode_bstr(e, tid, 64);
        if (shape == 2) {
            cbor_encode_cstr(e, "tid"); cbor_encode_bstr(e, tid, 64);
        }
    }
    return cbor_encoder_len(e);
}

static void test_utxo(void) {
    cbor_encoder_t e;
    nodus_dnac_utxo_result_t res;

    /* well-formed: count, block_height, one "utxos" */
    reply_head(&e, "dnac_utxo", 3);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 2);
    cbor_encode_cstr(&e, "block_height"); cbor_encode_uint(&e, 77);
    enc_utxo_array(&e, 2, 1000);
    int rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 2 && res.entries &&
          res.entries[1].amount == 1001 && res.block_height == 77,
          "utxo: well-formed reply decodes");
    nodus_client_free_utxo_result(&res);

    /* repeated "utxos": 3 entries, then 1 — pre-fix wrote entries[3] of a
     * 1-slot allocation */
    reply_head(&e, "dnac_utxo", 3);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 3);
    enc_utxo_array(&e, 3, 1);
    enc_utxo_array(&e, 1, 9);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL && res.count == 0,
          "utxo: repeated \"utxos\" refused, result freed");
    nodus_client_free_utxo_result(&res);

    /* repeated scalar key refused too (no key may repeat) */
    reply_head(&e, "dnac_utxo", 2);
    cbor_encode_cstr(&e, "block_height"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "block_height"); cbor_encode_uint(&e, 2);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "utxo: repeated \"block_height\" refused");
    nodus_client_free_utxo_result(&res);

    /* C-11: the unfiltered decode is strict about the token id too. A
     * missing / 63-byte / repeated "tid" used to leave the id zero (= native)
     * or let the last one win; each is now a protocol error, result freed. */
    size_t n = craft_tid_reply(&e, 3);
    rc = nodus_client_test_parse_utxo(g_frame, n, &res);
    CHECK(rc == 0 && res.count == 1 && res.entries[0].token_id[0] == 0xA1 &&
          res.entries[0].token_id[63] == 0xA1,
          "utxo: an entry with one 64-byte tid decodes");
    nodus_client_free_utxo_result(&res);
    n = craft_tid_reply(&e, 0);
    rc = nodus_client_test_parse_utxo(g_frame, n, &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL && res.count == 0,
          "utxo: an entry without a tid is refused (no silent native)");
    nodus_client_free_utxo_result(&res);
    n = craft_tid_reply(&e, 1);
    rc = nodus_client_test_parse_utxo(g_frame, n, &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL && res.count == 0,
          "utxo: a 63-byte tid is refused");
    nodus_client_free_utxo_result(&res);
    n = craft_tid_reply(&e, 2);
    rc = nodus_client_test_parse_utxo(g_frame, n, &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL && res.count == 0,
          "utxo: a repeated tid inside an entry is refused");
    nodus_client_free_utxo_result(&res);

    /* no "r" map */
    cbor_encoder_init(&e, g_frame, sizeof(g_frame));
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 1);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "utxo: reply without \"r\" refused");
    nodus_client_free_utxo_result(&res);
}

int main(void) {
    QGP_LOG_INFO(LOG_TAG, "=== Nodus client DNAC decoder repeated-key tests ===");

    test_utxo();

    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===", passed, failed);
    return failed > 0 ? 1 : 0;
}
