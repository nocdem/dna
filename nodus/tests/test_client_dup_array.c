/**
 * Nodus — client DNAC response decoders vs. repeated keys (P0-B, 2026-09-28)
 *
 * What it proves (a hostile or broken server cannot corrupt client memory):
 *   - dnac_utxo: a second "utxos" array is refused (NODUS_ERR_PROTOCOL_ERROR,
 *     result freed). Before the fix it re-calloc'd entries without resetting
 *     count and wrote at entries[count] — with a 3-entry first array and a
 *     1-entry second one that is a write 3 slots past a 1-slot allocation.
 *   - dnac_ledger_range: a "count" AFTER "entries" no longer overrides the
 *     decoded count (it is informational); result.count is the number of
 *     entries decoded. A repeated "entries" is refused.
 *   - dnac_block: a second "commit_cert" is refused. Before the fix
 *     commit_cert_count carried over from the first array and a shorter
 *     second array was written past its end.
 *   - Well-formed replies of the shape the node's handlers write
 *     (nodus_witness_handlers.c) still decode with the expected counts.
 *
 * Seam: the three decoders are static in nodus_client.c. This target
 * compiles nodus_client.c itself with NODUS_CLIENT_TEST_SEAM=1, which adds
 * the nodus_client_test_parse_* wrappers declared below (they decode bytes
 * and bypass nothing); libnodus is static, so its own nodus_client.o is
 * never pulled — see nodus/CMakeLists.txt.
 *
 * Requires: a default standalone nodus build; no environment.
 * Leaves behind: nothing.
 * How it can lie: the return-code and count checks would fail on the
 * pre-fix decoders (they returned 0 for every reply here); the
 * out-of-bounds write itself is only OBSERVED under ASan. Only the three
 * split decoders are exercised — the others (history, delegations,
 * block_range, token_list, committee, validator_list, roster, tx, genesis)
 * carry the same fix inline in their request functions and have no seam.
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
int nodus_client_test_parse_ledger_range(const uint8_t *raw, size_t raw_len,
                                         nodus_dnac_range_result_t *out);
int nodus_client_test_parse_block(const uint8_t *raw, size_t raw_len,
                                  nodus_dnac_block_result_t *out);

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
    cbor_encode_cstr(e, "utxos");
    cbor_encode_array(e, n);
    for (size_t i = 0; i < n; i++) {
        memset(nul, (int)(0x10 + i), sizeof(nul));
        cbor_encode_map(e, 2);
        cbor_encode_cstr(e, "n");      cbor_encode_bstr(e, nul, sizeof(nul));
        cbor_encode_cstr(e, "amount"); cbor_encode_uint(e, amount0 + i);
    }
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

    /* no "r" map */
    cbor_encoder_init(&e, g_frame, sizeof(g_frame));
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "t"); cbor_encode_uint(&e, 1);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "utxo: reply without \"r\" refused");
    nodus_client_free_utxo_result(&res);
}

/* ── dnac_ledger_range ───────────────────────────────────────────── */

static void enc_range_entries(cbor_encoder_t *e, size_t n) {
    cbor_encode_cstr(e, "entries");
    cbor_encode_array(e, n);
    for (size_t i = 0; i < n; i++) {
        cbor_encode_map(e, 2);
        cbor_encode_cstr(e, "seq");   cbor_encode_uint(e, 100 + i);
        cbor_encode_cstr(e, "epoch"); cbor_encode_uint(e, 5);
    }
}

static void test_ledger_range(void) {
    cbor_encoder_t e;
    nodus_dnac_range_result_t res;

    /* the node's order: total, count, entries */
    reply_head(&e, "dnac_ledger_range", 3);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 9);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 2);
    enc_range_entries(&e, 2);
    int rc = nodus_client_test_parse_ledger_range(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 2 && res.total_entries == 9 &&
          res.entries && res.entries[1].sequence == 101,
          "ledger_range: well-formed reply decodes");
    nodus_client_free_range_result(&res);

    /* "count" AFTER "entries" claiming 1000 — pre-fix result.count = 1000
     * over a 1-entry array */
    reply_head(&e, "dnac_ledger_range", 2);
    enc_range_entries(&e, 1);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 1000);
    rc = nodus_client_test_parse_ledger_range(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 1 && res.entries,
          "ledger_range: \"count\" cannot exceed the decoded length");
    nodus_client_free_range_result(&res);

    /* repeated "entries" */
    reply_head(&e, "dnac_ledger_range", 2);
    enc_range_entries(&e, 3);
    enc_range_entries(&e, 1);
    rc = nodus_client_test_parse_ledger_range(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL && res.count == 0,
          "ledger_range: repeated \"entries\" refused, result freed");
    nodus_client_free_range_result(&res);
}

/* ── dnac_block (commit_cert) ────────────────────────────────────── */

static void enc_commit_cert(cbor_encoder_t *e, size_t n) {
    static uint8_t sig[NODUS_SIG_BYTES];
    uint8_t signer[NODUS_T3_WITNESS_ID_LEN];
    cbor_encode_cstr(e, "commit_cert");
    cbor_encode_array(e, n);
    for (size_t i = 0; i < n; i++) {
        memset(signer, (int)(0x40 + i), sizeof(signer));
        memset(sig, (int)(0x60 + i), sizeof(sig));
        cbor_encode_map(e, 2);
        cbor_encode_cstr(e, "signer_id"); cbor_encode_bstr(e, signer, sizeof(signer));
        cbor_encode_cstr(e, "sig");       cbor_encode_bstr(e, sig, sizeof(sig));
    }
}

static void test_block(void) {
    cbor_encoder_t e;
    nodus_dnac_block_result_t res;

    reply_head(&e, "dnac_block", 3);
    cbor_encode_cstr(&e, "found");  cbor_encode_bool(&e, true);
    cbor_encode_cstr(&e, "height"); cbor_encode_uint(&e, 12);
    enc_commit_cert(&e, 2);
    int rc = nodus_client_test_parse_block(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.found && res.height == 12 &&
          res.commit_cert_count == 2 && res.commit_cert &&
          res.commit_cert[1].signer_id[0] == 0x41,
          "block: well-formed reply decodes");
    nodus_client_free_block_result(&res);

    /* 3 signatures, then 1 — pre-fix wrote commit_cert[3] of a 1-slot
     * allocation (count not reset) */
    reply_head(&e, "dnac_block", 3);
    cbor_encode_cstr(&e, "found"); cbor_encode_bool(&e, true);
    enc_commit_cert(&e, 3);
    enc_commit_cert(&e, 1);
    rc = nodus_client_test_parse_block(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.commit_cert == NULL &&
          res.commit_cert_count == 0,
          "block: repeated \"commit_cert\" refused, result freed");
    nodus_client_free_block_result(&res);
}

int main(void) {
    QGP_LOG_INFO(LOG_TAG, "=== Nodus client DNAC decoder repeated-key tests ===");

    test_utxo();
    test_ledger_range();
    test_block();

    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===", passed, failed);
    return failed > 0 ? 1 : 0;
}
