/**
 * Nodus — client DNAC response decoders vs. repeated keys (P0-B, 2026-09-28)
 *
 * What it proves (a hostile or broken server cannot corrupt client memory):
 *   - dnac_utxo: a second "utxos" array is refused (NODUS_ERR_PROTOCOL_ERROR,
 *     result freed). Before the fix it re-calloc'd entries without resetting
 *     count and wrote at entries[count] — with a 3-entry first array and a
 *     1-entry second one that is a write 3 slots past a 1-slot allocation.
 *   - C-11: "count" is required: a reply with "utxos" and no "count" is
 *     refused (and the same list with its "count" decodes).
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
#include "protocol/nodus_tier2.h"
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

    /* C-11: "count" is required. A well-formed "utxos" list with NO "count"
     * (nothing to prove the list whole) is refused, result freed; the same
     * list with its "count" decodes (control). */
    reply_head(&e, "dnac_utxo", 1);
    enc_utxo_array(&e, 2, 500);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL && res.count == 0,
          "utxo: a reply with \"utxos\" and no \"count\" is refused");
    nodus_client_free_utxo_result(&res);
    reply_head(&e, "dnac_utxo", 2);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 2);
    enc_utxo_array(&e, 2, 500);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 2 && res.entries[0].amount == 500,
          "utxo: (control) the same list with its \"count\" decodes");
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

/* ── reply envelope (C-09, C-10) ─────────────────────────────────────
 *
 * Proves: the client reads the reply envelope only when the whole outer map
 * is well formed — every key text, "r" once, every declared pair present
 * with its whole value, nothing after the map. Each malformed shape below is
 * NODUS_ERR_PROTOCOL_ERROR (today the container-key, short and trailing-byte
 * shapes decode: the first returns the NESTED "r", the other two ignore the
 * damage). The controls (an honest reply; an unknown text key holding a
 * negative integer and nested data) still decode.
 * How it can falsely pass: the cases go through the split dnac_utxo decoder
 * (find_response_map is shared by every dnac_* decoder, only this one has a
 * byte-level seam); a frame the Tier-2 receive path would already drop never
 * reaches this decoder in production, so each case here is one that path
 * lets through. */

/* One entry {"amount": a, "tid": 64 bytes} as the node writes it. */
static void enc_one_entry_r(cbor_encoder_t *e, uint64_t amount) {
    uint8_t tid[64];
    memset(tid, 0xA1, sizeof(tid));
    cbor_encode_map(e, 2);
    cbor_encode_cstr(e, "count"); cbor_encode_uint(e, 1);
    cbor_encode_cstr(e, "utxos");
    cbor_encode_array(e, 1);
    cbor_encode_map(e, 2);
    cbor_encode_cstr(e, "amount"); cbor_encode_uint(e, amount);
    cbor_encode_cstr(e, "tid"); cbor_encode_bstr(e, tid, sizeof(tid));
}

static void enc_envelope_head(cbor_encoder_t *e, size_t pairs) {
    cbor_encoder_init(e, g_frame, sizeof(g_frame));
    cbor_encode_map(e, pairs);
    cbor_encode_cstr(e, "t"); cbor_encode_uint(e, 42);
    cbor_encode_cstr(e, "y"); cbor_encode_cstr(e, "r");
    cbor_encode_cstr(e, "q"); cbor_encode_cstr(e, "dnac_utxo");
}

static void test_envelope(void) {
    cbor_encoder_t e;
    nodus_dnac_utxo_result_t res;
    int rc;

    /* control: honest envelope */
    enc_envelope_head(&e, 4);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 700);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 1 && res.entries[0].amount == 700,
          "envelope: honest reply decodes");
    nodus_client_free_utxo_result(&res);

    /* control: an unknown TEXT key before "r" holding a negative integer and
     * nested data is stepped over whole and the real "r" is read */
    enc_envelope_head(&e, 5);
    cbor_encode_cstr(&e, "zz");
    cbor_encode_array(&e, 2);
    cbor_encode_int(&e, -7);
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "a"); cbor_encode_int(&e, -1);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 701);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 1 && res.entries[0].amount == 701,
          "envelope: unknown text key with negative/nested value is skipped whole");
    nodus_client_free_utxo_result(&res);

    /* C-09: {..., ["pad","r",R_A]: null, "r": R_B} — the old walk read the
     * array key as a header, then took its child "r" for the envelope's */
    enc_envelope_head(&e, 5);
    cbor_encode_array(&e, 3);
    cbor_encode_cstr(&e, "pad"); cbor_encode_cstr(&e, "r");
    enc_one_entry_r(&e, 111);                       /* R_A */
    cbor_encode_null(&e);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 222);   /* R_B */
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL,
          "envelope: a container key cannot shadow the real \"r\"");
    nodus_client_free_utxo_result(&res);

    /* a non-text key of another kind (uint) */
    enc_envelope_head(&e, 5);
    cbor_encode_uint(&e, 9); cbor_encode_null(&e);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 5);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "envelope: a non-text key is refused");
    nodus_client_free_utxo_result(&res);

    /* "r" twice */
    enc_envelope_head(&e, 5);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 1);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 2);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR, "envelope: a repeated \"r\" is refused");
    nodus_client_free_utxo_result(&res);

    /* C-10 (a): five pairs declared, four carried */
    enc_envelope_head(&e, 5);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 3);
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR,
          "envelope: fewer pairs than declared is refused");
    nodus_client_free_utxo_result(&res);

    /* C-10 (a): a byte after the outer map */
    enc_envelope_head(&e, 4);
    cbor_encode_cstr(&e, "r"); enc_one_entry_r(&e, 4);
    {
        size_t n = cbor_encoder_len(&e);
        g_frame[n] = 0x00;
        rc = nodus_client_test_parse_utxo(g_frame, n + 1, &res);
        CHECK(rc == NODUS_ERR_PROTOCOL_ERROR,
              "envelope: a trailing byte after the map is refused");
        nodus_client_free_utxo_result(&res);
    }

    /* a value cut short inside the last pair */
    enc_envelope_head(&e, 5);
    cbor_encode_cstr(&e, "zz");
    cbor_encode_array(&e, 3);                       /* three items declared ... */
    cbor_encode_uint(&e, 1);                        /* ... one present, no "r" */
    rc = nodus_client_test_parse_utxo(g_frame, cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR,
          "envelope: a value cut short is refused");
    nodus_client_free_utxo_result(&res);
}

/* ── EVM reply envelope and Tier-2 outer walk (C-09, C-10) ────────────
 *
 * Proves: evm_reply_map (the raw "r" map of nodus_client_dnac_query_raw)
 * walks the WHOLE envelope — a trailing byte, a container key that shadows
 * "r", a repeated "r", a non-map "r" and a missing "r" are all refused, an
 * honest reply and an unknown text key (also holding a nested value) before
 * or after "r" still return exactly the "r" bytes. nodus_t2_decode refuses a
 * non-text top-level key (a container key) and a map that declares more pairs
 * than it carries. Today evm_reply_map returns at the first "r" (trailing
 * byte / later repeat / shadowing container accepted) and nodus_t2_decode
 * accepts both Tier-2 shapes. How it can falsely pass: the frames are
 * hand-built; the Tier-2 trailing-byte case is NOT asserted there (the
 * shared decoder also parses requests; the client's response path rejects it
 * in client_on_frame, test_client_request_correlation.c). */
int nodus_client_test_evm_reply_map(const uint8_t *raw, size_t raw_len,
                                    uint8_t **out, size_t *out_len);

static void test_evm_and_t2_envelope(void) {
    cbor_encoder_t e;
    uint8_t *r = NULL;
    size_t rl = 0, n;
    nodus_tier2_msg_t msg;

    /* honest: {t, y, q, r:{a:1}} */
    enc_envelope_head(&e, 4);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "a"); cbor_encode_uint(&e, 1);
    n = cbor_encoder_len(&e);
    CHECK(nodus_client_test_evm_reply_map(g_frame, n, &r, &rl) == 0 && rl == 4 &&
          r[0] == 0xA1, "evm: honest reply returns the r map");
    free(r); r = NULL;

    /* unknown key with nested value AFTER r */
    enc_envelope_head(&e, 5);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    cbor_encode_cstr(&e, "zz"); cbor_encode_array(&e, 1); cbor_encode_uint(&e, 9);
    n = cbor_encoder_len(&e);
    CHECK(nodus_client_test_evm_reply_map(g_frame, n, &r, &rl) == 0 && rl == 1,
          "evm: unknown key after r is skipped whole");
    free(r); r = NULL;

    /* trailing byte */
    enc_envelope_head(&e, 4);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    n = cbor_encoder_len(&e);
    g_frame[n] = 0x00;
    CHECK(nodus_client_test_evm_reply_map(g_frame, n + 1, &r, &rl) != 0,
          "evm: a trailing byte is refused");

    /* repeated r */
    enc_envelope_head(&e, 5);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    CHECK(nodus_client_test_evm_reply_map(g_frame, cbor_encoder_len(&e), &r, &rl) != 0,
          "evm: a repeated r is refused");

    /* container key shadowing r: ["pad","r",{}] : null, r: {} */
    enc_envelope_head(&e, 5);
    cbor_encode_array(&e, 3);
    cbor_encode_cstr(&e, "pad"); cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    cbor_encode_null(&e);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    CHECK(nodus_client_test_evm_reply_map(g_frame, cbor_encoder_len(&e), &r, &rl) != 0,
          "evm: a container key cannot shadow r");

    /* r not a map; no r at all */
    enc_envelope_head(&e, 4);
    cbor_encode_cstr(&e, "r"); cbor_encode_uint(&e, 1);
    CHECK(nodus_client_test_evm_reply_map(g_frame, cbor_encoder_len(&e), &r, &rl) != 0,
          "evm: r that is not a map is refused");
    enc_envelope_head(&e, 3);
    CHECK(nodus_client_test_evm_reply_map(g_frame, cbor_encoder_len(&e), &r, &rl) != 0,
          "evm: no r is refused");

    /* Tier-2: honest, container key, short map */
    enc_envelope_head(&e, 4);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    memset(&msg, 0, sizeof(msg));
    CHECK(nodus_t2_decode(g_frame, cbor_encoder_len(&e), &msg) == 0 &&
          msg.txn_id == 42, "t2: honest frame decodes");
    nodus_t2_msg_free(&msg);

    enc_envelope_head(&e, 5);
    cbor_encode_array(&e, 3);
    cbor_encode_cstr(&e, "pad"); cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    cbor_encode_null(&e);
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    memset(&msg, 0, sizeof(msg));
    CHECK(nodus_t2_decode(g_frame, cbor_encoder_len(&e), &msg) != 0,
          "t2: a container key is refused");
    nodus_t2_msg_free(&msg);

    enc_envelope_head(&e, 5);                 /* five pairs declared, four carried */
    cbor_encode_cstr(&e, "r"); cbor_encode_map(&e, 0);
    memset(&msg, 0, sizeof(msg));
    CHECK(nodus_t2_decode(g_frame, cbor_encoder_len(&e), &msg) != 0,
          "t2: a missing declared pair is refused");
    nodus_t2_msg_free(&msg);
}

int main(void) {
    QGP_LOG_INFO(LOG_TAG, "=== Nodus client DNAC decoder repeated-key tests ===");

    test_utxo();
    test_envelope();
    test_evm_and_t2_envelope();

    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===", passed, failed);
    return failed > 0 ? 1 : 0;
}
