/**
 * Nodus — client dnac_validator_list_query decoder: the per-entry
 * delegator count ("dlg")
 *
 * What it proves:
 *   - A reply whose entries carry "dlg" decodes has_delegator_count = 1
 *     and the exact delegator_count per entry (incl. 0 — a validator with
 *     no delegators is a known 0, not "unknown") next to every existing
 *     field.
 *   - A reply WITHOUT "dlg" (the shape a node older than the key
 *     answers, nodus_witness_handlers.c handle_dnac_validator_list_query
 *     before the key) still decodes, with has_delegator_count = 0 —
 *     "unknown", distinct from a known 0.
 *   - A "dlg" that is not a uint, exceeds UINT32_MAX, or is repeated in
 *     one entry refuses the whole reply (NODUS_ERR_PROTOCOL_ERROR, result
 *     freed) — a malformed count is never shown.
 *   - An entry key the decoder does not know is skipped (the rule that
 *     lets an OLD client read a NEW node's reply), and a repeated
 *     top-level key is still refused (P0-B).
 *   - HF-6 slice 7a: entries carrying "vid" and "owner" (bstr(64) each,
 *     the generation-4 shape) decode has_v2 = 1 with the exact
 *     validator_id / owner_fp bytes and every other field unchanged; an
 *     entry without them (older node) decodes has_v2 = 0 with both
 *     fields zero; a 63- or 65-byte "vid", a text-string "owner", a
 *     repeated "vid" and a "vid" without "owner" each refuse the whole
 *     reply (NODUS_ERR_PROTOCOL_ERROR, result freed).
 *
 * Seam: the decoder is static in nodus_client.c. This target compiles
 * nodus_client.c itself with NODUS_CLIENT_TEST_SEAM=1, which adds
 * nodus_client_test_parse_validator_list (declared below; it decodes
 * bytes and bypasses nothing); libnodus is static, so its own
 * nodus_client.o is never pulled — the test_client_dup_array arrangement
 * (nodus/CMakeLists.txt).
 *
 * Requires: a default standalone nodus build; no environment.
 * Leaves behind: nothing.
 * How it can lie:
 *   - The replies are hand-built in the shape the handler encodes; the
 *     handler's own encoder (static, it only sends) is NOT driven here.
 *     The count SOURCE is pinned separately by
 *     tests/test_validator_list_query_rpc.c (scenario 6).
 *   - "An old client skips the unknown key" is shown with THIS decoder's
 *     generic skip branch (an entry key "zzz"); the pre-change binary is
 *     not run.
 *   - The "vid" / "owner" entries are hand-built in the order
 *     handle_dnac_validator_list_query writes them under generation 4;
 *     a real generation-4 node's reply is not decoded here.
 *   - Nothing here was RUN by its author (BUILDER: compile only).
 */

#include "nodus/nodus.h"
#include "protocol/nodus_cbor.h"
#include "crypto/utils/qgp_log.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TEST_CLIENT_VLIST"

/* Defined in nodus_client.c under NODUS_CLIENT_TEST_SEAM. */
int nodus_client_test_parse_validator_list(const uint8_t *raw, size_t raw_len,
                                           nodus_dnac_validator_list_result_t *out);

static int passed = 0;
static int failed = 0;

#define CHECK(cond, name) do {                                          \
    if (cond) { passed++; }                                             \
    else { failed++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s (%s:%d): %s",      \
                                   (name), __FILE__, __LINE__, #cond); } \
} while (0)

static uint8_t g_frame[65536];

/* {t, y:"r", q:method, r:{ <r_count entries follow> }} */
static void reply_head(cbor_encoder_t *e, size_t r_count) {
    cbor_encoder_init(e, g_frame, sizeof(g_frame));
    cbor_encode_map(e, 4);
    cbor_encode_cstr(e, "t"); cbor_encode_uint(e, 42);
    cbor_encode_cstr(e, "y"); cbor_encode_cstr(e, "r");
    cbor_encode_cstr(e, "q"); cbor_encode_cstr(e, "dnac_validator_list_query");
    cbor_encode_cstr(e, "r");
    cbor_encode_map(e, r_count);
}

/* "dlg" handling per entry */
enum { DLG_NONE, DLG_UINT, DLG_TSTR, DLG_TWICE, DLG_EXTRA_KEY };

/* One entry in the handler's shape (7 keys, + "dlg" / an unknown key). */
static void enc_entry(cbor_encoder_t *e, uint8_t pk_fill, uint64_t self,
                      int dlg_mode, uint64_t dlg) {
    uint8_t pk[NODUS_PK_BYTES];
    memset(pk, pk_fill, sizeof(pk));
    size_t n = 7;
    if (dlg_mode == DLG_UINT || dlg_mode == DLG_TSTR ||
        dlg_mode == DLG_EXTRA_KEY) n = 8;
    if (dlg_mode == DLG_TWICE) n = 9;
    cbor_encode_map(e, n);
    cbor_encode_cstr(e, "pk");     cbor_encode_bstr(e, pk, sizeof(pk));
    cbor_encode_cstr(e, "self");   cbor_encode_uint(e, self);
    cbor_encode_cstr(e, "total");  cbor_encode_uint(e, 500);
    cbor_encode_cstr(e, "ext");    cbor_encode_uint(e, 400);
    cbor_encode_cstr(e, "comm");   cbor_encode_uint(e, 1000);
    cbor_encode_cstr(e, "status"); cbor_encode_uint(e, 0);
    cbor_encode_cstr(e, "since");  cbor_encode_uint(e, 7);
    if (dlg_mode == DLG_UINT) {
        cbor_encode_cstr(e, "dlg"); cbor_encode_uint(e, dlg);
    } else if (dlg_mode == DLG_TSTR) {
        cbor_encode_cstr(e, "dlg"); cbor_encode_cstr(e, "37");
    } else if (dlg_mode == DLG_TWICE) {
        cbor_encode_cstr(e, "dlg"); cbor_encode_uint(e, dlg);
        cbor_encode_cstr(e, "dlg"); cbor_encode_uint(e, dlg);
    } else if (dlg_mode == DLG_EXTRA_KEY) {
        cbor_encode_cstr(e, "zzz"); cbor_encode_uint(e, 99);
    }
}

static void test_with_key(void) {
    cbor_encoder_t e;
    nodus_dnac_validator_list_result_t res;

    reply_head(&e, 3);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 3);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 3);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 3);
    enc_entry(&e, 0x11, 1000, DLG_UINT, 37);
    enc_entry(&e, 0x22, 2000, DLG_UINT, 0);
    enc_entry(&e, 0x33, 3000, DLG_UINT, 2048);
    int rc = nodus_client_test_parse_validator_list(g_frame,
                                                    cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 3 && res.total == 3 && res.entries,
          "with dlg: reply decodes");
    if (rc == 0 && res.count == 3 && res.entries) {
        CHECK(res.entries[0].has_delegator_count == 1 &&
              res.entries[0].delegator_count == 37,
              "with dlg: entry 0 = 37 known");
        CHECK(res.entries[1].has_delegator_count == 1 &&
              res.entries[1].delegator_count == 0,
              "with dlg: entry 1 = known 0 (not unknown)");
        CHECK(res.entries[2].has_delegator_count == 1 &&
              res.entries[2].delegator_count == 2048,
              "with dlg: entry 2 = 2048 (a full validator)");
        CHECK(res.entries[0].pubkey[0] == 0x11 &&
              res.entries[0].self_stake == 1000 &&
              res.entries[0].total_delegated == 500 &&
              res.entries[0].external_delegated == 400 &&
              res.entries[0].commission_bps == 1000 &&
              res.entries[0].active_since_block == 7,
              "with dlg: the existing fields are unchanged");
    }
    nodus_client_free_validator_list_result(&res);
}

static void test_without_key(void) {
    cbor_encoder_t e;
    nodus_dnac_validator_list_result_t res;

    reply_head(&e, 3);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 2);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 2);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 2);
    enc_entry(&e, 0x11, 1000, DLG_NONE, 0);
    enc_entry(&e, 0x22, 2000, DLG_NONE, 0);
    int rc = nodus_client_test_parse_validator_list(g_frame,
                                                    cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 2 && res.entries,
          "without dlg (older node): reply decodes");
    if (rc == 0 && res.count == 2 && res.entries) {
        CHECK(res.entries[0].has_delegator_count == 0 &&
              res.entries[1].has_delegator_count == 0,
              "without dlg: count is UNKNOWN, not 0");
        CHECK(res.entries[1].self_stake == 2000,
              "without dlg: the existing fields decode");
    }
    nodus_client_free_validator_list_result(&res);
}

static void test_unknown_entry_key_skipped(void) {
    cbor_encoder_t e;
    nodus_dnac_validator_list_result_t res;

    reply_head(&e, 2);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 1);
    enc_entry(&e, 0x44, 4000, DLG_EXTRA_KEY, 0);
    int rc = nodus_client_test_parse_validator_list(g_frame,
                                                    cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 1 && res.entries &&
          res.entries[0].self_stake == 4000 &&
          res.entries[0].has_delegator_count == 0,
          "an unknown entry key is skipped (old-client rule)");
    nodus_client_free_validator_list_result(&res);
}

static void refused(int dlg_mode, uint64_t dlg, const char *name) {
    cbor_encoder_t e;
    nodus_dnac_validator_list_result_t res;

    reply_head(&e, 2);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 2);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 2);
    enc_entry(&e, 0x11, 1000, DLG_UINT, 5);
    enc_entry(&e, 0x22, 2000, dlg_mode, dlg);
    int rc = nodus_client_test_parse_validator_list(g_frame,
                                                    cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL &&
          res.count == 0, name);
    nodus_client_free_validator_list_result(&res);
}

/* HF-6 slice 7a — the generation-4 entry keys "vid" / "owner" (bstr(64)
 * each, handle_dnac_validator_list_query under generation 4, written
 * BEFORE "pk" as the handler writes them). */
enum { V2_BOTH, V2_VID_ONLY, V2_VID_63, V2_VID_65, V2_OWNER_TSTR,
       V2_VID_TWICE };

static void enc_entry_v2(cbor_encoder_t *e, uint8_t pk_fill, uint64_t self,
                         int mode) {
    uint8_t pk[NODUS_PK_BYTES], vid[65], own[64];
    memset(pk, pk_fill, sizeof(pk));
    memset(vid, pk_fill ^ 0x5a, sizeof(vid));
    memset(own, pk_fill ^ 0xa5, sizeof(own));
    size_t n = 8 + 1;                    /* 7 + "dlg" + "vid"            */
    if (mode != V2_VID_ONLY) n++;        /* + "owner"                    */
    if (mode == V2_VID_TWICE) n++;       /* + a second "vid"             */
    cbor_encode_map(e, n);
    cbor_encode_cstr(e, "vid");
    cbor_encode_bstr(e, vid, mode == V2_VID_63 ? 63 :
                             mode == V2_VID_65 ? 65 : 64);
    if (mode == V2_VID_TWICE) {
        cbor_encode_cstr(e, "vid"); cbor_encode_bstr(e, vid, 64);
    }
    if (mode == V2_OWNER_TSTR) {
        cbor_encode_cstr(e, "owner"); cbor_encode_cstr(e, "a5a5");
    } else if (mode != V2_VID_ONLY) {
        cbor_encode_cstr(e, "owner"); cbor_encode_bstr(e, own, 64);
    }
    cbor_encode_cstr(e, "pk");     cbor_encode_bstr(e, pk, sizeof(pk));
    cbor_encode_cstr(e, "self");   cbor_encode_uint(e, self);
    cbor_encode_cstr(e, "total");  cbor_encode_uint(e, 500);
    cbor_encode_cstr(e, "ext");    cbor_encode_uint(e, 400);
    cbor_encode_cstr(e, "comm");   cbor_encode_uint(e, 1000);
    cbor_encode_cstr(e, "status"); cbor_encode_uint(e, 0);
    cbor_encode_cstr(e, "since");  cbor_encode_uint(e, 7);
    cbor_encode_cstr(e, "dlg");    cbor_encode_uint(e, 3);
}

static void test_v2_keys(void) {
    cbor_encoder_t e;
    nodus_dnac_validator_list_result_t res;

    /* a generation-4 reply: every entry carries both keys */
    reply_head(&e, 3);
    cbor_encode_cstr(&e, "count"); cbor_encode_uint(&e, 2);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 2);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 2);
    enc_entry_v2(&e, 0x11, 1000, V2_BOTH);
    enc_entry_v2(&e, 0x22, 2000, V2_BOTH);
    int rc = nodus_client_test_parse_validator_list(g_frame,
                                                    cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 2 && res.entries,
          "with vid/owner: reply decodes");
    if (rc == 0 && res.count == 2 && res.entries) {
        uint8_t vid[64], own[64];
        memset(vid, 0x11 ^ 0x5a, sizeof(vid));
        memset(own, 0x11 ^ 0xa5, sizeof(own));
        CHECK(res.entries[0].has_v2 == 1 &&
              memcmp(res.entries[0].validator_id, vid, 64) == 0 &&
              memcmp(res.entries[0].owner_fp, own, 64) == 0,
              "with vid/owner: entry 0 validator_id and owner_fp exact");
        memset(vid, 0x22 ^ 0x5a, sizeof(vid));
        memset(own, 0x22 ^ 0xa5, sizeof(own));
        CHECK(res.entries[1].has_v2 == 1 &&
              memcmp(res.entries[1].validator_id, vid, 64) == 0 &&
              memcmp(res.entries[1].owner_fp, own, 64) == 0,
              "with vid/owner: entry 1 validator_id and owner_fp exact");
        CHECK(res.entries[0].pubkey[0] == 0x11 &&
              res.entries[0].self_stake == 1000 &&
              res.entries[0].has_delegator_count == 1 &&
              res.entries[0].delegator_count == 3,
              "with vid/owner: pk (the consensus key) and the other "
              "fields unchanged");
    }
    nodus_client_free_validator_list_result(&res);

    /* an older node: neither key → has_v2 0, both fields zero */
    reply_head(&e, 2);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 1);
    enc_entry(&e, 0x33, 3000, DLG_UINT, 1);
    rc = nodus_client_test_parse_validator_list(g_frame,
                                                cbor_encoder_len(&e), &res);
    CHECK(rc == 0 && res.count == 1 && res.entries,
          "without vid/owner (older node): reply decodes");
    if (rc == 0 && res.count == 1 && res.entries) {
        uint8_t zero[64];
        memset(zero, 0, sizeof(zero));
        CHECK(res.entries[0].has_v2 == 0 &&
              memcmp(res.entries[0].validator_id, zero, 64) == 0 &&
              memcmp(res.entries[0].owner_fp, zero, 64) == 0,
              "without vid/owner: has_v2 0, both fields zero");
    }
    nodus_client_free_validator_list_result(&res);
}

static void refused_v2(int mode, const char *name) {
    cbor_encoder_t e;
    nodus_dnac_validator_list_result_t res;

    reply_head(&e, 2);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 2);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 2);
    enc_entry_v2(&e, 0x11, 1000, V2_BOTH);
    enc_entry_v2(&e, 0x22, 2000, mode);
    int rc = nodus_client_test_parse_validator_list(g_frame,
                                                    cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL &&
          res.count == 0, name);
    nodus_client_free_validator_list_result(&res);
}

static void test_v2_refusals(void) {
    refused_v2(V2_VID_63, "vid of 63 bytes refused, result freed");
    refused_v2(V2_VID_65, "vid of 65 bytes refused, result freed");
    refused_v2(V2_OWNER_TSTR, "owner as a text string refused, result freed");
    refused_v2(V2_VID_TWICE, "vid repeated in one entry refused, result freed");
    refused_v2(V2_VID_ONLY, "vid without owner refused, result freed");
}

static void test_refusals(void) {
    refused(DLG_TSTR, 0, "dlg as a text string refused, result freed");
    refused(DLG_TWICE, 3, "dlg repeated in one entry refused, result freed");
    refused(DLG_UINT, (uint64_t)UINT32_MAX + 1,
            "dlg above UINT32_MAX refused, result freed");

    /* A repeated top-level key is still refused (P0-B). */
    cbor_encoder_t e;
    nodus_dnac_validator_list_result_t res;
    reply_head(&e, 3);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 1);
    enc_entry(&e, 0x11, 1000, DLG_UINT, 1);
    cbor_encode_cstr(&e, "total"); cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "validators");
    cbor_encode_array(&e, 1);
    enc_entry(&e, 0x22, 2000, DLG_UINT, 2);
    int rc = nodus_client_test_parse_validator_list(g_frame,
                                                    cbor_encoder_len(&e), &res);
    CHECK(rc == NODUS_ERR_PROTOCOL_ERROR && res.entries == NULL &&
          res.count == 0,
          "repeated \"validators\" refused, result freed");
    nodus_client_free_validator_list_result(&res);
}

int main(void) {
    QGP_LOG_INFO(LOG_TAG, "=== Nodus client validator_list decoder: delegator count ===");

    test_with_key();
    test_without_key();
    test_unknown_entry_key_skipped();
    test_refusals();
    test_v2_keys();
    test_v2_refusals();

    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===", passed, failed);
    return failed > 0 ? 1 : 0;
}
