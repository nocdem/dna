/**
 * Nodus — Tier 3: the channel-0x70 / 0x71 message bodies. Contract and
 * the retirement of the tier-3 envelope: nodus_tier3.h.
 *
 * The four encoders and decoders are the former verbs 24/25/40/41's `a`
 * codecs, unchanged byte for byte (the envelope that wrapped them —
 * {t, y, q, wh, a, wsig} and its 0x03 signature — is deleted, fleet
 * P2P-PORT phase F5).
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"

#include <string.h>
#include <stdlib.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Key comparison helper */
#define KEY_IS(k, s) \
    ((k).tstr.len == sizeof(s) - 1 && memcmp((k).tstr.ptr, (s), sizeof(s) - 1) == 0)

/* Both channel ceilings must fit one 4004 MConnection message; the
 * channel descriptors carry them as RecvMessageCapacity (int). */
_Static_assert((uint64_t)NODUS_T3_CC_APPR_MSG_MAX < (uint64_t)INT32_MAX,
               "0x71 message ceiling must fit a channel descriptor");
_Static_assert(NODUS_T3_CC_APPR_RSP_MAX + 256u <= NODUS_T3_CC_APPR_MSG_MAX,
               "0x71 response must fit the channel ceiling");

/* ══════════════════════════════════════════════════════════════════
 * ENCODE
 * ══════════════════════════════════════════════════════════════════ */

static int enc_finish(cbor_encoder_t *enc, size_t *out_len)
{
    if (enc->error) return -1;
    *out_len = cbor_encoder_len(enc);
    return *out_len > 0 ? 0 : -1;
}

int nodus_t3_gbundle_q_encode(const nodus_t3_w_v2_gbundle_q_t *m,
                              uint8_t *buf, size_t cap, size_t *out_len)
{
    cbor_encoder_t enc;

    if (!m || !buf || !out_len) return -1;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, m->chain, 32);
    cbor_encode_cstr(&enc, "p"); cbor_encode_bstr(&enc, m->pin, 32);
    cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, m->offset);
    return enc_finish(&enc, out_len);
}

int nodus_t3_gbundle_r_encode(const nodus_t3_w_v2_gbundle_r_t *m,
                              uint8_t *buf, size_t cap, size_t *out_len)
{
    cbor_encoder_t enc;

    if (!m || !buf || !out_len) return -1;
    /* The sender refuses an out-of-class chunk before emitting, so an
     * encoder never produces bytes its own decoder would reject. */
    if (m->chunk_len > NODUS_T3_V2_GBUNDLE_CHUNK_MAX ||
        (m->chunk_len > 0 && !m->chunk))
        return -1;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 5);
    cbor_encode_cstr(&enc, "c"); cbor_encode_bstr(&enc, m->chain, 32);
    cbor_encode_cstr(&enc, "p"); cbor_encode_bstr(&enc, m->pin, 32);
    cbor_encode_cstr(&enc, "t"); cbor_encode_uint(&enc, m->total);
    cbor_encode_cstr(&enc, "o"); cbor_encode_uint(&enc, m->offset);
    cbor_encode_cstr(&enc, "d"); cbor_encode_bstr(&enc, m->chunk, m->chunk_len);
    return enc_finish(&enc, out_len);
}

int nodus_t3_cc_appr_req_encode(const nodus_t3_cc_appr_req_t *m,
                                uint8_t *buf, size_t cap, size_t *out_len)
{
    cbor_encoder_t enc;

    if (!m || !buf || !out_len) return -1;
    if ((m->e == NULL && m->e_len != 0) ||
        m->e_len > (size_t)NODUS_T3_CC_APPR_E_MAX)
        return -1;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "e"); cbor_encode_bstr(&enc, m->e, m->e_len);
    return enc_finish(&enc, out_len);
}

int nodus_t3_cc_appr_rsp_encode(const nodus_t3_cc_appr_rsp_t *m,
                                uint8_t *buf, size_t cap, size_t *out_len)
{
    cbor_encoder_t enc;

    if (!m || !buf || !out_len) return -1;
    cbor_encoder_init(&enc, buf, cap);
    if (m->ok) {
        cbor_encode_map(&enc, 5);
        cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, true);
        cbor_encode_cstr(&enc, "i");  cbor_encode_uint(&enc, m->seat);
        cbor_encode_cstr(&enc, "s");  cbor_encode_bstr(&enc, m->sig, NODUS_SIG_BYTES);
        cbor_encode_cstr(&enc, "sh"); cbor_encode_bstr(&enc, m->set_hash, 64);
        cbor_encode_cstr(&enc, "ep"); cbor_encode_uint(&enc, m->epoch);
    } else {
        cbor_encode_map(&enc, 2);
        cbor_encode_cstr(&enc, "ok"); cbor_encode_bool(&enc, false);
        cbor_encode_cstr(&enc, "r");  cbor_encode_cstr(&enc, m->reason);
    }
    return enc_finish(&enc, out_len);
}

/* ══════════════════════════════════════════════════════════════════
 * DECODE
 * ══════════════════════════════════════════════════════════════════ */

static void dec_gbundle_q(cbor_decoder_t *dec, size_t count,
                          nodus_t3_w_v2_gbundle_q_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "p")) {
            /* D-24 rev 4 (1): the pin is EXACTLY the 32-byte chain id — a
             * wrong length here is a HARD DECODE ERROR, not a silently-
             * zeroed field: the pin is the whole of a joiner's trust
             * decision (nodus_witness_v2_join.c). */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != 32) {
                dec->error = true;
                return;
            }
            memcpy(m->pin, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "o")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->offset = val.uint_val;
        } else {
            cbor_decode_skip(dec);
        }
    }
}

static void dec_gbundle_r(cbor_decoder_t *dec, size_t count,
                          nodus_t3_w_v2_gbundle_r_t *m) {
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { cbor_decode_skip(dec); continue; }
        if (KEY_IS(key, "c")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR && val.bstr.len == 32)
                memcpy(m->chain, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "p")) {
            /* D-24 rev 4 (1) — a wrong-length pin is a hard decode error
             * here too (see dec_gbundle_q). */
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != 32) {
                dec->error = true;
                return;
            }
            memcpy(m->pin, val.bstr.ptr, 32);
        } else if (KEY_IS(key, "t")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->total = val.uint_val;
        } else if (KEY_IS(key, "o")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_UINT) m->offset = val.uint_val;
        } else if (KEY_IS(key, "d")) {
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type == CBOR_ITEM_BSTR) {
                if (val.bstr.len > NODUS_T3_V2_GBUNDLE_CHUNK_MAX) {
                    dec->error = true;
                    return;
                }
                m->chunk = val.bstr.ptr;
                m->chunk_len = (uint32_t)val.bstr.len;
            }
        } else {
            cbor_decode_skip(dec);
        }
    }
}

/* STRICT exact-key-set discipline (the W4-CC decoders): an unrecognized
 * key, a wrong-typed value, an oversize `e`, or a key the `ok` value does
 * not admit are all `dec->error = true`, never a silently-skipped field. */
static void dec_cc_appr_req(cbor_decoder_t *dec, size_t count,
                            nodus_t3_cc_appr_req_t *r) {
    bool seen_e = false;
    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "e")) {
            if (seen_e) { dec->error = true; return; }
            seen_e = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR ||
                val.bstr.len > (size_t)NODUS_T3_CC_APPR_E_MAX) {
                dec->error = true;
                return;
            }
            r->e     = val.bstr.ptr;
            r->e_len = val.bstr.len;
        } else {
            dec->error = true; return;
        }
    }
    if (!seen_e) dec->error = true;   /* the key was missing */
}

/* `ok` gates which OTHER keys are legal: ok=true admits exactly
 * {ok,i,s,sh,ep}; ok=false admits exactly {ok,r}. */
static void dec_cc_appr_rsp(cbor_decoder_t *dec, size_t count,
                            nodus_t3_cc_appr_rsp_t *r) {
    bool seen_ok = false, ok_val = false;
    bool seen_i = false, seen_s = false, seen_sh = false;
    bool seen_ep = false, seen_r = false;

    for (size_t i = 0; i < count; i++) {
        cbor_item_t key = cbor_decode_next(dec);
        if (key.type != CBOR_ITEM_TSTR) { dec->error = true; return; }
        if (KEY_IS(key, "ok")) {
            if (seen_ok) { dec->error = true; return; }
            seen_ok = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BOOL) { dec->error = true; return; }
            ok_val = val.bool_val;
            r->ok = ok_val;
        } else if (KEY_IS(key, "i")) {
            if (seen_i) { dec->error = true; return; }
            seen_i = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_UINT || val.uint_val > UINT16_MAX) {
                dec->error = true; return;
            }
            r->seat = (uint16_t)val.uint_val;
        } else if (KEY_IS(key, "s")) {
            if (seen_s) { dec->error = true; return; }
            seen_s = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != NODUS_SIG_BYTES) {
                dec->error = true; return;
            }
            memcpy(r->sig, val.bstr.ptr, NODUS_SIG_BYTES);
        } else if (KEY_IS(key, "sh")) {
            if (seen_sh) { dec->error = true; return; }
            seen_sh = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_BSTR || val.bstr.len != 64) {
                dec->error = true; return;
            }
            memcpy(r->set_hash, val.bstr.ptr, 64);
        } else if (KEY_IS(key, "ep")) {
            if (seen_ep) { dec->error = true; return; }
            seen_ep = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_UINT) { dec->error = true; return; }
            r->epoch = val.uint_val;
        } else if (KEY_IS(key, "r")) {
            if (seen_r) { dec->error = true; return; }
            seen_r = true;
            cbor_item_t val = cbor_decode_next(dec);
            if (val.type != CBOR_ITEM_TSTR ||
                val.tstr.len > sizeof(r->reason) - 1) {
                dec->error = true; return;
            }
            memcpy(r->reason, val.tstr.ptr, val.tstr.len);
            r->reason[val.tstr.len] = '\0';
        } else {
            dec->error = true; return;
        }
    }
    if (!seen_ok) { dec->error = true; return; }
    if (ok_val) {
        if (!seen_i || !seen_s || !seen_sh || !seen_ep || seen_r) {
            dec->error = true; return;
        }
    } else {
        if (!seen_r || seen_i || seen_s || seen_sh || seen_ep) {
            dec->error = true; return;
        }
    }
}

/* Pass 1 over ONE top-level map: keys must be text, no negative integer
 * anywhere (D-22 rev 3 — the envelope's `a` rule), nothing after the map.
 * Reports whether a key named `k1` or `k2` is present. */
static int scan_map(const uint8_t *buf, size_t len, const char *k1,
                    const char *k2, size_t *count, size_t *entries_start,
                    bool *has_key)
{
    cbor_decoder_t dec;
    bool negint = false;

    cbor_decoder_init(&dec, buf, len);
    cbor_item_t top = cbor_decode_next(&dec);
    if (dec.error || top.type != CBOR_ITEM_MAP) return -1;
    *count = top.count;
    *entries_start = dec.pos;
    *has_key = false;
    for (size_t i = 0; i < top.count; i++) {
        cbor_item_t key = cbor_decode_next(&dec);
        if (dec.error || key.type != CBOR_ITEM_TSTR) return -1;
        if ((k1 && key.tstr.len == strlen(k1) &&
             memcmp(key.tstr.ptr, k1, key.tstr.len) == 0) ||
            (k2 && key.tstr.len == strlen(k2) &&
             memcmp(key.tstr.ptr, k2, key.tstr.len) == 0))
            *has_key = true;
        cbor_decode_skip_signed(&dec, &negint);
        if (dec.error) return -1;
    }
    if (negint || dec.pos != len) return -1;
    return 0;
}

int nodus_t3_gbundle_decode(const uint8_t *buf, size_t len, nodus_t3_msg_t *out)
{
    cbor_decoder_t dec;
    size_t count = 0, start = 0;
    bool is_rsp = false;

    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (scan_map(buf, len, "t", "d", &count, &start, &is_rsp) != 0) return -1;
    cbor_decoder_init(&dec, buf, len);
    dec.pos = start;
    if (is_rsp) {
        out->type = NODUS_T3_V2_GBUNDLE_RSP;
        dec_gbundle_r(&dec, count, &out->w_v2_gbundle_r);
    } else {
        out->type = NODUS_T3_V2_GBUNDLE_REQ;
        dec_gbundle_q(&dec, count, &out->w_v2_gbundle_q);
    }
    if (dec.error) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}

int nodus_t3_cc_appr_decode(const uint8_t *buf, size_t len, nodus_t3_msg_t *out)
{
    cbor_decoder_t dec;
    size_t count = 0, start = 0;
    bool is_req = false;

    if (!buf || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (scan_map(buf, len, "e", NULL, &count, &start, &is_req) != 0) return -1;
    cbor_decoder_init(&dec, buf, len);
    dec.pos = start;
    if (is_req) {
        out->type = NODUS_T3_CC_APPR_REQ;
        dec_cc_appr_req(&dec, count, &out->cc_appr_req);
    } else {
        out->type = NODUS_T3_CC_APPR_RSP;
        dec_cc_appr_rsp(&dec, count, &out->cc_appr_rsp);
    }
    if (dec.error) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    return 0;
}
