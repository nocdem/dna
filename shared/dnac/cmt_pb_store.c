/**
 * @file shared/dnac/cmt_pb_store.c
 * @brief cometbft @709fd12b — proto3 codecs of the STORED values and the
 *        Block wire decoder. Contract and every file:line: cmt_pb_store.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_pb_store.h"
#include "dnac/cmt_pb_wire.h"   /* pb_w_t and the shared wire primitives */

#include <string.h>

#include "dnac/cmt_validator_set.h"

/* The writer and reader primitives come from cmt_pb_wire.h — ONE
 * definition for every cmt_pb* codec (merged at O7 from this file's own
 * QUESTION; R3-B had to copy them because cmt_pb.{h,c} were outside its
 * whitelist). */

/* ═══════════════════════════════════════════════════════════════════════
 * Embedding a cmt_pb message through its PUBLIC marshal.
 *
 * The generated code marshals a nested message in place, backwards. The
 * public `cmt_pb_X_marshal` writes into the FRONT of the buffer it is
 * given. So: marshal into the free region [0, w->i), then move the
 * result up to [w->i - n, w->i) and frame it. Two moves where the
 * generated code makes none; the bytes are identical.
 * ═══════════════════════════════════════════════════════════════════════ */

#define W_EMBED_DEFINE(name, type, fn)                                      \
    static void name(pb_w_t *w, uint32_t field, const type *m)              \
    {                                                                       \
        size_t n = 0;                                                       \
        if (w->err != CMT_OK) {                                             \
            return;                                                         \
        }                                                                   \
        if (fn(m, w->buf, w->i, &n) != CMT_OK) {                            \
            w->err = CMT_REJECT;                                            \
            return;                                                         \
        }                                                                   \
        if (n != 0) {                                                       \
            memmove(w->buf + w->i - n, w->buf, n);                          \
        }                                                                   \
        w->i -= n;                                                          \
        w_uvarint(w, (uint64_t)n);                                          \
        w_tag(w, field, 2);                                                 \
    }

W_EMBED_DEFINE(w_embed_block_id,      cmt_pb_block_id_t,      cmt_pb_block_id_marshal)
W_EMBED_DEFINE(w_embed_header,        cmt_pb_header_t,        cmt_pb_header_marshal)
W_EMBED_DEFINE(w_embed_consensus,     cmt_pb_consensus_t,     cmt_pb_consensus_marshal)
W_EMBED_DEFINE(w_embed_validator_set, cmt_pb_validator_set_t, cmt_pb_validator_set_marshal)
W_EMBED_DEFINE(w_embed_public_key,    cmt_pb_public_key_t,    cmt_pb_public_key_marshal)
W_EMBED_DEFINE(w_embed_timestamp,     cmt_time_t,             cmt_pb_timestamp_marshal)

/* `(gogoproto.stdduration) = true` — StdDurationMarshalTo. */
static void w_embed_std_duration(pb_w_t *w, uint32_t field, int64_t d_ns)
{
    size_t n = 0;

    if (w->err != CMT_OK) {
        return;
    }
    if (cmt_pb_std_duration_marshal(d_ns, w->buf, w->i, &n) != CMT_OK) {
        w->err = CMT_REJECT;
        return;
    }
    if (n != 0) {
        memmove(w->buf + w->i - n, w->buf, n);
    }
    w->i -= n;
    w_uvarint(w, (uint64_t)n);
    w_tag(w, field, 2);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Size bounds. Each is the K-1 worst case of the message's fields; the
 * embedded cmt_pb messages are bounded from their fixed capacities.
 * ═══════════════════════════════════════════════════════════════════════ */

#define B_VARINT      11u                       /* tag + 10-byte varint     */
#define B_HASH        (2u + CMT_PB_HASH_MAX)    /* tag + len + 64           */
#define B_PSH         (2u + 6u + B_HASH)        /* PartSetHeader body+frame */
#define B_BLOCK_ID    (3u + B_HASH + B_PSH)     /* BlockID framed           */
#define B_HEADER      (3u + (size_t)CMT_MAX_HEADER_BYTES)
#define B_CONSENSUS   (2u + 2u * B_VARINT)
#define B_SOFTWARE    (2u + CMT_PB_STORE_SOFTWARE_MAX)
#define B_VERSION     (3u + B_CONSENSUS + B_SOFTWARE)
#define B_PUBKEY      (3u + 3u + CMT_PB_PUBKEY_LEN)
#define B_VALIDATOR   (3u + (2u + CMT_PB_ADDRESS_MAX) + B_PUBKEY + 2u * B_VARINT)
#define B_TIMESTAMP   (2u + 2u * B_VARINT)
#define B_DURATION    (2u + 2u * B_VARINT)
#define B_BLOCK_P     (3u + 2u * B_VARINT)
#define B_EVIDENCE_P  (3u + 2u * B_VARINT + B_DURATION)
#define B_VALIDATOR_P (3u + (size_t)CMT_PARAMS_MAX_PUBKEY_TYPES * \
                       (2u + (size_t)CMT_PARAMS_PUBKEY_TYPE_MAX))
#define B_VERSION_P   (3u + B_VARINT)
#define B_ABCI_P      (3u + B_VARINT)
#define B_CONSENSUS_PARAMS \
    (B_BLOCK_P + B_EVIDENCE_P + B_VALIDATOR_P + B_VERSION_P + B_ABCI_P)

static size_t bound_validator_set(size_t n)
{
    /* n members + the proposer, each framed, + total_voting_power, +
     * the set's own frame (a length of up to 5 bytes for this size). */
    return 6u + (n + 1u) * B_VALIDATOR + B_VARINT;
}

/* ═══════════════════════════════════════════════════════════════════════
 * BlockStoreState — store/types.pb.go:113-131
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_block_store_state_init(cmt_pb_block_store_state_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

size_t cmt_pb_store_block_store_state_upper_bound(void)
{
    return 2u * B_VARINT;
}

int cmt_pb_store_block_store_state_marshal(const cmt_pb_block_store_state_t *m,
                                           uint8_t *out, size_t cap,
                                           size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 2, (uint64_t)m->height);     /* :118-122 */
    wf_varint(&w, 1, (uint64_t)m->base);       /* :123-127 */
    return w_finish(&w, out_len);
}

/* store/types.pb.go — BlockStoreState.Unmarshal: two varint fields. */
int cmt_pb_store_block_store_state_unmarshal(const uint8_t *in, size_t len,
                                             cmt_pb_block_store_state_t *m)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_block_store_state_init(m);
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
        case 2:
            if (wt != 0u) {
                return CMT_REJECT;
            }
            if (cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                m->base = (int64_t)v;
            } else {
                m->height = (int64_t)v;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * BlockMeta — types.pb.go:2058-2098
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_block_meta_init(cmt_pb_block_meta_t *m)
{
    if (m == NULL) {
        return;
    }
    cmt_pb_block_id_init(&m->block_id);
    m->block_size = 0;
    cmt_pb_header_init(&m->header);
    m->num_txs = 0;
}

size_t cmt_pb_store_block_meta_upper_bound(void)
{
    return B_BLOCK_ID + B_VARINT + B_HEADER + B_VARINT;
}

int cmt_pb_store_block_meta_marshal(const cmt_pb_block_meta_t *m,
                                    uint8_t *out, size_t cap,
                                    size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 4, (uint64_t)m->num_txs);         /* :2063-2067 */
    w_embed_header(&w, 3, &m->header);              /* :2068-2077 ALWAYS */
    wf_varint(&w, 2, (uint64_t)m->block_size);      /* :2078-2082 */
    w_embed_block_id(&w, 1, &m->block_id);          /* :2083-2092 ALWAYS */
    return w_finish(&w, out_len);
}

/* types.pb.go — BlockMeta.Unmarshal. DEVIATION (cmt_pb_store.h): a
 * second occurrence of field 1 or 3 REPLACES rather than merges. */
int cmt_pb_store_block_meta_unmarshal(const uint8_t *in, size_t len,
                                      cmt_pb_block_meta_t *m)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_block_meta_init(m);
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_block_id_unmarshal(p, n, &m->block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->block_size = (int64_t)v;
            break;
        case 3:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_header_unmarshal(p, n, &m->header) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->num_txs = (int64_t)v;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Version — state/types.pb.go:965-1003
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_version_init(cmt_pb_version_t *m)
{
    if (m == NULL) {
        return;
    }
    cmt_pb_consensus_init(&m->consensus);
    memset(m->software, 0, sizeof(m->software));
    m->software_len = 0;
}

size_t cmt_pb_store_version_upper_bound(void)
{
    return B_VERSION;
}

int cmt_pb_store_version_marshal(const cmt_pb_version_t *m, uint8_t *out,
                                 size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->software_len > sizeof(m->software)) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    wf_bytes(&w, 2, m->software, m->software_len);   /* :970-976 */
    w_embed_consensus(&w, 1, &m->consensus);         /* :977-986 ALWAYS */
    return w_finish(&w, out_len);
}

static int version_merge(const uint8_t *in, size_t len, cmt_pb_version_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_consensus_unmarshal(p, n, &m->consensus) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_fixed(m->software, sizeof(m->software),
                             &m->software_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_store_version_unmarshal(const uint8_t *in, size_t len,
                                   cmt_pb_version_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_version_init(m);
    return version_merge(in, len, m);
}

int cmt_pb_store_version_from_c(const cmt_state_version_t *v,
                                cmt_pb_version_t *out)
{
    size_t n;

    if (v == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_store_version_init(out);
    out->consensus = v->consensus;
    n = strnlen(v->software, sizeof(v->software));
    if (n > sizeof(out->software)) {
        return CMT_REJECT;
    }
    memcpy(out->software, v->software, n);
    out->software_len = n;
    return CMT_OK;
}

int cmt_pb_store_version_to_c(const cmt_pb_version_t *m,
                              cmt_state_version_t *out)
{
    if (m == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (m->software_len >= sizeof(out->software)) {
        return CMT_REJECT;                /* no room for the NUL */
    }
    out->consensus = m->consensus;
    memset(out->software, 0, sizeof(out->software));
    memcpy(out->software, m->software, m->software_len);
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * ConsensusParams — params.pb.go:702-978
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_consensus_params_init(cmt_pb_consensus_params_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

size_t cmt_pb_store_consensus_params_upper_bound(void)
{
    return B_CONSENSUS_PARAMS;
}

/* :785-816 */
static void block_params_wr(pb_w_t *w, const cmt_block_params_t *p)
{
    wf_varint(w, 2, (uint64_t)p->max_gas);
    wf_varint(w, 1, (uint64_t)p->max_bytes);
}

/* :818-857 — max_age_duration is ALWAYS written (:825-834). */
static void evidence_params_wr(pb_w_t *w, const cmt_evidence_params_t *p)
{
    wf_varint(w, 3, (uint64_t)p->max_bytes);
    w_embed_std_duration(w, 2, p->max_age_duration_ns);
    wf_varint(w, 1, (uint64_t)p->max_age_num_blocks);
}

/* :859-889 — one tag per element, elements written unconditionally
 * (:864-870), the slice guarded (:863). */
static int validator_params_wr(pb_w_t *w, const cmt_validator_params_t *p)
{
    size_t k;

    if (p->pub_key_types_len > CMT_PARAMS_MAX_PUBKEY_TYPES) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = p->pub_key_types_len; k > 0; k--) {
        const char *s = p->pub_key_types[k - 1];
        size_t      n = strnlen(s, CMT_PARAMS_PUBKEY_TYPE_MAX);

        if (n >= CMT_PARAMS_PUBKEY_TYPE_MAX) {
            w->err = CMT_REJECT;          /* not NUL-terminated */
            return CMT_REJECT;
        }
        wf_bytes_elem(w, 1, (const uint8_t *)s, n);
    }
    return CMT_OK;
}

/* :891-917 */
static void version_params_wr(pb_w_t *w, const cmt_version_params_t *p)
{
    wf_varint(w, 1, p->app);
}

/* :952-978 */
static void abci_params_wr(pb_w_t *w, const cmt_abci_params_t *p)
{
    wf_varint(w, 1, (uint64_t)p->vote_extensions_enable_height);
}

/* :702-783 — five POINTER sub-messages, 5 down to 1. */
static int consensus_params_wr(pb_w_t *w, const cmt_pb_consensus_params_t *m)
{
    size_t before;

    if (m->has_abci) {
        before = w->i;
        abci_params_wr(w, &m->abci);
        wf_close_msg(w, 5, before);
    }
    if (m->has_version) {
        before = w->i;
        version_params_wr(w, &m->version);
        wf_close_msg(w, 4, before);
    }
    if (m->has_validator) {
        before = w->i;
        if (validator_params_wr(w, &m->validator) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 3, before);
    }
    if (m->has_evidence) {
        before = w->i;
        evidence_params_wr(w, &m->evidence);
        wf_close_msg(w, 2, before);
    }
    if (m->has_block) {
        before = w->i;
        block_params_wr(w, &m->block);
        wf_close_msg(w, 1, before);
    }
    return w->err;
}

int cmt_pb_store_consensus_params_marshal(const cmt_pb_consensus_params_t *m,
                                          uint8_t *out, size_t cap,
                                          size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (consensus_params_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* params.pb.go — BlockParams.Unmarshal (fields 1, 2; 3 is reserved and
 * therefore unknown → skipped). */
static int block_params_merge(const uint8_t *in, size_t len,
                              cmt_block_params_t *p)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1 || fieldnum == 2) {
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fieldnum == 1) {
                p->max_bytes = (int64_t)v;
            } else {
                p->max_gas = (int64_t)v;
            }
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* params.pb.go — EvidenceParams.Unmarshal; field 2 through
 * StdDurationUnmarshal, which validates the Duration. */
static int evidence_params_merge(const uint8_t *in, size_t len,
                                 cmt_evidence_params_t *p)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *q;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            p->max_age_num_blocks = (int64_t)v;
            break;
        case 2: {
            int64_t ns;

            if (wt != 2u || r_ld(in, len, &i, &q, &n) != CMT_OK ||
                cmt_pb_std_duration_unmarshal(q, n, &ns) != CMT_OK) {
                return CMT_REJECT;
            }
            p->max_age_duration_ns = ns;
            break;
        }
        case 3:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            p->max_bytes = (int64_t)v;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* params.pb.go — ValidatorParams.Unmarshal: append each string. A name
 * that does not fit the fixed array, a ninth name, or a name carrying a
 * NUL byte (unrepresentable in NUL-terminated storage) is REFUSED —
 * capacity rules of this port, not the reference's. */
static int validator_params_merge(const uint8_t *in, size_t len,
                                  cmt_validator_params_t *p)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *q;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 2u || r_ld(in, len, &i, &q, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (p->pub_key_types_len >= CMT_PARAMS_MAX_PUBKEY_TYPES ||
                n >= CMT_PARAMS_PUBKEY_TYPE_MAX ||
                (n != 0 && memchr(q, 0, n) != NULL)) {
                return CMT_REJECT;
            }
            memset(p->pub_key_types[p->pub_key_types_len], 0,
                   CMT_PARAMS_PUBKEY_TYPE_MAX);
            if (n != 0) {
                memcpy(p->pub_key_types[p->pub_key_types_len], q, n);
            }
            p->pub_key_types_len++;
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* One-varint messages: VersionParams.app (uint64), ABCIParams.height. */
static int one_varint_merge(const uint8_t *in, size_t len, uint64_t *out)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            *out = v;
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* params.pb.go — ConsensusParams.Unmarshal: each sub-message is
 * allocated on first sight and MERGED on every occurrence (the generated
 * `if m.Block == nil { m.Block = &BlockParams{} }` then `Unmarshal`).
 * These five are decoded here, not through a public init+merge, so
 * they DO merge like the generated code. */
static int consensus_params_merge(const uint8_t *in, size_t len,
                                  cmt_pb_consensus_params_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum >= 1 && fieldnum <= 5) {
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
        }
        switch (fieldnum) {
        case 1:
            if (!m->has_block) {
                memset(&m->block, 0, sizeof(m->block));
                m->has_block = true;
            }
            if (block_params_merge(p, n, &m->block) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (!m->has_evidence) {
                memset(&m->evidence, 0, sizeof(m->evidence));
                m->has_evidence = true;
            }
            if (evidence_params_merge(p, n, &m->evidence) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            if (!m->has_validator) {
                memset(&m->validator, 0, sizeof(m->validator));
                m->has_validator = true;
            }
            if (validator_params_merge(p, n, &m->validator) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (!m->has_version) {
                memset(&m->version, 0, sizeof(m->version));
                m->has_version = true;
            }
            if (one_varint_merge(p, n, &m->version.app) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5: {
            uint64_t h = (uint64_t)m->abci.vote_extensions_enable_height;

            if (!m->has_abci) {
                memset(&m->abci, 0, sizeof(m->abci));
                m->has_abci = true;
                h = 0;
            }
            if (one_varint_merge(p, n, &h) != CMT_OK) {
                return CMT_REJECT;
            }
            m->abci.vote_extensions_enable_height = (int64_t)h;
            break;
        }
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_store_consensus_params_unmarshal(const uint8_t *in, size_t len,
                                            cmt_pb_consensus_params_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_consensus_params_init(m);
    return consensus_params_merge(in, len, m);
}

/* types/params.go:325-346 — ToProto: every sub-message set. */
int cmt_pb_store_consensus_params_from_c(const cmt_consensus_params_t *p,
                                         cmt_pb_consensus_params_t *out)
{
    if (p == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_store_consensus_params_init(out);
    out->has_block     = true;  out->block     = p->block;      /* :327-330 */
    out->has_evidence  = true;  out->evidence  = p->evidence;   /* :331-335 */
    out->has_validator = true;  out->validator = p->validator;  /* :336-338 */
    out->has_version   = true;  out->version   = p->version;    /* :339-341 */
    out->has_abci      = true;  out->abci      = p->abci;       /* :342-344 */
    return CMT_OK;
}

/* types/params.go:348-370 — ConsensusParamsFromProto. The four
 * unchecked dereferences (:349-365) are explicit refusals here. */
int cmt_pb_store_consensus_params_to_c(const cmt_pb_consensus_params_t *m,
                                       cmt_consensus_params_t *out)
{
    if (m == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (!m->has_block || !m->has_evidence || !m->has_validator ||
        !m->has_version) {
        return CMT_REJECT;                /* the reference's nil panic */
    }
    memset(out, 0, sizeof(*out));
    out->block     = m->block;            /* :350-353 */
    out->evidence  = m->evidence;         /* :354-358 */
    out->validator = m->validator;        /* :359-361 */
    out->version   = m->version;          /* :362-364 */
    if (m->has_abci) {                    /* :366-368 */
        out->abci.vote_extensions_enable_height =
            m->abci.vote_extensions_enable_height;
    }
    return CMT_OK;
}

bool cmt_pb_store_consensus_params_is_empty(const cmt_pb_consensus_params_t *m)
{
    if (m == NULL) {
        return true;
    }
    return !m->has_block && !m->has_evidence && !m->has_validator &&
           !m->has_version && !m->has_abci;
}

/* ═══════════════════════════════════════════════════════════════════════
 * State — state/types.pb.go:1005-1116
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_state_init(cmt_pb_state_t *m)
{
    cmt_pb_validator_t *s6, *s7, *s8;
    size_t              c6, c7, c8;

    if (m == NULL) {
        return;
    }
    /* The three sets' caller storage survives init (cmt_pb.c:1490-1504). */
    s6 = m->next_validators.validators; c6 = m->next_validators.validators_cap;
    s7 = m->validators.validators;      c7 = m->validators.validators_cap;
    s8 = m->last_validators.validators; c8 = m->last_validators.validators_cap;
    memset(m, 0, sizeof(*m));
    cmt_pb_store_version_init(&m->version);
    cmt_pb_block_id_init(&m->last_block_id);
    cmt_pb_timestamp_init(&m->last_block_time);       /* Go's zero time */
    m->next_validators.validators = s6; m->next_validators.validators_cap = c6;
    m->validators.validators      = s7; m->validators.validators_cap      = c7;
    m->last_validators.validators = s8; m->last_validators.validators_cap = c8;
    cmt_pb_validator_set_init(&m->next_validators);
    cmt_pb_validator_set_init(&m->validators);
    cmt_pb_validator_set_init(&m->last_validators);
    cmt_pb_store_consensus_params_init(&m->consensus_params);
}

size_t cmt_pb_store_state_upper_bound(size_t n_validators)
{
    return B_VERSION + (2u + CMT_PB_CHAINID_MAX) + B_VARINT + B_BLOCK_ID +
           (3u + B_TIMESTAMP) + 3u * bound_validator_set(n_validators) +
           B_VARINT + (3u + B_CONSENSUS_PARAMS) + B_VARINT + B_HASH + B_HASH +
           B_VARINT;
}

int cmt_pb_store_state_marshal(const cmt_pb_state_t *m, uint8_t *out,
                               size_t cap, size_t *out_len)
{
    pb_w_t w;
    size_t before;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (m->chain_id_len > sizeof(m->chain_id) ||
        m->last_results_hash_len > sizeof(m->last_results_hash) ||
        m->app_hash_len > sizeof(m->app_hash)) {
        return CMT_REJECT;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 14, (uint64_t)m->initial_height);               /* :1010-1014 */
    wf_bytes(&w, 13, m->app_hash, m->app_hash_len);                /* :1015-1021 */
    wf_bytes(&w, 12, m->last_results_hash, m->last_results_hash_len); /* :1022-1028 */
    wf_varint(&w, 11, (uint64_t)m->last_height_consensus_params_changed); /* :1029-1033 */
    before = w.i;                                                  /* :1034-1043 ALWAYS */
    if (consensus_params_wr(&w, &m->consensus_params) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(&w, 10, before);
    wf_varint(&w, 9, (uint64_t)m->last_height_validators_changed); /* :1044-1048 */
    if (m->has_last_validators) {                                  /* :1049-1060 */
        w_embed_validator_set(&w, 8, &m->last_validators);
    }
    if (m->has_validators) {                                       /* :1061-1072 */
        w_embed_validator_set(&w, 7, &m->validators);
    }
    if (m->has_next_validators) {                                  /* :1073-1084 */
        w_embed_validator_set(&w, 6, &m->next_validators);
    }
    w_embed_timestamp(&w, 5, &m->last_block_time);                 /* :1085-1093 ALWAYS */
    w_embed_block_id(&w, 4, &m->last_block_id);                    /* :1094-1103 ALWAYS */
    wf_varint(&w, 3, (uint64_t)m->last_block_height);              /* :1104-1108 */
    wf_bytes(&w, 2, m->chain_id, m->chain_id_len);                 /* :1109-1115 */
    before = w.i;                                                  /* :1116-1125 ALWAYS */
    wf_bytes(&w, 2, m->version.software, m->version.software_len);
    w_embed_consensus(&w, 1, &m->version.consensus);
    wf_close_msg(&w, 1, before);
    return w_finish(&w, out_len);
}

/* state/types.pb.go — State.Unmarshal. DEVIATION (cmt_pb_store.h): a
 * second occurrence of an embedded field decoded through a public
 * `_unmarshal` (1, 4, 5, 6, 7, 8) REPLACES; field 10 merges. */
static int state_merge(const uint8_t *in, size_t len, cmt_pb_state_t *m)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p = NULL;
        size_t   n = 0;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1: case 2: case 4: case 5: case 6: case 7: case 8:
        case 10: case 12: case 13:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3: case 9: case 11: case 14:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            continue;
        }
        switch (fieldnum) {
        case 1:
            if (cmt_pb_store_version_unmarshal(p, n, &m->version) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (r_copy_fixed(m->chain_id, sizeof(m->chain_id),
                             &m->chain_id_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            m->last_block_height = (int64_t)v;
            break;
        case 4:
            if (cmt_pb_block_id_unmarshal(p, n, &m->last_block_id) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5:
            if (cmt_pb_timestamp_unmarshal(p, n, &m->last_block_time)
                != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 6:
            if (cmt_pb_validator_set_unmarshal(p, n, &m->next_validators)
                != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_next_validators = true;
            break;
        case 7:
            if (cmt_pb_validator_set_unmarshal(p, n, &m->validators)
                != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_validators = true;
            break;
        case 8:
            if (cmt_pb_validator_set_unmarshal(p, n, &m->last_validators)
                != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_last_validators = true;
            break;
        case 9:
            m->last_height_validators_changed = (int64_t)v;
            break;
        case 10:
            if (consensus_params_merge(p, n, &m->consensus_params) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 11:
            m->last_height_consensus_params_changed = (int64_t)v;
            break;
        case 12:
            if (r_copy_fixed(m->last_results_hash, sizeof(m->last_results_hash),
                             &m->last_results_hash_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 13:
            if (r_copy_fixed(m->app_hash, sizeof(m->app_hash),
                             &m->app_hash_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default: /* 14 */
            m->initial_height = (int64_t)v;
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_store_state_unmarshal(const uint8_t *in, size_t len,
                                 cmt_pb_state_t *m)
{
    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_state_init(m);
    return state_merge(in, len, m);
}

/* state/state.go:145-183 — ToProto */
int cmt_pb_store_state_from_c(const cmt_state_t *state, cmt_pb_state_t *out)
{
    int rc;

    if (state == NULL || out == NULL) {
        return CMT_FAULT;                                       /* :146-148 */
    }
    cmt_pb_store_state_init(out);
    rc = cmt_pb_store_version_from_c(&state->version, &out->version); /* :151 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (state->chain_id_len > sizeof(out->chain_id)) {
        return CMT_REJECT;
    }
    memcpy(out->chain_id, state->chain_id, state->chain_id_len);  /* :152 */
    out->chain_id_len = state->chain_id_len;
    out->initial_height = state->initial_height;                 /* :153 */
    out->last_block_height = state->last_block_height;           /* :154 */
    rc = cmt_block_id_to_proto(&state->last_block_id, &out->last_block_id); /* :156 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->last_block_time = state->last_block_time;               /* :157 */
    rc = cmt_validator_set_to_proto(&state->validators, &out->validators); /* :158-162 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->has_validators = true;
    rc = cmt_validator_set_to_proto(&state->next_validators,
                                    &out->next_validators);      /* :164-168 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->has_next_validators = true;
    if (state->last_block_height >= 1) {                         /* :170-176 */
        rc = cmt_validator_set_to_proto(&state->last_validators,
                                        &out->last_validators);
        if (rc != CMT_OK) {
            return rc;
        }
        out->has_last_validators = true;
    }
    out->last_height_validators_changed =
        state->last_height_validators_changed;                   /* :178 */
    rc = cmt_pb_store_consensus_params_from_c(&state->consensus_params,
                                              &out->consensus_params); /* :179 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->last_height_consensus_params_changed =
        state->last_height_consensus_params_changed;             /* :180 */
    if (state->last_results_hash_len > sizeof(out->last_results_hash) ||
        state->app_hash_len > sizeof(out->app_hash)) {
        return CMT_REJECT;
    }
    memcpy(out->last_results_hash, state->last_results_hash,
           state->last_results_hash_len);                        /* :181 */
    out->last_results_hash_len = state->last_results_hash_len;
    memcpy(out->app_hash, state->app_hash, state->app_hash_len); /* :182 */
    out->app_hash_len = state->app_hash_len;
    return CMT_OK;
}

/* state/state.go:186-232 — FromProto */
int cmt_pb_store_state_to_c(const cmt_pb_state_t *m, cmt_state_t *out)
{
    int rc;

    if (m == NULL || out == NULL) {
        return CMT_FAULT;                                       /* :187-189 */
    }
    if (out->storage == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_state_init(out, out->storage);                     /* :191 new(State) */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_pb_store_version_to_c(&m->version, &out->version);  /* :193 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (m->chain_id_len > sizeof(out->chain_id)) {
        return CMT_REJECT;
    }
    memcpy(out->chain_id, m->chain_id, m->chain_id_len);         /* :194 */
    out->chain_id_len = m->chain_id_len;
    out->initial_height = m->initial_height;                     /* :195 */
    rc = cmt_block_id_from_proto(&m->last_block_id, &out->last_block_id); /* :197-201 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->last_block_height = m->last_block_height;               /* :202 */
    out->last_block_time = m->last_block_time;                   /* :203 */

    /* :205-209 — ValidatorSetFromProto(pb.Validators): nil is an error. */
    if (!m->has_validators) {
        return CMT_REJECT;
    }
    rc = cmt_validator_set_init(&out->validators, out->storage->validators,
                                CMT_VALSET_MAX);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_from_proto(&m->validators, &out->validators);
    if (rc != CMT_OK) {
        return rc;
    }
    /* :211-215 */
    if (!m->has_next_validators) {
        return CMT_REJECT;
    }
    rc = cmt_validator_set_init(&out->next_validators,
                                out->storage->next_validators, CMT_VALSET_MAX);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_validator_set_from_proto(&m->next_validators,
                                      &out->next_validators);
    if (rc != CMT_OK) {
        return rc;
    }
    /* :217-225 — at block 1 LastValidators is NewValidatorSet(nil): an
     * EMPTY set bound to its storage, not a nil one. */
    rc = cmt_validator_set_init(&out->last_validators,
                                out->storage->last_validators, CMT_VALSET_MAX);
    if (rc != CMT_OK) {
        return rc;
    }
    if (out->last_block_height >= 1) {
        if (!m->has_last_validators) {
            return CMT_REJECT;
        }
        rc = cmt_validator_set_from_proto(&m->last_validators,
                                          &out->last_validators);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    out->last_height_validators_changed =
        m->last_height_validators_changed;                       /* :227 */
    rc = cmt_pb_store_consensus_params_to_c(&m->consensus_params,
                                            &out->consensus_params); /* :228 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->last_height_consensus_params_changed =
        m->last_height_consensus_params_changed;                 /* :229 */
    memcpy(out->last_results_hash, m->last_results_hash,
           m->last_results_hash_len);                            /* :230 */
    out->last_results_hash_len = m->last_results_hash_len;
    memcpy(out->app_hash, m->app_hash, m->app_hash_len);         /* :231 */
    out->app_hash_len = m->app_hash_len;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * ValidatorsInfo — state/types.pb.go:835-873
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_validators_info_init(cmt_pb_validators_info_t *m)
{
    cmt_pb_validator_t *s;
    size_t              c;

    if (m == NULL) {
        return;
    }
    s = m->validator_set.validators;
    c = m->validator_set.validators_cap;
    memset(m, 0, sizeof(*m));
    m->validator_set.validators     = s;
    m->validator_set.validators_cap = c;
    cmt_pb_validator_set_init(&m->validator_set);
}

size_t cmt_pb_store_validators_info_upper_bound(size_t n_validators)
{
    return bound_validator_set(n_validators) + B_VARINT;
}

int cmt_pb_store_validators_info_marshal(const cmt_pb_validators_info_t *m,
                                         uint8_t *out, size_t cap,
                                         size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 2, (uint64_t)m->last_height_changed);   /* :840-844 */
    if (m->has_validator_set) {                            /* :845-856 */
        w_embed_validator_set(&w, 1, &m->validator_set);
    }
    return w_finish(&w, out_len);
}

int cmt_pb_store_validators_info_unmarshal(const uint8_t *in, size_t len,
                                           cmt_pb_validators_info_t *m)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_validators_info_init(m);
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_validator_set_unmarshal(p, n, &m->validator_set)
                    != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_validator_set = true;
            break;
        case 2:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->last_height_changed = (int64_t)v;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * ConsensusParamsInfo — state/types.pb.go:875-911
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_consensus_params_info_init(cmt_pb_consensus_params_info_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
    }
}

size_t cmt_pb_store_consensus_params_info_upper_bound(void)
{
    return 3u + B_CONSENSUS_PARAMS + B_VARINT;
}

int cmt_pb_store_consensus_params_info_marshal(
    const cmt_pb_consensus_params_info_t *m, uint8_t *out, size_t cap,
    size_t *out_len)
{
    pb_w_t w;
    size_t before;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 2, (uint64_t)m->last_height_changed);   /* :880-884 */
    before = w.i;                                          /* :885-894 ALWAYS */
    if (consensus_params_wr(&w, &m->consensus_params) != CMT_OK) {
        return CMT_REJECT;
    }
    wf_close_msg(&w, 1, before);
    return w_finish(&w, out_len);
}

int cmt_pb_store_consensus_params_info_unmarshal(
    const uint8_t *in, size_t len, cmt_pb_consensus_params_info_t *m)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_consensus_params_info_init(m);
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                consensus_params_merge(p, n, &m->consensus_params) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->last_height_changed = (int64_t)v;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * EventAttribute / Event / stored ExecTxResult / ValidatorUpdate /
 * ResponseFinalizeBlock — abci/types/types.pb.go
 * ═══════════════════════════════════════════════════════════════════════ */

size_t cmt_pb_store_event_attribute_upper_bound(const cmt_pb_event_attribute_t *a)
{
    if (a == NULL) {
        return 0;
    }
    return (11u + a->key.len) + (11u + a->value.len) + 2u + 11u;
}

/* :6987-7026 */
static void event_attribute_wr(pb_w_t *w, const cmt_pb_event_attribute_t *a)
{
    if (a->index) {                                    /* :6992-7000 */
        uint8_t one = 1;

        w_raw(w, &one, 1);
        w_tag(w, 3, 0);
    }
    wf_bytes(w, 2, a->value.data, a->value.len);       /* :7001-7007 */
    wf_bytes(w, 1, a->key.data, a->key.len);           /* :7008-7014 */
}

int cmt_pb_store_event_attribute_marshal(const cmt_pb_event_attribute_t *m,
                                         uint8_t *out, size_t cap,
                                         size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    event_attribute_wr(&w, m);
    return w_finish(&w, out_len);
}

size_t cmt_pb_store_event_upper_bound(const cmt_pb_event_t *e)
{
    size_t k, n;

    if (e == NULL) {
        return 0;
    }
    n = 11u + e->type.len + 11u;
    for (k = 0; k < e->attributes_len; k++) {
        n += 11u + cmt_pb_store_event_attribute_upper_bound(&e->attributes[k]);
    }
    return n;
}

/* :6943-6985 — attributes 2 (repeated, one tag each, slice guarded),
 * type 1. */
static int event_wr(pb_w_t *w, const cmt_pb_event_t *e)
{
    size_t k;

    if (e->attributes_len != 0 && e->attributes == NULL) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = e->attributes_len; k > 0; k--) {          /* :6948-6960 */
        size_t before = w->i;

        event_attribute_wr(w, &e->attributes[k - 1]);
        wf_close_msg(w, 2, before);
    }
    wf_bytes(w, 1, e->type.data, e->type.len);         /* :6961-6967 */
    return w->err;
}

int cmt_pb_store_event_marshal(const cmt_pb_event_t *m, uint8_t *out,
                               size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (event_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

size_t cmt_pb_store_stored_exec_tx_result_upper_bound(
    const cmt_pb_stored_exec_tx_result_t *r)
{
    size_t k, n;

    if (r == NULL) {
        return 0;
    }
    n = B_VARINT + (11u + r->det.data.len) + (11u + r->log.len) +
        (11u + r->info.len) + 2u * B_VARINT + (11u + r->codespace.len) + 11u;
    for (k = 0; k < r->events_len; k++) {
        n += 11u + cmt_pb_store_event_upper_bound(&r->events[k]);
    }
    return n;
}

/* :7034-7097 — all eight fields, 8 down to 1. */
static int stored_exec_tx_result_wr(pb_w_t *w,
                                    const cmt_pb_stored_exec_tx_result_t *r)
{
    size_t k;

    wf_bytes(w, 8, r->codespace.data, r->codespace.len);   /* :7039-7045 */
    if (r->events_len != 0 && r->events == NULL) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = r->events_len; k > 0; k--) {                  /* :7046-7058 */
        size_t before = w->i;

        if (event_wr(w, &r->events[k - 1]) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 7, before);
    }
    wf_varint(w, 6, (uint64_t)r->det.gas_used);            /* :7059-7063 */
    wf_varint(w, 5, (uint64_t)r->det.gas_wanted);          /* :7064-7068 */
    wf_bytes(w, 4, r->info.data, r->info.len);             /* :7069-7075 */
    wf_bytes(w, 3, r->log.data, r->log.len);               /* :7076-7082 */
    wf_bytes(w, 2, r->det.data.data, r->det.data.len);     /* :7083-7089 */
    wf_varint(w, 1, (uint64_t)r->det.code);                /* :7090-7094 */
    return w->err;
}

int cmt_pb_store_stored_exec_tx_result_marshal(
    const cmt_pb_stored_exec_tx_result_t *m, uint8_t *out, size_t cap,
    size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (stored_exec_tx_result_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

size_t cmt_pb_store_validator_update_upper_bound(void)
{
    return B_PUBKEY + B_VARINT;
}

/* :7199-7235 — power 2, pub_key 1 ALWAYS. */
static void validator_update_wr(pb_w_t *w, const cmt_pb_validator_update_t *u)
{
    wf_varint(w, 2, (uint64_t)u->power);                   /* :7204-7208 */
    w_embed_public_key(w, 1, &u->pub_key);                 /* :7209-7218 */
}

int cmt_pb_store_validator_update_marshal(const cmt_pb_validator_update_t *m,
                                          uint8_t *out, size_t cap,
                                          size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    validator_update_wr(&w, m);
    return w_finish(&w, out_len);
}

void cmt_pb_store_response_finalize_block_init(
    cmt_pb_response_finalize_block_t *m)
{
    cmt_pb_event_t                 *e;  size_t ec;
    cmt_pb_stored_exec_tx_result_t *t;  size_t tc;
    cmt_pb_validator_update_t      *u;  size_t uc;

    if (m == NULL) {
        return;
    }
    e = m->events;            ec = m->events_cap;
    t = m->tx_results;        tc = m->tx_results_cap;
    u = m->validator_updates; uc = m->validator_updates_cap;
    memset(m, 0, sizeof(*m));
    m->events = e;            m->events_cap = ec;
    m->tx_results = t;        m->tx_results_cap = tc;
    m->validator_updates = u; m->validator_updates_cap = uc;
}

size_t cmt_pb_store_response_finalize_block_upper_bound(
    const cmt_pb_response_finalize_block_t *m)
{
    size_t k, n;

    if (m == NULL) {
        return 0;
    }
    n = B_HASH + (3u + B_CONSENSUS_PARAMS);
    for (k = 0; k < m->events_len; k++) {
        n += 11u + cmt_pb_store_event_upper_bound(&m->events[k]);
    }
    for (k = 0; k < m->tx_results_len; k++) {
        n += 11u + cmt_pb_store_stored_exec_tx_result_upper_bound(
                       &m->tx_results[k]);
    }
    n += m->validator_updates_len * (11u + B_PUBKEY + B_VARINT);
    return n;
}

/* :6775-6843 — 5 down to 1. */
static int response_finalize_block_wr(pb_w_t *w,
                                      const cmt_pb_response_finalize_block_t *m)
{
    size_t k;

    if (m->app_hash_len > sizeof(m->app_hash)) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    wf_bytes(w, 5, m->app_hash, m->app_hash_len);          /* :6780-6786 */
    if (m->has_consensus_param_updates) {                  /* :6787-6798 */
        size_t before = w->i;

        if (consensus_params_wr(w, &m->consensus_param_updates) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 4, before);
    }
    if ((m->validator_updates_len != 0 && m->validator_updates == NULL) ||
        (m->tx_results_len != 0 && m->tx_results == NULL) ||
        (m->events_len != 0 && m->events == NULL)) {
        w->err = CMT_REJECT;
        return CMT_REJECT;
    }
    for (k = m->validator_updates_len; k > 0; k--) {       /* :6799-6811 */
        size_t before = w->i;

        validator_update_wr(w, &m->validator_updates[k - 1]);
        wf_close_msg(w, 3, before);
    }
    for (k = m->tx_results_len; k > 0; k--) {              /* :6812-6825 */
        size_t before = w->i;

        if (stored_exec_tx_result_wr(w, &m->tx_results[k - 1]) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 2, before);
    }
    for (k = m->events_len; k > 0; k--) {                  /* :6826-6838 */
        size_t before = w->i;

        if (event_wr(w, &m->events[k - 1]) != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(w, 1, before);
    }
    return w->err;
}

int cmt_pb_store_response_finalize_block_marshal(
    const cmt_pb_response_finalize_block_t *m, uint8_t *out, size_t cap,
    size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (response_finalize_block_wr(&w, m) != CMT_OK) {
        return CMT_REJECT;
    }
    return w_finish(&w, out_len);
}

/* ── the decoder's pools ─────────────────────────────────────────────── */

typedef struct {
    cmt_pb_rfb_storage_t *st;
    size_t events_used;
    size_t attributes_used;
    size_t tx_results_used;
    size_t validator_updates_used;
} rfb_pools_t;

/* Take one more slot for `arr` (which holds `len` elements at the pool's
 * position `base`): the array must still be the pool's tail, or the
 * generated code's contiguous slice cannot be reproduced — a stream
 * interleaving two consumers of one pool is REFUSED (the generated
 * encoder never writes one: fields ascend). */
#define POOL_APPEND(pool, cap, used, arr, len, out_slot)                    \
    do {                                                                    \
        if ((pool) == NULL) { return CMT_REJECT; }                          \
        if ((arr) == NULL) {                                                \
            (arr) = (pool) + (used);                                        \
        } else if ((arr) + (len) != (pool) + (used)) {                      \
            return CMT_REJECT;                                              \
        }                                                                   \
        if ((used) >= (cap)) { return CMT_REJECT; }                         \
        (out_slot) = (pool) + (used);                                       \
        (used)++;                                                           \
    } while (0)

/* abci/types/types.pb.go:15138 EventAttribute.Unmarshal — 1, 2 string,
 * 3 bool */
static int event_attribute_merge(const uint8_t *in, size_t len,
                                 cmt_pb_event_attribute_t *a,
                                 cmt_pb_arena_t *arena)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_arena(arena, p, n, &a->key) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_arena(arena, p, n, &a->value) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            a->index = (v != 0);                     /* `bool(v != 0)` */
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* abci/types/types.pb.go:15022 Event.Unmarshal — type 1, attributes 2
 * appended (`append(m.Attributes, EventAttribute{})` then Unmarshal into
 * the last). */
static int event_merge(const uint8_t *in, size_t len, cmt_pb_event_t *e,
                       rfb_pools_t *pools)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_arena(pools->st->arena, p, n, &e->type) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2: {
            cmt_pb_event_attribute_t *slot;

            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            POOL_APPEND(pools->st->attributes, pools->st->attributes_cap,
                        pools->attributes_used, e->attributes,
                        e->attributes_len, slot);
            memset(slot, 0, sizeof(*slot));
            if (event_attribute_merge(p, n, slot, pools->st->arena) != CMT_OK) {
                return CMT_REJECT;
            }
            e->attributes_len++;
            e->attributes_cap = e->attributes_len;
            break;
        }
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* abci/types/types.pb.go:15272-15542 ExecTxResult.Unmarshal — ALL eight
 * fields parsed, as the generated code does (the four-field refusal is
 * cmt_pb's, for the HASHED copy; the STORED copy keeps everything). */
static int stored_exec_tx_result_merge(const uint8_t *in, size_t len,
                                       cmt_pb_stored_exec_tx_result_t *r,
                                       rfb_pools_t *pools)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            r->det.code = (uint32_t)v;           /* uint32 accumulation */
            break;
        case 2:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_arena(pools->st->arena, p, n, &r->det.data) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_arena(pools->st->arena, p, n, &r->log) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_arena(pools->st->arena, p, n, &r->info) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            r->det.gas_wanted = (int64_t)v;
            break;
        case 6:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            r->det.gas_used = (int64_t)v;
            break;
        case 7: {
            cmt_pb_event_t *slot;

            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            POOL_APPEND(pools->st->events, pools->st->events_cap,
                        pools->events_used, r->events, r->events_len, slot);
            memset(slot, 0, sizeof(*slot));
            if (event_merge(p, n, slot, pools) != CMT_OK) {
                return CMT_REJECT;
            }
            r->events_len++;
            r->events_cap = r->events_len;
            break;
        }
        case 8:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                r_copy_arena(pools->st->arena, p, n, &r->codespace) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* abci/types/types.pb.go:15801 ValidatorUpdate.Unmarshal — pub_key 1
 * (merged into the value field; a second occurrence REPLACES here,
 * DEVIATION), power 2. */
static int validator_update_merge(const uint8_t *in, size_t len,
                                  cmt_pb_validator_update_t *u)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_public_key_unmarshal(p, n, &u->pub_key) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            u->power = (int64_t)v;
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* abci/types/types.pb.go:14594 ResponseFinalizeBlock.Unmarshal — 1
 * events (append), 2 tx_results (append), 3 validator_updates (append),
 * 4 consensus_param_updates (allocate-if-nil, merge), 5 app_hash. */
static int response_finalize_block_merge(const uint8_t *in, size_t len,
                                         cmt_pb_response_finalize_block_t *m,
                                         rfb_pools_t *pools)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum >= 1 && fieldnum <= 5) {
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
        }
        switch (fieldnum) {
        case 1: {
            cmt_pb_event_t *slot;

            POOL_APPEND(pools->st->events, pools->st->events_cap,
                        pools->events_used, m->events, m->events_len, slot);
            memset(slot, 0, sizeof(*slot));
            if (event_merge(p, n, slot, pools) != CMT_OK) {
                return CMT_REJECT;
            }
            m->events_len++;
            m->events_cap = m->events_len;
            break;
        }
        case 2: {
            cmt_pb_stored_exec_tx_result_t *slot;

            POOL_APPEND(pools->st->tx_results, pools->st->tx_results_cap,
                        pools->tx_results_used, m->tx_results,
                        m->tx_results_len, slot);
            memset(slot, 0, sizeof(*slot));
            if (stored_exec_tx_result_merge(p, n, slot, pools) != CMT_OK) {
                return CMT_REJECT;
            }
            m->tx_results_len++;
            m->tx_results_cap = m->tx_results_len;
            break;
        }
        case 3: {
            cmt_pb_validator_update_t *slot;

            POOL_APPEND(pools->st->validator_updates,
                        pools->st->validator_updates_cap,
                        pools->validator_updates_used, m->validator_updates,
                        m->validator_updates_len, slot);
            memset(slot, 0, sizeof(*slot));
            cmt_pb_public_key_init(&slot->pub_key);
            if (validator_update_merge(p, n, slot) != CMT_OK) {
                return CMT_REJECT;
            }
            m->validator_updates_len++;
            m->validator_updates_cap = m->validator_updates_len;
            break;
        }
        case 4:
            if (!m->has_consensus_param_updates) {
                cmt_pb_store_consensus_params_init(&m->consensus_param_updates);
                m->has_consensus_param_updates = true;
            }
            if (consensus_params_merge(p, n, &m->consensus_param_updates)
                != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 5:
            if (r_copy_fixed(m->app_hash, sizeof(m->app_hash),
                             &m->app_hash_len, p, n) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

int cmt_pb_store_response_finalize_block_unmarshal(
    const uint8_t *in, size_t len, cmt_pb_response_finalize_block_t *m,
    cmt_pb_rfb_storage_t *storage)
{
    rfb_pools_t pools;

    if (m == NULL || storage == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    memset(&pools, 0, sizeof(pools));
    pools.st = storage;
    /* The decoder carves the repeated fields out of the pools: the
     * message's own pointers are set here, not by the caller. */
    memset(m, 0, sizeof(*m));
    return response_finalize_block_merge(in, len, m, &pools);
}

/* ═══════════════════════════════════════════════════════════════════════
 * ABCIResponsesInfo — state/types.pb.go:913-963
 * ═══════════════════════════════════════════════════════════════════════ */

void cmt_pb_store_abci_responses_info_init(cmt_pb_abci_responses_info_t *m)
{
    if (m == NULL) {
        return;
    }
    m->height = 0;
    m->has_response_finalize_block = false;
    cmt_pb_store_response_finalize_block_init(&m->response_finalize_block);
}

size_t cmt_pb_store_abci_responses_info_upper_bound(
    const cmt_pb_abci_responses_info_t *m)
{
    if (m == NULL) {
        return 0;
    }
    return B_VARINT + 6u +
           cmt_pb_store_response_finalize_block_upper_bound(
               &m->response_finalize_block);
}

int cmt_pb_store_abci_responses_info_marshal(
    const cmt_pb_abci_responses_info_t *m, uint8_t *out, size_t cap,
    size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (m->has_response_finalize_block) {                  /* :918-929 */
        size_t before = w.i;

        if (response_finalize_block_wr(&w, &m->response_finalize_block)
            != CMT_OK) {
            return CMT_REJECT;
        }
        wf_close_msg(&w, 3, before);
    }
    wf_varint(&w, 2, (uint64_t)m->height);                 /* :930-934 */
    /* :935-946 field 1 legacy_abci_responses: never written. */
    return w_finish(&w, out_len);
}

int cmt_pb_store_abci_responses_info_unmarshal(
    const uint8_t *in, size_t len, cmt_pb_abci_responses_info_t *m,
    cmt_pb_rfb_storage_t *storage)
{
    size_t      i = 0;
    rfb_pools_t pools;

    if (m == NULL || storage == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_pb_store_abci_responses_info_init(m);
    memset(&m->response_finalize_block, 0, sizeof(m->response_finalize_block));
    memset(&pools, 0, sizeof(pools));
    pools.st = storage;
    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        uint64_t v;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:
            /* The legacy slot: this chain has no legacy format
             * (D-23 rev 4); a value here is not this chain's. */
            return CMT_REJECT;
        case 2:
            if (wt != 0u || cmt_pb_get_uvarint(in, len, &i, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->height = (int64_t)v;
            break;
        case 3:
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_response_finalize_block = true;
            if (response_finalize_block_merge(p, n, &m->response_finalize_block,
                                              &pools) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Block — block.pb.go:222-380 Block.Unmarshal
 * ═══════════════════════════════════════════════════════════════════════ */

/* evidence.pb.go:1227-1300 — EvidenceList.Unmarshal: append one
 * Evidence per field-1 element into the caller's storage. */
static int evidence_list_merge(const uint8_t *in, size_t len,
                               cmt_evidence_data_t *ev, cmt_pb_arena_t *arena)
{
    size_t i = 0;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum == 1) {
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (ev->evidence == NULL || ev->evidence_len >= ev->evidence_cap) {
                return CMT_REJECT;
            }
            if (cmt_pb_evidence_unmarshal(p, n, &ev->evidence[ev->evidence_len],
                                          arena) != CMT_OK) {
                return CMT_REJECT;
            }
            ev->evidence_len++;
        } else {
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

int cmt_pb_block_unmarshal(const uint8_t *in, size_t len, cmt_block_t *out,
                           cmt_commit_t *last_commit, cmt_pb_arena_t *arena)
{
    size_t          i = 0;
    cmt_pb_bytes_t *txs;
    size_t          txs_cap;
    cmt_pb_evidence_t *evs;
    size_t          evs_cap;

    if (out == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    txs     = out->data.txs;
    txs_cap = out->data.txs_cap;
    evs     = out->evidence.evidence;
    evs_cap = out->evidence.evidence_cap;
    memset(out, 0, sizeof(*out));
    cmt_pb_header_init(&out->header);
    out->data.txs          = txs;
    out->data.txs_cap      = txs_cap;
    cmt_pb_data_init(&out->data);
    out->evidence.evidence     = evs;
    out->evidence.evidence_cap = evs_cap;
    out->last_commit = NULL;

    while (i < len) {
        int32_t  fieldnum;
        uint32_t wt;
        size_t   start = i;
        const uint8_t *p;
        size_t   n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fieldnum >= 1 && fieldnum <= 4) {
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
        }
        switch (fieldnum) {
        case 1:                                                /* :251-282 */
            /* DEVIATION: init+merge; a second Header REPLACES. */
            if (cmt_pb_header_unmarshal(p, n, &out->header) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:                                                /* :283-315 */
            /* DEVIATION: init+merge; a second Data REPLACES its txs where
             * the generated code would append. */
            if (cmt_pb_data_unmarshal(p, n, &out->data, arena) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 3:                                                /* :316-348 */
            if (evidence_list_merge(p, n, &out->evidence, arena) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 4:                                                /* :349-384 */
            if (last_commit == NULL) {
                return CMT_FAULT;
            }
            if (out->last_commit == NULL) {
                /* `if m.LastCommit == nil { m.LastCommit = &Commit{} }` */
                cmt_pb_commit_init(last_commit);
                out->last_commit = last_commit;
            }
            /* DEVIATION: init+merge; a second LastCommit REPLACES. */
            if (cmt_pb_commit_unmarshal(p, n, last_commit) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        default:
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;
}
