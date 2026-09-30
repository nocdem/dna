/**
 * @file shared/dnac/cmt_bsync_msgs.c
 * @brief cometbft @v0.38.26 blocksync messages in C — see
 *        cmt_bsync_msgs.h for the wire rules and the merge rule.
 *
 * NOTHING HERE READS A CLOCK, DRAWS RANDOMNESS OR ITERATES A MAP.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_bsync_msgs.h"
#include "dnac/cmt_pb_wire.h"

#include <stdlib.h>
#include <string.h>

/* ══ helpers ══════════════════════════════════════════════════════════ */

void cmt_bsync_msg_init(cmt_bsync_msg_t *m)
{
    if (m != NULL) {
        memset(m, 0, sizeof(*m));
        m->kind = CMT_BSYNC_MSG_NONE;
    }
}

void cmt_bsync_msg_release(cmt_bsync_msg_t *m)
{
    if (m == NULL) {
        return;
    }
    free(m->block_owned);
    free(m->ext_owned);
    cmt_bsync_msg_init(m);
}

/* sovTypes (types.pb.go:869-871) of an int64 field value: the generated
 * code encodes `uint64(v)`, so a negative value is ten bytes. */
static size_t i64_field_size(int64_t v)
{
    if (v == 0) {
        return 0;                                  /* omitted: :444 etc. */
    }
    return 1u + cmt_pb_uvarint_size((uint64_t)v);  /* tag + varint       */
}

/* The body size of the member `m->kind` (types.pb.go:731-794). */
static size_t body_size(const cmt_bsync_msg_t *m)
{
    size_t n = 0;

    switch (m->kind) {
    case CMT_BSYNC_MSG_BLOCK_REQUEST:                              /* :731-741 */
    case CMT_BSYNC_MSG_NO_BLOCK_RESPONSE:                          /* :743-753 */
        return i64_field_size(m->height);
    case CMT_BSYNC_MSG_BLOCK_RESPONSE:                             /* :755-770 */
        if (m->has_block) {
            n += 1u + cmt_pb_uvarint_size((uint64_t)m->block_len) + m->block_len;
        }
        if (m->has_ext_commit) {
            n += 1u + cmt_pb_uvarint_size((uint64_t)m->ext_commit_len) +
                 m->ext_commit_len;
        }
        return n;
    case CMT_BSYNC_MSG_STATUS_REQUEST:                             /* :772-779 */
        return 0;
    case CMT_BSYNC_MSG_STATUS_RESPONSE:                            /* :781-794 */
        return i64_field_size(m->height) + i64_field_size(m->base);
    default:
        return 0;
    }
}

/* ══ Size / Marshal ═══════════════════════════════════════════════════ */

/* types.pb.go:796-867 — Message.Size(): the member is always framed
 * (:808-867: `l = m.X.Size(); n += 1 + l + sovTypes(uint64(l))`). */
size_t cmt_bsync_msg_size(const cmt_bsync_msg_t *m)
{
    size_t l;

    if (m == NULL || m->kind == CMT_BSYNC_MSG_NONE) {
        return 0;                                          /* :799 Sum nil */
    }
    if (m->kind < CMT_BSYNC_MSG_BLOCK_REQUEST ||
        m->kind > CMT_BSYNC_MSG_STATUS_RESPONSE) {
        return 0;
    }
    l = body_size(m);
    return 1u + cmt_pb_uvarint_size((uint64_t)l) + l;
}

/* types.pb.go:583-718 — Message.Marshal() and the five member writers. */
int cmt_bsync_msg_marshal(const cmt_bsync_msg_t *m, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    pb_w_t w;
    size_t before;

    if (m == NULL || out_len == NULL || (out == NULL && cap != 0)) {
        return CMT_FAULT;
    }
    if (m->kind == CMT_BSYNC_MSG_BLOCK_RESPONSE &&
        ((m->has_block && m->block == NULL && m->block_len != 0) ||
         (m->has_ext_commit && m->ext_commit == NULL &&
          m->ext_commit_len != 0))) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (m->kind == CMT_BSYNC_MSG_NONE) {
        return w_finish(&w, out_len);                      /* :603 Sum nil */
    }
    before = w.i;
    switch (m->kind) {
    case CMT_BSYNC_MSG_BLOCK_REQUEST:          /* :439-450 then :620-634 */
        wf_varint(&w, 1, (uint64_t)m->height);
        wf_close_msg(&w, 1, before);                             /* 0x0a */
        break;
    case CMT_BSYNC_MSG_NO_BLOCK_RESPONSE:      /* :467-478 then :641-655 */
        wf_varint(&w, 1, (uint64_t)m->height);
        wf_close_msg(&w, 2, before);                             /* 0x12 */
        break;
    case CMT_BSYNC_MSG_BLOCK_RESPONSE:         /* :495-525 then :662-676 */
        if (m->has_ext_commit) {                                 /* :500 */
            w_raw(&w, m->ext_commit, m->ext_commit_len);
            w_uvarint(&w, (uint64_t)m->ext_commit_len);
            w_tag(&w, 2, 2);                                     /* 0x12 */
        }
        if (m->has_block) {                                      /* :512 */
            w_raw(&w, m->block, m->block_len);
            w_uvarint(&w, (uint64_t)m->block_len);
            w_tag(&w, 1, 2);                                     /* 0x0a */
        }
        wf_close_msg(&w, 3, before);                             /* 0x1a */
        break;
    case CMT_BSYNC_MSG_STATUS_REQUEST:         /* :542-548 then :683-697 */
        wf_close_msg(&w, 4, before);                             /* 0x22 */
        break;
    case CMT_BSYNC_MSG_STATUS_RESPONSE:        /* :565-581 then :704-718 */
        wf_varint(&w, 2, (uint64_t)m->base);                     /* :570 */
        wf_varint(&w, 1, (uint64_t)m->height);                   /* :575 */
        wf_close_msg(&w, 5, before);                             /* 0x2a */
        break;
    default:
        return CMT_FAULT;
    }
    return w_finish(&w, out_len);
}

/* ══ Unmarshal ════════════════════════════════════════════════════════ */

/* The body of BlockRequest / NoBlockResponse (:875-1012): field 1 is an
 * int64 (wire type 0), every other field is skipped. */
static int unmarshal_height_body(const uint8_t *in, size_t len, int64_t *h)
{
    size_t off = 0;

    *h = 0;
    while (off < len) {
        size_t   pre = off;
        int32_t  fn;
        uint32_t wt;
        uint64_t v;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;                            /* :897-902 */
        }
        if (fn == 1) {
            if (wt != 0u) {
                return CMT_REJECT;                        /* :905-907 */
            }
            if (cmt_pb_get_uvarint(in, len, &off, &v) != CMT_OK) {
                return CMT_REJECT;                        /* :909-922 */
            }
            *h = (int64_t)v;
        } else {
            off = pre;                                    /* :924 */
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;                        /* :925-935 */
            }
        }
    }
    return CMT_OK;
}

/* StatusRequest (:1135-1184): no fields; everything is skipped. */
static int unmarshal_empty_body(const uint8_t *in, size_t len)
{
    size_t off = 0;

    while (off < len) {
        size_t   pre = off;
        int32_t  fn;
        uint32_t wt;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;                            /* :1157-1162 */
        }
        off = pre;
        if (pb_skip(in, len, &off) != CMT_OK) {
            return CMT_REJECT;                            /* :1165-1176 */
        }
    }
    return CMT_OK;
}

/* StatusResponse (:1185-1272): height = 1, base = 2, both wire type 0. */
static int unmarshal_status_body(const uint8_t *in, size_t len,
                                 int64_t *height, int64_t *base)
{
    size_t off = 0;

    *height = 0;
    *base   = 0;
    while (off < len) {
        size_t   pre = off;
        int32_t  fn;
        uint32_t wt;
        uint64_t v;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;                            /* :1207-1212 */
        }
        if (fn == 1 || fn == 2) {
            if (wt != 0u) {
                return CMT_REJECT;                        /* :1215, :1234 */
            }
            if (cmt_pb_get_uvarint(in, len, &off, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fn == 1) {
                *height = (int64_t)v;                     /* :1218-1232 */
            } else {
                *base = (int64_t)v;                       /* :1237-1251 */
            }
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;                        /* :1253-1264 */
            }
        }
    }
    return CMT_OK;
}

/* One more occurrence of a merged field (header, "merge rule"): the first
 * occurrence is a view; from the second on, the concatenation is an owned
 * copy. */
static int merge_append(const uint8_t **view, size_t *view_len, bool *has,
                        uint8_t **owned, const uint8_t *p, size_t n)
{
    uint8_t *nb;

    if (!*has) {
        *view     = p;
        *view_len = n;
        *has      = true;
        return CMT_OK;
    }
    if (n > SIZE_MAX - *view_len) {
        return CMT_REJECT;
    }
    if (*owned == NULL) {
        nb = (uint8_t *)malloc(*view_len + n + 1u);
        if (nb == NULL) {
            return CMT_FAULT;
        }
        if (*view_len != 0) {
            memcpy(nb, *view, *view_len);
        }
    } else {
        nb = (uint8_t *)realloc(*owned, *view_len + n + 1u);
        if (nb == NULL) {
            return CMT_FAULT;
        }
    }
    if (n != 0) {
        memcpy(nb + *view_len, p, n);
    }
    *owned    = nb;
    *view     = nb;
    *view_len += n;
    return CMT_OK;
}

/* BlockResponse (:1013-1134): field 1 Block and field 2 ExtendedCommit,
 * both wire type 2 and both MERGED across occurrences (:1071-1076,
 * :1107-1112). Their contents are decoded by the reactor (header). */
static int unmarshal_block_response_body(const uint8_t *in, size_t len,
                                         cmt_bsync_msg_t *out)
{
    size_t off = 0;
    int    rc;

    while (off < len) {
        size_t         pre = off;
        int32_t        fn;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;                            /* :1035-1040 */
        }
        if (fn == 1 || fn == 2) {
            if (wt != 2u) {
                return CMT_REJECT;                        /* :1043, :1079 */
            }
            if (r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;                        /* :1046-1070 */
            }
            if (fn == 1) {
                rc = merge_append(&out->block, &out->block_len,
                                  &out->has_block, &out->block_owned, p, n);
            } else {
                rc = merge_append(&out->ext_commit, &out->ext_commit_len,
                                  &out->has_ext_commit, &out->ext_owned, p, n);
            }
            if (rc != CMT_OK) {
                return rc;
            }
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;                        /* :1115-1126 */
            }
        }
    }
    return CMT_OK;
}

/* types.pb.go:1273-1497 — Message.Unmarshal() */
int cmt_bsync_msg_unmarshal(const uint8_t *in, size_t len,
                            cmt_bsync_msg_t *out)
{
    size_t off = 0;
    int    rc;

    if (out == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    cmt_bsync_msg_release(out);
    while (off < len) {
        size_t         pre = off;
        int32_t        fn;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            rc = CMT_REJECT;                              /* :1295-1300 */
            goto fail;
        }
        if (fn < 1 || fn > 5) {
            off = pre;                                    /* :1477-1489 */
            if (pb_skip(in, len, &off) != CMT_OK) {
                rc = CMT_REJECT;
                goto fail;
            }
            continue;
        }
        if (wt != 2u) {
            rc = CMT_REJECT;          /* :1303, :1338, :1373, :1408, :1443 */
            goto fail;
        }
        if (r_ld(in, len, &off, &p, &n) != CMT_OK) {
            rc = CMT_REJECT;          /* msglen / postIndex checks        */
            goto fail;
        }
        /* `v := &X{}` then `m.Sum = &Message_X{v}` — a FRESH member each
         * time, replacing whatever the Sum held (last wins). */
        cmt_bsync_msg_release(out);
        switch (fn) {
        case 1:                                           /* :1302-1336 */
            rc = unmarshal_height_body(p, n, &out->height);
            out->kind = CMT_BSYNC_MSG_BLOCK_REQUEST;
            break;
        case 2:                                           /* :1337-1371 */
            rc = unmarshal_height_body(p, n, &out->height);
            out->kind = CMT_BSYNC_MSG_NO_BLOCK_RESPONSE;
            break;
        case 3:                                           /* :1372-1406 */
            rc = unmarshal_block_response_body(p, n, out);
            out->kind = CMT_BSYNC_MSG_BLOCK_RESPONSE;
            break;
        case 4:                                           /* :1407-1441 */
            rc = unmarshal_empty_body(p, n);
            out->kind = CMT_BSYNC_MSG_STATUS_REQUEST;
            break;
        default:                                          /* :1442-1476 */
            rc = unmarshal_status_body(p, n, &out->height, &out->base);
            out->kind = CMT_BSYNC_MSG_STATUS_RESPONSE;
            break;
        }
        if (rc != CMT_OK) {
            goto fail;
        }
    }
    return CMT_OK;                                        /* :1493-1496 */

fail:
    cmt_bsync_msg_release(out);
    return rc;
}

/* ══ SigCount stub (cometbft@v0.38.26 proto/tendermint/blocksync/
 *    stub.pb.go:561-1102, nosig.go) — see the header ══════════════════ */

static void count_inc(size_t *n)
{
    if (*n != SIZE_MAX) {
        (*n)++;
    }
}

/* SigCountCommit / SigCountExtendedCommit .Unmarshal (:855-939,
 * :940-1024): field 4 is a repeated NoSig, counted and never read. */
static int stub_sigs(const uint8_t *in, size_t len, size_t *count)
{
    size_t off = 0;

    while (off < len) {
        size_t         pre = off;
        int32_t        fn;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn == 4) {
            if (wt != 2u || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;                        /* :885, :970 */
            }
            count_inc(count);                             /* :914, :999 */
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* SigCountBlock.Unmarshal (:769-854): field 4 last_commit, merged. */
static int stub_block(const uint8_t *in, size_t len, size_t *commit_sigs)
{
    size_t off = 0;

    while (off < len) {
        size_t         pre = off;
        int32_t        fn;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn == 4) {
            if (wt != 2u || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;                        /* :799 */
            }
            if (stub_sigs(p, n, commit_sigs) != CMT_OK) {  /* :827-831 */
                return CMT_REJECT;
            }
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* SigCountBlockResponse.Unmarshal (:647-768): block 1, ext_commit 2,
 * both merged. */
static int stub_block_response(const uint8_t *in, size_t len,
                               size_t *commit_sigs, size_t *ext_sigs)
{
    size_t off = 0;

    while (off < len) {
        size_t         pre = off;
        int32_t        fn;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn == 1 || fn == 2) {
            if (wt != 2u || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;                        /* :677, :713 */
            }
            if ((fn == 1 ? stub_block(p, n, commit_sigs)          /* :705 */
                         : stub_sigs(p, n, ext_sigs)) != CMT_OK) { /* :741 */
                return CMT_REJECT;
            }
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* SigCountMessage.Unmarshal (:561-646): field 3 block_response, merged
 * across occurrences (:619); every other field skipped. */
int cmt_bsync_msg_sig_count(const uint8_t *in, size_t len,
                            bool *out_is_block_response,
                            size_t *out_commit_sigs, size_t *out_ext_sigs)
{
    size_t off = 0;

    if (out_is_block_response == NULL || out_commit_sigs == NULL ||
        out_ext_sigs == NULL || (in == NULL && len != 0)) {
        return CMT_FAULT;
    }
    *out_is_block_response = false;
    *out_commit_sigs       = 0;
    *out_ext_sigs          = 0;
    while (off < len) {
        size_t         pre = off;
        int32_t        fn;
        uint32_t       wt;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;                            /* :583-588 */
        }
        if (fn == 3) {
            if (wt != 2u || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;                        /* :591-618 */
            }
            *out_is_block_response = true;                /* :619-621 */
            if (stub_block_response(p, n, out_commit_sigs,
                                    out_ext_sigs) != CMT_OK) {
                return CMT_REJECT;                        /* :622-624 */
            }
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;                        /* :626-638 */
            }
        }
    }
    return CMT_OK;
}

/* ══ ValidateMsg (msgs.go:21-56) ══════════════════════════════════════ */

int cmt_bsync_validate_msg(const cmt_bsync_msg_t *m, cmt_bsync_msg_err_t *err)
{
    cmt_bsync_msg_err_t e = CMT_BSYNC_MSG_ERR_NONE;

    if (m == NULL) {
        if (err != NULL) {
            *err = CMT_BSYNC_MSG_ERR_NIL_MESSAGE;
        }
        return CMT_FAULT;
    }
    switch (m->kind) {
    case CMT_BSYNC_MSG_BLOCK_REQUEST:                             /* :28 */
        if (m->height < 0) {
            e = CMT_BSYNC_MSG_ERR_INVALID_HEIGHT;                 /* :29-31 */
        }
        break;
    case CMT_BSYNC_MSG_BLOCK_RESPONSE:                            /* :32-35 */
        break;
    case CMT_BSYNC_MSG_NO_BLOCK_RESPONSE:                         /* :36 */
        if (m->height < 0) {
            e = CMT_BSYNC_MSG_ERR_INVALID_HEIGHT;                 /* :37-39 */
        }
        break;
    case CMT_BSYNC_MSG_STATUS_RESPONSE:                           /* :40 */
        if (m->base < 0) {
            e = CMT_BSYNC_MSG_ERR_INVALID_BASE;                   /* :41-43 */
        } else if (m->height < 0) {
            e = CMT_BSYNC_MSG_ERR_INVALID_HEIGHT;                 /* :44-46 */
        } else if (m->base > m->height) {
            e = CMT_BSYNC_MSG_ERR_INVALID_HEIGHT;                 /* :47-49 */
        }
        break;
    case CMT_BSYNC_MSG_STATUS_REQUEST:                            /* :50-51 */
        break;
    case CMT_BSYNC_MSG_NONE:
        e = CMT_BSYNC_MSG_ERR_NIL_MESSAGE;                        /* :23-25 */
        break;
    default:
        e = CMT_BSYNC_MSG_ERR_UNKNOWN_TYPE;                       /* :52-53 */
        break;
    }
    if (err != NULL) {
        *err = e;
    }
    return e == CMT_BSYNC_MSG_ERR_NONE ? CMT_OK : CMT_REJECT;     /* :55 */
}
