/**
 * @file shared/dnac/cmt_light_block.c
 * @brief cometbft @v0.38.26 `types.LightBlock` (types/light.go:11-112,
 *        :183-226) and the SignedHeader / LightBlock proto3 codec
 *        (types.pb.go:1949-2041, :4742-4985) in C — see cmt_light_block.h
 *        for the contract, the deviations and the taşınmadı list.
 *
 * NOTHING HERE READS A CLOCK, DRAWS RANDOMNESS OR ITERATES A MAP.
 *
 * The writer and reader primitives come from cmt_pb_wire.h — the ONE
 * definition for every proto3 codec of the port (cmt_pb_wire.h:19-28
 * names "light client" among the waves that add a codec TU and should
 * share it rather than copy it). NOTE: the includer list in that
 * header's INTERNAL banner (cmt_pb_wire.h:6-16) does not name this file;
 * that banner is outside this package's whitelist and is left as is.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_light_block.h"
#include "dnac/cmt_pb_wire.h"      /* pb_w_t, r_tag, r_ld, pb_skip */
#include "dnac/cmt_merkle.h"       /* cmt_merkle_item_t            */

#include <stdlib.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 * C-only helpers
 * ══════════════════════════════════════════════════════════════════════ */

/* Go `bytes.Equal(a, b)`: equal lengths and equal bytes; a nil slice and
 * an empty one are equal. The same helper as cmt_light_verifier.c's. */
static bool go_bytes_equal(const uint8_t *a, size_t a_len,
                           const uint8_t *b, size_t b_len)
{
    if (a_len != b_len) {
        return false;
    }
    if (a_len == 0u) {
        return true;
    }
    return memcmp(a, b, a_len) == 0;
}

/* Embedding a cmt_pb message through its PUBLIC marshal — the pattern of
 * cmt_pb_store.c:22-56: marshal into the free region [0, w->i), move the
 * result up to [w->i - n, w->i) and frame it. The bytes are those of the
 * generated in-place backward write. */
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

W_EMBED_DEFINE(w_embed_header,        cmt_pb_header_t,        cmt_pb_header_marshal)
W_EMBED_DEFINE(w_embed_commit,        cmt_pb_commit_t,        cmt_pb_commit_marshal)
W_EMBED_DEFINE(w_embed_validator_set, cmt_pb_validator_set_t, cmt_pb_validator_set_marshal)

/* ══════════════════════════════════════════════════════════════════════
 * Size bound. Every term is the widest form K-1 rev 2 allows for the
 * field: a scalar is a tag plus a 10-byte varint (any int64, any uint64,
 * and a NEGATIVE int32, which proto3 sign-extends to 10 bytes); an
 * embedded message is framed by a tag plus a 10-byte length varint; a
 * byte field is bounded by its cmt_pb capacity. Generous rather than
 * tight: it sizes a buffer, it is never written to the wire, and a value
 * that did not fit would be REFUSED by the writer (cmt_pb_wire.h w_raw),
 * never overrun.
 * ══════════════════════════════════════════════════════════════════════ */

#define LB_VARINT  11u                          /* tag + 10-byte varint     */
#define LB_FRAME   11u                          /* tag + 10-byte length     */
#define LB_HASH    (2u + CMT_PB_HASH_MAX)       /* tag + 1-byte len + 64    */
#define LB_TS_BODY (2u * LB_VARINT)             /* seconds, nanos           */
/* BlockID {hash = 1, PartSetHeader part_set_header = 2 {total, hash}}. */
#define LB_BLOCK_ID_BODY (LB_HASH + LB_FRAME + LB_VARINT + LB_HASH)
/* Header, its 14 fields (types.proto:47-71). */
#define LB_HEADER_BODY                                                     \
    ((LB_FRAME + 2u * LB_VARINT)        /* 1  version {block, app}    */   \
     + (2u + CMT_PB_CHAINID_MAX)        /* 2  chain_id                */   \
     + LB_VARINT                        /* 3  height                  */   \
     + (LB_FRAME + LB_TS_BODY)          /* 4  time                    */   \
     + (LB_FRAME + LB_BLOCK_ID_BODY)    /* 5  last_block_id           */   \
     + 8u * LB_HASH                     /* 6-13 the eight hashes      */   \
     + (2u + CMT_PB_ADDRESS_MAX))       /* 14 proposer_address        */
/* Commit {height = 1, round = 2, block_id = 3} without its signatures. */
#define LB_COMMIT_FIXED (2u * LB_VARINT + LB_FRAME + LB_BLOCK_ID_BODY)
/* One framed CommitSig {flag, address, timestamp, signature}; the
 * signature's length (4627) is a 2-byte varint. */
#define LB_PER_SIG                                                         \
    (LB_FRAME + LB_VARINT + (2u + CMT_PB_ADDRESS_MAX) +                    \
     (LB_FRAME + LB_TS_BODY) + (3u + CMT_PB_SIG_MAX))
/* One framed Validator {address, PublicKey pub_key {field 9: 2592 bytes},
 * voting_power, proposer_priority}. */
#define LB_PER_VAL                                                         \
    (LB_FRAME + (2u + CMT_PB_ADDRESS_MAX) +                                \
     (LB_FRAME + 3u + CMT_PB_PUBKEY_LEN) + 2u * LB_VARINT)

size_t cmt_pb_light_block_upper_bound(size_t n_validators,
                                      size_t n_signatures)
{
    if (n_validators > (size_t)CMT_VALSET_MAX ||
        n_signatures > (size_t)CMT_VALSET_MAX) {
        return 0u;
    }
    return LB_FRAME                                   /* LightBlock.1     */
           + LB_FRAME + LB_HEADER_BODY                /* SignedHeader.1   */
           + LB_FRAME + LB_COMMIT_FIXED +
             n_signatures * LB_PER_SIG                /* SignedHeader.2   */
           + LB_FRAME                                 /* LightBlock.2     */
           + (n_validators + 1u) * LB_PER_VAL         /* validators + proposer */
           + LB_VARINT;                               /* total_voting_power */
}

/* ══════════════════════════════════════════════════════════════════════
 * SignedHeader — types.pb.go:1949-1994, :4742-4863
 * ══════════════════════════════════════════════════════════════════════ */

void cmt_pb_signed_header_init(cmt_pb_signed_header_t *m)
{
    if (m == NULL) {
        return;
    }
    m->has_header = false;
    cmt_pb_header_init(&m->header);
    m->has_commit = false;
    cmt_pb_commit_init(&m->commit);     /* keeps the caller's storage */
}

/* types.pb.go:1964-1994 — backwards: field 2 first, then field 1. */
static void signed_header_wr(pb_w_t *w, const cmt_pb_signed_header_t *m)
{
    if (m->has_commit) {                                   /* :1969-1980 */
        w_embed_commit(w, 2, &m->commit);
    }
    if (m->has_header) {                                   /* :1981-1992 */
        w_embed_header(w, 1, &m->header);
    }
}

int cmt_pb_signed_header_marshal(const cmt_pb_signed_header_t *m,
                                 uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    signed_header_wr(&w, m);
    return w_finish(&w, out_len);
}

/* types.pb.go:4742-4863 — SignedHeader.Unmarshal, on an EXISTING message
 * (the generated `m.SignedHeader.Unmarshal` of :4925 runs on a message
 * that may already hold a first occurrence). DEVIATION (file header):
 * fields 1 and 2 are read with cmt_pb's public `_unmarshal`, so a second
 * occurrence REPLACES where :4800-4803 / :4836-4839 merge. */
static int signed_header_merge(const uint8_t *in, size_t len,
                               cmt_pb_signed_header_t *m)
{
    size_t i = 0;

    while (i < len) {                                           /* :4745 */
        int32_t        fieldnum;
        uint32_t       wt;
        size_t         start = i;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {     /* :4746-4769 */
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:                                                 /* :4771-4806 */
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_header_unmarshal(p, n, &m->header) != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_header = true;
            break;
        case 2:                                                 /* :4807-4842 */
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_commit_unmarshal(p, n, &m->commit) != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_commit = true;
            break;
        default:                                                /* :4843-4856 */
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;                                              /* :4859-4862 */
}

int cmt_pb_signed_header_unmarshal(const uint8_t *in, size_t len,
                                   cmt_pb_signed_header_t *m)
{
    if (m == NULL || (in == NULL && len != 0u)) {
        return CMT_FAULT;
    }
    cmt_pb_signed_header_init(m);
    return signed_header_merge(in, len, m);
}

/* ══════════════════════════════════════════════════════════════════════
 * LightBlock — types.pb.go:1996-2041, :4864-4985
 * ══════════════════════════════════════════════════════════════════════ */

void cmt_pb_light_block_init(cmt_pb_light_block_t *m)
{
    if (m == NULL) {
        return;
    }
    m->has_signed_header = false;
    cmt_pb_signed_header_init(&m->signed_header);
    m->has_validator_set = false;
    cmt_pb_validator_set_init(&m->validator_set);  /* keeps the storage */
}

int cmt_pb_light_block_marshal(const cmt_pb_light_block_t *m,
                               uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    if (m->has_validator_set) {                            /* :2016-2027 */
        w_embed_validator_set(&w, 2, &m->validator_set);
    }
    if (m->has_signed_header) {                            /* :2028-2039 */
        size_t before = w.i;

        signed_header_wr(&w, &m->signed_header);
        wf_close_msg(&w, 1, before);
    }
    return w_finish(&w, out_len);
}

/* types.pb.go:4864-4985 — LightBlock.Unmarshal. */
int cmt_pb_light_block_unmarshal(const uint8_t *in, size_t len,
                                 cmt_pb_light_block_t *m)
{
    size_t i = 0;

    if (m == NULL || (in == NULL && len != 0u)) {
        return CMT_FAULT;
    }
    cmt_pb_light_block_init(m);
    while (i < len) {                                           /* :4867 */
        int32_t        fieldnum;
        uint32_t       wt;
        size_t         start = i;
        const uint8_t *p;
        size_t         n;

        if (r_tag(in, len, &i, &fieldnum, &wt) != CMT_OK) {     /* :4868-4891 */
            return CMT_REJECT;
        }
        switch (fieldnum) {
        case 1:                                                 /* :4893-4928 */
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            /* :4922-4925 — allocate on first sight, then MERGE: this
             * level's decoder is this file's own, so it merges as the
             * generated code does. */
            if (!m->has_signed_header) {
                cmt_pb_signed_header_init(&m->signed_header);
                m->has_signed_header = true;
            }
            if (signed_header_merge(p, n, &m->signed_header) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        case 2:                                                 /* :4929-4964 */
            /* DEVIATION (file header): cmt_pb's public `_unmarshal`, so a
             * second occurrence REPLACES where :4958-4961 merge. */
            if (wt != 2u || r_ld(in, len, &i, &p, &n) != CMT_OK ||
                cmt_pb_validator_set_unmarshal(p, n, &m->validator_set)
                    != CMT_OK) {
                return CMT_REJECT;
            }
            m->has_validator_set = true;
            break;
        default:                                                /* :4965-4978 */
            i = start;
            if (pb_skip(in, len, &i) != CMT_OK) {
                return CMT_REJECT;
            }
            break;
        }
    }
    return CMT_OK;                                              /* :4981-4984 */
}

/* ══════════════════════════════════════════════════════════════════════
 * types/light.go — ValidateBasic
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 types/light.go:18-44 — (lb LightBlock) ValidateBasic(chainID) */
int cmt_light_block_validate_basic(const cmt_light_block_t *lb,
                                   const uint8_t *chain_id,
                                   size_t chain_id_len,
                                   uint64_t block_protocol)
{
    uint8_t           *scratch = NULL;
    cmt_merkle_item_t *items   = NULL;
    uint8_t            vals_hash[CMT_TMHASH_SIZE];
    const cmt_header_t *h;
    size_t             n;
    int                rc;

    if (lb == NULL) {
        return CMT_FAULT;   /* the reference takes LightBlock by value */
    }
    if (chain_id == NULL && chain_id_len != 0u) {
        return CMT_FAULT;
    }
    if (lb->signed_header == NULL) {
        return CMT_REJECT;                 /* :22-24 "missing signed header" */
    }
    if (lb->validator_set == NULL) {
        return CMT_REJECT;                 /* :25-27 "missing validator set" */
    }

    rc = cmt_signed_header_validate_basic(lb->signed_header, chain_id,
                                          chain_id_len, block_protocol);
    if (rc != CMT_OK) {
        return rc;                         /* :29-31 "invalid signed header" */
    }
    rc = cmt_validator_set_validate_basic(lb->validator_set);
    if (rc != CMT_OK) {
        return rc;                         /* :32-34 "invalid validator set" */
    }

    /* :36-37 — `lb.ValidatorSet.Hash()`. The leaf scratch is sized as
     * cmt_light_verifier.c:198-225 sizes it. */
    n = lb->validator_set->validators_len;
    if (n > (size_t)CMT_VALSET_MAX) {
        return CMT_FAULT;   /* the type's own invariant, not an input */
    }
    if (n != 0u) {
        scratch = malloc(n * (size_t)CMT_VALIDATOR_BYTES_MAX);
        items   = calloc(n, sizeof(*items));
        if (scratch == NULL || items == NULL) {
            free(scratch);
            free(items);
            return CMT_FAULT;
        }
    }
    rc = cmt_validator_set_hash(lb->validator_set, scratch,
                                n * (size_t)CMT_VALIDATOR_BYTES_MAX,
                                items, n, vals_hash);
    free(scratch);
    free(items);
    if (rc != CMT_OK) {
        return rc;
    }

    /* :37 — `lb.ValidatorsHash` through the embedded header, which :29
     * has just proved present. */
    h = lb->signed_header->header;
    if (!go_bytes_equal(h->validators_hash, h->validators_hash_len,
                        vals_hash, sizeof(vals_hash))) {
        return CMT_REJECT;   /* :37-41 "expected validator hash of header to match validator set hash" */
    }
    return CMT_OK;                                               /* :43 */
}

/* ══════════════════════════════════════════════════════════════════════
 * types/light.go — ToProto / FromProto
 * ══════════════════════════════════════════════════════════════════════ */

/* cometbft@v0.38.26 types/light.go:183-198 — (sh *SignedHeader) ToProto() */
int cmt_signed_header_to_proto(const cmt_signed_header_t *sh,
                               cmt_pb_signed_header_t *out)
{
    int rc;

    if (sh == NULL || out == NULL) {
        return CMT_FAULT;   /* :185-187 nil receiver — R1B-10 */
    }
    cmt_pb_signed_header_init(out);                             /* :189 */
    if (sh->header != NULL) {                                   /* :190-192 */
        rc = cmt_header_to_proto(sh->header, &out->header);
        if (rc != CMT_OK) {
            return rc;
        }
        out->has_header = true;
    }
    if (sh->commit != NULL) {                                   /* :193-195 */
        rc = cmt_commit_to_proto(sh->commit, &out->commit);
        if (rc != CMT_OK) {
            return rc;
        }
        out->has_commit = true;
    }
    return CMT_OK;                                              /* :197 */
}

/* cometbft@v0.38.26 types/light.go:200-226 — SignedHeaderFromProto() */
int cmt_signed_header_from_proto(const cmt_pb_signed_header_t *shp,
                                 uint64_t block_protocol,
                                 cmt_header_t *h,
                                 cmt_commit_sig_t *sigs, size_t sigs_cap,
                                 cmt_commit_t *c,
                                 cmt_signed_header_t *out)
{
    int rc;

    if (shp == NULL || h == NULL || c == NULL || out == NULL) {
        return CMT_FAULT;   /* :203-205 "nil SignedHeader" — R1B-10 */
    }
    out->header = NULL;                                         /* :207 */
    out->commit = NULL;

    if (shp->has_header) {                                      /* :209-215 */
        rc = cmt_header_from_proto(&shp->header, block_protocol, h);
        if (rc != CMT_OK) {
            return rc;
        }
        out->header = h;
    }
    if (shp->has_commit) {                                      /* :217-223 */
        rc = cmt_commit_from_proto(&shp->commit, sigs, sigs_cap, c);
        if (rc != CMT_OK) {
            out->header = NULL;
            return rc;
        }
        out->commit = c;
    }
    return CMT_OK;                                              /* :225 */
}

/* cometbft@v0.38.26 types/light.go:65-84 — (lb *LightBlock) ToProto() */
int cmt_light_block_to_proto(const cmt_light_block_t *lb,
                             cmt_pb_light_block_t *out)
{
    int rc;

    if (lb == NULL || out == NULL) {
        return CMT_FAULT;   /* :67-69 nil receiver — R1B-10 */
    }
    cmt_pb_light_block_init(out);                               /* :71 */
    if (lb->signed_header != NULL) {                            /* :73-75 */
        rc = cmt_signed_header_to_proto(lb->signed_header,
                                        &out->signed_header);
        if (rc != CMT_OK) {
            return rc;
        }
        out->has_signed_header = true;
    }
    if (lb->validator_set != NULL) {                            /* :76-81 */
        rc = cmt_validator_set_to_proto(lb->validator_set,
                                        &out->validator_set);
        if (rc != CMT_OK) {
            return rc;                                          /* :78-80 */
        }
        out->has_validator_set = true;
    }
    return CMT_OK;                                              /* :83 */
}

cmt_light_block_buf_t *cmt_light_block_buf_new(void)
{
    cmt_light_block_buf_t *b = calloc(1, sizeof(*b));

    if (b == NULL) {
        return NULL;
    }
    b->lb.signed_header = NULL;
    b->lb.validator_set = NULL;
    return b;
}

void cmt_light_block_buf_free(cmt_light_block_buf_t *b)
{
    free(b);
}

/* Reset `b` to the empty light block, so that nothing of an earlier
 * decode survives a failed one. The two big arrays are not cleared: no
 * pointer aims at them until a decode succeeds. */
int cmt_light_block_buf_reset(cmt_light_block_buf_t *b)
{
    if (b == NULL) {
        return CMT_FAULT;
    }
    b->lb.signed_header       = NULL;
    b->lb.validator_set       = NULL;
    b->signed_header.header   = NULL;
    b->signed_header.commit   = NULL;
    cmt_pb_header_init(&b->header);
    cmt_pb_commit_init(&b->commit);
    b->commit.signatures      = NULL;
    b->commit.signatures_cap  = 0u;
    if (cmt_validator_set_init(&b->validator_set, b->validators,
                               (size_t)CMT_VALSET_MAX) != CMT_OK) {
        return CMT_FAULT;   /* CMT_VALSET_MAX storage: cannot fail */
    }
    return CMT_OK;
}

/* cometbft@v0.38.26 types/light.go:86-112 — LightBlockFromProto() */
int cmt_light_block_from_proto(const cmt_pb_light_block_t *pb,
                               uint64_t block_protocol,
                               cmt_light_block_buf_t *out)
{
    int rc;

    if (pb == NULL || out == NULL) {
        return CMT_FAULT;   /* :89-91 "nil light block" — R1B-10 */
    }
    rc = cmt_light_block_buf_reset(out);                        /* :93 */
    if (rc != CMT_OK) {
        return rc;
    }

    if (pb->has_signed_header) {                                /* :95-101 */
        rc = cmt_signed_header_from_proto(&pb->signed_header,
                                          block_protocol, &out->header,
                                          out->sigs, (size_t)CMT_VALSET_MAX,
                                          &out->commit,
                                          &out->signed_header);
        if (rc != CMT_OK) {
            (void)cmt_light_block_buf_reset(out);
            return rc;
        }
    }

    if (pb->has_validator_set) {                                /* :103-109 */
        rc = cmt_validator_set_from_proto(&pb->validator_set,
                                          &out->validator_set);
        if (rc != CMT_OK) {
            (void)cmt_light_block_buf_reset(out);
            return rc;
        }
    }

    if (pb->has_signed_header) {
        out->lb.signed_header = &out->signed_header;            /* :100 */
    }
    if (pb->has_validator_set) {
        out->lb.validator_set = &out->validator_set;            /* :108 */
    }
    return CMT_OK;                                              /* :111 */
}

/* ══════════════════════════════════════════════════════════════════════
 * The two-step forms the store uses (light/store/db/db.go:47-55, :120-129)
 * ══════════════════════════════════════════════════════════════════════ */

int cmt_light_block_encode(const cmt_light_block_t *lb,
                           uint8_t **out, size_t *out_len)
{
    cmt_pb_light_block_t *pb    = NULL;
    cmt_pb_validator_t   *pvals = NULL;
    uint8_t              *buf   = NULL;
    size_t                n_v   = 0u;
    size_t                n_s   = 0u;
    size_t                cap;
    size_t                len   = 0u;
    int                   rc;

    if (out != NULL) {
        *out = NULL;
    }
    if (out_len != NULL) {
        *out_len = 0u;
    }
    if (lb == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    if (lb->validator_set != NULL) {
        n_v = lb->validator_set->validators_len;
        if (n_v > (size_t)CMT_VALSET_MAX) {
            return CMT_FAULT;   /* the type's own invariant */
        }
    }
    if (lb->signed_header != NULL && lb->signed_header->commit != NULL) {
        n_s = lb->signed_header->commit->signatures_len;
        if (n_s > (size_t)CMT_VALSET_MAX) {
            return CMT_REJECT;  /* the decoder's capacity rule (header) */
        }
    }

    pb    = calloc(1, sizeof(*pb));
    pvals = calloc(n_v != 0u ? n_v : 1u, sizeof(*pvals));
    if (pb == NULL || pvals == NULL) {
        free(pb);
        free(pvals);
        return CMT_FAULT;
    }
    pb->validator_set.validators     = pvals;
    pb->validator_set.validators_cap = n_v;

    rc = cmt_light_block_to_proto(lb, pb);                  /* db.go:47-50 */
    if (rc == CMT_OK) {
        cap = cmt_pb_light_block_upper_bound(n_v, n_s);
        buf = malloc(cap);
        if (buf == NULL) {
            rc = CMT_FAULT;
        } else {
            rc = cmt_pb_light_block_marshal(pb, buf, cap, &len); /* :52-55 */
        }
    }
    free(pvals);
    free(pb);
    if (rc != CMT_OK) {
        free(buf);
        return rc;
    }
    *out     = buf;
    *out_len = len;
    return CMT_OK;
}

int cmt_light_block_decode(const uint8_t *in, size_t len,
                           uint64_t block_protocol,
                           cmt_light_block_buf_t *out)
{
    cmt_pb_light_block_t *pb    = NULL;
    cmt_pb_commit_sig_t  *psigs = NULL;
    cmt_pb_validator_t   *pvals = NULL;
    int                   rc;

    if (out == NULL || (in == NULL && len != 0u)) {
        return CMT_FAULT;
    }
    if (cmt_light_block_buf_reset(out) != CMT_OK) {
        return CMT_FAULT;
    }

    pb    = calloc(1, sizeof(*pb));
    psigs = calloc((size_t)CMT_VALSET_MAX, sizeof(*psigs));
    pvals = calloc((size_t)CMT_VALSET_MAX, sizeof(*pvals));
    if (pb == NULL || psigs == NULL || pvals == NULL) {
        free(pb);
        free(psigs);
        free(pvals);
        return CMT_FAULT;
    }
    pb->signed_header.commit.signatures     = psigs;
    pb->signed_header.commit.signatures_cap = (size_t)CMT_VALSET_MAX;
    pb->validator_set.validators            = pvals;
    pb->validator_set.validators_cap        = (size_t)CMT_VALSET_MAX;

    rc = cmt_pb_light_block_unmarshal(in, len, pb);        /* db.go:120-124 */
    if (rc == CMT_OK) {
        rc = cmt_light_block_from_proto(pb, block_protocol, out); /* :126-129 */
    }
    free(pvals);
    free(psigs);
    free(pb);
    return rc;
}
