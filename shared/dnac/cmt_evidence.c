/**
 * @file shared/dnac/cmt_evidence.c
 * @brief cometbft @709fd12b `types/evidence.go` in C — see cmt_evidence.h
 *        for the contract, the substitutions and the taşınmadı list.
 *
 * NOTHING HERE READS A CLOCK, DRAWS RANDOMNESS OR ITERATES A MAP. The only
 * allocations are transient marshal buffers, freed on every path
 * (deviation register R1B-11).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_evidence.h"

#include <stdlib.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 * Size bounds.
 *
 * REPRODUCED from cmt_block.c:116-144, where the same two helpers are
 * file-static and are still needed there by `cmt_evidence_data_byte_size`
 * (block.go:1388-1398), which bounds the WRAPPED list rather than a bare
 * item. Keeping one copy would mean either exporting a block-private
 * helper or moving ByteSize, neither of which is this wave's scope; the
 * duplication is recorded in the wave report with a recommendation to
 * consolidate at integration.
 *
 * Every "11" below is one protobuf tag byte plus a ten-byte varint, the
 * widest a field header and a 64-bit value can be.
 * ══════════════════════════════════════════════════════════════════════ */

/** Widest marshal of one `cmt_pb_vote_t` (types.proto Vote, ten fields). */
static size_t vote_bound(const cmt_pb_vote_t *v)
{
    size_t n = 0;

    n += 11u;                                            /* 1 type      */
    n += 11u;                                            /* 2 height    */
    n += 11u;                                            /* 3 round     */
    n += 11u + (size_t)CMT_BLOCK_ID_MAX_BYTES;           /* 4 block_id  */
    n += 11u + 17u;                                      /* 5 timestamp */
    n += 11u + (size_t)CMT_PB_ADDRESS_MAX;               /* 6 address   */
    n += 11u;                                            /* 7 index     */
    n += 11u + (size_t)CMT_PB_SIG_MAX;                   /* 8 signature */
    n += 11u + v->extension.len;                         /* 9 extension */
    n += 11u + (size_t)CMT_PB_SIG_MAX;                   /* 10 ext sig  */
    return n;
}

/* Widest marshal of a bare DuplicateVoteEvidence (evidence.proto:19-25). */
size_t cmt_dve_upper_bound(const cmt_duplicate_vote_evidence_t *d)
{
    size_t n = 0;

    if (d == NULL) {
        return 0u;
    }
    n += 11u + vote_bound(&d->vote_a);                   /* 1 vote_a    */
    n += 11u + vote_bound(&d->vote_b);                   /* 2 vote_b    */
    n += 11u;                                            /* 3 total pow */
    n += 11u;                                            /* 4 val power */
    n += 11u + 17u;                                      /* 5 timestamp */
    return n;
}

/* ══════════════════════════════════════════════════════════════════════
 * Go's `strings.Compare` over the bytes of two BlockID keys.
 *
 * `strings.Compare(a, b)` orders by content and then by length: it walks
 * the shorter length and, if every byte matches, the SHORTER string sorts
 * first. Reproduced with a memcmp over the shorter length followed by a
 * length comparison — the same construction
 * `cmt_validator_compare_proposer_priority` uses for `bytes.Compare`
 * (cmt_validator_set.h:370-372). A BlockID key CAN differ in length: the
 * hash half may be empty (block.go:1487, a POL BlockID has none).
 *
 * @return <0, 0 or >0 like the reference's.
 * ══════════════════════════════════════════════════════════════════════ */
static int key_compare(const uint8_t *a, size_t alen,
                       const uint8_t *b, size_t blen)
{
    size_t n = (alen < blen) ? alen : blen;
    int    c;

    if (n != 0u) {
        c = memcmp(a, b, n);
        if (c != 0) {
            return c;
        }
    }
    if (alen < blen) {
        return -1;
    }
    if (alen > blen) {
        return 1;
    }
    return 0;
}

/* ══ DuplicateVoteEvidence ════════════════════════════════════════════ */

/* cometbft@709fd12b types/evidence.go:95-103 —
 * (dve *DuplicateVoteEvidence) Bytes(). ToProto then Marshal, of the BARE
 * message; see cmt_evidence.h. */
int cmt_dve_bytes(const cmt_duplicate_vote_evidence_t *dve,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_duplicate_vote_evidence_t pbe;
    int                              rc;

    if (dve == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_dve_to_proto(dve, &pbe);                            /* :96  */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :97-100 — the reference panics on a marshal failure. */
    return cmt_pb_duplicate_vote_evidence_marshal(&pbe, out, cap, out_len);
}

/* cometbft@709fd12b types/evidence.go:106-108 —
 * (dve *DuplicateVoteEvidence) Hash() = tmhash.Sum(dve.Bytes()).
 * FLAT, not Merkle. */
int cmt_dve_hash(const cmt_duplicate_vote_evidence_t *dve,
                 uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t *buf;
    size_t   bound;
    size_t   len;
    int      rc;

    if (dve == NULL || out == NULL) {
        return CMT_FAULT;
    }
    bound = cmt_dve_upper_bound(dve);
    buf   = (uint8_t *)malloc(bound);
    if (buf == NULL) {
        return CMT_FAULT;                                /* R1B-11       */
    }
    rc = cmt_dve_bytes(dve, buf, bound, &len);                   /* :107 */
    if (rc == CMT_OK) {
        rc = cmt_tmhash_sum(buf, len, out);                      /* :107 */
    }
    free(buf);
    return rc;
}

/* cometbft@709fd12b types/evidence.go:111-113 —
 * (dve *DuplicateVoteEvidence) Height() = dve.VoteA.Height. */
int cmt_dve_height(const cmt_duplicate_vote_evidence_t *dve, int64_t *out)
{
    if (dve == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (!dve->has_vote_a) {
        /* The reference dereferences a nil *Vote here and panics. A NULL
         * dereference is not a verdict about the input (R1B-10). */
        return CMT_FAULT;
    }
    *out = dve->vote_a.height;                                   /* :112 */
    return CMT_OK;
}

/* cometbft@709fd12b types/evidence.go:121-123 —
 * (dve *DuplicateVoteEvidence) Time(). The EVIDENCE's Timestamp. */
int cmt_dve_time(const cmt_duplicate_vote_evidence_t *dve, cmt_time_t *out)
{
    if (dve == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = dve->timestamp;                                       /* :122 */
    return CMT_OK;
}

/* cometbft@709fd12b types/evidence.go:126-145 —
 * (dve *DuplicateVoteEvidence) ValidateBasic() */
int cmt_dve_validate_basic(const cmt_duplicate_vote_evidence_t *dve)
{
    uint8_t ka[CMT_BLOCK_ID_MAX_BYTES];
    uint8_t kb[CMT_BLOCK_ID_MAX_BYTES];
    size_t  ka_len;
    size_t  kb_len;
    int     rc;

    if (dve == NULL) {
        return CMT_FAULT;               /* :127-129 is an error; R1B-10 */
    }
    if (!dve->has_vote_a || !dve->has_vote_b) {
        return CMT_REJECT;                                    /* :131-133 */
    }
    rc = cmt_vote_validate_basic(&dve->vote_a);               /* :134-136 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_vote_validate_basic(&dve->vote_b);               /* :137-139 */
    if (rc != CMT_OK) {
        return rc;
    }
    /* :140-143 — "Enforce Votes are lexicographically sorted on blockID".
     * `>= 0` refuses the wrong order AND an equal pair, which is not a
     * conflict at all. See cmt_evidence.h. */
    rc = cmt_block_id_key(&dve->vote_a.block_id, ka, sizeof(ka), &ka_len);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_block_id_key(&dve->vote_b.block_id, kb, sizeof(kb), &kb_len);
    if (rc != CMT_OK) {
        return rc;
    }
    if (key_compare(ka, ka_len, kb, kb_len) >= 0) {
        return CMT_REJECT;              /* :142 "invalid order"          */
    }
    return CMT_OK;                                                /* :144 */
}

/* cometbft@709fd12b types/evidence.go:148-159 —
 * (dve *DuplicateVoteEvidence) ToProto(). The identity. */
int cmt_dve_to_proto(const cmt_duplicate_vote_evidence_t *dve,
                     cmt_pb_duplicate_vote_evidence_t *out)
{
    if (dve == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *dve;                                              /* :151-157 */
    return CMT_OK;
}

/* cometbft@709fd12b types/evidence.go:162-200 —
 * DuplicateVoteEvidenceFromProto() */
int cmt_dve_from_proto(const cmt_pb_duplicate_vote_evidence_t *pb,
                       cmt_duplicate_vote_evidence_t *out)
{
    cmt_duplicate_vote_evidence_t tmp;
    int                           rc;

    if (pb == NULL || out == NULL) {
        return CMT_FAULT;               /* :163-165 is an error; R1B-10 */
    }
    memset(&tmp, 0, sizeof(tmp));
    tmp.has_vote_a = pb->has_vote_a;
    tmp.has_vote_b = pb->has_vote_b;

    if (pb->has_vote_a) {                                     /* :168-177 */
        rc = cmt_vote_from_proto(&pb->vote_a, &tmp.vote_a);       /* :170 */
        if (rc != CMT_OK) {
            return rc;
        }
        rc = cmt_vote_validate_basic(&tmp.vote_a);               /* :174 */
        if (rc != CMT_OK) {
            return rc;
        }
    }
    if (pb->has_vote_b) {                                     /* :180-189 */
        rc = cmt_vote_from_proto(&pb->vote_b, &tmp.vote_b);       /* :182 */
        if (rc != CMT_OK) {
            return rc;
        }
        rc = cmt_vote_validate_basic(&tmp.vote_b);               /* :186 */
        if (rc != CMT_OK) {
            return rc;
        }
    }
    tmp.total_voting_power = pb->total_voting_power;             /* :194 */
    tmp.validator_power    = pb->validator_power;                /* :195 */
    tmp.timestamp          = pb->timestamp;                      /* :196 */

    /* :199 — the whole is ValidateBasic'd, and THAT is where an absent
     * vote and a wrongly ordered pair are refused. */
    rc = cmt_dve_validate_basic(&tmp);
    if (rc != CMT_OK) {
        return rc;
    }
    *out = tmp;
    return CMT_OK;
}

/* ══ the Evidence wrapper ═════════════════════════════════════════════ */

/* cometbft@709fd12b types/evidence.go:495-523 — EvidenceToProto(),
 * DuplicateVoteEvidence branch (:501-507). */
int cmt_evidence_to_proto(const cmt_duplicate_vote_evidence_t *dve,
                          cmt_pb_evidence_t *out)
{
    int rc;

    if (dve == NULL || out == NULL) {
        return CMT_FAULT;               /* :496-498 is an error; R1B-10 */
    }
    memset(out, 0, sizeof(*out));
    rc = cmt_dve_to_proto(dve, &out->duplicate_vote_evidence);   /* :502 */
    if (rc != CMT_OK) {
        return rc;
    }
    out->has_duplicate_vote_evidence = true;                  /* :503-507 */
    return CMT_OK;
}

/* cometbft@709fd12b types/evidence.go:527-540 — EvidenceFromProto(),
 * DuplicateVoteEvidence branch (:533-534). */
int cmt_evidence_from_proto(const cmt_pb_evidence_t *ev,
                            cmt_duplicate_vote_evidence_t *out)
{
    if (ev == NULL || out == NULL) {
        return CMT_FAULT;               /* :528-530 is an error; R1B-10 */
    }
    if (!ev->has_duplicate_vote_evidence) {
        /* :537-538 "evidence is not recognized" — either no oneof arm was
         * set, or the decoder met branch 2, which cmt_pb refuses outright
         * (cmt_pb.h:379-397). */
        return CMT_REJECT;
    }
    return cmt_dve_from_proto(&ev->duplicate_vote_evidence, out);/* :534 */
}

/* ══ EvidenceList ═════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/evidence.go:450-461 — (evl EvidenceList) Hash().
 * The Merkle root over each item's BARE marshal. THE HEADER'S EvidenceHash
 * (D-19 rev 6 item 8). */
int cmt_evidence_list_hash(const cmt_pb_evidence_t *items, size_t n,
                           uint8_t out[CMT_TMHASH_SIZE])
{
    cmt_merkle_item_t *leaves = NULL;
    uint8_t          **bufs   = NULL;
    size_t             i;
    int                rc = CMT_OK;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (n != 0u) {
        if (items == NULL) {
            return CMT_FAULT;
        }
        /* :454 — the reference's `make([][]byte, len(evl))`. Transient,
         * freed on every path below (R1B-11). */
        leaves = (cmt_merkle_item_t *)calloc(n, sizeof(*leaves));
        bufs   = (uint8_t **)calloc(n, sizeof(*bufs));
        if (leaves == NULL || bufs == NULL) {
            free(leaves);
            free(bufs);
            return CMT_FAULT;
        }
    }
    for (i = 0; i < n; i++) {                                 /* :455-459 */
        const cmt_pb_evidence_t *ev = &items[i];
        size_t                   bound;
        size_t                   len;

        if (!ev->has_duplicate_vote_evidence) {
            rc = CMT_REJECT;   /* only branch 1 is in scope (cmt_pb.h)   */
            break;
        }
        bound   = cmt_dve_upper_bound(&ev->duplicate_vote_evidence);
        bufs[i] = (uint8_t *)malloc(bound);
        if (bufs[i] == NULL) {
            rc = CMT_FAULT;
            break;
        }
        /* :458 — the leaf is `Bytes()`, the BARE message. The reference's
         * own TODO at :456-457 is deliberately not acted on. */
        rc = cmt_dve_bytes(&ev->duplicate_vote_evidence, bufs[i], bound,
                           &len);
        if (rc != CMT_OK) {
            break;
        }
        leaves[i].data = bufs[i];
        leaves[i].len  = len;
    }
    if (rc == CMT_OK) {
        rc = cmt_merkle_hash_from_byte_slices(leaves, n, out);    /* :460 */
    }
    for (i = 0; i < n; i++) {
        free(bufs != NULL ? bufs[i] : NULL);
    }
    free(leaves);
    free(bufs);
    return rc;
}

/* cometbft@709fd12b types/evidence.go:472-479 — (evl EvidenceList) Has() */
int cmt_evidence_list_has(const cmt_pb_evidence_t *items, size_t n,
                          const cmt_pb_evidence_t *ev, bool *out)
{
    uint8_t needle[CMT_TMHASH_SIZE];
    uint8_t hay[CMT_TMHASH_SIZE];
    size_t  i;
    int     rc;

    if (out == NULL || ev == NULL || (items == NULL && n != 0u)) {
        return CMT_FAULT;
    }
    *out = false;
    if (!ev->has_duplicate_vote_evidence) {
        return CMT_REJECT;
    }
    rc = cmt_dve_hash(&ev->duplicate_vote_evidence, needle);      /* :474 */
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < n; i++) {                                  /* :473-478 */
        if (!items[i].has_duplicate_vote_evidence) {
            return CMT_REJECT;
        }
        rc = cmt_dve_hash(&items[i].duplicate_vote_evidence, hay);/* :474 */
        if (rc != CMT_OK) {
            return rc;
        }
        if (memcmp(needle, hay, (size_t)CMT_TMHASH_SIZE) == 0) {
            *out = true;                                         /* :475 */
            return CMT_OK;
        }
    }
    return CMT_OK;                                               /* :478 */
}

/* ══ errors ═══════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/evidence.go:572-574 — NewErrEvidenceOverflow().
 * A plain constructor; it does NOT check that got > max, exactly as the
 * reference does not. */
int cmt_new_err_evidence_overflow(int64_t max, int64_t got,
                                  cmt_ev_error_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    out->code = CMT_EV_ERR_OVERFLOW;
    out->max  = max;                                             /* :573 */
    out->got  = got;                                             /* :573 */
    return CMT_OK;
}
