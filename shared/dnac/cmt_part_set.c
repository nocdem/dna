/**
 * @file shared/dnac/cmt_part_set.c
 * @brief cometbft @709fd12b `types/part_set.go` ported to C — see
 *        cmt_part_set.h for the contract, the substitutions and the
 *        taşınmadı list.
 *
 * Every function below carries the `// cometbft@709fd12b <file>:<from>-<to>`
 * line of the Go function it ports.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_part_set.h"

#include <stdlib.h>
#include <string.h>

/* ══ validation.go ════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/validation.go:196-204 — ValidateHash() */
int cmt_validate_hash(const uint8_t *h, size_t len)
{
    (void)h;
    if (len > 0 && len != (size_t)CMT_TMHASH_SIZE) {
        return CMT_REJECT;
    }
    return CMT_OK;
}

/* ══ Part ═════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/part_set.go:45-60 — (part *Part) ValidateBasic() */
int cmt_part_validate_basic(const cmt_part_t *part)
{
    if (part == NULL) {
        return CMT_FAULT;
    }
    if (part->bytes.len > (size_t)CMT_BLOCK_PART_SIZE_BYTES) {
        return CMT_REJECT;                       /* :46-48 ErrPartTooBig  */
    }
    /* :50-52 ErrPartInvalidSize — every part but the LAST is exactly one
     * full part wide. The bound is the PROOF's total, not the part set's:
     * a Part validates before it ever meets a PartSet. */
    if ((int64_t)part->index < part->proof.total - 1 &&
        part->bytes.len != (size_t)CMT_BLOCK_PART_SIZE_BYTES) {
        return CMT_REJECT;
    }
    if ((int64_t)part->index != part->proof.index) {
        return CMT_REJECT;                       /* :53-55 ErrInvalidPart */
    }
    if (cmt_proof_validate_basic(&part->proof) != CMT_OK) {
        return CMT_REJECT;                       /* :56-58               */
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:83-95 — (part *Part) ToProto().
 * The identity on this representation; see cmt_part_set.h. */
int cmt_part_to_proto(const cmt_part_t *part, cmt_pb_part_t *out)
{
    if (part == NULL || out == NULL) {
        return CMT_FAULT;                        /* :84-86 "nil part"    */
    }
    *out = *part;
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:97-112 — PartFromProto().
 * The reference's `merkle.ProofFromProto` (:103) is a decode FOLLOWED BY
 * Proof.ValidateBasic (crypto/merkle/proof.go:160); on an already-decoded
 * struct the decode is the identity, so what survives is the check. Then
 * :111's Part.ValidateBasic. */
int cmt_part_from_proto(const cmt_pb_part_t *pb, cmt_part_t *out)
{
    if (pb == NULL || out == NULL) {
        return CMT_FAULT;                        /* :98-100 "nil part"   */
    }
    if (cmt_proof_validate_basic(&pb->proof) != CMT_OK) {
        return CMT_REJECT;                       /* :103-106             */
    }
    *out = *pb;                                  /* :107-109             */
    return cmt_part_validate_basic(out);         /* :111                 */
}

/* ══ PartSetHeader ════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/part_set.go:129-131 — IsZero() */
bool cmt_psh_is_zero(const cmt_part_set_header_t *psh)
{
    if (psh == NULL) {
        return true;                             /* the zero value       */
    }
    return psh->total == 0u && psh->hash_len == 0u;
}

/* cometbft@709fd12b types/part_set.go:133-135 — Equals() */
bool cmt_psh_equals(const cmt_part_set_header_t *psh,
                    const cmt_part_set_header_t *other)
{
    if (psh == NULL || other == NULL) {
        return psh == other;
    }
    if (psh->total != other->total || psh->hash_len != other->hash_len) {
        return false;
    }
    if (psh->hash_len == 0u) {
        return true;
    }
    return memcmp(psh->hash, other->hash, psh->hash_len) == 0;
}

/* cometbft@709fd12b types/part_set.go:138-144 — ValidateBasic() */
int cmt_psh_validate_basic(const cmt_part_set_header_t *psh)
{
    if (psh == NULL) {
        return CMT_FAULT;
    }
    /* :140 — the hash may be EMPTY (a Proposal's POL BlockID carries
     * none), but must otherwise be exactly one digest wide. */
    return cmt_validate_hash(psh->hash, psh->hash_len);
}

/* cometbft@709fd12b types/part_set.go:147-156 — (psh *PartSetHeader) ToProto() */
int cmt_psh_to_proto(const cmt_part_set_header_t *psh,
                     cmt_pb_part_set_header_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (psh == NULL) {
        cmt_pb_part_set_header_init(out);        /* :148-150 zero value  */
        return CMT_OK;
    }
    *out = *psh;
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:159-168 — PartSetHeaderFromProto().
 * The reference's "nil PartSetHeader" error (:160-162) cannot arise from a
 * decoded message in this port — cmt_pb always produces a struct — so a
 * NULL here is a programming fault, not wire data. */
int cmt_psh_from_proto(const cmt_pb_part_set_header_t *ppsh,
                       cmt_part_set_header_t *out)
{
    if (ppsh == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *ppsh;                                /* :164-165             */
    return cmt_psh_validate_basic(out);          /* :167                 */
}

/* cometbft@709fd12b types/part_set.go:172-174 — ProtoPartSetHeaderIsZero() */
bool cmt_proto_part_set_header_is_zero(const cmt_pb_part_set_header_t *ppsh)
{
    if (ppsh == NULL) {
        return true;
    }
    return ppsh->total == 0u && ppsh->hash_len == 0u;
}

/* ══ PartSet ══════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/part_set.go:194-222 — NewPartSetFromData() */
int cmt_new_part_set_from_data(const uint8_t *data, size_t data_len,
                               uint32_t part_size,
                               cmt_part_t *parts, size_t parts_cap,
                               cmt_part_set_t *out)
{
    cmt_merkle_item_t *items  = NULL;
    cmt_proof_t       *proofs = NULL;
    uint64_t           total64;
    size_t             total;
    size_t             i;
    int                rc;

    if (out == NULL || (data == NULL && data_len != 0)) {
        return CMT_FAULT;
    }
    /* :193 CONTRACT "partSize is greater than zero". Go's callers never
     * pass zero; C would divide by it, so it is checked. */
    if (part_size == 0u) {
        return CMT_REJECT;
    }
    /* :196 computes this in uint32, which would wrap for a data length at
     * or above 2^32. Computed in 64 bits here and then bounded, which
     * cannot change the answer for any length the bound admits. */
    total64 = ((uint64_t)data_len + (uint64_t)part_size - 1u) /
              (uint64_t)part_size;
    if (total64 > (uint64_t)CMT_PART_SET_MAX_PARTS) {
        return CMT_REJECT;                       /* params.go:22 bound   */
    }
    total = (size_t)total64;
    if (total != 0 && (parts == NULL || total > parts_cap)) {
        return CMT_REJECT;                       /* caller storage bound */
    }

    memset(out, 0, sizeof(*out));
    out->total     = (uint32_t)total;
    out->parts     = parts;
    out->parts_cap = parts_cap;

    /* :199 partsBitArray = bits.NewBitArray(int(total)) — nil for 0. */
    rc = cmt_bits_new(&out->parts_bit_array, (int)total);
    if (rc == CMT_BITS_NIL) {
        out->parts_bit_array_nil = true;
    } else if (rc != CMT_OK) {
        return rc;
    }

    /* :200-208 — the parts point INTO `data`, as the reference's slices
     * point into theirs. */
    for (i = 0; i < total; i++) {
        size_t start = i * (size_t)part_size;
        size_t end   = start + (size_t)part_size;

        if (end > data_len) {
            end = data_len;                      /* :203 cmtmath.MinInt  */
        }
        cmt_pb_part_init(&parts[i]);
        parts[i].index      = (uint32_t)i;
        parts[i].bytes.data = data + start;
        parts[i].bytes.len  = end - start;
        if (!out->parts_bit_array_nil) {
            (void)cmt_bits_set_index(&out->parts_bit_array, (int)i, true);
        }
    }

    /* :210-213 — one Merkle pass gives the root and every part's proof.
     * The two arrays are the C cost of the reference's [][]byte and
     * []*Proof; both are released before returning. */
    if (total != 0) {
        items  = (cmt_merkle_item_t *)calloc(total, sizeof(*items));
        proofs = (cmt_proof_t *)calloc(total, sizeof(*proofs));
        if (items == NULL || proofs == NULL) {
            free(items);
            free(proofs);
            return CMT_FAULT;
        }
        for (i = 0; i < total; i++) {
            items[i].data = parts[i].bytes.data;
            items[i].len  = parts[i].bytes.len;
        }
    }
    rc = cmt_merkle_proofs_from_byte_slices(items, total, out->hash, proofs);
    if (rc != CMT_OK) {
        free(items);
        free(proofs);
        return rc;
    }
    out->hash_len = CMT_TMHASH_SIZE;
    for (i = 0; i < total; i++) {
        parts[i].proof = proofs[i];              /* :212                 */
    }
    free(items);
    free(proofs);

    out->count     = (uint32_t)total;            /* :219                 */
    out->byte_size = (int64_t)data_len;          /* :220                 */
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:225-234 — NewPartSetFromHeader() */
int cmt_new_part_set_from_header(const cmt_part_set_header_t *header,
                                 cmt_part_t *parts, size_t parts_cap,
                                 cmt_part_set_t *out)
{
    size_t i;
    int    rc;

    if (header == NULL || out == NULL) {
        return CMT_FAULT;
    }
    /* INVARIANT 7495d337: `total` arrives from a wire PartSetHeader. Go
     * would `make([]*Part, header.Total)` — allocate whatever was asked. */
    if ((uint64_t)header->total > (uint64_t)CMT_PART_SET_MAX_PARTS) {
        return CMT_REJECT;
    }
    if (header->total != 0u && (parts == NULL ||
                                (size_t)header->total > parts_cap)) {
        return CMT_REJECT;
    }

    memset(out, 0, sizeof(*out));
    out->total     = header->total;              /* :227                 */
    out->parts     = parts;                      /* :229                 */
    out->parts_cap = parts_cap;
    if (header->hash_len != 0u) {                /* :228                 */
        if (header->hash_len > (size_t)CMT_TMHASH_SIZE) {
            return CMT_REJECT;
        }
        memcpy(out->hash, header->hash, header->hash_len);
    }
    out->hash_len = header->hash_len;

    rc = cmt_bits_new(&out->parts_bit_array, (int)header->total); /* :230 */
    if (rc == CMT_BITS_NIL) {
        out->parts_bit_array_nil = true;
    } else if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < (size_t)header->total; i++) {
        cmt_pb_part_init(&parts[i]);             /* Go's nil slots       */
    }
    out->count     = 0u;                         /* :231                 */
    out->byte_size = 0;                          /* :232                 */
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:236-244 — Header() */
int cmt_part_set_header(const cmt_part_set_t *ps, cmt_part_set_header_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_part_set_header_init(out);
    if (ps == NULL) {
        return CMT_OK;                           /* :237-239 zero header */
    }
    out->total = ps->total;                      /* :241                 */
    if (ps->hash_len != 0u) {
        memcpy(out->hash, ps->hash, ps->hash_len);   /* :242             */
    }
    out->hash_len = ps->hash_len;
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:246-251 — HasHeader() */
bool cmt_part_set_has_header(const cmt_part_set_t *ps,
                             const cmt_part_set_header_t *header)
{
    cmt_part_set_header_t own;

    if (ps == NULL) {
        return false;                            /* :247-249             */
    }
    if (cmt_part_set_header(ps, &own) != CMT_OK) {
        return false;
    }
    return cmt_psh_equals(&own, header);         /* :250                 */
}

/* cometbft@709fd12b types/part_set.go:253-257 — BitArray() */
int cmt_part_set_bit_array(const cmt_part_set_t *ps, cmt_bit_array_t *out)
{
    if (ps == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (ps->parts_bit_array_nil) {
        /* The reference's `(*BitArray)(nil).Copy()` is nil
         * (libs/bits/bit_array.go:106-108). */
        memset(out, 0, sizeof(*out));
        return CMT_BITS_NIL;
    }
    return cmt_bits_copy(&ps->parts_bit_array, out);  /* :256            */
}

/* cometbft@709fd12b types/part_set.go:259-264 — Hash() */
int cmt_part_set_hash(const cmt_part_set_t *ps, uint8_t out[CMT_TMHASH_SIZE])
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (ps == NULL) {
        return cmt_merkle_empty_hash(out);       /* :260-262             */
    }
    /* A PartSet built here always carries a full-width hash; one built
     * from a wire header need not (ValidateBasic admits an empty hash).
     * Reported rather than copied out short. */
    if (ps->hash_len != (size_t)CMT_TMHASH_SIZE) {
        return CMT_REJECT;
    }
    memcpy(out, ps->hash, CMT_TMHASH_SIZE);      /* :263                 */
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:266-271 — HashesTo() */
bool cmt_part_set_hashes_to(const cmt_part_set_t *ps,
                            const uint8_t *hash, size_t hash_len)
{
    if (ps == NULL) {
        return false;                            /* :267-269             */
    }
    if (ps->hash_len != hash_len) {
        return false;
    }
    if (hash_len == 0u) {
        return true;
    }
    if (hash == NULL) {
        return false;
    }
    return memcmp(ps->hash, hash, hash_len) == 0;    /* :270             */
}

/* cometbft@709fd12b types/part_set.go:273-278 — Count() */
uint32_t cmt_part_set_count(const cmt_part_set_t *ps)
{
    return ps == NULL ? 0u : ps->count;
}

/* cometbft@709fd12b types/part_set.go:280-285 — ByteSize() */
int64_t cmt_part_set_byte_size(const cmt_part_set_t *ps)
{
    return ps == NULL ? 0 : ps->byte_size;
}

/* cometbft@709fd12b types/part_set.go:287-292 — Total() */
uint32_t cmt_part_set_total(const cmt_part_set_t *ps)
{
    return ps == NULL ? 0u : ps->total;
}

/* cometbft@709fd12b types/part_set.go:295-331 — AddPart() */
int cmt_part_set_add_part(cmt_part_set_t *ps, const cmt_part_t *part,
                          bool *added)
{
    int rc;

    if (added == NULL || part == NULL) {
        return CMT_FAULT;
    }
    *added = false;
    if (ps == NULL) {
        return CMT_OK;                           /* :298-300 (false, nil)*/
    }
    if (part->index >= ps->total) {
        return CMT_REJECT;             /* :306-308 UnexpectedIndex       */
    }
    if (ps->parts == NULL || (size_t)part->index >= ps->parts_cap) {
        return CMT_FAULT;              /* storage the caller did not give*/
    }
    /* :311-313 — already held. The reference tests `ps.parts[i] != nil`;
     * the bit array is the same predicate (it is set at :207 and :327 and
     * nowhere else) and needs no nil pointer. */
    if (!ps->parts_bit_array_nil &&
        cmt_bits_get_index(&ps->parts_bit_array, (int)part->index) == 1) {
        return CMT_OK;                           /* (false, nil)         */
    }
    if (part->proof.total != (int64_t)ps->total) {
        return CMT_REJECT;                       /* :316-318 InvalidProof*/
    }
    /* INVARIANT 7495d337 — cmt_proof_verify reads CMT_TMHASH_SIZE bytes
     * of the root. Go's bytes.Equal would merely have failed. */
    if (ps->hash_len != (size_t)CMT_TMHASH_SIZE) {
        return CMT_REJECT;
    }
    rc = cmt_proof_verify(&part->proof, ps->hash,
                          part->bytes.data, part->bytes.len);   /* :321  */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        return CMT_REJECT;                       /* :321-323 InvalidProof*/
    }

    ps->parts[part->index] = *part;              /* :326                 */
    if (!ps->parts_bit_array_nil) {
        (void)cmt_bits_set_index(&ps->parts_bit_array,
                                 (int)part->index, true);       /* :327  */
    }
    ps->count++;                                 /* :328                 */
    ps->byte_size += (int64_t)part->bytes.len;   /* :329                 */
    *added = true;
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:333-337 — GetPart() */
const cmt_part_t *cmt_part_set_get_part(const cmt_part_set_t *ps,
                                        size_t index)
{
    if (ps == NULL || ps->parts == NULL) {
        return NULL;
    }
    if (index >= (size_t)ps->total || index >= ps->parts_cap) {
        return NULL;                   /* the reference's index panic    */
    }
    if (ps->parts_bit_array_nil ||
        cmt_bits_get_index(&ps->parts_bit_array, (int)index) != 1) {
        return NULL;                   /* the reference's nil slot       */
    }
    return &ps->parts[index];                    /* :336                 */
}

/* cometbft@709fd12b types/part_set.go:339-341 — IsComplete() */
bool cmt_part_set_is_complete(const cmt_part_set_t *ps)
{
    if (ps == NULL) {
        return false;                  /* the reference has no nil check */
    }
    return ps->count == ps->total;               /* :340                 */
}

/* cometbft@709fd12b types/part_set.go:356-362 — NewPartSetReader() */
int cmt_new_part_set_reader(const cmt_part_t *parts, size_t n,
                            cmt_part_set_reader_t *out)
{
    if (out == NULL || (parts == NULL && n != 0)) {
        return CMT_FAULT;
    }
    if (n == 0) {
        return CMT_REJECT;             /* :360 indexes parts[0] — panic  */
    }
    out->parts = parts;                          /* :359                 */
    out->n     = n;
    out->i     = 0;                              /* :358                 */
    out->off   = 0;
    return CMT_OK;
}

/* cometbft@709fd12b types/part_set.go:343-348 — GetReader() */
int cmt_part_set_get_reader(const cmt_part_set_t *ps,
                            cmt_part_set_reader_t *out)
{
    if (ps == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (!cmt_part_set_is_complete(ps)) {
        return CMT_REJECT;                       /* :344-346 panic       */
    }
    return cmt_new_part_set_reader(ps->parts, (size_t)ps->total, out);
}

/* cometbft@709fd12b types/part_set.go:364-383 — (psr *PartSetReader) Read().
 * The reference's recursion, written as a loop; see cmt_part_set.h for the
 * one stated difference (when the end is announced). */
int cmt_part_set_reader_read(cmt_part_set_reader_t *psr, uint8_t *p,
                             size_t len, size_t *n_out)
{
    size_t total = 0;

    if (psr == NULL || n_out == NULL || (p == NULL && len != 0)) {
        return CMT_FAULT;
    }
    *n_out = 0;
    if (len == 0) {
        /* :366-367 — `readerLen >= 0` holds, and a bytes.Reader asked for
         * nothing returns (0, nil). */
        return CMT_OK;
    }
    while (total < len) {
        size_t remaining;

        if (psr->i >= psr->n) {
            break;                               /* :378-380 io.EOF      */
        }
        remaining = psr->parts[psr->i].bytes.len - psr->off;
        if (remaining == 0) {
            psr->i++;                            /* :377                 */
            psr->off = 0;                        /* :381                 */
            continue;
        }
        if (remaining > len - total) {
            remaining = len - total;             /* :366-367             */
        }
        if (psr->parts[psr->i].bytes.data == NULL) {
            return CMT_FAULT;
        }
        memcpy(p + total, psr->parts[psr->i].bytes.data + psr->off,
               remaining);
        psr->off += remaining;
        total    += remaining;
    }
    *n_out = total;
    if (total == 0) {
        return CMT_PART_SET_EOF;                 /* :379                 */
    }
    return CMT_OK;
}
