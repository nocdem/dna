/**
 * @file shared/dnac/cmt_block.c
 * @brief cometbft @709fd12b `types/block.go` ported to C — see cmt_block.h
 *        for the contract, the substitutions, the re-derived constants and
 *        the taşınmadı / stage-D lists.
 *
 * Every function below carries the `// cometbft@709fd12b <file>:<from>-<to>`
 * line of the Go function it ports.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"     /* cmt_vote_sign_bytes (block.go:897)      */
#include "dnac/cmt_evidence.h" /* the evidence domain: block.go:94, :1448,
                                * and EvidenceList.Hash at :1383. Included
                                * from the .c and NOT from cmt_block.h, so
                                * that cmt_evidence.h may keep including
                                * cmt_block.h for BlockID.Key(). */

#include <stdlib.h>
#include <string.h>

/* ══ the block's own proto3 frame ═════════════════════════════════════
 * RELOCATED (wave R2-B, R1B-6). The Block and EvidenceList encoders that
 * wave R1-B had to build here — because that wave's whitelist closed
 * cmt_pb — now live in cmt_pb.c beside every other generated encoder, as
 * `cmt_pb_block_marshal` and `cmt_pb_evidence_list_marshal`, on the same
 * backward writer. The forward frame-and-memmove helpers they needed
 * (`frame_begin`, `frame_end`, `PB_LEN_RESERVE`) went with them and have
 * no counterpart there: the backward writer never needs one.
 *
 * THE BYTES ARE UNCHANGED. The two functions below now only build the
 * cmt_pb view of what they already held and call the relocated encoder;
 * test_cmt_block.c's vectors, untouched by this wave, are the proof.
 * ═════════════════════════════════════════════════════════════════════ */

/** Fill the wire view of an EvidenceData. `cmt_evidence_data_t.evidence`
 *  is already an array of `cmt_pb_evidence_t` (types/block.go:1420-1438 —
 *  ToProto is the identity), so this is a two-field copy. */
static void evidence_list_view(const cmt_evidence_data_t *ed,
                               cmt_pb_evidence_list_t *out)
{
    out->evidence     = (ed == NULL) ? NULL : ed->evidence;
    out->evidence_len = (ed == NULL) ? 0u : ed->evidence_len;
}

/* ── upper bounds for the transient buffers ─────────────────────────── */
/*
 * REMOVED (wave R2-B, R1D-5). The file-static `vote_upper_bound` and
 * `dve_upper_bound` that stood here were a second copy of
 * `cmt_dve_upper_bound` (cmt_evidence.h:138) and its `vote_bound` helper
 * (cmt_evidence.c:34-50) — wave R1-D wrote the copy there and recorded the
 * duplication with a recommendation to consolidate. The single definition
 * in cmt_evidence is used now; `vote_upper_bound` went with it because
 * `dve_upper_bound` was its only caller. The two bodies were identical
 * term for term, so no bound changes.
 */

/* ══ BlockID ══════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/block.go:1468-1472 — (blockID BlockID) Equals() */
bool cmt_block_id_equals(const cmt_block_id_t *a, const cmt_block_id_t *b)
{
    if (a == NULL || b == NULL) {
        return a == b;
    }
    if (a->hash_len != b->hash_len) {
        return false;
    }
    if (a->hash_len != 0u && memcmp(a->hash, b->hash, a->hash_len) != 0) {
        return false;
    }
    return cmt_psh_equals(&a->part_set_header, &b->part_set_header);
}

/* cometbft@709fd12b types/block.go:1474-1483 — (blockID BlockID) Key() */
int cmt_block_id_key(const cmt_block_id_t *bid, uint8_t *out, size_t cap,
                     size_t *out_len)
{
    uint8_t psh[CMT_BLOCK_ID_MAX_BYTES];
    size_t  psh_len;
    int     rc;

    if (bid == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_pb_part_set_header_marshal(&bid->part_set_header, psh,
                                        sizeof(psh), &psh_len);   /* :1477 */
    if (rc != CMT_OK) {
        return rc;                                 /* :1478-1480 panic   */
    }
    if (cap < bid->hash_len + psh_len) {
        return CMT_REJECT;
    }
    if (bid->hash_len != 0u) {
        memcpy(out, bid->hash, bid->hash_len);
    }
    memcpy(out + bid->hash_len, psh, psh_len);      /* :1482 concatenate  */
    *out_len = bid->hash_len + psh_len;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1485-1495 — (blockID BlockID) ValidateBasic() */
int cmt_block_id_validate_basic(const cmt_block_id_t *bid)
{
    if (bid == NULL) {
        return CMT_FAULT;
    }
    /* :1487-1490 — the hash MAY be empty; a Proposal's POL BlockID is. */
    if (cmt_validate_hash(bid->hash, bid->hash_len) != CMT_OK) {
        return CMT_REJECT;
    }
    return cmt_psh_validate_basic(&bid->part_set_header);        /* :1491 */
}

/* cometbft@709fd12b types/block.go:1497-1501 — (blockID BlockID) IsZero() */
bool cmt_block_id_is_zero(const cmt_block_id_t *bid)
{
    if (bid == NULL) {
        return true;
    }
    return bid->hash_len == 0u && cmt_psh_is_zero(&bid->part_set_header);
}

/* cometbft@709fd12b types/block.go:1503-1508 — (blockID BlockID) IsComplete() */
bool cmt_block_id_is_complete(const cmt_block_id_t *bid)
{
    if (bid == NULL) {
        return false;
    }
    return bid->hash_len == (size_t)CMT_TMHASH_SIZE &&
           bid->part_set_header.total > 0u &&
           bid->part_set_header.hash_len == (size_t)CMT_TMHASH_SIZE;
}

/* cometbft@709fd12b types/block.go:1520-1530 — (blockID *BlockID) ToProto() */
int cmt_block_id_to_proto(const cmt_block_id_t *bid, cmt_pb_block_id_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (bid == NULL) {
        cmt_pb_block_id_init(out);                   /* :1522-1524       */
        return CMT_OK;
    }
    *out = *bid;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1532-1549 — BlockIDFromProto() */
int cmt_block_id_from_proto(const cmt_pb_block_id_t *bp, cmt_block_id_t *out)
{
    int rc;

    if (bp == NULL || out == NULL) {
        return CMT_FAULT;                            /* :1535-1537       */
    }
    rc = cmt_psh_from_proto(&bp->part_set_header,
                            &out->part_set_header);  /* :1540            */
    if (rc != CMT_OK) {
        return rc;
    }
    if (bp->hash_len > (size_t)CMT_PB_HASH_MAX) {
        return CMT_REJECT;
    }
    if (bp->hash_len != 0u) {
        memcpy(out->hash, bp->hash, bp->hash_len);   /* :1546            */
    }
    out->hash_len = bp->hash_len;
    return cmt_block_id_validate_basic(out);         /* :1548            */
}

/* cometbft@709fd12b types/block.go:1551-1555 — ProtoBlockIDIsNil() */
bool cmt_proto_block_id_is_nil(const cmt_pb_block_id_t *bp)
{
    if (bp == NULL) {
        return true;
    }
    return bp->hash_len == 0u &&
           cmt_proto_part_set_header_is_zero(&bp->part_set_header);
}

/* ══ Header ═══════════════════════════════════════════════════════════ */

/* Copy a byte field into a fixed-width header slot. */
static int hdr_set(uint8_t *dst, size_t cap, size_t *dst_len,
                   const uint8_t *src, size_t n)
{
    if (n > cap) {
        return CMT_REJECT;
    }
    if (n != 0u) {
        if (src == NULL) {
            return CMT_FAULT;
        }
        memcpy(dst, src, n);
    }
    *dst_len = n;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:360-377 — (h *Header) Populate() */
int cmt_header_populate(cmt_header_t *h,
                        const cmt_pb_consensus_t *version,
                        const uint8_t *chain_id, size_t chain_id_len,
                        cmt_time_t timestamp,
                        const cmt_block_id_t *last_block_id,
                        const uint8_t *val_hash, size_t val_hash_len,
                        const uint8_t *next_val_hash, size_t next_val_hash_len,
                        const uint8_t *consensus_hash, size_t consensus_hash_len,
                        const uint8_t *app_hash, size_t app_hash_len,
                        const uint8_t *last_results_hash,
                        size_t last_results_hash_len,
                        const uint8_t *proposer_address,
                        size_t proposer_address_len)
{
    int rc;

    if (h == NULL || version == NULL || last_block_id == NULL) {
        return CMT_FAULT;
    }
    h->version     = *version;                                   /* :367 */
    rc = hdr_set(h->chain_id, CMT_PB_CHAINID_MAX, &h->chain_id_len,
                 chain_id, chain_id_len);                        /* :368 */
    if (rc != CMT_OK) {
        return rc;
    }
    h->time          = timestamp;                                /* :369 */
    h->last_block_id = *last_block_id;                           /* :370 */
    rc = hdr_set(h->validators_hash, CMT_PB_HASH_MAX,
                 &h->validators_hash_len, val_hash, val_hash_len);/* :371 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = hdr_set(h->next_validators_hash, CMT_PB_HASH_MAX,
                 &h->next_validators_hash_len,
                 next_val_hash, next_val_hash_len);              /* :372 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = hdr_set(h->consensus_hash, CMT_PB_HASH_MAX,
                 &h->consensus_hash_len,
                 consensus_hash, consensus_hash_len);            /* :373 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = hdr_set(h->app_hash, CMT_PB_HASH_MAX, &h->app_hash_len,
                 app_hash, app_hash_len);                        /* :374 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = hdr_set(h->last_results_hash, CMT_PB_HASH_MAX,
                 &h->last_results_hash_len,
                 last_results_hash, last_results_hash_len);      /* :375 */
    if (rc != CMT_OK) {
        return rc;
    }
    return hdr_set(h->proposer_address, CMT_PB_ADDRESS_MAX,
                   &h->proposer_address_len,
                   proposer_address, proposer_address_len);      /* :376 */
}

/* cometbft@709fd12b types/block.go:383-437 — (h Header) ValidateBasic() */
int cmt_header_validate_basic(const cmt_header_t *h, uint64_t block_protocol)
{
    if (h == NULL) {
        return CMT_FAULT;
    }
    if (h->version.block != block_protocol) {
        return CMT_REJECT;                                    /* :384-386 */
    }
    if (h->chain_id_len > (size_t)CMT_MAX_CHAIN_ID_LEN) {
        return CMT_REJECT;                                    /* :387-389 */
    }
    if (h->height < 0) {
        return CMT_REJECT;                                    /* :391-392 */
    }
    if (h->height == 0) {
        return CMT_REJECT;                                    /* :393-395 */
    }
    if (cmt_block_id_validate_basic(&h->last_block_id) != CMT_OK) {
        return CMT_REJECT;                                    /* :397-399 */
    }
    if (cmt_validate_hash(h->last_commit_hash,
                          h->last_commit_hash_len) != CMT_OK) {
        return CMT_REJECT;                                    /* :401-403 */
    }
    if (cmt_validate_hash(h->data_hash, h->data_hash_len) != CMT_OK) {
        return CMT_REJECT;                                    /* :405-407 */
    }
    if (cmt_validate_hash(h->evidence_hash,
                          h->evidence_hash_len) != CMT_OK) {
        return CMT_REJECT;                                    /* :409-411 */
    }
    /* :413-418 — crypto.AddressSize 20 → CMT_ADDRESS_SIZE 32. */
    if (h->proposer_address_len != (size_t)CMT_ADDRESS_SIZE) {
        return CMT_REJECT;
    }
    if (cmt_validate_hash(h->validators_hash,
                          h->validators_hash_len) != CMT_OK) {
        return CMT_REJECT;                                    /* :422-424 */
    }
    if (cmt_validate_hash(h->next_validators_hash,
                          h->next_validators_hash_len) != CMT_OK) {
        return CMT_REJECT;                                    /* :425-427 */
    }
    if (cmt_validate_hash(h->consensus_hash,
                          h->consensus_hash_len) != CMT_OK) {
        return CMT_REJECT;                                    /* :428-430 */
    }
    /* :431 — AppHash is of arbitrary length and is NOT checked. */
    if (cmt_validate_hash(h->last_results_hash,
                          h->last_results_hash_len) != CMT_OK) {
        return CMT_REJECT;                                    /* :432-434 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:445-480 — (h *Header) Hash().
 * The fourteen leaves of :464-479, in that order. */
int cmt_header_hash(const cmt_header_t *h, uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t           buf[CMT_HEADER_LEAVES][CMT_HEADER_LEAF_MAX];
    cmt_merkle_item_t items[CMT_HEADER_LEAVES];
    size_t            len;
    bool              is_nil;
    int               k;

    if (h == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (h->validators_hash_len == 0u) {
        return CMT_HASH_NIL;                                  /* :446-448 */
    }

    /* [0] h.Version.Marshal() — a BARE Consensus message (:449-452). */
    if (cmt_pb_consensus_marshal(&h->version, buf[0], sizeof(buf[0]),
                                 &len) != CMT_OK) {
        return CMT_HASH_NIL;                                  /* :451     */
    }
    items[0].data = buf[0];
    items[0].len  = len;

    /* [1] cdcEncode(h.ChainID) — StringValue{1} (:466). */
    if (cmt_pb_cdc_encode_string(h->chain_id, h->chain_id_len, buf[1],
                                 sizeof(buf[1]), &len, &is_nil) != CMT_OK) {
        return CMT_FAULT;
    }
    items[1].data = is_nil ? NULL : buf[1];
    items[1].len  = is_nil ? 0u : len;

    /* [2] cdcEncode(h.Height) — Int64Value{1}; 0 encodes to no bytes and
     *     is NOT nil (see cmt_pb.h's cdc_encode note) (:467). */
    if (cmt_pb_cdc_encode_int64(h->height, buf[2], sizeof(buf[2]), &len,
                                &is_nil) != CMT_OK) {
        return CMT_FAULT;
    }
    items[2].data = is_nil ? NULL : buf[2];
    items[2].len  = is_nil ? 0u : len;

    /* [3] gogotypes.StdTimeMarshal(h.Time) — a BARE Timestamp (:454-457).
     *     An out-of-range time is the reference's nil result. */
    if (cmt_pb_timestamp_marshal(&h->time, buf[3], sizeof(buf[3]),
                                 &len) != CMT_OK) {
        return CMT_HASH_NIL;                                  /* :456     */
    }
    items[3].data = buf[3];
    items[3].len  = len;

    /* [4] h.LastBlockID.ToProto().Marshal() — a BARE BlockID; the zero
     *     BlockID is the two bytes 12 00 (:459-463). */
    if (cmt_pb_block_id_marshal(&h->last_block_id, buf[4], sizeof(buf[4]),
                                &len) != CMT_OK) {
        return CMT_HASH_NIL;                                  /* :462     */
    }
    items[4].data = buf[4];
    items[4].len  = len;

    /* [5..13] cdcEncode of the eight hashes and the proposer address —
     *         BytesValue{1}; empty → nil → leaf H(0x00) (:470-478). */
    {
        const uint8_t *src[9];
        size_t         src_len[9];
        int            i;

        src[0] = h->last_commit_hash;      src_len[0] = h->last_commit_hash_len;
        src[1] = h->data_hash;             src_len[1] = h->data_hash_len;
        src[2] = h->validators_hash;       src_len[2] = h->validators_hash_len;
        src[3] = h->next_validators_hash;  src_len[3] = h->next_validators_hash_len;
        src[4] = h->consensus_hash;        src_len[4] = h->consensus_hash_len;
        src[5] = h->app_hash;              src_len[5] = h->app_hash_len;
        src[6] = h->last_results_hash;     src_len[6] = h->last_results_hash_len;
        src[7] = h->evidence_hash;         src_len[7] = h->evidence_hash_len;
        src[8] = h->proposer_address;      src_len[8] = h->proposer_address_len;
        for (i = 0; i < 9; i++) {
            k = 5 + i;
            if (cmt_pb_cdc_encode_bytes(src[i], src_len[i], buf[k],
                                        sizeof(buf[k]), &len,
                                        &is_nil) != CMT_OK) {
                return CMT_FAULT;
            }
            items[k].data = is_nil ? NULL : buf[k];
            items[k].len  = is_nil ? 0u : len;
        }
    }

    return cmt_merkle_hash_from_byte_slices(items, CMT_HEADER_LEAVES, out);
}

/* cometbft@709fd12b types/block.go:521-543 — (h *Header) ToProto() */
int cmt_header_to_proto(const cmt_header_t *h, cmt_pb_header_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (h == NULL) {
        cmt_pb_header_init(out);                     /* :523-525 nil     */
        return CMT_OK;
    }
    *out = *h;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:546-576 — HeaderFromProto() */
int cmt_header_from_proto(const cmt_pb_header_t *ph, uint64_t block_protocol,
                          cmt_header_t *out)
{
    cmt_block_id_t bi;
    int            rc;

    if (ph == NULL || out == NULL) {
        return CMT_FAULT;                            /* :548-550         */
    }
    rc = cmt_block_id_from_proto(&ph->last_block_id, &bi);   /* :554     */
    if (rc != CMT_OK) {
        return rc;
    }
    *out = *ph;                                      /* :559-573         */
    /* NOTE reference quirk (:561, :563): `h.Height = ph.Height` is
     * written twice. The struct copy above does it once; the duplicate is
     * a no-op in the reference too. */
    out->last_block_id = bi;                         /* :564             */
    return cmt_header_validate_basic(out, block_protocol);   /* :575     */
}

/* ══ CommitSig ════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/block.go:608-612 — MaxCommitBytes() */
int cmt_max_commit_bytes(int64_t val_count, int64_t *out)
{
    const int64_t per = CMT_MAX_COMMIT_SIG_BYTES + 2;    /* :610 overhead */

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (val_count < 0) {
        return CMT_REJECT;
    }
    if (val_count != 0 && per > (INT64_MAX - CMT_MAX_COMMIT_OVERHEAD_BYTES) /
                                val_count) {
        return CMT_REJECT;            /* Go's int64 would have wrapped   */
    }
    *out = CMT_MAX_COMMIT_OVERHEAD_BYTES + per * val_count;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:614-620 — NewCommitSigAbsent() */
void cmt_new_commit_sig_absent(cmt_commit_sig_t *out)
{
    if (out == NULL) {
        return;
    }
    cmt_pb_commit_sig_init(out);      /* timestamp = Go's zero time      */
    out->block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_ABSENT;      /* :618 */
}

/* cometbft@709fd12b types/block.go:636-651 — (cs CommitSig) BlockID() */
int cmt_commit_sig_block_id(const cmt_commit_sig_t *cs,
                            const cmt_block_id_t *commit_block_id,
                            cmt_block_id_t *out)
{
    if (cs == NULL || out == NULL) {
        return CMT_FAULT;
    }
    switch (cs->block_id_flag) {
    case (int32_t)CMT_BLOCK_ID_FLAG_ABSENT:
        cmt_pb_block_id_init(out);                              /* :642 */
        return CMT_OK;
    case (int32_t)CMT_BLOCK_ID_FLAG_COMMIT:
        if (commit_block_id == NULL) {
            return CMT_FAULT;
        }
        *out = *commit_block_id;                                /* :644 */
        return CMT_OK;
    case (int32_t)CMT_BLOCK_ID_FLAG_NIL:
        cmt_pb_block_id_init(out);                              /* :646 */
        return CMT_OK;
    default:
        return CMT_REJECT;                        /* :647-649 panics     */
    }
}

/* cometbft@709fd12b types/block.go:653-691 — (cs CommitSig) ValidateBasic() */
int cmt_commit_sig_validate_basic(const cmt_commit_sig_t *cs)
{
    if (cs == NULL) {
        return CMT_FAULT;
    }
    switch (cs->block_id_flag) {                               /* :655-661 */
    case (int32_t)CMT_BLOCK_ID_FLAG_ABSENT:
    case (int32_t)CMT_BLOCK_ID_FLAG_COMMIT:
    case (int32_t)CMT_BLOCK_ID_FLAG_NIL:
        break;
    default:
        return CMT_REJECT;
    }
    if (cs->block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_ABSENT) {
        if (cs->validator_address_len != 0u) {
            return CMT_REJECT;                                 /* :665-667 */
        }
        if (!cmt_time_is_zero(cs->timestamp)) {
            return CMT_REJECT;                                 /* :668-670 */
        }
        if (cs->signature_len != 0u) {
            return CMT_REJECT;                                 /* :671-673 */
        }
        return CMT_OK;
    }
    /* :674-688 — every non-Absent entry. */
    if (cs->validator_address_len != (size_t)CMT_ADDRESS_SIZE) {
        return CMT_REJECT;                                     /* :675-680 */
    }
    /* :681 — "Timestamp validation is subtle and handled elsewhere." */
    if (cs->signature_len == 0u) {
        return CMT_REJECT;                                     /* :682-684 */
    }
    if (cs->signature_len > (size_t)CMT_MAX_SIGNATURE_SIZE) {
        return CMT_REJECT;                                     /* :685-687 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:693-705 — (cs *CommitSig) ToProto() */
int cmt_commit_sig_to_proto(const cmt_commit_sig_t *cs,
                            cmt_pb_commit_sig_t *out)
{
    if (cs == NULL || out == NULL) {
        return CMT_FAULT;                            /* :695-697 nil     */
    }
    *out = *cs;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:707-716 — (cs *CommitSig) FromProto().
 * :715's ValidateBasic is where the Absent rule reaches the wire. */
int cmt_commit_sig_from_proto(const cmt_pb_commit_sig_t *csp,
                              cmt_commit_sig_t *out)
{
    if (csp == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *csp;                                     /* :710-713         */
    return cmt_commit_sig_validate_basic(out);       /* :715             */
}

/* ══ ExtendedCommitSig ════════════════════════════════════════════════ */

/* cometbft@709fd12b types/block.go:728-732 — NewExtendedCommitSigAbsent() */
void cmt_new_extended_commit_sig_absent(cmt_extended_commit_sig_t *out)
{
    if (out == NULL) {
        return;
    }
    cmt_pb_extended_commit_sig_init(out);
    cmt_new_commit_sig_absent(&out->commit_sig);                /* :731 */
}

/* cometbft@709fd12b types/block.go:747-767 —
 * (ecs ExtendedCommitSig) ValidateBasic() */
int cmt_ecs_validate_basic(const cmt_extended_commit_sig_t *ecs)
{
    int rc;

    if (ecs == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_commit_sig_validate_basic(&ecs->commit_sig);      /* :749-751 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (ecs->commit_sig.block_id_flag ==
        (int32_t)CMT_BLOCK_ID_FLAG_COMMIT) {                   /* :753     */
        if (ecs->extension.len > CMT_MAX_VOTE_EXTENSION_SIZE) {
            return CMT_REJECT;                                 /* :754-756 */
        }
        if (ecs->extension_signature_len >
            (size_t)CMT_MAX_SIGNATURE_SIZE) {
            return CMT_REJECT;                                 /* :757-759 */
        }
        return CMT_OK;                                         /* :760     */
    }
    if (ecs->extension_signature_len == 0u && ecs->extension.len != 0u) {
        return CMT_REJECT;                                     /* :763-765 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:769-806 —
 * (ecs ExtendedCommitSig) EnsureExtension() */
int cmt_ecs_ensure_extension(const cmt_extended_commit_sig_t *ecs,
                             bool ext_enabled)
{
    bool is_commit;

    if (ecs == NULL) {
        return CMT_FAULT;
    }
    is_commit = ecs->commit_sig.block_id_flag ==
                (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    if (ext_enabled) {                                         /* :772     */
        if (is_commit && ecs->extension_signature_len == 0u) {
            return CMT_REJECT;                                 /* :773-778 */
        }
        if (!is_commit && ecs->extension.len != 0u) {
            return CMT_REJECT;                                 /* :779-784 */
        }
        if (!is_commit && ecs->extension_signature_len != 0u) {
            return CMT_REJECT;                                 /* :785-790 */
        }
        return CMT_OK;
    }
    if (ecs->extension.len != 0u) {
        return CMT_REJECT;                                     /* :792-797 */
    }
    if (ecs->extension_signature_len != 0u) {
        return CMT_REJECT;                                     /* :798-803 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:808-822 — (ecs *ExtendedCommitSig) ToProto() */
int cmt_ecs_to_proto(const cmt_extended_commit_sig_t *ecs,
                     cmt_pb_extended_commit_sig_t *out)
{
    if (ecs == NULL || out == NULL) {
        return CMT_FAULT;                            /* :810-812 nil     */
    }
    *out = *ecs;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:824-836 — (ecs *ExtendedCommitSig) FromProto() */
int cmt_ecs_from_proto(const cmt_pb_extended_commit_sig_t *ecsp,
                       cmt_extended_commit_sig_t *out)
{
    if (ecsp == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *ecsp;                                    /* :828-833         */
    return cmt_ecs_validate_basic(out);              /* :835             */
}

/* ══ Commit ═══════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/block.go:858-865 — (commit *Commit) Clone() */
int cmt_commit_clone(const cmt_commit_t *commit, cmt_commit_sig_t *sigs,
                     size_t sigs_cap, cmt_commit_t *out)
{
    size_t i;

    if (commit == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (commit->signatures_len > sigs_cap ||
        (commit->signatures_len != 0u && sigs == NULL)) {
        return CMT_REJECT;
    }
    for (i = 0; i < commit->signatures_len; i++) {
        sigs[i] = commit->signatures[i];             /* :860-861         */
    }
    *out = *commit;                                  /* :862             */
    out->signatures     = sigs;                      /* :863             */
    out->signatures_cap = sigs_cap;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:867-884 — (commit *Commit) GetVote() */
int cmt_commit_get_vote(const cmt_commit_t *commit, int32_t val_idx,
                        cmt_pb_vote_t *out)
{
    const cmt_commit_sig_t *cs;
    cmt_block_id_t          bid;
    int                     rc;

    if (commit == NULL || out == NULL) {
        return CMT_FAULT;
    }
    /* :871 "Panics if valIdx >= commit.Size()" — and a negative index
     * would be a negative subscript in Go (INVARIANT 7495d337). */
    if (val_idx < 0 || (size_t)val_idx >= commit->signatures_len ||
        commit->signatures == NULL) {
        return CMT_REJECT;
    }
    cs = &commit->signatures[val_idx];               /* :873             */
    /* INVARIANT 7495d337: the entry's own length fields drive the copies
     * below, and a struct a caller filled by hand could carry a length
     * wider than its array. Go's slice copy could not. */
    if (cs->validator_address_len > (size_t)CMT_PB_ADDRESS_MAX ||
        cs->signature_len > (size_t)CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    rc = cmt_commit_sig_block_id(cs, &commit->block_id, &bid);  /* :878  */
    if (rc != CMT_OK) {
        return rc;
    }
    cmt_pb_vote_init(out);
    out->type      = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;        /* :875  */
    out->height    = commit->height;                            /* :876  */
    out->round     = commit->round;                             /* :877  */
    out->block_id  = bid;                                       /* :878  */
    out->timestamp = cs->timestamp;                             /* :879  */
    memcpy(out->validator_address, cs->validator_address,
           cs->validator_address_len);                          /* :880  */
    out->validator_address_len = cs->validator_address_len;
    out->validator_index       = val_idx;                       /* :881  */
    memcpy(out->signature, cs->signature, cs->signature_len);   /* :882  */
    out->signature_len         = cs->signature_len;
    /* :869-870 — a Commit carries no extension, so fields 9 and 10 stay
     * at the zero value cmt_pb_vote_init gave them. */
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:886-898 — (commit *Commit) VoteSignBytes() */
int cmt_commit_vote_sign_bytes(const cmt_commit_t *commit,
                               const uint8_t *chain_id, size_t chain_id_len,
                               int32_t val_idx,
                               uint8_t *out, size_t cap, size_t *out_len)
{
    cmt_pb_vote_t v;
    int           rc;

    rc = cmt_commit_get_vote(commit, val_idx, &v);              /* :896  */
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_vote_sign_bytes(chain_id, chain_id_len, &v, out, cap,
                               out_len);                        /* :897  */
}

/* cometbft@709fd12b types/block.go:900-906 — (commit *Commit) Size() */
size_t cmt_commit_size(const cmt_commit_t *commit)
{
    return commit == NULL ? 0u : commit->signatures_len;
}

/* cometbft@709fd12b types/block.go:908-933 — (commit *Commit) ValidateBasic() */
int cmt_commit_validate_basic(const cmt_commit_t *commit)
{
    size_t i;

    if (commit == NULL) {
        return CMT_FAULT;
    }
    if (commit->height < 0) {
        return CMT_REJECT;                                     /* :911-913 */
    }
    if (commit->round < 0) {
        return CMT_REJECT;                                     /* :914-916 */
    }
    if (commit->height >= 1) {                                 /* :918     */
        if (cmt_block_id_is_zero(&commit->block_id)) {
            return CMT_REJECT;                                 /* :919-921 */
        }
        if (commit->signatures_len == 0u) {
            return CMT_REJECT;                                 /* :923-925 */
        }
        if (commit->signatures == NULL) {
            return CMT_FAULT;
        }
        for (i = 0; i < commit->signatures_len; i++) {         /* :926-930 */
            if (cmt_commit_sig_validate_basic(&commit->signatures[i])
                != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:935-954 — (commit *Commit) Hash().
 * The Merkle root over the MARSHALLED CommitSig entries, in list order.
 * The height-1 commit is empty-but-not-nil and hashes to H(""). */
int cmt_commit_hash(const cmt_commit_t *commit, uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t           *buf   = NULL;
    cmt_merkle_item_t *items = NULL;
    size_t             n;
    size_t             i;
    int                rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (commit == NULL) {
        return CMT_HASH_NIL;                                   /* :937-939 */
    }
    n = commit->signatures_len;
    if (n != 0u) {
        if (commit->signatures == NULL) {
            return CMT_FAULT;
        }
        buf   = (uint8_t *)malloc(n * (size_t)CMT_MAX_COMMIT_SIG_BYTES);
        items = (cmt_merkle_item_t *)calloc(n, sizeof(*items));
        if (buf == NULL || items == NULL) {
            free(buf);
            free(items);
            return CMT_FAULT;
        }
    }
    for (i = 0; i < n; i++) {                                  /* :941-950 */
        uint8_t *slot = buf + i * (size_t)CMT_MAX_COMMIT_SIG_BYTES;
        size_t   len;

        rc = cmt_pb_commit_sig_marshal(&commit->signatures[i], slot,
                                       (size_t)CMT_MAX_COMMIT_SIG_BYTES,
                                       &len);
        if (rc != CMT_OK) {
            free(buf);
            free(items);
            return rc;                             /* :945-947 panics     */
        }
        items[i].data = slot;
        items[i].len  = len;
    }
    rc = cmt_merkle_hash_from_byte_slices(items, n, out);       /* :951    */
    free(buf);
    free(items);
    return rc;
}

/* cometbft@709fd12b types/block.go:956-974 — WrappedExtendedCommit() */
int cmt_commit_wrapped_extended_commit(const cmt_commit_t *commit,
                                       cmt_extended_commit_sig_t *sigs,
                                       size_t sigs_cap,
                                       cmt_pb_extended_commit_t *out)
{
    size_t i;

    if (commit == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (commit->signatures_len > sigs_cap ||
        (commit->signatures_len != 0u && sigs == NULL)) {
        return CMT_REJECT;
    }
    for (i = 0; i < commit->signatures_len; i++) {             /* :962-967 */
        cmt_pb_extended_commit_sig_init(&sigs[i]);
        sigs[i].commit_sig = commit->signatures[i];
    }
    /* memset rather than cmt_pb_extended_commit_init: that _init PRESERVES
     * `out`'s existing slot pointer and capacity, which are indeterminate
     * in a caller's fresh struct. Every field is assigned below, and
     * ExtendedCommit holds no time, so a zero fill is its complete zero
     * value. Same reasoning at the three other sites in this file. */
    memset(out, 0, sizeof(*out));
    out->height                  = commit->height;             /* :969    */
    out->round                   = commit->round;              /* :970    */
    out->block_id                = commit->block_id;           /* :971    */
    out->extended_signatures     = sigs;                       /* :972    */
    out->extended_signatures_cap = sigs_cap;
    out->extended_signatures_len = commit->signatures_len;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1000-1018 — (commit *Commit) ToProto() */
int cmt_commit_to_proto(const cmt_commit_t *commit, cmt_pb_commit_t *out)
{
    if (commit == NULL || out == NULL) {
        return CMT_FAULT;                            /* :1002-1004 nil   */
    }
    *out = *commit;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1020-1047 — CommitFromProto() */
int cmt_commit_from_proto(const cmt_pb_commit_t *cp, cmt_commit_sig_t *sigs,
                          size_t sigs_cap, cmt_commit_t *out)
{
    cmt_block_id_t bi;
    size_t         i;
    int            rc;

    if (cp == NULL || out == NULL) {
        return CMT_FAULT;                            /* :1023-1025       */
    }
    if (cp->signatures_len > sigs_cap ||
        (cp->signatures_len != 0u && (sigs == NULL ||
                                      cp->signatures == NULL))) {
        return CMT_REJECT;
    }
    rc = cmt_block_id_from_proto(&cp->block_id, &bi);           /* :1029  */
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < cp->signatures_len; i++) {                  /* :1034-1039 */
        rc = cmt_commit_sig_from_proto(&cp->signatures[i], &sigs[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    memset(out, 0, sizeof(*out));      /* see WrappedExtendedCommit above */
    out->signatures     = sigs;                                 /* :1040  */
    out->signatures_cap = sigs_cap;
    out->signatures_len = cp->signatures_len;
    out->height         = cp->height;                           /* :1042  */
    out->round          = cp->round;                            /* :1043  */
    out->block_id       = bi;                                   /* :1044  */
    return cmt_commit_validate_basic(out);                      /* :1046  */
}

/* ══ ExtendedCommit ═══════════════════════════════════════════════════ */

/* cometbft@709fd12b types/block.go:1062-1069 — (ec *ExtendedCommit) Clone() */
int cmt_extended_commit_clone(const cmt_extended_commit_t *ec,
                              cmt_extended_commit_sig_t *sigs,
                              size_t sigs_cap, cmt_extended_commit_t *out)
{
    size_t i;

    if (ec == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (ec->extended_signatures_len > sigs_cap ||
        (ec->extended_signatures_len != 0u && sigs == NULL)) {
        return CMT_REJECT;
    }
    for (i = 0; i < ec->extended_signatures_len; i++) {
        sigs[i] = ec->extended_signatures[i];                   /* :1064-1065 */
    }
    *out = *ec;                                                 /* :1066  */
    out->extended_signatures     = sigs;                        /* :1067  */
    out->extended_signatures_cap = sigs_cap;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1121-1128 —
 * (ec *ExtendedCommit) EnsureExtensions() */
int cmt_extended_commit_ensure_extensions(const cmt_extended_commit_t *ec,
                                          bool ext_enabled)
{
    size_t i;
    int    rc;

    if (ec == NULL) {
        return CMT_FAULT;
    }
    /* INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07: the length is
     * the struct's own, so it is checked against the list before the list
     * is indexed. Go's range over a nil slice cannot run at all. */
    if (ec->extended_signatures_len != 0u &&
        ec->extended_signatures == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < ec->extended_signatures_len; i++) {         /* :1122  */
        rc = cmt_ecs_ensure_extension(&ec->extended_signatures[i],
                                      ext_enabled);             /* :1123  */
        if (rc != CMT_OK) {
            return rc;                                          /* :1124-1126 */
        }
    }
    return CMT_OK;                                              /* :1127  */
}

/* cometbft@709fd12b types/block.go:1130-1143 — (ec *ExtendedCommit) ToCommit() */
int cmt_extended_commit_to_commit(const cmt_extended_commit_t *ec,
                                  cmt_commit_sig_t *sigs, size_t sigs_cap,
                                  cmt_commit_t *out)
{
    size_t i;

    if (ec == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (ec->extended_signatures_len > sigs_cap ||
        (ec->extended_signatures_len != 0u &&
         (sigs == NULL || ec->extended_signatures == NULL))) {
        return CMT_REJECT;
    }
    for (i = 0; i < ec->extended_signatures_len; i++) {         /* :1133-1136 */
        sigs[i] = ec->extended_signatures[i].commit_sig;
    }
    memset(out, 0, sizeof(*out));      /* see WrappedExtendedCommit above */
    out->height         = ec->height;                           /* :1138  */
    out->round          = ec->round;                            /* :1139  */
    out->block_id       = ec->block_id;                         /* :1140  */
    out->signatures     = sigs;                                 /* :1141  */
    out->signatures_cap = sigs_cap;
    out->signatures_len = ec->extended_signatures_len;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1145-1162 — GetExtendedVote() */
int cmt_extended_commit_get_extended_vote(const cmt_extended_commit_t *ec,
                                          int32_t val_index,
                                          cmt_pb_vote_t *out)
{
    const cmt_extended_commit_sig_t *ecs;
    cmt_block_id_t                   bid;
    int                              rc;

    if (ec == NULL || out == NULL) {
        return CMT_FAULT;
    }
    /* :1147 "It panics if valIndex is out of range." */
    if (val_index < 0 || (size_t)val_index >= ec->extended_signatures_len ||
        ec->extended_signatures == NULL) {
        return CMT_REJECT;
    }
    ecs = &ec->extended_signatures[val_index];                  /* :1149  */
    /* INVARIANT 7495d337 — see cmt_commit_get_vote. */
    if (ecs->commit_sig.validator_address_len >
            (size_t)CMT_PB_ADDRESS_MAX ||
        ecs->commit_sig.signature_len > (size_t)CMT_PB_SIG_MAX ||
        ecs->extension_signature_len > (size_t)CMT_PB_SIG_MAX) {
        return CMT_REJECT;
    }
    rc = cmt_commit_sig_block_id(&ecs->commit_sig, &ec->block_id, &bid);
    if (rc != CMT_OK) {                                         /* :1154  */
        return rc;
    }
    cmt_pb_vote_init(out);
    out->type      = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;        /* :1151  */
    out->height    = ec->height;                                /* :1152  */
    out->round     = ec->round;                                 /* :1153  */
    out->block_id  = bid;                                       /* :1154  */
    out->timestamp = ecs->commit_sig.timestamp;                 /* :1155  */
    memcpy(out->validator_address, ecs->commit_sig.validator_address,
           ecs->commit_sig.validator_address_len);              /* :1156  */
    out->validator_address_len = ecs->commit_sig.validator_address_len;
    out->validator_index       = val_index;                     /* :1157  */
    memcpy(out->signature, ecs->commit_sig.signature,
           ecs->commit_sig.signature_len);                      /* :1158  */
    out->signature_len         = ecs->commit_sig.signature_len;
    out->extension             = ecs->extension;                /* :1159  */
    memcpy(out->extension_signature, ecs->extension_signature,
           ecs->extension_signature_len);                       /* :1160  */
    out->extension_signature_len = ecs->extension_signature_len;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1164-1167 — (ec *ExtendedCommit) Type() */
uint8_t cmt_extended_commit_type(const cmt_extended_commit_t *ec)
{
    (void)ec;
    return (uint8_t)CMT_PB_MSG_TYPE_PRECOMMIT;
}

/* cometbft@709fd12b types/block.go:1169-1171 — GetHeight() */
int64_t cmt_extended_commit_get_height(const cmt_extended_commit_t *ec)
{
    return ec == NULL ? 0 : ec->height;
}

/* cometbft@709fd12b types/block.go:1173-1175 — GetRound() */
int32_t cmt_extended_commit_get_round(const cmt_extended_commit_t *ec)
{
    return ec == NULL ? 0 : ec->round;
}

/* cometbft@709fd12b types/block.go:1177-1184 — (ec *ExtendedCommit) Size() */
size_t cmt_extended_commit_size(const cmt_extended_commit_t *ec)
{
    return ec == NULL ? 0u : ec->extended_signatures_len;
}

/* The `initialBitFn` closure of block.go:1191-1195. */
static bool ec_bit_fn(int i, void *ctx)
{
    const cmt_extended_commit_t *ec = (const cmt_extended_commit_t *)ctx;

    /* NOTE reference TODO (:1192-1193): the BlockID is deliberately NOT
     * consulted, so a conflicting vote sets its bit too. Ported as-is. */
    return ec->extended_signatures[i].commit_sig.block_id_flag !=
           (int32_t)CMT_BLOCK_ID_FLAG_ABSENT;
}

/* cometbft@709fd12b types/block.go:1186-1199 — (ec *ExtendedCommit) BitArray() */
int cmt_extended_commit_bit_array(const cmt_extended_commit_t *ec,
                                  cmt_bit_array_t *out)
{
    if (ec == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (ec->extended_signatures_len != 0u &&
        ec->extended_signatures == NULL) {
        return CMT_FAULT;
    }
    if (ec->extended_signatures_len > (size_t)CMT_BITS_MAX_BITS) {
        return CMT_REJECT;                   /* the derived bit bound     */
    }
    return cmt_bits_new_from_fn(out, (int)ec->extended_signatures_len,
                                ec_bit_fn, (void *)ec);         /* :1196 */
}

/* cometbft@709fd12b types/block.go:1201-1206 — GetByIndex() */
int cmt_extended_commit_get_by_index(const cmt_extended_commit_t *ec,
                                     int32_t val_idx, cmt_pb_vote_t *out)
{
    return cmt_extended_commit_get_extended_vote(ec, val_idx, out);
}

/* cometbft@709fd12b types/block.go:1208-1212 — IsCommit() */
bool cmt_extended_commit_is_commit(const cmt_extended_commit_t *ec)
{
    return ec != NULL && ec->extended_signatures_len != 0u;
}

/* cometbft@709fd12b types/block.go:1214-1239 — (ec *ExtendedCommit) ValidateBasic() */
int cmt_extended_commit_validate_basic(const cmt_extended_commit_t *ec)
{
    size_t i;

    if (ec == NULL) {
        return CMT_FAULT;
    }
    if (ec->height < 0) {
        return CMT_REJECT;                                     /* :1217-1219 */
    }
    if (ec->round < 0) {
        return CMT_REJECT;                                     /* :1220-1222 */
    }
    if (ec->height >= 1) {                                     /* :1224     */
        if (cmt_block_id_is_zero(&ec->block_id)) {
            return CMT_REJECT;                                 /* :1225-1227 */
        }
        if (ec->extended_signatures_len == 0u) {
            return CMT_REJECT;                                 /* :1229-1231 */
        }
        if (ec->extended_signatures == NULL) {
            return CMT_FAULT;
        }
        for (i = 0; i < ec->extended_signatures_len; i++) {    /* :1232-1236 */
            if (cmt_ecs_validate_basic(&ec->extended_signatures[i])
                != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1241-1259 — (ec *ExtendedCommit) ToProto() */
int cmt_extended_commit_to_proto(const cmt_extended_commit_t *ec,
                                 cmt_pb_extended_commit_t *out)
{
    if (ec == NULL || out == NULL) {
        return CMT_FAULT;                            /* :1243-1245 nil   */
    }
    *out = *ec;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1261-1287 — ExtendedCommitFromProto() */
int cmt_extended_commit_from_proto(const cmt_pb_extended_commit_t *ecp,
                                   cmt_extended_commit_sig_t *sigs,
                                   size_t sigs_cap,
                                   cmt_extended_commit_t *out)
{
    cmt_block_id_t bi;
    size_t         i;
    int            rc;

    if (ecp == NULL || out == NULL) {
        return CMT_FAULT;                            /* :1264-1266       */
    }
    if (ecp->extended_signatures_len > sigs_cap ||
        (ecp->extended_signatures_len != 0u &&
         (sigs == NULL || ecp->extended_signatures == NULL))) {
        return CMT_REJECT;
    }
    rc = cmt_block_id_from_proto(&ecp->block_id, &bi);          /* :1270  */
    if (rc != CMT_OK) {
        return rc;
    }
    for (i = 0; i < ecp->extended_signatures_len; i++) {        /* :1275-1280 */
        rc = cmt_ecs_from_proto(&ecp->extended_signatures[i], &sigs[i]);
        if (rc != CMT_OK) {
            return rc;
        }
    }
    memset(out, 0, sizeof(*out));      /* see WrappedExtendedCommit above */
    out->extended_signatures     = sigs;                        /* :1281  */
    out->extended_signatures_cap = sigs_cap;
    out->extended_signatures_len = ecp->extended_signatures_len;
    out->height                  = ecp->height;                 /* :1282  */
    out->round                   = ecp->round;                  /* :1283  */
    out->block_id                = bi;                          /* :1284  */
    return cmt_extended_commit_validate_basic(out);             /* :1286  */
}

/* ══ Data and transactions ════════════════════════════════════════════ */

/* cometbft@709fd12b types/tx.go:28-31 — (tx Tx) Hash() */
int cmt_tx_hash(const uint8_t *tx, size_t tx_len,
                uint8_t out[CMT_TMHASH_SIZE])
{
    return cmt_tmhash_sum(tx, tx_len, out);
}

/* cometbft@709fd12b types/block.go:1302-1311 — (data *Data) Hash(), via
 * types/tx.go:45-50 Txs.Hash and :63-69 hashList. */
int cmt_data_hash(const cmt_data_t *data, uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t           *buf   = NULL;
    cmt_merkle_item_t *items = NULL;
    size_t             n;
    size_t             i;
    int                rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    n = (data == NULL) ? 0u : data->txs_len;         /* :1304-1306 nil   */
    if (n != 0u) {
        if (data->txs == NULL) {
            return CMT_FAULT;
        }
        buf   = (uint8_t *)malloc(n * (size_t)CMT_TMHASH_SIZE);
        items = (cmt_merkle_item_t *)calloc(n, sizeof(*items));
        if (buf == NULL || items == NULL) {
            free(buf);
            free(items);
            return CMT_FAULT;
        }
    }
    for (i = 0; i < n; i++) {                        /* tx.go:65-67      */
        uint8_t *slot = buf + i * (size_t)CMT_TMHASH_SIZE;

        rc = cmt_tx_hash(data->txs[i].data, data->txs[i].len, slot);
        if (rc != CMT_OK) {
            free(buf);
            free(items);
            return rc;
        }
        items[i].data = slot;
        items[i].len  = CMT_TMHASH_SIZE;
    }
    rc = cmt_merkle_hash_from_byte_slices(items, n, out);   /* tx.go:49  */
    free(buf);
    free(items);
    return rc;
}

/* cometbft@709fd12b types/block.go:1333-1346 — (data *Data) ToProto() */
int cmt_data_to_proto(const cmt_data_t *data, cmt_pb_data_t *out)
{
    if (data == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *data;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1348-1367 — DataFromProto().
 * NOTE reference behaviour (:1363): an empty input yields an EMPTY-BUT-
 * NOT-NIL Txs. Both are {NULL, 0} here and both hash to H(""). */
int cmt_data_from_proto(const cmt_pb_data_t *dp, cmt_data_t *out)
{
    if (dp == NULL || out == NULL) {
        return CMT_FAULT;                            /* :1351-1353       */
    }
    *out = *dp;
    return CMT_OK;                                   /* no ValidateBasic */
}

/* ══ EvidenceData ═════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/block.go:1380-1386 — (data *EvidenceData) Hash().
 *
 * The reference's body is `data.Evidence.Hash()` — one call to
 * EvidenceList.Hash (types/evidence.go:450-461). Wave R1-D put that row in
 * its Go file's own home, cmt_evidence.c, so this function is now the one
 * call the reference makes. THE BYTES ARE UNCHANGED: R1-B computed the
 * Merkle root over each item's bare DuplicateVoteEvidence marshal here, and
 * cmt_evidence_list_hash computes the same root over the same leaves; the
 * vectors pinned in test_cmt_block.c are the second reading of that.
 *
 * A NULL `data` hashes the empty list, i.e. H("") — the reference's nil
 * EvidenceData at :1382-1384. */
int cmt_evidence_data_hash(const cmt_evidence_data_t *data,
                           uint8_t out[CMT_TMHASH_SIZE])
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (data == NULL) {
        return cmt_evidence_list_hash(NULL, 0u, out);
    }
    return cmt_evidence_list_hash(data->evidence, data->evidence_len, out);
}

/* cometbft@709fd12b types/block.go:1388-1398 — (data *EvidenceData) ByteSize().
 * The size of the WRAPPED EvidenceList (:1395), not of the bare items. */
int cmt_evidence_data_byte_size(cmt_evidence_data_t *data, int64_t *out)
{
    cmt_pb_evidence_list_t view;
    uint8_t               *buf;
    size_t                 bound = 0;
    size_t                 len;
    size_t                 i;
    int                    rc;

    if (data == NULL || out == NULL) {
        return CMT_FAULT;
    }
    /* :1390 — recomputed while the cache reads 0, which for a genuinely
     * empty list means "every call". Harmless; ported as-is. */
    if (data->byte_size != 0 || data->evidence_len == 0u) {
        *out = data->byte_size;                                /* :1397  */
        return CMT_OK;
    }
    if (data->evidence == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < data->evidence_len; i++) {
        if (!data->evidence[i].has_duplicate_vote_evidence) {
            return CMT_REJECT;
        }
        /* wrapper: tag + uvarint + bare body, then the list's own frame */
        bound += 22u + cmt_dve_upper_bound(
                     &data->evidence[i].duplicate_vote_evidence);
    }
    buf = (uint8_t *)malloc(bound);
    if (buf == NULL) {
        return CMT_FAULT;
    }
    evidence_list_view(data, &view);
    rc = cmt_pb_evidence_list_marshal(&view, buf, bound, &len);
    free(buf);
    if (rc != CMT_OK) {
        return rc;                                   /* :1392-1394 panics */
    }
    data->byte_size = (int64_t)len;                  /* :1395             */
    *out            = data->byte_size;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1420-1438 — (data *EvidenceData) ToProto().
 * The identity: each item already IS the wire wrapper. */
int cmt_evidence_data_to_proto(const cmt_evidence_data_t *data,
                               cmt_pb_evidence_t *out, size_t out_cap,
                               size_t *out_len)
{
    size_t i;

    if (data == NULL || out_len == NULL) {
        return CMT_FAULT;                            /* :1422-1424       */
    }
    if (data->evidence_len > out_cap ||
        (data->evidence_len != 0u && (out == NULL ||
                                      data->evidence == NULL))) {
        return CMT_REJECT;
    }
    for (i = 0; i < data->evidence_len; i++) {       /* :1428-1434       */
        out[i] = data->evidence[i];
    }
    *out_len = data->evidence_len;
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1440-1458 — (data *EvidenceData) FromProto().
 *
 * The per-item EvidenceFromProto of :1448 is PERFORMED since wave R1-D;
 * it was the second of R1-B's two named stage-D holes. */
int cmt_evidence_data_from_proto(const cmt_pb_evidence_t *items, size_t n,
                                 cmt_pb_evidence_t *storage, size_t cap,
                                 cmt_evidence_data_t *out)
{
    cmt_evidence_data_t tmp;
    size_t              i;
    int64_t             size;
    int                 rc;

    if (out == NULL || (items == NULL && n != 0u)) {
        return CMT_FAULT;                            /* :1442-1444       */
    }
    if (n > cap || (n != 0u && storage == NULL)) {
        return CMT_REJECT;
    }
    for (i = 0; i < n; i++) {                        /* :1446-1453       */
        cmt_duplicate_vote_evidence_t ev;

        /* :1448 — `EvidenceFromProto(&pb.Evidence[i])`, which ends in
         * evidence.go:199 ValidateBasic. An invalid item makes the whole
         * FromProto fail (:1449-1451).
         *
         * The reference then stores the DECODED domain object (:1452);
         * this stores the wire item, because `cmt_evidence_data_t` holds
         * wire items (cmt_block.h:677-690, wave R1-B's one non-alias
         * type). The two carry the same bytes: the domain type IS the wire
         * type (cmt_evidence.h) and every step of the decode — VoteFromProto,
         * BlockIDFromProto — is the identity plus validation. So `ev` here
         * exists to be VALIDATED, not to be kept. */
        rc = cmt_evidence_from_proto(&items[i], &ev);
        if (rc != CMT_OK) {
            return rc;
        }
        storage[i] = items[i];
    }
    memset(&tmp, 0, sizeof(tmp));
    tmp.evidence     = storage;
    tmp.evidence_cap = cap;
    tmp.evidence_len = n;                            /* :1454            */
    rc = cmt_evidence_data_byte_size(&tmp, &size);   /* :1455            */
    if (rc != CMT_OK) {
        return rc;
    }
    *out = tmp;
    return CMT_OK;
}

/* ══ Block ════════════════════════════════════════════════════════════ */

/* cometbft@709fd12b types/test_util.go:106-123 — MakeBlock().
 * The production block constructor; see cmt_block.h. */
int cmt_make_block(int64_t height,
                   uint64_t version_block, uint64_t version_app,
                   const cmt_data_t *data,
                   cmt_commit_t *last_commit,
                   const cmt_evidence_data_t *evidence,
                   cmt_block_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    cmt_pb_header_init(&out->header);
    out->header.version.block = version_block;                 /* :112    */
    out->header.version.app   = version_app;                   /* :112    */
    out->header.height        = height;                        /* :113    */
    if (data != NULL) {
        out->data = *data;                                     /* :115-117 */
    }
    if (evidence != NULL) {
        out->evidence = *evidence;                             /* :118    */
    }
    out->last_commit = last_commit;                            /* :119    */
    return cmt_block_fill_header(out);                         /* :121    */
}

/* cometbft@709fd12b types/block.go:109-120 — (b *Block) fillHeader().
 * NOTE reference quirk (:111, :114, :117): the guards are `== nil`, not
 * `len(...) == 0`; C cannot tell the two apart. See cmt_block.h. */
int cmt_block_fill_header(cmt_block_t *b)
{
    int rc;

    if (b == NULL) {
        return CMT_FAULT;
    }
    if (b->header.last_commit_hash_len == 0u) {                /* :111    */
        rc = cmt_commit_hash(b->last_commit, b->header.last_commit_hash);
        if (rc == CMT_HASH_NIL) {
            b->header.last_commit_hash_len = 0u;   /* a nil LastCommit    */
        } else if (rc != CMT_OK) {
            return rc;
        } else {
            b->header.last_commit_hash_len = CMT_TMHASH_SIZE;  /* :112    */
        }
    }
    if (b->header.data_hash_len == 0u) {                       /* :114    */
        rc = cmt_data_hash(&b->data, b->header.data_hash);
        if (rc != CMT_OK) {
            return rc;
        }
        b->header.data_hash_len = CMT_TMHASH_SIZE;             /* :115    */
    }
    if (b->header.evidence_hash_len == 0u) {                   /* :117    */
        rc = cmt_evidence_data_hash(&b->evidence, b->header.evidence_hash);
        if (rc != CMT_OK) {
            return rc;
        }
        b->header.evidence_hash_len = CMT_TMHASH_SIZE;         /* :118    */
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:53-107 — (b *Block) ValidateBasic().
 * The per-evidence loop of :92-97 is PERFORMED since wave R1-D; it was the
 * first of R1-B's two named stage-D holes. */
int cmt_block_validate_basic(const cmt_block_t *b, uint64_t block_protocol)
{
    uint8_t h[CMT_TMHASH_SIZE];
    int     rc;

    if (b == NULL) {
        return CMT_FAULT;                                      /* :57-59  */
    }
    rc = cmt_header_validate_basic(&b->header, block_protocol);/* :64-66  */
    if (rc != CMT_OK) {
        return rc;
    }
    if (b->last_commit == NULL) {
        return CMT_REJECT;                                     /* :69-71  */
    }
    rc = cmt_commit_validate_basic(b->last_commit);            /* :72-74  */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_commit_hash(b->last_commit, h);                   /* :76-81  */
    if (rc != CMT_OK) {
        return rc;
    }
    if (b->header.last_commit_hash_len != (size_t)CMT_TMHASH_SIZE ||
        memcmp(b->header.last_commit_hash, h, CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;
    }
    rc = cmt_data_hash(&b->data, h);                           /* :83-90  */
    if (rc != CMT_OK) {
        return rc;
    }
    if (b->header.data_hash_len != (size_t)CMT_TMHASH_SIZE ||
        memcmp(b->header.data_hash, h, CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;
    }
    /* :92-97 — "b.Evidence.Evidence may be nil, but we're just looping."
     *
     * Each item is materialised through the FromProto path, which is where
     * the reference's ValidateBasic for this branch lives: EvidenceFromProto
     * -> DuplicateVoteEvidenceFromProto -> ValidateBasic (evidence.go:534,
     * :199). The reference's Block holds ALREADY-VALIDATED domain objects
     * and :94 validates them a second time; this port holds wire items
     * (cmt_block.h:677-690), so the decode is how it reaches the same
     * check. The extra run is idempotent — ValidateBasic is a pure
     * predicate over the item's own fields — so the verdict is the
     * reference's, item for item. */
    for (size_t ei = 0; ei < b->evidence.evidence_len; ei++) {
        cmt_duplicate_vote_evidence_t ev;

        if (b->evidence.evidence == NULL) {
            return CMT_FAULT;
        }
        rc = cmt_evidence_from_proto(&b->evidence.evidence[ei], &ev);
        if (rc != CMT_OK) {
            return rc;                                         /* :94-96  */
        }
    }
    rc = cmt_evidence_data_hash(&b->evidence, h);              /* :99-104 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (b->header.evidence_hash_len != (size_t)CMT_TMHASH_SIZE ||
        memcmp(b->header.evidence_hash, h, CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:122-141 — (b *Block) Hash() */
int cmt_block_hash(cmt_block_t *b, uint8_t out[CMT_TMHASH_SIZE])
{
    int rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (b == NULL) {
        return CMT_HASH_NIL;                                   /* :125-127 */
    }
    if (b->last_commit == NULL) {
        return CMT_HASH_NIL;                                   /* :131-133 */
    }
    rc = cmt_block_fill_header(b);                             /* :137     */
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_header_hash(&b->header, out);                   /* :138     */
}

/* cometbft@709fd12b types/block.go:164-174 — (b *Block) HashesTo() */
bool cmt_block_hashes_to(cmt_block_t *b, const uint8_t *hash, size_t hash_len)
{
    uint8_t h[CMT_TMHASH_SIZE];

    if (hash_len == 0u || hash == NULL) {
        return false;                                          /* :167-169 */
    }
    if (b == NULL) {
        return false;                                          /* :170-172 */
    }
    if (cmt_block_hash(b, h) != CMT_OK) {
        return false;              /* a nil hash never equals a non-empty */
    }
    if (hash_len != (size_t)CMT_TMHASH_SIZE) {
        return false;
    }
    return memcmp(h, hash, CMT_TMHASH_SIZE) == 0;              /* :173     */
}

/* cometbft@709fd12b types/block.go:225-244 `(b *Block) ToProto()` followed
 * by proto.Marshal — the outer frame is block.pb.go:136-184. */
int cmt_block_marshal(const cmt_block_t *b, uint8_t *out, size_t cap,
                      size_t *out_len)
{
    cmt_pb_block_t pb;

    if (b == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;                            /* :227-229 nil     */
    }
    /* The wire view of this block: field 1 header, field 2 data and
     * field 3 evidence are ALWAYS emitted and field 4 last_commit is a
     * POINTER, omitted when nil (block.pb.go:136-184). Every one of these
     * members already IS the cmt_pb type — `(b *Block) ToProto()`
     * (block.go:225-244) is the identity on this representation — so this
     * is a copy of four fields and not a conversion. */
    pb.header      = b->header;
    pb.data        = b->data;
    evidence_list_view(&b->evidence, &pb.evidence);
    pb.last_commit = b->last_commit;
    return cmt_pb_block_marshal(&pb, out, cap, out_len);
}

/* cometbft@709fd12b types/block.go:176-184 — (b *Block) Size() */
size_t cmt_block_size(const cmt_block_t *b, uint8_t *scratch,
                      size_t scratch_cap)
{
    size_t len;

    if (cmt_block_marshal(b, scratch, scratch_cap, &len) != CMT_OK) {
        return 0u;                                             /* :179-181 */
    }
    return len;                                                /* :183     */
}

/* cometbft@709fd12b types/block.go:143-162 — (b *Block) MakePartSet() */
int cmt_block_make_part_set(const cmt_block_t *b, uint32_t part_size,
                            uint8_t *scratch, size_t scratch_cap,
                            cmt_part_t *parts, size_t parts_cap,
                            cmt_part_set_t *out)
{
    size_t len;
    int    rc;

    if (b == NULL || out == NULL) {
        return CMT_FAULT;                                      /* :147-149 */
    }
    rc = cmt_block_marshal(b, scratch, scratch_cap, &len);     /* :153-160 */
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_new_part_set_from_data(scratch, len, part_size, parts,
                                      parts_cap, out);         /* :161     */
}

/* cometbft@709fd12b types/block.go:246-277 — BlockFromProto() */
int cmt_block_from_proto(const cmt_block_t *bp, uint64_t block_protocol,
                         cmt_commit_sig_t *sigs, size_t sigs_cap,
                         cmt_pb_evidence_t *ev_storage, size_t ev_cap,
                         cmt_commit_t *last_commit,
                         cmt_block_t *out)
{
    int rc;

    if (bp == NULL || out == NULL) {
        return CMT_FAULT;                                      /* :249-251 */
    }
    memset(out, 0, sizeof(*out));
    rc = cmt_header_from_proto(&bp->header, block_protocol,
                               &out->header);                  /* :254-258 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_data_from_proto(&bp->data, &out->data);           /* :259-263 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_evidence_data_from_proto(bp->evidence.evidence,
                                      bp->evidence.evidence_len,
                                      ev_storage, ev_cap,
                                      &out->evidence);         /* :264-266 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (bp->last_commit != NULL) {                             /* :268     */
        if (last_commit == NULL) {
            return CMT_FAULT;
        }
        rc = cmt_commit_from_proto(bp->last_commit, sigs, sigs_cap,
                                   last_commit);               /* :269-272 */
        if (rc != CMT_OK) {
            return rc;
        }
        out->last_commit = last_commit;                        /* :273     */
    }
    return cmt_block_validate_basic(out, block_protocol);      /* :276     */
}

/* cometbft@709fd12b types/block.go:281-300 — MaxDataBytes().
 * The reference panics on a negative result (:291-297); this REFUSES. */
int cmt_max_data_bytes(int64_t max_bytes, int64_t evidence_bytes,
                       int64_t vals_count, int64_t *out)
{
    int64_t commit_max;
    int64_t v;
    int     rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (evidence_bytes < 0) {
        return CMT_REJECT;
    }
    rc = cmt_max_commit_bytes(vals_count, &commit_max);
    if (rc != CMT_OK) {
        return rc;
    }
    /* Go's int64 subtraction wraps; C's signed overflow is UNDEFINED, so
     * every term is checked before it is subtracted, including the two
     * constants. Reachable only for an absurd configured MaxBytes near
     * INT64_MIN, which :291-297 would refuse anyway. */
    v = max_bytes;                                             /* :285-289 */
    if (v < INT64_MIN + CMT_MAX_OVERHEAD_FOR_BLOCK) {
        return CMT_REJECT;
    }
    v -= CMT_MAX_OVERHEAD_FOR_BLOCK;
    if (v < INT64_MIN + CMT_MAX_HEADER_BYTES) {
        return CMT_REJECT;
    }
    v -= CMT_MAX_HEADER_BYTES;
    if (v < INT64_MIN + commit_max) {
        return CMT_REJECT;
    }
    v -= commit_max;
    if (v < INT64_MIN + evidence_bytes) {
        return CMT_REJECT;
    }
    v -= evidence_bytes;
    if (v < 0) {
        return CMT_REJECT;                                     /* :291-297 */
    }
    *out = v;                                                  /* :299     */
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:302-321 — MaxDataBytesNoEvidence() */
int cmt_max_data_bytes_no_evidence(int64_t max_bytes, int64_t vals_count,
                                   int64_t *out)
{
    return cmt_max_data_bytes(max_bytes, 0, vals_count, out);
}
