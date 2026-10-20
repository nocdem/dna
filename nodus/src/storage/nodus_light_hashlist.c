/**
 * @file nodus_light_hashlist.c
 * @brief Storage package P-B2 — the light hash list of one historical
 *        segment: the anchor, the backward header pass over channel 0x73
 *        and the hash source. Contract, checks, rotation and determinism:
 *        nodus_light_hashlist.h.
 *
 * Nothing here reads a clock (the light client's `now` is the caller's),
 * draws randomness, touches a file or opens a socket.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "storage/nodus_light_hashlist.h"

#include "dnac/cmt_light_block.h"
#include "dnac/cmt_light_verifier.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_tmhash.h"

#include "crypto/utils/qgp_log.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "LIGHT_HASHLIST"

#define LHL_P  ((uint64_t)DNA_V2_SEGMENT_BLOCKS)

struct nodus_light_hashlist {
    uint64_t       k;
    uint64_t       first;          /* (k−1)·P + 1                        */
    uint64_t       last;           /* k·P                                */
    uint64_t       next_h;         /* next request's h; first − 1 = done */
    uint64_t       block_protocol;
    uint8_t      (*hash)[64];      /* hash[i] = the hash at first + i,
                                    * i = 0 … P (P + 1 entries)          */
    cmt_header_t  *trusted;        /* the verified header above next_h   */
    cmt_header_t  *cand;           /* the candidate being checked        */
    uint8_t       *ans;            /* NODUS_STFETCH_MSG_MAX              */
    size_t         peer;           /* the peer the next request goes to  */
    size_t         fails;          /* refusals since the last accept     */
    bool           complete;
    nodus_lhl_stats_t stats;
};

const char *nodus_lhl_refusal_str(nodus_lhl_refusal_t r) {
    switch (r) {
    case NODUS_LHL_R_SILENT:     return "silent";
    case NODUS_LHL_R_ANSWER:     return "answer";
    case NODUS_LHL_R_RQ:         return "rq";
    case NODUS_LHL_R_REFUSED:    return "refused";
    case NODUS_LHL_R_SHAPE:      return "shape";
    case NODUS_LHL_R_HDR_DECODE: return "hdr_decode";
    case NODUS_LHL_R_HEIGHT:     return "height";
    case NODUS_LHL_R_BACKWARDS:  return "backwards";
    case NODUS_LHL_R_HASH:       return "hash";
    case NODUS_LHL_R_BLOCK_ID:   return "block_id";
    case NODUS_LHL_R_COUNT:      break;
    }
    return "?";
}

/* k·P + 1 inside int64 — the request rule (nodus_stfetch_req_valid, the
 * part-0 request at h = k·P). */
static bool k_ok(uint64_t k) {
    const nodus_stfetch_req_t r = { k, k == 0 ? 0 : k * LHL_P, 0,
                                    NODUS_STFETCH_CONT_FIRST };
    return k != 0 && nodus_stfetch_req_valid(&r);
}

void nodus_light_hashlist_free(nodus_light_hashlist_t *hl) {
    if (!hl) return;
    if (hl->hash) {
        memset(hl->hash, 0, (size_t)(LHL_P + 1u) * 64u);
        free(hl->hash);
    }
    free(hl->trusted);
    free(hl->cand);
    free(hl->ans);
    free(hl);
}

int nodus_light_hashlist_new(uint64_t k, const cmt_header_t *anchor,
                             uint64_t block_protocol,
                             nodus_light_hashlist_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!anchor || !k_ok(k)) return -1;
    const uint64_t first = (k - 1u) * LHL_P + 1u, last = k * LHL_P;
    if (anchor->height < 0 || (uint64_t)anchor->height != last + 1u) {
        QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": anchor height %" PRId64
                     " is not %" PRIu64, k, (int64_t)anchor->height,
                     last + 1u);
        return -1;
    }
    if (anchor->last_block_id.hash_len != CMT_TMHASH_SIZE) return -1;

    nodus_light_hashlist_t *hl = calloc(1, sizeof(*hl));
    if (!hl) return -1;
    hl->hash = calloc((size_t)(LHL_P + 1u), 64u);
    hl->trusted = malloc(sizeof(*hl->trusted));
    hl->cand = malloc(sizeof(*hl->cand));
    hl->ans = malloc(NODUS_STFETCH_MSG_MAX);
    if (!hl->hash || !hl->trusted || !hl->cand || !hl->ans) goto fail;

    hl->k = k;
    hl->first = first;
    hl->last = last;
    hl->block_protocol = block_protocol;
    memcpy(hl->trusted, anchor, sizeof(*hl->trusted));
    if (cmt_header_hash(hl->trusted, hl->hash[LHL_P]) != CMT_OK)
        goto fail;                       /* nil (CMT_HASH_NIL) or a fault */
    memcpy(hl->hash[LHL_P - 1u], anchor->last_block_id.hash, 64);
    hl->next_h = last - 1u;              /* brings header(last)          */
    *out = hl;
    return 0;
fail:
    nodus_light_hashlist_free(hl);
    return -1;
}

int nodus_light_hashlist_new_from_client(cmt_light_client_t *c, uint64_t k,
                                         cmt_time_t now,
                                         uint64_t block_protocol,
                                         nodus_light_hashlist_t **out,
                                         cmt_light_client_error_t *err) {
    if (out) *out = NULL;
    if (!c || !out || !k_ok(k)) return -1;
    cmt_light_block_buf_t *b = cmt_light_block_buf_new();
    if (!b) return -1;
    int ret = -1;
    const int rc = cmt_light_client_verify_light_block_at_height(
            c, (int64_t)(k * LHL_P + 1u), now, b, err);
    if (rc == CMT_REJECT) {
        QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": the light client did "
                     "not verify height %" PRIu64, k, k * LHL_P + 1u);
        ret = 1;
    } else if (rc == CMT_OK && b->lb.signed_header &&
               b->lb.signed_header->header) {
        ret = nodus_light_hashlist_new(k, b->lb.signed_header->header,
                                       block_protocol, out);
    }
    cmt_light_block_buf_free(b);
    return ret;
}

uint64_t nodus_light_hashlist_k(const nodus_light_hashlist_t *hl) {
    return hl ? hl->k : 0;
}

uint64_t nodus_light_hashlist_next_height(const nodus_light_hashlist_t *hl) {
    return (!hl || hl->next_h < hl->first) ? 0 : hl->next_h;
}

size_t nodus_light_hashlist_peer(const nodus_light_hashlist_t *hl) {
    return hl ? hl->peer : 0;
}

nodus_lhl_stats_t nodus_light_hashlist_stats(const nodus_light_hashlist_t *hl) {
    nodus_lhl_stats_t s;
    if (hl) return hl->stats;
    memset(&s, 0, sizeof(s));
    return s;
}

/* One exchange for h = hl->next_h with hl->peer. @return 1 accepted
 * (hash(h) stored, the candidate is the trusted header), 0 refused
 * (*why), -1 fault. Nothing is stored unless every check passed. */
static int exchange(nodus_light_hashlist_t *hl, const nodus_light_fetch_t *f,
                    nodus_lhl_refusal_t *why) {
    const uint64_t h = hl->next_h;
    const nodus_stfetch_req_t req = { hl->k, h, 0, NODUS_STFETCH_CONT_FIRST };
    uint8_t msg[NODUS_STFETCH_REQ_MSG_LEN], rq[64];
    size_t len = 0;
    if (nodus_stfetch_req_encode(&req, msg) != 0 ||
        nodus_stfetch_req_id(&req, rq) != 0)
        return -1;
    hl->stats.requests++;
    const int t = f->request(f->ctx, hl->peer, msg, sizeof(msg), hl->ans,
                             NODUS_STFETCH_MSG_MAX, &len);
    if (t < 0) return -1;
    if (t != 0) { *why = NODUS_LHL_R_SILENT; return 0; }
    if (len > NODUS_STFETCH_MSG_MAX) { *why = NODUS_LHL_R_ANSWER; return 0; }

    /* a. the answer: decodes, answers this request, OK, its shape */
    nodus_stfetch_ans_view_t a;
    if (nodus_stfetch_ans_decode(hl->ans, len, &a) != 0) {
        *why = NODUS_LHL_R_ANSWER;
        return 0;
    }
    if (memcmp(a.rq, rq, 64) != 0) { *why = NODUS_LHL_R_RQ; return 0; }
    if (a.code != NODUS_STFETCH_OK) { *why = NODUS_LHL_R_REFUSED; return 0; }
    if (!nodus_stfetch_ans_shape_ok(&req, &a)) {
        *why = NODUS_LHL_R_SHAPE;
        return 0;
    }

    /* b. header(h+1) decodes */
    cmt_pb_header_init(hl->cand);
    if (cmt_pb_header_unmarshal(a.hdr, a.hdr_len, hl->cand) != CMT_OK) {
        *why = NODUS_LHL_R_HDR_DECODE;
        return 0;
    }
    /* c. exactly height h + 1 (VerifyBackwards does not check it) */
    if (hl->cand->height < 0 || (uint64_t)hl->cand->height != h + 1u) {
        *why = NODUS_LHL_R_HEIGHT;
        return 0;
    }
    /* d. VerifyBackwards against the trusted header above it */
    cmt_light_error_t verr;
    const int vb = cmt_light_verify_backwards(hl->cand, hl->trusted,
                                              hl->block_protocol, &verr);
    if (vb == CMT_FAULT) return -1;
    if (vb != CMT_OK) { *why = NODUS_LHL_R_BACKWARDS; return 0; }
    /* e. its hash is the one this list holds for h + 1 */
    uint8_t got[CMT_TMHASH_SIZE];
    const int hr = cmt_header_hash(hl->cand, got);
    if (hr == CMT_FAULT) return -1;
    if (hr != CMT_OK ||
        memcmp(got, hl->hash[h + 1u - hl->first], 64) != 0) {
        *why = NODUS_LHL_R_HASH;
        return 0;
    }
    /* f. it names block h by a 64-byte hash */
    if (hl->cand->last_block_id.hash_len != CMT_TMHASH_SIZE) {
        *why = NODUS_LHL_R_BLOCK_ID;
        return 0;
    }

    memcpy(hl->hash[h - hl->first], hl->cand->last_block_id.hash, 64);
    cmt_header_t *tmp = hl->trusted;
    hl->trusted = hl->cand;
    hl->cand = tmp;
    return 1;
}

/* The pass is over once header(first + 1) was accepted (next_h = first −
 * 1). Marks the list complete. */
static bool pass_over(nodus_light_hashlist_t *hl) {
    if (hl->next_h >= hl->first) return false;
    if (!hl->complete) {
        hl->complete = true;
        QGP_LOG_INFO(LOG_TAG, "segment %" PRIu64 ": %" PRIu64 " hashes held "
                     "(%" PRIu64 " requests, %" PRIu64 " refused)", hl->k,
                     LHL_P + 1u, hl->stats.requests,
                     hl->stats.requests - hl->stats.accepted);
    }
    return true;
}

int nodus_light_hashlist_step(nodus_light_hashlist_t *hl,
                              const nodus_light_fetch_t *f,
                              uint32_t max_headers) {
    if (!hl || !f || !f->request || f->n_peers == 0)
        return NODUS_LHL_STEP_FAULT;
    if (pass_over(hl)) return NODUS_LHL_STEP_DONE;
    if (hl->peer >= f->n_peers) hl->peer = 0;   /* the peer list shrank */

    uint32_t done = 0;
    while (done < max_headers) {
        if (pass_over(hl)) return NODUS_LHL_STEP_DONE;
        nodus_lhl_refusal_t why = NODUS_LHL_R_SILENT;
        const int rc = exchange(hl, f, &why);
        if (rc < 0) return NODUS_LHL_STEP_FAULT;
        if (rc == 1) {
            hl->stats.accepted++;
            hl->fails = 0;
            hl->next_h--;                /* first − 1 when first was done */
            done++;
            continue;
        }
        hl->stats.refused[why]++;
        QGP_LOG_DEBUG(LOG_TAG, "segment %" PRIu64 " h %" PRIu64 ": peer %zu "
                      "refused (%s), next peer", hl->k, hl->next_h, hl->peer,
                      nodus_lhl_refusal_str(why));
        hl->peer = (hl->peer + 1u) % f->n_peers;
        if (++hl->fails >= f->n_peers) {
            hl->fails = 0;
            QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 " h %" PRIu64 ": a "
                         "full round of %zu peers without a header",
                         hl->k, hl->next_h, f->n_peers);
            return NODUS_LHL_STEP_ROUND;
        }
    }
    return pass_over(hl) ? NODUS_LHL_STEP_DONE : NODUS_LHL_STEP_MORE;
}

static int lhl_hash_at(void *ctx, uint64_t h, uint8_t out[64]) {
    const nodus_light_hashlist_t *hl = ctx;
    if (!hl || !out) return -1;
    if (!hl->complete || h < hl->first || h > hl->last + 1u) return 1;
    memcpy(out, hl->hash[h - hl->first], 64);
    return 0;
}

nodus_seg_hash_src_t nodus_light_hashlist_src(const nodus_light_hashlist_t *hl) {
    nodus_seg_hash_src_t s;
    s.ctx = (void *)(uintptr_t)hl;   /* read only: lhl_hash_at never writes */
    s.hash_at = lhl_hash_at;
    return s;
}
