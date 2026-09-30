/**
 * @file shared/dnac/cmt_params.c
 * @brief cometbft @v0.38.26 types/params.go in C — see cmt_params.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_params.h"

#include <string.h>

/**
 * cometbft@709fd12b types/params.go:28-31 — `ABCIPubKeyTypesToNames` (709fd12b; at v0.38.26: :30-34, with a third row, mldsa65 — not ported).
 * Only the KEY SET is consulted (:202, a bare `_, ok :=`), so the map's
 * value side has no consumer here and the map itself becomes an array.
 * The reference's two rows have no counterpart on this chain; the one row
 * below is the ML-DSA-87 name, whose VALUE is the header's QUESTION.
 */
static const char *const k_known_pubkey_types[] = {
    CMT_PUBKEY_TYPE_MLDSA87_NAME
};
#define K_KNOWN_PUBKEY_TYPES_N \
    (sizeof(k_known_pubkey_types) / sizeof(k_known_pubkey_types[0]))

/** Bounded, NUL-terminated string equality over the fixed-width storage. */
static bool type_eq(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    return strncmp(a, b, CMT_PARAMS_PUBKEY_TYPE_MAX) == 0;
}

static bool is_known_pubkey_type(const char *t)
{
    size_t i;

    for (i = 0; i < K_KNOWN_PUBKEY_TYPES_N; i++) {   /* :202 membership */
        if (type_eq(t, k_known_pubkey_types[i])) {
            return true;
        }
    }
    return false;
}

/* ── constructors ───────────────────────────────────────────────────── */

/* :100-105 DefaultBlockParams() */
void cmt_default_block_params(cmt_block_params_t *out)
{
    if (out == NULL) {
        return;
    }
    out->max_bytes = 22020096;   /* :102, 21MB */
    out->max_gas   = -1;         /* :103 */
}

/* :108-114 DefaultEvidenceParams() */
void cmt_default_evidence_params(cmt_evidence_params_t *out)
{
    if (out == NULL) {
        return;
    }
    out->max_age_num_blocks = 100000;   /* :110, 27.8 hrs at 1 block/s */
    /* :111 `48 * time.Hour`. A time.Duration counts NANOSECONDS, so the
     * arithmetic is spelled out rather than pasted as a magic number:
     * 48 * 3600 * 1e9 = 172800000000000. */
    out->max_age_duration_ns = (int64_t)48 * 3600 * 1000000000;
    out->max_bytes           = 1048576; /* :112, 1MB */
}

/* :118-122 DefaultValidatorParams() */
void cmt_default_validator_params(cmt_validator_params_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    /* :120 — the reference lists exactly one type, ed25519. */
    strncpy(out->pub_key_types[0], CMT_PUBKEY_TYPE_MLDSA87_NAME,
            CMT_PARAMS_PUBKEY_TYPE_MAX - 1);
    out->pub_key_types_len = 1;
}

/* :124-128 DefaultVersionParams() */
void cmt_default_version_params(cmt_version_params_t *out)
{
    if (out != NULL) {
        out->app = 0;    /* :126 */
    }
}

/* :130-135 DefaultABCIParams() */
void cmt_default_abci_params(cmt_abci_params_t *out)
{
    if (out != NULL) {
        /* :132-133 — 0 MEANS "not required", it is not a height. */
        out->vote_extensions_enable_height = 0;
    }
}

/* :89-97 DefaultConsensusParams() */
void cmt_default_consensus_params(cmt_consensus_params_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    cmt_default_block_params(&out->block);         /* :91 */
    cmt_default_evidence_params(&out->evidence);   /* :92 */
    cmt_default_validator_params(&out->validator); /* :93 */
    cmt_default_version_params(&out->version);     /* :94 */
    cmt_default_abci_params(&out->abci);           /* :95 */
}

/* ── predicates ─────────────────────────────────────────────────────── */

/* :78-86 VoteExtensionsEnabled() */
int cmt_abci_params_vote_extensions_enabled(cmt_abci_params_t a, int64_t h,
                                            bool *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (h < 1) {                                   /* :79-81 panic */
        return CMT_REJECT;
    }
    if (a.vote_extensions_enable_height == 0) {    /* :82-84 */
        *out = false;
        return CMT_OK;
    }
    *out = (a.vote_extensions_enable_height <= h); /* :85 */
    return CMT_OK;
}

/* :137-144 IsValidPubkeyType() */
bool cmt_is_valid_pubkey_type(const cmt_validator_params_t *params,
                              const char *pubkey_type)
{
    size_t i;

    if (params == NULL || pubkey_type == NULL) {
        return false;
    }
    for (i = 0; i < params->pub_key_types_len &&
                i < CMT_PARAMS_MAX_PUBKEY_TYPES; i++) {   /* :138-142 */
        if (type_eq(params->pub_key_types[i], pubkey_type)) {
            return true;                                  /* :140 */
        }
    }
    return false;                                         /* :143 */
}

/* :148-209 ValidateBasic() */
int cmt_consensus_params_validate_basic(const cmt_consensus_params_t *params)
{
    int64_t max_bytes;
    size_t  i;

    if (params == NULL) {
        return CMT_FAULT;
    }
    if (params->block.max_bytes == 0) {                   /* :149-151 */
        return CMT_REJECT;
    }
    if (params->block.max_bytes < -1) {                   /* :152-156 */
        return CMT_REJECT;
    }
    if (params->block.max_bytes > CMT_MAX_BLOCK_SIZE_BYTES) {  /* :157-160 */
        return CMT_REJECT;
    }
    if (params->block.max_gas < -1) {                     /* :162-165 */
        return CMT_REJECT;
    }
    if (params->evidence.max_age_num_blocks <= 0) {       /* :167-170 */
        return CMT_REJECT;
    }
    if (params->evidence.max_age_duration_ns <= 0) {      /* :172-175 */
        return CMT_REJECT;
    }
    /* :177-180 — a Block.MaxBytes of -1 (unbounded) is measured against
     * the hard ceiling instead. */
    max_bytes = params->block.max_bytes;
    if (max_bytes == -1) {
        max_bytes = (int64_t)CMT_MAX_BLOCK_SIZE_BYTES;
    }
    if (params->evidence.max_bytes > max_bytes) {         /* :181-184 */
        return CMT_REJECT;
    }
    if (params->evidence.max_bytes < 0) {                 /* :186-189 */
        return CMT_REJECT;
    }
    if (params->abci.vote_extensions_enable_height < 0) { /* :191-193 */
        return CMT_REJECT;
    }
    if (params->validator.pub_key_types_len == 0) {       /* :195-197 */
        return CMT_REJECT;
    }
    if (params->validator.pub_key_types_len > CMT_PARAMS_MAX_PUBKEY_TYPES) {
        return CMT_REJECT;   /* capacity — the reference's slice is unbounded */
    }
    for (i = 0; i < params->validator.pub_key_types_len; i++) { /* :199-206 */
        if (!is_known_pubkey_type(params->validator.pub_key_types[i])) {
            return CMT_REJECT;                            /* :203-205 */
        }
    }
    return CMT_OK;                                        /* :208 */
}

/* :223-269 ValidateUpdate(). The numbered rows are the table at :212-222. */
int cmt_consensus_params_validate_update(
        const cmt_consensus_params_t *params,
        const cmt_consensus_params_proto_t *updated, int64_t h)
{
    int64_t cur, upd;

    if (params == NULL) {
        return CMT_FAULT;
    }
    if (updated == NULL || !updated->has_abci) {          /* 1 — :225-227 */
        return CMT_OK;
    }
    cur = params->abci.vote_extensions_enable_height;
    upd = updated->abci.vote_extensions_enable_height;

    if (upd < 0) {                                        /* 2 — :229-231 */
        return CMT_REJECT;
    }
    if (cur <= 0 && upd == 0) {                           /* 3 — :233-235 */
        return CMT_OK;
    }
    if (cur == upd) {                                     /* 4 — :237-239 */
        return CMT_OK;
    }
    if (cur > 0 && upd == 0) {                            /* 5 & 6 — :241-250 */
        if (cur <= h) {
            return CMT_REJECT;                            /* 5 — :243-247 */
        }
        return CMT_OK;                                    /* 6 — :249 */
    }
    if (upd <= h) {                                       /* 7 — :252-256 */
        return CMT_REJECT;
    }
    if (cur <= 0) {                                       /* 8 — :258-260 */
        return CMT_OK;
    }
    if (cur <= h) {                                       /* 9 — :262-266 */
        return CMT_REJECT;
    }
    return CMT_OK;                                        /* 10 — :268 */
}

/* :275-293 Hash() — ConsensusHash. FLAT, not Merkle. */
int cmt_consensus_params_hash(const cmt_consensus_params_t *params,
                              uint8_t out[CMT_TMHASH_SIZE])
{
    cmt_pb_hashed_params_t hp;
    uint8_t                buf[32];
    size_t                 len = 0;
    int                    rc;

    if (params == NULL || out == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_hashed_params_init(&hp);
    hp.block_max_bytes = params->block.max_bytes;         /* :279 */
    hp.block_max_gas   = params->block.max_gas;           /* :280 */

    /* :283 — the whole message is two varint fields, so 32 bytes is
     * generous: the worst case is 2 * (1 tag + 10 varint) = 22. */
    rc = cmt_pb_hashed_params_marshal(&hp, buf, sizeof(buf), &len);
    if (rc != CMT_OK) {
        return rc;                                        /* :284-286 panic */
    }
    /* :276 + :288-292 — hasher.Write(bz) then Sum(nil). */
    return cmt_tmhash_sum(buf, len, out);
}

/* :297-326 Update() */
int cmt_consensus_params_update(const cmt_consensus_params_t *params,
                                const cmt_consensus_params_proto_t *params2,
                                cmt_consensus_params_t *out)
{
    if (params == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *params;                                       /* :298 explicit copy */
    if (params2 == NULL) {                                /* :300-302 */
        return CMT_OK;
    }
    /* :304-324 — each sub-message is applied WHOLE when it is non-nil,
     * zeros included. See the header's NOTE on the comment at :295. */
    if (params2->has_block) {                             /* :305-308 */
        out->block.max_bytes = params2->block.max_bytes;
        out->block.max_gas   = params2->block.max_gas;
    }
    if (params2->has_evidence) {                          /* :309-313 */
        out->evidence.max_age_num_blocks  = params2->evidence.max_age_num_blocks;
        out->evidence.max_age_duration_ns = params2->evidence.max_age_duration_ns;
        out->evidence.max_bytes           = params2->evidence.max_bytes;
    }
    if (params2->has_validator) {                         /* :314-318 */
        if (params2->validator.pub_key_types_len >
            CMT_PARAMS_MAX_PUBKEY_TYPES) {
            return CMT_REJECT;
        }
        /* :317 — the reference APPENDS to a fresh slice precisely so the
         * result does not alias params2's; the struct copy does the same. */
        out->validator = params2->validator;
    }
    if (params2->has_version) {                           /* :319-321 */
        out->version.app = params2->version.app;
    }
    if (params2->has_abci) {                              /* :322-324 */
        out->abci.vote_extensions_enable_height =
            params2->abci.vote_extensions_enable_height;
    }
    return CMT_OK;                                        /* :325 */
}
