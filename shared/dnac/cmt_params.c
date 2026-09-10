/**
 * @file shared/dnac/cmt_params.c
 * @brief cometbft @709fd12b types/params.go in C — see cmt_params.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_params.h"

#include <string.h>

/**
 * cometbft@709fd12b types/params.go:28-31 — `ABCIPubKeyTypesToNames`.
 * Only the KEY SET is consulted (:199, a bare `_, ok :=`), so the map's
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

    for (i = 0; i < K_KNOWN_PUBKEY_TYPES_N; i++) {   /* :199 membership */
        if (type_eq(t, k_known_pubkey_types[i])) {
            return true;
        }
    }
    return false;
}

/* ── constructors ───────────────────────────────────────────────────── */

/* :97-102 DefaultBlockParams() */
void cmt_default_block_params(cmt_block_params_t *out)
{
    if (out == NULL) {
        return;
    }
    out->max_bytes = 22020096;   /* :99, 21MB */
    out->max_gas   = -1;         /* :100 */
}

/* :105-111 DefaultEvidenceParams() */
void cmt_default_evidence_params(cmt_evidence_params_t *out)
{
    if (out == NULL) {
        return;
    }
    out->max_age_num_blocks = 100000;   /* :107, 27.8 hrs at 1 block/s */
    /* :108 `48 * time.Hour`. A time.Duration counts NANOSECONDS, so the
     * arithmetic is spelled out rather than pasted as a magic number:
     * 48 * 3600 * 1e9 = 172800000000000. */
    out->max_age_duration_ns = (int64_t)48 * 3600 * 1000000000;
    out->max_bytes           = 1048576; /* :109, 1MB */
}

/* :115-119 DefaultValidatorParams() */
void cmt_default_validator_params(cmt_validator_params_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    /* :117 — the reference lists exactly one type, ed25519. */
    strncpy(out->pub_key_types[0], CMT_PUBKEY_TYPE_MLDSA87_NAME,
            CMT_PARAMS_PUBKEY_TYPE_MAX - 1);
    out->pub_key_types_len = 1;
}

/* :121-125 DefaultVersionParams() */
void cmt_default_version_params(cmt_version_params_t *out)
{
    if (out != NULL) {
        out->app = 0;    /* :123 */
    }
}

/* :127-132 DefaultABCIParams() */
void cmt_default_abci_params(cmt_abci_params_t *out)
{
    if (out != NULL) {
        /* :129-130 — 0 MEANS "not required", it is not a height. */
        out->vote_extensions_enable_height = 0;
    }
}

/* :86-94 DefaultConsensusParams() */
void cmt_default_consensus_params(cmt_consensus_params_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    cmt_default_block_params(&out->block);         /* :88 */
    cmt_default_evidence_params(&out->evidence);   /* :89 */
    cmt_default_validator_params(&out->validator); /* :90 */
    cmt_default_version_params(&out->version);     /* :91 */
    cmt_default_abci_params(&out->abci);           /* :92 */
}

/* ── predicates ─────────────────────────────────────────────────────── */

/* :75-83 VoteExtensionsEnabled() */
int cmt_abci_params_vote_extensions_enabled(cmt_abci_params_t a, int64_t h,
                                            bool *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (h < 1) {                                   /* :76-78 panic */
        return CMT_REJECT;
    }
    if (a.vote_extensions_enable_height == 0) {    /* :79-81 */
        *out = false;
        return CMT_OK;
    }
    *out = (a.vote_extensions_enable_height <= h); /* :82 */
    return CMT_OK;
}

/* :134-141 IsValidPubkeyType() */
bool cmt_is_valid_pubkey_type(const cmt_validator_params_t *params,
                              const char *pubkey_type)
{
    size_t i;

    if (params == NULL || pubkey_type == NULL) {
        return false;
    }
    for (i = 0; i < params->pub_key_types_len &&
                i < CMT_PARAMS_MAX_PUBKEY_TYPES; i++) {   /* :135-139 */
        if (type_eq(params->pub_key_types[i], pubkey_type)) {
            return true;                                  /* :137 */
        }
    }
    return false;                                         /* :140 */
}

/* :145-206 ValidateBasic() */
int cmt_consensus_params_validate_basic(const cmt_consensus_params_t *params)
{
    int64_t max_bytes;
    size_t  i;

    if (params == NULL) {
        return CMT_FAULT;
    }
    if (params->block.max_bytes == 0) {                   /* :146-148 */
        return CMT_REJECT;
    }
    if (params->block.max_bytes < -1) {                   /* :149-153 */
        return CMT_REJECT;
    }
    if (params->block.max_bytes > CMT_MAX_BLOCK_SIZE_BYTES) {  /* :154-157 */
        return CMT_REJECT;
    }
    if (params->block.max_gas < -1) {                     /* :159-162 */
        return CMT_REJECT;
    }
    if (params->evidence.max_age_num_blocks <= 0) {       /* :164-167 */
        return CMT_REJECT;
    }
    if (params->evidence.max_age_duration_ns <= 0) {      /* :169-172 */
        return CMT_REJECT;
    }
    /* :174-177 — a Block.MaxBytes of -1 (unbounded) is measured against
     * the hard ceiling instead. */
    max_bytes = params->block.max_bytes;
    if (max_bytes == -1) {
        max_bytes = (int64_t)CMT_MAX_BLOCK_SIZE_BYTES;
    }
    if (params->evidence.max_bytes > max_bytes) {         /* :178-181 */
        return CMT_REJECT;
    }
    if (params->evidence.max_bytes < 0) {                 /* :183-186 */
        return CMT_REJECT;
    }
    if (params->abci.vote_extensions_enable_height < 0) { /* :188-190 */
        return CMT_REJECT;
    }
    if (params->validator.pub_key_types_len == 0) {       /* :192-194 */
        return CMT_REJECT;
    }
    if (params->validator.pub_key_types_len > CMT_PARAMS_MAX_PUBKEY_TYPES) {
        return CMT_REJECT;   /* capacity — the reference's slice is unbounded */
    }
    for (i = 0; i < params->validator.pub_key_types_len; i++) { /* :196-203 */
        if (!is_known_pubkey_type(params->validator.pub_key_types[i])) {
            return CMT_REJECT;                            /* :200-202 */
        }
    }
    return CMT_OK;                                        /* :205 */
}

/* :220-266 ValidateUpdate(). The numbered rows are the table at :209-219. */
int cmt_consensus_params_validate_update(
        const cmt_consensus_params_t *params,
        const cmt_consensus_params_proto_t *updated, int64_t h)
{
    int64_t cur, upd;

    if (params == NULL) {
        return CMT_FAULT;
    }
    if (updated == NULL || !updated->has_abci) {          /* 1 — :222-224 */
        return CMT_OK;
    }
    cur = params->abci.vote_extensions_enable_height;
    upd = updated->abci.vote_extensions_enable_height;

    if (upd < 0) {                                        /* 2 — :226-228 */
        return CMT_REJECT;
    }
    if (cur <= 0 && upd == 0) {                           /* 3 — :230-232 */
        return CMT_OK;
    }
    if (cur == upd) {                                     /* 4 — :234-236 */
        return CMT_OK;
    }
    if (cur > 0 && upd == 0) {                            /* 5 & 6 — :238-247 */
        if (cur <= h) {
            return CMT_REJECT;                            /* 5 — :240-244 */
        }
        return CMT_OK;                                    /* 6 — :246 */
    }
    if (upd <= h) {                                       /* 7 — :249-253 */
        return CMT_REJECT;
    }
    if (cur <= 0) {                                       /* 8 — :255-257 */
        return CMT_OK;
    }
    if (cur <= h) {                                       /* 9 — :259-263 */
        return CMT_REJECT;
    }
    return CMT_OK;                                        /* 10 — :265 */
}

/* :272-290 Hash() — ConsensusHash. FLAT, not Merkle. */
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
    hp.block_max_bytes = params->block.max_bytes;         /* :276 */
    hp.block_max_gas   = params->block.max_gas;           /* :277 */

    /* :280 — the whole message is two varint fields, so 32 bytes is
     * generous: the worst case is 2 * (1 tag + 10 varint) = 22. */
    rc = cmt_pb_hashed_params_marshal(&hp, buf, sizeof(buf), &len);
    if (rc != CMT_OK) {
        return rc;                                        /* :281-283 panic */
    }
    /* :273 + :285-289 — hasher.Write(bz) then Sum(nil). */
    return cmt_tmhash_sum(buf, len, out);
}

/* :294-323 Update() */
int cmt_consensus_params_update(const cmt_consensus_params_t *params,
                                const cmt_consensus_params_proto_t *params2,
                                cmt_consensus_params_t *out)
{
    if (params == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = *params;                                       /* :295 explicit copy */
    if (params2 == NULL) {                                /* :297-299 */
        return CMT_OK;
    }
    /* :301-321 — each sub-message is applied WHOLE when it is non-nil,
     * zeros included. See the header's NOTE on the comment at :292. */
    if (params2->has_block) {                             /* :302-305 */
        out->block.max_bytes = params2->block.max_bytes;
        out->block.max_gas   = params2->block.max_gas;
    }
    if (params2->has_evidence) {                          /* :306-310 */
        out->evidence.max_age_num_blocks  = params2->evidence.max_age_num_blocks;
        out->evidence.max_age_duration_ns = params2->evidence.max_age_duration_ns;
        out->evidence.max_bytes           = params2->evidence.max_bytes;
    }
    if (params2->has_validator) {                         /* :311-315 */
        if (params2->validator.pub_key_types_len >
            CMT_PARAMS_MAX_PUBKEY_TYPES) {
            return CMT_REJECT;
        }
        /* :314 — the reference APPENDS to a fresh slice precisely so the
         * result does not alias params2's; the struct copy does the same. */
        out->validator = params2->validator;
    }
    if (params2->has_version) {                           /* :316-318 */
        out->version.app = params2->version.app;
    }
    if (params2->has_abci) {                              /* :319-321 */
        out->abci.vote_extensions_enable_height =
            params2->abci.vote_extensions_enable_height;
    }
    return CMT_OK;                                        /* :322 */
}
