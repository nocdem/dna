/**
 * @file shared/dnac/activation_wire.c
 * @brief Ledger V2 O15C — activation authority codecs and digests.
 *
 * Layouts and rationale: activation_wire.h. Compiled into BOTH libdna
 * and libnodus; a drift between encoder and decoder is a silent
 * consensus break, so nothing here may branch on anything but the bytes.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/activation_wire.h"

#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* Cap invariants (mirrors chain_config_wire.c discipline). */
_Static_assert(DNA_ACT15_WIRE_MAX_SLOTS <= 255,
               "vote_count is a u8 — the slot cap must fit it");
_Static_assert(DNA_ACT15_WIRE_FIXED_LEN == 102,
               "type-15 fixed section drifted");
_Static_assert(DNA_ACT16_WIRE_LEN == 7391,
               "type-16 section drifted");
_Static_assert(sizeof(DNA_ACT_TAG_TARGET)   == 17 &&
               sizeof(DNA_ACT_TAG_SCHEDULE) == 17 &&
               sizeof(DNA_ACT_TAG_CANCEL)   == 17 &&
               sizeof(DNA_ACT_TAG_READY)    == 17 &&
               sizeof(DNA_ACT_TAG_REC_LEAF) == 17 &&
               sizeof(DNA_ACT_TAG_RDY_LEAF) == 17,
               "activation domain tags must be exactly 16 bytes");
_Static_assert(sizeof(DNA_ACT_SOURCE_TAG) == DNA_ACT_SOURCE_TAG_LEN + 1,
               "source tag length drifted");

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* ── type-15 ─────────────────────────────────────────────────────────── */

size_t dna_act15_wire_encoded_size(const dna_act15_wire_t *f) {
    if (!f) return 0;
    uint8_t n = f->vote_count;
    if (n > DNA_ACT15_WIRE_MAX_SLOTS) n = DNA_ACT15_WIRE_MAX_SLOTS;
    return (size_t)DNA_ACT15_WIRE_FIXED_LEN +
           (size_t)n * DNA_ACT15_WIRE_PER_VOTE;
}

int dna_act15_wire_encode(const dna_act15_wire_t *f,
                          uint8_t *dst, size_t dst_cap, size_t *written) {
    if (!f || !dst || !written) return -1;
    size_t need = dna_act15_wire_encoded_size(f);
    if (need == 0 || dst_cap < need) return -1;
    uint8_t n = f->vote_count;
    if (n > DNA_ACT15_WIRE_MAX_SLOTS) n = DNA_ACT15_WIRE_MAX_SLOTS;

    uint8_t *p = dst;
    put32(p, f->record_version);              p += 4;
    *p++ = f->op;
    memcpy(p, f->target, DNA_ACT_HASH_LEN);   p += DNA_ACT_HASH_LEN;
    put64(p, f->activation_height);           p += 8;
    put64(p, f->proposal_nonce);              p += 8;
    put64(p, f->signed_at_block);             p += 8;
    put64(p, f->valid_before_block);          p += 8;
    *p++ = n;
    for (uint8_t i = 0; i < n; i++) {
        memcpy(p, f->votes[i].witness_id, DNA_ACT_VOTER_ID_LEN);
        p += DNA_ACT_VOTER_ID_LEN;
        memcpy(p, f->votes[i].signature, DNA_ACT_SIG_LEN);
        p += DNA_ACT_SIG_LEN;
    }
    *written = (size_t)(p - dst);
    return (*written == need) ? 0 : -1;
}

int dna_act15_wire_decode(const uint8_t *src, size_t src_len,
                          dna_act15_wire_t *out, size_t *consumed) {
    if (!src || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (src_len < DNA_ACT15_WIRE_FIXED_LEN) return -1;

    const uint8_t *p = src;
    out->record_version    = get32(p);        p += 4;
    out->op                = *p++;
    memcpy(out->target, p, DNA_ACT_HASH_LEN); p += DNA_ACT_HASH_LEN;
    out->activation_height = get64(p);        p += 8;
    out->proposal_nonce    = get64(p);        p += 8;
    out->signed_at_block   = get64(p);        p += 8;
    out->valid_before_block= get64(p);        p += 8;
    uint8_t n = *p++;
    if (n > DNA_ACT15_WIRE_MAX_SLOTS) { memset(out, 0, sizeof(*out)); return -1; }
    size_t votes_total = (size_t)n * DNA_ACT15_WIRE_PER_VOTE;
    if (src_len - DNA_ACT15_WIRE_FIXED_LEN < votes_total) {
        memset(out, 0, sizeof(*out));
        return -1;
    }
    out->vote_count = n;
    for (uint8_t i = 0; i < n; i++) {
        memcpy(out->votes[i].witness_id, p, DNA_ACT_VOTER_ID_LEN);
        p += DNA_ACT_VOTER_ID_LEN;
        memcpy(out->votes[i].signature, p, DNA_ACT_SIG_LEN);
        p += DNA_ACT_SIG_LEN;
    }
    if (consumed) *consumed = (size_t)(p - src);
    return 0;
}

/* ── type-16 ─────────────────────────────────────────────────────────── */

int dna_act16_wire_encode(const dna_act16_wire_t *f,
                          uint8_t *dst, size_t dst_cap, size_t *written) {
    if (!f || !dst || !written) return -1;
    if (dst_cap < (size_t)DNA_ACT16_WIRE_LEN) return -1;
    uint8_t *p = dst;
    put32(p, f->signal_version);                        p += 4;
    memcpy(p, f->schedule_digest, DNA_ACT_HASH_LEN);    p += DNA_ACT_HASH_LEN;
    memcpy(p, f->target, DNA_ACT_HASH_LEN);             p += DNA_ACT_HASH_LEN;
    memcpy(p, f->voter_id, DNA_ACT_VOTER_ID_LEN);       p += DNA_ACT_VOTER_ID_LEN;
    put64(p, f->signal_epoch);                          p += 8;
    memcpy(p, f->pubkey, DNA_ACT_PUBKEY_LEN);           p += DNA_ACT_PUBKEY_LEN;
    memcpy(p, f->signature, DNA_ACT_SIG_LEN);           p += DNA_ACT_SIG_LEN;
    *written = (size_t)(p - dst);
    return (*written == (size_t)DNA_ACT16_WIRE_LEN) ? 0 : -1;
}

int dna_act16_wire_decode(const uint8_t *src, size_t src_len,
                          dna_act16_wire_t *out, size_t *consumed) {
    if (!src || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (src_len < (size_t)DNA_ACT16_WIRE_LEN) return -1;
    const uint8_t *p = src;
    out->signal_version = get32(p);                     p += 4;
    memcpy(out->schedule_digest, p, DNA_ACT_HASH_LEN);  p += DNA_ACT_HASH_LEN;
    memcpy(out->target, p, DNA_ACT_HASH_LEN);           p += DNA_ACT_HASH_LEN;
    memcpy(out->voter_id, p, DNA_ACT_VOTER_ID_LEN);     p += DNA_ACT_VOTER_ID_LEN;
    out->signal_epoch = get64(p);                       p += 8;
    memcpy(out->pubkey, p, DNA_ACT_PUBKEY_LEN);         p += DNA_ACT_PUBKEY_LEN;
    memcpy(out->signature, p, DNA_ACT_SIG_LEN);         p += DNA_ACT_SIG_LEN;
    if (consumed) *consumed = (size_t)(p - src);
    return 0;
}

/* ── Digests ─────────────────────────────────────────────────────────── */

int dna_act_target_digest(uint32_t target_version,
                          uint8_t  header_version,
                          uint32_t schema_version,
                          const dna_act_target_rt_t *rts, size_t n,
                          uint8_t out[DNA_ACT_HASH_LEN]) {
    if (!rts || !out || n < 1 || n > 16) return -1;
    for (size_t i = 1; i < n; i++)
        if (rts[i - 1].domain_id >= rts[i].domain_id) return -1;

    /* 16 + 4 + 1 + 4 + 4 + 16*(4+4+64) = 1181 max */
    uint8_t buf[16 + 4 + 1 + 4 + 4 + 16 * (4 + 4 + DNA_ACT_HASH_LEN)];
    uint8_t *p = buf;
    memcpy(p, DNA_ACT_TAG_TARGET, 16); p += 16;
    put32(p, target_version);          p += 4;
    *p++ = header_version;
    put32(p, schema_version);          p += 4;
    put32(p, (uint32_t)n);             p += 4;
    for (size_t i = 0; i < n; i++) {
        put32(p, rts[i].domain_id);       p += 4;
        put32(p, rts[i].ruleset_version); p += 4;
        memcpy(p, rts[i].ruleset_hash, DNA_ACT_HASH_LEN);
        p += DNA_ACT_HASH_LEN;
    }
    return qgp_sha3_512(buf, (size_t)(p - buf), out) == 0 ? 0 : -1;
}

int dna_act_sched_digest(const uint8_t chain_id[DNA_ACT_CHAIN_ID_LEN],
                         uint32_t record_version,
                         const uint8_t target[DNA_ACT_HASH_LEN],
                         uint64_t activation_height,
                         uint64_t proposal_nonce,
                         uint64_t signed_at_block,
                         uint64_t valid_before_block,
                         uint8_t out[DNA_ACT_HASH_LEN]) {
    if (!chain_id || !target || !out) return -1;
    uint8_t buf[16 + 32 + 4 + 64 + 8 + 8 + 8 + 8];
    uint8_t *p = buf;
    memcpy(p, DNA_ACT_TAG_SCHEDULE, 16);            p += 16;
    memcpy(p, chain_id, DNA_ACT_CHAIN_ID_LEN);      p += DNA_ACT_CHAIN_ID_LEN;
    put32(p, record_version);                       p += 4;
    memcpy(p, target, DNA_ACT_HASH_LEN);            p += DNA_ACT_HASH_LEN;
    put64(p, activation_height);                    p += 8;
    put64(p, proposal_nonce);                       p += 8;
    put64(p, signed_at_block);                      p += 8;
    put64(p, valid_before_block);                   p += 8;
    return qgp_sha3_512(buf, sizeof(buf), out) == 0 ? 0 : -1;
}

int dna_act_cancel_digest(const uint8_t chain_id[DNA_ACT_CHAIN_ID_LEN],
                          const uint8_t schedule_digest[DNA_ACT_HASH_LEN],
                          uint64_t proposal_nonce,
                          uint64_t signed_at_block,
                          uint64_t valid_before_block,
                          uint8_t out[DNA_ACT_HASH_LEN]) {
    if (!chain_id || !schedule_digest || !out) return -1;
    uint8_t buf[16 + 32 + 64 + 8 + 8 + 8];
    uint8_t *p = buf;
    memcpy(p, DNA_ACT_TAG_CANCEL, 16);              p += 16;
    memcpy(p, chain_id, DNA_ACT_CHAIN_ID_LEN);      p += DNA_ACT_CHAIN_ID_LEN;
    memcpy(p, schedule_digest, DNA_ACT_HASH_LEN);   p += DNA_ACT_HASH_LEN;
    put64(p, proposal_nonce);                       p += 8;
    put64(p, signed_at_block);                      p += 8;
    put64(p, valid_before_block);                   p += 8;
    return qgp_sha3_512(buf, sizeof(buf), out) == 0 ? 0 : -1;
}

int dna_act_ready_digest(uint32_t signal_version,
                         const uint8_t chain_id[DNA_ACT_CHAIN_ID_LEN],
                         const uint8_t schedule_digest[DNA_ACT_HASH_LEN],
                         const uint8_t target[DNA_ACT_HASH_LEN],
                         const uint8_t voter_id[DNA_ACT_VOTER_ID_LEN],
                         uint64_t signal_epoch,
                         uint8_t out[DNA_ACT_HASH_LEN]) {
    if (!chain_id || !schedule_digest || !target || !voter_id || !out)
        return -1;
    uint8_t buf[16 + 4 + 32 + 64 + 64 + 32 + 8];
    uint8_t *p = buf;
    memcpy(p, DNA_ACT_TAG_READY, 16);               p += 16;
    put32(p, signal_version);                       p += 4;
    memcpy(p, chain_id, DNA_ACT_CHAIN_ID_LEN);      p += DNA_ACT_CHAIN_ID_LEN;
    memcpy(p, schedule_digest, DNA_ACT_HASH_LEN);   p += DNA_ACT_HASH_LEN;
    memcpy(p, target, DNA_ACT_HASH_LEN);            p += DNA_ACT_HASH_LEN;
    memcpy(p, voter_id, DNA_ACT_VOTER_ID_LEN);      p += DNA_ACT_VOTER_ID_LEN;
    put64(p, signal_epoch);                         p += 8;
    return qgp_sha3_512(buf, sizeof(buf), out) == 0 ? 0 : -1;
}

int dna_act_source_commit(const uint8_t legacy_chain_id[DNA_ACT_CHAIN_ID_LEN],
                          const uint8_t terminal_block_id[DNA_ACT_HASH_LEN],
                          const uint8_t terminal_state_root[DNA_ACT_HASH_LEN],
                          uint64_t terminal_height,
                          uint8_t out[DNA_ACT_SOURCE_COMMIT_LEN]) {
    if (!legacy_chain_id || !terminal_block_id || !terminal_state_root ||
        !out)
        return -1;
    uint8_t *p = out;
    memcpy(p, legacy_chain_id, DNA_ACT_CHAIN_ID_LEN);   p += DNA_ACT_CHAIN_ID_LEN;
    memcpy(p, terminal_block_id, DNA_ACT_HASH_LEN);     p += DNA_ACT_HASH_LEN;
    memcpy(p, terminal_state_root, DNA_ACT_HASH_LEN);   p += DNA_ACT_HASH_LEN;
    put64(p, terminal_height);
    return 0;
}
