/**
 * @file shared/dnac/domain_wire.c
 * @brief Ledger V2 Season 4 — canonical domain manifest / registry /
 *        readiness codec implementation (INACTIVE).
 *
 * See domain_wire.h for the exact layouts, tag table and validation rules.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "domain_wire.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

#define TAG_LEN 16

static const uint8_t TAG_DOMMAN[TAG_LEN]  = "DNA.DOMMAN.v1\0\0";
static const uint8_t TAG_RULESET[TAG_LEN] = "DNA.RULESET.v1\0";
static const uint8_t TAG_DRLEAF[TAG_LEN]  = "DNA.DRLEAF.v1\0\0";
static const uint8_t TAG_DRNODE[TAG_LEN]  = "DNA.DRNODE.v1\0\0";
static const uint8_t TAG_DOMRDY[TAG_LEN]  = "DNA.DOMRDY.v1\0\0";
static const uint8_t TAG_DOMPROP[TAG_LEN] = "DNA.DOMPROP.v1\0";

static void put_be16(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)(v >> 8); out[1] = (uint8_t)v;
}
static void put_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* Canonical name: first byte non-NUL; every non-NUL byte in 0x21..0x7E;
 * once a NUL appears every later byte must be NUL (zero-padding only). */
static int name_is_canonical(const uint8_t name[DNA_DOM_NAME_LEN]) {
    if (name[0] == 0) return 0;
    int padding = 0;
    for (size_t i = 0; i < DNA_DOM_NAME_LEN; i++) {
        if (name[i] == 0) { padding = 1; continue; }
        if (padding) return 0;                 /* non-NUL after padding    */
        if (name[i] < 0x21 || name[i] > 0x7e) return 0;
    }
    return 1;
}

static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

/* ══════════════════════════════════════════════════════════════════════
 * 1. DomainManifest v1
 * ════════════════════════════════════════════════════════════════════ */

int dna_domman_validate(const dna_domain_manifest_t *m) {
    if (!m) return -1;
    if (m->manifest_version != DNA_DOMMAN_VERSION) return -1;
    if (!name_is_canonical(m->name)) return -1;
    if (m->runtime_kind != DNA_RUNTIME_NATIVE_BUILTIN) return -1;
    if (m->fee_policy != DNA_FEEPOL_GLOBAL_BURN) return -1;
    if (m->upgrade_authority != DNA_UPGAUTH_CHAIN_CONFIG) return -1;
    if (m->readiness_policy != DNA_RDYPOL_STAGED_V1) return -1;
    if (m->tx_type_count > DNA_DOM_MAX_TX_TYPES) return -1;
    for (size_t i = 1; i < m->tx_type_count; i++)
        if (m->tx_types[i - 1] >= m->tx_types[i]) return -1;
    return 0;
}

size_t dna_domman_encoded_len(const dna_domain_manifest_t *m) {
    if (dna_domman_validate(m) != 0) return 0;
    return DNA_DOMMAN_ENC_LEN(m->tx_type_count);
}

int dna_domman_encode(const dna_domain_manifest_t *m,
                      uint8_t *dst, size_t cap, size_t *written) {
    size_t need = dna_domman_encoded_len(m);
    if (need == 0 || !dst || cap < need) return -1;

    uint8_t *p = dst;
    put_be32(m->manifest_version, p);              p += 4;
    put_be32(m->domain_id, p);                     p += 4;
    memcpy(p, m->name, DNA_DOM_NAME_LEN);          p += DNA_DOM_NAME_LEN;
    *p++ = m->runtime_kind;
    put_be32(m->runtime_abi, p);                   p += 4;
    put_be32(m->ruleset_version, p);               p += 4;
    memcpy(p, m->ruleset_hash, DNA_DOM_HASH_LEN);  p += DNA_DOM_HASH_LEN;
    memcpy(p, m->genesis_state_root, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    put_be16(m->tx_type_count, p);                 p += 2;
    memcpy(p, m->tx_types, m->tx_type_count);      p += m->tx_type_count;
    *p++ = m->fee_policy;
    put_be16(m->quota_tx_per_block, p);            p += 2;
    put_be32(m->quota_verify_cost, p);             p += 4;
    *p++ = m->upgrade_authority;
    put_be64(m->activation_epoch, p);              p += 8;
    put_be32(m->readiness_policy, p);              p += 4;

    if ((size_t)(p - dst) != need) return -1;      /* internal invariant   */
    if (written) *written = need;
    return 0;
}

int dna_domman_decode(const uint8_t *src, size_t len,
                      dna_domain_manifest_t *out) {
    if (!src || !out) return -1;
    if (len < DNA_DOMMAN_FIXED_HEAD + DNA_DOMMAN_FIXED_TAIL) return -1;

    uint16_t count = get_be16(src + 177);
    if (count > DNA_DOM_MAX_TX_TYPES) return -1;
    if (len != DNA_DOMMAN_ENC_LEN(count)) return -1;   /* exact length     */

    dna_domain_manifest_t m;
    memset(&m, 0, sizeof(m));
    const uint8_t *p = src;
    m.manifest_version = get_be32(p);              p += 4;
    m.domain_id        = get_be32(p);              p += 4;
    memcpy(m.name, p, DNA_DOM_NAME_LEN);           p += DNA_DOM_NAME_LEN;
    m.runtime_kind     = *p++;
    m.runtime_abi      = get_be32(p);              p += 4;
    m.ruleset_version  = get_be32(p);              p += 4;
    memcpy(m.ruleset_hash, p, DNA_DOM_HASH_LEN);   p += DNA_DOM_HASH_LEN;
    memcpy(m.genesis_state_root, p, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    m.tx_type_count    = get_be16(p);              p += 2;
    memcpy(m.tx_types, p, count);                  p += count;
    m.fee_policy       = *p++;
    m.quota_tx_per_block = get_be16(p);            p += 2;
    m.quota_verify_cost  = get_be32(p);            p += 4;
    m.upgrade_authority  = *p++;
    m.activation_epoch   = get_be64(p);            p += 8;
    m.readiness_policy   = get_be32(p);            p += 4;

    if (dna_domman_validate(&m) != 0) return -1;
    *out = m;
    return 0;
}

int dna_domman_hash(const dna_domain_manifest_t *m,
                    uint8_t out[DNA_DOM_HASH_LEN]) {
    if (!out) return -1;
    size_t enc_len = dna_domman_encoded_len(m);
    if (enc_len == 0) return -1;

    uint8_t *pre = (uint8_t *)malloc(TAG_LEN + enc_len);
    if (!pre) return -1;
    memcpy(pre, TAG_DOMMAN, TAG_LEN);
    size_t written = 0;
    if (dna_domman_encode(m, pre + TAG_LEN, enc_len, &written) != 0 ||
        written != enc_len) {
        free(pre);
        return -1;
    }
    int rc = qgp_sha3_512(pre, TAG_LEN + enc_len, out);
    free(pre);
    return rc == 0 ? 0 : -1;
}

int dna_domman_owns_type(const dna_domain_manifest_t *m, uint8_t tx_type) {
    if (dna_domman_validate(m) != 0) return -1;
    for (size_t i = 0; i < m->tx_type_count; i++) {
        if (m->tx_types[i] == tx_type) return 0;
        if (m->tx_types[i] > tx_type) break;   /* list is ascending        */
    }
    return 1;
}

/* ══════════════════════════════════════════════════════════════════════
 * 2. RulesetDescriptor v1
 * ════════════════════════════════════════════════════════════════════ */

int dna_ruleset_desc_hash(const dna_ruleset_desc_t *d,
                          uint8_t out[DNA_DOM_HASH_LEN]) {
    if (!d || !out) return -1;
    if (d->descriptor_version != DNA_RULESET_DESC_VERSION) return -1;
    if (!name_is_canonical(d->name)) return -1;
    if (d->rule_count > DNA_DOM_MAX_RULE_IDS) return -1;
    if (d->tx_type_count > DNA_DOM_MAX_TX_TYPES) return -1;
    if ((d->rule_count > 0 && !d->rule_ids) ||
        (d->tx_type_count > 0 && !d->tx_types))
        return -1;
    for (size_t i = 1; i < d->rule_count; i++)
        if (d->rule_ids[i - 1] >= d->rule_ids[i]) return -1;
    for (size_t i = 1; i < d->tx_type_count; i++)
        if (d->tx_types[i - 1] >= d->tx_types[i]) return -1;

    size_t enc_len = 4 + 4 + DNA_DOM_NAME_LEN + 4 + 4
                   + 2 + (size_t)d->rule_count * 4
                   + 2 + (size_t)d->tx_type_count;
    uint8_t *pre = (uint8_t *)malloc(TAG_LEN + enc_len);
    if (!pre) return -1;
    uint8_t *p = pre;
    memcpy(p, TAG_RULESET, TAG_LEN);               p += TAG_LEN;
    put_be32(d->descriptor_version, p);            p += 4;
    put_be32(d->domain_id, p);                     p += 4;
    memcpy(p, d->name, DNA_DOM_NAME_LEN);          p += DNA_DOM_NAME_LEN;
    put_be32(d->runtime_abi, p);                   p += 4;
    put_be32(d->ruleset_version, p);               p += 4;
    put_be16(d->rule_count, p);                    p += 2;
    for (size_t i = 0; i < d->rule_count; i++) {
        put_be32(d->rule_ids[i], p);               p += 4;
    }
    put_be16(d->tx_type_count, p);                 p += 2;
    for (size_t i = 0; i < d->tx_type_count; i++)
        *p++ = d->tx_types[i];

    int rc = -1;
    if ((size_t)(p - pre) == TAG_LEN + enc_len)
        rc = qgp_sha3_512(pre, TAG_LEN + enc_len, out) == 0 ? 0 : -1;
    free(pre);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * 3. DomainRegistryRecord v1
 * ════════════════════════════════════════════════════════════════════ */

int dna_domreg_record_validate(const dna_domreg_record_t *r) {
    if (!r) return -1;
    if (r->record_version != DNA_DOMREG_REC_VERSION) return -1;
    if (r->status < DNA_DOMST_REGISTERED || r->status > DNA_DOMST_RETIRED)
        return -1;
    if (r->pending_present > 1 || r->proposal_present > 1) return -1;

    /* Present flags are the single authority over their hash fields:
     * absent → the hash MUST be all-zero; present → MUST NOT be all-zero.
     * That keeps exactly one canonical encoding per logical state. */
    if (r->pending_present == 0) {
        if (!all_zero(r->pending_manifest_hash, DNA_DOM_HASH_LEN)) return -1;
    } else {
        if (all_zero(r->pending_manifest_hash, DNA_DOM_HASH_LEN)) return -1;
    }
    if (r->proposal_present == 0) {
        if (!all_zero(r->proposal_digest, DNA_DOM_HASH_LEN)) return -1;
    } else {
        if (all_zero(r->proposal_digest, DNA_DOM_HASH_LEN)) return -1;
    }

    /* Scheduling fields travel together and only under a live proposal. */
    if ((r->scheduled_activation_epoch != 0) !=
        (r->readiness_deadline_epoch != 0))
        return -1;
    if (r->scheduled_activation_epoch != 0 && r->proposal_present == 0)
        return -1;
    if (r->postpone_count != 0 && r->scheduled_activation_epoch == 0)
        return -1;

    switch (r->status) {
        case DNA_DOMST_REGISTERED:
            /* An initial-activation proposal targets the CURRENT manifest;
             * scheduling flips the status to SCHEDULED. */
            if (r->pending_present != 0) return -1;
            if (r->scheduled_activation_epoch != 0) return -1;
            break;
        case DNA_DOMST_SCHEDULED:
            if (r->proposal_present != 1) return -1;
            if (r->pending_present != 0) return -1;
            if (r->scheduled_activation_epoch == 0) return -1;
            break;
        case DNA_DOMST_ACTIVE:
            /* An upgrade proposal always targets a NEW pending manifest. */
            if (r->proposal_present != r->pending_present) return -1;
            break;
        case DNA_DOMST_PAUSED:
        case DNA_DOMST_RETIRED:
            if (r->proposal_present != 0 || r->pending_present != 0) return -1;
            if (r->scheduled_activation_epoch != 0) return -1;
            break;
        default:
            return -1;
    }
    return 0;
}

int dna_domreg_record_encode(const dna_domreg_record_t *r,
                             uint8_t out[DNA_DOMREG_REC_ENC_LEN]) {
    if (!out || dna_domreg_record_validate(r) != 0) return -1;
    uint8_t *p = out;
    put_be32(r->record_version, p);                p += 4;
    put_be32(r->domain_id, p);                     p += 4;
    *p++ = r->status;
    memcpy(p, r->current_manifest_hash, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    *p++ = r->pending_present;
    memcpy(p, r->pending_manifest_hash, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    *p++ = r->proposal_present;
    memcpy(p, r->proposal_digest, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    put_be64(r->scheduled_activation_epoch, p);    p += 8;
    put_be64(r->readiness_deadline_epoch, p);      p += 8;
    put_be32(r->postpone_count, p);                p += 4;
    return (size_t)(p - out) == DNA_DOMREG_REC_ENC_LEN ? 0 : -1;
}

int dna_domreg_record_decode(const uint8_t *src, size_t len,
                             dna_domreg_record_t *out) {
    if (!src || !out || len != DNA_DOMREG_REC_ENC_LEN) return -1;
    dna_domreg_record_t r;
    memset(&r, 0, sizeof(r));
    const uint8_t *p = src;
    r.record_version = get_be32(p);                p += 4;
    r.domain_id      = get_be32(p);                p += 4;
    r.status         = *p++;
    memcpy(r.current_manifest_hash, p, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    r.pending_present = *p++;
    memcpy(r.pending_manifest_hash, p, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    r.proposal_present = *p++;
    memcpy(r.proposal_digest, p, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    r.scheduled_activation_epoch = get_be64(p);    p += 8;
    r.readiness_deadline_epoch   = get_be64(p);    p += 8;
    r.postpone_count             = get_be32(p);    p += 4;

    if (dna_domreg_record_validate(&r) != 0) return -1;
    *out = r;
    return 0;
}

int dna_domreg_record_leaf(const dna_domreg_record_t *r,
                           uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out) return -1;
    uint8_t pre[TAG_LEN + DNA_DOMREG_REC_ENC_LEN];
    memcpy(pre, TAG_DRLEAF, TAG_LEN);
    if (dna_domreg_record_encode(r, pre + TAG_LEN) != 0) return -1;
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

int dna_domreg_root(const dna_domreg_record_t *records, size_t n,
                    uint8_t out[DNA_V2_ROOT_LEN]) {
    if (!out || (n > 0 && !records)) return -1;
    if (n == 0)
        return dna_v2_empty_root(DNA_V2_EMPTY_DOMREG, out);

    if (records[0].domain_id != DNA_DOMAIN_SYSTEM) return -1;
    for (size_t i = 1; i < n; i++)
        if (records[i - 1].domain_id >= records[i].domain_id) return -1;

    uint8_t (*level)[DNA_V2_ROOT_LEN] = malloc(n * sizeof(*level));
    if (!level) return -1;
    int rc = 0;
    for (size_t i = 0; i < n; i++) {
        if (dna_domreg_record_leaf(&records[i], level[i]) != 0) {
            rc = -1;
            break;
        }
    }
    /* RFC6962-style: inner = H(tag ‖ L ‖ R); odd node PROMOTED. */
    size_t cnt = n;
    while (rc == 0 && cnt > 1) {
        size_t next = 0;
        for (size_t i = 0; i + 1 < cnt; i += 2) {
            uint8_t pre[TAG_LEN + 2 * DNA_V2_ROOT_LEN];
            memcpy(pre, TAG_DRNODE, TAG_LEN);
            memcpy(pre + TAG_LEN, level[i], DNA_V2_ROOT_LEN);
            memcpy(pre + TAG_LEN + DNA_V2_ROOT_LEN, level[i + 1],
                   DNA_V2_ROOT_LEN);
            if (qgp_sha3_512(pre, sizeof(pre), level[next]) != 0) {
                rc = -1;
                break;
            }
            next++;
        }
        if (rc != 0) break;
        if (cnt & 1) {
            memcpy(level[next], level[cnt - 1], DNA_V2_ROOT_LEN);
            next++;
        }
        cnt = next;
    }
    if (rc == 0)
        memcpy(out, level[0], DNA_V2_ROOT_LEN);
    free(level);
    return rc;
}

/* ══════════════════════════════════════════════════════════════════════
 * 4. Proposal digest + ReadinessSignal v1
 * ════════════════════════════════════════════════════════════════════ */

int dna_domprop_digest(const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                       uint32_t domain_id,
                       const uint8_t target_manifest_hash[DNA_DOM_HASH_LEN],
                       uint64_t proposal_nonce,
                       uint64_t proposed_at_epoch,
                       uint8_t out[DNA_DOM_HASH_LEN]) {
    if (!chain_id || !target_manifest_hash || !out) return -1;
    uint8_t pre[TAG_LEN + DNA_CHAIN_ID_LEN + 4 + DNA_DOM_HASH_LEN + 8 + 8];
    uint8_t *p = pre;
    memcpy(p, TAG_DOMPROP, TAG_LEN);               p += TAG_LEN;
    memcpy(p, chain_id, DNA_CHAIN_ID_LEN);         p += DNA_CHAIN_ID_LEN;
    put_be32(domain_id, p);                        p += 4;
    memcpy(p, target_manifest_hash, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    put_be64(proposal_nonce, p);                   p += 8;
    put_be64(proposed_at_epoch, p);                p += 8;
    if ((size_t)(p - pre) != sizeof(pre)) return -1;
    return qgp_sha3_512(pre, sizeof(pre), out) == 0 ? 0 : -1;
}

/* Shared structural check for a readiness signal's non-signature fields. */
static int domrdy_fields_valid(const dna_readiness_signal_t *s) {
    if (!s) return -1;
    if (s->msg_version != DNA_DOMRDY_MSG_VERSION) return -1;
    /* Only a KNOWN runtime kind may be claimed ready — an unknown kind is
     * exactly the thing a validator must never signal support for. */
    if (s->runtime_kind != DNA_RUNTIME_NATIVE_BUILTIN) return -1;
    return 0;
}

/* Write the 217 canonical field bytes (everything after the tag). */
static void domrdy_fields_encode(const dna_readiness_signal_t *s,
                                 uint8_t *p) {
    put_be32(s->msg_version, p);                   p += 4;
    memcpy(p, s->chain_id, DNA_CHAIN_ID_LEN);      p += DNA_CHAIN_ID_LEN;
    memcpy(p, s->voter_id, DNA_DOM_VOTER_ID_LEN);  p += DNA_DOM_VOTER_ID_LEN;
    put_be32(s->domain_id, p);                     p += 4;
    *p++ = s->runtime_kind;
    put_be32(s->runtime_abi, p);                   p += 4;
    put_be32(s->ruleset_version, p);               p += 4;
    memcpy(p, s->ruleset_hash, DNA_DOM_HASH_LEN);  p += DNA_DOM_HASH_LEN;
    memcpy(p, s->proposal_digest, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    put_be64(s->signal_epoch, p);
}

int dna_domrdy_preimage(const dna_readiness_signal_t *s,
                        uint8_t out[DNA_DOMRDY_PREIMAGE_LEN]) {
    if (!out || domrdy_fields_valid(s) != 0) return -1;
    memcpy(out, TAG_DOMRDY, TAG_LEN);
    domrdy_fields_encode(s, out + TAG_LEN);
    return 0;
}

int dna_domrdy_encode(const dna_readiness_signal_t *s,
                      uint8_t out[DNA_DOMRDY_WIRE_LEN]) {
    if (!out || domrdy_fields_valid(s) != 0) return -1;
    domrdy_fields_encode(s, out);
    memcpy(out + (DNA_DOMRDY_PREIMAGE_LEN - TAG_LEN), s->signature,
           DNA_DOM_SIG_LEN);
    return 0;
}

int dna_domrdy_decode(const uint8_t *src, size_t len,
                      dna_readiness_signal_t *out) {
    if (!src || !out || len != DNA_DOMRDY_WIRE_LEN) return -1;
    dna_readiness_signal_t s;
    memset(&s, 0, sizeof(s));
    const uint8_t *p = src;
    s.msg_version = get_be32(p);                   p += 4;
    memcpy(s.chain_id, p, DNA_CHAIN_ID_LEN);       p += DNA_CHAIN_ID_LEN;
    memcpy(s.voter_id, p, DNA_DOM_VOTER_ID_LEN);   p += DNA_DOM_VOTER_ID_LEN;
    s.domain_id = get_be32(p);                     p += 4;
    s.runtime_kind = *p++;
    s.runtime_abi = get_be32(p);                   p += 4;
    s.ruleset_version = get_be32(p);               p += 4;
    memcpy(s.ruleset_hash, p, DNA_DOM_HASH_LEN);   p += DNA_DOM_HASH_LEN;
    memcpy(s.proposal_digest, p, DNA_DOM_HASH_LEN);
    p += DNA_DOM_HASH_LEN;
    s.signal_epoch = get_be64(p);                  p += 8;
    memcpy(s.signature, p, DNA_DOM_SIG_LEN);       p += DNA_DOM_SIG_LEN;

    if ((size_t)(p - src) != DNA_DOMRDY_WIRE_LEN) return -1;
    if (domrdy_fields_valid(&s) != 0) return -1;
    *out = s;
    return 0;
}
