/**
 * Nodus — Ledger V2: the compiled STORAGE-ADAPTER boundary (INACTIVE).
 * Authority model, the probe/eval/mutate split, the fault-vs-verdict rule
 * and the honest label live in nodus_witness_v2_adapter.h.
 *
 * This module holds the GENERIC half of the boundary: op resolution,
 * structural self-check, the ONE precondition decision table, and the
 * validate/apply walks. It contains no SQL, no table name and no schema
 * string — by construction, since it never learns where a domain keeps
 * anything. The concrete storage lives behind the two compiled function
 * pointers the runtime registered.
 *
 * @file nodus_witness_v2_adapter.c
 */

#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_runtime.h"

#include <string.h>

/* ── Op resolution ──────────────────────────────────────────────────── */

const nodus_adapter_op_t *nodus_adapter_op_lookup(
        const nodus_domain_adapter_t *ad, uint32_t op_id) {
    if (!ad || !ad->ops) return NULL;
    for (size_t i = 0; i < ad->n_ops; i++) {
        if (ad->ops[i].op_id == op_id) return &ad->ops[i];
        if (ad->ops[i].op_id > op_id) break;   /* ascending array          */
    }
    return NULL;
}

/* ── Structural self-check ──────────────────────────────────────────── */

int nodus_adapter_selfcheck(const nodus_domain_adapter_t *ad) {
    if (!ad) return -1;
    if (ad->adapter_version != NODUS_DOMAIN_ADAPTER_V1) return -1;
    if (!ad->ops || ad->n_ops == 0) return -1;
    if (!ad->probe || !ad->mutate) return -1;

    for (size_t i = 0; i < ad->n_ops; i++) {
        const nodus_adapter_op_t *op = &ad->ops[i];

        /* STRICTLY ascending: `<=` rejects a duplicate id as well as a
         * descent, so one op_id can never resolve two ways. */
        if (i > 0 && op->op_id <= ad->ops[i - 1].op_id) return -1;

        if (op->allowed_kinds == 0) {
            /* READ-ONLY op (native auth season): serves ONLY the
             * mediated-read boundary. It can never be named by an
             * effect — validate's kind test fails against an empty mask
             * (ERR_KIND, a deterministic verdict) — so a precondition
             * mask on it would be dead weight: require it empty too.
             * The blob bounds still apply (they bound read keys and
             * read-result sizes). */
            if (op->allowed_preconds != 0) return -1;
            if (op->key_len_min > op->key_len_max) return -1;
            if (op->key_len_max > DNA_EFFECT_MAX_KEY_LEN) return -1;
            if (op->value_len_min > op->value_len_max) return -1;
            if (op->value_len_max > DNA_EFFECT_MAX_VALUE_LEN) return -1;
            continue;
        }
        if ((op->allowed_kinds & (uint8_t)~NODUS_ADAPTER_KINDS_ALL) != 0)
            return -1;
        if (op->allowed_preconds == 0) return -1;
        if ((op->allowed_preconds &
             (uint8_t)~NODUS_ADAPTER_PRECONDS_ALL) != 0)
            return -1;

        if (op->key_len_min > op->key_len_max) return -1;
        if (op->key_len_max > DNA_EFFECT_MAX_KEY_LEN) return -1;
        if (op->value_len_min > op->value_len_max) return -1;
        if (op->value_len_max > DNA_EFFECT_MAX_VALUE_LEN) return -1;

        /* DEAD-OP checks: under the codec's CREATE <=> ABSENT
         * biconditional, an allowed kind with no allowed compatible tag
         * (or vice versa) can never admit a single effect, and an op that
         * allows DELETE with a nonzero value floor makes every DELETE
         * unshapeable (the codec pins a DELETE's value_len to 0). All
         * three fail in the DENY direction, so they are not admission
         * holes — but a compiled adapter must not SHIP believing it
         * registered a working path that can never fire. */
        {
            const uint8_t k_create =
                (uint8_t)(op->allowed_kinds &
                          NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE));
            const uint8_t k_mut =
                (uint8_t)(op->allowed_kinds &
                          (NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET) |
                           NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE)));
            const uint8_t p_absent =
                (uint8_t)(op->allowed_preconds &
                          NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT));
            const uint8_t p_exists =
                (uint8_t)(op->allowed_preconds & (uint8_t)~
                          NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT));
            if (k_create && !p_absent) return -1;   /* CREATE needs ABSENT */
            if (k_mut && !p_exists) return -1;      /* SET/DEL need EXISTS* */
            if (p_absent && !k_create) return -1;   /* ABSENT needs CREATE */
            if (p_exists && !k_mut) return -1;      /* EXISTS* need SET/DEL */
            if ((op->allowed_kinds &
                 NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE)) &&
                op->value_len_min != 0) return -1;  /* DELETE value is 0   */
        }
    }
    return 0;
}

/* ── The ONE precondition decision ──────────────────────────────────── */

/**
 * The kind/precondition biconditional of effect_wire.h:86-99, restated
 * here so a DIRECT caller (one that did not come through the codec)
 * cannot invent an illegal pair.
 *
 * @return 1 legal, 0 illegal or out of range.
 */
static int pair_legal(uint8_t kind, uint8_t tag) {
    switch (kind) {
        case DNA_EFFECT_CREATE:
            return tag == DNA_EFFECT_PRE_ABSENT;
        case DNA_EFFECT_SET:
        case DNA_EFFECT_DELETE:
            return tag == DNA_EFFECT_PRE_EXISTS ||
                   tag == DNA_EFFECT_PRE_EXISTS_VERSION ||
                   tag == DNA_EFFECT_PRE_EXISTS_VHASH;
        default:
            return 0;                    /* INVALID or unknown kind        */
    }
}

nodus_adapter_status_t nodus_adapter_precond_eval(
        uint8_t effect_kind, uint8_t precond_tag,
        uint64_t expected_version,
        const uint8_t expected_vhash[DNA_EFFECT_HASH_LEN],
        const nodus_adapter_row_facts_t *facts) {

    /* A NULL facts pointer is a CALLER bug — ERR_ARG. An out-of-contract
     * FACT VALUE is different: the probe said OK and then reported
     * something other than 0/1, which means the COMPILED ADAPTER is
     * broken on THIS node — that is a node-local fault, never a verdict,
     * so it is ERR_STORAGE_FAULT (guessing either existence branch would
     * manufacture a transaction outcome out of a broken adapter, and the
     * corruption may exist on one witness only). */
    if (!facts) return NODUS_ADAPTER_ERR_ARG;
    if (facts->exists != 0 && facts->exists != 1)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;

    if (!pair_legal(effect_kind, precond_tag))
        return NODUS_ADAPTER_ERR_PRECOND_FORM;

    if (precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH && !expected_vhash)
        return NODUS_ADAPTER_ERR_ARG;

    if (precond_tag == DNA_EFFECT_PRE_ABSENT)
        return facts->exists ? NODUS_ADAPTER_ERR_PRECOND_EXISTS
                             : NODUS_ADAPTER_OK;

    /* Every remaining tag requires the row. Absence is decided FIRST so a
     * version or hash comparison never runs against the fields of a row
     * that does not exist. */
    if (!facts->exists) return NODUS_ADAPTER_ERR_PRECOND_MISSING;

    if (precond_tag == DNA_EFFECT_PRE_EXISTS_VERSION)
        return facts->version == expected_version
                   ? NODUS_ADAPTER_OK
                   : NODUS_ADAPTER_ERR_PRECOND_VERSION;

    if (precond_tag == DNA_EFFECT_PRE_EXISTS_VHASH)
        return memcmp(facts->value_hash, expected_vhash,
                      DNA_EFFECT_HASH_LEN) == 0
                   ? NODUS_ADAPTER_OK
                   : NODUS_ADAPTER_ERR_PRECOND_HASH;

    /* DNA_EFFECT_PRE_EXISTS — presence is the whole condition. */
    return NODUS_ADAPTER_OK;
}

/* ── Generic validation ─────────────────────────────────────────────── */

nodus_adapter_status_t nodus_witness_v2_effects_validate(
        const struct nodus_domain_runtime *rt,
        const dna_effect_view_t *v,
        uint16_t *fail_index_out) {

    if (fail_index_out) *fail_index_out = 0;

    if (!rt) return NODUS_ADAPTER_ERR_ARG;

    /* Fail-closed: a runtime with no adapter cannot execute typed effects
     * at all. There is deliberately no fallback adapter to fall back to. */
    const nodus_domain_adapter_t *ad = rt->adapter;
    if (!ad) return NODUS_ADAPTER_ERR_NO_ADAPTER;
    if (nodus_adapter_selfcheck(ad) != 0) return NODUS_ADAPTER_ERR_ARG;

    if (!v) return NODUS_ADAPTER_ERR_ARG;
    /* `buf` is the rejected-view marker (effect_wire.h:269-272). The count
     * cannot serve: effect_count == 0 with buf != NULL is a VALID empty
     * result and validates vacuously below. */
    if (!v->buf) return NODUS_ADAPTER_ERR_ARG;
    if (v->result_version != DNA_EFFECT_RESULT_VERSION)
        return NODUS_ADAPTER_ERR_ARG;
    if (v->effect_count > DNA_EFFECT_MAX_COUNT)
        return NODUS_ADAPTER_ERR_ARG;

    for (uint16_t i = 0; i < v->effect_count; i++) {
        const dna_effect_hdr_t *h = &v->eff[i];

        /* Defence in depth (the env_wire.c view_slice_ok discipline,
         * env_wire.c:168-185): both blob windows must lie inside the
         * view's DECLARED buffer. True by construction for any view
         * dna_effect_result_decode produced — but this function is
         * callable directly, and apply() dereferences these offsets, so
         * a hand-built or stale view must die HERE, not over-read there.
         * Subtraction form, so nothing can wrap. */
        if ((size_t)v->key_off[i] > v->res_len ||
            (size_t)h->key_len > v->res_len - (size_t)v->key_off[i] ||
            (size_t)v->val_off[i] > v->res_len ||
            (size_t)h->value_len > v->res_len - (size_t)v->val_off[i]) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_ARG;
        }

        const nodus_adapter_op_t *op = nodus_adapter_op_lookup(ad, h->op_id);
        if (!op) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_UNKNOWN_OP;
        }

        /* Range-check before shifting: NODUS_ADAPTER_KIND_BIT is only
         * defined for a real enum value, and a decoded view guarantees
         * one — but this function is callable directly. */
        if (h->effect_kind < DNA_EFFECT_CREATE ||
            h->effect_kind > DNA_EFFECT_DELETE ||
            (op->allowed_kinds &
             NODUS_ADAPTER_KIND_BIT(h->effect_kind)) == 0) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_KIND;
        }

        if (h->precond_tag < DNA_EFFECT_PRE_ABSENT ||
            h->precond_tag > DNA_EFFECT_PRE_EXISTS_VHASH ||
            (op->allowed_preconds &
             NODUS_ADAPTER_PRECOND_BIT(h->precond_tag)) == 0) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_PRECOND_FORM;
        }

        /* The CREATE <=> ABSENT biconditional, re-applied so validate is
         * complete on the FORM axis for a DIRECT caller too: a decoded
         * view cannot carry an illegal pair (the codec rejects all of
         * them), but validate is the documented pre-apply gate, and a
         * hand-built (SET, ABSENT) effect must die HERE — before apply
         * has probed storage or mutated any preceding effect. */
        if (!pair_legal(h->effect_kind, h->precond_tag)) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_PRECOND_FORM;
        }

        /* The op's own bounds, INCLUSIVE. Note this is uniform across
         * kinds: an op that permits DELETE must therefore set
         * value_len_min == 0, because the codec pins a DELETE's value_len
         * to 0 (effect_wire.h:65-66) and a nonzero floor would make every
         * one of that op's DELETEs unshapeable. */
        if (h->key_len < op->key_len_min || h->key_len > op->key_len_max ||
            h->value_len < op->value_len_min ||
            h->value_len > op->value_len_max) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_SHAPE;
        }
    }

    return NODUS_ADAPTER_OK;
}

/* ── Mediated read (contract: nodus_witness_v2_adapter.h) ───────────── */

nodus_adapter_status_t nodus_witness_v2_read_one(
        struct nodus_witness *w,
        const struct nodus_domain_runtime *rt,
        const nodus_rt_read_req_t *req,
        nodus_rt_read_res_t *res_out) {

    if (!res_out) return NODUS_ADAPTER_ERR_ARG;
    memset(res_out, 0, sizeof(*res_out));
    if (!w || !rt || !req) return NODUS_ADAPTER_ERR_ARG;

    const nodus_domain_adapter_t *ad = rt->adapter;
    if (!ad || !ad->read) return NODUS_ADAPTER_ERR_NO_ADAPTER;
    if (nodus_adapter_selfcheck(ad) != 0) return NODUS_ADAPTER_ERR_ARG;

    const nodus_adapter_op_t *op = nodus_adapter_op_lookup(ad, req->op_id);
    if (!op) return NODUS_ADAPTER_ERR_UNKNOWN_OP;

    if (req->key_len < 1 || req->key_len > DNA_EFFECT_MAX_KEY_LEN ||
        req->key_len < op->key_len_min || req->key_len > op->key_len_max)
        return NODUS_ADAPTER_ERR_SHAPE;

    int present = 0;
    uint32_t vlen = 0;
    nodus_adapter_status_t st = ad->read(ad, w,
                                         /* the ONE source of the domain */
                                         rt->domain_id, op,
                                         req->key, req->key_len,
                                         &present, res_out->value,
                                         DNA_EFFECT_MAX_VALUE_LEN, &vlen);
    if (st != NODUS_ADAPTER_OK) {
        /* {OK, ERR_STORAGE_FAULT} is the whole contract; anything else
         * is a broken compiled adapter on THIS node — coerced, exactly
         * as probe/mutate coerce. */
        memset(res_out, 0, sizeof(*res_out));
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    /* Out-of-contract FACTS are node faults too: present outside {0,1},
     * a value over the op's own bound or the codec cap, or bytes
     * reported on an absent row. */
    if ((present != 0 && present != 1) ||
        vlen > DNA_EFFECT_MAX_VALUE_LEN ||
        vlen > op->value_len_max ||
        (present == 0 && vlen != 0)) {
        memset(res_out, 0, sizeof(*res_out));
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    res_out->present = (uint8_t)present;
    res_out->value_len = vlen;
    if (present == 0)
        memset(res_out->value, 0, sizeof(res_out->value));
    return NODUS_ADAPTER_OK;
}

/* ── Generic apply ──────────────────────────────────────────────────── */

nodus_adapter_status_t nodus_witness_v2_effects_apply(
        struct nodus_witness *w,
        const struct nodus_domain_runtime *rt,
        const dna_effect_view_t *v,
        uint16_t *fail_index_out) {

    if (fail_index_out) *fail_index_out = 0;
    if (!w) return NODUS_ADAPTER_ERR_ARG;

    nodus_adapter_status_t st =
        nodus_witness_v2_effects_validate(rt, v, fail_index_out);
    if (st != NODUS_ADAPTER_OK) return st;

    const nodus_domain_adapter_t *ad = rt->adapter;
    /* The ONE source of the domain. Not a parameter, not a field of the
     * result, not a default — the resolved runtime's own id. */
    const uint32_t domain_id = rt->domain_id;

    for (uint16_t i = 0; i < v->effect_count; i++) {
        const dna_effect_hdr_t *h = &v->eff[i];
        const nodus_adapter_op_t *op = nodus_adapter_op_lookup(ad, h->op_id);
        if (!op) {                       /* validate proved it resolves    */
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_UNKNOWN_OP;
        }

        const uint8_t *key = v->buf + v->key_off[i];
        const uint8_t *value =
            h->value_len > 0 ? v->buf + v->val_off[i] : NULL;

        nodus_adapter_row_facts_t facts;
        memset(&facts, 0, sizeof(facts));
        st = ad->probe(ad, w, domain_id, op, key, h->key_len, &facts);
        if (st != NODUS_ADAPTER_OK) {
            /* A storage fault is a node fault, never a transaction
             * verdict, and never an absent row. The probe's contract is
             * {OK, ERR_STORAGE_FAULT}; ANY other return is a broken
             * compiled adapter — also a node-local fault — and is
             * COERCED to ERR_STORAGE_FAULT so precondition statuses can
             * only ever originate in the ONE shipped decision table
             * (nodus_adapter_precond_eval), never in adapter code. */
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }

        st = nodus_adapter_precond_eval(h->effect_kind, h->precond_tag,
                                        h->expected_version,
                                        h->expected_vhash, &facts);
        if (st != NODUS_ADAPTER_OK) {
            if (fail_index_out) *fail_index_out = i;
            return st;
        }

        st = ad->mutate(ad, w, domain_id, op, h->effect_kind,
                        key, h->key_len, value, h->value_len);
        if (st != NODUS_ADAPTER_OK) {
            /* Same coercion as the probe: the mutate contract is
             * {OK, ERR_STORAGE_FAULT}, and a mutate that answers with a
             * precondition status would be a SECOND decision point after
             * the shipped table already ruled — fail as the node fault
             * it is. */
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
    }

    return NODUS_ADAPTER_OK;
}
