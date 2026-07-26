/**
 * @file logup_bus.c
 * @brief LogUp interaction/bus layer — port of Plonky3 p3-lookup builder/bus
 *        + the batch-stark per-bus challenge memo and global-sum grouping.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 * See logup_bus.h for the scope and convention pins (P2L-b).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include "logup_bus.h"

/* ============================================================================
 * Builder storage
 * ========================================================================== */

/* One recorded global interaction (builder.rs:21-39 SymbolicInteraction). */
typedef struct {
    char     *bus_name;     /* owned copy */
    int32_t  *fields;       /* owned copy, [num_fields] */
    uint32_t  num_fields;
    int32_t   count;
    uint32_t  count_weight;
} bus_global_rec_t;

/* One recorded local interaction (builder.rs:49-53). */
typedef struct {
    uint32_t  num_tuples;
    uint32_t *tuple_widths; /* owned, [num_tuples]                     */
    int32_t  *elems_flat;   /* owned, concatenated tuple element lists */
    int32_t  *mults;        /* owned, [num_tuples]                     */
} bus_local_rec_t;

struct dnac_logup_builder {
    bus_global_rec_t *globals;
    uint32_t          num_globals, cap_globals;
    bus_local_rec_t  *locals;
    uint32_t          num_locals, cap_locals;
};

dnac_logup_builder_t *dnac_logup_builder_new(void)
{
    return (dnac_logup_builder_t *)calloc(1, sizeof(dnac_logup_builder_t));
}

void dnac_logup_builder_free(dnac_logup_builder_t *b)
{
    if (!b) {
        return;
    }
    for (uint32_t i = 0; i < b->num_globals; i++) {
        free(b->globals[i].bus_name);
        free(b->globals[i].fields);
    }
    free(b->globals);
    for (uint32_t i = 0; i < b->num_locals; i++) {
        free(b->locals[i].tuple_widths);
        free(b->locals[i].elems_flat);
        free(b->locals[i].mults);
    }
    free(b->locals);
    free(b);
}

/* Push order is preserved: it drives auxiliary-column assignment
 * (symbolic.rs:155-162 comment; types.rs:59-89). */
int dnac_logup_push_interaction(dnac_logup_builder_t *b,
                                const char           *bus_name,
                                const int32_t        *fields,
                                uint32_t              num_fields,
                                int32_t               count,
                                uint32_t              count_weight)
{
    if (!b || !bus_name || (num_fields > 0 && !fields)) {
        return DNAC_LOGUP_ERR_NULL;
    }
    if (b->num_globals == b->cap_globals) {
        uint32_t nc = b->cap_globals ? b->cap_globals * 2 : 8;
        bus_global_rec_t *ng =
            (bus_global_rec_t *)realloc(b->globals, nc * sizeof(*ng));
        if (!ng) {
            return DNAC_LOGUP_ERR_OOM;
        }
        b->globals = ng;
        b->cap_globals = nc;
    }
    bus_global_rec_t *g = &b->globals[b->num_globals];
    memset(g, 0, sizeof(*g));
    size_t name_len = strlen(bus_name);
    g->bus_name = (char *)malloc(name_len + 1);
    g->fields = (int32_t *)malloc(sizeof(int32_t) * (num_fields ? num_fields : 1));
    if (!g->bus_name || !g->fields) {
        free(g->bus_name);
        free(g->fields);
        return DNAC_LOGUP_ERR_OOM;
    }
    memcpy(g->bus_name, bus_name, name_len + 1);
    if (num_fields) {
        memcpy(g->fields, fields, sizeof(int32_t) * num_fields);
    }
    g->num_fields = num_fields;
    g->count = count;
    g->count_weight = count_weight;
    b->num_globals++;
    return DNAC_LOGUP_OK;
}

int dnac_logup_push_local_interaction(dnac_logup_builder_t *b,
                                      const uint32_t       *tuple_widths,
                                      const int32_t *const *tuple_elems,
                                      const int32_t        *multiplicities,
                                      uint32_t              num_tuples)
{
    if (!b ||
        (num_tuples > 0 && (!tuple_widths || !tuple_elems || !multiplicities))) {
        return DNAC_LOGUP_ERR_NULL;
    }
    if (b->num_locals == b->cap_locals) {
        uint32_t nc = b->cap_locals ? b->cap_locals * 2 : 8;
        bus_local_rec_t *nl =
            (bus_local_rec_t *)realloc(b->locals, nc * sizeof(*nl));
        if (!nl) {
            return DNAC_LOGUP_ERR_OOM;
        }
        b->locals = nl;
        b->cap_locals = nc;
    }
    uint32_t total = 0;
    for (uint32_t t = 0; t < num_tuples; t++) {
        if (tuple_widths[t] > 0 && !tuple_elems[t]) {
            return DNAC_LOGUP_ERR_NULL;
        }
        total += tuple_widths[t];
    }
    bus_local_rec_t *l = &b->locals[b->num_locals];
    memset(l, 0, sizeof(*l));
    l->tuple_widths =
        (uint32_t *)malloc(sizeof(uint32_t) * (num_tuples ? num_tuples : 1));
    l->elems_flat = (int32_t *)malloc(sizeof(int32_t) * (total ? total : 1));
    l->mults = (int32_t *)malloc(sizeof(int32_t) * (num_tuples ? num_tuples : 1));
    if (!l->tuple_widths || !l->elems_flat || !l->mults) {
        free(l->tuple_widths);
        free(l->elems_flat);
        free(l->mults);
        return DNAC_LOGUP_ERR_OOM;
    }
    uint32_t off = 0;
    for (uint32_t t = 0; t < num_tuples; t++) {
        l->tuple_widths[t] = tuple_widths[t];
        l->mults[t] = multiplicities[t];
        for (uint32_t j = 0; j < tuple_widths[t]; j++) {
            l->elems_flat[off++] = tuple_elems[t][j];
        }
    }
    l->num_tuples = num_tuples;
    b->num_locals++;
    return DNAC_LOGUP_OK;
}

/* ============================================================================
 * Finalize — types.rs:59-89 from_interactions
 * ========================================================================== */

/* Owning set + trailing arenas. */
typedef struct {
    dnac_logup_lookup_set_t pub_set;
    /* arenas */
    dnac_logup_lookup_t *lookups;
    char               **bus_names;     /* [n], NULL for locals */
    uint32_t            *count_weights; /* [n]                  */
    uint32_t            *widths_arena;
    int32_t             *elems_arena;
    int32_t            **tuple_ptr_arena;
    int32_t             *mults_arena;
    const char         **view_names;    /* [num_globals]        */
    uint32_t            *view_weights;  /* [num_globals]        */
} set_impl_t;

int dnac_logup_builder_finalize(dnac_logup_builder_t     *b,
                                dnac_logup_lookup_set_t **out)
{
    if (!b || !out) {
        return DNAC_LOGUP_ERR_NULL;
    }
    const uint32_t n = b->num_locals + b->num_globals;

    /* Totals for the arenas. */
    uint32_t total_tuples = 0, total_elems = 0;
    for (uint32_t i = 0; i < b->num_locals; i++) {
        total_tuples += b->locals[i].num_tuples;
        for (uint32_t t = 0; t < b->locals[i].num_tuples; t++) {
            total_elems += b->locals[i].tuple_widths[t];
        }
    }
    for (uint32_t i = 0; i < b->num_globals; i++) {
        total_tuples += 1; /* one tuple per global (types.rs:78-86) */
        total_elems += b->globals[i].num_fields;
    }

    set_impl_t *s = (set_impl_t *)calloc(1, sizeof(set_impl_t));
    if (!s) {
        return DNAC_LOGUP_ERR_OOM;
    }
    s->lookups =
        (dnac_logup_lookup_t *)calloc(n ? n : 1, sizeof(dnac_logup_lookup_t));
    s->bus_names = (char **)calloc(n ? n : 1, sizeof(char *));
    s->count_weights = (uint32_t *)calloc(n ? n : 1, sizeof(uint32_t));
    s->widths_arena =
        (uint32_t *)calloc(total_tuples ? total_tuples : 1, sizeof(uint32_t));
    s->elems_arena =
        (int32_t *)calloc(total_elems ? total_elems : 1, sizeof(int32_t));
    s->tuple_ptr_arena =
        (int32_t **)calloc(total_tuples ? total_tuples : 1, sizeof(int32_t *));
    s->mults_arena =
        (int32_t *)calloc(total_tuples ? total_tuples : 1, sizeof(int32_t));
    s->view_names = (const char **)calloc(
        b->num_globals ? b->num_globals : 1, sizeof(const char *));
    s->view_weights = (uint32_t *)calloc(
        b->num_globals ? b->num_globals : 1, sizeof(uint32_t));
    /* Set the lookup count up front so the free path releases every
     * bus-name slot (all NULL from calloc until individually filled). */
    s->pub_set.num_lookups = n;
    if (!s->lookups || !s->bus_names || !s->count_weights || !s->widths_arena ||
        !s->elems_arena || !s->tuple_ptr_arena || !s->mults_arena ||
        !s->view_names || !s->view_weights) {
        dnac_logup_lookup_set_free(&s->pub_set);
        return DNAC_LOGUP_ERR_OOM;
    }

    uint32_t col = 0, w_off = 0, e_off = 0;

    /* Locals first, in push order (types.rs:66-76). */
    for (uint32_t i = 0; i < b->num_locals; i++, col++) {
        const bus_local_rec_t *l = &b->locals[i];
        dnac_logup_lookup_t *lk = &s->lookups[col];
        lk->is_global = 0;
        lk->column = col;
        lk->num_tuples = l->num_tuples;
        lk->tuple_widths = &s->widths_arena[w_off];
        lk->tuple_elems = (const int32_t *const *)&s->tuple_ptr_arena[w_off];
        lk->multiplicities = &s->mults_arena[w_off];
        uint32_t l_off = 0;
        for (uint32_t t = 0; t < l->num_tuples; t++) {
            s->widths_arena[w_off + t] = l->tuple_widths[t];
            s->mults_arena[w_off + t] = l->mults[t];
            s->tuple_ptr_arena[w_off + t] = &s->elems_arena[e_off];
            for (uint32_t j = 0; j < l->tuple_widths[t]; j++) {
                s->elems_arena[e_off++] = l->elems_flat[l_off++];
            }
        }
        w_off += l->num_tuples;
        s->bus_names[col] = NULL;
        s->count_weights[col] = 0;
    }

    /* Then globals, in push order (types.rs:78-88): single-tuple lookups. */
    for (uint32_t i = 0; i < b->num_globals; i++, col++) {
        const bus_global_rec_t *g = &b->globals[i];
        dnac_logup_lookup_t *lk = &s->lookups[col];
        lk->is_global = 1;
        lk->column = col;
        lk->num_tuples = 1;
        lk->tuple_widths = &s->widths_arena[w_off];
        lk->tuple_elems = (const int32_t *const *)&s->tuple_ptr_arena[w_off];
        lk->multiplicities = &s->mults_arena[w_off];
        s->widths_arena[w_off] = g->num_fields;
        s->mults_arena[w_off] = g->count;
        s->tuple_ptr_arena[w_off] = &s->elems_arena[e_off];
        for (uint32_t j = 0; j < g->num_fields; j++) {
            s->elems_arena[e_off++] = g->fields[j];
        }
        w_off += 1;
        size_t name_len = strlen(g->bus_name);
        s->bus_names[col] = (char *)malloc(name_len + 1);
        if (!s->bus_names[col]) {
            dnac_logup_lookup_set_free(&s->pub_set);
            return DNAC_LOGUP_ERR_OOM;
        }
        memcpy(s->bus_names[col], g->bus_name, name_len + 1);
        s->count_weights[col] = g->count_weight;
        s->view_names[i] = s->bus_names[col];
        s->view_weights[i] = g->count_weight;
    }

    s->pub_set.lookups = s->lookups;
    s->pub_set.bus_names = (const char *const *)s->bus_names;
    s->pub_set.count_weights = s->count_weights;
    s->pub_set.num_lookups = n;
    s->pub_set.num_locals = b->num_locals;
    s->pub_set.num_globals = b->num_globals;
    s->pub_set.view.num_locals = b->num_locals;
    s->pub_set.view.num_globals = b->num_globals;
    s->pub_set.view.global_bus_names = s->view_names;
    s->pub_set.view.global_count_weights = s->view_weights;

    *out = &s->pub_set;
    return DNAC_LOGUP_OK;
}

void dnac_logup_lookup_set_free(dnac_logup_lookup_set_t *set)
{
    if (!set) {
        return;
    }
    /* pub_set is the first member — recover the impl. */
    set_impl_t *s = (set_impl_t *)set;
    if (s->bus_names) {
        for (uint32_t i = 0; i < s->pub_set.num_lookups; i++) {
            free(s->bus_names[i]);
        }
    }
    free(s->lookups);
    free(s->bus_names);
    free(s->count_weights);
    free(s->widths_arena);
    free(s->elems_arena);
    free(s->tuple_ptr_arena);
    free(s->mults_arena);
    free(s->view_names);
    free(s->view_weights);
    free(s);
}

/* ============================================================================
 * Per-bus challenge assignment (transcript.rs:74-102)
 * ========================================================================== */

int dnac_logup_bus_assign_challenges(
    const dnac_logup_bus_view_t *views,
    uint32_t                     num_instances,
    const gold_fp2_t            *draws,
    uint32_t                     num_draw_pairs,
    gold_fp2_t *const           *out_challenges,
    uint32_t                    *out_draw_pairs_used)
{
    if ((num_instances > 0 && (!views || !out_challenges)) ||
        (num_draw_pairs > 0 && !draws) || !out_draw_pairs_used) {
        return DNAC_LOGUP_ERR_NULL;
    }

    /* Memo: bus name -> draw-pair index (first occurrence registers;
     * transcript.rs:92-98). Bounded by the total global count. */
    uint32_t total_globals = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        if (views[i].num_globals > 0 && !views[i].global_bus_names) {
            return DNAC_LOGUP_ERR_NULL;
        }
        total_globals += views[i].num_globals;
    }
    const char **memo_names = (const char **)malloc(
        sizeof(const char *) * (total_globals ? total_globals : 1));
    uint32_t *memo_pair = (uint32_t *)malloc(
        sizeof(uint32_t) * (total_globals ? total_globals : 1));
    if (!memo_names || !memo_pair) {
        free((void *)memo_names);
        free(memo_pair);
        return DNAC_LOGUP_ERR_OOM;
    }
    uint32_t num_memo = 0, next_pair = 0;
    int rc = DNAC_LOGUP_OK;

    for (uint32_t i = 0; i < num_instances && rc == DNAC_LOGUP_OK; i++) {
        gold_fp2_t *out = out_challenges[i];
        if (!out && (views[i].num_locals + views[i].num_globals) > 0) {
            rc = DNAC_LOGUP_ERR_NULL;
            break;
        }
        uint32_t slot = 0;
        /* Locals first (column order): each draws fresh
         * (transcript.rs:97). */
        for (uint32_t l = 0; l < views[i].num_locals; l++) {
            if (next_pair >= num_draw_pairs) {
                rc = DNAC_LOGUP_ERR_PARAM;
                break;
            }
            out[slot++] = draws[2u * next_pair];
            out[slot++] = draws[2u * next_pair + 1u];
            next_pair++;
        }
        /* Globals: memo by bus name (transcript.rs:93-96). */
        for (uint32_t g = 0; g < views[i].num_globals && rc == DNAC_LOGUP_OK;
             g++) {
            const char *name = views[i].global_bus_names[g];
            if (!name) {
                rc = DNAC_LOGUP_ERR_NULL;
                break;
            }
            uint32_t pair = UINT32_MAX;
            for (uint32_t m = 0; m < num_memo; m++) {
                if (strcmp(memo_names[m], name) == 0) {
                    pair = memo_pair[m];
                    break;
                }
            }
            if (pair == UINT32_MAX) {
                if (next_pair >= num_draw_pairs) {
                    rc = DNAC_LOGUP_ERR_PARAM;
                    break;
                }
                pair = next_pair++;
                memo_names[num_memo] = name;
                memo_pair[num_memo] = pair;
                num_memo++;
            }
            out[slot++] = draws[2u * pair];
            out[slot++] = draws[2u * pair + 1u];
        }
    }

    *out_draw_pairs_used = next_pair;
    free((void *)memo_names);
    free(memo_pair);
    return rc;
}

/* ============================================================================
 * Per-bus global-sum verification (verifier/mod.rs:623-643)
 * ========================================================================== */

int dnac_logup_bus_verify_global_sums(
    const dnac_logup_bus_view_t *views,
    uint32_t                     num_instances,
    const gold_fp2_t *const    *cum_sums,
    const char                 **out_failed_bus)
{
    if (out_failed_bus) {
        *out_failed_bus = NULL;
    }
    if (num_instances > 0 && (!views || !cum_sums)) {
        return DNAC_LOGUP_ERR_NULL;
    }
    uint32_t total_globals = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        if (views[i].num_globals > 0 &&
            (!views[i].global_bus_names || !cum_sums[i])) {
            return DNAC_LOGUP_ERR_NULL;
        }
        total_globals += views[i].num_globals;
    }
    if (total_globals == 0) {
        return DNAC_LOGUP_OK;
    }

    /* First-occurrence-ordered bus list (deterministic; the verdict is a
     * conjunction so it equals the reference HashMap grouping, G-DET-L4). */
    const char **names = (const char **)malloc(sizeof(const char *) * total_globals);
    gold_fp2_t *group = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * total_globals);
    if (!names || !group) {
        free((void *)names);
        free(group);
        return DNAC_LOGUP_ERR_OOM;
    }
    uint32_t num_names = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        for (uint32_t g = 0; g < views[i].num_globals; g++) {
            const char *name = views[i].global_bus_names[g];
            if (!name) {
                free((void *)names);
                free(group);
                return DNAC_LOGUP_ERR_NULL;
            }
            int seen = 0;
            for (uint32_t m = 0; m < num_names; m++) {
                if (strcmp(names[m], name) == 0) {
                    seen = 1;
                    break;
                }
            }
            if (!seen) {
                names[num_names++] = name;
            }
        }
    }

    int rc = DNAC_LOGUP_OK;
    for (uint32_t m = 0; m < num_names; m++) {
        /* Gather this bus's sums across all instances, instance order then
         * global-lookup order (verifier/mod.rs:624-636). */
        uint32_t cnt = 0;
        for (uint32_t i = 0; i < num_instances; i++) {
            for (uint32_t g = 0; g < views[i].num_globals; g++) {
                if (strcmp(views[i].global_bus_names[g], names[m]) == 0) {
                    group[cnt++] = cum_sums[i][g];
                }
            }
        }
        /* EACH name group must sum to zero (verifier/mod.rs:639-643). */
        if (dnac_logup_verify_global_sum(group, cnt) != DNAC_LOGUP_OK) {
            if (out_failed_bus) {
                *out_failed_bus = names[m];
            }
            rc = DNAC_LOGUP_ERR_GLOBAL_SUM;
            break;
        }
    }

    free((void *)names);
    free(group);
    return rc;
}

/* ============================================================================
 * Height-bound offline precondition (builder.rs:33-38; F4)
 * ========================================================================== */

int dnac_logup_bus_check_height_bound(const dnac_logup_bus_view_t *views,
                                      const uint32_t              *heights,
                                      uint32_t                     num_instances)
{
    if (num_instances > 0 && (!views || !heights)) {
        return DNAC_LOGUP_ERR_NULL;
    }
    uint64_t acc = 0;
    for (uint32_t i = 0; i < num_instances; i++) {
        if (views[i].num_globals > 0 &&
            (!views[i].global_bus_names || !views[i].global_count_weights)) {
            return DNAC_LOGUP_ERR_NULL;
        }
        for (uint32_t g = 0; g < views[i].num_globals; g++) {
            /* u32 * u32 always fits u64 (max (2^32-1)^2 < 2^64). */
            uint64_t prod =
                (uint64_t)views[i].global_count_weights[g] * (uint64_t)heights[i];
            if (prod >= GOLDILOCKS_P || acc > GOLDILOCKS_P - 1u - prod) {
                return DNAC_LOGUP_ERR_HEIGHT_BOUND;
            }
            acc += prod;
        }
    }
    /* acc <= p-1 by construction here — the bound Σ < p holds. */
    return DNAC_LOGUP_OK;
}
