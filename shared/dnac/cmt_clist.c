/**
 * @file shared/dnac/cmt_clist.c
 * @brief cometbft @709fd12b `libs/clist/clist.go` in C — see the header.
 *
 * Every function names the Go line it ports. The reference-count helpers
 * (`elem_retain`, `elem_release`) are the C-only device the header
 * describes; `elem_set_next` is the one place a `next` reference moves.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_clist.h"

#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_CLIST"

/* ══ the reference count (C-only) ═════════════════════════════════════ */

static void elem_retain(cmt_clist_elem_t *e)
{
    if (e != NULL) {
        e->refs++;
    }
}

/* Drop one reference. When the count reaches zero the element is freed,
 * its value released, and the reference it held on its own `next` is
 * dropped in turn — iteratively, so a long chain of removed elements
 * that one cursor kept alive does not recurse. */
static void elem_release(cmt_clist_elem_t *e)
{
    while (e != NULL) {
        cmt_clist_elem_t *next;

        if (e->refs == 0) {
            /* A release with nothing to release is a bookkeeping defect
             * in this file, never a peer's doing; it cannot be reported
             * from a void path, so it is logged and the element left. */
            QGP_LOG_ERROR(LOG_TAG, "clist: reference count underflow");
            return;
        }
        e->refs--;
        if (e->refs != 0) {
            return;
        }
        next    = e->next;
        e->next = NULL;
        if (e->free_value != NULL) {
            e->free_value(e->free_ctx, e->value);
        }
        free(e);
        e = next;   /* the reference `e->next` held */
    }
}

/* ══ CElement ═════════════════════════════════════════════════════════ */

/* clist.go:114-119 — Next() */
cmt_clist_elem_t *cmt_clist_elem_next(const cmt_clist_elem_t *e)
{
    return (e == NULL) ? NULL : e->next;
}

/* clist.go:122-127 — Prev() */
cmt_clist_elem_t *cmt_clist_elem_prev(const cmt_clist_elem_t *e)
{
    return (e == NULL) ? NULL : e->prev;
}

/* clist.go:129-134 — Removed() */
bool cmt_clist_elem_removed(const cmt_clist_elem_t *e)
{
    return (e != NULL) && e->removed;
}

void *cmt_clist_elem_value(const cmt_clist_elem_t *e)
{
    return (e == NULL) ? NULL : e->value;
}

/* clist.go:67 — the condition NextWait() returns on; :172-175 and
 * :207-210 are the two sites that make NextWaitChan() readable. */
bool cmt_clist_elem_next_wait_ready(const cmt_clist_elem_t *e)
{
    if (e == NULL) {
        return false;
    }
    return e->next != NULL || e->removed;
}

/* clist.go:158-177 — SetNext(). The WaitGroup/channel bookkeeping of
 * :163-175 is the blocking machinery the header drops; what remains is
 * the pointer move, and here the reference move with it. Retain the new
 * target before releasing the old one so the two can never be confused
 * when either is NULL. */
static void elem_set_next(cmt_clist_elem_t *e, cmt_clist_elem_t *new_next)
{
    cmt_clist_elem_t *old_next = e->next;                     /* :161 */

    elem_retain(new_next);
    e->next = new_next;                                       /* :162 */
    elem_release(old_next);
}

/* clist.go:181-195 — SetPrev(). No reference travels with `prev`. */
static void elem_set_prev(cmt_clist_elem_t *e, cmt_clist_elem_t *new_prev)
{
    e->prev = new_prev;                                       /* :185 */
}

/* clist.go:197-212 — SetRemoved(). The wake-ups of :202-210 are the
 * blocking machinery; the flag is what remains. */
static void elem_set_removed(cmt_clist_elem_t *e)
{
    e->removed = true;                                        /* :200 */
}

/* clist.go:136-144 — DetachNext() */
int cmt_clist_elem_detach_next(cmt_clist_elem_t *e)
{
    if (e == NULL) {
        return CMT_FAULT;
    }
    if (!e->removed) {
        /* :140 panic("DetachNext() must be called after Remove(e)") —
         * CMT_FAULT: an invariant of the list's own use, node-local. */
        return CMT_FAULT;
    }
    elem_set_next(e, NULL);                                   /* :142 */
    return CMT_OK;
}

/* clist.go:146-154 — DetachPrev() */
int cmt_clist_elem_detach_prev(cmt_clist_elem_t *e)
{
    if (e == NULL) {
        return CMT_FAULT;
    }
    if (!e->removed) {
        /* :150 panic("DetachPrev() must be called after Remove(e)") —
         * CMT_FAULT, same class as DetachNext's. */
        return CMT_FAULT;
    }
    elem_set_prev(e, NULL);                                   /* :152 */
    return CMT_OK;
}

void cmt_clist_elem_ref(cmt_clist_elem_t *e)
{
    elem_retain(e);
}

void cmt_clist_elem_unref(cmt_clist_elem_t *e)
{
    elem_release(e);
}

/* ══ CList ════════════════════════════════════════════════════════════ */

/* clist.go:230-240 — Init(), on a list whose max_len is already set. */
static void clist_do_init(cmt_clist_t *l)
{
    l->head    = NULL;                                        /* :235 */
    l->tail    = NULL;                                        /* :236 */
    l->cur_len = 0;                                           /* :237 */
}

/* clist.go:247-251 — newWithMax(), then Init() */
int cmt_clist_init_with_max(cmt_clist_t *l, int max_length,
                            cmt_clist_free_value_fn free_value,
                            void *free_ctx)
{
    if (l == NULL || max_length < 0) {
        return CMT_FAULT;
    }
    memset(l, 0, sizeof(*l));
    l->max_len    = max_length;                               /* :249 */
    l->free_value = free_value;
    l->free_ctx   = free_ctx;
    clist_do_init(l);                                         /* :250 */
    return CMT_OK;
}

/* clist.go:243 — New() */
int cmt_clist_init(cmt_clist_t *l, cmt_clist_free_value_fn free_value,
                   void *free_ctx)
{
    return cmt_clist_init_with_max(l, CMT_CLIST_MAX_LENGTH, free_value,
                                   free_ctx);
}

void cmt_clist_free(cmt_clist_t *l)
{
    cmt_clist_elem_t *head;

    if (l == NULL) {
        return;
    }
    head = l->head;
    clist_do_init(l);
    elem_release(head);   /* the list's own reference; the chain follows */
}

/* clist.go:253-258 — Len() */
int cmt_clist_len(const cmt_clist_t *l)
{
    return (l == NULL) ? 0 : l->cur_len;
}

/* clist.go:260-265 — Front() */
cmt_clist_elem_t *cmt_clist_front(const cmt_clist_t *l)
{
    return (l == NULL) ? NULL : l->head;
}

/* clist.go:283-288 — Back() */
cmt_clist_elem_t *cmt_clist_back(const cmt_clist_t *l)
{
    return (l == NULL) ? NULL : l->tail;
}

/* clist.go:316-352 — PushBack(v) */
int cmt_clist_push_back(cmt_clist_t *l, void *value,
                        cmt_clist_elem_t **out_elem)
{
    cmt_clist_elem_t *e;

    if (out_elem != NULL) {
        *out_elem = NULL;
    }
    if (l == NULL) {
        return CMT_FAULT;
    }
    /* :336-338 panic("clist: maximum length list reached") — CMT_FAULT:
     * the list's own bound, node-local. Checked before the allocation
     * rather than after it (:320-329 allocate first); no observable
     * difference. */
    if (l->cur_len >= l->max_len) {
        return CMT_FAULT;
    }
    e = (cmt_clist_elem_t *)calloc(1, sizeof(*e));            /* :320-329 */
    if (e == NULL) {
        return CMT_FAULT;
    }
    e->value      = value;                                    /* :328 */
    e->free_value = l->free_value;
    e->free_ctx   = l->free_ctx;
    /* :332-335 — the FrontWait/BackWait release: dropped with the waits. */
    l->cur_len++;                                             /* :339 */
    if (l->tail == NULL) {                                    /* :342 */
        elem_retain(e);
        l->head = e;                                          /* :343 */
        l->tail = e;                                          /* :344 */
    } else {
        elem_set_prev(e, l->tail);                            /* :346 */
        elem_set_next(l->tail, e);                            /* :347 */
        l->tail = e;                                          /* :348 */
    }
    if (out_elem != NULL) {
        *out_elem = e;
    }
    return CMT_OK;
}

/* clist.go:356-401 — Remove(e) */
int cmt_clist_remove(cmt_clist_t *l, cmt_clist_elem_t *e, void **out_value)
{
    cmt_clist_elem_t *prev;
    cmt_clist_elem_t *next;

    if (out_value != NULL) {
        *out_value = NULL;
    }
    if (l == NULL || e == NULL) {
        return CMT_FAULT;
    }

    /* The three panics, all CMT_FAULT (node-local invariants of the
     * list's own use — a peer cannot reach them). The empty-list check
     * (:363-365) is taken BEFORE the :359-360 reads of `e`: it depends
     * only on `l`, so the verdict is the reference's, and an `e` that
     * the reference count has already freed (nothing in an empty list
     * references it) is never dereferenced. */
    if (l->head == NULL || l->tail == NULL) {
        return CMT_FAULT;                 /* :364 "Remove(e) on empty CList" */
    }
    prev = e->prev;                                           /* :359 */
    next = e->next;                                           /* :360 */
    if (prev == NULL && l->head != e) {
        return CMT_FAULT;                 /* :368 "Remove(e) with false head" */
    }
    if (next == NULL && l->tail != e) {
        return CMT_FAULT;                 /* :372 "Remove(e) with false tail" */
    }

    /* Hold `e` across the unlink: dropping the head's or the
     * predecessor's reference below may otherwise free it before the
     * removed flag and the value are read. */
    elem_retain(e);

    /* :376-379 — the FrontWait/BackWait reset: dropped with the waits. */
    l->cur_len--;                                             /* :382 */

    if (prev == NULL) {                                       /* :385 */
        cmt_clist_elem_t *old_head = l->head;

        elem_retain(next);
        l->head = next;                                       /* :386 */
        elem_release(old_head);
    } else {
        elem_set_next(prev, next);                            /* :388 */
    }
    if (next == NULL) {                                       /* :390 */
        l->tail = prev;                                       /* :391 */
    } else {
        elem_set_prev(next, prev);                            /* :393 */
    }

    elem_set_removed(e);                                      /* :397 */
    if (out_value != NULL) {
        *out_value = e->value;                                /* :400 */
    }
    elem_release(e);
    return CMT_OK;
}
