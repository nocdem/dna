/**
 * @file shared/dnac/cmt_clist.h
 * @brief cometbft @709fd12b `libs/clist/clist.go` ported to C — the
 *        linked list the Flood mempool keeps its transactions in.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R3-M of the cometbft → C consensus port. The only user is
 * cmt_mem.c; nothing in the running chain reaches it yet.
 * ════════════════════════════════════════════════════════════════════════
 *
 * The reference is a goroutine-safe doubly linked list whose elements can
 * be traversed by many readers while the owner pushes and removes. Two of
 * its properties are the whole reason it exists and are kept exactly:
 *
 *   1. A REMOVED ELEMENT STAYS TRAVERSABLE FORWARDS. `Remove` (:356-401)
 *      unlinks the element from its live neighbours but never clears the
 *      element's own `next`; the reference's contract (:354) leaves it
 *      to the caller to `DetachPrev()` and/or `DetachNext()`, and the
 *      mempool only ever detaches `prev` (clist_mempool.go:115, :369).
 *      A reader parked on an element that is then removed steps off it
 *      with `Next()` onto whatever followed it — the mempool's own
 *      `removeAllTxs` (:113-116) and `recheckTxs` (:658) loops, and every
 *      reactor cursor (reactor.go:250-252), depend on this.
 *   2. REMOVED ELEMENTS ARE NEVER RE-LINKED (:7). `DetachNext`/
 *      `DetachPrev` refuse to run on a live element (:140, :150) and
 *      `Remove` refuses an element that is not where the list thinks it
 *      is (:364-372).
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 * Every BLOCKING wait: `NextWait` (:59-75), `PrevWait` (:79-93),
 * `NextWaitChan` (:106-111), `PrevWaitChan` (:97-102), `FrontWait`
 * (:267-281), `BackWait` (:290-304), `WaitChan` (:308-313), the
 * WaitGroups and channels inside `SetNext`/`SetPrev`/`SetRemoved`
 * (:163-175, :186-193, :202-210) and `waitGroup1` (:403-407). Umbrella
 * rev 4's substitution table item 7: a blocking wait becomes "return and
 * continue on the next tick", so the single-threaded caller POLLS
 * `cmt_clist_elem_next()` / `cmt_clist_front()` instead. The CONDITION
 * those waits return on is kept, because the reactor's cursor branches on
 * it: `cmt_clist_elem_next_wait_ready()` below is exactly `next != nil ||
 * removed` (:67, and the two `close` sites :174/:209 that make
 * `NextWaitChan` readable). The mutexes (:45, :221) are dropped with the
 * threads.
 *
 * ── THE ONE C-ONLY DEVICE: reference counting in place of Go's GC ──────
 * Property 1 means an element can be REMOVED yet still be pointed at — by
 * a reader's cursor, or by the `next` pointer of an earlier removed
 * element that a cursor is walking through. Go frees it when the last
 * such pointer is gone; C has to count. Every element carries `refs`,
 * and a reference is held by exactly three kinds of pointer:
 *
 *   · the list's `head`                       (one ref on the head element)
 *   · any element's `next`                    (one ref on the element it
 *                                              names, live or removed)
 *   · a CURSOR a caller registered with       (one ref per registration)
 *     `cmt_clist_elem_ref`
 *
 * `prev` pointers and the list's `tail` hold NO reference: `tail` is
 * always reachable from `head` through live `next` pointers, and `prev`
 * is a back-pointer whose only readers (`Remove`'s `e.Prev()` :359 and
 * the caller's `DetachPrev`) act on live elements or write without
 * reading. That is what keeps the count acyclic — `next` pointers only
 * ever point forwards in list order — so an element is freed exactly when
 * the list no longer holds it, no cursor sits on it, and no removed
 * predecessor still names it; freeing it releases the reference it held
 * on its own `next`, and the release runs down the chain iteratively.
 *
 * CONSEQUENCE FOR CALLERS, stated because Go had no such rule: a loop
 * that removes the element it stands on and then reads `Next()` from it
 * (the three reference loops above) must hold a cursor reference across
 * the body — `cmt_clist_elem_ref` before, read `next`, `cmt_clist_elem_
 * unref` after — or the element may already be gone when `Next()` is
 * read. Reading `prev` of a REMOVED element is undefined here: the
 * reference leaves it stale (:354 asks for the detach), this port leaves
 * it stale AND unreferenced.
 *
 * `Value` (:54) is `void *` here and is OWNED BY THE ELEMENT: the list
 * takes a `free_value` callback at init and calls it once, when the
 * element is freed — never at `Remove`, because a removed element's
 * value is still read by readers parked on it (reactor.go:229, :241 read
 * a removed element's mempoolTx and SEND it).
 *
 * ── Panics ─────────────────────────────────────────────────────────────
 * All five are node-local invariants of the list's own use and are
 * CMT_FAULT under umbrella rev 4's rule: `PushBack` past `maxLen` (:337),
 * `Remove` on an empty list (:364), with a false head (:368) or a false
 * tail (:372), and `DetachNext`/`DetachPrev` on a live element (:140,
 * :150). None can be reached by a peer's message.
 *
 * ── MaxLength ──────────────────────────────────────────────────────────
 * `MaxLength = int(^uint(0) >> 1)` (:24) is the largest Go `int`, 2^63-1
 * on this project's targets; `Len()` returns an `int`. This port keeps
 * `int` for `cur_len`/`max_len`, so its `CMT_CLIST_MAX_LENGTH` is C's
 * INT_MAX (2^31-1). The two bounds differ; neither is reachable — the
 * mempool caps the list at `config.Size` (5 000) long before either.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * No clock, no randomness, no hashing; order is insertion order and
 * nothing else. Allocation failure is CMT_FAULT.
 *
 * Reference @709fd12b (SHA-256 verified before use; pin record rev 12 →
 * rev 15, atlas-dec-483ec17cbb352ef0ec2267ccd953339c):
 *   libs/clist/clist.go 407 lines f5206294…
 * Governing records: umbrella rev 4 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-4 rev 3 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_CLIST_H
#define SHARED_DNAC_CMT_CLIST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>

#include "cmt_tmhash.h"   /* CMT_OK / CMT_REJECT / CMT_FAULT */

#ifdef __cplusplus
extern "C" {
#endif

/** clist.go:24 — `MaxLength`, the largest `int`. C's, see the header. */
#define CMT_CLIST_MAX_LENGTH INT_MAX

typedef struct cmt_clist      cmt_clist_t;
typedef struct cmt_clist_elem cmt_clist_elem_t;

/** Called once per element, when the element is FREED (not when it is
 *  removed) — see "THE ONE C-ONLY DEVICE" in the header. May be NULL. */
typedef void (*cmt_clist_free_value_fn)(void *ctx, void *value);

/**
 * clist.go:44-55 — `CElement`, minus the mutex, the two WaitGroups and
 * the two wait channels (the header's "taşınmadı"), plus the two C-only
 * fields the reference counting needs.
 *
 * Treat every field as PRIVATE; use the accessors. The struct is exposed
 * so the mempool can embed pointers to it without a heap indirection and
 * so the tests can pin the invariants directly.
 */
struct cmt_clist_elem {
    cmt_clist_elem_t *prev;      /* :46 */
    cmt_clist_elem_t *next;      /* :49 */
    bool              removed;   /* :52 */
    void             *value;     /* :54 — immutable, element-owned */

    /* C-only: the reference count of the header, and the destructor for
     * `value` — copied from the list at PushBack so that an element a
     * cursor keeps alive past `cmt_clist_free` still knows how to release
     * its value. */
    size_t                  refs;
    cmt_clist_free_value_fn free_value;
    void                   *free_ctx;
};

/**
 * clist.go:220-228 — `CList`, minus the mutex, the WaitGroup and the wait
 * channel. The zero value is NOT ready to use here, unlike Go's (:217):
 * call `cmt_clist_init` first, because `max_len` and the free hook have
 * to come from somewhere.
 */
struct cmt_clist {
    cmt_clist_elem_t *head;      /* :224 — first element (holds a ref) */
    cmt_clist_elem_t *tail;      /* :225 — last element (no ref) */
    int               cur_len;   /* :226 */
    int               max_len;   /* :227 */

    /* C-only: the value destructor. */
    cmt_clist_free_value_fn free_value;
    void                   *free_ctx;
};

/* ══ CElement ═════════════════════════════════════════════════════════ */

/** clist.go:114-119 — `Next()`. Nonblocking, NULL at the end. Valid on
 *  a removed element (see property 1 in the header). */
cmt_clist_elem_t *cmt_clist_elem_next(const cmt_clist_elem_t *e);

/** clist.go:122-127 — `Prev()`. Nonblocking, NULL at the front.
 *  ⚠ Undefined on a REMOVED element — see the header. */
cmt_clist_elem_t *cmt_clist_elem_prev(const cmt_clist_elem_t *e);

/** clist.go:129-134 — `Removed()`. */
bool cmt_clist_elem_removed(const cmt_clist_elem_t *e);

/** The `Value` field (:54). NULL for a NULL element. */
void *cmt_clist_elem_value(const cmt_clist_elem_t *e);

/**
 * C-only: the condition `NextWait()` returns on (:67, `next != nil ||
 * removed`), which is also exactly when `NextWaitChan()` is readable —
 * the channel is closed when a next is set (:172-175) or when the element
 * is removed while it has no next (:207-210). The reactor's cursor
 * (reactor.go:249-257) polls this instead of blocking.
 */
bool cmt_clist_elem_next_wait_ready(const cmt_clist_elem_t *e);

/** clist.go:136-144 — `DetachNext()`. Clears `next` (and releases the
 *  reference it held).
 *  @return CMT_OK; CMT_FAULT on NULL or on a LIVE element (:140, a
 *          node-local invariant: "must be called after Remove(e)"). */
int cmt_clist_elem_detach_next(cmt_clist_elem_t *e);

/** clist.go:146-154 — `DetachPrev()`. Clears `prev`.
 *  @return CMT_OK; CMT_FAULT on NULL or on a LIVE element (:150). */
int cmt_clist_elem_detach_prev(cmt_clist_elem_t *e);

/** C-only: register a cursor on `e` — one reference, see the header.
 *  NULL is a no-op so a cursor variable can be re-registered blindly. */
void cmt_clist_elem_ref(cmt_clist_elem_t *e);

/** C-only: release a cursor's reference. May free `e`, and then any
 *  chain of removed elements it alone kept alive. NULL is a no-op.
 *  ⚠ `e` must not be read after this call. */
void cmt_clist_elem_unref(cmt_clist_elem_t *e);

/* ══ CList ════════════════════════════════════════════════════════════ */

/**
 * clist.go:243 — `New()`, i.e. `newWithMax(MaxLength)` (:247-251) and
 * `Init()` (:230-240). `l` must be a fresh (never initialised, or
 * `cmt_clist_free`d) list: `Init` on a list that still holds elements
 * would drop them in Go and leak them here.
 * @param free_value the value destructor of the header; may be NULL.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_clist_init(cmt_clist_t *l, cmt_clist_free_value_fn free_value,
                   void *free_ctx);

/** clist.go:247-251 — `newWithMax(maxLength)`, then `Init()`.
 *  @return CMT_OK, CMT_FAULT on NULL or a negative `max_length`. */
int cmt_clist_init_with_max(cmt_clist_t *l, int max_length,
                            cmt_clist_free_value_fn free_value,
                            void *free_ctx);

/**
 * C-only: drop the list's own reference (its `head`) and reset to empty.
 * Elements that no cursor and no removed predecessor still reference are
 * freed, in list order; the rest are freed when their last reference
 * goes. This is what Go's `Init` (:230-240) on a populated list amounts
 * to once the GC runs. NULL is a no-op.
 */
void cmt_clist_free(cmt_clist_t *l);

/** clist.go:253-258 — `Len()`. 0 for NULL. */
int cmt_clist_len(const cmt_clist_t *l);

/** clist.go:260-265 — `Front()`. NULL when empty or for NULL. */
cmt_clist_elem_t *cmt_clist_front(const cmt_clist_t *l);

/** clist.go:283-288 — `Back()`. NULL when empty or for NULL. */
cmt_clist_elem_t *cmt_clist_back(const cmt_clist_t *l);

/**
 * clist.go:316-352 — `PushBack(v)`. Allocates the element (:320-329),
 * refuses to grow past `max_len` (:336-338), links it at the tail
 * (:342-349). The wait-group release of :332-335 is gone with the waits.
 * @param out_elem receives the new element (the reference's return
 *        value); may be NULL when the caller does not need it. The
 *        element is owned by the list — do NOT unref it unless you
 *        `cmt_clist_elem_ref`d it yourself.
 * @return CMT_OK; CMT_FAULT on NULL, on allocation failure, or at the
 *         MaxLength panic (:337, node-local).
 */
int cmt_clist_push_back(cmt_clist_t *l, void *value,
                        cmt_clist_elem_t **out_elem);

/**
 * clist.go:356-401 — `Remove(e)`. Unlinks `e` from its live neighbours
 * (:385-394), marks it removed (:397) and returns its value (:400). The
 * element's own `next` is NOT cleared — property 1 — and its `prev` is
 * left as the reference leaves it, for the caller's `DetachPrev`.
 *
 * ⚠ After this call `e` may already be FREED (if nothing else referenced
 * it) — hold a cursor reference across any later read of it, as the
 * header explains. The returned value pointer is valid only while `e`
 * is.
 *
 * @param out_value receives `e.Value`; may be NULL.
 * @return CMT_OK; CMT_FAULT on NULL, or at the three panics — an empty
 *         list (:364), a false head (:368), a false tail (:372) — all
 *         node-local invariants of the list's own use.
 */
int cmt_clist_remove(cmt_clist_t *l, cmt_clist_elem_t *e, void **out_value);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_CLIST_H */
