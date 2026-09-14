/**
 * Nodus — cometbft @709fd12b C port, wave R3-M: the concurrent list of
 * `shared/dnac/cmt_clist.c`, ported from `libs/clist/clist_test.go`
 * (INACTIVE layer).
 *
 * Every case names the Go `func Test…` it comes from and its line; an
 * assertion STRONGER or WEAKER than the reference's is labelled at the
 * site.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the list keeps the two properties the mempool and its reactor
 * depend on (cmt_clist.h header), and that the C-only reference count
 * frees an element exactly when Go's GC would have. If this file failed,
 * one of these would be false:
 *   · pushing past `max_len` is refused as a FAULT and the list is left
 *     as it was (clist.go:336-338);
 *   · three pushes, three removals in order: each Remove returns the
 *     value it held, Len counts down to 0, and the list is empty (:27-67);
 *   · a REMOVED element still answers `Next()` with the element that
 *     followed it (:354, :356-401: `next` is never cleared), so a reader
 *     parked on it steps forward — the three reference loops that do
 *     this (clist_mempool.go:113, :658; reactor.go:252) are sound;
 *   · `next_wait_ready` is exactly `next != nil || removed` (:67): false
 *     on a live tail, true once a successor is pushed, true once the
 *     tail is removed;
 *   · `DetachNext`/`DetachPrev` on a LIVE element are FAULTs (:140,
 *     :150) and on a removed one clear the pointer;
 *   · `Remove` of an element that is not in the list — twice, or after a
 *     detach — is a FAULT (:364-372), never a corruption;
 *   · THE REFERENCE COUNT: an element removed while a cursor holds it is
 *     NOT freed (its value destructor does not run) until the cursor
 *     lets go; a chain of removed elements that one cursor keeps alive is
 *     freed in one cascade when that cursor moves off; `cmt_clist_free`
 *     frees every live element exactly once and no element twice.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION`, which the nodus build defines
 *   for every cmt_* target (cmt_clist.c does not read it; the build
 *   adds it globally). `QGP_FAULT_INJECT` does not matter: nothing here
 *   has a fail point. A DEFAULT BUILD is enough.
 * ENVIRONMENT: none. No variable is read or written.
 * No network, no files, no clock, no randomness, no threads.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. Every list is freed on the success path; a CHECK failure
 * returns early and leaks, which is acceptable in a failing test process.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The reference count is observed through a value DESTRUCTOR that
 *     counts calls. If the destructor were wired to the wrong element,
 *     the count would still add up in the simple cases; the chain case
 *     (`t_refcount_chain`) and the free-all case exist to separate
 *     "freed once each" from "freed the right one".
 *  2. A use-after-free that happens to read intact memory passes here
 *     without a sanitizer. Under ASan/UBSan (the O9 sweep) it does not.
 *  3. No goroutine test is ported (below), so nothing here says anything
 *     about concurrent traversal — which the single-threaded port has
 *     no need of, but that is an argument, not a measurement.
 *
 * ── NOT PORTED — BLOCKED BY ────────────────────────────────────────────
 *   · `TestScanRightDeleteRandom` (clist_test.go:168-239): ten scanner
 *     GOROUTINES racing a remover, with `FrontWait`; a goroutine test of
 *     the waits the port drops (cmt_clist.h "taşınmadı").
 *   · `TestWaitChan` (:241-314): `WaitChan`, `NextWaitChan`,
 *     `PrevWaitChan` with a pushing goroutine and `time.Sleep` — the
 *     blocking waits, not ported.
 *   · `_TestGCFifo` (:73-117), `_TestGCRandom` (:123-166): disabled in
 *     the reference itself (underscore-prefixed; "relies on SetFinalizer
 *     which isn't guaranteed to run"). Their INTENT — removed elements
 *     are eventually collected — is what the reference-count cases here
 *     pin deterministically.
 *
 * @file test_cmt_clist.c
 */

#include "dnac/cmt_clist.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* Values are small integers cast through intptr_t, as the reference
 * pushes `1`, `2`, `3` (clist_test.go:29-31). */
#define V(n) ((void *)(intptr_t)(n))

/* A destructor that counts, for the reference-count cases. */
static int g_freed = 0;
static void count_free(void *ctx, void *value)
{
    (void)ctx;
    (void)value;
    g_freed++;
}

/* clist_test.go:15-25 — TestPanicOnMaxLength. The panic is a FAULT
 * (cmt_clist.h "Panics"). */
static int t_panic_on_max_length(void)
{
    cmt_clist_t l;
    int         max_length = 1000;                      /* :16 */
    int         i;

    CHECK(cmt_clist_init_with_max(&l, max_length, NULL, NULL) == CMT_OK,
          "newWithMax");                                /* :18 */
    for (i = 0; i < max_length; i++) {                  /* :19-21 */
        CHECK(cmt_clist_push_back(&l, V(1), NULL) == CMT_OK, "PushBack");
    }
    CHECK(cmt_clist_len(&l) == max_length, "Len == maxLength");
    CHECK(cmt_clist_push_back(&l, V(1), NULL) == CMT_FAULT,
          "the 1001st push is the MaxLength panic → FAULT");  /* :22-24 */
    /* STRONGER than the reference: the list is unchanged after the
     * refused push (Go's panic unwinds without a defined state). */
    CHECK(cmt_clist_len(&l) == max_length, "Len unchanged after refusal");
    cmt_clist_free(&l);
    OK();

    CHECK(cmt_clist_init_with_max(&l, -1, NULL, NULL) == CMT_FAULT,
          "a negative max is refused");
    CHECK(cmt_clist_init(NULL, NULL, NULL) == CMT_FAULT, "NULL list");
    OK();
    return 0;
}

/* clist_test.go:27-67 — TestSmall */
static int t_small(void)
{
    cmt_clist_t       l;
    cmt_clist_elem_t *el1, *el2, *el3;
    void             *r1, *r2, *r3;

    CHECK(cmt_clist_init(&l, NULL, NULL) == CMT_OK, "New");     /* :28 */
    CHECK(cmt_clist_push_back(&l, V(1), &el1) == CMT_OK, "el1"); /* :29 */
    CHECK(cmt_clist_push_back(&l, V(2), &el2) == CMT_OK, "el2"); /* :30 */
    CHECK(cmt_clist_push_back(&l, V(3), &el3) == CMT_OK, "el3"); /* :31 */
    CHECK(cmt_clist_len(&l) == 3, "Expected len 3");             /* :32-34 */
    CHECK(cmt_clist_front(&l) == el1 && cmt_clist_back(&l) == el3,
          "front/back");
    CHECK(cmt_clist_elem_next(el1) == el2 && cmt_clist_elem_next(el2) == el3 &&
          cmt_clist_elem_next(el3) == NULL, "next chain");
    CHECK(cmt_clist_elem_prev(el3) == el2 && cmt_clist_elem_prev(el2) == el1 &&
          cmt_clist_elem_prev(el1) == NULL, "prev chain");

    CHECK(cmt_clist_remove(&l, el1, &r1) == CMT_OK, "Remove el1"); /* :40 */
    CHECK(cmt_clist_remove(&l, el2, &r2) == CMT_OK, "Remove el2"); /* :46 */
    CHECK(cmt_clist_remove(&l, el3, &r3) == CMT_OK, "Remove el3"); /* :52 */
    CHECK(r1 == V(1), "Expected 1");                             /* :54-56 */
    CHECK(r2 == V(2), "Expected 2");                             /* :57-59 */
    CHECK(r3 == V(3), "Expected 3");                             /* :60-62 */
    CHECK(cmt_clist_len(&l) == 0, "Expected len 0");             /* :63-65 */
    CHECK(cmt_clist_front(&l) == NULL && cmt_clist_back(&l) == NULL,
          "empty");
    cmt_clist_free(&l);
    OK();
    return 0;
}

/* C-only: property 1 of cmt_clist.h — a removed element keeps `next`
 * (clist.go:356-401 never clears it), and `next_wait_ready` is :67. */
static int t_removed_keeps_next(void)
{
    cmt_clist_t       l;
    cmt_clist_elem_t *a, *b, *c;
    cmt_clist_elem_t *cursor;

    CHECK(cmt_clist_init(&l, NULL, NULL) == CMT_OK, "New");
    CHECK(cmt_clist_push_back(&l, V(1), &a) == CMT_OK, "a");
    CHECK(cmt_clist_push_back(&l, V(2), &b) == CMT_OK, "b");
    CHECK(cmt_clist_push_back(&l, V(3), &c) == CMT_OK, "c");

    /* A live tail: NextWait would block (:67 both false). */
    CHECK(!cmt_clist_elem_next_wait_ready(c), "live tail is not ready");
    CHECK(cmt_clist_elem_next_wait_ready(a), "a has a next → ready");
    CHECK(!cmt_clist_elem_removed(b), "b is live");

    /* A cursor parked on b; b is removed (as recheckTxs :658 / :495
     * removes the element it stands on); b.Next() is still c. */
    cursor = b;
    cmt_clist_elem_ref(cursor);
    CHECK(cmt_clist_remove(&l, b, NULL) == CMT_OK, "Remove b");
    CHECK(cmt_clist_elem_removed(b), "b is removed");
    CHECK(cmt_clist_elem_next(b) == c, "removed b still names c (:354)");
    CHECK(cmt_clist_elem_next(a) == c && cmt_clist_elem_prev(c) == a,
          "a and c are linked around b (:388, :393)");
    CHECK(cmt_clist_len(&l) == 2, "Len 2");
    CHECK(cmt_clist_elem_next_wait_ready(b), "removed with a next → ready");
    /* The mempool's contract: DetachPrev after Remove (:369). */
    CHECK(cmt_clist_elem_detach_prev(b) == CMT_OK, "DetachPrev on removed");
    CHECK(cmt_clist_elem_prev(b) == NULL, "prev cleared");
    cmt_clist_elem_unref(cursor);
    OK();

    /* Removing the tail: no next, removed → ready (:207-210). */
    cursor = c;
    cmt_clist_elem_ref(cursor);
    CHECK(cmt_clist_remove(&l, c, NULL) == CMT_OK, "Remove c");
    CHECK(cmt_clist_elem_next(c) == NULL, "tail had no next");
    CHECK(cmt_clist_elem_next_wait_ready(c), "removed tail → ready");
    CHECK(cmt_clist_back(&l) == a && cmt_clist_front(&l) == a, "a alone");
    cmt_clist_elem_unref(cursor);
    OK();

    /* Detach on a LIVE element is the panic → FAULT (:140, :150). */
    CHECK(cmt_clist_elem_detach_next(a) == CMT_FAULT, "DetachNext on live");
    CHECK(cmt_clist_elem_detach_prev(a) == CMT_FAULT, "DetachPrev on live");
    CHECK(cmt_clist_elem_detach_next(NULL) == CMT_FAULT, "NULL");
    OK();

    /* Remove of an element the list does not hold → FAULT (:364-372):
     * an element whose prev is NULL but is not the head (:368, `x`
     * below), and a second removal of `y` once the list is empty
     * (:364). */
    CHECK(cmt_clist_remove(&l, a, NULL) == CMT_OK, "Remove a");
    CHECK(cmt_clist_len(&l) == 0, "empty");
    {
        cmt_clist_elem_t *x, *y;

        CHECK(cmt_clist_push_back(&l, V(7), &x) == CMT_OK, "x");
        CHECK(cmt_clist_push_back(&l, V(8), &y) == CMT_OK, "y");
        cmt_clist_elem_ref(x);
        CHECK(cmt_clist_remove(&l, x, NULL) == CMT_OK, "Remove x");
        CHECK(cmt_clist_elem_detach_prev(x) == CMT_OK, "detach x");
        /* x: prev NULL, not the head → "false head" → FAULT. */
        CHECK(cmt_clist_remove(&l, x, NULL) == CMT_FAULT,
              "double Remove is the false-head panic → FAULT");
        CHECK(cmt_clist_len(&l) == 1 && cmt_clist_front(&l) == y,
              "list untouched by the refused Remove");
        cmt_clist_elem_unref(x);
        /* A cursor keeps `y` alive across both removes: after the first
         * one nothing else references it (x, which named it as `next`,
         * is already gone), and the second call must be handed a live
         * element. */
        cmt_clist_elem_ref(y);
        CHECK(cmt_clist_remove(&l, y, NULL) == CMT_OK, "Remove y");
        CHECK(cmt_clist_remove(&l, y, NULL) == CMT_FAULT,
              "Remove on an empty list → FAULT (:364)");
        cmt_clist_elem_unref(y);
    }
    CHECK(cmt_clist_remove(NULL, a, NULL) == CMT_FAULT, "NULL list");
    CHECK(cmt_clist_remove(&l, NULL, NULL) == CMT_FAULT, "NULL elem");
    cmt_clist_free(&l);
    OK();
    return 0;
}

/* C-only: the reference count frees an element exactly when Go's GC
 * would — never while a cursor holds it, once when nothing does. */
static int t_refcount_cursor(void)
{
    cmt_clist_t       l;
    cmt_clist_elem_t *a, *b;

    g_freed = 0;
    CHECK(cmt_clist_init(&l, count_free, NULL) == CMT_OK, "New");
    CHECK(cmt_clist_push_back(&l, V(1), &a) == CMT_OK, "a");
    CHECK(cmt_clist_push_back(&l, V(2), &b) == CMT_OK, "b");

    /* No cursor: Remove frees at once (nothing else references a). */
    CHECK(cmt_clist_remove(&l, a, NULL) == CMT_OK, "Remove a");
    CHECK(g_freed == 1, "a freed at removal: no cursor held it");

    /* A cursor: Remove does NOT free; unref does. */
    cmt_clist_elem_ref(b);
    CHECK(cmt_clist_remove(&l, b, NULL) == CMT_OK, "Remove b");
    CHECK(g_freed == 1, "b NOT freed: a cursor holds it");
    CHECK(cmt_clist_elem_removed(b) && cmt_clist_elem_value(b) == V(2),
          "b is still readable through the cursor (reactor.go:229, :241)");
    cmt_clist_elem_unref(b);
    CHECK(g_freed == 2, "b freed when the cursor let go");
    CHECK(cmt_clist_len(&l) == 0, "empty");
    cmt_clist_free(&l);
    CHECK(g_freed == 2, "nothing freed twice");
    OK();

    /* NULL is a no-op for both. */
    cmt_clist_elem_ref(NULL);
    cmt_clist_elem_unref(NULL);
    OK();
    return 0;
}

/* C-only: a chain of removed elements kept alive by ONE cursor at its
 * head — the shape a slow reactor cursor produces when Update removes
 * everything ahead of it — is freed in one cascade when the cursor
 * moves off, and a cursor can walk the chain forward. */
static int t_refcount_chain(void)
{
    cmt_clist_t       l;
    cmt_clist_elem_t *e[5];
    cmt_clist_elem_t *cursor;
    cmt_clist_elem_t *live;
    int               i;

    g_freed = 0;
    CHECK(cmt_clist_init(&l, count_free, NULL) == CMT_OK, "New");
    for (i = 0; i < 5; i++) {
        CHECK(cmt_clist_push_back(&l, V(i + 1), &e[i]) == CMT_OK, "push");
    }
    cursor = e[0];
    cmt_clist_elem_ref(cursor);

    /* Remove e0..e3 (the mempool's Remove + DetachPrev), keep e4 live. */
    for (i = 0; i < 4; i++) {
        CHECK(cmt_clist_remove(&l, e[i], NULL) == CMT_OK, "Remove");
        CHECK(cmt_clist_elem_detach_prev(e[i]) == CMT_OK, "DetachPrev");
    }
    CHECK(g_freed == 0, "nothing freed: the cursor's chain holds e0..e3");
    CHECK(cmt_clist_len(&l) == 1 && cmt_clist_front(&l) == e[4], "e4 live");

    /* Walk the cursor forward through the removed chain, as
     * broadcastTxRoutine does (:250-252), releasing as it goes. */
    for (i = 0; i < 4; i++) {
        cmt_clist_elem_t *next;

        CHECK(cursor == e[i], "cursor on e[i]");
        CHECK(cmt_clist_elem_next_wait_ready(cursor), "ready (removed)");
        next = cmt_clist_elem_next(cursor);
        CHECK(next == e[i + 1], "next is the element that followed");
        cmt_clist_elem_ref(next);
        cmt_clist_elem_unref(cursor);
        cursor = next;
        CHECK(g_freed == i + 1, "exactly one element freed per step");
    }
    CHECK(cursor == e[4] && !cmt_clist_elem_removed(e[4]), "at the live tail");
    live = e[4];
    cmt_clist_elem_unref(cursor);
    CHECK(g_freed == 4, "the live element is not freed by unref");
    OK();

    /* And the cascade: a cursor at the head of a removed chain lets go
     * → the whole chain goes at once. */
    for (i = 0; i < 3; i++) {
        CHECK(cmt_clist_push_back(&l, V(10 + i), &e[i]) == CMT_OK, "push");
    }
    /* list: live, e0, e1, e2 */
    cursor = live;
    cmt_clist_elem_ref(cursor);
    CHECK(cmt_clist_remove(&l, live, NULL) == CMT_OK, "Remove live");
    CHECK(cmt_clist_elem_detach_prev(live) == CMT_OK, "detach");
    for (i = 0; i < 3; i++) {
        CHECK(cmt_clist_remove(&l, e[i], NULL) == CMT_OK, "Remove");
        CHECK(cmt_clist_elem_detach_prev(e[i]) == CMT_OK, "detach");
    }
    CHECK(g_freed == 4, "nothing freed: cursor → live → e0 → e1 → e2");
    CHECK(cmt_clist_len(&l) == 0, "empty");
    cmt_clist_elem_unref(cursor);
    CHECK(g_freed == 8, "the four-element chain freed in one cascade");
    cmt_clist_free(&l);
    CHECK(g_freed == 8, "free of an empty list frees nothing");
    OK();
    return 0;
}

/* C-only: cmt_clist_free on a populated list frees every element once;
 * an element a cursor still holds survives it. */
static int t_free_all(void)
{
    cmt_clist_t       l;
    cmt_clist_elem_t *held = NULL;
    int               i;

    g_freed = 0;
    CHECK(cmt_clist_init(&l, count_free, NULL) == CMT_OK, "New");
    for (i = 0; i < 10; i++) {
        cmt_clist_elem_t *e;

        CHECK(cmt_clist_push_back(&l, V(i), &e) == CMT_OK, "push");
        if (i == 5) {
            held = e;
        }
    }
    cmt_clist_elem_ref(held);
    cmt_clist_free(&l);
    CHECK(cmt_clist_len(&l) == 0 && cmt_clist_front(&l) == NULL, "reset");
    /* e0..e4 freed by the cascade from the head; e5 is held, and it
     * holds e6..e9 through its `next` reference. */
    CHECK(g_freed == 5, "five freed, the held one and its chain not");
    CHECK(cmt_clist_elem_value(held) == V(5), "held is readable");
    cmt_clist_elem_unref(held);
    CHECK(g_freed == 10, "the rest freed when the cursor let go");
    cmt_clist_free(NULL);
    OK();
    return 0;
}

int main(void)
{
    if (t_panic_on_max_length() != 0) { return 1; }
    if (t_small() != 0)               { return 1; }
    if (t_removed_keeps_next() != 0)  { return 1; }
    if (t_refcount_cursor() != 0)     { return 1; }
    if (t_refcount_chain() != 0)      { return 1; }
    if (t_free_all() != 0)            { return 1; }

    printf("test_cmt_clist: OK (%d groups)\n", g_checks);
    return 0;
}
