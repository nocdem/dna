/**
 * O15H — TEMPORARY DIAGNOSTIC INSTRUMENTATION. NOT PRODUCTION CODE.
 * See nodus_witness_o15h_diag.h for scope, cost and the revert list.
 *
 * The whole translation unit is inside `#ifdef O15H_DIAG`, so with the
 * CMake option off it compiles to an empty object — the same discipline
 * nodus_witness_fault.c uses for its own test-only hook.
 */
#ifdef O15H_DIAG_ENABLED

#include "witness/nodus_witness_o15h_diag.h"
#include "witness/nodus_witness.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE *g_diag = NULL;
static int   g_open_tried = 0;

uint64_t o15h_diag_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

/* One file per node, beside the node's data directory so the harness's
 * artifact capture picks it up with everything else. */
static FILE *diag_stream(const nodus_witness_t *w) {
    if (g_diag || g_open_tried) return g_diag;
    g_open_tried = 1;
    char path[1024];
    const char *base = (w && w->data_path[0]) ? w->data_path : "/tmp";
    snprintf(path, sizeof(path), "%s/o15h-diag.log", base);
    g_diag = fopen(path, "a");
    if (g_diag) {
        /* Line-buffered on purpose: the tail is where the failure lives,
         * and a block buffer loses it if the node is killed. */
        setvbuf(g_diag, NULL, _IOLBF, 0);
    }
    return g_diag;
}

/* Pointer-keyed heartbeat throttle. Eight slots is more than the two
 * witnesses a process ever hosts; a full table simply stops throttling
 * (it emits), which is the safe direction for a diagnostic. */
bool o15h_diag_rate_ok(const void *w_opaque, unsigned key,
                       uint64_t min_interval_ms) {
    static struct { const void *w; unsigned key; uint64_t last; } slots[8];
    uint64_t now = o15h_diag_ms();
    for (int i = 0; i < 8; i++) {
        if (slots[i].w == w_opaque && slots[i].key == key) {
            if (now - slots[i].last < min_interval_ms) return false;
            slots[i].last = now;
            return true;
        }
    }
    for (int i = 0; i < 8; i++) {
        if (!slots[i].w) {
            slots[i].w = w_opaque;
            slots[i].key = key;
            slots[i].last = now;
            return true;
        }
    }
    return true;
}

static void hex8(char *out, const unsigned char *id) {
    if (!id) { memcpy(out, "--------", 9); return; }
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        out[2 * i]     = h[(id[i] >> 4) & 0xF];
        out[2 * i + 1] = h[id[i] & 0xF];
    }
    out[8] = '\0';
}

void o15h_diag_emit(const void *w_opaque,
                    const char *ev,
                    const unsigned char *who,
                    unsigned long long height,
                    unsigned cur_view,
                    unsigned tgt_view,
                    int phase,
                    unsigned long long phase_start_ms,
                    unsigned long long elapsed_ms,
                    const char *msg_type,
                    int is_leader,
                    unsigned tally,
                    unsigned quorum,
                    const char *why)
{
    const nodus_witness_t *w = (const nodus_witness_t *)w_opaque;
    FILE *f = diag_stream(w);
    if (!f) return;

    char me[9], sender[9];
    hex8(me, w ? w->my_id : NULL);
    hex8(sender, who);

    /* sc= is the chain tag: 1 = V2 successor, 0 = legacy. Both witnesses
     * in a process share this stream, and without the tag their records
     * are indistinguishable. */
    fprintf(f,
            "O15HDIAG ms=%llu node=%s sc=%d ev=%s h=%llu cv=%u tv=%u ph=%d "
            "pst=%llu el=%llu msg=%s lead=%d tally=%u quorum=%u why=%s\n",
            (unsigned long long)o15h_diag_ms(), me,
            (w && w->v2_successor) ? 1 : 0, ev ? ev : "-",
            height, cur_view, tgt_view, phase,
            phase_start_ms, elapsed_ms,
            msg_type ? msg_type : "-", is_leader, tally, quorum,
            why ? why : "-");
}

#endif /* O15H_DIAG_ENABLED */
