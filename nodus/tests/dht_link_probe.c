/**
 * Component split S4 — link probe for the DHT / storage half.
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md: the
 * DHT half (dht/nodus_dht_server.c, dht/nodus_dht_media.c) reaches core
 * only through the host it is given (nodus_dht_host_t) — never by calling
 * into an auth, presence, cluster or session-table object. S5 moves it into
 * its own process; a direct call would make that process carry core.
 *
 * This program is NEVER RUN. It references every core -> DHT entry point
 * so the linker pulls the DHT objects (and everything they call, nothing
 * else) out of libnodus; tests/dht_linked.cmake then inspects the linked
 * binary's symbol table with `nm`.
 *
 * @file dht_link_probe.c
 */

#include "dht/nodus_dht.h"

/* `void (*)(void)` is the one function-pointer type every other converts
 * to without -Wcast-function-type. */
typedef void (*probe_fn_t)(void);

int main(void) {
    static probe_fn_t volatile keep[] = {
        (probe_fn_t)nodus_dht_init,
        (probe_fn_t)nodus_dht_open,
        (probe_fn_t)nodus_dht_stop,
        (probe_fn_t)nodus_dht_close,
        (probe_fn_t)nodus_dht_session_opened,
        (probe_fn_t)nodus_dht_session_closed,
        (probe_fn_t)nodus_dht_client_request,
        (probe_fn_t)nodus_dht_inter_request,
        (probe_fn_t)nodus_dht_inter_t1,
        (probe_fn_t)nodus_dht_udp_request,
        (probe_fn_t)nodus_dht_peer_seen,
        (probe_fn_t)nodus_dht_peer_dead,
        (probe_fn_t)nodus_dht_hint_store,
        (probe_fn_t)nodus_dht_routing_snapshot,
        (probe_fn_t)nodus_dht_evict_tick,
        (probe_fn_t)nodus_dht_tick,
    };
    return keep[0] == (probe_fn_t)0;
}
