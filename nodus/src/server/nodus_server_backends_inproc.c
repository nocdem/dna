/**
 * Nodus — the server's in-process constructor table (split S6)
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md
 * items 2, 8: the combined nodus-server stays. This TU is the ONE place
 * that names the in-process DHT and witness constructors for the server,
 * and it holds nodus_server_init, so every binary or test that calls
 * nodus_server_init gets exactly what it had before the seam. nodus-core
 * does not reference this object (it calls nodus_server_init_ex with
 * nodus_server_backends_ipc), so the static link leaves nodus_dht_server.c
 * and nodus_witness.c out of it (tests/core_linked.cmake).
 *
 * @file nodus_server_backends_inproc.c
 */

#include "server/nodus_server.h"

const nodus_server_backends_t nodus_server_backends_inproc = {
    .admit      = NULL,
    .check_pin  = nodus_chain_backend_inproc_check_pin,
    .dht_new    = nodus_dht_backend_inproc_new,
    .dht_open   = nodus_dht_backend_inproc_open,
    .chain_open = nodus_chain_backend_inproc_open,
};

int nodus_server_init(nodus_server_t *srv, const nodus_server_config_t *config) {
    return nodus_server_init_ex(srv, config, &nodus_server_backends_inproc);
}
