/**
 * Nodus — the server's IPC-only constructor table (split S6, nodus-core)
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md
 * items 2, 3, 4, 6, 12: nodus-core keeps 4000 / 4001 / 4002, sessions,
 * cluster, presence and circuits, and reaches its storage
 * (<data_path>/storage.sock) and witness (<data_path>/witness.sock)
 * over IPC only. Every in-process slot is NULL — nodus_server_init_ex
 * refuses a config that would need one — and `admit` refuses up front
 * unless BOTH storage_external and witness_external are set, before the
 * partial-wipe gate or anything else touches the data directory.
 *
 * This TU references no in-process DHT or witness object
 * (tests/core_linked.cmake).
 *
 * @file nodus_server_backends_ipc.c
 */

#include "server/nodus_server.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "NODUS_CORE"

static int ipc_admit(const nodus_server_config_t *config) {
    if (config->storage_external && config->witness_external)
        return 0;
    QGP_LOG_ERROR(LOG_TAG, "nodus-core runs only with BOTH storage_external "
                  "and witness_external set (storage_external=%s, "
                  "witness_external=%s) — it carries no in-process DHT or "
                  "witness. Use nodus-server for a combined node. Not "
                  "starting.",
                  config->storage_external ? "true" : "false",
                  config->witness_external ? "true" : "false");
    return -1;
}

const nodus_server_backends_t nodus_server_backends_ipc = {
    .admit      = ipc_admit,
    .check_pin  = NULL,
    .dht_new    = NULL,
    .dht_open   = NULL,
    .chain_open = NULL,
};
