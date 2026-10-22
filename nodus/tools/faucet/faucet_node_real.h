/**
 * @file faucet_node_real.h
 * @brief The production implementation of faucet_node_t: ONE authenticated,
 *        identity-pinned session to the faucet's LOCAL node through the
 *        client SDK (nodus_client_*). Every call is serialised by one mutex
 *        (the worker and the HTTP thread share the session) and reconnects
 *        by itself when the session is down.
 *
 * Trust (operator "Kendi düğümüne güvensin", design section 6.4): the
 * node is the evidence source; its identity is pinned (config node_fp), so
 * a different server on that port cannot answer.
 */
#ifndef FAUCET_NODE_REAL_H
#define FAUCET_NODE_REAL_H

#include "faucet_cfg.h"
#include "faucet_node.h"

typedef struct faucet_node_real faucet_node_real_t;

/** Create the adapter and fill `vt` (vt->ctx = the adapter). Does not
 *  connect (the first call does). `id` must outlive the adapter.
 *  @return 0 / -1. */
int  faucet_node_real_open(const faucet_cfg_t *cfg, const nodus_identity_t *id,
                           faucet_node_real_t **out, faucet_node_t *vt);
void faucet_node_real_close(faucet_node_real_t *n);

#endif /* FAUCET_NODE_REAL_H */
