/**
 * @file amm_node_real.h
 * @brief The production implementation of amm_node_t: ONE authenticated,
 *        identity-pinned session to the bot's LOCAL node through the client
 *        SDK (nodus_client_*). Every call is serialised by one mutex (the
 *        worker and the HTTP thread share the session). A call WITHOUT a
 *        deadline rebuilds a down session; a call with a deadline never
 *        (re)connects and is bounded by the time left.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 11: "The bot trusts its own node with pinned identity, as the
 * faucet does" (tools/faucet/faucet_node_real.h). The node is the evidence
 * source; its identity is pinned (node_fp of amm_cfg), so a different server
 * on that port cannot answer, and the 4001 secret connection carries the
 * chain id the bot serves.
 *
 * COMPILED INTO NOTHING THAT A TEST RUNS: it needs a live node. CMake builds
 * it as an OBJECT library (amm_node_real) so it is compiled -- with the same
 * warning flags as every AMM target -- and linked by no executable yet
 * (amm_main is a later package).
 */
#ifndef AMM_NODE_REAL_H
#define AMM_NODE_REAL_H

#include "amm_cfg.h"
#include "amm_node.h"

typedef struct amm_node_real amm_node_real_t;

/** Create the adapter and fill `vt` (vt->ctx = the adapter). Does not
 *  connect (the first call does). `id` is the bot's own Nodus identity (the
 *  session owner: the address history and the coin list are the bot's own)
 *  and must outlive the adapter. @return 0 / -1. */
int  amm_node_real_open(const amm_cfg_t *cfg, const nodus_identity_t *id,
                        amm_node_real_t **out, amm_node_t *vt);
void amm_node_real_close(amm_node_real_t *n);

#endif /* AMM_NODE_REAL_H */
