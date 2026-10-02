/**
 * Nodus — node command line + config file (shared by nodus-server and
 * nodus-witness; component split S3, decision item 18)
 *
 * @file nodus_node_config.h
 */

#ifndef NODUS_NODE_CONFIG_H
#define NODUS_NODE_CONFIG_H

#include "server/nodus_server.h"   /* nodus_server_config_t (type only) */

/**
 * Build the node configuration from the command line, the JSON config
 * file (-c) and the network file, exactly as nodus-server always has:
 * defaults, the first option pass, the JSON file, the second option pass
 * (command line over file), then the network file. `--derive-v2-genesis`
 * runs its offline one-shot here and ends the process's work.
 * `title` heads the -h text ("Nodus Server", "Nodus Witness").
 *
 * @return -1: start the node with `*out`;
 *         >= 0: do not start — exit with this code (-h, a refused option
 *         or file, or the derivation one-shot's result); `*out` untouched.
 */
int nodus_node_config_load(int argc, char **argv, const char *title,
                           nodus_server_config_t *out);

#endif /* NODUS_NODE_CONFIG_H */
