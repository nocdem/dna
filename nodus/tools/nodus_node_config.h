/**
 * Nodus — node command line + config file (shared by nodus-server,
 * nodus-witness and nodus-storage; component split S3 / S5b, decision
 * item 18: one config file, each service reads its own keys)
 *
 * Two translation units:
 *   - nodus_node_config.c — the options, the JSON keys and the two parse
 *     passes. It references no witness object, so nodus-storage can link
 *     it (tests/storage_linked.cmake).
 *   - nodus_node_config_witness.c — the witness-side parts: the 4004 p2p
 *     section (defaults, persistent / unconditional / private peers, the
 *     "id@" half of a seed), the network file, and the --derive-v2-genesis
 *     one-shot. Linked only by nodus-server and nodus-witness, which get
 *     exactly what they had before the split (nodus_node_config_load).
 *
 * @file nodus_node_config.h
 */

#ifndef NODUS_NODE_CONFIG_H
#define NODUS_NODE_CONFIG_H

#include "server/nodus_server.h"   /* nodus_server_config_t (type only) */

/**
 * The witness-side parts of the parse (nodus_node_config_witness.c). Each
 * runs at the exact point of the parse where the single-TU loader ran it.
 * NULL (nodus-storage): the p2p section stays zero, an "id@" seed adds
 * only its DHT seed, the p2p JSON keys and the network file are not read,
 * and --derive-v2-genesis is refused.
 */
typedef struct {
    void (*p2p_default)(nodus_p2p_config_t *c);
    int  (*p2p_add_persistent)(nodus_p2p_config_t *c, const char *s);
    int  (*p2p_add_unconditional)(nodus_p2p_config_t *c, const char *id);
    int  (*p2p_add_private)(nodus_p2p_config_t *c, const char *id);
    /** The --derive-v2-genesis one-shot. @return the process exit code. */
    int  (*derive)(const char *cfg_path, const char *data_path,
                   const char *network_file);
    /** Load the network file at `path` and apply it to `cfg` (pin,
     *  persistent peers), printing the outcome. @return 0, or -1 refused
     *  (logged: the node must not start). */
    int  (*network_file_apply)(const char *path, nodus_server_config_t *cfg);
} nodus_node_config_witness_t;

/**
 * The parse itself: defaults, the first option pass, the JSON file, the
 * second option pass (command line over file), then — with `w` — the
 * network file or the derivation one-shot. `title` heads the -h text.
 *
 * @return -1: start the node with `*out`;
 *         >= 0: do not start — exit with this code (-h, a refused option
 *         or file, or the derivation one-shot's result); `*out` untouched.
 */
int nodus_node_config_parse(int argc, char **argv, const char *title,
                            const nodus_node_config_witness_t *w,
                            nodus_server_config_t *out);

/**
 * nodus-server and nodus-witness (nodus_node_config_witness.c): the parse
 * with every witness-side part, exactly as nodus-server always built its
 * configuration. `--derive-v2-genesis` runs its offline one-shot here and
 * ends the process's work. Same return contract.
 */
int nodus_node_config_load(int argc, char **argv, const char *title,
                           nodus_server_config_t *out);

/**
 * nodus-storage (split S5b): the parse without the witness-side parts
 * (`w` NULL above) — the storage process reads no 4004 setting, no network
 * file, and does not run the derivation. Same return contract.
 */
int nodus_node_config_load_storage(int argc, char **argv, const char *title,
                                   nodus_server_config_t *out);

#endif /* NODUS_NODE_CONFIG_H */
