/**
 * Nodus — the published network file and the chain-pin start check
 *
 * P2P-PORT F6. Moved out of nodus_server.c by the S1 witness seam
 * (decision docs/plans/decisions/2026-10-01-nodus-component-split.md):
 * everything here is about the chain the witness runs — its database's
 * id, the pin a node starts against, and the 4004 persistent peers —
 * and nothing here needs the server.
 *
 * @file nodus_witness_network_file.h
 */

#ifndef NODUS_WITNESS_NETWORK_FILE_H
#define NODUS_WITNESS_NETWORK_FILE_H

#include <stdbool.h>
#include <stdint.h>

#include "witness/nodus_witness_p2p.h"      /* nodus_p2p_config_t, list caps */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The committed chain id (32 bytes) of the version-3 chain database at
 * `db_path`, read on a read-only handle through
 * nodus_witness_v2_gen_stored_chain_id. @return 0 / -1.
 */
int nodus_witness_read_chain_id(const char *db_path, uint8_t out[32]);

/**
 * P2P-PORT F6 — the pin-at-start check. The chain database the witness
 * will open (nodus_witness_scan_chain_db's selection: the
 * lexicographically smallest canonical `witness_<32 lowercase hex>.db`)
 * must be a readable version-3 chain whose id equals `pin`.
 * @return 0 no chain database present, or it matches;
 *         -1 a chain with a different id, or one whose id cannot be read
 *         (logged at ERROR) — the caller refuses to start.
 */
int nodus_witness_check_chain_pin(const char *data_path, const uint8_t pin[32]);

/* ── P2P-PORT F6 — the published network file ─────────────────────────
 *
 * Decision `docs/plans/decisions/2026-09-26-witness-port-session.md`
 * ("Ağ config dosyası (pin + seed'ler)", "Pin'i tören yazar"); design
 * `docs/plans/2026-09-26-p2p-port-design.md` §4. A JSON object, SEPARATE
 * from the node's own nodus.json, with exactly these keys:
 *
 *   {
 *     "v2_genesis_pin":   "<64 hex>" | "" | absent,
 *     "persistent_peers": ["<id>@<ip>:<port>", ...]  | absent
 *   }
 *
 * Any other key, a pin that is not 0 or 64 hex digits, a peer entry that
 * is not "id@ip:port" with a valid ID and an IP literal (R-P2P-24 /
 * R-P2P-33), a duplicate peer entry, or more than NODUS_P2P_MAX_PEER_LIST
 * peers makes the WHOLE file refused: a typo'd key would otherwise read
 * as "no pin" and silently change what the node does.
 *
 * Pin rules (operator): empty/absent → no join; set + no local chain →
 * join exactly like --v2-genesis-pin; set + local chain → must equal the
 * chain's 32-byte id or the node refuses to start; the offline
 * `--derive-v2-genesis` writes the derived id into an EMPTY pin (a pin
 * already there: equal → nothing written, different → refused, never
 * overwritten). A running node never writes the file.
 *
 * Built only with json-c (NODUS_HAS_JSONC), like nodus-server's own
 * config loader.
 */
#ifdef NODUS_HAS_JSONC
typedef struct {
    bool    has_pin;
    uint8_t pin[32];
    int     n_peers;
    char    peers[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_NETADDR_STR_MAX];
} nodus_network_file_t;

/**
 * The configuration fields a network file sets, by reference: the 4004
 * p2p section (persistent peers merged in), the joiner pin and the
 * start-check pin. The node's configuration owns them; the server fills
 * this view from its config (nodus_server_network_file_target).
 */
typedef struct {
    nodus_p2p_config_t *p2p;
    bool               *has_v2_genesis_pin;
    uint8_t            *v2_genesis_pin;       /* [32] */
    bool               *has_network_pin;
    uint8_t            *network_pin;          /* [32] */
} nodus_network_file_target_t;

/** Parse and validate `path` (rules above). @return 0; -1 refused (the
 *  reason is logged at ERROR). `out` is zeroed first. */
int nodus_network_file_load(const char *path, nodus_network_file_t *out);

/**
 * Apply a loaded file to a node configuration: the file's persistent
 * peers are merged into `*t->p2p` (an entry already present — e.g. from
 * `-s id@` or nodus.json — is not added twice); a file pin arms the joiner
 * (`has_v2_genesis_pin`) and the start check (`has_network_pin`). A file
 * pin that differs from an already-given `--v2-genesis-pin` is refused.
 * @return 0; -1 refused (logged).
 */
int nodus_network_file_apply(const nodus_network_file_t *nf,
                             const nodus_network_file_target_t *t);

/**
 * The pin-auto write of the genesis ceremony: put `chain32` into the
 * file's EMPTY pin — temp file in the same directory, fsync, rename,
 * directory fsync; every other key kept, in its order.
 * @return 0 written; 1 the file already holds exactly this pin (nothing
 *         written); -1 refused — the file is malformed or holds a
 *         DIFFERENT pin (never overwritten) — or an I/O fault (logged).
 */
int nodus_network_file_write_pin(const char *path, const uint8_t chain32[32]);
#endif /* NODUS_HAS_JSONC */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_NETWORK_FILE_H */
