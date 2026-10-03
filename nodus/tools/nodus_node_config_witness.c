/**
 * Nodus — node command line + config file: the WITNESS-SIDE parts
 * (nodus-server and nodus-witness only)
 *
 * Component split S5b: the 4004 p2p section, the network file and the
 * --derive-v2-genesis one-shot moved here out of nodus_node_config.c,
 * unchanged, so that the nodus-storage binary — which links only
 * nodus_node_config.c — references no witness object
 * (tests/storage_linked.cmake). nodus_node_config_load hands these parts
 * to the shared parse (nodus_node_config_parse) at the points the
 * single-TU loader ran them, so nodus-server and nodus-witness build the
 * same configuration as before.
 *
 * @file nodus_node_config_witness.c
 */

#include "nodus_node_config.h"
#include "witness/nodus_witness_v2_gen.h" /* O16A / D1 — the genesis builder */
#include "witness/nodus_witness_p2p.h"    /* the 4004 p2p section helpers   */
#include "nodus_v2_gen_config.h"          /* O16A / D2 — its text config     */
#include "nodus/nodus_types.h"

#include <dirent.h>
#include <sys/stat.h>                     /* O16A — derive-time sentinel check */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* ── O16A / D1 — the offline genesis derivation one-shot ─────────────
 *
 * Everything below runs INSTEAD OF starting a server, never beside one.
 * That shape is not a convenience; two properties of the ceremony fall
 * out of it rather than out of a check:
 *
 *  - The node is not on the network while the chain is being derived.
 *    nodus_witness_v2_gen_derive_v3 takes no witness and no server
 *    handle (nodus_witness_v2_gen.h), so nothing arriving from a peer can
 *    reach a derived byte; with an offline tool there is additionally no
 *    process a peer could talk to.
 *  - The two abort()ing migrations inside nodus_witness_create_chain_db
 *    (nodus_witness_db.c, migrate_v12's ALTER and DROP INDEX paths)
 *    cannot kill a live node. On a one-shot tool an abort is a failed
 *    ceremony step the operator sees on their terminal; inside a running
 *    node it is a process death.
 *
 * ⚠ The rejected alternative was "derive automatically when the data dir
 * is empty and a genesis config is present". A node that lost its
 * database would then silently re-derive a chain instead of refusing or
 * joining, and in a hard cutover there is no second chance: the operator
 * gets a node that looks healthy and is on its own chain.
 */

/* Print a byte string as lowercase hex on stdout. */
static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* Locate the single chain database in `dir`.
 *
 * The filename predicate is character-for-character the one
 * gen_chain_db_scan uses (nodus_witness_v2_gen.c). That agreement is
 * load-bearing rather than tidy: if this tool counted a file the builder
 * ignores — or missed one it counts — the operator would be shown a pin
 * for a database the builder does not consider part of the data path.
 *
 * @return 0 exactly one found (path written), -1 otherwise. */
static int find_single_chain_db(const char *dir, char *out, size_t out_len) {
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "cannot read data directory %s\n", dir);
        return -1;
    }
    struct dirent *e;
    int found = 0;
    int truncated = 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        found++;
        if (found == 1) {
            int n = snprintf(out, out_len, "%s/%s", dir, e->d_name);
            if (n < 0 || (size_t)n >= out_len) truncated = 1;
        }
    }
    closedir(d);
    if (truncated) {
        fprintf(stderr,
                "the chain database path under %s is too long to express — "
                "refusing rather than reading a truncated path\n", dir);
        return -1;
    }
    if (found == 1) return 0;
    /* More than one is refused rather than reported: with two chain
     * databases present, "which chain did this ceremony produce" has no
     * answer, and printing whichever readdir handed over first would make
     * the operator's pin depend on filesystem order. */
    fprintf(stderr,
            "expected exactly one witness_<hex>.db in %s after a "
            "derivation, found %d\n", dir, found);
    return -1;
}

/* Read the committed chain id out of a landed version-3 chain database.
 *
 * R3 W3 (D-17 rev 10 (8) / D-18 rev 4): a version-3 chain writes no
 * height-0 `v2_blocks` row (D-19 rev 6 withdrew the genesis block) — its
 * identity is the hash of its stored genesis DOCUMENT, read through the
 * canonical-strict accessor `nodus_witness_v2_gen_stored_chain_id`
 * (nodus_witness_v2_gen.h), the same reader the preflight and the join
 * pipeline use. `nodus_witness_v2_gen_stored_chain_id`'s own doc comment
 * says only `w->db` is used, so a read-only handle with nothing else set
 * is enough — no full witness-open ceremony is needed for an offline
 * tool.
 *
 * @return 0 / -1. */
static int read_genesis_chain_id(const char *db_path,
                                 uint8_t out[NODUS_V2_GEN_CHAIN_ID_LEN]) {
    /* P2P-PORT F6: the reader itself lives in
     * nodus_witness_network_file.c (nodus_witness_read_chain_id) so the
     * network file's pin-at-start check reads the chain id through the
     * SAME code as this ceremony. */
    int rc = nodus_witness_read_chain_id(db_path, out);
    if (rc != 0)
        fprintf(stderr,
                "the derived chain database %s could not be opened or has "
                "no readable genesis document identity — the W_V2GEN lines "
                "above name the reason\n", db_path);
    return rc;
}

/* Parse the config, derive the chain into `data_path`, print the two
 * values the ceremony needs, and return the process exit code. */
/* Refuse to derive into a data directory that still carries unfinished
 * business from a previous life.
 *
 * ── WHAT WOULD HAVE TO HAPPEN, because a risk without a cause is a
 * guess ──────────────────────────────────────────────────────────────
 *
 * Two dotfiles live beside the chain, and BOTH SURVIVE THE CEREMONY'S
 * WIPE: the runbook removes `witness_*`, and a name beginning with a dot
 * does not match that glob.
 *
 *   .bootstrap_in_progress — written by the LEGACY FETCH_GENESIS handler,
 *     which used to create it before deriving a chain database and unlink
 *     it on success. R3 W4 deleted that handler (and the DISCOVER branch
 *     that reached it) with the closed consensus lane, so a binary built
 *     from this tree can no longer write this file; present at boot, it
 *     means an OLDER binary died mid-write before this delta.
 *
 *   .recovery_in_progress — armed by halt recovery between dropping the
 *     witness database and replaying the first block.
 *
 * For either to be sitting here when the ceremony runs, a node must have
 * died inside one of those windows AND never been restarted since —
 * because the very next start clears the first and refuses on the
 * second. A stop-all cutover is exactly the situation that supplies the
 * "never restarted": the node crashed, nobody brought it back, and the
 * operator moved straight to the ceremony.
 *
 * ── WHY THIS IS WORTH A CHECK, given how narrow that is ──────────────
 *
 * The two consequences are not equally survivable. `.recovery_in_progress`
 * REFUSES the start, loudly, printing its own remedy — annoying, not
 * dangerous. `.bootstrap_in_progress` is the dangerous one: witness init
 * hands it to nodus_witness_check_orphan_bootstrap_sentinel, which calls
 * witness_archive_stale_chain_dbs(data_path, NULL) — and NULL means
 * archive EVERY witness_<hex>.db in the directory, including the genesis
 * chain derived twenty minutes earlier. It then clears the sentinel and
 * the node comes up reporting "no chain DB found — pre-genesis state".
 * A correct ceremony, silently undone, with no error anywhere.
 *
 * ── WHY HERE AND NOT IN THE ARCHIVE PATH ─────────────────────────────
 *
 * The archive is not wrong about what it was written for: a partial
 * database from a crashed legacy bootstrap IS garbage. It is wrong only
 * about a pure-V2 chain, which that path never produced. Teaching it the
 * difference means touching witness init; refusing here costs one stat
 * per ceremony and puts the message in front of the operator at the one
 * moment they are present, with nothing derived yet to lose.
 *
 * And the window is now closed for every node, not just a pure-V2 one:
 * R3 W4 deleted the legacy DISCOVER/FETCH_GENESIS bootstrap path
 * (nodus_witness_bootstrap_start and the verbs it drove) outright, so
 * no binary built from this tree can write .bootstrap_in_progress
 * again. The reader side this precheck guards against —
 * nodus_witness_check_orphan_bootstrap_sentinel and
 * witness_archive_stale_chain_dbs, both still live in nodus_witness.c
 * — is unchanged, which is why a sentinel left by an older binary is
 * still worth refusing on here.
 *
 * @return 0 clean, -1 refuse. */
static int derive_precheck_sentinels(const char *data_path) {
    static const struct {
        const char *name;
        const char *what;
    } sentinels[] = {
        { ".bootstrap_in_progress",
          "a previous LEGACY bootstrap died mid-write. Left in place, the "
          "next start would ARCHIVE the chain this ceremony is about to "
          "derive and come up as if it had none" },
        { ".recovery_in_progress",
          "a previous halt recovery did not finish. Left in place, the "
          "next start refuses outright" },
    };

    int bad = 0;
    for (size_t i = 0; i < sizeof(sentinels) / sizeof(sentinels[0]); i++) {
        char p[640];
        int n = snprintf(p, sizeof(p), "%s/%s", data_path, sentinels[i].name);
        if (n < 0 || (size_t)n >= sizeof(p)) {
            fprintf(stderr, "data path too long to check for %s\n",
                    sentinels[i].name);
            return -1;
        }
        struct stat st;
        if (stat(p, &st) != 0) continue;          /* absent — the normal case */

        fprintf(stderr,
                "REFUSING TO DERIVE — %s is present in %s.\n"
                "  What it means: %s.\n"
                "  Note it survived the wipe: the runbook removes "
                "witness_*, and a dot-file does not match that glob.\n"
                "  Fix: establish why the node died, then `rm %s` and "
                "re-run this command.\n",
                sentinels[i].name, data_path, sentinels[i].what, p);
        bad = 1;
    }
    return bad ? -1 : 0;
}

/* P2P-PORT F6 — `network_file` (may be NULL): the published network file
 * the ceremony writes the derived chain id into ("Pin'i tören yazar",
 * decision 2026-09-26-witness-port-session.md). An EMPTY pin is filled;
 * the SAME pin is left alone (several nodes deriving independently all
 * reach this case after the first); a DIFFERENT pin stops the ceremony
 * and is never overwritten. */
static int run_derive_v2_genesis(const char *cfg_path, const char *data_path,
                                 const char *network_file) {
    /* BEFORE the config is even parsed: nothing has been done yet, so a
     * refusal here costs the operator nothing but a message. */
    if (derive_precheck_sentinels(data_path) != 0)
        return 1;

#ifdef NODUS_HAS_JSONC
    if (network_file) {
        nodus_network_file_t nf;
        if (nodus_network_file_load(network_file, &nf) != 0) {
            fprintf(stderr, "network file %s was REFUSED (the lines above "
                    "say why) — nothing derived.\n", network_file);
            return 1;
        }
        /* A data directory that already holds a chain lets the pin be
         * compared BEFORE anything is written (the derivation is
         * idempotent there). Without a chain the id exists only after
         * the derivation, and the comparison happens at the write. */
        if (nf.has_pin &&
            nodus_witness_check_chain_pin(data_path, nf.pin) != 0) {
            fprintf(stderr, "network file %s pins a different chain than "
                    "the one in %s — nothing derived.\n", network_file,
                    data_path);
            return 1;
        }
    }
#else
    if (network_file) {
        fprintf(stderr, "--network-file / \"network_file\" needs a build "
                "with json-c — nothing derived.\n");
        return 1;
    }
#endif

    nodus_v2_gen_config_t *cfg = NULL;
    if (nodus_v2_gen_config_parse_file(cfg_path, &cfg) != 0) {
        fprintf(stderr, "genesis config %s was REFUSED — nothing derived.\n",
                cfg_path);
        return 1;
    }

    fprintf(stderr,
            "deriving a cometbft (version 3) chain from %s into %s\n"
            "(offline one-shot: no socket is opened, no server is started)\n",
            cfg_path, data_path);

    /* R3 W3 (D-17 rev 10 (9)): the ceremony derives version 3 only. The
     * version-2 entry (nodus_witness_v2_gen_derive), closed by W3, is
     * DELETED from the tree by tokenomics-v3 P4 (OBLIGATION
     * atlas-dec-71525f3b), and the config parser refuses a version-2 or
     * version-less file before this point. out_chain32 is still passed
     * as NULL on purpose, and the printed value comes from the committed
     * database instead: nodus_witness_v2_gen_derive_v3 is idempotent and
     * returns 0 WITHOUT writing out_chain32 when a chain built from this
     * same config is already present, so printing from that buffer would
     * print whatever it held on exactly the re-run an operator is most
     * likely to perform — and a WRONG pin handed to six other nodes is
     * the failure this whole change exists to make impossible. The
     * database is the one source that is correct on both paths. */
    int derived_ok = (nodus_witness_v2_gen_derive_v3(data_path, cfg,
                                                     NULL) == 0);
    nodus_v2_gen_config_free(cfg);
    cfg = NULL;

    if (!derived_ok) {
        fprintf(stderr,
                "derivation REFUSED — the W_V2GEN lines above name the "
                "reason. The data directory is unchanged.\n");
        return 1;
    }

    char db_path[600];
    if (find_single_chain_db(data_path, db_path, sizeof(db_path)) != 0)
        return 1;

    /* R3 W3 (D-18 rev 4 / D-24 rev 4 (1)): the chain id IS the pin — a
     * version-3 chain has no 64-byte genesis BlockID to derive one from
     * (D-19 rev 6). One identity, read once. */
    uint8_t chain_id[NODUS_V2_GEN_CHAIN_ID_LEN];
    if (read_genesis_chain_id(db_path, chain_id) != 0) return 1;

    printf("chain-id       ");
    print_hex(chain_id, sizeof(chain_id));
    printf("\n");
    printf("v2-genesis-pin ");
    print_hex(chain_id, sizeof(chain_id));
    printf("\n");

    fprintf(stderr,
            "\nThe chain-id above MUST be identical on every node of the "
            "fleet — compare them before starting anything. Hand the\n"
            "v2-genesis-pin value to a joining node as\n"
            "  nodus-server --v2-genesis-pin <that 64-hex string> ...\n"
            "It is that node's LOCAL trust anchor: it adopts a peer's "
            "genesis bundle only if the bundle re-derives to it.\n");

#ifdef NODUS_HAS_JSONC
    if (network_file) {
        int wrc = nodus_network_file_write_pin(network_file, chain_id);
        if (wrc < 0) {
            fprintf(stderr, "network file %s: the pin was NOT written (the "
                    "lines above say why) — the ceremony is NOT complete. "
                    "The chain above is derived in %s.\n", network_file,
                    data_path);
            return 1;
        }
        printf("network-file   %s %s\n", network_file,
               wrc == 0 ? "pin-written" : "pin-already-equal");
    }
#endif
    return 0;
}

/* P2P-PORT F6 — a running node READS the network file, never writes it:
 * the pin arms the joiner (no chain) and the start check in
 * nodus_server_init (a chain), the peers join the witness port's
 * persistent peers. A malformed file refuses the start. */
static int network_file_apply(const char *network_file,
                              nodus_server_config_t *config) {
#ifdef NODUS_HAS_JSONC
    nodus_network_file_t nf;
    nodus_network_file_target_t nft =
        nodus_server_network_file_target(config);
    if (nodus_network_file_load(network_file, &nf) != 0 ||
        nodus_network_file_apply(&nf, &nft) != 0) {
        fprintf(stderr, "network file %s was REFUSED (the lines above "
                "say why) — not starting\n", network_file);
        return -1;
    }
    fprintf(stderr, "network file %s: pin %s, %d persistent peer(s)\n",
            network_file, nf.has_pin ? "set" : "empty", nf.n_peers);
    return 0;
#else
    (void)config;
    fprintf(stderr, "a network file is configured but this build has "
            "no json-c — not starting\n");
    return -1;
#endif
}

static const nodus_node_config_witness_t g_witness_parts = {
    .p2p_default           = nodus_p2p_config_default,
    .p2p_add_persistent    = nodus_p2p_config_add_persistent,
    .p2p_add_unconditional = nodus_p2p_config_add_unconditional,
    .p2p_add_private       = nodus_p2p_config_add_private,
    .derive                = run_derive_v2_genesis,
    .network_file_apply    = network_file_apply,
};

int nodus_node_config_load(int argc, char **argv, const char *title,
                           nodus_server_config_t *out) {
    return nodus_node_config_parse(argc, argv, title, &g_witness_parts, out);
}
