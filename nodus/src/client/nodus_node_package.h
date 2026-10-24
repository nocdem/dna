/**
 * @file nodus/src/client/nodus_node_package.h
 * @brief `sudo nodus-cli package list | add <witness|storage> |
 *        remove <witness|storage>` — turn a package of an installed
 *        three-service node on or off.
 *
 * Governing records (local): docs/plans/2026-10-22-nodus-packages-design.md
 * (§1 §2 §3 §4 §5), docs/plans/decisions/2026-10-22-nodus-packages-add-
 * remove.md (add = turn on, remove = turn off, data kept, names witness /
 * storage, `remove witness` refused while registered, core never alone),
 * docs/plans/decisions/2026-10-22-kurultay-36-summary.md (`remove storage`
 * not available in this version; refuse until every post-leave duty is
 * done; one host lock).
 *
 * Four parts, each usable on its own by the unit test:
 *   1. a PURE verdict (nodus_node_package_verdict): unit states + action +
 *      the preflight reply -> allow / already / refuse with a reason code;
 *   2. a systemd adapter: /bin/systemctl, a fixed argument table, a hard
 *      deadline on the child, the post-state checked after every change;
 *   3. the host lock /run/lock/nodus-admin.lock (flock, non-blocking);
 *   4. the registration read (nodus_client_dnac_node_duties over a session
 *      pinned to this node's own key) and the `add witness` addr_seq rule.
 * nodus_node_package_main ties them together; it returns the text the CLI
 * prints (the CLI prints, this module does not).
 *
 * Not consensus code: nothing here is read by a block, a vote or a state
 * root. The clock is read only for the child's deadline.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_NODE_PACKAGE_H
#define NODUS_NODE_PACKAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>          /* uid_t */

#include "nodus/nodus.h"       /* nodus_dnac_node_duties_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ── fixed names ─────────────────────────────────────────────────── */

#define NODUS_NODE_PACKAGE_SYSTEMCTL   "/bin/systemctl"
#define NODUS_NODE_PACKAGE_LOCK_PATH   "/run/lock/nodus-admin.lock"
#define NODUS_NODE_PACKAGE_CONFIG_PATH "/etc/nodus.conf"
/* the address-record sequence file (deploy/install.sh ADDR_SEQ) */
#define NODUS_NODE_PACKAGE_ADDR_SEQ    "nodus.addr_seq"

/* Child deadlines of the adapter (milliseconds): a state query, and an
 * `enable --now` / `disable --now` (which waits for the unit to start or
 * stop). Past it the child is killed and reaped and the answer is
 * "unknown" -> refuse. */
#define NODUS_NODE_PACKAGE_QUERY_MS    10000
#define NODUS_NODE_PACKAGE_CHANGE_MS   180000

/* Size of the text buffers: the longest message is the "registered" refusal
 * with NODUS_DNAC_DUTIES_OWNERS_MAX (16) owner fingerprints of 128 hex
 * characters (about 2.4 KiB) plus its sentences. */
#define NODUS_NODE_PACKAGE_TEXT_MAX    4096

/* ── units, packages, actions ────────────────────────────────────── */

/* The four units, in this order; also the index into the state arrays. */
typedef enum {
    NODUS_NP_UNIT_NODUS   = 0,   /* nodus.service         (combined)   */
    NODUS_NP_UNIT_CORE    = 1,   /* nodus-core.service                 */
    NODUS_NP_UNIT_STORAGE = 2,   /* nodus-storage.service              */
    NODUS_NP_UNIT_WITNESS = 3,   /* nodus-witness.service              */
    NODUS_NP_UNIT_COUNT   = 4
} nodus_np_unit_t;

/** "nodus", "nodus-core", "nodus-storage", "nodus-witness"; NULL for an
 *  out-of-range value. */
const char *nodus_node_package_unit_name(nodus_np_unit_t unit);

/* What `systemctl is-enabled <unit>` said. ONLY the exact word "enabled"
 * is ON and only "disabled" is OFF; every other answer (masked, static,
 * linked, enabled-runtime, not-found, empty, a killed child, ...) is
 * UNKNOWN and makes add / remove refuse. */
typedef enum {
    NODUS_NP_UNKNOWN  = 0,
    NODUS_NP_ON       = 1,
    NODUS_NP_OFF      = 2
} nodus_np_state_t;

typedef struct {
    nodus_np_state_t enabled[NODUS_NP_UNIT_COUNT];
    /* `systemctl is-active` text of each unit ("" = could not be read);
     * shown by `list`. The verdict reads ONLY active[NODUS_NP_UNIT_NODUS]
     * (the combined unit must not be running, see NODUS_NP_R_COMBINED_
     * RUNNING). */
    char             active[NODUS_NP_UNIT_COUNT][24];
} nodus_np_units_t;

typedef enum {
    NODUS_NP_PKG_WITNESS = 0,
    NODUS_NP_PKG_STORAGE = 1
} nodus_np_pkg_t;

typedef enum {
    NODUS_NP_ACT_ADD    = 0,
    NODUS_NP_ACT_REMOVE = 1
} nodus_np_action_t;

/* The layout the four enabled states describe. */
typedef enum {
    NODUS_NP_LAYOUT_UNKNOWN   = 0,  /* a unit state could not be read    */
    NODUS_NP_LAYOUT_COMBINED  = 1,  /* nodus enabled, no split unit      */
    NODUS_NP_LAYOUT_SPLIT     = 2,  /* nodus-core enabled, nodus not     */
    NODUS_NP_LAYOUT_AMBIGUOUS = 3,  /* both layouts, or a split unit
                                     * without nodus-core                */
    NODUS_NP_LAYOUT_NONE      = 4   /* nothing enabled                   */
} nodus_np_layout_t;

nodus_np_layout_t nodus_node_package_layout(const nodus_np_units_t *u);

/* ── the pure verdict ────────────────────────────────────────────── */

typedef enum {
    NODUS_NP_OUT_DO      = 0,   /* change the unit                       */
    NODUS_NP_OUT_ALREADY = 1,   /* already in the wanted state: success,
                                 * nothing to change                     */
    NODUS_NP_OUT_REFUSE  = 2    /* nothing may be changed                */
} nodus_np_outcome_t;

typedef enum {
    NODUS_NP_R_NONE = 0,
    NODUS_NP_R_UNIT_UNKNOWN,        /* a unit state could not be read     */
    NODUS_NP_R_COMBINED,            /* nodus.service is the layout        */
    NODUS_NP_R_AMBIGUOUS,           /* both layouts / split without core  */
    NODUS_NP_R_NO_LAYOUT,           /* no layout enabled at all           */
    NODUS_NP_R_CORE_ALONE,          /* the removal would leave core alone */
    NODUS_NP_R_STORAGE_UNAVAILABLE, /* `remove storage`, this version     */
    NODUS_NP_R_NOT_READ,            /* the preflight was not read / failed*/
    NODUS_NP_R_UNKNOWN,             /* the witness said UNKNOWN (or an
                                     * inconsistent reply)                */
    NODUS_NP_R_NOT_FRESH,           /* the witness is not caught up       */
    NODUS_NP_R_REGISTERED,          /* registered: the owner must leave   */
    NODUS_NP_R_LEAVING,             /* leaving: wait for the graduation   */
    NODUS_NP_R_DUTIES,              /* left, but duties remain            */
    NODUS_NP_R_COMBINED_RUNNING     /* nodus.service is active, activating,
                                     * deactivating or reloading (or its
                                     * is-active word is not a known one):
                                     * a mixed state, not touched         */
} nodus_np_reason_t;

typedef struct {
    nodus_np_outcome_t outcome;
    nodus_np_reason_t  reason;
    /* the committed tip after which the node may be asked again: the
     * largest "end" over the blockers that have one; 0 = none */
    uint64_t           end_height;
    /* bit (1 << NODUS_DNAC_DUTY_*) of every blocker the reply carried */
    uint32_t           blocker_mask;
    /* owner fingerprints of the rows behind the blockers */
    size_t             n_owners;
    char               owners[NODUS_DNAC_DUTIES_OWNERS_MAX][129];
    /* the witness's "why" of an UNKNOWN reply; for COMBINED_RUNNING the
     * is-active word of nodus.service ("" = could not be read); ""
     * otherwise */
    char               why[NODUS_DNAC_DUTIES_WHY_MAX + 1];
} nodus_np_verdict_t;

/** `remove storage` is not available in this version (khan B). Checked by
 *  the CLI before the lock is taken, and again first in the verdict. */
bool nodus_node_package_unavailable(nodus_np_action_t action,
                                    nodus_np_pkg_t pkg);

/**
 * The decision, with no I/O.
 *
 * `duties` is the decoded dnac_node_duties reply, or NULL when it was not
 * read (then `read_error` says why; it is only copied into why[]). The
 * reply is consulted ONLY for `remove witness` of a witness that is ON.
 *
 * Rules, in this order:
 *   1. remove storage                  -> REFUSE STORAGE_UNAVAILABLE
 *   2. any of the four states UNKNOWN  -> REFUSE UNIT_UNKNOWN
 *   3. layout COMBINED / AMBIGUOUS / NONE -> REFUSE (COMBINED / AMBIGUOUS /
 *      NO_LAYOUT)
 *   3b. nodus.service active / activating / deactivating / reloading /
 *      refreshing, or its is-active word not one of the known words
 *      (those and inactive / failed) or unread
 *                                      -> REFUSE COMBINED_RUNNING (the rule
 *      of website/install-node.sh unit_busy: enabling a split unit
 *      Conflicts= with and would stop the running combined server)
 *   4. add of a package that is ON, remove of one that is OFF -> ALREADY
 *      (no reply is consulted)
 *   5. add of a package that is OFF    -> DO
 *   6. remove that would leave nodus-core as the only package ON
 *                                      -> REFUSE CORE_ALONE
 *   7. remove witness of a witness that is ON: DO ONLY when the reply was
 *      decoded AND state == CLEAR AND fresh AND it carries no blocker.
 *      Everything else refuses: not read -> NOT_READ; state UNKNOWN or an
 *      inconsistent reply -> UNKNOWN; !fresh -> NOT_FRESH; BLOCKED ->
 *      REGISTERED (a blocker with end 0: witness / storage registered),
 *      else LEAVING (a leaving row), else DUTIES.
 */
void nodus_node_package_verdict(const nodus_np_units_t *units,
                                nodus_np_action_t action, nodus_np_pkg_t pkg,
                                const nodus_dnac_node_duties_t *duties,
                                const char *read_error,
                                nodus_np_verdict_t *out);

/**
 * The plain-English text of a verdict (design §3.5), one or more lines
 * each ending in '\n'; "" for outcome DO. For ALREADY it is
 * "<pkg> is already on|off. Nothing was changed.".
 */
void nodus_node_package_verdict_text(const nodus_np_verdict_t *v,
                                     nodus_np_action_t action,
                                     nodus_np_pkg_t pkg,
                                     char *out, size_t cap);

/* ── the systemd adapter ─────────────────────────────────────────── */

typedef struct {
    /* absolute path of systemctl; the CLI always passes
     * NODUS_NODE_PACKAGE_SYSTEMCTL, the test points it at a fake script */
    const char *systemctl;
    int         query_ms;     /* deadline of is-enabled / is-active      */
    int         change_ms;    /* deadline of enable --now / disable --now */
} nodus_np_sysd_t;

/** The default adapter: the fixed path and the two deadlines above. */
void nodus_node_package_sysd_default(nodus_np_sysd_t *s);

/**
 * Read is-enabled and is-active of the four units into `out`. A unit
 * whose child did not run, was killed past its deadline, or answered
 * something other than the exact words is UNKNOWN (enabled) / "" (active).
 * @return 0 the adapter ran (the states may still be UNKNOWN); -1 the
 *         systemctl path is not a regular executable file (err says so).
 */
int nodus_node_package_read_units(const nodus_np_sysd_t *s,
                                  nodus_np_units_t *out,
                                  char *err, size_t errcap);

/**
 * `systemctl enable --now <unit>` (enable = true) or `disable --now`
 * (false), then `is-enabled` again: success only when the child exited 0
 * and the post-state is the wanted one ("enabled" / "disabled").
 * @return 0; -1 with the reason in err (the child was killed past its
 *         deadline, exited non-zero, or the post-state is not the wanted
 *         one). The unit may be half-changed on failure; err says to
 *         check `systemctl status`.
 */
int nodus_node_package_change(const nodus_np_sysd_t *s, nodus_np_unit_t unit,
                              bool enable, char *err, size_t errcap);

/* ── the host lock ───────────────────────────────────────────────── */

/**
 * Take the host lock at `path` (NODUS_NODE_PACKAGE_LOCK_PATH, in the
 * world-writable /run/lock, so the file itself is vetted): open the
 * existing file O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK (no O_CREAT; a
 * planted FIFO cannot block the open); when missing create it with
 * O_CREAT|O_EXCL mode 0600 (fchmod, so the umask does not matter);
 * then require a regular file owned by uid `owner` with no group/other
 * permission bit; flock(LOCK_EX|LOCK_NB). The lock lives as long as
 * *fd_out stays open.
 *
 * `owner` is the uid the file must belong to: the CLI passes 0 (root);
 * the unit test passes geteuid() so it can run as a normal user.
 *
 * @return 0 taken (*fd_out); 1 held by another process; -1 error (err);
 *         -2 the file is not acceptable (a symlink, not a regular file,
 *         not owned by `owner`, or any group/other bit set): err is the
 *         complete user message "<path> is not a root-owned 0600 regular
 *         file; remove it and retry. Nothing was changed." — never "busy".
 */
int nodus_node_package_lock_take(const char *path, uid_t owner, int *fd_out,
                                 char *err, size_t errcap);

/** Release (close) a lock taken above; a negative fd is ignored. */
void nodus_node_package_lock_release(int fd);

/* ── registration read and the addr_seq rule ─────────────────────── */

/**
 * Ask THIS node whether it may stop its witness: identity_path and
 * tcp_port from the config at `config_path`; the key is loaded ONLY with
 * nodus_identity_load_readonly; a session to 127.0.0.1:<tcp_port> that
 * authenticates with that key and is pinned to the same key's id (so the
 * answer can only come from this node); one nodus_client_dnac_node_duties
 * call; close; the key wiped. The session is bound to `chain_id` (32
 * bytes; DHT v2 package 3c — the caller takes it from the tool network
 * file / --chain), so it only completes with a node of that chain.
 * @return 0 the reply decoded (*out); -1 anything else, the reason in err
 *         (config, key, connection, pin, auth, timeout, decode, "witness
 *         module not enabled", an old node).
 */
int nodus_node_package_read_duties(const char *config_path,
                                   const uint8_t chain_id[NODUS_CLIENT_CHAIN_ID_SIZE],
                                   nodus_dnac_node_duties_t *out,
                                   char *err, size_t errcap);

/**
 * The item-21 rule of deploy/install.sh (669-684) for `add witness`:
 * identity_path == data_path or neither file -> nothing; both
 * <identity_path>/nodus.addr_seq and <data_path>/nodus.addr_seq present
 * -> refuse; only the identity one -> rename it into data_path.
 * @return 0 (nothing to do, or moved: *moved says which); -1 refuse /
 *         failure, the reason in err (nothing is moved on -1 except a
 *         failed rename, which moves nothing either).
 */
int nodus_node_package_addr_seq(const char *identity_path,
                                const char *data_path, bool *moved,
                                char *err, size_t errcap);

/* ── the command ─────────────────────────────────────────────────── */

/**
 * `package list | add <witness|storage> | remove <witness|storage>`.
 * `args` / `nargs` are the words AFTER "package" (so args[0] is the
 * subcommand). `sysd`, `lock_path`, `lock_owner` and `config_path` are the
 * test seams; the CLI passes the defaults (lock_owner 0 = root).
 * `chain_id` (32 bytes, or NULL) is the chain the registration read's
 * session is bound to; only `remove witness` of a running witness reads
 * the chain, and with NULL that read is refused ("no chain id") — the
 * other paths never need it.
 *
 * Writes everything the user must read into `out` (one or more lines,
 * each ending in '\n'); the CLI prints it to stdout on 0 and stderr on 1.
 * `out` should hold NODUS_NODE_PACKAGE_TEXT_MAX bytes: a refusal that does
 * not fit is replaced by a short fixed message ending "Nothing was
 * changed.".
 * @return 0 success or "already on/off", or `list`; 1 any refusal,
 *         failure or bad usage (nothing was changed unless `out` says a
 *         change was left half done).
 */
int nodus_node_package_main(const char *const *args, int nargs,
                            const nodus_np_sysd_t *sysd,
                            const char *lock_path, uid_t lock_owner,
                            const char *config_path,
                            const uint8_t *chain_id,
                            char *out, size_t outcap);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_NODE_PACKAGE_H */
