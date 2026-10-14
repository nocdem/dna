/**
 * @file nodus/src/client/nodus_node_status.h
 * @brief The local, network-free half of `nodus-cli status`: the node
 *        config fields the status screen shows, the network file's peer
 *        hosts, /proc parsing, the chain database and segment directory
 *        sizes, the disk, and one fixed-argv command runner.
 *
 * `sudo nodus-cli status` (nodus/tools/nodus-cli.c cmd_status) prints the
 * node's whole state on the node itself. Everything that talks to a node
 * over RPC stays in nodus-cli.c (it reuses the existing client calls);
 * everything here takes a path, so the unit test (tests/test_node_status.c)
 * runs it on fixture files and temp directories. READ-ONLY: nothing here
 * writes, creates or removes a file, and nothing here is a consensus
 * input — it reports this machine.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_NODE_STATUS_H
#define NODUS_NODE_STATUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bound on the node config file nodus_node_status_read_config reads (the
 * same bound as nodus_consent_req_read_config). */
#define NODUS_NODE_STATUS_CONFIG_MAX (1024u * 1024u)

/* data_path when the config has none — the node's own default
 * (tools/nodus_node_config.c, nodus_node_config_parse: "/var/lib/nodus"). */
#define NODUS_NODE_STATUS_DATA_PATH_DEFAULT "/var/lib/nodus"

/* The judgements the status screen makes (plain, local thresholds of the
 * screen, never consensus inputs):
 *   - in sync: this node's tip at most this many blocks below the highest
 *     tip the asked witnesses report;
 *   - disk: WARN below this many free bytes on the data_path file system. */
#define NODUS_NODE_STATUS_BEHIND_OK      2u
#define NODUS_NODE_STATUS_DISK_WARN_BYTES (20ull * 1024ull * 1024ull * 1024ull)

/* The fields of the node config (/etc/nodus.conf) the status screen shows,
 * read with the node's own key names (tools/nodus_node_config.c). A key
 * that is absent leaves the node's default and its has_* flag false. */
typedef struct {
    char     data_path[512];      /* "data_path"; default above          */
    bool     has_data_path;
    char     network_file[512];   /* "network_file"; "" when absent       */
    char     external_ip[64];     /* "external_ip"; "" when absent        */
    char     segment_dir[64];     /* "segment_dir"; default "segments"
                                   * (witness/nodus_witness.h
                                   * NODUS_SEG_DIR_DEFAULT)               */
    bool     has_retain_blocks;   /* "retain_blocks" present              */
    int64_t  retain_blocks;       /* its value when present               */
    uint16_t udp_port;            /* "udp_port";     default 4000         */
    uint16_t tcp_port;            /* "tcp_port";     default 4001         */
    uint16_t peer_port;           /* "peer_port";    default 4002         */
    uint16_t witness_port;        /* "witness_port"; default 4004         */
} nodus_node_status_config_t;

/**
 * Read the node config at `path` (at most NODUS_NODE_STATUS_CONFIG_MAX
 * bytes, one JSON object). Absent keys keep the defaults above; a key of
 * the wrong type, a port outside 1..65535, a negative retain_blocks or a
 * string that does not fit is refused — the node itself refuses to start
 * on the same values.
 *
 * Without json-c in the build this always returns -1.
 *
 * @return 0; -1 with a message in err (the file cannot be opened or read,
 *         is not a JSON object, or holds a refused value).
 */
int nodus_node_status_read_config(const char *path,
                                  nodus_node_status_config_t *out,
                                  char *err, size_t errcap);

/**
 * The host of one network-file peer entry "id@ip:port" (the form
 * nodus_network_file_load validates): the text between the '@' and the
 * LAST ':'; an IPv6 literal in brackets is returned without them.
 * @return 0; -1 (no '@', no ':' after it, an empty host, or it does not
 *         fit cap).
 */
int nodus_node_status_peer_host(const char *peer, char *host, size_t cap);

/**
 * The first line of a small text file (trailing "\r\n" removed), e.g.
 * /var/lib/nodus/install-commit. @return 0; -1 (cannot open / read, an
 * empty first line, or it does not fit cap).
 */
int nodus_node_status_first_line(const char *path, char *out, size_t cap);

/** /proc/loadavg: the three load averages. @return 0 / -1. */
int nodus_node_status_loadavg(const char *path, double out[3]);

/** /proc/meminfo: MemTotal and MemAvailable in kB. @return 0 / -1 (either
 *  line missing). */
int nodus_node_status_meminfo(const char *path, uint64_t *total_kb,
                              uint64_t *avail_kb);

/**
 * The resident set of the process whose /proc/<pid>/comm is `comm`
 * (proc_root is "/proc", or a fixture directory with the same layout:
 * <pid>/comm and <pid>/status with a "VmRSS: <n> kB" line). When more
 * than one process has that name, the lowest pid is taken.
 * @return 0 found (*rss_kb, *pid); 1 no such process; -1 proc_root cannot
 *         be read.
 */
int nodus_node_status_proc_rss(const char *proc_root, const char *comm,
                               uint64_t *rss_kb, int *pid);

/**
 * The segment directory: the number of complete segments — names
 * "seg-<k>.ok", k decimal (witness/nodus_witness_storage_segment.h: a
 * segment is HELD iff its .ok marker exists) — and the total size of the
 * regular files in it. @return 0; 1 the directory does not exist; -1 it
 * cannot be read.
 */
int nodus_node_status_segments(const char *dir, uint64_t *n_ok,
                               uint64_t *total_bytes);

/**
 * The chain database under data_path: the file the witness opens — the
 * lexicographically smallest "witness_<32 lowercase hex>.db" (the
 * predicate of witness/nodus_witness_network_file.c chain_db_name_ok,
 * restated: it is file-static there) — its name, and its size plus the
 * sizes of its "-wal" and "-shm" files when present.
 * @return 0 found; 1 none (a node that has not joined a chain yet); -1
 *         data_path cannot be read.
 */
int nodus_node_status_chain_db(const char *data_path, char *name, size_t cap,
                               uint64_t *total_bytes);

/** statvfs of `path`: bytes available to an unprivileged user, and the
 *  file system's size. @return 0 / -1. */
int nodus_node_status_disk(const char *path, uint64_t *avail_bytes,
                           uint64_t *total_bytes);

/**
 * Run a FIXED argv (argv[0] looked up on PATH, no shell), its stdout's
 * first line into `out` (trailing "\r\n" removed; "" when it printed
 * nothing), stderr to /dev/null, stdin from /dev/null.
 * @return 0 it ran (*exit_code: its exit status, or -1 when it did not
 *         exit normally); -1 it could not be started.
 */
int nodus_node_status_run(const char *const argv[], char *out, size_t cap,
                          int *exit_code);

/** "yes" → 1, "no" → 0, anything else → -1 (timedatectl's
 *  `show -p NTPSynchronized --value`). */
int nodus_node_status_yes_no(const char *s);

/** 1 when `local` is at most NODUS_NODE_STATUS_BEHIND_OK blocks below
 *  `network` (a local tip at or above it is in sync), else 0. */
int nodus_node_status_in_sync(uint64_t local, uint64_t network);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_NODE_STATUS_H */
