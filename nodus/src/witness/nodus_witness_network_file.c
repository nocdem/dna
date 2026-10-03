/**
 * Nodus — the published network file and the chain-pin start check
 *
 * P2P-PORT F6; moved verbatim out of nodus_server.c by the S1 witness
 * seam (decision 2026-10-01-nodus-component-split.md). See
 * nodus_witness_network_file.h.
 *
 * @file nodus_witness_network_file.c
 */

#include "witness/nodus_witness_network_file.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_gen.h"     /* stored chain id (P2P-PORT F6) */
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sqlite3.h>                        /* chain id reader (P2P-PORT F6) */
#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>                    /* the network file (P2P-PORT F6) */
#endif

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* The tag these lines carried in nodus_server.c, kept so the combined
 * binary's journal reads exactly as before the move. */
#define LOG_TAG "NODUS_SRV"

/* ── P2P-PORT F6 — chain id reader + the pin-at-start check ─────── */

int nodus_witness_read_chain_id(const char *db_path, uint8_t out[32]) {
    if (!db_path || !out) return -1;
    /* Heap, never stack: nodus_witness_t is multi-MB. Only `db` is used
     * by the stored-chain-id reader (nodus_witness_v2_gen.h). */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return -1;
    if (sqlite3_open_v2(db_path, &w->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return -1;
    }
    int rc = nodus_witness_v2_gen_stored_chain_id(w, out);
    sqlite3_close(w->db);
    free(w);
    return rc == 0 ? 0 : -1;
}

static void hex32_lower(const uint8_t b[32], char out[65]) {
    static const char hd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hd[b[i] >> 4];
        out[2 * i + 1] = hd[b[i] & 0x0F];
    }
    out[64] = '\0';
}

/* The witness scan's filename predicate, restated (nodus_witness.c
 * witness_chain_id_from_name is file-static): "witness_" + EXACTLY 32
 * LOWERCASE hex digits + ".db", nothing after (-wal / -shm rejected, an
 * upper-case alias rejected). The two MUST stay identical — a drift would
 * make the start check look at a different file than the one the node
 * runs. */
static bool chain_db_name_ok(const char *d_name) {
    if (strncmp(d_name, "witness_", 8) != 0) return false;
    const char *hex = d_name + 8;
    const char *dot = strstr(hex, ".db");
    if (!dot || dot[3] != '\0' || (size_t)(dot - hex) != 32) return false;
    for (size_t i = 0; i < 32; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

int nodus_witness_check_chain_pin(const char *data_path, const uint8_t pin[32]) {
    if (!data_path || !pin) return -1;
    DIR *dir = opendir(data_path);
    if (!dir) {
        /* An absent data directory holds no chain; any other failure is
         * "could not establish", which is not "no chain". */
        if (errno == ENOENT) return 0;
        QGP_LOG_ERROR(LOG_TAG, "network file pin: cannot read data "
                      "directory %s (%s) — refusing to start without "
                      "knowing whether it holds a chain", data_path,
                      strerror(errno));
        return -1;
    }
    /* The ONE file the witness will open: the lexicographically smallest
     * canonical name (nodus_witness_scan_chain_db, O15A deterministic
     * selection). Other files in the directory are never opened by the
     * node and are not judged here either. */
    char best[256];
    bool have = false;
    struct dirent *e;
    while ((e = readdir(dir)) != NULL) {
        if (!chain_db_name_ok(e->d_name)) continue;
        if (!have || strcmp(e->d_name, best) < 0) {
            snprintf(best, sizeof(best), "%s", e->d_name);
            have = true;
        }
    }
    closedir(dir);
    if (!have) return 0;                         /* no chain: a joiner */

    char want[65];
    hex32_lower(pin, want);
    char p[640];
    int n = snprintf(p, sizeof(p), "%s/%s", data_path, best);
    if (n < 0 || (size_t)n >= sizeof(p)) {
        QGP_LOG_ERROR(LOG_TAG, "network file pin: chain database path under "
                      "%s too long — refusing to start", data_path);
        return -1;
    }
    uint8_t id[32];
    if (nodus_witness_read_chain_id(p, id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "network file pin: %s holds no readable "
                      "version-3 chain id — cannot verify it against the "
                      "pin %s; refusing to start", p, want);
        return -1;
    }
    if (memcmp(id, pin, 32) != 0) {
        char have_hex[65];
        hex32_lower(id, have_hex);
        QGP_LOG_ERROR(LOG_TAG, "REFUSING START — the network file pins chain "
                      "%s but this node's database %s is chain %s. A wrong "
                      "database is caught here, locally, before it can talk "
                      "to the network. Fix the network file or the data "
                      "directory.", want, p, have_hex);
        return -1;
    }
    return 0;
}

#ifdef NODUS_HAS_JSONC
/* ── P2P-PORT F6 — the network file (nodus_witness_network_file.h) ── */

#define NF_KEY_PIN   "v2_genesis_pin"
#define NF_KEY_PEERS "persistent_peers"

static int nf_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* A pin value: "" → no pin (0, *has = false); 64 hex digits → the pin;
 * anything else → -1. */
static int nf_parse_pin(struct json_object *v, bool *has, uint8_t out[32]) {
    *has = false;
    if (!json_object_is_type(v, json_type_string)) return -1;
    const char *s = json_object_get_string(v);
    size_t n = (size_t)json_object_get_string_len(v);
    if (n == 0) return 0;
    if (n != 64 || strlen(s) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        int hi = nf_hexval(s[2 * i]), lo = nf_hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *has = true;
    return 0;
}

/* Validate a parsed root object into `out`. `path` is for messages. */
static int nf_validate(struct json_object *root, const char *path,
                       nodus_network_file_t *out) {
    memset(out, 0, sizeof(*out));
    if (!json_object_is_type(root, json_type_object)) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: not a JSON object", path);
        return -1;
    }
    json_object_object_foreach(root, key, val) {
        if (strcmp(key, NF_KEY_PIN) == 0) {
            if (nf_parse_pin(val, &out->has_pin, out->pin) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "network file %s: \"%s\" must be a "
                              "string of 64 hex digits or empty", path, key);
                return -1;
            }
        } else if (strcmp(key, NF_KEY_PEERS) == 0) {
            if (!json_object_is_type(val, json_type_array)) {
                QGP_LOG_ERROR(LOG_TAG, "network file %s: \"%s\" must be an "
                              "array of \"id@ip:port\" strings", path, key);
                return -1;
            }
            size_t n = json_object_array_length(val);
            if (n > NODUS_P2P_MAX_PEER_LIST) {
                QGP_LOG_ERROR(LOG_TAG, "network file %s: %zu persistent "
                              "peers, at most %d", path, n,
                              NODUS_P2P_MAX_PEER_LIST);
                return -1;
            }
            for (size_t i = 0; i < n; i++) {
                struct json_object *it = json_object_array_get_idx(val, i);
                if (!json_object_is_type(it, json_type_string)) {
                    QGP_LOG_ERROR(LOG_TAG, "network file %s: peer %zu is "
                                  "not a string", path, i);
                    return -1;
                }
                const char *s = json_object_get_string(it);
                size_t sl = (size_t)json_object_get_string_len(it);
                cmt_p2p_netaddr_t na;
                if (sl == 0 || sl >= CMT_P2P_NETADDR_STR_MAX ||
                    strlen(s) != sl ||
                    cmt_p2p_netaddr_new_string(s, sl, &na) !=
                        CMT_P2P_ERR_NONE) {
                    /* NO_ID included: the 4004 layer never dials an
                     * unpinned address (R-P2P-33); a non-IP host is
                     * ErrNetAddressLookup (R-P2P-24). */
                    QGP_LOG_ERROR(LOG_TAG, "network file %s: peer \"%s\" is "
                                  "not id@ip:port with a valid ID and an IP "
                                  "literal", path, s);
                    return -1;
                }
                for (int j = 0; j < out->n_peers; j++) {
                    if (strcmp(out->peers[j], s) == 0) {
                        QGP_LOG_ERROR(LOG_TAG, "network file %s: peer "
                                      "\"%s\" listed twice", path, s);
                        return -1;
                    }
                }
                memcpy(out->peers[out->n_peers], s, sl + 1);
                out->n_peers++;
            }
        } else {
            /* A typo'd pin key would otherwise read as "no pin" and
             * silently change what the node does. */
            QGP_LOG_ERROR(LOG_TAG, "network file %s: unknown key \"%s\" "
                          "(allowed: \"%s\", \"%s\")", path, key,
                          NF_KEY_PIN, NF_KEY_PEERS);
            return -1;
        }
    }
    return 0;
}

int nodus_network_file_load(const char *path, nodus_network_file_t *out) {
    if (!path || !out) return -1;
    memset(out, 0, sizeof(*out));
    struct json_object *root = json_object_from_file(path);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: missing, unreadable or not "
                      "JSON (%s)", path, json_util_get_last_err()
                      ? json_util_get_last_err() : "?");
        return -1;
    }
    int rc = nf_validate(root, path, out);
    json_object_put(root);
    if (rc != 0) memset(out, 0, sizeof(*out));
    return rc;
}

int nodus_network_file_apply(const nodus_network_file_t *nf,
                             const nodus_network_file_target_t *t) {
    if (!nf || !t || !t->p2p || !t->has_v2_genesis_pin ||
        !t->v2_genesis_pin || !t->has_network_pin || !t->network_pin)
        return -1;
    if (nf->has_pin) {
        if (*t->has_v2_genesis_pin &&
            memcmp(t->v2_genesis_pin, nf->pin, 32) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "--v2-genesis-pin and the network file's "
                          "pin differ — two different chains named; "
                          "refusing");
            return -1;
        }
        memcpy(t->v2_genesis_pin, nf->pin, 32);
        *t->has_v2_genesis_pin = true;
        memcpy(t->network_pin, nf->pin, 32);
        *t->has_network_pin = true;
    }
    for (int i = 0; i < nf->n_peers; i++) {
        bool dup = false;
        for (int j = 0; j < t->p2p->n_persistent_peers; j++) {
            if (strcmp(t->p2p->persistent_peers[j], nf->peers[i]) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (nodus_p2p_config_add_persistent(t->p2p, nf->peers[i]) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "network file peer \"%s\": the persistent "
                          "peer list is full (%d)", nf->peers[i],
                          NODUS_P2P_MAX_PEER_LIST);
            return -1;
        }
    }
    return 0;
}

int nodus_network_file_write_pin(const char *path, const uint8_t chain32[32]) {
    if (!path || !chain32) return -1;
    struct json_object *root = json_object_from_file(path);
    if (!root) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: missing, unreadable or not "
                      "JSON — the pin was NOT written", path);
        return -1;
    }
    nodus_network_file_t nf;
    int rc = -1;
    char hex[65];
    char tmp[600];
    int fd = -1;
    tmp[0] = '\0';
    hex32_lower(chain32, hex);

    /* Never write into a file the loader would refuse. */
    if (nf_validate(root, path, &nf) != 0) goto out;
    if (nf.has_pin) {
        if (memcmp(nf.pin, chain32, 32) == 0) { rc = 1; goto out; }
        char have[65];
        hex32_lower(nf.pin, have);
        QGP_LOG_ERROR(LOG_TAG, "network file %s already pins chain %s, this "
                      "ceremony derived %s — NOT overwritten; the ceremony "
                      "stops here", path, have, hex);
        goto out;
    }

    /* Replaces an existing "" in place (json-c keeps the key's position)
     * or appends the key; every other key is untouched. */
    if (json_object_object_add(root, NF_KEY_PIN,
                               json_object_new_string(hex)) != 0)
        goto out;
    const char *text = json_object_to_json_string_ext(
        root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!text) goto out;
    size_t tlen = strlen(text);

    struct stat st;
    mode_t mode = 0644;
    if (stat(path, &st) == 0) mode = st.st_mode & 0777;

    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp)) { tmp[0] = '\0'; goto out; }
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "network file %s: cannot create %s (%s)",
                      path, tmp, strerror(errno));
        tmp[0] = '\0';
        goto out;
    }
    size_t off = 0;
    while (off < tlen) {
        ssize_t w = write(fd, text + off, tlen - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            goto io_fail;
        }
        off += (size_t)w;
    }
    if (write(fd, "\n", 1) != 1) goto io_fail;
    if (fsync(fd) != 0) goto io_fail;
    if (close(fd) != 0) { fd = -1; goto io_fail; }
    fd = -1;
    if (rename(tmp, path) != 0) goto io_fail;
    tmp[0] = '\0';                              /* now the real file */
    {
        /* make the rename itself durable */
        char dir[600];
        snprintf(dir, sizeof(dir), "%s", path);
        char *slash = strrchr(dir, '/');
        if (slash == dir) dir[1] = '\0';
        else if (slash) *slash = '\0';
        else snprintf(dir, sizeof(dir), ".");
        int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) {
            if (fsync(dfd) != 0)
                QGP_LOG_WARN(LOG_TAG, "network file: directory fsync of %s "
                             "failed (%s)", dir, strerror(errno));
            close(dfd);
        }
    }
    rc = 0;
    goto out;

io_fail:
    QGP_LOG_ERROR(LOG_TAG, "network file %s: writing the pin failed (%s) — "
                  "the file is unchanged", path, strerror(errno));
out:
    if (fd >= 0) close(fd);
    if (tmp[0]) unlink(tmp);
    json_object_put(root);
    return rc;
}
#endif /* NODUS_HAS_JSONC */
