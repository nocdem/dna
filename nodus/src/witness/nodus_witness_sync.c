/**
 * Nodus — Witness State Sync Implementation
 *
 * Block-by-block catch-up from peers with fork detection.
 */

#include "witness/nodus_witness_sync.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_peer.h"
#include "protocol/nodus_tier3.h"
#include "transport/nodus_tcp.h"
#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"
#include "nodus/nodus_chain_config.h"  /* derive_witness_id (Faz 4D halt_recovery_check) */
#include "dnac/transaction.h"   /* DNAC_TX_HEADER_SIZE (v0.17.1) */
#include "dnac/ledger_ids.h"    /* S3: dna_bft_quorum over the pinned halt set */
#include "witness/nodus_witness_vset.h"      /* S3: historical-quorum source (1) */
#include "witness/nodus_witness_committee.h" /* S3: historical-quorum source (2) */
#include "witness/nodus_witness_v2_result.h" /* O15G typed cert-verify results  */
#include "witness/nodus_witness_genesis_seed.h" /* S3: genesis quorum source (3) */

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#include "crypto/utils/qgp_log.h"           /* QGP_LOG_* (new code; legacy lines use fprintf) */
#include "crypto/hash/qgp_sha3.h"           /* O15G: qgp_sha3_512 — the EXACT function
                                             * bootstrap.c:928 hashed g_quorum_cdh with */

#define LOG_TAG "WITNESS-SYNC"

/* Rate limiting */
#define SYNC_MIN_INTERVAL_SEC   30

/* How long a sync may make NO progress before the `syncing` latch is
 * force-released.
 *
 * O15J Faz 3 — `sync_state.syncing` is a one-way latch: it is set when a
 * block request goes out, and every clear lives on a RESPONSE path. A
 * response that never arrives — the peer died mid-sync, the frame was
 * dropped, the peer serves nothing — therefore wedges the node OUT OF
 * SYNC PERMANENTLY, with no error and no recovery. `sync_check` returns
 * at the "already syncing" guard on every subsequent tick, forever.
 *
 * The bootstrap instance of this (a sync started before the chain DB
 * existed) is fixed at its source, but the latch is reachable from any
 * lost response, so the general case needs a watchdog too.
 *
 * 60 s is two rate-limit intervals: comfortably longer than any healthy
 * request/response round trip on this network (the stamp is refreshed on
 * EVERY request, so a catch-up of a thousand blocks keeps resetting it
 * and is never interrupted), and short enough that a node recovers on
 * its own within a block or two rather than needing a restart.
 *
 * This is a LIVENESS timer on a recovery path, not a consensus branch:
 * releasing the latch only permits a re-request of blocks the node
 * already lacks. It cannot change what the node accepts, what it votes,
 * or any committed value, so it introduces no timing-dependent state
 * transition. */
#define SYNC_STALL_TIMEOUT_SEC  60
#define SYNC_MAX_BLOCKS         1000

/* O15G HIGH-1 — per-peer invalid-cert cooldown window. A peer that served a
 * CONSENSUS_INVALID sync response is skipped by peer selection for this many
 * seconds (~2 sync intervals), then re-admitted. Bounded + self-healing: it
 * routes AROUND a Byzantine height-inflating peer without permanently
 * blacklisting a transiently-behind honest peer. LOCAL liveness only. */
#define SYNC_BAD_PEER_COOLDOWN_SEC  60

/* ── Helper: send w_sync_req to a peer ──────────────────────────── */

static int send_sync_req(nodus_witness_t *w, struct nodus_tcp_conn *conn,
                          uint64_t height) {
    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = NODUS_T3_SYNC_REQ;
    msg.txn_id = ++w->next_txn_id;

    msg.sync_req.height = height;

    /* Fill header */
    msg.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(msg.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    msg.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&msg.header.nonce, sizeof(msg.header.nonce));
    memcpy(msg.header.chain_id, w->chain_id, 32);

    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(&msg, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "%s: failed to encode w_sync_req\n", LOG_TAG);
        return -1;
    }

    return nodus_tcp_send((nodus_tcp_conn_t *)conn, buf, len);
}

/* ── Helper: compute expected prev_hash from a block ────────────── */

static void compute_prev_hash(nodus_witness_t *w,
                                const nodus_witness_block_t *blk,
                                uint8_t *prev_hash_out) {
    /* Load chain_def_blob for genesis blocks so prev_hash of block 1
     * matches the anchored genesis block hash. */
    const uint8_t *cd_blob = NULL;
    size_t cd_len = 0;
    uint8_t *cd_alloc = NULL;
    if (blk->height == 0 && w && w->db) {
        sqlite3_stmt *cdst;
        if (sqlite3_prepare_v2(w->db,
                "SELECT chain_def_blob FROM blocks WHERE height = 0",
                -1, &cdst, NULL) == SQLITE_OK) {
            if (sqlite3_step(cdst) == SQLITE_ROW) {
                const void *blob = sqlite3_column_blob(cdst, 0);
                int blen = sqlite3_column_bytes(cdst, 0);
                if (blob && blen > 0) {
                    cd_alloc = malloc((size_t)blen);
                    if (cd_alloc) {
                        memcpy(cd_alloc, blob, (size_t)blen);
                        cd_blob = cd_alloc;
                        cd_len = (size_t)blen;
                    }
                }
            }
            sqlite3_finalize(cdst);
        }
    }
    nodus_witness_compute_block_hash_ex(blk->height,
                                          blk->prev_hash,
                                          blk->state_root,
                                          blk->tx_root,
                                          blk->tx_count,
                                          blk->proposer_id,
                                          cd_blob, cd_len,
                                          prev_hash_out);
    free(cd_alloc);
}

/* ── Recovery sentinel — audit B-2 fix ───────────────────────────────
 *
 * Persisted at <data_path>/.recovery_in_progress when drop_witness_db
 * is invoked from a halt-recovery path. Cleared after the first
 * successful sync block replay. On boot (nodus_witness_init), presence
 * rejects startup unless an operator manually clears the file —
 * forensic gate against the F17-class bug where a process crash
 * between drop_witness_db and safety_halt = false would leave the node
 * with empty DB + cleared halt latch on restart.
 *
 * Format: 40 bytes binary
 *   [0..31]  chain_id  (32 bytes)
 *   [32..39] halt_height (uint64 little-endian)
 */

#define RECOVERY_SENTINEL_NAME ".recovery_in_progress"
#define RECOVERY_SENTINEL_LEN  40

static void recovery_sentinel_path(const char *data_path,
                                     char *out, size_t out_len) {
    snprintf(out, out_len, "%s/" RECOVERY_SENTINEL_NAME, data_path);
}

int nodus_witness_recovery_sentinel_create(nodus_witness_t *w,
                                             uint64_t halt_height) {
    if (!w || w->data_path[0] == '\0') return -1;
    char path[512];
    recovery_sentinel_path(w->data_path, path, sizeof(path));

    uint8_t buf[RECOVERY_SENTINEL_LEN];
    memcpy(buf, w->chain_id, 32);
    for (int i = 0; i < 8; i++)
        buf[32 + i] = (uint8_t)((halt_height >> (i * 8)) & 0xFF);

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "%s: sentinel create failed at %s: %s\n",
                LOG_TAG, path, strerror(errno));
        return -1;
    }
    size_t written = fwrite(buf, 1, RECOVERY_SENTINEL_LEN, fp);
    int flush_rc = fflush(fp);
    int sync_rc = 0;
#ifdef __linux__
    /* fsync for crash safety — sentinel must hit disk before drop runs.
     * If fsync fails we still close + report; the drop will likely also
     * fail in that case but at minimum the partial write is on disk. */
    sync_rc = fsync(fileno(fp));
#endif
    fclose(fp);
    if (written != RECOVERY_SENTINEL_LEN || flush_rc != 0 || sync_rc != 0) {
        fprintf(stderr, "%s: sentinel write incomplete at %s\n",
                LOG_TAG, path);
        return -1;
    }
    fprintf(stderr, "%s: recovery sentinel armed at %s (halt_height=%llu)\n",
            LOG_TAG, path, (unsigned long long)halt_height);
    return 0;
}

int nodus_witness_recovery_sentinel_clear(nodus_witness_t *w) {
    if (!w || w->data_path[0] == '\0') return -1;
    char path[512];
    recovery_sentinel_path(w->data_path, path, sizeof(path));
    if (unlink(path) != 0) {
        if (errno == ENOENT) return 0;  /* already clean */
        fprintf(stderr, "%s: sentinel clear failed at %s: %s\n",
                LOG_TAG, path, strerror(errno));
        return -1;
    }
    fprintf(stderr, "%s: recovery sentinel cleared at %s\n", LOG_TAG, path);
    return 0;
}

/* Returns 0 if absent (clean boot), 1 if present (admin clear required),
 * -1 on read error. Reads halt_height into *out_halt_height when present. */
int nodus_witness_recovery_sentinel_check(const char *data_path,
                                            uint64_t *out_halt_height) {
    char path[512];
    recovery_sentinel_path(data_path, path, sizeof(path));
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "%s: sentinel check open failed at %s: %s\n",
                LOG_TAG, path, strerror(errno));
        return -1;
    }
    uint8_t buf[RECOVERY_SENTINEL_LEN];
    size_t got = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (got != RECOVERY_SENTINEL_LEN) {
        fprintf(stderr, "%s: sentinel truncated at %s (got %zu, need %d)\n",
                LOG_TAG, path, got, RECOVERY_SENTINEL_LEN);
        return -1;
    }
    if (out_halt_height) {
        uint64_t h = 0;
        for (int i = 0; i < 8; i++)
            h |= ((uint64_t)buf[32 + i]) << (i * 8);
        *out_halt_height = h;
    }
    return 1;
}

/* ── Helper: drop witness DB for fork rebuild ───────────────────── */

static int drop_witness_db(nodus_witness_t *w) {
    if (!w->db) return 0;  /* Already in pre-genesis state */

    /* Build DB file path from chain_id */
    char hex[33];
    for (int i = 0; i < 16; i++)
        snprintf(hex + i * 2, 3, "%02x", w->chain_id[i]);

    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/witness_%s.db",
             w->data_path, hex);

    /* Close DB */
    sqlite3_close(w->db);
    w->db = NULL;

    /* Delete file */
    if (unlink(db_path) != 0) {
        fprintf(stderr, "%s: failed to delete %s: %s\n",
                LOG_TAG, db_path, strerror(errno));
        return -1;
    }

    /* Clear chain_id.
     *
     * ── O15L Faz 4 / F-6 — THE V2 IDENTITY GOES WITH IT ─────────────────
     *
     * `v2_successor` and `v2_chain32` are derived from COMMITTED state at
     * every database open (nodus_witness.c, witness_post_open_gate: false
     * at the top, true only once the height-0 successor genesis manifest
     * has been read). The database that carried that state has just been
     * closed and unlinked, so both are now claims about a chain this node
     * no longer has.
     *
     * Leaving them behind produced the triple
     * (chain_id == 0, db == NULL, v2_successor == true): the O15L DG-1
     * matrix reads that as row 3, "genuine pre-genesis, exempt", while
     * every bare `if (w->v2_successor)` branch still steers the successor
     * lane at a NULL handle. One node, two irreconcilable answers about
     * which chain it is on — and after the F-9 loader change above, the
     * committee lookup would call it pre-genesis (chain_id zero) while
     * the V2 lanes called it a successor.
     *
     * They are cleared HERE, beside chain_id, and deliberately NOT on the
     * unlink-failure return above: that path leaves the node in DG-1
     * row 2 (identity retained, handle gone), which F-9 makes inert at
     * every committee gate — the correct state for a drop that did not
     * complete. Nothing is lost by clearing: a re-bootstrap re-derives
     * both from the new database's committed state.
     *
     * Verified: on a live witness the only writer that sets
     * v2_successor false is witness_post_open_gate; the two other
     * assignments in the tree operate on temporary structs
     * (nodus_witness_v2_join.c, nodus_witness_v2_gen.c). */
    memset(w->chain_id, 0, 32);
    w->v2_successor = false;
    memset(w->v2_chain32, 0, sizeof(w->v2_chain32));
    w->cached_state_root_valid = false;

    fprintf(stderr, "%s: dropped witness DB %s for fork rebuild "
            "(chain_id, v2_successor and v2_chain32 cleared)\n",
            LOG_TAG, db_path);
    return 0;
}

/* ── Halt recovery — Hybrid model (Faz 4D, audit B-3/C-4/M-3) ───────
 *
 * After finalize_block latches safety_halt and snapshots
 * halt_committee_pubkeys at halt_block_height, this checker runs on
 * each periodic tick. Hybrid policy:
 *   - default OFF (config.halt_auto_recover = false): never auto-drop;
 *     operator must clear sentinel + restart.
 *   - opt-in ON: 60s cooldown gate; bypassed if disagree-quorum is
 *     immediately clear (M-3 expedite).
 *
 * Disagree counts ONLY peers whose pubkey hashes to a witness_id in
 * the halt_committee snapshot — phantom committee members spawned
 * during halt window cannot inflate the vote (B-3).
 *
 * On qualified drop: arm sentinel BEFORE drop_witness_db (B-2 crash
 * safety). Sentinel cleared by sync_handle_rsp on first replayed
 * block (Faz 4D follow-up).
 */

#define HALT_COOLDOWN_SEC 60

void nodus_witness_halt_recovery_check(nodus_witness_t *w) {
    if (!w || !w->safety_halt) return;
    if (!w->config.halt_auto_recover) return;          /* B-3 default off */
    if (w->halt_committee_count == 0) return;          /* snapshot failed */

    uint64_t now = (uint64_t)time(NULL);
    uint64_t cooldown_remaining = 0;
    if (w->halt_timestamp > 0 && now > w->halt_timestamp) {
        uint64_t elapsed = now - w->halt_timestamp;
        cooldown_remaining = (elapsed >= HALT_COOLDOWN_SEC) ? 0
                                : HALT_COOLDOWN_SEC - elapsed;
    } else if (w->halt_timestamp >= now) {
        cooldown_remaining = HALT_COOLDOWN_SEC;
    }

    /* Compute peer disagreement against halt-time committee snapshot. */
    uint8_t local_cksum[NODUS_KEY_BYTES];
    if (w->cached_state_root_valid) {
        memcpy(local_cksum, w->cached_state_root, NODUS_KEY_BYTES);
    } else if (nodus_witness_merkle_compute_state_root(w, local_cksum) != 0) {
        return;  /* can't compute — wait for next tick */
    }
    static const uint8_t zero_cksum[NODUS_KEY_BYTES] = {0};

    /* Pre-derive witness_ids for halt_committee pubkeys (one SHA3-512
     * each). S3: bound by the snapshot array's real capacity
     * (DNAC_MAX_ACTIVE_VALIDATORS = 128 × 32 B = 4 KB — stack is fine),
     * not by DNAC_COMMITTEE_SIZE, which would silently ignore every
     * member past the 7th of a larger halt-time set and make the quorum
     * below uncountable. */
    uint8_t hist_wids[DNAC_MAX_ACTIVE_VALIDATORS][NODUS_T3_WITNESS_ID_LEN];
    int hist_n = w->halt_committee_count;
    if (hist_n > DNAC_MAX_ACTIVE_VALIDATORS)
        hist_n = DNAC_MAX_ACTIVE_VALIDATORS;
    for (int i = 0; i < hist_n; i++) {
        if (nodus_chain_config_derive_witness_id(w->halt_committee_pubkeys[i],
                                                   hist_wids[i]) != 0) {
            /* Snapshot corruption → bail to inconclusive. */
            return;
        }
    }

    int agree = 0, disagree = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].identified) continue;
        if (memcmp(w->peers[i].remote_checksum, zero_cksum,
                   NODUS_KEY_BYTES) == 0) continue;

        bool in_hist = false;
        for (int j = 0; j < hist_n; j++) {
            if (memcmp(w->peers[i].witness_id, hist_wids[j],
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                in_hist = true;
                break;
            }
        }
        if (!in_hist) continue;  /* phantom or non-committee → ignore */

        if (memcmp(w->peers[i].remote_checksum, local_cksum,
                   NODUS_KEY_BYTES) == 0) {
            agree++;
        } else {
            disagree++;
        }
    }

    /* S3 — the quorum must come from the PINNED snapshot's size, not from
     * the live w->bft_config.
     *
     * Both `agree` and `disagree` above are counted ONLY over peers whose
     * witness_id is in hist_wids, i.e. over the halt-time committee. Using
     * the current bft_config.quorum against that historical membership is
     * exactly the current-set substitution S3 forbids: after the halt the
     * active set may have been resized by governance
     * (DNAC_CFG_TARGET_ACTIVE_COUNT) or reshaped by boundary flips, and a
     * SMALLER current set would lower the bar for auto-dropping this
     * node's DB on the say-so of the halt-time peers — the destructive
     * direction. dna_bft_quorum is the same (2n)/3+1 formula
     * nodus_witness_bft_config_init uses (shared/dnac/ledger_ids.h:102).
     *
     * hist_n > 0 is guaranteed: halt_committee_count == 0 returned early
     * at the top of this function as "inconclusive". */
    int quorum = (int)dna_bft_quorum((uint32_t)hist_n);
    bool clear_quorum = (quorum > 0 && disagree >= quorum && disagree > agree);

    /* M-3 expedite: clear quorum bypasses cooldown. */
    if (cooldown_remaining > 0 && !clear_quorum) {
        return;
    }

    if (!clear_quorum) {
        /* Cooldown elapsed but no quorum — admin will need to act. */
        return;
    }

    fprintf(stderr,
        "%s: halt_recovery: historical-committee quorum reached "
        "(disagree=%d agree=%d quorum=%d) at halt_height=%llu — "
        "arming sentinel and dropping DB\n",
        LOG_TAG, disagree, agree, quorum,
        (unsigned long long)w->halt_block_height);

    if (nodus_witness_recovery_sentinel_create(w, w->halt_block_height) != 0) {
        fprintf(stderr, "%s: halt_recovery: sentinel arm failed — refusing drop\n",
                LOG_TAG);
        return;
    }
    if (drop_witness_db(w) != 0) {
        fprintf(stderr, "%s: halt_recovery: drop failed — sentinel persists, "
                "manual intervention required\n", LOG_TAG);
        return;
    }

    /* Clear halt state — sentinel persists until first replayed block. */
    w->safety_halt = false;
    w->halt_block_height = 0;
    w->halt_timestamp = 0;
    w->halt_committee_count = 0;
    fprintf(stderr, "%s: halt_recovery: halt cleared, sync will re-fetch chain\n",
            LOG_TAG);
}

/* ── Find best sync peer ────────────────────────────────────────── */

/* O15G HIGH-1 — un-static'd (declared in nodus_witness.h under
 * NODUS_WITNESS_INTERNAL_API) so the cooldown behaviour is unit-testable.
 * SKIPS a peer whose invalid-cert cooldown is unexpired, so a Byzantine
 * height-inflating peer that served an invalid cert is not re-selected while an
 * honest peer (ANY index, including a lower one) is reachable. */
int nodus_witness_sync_find_peer(nodus_witness_t *w) {
    uint64_t local_height = nodus_witness_block_height(w);
    uint64_t now = (uint64_t)time(NULL);
    int best = -1;
    uint64_t best_height = local_height;

    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].identified || !w->peers[i].conn) continue;
        if (w->peers[i].conn->state != NODUS_CONN_CONNECTED) continue;
        if (w->peers[i].sync_bad_until > now) continue;   /* invalid-cert cooldown */
        if (w->peers[i].remote_height > best_height) {
            best_height = w->peers[i].remote_height;
            best = i;
        }
    }
    return best;
}

/* ── O15G — rotate to a DIFFERENT authenticated peer ────────────────────
 *
 * When a peer serves a response whose certs are INVALID against the committed
 * committee, one bad peer must not abandon all catch-up. Scan FORWARD ONLY
 * (no wrap) for another reachable peer (identified + live conn) that holds the
 * height we are stuck on, strictly after the current sync peer index. This is a
 * pure transport-availability scan — the peer count is NEVER an input to any
 * quorum computation.
 *
 * The forward-only bound is load-bearing: each INVALID-cert rotation moves to a
 * strictly higher index, so the rotation chain is bounded by peer_count and
 * always terminates in syncing=false. The next nodus_witness_sync_check tick —
 * rate-limited by SYNC_MIN_INTERVAL_SEC — then restarts from find_sync_peer's
 * highest peer. A wrapping ring scan would instead be an unbounded, network-
 * paced retry loop (A→B→A→B) that masks the underlying failure, which this
 * codebase forbids. Returns the new peer index, or -1 if no higher peer serves.
 *
 * O15G HIGH-1 — un-static'd for unit testing; also SKIPS peers in invalid-cert
 * cooldown (a peer just stamped bad, or a previously-bad peer, is not a
 * rotation target). */
int nodus_witness_sync_rotate_peer(nodus_witness_t *w) {
    int cur = w->sync_state.sync_peer_idx;
    uint64_t need = w->sync_state.sync_current_height;
    uint64_t now = (uint64_t)time(NULL);
    for (int i = cur + 1; i < w->peer_count; i++) {
        if (!w->peers[i].identified || !w->peers[i].conn) continue;
        if (w->peers[i].conn->state != NODUS_CONN_CONNECTED) continue;
        if (w->peers[i].sync_bad_until > now) continue;   /* invalid-cert cooldown */
        if (w->peers[i].remote_height < need) continue;
        return i;
    }
    return -1;
}

/* ── O15G HIGH-2 — genesis bootstrap-anchor check ───────────────────────────
 *
 * Bind a synced genesis to the DISCOVER-agreed anchor and verify its block-1
 * certs against the ANCHORED chain_def (design §8.1). Declared in
 * nodus_witness_cert.h; called by the genesis leg of handle_rsp, and exercised
 * directly by test_sync_genesis_anchor with hand-built tx_data + chain_def so
 * the property is unit-tested without a replayable genesis. */
int nodus_witness_sync_genesis_anchor_check(nodus_witness_t *w,
                                            const uint8_t *tx_data,
                                            uint32_t tx_len,
                                            const uint8_t *tx_hash,
                                            const uint8_t *block_hash,
                                            const nodus_t3_sync_cert_t *certs,
                                            uint32_t cert_count) {
    if (!w || !tx_data || !tx_hash || !block_hash || !certs)
        return NODUS_W_GENESIS_ANCHOR_FAULT;
    if (!w->g_quorum_cdh_set)
        return NODUS_W_GENESIS_ANCHOR_FAULT;   /* caller MUST gate on this */

    /* 1. Extract the genesis TX's chain_def trailer (verbatim bytes — the same
     *    bytes bootstrap serves from blocks.chain_def_blob and hashes into the
     *    anchor). */
    const uint8_t *cd = NULL;
    uint32_t cd_len = 0;
    if (nodus_witness_extract_chain_def(tx_data, tx_len, &cd, &cd_len) != 0 ||
        !cd || cd_len == 0)
        return NODUS_W_GENESIS_ANCHOR_MALFORMED;

    /* 2. ANCHOR — SHA3-512(chain_def) == the DISCOVER-agreed g_quorum_cdh (the
     *    EXACT function bootstrap.c:928 hashed the anchor with). This is the
     *    LOAD-BEARING check: the genesis tx_hash does NOT cover the chain_def
     *    trailer (shared/dnac/tx_wire.c:504-506), so nothing else binds the
     *    validator set. A mismatch is a forged genesis. */
    uint8_t got_cdh[64];
    if (qgp_sha3_512(cd, cd_len, got_cdh) != 0)
        return NODUS_W_GENESIS_ANCHOR_FAULT;
    if (memcmp(got_cdh, w->g_quorum_cdh, 64) != 0)
        return NODUS_W_GENESIS_ANCHOR_CDH_MISMATCH;

    /* 3. Belt-and-braces — derive_chain_id(genesis) == the chain we adopted.
     *    Redundant with the anchor for the validator set, but binds the genesis
     *    outputs/tx_hash to THIS chain (commit_genesis skips this on a
     *    bootstrapped joiner because w->db is already set). */
    uint8_t derived[32];
    if (nodus_witness_genesis_derive_chain_id(tx_data, tx_len, tx_hash,
                                              derived) != 0)
        return NODUS_W_GENESIS_ANCHOR_MALFORMED;
    if (memcmp(derived, w->chain_id, 32) != 0)
        return NODUS_W_GENESIS_ANCHOR_CID_MISMATCH;

    /* 4. Verify certs against the ANCHORED chain_def's initial_validators[].
     *    Genesis signers used a ZERO chain_id at sign time (chain_id is derived
     *    only in commit_genesis, AFTER quorum), so the preimage chain_id here
     *    is all-zeros. */
    uint8_t cert_chain_id_zero[32] = {0};
    uint32_t q = 0;
    int cv = nodus_witness_verify_certs_chain_def(block_hash, 1,
                                                  cert_chain_id_zero,
                                                  cd, cd_len,
                                                  certs, cert_count, &q);
    if (cv == NODUS_V2_INTERNAL_FAULT)
        return NODUS_W_GENESIS_ANCHOR_FAULT;       /* corrupt anchored chain_def */
    if (cv == NODUS_V2_CONSENSUS_INVALID)
        return NODUS_W_GENESIS_ANCHOR_CERT_SHORT;  /* < quorum vs anchored set   */
    return NODUS_W_GENESIS_ANCHOR_OK;
}

/* ── Sync check + initiate ──────────────────────────────────────── */

void nodus_witness_sync_check(nodus_witness_t *w) {
    if (!w || !w->running) return;

    /* O15D — LEGACY sync never runs on a successor chain: it replays
     * legacy blocks through the legacy apply, which a successor refuses
     * by role. Successor catch-up is the (still-dormant) V2 sync lane —
     * a named open item, not this path. */
    if (w->v2_successor) return;

    /* A node with NO CHAIN DATABASE has nothing to sync INTO.
     *
     * O15J Faz 3 (2026-08-27) — this guard is the fix for a permanent
     * wedge, not a tidy-up. A brand-new node joining a chain that is
     * already past genesis runs sync_check while still in bootstrap
     * DISCOVER, before nodus_witness_create_chain_db has produced a
     * database (`WITNESS: no chain DB found — pre-genesis state`). Sync
     * saw local=0 (block_height with no db) against a live peer,
     * latched `syncing = true` at :~629 and requested block 1 — into
     * nothing.
     *
     * That latch is one-way. Every clear of `sync_state.syncing` lives
     * on a RESPONSE path; there is no watchdog that clears it when no
     * usable response ever arrives. So the "Already syncing" guard
     * immediately below returned on every later tick, forever: the node
     * completed bootstrap, created its chain DB, joined the peer mesh —
     * and never fetched a single block. `blocks` and `validators` both
     * stayed empty, so it could not resolve a committee either, and its
     * log filled with `C5 prepared cert REJECTED ... committee=-1`.
     *
     * Bootstrap's DONE transition already tried to re-enable sync by
     * resetting `last_sync_attempt` — but that only defeats the RATE
     * LIMIT guard further down; the `syncing` latch sits ABOVE it and
     * was never cleared (nodus_witness_bootstrap.c, which now clears it
     * as well). Refusing to start at all without a database is the
     * upstream half: the impossible sync is never begun, so there is no
     * latch to recover from.
     *
     * Genesis does NOT come through this path — bootstrap fetches it
     * with w_genesis_req/w_genesis_rsp and creates the DB from the
     * response — so nothing is lost by declining to sync before it
     * exists. Reproduced by `test_vset_grow_shrink.sh` (needs a
     * short-epoch build); see nodus/BUGS.md. */
    /* ── STALE-LATCH WATCHDOG — must run BEFORE every guard below ──
     *
     * `syncing` used to be a bare `return`, which made it a ONE-WAY
     * latch: it is set when a request goes out, and every clear of it
     * lives on a RESPONSE path. A response that never arrives — peer
     * died mid-sync, frame dropped, peer serves nothing — therefore left
     * the node permanently unable to sync, silently, with no error and
     * no recovery short of an operator restart.
     *
     * ORDER IS LOAD-BEARING. Releasing a latch is pure cleanup and is
     * correct whatever the database state or round phase; if the `!w->db`
     * guard below came first, a node latched while it had no chain DB
     * could never release — which is precisely the wedge being fixed
     * (bootstrap DISCOVER starts a sync into a database that does not
     * exist yet). `test_sync_stall_watchdog.c` fails if these are
     * reordered.
     *
     * `sync_last_progress` is stamped on every request actually sent, so
     * a healthy catch-up refreshes it block by block and never trips
     * this — the direction a naive watchdog breaks. Only a sync that has
     * sent and received nothing for SYNC_STALL_TIMEOUT_SEC is released,
     * and then we fall THROUGH rather than return, so the same tick
     * re-evaluates the gap and starts fresh (against a freshly chosen
     * peer, the old one being the likely reason we stalled). */
    if (w->sync_state.syncing) {
        uint64_t now_chk = (uint64_t)time(NULL);
        if (now_chk - w->sync_state.sync_last_progress
                < SYNC_STALL_TIMEOUT_SEC)
            return;                     /* progressing — leave it alone */

        fprintf(stderr, "%s: sync STALLED — no progress for %llus at "
                "block %llu from peer %d; releasing the latch and "
                "restarting\n", LOG_TAG,
                (unsigned long long)(now_chk -
                                     w->sync_state.sync_last_progress),
                (unsigned long long)w->sync_state.sync_current_height,
                w->sync_state.sync_peer_idx);
        w->sync_state.syncing = false;
        /* fall through — the guards below decide whether a NEW sync may
         * start; the latch itself is now clean either way. */
    }

    if (!w->db) return;

    /* Only sync during IDLE phase */
    if (w->round_state.phase != NODUS_W_PHASE_IDLE) return;

    /* Rate limit */
    uint64_t now = (uint64_t)time(NULL);
    if (now - w->sync_state.last_sync_attempt < SYNC_MIN_INTERVAL_SEC) return;

    /* 2026-05-02 audit C-3: stamp last_sync_attempt as soon as we
     * pass the basic guards (running, IDLE, syncing, rate-limit).
     * Without this, every early-return path below (no peer ahead,
     * no fork, peer behind, quorum unset) bypasses the rate limit
     * and a malicious COMMIT storm pays the full peer-table walk
     * + state_root Merkle recompute on each call. The original
     * timestamp set deeper in the function only fired on the
     * "actually start syncing" path. */
    w->sync_state.last_sync_attempt = now;

    /* Check for height gap — find peer with higher chain */
    int peer_idx = nodus_witness_sync_find_peer(w);
    if (peer_idx < 0) return;  /* No peer ahead of us */

    uint64_t local_height = nodus_witness_block_height(w);
    uint64_t peer_height = w->peers[peer_idx].remote_height;

    /* Also check UTXO checksum mismatch at same height (fork detection) */
    if (peer_height == local_height && local_height > 0) {
        /* Same-height fork detection via checksum quorum */
        uint8_t local_cksum[NODUS_KEY_BYTES];
        if (w->cached_state_root_valid) {
            memcpy(local_cksum, w->cached_state_root, NODUS_KEY_BYTES);
        } else if (nodus_witness_merkle_compute_state_root(w, local_cksum) != 0) {
            return;  /* Can't compute checksum */
        }

        /* Count peers per checksum to find majority */
        int agree_count = 0;  /* peers that match our checksum */
        int disagree_count = 0;
        uint8_t zero[NODUS_KEY_BYTES];
        memset(zero, 0, sizeof(zero));

        for (int i = 0; i < w->peer_count; i++) {
            if (!w->peers[i].identified) continue;
            if (memcmp(w->peers[i].remote_checksum, zero, NODUS_KEY_BYTES) == 0) continue;
            if (w->peers[i].remote_height != local_height) continue;

            if (memcmp(w->peers[i].remote_checksum, local_cksum, NODUS_KEY_BYTES) == 0)
                agree_count++;
            else
                disagree_count++;
        }

        /* If majority disagrees, we're on wrong fork */
        if (disagree_count >= (int)w->bft_config.quorum && disagree_count > agree_count) {
            fprintf(stderr, "%s: UTXO checksum quorum disagrees (%d vs %d) — "
                    "fork at same height %llu, dropping DB\n",
                    LOG_TAG, disagree_count, agree_count,
                    (unsigned long long)local_height);

            w->sync_state.last_sync_attempt = now;
            if (drop_witness_db(w) != 0) return;

            /* Recalculate — now we're at height 0, peer is ahead */
            local_height = 0;
        } else {
            return;  /* No fork, nothing to sync */
        }
    }

    if (peer_height <= local_height) return;

    /* O15G — the "may I sync?" precondition is pure TRANSPORT AVAILABILITY,
     * never roster quorum. cert verification now binds to the committed
     * committee snapshot (nodus_witness_verify_certs_snapshot), so it no longer
     * needs the roster to be populated and w->bft_config.quorum is not an input
     * to it. find_sync_peer above already established the ONLY precondition
     * that matters: peer_idx >= 0 means there is >= 1 authenticated (identified
     * + CONNECTED) transport peer, ahead of us, to send the request to. The old
     * "roster quorum not yet established" gate (which deferred sync until the
     * DHT-propagated roster filled) is REMOVED — it was the timing-coupled wedge
     * this season closes. */

    fprintf(stderr, "%s: sync needed: local=%llu peer=%llu (peer_idx=%d)\n",
            LOG_TAG, (unsigned long long)local_height,
            (unsigned long long)peer_height, peer_idx);

    /* Start sync */
    w->sync_state.syncing = true;
    w->sync_state.sync_peer_idx = peer_idx;
    w->sync_state.sync_target_height = peer_height;
    w->sync_state.last_sync_attempt = now;
    /* Stamp progress at the moment the latch is taken, so a request that
     * fails to send never leaves `syncing` true with a stale (or zero)
     * progress time that the watchdog would have to interpret. */
    w->sync_state.sync_last_progress = now;

    /* Start from block 1 (genesis is height=1 in DB).
     * If local_height > 0: fork detection from block 1.
     * If local_height == 0: full sync from genesis (block 1). */
    w->sync_state.sync_current_height = 1;

    nodus_witness_sync_request_next(w);
}

/* ── Request next block ─────────────────────────────────────────── */

int nodus_witness_sync_request_next(nodus_witness_t *w) {
    if (!w->sync_state.syncing) return -1;

    int pi = w->sync_state.sync_peer_idx;
    if (pi < 0 || pi >= w->peer_count || !w->peers[pi].conn) {
        fprintf(stderr, "%s: sync peer lost, aborting\n", LOG_TAG);
        w->sync_state.syncing = false;
        return -1;
    }

    uint64_t h = w->sync_state.sync_current_height;

    /* O15J Faz 3 — the stall watchdog's progress stamp. Every request
     * that goes out IS the progress: the response path calls back here
     * for the next block, so a healthy catch-up refreshes this on every
     * block and never trips SYNC_STALL_TIMEOUT_SEC, while a sync whose
     * peer stops answering stops refreshing it and is released. */
    w->sync_state.sync_last_progress = (uint64_t)time(NULL);

    fprintf(stderr, "%s: requesting block %llu from peer %d\n",
            LOG_TAG, (unsigned long long)h, pi);

    return send_sync_req(w, w->peers[pi].conn, h);
}

/* ── Handle incoming w_sync_req (server side) ───────────────────── */

int nodus_witness_sync_handle_req(nodus_witness_t *w,
                                   struct nodus_tcp_conn *conn,
                                   const nodus_t3_msg_t *msg) {
    if (!w || !conn || !msg) return -1;

    /* O15D — a successor holds no legacy blocks and serves none. */
    if (w->v2_successor) return -1;

    uint64_t height = msg->sync_req.height;

    /* Genesis is block height 0 in the request but stored as height 1 */
    uint64_t db_height = (height == 0) ? 1 : height;

    nodus_witness_block_t blk;
    if (nodus_witness_block_get(w, db_height, &blk) != 0) {
        /* Block not found — send empty response */
        nodus_t3_msg_t rsp;
        memset(&rsp, 0, sizeof(rsp));
        rsp.type = NODUS_T3_SYNC_RSP;
        /* F20 — echo request txn_id so the requester's RPC correlation
         * filter accepts the response. Mirrors the CC_VOTE_RSP fix in
         * nodus_witness_chain_config.c (commit f334b3ff). */
        rsp.txn_id = msg->txn_id;
        rsp.sync_rsp.found = false;
        rsp.sync_rsp.height = height;

        rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
        memcpy(rsp.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
        rsp.header.timestamp = (uint64_t)time(NULL);
        nodus_random((uint8_t *)&rsp.header.nonce, sizeof(rsp.header.nonce));
        memcpy(rsp.header.chain_id, w->chain_id, 32);

        uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
        size_t len = 0;
        if (nodus_t3_encode(&rsp, &w->server->identity.sk,
                             buf, sizeof(buf), &len) != 0)
            return -1;
        return nodus_tcp_send((nodus_tcp_conn_t *)conn, buf, len);
    }

    /* Phase 11 / Task 11.1 — fetch ALL committed TXs in this block
     * via nodus_witness_block_txs_get. */
    nodus_witness_block_tx_row_t rows[NODUS_W_MAX_BLOCK_TXS];
    memset(rows, 0, sizeof(rows));
    int row_count = 0;
    if (nodus_witness_block_txs_get(w, db_height, rows,
                                      NODUS_W_MAX_BLOCK_TXS, &row_count) != 0 ||
        row_count == 0) {
        return -1;
    }

    /* Per-TX nullifier scratch — pointers into the row tx_data parse. */
    uint8_t nullifier_bufs[NODUS_W_MAX_BLOCK_TXS]
                          [NODUS_T3_MAX_TX_INPUTS]
                          [NODUS_T3_NULLIFIER_LEN];

    /* Get commit certificates */
    nodus_witness_vote_record_t certs[NODUS_T3_MAX_WITNESSES];
    int cert_count = 0;
    nodus_witness_cert_get(w, db_height, certs, NODUS_T3_MAX_WITNESSES, &cert_count);

    /* Build response */
    nodus_t3_msg_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.type = NODUS_T3_SYNC_RSP;
    /* F20 — echo request txn_id (see block-not-found branch above). */
    rsp.txn_id = msg->txn_id;

    rsp.sync_rsp.found = true;
    rsp.sync_rsp.height = height;
    rsp.sync_rsp.timestamp = blk.timestamp;
    memcpy(rsp.sync_rsp.proposer_id, blk.proposer_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(rsp.sync_rsp.prev_hash, blk.prev_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(rsp.sync_rsp.tx_root, blk.tx_root, NODUS_T3_TX_HASH_LEN);
    /* 2026-05-02 — C3 fix follow-up (Faz 2 wire field "sr"): include
     * sender's stored state_root so the receiver's replay_block can
     * verify against finalize_block's mismatch check. */
    memcpy(rsp.sync_rsp.state_root, blk.state_root, NODUS_KEY_BYTES);
    rsp.sync_rsp.tx_count = row_count;

    /* Phase 11 follow-up — committed_transactions now stores
     * client_pubkey and client_sig (migration v13 client-fields). Use
     * the real values when present; fall back to zero pad on rows that
     * predate the migration. The wire encoder requires non-NULL bstr
     * pointers either way. */
    static const uint8_t zero_pk[NODUS_PK_BYTES] = {0};
    static const uint8_t zero_sig[NODUS_SIG_BYTES] = {0};

    for (int i = 0; i < row_count; i++) {
        nodus_t3_batch_tx_t *btx = &rsp.sync_rsp.batch_txs[i];
        memcpy(btx->tx_hash, rows[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        btx->tx_type = rows[i].tx_type;
        btx->tx_data = rows[i].tx_data;
        btx->tx_len = rows[i].tx_len;
        btx->client_pubkey = rows[i].client_pubkey ?
                              rows[i].client_pubkey : zero_pk;
        btx->client_sig = rows[i].client_sig ?
                            rows[i].client_sig : zero_sig;
        btx->fee = 0;
        /* Parse input nullifiers from tx_data for the wire, mirrors
         * the existing batch-propose pattern. */
        if (rows[i].tx_data && rows[i].tx_len > DNAC_TX_HEADER_SIZE &&
            rows[i].tx_type != NODUS_W_TX_GENESIS) {
            size_t off = DNAC_TX_HEADER_SIZE;
            uint8_t nc = rows[i].tx_data[off++];
            if (nc > NODUS_T3_MAX_TX_INPUTS) nc = NODUS_T3_MAX_TX_INPUTS;
            btx->nullifier_count = nc;
            for (int j = 0; j < nc; j++) {
                if (off + NODUS_T3_NULLIFIER_LEN > rows[i].tx_len) break;
                memcpy(nullifier_bufs[i][j], rows[i].tx_data + off,
                       NODUS_T3_NULLIFIER_LEN);
                btx->nullifiers[j] = nullifier_bufs[i][j];
                off += NODUS_T3_NULLIFIER_LEN + 8 + 64;
            }
        }
    }

    /* Convert vote records to sync certs */
    rsp.sync_rsp.cert_count = (uint32_t)cert_count;
    for (int i = 0; i < cert_count && i < NODUS_T3_MAX_WITNESSES; i++) {
        memcpy(rsp.sync_rsp.certs[i].voter_id, certs[i].voter_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(rsp.sync_rsp.certs[i].signature, certs[i].signature,
               NODUS_SIG_BYTES);
    }

    /* Encode and send — use heap buffer for large responses */
    rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(rsp.header.sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    rsp.header.timestamp = (uint64_t)time(NULL);
    nodus_random((uint8_t *)&rsp.header.nonce, sizeof(rsp.header.nonce));
    memcpy(rsp.header.chain_id, w->chain_id, 32);

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) {
        for (int i = 0; i < row_count; i++)
            nodus_witness_block_tx_row_free(&rows[i]);
        return -1;
    }
    size_t len = 0;

    int rc = nodus_t3_encode(&rsp, &w->server->identity.sk,
                              buf, NODUS_W_MAX_SYNC_RSP_SIZE, &len);
    /* Phase 11 / Task 11.3 — tier 3 aggregate guard. */
    if (rc == 0 && len > NODUS_W_MAX_SYNC_RSP_SIZE) {
        fprintf(stderr, "%s: sync_rsp encode size %zu > 1 MB cap\n",
                LOG_TAG, len);
        rc = -1;
    }
    if (rc == 0)
        nodus_tcp_send((nodus_tcp_conn_t *)conn, buf, len);

    free(buf);
    for (int i = 0; i < row_count; i++)
        nodus_witness_block_tx_row_free(&rows[i]);
    return rc;
}

/* ── Handle incoming w_sync_rsp (client side) ───────────────────── */

int nodus_witness_sync_handle_rsp(nodus_witness_t *w,
                                   const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;
    /* O15D — a successor never legacy-syncs (sync_check refuses, so
     * syncing can never be true here; belt for a hostile frame). */
    if (w->v2_successor) return -1;
    if (!w->sync_state.syncing) {
        fprintf(stderr, "%s: received w_sync_rsp but not syncing\n", LOG_TAG);
        return -1;
    }

    const nodus_t3_sync_rsp_t *rsp = &msg->sync_rsp;

    if (!rsp->found) {
        fprintf(stderr, "%s: peer does not have block %llu, aborting sync\n",
                LOG_TAG, (unsigned long long)rsp->height);
        w->sync_state.syncing = false;
        return -1;
    }

    uint64_t local_height = nodus_witness_block_height(w);
    uint64_t expected_height = w->sync_state.sync_current_height;

    fprintf(stderr, "%s: received block %llu (local=%llu, target=%llu)\n",
            LOG_TAG, (unsigned long long)rsp->height,
            (unsigned long long)local_height,
            (unsigned long long)w->sync_state.sync_target_height);

    /* Phase 1: Fork detection — compare block hashes for existing blocks */
    /* Map height: request height 0 = genesis = DB height 1 */
    uint64_t db_height = (rsp->height == 0) ? 1 : rsp->height;

    if (db_height <= local_height) {
        /* We have this block — compare tx_root values for fork detection. */
        nodus_witness_block_t local_blk;
        if (nodus_witness_block_get(w, db_height, &local_blk) == 0) {
            if (memcmp(local_blk.tx_root, rsp->tx_root,
                       NODUS_T3_TX_HASH_LEN) != 0) {
                /* Fork detected! */
                if (db_height == 1) {
                    /* Genesis mismatch — different chain, abort */
                    fprintf(stderr, "%s: GENESIS MISMATCH — different chain, "
                            "aborting sync\n", LOG_TAG);
                    w->sync_state.syncing = false;
                    return -1;
                }

                fprintf(stderr, "%s: FORK DETECTED at height %llu — "
                        "dropping DB for full resync\n",
                        LOG_TAG, (unsigned long long)db_height);

                if (drop_witness_db(w) != 0) {
                    w->sync_state.syncing = false;
                    return -1;
                }

                /* Reset sync to start from genesis (height=1 in DB) */
                w->sync_state.sync_current_height = 1;
                return nodus_witness_sync_request_next(w);
            }

            /* Block matches — continue fork check with next block */
            w->sync_state.sync_current_height = expected_height + 1;

            /* If we've verified all local blocks, switch to replay mode */
            if (w->sync_state.sync_current_height > local_height) {
                /* Fork check complete, no fork found. Start replay. */
                fprintf(stderr, "%s: fork check complete — no fork, "
                        "replaying from %llu\n", LOG_TAG,
                        (unsigned long long)w->sync_state.sync_current_height);
            }

            /* Check if done */
            if (w->sync_state.sync_current_height > w->sync_state.sync_target_height) {
                fprintf(stderr, "%s: sync complete (verified all blocks)\n", LOG_TAG);
                w->sync_state.syncing = false;
                return 0;
            }

            return nodus_witness_sync_request_next(w);
        }
    }

    /* Phase 3: Block replay — verify and commit */

    /* Check: prevent duplicate blocks */
    if (local_height >= db_height) {
        fprintf(stderr, "%s: already have block %llu, skipping\n",
                LOG_TAG, (unsigned long long)db_height);
        w->sync_state.sync_current_height = expected_height + 1;
        goto next;
    }

    /* Verify prev_hash chain continuity */
    if (db_height == 1) {
        /* Genesis: prev_hash must be all zeros */
        uint8_t zeros[NODUS_T3_TX_HASH_LEN];
        memset(zeros, 0, sizeof(zeros));
        if (memcmp(rsp->prev_hash, zeros, NODUS_T3_TX_HASH_LEN) != 0) {
            fprintf(stderr, "%s: genesis prev_hash not zero, rejecting\n", LOG_TAG);
            w->sync_state.syncing = false;
            return -1;
        }
    } else {
        /* Non-genesis: verify prev_hash matches our latest block */
        nodus_witness_block_t latest;
        if (nodus_witness_block_get_latest(w, &latest) == 0) {
            uint8_t expected_prev[NODUS_T3_TX_HASH_LEN];
            compute_prev_hash(w, &latest, expected_prev);

            if (memcmp(rsp->prev_hash, expected_prev, NODUS_T3_TX_HASH_LEN) != 0) {
                fprintf(stderr, "%s: prev_hash mismatch at height %llu, "
                        "aborting sync\n", LOG_TAG,
                        (unsigned long long)db_height);
                w->sync_state.syncing = false;
                return -1;
            }
        }
    }

    /* Phase 11 / Task 11.4 — three-step receiver recomputation. */
    if (rsp->tx_count <= 0 || rsp->tx_count > NODUS_W_MAX_BLOCK_TXS) {
        fprintf(stderr, "%s: sync_rsp tx_count %d out of range\n",
                LOG_TAG, rsp->tx_count);
        w->sync_state.syncing = false;
        return -1;
    }

    /* Step a — recompute tx_root locally and check vs wire claim */
    uint8_t local_tx_root[NODUS_T3_TX_HASH_LEN];
    {
        uint8_t flat[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];
        for (int i = 0; i < rsp->tx_count; i++) {
            memcpy(flat + i * NODUS_T3_TX_HASH_LEN,
                   rsp->batch_txs[i].tx_hash, NODUS_T3_TX_HASH_LEN);
        }
        if (nodus_witness_merkle_tx_root(flat, (uint32_t)rsp->tx_count,
                                           local_tx_root) != 0) {
            fprintf(stderr, "%s: local tx_root compute failed\n", LOG_TAG);
            w->sync_state.syncing = false;
            return -1;
        }
    }
    if (memcmp(local_tx_root, rsp->tx_root, NODUS_T3_TX_HASH_LEN) != 0) {
        fprintf(stderr, "%s: tx_root divergence — sender lied at height %llu\n",
                LOG_TAG, (unsigned long long)db_height);
        w->sync_state.syncing = false;
        return -1;
    }

    /* Step b — compute the SAME block_hash the cert preimage was
     * signed over. The original sync code used
     * nodus_witness_compute_block_hash() — a wholly different hash
     * formulation that mixes prev_hash + state_root + tx_root +
     * tx_count + proposer_id. That hash never matches what BFT
     * signs. The actual cert preimage's "block_hash" field is
     * SHA3-512 over the concatenated tx_hashes of the block (see
     * nodus_witness_bft.c:3398-3414 leader path; the follower
     * path at :4024-4045 verifies the same formula). The
     * round_state.tx_hash field stored at signing time IS
     * SHA3(concat tx_hashes), so cert_preimage(round_state.tx_hash,
     * ...) and our cert_preimage(this hash, ...) produce
     * byte-identical preimages → cert verify passes.
     *
     * F2 (test_bootstrap_join_live) caught the original
     * compute_block_hash misuse: every fresh-bootstrap node failed
     * cert verify at height 1 because its "block_hash" had nothing
     * to do with the cert preimage's "block_hash" field name. The
     * shared name with two different meanings was the trap. */
    uint8_t local_block_hash[NODUS_T3_TX_HASH_LEN];
    {
        uint8_t hash_input[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];
        size_t total_len = 0;
        for (int i = 0; i < rsp->tx_count; i++) {
            memcpy(hash_input + total_len,
                   rsp->batch_txs[i].tx_hash, NODUS_T3_TX_HASH_LEN);
            total_len += NODUS_T3_TX_HASH_LEN;
        }
        nodus_key_t bh;
        if (nodus_hash(hash_input, total_len, &bh) != 0) {
            fprintf(stderr,
                "%s: cert-preimage block_hash compute failed at "
                "height %llu\n", LOG_TAG, (unsigned long long)db_height);
            w->sync_state.syncing = false;
            return -1;
        }
        memcpy(local_block_hash, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }

    /* Step c — verify cert sigs against the LOCAL block_hash.
     *
     * Genesis-block special case (db_height == 1): the BFT signer's
     * w->chain_id is still all-zeros at PRECOMMIT sign time, because
     * derive_chain_id only runs in commit_genesis (the COMMIT phase
     * AFTER quorum). So the cert preimage at sign time used a zero
     * chain_id; verify must mirror that or the chain_id field in
     * the preimage diverges between signer (zeros) and verifier
     * (post-derive value), making every cert appear invalid.
     *
     * For height >= 2 the chain_id is set on every node before
     * cert signing, so the existing w->chain_id is correct. */
    if (db_height >= 2) {
        /* ── O15G — heights >= 2 verify signer pubkeys against the COMMITTED
         * committee snapshot for the block's epoch (roster-free). This is the
         * sync-path half of the O15F fix. It SUBSUMES the (1)-(4) quorum
         * fallback chain that used to live here: the snapshot / legacy-recompute
         * authority (arms 1-2) now lives INSIDE the verifier, its quorum is the
         * ONLY quorum, and the roster fallback (arm 4, w->bft_config.quorum) is
         * gone. Genesis (db_height == 1) keeps the legacy roster leg in the
         * `else` below because at replay-of-block-1 no snapshot authority is
         * committed yet — the genesis-TX chain_def seat count (arm 3) is the
         * only source available (design §2.3 / §7.6). */
        uint32_t rv_quorum = 0;
        int cv = nodus_witness_verify_certs_snapshot(w, local_block_hash,
                                                     db_height, w->chain_id,
                                                     rsp->certs,
                                                     rsp->cert_count,
                                                     &rv_quorum);
        if (cv < 0) {
            if (cv == NODUS_V2_CONSENSUS_INVALID) {
                /* This peer's response is INVALID against a KNOWN committee.
                 * Reject THIS peer and rotate to another that holds the block —
                 * one invalid peer must not abandon all catch-up.
                 *
                 * O15G HIGH-1 — stamp THIS peer's cooldown so a Byzantine
                 * height-inflating peer that served an invalid cert is not
                 * re-selected by find_sync_peer on the next tick while an honest
                 * peer (any index) is reachable. Stamped ONLY on
                 * CONSENSUS_INVALID (a real verdict against a known committee) —
                 * never on -2/-3, which are non-verdicts about local state. The
                 * stamp is applied even if rotation finds no peer this session;
                 * the next tick then routes around the bad peer. */
                int cur = w->sync_state.sync_peer_idx;
                if (cur >= 0 && cur < w->peer_count)
                    w->peers[cur].sync_bad_until =
                        (uint64_t)time(NULL) + SYNC_BAD_PEER_COOLDOWN_SEC;

                int nxt = nodus_witness_sync_rotate_peer(w);
                if (nxt >= 0) {
                    fprintf(stderr, "%s: cert verify INVALID at height %llu "
                            "(quorum=%u) — rotating to peer %d\n", LOG_TAG,
                            (unsigned long long)db_height, rv_quorum, nxt);
                    w->sync_state.sync_peer_idx = nxt;
                    return nodus_witness_sync_request_next(w);
                }
                fprintf(stderr, "%s: cert verify INVALID at height %llu "
                        "(quorum=%u) — no other peer to rotate to\n", LOG_TAG,
                        (unsigned long long)db_height, rv_quorum);
                w->sync_state.syncing = false;
                return -1;
            }
            if (cv == NODUS_V2_NOT_YET_LINKABLE) {
                /* Committed authority for this epoch is not present yet — this
                 * node is behind. Stop THIS attempt; the SYNC_MIN_INTERVAL_SEC
                 * rate limit in nodus_witness_sync_check is the bounded backoff
                 * before the next tick retries — no tight loop. */
                fprintf(stderr, "%s: cert authority not yet available at "
                        "height %llu — deferring sync (bounded backoff)\n",
                        LOG_TAG, (unsigned long long)db_height);
                w->sync_state.syncing = false;
                return -1;
            }
            /* NODUS_V2_INTERNAL_FAULT — local corruption / unreadable committed
             * authority. Fail closed; this replaces the corrupt-snapshot arm
             * the old (1)-(4) block had. */
            fprintf(stderr, "%s: cert authority LOCAL FAULT at height %llu — "
                    "refusing to verify (fail-closed)\n", LOG_TAG,
                    (unsigned long long)db_height);
            w->sync_state.syncing = false;
            return -1;
        }
        fprintf(stderr, "%s: block %llu certs verified: %d/%u (quorum=%u)\n",
                LOG_TAG, (unsigned long long)db_height,
                cv, rsp->cert_count, rv_quorum);
    } else if (w->g_quorum_cdh_set) {
        /* ── O15G HIGH-2 — ANCHORED genesis leg (db_height == 1) ───────────
         * This node bootstrapped through DISCOVER, so it holds the
         * quorum-agreed chain_def hash. Bind the synced genesis to that anchor
         * and verify block-1 certs against the ANCHORED chain_def's OWN
         * validator set — NEVER the DHT roster. This closes §7.6 (no DHT-roster
         * genesis authority) and the partial-eclipse forgery path: a sync peer
         * plus roster sybils can no longer get a forged validator set adopted,
         * because the genesis tx_hash does NOT cover the chain_def trailer
         * (shared/dnac/tx_wire.c:504-506) — the g_quorum_cdh hash is the
         * load-bearing anchor. */
        if (rsp->tx_count != 1 ||
            rsp->batch_txs[0].tx_type != NODUS_W_TX_GENESIS) {
            fprintf(stderr, "%s: anchored genesis leg: height-1 block is not a "
                    "single genesis TX — rejecting\n", LOG_TAG);
            w->sync_state.syncing = false;
            return -1;
        }
        int arc = nodus_witness_sync_genesis_anchor_check(
                      w, rsp->batch_txs[0].tx_data, rsp->batch_txs[0].tx_len,
                      rsp->batch_txs[0].tx_hash, local_block_hash,
                      rsp->certs, rsp->cert_count);
        if (arc != NODUS_W_GENESIS_ANCHOR_OK) {
            fprintf(stderr, "%s: genesis anchor check FAILED (rc=%d) at "
                    "height 1 — forged/mismatched genesis, aborting sync\n",
                    LOG_TAG, arc);
            w->sync_state.syncing = false;
            return -1;
        }
        fprintf(stderr, "%s: genesis anchored to DISCOVER cdh; certs verified "
                "vs anchored chain_def\n", LOG_TAG);
    } else {
    /* ── UNANCHORED founder / legacy-fixture genesis leg (db_height == 1) ──
     * No DISCOVER bootstrap anchor exists (w->g_quorum_cdh_set == false), e.g.
     * a genesis-creating founder or a legacy fixture. The roster + genesis-TX
     * chain_def seat count is the only source. Preserved verbatim; §8.1 closes
     * the roster path for anchored joiners in the branch above. */
    uint8_t cert_chain_id_zero[32] = {0};
    const uint8_t *cert_chain_id =
        (db_height == 1) ? cert_chain_id_zero : w->chain_id;
    {
        /* ── S3: the quorum for verifying a HISTORICAL block's certs is
         * the quorum of the set that SIGNED it, never the local
         * roster-derived bft_config. A joining node's transient mesh
         * size (e.g. 9 peers up while two candidates bootstrap) must not
         * decide whether committed history verifies — with the old
         * `w->bft_config.quorum` a 9-node mesh demanded 7 sigs from a
         * 7-member epoch's 5-sig block and the sync deadlocked.
         * Sources, in order:
         *   1. the persisted validator-set snapshot for the block's
         *      epoch (committed one epoch ahead — the S3 authority);
         *   2. no snapshot row: deterministic committee recompute
         *      (legacy epochs), DIRECT compute — never the per-epoch
         *      cache, so an empty pre-replay result cannot poison it;
         *   3. genesis replay (no local validators yet): the seat count
         *      from the genesis TX's own chain_def — the same bytes
         *      Rule P verifies during the replay right below, so a
         *      forged count cannot outlive this block;
         *   4. legacy roster quorum (pre-genesis harness paths only).
         * A snapshot row that exists but fails integrity is a FAULT and
         * the sync fails closed — never a fallback.
         *
         * O15G: this whole (1)-(4) leg now runs ONLY for db_height == 1
         * (genesis replay). Every height >= 2 is handled by the snapshot
         * verifier in the `if` branch above. */
        uint32_t sync_quorum = w->bft_config.quorum;   /* (4) fallback */
        {
            uint64_t e_start = (db_height / (uint64_t)DNAC_EPOCH_LENGTH) *
                               (uint64_t)DNAC_EPOCH_LENGTH;
            dna_vset_snapshot_t *snap = NULL;
            int grc = nodus_witness_vset_get(w, e_start, &snap, NULL);
            if (grc == 0) {                                      /* (1) */
                sync_quorum = dna_bft_quorum((uint32_t)snap->active_count);
                dna_vset_free(&snap);
            } else if (grc == 1) {
                nodus_committee_member_t *hist =
                    calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS,
                           sizeof(*hist));
                int hist_n = 0;
                if (hist &&
                    nodus_committee_compute_for_epoch(w, e_start, hist,
                        DNAC_MAX_ACTIVE_VALIDATORS, &hist_n) == 0 &&
                    hist_n > 0) {                                /* (2) */
                    sync_quorum = dna_bft_quorum((uint32_t)hist_n);
                } else if (rsp->tx_count == 1 &&
                           rsp->batch_txs[0].tx_type == NODUS_W_TX_GENESIS) {
                    const uint8_t *cd = NULL; uint32_t cd_len = 0;
                    uint64_t cd_sup = 0; uint8_t cd_vc = 0;
                    if (nodus_witness_extract_chain_def(
                            rsp->batch_txs[0].tx_data,
                            rsp->batch_txs[0].tx_len, &cd, &cd_len) == 0 &&
                        cd && cd_len > 0 &&
                        nodus_witness_parse_cd_supply(cd, (size_t)cd_len,
                                                      &cd_sup, &cd_vc) == 0 &&
                        cd_vc > 0) {                             /* (3) */
                        sync_quorum = dna_bft_quorum((uint32_t)cd_vc);
                    }
                }
                free(hist);
            } else {
                fprintf(stderr, "%s: historical validator-set snapshot for "
                        "epoch %llu is CORRUPT — refusing to verify block "
                        "%llu\n", LOG_TAG, (unsigned long long)e_start,
                        (unsigned long long)db_height);
                w->sync_state.syncing = false;
                return -1;
            }
        }

        int verified = nodus_witness_verify_sync_certs(local_block_hash,
                                                         db_height,
                                                         cert_chain_id,
                                                         &w->roster,
                                                         rsp->certs,
                                                         rsp->cert_count,
                                                         sync_quorum);
        if (verified < 0) {
            fprintf(stderr, "%s: cert verify FAILED at height %llu "
                    "(< quorum %u)\n", LOG_TAG,
                    (unsigned long long)db_height, sync_quorum);
            w->sync_state.syncing = false;
            return -1;
        }
        fprintf(stderr, "%s: block %llu certs verified: %d/%u (quorum=%u)\n",
                LOG_TAG, (unsigned long long)db_height,
                verified, rsp->cert_count, sync_quorum);
    }
    }

    /* Step d — replay every TX in the block via Phase 6 wrappers */
    {
        nodus_witness_mempool_entry_t entries[NODUS_W_MAX_BLOCK_TXS];
        nodus_witness_mempool_entry_t *entry_ptrs[NODUS_W_MAX_BLOCK_TXS];
        memset(entries, 0, sizeof(entries));

        for (int i = 0; i < rsp->tx_count; i++) {
            const nodus_t3_batch_tx_t *btx = &rsp->batch_txs[i];
            nodus_witness_mempool_entry_t *e = &entries[i];
            memcpy(e->tx_hash, btx->tx_hash, NODUS_T3_TX_HASH_LEN);
            e->tx_type = btx->tx_type;
            e->nullifier_count = btx->nullifier_count;
            for (int j = 0; j < btx->nullifier_count; j++) {
                if (btx->nullifiers[j])
                    memcpy(e->nullifiers[j], btx->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN);
            }
            e->tx_data = (uint8_t *)btx->tx_data;
            e->tx_len = btx->tx_len;
            entry_ptrs[i] = e;
        }

        int rc;
        if (rsp->tx_count == 1 &&
            entries[0].tx_type == NODUS_W_TX_GENESIS) {
            rc = nodus_witness_commit_genesis(w, entries[0].tx_hash,
                                                entries[0].tx_data,
                                                entries[0].tx_len,
                                                rsp->timestamp,
                                                rsp->proposer_id);
        } else {
            /* 2026-05-02 — C3 fix follow-up landed in Faz 2: sync_rsp
             * now carries state_root on the wire (key "sr"). Pass it
             * to replay_block so finalize_block's existing mismatch
             * check (nodus_witness_bft.c:3186-3211) catches Byzantine
             * peer fake blocks before any state mutation. Defense in
             * depth alongside cert verify (verify_sync_certs). */
            rc = nodus_witness_replay_block(w, db_height, entry_ptrs,
                                              rsp->tx_count,
                                              rsp->timestamp,
                                              rsp->proposer_id,
                                              rsp->state_root);
        }
        if (rc != 0) {
            fprintf(stderr, "%s: block replay failed at height %llu\n",
                    LOG_TAG, (unsigned long long)db_height);
            w->sync_state.syncing = false;
            return -1;
        }
    }

    /* Store commit certificates */
    {
        uint64_t stored_bh = nodus_witness_block_height(w);
        nodus_witness_vote_record_t votes[NODUS_T3_MAX_WITNESSES];
        for (uint32_t i = 0; i < rsp->cert_count && i < NODUS_T3_MAX_WITNESSES; i++) {
            memcpy(votes[i].voter_id, rsp->certs[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN);
            votes[i].vote = NODUS_W_VOTE_APPROVE;
            memcpy(votes[i].signature, rsp->certs[i].signature,
                   NODUS_SIG_BYTES);
        }
        nodus_witness_cert_store(w, stored_bh, votes, (int)rsp->cert_count);

        /* O15B.1 — THE POST-ROOT ATTENDANCE WRITE IS GONE.
         *
         * What used to be here: a second nodus_witness_record_attendance()
         * for this height, AFTER replay_block had already computed and
         * verified the block's state_root and committed it. It was
         * justified as a no-op "because commit_batch already credited the
         * same proposer at the same height INSIDE the block transaction",
         * with the monotonic guard (nodus_witness_bft.c:3401,
         * block_height <= last_signed_block) as the thing making it inert.
         *
         * That reasoning holds for an ordinary block and fails at an
         * epoch boundary. record_attendance only matches validators whose
         * status is ACTIVE or RETIRING (bft.c:3329-3348), and it runs
         * BEFORE finalize_block, so at a boundary it sees the ENDING
         * epoch's statuses. A proposer that was ELIGIBLE in the ending
         * epoch and is flipped to ACTIVE by that same boundary block is
         * therefore — canonically, on every node, live and replaying —
         * given NO credit for it: last_signed_block keeps its old value.
         * The guard was then wide open (33 <= 14 is false), so this call
         * fired and wrote last_signed_block and
         * signed_blocks_this_epoch — both hashed into the validator leaf
         * (nodus_witness_merkle.c:894-896) — AFTER the root that commits
         * them had been computed.
         *
         * Consequence, observed: a node that crashed at h=30 and
         * re-synced replayed 31,32,33 with byte-identical roots, ended
         * h=33 holding a validator row no live node has, and diverged on
         * the very next block:
         *   FATAL: state_root DIVERGED at h=34 — local=a3b174bd…
         *   leader=0ed8d85a… — entering safety halt
         * The halt was correct; the node could simply never rejoin.
         *
         * Proven offline before removal: replaying that chain's canonical
         * blocks 1..35 through commit_genesis + replay_block — i.e. with
         * no post-root writer at all — reproduces the healthy node's
         * state_root at EVERY height, including 33 and 34. So nothing was
         * relying on this write; canonical attendance is produced
         * entirely inside commit_batch, before the root.
         *
         * No compensating write is added. The invariant this restores:
         * a field committed by a block's state_root is never mutated
         * after that root has been calculated.
         *
         * Two earlier hardenings of that call are retired with it: the
         * genesis EXCEPTION (height == 1 was skipped because
         * commit_genesis does not credit, so crediting here diverged the
         * bootstrap-recovered node) and F1b's CHECKED return (a DB fault
         * had to abort the sync session rather than be swallowed). Both
         * were guards on a write that should not have existed; neither
         * describes a behaviour that is now missing. Attendance is
         * credited in exactly one place, inside the block transaction:
         * nodus_witness_bft.c:6640, before finalize_block. */
        (void)stored_bh;
    }

    /* Update cached state_root (Phase 3 / Task 10: 4-subtree composite). */
    if (nodus_witness_merkle_compute_state_root(w, w->cached_state_root) == 0)
        w->cached_state_root_valid = true;

    fprintf(stderr, "%s: replayed block %llu OK\n",
            LOG_TAG, (unsigned long long)db_height);

    /* Faz 4D 2026-05-02 — clear recovery sentinel after first
     * successful replay. Idempotent: returns 0 when already absent.
     * Failure here is non-fatal but logged; the sentinel will linger
     * and force admin intervention on the NEXT crash, which is the
     * correct conservative behavior. */
    (void)nodus_witness_recovery_sentinel_clear(w);

    w->sync_state.sync_current_height = expected_height + 1;

next:
    /* Check if sync is complete */
    if (w->sync_state.sync_current_height > w->sync_state.sync_target_height) {
        uint64_t final_height = nodus_witness_block_height(w);
        fprintf(stderr, "%s: SYNC COMPLETE — height now %llu\n",
                LOG_TAG, (unsigned long long)final_height);
        w->sync_state.syncing = false;

        /* Update cached state_root (Phase 3 / Task 10: 4-subtree composite). */
        if (nodus_witness_merkle_compute_state_root(w, w->cached_state_root) == 0)
            w->cached_state_root_valid = true;

        return 0;
    }

    /* Enforce max blocks per sync session */
    uint64_t blocks_synced = w->sync_state.sync_current_height;
    if (blocks_synced > SYNC_MAX_BLOCKS) {
        fprintf(stderr, "%s: max blocks per session (%d) reached, pausing\n",
                LOG_TAG, SYNC_MAX_BLOCKS);
        w->sync_state.syncing = false;
        return 0;
    }

    /* Request next block */
    return nodus_witness_sync_request_next(w);
}
