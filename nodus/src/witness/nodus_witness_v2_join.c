/**
 * @file nodus/src/witness/nodus_witness_v2_join.c
 * @brief Ledger V2 O15E Faz D — pinned-genesis joiner bootstrap.
 *
 * Contract and the trust model are in the header. The joiner pulls the
 * canonical genesis bundle, re-derives the genesis in a scratch DB, and
 * adopts it in place ONLY when the derivation matches the local pin — a
 * 32-byte chain id (R3 W3, D-24 rev 4 (1)). There is ONE derivation
 * engine, nodus_witness_v2_bundle_apply, and ONE bundle shape it
 * accepts: version-4 (magic "DNA.GBUNDLE.v4\0\0", root-layout round).
 * Any other magic, including the retired v1 and v3 ones, is refused by
 * the magic check itself (nodus_witness_v2_bundle.c:487-505) before any
 * table is touched — there is no internal branch to a version-2 path;
 * this module is transport + lifecycle and hands the bytes straight to
 * that one engine.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_v2_join.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_p2p.h"   /* the 0x70 channel (P2P-PORT F5) */
#include "server/nodus_server.h"
#include "nodus/nodus_chain_config.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2JOIN"

#define V2JOIN_REQ_INTERVAL_MS  4000u   /* bundle-chunk request cadence   */

/* The most bytes a joiner accepts as a bundle's `total` before it
 * allocates. The bundle format has NO bound of its own to derive one from
 * (nodus_witness_v2_bundle.h "CANONICAL LAYOUT": u32 row counts, u32
 * TEXT / BLOB lengths, a u32 document length — a well-formed frame can
 * claim up to ~4 GiB per field), so the pre-existing 64 MiB ceiling
 * stays. ⚠ NOT GROUNDED — a size: a genesis of a few thousand validator
 * and delegation rows is far below it, and it caps the one allocation a
 * peer's `total` can trigger. */
#define V2JOIN_BUNDLE_MAX  (64u * 1024u * 1024u)

_Static_assert(NODUS_V2_JOIN_ID_CAP == CMT_P2P_ID_CAP,
               "the joiner's peer-ID buffers must hold a p2p ID");

static uint64_t join_mono_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

/* Remove a scratch derivation directory and its files (best effort — a
 * crashed prior attempt or a completed one). Only the two files the
 * derivation can create are unlinked; the seam uses the same shape. */
static void join_scratch_clear(const char *dir) {
    if (!dir || !dir[0]) return;
    /* the derivation creates witness_*.db (+ -wal/-shm) under `dir`;
     * unlink by globbing is avoided — rmdir fails if non-empty, so
     * remove the known artifacts first. A leftover unknown file only
     * makes rmdir fail, which is harmless (next run reuses the dir). */
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char p[600];
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

int nodus_witness_v2_join_arm(nodus_witness_t *w) {
    if (!w || !w->server) return -1;
    if (!w->server->config.has_v2_genesis_pin) return 0;   /* not a joiner */

    /* If a chain is already open (successor scan found one), this node is
     * NOT a fresh joiner — the pin is inert. */
    if (w->db) return 0;

    memcpy(w->v2_join.pin, w->server->config.v2_genesis_pin, 32);
    w->v2_join.active    = 1;
    w->v2_join.acc       = NULL;
    w->v2_join.acc_len   = 0;
    w->v2_join.acc_total = 0;
    w->v2_join.last_req_ms = 0;
    w->v2_join.src[0]    = '\0';
    w->v2_join.awaiting  = false;
    w->v2_join.n_excl    = 0;
    w->v2_join.excl_next = 0;
    QGP_LOG_INFO(LOG_TAG, "%s", "fresh successor joiner armed with a local "
                 "genesis pin — will pull the genesis bundle");
    return 1;
}

int nodus_witness_v2_join_active(nodus_witness_t *w) {
    return w && w->v2_join.active;
}

static void join_reset_acc(nodus_witness_t *w) {
    free(w->v2_join.acc);
    w->v2_join.acc = NULL;
    w->v2_join.acc_len = 0;
    w->v2_join.acc_total = 0;
}

/* ── the ONE source per download (decision 2026-09-27-p2p-fix-2.md (3),
 * RT2 B-F1) ─────────────────────────────────────────────────────────────
 * Every chunk of one download comes from ONE peer, `v2_join.src`, from
 * offset 0 to the end. Mixing chunks of two peers could assemble a bundle
 * no peer holds — the pin check at adopt would refuse it, but only after
 * the whole download and a scratch derivation, and without naming a
 * culprit. When the download from `src` FAILS — its `total` changed, it
 * refused a chunk (an answer that fails a check below, or no answer
 * within V2JOIN_REQ_INTERVAL_MS), or the assembled bundle failed at adopt
 * — that peer is EXCLUDED for the rest of this join attempt, the bytes
 * are dropped, and the next non-excluded peer starts again from offset 0.
 * Losing the connection to `src` drops the bytes too but excludes
 * nobody (the peer did nothing wrong). When every connected peer is
 * excluded the ring is cleared and the round starts over (JUDGMENT: a
 * joiner whose only peers are other joiners, or peers not yet serving,
 * must keep trying; the exclusion only orders the attempts). No reference
 * counterpart: channel 0x70 is nodus's own (R-P2P-5). */

bool nodus_witness_v2_join_is_excluded(const nodus_witness_t *w,
                                       const char *peer_id) {
    if (!w || !peer_id) return false;
    for (int i = 0; i < w->v2_join.n_excl; i++) {
        if (strcmp(w->v2_join.excl[i], peer_id) == 0) return true;
    }
    return false;
}

/* The download from the current source failed (`why`): exclude it, drop
 * its bytes; the next tick picks the next peer (join_pick_source). */
static void join_fail_source(nodus_witness_t *w, const char *why) {
    if (w->v2_join.src[0] != '\0' &&
        !nodus_witness_v2_join_is_excluded(w, w->v2_join.src)) {
        int slot = w->v2_join.excl_next;
        snprintf(w->v2_join.excl[slot], sizeof(w->v2_join.excl[slot]), "%s",
                 w->v2_join.src);
        w->v2_join.excl_next = (slot + 1) % NODUS_V2_JOIN_EXCLUDE_MAX;
        if (w->v2_join.n_excl < NODUS_V2_JOIN_EXCLUDE_MAX) w->v2_join.n_excl++;
    }
    QGP_LOG_WARN(LOG_TAG, "genesis bundle source %s excluded for this join "
                 "(%s) — the next peer starts from offset 0", w->v2_join.src,
                 why);
    w->v2_join.src[0] = '\0';
    w->v2_join.awaiting = false;
    join_reset_acc(w);
}

/* Choose the source of a new download: the first connected peer, from
 * the round-robin cursor on, that is not excluded. Every connected peer
 * excluded → the ring is cleared (above) and the cursor's peer is taken.
 * @return true and `v2_join.src` set; false when the peer set changed
 * under the cursor. */
static bool join_pick_source(nodus_witness_t *w, int n_peers) {
    char id[CMT_P2P_ID_CAP];
    int start = (int)(w->v2_join.peer_rr % (uint32_t)n_peers);

    for (int k = 0; k < n_peers; k++) {
        int i = (start + k) % n_peers;
        if (!nodus_witness_p2p_peer_id_at(w->p2p, i, id)) return false;
        if (nodus_witness_v2_join_is_excluded(w, id)) continue;
        snprintf(w->v2_join.src, sizeof(w->v2_join.src), "%s", id);
        w->v2_join.peer_rr = (uint32_t)((i + 1) % n_peers);
        return true;
    }
    QGP_LOG_WARN(LOG_TAG, "every connected peer (%d) failed this joiner's "
                 "genesis bundle download — the exclusions are cleared and "
                 "the round starts over", n_peers);
    w->v2_join.n_excl = 0;
    w->v2_join.excl_next = 0;
    if (!nodus_witness_p2p_peer_id_at(w->p2p, start, id)) return false;
    snprintf(w->v2_join.src, sizeof(w->v2_join.src), "%s", id);
    w->v2_join.peer_rr = (uint32_t)((start + 1) % n_peers);
    return true;
}

/* Adopt the fully-received bundle: re-derive the genesis in a scratch DB
 * against the local pin and, on a match, rename it into the real data
 * path and open the main witness on it. Returns 0 adopted, -1 not (the
 * joiner stays active and retries). */
static int join_adopt(nodus_witness_t *w) {
    const uint8_t *bytes = w->v2_join.acc;
    size_t len = w->v2_join.acc_len;

    nodus_witness_t *w2 = calloc(1, sizeof(*w2));
    if (!w2) return -1;
    w2->cached_committee_epoch_start = UINT64_MAX;
    w2->server = w->server;               /* identity only; no signing here */

    snprintf(w2->data_path, sizeof(w2->data_path), "%s/.v2join.tmp",
             w->data_path);
    join_scratch_clear(w2->data_path);
    if (mkdir(w2->data_path, 0700) != 0 && errno != EEXIST) {
        w2->server = NULL; free(w2); return -1;
    }

    /* Provisional deterministic name; renamed to the real chain id after
     * a COMPLETE, pin-matched derivation. */
    uint8_t prov16[16];
    memcpy(prov16, w->v2_join.pin, 16);   /* pin[0..15] — deterministic   */
    char prov_path[512];
    {
        char hex[33];
        for (int i = 0; i < 16; i++)
            snprintf(hex + i * 2, 3, "%02x", prov16[i]);
        snprintf(prov_path, sizeof(prov_path), "%s/witness_%s.db",
                 w2->data_path, hex);
    }

    int adopted = -1;
    do {
        if (nodus_witness_create_chain_db(w2, prov16) != 0) break;
        /* O15F Task 5 (defence-in-depth): mark the scratch handle a V2
         * chain before its genesis re-derivation — bundle_apply's real
         * order (R3 W3 delta 6 fix) is: migrate to S14, store the
         * carried document, THEN vset_commit_genesis, THEN
         * domreg_init_genesis, THEN genesis_cmt, THEN the canonical-strict
         * reader confirms chain_id == pin && app_hash == the recomputed
         * global root — the same way every chain builder does immediately
         * after create_chain_db. This makes the D1 max-30 target clamp
         * fire during the joiner's re-derivation too; correctness is
         * already backstopped by the byte-identical pin check below, but
         * the guard is now uniform across the builder and the joiner. */
        w2->v2_successor = 1;
        /* R3 W3 (D-24 rev 4 (2)): the joiner re-derives its OWN chain and
         * MUST land at the same schema the chain builder produces — S16
         * (tokenomics-v3 P1 moved the live rung from S14 to S15, P2 from
         * S15 to S16), where the Comet stores, the out-of-root
         * attendance tables and the reward tables live
         * (nodus_witness_v2_gen_derive_v3). O15F Task 4's original reason
         * (v2_claim_counts, the S12-era count-row-driven serving seam)
         * still holds AS A LOWER BOUND: S16 is a structural superset of
         * S12 (the migration ladder cascades through it), so nothing
         * that reason needed is lost. `nodus_witness_v2_bundle_apply`'s
         * own version-3 branch also migrates to S16 before storing the
         * document, so this call is not load-bearing for that path — but
         * the chain_config table it plants IS needed before that branch
         * runs, so it stays here. */
        if (nodus_witness_db_migrate_v2s16(w2) != 0) break;
        if (nodus_chain_config_db_migrate(w2) != 0) break;

        if (nodus_witness_v2_bundle_apply(w2, bytes, len,
                                          w->v2_join.pin) != 0) {
            QGP_LOG_WARN(LOG_TAG, "%s", "bundle did not re-derive to the "
                         "local pin — rejecting (will retry)");
            break;
        }

        uint8_t chain32[32];
        if (nodus_witness_v2_chain_id(w2, chain32) != 0) break;
        /* R3 W3 (D-24 rev 4 (1)): chain id == pin directly — a version-3
         * chain's identity IS the 32-byte pin, not a genesis BlockID's
         * first half. bundle_apply's own version-3 branch already
         * required this (chain_id == pin, app_hash == the computed
         * root); this re-checks the coupling explicitly on the SAME
         * accessor the rest of the witness uses
         * (nodus_witness_v2_chain_id), the way the pre-flip code did. */
        if (memcmp(chain32, w->v2_join.pin, 32) != 0) break;

        sqlite3_close(w2->db);
        w2->db = NULL;

        char real_path[512];
        {
            char hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(hex + i * 2, 3, "%02x", chain32[i]);
            snprintf(real_path, sizeof(real_path), "%s/witness_%s.db",
                     w->data_path, hex);
        }
        if (rename(prov_path, real_path) != 0) break;
        adopted = 0;
    } while (0);

    if (w2->db) { sqlite3_close(w2->db); w2->db = NULL; }
    join_scratch_clear(w2->data_path);
    w2->server = NULL;
    free(w2);

    if (adopted != 0) return -1;

    /* Open the main witness on the adopted successor — the SAME path a
     * restart takes (scan → open → post-open gate arms ingress). */
    if (nodus_witness_scan_chain_db(w) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "adopted successor did not open — "
                      "fatal joiner state");
        return -1;
    }

    /* R3 W3 delta 9 (register row R3-W3-C2c-15) — the cometbft server
     * binding, immediately, on THIS live `w`. The reference has no
     * mid-life adoption (a node starts with its genesis document already
     * on disk); the honest port of "this node now starts with this
     * genesis" is to run, right here, the SAME construction a process
     * start runs (`nodus_witness_init`'s `if (witness->v2_successor)`
     * block, nodus_witness.c) — `nodus_witness_cmt_live_init`, exported
     * for exactly this second call site (nodus_witness.h, right after
     * `nodus_witness_create_chain_db`).
     *
     * MEASURED without this call (Genesis Protocol harness,
     * `test_v2_join.sh` and `test_v2_partial_wipe.sh`'s restore, same
     * shape): the joiner received the bundle, re-derived, adopted, and
     * the post-open gate printed the COMETBFT role — then NOTHING. No
     * startup table was ever built, so `witness_cmt_tick`
     * (nodus_witness.c) found `cmt_node == NULL` and returned INT64_MAX
     * every tick, forever; there is no blocksync in this port, so the
     * node also never caught up any other way.
     *
     * PRECONDITIONS, proven by reading, not assumed: the scan just above
     * has already run `witness_post_open_gate` on `w` (the SAME gate
     * `nodus_witness_create_chain_db` runs at process start), so
     * `w->v2_successor` is true and `w->v2_chain32` is populated —
     * `nodus_cmt_live_init`'s own precondition. `w->server` and
     * `w->data_path` are the LIVE witness's, set once at process start;
     * `join_adopt` never touches either — it only set them on the
     * throwaway SCRATCH handle `w2` above (:114/:117), which is already
     * closed and freed by this point. And no tick can land between the
     * scan and this call: `join_adopt` runs synchronously inside
     * `nodus_witness_v2_join_tick`, itself called synchronously from
     * `nodus_witness_tick`'s own body — one function call inside one
     * tick, no thread, no re-entrant call, no yield point. */
    if (nodus_witness_cmt_live_init(w) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "adopted successor opened but the "
                      "cometbft server binding could not be built — "
                      "fatal joiner state");
        return -1;
    }

    w->v2_join.active = 0;
    join_reset_acc(w);
    QGP_LOG_INFO(LOG_TAG, "%s", "successor genesis adopted from a peer "
                 "bundle (pin matched) — the cometbft server binding is "
                 "built and will go live at the next tick (genesis time "
                 "is already in the past for a joiner), catching up "
                 "through the consensus reactor's own stored-part "
                 "gossip");
    return 0;
}

void nodus_witness_v2_join_handle_gbundle_r(nodus_witness_t *w,
                                            const char *peer_id,
                                            const nodus_t3_w_v2_gbundle_r_t *r) {
    if (!w || !peer_id || !r || !w->v2_join.active) return;

    /* Red-team H2: a chunk is taken ONLY as the answer to this joiner's
     * one outstanding request — from the peer it asked, for the offset
     * it asked (nodus_witness_p2p_gb_take). Anything else is DROPPED
     * before it can cost a buffer or a join_adopt (scratch DB +
     * migrations): an unsolicited response, a second copy, or a late
     * honest answer to a request the tick has since replaced. The sender
     * is NOT stopped — that late honest answer looks exactly like an
     * unsolicited one (fix proposals 2026-09-27 "REVISED" H2). No
     * reference counterpart: channel 0x70 is nodus's own (R-P2P-5). */
    if (!nodus_witness_p2p_gb_take(w->p2p, peer_id, r->offset)) {
        QGP_LOG_DEBUG(LOG_TAG, "0x70 response from %s @%llu is not the "
                      "outstanding request — dropped", peer_id,
                      (unsigned long long)r->offset);
        return;
    }
    /* The take matched the ONE outstanding request, and every request
     * goes to the current source (nodus_witness_v2_join_tick) — so this
     * IS the source's answer. A source replaced since (its request was
     * replaced by the new source's in the host) cannot get here. */
    if (strcmp(peer_id, w->v2_join.src) != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "0x70 response from %s: not this download's "
                      "source — dropped", peer_id);
        return;
    }
    w->v2_join.awaiting = false;

    /* Every check below is the SOURCE refusing its chunk (decision
     * 2026-09-27-p2p-fix-2.md (3)): it answered the request we sent with
     * something this download cannot use, so the download from it ends
     * and the next peer starts over (join_fail_source).
     * R3 W3 (D-24 rev 4 (1)): the pin IS the 32-byte chain id — `r->pin`
     * and `r->chain` now name the same identity (nodus_witness_v2_sync2.c
     * answers both with `w->v2_chain32`), so the two separate comparisons
     * this used to be collapse into ONE — the pin is the only anchor. */
    if (memcmp(r->pin, w->v2_join.pin, 32) != 0) {
        join_fail_source(w, "a chunk for another pin");
        return;
    }
    if (r->total == 0 || r->total > V2JOIN_BUNDLE_MAX || r->chunk_len == 0) {
        join_fail_source(w, "an empty chunk or a total out of range");
        return;
    }

    /* Contiguous append only: a chunk must start exactly where we are
     * (the offset was ours — the take compared it — so this holds; kept
     * as the buffer's own guard). */
    if (r->offset != w->v2_join.acc_len ||
        (uint64_t)w->v2_join.acc_len + r->chunk_len > r->total) {
        join_fail_source(w, "a chunk past the bundle's end");
        return;
    }

    if (w->v2_join.acc_total == 0) {
        w->v2_join.acc = malloc((size_t)r->total);
        if (!w->v2_join.acc) return;
        w->v2_join.acc_total = (size_t)r->total;
    } else if (w->v2_join.acc_total != (size_t)r->total) {
        /* the total changed mid-transfer — the source serves another
         * bundle than it began with */
        join_fail_source(w, "its total changed mid-download");
        return;
    }

    memcpy(w->v2_join.acc + w->v2_join.acc_len, r->chunk, r->chunk_len);
    w->v2_join.acc_len += r->chunk_len;

    if (w->v2_join.acc_len < w->v2_join.acc_total) return;   /* more chunks */

    QGP_LOG_INFO(LOG_TAG, "genesis bundle fully received (%zu bytes) from "
                 "%s — re-deriving against the local pin",
                 w->v2_join.acc_len, w->v2_join.src);
    if (join_adopt(w) != 0) {
        /* Rejected / faulted: the whole bundle came from the source, so
         * the source is excluded (join_fail_source drops the buffer) and
         * the tick re-pulls from offset 0 from the next peer. */
        join_fail_source(w, "its bundle failed at adopt");
    }
}

/* Say — at most once a minute — WHY a joiner is not asking anyone.
 *
 * A stuck joiner used to log its arm line and then nothing at all, which
 * is how one silently sat for 9 minutes without a chain while its peers
 * all held one. Both early returns below are invisible states; this makes
 * them nameable from a log file. */
static void join_diag(nodus_witness_t *w, uint64_t now, const char *why) {
    if (w->v2_join.last_diag_ms != 0 &&
        now - w->v2_join.last_diag_ms < 60000ULL) return;
    w->v2_join.last_diag_ms = now;
    QGP_LOG_WARN(LOG_TAG, "joiner is NOT requesting a genesis bundle: %s "
                 "(p2p peers=%d, bytes accumulated=%zu) — it holds no "
                 "chain and is serving DHT only",
                 why, nodus_witness_p2p_peer_count(w->p2p),
                 w->v2_join.acc_len);
}

void nodus_witness_v2_join_tick(nodus_witness_t *w) {
    if (!w || !w->v2_join.active) return;

    uint64_t now = join_mono_ms();
    int n_peers = nodus_witness_p2p_peer_count(w->p2p);
    if (n_peers <= 0) {
        join_diag(w, now, w->p2p ? "no p2p peer connected"
                                 : "no p2p host (port 4004 is not running)");
        return;
    }

    if (w->v2_join.last_req_ms != 0 &&
        now - w->v2_join.last_req_ms < V2JOIN_REQ_INTERVAL_MS)
        return;

    /* One request per interval, to this download's ONE source, at the
     * accumulated offset (the file's "ONE SOURCE" block). The response
     * accumulates; when complete, the handler adopts.
     *
     * A source that left no answer for a whole interval refused its
     * chunk: it may decline for a reason a joiner cannot see — it holds
     * no chain itself (another joiner), it is not serving yet — so it is
     * excluded and the next peer is asked. The choice of a NEW source
     * walks the switch's peer set (its List() order) round-robin from a
     * cursor that advances once per choice (measured before rotation
     * existed: 1 of 13 simultaneous joiners never adopted, asking the
     * same unhelpful peer forever). Every connected peer has
     * authenticated its identity and our chain id (the pin) at the secret
     * connection and NodeInfo (P2P-PORT F5); the serve side authorizes by
     * the pin equalling its committed genesis. */
    if (w->v2_join.awaiting && w->v2_join.src[0] != '\0') {
        join_fail_source(w, "no answer within the request interval");
    }
    if (w->v2_join.src[0] != '\0' &&
        !nodus_witness_p2p_has_peer(w->p2p, w->v2_join.src)) {
        QGP_LOG_INFO(LOG_TAG, "genesis bundle source %s disconnected — its "
                     "bytes are dropped, the next peer starts from offset 0",
                     w->v2_join.src);
        w->v2_join.src[0] = '\0';
        w->v2_join.awaiting = false;
        join_reset_acc(w);
    }
    if (w->v2_join.src[0] == '\0') {
        if (!join_pick_source(w, n_peers)) {
            join_diag(w, now, "the p2p peer set changed under the cursor");
            return;
        }
        join_reset_acc(w);                    /* a new source: offset 0 */
    }

    nodus_t3_w_v2_gbundle_q_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.chain, w->v2_join.pin, 32);
    memcpy(req.pin, w->v2_join.pin, 32);
    req.offset = (uint64_t)w->v2_join.acc_len;

    uint8_t buf[128];
    size_t len = 0;
    /* Sent through the host so it remembers (peer, offset) as the one
     * outstanding request — the only answer handle_gbundle_r takes. A
     * request that could not be queued is THIS node's send failure, not
     * the source's: it is retried next interval with the same source and
     * never counted as "no answer" (ORCHESTRATOR repair — verifier F3:
     * `awaiting` set on a failed send excluded an honest source). */
    bool queued = nodus_t3_gbundle_q_encode(&req, buf, sizeof(buf), &len) == 0 &&
                  nodus_witness_p2p_gb_request(w->p2p, w->v2_join.src,
                                               req.offset, buf, len);
    if (!queued)
        QGP_LOG_WARN(LOG_TAG, "genesis bundle request to %s not queued — "
                     "retrying next interval", w->v2_join.src);
    w->v2_join.awaiting = queued;
    w->v2_join.last_req_ms = now;
}
