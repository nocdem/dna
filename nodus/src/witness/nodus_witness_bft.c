/**
 * Nodus — Witness BFT Consensus Engine
 *
 * BFT consensus for DNAC transaction witnessing.
 * Ported from dnac/src/bft/consensus.c (2168 lines).
 *
 * Key adaptations from DNAC:
 *   - No pthreads (single-threaded in epoll loop)
 *   - CBOR via nodus_t3_encode/decode (not binary serialization)
 *   - Direct nodus_witness_db calls (not callback indirection)
 *   - Signing handled by T3 encode layer
 *
 * Consensus flow: PROPOSE → PREVOTE → PRECOMMIT → COMMIT
 *   - Genesis requires unanimous (N/N) approval
 *   - Normal transactions require quorum (2f+1)
 *   - Round timeout triggers view change
 */

#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_epoch.h"
#include "witness/nodus_witness_emission.h"
#include "witness/nodus_witness_genesis_seed.h"
#include "nodus/nodus_chain_config.h"          /* Hard-Fork v1 apply dispatch */
#include "protocol/nodus_tier3.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_u128.h"
#include "crypto/utils/qgp_fingerprint.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/transaction.h"   /* DNAC_STAKE_PURPOSE_TAG_LEN */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-BFT"

/* Forward declaration — defined near bft_check_timeout */
static void round_state_free_batch(nodus_witness_round_state_t *rs);
static void bft_emit_batch_replies(nodus_witness_t *w);

/* Phase 6 commit wrappers — defined later in this file. Forward
 * declarations let the Phase 7 / Task 7.6 dispatchers (commit_block,
 * the local batch path, the remote batch path) call them without
 * pulling the test-only nodus_witness_bft_internal.h header. */
int nodus_witness_commit_genesis(nodus_witness_t *w,
                                   const uint8_t *tx_hash,
                                   const uint8_t *tx_data,
                                   uint32_t tx_len,
                                   uint64_t timestamp,
                                   const uint8_t *proposer_id);
int nodus_witness_commit_batch(nodus_witness_t *w,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id);

/* ── Time helper ─────────────────────────────────────────────────── */

static uint64_t time_ms(void) {
    return nodus_time_now() * 1000ULL;
}

/* ── Replay prevention ───────────────────────────────────────────── */

/* ── Nonce hash table (HIGH-2: replaces linear-scan array) ──────── */

#define NONCE_BUCKET_COUNT  256
#define NONCE_TTL_SECS      300  /* 5 minutes */
#define NONCE_MAX_TOTAL     10000  /* M-35: Max entries to prevent memory exhaustion */

typedef struct nonce_node {
    uint8_t  sender_id[NODUS_T3_WITNESS_ID_LEN];
    uint64_t nonce;
    uint64_t timestamp;
    struct nonce_node *next;
} nonce_node_t;

static nonce_node_t *nonce_buckets[NONCE_BUCKET_COUNT];
static uint32_t nonce_total_count = 0;  /* M-35: Track total entries */

static uint32_t nonce_hash_fn(const uint8_t *sender_id, uint64_t nonce) {
    uint32_t h = 0x811c9dc5;
    for (int i = 0; i < NODUS_T3_WITNESS_ID_LEN; i++) {
        h ^= sender_id[i];
        h *= 0x01000193;
    }
    for (int i = 0; i < 8; i++) {
        h ^= (uint8_t)(nonce >> (i * 8));
        h *= 0x01000193;
    }
    return h % NONCE_BUCKET_COUNT;
}

static void nonce_evict_bucket(uint32_t bucket, uint64_t now) {
    nonce_node_t **pp = &nonce_buckets[bucket];
    while (*pp) {
        if (now - (*pp)->timestamp >= NONCE_TTL_SECS) {
            nonce_node_t *expired = *pp;
            *pp = expired->next;
            free(expired);
            if (nonce_total_count > 0) nonce_total_count--;
        } else {
            pp = &(*pp)->next;
        }
    }
}

/* M-35: Evict oldest entries across all buckets when table is full */
static void nonce_evict_oldest(void) {
    uint64_t oldest_ts = UINT64_MAX;
    uint32_t oldest_bucket = 0;

    /* Find bucket containing the oldest entry */
    for (uint32_t b = 0; b < NONCE_BUCKET_COUNT; b++) {
        for (nonce_node_t *n = nonce_buckets[b]; n; n = n->next) {
            if (n->timestamp < oldest_ts) {
                oldest_ts = n->timestamp;
                oldest_bucket = b;
            }
        }
    }

    /* Remove all entries from that bucket (batch eviction) */
    nonce_node_t *head = nonce_buckets[oldest_bucket];
    nonce_buckets[oldest_bucket] = NULL;
    while (head) {
        nonce_node_t *next = head->next;
        free(head);
        if (nonce_total_count > 0) nonce_total_count--;
        head = next;
    }
}

static bool is_replay(const uint8_t *sender_id, uint64_t nonce,
                       uint64_t timestamp) {
    uint64_t now = (uint64_t)time(NULL);

    /* Reject messages outside ±5 minute window */
    if (timestamp > now + 300 || timestamp + 300 < now)
        return true;

    uint32_t bucket = nonce_hash_fn(sender_id, nonce);

    /* Evict expired entries from this bucket */
    nonce_evict_bucket(bucket, now);

    /* Check for duplicate */
    for (nonce_node_t *n = nonce_buckets[bucket]; n; n = n->next) {
        if (n->nonce == nonce &&
            memcmp(n->sender_id, sender_id, NODUS_T3_WITNESS_ID_LEN) == 0)
            return true;
    }

    /* M-35: Evict oldest bucket if at capacity */
    if (nonce_total_count >= NONCE_MAX_TOTAL) {
        nonce_evict_oldest();
    }

    /* Insert new entry at head (no mutex needed — single-threaded epoll) */
    nonce_node_t *node = malloc(sizeof(nonce_node_t));
    if (node) {
        memcpy(node->sender_id, sender_id, NODUS_T3_WITNESS_ID_LEN);
        node->nonce = nonce;
        node->timestamp = timestamp;
        node->next = nonce_buckets[bucket];
        nonce_buckets[bucket] = node;
        nonce_total_count++;
    }

    return false;
}

/* ── Chain ID validation ─────────────────────────────────────────── */

/**
 * CRITICAL-2: Verify message chain_id matches our configured chain_id.
 * Prevents cross-zone replay attacks when multi-zone is enabled.
 * All-zero chain_id means pre-genesis / default zone — skip check.
 */
static bool verify_chain_id(nodus_witness_t *w, const uint8_t *msg_chain_id) {
    static const uint8_t zero[32] = {0};
    /* If our chain_id is not set, skip validation (pre-genesis) */
    if (memcmp(w->chain_id, zero, 32) == 0) return true;
    /* If message chain_id matches ours, OK */
    if (memcmp(w->chain_id, msg_chain_id, 32) == 0) return true;
    fprintf(stderr, "%s: chain_id mismatch — rejecting message\n", LOG_TAG);
    return false;
}

/* ── Nonce generation ────────────────────────────────────────────── */

static uint64_t generate_nonce(void) {
    uint64_t nonce;
    /* CRITICAL-3: Abort on RNG failure — no weak fallback */
    if (nodus_random((uint8_t *)&nonce, sizeof(nonce)) != 0) {
        fprintf(stderr, "%s: FATAL: Cannot generate secure nonce\n", LOG_TAG);
        abort();
    }
    return nonce;
}

/* ── F17 A2: committee helpers ───────────────────────────────────────
 *
 * Under F17 consensus authority comes from the chain-derived committee,
 * not the gossip roster. These helpers centralize the lookup + pubkey-
 * based membership checks used by is_leader, handle_propose, handle_vote
 * and the round-start path.
 *
 * The committee accessor (nodus_committee_get_for_block) hits a
 * per-epoch cache, so repeated calls within the same epoch are O(1).
 * ──────────────────────────────────────────────────────────────────── */

/** Find a pubkey in a committee array. Returns the slot index or -1. */
static int committee_find_pubkey(const nodus_committee_member_t *arr,
                                   int count, const uint8_t *pk) {
    if (!arr || !pk) return -1;
    for (int i = 0; i < count; i++) {
        if (memcmp(arr[i].pubkey, pk, DNAC_PUBKEY_SIZE) == 0) return i;
    }
    return -1;
}

/** Load the committee authoritative for a given block height.
 *
 * F17 A5 — pre-genesis the chain DB is not yet created (w->db == NULL),
 * so nodus_committee_get_for_block would return -1. Treat that case
 * as "empty committee" (count=0, rc=0) so callers can take the
 * gossip-roster bootstrap fallback. This matches the semantic
 * "no on-chain validator set exists yet."
 *
 * @return 0 on success (count_out populated, possibly 0 for pre-genesis
 *         or empty validator table), -1 on DB error after DB is open. */
static int load_committee_at_height(nodus_witness_t *w,
                                      uint64_t block_height,
                                      nodus_committee_member_t *out,
                                      int max_entries,
                                      int *count_out) {
    if (!w || !out || !count_out) return -1;
    *count_out = 0;
    if (!w->db) return 0;   /* pre-genesis: no chain DB, no committee */
    return nodus_committee_get_for_block(w, block_height, out,
                                           max_entries, count_out);
}

/** Recompute w->bft_config from the committee for `block_height`.
 *
 * Authoritative source for quorum/f_tolerance. Replaces the legacy
 * gossip-roster-driven bft_config_init called from roster_add /
 * epoch-tick paths.
 *
 * F17 A5 bootstrap — if the committee is empty (chain has no
 * validators yet, i.e. pre-genesis) the function falls back to the
 * gossip-roster-derived quorum. This is ONLY reachable for the
 * genesis consensus round itself; once genesis commits and inserts
 * initial_validators into the validators table, subsequent rounds
 * always see a populated committee. Genesis security comes from
 * genesis_verify (Rule P — distinct pubkeys, supply invariant) +
 * honest-majority, not from committee gating.
 *
 * @return 0 on success (consensus_active may be true or false based on
 *         config state), -1 on DB error (w->bft_config left
 *         untouched, caller should fail-closed). */
static int refresh_bft_config_from_committee(nodus_witness_t *w,
                                                uint64_t block_height) {
    if (!w) return -1;
    nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
    int count = 0;
    if (load_committee_at_height(w, block_height, committee,
                                   DNAC_COMMITTEE_SIZE, &count) != 0) {
        return -1;
    }
    if (count == 0) {
        /* F17 A5 bootstrap — pre-genesis fallback to gossip roster. */
        nodus_witness_bft_config_init(&w->bft_config,
                                        w->roster.n_witnesses);
    } else {
        nodus_witness_bft_config_init(&w->bft_config, (uint32_t)count);
    }
    return 0;
}

/* ── Config ──────────────────────────────────────────────────────── */

void nodus_witness_bft_config_init(nodus_witness_bft_config_t *cfg,
                                     uint32_t n) {
    if (!cfg) return;

    /* F17 A1 — clamp at committee size. Callers may pass gossip-roster
     * size (up to NODUS_T3_MAX_WITNESSES = 128) during the A1→A3
     * interim, but vote arrays only hold DNAC_COMMITTEE_SIZE entries.
     * Computing quorum against a larger n would yield an unreachable
     * threshold. A3 will eliminate the gossip-roster path entirely;
     * this clamp is the safety net until then. */
    if (n > DNAC_COMMITTEE_SIZE) n = DNAC_COMMITTEE_SIZE;

    cfg->n_witnesses = n;

    /* Below minimum — consensus disabled */
    if (n < NODUS_T3_MIN_WITNESSES) {
        cfg->f_tolerance = 0;
        cfg->quorum = 0;
        cfg->round_timeout_ms = 0;
        cfg->viewchg_timeout_ms = 0;
        cfg->max_view_changes = 0;
        return;
    }

    /* Phase 8 / Task 8.1 — derive the quorum from n directly via the
     * standard PBFT safety formula (2n)/3 + 1, and keep f_tolerance as
     * informational only.
     *
     * The old formula 2*f + 1 with f = (n-1)/3 was UNSAFE for cluster
     * sizes where n ∉ {3f+1}. Example: n=5 → f=(5-1)/3=1 → q=3. Two
     * disjoint quorums of 3 from a 5-witness cluster can overlap on
     * just 1 witness — NOT > f, which means both quorums can be
     * simultaneously honest-majority while disagreeing. (2n)/3+1 gives
     * q=4 for n=5, restoring the >f intersection guarantee.
     *
     * Production cluster (n=7) is unaffected — both formulas give q=5.
     * Only n=5, 8, 11, ... see a value change. See Phase 8 release
     * notes; this is a silent security upgrade. */
    cfg->f_tolerance = (n - 1) / 3;
    cfg->quorum = (2 * n) / 3 + 1;

    /* Timeouts */
    cfg->round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
    cfg->viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;
    cfg->max_view_changes = NODUS_T3_MAX_VIEW_CHANGES;
}

bool nodus_witness_bft_consensus_active(const nodus_witness_t *w) {
    return w && w->bft_config.quorum > 0;
}

/* ── Leader election ─────────────────────────────────────────────── */

int nodus_witness_bft_leader_index(uint64_t epoch, uint32_t view, int n) {
    if (n <= 0) return -1;
    return (int)((epoch + view) % (uint64_t)n);
}

bool nodus_witness_bft_is_leader(nodus_witness_t *w) {
    if (!w) return false;

    /* F17 A3 — leader is determined by the chain-derived committee for
     * the next block. F17 A5 bootstrap — if committee empty (pre-
     * genesis), fall back to gossip roster. */
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
    int count = 0;
    int my_idx = -1;
    if (load_committee_at_height(w, next_bh, committee,
                                   DNAC_COMMITTEE_SIZE, &count) == 0 &&
        count > 0) {
        my_idx = committee_find_pubkey(committee, count,
                                         w->server->identity.pk.bytes);
    } else {
        /* Pre-genesis bootstrap: gossip-roster-based leader selection.
         * Only active for the genesis round itself. */
        count = (int)w->roster.n_witnesses;
        my_idx = nodus_witness_roster_find(&w->roster, w->my_id);
    }

    if (my_idx < 0 || count <= 0) return false;
    uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
    int leader = nodus_witness_bft_leader_index(epoch, w->current_view,
                                                  count);
    return leader == my_idx;
}

/* ── Roster ──────────────────────────────────────────────────────── */

int nodus_witness_roster_find(const nodus_witness_roster_t *roster,
                                const uint8_t *witness_id) {
    if (!roster || !witness_id) return -1;

    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (memcmp(roster->witnesses[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return (int)i;
    }
    return -1;
}

int nodus_witness_roster_add(nodus_witness_t *w,
                               const nodus_witness_roster_entry_t *entry) {
    if (!w || !entry) return -1;

    if (w->roster.n_witnesses >= NODUS_T3_MAX_WITNESSES)
        return -1;

    /* Duplicate check */
    if (nodus_witness_roster_find(&w->roster, entry->witness_id) >= 0)
        return 0;

    memcpy(&w->roster.witnesses[w->roster.n_witnesses], entry,
           sizeof(nodus_witness_roster_entry_t));
    w->roster.n_witnesses++;
    w->roster.version++;

    /* F17 A4 — roster is now transport-only (peer discovery +
     * witness_id↔pubkey map). BFT config is refreshed from the chain
     * committee at round-start. No my_index tracking needed: self-
     * identity in consensus paths is resolved via
     * w->server->identity.pk against the committee pubkey list. */

    fprintf(stderr, "%s: roster add (now %u witnesses, transport)\n",
            LOG_TAG, w->roster.n_witnesses);
    return 0;
}

/* ── Fill T3 message header with identity ────────────────────────── */

static void fill_header(nodus_witness_t *w, nodus_t3_header_t *hdr) {
    hdr->version = NODUS_T3_BFT_PROTOCOL_VER;
    hdr->round = w->current_round;
    hdr->view = w->current_view;
    memcpy(hdr->sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    hdr->timestamp = (uint64_t)time(NULL);
    hdr->nonce = generate_nonce();
    memcpy(hdr->chain_id, w->chain_id, 32);
}

/* ── Broadcast T3 message to all connected witness peers ─────────── */

int nodus_witness_bft_broadcast(nodus_witness_t *w, nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* Fill header with our identity */
    fill_header(w, &msg->header);

    /* Set method string from type */
    const char *method = nodus_t3_type_to_method(msg->type);
    if (method)
        snprintf(msg->method, sizeof(msg->method), "%s", method);

    /* Encode (signs with our secret key) */
    uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    if (nodus_t3_encode(msg, &w->server->identity.sk,
                         buf, sizeof(buf), &len) != 0) {
        fprintf(stderr, "%s: failed to encode T3 %s\n",
                LOG_TAG, msg->method);
        return -1;
    }

    /* Send to all connected identified peers */
    int sent = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn && w->peers[i].identified) {
            if (nodus_tcp_send(w->peers[i].conn, buf, len) == 0)
                sent++;
        }
    }

    return sent;
}

/* ── Commit to database ──────────────────────────────────────────── */

/**
 * Update UTXO set from committed transaction data.
 *
 * Parses the serialized transaction to extract outputs, then:
 *   - SPEND: removes spent UTXOs (by input nullifiers)
 *   - ALL: adds new output UTXOs (computing nullifier from fingerprint + seed)
 *
 * Called inside the same SQLite transaction as nullifier/genesis writes.
 *
 * DNAC v1 wire format (outputs section):
 *   Header: version(1) + type(1) + timestamp(8) + tx_hash(64) = 74
 *   Inputs: count(1) + [nullifier(64) + amount(8)] * N
 *   Outputs: count(1) + [version(1) + fingerprint(129) + amount(8) + seed(32) + memo_len(1) + memo(n)] * M
 */

/* ── Derive chain_id = SHA3-256(fp_bytes || tx_hash) ─────────────── */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Derive chain_id from genesis fingerprint and tx_hash.
 * chain_id = SHA3-256( fp_bytes(64) || tx_hash(64) )
 *
 * @param genesis_fp  128-char hex fingerprint string
 * @param tx_hash     64-byte transaction hash
 * @param chain_id_out 32-byte output buffer
 * @return 0 on success, -1 on error
 */
static int nodus_derive_chain_id(const char *genesis_fp,
                                  const uint8_t *tx_hash,
                                  uint8_t *chain_id_out) {
    if (!genesis_fp || !tx_hash || !chain_id_out) return -1;

    size_t fp_len = strnlen(genesis_fp, 129);
    if (fp_len != 128) {
        fprintf(stderr, "%s: derive_chain_id: bad fingerprint len %zu\n",
                LOG_TAG, fp_len);
        return -1;
    }

    /* Convert hex fingerprint to 64 binary bytes */
    uint8_t fp_bytes[64];
    for (size_t i = 0; i < 64; i++) {
        int hi = hex_nibble(genesis_fp[i * 2]);
        int lo = hex_nibble(genesis_fp[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "%s: derive_chain_id: invalid hex at pos %zu\n",
                    LOG_TAG, i * 2);
            return -1;
        }
        fp_bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    /* Concatenate: fp_bytes(64) || tx_hash(64) = 128 bytes */
    uint8_t data[64 + NODUS_T3_TX_HASH_LEN];
    memcpy(data, fp_bytes, 64);
    memcpy(data + 64, tx_hash, NODUS_T3_TX_HASH_LEN);

    if (qgp_sha3_256(data, sizeof(data), chain_id_out) != 0)
        return -1;

    /* Canonical chain_id layout: the first 16 bytes (128 bits) are the
     * authoritative identifier; bytes 16-31 are ALWAYS zero. This matches
     * the format produced by witness_scan_chain_db on restart (which only
     * parses 16 bytes out of the filename) so both paths converge on the
     * same in-memory value. Without this, a live-genesis node ends up
     * with full-32-byte chain_id in memory while a restarted node has
     * 16-byte + 16-zero, causing bogus CHAIN_QUORUM dissent and sticky
     * quarantine that blocks forwarded dnac_spend requests from ever
     * reaching the leader's handler. */
    memset(chain_id_out + 16, 0, 16);
    return 0;
}

/* v0.16 stage C.3 — TX-type-aware fee burn helper.
 *
 * In v0.16 the reward system moved from "fees pooled + redistributed"
 * (accumulator model) to "fees burn immediately + rewards come from
 * inflation mint" (push-settlement model). route_tx_fee is the single
 * destination for every TX's committed_fee — it always adds to
 * supply_tracking.total_burned, regardless of tx_type.
 *
 * The tx_type parameter is kept in the signature for future variants
 * (e.g. per-type burn fraction); today it is intentionally unused.
 *
 * @param w            witness context (DB must be open)
 * @param tx_type      NODUS_W_TX_* (unused in v0.16 — see above)
 * @param committed_fee  fee amount in raw DNAC units (may be 0)
 * @param tx_hash      tx_hash the fee came from (for the
 *                     supply_tracking.last_tx_hash audit trail)
 * @return 0 on success or no-op (fee == 0), -1 on overflow / DB error
 */
static int route_tx_fee(nodus_witness_t *w, uint32_t tx_type,
                          uint64_t committed_fee, const uint8_t *tx_hash) {
    (void)tx_type;
    if (committed_fee == 0) return 0;
    return nodus_witness_supply_add_burned(w, committed_fee, tx_hash);
}

static int update_utxo_set(nodus_witness_t *w,
                              const uint8_t *tx_hash,
                              uint8_t tx_type,
                              const uint8_t *const *nullifiers,
                              uint8_t nullifier_count,
                              const uint8_t *tx_data,
                              uint32_t tx_len,
                              uint64_t *fee_out) {
    if (!tx_data || tx_len < 75) {
        fprintf(stderr, "%s: update_utxo_set: invalid tx_data (ptr=%p len=%u)\n",
                LOG_TAG, (void *)tx_data, tx_len);
        return -1;
    }

    /* For SPEND: remove spent UTXOs by input nullifiers */
    if (tx_type != NODUS_W_TX_GENESIS) {
        for (int i = 0; i < nullifier_count; i++) {
            nodus_witness_utxo_remove(w, nullifiers[i]);
        }
    }

    /* Parse to output section:
     * Header: version(1) + type(1) + timestamp(8) + tx_hash(64) = 74 */
    size_t offset = 74;
    if (offset >= tx_len) {
        fprintf(stderr, "%s: update_utxo_set: tx_data too short for inputs (len=%u)\n",
                LOG_TAG, tx_len);
        return -1;
    }

    /* Parse inputs and sum their amounts (for fee calculation) */
    uint8_t input_count = tx_data[offset++];
    uint64_t total_input = 0;
    for (int i = 0; i < input_count; i++) {
        offset += NODUS_T3_NULLIFIER_LEN;  /* skip nullifier (64) */
        if (offset + 8 + 64 > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: input %d truncated at amount/token_id\n",
                    LOG_TAG, i);
            return -1;
        }
        uint64_t in_amt;
        memcpy(&in_amt, tx_data + offset, 8);
        total_input += in_amt;
        offset += 8;   /* amount */
        offset += 64;  /* token_id */
    }

    /* Read output count */
    if (offset >= tx_len) {
        fprintf(stderr, "%s: update_utxo_set: tx_data truncated at outputs (offset=%zu len=%u)\n",
                LOG_TAG, offset, tx_len);
        return -1;
    }
    uint8_t output_count = tx_data[offset++];
    if (output_count > NODUS_T3_MAX_TX_OUTPUTS) {
        fprintf(stderr, "%s: update_utxo_set: output_count %u exceeds max %d\n",
                LOG_TAG, output_count, NODUS_T3_MAX_TX_OUTPUTS);
        return -1;
    }

    uint64_t block_height = nodus_witness_block_height(w) + 1;
    int stored = 0;
    uint64_t total_output = 0;

    for (int i = 0; i < output_count; i++) {
        /* Minimum output: version(1) + fp(129) + amount(8) + token_id(64) + seed(32) + memo_len(1) = 235 */
        if (offset + 235 > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: output %d truncated (need %zu, have %u)\n",
                    LOG_TAG, i, offset + 235, tx_len);
            return -1;
        }

        offset += 1;  /* output version */

        const char *fingerprint = (const char *)(tx_data + offset);
        offset += 129;  /* fingerprint (128 hex + null) */

        uint64_t amount;
        memcpy(&amount, tx_data + offset, 8);
        offset += 8;
        total_output += amount;

        /* Read token_id (64 bytes — zeros = native DNAC) */
        const uint8_t *output_token_id = tx_data + offset;
        offset += 64;

        const uint8_t *nullifier_seed = tx_data + offset;
        offset += 32;

        uint8_t memo_len = tx_data[offset++];
        if (offset + memo_len > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: memo truncated at output %d\n",
                    LOG_TAG, i);
            return -1;
        }
        offset += memo_len;

        /* Compute nullifier = SHA3-512(fingerprint_str + nullifier_seed) */
        size_t fp_len = strnlen(fingerprint, 128);
        uint8_t nul_input[256];
        memcpy(nul_input, fingerprint, fp_len);
        memcpy(nul_input + fp_len, nullifier_seed, 32);

        nodus_key_t nul_hash;
        if (nodus_hash(nul_input, fp_len + 32, &nul_hash) != 0) {
            fprintf(stderr, "%s: update_utxo_set: hash failed for output %d\n",
                    LOG_TAG, i);
            return -1;
        }

        if (nodus_witness_utxo_add(w, nul_hash.bytes, fingerprint,
                                      amount, tx_hash, (uint32_t)i, block_height,
                                      output_token_id) == 0) {
            stored++;
        }
    }

    /* ── Burn UTXO for fee ──────────────────────────────────────── */
    /* Determine fee token_id from first input (zeros = native DNAC).
     * For token transfers, fee is charged in the same token being sent;
     * for TOKEN_CREATE, fee is always native DNAC (enforced below). */
    uint8_t fee_token_id[64] = {0};
    if (tx_type != NODUS_W_TX_GENESIS && nullifier_count > 0 && tx_len >= 74 + 1 + 64 + 8 + 64) {
        /* Input layout: nullifier(64) + amount(8) + token_id(64)
         * First input's token_id starts at offset 74 + 1 + 64 + 8 = 147 */
        memcpy(fee_token_id, tx_data + 74 + 1 + 64 + 8, 64);
    }

    uint64_t fee = 0;
    if (tx_type == NODUS_W_TX_TOKEN_CREATE) {
        /* TOKEN_CREATE: fee = input DNAC - change DNAC output.
         * total_output includes token genesis supply (different token),
         * so we sum only native DNAC outputs for fee calculation. */
        uint8_t zeros[64];
        memset(zeros, 0, sizeof(zeros));
        uint64_t dnac_output = 0;
        /* Re-parse outputs to sum only native DNAC amounts */
        size_t foff = 74; /* header */
        uint8_t ic = tx_data[foff++];
        for (int i = 0; i < ic; i++)
            foff += 64 + 8 + 64; /* nullifier + amount + token_id */
        uint8_t oc = tx_data[foff++];
        for (int i = 0; i < oc; i++) {
            foff += 1; /* version */
            foff += 129; /* fingerprint */
            uint64_t oamt;
            memcpy(&oamt, tx_data + foff, 8);
            foff += 8;
            uint8_t otid[64];
            memcpy(otid, tx_data + foff, 64);
            foff += 64;
            foff += 32; /* nullifier_seed */
            uint8_t mlen = tx_data[foff++];
            foff += mlen;
            if (memcmp(otid, zeros, 64) == 0)
                dnac_output += oamt;
        }
        if (total_input > dnac_output)
            fee = total_input - dnac_output;
        /* TOKEN_CREATE fee is always native DNAC (creating a new token
         * shouldn't charge fee in that token since creator doesn't own any yet). */
        memset(fee_token_id, 0, 64);
    } else if (tx_type != NODUS_W_TX_GENESIS && total_input > total_output) {
        fee = total_input - total_output;
    }

    /* v0.16 stage C.3 — fees burn directly into total_burned.
     *
     * route_tx_fee ignores tx_type in v0.16 (all fees burn regardless
     * of TX type), but carries the type parameter per design §2.2 so
     * future per-type routing variants (e.g. congestion-dependent
     * burn fraction) can slot in without another signature change.
     *
     * ⚠ Transitional SB-1 note:
     *   For SPEND + TOKEN_CREATE the implicit `fee = input_sum −
     *   output_sum` equals the user-intended fee — correctly burned.
     *   For STAKE / DELEGATE / UNDELEGATE / UNSTAKE the same
     *   subtraction inflates the fee by the stake/delegation amount
     *   (SB-1 original cause). Routing THAT figure to burn would
     *   reintroduce supply deflation. Until a committed_fee wire
     *   field lands (separate change), these TX types burn ZERO:
     *   apply_delegate + siblings treat all input − output as state-
     *   transition amount, and fee routing is skipped.
     *
     * Token-fee handling remains deferred: if fee_token_id is
     * non-zero (custom-token burn path), we also skip for v0.16.
     */
    bool is_stake_family = (tx_type == NODUS_W_TX_STAKE      ||
                            tx_type == NODUS_W_TX_DELEGATE   ||
                            tx_type == NODUS_W_TX_UNSTAKE    ||
                            tx_type == NODUS_W_TX_UNDELEGATE ||
                            tx_type == NODUS_W_TX_CHAIN_CONFIG);
    uint8_t zeros_tok[64] = {0};
    bool native_fee = (memcmp(fee_token_id, zeros_tok, 64) == 0);
    if (fee > 0 && !is_stake_family && native_fee) {
        if (route_tx_fee(w, tx_type, fee, tx_hash) != 0) {
            fprintf(stderr, "%s: route_tx_fee failed (fee=%llu)\n",
                    LOG_TAG, (unsigned long long)fee);
            return -1;
        }
    } else if (fee > 0) {
        fprintf(stderr,
                "%s: fee observed %llu (tx_type=%u, routing deferred)\n",
                LOG_TAG, (unsigned long long)fee, (unsigned)tx_type);
    }

    if (fee_out) *fee_out = fee;

    fprintf(stderr, "%s: UTXO set updated: -%d spent, +%d/%d outputs, fee=%llu (block %llu)\n",
            LOG_TAG,
            (tx_type != NODUS_W_TX_GENESIS) ? nullifier_count : 0,
            stored, output_count,
            (unsigned long long)fee,
            (unsigned long long)block_height);
    return 0;
}

/**
 * Write committed transaction state to witness database.
 * Called for both local commit (PRECOMMIT quorum) and remote commit.
 *
 * Operations (atomic via SQLite transaction):
 *   - Genesis: record genesis state
 *   - Non-genesis: add all nullifiers
 *   - Update UTXO set (remove spent, add outputs)
 * After atomic block:
 *   - Add ledger entry (audit trail)
 *   - Create block
 */
/**
 * Inner commit logic: nullifiers, UTXO, TX store, ledger.
 * Does NOT manage DB transaction (caller handles begin/commit).
 * Does NOT create blocks (caller handles block_add).
 * Used by both single-TX commit_block() and batch commit path.
 *
 * @return 0 on success, -1 on failure (caller should rollback)
 */
/* Supply invariant check (Phase 3 / Task 3.0).
 *
 * Returns true if any of the following invariants is currently violated
 * for the live witness DB state:
 *
 *   1. Native DNAC: registered genesis_supply must equal the sum of all
 *      utxo_set rows whose token_id is the native (zero) token.
 *   2. Per custom token: the registered supply (from the `tokens` table)
 *      must equal the sum of utxo_set rows for that token_id.
 *
 * Burn fees are tracked separately and excluded from the comparison
 * (genesis_supply is the post-burn target).
 *
 * Read-only — does not modify w->db. Side effect: emits an ERROR log
 * line via QGP_LOG_ERROR with the specific delta that violated. Phase
 * 6 SAVEPOINT attribution replay relies on these log lines to identify
 * the offending TX in a batch.
 *
 * Lifted from the inline check in the legacy commit_block_inner so
 * Phase 3.4 can move the call from per-TX to per-block (run once
 * inside finalize_block) without changing the check's semantics.
 */
/* v0.16 Stage F.1 — HARD supply invariant check.
 *
 * Replaces the pre-v0.16 advisory invariant (which used
 * dnac_total_minted_at against the old 16-DNAC halving curve). The
 * new model is bookkeeping-closed:
 *
 *   expected = genesis_supply + total_minted − total_burned
 *   observed = Σ utxo_set.amount (native DNAC only)
 *            + Σ validator.self_stake
 *            + Σ validator.total_delegated
 *            + Σ epoch_state.epoch_pool_accum (current + any queued)
 *
 * Any mismatch is a consensus-critical bug and MUST reject the block.
 *
 * Returns 0 when the invariant holds (including pre-genesis state
 * where supply_tracking is empty — no supply to conserve yet); -1
 * when violated; also -1 on internal DB error so the block is
 * rejected rather than committed on stale/partial reads.
 *
 * Read-only — does not mutate w->db.
 */
static int check_supply_invariant_v016(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    int sup_rc = nodus_witness_supply_get(w, &sup);
    if (sup_rc != 0) {
        /* Pre-genesis: the supply_tracking row hasn't been initialized.
         * Nothing to conserve yet — genesis commit populates it. */
        return 0;
    }

    /* expected, guarded against overflow + underflow. */
    uint64_t expected = sup.genesis_supply;
    if (sup.total_minted > UINT64_MAX - expected) {
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY INVARIANT: genesis+minted overflow genesis=%llu minted=%llu",
            (unsigned long long)sup.genesis_supply,
            (unsigned long long)sup.total_minted);
        return -1;
    }
    expected += sup.total_minted;
    if (sup.total_burned > expected) {
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY INVARIANT: burned > genesis+minted (burned=%llu exp=%llu)",
            (unsigned long long)sup.total_burned,
            (unsigned long long)expected);
        return -1;
    }
    expected -= sup.total_burned;

    /* observed = utxo_native + validator_stakes + delegations + epoch_pool */
    uint64_t utxo_native = 0;
    if (nodus_witness_utxo_sum_by_token(w, NULL, &utxo_native) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SUPPLY INVARIANT: utxo_sum_by_token failed");
        return -1;
    }

    uint64_t self_stake_sum = 0;
    uint64_t total_delegated_sum = 0;
    {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COALESCE(SUM(self_stake), 0), "
                "       COALESCE(SUM(total_delegated), 0) "
                "FROM validators",
                -1, &stmt, NULL) != SQLITE_OK) {
            /* Schema-missing in unit-test fixtures is acceptable; skip
             * these two terms (they'd be zero anyway). */
        } else {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                self_stake_sum      = (uint64_t)sqlite3_column_int64(stmt, 0);
                total_delegated_sum = (uint64_t)sqlite3_column_int64(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }
    }

    uint64_t epoch_pool_sum = 0;
    {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COALESCE(SUM(epoch_pool_accum), 0) FROM epoch_state",
                -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                epoch_pool_sum = (uint64_t)sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    }

    uint64_t observed = utxo_native;
    if (self_stake_sum > UINT64_MAX - observed) goto overflow_fail;
    observed += self_stake_sum;
    if (total_delegated_sum > UINT64_MAX - observed) goto overflow_fail;
    observed += total_delegated_sum;
    if (epoch_pool_sum > UINT64_MAX - observed) goto overflow_fail;
    observed += epoch_pool_sum;

    if (expected != observed) {
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY INVARIANT VIOLATION: expected=%llu observed=%llu delta=%lld "
            "(genesis=%llu minted=%llu burned=%llu utxo=%llu self_stake=%llu "
            "delegated=%llu pool=%llu)",
            (unsigned long long)expected,
            (unsigned long long)observed,
            (long long)((int64_t)observed - (int64_t)expected),
            (unsigned long long)sup.genesis_supply,
            (unsigned long long)sup.total_minted,
            (unsigned long long)sup.total_burned,
            (unsigned long long)utxo_native,
            (unsigned long long)self_stake_sum,
            (unsigned long long)total_delegated_sum,
            (unsigned long long)epoch_pool_sum);
        return -1;
    }
    return 0;

overflow_fail:
    QGP_LOG_ERROR(LOG_TAG,
        "SUPPLY INVARIANT: observed sum overflow (utxo=%llu self_stake=%llu "
        "delegated=%llu pool=%llu)",
        (unsigned long long)utxo_native,
        (unsigned long long)self_stake_sum,
        (unsigned long long)total_delegated_sum,
        (unsigned long long)epoch_pool_sum);
    return -1;
}

bool supply_invariant_violated(nodus_witness_t *w) {
    if (!w || !w->db) return false;

    bool violated = false;

    nodus_witness_supply_t sup;
    uint64_t utxo_total = 0;
    if (nodus_witness_supply_get(w, &sup) == 0 &&
        nodus_witness_utxo_sum_by_token(w, NULL, &utxo_total) == 0) {

        /* Effective supply = genesis + cumulative inflation-mint at current
         * height. Locks (validator.self_stake, delegation.amount) and pools
         * (validator.accumulator, block_fee_pool) are NOT in utxo_total but
         * ARE in effective_supply — so effective_supply > utxo_total is the
         * healthy case. Violation = utxo_total > effective_supply (impossible
         * without a bug) OR the delta exceeds known locks+pools sum. The
         * latter requires aggregating validator/delegation tables — left as
         * a Phase 10+ TODO; for now this check is advisory. */
        uint64_t block_h  = nodus_witness_block_height(w);
        uint64_t minted   = dnac_total_minted_at(block_h, 1ULL);
        uint64_t effective = sup.genesis_supply;
        /* Saturating add to guard against a pathological mint overflow. */
        if (minted > UINT64_MAX - effective) effective = UINT64_MAX;
        else effective += minted;

        if (utxo_total > effective) {
            QGP_LOG_ERROR(LOG_TAG,
                "SUPPLY INVARIANT VIOLATION (impossible): utxo_sum=%llu > "
                "effective=%llu (genesis=%llu minted=%llu height=%llu delta=%lld)",
                (unsigned long long)utxo_total,
                (unsigned long long)effective,
                (unsigned long long)sup.genesis_supply,
                (unsigned long long)minted,
                (unsigned long long)block_h,
                (long long)(utxo_total - effective));
            violated = true;
        } else if (sup.genesis_supply != utxo_total) {
            /* Advisory: delta should equal locks + pools. Full check TODO. */
            QGP_LOG_DEBUG(LOG_TAG,
                "supply: genesis=%llu minted=%llu effective=%llu utxo_sum=%llu "
                "locks+pools=%llu (height=%llu)",
                (unsigned long long)sup.genesis_supply,
                (unsigned long long)minted,
                (unsigned long long)effective,
                (unsigned long long)utxo_total,
                (unsigned long long)(effective - utxo_total),
                (unsigned long long)block_h);
        }
    }

    /* Per-token supply invariant: each custom token's UTXO sum must equal
     * its registered initial_supply (custom tokens have no fee burn). */
    nodus_witness_token_entry_t tokens[64];
    int token_count = 0;
    if (nodus_witness_token_list(w, tokens, 64, &token_count) == 0) {
        for (int ti = 0; ti < token_count; ti++) {
            uint64_t token_utxo_sum = 0;
            if (nodus_witness_utxo_sum_by_token(w, tokens[ti].token_id,
                                                  &token_utxo_sum) == 0) {
                if (tokens[ti].supply != token_utxo_sum) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "TOKEN SUPPLY INVARIANT VIOLATION: "
                        "token=%s initial=%llu utxo_sum=%llu (delta=%lld)",
                        tokens[ti].symbol,
                        (unsigned long long)tokens[ti].supply,
                        (unsigned long long)token_utxo_sum,
                        (long long)(tokens[ti].supply - token_utxo_sum));
                    violated = true;
                }
            }
        }
    }

    return violated;
}

/* ── Phase 8: Stake & delegation state mutation helpers ───────────── */

/* Compute the offset in tx_data at which the type-specific appended
 * fields begin (i.e. the byte right after the last signer's signature),
 * and (optionally) return a pointer to signers[0].pubkey inside tx_data.
 *
 * Wire layout (design 2.3; see dnac/src/transaction/serialize.c):
 *   header(74) then input_count(1) then inputs then output_count(1) then outputs
 *   then witness_count(1) then witnesses then signer_count(1) then signers
 *   then type-specific appended fields
 *   then has_chain_def(1) then optional chain_def blob.
 *
 * Returns 0 on success, -1 on malformed / truncated input. signer_pk_out
 * may be NULL.
 */
static int compute_appended_fields_offset(const uint8_t *tx_data,
                                            uint32_t tx_len,
                                            size_t *off_out,
                                            const uint8_t **signer_pk_out) {
    if (!tx_data || !off_out) return -1;

    /* header: version(1) + type(1) + timestamp(8) + tx_hash(64) = 74 */
    if (tx_len < 74) return -1;
    size_t off = 74;

    /* Inputs */
    if (off >= tx_len) return -1;
    uint8_t input_count = tx_data[off++];
    const size_t input_size = NODUS_T3_NULLIFIER_LEN + 8 + 64;
    if ((size_t)input_count * input_size > tx_len - off) return -1;
    off += (size_t)input_count * input_size;

    /* Outputs (variable memo) */
    if (off >= tx_len) return -1;
    uint8_t output_count = tx_data[off++];
    for (int i = 0; i < output_count; i++) {
        if (off + 235 > tx_len) return -1;
        off += 1 + 129 + 8 + 64 + 32;   /* version + fp + amount + token_id + seed */
        uint8_t memo_len = tx_data[off++];
        if (memo_len > tx_len - off) return -1;
        off += memo_len;
    }

    /* Witnesses */
    if (off >= tx_len) return -1;
    uint8_t witness_count = tx_data[off++];
    const size_t witness_size = 32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE;
    if ((size_t)witness_count * witness_size > tx_len - off) return -1;
    off += (size_t)witness_count * witness_size;

    /* Signers */
    if (off >= tx_len) return -1;
    uint8_t signer_count = tx_data[off++];
    if (signer_count == 0) return -1;
    const size_t signer_size = DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE;
    if ((size_t)signer_count * signer_size > tx_len - off) return -1;

    if (signer_pk_out) {
        /* signers[0].pubkey sits at current offset (pubkey first, sig after). */
        *signer_pk_out = tx_data + off;
    }
    off += (size_t)signer_count * signer_size;

    *off_out = off;
    return 0;
}

/* Sum native-DNAC (token_id all-zero) input and output amounts. Needed
 * by DELEGATE for exact delegation_amount = in - out - fee. Returns 0
 * on success, -1 on malformed tx_data. */
static int sum_native_dnac_in_out(const uint8_t *tx_data,
                                    uint32_t tx_len,
                                    uint64_t *in_sum_out,
                                    uint64_t *out_sum_out) {
    static const uint8_t zero_tid[64] = {0};

    if (!tx_data || !in_sum_out || !out_sum_out) return -1;
    if (tx_len < 74) return -1;

    uint64_t in_sum = 0;
    uint64_t out_sum = 0;

    size_t off = 74;

    if (off >= tx_len) return -1;
    uint8_t input_count = tx_data[off++];
    for (int i = 0; i < input_count; i++) {
        if (off + NODUS_T3_NULLIFIER_LEN + 8 + 64 > tx_len) return -1;
        off += NODUS_T3_NULLIFIER_LEN;
        uint64_t amt;
        memcpy(&amt, tx_data + off, 8);
        off += 8;
        const uint8_t *tid = tx_data + off;
        off += 64;
        if (memcmp(tid, zero_tid, 64) == 0) {
            in_sum += amt;
        }
    }

    if (off >= tx_len) return -1;
    uint8_t output_count = tx_data[off++];
    for (int i = 0; i < output_count; i++) {
        if (off + 235 > tx_len) return -1;
        off += 1 + 129;
        uint64_t amt;
        memcpy(&amt, tx_data + off, 8);
        off += 8;
        const uint8_t *tid = tx_data + off;
        off += 64;
        off += 32;
        uint8_t memo_len = tx_data[off++];
        if (memo_len > tx_len - off) return -1;
        off += memo_len;
        if (memcmp(tid, zero_tid, 64) == 0) {
            out_sum += amt;
        }
    }

    *in_sum_out = in_sum;
    *out_sum_out = out_sum;
    return 0;
}

/* Phase 8 Task 41 — DELEGATE state mutation.
 *
 * Parses validator_pubkey[2592] appended field, fetches target validator
 * + current reward accumulator, inserts (or updates) delegation row with
 * reward_snapshot = V.accumulator, bumps V.total_delegated +
 * V.external_delegated.
 *
 * delegation_amount is computed as
 *     native_input_sum - native_output_sum - committed_fee
 * (DELEGATE consumes DNAC inputs >= amount + fee, outputs are change
 * only; see design 2.4).
 */
static int apply_delegate(nodus_witness_t *w,
                           const uint8_t *tx_data, uint32_t tx_len,
                           uint64_t block_height,
                           uint64_t committed_fee) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_delegate: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    if (off + DNAC_PUBKEY_SIZE > tx_len) {
        fprintf(stderr, "%s: apply_delegate: truncated appended fields\n", LOG_TAG);
        return -1;
    }
    const uint8_t *validator_pubkey = tx_data + off;

    /* Rule S defense-in-depth: reject self-delegation. */
    if (memcmp(signer_pubkey, validator_pubkey, DNAC_PUBKEY_SIZE) == 0) {
        fprintf(stderr, "%s: apply_delegate: self-delegation rejected (Rule S)\n",
                LOG_TAG);
        return -1;
    }

    /* Compute delegation_amount from native-DNAC flows.
     *
     * v0.16 transitional state (Stage C.4): DELEGATE carries zero
     * protocol fee because the TX wire format does not yet include an
     * explicit `committed_fee` field. update_utxo_set's fee routing
     * (Stage C.3) also skips the stake-family TX types for the same
     * reason. With fee ≡ 0, (input_sum − output_sum) equals the
     * delegation amount exactly and the SB-1 supply-inflation class is
     * neutralized (no fee is double-counted into total_burned).
     *
     * Final fix — add an explicit fee field to the TX wire body and
     * switch to
     *     delegation_amount = input_sum − output_sum − committed_fee;
     * the committed_fee parameter below is kept in the signature so
     * that upgrade is a local edit.
     */
    (void)committed_fee;
    uint64_t input_sum = 0, output_sum = 0;
    if (sum_native_dnac_in_out(tx_data, tx_len, &input_sum, &output_sum) != 0) {
        fprintf(stderr, "%s: apply_delegate: sum_native_dnac_in_out failed\n",
                LOG_TAG);
        return -1;
    }
    if (input_sum <= output_sum) {
        fprintf(stderr, "%s: apply_delegate: input_sum (%llu) <= output_sum (%llu)\n",
                LOG_TAG,
                (unsigned long long)input_sum,
                (unsigned long long)output_sum);
        return -1;
    }
    uint64_t delegation_amount = input_sum - output_sum;

    /* Fetch target validator. */
    dnac_validator_record_t v;
    int rc = nodus_validator_get(w, validator_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_delegate: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    if (v.status != DNAC_VALIDATOR_ACTIVE) {
        fprintf(stderr, "%s: apply_delegate: validator not ACTIVE (status=%u)\n",
                LOG_TAG, v.status);
        return -1;
    }

    /* v0.16: reward accumulator snapshot removed — distribution is now
     * push-per-epoch via apply_epoch_settlement (Stage E). Delegations
     * applied mid-epoch become eligible at the NEXT epoch snapshot. */

    /* Insert (or update if already exists) delegation row. */
    dnac_delegation_record_t d;
    memset(&d, 0, sizeof(d));
    memcpy(d.delegator_pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    memcpy(d.validator_pubkey, validator_pubkey, DNAC_PUBKEY_SIZE);
    d.amount             = delegation_amount;
    d.delegated_at_block = block_height;

    int rc2 = nodus_delegation_insert(w, &d);
    if (rc2 == -2) {
        /* Existing row — top up amount + refresh Rule O block.
         * Note: Rule O's "1 epoch min hold" is measured from the most
         * recent delegated_at_block, so resetting here imposes a fresh
         * hold period on the added amount. */
        dnac_delegation_record_t existing;
        int gr = nodus_delegation_get(w, signer_pubkey, validator_pubkey,
                                       &existing);
        if (gr != 0) {
            fprintf(stderr, "%s: apply_delegate: PK collision but get failed (rc=%d)\n",
                    LOG_TAG, gr);
            return -1;
        }
        /* Overflow guard */
        if (existing.amount > UINT64_MAX - delegation_amount) {
            fprintf(stderr, "%s: apply_delegate: amount overflow\n", LOG_TAG);
            return -1;
        }
        existing.amount += delegation_amount;
        existing.delegated_at_block = block_height;
        rc2 = nodus_delegation_update(w, &existing);
    }
    rc = rc2;
    if (rc != 0) {
        fprintf(stderr, "%s: apply_delegate: delegation insert/update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    /* Bump validator totals. Rule S blocks self-delegation so every
     * delegation is external. */
    if (v.total_delegated > UINT64_MAX - delegation_amount ||
        v.external_delegated > UINT64_MAX - delegation_amount) {
        fprintf(stderr, "%s: apply_delegate: validator totals overflow\n", LOG_TAG);
        return -1;
    }
    v.total_delegated    += delegation_amount;
    v.external_delegated += delegation_amount;
    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_delegate: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* Phase 8 Task 40 — STAKE state mutation.
 *
 * Parses the type-specific appended fields (commission_bps +
 * unstake_destination_fp + purpose_tag), inserts a new validator row
 * with self_stake=10M, bumps validator_stats.active_count.
 * (v0.16: reward row seeding removed — push-settlement model has no
 * per-validator reward state.)
 */
static int apply_stake(nodus_witness_t *w,
                        const uint8_t *tx_data, uint32_t tx_len,
                        uint64_t block_height) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_stake: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    if (off + 2 + 64 + DNAC_STAKE_PURPOSE_TAG_LEN > tx_len) {
        fprintf(stderr, "%s: apply_stake: truncated appended fields\n", LOG_TAG);
        return -1;
    }

    uint16_t commission_bps = ((uint16_t)tx_data[off] << 8) |
                               (uint16_t)tx_data[off + 1];
    const uint8_t *unstake_fp_raw = tx_data + off + 2;
    /* purpose_tag bytes are validated by Phase 7 STAKE verify; we trust
     * them here. */

    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    v.self_stake              = DNAC_SELF_STAKE_AMOUNT;
    v.total_delegated         = 0;
    v.external_delegated      = 0;
    v.commission_bps          = commission_bps;
    v.pending_commission_bps  = 0;
    v.pending_effective_block = 0;
    v.status                  = DNAC_VALIDATOR_ACTIVE;
    v.active_since_block      = block_height;
    v.unstake_commit_block    = 0;
    v.last_validator_update_block = 0;
    v.consecutive_missed_epochs   = 0;
    v.last_signed_block           = 0;

    /* Convert 64 raw bytes to 128-char hex + NUL for the TEXT schema. */
    qgp_fp_raw_to_hex(unstake_fp_raw, (char *)v.unstake_destination_fp);

    /* If the destination fingerprint derives from the signer's own
     * pubkey, populate unstake_destination_pubkey immediately so the
     * post-cooldown SPEND can verify. Otherwise leave zero. */
    uint8_t signer_fp_raw[64];
    qgp_sha3_512(signer_pubkey, DNAC_PUBKEY_SIZE, signer_fp_raw);
    if (memcmp(signer_fp_raw, unstake_fp_raw, 64) == 0) {
        memcpy(v.unstake_destination_pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    }

    int rc = nodus_validator_insert(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_stake: validator_insert failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    char *err = NULL;
    int src = sqlite3_exec(w->db,
        "UPDATE validator_stats SET value = value + 1 WHERE key = 'active_count'",
        NULL, NULL, &err);
    if (src != SQLITE_OK) {
        fprintf(stderr, "%s: apply_stake: active_count bump failed: %s\n",
                LOG_TAG, err ? err : "(null)");
        if (err) sqlite3_free(err);
        return -1;
    }

    return 0;
}

/* Phase 8 Task 42 — UNSTAKE state mutation (phase 1 — RETIRING transition).
 *
 * UNSTAKE has no type-specific appended fields. The signer[0] pubkey is
 * the validator requesting retirement. On success:
 *   - status := RETIRING
 *   - unstake_commit_block := block_height
 *
 * Rule A defense-in-depth: require NO delegation records exist with
 * validator == signer[0]. Matches Phase 7 UNSTAKE verify rule A; this
 * is the last-line-of-defense check.
 *
 * Graduation to UNSTAKED + cooldown UTXO emission is deferred to phase
 * 2 (next epoch boundary). Keeps BFT peer set stable mid-epoch.
 */
static int apply_unstake(nodus_witness_t *w,
                          const uint8_t *tx_data, uint32_t tx_len,
                          uint64_t block_height) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_unstake: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    /* UNSTAKE has no appended fields — not enforced here (Phase 7
     * UNSTAKE verify is the source of truth for wire-level constraints). */

    /* Fetch validator — must exist and be ACTIVE. */
    dnac_validator_record_t v;
    int rc = nodus_validator_get(w, signer_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_unstake: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    if (v.status != DNAC_VALIDATOR_ACTIVE) {
        fprintf(stderr, "%s: apply_unstake: validator not ACTIVE (status=%u)\n",
                LOG_TAG, v.status);
        return -1;
    }

    /* Rule A defense-in-depth: reject if any delegator references this
     * validator. */
    int deleg_count = 0;
    if (nodus_delegation_count_by_validator(w, signer_pubkey,
                                              &deleg_count) != 0) {
        fprintf(stderr, "%s: apply_unstake: count_by_validator failed\n",
                LOG_TAG);
        return -1;
    }
    if (deleg_count != 0) {
        fprintf(stderr, "%s: apply_unstake: %d delegations still reference this validator (Rule A)\n",
                LOG_TAG, deleg_count);
        return -1;
    }

    v.status               = DNAC_VALIDATOR_RETIRING;
    v.unstake_commit_block = block_height;

    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_unstake: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* Emit a synthetic native-DNAC UTXO owned by `owner_pubkey`. Used by
 * UNDELEGATE which produces payouts that are NOT encoded as wire-format
 * outputs in tx_data (update_utxo_set doesn't see them).
 *
 * The nullifier is derived deterministically as
 *   SHA3-512(tx_hash || kind_byte || u32_be(output_index))
 * where kind_byte disambiguates multiple synthetic UTXOs from the same
 * TX (e.g. UNDELEGATE emits 0x01 = principal and 0x02 = pending-reward).
 *
 * `output_index` MUST NOT collide with any wire-format output index used
 * by update_utxo_set. Callers pass a high base (e.g. 100+) to stay
 * clear of wire outputs which start at 0.
 *
 * Returns 0 on success, -1 on error. `unlock_block = 0` ⇒ immediately
 * spendable.
 */
static int emit_synthetic_utxo(nodus_witness_t *w,
                                 const uint8_t *tx_hash,
                                 const uint8_t *owner_pubkey,
                                 uint64_t amount,
                                 uint64_t block_height,
                                 uint8_t kind_byte,
                                 uint32_t output_index,
                                 uint64_t unlock_block) {
    /* Derive synthetic nullifier: SHA3-512(tx_hash || kind || index_be). */
    uint8_t preimage[64 + 1 + 4];
    memcpy(preimage, tx_hash, 64);
    preimage[64] = kind_byte;
    preimage[65] = (uint8_t)((output_index >> 24) & 0xff);
    preimage[66] = (uint8_t)((output_index >> 16) & 0xff);
    preimage[67] = (uint8_t)((output_index >> 8) & 0xff);
    preimage[68] = (uint8_t)(output_index & 0xff);
    uint8_t nullifier[64];
    qgp_sha3_512(preimage, sizeof(preimage), nullifier);

    /* Owner fingerprint = hex-encoded SHA3-512(owner_pubkey). */
    uint8_t owner_fp_raw[QGP_FP_RAW_BYTES];
    qgp_sha3_512(owner_pubkey, DNAC_PUBKEY_SIZE, owner_fp_raw);
    char owner_fp_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(owner_fp_raw, owner_fp_hex);

    /* Native DNAC token_id = 64 zeros. */
    uint8_t zero_token_id[64];
    memset(zero_token_id, 0, sizeof(zero_token_id));

    int rc = nodus_witness_utxo_add_locked(w, nullifier, owner_fp_hex,
                                             amount, tx_hash, output_index,
                                             block_height, zero_token_id,
                                             unlock_block);
    if (rc != 0) {
        fprintf(stderr, "%s: emit_synthetic_utxo: utxo_add_locked failed (rc=%d, kind=0x%02x, idx=%u)\n",
                LOG_TAG, rc, kind_byte, output_index);
        return -1;
    }
    return 0;
}

/* Phase 8 Task 46 — Emit a synthetic UTXO directly owned by a precomputed
 * hex fingerprint. Used by the epoch-boundary graduation path where the
 * owner is a stored `unstake_destination_fp` (validator record field) and
 * the validator's own pubkey is not the owner. Mirrors emit_synthetic_utxo
 * except it skips the SHA3-512(pubkey) fp derivation step.
 *
 * owner_fp_hex MUST be the 128-char lowercase hex fingerprint + NUL. The
 * nullifier derivation, token_id (zeros), and locked-UTXO insert path are
 * identical to emit_synthetic_utxo so the two helpers share identical
 * supply-accounting behavior.
 */
static int emit_synthetic_utxo_for_fp(nodus_witness_t *w,
                                         const uint8_t *tx_hash,
                                         const char *owner_fp_hex,
                                         uint64_t amount,
                                         uint64_t block_height,
                                         uint8_t kind_byte,
                                         uint32_t output_index,
                                         uint64_t unlock_block) {
    /* Same nullifier derivation as emit_synthetic_utxo. */
    uint8_t preimage[64 + 1 + 4];
    memcpy(preimage, tx_hash, 64);
    preimage[64] = kind_byte;
    preimage[65] = (uint8_t)((output_index >> 24) & 0xff);
    preimage[66] = (uint8_t)((output_index >> 16) & 0xff);
    preimage[67] = (uint8_t)((output_index >> 8) & 0xff);
    preimage[68] = (uint8_t)(output_index & 0xff);
    uint8_t nullifier[64];
    qgp_sha3_512(preimage, sizeof(preimage), nullifier);

    uint8_t zero_token_id[64];
    memset(zero_token_id, 0, sizeof(zero_token_id));

    int rc = nodus_witness_utxo_add_locked(w, nullifier, owner_fp_hex,
                                             amount, tx_hash, output_index,
                                             block_height, zero_token_id,
                                             unlock_block);
    if (rc != 0) {
        fprintf(stderr, "%s: emit_synthetic_utxo_for_fp: utxo_add_locked failed (rc=%d, kind=0x%02x, idx=%u)\n",
                LOG_TAG, rc, kind_byte, output_index);
        return -1;
    }
    return 0;
}

/* Phase 8 Task 43 — UNDELEGATE state mutation.
 *
 * Parses validator_pubkey[2592] + amount[8 BE] appended fields. Computes
 * pending reward from the u128 accumulator math (design §3.5):
 *     diff       = V.accumulator − D.reward_snapshot              (u128 BE)
 *     pending_w  = (diff × D.amount) >> 64                        (u128)
 *     pending    = (uint64) pending_w.lo                          (design §3.5: shift 64)
 *
 * Emits TWO synthetic UTXOs (Rule Q — always both, even if pending==0
 * to preserve supply accounting invariants):
 *   kind 0x01 = principal UTXO (amount = undelegate_amount)
 *   kind 0x02 = pending-reward UTXO (amount = pending)
 *
 * Advances D.reward_snapshot := V.accumulator. If the delegation is
 * fully drained (undelegate_amount == D.amount), deletes the row;
 * otherwise decrements D.amount. Decrements V.total_delegated and
 * V.external_delegated (Rule S — all delegations are external).
 *
 * No validator status gate: UNDELEGATE is permitted against any status
 * so delegators of an AUTO_RETIRED / RETIRING / UNSTAKED validator can
 * always pull their principal. Rule B only restricts new DELEGATEs.
 */
static int apply_undelegate(nodus_witness_t *w,
                             const uint8_t *tx_data, uint32_t tx_len,
                             uint64_t block_height,
                             const uint8_t *tx_hash) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_undelegate: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    /* Appended: validator_pubkey[2592] + amount[8 BE] = 2600 bytes. */
    if (off + DNAC_PUBKEY_SIZE + 8 > tx_len) {
        fprintf(stderr, "%s: apply_undelegate: truncated appended fields\n", LOG_TAG);
        return -1;
    }
    const uint8_t *validator_pubkey = tx_data + off;
    uint64_t undelegate_amount = 0;
    for (int i = 0; i < 8; i++) {
        undelegate_amount = (undelegate_amount << 8) |
                             (uint64_t)tx_data[off + DNAC_PUBKEY_SIZE + i];
    }

    /* Fetch delegation. */
    dnac_delegation_record_t d;
    int rc = nodus_delegation_get(w, signer_pubkey, validator_pubkey, &d);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: delegation not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    if (undelegate_amount == 0 || undelegate_amount > d.amount) {
        fprintf(stderr, "%s: apply_undelegate: invalid amount (req=%llu, have=%llu)\n",
                LOG_TAG,
                (unsigned long long)undelegate_amount,
                (unsigned long long)d.amount);
        return -1;
    }

    /* Fetch validator. */
    dnac_validator_record_t v;
    rc = nodus_validator_get(w, validator_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    /* v0.16: reward auto-claim removed — push-settlement distributes
     * accrued rewards at each epoch boundary regardless of UNDELEGATE
     * timing. UNDELEGATE only returns the principal. */

    /* Emit principal UTXO (kind 0x01) — always spendable immediately. */
    if (emit_synthetic_utxo(w, tx_hash, signer_pubkey, undelegate_amount,
                              block_height, /*kind=*/0x01,
                              /*output_index=*/100, /*unlock=*/0) != 0) {
        return -1;
    }

    if (undelegate_amount == d.amount) {
        /* Fully drained — remove the row. */
        rc = nodus_delegation_delete(w, signer_pubkey, validator_pubkey);
    } else {
        d.amount -= undelegate_amount;
        rc = nodus_delegation_update(w, &d);
    }
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: delegation update/delete failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    /* Decrement validator totals. Rule S ⇒ all delegations are external. */
    if (v.total_delegated < undelegate_amount ||
        v.external_delegated < undelegate_amount) {
        fprintf(stderr, "%s: apply_undelegate: validator total underflow\n", LOG_TAG);
        return -1;
    }
    v.total_delegated    -= undelegate_amount;
    v.external_delegated -= undelegate_amount;
    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* Phase 8 Task 45 — VALIDATOR_UPDATE state mutation.
 *
 * Appended fields (design §2.3):
 *   new_commission_bps[2 BE] || signed_at_block[8 BE]  (10 bytes total)
 *
 * Commission-change semantics (design §3.9):
 *   - Increase (new > current): defer — set pending_commission_bps +
 *     pending_effective_block := max(next_epoch_boundary, current_block +
 *     DNAC_EPOCH_LENGTH). Delegators get a full epoch of notice.
 *   - Decrease (new <= current): immediate — current_commission_bps :=
 *     new, pending fields cleared. Decreases are always delegator-safe,
 *     no notice needed.
 *   - Equal (new == current): falls through the decrease branch; the
 *     net effect is clearing any stale pending entry without mutating
 *     current. Benign.
 *
 * Always: v.last_validator_update_block := block_height (Rule K cooldown).
 *
 * Requires the validator row to exist with status ∈ {ACTIVE, RETIRING}.
 * UNSTAKED / AUTO_RETIRED validators cannot update commissions — their
 * stake is frozen.
 *
 * signed_at_block is a verify-time field (freshness); not consumed here.
 */
static int apply_validator_update(nodus_witness_t *w,
                                     const uint8_t *tx_data, uint32_t tx_len,
                                     uint64_t block_height) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_validator_update: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    /* Appended: new_commission_bps[2 BE] + signed_at_block[8 BE]. */
    if (off + 2 + 8 > tx_len) {
        fprintf(stderr, "%s: apply_validator_update: truncated appended fields\n", LOG_TAG);
        return -1;
    }
    uint16_t new_bps = ((uint16_t)tx_data[off] << 8) |
                        (uint16_t)tx_data[off + 1];
    /* signed_at_block at off+2..off+9 — verify-time, ignored here. */

    if (new_bps > DNAC_COMMISSION_BPS_MAX) {
        fprintf(stderr, "%s: apply_validator_update: new_bps %u > max %u\n",
                LOG_TAG, new_bps, DNAC_COMMISSION_BPS_MAX);
        return -1;
    }

    dnac_validator_record_t v;
    int rc = nodus_validator_get(w, signer_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_validator_update: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    if (v.status != DNAC_VALIDATOR_ACTIVE &&
        v.status != DNAC_VALIDATOR_RETIRING) {
        fprintf(stderr, "%s: apply_validator_update: validator status=%u not updatable\n",
                LOG_TAG, v.status);
        return -1;
    }

    if (new_bps > v.commission_bps) {
        /* Increase — defer one full epoch. */
        v.pending_commission_bps  = new_bps;
        uint64_t next_epoch_boundary =
            ((block_height / DNAC_EPOCH_LENGTH) + 1) * DNAC_EPOCH_LENGTH;
        uint64_t plus_epoch = block_height + DNAC_EPOCH_LENGTH;
        v.pending_effective_block = (next_epoch_boundary > plus_epoch)
                                     ? next_epoch_boundary
                                     : plus_epoch;
    } else {
        /* Decrease (or equal) — immediate + clear pending. */
        v.commission_bps          = new_bps;
        v.pending_commission_bps  = 0;
        v.pending_effective_block = 0;
    }
    v.last_validator_update_block = block_height;

    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_validator_update: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* apply_tx_to_state — Phase 3 / Task 3.1.
 *
 * Per-TX state mutation: extracts the per-TX body of the legacy
 * commit_block_inner. Does NOT touch state_root, supply check, or
 * block_add — those live in finalize_block (Task 3.2). Suitable for
 * use inside both single-TX paths (caller invokes finalize_block once
 * after a single apply_tx_to_state) and multi-TX batch paths (caller
 * invokes apply_tx_to_state N times, then finalize_block once).
 *
 * The block_height parameter is the height at which the TX is being
 * committed — for single-TX paths it equals
 * nodus_witness_block_height(w) + 1; for batch paths all N TXs share
 * the same height (the height of the block they are being applied to).
 *
 * batch_ctx is a forward declaration for Phase 4's intra-batch
 * chained-UTXO defense. NULL is legal — the chained check is skipped,
 * which is what single-TX paths and the SAVEPOINT attribution replay
 * (Task 6.2) want.
 */
/* Non-static so test executables (compiled with NODUS_WITNESS_INTERNAL_API
 * via register_witness_test) can call directly. The function is not
 * declared in any public header — production callers reach it via
 * nodus_witness_commit_block / Phase 6 wrappers. */
int apply_tx_to_state(nodus_witness_t *w,
                       const uint8_t *tx_hash,
                       uint8_t tx_type,
                       const uint8_t *const *nullifiers,
                       uint8_t nullifier_count,
                       const uint8_t *tx_data,
                       uint32_t tx_len,
                       uint64_t block_height,
                       nodus_witness_batch_ctx_t *batch_ctx,
                       const uint8_t *client_pubkey,
                       const uint8_t *client_sig) {
    bool failed = false;

    /* Phase 4 / Task 4.3 — layer-3 chained UTXO check.
     *
     * BEFORE consuming the input nullifiers, verify that none of them
     * appears in batch_ctx->seen_nullifiers (the future-nullifiers of
     * outputs produced by earlier TXs in this batch). NULL batch_ctx
     * skips the check — single-TX paths and the SAVEPOINT attribution
     * replay (Task 6.2) want that.
     *
     * Layer 2 (propose_batch) catches the same pattern at proposal
     * time, but layer 3 is the last line of defense — bug, attack, or
     * test hook bypass. The check happens BEFORE the nullifier_add
     * inserts so a violation rolls back via the outer transaction
     * without polluting state. */
    if (batch_ctx) {
        for (int j = 0; j < nullifier_count; j++) {
            for (int k = 0; k < batch_ctx->seen_count; k++) {
                if (memcmp(batch_ctx->seen_nullifiers[k], nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN) == 0) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "layer-3: chained UTXO detected — input nullifier "
                        "matches an earlier TX's output future-nullifier");
                    return -1;
                }
            }
        }
    }

    /* Genesis-specific DB init (genesis_set + supply_init) moved to
     * commit_genesis — the only caller with tx_type==NODUS_W_TX_GENESIS.
     * commit_genesis has cd_supply from the chain_def trailer, which is
     * the correct initial_supply_raw. Deriving supply from output amounts
     * here missed the validator self-stake locks seeded by
     * genesis_seed_validators and tripped the supply invariant by exactly
     * stake_locked on every block. Restores this function's stated role
     * as pure per-TX state mutation (see function doc at top). */
    if (tx_type != NODUS_W_TX_GENESIS) {
        for (int i = 0; i < nullifier_count; i++) {
            int rc = nodus_witness_nullifier_add(w, nullifiers[i], tx_hash);
            if (rc != 0 && rc != -2) {
                fprintf(stderr, "%s: nullifier add %d failed\n", LOG_TAG, i);
                failed = true;
                break;
            }
        }
    }

    uint64_t committed_fee = 0;
    if (!failed && tx_data && tx_len > 0) {
        if (update_utxo_set(w, tx_hash, tx_type, nullifiers, nullifier_count,
                               tx_data, tx_len, &committed_fee) != 0) {
            fprintf(stderr, "%s: UTXO set update failed\n", LOG_TAG);
            failed = true;
        }
    }

    /* Phase 8 — stake & delegation state mutation. Runs AFTER
     * update_utxo_set so committed_fee is known (needed by DELEGATE for
     * exact amount calculation). Each helper is additive on top of the
     * nullifier/UTXO updates handled above: STAKE/DELEGATE/UNSTAKE all
     * still have at least one fee input whose nullifier was added. */
    if (!failed && tx_data && tx_len > 0) {
        if (tx_type == NODUS_W_TX_STAKE) {
            if (apply_stake(w, tx_data, tx_len, block_height) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_DELEGATE) {
            if (apply_delegate(w, tx_data, tx_len, block_height,
                                committed_fee) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_UNSTAKE) {
            if (apply_unstake(w, tx_data, tx_len, block_height) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_UNDELEGATE) {
            if (apply_undelegate(w, tx_data, tx_len, block_height,
                                  tx_hash) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_VALIDATOR_UPDATE) {
            if (apply_validator_update(w, tx_data, tx_len,
                                         block_height) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_CHAIN_CONFIG) {
            if (nodus_chain_config_apply(w, tx_data, tx_len,
                                          block_height) != 0) {
                failed = true;
            }
        }
    }

    /* Phase 6 / Task 31 — fees no longer decrement current_supply.
     *
     * Legacy behavior: fee → burn UTXO, supply_add_burned decremented
     * current_supply by fee (invariant: genesis_supply = utxo_sum +
     * total_burned). New behavior: fees accumulate in w->block_fee_pool
     * and Phase 9 Task 49 routes them back into the committee. The
     * supply invariant now reads: genesis_supply == utxo_sum +
     * block_fee_pool (in-flight, zeroed per block) + total_burned
     * (legacy column, untouched by SPEND fees). supply_invariant_violated
     * is advisory during Phase 3 so the pool temporarily showing up as
     * a non-zero delta is tolerated until Phase 9 lands. */
    (void)committed_fee;

    /* Phase 3 / Task 3.4: supply check moved to finalize_block —
     * runs once per block instead of N times per batch. */

    if (!failed && tx_data && tx_len > 0) {
        uint64_t bh = block_height;  /* Phase 3 / Task 3.1: explicit param */

        /* Extract sender_fp and per-output data from TX binary.
         * Wire format: header(74) → inputs(1+N*(64+8+64)) → outputs(1+...)
         *              → witnesses(1+N*7259) → sender(pk(2592)+sig(4627)) */
        char sender_fp[129] = {0};

        /* Temporary output storage for tx_outputs table */
        char    out_fps[NODUS_WITNESS_MAX_TX_OUTPUTS][129];
        uint64_t out_amts[NODUS_WITNESS_MAX_TX_OUTPUTS];
        uint8_t out_tids[NODUS_WITNESS_MAX_TX_OUTPUTS][64];
        int    out_total = 0;

        if (tx_len > 75) {
            size_t off = 74; /* skip header: version(1)+type(1)+timestamp(8)+tx_hash(64) */
            uint8_t in_count = tx_data[off++];
            off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64); /* nullifier + amount + token_id */

            /* Parse outputs — store each separately */
            if (off < tx_len) {
                uint8_t out_count = tx_data[off++];
                for (int oi = 0; oi < out_count && off + 235 <= tx_len; oi++) {
                    off += 1;  /* version */
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS) {
                        memcpy(out_fps[oi], tx_data + off, 128);
                        out_fps[oi][128] = '\0';
                    }
                    off += 129; /* fingerprint */
                    uint64_t amt;
                    memcpy(&amt, tx_data + off, 8);
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS) {
                        out_amts[oi] = amt;
                    }
                    off += 8;   /* amount */
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS) {
                        memcpy(out_tids[oi], tx_data + off, 64);
                    }
                    off += 64;  /* token_id */
                    off += 32;  /* seed */
                    uint8_t ml = tx_data[off++]; /* memo_len */
                    off += ml;
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS)
                        out_total = oi + 1;
                }
            }

            /* Skip witness signatures to reach sender pubkey */
            if (off < tx_len) {
                uint8_t wit_count = tx_data[off++];
                off += (size_t)wit_count * (32 + 4627 + 8 + 2592);
            }

            /* Sender pubkey (2592 bytes) → SHA3-512 → hex fingerprint */
            if (off + 2592 <= tx_len) {
                qgp_sha3_512_fingerprint(tx_data + off, 2592, sender_fp);
            }
        }

        nodus_witness_tx_store(w, tx_hash, tx_type, tx_data, tx_len, bh,
                               sender_fp, committed_fee,
                               client_pubkey, client_sig);

        /* Insert each output into tx_outputs table (with token_id) */
        for (int oi = 0; oi < out_total; oi++) {
            nodus_witness_tx_output_add(w, tx_hash, (uint32_t)oi,
                                          out_fps[oi], out_amts[oi],
                                          out_tids[oi]);
        }

        /* ── TOKEN_CREATE: register token in tokens table ──────── */
        if (tx_type == NODUS_W_TX_TOKEN_CREATE && tx_len > 75) {
            /* Re-parse to extract output[0]'s token_id, amount, and memo.
             * Memo format: "name:symbol:decimals" */
            size_t toff = 74;
            uint8_t tc_in_count = tx_data[toff++];
            toff += (size_t)tc_in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);

            if (toff < tx_len) {
                uint8_t tc_out_count = tx_data[toff++];
                if (tc_out_count > 0 && toff + 235 <= tx_len) {
                    toff += 1;   /* version */
                    const char *creator_fp = (const char *)(tx_data + toff);
                    toff += 129; /* fingerprint */
                    uint64_t token_supply;
                    memcpy(&token_supply, tx_data + toff, 8);
                    toff += 8;   /* amount */
                    const uint8_t *new_token_id = tx_data + toff;
                    toff += 64;  /* token_id */
                    toff += 32;  /* seed */

                    if (toff < tx_len) {
                        uint8_t memo_len = tx_data[toff++];
                        if (memo_len > 0 && toff + memo_len <= tx_len) {
                            /* Parse "name:symbol:decimals" from memo */
                            char memo_buf[256];
                            size_t copy_len = memo_len < sizeof(memo_buf) - 1
                                              ? memo_len : sizeof(memo_buf) - 1;
                            memcpy(memo_buf, tx_data + toff, copy_len);
                            memo_buf[copy_len] = '\0';

                            char *first_colon = strchr(memo_buf, ':');
                            if (first_colon) {
                                *first_colon = '\0';
                                char *second_colon = strchr(first_colon + 1, ':');
                                if (second_colon) {
                                    *second_colon = '\0';
                                    const char *t_name = memo_buf;
                                    const char *t_symbol = first_colon + 1;
                                    uint8_t t_decimals = (uint8_t)atoi(second_colon + 1);

                                    /* Use creator_fp from output (null-terminated 128-char hex) */
                                    char cfp[129];
                                    memcpy(cfp, creator_fp, 128);
                                    cfp[128] = '\0';

                                    nodus_witness_token_add(w, new_token_id,
                                        t_name, t_symbol, t_decimals,
                                        token_supply, cfp, 0, bh);

                                    fprintf(stderr, "%s: TOKEN_CREATE registered: "
                                            "name=%s symbol=%s decimals=%u "
                                            "supply=%llu (block %llu)\n",
                                            LOG_TAG, t_name, t_symbol,
                                            (unsigned)t_decimals,
                                            (unsigned long long)token_supply,
                                            (unsigned long long)bh);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (failed) return -1;

    nodus_witness_ledger_add(w, tx_hash, tx_type, nullifier_count);

    /* Phase 3 / Task 3.2: state_root + cached_state_root invalidation +
     * block_add moved to finalize_block. The caller is expected to call
     * finalize_block() once after applying all TXs in the block. */
    return 0;
}

/* Phase 8 Task 46 — epoch-boundary state transitions.
 *
 * Runs once per block inside finalize_block AFTER all per-TX
 * apply_tx_to_state calls have finished, but BEFORE state_root is
 * recomputed. No-op on non-epoch-boundary blocks.
 *
 * The three time-driven transitions implemented here:
 *
 *   1. Pending commission activation — any validator row whose
 *      pending_effective_block == block_height and whose
 *      pending_commission_bps != 0 promotes the pending rate to
 *      current and clears both pending columns.
 *
 *   2. RETIRING → UNSTAKED graduation — any validator in RETIRING
 *      status emits:
 *        (a) a time-locked principal UTXO (amount = DNAC_SELF_STAKE_AMOUNT,
 *            unlock_block = block_height + DNAC_UNSTAKE_COOLDOWN_BLOCKS)
 *        (b) an immediately-spendable unclaimed-rewards UTXO
 *            (amount = reward_record.validator_unclaimed, possibly zero
 *             to preserve supply-accounting symmetry — Rule Q)
 *      both owned by validator.unstake_destination_fp. Reward record's
 *      validator_unclaimed is then zeroed, validator transitions to
 *      UNSTAKED, and validator_stats.active_count is decremented.
 *
 *   3. Liveness-based AUTO_RETIRED — deferred. See TODO below.
 *
 * Committee election for the next epoch is ALSO an epoch-boundary
 * operation but lives in Phase 10 / Task 51; only a TODO hook is
 * present here.
 *
 * Synthetic UTXOs emitted at the boundary are not tied to a specific
 * TX hash (no TX triggered them). We derive a deterministic
 * pseudo-tx_hash as
 *   SHA3-512("dnac_epoch_graduation_v1" || block_height[8 BE])
 * which cannot collide with any real TX hash (real TX hashes are
 * SHA3-512 over canonical TX preimage) and is deterministic across all
 * witnesses for the same block.
 *
 * Returns 0 on success (including the no-op non-boundary path), -1 on
 * any failure — caller (finalize_block) should propagate the error so
 * the outer transaction rolls back.
 */
static int apply_epoch_boundary_transitions(nodus_witness_t *w,
                                               uint64_t block_height) {
    if (!w || !w->db) return -1;

    /* Epoch-boundary check. block_height==0 would be pre-genesis; the
     * first real epoch boundary is DNAC_EPOCH_LENGTH itself. */
    if (block_height == 0 || (block_height % DNAC_EPOCH_LENGTH) != 0) {
        return 0;
    }

    /* Derive deterministic pseudo-tx_hash for synthetic UTXOs. */
    uint8_t boundary_tx_hash[64];
    {
        static const char tag[] = "dnac_epoch_graduation_v1";
        const size_t tag_len = sizeof(tag) - 1;  /* exclude NUL */
        uint8_t preimage[32 + 8];
        memset(preimage, 0, sizeof(preimage));
        memcpy(preimage, tag, tag_len);
        /* Big-endian encoding of block_height in last 8 bytes. */
        for (int i = 0; i < 8; i++) {
            preimage[32 + i] =
                (uint8_t)((block_height >> (56 - 8 * i)) & 0xff);
        }
        qgp_sha3_512(preimage, sizeof(preimage), boundary_tx_hash);
    }

    /* ─────── 1. Pending commission activation ─────── */
    {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "UPDATE validators "
            "SET commission_bps = pending_commission_bps, "
            "    pending_commission_bps = 0, "
            "    pending_effective_block = 0 "
            "WHERE pending_effective_block = ? "
            "  AND pending_commission_bps != 0";
        int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare pending_commission failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            return -1;
        }
        sqlite3_bind_int64(stmt, 1, (int64_t)block_height);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: exec pending_commission failed (rc=%d): %s\n",
                    LOG_TAG, rc, sqlite3_errmsg(w->db));
            return -1;
        }
    }

    /* ─────── 2. RETIRING → UNSTAKED graduation ─────── */
    {
        /* Collect candidate pubkeys first — we cannot hold a SELECT stmt
         * open across the subsequent UPDATEs on the same table. */
        typedef struct {
            uint8_t pubkey[DNAC_PUBKEY_SIZE];
        } graduate_t;
        graduate_t *candidates = NULL;
        size_t candidate_count = 0, candidate_cap = 0;

        sqlite3_stmt *sel = NULL;
        int rc = sqlite3_prepare_v2(
            w->db,
            "SELECT pubkey FROM validators WHERE status = ?",
            -1, &sel, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare RETIRING select failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            return -1;
        }
        sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_RETIRING);
        while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
            const void *pk = sqlite3_column_blob(sel, 0);
            int pk_len = sqlite3_column_bytes(sel, 0);
            if (!pk || pk_len != DNAC_PUBKEY_SIZE) {
                fprintf(stderr, "%s: epoch_boundary: RETIRING pubkey wrong size (%d)\n",
                        LOG_TAG, pk_len);
                sqlite3_finalize(sel);
                free(candidates);
                return -1;
            }
            if (candidate_count == candidate_cap) {
                size_t new_cap = candidate_cap ? candidate_cap * 2 : 8;
                graduate_t *grown = realloc(candidates,
                                              new_cap * sizeof(graduate_t));
                if (!grown) {
                    fprintf(stderr, "%s: epoch_boundary: OOM collecting RETIRING\n",
                            LOG_TAG);
                    sqlite3_finalize(sel);
                    free(candidates);
                    return -1;
                }
                candidates = grown;
                candidate_cap = new_cap;
            }
            memcpy(candidates[candidate_count].pubkey, pk, DNAC_PUBKEY_SIZE);
            candidate_count++;
        }
        sqlite3_finalize(sel);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: RETIRING select step failed (rc=%d): %s\n",
                    LOG_TAG, rc, sqlite3_errmsg(w->db));
            free(candidates);
            return -1;
        }

        /* Per-graduate: emit principal UTXO, flip status, dec stat.
         * (v0.16: reward auto-claim on graduation removed — push-settlement
         * distributes rewards at epoch boundary independently of RETIRING
         * graduation.) */
        for (size_t i = 0; i < candidate_count; i++) {
            const uint8_t *val_pubkey = candidates[i].pubkey;

            dnac_validator_record_t v;
            rc = nodus_validator_get(w, val_pubkey, &v);
            if (rc != 0) {
                fprintf(stderr, "%s: epoch_boundary: validator_get failed (rc=%d)\n",
                        LOG_TAG, rc);
                free(candidates);
                return -1;
            }

            /* Emit principal 10M locked UTXO (kind 0x10) — unlock_block =
             * block_height + cooldown. */
            if (emit_synthetic_utxo_for_fp(
                    w, boundary_tx_hash,
                    (const char *)v.unstake_destination_fp,
                    DNAC_SELF_STAKE_AMOUNT,
                    block_height,
                    /*kind=*/0x10,
                    /*output_index=*/200,
                    /*unlock_block=*/block_height + DNAC_UNSTAKE_COOLDOWN_BLOCKS)
                != 0) {
                fprintf(stderr, "%s: epoch_boundary: emit principal UTXO failed\n",
                        LOG_TAG);
                free(candidates);
                return -1;
            }

            /* Transition RETIRING → UNSTAKED. */
            v.status = (uint8_t)DNAC_VALIDATOR_UNSTAKED;
            rc = nodus_validator_update(w, &v);
            if (rc != 0) {
                fprintf(stderr, "%s: epoch_boundary: validator_update failed (rc=%d)\n",
                        LOG_TAG, rc);
                free(candidates);
                return -1;
            }

            /* Decrement active_count. A RETIRING validator was already
             * subtracted from the committee by status filter but
             * active_count still reflected the STAKE bump; graduation
             * is when the counter actually drops. */
            char *err = NULL;
            int src = sqlite3_exec(w->db,
                "UPDATE validator_stats SET value = value - 1 "
                "WHERE key = 'active_count'",
                NULL, NULL, &err);
            if (src != SQLITE_OK) {
                fprintf(stderr, "%s: epoch_boundary: active_count dec failed: %s\n",
                        LOG_TAG, err ? err : "(null)");
                if (err) sqlite3_free(err);
                free(candidates);
                return -1;
            }
        }

        free(candidates);
    }

    /* ─────── 3. Liveness-based AUTO_RETIRED ─────── */
    /* Phase 9 / Task 48 — liveness attendance transition.
     *
     * Per design §3 (Rule N): a validator that misses the liveness
     * threshold for DNAC_AUTO_RETIRE_EPOCHS consecutive epochs is
     * auto-retired. The per-block attendance watermark
     * (validator.last_signed_block) is maintained by
     * nodus_witness_record_attendance (called after cert_store in the
     * BFT commit path). Here at the epoch boundary we read that
     * watermark to decide who attended the past epoch.
     *
     * Semantics (v1 simplification): "present" == signed ANY block in
     * the past epoch. This is stricter than the 80% threshold in
     * design §3.5 (a validator that signed 95/120 is treated the same
     * as one that signed 120/120) but it is a safe
     * over-approximation: anyone counted "present" here would also
     * clear the 80% bar. The DNAC_LIVENESS_THRESHOLD_BPS constant is
     * retained for the accumulator-side liveness gate in Task 49.
     *
     * A future v2 refinement would add a per-epoch signed-block
     * counter to validator_stats and compare against
     * DNAC_LIVENESS_THRESHOLD_BPS exactly. */
    {
        uint64_t epoch_start = 0;
        if (block_height > DNAC_EPOCH_LENGTH) {
            epoch_start = block_height - DNAC_EPOCH_LENGTH;
        }

        /* Step 3a: increment consecutive_missed_epochs for ACTIVE
         * validators whose last_signed_block is older than the past
         * epoch start. Reset to 0 for those who signed within it. */
        sqlite3_stmt *inc = NULL;
        int rc = sqlite3_prepare_v2(w->db,
            "UPDATE validators "
            "SET consecutive_missed_epochs = consecutive_missed_epochs + 1 "
            "WHERE status = ? AND last_signed_block < ? "
            "  AND active_since_block + ? <= ?",
            -1, &inc, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare miss_inc failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            return -1;
        }
        sqlite3_bind_int(inc, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(inc, 2, (int64_t)epoch_start);
        /* MIN_TENURE gate: a validator that just staked in the epoch
         * being evaluated cannot be blamed for missing it. */
        sqlite3_bind_int64(inc, 3, (int64_t)DNAC_MIN_TENURE_BLOCKS);
        sqlite3_bind_int64(inc, 4, (int64_t)block_height);
        rc = sqlite3_step(inc);
        sqlite3_finalize(inc);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: miss_inc step failed (rc=%d)\n",
                    LOG_TAG, rc);
            return -1;
        }

        sqlite3_stmt *rst = NULL;
        rc = sqlite3_prepare_v2(w->db,
            "UPDATE validators SET consecutive_missed_epochs = 0 "
            "WHERE status = ? AND last_signed_block >= ?",
            -1, &rst, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare miss_reset failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            return -1;
        }
        sqlite3_bind_int(rst, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(rst, 2, (int64_t)epoch_start);
        rc = sqlite3_step(rst);
        sqlite3_finalize(rst);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: miss_reset step failed (rc=%d)\n",
                    LOG_TAG, rc);
            return -1;
        }

        /* Step 3b: flip ACTIVE validators that crossed
         * DNAC_AUTO_RETIRE_EPOCHS to AUTO_RETIRED. Count the flipped
         * rows so active_count can be decremented once per flip. */
        sqlite3_stmt *count = NULL;
        rc = sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM validators "
            "WHERE status = ? AND consecutive_missed_epochs >= ?",
            -1, &count, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare auto_retire count failed\n",
                    LOG_TAG);
            return -1;
        }
        sqlite3_bind_int(count, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(count, 2, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
        int retire_count = 0;
        if (sqlite3_step(count) == SQLITE_ROW)
            retire_count = sqlite3_column_int(count, 0);
        sqlite3_finalize(count);

        if (retire_count > 0) {
            sqlite3_stmt *ar = NULL;
            rc = sqlite3_prepare_v2(w->db,
                "UPDATE validators SET status = ? "
                "WHERE status = ? AND consecutive_missed_epochs >= ?",
                -1, &ar, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "%s: epoch_boundary: prepare auto_retire failed\n",
                        LOG_TAG);
                return -1;
            }
            sqlite3_bind_int(ar, 1, (int)DNAC_VALIDATOR_AUTO_RETIRED);
            sqlite3_bind_int(ar, 2, (int)DNAC_VALIDATOR_ACTIVE);
            sqlite3_bind_int64(ar, 3, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
            rc = sqlite3_step(ar);
            sqlite3_finalize(ar);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "%s: epoch_boundary: auto_retire step failed (rc=%d)\n",
                        LOG_TAG, rc);
                return -1;
            }

            /* Decrement validator_stats.active_count by retire_count.
             * Using a parameterized UPDATE to avoid embedding a raw
             * integer in the SQL string. */
            sqlite3_stmt *dec = NULL;
            rc = sqlite3_prepare_v2(w->db,
                "UPDATE validator_stats "
                "SET value = value - ? WHERE key = 'active_count'",
                -1, &dec, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "%s: epoch_boundary: prepare active_count dec failed\n",
                        LOG_TAG);
                return -1;
            }
            sqlite3_bind_int64(dec, 1, (int64_t)retire_count);
            rc = sqlite3_step(dec);
            sqlite3_finalize(dec);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "%s: epoch_boundary: active_count dec step failed (rc=%d)\n",
                        LOG_TAG, rc);
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG,
                "auto-retired %d validator(s) at epoch boundary block %llu",
                retire_count, (unsigned long long)block_height);
        }
    }

    /* ─────── 4. Committee election for next epoch ─────── */
    /* Phase 10 / Task 51-53 — committee election is demand-driven
     * through nodus_committee_get_for_block(), which caches per-epoch
     * on w->cached_committee_* and consumes the post-commit lookback
     * snapshot defined in §3.6. BFT roster wiring (Task 59) consumes
     * the same accessor. */

    return 0;
}

/* v0.16: apply_accumulator_update removed. The accumulator/residual-dust
 * u128 reward-distribution model has been replaced by the push-per-epoch
 * UTXO settlement arriving in Stage E (apply_epoch_settlement). TX fees
 * now burn directly to total_burned; validator rewards come from
 * inflation mint only, distributed atomically at block_height % 120 == 0. */

/* ── Stage E — apply_epoch_settlement ─────────────────────────────────
 *
 * Fires at finalize_block whenever block_height > 0 &&
 * block_height % DNAC_EPOCH_LENGTH == 0 — i.e. the first block of a
 * new epoch. Settles the epoch that JUST ENDED (settling_epoch_start
 * = block_height − DNAC_EPOCH_LENGTH).
 *
 * Reads the snapshot_blob captured at epoch start (Stage D.1) —
 * committee list + per-delegation amounts — and drains
 * epoch_state.epoch_pool_accum into UTXOs + burn according to the
 * design §3.4 pseudocode:
 *
 *   per_slot   = pool / committee_count
 *   outer_dust = pool − per_slot * committee_count → burn (D8)
 *
 *   for each committee validator V:
 *     if V did NOT sign ANY block in the epoch:
 *       per_slot → burn  (D7 offline-share)
 *       continue
 *     if V has no delegations:
 *       emit_utxo(V.pubkey, per_slot)
 *     else:
 *       total_stake = V.self_stake + V.total_delegated
 *       validator_base  = per_slot * V.self_stake / total_stake
 *       delegator_gross = per_slot − validator_base
 *       commission      = delegator_gross * V.commission_bps / 10000
 *       validator_total = validator_base + commission
 *       delegator_net   = delegator_gross − commission
 *       for each delegation D of V (snapshot):
 *         share = delegator_net * D.amount / V.total_delegated
 *         emit_utxo(D.delegator_pubkey, share)
 *       inner_dust = delegator_net − Σ shares → burn
 *       emit_utxo(V.pubkey, validator_total)
 *
 *   delete epoch_state[settling_epoch_start]
 *
 * Attendance check (D6): we read validator.last_signed_block. A
 * validator whose last_signed_block is within the settled epoch
 * range is considered present. This is a coarser gate than the
 * plan's "proposed ≥ 1 block" — last_signed_block is bumped in
 * record_attendance for the BLOCK PROPOSER, so the two are
 * equivalent in practice on a committed chain.
 */
static uint32_t be32_load(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static uint16_t be16_load(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static uint64_t be64_load(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* Settlement-UTXO tx_hash derivation: deterministic per epoch boundary.
 *   tx_hash = SHA3-512("settlement" || epoch_start_height BE)
 * Collision-free with any real TX hash (which is SHA3-512 over full
 * TX body) modulo second-preimage resistance. */
static void settlement_tx_hash(uint64_t settling_epoch_start,
                                uint8_t out[64]) {
    uint8_t preimage[10 + 8];
    memcpy(preimage, "settlement", 10);
    for (int i = 7; i >= 0; i--) {
        preimage[10 + i] = (uint8_t)(settling_epoch_start & 0xff);
        settling_epoch_start >>= 8;
    }
    qgp_sha3_512(preimage, sizeof(preimage), out);
}

/* Scan the delegations portion of the snapshot for rows whose
 * validator_pubkey matches `validator_pubkey`. Caller owns
 * dels_out — an array sized by the total delegation_count in the
 * snapshot.
 *
 * Returns count written into dels_out / amount_out.
 */
typedef struct {
    uint8_t  delegator_pubkey[DNAC_PUBKEY_SIZE];
    uint64_t amount;
} settlement_deleg_t;

static int collect_delegations_for_validator(
    const uint8_t *deleg_base, uint32_t deleg_count,
    const uint8_t *validator_pubkey,
    settlement_deleg_t *out, int max_out) {
    const size_t per_row = DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + 8;
    int written = 0;
    for (uint32_t i = 0; i < deleg_count && written < max_out; i++) {
        const uint8_t *row = deleg_base + (size_t)i * per_row;
        const uint8_t *dpk = row;
        const uint8_t *vpk = row + DNAC_PUBKEY_SIZE;
        if (memcmp(vpk, validator_pubkey, DNAC_PUBKEY_SIZE) != 0) continue;
        uint64_t amt = be64_load(row + 2 * DNAC_PUBKEY_SIZE);
        memcpy(out[written].delegator_pubkey, dpk, DNAC_PUBKEY_SIZE);
        out[written].amount = amt;
        written++;
    }
    return written;
}

/* Output-index reservation: one epoch's settlement may emit up to
 * 7 committee validators × 65 (1 commission + 64 delegations) = 455
 * UTXOs. We start synthetic output_index at 400 to stay clear of the
 * UNDELEGATE principal/reward range (100-101) and the
 * apply_epoch_boundary_transitions RETIRING graduation range (200-201). */
#define NODUS_EPOCH_SETTLE_OUTPUT_INDEX_BASE 400

static int apply_epoch_settlement(nodus_witness_t *w,
                                    uint64_t settling_epoch_start) {
    if (!w || !w->db) return -1;

    /* Load the epoch_state row for the settling epoch. Missing row is
     * fine — nothing to settle (first boundary in a fresh chain). */
    nodus_epoch_state_t es = {0};
    int grc = nodus_witness_epoch_get(w, settling_epoch_start, &es);
    if (grc != 0) return 0;

    uint64_t pool = es.epoch_pool_accum;
    const uint8_t *blob = es.snapshot_blob;
    size_t blob_len = es.snapshot_blob_len;

    /* Canonical empty snapshot (Stage D.2) is 6 bytes: 0x0000 || 0x00000000.
     * In that case there's no committee to distribute to — burn the
     * whole pool (keeps supply bookkeeping closed) and retire the row. */
    if (!blob || blob_len < 6) {
        if (pool > 0) nodus_witness_supply_add_burned(w, pool, es.snapshot_hash);
        nodus_witness_epoch_free(&es);
        nodus_witness_epoch_delete(w, settling_epoch_start);
        return 0;
    }

    size_t off = 0;
    uint16_t committee_count = be16_load(blob + off); off += 2;

    const size_t VAL_ROW = DNAC_PUBKEY_SIZE + 8 + 8 + 2 + 1;  /* 2611 */
    if (off + (size_t)committee_count * VAL_ROW + 4 > blob_len) {
        fprintf(stderr, "%s: epoch_settlement: truncated snapshot_blob\n",
                LOG_TAG);
        nodus_witness_epoch_free(&es);
        return -1;
    }
    const uint8_t *val_base = blob + off;
    off += (size_t)committee_count * VAL_ROW;

    uint32_t deleg_count = be32_load(blob + off); off += 4;
    const size_t DEL_ROW = DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + 8;  /* 5192 */
    if (off + (size_t)deleg_count * DEL_ROW > blob_len) {
        fprintf(stderr, "%s: epoch_settlement: truncated snapshot delegations\n",
                LOG_TAG);
        nodus_witness_epoch_free(&es);
        return -1;
    }
    const uint8_t *deleg_base = blob + off;

    if (committee_count == 0) {
        /* Empty committee but non-zero pool → burn it all. */
        if (pool > 0) nodus_witness_supply_add_burned(w, pool, es.snapshot_hash);
        nodus_witness_epoch_free(&es);
        nodus_witness_epoch_delete(w, settling_epoch_start);
        return 0;
    }

    uint64_t per_slot = pool / (uint64_t)committee_count;
    uint64_t outer_dust = pool - per_slot * (uint64_t)committee_count;

    uint8_t tx_hash[64];
    settlement_tx_hash(settling_epoch_start, tx_hash);

    uint32_t out_idx = NODUS_EPOCH_SETTLE_OUTPUT_INDEX_BASE;
    uint64_t total_burned_here = outer_dust;

    /* Temporary buffer for per-validator delegation list — sized to
     * the worst case (all delegations belong to one validator). */
    settlement_deleg_t *dels = NULL;
    if (deleg_count > 0) {
        dels = calloc(deleg_count, sizeof(*dels));
        if (!dels) {
            nodus_witness_epoch_free(&es);
            return -1;
        }
    }

    for (uint16_t vi = 0; vi < committee_count; vi++) {
        const uint8_t *vrow = val_base + (size_t)vi * VAL_ROW;
        const uint8_t *vpk = vrow;
        uint64_t self_stake      = be64_load(vrow + DNAC_PUBKEY_SIZE);
        uint64_t total_delegated = be64_load(vrow + DNAC_PUBKEY_SIZE + 8);
        uint16_t commission_bps  = be16_load(vrow + DNAC_PUBKEY_SIZE + 16);
        /* status byte at vrow + 2610 — unused here (RETIRING members stay
         * in committee for the epoch per design §3.6). */

        /* Attendance gate (D6). We query validator.last_signed_block
         * from the current validators table — it reflects the latest
         * block the validator signed, so any value >= epoch_start
         * means they were present at least once in the epoch. */
        dnac_validator_record_t current_v;
        bool present = false;
        if (nodus_validator_get(w, vpk, &current_v) == 0) {
            uint64_t epoch_end = settling_epoch_start +
                                 (uint64_t)DNAC_EPOCH_LENGTH - 1;
            if (current_v.last_signed_block >= settling_epoch_start &&
                current_v.last_signed_block <= epoch_end) {
                present = true;
            }
        }
        if (!present) {
            total_burned_here += per_slot;
            continue;
        }

        if (per_slot == 0) continue;  /* pool too small to split */

        if (total_delegated == 0 || deleg_count == 0) {
            /* Pure validator share. */
            if (emit_synthetic_utxo(w, tx_hash, vpk, per_slot,
                                      settling_epoch_start,
                                      /*kind=*/0x20,
                                      out_idx++, /*unlock=*/0) != 0) {
                free(dels);
                nodus_witness_epoch_free(&es);
                return -1;
            }
            continue;
        }

        uint64_t total_stake = self_stake + total_delegated;
        if (total_stake == 0) total_stake = 1;   /* defensive */

        /* Use u128 for the multiply to avoid overflow. */
        qgp_u128_t num = qgp_u128_from_u64(per_slot);
        num = qgp_u128_mul_u64(num, self_stake);
        uint64_t rem = 0;
        qgp_u128_t q = qgp_u128_div_u64(num, total_stake, &rem);
        uint64_t validator_base = q.lo;   /* high limb provably 0 here
                                             since per_slot * self_stake
                                             < 2^128 and /total_stake
                                             compresses further */

        uint64_t delegator_gross = (per_slot > validator_base)
                                    ? (per_slot - validator_base) : 0;

        uint64_t commission = 0;
        if (commission_bps > 0 && delegator_gross > 0) {
            qgp_u128_t cn = qgp_u128_from_u64(delegator_gross);
            cn = qgp_u128_mul_u64(cn, (uint64_t)commission_bps);
            qgp_u128_t cq = qgp_u128_div_u64(cn, 10000ULL, &rem);
            commission = cq.lo;
            if (commission > delegator_gross) commission = delegator_gross;
        }
        uint64_t validator_total = validator_base + commission;
        uint64_t delegator_net   = delegator_gross - commission;

        /* Collect this validator's delegations from snapshot. */
        int n_dels = collect_delegations_for_validator(
            deleg_base, deleg_count, vpk, dels, (int)deleg_count);

        uint64_t distributed = 0;
        for (int di = 0; di < n_dels; di++) {
            /* share = delegator_net * D.amount / total_delegated */
            qgp_u128_t sn = qgp_u128_from_u64(delegator_net);
            sn = qgp_u128_mul_u64(sn, dels[di].amount);
            qgp_u128_t sq = qgp_u128_div_u64(sn, total_delegated, &rem);
            uint64_t share = sq.lo;

            if (share > 0) {
                if (emit_synthetic_utxo(w, tx_hash, dels[di].delegator_pubkey,
                                         share, settling_epoch_start,
                                         /*kind=*/0x21,
                                         out_idx++, /*unlock=*/0) != 0) {
                    free(dels);
                    nodus_witness_epoch_free(&es);
                    return -1;
                }
                distributed += share;
            }
        }
        if (distributed > delegator_net) distributed = delegator_net;
        uint64_t inner_dust = delegator_net - distributed;
        total_burned_here += inner_dust;

        /* Validator's consolidated UTXO (base + commission). */
        if (validator_total > 0) {
            if (emit_synthetic_utxo(w, tx_hash, vpk, validator_total,
                                      settling_epoch_start,
                                      /*kind=*/0x20,
                                      out_idx++, /*unlock=*/0) != 0) {
                free(dels);
                nodus_witness_epoch_free(&es);
                return -1;
            }
        }
    }

    free(dels);

    /* Burn aggregated dust + offline shares. */
    if (total_burned_here > 0) {
        (void)nodus_witness_supply_add_burned(w, total_burned_here, tx_hash);
    }

    nodus_witness_epoch_free(&es);
    /* Retire the settled epoch row. Design §3.1 — only the current
     * epoch carries a live row; previous-epoch snapshot is discarded. */
    nodus_witness_epoch_delete(w, settling_epoch_start);
    return 0;
}

/* Phase 9 / Task 48 — per-block attendance record.
 *
 * For every PRECOMMIT voter whose witness_id maps to an ACTIVE
 * validator row, update validator.last_signed_block = block_height.
 * Used at the epoch boundary (apply_epoch_boundary_transitions) to
 * decide whether each validator was "present" during the past epoch.
 *
 * voter_id is the first 32 bytes of SHA3-512(validator_pubkey) — the
 * same truncation the DHT identity layer uses (see
 * witness_setup_identity). We scan all rows with status in
 * {ACTIVE, RETIRING}, hash their pubkey, and match. A RETIRING
 * validator may still be on the committee for the current epoch so
 * we bump its last_signed_block too; only ACTIVE rows are considered
 * at the liveness check, however.
 *
 * Opens its OWN short-lived SQLite transaction separate from the
 * block commit transaction. Rationale: Task 47 closed the block
 * commit transaction inside the three wrapper functions before
 * cert_store is called. A failed attendance update only costs a
 * single block of credit for one validator; the epoch-boundary
 * enforcement gate uses last_signed_block as a monotonic watermark
 * so one missed bump is tolerable (a validator with enough
 * attendance will still clear the threshold).
 *
 * Returns 0 on success, -1 on DB error.
 */
int nodus_witness_record_attendance(nodus_witness_t *w,
                                      uint64_t block_height,
                                      const uint8_t *proposer_id) {
    if (!w || !w->db || !proposer_id || block_height == 0) return 0;

    /* Proposer-based attendance (2026-04-19 fix). The block's proposer_id
     * is part of the committed block header and is deterministic across
     * all nodes. Record attendance only for the proposer. Over a healthy
     * 7-member committee with round-robin leader election, each member
     * proposes roughly every 7 blocks — well within the 16-block
     * DNAC_LIVENESS_SHORT_WINDOW_BLOCKS. An offline member misses their
     * slots → falls out of the liveness window → accumulator excludes
     * them from the per-member fee split. */
    sqlite3_stmt *sel = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT pubkey, last_signed_block FROM validators "
        "WHERE status IN (?, ?)",
        -1, &sel, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: record_attendance: prepare select failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int(sel, 2, (int)DNAC_VALIDATOR_RETIRING);

    uint8_t match_pubkey[DNAC_PUBKEY_SIZE];
    uint64_t match_last_signed = 0;
    bool matched = false;

    while (sqlite3_step(sel) == SQLITE_ROW) {
        const void *pk = sqlite3_column_blob(sel, 0);
        int pk_len = sqlite3_column_bytes(sel, 0);
        if (!pk || pk_len != DNAC_PUBKEY_SIZE) continue;

        uint8_t digest[64];
        qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, digest);
        if (memcmp(digest, proposer_id, NODUS_T3_WITNESS_ID_LEN) != 0)
            continue;

        memcpy(match_pubkey, pk, DNAC_PUBKEY_SIZE);
        match_last_signed = (uint64_t)sqlite3_column_int64(sel, 1);
        matched = true;
        break;
    }
    sqlite3_finalize(sel);

    if (!matched) return 0;  /* proposer not a known validator — skip */
    if (block_height <= match_last_signed) return 0;  /* monotonic */

    char *err = NULL;
    if (sqlite3_exec(w->db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "%s: record_attendance: BEGIN failed: %s\n",
                LOG_TAG, err ? err : "(null)");
        if (err) sqlite3_free(err);
        return -1;
    }

    sqlite3_stmt *upd = NULL;
    rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET last_signed_block = ? WHERE pubkey = ?",
        -1, &upd, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    sqlite3_bind_int64(upd, 1, (int64_t)block_height);
    sqlite3_bind_blob(upd, 2, match_pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    int urc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (urc != SQLITE_DONE) {
        sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    if (sqlite3_exec(w->db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "%s: record_attendance: COMMIT failed: %s\n",
                LOG_TAG, err ? err : "(null)");
        if (err) sqlite3_free(err);
        sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG,
        "record_attendance: block %llu — proposer credited",
        (unsigned long long)block_height);
    return 0;
}

/* finalize_block — Phase 3 / Task 3.2.
 *
 * Per-block work: invalidate the cached state_root, recompute it from
 * the post-batch UTXO set, run the supply invariant check once, build
 * the tx_root over the batch's TX hashes, and write the block row.
 *
 * MUST be called inside the same outer DB transaction as the
 * apply_tx_to_state calls that produced the batch. The state_root
 * read sees the uncommitted UTXO writes from that transaction.
 *
 * tx_hashes is the flat n*64 buffer of raw TX hashes for tx_root
 * computation. tx_count is the batch size (1..NODUS_W_MAX_BLOCK_TXS).
 *
 * The supply invariant check is currently advisory (logs only) to
 * preserve legacy single-TX behavior. Phase 6 commit_batch wrapper
 * promotes a violation to fatal via outer rollback.
 */
/* Non-static — see apply_tx_to_state comment. */
int finalize_block(nodus_witness_t *w,
                    const uint8_t *tx_hashes,
                    uint32_t tx_count,
                    const uint8_t *proposer_id,
                    uint64_t timestamp,
                    uint64_t expected_height,
                    const uint8_t *chain_def_blob,
                    size_t chain_def_blob_len) {
    if (!w || !w->db) return -1;
    if (!proposer_id) return 0;  /* legacy: skip block_add when no proposer */
    if (tx_count == 0 || tx_count > NODUS_W_MAX_BLOCK_TXS) return -1;
    if (!tx_hashes) return -1;

    /* Phase 9 / Task 47 — finalize_block MUST run inside the outer
     * single-transaction block wrapper. The commit_genesis /
     * commit_batch / replay_block callers open BEGIN IMMEDIATE before
     * the first apply_tx_to_state and either COMMIT on success or
     * ROLLBACK on any error (design F-STATE-02). Catch callers that
     * bypass the wrapper here — they would silently partial-commit. */
    if (!w->in_block_transaction) {
        fprintf(stderr, "%s: finalize_block: called outside block "
                "transaction (F-STATE-02 violation)\n", LOG_TAG);
        return -1;
    }

    /* Phase 8 Task 46 — epoch-boundary state transitions.
     *
     * MUST run AFTER per-TX apply_tx_to_state calls (so pending-commission
     * rows set by this block's VALIDATOR_UPDATE TXs with
     * pending_effective_block == block_height are visible) and BEFORE the
     * state_root recomputation below (so all epoch-driven mutations are
     * reflected in the committed root). This implements step 5 of design
     * §4.1's block-commit order.
     *
     * `expected_height` is the height the block is being committed at —
     * passed by all callers (commit_genesis, commit_batch, replay_block).
     */
    if (apply_epoch_boundary_transitions(w, expected_height) != 0) {
        fprintf(stderr, "%s: finalize_block: epoch_boundary failed\n",
                LOG_TAG);
        return -1;
    }

    /* v0.16 stage C.2 — per-block inflation emission.
     *
     * Every block height mints nodus_emission_per_block(bh) raw DNAC
     * (see nodus_witness_emission.h for the 32→16→8→4→2→1 schedule).
     * The mint accrues into:
     *   (a) supply_tracking.total_minted — bumps current_supply too.
     *   (b) epoch_state.epoch_pool_accum — Stage E's
     *       apply_epoch_settlement drains this into UTXOs.
     *
     * Hard-Fork v1: the INFLATION_START_BLOCK override (chain_config)
     * gates activation. Pre-wipe chains passed 0 (=disabled) here;
     * v0.16 chains default to 1 (active from block 1). An unfetchable
     * override is treated as 1ULL so that a transient DB fault cannot
     * silently turn off emission cross-nodes.
     */
    {
        uint64_t inflation_start =
            nodus_chain_config_get_u64(w,
                                        DNAC_CFG_INFLATION_START_BLOCK,
                                        expected_height,
                                        1ULL);
        uint64_t emission = 0;
        if (inflation_start != 0 && expected_height >= inflation_start) {
            emission = nodus_emission_per_block(expected_height);
        }

        if (emission > 0) {
            /* Global supply counters. */
            if (nodus_witness_supply_add_minted(w, emission) != 0) {
                fprintf(stderr, "%s: finalize_block: supply_add_minted failed\n",
                        LOG_TAG);
                return -1;
            }

            /* Per-epoch pool accumulator. Canonical epoch_start_height
             * formula: floor(block_height / DNAC_EPOCH_LENGTH) *
             * DNAC_EPOCH_LENGTH. Auto-seed the row on first touch per
             * epoch; Stage D.1 will layer snapshot_hash + snapshot_blob
             * on top of it at the first block of each new epoch. */
            uint64_t epoch_start = (expected_height / (uint64_t)DNAC_EPOCH_LENGTH) *
                                   (uint64_t)DNAC_EPOCH_LENGTH;
            int add_rc = nodus_witness_epoch_add_pool(w, epoch_start, emission);
            if (add_rc == 1) {
                /* Row missing — seed with zeroed snapshot_hash and the
                 * current mint as the starting pool. Stage D.1
                 * overwrites snapshot_hash at epoch-start. */
                nodus_epoch_state_t seed = {0};
                seed.epoch_start_height = epoch_start;
                seed.epoch_pool_accum   = emission;
                int ins_rc = nodus_witness_epoch_insert(w, &seed);
                if (ins_rc != 0 && ins_rc != -2) {
                    fprintf(stderr,
                        "%s: finalize_block: epoch_insert seed failed rc=%d\n",
                        LOG_TAG, ins_rc);
                    return -1;
                }
                /* If -2 (another path raced us), retry add_pool. */
                if (ins_rc == -2) {
                    if (nodus_witness_epoch_add_pool(w, epoch_start, emission)
                        != 0) {
                        fprintf(stderr,
                            "%s: finalize_block: epoch_add_pool retry failed\n",
                            LOG_TAG);
                        return -1;
                    }
                }

                /* Stage D.1: first time an epoch_state row is seeded,
                 * capture the committee + delegation snapshot for
                 * this epoch. Idempotent — a retry with the same
                 * state produces the same snapshot_hash. */
                if (nodus_witness_epoch_snapshot_apply(w, epoch_start) != 0) {
                    fprintf(stderr,
                        "%s: finalize_block: epoch_snapshot_apply failed\n",
                        LOG_TAG);
                    return -1;
                }
            } else if (add_rc != 0) {
                fprintf(stderr,
                    "%s: finalize_block: epoch_add_pool failed rc=%d\n",
                    LOG_TAG, add_rc);
                return -1;
            }
        }
    }

    /* Stage E — epoch settlement trigger.
     *
     * Fires strictly on block_height % DNAC_EPOCH_LENGTH == 0 &&
     * block_height > 0 (RT-C1: no round/view dependency). Drains the
     * prior epoch's epoch_pool_accum into UTXOs per the Stage E
     * distribution rules and retires that epoch_state row. The NEW
     * epoch's row was already auto-seeded by the C.2 path above, so
     * compute_state_root below sees the updated table (settled row
     * gone, new row present). */
    if (expected_height > 0 &&
        (expected_height % (uint64_t)DNAC_EPOCH_LENGTH) == 0) {
        uint64_t settling_epoch_start =
            expected_height - (uint64_t)DNAC_EPOCH_LENGTH;
        if (apply_epoch_settlement(w, settling_epoch_start) != 0) {
            fprintf(stderr,
                "%s: finalize_block: epoch_settlement failed (epoch_start=%llu)\n",
                LOG_TAG, (unsigned long long)settling_epoch_start);
            return -1;
        }
    }

    /* Invalidate the cached UTXO checksum — the per-TX writes from this
     * batch made the previous root stale. Phase 11 renames this to
     * cached_state_root. */
    w->cached_state_root_valid = false;

    /* 1. Compute post-batch state_root.
     *
     * Phase 3 / Task 10: extended to SHA3-512(utxo || validator ||
     * delegation || reward) via nodus_witness_merkle_compute_state_root.
     * validator/delegation/reward subtrees default to empty-root stubs
     * until Phase 4+ populates them from real state. */
    uint8_t state_root[NODUS_T3_TX_HASH_LEN];
    if (nodus_witness_merkle_compute_state_root(w, state_root) != 0) {
        fprintf(stderr, "%s: finalize_block: state_root compute failed\n",
                LOG_TAG);
        return -1;
    }

    /* 2. Supply invariant — v0.16 Stage F.1 HARD gate.
     *
     * expected = genesis_supply + total_minted − total_burned
     * observed = Σ utxo_native + Σ self_stake + Σ total_delegated
     *          + Σ epoch_state.epoch_pool_accum
     *
     * Any mismatch rejects the block so the outer commit_batch
     * transaction rolls back — no state_root, no block row, no
     * UTXO mutations reach the committed DB. The legacy advisory
     * check (supply_invariant_violated) is retained below for the
     * attribution-replay path, which runs per-TX diagnostics when a
     * batch fails. */
    if (check_supply_invariant_v016(w) != 0) {
        fprintf(stderr,
            "%s: finalize_block REJECTED: supply invariant violated at h=%llu\n",
            LOG_TAG, (unsigned long long)expected_height);
        return -1;
    }
    (void)supply_invariant_violated(w);

    /* 3. tx_root via RFC 6962 over the batch's TX hashes (Phase 2 wrapper). */
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    if (nodus_witness_merkle_tx_root(tx_hashes, (size_t)tx_count, tx_root) != 0) {
        fprintf(stderr, "%s: finalize_block: tx_root compute failed\n",
                LOG_TAG);
        return -1;
    }

    /* 4. Block row insert. */
    if (nodus_witness_block_add(w, tx_root, tx_count, timestamp,
                                  proposer_id, state_root,
                                  chain_def_blob, chain_def_blob_len) != 0) {
        fprintf(stderr, "%s: finalize_block: block_add failed\n", LOG_TAG);
        return -1;
    }

    return 0;
}

/* v0.16 stage A.5: nodus_witness_get_block_fee_pool accessor removed
 * with the block_fee_pool field itself. Stage C.3 replaces the
 * concept with total_burned (fees) and epoch_pool_accum (mint). */

/* nodus_witness_commit_block — DELETED in Phase 11 partial.
 *
 * The thin dispatcher had a single remaining caller (sync.c:521); that
 * caller now calls nodus_witness_commit_genesis or
 * nodus_witness_replay_block directly. The legacy single-TX commit
 * wrapper / Phase 7 dispatcher is fully gone. */

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.4 — legacy single-TX nodus_witness_bft_start_round
 * DELETED. Genesis and forwarded-genesis callers now build a 1-entry
 * mempool entry array and call nodus_witness_bft_start_round_from_entries
 * instead. Phase 7 / Task 7.6 made the commit path multi-tx-aware so
 * batch-of-1 genesis works (commit_genesis dispatches the chain DB
 * bootstrap when w->db is still NULL).
 * ════════════════════════════════════════════════════════════════════ */

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.3 — shared start-round body (leader only)
 *
 * The body of the previous public bft_start_round_batch. Both
 * from_entries and from_mempool funnel here. Stays file-static; tests
 * exercise it through the wrappers.
 * ════════════════════════════════════════════════════════════════════ */

static int bft_start_round_internal(nodus_witness_t *w,
                                      nodus_witness_mempool_entry_t **entries,
                                      int count) {
    if (!w || !entries || count <= 0) return -1;

    /* F17 A2 — transport-layer roster swap (gossip discovery). Consensus
     * authority is NOT tied to this swap anymore; bft_config is refreshed
     * from committee just below. */
    if (w->pending_roster_ready &&
        w->pending_roster.n_witnesses != w->roster.n_witnesses) {
        memcpy(&w->roster, &w->pending_roster, sizeof(nodus_witness_roster_t));
        w->pending_roster_ready = false;
        fprintf(stderr, "%s: force roster swap before batch: %u witnesses "
                "(transport)\n", LOG_TAG, w->roster.n_witnesses);
    }

    /* F17 A2 — recompute BFT config from the chain-derived committee
     * for the next block. This is the authoritative quorum source. */
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    if (refresh_bft_config_from_committee(w, next_bh) != 0) {
        fprintf(stderr, "%s: failed to load committee for block %llu\n",
                LOG_TAG, (unsigned long long)next_bh);
        return -1;
    }

    if (!nodus_witness_bft_consensus_active(w)) {
        fprintf(stderr, "%s: consensus disabled (committee_count=%u < %d)\n",
                LOG_TAG, w->bft_config.n_witnesses, NODUS_T3_MIN_WITNESSES);
        return -1;
    }

    if (!nodus_witness_bft_is_leader(w)) {
        fprintf(stderr, "%s: batch start_round but not leader\n", LOG_TAG);
        return -1;
    }

    if (w->round_state.phase != NODUS_W_PHASE_IDLE) {
        fprintf(stderr, "%s: batch round rejected — round active (phase=%d)\n",
                LOG_TAG, w->round_state.phase);
        return -1;
    }

    /* Compute block_hash = SHA3-512(tx_hash_1 || tx_hash_2 || ... || tx_hash_n) */
    uint8_t block_hash[NODUS_T3_TX_HASH_LEN];
    {
        uint8_t hash_input[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];
        size_t total_len = 0;
        for (int i = 0; i < count; i++) {
            memcpy(hash_input + total_len, entries[i]->tx_hash,
                   NODUS_T3_TX_HASH_LEN);
            total_len += NODUS_T3_TX_HASH_LEN;
        }
        nodus_key_t bh;
        if (nodus_hash(hash_input, total_len, &bh) != 0) {
            fprintf(stderr, "%s: block_hash computation failed\n", LOG_TAG);
            return -1;
        }
        memcpy(block_hash, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }

    /* Initialize round state */
    w->current_round++;
    round_state_free_batch(&w->round_state);
    memset(&w->round_state, 0, sizeof(w->round_state));

    w->round_state.round = w->current_round;
    w->round_state.view = w->current_view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    memcpy(w->round_state.tx_root, block_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.tx_hash, block_hash, NODUS_T3_TX_HASH_LEN);
    w->round_state.proposal_timestamp = (uint64_t)time(NULL);
    memcpy(w->round_state.proposer_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    w->round_state.phase_start_time = time_ms();

    /* Store batch entries. Genesis is single-TX but flows through the same
     * batch path since 4d8ad851; propagate the entry's actual tx_type so the
     * quorum check at handle_vote() can apply the GENESIS unanimous rule. */
    w->round_state.tx_type = (count > 0) ? entries[0]->tx_type : NODUS_W_TX_SPEND;
    w->round_state.batch_count = count;
    for (int i = 0; i < count; i++)
        w->round_state.batch_entries[i] = entries[i];

    /* Record our own PREVOTE */
    memcpy(w->round_state.prevotes[0].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    /* F17 A1 — carry our pubkey alongside for committee authorization. */
    memcpy(w->round_state.prevotes[0].pubkey,
           w->server->identity.pk.bytes, DNAC_PUBKEY_SIZE);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;

    /* Build batch PROPOSAL */
    nodus_t3_msg_t proposal;
    memset(&proposal, 0, sizeof(proposal));
    proposal.type = NODUS_T3_PROPOSE;
    proposal.txn_id = ++w->next_txn_id;

    proposal.propose.batch_count = count;
    memcpy(proposal.propose.tx_root, block_hash, NODUS_T3_TX_HASH_LEN);

    for (int i = 0; i < count; i++) {
        nodus_t3_batch_tx_t *btx = &proposal.propose.batch_txs[i];
        nodus_witness_mempool_entry_t *e = entries[i];
        memcpy(btx->tx_hash, e->tx_hash, NODUS_T3_TX_HASH_LEN);
        btx->nullifier_count = e->nullifier_count;
        for (int j = 0; j < e->nullifier_count; j++)
            btx->nullifiers[j] = e->nullifiers[j];
        btx->tx_type = e->tx_type;
        btx->tx_data = e->tx_data;
        btx->tx_len = e->tx_len;
        btx->client_pubkey = e->client_pubkey;
        btx->client_sig = e->client_sig;
        btx->fee = e->fee;
    }

    int sent = nodus_witness_bft_broadcast(w, &proposal);

    /* Broadcast own PREVOTE */
    nodus_t3_msg_t prevote;
    memset(&prevote, 0, sizeof(prevote));
    prevote.type = NODUS_T3_PREVOTE;
    prevote.txn_id = ++w->next_txn_id;
    memcpy(prevote.vote.vote_target, block_hash, NODUS_T3_TX_HASH_LEN);
    prevote.vote.vote = NODUS_W_VOTE_APPROVE;
    nodus_witness_bft_broadcast(w, &prevote);

    fprintf(stderr, "%s: batch proposal broadcast to %d peers "
            "(round %lu, %d TXs, block_hash=%.16s...)\n",
            LOG_TAG, sent, (unsigned long)w->current_round, count,
            "computed");

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.1 — start round from caller-owned entries
 *
 * Thin pass-through to bft_start_round_batch. In commit 3 of the Phase 7
 * refactor bft_start_round_batch becomes a static bft_start_round_internal
 * and both from_entries and from_mempool become the only public entry
 * points. For now the wrapper exists so genesis callers can migrate to
 * the entry-based API without touching the underlying body.
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_start_round_from_entries(nodus_witness_t *w,
                                                 nodus_witness_mempool_entry_t **entries,
                                                 int count) {
    return bft_start_round_internal(w, entries, count);
}

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.2 — start round from mempool
 *
 * Pops a batch from the mempool, runs Phase 4 layer-2 chained-UTXO
 * filtering and DB-nullifier rechecks, then forwards the surviving
 * entries to bft_start_round_batch. On round-start failure, surviving
 * entries are returned to the mempool so they can be retried in the
 * next block interval; entries dropped by the validation pass are
 * freed.
 *
 * Body lifted verbatim (semantically) from the previous static
 * nodus_witness_propose_batch in nodus_witness.c. The helpers
 * nodus_compute_output_nullifier and nodus_extract_output_nullifiers
 * moved with it — they are static-local to bft.c now.
 * ════════════════════════════════════════════════════════════════════ */

/* Static helper — DNAC nullifier mirror.
 *
 * Mirrors dnac_derive_nullifier so nodus does not link libdnac —
 * duplication is acceptable for a 15-line crypto-only function. If the
 * DNAC nullifier scheme ever gains a secret input, this helper becomes
 * silently impotent and the entire 3-layer chained-UTXO defense MUST
 * be redesigned. */
static int nodus_compute_output_nullifier(const char *owner_fp,
                                            const uint8_t *seed,
                                            uint8_t *out64) {
    if (!owner_fp || !seed || !out64) return -1;
    uint8_t buf[256];
    size_t off = 0;
    size_t fp_len = strlen(owner_fp);
    if (fp_len > 192) fp_len = 192;
    memcpy(buf, owner_fp, fp_len); off = fp_len;
    memcpy(buf + off, seed, 32); off += 32;
    return qgp_sha3_512(buf, off, out64);
}

/* Walk a serialized TX's outputs and append each output's future
 * nullifier to a flat 64-byte array. Returns the number of outputs
 * appended (0 on parse failure). */
static int nodus_extract_output_nullifiers(const uint8_t *tx_data, uint32_t tx_len,
                                             uint8_t out_nullifiers[][64],
                                             int max_outputs) {
    if (!tx_data || tx_len < 75 || !out_nullifiers || max_outputs <= 0) return 0;
    size_t off = 74;  /* version(1)+type(1)+timestamp(8)+tx_hash(64) */
    if (off >= tx_len) return 0;
    uint8_t in_count = tx_data[off++];
    off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
    if (off >= tx_len) return 0;
    uint8_t out_count = tx_data[off++];

    int written = 0;
    for (int i = 0; i < out_count && off + 235 <= tx_len && written < max_outputs; i++) {
        off += 1;   /* version */
        const char *owner_fp = (const char *)(tx_data + off);
        char fp_buf[129];
        memcpy(fp_buf, owner_fp, 128);
        fp_buf[128] = '\0';
        off += 129; /* fingerprint */
        off += 8;   /* amount */
        off += 64;  /* token_id */
        const uint8_t *seed = tx_data + off;
        off += 32;  /* seed */
        if (off >= tx_len) break;
        uint8_t ml = tx_data[off++]; /* memo_len */
        off += ml;

        if (nodus_compute_output_nullifier(fp_buf, seed, out_nullifiers[written]) == 0) {
            written++;
        }
    }
    return written;
}

int nodus_witness_bft_start_round_from_mempool(nodus_witness_t *w) {
    if (!w || w->mempool.count == 0) return -1;

    /* Pop batch from mempool (highest fee first).
     *
     * Hard-Fork v1 / Stage D: the effective batch cap is
     *     min(NODUS_W_MAX_BLOCK_TXS, chain_config.max_txs_per_block)
     * Compile-time NODUS_W_MAX_BLOCK_TXS stays the hard upper bound so
     * the stack-allocated batch[] array remains size-safe; runtime
     * override only tightens. Default when no override exists: the
     * compile-time cap, preserving current semantics. */
    uint64_t current_tip = 0;
    if (w->db) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT MAX(block_height) FROM blocks",
                -1, &st, NULL) == SQLITE_OK) {
            if (sqlite3_step(st) == SQLITE_ROW &&
                sqlite3_column_type(st, 0) != SQLITE_NULL) {
                current_tip = (uint64_t)sqlite3_column_int64(st, 0);
            }
            sqlite3_finalize(st);
        }
    }
    uint64_t max_override =
        nodus_chain_config_get_u64(w,
                                    DNAC_CFG_MAX_TXS_PER_BLOCK,
                                    current_tip,
                                    (uint64_t)NODUS_W_MAX_BLOCK_TXS);
    int effective_max = (max_override < (uint64_t)NODUS_W_MAX_BLOCK_TXS)
                         ? (int)max_override
                         : NODUS_W_MAX_BLOCK_TXS;
    if (effective_max < 1) effective_max = 1;

    nodus_witness_mempool_entry_t *batch[NODUS_W_MAX_BLOCK_TXS];
    int count = nodus_witness_mempool_pop_batch(&w->mempool, batch,
                                                  effective_max);
    if (count <= 0) return -1;

    /* Q7 / CC-GOV-008 — exclusive-block rule for chain_config_tx.
     * If the popped batch contains a DNAC_TX_CHAIN_CONFIG TX mixed with
     * other TX types, strip down to just the chain_config and push the
     * others back into mempool for a future round. This ensures
     * governance events always occupy their own block — unmissable in
     * block explorers, impossible to bury under unrelated spends.
     * Follower-side rejection of violating proposals lives below in
     * the propose handler (layer 2 defense). */
    {
        int cc_idx = -1;
        for (int i = 0; i < count; i++) {
            if (batch[i]->tx_type == NODUS_W_TX_CHAIN_CONFIG) {
                cc_idx = i;
                break;
            }
        }
        if (cc_idx >= 0 && count > 1) {
            /* Push non-cc entries back to mempool (re-sorted by fee),
             * keep only the chain_config entry. */
            nodus_witness_mempool_entry_t *keep = batch[cc_idx];
            for (int i = 0; i < count; i++) {
                if (i != cc_idx) {
                    if (nodus_witness_mempool_add(&w->mempool, batch[i]) != 0) {
                        /* mempool full — free rather than drop on floor */
                        nodus_witness_mempool_entry_free(batch[i]);
                    }
                }
            }
            batch[0] = keep;
            count = 1;
            QGP_LOG_INFO(LOG_TAG,
                "Q7: chain_config_tx batch-isolated (others requeued)");
        }
    }

    /* Re-verify each TX (mempool entries may be stale due to
     * double-spend from a concurrent batch on another view) */
    /* Track all nullifiers seen in this batch to prevent intra-batch double-spend.
     * Max: NODUS_W_MAX_BLOCK_TXS(10) * NODUS_T3_MAX_TX_INPUTS(16) = 160 entries */
    uint8_t seen_nullifiers[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS]
                           [NODUS_T3_NULLIFIER_LEN];
    int seen_count = 0;

    /* Phase 4 / Task 4.1: layer-2 chained UTXO defense.
     *
     * Track the future nullifiers of every output produced by an earlier
     * TX in the batch. When verifying TX[i]'s INPUT nullifiers, reject
     * the entire batch if any input matches an output future-nullifier
     * from TX[j] where j < i — that means TX[i] is trying to spend a
     * UTXO that TX[j] just created, which is forbidden inside a single
     * block (the Phase 6 commit_batch wrapper applies all TXs against
     * the SAME pre-batch UTXO snapshot). */
    uint8_t seen_output_nfs[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS]
                           [NODUS_T3_NULLIFIER_LEN];
    int seen_output_nf_count = 0;

    int valid = 0;
    for (int i = 0; i < count; i++) {
        bool reject = false;

        for (int j = 0; j < batch[i]->nullifier_count; j++) {
            /* Check against DB (already committed) */
            if (nodus_witness_nullifier_exists(w, batch[i]->nullifiers[j])) {
                QGP_LOG_WARN(LOG_TAG, "mempool TX stale (DB double-spend), dropping");
                reject = true;
                break;
            }
            /* Check against other TXs in this batch (intra-batch double-spend) */
            for (int k = 0; k < seen_count; k++) {
                if (memcmp(seen_nullifiers[k], batch[i]->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN) == 0) {
                    QGP_LOG_WARN(LOG_TAG, "intra-batch double-spend detected, "
                                 "dropping TX %d", i);
                    reject = true;
                    break;
                }
            }
            if (reject) break;
            /* Layer 2: chained-UTXO check — input must not match any
             * earlier TX's output future-nullifier. */
            for (int k = 0; k < seen_output_nf_count; k++) {
                if (memcmp(seen_output_nfs[k], batch[i]->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN) == 0) {
                    QGP_LOG_WARN(LOG_TAG,
                        "layer-2: intra-batch chained UTXO detected at TX %d, "
                        "rejecting entire batch", i);
                    reject = true;
                    break;
                }
            }
            if (reject) break;
        }

        if (reject) {
            nodus_witness_mempool_entry_free(batch[i]);
            batch[i] = NULL;
        } else {
            /* Record this TX's nullifiers as seen */
            for (int j = 0; j < batch[i]->nullifier_count; j++) {
                if (seen_count < NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS) {
                    memcpy(seen_nullifiers[seen_count], batch[i]->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN);
                    seen_count++;
                }
            }

            /* Layer 2: append this TX's output future-nullifiers so
             * subsequent batch entries can detect chained-UTXO attempts. */
            uint8_t out_nfs[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
            int n_out = nodus_extract_output_nullifiers(batch[i]->tx_data,
                                                          batch[i]->tx_len,
                                                          out_nfs,
                                                          NODUS_T3_MAX_TX_INPUTS);
            for (int j = 0; j < n_out; j++) {
                if (seen_output_nf_count <
                    NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS) {
                    memcpy(seen_output_nfs[seen_output_nf_count], out_nfs[j],
                           NODUS_T3_NULLIFIER_LEN);
                    seen_output_nf_count++;
                }
            }

            if (valid != i)
                batch[valid] = batch[i];
            valid++;
        }
    }

    if (valid == 0) {
        QGP_LOG_WARN(LOG_TAG, "all batch TXs stale, skipping");
        w->mempool.last_block_time_ms = nodus_time_now() * 1000ULL;
        return -1;
    }

    /* Start batch BFT round */
    int rc = bft_start_round_internal(w, batch, valid);
    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "batch start_round failed: %d", rc);
        /* Put entries back into mempool or free them */
        for (int i = 0; i < valid; i++) {
            if (batch[i]) {
                int add_rc = nodus_witness_mempool_add(&w->mempool, batch[i]);
                if (add_rc != 0)
                    nodus_witness_mempool_entry_free(batch[i]);
            }
        }
    }

    w->mempool.last_block_time_ms = nodus_time_now() * 1000ULL;
    return rc;
}

/* ════════════════════════════════════════════════════════════════════
 * Handle PROPOSAL (follower receives from leader)
 *
 * F-CONS-06 invariant (mandatory independent state_root recompute):
 *   The wire-format nodus_t3_propose_t does NOT carry a leader-claimed
 *   state_root, and no code path below signs PREVOTE on the basis of
 *   a leader-supplied state_root. Every follower runs
 *   nodus_witness_verify_transaction() on each batch TX and validates
 *   block_hash from the batch's own tx_hashes — no "trust-leader"
 *   fast-path exists.
 *
 *   After COMMIT, each follower calls
 *   nodus_witness_merkle_compute_state_root() against its own DB
 *   (see handle_commit at the bottom of this file) and compares the
 *   result against the leader's COMMIT-message state_root. A
 *   compromised leader therefore cannot force followers to adopt an
 *   invalid post-block state.
 *
 *   DO NOT add a field to nodus_t3_propose_t that carries a leader-
 *   claimed state_root followers sign without local recompute — that
 *   would reintroduce the exact fast-path F-CONS-06 forbids. See
 *   design doc 2026-04-17-witness-stake-delegation-design.md §F-CONS-06
 *   and the regression test tests/test_prevote_state_root_mutation.c
 *   before editing this flow.
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_handle_propose(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_propose_t *prop = &msg->propose;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay check */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* F17 A2 — transport-layer roster swap (gossip discovery). Consensus
     * authority is NOT tied to this swap anymore; bft_config refreshes
     * from committee below. */
    if (w->pending_roster_ready &&
        w->pending_roster.n_witnesses != w->roster.n_witnesses) {
        memcpy(&w->roster, &w->pending_roster, sizeof(nodus_witness_roster_t));
        w->pending_roster_ready = false;
    }

    /* F17 A2 — recompute BFT config from the chain-derived committee
     * for the block this proposal is for. A3 will additionally gate
     * the leader check against this committee (not w->roster). */
    {
        uint64_t next_bh = nodus_witness_block_height(w) + 1;
        if (refresh_bft_config_from_committee(w, next_bh) != 0) {
            fprintf(stderr, "%s: failed to load committee for block %llu\n",
                    LOG_TAG, (unsigned long long)next_bh);
            return -1;
        }
    }

    /* Check for existing round in progress */
    if (w->round_state.phase != NODUS_W_PHASE_IDLE) {
        fprintf(stderr, "%s: proposal rejected — round in progress (phase=%d)\n",
                LOG_TAG, w->round_state.phase);
        return -1;
    }

    /* F17 A3 — verify proposal is from the committee-derived leader for
     * the target block. F17 A5 bootstrap — if committee empty (pre-
     * genesis), fall back to gossip roster. */
    {
        uint64_t next_bh = nodus_witness_block_height(w) + 1;
        nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
        int count = 0;
        int sender_idx = -1;

        int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
        if (gossip_idx < 0) {
            fprintf(stderr, "%s: proposal from unknown sender_id\n", LOG_TAG);
            return -1;
        }

        if (load_committee_at_height(w, next_bh, committee,
                                       DNAC_COMMITTEE_SIZE, &count) == 0 &&
            count > 0) {
            sender_idx = committee_find_pubkey(committee, count,
                                                 w->roster.witnesses[gossip_idx].pubkey);
        } else {
            /* Pre-genesis bootstrap: leader is a gossip-roster slot. */
            count = (int)w->roster.n_witnesses;
            sender_idx = gossip_idx;
        }

        uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
        int leader = nodus_witness_bft_leader_index(epoch, hdr->view, count);
        if (sender_idx < 0 || sender_idx != leader) {
            fprintf(stderr,
                    "%s: proposal from non-leader "
                    "(sender_idx=%d, leader=%d, count=%d)\n",
                    LOG_TAG, sender_idx, leader, count);
            return -1;
        }
    }

    /* Initialize round state from proposal */
    w->current_round = hdr->round;
    w->current_view = hdr->view;

    round_state_free_batch(&w->round_state);
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.client_conn = NULL;
    w->round_state.round = hdr->round;
    w->round_state.view = hdr->view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    w->round_state.phase_start_time = time_ms();
    w->round_state.proposal_timestamp = hdr->timestamp;
    memcpy(w->round_state.proposer_id, hdr->sender_id,
           NODUS_T3_WITNESS_ID_LEN);

    bool tx_invalid = false;
    char reject_reason[256] = {0};

    if (prop->batch_count > 0) {
        /* ── Batch mode ──────────────────────────────────────────── */
        memcpy(w->round_state.tx_root, prop->tx_root,
               NODUS_T3_TX_HASH_LEN);
        memcpy(w->round_state.tx_hash, prop->tx_root,
               NODUS_T3_TX_HASH_LEN);

        /* Verify block_hash = SHA3-512(all tx_hashes) */
        uint8_t computed_bh[NODUS_T3_TX_HASH_LEN];
        {
            uint8_t hash_input[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];
            size_t total_len = 0;
            for (int i = 0; i < prop->batch_count; i++) {
                memcpy(hash_input + total_len,
                       prop->batch_txs[i].tx_hash, NODUS_T3_TX_HASH_LEN);
                total_len += NODUS_T3_TX_HASH_LEN;
            }
            nodus_key_t bh;
            nodus_hash(hash_input, total_len, &bh);
            memcpy(computed_bh, bh.bytes, NODUS_T3_TX_HASH_LEN);
        }

        if (memcmp(computed_bh, prop->tx_root, NODUS_T3_TX_HASH_LEN) != 0) {
            fprintf(stderr, "%s: batch block_hash mismatch — rejecting\n",
                    LOG_TAG);
            tx_invalid = true;
            snprintf(reject_reason, sizeof(reject_reason),
                     "block_hash mismatch");
        }

        /* Q7 / CC-GOV-008 — exclusive-block rule. A proposal containing
         * a DNAC_TX_CHAIN_CONFIG MUST contain only that TX. Rejects
         * proposers that try to bury governance events among spends. */
        if (!tx_invalid) {
            for (int i = 0; i < prop->batch_count; i++) {
                if (prop->batch_txs[i].tx_type == NODUS_W_TX_CHAIN_CONFIG &&
                    prop->batch_count != 1) {
                    fprintf(stderr,
                        "%s: Q7 exclusive-block violation — "
                        "chain_config_tx in batch of %d\n",
                        LOG_TAG, prop->batch_count);
                    tx_invalid = true;
                    snprintf(reject_reason, sizeof(reject_reason),
                             "chain_config_tx must occupy its own block");
                    break;
                }
            }
        }

        /* Allocate batch entries from proposal data.
         * Track nullifiers across TXs to prevent intra-batch double-spend. */
        uint8_t batch_seen_nuls[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS]
                               [NODUS_T3_NULLIFIER_LEN];
        int batch_seen_count = 0;

        /* Follower path: mirror leader's tx_type propagation so unanimous
         * quorum check at handle_vote() fires for GENESIS entries. */
        w->round_state.tx_type = (prop->batch_count > 0)
            ? prop->batch_txs[0].tx_type
            : NODUS_W_TX_SPEND;
        w->round_state.batch_count = prop->batch_count;
        for (int i = 0; i < prop->batch_count && !tx_invalid; i++) {
            const nodus_t3_batch_tx_t *btx = &prop->batch_txs[i];
            nodus_witness_mempool_entry_t *entry = calloc(1, sizeof(*entry));
            if (!entry) { tx_invalid = true; break; }

            memcpy(entry->tx_hash, btx->tx_hash, NODUS_T3_TX_HASH_LEN);
            entry->nullifier_count = btx->nullifier_count;
            for (int j = 0; j < btx->nullifier_count; j++) {
                if (btx->nullifiers[j])
                    memcpy(entry->nullifiers[j], btx->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN);
            }
            entry->tx_type = btx->tx_type;
            if (btx->tx_data && btx->tx_len > 0 &&
                btx->tx_len <= NODUS_T3_MAX_TX_SIZE) {
                entry->tx_data = malloc(btx->tx_len);
                if (!entry->tx_data) {
                    free(entry);
                    tx_invalid = true;
                    break;
                }
                memcpy(entry->tx_data, btx->tx_data, btx->tx_len);
                entry->tx_len = btx->tx_len;
            }
            if (btx->client_pubkey)
                memcpy(entry->client_pubkey, btx->client_pubkey, NODUS_PK_BYTES);
            if (btx->client_sig)
                memcpy(entry->client_sig, btx->client_sig, NODUS_SIG_BYTES);
            entry->fee = btx->fee;
            entry->client_conn = NULL;  /* Follower has no client conn */

            /* Verify this TX independently */
            int vrc = nodus_witness_verify_transaction(w,
                          entry->tx_data, entry->tx_len,
                          entry->tx_hash, entry->tx_type,
                          (const uint8_t *)entry->nullifiers,
                          entry->nullifier_count,
                          entry->client_pubkey, entry->client_sig,
                          entry->fee, reject_reason, sizeof(reject_reason));
            if (vrc != 0) {
                fprintf(stderr, "%s: batch TX %d rejected: %s\n",
                        LOG_TAG, i, reject_reason);
                nodus_witness_mempool_entry_free(entry);
                tx_invalid = true;
                break;
            }

            /* Intra-batch double-spend check: reject if any nullifier
             * was already seen in an earlier TX in this batch */
            for (int j = 0; j < entry->nullifier_count && !tx_invalid; j++) {
                for (int k = 0; k < batch_seen_count; k++) {
                    if (memcmp(batch_seen_nuls[k], entry->nullifiers[j],
                               NODUS_T3_NULLIFIER_LEN) == 0) {
                        fprintf(stderr, "%s: batch TX %d intra-batch "
                                "double-spend — REJECTING batch\n",
                                LOG_TAG, i);
                        snprintf(reject_reason, sizeof(reject_reason),
                                 "intra-batch double-spend");
                        nodus_witness_mempool_entry_free(entry);
                        entry = NULL;
                        tx_invalid = true;
                        break;
                    }
                }
            }
            if (tx_invalid) break;

            /* Record nullifiers as seen */
            for (int j = 0; j < entry->nullifier_count; j++) {
                if (batch_seen_count <
                    NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS) {
                    memcpy(batch_seen_nuls[batch_seen_count],
                           entry->nullifiers[j], NODUS_T3_NULLIFIER_LEN);
                    batch_seen_count++;
                }
            }

            w->round_state.batch_entries[i] = entry;
        }

        /* Cleanup on invalid batch */
        if (tx_invalid) {
            for (int i = 0; i < w->round_state.batch_count; i++) {
                if (w->round_state.batch_entries[i]) {
                    nodus_witness_mempool_entry_free(
                        w->round_state.batch_entries[i]);
                    w->round_state.batch_entries[i] = NULL;
                }
            }
        }

        fprintf(stderr, "%s: batch proposal from leader: %d TXs, %s\n",
                LOG_TAG, prop->batch_count,
                tx_invalid ? "REJECTED" : "APPROVED");
    } else {
        /* Phase 9 / Task 9.1 — legacy single-TX propose path DELETED.
         * Phase 7 removed the only sender of legacy single-TX proposals
         * (nodus_witness_bft_start_round); after the chain-wipe deploy,
         * no peer ever sends batch_count == 0. Reject defensively. */
        fprintf(stderr, "%s: legacy single-TX propose rejected — "
                "batch_count == 0 unsupported after Phase 7\n", LOG_TAG);
        tx_invalid = true;
        snprintf(reject_reason, sizeof(reject_reason),
                 "legacy single-TX propose unsupported");
    }

    nodus_witness_vote_t my_vote =
        tx_invalid ? NODUS_W_VOTE_REJECT : NODUS_W_VOTE_APPROVE;

    /* Record our own PREVOTE */
    memcpy(w->round_state.prevotes[0].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    /* F17 A1 — carry our pubkey alongside for committee authorization. */
    memcpy(w->round_state.prevotes[0].pubkey,
           w->server->identity.pk.bytes, DNAC_PUBKEY_SIZE);
    w->round_state.prevotes[0].vote = my_vote;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count =
        (my_vote == NODUS_W_VOTE_APPROVE) ? 1 : 0;

    /* Build and broadcast our PREVOTE */
    nodus_t3_msg_t vote_msg;
    memset(&vote_msg, 0, sizeof(vote_msg));
    vote_msg.type = NODUS_T3_PREVOTE;
    vote_msg.txn_id = ++w->next_txn_id;
    /* Use round_state.tx_hash — set to block_hash in batch mode */
    memcpy(vote_msg.vote.vote_target, w->round_state.tx_hash, NODUS_T3_TX_HASH_LEN);
    vote_msg.vote.vote = (uint32_t)my_vote;
    if (tx_invalid)
        snprintf(vote_msg.vote.reason, sizeof(vote_msg.vote.reason),
                 "%s", reject_reason);

    int sent = nodus_witness_bft_broadcast(w, &vote_msg);

    fprintf(stderr, "%s: PREVOTE %s for round %lu (%d batch txs, sent=%d)\n",
            LOG_TAG,
            my_vote == NODUS_W_VOTE_APPROVE ? "APPROVE" : "REJECT",
            (unsigned long)hdr->round, prop->batch_count, sent);

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Handle PREVOTE / PRECOMMIT
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_handle_vote(nodus_witness_t *w,
                                    const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_vote_t *vote = &msg->vote;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay check */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* Verify round and view match */
    if (hdr->round != w->round_state.round ||
        hdr->view != w->round_state.view)
        return 0;  /* Stale vote, ignore */

    /* Verify tx_hash matches */
    if (memcmp(vote->vote_target, w->round_state.tx_hash,
               NODUS_T3_TX_HASH_LEN) != 0) {
        fprintf(stderr, "%s: vote for different tx_hash\n", LOG_TAG);
        return -1;
    }

    /* Determine vote arrays based on message type */
    nodus_witness_vote_record_t *votes;
    int *vote_count;
    int *approve_count;
    nodus_witness_phase_t expected_phase;
    nodus_witness_phase_t next_phase;

    if (msg->type == NODUS_T3_PREVOTE) {
        votes = w->round_state.prevotes;
        vote_count = &w->round_state.prevote_count;
        approve_count = &w->round_state.prevote_approve_count;
        expected_phase = NODUS_W_PHASE_PREVOTE;
        next_phase = NODUS_W_PHASE_PRECOMMIT;
    } else if (msg->type == NODUS_T3_PRECOMMIT) {
        votes = w->round_state.precommits;
        vote_count = &w->round_state.precommit_count;
        approve_count = &w->round_state.precommit_approve_count;
        expected_phase = NODUS_W_PHASE_PRECOMMIT;
        next_phase = NODUS_W_PHASE_COMMIT;
    } else {
        return -1;
    }

    /* Check phase */
    if (w->round_state.phase != expected_phase)
        return 0;  /* Wrong phase, ignore */

    /* F17 A3 — resolve sender's pubkey via gossip roster (witness_id →
     * pubkey mapping, safe by A15 because witness_id = H(pubkey)).
     * Envelope sig already verified against this pubkey at
     * witness.c:657-678 before this handler was invoked. */
    int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (gossip_idx < 0) {
        fprintf(stderr, "%s: vote from unknown sender\n", LOG_TAG);
        return -1;
    }
    const uint8_t *sender_pk = w->roster.witnesses[gossip_idx].pubkey;

    /* F17 A17 — duplicate check by pubkey (canonical identity).
     * Historical voter_id-based dedup could in principle be bypassed
     * by a node advertising the same pubkey under two witness_ids
     * in gossip. Pubkey dedup closes that edge. */
    for (int i = 0; i < *vote_count; i++) {
        if (memcmp(votes[i].pubkey, sender_pk, DNAC_PUBKEY_SIZE) == 0)
            return 0;  /* Already received */
    }

    /* F17 A3 — committee membership gate. F17 A5 bootstrap — if
     * committee empty (pre-genesis), gossip_idx >= 0 is already
     * sufficient authorization (gossip peer = legitimate pre-genesis
     * witness). Only active for the genesis round itself. */
    {
        nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
        int count = 0;
        if (load_committee_at_height(w, w->round_state.round, committee,
                                       DNAC_COMMITTEE_SIZE, &count) == 0 &&
            count > 0) {
            if (committee_find_pubkey(committee, count, sender_pk) < 0) {
                fprintf(stderr,
                        "%s: vote from non-committee member (round=%llu)\n",
                        LOG_TAG,
                        (unsigned long long)w->round_state.round);
                return -1;
            }
        }
        /* else: pre-genesis, gossip_idx check above is sufficient. */
    }

    /* Record vote — vote arrays sized to DNAC_COMMITTEE_SIZE per F17
     * A1 (committee is the voting authority). Reject if somehow we've
     * accumulated more votes than committee slots. */
    if (*vote_count >= DNAC_COMMITTEE_SIZE)
        return -1;

    memcpy(votes[*vote_count].voter_id, hdr->sender_id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(votes[*vote_count].pubkey, sender_pk, DNAC_PUBKEY_SIZE);
    votes[*vote_count].vote = (nodus_witness_vote_t)vote->vote;
    /* Phase 7.5 / Task 7.5.2 — store the wire-supplied cert_sig.
     * Only PRECOMMIT messages carry a meaningful cert_sig; PREVOTE
     * cert_sig is zero-padded by senders and ignored downstream. */
    if (msg->type == NODUS_T3_PRECOMMIT) {
        memcpy(votes[*vote_count].signature, vote->cert_sig,
               NODUS_SIG_BYTES);
    }
    (*vote_count)++;

    if (vote->vote == NODUS_W_VOTE_APPROVE)
        (*approve_count)++;

    fprintf(stderr, "%s: %s from gossip %d: %s (approve=%d/%d, quorum=%u)\n",
            LOG_TAG,
            msg->type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
            gossip_idx,
            vote->vote == NODUS_W_VOTE_APPROVE ? "APPROVE" : "REJECT",
            *approve_count, *vote_count, w->bft_config.quorum);

    /* Check for quorum. All TX types use standard BFT 2f+1, including
     * genesis — unanimity was over-specified and blocked liveness when
     * one witness had message delivery asymmetry. Safety still holds:
     * 2f+1 is sufficient to bind a single value across the cluster, and
     * genesis TX content is validated independently (sig, validators,
     * chain_def). Lagging witnesses catch up via block sync. */
    uint32_t required = w->bft_config.quorum;

    if ((uint32_t)*approve_count < required)
        return 0;  /* Not yet quorum */

    /* ── Quorum reached ──────────────────────────────────────────── */

    fprintf(stderr, "%s: %s QUORUM! approve=%d >= required=%u\n",
            LOG_TAG,
            msg->type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
            *approve_count, required);

    w->round_state.phase = next_phase;
    w->round_state.phase_start_time = time_ms();

    if (next_phase == NODUS_W_PHASE_PRECOMMIT) {
        /* PREVOTE quorum → send PRECOMMIT */

        /* Phase 7.5 / Task 7.5.2 — sign the cert preimage with our own
         * Dilithium5 SK before recording or broadcasting the precommit.
         * If signing fails (entropy / OOM / Dilithium internal), abort
         * the precommit and let the round time out via view change. */
        uint64_t cert_height = nodus_witness_block_height(w) + 1;
        uint8_t cert_preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(w->round_state.tx_hash,
                                                  w->my_id, cert_height,
                                                  w->chain_id,
                                                  cert_preimage) != 0) {
            fprintf(stderr, "%s: cert preimage compute failed — "
                    "aborting precommit\n", LOG_TAG);
            return -1;
        }

        uint8_t cert_sig[NODUS_SIG_BYTES];
        size_t cert_sig_len = 0;
        if (qgp_dsa87_sign(cert_sig, &cert_sig_len, cert_preimage,
                            sizeof(cert_preimage),
                            w->server->identity.sk.bytes) != 0 ||
            cert_sig_len > NODUS_SIG_BYTES) {
            fprintf(stderr, "%s: cert dilithium sign failed — "
                    "aborting precommit\n", LOG_TAG);
            return -1;
        }
        /* Pad sig out to the fixed wire size if the detached
         * signature came back shorter than NODUS_SIG_BYTES. */
        if (cert_sig_len < NODUS_SIG_BYTES)
            memset(cert_sig + cert_sig_len, 0,
                   NODUS_SIG_BYTES - cert_sig_len);

        /* Record our own precommit first */
        memcpy(w->round_state.precommits[0].voter_id, w->my_id,
               NODUS_T3_WITNESS_ID_LEN);
        /* F17 A1 — carry our pubkey alongside for committee authorization. */
        memcpy(w->round_state.precommits[0].pubkey,
               w->server->identity.pk.bytes, DNAC_PUBKEY_SIZE);
        w->round_state.precommits[0].vote = NODUS_W_VOTE_APPROVE;
        memcpy(w->round_state.precommits[0].signature, cert_sig,
               NODUS_SIG_BYTES);
        w->round_state.precommit_count = 1;
        w->round_state.precommit_approve_count = 1;

        /* Broadcast PRECOMMIT (cert_sig embedded in vote payload) */
        nodus_t3_msg_t pc;
        memset(&pc, 0, sizeof(pc));
        pc.type = NODUS_T3_PRECOMMIT;
        pc.txn_id = ++w->next_txn_id;
        memcpy(pc.vote.vote_target, w->round_state.tx_hash,
               NODUS_T3_TX_HASH_LEN);
        pc.vote.vote = NODUS_W_VOTE_APPROVE;
        memcpy(pc.vote.cert_sig, cert_sig, NODUS_SIG_BYTES);

        nodus_witness_bft_broadcast(w, &pc);
        return 0;
    }

    /* next_phase == NODUS_W_PHASE_COMMIT: PRECOMMIT quorum → COMMIT */

    if (w->round_state.batch_count > 0) {
        /* ── Phase 7 / Task 7.6 — multi-tx block via Phase 6 wrappers ──
         *
         * Local-leader commit path. The Phase 6 commit_batch wrapper
         * applies all N TXs against the SAME pre-batch state at one
         * shared block height, then runs a single finalize_block — so a
         * batch of N TXs becomes ONE multi-tx block, not N single-TX
         * blocks. Genesis (always batch_count == 1 under this path)
         * routes through commit_genesis which bootstraps the chain DB. */
        bool batch_failed;
        if (w->round_state.batch_count == 1 &&
            w->round_state.batch_entries[0] &&
            w->round_state.batch_entries[0]->tx_type == NODUS_W_TX_GENESIS) {
            nodus_witness_mempool_entry_t *ge =
                w->round_state.batch_entries[0];
            batch_failed = (nodus_witness_commit_genesis(w, ge->tx_hash,
                                ge->tx_data, ge->tx_len,
                                w->round_state.proposal_timestamp,
                                w->round_state.proposer_id) != 0);
        } else {
            batch_failed = (nodus_witness_commit_batch(w,
                                w->round_state.batch_entries,
                                w->round_state.batch_count,
                                w->round_state.proposal_timestamp,
                                w->round_state.proposer_id) != 0);
        }

        if (batch_failed) {
            fprintf(stderr, "%s: BATCH COMMIT FAILED round %lu\n",
                    LOG_TAG, (unsigned long)w->round_state.round);
        } else {
            /* Store one commit certificate for the new block. With true
             * multi-tx blocks, batch_count TXs share a single height. */
            uint64_t bh = nodus_witness_block_height(w);
            nodus_witness_cert_store(w, bh, w->round_state.precommits,
                                      w->round_state.precommit_count);

            /* Phase 9 / Task 48 — liveness attendance. Credit the block's
             * proposer (deterministic across all nodes — proposer_id is
             * in the committed block header). See record_attendance. */
            nodus_witness_record_attendance(w, bh,
                                              w->round_state.proposer_id);

            fprintf(stderr, "%s: BATCH COMMITTED round %lu (%d TXs, height %llu)\n",
                    LOG_TAG, (unsigned long)w->round_state.round,
                    w->round_state.batch_count,
                    (unsigned long long)bh);
        }
    }
    /* Phase 9 cleanup — legacy single-TX commit branch deleted; every
     * round goes through the batch path above since Phase 7. */

    /* Compute chain state_root (Phase 3 / Task 10: 4-subtree composite).
     * The cached_state_root + COMMIT message field must match what
     * finalize_block wrote into the block row, so we use the same
     * compute_state_root path here. */
    uint8_t utxo_cksum[NODUS_KEY_BYTES];
    bool have_cksum = (nodus_witness_merkle_compute_state_root(w, utxo_cksum) == 0);
    if (have_cksum) {
        char hex[17];
        for (int i = 0; i < 8; i++)
            snprintf(hex + i * 2, 3, "%02x", utxo_cksum[i]);
        fprintf(stderr, "%s: state_root after round %llu: %s\n",
                LOG_TAG, (unsigned long long)w->round_state.round, hex);
        memcpy(w->cached_state_root, utxo_cksum, NODUS_KEY_BYTES);
        w->cached_state_root_valid = true;
    }

    w->last_committed_round = w->round_state.round;

    /* Build and broadcast COMMIT */
    nodus_t3_msg_t c_msg;
    memset(&c_msg, 0, sizeof(c_msg));
    c_msg.type = NODUS_T3_COMMIT;
    c_msg.txn_id = ++w->next_txn_id;

    if (w->round_state.batch_count > 0) {
        /* Batch commit message */
        c_msg.commit.batch_count = w->round_state.batch_count;
        memcpy(c_msg.commit.tx_root, w->round_state.tx_root,
               NODUS_T3_TX_HASH_LEN);
        for (int i = 0; i < w->round_state.batch_count; i++) {
            nodus_witness_mempool_entry_t *e = w->round_state.batch_entries[i];
            if (!e) continue;
            nodus_t3_batch_tx_t *btx = &c_msg.commit.batch_txs[i];
            memcpy(btx->tx_hash, e->tx_hash, NODUS_T3_TX_HASH_LEN);
            btx->nullifier_count = e->nullifier_count;
            for (int j = 0; j < e->nullifier_count; j++)
                btx->nullifiers[j] = e->nullifiers[j];
            btx->tx_type = e->tx_type;
            btx->tx_data = e->tx_data;
            btx->tx_len = e->tx_len;
            btx->client_pubkey = e->client_pubkey;
            btx->client_sig = e->client_sig;
            btx->fee = e->fee;
        }
    }
    /* Phase 9 / Task 9.1 — legacy single-TX commit message build deleted. */

    c_msg.commit.proposal_timestamp = w->round_state.proposal_timestamp;
    memcpy(c_msg.commit.proposer_id, w->round_state.proposer_id,
           NODUS_T3_WITNESS_ID_LEN);
    c_msg.commit.n_precommits = w->round_state.precommit_count;
    for (int i = 0; i < w->round_state.precommit_count &&
                    i < NODUS_T3_MAX_WITNESSES; i++) {
        memcpy(c_msg.commit.certs[i].voter_id,
               w->round_state.precommits[i].voter_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(c_msg.commit.certs[i].signature,
               w->round_state.precommits[i].signature,
               NODUS_SIG_BYTES);
    }
    if (have_cksum)
        memcpy(c_msg.commit.state_root, utxo_cksum, NODUS_KEY_BYTES);

    nodus_witness_bft_broadcast(w, &c_msg);

    /* Send client responses. Helper is idempotent — noop if already emitted
     * (e.g. via handle_commit remote-COMMIT race path). */
    bft_emit_batch_replies(w);
    /* Legacy single-TX client response branch deleted in Phase 12 — every
     * round is now batch_count > 0 since Phase 7 removed the single-TX
     * BFT entrypoint. */

    /* Reset round */
    w->round_state.phase = NODUS_W_PHASE_IDLE;
    w->round_state.client_conn = NULL;

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Handle COMMIT (from remote leader / reaching quorum elsewhere)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_handle_commit(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_commit_t *cmt = &msg->commit;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay check */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* Skip if we already committed this round */
    if (hdr->round <= w->last_committed_round) {
        QGP_LOG_DEBUG(LOG_TAG, "round %lu already committed, skipping",
                      (unsigned long)hdr->round);
        return 0;
    }

    if (cmt->batch_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "received batch COMMIT for round %lu (%d TXs)",
                     (unsigned long)hdr->round, cmt->batch_count);

        /* Phase 7 / Task 7.6 — multi-tx block via Phase 6 wrappers.
         *
         * Build stack-allocated mempool entries from cmt->batch_txs.
         * tx_data pointers borrow the message buffer; commit_batch does
         * not free entries. Genesis (batch_count == 1, type GENESIS)
         * dispatches to commit_genesis for chain DB bootstrap. */
        bool rmt_batch_failed;
        nodus_witness_mempool_entry_t local_entries[NODUS_W_MAX_BLOCK_TXS];
        nodus_witness_mempool_entry_t *entry_ptrs[NODUS_W_MAX_BLOCK_TXS];

        if ((uint32_t)cmt->batch_count > NODUS_W_MAX_BLOCK_TXS) {
            QGP_LOG_ERROR(LOG_TAG, "batch remote: count %d exceeds max",
                          cmt->batch_count);
            return -1;
        }

        memset(local_entries, 0, sizeof(local_entries));
        for (int bi = 0; bi < cmt->batch_count; bi++) {
            const nodus_t3_batch_tx_t *btx = &cmt->batch_txs[bi];
            nodus_witness_mempool_entry_t *e = &local_entries[bi];
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
            /* F02 — carry client_pubkey / client_sig / fee through so the
             * verify loop below sees the same signer material as
             * handle_propose did on the leader's proposal path. */
            if (btx->client_pubkey)
                memcpy(e->client_pubkey, btx->client_pubkey, NODUS_PK_BYTES);
            if (btx->client_sig)
                memcpy(e->client_sig, btx->client_sig, NODUS_SIG_BYTES);
            e->fee = btx->fee;
            entry_ptrs[bi] = e;
        }

        /* F02 — re-verify every batch TX before applying to state.
         * handle_propose verifies on the proposal path; handle_commit's
         * fast-path (non-leader peer reaches precommit quorum and
         * broadcasts COMMIT before local_vote accumulates) previously
         * skipped verify, letting a Byzantine proposer substitute signed
         * TXs between PRECOMMIT and COMMIT. Mirrors the loop at line
         * 3562. Cost: ≤10 Dilithium5 verifies per COMMIT (bounded by
         * NODUS_W_MAX_BLOCK_TXS). */
        for (int bi = 0; bi < cmt->batch_count; bi++) {
            nodus_witness_mempool_entry_t *e = &local_entries[bi];
            char f02_reject[256];
            int f02_vrc = nodus_witness_verify_transaction(w,
                              e->tx_data, e->tx_len,
                              e->tx_hash, e->tx_type,
                              (const uint8_t *)e->nullifiers,
                              e->nullifier_count,
                              e->client_pubkey, e->client_sig,
                              e->fee, f02_reject, sizeof(f02_reject));
            if (f02_vrc != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "commit-path verify rejected batch TX %d: %s",
                              bi, f02_reject);
                return -1;
            }
        }

        if (cmt->batch_count == 1 &&
            local_entries[0].tx_type == NODUS_W_TX_GENESIS) {
            rmt_batch_failed = (nodus_witness_commit_genesis(w,
                                    local_entries[0].tx_hash,
                                    local_entries[0].tx_data,
                                    local_entries[0].tx_len,
                                    cmt->proposal_timestamp,
                                    cmt->proposer_id) != 0);
        } else {
            rmt_batch_failed = (nodus_witness_commit_batch(w, entry_ptrs,
                                    cmt->batch_count,
                                    cmt->proposal_timestamp,
                                    cmt->proposer_id) != 0);
        }

        if (rmt_batch_failed) {
            QGP_LOG_ERROR(LOG_TAG, "batch remote commit FAILED");
            return -1;
        }
    } else {
        /* Phase 9 / Task 9.1 — legacy single-TX COMMIT path DELETED.
         * After Phase 7 every commit is batch-shaped; reject defensively. */
        QGP_LOG_ERROR(LOG_TAG, "legacy single-TX COMMIT rejected — "
                     "batch_count == 0 unsupported after Phase 7");
        return -1;
    }

    /* Store commit certificates from leader's COMMIT message */
    if (cmt->n_precommits > 0) {
        uint64_t bh = nodus_witness_block_height(w);
        nodus_witness_vote_record_t votes[NODUS_T3_MAX_WITNESSES];
        for (uint32_t i = 0; i < cmt->n_precommits && i < NODUS_T3_MAX_WITNESSES; i++) {
            memcpy(votes[i].voter_id, cmt->certs[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN);
            votes[i].vote = NODUS_W_VOTE_APPROVE;
            memcpy(votes[i].signature, cmt->certs[i].signature,
                   NODUS_SIG_BYTES);
        }
        nodus_witness_cert_store(w, bh, votes, (int)cmt->n_precommits);

        /* Phase 9 / Task 48 — liveness attendance. Credit this block's
         * proposer (cmt->proposer_id), not the precommit voters — the
         * voter set diverges per node, the proposer_id does not. */
        nodus_witness_record_attendance(w, bh, cmt->proposer_id);
    }

    /* Compute chain state_root and compare with leader's (Phase 3 / Task 10).
     *
     * F-CONS-06 — Independent state_root recompute.
     * The follower ALWAYS calls nodus_witness_merkle_compute_state_root()
     * against its own freshly-committed DB state. The leader's claimed
     * state_root (cmt->state_root, sourced from the COMMIT message) is
     * NEVER copied into w->cached_state_root; only the locally-computed
     * utxo_cksum value is retained. That guarantees a compromised leader
     * cannot propagate an invalid post-block state into follower caches
     * — even a WARN-level divergence leaves the follower with its own
     * honest state_root for every downstream consumer (cert preimages,
     * block header assembly, Merkle proof anchoring).
     * Regression: tests/test_prevote_state_root_mutation.c. */
    {
        uint8_t utxo_cksum[NODUS_KEY_BYTES];
        if (nodus_witness_merkle_compute_state_root(w, utxo_cksum) == 0) {
            char hex[17];
            for (int i = 0; i < 8; i++)
                snprintf(hex + i * 2, 3, "%02x", utxo_cksum[i]);
            QGP_LOG_DEBUG(LOG_TAG, "state_root after remote commit round %llu: %s",
                         (unsigned long long)hdr->round, hex);

            /* Compare with leader's checksum (if present) */
            uint8_t zero_ck[NODUS_KEY_BYTES];
            memset(zero_ck, 0, NODUS_KEY_BYTES);
            if (memcmp(cmt->state_root, zero_ck, NODUS_KEY_BYTES) != 0) {
                if (memcmp(utxo_cksum, cmt->state_root, NODUS_KEY_BYTES) != 0) {
                    QGP_LOG_WARN(LOG_TAG, "state_root DIVERGED from "
                                 "leader at round %llu!",
                                 (unsigned long long)hdr->round);
                }
            }
            /* F-CONS-06: retain locally-computed value only, never the
             * leader's claim. */
            memcpy(w->cached_state_root, utxo_cksum, NODUS_KEY_BYTES);
            w->cached_state_root_valid = true;
        }
    }

    /* Update committed round */
    if (hdr->round > w->last_committed_round)
        w->last_committed_round = hdr->round;

    /* Race path: the leader can reach here when a non-leader peer hits
     * precommit quorum and broadcasts COMMIT before the leader's own
     * handle_vote accumulates its local quorum. In that case the leader's
     * round_state still holds batch_entries with client_conn / forwarder_id
     * routing info, but handle_vote's reply loop will never run (handle_vote
     * bails once phase != PRECOMMIT). Emit replies here so forwarded client
     * spends don't silently drop their w_fwd_rsp. Helper is idempotent.
     *
     * handle_commit calls commit_batch with stack-allocated local_entries
     * (built from cmt->batch_txs), so commit_batch populates
     * committed_block_height / committed_tx_index on THOSE stack entries,
     * not on round_state.batch_entries. Copy the coordinates across so the
     * helper emits the correct block number / tx index in spend_result and
     * w_fwd_rsp; otherwise the forwarder path still sees zeros. */
    if (w->round_state.round == hdr->round &&
        w->round_state.batch_count > 0) {
        fprintf(stderr, "%s: remote-COMMIT race — emitting replies for own "
                "round %lu from handle_commit path\n",
                LOG_TAG, (unsigned long)hdr->round);
        uint64_t committed_bh = nodus_witness_block_height(w);
        for (int bi = 0; bi < w->round_state.batch_count; bi++) {
            if (w->round_state.batch_entries[bi]) {
                w->round_state.batch_entries[bi]->committed_block_height =
                    committed_bh;
                w->round_state.batch_entries[bi]->committed_tx_index =
                    (uint32_t)bi;
            }
        }
        bft_emit_batch_replies(w);
    }
    if (w->round_state.round == hdr->round) {
        w->round_state.phase = NODUS_W_PHASE_IDLE;
        w->round_state.client_conn = NULL;
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * View change
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_initiate_view_change(nodus_witness_t *w) {
    if (!w) return -1;

    if (w->view_change_in_progress)
        return 0;

    w->view_change_in_progress = true;
    w->view_change_target = w->current_view + 1;
    w->view_change_count = 0;
    w->round_state.phase = NODUS_W_PHASE_VIEW_CHANGE;

    /* Record our own view change vote */
    memcpy(w->view_changes[0].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    w->view_changes[0].target_view = w->view_change_target;
    w->view_changes[0].last_committed_round = w->last_committed_round;
    w->view_change_count = 1;

    /* Build and broadcast VIEW_CHANGE */
    nodus_t3_msg_t vc;
    memset(&vc, 0, sizeof(vc));
    vc.type = NODUS_T3_VIEWCHG;
    vc.txn_id = ++w->next_txn_id;
    vc.viewchg.new_view = w->view_change_target;
    vc.viewchg.last_committed_round = w->last_committed_round;

    int sent = nodus_witness_bft_broadcast(w, &vc);

    fprintf(stderr, "%s: initiated view change to view %u (sent=%d)\n",
            LOG_TAG, w->view_change_target, sent);
    return 0;
}

int nodus_witness_bft_handle_viewchg(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_viewchg_t *vc = &msg->viewchg;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay check */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* F17 A3 — VIEW_CHANGE sender must be a committee member. F17 A5
     * bootstrap — pre-genesis (no committee), gossip_idx >= 0 is
     * sufficient authorization. */
    int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (gossip_idx < 0) return -1;
    const uint8_t *sender_pk = w->roster.witnesses[gossip_idx].pubkey;
    {
        uint64_t next_bh = nodus_witness_block_height(w) + 1;
        nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
        int count = 0;
        if (load_committee_at_height(w, next_bh, committee,
                                       DNAC_COMMITTEE_SIZE, &count) == 0 &&
            count > 0 &&
            committee_find_pubkey(committee, count, sender_pk) < 0) {
            fprintf(stderr,
                    "%s: VIEW_CHANGE from non-committee sender\n", LOG_TAG);
            return -1;
        }
        /* else: pre-genesis or committee member, accept. */
    }

    /* Must be for a future view */
    if (vc->new_view <= w->current_view)
        return 0;

    /* Update target if higher */
    if (!w->view_change_in_progress || vc->new_view > w->view_change_target) {
        w->view_change_in_progress = true;
        w->view_change_target = vc->new_view;
        w->view_change_count = 0;
    }

    /* Record vote if for current target */
    if (vc->new_view != w->view_change_target)
        return 0;

    /* Duplicate check */
    for (int i = 0; i < w->view_change_count; i++) {
        if (memcmp(w->view_changes[i].voter_id, hdr->sender_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return 0;
    }

    if (w->view_change_count < DNAC_COMMITTEE_SIZE) {
        memcpy(w->view_changes[w->view_change_count].voter_id,
               hdr->sender_id, NODUS_T3_WITNESS_ID_LEN);
        w->view_changes[w->view_change_count].target_view = vc->new_view;
        w->view_changes[w->view_change_count].last_committed_round =
            vc->last_committed_round;
        w->view_change_count++;
    }

    fprintf(stderr, "%s: VIEW_CHANGE from gossip %d: view %u (%d/%u)\n",
            LOG_TAG, gossip_idx, vc->new_view,
            w->view_change_count, w->bft_config.quorum);

    /* Check for quorum */
    if ((uint32_t)w->view_change_count < w->bft_config.quorum)
        return 0;

    /* View change quorum reached */
    fprintf(stderr, "%s: view change quorum! new view: %u\n",
            LOG_TAG, w->view_change_target);

    w->current_view = w->view_change_target;
    w->view_change_in_progress = false;
    w->round_state.phase = NODUS_W_PHASE_IDLE;

    /* F17 A4 — if we are the committee-derived new leader for the new
     * view, broadcast NEW_VIEW. is_leader already consults the chain
     * committee for the next block's target; current_view was just
     * updated above so the modulus picks up the new view. */
    if (nodus_witness_bft_is_leader(w)) {
        fprintf(stderr, "%s: we are new leader for view %u\n",
                LOG_TAG, w->current_view);

        nodus_t3_msg_t nv;
        memset(&nv, 0, sizeof(nv));
        nv.type = NODUS_T3_NEWVIEW;
        nv.txn_id = ++w->next_txn_id;
        nv.newview.new_view = w->current_view;
        nv.newview.n_proofs = w->view_change_count;

        nodus_witness_bft_broadcast(w, &nv);
    }

    return 0;
}

int nodus_witness_bft_handle_newview(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    const nodus_t3_newview_t *nv = &msg->newview;
    const nodus_t3_header_t *hdr = &msg->header;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* F17 A3 — verify sender is the committee-derived expected leader
     * for the new view. F17 A5 bootstrap — fall back to gossip roster
     * when committee is empty (pre-genesis). */
    uint64_t next_bh = nodus_witness_block_height(w) + 1;
    nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
    int count = 0;
    int sender_idx = -1;

    int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (gossip_idx < 0) {
        fprintf(stderr, "%s: NEW_VIEW from unknown sender_id\n", LOG_TAG);
        return -1;
    }

    if (load_committee_at_height(w, next_bh, committee,
                                   DNAC_COMMITTEE_SIZE, &count) == 0 &&
        count > 0) {
        sender_idx = committee_find_pubkey(committee, count,
                                             w->roster.witnesses[gossip_idx].pubkey);
    } else {
        /* Pre-genesis bootstrap: leader is a gossip-roster slot. */
        count = (int)w->roster.n_witnesses;
        sender_idx = gossip_idx;
    }

    uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
    int expected_leader = nodus_witness_bft_leader_index(
        epoch, nv->new_view, count);
    if (sender_idx < 0 || sender_idx != expected_leader) {
        fprintf(stderr, "%s: NEW_VIEW from non-leader\n", LOG_TAG);
        return -1;
    }

    int sender_cm = sender_idx;  /* for downstream log */

    /* Accept new view if higher than current */
    if (nv->new_view > w->current_view) {
        w->current_view = nv->new_view;
        w->view_change_in_progress = false;
        round_state_free_batch(&w->round_state);
        w->round_state.phase = NODUS_W_PHASE_IDLE;

        fprintf(stderr, "%s: accepted NEW_VIEW %u from leader %d\n",
                LOG_TAG, nv->new_view, sender_cm);
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Timeout check (called from nodus_witness_tick)
 * ════════════════════════════════════════════════════════════════════ */

/* Free any heap-allocated batch entries in round_state */
static void round_state_free_batch(nodus_witness_round_state_t *rs) {
    for (int i = 0; i < rs->batch_count; i++) {
        if (rs->batch_entries[i]) {
            nodus_witness_mempool_entry_free(rs->batch_entries[i]);
            rs->batch_entries[i] = NULL;
        }
    }
    rs->batch_count = 0;
}

/* Emit client responses for the round currently held in round_state and free
 * the batch. Idempotent — if batch_count == 0 this is a no-op.
 *
 * Split out from handle_vote precommit→commit path so that handle_commit can
 * also call it when the leader ends up committing its own round via the
 * remote-COMMIT fast path (non-leader peer reached precommit quorum first and
 * broadcast COMMIT before our handle_vote accumulated its own quorum). Without
 * this, forwarded client spends on the leader node silently drop the
 * w_fwd_rsp reply, and the original client times out at 60s even though the
 * TX committed on-chain in ~1 second. */
static void bft_emit_batch_replies(nodus_witness_t *w) {
    if (!w || w->round_state.batch_count <= 0)
        return;

    fprintf(stderr, "%s: emitting client replies for round %lu (%d entries)\n",
            LOG_TAG, (unsigned long)w->round_state.round,
            w->round_state.batch_count);

    for (int bi = 0; bi < w->round_state.batch_count; bi++) {
        nodus_witness_mempool_entry_t *e = w->round_state.batch_entries[bi];
        if (!e) continue;

        if (e->client_conn && !e->is_forwarded) {
            nodus_witness_send_spend_result(w, e, 0, NULL);
        } else if (e->is_forwarded) {
            int fwd_pi = -1;
            for (int pi = 0; pi < w->peer_count; pi++) {
                if (memcmp(w->peers[pi].witness_id,
                           e->forwarder_id,
                           NODUS_T3_WITNESS_ID_LEN) == 0 &&
                    w->peers[pi].conn && w->peers[pi].identified) {
                    fwd_pi = pi;
                    break;
                }
            }
            if (fwd_pi < 0) {
                fprintf(stderr, "%s: batch fwd_rsp: forwarder not found "
                        "(peers=%d, fid=", LOG_TAG, w->peer_count);
                for (int k = 0; k < 4; k++)
                    fprintf(stderr, "%02x", e->forwarder_id[k]);
                fprintf(stderr, ")\n");
            } else {
                nodus_t3_msg_t fwd_rsp;
                memset(&fwd_rsp, 0, sizeof(fwd_rsp));
                fwd_rsp.type = NODUS_T3_FWD_RSP;
                fwd_rsp.txn_id = ++w->next_txn_id;
                snprintf(fwd_rsp.method, sizeof(fwd_rsp.method),
                         "w_fwd_rsp");
                fwd_rsp.fwd_rsp.status = 0;
                memcpy(fwd_rsp.fwd_rsp.tx_hash, e->tx_hash,
                       NODUS_T3_TX_HASH_LEN);
                /* Phase 13 / Task 13.2 — populate full receipt fields so
                 * the forwarder can pass them through to the client
                 * instead of the legacy hardcoded 0/0. */
                fwd_rsp.fwd_rsp.block_height = e->committed_block_height;
                fwd_rsp.fwd_rsp.tx_index = e->committed_tx_index;
                memcpy(fwd_rsp.fwd_rsp.chain_id, w->chain_id, 32);
                fill_header(w, &fwd_rsp.header);
                uint8_t fwd_buf[NODUS_T3_MAX_MSG_SIZE];
                size_t fwd_len = 0;
                if (nodus_t3_encode(&fwd_rsp, &w->server->identity.sk,
                                     fwd_buf, sizeof(fwd_buf),
                                     &fwd_len) == 0) {
                    nodus_tcp_send(w->peers[fwd_pi].conn, fwd_buf, fwd_len);
                    fprintf(stderr, "%s: sent w_fwd_rsp to forwarder peer %d "
                            "for tx_hash ", LOG_TAG, fwd_pi);
                    for (int k = 0; k < 4; k++)
                        fprintf(stderr, "%02x", e->tx_hash[k]);
                    fprintf(stderr, "\n");
                }
            }
        }
    }

    round_state_free_batch(&w->round_state);
}

void nodus_witness_bft_check_timeout(nodus_witness_t *w) {
    if (!w) return;

    if (w->round_state.phase == NODUS_W_PHASE_IDLE)
        return;

    uint64_t elapsed = time_ms() - w->round_state.phase_start_time;

    /* View change stuck: if quorum not reached within viewchg_timeout,
     * abort and return to IDLE. Prevents node from being permanently stuck. */
    if (w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE) {
        if (elapsed > w->bft_config.viewchg_timeout_ms) {
            fprintf(stderr, "%s: view change timeout (%lu ms), "
                    "returning to IDLE (view stays %u)\n",
                    LOG_TAG, (unsigned long)elapsed, w->current_view);
            round_state_free_batch(&w->round_state);
            w->round_state.phase = NODUS_W_PHASE_IDLE;
            w->view_change_in_progress = false;
            w->view_change_count = 0;
            memset(&w->round_state, 0, sizeof(w->round_state));
        }
        return;
    }

    if (elapsed > w->bft_config.round_timeout_ms) {
        /* Free batch entries before transitioning — they won't be committed */
        round_state_free_batch(&w->round_state);

        w->round_state.phase = NODUS_W_PHASE_VIEW_CHANGE;

        fprintf(stderr, "%s: round timeout (%lu ms), initiating view change\n",
                LOG_TAG, (unsigned long)elapsed);
        nodus_witness_bft_initiate_view_change(w);
    }
}

/* ── Phase 6 commit wrappers ───────────────────────────────────────────
 *
 * These three wrappers compose apply_tx_to_state + finalize_block into
 * the named operations that the BFT round (Phase 7) and sync handler
 * (Phase 11) will call. Declared in nodus_witness_bft_internal.h for
 * test executables; not in any production header — Phase 7 / Phase 11
 * add the public wiring.
 */

/* Task 6.1 — single-TX genesis commit with chain DB bootstrap. */
int nodus_witness_commit_genesis(nodus_witness_t *w,
                                   const uint8_t *tx_hash,
                                   const uint8_t *tx_data,
                                   uint32_t tx_len,
                                   uint64_t timestamp,
                                   const uint8_t *proposer_id) {
    if (!w || !tx_hash || !tx_data) return -1;

    /* Chain DB bootstrap — lifted from legacy nodus_witness_commit_block */
    if (!w->db) {
        if (tx_len < 77 + 129) {
            fprintf(stderr, "%s: genesis tx_data too short for fingerprint (len=%u)\n",
                    LOG_TAG, tx_len);
            return -1;
        }
        size_t fp_off = 74;
        uint8_t in_count = tx_data[fp_off++];
        fp_off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
        if (fp_off >= tx_len) return -1;
        uint8_t out_count = tx_data[fp_off++];
        if (out_count == 0 || fp_off + 1 + 129 > tx_len) return -1;
        fp_off += 1;
        const char *genesis_fp = (const char *)(tx_data + fp_off);

        uint8_t derived_chain_id[32];
        if (nodus_derive_chain_id(genesis_fp, tx_hash, derived_chain_id) != 0) {
            fprintf(stderr, "%s: commit_genesis: derive_chain_id failed\n", LOG_TAG);
            return -1;
        }
        if (nodus_witness_create_chain_db(w, derived_chain_id) != 0) {
            fprintf(stderr, "%s: commit_genesis: create_chain_db failed\n", LOG_TAG);
            return -1;
        }
    }

    /* Extract chain_def trailer from genesis TX (if anchored genesis).
     * Moved BEFORE apply_tx_to_state so Rule P.2 can reject ghost-stake
     * genesis TXs before any state mutation — see
     * dnac/docs/plans/2026-04-19-genesis-ghost-stake-fix.md. */
    const uint8_t *cd_blob = NULL;
    uint32_t cd_blob_len = 0;
    uint64_t cd_supply = 0;
    uint8_t  cd_vcount = 0;
    {
        /* Walk TX wire format to find the optional chain_def trailer
         * appended after sender_signature by the v2 serialize path. */
        const uint8_t *p = tx_data;
        const uint8_t *end = tx_data + tx_len;
        if (tx_len >= 74) {
            p += 74;  /* header: version + type + timestamp + tx_hash */
            if (p < end) {
                uint8_t ic = *p++; p += (size_t)ic * (64 + 8 + 64); /* inputs */
            }
            if (p < end) {
                uint8_t oc = *p++;
                for (int oi = 0; oi < oc && p < end; oi++) {
                    p += 1 + 129 + 8 + 64 + 32; /* version+fp+amt+token+seed */
                    if (p < end) { uint8_t ml = *p++; p += ml; } /* memo */
                }
            }
            if (p < end) {
                uint8_t wc = *p++; p += (size_t)wc * (32 + NODUS_SIG_BYTES + 8 + NODUS_PK_BYTES); /* witnesses */
            }
            if (p < end) {
                uint8_t sc = *p++; p += (size_t)sc * (NODUS_PK_BYTES + NODUS_SIG_BYTES); /* signers */
            }
            /* Now at has_chain_def flag byte */
            if (p < end) {
                uint8_t has_cd = *p++;
                if (has_cd && p + 4 <= end) {
                    cd_blob_len = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                                | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
                    p += 4;
                    if (p + cd_blob_len <= end) {
                        cd_blob = p;
                        QGP_LOG_INFO(LOG_TAG, "Genesis TX carries chain_def trailer (%u bytes)", cd_blob_len);
                    } else {
                        cd_blob_len = 0;
                    }
                }
            }
        }
    }

    /* Rule P.2 — outputs_sum + initial_validator_count * SELF_STAKE ==
     * initial_supply_raw. Prevents ghost-stake genesis where an operator
     * (or buggy client) creates a recipient UTXO equal to gross supply
     * without deducting validator self-stake locks. */
    if (cd_blob && cd_blob_len > 0) {
        if (nodus_witness_parse_cd_supply(cd_blob, (size_t)cd_blob_len,
                                           &cd_supply, &cd_vcount) != 0) {
            fprintf(stderr, "%s: Rule P.2 — chain_def parse failed\n", LOG_TAG);
            return -1;
        }
        if (cd_vcount > 0) {
            /* Parse outputs_sum (native DNAC only) from tx_data. */
            uint64_t outputs_sum = 0;
            if (tx_len > 75) {
                size_t off = 74;
                uint8_t in_count = tx_data[off++];
                off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
                if (off < tx_len) {
                    uint8_t out_count = tx_data[off++];
                    for (int i = 0; i < out_count && off + 235 <= tx_len; i++) {
                        off += 1;    /* version */
                        off += 129;  /* fingerprint */
                        uint64_t amt;
                        memcpy(&amt, tx_data + off, 8);
                        off += 8;
                        const uint8_t *tid = tx_data + off;
                        off += 64;
                        off += 32;  /* nullifier_seed */
                        uint8_t ml = tx_data[off++];
                        off += ml;
                        /* Native DNAC only — token_id == all zeros. */
                        bool is_native = true;
                        for (int bi = 0; bi < 64; bi++) if (tid[bi] != 0) { is_native = false; break; }
                        if (is_native) outputs_sum += amt;
                    }
                }
            }
            uint64_t stake_locked = (uint64_t)cd_vcount * DNAC_SELF_STAKE_AMOUNT;
            if (stake_locked > cd_supply) {
                fprintf(stderr,
                    "%s: Rule P.2 — stake_lock=%llu > initial_supply_raw=%llu\n",
                    LOG_TAG,
                    (unsigned long long)stake_locked,
                    (unsigned long long)cd_supply);
                return -1;
            }
            uint64_t expected = cd_supply - stake_locked;
            if (outputs_sum != expected) {
                fprintf(stderr,
                    "%s: Rule P.2 REJECT — outputs_sum=%llu != expected=%llu "
                    "(initial_supply=%llu minus %u x self_stake=%llu). "
                    "Genesis TX would create ghost stake — rejecting.\n",
                    LOG_TAG,
                    (unsigned long long)outputs_sum,
                    (unsigned long long)expected,
                    (unsigned long long)cd_supply,
                    (unsigned)cd_vcount,
                    (unsigned long long)stake_locked);
                return -1;
            }
            QGP_LOG_INFO(LOG_TAG,
                "Rule P.2 OK — outputs_sum=%llu, stake_lock=%llu, total=%llu",
                (unsigned long long)outputs_sum,
                (unsigned long long)stake_locked,
                (unsigned long long)cd_supply);
        }
    }

    if (nodus_witness_db_begin(w) != 0) return -1;

    uint64_t bh = nodus_witness_block_height(w) + 1;
    if (apply_tx_to_state(w, tx_hash, NODUS_W_TX_GENESIS, NULL, 0,
                           tx_data, tx_len, bh, NULL,
                           NULL, NULL) != 0) {
        nodus_witness_db_rollback(w);
        return -1;
    }

    /* v0.16 supply-invariant fix — write genesis_state + supply_tracking
     * with the full initial_supply_raw from chain_def (cd_supply), not
     * the outputs_sum. The supply invariant at finalize_block observes
     * utxo + self_stake + delegated + pool; self_stake for the 7 bootstrap
     * validators (7 × DNAC_SELF_STAKE_AMOUNT) is seeded next by
     * genesis_seed_validators. Using cd_supply keeps
     * expected = genesis_supply + minted − burned balanced against
     * observed for every block starting at h=1. */
    {
        int rc = nodus_witness_genesis_set(w, tx_hash, cd_supply, tx_hash);
        if (rc != 0 && rc != -2) {
            fprintf(stderr, "%s: genesis record failed: %d\n", LOG_TAG, rc);
            nodus_witness_db_rollback(w);
            return -1;
        }
        int src = nodus_witness_supply_init(w, cd_supply, tx_hash);
        if (src != 0 && src != -2) {
            fprintf(stderr, "%s: supply_init failed: %d\n", LOG_TAG, src);
            nodus_witness_db_rollback(w);
            return -1;
        }
    }

    /* Phase 12 Task 57 — seed validator_tree + reward_tree from the
     * initial_validators[] block of the chain_def. Runs inside the same
     * db transaction as apply_tx_to_state / finalize_block, so a failure
     * rolls back atomically with the genesis commit. */
    if (nodus_witness_genesis_seed_validators(w, cd_blob, (size_t)cd_blob_len) != 0) {
        fprintf(stderr, "%s: genesis_seed_validators failed\n", LOG_TAG);
        nodus_witness_db_rollback(w);
        return -1;
    }

    if (finalize_block(w, tx_hash, 1, proposer_id, timestamp, bh,
                       cd_blob, (size_t)cd_blob_len) != 0) {
        nodus_witness_db_rollback(w);
        return -1;
    }
    return nodus_witness_db_commit(w);
}

/* Task 6.2 — multi-TX batch commit with SAVEPOINT attribution replay. */
int nodus_witness_commit_batch(nodus_witness_t *w,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id) {
    if (!w || !entries || count <= 0 || count > NODUS_W_MAX_BLOCK_TXS) return -1;

    nodus_witness_batch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* F17 determinism fix historically snapshotted w->block_fee_pool
     * here so rollback paths could restore it on retried/attribution-
     * replay passes. v0.16 stage A.5 deletes the field outright — fees
     * no longer live in RAM state at all — so the snapshot becomes a
     * no-op. Stage F.1 re-enforces determinism through the hard supply
     * invariant at finalize_block. */

    if (nodus_witness_db_begin(w) != 0) return -1;

    uint64_t bh = nodus_witness_block_height(w) + 1;

    /* Flat buffer of all TX hashes for finalize_block's tx_root compute */
    uint8_t tx_hashes[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];

    for (int i = 0; i < count; i++) {
        nodus_witness_mempool_entry_t *e = entries[i];
        if (!e) {
            nodus_witness_db_rollback(w);
            return -1;
        }

        const uint8_t *nul_ptrs[NODUS_T3_MAX_TX_INPUTS];
        for (int j = 0; j < e->nullifier_count; j++)
            nul_ptrs[j] = e->nullifiers[j];

        if (apply_tx_to_state(w, e->tx_hash, e->tx_type, nul_ptrs,
                               e->nullifier_count, e->tx_data, e->tx_len,
                               bh, &ctx,
                               e->client_pubkey, e->client_sig) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "commit_batch: TX %d apply_tx failed", i);
            nodus_witness_db_rollback(w);
            return -1;
        }

        /* Append this TX's output future-nullifiers so subsequent TXs
         * in the batch see them via layer-3. Uses the same derivation
         * as propose_batch's layer-2 check. */
        extern int nodus_extract_output_nullifiers_public(const uint8_t *, uint32_t,
                                                            uint8_t [][64], int);
        /* Inline the same extraction logic because the propose_batch
         * helper is file-static. Rather than widen that helper's
         * visibility, re-derive here. */
        /* Parse tx_data outputs and compute nullifiers */
        if (e->tx_data && e->tx_len > 75) {
            size_t off = 74;
            uint8_t in_count = e->tx_data[off++];
            off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
            if (off < e->tx_len) {
                uint8_t out_count = e->tx_data[off++];
                for (int oi = 0; oi < out_count && off + 235 <= e->tx_len &&
                                 ctx.seen_count <
                                 NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS;
                     oi++) {
                    off += 1;   /* version */
                    char fp_buf[129];
                    memcpy(fp_buf, e->tx_data + off, 128);
                    fp_buf[128] = '\0';
                    off += 129; /* fingerprint */
                    off += 8;   /* amount */
                    off += 64;  /* token_id */
                    const uint8_t *seed = e->tx_data + off;
                    off += 32;  /* seed */
                    if (off >= e->tx_len) break;
                    uint8_t ml = e->tx_data[off++];
                    off += ml;

                    /* SHA3-512(owner_fp || seed) — mirrors
                     * nodus_compute_output_nullifier in nodus_witness.c */
                    uint8_t nf_out[64];
                    uint8_t buf_in[192 + 32];
                    size_t fp_len = strlen(fp_buf);
                    if (fp_len > 192) fp_len = 192;
                    memcpy(buf_in, fp_buf, fp_len);
                    memcpy(buf_in + fp_len, seed, 32);
                    qgp_sha3_512(buf_in, fp_len + 32, nf_out);

                    memcpy(ctx.seen_nullifiers[ctx.seen_count++], nf_out, 64);
                }
            }
        }

        memcpy(tx_hashes + i * NODUS_T3_TX_HASH_LEN, e->tx_hash, NODUS_T3_TX_HASH_LEN);
    }

    if (finalize_block(w, tx_hashes, (uint32_t)count, proposer_id,
                        timestamp, bh, NULL, 0) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "commit_batch: finalize_block failed");
        nodus_witness_db_rollback(w);
        /* fall through to attribution replay */

        /* SAVEPOINT attribution replay — one TX at a time in a fresh
         * read-only transaction, check supply invariant after each,
         * roll back. The inner batch_ctx is empty so layer-3 does not
         * double-flag the chained check. */
        if (nodus_witness_db_begin(w) == 0) {
            for (int i = 0; i < count; i++) {
                if (nodus_witness_db_savepoint(w, "attr_sp") != 0) break;
                nodus_witness_batch_ctx_t empty_ctx;
                memset(&empty_ctx, 0, sizeof(empty_ctx));
                const uint8_t *nul_ptrs[NODUS_T3_MAX_TX_INPUTS];
                for (int j = 0; j < entries[i]->nullifier_count; j++)
                    nul_ptrs[j] = entries[i]->nullifiers[j];

                apply_tx_to_state(w, entries[i]->tx_hash, entries[i]->tx_type,
                                   nul_ptrs, entries[i]->nullifier_count,
                                   entries[i]->tx_data, entries[i]->tx_len,
                                   bh, &empty_ctx,
                                   entries[i]->client_pubkey,
                                   entries[i]->client_sig);
                if (supply_invariant_violated(w)) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "attribution: TX %d violates supply invariant", i);
                }
                nodus_witness_db_rollback_to_savepoint(w, "attr_sp");
            }
            nodus_witness_db_rollback(w);
        }
        return -1;
    }

    /* Phase 12 / Task 12.0 — populate per-entry committed coordinates
     * after the block lands. Used by the per-entry spend_result sender
     * (Task 12.5) so each receipt carries the height + tx_index. */
    for (int i = 0; i < count; i++) {
        if (entries[i]) {
            entries[i]->committed_block_height = bh;
            entries[i]->committed_tx_index = (uint32_t)i;
        }
    }

    return nodus_witness_db_commit(w);
}

/* Task 6.3 — replay a block from a sync_rsp. */
int nodus_witness_replay_block(nodus_witness_t *w,
                                 uint64_t rsp_height,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id) {
    if (!w || !entries || count <= 0 || count > NODUS_W_MAX_BLOCK_TXS) return -1;

    uint64_t local_height = nodus_witness_block_height(w);
    if (rsp_height != local_height + 1) {
        QGP_LOG_ERROR(LOG_TAG,
            "replay_block: out-of-order sync_rsp (h=%llu, local=%llu)",
            (unsigned long long)rsp_height,
            (unsigned long long)local_height);
        return -1;
    }

    /* replay_block uses the same body as commit_batch — the only
     * difference is the height precondition above. Delegate to avoid
     * duplicating the apply+finalize+output-nullifier-append loop. */
    return nodus_witness_commit_batch(w, entries, count, timestamp, proposer_id);
}
