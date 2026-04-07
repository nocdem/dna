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
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_handlers.h"
#include "protocol/nodus_tier3.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"

#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS-BFT"

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

/* ── Config ──────────────────────────────────────────────────────── */

void nodus_witness_bft_config_init(nodus_witness_bft_config_t *cfg,
                                     uint32_t n) {
    if (!cfg) return;

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

    /* n = 3f + 1 → f = (n-1)/3 */
    cfg->f_tolerance = (n - 1) / 3;
    cfg->quorum = 2 * cfg->f_tolerance + 1;

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
    if (!w || w->my_index < 0) return false;

    uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
    int leader = nodus_witness_bft_leader_index(epoch, w->current_view,
                                                  w->roster.n_witnesses);
    return leader == w->my_index;
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

    /* Recalculate BFT config */
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);

    /* Update our index */
    w->my_index = nodus_witness_roster_find(&w->roster, w->my_id);

    fprintf(stderr, "%s: roster add (now %u witnesses, quorum=%u)\n",
            LOG_TAG, w->roster.n_witnesses, w->bft_config.quorum);
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

    return qgp_sha3_256(data, sizeof(data), chain_id_out);
}

static int update_utxo_set(nodus_witness_t *w,
                              const uint8_t *tx_hash,
                              uint8_t tx_type,
                              const uint8_t *const *nullifiers,
                              uint8_t nullifier_count,
                              const uint8_t *tx_data,
                              uint32_t tx_len) {
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

    /* Skip inputs */
    uint8_t input_count = tx_data[offset++];
    size_t input_skip = (size_t)input_count * (NODUS_T3_NULLIFIER_LEN + 8);
    offset += input_skip;

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

    for (int i = 0; i < output_count; i++) {
        /* Minimum output: version(1) + fp(129) + amount(8) + seed(32) + memo_len(1) = 171 */
        if (offset + 171 > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: output %d truncated (need %zu, have %u)\n",
                    LOG_TAG, i, offset + 171, tx_len);
            break;
        }

        offset += 1;  /* output version */

        const char *fingerprint = (const char *)(tx_data + offset);
        offset += 129;  /* fingerprint (128 hex + null) */

        uint64_t amount;
        memcpy(&amount, tx_data + offset, 8);
        offset += 8;

        const uint8_t *nullifier_seed = tx_data + offset;
        offset += 32;

        uint8_t memo_len = tx_data[offset++];
        if (offset + memo_len > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: memo truncated at output %d\n",
                    LOG_TAG, i);
            break;
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
            continue;
        }

        if (nodus_witness_utxo_add(w, nul_hash.bytes, fingerprint,
                                      amount, tx_hash, (uint32_t)i, block_height) == 0) {
            stored++;
        }
    }

    fprintf(stderr, "%s: UTXO set updated: -%d spent, +%d/%d outputs (block %llu)\n",
            LOG_TAG,
            (tx_type != NODUS_W_TX_GENESIS) ? nullifier_count : 0,
            stored, output_count,
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
static int do_commit_db(nodus_witness_t *w,
                          const uint8_t *tx_hash,
                          uint8_t tx_type,
                          const uint8_t *const *nullifiers,
                          uint8_t nullifier_count,
                          uint64_t total_supply,
                          uint64_t proposal_timestamp,
                          const uint8_t *proposer_id,
                          const uint8_t *tx_data,
                          uint32_t tx_len) {
    /* For genesis: derive chain_id from fingerprint + tx_hash, then create DB
     * (db_begin requires w->db to be open) */
    if (tx_type == NODUS_W_TX_GENESIS && !w->db) {
        /* Parse genesis fingerprint from first output in tx_data:
         * Header(74) + input_count(1) + output_count(1) + out_version(1) = 77
         * Then fingerprint is 129 bytes (128 hex + null) */
        if (!tx_data || tx_len < 77 + 129) {
            fprintf(stderr, "%s: genesis tx_data too short for fingerprint (len=%u)\n",
                    LOG_TAG, tx_len);
            return -1;
        }

        size_t fp_offset = 74;                         /* end of header */
        uint8_t in_count = tx_data[fp_offset++];       /* input_count (should be 0) */
        fp_offset += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8);  /* skip inputs */
        if (fp_offset >= tx_len) {
            fprintf(stderr, "%s: genesis tx_data truncated at outputs\n", LOG_TAG);
            return -1;
        }
        uint8_t out_count = tx_data[fp_offset++];      /* output_count */
        if (out_count == 0 || fp_offset + 1 + 129 > tx_len) {
            fprintf(stderr, "%s: genesis has no outputs or truncated\n", LOG_TAG);
            return -1;
        }
        fp_offset += 1;                                /* output version byte */
        const char *genesis_fp = (const char *)(tx_data + fp_offset);

        /* Derive chain_id = SHA3-256(fp_bytes || tx_hash) */
        uint8_t derived_chain_id[32];
        if (nodus_derive_chain_id(genesis_fp, tx_hash, derived_chain_id) != 0) {
            fprintf(stderr, "%s: failed to derive chain_id from genesis\n", LOG_TAG);
            return -1;
        }

        if (nodus_witness_create_chain_db(w, derived_chain_id) != 0) {
            fprintf(stderr, "%s: failed to create chain DB\n", LOG_TAG);
            return -1;
        }
    }

    /* Begin atomic transaction */
    if (nodus_witness_db_begin(w) != 0) {
        fprintf(stderr, "%s: db begin failed\n", LOG_TAG);
        return -1;
    }

    bool failed = false;

    if (tx_type == NODUS_W_TX_GENESIS) {

        /* Derive genesis supply from tx outputs if not provided */
        uint64_t supply = total_supply;
        if (supply == 0 && tx_data && tx_len > 75) {
            size_t off = 74;
            uint8_t in_count = tx_data[off++];
            off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8);
            if (off < tx_len) {
                uint8_t out_count = tx_data[off++];
                for (int i = 0; i < out_count && off + 171 <= tx_len; i++) {
                    off += 1;   /* version */
                    off += 129; /* fingerprint */
                    uint64_t amt;
                    memcpy(&amt, tx_data + off, 8);
                    supply += amt;
                    off += 8;   /* amount */
                    off += 32;  /* seed */
                    uint8_t ml = tx_data[off++]; /* memo_len */
                    off += ml;
                }
            }
        }
        int rc = nodus_witness_genesis_set(w, tx_hash, supply, tx_hash);
        if (rc != 0 && rc != -2) {
            fprintf(stderr, "%s: genesis record failed: %d\n", LOG_TAG, rc);
            failed = true;
        }
    } else {
        for (int i = 0; i < nullifier_count; i++) {
            int rc = nodus_witness_nullifier_add(w, nullifiers[i], tx_hash);
            if (rc != 0 && rc != -2) {  /* -2 = already exists, ok */
                fprintf(stderr, "%s: nullifier add %d failed\n", LOG_TAG, i);
                failed = true;
                break;
            }
        }
    }

    /* Update UTXO set within the same atomic transaction */
    if (!failed && tx_data && tx_len > 0) {
        if (update_utxo_set(w, tx_hash, tx_type, nullifiers, nullifier_count,
                               tx_data, tx_len) != 0) {
            fprintf(stderr, "%s: UTXO set update failed\n", LOG_TAG);
            failed = true;
        }
    }

    /* Store full transaction data for client retrieval */
    if (!failed && tx_data && tx_len > 0) {
        uint64_t bh = nodus_witness_block_height(w) + 1;
        nodus_witness_tx_store(w, tx_hash, tx_type, tx_data, tx_len, bh);
    }

    if (failed) {
        nodus_witness_db_rollback(w);
        return -1;
    }

    /* H-16: Ledger entry INSIDE atomic transaction (before COMMIT) */
    nodus_witness_ledger_add(w, tx_hash, tx_type, nullifier_count);

    if (nodus_witness_db_commit(w) != 0) {
        fprintf(stderr, "%s: db commit failed\n", LOG_TAG);
        nodus_witness_db_rollback(w);
        return -1;
    }

    /* Block creation */
    if (proposer_id) {
        nodus_witness_block_add(w, tx_hash, tx_type,
                                  proposal_timestamp, proposer_id);
    }

    return 0;
}

/* Helper: build pointer array from round_state inline nullifiers */
static void round_state_nullifier_ptrs(nodus_witness_round_state_t *rs,
                                         const uint8_t *ptrs[]) {
    for (int i = 0; i < rs->nullifier_count; i++)
        ptrs[i] = rs->nullifiers[i];
}

/* ════════════════════════════════════════════════════════════════════
 * Start round (leader only)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_start_round(nodus_witness_t *w,
                                    const uint8_t *tx_hash,
                                    const uint8_t nullifiers[][NODUS_T3_NULLIFIER_LEN],
                                    uint8_t nullifier_count,
                                    uint8_t tx_type,
                                    const uint8_t *tx_data,
                                    uint32_t tx_len,
                                    const uint8_t *client_pubkey,
                                    const uint8_t *client_sig,
                                    uint64_t fee) {
    if (!w || !tx_hash) return -1;

    if (!nodus_witness_bft_consensus_active(w)) {
        fprintf(stderr, "%s: consensus disabled (n=%u < %d)\n",
                LOG_TAG, w->bft_config.n_witnesses, NODUS_T3_MIN_WITNESSES);
        return -1;
    }

    if (!tx_data || tx_len == 0 || tx_len > NODUS_T3_MAX_TX_SIZE) {
        fprintf(stderr, "%s: invalid tx_data: ptr=%p len=%u\n",
                LOG_TAG, (void *)tx_data, tx_len);
        return -1;
    }

    /* Non-genesis requires nullifiers */
    if (tx_type != NODUS_W_TX_GENESIS &&
        (!nullifiers || nullifier_count == 0))
        return -1;

    if (nullifier_count > NODUS_T3_MAX_TX_INPUTS)
        return -1;

    /* Verify we are leader */
    if (!nodus_witness_bft_is_leader(w)) {
        fprintf(stderr, "%s: start_round but not leader\n", LOG_TAG);
        return -1;
    }

    /* Check for existing round in progress */
    if (w->round_state.phase != NODUS_W_PHASE_IDLE) {
        fprintf(stderr, "%s: round already in progress (phase=%d)\n",
                LOG_TAG, w->round_state.phase);
        return -1;
    }

    /* Full transaction verification */
    char reject_reason[256] = {0};
    int vrc = nodus_witness_verify_transaction(w, tx_data, tx_len, tx_hash,
                  tx_type, (const uint8_t *)nullifiers, nullifier_count,
                  client_pubkey, client_sig, fee,
                  reject_reason, sizeof(reject_reason));
    if (vrc != 0) {
        fprintf(stderr, "%s: TX rejected: %s\n", LOG_TAG, reject_reason);
        return vrc;  /* -1 invalid, -2 double-spend */
    }

    /* Save client connection info (set by handler before calling us) */
    struct nodus_tcp_conn *saved_conn = w->round_state.client_conn;
    uint32_t saved_txn = w->round_state.client_txn_id;
    bool saved_fwd = w->round_state.is_forwarded;
    uint8_t saved_fwd_id[NODUS_T3_WITNESS_ID_LEN];
    memcpy(saved_fwd_id, w->round_state.forwarder_id, NODUS_T3_WITNESS_ID_LEN);

    /* Initialize round state */
    w->current_round++;
    memset(&w->round_state, 0, sizeof(w->round_state));

    /* Restore client connection info */
    w->round_state.client_conn = saved_conn;
    w->round_state.client_txn_id = saved_txn;
    w->round_state.is_forwarded = saved_fwd;
    memcpy(w->round_state.forwarder_id, saved_fwd_id, NODUS_T3_WITNESS_ID_LEN);

    w->round_state.round = w->current_round;
    w->round_state.view = w->current_view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    memcpy(w->round_state.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    w->round_state.tx_type = tx_type;

    w->round_state.nullifier_count = nullifier_count;
    for (int i = 0; i < nullifier_count; i++)
        memcpy(w->round_state.nullifiers[i], nullifiers[i],
               NODUS_T3_NULLIFIER_LEN);

    memcpy(w->round_state.tx_data, tx_data, tx_len);
    w->round_state.tx_len = tx_len;
    w->round_state.proposal_timestamp = (uint64_t)time(NULL);
    memcpy(w->round_state.proposer_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    w->round_state.phase_start_time = time_ms();

    if (client_pubkey)
        memcpy(w->round_state.client_pubkey, client_pubkey, NODUS_PK_BYTES);
    if (client_sig)
        memcpy(w->round_state.client_signature, client_sig, NODUS_SIG_BYTES);
    w->round_state.fee_amount = fee;

    /* Record our own PREVOTE (leader approves own proposal) */
    memcpy(w->round_state.prevotes[0].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;

    /* Build and broadcast PROPOSAL */
    nodus_t3_msg_t proposal;
    memset(&proposal, 0, sizeof(proposal));
    proposal.type = NODUS_T3_PROPOSE;
    proposal.txn_id = ++w->next_txn_id;

    memcpy(proposal.propose.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    proposal.propose.nullifier_count = nullifier_count;
    for (int i = 0; i < nullifier_count; i++)
        proposal.propose.nullifiers[i] = w->round_state.nullifiers[i];
    proposal.propose.tx_type = tx_type;
    proposal.propose.tx_data = w->round_state.tx_data;
    proposal.propose.tx_len = tx_len;
    proposal.propose.client_pubkey = w->round_state.client_pubkey;
    proposal.propose.client_sig = w->round_state.client_signature;
    proposal.propose.fee = fee;

    int sent = nodus_witness_bft_broadcast(w, &proposal);

    /* Also broadcast our own PREVOTE so followers can count it */
    nodus_t3_msg_t prevote;
    memset(&prevote, 0, sizeof(prevote));
    prevote.type = NODUS_T3_PREVOTE;
    prevote.txn_id = ++w->next_txn_id;
    memcpy(prevote.vote.tx_hash, tx_hash, NODUS_T3_TX_HASH_LEN);
    prevote.vote.vote = NODUS_W_VOTE_APPROVE;

    nodus_witness_bft_broadcast(w, &prevote);

    fprintf(stderr, "%s: proposal broadcast to %d peers "
            "(round %lu, %d nullifiers, tx_len=%u)\n",
            LOG_TAG, sent, (unsigned long)w->current_round,
            nullifier_count, tx_len);

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Handle PROPOSAL (follower receives from leader)
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

    /* Check for existing round in progress */
    if (w->round_state.phase != NODUS_W_PHASE_IDLE) {
        fprintf(stderr, "%s: proposal rejected — round in progress (phase=%d)\n",
                LOG_TAG, w->round_state.phase);
        return -1;
    }

    /* Verify proposal is from current leader */
    uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
    int leader = nodus_witness_bft_leader_index(epoch, hdr->view,
                                                  w->roster.n_witnesses);
    int sender_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (sender_idx != leader) {
        fprintf(stderr, "%s: proposal from non-leader (sender %d, leader %d)\n",
                LOG_TAG, sender_idx, leader);
        return -1;
    }

    /* Initialize round state from proposal (needed before verification) */
    w->current_round = hdr->round;
    w->current_view = hdr->view;

    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.client_conn = NULL;
    w->round_state.round = hdr->round;
    w->round_state.view = hdr->view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    memcpy(w->round_state.tx_hash, prop->tx_hash, NODUS_T3_TX_HASH_LEN);
    w->round_state.tx_type = prop->tx_type;

    w->round_state.nullifier_count = prop->nullifier_count;
    for (int i = 0; i < prop->nullifier_count; i++)
        memcpy(w->round_state.nullifiers[i], prop->nullifiers[i],
               NODUS_T3_NULLIFIER_LEN);

    if (prop->tx_data && prop->tx_len > 0 &&
        prop->tx_len <= NODUS_T3_MAX_TX_SIZE) {
        memcpy(w->round_state.tx_data, prop->tx_data, prop->tx_len);
        w->round_state.tx_len = prop->tx_len;
    }

    if (prop->client_pubkey)
        memcpy(w->round_state.client_pubkey, prop->client_pubkey,
               NODUS_PK_BYTES);
    if (prop->client_sig)
        memcpy(w->round_state.client_signature, prop->client_sig,
               NODUS_SIG_BYTES);
    w->round_state.fee_amount = prop->fee;
    w->round_state.phase_start_time = time_ms();
    w->round_state.proposal_timestamp = hdr->timestamp;
    memcpy(w->round_state.proposer_id, hdr->sender_id,
           NODUS_T3_WITNESS_ID_LEN);

    /* Full transaction verification */
    char reject_reason[256] = {0};
    int vrc = nodus_witness_verify_transaction(w,
                  w->round_state.tx_data, w->round_state.tx_len,
                  prop->tx_hash, prop->tx_type,
                  (const uint8_t *)w->round_state.nullifiers,
                  w->round_state.nullifier_count,
                  w->round_state.client_pubkey,
                  w->round_state.client_signature,
                  w->round_state.fee_amount,
                  reject_reason, sizeof(reject_reason));

    bool tx_invalid = (vrc != 0);
    nodus_witness_vote_t my_vote =
        tx_invalid ? NODUS_W_VOTE_REJECT : NODUS_W_VOTE_APPROVE;

    /* Record our own PREVOTE */
    memcpy(w->round_state.prevotes[0].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    w->round_state.prevotes[0].vote = my_vote;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count =
        (my_vote == NODUS_W_VOTE_APPROVE) ? 1 : 0;

    /* Build and broadcast our PREVOTE */
    nodus_t3_msg_t vote_msg;
    memset(&vote_msg, 0, sizeof(vote_msg));
    vote_msg.type = NODUS_T3_PREVOTE;
    vote_msg.txn_id = ++w->next_txn_id;
    memcpy(vote_msg.vote.tx_hash, prop->tx_hash, NODUS_T3_TX_HASH_LEN);
    vote_msg.vote.vote = (uint32_t)my_vote;
    if (tx_invalid)
        snprintf(vote_msg.vote.reason, sizeof(vote_msg.vote.reason),
                 "%s", reject_reason);

    int sent = nodus_witness_bft_broadcast(w, &vote_msg);

    fprintf(stderr, "%s: PREVOTE %s for round %lu (%d nullifiers, sent=%d)\n",
            LOG_TAG,
            my_vote == NODUS_W_VOTE_APPROVE ? "APPROVE" : "REJECT",
            (unsigned long)hdr->round, prop->nullifier_count, sent);

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
    if (memcmp(vote->tx_hash, w->round_state.tx_hash,
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

    /* Duplicate check */
    for (int i = 0; i < *vote_count; i++) {
        if (memcmp(votes[i].voter_id, hdr->sender_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return 0;  /* Already received */
    }

    /* Verify sender is in roster */
    int sender_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (sender_idx < 0) {
        fprintf(stderr, "%s: vote from unknown sender\n", LOG_TAG);
        return -1;
    }

    /* Record vote */
    if (*vote_count >= NODUS_T3_MAX_WITNESSES)
        return -1;

    memcpy(votes[*vote_count].voter_id, hdr->sender_id,
           NODUS_T3_WITNESS_ID_LEN);
    votes[*vote_count].vote = (nodus_witness_vote_t)vote->vote;
    (*vote_count)++;

    if (vote->vote == NODUS_W_VOTE_APPROVE)
        (*approve_count)++;

    fprintf(stderr, "%s: %s from roster %d: %s (approve=%d/%d, quorum=%u)\n",
            LOG_TAG,
            msg->type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
            sender_idx,
            vote->vote == NODUS_W_VOTE_APPROVE ? "APPROVE" : "REJECT",
            *approve_count, *vote_count, w->bft_config.quorum);

    /* Check for quorum (genesis requires unanimous) */
    uint32_t required = w->bft_config.quorum;
    if (w->round_state.tx_type == NODUS_W_TX_GENESIS)
        required = w->bft_config.n_witnesses;

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

        /* Record our own precommit first */
        memcpy(w->round_state.precommits[0].voter_id, w->my_id,
               NODUS_T3_WITNESS_ID_LEN);
        w->round_state.precommits[0].vote = NODUS_W_VOTE_APPROVE;
        w->round_state.precommit_count = 1;
        w->round_state.precommit_approve_count = 1;

        /* Broadcast PRECOMMIT */
        nodus_t3_msg_t pc;
        memset(&pc, 0, sizeof(pc));
        pc.type = NODUS_T3_PRECOMMIT;
        pc.txn_id = ++w->next_txn_id;
        memcpy(pc.vote.tx_hash, w->round_state.tx_hash,
               NODUS_T3_TX_HASH_LEN);
        pc.vote.vote = NODUS_W_VOTE_APPROVE;

        nodus_witness_bft_broadcast(w, &pc);
        return 0;
    }

    /* next_phase == NODUS_W_PHASE_COMMIT: PRECOMMIT quorum → COMMIT */

    /* Write to database */
    const uint8_t *nul_ptrs[NODUS_T3_MAX_TX_INPUTS];
    round_state_nullifier_ptrs(&w->round_state, nul_ptrs);

    if (do_commit_db(w, w->round_state.tx_hash,
                       w->round_state.tx_type,
                       nul_ptrs,
                       w->round_state.nullifier_count,
                       w->round_state.fee_amount,
                       w->round_state.proposal_timestamp,
                       w->round_state.proposer_id,
                       w->round_state.tx_data,
                       w->round_state.tx_len) != 0) {
        fprintf(stderr, "%s: commit to DB failed!\n", LOG_TAG);
    }

    /* Store commit certificate (2f+1 precommit signatures) */
    uint64_t cert_bh = nodus_witness_block_height(w);
    nodus_witness_cert_store(w, cert_bh, w->round_state.precommits,
                              w->round_state.precommit_count);

    /* Compute UTXO set checksum for cross-witness validation */
    uint8_t utxo_cksum[NODUS_KEY_BYTES];
    bool have_cksum = (nodus_witness_utxo_checksum(w, utxo_cksum) == 0);
    if (have_cksum) {
        char hex[17];
        for (int i = 0; i < 8; i++)
            snprintf(hex + i * 2, 3, "%02x", utxo_cksum[i]);
        fprintf(stderr, "%s: UTXO checksum after round %llu: %s\n",
                LOG_TAG, (unsigned long long)w->round_state.round, hex);
    }

    w->last_committed_round = w->round_state.round;

    /* Build and broadcast COMMIT */
    nodus_t3_msg_t c_msg;
    memset(&c_msg, 0, sizeof(c_msg));
    c_msg.type = NODUS_T3_COMMIT;
    c_msg.txn_id = ++w->next_txn_id;

    memcpy(c_msg.commit.tx_hash, w->round_state.tx_hash,
           NODUS_T3_TX_HASH_LEN);
    c_msg.commit.nullifier_count = w->round_state.nullifier_count;
    for (int i = 0; i < w->round_state.nullifier_count; i++)
        c_msg.commit.nullifiers[i] = w->round_state.nullifiers[i];
    c_msg.commit.tx_type = w->round_state.tx_type;
    c_msg.commit.tx_data = w->round_state.tx_data;
    c_msg.commit.tx_len = w->round_state.tx_len;
    c_msg.commit.proposal_timestamp = w->round_state.proposal_timestamp;
    memcpy(c_msg.commit.proposer_id, w->round_state.proposer_id,
           NODUS_T3_WITNESS_ID_LEN);
    c_msg.commit.n_precommits = w->round_state.precommit_count;
    if (have_cksum)
        memcpy(c_msg.commit.utxo_checksum, utxo_cksum, NODUS_KEY_BYTES);

    nodus_witness_bft_broadcast(w, &c_msg);

    fprintf(stderr, "%s: COMMITTED round %lu (tx_type=%u)\n",
            LOG_TAG, (unsigned long)w->round_state.round,
            w->round_state.tx_type);

    /* Send spend result to client (before resetting round state) */
    if (w->round_state.client_conn && !w->round_state.is_forwarded) {
        /* Direct client request — send spend result */
        nodus_witness_send_spend_result(w, 0, NULL);
    } else if (w->round_state.is_forwarded) {
        /* Forwarded request — send w_fwd_rsp to forwarder */
        int fwd_pi = -1;
        for (int i = 0; i < w->peer_count; i++) {
            if (memcmp(w->peers[i].witness_id,
                       w->round_state.forwarder_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0 &&
                w->peers[i].conn && w->peers[i].identified) {
                fwd_pi = i;
                break;
            }
        }

        if (fwd_pi < 0) {
            fprintf(stderr, "%s: w_fwd_rsp: forwarder not found "
                    "(peers=%d, searching fid=",
                    LOG_TAG, w->peer_count);
            for (int k = 0; k < 8; k++)
                fprintf(stderr, "%02x", w->round_state.forwarder_id[k]);
            fprintf(stderr, ")\n");
            for (int i = 0; i < w->peer_count; i++) {
                fprintf(stderr, "%s:   peer %d: id=", LOG_TAG, i);
                for (int k = 0; k < 8; k++)
                    fprintf(stderr, "%02x", w->peers[i].witness_id[k]);
                fprintf(stderr, " conn=%p ident=%d\n",
                        (void *)w->peers[i].conn, w->peers[i].identified);
            }
        }

        if (fwd_pi >= 0) {
            nodus_t3_msg_t fwd_rsp;
            memset(&fwd_rsp, 0, sizeof(fwd_rsp));
            fwd_rsp.type = NODUS_T3_FWD_RSP;
            fwd_rsp.txn_id = ++w->next_txn_id;
            snprintf(fwd_rsp.method, sizeof(fwd_rsp.method), "w_fwd_rsp");

            fwd_rsp.fwd_rsp.status = 0;  /* approved */
            memcpy(fwd_rsp.fwd_rsp.tx_hash, w->round_state.tx_hash,
                   NODUS_T3_TX_HASH_LEN);
            fwd_rsp.fwd_rsp.witness_count = 0;  /* forwarder doesn't use sigs */

            fwd_rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
            fwd_rsp.header.round = w->current_round;
            fwd_rsp.header.view = w->current_view;
            memcpy(fwd_rsp.header.sender_id, w->my_id,
                   NODUS_T3_WITNESS_ID_LEN);
            fwd_rsp.header.timestamp = (uint64_t)time(NULL);
            nodus_random((uint8_t *)&fwd_rsp.header.nonce,
                          sizeof(fwd_rsp.header.nonce));
            memcpy(fwd_rsp.header.chain_id, w->chain_id, 32);

            uint8_t fwd_buf[NODUS_T3_MAX_MSG_SIZE];
            size_t fwd_len = 0;
            if (nodus_t3_encode(&fwd_rsp, &w->server->identity.sk,
                                 fwd_buf, sizeof(fwd_buf), &fwd_len) == 0) {
                nodus_tcp_send(w->peers[fwd_pi].conn, fwd_buf, fwd_len);
                QGP_LOG_DEBUG(LOG_TAG, "sent w_fwd_rsp to forwarder");
            }
        }
    }

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

    QGP_LOG_INFO(LOG_TAG, "received COMMIT for round %lu (%d nullifiers)",
                 (unsigned long)hdr->round, cmt->nullifier_count);

    /* HIGH-1: Verify tx_hash integrity before committing.
     * Recompute tx_hash from tx_data and compare with the claimed hash. */
    if (cmt->tx_data && cmt->tx_len > 0) {
        /* Determine pubkey for hash: use round_state if we participated,
         * else use all-zeros for genesis (tx_type 0). For spends where
         * we missed PROPOSE, round_state.client_pubkey will be all-zero
         * if we didn't participate — skip verification in that case since
         * the leader already verified during PROPOSE. */
        const uint8_t *hash_pubkey = w->round_state.client_pubkey;
        uint8_t zero_pk[NODUS_PK_BYTES];
        memset(zero_pk, 0, NODUS_PK_BYTES);

        if (cmt->tx_type == NODUS_W_TX_GENESIS) {
            hash_pubkey = zero_pk;
        }

        bool have_pubkey = (cmt->tx_type == NODUS_W_TX_GENESIS) ||
                           (memcmp(hash_pubkey, zero_pk, NODUS_PK_BYTES) != 0);

        if (have_pubkey) {
            uint8_t computed_hash[NODUS_KEY_BYTES];
            if (nodus_witness_recompute_tx_hash(cmt->tx_data, cmt->tx_len,
                    hash_pubkey, computed_hash) != 0 ||
                memcmp(computed_hash, cmt->tx_hash, NODUS_T3_TX_HASH_LEN) != 0) {
                QGP_LOG_WARN(LOG_TAG, "COMMIT tx_hash mismatch — rejecting round %lu",
                             (unsigned long)hdr->round);
                return -1;
            }
        } else {
            QGP_LOG_DEBUG(LOG_TAG, "COMMIT: no client_pubkey available, "
                          "skipping tx_hash re-verification (missed PROPOSE)");
        }
    }

    /* Build nullifier pointer array from T3 message */
    const uint8_t *nul_ptrs[NODUS_T3_MAX_TX_INPUTS];
    for (int i = 0; i < cmt->nullifier_count; i++)
        nul_ptrs[i] = cmt->nullifiers[i];

    /* Write to database */
    if (do_commit_db(w, cmt->tx_hash, cmt->tx_type,
                       nul_ptrs, cmt->nullifier_count,
                       0, /* total_supply not in commit */
                       cmt->proposal_timestamp,
                       cmt->proposer_id,
                       cmt->tx_data, cmt->tx_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "remote commit to DB failed!");
        return -1;
    }

    /* Compute UTXO set checksum and compare with leader's */
    {
        uint8_t utxo_cksum[NODUS_KEY_BYTES];
        if (nodus_witness_utxo_checksum(w, utxo_cksum) == 0) {
            char hex[17];
            for (int i = 0; i < 8; i++)
                snprintf(hex + i * 2, 3, "%02x", utxo_cksum[i]);
            QGP_LOG_DEBUG(LOG_TAG, "UTXO checksum after remote commit round %llu: %s",
                         (unsigned long long)hdr->round, hex);

            /* Compare with leader's checksum (if present) */
            uint8_t zero_ck[NODUS_KEY_BYTES];
            memset(zero_ck, 0, NODUS_KEY_BYTES);
            if (memcmp(cmt->utxo_checksum, zero_ck, NODUS_KEY_BYTES) != 0) {
                if (memcmp(utxo_cksum, cmt->utxo_checksum, NODUS_KEY_BYTES) != 0) {
                    QGP_LOG_WARN(LOG_TAG, "UTXO checksum DIVERGED from "
                                 "leader at round %llu!",
                                 (unsigned long long)hdr->round);
                }
            }
        }
    }

    /* Update committed round */
    if (hdr->round > w->last_committed_round)
        w->last_committed_round = hdr->round;

    /* Handle client response if this was our active round */
    if (w->round_state.round == hdr->round) {
        /* Direct client request — send spend result */
        if (w->round_state.client_conn && !w->round_state.is_forwarded) {
            nodus_witness_send_spend_result(w, 0, NULL);
        } else if (w->round_state.is_forwarded) {
            /* Forwarded request — send w_fwd_rsp to forwarder */
            int fwd_pi = -1;
            for (int i = 0; i < w->peer_count; i++) {
                if (memcmp(w->peers[i].witness_id,
                           w->round_state.forwarder_id,
                           NODUS_T3_WITNESS_ID_LEN) == 0 &&
                    w->peers[i].conn && w->peers[i].identified) {
                    fwd_pi = i;
                    break;
                }
            }

            if (fwd_pi >= 0) {
                nodus_t3_msg_t fwd_rsp;
                memset(&fwd_rsp, 0, sizeof(fwd_rsp));
                fwd_rsp.type = NODUS_T3_FWD_RSP;
                fwd_rsp.txn_id = ++w->next_txn_id;
                snprintf(fwd_rsp.method, sizeof(fwd_rsp.method), "w_fwd_rsp");

                fwd_rsp.fwd_rsp.status = 0;
                memcpy(fwd_rsp.fwd_rsp.tx_hash, cmt->tx_hash,
                       NODUS_T3_TX_HASH_LEN);
                fwd_rsp.fwd_rsp.witness_count = 0;  /* forwarder doesn't use sigs */

                fwd_rsp.header.version = NODUS_T3_BFT_PROTOCOL_VER;
                fwd_rsp.header.round = hdr->round;
                fwd_rsp.header.view = hdr->view;
                memcpy(fwd_rsp.header.sender_id, w->my_id,
                       NODUS_T3_WITNESS_ID_LEN);
                fwd_rsp.header.timestamp = (uint64_t)time(NULL);
                nodus_random((uint8_t *)&fwd_rsp.header.nonce,
                              sizeof(fwd_rsp.header.nonce));
                memcpy(fwd_rsp.header.chain_id, w->chain_id, 32);

                uint8_t fwd_buf[NODUS_T3_MAX_MSG_SIZE];
                size_t fwd_len = 0;
                if (nodus_t3_encode(&fwd_rsp, &w->server->identity.sk,
                                     fwd_buf, sizeof(fwd_buf), &fwd_len) == 0) {
                    nodus_tcp_send(w->peers[fwd_pi].conn, fwd_buf, fwd_len);
                    fprintf(stderr, "%s: sent w_fwd_rsp to forwarder "
                            "(via handle_commit)\n", LOG_TAG);
                }
            }
        }

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

    /* Verify sender is in roster */
    int sender_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (sender_idx < 0)
        return -1;

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

    if (w->view_change_count < NODUS_T3_MAX_WITNESSES) {
        memcpy(w->view_changes[w->view_change_count].voter_id,
               hdr->sender_id, NODUS_T3_WITNESS_ID_LEN);
        w->view_changes[w->view_change_count].target_view = vc->new_view;
        w->view_changes[w->view_change_count].last_committed_round =
            vc->last_committed_round;
        w->view_change_count++;
    }

    fprintf(stderr, "%s: VIEW_CHANGE from roster %d: view %u (%d/%u)\n",
            LOG_TAG, sender_idx, vc->new_view,
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

    /* If we are new leader, broadcast NEW_VIEW */
    uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
    int new_leader = nodus_witness_bft_leader_index(epoch, w->current_view,
                                                      w->roster.n_witnesses);

    if (new_leader == w->my_index) {
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

    /* Verify sender is expected new leader */
    uint64_t epoch = (uint64_t)time(NULL) / NODUS_T3_EPOCH_DURATION_SEC;
    int expected_leader = nodus_witness_bft_leader_index(
        epoch, nv->new_view, w->roster.n_witnesses);

    int sender_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (sender_idx != expected_leader) {
        fprintf(stderr, "%s: NEW_VIEW from non-leader\n", LOG_TAG);
        return -1;
    }

    /* Accept new view if higher than current */
    if (nv->new_view > w->current_view) {
        w->current_view = nv->new_view;
        w->view_change_in_progress = false;
        w->round_state.phase = NODUS_W_PHASE_IDLE;

        fprintf(stderr, "%s: accepted NEW_VIEW %u from leader %d\n",
                LOG_TAG, nv->new_view, sender_idx);
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Timeout check (called from nodus_witness_tick)
 * ════════════════════════════════════════════════════════════════════ */

void nodus_witness_bft_check_timeout(nodus_witness_t *w) {
    if (!w) return;

    if (w->round_state.phase == NODUS_W_PHASE_IDLE ||
        w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE)
        return;

    uint64_t elapsed = time_ms() - w->round_state.phase_start_time;

    if (elapsed > w->bft_config.round_timeout_ms) {
        /* Transition to VIEW_CHANGE immediately to stop further timeout checks.
         * Must happen here, not inside initiate_view_change, because a remote
         * VIEW_CHANGE message may have set view_change_in_progress=true without
         * changing the phase — causing initiate to return early. */
        w->round_state.phase = NODUS_W_PHASE_VIEW_CHANGE;

        fprintf(stderr, "%s: round timeout (%lu ms), initiating view change\n",
                LOG_TAG, (unsigned long)elapsed);
        nodus_witness_bft_initiate_view_change(w);
    }
}
