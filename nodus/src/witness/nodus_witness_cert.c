/**
 * Nodus — Witness Sync Cert Preimage Signing — Implementation
 *
 * See nodus_witness_cert.h for the layout spec.
 *
 * @file nodus_witness_cert.c
 */

#include "witness/nodus_witness_cert.h"

#include "witness/nodus_witness_committee.h"   /* legacy Layer-A resolver     */
#include "witness/nodus_witness_v2_epoch.h"    /* successor Layer-A resolver  */
#include "witness/nodus_witness_v2_result.h"   /* typed 4-way result algebra  */
#include "witness/nodus_witness_db.h"          /* nodus_witness_block_height  */
#include "nodus/nodus_chain_config.h"          /* derive_witness_id           */
#include "dnac/dnac.h"                          /* DNAC_PUBKEY_SIZE / _FINGERPRINT_SIZE
                                                 * / _COMMITTEE_SIZE — explicit, not
                                                 * transitive (genesis_seed.c discipline) */

#include "crypto/nodus_sign.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS-CERT"

const uint8_t NODUS_WITNESS_CERT_DOMAIN_TAG[8] = {
    'c', 'e', 'r', 't', 0x00, 0x00, 0x00, 0x00
};

_Static_assert(sizeof(NODUS_WITNESS_CERT_DOMAIN_TAG) == 8,
               "cert domain tag must be exactly 8 bytes");

int nodus_witness_compute_cert_preimage(const uint8_t *block_hash,
                                          const uint8_t *voter_id,
                                          uint64_t height,
                                          const uint8_t *chain_id,
                                          uint8_t *out_buf) {
    if (!block_hash || !voter_id || !chain_id || !out_buf) return -1;

    /* [0..7] domain tag */
    memcpy(out_buf, NODUS_WITNESS_CERT_DOMAIN_TAG,
           sizeof(NODUS_WITNESS_CERT_DOMAIN_TAG));

    /* [8..71] block_hash (64 bytes) */
    memcpy(out_buf + 8, block_hash, NODUS_T3_TX_HASH_LEN);

    /* [72..103] voter_id (32 bytes) */
    memcpy(out_buf + 72, voter_id, NODUS_T3_WITNESS_ID_LEN);

    /* [104..111] height (little-endian uint64) */
    for (int i = 0; i < 8; i++)
        out_buf[104 + i] = (uint8_t)((height >> (i * 8)) & 0xFF);

    /* [112..143] chain_id (32 bytes) */
    memcpy(out_buf + 112, chain_id, 32);

    return 0;
}

int nodus_witness_verify_sync_certs(const uint8_t *block_hash,
                                      uint64_t height,
                                      const uint8_t *chain_id,
                                      const nodus_witness_roster_t *roster,
                                      const nodus_t3_sync_cert_t *certs,
                                      uint32_t cert_count,
                                      uint32_t quorum) {
    if (!block_hash || !chain_id || !roster || !certs) return -1;

    int verified = 0;
    for (uint32_t i = 0; i < cert_count; i++) {
        const nodus_t3_sync_cert_t *c = &certs[i];

        /* Resolve voter pubkey from roster — drop unknown voters */
        const nodus_witness_roster_entry_t *voter = NULL;
        for (uint32_t r = 0; r < roster->n_witnesses; r++) {
            if (memcmp(roster->witnesses[r].witness_id, c->voter_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                voter = &roster->witnesses[r];
                break;
            }
        }
        if (!voter) continue;

        /* Reconstruct cert preimage with this cert's voter_id */
        uint8_t preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(block_hash, c->voter_id,
                                                  height, chain_id,
                                                  preimage) != 0)
            continue;

        /* CERT verify kept RAW — DNAC client also verifies these sigs via
         * qgp_dsa87_verify in dnac/src/transaction/builder.c:518 and
         * dnac/src/transaction/genesis.c:329. Tagging only one side breaks
         * compat. Deferred to a future cross-repo migration. */
        if (qgp_dsa87_verify(c->signature, NODUS_SIG_BYTES,
                              preimage, sizeof(preimage),
                              voter->pubkey) != 0) {
            QGP_LOG_WARN(LOG_TAG, "cert verify failed for voter %02x%02x..%02x%02x at height %llu",
                         c->voter_id[0], c->voter_id[1],
                         c->voter_id[30], c->voter_id[31],
                         (unsigned long long)height);
            continue;
        }
        verified++;
    }

    if ((uint32_t)verified < quorum)
        return -1;
    return verified;
}

/* ── O15G — snapshot-authority cert verifier ─────────────────────────────
 *
 * Layer-A member: the canonical voter_id (RE-DERIVED verify-time from the
 * member's pubkey) plus a borrowed pointer to that pubkey inside the resolved
 * authority object. The stored voter_id is never the source. */
typedef struct {
    uint8_t        voter_id[NODUS_T3_WITNESS_ID_LEN];
    const uint8_t *pubkey;   /* borrowed, DNAC_PUBKEY_SIZE bytes */
} cert_auth_member_t;

int nodus_witness_verify_certs_snapshot(nodus_witness_t *w,
                                          const uint8_t *block_hash,
                                          uint64_t height,
                                          const uint8_t *chain_id,
                                          const nodus_t3_sync_cert_t *certs,
                                          uint32_t cert_count,
                                          uint32_t *out_quorum) {
    /* NULL is a node-local fault, never a verdict about the block. */
    if (!w || !block_hash || !chain_id || !certs)
        return NODUS_V2_INTERNAL_FAULT;

    /* All heap owners declared up front so the single cleanup at `done`
     * releases them on every path and a goto skips no live initializer. */
    cert_auth_member_t       *members   = NULL;   /* voter_id -> pubkey map  */
    uint8_t                  *seen       = NULL;   /* Layer-B dedup set       */
    dna_vset_snapshot_t      *succ_snap  = NULL;   /* successor authority     */
    nodus_committee_member_t *leg_mem    = NULL;   /* legacy authority        */
    int      leg_count = 0;
    uint32_t n         = 0;
    uint32_t quorum    = 0;
    int      result    = NODUS_V2_INTERNAL_FAULT;  /* every goto sets it; safe default */

    /* ── Layer A — resolve the committing committee (ROSTER-FREE) ──────────
     *
     * Both resolvers read committed chain state ONLY; neither can be steered
     * by the transport mesh (Determinism G-D1). Quorum comes from the resolved
     * set size alone — never w->bft_config.quorum. */
    if (w->v2_successor) {
        int rc = nodus_witness_v2_epoch_authority_for_height(
                     w, height, &succ_snap, &n, &quorum);
        if (rc == 1) {
            /* No committed snapshot for this epoch on THIS node. -2 vs -3
             * turns on whether the boundary that freezes epoch(height) has
             * already passed on our chain (design §7.2): if it has, a missing
             * row is a genuine local hole (fail-closed, INTERNAL_FAULT); if
             * not, we are merely behind and must sync prerequisites first
             * (NOT_YET_LINKABLE). Both are NON-VERDICTS, so this boundary can
             * never fork the chain — it only steers local retry. Epochs 0 and
             * DNAC_EPOCH_LENGTH are always genesis-seeded, so es <= E ⇒
             * must-exist; every later epoch's snapshot is frozen at the prior
             * boundary (es - E). */
            uint64_t es   = nodus_v2_epoch_start_for_height(height);
            uint64_t head = nodus_witness_block_height(w);
            int must_exist = (es <= (uint64_t)DNAC_EPOCH_LENGTH) ||
                             (es - (uint64_t)DNAC_EPOCH_LENGTH) <= head;
            return must_exist ? NODUS_V2_INTERNAL_FAULT
                              : NODUS_V2_NOT_YET_LINKABLE;
        }
        if (rc != 0 || !succ_snap) {
            /* Corrupt / unreadable committed authority — fail closed. */
            return NODUS_V2_INTERNAL_FAULT;
        }
        n = (uint32_t)succ_snap->active_count;
        /* Belt-and-braces (design §8.3): the resolver already rejects an
         * active_count of 0 (epoch.c), but guard the successor arm explicitly
         * so it matches the legacy arm's leg_count<=0 fail-closed — a zero-member
         * authority is never something we may verify a quorum against. */
        if (n == 0) { result = NODUS_V2_INTERNAL_FAULT; goto done; }
    } else {
        if (nodus_committee_get_for_block_alloc(w, height, &leg_mem,
                                                  &leg_count) != 0 ||
            !leg_mem || leg_count <= 0) {
            /* Legacy resolver fails closed on a fault; an empty committee is
             * not an authority we may verify against. */
            free(leg_mem);
            return NODUS_V2_INTERNAL_FAULT;
        }
        n      = (uint32_t)leg_count;
        quorum = dna_bft_quorum(n);
    }

    members = calloc((size_t)n, sizeof(*members));
    seen    = calloc((size_t)n, sizeof(*seen));
    if (!members || !seen) { result = NODUS_V2_INTERNAL_FAULT; goto done; }

    /* Build the voter_id -> pubkey map by RE-DERIVING each voter_id from its
     * pubkey (G-D3). The successor snapshot's STORED voter_id is cross-checked
     * against the derivation but never trusted as the source; a mismatch, or a
     * duplicate member / key, is a LOCAL AUTHORITY CORRUPTION (a node fault,
     * not a verdict). O(N^2) dedup is fine at N <= 128. */
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *pk = w->v2_successor
                          ? succ_snap->entries[i].pubkey
                          : leg_mem[i].pubkey;
        if (nodus_chain_config_derive_witness_id(pk, members[i].voter_id) != 0) {
            result = NODUS_V2_INTERNAL_FAULT;   /* hash-backend failure */
            goto done;
        }
        if (w->v2_successor &&
            memcmp(succ_snap->entries[i].voter_id, members[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "snapshot integrity: stored voter_id != "
                          "derive(pubkey) for member %u at height %llu",
                          i, (unsigned long long)height);
            result = NODUS_V2_INTERNAL_FAULT;
            goto done;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (memcmp(members[j].voter_id, members[i].voter_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0 ||
                memcmp(members[j].pubkey, pk, DNAC_PUBKEY_SIZE) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "snapshot integrity: duplicate "
                              "member/key (%u==%u) at height %llu",
                              j, i, (unsigned long long)height);
                result = NODUS_V2_INTERNAL_FAULT;
                goto done;
            }
        }
        members[i].pubkey = pk;
    }

    /* ── Layer B — count UNIQUE VALID committee signers (order-free) ───────
     *
     * Legacy certs are arrival-ordered (bft.c collection dedups by pubkey,
     * does NOT sort), so signers are walked in WIRE ORDER. A non-member, a
     * duplicate signer (seen[]) and a bad signature are each DROPPED from the
     * count — never a whole-batch reject, which would let a Byzantine relayer
     * wedge an otherwise-valid quorum COMMIT by appending one garbage entry
     * (Security G-S2). Only unique valid committee signers count. */
    int verified = 0;
    for (uint32_t c = 0; c < cert_count; c++) {
        const nodus_t3_sync_cert_t *cert = &certs[c];

        /* Resolve signer -> committee member: the committee is the authority,
         * not the mesh. A non-member signer cannot be counted (G-S1). */
        int m = -1;
        for (uint32_t j = 0; j < n; j++) {
            if (memcmp(members[j].voter_id, cert->voter_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) { m = (int)j; break; }
        }
        if (m < 0)      continue;   /* non-member       — drop */
        if (seen[m])    continue;   /* duplicate signer — drop */

        /* Reconstruct cert preimage with this cert's voter_id — the SAME
         * 144-byte compute_cert_preimage the signer used; UNCHANGED. */
        uint8_t preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(block_hash, cert->voter_id,
                                                  height, chain_id,
                                                  preimage) != 0)
            continue;

        /* CERT verify kept RAW — DNAC client also verifies these sigs via
         * qgp_dsa87_verify in dnac/src/transaction/builder.c:518 and
         * dnac/src/transaction/genesis.c:329. Tagging only one side breaks
         * compat. Deferred to a future cross-repo migration. */
        if (qgp_dsa87_verify(cert->signature, NODUS_SIG_BYTES,
                              preimage, sizeof(preimage),
                              members[m].pubkey) != 0) {
            QGP_LOG_WARN(LOG_TAG, "cert verify failed for voter %02x%02x..%02x%02x at height %llu",
                         cert->voter_id[0], cert->voter_id[1],
                         cert->voter_id[30], cert->voter_id[31],
                         (unsigned long long)height);
            continue;
        }
        seen[m] = 1;
        verified++;
    }

    if (out_quorum) *out_quorum = quorum;

    /* Quorum comes ONLY from the resolved authority. A shortfall against a
     * KNOWN committee is a real verdict (peer-rotate); it is not a fault. */
    result = ((uint32_t)verified >= quorum)
           ? verified
           : NODUS_V2_CONSENSUS_INVALID;

done:
    free(members);
    free(seen);
    free(leg_mem);
    dna_vset_free(&succ_snap);
    return result;
}

/* ── O15G HIGH-2 — genesis chain_def authority cert verifier ──────────────
 *
 * The genesis block precedes any committed validator_set_snapshot, so its cert
 * authority is the genesis chain_def's OWN initial_validators[] set. The blob
 * is trustworthy only because the caller has already bound it to the
 * DISCOVER-agreed anchor (SHA3-512(chain_def) == w->g_quorum_cdh).
 *
 * The initial_validators[] pubkeys are parsed inline from the PINNED chain_def
 * layout — this MIRRORS nodus_witness_genesis_seed.c:40-95, the SAME walk the
 * genesis validator seeding uses (chain_def_codec.c is deliberately NOT linked
 * into libnodus; genesis_seed.c hand-walks for the same reason). Bounds mirror
 * that file exactly: witness_count <= 21, iv_count in [1, DNAC_COMMITTEE_SIZE],
 * full trailer present. */
#define CERT_CD_FIXED_BYTES  (32 + 4 + 64 + 64 + 4 + 4 + 4 + 4 + 4 + 8 + 1 + 8 + 64 + 32)  /* 297 */
#define CERT_CD_IV_ENTRY     ((size_t)DNAC_PUBKEY_SIZE + DNAC_FINGERPRINT_SIZE + 2 + 128)

int nodus_witness_verify_certs_chain_def(const uint8_t *block_hash,
                                          uint64_t height,
                                          const uint8_t *chain_id,
                                          const uint8_t *cd_blob,
                                          uint32_t cd_blob_len,
                                          const nodus_t3_sync_cert_t *certs,
                                          uint32_t cert_count,
                                          uint32_t *out_quorum) {
    if (!block_hash || !chain_id || !cd_blob || !certs)
        return NODUS_V2_INTERNAL_FAULT;

    /* A blob that fails ANY bound is corrupt authority → INTERNAL_FAULT (every
     * peer serves the SAME anchored bytes; a peer rotation cannot help). */
    if ((size_t)cd_blob_len < (size_t)CERT_CD_FIXED_BYTES)
        return NODUS_V2_INTERNAL_FAULT;

    const uint8_t *p_wc = cd_blob + 32 + 4 + 64 + 64;   /* witness_count @ 164 LE */
    uint32_t witness_count = (uint32_t)p_wc[0]
                           | ((uint32_t)p_wc[1] << 8)
                           | ((uint32_t)p_wc[2] << 16)
                           | ((uint32_t)p_wc[3] << 24);
    if (witness_count > 21)
        return NODUS_V2_INTERNAL_FAULT;

    size_t iv_count_off = (size_t)CERT_CD_FIXED_BYTES
                        + (size_t)witness_count * DNAC_PUBKEY_SIZE;
    if ((size_t)cd_blob_len < iv_count_off + 1)
        return NODUS_V2_INTERNAL_FAULT;

    uint8_t iv_count = cd_blob[iv_count_off];
    if (iv_count == 0 || iv_count > DNAC_COMMITTEE_SIZE)
        return NODUS_V2_INTERNAL_FAULT;

    size_t need = iv_count_off + 1 + (size_t)iv_count * CERT_CD_IV_ENTRY;
    if ((size_t)cd_blob_len < need)
        return NODUS_V2_INTERNAL_FAULT;

    uint32_t n      = iv_count;
    uint32_t quorum = dna_bft_quorum(n);
    if (out_quorum) *out_quorum = quorum;

    cert_auth_member_t *members = calloc((size_t)n, sizeof(*members));
    uint8_t            *seen    = calloc((size_t)n, sizeof(*seen));
    int result = NODUS_V2_INTERNAL_FAULT;
    if (!members || !seen) { result = NODUS_V2_INTERNAL_FAULT; goto done; }

    /* Layer A — voter_id -> pubkey map from the anchored validators, RE-DERIVING
     * each voter_id from its pubkey (G-D3). A duplicate member / pubkey is a
     * corrupt authority. The pubkey is the FIRST field of each IV entry. */
    const uint8_t *iv = cd_blob + iv_count_off + 1;
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *pk = iv + (size_t)i * CERT_CD_IV_ENTRY;
        if (nodus_chain_config_derive_witness_id(pk, members[i].voter_id) != 0) {
            result = NODUS_V2_INTERNAL_FAULT;
            goto done;
        }
        for (uint32_t j = 0; j < i; j++) {
            if (memcmp(members[j].voter_id, members[i].voter_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0 ||
                memcmp(members[j].pubkey, pk, DNAC_PUBKEY_SIZE) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "genesis chain_def integrity: duplicate "
                              "member/key (%u==%u)", j, i);
                result = NODUS_V2_INTERNAL_FAULT;
                goto done;
            }
        }
        members[i].pubkey = pk;
    }

    /* Layer B — count UNIQUE VALID committee signers (order-free); non-member /
     * duplicate / bad-sig each DROPPED, never a whole-batch reject. Identical
     * semantics to nodus_witness_verify_certs_snapshot, over the anchored set. */
    int verified = 0;
    for (uint32_t c = 0; c < cert_count; c++) {
        const nodus_t3_sync_cert_t *cert = &certs[c];

        int m = -1;
        for (uint32_t j = 0; j < n; j++) {
            if (memcmp(members[j].voter_id, cert->voter_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) { m = (int)j; break; }
        }
        if (m < 0)   continue;   /* non-member       — drop */
        if (seen[m]) continue;   /* duplicate signer — drop */

        uint8_t preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(block_hash, cert->voter_id,
                                                  height, chain_id,
                                                  preimage) != 0)
            continue;

        if (qgp_dsa87_verify(cert->signature, NODUS_SIG_BYTES,
                              preimage, sizeof(preimage),
                              members[m].pubkey) != 0) {
            QGP_LOG_WARN(LOG_TAG, "genesis cert verify failed for voter "
                         "%02x%02x..%02x%02x", cert->voter_id[0],
                         cert->voter_id[1], cert->voter_id[30], cert->voter_id[31]);
            continue;
        }
        seen[m] = 1;
        verified++;
    }

    result = ((uint32_t)verified >= quorum)
           ? verified
           : NODUS_V2_CONSENSUS_INVALID;

done:
    free(members);
    free(seen);
    return result;
}
