/**
 * Nodus — Task 29 Rule D locked-UTXO verify test
 *
 * Rule D (design §3.8): SPEND verify rejects inputs whose referenced UTXO
 * has unlock_block > current_block. UNSTAKE commit produces a locked UTXO
 * whose unlock_block = commit_block + DNAC_UNSTAKE_COOLDOWN_BLOCKS (17280
 * blocks ≈ 24h at 5s/block).
 *
 * This test exercises the lookup layer directly via
 * nodus_witness_utxo_lookup_ex — it verifies that the v15 unlock_block
 * column round-trips through insert and retrieval, and that the lock
 * boundary is strict inequality (unlock_block > current ⇒ locked;
 * unlock_block == current ⇒ already spendable).
 *
 * The full SPEND verify path is exercised indirectly (the verify code at
 * line 434 of nodus_witness_verify.c reads unlock_block and rejects when
 * utxo_unlock_block > current_block). Building a full signed SPEND TX
 * would require Dilithium5 signers + witness attestations and is out of
 * scope for a focused lock-boundary regression.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); exit(1); \
    } } while (0)

static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

int main(void) {
    char data_path[] = "/tmp/test_locked_utxo_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xB2, sizeof(chain_id));

    /* Create chain DB — runs full schema + v15 (unlock_block) migration. */
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);
    CHECK(w.db != NULL);

    /* ── Fixture: two UTXOs, one unlocked, one locked ────────────────── */

    /* Nullifier #1: unlocked (unlock_block = 0, spendable at any height). */
    uint8_t nul_a[64];
    memset(nul_a, 0xA1, sizeof(nul_a));
    uint8_t txh_a[64];
    memset(txh_a, 0x01, sizeof(txh_a));

    rc = nodus_witness_utxo_add(&w, nul_a, "fp_a", 12345ULL,
                                 txh_a, 0, 50ULL, NULL);
    CHECK_EQ(rc, 0);

    /* Nullifier #2: locked (unlock_block = 100). Spendable only when
     * current_block >= 100 per design §3.8 strict-inequality rule D. */
    uint8_t nul_b[64];
    memset(nul_b, 0xB2, sizeof(nul_b));
    uint8_t txh_b[64];
    memset(txh_b, 0x02, sizeof(txh_b));

    rc = nodus_witness_utxo_add_locked(&w, nul_b, "fp_b", 67890ULL,
                                        txh_b, 0, 50ULL, NULL, 100ULL);
    CHECK_EQ(rc, 0);

    /* ── Phase 1: lookup round-trip preserves unlock_block ───────────── */
    {
        uint64_t amount = 0, unlock = 0;
        char owner[129] = {0};
        uint8_t token[64];
        memset(token, 0xFF, sizeof(token));  /* poison → should be zeroed */

        rc = nodus_witness_utxo_lookup_ex(&w, nul_a, &amount, owner,
                                            token, &unlock);
        CHECK_EQ(rc, 0);
        CHECK_EQ(amount, 12345ULL);
        CHECK(strcmp(owner, "fp_a") == 0);
        CHECK_EQ(unlock, 0ULL);  /* unlocked UTXO */
        for (int i = 0; i < 64; i++) CHECK_EQ(token[i], 0);  /* native DNAC */
    }
    {
        uint64_t amount = 0, unlock = 0;
        char owner[129] = {0};
        uint8_t token[64];

        rc = nodus_witness_utxo_lookup_ex(&w, nul_b, &amount, owner,
                                            token, &unlock);
        CHECK_EQ(rc, 0);
        CHECK_EQ(amount, 67890ULL);
        CHECK(strcmp(owner, "fp_b") == 0);
        CHECK_EQ(unlock, 100ULL);  /* locked at block 100 */
    }

    /* ── Phase 2: lock-boundary simulation of SPEND verify check ──────
     *
     * Mirrors the witness verify logic (nodus_witness_verify.c:~440):
     *     if (utxo.unlock_block > current_block) REJECT
     *
     * For nul_b (unlock_block=100):
     *   current=50  → 100 > 50 → LOCKED (reject)
     *   current=99  → 100 > 99 → LOCKED (reject)
     *   current=100 → 100 > 100 is false → UNLOCKED (accept)
     *   current=101 → 100 > 101 is false → UNLOCKED (accept)
     */
    {
        uint64_t unlock = 0;
        rc = nodus_witness_utxo_lookup_ex(&w, nul_b, NULL, NULL, NULL, &unlock);
        CHECK_EQ(rc, 0);

        CHECK(unlock > 50ULL);    /* would reject at current=50 */
        CHECK(unlock > 99ULL);    /* would reject at current=99 */
        CHECK(!(unlock > 100ULL)); /* boundary: unlock == current → accept */
        CHECK(!(unlock > 101ULL)); /* past boundary → accept */
    }

    /* ── Phase 3: unlocked UTXO is always spendable ──────────────────── */
    {
        uint64_t unlock = 42ULL;  /* poison sentinel */
        rc = nodus_witness_utxo_lookup_ex(&w, nul_a, NULL, NULL, NULL, &unlock);
        CHECK_EQ(rc, 0);
        CHECK_EQ(unlock, 0ULL);
        /* Any non-negative current_block ≥ 0 ≥ unlock → accept. */
        CHECK(!(unlock > 0ULL));
    }

    /* ── Phase 4: backward-compat — legacy nodus_witness_utxo_lookup
     *    returns same amount/owner as _ex but without unlock_block. ──── */
    {
        uint64_t amount = 0;
        char owner[129] = {0};
        uint8_t token[64];
        memset(token, 0xFF, sizeof(token));

        rc = nodus_witness_utxo_lookup(&w, nul_b, &amount, owner, token);
        CHECK_EQ(rc, 0);
        CHECK_EQ(amount, 67890ULL);
        CHECK(strcmp(owner, "fp_b") == 0);
    }

    /* ── Phase 5: missing nullifier returns -1 ──────────────────────── */
    {
        uint8_t missing[64];
        memset(missing, 0xCC, sizeof(missing));

        uint64_t amount = 0, unlock = 0;
        rc = nodus_witness_utxo_lookup_ex(&w, missing, &amount, NULL,
                                            NULL, &unlock);
        CHECK(rc != 0);
    }

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_locked_utxo: ALL CHECKS PASSED\n");
    return 0;
}
