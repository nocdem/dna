/**
 * @file check_witness_announce.c
 * @brief Check if witness servers are publishing epoch announcements
 *
 * Usage: check_witness_announce [-d datadir]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <dna/dna_engine.h>
#include "nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_types.h"
#include "dnac/epoch.h"

/* Witness fingerprints */
static const char *WITNESSES[] = {
    "46de00d4e2ac54bdb70f3867498707ebaca58c65ca7713569fe183ffeeea46bdf380804405430d4684d8fc17b4702003d46d013151749a43fdc6b84d7472709d",  /* node1 */
    "d43514f121b508ca304ce741edca0bd1fbe661fe5fbd6f188b6831d0794179977083e9fbae4aa40e7d16ee73918b6e26f9c29011914415732322a2b129303634",  /* treasury */
    "7dea0967abe22f720be1b1c0f68131eb1e39d93a5bb58039836fe842a10fefec1db52df710238edcb90216f232da5c621e4a2e92b6c42508b64baf43594935e7",  /* cpunkroot2 */
    NULL
};

static const char *WITNESS_NAMES[] = {
    "node1 (192.168.0.195)",
    "treasury (192.168.0.196)",
    "cpunkroot2 (192.168.0.199)",
    NULL
};

#define WITNESS_ANNOUNCE_PREFIX "dnac:witness:announce:"

/* Identity load callback */
static volatile int g_identity_loaded = 0;
static volatile int g_identity_result = -1;

static void identity_loaded_cb(unsigned long req_id, int result, void *user_data) {
    (void)req_id;
    (void)user_data;
    g_identity_result = result;
    g_identity_loaded = 1;
}

/**
 * Compute fingerprint from identity key file
 */
static int compute_identity_fingerprint(const char *data_dir, char *fingerprint_out) {
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        fprintf(stderr, "Failed to load signing key: %s\n", key_path);
        return -1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->public_key) {
        fprintf(stderr, "Not a Dilithium5 key or missing public key\n");
        qgp_key_free(key);
        return -1;
    }

    int rc = qgp_sha3_512_fingerprint(key->public_key, key->public_key_size, fingerprint_out);
    qgp_key_free(key);
    return rc;
}

static int check_witness_announcement(const char *fingerprint, const char *name) {
    /* Build the key: SHA3-512(prefix + fingerprint) */
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s%s", WITNESS_ANNOUNCE_PREFIX, fingerprint);

    uint8_t key_hash[64];
    if (qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), key_hash) != 0) {
        printf("  [%s] FAILED - Could not compute key hash\n", name);
        return -1;
    }

    /* Convert to hex for display */
    char key_hex[129];
    for (int i = 0; i < 64; i++) {
        sprintf(&key_hex[i*2], "%02x", key_hash[i]);
    }
    key_hex[128] = '\0';

    printf("  [%s]\n", name);
    printf("    Key: %.32s...\n", key_hex);

    /* Query DHT (blocking) */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int rc = nodus_ops_get(key_hash, 64, &data, &data_len);

    if (rc == 0 && data != NULL && data_len > 0) {
        printf("    Status: FOUND (%zu bytes)\n", data_len);
        free(data);
        return 0;
    } else {
        printf("    Status: NOT FOUND (rc=%d)\n", rc);
        return -1;
    }
}

int main(int argc, char *argv[]) {
    char *data_dir = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "d:h")) != -1) {
        switch (opt) {
            case 'd':
                data_dir = strdup(optarg);
                break;
            case 'h':
                printf("Usage: %s [-d datadir]\n", argv[0]);
                return 0;
            default:
                return 1;
        }
    }

    if (!data_dir) {
        const char *home = getenv("HOME");
        if (home) {
            data_dir = malloc(strlen(home) + 10);
            sprintf(data_dir, "%s/.dna", home);
        } else {
            data_dir = strdup(".dna");
        }
    }

    printf("Check Witness Epoch Announcements\n");
    printf("==================================\n");
    printf("Data dir: %s\n", data_dir);
    printf("Current epoch: %lu\n", (unsigned long)(time(NULL) / DNAC_EPOCH_DURATION_SEC));
    printf("\n");

    /* Create engine */
    dna_engine_t *engine = dna_engine_create(data_dir);
    if (!engine) {
        fprintf(stderr, "Failed to create DNA engine\n");
        free(data_dir);
        return 1;
    }

    /* Check and load identity */
    if (!dna_engine_has_identity(engine)) {
        fprintf(stderr, "No identity found in %s\n", data_dir);
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    /* Compute fingerprint from key file */
    char fingerprint[129] = {0};
    if (compute_identity_fingerprint(data_dir, fingerprint) != 0) {
        fprintf(stderr, "Failed to compute fingerprint\n");
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    printf("Loading identity: %.32s...\n", fingerprint);
    dna_engine_load_identity(engine, fingerprint, NULL, identity_loaded_cb, NULL);

    /* Wait for identity to load (max 30 seconds) */
    int wait_count = 0;
    while (!g_identity_loaded && wait_count < 300) {
        usleep(100000);  /* 100ms */
        wait_count++;
    }

    if (!g_identity_loaded || g_identity_result != 0) {
        fprintf(stderr, "Failed to load identity (result=%d, timeout=%d)\n",
                g_identity_result, !g_identity_loaded);
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    printf("Identity loaded.\n");

    /* Wait for DHT to be ready */
    printf("Waiting for DHT connection...\n");
    wait_count = 0;
    while (!nodus_ops_is_ready() && wait_count < 100) {
        usleep(100000);  /* 100ms */
        wait_count++;
    }

    if (!nodus_ops_is_ready()) {
        fprintf(stderr, "DHT not connected after 10s\n");
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    printf("DHT connected.\n\n");

    printf("Checking witness announcements:\n");

    int found_count = 0;
    for (int i = 0; WITNESSES[i] != NULL; i++) {
        if (check_witness_announcement(WITNESSES[i], WITNESS_NAMES[i]) == 0) {
            found_count++;
        }
        printf("\n");
    }

    printf("==================================\n");
    printf("Result: %d/%d witnesses publishing\n", found_count, 3);

    dna_engine_destroy(engine);
    free(data_dir);

    return (found_count == 3) ? 0 : 1;
}
