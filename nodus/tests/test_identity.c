/**
 * Nodus — Identity Tests
 *
 * Tests keypair generation, deterministic seed derivation,
 * sign/verify, and save/load roundtrip.
 * Read-only loader (nodus_identity_load_readonly): full load matches, and a
 * missing/mismatched key file is refused with the directory left exactly as
 * it was; mkdtemp dirs under /tmp, removed at the end.
 */

#define _DEFAULT_SOURCE 1   /* mkdtemp, st_mtim under -std=c11 */

#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_generate_random(void) {
    TEST("generate random identity");
    nodus_identity_t id;
    int rc = nodus_identity_generate(&id);

    if (rc == 0 &&
        !nodus_key_is_zero(&id.node_id) &&
        id.fingerprint[0] != '\0' &&
        strlen(id.fingerprint) == 128) {
        PASS();
    } else {
        FAIL("generate failed");
    }
    nodus_identity_clear(&id);
}

static void test_from_seed_deterministic(void) {
    TEST("seed derivation is deterministic");
    uint8_t seed[32];
    memset(seed, 0xAA, sizeof(seed));

    nodus_identity_t id1, id2;
    nodus_identity_from_seed(seed, &id1);
    nodus_identity_from_seed(seed, &id2);

    if (memcmp(id1.pk.bytes, id2.pk.bytes, NODUS_PK_BYTES) == 0 &&
        memcmp(id1.sk.bytes, id2.sk.bytes, NODUS_SK_BYTES) == 0 &&
        nodus_key_cmp(&id1.node_id, &id2.node_id) == 0 &&
        strcmp(id1.fingerprint, id2.fingerprint) == 0) {
        PASS();
    } else {
        FAIL("same seed produced different identity");
    }
    nodus_identity_clear(&id1);
    nodus_identity_clear(&id2);
}

static void test_different_seeds(void) {
    TEST("different seeds produce different identities");
    uint8_t seed1[32], seed2[32];
    memset(seed1, 0x11, sizeof(seed1));
    memset(seed2, 0x22, sizeof(seed2));

    nodus_identity_t id1, id2;
    nodus_identity_from_seed(seed1, &id1);
    nodus_identity_from_seed(seed2, &id2);

    if (memcmp(id1.pk.bytes, id2.pk.bytes, NODUS_PK_BYTES) != 0 &&
        nodus_key_cmp(&id1.node_id, &id2.node_id) != 0) {
        PASS();
    } else {
        FAIL("different seeds produced same identity");
    }
    nodus_identity_clear(&id1);
    nodus_identity_clear(&id2);
}

static void test_fingerprint_is_sha3_512(void) {
    TEST("fingerprint = SHA3-512(pubkey)");
    uint8_t seed[32] = {0};
    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    /* Compute fingerprint manually */
    nodus_key_t computed_fp;
    nodus_fingerprint(&id.pk, &computed_fp);

    if (nodus_key_cmp(&id.node_id, &computed_fp) == 0) {
        PASS();
    } else {
        FAIL("node_id != SHA3-512(pk)");
    }
    nodus_identity_clear(&id);
}

static void test_sign_verify_with_identity(void) {
    TEST("sign and verify with identity");
    uint8_t seed[32];
    memset(seed, 0x55, sizeof(seed));

    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    const uint8_t msg[] = "test message for signing";
    nodus_sig_t sig;

    int sign_rc = nodus_sign(&sig, msg, sizeof(msg) - 1, &id.sk);
    if (sign_rc != 0) {
        FAIL("sign failed");
        nodus_identity_clear(&id);
        return;
    }

    int verify_rc = nodus_verify(&sig, msg, sizeof(msg) - 1, &id.pk);
    if (verify_rc == 0) {
        PASS();
    } else {
        FAIL("verify failed");
    }
    nodus_identity_clear(&id);
}

static void test_value_id_derivation(void) {
    TEST("value_id from identity");
    uint8_t seed[32];
    memset(seed, 0x77, sizeof(seed));

    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    uint64_t vid = nodus_identity_value_id(&id);

    /* Should be non-zero for non-zero identity */
    if (vid != 0) {
        /* Deterministic */
        nodus_identity_t id2;
        nodus_identity_from_seed(seed, &id2);
        uint64_t vid2 = nodus_identity_value_id(&id2);

        if (vid == vid2)
            PASS();
        else
            FAIL("value_id not deterministic");

        nodus_identity_clear(&id2);
    } else {
        FAIL("value_id is zero");
    }
    nodus_identity_clear(&id);
}

static void test_save_load_roundtrip(void) {
    TEST("save/load identity roundtrip");

    /* Create temp directory */
    const char *tmpdir = "/tmp/nodus_test_identity";
    mkdir(tmpdir, 0700);

    uint8_t seed[32];
    memset(seed, 0xBB, sizeof(seed));

    nodus_identity_t id_orig;
    nodus_identity_from_seed(seed, &id_orig);

    /* Save */
    int rc = nodus_identity_save(&id_orig, tmpdir);
    if (rc != 0) {
        FAIL("save failed");
        nodus_identity_clear(&id_orig);
        return;
    }

    /* Load */
    nodus_identity_t id_loaded;
    rc = nodus_identity_load(tmpdir, &id_loaded);
    if (rc != 0) {
        FAIL("load failed");
        nodus_identity_clear(&id_orig);
        return;
    }

    /* Compare */
    if (memcmp(id_orig.pk.bytes, id_loaded.pk.bytes, NODUS_PK_BYTES) == 0 &&
        memcmp(id_orig.sk.bytes, id_loaded.sk.bytes, NODUS_SK_BYTES) == 0 &&
        nodus_key_cmp(&id_orig.node_id, &id_loaded.node_id) == 0 &&
        strcmp(id_orig.fingerprint, id_loaded.fingerprint) == 0) {
        PASS();
    } else {
        FAIL("loaded identity doesn't match original");
    }

    /* Cleanup */
    char path[256];
    snprintf(path, sizeof(path), "%s/nodus.pk", tmpdir);
    remove(path);
    snprintf(path, sizeof(path), "%s/nodus.sk", tmpdir);
    remove(path);
    snprintf(path, sizeof(path), "%s/nodus.fp", tmpdir);
    remove(path);
    rmdir(tmpdir);

    nodus_identity_clear(&id_orig);
    nodus_identity_clear(&id_loaded);
}

static void test_hex_fingerprint_format(void) {
    TEST("hex fingerprint is 128 lowercase hex chars");
    uint8_t seed[32];
    memset(seed, 0xCC, sizeof(seed));

    nodus_identity_t id;
    nodus_identity_from_seed(seed, &id);

    if (strlen(id.fingerprint) != 128) {
        FAIL("wrong length");
        nodus_identity_clear(&id);
        return;
    }

    /* Check all chars are hex */
    bool all_hex = true;
    for (int i = 0; i < 128; i++) {
        char c = id.fingerprint[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            all_hex = false;
            break;
        }
    }

    if (all_hex)
        PASS();
    else
        FAIL("non-hex characters in fingerprint");

    nodus_identity_clear(&id);
}

/* ── Read-only loader (component split S2, decision 2026-10-01-nodus-
 * component-split item 10: storage and witness only READ identity files) ──
 *
 * A directory snapshot = every entry's name, size and mtime (ns), sorted by
 * name. Two equal snapshots mean no file was created, removed, resized or
 * rewritten. The control case runs the OLD (writing) loader on the same
 * kind of directory and requires the snapshot to CHANGE — proof the
 * detector can see a write, so an "unchanged" verdict is not vacuous. */

#define SNAP_MAX 32

typedef struct {
    char     name[64];
    off_t    size;
    long     mtime_sec;
    long     mtime_nsec;
} snap_entry_t;

typedef struct {
    int          n;
    snap_entry_t e[SNAP_MAX];
} dir_snap_t;

static int snap_cmp(const void *a, const void *b) {
    return strcmp(((const snap_entry_t *)a)->name, ((const snap_entry_t *)b)->name);
}

static int dir_snapshot(const char *dir, dir_snap_t *out) {
    memset(out, 0, sizeof(*out));
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (out->n >= SNAP_MAX) { closedir(d); return -1; }
        snap_entry_t *e = &out->e[out->n++];
        snprintf(e->name, sizeof(e->name), "%s", de->d_name);
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(p, &st) != 0) { closedir(d); return -1; }
        e->size = st.st_size;
        e->mtime_sec = (long)st.st_mtim.tv_sec;
        e->mtime_nsec = (long)st.st_mtim.tv_nsec;
    }
    closedir(d);
    qsort(out->e, (size_t)out->n, sizeof(out->e[0]), snap_cmp);
    return 0;
}

static bool snap_equal(const dir_snap_t *a, const dir_snap_t *b) {
    if (a->n != b->n) return false;
    for (int i = 0; i < a->n; i++) {
        if (strcmp(a->e[i].name, b->e[i].name) != 0 ||
            a->e[i].size != b->e[i].size ||
            a->e[i].mtime_sec != b->e[i].mtime_sec ||
            a->e[i].mtime_nsec != b->e[i].mtime_nsec)
            return false;
    }
    return true;
}

/* Fresh mkdtemp dir holding a full saved identity (all six key files +
 * nodus.fp) from a fixed seed. Returns 0 and the dir in `dir`. */
static int make_identity_dir(char *dir, size_t cap, nodus_identity_t *id_out) {
    snprintf(dir, cap, "/tmp/nodus_idro_XXXXXX");
    if (!mkdtemp(dir)) return -1;
    uint8_t seed[32];
    memset(seed, 0x5A, sizeof(seed));
    if (nodus_identity_from_seed(seed, id_out) != 0) return -1;
    return nodus_identity_save(id_out, dir);
}

static void remove_identity_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
            char p[512];
            snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

static bool id_equal(const nodus_identity_t *a, const nodus_identity_t *b) {
    return memcmp(a->pk.bytes, b->pk.bytes, NODUS_PK_BYTES) == 0 &&
           memcmp(a->sk.bytes, b->sk.bytes, NODUS_SK_BYTES) == 0 &&
           nodus_key_cmp(&a->node_id, &b->node_id) == 0 &&
           strcmp(a->fingerprint, b->fingerprint) == 0 &&
           a->has_kyber && b->has_kyber &&
           memcmp(a->kyber_pk, b->kyber_pk, NODUS_KYBER_PK_BYTES) == 0 &&
           memcmp(a->kyber_sk, b->kyber_sk, NODUS_KYBER_SK_BYTES) == 0 &&
           a->has_mlkem && b->has_mlkem &&
           memcmp(a->mlkem_pk, b->mlkem_pk, NODUS_MLKEM_PK_BYTES) == 0 &&
           memcmp(a->mlkem_sk, b->mlkem_sk, NODUS_MLKEM_SK_BYTES) == 0;
}

static void test_readonly_full_load(void) {
    TEST("readonly load: full identity matches, dir unchanged");
    char dir[64];
    nodus_identity_t orig;
    if (make_identity_dir(dir, sizeof(dir), &orig) != 0) {
        FAIL("fixture failed");
        return;
    }
    dir_snap_t before, after;
    dir_snapshot(dir, &before);

    nodus_identity_t ro, rw;
    int ro_rc = nodus_identity_load_readonly(dir, &ro);
    dir_snapshot(dir, &after);
    bool unchanged = snap_equal(&before, &after) && before.n == 7;
    int rw_rc = nodus_identity_load(dir, &rw);   /* full dir: old loader writes nothing */

    if (ro_rc == 0 && rw_rc == 0 && unchanged && id_equal(&ro, &orig) && id_equal(&ro, &rw))
        PASS();
    else
        FAIL("readonly load failed, differs from original/old loader, or touched the dir");

    nodus_identity_clear(&orig);
    nodus_identity_clear(&ro);
    nodus_identity_clear(&rw);
    remove_identity_dir(dir);
}

/* Remove `victim` (or, if corrupt_byte, flip a byte of it in place), then
 * require: readonly load fails, id_out is zeroed, and the dir snapshot is
 * identical before/after the load. */
static void readonly_refuses(const char *label, const char *victim, bool corrupt_byte) {
    TEST(label);
    char dir[64];
    nodus_identity_t orig;
    if (make_identity_dir(dir, sizeof(dir), &orig) != 0) {
        FAIL("fixture failed");
        return;
    }
    char vp[512];
    snprintf(vp, sizeof(vp), "%s/%s", dir, victim);
    if (corrupt_byte) {
        FILE *f = fopen(vp, "r+b");
        int c = f ? fgetc(f) : EOF;
        if (f && c != EOF) {
            fseek(f, 0, SEEK_SET);
            fputc(c ^ 0xFF, f);
        }
        if (f) fclose(f);
    } else {
        unlink(vp);
    }

    dir_snap_t before, after;
    dir_snapshot(dir, &before);
    nodus_identity_t ro;
    memset(&ro, 0xA5, sizeof(ro));
    int rc = nodus_identity_load_readonly(dir, &ro);
    dir_snapshot(dir, &after);

    nodus_identity_t zero;
    memset(&zero, 0, sizeof(zero));
    bool zeroed = memcmp(&ro, &zero, sizeof(ro)) == 0;

    if (rc == -1 && zeroed && snap_equal(&before, &after))
        PASS();
    else
        FAIL("did not refuse, left key material in id_out, or touched the dir");

    nodus_identity_clear(&orig);
    remove_identity_dir(dir);
}

static void test_readonly_control_old_loader_writes(void) {
    TEST("control: OLD loader on missing ML-KEM DOES change dir");
    char dir[64];
    nodus_identity_t orig;
    if (make_identity_dir(dir, sizeof(dir), &orig) != 0) {
        FAIL("fixture failed");
        return;
    }
    char vp[512];
    snprintf(vp, sizeof(vp), "%s/nodus.mlkem_sk", dir);
    unlink(vp);

    dir_snap_t before, after;
    dir_snapshot(dir, &before);
    nodus_identity_t rw;
    int rc = nodus_identity_load(dir, &rw);
    dir_snapshot(dir, &after);

    /* The old loader regenerates and writes both ML-KEM files; the
     * snapshot detector must see that. */
    if (rc == 0 && !snap_equal(&before, &after))
        PASS();
    else
        FAIL("snapshot did not detect the old loader's write (detector blind)");

    nodus_identity_clear(&orig);
    nodus_identity_clear(&rw);
    remove_identity_dir(dir);
}

int main(void) {
    printf("=== Nodus Identity Tests ===\n");

    test_generate_random();
    test_from_seed_deterministic();
    test_different_seeds();
    test_fingerprint_is_sha3_512();
    test_sign_verify_with_identity();
    test_value_id_derivation();
    test_save_load_roundtrip();
    test_hex_fingerprint_format();
    test_readonly_full_load();
    readonly_refuses("readonly load: missing nodus.mlkem_sk refused",
                     "nodus.mlkem_sk", false);
    readonly_refuses("readonly load: missing nodus.mlkem_pk refused",
                     "nodus.mlkem_pk", false);
    readonly_refuses("readonly load: missing nodus.kyber_pk refused",
                     "nodus.kyber_pk", false);
    readonly_refuses("readonly load: missing nodus.kyber_sk refused",
                     "nodus.kyber_sk", false);
    readonly_refuses("readonly load: missing nodus.sk refused",
                     "nodus.sk", false);
    readonly_refuses("readonly load: mismatched ML-KEM pair refused",
                     "nodus.mlkem_pk", true);
    test_readonly_control_old_loader_writes();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
