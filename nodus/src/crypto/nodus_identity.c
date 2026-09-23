/**
 * Nodus — Identity Generation & Management
 *
 * Generates Dilithium5 keypairs from seed (deterministic) or randomly.
 * Seed derivation uses qgp_dsa87_keypair_derand() which produces
 * identical keypairs to OpenDHT-PQ's pqcrystals_dilithium5_ref_keypair_from_seed().
 */

#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "crypto/enc/kyber_r3_legacy.h"
#include "crypto/enc/kem/fips202.h"   /* D10 (N1 delta 1): shake256() for the
                                        * ML-KEM identity seed, same shape as
                                        * seed_derivation.c:86-102 */
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LOG_TAG "NODUS_IDENTITY"

#ifdef _WIN32
#include <io.h>
#define F_OK 0
#define access _access
#else
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>            /* D3 (N1 delta 1): O_WRONLY|O_CREAT|O_EXCL for
                                * identity_write_file_atomic() */
#include <errno.h>            /* E2 (N1 delta 2): errno for the dir-fsync
                                * WARN log in identity_write_file_atomic() */

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */
#endif

/* D3 (N1 delta 1) — first-start identity rewrite hardening.
 *
 * Problem this closes: nodus_identity_save() below writes each file with
 * fopen(path, "wb") — open-truncate-then-write. A crash or ENOSPC between
 * the truncate and the last fwrite leaves that file SHORT. For
 * nodus.sk/nodus.pk specifically, nodus_identity_load()'s auto-generate
 * path used to call nodus_identity_save() (rewriting ALL identity files,
 * `nodus.sk` included) whenever ANY one file was found missing — so a
 * crash in that window on a node's FIRST start after upgrading to a
 * ML-KEM-aware binary could truncate `nodus.sk`, and the NEXT start would
 * then fail to read it and silently generate an entirely NEW Dilithium5
 * identity (new node_id) for a currently-registered validator. Faz 1
 * exercises this path on every one of the 7 production nodes on their
 * first start with the new binary.
 *
 * Fix: write to "<path>.tmp" (created with O_EXCL so two writers can
 * never interleave on the same temp name), fwrite + fflush + fsync +
 * fclose, THEN rename() onto the real path. POSIX rename() within one
 * filesystem is atomic: a crash/ENOSPC anywhere in this sequence leaves
 * either the OLD file completely intact (temp file never renamed) or the
 * NEW file complete (temp file renamed only after fsync succeeded) — it
 * can never leave a short file at the REAL path the way fopen("wb") can.
 * Used ONLY for the two ML-KEM files in nodus_identity_load()'s
 * auto-generate path (see there) — nodus_identity_save() itself, and its
 * other callers, are UNCHANGED (out of scope for this fix; see the
 * comment at nodus_identity_save()). No Windows equivalent is
 * implemented (no O_EXCL/fsync parity claim here) — falls back to the
 * pre-existing non-atomic write on that platform rather than invent an
 * uncited MoveFileEx-based scheme.
 *
 * @param path  Final destination path (NOT the temp path)
 * @param bytes Buffer to write
 * @param len   Buffer length
 * @param mode  Permission bits for open()'s O_CREAT (POSIX only) — pass
 *              0600 for secret material so it is never briefly
 *              world-readable, even during the write.
 * @return 0 on success, -1 on any failure (temp file is unlinked on every
 *         failure path that created one; the real path is never touched
 *         on failure).
 */
static int identity_write_file_atomic(const char *path, const uint8_t *bytes,
                                       size_t len, int mode) {
#ifdef _WIN32
    (void)mode;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t written = fwrite(bytes, 1, len, f);
    fclose(f);
    return (written == len) ? 0 : -1;
#else
    char tmp_path[1024];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) return -1;

    /* Clear a leftover .tmp from an EARLIER crashed write before creating
     * a fresh one (advisor review, N1 delta 1 D3 follow-up): nodus does
     * not support concurrent writers to the same identity directory, so
     * O_EXCL here only ever guards against this exact stale-leftover
     * case, never a real race. Without this unlink, a crash between a
     * PRIOR open() and rename() leaves the .tmp behind, and O_EXCL makes
     * every SUBSEQUENT call fail with EEXIST forever — the has_mlkem=true
     * in-memory-only fallback would then fire on every single start,
     * never actually persisting, which is precisely the failure mode D3
     * exists to close. Best-effort: if the leftover cannot be removed
     * (e.g. permissions), open() below still fails safely and this
     * function still returns -1 rather than silently overwriting. */
    unlink(tmp_path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, (mode_t)mode);
    if (fd < 0) return -1;

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    size_t written = fwrite(bytes, 1, len, f);
    if (written != len || fflush(f) != 0) {
        fclose(f);
        unlink(tmp_path);
        return -1;
    }
    if (fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp_path);
        return -1;
    }
    fclose(f);

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    /* E2 (N1 delta 2): make the directory ENTRY durable too, mirroring
     * nodus_witness_cmt_privval.c:695-710 (DEVIATION R3-B-1, the reference-
     * derived atomic-write helper's own extra step beyond plain
     * write+rename) — rename() updates the directory but that update can
     * itself still be sitting in the page cache; fsync-ing the directory
     * fd forces it out. UNLIKE the privval helper (where a directory
     * fsync failure fails the whole write, because that file backs
     * consensus signing state), a failure here is WARN-only and does NOT
     * fail this write: the identity FILE itself is already durable (the
     * fsync on `f` above already forced its data+rename-target inode
     * out), so at worst a crash immediately after this point could still
     * show the OLD directory entry on some filesystems/without a clean
     * unmount — a narrower, lower-stakes window than losing the file
     * content itself, and not worth turning an otherwise-successful
     * identity write into a hard failure over. */
    {
        char dir_path[1024];
        const char *slash = strrchr(path, '/');
        if (slash) {
            size_t dir_len = (size_t)(slash - path);
            if (dir_len == 0) dir_len = 1; /* root-level file: dir is "/" */
            if (dir_len < sizeof(dir_path)) {
                memcpy(dir_path, path, dir_len);
                dir_path[dir_len] = '\0';
            } else {
                dir_path[0] = '\0';
            }
        } else {
            snprintf(dir_path, sizeof(dir_path), ".");
        }

        if (dir_path[0] != '\0') {
            int dfd = open(dir_path, O_RDONLY | O_DIRECTORY);
            if (dfd < 0) {
                QGP_LOG_WARN(LOG_TAG,
                             "atomic write: open dir %s for fsync failed "
                             "(errno=%d) — %s is written and renamed, only "
                             "the directory entry's durability may lag",
                             dir_path, errno, path);
            } else {
                if (fsync(dfd) != 0) {
                    QGP_LOG_WARN(LOG_TAG,
                                 "atomic write: fsync dir %s failed "
                                 "(errno=%d) — %s is written and renamed, "
                                 "only the directory entry's durability "
                                 "may lag",
                                 dir_path, errno, path);
                }
                close(dfd);
            }
        }
    }

    return 0;
#endif
}

int nodus_identity_from_seed(const uint8_t *seed, nodus_identity_t *id_out) {
    if (!seed || !id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    /* Deterministic Dilithium5 keypair from seed — same algorithm as OpenDHT-PQ */
    int rc = qgp_dsa87_keypair_derand(id_out->pk.bytes, id_out->sk.bytes, seed);
    if (rc != 0)
        return -1;

    /* Derive node_id = SHA3-512(public_key) */
    rc = nodus_fingerprint(&id_out->pk, &id_out->node_id);
    if (rc != 0)
        return -1;

    /* Hex fingerprint */
    rc = nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint);
    if (rc != 0)
        return -1;

    /* Derive Kyber1024 keypair from seed via HKDF */
    uint8_t kyber_seed[64];
    static const uint8_t hkdf_salt[] = "nodus-kyber-v1";
    static const uint8_t hkdf_info[] = "kyber-identity";
    rc = hkdf_sha3_256(hkdf_salt, sizeof(hkdf_salt) - 1,
                       seed, NODUS_SEED_BYTES,
                       hkdf_info, sizeof(hkdf_info) - 1,
                       kyber_seed, 32);
    if (rc != 0)
        return -1;

    rc = kyber_r3_keypair_derand(id_out->kyber_pk, id_out->kyber_sk, kyber_seed);
    qgp_secure_memzero(kyber_seed, sizeof(kyber_seed));
    if (rc != 0)
        return -1;

    id_out->has_kyber = true;

    /* Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-mlkem-
     * migration.md, K3 — amended 2026-09-23, N1 delta 1 D10, operator
     * decision): nodus derives its ML-KEM-1024 identity seed with the SAME
     * construction the messenger uses for its own
     * (shared/crypto/key/bip39/seed_derivation.c:86-102 shape) — SHAKE256,
     * NOT HKDF: the tree's hkdf_sha3_256() caps output at 32 bytes
     * (shared/crypto/hash/hkdf_sha3.c:85-89) and this needs 64
     * (qgp_mlkem1024_keypair_derand()'s (d||z) coins, qgp_mlkem.h:35,52). */
    uint8_t coins[QGP_MLKEM1024_COINS_BYTES];
    static const uint8_t mlkem_ctx[] = "nodus-mlkem-1024";
    uint8_t shake_input[NODUS_SEED_BYTES + sizeof(mlkem_ctx) - 1];
    memcpy(shake_input, seed, NODUS_SEED_BYTES);
    memcpy(shake_input + NODUS_SEED_BYTES, mlkem_ctx, sizeof(mlkem_ctx) - 1);
    shake256(coins, sizeof(coins), shake_input, sizeof(shake_input));
    qgp_secure_memzero(shake_input, sizeof(shake_input));

    rc = qgp_mlkem1024_keypair_derand(id_out->mlkem_pk, id_out->mlkem_sk, coins);
    qgp_secure_memzero(coins, sizeof(coins));
    if (rc != 0)
        return -1;

    id_out->has_mlkem = true;
    return 0;
}

int nodus_identity_generate(nodus_identity_t *id_out) {
    if (!id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    /* Random Dilithium5 keypair */
    int rc = qgp_dsa87_keypair(id_out->pk.bytes, id_out->sk.bytes);
    if (rc != 0)
        return -1;

    /* Derive node_id */
    rc = nodus_fingerprint(&id_out->pk, &id_out->node_id);
    if (rc != 0)
        return -1;

    /* Hex fingerprint */
    rc = nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint);
    if (rc != 0)
        return -1;

    /* Random Kyber round-3 keypair (legacy — backward compat) */
    rc = qgp_kem1024_keypair(id_out->kyber_pk, id_out->kyber_sk);
    if (rc != 0)
        return -1;

    id_out->has_kyber = true;

    /* Faz 1 KEM migration: random ML-KEM-1024 keypair (no seed involved —
     * unrelated to the SHAKE256 seed derivation in
     * nodus_identity_from_seed() above, D10). */
    rc = qgp_mlkem1024_keypair(id_out->mlkem_pk, id_out->mlkem_sk);
    if (rc != 0)
        return -1;

    id_out->has_mlkem = true;
    return 0;
}

/* D3 (N1 delta 1): unchanged — still writes every file with fopen(path,
 * "wb") (truncate-then-write, non-atomic). Explicit callers of THIS
 * function (identity generation/rotation flows) are out of scope for the
 * D3 fix; see identity_write_file_atomic() above, which the
 * nodus_identity_load() auto-generate path now uses instead of calling
 * back into this function. */
int nodus_identity_save(const nodus_identity_t *id, const char *path) {
    if (!id || !path)
        return -1;

    char filepath[1024];
    FILE *f;

    /* Write public key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.pk", path);
    f = fopen(filepath, "wb");
    if (!f) return -1;
    if (fwrite(id->pk.bytes, 1, NODUS_PK_BYTES, f) != NODUS_PK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Write secret key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.sk", path);
    f = fopen(filepath, "wb");
    if (!f) return -1;
    if (fwrite(id->sk.bytes, 1, NODUS_SK_BYTES, f) != NODUS_SK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);
#ifndef _WIN32
    chmod(filepath, 0600);  /* M-12: restrict secret key to owner-only */
#endif

    /* Write fingerprint */
    snprintf(filepath, sizeof(filepath), "%s/nodus.fp", path);
    f = fopen(filepath, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", id->fingerprint);
    fclose(f);

    /* Write Kyber keypair (if available) */
    if (id->has_kyber) {
        snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_pk", path);
        f = fopen(filepath, "wb");
        if (!f) return -1;
        if (fwrite(id->kyber_pk, 1, NODUS_KYBER_PK_BYTES, f) != NODUS_KYBER_PK_BYTES) {
            fclose(f);
            return -1;
        }
        fclose(f);

        snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_sk", path);
        f = fopen(filepath, "wb");
        if (!f) return -1;
        if (fwrite(id->kyber_sk, 1, NODUS_KYBER_SK_BYTES, f) != NODUS_KYBER_SK_BYTES) {
            fclose(f);
            return -1;
        }
        fclose(f);
#ifndef _WIN32
        chmod(filepath, 0600);
#endif
    }

    /* Write ML-KEM-1024 keypair (Faz 1 KEM migration, if available) */
    if (id->has_mlkem) {
        snprintf(filepath, sizeof(filepath), "%s/nodus.mlkem_pk", path);
        f = fopen(filepath, "wb");
        if (!f) return -1;
        if (fwrite(id->mlkem_pk, 1, NODUS_MLKEM_PK_BYTES, f) != NODUS_MLKEM_PK_BYTES) {
            fclose(f);
            return -1;
        }
        fclose(f);

        snprintf(filepath, sizeof(filepath), "%s/nodus.mlkem_sk", path);
        f = fopen(filepath, "wb");
        if (!f) return -1;
        if (fwrite(id->mlkem_sk, 1, NODUS_MLKEM_SK_BYTES, f) != NODUS_MLKEM_SK_BYTES) {
            fclose(f);
            return -1;
        }
        fclose(f);
#ifndef _WIN32
        chmod(filepath, 0600);
#endif
    }

    return 0;
}

int nodus_identity_load(const char *path, nodus_identity_t *id_out) {
    if (!path || !id_out)
        return -1;

    memset(id_out, 0, sizeof(*id_out));

    char filepath[1024];
    FILE *f;

    /* Read public key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.pk", path);
    f = fopen(filepath, "rb");
    if (!f) return -1;
    if (fread(id_out->pk.bytes, 1, NODUS_PK_BYTES, f) != NODUS_PK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Read secret key */
    snprintf(filepath, sizeof(filepath), "%s/nodus.sk", path);
    f = fopen(filepath, "rb");
    if (!f) return -1;
    if (fread(id_out->sk.bytes, 1, NODUS_SK_BYTES, f) != NODUS_SK_BYTES) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Derive node_id from public key */
    int rc = nodus_fingerprint(&id_out->pk, &id_out->node_id);
    if (rc != 0)
        return -1;

    rc = nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint);
    if (rc != 0)
        return -1;

    /* Load Kyber keypair, or auto-generate if missing (migration from pre-Kyber identity) */
    snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_pk", path);
    f = fopen(filepath, "rb");
    if (f) {
        if (fread(id_out->kyber_pk, 1, NODUS_KYBER_PK_BYTES, f) == NODUS_KYBER_PK_BYTES) {
            fclose(f);
            snprintf(filepath, sizeof(filepath), "%s/nodus.kyber_sk", path);
            f = fopen(filepath, "rb");
            if (f && fread(id_out->kyber_sk, 1, NODUS_KYBER_SK_BYTES, f) == NODUS_KYBER_SK_BYTES) {
                id_out->has_kyber = true;
            }
            if (f) fclose(f);
        } else {
            fclose(f);
        }
    }

    /* Auto-generate Kyber keypair if not found (first run with new binary) */
    if (!id_out->has_kyber) {
        if (qgp_kem1024_keypair(id_out->kyber_pk, id_out->kyber_sk) == 0) {
            id_out->has_kyber = true;
            /* Save for next startup */
            nodus_identity_save(id_out, path);
        }
    }

    /* Load ML-KEM-1024 keypair (Faz 1 KEM migration), or auto-generate if
     * missing (migration from a pre-Faz-1 identity — same pattern as the
     * Kyber auto-generate above). Random, not seed-derived — this load
     * path never had access to the original BIP39 seed anyway (D10, N1
     * delta 1: nodus_identity_from_seed() above DOES now derive a real
     * ML-KEM key via SHAKE256; that fix does not apply here since there
     * is no seed at hand). */
    snprintf(filepath, sizeof(filepath), "%s/nodus.mlkem_pk", path);
    f = fopen(filepath, "rb");
    if (f) {
        if (fread(id_out->mlkem_pk, 1, NODUS_MLKEM_PK_BYTES, f) == NODUS_MLKEM_PK_BYTES) {
            fclose(f);
            snprintf(filepath, sizeof(filepath), "%s/nodus.mlkem_sk", path);
            f = fopen(filepath, "rb");
            if (f && fread(id_out->mlkem_sk, 1, NODUS_MLKEM_SK_BYTES, f) == NODUS_MLKEM_SK_BYTES) {
                id_out->has_mlkem = true;
            }
            if (f) fclose(f);
        } else {
            fclose(f);
        }
    }

    /* E1 (N1 delta 2): pk/sk file-PAIR consistency. identity_write_file_
     * atomic() renames nodus.mlkem_pk and nodus.mlkem_sk SEPARATELY (two
     * independent open+write+rename sequences) — two crashes on the same
     * node, each between a DIFFERENT one of those two renames, could in
     * principle leave pk1 (from one generation) next to sk2 (from
     * another). The node would then advertise a correctly self-signed
     * mpk (mpk_sig only proves possession of the Dilithium5 IDENTITY
     * key, not of the matching ML-KEM secret) that it cannot actually
     * decapsulate — and an ML-KEM client trusts mpk_sig, so it would
     * never fall back to Kyber round-3; every session with it would
     * fail. FIPS 203 Algorithm 16 lays a decapsulation key out as
     * dk_PKE(1536) || ek(1568) || H(ek)(32) || z(32); this tree already
     * relies on that layout for the §7.3 hash check in
     * shared/crypto/enc/qgp_mlkem.c:28-33 (the MLKEM_DK_HCHECK_OFFSET=
     * 1536 / MLKEM_DK_HASH_OFFSET=3104 constants) and :135-137 (the read
     * of dk+1536 that check hashes). Reuse the SAME 1536 offset directly
     * here — no hashing needed, a loaded pk/sk pair from the SAME
     * keygen call has the pk copy embedded in the sk byte-for-byte. */
    if (id_out->has_mlkem &&
        memcmp(id_out->mlkem_pk, id_out->mlkem_sk + 1536,
               NODUS_MLKEM_PK_BYTES) != 0) {
        char mlkem_pk_load_path[1024], mlkem_sk_load_path[1024];
        snprintf(mlkem_pk_load_path, sizeof(mlkem_pk_load_path), "%s/nodus.mlkem_pk", path);
        snprintf(mlkem_sk_load_path, sizeof(mlkem_sk_load_path), "%s/nodus.mlkem_sk", path);
        QGP_LOG_ERROR(LOG_TAG,
                      "%s and %s do not belong to the same ML-KEM-1024 "
                      "keypair (pk != the ek copy embedded in sk at offset "
                      "1536) — treating the pair as ABSENT and regenerating "
                      "both",
                      mlkem_pk_load_path, mlkem_sk_load_path);
        id_out->has_mlkem = false;
    }

    if (!id_out->has_mlkem) {
        if (qgp_mlkem1024_keypair(id_out->mlkem_pk, id_out->mlkem_sk) == 0) {
            /* has_mlkem = true regardless of whether the save below
             * succeeds (D3, N1 delta 1, (c)): the keypair in id_out is
             * valid either way, so THIS run works correctly. What a save
             * failure means is only that the NEXT start will not find
             * these files and will generate a fresh (different) ML-KEM
             * keypair — logged as an ERROR so an operator watching the
             * log sees the degraded-persistence state, but never a hard
             * failure of nodus_identity_load() itself. */
            id_out->has_mlkem = true;

            /* D3: write ONLY the two ML-KEM files, atomically, via
             * identity_write_file_atomic() above — deliberately NOT
             * nodus_identity_save(), which would rewrite (non-atomically)
             * every identity file including nodus.sk. mlkem_pk is public
             * material but written 0600 too, same as mlkem_sk, for
             * consistency and because identity_write_file_atomic()'s
             * temp-file step is simplest with one mode for both calls. */
            char mlkem_pk_path[1024], mlkem_sk_path[1024];
            snprintf(mlkem_pk_path, sizeof(mlkem_pk_path), "%s/nodus.mlkem_pk", path);
            snprintf(mlkem_sk_path, sizeof(mlkem_sk_path), "%s/nodus.mlkem_sk", path);

            int pk_rc = identity_write_file_atomic(mlkem_pk_path, id_out->mlkem_pk,
                                                     NODUS_MLKEM_PK_BYTES, 0600);
            int sk_rc = identity_write_file_atomic(mlkem_sk_path, id_out->mlkem_sk,
                                                     NODUS_MLKEM_SK_BYTES, 0600);
            if (pk_rc != 0 || sk_rc != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "auto-generated ML-KEM-1024 keypair could not be "
                              "persisted to %s (pk_rc=%d sk_rc=%d) — this run "
                              "uses it in memory, but the NEXT start will "
                              "generate a DIFFERENT ML-KEM keypair unless this "
                              "is fixed (disk full? permissions?)",
                              path, pk_rc, sk_rc);
            }
        }
    }

    return 0;
}

uint64_t nodus_identity_value_id(const nodus_identity_t *id) {
    if (!id)
        return 0;

    /* First 8 bytes of node_id (SHA3-512 of pk), little-endian */
    uint64_t vid = 0;
    for (int i = 7; i >= 0; i--)
        vid = (vid << 8) | id->node_id.bytes[i];

    return vid;
}

/* Faz 1 KEM migration: deliberately UNCHANGED. This export was already
 * Dilithium5 pk+sk only (7488 bytes) — it never carried the Kyber keypair
 * either, so there is no existing precedent to extend and no compat
 * surface to preserve by adding one now. Left as-is per the N1 dispatch. */
int nodus_identity_export(const nodus_identity_t *id, uint8_t **buf, size_t *len) {
    if (!id || !buf || !len) return -1;
    size_t total = NODUS_PK_BYTES + NODUS_SK_BYTES;  /* 7488 */
    uint8_t *out = malloc(total);
    if (!out) return -1;
    memcpy(out, id->pk.bytes, NODUS_PK_BYTES);
    memcpy(out + NODUS_PK_BYTES, id->sk.bytes, NODUS_SK_BYTES);
    *buf = out;
    *len = total;
    return 0;
}

int nodus_identity_import(const uint8_t *buf, size_t len, nodus_identity_t *id_out) {
    if (!buf || !id_out) return -1;
    size_t total = NODUS_PK_BYTES + NODUS_SK_BYTES;  /* 7488 */
    if (len != total) return -1;

    memset(id_out, 0, sizeof(*id_out));
    memcpy(id_out->pk.bytes, buf, NODUS_PK_BYTES);
    memcpy(id_out->sk.bytes, buf + NODUS_PK_BYTES, NODUS_SK_BYTES);

    if (nodus_fingerprint(&id_out->pk, &id_out->node_id) != 0)
        return -1;
    if (nodus_fingerprint_hex(&id_out->pk, id_out->fingerprint) != 0)
        return -1;

    return 0;
}

void nodus_identity_clear(nodus_identity_t *id) {
    if (!id) return;
    /* M-13: Use platform secure memzero instead of hand-rolled volatile loop */
    qgp_secure_memzero(id, sizeof(*id));
}
