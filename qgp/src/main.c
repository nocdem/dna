/**
 * qgp - Quantum Good Privacy, phase 1: signing.
 *
 *   qgp keygen <out>                         ML-DSA-87 key: <out> (secret, 0600, O_EXCL)
 *                                            and <out>.pub (public, 0644, O_EXCL)
 *   qgp sign <file> <sk> [--out <sig>]       detached signature (default <file>.qgpsig)
 *   qgp verify <file> <sig> <pk>
 *   qgp deb-sign <deb> <sk>                  append the `_qgp.sig` member (in place,
 *                                            atomically); <sk>.pub must be next to <sk>
 *   qgp deb-verify <deb> --trust <dir> [--allow-downgrade]
 *   qgp trust-make <body> <sk> --serial <n> --out <file> [--prev <trust-file>]
 *   qgp trust-accept <trust-file>... --trust <dir> [--bootstrap]
 *
 * stdout carries command results only; diagnostics go through QGP_LOG_* (stderr).
 * Exit status: 0 success, 1 refused / failed, 2 usage error. Every failure is a
 * refusal: nothing is accepted, written or recorded on any error path.
 */
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qgp_core.h"
#include "qgp_deb.h"
#include "qgp_filesig.h"
#include "qgp_io.h"
#include "qgp_state.h"
#include "qgp_trust.h"

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_safe_string.h"

#define LOG_TAG "QGP"

#define EXIT_REFUSED 1
#define EXIT_USAGE   2

/* Command results on stdout (the only stdout writer in the program). */
static void out_result(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out_result(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
}

static int usage(void)
{
    QGP_LOG_ERROR(LOG_TAG,
        "usage: qgp keygen <out> | sign <file> <sk> [--out <sig>] | verify <file> <sig> <pk> | "
        "deb-sign <deb> <sk> | deb-verify <deb> --trust <dir> [--allow-downgrade] | "
        "trust-make <body> <sk> --serial <n> --out <file> [--prev <trust-file>] | "
        "trust-accept <trust-file>... --trust <dir> [--bootstrap]");
    return EXIT_USAGE;
}

static int refuse(const char *what, qgp_rc_t rc)
{
    QGP_LOG_ERROR(LOG_TAG, "%s: REFUSED (%s)", what, qgp_rc_str(rc));
    return EXIT_REFUSED;
}

/* Strict unsigned decimal, no sign, no spaces, fits uint64. */
static int parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s)
        return -1;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            return -1;
        uint64_t d = (uint64_t)(*p - '0');
        if (v > (UINT64_MAX - d) / 10u)
            return -1;
        v = v * 10u + d;
    }
    *out = v;
    return 0;
}

/* Secret key + its public key `<sk>.pub`. */
static qgp_rc_t load_keypair(const char *sk_path, uint8_t sk[QGP_SK_LEN], uint8_t pk[QGP_PK_LEN])
{
    char pub[PATH_MAX];
    qgp_rc_t rc = qgp_key_pub_path(sk_path, pub, sizeof(pub));
    if (rc != QGP_OK)
        return rc;
    rc = qgp_key_load_sk(sk_path, sk);
    if (rc != QGP_OK)
        return rc;
    rc = qgp_key_load_pk(pub, pk);
    if (rc != QGP_OK)
        qgp_secure_memzero(sk, QGP_SK_LEN);
    return rc;
}

static int cmd_keygen(int argc, char **argv)
{
    if (argc != 1)
        return usage();
    uint8_t key_id[QGP_HASH_LEN];
    qgp_rc_t rc = qgp_key_generate(argv[0], key_id);
    if (rc != QGP_OK)
        return refuse("keygen", rc);

    uint8_t pk[QGP_PK_LEN];
    char pub[PATH_MAX];
    if (qgp_key_pub_path(argv[0], pub, sizeof(pub)) != QGP_OK || qgp_key_load_pk(pub, pk) != QGP_OK)
        return refuse("keygen: re-read public key", QGP_E_IO);
    char fp_hex[2 * QGP_HASH_LEN + 1];
    char *pk_hex = malloc(2 * QGP_PK_LEN + 1);
    if (!pk_hex)
        return refuse("keygen", QGP_E_NOMEM);
    qgp_hex_encode(key_id, QGP_HASH_LEN, fp_hex);
    qgp_hex_encode(pk, QGP_PK_LEN, pk_hex);
    out_result("key_id %s", fp_hex);
    out_result("key %s %s", fp_hex, pk_hex);   /* the trust-body record (R2-1) */
    free(pk_hex);
    return 0;
}

static int cmd_sign(int argc, char **argv)
{
    const char *out_path = NULL;
    const char *pos[2];
    int npos = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_path = argv[++i];
        else if (npos < 2)
            pos[npos++] = argv[i];
        else
            return usage();
    }
    if (npos != 2)
        return usage();
    char def_out[PATH_MAX];
    if (!out_path) {
        int n = snprintf(def_out, sizeof(def_out), "%s.qgpsig", pos[0]);
        if (n < 0 || (size_t)n >= sizeof(def_out))
            return refuse("sign", QGP_E_ARG);
        out_path = def_out;
    }

    uint8_t sk[QGP_SK_LEN], pk[QGP_PK_LEN], sig[QGP_SIG_LEN];
    qgp_rc_t rc = load_keypair(pos[1], sk, pk);
    if (rc != QGP_OK)
        return refuse("sign: key", rc);
    uint8_t *data = NULL;
    size_t len = 0;
    rc = qgp_io_read_file(pos[0], QGP_FILE_MAX, &data, &len);
    if (rc == QGP_OK)
        rc = qgp_filesig_sign_v1_UNAPPROVED(data, len, sk, pk, sig);
    qgp_secure_memzero(sk, sizeof(sk));
    free(data);
    if (rc == QGP_OK)
        rc = qgp_io_write_atomic(out_path, sig, sizeof(sig), 0644);
    if (rc != QGP_OK)
        return refuse("sign", rc);
    out_result("signed %s -> %s", pos[0], out_path);
    return 0;
}

static int cmd_verify(int argc, char **argv)
{
    if (argc != 3)
        return usage();
    uint8_t pk[QGP_PK_LEN];
    qgp_rc_t rc = qgp_key_load_pk(argv[2], pk);
    if (rc != QGP_OK)
        return refuse("verify: public key", rc);
    uint8_t *sig = NULL, *data = NULL;
    size_t sig_len = 0, len = 0;
    rc = qgp_io_read_file(argv[1], QGP_SIG_LEN, &sig, &sig_len);
    if (rc == QGP_E_TOO_LARGE)
        rc = QGP_E_SIG_LEN;
    if (rc == QGP_OK)
        rc = qgp_io_read_file(argv[0], QGP_FILE_MAX, &data, &len);
    if (rc == QGP_OK)
        rc = qgp_filesig_verify_v1_UNAPPROVED(data, len, sig, sig_len, pk);
    free(sig);
    free(data);
    if (rc != QGP_OK)
        return refuse("verify", rc);
    out_result("OK %s", argv[0]);
    return 0;
}

static int cmd_deb_sign(int argc, char **argv)
{
    if (argc != 2)
        return usage();
    uint8_t sk[QGP_SK_LEN], pk[QGP_PK_LEN];
    qgp_rc_t rc = load_keypair(argv[1], sk, pk);
    if (rc != QGP_OK)
        return refuse("deb-sign: key", rc);
    uint8_t *deb = NULL, *signed_deb = NULL;
    size_t len = 0, signed_len = 0;
    rc = qgp_io_read_file(argv[0], QGP_FILE_MAX, &deb, &len);
    if (rc == QGP_OK)
        rc = qgp_deb_sign(deb, len, sk, pk, &signed_deb, &signed_len);
    qgp_secure_memzero(sk, sizeof(sk));
    free(deb);
    if (rc == QGP_OK)
        rc = qgp_io_write_atomic(argv[0], signed_deb, signed_len, 0644);
    free(signed_deb);
    if (rc != QGP_OK)
        return refuse("deb-sign", rc);
    uint8_t key_id[QGP_HASH_LEN];
    char hex[2 * QGP_HASH_LEN + 1];
    if (qgp_sha3_512(pk, QGP_PK_LEN, key_id) != 0)
        return refuse("deb-sign", QGP_E_CRYPTO);
    qgp_hex_encode(key_id, QGP_HASH_LEN, hex);
    out_result("signed %s prefix_len=%zu key_id=%s", argv[0], len, hex);
    return 0;
}

static int cmd_deb_verify(int argc, char **argv)
{
    const char *deb_path = NULL, *dir = NULL;
    int allow_downgrade = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--trust") == 0 && i + 1 < argc)
            dir = argv[++i];
        else if (strcmp(argv[i], "--allow-downgrade") == 0)
            allow_downgrade = 1;
        else if (!deb_path)
            deb_path = argv[i];
        else
            return usage();
    }
    if (!deb_path || !dir)
        return usage();

    int lock = -1;
    qgp_rc_t rc = qgp_state_lock(dir, &lock);
    if (rc != QGP_OK)
        return refuse("deb-verify: lock trust state", rc);

    qgp_trust_stored_t stored;
    qgp_accepted_list_t acc;
    qgp_control_fields_t fields;
    qgp_deb_sig_info_t info;
    uint8_t *deb = NULL;
    size_t len = 0;
    int record = 0;
    memset(&acc, 0, sizeof(acc));

    rc = qgp_state_load_trust(dir, &stored);
    if (rc != QGP_OK) {
        qgp_state_unlock(lock);
        return refuse("deb-verify: trust state", rc);
    }
    rc = qgp_io_read_file(deb_path, QGP_FILE_MAX, &deb, &len);
    /* §1: structure, prefix, M_pkg, pinned unrevoked key, signature ... */
    if (rc == QGP_OK)
        rc = qgp_deb_verify(deb, len, &stored.parsed.state, &info);
    /* ... THEN the control fields, from the same verified bytes ... */
    if (rc == QGP_OK)
        rc = qgp_deb_read_control_fields(deb, len, &fields);
    /* ... then the trust floor and the local highest-accepted version (R2-5). */
    if (rc == QGP_OK)
        rc = qgp_state_load_accepted(dir, &acc);
    if (rc == QGP_OK)
        rc = qgp_policy_check(&stored.parsed.state, &acc, fields.pkg, fields.ver,
                              allow_downgrade, &record);
    if (rc == QGP_OK && record) {
        rc = qgp_accepted_set(&acc, fields.pkg, fields.ver);
        if (rc == QGP_OK)
            rc = qgp_state_store_accepted(dir, &acc);
    }
    free(deb);
    qgp_accepted_free(&acc);
    qgp_trust_stored_free(&stored);
    qgp_state_unlock(lock);
    if (rc != QGP_OK)
        return refuse(deb_path, rc);

    char hex[2 * QGP_HASH_LEN + 1];
    qgp_hex_encode(info.key_id, QGP_HASH_LEN, hex);
    out_result("OK %s %s %s key_id=%s", fields.pkg, fields.ver, fields.arch, hex);
    return 0;
}

static int cmd_trust_make(int argc, char **argv)
{
    const char *out_path = NULL, *prev_path = NULL, *serial_s = NULL;
    const char *pos[2];
    int npos = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_path = argv[++i];
        else if (strcmp(argv[i], "--prev") == 0 && i + 1 < argc)
            prev_path = argv[++i];
        else if (strcmp(argv[i], "--serial") == 0 && i + 1 < argc)
            serial_s = argv[++i];
        else if (npos < 2)
            pos[npos++] = argv[i];
        else
            return usage();
    }
    uint64_t serial = 0;
    if (npos != 2 || !out_path || !serial_s || parse_u64(serial_s, &serial) != 0)
        return usage();

    qgp_trust_stored_t prev;
    int have_prev = 0;
    uint8_t *body = NULL, *file = NULL;
    size_t body_len = 0, file_len = 0;
    uint8_t sk[QGP_SK_LEN], pk[QGP_PK_LEN];

    qgp_rc_t rc = qgp_io_read_file(pos[0], QGP_BODY_MAX, &body, &body_len);
    if (rc == QGP_E_TOO_LARGE)
        rc = QGP_E_BODY_TOO_LARGE;
    if (rc == QGP_OK && prev_path) {
        uint8_t *pf = NULL;
        size_t pf_len = 0;
        rc = qgp_io_read_file(prev_path, QGP_TRUST_FILE_MAX, &pf, &pf_len);
        if (rc == QGP_E_TOO_LARGE)
            rc = QGP_E_FILE_LENGTH;
        if (rc == QGP_OK) {
            rc = qgp_trust_stored_load(pf, pf_len, &prev);
            have_prev = (rc == QGP_OK);
        }
        free(pf);
    }
    if (rc == QGP_OK)
        rc = load_keypair(pos[1], sk, pk);
    if (rc == QGP_OK) {
        rc = qgp_trust_make(body, body_len, serial, have_prev ? &prev : NULL, sk, pk,
                            &file, &file_len);
        qgp_secure_memzero(sk, sizeof(sk));
    }
    if (rc == QGP_OK)
        rc = qgp_io_create_excl(out_path, file, file_len, 0644);
    free(body);
    free(file);
    if (have_prev)
        qgp_trust_stored_free(&prev);
    if (rc != QGP_OK)
        return refuse("trust-make", rc);
    out_result("wrote %s serial=%llu%s", out_path, (unsigned long long)serial,
               have_prev ? "" : " (bootstrap: prev_digest = zeros)");
    return 0;
}

static int cmd_trust_accept(int argc, char **argv)
{
    const char *dir = NULL;
    int bootstrap = 0;
    const char **files = calloc((size_t)(argc > 0 ? argc : 1), sizeof(*files));
    int nfiles = 0;
    if (!files)
        return refuse("trust-accept", QGP_E_NOMEM);
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--trust") == 0 && i + 1 < argc)
            dir = argv[++i];
        else if (strcmp(argv[i], "--bootstrap") == 0)
            bootstrap = 1;
        else
            files[nfiles++] = argv[i];
    }
    if (!dir || nfiles == 0) {
        free(files);
        return usage();
    }

    int lock = -1;
    qgp_rc_t rc = qgp_state_lock(dir, &lock);
    if (rc != QGP_OK) {
        free(files);
        return refuse("trust-accept: lock trust state", rc);
    }
    qgp_trust_stored_t stored;
    int have_stored = 0;
    rc = qgp_state_load_trust(dir, &stored);
    if (rc == QGP_OK) {
        have_stored = 1;
        if (bootstrap) {
            QGP_LOG_ERROR(LOG_TAG, "--bootstrap given but %s/%s already exists", dir,
                          QGP_STATE_TRUST_FILE);
            rc = QGP_E_STATE_EXISTS;
        }
    } else if (rc == QGP_E_NO_TRUST_STATE && bootstrap) {
        QGP_LOG_WARN(LOG_TAG, "BOOTSTRAP: pinning %s; it must have been checked by hand", files[0]);
        rc = QGP_OK;
    }

    /* Files in serial order; each one is stored before the next is checked
     * against it (R2-3: every intermediate file, in order). */
    int accepted = 0;
    for (int i = 0; i < nfiles && rc == QGP_OK; i++) {
        uint8_t *f = NULL;
        size_t f_len = 0;
        qgp_trust_file_t tf;
        rc = qgp_io_read_file(files[i], QGP_TRUST_FILE_MAX, &f, &f_len);
        if (rc == QGP_E_TOO_LARGE)
            rc = QGP_E_FILE_LENGTH;
        if (rc == QGP_OK)
            rc = qgp_trust_verify(f, f_len, have_stored ? &stored : NULL, &tf);
        if (rc == QGP_OK) {
            uint64_t serial = tf.serial;
            char hex[2 * QGP_HASH_LEN + 1];
            qgp_hex_encode(tf.signer, QGP_HASH_LEN, hex);
            qgp_trust_file_free(&tf);
            rc = qgp_state_store_trust(dir, f, f_len);
            if (rc == QGP_OK) {
                if (have_stored)
                    qgp_trust_stored_free(&stored);
                have_stored = 0;
                rc = qgp_trust_stored_load(f, f_len, &stored);
                have_stored = (rc == QGP_OK);
            }
            if (rc == QGP_OK) {
                out_result("ACCEPTED %s serial=%llu signer=%s", files[i],
                           (unsigned long long)serial, hex);
                accepted++;
            }
        }
        if (rc != QGP_OK)
            QGP_LOG_ERROR(LOG_TAG, "%s: REFUSED (%s)", files[i], qgp_rc_str(rc));
        free(f);
    }
    if (have_stored)
        qgp_trust_stored_free(&stored);
    qgp_state_unlock(lock);
    free(files);
    if (rc != QGP_OK) {
        QGP_LOG_ERROR(LOG_TAG, "trust-accept: %d of %d file(s) accepted before the refusal",
                      accepted, nfiles);
        return EXIT_REFUSED;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return usage();
    const char *cmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;
    if (strcmp(cmd, "keygen") == 0)       return cmd_keygen(sub_argc, sub_argv);
    if (strcmp(cmd, "sign") == 0)         return cmd_sign(sub_argc, sub_argv);
    if (strcmp(cmd, "verify") == 0)       return cmd_verify(sub_argc, sub_argv);
    if (strcmp(cmd, "deb-sign") == 0)     return cmd_deb_sign(sub_argc, sub_argv);
    if (strcmp(cmd, "deb-verify") == 0)   return cmd_deb_verify(sub_argc, sub_argv);
    if (strcmp(cmd, "trust-make") == 0)   return cmd_trust_make(sub_argc, sub_argv);
    if (strcmp(cmd, "trust-accept") == 0) return cmd_trust_accept(sub_argc, sub_argv);
    return usage();
}
