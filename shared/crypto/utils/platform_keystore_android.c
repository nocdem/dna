// shared/crypto/utils/platform_keystore_android.c
/**
 * Platform keystore — Android backend via JNI to DnaKeyStore.kt
 *
 * Uses Android Keystore API (TEE-backed) for AES-256-GCM key wrapping.
 * Thread-safe: caches JavaVM, attaches/detaches per call from C threads.
 */

#ifdef __ANDROID__

#include "crypto/utils/platform_keystore.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/key/seed_storage.h"

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>

#define LOG_TAG "KEYSTORE_ANDROID"

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static JavaVM *g_jvm = NULL;
static jclass g_keystore_class = NULL;
static pthread_mutex_t g_migration_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ============================================================================
 * JNI HELPERS
 * ============================================================================ */

void platform_keystore_jni_init(JavaVM *jvm) {
    g_jvm = jvm;
    QGP_LOG_INFO(LOG_TAG, "JNI initialized for platform keystore");
}

/**
 * Get JNIEnv for current thread, attaching if necessary.
 * Sets *need_detach = 1 if caller must detach after use.
 */
static JNIEnv *get_env(int *need_detach) {
    JNIEnv *env = NULL;
    *need_detach = 0;

    if (!g_jvm) return NULL;

    jint rc = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to attach thread to JVM");
            return NULL;
        }
        *need_detach = 1;
    } else if (rc != JNI_OK) {
        QGP_LOG_ERROR(LOG_TAG, "GetEnv failed: %d", rc);
        return NULL;
    }

    return env;
}

static void release_env(int need_detach) {
    if (need_detach && g_jvm) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
}

/**
 * Ensure DnaKeyStore class is loaded (lazy, cached as GlobalRef).
 */
static bool ensure_class(JNIEnv *env) {
    if (g_keystore_class) return true;

    jclass cls = (*env)->FindClass(env, "io/cpunk/dna_connect/DnaKeyStore");
    if (!cls) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
        QGP_LOG_ERROR(LOG_TAG, "FindClass failed for DnaKeyStore");
        return false;
    }

    g_keystore_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    return g_keystore_class != NULL;
}

/**
 * Check for and clear Java exceptions. Returns true if exception occurred.
 */
static bool check_exception(JNIEnv *env, const char *context) {
    if ((*env)->ExceptionCheck(env)) {
        QGP_LOG_ERROR(LOG_TAG, "Java exception in %s", context);
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return true;
    }
    return false;
}

/**
 * Build AAD bytes for GCM (6-byte DNAT header).
 */
static void build_aad(uint8_t aad[PLATFORM_KEYSTORE_HEADER_SIZE]) {
    memcpy(aad, PLATFORM_KEYSTORE_MAGIC, PLATFORM_KEYSTORE_MAGIC_SIZE);
    aad[4] = PLATFORM_KEYSTORE_VERSION;
    aad[5] = PLATFORM_KEYSTORE_KEY_VER;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

bool platform_keystore_available(void) {
    if (!g_jvm) return false;

    int need_detach = 0;
    JNIEnv *env = get_env(&need_detach);
    if (!env) return false;

    bool result = false;

    if (!ensure_class(env)) goto done;

    jmethodID mid = (*env)->GetStaticMethodID(env, g_keystore_class, "isAvailable", "()Z");
    if (!mid || check_exception(env, "GetStaticMethodID(isAvailable)")) goto done;

    result = (*env)->CallStaticBooleanMethod(env, g_keystore_class, mid);
    if (check_exception(env, "isAvailable()")) result = false;

done:
    release_env(need_detach);
    return result;
}

int platform_keystore_wrap(
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;

    if (!data || !out || !out_len || data_len == 0) return -1;
    if (data_len > PLATFORM_KEYSTORE_MAX_FILE) return -1;

    int need_detach = 0;
    JNIEnv *env = get_env(&need_detach);
    if (!env) return -1;

    int result = -1;
    jbyteArray jdata = NULL;
    jbyteArray jaad = NULL;
    jbyteArray jresult = NULL;

    if (!ensure_class(env)) goto done;

    jmethodID mid = (*env)->GetStaticMethodID(env, g_keystore_class, "encrypt", "([B[B)[B");
    if (!mid || check_exception(env, "GetStaticMethodID(encrypt)")) goto done;

    jdata = (*env)->NewByteArray(env, (jsize)data_len);
    if (!jdata || check_exception(env, "NewByteArray(data)")) goto done;
    (*env)->SetByteArrayRegion(env, jdata, 0, (jsize)data_len, (const jbyte *)data);

    uint8_t aad[PLATFORM_KEYSTORE_HEADER_SIZE];
    build_aad(aad);
    jaad = (*env)->NewByteArray(env, PLATFORM_KEYSTORE_HEADER_SIZE);
    if (!jaad || check_exception(env, "NewByteArray(aad)")) goto done;
    (*env)->SetByteArrayRegion(env, jaad, 0, PLATFORM_KEYSTORE_HEADER_SIZE, (const jbyte *)aad);

    jresult = (*env)->CallStaticObjectMethod(env, g_keystore_class, mid, jdata, jaad);
    if (check_exception(env, "encrypt()") || !jresult) goto done;

    jsize result_len = (*env)->GetArrayLength(env, jresult);
    *out = malloc((size_t)result_len);
    if (!*out) goto done;
    (*env)->GetByteArrayRegion(env, jresult, 0, result_len, (jbyte *)*out);
    *out_len = (size_t)result_len;
    result = 0;

done:
    if (jdata) (*env)->DeleteLocalRef(env, jdata);
    if (jaad) (*env)->DeleteLocalRef(env, jaad);
    if (jresult) (*env)->DeleteLocalRef(env, jresult);
    release_env(need_detach);
    return result;
}

int platform_keystore_unwrap(
    const uint8_t *data, size_t data_len,
    uint8_t **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;

    if (!data || !out || !out_len || data_len == 0) return -1;

    int need_detach = 0;
    JNIEnv *env = get_env(&need_detach);
    if (!env) return -1;

    int result = -1;
    jbyteArray jdata = NULL;
    jbyteArray jaad = NULL;
    jbyteArray jresult = NULL;

    if (!ensure_class(env)) goto done;

    jmethodID mid = (*env)->GetStaticMethodID(env, g_keystore_class, "decrypt", "([B[B)[B");
    if (!mid || check_exception(env, "GetStaticMethodID(decrypt)")) goto done;

    jdata = (*env)->NewByteArray(env, (jsize)data_len);
    if (!jdata || check_exception(env, "NewByteArray(data)")) goto done;
    (*env)->SetByteArrayRegion(env, jdata, 0, (jsize)data_len, (const jbyte *)data);

    uint8_t aad[PLATFORM_KEYSTORE_HEADER_SIZE];
    build_aad(aad);
    jaad = (*env)->NewByteArray(env, PLATFORM_KEYSTORE_HEADER_SIZE);
    if (!jaad || check_exception(env, "NewByteArray(aad)")) goto done;
    (*env)->SetByteArrayRegion(env, jaad, 0, PLATFORM_KEYSTORE_HEADER_SIZE, (const jbyte *)aad);

    jresult = (*env)->CallStaticObjectMethod(env, g_keystore_class, mid, jdata, jaad);
    if (check_exception(env, "decrypt()") || !jresult) goto done;

    jsize result_len = (*env)->GetArrayLength(env, jresult);
    *out = malloc((size_t)result_len);
    if (!*out) goto done;
    (*env)->GetByteArrayRegion(env, jresult, 0, result_len, (jbyte *)*out);
    *out_len = (size_t)result_len;
    result = 0;

done:
    if (jdata) (*env)->DeleteLocalRef(env, jdata);
    if (jaad) (*env)->DeleteLocalRef(env, jaad);
    if (jresult) (*env)->DeleteLocalRef(env, jresult);
    release_env(need_detach);
    return result;
}

bool platform_keystore_is_wrapped(const char *file_path) {
    if (!file_path) return false;

    FILE *fp = fopen(file_path, "rb");
    if (!fp) return false;

    char magic[PLATFORM_KEYSTORE_MAGIC_SIZE];
    size_t n = fread(magic, 1, PLATFORM_KEYSTORE_MAGIC_SIZE, fp);
    fclose(fp);

    return (n == PLATFORM_KEYSTORE_MAGIC_SIZE &&
            memcmp(magic, PLATFORM_KEYSTORE_MAGIC, PLATFORM_KEYSTORE_MAGIC_SIZE) == 0);
}

int platform_keystore_migrate_file(const char *file_path, const char *data_dir) {
    if (!file_path || !data_dir) return PLATFORM_KEYSTORE_ERROR;

    /* Check if already wrapped */
    if (platform_keystore_is_wrapped(file_path))
        return PLATFORM_KEYSTORE_ALREADY_WRAPPED;

    /* Check TEE availability */
    if (!platform_keystore_available())
        return PLATFORM_KEYSTORE_UNAVAILABLE;

    /* Check mnemonic backup exists — don't migrate if user has no recovery path */
    if (!mnemonic_storage_exists(data_dir)) {
        QGP_LOG_WARN(LOG_TAG, "Skipping TEE migration: no mnemonic backup");
        return PLATFORM_KEYSTORE_NO_MNEMONIC;
    }

    pthread_mutex_lock(&g_migration_mutex);

    int result = PLATFORM_KEYSTORE_ERROR;
    uint8_t *old_data = NULL;
    size_t file_size = 0;
    uint8_t *wrapped = NULL;
    size_t wrapped_len = 0;
    char tmp_path[1024];
    char bak_path[1024];

    /* Re-check after acquiring mutex */
    if (platform_keystore_is_wrapped(file_path)) {
        result = PLATFORM_KEYSTORE_ALREADY_WRAPPED;
        goto unlock;
    }

    /* Read existing file */
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot open file for migration: %s", file_path);
        goto unlock;
    }

    fseek(fp, 0, SEEK_END);
    long fs = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fs <= 0 || fs > PLATFORM_KEYSTORE_MAX_FILE) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid file size for migration: %ld", fs);
        fclose(fp);
        goto unlock;
    }
    file_size = (size_t)fs;

    old_data = malloc(file_size);
    if (!old_data) { fclose(fp); goto unlock; }

    if (fread(old_data, 1, file_size, fp) != file_size) {
        fclose(fp);
        goto unlock;
    }
    fclose(fp);

    /* TEE wrap */
    if (platform_keystore_wrap(old_data, file_size, &wrapped, &wrapped_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "TEE wrap failed during migration");
        goto unlock;
    }

    /* Create backup of original file before any modification */
    int ret = snprintf(bak_path, sizeof(bak_path), "%s.bak", file_path);
    if (ret < 0 || (size_t)ret >= sizeof(bak_path)) {
        QGP_LOG_ERROR(LOG_TAG, "bak path too long");
        goto unlock;
    }
    {
        FILE *src = fopen(file_path, "rb");
        FILE *dst = fopen(bak_path, "wb");
        if (src && dst) {
            uint8_t copy_buf[4096];
            size_t n;
            while ((n = fread(copy_buf, 1, sizeof(copy_buf), src)) > 0) {
                fwrite(copy_buf, 1, n, dst);
            }
            fflush(dst);
            fsync(fileno(dst));
            chmod(bak_path, S_IRUSR | S_IWUSR);
        }
        if (src) fclose(src);
        if (dst) fclose(dst);

        if (!qgp_platform_file_exists(bak_path)) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create backup: %s", bak_path);
            goto unlock;
        }
        QGP_LOG_INFO(LOG_TAG, "Backup created: %s", bak_path);
    }

    /* Write DNAT file to .tmp: header + wrapped */
    ret = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);
    if (ret < 0 || (size_t)ret >= sizeof(tmp_path)) {
        QGP_LOG_ERROR(LOG_TAG, "tmp path too long");
        goto unlock;
    }

    FILE *tmp_fp = fopen(tmp_path, "wb");
    if (!tmp_fp) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot create temp file: %s", tmp_path);
        goto unlock;
    }

    uint8_t header[PLATFORM_KEYSTORE_HEADER_SIZE];
    memcpy(header, PLATFORM_KEYSTORE_MAGIC, PLATFORM_KEYSTORE_MAGIC_SIZE);
    header[4] = PLATFORM_KEYSTORE_VERSION;
    header[5] = PLATFORM_KEYSTORE_KEY_VER;

    size_t expected = PLATFORM_KEYSTORE_HEADER_SIZE + wrapped_len;
    size_t written = 0;
    written += fwrite(header, 1, PLATFORM_KEYSTORE_HEADER_SIZE, tmp_fp);
    written += fwrite(wrapped, 1, wrapped_len, tmp_fp);

    if (written != expected) {
        QGP_LOG_ERROR(LOG_TAG, "Partial write during migration: %zu/%zu", written, expected);
        fclose(tmp_fp);
        unlink(tmp_path);
        goto unlock;
    }

    if (fflush(tmp_fp) != 0 || fsync(fileno(tmp_fp)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "fflush/fsync failed during migration");
        fclose(tmp_fp);
        unlink(tmp_path);
        goto unlock;
    }

    if (fclose(tmp_fp) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "fclose failed during migration");
        unlink(tmp_path);
        goto unlock;
    }

    /* Atomic rename — .bak remains as safety net */
    if (rename(tmp_path, file_path) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "rename failed during migration: %s", file_path);
        unlink(tmp_path);
        goto unlock;
    }

    chmod(file_path, S_IRUSR | S_IWUSR);

    /* NOTE: .bak intentionally NOT deleted during testing phase */
    QGP_LOG_INFO(LOG_TAG, "Migrated to TEE-wrapped format: %s (backup: %s)", file_path, bak_path);
    result = PLATFORM_KEYSTORE_OK;

unlock:
    if (old_data) {
        qgp_secure_memzero(old_data, file_size);
        free(old_data);
    }
    if (wrapped) {
        qgp_secure_memzero(wrapped, wrapped_len);
        free(wrapped);
    }
    pthread_mutex_unlock(&g_migration_mutex);
    return result;
}

#endif /* __ANDROID__ */
