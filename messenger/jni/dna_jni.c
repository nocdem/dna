/*
 * DNA Messenger JNI Bridge
 *
 * JNI bindings for Android to access DNA Engine C API.
 * Provides async callbacks via JNI GlobalRef and main thread posting.
 *
 * Java package: io.cpunk.dna
 * Main class: DNAEngine
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <android/log.h>

#include "dna/dna_engine.h"
#include "dht/client/dht_singleton.h"
#include "dht/core/dht_listen.h"
#include "crypto/utils/qgp_platform.h"  /* v0.6.0+: For identity lock check */

#define LOG_TAG "DNA-JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static JavaVM *g_jvm = NULL;
static dna_engine_t *g_engine = NULL;

/* ============================================================================
 * JNI LIFECYCLE
 * ============================================================================ */

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    LOGI("DNA JNI loaded");
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNI_OnUnload(JavaVM *vm, void *reserved) {
    LOGI("DNA JNI unloading");
    if (g_engine) {
        dna_engine_destroy(g_engine);
        g_engine = NULL;
    }
    g_jvm = NULL;
}

/* Get JNIEnv for current thread
 * Returns env and sets *did_attach to true if we attached (caller must detach)
 * IMPORTANT: Caller MUST call release_env() after JNI work is done!
 */
static JNIEnv* get_env(int *did_attach) {
    JNIEnv *env = NULL;
    *did_attach = 0;

    if (g_jvm) {
        int status = (*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
                LOGE("Failed to attach thread");
                return NULL;
            }
            *did_attach = 1;  /* We attached, caller must detach */
            LOGD("Thread attached to JVM");
        }
    }
    return env;
}

/* Release JNIEnv - detaches thread if we attached it */
static void release_env(int did_attach) {
    if (did_attach && g_jvm) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
        LOGD("Thread detached from JVM");
    }
}

/* ============================================================================
 * CALLBACK CONTEXT
 * ============================================================================ */

typedef struct {
    jobject callback_obj;   /* Global ref to Java callback object */
    jlong request_id;
} jni_callback_ctx_t;

static jni_callback_ctx_t* create_callback_ctx(JNIEnv *env, jobject callback) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)malloc(sizeof(jni_callback_ctx_t));
    if (ctx) {
        ctx->callback_obj = (*env)->NewGlobalRef(env, callback);
        ctx->request_id = 0;
    }
    return ctx;
}

static void free_callback_ctx(JNIEnv *env, jni_callback_ctx_t *ctx) {
    if (ctx) {
        if (ctx->callback_obj) {
            (*env)->DeleteGlobalRef(env, ctx->callback_obj);
        }
        free(ctx);
    }
}

/* ============================================================================
 * NATIVE CALLBACKS -> JAVA
 * ============================================================================ */

/* Completion callback (success/error only) */
static void jni_completion_callback(dna_request_id_t request_id, int error, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onCompletion", "(JI)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error);
    }

    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Send tokens callback - includes tx_hash */
static void jni_send_tokens_callback(dna_request_id_t request_id, int error, const char *tx_hash, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onSendTokens", "(JILjava/lang/String;)V");
    if (method) {
        jstring jtx_hash = tx_hash ? (*env)->NewStringUTF(env, tx_hash) : NULL;
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, jtx_hash);
        if (jtx_hash) (*env)->DeleteLocalRef(env, jtx_hash);
    }

    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* v0.3.0: jni_identities_callback removed - single-user model */

/* Identity created callback */
static void jni_identity_created_callback(dna_request_id_t request_id, int error,
                                          const char *fingerprint, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jstring fp_str = fingerprint ? (*env)->NewStringUTF(env, fingerprint) : NULL;

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onIdentityCreated", "(JILjava/lang/String;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, fp_str);
    }

    if (fp_str) (*env)->DeleteLocalRef(env, fp_str);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Display name callback */
static void jni_display_name_callback(dna_request_id_t request_id, int error,
                                      const char *display_name, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jstring name_str = display_name ? (*env)->NewStringUTF(env, display_name) : NULL;

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onDisplayName", "(JILjava/lang/String;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, name_str);
    }

    if (name_str) (*env)->DeleteLocalRef(env, name_str);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Contacts callback */
static void jni_contacts_callback(dna_request_id_t request_id, int error,
                                  dna_contact_t *contacts, int count, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (contacts) dna_free_contacts(contacts, count);
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jobjectArray arr = NULL;
    if (error == 0 && contacts && count > 0) {
        jclass contact_class = (*env)->FindClass(env, "io/cpunk/dna/Contact");
        jmethodID ctor = (*env)->GetMethodID(env, contact_class, "<init>",
            "(Ljava/lang/String;Ljava/lang/String;ZJ)V");
        arr = (*env)->NewObjectArray(env, count, contact_class, NULL);

        for (int i = 0; i < count; i++) {
            jstring fp = (*env)->NewStringUTF(env, contacts[i].fingerprint);
            jstring name = (*env)->NewStringUTF(env, contacts[i].display_name);
            jobject obj = (*env)->NewObject(env, contact_class, ctor,
                fp, name, (jboolean)contacts[i].is_online, (jlong)contacts[i].last_seen);
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, fp);
            (*env)->DeleteLocalRef(env, name);
            (*env)->DeleteLocalRef(env, obj);
        }
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onContacts", "(JI[Lio/cpunk/dna/Contact;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, arr);
    }

    if (contacts) dna_free_contacts(contacts, count);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Messages callback */
static void jni_messages_callback(dna_request_id_t request_id, int error,
                                  dna_message_t *messages, int count, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (messages) dna_free_messages(messages, count);
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jobjectArray arr = NULL;
    if (error == 0 && messages && count > 0) {
        jclass msg_class = (*env)->FindClass(env, "io/cpunk/dna/Message");
        jmethodID ctor = (*env)->GetMethodID(env, msg_class, "<init>",
            "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;JZII)V");
        arr = (*env)->NewObjectArray(env, count, msg_class, NULL);

        for (int i = 0; i < count; i++) {
            jstring sender = (*env)->NewStringUTF(env, messages[i].sender);
            jstring recipient = (*env)->NewStringUTF(env, messages[i].recipient);
            jstring text = messages[i].plaintext ? (*env)->NewStringUTF(env, messages[i].plaintext) : NULL;
            jobject obj = (*env)->NewObject(env, msg_class, ctor,
                (jint)messages[i].id, sender, recipient, text,
                (jlong)messages[i].timestamp, (jboolean)messages[i].is_outgoing,
                (jint)messages[i].status, (jint)messages[i].message_type);
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, sender);
            (*env)->DeleteLocalRef(env, recipient);
            if (text) (*env)->DeleteLocalRef(env, text);
            (*env)->DeleteLocalRef(env, obj);
        }
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onMessages", "(JI[Lio/cpunk/dna/Message;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, arr);
    }

    if (messages) dna_free_messages(messages, count);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Groups callback */
static void jni_groups_callback(dna_request_id_t request_id, int error,
                                dna_group_t *groups, int count, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (groups) dna_free_groups(groups, count);
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jobjectArray arr = NULL;
    if (error == 0 && groups && count > 0) {
        jclass grp_class = (*env)->FindClass(env, "io/cpunk/dna/Group");
        jmethodID ctor = (*env)->GetMethodID(env, grp_class, "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJ)V");
        arr = (*env)->NewObjectArray(env, count, grp_class, NULL);

        for (int i = 0; i < count; i++) {
            jstring uuid = (*env)->NewStringUTF(env, groups[i].uuid);
            jstring name = (*env)->NewStringUTF(env, groups[i].name);
            jstring creator = (*env)->NewStringUTF(env, groups[i].creator);
            jobject obj = (*env)->NewObject(env, grp_class, ctor,
                uuid, name, creator, (jint)groups[i].member_count, (jlong)groups[i].created_at);
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, uuid);
            (*env)->DeleteLocalRef(env, name);
            (*env)->DeleteLocalRef(env, creator);
            (*env)->DeleteLocalRef(env, obj);
        }
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onGroups", "(JI[Lio/cpunk/dna/Group;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, arr);
    }

    if (groups) dna_free_groups(groups, count);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Group created callback */
static void jni_group_created_callback(dna_request_id_t request_id, int error,
                                       const char *group_uuid, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jstring uuid_str = group_uuid ? (*env)->NewStringUTF(env, group_uuid) : NULL;

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onGroupCreated", "(JILjava/lang/String;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, uuid_str);
    }

    if (uuid_str) (*env)->DeleteLocalRef(env, uuid_str);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Invitations callback */
static void jni_invitations_callback(dna_request_id_t request_id, int error,
                                     dna_invitation_t *invitations, int count, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (invitations) dna_free_invitations(invitations, count);
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jobjectArray arr = NULL;
    if (error == 0 && invitations && count > 0) {
        jclass inv_class = (*env)->FindClass(env, "io/cpunk/dna/Invitation");
        jmethodID ctor = (*env)->GetMethodID(env, inv_class, "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IJ)V");
        arr = (*env)->NewObjectArray(env, count, inv_class, NULL);

        for (int i = 0; i < count; i++) {
            jstring uuid = (*env)->NewStringUTF(env, invitations[i].group_uuid);
            jstring name = (*env)->NewStringUTF(env, invitations[i].group_name);
            jstring inviter = (*env)->NewStringUTF(env, invitations[i].inviter);
            jobject obj = (*env)->NewObject(env, inv_class, ctor,
                uuid, name, inviter, (jint)invitations[i].member_count, (jlong)invitations[i].invited_at);
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, uuid);
            (*env)->DeleteLocalRef(env, name);
            (*env)->DeleteLocalRef(env, inviter);
            (*env)->DeleteLocalRef(env, obj);
        }
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onInvitations", "(JI[Lio/cpunk/dna/Invitation;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, arr);
    }

    if (invitations) dna_free_invitations(invitations, count);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Wallets callback */
static void jni_wallets_callback(dna_request_id_t request_id, int error,
                                 dna_wallet_t *wallets, int count, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (wallets) dna_free_wallets(wallets, count);
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jobjectArray arr = NULL;
    if (error == 0 && wallets && count > 0) {
        jclass wallet_class = (*env)->FindClass(env, "io/cpunk/dna/Wallet");
        jmethodID ctor = (*env)->GetMethodID(env, wallet_class, "<init>",
            "(Ljava/lang/String;Ljava/lang/String;IZ)V");
        arr = (*env)->NewObjectArray(env, count, wallet_class, NULL);

        for (int i = 0; i < count; i++) {
            jstring name = (*env)->NewStringUTF(env, wallets[i].name);
            jstring addr = (*env)->NewStringUTF(env, wallets[i].address);
            jobject obj = (*env)->NewObject(env, wallet_class, ctor,
                name, addr, (jint)wallets[i].sig_type, (jboolean)wallets[i].is_protected);
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, name);
            (*env)->DeleteLocalRef(env, addr);
            (*env)->DeleteLocalRef(env, obj);
        }
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onWallets", "(JI[Lio/cpunk/dna/Wallet;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, arr);
    }

    if (wallets) dna_free_wallets(wallets, count);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Balances callback */
static void jni_balances_callback(dna_request_id_t request_id, int error,
                                  dna_balance_t *balances, int count, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (balances) dna_free_balances(balances, count);
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jobjectArray arr = NULL;
    if (error == 0 && balances && count > 0) {
        jclass bal_class = (*env)->FindClass(env, "io/cpunk/dna/Balance");
        jmethodID ctor = (*env)->GetMethodID(env, bal_class, "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        arr = (*env)->NewObjectArray(env, count, bal_class, NULL);

        for (int i = 0; i < count; i++) {
            jstring token = (*env)->NewStringUTF(env, balances[i].token);
            jstring balance = (*env)->NewStringUTF(env, balances[i].balance);
            jstring network = (*env)->NewStringUTF(env, balances[i].network);
            jobject obj = (*env)->NewObject(env, bal_class, ctor, token, balance, network);
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, token);
            (*env)->DeleteLocalRef(env, balance);
            (*env)->DeleteLocalRef(env, network);
            (*env)->DeleteLocalRef(env, obj);
        }
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onBalances", "(JI[Lio/cpunk/dna/Balance;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, arr);
    }

    if (balances) dna_free_balances(balances, count);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* Transactions callback */
static void jni_transactions_callback(dna_request_id_t request_id, int error,
                                      dna_transaction_t *transactions, int count, void *user_data) {
    jni_callback_ctx_t *ctx = (jni_callback_ctx_t*)user_data;
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env || !ctx || !ctx->callback_obj) {
        if (transactions) dna_free_transactions(transactions, count);
        if (ctx) free(ctx);
        release_env(did_attach);
        return;
    }

    jobjectArray arr = NULL;
    if (error == 0 && transactions && count > 0) {
        jclass tx_class = (*env)->FindClass(env, "io/cpunk/dna/Transaction");
        jmethodID ctor = (*env)->GetMethodID(env, tx_class, "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        arr = (*env)->NewObjectArray(env, count, tx_class, NULL);

        for (int i = 0; i < count; i++) {
            jstring hash = (*env)->NewStringUTF(env, transactions[i].tx_hash);
            jstring dir = (*env)->NewStringUTF(env, transactions[i].direction);
            jstring amt = (*env)->NewStringUTF(env, transactions[i].amount);
            jstring tok = (*env)->NewStringUTF(env, transactions[i].token);
            jstring addr = (*env)->NewStringUTF(env, transactions[i].other_address);
            jstring ts = (*env)->NewStringUTF(env, transactions[i].timestamp);
            jstring status = (*env)->NewStringUTF(env, transactions[i].status);
            jobject obj = (*env)->NewObject(env, tx_class, ctor, hash, dir, amt, tok, addr, ts, status);
            (*env)->SetObjectArrayElement(env, arr, i, obj);
            (*env)->DeleteLocalRef(env, hash);
            (*env)->DeleteLocalRef(env, dir);
            (*env)->DeleteLocalRef(env, amt);
            (*env)->DeleteLocalRef(env, tok);
            (*env)->DeleteLocalRef(env, addr);
            (*env)->DeleteLocalRef(env, ts);
            (*env)->DeleteLocalRef(env, status);
            (*env)->DeleteLocalRef(env, obj);
        }
    }

    jclass cls = (*env)->GetObjectClass(env, ctx->callback_obj);
    jmethodID method = (*env)->GetMethodID(env, cls, "onTransactions", "(JI[Lio/cpunk/dna/Transaction;)V");
    if (method) {
        (*env)->CallVoidMethod(env, ctx->callback_obj, method, (jlong)request_id, (jint)error, arr);
    }

    if (transactions) dna_free_transactions(transactions, count);
    free_callback_ctx(env, ctx);
    release_env(did_attach);
}

/* ============================================================================
 * EVENT CALLBACK
 * ============================================================================ */

static jobject g_event_listener = NULL;

static void jni_event_callback(const dna_event_t *event, void *user_data) {
    /* CRITICAL: Check g_jvm first - if NULL, JVM is shutting down */
    if (!g_jvm) return;

    if (!g_event_listener || !event) return;

    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env) return;

    jclass cls = (*env)->GetObjectClass(env, g_event_listener);
    jmethodID method = (*env)->GetMethodID(env, cls, "onEvent", "(ILjava/lang/String;Ljava/lang/String;)V");
    if (!method) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, cls);
        release_env(did_attach);
        return;
    }

    jstring data1 = NULL;
    jstring data2 = NULL;

    switch (event->type) {
        case DNA_EVENT_MESSAGE_RECEIVED:
            data1 = (*env)->NewStringUTF(env, event->data.message_received.message.sender);
            data2 = event->data.message_received.message.plaintext ?
                    (*env)->NewStringUTF(env, event->data.message_received.message.plaintext) : NULL;
            break;
        case DNA_EVENT_CONTACT_ONLINE:
        case DNA_EVENT_CONTACT_OFFLINE:
            data1 = (*env)->NewStringUTF(env, event->data.contact_status.fingerprint);
            break;
        case DNA_EVENT_GROUP_INVITATION_RECEIVED:
            data1 = (*env)->NewStringUTF(env, event->data.group_invitation.invitation.group_uuid);
            data2 = (*env)->NewStringUTF(env, event->data.group_invitation.invitation.group_name);
            break;
        case DNA_EVENT_IDENTITY_LOADED:
            data1 = (*env)->NewStringUTF(env, event->data.identity_loaded.fingerprint);
            break;
        case DNA_EVENT_ERROR:
            data1 = (*env)->NewStringUTF(env, event->data.error.message);
            break;
        default:
            break;
    }

    (*env)->CallVoidMethod(env, g_event_listener, method, (jint)event->type, data1, data2);

    if (data1) (*env)->DeleteLocalRef(env, data1);
    if (data2) (*env)->DeleteLocalRef(env, data2);
    release_env(did_attach);
}

/* ============================================================================
 * ANDROID NOTIFICATION CALLBACK
 * Called when contact's outbox has new messages (for background notifications)
 * ============================================================================ */

static jobject g_notification_helper = NULL;

/**
 * Native callback invoked by dna_engine when DNA_EVENT_OUTBOX_UPDATED fires.
 * Calls the Java NotificationHelper.onOutboxUpdated() method.
 *
 * Note: Message fetching is already handled by dna_engine's auto-fetch in
 * dna_dispatch_event() which spawns background_fetch_thread on OUTBOX_UPDATED.
 */
static void jni_android_notification_callback(const char *contact_fingerprint, const char *display_name, void *user_data) {
    (void)user_data;

    /* CRITICAL: Check g_jvm first - if NULL, JVM is shutting down */
    if (!g_jvm) {
        return;  /* Silent return - JVM shutdown in progress */
    }

    if (!g_notification_helper || !contact_fingerprint) {
        LOGD("Android notification callback: no helper or fingerprint");
        return;
    }

    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env) {
        LOGE("Failed to get JNIEnv for notification callback");
        return;
    }

    LOGI("[NOTIFY] Calling Java notification helper for %.16s... (name=%s)",
         contact_fingerprint, display_name ? display_name : "(null)");

    jclass cls = (*env)->GetObjectClass(env, g_notification_helper);
    if (!cls) {
        LOGE("Failed to get notification helper class");
        release_env(did_attach);
        return;
    }

    jmethodID method = (*env)->GetMethodID(env, cls, "onOutboxUpdated", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (!method) {
        /* IMPORTANT: Clear pending exception from GetMethodID failure */
        (*env)->ExceptionClear(env);
        LOGE("Failed to get onOutboxUpdated method");
        (*env)->DeleteLocalRef(env, cls);
        release_env(did_attach);
        return;
    }

    jstring fp_str = (*env)->NewStringUTF(env, contact_fingerprint);
    jstring name_str = display_name ? (*env)->NewStringUTF(env, display_name) : NULL;

    if (fp_str) {
        (*env)->CallVoidMethod(env, g_notification_helper, method, fp_str, name_str);
        (*env)->DeleteLocalRef(env, fp_str);
    }
    if (name_str) {
        (*env)->DeleteLocalRef(env, name_str);
    }
    (*env)->DeleteLocalRef(env, cls);

    LOGI("[NOTIFY] Java notification helper called successfully");
    release_env(did_attach);
}

/* ============================================================================
 * ANDROID CONTACT REQUEST CALLBACK
 * Called when a new contact request is received via DHT listener
 * ============================================================================ */

/**
 * Native callback invoked by dna_engine when DNA_EVENT_CONTACT_REQUEST_RECEIVED fires.
 * Calls the Java NotificationHelper.onContactRequestReceived() method.
 */
static void jni_contact_request_callback(const char *user_fingerprint, const char *user_display_name, void *user_data) {
    (void)user_data;

    /* CRITICAL: Check g_jvm first - if NULL, JVM is shutting down */
    if (!g_jvm) {
        return;  /* Silent return - JVM shutdown in progress */
    }

    if (!g_notification_helper || !user_fingerprint) {
        LOGD("Contact request callback: no helper or fingerprint");
        return;
    }

    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env) {
        LOGE("Failed to get JNIEnv for contact request callback");
        return;
    }

    LOGI("[CONTACT-REQ] Calling Java helper for %.16s... (name=%s)",
         user_fingerprint, user_display_name ? user_display_name : "(null)");

    jclass cls = (*env)->GetObjectClass(env, g_notification_helper);
    if (!cls) {
        LOGE("Failed to get notification helper class");
        release_env(did_attach);
        return;
    }

    jmethodID method = (*env)->GetMethodID(env, cls, "onContactRequestReceived", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (!method) {
        (*env)->ExceptionClear(env);
        LOGE("Failed to get onContactRequestReceived method");
        (*env)->DeleteLocalRef(env, cls);
        release_env(did_attach);
        return;
    }

    jstring jni_fingerprint = (*env)->NewStringUTF(env, user_fingerprint);
    jstring jni_display_name = user_display_name ? (*env)->NewStringUTF(env, user_display_name) : NULL;

    if (jni_fingerprint) {
        (*env)->CallVoidMethod(env, g_notification_helper, method, jni_fingerprint, jni_display_name);
        (*env)->DeleteLocalRef(env, jni_fingerprint);
    }
    if (jni_display_name) {
        (*env)->DeleteLocalRef(env, jni_display_name);
    }
    (*env)->DeleteLocalRef(env, cls);

    LOGI("[CONTACT-REQ] Java helper called successfully");
    release_env(did_attach);
}

/* ============================================================================
 * ANDROID DHT RECONNECT CALLBACK
 * Called when DHT reconnects after network change (for foreground service)
 * ============================================================================ */

static jobject g_reconnect_helper = NULL;

/**
 * Native callback invoked by dna_engine when DHT reconnects after network change.
 * Calls the Java DnaMessengerService.onDhtReconnected() method.
 *
 * This allows the foreground service to recreate MINIMAL listeners after
 * network changes, instead of having the engine create FULL listeners.
 */
static void jni_reconnect_callback(void *user_data) {
    (void)user_data;

    /* CRITICAL: Check g_jvm first - if NULL, JVM is shutting down */
    if (!g_jvm) {
        return;  /* Silent return - JVM shutdown in progress */
    }

    if (!g_reconnect_helper) {
        LOGD("Reconnect callback: no helper registered");
        return;
    }

    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (!env) {
        LOGE("Failed to get JNIEnv for reconnect callback");
        return;
    }

    LOGI("[RECONNECT] Calling Java DnaMessengerService.onDhtReconnected()");

    jclass cls = (*env)->GetObjectClass(env, g_reconnect_helper);
    if (!cls) {
        LOGE("Failed to get reconnect helper class");
        release_env(did_attach);
        return;
    }

    jmethodID method = (*env)->GetMethodID(env, cls, "onDhtReconnected", "()V");
    if (!method) {
        (*env)->ExceptionClear(env);
        LOGE("Failed to get onDhtReconnected method");
        (*env)->DeleteLocalRef(env, cls);
        release_env(did_attach);
        return;
    }

    (*env)->CallVoidMethod(env, g_reconnect_helper, method);
    (*env)->DeleteLocalRef(env, cls);

    LOGI("[RECONNECT] Java helper called successfully");
    release_env(did_attach);
}

/* ============================================================================
 * JNI NATIVE METHODS
 * ============================================================================ */

/* 1. LIFECYCLE */

JNIEXPORT jboolean JNICALL
Java_io_cpunk_dna_DNAEngine_nativeCreate(JNIEnv *env, jobject thiz, jstring data_dir) {
    /* v0.6.0+: Each component (Flutter/Service) owns its own engine.
     * No global sharing - coordination via identity lock instead. */
    if (g_engine) {
        LOGI("Engine already created (JNI)");
        return JNI_TRUE;
    }

    const char *dir = data_dir ? (*env)->GetStringUTFChars(env, data_dir, NULL) : NULL;
    g_engine = dna_engine_create(dir);
    if (dir) (*env)->ReleaseStringUTFChars(env, data_dir, dir);

    if (!g_engine) {
        LOGE("Failed to create engine");
        return JNI_FALSE;
    }

    /* Set DEBUG log level by default on Android for easier debugging */
    dna_engine_set_log_level("DEBUG");

    LOGI("Engine created successfully (log level: DEBUG)");
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_io_cpunk_dna_DNAEngine_nativeDestroy(JNIEnv *env, jobject thiz) {
    if (g_engine) {
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        LOGI("Engine destroyed");
    }
    if (g_event_listener) {
        (*env)->DeleteGlobalRef(env, g_event_listener);
        g_event_listener = NULL;
    }
    if (g_notification_helper) {
        (*env)->DeleteGlobalRef(env, g_notification_helper);
        g_notification_helper = NULL;
    }
    if (g_reconnect_helper) {
        (*env)->DeleteGlobalRef(env, g_reconnect_helper);
        g_reconnect_helper = NULL;
    }
}

JNIEXPORT void JNICALL
Java_io_cpunk_dna_DNAEngine_nativeSetEventListener(JNIEnv *env, jobject thiz, jobject listener) {
    if (g_event_listener) {
        (*env)->DeleteGlobalRef(env, g_event_listener);
        g_event_listener = NULL;
    }

    if (listener) {
        g_event_listener = (*env)->NewGlobalRef(env, listener);
        dna_engine_set_event_callback(g_engine, jni_event_callback, NULL);
    } else {
        dna_engine_set_event_callback(g_engine, NULL, NULL);
    }
}

/**
 * Set the Android notification helper
 *
 * The helper object must implement onOutboxUpdated(String contactFingerprint).
 * This is called when a contact's outbox has new messages, allowing Android
 * to show native notifications even when Flutter's event callback is detached.
 *
 * This is separate from the event listener and is NOT cleared when Flutter
 * backgrounds - it persists as long as the native library is loaded.
 */
JNIEXPORT void JNICALL
Java_io_cpunk_dna_DNAEngine_nativeSetNotificationHelper(JNIEnv *env, jobject thiz, jobject helper) {
    LOGI("Setting notification helper: %p", helper);

    /* Clear existing helper */
    if (g_notification_helper) {
        (*env)->DeleteGlobalRef(env, g_notification_helper);
        g_notification_helper = NULL;
        dna_engine_set_android_notification_callback(NULL, NULL);
        dna_engine_set_android_contact_request_callback(NULL, NULL);
    }

    /* Set new helper */
    if (helper) {
        g_notification_helper = (*env)->NewGlobalRef(env, helper);
        dna_engine_set_android_notification_callback(jni_android_notification_callback, NULL);
        dna_engine_set_android_contact_request_callback(jni_contact_request_callback, NULL);
        LOGI("Notification helper registered successfully");
    } else {
        LOGI("Notification helper cleared");
    }
}

/**
 * Flutter app version - package io.cpunk.dna_messenger
 * Note: underscore in package name becomes _1 in JNI naming
 */
JNIEXPORT void JNICALL
Java_io_cpunk_dna_1messenger_DnaNotificationHelper_nativeSetNotificationHelper(JNIEnv *env, jobject thiz, jobject helper) {
    LOGI("Flutter: Setting notification helper: %p", helper);

    /* Clear existing helper */
    if (g_notification_helper) {
        (*env)->DeleteGlobalRef(env, g_notification_helper);
        g_notification_helper = NULL;
        dna_engine_set_android_notification_callback(NULL, NULL);
        dna_engine_set_android_contact_request_callback(NULL, NULL);
    }

    /* Set new helper */
    if (helper) {
        g_notification_helper = (*env)->NewGlobalRef(env, helper);
        dna_engine_set_android_notification_callback(jni_android_notification_callback, NULL);
        dna_engine_set_android_contact_request_callback(jni_contact_request_callback, NULL);
        LOGI("Flutter: Notification helper registered successfully");
    } else {
        LOGI("Flutter: Notification helper cleared");
    }
}

JNIEXPORT jstring JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetFingerprint(JNIEnv *env, jobject thiz) {
    if (!g_engine) return NULL;
    const char *fp = dna_engine_get_fingerprint(g_engine);
    return fp ? (*env)->NewStringUTF(env, fp) : NULL;
}

/* 2. IDENTITY */
/* v0.3.0: nativeListIdentities removed - single-user model, use hasIdentity() instead */

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeCreateIdentity(JNIEnv *env, jobject thiz,
                                                  jbyteArray signing_seed,
                                                  jbyteArray encryption_seed,
                                                  jobject callback) {
    if (!g_engine || !callback || !signing_seed || !encryption_seed) return 0;

    jbyte *sign_bytes = (*env)->GetByteArrayElements(env, signing_seed, NULL);
    jbyte *enc_bytes = (*env)->GetByteArrayElements(env, encryption_seed, NULL);

    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    /* Pass NULL for name - can be registered later with nativeRegisterName */
    dna_request_id_t req_id = dna_engine_create_identity(g_engine, NULL,
        (const uint8_t*)sign_bytes, (const uint8_t*)enc_bytes,
        jni_identity_created_callback, ctx);

    (*env)->ReleaseByteArrayElements(env, signing_seed, sign_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, encryption_seed, enc_bytes, JNI_ABORT);

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeLoadIdentity(JNIEnv *env, jobject thiz,
                                                jstring fingerprint, jobject callback) {
    if (!g_engine || !callback || !fingerprint) return 0;

    const char *fp = (*env)->GetStringUTFChars(env, fingerprint, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    /* Pass NULL for password - identity files are not password-protected on Android */
    dna_request_id_t req_id = dna_engine_load_identity(g_engine, fp, NULL, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, fingerprint, fp);

    return (jlong)req_id;
}

/**
 * Check if identity is loaded (v0.5.5+)
 */
JNIEXPORT jboolean JNICALL
Java_io_cpunk_dna_DNAEngine_nativeIsIdentityLoaded(JNIEnv *env, jobject thiz) {
    if (!g_engine) {
        return JNI_FALSE;
    }
    return dna_engine_is_identity_loaded(g_engine) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeRegisterName(JNIEnv *env, jobject thiz,
                                                jstring name, jobject callback) {
    if (!g_engine || !callback || !name) return 0;

    const char *n = (*env)->GetStringUTFChars(env, name, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_register_name(g_engine, n, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, name, n);

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetDisplayName(JNIEnv *env, jobject thiz,
                                                  jstring fingerprint, jobject callback) {
    if (!g_engine || !callback || !fingerprint) return 0;

    const char *fp = (*env)->GetStringUTFChars(env, fingerprint, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_get_display_name(g_engine, fp, jni_display_name_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, fingerprint, fp);

    return (jlong)req_id;
}

/* 3. CONTACTS */

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetContacts(JNIEnv *env, jobject thiz, jobject callback) {
    if (!g_engine || !callback) return 0;
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    return (jlong)dna_engine_get_contacts(g_engine, jni_contacts_callback, ctx);
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeAddContact(JNIEnv *env, jobject thiz,
                                              jstring identifier, jobject callback) {
    if (!g_engine || !callback || !identifier) return 0;

    const char *id = (*env)->GetStringUTFChars(env, identifier, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_add_contact(g_engine, id, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, identifier, id);

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeRemoveContact(JNIEnv *env, jobject thiz,
                                                 jstring fingerprint, jobject callback) {
    if (!g_engine || !callback || !fingerprint) return 0;

    const char *fp = (*env)->GetStringUTFChars(env, fingerprint, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_remove_contact(g_engine, fp, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, fingerprint, fp);

    return (jlong)req_id;
}

/* 4. MESSAGING */

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeSendMessage(JNIEnv *env, jobject thiz,
                                               jstring recipient, jstring message, jobject callback) {
    if (!g_engine || !callback || !recipient || !message) return 0;

    const char *r = (*env)->GetStringUTFChars(env, recipient, NULL);
    const char *m = (*env)->GetStringUTFChars(env, message, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_send_message(g_engine, r, m, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, recipient, r);
    (*env)->ReleaseStringUTFChars(env, message, m);

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetConversation(JNIEnv *env, jobject thiz,
                                                   jstring contact, jobject callback) {
    if (!g_engine || !callback || !contact) return 0;

    const char *c = (*env)->GetStringUTFChars(env, contact, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_get_conversation(g_engine, c, jni_messages_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, contact, c);

    return (jlong)req_id;
}

/* 5. GROUPS */

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetGroups(JNIEnv *env, jobject thiz, jobject callback) {
    if (!g_engine || !callback) return 0;
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    return (jlong)dna_engine_get_groups(g_engine, jni_groups_callback, ctx);
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeCreateGroup(JNIEnv *env, jobject thiz,
                                               jstring name, jobjectArray members, jobject callback) {
    if (!g_engine || !callback || !name) return 0;

    const char *n = (*env)->GetStringUTFChars(env, name, NULL);

    int count = members ? (*env)->GetArrayLength(env, members) : 0;
    const char **fps = NULL;
    if (count > 0) {
        fps = (const char**)malloc(count * sizeof(char*));
        for (int i = 0; i < count; i++) {
            jstring s = (jstring)(*env)->GetObjectArrayElement(env, members, i);
            fps[i] = (*env)->GetStringUTFChars(env, s, NULL);
        }
    }

    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_create_group(g_engine, n, fps, count, jni_group_created_callback, ctx);

    (*env)->ReleaseStringUTFChars(env, name, n);
    if (fps) {
        for (int i = 0; i < count; i++) {
            jstring s = (jstring)(*env)->GetObjectArrayElement(env, members, i);
            (*env)->ReleaseStringUTFChars(env, s, fps[i]);
        }
        free(fps);
    }

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeSendGroupMessage(JNIEnv *env, jobject thiz,
                                                    jstring group_uuid, jstring message, jobject callback) {
    if (!g_engine || !callback || !group_uuid || !message) return 0;

    const char *g = (*env)->GetStringUTFChars(env, group_uuid, NULL);
    const char *m = (*env)->GetStringUTFChars(env, message, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_send_group_message(g_engine, g, m, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, group_uuid, g);
    (*env)->ReleaseStringUTFChars(env, message, m);

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetInvitations(JNIEnv *env, jobject thiz, jobject callback) {
    if (!g_engine || !callback) return 0;
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    return (jlong)dna_engine_get_invitations(g_engine, jni_invitations_callback, ctx);
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeAcceptInvitation(JNIEnv *env, jobject thiz,
                                                    jstring group_uuid, jobject callback) {
    if (!g_engine || !callback || !group_uuid) return 0;

    const char *g = (*env)->GetStringUTFChars(env, group_uuid, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_accept_invitation(g_engine, g, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, group_uuid, g);

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeRejectInvitation(JNIEnv *env, jobject thiz,
                                                    jstring group_uuid, jobject callback) {
    if (!g_engine || !callback || !group_uuid) return 0;

    const char *g = (*env)->GetStringUTFChars(env, group_uuid, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_reject_invitation(g_engine, g, jni_completion_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, group_uuid, g);

    return (jlong)req_id;
}

/* 6. WALLET */

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeListWallets(JNIEnv *env, jobject thiz, jobject callback) {
    if (!g_engine || !callback) return 0;
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    return (jlong)dna_engine_list_wallets(g_engine, jni_wallets_callback, ctx);
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetBalances(JNIEnv *env, jobject thiz,
                                               jint wallet_index, jobject callback) {
    if (!g_engine || !callback) return 0;
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    return (jlong)dna_engine_get_balances(g_engine, wallet_index, jni_balances_callback, ctx);
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeSendTokens(JNIEnv *env, jobject thiz,
                                              jint wallet_index, jstring recipient,
                                              jstring amount, jstring token,
                                              jstring network, jint gas_speed,
                                              jobject callback) {
    if (!g_engine || !callback || !recipient || !amount || !token || !network) return 0;

    const char *r = (*env)->GetStringUTFChars(env, recipient, NULL);
    const char *a = (*env)->GetStringUTFChars(env, amount, NULL);
    const char *t = (*env)->GetStringUTFChars(env, token, NULL);
    const char *n = (*env)->GetStringUTFChars(env, network, NULL);

    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_send_tokens(g_engine, wallet_index, r, a, t, n,
                                                      gas_speed, jni_send_tokens_callback, ctx);

    (*env)->ReleaseStringUTFChars(env, recipient, r);
    (*env)->ReleaseStringUTFChars(env, amount, a);
    (*env)->ReleaseStringUTFChars(env, token, t);
    (*env)->ReleaseStringUTFChars(env, network, n);

    return (jlong)req_id;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeGetTransactions(JNIEnv *env, jobject thiz,
                                                   jint wallet_index, jstring network, jobject callback) {
    if (!g_engine || !callback || !network) return 0;

    const char *n = (*env)->GetStringUTFChars(env, network, NULL);
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    dna_request_id_t req_id = dna_engine_get_transactions(g_engine, wallet_index, n,
                                                           jni_transactions_callback, ctx);
    (*env)->ReleaseStringUTFChars(env, network, n);

    return (jlong)req_id;
}

/* 7. P2P */

JNIEXPORT jboolean JNICALL
Java_io_cpunk_dna_DNAEngine_nativeIsPeerOnline(JNIEnv *env, jobject thiz, jstring fingerprint) {
    if (!g_engine || !fingerprint) return JNI_FALSE;

    const char *fp = (*env)->GetStringUTFChars(env, fingerprint, NULL);
    jboolean result = dna_engine_is_peer_online(g_engine, fp) ? JNI_TRUE : JNI_FALSE;
    (*env)->ReleaseStringUTFChars(env, fingerprint, fp);

    return result;
}

JNIEXPORT jlong JNICALL
Java_io_cpunk_dna_DNAEngine_nativeRefreshPresence(JNIEnv *env, jobject thiz, jobject callback) {
    if (!g_engine || !callback) return 0;
    jni_callback_ctx_t *ctx = create_callback_ctx(env, callback);
    return (jlong)dna_engine_refresh_presence(g_engine, jni_completion_callback, ctx);
}

/* ============================================================================
 * NETWORK CHANGE HANDLING
 * ============================================================================ */

JNIEXPORT jint JNICALL
Java_io_cpunk_dna_DNAEngine_nativeNetworkChanged(JNIEnv *env, jobject thiz) {
    if (!g_engine) {
        LOGE("nativeNetworkChanged: engine not initialized");
        return -1;
    }
    LOGI("Network change detected - reinitializing DHT");
    return dna_engine_network_changed(g_engine);
}

/**
 * Direct DHT reinit for DnaMessengerService (foreground service).
 * Called when network changes while app is backgrounded.
 *
 * If engine is available with identity loaded, uses dna_engine_network_changed()
 * which properly cancels existing listeners before reinit.
 *
 * Otherwise falls back to direct dht_singleton_reinit() (no listeners to cancel).
 *
 * Returns: 0 on success, -1 if DHT not initialized, -2 on reinit failure
 */
JNIEXPORT jint JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeReinitDht(JNIEnv *env, jobject thiz) {
    /* If engine is ready (identity loaded), use the full network_changed path.
     * This properly cancels listeners before reinit and lets the status callback
     * restart them on the new DHT context. */
    if (g_engine && dna_engine_get_fingerprint(g_engine) != NULL) {
        LOGI("nativeReinitDht: Using engine network_changed path");
        return dna_engine_network_changed(g_engine);
    }

    /* Fallback: DHT-only reinit when engine/identity not available */
    if (!dht_singleton_is_initialized()) {
        LOGD("nativeReinitDht: DHT not initialized, skipping");
        return -1;
    }

    LOGI("nativeReinitDht: Network change - reinitializing DHT singleton (no engine)");
    int result = dht_singleton_reinit();
    if (result != 0) {
        LOGE("nativeReinitDht: DHT reinit failed");
        return -2;
    }

    LOGI("nativeReinitDht: DHT reinit successful");
    return 0;
}

/**
 * Check if DHT is healthy (initialized, connected, and has active listeners).
 * Used by foreground service for periodic health checks.
 */
JNIEXPORT jboolean JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeIsDhtHealthy(JNIEnv *env, jobject thiz) {
    if (!dht_singleton_is_initialized()) {
        return JNI_FALSE;
    }
    if (!dht_singleton_is_ready()) {
        return JNI_FALSE;
    }

    /* Also check if we have active listeners - DHT can be "ready" but listeners dead */
    size_t total = 0, active = 0, suspended = 0;
    dht_get_listener_stats(&total, &active, &suspended);
    LOGD("DHT health: ready=true, listeners total=%zu active=%zu suspended=%zu",
         total, active, suspended);

    /* Unhealthy if DHT is ready but we have no active listeners */
    if (active == 0 && total > 0) {
        LOGW("DHT ready but all %zu listeners are inactive/suspended", total);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

/**
 * Ensure engine is initialized (v0.6.0+)
 * Called by DnaMessengerService when it starts fresh after process killed.
 * v0.6.0: No global sharing - Service owns its own engine, coordinated via identity lock.
 */
JNIEXPORT jboolean JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeEnsureEngine(JNIEnv *env, jobject thiz, jstring data_dir) {
    /* Check if engine already exists */
    if (g_engine) {
        LOGI("nativeEnsureEngine: Engine already exists");
        return JNI_TRUE;
    }

    /* Create new engine - Service owns its own, doesn't share with Flutter */
    const char *dir = data_dir ? (*env)->GetStringUTFChars(env, data_dir, NULL) : NULL;
    g_engine = dna_engine_create(dir);
    if (dir) (*env)->ReleaseStringUTFChars(env, data_dir, dir);

    if (!g_engine) {
        LOGE("nativeEnsureEngine: Failed to create engine");
        return JNI_FALSE;
    }

    LOGI("nativeEnsureEngine: Engine created (Service-owned)");
    return JNI_TRUE;
}

/**
 * Check if identity is loaded (v0.5.5+)
 */
JNIEXPORT jboolean JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeIsIdentityLoaded(JNIEnv *env, jobject thiz) {
    if (!g_engine) {
        return JNI_FALSE;
    }
    return dna_engine_is_identity_loaded(g_engine) ? JNI_TRUE : JNI_FALSE;
}

/* Sync callback context for nativeLoadIdentityBackgroundSync */
typedef struct {
    volatile int result;
    volatile bool done;
} sync_load_ctx_t;

static void sync_load_callback(dna_request_id_t id, int error, void *user_data) {
    sync_load_ctx_t *ctx = (sync_load_ctx_t*)user_data;
    if (ctx) {
        ctx->result = error;
        ctx->done = true;
    }
}

/**
 * Load identity with minimal initialization - synchronous version (v0.5.24+)
 * Used by DnaMessengerService when it starts without Flutter.
 * Performs minimal initialization (DHT + listeners only) to save resources.
 * Skips: transport, presence heartbeat, wallet creation, pending message retry.
 * Returns: 0 on success, negative on error
 */
JNIEXPORT jint JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeLoadIdentityMinimalSync(JNIEnv *env, jobject thiz, jstring fingerprint) {
    if (!g_engine || !fingerprint) {
        LOGE("nativeLoadIdentityMinimalSync: engine or fingerprint is NULL");
        return -1;
    }

    const char *fp = (*env)->GetStringUTFChars(env, fingerprint, NULL);
    if (!fp) {
        LOGE("nativeLoadIdentityMinimalSync: failed to get fingerprint string");
        return -2;
    }

    LOGI("nativeLoadIdentityMinimalSync: Loading identity (minimal): %.16s...", fp);

    /* Synchronous wrapper using callback context */
    sync_load_ctx_t ctx = { .result = -100, .done = false };

    dna_request_id_t req_id = dna_engine_load_identity_minimal(
        g_engine, fp, NULL, sync_load_callback, &ctx);

    (*env)->ReleaseStringUTFChars(env, fingerprint, fp);

    if (req_id == 0) {
        LOGE("nativeLoadIdentityMinimalSync: Failed to submit request");
        return -3;
    }

    /* Wait for completion (with timeout) */
    int wait_count = 0;
    while (!ctx.done && wait_count < 300) {  /* 30 second timeout */
        usleep(100000);  /* 100ms */
        wait_count++;
    }

    if (!ctx.done) {
        LOGE("nativeLoadIdentityMinimalSync: Timeout waiting for identity load");
        return -4;
    }

    if (ctx.result == 0) {
        LOGI("nativeLoadIdentityMinimalSync: Identity loaded (minimal mode) - notifications active");
    } else {
        LOGE("nativeLoadIdentityMinimalSync: Identity load failed: %d", ctx.result);
    }

    return ctx.result;
}

/* ============================================================================
 * v0.6.0+: IDENTITY LOCK / SERVICE ENGINE MANAGEMENT
 * ============================================================================ */

/**
 * Check if identity lock is held by another process (v0.6.0+)
 *
 * The identity lock prevents both Flutter and Service from loading identity
 * simultaneously. Service can use this to check if Flutter has the lock.
 *
 * Returns: JNI_TRUE if lock is held (don't try to load), JNI_FALSE if available
 */
JNIEXPORT jboolean JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeIsIdentityLocked(JNIEnv *env, jobject thiz, jstring data_dir) {
    if (!data_dir) {
        LOGE("nativeIsIdentityLocked: data_dir is NULL");
        return JNI_FALSE;
    }

    const char *dir = (*env)->GetStringUTFChars(env, data_dir, NULL);
    if (!dir) {
        return JNI_FALSE;
    }

    int is_locked = qgp_platform_is_identity_locked(dir);
    (*env)->ReleaseStringUTFChars(env, data_dir, dir);

    LOGI("nativeIsIdentityLocked: %s", is_locked ? "YES (Flutter has lock)" : "NO (available)");
    return is_locked ? JNI_TRUE : JNI_FALSE;
}

/**
 * Release service's engine (v0.6.0+)
 *
 * Called when Flutter becomes active and wants to take over.
 * Service should call this to release its engine and identity lock.
 */
JNIEXPORT void JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeReleaseEngine(JNIEnv *env, jobject thiz) {
    if (g_engine) {
        LOGI("nativeReleaseEngine: Releasing service engine for Flutter takeover");
        dna_engine_destroy(g_engine);
        g_engine = NULL;
        LOGI("nativeReleaseEngine: Engine released, identity lock freed");
    } else {
        LOGI("nativeReleaseEngine: No engine to release");
    }
}

/**
 * Start listeners for all contacts (v0.6.3+)
 *
 * Called by DnaMessengerService after identity is loaded.
 * Service needs all listeners active for push notifications when app is killed.
 * Uses parallel subscription internally for faster setup on mobile.
 *
 * @return Number of contacts with listeners started, or 0 on error
 */
JNIEXPORT jint JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeListenAllContacts(JNIEnv *env, jobject thiz) {
    if (!g_engine) {
        LOGW("nativeListenAllContacts: No engine available");
        return 0;
    }

    LOGI("nativeListenAllContacts: Starting MINIMAL listeners (outbox + contact_req + groups)...");
    int count = dna_engine_listen_all_contacts_minimal(g_engine);
    LOGI("nativeListenAllContacts: Started minimal listeners for %d contacts", count);
    return (jint)count;
}

/**
 * Set the DHT reconnect helper (v0.6.8+)
 *
 * The helper object must implement onDhtReconnected().
 * This is called when DHT reconnects after network change, allowing the
 * foreground service to recreate MINIMAL listeners.
 *
 * When this callback is registered, the engine will NOT automatically spawn
 * its listener setup thread on DHT reconnection. The service must call
 * nativeListenAllContacts() in its onDhtReconnected() handler.
 *
 * @param helper The helper object (typically DnaMessengerService), or NULL to disable
 */
JNIEXPORT void JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeSetReconnectHelper(JNIEnv *env, jobject thiz, jobject helper) {
    LOGI("Setting reconnect helper: %p", helper);

    /* Clear existing helper */
    if (g_reconnect_helper) {
        (*env)->DeleteGlobalRef(env, g_reconnect_helper);
        g_reconnect_helper = NULL;
        dna_engine_set_android_reconnect_callback(NULL, NULL);
    }

    /* Set new helper */
    if (helper) {
        g_reconnect_helper = (*env)->NewGlobalRef(env, helper);
        dna_engine_set_android_reconnect_callback(jni_reconnect_callback, NULL);
        LOGI("Reconnect helper registered - service will handle DHT reconnection");
    } else {
        LOGI("Reconnect helper cleared - engine will handle DHT reconnection");
    }
}

/**
 * Check all contacts' outboxes for offline messages (v0.100.20+)
 *
 * Synchronous polling function for battery-optimized background service.
 * Replaces continuous DHT listeners with periodic polling every 5 minutes.
 *
 * @return Number of new messages fetched, or negative on error
 */
JNIEXPORT jint JNICALL
Java_io_cpunk_dna_1messenger_DnaMessengerService_nativeCheckOfflineMessages(JNIEnv *env, jobject thiz) {
    if (!g_engine) {
        LOGE("nativeCheckOfflineMessages: No engine available");
        return -1;
    }

    if (!dna_engine_is_identity_loaded(g_engine)) {
        LOGE("nativeCheckOfflineMessages: Identity not loaded");
        return -2;
    }

    LOGI("nativeCheckOfflineMessages: Checking all contacts' outboxes...");

    /* Synchronous wrapper using callback context */
    sync_load_ctx_t ctx = { .result = -100, .done = false };

    dna_request_id_t req_id = dna_engine_check_offline_messages(
        g_engine, sync_load_callback, &ctx);

    if (req_id == 0) {
        LOGE("nativeCheckOfflineMessages: Failed to submit request");
        return -3;
    }

    /* Wait for completion (with timeout) */
    int wait_count = 0;
    while (!ctx.done && wait_count < 300) {  /* 30 second timeout */
        usleep(100000);  /* 100ms */
        wait_count++;
    }

    if (!ctx.done) {
        LOGE("nativeCheckOfflineMessages: Timeout waiting for check");
        return -4;
    }

    if (ctx.result == 0) {
        LOGI("nativeCheckOfflineMessages: Check completed successfully");
    } else {
        LOGE("nativeCheckOfflineMessages: Check failed: %d", ctx.result);
    }

    return ctx.result;
}
