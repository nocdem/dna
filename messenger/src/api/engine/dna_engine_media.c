/*
 * DNA Engine - Media Module
 *
 * Async media upload/download/exists operations via Nodus DHT.
 *
 * Contains handlers and public API:
 *   - dna_handle_media_upload()
 *   - dna_handle_media_download()
 *   - dna_handle_media_exists()
 *   - dna_engine_media_upload()
 *   - dna_engine_media_download()
 *   - dna_engine_media_exists()
 *
 * STATUS: v0.9.146+ - Media storage via Nodus DHT
 */

#define DNA_ENGINE_MEDIA_IMPL

#include "engine_includes.h"
#include "dht/shared/nodus_ops.h"

/* Override LOG_TAG for this module (engine_includes.h defines DNA_ENGINE) */
#undef LOG_TAG
#define LOG_TAG "ENG_MEDIA"

/* ============================================================================
 * TASK HANDLERS
 * ============================================================================ */

void dna_handle_media_upload(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    uint8_t *data            = task->params.media_upload.data;
    size_t   data_len        = task->params.media_upload.data_len;
    uint8_t  media_type      = task->params.media_upload.media_type;
    bool     encrypted       = task->params.media_upload.encrypted;
    uint32_t ttl             = task->params.media_upload.ttl;

    if (!data || data_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Media upload: no data provided");
        task->callback.media_upload(task->request_id, DNA_ERROR_INVALID_ARG,
                                    NULL, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Media upload: %zu bytes, type=%u, encrypted=%d, ttl=%u",
                 data_len, media_type, encrypted, ttl);

    int ret = nodus_ops_media_put(task->params.media_upload.content_hash,
                                  data, data_len,
                                  media_type, encrypted, ttl);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Media upload failed: %d", ret);
        task->callback.media_upload(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Media upload complete: %zu bytes", data_len);
    task->callback.media_upload(task->request_id, DNA_OK,
                                task->params.media_upload.content_hash,
                                task->user_data);
}

void dna_handle_media_download(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    uint8_t *data = NULL;
    size_t data_len = 0;

    QGP_LOG_INFO(LOG_TAG, "Media download: fetching from DHT");

    int ret = nodus_ops_media_get(task->params.media_download.content_hash,
                                  &data, &data_len);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Media download failed: %d", ret);
        task->callback.media_download(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Media download complete: %zu bytes", data_len);
    task->callback.media_download(task->request_id, DNA_OK,
                                  data, data_len, task->user_data);
    free(data);
}

void dna_handle_media_exists(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    bool exists = false;

    int ret = nodus_ops_media_exists(task->params.media_exists.content_hash, &exists);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Media exists check failed: %d", ret);
        task->callback.media_exists(task->request_id, DNA_ERROR_INTERNAL,
                                    false, task->user_data);
        return;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Media exists: %s", exists ? "yes" : "no");
    task->callback.media_exists(task->request_id, DNA_OK,
                                exists, task->user_data);
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_media_upload(
    dna_engine_t *engine,
    const uint8_t *data, size_t data_len,
    const uint8_t content_hash[64],
    uint8_t media_type, bool encrypted, uint32_t ttl,
    dna_media_upload_cb callback, void *user_data)
{
    if (!engine || !data || data_len == 0 || !content_hash || !callback) return 0;

    dna_task_params_t params = {0};
    params.media_upload.data = malloc(data_len);
    if (!params.media_upload.data) return 0;
    memcpy(params.media_upload.data, data, data_len);
    params.media_upload.data_len = data_len;
    memcpy(params.media_upload.content_hash, content_hash, 64);
    params.media_upload.media_type = media_type;
    params.media_upload.encrypted = encrypted;
    params.media_upload.ttl = ttl;

    dna_task_callback_t cb = { .media_upload = callback };
    return dna_submit_task(engine, TASK_MEDIA_UPLOAD, &params, cb, user_data);
}

dna_request_id_t dna_engine_media_download(
    dna_engine_t *engine,
    const uint8_t content_hash[64],
    dna_media_download_cb callback, void *user_data)
{
    if (!engine || !content_hash || !callback) return 0;

    dna_task_params_t params = {0};
    memcpy(params.media_download.content_hash, content_hash, 64);

    dna_task_callback_t cb = { .media_download = callback };
    return dna_submit_task(engine, TASK_MEDIA_DOWNLOAD, &params, cb, user_data);
}

dna_request_id_t dna_engine_media_exists(
    dna_engine_t *engine,
    const uint8_t content_hash[64],
    dna_media_exists_cb callback, void *user_data)
{
    if (!engine || !content_hash || !callback) return 0;

    dna_task_params_t params = {0};
    memcpy(params.media_exists.content_hash, content_hash, 64);

    dna_task_callback_t cb = { .media_exists = callback };
    return dna_submit_task(engine, TASK_MEDIA_EXISTS, &params, cb, user_data);
}
