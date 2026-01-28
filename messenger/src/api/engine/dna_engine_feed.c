/*
 * DNA Engine - Feed Module
 *
 * Contains DNA Board/Feed handlers and public API:
 *   - dna_handle_get_feed_channels()
 *   - dna_handle_create_feed_channel()
 *   - dna_handle_init_default_channels()
 *   - dna_handle_get_feed_posts()
 *   - dna_handle_create_feed_post()
 *   - dna_handle_add_feed_comment()
 *   - dna_handle_get_feed_comments()
 *   - dna_handle_cast_feed_vote()
 *   - dna_handle_get_feed_votes()
 *   - dna_handle_cast_comment_vote()
 *   - dna_handle_get_comment_votes()
 *   - dna_engine_get_feed_channels()
 *   - dna_engine_create_feed_channel()
 *   - dna_engine_init_default_channels()
 *   - dna_engine_get_feed_posts()
 *   - dna_engine_create_feed_post()
 *   - dna_engine_add_feed_comment()
 *   - dna_engine_get_feed_comments()
 *   - dna_engine_cast_feed_vote()
 *   - dna_engine_get_feed_votes()
 *   - dna_engine_cast_comment_vote()
 *   - dna_engine_get_comment_votes()
 *
 * STATUS: EXTRACTED - Functions moved from dna_engine.c
 */

#define DNA_ENGINE_FEED_IMPL

#include "engine_includes.h"

/* ============================================================================
 * FEED INTERNAL HANDLERS
 * ============================================================================ */

void dna_handle_get_feed_channels(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_channels(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_registry_t *registry = NULL;
    int ret = dna_feed_registry_get(dht, &registry);

    if (ret == 0 && registry && registry->channel_count > 0) {
        /* Convert to engine format */
        dna_channel_info_t *channels = calloc(registry->channel_count, sizeof(dna_channel_info_t));
        if (channels) {
            for (size_t i = 0; i < registry->channel_count; i++) {
                strncpy(channels[i].channel_id, registry->channels[i].channel_id, 64);
                strncpy(channels[i].name, registry->channels[i].name, 63);
                strncpy(channels[i].description, registry->channels[i].description, 511);
                strncpy(channels[i].creator_fingerprint, registry->channels[i].creator_fingerprint, 128);
                channels[i].created_at = registry->channels[i].created_at;
                channels[i].subscriber_count = registry->channels[i].subscriber_count;
                channels[i].last_activity = registry->channels[i].last_activity;

                /* Count posts from last 7 days - v0.6.47: Use thread-safe gmtime */
                int post_count = 0;
                time_t now = time(NULL);
                for (int day = 0; day < 7; day++) {
                    time_t t = now - (day * 86400);
                    struct tm tm_buf;
                    struct tm *tm = safe_gmtime(&t, &tm_buf);
                    char date[12];
                    if (tm) {
                        snprintf(date, sizeof(date), "%04d%02d%02d",
                                 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
                    } else {
                        strncpy(date, "00000000", sizeof(date));
                    }

                    dna_feed_post_t *posts = NULL;
                    size_t count = 0;
                    if (dna_feed_posts_get_by_channel(dht, channels[i].channel_id, date, &posts, &count) == 0) {
                        post_count += (int)count;
                        free(posts);
                    }
                }
                channels[i].post_count = post_count;
            }
            task->callback.feed_channels(task->request_id, DNA_OK,
                                         channels, (int)registry->channel_count, task->user_data);
        } else {
            task->callback.feed_channels(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
        }
        dna_feed_registry_free(registry);
    } else if (ret == -2) {
        /* No registry - return empty */
        task->callback.feed_channels(task->request_id, DNA_OK, NULL, 0, task->user_data);
    } else {
        task->callback.feed_channels(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, 0, task->user_data);
        if (registry) dna_feed_registry_free(registry);
    }
}

void dna_handle_create_feed_channel(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_channel(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_channel_t *new_channel = NULL;
    int ret = dna_feed_channel_create(dht,
                                       task->params.create_feed_channel.name,
                                       task->params.create_feed_channel.description,
                                       engine->fingerprint,
                                       key->private_key,
                                       &new_channel);
    qgp_key_free(key);

    if (ret == 0 && new_channel) {
        dna_channel_info_t *channel = calloc(1, sizeof(dna_channel_info_t));
        if (channel) {
            strncpy(channel->channel_id, new_channel->channel_id, 64);
            strncpy(channel->name, new_channel->name, 63);
            strncpy(channel->description, new_channel->description, 511);
            strncpy(channel->creator_fingerprint, new_channel->creator_fingerprint, 128);
            channel->created_at = new_channel->created_at;
            channel->subscriber_count = 1;
            channel->last_activity = new_channel->created_at;
        }
        dna_feed_channel_free(new_channel);
        task->callback.feed_channel(task->request_id, DNA_OK, channel, task->user_data);
    } else if (ret == -2) {
        task->callback.feed_channel(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS,
                                    NULL, task->user_data);
    } else {
        task->callback.feed_channel(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
    }
}

void dna_handle_init_default_channels(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int created = dna_feed_init_default_channels(dht, engine->fingerprint, key->private_key);
    qgp_key_free(key);

    task->callback.completion(task->request_id, created >= 0 ? DNA_OK : DNA_ERROR_INTERNAL,
                              task->user_data);
}

void dna_handle_get_feed_posts(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_posts(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  NULL, 0, task->user_data);
        return;
    }

    const char *date = task->params.get_feed_posts.date[0] ? task->params.get_feed_posts.date : NULL;

    dna_feed_post_t *posts = NULL;
    size_t count = 0;
    int ret = dna_feed_posts_get_by_channel(dht, task->params.get_feed_posts.channel_id,
                                            date, &posts, &count);

    if (ret == 0 && posts && count > 0) {
        /* Convert to engine format */
        dna_post_info_t *out_posts = calloc(count, sizeof(dna_post_info_t));
        if (out_posts) {
            for (size_t i = 0; i < count; i++) {
                strncpy(out_posts[i].post_id, posts[i].post_id, 199);
                strncpy(out_posts[i].channel_id, posts[i].channel_id, 64);
                strncpy(out_posts[i].author_fingerprint, posts[i].author_fingerprint, 128);
                out_posts[i].text = strdup(posts[i].text);
                if (!out_posts[i].text) {
                    /* strdup failed - free already allocated and return error */
                    for (size_t j = 0; j < i; j++) {
                        free(out_posts[j].text);
                    }
                    free(out_posts);
                    free(posts);
                    task->callback.feed_posts(task->request_id, DNA_ERROR_INTERNAL,
                                              NULL, 0, task->user_data);
                    return;
                }
                out_posts[i].timestamp = posts[i].timestamp;
                out_posts[i].updated = posts[i].updated;

                /* Fetch actual comment count from DHT */
                dna_feed_comment_t *comments = NULL;
                size_t comment_count = 0;
                if (dna_feed_comments_get(dht, posts[i].post_id, &comments, &comment_count) == 0) {
                    out_posts[i].comment_count = (int)comment_count;
                    dna_feed_comments_free(comments, comment_count);
                } else {
                    out_posts[i].comment_count = 0;
                }

                out_posts[i].upvotes = posts[i].upvotes;
                out_posts[i].downvotes = posts[i].downvotes;
                out_posts[i].user_vote = posts[i].user_vote;
                out_posts[i].verified = (posts[i].signature_len > 0);
            }
            task->callback.feed_posts(task->request_id, DNA_OK,
                                      out_posts, (int)count, task->user_data);
        } else {
            task->callback.feed_posts(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
        }
        free(posts);
    } else if (ret == -2) {
        /* No posts - return empty */
        task->callback.feed_posts(task->request_id, DNA_OK, NULL, 0, task->user_data);
    } else {
        task->callback.feed_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        if (posts) free(posts);
    }
}

void dna_handle_create_feed_post(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_post(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                 NULL, task->user_data);
        return;
    }

    dna_feed_post_t *new_post = NULL;
    int ret = dna_feed_post_create(dht,
                                    task->params.create_feed_post.channel_id,
                                    engine->fingerprint,
                                    task->params.create_feed_post.text,
                                    key->private_key,
                                    &new_post);
    qgp_key_free(key);

    if (ret == 0 && new_post) {
        dna_post_info_t *post = calloc(1, sizeof(dna_post_info_t));
        if (post) {
            strncpy(post->post_id, new_post->post_id, 199);
            strncpy(post->channel_id, new_post->channel_id, 64);
            strncpy(post->author_fingerprint, new_post->author_fingerprint, 128);
            post->text = strdup(new_post->text);
            if (!post->text) {
                free(post);
                post = NULL;
            } else {
                post->timestamp = new_post->timestamp;
                post->updated = new_post->updated;
                post->comment_count = new_post->comment_count;
                post->upvotes = 0;
                post->downvotes = 0;
                post->user_vote = 0;
                post->verified = true;
            }
        }
        dna_feed_post_free(new_post);
        if (post) {
            task->callback.feed_post(task->request_id, DNA_OK, post, task->user_data);
        } else {
            task->callback.feed_post(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
        }
    } else {
        task->callback.feed_post(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, task->user_data);
    }
}

void dna_handle_add_feed_comment(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_comment(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_comment_t *new_comment = NULL;
    int ret = dna_feed_comment_add(dht,
                                    task->params.add_feed_comment.post_id,
                                    engine->fingerprint,
                                    task->params.add_feed_comment.text,
                                    key->private_key,
                                    &new_comment);
    qgp_key_free(key);

    if (ret == 0 && new_comment) {
        dna_comment_info_t *comment = calloc(1, sizeof(dna_comment_info_t));
        if (comment) {
            strncpy(comment->comment_id, new_comment->comment_id, 199);
            strncpy(comment->post_id, new_comment->post_id, 199);
            strncpy(comment->author_fingerprint, new_comment->author_fingerprint, 128);
            comment->text = strdup(new_comment->text);
            if (!comment->text) {
                free(comment);
                comment = NULL;
            } else {
                comment->timestamp = new_comment->timestamp;
                comment->upvotes = 0;
                comment->downvotes = 0;
                comment->user_vote = 0;
                comment->verified = true;
            }
        }
        dna_feed_comment_free(new_comment);
        if (comment) {
            task->callback.feed_comment(task->request_id, DNA_OK, comment, task->user_data);
        } else {
            task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
        }
    } else {
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
    }
}

void dna_handle_get_feed_comments(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comments(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_feed_comments_get(dht, task->params.get_feed_comments.post_id,
                                     &comments, &count);

    if (ret == 0 && comments && count > 0) {
        dna_comment_info_t *out_comments = calloc(count, sizeof(dna_comment_info_t));
        if (out_comments) {
            for (size_t i = 0; i < count; i++) {
                strncpy(out_comments[i].comment_id, comments[i].comment_id, 199);
                strncpy(out_comments[i].post_id, comments[i].post_id, 199);
                strncpy(out_comments[i].author_fingerprint, comments[i].author_fingerprint, 128);
                out_comments[i].text = strdup(comments[i].text);
                if (!out_comments[i].text) {
                    /* strdup failed - free already allocated and return error */
                    for (size_t j = 0; j < i; j++) {
                        free(out_comments[j].text);
                    }
                    free(out_comments);
                    dna_feed_comments_free(comments, count);
                    task->callback.feed_comments(task->request_id, DNA_ERROR_INTERNAL,
                                                 NULL, 0, task->user_data);
                    return;
                }
                out_comments[i].timestamp = comments[i].timestamp;
                out_comments[i].upvotes = comments[i].upvotes;
                out_comments[i].downvotes = comments[i].downvotes;
                out_comments[i].user_vote = comments[i].user_vote;
                out_comments[i].verified = (comments[i].signature_len > 0);
            }
            task->callback.feed_comments(task->request_id, DNA_OK,
                                         out_comments, (int)count, task->user_data);
        } else {
            task->callback.feed_comments(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
        }
        dna_feed_comments_free(comments, count);
    } else {
        task->callback.feed_comments(task->request_id, DNA_OK, NULL, 0, task->user_data);
        if (comments) dna_feed_comments_free(comments, count);
    }
}

void dna_handle_cast_feed_vote(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int ret = dna_feed_vote_cast(dht,
                                  task->params.cast_feed_vote.post_id,
                                  engine->fingerprint,
                                  task->params.cast_feed_vote.vote_value,
                                  key->private_key);
    qgp_key_free(key);

    if (ret == 0) {
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
    } else if (ret == -2) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS, task->user_data);
    } else {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
    }
}

void dna_handle_get_feed_votes(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_post(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                 NULL, task->user_data);
        return;
    }

    dna_feed_votes_t *votes = NULL;
    int ret = dna_feed_votes_get(dht, task->params.get_feed_votes.post_id, &votes);

    dna_post_info_t *post = calloc(1, sizeof(dna_post_info_t));
    if (post) {
        strncpy(post->post_id, task->params.get_feed_votes.post_id, 199);
        if (ret == 0 && votes) {
            post->upvotes = votes->upvote_count;
            post->downvotes = votes->downvote_count;
            post->user_vote = engine->identity_loaded ?
                              dna_feed_get_user_vote(votes, engine->fingerprint) : 0;
            dna_feed_votes_free(votes);
        }
        task->callback.feed_post(task->request_id, DNA_OK, post, task->user_data);
    } else {
        if (votes) dna_feed_votes_free(votes);
        task->callback.feed_post(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
    }
}

void dna_handle_cast_comment_vote(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    int ret = dna_feed_comment_vote_cast(dht,
                                          task->params.cast_comment_vote.comment_id,
                                          engine->fingerprint,
                                          task->params.cast_comment_vote.vote_value,
                                          key->private_key);
    qgp_key_free(key);

    if (ret == 0) {
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
    } else if (ret == -2) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_ALREADY_EXISTS, task->user_data);
    } else {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
    }
}

void dna_handle_get_comment_votes(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comment(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                    NULL, task->user_data);
        return;
    }

    dna_feed_votes_t *votes = NULL;
    int ret = dna_feed_comment_votes_get(dht, task->params.get_comment_votes.comment_id, &votes);

    dna_comment_info_t *comment = calloc(1, sizeof(dna_comment_info_t));
    if (comment) {
        strncpy(comment->comment_id, task->params.get_comment_votes.comment_id, 199);
        if (ret == 0 && votes) {
            comment->upvotes = votes->upvote_count;
            comment->downvotes = votes->downvote_count;
            comment->user_vote = engine->identity_loaded ?
                                 dna_feed_get_user_vote(votes, engine->fingerprint) : 0;
            dna_feed_votes_free(votes);
        }
        task->callback.feed_comment(task->request_id, DNA_OK, comment, task->user_data);
    } else {
        if (votes) dna_feed_votes_free(votes);
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL, NULL, task->user_data);
    }
}

/* ============================================================================
 * FEED PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_get_feed_channels(
    dna_engine_t *engine,
    dna_feed_channels_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_channels = callback;
    return dna_submit_task(engine, TASK_GET_FEED_CHANNELS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_create_feed_channel(
    dna_engine_t *engine,
    const char *name,
    const char *description,
    dna_feed_channel_cb callback,
    void *user_data
) {
    if (!engine || !name || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_feed_channel.name, name, 63);
    if (description) {
        strncpy(params.create_feed_channel.description, description, 511);
    }

    dna_task_callback_t cb = {0};
    cb.feed_channel = callback;
    return dna_submit_task(engine, TASK_CREATE_FEED_CHANNEL, &params, cb, user_data);
}

dna_request_id_t dna_engine_init_default_channels(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_INIT_DEFAULT_CHANNELS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_posts(
    dna_engine_t *engine,
    const char *channel_id,
    const char *date,
    dna_feed_posts_cb callback,
    void *user_data
) {
    if (!engine || !channel_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_posts.channel_id, channel_id, 64);
    if (date) {
        strncpy(params.get_feed_posts.date, date, 11);
    }

    dna_task_callback_t cb = {0};
    cb.feed_posts = callback;
    return dna_submit_task(engine, TASK_GET_FEED_POSTS, &params, cb, user_data);
}

dna_request_id_t dna_engine_create_feed_post(
    dna_engine_t *engine,
    const char *channel_id,
    const char *text,
    dna_feed_post_cb callback,
    void *user_data
) {
    if (!engine || !channel_id || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.create_feed_post.channel_id, channel_id, 64);
    params.create_feed_post.text = strdup(text);
    if (!params.create_feed_post.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_post = callback;
    return dna_submit_task(engine, TASK_CREATE_FEED_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_add_feed_comment(
    dna_engine_t *engine,
    const char *post_id,
    const char *text,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.add_feed_comment.post_id, post_id, 199);
    params.add_feed_comment.text = strdup(text);
    if (!params.add_feed_comment.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.feed_comment = callback;
    return dna_submit_task(engine, TASK_ADD_FEED_COMMENT, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_comments(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_comments_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_comments.post_id, post_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_comments = callback;
    return dna_submit_task(engine, TASK_GET_FEED_COMMENTS, &params, cb, user_data);
}

dna_request_id_t dna_engine_cast_feed_vote(
    dna_engine_t *engine,
    const char *post_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;
    if (vote_value != 1 && vote_value != -1) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.cast_feed_vote.post_id, post_id, 199);
    params.cast_feed_vote.vote_value = vote_value;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CAST_FEED_VOTE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_feed_votes(
    dna_engine_t *engine,
    const char *post_id,
    dna_feed_post_cb callback,
    void *user_data
) {
    if (!engine || !post_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_feed_votes.post_id, post_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_post = callback;
    return dna_submit_task(engine, TASK_GET_FEED_VOTES, &params, cb, user_data);
}

dna_request_id_t dna_engine_cast_comment_vote(
    dna_engine_t *engine,
    const char *comment_id,
    int8_t vote_value,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !comment_id || !callback) return DNA_REQUEST_ID_INVALID;
    if (vote_value != 1 && vote_value != -1) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.cast_comment_vote.comment_id, comment_id, 199);
    params.cast_comment_vote.vote_value = vote_value;

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CAST_COMMENT_VOTE, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_comment_votes(
    dna_engine_t *engine,
    const char *comment_id,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !comment_id || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.get_comment_votes.comment_id, comment_id, 199);

    dna_task_callback_t cb = {0};
    cb.feed_comment = callback;
    return dna_submit_task(engine, TASK_GET_COMMENT_VOTES, &params, cb, user_data);
}
