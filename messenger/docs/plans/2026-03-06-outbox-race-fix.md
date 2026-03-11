# Outbox Race Condition Fix — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the read-modify-write race in DHT outbox that causes message loss when sending rapidly.

**Architecture:** Replace the outbox's DHT GET + RAM cache with local `messages.db` as the single source of truth. On each send, query ALL PENDING outgoing messages for the recipient from `messages.db`, re-encrypt each one, build the complete blob, and PUT to DHT. The blob always reflects the full set of pending messages — no stale reads, no race.

**Tech Stack:** C, SQLite (messages.db), Kyber1024/Dilithium5 encryption, Nodus DHT

---

## Background

### The Bug
`dht_dm_queue_message()` in `dht_dm_outbox.c` does GET→append→PUT. When CLI sends rapidly (each send = separate process), the GET returns stale data because the previous PUT hasn't propagated. Result: each send overwrites the previous blob. Only the last message survives.

### Why It Works in Flutter
Flutter is a long-lived process. The in-memory `g_dm_cache` (60s TTL) holds the latest blob. Second send hits cache → append → PUT. No DHT GET needed.

### Why CLI Breaks
Each `dna-messenger-cli send` is a new process. Cache starts empty. Every send does DHT GET → stale or empty → only new message in blob → PUT overwrites previous.

### The Fix
Don't GET from DHT on send. Use `messages.db` PENDING messages as source of truth. Re-encrypt all pending messages for the recipient on each send, build complete blob, PUT. Even if two processes race, the later one's blob always contains ALL messages (because it reads from SQLite, which serializes writes).

### Re-encrypt Cost
Each message: ~3ms (Kyber1024 encap + AES-256-GCM + Dilithium5 sign). 20 pending messages = ~60ms. Acceptable. Max bucket = 500 messages.

---

## Task 1: Add `messenger_build_outbox_blob()` function

**Files:**
- Create: `messenger/messenger/outbox_builder.c`
- Create: `messenger/messenger/outbox_builder.h`
- Modify: `messenger/CMakeLists.txt` (add new .c to build)

This function reads ALL PENDING outgoing messages for a recipient from `messages.db`, re-encrypts each one, serializes into a blob, and returns it.

**Step 1: Create header `outbox_builder.h`**

```c
#ifndef OUTBOX_BUILDER_H
#define OUTBOX_BUILDER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build outbox blob for a recipient from local messages.db.
 *
 * Reads ALL PENDING (status=0) outgoing messages for the recipient,
 * re-encrypts each one, serializes into a single blob for DHT PUT.
 * This eliminates the DHT GET→append→PUT race condition.
 *
 * @param identity      Sender's identity/fingerprint
 * @param recipient     Recipient identity (name or fingerprint)
 * @param blob_out      Output serialized blob (caller must free)
 * @param blob_len_out  Output blob length
 * @return Number of messages in blob (>= 0), or -1 on error
 */
int messenger_build_outbox_blob(const char *identity,
                                 const char *recipient,
                                 uint8_t **blob_out,
                                 size_t *blob_len_out);

#ifdef __cplusplus
}
#endif

#endif /* OUTBOX_BUILDER_H */
```

**Step 2: Implement `outbox_builder.c`**

```c
#include "outbox_builder.h"
#include "messenger.h"
#include "message_backup.h"
#include "dht/shared/dht_dm_outbox.h"  /* dht_serialize_messages, dht_offline_message_t */
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "OUTBOX_BUILD"

int messenger_build_outbox_blob(const char *identity,
                                 const char *recipient,
                                 uint8_t **blob_out,
                                 size_t *blob_len_out)
{
    if (!identity || !recipient || !blob_out || !blob_len_out)
        return -1;

    *blob_out = NULL;
    *blob_len_out = 0;

    /* Get messenger context (singleton) */
    /* NOTE: Implementation needs access to messenger context for encryption.
     * This will use the existing messenger singleton or accept ctx as parameter.
     * See Step 3 notes below. */

    /* Query messages.db for ALL PENDING outgoing messages to this recipient */
    message_backup_context_t *backup_ctx = message_backup_init(identity);
    if (!backup_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init message backup for %s", identity);
        return -1;
    }

    backup_message_t *messages = NULL;
    int count = 0;
    /* Get pending messages for THIS specific recipient only */
    int rc = message_backup_get_pending_for_recipient(backup_ctx, recipient,
                                                       &messages, &count);
    if (rc != 0 || count == 0) {
        message_backup_close(backup_ctx);
        return 0;  /* No pending messages — empty blob */
    }

    /* Re-encrypt each message and build offline message array */
    /* ... encryption + serialization ... */

    message_backup_free_messages(messages, count);
    message_backup_close(backup_ctx);
    return count;
}
```

**Step 3: Add to CMakeLists.txt**

Add `messenger/outbox_builder.c` to the source list in `messenger/CMakeLists.txt`.

**Step 4: Build to verify compilation**

```bash
cd messenger/build && cmake .. && make -j$(nproc)
```

**Step 5: Commit skeleton**

---

## Task 2: Add `message_backup_get_pending_for_recipient()`

**Files:**
- Modify: `messenger/message_backup.c` (~line 964)
- Modify: `messenger/message_backup.h`

We need a variant of `message_backup_get_pending_messages()` that filters by recipient.

**Step 1: Add declaration to `message_backup.h`**

```c
/**
 * Get PENDING outgoing messages for a specific recipient.
 * Used by outbox builder to construct DHT blob from local state.
 *
 * @param ctx        Backup context
 * @param recipient  Recipient fingerprint or identity
 * @param messages_out  Output array (caller must free with message_backup_free_messages)
 * @param count_out  Number of messages returned
 * @return 0 on success, -1 on error
 */
int message_backup_get_pending_for_recipient(message_backup_context_t *ctx,
                                              const char *recipient,
                                              backup_message_t **messages_out,
                                              int *count_out);
```

**Step 2: Implement in `message_backup.c`**

```c
int message_backup_get_pending_for_recipient(message_backup_context_t *ctx,
                                              const char *recipient,
                                              backup_message_t **messages_out,
                                              int *count_out)
{
    if (!ctx || !recipient || !messages_out || !count_out) return -1;

    *messages_out = NULL;
    *count_out = 0;

    sqlite3 *db = message_backup_get_db(ctx);
    if (!db) return -1;

    pthread_mutex_lock(&ctx->mutex);

    const char *sql =
        "SELECT id, sender, recipient, plaintext, sender_fingerprint, "
        "       timestamp, delivered, read, status, group_id, message_type, retry_count "
        "FROM messages "
        "WHERE is_outgoing = 1 AND status = 0 AND recipient = ? "
        "ORDER BY timestamp ASC";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&ctx->mutex);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, recipient, -1, SQLITE_STATIC);

    /* Count results first, then allocate */
    /* ... same pattern as message_backup_get_pending_messages ... */

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}
```

**Step 3: Build and verify**

```bash
cd messenger/build && cmake .. && make -j$(nproc)
```

**Step 4: Commit**

---

## Task 3: Rewrite `dht_dm_queue_message()` to use local DB

**Files:**
- Modify: `messenger/dht/shared/dht_dm_outbox.c:217-403`

This is the core fix. Replace the GET→append→PUT logic with: save new ciphertext to local array → query messages.db for ALL pending → re-encrypt ALL → serialize blob → PUT.

**WAIT — SIMPLER APPROACH:** The function already receives the new ciphertext. We don't need to re-encrypt ALL pending messages. We just need to include them in the blob. But we only have ciphertext for the NEW message — the old pending messages are plaintext in messages.db.

**REVISED APPROACH:** Instead of modifying `dht_dm_queue_message()`, modify the CALLER. In `messenger_send_message()` (messages.c:510-543), after saving to messages.db, instead of calling `messenger_queue_to_dht()` for just the new message, call a new function that:

1. Reads ALL PENDING messages for this recipient from messages.db
2. Re-encrypts each one
3. Serializes into one blob
4. PUTs the complete blob

**EVEN SIMPLER:** Modify `messenger_queue_to_dht()` / `dht_dm_queue_message()` to:
1. Accept the new ciphertext as before
2. Instead of GET from DHT for existing messages, read the RAM cache
3. If cache miss, DON'T fall back to DHT GET — instead, just PUT the new message alone
4. The retry system will eventually rebuild with all pending messages

**WAIT — this still loses messages.** The whole point is the blob must contain ALL pending messages.

**FINAL APPROACH:** The cleanest fix is to change `dht_dm_queue_message()` lines 292-304 (the cache miss path). Instead of fetching from DHT, we accept that the RAM cache IS the source of truth for the current process. For CLI (cache always empty), we rely on the **bulletproof retry system** to rebuild. But the retry system calls `messenger_send_message()` per message, which goes through the same per-message path...

**ACTUAL FINAL APPROACH:** Modify the retry system to be the blob builder. The retry calls `messenger_send_message()` individually — change it to batch ALL pending messages for a recipient into one outbox blob PUT.

OK — let me re-think this cleanly. The simplest correct fix:

**In `dht_dm_queue_message()`, replace the cache miss DHT GET (lines 292-304) with a call that reads pending ciphertext from a local persistent store.**

But we don't HAVE persistent ciphertext. That's Option B (rejected).

**So the real fix for Option A is:**

1. `messenger_send_message()` saves plaintext to messages.db (already happens)
2. `messenger_send_message()` encrypts and DHT PUTs the new message ALONE (no blob — single message)
3. Immediately after, a new function `messenger_flush_outbox()` reads ALL PENDING for this recipient, re-encrypts all, builds complete blob, PUTs
4. The complete blob overwrites the single-message blob (higher seq wins)

**But this means EVERY send re-encrypts all pending messages. That's the accepted cost of Option A.**

Actually — simpler still:

1. DON'T change messenger_send_message()
2. DON'T change dht_dm_queue_message()
3. Just add a NEW function `messenger_flush_recipient_outbox(ctx, recipient)` that:
   - Queries messages.db for ALL PENDING to this recipient
   - Re-encrypts each
   - Serializes into blob
   - PUTs to DHT
4. Call this function AFTER the existing send path completes
5. The flush blob contains ALL messages (including the one just sent), overwriting any partial blobs

This is additive — no existing code modified in the hot path. The existing send still works as before (may lose messages individually), but the immediate flush corrects it.

---

## REVISED PLAN

### Task 1: Add `message_backup_get_pending_for_recipient()`

**Files:**
- Modify: `messenger/message_backup.c`
- Modify: `messenger/message_backup.h`

New SQL query: `WHERE is_outgoing = 1 AND status IN (0, 3) AND recipient = ?`

### Task 2: Add `messenger_flush_recipient_outbox()`

**Files:**
- Modify: `messenger/messenger/messages.c`
- Modify: `messenger/messenger.h`

New function that:
1. Gets backup_ctx from messenger context
2. Calls `message_backup_get_pending_for_recipient()`
3. For each pending message: re-encrypts (loads keys, `messenger_encrypt_multi_recipient`)
4. Builds `dht_offline_message_t` array
5. Serializes with `dht_serialize_messages()`
6. PUTs blob with `nodus_ops_put_str()`
7. Updates all messages to SENT on success

### Task 3: Call flush after send

**Files:**
- Modify: `messenger/messenger/messages.c:510-543`

After the existing per-recipient DHT queue loop, call `messenger_flush_recipient_outbox()` for each recipient. This ensures the complete blob is always published.

### Task 4: Remove DHT GET from outbox cache miss path

**Files:**
- Modify: `messenger/dht/shared/dht_dm_outbox.c:292-304`

Replace DHT GET fallback with: return empty (no existing messages). This prevents the race. The flush function handles completeness.

### Task 5: Build, test, commit

Build both messenger and nodus. Send 10 messages from CLI, verify all 10 arrive on receiver.

---

**Version bump:** Messenger 0.9.15 → 0.9.16
