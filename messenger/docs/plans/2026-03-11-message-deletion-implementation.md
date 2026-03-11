# Message Deletion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add message deletion with cross-device sync and sender notification — single message, contact purge, and purge-all scopes.

**Architecture:** DELETE notices travel as special JSON messages through the existing outbox mechanism (same encryption, signing, and DHT pipeline as regular messages). Cross-device sync uses self-addressed DELETE messages. A new `deleted_by_sender` column in SQLite tracks remote deletions for UI display.

**Tech Stack:** C (SQLite, JSON-C, DHT outbox), Dart/Flutter (Riverpod providers, FFI bindings)

**Design doc:** `messenger/docs/plans/2026-03-11-message-deletion-design.md`

---

### Task 1: Add `deleted_by_sender` Column to SQLite (DB Migration)

**Files:**
- Modify: `messenger/message_backup.c` (schema + migration section, around lines 60-90 and 470-490)
- Modify: `messenger/message_backup.h` (`backup_message_t` struct, around lines 69-84)

**Step 1: Add column to schema**

In `message_backup.c`, find the CREATE TABLE schema string (around line 60-74). Add `deleted_by_sender` column after `content_hash`:

```c
"  content_hash TEXT,"               // v16: SHA3-256 dedup hash (64 hex chars)
"  deleted_by_sender INTEGER DEFAULT 0"  // v17: remote deletion flag
```

**Step 2: Add migration for existing databases**

In `message_backup.c`, after the v16 migration block (around line 470-490), add v17 migration:

```c
/* Migration v17: deleted_by_sender flag for remote deletion notices */
const char *migration_sql_v17 =
    "ALTER TABLE messages ADD COLUMN deleted_by_sender INTEGER DEFAULT 0";

rc = sqlite3_exec(ctx->db, migration_sql_v17, NULL, NULL, &err_msg);
if (rc != SQLITE_OK) {
    QGP_LOG_DEBUG(LOG_TAG, "v17 deleted_by_sender column note: %s\n", err_msg);
    sqlite3_free(err_msg);
} else {
    QGP_LOG_INFO(LOG_TAG, "v17: Added deleted_by_sender column\n");
}
```

**Step 3: Add field to `backup_message_t` struct**

In `message_backup.h`, add to `backup_message_t` after `is_outgoing`:

```c
bool deleted_by_sender;  // true if sender sent deletion notice (v17)
```

**Step 4: Update all SELECT queries that populate `backup_message_t`**

Search for all `SELECT` queries in `message_backup.c` that read messages and add `deleted_by_sender` to the column list. Update the result mapping code to read the new column. Key functions to update:
- `message_backup_get_conversation()`
- `message_backup_get_pending_for_recipient()`
- `message_backup_search()`

For each, add `deleted_by_sender` to SELECT and map: `messages[i].deleted_by_sender = sqlite3_column_int(stmt, N);`

**Step 5: Build and verify**

Run: `cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)`
Expected: Clean build, no warnings

**Step 6: Commit**

```
feat: add deleted_by_sender column to messages table (v17 migration)
```

---

### Task 2: Add Batch Delete Functions to `message_backup`

**Files:**
- Modify: `messenger/message_backup.c` (after existing `message_backup_delete`, around line 1352)
- Modify: `messenger/message_backup.h` (after existing declaration, around line 350)

**Step 1: Add `message_backup_delete_conversation()` function**

In `message_backup.c`, after `message_backup_delete()`:

```c
int message_backup_delete_conversation(message_backup_context_t *ctx,
                                        const char *contact_identity) {
    if (!ctx || !ctx->db || !contact_identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid params for delete_conversation\n");
        return -1;
    }

    const char *sql = "DELETE FROM messages WHERE sender = ? OR recipient = ?";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare delete_conversation: %s\n",
                      sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, contact_identity, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete conversation: %s\n",
                      sqlite3_errmsg(ctx->db));
        return -1;
    }

    int changes = sqlite3_changes(ctx->db);
    QGP_LOG_INFO(LOG_TAG, "Deleted %d messages for contact %.20s...\n",
                 changes, contact_identity);
    return changes;
}
```

**Step 2: Add `message_backup_delete_all()` function**

```c
int message_backup_delete_all(message_backup_context_t *ctx) {
    if (!ctx || !ctx->db) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context for delete_all\n");
        return -1;
    }

    const char *sql = "DELETE FROM messages";
    char *err_msg = NULL;

    int rc = sqlite3_exec(ctx->db, sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete all messages: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    int changes = sqlite3_changes(ctx->db);
    QGP_LOG_INFO(LOG_TAG, "Deleted all %d messages\n", changes);
    return changes;
}
```

**Step 3: Add `message_backup_mark_deleted_by_sender()` function**

```c
int message_backup_mark_deleted_by_sender(message_backup_context_t *ctx,
                                           const char *content_hash) {
    if (!ctx || !ctx->db || !content_hash) return -1;

    const char *sql = "UPDATE messages SET deleted_by_sender = 1 WHERE content_hash = ?";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, content_hash, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}
```

**Step 4: Add `message_backup_get_content_hash_by_id()` function**

```c
int message_backup_get_content_hash_by_id(message_backup_context_t *ctx,
                                           int message_id,
                                           char *hash_out, size_t hash_out_size) {
    if (!ctx || !ctx->db || message_id <= 0 || !hash_out) return -1;

    const char *sql = "SELECT content_hash FROM messages WHERE id = ?";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int(stmt, 1, message_id);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        const char *hash = (const char *)sqlite3_column_text(stmt, 0);
        if (hash) {
            strncpy(hash_out, hash, hash_out_size - 1);
            hash_out[hash_out_size - 1] = '\0';
        } else {
            sqlite3_finalize(stmt);
            return -1;
        }
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}
```

**Step 5: Add `message_backup_get_all_content_hashes()` function**

```c
int message_backup_get_all_content_hashes(message_backup_context_t *ctx,
                                           const char *contact_identity,
                                           char ***hashes_out, int *count_out) {
    if (!ctx || !ctx->db || !contact_identity || !hashes_out || !count_out) return -1;

    const char *sql = "SELECT content_hash FROM messages "
                      "WHERE (sender = ? OR recipient = ?) AND content_hash IS NOT NULL";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, contact_identity, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, contact_identity, -1, SQLITE_STATIC);

    /* First pass: count */
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) count++;
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        *hashes_out = NULL;
        *count_out = 0;
        return 0;
    }

    char **hashes = calloc(count, sizeof(char*));
    if (!hashes) {
        sqlite3_finalize(stmt);
        return -1;
    }

    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char *hash = (const char *)sqlite3_column_text(stmt, 0);
        if (hash) {
            hashes[idx] = strdup(hash);
            idx++;
        }
    }

    sqlite3_finalize(stmt);
    *hashes_out = hashes;
    *count_out = idx;
    return 0;
}
```

**Step 6: Add `message_backup_delete_by_content_hash()` function**

```c
int message_backup_delete_by_content_hash(message_backup_context_t *ctx,
                                           const char *content_hash) {
    if (!ctx || !ctx->db || !content_hash) return -1;

    const char *sql = "DELETE FROM messages WHERE content_hash = ?";
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, content_hash, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}
```

**Step 7: Declare all new functions in `message_backup.h`**

After existing `message_backup_delete` declaration:

```c
int message_backup_delete_conversation(message_backup_context_t *ctx,
                                        const char *contact_identity);
int message_backup_delete_all(message_backup_context_t *ctx);
int message_backup_mark_deleted_by_sender(message_backup_context_t *ctx,
                                           const char *content_hash);
int message_backup_get_content_hash_by_id(message_backup_context_t *ctx,
                                           int message_id,
                                           char *hash_out, size_t hash_out_size);
int message_backup_get_all_content_hashes(message_backup_context_t *ctx,
                                           const char *contact_identity,
                                           char ***hashes_out, int *count_out);
int message_backup_delete_by_content_hash(message_backup_context_t *ctx,
                                           const char *content_hash);
```

**Step 8: Build and verify**

Run: `cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)`
Expected: Clean build

**Step 9: Commit**

```
feat: add batch delete and content hash query functions to message_backup
```

---

### Task 3: Add DELETE Message Type and Notice Functions

**Files:**
- Modify: `messenger/message_backup.h` (add MESSAGE_TYPE_DELETE constant)
- Modify: `messenger/messenger/messages.h` (add delete function declarations + enum)
- Modify: `messenger/messenger/messages.c` (implement functions)

**Step 1: Add MESSAGE_TYPE_DELETE constant**

In `message_backup.h`, after existing message type constants:

```c
#define MESSAGE_TYPE_DELETE 3  /* Deletion notice (v17) */
```

**Step 2: Add deletion action enum and declarations in `messages.h`**

```c
typedef enum {
    DELETE_ACTION_SINGLE = 0,
    DELETE_ACTION_CONVERSATION = 1,
    DELETE_ACTION_ALL = 2
} delete_action_t;

int messenger_delete_message_full(messenger_context_t *ctx, int message_id,
                                   bool send_notices);
int messenger_delete_conversation_full(messenger_context_t *ctx,
                                        const char *contact_identity);
int messenger_delete_all_messages(messenger_context_t *ctx);
int messenger_send_delete_notice(messenger_context_t *ctx,
                                  const char *recipient,
                                  delete_action_t action,
                                  const char **content_hashes,
                                  int hash_count);
```

**Step 3: Implement functions in `messages.c`**

Implement `messenger_delete_message_full()`, `messenger_delete_conversation_full()`, `messenger_delete_all_messages()`, and `messenger_send_delete_notice()`.

The key function is `messenger_send_delete_notice()` which builds a JSON delete message and sends it through the existing `messenger_send_message()` pipeline:

```c
int messenger_send_delete_notice(messenger_context_t *ctx,
                                  const char *recipient,
                                  delete_action_t action,
                                  const char **content_hashes,
                                  int hash_count) {
    if (!ctx || !recipient) return -1;

    json_object *j_notice = json_object_new_object();
    json_object_object_add(j_notice, "type", json_object_new_string("delete"));
    json_object_object_add(j_notice, "action", json_object_new_int(action));

    if (content_hashes && hash_count > 0) {
        json_object *j_hashes = json_object_new_array();
        for (int i = 0; i < hash_count; i++) {
            json_object_array_add(j_hashes, json_object_new_string(content_hashes[i]));
        }
        json_object_object_add(j_notice, "hashes", j_hashes);
    }

    if (action == DELETE_ACTION_CONVERSATION) {
        json_object_object_add(j_notice, "contact", json_object_new_string(recipient));
    }

    const char *json_str = json_object_to_json_string(j_notice);
    const char *recipients[1] = { recipient };
    int rc = messenger_send_message(ctx, recipients, 1, json_str,
                                     0, MESSAGE_TYPE_DELETE);
    json_object_put(j_notice);
    return rc;
}
```

**Step 4: Build and verify**

Run: `cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)`

**Step 5: Commit**

```
feat: add DELETE message type and notice functions
```

---

### Task 4: Handle Incoming DELETE Notices

**Files:**
- Modify: `messenger/messenger_transport.c` (message receive callback, around line 626-670)

**Step 1: Add DELETE notice handling in the receive callback**

In `messenger_transport.c`, the function `messenger_transport_on_message()` already parses JSON and checks for `"type": "group_invite"`. Add a new branch for `"type": "delete"` after the group invite block.

Key logic:
- If sender == our identity (self-addressed): actually delete from local DB (cross-device sync)
- If sender != our identity: mark messages with `deleted_by_sender` flag
- Fire `DNA_EVENT_MESSAGE_RECEIVED` event to trigger UI refresh
- Return early (don't save DELETE notice as a regular message)

For self-addressed DELETE notices:
- `DELETE_ACTION_SINGLE`: call `message_backup_delete_by_content_hash()` for each hash
- `DELETE_ACTION_CONVERSATION`: call `message_backup_delete_conversation()` with the contact fp
- `DELETE_ACTION_ALL`: call `message_backup_delete_all()`

For other-user DELETE notices:
- Call `message_backup_mark_deleted_by_sender()` for each content hash

**Step 2: Build and verify**

Run: `cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)`

**Step 3: Commit**

```
feat: handle incoming DELETE notices with cross-device sync
```

---

### Task 5: Add Engine API for Message Deletion

**Files:**
- Modify: `messenger/src/api/dna_engine_internal.h` (add task types + params)
- Modify: `messenger/src/api/engine/dna_engine_messaging.c` (add handlers + API wrappers)
- Modify: `messenger/src/api/dna_engine.c` (add dispatch cases)
- Modify: `messenger/include/dna/dna_engine.h` (public API + update `dna_message_t`)

**Step 1: Add task types to enum**

In `dna_engine_internal.h`, add after `TASK_CHECK_OFFLINE_MESSAGES_FROM`:

```c
TASK_DELETE_MESSAGE,
TASK_DELETE_CONVERSATION,
TASK_DELETE_ALL_MESSAGES,
```

**Step 2: Add task params to union**

```c
struct {
    int message_id;
    bool send_notices;
} delete_message;

struct {
    char contact[129];
    bool send_notices;
} delete_conversation;

struct {
    bool send_notices;
} delete_all_messages;
```

**Step 3: Implement handlers in `dna_engine_messaging.c`**

Add `dna_handle_delete_message()`, `dna_handle_delete_conversation()`, `dna_handle_delete_all_messages()`.

Key flow for `dna_handle_delete_conversation()`:
1. Get all content hashes before deleting (for notices)
2. Delete conversation locally
3. Rebuild outbox (flush)
4. Send DELETE notice to contact
5. Send DELETE notice to self (cross-device)

**Step 4: Add dispatch cases in `dna_engine.c`**

**Step 5: Add public API declarations in `dna_engine.h`**

Three new functions: `dna_engine_delete_message()`, `dna_engine_delete_conversation()`, `dna_engine_delete_all_messages()`.

Also add `deleted_by_sender` field to `dna_message_t` struct.

**Step 6: Implement public API wrappers using `dna_submit_task()`**

**Step 7: Build and run tests**

```
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)
cd /opt/dna/messenger/build && ctest --output-on-failure
```

**Step 8: Commit**

```
feat: add async engine API for message deletion with notices
```

---

### Task 6: Add FFI Bindings (Dart)

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/ffi/dna_bindings.dart` (native bindings)
- Modify: `messenger/dna_messenger_flutter/lib/ffi/dna_engine.dart` (Message model + wrapper)

**Step 1: Add `deletedBySender` field to `Message` class**

In `dna_engine.dart`, add field and update `fromNative()`.

**Step 2: Add native FFI lookups for new delete functions**

`dna_engine_delete_message`, `dna_engine_delete_conversation`, `dna_engine_delete_all_messages`

**Step 3: Add Dart async wrapper methods**

`deleteMessageFull()`, `deleteConversation()`, `deleteAllMessages()` — using same completion callback pattern as existing methods.

**Step 4: Build Flutter**

Run: `cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux`

**Step 5: Commit**

```
feat: add FFI bindings for message deletion API
```

---

### Task 7: Update Flutter UI — Message Bubble + Context Menu

**Files:**
- Modify: `messenger/dna_messenger_flutter/lib/screens/chat/chat_screen.dart`
- Modify: `messenger/dna_messenger_flutter/lib/screens/chat/widgets/message_bubble.dart`
- Modify: `messenger/dna_messenger_flutter/lib/providers/messages_provider.dart`

**Step 1: Update `ConversationNotifier.deleteMessage()` to use full pipeline**

Replace existing `deleteMessage()` to call `deleteMessageFull()` and add `deleteConversation()` method.

**Step 2: Add "deleted by sender" indicator to message bubble**

Show a small indicator when `message.deletedBySender` is true: FaIcon trash + "Sender deleted this" italic text.

**Step 3: Update delete confirmation dialog text**

**Step 4: Add "Delete Conversation" option to chat app bar menu**

Add menu item + confirmation dialog + handler.

**Step 5: Build Flutter**

Run: `cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux`

**Step 6: Commit**

```
feat: update Flutter UI for message deletion with sender indicator
```

---

### Task 8: Add Settings UI for Purge

**Files:**
- Modify: Settings screen file in `messenger/dna_messenger_flutter/lib/screens/settings/`

**Step 1: Add "Delete All Messages" option to settings**

Add a ListTile in the Privacy/Storage section with trash icon, confirmation dialog, and handler calling `deleteAllMessages()`.

**Step 2: Build Flutter**

Run: `cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux`

**Step 3: Commit**

```
feat: add purge all messages option to settings
```

---

### Task 9: Update Documentation

**Files:**
- Modify: `messenger/docs/MESSAGE_SYSTEM.md`
- Modify: `messenger/docs/DNA_ENGINE_API.md`
- Modify: `messenger/docs/functions/public-api.md`
- Modify: `messenger/docs/functions/messenger.md`
- Modify: `messenger/docs/functions/database.md`

**Step 1: Update MESSAGE_SYSTEM.md** — add Message Deletion section
**Step 2: Update DNA_ENGINE_API.md** — add new API entries
**Step 3: Update function reference files** — add all new function signatures

**Step 4: Commit**

```
docs: add message deletion documentation
```

---

### Task 10: Version Bump and Final Build Verification

**Files:**
- Modify: `messenger/include/dna/version.h`
- Modify: `messenger/dna_messenger_flutter/pubspec.yaml`

**Step 1: Bump versions** — C: 0.9.48 to 0.9.49, Flutter: rc11 to rc12

**Step 2: Full build and test**

```
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)
cd /opt/dna/messenger/build && ctest --output-on-failure
cd /opt/dna/messenger/dna_messenger_flutter && flutter build linux
```

**Step 3: Commit**

```
feat: message deletion with cross-device sync (v0.9.49 / v1.0.0-rc12)
```
