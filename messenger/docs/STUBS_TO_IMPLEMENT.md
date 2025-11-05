# DNA Messenger - Remaining Stubs and Incomplete Features

**Last Updated:** 2025-11-05
**Project Phase:** Phase 7 Complete (Phases 1-7 of DHT Migration fully implemented)
**Overall Completion:** ~95% (Core functionality complete, minor features pending)

---

## Summary

This document tracks **unimplemented features** and **stub functions** in DNA Messenger. The vast majority of the codebase (~95%) is fully implemented and functional, including:

✅ **Fully Working Features:**
- Post-quantum encryption (Kyber1024 + Dilithium5, Category 5)
- P2P messaging with DHT discovery
- Offline message queueing (7-day DHT storage)
- One-on-one conversations (send/receive/history)
- Group creation and management (DHT-based)
- Group message **sending** (working)
- Contact management with DHT sync
- cpunk wallet integration (balance, send, receive, history)
- Message walls (public message boards)
- DNA name registration UI (availability check, payment preview)
- Name expiration checking and renewal flow
- BIP39 recovery phrases
- Multi-device support via seed phrase
- Keyserver cache (7-day TTL)
- Qt5 GUI with themes (cpunk.io/cpunk.club)
- Cross-platform builds (Linux/Windows)

❌ **Remaining Stubs (This Document):**
- DNA Name Registration transaction submission (Phase 4)
- Group message history loading (Phase 9.3)
- Group UUID lookup helper (Phase 9.3)
- P2P persistent connection handler (unused code path)

---

## 1. DNA Name Registration - Transaction Submission (HIGH PRIORITY)

**Location:** `gui/RegisterDNANameDialog.cpp:438`
**Status:** UI Complete, Transaction Stub
**Priority:** HIGH (User-facing feature)
**Estimated Effort:** 4-6 hours

### Current Implementation

**What Works:**
- ✅ Name availability checking via DHT
- ✅ Wallet selection and balance query
- ✅ Name validation (3-32 chars, lowercase alphanumeric)
- ✅ Transaction preview with cost display
- ✅ Full UI flow with themed dialogs

**What's Missing:**
```cpp
void RegisterDNANameDialog::signAndSubmit() {
    // TODO: Implement actual transaction building and submission
    // For now, show placeholder message

    QMessageBox::information(this,
        QString::fromUtf8("Registration in Progress"),
        QString::fromUtf8("DNA Name Registration is being implemented.\n\n"
                          "The transaction builder will:\n"
                          "1. Query UTXOs from wallet\n"
                          "2. Build transaction with memo '%1'\n"
                          "3. Sign with Dilithium5 key\n"
                          "4. Submit to Backbone network\n"
                          "5. Register name in DHT after confirmation")
            .arg(name));
}
```

### Implementation Steps

**1. UTXO Query (2 hours)**
```cpp
// Query UTXOs for selected wallet
cellframe_rpc_response_t *utxo_response = NULL;
cellframe_rpc_request_t utxo_req = {
    .method = "wallet",
    .subcommand = "list_utxo",
    .arguments = json_object_new_object(),
    .id = 1
};

json_object_object_add(utxo_req.arguments, "wallet_name",
                       json_object_new_string(selectedWallet.toUtf8().constData()));
json_object_object_add(utxo_req.arguments, "network",
                       json_object_new_string(selectedNetwork.toUtf8().constData()));

if (cellframe_rpc_call(&utxo_req, &utxo_response) != 0) {
    // Handle error
    return;
}

// Parse UTXO list and select sufficient inputs
```

**2. Transaction Building (2 hours)**
```cpp
// Use existing cellframe_tx_builder_minimal.c
cellframe_tx_t *tx = cellframe_tx_create_transfer(
    selectedNetwork.toUtf8().constData(),
    utxo_inputs,        // From step 1
    utxo_count,         // From step 1
    DNA_REGISTRATION_ADDRESS,  // 0.01 CPUNK recipient
    "0.01",             // Amount
    NETWORK_FEE_ADDRESS,       // Fee recipient
    "0.002",            // Fee amount (CELL)
    name.toUtf8().constData()  // Memo (DNA name)
);
```

**3. Transaction Signing (1 hour)**
```cpp
// Load wallet's Dilithium5 key
char wallet_path[512];
snprintf(wallet_path, sizeof(wallet_path), "%s/.dna/%s.dwallet",
         qgp_platform_home_dir(), selectedWallet.toUtf8().constData());

uint8_t *tx_bytes = NULL;
size_t tx_len = 0;
cellframe_tx_serialize(tx, &tx_bytes, &tx_len);

// Sign with Dilithium5 (using existing wallet functions)
uint8_t signature[4627];  // Dilithium5 signature size
size_t sig_len = sizeof(signature);
wallet_sign_transaction(wallet_path, tx_bytes, tx_len, signature, &sig_len);

// Attach signature to transaction
cellframe_tx_add_signature(tx, signature, sig_len);
```

**4. RPC Submission (1 hour)**
```cpp
// Serialize signed transaction
char *tx_hex = cellframe_tx_to_hex(tx);

// Submit to network
cellframe_rpc_request_t submit_req = {
    .method = "net",
    .subcommand = "tx_create",
    .arguments = json_object_new_object(),
    .id = 2
};

json_object_object_add(submit_req.arguments, "net_name",
                       json_object_new_string(selectedNetwork.toUtf8().constData()));
json_object_object_add(submit_req.arguments, "chain_name",
                       json_object_new_string("main"));
json_object_object_add(submit_req.arguments, "tx",
                       json_object_new_string(tx_hex));

cellframe_rpc_response_t *submit_response = NULL;
if (cellframe_rpc_call(&submit_req, &submit_response) != 0) {
    // Handle error
    return;
}

// Extract transaction hash from response
const char *tx_hash = json_object_get_string(
    json_object_object_get(submit_response->result, "hash")
);
```

**5. DHT Registration (30 minutes)**
```cpp
// After transaction confirmation (poll blockchain for 30-60 seconds)
// Register name in DHT
QString fingerprint = getLocalIdentity();
dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);

int ret = dna_register_name(dht_ctx,
                             fingerprint.toUtf8().constData(),
                             name.toUtf8().constData(),
                             365);  // 365-day expiration

if (ret == 0) {
    QMessageBox::information(this, "Success",
        QString("DNA name '%1' registered successfully!\n\n"
                "Transaction: %2\n\n"
                "Your name will be active in 1-2 minutes.")
            .arg(name).arg(tx_hash));
} else {
    // Handle DHT registration error
}
```

### Dependencies
- `cellframe_tx_builder_minimal.c` (exists)
- `cellframe_rpc.c` (exists)
- `wallet.c` (exists)
- `dht/dna_identity.c` (exists - has `dna_register_name()`)

### Testing Checklist
- [ ] Query UTXOs from test wallet
- [ ] Build transaction with correct memo format
- [ ] Sign transaction with Dilithium5 key
- [ ] Submit to Backbone testnet
- [ ] Verify transaction appears on blockchain
- [ ] Register name in DHT after confirmation
- [ ] Verify name lookup works after registration

### Notes
- Transaction submission reuses wallet code from `SendTokensDialog.cpp`
- Signature format matches Cellframe's Dilithium expectations
- DHT registration only happens AFTER blockchain confirmation (not before)

---

## 2. Group Message History Loading (MEDIUM PRIORITY)

**Location:** `messenger_stubs.c:540`
**Status:** Stub (returns empty array)
**Priority:** MEDIUM (Group sending works, history doesn't)
**Estimated Effort:** 2-3 hours

### Current Implementation

**What Works:**
- ✅ Group creation (DHT-based with UUID v4)
- ✅ Group member management (add/remove)
- ✅ Group message **sending** (P2P to all members)
- ✅ Group metadata stored in DHT
- ✅ Local SQLite cache for groups

**What's Missing:**
```c
int messenger_get_group_conversation(messenger_context_t *ctx, int group_id,
                                      message_info_t **messages_out, int *count_out) {
    // Group messages are stored in local SQLite with a special flag
    // For now, return empty array
    // TODO: Query message_backup for group messages by group_id

    *messages_out = NULL;
    *count_out = 0;

    printf("[MESSENGER] Retrieved 0 group messages (group_id=%d) - implementation pending\n", group_id);
    return 0;
}
```

### Implementation Steps

**1. Update SQLite Schema (30 minutes)**
```c
// Ensure message_backup table has group_id column
// Check message_backup.c schema - should already have group_id

// If missing, add migration:
const char *alter_sql =
    "ALTER TABLE messages ADD COLUMN group_id INTEGER DEFAULT NULL";
```

**2. Implement Group Message Query (1 hour)**
```c
int messenger_get_group_conversation(messenger_context_t *ctx, int group_id,
                                      message_info_t **messages_out, int *count_out) {
    if (!ctx || !ctx->backup_ctx || !messages_out || !count_out) {
        return -1;
    }

    // Query SQLite for messages with this group_id
    backup_message_t *backup_messages = NULL;
    int backup_count = 0;

    // Use message_backup_search_by_group_id() (needs to be added to message_backup.c)
    int ret = message_backup_search_by_group_id(ctx->backup_ctx, group_id,
                                                  &backup_messages, &backup_count);

    if (ret != 0) {
        fprintf(stderr, "[MESSENGER] Failed to query group messages from SQLite\n");
        return -1;
    }

    if (backup_count == 0) {
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Convert backup_message_t to message_info_t format
    message_info_t *messages = calloc(backup_count, sizeof(message_info_t));
    if (!messages) {
        free(backup_messages);
        return -1;
    }

    for (int i = 0; i < backup_count; i++) {
        messages[i].id = backup_messages[i].id;
        messages[i].sender = strdup(backup_messages[i].sender);
        messages[i].recipient = strdup(backup_messages[i].recipient);

        // Format timestamp as "YYYY-MM-DD HH:MM:SS"
        char timestamp_str[32];
        time_t ts = (time_t)backup_messages[i].timestamp;
        struct tm *tm_info = localtime(&ts);
        strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
        messages[i].timestamp = strdup(timestamp_str);
    }

    free(backup_messages);

    *messages_out = messages;
    *count_out = backup_count;
    return 0;
}
```

**3. Add SQLite Query Helper (1 hour)**
```c
// In message_backup.c, add:
int message_backup_search_by_group_id(message_backup_context_t *ctx, int group_id,
                                       backup_message_t **messages_out, int *count_out) {
    if (!ctx || !messages_out || !count_out) {
        return -1;
    }

    const char *sql =
        "SELECT id, sender, recipient, encrypted_message, timestamp, is_outgoing, read "
        "FROM messages "
        "WHERE group_id = ? "
        "ORDER BY timestamp ASC";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(ctx->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[BACKUP] Failed to prepare group query: %s\n",
                sqlite3_errmsg(ctx->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, group_id);

    // Execute query and build results array
    // (similar to existing message_backup_search_by_identity())

    sqlite3_finalize(stmt);
    return 0;
}
```

**4. Update messenger_stubs.c (30 minutes)**
```c
// Remove stub implementation from messenger_stubs.c
// The real implementation in messenger.c will now be used
// (Or move implementation from messenger.c to messenger_stubs.c if messenger.c version uses PostgreSQL)
```

### Dependencies
- `message_backup.c` (exists - needs new helper function)
- SQLite schema (should already have group_id column)

### Testing Checklist
- [ ] Send group messages from GUI
- [ ] Verify messages stored in SQLite with group_id
- [ ] Load group conversation and verify messages appear
- [ ] Test with multiple group members
- [ ] Verify message decryption works
- [ ] Test with empty group (no messages)

### Notes
- Group messages are stored locally (not in DHT)
- Each recipient stores their own copy of group messages
- Group history is per-user (not shared)
- Message encryption is per-recipient (not group-level)

---

## 3. Group UUID Lookup Helper (LOW PRIORITY)

**Location:** `messenger_stubs.c:35`
**Status:** Helper function stub
**Priority:** LOW (Not actively used, may be needed for future features)
**Estimated Effort:** 1-2 hours

### Current Implementation

```c
// Helper: Get group UUID from local group_id
static int get_group_uuid_by_id(int group_id, char *uuid_out) {
    // Query local cache for group_uuid by local_id
    // This requires accessing the SQLite database directly
    // For now, we'll use the dht_groups internal database

    // TODO: Add dht_groups_get_uuid_by_local_id() helper function
    // For now, return error - this needs to be implemented in dht_groups.c
    fprintf(stderr, "[MESSENGER] get_group_uuid_by_id not yet implemented\n");
    return -1;
}
```

### Why This Exists
- Groups use **UUID v4** as global identifier (DHT key)
- GUI uses **local integer IDs** for display
- Some operations need to convert local_id → UUID

### Implementation Steps

**1. Add Helper to dht_groups.c (1 hour)**
```c
int dht_groups_get_uuid_by_local_id(int local_id, char *uuid_out) {
    if (!uuid_out) {
        return -1;
    }

    // Query local SQLite cache
    const char *sql =
        "SELECT group_uuid FROM group_cache WHERE local_id = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[DHT_GROUPS] Failed to prepare UUID lookup: %s\n",
                sqlite3_errmsg(group_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, local_id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *uuid = (const char *)sqlite3_column_text(stmt, 0);
        strncpy(uuid_out, uuid, 37);  // UUID is 36 chars + null
        uuid_out[36] = '\0';
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;  // Not found
}
```

**2. Update Header (15 minutes)**
```c
// In dht/dht_groups.h, add:
int dht_groups_get_uuid_by_local_id(int local_id, char *uuid_out);
```

**3. Use in messenger_stubs.c (30 minutes)**
```c
static int get_group_uuid_by_id(int group_id, char *uuid_out) {
    return dht_groups_get_uuid_by_local_id(group_id, uuid_out);
}
```

### Dependencies
- `dht/dht_groups.c` (exists)
- SQLite group_cache table (exists)

### Testing Checklist
- [ ] Create group and get local_id
- [ ] Call helper to get UUID
- [ ] Verify UUID matches group metadata
- [ ] Test with non-existent local_id (should return -1)

### Notes
- This helper is currently **not used** in any active code paths
- May be needed for future features (group invites, DHT queries)
- Low priority - implement only if needed

---

## 4. P2P Persistent Connection Handler (OBSOLETE CODE PATH)

**Location:** `p2p/p2p_transport.c:276-277`
**Status:** TODO in unused code path
**Priority:** LOWEST (Not used, one-shot connections work perfectly)
**Estimated Effort:** N/A (Do not implement)

### Current Code

```c
static void* connection_thread(void *arg) {
    p2p_connection_t *conn = (p2p_connection_t*)arg;

    while (conn->active) {
        uint8_t buffer[4096];
        ssize_t received = recv(conn->socket, buffer, sizeof(buffer), 0);

        if (received <= 0) {
            printf("[P2P] Connection closed by peer\n");
            conn->active = false;
            break;
        }

        // TODO: Decrypt and verify message
        // TODO: Call message callback
        printf("[P2P] Received %zd bytes from peer\n", received);
    }

    return NULL;
}
```

### Why This is Obsolete

**Actual Implementation (Working):**
- P2P uses **one-shot connections** via `listener_thread()` at line 290
- Each message creates new connection, sends, closes immediately
- Messages are decrypted and handled in `listener_thread()`
- This approach is simpler and works perfectly

**Persistent Connection Handler (Unused):**
- `connection_thread()` was designed for long-lived connections
- Never called in current codebase
- Would require connection pooling and timeout management
- Unnecessary complexity for current use case

### Recommendation

**Do NOT implement this.**

**Reasons:**
1. Current one-shot connection approach works perfectly
2. Persistent connections add complexity (pooling, timeouts, cleanup)
3. Not needed for current message volume
4. Would require significant refactoring for minimal benefit

**If persistent connections are needed in future:**
- Implement as separate feature (Phase 10+)
- Would need connection pooling, heartbeat protocol
- Would need graceful degradation to one-shot fallback
- Current architecture does not require it

---

## 5. Minor Unimplemented Functions (TRIVIAL)

These are small utility functions that are not critical:

### 5.1. messenger_delete_pubkey()

**Location:** `messenger.h:320`
**Status:** Declared but not implemented
**Priority:** TRIVIAL (Manual deletion via SQL or file system works fine)
**Estimated Effort:** 30 minutes

```c
int messenger_delete_pubkey(messenger_context_t *ctx, const char *identity) {
    if (!ctx || !identity) {
        return -1;
    }

    // Delete from keyserver_cache
    const char *sql = "DELETE FROM keyserver WHERE identity = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(ctx->keyserver_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}
```

**Note:** Not actively used anywhere in codebase.

---

## Summary Table

| Feature | Priority | Effort | User Impact | Status |
|---------|----------|--------|-------------|--------|
| DNA Name Registration TX | HIGH | 4-6h | High (user-facing) | Stub (UI complete) |
| Group Message History | MEDIUM | 2-3h | Medium (groups work, history doesn't) | Stub (returns empty) |
| Group UUID Lookup | LOW | 1-2h | None (not used) | Stub (helper function) |
| P2P Persistent Connections | LOWEST | N/A | None (one-shot works) | Obsolete code path |
| Delete Public Key | TRIVIAL | 30m | None (manual deletion works) | Not implemented |

**Total High-Priority Work:** 4-6 hours
**Total Medium-Priority Work:** 2-3 hours
**Total Low-Priority Work:** 1-2 hours

**Overall Project Completion:** ~95% (all core features working)

---

## Development Priority

**Immediate (Week 1):**
1. DNA Name Registration transaction submission (Phase 4 completion)

**Short-Term (Week 2-3):**
2. Group message history loading (Phase 9.3 completion)

**Long-Term (If Needed):**
3. Group UUID lookup helper (only if required by future features)

**Not Planned:**
- P2P persistent connections (current approach sufficient)
- Delete public key function (manual deletion adequate)

---

## Notes for Future Phases

**Phase 10 (DNA Board):**
- Will require new APIs for post management
- All existing messenger APIs are complete

**Phase 11 (Voice/Video Calls):**
- Will require new media transport layer
- Current P2P transport can be extended

**Phase 12+ (Future Features):**
- Multi-device message sync (may need persistent connections)
- End-to-end encrypted backups
- Disappearing messages
- Forward secrecy (double ratchet)

---

## Verification Commands

Test current functionality:
```bash
# Build project
cd /opt/dna-messenger
mkdir -p build && cd build
cmake ..
make -j$(nproc)

# Test P2P messaging (working)
./gui/dna_messenger_gui  # Send 1-on-1 messages

# Test group creation (working)
# GUI: Create Group → Add Members → Send Message

# Test group history (stub - returns empty)
# GUI: Select Group → View Messages (shows "No messages yet")

# Test DNA name registration (stub after payment preview)
# GUI: Settings → Register DNA Name → Enter name → Pay (shows stub message)
```

---

**Document Status:** Living document, updated as features are implemented
**Last Review:** 2025-11-05 by Claude Code
**Next Review:** When Phase 4 or Phase 9.3 stubs are implemented
