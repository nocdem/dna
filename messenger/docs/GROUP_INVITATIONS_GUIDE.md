# DNA Messenger - P2P Group Invitations System

**Version:** 1.0
**Date:** 2025-11-17
**Phase:** 5.6 (P2P Architecture)
**Author:** DNA Messenger Team

---

## Overview

The P2P Group Invitations system enables users to invite others to encrypted group chats through direct messaging. When a user is added to a group, they receive an invitation message in their 1-on-1 chat with the inviter, complete with Accept/Decline buttons. This provides a seamless onboarding experience for group participation.

**Key Features:**
- P2P invitation delivery via encrypted direct messages
- Rich invitation UI with group details and member count
- Accept/Decline workflow with database state management
- Automatic DHT group synchronization on acceptance
- JSON-based invitation format for extensibility
- Full integration with existing message history

---

## Architecture

### Components

The invitation system consists of three main layers:

1. **Database Layer** - SQLite storage for messages and invitation state
2. **Backend Layer** - Detection, parsing, and state management
3. **UI Layer** - Rendering and user interaction

```
┌─────────────────────────────────────────────────────────────┐
│                        UI Layer                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  chat_screen.cpp: Invitation rendering with buttons  │  │
│  │  - Blue invitation box (rounded border)              │  │
│  │  - Group icon, name, details                         │  │
│  │  - Accept/Decline buttons                            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           ↓ ↑
┌─────────────────────────────────────────────────────────────┐
│                      Backend Layer                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  messenger_p2p.c: Invitation detection               │  │
│  │  - Decrypt incoming messages                         │  │
│  │  - Parse JSON for "type": "group_invite"            │  │
│  │  - Extract group details                             │  │
│  │  - Store in group_invitations DB                     │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  messenger_stubs.c: Accept/Reject handlers           │  │
│  │  - messenger_accept_group_invitation()               │  │
│  │  - messenger_reject_group_invitation()               │  │
│  │  - DHT group sync on accept                          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           ↓ ↑
┌─────────────────────────────────────────────────────────────┐
│                     Database Layer                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  message_backup.c: Messages DB (schema v5)           │  │
│  │  - message_type field (0=chat, 1=group_invitation)  │  │
│  │  - invitation_status field (0=pending, 1=accepted,  │  │
│  │    2=rejected)                                        │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  group_invitations.c: Invitations DB                 │  │
│  │  - group_uuid, group_name, inviter                   │  │
│  │  - status, member_count, invited_at                  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Database Schema

### Messages Table (schema v5)

The messages table was extended to support invitation tracking:

```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    encrypted_message BLOB NOT NULL,
    encrypted_len INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    delivered INTEGER DEFAULT 1,
    read INTEGER DEFAULT 0,
    is_outgoing INTEGER DEFAULT 0,
    status INTEGER DEFAULT 1,
    group_id INTEGER DEFAULT 0,
    message_type INTEGER DEFAULT 0,        -- NEW (v4): 0=chat, 1=group_invitation
    invitation_status INTEGER DEFAULT 0    -- NEW (v5): 0=pending, 1=accepted, 2=rejected
);
```

**Schema Evolution:**
- **v3 → v4:** Added `message_type` field
- **v4 → v5:** Added `invitation_status` field

**Migration:** Automatic via `ALTER TABLE` with `DEFAULT 0` (backward compatible)

### Group Invitations Table

Separate table for invitation state management:

```sql
CREATE TABLE group_invitations (
    group_uuid TEXT PRIMARY KEY,
    group_name TEXT NOT NULL,
    inviter TEXT NOT NULL,
    invited_at INTEGER NOT NULL,
    status INTEGER DEFAULT 0,     -- 0=pending, 1=accepted, 2=rejected
    member_count INTEGER DEFAULT 0
);
```

**Location:** `~/.dna/group_invitations.db` (per-identity)

---

## Message Flow

### 1. Creating a Group and Adding Members

```
User A (Creator)                        User B (Invitee)
    │                                         │
    ├─[Create Group "Team Chat"]             │
    │  - Generate UUID v4                     │
    │  - Store in DHT + local cache           │
    │                                         │
    ├─[Add User B to group]                  │
    │  - Build invitation JSON                │
    │  - Encrypt with User B's Kyber key     │
    │  - Send via P2P/DHT                     │
    │                                         │
    └────────────────[Encrypted Message]────>│
                                             │
                     [Receive & Decrypt]<────┤
                     [Parse JSON]            │
                     [Detect type=group_invite]
                     [Store in messages DB]  │
                     [Store in invitations DB]
                     [Show invitation UI]    │
```

### 2. Invitation JSON Format

```json
{
    "type": "group_invite",
    "group_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "group_name": "Team Chat",
    "inviter": "a3f5e2d1...c8b4 (128 chars)",
    "member_count": 5
}
```

**Fields:**
- `type`: Always `"group_invite"` (distinguishes from regular chat messages)
- `group_uuid`: UUID v4 (36 characters, e.g., `550e8400-e29b-41d4-a716-446655440000`)
- `group_name`: Display name of the group
- `inviter`: 128-character SHA3-512 fingerprint of the person who sent the invitation
- `member_count`: Number of members currently in the group

### 3. Backend Detection (messenger_p2p.c)

When a message is received:

```c
// 1. Decrypt message
uint8_t *plaintext = NULL;
size_t plaintext_len = 0;
dna_decrypt_message(ctx->dna_ctx, message, message_len, ctx->identity,
                    &plaintext, &plaintext_len, NULL, NULL);

// 2. Check if JSON with "type": "group_invite"
json_object *j_msg = json_tokener_parse((const char*)plaintext);
json_object *j_type = NULL;
if (json_object_object_get_ex(j_msg, "type", &j_type)) {
    const char *type_str = json_object_get_string(j_type);
    if (strcmp(type_str, "group_invite") == 0) {
        message_type = MESSAGE_TYPE_GROUP_INVITATION;

        // 3. Extract invitation details
        const char *group_uuid = json_object_get_string(j_uuid);
        const char *group_name = json_object_get_string(j_name);

        // 4. Store in group_invitations database
        group_invitation_t invitation = {0};
        strncpy(invitation.group_uuid, group_uuid, sizeof(invitation.group_uuid) - 1);
        strncpy(invitation.group_name, group_name, sizeof(invitation.group_name) - 1);
        invitation.status = INVITATION_STATUS_PENDING;
        group_invitations_store(&invitation);
    }
}

// 5. Store message with correct type
message_backup_save(ctx->backup_ctx, sender_identity, ctx->identity,
                    message, message_len, now, false, 0, message_type);
```

---

## UI Implementation

### Invitation Rendering (chat_screen.cpp)

When loading messages, the UI checks `message_type`:

```cpp
// Regular message rendering
for (const auto& msg : messages_copy) {
    // Check if this is a group invitation
    if (msg.message_type == MESSAGE_TYPE_GROUP_INVITATION) {
        // Parse JSON to extract details
        json_object *j_msg = json_tokener_parse(msg.content.c_str());
        const char *group_uuid = json_object_get_string(j_uuid);
        const char *group_name = json_object_get_string(j_name);
        int member_count = json_object_get_int(j_count);

        // Render blue invitation box
        ImVec4 invitation_bg = ImVec4(0.2f, 0.4f, 0.8f, 0.3f);
        ImGui::BeginChild("invitation", ImVec2(width, 120.0f), true);

        // Icon and title
        ImGui::Text(ICON_FA_USERS " Group Invitation");

        // Group details
        ImGui::Text("You've been invited to:");
        ImGui::Text("  %s", group_name);
        ImGui::Text("From: %s • %d members", msg.sender.c_str(), member_count);

        // Buttons
        if (ImGui::Button(ICON_FA_CHECK " Accept")) {
            messenger_accept_group_invitation(ctx, group_uuid);
        }
        if (ImGui::Button(ICON_FA_XMARK " Decline")) {
            messenger_reject_group_invitation(ctx, group_uuid);
        }

        ImGui::EndChild();
        continue;  // Skip regular message rendering
    }

    // Regular message bubble
    // ...
}
```

**Visual Design:**
- **Background:** Blue (`rgba(0.2, 0.4, 0.8, 0.3)`)
- **Border:** Blue (`rgba(0.2, 0.4, 0.8, 0.6)`, 2px)
- **Rounded corners:** 8px radius
- **Height:** 120px fixed
- **Icon:** `ICON_FA_USERS` (Font Awesome group icon)
- **Buttons:** Accept (green check) / Decline (red X)

---

## Accept/Reject Workflow

### Accepting an Invitation

```c
int messenger_accept_group_invitation(messenger_context_t *ctx, const char *group_uuid) {
    // 1. Get invitation details from database
    group_invitation_t *invitation = NULL;
    int ret = group_invitations_get(group_uuid, &invitation);
    if (ret != 0) {
        return -1;  // Invitation not found
    }

    // 2. Sync group metadata from DHT
    dht_context_t *dht_ctx = dht_singleton_get();
    ret = dht_groups_sync_from_dht(dht_ctx, group_uuid);
    if (ret != 0) {
        fprintf(stderr, "Failed to sync group from DHT\n");
        return -1;
    }

    // 3. Update invitation status to ACCEPTED
    group_invitations_update_status(group_uuid, INVITATION_STATUS_ACCEPTED);

    // 4. Group now appears in user's groups list
    printf("[MESSENGER] Accepted group invitation: %s\n", group_uuid);

    return 0;
}
```

**DHT Group Sync:**
- Fetches group metadata from DHT using UUID as key
- Stores group in local cache (`~/.dna/groups_cache.db`)
- Group automatically appears in groups list on next app launch

### Rejecting an Invitation

```c
int messenger_reject_group_invitation(messenger_context_t *ctx, const char *group_uuid) {
    // Update invitation status to REJECTED
    int ret = group_invitations_update_status(group_uuid, INVITATION_STATUS_REJECTED);

    printf("[MESSENGER] Rejected group invitation: %s\n", group_uuid);
    return 0;
}
```

**Behavior:**
- Invitation remains in database but marked as rejected
- User can still re-accept later by clicking Accept again (invitation UI persists)
- No DHT sync occurs for rejected invitations

---

## Security Considerations

### Encryption

- **Invitations are encrypted:** Use same Kyber1024 + AES-256-GCM encryption as regular messages
- **End-to-end security:** Only inviter and invitee can read invitation content
- **No plaintext leakage:** Invitation JSON never stored unencrypted

### Authentication

- **Sender verification:** Message signature verifies inviter identity
- **DHT signature check:** Group metadata in DHT is signed by creator (Dilithium5)
- **Fingerprint validation:** 128-character SHA3-512 fingerprints prevent spoofing

### Spam Prevention

- **No unsolicited invitations:** Must be 1-on-1 contacts to receive invitations
- **Rate limiting:** (Future) Limit invitations per user per day
- **Reputation system:** (Future) Block users who spam invitations

---

## API Reference

### C API (Backend)

#### messenger_send_message()
```c
int messenger_send_message(
    messenger_context_t *ctx,
    const char **recipients,
    size_t recipient_count,
    const char *message,
    int group_id,
    int message_type  // MESSAGE_TYPE_CHAT or MESSAGE_TYPE_GROUP_INVITATION
);
```

**Purpose:** Send message with specified type
**Returns:** `0` on success, `-1` on error

#### messenger_accept_group_invitation()
```c
int messenger_accept_group_invitation(
    messenger_context_t *ctx,
    const char *group_uuid
);
```

**Purpose:** Accept invitation and sync group from DHT
**Returns:** `0` on success, `-1` on error

#### messenger_reject_group_invitation()
```c
int messenger_reject_group_invitation(
    messenger_context_t *ctx,
    const char *group_uuid
);
```

**Purpose:** Mark invitation as rejected
**Returns:** `0` on success, `-1` on error

### Database API

#### message_backup_save()
```c
int message_backup_save(
    message_backup_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *encrypted_message,
    size_t encrypted_len,
    time_t timestamp,
    bool is_outgoing,
    int group_id,
    int message_type  // NEW: 0=chat, 1=group_invitation
);
```

#### group_invitations_store()
```c
int group_invitations_store(const group_invitation_t *invitation);
```

#### group_invitations_update_status()
```c
int group_invitations_update_status(const char *group_uuid, int status);
```

---

## Testing Guide

### Manual Testing Steps

#### 1. Create Group and Add Member

**User A (Inviter):**
1. Launch DNA Messenger
2. Click "Create Group" button
3. Enter group name (e.g., "Test Group")
4. Select User B from contact list
5. Click "Create"
6. Verify group appears in groups list

**Expected Result:** User B receives invitation message

#### 2. Receive and View Invitation

**User B (Invitee):**
1. Check chat with User A
2. See blue invitation box with:
   - Group icon
   - "Group Invitation" title
   - Group name
   - Inviter name and member count
   - Accept/Decline buttons

**Expected Result:** Invitation displays correctly

#### 3. Accept Invitation

**User B:**
1. Click "Accept" button
2. Wait for DHT sync (1-2 seconds)
3. Check groups list

**Expected Result:** Group appears in groups list

#### 4. Verify Group Membership

**User B:**
1. Open group chat
2. Send test message
3. Verify User A receives message

**User A:**
1. Check group chat
2. See User B's message

**Expected Result:** Messages deliver successfully

#### 5. Test Reject Workflow

**User C (New invitee):**
1. Receive invitation
2. Click "Decline" button

**Expected Result:**
- Invitation marked as rejected in database
- Group does NOT appear in groups list
- Invitation UI persists (can re-accept later)

---

## Troubleshooting

### Common Issues

#### 1. Invitation Not Received

**Symptoms:** User added to group but no invitation appears

**Possible Causes:**
- P2P connection failed
- DHT offline queue not polled
- Message decryption failed

**Solutions:**
```bash
# Check DHT connectivity
./build/imgui_gui/dna_messenger_imgui
# Look for: "[DHT] Connected to bootstrap nodes"

# Manually trigger offline queue check
# (In GUI: wait for 2-minute polling interval or restart app)

# Check message database
sqlite3 ~/.dna/messages.db "SELECT message_type FROM messages WHERE message_type=1;"
```

#### 2. Accept Button Does Nothing

**Symptoms:** Clicking Accept button has no effect

**Possible Causes:**
- DHT group sync failed
- Group UUID mismatch
- Network connectivity issues

**Solutions:**
```bash
# Check DHT group cache
sqlite3 ~/.dna/groups_cache.db "SELECT * FROM groups;"

# Verify group exists in DHT
# (Check with creator's groups list)

# Check logs for error messages
./build/imgui_gui/dna_messenger_imgui 2>&1 | grep "group"
```

#### 3. Invitation Appears as Encrypted Text

**Symptoms:** Invitation shows `[encrypted]` instead of blue box

**Possible Causes:**
- Decryption failed
- Missing private key
- Corrupted message

**Solutions:**
```bash
# Verify key files exist
ls -la ~/.dna/*.kem ~/.dna/*.dsa

# Check message decryption
# (Should not happen if message appears in chat at all)
```

---

## Performance Considerations

### Database Queries

- **Message loading:** Single query with `message_type` filter
- **Invitation lookup:** Indexed by `group_uuid` (PRIMARY KEY)
- **DHT sync:** One-time fetch per invitation acceptance

### Memory Usage

- **Invitation JSON:** ~200 bytes per invitation
- **UI rendering:** Minimal overhead (blue box + buttons)
- **DHT cache:** ~1KB per group in local cache

### Network Traffic

- **Invitation delivery:** ~400 bytes (encrypted JSON + headers)
- **DHT group sync:** ~2KB (group metadata + member list)
- **Total per invitation:** <3KB

---

## Future Enhancements

### Planned Features

1. **Bulk Invitations**
   - Invite multiple users at once
   - Batch processing for large groups

2. **Invitation Expiry**
   - Auto-expire invitations after N days
   - Notify inviter of expired invitations

3. **Invitation Preview**
   - Show group avatar in invitation
   - Display recent group activity

4. **Re-invitation**
   - Resend declined invitations
   - Track invitation history

5. **Group Invitation Links**
   - Generate shareable invitation links
   - QR code support for mobile

---

## Related Documentation

- **Group Messaging:** `/docs/GROUP_MESSAGING.md` (if exists)
- **DHT Storage:** `/docs/DHT_STORAGE.md` (if exists)
- **P2P Transport:** `/docs/P2P_TRANSPORT.md` (if exists)
- **Database Schema:** `message_backup.h` (inline documentation)

---

## Version History

| Version | Date       | Changes |
|---------|------------|---------|
| 1.0     | 2025-11-17 | Initial release - P2P group invitations implementation |

---

## Credits

**Implementation:** Claude AI + DNA Messenger Team
**Phase:** 5.6 (P2P Architecture)
**Lines of Code:** ~300 (backend + UI)
**Testing:** Manual end-to-end verification

---

**For questions or issues, please visit:**
- GitLab: https://gitlab.cpunk.io/cpunk/dna-messenger
- GitHub: https://github.com/nocdem/dna-messenger
