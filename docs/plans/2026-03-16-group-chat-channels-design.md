# Group Chat via DHT Channels — Encrypted Group Messaging

**Date:** 2026-03-16
**Status:** PLANNED
**Priority:** HIGH

## Overview

Migrate group chat from current DHT outbox model to the **channel system** (like public channels, but encrypted). Server handles store-and-forward of encrypted blobs — zero knowledge of content.

## Architecture

### Current (DHT Outbox)
```
Alice → DHT PUT (encrypted blob per recipient)
Bob   → DHT GET (poll for messages)
```
- Problem: O(N) writes per message (one per member)
- Problem: polling-based, not real-time

### New (Encrypted Channel)
```
Alice → Nodus TCP 4003 → Channel Server → PUSH to all members
```
- Server stores encrypted blobs, pushes to online members
- Offline members fetch on reconnect (store-and-forward)
- O(1) write per message (server fans out)
- Real-time push via TCP 4003

## Flow

### 1. Group Creation
```
User selects contacts → Create group
  1. Generate group UUID
  2. Generate GEK v1 (Group Encryption Key) — Kyber1024 encap per member
  3. Send GEK to each member via DM (existing message system)
  4. Register channel on nodus: 3 responsible nodes (1 PRIMARY, 2 SECONDARY)
     - Channel UUID → SHA3-512 → closest nodes on hashring
     - Same as public channels
  5. Add all members as push targets on channel server
```

### 2. Sending a Message
```
Alice types message
  1. Encrypt with current GEK: AES-256-GCM(message, GEK)
  2. Sign with Dilithium5: SIGN(ciphertext, alice_sk)
  3. POST to channel server (TCP 4003):
     - channel_uuid
     - encrypted_blob (ciphertext + sig + author_fp + timestamp)
  4. Server stores blob in channel table
  5. Server pushes to all online push targets
  6. Offline members: fetch on reconnect (existing store-and-forward)
```

### 3. Receiving a Message
```
Bob receives PUSH from channel server
  1. Decrypt with GEK: AES-256-GCM-OPEN(blob, GEK)
  2. Verify Dilithium5 signature against author's pubkey
  3. Display in group chat UI
```

### 4. Server Role (ZERO KNOWLEDGE)
```
Server sees:
  - channel_uuid (which group)
  - encrypted_blob (opaque bytes)
  - author_fp (who sent — for push target routing)
  - timestamp

Server does NOT see:
  - Message content
  - Group name
  - Member list (only push target fingerprints)
```

## Key Differences from Public Channels

| Aspect | Public Channel | Encrypted Group |
|--------|---------------|-----------------|
| Content | Plaintext + Dilithium5 sig | AES-256-GCM encrypted blob |
| Server verification | Verifies author signature | Cannot verify (encrypted) |
| Membership | Anyone can subscribe | Only invited members (push targets) |
| Key management | None | GEK per group, Kyber1024 distribution |
| Member updates | Open | Owner-only (H-07 security fix) |

## GEK (Group Encryption Key) System

### GEK v1 (Current)
- 256-bit AES key, Kyber1024-encapsulated per member
- Stored locally in `groups.db`
- Distributed via DM to each member

### GEK v2 (Implemented — HKDF ratchet)
- HKDF-SHA3-256 ratchet chain
- Removed members cannot derive future keys
- Version counter: GEK rotation on member removal

### Distribution via Channel
- GEK encrypted per-member using their Kyber1024 public key
- Sent as special `gek_update` message type on the channel
- Members who miss a GEK update request it from the group owner

## Nodus Server Changes

### Already Done (from group-channel feature)
- ✅ Encrypted channel flag in channel_meta
- ✅ Push targets table (per-member)
- ✅ ch_member_update with owner auth (H-07)
- ✅ Store-and-forward queue
- ✅ Post replication on BACKUP nodes (H-08)
- ✅ Channel membership check for encrypted posts (C-05)

### Still Needed
- [ ] GEK update message type on channel wire protocol
- [ ] Member removal → revoke push target + trigger GEK rotation
- [ ] Offline message fetch (channel-based, not DHT outbox)

## Flutter Implementation

### Group Creation Screen
```dart
CreateGroupScreen
  → Select contacts (multi-select from contact list)
  → Set group name
  → [Create]
    1. dna_engine_create_group(name, member_fps[])
    2. Engine: generate GEK, register channel, add push targets
    3. Engine: send GEK to each member via DM
```

### Group Chat Screen
- Same as current group chat UI
- Messages rendered from channel push events (real-time)
- Offline messages fetched on screen open

### Migration
- Existing groups: dual-write (DHT outbox + channel) during transition
- New groups: channel-only
- Old clients: fall back to DHT outbox (backward compat)

## Wire Protocol

### Channel POST (encrypted group message)
```cbor
{
  "method": "ch_post",
  "channel_uuid": "...",
  "body": <encrypted_blob>,    // AES-256-GCM(message, GEK)
  "author_fp": "...",
  "ch_encrypted": true
}
```

### GEK Update (special message type)
```cbor
{
  "method": "ch_post",
  "channel_uuid": "...",
  "body": <gek_envelope>,      // Per-member Kyber1024 encapsulated GEK
  "author_fp": "...",
  "msg_type": "gek_update",
  "gek_version": N
}
```

## Files to Modify

### C (Messenger)
- `messenger/groups.c` — channel-based send/receive
- `src/api/engine/dna_engine_groups.c` — create group → register channel
- `dht/client/dna_group_outbox.c` — dual-write (outbox + channel)

### C (Nodus)
- Already mostly done from group-channel feature

### Flutter
- `lib/screens/group/create_group_screen.dart` — member selection
- `lib/providers/group_provider.dart` — channel-based message delivery
- `lib/screens/group/group_chat_screen.dart` — real-time push rendering

## Effort
~1-2 weeks (most nodus work already done, main effort is Flutter + engine integration)

## Dependencies
- ✅ Channel system (TCP 4003)
- ✅ GEK v2 (HKDF ratchet)
- ✅ Encrypted channel support
- ✅ H-07 member update auth
- ✅ C-05 encrypted channel post verification
- ✅ H-08 backup node post verification
