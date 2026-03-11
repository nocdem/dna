# DHT Storage Model

**Last Updated:** 2026-03-11
**Version:** 0.9.44
**Status:** Verified from source code

This document describes how each data type in DNA Messenger is stored on the Nodus DHT network. It covers key derivation, bucket strategies, serialization formats, TTLs, ownership models, and sync patterns.

**Source of truth:** The actual C source files listed in each section. This document summarizes their behavior.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Direct Messages (DM)](#2-direct-messages-dm)
3. [Group Messages](#3-group-messages)
4. [Wall Posts](#4-wall-posts)
5. [Channels](#5-channels)
6. [Comparison Table](#6-comparison-table)
7. [Common Patterns](#7-common-patterns)
8. [Source File Reference](#8-source-file-reference)

---

## 1. Overview

All persistent data in DNA Messenger is stored on the Nodus DHT via the `nodus_ops` abstraction layer (`dht/shared/nodus_ops.c`). There is **no chunked storage layer** — each value is stored as a single DHT PUT (up to 1MB, the Nodus native limit).

### Storage Strategies Used

| Strategy | Description | Used By |
|----------|-------------|---------|
| **Daily Bucket** | Key includes a day number (`unix_time / 86400`). Each day gets its own DHT key. TTL handles cleanup — no manual pruning needed. | DM, Group Messages, Channel Posts, Channel Index |
| **Single Key** | All data stored under one DHT key per entity. Read-modify-write on updates. | Wall Posts, Channel Metadata |
| **Single-Owner** | Only one identity writes to the key. | DM outbox, Wall posts, Channel metadata |
| **Multi-Owner** | Multiple identities write to the same key with different `value_id`. Retrieved via `nodus_ops_get_all()`. | Group messages, Wall comments, Channel posts, Channel index |

### DHT Key Derivation

All string keys are hashed to SHA3-512 internally by `nodus_ops_put_str()` / `nodus_ops_get_str()`. The string key formats shown below are the **pre-hash** inputs.

---

## 2. Direct Messages (DM)

**Source:** `dht/shared/dht_dm_outbox.c`, `dht/shared/dht_dm_outbox.h`

### Strategy: Daily Bucket, Single-Owner

Each sender maintains their own outbox for each recipient, partitioned by day.

### Key Format

```
<sender_fp>:outbox:<recipient_fp>:<day_bucket>
```

With per-contact salt (privacy enhancement):
```
<sender_fp>:outbox:<recipient_fp>:<day_bucket>:<salt_hex>
```

Where:
- `sender_fp` / `recipient_fp` = 128-char hex SHA3-512 fingerprint
- `day_bucket` = `unix_timestamp / 86400` (integer days since epoch)
- `salt_hex` = 64-char hex of 32-byte per-contact salt (optional)

### Properties

| Property | Value |
|----------|-------|
| **TTL** | 7 days (604,800 seconds) |
| **Owner model** | Single-owner (sender writes their own outbox) |
| **Serialization** | Custom binary format (v2) |
| **Max per bucket** | 50 messages (DoS prevention) |
| **Dedup** | By `seq_num` within bucket |
| **Local cache** | 64 entries, 60-second TTL, in-memory |

### Binary Serialization Format (v2)

```
[4-byte count (network order)]
For each message:
  [4-byte magic 0x444E414D (network order)]
  [1-byte version (2)]
  [8-byte seq_num (2×4 network order)]
  [8-byte timestamp (2×4 network order)]
  [8-byte expiry (2×4 network order)]
  [2-byte sender_len (network order)]
  [2-byte recipient_len (network order)]
  [4-byte ciphertext_len (network order)]
  [sender string (variable)]
  [recipient string (variable)]
  [ciphertext bytes (variable)]
```

### Sync Strategy

| Mode | Days Fetched | Use Case |
|------|-------------|----------|
| **Recent** | yesterday, today, tomorrow (3 days) | Periodic sync while app is running |
| **Full** | today-6 to today+1 (8 days) | Login after extended offline |

- Clock skew tolerance: ±1 day (tomorrow always included)
- All contacts synced in parallel via thread pool (`threadpool_map`)
- Listener rotates at midnight UTC (`dht_dm_outbox_check_day_rotation`)

### ACK System

Delivery confirmation uses a separate key:
```
<recipient_fp>:ack:<sender_fp>[:<salt_hex>]
```
- Value: 8-byte big-endian timestamp
- TTL: 7 days
- Recipient publishes ACK after fetching messages
- Sender listens for ACK to update message status to RECEIVED

### Outbox Flush

`messenger_flush_recipient_outbox()` rebuilds the complete blob from `messages.db` after each send. This eliminates the read-modify-write race condition — the per-message PUT is immediately overwritten by the flush.

---

## 3. Group Messages

**Source:** `dht/client/dna_group_outbox.c`, `dht/client/dna_group_outbox.h`

### Strategy: Daily Bucket, Multi-Owner

All group members write to the same DHT key using different `value_id` values. Each sender's messages are stored in their own slot at the shared key.

### Key Format

```
dna:group:<group_uuid>:out:<day_bucket>
```

Where:
- `group_uuid` = UUID v4 (36 chars)
- `day_bucket` = `unix_timestamp / 86400`

### Properties

| Property | Value |
|----------|-------|
| **TTL** | 7 days (604,800 seconds) |
| **Owner model** | Multi-owner (all members write to same key) |
| **Serialization** | JSON |
| **Encryption** | AES-256-GCM with GEK (Group Encryption Key) |
| **Signature** | Dilithium5 over `message_id + timestamp_ms + ciphertext` |
| **Max text** | 8,192 characters per message |
| **Message ID** | `<sender_fp>_<group_uuid>_<timestamp_ms>` |
| **SQLite tables** | `group_messages`, `group_sync_state` |

### Multi-Owner Pattern

```
DHT Key: dna:group:<uuid>:out:<day>
  ├── value_id=Alice  →  [Alice's messages for this day]
  ├── value_id=Bob    →  [Bob's messages for this day]
  └── value_id=Carol  →  [Carol's messages for this day]
```

Retrieved via `nodus_ops_get_all_str()` which returns all values at the key.

### Sync Strategy

| Mode | Days Fetched | Trigger |
|------|-------------|---------|
| **Recent** | yesterday, today, tomorrow (3 days) | Last sync < 3 days ago |
| **Full** | today-6 to today+1 (8 days) | Last sync > 3 days ago or first sync |
| **Smart** | Automatic selection | `dna_group_outbox_sync()` checks `group_sync_state` |

- Day content hash cache: skips unchanged days (bandwidth optimization)
- Dedup by `message_id` against `group_messages` SQLite table
- Listener rotates at midnight UTC (`dna_group_outbox_check_day_rotation`)

### Encryption Flow

```
Plaintext → AES-256-GCM(GEK) → Ciphertext + Nonce(12B) + Tag(16B)
                                  + Dilithium5 Signature
                                  + GEK version number
```

---

## 4. Wall Posts

**Source:** `dht/client/dna_wall.c`, `dht/client/dna_wall.h`

### Strategy: Single Key, Single-Owner

All posts for a user are stored as a single JSON array under one DHT key. No daily buckets.

### Key Format

**Wall posts:**
```
dna:wall:<fingerprint>
```

**Wall comments (per post):**
```
dna:wall:comments:<post_uuid>
```

### Properties

| Property | Value |
|----------|-------|
| **TTL** | 30 days (2,592,000 seconds) |
| **Owner model** | Single-owner (wall posts), Multi-owner (comments) |
| **Serialization** | JSON array |
| **Signature** | Each post signed with Dilithium5 |
| **Max posts** | 50 per user |
| **Max text** | 2,048 characters |
| **Image support** | `image_json` field (v0.7.0+), base64-encoded |

### JSON Format

```json
[
  {
    "uuid": "xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx",
    "author": "<128-char fingerprint>",
    "text": "Post content",
    "ts": 1710000000,
    "img": { ... },
    "sig": "<base64 Dilithium5 signature>"
  }
]
```

### Signing Payload

```
uuid_bytes + text_bytes + timestamp_be(8 bytes) [+ SHA3-512(image_json) if present]
```

Image hash is appended only when `image_json` is non-empty, maintaining backward compatibility with older clients.

### CRUD Operations

All wall operations use read-modify-write:

1. **Post**: Load existing wall → append new post → re-serialize → PUT
2. **Delete**: Load existing wall → remove post by UUID → re-serialize → PUT
3. **Load**: GET → parse JSON

When at max capacity (50 posts), the oldest post by timestamp is removed before appending.

### Wall Comments

Comments use the multi-owner pattern:
- Each commenter writes their own value at `dna:wall:comments:<post_uuid>`
- Retrieved via `nodus_ops_get_all()` (all commenters' values)
- Single-level threading via `parent_comment_uuid`
- Max body: 2,000 characters
- TTL: 30 days

---

## 5. Channels

**Source:** `dht/client/dna_channels.c`, `dht/client/dna_channels.h`

### Strategy: 3 Namespaces with Mixed Patterns

Channels use three separate DHT key namespaces, each with different storage characteristics.

### 5.1 Channel Metadata

```
dna:channels:meta:<uuid>
```

| Property | Value |
|----------|-------|
| **Bucket** | None (single key) |
| **Owner model** | Single-owner (only creator can update) |
| **Serialization** | JSON |
| **TTL** | 30 days |

Contains: name, description, creator fingerprint, created_at, is_public, deleted flag, signature.

### 5.2 Channel Posts

```
dna:channels:posts:<uuid>:<YYYYMMDD>
```

| Property | Value |
|----------|-------|
| **Bucket** | Daily (`YYYYMMDD` date string format) |
| **Owner model** | Multi-owner (any member can post) |
| **Serialization** | JSON |
| **TTL** | 30 days |
| **Max post body** | 4,000 characters |
| **Fetch range** | Default 3 days back, max 30 days |

### 5.3 Public Channel Index

```
dna:channels:idx:<YYYYMMDD>
```

| Property | Value |
|----------|-------|
| **Bucket** | Daily (`YYYYMMDD` date string format) |
| **Owner model** | Multi-owner (each channel creator registers) |
| **Serialization** | JSON |
| **TTL** | 30 days |
| **Browse range** | Default 7 days back, max 30 days |

Contains lightweight entries: channel UUID, name, description preview (127 chars), creator fingerprint, created_at.

### Date Format Note

Channels use `YYYYMMDD` string dates (e.g., `20260311`) for daily buckets, while DM and Group Messages use integer day numbers (`unix_timestamp / 86400`, e.g., `20529`). Both achieve the same daily partitioning but with different key formats.

---

## 6. Comparison Table

| Data Type | Daily Bucket | Owner Model | TTL | Serialization | Max Size/Count | Encryption |
|-----------|:------------:|:-----------:|:---:|:-------------:|:--------------:|:----------:|
| **DM** | Yes (`epoch/86400`) | Single | 7d | Binary (custom) | 50 msg/bucket | E2E (Kyber+AES) |
| **Group Messages** | Yes (`epoch/86400`) | Multi | 7d | JSON | 8,192 char/msg | GEK (AES-256-GCM) |
| **Wall Posts** | No | Single | 30d | JSON array | 50 posts/user | None (signed) |
| **Wall Comments** | No | Multi | 30d | JSON | 2,000 char/comment | None (signed) |
| **Channel Meta** | No | Single | 30d | JSON | 1 channel | None (signed) |
| **Channel Posts** | Yes (`YYYYMMDD`) | Multi | 30d | JSON | 4,000 char/post | None (signed) |
| **Channel Index** | Yes (`YYYYMMDD`) | Multi | 30d | JSON | N entries | None |

### Key Observations

- **No chunked storage**: Nodus supports up to 1MB per value natively. No chunking abstraction is used.
- **Daily buckets vs single key**: High-volume or time-series data (messages, posts) uses daily buckets. Low-volume or entity-centric data (wall, metadata) uses single key.
- **Multi-owner via value_id**: Nodus stores multiple values per key (one per writer's `value_id`). `nodus_ops_get_all()` retrieves all writers' values.
- **TTL-based cleanup**: No manual garbage collection. DHT entries expire automatically after their TTL.

---

## 7. Common Patterns

### 7.1 Daily Bucket Pattern

Used by: DM, Group Messages, Channel Posts, Channel Index.

```
Key = prefix + entity_id + day_number
Day = unix_timestamp / 86400

Sync recent:  [yesterday, today, tomorrow]     → 3 GET calls
Sync full:    [today-6 ... today+1]            → 8 GET calls
```

**Why daily buckets?**
1. **Size control**: Prevents any single DHT value from growing unbounded
2. **Automatic cleanup**: TTL expires old days without manual pruning
3. **Clock skew tolerance**: Fetching ±1 day handles timezone/clock differences
4. **Efficient sync**: Only fetch days that might have new data

**Listener rotation**: At midnight UTC, cancel old listener, subscribe to new day's key. Sync previous day to catch stragglers.

### 7.2 Single Key Pattern

Used by: Wall Posts, Channel Metadata.

```
Key = prefix + entity_id

Write: GET existing → modify → PUT entire blob
```

Appropriate when:
- Data has a hard cap (e.g., 50 wall posts)
- Updates are infrequent
- Read-modify-write race is acceptable

### 7.3 Multi-Owner Pattern

Used by: Group Messages, Wall Comments, Channel Posts, Channel Index.

```
DHT Key: shared_key
  ├── value_id=writer_A  →  [writer A's data]
  ├── value_id=writer_B  →  [writer B's data]
  └── value_id=writer_C  →  [writer C's data]
```

- Each writer uses their identity's `value_id` (derived from Dilithium5 public key)
- `nodus_ops_get_all()` retrieves all writers' values at once
- No coordination needed between writers — each manages their own slot

### 7.4 Salt-Based Privacy (DM Only)

DM keys include an optional per-contact salt:
```
sender_fp:outbox:recipient_fp:day:SALT_HEX
```

Without salt, anyone who knows both fingerprints can derive the outbox key and monitor message activity (not content — it's encrypted). The 32-byte salt makes the key unpredictable to third parties.

---

## 8. Source File Reference

| Component | Source File | Header |
|-----------|-----------|--------|
| DM Outbox | `dht/shared/dht_dm_outbox.c` | `dht/shared/dht_dm_outbox.h` |
| DM Offline Queue | `dht/shared/dht_offline_queue.c` | `dht/shared/dht_offline_queue.h` |
| Group Outbox | `dht/client/dna_group_outbox.c` | `dht/client/dna_group_outbox.h` |
| Wall Posts | `dht/client/dna_wall.c` | `dht/client/dna_wall.h` |
| Wall Comments | `dht/client/dna_wall_comments.c` | (in `dna_wall.h`) |
| Channels | `dht/client/dna_channels.c` | `dht/client/dna_channels.h` |
| Nodus Ops | `dht/shared/nodus_ops.c` | `dht/shared/nodus_ops.h` |

### Related Documentation

- **[DHT_SYSTEM.md](DHT_SYSTEM.md)** — DHT architecture, bootstrap, key derivation
- **[MESSAGE_SYSTEM.md](MESSAGE_SYSTEM.md)** — Message encryption, format, lifecycle
- **[ARCHITECTURE_DETAILED.md](ARCHITECTURE_DETAILED.md)** — Overall system architecture
- **[PROTOCOL.md](PROTOCOL.md)** — Wire formats (Seal, Spillway, Anchor)

---

**Priority:** When adding new data types to DHT storage, follow the daily bucket pattern for time-series data and the single key pattern for entity-centric data. Use multi-owner when multiple identities need to write to the same logical entity.
