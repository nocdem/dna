# Channel Post Scalability Redesign

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make channel posts scale to 50-150+ concurrent users per channel by switching from per-post signatures to per-bucket root signatures, enforcing a 16KB bucket size limit, and reducing max post body to 512 bytes.

**Architecture:** Each user's daily post bucket is signed once (root signature over SHA3-512 hash of all posts), instead of each post carrying its own Dilithium5 signature (~4.6KB). Bucket size is capped at 16KB (excluding signature); when exceeded, oldest posts are evicted. This reduces per-user bucket size from ~74KB (10 posts × 7.4KB) to ~18KB (22 posts × ~700B + 6.2KB sig), allowing `get_all` responses to serve 50+ users within Nodus resp_buf limits.

**Tech Stack:** C (messenger library), Dilithium5 (post-quantum signatures), SHA3-512 (hashing), JSON (serialization), Nodus DHT (storage)

---

## Context & Problem

### Current State
- Each post is individually signed with Dilithium5 (~4627 bytes raw, ~6.2KB base64)
- Post body max: 4000 bytes (`DNA_CHANNEL_POST_MAX`)
- No bucket size limit — grows unbounded
- Daily buckets: `dna:channels:posts:<uuid>:YYYYMMDD` (multi-owner)
- Nodus `resp_buf` = 1.1MB (static, `get_all` packs ALL owners into one response)

### Problem
- 10 posts per user with per-post signature = ~74KB/user
- 15 users = 1.1MB → **resp_buf overflow**, `get_all` fails silently
- Channels unusable beyond ~15 concurrent posters

### Target
- 50+ users per channel with comfortable margin
- 150+ users when Nodus resp_buf is increased to 4MB (separate server-side change)

## Design Decisions

### 1. Root Signature (per-bucket, not per-post)
**Before:** Each post carries its own Dilithium5 signature
```json
[
  {"post_uuid":"...", "body":"hello", "signature":"base64(4627B)", ...},
  {"post_uuid":"...", "body":"world", "signature":"base64(4627B)", ...}
]
```

**After:** Bucket has one root signature over all posts
```json
{
  "version": 2,
  "posts": [
    {"post_uuid":"...", "body":"hello", "created_at": 1741700000, ...},
    {"post_uuid":"...", "body":"world", "created_at": 1741700100, ...}
  ],
  "author": "fingerprint_hex_128chars",
  "posts_hash": "sha3-512 hex of canonical posts JSON",
  "signature": "base64(4627B)"
}
```

**Verification:** SHA3-512(canonical posts JSON) → verify signature against author's public key. If hash matches, ALL posts in bucket are verified.

**Trade-off:** Cannot verify a single post independently (need whole bucket). Acceptable for channels — posts are always read in bucket context.

### 2. Bucket Size Limit: 16KB
- 16KB limit applies to posts data only (excluding signature + metadata overhead)
- When adding a new post would exceed 16KB, evict oldest posts until it fits
- At ~700B per post (512B body + metadata), this allows ~22 posts per bucket
- Total bucket with signature: ~22KB/user

### 3. Post Body Max: 512 bytes
- Reduced from 4000 to 512
- ~500 characters — sufficient for channel chat messages
- Keeps per-post overhead predictable

### 4. Bucket Format Version
- New format uses `"version": 2` wrapper object
- Old format (bare JSON array) = version 1 (implicit)
- Reader must handle both formats during transition
- Writer always writes version 2

## Capacity Table (after changes)

| Users | Bucket/user | Total `get_all` | resp_buf 1.1MB | resp_buf 4MB |
|-------|-------------|-----------------|----------------|--------------|
| 20    | ~22KB       | 440KB           | OK             | OK           |
| 50    | ~22KB       | 1.1MB           | BORDERLINE     | OK           |
| 100   | ~22KB       | 2.2MB           | FAIL           | OK           |
| 150   | ~22KB       | 3.3MB           | FAIL           | OK           |

---

## Files Affected

### Must Modify
| File | Changes |
|------|---------|
| `messenger/dht/client/dna_channels.h` | Update `DNA_CHANNEL_POST_MAX` (4000→512), add `DNA_CHANNEL_BUCKET_MAX_SIZE` (16KB), remove per-post signature fields from struct |
| `messenger/dht/client/dna_channels.c` | Root signature logic, bucket size enforcement, eviction, v2 format read/write, backward compat v1 read |
| `messenger/src/api/engine/dna_engine_channels.c` | Update verified flag logic (bucket-level instead of per-post) |
| `messenger/include/dna/dna_engine.h` | Update `dna_channel_post_info_t` comment (body max 512) |

### No Change Needed
| File | Reason |
|------|--------|
| `messenger/dna_messenger_flutter/lib/models/channel.dart` | `verified` field stays, semantics unchanged (bucket verified = all posts verified) |
| `messenger/dna_messenger_flutter/lib/screens/channels/channel_detail_screen.dart` | Already shows verified checkmark per post — now all posts in a verified bucket show it |
| `messenger/dna_messenger_flutter/lib/ffi/dna_bindings.dart` | Struct unchanged |
| Nodus server | resp_buf increase is a separate task (one-line change + deploy) |

---

## Implementation Tasks

### Task 1: Update Constants and Struct

**Files:**
- Modify: `messenger/dht/client/dna_channels.h:31-34`

**Changes:**
1. Change `DNA_CHANNEL_POST_MAX` from `4000` to `512`
2. Add new constants:
```c
#define DNA_CHANNEL_POST_MAX        512
#define DNA_CHANNEL_BUCKET_MAX_SIZE (16 * 1024)  /* 16KB posts data limit per bucket */
#define DNA_CHANNEL_BUCKET_VERSION  2
```
3. Remove `signature` and `signature_len` from `dna_channel_post_internal_t` struct (lines 68-76). Posts no longer carry individual signatures.

**Updated struct:**
```c
typedef struct {
    char post_uuid[37];
    char channel_uuid[37];
    char author_fingerprint[129];
    char *body;                 /* heap-allocated, caller frees, max 512 bytes */
    uint64_t created_at;
} dna_channel_post_internal_t;
```

4. Update `dna_channel_post_free()` and `dna_channel_posts_free()` — remove `free(post->signature)` calls.

**Commit:** `refactor(channels): update post limits and remove per-post signature fields`

---

### Task 2: Implement Root Signature Bucket Format (v2 Writer)

**Files:**
- Modify: `messenger/dht/client/dna_channels.c`

**Changes to `posts_bucket_to_json()`:**

Replace current function that writes a bare JSON array with v2 format:

```c
static int posts_bucket_to_json_v2(const dna_channel_post_internal_t *posts,
                                     size_t count,
                                     const char *author_fingerprint,
                                     const uint8_t *private_key,
                                     char **json_out) {
    // 1. Build posts array JSON (without signatures)
    // 2. Compute SHA3-512 hash of canonical posts JSON
    // 3. Sign the hash with Dilithium5 (ONE signature for entire bucket)
    // 4. Wrap in v2 envelope: {"version":2, "posts":[...], "author":"...", "posts_hash":"...", "signature":"..."}
    // 5. Return the envelope JSON
}
```

**Canonical posts JSON** for hashing: The JSON array of posts (without signature), using `JSON_C_TO_STRING_PLAIN` for deterministic output.

**Changes to `post_to_json()`:**
- Remove `include_signature` parameter — posts never carry signatures anymore
- Simplify to always output: post_uuid, channel_uuid, author, body, created_at

**Commit:** `feat(channels): implement v2 bucket format with root signature`

---

### Task 3: Implement v2 Bucket Reader + v1 Backward Compatibility

**Files:**
- Modify: `messenger/dht/client/dna_channels.c`

**Changes to `posts_bucket_from_json()`:**

```c
static int posts_bucket_from_json_versioned(const char *json_str,
                                              dna_channel_post_internal_t **posts_out,
                                              size_t *count_out,
                                              bool *verified_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    if (json_object_is_type(root, json_type_array)) {
        // v1 format: bare array, per-post signatures
        // Parse as before, set *verified_out = false (can't verify without per-post sig in new code)
        // OR: verify each post's individual signature if present
        return parse_v1_bucket(root, posts_out, count_out, verified_out);
    }

    // v2 format: envelope object
    json_object *version_obj;
    if (json_object_object_get_ex(root, "version", &version_obj) &&
        json_object_get_int(version_obj) == 2) {
        return parse_v2_bucket(root, posts_out, count_out, verified_out);
    }

    // Unknown format
    json_object_put(root);
    return -1;
}
```

**v2 verification (`parse_v2_bucket`):**
1. Extract `posts` array, `posts_hash`, `signature`, `author`
2. Serialize `posts` array to canonical JSON
3. Compute SHA3-512 of canonical JSON
4. Compare with `posts_hash`
5. Verify Dilithium5 signature of `posts_hash` against author's public key
6. If valid → all posts `verified = true`

**v1 backward compat (`parse_v1_bucket`):**
- Parse bare JSON array as before
- Per-post signatures still verified if present
- Allows reading old data during transition period

**Public key lookup:** Author fingerprint is in the bucket. Use existing `dna_identity_get_public_key()` or the keyserver to resolve fingerprint → Dilithium5 public key.

**Note:** Need to investigate how the existing per-post verification resolves public keys. Check `merge_posts_from_key()` and its callers — currently `verified` is set to `(posts[i].signature_len > 0)` which is a weak check (presence of signature, not actual crypto verify). The new root signature should do actual crypto verification.

**Commit:** `feat(channels): add v2 bucket reader with backward v1 compatibility`

---

### Task 4: Implement Bucket Size Enforcement + Eviction

**Files:**
- Modify: `messenger/dht/client/dna_channels.c`

**Changes to `dna_channel_post_create()`:**

After Step 2 (building merged array), before serializing:

```c
/* Step 2.5: Enforce bucket size limit — evict oldest posts if needed */
// Sort by created_at ascending (oldest first)
// Calculate total posts data size (sum of serialized post sizes, excluding signature)
// While total_size > DNA_CHANNEL_BUCKET_MAX_SIZE:
//   - Remove oldest post (index 0)
//   - Recalculate size
// Log how many posts were evicted
```

**Size calculation:** For each post, estimate: `strlen(body) + 200` (metadata overhead: UUIDs, fingerprint, timestamp, JSON syntax). Or serialize to JSON and measure actual length.

**More accurate approach:** Serialize posts array to JSON, check `strlen(json)`. If > 16KB, remove oldest, re-serialize, repeat. Slightly wasteful but correct and simple.

**Simpler approach (recommended):** Calculate before serializing:
```c
static size_t estimate_post_size(const dna_channel_post_internal_t *post) {
    size_t size = 0;
    size += 37;   // post_uuid
    size += 37;   // channel_uuid
    size += 129;  // author_fingerprint
    size += post->body ? strlen(post->body) : 0;
    size += 20;   // created_at (timestamp digits)
    size += 80;   // JSON syntax overhead (keys, quotes, braces, commas)
    return size;
}
```

Then trim from the front (oldest) until total ≤ `DNA_CHANNEL_BUCKET_MAX_SIZE`.

**Commit:** `feat(channels): enforce 16KB bucket size limit with oldest-post eviction`

---

### Task 5: Update Engine Layer

**Files:**
- Modify: `messenger/src/api/engine/dna_engine_channels.c`

**Changes:**

1. In `dna_handle_channel_get_posts()` (line 659): Update the conversion loop. Currently sets `verified` from `signature_len > 0`. After change, `verified` comes from the bucket-level verification result.

2. In `dna_handle_channel_post()` (line 600): The `dna_channel_post_create()` signature changes — it no longer needs `private_key` per-post (the key is used for bucket signing). Actually — **it still needs private_key** because after adding the new post, the entire bucket is re-signed. So function signature stays the same, but internal behavior changes.

3. Update `dna_channel_post_info_t` comment in `dna_engine.h:283` — body max is now 512.

**Changes in `merge_posts_from_key()`:**
- Remove `free(bucket_posts[j].signature)` in dedup path (signature field no longer exists on individual posts)
- The `verified` flag needs to come from bucket-level verification, not per-post

**Commit:** `refactor(channels): update engine layer for root signature verification`

---

### Task 6: Update Cleanup Functions

**Files:**
- Modify: `messenger/dht/client/dna_channels.c`

**Changes:**
- `dna_channel_post_free()`: Remove `free(post->signature)` (line 604)
- `dna_channel_posts_free()`: Remove `free(posts[i].signature)` in loop
- `merge_posts_from_key()`: Remove `free(bucket_posts[j].signature)` in dedup cleanup (line 1055)

**Commit:** Can be combined with Task 1 commit.

---

### Task 7: Build Verification + Tests

**Steps:**
1. `cd messenger/build && cmake .. && make -j$(nproc)` — must compile clean (zero warnings)
2. `cd messenger/build && ctest --output-on-failure` — all existing tests must pass
3. Manual test with CLI: create channel, post messages, verify posts appear

**Test scenarios:**
- Post with body exactly 512 bytes → should succeed
- Post with body 513 bytes → should fail with error
- Post 25 times to same channel/day → bucket should auto-evict oldest, keeping ≤16KB
- Read channel with mix of v1 (old) and v2 (new) buckets → both should parse

---

### Task 8: Documentation Updates

**Files to update:**
- `messenger/docs/functions/dht.md` — update channel post function signatures
- `messenger/docs/DHT_SYSTEM.md` — document v2 bucket format
- `messenger/docs/ARCHITECTURE_DETAILED.md` — if channel storage model is documented there

---

## Breaking Change Analysis

**Is this a breaking change?** Partially.

- **Writer:** New code writes v2 format. Old clients can't read v2 buckets.
- **Reader:** New code reads both v1 and v2. Old clients reading v2 will fail (unknown JSON structure).
- **Post body limit:** Reduced from 4000→512. Old clients with cached 4000-char limit won't be affected (they can still READ longer posts), but new posts must be ≤512.

**Migration strategy:** Since channels are relatively new and not heavily used yet, a hard cutover is acceptable. Old daily buckets (v1) will expire via DHT TTL (30 days). New buckets are v2.

**Flutter side:** The `DNA_CHANNEL_POST_MAX` is not exposed via FFI — the C library enforces it. Flutter just needs to know the new limit for UI validation (text field max length). Check if `channel_detail_screen.dart` has a hardcoded max length.

---

## Future Work (NOT part of this plan)
- **Nodus resp_buf increase** to 4MB (separate server-side deploy, one line change)
- **Saatlik buckets** if 50+ concurrent users per hour becomes reality
- **Lazy signature loading** for bandwidth optimization
- **Post editing/deletion** within bucket
