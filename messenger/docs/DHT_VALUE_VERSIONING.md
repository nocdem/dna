# DHT Value Versioning and Replacement

**Date:** 2025-11-11
**Issue:** Value accumulation in DHT offline message queue
**Solution:** Use signed puts with fixed value IDs

---

## Problem Description

### Original Behavior (BEFORE Fix)

When using OpenDHT's unsigned `put()` function without specifying a value ID:

1. **Auto-generated Value IDs**: OpenDHT auto-generates a random 64-bit ID for each value
2. **Value Accumulation**: Each PUT creates a NEW value with a different ID
3. **No Replacement**: Old values are NOT replaced - they accumulate at the same key
4. **Result**: Multiple versions pile up in DHT (7+ values observed)

**Example from logs:**
```
[DHT] GET_ALL: Found 7 value(s)
  Value 1: 10781 bytes
  Value 2: 4 bytes
  Value 3: 4 bytes
  Value 4: 21563 bytes
  Value 5: 32355 bytes
  Value 6: 4 bytes
  Value 7: 21559 bytes
```

### Why This Happened

From OpenDHT documentation research:

- **Unsigned values** (`put()`) cannot be edited/replaced
- **EditPolicy** only applies to **signed values** with matching value IDs
- Each value with a different ID is treated as a separate entry
- `dht_delete()` is not implemented in OpenDHT (just a placeholder)
- There's no automatic cleanup of old unsigned values

---

## Solution: Signed Puts with Fixed Value IDs

### Key Changes

1. **Added `dht_put_signed()` C wrapper** (`dht/dht_context.h`, `dht/dht_context.cpp`)
   - Uses OpenDHT's `putSigned()` instead of `put()`
   - Sets fixed value ID (not auto-generated)
   - Old values with same ID are REPLACED (not accumulated)

2. **Modified offline queue** (`dht/dht_offline_queue.c`)
   - Replaced `dht_put()` calls with `dht_put_signed()`
   - Uses fixed `value_id=1` for offline queue slot
   - Both queueing and clearing use same value ID

### How It Works

**OpenDHT's Signed Value Mechanism:**

1. **Fixed Value ID**: We set `dht_value->id = 1` (not auto-generated)
2. **Signed Storage**: `putSigned()` enables editing via EditPolicy
3. **Sequence Numbers**: Auto-increment for versioning (0, 1, 2, ...)
4. **Replacement Logic**: When a PUT has same value ID, old value is replaced

**Before (Unsigned):**
```
PUT #1: id=random1 → stored
PUT #2: id=random2 → stored (accumulated!)
PUT #3: id=random3 → stored (accumulated!)
Result: 3 values in DHT
```

**After (Signed with fixed ID):**
```
PUT #1: id=1, seq=0 → stored
PUT #2: id=1, seq=1 → REPLACES PUT #1
PUT #3: id=1, seq=2 → REPLACES PUT #2
Result: 1 value in DHT (newest version)
```

---

## Code Changes

### 1. New C Wrapper Function

**File:** `dht/dht_context.h` (lines 122-149)

```c
/**
 * Put SIGNED value in DHT with fixed value ID (enables editing/replacement)
 *
 * This function uses OpenDHT's putSigned() with a fixed value ID, which
 * allows subsequent PUTs with the same ID to REPLACE the old value instead
 * of accumulating.
 *
 * @param ctx DHT context
 * @param key Key (will be hashed to 160-bit infohash)
 * @param key_len Key length
 * @param value Value to store
 * @param value_len Value length
 * @param value_id Fixed value ID (e.g., 1 for offline queue slot)
 * @param ttl_seconds Time-to-live in seconds (0 = default 7 days)
 * @return 0 on success, -1 on error
 */
int dht_put_signed(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *value, size_t value_len,
                   uint64_t value_id,
                   unsigned int ttl_seconds);
```

**File:** `dht/dht_context.cpp` (lines 591-700)

**Key implementation details:**

```cpp
// Create value blob
auto dht_value = std::make_shared<dht::Value>(data);

// Set TTL based on ValueType
dht_value->type = (ttl >= 365 days) ? DNA_TYPE_365DAY.id : DNA_TYPE_7DAY.id;

// CRITICAL: Set fixed value ID (not auto-generated)
dht_value->id = value_id;

// Use putSigned() to enable editing/replacement
ctx->runner.putSigned(hash, dht_value, callback, false);
```

**Important Notes:**

- `putSigned()` does NOT accept `creation_time` parameter (uses current time)
- `permanent` flag controls whether value expires based on ValueType
- Sequence numbers are auto-managed by OpenDHT

### 2. Offline Queue Changes

**File:** `dht/dht_offline_queue.c`

**Change 1: Queueing messages (line 449)**

```c
// OLD:
int put_result = dht_put(ctx, queue_key, 64, serialized, serialized_len);

// NEW:
int put_result = dht_put_signed(ctx, queue_key, 64, serialized, serialized_len, 1, 0);
//                                                                          ↑value_id
```

**Change 2: Clearing queue (line 619)**

```c
// OLD:
int result = dht_put(ctx, queue_key, 64, empty_queue, sizeof(uint32_t));

// NEW:
int result = dht_put_signed(ctx, queue_key, 64, empty_queue, sizeof(uint32_t), 1, 0);
//                                                                              ↑value_id
```

**Why use same value_id=1?**
- Both queue updates and queue clearing target the SAME storage slot
- Using the same value ID ensures proper replacement behavior
- Empty queue replaces full queue, and vice versa

---

## Expected Behavior After Fix

### Before Deployment (Old Unsigned Values)

```bash
./quick_lookup dei
# Output: Found 7 value(s) - accumulated from old puts
```

### After Deployment (New Signed Values)

When new messages are sent using the updated messenger:

1. **First message**: Creates value with `id=1, seq=0`
2. **Second message**: Replaces with `id=1, seq=1`
3. **Third message**: Replaces with `id=1, seq=2`

**Expected DHT query result:**
```bash
./quick_lookup dei
# Output: Found 1 value - newest version only
```

**Old unsigned values:**
- Will still exist in DHT (cannot be removed)
- `dht_get_all()` retrieves them, but we select largest/newest
- Will expire naturally after 7-day TTL
- New signed values will coexist with old unsigned ones initially

---

## Testing Procedure

### Step 1: Deploy Updated Messenger

```bash
cd /opt/dna-messenger/build
make -j$(nproc)
# Deploy to production (GUI or dna-send CLI)
```

### Step 2: Send Test Messages

```bash
# User A sends message to User B
# This will use NEW dht_put_signed() with value_id=1
```

### Step 3: Verify Single Value

```bash
./quick_lookup <recipient>
# Should show: Found 1 value (or more if old values still present)
# Check that newest messages use signed values
```

### Step 4: Monitor Over Time

- Old unsigned values will expire after 7 days
- New signed values will replace each other
- Eventually only 1 value per recipient queue

---

## Technical References

### OpenDHT API

**Function signature:**
```cpp
void DhtRunner::putSigned(InfoHash hash,
                          std::shared_ptr<Value> value,
                          DoneCallback cb = {},
                          bool permanent = false);
```

**Value fields:**
```cpp
struct Value {
    uint64_t id;        // Fixed ID enables replacement
    uint32_t seq;       // Auto-incrementing sequence number
    uint16_t type;      // ValueType (DNA_TYPE_7DAY, DNA_TYPE_365DAY)
    std::vector<uint8_t> data;  // Actual content
    // ... signature fields ...
};
```

### ValueType TTL Settings

**DNA Messenger uses custom ValueTypes:**

```cpp
DNA_TYPE_7DAY    (0x1001): 7-day TTL    // Offline messages, groups, social posts
DNA_TYPE_365DAY  (0x1002): 365-day TTL  // Name registrations, reverse mappings
PERMANENT        (max):    Never expires // Identity keys, contact lists
```

---

## Related Files

**Modified:**
- `dht/dht_context.h` - Added `dht_put_signed()` declaration
- `dht/dht_context.cpp` - Implemented `dht_put_signed()` wrapper
- `dht/dht_offline_queue.c` - Use signed puts for queueing/clearing

**Tested with:**
- `dht/quick_lookup.c` - DHT query tool
- `build/gui/dna_messenger_gui` - Main messenger application

---

## Commit Messages

```
Fix: DHT value accumulation - use signed puts with fixed IDs

Problem: Offline message queue accumulated multiple values in DHT
(7+ versions) because unsigned put() auto-generates random value IDs.

Solution:
- Added dht_put_signed() C wrapper using OpenDHT's putSigned()
- Modified dht_offline_queue.c to use signed puts with value_id=1
- Old values with same ID are now REPLACED (not accumulated)

Files changed:
- dht/dht_context.h (new function declaration)
- dht/dht_context.cpp (110 lines implementation)
- dht/dht_offline_queue.c (2 put call updates)

Documented in: /docs/DHT_VALUE_VERSIONING.md
```

---

## Future Considerations

### Cleanup of Old Unsigned Values

**Option 1: Wait for TTL expiry**
- Old unsigned values expire after 7 days
- Simplest approach, no code changes needed

**Option 2: Manual cleanup script**
- Create tool to clear old unsigned values
- Use `dht_get_all()` + filter by value type
- May not be necessary if automatic expiry works

### Value ID Strategy

**Current approach:**
- Fixed `value_id=1` for all offline queues
- Works because each recipient has unique DHT key

**Alternative approaches:**
- Derive value_id from recipient hash: `value_id = hash(recipient) % 1000`
- Use timestamp-based value_id: `value_id = current_time / 3600`
- Keep current approach (simplest and works)

### Sequence Number Monitoring

**Future enhancement:**
- Log sequence numbers for debugging
- Detect sequence number rollover (uint32_t max)
- Add sequence number to debug output

---

## Conclusion

This fix prevents DHT value accumulation by using OpenDHT's signed value mechanism with fixed value IDs. Old values are now REPLACED instead of accumulated, solving the storage bloat issue.

**Key takeaway:** Always use `putSigned()` with fixed value IDs when you want versioning/replacement behavior in OpenDHT.
