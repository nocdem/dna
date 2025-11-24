# DHT ValueTypes and TTL System

## Overview

DNA Messenger uses custom DHT ValueTypes to control data expiration (Time-To-Live / TTL). All nodes (clients and bootstrap nodes) must register these types for proper operation.

## Custom ValueTypes

| Type ID | Name | TTL | Duration (seconds) | Use Case |
|---------|------|-----|-------------------|----------|
| `0x1001` | `DNA_TYPE_7DAY` | **7 days** | 604,800 | Profiles, groups, wall posts, offline queue |
| `0x1003` | `DNA_TYPE_30DAY` | **30 days** | 2,592,000 | Medium-term data |
| `0x1002` | `DNA_TYPE_365DAY` | **365 days** | 31,536,000 | Name registrations, long-term data |

## TTL Selection Logic

When writing to DHT, the system automatically selects the appropriate ValueType based on TTL:

```c
if (ttl_seconds >= 365 * 24 * 3600) {
    value->type = 0x1002;  // 365-day
} else if (ttl_seconds >= 30 * 24 * 3600) {
    value->type = 0x1003;  // 30-day
} else {
    value->type = 0x1001;  // 7-day (default)
}
```

### Examples

| TTL Requested | Type Selected | Actual Expiration |
|---------------|---------------|-------------------|
| 0 (default) | `0x1001` | 7 days |
| 3 days | `0x1001` | 7 days |
| 45 days | `0x1003` | 30 days |
| 1 year | `0x1002` | 365 days |

## OpenDHT Default Fallback

**CRITICAL:** If a ValueType is NOT registered, OpenDHT falls back to:

```cpp
DEFAULT_VALUE_EXPIRATION = std::chrono::minutes(10);  // 10 MINUTES!
```

This caused the TTL bug where values expired after 10 minutes instead of days.

## Registration

### Client-Side (`dht_context.cpp`)

```cpp
ctx->type_7day = create_7day_type(ctx);
ctx->type_30day = create_30day_type(ctx);
ctx->type_365day = create_365day_type(ctx);

ctx->runner.registerType(ctx->type_7day);
ctx->runner.registerType(ctx->type_30day);
ctx->runner.registerType(ctx->type_365day);
```

### Bootstrap Nodes (`dna-nodus.cpp`)

```cpp
dht::ValueType type_7day(0x1001, "DNA_TYPE_7DAY", std::chrono::hours(7 * 24));
dht::ValueType type_30day(0x1003, "DNA_TYPE_30DAY", std::chrono::hours(30 * 24));
dht::ValueType type_365day(0x1002, "DNA_TYPE_365DAY", std::chrono::hours(365 * 24));

dht.registerType(type_7day);
dht.registerType(type_30day);
dht.registerType(type_365day);
```

## Data Lifecycle

### Write Flow

1. Client calls `dht_put()` or `dht_put_signed()` with `ttl_seconds`
2. System selects ValueType based on TTL
3. Value is stored with type ID (`0x1001`, `0x1003`, or `0x1002`)
4. DHT propagates to ~8 nodes (TARGET_NODES)

### Expiration Flow

1. Bootstrap nodes check ValueType
2. If type registered → use custom TTL (7/30/365 days)
3. If type NOT registered → use DEFAULT (10 minutes) ⚠️
4. Value expires automatically after TTL
5. No deletion needed - natural expiration

## Storage Persistence

ValueTypes with `storeCallback` trigger persistent storage on bootstrap nodes:

```cpp
dht::ValueType create_30day_type(dht_context_t* ctx) {
    return dht::ValueType(
        0x1003,
        "DNA_TYPE_30DAY",
        std::chrono::hours(30 * 24),
        [ctx](dht::InfoHash key, std::shared_ptr<dht::Value>& value,
              const dht::InfoHash&, const dht::SockAddr&) -> bool {
            // Persist to SQLite database
            if (ctx && ctx->storage && value) {
                dht_value_storage_put(ctx->storage, &metadata);
            }
            return true;
        }
    );
}
```

## Historical Bug: Missing Registration

**Problem:** Bootstrap nodes were not registering custom ValueTypes
**Impact:** All values expired after 10 minutes (DEFAULT_VALUE_EXPIRATION)
**Fix:** Added ValueType registration to `dna-nodus.cpp` (commit `ca381cc`)

### Before Fix
```
Client writes type 0x1001 (7-day) → Bootstrap doesn't recognize → Uses 10-minute default → Value expires quickly
```

### After Fix
```
Client writes type 0x1001 (7-day) → Bootstrap recognizes type → Uses 7-day TTL → Value persists properly
```

## API Usage

### C API

```c
// Default 7-day TTL
dht_put_signed(ctx, key, key_len, value, value_len, 0);

// 30-day TTL
dht_put_signed(ctx, key, key_len, value, value_len, 30 * 24 * 3600);

// 365-day TTL
dht_put_signed(ctx, key, key_len, value, value_len, 365 * 24 * 3600);
```

### Internal Functions

```cpp
// With explicit TTL
dht_put_with_ttl(ctx, key, key_len, value, value_len, ttl_seconds);

// With signature
dht_put_signed(ctx, key, key_len, value, value_len, ttl_seconds);
```

## Monitoring

Check ValueType registration on bootstrap nodes:

```bash
journalctl -u dna-nodus --no-pager | grep "Registered DNA_TYPE"
```

Expected output:
```
Registered DNA_TYPE_7DAY (0x1001, TTL=7 days)
Registered DNA_TYPE_30DAY (0x1003, TTL=30 days)
Registered DNA_TYPE_365DAY (0x1002, TTL=365 days)
```

## Best Practices

1. **Always register** custom ValueTypes on all nodes (clients and bootstrap)
2. **Use appropriate TTL** based on data type:
   - Temporary data (messages, presence) → 7 days
   - Medium-term (caches, sessions) → 30 days
   - Long-term (names, identities) → 365 days
3. **Never rely on deletion** - let values expire naturally
4. **Test TTL** in staging before deploying new types
5. **Monitor bootstrap logs** to verify type registration

## Related Files

- `dht/core/dht_context.cpp` - Client-side ValueType registration
- `vendor/opendht-pq/tools/dna-nodus.cpp` - Bootstrap node registration
- `vendor/opendht-pq/include/opendht/value.h` - OpenDHT ValueType definition
- `vendor/opendht-pq/include/opendht/dht.h` - DHT constants

## Commit History

- `0c2deb1` - Add 30-day ValueType (DNA_TYPE_30DAY)
- `ca381cc` - Fix dna-nodus TTL - register custom ValueTypes
- `e1c1d07` - Fix dna-nodus persistence - enable maintain_storage

---

**Last Updated:** 2025-11-24
**Status:** Production-ready with 7/30/365-day ValueTypes
