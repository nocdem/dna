# DHT Storage Double-Hash Bug Fix & Migration Guide

**Date:** 2025-11-12
**Severity:** CRITICAL
**Affected:** Bootstrap nodes with persistent storage
**Status:** ✅ FIXED (code patched, migration prepared)

---

## The Bug

### What Happened
Bootstrap nodes stored **derived InfoHash** (20 bytes) instead of **original key** (64 bytes) in SQLite database:

```
STORAGE:    key_hash = InfoHash(SHA3-512("alice:outbox:bob"))  ❌ WRONG
            key_hash = "a3f2..." (40-char hex)

REPUBLISH:  InfoHash("a3f2...")  ❌ DOUBLE HASH
            → Completely different DHT key
            → Data becomes unretrievable
```

### Impact
- ❌ After bootstrap restart: All identity keys, DNA names, contact lists would republish to **WRONG DHT KEYS**
- ❌ Result: All users unable to message new contacts (keys not found)
- ❌ Result: All DNA names break (alice/bob/etc stop resolving)
- ✅ **NOT AFFECTED YET**: Bootstrap servers haven't restarted since bug introduction

---

## The Fix

### Code Changes (Permanent)
1. **`dht/dht_context.cpp:546-551`** - Store original 64-byte key (not infohash)
2. **`dht/dht_value_storage.cpp:540-554`** - Skip old format on republish (prevent double-hash)

### Migration Strategy (One-Time)
Since servers **haven't restarted yet**, all DHT data is still at correct locations:

1. ✅ **Old permanent data** stays accessible (never expires)
2. ✅ **New data** uses correct key format (no double-hash)
3. ⚠️ **Old database entries** skipped on republish (prevents wrong-key corruption)
4. 📢 **Users re-publish** identities/names to get new format

---

## Migration Steps

### Step 1: Deploy Fixed Code (All Bootstrap Nodes)

```bash
# On each bootstrap node (dna-bootstrap-us-1, eu-1, eu-2):

cd /opt/dna-messenger
git pull origin main  # Get 2025-11-12 fix
cd build
cmake ..
make -j4

# Verify build
ls -lh /opt/dna-messenger/build/dht/persistent_bootstrap
```

### Step 2: Analyze Database (Before Restart)

```bash
# Compile migration tool
cd /opt/dna-messenger
g++ -std=c++17 -o dht/migrate_storage_once dht/migrate_storage_once.cpp -lsqlite3

# Run analysis
./dht/migrate_storage_once ~/.dna/persistence_path.values.db

# Expected output:
# === DHT Storage Migration Tool ===
# Current database state:
#   Key length 40 chars: XX entries [OLD FORMAT - will be skipped]
#   Key length 128 chars: YY entries [NEW FORMAT - will republish correctly]
#
# ✓ No data loss - old entries stay in DHT permanently
```

### Step 3: Restart Bootstrap Nodes (Staggered)

```bash
# Kill old process
pkill -f persistent_bootstrap

# Start new fixed version
cd /opt/dna-messenger/build/dht
nohup ./persistent_bootstrap 4000 ~/.dna/persistence_path.values.db &> /tmp/bootstrap.log &

# Monitor republish (should see "Skipping old-format entry" messages)
tail -f /tmp/bootstrap.log | grep -E "Skipping|Republish"
```

**Stagger restarts:** Wait 5 minutes between nodes to maintain DHT availability.

### Step 4: User Action (Gradual, No Rush)

Users should re-publish their identities/names when convenient:

**Client code (Qt/ImGui GUI):**
```cpp
// Re-publish identity keys to DHT (gets new format)
messenger_publish_identity_to_dht(ctx);

// Or from GUI: Settings → Identity → "Re-publish to DHT"
```

**No deadline** - old permanent data stays accessible indefinitely.

---

## Verification

### Check Republish Worked
```bash
# On bootstrap node after restart:
grep -c "Skipping old-format entry" /tmp/bootstrap.log
# Should match number of old-format entries from Step 2

grep "Republish complete" /tmp/bootstrap.log
# Example: "Republish complete: 15 values" (only new format)
```

### Check DHT Health
```bash
# Test key lookup (should still work)
./dht/quick_lookup alice

# Check bootstrap node is accepting connections
ss -tulnp | grep 4000
```

### Check Database After Restart
```bash
# Count entries by format
sqlite3 ~/.dna/persistence_path.values.db \
  "SELECT LENGTH(key_hash), COUNT(*) FROM dht_values GROUP BY LENGTH(key_hash)"

# Should see:
# 40|XX    <- Old format (not republished, still valid in DHT)
# 128|YY   <- New format (republished correctly)
```

---

## What Gets Fixed Automatically

✅ **New identity registrations** - Use correct key format
✅ **New name registrations** - Use correct key format
✅ **New contact list syncs** - Use correct key format
✅ **Bootstrap restarts** - Skip old entries (prevent corruption)

---

## What Needs User Re-Publish (Optional, No Rush)

⚠️ **Old identity keys** - Still accessible, but should re-publish for new format
⚠️ **Old DNA names** - Still working, but should re-register for new format (costs 0.01 CPUNK)
⚠️ **Old contact lists** - Still syncing, but should re-upload for new format

**How to trigger:**
```cpp
// In client app (Qt or ImGui GUI):
Settings → Identity → "Re-publish Identity to DHT"
Settings → DNA Name → "Re-register Name" (if name exists)
Settings → Contacts → "Sync to DHT" (force upload)
```

---

## Cleanup (After Migration Complete)

After all 3 bootstrap nodes restarted and verified:

```bash
# Delete one-time migration tool (no longer needed)
rm /opt/dna-messenger/dht/migrate_storage_once
rm /opt/dna-messenger/dht/migrate_storage_once.cpp
rm /opt/dna-messenger/dht/MIGRATION_GUIDE.md
```

---

## Rollback (If Needed)

If issues arise after restart:

```bash
# Stop new version
pkill -f persistent_bootstrap

# Restore old binary (if backed up)
cp /opt/dna-messenger/build.backup/dht/persistent_bootstrap \
   /opt/dna-messenger/build/dht/persistent_bootstrap

# Start old version
cd /opt/dna-messenger/build/dht
nohup ./persistent_bootstrap 4000 ~/.dna/persistence_path.values.db &> /tmp/bootstrap.log &
```

**Note:** Old version has the bug, but won't corrupt data if you restart again with new version later.

---

## Summary

| Aspect | Status |
|--------|--------|
| **Bug Severity** | 🔴 CRITICAL (data loss after restart) |
| **Current Impact** | 🟢 NONE (servers not restarted) |
| **Code Fixed** | ✅ YES (2025-11-12) |
| **Migration Needed** | ✅ YES (deploy + restart) |
| **Data Loss Risk** | 🟢 ZERO (smart skip logic) |
| **User Action** | ⚠️ OPTIONAL (re-publish for new format) |
| **Deadline** | 📅 Before next bootstrap restart |

---

## Questions?

- **Will old data disappear?** NO - permanent data stays in DHT indefinitely
- **Do users lose DNA names?** NO - names keep working, just in old format
- **Can we delay migration?** YES - but must happen before bootstrap restart
- **What if we restart without fixing?** ❌ CATASTROPHIC - all identities become unretrievable

**RECOMMENDATION:** Deploy fix at next maintenance window, no emergency restart needed.
