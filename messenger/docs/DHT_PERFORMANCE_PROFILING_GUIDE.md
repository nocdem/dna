# DHT Performance Profiling Guide

## Phase 1: Timing Instrumentation ✅ COMPLETED

Comprehensive timing instrumentation has been added to identify DHT performance bottlenecks.

### Changes Made

#### 1. DHT Core Layer (`dht/core/dht_context.cpp`)

**Function:** `dht_get()` - Line 801-866

**Added Timing:**
- Network latency measurement (future.get() blocking time)
- Memory copy overhead
- Total operation time

**Output Format:**
```
[DHT] GET successful: 1234 bytes (network: 5982ms, copy: 1ms, total: 5983ms)
```

#### 2. Offline Queue Retrieval (`dht/shared/dht_offline_queue.c`)

**Function:** `dht_retrieve_queued_messages_from_contacts()` - Line 476-599

**Added Timing:**
- Per-contact DHT GET time
- Per-contact deserialization time
- Total function execution time
- Average time per contact

**Output Format:**
```
[DHT Queue] [1/100] Checking sender abcd1234... outbox
[DHT Queue]   ✓ Found outbox (4567 bytes, dht_get took 6123 ms)
[DHT Queue]   Deserialized 20 message(s) from this sender (took 45 ms)
...
[DHT Queue] ✓ Retrieved 20 valid messages from 1 contacts (total: 6200 ms, avg per contact: 6200 ms)
```

#### 3. Message Queueing (`dht/shared/dht_offline_queue.c`)

**Function:** `dht_queue_message()` - Line 322-500

**Added Timing:**
- DHT GET_ALL time (fetching existing queue)
- Deserialization time
- Serialization time
- DHT PUT_SIGNED time (storing updated queue)
- Total queueing time

**Output Format:**
```
[DHT Queue] Selected version 1/1 (4567 bytes, get took 5234 ms)
[DHT Queue] Existing queue has 19 messages (deserialize took 12 ms)
[DHT Queue] Serialized queue: 20 messages, 4892 bytes (took 15 ms)
[DHT Queue] ✓ Message queued successfully (total: 5890 ms, get: 5234 ms, put: 629 ms)
```

---

## Phase 2: Profiling the 6-Second Bottleneck 🔄 IN PROGRESS

### Objective

Identify why a single DHT GET operation for 20 messages takes 6 seconds.

### Test Procedure

#### Step 1: Run the Application with Profiling

```bash
cd /home/mika/dev/dna-messenger
./build/dna-messenger 2>&1 | tee dht_profile_$(date +%Y%m%d_%H%M%S).log
```

#### Step 2: Trigger Offline Message Fetch

1. **Login to your identity**
2. **Wait for automatic offline message check** (runs 2 minutes after login)
3. **OR manually trigger check** (if UI option exists)

#### Step 3: Analyze the Logs

Look for these patterns in the log file:

**Example: Identify slow DHT GET:**
```
[DHT] GET: a1b2c3d4e5f6...
[DHT] GET successful: 4567 bytes (network: 5982ms, copy: 1ms, total: 5983ms)
                                            ^^^^^^^^ <- This is the problem!
```

**Questions to answer:**
1. How much time is spent in **network** vs **copy**?
   - If network > 5000ms: DHT network issue (slow bootstrap nodes, routing)
   - If copy > 100ms: Memory allocation issue (unlikely with small payloads)

2. Does the time vary by contact?
   - Some contacts fast, others slow: Contact-specific DHT key distribution
   - All contacts slow: Global DHT performance issue

3. How much time is deserialization taking?
   - Should be < 50ms for 20 messages
   - If > 500ms: Binary format inefficiency

#### Step 4: Bootstrap Node Latency Test

Test connectivity to each bootstrap node:

```bash
# Test US bootstrap node
ping -c 10 154.38.182.161

# Test EU bootstrap nodes
ping -c 10 164.68.105.227
ping -c 10 164.68.116.180
```

**Expected:** < 100ms average ping
**If higher:** Network path to bootstrap nodes is slow

---

## Expected Bottleneck Scenarios

### Scenario A: DHT Network Latency (MOST LIKELY)

**Symptoms:**
- `network: 5000-7000ms` in DHT GET logs
- Consistent across all contacts
- High ping to bootstrap nodes (> 200ms)

**Root Cause:**
- Multiple DHT hops to find value
- Slow bootstrap nodes
- DHT routing table not optimized

**Solution:**
- Add geographically closer bootstrap nodes
- Implement DHT query timeout (1-2s max)
- Parallel queries for multiple contacts

---

### Scenario B: Large Payload Size

**Symptoms:**
- `copy: 500+ms` in DHT GET logs
- Serialized queue > 100KB

**Root Cause:**
- Too many messages accumulated in sender's outbox
- Inefficient binary serialization

**Solution:**
- Implement outbox size limits (max 50 messages)
- Compress serialized data (zlib/zstd)
- Split large outboxes into chunks

---

### Scenario C: DHT Query Timeout/Retry

**Symptoms:**
- Network time varies wildly (2s-10s)
- Some queries fail then retry

**Root Cause:**
- OpenDHT default timeout too long (5-10s)
- Automatic retry logic adding delay

**Solution:**
- Set explicit 1-second timeout
- Disable automatic retries (fail fast)

---

### Scenario D: Synchronous Blocking

**Symptoms:**
- GUI freezes during message check
- All 100 contacts queried sequentially

**Root Cause:**
- `future.get()` blocks thread
- N+1 query problem (100 sequential queries)

**Solution:**
- Use async DHT API instead of blocking
- Parallelize queries (query all contacts concurrently)

---

## Data Collection Checklist

Run the application and collect this data:

- [ ] DHT GET timing for each contact (from logs)
- [ ] Deserialize timing for each contact
- [ ] Total fetch time for all contacts
- [ ] Number of contacts queried
- [ ] Number of messages retrieved
- [ ] Average message size (bytes)
- [ ] Bootstrap node ping latency
- [ ] Network bandwidth during fetch (optional: `iftop`)

---

## Next Steps After Profiling

Once we identify the bottleneck:

### If DHT Network Latency:
→ **Task 4: Parallelize contact outbox queries** (10-100× speedup)

### If Large Payloads:
→ **Task 11: Implement smart caching layer** (skip empty outboxes)

### If Timeout Issues:
→ **Task 9: Optimize OpenDHT configuration settings** (reduce timeout)

### If All of the Above:
→ **Task 5-6: Migrate to Recipient Inbox + Push Notifications** (architectural fix)

---

## Questions for User

After running the profiling, please share:

1. **Log file excerpt** showing DHT GET timing for 2-3 contacts
2. **Total time** to fetch messages from all contacts
3. **Bootstrap node ping times**
4. **Any patterns** observed (some contacts fast, others slow?)

This will guide the implementation of the optimal fix.
