# Witness Pubkey Registry — DHT-based Node Discovery

**Status:** APPROVED
**Date:** 2026-03-14
**Prerequisite:** Dynamic witness roster (implemented, Nodus v0.9.0)

---

## Problem

1. **Witness roster doesn't fully converge** — some nodes see 2-3 witnesses instead of 6. The w_ident exchange over TCP 4002 is unreliable (duplicate connections, timing issues).
2. **Pubkey not in routing table** — adding pubkey to `nodus_peer_t` caused stack overflow (2.5KB Dilithium5 key × 4096 entries = 10MB stack allocation in `nodus_presence_tick`). Reverted.
3. **No pubkey source for witness verification** — BFT signature verification needs pubkey, currently only available via w_ident exchange.

## Solution

Every nodus server publishes its identity to a well-known DHT key. Witness module reads all entries to build the roster. No wire protocol changes needed.

```
DHT Key:    SHA3-512("nodus:pk")     — deterministic, every node computes the same key
Value:      CBOR { "id": node_id, "pk": pubkey, "ip": external_ip, "port": peer_port }
Type:       EPHEMERAL
TTL:        600 seconds (10 minutes)
value_id:   0 (one entry per owner)
seq:        unix timestamp (newer wins)
Refresh:    Every 60s (epoch tick)
```

Dead/offline nodes expire after 10 minutes. Key-lost nodes same.

DHT storage PRIMARY KEY is `(key_hash, owner_fp, value_id)` — each node's entry is distinct by `owner_fp`. `nodus_storage_get_all()` returns all entries for a key.

---

## Tasks

### Task 1: Add pubkey publish function to nodus_server

**Files:**
- Modify: `nodus/src/server/nodus_server.c`

**Step 1: Add `nodus_server_publish_identity()` static function**

After the `ch_dht_put_signed()` function (~line 1716), add:

```c
#define NODUS_PK_REGISTRY_TTL  600   /* 10 minutes */

static const char NODUS_PK_REGISTRY_KEY[] = "nodus:pk";

/**
 * Publish this server's identity (node_id + pubkey + address) to DHT.
 * Called on startup and every epoch tick (60s) to refresh TTL.
 */
static int nodus_server_publish_identity(nodus_server_t *srv) {
    /* Derive DHT key: SHA3-512("nodus:pk") */
    nodus_key_t key;
    nodus_hash((const uint8_t *)NODUS_PK_REGISTRY_KEY,
               sizeof(NODUS_PK_REGISTRY_KEY) - 1, &key);

    /* Encode payload: CBOR { "id": node_id, "pk": pubkey, "ip": ip, "port": port } */
    uint8_t payload[4096];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, payload, sizeof(payload));
    cbor_encode_map(&enc, 4);

    cbor_encode_cstr(&enc, "id");
    cbor_encode_bstr(&enc, srv->identity.node_id.bytes, NODUS_KEY_BYTES);

    cbor_encode_cstr(&enc, "pk");
    cbor_encode_bstr(&enc, srv->identity.pk.bytes, NODUS_PK_BYTES);

    cbor_encode_cstr(&enc, "ip");
    const char *ip = srv->config.external_ip[0]
                   ? srv->config.external_ip
                   : srv->config.bind_ip;
    cbor_encode_cstr(&enc, ip);

    cbor_encode_cstr(&enc, "port");
    cbor_encode_uint(&enc, srv->config.peer_port);

    size_t payload_len = cbor_encoder_len(&enc);
    if (payload_len == 0) return -1;

    /* Create DHT value */
    nodus_value_t *val = NULL;
    int rc = nodus_value_create(&key, payload, payload_len,
                                 NODUS_VALUE_EPHEMERAL,
                                 NODUS_PK_REGISTRY_TTL,
                                 0, (uint64_t)time(NULL),
                                 &srv->identity.pk, &val);
    if (rc != 0 || !val) return -1;

    rc = nodus_value_sign(val, &srv->identity.sk);
    if (rc != 0) { nodus_value_free(val); return -1; }

    rc = nodus_storage_put(&srv->storage, val);
    if (rc != 0) { nodus_value_free(val); return -1; }

    /* Replicate to K-closest peers */
    nodus_server_replicate_value(srv, val);
    nodus_value_free(val);
    return 0;
}
```

**Step 2: Call from server init**

In `nodus_server_init()`, after witness init (~line 2025), add:

```c
    /* Publish identity to DHT for witness discovery */
    nodus_server_publish_identity(srv);
```

**Step 3: Call from server tick (every 60s)**

In `nodus_server_run()` tick section, add identity refresh. Find where `nodus_cluster_tick` is called and add after it:

```c
    /* Refresh identity in DHT (every 60s, matches witness epoch) */
    {
        static uint64_t last_pk_publish = 0;
        uint64_t now = nodus_time_now();
        if (now - last_pk_publish >= 60) {
            last_pk_publish = now;
            nodus_server_publish_identity(srv);
        }
    }
```

**Step 4: Build — should compile cleanly**

Includes needed: `protocol/nodus_cbor.h` (for cbor_encoder), `crypto/nodus_sign.h` (for nodus_hash). Check if already included.

---

### Task 2: Add DHT roster lookup to witness module

**Files:**
- Modify: `nodus/src/witness/nodus_witness_peer.c`
- Modify: `nodus/src/witness/nodus_witness_peer.h`

**Step 1: Add `nodus_witness_rebuild_roster_from_dht()` function**

```c
/**
 * Build roster from DHT pubkey registry.
 * Reads all entries from "nodus:pk" key, decodes CBOR payloads,
 * populates roster with node_id + pubkey + address.
 *
 * Returns number of witnesses in roster, or -1 on error.
 */
int nodus_witness_rebuild_roster_from_dht(nodus_witness_t *w,
                                           nodus_witness_roster_t *out);
```

Implementation:
1. Compute `SHA3-512("nodus:pk")` → key
2. `nodus_storage_get_all(&w->server->storage, &key, &vals, &count)`
3. For each value: verify signature, decode CBOR payload, extract id/pk/ip/port
4. Add to roster (skip self, skip expired, dedup by witness_id)
5. Sort by witness_id for deterministic ordering
6. Free values

**Step 2: Update `nodus_witness_rebuild_roster_from_peers()` to merge DHT data**

The existing function builds from `w->peers[]` (w_ident exchange). Modify to:
1. First call `rebuild_roster_from_dht()` to get DHT-discovered witnesses
2. Then add any w_ident peers not already in roster (fallback)
3. This way DHT is primary, w_ident is supplementary

OR simpler: replace `rebuild_roster_from_peers()` entirely with `rebuild_roster_from_dht()`. The DHT has everything: node_id, pubkey, address. No need for w_ident anymore (though keep w_ident for backward compat during transition).

**Recommended approach:** Merge both sources. DHT is authoritative (has pubkey + verified signature), w_ident peers fill gaps.

---

### Task 3: Verify full convergence

**Step 1: Build and run tests locally**
```bash
cd /opt/dna/nodus/build && cmake .. && make -j$(nproc) && ctest --output-on-failure
```

**Step 2: Deploy to all 6 servers**
```bash
for ip in 154.38.182.161 164.68.105.227 164.68.116.180 161.97.85.25 156.67.24.125 156.67.25.251; do
    ssh root@$ip "git -C /opt/dna pull && systemctl stop nodus && make -C /opt/dna/nodus/build -j4 && cp /opt/dna/nodus/build/nodus-server /usr/local/bin/nodus-server && systemctl start nodus"
done
```

**Step 3: Wait 2 minutes (2 epoch ticks) and verify**

Check that ALL 6 nodes show 6 witnesses with quorum:
```bash
for ip in ...; do
    ssh root@$ip "journalctl -u nodus --no-pager -n 50 | grep 'epoch roster swap' | tail -1"
done
```

Expected: `epoch roster swap: 6 witnesses, quorum=3` on ALL nodes.

**Step 4: Kill one node, verify roster shrinks**
```bash
ssh root@154.38.182.161 "systemctl stop nodus"
# Wait 10 minutes (TTL expiry)
# Check remaining 5 nodes — should show 5 witnesses
```

**Step 5: Restart killed node, verify it rejoins**
```bash
ssh root@154.38.182.161 "systemctl start nodus"
# Wait 2 minutes
# All 6 should show 6 witnesses again
```

---

### Task 4: Version bump + commit

**Step 1: Bump nodus PATCH version** (0.9.0 → 0.9.1)

**Step 2: Commit**
```bash
git commit -m "feat(witness): DHT-based pubkey registry for roster discovery (Nodus v0.9.1) [BUILD]"
```

**Step 3: Push + deploy + verify (same as Task 3)**

---

## Notes

- w_ident exchange is kept as fallback — nodes that haven't published to DHT yet can still be discovered via TCP 4002
- The `nodus:pk` key is the same on all nodes (deterministic hash) — any node can read it
- Signature verification on GET ensures only legitimate nodes are in the roster
- 10 minute TTL + 60s refresh = ~10 refreshes per TTL period (resilient to missed PUTs)
- This replaces the need for pubkey in `nodus_peer_t` (which caused stack overflow)
