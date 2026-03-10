# DNAC Testing Documentation

**Last Updated:** 2026-03-02 | **Version:** v0.10.2

---

## Test Suite Overview

### Gap Fixes Test (`test_gaps.c`)

Location: `dnac/tests/test_gaps.c`

17 unit tests validating v0.6.0 security fixes:

| Test Group | Coverage |
|------------|----------|
| Gaps 1-6 | BFT message signing with real Dilithium5 signatures |
| Gaps 8-9 | Integer overflow protection in amount calculations |
| Gap 12 | Public key validation (correct size, format) |
| Gaps 23-24 | Replay prevention via nonce and timestamp |
| Gap 25 | Memo support validation (up to 255 bytes) |

```bash
cd /opt/dna/dnac/build
ASAN_OPTIONS=detect_leaks=0 ./test_gaps
```

### Remote Test (`test_remote.c`)

Location: `dnac/tests/test_remote.c`

Cross-machine send/receive testing for validating real-world transaction flow.

### End-to-End Test (`test_real.c`)

Location: `dnac/tests/test_real.c`

This is the primary integration test that validates the complete transaction flow using the real BFT witness infrastructure.

#### Test Steps

| Step | Name | Description | Validates |
|------|------|-------------|-----------|
| 1 | MINT | Create 10000 test coins via mint transaction | Mint TX creation, witness authorization, broadcast |
| 2 | VERIFY MINT | Check wallet balance after mint | UTXO storage, balance calculation |
| 3 | SEND | Send 3000 coins (to self for testing) | TX building, fee calculation, witness consensus |
| 4 | VERIFY SEND | Check balance after send | UTXO update, change handling |
| 5 | DOUBLE-SPEND | Attempt to replay the same transaction | Nullifier persistence, double-spend rejection |
| 6 | RECEIVE | Verify UTXOs in wallet | UTXO enumeration, wallet state |

#### Running Tests

```bash
cd /opt/dna/dnac/build

# Clean run (clear databases first)
rm -f ~/.dna/dnac_wallet.db
# Also clear witness DBs on all nodes (see below)

# Run test
ASAN_OPTIONS=detect_leaks=0 ./test_real
```

#### Expected Output

```
╔═══════════════════════════════════════════════════════════════╗
║                    ALL TESTS PASSED                          ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## BFT Witness Infrastructure

### Deployed Nodes

| Node | Address | Role | Service |
|------|---------|------|---------|
| chat1 | 192.168.0.195:4200 | Witness 0 | `systemctl status dnac-witness` |
| treasury | 192.168.0.196:4200 | Witness 1 | `systemctl status dnac-witness` |
| cpunkroot2 | 192.168.0.199:4200 | Witness 2 | `systemctl status dnac-witness` |

### Leader Election

Leader rotates based on epoch and view:
```
leader_index = (epoch + view) % n_witnesses
epoch = time(NULL) / 3600  // Changes every hour
```

### Service Management

```bash
# Check status
ssh nocdem@192.168.0.195 "systemctl status dnac-witness"

# View logs
ssh nocdem@192.168.0.195 "journalctl -u dnac-witness -f"

# Restart service
ssh nocdem@192.168.0.195 "sudo systemctl restart dnac-witness"

# Clear nullifier DB (for fresh test)
ssh nocdem@192.168.0.195 "sudo systemctl stop dnac-witness && rm -f ~/.dna/nullifiers.db && sudo systemctl start dnac-witness"
```

### Clearing All Databases (Fresh Test)

```bash
# Stop, clear, restart all witnesses
for ip in 195 196 199; do
  ssh nocdem@192.168.0.$ip "sudo systemctl stop dnac-witness && rm -f ~/.dna/nullifiers.db && sudo systemctl start dnac-witness"
done

# Clear local wallet
rm -f ~/.dna/dnac_wallet.db

# Wait for mesh connection
sleep 5
```

---

### Nodus Witness Verify Tests (`test_witness_verify`)

Location: `nodus/tests/test_witness_verify.c`

9 test cases validating BFT PREVOTE transaction verification (run via `cd nodus/build && ctest`):

| Test | Coverage |
|------|----------|
| test_valid_spend | Valid SPEND with correct owner fingerprint |
| test_insufficient_balance | Reject spend exceeding UTXO amount |
| test_fee_too_low | Reject spend with insufficient fee |
| test_double_spend | Reject already-spent nullifier |
| test_invalid_genesis_supply | Reject genesis with mismatched supply |
| test_valid_genesis | Valid genesis transaction |
| test_unknown_tx_type | Reject unknown transaction types |
| test_null_params | Handle NULL parameter inputs |
| test_empty_tx | Handle empty transaction data |

Tests updated in v0.10.2 to use computed sender fingerprints (via `nodus_fingerprint_hex()`) as UTXO owners, validating the new UTXO ownership check (CRITICAL-4 fix).

## What Has Been Implemented (v0.10.2)

### BFT Consensus

- [x] PBFT-like consensus protocol (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- [x] Leader election: `(epoch + view) % n_witnesses`
- [x] Quorum requirement: 2 for 3 witnesses
- [x] TCP mesh networking between witnesses
- [x] Request forwarding (non-leader → leader)
- [x] Systemd service deployment
- [x] BFT message signing with Dilithium5 (v0.6.0)
- [x] BFT-signed epoch roots (v0.7.1)

### Transaction Flow

- [x] GENESIS transaction with 3-of-3 unanimous authorization (v0.5.0)
- [x] SPEND transaction with fee outputs
- [x] UTXO selection and change handling
- [x] Nullifier-based double-spend prevention
- [x] Multi-input double-spend fix (v0.4.0)
- [x] DHT-based payment delivery
- [x] Memo support up to 255 bytes (v0.6.0)
- [x] Replay prevention via nonce/timestamp (v0.6.0)

### Witness Infrastructure

- [x] 3-node BFT cluster deployment
- [x] Auto-start on boot (systemd)
- [x] Auto-restart on crash
- [x] Peer reconnection logic
- [x] Nullifier database persistence
- [x] Merkle tree for transaction proofs (v0.7.0)
- [x] Ledger confirmation tracking (v0.7.0)

### Cryptography

- [x] Dilithium5 signatures (post-quantum)
- [x] SHA3-512 for nullifiers and tx hashes
- [x] Fingerprint derivation from public keys
- [x] Integer overflow protection (v0.6.0)
- [x] Public key validation (v0.6.0)

### P0 Security Audit Fixes (v0.10.2)

- [x] UTXO ownership verification — sender fingerprint vs UTXO owner (CRITICAL-4)
- [x] Nullifier fail-closed — DB errors return true/spent (HIGH-10)
- [x] Chain ID validation — 10 BFT handlers check chain_id (CRITICAL-2)
- [x] Secure nonce generation — abort() on RNG failure (CRITICAL-3)
- [x] Overflow protection — safe_add_u64 for genesis supply and balance (HIGH-3, HIGH-8)
- [x] COMMIT signature verification — Dilithium5 sig check on COMMIT messages (CRITICAL-1)

---

## Future Tests TODO

### Unit Tests

- [ ] BFT message serialization/deserialization
- [ ] Leader calculation edge cases (epoch rollover, view changes)
- [ ] Quorum counting logic
- [ ] Nullifier hash computation

### Integration Tests

- [ ] Leader failure → view change → recovery
- [ ] Witness crash during consensus → restart → continue
- [ ] Network partition simulation
- [ ] Concurrent transaction handling
- [ ] Large transaction (many inputs/outputs)

### Stress Tests

- [ ] High transaction volume (100+ TPS)
- [ ] Long-running stability test (24h+)
- [ ] Memory leak detection under load
- [ ] Disk usage growth monitoring

### Security Tests

- [ ] Double-spend attack variations
- [ ] Replay attack across epochs
- [ ] Invalid signature rejection
- [ ] Malformed message handling
- [ ] Byzantine witness behavior simulation

### Edge Cases

- [ ] Zero-amount output handling
- [ ] Maximum UTXO count per wallet
- [ ] Transaction size limits
- [ ] Epoch boundary transitions
- [ ] Witness roster changes (add/remove)

### Performance Benchmarks

- [ ] Transaction latency measurement
- [ ] Consensus round timing
- [ ] DHT lookup latency
- [ ] Signature verification throughput

---

## Test Environment Requirements

### Local Machine

- DNA Messenger identity created (`dna-cli create <name>`)
- libdna built at `/opt/dna/messenger/build`
- DNAC built at `/opt/dna/dnac/build`

### Witness Nodes

- 3 machines with SSH access
- `dnac-witness` binary deployed to `~/dnac-witness`
- `roster.txt` with all 3 addresses
- systemd service installed and enabled

### Network

- All nodes can reach each other on port 4200/TCP
- Nodus DHT cluster accessible (OpenDHT has been removed)

---

## Troubleshooting

### Test fails with "Witness collection failed" (-11)

1. Check witnesses are running: `systemctl is-active dnac-witness`
2. Check mesh connectivity in logs: `journalctl -u dnac-witness | grep -i peer`
3. Verify TCP port 4200 is open

### Test fails with "Double spend" (-9)

The nullifier from a previous test run still exists. Clear all databases:
```bash
for ip in 195 196 199; do
  ssh nocdem@192.168.0.$ip "sudo systemctl stop dnac-witness && rm -f ~/.dna/nullifiers.db && sudo systemctl start dnac-witness"
done
rm -f ~/.dna/dnac_wallet.db
```

### Witnesses not connecting to each other

1. Check roster.txt is identical on all nodes
2. Verify DNS/IP resolution
3. Check firewall rules for port 4200
4. Wait 10-15 seconds for reconnect thread

### Service fails to start

Check logs: `journalctl -u dnac-witness -n 50`

Common issues:
- Missing roster.txt
- Invalid address format
- Port already in use
- Missing ~/.dna directory
