# Debug Log Delivery via Anonymous DHT Inbox

**Date:** 2026-04-05
**Status:** APPROVED
**Component:** New C engine module + Flutter UI + new CLI listener subcommand + systemd service

---

## Overview

Any DNA user (production, tester, or developer) can push a recent debug log to
the developer's workstation ("punk" identity) with a single tap, without
requiring a contact relationship. Logs are hybrid-encrypted to punk's Kyber1024
public key and stored at a well-known DHT key. Punk runs a listener that
decrypts incoming logs and writes them to disk. Sender authenticity is provided
by the Nodus value-signing layer (Dilithium5, per-PUT).

## Problem

`dna_engine_send_message` requires a contact relationship (receiver listens on
contacts' outboxes via `dna_engine_listen_all_contacts`). That model is wrong
for crash/bug reporting from production users: we do not want every user in
punk's contacts DB, nor do we want to auto-approve contact requests from
arbitrary fingerprints.

## Goal

A stateless, one-way, E2E-encrypted, rate-limited "log drop" channel that any
DNA user can write to and that the developer's workstation drains in real
time. Zero new ports. Zero new servers. No contact relationship required.

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Transport | Existing DHT via `nodus_ops_put` / `nodus_ops_listen` | Already E2E (transport-level), NAT-traversed, rate-limited (60 PUT/min/client), quota-enforced (10K values/owner) |
| Routing | Well-known DHT key `SHA3-512("dna-debug-inbox" \|\| punk_fp)` | Any user can compute it; only punk needs the secret to decrypt |
| Multi-writer | Nodus owner-keyed storage — each sender is a distinct `(key, owner)` entry | Confirmed in `nodus_storage.h:189` (`nodus_storage_has_owner`) + `nodus_ops_get_all` API |
| Payload encryption | Hybrid: Kyber1024 KEM + AES-256-GCM | Matches rest of the codebase; post-quantum throughout |
| Sender auth | Inherited from Nodus value signing (Dilithium5) — automatic | Every DHT PUT is signed by sender's identity; receiver sees `owner_fp` from wire |
| Payload content hint | Optional `hint` string in clear (e.g. "alice-phone", "rc-158-android") | Helps dev triage logs before decrypting; never contains secrets |
| TTL | 3600 seconds (1 hour) | Debug logs are consumed quickly; avoids DHT storage accumulation |
| Max payload size | 3,145,728 bytes (3 MB) of log content | DHT value cap is 4 MB; envelope (Kyber ct + nonce + metadata) ≈ 1.6 KB; comfortable headroom |
| Truncation policy | Keep last 3 MB of log | Debug log ring buffer + file rotation — the tail is where the bug shows |
| Log sanitization | Regex scrub on sender side before encryption | Defense in depth against mistakes in E2E or receiver compromise; also protects if dev shares a log externally |
| Receiver | New CLI subcommand `debug inbox listen` (not separate binary) | Reuses existing `dna-connect-cli` identity loading, Nodus init, keystore |
| Receiver output | Files in `/var/log/dna-debug/<owner_fp_short>_<ISO8601>.log` | Easy to `tail`, `grep`, date-sort; no DB needed |
| Spam defense | Nodus native limits (60 PUT/min/client, 10K per owner) + optional per-fp block list on receiver | Server-level rate limit is already enforced for every client |

## Flow

```
┌────────────────────────────────────────────────────────────────┐
│ PHONE (any DNA user — Flutter)                                 │
│                                                                │
│  Settings > Debug Log > [Send to Developer]                    │
│    │                                                           │
│    ├─ 1. raw  = DnaLogger.exportAsString()                     │
│    ├─ 2. safe = LogSanitizer.scrub(raw)                        │
│    ├─ 3. body = safe.takeLast(3 MB)                            │
│    ├─ 4. hint = "${buildMode}-${platform}-${appVersion}"       │
│    └─ 5. FFI → dna_engine_debug_log_send(                      │
│                  engine, punk_fp_const,                        │
│                  body, body_len, hint, cb)                     │
│                                                                │
│        C side (new module dna_engine_debug_log.c):             │
│          a. Fetch/cache punk's Kyber pubkey                    │
│             (existing profile lookup via punk_fp)              │
│          b. (ct, ss) = kyber1024_encapsulate(punk_kyber_pub)   │
│          c. nonce    = random(12)                              │
│          d. ciphertext = AES-256-GCM(ss, nonce,                │
│                            [hint_len][hint][log_len][body])    │
│          e. payload  = [v=1][ct][nonce][ciphertext][gcm_tag]   │
│          f. inbox_key = SHA3-512("dna-debug-inbox" ‖ punk_fp)  │
│          g. nodus_ops_put(inbox_key, payload, ttl=3600)        │
│             (automatically Dilithium-signed by sender)         │
└─────────────────────────────┬──────────────────────────────────┘
                              │
                              ▼
                           Nodus DHT
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│ WORKSTATION — systemd service                                  │
│                                                                │
│  dna-punk-debug-inbox.service                                  │
│  ExecStart=/opt/dna/messenger/build/cli/dna-connect-cli \      │
│            -i punk debug inbox listen                          │
│                                                                │
│  new CLI command (cli_commands.c → cmd_debug_inbox_listen):    │
│    a. key = SHA3-512("dna-debug-inbox" ‖ my_fp)                │
│    b. nodus_ops_listen(key, on_new_value_cb)                   │
│    c. block on SIGINT/SIGTERM                                  │
│                                                                │
│  on_new_value_cb(value_bytes, owner_fp):                       │
│    a. parse [v][ct][nonce][ciphertext][gcm_tag]                │
│    b. ss = kyber1024_decapsulate(my_kyber_sk, ct)              │
│    c. plain = AES-256-GCM_decrypt(ss, nonce, ciphertext, tag)  │
│    d. parse [hint_len][hint][log_len][body]                    │
│    e. write to /var/log/dna-debug/                             │
│         <owner_fp[0..16]>_<ISO8601>.log                        │
│    f. journald: "new debug log from <fp_short> hint=<hint>"    │
└────────────────────────────────────────────────────────────────┘
```

## Wire Format — Inbox Value

Outer (stored in DHT as Nodus value — signed by Nodus with sender Dilithium5):

```
Offset  Size     Field
──────  ────     ─────
0       1        version (0x01)
1       1568     kyber1024_ciphertext
1569    12       aes_gcm_nonce
1581    N        aes_gcm_ciphertext   (N = plaintext_len)
1581+N  16       aes_gcm_tag
──────
Total: 1597 + N bytes
```

Inner (AES-GCM plaintext, after decryption):

```
Offset  Size     Field
──────  ────     ─────
0       2        hint_len (big-endian, 0..128)
2       hint_len hint (UTF-8, no NUL)
2+H     4        log_len (big-endian)
6+H     log_len  log_body (UTF-8 text)
```

Constraints: `hint_len ≤ 128`, `log_len ≤ 3,145,728` (3 MB), total outer ≤ 4 MB.

## Components

### 1. C engine module — `dna_engine_debug_log.c`
**Location:** `messenger/src/api/engine/dna_engine_debug_log.c` (new)
**Header:** `messenger/src/api/engine/dna_engine_internal.h` (add task type)
**Public API:** `messenger/include/dna/dna_engine.h` (add `dna_engine_debug_log_send`)
**New code:** ~180 lines C

Exposes:
```c
dna_request_id_t dna_engine_debug_log_send(
    dna_engine_t *engine,
    const char *receiver_fp,         // punk's Dilithium fingerprint (hex)
    const uint8_t *log_body,         // UTF-8 log bytes
    size_t log_len,                  // ≤ 3 MB
    const char *hint,                // optional, ≤ 128 B, may be NULL
    dna_completion_cb callback,
    void *user_data);
```

Handler flow:
1. Validate: `log_len ≤ 3 MB`, `receiver_fp` parseable
2. Look up `receiver_fp` profile → extract Kyber pubkey
   (uses existing `dna_engine_lookup_profile` infrastructure)
3. Build inner plaintext
4. Kyber1024 encapsulate
5. AES-256-GCM encrypt
6. Build outer payload
7. Compute inbox key: `SHA3-512("dna-debug-inbox" || receiver_fp_raw_bytes)`
8. `nodus_ops_put(key, payload, 3600)` with owner=self
9. Invoke completion callback

### 2. Flutter — "Send to Developer" button + sanitizer
**Files (new/modified):**
- `lib/screens/settings/debug_log_screen.dart` — add button
- `lib/utils/log_sanitizer.dart` — new
- `lib/ffi/dna_bindings.dart` — add FFI binding
- `lib/ffi/dna_engine.dart` — add Dart wrapper
- `lib/l10n/app_en.arb` + `app_tr.arb` — strings

**New code:** ~120 lines Dart

Strings (i18n):
- `debugLogSendToDev` — "Send Debug Log to Developer"
- `debugLogSendConfirm` — "Send last 3 MB of debug log to developer? Secrets are automatically removed."
- `debugLogSendSuccess` — "Log sent"
- `debugLogSendFailed` — "Send failed: {error}"

LogSanitizer rules (pre-encryption, never leaves device unfiltered):

| Pattern | Replacement | Target |
|---------|-------------|--------|
| 12+ consecutive BIP39 words (English+any supported) | `[MNEMONIC REDACTED]` | Recovery phrases |
| Hex strings ≥ 64 chars | `[KEY-${len}B REDACTED]` | Kyber/Dilithium/AES keys, signatures |
| Base64 strings ≥ 88 chars | `[B64-${len} REDACTED]` | Encoded keys/secrets |
| `password[:\s=]+\S+` / `secret[:\s=]+\S+` / `token[:\s=]+\S+` | `<field>=[REDACTED]` | Credentials |

Conservative: prefer false positives. False-positive allowlist deferred to v2.

### 3. CLI listener subcommand — `debug inbox listen`
**Files (new/modified):**
- `messenger/cli/cli_commands.c` — add `cmd_debug_inbox_listen`
- `messenger/cli/cli_commands.h` — declare
- `messenger/cli/main.c` — dispatch `debug` group → `inbox listen`

**New code:** ~220 lines C

Flow:
1. Compute `inbox_key = SHA3-512("dna-debug-inbox" || my_fp_raw)`
2. Register `nodus_ops_listen(inbox_key, on_value_cb)`
3. Block on SIGINT/SIGTERM, print status every 60s

`on_value_cb`:
1. Parse + validate wire format (reject on any error, log sender fp)
2. Kyber decapsulate using engine's loaded Kyber secret key
3. AES-GCM decrypt — on MAC failure, log warning + discard
4. Parse inner (hint + log_body)
5. Make dir `/var/log/dna-debug/` if missing (0700)
6. Write file `<owner_fp[0:16]>_<ISO8601>.log` (0600)
7. Print to stdout: `[DEBUG-LOG] from=<fp_short> hint=<hint> size=<N> file=<path>`

Optional block list (v2): `/etc/dna/debug-inbox-blocklist` — line-separated fingerprints to ignore.

### 4. systemd service
**File:** `/etc/systemd/system/dna-punk-debug-inbox.service` (new, 25 lines)

```ini
[Unit]
Description=DNA Connect — punk debug inbox listener
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nocdem
Group=nocdem
Environment=HOME=/home/nocdem
ExecStart=/opt/dna/messenger/build/cli/dna-connect-cli -i punk debug inbox listen
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
ReadWritePaths=/var/log/dna-debug /home/nocdem/.dna
NoNewPrivileges=true

[Install]
WantedBy=default.target
```

## Error Handling

| Error | Sender behavior | Receiver behavior |
|-------|-----------------|-------------------|
| Log empty | Info SnackBar "Nothing to send" | N/A |
| Log > 3 MB | Auto-truncate, info SnackBar "truncated to last 3 MB" | N/A |
| Punk Kyber pubkey lookup fails | Error SnackBar with reason; cached key used if available | N/A |
| DHT PUT rate-limited by Nodus | Error SnackBar "Too many requests, try again later" | N/A |
| DHT PUT fails (network) | Error SnackBar; no retry in v1 | N/A |
| Malformed payload | Sender: N/A | Log warning, skip |
| AES MAC failure | N/A | Log warning with owner fp, skip (possible attacker) |
| Disk write fails | N/A | Log error, skip (do not crash listener) |
| Sender fp on blocklist | N/A (sender doesn't know) | Silently drop |

## Testing

1. **Unit — LogSanitizer** (`test/utils/log_sanitizer_test.dart`)
   - Mnemonic (12/15/18/24 words), hex keys (64/128/256/512), base64 secrets, `password=X` variants, negative cases (normal prose untouched)
2. **Unit — wire format** (`tests/test_debug_log_wire.c`)
   - round-trip encrypt/decrypt, oversize rejection, truncated payload rejection, tampered ciphertext rejection
3. **Integration — end-to-end**
   - Sender: CLI command that simulates phone (`dna-connect-cli -i alice debug inbox send punk_fp <logfile>`)
   - Receiver: running `debug inbox listen`
   - Assertions: file appears in `/var/log/dna-debug/`, content matches, journald prints
4. **Manual — Flutter on real device**
   - Install, log in, generate some log noise, tap Send, check workstation inbox
5. **Negative — spam**
   - 61 PUTs in 60s from one client → Nodus rejects → SnackBar error
6. **Negative — tampering**
   - Flip bit in stored value → AES MAC fail → listener logs warning, skips

## Security Notes

- **E2E encryption:** Only the holder of punk's Kyber1024 secret key can decrypt. No middlebox (Nodus nodes) sees plaintext.
- **Sender authenticity:** Enforced by Nodus signing layer — every value is Dilithium5-signed by its owner on PUT. Forged senders impossible (would need sender's Dilithium secret).
- **Rate limit / DoS:** Nodus native: 60 PUT/min/client, 10K values/owner. Per-sender block list available as v2.
- **Secret scrubbing:** Primary defense. Mnemonic, Kyber/Dilithium keys, passwords never leave device even in plaintext.
- **Replay:** Not relevant — debug log is idempotent information. Same log arriving twice writes two files, dev reads newest.
- **Forward secrecy:** None (Kyber1024 encapsulation to long-term pubkey). Acceptable — debug logs are low-sensitivity. V2 could add ephemeral Kyber keys.
- **Metadata leak to Nodus operator:** Inbox key is a known hash of punk's fingerprint; anyone observing Nodus storage can see "someone is PUTting to punk's debug-inbox." Size and timing visible. Acceptable — we run Nodus.

## Out of Scope (v1)

- Auto-send on crash (v2)
- Log streaming / tail mode (v2 — would need Nodus Relay TCP 4004)
- Multi-developer destinations (v2 — app could accept a list)
- Block list management UI/CLI (v2)
- Gzip compression before encrypt (v2 — fit more in 3 MB)
- Forward secrecy with ephemeral receiver keys (v2)
- False-positive allowlist for LogSanitizer (v2)

## Success Criteria

1. User taps "Send to Developer" on Flutter → log file appears in `/var/log/dna-debug/` within 30 s (online case)
2. Log is readable plaintext UTF-8, last 3 MB of what was on device
3. `journalctl -u dna-punk-debug-inbox` shows sender fp + hint + file path for each received log
4. No crypto material (mnemonic or hex keys ≥64 chars) present in any delivered file — verified by unit test with synthetic input
5. Sender gets clear success/failure feedback within 5 s online
6. Building: zero new warnings; all new unit tests pass
7. Total new code ≤ 550 lines across C+Dart (measured post-implementation)
