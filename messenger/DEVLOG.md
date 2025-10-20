# DNA Messenger Development Log

## 2025-10-20 - Technical Debt: Wallet/RPC Refactoring Needed

### Issue: Wallet Functionality in Core Library

**Status:** ⚠️ Technical debt identified - needs refactoring

**Problem:**
The wallet/RPC functionality (`cellframe_rpc.c`, `cellframe_addr.c`, `wallet.c`, `base58.c`) is currently integrated into the core DNA Messenger library and GUI. This creates several issues:

1. **Dependency bloat:** Core library now requires libcurl for HTTP calls
2. **Architecture violation:** Wallet features are not core messaging functionality
3. **Portability issues:** Cellframe-specific code mixed with protocol-agnostic code
4. **Build complexity:** All builds now require curl, even if wallet features aren't needed

**Current Implementation:**
- `cellframe_rpc.c` uses libcurl for HTTP RPC calls to Cellframe blockchain
- Used by both CLI and GUI (shared C library)
- Added to `gui/CMakeLists.txt` as required dependency
- Forces all platforms (Linux, Windows MXE) to include curl

**Proposed Solution:**

1. **Move wallet to separate module:**
   - Create `wallet/` directory with wallet-specific code
   - Make wallet an optional component (`-DBUILD_WALLET=ON`)
   - Keep core library focused on messaging

2. **Refactor networking:**
   - **For GUI:** Use Qt networking (QNetworkAccessManager) instead of curl
   - **For CLI:** Either keep curl for CLI wallet features, or make wallet GUI-only
   - Remove curl dependency from core library

3. **Architecture:**
   ```
   dna-messenger/
   ├── core/           # Core messaging (no wallet, no curl)
   ├── gui/            # Qt GUI (uses Qt networking for wallet)
   ├── cli/            # CLI interface
   └── wallet/         # Optional wallet module
   ```

**Temporary Fix:**
- Added curl to all build configurations (commit 2edc3b7)
- CI now installs libcurl4-openssl-dev (Linux) and mxe curl (Windows)
- Keeps builds working until proper refactoring is done

**Action Items:**
- [ ] Discuss architecture with team
- [ ] Plan wallet module separation
- [ ] Refactor RPC calls to use Qt networking in GUI
- [ ] Make wallet an optional build component
- [ ] Remove curl from core library dependencies

**Architectural Principle:**

The DNA Messenger core library should be **lean and mean** - focused exclusively on secure messaging functionality, similar to how Telegram's core does one thing well. The library should provide:

✅ **Core Messaging (Required):**
- End-to-end encryption (Kyber512 + Dilithium3)
- Message send/receive
- Multi-recipient encryption
- Contact management
- Message storage interface
- Group messaging

❌ **Not Core (Should be Optional):**
- Wallet functionality
- Blockchain RPC calls
- Payment processing
- Token management
- Any external service integrations

**Philosophy:** Keep the core library minimal and focused. Additional features (wallet, payments, etc.) should be **optional modules** that applications can choose to include. This ensures:
- Minimal dependencies for core functionality
- Easy to audit and maintain
- Portable across platforms
- Fast and lightweight
- Clear separation of concerns

Think of it like building blocks: The core is the foundation (messaging only), and everything else is an optional add-on that sits on top.

---

## 2025-10-14 - Phase 3: CLI Messenger Implementation

### Message Decryption Feature Complete

**Status:** ✅ Implemented and tested

**Changes:**

#### 1. Core Decryption API (`dna_api.c` / `dna_api.h`)

Added `dna_decrypt_message_raw()` function for PostgreSQL integration:
- Parses ciphertext format: [header | recipient_entries | nonce | ciphertext | tag | signature]
- Attempts Kyber512 decapsulation for each recipient entry
- Unwraps DEK using AES key wrap
- Decrypts message with AES-256-GCM
- Verifies Dilithium3 signature
- Extracts sender's public key from signature for verification

Updated `dna_encrypt_message_raw()`:
- Added `sender_sign_pubkey` parameter (1952 bytes)
- Sender's public key now loaded from keyserver instead of extracting from private key
- Ensures consistent public key used across all operations

#### 2. Messenger Implementation (`messenger.c`)

**Critical Bug Fix - Dilithium3 Key Size:**
- Changed all Dilithium3 secret key buffers from 4016 to **4032 bytes** (correct size)
- This was causing signature verification failures
- All keys regenerated after fix

**Message Reading (`messenger_read_message()`):**
- Fetches encrypted message from PostgreSQL by ID
- Loads recipient's Kyber512 private key from filesystem (`~/.dna/<identity>-kyber512.pqkey`)
- Decrypts message using `dna_decrypt_message_raw()`
- **Sender verification:** Compares extracted public key from message with keyserver
- Detects spoofing attempts by checking key mismatch
- Displays decrypted plaintext with verification status

**Message Sending (Updated):**
- Now loads sender's public signing key from PostgreSQL keyserver
- Passes sender's public key to `dna_encrypt_message_raw()`
- Ensures signature contains correct public key for recipient verification

#### 3. CLI Interface (`messenger/main.c`)

Added menu option "3. Read message":
- Prompts user for message ID
- Calls `messenger_read_message()` to decrypt and display
- Shows signature verification and sender identity confirmation

### Testing Results

**Test scenario:**
1. Created fresh identities: alice, bob (with correct 4032-byte Dilithium3 keys)
2. Sent message: bob → alice ("Hello Alice, this message should decrypt correctly!")
3. Successfully decrypted as alice
4. Verified sender identity against keyserver
5. Displayed plaintext correctly

**Ciphertext analysis:**
- Message size: 52 bytes plaintext → 6174 bytes ciphertext
- Overhead: ~6122 bytes for post-quantum crypto
- Large overhead due to Dilithium3 signatures (3309 bytes)

### Database Schema

**Current tables (PostgreSQL):**

```sql
-- Public key storage
CREATE TABLE keyserver (
    id SERIAL PRIMARY KEY,
    identity TEXT UNIQUE NOT NULL,
    signing_pubkey BYTEA NOT NULL,           -- Dilithium3 (1952 bytes)
    signing_pubkey_len INTEGER NOT NULL,
    encryption_pubkey BYTEA NOT NULL,        -- Kyber512 (800 bytes)
    encryption_pubkey_len INTEGER NOT NULL,
    fingerprint TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Message storage (encrypted blobs only)
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    ciphertext BYTEA NOT NULL,               -- Full encrypted message
    ciphertext_len INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Future messenger features (database-agnostic):**

```sql
-- Session management
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    identity TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP,
    status TEXT                               -- 'active', 'away', 'offline'
);

-- Message metadata (local only, not shared)
CREATE TABLE message_metadata (
    message_id INTEGER PRIMARY KEY,
    conversation_id TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP,
    local_timestamp TIMESTAMP,
    flags TEXT                                -- 'starred', 'archived', etc.
);

-- Conversations (local grouping)
CREATE TABLE conversations (
    conversation_id TEXT PRIMARY KEY,
    participants TEXT,                        -- JSON array or comma-separated
    last_message_id INTEGER,
    last_message_at TIMESTAMP,
    unread_count INTEGER DEFAULT 0
);

-- Delivery receipts (optional, privacy trade-off)
CREATE TABLE delivery_receipts (
    message_id INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    status TEXT,                              -- 'sent', 'delivered', 'read'
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Contact list (local only)
CREATE TABLE contacts (
    identity TEXT PRIMARY KEY,
    display_name TEXT,
    notes TEXT,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP
);
```

### Configuration

**Default server:** `localhost` (for development)
**Production server:** `ai.cpunk.io:5432` (mentioned in README)

Configuration file: `~/.dna/config`
```
server_host=localhost           # or ai.cpunk.io for production
server_port=5432
database=dna_messenger
username=dna
password=dna_password
```

### Security Model

**End-to-End Encryption:**
- PostgreSQL stores only encrypted ciphertext blobs
- No plaintext metadata stored on server
- Recipient verification prevents spoofing attacks
- Post-quantum algorithms (Kyber512, Dilithium3) resist quantum attacks

**Key Storage:**
- **Private keys:** `~/.dna/<identity>-{kyber512,dilithium}.pqkey` (local filesystem)
- **Public keys:** PostgreSQL `keyserver` table (shared globally)

**Threat Model:**
- ✅ Protected: Network eavesdropping, MitM, quantum attacks, message tampering
- ✅ Verified: Sender identity via Dilithium3 signatures + keyserver comparison
- ❌ Not protected: Compromised devices, physical access, social engineering

### Key Algorithms

- **Key Encapsulation:** Kyber512 (public=800, secret=1632 bytes)
- **Digital Signatures:** Dilithium3 (public=1952, secret=4032 bytes)
- **Symmetric Encryption:** AES-256-GCM (authenticated encryption)
- **Key Derivation:** AES Key Wrap (RFC 3394) for DEK wrapping

### Next Steps

**Completed in Phase 3:**
- ✅ Message encryption (multi-recipient support)
- ✅ Message decryption with sender verification
- ✅ CLI interface for sending/reading messages
- ✅ PostgreSQL integration for message queue
- ✅ Keyserver for public key distribution

**Future Phases:**
- **Phase 4:** Network layer (WebSocket transport, P2P discovery)
- **Phase 5:** Desktop GUI (Qt application)
- **Phase 6:** Mobile apps (Flutter cross-platform)
- **Phase 7:** Advanced features (forward secrecy, multi-device sync, group messaging)

---

**Developer:** nocdem
**Project:** DNA Messenger v0.1.0-alpha
**Repository:** /opt/dna-messenger
**Branch:** main
