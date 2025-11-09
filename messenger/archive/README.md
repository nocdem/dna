# Archive

This directory contains obsolete components that have been replaced by newer implementations.

**Archived:** 2025-11-08

## Contents

### `keyserver/`
**Status:** Obsolete centralized HTTP REST API keyserver

**Original purpose:**
- HTTP REST API for identity management
- PostgreSQL database backend
- Rate limiting and signature verification

**Replaced by:**
- `dht/dht_keyserver.c/h` - DHT-based decentralized keyserver
- No central server required
- OpenDHT for distributed identity storage
- Forward/reverse mapping (name ↔ fingerprint)

**Archived because:**
- Centralized architecture doesn't align with decentralization goals
- PostgreSQL dependency removed (migrated to SQLite for local storage)
- DHT-based keyserver is fully functional and deployed

---

### `utils/`
**Status:** Disabled utility programs

**Original purpose:**
- `export_pubkey` - Export public key from identity
- `sign_json` - Sign JSON data with Dilithium
- `verify_json` - Verify JSON signatures

**Replaced by:**
- Inline functions in `dht/dht_keyserver.c`
- Direct API calls in messenger code

**Archived because:**
- No longer built (disabled in CMakeLists.txt line 149-150)
- Functionality integrated into core library
- Old compiled binaries were committed to git (cleaned up)

---

### `wallet-gui/`
**Status:** Standalone wallet GUI (superseded)

**Original purpose:**
- Standalone cpunk wallet application
- Send/receive CPUNK, CELL, KEL tokens
- Transaction history

**Replaced by:**
- `gui/WalletDialog.*` - Integrated wallet in messenger GUI
- `gui/SendTokensDialog.*` - Send tokens dialog
- `gui/ReceiveDialog.*` - Receive with QR codes
- `gui/TransactionHistoryDialog.*` - Full transaction list

**Archived because:**
- Wallet functionality fully integrated into main messenger GUI
- BUILD_WALLET_GUI option disabled by default (CMakeLists.txt line 283)
- Better UX with integrated approach (one app instead of two)

---

## Historical Context

These components represent earlier architectural decisions that were superseded during the migration to a fully decentralized DHT-based architecture (Phase 9.1-9.5).

The transition timeline:
- **Phase 9.1-9.2** (2025-11-02): P2P transport + offline messaging
- **Phase 9.3** (2025-11-03): PostgreSQL → SQLite migration
- **Phase 9.4** (2025-11-04): DHT-based keyserver with reverse mapping
- **Phase 9.5** (2025-11-05): Per-identity contact lists with DHT sync

---

### `futuredesign/`
**Status:** Implemented design documents

**Original purpose:**
- Design specs for DHT-based architecture
- P2P transport layer planning
- Multi-device sync protocol
- Decentralized keyserver design

**Archived designs:**
- `DHT-KEYSERVER-DESIGN.md` - ✅ Implemented in Phase 9.4 (`dht/dht_keyserver.c`)
- `DHT-STORAGE-DESIGN.md` - ✅ Implemented in Phase 9.1-9.3 (`dht/dht_offline_queue.c`, `dht/dht_groups.c`)
- `P2P-TRANSPORT-DESIGN.md` - ✅ Implemented in Phase 9.1 (`p2p/p2p_transport.c`)
- `SYNC-PROTOCOL-DESIGN.md` - ✅ Implemented in Phase 9.5 (`dht/dht_contactlist.c`)
- `ARCHITECTURE-OVERVIEW.md` - General v2.0 vision (mostly implemented)

**Still active:**
- `VOICE-VIDEO-DESIGN.md` remains in `futuredesign/` (Phase 11 - planned)

**Archived because:**
- Design documents served their purpose - features are now implemented
- Keeping them as historical reference for architecture decisions
- Moving to archive reduces confusion about project status

---

## Git History

All files were moved using `git mv` to preserve full commit history. Use:

```bash
# View history of archived files
git log --follow archive/keyserver/
git log --follow archive/utils/
git log --follow archive/wallet-gui/

# View original location
git log -- keyserver/
```

## Restoration

If needed, these components can be restored:

```bash
git mv archive/keyserver .
git mv archive/utils .
git mv archive/wallet-gui .
```

However, they would require updates to work with the current codebase (DHT integration, SQLite instead of PostgreSQL, etc.).
