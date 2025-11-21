# DNA Messenger - Development Guidelines

**Last Updated:** 2025-11-21

---

## Team Development

DNA Messenger is developed by a **collaborative team**. Our workflow emphasizes:
- **Communication** - Document changes, discuss architecture decisions
- **Code reviews** - Review each other's code for quality and security
- **Merge over rebase** - Preserve commit history for team visibility
- **Testing** - Test on both platforms before committing

---

## Code Style

| Area | Guidelines |
|------|-----------|
| **C Code** | K&R style, 4-space indent • Clear comments • Always free memory, check NULL |
| **C++ ImGui** | C++17, camelCase, STL • Namespace-based • Centralized `AppState` • Theme-aware |
| **Qt5** | DEPRECATED (reference only) |

---

## Cryptography Rules

**⚠️ CRITICAL: DO NOT modify crypto primitives without expert review**

- Use `dna_api.h` API only
- Memory-based operations only
- Never log keys/plaintext
- Check all crypto return codes

---

## Database

**SQLite only** (no PostgreSQL)

| Database | Location | Purpose |
|----------|----------|---------|
| Messages | `~/.dna/messages.db` | Local message storage |
| Contacts | `~/.dna/<identity>_contacts.db` | Per-identity contacts (DHT sync, Kyber1024 encrypted) |
| Profiles | `~/.dna/<identity>_profiles.db` | Per-identity profiles (7d TTL, cache-first) |
| Groups | DHT + local cache | UUID v4, SHA256 keys, JSON |
| Keyserver | `~/.dna/keyserver_cache.db` | Public key cache (7d TTL, BLOB) |

**Best Practices:**
- Use `cache_manager_init()` for unified cache lifecycle
- Always use prepared statements (`sqlite3_prepare_v2`, `sqlite3_bind_*`)
- Check all return codes

---

## DHT Storage TTL Settings

| Data Type | TTL | DHT Key | Rationale |
|-----------|-----|---------|-----------|
| **Identity Keys** | **PERMANENT** | `SHA3-512(fingerprint + ":pubkey")` | Core crypto identity |
| **Name Registration** | **365 days** | `SHA3-512(name + ":lookup")` | Annual renewal (FREE in alpha) |
| **Reverse Mapping** | **365 days** | `SHA3-512(fingerprint + ":reverse")` | Sender ID without pre-adding |
| **Contact Lists** | **PERMANENT** | `SHA3-512(identity + ":contactlist")` | Multi-device sync |
| **User Profiles** | **PERMANENT** | `SHA3-512(fingerprint + ":profile")` | Profile data (7d local cache) |
| **Offline Queue** | **7 days** | `SHA3-512(sender + ":outbox:" + recipient)` | Sender outbox (Model E) |
| **Groups** | **7 days** | `SHA256(group_uuid)` | Active groups |
| **Wall Posts** | **7 days** | `SHA256(fingerprint + ":message_wall")` | Social media (FREE in alpha) |
| **Wall Votes** | **7 days** | `SHA256(post_id + ":votes")` | Community voting |

**API:**
- `dht_put_permanent()` - Never expires
- `dht_put_signed_permanent()` - Signed + permanent
- `dht_put_ttl(ctx, key, val, 365*24*3600)` - 365 days
- `dht_put()` - 7 days (default)

---

## GUI Development

**ImGui (ACTIVE):**
- Modular namespace-based screens (`screens/` + `helpers/`)
- Centralized `AppState` struct
- Async tasks via `state.task_queue`
- Theme-aware colors
- Mobile-responsive layouts

**Qt5 (DEPRECATED):**
- Reference only, not maintained

---

## Wallet Integration

- Read from `~/.dna/` or system dir
- Use `cellframe_rpc.h` API
- Amounts as strings (preserve precision)
- Smart decimals (8 for tiny, 2 normal)
- Minimal TX builder (no JSON-C dependency)

---

## Cross-Platform

- Linux (primary)
- Windows (MXE cross-compile)
- CMake build system
- Avoid platform-specific code
- **Test both platforms before commit** (team responsibility)

---

## Module Patterns

**C Modules:**
- Shared core header (e.g., `messenger_core.h`)
- Function prefix matching module name
- Error codes: 0=success, -1=error
- Explicit includes
- Context-passing

**C++ Modules:**
- Namespace-based
- Centralized `AppState`
- Stateless functions
- No circular dependencies
- Theme-aware

---

## Adding Features

**Messenger Module:**
```c
// 1. Create messenger/new_module.{h,c}
// 2. Add to CMakeLists.txt
// 3. Include in messenger.c
```

**ImGui Screen:**
```cpp
// 1. Create screens/new_screen.{h,cpp}
// 2. Add render(AppState& state) entry point
// 3. Add to CMakeLists.txt
// 4. Call from app.cpp
```

---

## Common Tasks

**Build:**
```bash
mkdir build && cd build
cmake .. && make -j$(nproc)
```

**Cross-compile Windows:**
```bash
./build-cross-compile.sh windows-x64
```

**Run:**
```bash
./build/imgui_gui/dna_messenger_imgui
```

---

## Documentation Structure

**Documentation Files:**
- **ALL documentation MUST be in `docs/` directory**
- **Exceptions:** Only `CLAUDE.md`, `README.md`, and `ROADMAP.md` stay in root
- Keep documentation organized and discoverable

---

## Testing & Troubleshooting

**Test Files:**
- **ALL test files MUST be created in `tests/` directory**
- Naming convention: `test_*.c`, `test_*.cpp`, `test_*.sh`
- Keep tests organized in one location

**Manual Tests:**
- Messaging: Send/receive, verify encryption, check receipts
- Groups: Create, send, add/remove members
- Wallet: Balances, send TX, check history

**Debug:**
- Use `printf("[DEBUG] ...")` with prefixes `[DEBUG TX]`, `[DEBUG RPC]`
- Remove before commit

**Common Issues:**
- Wallet 0.00: Check Cellframe node (port 8079, RPC enabled, wallet exists)
- TX fails: Check balance+fee, UTXO query, signature
- Theme: Init ThemeManager, connect signals
- Windows: Check MXE deps, toolchain path

---

## Security Best Practices

- Never log keys/plaintext
- Validate all inputs
- Check crypto return codes
- Secure memory (mlock - future)

---

**See also:**
- [Architecture](ARCHITECTURE.md) - System architecture and directory structure
- [API Reference](API.md) - Quick API reference
- [Git Workflow](GIT_WORKFLOW.md) - Commit and push guidelines
