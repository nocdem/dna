# DNA Messenger CLI Testing Guide

**Version:** 2.4.0
**Purpose:** Command-line tool for automated testing and debugging of DNA Messenger without GUI
**Location:** `build/cli/dna-messenger-cli`

---

## Overview

The `dna-messenger-cli` tool allows Claude (or any automated system) to test DNA Messenger functionality through single-command invocations. Each command initializes the engine, executes the operation, and exits cleanly.

**Key Features (v2.3.0):**
- Auto-loads identity if only one exists
- Waits for DHT connection before network operations
- Includes propagation delays for DHT put operations
- `messages` command resolves names to fingerprints via DHT

---

## Building

```bash
cd /opt/dna-messenger
mkdir -p build && cd build
cmake ..
make dna-messenger-cli
```

The executable will be at: `build/cli/dna-messenger-cli`

---

## Quick Reference

```bash
CLI=/opt/dna-messenger/build/cli/dna-messenger-cli

# Identity
$CLI create <name>                    # Create new identity (prompts for password)
$CLI restore <mnemonic...>            # Restore from 24 words
$CLI delete <fingerprint>             # Delete an identity
$CLI list                             # List identities
$CLI load <fingerprint>               # Load identity (prompts for password if encrypted)
$CLI whoami                           # Show current identity
$CLI change-password                  # Change password for current identity
$CLI register <name>                  # Register DHT name
$CLI name                             # Show registered name
$CLI lookup <name>                    # Check name availability
$CLI lookup-profile <name|fp>         # View any user's DHT profile
$CLI profile                          # Show profile
$CLI profile bio="Hello world"        # Update profile field

# Contacts
$CLI contacts                         # List contacts
$CLI add-contact <name|fp>            # Add contact
$CLI remove-contact <fp>              # Remove contact
$CLI request <fp> [message]           # Send contact request
$CLI requests                         # List pending requests
$CLI approve <fp>                     # Approve request

# Messaging
$CLI send <name|fp> "message"         # Send message (use name or FULL fingerprint)
$CLI messages <name|fp>               # Show conversation (resolves name to fp)
$CLI check-offline                    # Check offline messages

# Wallet
$CLI wallets                          # List wallets
$CLI balance <index>                  # Show balances

# Network
$CLI online <fp>                      # Check if peer online
```

---

## Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `-d, --data-dir <path>` | Use custom data directory (default: `~/.dna`) |
| `-i, --identity <fp>` | Use specific identity (fingerprint prefix) |
| `-q, --quiet` | Suppress initialization/shutdown messages |
| `-h, --help` | Show help and exit |
| `-v, --version` | Show version and exit |

### Auto-Load Behavior

For commands that require an identity (everything except `create`, `restore`, `list`):
- If `-i <fingerprint>` is provided, loads that identity
- If only ONE identity exists, auto-loads it
- If multiple identities exist, requires `-i` flag

---

## Identity Commands

### `create <name>` - Create New Identity

Creates a new DNA identity with a BIP39 mnemonic phrase.

```bash
dna-messenger-cli create alice
```

**Output:**
- Prompts for optional password (recommended for key encryption)
- Generates 24-word BIP39 mnemonic (SAVE THIS!)
- Creates Dilithium5 signing key
- Creates Kyber1024 encryption key
- Encrypts keys with password (PBKDF2-SHA256 + AES-256-GCM)
- Registers name on DHT keyserver
- Returns 128-character hex fingerprint

**Password Protection:**
- Password encrypts: `.dsa` key, `.kem` key, `mnemonic.enc`
- Uses PBKDF2-SHA256 with 210,000 iterations (OWASP 2023)
- Password is optional but strongly recommended
- Wallet addresses are derived on-demand from mnemonic (no plaintext wallet files)

**Note:** Identity creation automatically registers the name on DHT.

---

### `restore <mnemonic...>` - Restore Identity

Restores an identity from a 24-word BIP39 mnemonic.

```bash
dna-messenger-cli restore abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt
```

**Notes:**
- Does NOT register name on DHT (use `register` separately)
- Recreates exact same keys from seed

---

### `list` - List Identities

Lists all available identities in the data directory.

```bash
dna-messenger-cli list
```

**Sample Output:**
```
Available identities (2):
  1. db73e6091aef325e... (loaded)
  2. 5a8f2c3d4e6b7a9c...
```

---

### `load <fingerprint>` - Load Identity

Loads an identity for operations.

```bash
dna-messenger-cli load db73e609
```

**Notes:**
- Fingerprint can be a prefix (at least 8 chars)
- Prompts for password if keys are encrypted
- Loads keys, starts DHT, registers presence

---

### `whoami` - Show Current Identity

```bash
dna-messenger-cli whoami
```

---

### `change-password` - Change Identity Password

Changes the password protecting the current identity's keys.

```bash
dna-messenger-cli change-password
```

**Process:**
1. Prompts for current password (Enter for none)
2. Prompts for new password (Enter to remove password)
3. Confirms new password
4. Re-encrypts all key files with new password

**Files Updated:**
- `~/.dna/<fingerprint>/keys/<fingerprint>.dsa`
- `~/.dna/<fingerprint>/keys/<fingerprint>.kem`
- `~/.dna/<fingerprint>/mnemonic.enc`

**Requirements:**
- Identity must be loaded
- Current password must be correct

---

### `register <name>` - Register DHT Name

Registers a human-readable name on the DHT.

```bash
dna-messenger-cli register alice
```

**Requirements:**
- Identity must be loaded
- Name: 3-20 chars, alphanumeric + underscore

**Important:** DHT propagation takes ~1 minute. The command waits 3 seconds before exiting, but full network propagation takes longer.

---

### `name` - Show Registered Name

```bash
dna-messenger-cli name
```

---

### `lookup <name>` - Check Name Availability

```bash
dna-messenger-cli lookup alice
```

**Output:**
- `Name 'alice' is AVAILABLE` - name not taken
- `Name 'alice' is TAKEN by: <fingerprint>` - name registered

**Note:** If you just registered a name, wait ~1 minute for DHT propagation before lookup will find it.

---

### `lookup-profile <name|fingerprint>` - View Any User's DHT Profile

View complete profile data from DHT for any user (by name or fingerprint).

```bash
dna-messenger-cli lookup-profile alice
dna-messenger-cli lookup-profile 5a8f2c3d4e6b7a9c...
```

**Sample Output:**
```
========================================
Fingerprint: 5a8f2c3d4e6b7a9c...
Name: alice
Registered: 1765484288
Expires: 1797020288
Version: 3
Timestamp: 1765504847

--- Wallet Addresses ---
Backbone: Rj7J7MiX...
Ethereum: 0x2e976Ec...

--- Social Links ---
Telegram: @alice

--- Profile ---
Bio: Post-quantum enthusiast

--- Avatar ---
(no avatar)
========================================
```

**Use Cases:**
- Debug profile registration issues
- Verify name registration data (Registered/Expires timestamps)
- Check if profile data is properly stored in DHT
- Compare profiles between users

---

### `profile [field=value]` - Get/Update Profile

Show profile:
```bash
dna-messenger-cli profile
```

Update profile field:
```bash
dna-messenger-cli profile bio="Post-quantum enthusiast"
dna-messenger-cli profile twitter="@alice"
dna-messenger-cli profile website="https://alice.dev"
```

**Valid fields:** bio, location, website, telegram, twitter, github

---

## Contact Commands

### `contacts` - List Contacts

```bash
dna-messenger-cli contacts
```

**Sample Output:**
```
Contacts (2):
  1. bob
     Fingerprint: 5a8f2c3d4e6b7a9c...
     Status: ONLINE
  2. charlie
     Fingerprint: 7f8e9d0c1b2a3456...
     Status: offline
```

---

### `add-contact <name|fingerprint>` - Add Contact

```bash
dna-messenger-cli add-contact bob
dna-messenger-cli add-contact 5a8f2c3d4e6b7a9c...
```

---

### `remove-contact <fingerprint>` - Remove Contact

```bash
dna-messenger-cli remove-contact 5a8f2c3d
```

---

### `request <fingerprint> [message]` - Send Contact Request

```bash
dna-messenger-cli request 5a8f2c3d "Hi, let's connect!"
dna-messenger-cli request 5a8f2c3d
```

**Note:** The command waits 2 seconds for DHT propagation before exiting.

---

### `requests` - List Pending Requests

```bash
dna-messenger-cli requests
```

**Sample Output:**
```
Pending contact requests (1):
  1. charlie
     Fingerprint: 7f8e9d0c1b2a3456...
     Message: Would like to chat!

Use 'approve <fingerprint>' to accept a request.
```

---

### `approve <fingerprint>` - Approve Contact Request

```bash
dna-messenger-cli approve 7f8e9d0c
```

---

## Messaging Commands

### `send <name|fingerprint> <message>` - Send Message

```bash
dna-messenger-cli send nox "Hello from CLI!"
dna-messenger-cli send 5a8f2c3d4e6b7a9c1b2a34567890abcd... "Hello from CLI!"
```

**IMPORTANT:** Use registered name OR full 128-char fingerprint. Partial fingerprints do NOT work for send.

**Requirements:**
- Identity must be loaded
- Recipient must be a registered name OR full 128-character fingerprint
- Message is E2E encrypted with Kyber1024 + AES-256-GCM

---

### `messages <name|fingerprint>` - Show Conversation

Shows messages with a contact. If a name is provided, it resolves to fingerprint via DHT lookup.

```bash
dna-messenger-cli messages nox          # By registered name (resolves to fp)
dna-messenger-cli messages 5a8f2c3d...  # By full fingerprint
```

**Sample Output:**
```
Conversation with f6ddccbee2b3ee69... (3 messages):

[2024-01-15 14:30] >>> Hello!
[2024-01-15 14:31] <<< Hi there!
[2024-01-15 14:32] >>> How are you?
```

**Note:** Name resolution queries the DHT, so the contact must have a registered name.

---

### `check-offline` - Check Offline Messages

```bash
dna-messenger-cli check-offline
```

---

## Wallet Commands

### `wallets` - List Wallets

```bash
dna-messenger-cli wallets
```

**Sample Output:**
```
Wallets (1):
  0. alice_wallet
     Address: KbB...xyz

Use 'balance <index>' to see balances.
```

---

### `balance <index>` - Show Wallet Balances

```bash
dna-messenger-cli balance 0
```

**Sample Output:**
```
Balances:
  1000.00 CPUNK (Backbone)
  50.00 KEL (KelVPN)
```

---

## Network Commands

### `online <fingerprint>` - Check Peer Online Status

```bash
dna-messenger-cli online 5a8f2c3d
```

**Output:**
```
Peer 5a8f2c3d... is ONLINE
```
or
```
Peer 5a8f2c3d... is OFFLINE
```

---

## DHT Propagation

**Important:** DHT operations are asynchronous and require time to propagate across the network.

| Operation | CLI Wait | Full Propagation |
|-----------|----------|------------------|
| `register` | 3 seconds | ~1 minute |
| `request` | 2 seconds | ~30 seconds |
| `profile` updates | 2 seconds | ~1 minute |

**Best Practice:** After `register` or profile updates, wait ~1 minute before expecting other users to see the changes.

---

## Testing Workflows for Claude

### Workflow 1: Create Identity and Register Name

```bash
CLI=/opt/dna-messenger/build/cli/dna-messenger-cli

# Create identity (auto-registers name)
$CLI create alice
# Wait for DHT propagation
sleep 60

# Verify registration
$CLI lookup alice
```

### Workflow 2: Contact Request Flow

```bash
# Lookup target user
$CLI lookup nox
# Note the fingerprint from output

# Send contact request
$CLI request <NOX_FINGERPRINT> "Hello from CLI!"

# Wait for propagation
sleep 30

# Target user checks requests (on their machine)
# Target user approves (on their machine)
```

### Workflow 3: Two-User Messaging Test

```bash
# User A: Create and register
$CLI -d /tmp/user-a create user_a
sleep 60

# User B: Create and register
$CLI -d /tmp/user-b create user_b
sleep 60

# User A: Send request to User B
$CLI -d /tmp/user-a request <USER_B_FP> "Let's chat"
sleep 30

# User B: Approve request
$CLI -d /tmp/user-b requests
$CLI -d /tmp/user-b approve <USER_A_FP>

# User A: Send message
$CLI -d /tmp/user-a send <USER_B_FP> "Hello User B!"

# User B: Check messages
$CLI -d /tmp/user-b messages <USER_A_FP>
```

### Workflow 4: Quiet Mode for Clean Output

```bash
$CLI -q list                          # Just identities, no noise
$CLI -q contacts                      # Just contacts
$CLI -q messages $BOB_FP              # Just conversation
```

### Workflow 5: Specific Identity Selection

```bash
# With multiple identities, use -i flag
$CLI -i db73e609 whoami
$CLI -i db73e609 contacts
$CLI -i 5a8f2c3d send <FP> "Message from second identity"
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid arguments, command failed, etc.) |
| 130 | Interrupted (SIGINT/SIGTERM) |

---

## Tips for Claude

1. **Use `-q` flag** for cleaner output parsing
2. **Extract fingerprints** from create/list output for subsequent commands
3. **Wait for DHT propagation** (~1 minute after register, ~30s after request)
4. **Isolate tests** with `-d /tmp/unique-test-dir`
5. **Check exit codes** - 0 = success, non-zero = failure
6. **Auto-load works** when only one identity exists
7. **Use `-i` flag** when multiple identities exist

---

## Common Warnings (Safe to Ignore)

These warnings appear during normal operation and don't indicate errors:

| Warning | Meaning |
|---------|---------|
| `[MSG_KEYS] ERROR: Already initialized` | Internal state logging, not an error |
| `Send failed, errno=101` | Network interface not available (IPv6, etc.) |
| `[DNA_ENGINE] WARN: DHT disconnected` | DHT temporarily disconnected, will reconnect |
| `[DHT_CHUNK] ERROR: Failed to fetch chunk0` | DHT data not yet available, normal during startup |

---

## Limitations

- **Single command per invocation**: Each call initializes and shuts down engine
- **No real-time message receiving**: Use `messages` to poll conversation
- **DHT propagation delay**: Network operations take time to propagate
- **Auto-load requires single identity**: Use `-i` flag with multiple identities

---

## File Locations

| Item | Path |
|------|------|
| Executable | `build/cli/dna-messenger-cli` |
| Source | `cli/main.c`, `cli/cli_commands.c` |
| Default data | `~/.dna/` |
| Identity keys | `~/.dna/<fingerprint>/keys/` |
| Wallets | `~/.dna/<fingerprint>/wallets/` |
| Database | `~/.dna/<fingerprint>/db/` |

---

## Changelog

### v2.2.0
- Added `lookup-profile <name|fp>` command to view any user's DHT profile
- Useful for debugging profile registration issues and comparing profiles

### v2.1.0
- Added `-i, --identity` option to specify identity by fingerprint prefix
- Added auto-load: automatically loads identity if only one exists
- Added DHT connection wait (up to 10 seconds) before network operations
- Added propagation delays for `register` (3s) and `request` (2s) commands
- Fixed timing issues where CLI exited before async DHT operations completed

### v2.0.0
- Added all 22 commands (identity, contacts, messaging, wallet, network)
- Single-command mode (non-interactive)
- Async-to-sync wrappers for all DNA Engine callbacks

### v1.0.0
- Initial release with basic commands (create, list, load, send, whoami)
