# DNA Messenger CLI Testing Guide

**Version:** 2.5.0
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

# NAT Traversal (STUN/ICE/TURN)
$CLI stun-test                        # Test STUN, show public IP
$CLI ice-status                       # Show ICE connection status
$CLI turn-creds                       # Show cached TURN credentials
$CLI turn-creds --force               # Force request TURN credentials

# Version Management
$CLI publish-version --lib 0.4.0 --app 0.99.106 --nodus 0.4.3   # Publish version to DHT
$CLI check-version                    # Check latest version from DHT

# Groups (GEK encrypted)
$CLI group-list                       # List all groups
$CLI group-create "Team Name"         # Create a new group
$CLI group-send <uuid> "message"      # Send message to group
$CLI group-info <uuid>                # Show group info and members
$CLI group-invite <uuid> <fp>         # Invite member to group
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

## NAT Traversal Commands

### `stun-test` - Test STUN Connectivity

Tests STUN server connectivity and displays your public IP address.

```bash
dna-messenger-cli stun-test
```

**Sample Output:**
```
Testing STUN connectivity...
========================================
✓ STUN Test PASSED
  Public IP: 195.174.168.27
========================================

STUN Servers Tested:
  1. stun.l.google.com:19302
  2. stun1.l.google.com:19302
  3. stun.cloudflare.com:3478

NAT Type: Likely Open/Full Cone (direct P2P possible)
```

**Notes:**
- Does not require identity load
- Tests Google and Cloudflare STUN servers
- Shows NAT type assessment

---

### `ice-status` - Show ICE Connection Status

Displays ICE (Interactive Connectivity Establishment) status and gathered candidates.

```bash
dna-messenger-cli ice-status
```

**Sample Output:**
```
ICE Connection Status
========================================
P2P Transport: ACTIVE
  Listen Port: 4001 (TCP)
  ICE Status: READY

Local ICE Candidates:
  [HOST]  a=candidate:1 1 UDP 2114977791 192.168.0.198 54206 typ host
  [SRFLX] a=candidate:2 1 UDP 1678769919 195.174.168.27 54206 typ srflx

Active Connections: 0
========================================
```

**Candidate Types:**
- `[HOST]` - Local network interface address
- `[SRFLX]` - Server-reflexive (NAT-mapped public IP via STUN)
- `[RELAY]` - TURN relay candidate

**Requirements:**
- Identity must be loaded

---

### `turn-creds [--force]` - Show/Request TURN Credentials

Displays or requests TURN relay credentials from DNA Nodus bootstrap servers.

```bash
# Show cached credentials
dna-messenger-cli turn-creds

# Force request new credentials
dna-messenger-cli turn-creds --force
```

**Sample Output (with --force):**
```
TURN Credentials
========================================
Identity: 71194ec906913bb7...

Requesting TURN credentials from DNA Nodus...
✓ Credentials obtained!

Cached credentials:

TURN Servers (3):
  1. 154.38.182.161:3478
     Username: 71194ec9_1703185432
     Password: a8f2c3d4e5f67890
     Expires:  6 days, 23 hours
  2. 164.68.105.227:3478
     ...
========================================
```

**Sample Output (no credentials):**
```
No cached credentials found.

Use 'turn-creds --force' to request credentials from DNA Nodus.

TURN credentials are also obtained automatically when:
  1. ICE direct connection fails
  2. STUN-only candidates are insufficient
  3. Symmetric NAT requires relay
```

**Options:**
- `--force` - Request new credentials from DNA Nodus even if not needed

**Notes:**
- TURN credentials are requested automatically during ICE negotiation
- Credentials have 7-day TTL
- Credentials are signed with Dilithium5
- Uses UDP port 3479 for fast credential requests

---

## Version Commands

### `publish-version` - Publish Version Info to DHT

Publishes version information to a well-known DHT key. The first publisher "owns" the key - only that identity can update it.

```bash
dna-messenger-cli publish-version --lib 0.4.0 --app 0.99.106 --nodus 0.4.3
```

**Required Arguments:**
- `--lib <version>` - Library version (e.g., "0.3.91")
- `--app <version>` - Flutter app version (e.g., "0.99.30")
- `--nodus <version>` - Nodus server version (e.g., "0.4.4")

**Optional Arguments:**
- `--lib-min <version>` - Minimum supported library version
- `--app-min <version>` - Minimum supported app version
- `--nodus-min <version>` - Minimum supported nodus version

**Sample Output:**
```
Publishing version info to DHT...
  Library: 0.4.0 (min: 0.4.0)
  App:     0.99.106 (min: 0.99.0)
  Nodus:   0.4.3 (min: 0.4.0)
  Publisher: 71194ec906913bb7...
Waiting for DHT propagation...
✓ Version info published successfully!
```

**Notes:**
- Requires identity loaded (`load` command)
- First publisher owns the DHT key permanently
- Subsequent publishes must use the same identity
- Data is signed with Dilithium5

---

### `check-version` - Check Latest Version from DHT

Fetches version info from DHT and compares with local library version.

```bash
dna-messenger-cli check-version
```

**Sample Output:**
```
Checking version info from DHT...

Version Info from DHT:
  Library: 0.4.0 (min: 0.4.0) [UP TO DATE]
  App:     0.99.106 (min: 0.99.0)
  Nodus:   0.4.3 (min: 0.4.0)
  Published: 2026-01-10 10:15 UTC
  Publisher: 3cbba8d8bf0c3603...
```

**Notes:**
- Does not require identity loaded (read-only operation)
- Shows [UPDATE AVAILABLE] if newer version exists
- Returns -2 if no version info has been published yet

---

## Group Commands

Group messaging uses GEK (Group Encryption Key) for end-to-end encrypted group chats.

### `group-list` - List All Groups

Lists all groups the user belongs to.

```bash
dna-messenger-cli group-list
```

**Sample Output:**
```
Groups (2):
  1. Project Team
     UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
     Members: 5
     Owner: You
  2. Friends
     UUID: 98765432-abcd-ef01-2345-678901234567
     Members: 3
     Owner: 5a8f2c3d4e6b7a9c...
```

---

### `group-create <name>` - Create New Group

Creates a new group with you as the owner.

```bash
dna-messenger-cli group-create "Project Team"
```

**Sample Output:**
```
Creating group 'Project Team'...
✓ Group created!
UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Notes:**
- You become the group owner
- GEK v0 is automatically generated
- Use the UUID for subsequent group operations

---

### `group-send <uuid> <message>` - Send Group Message

Sends an encrypted message to a group.

```bash
dna-messenger-cli group-send a1b2c3d4-e5f6-7890-abcd-ef1234567890 "Hello team!"
```

**Sample Output:**
```
Sending message to group a1b2c3d4...
✓ Message sent!
```

**Requirements:**
- Must be a member of the group
- Message encrypted with current GEK

---

### `group-info <uuid>` - Show Group Info

Displays group metadata and member list.

```bash
dna-messenger-cli group-info a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Sample Output:**
```
Group Info
========================================
Name: Project Team
UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Owner: 71194ec906913bb7... (You)
Created: 2026-01-10 12:00 UTC
GEK Version: 2

Members (3):
  1. 71194ec906913bb7... (owner)
  2. 5a8f2c3d4e6b7a9c...
  3. 7f8e9d0c1b2a3456...
========================================
```

---

### `group-invite <uuid> <fingerprint>` - Invite Member

Invites a user to join the group. Only the group owner can invite.

```bash
dna-messenger-cli group-invite a1b2c3d4-e5f6-7890-abcd-ef1234567890 5a8f2c3d4e6b7a9c...
```

**Sample Output:**
```
Inviting 5a8f2c3d... to group a1b2c3d4...
✓ Invitation sent!
GEK rotated to version 3.
```

**Notes:**
- Only group owner can invite members
- GEK is automatically rotated when adding members
- Invited user receives the new GEK via IKP (Initial Key Packet)

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

### v2.5.0
- Added Group commands (GEK encrypted group messaging):
  - `group-list` - List all groups
  - `group-create` - Create a new group
  - `group-send` - Send message to group
  - `group-info` - Show group info and members
  - `group-invite` - Invite member to group

### v2.4.0
- Added NAT Traversal debugging commands:
  - `stun-test` - Test STUN connectivity, show public IP
  - `ice-status` - Show ICE connection status and candidates
  - `turn-creds` - Show cached TURN credentials
- Commands help debug P2P connectivity issues

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
