# DNA Connect CLI Testing Guide

**Version:** 3.0.0
**Purpose:** Command-line tool for automated testing and debugging of DNA Connect without GUI
**Location:** `/opt/dna/messenger/build/cli/dna-connect-cli`

---

## Overview

The `dna-connect-cli` tool allows Claude (or any automated system) to test DNA Connect functionality through single-command invocations. Each command initializes the engine, executes the operation, and exits cleanly.

**Key Features (v3.0.0):**
- **Grouped subcommand structure**: All commands use `<group> <subcommand>` format
- Auto-loads identity if only one exists
- Waits for DHT connection before network operations
- Includes propagation delays for DHT put operations
- `message list` command resolves names to fingerprints via DHT

---

## Building

```bash
cd /opt/dna/messenger/build
cmake ..
make dna-connect-cli
```

The executable will be at: `/opt/dna/messenger/build/cli/dna-connect-cli`

---

## Quick Reference

```bash
CLI=/opt/dna/messenger/build/cli/dna-connect-cli

# Identity
$CLI identity create <name>                    # Create new identity (prompts for password)
$CLI identity restore <mnemonic...>            # Restore from 24 words
$CLI identity delete <fingerprint>             # Delete an identity
$CLI identity list                             # List identities
$CLI identity load <fingerprint>               # Load identity (prompts for password if encrypted)
$CLI identity whoami                           # Show current identity
$CLI identity change-password                  # Change password for current identity
$CLI identity register <name>                  # Register DHT name
$CLI identity name                             # Show registered name
$CLI identity lookup <name>                    # Check name availability
$CLI identity lookup-profile <name|fp>         # View any user's DHT profile
$CLI identity profile                          # Show profile
$CLI identity profile bio="Hello world"        # Update profile field
$CLI identity set-nickname <fp> <n>            # Set nickname for contact
$CLI identity get-avatar <fp>                  # Get avatar for identity
$CLI identity get-mnemonic                     # Show mnemonic phrase
$CLI identity refresh-profile <fp>             # Refresh profile from DHT

# Contacts
$CLI contact list                              # List contacts
$CLI contact remove <fp>                       # Remove contact
$CLI contact request <fp> [message]            # Send contact request
$CLI contact requests                          # List pending requests
$CLI contact request-count                     # Show pending request count
$CLI contact approve <fp>                      # Approve request
$CLI contact deny <fp>                         # Deny request
$CLI contact block <id>                        # Block user
$CLI contact unblock <fp>                      # Unblock user
$CLI contact blocked                           # List blocked users
$CLI contact is-blocked <fp>                   # Check if user is blocked
$CLI contact check-inbox <id>                  # Check inbox for contact
$CLI contact sync-up                           # Sync contacts to DHT
$CLI contact sync-down                         # Sync contacts from DHT

# Following (one-directional, no approval needed)
$CLI follow <name|fp>                          # Follow a user
$CLI follow list                               # List followed users
$CLI follow remove <name|fp>                   # Unfollow a user
$CLI follow sync-up                            # Push follow list to DHT
$CLI follow sync-down                          # Pull follow list from DHT

# Messaging
$CLI message send <name|fp> "message"          # Send message (use name or FULL fingerprint)
$CLI message list <name|fp>                    # Show conversation (resolves name to fp)
$CLI message page <fp> <n> <off>               # Paginated messages
$CLI message delete <id>                       # Delete a message
$CLI message mark-read <fp>                    # Mark conversation as read
$CLI message unread <fp>                       # Get unread count
$CLI message check-offline                     # Check offline messages
$CLI message listen                            # Subscribe to push notifications
$CLI message queue-status                      # Show message queue status
$CLI message queue-send <fp> <msg>             # Queue message for sending
$CLI message queue-capacity <n>                # Set queue capacity
$CLI message retry-pending                     # Retry all pending messages
$CLI message retry-message <id>                # Retry specific message
$CLI message backup                            # Backup messages to DHT
$CLI message restore                           # Restore messages from DHT

# Wallet
$CLI wallet list                               # List wallets
$CLI wallet balance <index>                    # Show balances
$CLI wallet send <w> <net> <tok> <to> <amt>    # Send tokens
$CLI wallet transactions <idx>                 # Show transactions
$CLI wallet estimate-gas <id>                  # Estimate gas for transaction

# DEX
$CLI dex quote <from> <to> <amt> [dex]         # Get DEX quote
$CLI dex pairs                                 # List DEX pairs

# Groups (GEK encrypted)
$CLI group list                                # List all groups
$CLI group create "Team Name"                  # Create a new group
$CLI group send <uuid> "message"               # Send message to group
$CLI group info <uuid>                         # Show group info and members
$CLI group members <uuid>                      # List group members
$CLI group invite <uuid> <fp>                  # Invite member to group
$CLI group messages <uuid>                     # Show group messages
$CLI group sync <uuid>                         # Sync group from DHT to local cache
$CLI group sync-all                            # Sync all groups
$CLI group sync-up                             # Sync groups to DHT
$CLI group sync-down                           # Sync groups from DHT
$CLI group publish-gek <uuid>                  # Publish GEK to DHT
$CLI group gek-fetch <uuid>                    # Fetch GEK from DHT
$CLI group invitations                         # List pending invitations
$CLI group invite-accept <uuid>                # Accept group invitation
$CLI group invite-reject <uuid>                # Reject group invitation

# Channels (Topic-based public channels)
$CLI channel create "Name" "Description"
$CLI channel get <uuid>                        # Get channel by UUID
$CLI channel delete <uuid>                     # Delete channel (author only)
$CLI channel discover --days 7                 # Discover channels
$CLI channel post <uuid> "Message"             # Post to channel
$CLI channel posts <uuid> [--days N]           # Get posts in channel (default 3 days, max 30)
$CLI channel subscribe <uuid>                  # Subscribe to channel
$CLI channel unsubscribe <uuid>                # Unsubscribe from channel
$CLI channel subscriptions                     # List subscriptions
$CLI channel sync                              # Sync subscriptions to/from DHT

# Network
$CLI network online <fp>                       # Check if peer online
$CLI network dht-status                        # Show DHT connection status
$CLI network pause-presence                    # Pause presence heartbeat
$CLI network resume-presence                   # Resume presence heartbeat
$CLI network refresh-presence                  # Refresh presence
$CLI network changed                           # Notify network changed
$CLI network bootstrap-registry                # Show bootstrap registry

# Version Management
$CLI version publish --lib 0.4.0 --app 0.99.106 --nodus 0.4.3   # Publish version to DHT
$CLI version check                             # Check latest version from DHT

# Signing
$CLI sign data <data>                          # Sign data
$CLI sign pubkey                               # Show signing public key

# Debug
$CLI debug log-level [lvl]                     # Get/set log level
$CLI debug log-tags [tags]                     # Get/set log tags
$CLI debug log <on|off>                        # Enable/disable debug log
$CLI debug entries [n]                         # Show debug log entries
$CLI debug count                               # Show debug entry count
$CLI debug clear                               # Clear debug log
$CLI debug export <file>                       # Export debug log to file
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

For commands that require an identity (everything except `identity create`, `identity restore`, `identity list`):
- If `-i <fingerprint>` is provided, loads that identity
- If only ONE identity exists, auto-loads it
- If multiple identities exist, requires `-i` flag

---

## Identity Commands

### `identity create <name>` - Create New Identity

Creates a new DNA identity with a BIP39 mnemonic phrase.

```bash
dna-connect-cli identity create alice
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

### `identity restore <mnemonic...>` - Restore Identity

Restores an identity from a 24-word BIP39 mnemonic.

```bash
dna-connect-cli identity restore abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt
```

**Notes:**
- Does NOT register name on DHT (use `identity register` separately)
- Recreates exact same keys from seed

---

### `identity list` - List Identities

Lists all available identities in the data directory.

```bash
dna-connect-cli identity list
```

**Sample Output:**
```
Available identities (2):
  1. db73e6091aef325e... (loaded)
  2. 5a8f2c3d4e6b7a9c...
```

---

### `identity load <fingerprint>` - Load Identity

Loads an identity for operations.

```bash
dna-connect-cli identity load db73e609
```

**Notes:**
- Fingerprint can be a prefix (at least 8 chars)
- Prompts for password if keys are encrypted
- Loads keys, starts DHT, registers presence

---

### `identity whoami` - Show Current Identity

```bash
dna-connect-cli identity whoami
```

---

### `identity change-password` - Change Identity Password

Changes the password protecting the current identity's keys.

```bash
dna-connect-cli identity change-password
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

### `identity register <name>` - Register DHT Name

Registers a human-readable name on the DHT.

```bash
dna-connect-cli identity register alice
```

**Requirements:**
- Identity must be loaded
- Name: 3-20 chars, alphanumeric + underscore

**Important:** DHT propagation takes ~1 minute. The command waits 3 seconds before exiting, but full network propagation takes longer.

---

### `identity name` - Show Registered Name

```bash
dna-connect-cli identity name
```

---

### `identity lookup <name>` - Check Name Availability

```bash
dna-connect-cli identity lookup alice
```

**Output:**
- `Name 'alice' is AVAILABLE` - name not taken
- `Name 'alice' is TAKEN by: <fingerprint>` - name registered

**Note:** If you just registered a name, wait ~1 minute for DHT propagation before lookup will find it.

---

### `identity lookup-profile <name|fingerprint>` - View Any User's DHT Profile

View complete profile data from DHT for any user (by name or fingerprint).

```bash
dna-connect-cli identity lookup-profile alice
dna-connect-cli identity lookup-profile 5a8f2c3d4e6b7a9c...
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

### `identity profile [field=value]` - Get/Update Profile

Show profile:
```bash
dna-connect-cli identity profile
```

Update profile field:
```bash
dna-connect-cli identity profile bio="Post-quantum enthusiast"
dna-connect-cli identity profile twitter="@alice"
dna-connect-cli identity profile website="https://alice.dev"
```

**Valid fields:** bio, location, website, telegram, twitter, github

---

## Contact Commands

### `contact list` - List Contacts

```bash
dna-connect-cli contact list
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

### `contact add <name|fingerprint>` - Add Contact

```bash
dna-connect-cli contact add bob
dna-connect-cli contact add 5a8f2c3d4e6b7a9c...
```

---

### `contact remove <fingerprint>` - Remove Contact

```bash
dna-connect-cli contact remove 5a8f2c3d
```

---

### `contact request <fingerprint> [message]` - Send Contact Request

```bash
dna-connect-cli contact request 5a8f2c3d "Hi, let's connect!"
dna-connect-cli contact request 5a8f2c3d
```

**Note:** The command waits 2 seconds for DHT propagation before exiting.

---

### `contact requests` - List Pending Requests

```bash
dna-connect-cli contact requests
```

**Sample Output:**
```
Pending contact requests (1):
  1. charlie
     Fingerprint: 7f8e9d0c1b2a3456...
     Message: Would like to chat!

Use 'contact approve <fingerprint>' to accept a request.
```

---

### `contact approve <fingerprint>` - Approve Contact Request

```bash
dna-connect-cli contact approve 7f8e9d0c
```

---

## Messaging Commands

### `message send <name|fingerprint> <message>` - Send Message

```bash
dna-connect-cli message send nox "Hello from CLI!"
dna-connect-cli message send 5a8f2c3d4e6b7a9c1b2a34567890abcd... "Hello from CLI!"
```

**IMPORTANT:** Use registered name OR full 128-char fingerprint. Partial fingerprints do NOT work for send.

**Requirements:**
- Identity must be loaded
- Recipient must be a registered name OR full 128-character fingerprint
- Message is E2E encrypted with Kyber1024 + AES-256-GCM

---

### `message list <name|fingerprint>` - Show Conversation

Shows messages with a contact. If a name is provided, it resolves to fingerprint via DHT lookup.

```bash
dna-connect-cli message list nox          # By registered name (resolves to fp)
dna-connect-cli message list 5a8f2c3d...  # By full fingerprint
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

### `message check-offline` - Check Offline Messages

```bash
dna-connect-cli message check-offline
```

---

## Wallet Commands

### `wallet list` - List Wallets

```bash
dna-connect-cli wallet list
```

**Sample Output:**
```
Wallets (1):
  0. alice_wallet
     Address: KbB...xyz

Use 'wallet balance <index>' to see balances.
```

---

### `wallet balance <index>` - Show Wallet Balances

```bash
dna-connect-cli wallet balance 0
```

**Sample Output:**
```
Balances:
  1000.00 CPUNK (Backbone)
  50.00 KEL (KelVPN)
```

---

## Network Commands

### `network online <fingerprint>` - Check Peer Online Status

```bash
dna-connect-cli network online 5a8f2c3d
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

## NAT Traversal Commands (DEPRECATED)

> **Deprecated since v0.4.61 (STUN/TURN removal).** ICE/STUN/TURN were removed to prevent IP leakage to third-party servers. All messaging now uses DHT-only (Spillway protocol). The code still exists for backward compatibility but these features are non-functional.

### `stun-test` - DEPRECATED
### `ice-status` - DEPRECATED
### `turn-creds` - DEPRECATED

These commands are non-functional and return deprecation messages. They are retained only for backward compatibility.

---

## Version Commands

### `version publish` - Publish Version Info to DHT

Publishes version information to a well-known DHT key. The first publisher "owns" the key - only that identity can update it.

```bash
dna-connect-cli version publish --lib 0.4.0 --app 0.99.106 --nodus 0.4.3
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
- Requires identity loaded (`identity load` command)
- First publisher owns the DHT key permanently
- Subsequent publishes must use the same identity
- Data is signed with Dilithium5

---

### `version check` - Check Latest Version from DHT

Fetches version info from DHT and compares with local library version.

```bash
dna-connect-cli version check
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

### `group list` - List All Groups

Lists all groups the user belongs to.

```bash
dna-connect-cli group list
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

### `group create <name>` - Create New Group

Creates a new group with you as the owner.

```bash
dna-connect-cli group create "Project Team"
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

### `group send <uuid> <message>` - Send Group Message

Sends an encrypted message to a group.

```bash
dna-connect-cli group send a1b2c3d4-e5f6-7890-abcd-ef1234567890 "Hello team!"
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

### `group info <uuid>` - Show Group Info

Displays group metadata and member list.

```bash
dna-connect-cli group info a1b2c3d4-e5f6-7890-abcd-ef1234567890
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

### `group invite <uuid> <fingerprint>` - Invite Member

Invites a user to join the group. Only the group owner can invite.

```bash
dna-connect-cli group invite a1b2c3d4-e5f6-7890-abcd-ef1234567890 5a8f2c3d4e6b7a9c...
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

### `group sync <uuid>` - Sync Group from DHT

Syncs a specific group from DHT to local cache. Useful for recovering groups after database reset when you're still a member in the DHT metadata.

```bash
dna-connect-cli group sync c9291b06-6768-44f6-a08e-8f06f4ceebe9
```

**Sample Output:**
```
Syncing group c9291b06-6768-44f6-a08e-8f06f4ceebe9 from DHT...
Group synced successfully from DHT!
```

**Notes:**
- Fetches group metadata from DHT and stores in local cache
- Only works if you're already a member in the DHT group metadata
- Useful for database recovery scenarios

---

## Feeds v2 Commands

Topic-based public feeds with categories and tags. All feeds data is signed with Dilithium5 and stored in DHT with 30-day TTL.

### `feeds create <title> <body> [options]` - Create Topic

Creates a new public topic in the feed system.

```bash
dna-connect-cli feeds create "My Topic" "This is the body text" --category technology --tags "rust,webdev"
```

**Options:**
- `--category <name>` - Category (default: "general"). Valid: general, technology, help, announcements, trading, offtopic
- `--tags <list>` - Comma-separated tags, max 5 tags, 32 chars each

**Sample Output:**
```
Topic: My Topic
  UUID: 4b7c5dce-28ad-4f45-92d1-c5dae1ed952e
  Author: 3cbba8d8bf0c3603...
  Category: e91fadf24f78c081972a2015146e9b7ad4636bb5a208f5733b54ee4407682078
  Created: 2026-01-30 21:11
  Tags: rust, webdev
  Body:
    This is the body text
  Verified: yes
```

---

### `channel get <uuid>` - Get Channel

Retrieves a channel by its UUID.

```bash
dna-connect-cli channel get 4b7c5dce-28ad-4f45-92d1-c5dae1ed952e
```

---

### `feeds delete <uuid>` - Delete Topic

Soft-deletes a topic (author only). Topic remains in DHT with `deleted=true` until TTL expires.

```bash
dna-connect-cli feeds delete 4b7c5dce-28ad-4f45-92d1-c5dae1ed952e
```

---

### `feeds list --category <name> --days <n>` - List by Category

Lists topics in a category from the last N days.

```bash
dna-connect-cli feeds list --category technology --days 7
```

**Sample Output:**
```
Topics (2):

  1. My Topic
     UUID: 4b7c5dce-28ad-4f45-92d1-c5dae1ed952e
     Author: 3cbba8d8bf0c3603...
     Category: e91fadf24...  |  Created: 2026-01-30 21:11

  2. Another Topic
     UUID: 7a8b9c0d-1234-5678-90ab-cdef12345678
     Author: 5a8f2c3d4e6b7a9c...
     Category: e91fadf24...  |  Created: 2026-01-29 15:30
```

---

### `feeds list-all --days <n>` - List All Topics

Lists all topics from the last N days across all categories.

```bash
dna-connect-cli feeds list-all --days 7
```

---

### `channel post <uuid> <body>` - Post to Channel

Posts a message to a channel.

```bash
dna-connect-cli channel post 4b7c5dce-28ad-4f45-92d1-c5dae1ed952e "Great topic!"
```

---

### `channel posts <uuid> [--days N]` - Get Posts

Retrieves posts from a channel by scanning daily DHT buckets.

```bash
dna-connect-cli channel posts 4b7c5dce-28ad-4f45-92d1-c5dae1ed952e
dna-connect-cli channel posts 4b7c5dce-28ad-4f45-92d1-c5dae1ed952e --days 7
```

**Options:**
- `--days N` - Number of days to look back (default: 3, max: 30). Scans daily buckets from today backwards.

**Sample Output:**
```
Comments (2):

  1. [2026-01-30 21:12] 3cbba8d8bf0c3603...:
     Great topic!
     UUID: c13718b4-49ed-4a1d-bc95-a3baf559f269
     Verified: yes

  2. [2026-01-30 21:15] 5a8f2c3d4e6b7a9c...:
     I agree!
     UUID: d24829c5-5afe-5b2e-cd06-c4cbg660g370
     Verified: yes
```

---

## DHT Propagation

**Important:** DHT operations are asynchronous and require time to propagate across the network.

| Operation | CLI Wait | Full Propagation |
|-----------|----------|------------------|
| `identity register` | 3 seconds | ~1 minute |
| `contact request` | 2 seconds | ~30 seconds |
| `identity profile` updates | 2 seconds | ~1 minute |

**Best Practice:** After `identity register` or profile updates, wait ~1 minute before expecting other users to see the changes.

---

## Testing Workflows for Claude

### Workflow 1: Create Identity and Register Name

```bash
CLI=/opt/dna/messenger/build/cli/dna-connect-cli

# Create identity (auto-registers name)
$CLI identity create alice
# Wait for DHT propagation
sleep 60

# Verify registration
$CLI identity lookup alice
```

### Workflow 2: Contact Request Flow

```bash
# Lookup target user
$CLI identity lookup nox
# Note the fingerprint from output

# Send contact request
$CLI contact request <NOX_FINGERPRINT> "Hello from CLI!"

# Wait for propagation
sleep 30

# Target user checks requests (on their machine)
# Target user approves (on their machine)
```

### Workflow 3: Two-User Messaging Test

```bash
# User A: Create and register
$CLI -d /tmp/user-a identity create user_a
sleep 60

# User B: Create and register
$CLI -d /tmp/user-b identity create user_b
sleep 60

# User A: Send request to User B
$CLI -d /tmp/user-a contact request <USER_B_FP> "Let's chat"
sleep 30

# User B: Approve request
$CLI -d /tmp/user-b contact requests
$CLI -d /tmp/user-b contact approve <USER_A_FP>

# User A: Send message
$CLI -d /tmp/user-a message send <USER_B_FP> "Hello User B!"

# User B: Check messages
$CLI -d /tmp/user-b message list <USER_A_FP>
```

### Workflow 4: Quiet Mode for Clean Output

```bash
$CLI -q identity list                    # Just identities, no noise
$CLI -q contact list                     # Just contacts
$CLI -q message list $BOB_FP             # Just conversation
```

### Workflow 5: Specific Identity Selection

```bash
# With multiple identities, use -i flag
$CLI -i db73e609 identity whoami
$CLI -i db73e609 contact list
$CLI -i 5a8f2c3d message send <FP> "Message from second identity"
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
2. **Extract fingerprints** from `identity create`/`identity list` output for subsequent commands
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
- **No real-time message receiving**: Use `message list` to poll conversation
- **DHT propagation delay**: Network operations take time to propagate
- **Auto-load requires single identity**: Use `-i` flag with multiple identities

---

## File Locations

| Item | Path |
|------|------|
| Executable | `/opt/dna/messenger/build/cli/dna-connect-cli` |
| Source | `cli/main.c`, `cli/cli_commands.c` |
| Default data | `~/.dna/` |
| Identity keys | `~/.dna/<fingerprint>/keys/` |
| Wallets | `~/.dna/<fingerprint>/wallets/` |
| Database | `~/.dna/<fingerprint>/db/` |

---

## Changelog

### v3.0.0
- **BREAKING:** Refactored CLI from flat commands to grouped subcommand structure
- All commands now use `<group> <subcommand>` format (e.g., `identity create`, `message send`, `contact list`)
- Command groups: `identity`, `contact`, `message`, `group`, `channel`, `wallet`, `dex`, `network`, `version`, `sign`, `debug`
- Old flat commands (e.g., `create`, `send`, `contacts`) no longer work
- Added new commands: `contact deny`, `contact block/unblock/blocked/is-blocked`, `contact check-inbox`, `contact sync-up/sync-down`, `message page/delete/mark-read/unread/queue-send/queue-capacity/retry-pending/retry-message/backup/restore`, `group members/messages/sync-all/sync-up/sync-down/publish-gek/gek-fetch/invitations/invite-accept/invite-reject`, `wallet send/transactions/estimate-gas`, `dex quote/pairs`, `network dht-status/pause-presence/resume-presence/refresh-presence/changed/bootstrap-registry`, `sign data/pubkey`, `debug log-level/log-tags/log/entries/count/clear/export`
- Updated CLI path to monorepo location: `/opt/dna/messenger/build/cli/dna-connect-cli`

### v2.7.0
- Migrated feeds to channels system:
  - `channel create` - Create a channel
  - `channel get` - Get channel by UUID
  - `channel delete` - Delete channel (author only)
  - `channel discover` - Discover channels
  - `channel post` - Post to channel
  - `channel posts` - Get posts in channel
  - `channel subscribe` / `channel unsubscribe` - Manage subscriptions
  - `channel subscriptions` - List subscriptions
  - `channel sync` - Sync subscriptions to/from DHT

### v2.5.0
- Added Group commands (GEK encrypted group messaging):
  - `group-list` - List all groups
  - `group-create` - Create a new group
  - `group-send` - Send message to group
  - `group-info` - Show group info and members
  - `group-invite` - Invite member to group

### v2.4.0
- Added NAT Traversal debugging commands:
  - `stun-test` - DEPRECATED (v0.4.61)
  - `ice-status` - DEPRECATED (v0.4.61)
  - `turn-creds` - DEPRECATED (v0.4.61)
- These commands are deprecated since v0.4.61 (STUN/TURN removal). The code still exists for backward compatibility but these features are non-functional.

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
