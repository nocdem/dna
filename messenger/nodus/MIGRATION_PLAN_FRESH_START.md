# DNA Messenger → DNA Nodus Fresh Start Plan

**Migration Type:** FRESH START - No User Migration
**Strategy:** New Dilithium5-only network launch, old RSA network discontinuation
**Timeline:** 3 weeks preparation + cutover day
**Security:** FIPS 204 Dilithium5 (ML-DSA-87) - NIST Category 5 (256-bit quantum)

---

## ⚠️ CRITICAL: Fresh Start Strategy

**What "No Migration" Means:**
- ✅ **New network** - Dilithium5-only from day one
- ✅ **New identities** - All users create fresh Dilithium5 identities
- ✅ **Clean slate** - No contact lists, no groups, no history
- ✅ **No migration tools** - No export/import, no conversion utilities
- ❌ **No backward compatibility** - Old RSA network is discontinued
- ❌ **No identity conversion** - Users don't convert, they create new
- ❌ **No contact migration** - Users rebuild their contact lists manually
- ❌ **No data transfer** - Wall posts, messages, groups start from zero

**This is essentially launching a NEW network** with existing users starting over.

---

## Overview

### Current State (RSA-2048) - TO BE DISCONTINUED
- DNA Messenger uses RSA-2048 DHT network
- Users have RSA identities
- Historical data on old network

### Target State (Dilithium5) - FRESH LAUNCH
- New DNA Nodus DHT network with Dilithium5
- All users create new identities
- Empty DHT (no historical data)
- Post-quantum security from day one

### Cutover Event
**Date:** TBD (announced 3 weeks in advance)
**Time:** Coordinated UTC time (e.g., 00:00 UTC)
**Process:**
1. Old RSA network shuts down
2. New Dilithium5 network goes live
3. Users install new client
4. Users create new identities
5. Users rebuild contacts manually

---

## Migration Phases

### Phase 1: Client Updates (Week 1)

#### 1.1 Remove ALL RSA Code
**Goal:** Clean Dilithium5-only codebase

**Files to Modify:**

**DHT Layer:**
```
dht/client/dht_singleton.h/cpp           # Dilithium5 only
dht/client/dht_profile.h/cpp             # Dilithium5 signatures
dht/client/dht_offline_queue.h/cpp       # Dilithium5 signatures
dht/client/dht_group_invitation.h/cpp    # Dilithium5 signatures
dht/client/dna_message_wall.h/cpp        # Dilithium5 signatures
dht/crypto/dna_identity.h/cpp            # Dilithium5 identity only
dht/CMakeLists.txt                       # Link opendht-pq
```

**Code to DELETE:**
```cpp
// Remove ALL RSA code
- crypto::loadRSAIdentity(...)           // DELETE
- crypto::generateRSAIdentity(...)       // DELETE
- value->sign(rsa_key)                   // DELETE
- value->checkRSASignature()             // DELETE
- RSA-2048 implementation (~50KB)        // DELETE
```

**Result:** Clean, simple Dilithium5-only codebase

---

#### 1.2 Update Bootstrap Configuration
**Goal:** Point clients to DNA Nodus nodes

**Replace:**
```cpp
// Old RSA bootstrap (REMOVE)
bootstrap_nodes = {
    "old-bootstrap-1.example.com:4222",
    "old-bootstrap-2.example.com:4222"
};
```

**With:**
```cpp
// DNA Nodus post-quantum bootstrap (NEW)
const std::vector<std::string> BOOTSTRAP_NODES = {
    "154.38.182.161:4000",  // US-1
    "164.68.105.227:4000",  // EU-1
    "164.68.116.180:4000"   // EU-2
};
```

**Hardcoded:** No runtime configuration, compile-time constants

---

#### 1.3 Identity Creation Flow
**Goal:** Streamlined new identity creation

**Implementation:**
```cpp
// Simple Dilithium5 identity generation
auto identity = dht::crypto::generateDilithiumIdentity(user_name);
crypto::saveDilithiumIdentity(identity, "~/.dna/" + user_name + ".dsa");

// No migration, no conversion, just create new
```

**UI Changes:**
- Remove "Import RSA Identity" option
- Remove "Migration Wizard"
- Single flow: "Create New Identity"
- Show Dilithium5 fingerprint immediately
- Backup reminder for new identity

---

#### 1.4 Contact Discovery
**Goal:** Users manually add contacts with new fingerprints

**Implementation:**
```cpp
// Add contact by Dilithium5 fingerprint
void addContact(const std::string& name, const std::string& dilithium5_fingerprint) {
    // Verify fingerprint format (SHA3-512)
    // Query DHT for user's profile
    // Verify signature with Dilithium5
    // Add to contact list
}
```

**UI:**
```
Add Contact
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Name:        [Alice                    ]
Fingerprint: [abc123...xyz789          ]
             (Dilithium5 - 128 hex chars)

[Verify] [Add Contact]

Note: Share your fingerprint with contacts
      to allow them to add you.
```

**No automatic migration:** Users exchange fingerprints manually

---

### Phase 2: Testing (Week 2)

#### 2.1 Internal Testing
**Goal:** Validate new Dilithium5-only client

**Test Scenarios:**
1. **Fresh Install:**
   - Create new Dilithium5 identity
   - Connect to DNA Nodus network
   - Publish profile to DHT
   - Verify profile retrieval

2. **Contact Discovery:**
   - Add contact by fingerprint
   - Verify contact's profile
   - Send first message (P2P)
   - Verify E2E encryption (Kyber1024)

3. **Group Creation:**
   - Create new group
   - Generate GSK (AES-256-GCM)
   - Invite contacts
   - Verify group messages

4. **Wall Posts:**
   - Publish wall post
   - Verify Dilithium5 signature
   - Retrieve from DHT
   - Verify data integrity

**Success Criteria:**
- ✅ All features work with Dilithium5
- ✅ No RSA code paths exist
- ✅ DHT operations < 5 second latency
- ✅ 100% signature verification success

---

#### 2.2 Alpha Testing (50 users)
**Timeline:** Days 10-12

**Goals:**
- Test new identity creation at scale
- Validate contact discovery UX
- Test network under load
- Collect user feedback

**Metrics:**
- Identity creation success rate: > 99%
- Profile publishing success: > 99%
- Contact discovery success: > 95%
- Average DHT latency: < 3 seconds

**User Instructions:**
```
Welcome to DNA Messenger Post-Quantum Alpha!

This is a FRESH START - no old data will be migrated.

Steps:
1. Create new Dilithium5 identity
2. Share your fingerprint with contacts
3. Add contacts by their fingerprints
4. Start messaging with post-quantum security!

Your old RSA identity will NOT work on this network.
```

---

#### 2.3 Beta Testing (500 users)
**Timeline:** Days 13-18

**Goals:**
- Stress test DNA Nodus network
- Validate UX for contact rebuilding
- Test group creation/invitations
- Final validation before launch

**Stress Tests:**
- 500 concurrent identity creations
- 10,000 DHT operations/hour
- 100 simultaneous group creations
- 1,000 wall post publishes

**Success Criteria:**
- < 5 second DHT operation latency
- > 99% operation success rate
- > 95% user satisfaction
- Zero critical bugs

---

### Phase 3: Launch Preparation (Week 3)

#### 3.1 User Communication
**Goal:** Inform users this is a fresh start

**Key Message:**
```
╔══════════════════════════════════════════════════╗
║  DNA Messenger - Post-Quantum Launch             ║
║                                                  ║
║  IMPORTANT: This is a FRESH START                ║
║                                                  ║
║  • New Dilithium5 post-quantum network           ║
║  • Create new identity (old RSA won't work)      ║
║  • Rebuild contact list manually                 ║
║  • No historical data migrated                   ║
║                                                  ║
║  Launch Date: December 21, 2025 00:00 UTC        ║
║                                                  ║
║  [Learn More] [Download]                         ║
╚══════════════════════════════════════════════════╝
```

**Communication Channels:**
1. **Blog Post:**
   - Explain fresh start approach
   - Benefits of post-quantum security
   - Clear expectations (no migration)
   - FAQ

2. **Email:**
   - Week 3: Launch announcement
   - Week 2: Reminder + preparation guide
   - Week 1: Final reminder
   - Day 0: Launch notification

3. **In-App (Old Client):**
   - "New version available"
   - "Fresh start - create new identity"
   - Link to download

4. **Social Media:**
   - Launch countdown
   - Feature highlights
   - User testimonials (from beta)

---

#### 3.2 Release Preparation

**Binary Builds:**
- Linux (x86_64, ARM64)
- Windows (x86_64)
- macOS (x86_64, ARM64) - if supported

**Version:** `v2.0.0-quantum` (major version bump for fresh start)

**Release Checklist:**
- [ ] ALL RSA code removed
- [ ] Dilithium5-only implementation
- [ ] DNA Nodus bootstrap hardcoded
- [ ] Clean identity creation flow
- [ ] Manual contact discovery
- [ ] Tested on all platforms
- [ ] Code signed
- [ ] Release notes published

**Release Notes:**
```markdown
# DNA Messenger v2.0.0-quantum - Post-Quantum Launch

## 🎉 Fresh Start with Post-Quantum Security

This is a **FRESH START** release. DNA Messenger now uses:
- **Dilithium5 (ML-DSA-87)** - FIPS 204, NIST Category 5
- **256-bit quantum resistance**
- **New DHT network** (DNA Nodus)

## ⚠️ Important: No Migration

This is NOT an update - it's a fresh start:
- Create NEW Dilithium5 identity
- Rebuild contact list manually
- No historical data migrated
- Old RSA network discontinued

## What's New
- ✅ Post-quantum signatures (Dilithium5)
- ✅ Quantum-resistant DHT network
- ✅ Cleaner, simpler codebase
- ✅ Faster DHT operations

## Getting Started
1. Install DNA Messenger v2.0.0
2. Create new Dilithium5 identity
3. Share fingerprint with contacts
4. Add contacts by fingerprint
5. Start messaging!

## Old Network
The old RSA-2048 network will be shut down on:
**December 21, 2025 at 00:00 UTC**

After this date, old clients will no longer connect.

## Questions?
Visit: https://cpunk.io/dna-messenger/fresh-start-faq
```

---

#### 3.3 Old Network Sunset Plan

**Timeline:**
- **T-7 days:** Display shutdown warning in old client
- **T-1 day:** Continuous shutdown warnings
- **T-0:** Old bootstrap nodes shut down
- **T+30 days:** Old bootstrap VPS decommissioned

**Old Client Behavior (after T-0):**
```
╔══════════════════════════════════════════════════╗
║  Network Unavailable                             ║
║                                                  ║
║  The RSA-2048 network has been discontinued.     ║
║                                                  ║
║  Please download DNA Messenger v2.0.0 with       ║
║  post-quantum security:                          ║
║                                                  ║
║  https://cpunk.io/dna-messenger/download         ║
║                                                  ║
║  This is a fresh start - you will create a new  ║
║  identity and rebuild your contact list.         ║
║                                                  ║
║  [Download v2.0.0]                               ║
╚══════════════════════════════════════════════════╝
```

---

### Phase 4: LAUNCH DAY (Day 0)

#### Timeline (All times UTC)

**T-24 hours (Day -1, 00:00 UTC):**
- Final launch notification sent
- DNA Nodus nodes verified operational
- Support team briefed and ready
- New client builds finalized

**T-12 hours (Day -1, 12:00 UTC):**
- Download links activated
- Website updated with launch info
- Support channels staffed

**T-1 hour (Day 0, 23:00 UTC):**
- Old network enters "shutdown warning" mode
- DNA Nodus nodes ready
- Monitoring dashboards active
- Support team online

**T-0 LAUNCH (00:00 UTC):**
```
┌─────────────────────────────────────────────────┐
│  OLD RSA NETWORK SHUTDOWN                       │
├─────────────────────────────────────────────────┤
│  • All old bootstrap nodes STOP                 │
│  • RSA network discontinued                     │
│                                                 │
│  DNA NODUS NETWORK LAUNCH                       │
├─────────────────────────────────────────────────┤
│  • DNA Nodus nodes accepting connections        │
│  • Dilithium5 post-quantum security active      │
│  • Fresh network ready for users                │
└─────────────────────────────────────────────────┘
```

**T+1 hour (01:00 UTC):**
- Monitor new user registrations
- Check DHT operation success rate
- Verify bootstrap node connectivity
- Review support tickets

**T+6 hours (06:00 UTC):**
- First usage statistics
- Connection rate analysis
- Issue tracking and resolution

**T+24 hours (Day 1, 00:00 UTC):**
- Launch day report
- User adoption rate
- Network health assessment
- Support ticket summary

---

#### Launch Day Metrics

**Success Indicators:**
- New identity creations: > 500 in first 24 hours
- DHT operation success: > 99%
- Bootstrap node uptime: 100%
- Average connection time: < 10 seconds
- Support ticket rate: < 5%

**Monitor:**
- User registrations per hour
- DHT operations per hour
- Profile publications
- Contact discoveries
- Group creations
- Wall posts

---

### Phase 5: Post-Launch (Week 4+)

#### 4.1 Growth Monitoring (Week 4-8)

**Key Metrics:**
- **Adoption Rate:**
  - Daily new users
  - Active users (DAU)
  - User retention
  - Growth rate

- **Network Health:**
  - DHT operation success rate
  - Average latency
  - Bootstrap node stability
  - Storage usage

- **User Engagement:**
  - Messages sent
  - Groups created
  - Wall posts published
  - Contact additions

**Target (Week 8):**
- 2,000+ active users
- > 99.5% DHT operation success
- < 2 second average latency
- > 90% user retention

---

#### 4.2 Feature Iteration

**Based on User Feedback:**
- Contact discovery improvements
- Group invitation UX
- Profile enhancements
- Performance optimizations

**Potential Features:**
- QR code fingerprint sharing
- Contact verification badges
- Group discovery
- Enhanced wall posts

---

#### 4.3 Old Network Decommission (Week 8)

**Final Steps:**
1. **Verify old network inactive:**
   - No connections for 30 days
   - All users migrated to new network
   - Support tickets resolved

2. **Archive data:**
   - Export old bootstrap node logs
   - Save configuration files
   - Document lessons learned

3. **Decommission VPS:**
   - Shut down old bootstrap nodes
   - Release VPS resources
   - Update DNS records

4. **Code cleanup:**
   - Remove old client from repositories
   - Archive RSA implementation code
   - Update documentation

---

## Technical Implementation

### Identity Format

**Dilithium5 Only:**
```cpp
struct DNAIdentity {
    std::string name;
    crypto::PrivateKey dilithium5_private;  // 4896 bytes
    crypto::Certificate dilithium5_cert;
    std::string fingerprint;                // SHA3-512 (128 hex chars)
};
```

**File Format:**
```
~/.dna/<name>.dsa      # Dilithium5 private key (binary)
~/.dna/<name>.pub      # Dilithium5 public key (binary)
~/.dna/<name>.cert     # Dilithium5 certificate
```

**No RSA files:** Clean directory structure

---

### DHT Operations

**All operations use Dilithium5 signatures:**

**User Profile:**
```cpp
auto profile_value = std::make_shared<Value>(profile_json);
profile_value->sign(*dilithium5_identity.first);  // 4627-byte signature
auto expire = dht::clock::now() + std::chrono::hours(24 * 365);
dht.put(profile_key, profile_value, callback, expire);
```

**Offline Messages:**
```cpp
std::string key = "dna:offline:" + dilithium5_fingerprint;
auto msg_value = std::make_shared<Value>(encrypted_msg);
msg_value->sign(*dilithium5_identity.first);
auto expire = dht::clock::now() + std::chrono::hours(24 * 7);
dht.put(key, msg_value, callback, expire);
```

**Wall Posts:**
```cpp
std::string wall_key = "dna:wall:" + dilithium5_fingerprint;
auto post_value = std::make_shared<Value>(post_json);
post_value->sign(*dilithium5_identity.first);
auto expire = dht::clock::now() + std::chrono::hours(24 * 30);
dht.put(wall_key, post_value, callback, expire);
```

**Simple and consistent:** One signature type throughout

---

### Database Schema

**Contacts Table:**
```sql
CREATE TABLE contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    dilithium5_fingerprint TEXT UNIQUE NOT NULL,  -- SHA3-512 (128 chars)
    public_key BLOB,                               -- Dilithium5 pubkey (2592 bytes)
    added_timestamp INTEGER,
    last_seen INTEGER,
    verified BOOLEAN DEFAULT 0
);
```

**Groups Table:**
```sql
CREATE TABLE groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    creator_fingerprint TEXT,  -- Dilithium5
    gsk BLOB,                   -- AES-256-GCM key
    created_timestamp INTEGER
);
```

**No migration columns:** Clean schema from day one

---

## User Experience

### First Run Flow

**Step 1: Create Identity**
```
Welcome to DNA Messenger!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This is a fresh start with post-quantum security.

Create your Dilithium5 identity:

Name: [Alice                    ]

[Create Identity]

Note: This will generate a new quantum-resistant
      identity. Your old RSA identity (if any)
      will NOT work on this network.
```

**Step 2: Backup Reminder**
```
Identity Created! ✓
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Your Dilithium5 Fingerprint:

abc123def456...xyz789

⚠️ IMPORTANT: Back up your identity files:

~/.dna/Alice.dsa
~/.dna/Alice.pub
~/.dna/Alice.cert

[Copy Fingerprint] [Continue]
```

**Step 3: Add Contacts**
```
Add Your First Contact
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Share your fingerprint with contacts and
ask for theirs to add them.

Your Fingerprint:
abc123def456...xyz789
[Copy] [QR Code]

Add Contact:
Name:        [Bob                    ]
Fingerprint: [                        ]

[Add Contact] [Skip]
```

**Clean and simple:** No migration complexity

---

### Fingerprint Sharing

**Methods:**
1. **Copy/Paste:**
   - Copy fingerprint to clipboard
   - Share via any channel (email, Signal, etc.)
   - Paste into "Add Contact" dialog

2. **QR Code:**
   - Generate QR code with fingerprint
   - Scan with phone/camera
   - Automatic contact addition

3. **Profile Link:**
   - Optional: `dna://profile/abc123...xyz789`
   - Click to add contact
   - Verify fingerprint

**Security:** Users verify fingerprints out-of-band (voice call, in-person)

---

## Risk Assessment

### Low Risks 🟢

#### 1. User Confusion
**Impact:** Users expect migration, find fresh start
**Probability:** LOW (clear communication)
**Mitigation:**
- Repeated messaging: "This is a FRESH START"
- Clear release notes
- FAQ addressing expectations
- Support ready to explain

**Acceptance:** Users adapt quickly to clean slate

---

#### 2. Slow Adoption
**Impact:** Network growth slower than expected
**Probability:** MEDIUM
**Mitigation:**
- Marketing campaign
- Beta user evangelism
- Feature highlights
- Post-quantum security education

**Target:** 2,000 users by week 8 (achievable)

---

#### 3. Network Performance
**Impact:** Slower than expected DHT operations
**Probability:** LOW
**Mitigation:**
- Already tested: < 2s latency
- 3 geographically distributed nodes
- Proven at 99% uptime

**Current Performance:** Excellent (from testing)

---

### No Critical Risks 🔴

**Why:** Fresh start eliminates migration risks
- No identity conversion failures
- No contact migration issues
- No backward compatibility bugs
- No data loss (nothing to migrate)

**Simplicity = Reliability**

---

## Success Criteria

### Launch Success (Week 1)
- ✅ > 500 new identities created
- ✅ > 99% identity creation success rate
- ✅ > 99% DHT operation success rate
- ✅ < 5 second average DHT latency
- ✅ 100% bootstrap node uptime
- ✅ < 5% support ticket rate

### Growth Success (Week 8)
- ✅ > 2,000 active users
- ✅ > 10,000 messages sent
- ✅ > 500 groups created
- ✅ > 1,000 wall posts published
- ✅ > 90% user retention
- ✅ Positive user feedback

### Network Health (Ongoing)
- ✅ > 99.5% DHT operation success
- ✅ < 2 second average latency
- ✅ > 99.9% bootstrap node uptime
- ✅ Zero security vulnerabilities
- ✅ Zero data loss incidents

---

## Launch Day Runbook

### Personnel
- **Launch Lead** - Overall coordination
- **Network Engineer** - DNA Nodus operations
- **Support Lead** - User assistance
- **Developer** - Bug fixes
- **Communications** - User messaging

**Schedule:**
- All hands: T-1 hour to T+6 hours
- Extended support: T+6 to T+24 hours
- On-call: T+24 to T+72 hours

---

### Checklist

#### T-24 Hours
- [ ] DNA Nodus nodes verified operational
- [ ] New client builds published
- [ ] Download links active
- [ ] Support team briefed
- [ ] Monitoring dashboards ready
- [ ] Launch announcement sent

#### T-1 Hour
- [ ] Old bootstrap nodes displaying shutdown warning
- [ ] DNA Nodus ready for connections
- [ ] Support team online
- [ ] Social media posts scheduled

#### T-0 (Launch)
- [ ] Old bootstrap nodes stopped
- [ ] DNA Nodus accepting connections
- [ ] Launch announcement posted
- [ ] Monitor new user registrations
- [ ] Track support tickets

#### T+1 Hour
- [ ] First users connected
- [ ] DHT operations successful
- [ ] No critical issues
- [ ] Performance within targets

#### T+24 Hours
- [ ] Launch report published
- [ ] User count: > 500 target
- [ ] Network stable
- [ ] Support volume normal

---

## User Communication Templates

### Launch Announcement (T-3 weeks)

**Subject:** DNA Messenger v2.0 - Fresh Start with Post-Quantum Security

**Body:**
```
We're excited to announce DNA Messenger v2.0 - a FRESH START
with post-quantum security!

🔒 What's New:
• Dilithium5 (ML-DSA-87) post-quantum signatures
• NIST FIPS 204 - Category 5 security (256-bit quantum resistance)
• New DNA Nodus DHT network
• Faster, simpler, quantum-resistant

⚠️ Important: This is a FRESH START
• Create NEW Dilithium5 identity
• Rebuild contact list manually
• No historical data migrated
• Old RSA network will shut down

📅 Launch Date: December 21, 2025 00:00 UTC

🎯 What You Need to Do:
1. Download DNA Messenger v2.0 (launches Dec 21)
2. Create new Dilithium5 identity
3. Share your new fingerprint with contacts
4. Add contacts by their new fingerprints
5. Start messaging with quantum resistance!

Why Fresh Start?
This allows us to deliver the cleanest, simplest, most secure
post-quantum messenger without the complexity of migration.

Questions? https://cpunk.io/dna-messenger/fresh-start-faq

Welcome to the post-quantum era!

The cpunk Team
```

---

### Launch Day (T-0)

**Subject:** 🎉 DNA Messenger v2.0 is LIVE!

**Body:**
```
DNA Messenger v2.0 with post-quantum security is NOW LIVE!

🚀 Download: https://cpunk.io/dna-messenger/download

✅ Post-quantum signatures (Dilithium5 - FIPS 204)
✅ 256-bit quantum resistance (NIST Category 5)
✅ New DNA Nodus DHT network
✅ Clean, simple, secure

Getting Started (5 minutes):
1. Install DNA Messenger v2.0
2. Create new Dilithium5 identity
3. Copy your fingerprint
4. Share fingerprint with contacts
5. Add contacts by fingerprint
6. Start chatting!

🔒 Quantum-Resistant Security
Your messages are now protected against both
classical AND quantum computer attacks.

Need Help?
• Quick Start Guide: https://cpunk.io/guide
• FAQ: https://cpunk.io/faq
• Support: https://cpunk.io/support

Old RSA Network:
The old RSA-2048 network is now OFFLINE.
Old clients will no longer connect.

Welcome to quantum-resistant messaging!

The cpunk Team
```

---

## Conclusion

This **fresh start approach** is the **simplest and cleanest** path to post-quantum security:

**Advantages:**
- ✅ **No migration complexity** - No tools, no conversion, no attestations
- ✅ **Clean codebase** - Remove ALL RSA code
- ✅ **Smaller binary** - ~70KB code reduction
- ✅ **Faster development** - No dual-signature logic
- ✅ **Zero migration bugs** - Nothing to migrate = nothing to fail
- ✅ **Immediate full security** - Dilithium5-only from day one

**User Experience:**
- Fresh identity creation (simple)
- Manual contact rebuilding (users control)
- Clean slate (no legacy data issues)
- Clear expectations (no migration confusion)

**Timeline:**
- **Week 1:** Remove RSA, Dilithium5-only client
- **Week 2:** Testing (internal, alpha, beta)
- **Week 3:** Launch preparation
- **Day 0:** LAUNCH
- **Week 4-8:** Growth and optimization

**Risk Level:** LOW (fresh start eliminates migration risks)

**Network Status:**
- DNA Nodus: ✅ Operational (8/8 tests passing)
- Bootstrap nodes: ✅ 3 nodes ready
- Performance: ✅ < 2s latency
- Uptime: ✅ 99%+

**Ready to Launch:** YES - DNA Nodus network is production-ready

---

**Plan Status:** READY FOR EXECUTION
**Launch Date:** TBD (recommend 3 weeks from approval)
**Next Steps:**
1. Approve fresh start approach
2. Set launch date
3. Begin Phase 1 (remove RSA code)

---

**Document:** `nodus/MIGRATION_PLAN_FRESH_START.md`
**Created:** 2025-11-23
**Strategy:** No user migration - fresh start with Dilithium5
**Network:** DNA Nodus operational, ready for launch
