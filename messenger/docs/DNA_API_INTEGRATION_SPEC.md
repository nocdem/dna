# DNA Global Database API - Integration Specification

**Version:** 1.0
**Date:** 2025-10-23
**Target Applications:** DNA Wallet GUI, DNA Messenger

---

## Table of Contents
1. [Overview](#overview)
2. [API Reference](#api-reference)
3. [Wallet GUI Integration Ideas](#wallet-gui-integration-ideas)
4. [Messenger Integration Ideas](#messenger-integration-ideas)
5. [Implementation Priority](#implementation-priority)
6. [Code Examples](#code-examples)
7. [Data Structures](#data-structures)
8. [Security Considerations](#security-considerations)

---

## Overview

The DNA Global Database (GDB) is a decentralized identity and profile system that maps human-readable names to wallet addresses across multiple Cellframe networks. It provides social profiles, messaging, delegation tracking, and a marketplace for DNA names.

**Base URL:** `https://api.dna.cpunk.club`

**Response Format:** JSON
```json
{
  "status_code": 0,           // 0 = success, -1 = error
  "message": "OK",            // Status message
  "response_data": {...}      // Actual data payload
}
```

---

## API Reference

### GET Endpoints

| Endpoint | Parameters | Returns | Use Case |
|----------|-----------|---------|----------|
| `?lookup=<name\|wallet>` | DNA name or wallet address | Full profile | Profile lookup, address resolution |
| `?lookup2=<partial>` | Partial DNA name | Array of matching names | Auto-complete, search |
| `?by_telegram=<username>` | Telegram username | Profile | Social integration |
| `?by_order=<hash>` | Delegation order hash | Profile | Delegation tracking |
| `?all_delegations` | None | All delegations | Staking overview |
| `?tx_validate=<hash>&network=<net>` | TX hash, network name | Validation status | TX verification |

### POST Endpoints

| Action | Required Fields | Description |
|--------|----------------|-------------|
| `add` | name, wallet, tx_hash | Register new DNA name |
| `update` | wallet, [fields to update] | Update profile data |
| `list_for_sale` | wallet, name, price | List DNA for sale (min 500 CPUNK) |
| `remove_from_sale` | wallet, name | Remove from marketplace |
| `purchase` | name, tx_hash, buyer_wallet | Buy DNA name |

---

## Wallet GUI Integration Ideas

### 1. **Address Book with DNA Names**
**Priority: HIGH**

- Replace long wallet addresses with DNA names
- Auto-resolve DNA names to addresses when sending
- Display contact list from DNA GDB
- Show profile pictures next to contacts

**Features:**
- Search contacts by DNA name
- View contact's social profiles
- See contact's wallet addresses across all networks
- Import/export address book

**UI Elements:**
```
┌─────────────────────────────────────┐
│ 🔍 Search Contacts                  │
├─────────────────────────────────────┤
│ 👤 nocdem                           │
│    Rj7J7MiX2bWy8sNy...              │
│    "Vi veri universum vivus vici"   │
│    📱 Telegram: @Nocdem             │
├─────────────────────────────────────┤
│ 👤 john                             │
│    jrmnGqeeds4Dp67A...              │
└─────────────────────────────────────┘
```

### 2. **DNA Name Registration**
**Priority: HIGH**

- Register new DNA names from wallet
- Renew expiring names
- View owned DNA names with expiration dates
- Auto-notify 30 days before expiration

**Workflow:**
1. Check name availability (`?lookup=<name>`)
2. Create registration transaction (0.01 CPUNK registration fee)
3. Submit to GDB (`action: "add"`)
4. Confirm registration

### 3. **Profile Management**
**Priority: MEDIUM**

- Edit DNA profile from wallet
- Update social media links
- Set bio and profile picture
- Link external wallets (BTC, ETH, SOL, etc.)

**Profile Editor UI:**
```
┌─────────────────────────────────────┐
│ Edit DNA Profile: nocdem            │
├─────────────────────────────────────┤
│ Bio: [Vi veri universum vivus vici] │
│                                     │
│ 🌐 Social Links:                   │
│   Telegram: [Nocdem              ] │
│   X/Twitter: [NocdemDeus         ] │
│   GitHub: [nocdem                ] │
│                                     │
│ 💰 External Wallets:               │
│   BTC: [bc1...                   ] │
│   ETH: [0x...                    ] │
│                                     │
│ [Cancel]              [Save Changes]│
└─────────────────────────────────────┘
```

### 4. **DNA Marketplace**
**Priority: MEDIUM**

- Browse DNA names for sale
- List your DNA names for sale
- Purchase DNA names
- View sale history

**Features:**
- Filter by price range
- Search available names
- View name history (previous owners)
- Escrow-based transactions

### 5. **Send to DNA Name**
**Priority: HIGH**

- Enter DNA name instead of full address
- Auto-complete suggestions
- Show recipient profile before sending
- Support multiple networks

**Send Dialog Enhancement:**
```
┌─────────────────────────────────────┐
│ Send CPUNK                          │
├─────────────────────────────────────┤
│ Recipient: [nocdem              ▼] │
│            ↓ Resolves to:           │
│   👤 nocdem                         │
│   Network: Backbone                 │
│   Rj7J7MiX2bWy8sNyWhXjfah...        │
│   ✓ Verified DNA name               │
│                                     │
│ Amount: [0.1           ] CPUNK     │
│                                     │
│ [Cancel]                   [Send →] │
└─────────────────────────────────────┘
```

### 6. **Transaction History with DNA Names**
**Priority: MEDIUM**

- Show DNA names in TX history instead of addresses
- Profile pictures in transaction list
- Filter by contact

### 7. **Delegation Dashboard**
**Priority: LOW**

- View all delegations (`?all_delegations`)
- Track delegation rewards
- Show delegated validators with DNA names
- Delegation leaderboard

---

## Messenger Integration Ideas

### 1. **DNA Name Messaging**
**Priority: HIGH**

- Send messages to DNA names instead of addresses
- Resolve recipient automatically
- Show online status if available

**Message Input:**
```
To: @nocdem [DNA verified ✓]
Message: Hello from DNA messenger!
```

### 2. **Profile Integration**
**Priority: HIGH**

- Show contact profile from DNA GDB
- Display bio, socials, profile picture
- Right-click contact → "View DNA Profile"

**Profile Card:**
```
┌─────────────────────────────────────┐
│          👤 nocdem                  │
├─────────────────────────────────────┤
│ "Vi veri universum vivus vici"      │
│                                     │
│ 📱 @Nocdem (Telegram)               │
│ 𝕏 @NocdemDeus                       │
│ 💻 github.com/nocdem                │
│                                     │
│ Networks:                           │
│ • Backbone: Rj7J7MiX2bWy8sNy...    │
│ • KelVPN: Rj7J7MjNgdr8DX5E...      │
│                                     │
│ [Send Message] [Add to Favorites]   │
└─────────────────────────────────────┘
```

### 3. **Contact Discovery**
**Priority: MEDIUM**

- Search DNA database for contacts
- Find users by Telegram username (`?by_telegram=`)
- Suggest contacts based on delegations
- Import contacts from DNA GDB

### 4. **Public Message Wall**
**Priority: LOW**

- View public messages from DNA profiles
- Post to your own message wall
- Like/react to messages
- Message history

### 5. **Verified Identity Badges**
**Priority: MEDIUM**

- Show "DNA Verified ✓" badge for registered names
- Display sign_id for signature verification
- Warn if messaging unverified address

### 6. **Group Chat with DNA Names**
**Priority: LOW**

- Create groups using DNA names
- Group admin by DNA ownership
- Persistent group identity

### 7. **Social Feed**
**Priority: LOW**

- Activity feed from your contacts
- New delegations, purchases, messages
- Filter by activity type

---

## Implementation Priority

### Phase 1: Core Functionality (Essential)
1. **DNA name lookup** - Resolve names to addresses
2. **Address book integration** - Store and display DNA contacts
3. **Send to DNA name** - Replace address with name in send dialog
4. **Profile viewer** - Display DNA profile information

### Phase 2: Profile Management (Important)
5. **DNA name registration** - Register new names from GUI
6. **Profile editor** - Update bio, socials, etc.
7. **Name renewal** - Extend expiration dates
8. **Transaction history with names** - Show names in TX list

### Phase 3: Advanced Features (Nice to Have)
9. **DNA marketplace** - Buy/sell DNA names
10. **Contact discovery** - Search DNA database
11. **Delegation tracking** - View staking info
12. **Message wall** - Public messaging

### Phase 4: Social Integration (Future)
13. **Telegram integration** - Link Telegram accounts
14. **Social feed** - Activity from contacts
15. **Reputation system** - Trust scores
16. **NFT profile pictures** - Display NFTs

---

## Code Examples

### C++ HTTP Request Helper

```cpp
#include <curl/curl.h>
#include <json/json.h>
#include <string>

class DNAApi {
private:
    static const std::string BASE_URL;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
        userp->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

public:
    // GET request
    static Json::Value lookup(const std::string& name) {
        CURL* curl = curl_easy_init();
        std::string response;

        if(curl) {
            std::string url = BASE_URL + "?lookup=" + name;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            if(res == CURLE_OK) {
                Json::Value root;
                Json::Reader reader;
                reader.parse(response, root);
                return root;
            }
        }
        return Json::Value::null;
    }

    // Resolve DNA name to address for specific network
    static std::string resolveAddress(const std::string& dnaName, const std::string& network) {
        Json::Value result = lookup(dnaName);

        if(result["status_code"].asInt() == 0) {
            return result["response_data"]["wallet_addresses"][network].asString();
        }
        return "";
    }

    // Check if DNA name exists
    static bool exists(const std::string& name) {
        Json::Value result = lookup(name);
        return result["status_code"].asInt() == 0;
    }

    // POST request
    static Json::Value updateProfile(const std::string& wallet,
                                     const std::string& bio,
                                     const Json::Value& socials) {
        CURL* curl = curl_easy_init();
        std::string response;

        if(curl) {
            Json::Value payload;
            payload["action"] = "update";
            payload["wallet"] = wallet;
            payload["bio"] = bio;
            payload["socials"] = socials;

            Json::FastWriter writer;
            std::string jsonStr = writer.write(payload);

            curl_easy_setopt(curl, CURLOPT_URL, BASE_URL.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            CURLcode res = curl_easy_perform(curl);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            if(res == CURLE_OK) {
                Json::Value root;
                Json::Reader reader;
                reader.parse(response, root);
                return root;
            }
        }
        return Json::Value::null;
    }
};

const std::string DNAApi::BASE_URL = "https://api.dna.cpunk.club";
```

### Qt Widget for DNA Name Input

```cpp
// DNANameInput.h
#ifndef DNANAMEINPUT_H
#define DNANAMEINPUT_H

#include <QLineEdit>
#include <QLabel>
#include <QTimer>

class DNANameInput : public QWidget {
    Q_OBJECT

private:
    QLineEdit* nameInput;
    QLabel* statusLabel;
    QLabel* addressPreview;
    QTimer* debounceTimer;
    std::string currentNetwork;

    void validateName(const QString& name);

private slots:
    void onTextChanged(const QString& text);
    void onDebounceTimeout();

signals:
    void nameResolved(const QString& dnaName, const QString& address);
    void nameInvalid();

public:
    DNANameInput(const std::string& network, QWidget* parent = nullptr);
    QString getResolvedAddress() const;
    bool isValid() const;
};

#endif
```

```cpp
// DNANameInput.cpp
#include "DNANameInput.h"
#include "DNAApi.h"
#include <QVBoxLayout>

DNANameInput::DNANameInput(const std::string& network, QWidget* parent)
    : QWidget(parent), currentNetwork(network) {

    QVBoxLayout* layout = new QVBoxLayout(this);

    nameInput = new QLineEdit(this);
    nameInput->setPlaceholderText("Enter DNA name or wallet address...");

    statusLabel = new QLabel(this);
    statusLabel->setStyleSheet("QLabel { color: gray; font-size: 10px; }");

    addressPreview = new QLabel(this);
    addressPreview->setStyleSheet("QLabel { color: #00ff00; font-family: monospace; }");
    addressPreview->setWordWrap(true);

    layout->addWidget(nameInput);
    layout->addWidget(statusLabel);
    layout->addWidget(addressPreview);

    debounceTimer = new QTimer(this);
    debounceTimer->setSingleShot(true);
    debounceTimer->setInterval(500); // 500ms debounce

    connect(nameInput, &QLineEdit::textChanged, this, &DNANameInput::onTextChanged);
    connect(debounceTimer, &QTimer::timeout, this, &DNANameInput::onDebounceTimeout);
}

void DNANameInput::onTextChanged(const QString& text) {
    statusLabel->setText("⏳ Validating...");
    addressPreview->clear();
    debounceTimer->start();
}

void DNANameInput::onDebounceTimeout() {
    QString text = nameInput->text().trimmed();

    if(text.isEmpty()) {
        statusLabel->clear();
        return;
    }

    // Check if it's already a full address
    if(text.length() > 80 && text.startsWith("Rj") || text.startsWith("o9") || text.startsWith("m")) {
        statusLabel->setText("✓ Valid address");
        addressPreview->setText(text);
        emit nameResolved("", text);
        return;
    }

    // Try to resolve as DNA name
    std::string resolved = DNAApi::resolveAddress(text.toStdString(), currentNetwork);

    if(!resolved.empty()) {
        statusLabel->setText("✓ DNA name verified");
        addressPreview->setText(QString::fromStdString(resolved));
        emit nameResolved(text, QString::fromStdString(resolved));
    } else {
        statusLabel->setText("✗ DNA name not found");
        statusLabel->setStyleSheet("QLabel { color: red; font-size: 10px; }");
        emit nameInvalid();
    }
}

QString DNANameInput::getResolvedAddress() const {
    return addressPreview->text();
}

bool DNANameInput::isValid() const {
    return !addressPreview->text().isEmpty();
}
```

### Usage in Send Dialog

```cpp
// In SendTokensDialog.cpp

DNANameInput* recipientInput = new DNANameInput("Backbone", this);
layout->addWidget(recipientInput);

connect(recipientInput, &DNANameInput::nameResolved, this,
    [this](const QString& dnaName, const QString& address) {
        // Update recipient field with resolved address
        m_recipientAddress = address.toStdString();

        // Optionally fetch and display profile
        if(!dnaName.isEmpty()) {
            Json::Value profile = DNAApi::lookup(dnaName.toStdString());
            if(profile["status_code"].asInt() == 0) {
                QString bio = QString::fromStdString(
                    profile["response_data"]["bio"].asString()
                );
                // Display bio in UI
            }
        }
    }
);
```

---

## Data Structures

### Profile Object
```json
{
  "public_hash": "05e34a7bc2a711920de8d6322fb4db67496d4c3e8d7840ec8031d7a58825c54c",
  "sign_id": 258,
  "registered_names": {
    "nocdem": {
      "created_at": "2025-03-28T03:14:42.319782+00:00",
      "expires_on": "2026-03-28T03:14:42.319792+00:00",
      "tx_hash": "0x10D0C778B32716FA70822E14C60B09FBC131DD3707A1970C42AC10E89E828F45"
    }
  },
  "socials": {
    "telegram": { "profile": "Nocdem" },
    "x": { "profile": "NocdemDeus" },
    "facebook": { "profile": "" },
    "instagram": { "profile": "" },
    "google": { "profile": "nocdem@gmail.com" },
    "linkedin": { "profile": "nocdem@gmail.com" },
    "github": { "profile": "nocdem" }
  },
  "bio": "Vi veri universum vivus vici",
  "dinosaur_wallets": {
    "BTC": "",
    "ETH": "",
    "SOL": "",
    "QEVM": "",
    "BNB": ""
  },
  "nft_images": [],
  "profile_picture": "",
  "delegations": [
    {
      "tx_hash": "0x61C54E9A02EFF724C8B0575CE3B7BFDAE47B3B848B0CEBE2DD19AC36E1B125F8",
      "order_hash": "0xBBC72D08EEE5257DBBBADB4D3BAAE7931C365B0034D49000C22230381D205151",
      "network": "Backbone",
      "amount": 1e-08,
      "tax": 30,
      "delegation_time": "2025-05-30T12:30:30.584180+00:00"
    }
  ],
  "modified_at": "2025-05-30T12:30:30.584198+00:00",
  "messages": [
    {
      "s_dna": "nocdem",
      "r_dna": "wall",
      "msg": "Vi veri universum vivus vici",
      "timestamp": "2025-05-26T23:56:02.247Z"
    }
  ],
  "marketplace": {
    "for_sale": {},
    "sale_history": []
  },
  "wallet_addresses": {
    "riemann": "o9z3wUTSTicckJuovshcyvwGL8xcUSSf2rh4y3MuBv28gSRAUk7vDYspwGn5FVQBzTQFmJvH61LaMHttTpzddmaHdD9U3GZDkiLVhbzt",
    "raiden": "jrmnGqeeds4Dp67AYSAwQdWW4DkC4137FE97GgSU47BPWjMKAfM5SHaQ2hsXoyssGkD2AbdpF8vuHpjWyBsYn2Uk7Peodoafjduxpac9",
    "KelVPN": "Rj7J7MjNgdr8DX5E9h4MJj2ZkFfpJ4bpKj4UQjAvftNyGPjq92PKppkewuXZfTLwi3JFtrnoQm8tYDLLBJNqBEAXAkoYX4tQHNWeLpsV",
    "Backbone": "Rj7J7MiX2bWy8sNyWhXjfahLCfe4B5AgDU9JcMCJtJa8m2P2HewH3kzik2mjDYKuLD5Jj4ioVQLxAkocDhFJiD4isBNkD5jjorokvTEy",
    "mileena": "mWNv7A43YnqRHCWVEewHCHDtCBMQGDjt93R67ruBd1bm6atEphjVpvE7UzKoW2KYRVjPzjQgEU6UUnXAkYBK4UdJdtjDr4kg9VfgfGcK",
    "subzero": "mJUUJk6Yk2gBSTjcAKk7jcDvQH4q9WSPknxGsPRFvaZrXw7zUAk6FdhguvhMkEJTzT1i1gdxoFxj3yyYdtbFPLj6CTvCB1pP5hVwLL2m",
    "cpunk_testnet": "Rj7w51h2V3SE8twXMn1BinVnM1HhSRgcETXfvR57EserNqaSeBpWjPJUGRs66mYfRKgkHwRn7bTiFU2iPf22XCqnUFvwyV4j8FS7Ewui"
  }
}
```

### Network IDs
```cpp
const std::map<std::string, uint64_t> NETWORK_IDS = {
    {"riemann", 0x000000000000dddd},
    {"raiden", 0x000000000000bbbb},
    {"KelVPN", 0x1807202300000000},
    {"Backbone", 0x0404202200000000},
    {"mileena", 0x000000000000cccc},
    {"subzero", 0x000000000000acca},
    {"cpunk_testnet", 0x2884202288800000}
};
```

---

## Security Considerations

### 1. **Input Validation**
- Always validate DNA names before API calls
- Regex: `^[a-zA-Z0-9\._-]{3,36}$`
- Sanitize all user inputs
- Prevent injection attacks

### 2. **HTTPS Only**
- All API calls must use HTTPS
- Verify SSL certificates
- No cleartext transmission

### 3. **Transaction Validation**
- Always verify DNA name ownership before sending funds
- Confirm resolved address with user
- Show full address alongside DNA name
- Validate transaction hash from blockchain

### 4. **Rate Limiting**
- Implement client-side rate limiting
- Cache DNS lookups (5 minute TTL)
- Debounce autocomplete requests
- Respect API rate limits

### 5. **Privacy**
- Don't auto-upload contacts to DNA GDB
- Let users opt-in to profile visibility
- Warn before posting public messages
- Local caching with encryption

### 6. **Phishing Prevention**
- Show full address on hover
- Visual indicators for verified names
- Warn on similar-looking names (homograph attacks)
- Example: `nocdem` vs `n0cdem` (0 instead of o)

### 7. **Marketplace Security**
- Verify ownership before purchase
- Escrow transactions
- Check TX confirmation before transfer
- Prevent front-running attacks

---

## Testing Checklist

### Functional Tests
- [ ] Resolve DNA name to address
- [ ] Handle non-existent names gracefully
- [ ] Search with partial names
- [ ] Register new DNA name
- [ ] Update profile fields
- [ ] List name for sale
- [ ] Purchase DNA name
- [ ] View delegations
- [ ] Validate transactions

### Edge Cases
- [ ] Empty/null inputs
- [ ] Special characters in names
- [ ] Very long names (>36 chars)
- [ ] Network timeout handling
- [ ] Invalid JSON responses
- [ ] Expired names
- [ ] Conflicting name registrations
- [ ] Unicode/emoji in names

### Security Tests
- [ ] SQL injection attempts
- [ ] XSS in profile fields
- [ ] Invalid wallet addresses
- [ ] Fake transaction hashes
- [ ] Homograph attack detection
- [ ] Rate limit compliance

### UI/UX Tests
- [ ] Autocomplete performance
- [ ] Profile picture loading
- [ ] Responsive layout
- [ ] Error message clarity
- [ ] Loading indicators
- [ ] Offline mode handling

---

## Future Enhancements

### 1. **ENS-style Subdomains**
- Support `subdomain.nocdem`
- Delegate subdomain control
- Hierarchical naming

### 2. **Multi-signature Profiles**
- Require multiple signatures for updates
- Team/organization accounts
- Recovery mechanisms

### 3. **Reputation System**
- Trust scores based on delegations
- Transaction history analysis
- Community voting

### 4. **IPFS Integration**
- Store profile data on IPFS
- Decentralized profile pictures
- Censorship resistance

### 5. **Payment Links**
- `dna:nocdem?amount=10&network=Backbone`
- QR codes for DNA names
- Payment request system

### 6. **Notification System**
- Email/Telegram alerts for:
  - Name expiration warnings
  - Incoming messages
  - Marketplace offers
  - Delegation changes

### 7. **Web3 Integration**
- Connect to MetaMask
- Bridge to Ethereum/Polygon
- Cross-chain identity

---

## Resources

- **API Base URL:** https://api.dna.cpunk.club
- **Backend Source:** /opt/cpunk/backend/
- **Network Config:** /opt/cpunk/backend/config.json
- **Cellframe Docs:** https://docs.cellframe.net
- **CPUNK Website:** https://cpunk.club

---

## Support

For questions or issues:
- GitHub: https://github.com/nocdem/dna-messenger
- Telegram: @Nocdem
- Email: nocdem@gmail.com

---

**Document Status:** Draft v1.0
**Last Updated:** 2025-10-23
**Maintainer:** nocdem
