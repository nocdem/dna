# DNA API Quick Reference

**Base URL:** `https://api.dna.cpunk.club`

---

## GET Requests (Query String)

```bash
# Lookup by name or wallet
curl "https://api.dna.cpunk.club?lookup=nocdem"

# Search names (partial match)
curl "https://api.dna.cpunk.club?lookup2=noc"

# Lookup by Telegram username
curl "https://api.dna.cpunk.club?by_telegram=Nocdem"

# Lookup by delegation order hash
curl "https://api.dna.cpunk.club?by_order=0xBBC72D08..."

# Get all delegations
curl "https://api.dna.cpunk.club?all_delegations"

# Validate transaction
curl "https://api.dna.cpunk.club?tx_validate=0x10D0C778...&network=Backbone"
```

---

## POST Requests (JSON Body)

### Register New Name
```bash
curl -X POST https://api.dna.cpunk.club \
  -H "Content-Type: application/json" \
  -d '{
    "action": "add",
    "name": "myname",
    "wallet": "Rj7J7MiX2bWy8sNyWhXjfah...",
    "tx_hash": "0x10D0C778B32716FA..."
  }'
```

### Update Profile
```bash
curl -X POST https://api.dna.cpunk.club \
  -H "Content-Type: application/json" \
  -d '{
    "action": "update",
    "wallet": "Rj7J7MiX2bWy8sNyWhXjfah...",
    "bio": "My new bio",
    "socials": {
      "telegram": {"profile": "myusername"},
      "x": {"profile": "myhandle"}
    }
  }'
```

### List Name for Sale
```bash
curl -X POST https://api.dna.cpunk.club \
  -H "Content-Type: application/json" \
  -d '{
    "action": "list_for_sale",
    "wallet": "Rj7J7MiX2bWy8sNyWhXjfah...",
    "name": "myname",
    "price": 500.0
  }'
```

### Purchase Name
```bash
curl -X POST https://api.dna.cpunk.club \
  -H "Content-Type: application/json" \
  -d '{
    "action": "purchase",
    "name": "targetname",
    "tx_hash": "0x...",
    "buyer_wallet": "Rj7J7MiX2bWy8sNyWhXjfah..."
  }'
```

---

## Response Format

**Success:**
```json
{
  "status_code": 0,
  "message": "OK",
  "response_data": {
    "public_hash": "05e34a7b...",
    "sign_id": 258,
    "registered_names": {...},
    "wallet_addresses": {...}
  }
}
```

**Error:**
```json
{
  "status_code": -1,
  "message": "NOK",
  "description": "Error message here"
}
```

---

## Common Use Cases

### 1. Resolve DNA Name to Address
```cpp
std::string resolveAddress(const std::string& dnaName, const std::string& network) {
    // GET ?lookup=dnaName
    // Parse response_data.wallet_addresses[network]
}
```

### 2. Check Name Availability
```cpp
bool isNameAvailable(const std::string& name) {
    // GET ?lookup=name
    // Return true if status_code == -1
}
```

### 3. Get User Profile
```cpp
Json::Value getProfile(const std::string& dnaName) {
    // GET ?lookup=dnaName
    // Return response_data (bio, socials, etc.)
}
```

### 4. Send to DNA Name
```cpp
bool sendToDNA(const std::string& dnaName, double amount) {
    std::string address = resolveAddress(dnaName, "Backbone");
    if (!address.empty()) {
        return sendTransaction(address, amount);
    }
    return false;
}
```

---

## Validation Rules

| Field | Rule |
|-------|------|
| DNA Name | 3-36 chars, alphanumeric + `.` `_` `-` |
| Minimum Price | 500 CPUNK |
| Expiration | 365 days from registration |
| Disallowed Names | admin, root, system, network, cpunk, demlabs, cellframe |

---

## Supported Networks

| Network | ID |
|---------|-----|
| riemann | 0x000000000000dddd |
| raiden | 0x000000000000bbbb |
| KelVPN | 0x1807202300000000 |
| Backbone | 0x0404202200000000 |
| mileena | 0x000000000000cccc |
| subzero | 0x000000000000acca |
| cpunk_testnet | 0x2884202288800000 |

---

## Error Codes

| Status Code | Meaning |
|-------------|---------|
| 0 | Success |
| -1 | Error (see description field) |

---

## Tips

- **Cache lookups** for 5 minutes to reduce API calls
- **Debounce autocomplete** to avoid rate limits
- **Always validate** transaction hashes on-chain
- **Show full address** alongside DNA name for user confirmation
- **Handle timeouts** gracefully with retry logic
